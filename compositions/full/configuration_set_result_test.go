package compositionfull

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
)

// full_only: false
func TestConfigurationSetResultContract(t *testing.T) {
	source := configurationSetPair(t, "aws", configuration.JSON, nil)
	configurationSetWritable(t, source)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	name := "n/雪"
	input := &configurationSetInput{Reader: strings.NewReader("private-result-input-must-not-appear")}
	result, err := SetConfiguration(ctx, source.path, configuration.JSON, name, input, SetOptions{Confidential: true})
	if err != nil || result.StateResult != SetSuccess || result.Payload == nil || input.closes != 1 {
		t.Fatal("real local artifact did not complete")
	}
	body, err := RenderSetJSON(result, nil)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Schema    string `json:"schema"`
		Operation string `json:"operation_kind"`
		State     string `json:"state_result"`
		Effect    string `json:"effect_summary"`
		Output    string `json:"output_summary"`
		Variant   string `json:"operation_payload"`
		Payload   struct {
			FileID      string `json:"input_file_id"`
			Predecessor string `json:"predecessor_digest"`
			Artifact    string `json:"sealed_artifact_digest"`
			Readback    struct {
				Editable  string `json:"editable_digest"`
				Generated string `json:"generated_digest"`
			} `json:"readback"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	generatedBytes, err := os.ReadFile(result.GeneratedPath)
	if err != nil {
		t.Fatal(err)
	}
	editableBytes, err := os.ReadFile(result.EditablePath)
	if err != nil {
		t.Fatal(err)
	}
	var generated struct {
		Secrets map[string]struct{ Sealed []byte }
	}
	if err := json.Unmarshal(generatedBytes, &generated); err != nil {
		t.Fatal(err)
	}
	hash := func(b []byte) string { digest := sha256.Sum256(b); return hex.EncodeToString(digest[:]) }
	if wire.Schema != "ProductResult/v1" || wire.Operation != "set-confidential" || wire.State != "success" || wire.Effect != "not-applicable" || wire.Output != "not-applicable" || wire.Variant != "SealedArtifactPayload/v1" || wire.Payload.FileID != hash([]byte("Reader file fixture")) || wire.Payload.Predecessor != hash(source.editableBytes) || wire.Payload.Artifact != hash(generated.Secrets[name].Sealed) || wire.Payload.Readback.Editable != hash(editableBytes) || wire.Payload.Readback.Generated != hash(generatedBytes) {
		t.Fatal("result omitted or changed exact artifact/readback facts")
	}
	if SetExitCode(result, nil) != 0 || SetExitCode(result, errors.New("opaque-cleanup")) != 2 {
		t.Fatal("confirmed result exit classification changed")
	}
	for _, key := range []string{"receipt_hex", "observed_revision_id", "observed_snapshot_id", "outcome"} {
		var fields map[string]json.RawMessage
		if json.Unmarshal(body, &fields) != nil || fields[key] != nil {
			t.Fatal("local artifact acquired canonical/legacy result field", key)
		}
	}
	if strings.Contains(string(body), "private-result-input-must-not-appear") {
		t.Fatal("plaintext reached public result")
	}

	for _, damage := range []string{"artifact", "editable-readback", "generated-readback", "file", "target", "path", "native-receipt", "request", "failure-with-payload"} {
		t.Run(damage, func(t *testing.T) {
			changed := *result
			payload := *result.Payload
			changed.Payload = &payload
			switch damage {
			case "artifact":
				payload.SealedArtifactDigest[0] ^= 1
			case "editable-readback":
				payload.Readback.EditableDigest[0] ^= 1
			case "generated-readback":
				payload.Readback.GeneratedDigest[0] ^= 1
			case "file":
				payload.InputFileID[0] ^= 1
			case "target":
				payload.Target.Name = "another"
			case "path":
				changed.EditablePath += "different"
			case "native-receipt":
				changed.delivery = nil
			case "request":
				request := *result.RequestIdentity
				request.RecipientImageDigest[0] ^= 1
				changed.RequestIdentity = &request
			case "failure-with-payload":
				changed.StateResult = SetRefused
			}
			if _, err := RenderSetJSON(&changed, nil); !errors.Is(err, ErrSetResult) {
				t.Fatal("mismatched or unproved artifact fact rendered")
			}
		})
	}
	t.Run("zero-observation-refuses", func(t *testing.T) {
		changed := *result
		changed.StateResult = SetUnavailable
		changed.Payload = nil
		changed.delivery = nil
		changed.EditablePath, changed.GeneratedPath = "", ""
		if _, err := RenderSetJSON(&changed, &configuration.UnknownEdit{Observation: &configuration.EditObservation{}}); !errors.Is(err, ErrSetResult) {
			t.Fatal("empty public observation value claimed exact retained material")
		}
	})
	t.Run("pre-admission-refusal", func(t *testing.T) {
		badInput := &configurationSetInput{Reader: strings.NewReader("AB==")}
		refused, err := SetConfiguration(ctx, source.path, configuration.JSON, "other", badInput, SetOptions{Confidential: true, Base64: true})
		if err == nil || refused.StateResult != SetRefused || refused.Payload != nil || refused.RequestIdentity != nil || badInput.closes != 1 {
			t.Fatal("invalid input fabricated artifact identity")
		}
		body, renderErr := RenderSetJSON(refused, err)
		if renderErr != nil {
			t.Fatal(renderErr)
		}
		var record struct {
			Variant  string          `json:"operation_payload"`
			Payload  json.RawMessage `json:"payload"`
			Identity struct {
				Schema      string `json:"schema"`
				Predecessor string `json:"predecessor_digest"`
			} `json:"request_identity"`
		}
		if json.Unmarshal(body, &record) != nil || record.Variant != "none" || record.Payload != nil || record.Identity.Schema != "PreAdmissionRequestIdentity/v1" || record.Identity.Predecessor != "" || SetExitCode(refused, err) != 2 {
			t.Fatal("refusal granted payload, predecessor, or retry identity")
		}
	})
}

// full_only: false
func TestSetHumanShowsOutcomeAndSourceAction(t *testing.T) {
	for _, confidential := range []bool{false, true} {
		result, err := NewSetRefusal(confidential)
		if err != nil {
			t.Fatal(err)
		}
		diagnostic := &configuration.Diagnostic{Field: "schema", Reason: "unsupported-schema", Line: 3, Column: 9}
		body, err := RenderSetHuman(result, diagnostic)
		label := "Plain value edit: refused\n"
		if confidential {
			label = "Supplied secret preparation: refused\n"
		}
		if err != nil || !strings.HasPrefix(string(body), label) || !strings.Contains(string(body), "Input source: unsupported-schema; field schema; exact location 3:9") {
			t.Fatalf("human set result lost its outcome or source action: %v; %s", err, body)
		}
		for _, hidden := range []string{"ProductResult/v1", "PreAdmissionRequestIdentity/v1", "capsule_policy", "request_identity:"} {
			if strings.Contains(string(body), hidden) {
				t.Fatalf("routine codec detail escaped human summary: %s", body)
			}
		}
	}
}

// full_only: false
func TestSetSourceFailureReportsSafeOrigin(t *testing.T) {
	for _, confidential := range []bool{false, true} {
		result, err := NewSetRefusal(confidential)
		if err != nil {
			t.Fatal(err)
		}
		diagnostic := &configuration.Diagnostic{Field: "schema", Reason: "unsupported-schema", Line: 3, Column: 9}
		body, err := RenderSetJSON(result, diagnostic)
		var wire struct {
			SourceFailure *ConfigurationSourceFailure `json:"source_failure"`
		}
		if err != nil || json.Unmarshal(body, &wire) != nil || wire.SourceFailure == nil || *wire.SourceFailure != (ConfigurationSourceFailure{SourceID: "source", Field: "schema", Reason: "unsupported-schema", Line: 3, Column: 9, Precision: "exact"}) {
			t.Fatalf("set source origin missing: %s, %v", body, err)
		}
		human, err := RenderSetHuman(result, diagnostic)
		if err != nil || !strings.Contains(string(human), "Input source: unsupported-schema; field schema; exact location 3:9") {
			t.Fatalf("human set source origin missing: %s, %v", human, err)
		}
	}
}

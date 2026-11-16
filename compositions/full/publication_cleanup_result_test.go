package compositionfull

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func setPublicationCleanupFailure(r *core.PublicPublicationResult) {
	field := reflect.ValueOf(r).Elem().FieldByName("ExecutableCleanupFailed")
	if field.IsValid() && field.CanSet() && field.Kind() == reflect.Bool {
		field.SetBool(true)
	}
}

// full_only: false
func TestPublicationExecutableCleanupFailureKeepsExactPublicResult(t *testing.T) {
	for _, row := range []struct {
		name        string
		disposition uint8
		state       string
		summary     string
		exit        int
	}{
		{"acknowledged", contract.PublicationOutcomeAcknowledged, "effect-terminal-failure", "output-complete", 2},
		{"qualified-no-effect", contract.PublicationOutcomeQualifiedNoEffect, "effect-terminal-failure", "output-failed", 2},
		{"unknown", contract.PublicationOutcomeUnknown, "effect-unknown", "output-unknown", 3},
	} {
		t.Run(row.name, func(t *testing.T) {
			r := publicPublicationResultFixture(contract.PublicationWriteValue, row.disposition)
			r.Result = core.Result{Outcome: core.AdmissionRefused, Reason: core.CustodyUnavailable}
			before, err := RenderPublicationJSON(r)
			if err != nil {
				t.Fatal(err)
			}
			setPublicationCleanupFailure(&r)
			body, err := RenderPublicationJSON(r)
			if err != nil {
				t.Fatal("known executable cleanup failure made checked result unrenderable", err)
			}
			var old, got map[string]json.RawMessage
			if json.Unmarshal(before, &old) != nil || json.Unmarshal(body, &got) != nil {
				t.Fatal("publication envelope did not decode")
			}
			if string(got["executable_cleanup_failed"]) != "true" || string(got["state_result"]) != `"`+row.state+`"` || string(got["output_summary"]) != `"`+row.summary+`"` || PublicationExitCode(r) != row.exit || !bytes.Equal(got["payload"], old["payload"]) {
				t.Error("publication result lost the named local failure or changed its independent outcome", string(body))
			}
			if len(body)-len(before) != len(`,"executable_cleanup_failed":true`)+4 {
				t.Error("named failure did not use its fixed bounded encoding")
			}
			human, err := RenderPublicationHuman(r)
			if err != nil || !bytes.Contains(human, []byte("Warning: executable cleanup failed.\n")) || !bytes.Contains(human, []byte("Output result: "+row.summary+"\n")) {
				t.Error("human result lost executable cleanup failure or provider outcome", err)
			}
			combined := core.PublicApplyPublicationResult{Apply: suppliedApplyResultFixture(t), Publication: core.ApplyPublicationStage{Stage: "evaluated", Result: &r}}
			var joined, joinedHuman bytes.Buffer
			if err := WriteApplyPublicationJSON(&joined, combined); err != nil || bytes.Count(joined.Bytes(), []byte(`"executable_cleanup_failed": true`)) != 1 {
				t.Error("combined JSON result lost the named local failure", err)
			}
			if err := WriteApplyPublicationHuman(&joinedHuman, combined); err != nil || bytes.Count(joinedHuman.Bytes(), []byte("Warning: executable cleanup failed.\n")) != 1 {
				t.Error("combined human result lost the named local failure", err)
			}
		})
	}
}

// full_only: false
func TestPublicationExecutableCleanupFailureHasBoundedProjection(t *testing.T) {
	const want = 108068864 + len(`,"executable_cleanup_failed":true`) + len(`,"cleanup_failed":true`)
	if publicationCompactResultLimit != want+2048 || MaxPublicationResultJSONBytes != 67*(want+2048) {
		t.Error("publication bound omits the fixed local failure fact", MaxPublicationResultJSONBytes, want)
	}
	for _, row := range []struct {
		name             string
		framing, maximum uint64
	}{{"json", 63, MaxApplyPublicationJSONBytes}, {"human", 256, MaxApplyPublicationHumanBytes}} {
		t.Run(row.name, func(t *testing.T) {
			got, err := applyPublicationResultSize(MaxApplyPublicationApplyBytes, uint64(want), row.framing, row.maximum)
			if err != nil || got != MaxApplyPublicationApplyBytes+uint64(want)+row.framing {
				t.Error("combined bound omits a complete publication failure projection", got, err)
			}
		})
	}
}

// full_only: false
func TestPublicationExecutableCleanupFailureRequiresAdmittedOutput(t *testing.T) {
	for _, condition := range []string{"missing-vector", "no-local-failure"} {
		t.Run(condition, func(t *testing.T) {
			r := publicPublicationResultFixture(contract.PublicationWriteValue, contract.PublicationOutcomeAcknowledged)
			if condition == "missing-vector" {
				r.Result = core.Result{Outcome: core.AdmissionRefused, Reason: core.CustodyUnavailable}
				r.Output, r.Summary = nil, 0
			}
			setPublicationCleanupFailure(&r)
			if _, err := RenderPublicationJSON(r); err == nil {
				t.Error("unrelated result acquired an executable cleanup failure")
			}
			if _, err := RenderPublicationHuman(r); err == nil {
				t.Error("unrelated human result acquired an executable cleanup failure")
			}
		})
	}
}

// full_only: false
func TestPublicationExecutableCleanupFailureRetainsStrongerOperationFailure(t *testing.T) {
	for _, native := range []core.Result{{Outcome: core.AdmissionRefused, Reason: core.InvalidIntent}, {Outcome: core.EvidenceUnavailable, Reason: core.ReadUnavailable}, {Outcome: core.IntegrityFailure, Reason: core.InvalidProof}} {
		r := publicPublicationResultFixture(contract.PublicationWriteValue, contract.PublicationOutcomeAcknowledged)
		r.Result, r.ExecutableCleanupFailed = native, true
		body, err := RenderPublicationJSON(r)
		wantExit := 2
		if native.Outcome == core.EvidenceUnavailable {
			wantExit = 3
		}
		if err != nil || !bytes.Contains(body, []byte(`"state_result": "effect-terminal-failure"`)) || !bytes.Contains(body, []byte(`"output_summary": "output-complete"`)) || PublicationExitCode(r) != wantExit || r.Result != native {
			t.Error("executable cleanup granted success or changed native failure", native, err)
		}
	}
}

package core

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/testsupport/nativeprocess"
)

type publicProductResult struct {
	Schema           string `json:"schema"`
	Operation        string `json:"operation_kind"`
	State            string `json:"state_result"`
	Effect           string `json:"effect_summary"`
	Output           string `json:"output_summary"`
	payloadNull      bool
	CommitUnknown    bool                         `json:"commit_may_have_occurred"`
	Receipt          string                       `json:"receipt_hex"`
	RequestIdentity  json.RawMessage              `json:"request_identity"`
	OperationID      string                       `json:"operation_id"`
	ReplayIdentity   string                       `json:"replay_identity"`
	OperationPayload string                       `json:"operation_payload"`
	Observation      *publicComparisonObservation `json:"observation"`
	Delivery         struct {
		Outcome   string `json:"outcome"`
		Editable  string `json:"editable_path"`
		Generated string `json:"generated_path"`
		Manifest  string `json:"manifest_path"`
	} `json:"local_delivery"`
	Payload struct {
		Schema             string `json:"schema"`
		Init               string `json:"init_id"`
		DescriptorArtifact string `json:"descriptor_artifact_id"`
		ManifestArtifact   string `json:"manifest_artifact_id"`
		DescriptorDigest   string `json:"descriptor_digest"`
		Store              string `json:"store_id"`
		Revision           string `json:"ready_head_revision_id"`
		Snapshot           string `json:"snapshot_id"`
		Domain             string `json:"domain_id"`
		Verdict            string `json:"verdict"`
		EvidenceLimit      string `json:"evidence_limit"`
		Complete           bool   `json:"diagnostics_complete"`
		Scope              []struct {
			Status string `json:"status"`
		} `json:"checked_scope"`
	} `json:"payload"`
}

type publicComparisonObservation struct {
	Domain   string `json:"domain_id"`
	Revision string `json:"head_revision_id"`
	Snapshot string `json:"snapshot_id"`
}

// full_only: false
func TestPublicPairComparisonExpectedVerdictAndObservation(t *testing.T) {
	const body = `{"schema":"ProductResult/v1","operation_kind":"compare-public-configuration","state_result":"success","observation":{"domain_id":"1111111111111111111111111111111111111111111111111111111111111111","head_revision_id":"2222222222222222222222222222222222222222222222222222222222222222","snapshot_id":"3333333333333333333333333333333333333333333333333333333333333333"},"payload":{"verdict":"mismatch","diagnostics_complete":true,"checked_scope":[{"status":"complete"},{"status":"complete"},{"status":"complete"},{"status":"complete"},{"status":"complete"},{"status":"complete"},{"status":"complete"},{"status":"complete"},{"status":"complete"},{"status":"complete"},{"status":"complete"},{"status":"complete"}]}}`
	for _, condition := range []string{"mismatch", "match", "wrong-verdict", "unknown-verdict", "wrong-exit", "refused", "incomplete", "missing-scope", "extra-scope", "incomplete-scope", "missing-observation", "domain", "revision", "snapshot", "no-get", "kms", "write"} {
		t.Run(condition, func(t *testing.T) {
			result := publicChildResult{Code: 1, Body: []byte(body), Capture: nativeprocess.Capture{Events: []nativeprocess.Event{
				{Kind: "http-start", Operation: "head-read", Sequence: 1, Sent: true},
				{Kind: "http-return", Operation: "head-read", Sequence: 1, Sent: true, Status: 200},
				{Kind: "footer", Code: 1},
			}}}
			product := publicProduct(t, result, contract.ReaderCompareOperation)
			observation := &publicComparisonObservation{Domain: strings.Repeat("1", 64), Revision: strings.Repeat("2", 64), Snapshot: strings.Repeat("3", 64)}
			verdict := "mismatch"
			switch condition {
			case "match":
				verdict, product.Payload.Verdict, result.Code = "match", "match", 0
			case "wrong-verdict":
				verdict = "match"
			case "unknown-verdict":
				verdict = "unknown"
			case "wrong-exit":
				result.Code = 0
			case "refused":
				product.State = "refused"
			case "incomplete":
				product.Payload.Complete = false
			case "missing-scope":
				product.Payload.Scope = product.Payload.Scope[:11]
			case "extra-scope":
				product.Payload.Scope = append(product.Payload.Scope, product.Payload.Scope[0])
			case "incomplete-scope":
				product.Payload.Scope[11].Status = "unchecked"
			case "missing-observation":
				product.Observation = nil
			case "domain":
				product.Observation.Domain = strings.Repeat("4", 64)
			case "revision":
				product.Observation.Revision = strings.Repeat("4", 64)
			case "snapshot":
				product.Observation.Snapshot = strings.Repeat("4", 64)
			case "no-get":
				result.Capture.Events = result.Capture.Events[2:]
			case "kms":
				result.Capture.Events[0].Operation = "kms-public"
				result.Capture.Events[1].Operation = "kms-public"
			case "write":
				result.Capture.Events[0].Operation = "head-write"
				result.Capture.Events[1].Operation = "head-write"
			}
			result.Capture.Events[len(result.Capture.Events)-1].Code = result.Code
			want := condition == "match" || condition == "mismatch"
			if publicPairComparisonMatches(result, product, verdict, observation) != want {
				t.Fatal("pair comparison accepted a different verdict, selected observation, scope or capability")
			}
		})
	}
}

func publicProduct(t testing.TB, result publicChildResult, operation string) publicProductResult {
	t.Helper()
	var product publicProductResult
	if json.Unmarshal(result.Body, &product) != nil || product.Schema != "ProductResult/v1" || product.Operation != operation || !publicRequestIdentityValid(product) {
		t.Fatal("public result envelope refused")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(result.Body, &fields) != nil {
		t.Fatal("public result fields refused")
	}
	product.payloadNull = bytes.Equal(bytes.TrimSpace(fields["payload"]), []byte("null"))
	return product
}

// Set reports ciphertext and exact local readback facts. These facts do not
// establish remote acceptance; the following ordinary apply must establish it.
func publicAssertSet(t testing.TB, result publicChildResult, source, name string) {
	t.Helper()
	publicAssertSetPair(t, result, source, name)
	if !publicSetCaptureLocalOnly(result.Capture) {
		t.Fatal("local confidential set selected a credential source or remote capability")
	}
}

func publicSetCaptureLocalOnly(capture nativeprocess.Capture) bool {
	return len(capture.Events) == 1 && capture.Events[0].Kind == "footer"
}

// The public Product envelope and exact pair readback apply to stock and
// observed executables. Observer facts remain an obligation of the old wrapper.
func publicAssertSetPair(t testing.TB, result publicChildResult, source, name string) {
	t.Helper()
	var product struct {
		Schema           string `json:"schema"`
		Operation        string `json:"operation_kind"`
		State            string `json:"state_result"`
		Effect           string `json:"effect_summary"`
		Output           string `json:"output_summary"`
		OperationPayload string `json:"operation_payload"`
		Evidence         string `json:"evidence_ceiling"`
		Payload          *struct {
			Schema               string `json:"schema"`
			InputFileID          string `json:"input_file_id"`
			PredecessorDigest    string `json:"predecessor_digest"`
			SealedArtifactDigest string `json:"sealed_artifact_digest"`
			Target               struct {
				Domain string `json:"domain_id"`
				Name   string `json:"name"`
			} `json:"target"`
			Readback struct {
				Editable  string `json:"editable_digest"`
				Generated string `json:"generated_digest"`
			} `json:"readback"`
		} `json:"payload"`
		Delivery struct {
			Outcome     string   `json:"outcome"`
			Editable    string   `json:"editable_path"`
			Generated   string   `json:"generated_path"`
			Observation []string `json:"observation_paths"`
			Cleanup     bool     `json:"cleanup_failed"`
		} `json:"local_delivery"`
	}
	var fields map[string]json.RawMessage
	if result.Code != 0 || json.Unmarshal(result.Body, &product) != nil || json.Unmarshal(result.Body, &fields) != nil || product.Schema != "ProductResult/v1" || product.Operation != "set-confidential" || product.State != "success" || product.Effect != "not-applicable" || product.Output != "not-applicable" || product.OperationPayload != "SealedArtifactPayload/v1" || product.Evidence != "exact-local-pair-readback" || product.Payload == nil || product.Payload.Schema != product.OperationPayload {
		t.Fatal("local confidential set result refused")
	}
	for _, legacy := range []string{"outcome", "editable_path", "generated_path"} {
		if _, present := fields[legacy]; present {
			t.Fatal("local confidential set retained an obsolete result field")
		}
	}
	document := publicSourceDocument(t, source)
	ref, ok := document["generated"].(string)
	if !ok || ref == "" {
		t.Fatal("local confidential set generated reference unavailable")
	}
	generatedPath := filepath.Join(filepath.Dir(source), filepath.FromSlash(ref))
	image := publicSourceImage(t, source)
	var generated struct {
		FileID string `json:"file_id"`
		Domain struct {
			ID string `json:"id"`
		} `json:"domain"`
		Secrets map[string]struct {
			Sealed string `json:"sealed"`
		} `json:"secrets"`
	}
	if json.Unmarshal(image.Files[generatedPath], &generated) != nil {
		t.Fatal("local confidential set generated readback refused")
	}
	sealed, err := base64.StdEncoding.Strict().DecodeString(generated.Secrets[name].Sealed)
	defer clear(sealed)
	if err != nil || len(sealed) == 0 {
		t.Fatal("local confidential set sealed readback refused")
	}
	view, err := contract.InspectSealedInputEnvelope(sealed)
	if err != nil || !bytes.Equal(view.Core.Name, []byte(name)) || hex.EncodeToString(view.Core.FileIdentity[:]) != generated.FileID || hex.EncodeToString(view.Core.DomainID[:]) != generated.Domain.ID {
		t.Fatal("local confidential set sealed target differs")
	}
	payload, delivery := product.Payload, product.Delivery
	if payload.InputFileID != generated.FileID || payload.PredecessorDigest != hex.EncodeToString(view.Core.FilePredecessorDigest[:]) || payload.Target.Domain != generated.Domain.ID || payload.Target.Name != name || payload.SealedArtifactDigest != bodyDigest(sealed) || payload.Readback.Editable != bodyDigest(image.Files[source]) || payload.Readback.Generated != bodyDigest(image.Files[generatedPath]) || delivery.Outcome != "recorded" || delivery.Editable != source || delivery.Generated != generatedPath || len(delivery.Observation) != 0 || delivery.Cleanup {
		t.Fatal("local confidential set payload or native readback differs")
	}
}

func publicApplyUnchanged(product publicProductResult) bool {
	return product.State == "no-op" && product.payloadNull && product.Receipt == "" && !product.CommitUnknown
}

func publicApplyCommitUnknown(result publicChildResult, product publicProductResult) bool {
	return result.Code != 0 && product.State == "commit-outcome-unknown" && product.CommitUnknown && product.Receipt == ""
}

func publicApplyMatches(result publicChildResult, product publicProductResult, state string) bool {
	if product.Schema != "ProductResult/v1" || product.Operation != "apply-declaration" || product.State != state || product.Effect != "effect-no-change" || product.Output != "not-applicable" {
		return false
	}
	_, admittedIdentity := publicAdmittedRequestIdentity(product)
	switch state {
	case "success":
		return admittedIdentity && result.Code == 0 && !product.CommitUnknown && product.Payload.Schema == "TransitionPayload/v1" && product.Receipt != ""
	case "no-op":
		return admittedIdentity && result.Code == 0 && publicApplyUnchanged(product)
	case "contention", "refused":
		return result.Code != 0 && !product.CommitUnknown && product.Receipt == ""
	case "commit-outcome-unknown":
		return publicApplyCommitUnknown(result, product)
	default:
		return false
	}
}

func publicApplyHeadWrite(capture nativeprocess.Capture) (nativeprocess.Event, bool) {
	var start, returned nativeprocess.Event
	starts, returns := 0, 0
	for _, event := range capture.Events {
		if event.Operation != "head-write" {
			continue
		}
		switch event.Kind {
		case "http-start":
			start, starts = event, starts+1
		case "http-return":
			returned, returns = event, returns+1
		}
	}
	return returned, starts == 1 && returns == 1 && start.Sent && returned.Sent && start.Sequence != 0 && start.Sequence == returned.Sequence &&
		publicIdentityHex(start.ObjectKeySHA256) && start.ObjectKeySHA256 == returned.ObjectKeySHA256
}

func publicApplyCompetitionSettled(provider string, first, second publicChildResult, a, b publicProductResult) bool {
	if provider != "aws" && provider != "gcp" {
		return false
	}
	left, leftValid := publicApplyHeadWrite(first.Capture)
	right, rightValid := publicApplyHeadWrite(second.Capture)
	_, leftAdmitted := publicAdmittedRequestIdentity(a)
	_, rightAdmitted := publicAdmittedRequestIdentity(b)
	if !leftValid || !rightValid || !leftAdmitted || !rightAdmitted || left.ObjectKeySHA256 != right.ObjectKeySHA256 {
		return false
	}
	if publicApplyMatches(second, b, "success") && right.Status == 200 {
		first, second, a, b, left, right = second, first, b, a, right, left
	}
	if !publicApplyMatches(first, a, "success") || left.Status != 200 {
		return false
	}
	// A real S3 conflict can leave prior selection unproved even after another
	// candidate is observed. It cannot be relabelled as precondition refusal.
	return right.Status == 412 && publicApplyMatches(second, b, "contention") ||
		provider == "aws" && right.Status == 409 && publicApplyMatches(second, b, "commit-outcome-unknown")
}

// These independent CLI examples name the fields consumed by the live
// assertions. Receipt bytes are opaque to this consumer, not receipt fixtures.
const publicApplySelectedJSON = `{"schema":"ProductResult/v1","operation_id":"4444444444444444444444444444444444444444444444444444444444444444","request_identity":"5555555555555555555555555555555555555555555555555555555555555555","operation_kind":"apply-declaration","state_result":"success","effect_summary":"effect-no-change","output_summary":"not-applicable","commit_may_have_occurred":false,"evidence_ceiling":"canonical","payload":{"schema":"TransitionPayload/v1","predecessor_revision_id":"1111111111111111111111111111111111111111111111111111111111111111","requested_revision_id":"2222222222222222222222222222222222222222222222222222222222222222","observed_revision_id":"2222222222222222222222222222222222222222222222222222222222222222","changed_subject_commitment":{"count":1,"identity_root_digest":"3333333333333333333333333333333333333333333333333333333333333333"},"live_duty_ids":[],"live_hazard_ids":[]},"receipt_hex":"0102"}`

const publicApplyNoOpJSON = `{"schema":"ProductResult/v1","operation_id":"4444444444444444444444444444444444444444444444444444444444444444","request_identity":"5555555555555555555555555555555555555555555555555555555555555555","operation_kind":"apply-declaration","state_result":"no-op","effect_summary":"effect-no-change","output_summary":"not-applicable","commit_may_have_occurred":false,"evidence_ceiling":"canonical","payload":null}`

const publicApplyContentionJSON = `{"schema":"ProductResult/v1","operation_id":"4444444444444444444444444444444444444444444444444444444444444444","request_identity":"5555555555555555555555555555555555555555555555555555555555555555","operation_kind":"apply-declaration","state_result":"contention","effect_summary":"effect-no-change","output_summary":"not-applicable","commit_may_have_occurred":false,"evidence_ceiling":"unavailable","payload":null}`

const publicApplyUnknownJSON = `{"schema":"ProductResult/v1","operation_id":"4444444444444444444444444444444444444444444444444444444444444444","request_identity":"5555555555555555555555555555555555555555555555555555555555555555","operation_kind":"apply-declaration","state_result":"commit-outcome-unknown","effect_summary":"effect-no-change","output_summary":"not-applicable","commit_may_have_occurred":true,"evidence_ceiling":"unavailable","payload":null}`

const publicApplyRefusedJSON = `{"schema":"ProductResult/v1","operation_id":"4444444444444444444444444444444444444444444444444444444444444444","request_identity":"5555555555555555555555555555555555555555555555555555555555555555","operation_kind":"apply-declaration","state_result":"refused","effect_summary":"effect-no-change","output_summary":"not-applicable","commit_may_have_occurred":false,"evidence_ceiling":"unavailable","payload":null}`

// full_only: false
func TestPublicConfigurationApplyResultConsumer(t *testing.T) {
	for _, row := range []struct {
		name, body, state string
		code              int
		unchanged         bool
		unknown           bool
	}{
		{"selected", publicApplySelectedJSON, "success", 0, false, false},
		{"no-op", publicApplyNoOpJSON, "no-op", 0, true, false},
		{"contention", publicApplyContentionJSON, "contention", 1, false, false},
		{"unknown", publicApplyUnknownJSON, "commit-outcome-unknown", 1, false, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			result := publicChildResult{Code: row.code, Body: []byte(row.body)}
			product := publicProduct(t, result, "apply-declaration")
			if !publicApplyMatches(result, product, row.state) {
				t.Error("live apply helper refused the exact expected state")
			}
			if publicApplyUnchanged(product) != row.unchanged {
				t.Error("live apply consumer misclassified no-op")
			}
			if publicApplyCommitUnknown(result, product) != row.unknown {
				t.Error("live apply consumer misclassified commit uncertainty")
			}
		})
	}
	for _, row := range []struct {
		name, body, state string
		code              int
	}{
		{"success-expected-no-op", publicApplySelectedJSON, "no-op", 0},
		{"no-op-expected-success", publicApplyNoOpJSON, "success", 0},
		{"no-op-nonzero-exit", publicApplyNoOpJSON, "no-op", 1},
		{"no-op-object-payload", strings.Replace(publicApplyNoOpJSON, `"payload":null`, `"payload":{}`, 1), "no-op", 0},
		{"no-op-missing-payload", strings.Replace(publicApplyNoOpJSON, `,"payload":null`, ``, 1), "no-op", 0},
		{"no-op-receipt", strings.Replace(publicApplyNoOpJSON, `"payload":null`, `"payload":null,"receipt_hex":"0102"`, 1), "no-op", 0},
		{"no-op-unknown", strings.Replace(publicApplyNoOpJSON, `"commit_may_have_occurred":false`, `"commit_may_have_occurred":true`, 1), "no-op", 0},
		{"success-nonzero-exit", publicApplySelectedJSON, "success", 1},
		{"success-unknown", strings.Replace(publicApplySelectedJSON, `"commit_may_have_occurred":false`, `"commit_may_have_occurred":true`, 1), "success", 0},
		{"success-missing-receipt", strings.Replace(publicApplySelectedJSON, `,"receipt_hex":"0102"`, ``, 1), "success", 0},
		{"success-wrong-payload", strings.Replace(publicApplySelectedJSON, `"TransitionPayload/v1"`, `"InitPayload/v1"`, 1), "success", 0},
		{"contention-zero-exit", publicApplyContentionJSON, "contention", 0},
		{"contention-unknown", strings.Replace(publicApplyContentionJSON, `"commit_may_have_occurred":false`, `"commit_may_have_occurred":true`, 1), "contention", 1},
		{"unknown-zero-exit", publicApplyUnknownJSON, "commit-outcome-unknown", 0},
		{"unknown-flag-false", strings.Replace(publicApplyUnknownJSON, `"commit_may_have_occurred":true`, `"commit_may_have_occurred":false`, 1), "commit-outcome-unknown", 1},
		{"unknown-receipt", strings.Replace(publicApplyUnknownJSON, `"payload":null`, `"payload":null,"receipt_hex":"0102"`, 1), "commit-outcome-unknown", 1},
	} {
		t.Run(row.name, func(t *testing.T) {
			result := publicChildResult{Code: row.code, Body: []byte(row.body)}
			product := publicProduct(t, result, "apply-declaration")
			if publicApplyMatches(result, product, row.state) {
				t.Error("live apply helper accepted an inconsistent result")
			}
		})
	}
	for _, row := range []struct {
		name, first, second string
		firstCode, nextCode int
		settled             bool
	}{
		{"selected-contention", publicApplySelectedJSON, publicApplyContentionJSON, 0, 1, true},
		{"contention-selected", publicApplyContentionJSON, publicApplySelectedJSON, 1, 0, true},
		{"selected-unknown", publicApplySelectedJSON, publicApplyUnknownJSON, 0, 1, false},
		{"unknown-selected", publicApplyUnknownJSON, publicApplySelectedJSON, 1, 0, false},
		{"selected-refused", publicApplySelectedJSON, publicApplyRefusedJSON, 0, 1, false},
		{"two-selected", publicApplySelectedJSON, publicApplySelectedJSON, 0, 0, false},
		{"two-contentions", publicApplyContentionJSON, publicApplyContentionJSON, 1, 1, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			first := publicChildResult{Code: row.firstCode, Body: []byte(row.first)}
			second := publicChildResult{Code: row.nextCode, Body: []byte(row.second)}
			for _, child := range []*publicChildResult{&first, &second} {
				status := 412
				if child.Code == 0 {
					status = 200
				}
				child.Capture.Events = []nativeprocess.Event{
					{Kind: "http-start", Operation: "head-write", Sequence: 1, ObjectKeySHA256: strings.Repeat("a", 64), Sent: true},
					{Kind: "http-return", Operation: "head-write", Sequence: 1, ObjectKeySHA256: strings.Repeat("a", 64), Sent: true, Status: status},
				}
			}
			a := publicProduct(t, first, "apply-declaration")
			b := publicProduct(t, second, "apply-declaration")
			if publicApplyCompetitionSettled("aws", first, second, a, b) != row.settled {
				t.Error("live apply consumer did not require one selected result and one contention loser")
			}
		})
	}

	t.Run("competition-native-evidence", func(t *testing.T) {
		for _, provider := range []string{"aws", "gcp"} {
			t.Run(provider, func(t *testing.T) {
				for _, condition := range []string{
					"precondition", "conflict-unknown", "unknown-precondition", "contention-conflict",
					"unknown-zero-exit", "unknown-flag-false", "unknown-receipt", "unknown-wrong-operation",
					"unknown-wrong-schema", "unknown-wrong-effect", "unknown-wrong-output", "unknown-missing-identity", "unknown-provider",
					"missing-winner", "missing-loser", "extra-winner", "extra-loser",
					"unsent-winner-start", "unsent-winner-return", "unsent-loser-start", "unsent-loser-return",
					"mismatched-sequence", "mismatched-target", "different-target", "wrong-operation", "winner-conflict", "loser-server-error",
					"two-selected", "two-contentions", "two-unknowns",
				} {
					t.Run(condition, func(t *testing.T) {
						winner := publicChildResult{Code: 0, Body: []byte(publicApplySelectedJSON)}
						loser := publicChildResult{Code: 3, Body: []byte(publicApplyContentionJSON)}
						status := 412
						if strings.HasPrefix(condition, "unknown-") || condition == "conflict-unknown" || condition == "two-unknowns" {
							loser.Body, status = []byte(publicApplyUnknownJSON), 409
						}
						capture := func(status int) nativeprocess.Capture {
							return nativeprocess.Capture{Events: []nativeprocess.Event{
								{Kind: "http-start", Operation: "head-write", Sequence: 1, ObjectKeySHA256: strings.Repeat("a", 64), Sent: true},
								{Kind: "http-return", Operation: "head-write", Sequence: 1, ObjectKeySHA256: strings.Repeat("a", 64), Sent: true, Status: status},
							}}
						}
						winner.Capture, loser.Capture = capture(200), capture(status)
						switch condition {
						case "unknown-precondition":
							loser.Capture = capture(412)
						case "contention-conflict":
							loser.Capture = capture(409)
						case "unknown-zero-exit":
							loser.Code = 0
						case "unknown-flag-false":
							loser.Body = []byte(strings.Replace(publicApplyUnknownJSON, `"commit_may_have_occurred":true`, `"commit_may_have_occurred":false`, 1))
						case "unknown-receipt":
							loser.Body = []byte(strings.Replace(publicApplyUnknownJSON, `"payload":null`, `"payload":null,"receipt_hex":"0102"`, 1))
						case "unknown-wrong-operation":
							loser.Body = []byte(strings.Replace(publicApplyUnknownJSON, "apply-declaration", "initialize-empty-domain", 1))
						case "unknown-wrong-schema":
							loser.Body = []byte(strings.Replace(publicApplyUnknownJSON, "ProductResult/v1", "ProductResult/v2", 1))
						case "unknown-wrong-effect":
							loser.Body = []byte(strings.Replace(publicApplyUnknownJSON, "effect-no-change", "effect-changed", 1))
						case "unknown-wrong-output":
							loser.Body = []byte(strings.Replace(publicApplyUnknownJSON, "not-applicable", "success", 1))
						case "unknown-missing-identity":
							loser.Body = []byte(strings.Replace(publicApplyUnknownJSON, `"request_identity":"5555555555555555555555555555555555555555555555555555555555555555",`, ``, 1))
						case "missing-winner":
							winner.Capture.Events = nil
						case "missing-loser":
							loser.Capture.Events = nil
						case "extra-winner":
							winner.Capture.Events = append(winner.Capture.Events, winner.Capture.Events...)
						case "extra-loser":
							loser.Capture.Events = append(loser.Capture.Events, loser.Capture.Events...)
						case "unsent-winner-start":
							winner.Capture.Events[0].Sent = false
						case "unsent-winner-return":
							winner.Capture.Events[1].Sent = false
						case "unsent-loser-start":
							loser.Capture.Events[0].Sent = false
						case "unsent-loser-return":
							loser.Capture.Events[1].Sent = false
						case "mismatched-sequence":
							loser.Capture.Events[1].Sequence = 2
						case "mismatched-target":
							loser.Capture.Events[1].ObjectKeySHA256 = strings.Repeat("b", 64)
						case "different-target":
							for i := range loser.Capture.Events {
								loser.Capture.Events[i].ObjectKeySHA256 = strings.Repeat("b", 64)
							}
						case "wrong-operation":
							loser.Capture.Events[1].Operation = "store-write"
						case "winner-conflict":
							winner.Capture = capture(409)
						case "loser-server-error":
							loser.Capture = capture(503)
						case "two-selected":
							loser = winner
						case "two-contentions":
							winner = loser
						case "two-unknowns":
							winner = loser
						}
						var a, b publicProductResult
						if json.Unmarshal(winner.Body, &a) != nil || json.Unmarshal(loser.Body, &b) != nil {
							t.Fatal("independent competition fixture JSON refused")
						}
						selectedProvider := provider
						if condition == "unknown-provider" {
							selectedProvider = "unavailable"
						}
						want := condition == "precondition" || provider == "aws" && condition == "conflict-unknown"
						if publicApplyCompetitionSettled(selectedProvider, winner, loser, a, b) != want || publicApplyCompetitionSettled(selectedProvider, loser, winner, b, a) != want {
							t.Error("competition result and native evidence do not match the expected outcome in both child orders")
						}
					})
				}
			})
		}
	})
}

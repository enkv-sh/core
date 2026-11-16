package compositionfull

import (
	"context"
	"os"
	"reflect"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestProposedChangeCleanupRetainsAuthenticatedFacts(t *testing.T) {
	for _, refused := range []bool{false, true} {
		name := "completed-comparison"
		if refused {
			name = "independent-source-failure"
		}
		t.Run(name, func(t *testing.T) {
			result, h, baseline, candidate := proposedChangeComparison(t, func(editable, _ map[string]interface{}) {
				editable["entries"].(map[string]interface{})["a/\n雪"].(map[string]interface{})["source"].(map[string]interface{})["bytes"] = []byte{0, 10, 66}
			})
			if result.StateResult != contract.ReaderSuccess || result.Verdict != contract.ComparisonMismatch || result.Observation == nil {
				t.Fatal("fixture has no completed public change")
			}
			observation := *result.Observation
			baseline.assertUnchanged(t)
			candidate.assertUnchanged(t)
			if refused {
				result.StateResult, result.Verdict = contract.ReaderRefused, contract.ComparisonUnable
				result.Result = core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}
				result.Diagnostics = []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectStore}, Path: []contract.DiagnosticField{contract.FieldRegion}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonInvalidInput}}
			}
			// Use the existing captured-image owner. Its real second Close fails;
			// no production constructor, hook or alternate cleanup path is added.
			fileField := reflect.ValueOf(baseline.pair.Editable).Elem().FieldByName("file")
			if fileField.IsNil() {
				t.Fatal("captured image has no handle")
			}
			file := (*os.File)(fileField.UnsafePointer())
			if err := file.Close(); err != nil {
				t.Fatal("controlled captured-image close", err)
			}
			got := closeConfigurationComparison(context.Background(), contract.ID{1}, result, baseline.pair, candidate.pair)
			wantState := contract.ReaderUnavailable
			if refused {
				wantState = contract.ReaderRefused
			}
			if got.StateResult != wantState || got.Verdict != contract.ComparisonUnable || !got.DiagnosticsComplete || got.Observation == nil || *got.Observation != observation || !reflect.DeepEqual(got.InstallationRequirements, result.InstallationRequirements) {
				t.Fatal("cleanup erased completed facts or changed stronger failure")
			}
			if len(got.Diagnostics) != 1+len(result.Diagnostics) || got.Diagnostics[len(got.Diagnostics)-1].Reason != contract.ReasonEvidenceUnavailable {
				t.Fatal("cleanup lost its exact safe failure")
			}
			h.reset(true, "", 0)
			_, changes := proposedChangeJSON(t, got)
			assertProposedJSON(t, changes, `[{"subject":{"kind":"entry","name":"a/\n雪"},"path":[{"field":"plain_value"}],"action":"changed","before":{"state":"present","type":"bytes","value":{"base64":"AApB","byte_length":3}},"after":{"state":"present","type":"bytes","value":{"base64":"AApC","byte_length":3}}}]`)
			h.mu.Lock()
			reads := len(h.reads)
			h.mu.Unlock()
			if reads != 0 {
				t.Fatal("cleanup-result formatting reread state")
			}
			h.assertNoEffects(t)
		})
	}
}

package compositionfull

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestPlanningHumanSeparatesComparisonDimensions(t *testing.T) {
	id := contract.ID{1}
	r := ConfigurationPlanningResult{PlanningResult: core.PlanningResult{
		Context: core.ReaderOperationContext{Operation: contract.PlanningOperation}, StateResult: contract.ReaderSuccess,
		PlanningPayload: contract.PlanningPayload{ComparisonPayload: contract.ComparisonPayload{
			Observation: &contract.ComparisonObservation{DomainID: id, HeadRevisionID: id, SnapshotID: id}, Verdict: contract.ComparisonMismatch,
			DiagnosticsComplete: true, EvidenceLimit: contract.PlanningEvidenceLimit,
			CheckedScope: []contract.ComparisonScope{{Family: contract.ScopeSecretSettings, Status: contract.ScopeComplete}},
		}, PrivateComplete: true, DisplayDelivery: contract.PlanningNotRequested,
			PrivateEntries: []contract.PlanningRelation{{Name: "supplied\nvalue", Form: contract.PlanningSealed, Relation: contract.PlanningChanged, Code: contract.CryptoSuccess}}}},
		InstallationRequirements: InstallationRequirementComparison{Differences: []InstallationRequirementDifference{}}}
	body, err := RenderPlanningHuman(r)
	if err != nil || PlanningExitCode(r) != 1 {
		t.Fatal("complete private difference refused", err)
	}
	for _, want := range []string{"Public configuration: unchanged.", `Supplied secret "supplied\nvalue": changed`, "Private checks: complete.", "secret_settings: complete", "No changes were applied or published."} {
		if !bytes.Contains(body, []byte(want)) {
			t.Fatalf("missing independent result fact %q in %s", want, body)
		}
	}
	for _, unwanted := range []string{"Changes: 0", "private_entry: {", "scope: {"} {
		if strings.Contains(string(body), unwanted) {
			t.Fatal("structural or misleading summary remained", unwanted)
		}
	}
	r.StateResult, r.Verdict, r.PrivateComplete = contract.ReaderUnavailable, contract.ComparisonUnable, false
	r.PrivateEntries = append(r.PrivateEntries, contract.PlanningRelation{Name: "unchecked", Form: contract.PlanningSealed, Relation: contract.PlanningFailed, Code: contract.CryptoCustodyUnavailable})
	body, err = RenderPlanningHuman(r)
	if err != nil || PlanningExitCode(r) != 3 || !bytes.HasPrefix(body, []byte("Plan incomplete:")) || !bytes.Contains(body, []byte("Private checks: incomplete.")) || !bytes.Contains(body, []byte(`Supplied secret "supplied\nvalue": changed`)) {
		t.Fatal("incomplete check hid a known difference or lost failure precedence", err, string(body))
	}
}

// full_only: false
func TestPlanningResultRejectsContradictorySuccess(t *testing.T) {
	for _, condition := range []string{"unfinished-row", "incomplete-private", "failed-match", "changed-match", "unproved-mismatch", "retained-changed", "retained-new", "retained-unchecked", "completed-display-incomplete-private"} {
		t.Run(condition, func(t *testing.T) {
			id := contract.Hash([]byte("result observation"))
			result := ConfigurationPlanningResult{PlanningResult: core.PlanningResult{Context: core.ReaderOperationContext{Operation: contract.PlanningOperation}, StateResult: contract.ReaderSuccess, PlanningPayload: contract.PlanningPayload{ComparisonPayload: contract.ComparisonPayload{Observation: &contract.ComparisonObservation{DomainID: id, HeadRevisionID: id, SnapshotID: id}, Verdict: contract.ComparisonMatch, DiagnosticsComplete: true, EvidenceLimit: contract.PlanningEvidenceLimit}, PrivateComplete: true, DisplayDelivery: contract.PlanningNotRequested}}, InstallationRequirements: InstallationRequirementComparison{Differences: []InstallationRequirementDifference{}}}
			if _, err := RenderPlanningJSON(result); err != nil || PlanningExitCode(result) != 0 {
				t.Fatal("valid empty private scope refused")
			}
			switch condition {
			case "unfinished-row":
				result.PrivateEntries = []contract.PlanningRelation{{Name: "a", Form: contract.PlanningSealed, Relation: contract.PlanningUnchecked}}
			case "incomplete-private":
				result.PrivateComplete = false
			case "changed-match":
				result.PrivateEntries = []contract.PlanningRelation{{Name: "a", Form: contract.PlanningSealed, Relation: contract.PlanningChanged, Code: contract.CryptoSuccess}}
			case "unproved-mismatch":
				result.Verdict = contract.ComparisonMismatch
			case "retained-changed", "retained-new", "retained-unchecked":
				relation := contract.PlanningChanged
				result.Verdict = contract.ComparisonMismatch
				if condition == "retained-new" {
					relation = contract.PlanningNew
				}
				if condition == "retained-unchecked" {
					relation = contract.PlanningUnchecked
					result.Verdict = contract.ComparisonMatch
				}
				result.PrivateEntries = []contract.PlanningRelation{{Name: "a", Form: contract.PlanningRetained, Relation: relation, Code: contract.CryptoSuccess}}
			case "completed-display-incomplete-private":
				result.StateResult = contract.ReaderUnavailable
				result.Verdict = contract.ComparisonUnable
				result.PrivateComplete = false
				result.DisplayDelivery = contract.PlanningDeliveryComplete
				result.SelectedRecords = 1
				result.CompletedRecords = 1
				result.PrivateEntries = []contract.PlanningRelation{{Name: "a", Form: contract.PlanningSealed, Relation: contract.PlanningEqual, Code: contract.CryptoSuccess}}
			case "failed-match":
				result.StateResult = contract.ReaderRefused
				result.PrivateComplete = false
			}
			if _, err := RenderPlanningJSON(result); err == nil {
				t.Fatal("contradictory planning facts serialized as a valid result")
			}
			if code := PlanningExitCode(result); code != 2 {
				t.Fatal("contradictory planning facts received a pass or unavailable exit", code)
			}
		})
	}
}

// full_only: false
func TestPlanningResultPreservesIntentionalUncheckedScope(t *testing.T) {
	id := contract.Hash([]byte("unchecked observation"))
	result := ConfigurationPlanningResult{PlanningResult: core.PlanningResult{Context: core.ReaderOperationContext{Operation: contract.PlanningOperation}, StateResult: contract.ReaderSuccess, PlanningPayload: contract.PlanningPayload{ComparisonPayload: contract.ComparisonPayload{Observation: &contract.ComparisonObservation{DomainID: id, HeadRevisionID: id, SnapshotID: id}, Verdict: contract.ComparisonMatch, DiagnosticsComplete: true, EvidenceLimit: contract.PlanningEvidenceLimit}, PrivateComplete: true, DisplayDelivery: contract.PlanningNotRequested, PrivateEntries: []contract.PlanningRelation{{Name: "a", Form: contract.PlanningSealed, Relation: contract.PlanningUnchecked, Code: contract.CryptoSuccess}}}}, InstallationRequirements: InstallationRequirementComparison{Differences: []InstallationRequirementDifference{}}}
	if _, err := RenderPlanningJSON(result); err != nil || PlanningExitCode(result) != 0 {
		t.Fatal("intentional unchecked scope became an unfinished check")
	}
}

// full_only: false
func TestPlanningCleanupPreservesCompletedPrivateAndDisplayFacts(t *testing.T) {
	for _, state := range []contract.ReaderStateResult{contract.ReaderSuccess, contract.ReaderRefused} {
		t.Run(string(state), func(t *testing.T) {
			id := contract.Hash([]byte("cleanup observation"))
			out := ConfigurationPlanningResult{PlanningResult: core.PlanningResult{Context: core.ReaderOperationContext{Operation: contract.PlanningOperation, RequestID: id, ExpectedDomain: id}, StateResult: state, PlanningPayload: contract.PlanningPayload{ComparisonPayload: contract.ComparisonPayload{Observation: &contract.ComparisonObservation{DomainID: id, HeadRevisionID: id, SnapshotID: id}, Verdict: contract.ComparisonMatch, DiagnosticsComplete: true, EvidenceLimit: contract.PlanningEvidenceLimit}, PrivateComplete: true, DisplayDelivery: contract.PlanningDeliveryComplete, SelectedRecords: 1, CompletedRecords: 1, PrivateEntries: []contract.PlanningRelation{{Name: "a", Form: contract.PlanningSealed, Relation: contract.PlanningEqual, Code: contract.CryptoSuccess}}}}, InstallationRequirements: InstallationRequirementComparison{Differences: []InstallationRequirementDifference{}}}
			if state == contract.ReaderRefused {
				out.Verdict = contract.ComparisonUnable
				out.DisplayDelivery = contract.PlanningDeliveryIncomplete
			}
			out.InstallationRequirements = InstallationRequirementComparison{Complete: true, Differences: []InstallationRequirementDifference{{Name: "generic-json", Trusted: &InstallationRequirement{}, Candidate: &InstallationRequirement{Version: "1.0.0"}}}}
			if state == contract.ReaderSuccess {
				out.Verdict = contract.ComparisonMismatch
			}
			out.Changes = []contract.ComparisonChange{proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "public"}, contract.FieldPlainValue, contract.ComparisonBytes{0, 10, 65}, contract.ComparisonBytes{0, 10, 66})}
			label := ""
			out.BeforeRecipients = []contract.ComparisonRecipientLabel{{RecipientID: contract.ID{1}, DisplayName: &label}}
			out.AfterRecipients = []contract.ComparisonRecipientLabel{{RecipientID: contract.ID{1}, DisplayName: &label}}
			got := configurationPlanningCleanup(context.Background(), id, out, errors.New("controlled cleanup failure"))
			if !reflect.DeepEqual(got.InstallationRequirements, out.InstallationRequirements) || !reflect.DeepEqual(got.Changes, out.Changes) || !reflect.DeepEqual(got.BeforeRecipients, out.BeforeRecipients) || !reflect.DeepEqual(got.AfterRecipients, out.AfterRecipients) {
				t.Fatal("source cleanup erased completed installation preferences")
			}
			if !got.PrivateComplete || got.DisplayDelivery != out.DisplayDelivery || got.SelectedRecords != out.SelectedRecords || got.CompletedRecords != out.CompletedRecords || !reflect.DeepEqual(got.PrivateEntries, out.PrivateEntries) || !reflect.DeepEqual(got.Observation, out.Observation) || got.Verdict != contract.ComparisonUnable {
				t.Fatal("source cleanup erased authenticated checks or actual disclosure facts")
			}
			want := contract.ReaderUnavailable
			if state == contract.ReaderRefused {
				want = contract.ReaderRefused
			}
			if got.StateResult != want {
				t.Fatal("cleanup changed stronger failure precedence")
			}
		})
	}
}

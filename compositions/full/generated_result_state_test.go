package compositionfull

import (
	"bytes"
	"fmt"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedStateVocabularyIsClosed(t *testing.T) {
	for _, state := range []string{"success", "no-op", "exact-resume", "possible-live-residue-accepted", "retirement-pending", "effect-pending", "effect-partial", "effect-unknown", "effect-terminal-failure", "contention", "commit-outcome-unknown", "positive-defect", "unavailable", "refused", "snapshot-size-refusal"} {
		if !validGeneratedState(state) {
			t.Errorf("supported generated state was refused: %q", state)
		}
	}
	for _, state := range []string{"", "invented-state", "gc-partial-garbage", "root-loss-unsupported"} {
		if validGeneratedState(state) {
			t.Errorf("unavailable generated state was admitted: %q", state)
		}
	}
}

// full_only: false
func TestGeneratedNonselectionCannotRenderSelectedCanonicalOutcome(t *testing.T) {
	for _, test := range []struct {
		name      string
		operation uint16
		outcome   core.Outcome
		state     string
	}{
		{"apply-contention", contract.OperationApplyDeclaration, core.Contention, "contention"},
		{"apply-unknown", contract.OperationApplyDeclaration, core.UnresolvedCommit, "commit-outcome-unknown"},
		{"apply-refusal", contract.OperationApplyDeclaration, core.AdmissionRefused, "refused"},
		{"apply-unavailable", contract.OperationApplyDeclaration, core.EvidenceUnavailable, "unavailable"},
		{"apply-integrity", contract.OperationApplyDeclaration, core.IntegrityFailure, "positive-defect"},
		{"apply-no-op", contract.OperationApplyDeclaration, core.Unchanged, "no-op"},
		{"retirement-contention", contract.OperationRetireGeneratedGeneration, core.Contention, "contention"},
		{"risk-contention", contract.OperationAcceptGeneratedRetirementResidue, core.Contention, "contention"},
	} {
		t.Run(test.name, func(t *testing.T) {
			id := contract.ID{1}
			r := core.PublicApplyResult{RequestID: id, OperationID: id, RequestIdentity: id, DomainID: id,
				Result: core.Result{Outcome: test.outcome, CommitMayHaveOccurred: test.outcome == core.UnresolvedCommit},
				Generated: &core.GeneratedInvocationResult{OperationKind: test.operation, StateResult: test.state,
					CanonicalOutcome: contract.ReceiptCanonicalNotSelected, EffectSummary: contract.ReceiptEffectNoChange,
					EvidenceCeiling: contract.ReceiptEvidenceCanonical}}
			if test.outcome == core.UnresolvedCommit {
				r.Result.RequestedRevision = id
			}
			for _, render := range []func(core.PublicApplyResult, uint16) ([]byte, error){RenderGeneratedMutationJSON, RenderGeneratedMutationHuman} {
				if body, err := render(r, test.operation); err != nil || len(body) == 0 {
					t.Fatal("coherent nonselection refused", err)
				}
				r.Generated.CanonicalOutcome = contract.ReceiptCanonicalSelected
				if body, err := render(r, test.operation); err == nil || body != nil {
					t.Fatal("nonselection claimed canonical selection")
				}
				r.Generated.CanonicalOutcome = contract.ReceiptCanonicalNotSelected
			}
		})
	}
}

// full_only: false
func TestGeneratedHumanHazardWarningNamesEachExactIdentity(t *testing.T) {
	id := contract.ID{1}
	hazard := generatedRendererHazard()
	hazard.Record.HazardID = contract.ID{2}
	hazard.Record.OriginalAttemptID = contract.ID{3}
	hazard.Target.OriginalAttemptID = hazard.Record.OriginalAttemptID
	hazard.Record.ResourceID, hazard.Target.ResourceID = contract.ID{4}, contract.ID{4}
	hazard.Record.ConfigContractID, hazard.Target.ConfigContractID = contract.ID{5}, contract.ID{5}
	hazard.Record.CredentialRouteID = contract.ID{6}
	hazard.Record.ResourceContractID, hazard.Target.ResourceContractID, hazard.Target.ResourceDigest = contract.ID{7}, contract.ID{7}, contract.ID{8}
	view := &core.GeneratedListView{DomainID: id, RevisionID: id, SnapshotID: id, Hazards: []core.GeneratedHazardFact{hazard}, Warnings: hazard.Warnings}
	r := core.PublicGeneratedListResult{Context: core.ReaderOperationContext{Operation: core.GeneratedListOperation, RequestID: id, ExpectedDomain: id},
		Result: core.Result{Outcome: core.ObservedCurrent, Evidence: core.AuthenticatedClosure, ObservedRevision: id, ObservedSnapshotID: id}, StateResult: contract.ReaderSuccess, View: view}
	body, err := RenderGeneratedListHuman(r)
	if err != nil {
		t.Fatal(err)
	}
	at := bytes.Index(body, []byte("Warning: The old effect can still be live."))
	if at < 0 {
		t.Fatal("human hazard warning missing")
	}
	warning := body[at:]
	for _, line := range []string{
		fmt.Sprintf("Hazard ID: %x; Attempt ID: %x; resource incarnation ID: %x; evidence ceiling: canonical.\n", hazard.Record.HazardID, hazard.Record.OriginalAttemptID, hazard.Record.ResourceID),
		fmt.Sprintf("Descriptor ID: %x; credential route ID: %x.\n", hazard.Record.DescriptorID, hazard.Record.CredentialRouteID),
		fmt.Sprintf("Resource contract ID: %x; resource digest: %x.\n", hazard.Target.ResourceContractID, hazard.Target.ResourceDigest),
	} {
		if !bytes.Contains(warning, []byte(line)) {
			t.Fatal("warning lost a named identity", line)
		}
	}
}

// full_only: false
func TestGeneratedTerminalFailureKeepsFrozenAndSelectedRevisions(t *testing.T) {
	for _, operation := range []uint16{contract.OperationApplyDeclaration, contract.OperationRotateValueEntryValue, contract.OperationRetireGeneratedGeneration} {
		for _, unknown := range []bool{false, true} {
			t.Run(fmt.Sprintf("operation-%d/unknown-%t", operation, unknown), func(t *testing.T) {
				r := suppliedApplyResultFixture(t)
				row, err := contract.InspectCompactMutationReceipt(r.Receipt)
				if err != nil {
					t.Fatal(err)
				}
				effect := generatedRendererEffect()
				effect.Record.OperationID = r.OperationID
				effect.Record.State, effect.Record.Stage = contract.GeneratedEffectFailedTerminal, contract.GeneratedStageTerminal
				effect.SummaryClass = contract.ReceiptSummaryFailureCount
				row.OperationKind, row.StateResult = operation, contract.ReceiptStateEffectTerminalFailure
				row.EffectSummary, row.EvidenceCeiling = contract.ReceiptEffectFailed, contract.ReceiptEvidenceProviderFacts
				state := "effect-terminal-failure"
				if unknown {
					state = "effect-unknown"
					effect.Record.State, effect.SummaryClass = contract.GeneratedEffectUnknown, contract.ReceiptSummaryUnknownCount
					row.StateResult, row.EffectSummary, row.UnknownCount = contract.ReceiptStateEffectUnknown, contract.ReceiptEffectUnknown, 1
				}
				if operation == contract.OperationRetireGeneratedGeneration {
					effect.Action = contract.GeneratorActionDelete
				}
				row.CanonicalOutcome, row.ObservedRevisionID = contract.ReceiptCanonicalNotSelected, contract.ID{20}
				row.SummaryCounts[contract.ReceiptEffectCount], row.SummaryCounts[effect.SummaryClass] = 1, 1
				r.Payload.ObservedRevisionID = contract.ID{20}
				r.Receipt, err = contract.EncodeCompactMutationReceipt(row)
				if err != nil {
					t.Fatal(err)
				}
				r.Generated = &core.GeneratedInvocationResult{OperationKind: operation, StateResult: state,
					CanonicalOutcome: row.CanonicalOutcome, EffectSummary: row.EffectSummary, EvidenceCeiling: row.EvidenceCeiling,
					SummaryCountsAvailable: true, SummaryCounts: row.SummaryCounts, UnknownCount: row.UnknownCount,
					EffectsAvailable: true, Effects: []core.GeneratedEffectFact{effect}, RelatedWorkAvailable: true}
				for mode, render := range []func(core.PublicApplyResult, uint16) ([]byte, error){RenderGeneratedMutationJSON, RenderGeneratedMutationHuman} {
					body, err := render(r, operation)
					if err != nil || !bytes.Contains(body, []byte(readerID(contract.ID{5}))) || !bytes.Contains(body, []byte(readerID(contract.ID{20}))) {
						t.Error("terminal result lost selected closure or frozen canonical observation", err)
					}
					if mode == 1 {
						for _, want := range []string{"Observed revision: " + readerID(contract.ID{5}) + "\n", "Original receipt observed revision: " + readerID(contract.ID{20}) + "\n"} {
							if !bytes.Contains(body, []byte(want)) {
								t.Error("human result merged current selection with original receipt observation", want)
							}
						}
					}
					for _, damage := range []string{"invocation-requested", "invocation-observed", "payload-requested", "payload-observed", "request", "domain", "unauthenticated", "unknown-commit"} {
						broken := r
						payload := *r.Payload
						broken.Payload = &payload
						switch damage {
						case "invocation-requested":
							broken.Result.RequestedRevision = contract.ID{99}
						case "invocation-observed":
							broken.Result.ObservedRevision = contract.ID{99}
						case "payload-requested":
							payload.RequestedRevisionID = contract.ID{99}
						case "payload-observed":
							payload.ObservedRevisionID = contract.ID{99}
						case "request":
							broken.RequestIdentity = contract.ID{99}
						case "domain":
							broken.DomainID = contract.ID{99}
						case "unauthenticated":
							broken.Result.Evidence = 0
						case "unknown-commit":
							broken.Result.Outcome, broken.Result.CommitMayHaveOccurred = core.UnresolvedCommit, true
						}
						if body, err := render(broken, operation); err == nil || body != nil {
							t.Error("terminal result admitted contradictory identities", damage)
						}
					}
				}
			})
		}
	}
}

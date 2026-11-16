package compositionfull

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func generatedRendererTarget() contract.GeneratorTarget {
	id := contract.ID{1}
	return contract.GeneratorTarget{Schema: 2, LifecycleMode: contract.GeneratorLifecycleManaged, Name: "generated", IncarnationID: id, ResourceID: id, ResourceDigest: id, ConfigContractID: id, ResourceContractID: id, OriginalOperationID: id, OriginalAttemptID: id, ResultContractID: id, CompletionClass: contract.GeneratedCompletionAcknowledged}
}
func generatedRendererDuty() core.GeneratedDutyFact {
	id := contract.ID{1}
	d := contract.GeneratorDescriptor{Digest: id, Length: 4}
	r := contract.GeneratedDutyRecord{Schema: 3, LifecycleMode: contract.GeneratorLifecycleManaged, DomainID: id, DutyID: id, OriginalOperationID: id, OriginalAttemptID: id, OwnerID: id, ResourceID: id, ConfigContractID: id, ResourceContractID: id, ExecutorID: id, CredentialRouteID: id, DescriptorID: id, ResultContractID: id, Kind: contract.GeneratedDutyRetirement, CompletionClass: contract.GeneratedCompletionAcknowledged, Step: 1, Status: contract.GeneratedEffectNotStarted, CapacityReservation: d, Target: d, Progress: d, History: d, Support: d, Consumers: d}
	target := generatedRendererTarget()
	return core.GeneratedDutyFact{Record: r, Target: &target, EvidenceCeiling: contract.ReceiptEvidenceCanonical}
}
func generatedRendererEffect() core.GeneratedEffectFact {
	id := contract.ID{1}
	d := contract.GeneratorDescriptor{Digest: id, Length: 4}
	r := contract.GeneratedAttemptRecord{Schema: 3, LifecycleMode: contract.GeneratorLifecycleManaged, DomainID: id, OperationID: id, LineageID: id, AttemptID: id, TemplateDigest: id, OwnerID: id, ResourceID: id, TransmissionID: id, ResultID: id, InboxID: id, ConfigContractID: id, ResourceContractID: id, ExecutorID: id, CredentialRouteID: id, DescriptorID: id, ResultContractID: id, RequestDigest: id, State: contract.GeneratedEffectUnknown, Stage: contract.GeneratedStageRetainedResult, CompletionClass: contract.GeneratedCompletionAcknowledged, Facts: d, Progress: d, Support: d, History: d}
	target := generatedRendererTarget()
	return core.GeneratedEffectFact{Record: r, Action: contract.GeneratorActionCreate, Name: target.Name, EntryIncarnationID: id, PlannedValueSlotID: id, ResourceDigest: id, Target: &target, EvidenceCeiling: contract.ReceiptEvidenceProviderFacts, SummaryClass: contract.ReceiptSummaryUnknownCount}
}

func generatedRendererRelease(record contract.PendingInboxReleaseRecord) (core.GeneratedPendingResultCleanup, core.GeneratedEffectFact) {
	effect := generatedRendererEffect()
	effect.Record.DomainID, effect.Record.InboxID, effect.Record.ResultID = record.DomainID, record.InboxID, record.OriginalResultID
	effect.Record.Stage, effect.Record.State = contract.GeneratedStageTerminal, contract.GeneratedEffectSucceeded
	effect.SummaryClass = contract.ReceiptSummarySuccessCount
	row := core.GeneratedPendingResultCleanup{PendingInboxReleaseRecord: record, OriginalOperationID: effect.Record.OperationID, OriginalAttemptID: effect.Record.AttemptID, Action: effect.Action, EffectState: effect.Record.State, CompletionClass: effect.Record.CompletionClass, EffectIndex: 0}
	return row, effect
}

func generatedRendererHazard() core.GeneratedHazardFact {
	v := generatedRendererDuty()
	r := v.Record
	return core.GeneratedHazardFact{Record: contract.GeneratedHazardRecord{Schema: 2, DomainID: r.DomainID, HazardID: r.DutyID, OriginalOperationID: r.OriginalOperationID, OriginalAttemptID: r.OriginalAttemptID, OwnerID: r.OwnerID, ResourceID: r.ResourceID, ConfigContractID: r.ConfigContractID, ResourceContractID: r.ResourceContractID, ExecutorID: r.ExecutorID, CredentialRouteID: r.CredentialRouteID, DescriptorID: r.DescriptorID, ResultContractID: r.ResultContractID, Exposure: contract.GeneratedExposurePossibleLive, CompletionClass: r.CompletionClass, Fenced: 1, Eligibility: contract.GeneratedExposurePossibleLive, CapacityReservation: r.CapacityReservation, OriginalResults: r.History, Target: r.Target, History: r.History, Support: r.Support, Consumers: r.Consumers}, Target: v.Target, EvidenceCeiling: contract.ReceiptEvidenceCanonical, Warnings: core.GeneratedResultWarnings{PossibleLiveResidue: true}}
}

// full_only: false
func TestGeneratedHumanWarningsRemainVisibleAfterFrontierSuccess(t *testing.T) {
	r := suppliedApplyResultFixture(t)
	r.Receipt = nil
	hazard := generatedRendererHazard()
	r.Payload.LiveHazardIDs = []contract.ID{hazard.Record.HazardID}
	r.Generated = &core.GeneratedInvocationResult{OperationKind: contract.OperationApplyDeclaration, StateResult: "success", CanonicalOutcome: contract.ReceiptCanonicalSelected, EffectSummary: contract.ReceiptEffectNoChange, EvidenceCeiling: contract.ReceiptEvidenceCanonical, SummaryCountsAvailable: true, EffectsAvailable: true, RelatedWorkAvailable: true, RelatedHazardIDs: []contract.ID{hazard.Record.HazardID}, Hazards: []core.GeneratedHazardFact{hazard}, Warnings: hazard.Warnings}
	r.Generated.SummaryCounts[contract.ReceiptHazardCount] = 1
	human, err := RenderApplyHuman(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"The old effect can still be live.", "A succeeded frontier does not close this hazard.", "No qualified cleanup path is available.", readerID(hazard.Record.HazardID), readerID(hazard.Record.OriginalAttemptID), readerID(hazard.Record.ResourceID)} {
		if !bytes.Contains(human, []byte(want)) {
			t.Fatal("human result lost the required hazard warning", want)
		}
	}
}

// full_only: false
func TestGeneratedUnknownReservationDoesNotRenderInventedCounts(t *testing.T) {
	r := suppliedApplyResultFixture(t)
	r.Receipt, r.Payload = nil, nil
	r.Result.Outcome, r.Result.CommitMayHaveOccurred = core.UnresolvedCommit, true
	r.Generated = &core.GeneratedInvocationResult{OperationKind: contract.OperationApplyDeclaration, StateResult: "commit-outcome-unknown", CanonicalOutcome: contract.ReceiptCanonicalNotSelected, EffectSummary: contract.ReceiptEffectNoChange, EvidenceCeiling: contract.ReceiptEvidenceCanonical}
	for mode, render := range []func(core.PublicApplyResult) ([]byte, error){RenderApplyJSON, RenderApplyHuman} {
		body, err := render(r)
		if err != nil {
			t.Fatal(err)
		}
		if mode == 1 {
			if !bytes.Contains(body, []byte("Summary counts are unavailable.\n")) || bytes.Contains(body, []byte("Deletion acknowledgements:")) || bytes.Contains(body, []byte("confirmed invalidations:")) || bytes.Contains(body, []byte("unknown results:")) {
				t.Fatal("human unavailable counts became numeric facts")
			}
			continue
		}
		if !bytes.Contains(body, []byte(`"summary_counts": null`)) && !bytes.Contains(body, []byte("summary_counts: null")) {
			t.Fatal("unavailable reservation counts became known empty counts")
		}
		for _, name := range []string{"deletion_acknowledged_count", "invalidation_confirmed_count", "unknown_count"} {
			if !bytes.Contains(body, []byte(`"`+name+`": null`)) && !bytes.Contains(body, []byte(name+": null")) {
				t.Fatal("unavailable reservation count became zero", name)
			}
		}
	}
}

// full_only: false
func TestGeneratedResultSeparatesRelatedHandoffsFromDomainWork(t *testing.T) {
	r := suppliedApplyResultFixture(t)
	duty := generatedRendererDuty()
	r.Payload.LiveDutyIDs = []contract.ID{duty.Record.DutyID, {2}}
	row, err := contract.InspectCompactMutationReceipt(r.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	row.StateResult = contract.ReceiptStateRetirementPending
	row.SummaryCounts[contract.ReceiptDutyCount] = 2
	r.Receipt, err = contract.EncodeCompactMutationReceipt(row)
	if err != nil {
		t.Fatal(err)
	}
	r.Generated = &core.GeneratedInvocationResult{OperationKind: contract.OperationApplyDeclaration, StateResult: "retirement-pending", CanonicalOutcome: contract.ReceiptCanonicalSelected, EffectSummary: contract.ReceiptEffectNoChange, EvidenceCeiling: contract.ReceiptEvidenceCanonical, SummaryCountsAvailable: true, EffectsAvailable: true, RelatedWorkAvailable: true, RelatedDutyIDs: []contract.ID{duty.Record.DutyID}, Duties: []core.GeneratedDutyFact{duty}, SummaryCounts: row.SummaryCounts}
	body, err := RenderApplyJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if string(got["state_result"]) != `"retirement-pending"` || !bytes.Contains(got["summary_counts"], []byte(`"duties": 2`)) || !resultJSONFactsEqual(got["related_duty_ids"], []byte(`["`+readerID(duty.Record.DutyID)+`"]`)) {
		t.Fatal("related/global result lost", string(body))
	}
	human, err := RenderApplyHuman(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Related duty: " + readerID(duty.Record.DutyID) + "\n", "Current duty: " + readerID(contract.ID{1}) + "\n", "Current duty: " + readerID(contract.ID{2}) + "\n", "An exact stored mutation receipt is available.\n"} {
		if !bytes.Contains(human, []byte(want)) {
			t.Fatal("human result lost related/current work or receipt availability", want, string(human))
		}
	}
	if bytes.Contains(human, []byte(hex.EncodeToString(r.Receipt))) {
		t.Fatal("human result exposed encoded receipt backing")
	}
	if string(got["receipt_hex"]) != `"`+hex.EncodeToString(r.Receipt)+`"` {
		t.Fatal("JSON result lost exact stored receipt")
	}

	r.Generated.RelatedDutyIDs[0] = contract.ID{9}
	if body, err := RenderApplyJSON(r); err == nil || body != nil {
		t.Fatal("contradictory related duty escaped")
	}
}

// full_only: false
func TestGeneratedReceiptObservationDoesNotInventCompleteVectors(t *testing.T) {
	r := suppliedApplyResultFixture(t)
	row, _ := contract.InspectCompactMutationReceipt(r.Receipt)
	r.Generated = &core.GeneratedInvocationResult{OperationKind: row.OperationKind, StateResult: "success", CanonicalOutcome: row.CanonicalOutcome, EffectSummary: row.EffectSummary, EvidenceCeiling: row.EvidenceCeiling, SummaryCountsAvailable: true, SummaryCounts: row.SummaryCounts, ReceiptObservation: true}
	r.Result.RequestedRevision = contract.ID{}
	r.Result.ObservedRevision = contract.ID{99}
	r.WarningBits = core.WarningLateDestructiveEffect
	body, err := RenderApplyJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"summary_counts_available": true`, `"summary_counts": {`, `"effects_available": false`, `"effects": null`, `"related_work_available": false`, `"duties": null`, `"observed_revision_id": "` + readerID(contract.ID{99}) + `"`, `"receipt_hex": "` + hex.EncodeToString(r.Receipt) + `"`} {
		if !bytes.Contains(body, []byte(want)) {
			t.Fatal("receipt observation lost fact", want)
		}
	}
	for _, damage := range []string{"vector", "identity", "summary", "cleanup receipt"} {
		t.Run(damage, func(t *testing.T) {
			copy := r
			g := *r.Generated
			copy.Generated = &g
			switch damage {
			case "vector":
				g.EffectsAvailable = true
			case "identity":
				copy.RequestIdentity = contract.ID{88}
			case "summary":
				g.SummaryCounts[contract.ReceiptEffectCount] = 1
			case "cleanup receipt":
				g.OperationKind = contract.OperationCleanOwnedFailureResidue
			}
			if b, e := RenderGeneratedMutationJSON(copy, g.OperationKind); e == nil || b != nil {
				t.Fatal("contradiction accepted")
			}
		})
	}
}

// full_only: false
func TestGeneratedHumanReceiptWarningsKeepOriginalMeaning(t *testing.T) {
	r := suppliedApplyResultFixture(t)
	row, err := contract.InspectCompactMutationReceipt(r.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	row.WarningBits, err = contract.EncodeReceiptWarningBits(row.OperationKind, core.WarningPublicationOrderValue, 0)
	if err != nil {
		t.Fatal(err)
	}
	r.Receipt, err = contract.EncodeCompactMutationReceipt(row)
	if err != nil {
		t.Fatal(err)
	}
	r.Generated = &core.GeneratedInvocationResult{OperationKind: row.OperationKind, StateResult: "success", CanonicalOutcome: row.CanonicalOutcome, EffectSummary: row.EffectSummary, EvidenceCeiling: row.EvidenceCeiling, SummaryCountsAvailable: true, SummaryCounts: row.SummaryCounts, ReceiptObservation: true}
	r.Result.RequestedRevision = contract.ID{}
	r.Result.ObservedRevision = contract.ID{99}
	if _, err := RenderApplyJSON(r); err != nil {
		t.Fatal("original receipt control refused", err)
	}
	body, err := RenderApplyHuman(r)
	if err != nil || !bytes.Contains(body, []byte("Original receipt warning: An old publication may replace a newer value.")) || bytes.Contains(body, []byte("Immutable store garbage may remain")) || bytes.Contains(body, []byte("Stored receipt bytes")) {
		t.Fatal("original warning bits changed meaning", err, string(body))
	}
}

// full_only: false
func TestGeneratedMutationKeepsEffectsOnUnknownCommit(t *testing.T) {
	r := suppliedApplyResultFixture(t)
	r.Receipt = nil
	fact := generatedRendererEffect()
	r.Generated = &core.GeneratedInvocationResult{OperationKind: contract.OperationApplyDeclaration, StateResult: "commit-outcome-unknown", CanonicalOutcome: contract.ReceiptCanonicalNotSelected, EffectSummary: contract.ReceiptEffectUnknown, EvidenceCeiling: contract.ReceiptEvidenceProviderFacts, SummaryCountsAvailable: true, EffectsAvailable: true, Effects: []core.GeneratedEffectFact{fact}, RelatedWorkAvailable: true, UnknownCount: 1}
	r.Generated.SummaryCounts[contract.ReceiptEffectCount] = 1
	r.Generated.SummaryCounts[contract.ReceiptSummaryUnknownCount] = 1
	r.Result.Outcome = core.UnresolvedCommit
	r.Result.CommitMayHaveOccurred = true
	body, err := RenderApplyJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"canonical_outcome": "not-selected"`, `"commit_may_have_occurred": true`, `"state": "unknown"`, `"generation_id": null`} {
		if !bytes.Contains(body, []byte(want)) {
			t.Fatal("unknown result promoted or discarded effects", want)
		}
	}
	for _, condition := range []string{"success-state", "missing-commit-flag", "missing-requested-revision", "observed-with-unknown-state", "observed-with-contention-state", "missing-unknown-count", "extra-unknown-count", "acknowledged-unknown", "confirmed-unknown", "acknowledged-failed", "confirmed-failed", "succeeded-create"} {
		t.Run(condition, func(t *testing.T) {
			invalid := r
			generated := *r.Generated
			invalid.Generated = &generated
			generated.Effects = []core.GeneratedEffectFact{fact}
			switch condition {
			case "success-state":
				generated.StateResult = "success"
			case "missing-commit-flag":
				invalid.Result.CommitMayHaveOccurred = false
			case "missing-requested-revision":
				invalid.Result.RequestedRevision = contract.ID{}
				invalid.Payload = nil
			case "observed-with-unknown-state":
				invalid.Result.Outcome = core.ObservedCurrent
				invalid.Result.CommitMayHaveOccurred = false
			case "observed-with-contention-state":
				invalid.Result.Outcome = core.ObservedCurrent
				invalid.Result.CommitMayHaveOccurred = false
				generated.StateResult = "contention"
			case "missing-unknown-count":
				generated.UnknownCount = 0
			case "extra-unknown-count":
				generated.UnknownCount = 2
			case "acknowledged-unknown":
				generated.AcknowledgedCount = 1
			case "confirmed-unknown":
				generated.ConfirmedCount = 1
			case "acknowledged-failed", "confirmed-failed", "succeeded-create":
				generated.UnknownCount = 0
				generated.SummaryCounts[contract.ReceiptSummaryUnknownCount] = 0
				generated.Effects[0].Record.Stage = contract.GeneratedStageTerminal
				if condition == "succeeded-create" {
					generated.EffectSummary = contract.ReceiptEffectComplete
					generated.SummaryCounts[contract.ReceiptSummarySuccessCount] = 1
					generated.Effects[0].SummaryClass = contract.ReceiptSummarySuccessCount
					generated.Effects[0].Record.State = contract.GeneratedEffectSucceeded
				} else {
					generated.EffectSummary = contract.ReceiptEffectFailed
					generated.SummaryCounts[contract.ReceiptSummaryFailureCount] = 1
					generated.Effects[0].SummaryClass = contract.ReceiptSummaryFailureCount
					generated.Effects[0].Record.State = contract.GeneratedEffectFailedTerminal
					if condition == "acknowledged-failed" {
						generated.AcknowledgedCount = 1
					} else {
						generated.ConfirmedCount = 1
					}
				}
			}
			for _, render := range []func(core.PublicApplyResult) ([]byte, error){RenderApplyJSON, RenderApplyHuman} {
				body, err := render(invalid)
				if condition == "succeeded-create" {
					if err != nil || body == nil {
						t.Fatal("successful create required a delete completion count", err)
					}
				} else if err == nil || body != nil {
					t.Fatal("contradictory generated result rendered")
				}
			}
		})
	}
	for _, test := range []struct {
		name                    string
		action, completion      uint8
		ceiling                 uint16
		acknowledged, confirmed uint32
		valid                   bool
	}{
		{"create-with-acknowledged-count", contract.GeneratorActionCreate, contract.GeneratedCompletionAcknowledged, contract.ReceiptEvidenceAcknowledged, 1, 0, false},
		{"create-with-confirmed-count", contract.GeneratorActionCreate, contract.GeneratedCompletionConfirmed, contract.ReceiptEvidenceConfirmed, 0, 1, false},
		{"acknowledged-delete-with-confirmed-count", contract.GeneratorActionDelete, contract.GeneratedCompletionAcknowledged, contract.ReceiptEvidenceAcknowledged, 0, 1, false},
		{"confirmed-delete-with-acknowledged-count", contract.GeneratorActionDelete, contract.GeneratedCompletionConfirmed, contract.ReceiptEvidenceConfirmed, 1, 0, false},
		{"ack-only-delete-with-confirmed-count", contract.GeneratorActionDelete, contract.GeneratedCompletionConfirmed, contract.ReceiptEvidenceAcknowledged, 0, 1, false},
		{"acknowledged-delete", contract.GeneratorActionDelete, contract.GeneratedCompletionAcknowledged, contract.ReceiptEvidenceAcknowledged, 1, 0, true},
		{"confirmed-delete", contract.GeneratorActionDelete, contract.GeneratedCompletionConfirmed, contract.ReceiptEvidenceConfirmed, 0, 1, true},
		{"confirmed-delete-awaiting-proof", contract.GeneratorActionDelete, contract.GeneratedCompletionConfirmed, contract.ReceiptEvidenceAcknowledged, 0, 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := r
			generated := *r.Generated
			result.Generated = &generated
			effect, target := fact, *fact.Target
			effect.Target = &target
			effect.Action, effect.Record.CompletionClass, target.CompletionClass = test.action, test.completion, test.completion
			effect.Record.State, effect.Record.Stage = contract.GeneratedEffectSucceeded, contract.GeneratedStageTerminal
			effect.SummaryClass, effect.EvidenceCeiling = contract.ReceiptSummarySuccessCount, test.ceiling
			effect.Warnings.InvalidationNotConfirmed = test.acknowledged != 0
			generated.Effects = []core.GeneratedEffectFact{effect}
			generated.EffectSummary, generated.EvidenceCeiling = contract.ReceiptEffectComplete, test.ceiling
			generated.SummaryCounts[contract.ReceiptSummaryUnknownCount] = 0
			generated.SummaryCounts[contract.ReceiptSummarySuccessCount] = 1
			generated.AcknowledgedCount, generated.ConfirmedCount, generated.UnknownCount = test.acknowledged, test.confirmed, 0
			generated.Warnings = effect.Warnings
			for _, render := range []func(core.PublicApplyResult) ([]byte, error){RenderApplyJSON, RenderApplyHuman} {
				body, err := render(result)
				if test.valid {
					if err != nil || body == nil {
						t.Fatal("valid completion evidence refused", err)
					}
				} else if err == nil || body != nil {
					t.Fatal("completion count has no matching Delete evidence")
				}
			}
		})
	}

}

// full_only: false
func TestGeneratedListMaximumNameRowsAndLateRefusal(t *testing.T) {
	id := contract.ID{1}
	v := &core.GeneratedListView{DomainID: id, RevisionID: id, SnapshotID: id}
	for i := 0; i < contract.GeneratedCurrentEntryLimit; i++ {
		v.CurrentGenerations = append(v.CurrentGenerations, core.GeneratedCurrentGeneration{Name: fmt.Sprintf("%03d", i) + strings.Repeat("\x00", contract.CryptoMaxName-3), EntryIncarnationID: id, GenerationID: id, OriginOperationID: id, OriginAttemptID: id, ResourceID: id, ResourceDigest: id, ConfigContractID: id, ResourceContractID: id, LifecycleMode: contract.GeneratorLifecycleManaged, CompletionClass: contract.GeneratedCompletionAcknowledged, RetirementMode: contract.GeneratedRetirementManual})
	}
	fact := generatedRendererEffect()
	fact.Name = strings.Repeat("\x00", contract.CryptoMaxName)
	fact.Target.Name = fact.Name
	v.Effects = []core.GeneratedEffectFact{fact}
	r := core.PublicGeneratedListResult{Context: core.ReaderOperationContext{Operation: core.GeneratedListOperation, RequestID: id, OperationID: id, ExpectedDomain: id}, Result: core.Result{Outcome: core.ObservedCurrent, Evidence: core.AuthenticatedClosure, ObservedRevision: id, ObservedSnapshotID: id}, StateResult: contract.ReaderSuccess, View: v}
	body, err := RenderGeneratedListJSON(r)
	if err != nil || !json.Valid(body) {
		t.Fatal("complete maximum-name rows failed", err)
	}
	human, err := RenderGeneratedListHuman(r)
	if err != nil || !bytes.Contains(human, []byte(fmt.Sprintf("%q", fact.Name))) {
		t.Fatal("human escaping differs", err)
	}
	v.CurrentGenerations = append(v.CurrentGenerations, v.CurrentGenerations[0])
	if b, e := RenderGeneratedListJSON(r); e == nil || b != nil {
		t.Fatal("one-over current limit accepted")
	}
	v.CurrentGenerations = v.CurrentGenerations[:contract.GeneratedCurrentEntryLimit]
	v.Effects[0].Target.ResourceContractID = contract.ID{2}
	if b, e := RenderGeneratedListJSON(r); e == nil || b != nil {
		t.Fatal("late contradictory target returned partial output")
	}
}

// full_only: false
func TestGeneratedResultWriterBoundAndExactAllocation(t *testing.T) {
	var count generatedResultWriter
	count.size = generatedResultOutputLimit - 1
	count.text("x")
	if count.err != nil || count.size != generatedResultOutputLimit {
		t.Fatal("bound refused")
	}
	count.text("x")
	if count.err == nil {
		t.Fatal("one-over bound admitted")
	}
	body, err := renderGeneratedResult(func(w *generatedResultWriter) { w.text("{"); w.value(strings.Repeat("x", 30)); w.text("}") })
	if err != nil || len(body) != cap(body) {
		t.Fatal("output ownership", err)
	}
	body, err = renderGeneratedResult(func(w *generatedResultWriter) {
		w.text("prefix")
		w.value(strings.Repeat("x", generatedResultRowLimit))
	})
	if err == nil || body != nil {
		t.Fatal("oversized late row escaped")
	}
}

// full_only: false
func TestGeneratedListHazardWarningUsesOwnedQualification(t *testing.T) {
	t.Run("domain-warnings-without-work", func(t *testing.T) {
		const orphan = "Warning: An old generated effect may still be live.\n"
		const destructive = "Warning: An old destructive request may act after this exit.\n"
		const publication = "Warning: An old publication may replace a newer value.\n"
		const discarded = "Warning: Original completion and remote cleanup remain unproved; exact discarded evidence cannot be recovered from this exit.\n"
		const garbage = "Warning: Immutable store garbage may remain after this exit.\n"
		for _, test := range []struct {
			name string
			bits uint8
			want string
		}{
			{"none", 0, ""},
			{"orphan-generated-effect", core.WarningOrphanGeneratedEffect, orphan},
			{"late-destructive-effect", core.WarningLateDestructiveEffect, destructive},
			{"publication-order-value", core.WarningPublicationOrderValue, publication},
			{"discarded-exact-evidence", core.WarningDiscardedExactEvidence, discarded},
			{"possible-store-garbage", core.WarningPossibleStoreGarbage, garbage},
			{"all", 31, orphan + destructive + publication + discarded + garbage},
		} {
			t.Run(test.name, func(t *testing.T) {
				id := contract.ID{1}
				view := &core.GeneratedListView{DomainID: id, RevisionID: id, SnapshotID: id, DomainWarningBits: test.bits}
				result := core.PublicGeneratedListResult{Context: core.ReaderOperationContext{Operation: core.GeneratedListOperation, RequestID: id, ExpectedDomain: id},
					Result: core.Result{Outcome: core.ObservedCurrent, Evidence: core.AuthenticatedClosure, ObservedRevision: id, ObservedSnapshotID: id}, StateResult: contract.ReaderSuccess, View: view}
				human, err := RenderGeneratedListHuman(result)
				if err != nil {
					t.Fatal(err)
				}
				const idText = "0100000000000000000000000000000000000000000000000000000000000000"
				want := "Generated work: success\nDomain: " + idText + "\nObserved revision: " + idText + "\nSnapshot: " + idText + "\n" + test.want + "Active operation: none\nNo generated work or current generations were observed.\nNo supported generated-work action is available.\n"
				if string(human) != want {
					t.Fatalf("row-free current domain warning projection changed:\ngot %q\nwant %q", human, want)
				}
				body, err := RenderGeneratedListJSON(result)
				if err != nil {
					t.Fatal(err)
				}
				var document struct {
					Bits     uint8 `json:"current_domain_warning_bits"`
					Warnings struct {
						PossibleLive             bool `json:"possible_live_residue"`
						LateEffect               bool `json:"late_effect"`
						InvalidationNotConfirmed bool `json:"invalidation_not_confirmed"`
					} `json:"effect_warnings"`
				}
				if err := json.Unmarshal(body, &document); err != nil {
					t.Fatal(err)
				}
				if document.Bits != test.bits || document.Warnings.PossibleLive || document.Warnings.LateEffect || document.Warnings.InvalidationNotConfirmed {
					t.Fatal("current domain warnings changed or became generated-effect facts", document)
				}
			})
		}
	})
	id := contract.ID{1}
	hazard := generatedRendererHazard()
	hazard.CleanupResultContractID = id
	v := &core.GeneratedListView{DomainID: id, RevisionID: id, SnapshotID: id, Hazards: []core.GeneratedHazardFact{hazard}, DomainWarningBits: core.WarningPublicationOrderValue, Warnings: hazard.Warnings}
	r := core.PublicGeneratedListResult{Context: core.ReaderOperationContext{Operation: core.GeneratedListOperation, RequestID: id, OperationID: id, ExpectedDomain: id}, Result: core.Result{Outcome: core.ObservedCurrent, Evidence: core.AuthenticatedClosure, ObservedRevision: id, ObservedSnapshotID: id}, StateResult: contract.ReaderSuccess, View: v}
	for _, qualified := range []bool{false, true} {
		v.Hazards[0].CleanupImplementationQualified = qualified
		body, err := RenderGeneratedListHuman(r)
		if err != nil {
			t.Fatal(err)
		}
		want := "No qualified cleanup path is available."
		if qualified {
			want = "generated cleanup can use the currently qualified cleanup implementation."
		}
		for _, text := range []string{want, "Warning: An old publication may replace a newer value.\n", "The old effect can still be live.", "A succeeded frontier does not close this hazard.", readerID(hazard.Record.OriginalAttemptID), readerID(hazard.Record.HazardID), readerID(hazard.Record.ResourceID), readerID(hazard.Target.ResourceContractID), readerID(hazard.Target.ResourceDigest), generatedEvidence(hazard.EvidenceCeiling)} {
			if !bytes.Contains(body, []byte(text)) {
				t.Fatal("list omitted required owned warning fact", text)
			}
		}
		structured, err := RenderGeneratedListJSON(r)
		if err != nil || !json.Valid(structured) || !bytes.Contains(structured, []byte(`"current_domain_warning_bits": 4`)) || !bytes.Contains(structured, []byte(fmt.Sprintf(`"cleanup_implementation_qualified": %t`, qualified))) || bytes.Contains(structured, []byte("The old effect can still be live.")) {
			t.Fatal("structured qualification or human-only warning differs", err)
		}
	}
	v.Hazards[0].CleanupResultContractID = contract.ID{}
	if body, err := RenderGeneratedListHuman(r); err == nil || body != nil {
		t.Fatal("qualification without an exact cleanup contract was rendered")
	}
}

// full_only: false
func TestGeneratedPreservedEffectWarningRequiresExactHazard(t *testing.T) {
	r := suppliedApplyResultFixture(t)
	r.Receipt = nil
	hazard := generatedRendererHazard()
	hazard.Record.Exposure = contract.GeneratedExposureLateEffect
	hazard.Record.Eligibility = contract.GeneratedExposureLateEffect
	hazard.Warnings = core.GeneratedResultWarnings{LateEffect: true}
	older := generatedRendererEffect()
	older.Record.State = contract.GeneratedEffectClosedWithResidue
	older.HazardID = hazard.Record.HazardID
	older.SummaryClass = contract.ReceiptPreservedResidueCount
	older.Warnings = hazard.Warnings
	frontier := generatedRendererEffect()
	frontier.Record.AttemptID = contract.ID{2}
	frontier.Record.State = contract.GeneratedEffectSucceeded
	frontier.SummaryClass = contract.ReceiptSummarySuccessCount
	r.Payload.LiveHazardIDs = []contract.ID{hazard.Record.HazardID}
	r.Generated = &core.GeneratedInvocationResult{OperationKind: contract.OperationApplyDeclaration, StateResult: "success", CanonicalOutcome: contract.ReceiptCanonicalSelected, EffectSummary: contract.ReceiptEffectComplete, EvidenceCeiling: contract.ReceiptEvidenceCanonical,
		SummaryCountsAvailable: true, EffectsAvailable: true, Effects: []core.GeneratedEffectFact{older, frontier}, RelatedWorkAvailable: true, RelatedHazardIDs: []contract.ID{hazard.Record.HazardID}, Hazards: []core.GeneratedHazardFact{hazard}, UnknownCount: 1, Warnings: hazard.Warnings}
	r.Generated.SummaryCounts[contract.ReceiptEffectCount] = 2
	r.Generated.SummaryCounts[contract.ReceiptSummarySuccessCount] = 1
	r.Generated.SummaryCounts[contract.ReceiptPreservedResidueCount] = 1
	r.Generated.SummaryCounts[contract.ReceiptHazardCount] = 1
	body, err := RenderApplyHuman(r)
	if err != nil || bytes.Count(body, []byte("The old effect can still be live.")) != 1 {
		t.Fatal("preserved-residue effect lost its one exact hazard warning", err)
	}
	for _, damage := range []string{"missing hazard", "different attempt", "different route", "different coordinate"} {
		t.Run(damage, func(t *testing.T) {
			g := *r.Generated
			g.Hazards = append([]core.GeneratedHazardFact(nil), g.Hazards...)
			x := r
			x.Generated = &g
			switch damage {
			case "missing hazard":
				g.RelatedHazardIDs, g.Hazards = nil, nil
			case "different attempt":
				g.Hazards[0].Record.OriginalAttemptID = contract.ID{3}
			case "different route":
				g.Hazards[0].Record.CredentialRouteID = contract.ID{3}
			case "different coordinate":
				target := *g.Hazards[0].Target
				target.ResourceDigest = contract.ID{3}
				g.Hazards[0].Target = &target
			}
			if body, err := RenderApplyHuman(x); err == nil || body != nil {
				t.Fatal("unrelated hazard supplied a warning for an older effect")
			}
		})
	}
}

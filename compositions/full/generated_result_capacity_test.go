package compositionfull

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedResultRowAndWarningBounds(t *testing.T) {
	effect := generatedRendererEffect()
	effect.Name = strings.Repeat("\x00", contract.CryptoMaxName)
	effect.Target.Name = effect.Name
	effect.Epoch, effect.Target.Epoch = math.MaxUint64, math.MaxUint64
	effect.GenerationID, effect.DutyID, effect.HazardID = contract.ID{1}, contract.ID{1}, contract.ID{1}
	effect.Record.PredecessorAttemptID = contract.ID{1}
	effect.Reason, effect.Record.Stage = math.MaxUint8, contract.GeneratedStageTerminal
	effect.Record.RetryUsed = 1
	effect.Warnings = core.GeneratedResultWarnings{PossibleLiveResidue: true, LateEffect: true, InvalidationNotConfirmed: true}
	duty := generatedRendererDuty()
	duty.Target = effect.Target
	duty.GenerationID, duty.RetirementMode = contract.ID{1}, contract.GeneratedRetirementManual
	duty.Record.Kind = contract.GeneratedDutyUnselectedCleanup
	duty.Warnings = effect.Warnings
	hazard := generatedRendererHazard()
	hazard.Target = effect.Target
	hazard.GenerationID, hazard.RetirementMode = contract.ID{1}, contract.GeneratedRetirementManual
	hazard.CleanupResultContractID, hazard.CleanupImplementationQualified = contract.ID{1}, true
	hazard.Warnings = effect.Warnings
	localEffect, localDuty := localResultEffect(), localResultDuty()
	localEffect.Name, localEffect.Epoch = strings.Repeat("\x00", contract.CryptoMaxName), math.MaxUint64
	for name, emit := range map[string]func(*generatedResultWriter){
		"effect":       func(w *generatedResultWriter) { writeGeneratedEffect(w, effect) },
		"duty":         func(w *generatedResultWriter) { writeGeneratedDuty(w, duty) },
		"hazard":       func(w *generatedResultWriter) { writeGeneratedHazard(w, hazard) },
		"local effect": func(w *generatedResultWriter) { writeGeneratedEffect(w, localEffect) },
		"local duty":   func(w *generatedResultWriter) { writeGeneratedDuty(w, localDuty) },
	} {
		t.Run(name, func(t *testing.T) {
			body, err := renderGeneratedResult(emit)
			if err != nil || len(body)+1 > 6144 || !json.Valid(body) {
				t.Fatal("bounded complete row failed", len(body), err)
			}
			var row map[string]json.RawMessage
			if err := json.Unmarshal(body, &row); err != nil {
				t.Fatal(err)
			}
			factsLimit := 2048
			if name == "effect" || name == "local effect" {
				factsLimit = 4096
			}
			if len(row["facts"]) > factsLimit || len(row["target"]) > 3072 {
				t.Fatal("row component exceeds its charged bound", len(row["facts"]), len(row["target"]))
			}
		})
	}
	for _, qualified := range []bool{false, true} {
		hazard.CleanupImplementationQualified = qualified
		body, err := renderGeneratedResult(func(w *generatedResultWriter) {
			writeGeneratedHazardWarnings(w, []core.GeneratedHazardFact{hazard}, nil)
		})
		if err != nil || len(body) > 1024 {
			t.Fatal("human warning exceeds its charged bound", len(body), err)
		}
	}
}

// full_only: false
func TestGeneratedResultOutputBoundCoversIndependentRowLimits(t *testing.T) {
	s := core.GeneratedResultSupportBytes
	attempts := s / 797
	work := s / 692
	progress := s/270 + 2*(s/1045)
	// These independent maxima are more permissive than one authenticated
	// image. The bound must also cover structurally valid public DTO inputs.
	rows, progressRows := 6144*(attempts+work), 512*progress
	releases, nextActions := 512*attempts, 512*(2*work+2)
	relatedIDs, remainingCleanupIDs := 67*work, 67*work
	terminalSiblingIDs, hazardWarnings := uint64(67*2*65535), 1024*work
	variable := rows + progressRows + releases + nextActions + relatedIDs + remainingCleanupIDs + terminalSiblingIDs + hazardWarnings
	humanVariable := variable + 2048*(attempts+work) + 1024*attempts
	if attempts != 673590 || work != 775797 || progress != 3015805 || terminalSiblingIDs != 8781690 || variable != 12495575736 || humanVariable != 16153676472 || humanVariable > 32*s {
		t.Fatal("independent support/population arithmetic changed", attempts, work, progress, variable)
	}
	if core.GeneratedResultAttemptLimit != attempts || core.GeneratedResultWorkLimit != work || core.GeneratedResultProgressLimit != progress {
		t.Fatal("output account no longer covers accepted row populations", variable, s)
	}
	fixed := uint64(65536 + 8192*(1408+128) + 2*471 + 116)
	if core.MaxApplyResultDiagnostics != 3081 || applyResultDiagnosticBytes != 10561668 || contract.GeneratorMaxTemplates != 1408 || contract.GeneratedCurrentEntryLimit != 128 || contract.CompactMutationReceiptLength != 471 || generatedResultOutputLimit != fixed+32*s+10561668+512*attempts+2048+1024 {
		t.Fatal("fixed output account changed without a new derivation")
	}
}

// full_only: false
func TestGeneratedResultProgressReleaseAndActionBounds(t *testing.T) {
	id := contract.ID{1}
	progress := contract.GeneratorProgress{Schema: 1, AttemptID: id, ResultID: id,
		Evidence:      contract.GeneratorDescriptor{Count: 1, Length: uint64(contract.GeneratedResultRecordMaxLength), Digest: id},
		RequiredSteps: contract.GeneratorConfirmedRequiredSteps, CompletedSteps: contract.GeneratorProgressConfirmed, CompletionClass: contract.GeneratedCompletionConfirmed}
	if _, err := contract.EncodeGeneratorProgress(progress); err != nil {
		t.Fatal(err)
	}
	body, err := renderGeneratedResult(func(w *generatedResultWriter) { writeGeneratedProgress(w, []contract.GeneratorProgress{progress}) })
	if err != nil || len(body) > 512 {
		t.Fatal("progress exceeds its charged bound", len(body), err)
	}
	row, effect := generatedRendererRelease(contract.PendingInboxReleaseRecord{Schema: 1, DomainID: id, InboxID: id, OriginalResultID: id, SelectedHandoffDigest: id, HandoffRevisionID: id, CapacityReservation: contract.GeneratorDescriptor{Digest: id, Length: 4}, ObjectLength: uint32(contract.GeneratedResultRecordMaxLength), State: contract.GeneratedReleaseUnknown})
	v := &core.GeneratedListView{DomainID: id, RevisionID: id, SnapshotID: id,
		PendingReleases: []core.GeneratedPendingResultCleanup{row}, Effects: []core.GeneratedEffectFact{effect},
		NextActions: []core.GeneratedNextAction{{Command: "generated accept-retirement-risk", DutyID: id, AttemptID: id}}}
	r := core.PublicGeneratedListResult{Context: core.ReaderOperationContext{Operation: core.GeneratedListOperation, RequestID: id, ExpectedDomain: id},
		Result: core.Result{Outcome: core.ObservedCurrent, Evidence: core.AuthenticatedClosure, ObservedRevision: id, ObservedSnapshotID: id}, StateResult: contract.ReaderSuccess, View: v}
	body, err = RenderGeneratedListJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"pending_releases", "next_actions"} {
		maximum := 512
		if field == "pending_releases" {
			maximum = 1024
		}
		var rows []json.RawMessage
		if err := json.Unmarshal(document[field], &rows); err != nil || len(rows) != 1 || len(localResultCompact(t, rows[0]))+1 > maximum || len(rows[0])+1 > 67*maximum {
			t.Fatal("row exceeds its charged bound", field, err)
		}
	}
}

package core

import (
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedLocalFailedFinalRequiresExactRetainedReceipt(t *testing.T) {
	for _, damage := range []string{"exact", "missing", "request", "requested_revision", "observed_revision", "zero_failures", "zero_effects", "extra_effect", "selected", "empty_digest"} {
		t.Run(damage, func(t *testing.T) {
			basis, input := generatedTerminalMutationFixture(t, true)
			attempt, err := contract.InspectGeneratedAttemptRecord(input.Effects[0].Body)
			if err != nil {
				t.Fatal(err)
			}
			attempt.Schema, attempt.LifecycleMode = contract.GeneratedAttemptRecordSchema, contract.GeneratorLifecycleNone
			attempt.ResourceContractID = contract.ID{}
			attempt.CompletionClass, attempt.RetryUsed, attempt.FailureReason = 0, 0, contract.GeneratorFailureUnavailable
			attempt.PredecessorAttemptID, attempt.Progress = contract.ID{}, contract.EmptyGeneratorVector(contract.GeneratorVectorProgress)
			attempt.State, attempt.Stage = contract.GeneratedEffectFailedTerminal, contract.GeneratedStageTerminal
			attempt.Facts = contract.EmptyGeneratorVector(contract.GeneratorVectorFacts)
			body, err := contract.EncodeGeneratedAttemptRecord(attempt)
			if err != nil {
				t.Fatal(err)
			}
			input.Effects = []contract.SupportRecord{{Kind: contract.GeneratedAttemptSupportKind, RecordID: attempt.AttemptID, Body: body}}
			input.EffectClasses = map[contract.ID]int{attempt.AttemptID: contract.ReceiptSummaryFailureCount}
			input.Selected, input.ObservedRevisionID = false, input.OriginalPredecessorRevisionID
			input.ChangedSubjects, err = contract.ChangedSubjectDescriptor(nil)
			if err != nil {
				t.Fatal(err)
			}
			delta, retained, err := basis.generatedTerminalMutation(t.Context(), input)
			if err != nil || !retained {
				t.Fatal("actual failed-local receipt construction", err)
			}
			row := contract.CompactMutationReceipt(delta.NewReceipt)
			row.RequestIdentityDigest = input.Parent.RequestIdentityDigest
			switch damage {
			case "request":
				row.RequestIdentityDigest = generatedVectorID(241)
			case "requested_revision":
				row.RequestedRevisionID = generatedVectorID(242)
			case "observed_revision":
				row.ObservedRevisionID = generatedVectorID(243)
			case "zero_failures":
				row.SummaryCounts[contract.ReceiptSummaryFailureCount], row.SummaryCounts[contract.ReceiptSummaryUnknownCount] = 0, 1
				row.UnknownCount, row.EffectSummary, row.StateResult = 1, contract.ReceiptEffectUnknown, contract.ReceiptStateEffectUnknown
				row.WarningBits |= contract.ReceiptWarningPossibleLive
			case "zero_effects":
				row.SummaryCounts[contract.ReceiptSummaryFailureCount], row.SummaryCounts[contract.ReceiptEffectCount] = 0, 0
			case "extra_effect":
				row.SummaryCounts[contract.ReceiptSummarySuccessCount], row.SummaryCounts[contract.ReceiptEffectCount] = 1, 2
				row.EffectSummary = contract.ReceiptEffectMixedTerminal
			case "selected":
				row.CanonicalOutcome, row.ObservedRevisionID = contract.ReceiptCanonicalSelected, row.RequestedRevisionID
				row.SummaryCounts[contract.ReceiptSummaryFailureCount], row.SummaryCounts[contract.ReceiptSummarySuccessCount] = 0, 1
				row.EffectSummary, row.StateResult = contract.ReceiptEffectComplete, contract.ReceiptStateSuccess
			}
			windows := delta.Before
			if damage != "missing" {
				windows, err = contract.AppendMutationReceipt(windows, row)
				if damage == "zero_effects" {
					if err == nil {
						t.Fatal("receipt codec accepted terminal nonselection with no effects")
					}
					return
				}
				if err != nil {
					t.Fatal("negative must reach cold receipt validation with valid receipt syntax", err)
				}
			}
			basis.head.Core.Revision = input.RequestedRevisionID
			selected := generatedReceiptWindowState(t, basis, windows)
			checked, err := selected.receiptWindows(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if err := selected.recordSelectedReceiptWindows(checked); err != nil {
				t.Fatal(err)
			}
			empty, err := contract.GeneratorResultReferencesDescriptor(nil)
			if err != nil {
				t.Fatal(err)
			}
			subject := contract.GeneratorAuthoritySubject{OperationID: input.Parent.OperationID,
				RequestIdentityDigest: input.Parent.RequestIdentityDigest, ResultVector: contract.GeneratorDescriptor(empty), PreviousRevisionID: input.OriginalPredecessorRevisionID}
			if damage == "empty_digest" {
				subject.ResultVector.Digest = generatedVectorID(244)
			}
			proof := &selectedGeneratedProof{selectedImage: selected.selectedImage(), head: selected.head}
			err = proof.validateGeneratedFinalReceipt(t.Context(), subject, false)
			if damage == "exact" && err != nil {
				t.Fatal("exact signed failed-local closure refused", err)
			}
			if damage != "exact" && err == nil {
				t.Fatal("cold failed-local Final accepted changed or missing receipt evidence")
			}
		})
	}
}

// full_only: false
func TestGeneratedResidueFinalRequiresExactRetainedReceipt(t *testing.T) {
	for _, damage := range []string{"exact", "exact_two_hazards", "exact_with_terminal_predecessors", "acknowledged_without_result", "confirmed_without_result", "missing", "request", "requested_revision", "observed_revision", "hazards", "extra_effect", "missing_warning", "result_digest", "result_length"} {
		t.Run(damage, func(t *testing.T) {
			basis, input := generatedTerminalMutationFixture(t, false)
			attempt, err := contract.InspectGeneratedAttemptRecord(input.Effects[1].Body)
			if err != nil {
				t.Fatal(err)
			}
			attempt.State, attempt.Stage = contract.GeneratedEffectClosedWithResidue, contract.GeneratedStageTerminal
			_, err = contract.EncodeGeneratedAttemptRecord(attempt)
			if err != nil {
				t.Fatal(err)
			}
			hazard, err := contract.InspectGeneratedHazardRecord(input.Hazards[0].Body)
			if err != nil || hazard.Fenced != 1 || hazard.OriginalAttemptID != attempt.AttemptID || hazard.OwnerID != attempt.OwnerID {
				t.Fatal("residue fixture lacks its exact fenced owner", err)
			}
			empty, err := contract.GeneratorResultReferencesDescriptor(nil)
			if err != nil {
				t.Fatal(err)
			}
			subject := contract.GeneratorAuthoritySubject{Purpose: contract.GeneratorAuthorityFinal, DomainID: basis.root.Domain,
				OperationID: input.Parent.OperationID, OwnerID: input.Parent.OperationID, RequestIdentityDigest: input.Parent.RequestIdentityDigest,
				PreviousRevisionID: input.OriginalPredecessorRevisionID, PreviousHEADDigest: generatedVectorID(230), ConditionDigest: generatedVectorID(231),
				BeforePhase: 1, AfterPhase: 2, ResultVector: contract.GeneratorDescriptor(empty)}
			if damage == "result_digest" {
				subject.ResultVector.Digest = generatedVectorID(232)
			}
			if damage == "result_length" {
				subject.ResultVector.Length++
			}
			subject.PhaseID, err = contract.GeneratorPhaseID(contract.GeneratorPhaseIdentity{RequestIdentityDigest: subject.RequestIdentityDigest,
				ObservedHEADDigest: subject.PreviousHEADDigest, ConditionDigest: subject.ConditionDigest, TransitionKind: subject.Purpose,
				BeforePhase: subject.BeforePhase, AfterPhase: subject.AfterPhase, Evidence: subject.ResultVector})
			if damage == "result_length" {
				if err == nil {
					t.Fatal("phase identity admitted a zero-count result descriptor with a nonempty length")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			revision, err := contract.GeneratorPhaseRevisionID(subject.PhaseID)
			if err != nil {
				t.Fatal(err)
			}
			changed, err := contract.ChangedSubjectDescriptor(nil)
			if err != nil {
				t.Fatal(err)
			}
			// One entered resultless residue create gives one unknown effect,
			// one fenced Hazard, no selected changes, and the predecessor revision.
			row := contract.CompactMutationReceipt{Schema: contract.MutationReceiptSchema, OperationKind: contract.OperationApplyDeclaration,
				DomainID: basis.root.Domain, OperationID: subject.OperationID, RequestIdentityDigest: subject.RequestIdentityDigest,
				PredecessorRevisionID: subject.PreviousRevisionID, RequestedRevisionID: revision, ObservedRevisionID: subject.PreviousRevisionID,
				CanonicalOutcome: contract.ReceiptCanonicalNotSelected, StateResult: contract.ReceiptStateEffectUnknown,
				EffectSummary: contract.ReceiptEffectUnknown, EvidenceCeiling: contract.ReceiptEvidenceProviderFacts, WarningBits: contract.ReceiptWarningPossibleLive,
				ChangedSubjects: changed, UnknownCount: 1,
				CompleteResult: contract.GeneratorDescriptor{Digest: generatedVectorID(233), Length: 8 + contract.MutationResultProjectionLength, Count: 1}}
			row.SummaryCounts[contract.ReceiptEffectCount], row.SummaryCounts[contract.ReceiptHazardCount], row.SummaryCounts[contract.ReceiptSummaryUnknownCount] = 1, 1, 1
			if damage == "exact_with_terminal_predecessors" || damage == "acknowledged_without_result" || damage == "confirmed_without_result" {
				// Ended-only terminal/no-effect predecessors are pruned from
				// live support but remain in the original operation receipt.
				row.SummaryCounts[contract.ReceiptSummaryFailureCount], row.SummaryCounts[contract.ReceiptNoEffectPredecessorCount], row.SummaryCounts[contract.ReceiptEffectCount] = 1, 1, 3
			}
			switch damage {
			case "acknowledged_without_result":
				row.AcknowledgedCount, row.EvidenceCeiling = 1, contract.ReceiptEvidenceAcknowledged
				row.WarningBits |= contract.ReceiptWarningInvalidationNotConfirmed
			case "confirmed_without_result":
				row.ConfirmedCount, row.EvidenceCeiling = 1, contract.ReceiptEvidenceConfirmed
			case "request":
				row.RequestIdentityDigest = generatedVectorID(234)
			case "requested_revision":
				row.RequestedRevisionID = generatedVectorID(235)
			case "observed_revision":
				row.ObservedRevisionID = generatedVectorID(236)
			case "hazards":
				row.SummaryCounts[contract.ReceiptHazardCount] = 0
			case "extra_effect":
				row.SummaryCounts[contract.ReceiptEffectCount], row.SummaryCounts[contract.ReceiptSummaryUnknownCount], row.UnknownCount = 2, 2, 2
			case "missing_warning":
				row.WarningBits = 0
			}
			windows, err := basis.receiptWindows(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if damage != "missing" {
				windows, err = contract.AppendMutationReceipt(windows, row)
				if err != nil {
					t.Fatal("receipt negative must retain valid codec syntax", err)
				}
			}
			g := &generatedSelection{attempts: map[contract.ID]generatedAttempt{attempt.AttemptID: {record: attempt,
				expected: contract.GeneratorResultExpectation{InputEncoding: contract.InputEncodingRaw, Template: contract.GeneratorAttemptTemplate{HazardID: hazard.HazardID}}}},
				records: map[generatedRecordKey]contract.SupportRecord{{kind: contract.GeneratedHazardSupportKind, id: hazard.HazardID}: input.Hazards[0]}}
			live := []contract.SupportRecord{input.Hazards[0]}
			if damage == "exact_two_hazards" {
				second := hazard
				second.HazardID, second.OriginalAttemptID, second.OwnerID, second.ResourceID = generatedVectorID(237), generatedVectorID(238), generatedVectorID(239), generatedVectorID(240)
				body, err := contract.EncodeGeneratedHazardRecord(second)
				if err != nil {
					t.Fatal(err)
				}
				other := attempt
				other.AttemptID, other.OwnerID, other.ResourceID = second.OriginalAttemptID, second.OwnerID, second.ResourceID
				g.attempts[other.AttemptID] = generatedAttempt{record: other, expected: contract.GeneratorResultExpectation{InputEncoding: contract.InputEncodingRaw, Template: contract.GeneratorAttemptTemplate{HazardID: second.HazardID}}}
				otherRow := contract.SupportRecord{Kind: contract.GeneratedHazardSupportKind, RecordID: second.HazardID, Body: body}
				g.records[generatedRecordKey{kind: otherRow.Kind, id: otherRow.RecordID}] = otherRow
				live = append(live, otherRow)
				row.SummaryCounts[contract.ReceiptEffectCount], row.SummaryCounts[contract.ReceiptHazardCount], row.SummaryCounts[contract.ReceiptSummaryUnknownCount], row.UnknownCount = 2, 2, 2, 2
				windows, err = basis.receiptWindows(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				windows, err = contract.AppendMutationReceipt(windows, row)
				if err != nil {
					t.Fatal(err)
				}
			}
			selected := generatedReceiptWindowState(t, basis, windows, live...)
			checked, err := selected.receiptWindows(t.Context())
			if err != nil || selected.recordSelectedReceiptWindows(checked) != nil {
				t.Fatal("selected receipt witness unavailable", err)
			}
			proof := &selectedGeneratedProof{selectedImage: selected.selectedImage(), head: selected.head}
			// This owner-local validator starts after the authenticated image
			// boundary. Bind the candidate's exact deterministic phase identities.
			proof.root.Snapshot, err = contract.GeneratorPhaseSnapshotID(subject.PhaseID)
			if err != nil {
				t.Fatal(err)
			}
			proof.root.Transition, err = contract.GeneratorPhaseTransitionID(subject.PhaseID)
			if err != nil {
				t.Fatal(err)
			}
			proof.head.Core.Revision = revision
			identity := contract.IdentityPlan{Operation: subject.OperationID, Snapshot: proof.root.Snapshot, Transition: proof.root.Transition, Revision: revision}
			for _, ref := range proof.root.Recipients {
				if ref != nil {
					ref.Object, err = contract.GeneratorPhasePageID(subject.PhaseID, contract.RecipientKind, ref.Index)
					if err != nil {
						t.Fatal(err)
					}
					identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
				}
			}
			for _, ref := range proof.root.ValueEntryPages {
				if ref != nil {
					identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
				}
			}
			for _, ref := range proof.root.CurrentAccess.Core.AccessPageRefs {
				identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
			}
			for i := range proof.root.RequiredSupport {
				ref := &proof.root.RequiredSupport[i]
				ref.Object, err = contract.GeneratorPhasePageID(subject.PhaseID, contract.RequiredSupportKind, ref.Index)
				if err != nil {
					t.Fatal(err)
				}
				identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
			}
			slices.SortFunc(identity.Pages, func(a, b contract.IdentityPage) int {
				if a.Kind != b.Kind {
					return int(a.Kind) - int(b.Kind)
				}
				return int(a.Index) - int(b.Index)
			})
			subject.IdentityPlan, err = contract.GeneratorAuthorityIdentityDescriptor(identity)
			if err != nil {
				t.Fatal(err)
			}
			union := proof.generatedUnchangedEntryUnion()
			subject.ValueEntryUnion, err = contract.GeneratorAuthorityValueEntriesDescriptor(proof.root.Domain, union)
			if err != nil {
				t.Fatal(err)
			}
			for i := range union {
				union[i].After.EntryDigest = contract.ID{}
			}
			subject.MembershipChanges, err = contract.GeneratorAuthorityMembershipDescriptor(proof.root.Domain, union)
			if err != nil {
				t.Fatal(err)
			}
			err = proof.validateGeneratedFinalSelection(t.Context(), g, subject)
			genuine := damage == "exact" || damage == "exact_two_hazards" || damage == "exact_with_terminal_predecessors"
			if genuine && err != nil {
				t.Fatal("genuine zero-result residue Final refused", err)
			}
			if !genuine && err == nil {
				t.Fatal("zero-result residue Final accepted missing or changed terminal evidence")
			}
		})
	}
}

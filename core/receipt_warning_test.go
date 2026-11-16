package core

import (
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedTerminalReceiptPreservesInheritedDomainWarnings(t *testing.T) {
	for _, condition := range []string{"success", "possible-live", "acknowledged"} {
		t.Run(condition, func(t *testing.T) {
			s, input := generatedTerminalMutationFixture(t, condition != "possible-live")
			if _, retained, err := s.generatedTerminalMutation(t.Context(), input); err != nil || !retained {
				t.Fatal("zero-warning terminal control refused", err)
			}
			s.root.WarningBits = 31
			generatedSealSelectedFixture(t, s)
			generatedVerifySelectedFixtureSlices(t, s)
			if _, err := s.receiptWindows(t.Context()); err != nil {
				t.Fatal("warning Root receipt-window precondition refused", err)
			}
			want := uint64(124)
			if condition == "possible-live" {
				want = 125
			}
			if condition == "acknowledged" {
				attempt, err := contract.InspectGeneratedAttemptRecord(input.Effects[0].Body)
				if err != nil {
					t.Fatal(err)
				}
				attempt.CompletionClass = contract.GeneratedCompletionAcknowledged
				input.Effects[0].Body, err = contract.EncodeGeneratedAttemptRecord(attempt)
				if err != nil {
					t.Fatal(err)
				}
				input.CompletionClasses = map[contract.ID]uint8{attempt.AttemptID: contract.GeneratedCompletionAcknowledged}
				want = 126
			}
			delta, retained, err := s.generatedTerminalMutation(t.Context(), input)
			if err != nil || !retained {
				t.Fatal("existing terminal receipt construction refused", err)
			}
			if delta.NewReceipt.WarningBits != want {
				t.Fatalf("inherited domain warning summary lost: got %d, want %d", delta.NewReceipt.WarningBits, want)
			}
		})
	}
}

// full_only: false
func TestSuccessionCapacityReceiptCommitsInheritedDomainWarnings(t *testing.T) {
	s := successionReceiptCapacityFixture(t)
	plan := transitionPlan{snapshot: contract.ID{132}, transition: contract.ID{133}, revision: contract.ID{131}}
	indexes, err := s.mutationReceiptPageIndexes(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range indexes {
		plan.supportPages[index] = contract.ID{134, byte(index)}
	}
	request := contract.SuccessionRequestCore{OperationKind: contract.SuccessionReplaceRecoveryBasis,
		DomainID: s.root.Domain, OperationID: contract.ID{130}, PredecessorHeadRevisionID: contract.ID{129}}
	subjects := contract.GeneratorDescriptor{Digest: contract.ID{135}, Length: 4}
	without, err := s.projectedSuccessionRoot(t.Context(), request, plan, subjects)
	if err != nil {
		t.Fatal("zero-warning capacity control refused", err)
	}
	s.root.WarningBits = 31
	generatedSealSelectedFixture(t, s)
	generatedVerifySelectedFixtureSlices(t, s)
	if _, err := s.receiptWindows(t.Context()); err != nil {
		t.Fatal("warning Root receipt-window precondition refused", err)
	}
	with, err := s.projectedSuccessionRoot(t.Context(), request, plan, subjects)
	if err != nil {
		t.Fatal("inherited-warning capacity projection refused", err)
	}
	if with.WarningBits != 31 || with.ChildCount != without.ChildCount || with.ChildEncodedBytes != without.ChildEncodedBytes {
		t.Fatal("fixed-size warning summary changed capacity or root meaning")
	}
	if slices.Equal(with.RequiredSupport, without.RequiredSupport) {
		t.Fatal("projected receipt support did not commit inherited warning summary")
	}
}

// full_only: false
func TestSelectedGeneratedTerminalReceiptRequiresExactDomainWarnings(t *testing.T) {
	for _, condition := range []string{"exact", "omitted", "different"} {
		t.Run(condition, func(t *testing.T) {
			basis, input := generatedTerminalMutationFixture(t, true)
			bundle, _, _ := generatedContentPlanFixture(t)
			identity, err := contract.ChangedSubjectIdentityID(input.Parent.DomainID, contract.ChangedSubjectValueEntry,
				bundle.ValueEntryPlans[0].EntryIncarnationID, contract.ID{})
			if err != nil {
				t.Fatal(err)
			}
			input.ChangedSubjects, err = contract.ChangedSubjectDescriptor([]contract.ChangedSubjectIdentity{{
				Kind: contract.ChangedSubjectValueEntry, Change: contract.ChangedSubjectAdded, Identity: identity}})
			if err != nil {
				t.Fatal(err)
			}
			delta, retained, err := basis.generatedTerminalMutation(t.Context(), input)
			if err != nil || !retained || len(delta.Before.Successes)+len(delta.Before.Failures) == 0 {
				t.Fatal("historical receipt control unavailable", err)
			}
			plan := delta.NewReceipt
			plan.WarningBits = 124
			switch condition {
			case "omitted":
				plan.WarningBits = 0
			case "different":
				plan.WarningBits = 4
			}
			effects, err := contract.MutationResultRecordDescriptor(contract.MutationResultEffects, input.Parent.DomainID, input.Effects)
			if err != nil {
				t.Fatal(err)
			}
			empty := contract.EmptyMutationResultDescriptors()
			plan.CompleteResult = contract.GeneratorDescriptor{}
			plan.CompleteResult, err = contract.CompleteMutationResultDescriptor(contract.MutationResultProjection{Receipt: plan,
				RequestCoreDigest: input.Parent.RequestCoreDigest, ChangedAccess: input.ChangedAccess, Effects: effects, Outputs: empty[2], Duties: empty[3], Hazards: empty[4]})
			if err != nil {
				t.Fatal("warning receipt complete-result projection refused", err)
			}
			row := contract.CompactMutationReceipt(plan)
			row.RequestIdentityDigest = input.Parent.RequestIdentityDigest
			windows, err := contract.AppendMutationReceipt(delta.Before, row)
			if err != nil {
				t.Fatal("warning receipt window refused", err)
			}
			basis.root.WarningBits = 31
			basis.head.Core.Revision = input.RequestedRevisionID
			selected := generatedReceiptWindowState(t, basis, windows)
			checked, err := selected.receiptWindows(t.Context())
			if err != nil {
				t.Fatal("selected warning receipt precondition refused", err)
			}
			if err := selected.recordSelectedReceiptWindows(checked); err != nil {
				t.Fatal("selected warning receipt ownership refused", err)
			}
			proof := &selectedGeneratedProof{selectedImage: selected.selectedImage(), head: selected.head}
			subject := contract.GeneratorAuthoritySubject{OperationID: row.OperationID, RequestIdentityDigest: row.RequestIdentityDigest, ResultVector: effects}
			err = proof.validateGeneratedFinalReceipt(t.Context(), subject, true)
			if condition == "exact" && err != nil {
				t.Fatal("exact current domain summary or older historical summary refused", err)
			}
			if condition != "exact" && err == nil {
				t.Fatal("selected terminal receipt admitted omitted or different domain warning summary")
			}
		})
	}
}

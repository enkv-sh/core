package core

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGeneratedFinalAccessChangesUseActualSelectedRows(t *testing.T) {
	before := generatedReservationState(t)
	after := *before
	after.access[0] = &format.AccessPage{Records: slices.Clone(before.access[0].Records)}
	old := before.access[0].Records[0]
	old.MaterialKind = contract.ValueMaterialKind
	before.access[0].Records[0] = old
	changed := old
	changed.Wraps = slices.Clone(old.Wraps)
	grant := changed.Wraps[0]
	grant.SubjectID, grant.BindingID, grant.PublicBindingDigest = generatedVectorID(90), generatedVectorID(91), generatedVectorID(92)
	changed.Wraps = append(changed.Wraps, grant)
	after.access[0].Records[0] = changed
	want, err := contract.AccessChangeDescriptor(before.root.Domain, []contract.AccessChangeRow{{Before: old, After: changed}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := generatedFinalChangedAccess(before, &after)
	if err != nil || got != want || got.Count != 1 {
		t.Fatal("changed access was not committed independently of membership", err, got)
	}
	empty, err := contract.AccessChangeDescriptor(before.root.Domain, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err = generatedFinalChangedAccess(before, before)
	if err != nil || got != empty {
		t.Fatal("unchanged access created a receipt change", err, got)
	}
	fresh := after
	fresh.access[0] = &format.AccessPage{Records: slices.Clone(after.access[0].Records)}
	fresh.access[0].Records[0].MaterialID = generatedVectorID(93)
	got, err = generatedFinalChangedAccess(before, &fresh)
	if err != nil || got != empty {
		t.Fatal("fresh material was counted as a same-material access change", err, got)
	}

	receiptSession, input := generatedTerminalMutationFixture(t, true)
	input.ChangedAccess = want
	delta, retained, err := receiptSession.generatedTerminalMutation(t.Context(), input)
	if err != nil || !retained || delta.NewReceipt.SummaryCounts[contract.ReceiptChangedAccessCount] != 1 {
		t.Fatal("frozen generated receipt omitted the retained-material grant", err)
	}
	effects, err := contract.MutationResultRecordDescriptor(contract.MutationResultEffects, input.Parent.DomainID, input.Effects)
	if err != nil {
		t.Fatal(err)
	}
	duties, err := contract.MutationResultRecordDescriptor(contract.MutationResultDuties, input.Parent.DomainID, input.Duties)
	if err != nil {
		t.Fatal(err)
	}
	hazards, err := contract.MutationResultRecordDescriptor(contract.MutationResultHazards, input.Parent.DomainID, input.Hazards)
	if err != nil {
		t.Fatal(err)
	}
	projection := contract.MutationResultProjection{Receipt: delta.NewReceipt, RequestCoreDigest: input.Parent.RequestCoreDigest,
		ChangedAccess: want, Effects: effects, Outputs: contract.EmptyMutationResultDescriptors()[2], Duties: duties, Hazards: hazards}
	projection.Receipt.CompleteResult = contract.GeneratorDescriptor{}
	complete, err := contract.CompleteMutationResultDescriptor(projection)
	if err != nil || delta.NewReceipt.CompleteResult != complete {
		t.Fatal("frozen generated receipt omitted the exact changed-access digest", err)
	}
	rows, successes, failures, order, err := receiptSession.generatedReceiptSupport(slices.Clone(receiptSession.supportRecords()), delta,
		input.Parent.RequestIdentityDigest)
	if err != nil {
		t.Fatal("freeze generated receipt", err)
	}
	receiptSession.root.Generated.SuccessWindow, receiptSession.root.Generated.FailureWindow, receiptSession.root.Generated.ReceiptOrder = successes, failures, order
	generatedRepackSupport(t, receiptSession, rows, nil)
	generatedVerifySelectedFixtureSlices(t, receiptSession)
	freshWindows, err := receiptSession.receiptWindows(t.Context())
	if err != nil {
		t.Fatal("fresh receipt index lookup", err)
	}
	i := slices.IndexFunc(freshWindows.Successes, func(row contract.CompactMutationReceipt) bool {
		return row.OperationID == input.Parent.OperationID
	})
	if i < 0 || freshWindows.Successes[i].CompleteResult != complete ||
		freshWindows.Successes[i].SummaryCounts[contract.ReceiptChangedAccessCount] != 1 {
		t.Fatal("fresh lookup changed the frozen access projection")
	}
}

func generatedTerminalMutationFixture(t testing.TB, success bool) (*StateSession, generatedMutationTerminalInput) {
	t.Helper()
	base := generatedEmptyPredecessor(t)
	s, _, _ := receiptStateFixtureForDomain(t, base.root.Domain)
	s.root.Snapshot = base.root.Snapshot
	generatedFixtureSelectedShell(t, s)
	generatedInitializeFixtureOutput(t, s)
	generatedSealSelectedFixture(t, s)
	generatedVerifySelectedFixtureSlices(t, s)
	s.head.Core.Revision = generatedVectorID(69)
	_, _, parent := generatedContentPlanFixture(t)
	parent.DomainID, parent.OperationID = s.admission.domain, generatedVectorID(50)

	first := generatedAttemptVectorFixture()
	first.DomainID, first.OperationID, first.State, first.Stage = parent.DomainID, parent.OperationID, contract.GeneratedEffectSucceeded, contract.GeneratedStageTerminal
	firstBody, err := contract.EncodeGeneratedAttemptRecord(first)
	if err != nil {
		t.Fatal(err)
	}
	effects := []contract.SupportRecord{{Kind: 9, RecordID: first.AttemptID, Body: firstBody}}
	classes := map[contract.ID]int{first.AttemptID: contract.ReceiptSummarySuccessCount}
	var duties, hazards []contract.SupportRecord
	if !success {
		second := first
		second.LineageID, second.AttemptID, second.TransmissionID, second.ResultID, second.InboxID =
			generatedVectorID(31), generatedVectorID(32), generatedVectorID(33), generatedVectorID(34), generatedVectorID(35)
		second.State = contract.GeneratedEffectFailedTerminal
		secondBody, err := contract.EncodeGeneratedAttemptRecord(second)
		if err != nil {
			t.Fatal(err)
		}
		effects = append(effects, contract.SupportRecord{Kind: 9, RecordID: second.AttemptID, Body: secondBody})
		classes[second.AttemptID] = contract.ReceiptSummaryFailureCount
		empty := contract.EmptyGeneratorVector
		duty := contract.GeneratedDutyRecord{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratedDutyRecordSchema, DomainID: parent.DomainID, DutyID: first.OwnerID,
			OriginalOperationID: parent.OperationID, OriginalAttemptID: first.AttemptID, OwnerID: first.OwnerID, ResourceID: first.ResourceID,
			ConfigContractID: first.ConfigContractID, ResourceContractID: first.ResourceContractID, ExecutorID: first.ExecutorID, CredentialRouteID: first.CredentialRouteID,
			DescriptorID: first.DescriptorID, ResultContractID: first.ResultContractID, Kind: contract.GeneratedDutyUnselectedCleanup,
			CompletionClass: first.CompletionClass, Step: 1, Status: contract.GeneratedEffectSucceeded,
			CapacityReservation: parent.Capacity, Target: empty(contract.GeneratorVectorTargets),
			Progress: empty(contract.GeneratorVectorProgress), History: empty(contract.GeneratorVectorHistory), Support: empty(contract.GeneratorVectorSupport),
			Consumers: empty(contract.GeneratorVectorConsumers)}
		dutyBody, err := contract.EncodeGeneratedDutyRecord(duty)
		if err != nil {
			t.Fatal(err)
		}
		duties = []contract.SupportRecord{{Kind: 10, RecordID: duty.DutyID, Body: dutyBody}}
		hazard := contract.GeneratedHazardRecord{Schema: contract.GeneratedHazardRecordSchema, DomainID: parent.DomainID, HazardID: generatedVectorID(40),
			OriginalOperationID: parent.OperationID, OriginalAttemptID: second.AttemptID, OwnerID: second.OwnerID, ResourceID: second.ResourceID,
			ConfigContractID: second.ConfigContractID, ResourceContractID: second.ResourceContractID, ExecutorID: second.ExecutorID, CredentialRouteID: second.CredentialRouteID,
			DescriptorID: second.DescriptorID, ResultContractID: second.ResultContractID, Exposure: contract.GeneratedExposurePossibleLive,
			CompletionClass: second.CompletionClass, Fenced: 1, CapacityReservation: parent.Capacity,
			OriginalResults: contract.EmptyGeneratorRecordSet(contract.GeneratorHazardResults),
			Target:          empty(contract.GeneratorVectorTargets), History: empty(contract.GeneratorVectorHistory), Support: empty(contract.GeneratorVectorSupport),
			Consumers: empty(contract.GeneratorVectorConsumers)}
		hazardBody, err := contract.EncodeGeneratedHazardRecord(hazard)
		if err != nil {
			t.Fatal(err)
		}
		hazards = []contract.SupportRecord{{Kind: 11, RecordID: hazard.HazardID, Body: hazardBody}}
	}
	changed := contract.GeneratorDescriptor{Digest: generatedVectorID(60), Length: 4}
	empty := contract.EmptyMutationResultDescriptors()
	observed := generatedVectorID(61)
	if !success {
		observed = generatedVectorID(6)
	}
	return s, generatedMutationTerminalInput{Parent: parent, OperationKind: 2, OriginalPredecessorRevisionID: generatedVectorID(6),
		RequestedRevisionID: generatedVectorID(61), ObservedRevisionID: observed,
		ChangedSubjects: changed, ChangedAccess: empty[0], Effects: effects, Duties: duties, Hazards: hazards,
		EffectClasses: classes, Selected: success}
}

// full_only: false
func TestGeneratedTerminalMutationBuildsCompleteSuccessAndFailureReceipts(t *testing.T) {
	for _, success := range []bool{true, false} {
		t.Run(map[bool]string{true: "success", false: "failure"}[success], func(t *testing.T) {
			s, input := generatedTerminalMutationFixture(t, success)
			out, retained, err := s.generatedTerminalMutation(t.Context(), input)
			if err != nil || !retained || out.AddedCount != 1 || out.Before.DomainID != s.admission.domain {
				t.Fatal("terminal result", retained, err)
			}
			r := contract.CompactMutationReceipt(out.NewReceipt)
			if r.RequestIdentityDigest != (contract.ID{}) || r.CompleteResult.Count != 1 || r.CompleteResult.Length != 655 ||
				r.PredecessorRevisionID != input.OriginalPredecessorRevisionID || r.PredecessorRevisionID == s.head.Core.Revision ||
				r.SummaryCounts[contract.ReceiptEffectCount] != uint32(len(input.Effects)) ||
				r.SummaryCounts[contract.ReceiptDutyCount] != uint32(len(input.Duties)) ||
				r.SummaryCounts[contract.ReceiptHazardCount] != uint32(len(input.Hazards)) {
				t.Fatal("incomplete terminal result", r)
			}
			if success {
				if r.CanonicalOutcome != 1 || r.StateResult != 1 || r.EffectSummary != 2 || r.WarningBits != 0 || r.SummaryCounts[contract.ReceiptSummarySuccessCount] != 1 {
					t.Fatal("success summary", r)
				}
			} else if r.CanonicalOutcome != 2 || r.StateResult != 11 || r.EffectSummary != 6 ||
				r.WarningBits != contract.ReceiptWarningPossibleLive || r.SummaryCounts[contract.ReceiptSummarySuccessCount] != 1 ||
				r.SummaryCounts[contract.ReceiptSummaryFailureCount] != 1 {
				t.Fatal("failure summary", r)
			}
		})
	}
}

// full_only: false
func TestGeneratedTerminalMutationKeepsReplacementAndCleanupReceiptFree(t *testing.T) {
	s, input := generatedTerminalMutationFixture(t, true)
	for _, operation := range []uint16{25, 31} {
		input.OperationKind = operation
		out, retained, err := s.generatedTerminalMutation(t.Context(), input)
		if err != nil || retained || out.DomainID != (contract.ID{}) || out.AddedCount != 0 ||
			len(out.Before.Successes) != 0 || len(out.Before.Failures) != 0 || out.NewReceipt != (contract.CompactMutationReceiptPlan{}) {
			t.Fatal("receipt-free exception changed", operation, retained, err)
		}
	}
}

// full_only: false
func TestGeneratedTerminalMutationRequiresOriginalPredecessorAndExactOwnedRows(t *testing.T) {
	s, input := generatedTerminalMutationFixture(t, true)
	for name, mutate := range map[string]func(*generatedMutationTerminalInput){
		"missing original predecessor": func(v *generatedMutationTerminalInput) { v.OriginalPredecessorRevisionID = contract.ID{} },
		"effect from another operation": func(v *generatedMutationTerminalInput) {
			attempt, err := contract.InspectGeneratedAttemptRecord(v.Effects[0].Body)
			if err != nil {
				t.Fatal(err)
			}
			attempt.OperationID = generatedVectorID(99)
			v.Effects[0].Body, err = contract.EncodeGeneratedAttemptRecord(attempt)
			if err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := input
			changed.Effects = slices.Clone(input.Effects)
			mutate(&changed)
			if _, retained, err := s.generatedTerminalMutation(t.Context(), changed); err == nil || retained {
				t.Fatal("invalid terminal projection accepted")
			}
		})
	}
}

// full_only: false
func TestGeneratedTerminalMutationEffectOrderIsOperationalNotIdentifierOrder(t *testing.T) {
	s, input := generatedTerminalMutationFixture(t, false)
	forward, retained, err := s.generatedTerminalMutation(t.Context(), input)
	if err != nil || !retained {
		t.Fatal("forward terminal result", err)
	}
	reversed := input
	reversed.Effects = slices.Clone(input.Effects)
	reversed.Effects[0], reversed.Effects[1] = reversed.Effects[1], reversed.Effects[0]
	backward, retained, err := s.generatedTerminalMutation(t.Context(), reversed)
	if err != nil || !retained {
		t.Fatal("reversed terminal result", err)
	}
	if forward.NewReceipt.CompleteResult == backward.NewReceipt.CompleteResult {
		t.Fatal("effect identifier/storage order replaced Product operational order")
	}
}

// full_only: false
func TestGeneratedTerminalMutationKeepsAcknowledgedAndConfirmedCeilingsDistinct(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		class                   uint8
		ceiling                 uint16
		warning                 uint64
		acknowledged, confirmed uint32
	}{
		{"acknowledged", contract.GeneratedCompletionAcknowledged, contract.ReceiptEvidenceAcknowledged,
			contract.ReceiptWarningInvalidationNotConfirmed, 1, 0},
		{"confirmed", contract.GeneratedCompletionConfirmed, contract.ReceiptEvidenceConfirmed, 0, 0, 1},
		{"mixed", contract.GeneratedCompletionAcknowledged, contract.ReceiptEvidenceMixedCompletion,
			contract.ReceiptWarningInvalidationNotConfirmed, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, input := generatedTerminalMutationFixture(t, true)
			attempt, err := contract.InspectGeneratedAttemptRecord(input.Effects[0].Body)
			if err != nil {
				t.Fatal(err)
			}
			attempt.CompletionClass = tc.class
			input.Effects[0].Body, err = contract.EncodeGeneratedAttemptRecord(attempt)
			if err != nil {
				t.Fatal(err)
			}
			input.CompletionClasses = map[contract.ID]uint8{attempt.AttemptID: tc.class}
			if tc.name == "mixed" {
				second := attempt
				second.LineageID, second.AttemptID, second.TransmissionID, second.ResultID, second.InboxID = generatedVectorID(240), generatedVectorID(241), generatedVectorID(242), generatedVectorID(243), generatedVectorID(244)
				second.CompletionClass = contract.GeneratedCompletionConfirmed
				body, err := contract.EncodeGeneratedAttemptRecord(second)
				if err != nil {
					t.Fatal(err)
				}
				input.Effects = append(input.Effects, contract.SupportRecord{Kind: contract.GeneratedAttemptSupportKind, RecordID: second.AttemptID, Body: body})
				input.EffectClasses[second.AttemptID] = contract.ReceiptSummarySuccessCount
				input.CompletionClasses[second.AttemptID] = contract.GeneratedCompletionConfirmed
			}
			delta, retained, err := s.generatedTerminalMutation(t.Context(), input)
			if err != nil || !retained || delta.NewReceipt.EvidenceCeiling != tc.ceiling ||
				delta.NewReceipt.WarningBits != tc.warning || delta.NewReceipt.AcknowledgedCount != tc.acknowledged ||
				delta.NewReceipt.ConfirmedCount != tc.confirmed {
				t.Fatal("completion ceiling", delta.NewReceipt, retained, err)
			}
		})
	}
}

func generatedReceiptTestID(class byte, ordinal int) contract.ID {
	var id contract.ID
	id[0] = class
	binary.BigEndian.PutUint16(id[1:3], uint16(ordinal+1))
	return id
}

func generatedTerminalReceiptAt(t testing.TB, s *StateSession, input generatedMutationTerminalInput, class byte, ordinal int) contract.CompactMutationReceipt {
	t.Helper()
	operation := generatedReceiptTestID(class, ordinal)
	input.Parent.OperationID = operation
	input.Parent.RequestIdentityDigest = generatedReceiptTestID(class+2, ordinal)
	input.Parent.RequestCoreDigest = generatedReceiptTestID(class+4, ordinal)
	input.RequestedRevisionID = generatedReceiptTestID(class+6, ordinal)
	input.ChangedSubjects.Digest = generatedReceiptTestID(class+8, ordinal)
	if input.Selected {
		input.ObservedRevisionID = input.RequestedRevisionID
	} else {
		input.ObservedRevisionID = input.OriginalPredecessorRevisionID
	}
	for i, row := range input.Effects {
		attempt, err := contract.InspectGeneratedAttemptRecord(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		attempt.OperationID = operation
		input.Effects[i].Body, err = contract.EncodeGeneratedAttemptRecord(attempt)
		if err != nil {
			t.Fatal(err)
		}
	}
	for i, row := range input.Duties {
		duty, err := contract.InspectGeneratedDutyRecord(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		duty.OriginalOperationID = operation
		input.Duties[i].Body, err = contract.EncodeGeneratedDutyRecord(duty)
		if err != nil {
			t.Fatal(err)
		}
	}
	for i, row := range input.Hazards {
		hazard, err := contract.InspectGeneratedHazardRecord(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		hazard.OriginalOperationID = operation
		input.Hazards[i].Body, err = contract.EncodeGeneratedHazardRecord(hazard)
		if err != nil {
			t.Fatal(err)
		}
	}
	delta, retained, err := s.generatedTerminalMutation(t.Context(), input)
	if err != nil || !retained {
		t.Fatal("construct terminal receipt", err)
	}
	receipt := contract.CompactMutationReceipt(delta.NewReceipt)
	receipt.RequestIdentityDigest = input.Parent.RequestIdentityDigest
	if !contract.CompactMutationReceiptValid(receipt) {
		t.Fatal("constructed receipt is not independently storable")
	}
	return receipt
}

func generatedReceiptWindowState(t testing.TB, basis *StateSession, windows contract.MutationReceiptWindows, live ...contract.SupportRecord) *StateSession {
	t.Helper()
	rows, err := windows.SupportRecords()
	if err != nil {
		t.Fatal(err)
	}
	rows = append(rows, live...)
	indexes, err := windows.Indexes()
	if err != nil {
		t.Fatal(err)
	}
	successes, failures, order, err := indexes.Descriptors()
	if err != nil {
		t.Fatal(err)
	}
	indexID, err := contract.MutationReceiptIndexBlobID(windows.DomainID, successes, failures, order)
	if err != nil {
		t.Fatal(err)
	}
	indexBody, err := contract.EncodeMutationReceiptIndexes(indexes)
	if err != nil {
		t.Fatal(err)
	}
	fragmentBody, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: 1, BlobID: indexID, Count: 1,
		TotalLength: uint64(len(indexBody)), WholeDigest: contract.Hash(indexBody), Payload: indexBody})
	if err != nil {
		t.Fatal(err)
	}
	fragmentID, err := contract.GeneratorFragmentID(indexID, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := *basis
	s.support, s.root.RequiredSupport = nil, nil
	s.root.RequiredSupportRecordCount = 0
	s.root.Generated = format.EmptyGeneratedClosure()
	s.root.Generated.SuccessWindow, s.root.Generated.FailureWindow, s.root.Generated.ReceiptOrder = successes, failures, order
	s.root.Generated.Fragments = []format.FragmentLocation{{BlobID: indexID, SupportPageIndex: 1}}
	for i, pageRows := range [][]contract.SupportRecord{rows, {{Kind: 3, RecordID: fragmentID, Body: fragmentBody}}} {
		page := format.RequiredSupportPage{Domain: windows.DomainID, Object: generatedReceiptTestID(240, i), Index: uint16(i), Records: pageRows}
		body, err := format.EncodeRequiredSupportPage(page)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal(err)
		}
		view, err := format.InspectRequiredSupportPage(body)
		if err != nil {
			t.Fatal(err)
		}
		s.root.RequiredSupport = append(s.root.RequiredSupport, ref)
		s.root.RequiredSupportRecordCount += uint32(len(pageRows))
		s.support = append(s.support, view)
	}
	configurationRows := 0
	for _, page := range basis.support {
		for _, row := range page.Records {
			if row.Kind != contract.OutputConfigurationSliceSupportKind {
				continue
			}
			physical := generatedFixtureFreeSupportIndex(t, &s)
			s.support = append(s.support, format.RequiredSupportPageView{Domain: s.root.Domain,
				Object: generatedReceiptTestID(241, int(physical)), Index: physical,
				Records: []contract.SupportRecordView{row}})
			configurationRows++
		}
	}
	if configurationRows != int(basis.root.OutputConfiguration.SliceCount) {
		t.Fatal("receipt fixture did not preserve the exact selected configuration")
	}
	generatedSealSelectedFixture(t, &s)
	generatedVerifySelectedFixtureSlices(t, &s)
	if got, err := s.receiptWindows(t.Context()); err != nil || !slices.Equal(got.Successes, windows.Successes) || !slices.Equal(got.Failures, windows.Failures) || !slices.Equal(got.Order, windows.Order) {
		t.Fatal("materialized receipt windows", err)
	}
	return &s
}

// full_only: false
func TestGeneratedSyntheticTerminalReceiptWindowsReplayAndEvictIndependentlyWithoutReleasingWork(t *testing.T) {
	basis, successInput := generatedTerminalMutationFixture(t, true)
	_, failureInput := generatedTerminalMutationFixture(t, false)
	windows := contract.MutationReceiptWindows{DomainID: basis.admission.domain}
	for i := 0; i < contract.MutationReceiptWindowLimit; i++ {
		var err error
		windows, err = contract.AppendMutationReceipt(windows, generatedTerminalReceiptAt(t, basis, successInput, 20, i))
		if err != nil {
			t.Fatal("success window", i, err)
		}
	}
	for i := 0; i < contract.MutationReceiptWindowLimit; i++ {
		var err error
		windows, err = contract.AppendMutationReceipt(windows, generatedTerminalReceiptAt(t, basis, failureInput, 40, i))
		if err != nil {
			t.Fatal("failure window", i, err)
		}
	}
	// The live Hazard belongs to the oldest failed outcome. The failure case
	// therefore proves that evicting that receipt cannot evict its live work.
	live := failureInput.Hazards[0]
	hazard, err := contract.InspectGeneratedHazardRecord(live.Body)
	if err != nil {
		t.Fatal(err)
	}
	hazard.OriginalOperationID = windows.Failures[0].OperationID
	live.Body, err = contract.EncodeGeneratedHazardRecord(hazard)
	if err != nil {
		t.Fatal(err)
	}
	var configuration contract.SupportRecord
	for _, row := range basis.supportRecords() {
		if row.Kind == contract.OutputConfigurationSliceSupportKind {
			configuration = row
			configuration.Body = bytes.Clone(row.Body)
		}
	}
	if configuration.Body == nil || basis.root.OutputConfiguration.SliceCount != 1 {
		t.Fatal("terminal receipt basis lacks its exact configuration")
	}
	wantWork := []contract.SupportRecord{live, configuration}
	for _, tc := range []struct {
		name  string
		input generatedMutationTerminalInput
		class byte
	}{
		{"success", successInput, 60},
		{"failure", failureInput, 80},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := generatedReceiptWindowState(t, basis, windows, live)
			beforeWork, err := s.workSupportRecords(t.Context())
			if err != nil || !slices.EqualFunc(beforeWork, wantWork, func(a, b contract.SupportRecord) bool {
				return a.Kind == b.Kind && a.RecordID == b.RecordID && bytes.Equal(a.Body, b.Body)
			}) {
				t.Fatal("selected live work before eviction", err)
			}
			configurationPage := slices.IndexFunc(s.support, func(page format.RequiredSupportPageView) bool {
				return slices.ContainsFunc(page.Records, func(row contract.SupportRecordView) bool {
					return row.Kind == configuration.Kind && row.RecordID == configuration.RecordID
				})
			})
			if configurationPage < 0 || configurationPage >= len(s.root.RequiredSupport) {
				t.Fatal("selected configuration page absent before receipt storage")
			}
			configurationRef := s.root.RequiredSupport[configurationPage]
			input := tc.input
			operation := generatedReceiptTestID(tc.class, contract.MutationReceiptWindowLimit)
			input.Parent.OperationID = operation
			input.Parent.RequestIdentityDigest = generatedReceiptTestID(tc.class+1, contract.MutationReceiptWindowLimit)
			input.Parent.RequestCoreDigest = generatedReceiptTestID(tc.class+2, contract.MutationReceiptWindowLimit)
			input.RequestedRevisionID = generatedReceiptTestID(tc.class+3, contract.MutationReceiptWindowLimit)
			input.ChangedSubjects.Digest = generatedReceiptTestID(tc.class+4, contract.MutationReceiptWindowLimit)
			if input.Selected {
				input.ObservedRevisionID = input.RequestedRevisionID
			} else {
				input.ObservedRevisionID = input.OriginalPredecessorRevisionID
			}
			for i, row := range input.Effects {
				attempt, err := contract.InspectGeneratedAttemptRecord(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				attempt.OperationID = operation
				input.Effects[i].Body, err = contract.EncodeGeneratedAttemptRecord(attempt)
				if err != nil {
					t.Fatal(err)
				}
			}
			for i, row := range input.Duties {
				duty, err := contract.InspectGeneratedDutyRecord(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				duty.OriginalOperationID = operation
				input.Duties[i].Body, err = contract.EncodeGeneratedDutyRecord(duty)
				if err != nil {
					t.Fatal(err)
				}
			}
			for i, row := range input.Hazards {
				hazard, err := contract.InspectGeneratedHazardRecord(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				hazard.OriginalOperationID = operation
				input.Hazards[i].Body, err = contract.EncodeGeneratedHazardRecord(hazard)
				if err != nil {
					t.Fatal(err)
				}
			}
			delta, retained, err := s.generatedTerminalMutation(t.Context(), input)
			if err != nil || !retained {
				t.Fatal("257th receipt plan", err)
			}
			indexes, err := s.mutationReceiptPageIndexes(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			var plan transitionPlan
			for _, index := range indexes {
				plan.supportPages[index] = generatedReceiptTestID(200, int(index))
			}
			stored, err := s.encodeMutationReceiptSupport(t.Context(), plan, delta, input.Parent.RequestIdentityDigest)
			if err != nil {
				t.Fatal("store 257th receipt", err)
			}
			next := *s
			stored.install(&next)
			configurationRows := 0
			for i, page := range next.support {
				for _, row := range page.Records {
					if row.Kind != configuration.Kind {
						continue
					}
					configurationRows++
					if row.RecordID != configuration.RecordID || !bytes.Equal(row.Body, configuration.Body) ||
						i >= len(next.root.RequiredSupport) || next.root.RequiredSupport[i] != configurationRef ||
						page.Domain != configurationRef.Domain || page.Object != configurationRef.Object || page.Index != configurationRef.Index {
						t.Fatal("raw installed configuration changed before fixture sealing")
					}
				}
			}
			if configurationRows != 1 || next.root.OutputConfiguration != s.root.OutputConfiguration {
				t.Fatal("raw installed configuration missing or duplicated before fixture sealing")
			}
			generatedSealSelectedFixture(t, &next)
			generatedVerifySelectedFixtureSlices(t, &next)
			got, err := next.receiptWindows(t.Context())
			if err != nil || len(got.Successes) != 256 || len(got.Failures) != 256 {
				t.Fatal("bounded independent windows", err)
			}
			if tc.input.Selected {
				if got.Successes[0] != windows.Successes[1] || !slices.Equal(got.Failures, windows.Failures) {
					t.Fatal("success eviction changed the wrong receipt class")
				}
			} else if got.Failures[0] != windows.Failures[1] || !slices.Equal(got.Successes, windows.Successes) {
				t.Fatal("failure eviction changed the wrong receipt class")
			}
			evicted := windows.Successes[0].OperationID
			if !tc.input.Selected {
				evicted = windows.Failures[0].OperationID
			}
			wantOrder := make([]contract.ID, 0, 2*contract.MutationReceiptWindowLimit)
			for _, retained := range windows.Order {
				if retained != evicted {
					wantOrder = append(wantOrder, retained)
				}
			}
			wantOrder = append(wantOrder, operation)
			if !slices.Equal(got.Order, wantOrder) {
				t.Fatal("receipt eviction changed selected common order")
			}
			appended := got.Successes[len(got.Successes)-1]
			if !tc.input.Selected {
				appended = got.Failures[len(got.Failures)-1]
			}
			body, err := contract.EncodeCompactMutationReceipt(appended)
			if err != nil {
				t.Fatal(err)
			}
			replayed, err := contract.InspectCompactMutationReceipt(body)
			if err != nil || replayed != appended || appended.OperationID != operation || appended.RequestIdentityDigest != input.Parent.RequestIdentityDigest {
				t.Fatal("exact terminal replay", err)
			}
			afterWork, err := next.workSupportRecords(t.Context())
			if err != nil || !slices.EqualFunc(afterWork, wantWork, func(a, b contract.SupportRecord) bool {
				return a.Kind == b.Kind && a.RecordID == b.RecordID && bytes.Equal(a.Body, b.Body)
			}) {
				t.Fatal("receipt eviction released or rewrote live work", err)
			}
			retainedHazard, err := contract.InspectGeneratedHazardRecord(afterWork[0].Body)
			if err != nil || retainedHazard.OriginalOperationID != windows.Failures[0].OperationID {
				t.Fatal("evicted failure no longer owns its live Hazard", err)
			}
		})
	}
}

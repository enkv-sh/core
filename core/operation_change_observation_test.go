package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// The expected preimages are literal purpose bytes followed by raw IDs. The
// vector is count, then length-prefixed 34-byte rows in encoded-row order.
func observationExpectedSubject(domain contract.ID, kind, change uint8, primary, secondary contract.ID, fields observationFields) observationSubject {
	preimage := []byte("ENKV/CRYPTO/v2/changed-subject-identity-v1\x00")
	preimage = append(preimage, domain[:]...)
	preimage = append(preimage, kind)
	preimage = append(preimage, primary[:]...)
	preimage = append(preimage, secondary[:]...)
	return observationSubject{Row: contract.ChangedSubjectIdentity{Kind: kind, Change: change, Identity: sha256.Sum256(preimage)}, PrimaryID: primary, SecondaryID: secondary, Fields: fields}
}

func observationExpectedDescriptor(subjects []observationSubject) (contract.GeneratorDescriptor, []observationSubject) {
	owned := slices.Clone(subjects)
	slices.SortFunc(owned, func(a, b observationSubject) int {
		if a.Row.Kind != b.Row.Kind {
			return int(a.Row.Kind) - int(b.Row.Kind)
		}
		if a.Row.Change != b.Row.Change {
			return int(a.Row.Change) - int(b.Row.Change)
		}
		return bytes.Compare(a.Row.Identity[:], b.Row.Identity[:])
	})
	body := binary.BigEndian.AppendUint32(nil, uint32(len(owned)))
	for _, subject := range owned {
		body = binary.BigEndian.AppendUint32(body, 34)
		body = append(body, subject.Row.Kind, subject.Row.Change)
		body = append(body, subject.Row.Identity[:]...)
	}
	preimage := []byte("ENKV/GENERATOR/v1/changed-subjects\x00")
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(body)))
	preimage = append(preimage, body...)
	return contract.GeneratorDescriptor{Digest: sha256.Sum256(preimage), Length: uint64(len(body)), Count: uint32(len(owned))}, owned
}

// full_only: false
func TestGeneratedChangeProjectionKeepsExactRowsAndHistoricalNames(t *testing.T) {
	for _, condition := range []string{"added", "removed", "content encoding", "membership", "reused incarnation", "empty", "retiring metadata"} {
		t.Run(condition, func(t *testing.T) {
			before, _ := observationTestSession(t)
			after := *before
			prior := observationPlainEntry("reused", generatedVectorID(201), []contract.ID{generatedVectorID(11), generatedVectorID(200)})
			next := prior
			var oldEntries, newEntries []contract.ValueEntry
			var want []observationSubject
			base := observationFieldSource | observationFieldConfidentiality | observationFieldMembership | observationFieldEncodedMaterial
			switch condition {
			case "added":
				newEntries = []contract.ValueEntry{next}
				want = append(want, observationExpectedSubject(before.root.Domain, contract.ChangedSubjectValueEntry, contract.ChangedSubjectAdded, next.Incarnation, contract.ID{}, base))
				for _, recipient := range next.Recipients {
					want = append(want, observationExpectedSubject(before.root.Domain, contract.ChangedSubjectMembership, contract.ChangedSubjectAdded, next.Incarnation, recipient, observationFieldMembership))
				}
			case "removed":
				oldEntries = []contract.ValueEntry{prior}
				want = append(want, observationExpectedSubject(before.root.Domain, contract.ChangedSubjectValueEntry, contract.ChangedSubjectRemoved, prior.Incarnation, contract.ID{}, base))
				for _, recipient := range prior.Recipients {
					want = append(want, observationExpectedSubject(before.root.Domain, contract.ChangedSubjectMembership, contract.ChangedSubjectRemoved, prior.Incarnation, recipient, observationFieldMembership))
				}
			case "content encoding":
				next.ValueBytes = []byte("other")
				next.ContentLength, next.RetainedLength = uint32(len(next.ValueBytes)), uint32(len(next.ValueBytes))
				oldEntries, newEntries = []contract.ValueEntry{prior}, []contract.ValueEntry{next}
				want = []observationSubject{observationExpectedSubject(before.root.Domain, contract.ChangedSubjectValueEntry, contract.ChangedSubjectUpdated, next.Incarnation, contract.ID{}, observationFieldEncodedMaterial)}
			case "membership":
				next.Recipients = next.Recipients[:1]
				oldEntries, newEntries = []contract.ValueEntry{prior}, []contract.ValueEntry{next}
				want = []observationSubject{observationExpectedSubject(before.root.Domain, contract.ChangedSubjectValueEntry, contract.ChangedSubjectUpdated, next.Incarnation, contract.ID{}, observationFieldMembership), observationExpectedSubject(before.root.Domain, contract.ChangedSubjectMembership, contract.ChangedSubjectRemoved, next.Incarnation, generatedVectorID(200), observationFieldMembership)}
			case "reused incarnation":
				next.Incarnation = generatedVectorID(202)
				oldEntries, newEntries = []contract.ValueEntry{prior}, []contract.ValueEntry{next}
				want = []observationSubject{observationExpectedSubject(before.root.Domain, contract.ChangedSubjectValueEntry, contract.ChangedSubjectRemoved, prior.Incarnation, contract.ID{}, base), observationExpectedSubject(before.root.Domain, contract.ChangedSubjectValueEntry, contract.ChangedSubjectAdded, next.Incarnation, contract.ID{}, base)}
				for _, recipient := range prior.Recipients {
					want = append(want, observationExpectedSubject(before.root.Domain, contract.ChangedSubjectMembership, contract.ChangedSubjectRemoved, prior.Incarnation, recipient, observationFieldMembership), observationExpectedSubject(before.root.Domain, contract.ChangedSubjectMembership, contract.ChangedSubjectAdded, next.Incarnation, recipient, observationFieldMembership))
				}
			case "retiring metadata":
				fixture, _, _ := generatedDetachedRetirementState(t, "new incarnation", 0)
				prior = *fixture.valueEntry(0)
				next = prior
				prior.Generated.RetiringDutyPresent, prior.Generated.RetiringDutyID = 1, generatedVectorID(200)
				oldEntries, newEntries = []contract.ValueEntry{prior}, []contract.ValueEntry{next}
				want = []observationSubject{observationExpectedSubject(before.root.Domain, contract.ChangedSubjectValueEntry, contract.ChangedSubjectUpdated, next.Incarnation, contract.ID{}, observationFieldGeneration), observationExpectedSubject(before.root.Domain, contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectUpdated, next.Generated.GenerationID, contract.ID{}, observationFieldGeneration)}
			}
			observationInstallEntries(before, oldEntries)
			observationInstallEntries(&after, newEntries)
			var detail changeObservation
			got, err := generatedChangedSubjects(t.Context(), before, &after, &detail)
			expected, expectedRows := observationExpectedDescriptor(want)
			if err != nil || got != expected || detail.Descriptor != expected || !detail.HasChangedSubjects || !slices.Equal(detail.Subjects, expectedRows) {
				t.Fatal("complete commitment or enrichment changed", err, got, expected, detail.Subjects, expectedRows)
			}
			plain, err := generatedFinalChangedSubjects(t.Context(), before, &after)
			if err != nil || plain != expected {
				t.Fatal("pure recomputation changed commitment", err)
			}
			var names []observationName
			for _, entry := range oldEntries {
				names = append(names, observationName{EntryIncarnationID: entry.Incarnation, Name: entry.Name, Side: observationBefore})
			}
			for _, entry := range newEntries {
				names = append(names, observationName{EntryIncarnationID: entry.Incarnation, Name: entry.Name, Side: observationAfter})
			}
			if !slices.Equal(detail.Names, names) {
				t.Fatal("historical before and after binding changed", detail.Names, names)
			}
			for _, entry := range detail.Entries {
				if entry.Relation != observationRelationUnavailable {
					t.Fatal("encoded difference made content claim")
				}
			}
			if len(oldEntries) > 0 {
				before.valueEntry(0).Name = "later"
				before.root.Names[0].Name = "later"
			}
			if len(newEntries) > 0 {
				after.valueEntry(0).Incarnation = generatedVectorID(250)
			}
			if !slices.Equal(detail.Names, names) {
				t.Fatal("later state changed names")
			}
		})
	}
}

func observationFinalFixture(t testing.TB, names ...string) (*StateSession, *generatedFinalPlan) {
	t.Helper()
	_, reservation := observationReservationFixture(t, names...)
	s := reservation.state
	for ordinal := 0; ; ordinal++ {
		g := mustSelectedGeneratedWork(t, s)
		attempt := g.attempts[g.phase.FrontierAttemptID]
		record, err := s.generatedRecordRequest(context.Background(), attempt.record.AttemptID, generatedPublicResultFixtureWithRawToken(t, attempt, 1, 1, observationBoundID(90000+ordinal)), generatedContinuationContext(t, s, byte(130+ordinal*2), byte(131+ordinal*2)))
		if err != nil {
			t.Fatal(err)
		}
		recorded, err := s.deriveGeneratedRecord(context.Background(), record)
		if err != nil {
			t.Fatal(err)
		}
		s = recorded.state
		work := mustSelectedGeneratedWork(t, s)
		if work.phase.Stage == contract.GeneratedStageTerminal {
			break
		}
	}
	observationProtectFixture(t, s)
	plan, err := s.generatedFinalRequest(t.Context(), generatedContinuationContext(t, s, 132, 133))
	if err != nil {
		t.Fatal(err)
	}
	return s, plan
}

// full_only: false
func TestGeneratedFinalOwnerKeepsCompleteCandidateDetail(t *testing.T) {
	for _, condition := range []string{"one entry", "two entries", "disabled", "full", "busy", "empty failure"} {
		t.Run(condition, func(t *testing.T) {
			names := []string{"generated"}
			if condition == "two entries" {
				names = []string{"alpha", "omega"}
			}
			var s *StateSession
			var plan *generatedFinalPlan
			if condition == "empty failure" {
				s = generatedActiveExhaustedUnknownState(t)
				observationProtectFixture(t, s)
				var err error
				plan, err = s.generatedFinalRequest(t.Context(), generatedContinuationContext(t, s, 132, 133))
				if err != nil {
					t.Fatal(err)
				}
			} else {
				s, plan = observationFinalFixture(t, names...)
				// The first preparation selects only a durable encrypted image.
				// Seed that exact typed association before testing the actual
				// Final constructor's complete current-value change detail.
				prepared := make([]contract.CryptoGeneratedValueEntryResult, len(plan.entryPlans))
				for i, entry := range plan.entryPlans {
					prepared[i] = generatedPreparedValueEntryFixture(t, s, entry)
				}
				checkpoint, err := s.deriveGeneratedFinalPreparation(t.Context(), mustSelectedGeneratedWork(t, s), plan, prepared, nil, nil)
				if err != nil || checkpoint.candidate.head.Generator.Purpose != contract.GeneratorAuthorityFinalPreparation {
					t.Fatal("observed Final selected checkpoint fixture", err)
				}
				unchanged, err := generatedFinalChangedSubjects(t.Context(), s, checkpoint.state)
				empty, _ := observationExpectedDescriptor(nil)
				if err != nil || unchanged != empty {
					t.Fatal("preparation checkpoint changed current values", err)
				}
				s = checkpoint.state
				s.prepared = false
				generatedInstallFixtureSupportReader(t, s)
				observationProtectFixture(t, s)
				plan, err = s.generatedFinalRequest(t.Context(), generatedContinuationContext(t, s, 134, 135))
				if err != nil || plan.materialization == nil {
					t.Fatal("observed actual Final image association", err)
				}
			}
			custody := &observationExchangeCustody{instance: generatedVectorID(105)}
			permit := &admittedGeneratedFinal{session: s, plan: plan, crypto: custody, instance: custody.instance, deadline: time.Unix(0, int64(plan.request.Context.Expiry))}
			if !attachOperationObservation(&permit.observation, s, plan.request.Context, condition != "disabled") {
				t.Fatal("final owner admission")
			}
			binding := s.authority().CurrentBinding
			digest, err := contract.PublicBindingDigest(*binding)
			if err != nil {
				t.Fatal(err)
			}
			key := contract.KeyUseRow{BindingID: binding.BindingID, PublicBindingDigest: digest, SubjectKind: 1, SubjectID: s.admission.recipient, Provider: binding.Provider, Purpose: contract.KeyUseMaterialOpen, Outcome: contract.KeyUseCompleted, Count: 1}
			prepared := make([]contract.CryptoGeneratedValueEntryResult, len(plan.entryPlans))
			for i, entry := range plan.entryPlans {
				prepared[i] = generatedPreparedValueEntryFixture(t, s, entry)
			}
			custody.reply = func(q contract.CryptoRequest) contract.CryptoResponse {
				if q.Kind == contract.CryptoCompare {
					body, err := contract.EncodeCryptoGeneratedCompareResult(contract.CryptoGeneratedCompareResult{OperationRef: generatedVectorID(128)})
					if err != nil {
						t.Fatal(err)
					}
					opened := key
					if plan.materialization != nil {
						opened.Count += uint32(len(prepared))
					}
					return observationReply(q, contract.CryptoSuccess, []contract.KeyUseRow{opened}, body)
				}
				body, err := contract.EncodeCryptoGeneratedValueEntriesResult(contract.CryptoGeneratedValueEntriesResult{Final: 1, Rows: prepared})
				if err != nil {
					t.Fatal(err)
				}
				var keys []contract.KeyUseRow
				if len(prepared) > 0 {
					wrap := key
					wrap.Purpose, wrap.Count = contract.KeyUseMaterialWrap, uint32(len(prepared))
					keys = []contract.KeyUseRow{wrap}
				}
				return observationReply(q, contract.CryptoSuccess, keys, body)
			}
			if condition == "full" {
				permit.observation.collector.storedBytes = observationRetainedLimit()
			}
			if condition == "busy" {
				permit.observation.collector.mu.Lock()
			}
			result, observed := s.prepareGeneratedFinal(t.Context(), permit)
			if condition == "busy" {
				permit.observation.collector.mu.Unlock()
			}
			if result == nil || observed.Outcome != ObservedCurrent {
				t.Fatal("real final preparation", observed)
			}
			wantSource := permit.observation.sourceFor(observationSource{Stage: observationExchange, OperationID: generatedVectorID(10), PhaseID: result.reservation.candidate.head.Generator.PhaseID})
			if result.reservation.candidate.observation != permit.observation || result.reservation.candidate.observationSource != wantSource {
				t.Fatal("candidate lost fixed owner")
			}
			facts, status := permit.observation.read()

			var expected []observationSubject
			base := observationFieldSource | observationFieldConfidentiality | observationFieldMembership | observationFieldEncodedMaterial | observationFieldGeneration
			for _, entry := range prepared {
				expected = append(expected, observationExpectedSubject(s.root.Domain, contract.ChangedSubjectValueEntry, contract.ChangedSubjectAdded, entry.Entry.Incarnation, contract.ID{}, base), observationExpectedSubject(s.root.Domain, contract.ChangedSubjectMembership, contract.ChangedSubjectAdded, entry.Entry.Incarnation, s.admission.recipient, observationFieldMembership), observationExpectedSubject(s.root.Domain, contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectAdded, entry.Entry.Generated.GenerationID, contract.ID{}, observationFieldGeneration))
			}
			descriptor, subjects := observationExpectedDescriptor(expected)
			pure, err := generatedFinalChangedSubjects(t.Context(), s, result.reservation.state)
			if err != nil || pure != descriptor {
				t.Fatal("original commitment changed under collector mode", condition, err, pure, descriptor)
			}
			if condition == "disabled" || condition == "full" || condition == "busy" {
				if len(facts) != 0 {
					t.Fatal("dropped fact retained", status)
				}
				return
			}
			changeIndex := 2
			if plan.materialization != nil {
				changeIndex = 1
			}
			if len(facts) != changeIndex+1 || facts[0].Exchange == nil || changeIndex == 2 && facts[1].Exchange == nil || facts[changeIndex].Change == nil {
				t.Fatal("real final facts missing", status)
			}
			detail := facts[changeIndex].Change

			if detail.Source.Stage != observationCandidate || detail.Descriptor != descriptor || !slices.Equal(detail.Subjects, subjects) || detail.Candidate != (observationCandidateIdentity{RevisionID: result.reservation.candidate.head.Core.Revision, SnapshotID: result.reservation.state.root.Snapshot, PredecessorRevisionID: s.head.Core.Revision, PredecessorDigest: contract.Hash(s.body)}) {
				t.Fatal("candidate detail or stage changed", detail)
			}

			again, _ := permit.observation.read()
			if len(again) != len(facts) {
				t.Fatal("pure recomputation emitted duplicate")
			}
			if len(prepared) > 0 {
				if len(detail.Generations) != 2*len(prepared) {
					t.Fatal("available metadata or plan intent lost", detail.Generations)
				}
				for i, entry := range prepared {
					if detail.Generations[i].GenerationID != entry.Entry.Generated.GenerationID || detail.Generations[len(prepared)+i].GenerationID != (contract.ID{}) || detail.Generations[len(prepared)+i].PlanID != plan.request.Parent.PlanGraphID {
						t.Fatal("actual generation and plan identity confused", detail.Generations)
					}
				}

				for _, entry := range detail.Entries {
					if entry.Relation != observationRelationUnavailable {
						t.Fatal("plan intent made equality claim")
					}
				}
			}
		})
	}
}

// full_only: true
// Proves the real comparison union of disjoint 512-entry states, 8192 changed
// memberships, and 1024 historical/proposed labels at the 256-byte name limit.
func TestComparisonObservationRealMaximumUnion(t *testing.T) {
	s, _ := observationTestSession(t)
	recipients := []contract.ID{s.admission.recipient}
	for i := 0; i < 7; i++ {
		id := observationBoundID(300 + i)
		binding := generatedPublicBinding(t, byte(220+i))
		binding.Provider, binding.ProtectionClass = contract.AWS, contract.HardwareProtection
		binding.KeySelector = fmt.Sprintf("arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-%012d", i+2)
		s.recipients[0].Slots[i+1] = &contract.RecipientRecord{RecipientID: id, Status: contract.CurrentRecipient, CurrentBinding: &binding}
		recipients = append(recipients, id)
	}
	slices.SortFunc(recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	old := make([]contract.ValueEntry, 512)
	input := make([]ApplyEntryInput, 512)
	for i := range old {
		name := fmt.Sprintf("before-%03d-", i)
		name += strings.Repeat("b", 256-len(name))
		old[i] = observationPlainEntry(name, observationBoundID(1000+i), recipients)
		old[i].ValueState = observationBoundID(5000 + i)
		name = fmt.Sprintf("after-%03d-", i)
		name += strings.Repeat("a", 256-len(name))
		input[i] = ApplyEntryInput{Name: name, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: slices.Clone(recipients), InputBytes: []byte("value"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
	}
	observationInstallEntries(s, old)
	// The actual comparison rereads the selected output source. Keep this
	// maximum predecessor's recipient order, references and root counts valid.
	slices.SortFunc(s.recipients[0].Slots[:], func(a, b *contract.RecipientRecord) int {
		return bytes.Compare(a.RecipientID[:], b.RecipientID[:])
	})
	generatedSealSelectedFixture(t, s)
	parent := &AdmittedParentComparison{session: s, deadline: time.Now().Add(time.Minute)}
	if !attachLocalObservation(&parent.observation, s, true) {
		t.Fatal("maximum local owner")
	}
	comparison, result := s.compareObserved(t.Context(), input, parent)
	if comparison == nil || result.Outcome != ObservedCurrent {
		t.Fatal("real maximum comparison", result)
	}
	staging := comparisonObservation(comparison)
	if cap(staging.Entries) != 1024 || cap(staging.Names) != 1024 || cap(staging.Memberships) != 8192 {
		t.Fatal("actual comparison projection exceeds pending bound")
	}
	facts, status := parent.observation.read()
	if len(facts) != 1 || status.Rejected != 0 || facts[0].Change == nil {
		t.Fatal("maximum complete fact missing", status)
	}
	detail := facts[0].Change
	if cap(detail.Entries) != 1024 || cap(detail.Names) != 512 || cap(detail.Memberships) != 8192 {
		t.Fatal("comparison staging capacity exceeded")
	}
	if len(detail.Entries) != 1024 || len(detail.Names) != 512 || len(detail.Memberships) != 8192 || detail.HasChangedSubjects {
		t.Fatal("maximum union truncated", len(detail.Entries), len(detail.Names), len(detail.Memberships))
	}
	for i, entry := range detail.Entries[:512] {
		if entry.BeforePresent || !entry.AfterPresent || entry.ProposedName != input[i].Name || !entry.AfterIncarnationID.IsZero() {
			t.Fatal("after proposed identity changed", i)
		}
	}
	for i, entry := range detail.Entries[512:] {
		if !entry.BeforePresent || entry.AfterPresent || entry.BeforeIncarnationID != old[i].Incarnation || detail.Names[i] != (observationName{EntryIncarnationID: old[i].Incarnation, Name: old[i].Name, Side: observationBefore}) {
			t.Fatal("before identity changed", i)
		}
	}
	expected := make(map[observationMembership]bool, 8192)
	for i, entry := range old {
		for _, recipient := range recipients {
			expected[observationMembership{EntryIncarnationID: entry.Incarnation, RecipientID: recipient, Change: contract.ChangedSubjectRemoved}] = true
			expected[observationMembership{EntryIndex: uint16(i), RecipientID: recipient, Change: contract.ChangedSubjectAdded}] = true
		}
	}
	for _, row := range detail.Memberships {
		if !expected[row] {
			t.Fatal("unexpected complete membership", row)
		}
		delete(expected, row)
	}
	if len(expected) != 0 {
		t.Fatal("missing complete memberships", len(expected))
	}
	after := *s
	entries := make([]contract.ValueEntry, len(input))
	for i, entry := range input {
		entries[i] = observationPlainEntry(entry.Name, observationBoundID(2000+i), recipients)
		entries[i].ValueState = observationBoundID(6000 + i)
	}
	observationInstallEntries(&after, entries)
	candidate := ordinaryCandidateObservation(s, &after)
	candidate.Source.Stage = observationCandidate
	if len(candidate.Entries) != 1024 || len(candidate.Names) != 1024 || candidate.HasChangedSubjects || len(candidate.Subjects) != 0 {
		t.Fatal("ordinary candidate union truncated or acquired a commitment")
	}
	for i, entry := range candidate.Entries {
		if entry.Relation != observationRelationUnavailable || entry.Fields != observationFieldSource|observationFieldConfidentiality|observationFieldMembership|observationFieldEncodedMaterial {
			t.Fatal("ordinary candidate fields changed", i, entry)
		}
	}
	observationAssertMaximumFits(t, candidate)
}

// full_only: true
// Proves the complete generated producer vector: 512 entries and 8 recipients
// per side, 128 generations per side, 9472 rows, and all 512 applicable plans.
func TestGeneratedChangeProjectionRealMaximum(t *testing.T) {
	before, _ := observationTestSession(t)
	after := *before
	fixture, _, _ := generatedDetachedRetirementState(t, "new incarnation", 0)
	generated := *fixture.valueEntry(0)
	recipients := make([]contract.ID, 8)
	for i := range recipients {
		recipients[i] = observationBoundID(300 + i)
	}
	old, next := make([]contract.ValueEntry, 512), make([]contract.ValueEntry, 512)
	var expected []observationSubject
	bundle := contract.GeneratorPlanBundle{}
	bundle.UsePlan.PlanGraphID = observationBoundID(70000)
	for i := range old {
		name := fmt.Sprintf("entry-%03d-", i)
		name += strings.Repeat("n", 256-len(name))
		old[i] = observationPlainEntry(name, observationBoundID(1000+i), recipients)
		next[i] = observationPlainEntry(name, observationBoundID(2000+i), recipients)
		fields := observationFieldSource | observationFieldConfidentiality | observationFieldMembership | observationFieldEncodedMaterial
		plan := contract.GeneratorValueEntryPlan{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorValueEntryPlanSchema, Slot: uint16(i), Name: name, EntryIncarnationID: next[i].Incarnation, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, SourceSlice: contract.GeneratorDescriptor{Digest: observationBoundID(80000 + i), Length: 4}, IntendedMembership: contract.GeneratorDescriptor{Digest: observationBoundID(81000 + i), Length: 260, Count: 8}, ChangeMask: contract.GeneratorValueChangeMask}
		if i < 128 {
			old[i], next[i] = generated, generated
			old[i].Name, next[i].Name = name, name
			old[i].Incarnation, next[i].Incarnation = observationBoundID(1000+i), observationBoundID(2000+i)
			old[i].Recipients, next[i].Recipients = slices.Clone(recipients), slices.Clone(recipients)
			old[i].Generated.GenerationID, next[i].Generated.GenerationID = observationBoundID(3000+i), observationBoundID(4000+i)
			old[i].ValueState, next[i].ValueState = old[i].Generated.GenerationID, next[i].Generated.GenerationID
			fields |= observationFieldGeneration
			plan.ValueSource, plan.ConfidentialityClass, plan.LifecycleMode = contract.Generated, contract.Secret, contract.GeneratorLifecycleManaged
			plan.Epoch, plan.IntentDigest, plan.PlannedValueSlotID, plan.LineageID, plan.RetirementMode, plan.SourceSlice = 1, generatedVectorID(206), observationBoundID(83000+i), observationBoundID(82000+i), 1, contract.GeneratorDescriptor{}
			expected = append(expected, observationExpectedSubject(before.root.Domain, contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectRemoved, old[i].Generated.GenerationID, contract.ID{}, observationFieldGeneration), observationExpectedSubject(before.root.Domain, contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectAdded, next[i].Generated.GenerationID, contract.ID{}, observationFieldGeneration))
		}
		bundle.ValueEntryPlans = append(bundle.ValueEntryPlans, plan)
		expected = append(expected, observationExpectedSubject(before.root.Domain, contract.ChangedSubjectValueEntry, contract.ChangedSubjectRemoved, old[i].Incarnation, contract.ID{}, fields), observationExpectedSubject(before.root.Domain, contract.ChangedSubjectValueEntry, contract.ChangedSubjectAdded, next[i].Incarnation, contract.ID{}, fields))
		for _, recipient := range recipients {
			expected = append(expected, observationExpectedSubject(before.root.Domain, contract.ChangedSubjectMembership, contract.ChangedSubjectRemoved, old[i].Incarnation, recipient, observationFieldMembership), observationExpectedSubject(before.root.Domain, contract.ChangedSubjectMembership, contract.ChangedSubjectAdded, next[i].Incarnation, recipient, observationFieldMembership))
		}
	}
	observationInstallEntries(before, old)
	observationInstallEntries(&after, next)
	if _, err := contract.GeneratorValueEntryPlansDescriptor(bundle.ValueEntryPlans); err != nil {
		t.Fatal("applicable maximum plans invalid", err)
	}
	var detail changeObservation
	got, err := generatedChangedSubjects(t.Context(), before, &after, &detail)
	if err != nil {
		t.Fatal(err)
	}
	addGeneratedPlanObservation(&detail, bundle)
	want, subjects := observationExpectedDescriptor(expected)
	if cap(detail.Entries) != 1024 || cap(detail.Names) != 1024 || cap(detail.Subjects) != 9472 || cap(detail.Memberships) != 8192 || cap(detail.Generations) != 768 {
		t.Fatal("producer capacity exceeded source bound")
	}
	if got != want || !slices.Equal(detail.Subjects, subjects) || got.Count != 9472 || got.Length != 359940 || len(detail.Names) != 1024 || len(detail.Memberships) != 8192 || len(detail.Generations) != 768 {
		t.Fatal("maximum producer output truncated or changed", got, want, len(detail.Generations))
	}
	detail.Source.Stage = observationCandidate
	var owner *operationObservation
	if !attachLocalObservation(&owner, before, true) {
		t.Fatal("maximum producer owner admission")
	}
	if !owner.offerChange(t.Context(), detail) {
		t.Fatal("maximum complete generated projection not accepted")
	}
	facts, status := owner.read()
	if len(facts) != 1 || status.Accepted != 1 || facts[0].Change == nil || !slices.Equal(facts[0].Change.Subjects, subjects) || len(facts[0].Change.Generations) != 768 || facts[0].Change.Descriptor != want {
		t.Fatal("maximum generated read lost complete rows", status)
	}
	for i := range old {
		wantBefore := observationName{EntryIncarnationID: old[i].Incarnation, Name: old[i].Name, Side: observationBefore}
		wantAfter := observationName{EntryIncarnationID: next[i].Incarnation, Name: next[i].Name, Side: observationAfter}
		if facts[0].Change.Names[2*i] != wantBefore || facts[0].Change.Names[2*i+1] != wantAfter {
			t.Fatal("maximum historical binding mismatch", i)
		}
		if i < 128 {
			wantPrior := observationGeneration{EntryIncarnationID: old[i].Incarnation, GenerationID: old[i].Generated.GenerationID, Side: observationBefore}
			wantNext := observationGeneration{EntryIncarnationID: next[i].Incarnation, GenerationID: next[i].Generated.GenerationID, Side: observationAfter}
			if facts[0].Change.Generations[2*i] != wantPrior || facts[0].Change.Generations[2*i+1] != wantNext {
				t.Fatal("actual generation identity mismatch", i)
			}
		}
	}
	if !observationChangeValid(detail) {
		t.Fatal("maximum complete producer output rejected by representation")
	}
	for i, plan := range detail.Generations[256:] {
		if plan.EntryIncarnationID != next[i].Incarnation || plan.PlanID != bundle.UsePlan.PlanGraphID || !plan.PlannedContent || !plan.PlannedMembership || !plan.PlannedRetirement || !plan.GenerationID.IsZero() {
			t.Fatal("supplied intent fabricated generation", i, plan)
		}
	}
}

type observationCandidateStore struct {
	*generatedFixtureSupportStore
	fail   bool
	writes int
}

func (s *observationCandidateStore) Create(_ context.Context, key string, body []byte) contract.WriteResult {
	s.writes++
	if s.fail {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess, NotSent: true}
	}
	s.objects[key] = bytes.Clone(body)
	return contract.WriteResult{Status: contract.WriteAcknowledged}
}

// full_only: false
func TestGeneratedRetirementOwnersKeepFactsBeforePersistenceFailure(t *testing.T) {
	for _, condition := range []string{"close signing", "close immutable write", "park unknown", "parked residue"} {
		t.Run(condition, func(t *testing.T) {
			var s *StateSession
			var original generatedAttempt
			var duty contract.GeneratedDutyRecord
			switch condition {
			case "close signing", "close immutable write":
				s, original, duty, _ = generatedLiveEnteredRetirementForLaterFailure(t)
			case "park unknown":
				s, original, duty, _ = generatedEnteredRetirementState(t, false)
				generatedLifecycleFixtureForFamily(t, s, contract.GCP)
			default:
				s, original, duty = generatedParkedRetirementState(t)
				generatedLifecycleFixtureForFamily(t, s, contract.GCP)
			}
			observationProtectFixture(t, s)
			admitted := generatedContinuationContext(t, s, 146, 147)
			backing := s.store.(*generatedFixtureSupportStore)
			store := &observationCandidateStore{generatedFixtureSupportStore: backing, fail: condition == "close immutable write"}
			s.store = store
			before, encodeErr := format.EncodeRoot(s.root)
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			var permit *admittedGeneratedLifecycle
			var err error
			switch condition {
			case "close signing", "close immutable write":
				permit, err = s.admitGeneratedRetirementClose(t.Context(), original.record.AttemptID, admitted)
			case "park unknown":
				facts, encodeErr := contract.EncodeGeneratorSafeFacts(generatedRetirementFactsFixture(t, s, original, contract.GeneratorDispositionUnknown))
				if encodeErr != nil {
					t.Fatal(encodeErr)
				}
				permit, err = s.admitGeneratedRetirementUnknown(t.Context(), duty.DutyID, facts, admitted)
			default:
				permit, err = s.admitGeneratedActiveRetirementResidue(t.Context(), duty.DutyID, nil, admitted)
			}
			if err != nil || permit == nil {
				t.Fatal("real lifecycle admission", err)
			}
			if !attachOperationObservation(&permit.observation, s, admitted, true) {
				t.Fatal("lifecycle observation admission")
			}
			selected := mustSelectedGeneratedWork(t, s)
			_, err = selected.retainedGraph(original.record.OperationID)
			if err != nil {
				t.Fatal(err)
			}
			if condition == "close signing" || condition == "close immutable write" {
				projection, err := s.generatedRetiringChangedSubjects(t.Context(), duty.DutyID)
				if err != nil || projection.Count != 2 {
					t.Fatal("retirement fixture missing exact metadata delta", err, projection)
				}
			}
			if pure, status := permit.observation.read(); len(pure) != 0 || status.Accepted != 0 {
				t.Fatal("pure admission or recomputation emitted", status)
			}
			trust := &generatedInboxReleaseReadTrust{identity: s.admission.trust, family: s.admission.store.Family}
			candidate, result := s.prepareGeneratedLifecycle(t.Context(), permit, trust)
			want := failure(EvidenceUnavailable, SigningUnavailable)
			if condition == "close immutable write" {
				want = Result{Outcome: EvidenceUnavailable, Reason: WriteUncertain, StoreReason: contract.ReasonAccess}
			}
			if candidate != nil || result != want || store.writes == 0 || condition != "close immutable write" && trust.signs != 1 || condition == "close immutable write" && trust.signs != 0 {
				t.Fatal("controlled persistence boundary changed", result, store.writes, trust.signs)
			}
			facts, status := permit.observation.read()
			if len(facts) != 1 || facts[0].Change == nil || status.Accepted != 1 {
				t.Fatal("validated candidate detail lost", status)
			}
			detail := facts[0].Change
			if detail.Source.Stage != observationCandidate || detail.Source.OperationID != permit.plan.identity.operation || detail.Source.ParentID != original.record.OperationID || detail.Source.AttemptID != original.record.AttemptID || detail.Candidate.RevisionID != permit.plan.identity.revision || detail.Candidate.SnapshotID != permit.plan.identity.snapshot || detail.Result != (Result{}) {
				t.Fatal("candidate stage or original/current roles changed", detail)
			}
			var expected []observationSubject
			if condition == "close signing" || condition == "close immutable write" {
				entry := s.valueEntry(0)
				expected = []observationSubject{observationExpectedSubject(s.root.Domain, contract.ChangedSubjectValueEntry, contract.ChangedSubjectUpdated, entry.Incarnation, contract.ID{}, observationFieldGeneration), observationExpectedSubject(s.root.Domain, contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectUpdated, entry.Generated.GenerationID, contract.ID{}, observationFieldGeneration)}
			}
			descriptor, subjects := observationExpectedDescriptor(expected)
			if !detail.HasChangedSubjects || detail.Descriptor != descriptor || !slices.Equal(detail.Subjects, subjects) {
				t.Fatal("retirement or authenticated empty commitment changed", detail.Descriptor, descriptor)
			}
			after, encodeErr := format.EncodeRoot(s.root)
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("observer changed predecessor")
			}
		})
	}
}

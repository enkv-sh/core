package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func generatedSuccessorPredecessorSnapshot(t testing.TB, s *StateSession) []byte {
	t.Helper()
	root, err := format.EncodeRoot(s.root)
	if err != nil {
		t.Fatal(err)
	}
	var backing []string
	backing = append(backing, fmt.Sprintf("body=%p names=%p support=%p support-facts=%p fragments=%p cache=%p access-locations=%p value-readers=%p generated-work=%p generated-graphs=%p publication-proof=%p slice-locations=%p",
		s.body, s.root.Names, s.support, s.supportFacts, s.fragmentFacts, s.cache, s.accessLocations, s.valueReaders,
		s.generatedWork, s.generatedGraphs, s.publicationProof, s.generatedSliceLocations))
	for i, page := range s.pages {
		backing = append(backing, fmt.Sprintf("entry-page[%d]=%p", i, page))
		if page == nil {
			continue
		}
		for j, entry := range page.Slots {
			backing = append(backing, fmt.Sprintf("entry[%d,%d]=%p", i, j, entry))
			if entry != nil {
				backing = append(backing, fmt.Sprintf("entry-bytes[%d,%d]=%p recipients=%p", i, j, entry.ValueBytes, entry.Recipients))
			}
		}
	}
	for i, page := range s.access {
		backing = append(backing, fmt.Sprintf("access-page[%d]=%p", i, page))
		if page == nil {
			continue
		}
		backing = append(backing, fmt.Sprintf("access-records[%d]=%p", i, page.Records))
		for j, row := range page.Records {
			backing = append(backing, fmt.Sprintf("access-wraps[%d,%d]=%p", i, j, row.Wraps))
			for k, wrap := range row.Wraps {
				backing = append(backing, fmt.Sprintf("wrap-bytes[%d,%d,%d]=%p", i, j, k, wrap.RSACiphertext))
			}
		}
	}
	for i, page := range s.support {
		backing = append(backing, fmt.Sprintf("support-records[%d]=%p", i, page.Records))
		for j, row := range page.Records {
			backing = append(backing, fmt.Sprintf("support-body[%d,%d]=%p", i, j, row.Body))
		}
	}
	for i, fact := range s.supportFacts {
		backing = append(backing, fmt.Sprintf("support-fact-rows[%d]=%p ordinals=%p", i, fact.rows, fact.ordinals))
	}
	if s.publicationProof != nil {
		backing = append(backing, fmt.Sprintf("publication-proof-rows=%p", s.publicationProof.rows))
	}
	facts := fmt.Sprintf("%#v", struct {
		Support                 []selectedSupportPageFacts
		Fragments               map[format.FragmentLocation]selectedFragmentFact
		AccessLocations         map[materialIdentity]materialLocation
		ValueReaders            map[contract.ID][]contract.ID
		Cache                   map[format.Ref][]byte
		GeneratedWork           *validatedGeneratedSelection
		GeneratedGraphs         map[contract.ID]validatedGeneratorGraph
		PublicationProof        *selectedPublicationProof
		GeneratedSliceLocations []contract.GeneratorSliceLocation
		GeneratedSlicesRoot     contract.ID
		OutputConfigurationRoot contract.ID
	}{s.supportFacts, s.fragmentFacts, s.accessLocations, s.valueReaders, s.cache, s.generatedWork,
		s.generatedGraphs, s.publicationProof,
		s.generatedSliceLocations, s.generatedSlicesRoot, s.outputConfigurationRoot})
	body, err := json.Marshal(struct {
		Root           []byte
		Head           format.Head
		Pages          [contract.MaxValueEntryPages]*format.ValueEntryPage
		Recipients     [contract.MaxRecipientPages]*format.RecipientPage
		Access         [contract.MaxChildPages]*format.AccessPage
		Support        []format.RequiredSupportPageView
		Administrative format.AdministrativeIndex
		Body           []byte
		Token          contract.Token
		Facts          string
		Backing        []string
	}{root, s.head, s.pages, s.recipients, s.access, s.support, s.adminIndex, s.body, s.token, facts, backing})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// full_only: false
func TestGeneratedSuccessorAssemblyFailuresLeavePredecessorUnchanged(t *testing.T) {
	s := generatedEmptyPredecessorForFamily(t, contract.AWS)
	before := generatedSuccessorPredecessorSnapshot(t, s)
	plan := transitionPlan{operation: generatedVectorID(201), transition: generatedVectorID(202),
		snapshot: generatedVectorID(203), revision: generatedVectorID(204)}

	t.Run("support construction", func(t *testing.T) {
		next, candidate, identity := s.beginGeneratedSuccessor(plan)
		good := generatedMaterializerFragment(t, generatedVectorID(205), []byte("first"))
		bad := good
		bad.Body = []byte{0}
		err := s.installGeneratedSuccessorSupport(t.Context(), &next, [][]contract.SupportRecord{{good}, {bad}},
			[]contract.ID{generatedVectorID(206), generatedVectorID(207)}, candidate, &identity)
		if err == nil || len(candidate.objects) != 0 || len(identity.Pages) != 0 ||
			!bytes.Equal(before, generatedSuccessorPredecessorSnapshot(t, s)) {
			t.Fatal("failed page construction exposed partial work or changed the predecessor", err)
		}
	})

	t.Run("successor validation", func(t *testing.T) {
		next, candidate, _ := s.beginGeneratedSuccessor(plan)
		next.root.SecretCount = next.root.AccessRecordCount + 1
		if validAggregate(next.root) || len(candidate.objects) != 0 ||
			!bytes.Equal(before, generatedSuccessorPredecessorSnapshot(t, s)) {
			t.Fatal("invalid successor passed aggregate validation or changed the predecessor")
		}
	})

	t.Run("root encoding", func(t *testing.T) {
		next, candidate, identity := s.beginGeneratedSuccessor(plan)
		next.root.Domain = contract.ID{}
		if _, err := s.encodeGeneratedSuccessorRoot(&next, candidate, identity.Revision); err == nil ||
			len(candidate.objects) != 0 || !bytes.Equal(before, generatedSuccessorPredecessorSnapshot(t, s)) {
			t.Fatal("failed root encoding exposed a root or changed the predecessor", err)
		}
	})

	for _, failure := range []string{"support after entry and access construction", "root encoding after entry and access construction"} {
		t.Run(failure, func(t *testing.T) {
			s, _, duty, _ := generatedLiveEnteredRetirementForLaterFailure(t)
			unrelated := s.pages[0].Slots[1]
			before := generatedSuccessorPredecessorSnapshot(t, s)
			localPlan := plan
			localPlan.accessPages[0] = generatedVectorID(208)
			next, candidate, identity := s.beginGeneratedSuccessor(localPlan)
			lifecyclePlan := &generatedLifecyclePlan{identity: localPlan, requestIdentity: generatedVectorID(209)}
			if err := next.clearGeneratedRetiringPointer(t.Context(), duty.DutyID, lifecyclePlan, candidate, &identity); err != nil {
				t.Fatal("construct changed live entry page", err)
			}
			if err := next.packGeneratedLifecycleAccess(s.accessRecords(), localPlan, candidate, &identity); err != nil {
				t.Fatal("construct retained access page", err)
			}
			current := s.pages[0].Slots[0]
			changed := next.pages[0].Slots[0]
			if next.pages[0] == s.pages[0] || changed == current || changed.Generated.RetiringDutyPresent != 0 ||
				!changed.Generated.RetiringDutyID.IsZero() || !bytes.Equal(changed.ValueBytes, current.ValueBytes) ||
				&changed.ValueBytes[0] != &current.ValueBytes[0] || next.pages[0].Slots[1] != unrelated ||
				next.access[0] == s.access[0] || next.root.AccessRecordCount == 0 || len(candidate.objects) != 2 {
				t.Fatal("fixture did not copy the changed page and entry, retain unrelated backing and replace access")
			}
			objectCount, identityCount := len(candidate.objects), len(identity.Pages)
			var err error
			if failure == "support after entry and access construction" {
				good := generatedMaterializerFragment(t, generatedVectorID(205), []byte("first"))
				bad := good
				bad.Body = []byte{0}
				err = s.installGeneratedSuccessorSupport(t.Context(), &next, [][]contract.SupportRecord{{good}, {bad}},
					[]contract.ID{generatedVectorID(206), generatedVectorID(207)}, candidate, &identity)
			} else {
				next.root.Domain = contract.ID{}
				_, err = s.encodeGeneratedSuccessorRoot(&next, candidate, identity.Revision)
			}
			if err == nil || len(candidate.objects) != objectCount || len(identity.Pages) != identityCount ||
				!bytes.Equal(before, generatedSuccessorPredecessorSnapshot(t, s)) {
				t.Fatal("later assembly failure exposed partial stage output or changed predecessor backing", err)
			}
		})
	}

	t.Run("authority construction and validation", func(t *testing.T) {
		s, original, duty, _ := generatedEnteredRetirementState(t, true)
		generatedLifecycleCanonicalRetirement(t, s, original.record.AttemptID, duty.DutyID)
		ctx := generatedLifecycleFixture(t, s)
		before := generatedSuccessorPredecessorSnapshot(t, s)
		plan, err := s.generatedRetirementClosePlan(t.Context(), original.record.AttemptID, ctx)
		if err != nil {
			t.Fatal(err)
		}
		reserved, err := s.deriveGeneratedRetirementClose(t.Context(), plan, nil)
		if err != nil {
			t.Fatal(err)
		}
		g, err := s.selectedGeneratedWork(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		closure, err := g.generatedRetirementAcknowledgement(t.Context(), original.record.AttemptID, plan.identity.revision)
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := g.retainedGraph(closure.attempt.record.OperationID)
		if err != nil {
			t.Fatal(err)
		}
		_, err = g.retirementAttemptTarget(t.Context(), bundle, closure.attempt.record)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.generatedRetirementCloseSubject(t.Context(), reserved.state, g, plan, closure,
			contract.IdentityPlan{}, reserved.candidate.head.Core); err == nil {
			t.Fatal("invalid identity produced an authority subject")
		}
		next := *reserved.state
		candidate := &Candidate{session: s}
		err = s.finalizeGeneratedSuccessor(t.Context(), &next, candidate, reserved.candidate.head.Core,
			contract.GeneratorAuthoritySubject{})
		if !errors.Is(err, contract.ErrRecord) || !bytes.Equal(before, generatedSuccessorPredecessorSnapshot(t, s)) {
			t.Fatal("invalid authority validated or changed the predecessor", err)
		}
	})
}

// full_only: false
func TestGeneratedSuccessorFinalizationKeepsSelectedReadError(t *testing.T) {
	before := generatedEmptyPredecessor(t)
	reserved, err := before.deriveGeneratedReservation(context.Background(), generatedReservationInputFixture(t, before))
	if err != nil {
		t.Fatal("derive reservation", err)
	}
	predecessor := generatedSuccessorPredecessorSnapshot(t, before)
	finalize := func(ctx context.Context) (*StateSession, error) {
		next := *reserved.state
		next.generatedWork, next.generatedGraphs = nil, nil
		candidate := &Candidate{session: before}
		err := before.finalizeGeneratedSuccessor(ctx, &next, candidate, reserved.candidate.head.Core,
			*reserved.candidate.head.Generator)
		return &next, err
	}
	healthy, err := finalize(t.Context())
	if err != nil || healthy.generatedWork == nil {
		t.Fatal("healthy successor finalization refused", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	next, err := finalize(ctx)
	got, typed := selectedReadResult(err)
	want := Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable}
	if !typed || got != want || next.generatedWork != nil || next.generatedGraphs != nil ||
		!bytes.Equal(predecessor, generatedSuccessorPredecessorSnapshot(t, before)) {
		t.Fatal("canceled finalization lost selected read error, published facts or changed predecessor", got, typed, err)
	}
}

package core

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"reflect"
	"strconv"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

type observationSelectionStore struct {
	*generatedFixtureSupportStore
	token       contract.Token
	write       contract.WriteResult
	commit      bool
	unavailable bool
	sends       int
}

func (s *observationSelectionStore) Create(_ context.Context, key string, body []byte) contract.WriteResult {
	s.objects[key] = bytes.Clone(body)
	return contract.WriteResult{Status: contract.WriteAcknowledged}
}
func (s *observationSelectionStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	if s.unavailable && key == s.descriptor.HeadKey {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
	}
	r := s.generatedFixtureSupportStore.Read(ctx, key, limit)
	if key == s.descriptor.HeadKey && r.Status == contract.ReadOK {
		r.Token = s.token
	}
	return r
}
func (s *observationSelectionStore) CompareAndSwap(_ context.Context, key string, _ contract.Token, body []byte) contract.WriteResult {
	s.sends++
	if s.commit {
		s.objects[key] = bytes.Clone(body)
		if s.token.Family == contract.AWS {
			s.token.Value = fmt.Sprintf(`"observation-%d"`, s.sends)
			return s.write
		}
		generation, err := strconv.Atoi(s.token.Value)
		if err != nil {
			s.t.Fatal(err)
		}
		s.token.Value = fmt.Sprint(generation + 1)
	}
	return s.write
}

func observationPreparedSelection(t testing.TB) (*StateSession, *Candidate, *operationObservation, *observationSelectionStore, Result) {
	return observationPreparedSelectionForFamily(t, contract.GCP)
}

func observationPreparedSelectionForFamily(t testing.TB, family contract.Family) (*StateSession, *Candidate, *operationObservation, *observationSelectionStore, Result) {
	t.Helper()
	s := generatedEmptyPredecessorForFamily(t, family)
	observationProtectFixture(t, s)
	s.key, _ = publicKey(s.admission.publicKey)
	signer := testtrust.New(t, family, s.admission.trust)
	bindingRequest, err := contract.NewBindingRequest(binding(s.admission))
	if err != nil {
		t.Fatal(err)
	}
	s.head.K1 = signer.Sign(t.Context(), bindingRequest).Signature
	store := &observationSelectionStore{generatedFixtureSupportStore: s.store.(*generatedFixtureSupportStore), token: s.token,
		write: contract.WriteResult{Status: contract.WriteAcknowledged}, commit: true}
	s.store = store
	for ref, body := range s.cache {
		key, err := format.Key(s.admission.store.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		store.objects[key] = bytes.Clone(body)
	}
	recipientBody, err := format.EncodeRecipientPage(s.recipient)
	if err != nil {
		t.Fatal(err)
	}
	recipientKey, err := format.Key(s.admission.store.Prefix, *s.root.Recipients[0])
	if err != nil {
		t.Fatal(err)
	}
	store.objects[recipientKey] = recipientBody
	candidate, owner, result := observationPrepareNextSelection(t, s, 100000, "value", "enabled")
	return s, candidate, owner, store, result
}

func observationPrepareNextSelection(t testing.TB, s *StateSession, nonce int, value, mode string) (*Candidate, *operationObservation, Result) {
	t.Helper()
	parent := &AdmittedParentComparison{session: s, deadline: time.Now().Add(time.Minute)}
	if !attachLocalObservation(&parent.observation, s, mode != "disabled") {
		t.Fatal("observer admission")
	}
	owner := parent.observation
	switch mode {
	case "absent":
		parent.observation = nil
	case "busy":
		owner.collector.mu.Lock()
		defer owner.collector.mu.Unlock()
	case "full":
		owner.collector.storedBytes = observationRetainedLimit()
	}
	input := []ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{s.admission.recipient}, InputBytes: []byte(value)}}
	var c *Comparison
	var r Result
	if mode == "absent" {
		c, r = s.compare(t.Context(), input, nil)
	} else {
		c, r = s.compareObserved(t.Context(), input, parent)
	}
	if c == nil || r != s.observed(ObservedCurrent) {
		t.Fatal("comparison", r)
	}
	var entropy []byte
	for i := 0; i < 100; i++ {
		id := observationBoundID(nonce + i)
		entropy = append(entropy, id[:]...)
	}
	s.admission.entropy = bytes.NewReader(entropy)
	plan, err := planTransition(t.Context(), c)
	if err != nil {
		t.Fatal("plan")
	}
	next, err := s.deriveSuccessor(t.Context(), c, plan)
	if err != nil {
		t.Fatal("derive")
	}
	authority, err := s.authorityFrom(next, c, plan)
	if err != nil {
		t.Fatal(err)
	}
	permit := &AdmittedParentTransition{session: s, comparison: c, predecessorDigest: contract.Hash(s.body), predecessorRevision: s.head.Core.Revision, predecessorToken: s.token, plan: plan, authority: authority}
	candidate, result := s.prepare(t.Context(), c, permit, testtrust.New(t, s.admission.store.Family, s.admission.trust))
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("prepare", result)
	}
	return candidate, parent.observation, result
}

// full_only: false
func TestSelectionObservationKeepsFinalResultAndCandidateOwner(t *testing.T) {
	s, candidate, owner, _, preparation := observationPreparedSelection(t)
	if preparation != (Result{Outcome: ObservedCurrent, ObservedRevision: s.head.Core.Revision, ObservedSnapshotID: s.root.Snapshot, Evidence: AuthenticatedClosure, RequestedRevision: candidate.head.Core.Revision}) {
		t.Fatal("preparation currentness changed", preparation)
	}
	before, _ := owner.read()
	current, result := s.selectCandidate(t.Context(), candidate)
	want := Result{Outcome: ObservedCurrent, RequestedRevision: candidate.head.Core.Revision, ObservedRevision: candidate.head.Core.Revision, ObservedSnapshotID: candidate.head.Core.Root.Object, Evidence: AuthenticatedClosure}
	if current == nil || result != want {
		t.Fatal("selection", result, want)
	}
	facts, status := owner.read()
	if len(facts) != len(before)+1 || status.Accepted != uint64(len(facts)) {
		t.Fatal("selection lost its admitted operation observation", status, len(facts), len(before))
	}
	expected := changeObservation{Source: owner.sourceFor(observationSource{Stage: observationSelection, OperationID: candidate.head.Subject.Operation}), Candidate: observationCandidateIdentity{RevisionID: candidate.head.Core.Revision, SnapshotID: candidate.head.Core.Root.Object, PredecessorRevisionID: s.head.Core.Revision, PredecessorDigest: contract.Hash(s.body)}, Result: want}
	if !reflect.DeepEqual(facts[len(facts)-1].Change, &expected) {
		t.Fatal("whole selection projection differs", facts[len(facts)-1])
	}
	if candidate.observation != owner {
		t.Fatal("candidate lost fixed owner")
	}
}

func observationSelectedPredecessor(t testing.TB) (*StateSession, *operationObservation, *observationSelectionStore) {
	t.Helper()
	s, c, old, store, _ := observationPreparedSelection(t)
	current, result := s.selectCandidate(t.Context(), c)
	if current == nil || result.Outcome != ObservedCurrent {
		t.Fatal("authenticated predecessor", result)
	}
	return current, old, store
}

func observationCheckSelectionFact(t testing.TB, s *StateSession, c *Candidate, owner *operationObservation, before []observationFact, want Result) {
	t.Helper()
	facts, status := owner.read()
	source := c.observationSource
	source.Stage = observationSelection
	expected := changeObservation{Source: source, Candidate: observationCandidateIdentity{RevisionID: c.head.Core.Revision, SnapshotID: c.head.Core.Root.Object, PredecessorRevisionID: s.head.Core.Revision, PredecessorDigest: contract.Hash(s.body)}, Result: want}
	if len(facts) != len(before)+1 || status.Accepted != uint64(len(facts)) || !reflect.DeepEqual(facts[:len(before)], before) || !reflect.DeepEqual(facts[len(facts)-1].Change, &expected) {
		t.Fatal("selection changed earlier facts or lost exact final fact", status)
	}
}

// full_only: false
func TestSelectionObservationPreservesControlledOutcomes(t *testing.T) {
	for _, condition := range []string{"acknowledged", "contention", "write refused", "lost reply exact readback", "unresolved commit", "ack unreadable", "conflict exact readback", "not sent predecessor", "different selected", "not sent different selected", "custody failure", "readiness refusal", "cancelled before send", "cancelled public wrapper"} {
		t.Run(condition, func(t *testing.T) {
			s, old, store := observationSelectedPredecessor(t)
			oldFacts, _ := old.read()
			c, owner, preparation := observationPrepareNextSelection(t, s, 101000, "changed", "enabled")
			if preparation != (Result{Outcome: ObservedCurrent, RequestedRevision: c.head.Core.Revision, ObservedRevision: s.head.Core.Revision, ObservedSnapshotID: s.root.Snapshot, Evidence: AuthenticatedClosure}) {
				t.Fatal("preparation made selection claim", preparation)
			}
			before, _ := owner.read()
			want := Result{Outcome: ObservedCurrent, RequestedRevision: c.head.Core.Revision, ObservedRevision: c.head.Core.Revision, ObservedSnapshotID: c.head.Core.Root.Object, Evidence: AuthenticatedClosure}
			handoffs := 0
			c.firstSend = &candidateFirstSend{handoff: func(_ context.Context, digest contract.ID) contract.CryptoResultCode {
				q, err := contract.NewLifecycleRequest(c.head.Subject)
				if err != nil || digest != q.Digest() {
					t.Fatal("handoff request changed")
				}
				handoffs++
				if condition == "custody failure" {
					return contract.CryptoCustodyUnavailable
				}
				return contract.CryptoSuccess
			}}
			ctx := t.Context()
			switch condition {
			case "contention":
				store.commit = false
				store.write = contract.WriteResult{Status: contract.WritePrecondition}
				want = Result{Outcome: Contention, Reason: StalePrecondition, RequestedRevision: c.head.Core.Revision, ObservedRevision: s.head.Core.Revision, ObservedSnapshotID: s.root.Snapshot, Evidence: AuthenticatedClosure}
			case "write refused":
				store.commit = false
				store.write = contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess}
				want = Result{Outcome: EvidenceUnavailable, Reason: WriteUncertain, StoreReason: contract.ReasonAccess, RequestedRevision: c.head.Core.Revision}
			case "lost reply exact readback":
				store.write = contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
			case "conflict exact readback":
				store.write = contract.WriteResult{Status: contract.WriteConflict}
			case "unresolved commit", "ack unreadable":
				store.unavailable = true
				if condition == "unresolved commit" {
					store.write = contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonAccess}
				}
				want = Result{Outcome: UnresolvedCommit, Reason: ReadUnavailable, RequestedRevision: c.head.Core.Revision, StoreReason: contract.ReasonAccess, CommitMayHaveOccurred: true}
			case "not sent predecessor":
				store.commit = false
				store.write = contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport, NotSent: true}
				want = Result{Outcome: EvidenceUnavailable, Reason: WriteUncertain, RequestedRevision: c.head.Core.Revision, StoreReason: contract.ReasonTransport}
			case "different selected", "not sent different selected":
				competitor := *s
				competitor.prepared = false
				other, _, _ := observationPrepareNextSelection(t, &competitor, 102000, "competitor", "enabled")
				store.objects[store.descriptor.HeadKey] = bytes.Clone(other.body)
				store.token.Value = "29"
				store.commit = false
				store.write = contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonAccess, NotSent: condition == "not sent different selected"}
				want = Result{Outcome: UnresolvedCommit, Reason: DifferentSelection, RequestedRevision: c.head.Core.Revision, ObservedRevision: other.head.Core.Revision, ObservedSnapshotID: other.head.Core.Root.Object, Evidence: AuthenticatedClosure, CommitMayHaveOccurred: true}
				if condition == "not sent different selected" {
					want.Outcome, want.CommitMayHaveOccurred = Contention, false
				}
			case "custody failure":
				want.Reason = CustodyUnavailable
			case "readiness refusal":
				c.generated = &generatedCandidateFacts{}
				want = (Result{Outcome: AdmissionRefused, Reason: AdmissionInvalid})
			case "cancelled before send", "cancelled public wrapper":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
				want = Result{Outcome: EvidenceUnavailable, Reason: WriteUncertain, RequestedRevision: c.head.Core.Revision, StoreReason: contract.ReasonLimit}
				if condition == "cancelled public wrapper" {
					want = (Result{Outcome: AdmissionRefused, Reason: AdmissionInvalid})
				}
			}
			sendsBefore := store.sends
			var result Result
			if condition == "cancelled public wrapper" {
				result = s.Select(ctx, c)
			} else {
				_, result = s.selectCandidate(ctx, c)
			}
			if result != want {
				t.Fatal("whole operational result differs", result, want)
			}
			expectedSends, expectedHandoffs := 1, 0
			switch condition {
			case "acknowledged", "custody failure":
				expectedHandoffs = 1
			case "not sent predecessor":
				expectedSends = 3
			case "readiness refusal", "cancelled before send", "cancelled public wrapper":
				expectedSends = 0
			}
			if store.sends-sendsBefore != expectedSends || handoffs != expectedHandoffs {
				t.Fatal("selection or first-send count changed", store.sends-sendsBefore, handoffs)
			}
			observationCheckSelectionFact(t, s, c, owner, before, want)
			after, _ := old.read()
			if !reflect.DeepEqual(after, oldFacts) {
				t.Fatal("returned-session reuse leaked into prior collector")
			}
		})
	}
}

// full_only: false
func TestSelectionObservationIsolationAndLossPreserveOperation(t *testing.T) {
	var root format.Ref
	var subject contract.LifecycleSubject
	var baselineKeys []string
	base, old, baseStore := observationSelectedPredecessor(t)
	for _, mode := range []string{"enabled", "absent", "disabled", "full", "busy"} {
		t.Run(mode, func(t *testing.T) {
			copy := *base
			s := &copy
			physical := *baseStore.generatedFixtureSupportStore
			physical.objects, physical.keys, physical.limits = maps.Clone(physical.objects), nil, nil
			storeCopy := *baseStore
			storeCopy.generatedFixtureSupportStore = &physical
			store := &storeCopy
			s.store = store
			s.cache = maps.Clone(s.cache)
			oldFacts, _ := old.read()
			c, owner, _ := observationPrepareNextSelection(t, s, 101000, "changed", mode)
			firstSend := &candidateFirstSend{}
			sends := 0
			firstSend.handoff = func(context.Context, contract.ID) contract.CryptoResultCode { sends++; return contract.CryptoSuccess }
			c.firstSend = firstSend
			if mode == "busy" {
				owner.collector.mu.Lock()
			}
			current, result := s.selectCandidate(t.Context(), c)
			if mode == "busy" {
				owner.collector.mu.Unlock()
			}
			want := Result{Outcome: ObservedCurrent, RequestedRevision: c.head.Core.Revision, ObservedRevision: c.head.Core.Revision, ObservedSnapshotID: c.head.Core.Root.Object, Evidence: AuthenticatedClosure}
			if current == nil || result != want || sends != 1 || store.sends != 2 || !c.used || c.firstSend != nil || c.objects != nil || firstSend.take() != nil {
				t.Fatal("observation altered result or one-use ownership", result, sends)
			}
			if mode == "enabled" {
				root, subject, baselineKeys = c.head.Core.Root, c.head.Subject, append([]string(nil), store.keys...)
			} else if c.head.Core.Root != root || c.head.Subject != subject || !reflect.DeepEqual(store.keys, baselineKeys) {
				t.Fatal("observation altered commitments or Store work")
			}
			facts, status := owner.read()
			switch mode {
			case "enabled":
				if len(facts) != 3 || status.Accepted != 3 {
					t.Fatal(status)
				}
			case "absent", "disabled":
				if len(facts) != 0 || status != (observationStatus{}) {
					t.Fatal(status)
				}
			case "full":
				if len(facts) != 0 || status.DroppedFull != 3 {
					t.Fatal(status)
				}
			case "busy":
				if len(facts) != 0 || status.DroppedContention != 3 {
					t.Fatal(status)
				}
			}
			after, _ := old.read()
			if !reflect.DeepEqual(after, oldFacts) {
				t.Fatal("new invocation changed old collector")
			}
		})
	}
	t.Run("fixed owner survives later context and replacement attempt", func(t *testing.T) {
		s, c, owner, _, _ := observationPreparedSelection(t)
		replacement := observationTestOwner(t)
		before, _ := owner.read()
		c.bindObservation(replacement, observationSource{OperationID: generatedVectorID(190)})
		ctx := context.WithValue(t.Context(), struct{ label string }{"later observer"}, replacement)
		_, result := s.selectCandidate(ctx, c)
		observationCheckSelectionFact(t, s, c, owner, before, result)
		if c.observation != owner || c.observationSource.OperationID != c.head.Subject.Operation {
			t.Fatal("later invocation replaced owner or correlation")
		}
		if facts, status := replacement.read(); len(facts) != 0 || status != (observationStatus{}) {
			t.Fatal("later context received candidate facts")
		}
		after, _ := owner.read()
		if _, got := s.selectCandidate(t.Context(), c); got != (Result{Outcome: AdmissionRefused, Reason: AdmissionInvalid}) {
			t.Fatal("candidate reuse")
		}
		if facts, _ := owner.read(); !reflect.DeepEqual(facts, after) {
			t.Fatal("reused candidate emitted")
		}
	})
	for _, condition := range []string{"foreign session", "expired admission", "changed domain", "invalid admission"} {
		t.Run(condition, func(t *testing.T) {
			s, c, owner, store, _ := observationPreparedSelection(t)
			before, _ := owner.read()
			selectedOwner := s
			switch condition {
			case "foreign session":
				copy := *s
				selectedOwner = &copy
			case "expired admission":
				s.admission.expires = time.Now().Add(-time.Second)
			case "changed domain":
				s.admission.domain = generatedVectorID(190)
			case "invalid admission":
				s.admission.composition = contract.ID{}
			}
			store.write, store.commit = contract.WriteResult{Status: contract.WritePrecondition}, false

			selectedOwner.selectCandidate(t.Context(), c)
			if facts, _ := owner.read(); !reflect.DeepEqual(facts, before) {
				t.Fatal("invalid owner disclosed candidate result")
			}
		})
	}
}

func observationPhysicalGeneratedStore(t testing.TB, s *StateSession) *observationSelectionStore {
	t.Helper()
	signer := testtrust.New(t, s.admission.store.Family, s.admission.trust)
	request, err := contract.NewBindingRequest(binding(s.admission))
	if err != nil {
		t.Fatal(err)
	}
	s.head.K1 = signer.Sign(t.Context(), request).Signature
	s.key, _ = publicKey(s.admission.publicKey)
	physical := s.store.(*generatedFixtureSupportStore)
	store := &observationSelectionStore{generatedFixtureSupportStore: physical, token: s.token, commit: true, write: contract.WriteResult{Status: contract.WriteAcknowledged}}
	for ref, body := range s.cache {
		key, err := format.Key(s.admission.store.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		store.objects[key] = bytes.Clone(body)
	}
	for _, page := range s.recipients {
		if page == nil {
			continue
		}
		body, err := format.EncodeRecipientPage(*page)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(format.RecipientKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal(err)
		}
		key, err := format.Key(s.admission.store.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		store.objects[key] = body
	}

	for _, page := range s.pages {
		if page == nil {
			continue
		}
		body, err := format.EncodeValueEntryPage(*page)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(format.ValueEntryPageKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal(err)
		}
		key, err := format.Key(s.admission.store.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		store.objects[key] = body
	}
	for _, page := range s.access {
		if page == nil {
			continue
		}
		body, err := format.EncodeAccessPage(*page)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(format.AccessKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal(err)
		}
		key, err := format.Key(s.admission.store.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		store.objects[key] = body
	}

	s.store = store
	if s.cache == nil {
		s.cache = make(map[format.Ref][]byte)
	}
	return store
}

// full_only: false
func TestGeneratedSelectionObservationRetainsUnknownAcrossNextAttempt(t *testing.T) {
	_, initial := observationReservationFixture(t, "generated")
	s := initial.state
	original := mustSelectedGeneratedWork(t, s)
	first := original.attempts[original.phase.FrontierAttemptID]

	plan, err := s.generatedCreateResidueRequest(t.Context(), first.record.AttemptID, generatedContinuationContext(t, s, 130, 131))
	if err != nil {
		t.Fatal(err)
	}
	permit := &admittedGeneratedCreateResidue{session: s, plan: plan}
	if !attachOperationObservation(&permit.observation, s, plan.context, true) {
		t.Fatal("owner")
	}
	store := observationPhysicalGeneratedStore(t, s)
	plan.source = observationSource{}
	c, result := s.prepareGeneratedCreateResidue(t.Context(), permit, testtrust.New(t, contract.GCP, s.admission.trust))
	if c == nil || result.Outcome != ObservedCurrent {
		t.Fatal("residue preparation", result)
	}
	wantSource := permit.observation.sourceFor(observationSource{Stage: observationExchange, OperationID: generatedVectorID(10), ParentID: generatedVectorID(10), PhaseID: c.head.Generator.PhaseID, AttemptID: first.record.AttemptID})
	if c.observationSource != wantSource {
		t.Fatal("original/current roles or Attempt lost", c.observationSource)
	}
	store.unavailable = true
	_, unknown := s.selectCandidate(t.Context(), c)
	wantUnknown := Result{Outcome: UnresolvedCommit, Reason: ReadUnavailable, RequestedRevision: c.head.Core.Revision, StoreReason: contract.ReasonAccess, CommitMayHaveOccurred: true}
	if unknown != wantUnknown {
		t.Fatal("unknown", unknown)
	}
	before, _ := permit.observation.read()
	if len(before) != 1 || before[0].Change.Result != wantUnknown {
		t.Fatal("unknown fact missing")
	}
	store.unavailable = false
	current, result := s.readCurrentImage(t.Context(), true)
	if current == nil || result.Outcome != ObservedCurrent {
		t.Fatal("exact later observation", result)
	}
	nextPlan, err := current.generatedSuccessorReservationRequest(t.Context(), generatedContinuationContext(t, current, 132, 133))
	if err != nil {
		t.Fatal(err)
	}
	nextPermit := &admittedGeneratedSuccessorReservation{session: current, plan: nextPlan}
	if !attachChildObservation(&nextPermit.observation, permit.observation, current, nextPlan.context) {
		t.Fatal("child owner")
	}
	nextPlan.source = observationSource{}
	preparation, result := current.prepareGeneratedSuccessorReservation(t.Context(), nextPermit)
	if preparation == nil || result.Outcome != ObservedCurrent {
		t.Fatal("successor preparation", result)
	}
	nextCandidate := preparation.reservation.candidate
	wantNextSource := nextPermit.observation.sourceFor(observationSource{Stage: observationExchange, OperationID: generatedVectorID(10), ParentID: generatedVectorID(10), PhaseID: nextCandidate.head.Generator.PhaseID, AttemptID: nextPlan.attempt})
	if nextCandidate.observationSource != wantNextSource || nextPlan.attempt == first.record.AttemptID {
		t.Fatal("new Attempt source differs", nextCandidate.observationSource)
	}

	// The fixed scheduled successor is a fixture predecessor for the next
	// admitted residue operation. No provider claim or send is synthesized.
	nextState := preparation.reservation.state
	physical := &generatedFixtureSupportStore{t: t, descriptor: store.descriptor, objects: store.objects}
	nextState.store = physical
	for _, object := range nextCandidate.objects {
		key, err := format.Key(nextState.admission.store.Prefix, object.ref)
		if err != nil {
			t.Fatal(err)
		}
		physical.objects[key] = bytes.Clone(object.body)
	}
	nextStore := observationPhysicalGeneratedStore(t, nextState)
	finalPlan, err := nextState.generatedCreateResidueRequest(t.Context(), nextPlan.attempt, generatedContinuationContext(t, nextState, 134, 135))
	if err != nil {
		t.Fatal(err)
	}
	finalPermit := &admittedGeneratedCreateResidue{session: nextState, plan: finalPlan}
	if !attachChildObservation(&finalPermit.observation, permit.observation, nextState, finalPlan.context) {
		t.Fatal("later owner")
	}
	finalCandidate, result := nextState.prepareGeneratedCreateResidue(t.Context(), finalPermit, testtrust.New(t, contract.GCP, nextState.admission.trust))
	if finalCandidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("later candidate", result)
	}
	selected, success := nextState.selectCandidate(t.Context(), finalCandidate)
	wantSuccess := Result{Outcome: ObservedCurrent, RequestedRevision: finalCandidate.head.Core.Revision, ObservedRevision: finalCandidate.head.Core.Revision, ObservedSnapshotID: finalCandidate.head.Core.Root.Object, Evidence: AuthenticatedClosure}
	if selected == nil || success != wantSuccess || nextStore.sends != 1 {
		t.Fatal("later selection", success)
	}
	after, _ := permit.observation.read()
	if len(after) != 2 || !reflect.DeepEqual(after[:1], before) || after[1].Change.Source.AttemptID != nextPlan.attempt || after[1].Change.Result != wantSuccess {
		t.Fatal("later successful Attempt rewrote unknown")
	}
}

// full_only: false
func TestGeneratedLifecycleSelectionObservationKeepsOriginalSources(t *testing.T) {
	for _, condition := range []string{"inbox release", "ordinary cleanup unknown", "ordinary cleanup close", "retirement unknown", "retirement close"} {
		t.Run(condition, func(t *testing.T) {
			var s *StateSession
			var attempt contract.GeneratedAttemptRecord
			var plan *generatedLifecyclePlan
			var err error
			var release contract.PendingInboxReleaseRecord
			var duty contract.GeneratedDutyRecord
			switch condition {
			case "inbox release":
				var original generatedAttempt
				s, original, release = generatedInboxReleaseState(t, 0, contract.GeneratedReleasePending)
				attempt = original.record
				generatedLifecycleFixtureForFamily(t, s, contract.GCP)
			case "retirement unknown", "retirement close":
				var original generatedAttempt
				if condition == "retirement unknown" {
					s, original, duty, _ = generatedEnteredRetirementState(t, false)
					generatedLifecycleFixtureForFamily(t, s, contract.GCP)
				} else {
					s, original, duty, _ = generatedLiveEnteredRetirementForLaterFailure(t)
				}
				attempt = original.record
			default:
				base, source := generatedOrdinaryCleanupSourceState(t, contract.GeneratedCompletionAcknowledged, false)
				reservation, err := base.deriveGeneratedReservation(context.Background(), generatedOrdinaryCleanupReservationInput(t, base, source, generatedVectorID(195)))
				if err != nil {
					t.Fatal(err)
				}
				s = reservation.state
				generatedLifecycleFixtureForFamily(t, s, contract.GCP)
				g := mustSelectedGeneratedWork(t, s)
				original := g.attempts[g.phase.FrontierAttemptID]
				attempt = original.record
				if condition == "ordinary cleanup close" {
					record, err := s.generatedRecordRequest(context.Background(), attempt.AttemptID, generatedRetirementResultFixture(t, s, original, contract.GeneratorDispositionRetirementAcknowledged), generatedContinuationContext(t, s, 128, 129))
					if err != nil {
						t.Fatal(err)
					}
					recorded, err := s.deriveGeneratedRecord(context.Background(), record)
					if err != nil {
						t.Fatal(err)
					}
					s = recorded.state
				}
			}
			observationProtectFixture(t, s)
			admitted := generatedContinuationContext(t, s, 130, 131)
			switch condition {
			case "inbox release":
				plan, err = s.generatedInboxReleasePlan(t.Context(), release.InboxID, admitted)
			case "ordinary cleanup close":
				plan, err = s.generatedOrdinaryCleanupClosePlan(t.Context(), attempt.AttemptID, admitted)
			case "retirement close":
				plan, err = s.generatedRetirementClosePlan(t.Context(), attempt.AttemptID, admitted)
			case "retirement unknown":
				g := mustSelectedGeneratedWork(t, s)
				original := g.attempts[attempt.AttemptID]
				facts, encodeErr := contract.EncodeGeneratorSafeFacts(generatedRetirementFactsFixture(t, s, original, contract.GeneratorDispositionUnknown))
				if encodeErr != nil {
					t.Fatal(encodeErr)
				}
				plan, err = s.generatedRetirementAmbiguityPlan(t.Context(), duty.DutyID, facts, admitted, false)
			case "ordinary cleanup unknown":
				g := mustSelectedGeneratedWork(t, s)
				original := g.attempts[attempt.AttemptID]
				facts, encodeErr := contract.EncodeGeneratorSafeFacts(generatedRetirementFactsFixture(t, s, original, contract.GeneratorDispositionUnknown))
				if encodeErr != nil {
					t.Fatal(encodeErr)
				}
				plan, err = s.generatedOrdinaryCleanupAmbiguityPlan(t.Context(), attempt.AttemptID, facts, admitted)
			}
			if err != nil {
				t.Fatal("plan", err)
			}
			expectedSource := observationSource{ParentID: attempt.OperationID, AttemptID: attempt.AttemptID}
			if plan.source != expectedSource {
				t.Fatal("planning lost available source", plan.source, expectedSource)
			}
			permit, err := s.admitGeneratedLifecyclePlan(t.Context(), plan)
			if err != nil {
				t.Fatal("admission", err)
			}
			if !attachOperationObservation(&permit.observation, s, plan.context, true) {
				t.Fatal("owner")
			}
			observationPhysicalGeneratedStore(t, s)
			c, result := s.prepareGeneratedLifecycle(t.Context(), permit, testtrust.New(t, contract.GCP, s.admission.trust))
			if c == nil || result.Outcome != ObservedCurrent {
				t.Fatal("preparation", result)
			}
			expectedSource = permit.observation.sourceFor(expectedSource)
			expectedSource.Stage, expectedSource.OperationID, expectedSource.PhaseID = observationExchange, plan.identity.operation, c.head.Generator.PhaseID
			if condition == "retirement unknown" || condition == "retirement close" {
				expectedSource.Stage = observationCandidate
			}
			if c.observationSource != expectedSource {
				t.Fatal("candidate lost fixed source", c.observationSource, expectedSource)
			}
			before, _ := permit.observation.read()
			selected, result := s.selectCandidate(t.Context(), c)
			want := Result{Outcome: ObservedCurrent, RequestedRevision: c.head.Core.Revision, ObservedRevision: c.head.Core.Revision, ObservedSnapshotID: c.head.Core.Root.Object, Evidence: AuthenticatedClosure}
			if selected == nil || result != want {
				t.Fatal("selection", result)
			}
			observationCheckSelectionFact(t, s, c, permit.observation, before, want)
		})
	}
}

// full_only: false
func TestGeneratedCandidatePreparationBindsSelectionSources(t *testing.T) {
	t.Run("initial plan", func(t *testing.T) {
		s, _ := observationTestSession(t)
		input := generatedPlanInputFixture(t, s)
		plan, err := s.generatedPlanRequest(t.Context(), input)
		if err != nil {
			t.Fatal(err)
		}
		finished := generatedReservationInputFixture(t, s).finished
		custody := &observationExchangeCustody{instance: generatedVectorID(105)}
		prepares := 0
		custody.reply = func(q contract.CryptoRequest) contract.CryptoResponse {
			var body []byte
			var err error
			if q.Kind == contract.CryptoCompare {
				body, err = contract.EncodeCryptoGeneratedCompareResult(contract.CryptoGeneratedCompareResult{OperationRef: generatedVectorID(128)})
			} else {
				prepares++
				if prepares <= 2 {
					body, err = contract.EncodeCryptoGeneratedPartResult(contract.CryptoGeneratedPartResult{})
				} else {
					body, err = contract.EncodeCryptoGeneratedFinishPlanResult(finished)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			var rows []contract.KeyUseRow
			if q.Kind == contract.CryptoPrepare && prepares == 3 {
				rows = []contract.KeyUseRow{observationSelectionKeyUse(t, s, contract.KeyUseMaterialWrap)}
			}
			return observationReply(q, contract.CryptoSuccess, rows, body)
		}
		permit := &admittedGeneratedPlan{session: s, plan: plan, crypto: custody, instance: custody.instance, deadline: time.Unix(0, int64(plan.request.Context.Expiry))}
		if !attachOperationObservation(&permit.observation, s, plan.request.Context, true) {
			t.Fatal("owner")
		}
		prepared, result := s.prepareGeneratedPlan(t.Context(), permit)
		if prepared == nil || result != s.observed(ObservedCurrent) || prepares != 3 {
			t.Fatal("initial preparation", result, prepares)
		}
		c := prepared.reservation.candidate
		want := permit.observation.sourceFor(observationSource{Stage: observationExchange, OperationID: generatedVectorID(10), PhaseID: c.head.Generator.PhaseID})
		if c.observation != permit.observation || c.observationSource != want || !c.observationSource.AttemptID.IsZero() {
			t.Fatal("initial source invented single Attempt or lost owner", c.observationSource)
		}
	})
	t.Run("record", func(t *testing.T) {
		_, reserved := observationReservationFixture(t, "generated")
		s := reserved.state
		g := mustSelectedGeneratedWork(t, s)
		a := g.attempts[g.phase.FrontierAttemptID]
		plan, err := s.generatedRecordRequest(context.Background(), a.record.AttemptID, generatedPublicResultFixture(t, a, 1), generatedContinuationContext(t, s, 130, 131))
		if err != nil {
			t.Fatal(err)
		}
		custody := &observationExchangeCustody{instance: generatedVectorID(105)}
		custody.reply = func(q contract.CryptoRequest) contract.CryptoResponse {
			var body []byte
			var err error
			if q.Kind == contract.CryptoCompare {
				body, err = contract.EncodeCryptoGeneratedCompareResult(contract.CryptoGeneratedCompareResult{OperationRef: generatedVectorID(128)})
			} else {
				body, err = contract.EncodeCryptoGeneratedAdoptResult(contract.CryptoGeneratedAdoptResult{Result: plan.result})
			}
			if err != nil {
				t.Fatal(err)
			}
			var rows []contract.KeyUseRow
			if q.Kind == contract.CryptoCompare {
				rows = []contract.KeyUseRow{observationSelectionKeyUse(t, s, contract.KeyUseMaterialOpen)}
			}
			return observationReply(q, contract.CryptoSuccess, rows, body)
		}
		permit := &admittedGeneratedRecord{session: s, plan: plan, crypto: custody, instance: custody.instance, deadline: time.Unix(0, int64(plan.request.Context.Expiry))}
		if !attachOperationObservation(&permit.observation, s, plan.request.Context, true) {
			t.Fatal("owner")
		}
		prepared, result := s.prepareGeneratedRecord(t.Context(), permit)
		if prepared == nil || result != s.observed(ObservedCurrent) || len(custody.calls) != 2 {
			t.Fatal("record preparation", result)
		}
		c := prepared.reservation.candidate
		want := permit.observation.sourceFor(observationSource{Stage: observationExchange, OperationID: generatedVectorID(10), PhaseID: c.head.Generator.PhaseID, AttemptID: a.record.AttemptID})
		if c.observation != permit.observation || c.observationSource != want {
			t.Fatal("record source", c.observationSource, want)
		}
	})
	for _, initialOwner := range []string{"enabled", "absent"} {
		t.Run("producer retains first enclosing owner/"+initialOwner, func(t *testing.T) {
			s, prior := observationInitialProducerFixture(t, initialOwner == "enabled", "alpha", "omega")
			initial := prior.reservation
			firstOwner, firstSource := initial.candidate.observation, initial.candidate.observationSource
			firstFacts, _ := firstOwner.read()
			admitted := prior.operation.context
			admitted.AdmissionID, admitted.SessionID, admitted.IntentDescriptor = generatedVectorID(132), generatedVectorID(133), contract.DescriptorVector{}
			q, preparation, err := s.generatedProducerRequest(context.Background(), prior, admitted)
			if err != nil {
				t.Fatal(err)
			}
			custody := &observationExchangeCustody{instance: generatedVectorID(105)}
			custody.reply = func(q contract.CryptoRequest) contract.CryptoResponse {
				var body []byte
				var err error
				if q.Kind == contract.CryptoCompare {
					body, err = contract.EncodeCryptoGeneratedCompareResult(contract.CryptoGeneratedCompareResult{OperationRef: generatedVectorID(128)})
				} else {
					body, err = contract.EncodeCryptoGeneratedProducerResult(contract.CryptoGeneratedProducerResult{ProducerLocatorID: generatedVectorID(129)})
				}
				if err != nil {
					t.Fatal(err)
				}
				var rows []contract.KeyUseRow
				if q.Kind == contract.CryptoCompare {
					rows = []contract.KeyUseRow{observationSelectionKeyUse(t, s, contract.KeyUseMaterialOpen)}
				}
				return observationReply(q, contract.CryptoSuccess, rows, body)
			}
			permit := &admittedGeneratedProducer{session: s, prior: prior, request: q, preparation: preparation, crypto: custody, instance: custody.instance, deadline: time.Unix(0, int64(q.Context.Expiry))}
			if !attachOperationObservation(&permit.observation, s, q.Context, true) {
				t.Fatal("owner")
			}
			prepared, result := s.prepareGeneratedProducer(t.Context(), permit)
			if prepared == nil || result != s.observed(ObservedCurrent) || len(custody.calls) != 2 {
				t.Fatal("producer preparation", result)
			}
			c := prepared.reservation.candidate

			if c.observation != firstOwner || c.observationSource != firstSource {
				t.Fatal("later producer replaced enclosing candidate owner or source", c.observationSource)
			}
			if facts, _ := firstOwner.read(); !reflect.DeepEqual(facts, firstFacts) {
				t.Fatal("producer invocation leaked into initial plan collector")
			}
			producerFacts, _ := permit.observation.read()
			s.selectCandidate(t.Context(), c)
			if facts, _ := permit.observation.read(); !reflect.DeepEqual(facts, producerFacts) {
				t.Fatal("candidate selection leaked into later producer collector")
			}
		})
	}
}

func observationSelectionKeyUse(t testing.TB, s *StateSession, purpose uint8) contract.KeyUseRow {
	t.Helper()
	binding := s.authority().CurrentBinding
	digest, err := contract.PublicBindingDigest(*binding)
	if err != nil {
		t.Fatal(err)
	}
	return contract.KeyUseRow{BindingID: binding.BindingID, PublicBindingDigest: digest, SubjectKind: 1, SubjectID: s.admission.recipient, Provider: binding.Provider, Purpose: purpose, Outcome: contract.KeyUseCompleted, Count: 1}
}

// full_only: false
func TestRecipientReplacementCandidateCarriesSelectionSource(t *testing.T) {
	s := generatedEmptyPredecessorForFamily(t, contract.GCP)
	before := generatedPublicBinding(t, 181)
	recipient := contract.RecipientRecord{RecipientID: generatedVectorID(12), Status: contract.CurrentRecipient, CurrentBinding: &before}
	s.recipients[0].Slots[1] = &recipient
	d, err := contract.DecodeGenesisDescriptorCore(s.admission.descriptor)
	if err != nil {
		t.Fatal(err)
	}
	d.Recipients = append(d.Recipients, recipient)
	s.admission.descriptor, err = contract.EncodeGenesisDescriptorCore(d)
	if err != nil {
		t.Fatal(err)
	}
	generatedSealSelectedFixture(t, s)
	generatedVerifySelectedFixtureSlices(t, s)
	observationProtectFixture(t, s)
	intent := contract.RecipientReplacementIntent{RecipientReplacementIntentFields: contract.RecipientReplacementIntentFields{Schema: contract.CanonicalSchema, Profile: 2, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), DomainID: s.admission.domain, BeforeAccessRoot: s.root.CurrentAccess.AccessRoot, RecipientID: recipient.RecipientID}, Before: before, Successor: observationNextBinding(t, before)}
	plan := transitionPlan{operation: generatedVectorID(182), snapshot: generatedVectorID(183), transition: generatedVectorID(184), revision: generatedVectorID(185)}
	plan.recipientPages[0] = generatedVectorID(186)
	receiptPages, err := s.mutationReceiptPageIndexes(t.Context())
	if err != nil || len(receiptPages) != 2 {
		t.Fatal("receipt support plan", receiptPages, err)
	}
	for i, index := range receiptPages {
		plan.supportPages[index] = generatedVectorID(byte(188 + i))
	}
	admitted := generatedContinuationContext(t, s, 130, 131)
	admitted.OperationClass = contract.CryptoAccessReplacementClass
	q, _, rows, err := s.replacementRequest(t.Context(), intent, plan, admitted)
	if err != nil || len(rows) != 0 {
		t.Fatal("empty material request")
	}
	requestBody, err := contract.EncodeCryptoAccessReplaceRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	custody := &observationExchangeCustody{instance: generatedVectorID(105)}
	custody.reply = func(request contract.CryptoRequest) contract.CryptoResponse {
		var body []byte
		var keys []contract.KeyUseRow
		var err error
		switch request.Kind {
		case contract.CryptoAccessReplace:
			body, err = contract.EncodeCryptoAccessReplaceResult(contract.CryptoAccessReplaceResult{OperationRef: generatedVectorID(128)})
			digest, digestErr := contract.PublicBindingDigest(intent.Successor)
			if digestErr != nil {
				t.Fatal(digestErr)
			}
			keys = []contract.KeyUseRow{{BindingID: intent.Successor.BindingID, PublicBindingDigest: digest, SubjectKind: 1, SubjectID: intent.RecipientID, Provider: contract.GCP, Purpose: contract.KeyUsePublicKeyRead, Outcome: contract.KeyUseCompleted, Count: 3}}
		case contract.CryptoPrepare:
			input, decodeErr := contract.DecodeCryptoAccessPrepareRequest(request.Body)
			if decodeErr != nil || len(input.Rows) != 0 {
				t.Fatal("material-free batch", decodeErr)
			}
			in, inErr := contract.AccessInputBatchDescriptor(nil)
			out, outErr := contract.AccessOutputBatchDescriptor(nil)
			if inErr != nil || outErr != nil {
				t.Fatal(inErr, outErr)
			}
			body, err = contract.EncodeCryptoAccessPrepareResult(contract.CryptoAccessPrepareResult{BatchIndex: input.BatchIndex, Final: 1, InputBatchDescriptor: in, OutputBatchDescriptor: out})
		case contract.CryptoFreeze:
			freeze, decodeErr := contract.DecodeCryptoAccessFreezeRequest(request.Body)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			fact, factErr := contract.CryptoAccessFactDigest(custody.instance, freeze)
			if factErr != nil {
				t.Fatal(factErr)
			}
			body, err = contract.EncodeCryptoFreezeResult(contract.CryptoFreezeResult{FactDigest: fact})
		case contract.CryptoClaim:
		default:
			t.Fatal("unexpected exchange", request.Kind)
		}
		if err != nil {
			t.Fatal(err)
		}
		return observationReply(request, contract.CryptoSuccess, keys, body)
	}
	permit := &AdmittedRecipientReplacement{session: s, intent: intent, plan: plan, context: q.Context, requestDigest: contract.Hash(requestBody), requestLength: len(requestBody), crypto: custody, instance: custody.instance, deadline: time.Unix(0, int64(q.Context.Expiry))}
	if !attachOperationObservation(&permit.observation, s, q.Context, true) {
		t.Fatal("owner")
	}
	observationPhysicalGeneratedStore(t, s)
	c, result := s.prepareRecipientReplacement(t.Context(), permit, testtrust.New(t, contract.GCP, s.admission.trust), nil)
	if c == nil || result.Outcome != ObservedCurrent || len(custody.calls) != 4 {
		var lastKind contract.CryptoKind
		if len(custody.calls) != 0 {
			lastKind = custody.calls[len(custody.calls)-1].Kind
		}
		t.Fatalf("preparation result=%+v calls=%d last_kind=%d permit_used=%t session_prepared=%t", result, len(custody.calls), lastKind, permit.used, s.prepared)
	}
	wantSource := permit.observation.sourceFor(observationSource{Stage: observationExchange, OperationID: generatedVectorID(182)})
	if c.observation != permit.observation || c.observationSource != wantSource {
		t.Fatal("replacement source", c.observationSource)
	}
	prefix, _ := permit.observation.read()
	current, result := s.selectCandidate(t.Context(), c)
	want := Result{Outcome: ObservedCurrent, RequestedRevision: generatedVectorID(185), ObservedRevision: generatedVectorID(185), ObservedSnapshotID: generatedVectorID(183), Evidence: AuthenticatedClosure}
	if current == nil || result != want {
		t.Fatal("selection", result)
	}
	observationCheckSelectionFact(t, s, c, permit.observation, prefix, want)
}

// full_only: false
func TestAdministrativeEndSelectionObservationKeepsFinalResult(t *testing.T) {
	s, duty, ids, _ := controlEndWorkFixture(t, "new incarnation")
	generatedLifecycleFixtureForFamily(t, s, contract.GCP)
	observationProtectFixture(t, s)
	s.admission.endWorkInvocation = generatedVectorID(196)
	store := observationPhysicalGeneratedStore(t, s)
	authority := &AuthoritySession{state: s, mode: LocalAuthorityEnd, trust: testtrust.New(t, contract.GCP, s.admission.trust)}
	if !attachLocalObservation(&authority.observation, s, true) {
		t.Fatal("owner")
	}
	candidate, _, err := s.deriveEndWorkCandidate(t.Context(), duty, ids)
	if err != nil {
		t.Fatal(err)
	}
	preview, ok := previewFromCandidate(candidate)
	if !ok {
		t.Fatal("preview")
	}
	var entropy []byte
	for _, id := range []contract.ID{ids.operation, ids.transition, ids.snapshot, ids.revision, ids.receipts, ids.receiptIndex} {
		entropy = append(entropy, id[:]...)
	}
	s.admission.entropy = bytes.NewReader(entropy)
	outcome := authority.end(t.Context(), preview, nil)
	want := Result{Outcome: ObservedCurrent, RequestedRevision: ids.revision, ObservedRevision: ids.revision, ObservedSnapshotID: ids.snapshot, Evidence: AuthenticatedClosure}
	if outcome.Result != want || len(outcome.Receipt) == 0 || outcome.OperationID != ids.operation || outcome.Revision != ids.revision || store.sends != 1 {
		t.Fatal("internal End selection", outcome.Result)
	}
	facts, status := authority.observation.read()
	expected := changeObservation{Source: authority.observation.sourceFor(observationSource{Stage: observationSelection, OperationID: ids.operation}), Candidate: observationCandidateIdentity{RevisionID: ids.revision, SnapshotID: ids.snapshot, PredecessorRevisionID: s.head.Core.Revision, PredecessorDigest: contract.Hash(s.body)}, Result: want}
	if len(facts) != 2 || status.Accepted != 2 || facts[0].Change.Source.Stage != observationCandidate || facts[0].Change.Administrative == nil || facts[0].Change.Candidate != expected.Candidate || !reflect.DeepEqual(facts[1].Change, &expected) {
		t.Fatal("internal caller lost final selection source or result", status)
	}
}

package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type generatedResultFixture struct {
	env      fixtureEnvironment
	f        *environmentFixture
	producer *generatedPreparation
	expected contract.GeneratorResultExpectation
	result   []byte
	calls    int
}

func newGeneratedResultFixture(t *testing.T, mode uint8, recovery bool) *generatedResultFixture {
	t.Helper()
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, recovery)
	a := &generatedResultFixture{env: env}
	run := newScenarioRun(t, ctx, env)
	a.f = newEnvironmentFixture(t, ctx, run.env, nil, false)
	input, canonical := generatedSourcePlanInput(t, run, a.f, mode)
	prior, _ := preparePrivateGeneratedReservation(t, env, a.f.session, input, canonical)
	a.producer, a.expected = preparePrivateGeneratedProducer(t, env, a.f.session, prior, nil)
	if !a.producer.reservation.candidate.bindFirstSend(a.producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		a.calls++
		var code contract.CryptoResultCode
		a.result, _, code = keys.InvokeGeneratedProducer(ctx, a.producer.operation.context.AdmissionID, a.producer.producerLocator, authority)
		return code
	}) {
		t.Fatal("original producer handoff")
	}
	selected, res := a.f.session.selectCandidate(ctx, a.producer.reservation.candidate)
	if selected == nil || res.Outcome != ObservedCurrent || a.calls != 1 || len(a.result) == 0 {
		t.Fatal("original generated result", res)
	}
	a.f.session = selected
	keys.RetireGenerated()
	return a
}

func generatedRecordPlanForResult(t *testing.T, s *StateSession, attempt contract.ID, result []byte, label string) *generatedRecordPlan {
	t.Helper()
	admitted := generatedPlanInputFixture(t, s).context
	admitted.AdmissionID, admitted.SessionID = testID(label+" admission"), testID(label+" session")
	plan, err := s.generatedRecordRequest(context.Background(), attempt, result, admitted)
	if err != nil {
		t.Fatal("generated result admission", err)
	}
	return plan
}

func (a *generatedResultFixture) assertState(t *testing.T, s *StateSession, recorded bool) {
	t.Helper()
	before := a.f.session
	prior, err := before.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal("original generated work", err)
	}
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil || g.parent == nil || *g.parent != *prior.parent || g.phase == nil ||
		s.root.CurrentAccess.AccessRoot != before.root.CurrentAccess.AccessRoot ||
		s.root.ValueEntryCount != before.root.ValueEntryCount || s.root.RawBytes != before.root.RawBytes ||
		!bytes.Equal(g.protected[g.parent.MaterialID], prior.protected[prior.parent.MaterialID]) {
		t.Fatal("result phase changed accepted work, source protection or access", err)
	}
	for _, entry := range before.root.Names {
		valueEntry := s.valueEntry(entry.Slot)
		if valueEntry == nil {
			t.Fatal("result phase removed a current member")
		}
		oldBody, oldErr := contract.EncodeValueEntry(*before.valueEntry(entry.Slot))
		body, err := contract.EncodeValueEntry(*valueEntry)
		if oldErr != nil || err != nil || !bytes.Equal(body, oldBody) ||
			!slices.Equal(g.consumers[materialIdentity{1, valueEntry.ValueState}], prior.consumers[materialIdentity{1, valueEntry.ValueState}]) {
			t.Fatal("result phase changed a current member or retained consumer", oldErr, err)
		}
	}
	attempt := g.attempts[a.expected.Template.AttemptID]
	state, stage, phase := uint8(contract.GeneratedEffectTransmitted), uint8(contract.GeneratedStageRetainedResult), prior.phase.Phase
	var result []byte
	if recorded {
		state, stage, phase = contract.GeneratedEffectSucceeded, contract.GeneratedStageTerminal, phase+1
		result = a.result
		if g.phase.AcceptedResultID != a.expected.Use.ResultID || g.phase.ResultDigest != contract.Hash(result) {
			t.Fatal("result phase changed its original result identity")
		}
	}
	if attempt.expected != a.expected || attempt.record.State != state || attempt.record.Stage != stage || g.phase.Phase != phase ||
		!bytes.Equal(attempt.result, result) || a.calls != 1 {
		t.Fatal("result phase changed its outcome or original producer count")
	}
	if body, _, code := a.env.Custody.InvokeGeneratedProducer(context.Background(), a.producer.operation.context.AdmissionID, a.producer.producerLocator, a.producer.reservation.candidate.generated.authority); code == contract.CryptoSuccess || len(body) != 0 {
		t.Fatal("result phase restored the original producer or regenerated its return")
	}
}

// full_only: false
func TestGeneratedRecordSelectionPreservesOriginalCondition(t *testing.T) {
	for _, fault := range []string{"lost-after", "lost-before", "delayed-before-fresh", "delayed-after-fresh"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			a := newGeneratedResultFixture(t, 2, true)
			env := a.env
			store := env.Store.(*memoryStore)
			s := a.f.session
			plan := generatedRecordPlanForResult(t, s, a.expected.Template.AttemptID, a.result, "original record")
			prepared := preparePrivateGeneratedRecord(t, env, s, plan)
			candidate := prepared.reservation.candidate
			oldToken, frozen := s.token, bytes.Clone(candidate.body)
			condition, err := contract.CryptoConditionDigest(matchedCondition(oldToken))
			if err != nil || plan.request.Context.OriginalConditionDigest != condition || candidate.head.Core.PreviousToken != oldToken {
				t.Fatal("phase did not retain its original selection condition", err)
			}
			store.casMode = fault
			if fault == "delayed-before-fresh" || fault == "delayed-after-fresh" {
				store.casMode = "delayed"
			}
			cas, signs := store.cas, env.Trust.(*fixtureTrust).signs
			selected, res := s.selectCandidate(ctx, candidate)
			wantCalls := 3
			if fault == "lost-after" {
				wantCalls = 1
			}
			if store.cas != cas+wantCalls || s.token != oldToken || !candidate.used || !bytes.Equal(candidate.body, frozen) || env.Trust.(*fixtureTrust).signs != signs {
				t.Fatal("uncertain selection exceeded its send bound or refreshed its frozen request")
			}
			for i := cas; i < store.cas; i++ {
				if store.casConditions[i] != oldToken || !bytes.Equal(store.casBodies[i], frozen) {
					t.Fatal("retry changed original condition or frozen HEAD")
				}
			}
			want := UnresolvedCommit
			switch fault {
			case "lost-after":
				want = ObservedCurrent
			case "lost-before":
				want = EvidenceUnavailable
			}
			if selected == nil || res.Outcome != want || res.CommitMayHaveOccurred != (want == UnresolvedCommit) {
				t.Fatal("selection uncertainty was not preserved", res)
			}
			a.assertState(t, selected, fault == "lost-after")
			if again, res := s.selectCandidate(ctx, candidate); again != nil || res != refused(AdmissionInvalid) || store.cas != cas+wantCalls {
				t.Fatal("one-use phase selection repeated", res)
			}
			env.Custody.RetireGenerated()
			store.casMode = ""
			cold, res := Open(ctx, a.f.admission, env.Store)
			if cold == nil || res.Outcome != ObservedCurrent {
				t.Fatal("independent phase observation", res)
			}
			if fault == "lost-after" {
				if !bytes.Equal(cold.body, frozen) {
					t.Fatal("lost reply did not select the exact frozen HEAD")
				}
				a.assertState(t, cold, true)
				checkFreshGeneratedProcess(t, store, cold)
				return
			}
			a.assertState(t, cold, false)
			original, present, res := cold.ReadGeneratedResult(ctx, a.expected.Template.AttemptID)
			if !present || res.Outcome != 0 || !bytes.Equal(original, a.result) {
				t.Fatal("fresh phase could not read the exact original inbox", res)
			}
			freshPlan := generatedRecordPlanForResult(t, cold, a.expected.Template.AttemptID, original, "fresh record")
			if freshPlan.phase != plan.phase || freshPlan.request.Context.AdmissionID == plan.request.Context.AdmissionID {
				t.Fatal("fresh admission changed the deterministic original result phase")
			}
			freshEnv := env
			freshEnv.Custody = memoryCurrentAuthorityKeys(t, cold)
			t.Cleanup(freshEnv.Custody.RetireGenerated)
			fresh := preparePrivateGeneratedRecord(t, freshEnv, cold, freshPlan).reservation.candidate
			if fault == "delayed-before-fresh" {
				if store.late == nil {
					t.Fatal("delayed selection was not retained")
				}
				if err := store.late(); err != nil {
					t.Fatal("delayed Store write", err)
				}
			}
			current, res := cold.selectCandidate(ctx, fresh)
			if fault == "delayed-before-fresh" {
				if current != nil || res.Outcome != Contention || res.Reason != StalePrecondition || cold.token != oldToken {
					t.Fatal("fresh candidate rebased after the delayed original selection", res)
				}
				current, res = Open(ctx, a.f.admission, env.Store)
				if current == nil || res.Outcome != ObservedCurrent || !bytes.Equal(current.body, frozen) {
					t.Fatal("delayed result did not leave its complete successor", res)
				}
			} else if current == nil || res.Outcome != ObservedCurrent {
				t.Fatal("fresh phase did not adopt the original encrypted result", res)
			}
			if fault == "delayed-after-fresh" {
				if store.late == nil {
					t.Fatal("delayed selection was not retained")
				}
				beforeLate, beforeLateToken := bytes.Clone(current.body), current.token
				if err := store.late(); err != nil {
					t.Fatal("delayed Store write", err)
				}
				current, res = Open(ctx, a.f.admission, env.Store)
				if current == nil || res.Outcome != ObservedCurrent || current.token != beforeLateToken || !bytes.Equal(current.body, beforeLate) {
					t.Fatal("delayed old condition replaced the fresh selection", res)
				}
			}
			a.assertState(t, current, true)
			checkFreshGeneratedProcess(t, store, current)
		})
	}
}

// full_only: false
func TestGeneratedRecordSupportPageReadbackKeepsFixedResult(t *testing.T) {
	for _, fault := range []string{"preexisting-equal", "preexisting-unequal", "lost-after"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			a := newGeneratedResultFixture(t, 0, false)
			env, original := a.env, a.result
			store := env.Store.(*memoryStore)
			s := a.f.session
			plan := generatedRecordPlanForResult(t, s, a.expected.Template.AttemptID, original, "support readback")
			permit := admitPrivateGeneratedRecord(env.operationContext(), t, env.Custody, s, plan)
			prepared, res := s.PrepareGeneratedRecord(ctx, permit)
			if prepared == nil || res.Outcome != ObservedCurrent {
				t.Fatal("record preparation", res)
			}
			if code := env.Custody.BindGeneratedCandidate(ctx, plan.request.Context.AdmissionID, generatedPrivateCandidate(t, prepared)); code != contract.CryptoSuccess {
				t.Fatal("record candidate binding", code)
			}
			var key string
			var body []byte
			for _, object := range prepared.reservation.candidate.objects {
				if object.ref.Kind != contract.RequiredSupportKind || !bytes.Contains(object.body, original) {
					continue
				}
				var err error
				key, err = format.Key(store.desc.Prefix, object.ref)
				if err != nil {
					t.Fatal(err)
				}
				body = bytes.Clone(object.body)
			}
			at := bytes.Index(body, original)
			if key == "" || at < 0 {
				t.Fatal("record page does not contain the exact original encrypted result")
			}
			if fault == "lost-after" {
				store.createMode = "lost-after"
			} else {
				storedBody := bytes.Clone(body)
				if fault == "preexisting-unequal" {
					storedBody[at+len(original)-1] ^= 1
				}
				store.put(key, storedBody)
			}
			cas, signs := store.cas, env.Trust.(*fixtureTrust).signs
			candidate, res := s.ClaimGeneratedPreparation(ctx, prepared.reservation.candidate, env.Trust)
			if store.cas != cas || !permit.used || !s.prepared {
				t.Fatal("immutable preparation selected HEAD or left reusable phase authority")
			}
			if fault == "preexisting-unequal" {
				if candidate != nil || res != failure(IntegrityFailure, ImmutableConflict) || env.Trust.(*fixtureTrust).signs != signs {
					t.Fatal("unequal immutable result bytes did not refuse before signing", res)
				}
				cold, res := Open(ctx, a.f.admission, env.Store)
				if cold == nil || res.Outcome != ObservedCurrent {
					t.Fatal("immutable conflict damaged the selected predecessor", res)
				}
				a.assertState(t, cold, false)
				return
			}
			if candidate == nil || res.Outcome != ObservedCurrent || env.Trust.(*fixtureTrust).signs != signs+1 || !bytes.Equal(store.objects[key].Body, body) {
				t.Fatal("exact immutable readback was not sufficient", res)
			}
			current, res := s.selectCandidate(ctx, candidate)
			if current == nil || res.Outcome != ObservedCurrent {
				t.Fatal("exact readback phase selection", res)
			}
			a.assertState(t, current, true)
		})
	}
}

// full_only: false
func TestGeneratedRecordColdSelectedFragmentsUseNewPhasePages(t *testing.T) {
	ctx := context.Background()
	a := newGeneratedResultFixture(t, 2, true)
	cold, res := Open(ctx, a.f.admission, a.env.Store)
	if cold == nil || res.Outcome != ObservedCurrent || len(cold.fragmentFacts) == 0 {
		t.Fatal("record predecessor did not reopen with authenticated fragment facts", res)
	}
	configurationPages := make(map[format.Ref]selectedSupportPageFacts)
	var configurationSlices int
	for _, page := range cold.supportFacts {
		if len(page.rows) == 0 {
			t.Fatal("cold predecessor has an empty selected support page")
		}
		onlyConfiguration := true
		for _, row := range page.rows {
			onlyConfiguration = onlyConfiguration && row.Kind() == contract.OutputConfigurationSliceSupportKind
		}
		if onlyConfiguration {
			page.rows = slices.Clone(page.rows)
			page.ordinals = slices.Clone(page.ordinals)
			configurationPages[page.ref] = page
			configurationSlices += len(page.rows)
		}
	}
	configuration := cold.root.OutputConfiguration
	if configurationSlices != int(configuration.SliceCount) || configurationSlices == 0 {
		t.Fatal("cold predecessor lacks complete configuration-only support pages")
	}
	plan := generatedRecordPlanForResult(t, cold, a.expected.Template.AttemptID, a.result, "cold fragment record")
	prepared := preparePrivateGeneratedRecord(t, a.env, cold, plan)
	selected, res := cold.selectCandidate(ctx, prepared.reservation.candidate)
	if selected == nil || res.Outcome != ObservedCurrent {
		t.Fatal("cold fragment record did not select", res)
	}
	reopened, res := Open(ctx, a.f.admission, a.env.Store)
	if reopened == nil || res.Outcome != ObservedCurrent || reopened.head.Core.Root != selected.head.Core.Root {
		t.Fatal("record successor did not cold reopen", res)
	}
	phaseID, err := contract.GeneratorPhaseID(plan.phase)
	if err != nil || len(reopened.root.RequiredSupport) == 0 {
		t.Fatal("record phase has no selected support", err)
	}
	if reopened.root.OutputConfiguration != configuration {
		t.Fatal("record changed the predecessor configuration descriptor")
	}
	var retained, generated int
	for i, ref := range reopened.root.RequiredSupport {
		page := reopened.supportFacts[i]
		if page.ref != ref || len(page.rows) == 0 {
			t.Fatal("record support facts do not match their selected reference", i)
		}
		onlyConfiguration := true
		for _, row := range page.rows {
			onlyConfiguration = onlyConfiguration && row.Kind() == contract.OutputConfigurationSliceSupportKind
		}
		if onlyConfiguration {
			prior, present := configurationPages[ref]
			if !present || !slices.Equal(page.rows, prior.rows) || !slices.Equal(page.ordinals, prior.ordinals) {
				t.Fatal("record changed its retained configuration facts", i)
			}
			retained++
			continue
		}
		want, err := contract.GeneratorPhasePageID(phaseID, contract.RequiredSupportKind, ref.Index)
		if err != nil || ref.Object != want || slices.Contains(cold.root.RequiredSupport, ref) {
			t.Fatal("record generated page did not use its new phase identity", i, err)
		}
		generated++
	}
	if retained != len(configurationPages) || generated == 0 {
		t.Fatal("record lost retained configuration or new generated phase pages", retained, generated)
	}
	a.assertState(t, reopened, true)
}

func expectedGeneratedResultKey(prefix string, expected contract.GeneratorResultExpectation) string {
	// Independent inbox preimage: the terminated label, B length=128, then
	// Domain, Operation, Attempt and Result IDs, without per-ID framing.
	body := binary.BigEndian.AppendUint32([]byte("ENKV/GENERATOR/v1/inbox\x00"), 128)
	for _, id := range []contract.ID{expected.Plan.DomainID, expected.Plan.OperationID, expected.Template.AttemptID, expected.Template.ResultID} {
		body = append(body, id[:]...)
	}
	inbox := sha256.Sum256(body)
	return prefix + "/" + hex.EncodeToString(expected.Plan.DomainID[:]) + "/result/" + hex.EncodeToString(inbox[:])
}

// full_only: false
func TestGeneratedResultFixedCoordinateSurvivesFreshAdmissions(t *testing.T) {
	for _, fault := range []string{"equal", "unequal", "lost-after", "lost-before", "unknown-readback"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			a := newGeneratedResultFixture(t, 2, true)
			env, original := a.env, a.result
			store := env.Store.(*memoryStore)
			key := expectedGeneratedResultKey(store.desc.Prefix, a.expected)
			if actual, attempt, err := a.f.session.generatedResultCoordinate(t.Context(), a.expected.Template.AttemptID); err != nil || actual != key || attempt.expected != a.expected {
				t.Fatal("fixed result address differs from accepted IDs")
			}
			if fault == "unequal" {
				other := bytes.Clone(original)
				other[len(other)-1] ^= 1
				store.put(key, other)
			}
			if fault == "lost-after" || fault == "lost-before" {
				store.createMode = fault
			}
			if fault == "unknown-readback" {
				store.readHook = func(k string, r contract.ReadResult) contract.ReadResult {
					if k == key {
						return contract.ReadResult{Status: contract.ReadUnavailable}
					}
					return r
				}
			}
			for phase := 0; phase < 2; phase++ {
				fresh, res := Open(ctx, a.f.admission, store)
				if fresh == nil || res.Outcome != ObservedCurrent {
					t.Fatal("fresh awaiting state unavailable", res)
				}
				keys := memoryCurrentAuthorityKeys(t, fresh)
				t.Cleanup(keys.RetireGenerated)
				supplied := original
				if phase == 1 && (fault == "equal" || fault == "lost-after") {
					var present bool
					supplied, present, res = fresh.ReadGeneratedResult(ctx, a.expected.Template.AttemptID)
					if !present || res.Outcome != 0 || !bytes.Equal(supplied, original) {
						t.Fatal("fresh owner could not discover the durable original return", res)
					}
				}
				plan := generatedRecordPlanForResult(t, fresh, a.expected.Template.AttemptID, supplied, fmt.Sprintf("fixed coordinate %d", phase))
				permit := admitPrivateGeneratedRecord(env.operationContext(), t, keys, fresh, plan)
				creates, cas := store.creates, store.cas
				prepared, res := fresh.PrepareGeneratedRecord(ctx, permit)
				if prepared == nil || res.Outcome != ObservedCurrent {
					t.Fatal("fixed result preparation", res)
				}
				if code := keys.BindGeneratedCandidate(ctx, plan.request.Context.AdmissionID, generatedPrivateCandidate(t, prepared)); code != contract.CryptoSuccess {
					t.Fatal("fixed result candidate binding", code)
				}
				candidate, res := fresh.ClaimGeneratedPreparation(ctx, prepared.reservation.candidate, env.Trust)
				keys.RetireGenerated()
				if store.cas != cas || a.calls != 1 {
					t.Fatal("fixed result preparation selected or repeated the effect")
				}
				a.assertState(t, fresh, false)
				want := Result{}
				wantCreates := 1
				switch fault {
				case "unequal":
					want = failure(IntegrityFailure, ImmutableConflict)
				case "lost-before":
					want = failure(EvidenceUnavailable, ReadUnavailable)
					want.StoreReason = contract.ReasonTransport
					wantCreates = 3
				case "unknown-readback":
					want = failure(EvidenceUnavailable, ReadUnavailable)
					want.StoreReason = contract.ReasonMalformed
				}
				if want.Outcome != 0 {
					if candidate != nil || res != want || store.creates != creates+wantCreates {
						t.Fatal("fixed result failure did not stop before support/HEAD", res)
					}
					continue
				}
				if candidate == nil || res.Outcome != ObservedCurrent || !bytes.Equal(store.objects[key].Body, original) {
					t.Fatal("equal fixed result readback refused", res)
				}
				if phase == 0 {
					continue // A later admission must recover without this candidate.
				}
				recorded, res := fresh.selectCandidate(ctx, candidate)
				if recorded == nil || res.Outcome != ObservedCurrent {
					t.Fatal("fresh phase could not select the same durable result", res)
				}
				a.assertState(t, recorded, true)
			}
		})
	}
}

// full_only: false
func TestGeneratedResultLookupDistinguishesAbsenceFromUnusableEvidence(t *testing.T) {
	for _, fault := range []string{"missing", "unavailable", "oversize", "trailing-byte", "malformed", "wrong-context", "cancelled", "deadline"} {
		t.Run(fault, func(t *testing.T) {
			a := newGeneratedResultFixture(t, 0, false)
			env, original := a.env, a.result
			store := env.Store.(*memoryStore)
			key := expectedGeneratedResultKey(store.desc.Prefix, a.expected)
			body := bytes.Clone(original)
			want := failure(EvidenceUnavailable, ReadUnavailable)
			switch fault {
			case "missing":
				want = Result{}
			case "oversize":
				body = make([]byte, contract.GeneratedResultRecordMaxLength+1)
				want = failure(IntegrityFailure, InvalidFormat)
			case "trailing-byte":
				body = append(body, 0)
				want = failure(IntegrityFailure, InvalidRelation)
			case "malformed":
				body[0] ^= 1
				want = failure(IntegrityFailure, InvalidRelation)
			case "wrong-context":
				body = newGeneratedResultFixture(t, 0, false).result
				want = failure(IntegrityFailure, InvalidRelation)
			case "unavailable":
				want.StoreReason = contract.ReasonMalformed
				store.readHook = func(k string, r contract.ReadResult) contract.ReadResult {
					if k == key {
						return contract.ReadResult{Status: contract.ReadUnavailable}
					}
					return r
				}
			}
			if fault != "missing" {
				store.put(key, body)
			}
			ctx := context.Background()
			if fault == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if fault == "deadline" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
			}
			reads, creates, cas := store.reads, store.creates, store.cas
			if result, present, res := a.f.session.ReadGeneratedResult(ctx, a.expected.Template.AttemptID); result != nil || present || res != want {
				t.Fatal("unusable fixed result admitted", res)
			}
			if store.creates != creates || store.cas != cas || (fault == "cancelled" || fault == "deadline") && store.reads != reads {
				t.Fatal("result lookup changed state or crossed cancellation")
			}
			a.assertState(t, a.f.session, false)
		})
	}
}

type resultInputMutationStore struct {
	contract.Store
	key      string
	before   bool
	retained []byte
}

func (s *resultInputMutationStore) StoreConfiguration() contract.StoreConfiguration {
	return fixtureStoreConfiguration(s.Store)
}

func (s *resultInputMutationStore) Create(ctx context.Context, key string, body []byte) contract.WriteResult {
	if key != s.key {
		return s.Store.Create(ctx, key, body)
	}
	s.retained = body
	if s.before {
		body[len(body)-1] ^= 1
	}
	result := s.Store.Create(ctx, key, body)
	if !s.before {
		body[len(body)-1] ^= 1
	}
	return result
}

// full_only: false
func TestGeneratedResultPublicationOwnsFrozenBytesAcrossStoreInputMutation(t *testing.T) {
	for _, beforeWrite := range []bool{false, true} {
		t.Run(fmt.Sprintf("before-write-%t", beforeWrite), func(t *testing.T) {
			a := newGeneratedResultFixture(t, 0, false)
			env, original := a.env, a.result
			before := bytes.Clone(original)
			store := &resultInputMutationStore{Store: env.Store, key: expectedGeneratedResultKey(env.Store.Descriptor().Prefix, a.expected), before: beforeWrite}
			s := a.f.session
			s.store = store
			plan := generatedRecordPlanForResult(t, s, a.expected.Template.AttemptID, original, "owned result bytes")
			permit := admitPrivateGeneratedRecord(env.operationContext(), t, env.Custody, s, plan)
			ctx := context.Background()
			prepared, res := s.PrepareGeneratedRecord(ctx, permit)
			if prepared == nil || res.Outcome != ObservedCurrent {
				t.Fatal("owned result preparation", res)
			}
			if code := env.Custody.BindGeneratedCandidate(ctx, plan.request.Context.AdmissionID, generatedPrivateCandidate(t, prepared)); code != contract.CryptoSuccess {
				t.Fatal("owned result candidate binding", code)
			}
			candidate, res := s.ClaimGeneratedPreparation(ctx, prepared.reservation.candidate, env.Trust)
			if len(store.retained) != len(original) || !bytes.Equal(original, before) || !bytes.Equal(plan.result, before) || !bytes.Equal(prepared.resultWrites[0].body, before) {
				t.Fatal("Store input aliases the admitted original result")
			}
			if beforeWrite {
				if candidate != nil || res != failure(IntegrityFailure, ImmutableConflict) {
					t.Fatal("mutated Store input changed the frozen equality oracle", res)
				}
			} else if candidate == nil || res.Outcome != ObservedCurrent {
				t.Fatal("Store ownership after Create corrupted retained frozen bytes", res)
			}
			a.assertState(t, s, false)
		})
	}
}

// full_only: false
func TestGeneratedResultDurableLookupRequiresPrivateAuthentication(t *testing.T) {
	a := newGeneratedResultFixture(t, 1, true)
	env, original := a.env, a.result
	store := env.Store.(*memoryStore)
	key := expectedGeneratedResultKey(store.desc.Prefix, a.expected)
	damaged := bytes.Clone(original)
	damaged[len(damaged)-1] ^= 1
	store.put(key, damaged)
	s := a.f.session
	ctx := context.Background()
	result, present, res := s.ReadGeneratedResult(ctx, a.expected.Template.AttemptID)
	if !present || res.Outcome != 0 || !bytes.Equal(result, damaged) {
		t.Fatal("private-authentication test did not preserve public result framing", res)
	}
	plan := generatedRecordPlanForResult(t, s, a.expected.Template.AttemptID, result, "durable authentication")
	permit := admitPrivateGeneratedRecord(env.operationContext(), t, env.Custody, s, plan)
	creates, cas := store.creates, store.cas
	if prepared, res := s.PrepareGeneratedRecord(ctx, permit); prepared != nil || res != failure(IntegrityFailure, InvalidProof) {
		t.Fatal("publicly related but unauthenticated durable result selected", res)
	}
	if store.creates != creates || store.cas != cas {
		t.Fatal("damaged durable result reached writes")
	}
	a.assertState(t, s, false)
}

func prepareGeneratedRecordCandidate(t *testing.T, env fixtureEnvironment, s *StateSession, permit *admittedGeneratedRecord, ctx context.Context) (*Candidate, Result) {
	t.Helper()
	prepared, res := s.PrepareGeneratedRecord(ctx, permit)
	if prepared == nil {
		return nil, res
	}
	if code := env.Custody.BindGeneratedCandidate(ctx, permit.plan.request.Context.AdmissionID, generatedPrivateCandidate(t, prepared)); code != contract.CryptoSuccess {
		t.Fatal("record candidate binding", code)
	}
	return s.ClaimGeneratedPreparation(ctx, prepared.reservation.candidate, env.Trust)
}

// full_only: false
func TestGeneratedRecordPrivateEvidenceCannotRestoreRights(t *testing.T) {
	for _, fault := range []struct {
		name string
		kind contract.CryptoKind
		want Result
	}{
		{"cancel-before-compare", 0, refused(AdmissionInvalid)},
		{"expired-before-compare", 0, refused(AdmissionInvalid)},
		{"cancel-after-compare", contract.CryptoCompare, refused(AdmissionInvalid)},
		{"cancel-after-claim", contract.CryptoClaim, refused(AdmissionInvalid)},
		{"missing-private-open", contract.CryptoCompare, refused(AdmissionInvalid)},
		{"changed-comparison-reference", contract.CryptoCompare, refused(AdmissionInvalid)},
		{"changed-frozen-fact", contract.CryptoFreeze, refused(AdmissionInvalid)},
		{"unknown-compare", contract.CryptoCompare, failure(EvidenceUnavailable, CustodyUnavailable)},
		{"unknown-prepare", contract.CryptoPrepare, failure(EvidenceUnavailable, CustodyUnavailable)},
		{"unknown-freeze", contract.CryptoFreeze, failure(EvidenceUnavailable, CustodyUnavailable)},
		{"unknown-claim", contract.CryptoClaim, failure(EvidenceUnavailable, CustodyUnavailable)},
	} {
		t.Run(fault.name, func(t *testing.T) {
			a := newGeneratedResultFixture(t, 0, false)
			env := a.env
			s := a.f.session
			store := env.Store.(*memoryStore)
			plan := generatedRecordPlanForResult(t, s, a.expected.Template.AttemptID, a.result, "private failure")
			permit := admitPrivateGeneratedRecord(env.operationContext(), t, env.Custody, s, plan)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			changed := &changedCryptoReply{inner: permit.crypto, kind: fault.kind}
			changed.change = func(r contract.CryptoResponse) contract.CryptoResponse {
				switch fault.name {
				case "cancel-after-compare", "cancel-after-claim":
					cancel()
				case "missing-private-open":
					r.KeyUseRows = nil
				case "changed-comparison-reference", "changed-frozen-fact":
					r.Body[len(r.Body)-1] ^= 1
				default:
					r.ResultCode, r.Body = contract.CryptoResponseUnknown, nil
				}
				return r
			}
			permit.crypto = changed
			if fault.name == "cancel-before-compare" {
				cancel()
			}
			if fault.name == "expired-before-compare" {
				permit.deadline = time.Now().Add(-time.Second)
			}
			creates, cas, signs := store.creates, store.cas, env.Trust.(*fixtureTrust).signs
			public, private := env.Custody.Calls()
			candidate, res := prepareGeneratedRecordCandidate(t, env, s, permit, ctx)
			wantCalls := 1
			if fault.kind == 0 {
				wantCalls = 0
			}
			if candidate != nil || res != fault.want || changed.calls != wantCalls || store.creates != creates || store.cas != cas || env.Trust.(*fixtureTrust).signs != signs {
				t.Fatal("invalid private phase evidence crossed the write boundary", res)
			}
			if fault.kind == 0 {
				if p, k := env.Custody.Calls(); p != public || k != private {
					t.Fatal("cancelled or expired admission reached private custody")
				}
			}
			if prepared, _ := s.PrepareGeneratedRecord(context.Background(), permit); prepared != nil || changed.calls != wantCalls || store.creates != creates {
				t.Fatal("failed private phase was repeated")
			}
			env.Custody.RetireGenerated()
			cold, res := Open(context.Background(), a.f.admission, env.Store)
			if cold == nil || res.Outcome != ObservedCurrent {
				t.Fatal("private phase failure damaged the predecessor", res)
			}
			a.assertState(t, cold, false)
		})
	}
}

// full_only: false
func TestGeneratedRecordAdmissionRequiresExactCurrentContext(t *testing.T) {
	a := newGeneratedResultFixture(t, 2, true)
	s := a.f.session
	admitted := generatedPlanInputFixture(t, s).context
	for name, change := range map[string]func(*contract.ApplyContext){
		"class":         func(c *contract.ApplyContext) { c.OperationClass = contract.CryptoOrdinaryLifecycle },
		"admission":     func(c *contract.ApplyContext) { c.AdmissionID = contract.ID{} },
		"session":       func(c *contract.ApplyContext) { c.SessionID = contract.ID{} },
		"domain":        func(c *contract.ApplyContext) { c.DomainID[0] ^= 1 },
		"compatibility": func(c *contract.ApplyContext) { c.CompatibilityID[0] ^= 1 },
		"access root":   func(c *contract.ApplyContext) { c.CurrentAccessRoot[0] ^= 1 },
		"HEAD":          func(c *contract.ApplyContext) { c.PredecessorHEADDigest[0] ^= 1 },
		"root":          func(c *contract.ApplyContext) { c.PredecessorRootRef[10] ^= 1 },
		"condition":     func(c *contract.ApplyContext) { c.OriginalConditionDigest[0] ^= 1 },
		"intent":        func(c *contract.ApplyContext) { c.IntentDescriptor.Digest[0] = 1 },
		"expired":       func(c *contract.ApplyContext) { c.Expiry = uint64(time.Now().Add(-time.Second).UnixNano()) },
		"expiry range":  func(c *contract.ApplyContext) { c.Expiry = 1 << 63 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := admitted
			change(&changed)
			if _, err := s.generatedRecordRequest(context.Background(), a.expected.Template.AttemptID, a.result, changed); err == nil {
				t.Fatal("changed current context admitted result recording")
			}
		})
	}
	for _, attempt := range []contract.ID{{}, a.expected.Use.ResultID, testID("unrelated attempt")} {
		if _, err := s.generatedRecordRequest(context.Background(), attempt, a.result, admitted); err == nil {
			t.Fatal("different frontier admitted result recording")
		}
	}
	plan := generatedRecordPlanForResult(t, s, a.expected.Template.AttemptID, a.result, "unchanged current context")
	prepared := preparePrivateGeneratedRecord(t, a.env, s, plan)
	recorded, res := s.selectCandidate(context.Background(), prepared.reservation.candidate)
	if recorded == nil || res.Outcome != ObservedCurrent {
		t.Fatal("invalid context attempt consumed valid result admission", res)
	}
	a.assertState(t, recorded, true)
}

// full_only: false
func TestGeneratedRecordDamagedResultReachesPrivateRefusal(t *testing.T) {
	a := newGeneratedResultFixture(t, 0, false)
	env, original := a.env, a.result
	result, err := contract.DecodeGeneratedResultRecord(original)
	if err != nil {
		t.Fatal(err)
	}
	result.Payload.Ciphertext[len(result.Payload.Ciphertext)-1] ^= 1
	bad, err := contract.EncodeGeneratedResultRecord(result)
	if err != nil || bytes.Equal(bad, original) {
		t.Fatal("damaged result must retain valid public framing", err)
	}
	s := a.f.session
	plan := generatedRecordPlanForResult(t, s, a.expected.Template.AttemptID, bad, "damaged result")
	permit := admitPrivateGeneratedRecord(env.operationContext(), t, env.Custody, s, plan)
	compared := &changedCryptoReply{inner: permit.crypto, kind: contract.CryptoPrepare, change: func(r contract.CryptoResponse) contract.CryptoResponse {
		if r.ResultCode != contract.CryptoStoredAuthenticationFailed || len(r.Body) != 0 {
			t.Fatal("damaged result did not fail private authentication")
		}
		return r
	}}
	permit.crypto = compared
	store := env.Store.(*memoryStore)
	creates, cas, signs := store.creates, store.cas, env.Trust.(*fixtureTrust).signs
	public, private := env.Custody.Calls()
	prepared, res := s.PrepareGeneratedRecord(context.Background(), permit)
	if prepared != nil || res != failure(IntegrityFailure, InvalidProof) || compared.calls != 1 || store.creates != creates || store.cas != cas || env.Trust.(*fixtureTrust).signs != signs {
		t.Fatal("damaged encrypted result reached signing or storage", res)
	}
	if p, k := env.Custody.Calls(); p != public || k != private+1 {
		t.Fatal("damaged result did not use exactly its admitted seed open")
	}
	a.assertState(t, s, false)
}

// full_only: false
func TestGeneratedRecordDerivesPhysicalIdentitiesApartFromOriginalResult(t *testing.T) {
	a := newGeneratedResultFixture(t, 0, false)
	record, err := contract.DecodeGeneratedResultRecord(a.result)
	if err != nil {
		t.Fatal(err)
	}
	s := a.f.session
	plan := generatedRecordPlanForResult(t, s, a.expected.Template.AttemptID, a.result, "physical phase")
	public, private := a.env.Custody.Calls()
	next, err := s.deriveGeneratedRecord(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	phase := next.state.root.Generated.ActivePhase
	seen := map[contract.ID]bool{record.Transfer.Core.EnvelopeID: true, record.Core.ResultID: true, a.expected.Plan.OperationID: true, phase: true}
	rows := []struct {
		label string
		body  []byte
		id    contract.ID
	}{
		{"phase-snapshot", phase[:], next.state.root.Snapshot},
		{"phase-transition", phase[:], next.state.root.Transition},
		{"phase-revision", phase[:], next.candidate.head.Core.Revision},
	}
	for _, prior := range s.adminIndex.Pages {
		if slices.ContainsFunc(prior.Rows, func(row format.AdministrativeRowSummary) bool {
			return row.Kind == contract.OutputConfigurationSliceSupportKind
		}) && !slices.Contains(next.state.root.RequiredSupport, prior.Ref) {
			t.Fatal("physical phase changed the retained configuration Ref")
		}
	}
	for _, page := range next.state.root.RequiredSupport {
		if slices.Contains(s.root.RequiredSupport, page) {
			continue
		}
		body := append(bytes.Clone(phase[:]), byte(page.Kind))
		body = binary.BigEndian.AppendUint16(body, page.Index)
		rows = append(rows, struct {
			label string
			body  []byte
			id    contract.ID
		}{"phase-page", body, page.Object})
	}
	for _, row := range rows {
		// Independent physical-ID preimage: NUL-terminated label, big-endian
		// body length, then PhaseID and (for pages) kind/index.
		preimage := []byte("ENKV/GENERATOR/v1/" + row.label + "\x00")
		preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(row.body)))
		preimage = append(preimage, row.body...)
		if row.id != contract.ID(sha256.Sum256(preimage)) || row.id.IsZero() || seen[row.id] {
			t.Fatal("physical phase identity changed its derivation or reused a retained identity", row.label)
		}
		seen[row.id] = true
	}
	for _, field := range []string{"request", "predecessor", "condition", "result"} {
		bad := *plan
		switch field {
		case "request":
			bad.phase.RequestIdentityDigest = record.Transfer.Core.EnvelopeID
		case "predecessor":
			bad.phase.ObservedHEADDigest = record.Transfer.Core.EnvelopeID
		case "condition":
			bad.phase.ConditionDigest = record.Transfer.Core.EnvelopeID
		case "result":
			bad.phase.Evidence.Digest = record.Transfer.Core.EnvelopeID
		}
		if _, err := s.deriveGeneratedRecord(context.Background(), &bad); err == nil {
			t.Fatal("changed phase identity input accepted", field)
		}
	}
	if p, k := a.env.Custody.Calls(); p != public || k != private {
		t.Fatal("public phase derivation entered private work")
	}
}

type changedGeneratedRequest struct {
	inner    contract.Crypto
	kind     contract.CryptoKind
	change   func([]byte) []byte
	original contract.CryptoRequest
	calls    int
}

func (c *changedGeneratedRequest) InstanceID() contract.ID { return c.inner.InstanceID() }
func (c *changedGeneratedRequest) Exchange(ctx context.Context, q contract.CryptoRequest) contract.CryptoResponse {
	if q.Kind == c.kind {
		c.calls++
		c.original = q
		c.original.Body = bytes.Clone(q.Body)
		q.Body = c.change(q.Body)
	}
	return c.inner.Exchange(ctx, q)
}

// full_only: false
func TestGeneratedRecordRejectsChangedStageBodies(t *testing.T) {
	for _, kind := range []contract.CryptoKind{contract.CryptoCompare, contract.CryptoPrepare, contract.CryptoFreeze, contract.CryptoClaim} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			a := newGeneratedResultFixture(t, 0, false)
			env := a.env
			s := a.f.session
			plan := generatedRecordPlanForResult(t, s, a.expected.Template.AttemptID, a.result, "changed stage")
			permit := admitPrivateGeneratedRecord(env.operationContext(), t, env.Custody, s, plan)
			changed := &changedGeneratedRequest{inner: permit.crypto, kind: kind}
			changed.change = func(body []byte) []byte {
				var out []byte
				var err error
				switch kind {
				case contract.CryptoCompare:
					q, decodeErr := contract.InspectCryptoGeneratedCompareRequest(body)
					if decodeErr != nil {
						t.Fatal(decodeErr)
					}
					q.Context.SessionID = testID("changed phase session")
					out, err = contract.EncodeCryptoGeneratedCompareRequest(q)
				case contract.CryptoPrepare:
					q, decodeErr := contract.InspectCryptoGeneratedAdoptRequest(body)
					if decodeErr != nil {
						t.Fatal(decodeErr)
					}
					q.Context.SessionID = testID("changed adoption session")
					out, err = contract.EncodeCryptoGeneratedAdoptRequest(contract.CryptoGeneratedAdoptRequest(q))
				case contract.CryptoFreeze:
					q, decodeErr := contract.InspectCryptoGeneratedFreezeRequest(body)
					if decodeErr != nil {
						t.Fatal(decodeErr)
					}
					q.CandidateSupport.Digest = testID("changed candidate support")
					out, err = contract.EncodeCryptoGeneratedFreezeRequest(q)
				case contract.CryptoClaim:
					q, decodeErr := contract.InspectCryptoGeneratedClaimRequest(body)
					if decodeErr != nil {
						t.Fatal(decodeErr)
					}
					q.KeyUses.Digest = testID("changed claim key uses")
					out, err = contract.EncodeCryptoGeneratedClaimRequest(q)
				}
				if err != nil || bytes.Equal(out, body) {
					t.Fatal("changed stage request lost valid framing", err)
				}
				return out
			}
			permit.crypto = changed
			store := env.Store.(*memoryStore)
			creates, cas, signs := store.creates, store.cas, env.Trust.(*fixtureTrust).signs
			candidate, res := prepareGeneratedRecordCandidate(t, env, s, permit, context.Background())
			if candidate != nil || res != refused(AdmissionInvalid) || changed.calls != 1 || store.creates != creates || store.cas != cas || env.Trust.(*fixtureTrust).signs != signs {
				t.Fatal("changed exact phase request was accepted", res)
			}
			public, private := env.Custody.Calls()
			reply := changed.inner.Exchange(context.Background(), changed.original)
			if err := contract.ValidateCryptoExchange(changed.original, reply); err != nil || reply.ResultCode != contract.CryptoAlreadyUsed || len(reply.Body) != 0 {
				t.Fatal("failed stage left reusable private phase authority", err)
			}
			if p, k := env.Custody.Calls(); p != public || k != private {
				t.Fatal("repeated phase request entered private work")
			}
			a.assertState(t, s, false)
		})
	}
}

// full_only: false
func TestGeneratedRecordRejectsValidReplyAfterDeadline(t *testing.T) {
	for _, kind := range []contract.CryptoKind{contract.CryptoCompare, contract.CryptoClaim} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a := newGeneratedResultFixture(t, 0, false)
				env := a.env
				s := a.f.session
				deadline := time.Now().Add(time.Second)
				plan := generatedRecordPlanForResult(t, s, a.expected.Template.AttemptID, a.result, "expired reply")
				plan.request.Context.Expiry = uint64(deadline.UnixNano())
				permit := admitPrivateGeneratedRecord(env.operationContext(), t, env.Custody, s, plan)
				late := &changedCryptoReply{inner: permit.crypto, kind: kind, change: func(r contract.CryptoResponse) contract.CryptoResponse {
					if r.ResultCode != contract.CryptoSuccess || !time.Now().Before(deadline) {
						t.Fatal("late reply was not produced successfully before expiry")
					}
					timer := time.NewTimer(time.Until(deadline) + 10*time.Millisecond)
					defer timer.Stop()
					<-timer.C
					return r
				}}
				permit.crypto = late
				store := env.Store.(*memoryStore)
				creates, cas, signs := store.creates, store.cas, env.Trust.(*fixtureTrust).signs
				candidate, res := prepareGeneratedRecordCandidate(t, env, s, permit, context.Background())
				if candidate != nil || res != refused(AdmissionInvalid) || late.calls != 1 || store.creates != creates || store.cas != cas || env.Trust.(*fixtureTrust).signs != signs {
					t.Fatal("late valid phase reply became usable", res)
				}
				env.Custody.RetireGenerated()
				a.assertState(t, s, false)
			})
		})
	}
}

package core

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

type generatedLifecycleDeleteStore struct {
	*memoryStore
	status      contract.WriteStatus
	deleteKey   string
	deleteToken contract.Token
	deletes     int
}

func (s *generatedLifecycleDeleteStore) DeleteIfToken(_ context.Context, key string, token contract.Token) contract.WriteResult {
	s.deletes++
	s.deleteKey, s.deleteToken = key, token
	return contract.WriteResult{Status: s.status, Reason: contract.ReasonTransport}
}

func generatedLifecycleReopen(t testing.TB, ctx context.Context, selected *StateSession, store contract.Store) *StateSession {
	t.Helper()
	reopened, result := Open(ctx, OpenContext{admission: &selected.admission}, store)
	if reopened == nil || result.Outcome != ObservedCurrent {
		t.Fatal("selected lifecycle state did not reopen through full authentication", result)
	}
	return reopened
}

func generatedLifecycleSelectionFixture(t testing.TB, s *StateSession) (*memoryStore, *fixtureTrust) {
	t.Helper()
	descriptor := s.admission.store
	descriptor.Prefix, descriptor.HeadKey = "fixture", "fixture/HEAD"
	store := &memoryStore{desc: descriptor, objects: make(map[string]stored)}
	store.objects[descriptor.HeadKey] = stored{Body: bytes.Clone(s.body), Token: s.token}
	s.admission.store, s.admission.composition, s.admission.expires = descriptor, generatedVectorID(244), time.Now().Add(time.Minute)
	s.store = store
	s.cache = make(map[format.Ref][]byte)
	seed := func(ref contract.Ref, body []byte, err error) {
		t.Helper()
		if err != nil || format.CheckReference(ref, body) != nil {
			t.Fatal("invalid lifecycle fixture object", err)
		}
		key, err := format.Key(descriptor.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		store.objects[key] = stored{Body: bytes.Clone(body), Token: s.token}
		s.cache[ref] = bytes.Clone(body)
	}
	for i, page := range s.recipients {
		if page != nil {
			body, err := format.EncodeRecipientPage(*page)
			seed(*s.root.Recipients[i], body, err)
		}
	}
	for i, page := range s.pages {
		if page != nil {
			body, err := format.EncodeValueEntryPage(*page)
			seed(*s.root.ValueEntryPages[i], body, err)
		}
	}
	for i, page := range s.access {
		if page != nil {
			body, err := format.EncodeAccessPage(*page)
			seed(s.root.CurrentAccess.Core.AccessPageRefs[i], body, err)
		}
	}
	for i, view := range s.support {
		page := format.RequiredSupportPage{Domain: view.Domain, Object: view.Object, Index: view.Index}
		for _, row := range view.Records {
			page.Records = append(page.Records, contract.SupportRecord(row))
		}
		body, err := format.EncodeRequiredSupportPage(page)
		seed(s.root.RequiredSupport[i], body, err)
	}
	var ok bool
	s.key, ok = publicKey(s.admission.publicKey)
	if !ok || !s.admission.valid(store) {
		t.Fatal("lifecycle admission fixture is invalid")
	}
	signer := testtrust.NewCurrent(t, s.root.CurrentAccess.Core.NormalSigning)
	binding, err := contract.NewBindingRequest(s.root.CurrentAccess.Core.NormalSigning.Binding)
	if err != nil {
		t.Fatal(err)
	}
	proof := signer.Sign(context.Background(), binding)
	if proof.Reason != contract.ReasonNone || len(proof.Signature) == 0 {
		t.Fatal("lifecycle fixture K1 proof unavailable")
	}
	s.head.K1 = proof.Signature
	return store, &fixtureTrust{Signer: signer}
}

// full_only: false
func TestGeneratedLifecyclePrivateAdmissionPreparesAndSelectsExactCleanupClose(t *testing.T) {
	for _, tc := range []struct {
		name      string
		casMode   string
		stale     bool
		want      Outcome
		wantState bool
	}{
		{name: "acknowledged", want: ObservedCurrent, wantState: true},
		{name: "lost reply readback", casMode: "lost-after", want: ObservedCurrent, wantState: true},
		{name: "stale predecessor", stale: true, want: Contention},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, s, original, result := generatedAuthenticatedDeleteHazardFixture(t, false, 0)
			admitted := generatedPlanInputFixture(t, s).context
			g, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			a := g.attempts[original.record.AttemptID]
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			store.creates, store.cas, trust.signs = 0, 0, 0
			store.casMode = tc.casMode
			key, err := format.GeneratedResultKey(store.desc.Prefix, a.record.DomainID, a.record.InboxID)
			if err != nil {
				t.Fatal(err)
			}
			store.objects[key] = stored{Body: bytes.Clone(result), Token: contract.Token{Family: store.desc.Family, Value: `"late-original"`}}

			plan, err := s.generatedReflectionPlan(context.Background(), a.record.ResultID, result, admitted)
			if err != nil || plan.kind != generatedLifecycleCleanupClose {
				t.Fatal("cleanup-close plan", err)
			}
			for name, damage := range map[string]func(*generatedLifecyclePlan){
				"owner":    func(p *generatedLifecyclePlan) { p.owner = generatedVectorID(245) },
				"evidence": func(p *generatedLifecyclePlan) { p.evidence = generatedVectorID(246) },
			} {
				t.Run("reject "+name, func(t *testing.T) {
					bad := *plan
					bad.result = bytes.Clone(plan.result)
					damage(&bad)
					if permit, err := s.admitGeneratedLifecyclePlan(t.Context(), &bad); err == nil || permit != nil || trust.signs != 0 || store.cas != 0 {
						t.Fatal("changed private lifecycle admission escaped validation")
					}
				})
			}
			permit := admitPrivateGeneratedOriginalReflection(t, env.Custody, s, a.record.ResultID, result, admitted)
			candidate, prepared := s.PrepareGeneratedLifecycle(context.Background(), permit, trust)
			if candidate == nil || prepared.Outcome != ObservedCurrent || trust.signs != 1 || store.cas != 0 || store.creates == 0 {
				t.Fatalf("prepare result=%+v signs=%d creates=%d cas=%d", prepared, trust.signs, store.creates, store.cas)
			}
			if duplicate, result := s.PrepareGeneratedLifecycle(context.Background(), permit, trust); duplicate != nil || result.Outcome != AdmissionRefused || trust.signs != 1 {
				t.Fatal("one-use private lifecycle admission was reusable")
			}
			if tc.stale {
				current := store.objects[store.desc.HeadKey]
				current.Token = contract.Token{Family: store.desc.Family, Value: `"stale"`}
				store.objects[store.desc.HeadKey] = current
			}
			next, selected := s.selectCandidate(context.Background(), candidate)
			if selected.Outcome != tc.want || (next != nil) != tc.wantState || store.cas != 1 || trust.signs != 1 {
				t.Fatalf("select result=%+v state=%v signs=%d cas=%d", selected, next != nil, trust.signs, store.cas)
			}
			if tc.wantState {
				work, err := next.selectedGeneratedWork(context.Background())
				if err != nil || work.parent != nil || work.phase != nil {
					t.Fatal("selected cleanup-close state is not the authenticated detached closure", err)
				}
				reopened := generatedLifecycleReopen(t, t.Context(), next, store)
				work, err = reopened.selectedGeneratedWork(context.Background())
				if err != nil || work.parent != nil || work.phase != nil {
					t.Fatal("reopened cleanup-close state changed its authenticated closure", err)
				}
			}
			if again, result := s.selectCandidate(context.Background(), candidate); again != nil || result.Outcome != AdmissionRefused || store.cas != 1 {
				t.Fatal("selected lifecycle candidate was reusable")
			}
		})
	}
}

// full_only: false
func TestGeneratedLifecyclePreissuedPermitsConsumeOnePreparation(t *testing.T) {
	for _, failedSign := range []bool{false, true} {
		t.Run(fmt.Sprint("failed sign ", failedSign), func(t *testing.T) {
			env, s, original, packet := generatedAuthenticatedDeleteHazardFixture(t, false, 0)
			admitted := generatedPlanInputFixture(t, s).context
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			key, err := format.GeneratedResultKey(store.desc.Prefix, original.record.DomainID, original.record.InboxID)
			if err != nil {
				t.Fatal(err)
			}
			store.objects[key] = stored{Body: bytes.Clone(packet), Token: contract.Token{Family: store.desc.Family, Value: `"late-original"`}}
			first := admitPrivateGeneratedOriginalReflection(t, env.Custody, s, original.record.ResultID, packet, admitted)
			second, err := s.admitGeneratedLifecyclePlan(t.Context(), first.plan)
			if err != nil {
				t.Fatal("second permit before preparation", err)
			}
			second.crypto, second.instance, second.verification = first.crypto, first.instance, first.verification
			trust.signs, trust.corrupt = 0, failedSign
			_, _ = s.PrepareGeneratedLifecycle(context.Background(), first, trust)
			if trust.signs != 1 {
				t.Fatal("first preparation did not reach one signing attempt", trust.signs)
			}
			if candidate, result := s.PrepareGeneratedLifecycle(context.Background(), second, trust); candidate != nil ||
				result.Outcome != AdmissionRefused || trust.signs != 1 {
				t.Fatal("preissued permit reached a second signing attempt", result, trust.signs)
			}
		})
	}
}

func admitPrivateGeneratedOriginalReflection(t testing.TB, keys *custody.Fixture, s *StateSession,
	resultID contract.ID, packet []byte, admitted contract.ApplyContext) *admittedGeneratedLifecycle {
	t.Helper()
	keys.RetireGenerated()
	permit, err := s.admitGeneratedReflection(context.Background(), resultID, packet, admitted, keys.Crypto())
	if err != nil {
		t.Fatal("private original-result reflection plan", err)
	}
	q := permit.verification
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a := g.attempts[q.Original.AttemptID]
	graph, err := g.content.graphForOperation(a.record.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	owner, present := g.records[generatedRecordKey{q.OriginalOwnerKind, q.OriginalOwnerID}]
	if !present {
		t.Fatal("exact selected original reflection owner")
	}
	input := custody.GeneratedVerificationInput{Expected: a.expected, Material: a.material, Owner: owner}
	input.Graph, err = contract.EncodeGeneratorPlanBundle(graph)
	if err != nil {
		t.Fatal(err)
	}
	access, ok := s.materialAccess(3, q.MaterialID)
	if !ok {
		t.Fatal("exact retained original seed access")
	}
	input.SeedAccess, err = contract.EncodeAccessRecord(access)
	if err != nil {
		t.Fatal(err)
	}
	input.BeforePublic, err = s.publicProjection()
	if err != nil {
		t.Fatal(err)
	}
	input.Output, err = s.generatedOutputTransition(t.Context())
	if err != nil {
		t.Fatal("verification selected output predecessor", err)
	}
	if a.expected.Template.Action == 2 {
		source, err := contract.InspectGeneratedDeleteSource(owner)
		if err != nil {
			t.Fatal(err)
		}
		target, err := g.generatedCleanupTarget(owner.Kind, owner.RecordID, source.Target)
		if err != nil {
			t.Fatal(err)
		}
		input.Target = &target
	}
	if err := keys.AdmitGeneratedVerification(q, currentControlOf(s), input, permit.deadline); err != nil {
		t.Fatal("fresh private original-result Crypto admission", err)
	}
	t.Cleanup(keys.RetireGenerated)
	return permit
}

func generatedAuthenticatedDeleteHazardFixture(t *testing.T, recovery bool, previous int) (fixtureEnvironment, *StateSession, generatedAttempt, []byte) {
	return generatedAuthenticatedDeleteHazardFixtureForProfile(t, t.Context(), recovery, previous, defaultGeneratedFixtureProfile())
}

func generatedAuthenticatedDeleteHazardFixtureForProfile(t *testing.T, operationCtx context.Context, recovery bool, previous int, profile generatedFixtureProfile, captured ...map[contract.ID][]byte) (fixtureEnvironment, *StateSession, generatedAttempt, []byte) {
	t.Helper()
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, recovery)
	if profile.CompletionClass == contract.GeneratedCompletionConfirmed {
		env = syntheticAuthorityScenarioEnvironment(t, env)
		keys = env.Custody
	}
	f := newEnvironmentFixture(t, ctx, env, nil, false)
	s := selectPrivateGeneratedOperation(t, env, f.session,
		generatedPlanInputForGenerations(t, f.session, generatedVectorID(230), []string{"generated"}, profile), "initial late-delete target")
	old := *s.valueEntry(0)
	s = selectPrivateGeneratedOperation(t, env, s,
		generatedStatePlanInput(t, s, generatedVectorID(231), []string{old.Name}, profile, old.Generated.Epoch+1,
			map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: old}), "late-delete rotation")
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	duty, err := contract.InspectGeneratedDutyRecord(g.records[generatedRecordKey{10, s.valueEntry(0).Generated.RetiringDutyID}].Body)
	if err != nil {
		t.Fatal(err)
	}
	target, err := g.retirementTarget(ctx, duty)
	if err != nil {
		t.Fatal(err)
	}
	var originalID contract.ID
	var originalPacket []byte
	for i := 0; i <= previous; i++ {
		operation := fixtureID(s.root.Domain, fmt.Sprintf("late delete operation %d", i))
		input, inputCanonical := generatedDeletePlanInput(t, s, operation, duty, target, 2)
		prior, _ := preparePrivateGeneratedReservation(t, env, s, input, inputCanonical)
		producer, expected := preparePrivateGeneratedProducer(t, env, s, prior, nil)
		var packet []byte
		var facts contract.GeneratorSafeFacts
		var code contract.CryptoResultCode
		if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
			packet, facts, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
			return code
		}) {
			t.Fatal("original delete producer handoff")
		}
		entered, result := s.selectCandidate(ctx, producer.reservation.candidate)
		if entered == nil || result.Outcome != ObservedCurrent || len(packet) == 0 {
			t.Fatal("original exact delete entry", result, code, facts, len(packet))
		}
		if len(captured) != 0 {
			captured[0][expected.Template.ResultID] = bytes.Clone(packet)
		}
		keys.RetireGenerated()
		if i == 0 {
			originalID, originalPacket = expected.Template.AttemptID, packet
		}
		// The original producer has sealed a packet, but it has not reached
		// its inbox. Core retains the entered invocation as uncertain.
		ambiguity, err := contract.EncodeGeneratorSafeFacts(generatedUnknownFixtureFacts(expected, generatedTargetEvidence(t, entered, target)))
		if err != nil {
			t.Fatal(err)
		}
		admitted := generatedPlanInputFixture(t, entered).context
		admitted.AdmissionID = fixtureID(s.root.Domain, fmt.Sprintf("late original ambiguity admission %d", i))
		admitted.SessionID = fixtureID(s.root.Domain, fmt.Sprintf("late original ambiguity session %d", i))
		var permit *admittedGeneratedLifecycle
		if i < previous {
			permit, err = entered.admitGeneratedRetirementUnknown(ctx, duty.DutyID, ambiguity, admitted)
		} else {
			permit, err = entered.admitGeneratedActiveRetirementResidue(ctx, duty.DutyID, ambiguity, admitted)
		}
		if err != nil {
			t.Fatal(err)
		}
		candidate, prepared := entered.PrepareGeneratedLifecycle(ctx, permit, env.Trust)
		if candidate == nil || prepared.Outcome != ObservedCurrent {
			t.Fatal("retain original delete uncertainty", prepared)
		}
		s, result = entered.selectCandidate(ctx, candidate)
		if s == nil || result.Outcome != ObservedCurrent {
			t.Fatal("select original delete uncertainty", result)
		}
		s = generatedLifecycleReopen(t, operationCtx, s, env.Store)
		if i < previous {
			g, err = s.selectedGeneratedWork(ctx)
			if err != nil {
				t.Fatal(err)
			}
			duty, err = contract.InspectGeneratedDutyRecord(g.records[generatedRecordKey{10, duty.DutyID}].Body)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	g, err = s.selectedGeneratedWork(ctx)
	if err != nil || g.parent != nil || g.phase != nil || len(g.attempts) != previous+1 {
		t.Fatal("exact detached original delete history", err)
	}
	return env, s, g.attempts[originalID], originalPacket
}

// full_only: false
func TestGeneratedStrongerLateAcknowledgementReflectsWithoutClosing(t *testing.T) {
	for _, tc := range []struct {
		recovery, lostCASReply bool
	}{{false, false}, {true, false}, {false, true}, {true, true}} {
		t.Run(fmt.Sprintf("recovery=%t/lost-CAS-reply=%t", tc.recovery, tc.lostCASReply), func(t *testing.T) {
			profile := defaultGeneratedFixtureProfile()
			profile.CompletionClass = contract.GeneratedCompletionConfirmed
			env, s, original, packet := generatedAuthenticatedDeleteHazardFixtureForProfile(t, t.Context(), tc.recovery, 0, profile)
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			key, err := format.GeneratedResultKey(store.desc.Prefix, original.record.DomainID, original.record.InboxID)
			if err != nil {
				t.Fatal(err)
			}
			store.objects[key] = stored{Body: bytes.Clone(packet), Token: contract.Token{Family: store.desc.Family, Value: `"stronger-late-ack"`}}
			work := mustSelectedGeneratedWork(t, s)
			hazardID := original.expected.Template.HazardID
			attempt := work.attempts[original.record.AttemptID]
			store.creates, store.cas, trust.signs = 0, 0, 0

			admitted := generatedPlanInputFixture(t, s).context
			admitted.AdmissionID, admitted.SessionID = testID("stronger late ACK reflection"), testID("stronger late ACK reflection session")
			permit := admitPrivateGeneratedOriginalReflection(t, env.Custody, s, original.record.ResultID, packet, admitted)
			candidate, prepared := s.PrepareGeneratedLifecycle(context.Background(), permit, trust)
			if candidate == nil || prepared.Outcome != ObservedCurrent || trust.signs != 1 || store.cas != 0 {
				t.Fatal("verified late ACK did not prepare one nonfinal K2 transition", prepared)
			}
			if tc.lostCASReply {
				store.casMode = "lost-after"
			}
			next, selected := s.selectCandidate(context.Background(), candidate)
			if next == nil || selected.Outcome != ObservedCurrent || store.cas != 1 {
				t.Fatal("verified late ACK did not select one nonfinal transition", selected)
			}
			store.casMode = ""
			if again, outcome := s.selectCandidate(context.Background(), candidate); again != nil || outcome.Outcome != AdmissionRefused || store.cas != 1 {
				t.Fatal("selected late ACK reflection repeated its effect")
			}
			cold := generatedLifecycleReopen(t, t.Context(), next, store)
			after := mustSelectedGeneratedWork(t, cold)
			if after.attempts[original.record.AttemptID].record != attempt.record ||
				!bytes.Equal(after.attempts[original.record.AttemptID].result, packet) ||
				cold.root.Generated.Hazards != 1 || cold.root.Generated.PendingReleases != 0 ||
				!cold.root.Generated.ActiveOwner.IsZero() {
				t.Fatal("late ACK changed the original state or closed a confirmed Hazard")
			}
			view, err := cold.inspectGeneratedWork(context.Background())
			if err != nil || len(view.hazards) != 1 || len(view.effects) != 1 ||
				view.effects[0].attempt.AttemptID != original.record.AttemptID ||
				view.effects[0].evidenceCeiling != contract.ReceiptEvidenceAcknowledged ||
				view.warnings&contract.ReceiptWarningInvalidationNotConfirmed == 0 ||
				view.warnings&contract.ReceiptWarningPossibleLive == 0 {
				t.Fatal("nonfinal ACK inspection lost its ceiling, warning, or unfinished owner", err)
			}
			hazard, err := contract.InspectGeneratedHazardRecord(after.records[generatedRecordKey{11, hazardID}].Body)
			if err != nil || hazard.Exposure != contract.GeneratedExposurePossibleLive || hazard.Fenced != 1 || hazard.OriginalResults.Count != 1 {
				t.Fatal("nonfinal reflection lost exact Hazard evidence", err)
			}
			source, err := after.generatedDeleteSource(attempt.record.OwnerID)
			if err != nil {
				t.Fatal(err)
			}
			target, err := after.generatedCleanupTarget(11, source.SourceID, source.Target)
			if err != nil {
				t.Fatal(err)
			}
			input, inputCanonical := generatedDeletePlanInputForSource(t, cold, generatedVectorID(241), source.Record, target)
			x := input.graph.Lineages[0].Templates[0]
			scope := contract.GeneratorControlledRetirementScope(source.DescriptorID, source.ConfigContractID, x.ResultContractID)
			input.requestBindings[0].Digest = contract.GeneratorControlledRetirementProbeDigest(source.DomainID, source.ResourceID, target.ResourceDigest,
				scope, original.record.ResultID, contract.Hash(packet))
			env.Custody.RetireGenerated()
			prior, _ := preparePrivateGeneratedReservation(t, env, cold, input, inputCanonical)
			responder := custody.NewControlledRetirementResponder(source.ResourceID, target.ResourceDigest, scope)
			defer responder.Close()
			responder.DeleteExact(target.ResourceDigest)
			confirmed, _, remaining, confirmation := selectActualGeneratedPacketRecord(t, env, cold, prior, custody.StandardValue, true,
				func(ctx context.Context, command contract.GeneratedProducerCommand) []byte {
					return responder.Probe(ctx, command)
				})
			if len(confirmation) == 0 || remaining.Template.AttemptID.IsZero() {
				t.Fatal("remaining confirmation result missing")
			}
			env.Custody.RetireGenerated()
			closed := selectOrdinaryGeneratedCleanupClose(t, t.Context(), env, confirmed, remaining.Template.AttemptID)
			closed = generatedLifecycleReopen(t, t.Context(), closed, store)
			final := mustSelectedGeneratedWork(t, closed)
			if _, present := final.records[generatedRecordKey{11, hazardID}]; present || closed.root.Generated.Hazards != 0 ||
				closed.root.Generated.PendingReleases != 2 || len(final.attempts) != 0 || final.parent != nil || final.phase != nil {
				t.Fatal("confirmed late ACK continuation did not close exact Hazard", present)
			}
			if _, present, read := closed.ReadGeneratedResult(context.Background(), original.record.AttemptID); present || read.Outcome != AdmissionRefused {
				t.Fatal("closed reflected original regained its result reader")
			}
		})
	}
}

// full_only: false
func TestGeneratedStrongerLateAcknowledgementStaleReflectionRetriesFromCurrentHead(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			profile := defaultGeneratedFixtureProfile()
			profile.CompletionClass = contract.GeneratedCompletionConfirmed
			env, s, original, packet := generatedAuthenticatedDeleteHazardFixtureForProfile(t, t.Context(), recovery, 0, profile)
			store := env.Store.(*memoryStore)
			key, err := format.GeneratedResultKey(store.desc.Prefix, original.record.DomainID, original.record.InboxID)
			if err != nil {
				t.Fatal(err)
			}
			store.objects[key] = stored{Body: bytes.Clone(packet), Token: contract.Token{Family: store.desc.Family, Value: `"late-original"`}}
			permit := admitPrivateGeneratedOriginalReflection(t, env.Custody, s, original.record.ResultID, packet,
				generatedPlanInputFixture(t, s).context)
			candidate, prepared := s.PrepareGeneratedLifecycle(context.Background(), permit, env.Trust)
			if candidate == nil || prepared.Outcome != ObservedCurrent {
				t.Fatal("stale reflection preparation", prepared)
			}
			old := store.objects[store.desc.HeadKey]
			store.put(store.desc.HeadKey, old.Body)
			if next, selected := s.selectCandidate(context.Background(), candidate); next != nil || selected.Outcome != Contention {
				t.Fatal("stale reflection selected against a competing current condition", selected)
			}
			current := generatedLifecycleReopen(t, t.Context(), s, store)
			fresh := generatedPlanInputFixture(t, current).context
			fresh.AdmissionID, fresh.SessionID = generatedVectorID(249), generatedVectorID(250)
			permit = admitPrivateGeneratedOriginalReflection(t, env.Custody, current, original.record.ResultID, packet,
				fresh)
			candidate, prepared = current.PrepareGeneratedLifecycle(context.Background(), permit, env.Trust)
			if candidate == nil || prepared.Outcome != ObservedCurrent {
				t.Fatal("fresh reflection preparation", prepared)
			}
			next, selected := current.selectCandidate(context.Background(), candidate)
			if next == nil || selected.Outcome != ObservedCurrent {
				t.Fatal("fresh reflection after contention", selected)
			}
			after := mustSelectedGeneratedWork(t, generatedLifecycleReopen(t, t.Context(), next, store))
			if len(after.attempts[original.record.AttemptID].result) == 0 || next.root.Generated.Hazards != 1 {
				t.Fatal("fresh reflection lost the selected ACK or unfinished Hazard")
			}
		})
	}
}

// full_only: false
func TestGeneratedConfirmedLateAcknowledgementsKeepExactMembershipInEitherOrder(t *testing.T) {
	for _, order := range [][]int{{0, 1, 2}, {2, 0, 1}} {
		t.Run(fmt.Sprint(order), func(t *testing.T) {
			profile := defaultGeneratedFixtureProfile()
			profile.CompletionClass = contract.GeneratedCompletionConfirmed
			_, s, _, _ := generatedAuthenticatedDeleteHazardFixtureForProfile(t, t.Context(), false, 2, profile)
			g := mustSelectedGeneratedWork(t, s)
			attempts := make([]generatedAttempt, 0, len(g.attempts))
			for _, a := range g.attempts {
				attempts = append(attempts, a)
			}
			slices.SortFunc(attempts, func(a, b generatedAttempt) int {
				return bytes.Compare(a.record.OperationID[:], b.record.OperationID[:])
			})
			if len(attempts) != 3 {
				t.Fatal("three original delete coordinates required")
			}
			bound := continuationTestBound(t, s).Remaining
			for i, index := range order {
				g = mustSelectedGeneratedWork(t, s)
				a := g.attempts[attempts[index].record.AttemptID]
				packet := generatedRetirementResultFixture(t, s, a, contract.GeneratorDispositionRetirementAcknowledged)
				plan, err := s.generatedReflectionPlan(t.Context(), a.record.ResultID, packet, generatedPlanInputFixture(t, s).context)
				if err != nil || plan.kind != generatedLifecycleReflection {
					t.Fatal("nonfinal late ACK plan", err)
				}
				next, err := s.deriveGeneratedReflection(t.Context(), plan)
				if err != nil || next.state.validateGeneratedSelection(t.Context(), nil) != nil {
					t.Fatal("nonfinal late ACK successor", err)
				}
				s = next.state
				continuationTestCandidateWithin(t, s, bound)
				g = mustSelectedGeneratedWork(t, s)
				h, err := contract.InspectGeneratedHazardRecord(g.records[generatedRecordKey{11, g.deleteHazards[a.record.AttemptID]}].Body)
				if err != nil || h.OriginalResults.Count != uint32(i+1) || h.Exposure != contract.GeneratedExposurePossibleLive ||
					len(g.attempts) != 3 || len(g.releases) != 0 {
					t.Fatal("late ACK changed owner or exact result membership", err)
				}
			}
			// Every original now has its immutable ACK. A further provider
			// confirmation requires fresh admission.
			selected, err := selectedContinuationGroups(t.Context(), g.image, g)
			if err != nil {
				t.Fatal(err)
			}
			groups, _, err := continuationGroupTotals(selected, continuationGrowth{})
			after := continuationTestBound(t, s).Remaining.Groups
			if err != nil || after[contract.GeneratorCapacityDeletes] != groups[contract.GeneratorCapacityDeletes] {
				t.Fatal("already recorded replies acquired fresh delete growth", err)
			}
		})
	}
}

// full_only: false
func TestGeneratedLateConfirmationBindsAlreadySelectedAck(t *testing.T) {
	profile := defaultGeneratedFixtureProfile()
	profile.CompletionClass = contract.GeneratedCompletionConfirmed
	for _, tc := range []struct {
		recovery, laterACK bool
	}{{false, false}, {true, false}, {false, true}, {true, true}} {
		t.Run(fmt.Sprintf("recovery=%t/later-ACK=%t", tc.recovery, tc.laterACK), func(t *testing.T) {
			previous, operation := 0, byte(242)
			if tc.laterACK {
				previous = 1
			}
			captured := make(map[contract.ID][]byte)
			env, s, original, ack := generatedAuthenticatedDeleteHazardFixtureForProfile(t, t.Context(), tc.recovery, previous, profile, captured)
			store := env.Store.(*memoryStore)
			ackKey, err := format.GeneratedResultKey(store.desc.Prefix, original.record.DomainID, original.record.InboxID)
			if err != nil {
				t.Fatal(err)
			}
			store.objects[ackKey] = stored{Body: bytes.Clone(ack), Token: contract.Token{Family: store.desc.Family, Value: `"late-ack-before-confirmation"`}}
			permit := admitPrivateGeneratedOriginalReflection(t, env.Custody, s, original.record.ResultID, ack, generatedPlanInputFixture(t, s).context)
			candidate, prepared := s.PrepareGeneratedLifecycle(context.Background(), permit, env.Trust)
			if candidate == nil || prepared.Outcome != ObservedCurrent {
				t.Fatal("late ACK reflection", prepared)
			}
			s, selected := s.selectCandidate(context.Background(), candidate)
			if s == nil || selected.Outcome != ObservedCurrent {
				t.Fatal("late ACK selection", selected)
			}
			s = generatedLifecycleReopen(t, t.Context(), s, store)
			g := mustSelectedGeneratedWork(t, s)
			source, err := g.generatedDeleteSource(original.record.OwnerID)
			if err != nil {
				t.Fatal(err)
			}
			target, err := g.generatedCleanupTarget(11, source.SourceID, source.Target)
			if err != nil {
				t.Fatal(err)
			}
			confirmationOperation := generatedVectorID(operation)
			if tc.laterACK {
				var minimum contract.ID
				found := false
				for _, attempt := range g.attempts {
					if !found || bytes.Compare(attempt.record.OperationID[:], minimum[:]) < 0 {
						minimum, found = attempt.record.OperationID, true
					}
				}
				if !found {
					t.Fatal("historical delete operation is absent")
				}
				confirmationOperation = minimum
				borrow := true
				for i := len(confirmationOperation) - 1; i >= 0; i-- {
					if confirmationOperation[i] != 0 {
						confirmationOperation[i]--
						borrow = false
						break
					}
					confirmationOperation[i] = 0xff
				}
				if borrow || confirmationOperation == (contract.ID{}) {
					t.Fatal("historical delete operations have no nonzero predecessor")
				}
				for _, attempt := range g.attempts {
					if bytes.Compare(confirmationOperation[:], attempt.record.OperationID[:]) >= 0 {
						t.Fatal("confirmation operation does not precede historical delete")
					}
				}
			}
			input, inputCanonical := generatedDeletePlanInputForSource(t, s, confirmationOperation, source.Record, target)
			x := input.graph.Lineages[0].Templates[0]
			scope := contract.GeneratorControlledRetirementScope(source.DescriptorID, source.ConfigContractID, x.ResultContractID)
			input.requestBindings[0].Digest = contract.GeneratorControlledRetirementProbeDigest(source.DomainID, source.ResourceID, target.ResourceDigest,
				scope, original.record.ResultID, contract.Hash(ack))
			env.Custody.RetireGenerated()
			prior, _ := preparePrivateGeneratedReservation(t, env, s, input, inputCanonical)
			responder := custody.NewControlledRetirementResponder(source.ResourceID, target.ResourceDigest, scope)
			defer responder.Close()
			responder.DeleteExact(target.ResourceDigest)
			producer, expected := preparePrivateGeneratedProducerProbe(t, env, s, prior, custody.StandardValue, nil,
				func(ctx context.Context, command contract.GeneratedProducerCommand) []byte {
					return responder.Probe(ctx, command)
				})
			var confirmation []byte
			if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
				var code contract.CryptoResultCode
				confirmation, _, code = env.Custody.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
				return code
			}) {
				t.Fatal("confirmation handoff")
			}
			entered, selected := s.selectCandidate(context.Background(), producer.reservation.candidate)
			if entered == nil || selected.Outcome != ObservedCurrent || len(confirmation) == 0 {
				t.Fatal("confirmation entry", selected)
			}
			env.Custody.RetireGenerated()
			ambiguity, err := contract.EncodeGeneratorSafeFacts(generatedUnknownFixtureFacts(expected, generatedTargetEvidence(t, entered, target)))
			if err != nil {
				t.Fatal(err)
			}
			park, err := entered.admitGeneratedOrdinaryCleanupUnknown(context.Background(), expected.Template.AttemptID, ambiguity, generatedPlanInputFixture(t, entered).context)
			if err != nil {
				t.Fatal("park missing confirmation", err)
			}
			candidate, prepared = entered.PrepareGeneratedLifecycle(context.Background(), park, env.Trust)
			if candidate == nil || prepared.Outcome != ObservedCurrent {
				t.Fatal("park missing confirmation", prepared)
			}
			parked, selected := entered.selectCandidate(context.Background(), candidate)
			if parked == nil || selected.Outcome != ObservedCurrent {
				t.Fatal("park missing confirmation", selected)
			}
			parked = generatedLifecycleReopen(t, t.Context(), parked, store)
			confirmationKey, err := format.GeneratedResultKey(store.desc.Prefix, source.DomainID, expected.Template.InboxID)
			if err != nil {
				t.Fatal(err)
			}
			store.objects[confirmationKey] = stored{Body: bytes.Clone(confirmation), Token: contract.Token{Family: store.desc.Family, Value: `"late-confirmation"`}}
			lateWork := mustSelectedGeneratedWork(t, parked)
			lateSource, err := lateWork.generatedDeleteSource(source.OwnerID)
			if err != nil {
				t.Fatal(err)
			}
			historical := lateWork.attempts[expected.Template.AttemptID]
			withoutAdmittedAck := historical
			withoutAdmittedAck.record.Progress = contract.EmptyGeneratorVector(contract.GeneratorVectorProgress)
			unadmittedWork := *lateWork
			unadmittedWork.attempts = maps.Clone(lateWork.attempts)
			unadmittedWork.attempts[expected.Template.AttemptID] = withoutAdmittedAck
			unadmitted := withoutAdmittedAck
			unadmitted.result = confirmation
			if _, err := unadmittedWork.controlledDeleteSourceProgress(lateSource, &unadmitted, false); err == nil {
				t.Fatal("ACK selected after probe admission supplied a missing historical prefix")
			}
			available := map[contract.ID][]byte{expected.Template.ResultID: confirmation}
			if tc.laterACK {
				for id, a := range lateWork.attempts {
					if id != original.record.AttemptID && id != expected.Template.AttemptID {
						packet := captured[a.record.ResultID]
						if a.record.OperationID != fixtureID(s.root.Domain, "late delete operation 1") || len(packet) == 0 {
							t.Fatal("later original ACK fixture is incomplete")
						}
						available[a.record.ResultID] = packet
					}
				}
				if len(available) != 2 {
					t.Fatal("later original ACK is absent")
				}
			}
			lateSelection, ok, selectErr := lateWork.selectGeneratedCleanup(context.Background(), available)
			if selectErr != nil || !ok || lateSelection.attempt.record.AttemptID != expected.Template.AttemptID {
				t.Fatal("late confirmation selection", selectErr)
			}
			if _, err := lateWork.generatedReflectLateDelete(t.Context(), lateSelection, parked.head.Core.Revision); err != nil {
				t.Fatal("late confirmation closure construction", err)
			}
			bound := continuationTestBound(t, parked).Remaining
			latePlan, err := parked.generatedReflectionPlan(t.Context(), expected.Template.ResultID, confirmation, generatedPlanInputFixture(t, parked).context)
			if err != nil {
				t.Fatal("late confirmation public plan", err)
			}
			if _, err := parked.deriveGeneratedCleanupClose(t.Context(), latePlan); err != nil {
				t.Fatal("late confirmation successor", err)
			}
			permit = admitPrivateGeneratedOriginalReflection(t, env.Custody, parked, expected.Template.ResultID, confirmation, generatedPlanInputFixture(t, parked).context)
			candidate, prepared = parked.PrepareGeneratedLifecycle(context.Background(), permit, env.Trust)
			if candidate == nil || prepared.Outcome != ObservedCurrent {
				t.Fatal("late confirmation reflection", prepared)
			}
			closed, selected := parked.selectCandidate(context.Background(), candidate)
			if closed == nil || selected.Outcome != ObservedCurrent {
				t.Fatal("late confirmation closure", selected)
			}
			closed = generatedLifecycleReopen(t, t.Context(), closed, store)
			continuationTestCandidateWithin(t, closed, bound)
			final := mustSelectedGeneratedWork(t, closed)
			if closed.root.Generated.Hazards != 0 || len(final.attempts) != 0 || closed.root.Generated.PendingReleases != uint32(previous+2) {
				t.Fatal("late confirmation did not close exact owner", closed.root.Generated.Hazards, len(final.attempts), closed.root.Generated.PendingReleases)
			}
		})
	}
}

// full_only: false
func TestGeneratedReflectionRefusesUnqualifiedOriginalCiphertextBeforeK2(t *testing.T) {
	for _, name := range []string{"create", "delete", "older delete"} {
		t.Run(name, func(t *testing.T) {
			checkGeneratedReflectionRefusesUnqualifiedOriginalCiphertext(t, name)
		})
	}
}

// full_only: false
func TestGeneratedOriginalReflectionAuthenticatesOlderDeleteBeforeOneK2Close(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			env, s, original, packet := generatedAuthenticatedDeleteHazardFixture(t, recovery, 2)
			bound := continuationTestBound(t, s).Remaining
			beforeWork, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			key, err := format.GeneratedResultKey(store.desc.Prefix, original.record.DomainID, original.record.InboxID)
			if err != nil {
				t.Fatal(err)
			}
			store.objects[key] = stored{Body: bytes.Clone(packet), Token: contract.Token{Family: store.desc.Family, Value: `"late-original"`}}
			permit := admitPrivateGeneratedOriginalReflection(t, env.Custody, s, original.record.ResultID, packet, generatedPlanInputFixture(t, s).context)
			store.creates, store.cas, trust.signs = 0, 0, 0
			candidate, prepared := s.PrepareGeneratedLifecycle(context.Background(), permit, trust)
			if candidate == nil || prepared.Outcome != ObservedCurrent || trust.signs != 1 || store.cas != 0 || store.creates == 0 {
				t.Fatal("authenticated older result did not prepare one K2 closure", prepared, trust.signs, store.cas)
			}
			next, selected := s.selectCandidate(context.Background(), candidate)
			if next == nil || selected.Outcome != ObservedCurrent || store.cas != 1 || trust.signs != 1 {
				t.Fatal("older result closure did not select once", selected)
			}
			cold := generatedLifecycleReopen(t, t.Context(), next, store)
			continuationTestCandidateWithin(t, cold, bound)
			g, err := cold.selectedGeneratedWork(context.Background())
			if err != nil || len(g.attempts) != 0 || len(g.releases) != len(beforeWork.releases)+3 || cold.root.Generated.Hazards != 0 {
				t.Fatalf("older result closure: error=%v attempts=%d materials=%d releases=%d previous releases=%d hazards=%d", err, len(g.attempts), len(g.materials), len(g.releases), len(beforeWork.releases), cold.root.Generated.Hazards)
			}
			for _, a := range beforeWork.attempts {
				if g.materials[materialIdentity{3, a.material.Core.OperationMaterialID}] {
					t.Fatal("closed original retained its seed")
				}
			}
			for id, release := range g.releases {
				if old, ok := beforeWork.releases[id]; ok {
					if old.release != release.release || old.attempt != release.attempt {
						t.Fatal("older result closure changed an unrelated release")
					}
					continue
				}
				if id == original.record.AttemptID {
					if release.release.State != contract.GeneratedReleasePending || release.release.ObjectLength != uint32(len(packet)) {
						t.Fatal("observed original release was not exact")
					}
				} else if release.release.State != contract.GeneratedReleaseUnobserved || release.release.ObjectLength != 0 {
					t.Fatal("another invocation acquired fabricated acknowledgement")
				}
			}
		})
	}
}

// full_only: false
func TestGeneratedOriginalReflectionRefusesDamagedSealedDeleteBeforeK2(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for _, previous := range []int{0, 2} {
			t.Run(fmt.Sprintf("recovery=%t/previous=%d", recovery, previous), func(t *testing.T) {
				env, s, original, packet := generatedAuthenticatedDeleteHazardFixture(t, recovery, previous)
				store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
				before := bytes.Clone(store.objects[store.desc.HeadKey].Body)
				key, err := format.GeneratedResultKey(store.desc.Prefix, original.record.DomainID, original.record.InboxID)
				if err != nil {
					t.Fatal(err)
				}
				for _, damage := range []string{"transfer", "package", "ciphertext", "semantic"} {
					t.Run(damage, func(t *testing.T) {
						current := generatedLifecycleReopen(t, t.Context(), s, store)
						result, err := contract.DecodeGeneratedResultRecord(packet)
						if err != nil {
							t.Fatal(err)
						}
						switch damage {
						case "transfer":
							result.Transfer.Ciphertext[0] ^= 1
						case "package":
							result.Payload.PackageCheck[0] ^= 1
						case "ciphertext":
							result.Payload.Ciphertext[0] ^= 1
						case "semantic":
							result.Payload.SemanticCommitment[0] ^= 1
						}
						damaged, err := contract.EncodeGeneratedResultRecord(result)
						if err != nil {
							t.Fatal(err)
						}
						store.objects[key] = stored{Body: damaged, Token: contract.Token{Family: store.desc.Family, Value: `"damaged-original"`}}
						admitted := generatedPlanInputFixture(t, current).context
						admitted.AdmissionID, admitted.SessionID = testID("verify "+damage), testID("verify session "+damage)
						permit := admitPrivateGeneratedOriginalReflection(t, env.Custody, current, original.record.ResultID, damaged, admitted)
						store.creates, store.cas, trust.signs = 0, 0, 0
						candidate, prepared := current.PrepareGeneratedLifecycle(context.Background(), permit, trust)
						if candidate != nil || prepared.Outcome != IntegrityFailure || trust.signs != 0 || store.creates != 0 || store.cas != 0 ||
							!bytes.Equal(before, store.objects[store.desc.HeadKey].Body) || !current.prepared || !permit.used {
							t.Fatal("unauthenticated original reached K2 or changed selected state", prepared, trust.signs, store.creates, store.cas)
						}
						if duplicate, outcome := current.PrepareGeneratedLifecycle(context.Background(), permit, trust); duplicate != nil || outcome.Outcome != AdmissionRefused || trust.signs != 0 || store.creates != 0 || store.cas != 0 {
							t.Fatal("failed verification reused its consumed permit", outcome)
						}
						if _, err := generatedLifecycleReopen(t, t.Context(), current, store).selectedGeneratedWork(context.Background()); err != nil {
							t.Fatal("authentication refusal lost retained work", err)
						}
					})
				}
			})
		}
	}
}

type changedGeneratedVerificationReply struct {
	contract.Crypto
	kind   contract.CryptoKind
	change func(*contract.CryptoResponse)
}

func (c changedGeneratedVerificationReply) Exchange(ctx context.Context, q contract.CryptoRequest) contract.CryptoResponse {
	reply := c.Crypto.Exchange(ctx, q)
	if q.Kind == c.kind {
		c.change(&reply)
	}
	return reply
}

// full_only: false
func TestGeneratedOriginalReflectionRejectsChangedPrivateRepliesBeforeK2(t *testing.T) {
	env, s, original, packet := generatedAuthenticatedDeleteHazardFixture(t, true, 2)
	store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
	key, err := format.GeneratedResultKey(store.desc.Prefix, original.record.DomainID, original.record.InboxID)
	if err != nil {
		t.Fatal(err)
	}
	store.objects[key] = stored{Body: bytes.Clone(packet), Token: contract.Token{Family: store.desc.Family, Value: `"late-original"`}}
	before := bytes.Clone(store.objects[store.desc.HeadKey].Body)
	for _, tc := range []struct {
		name   string
		kind   contract.CryptoKind
		change func(*contract.CryptoResponse)
	}{
		{"wrong instance", contract.CryptoCompare, func(r *contract.CryptoResponse) { r.CustodyInstanceID = testID("wrong Crypto") }},
		{"wrong request", contract.CryptoPrepare, func(r *contract.CryptoResponse) { r.RequestID = testID("wrong request") }},
		{"omitted seed open", contract.CryptoCompare, func(r *contract.CryptoResponse) { r.KeyUseRows = nil }},
		{"wrong original reference", contract.CryptoPrepare, func(r *contract.CryptoResponse) { r.Body = bytes.Clone(r.Body); r.Body[2] ^= 1 }},
		{"truncated reference", contract.CryptoPrepare, func(r *contract.CryptoResponse) { r.Body = r.Body[:len(r.Body)-1] }},
		{"unknown reply", contract.CryptoPrepare, func(r *contract.CryptoResponse) { r.ResultCode, r.Body = contract.CryptoResponseUnknown, nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := generatedLifecycleReopen(t, t.Context(), s, store)
			admitted := generatedPlanInputFixture(t, current).context
			admitted.AdmissionID, admitted.SessionID = testID("reply "+tc.name), testID("reply session "+tc.name)
			permit := admitPrivateGeneratedOriginalReflection(t, env.Custody, current, original.record.ResultID, packet, admitted)
			permit.crypto = changedGeneratedVerificationReply{Crypto: permit.crypto, kind: tc.kind, change: tc.change}
			store.creates, store.cas, trust.signs = 0, 0, 0
			candidate, prepared := current.PrepareGeneratedLifecycle(context.Background(), permit, trust)
			if candidate != nil || prepared.Outcome == ObservedCurrent || trust.signs != 0 || store.creates != 0 || store.cas != 0 || !current.prepared || !permit.used ||
				!bytes.Equal(before, store.objects[store.desc.HeadKey].Body) {
				t.Fatal("changed verification reply reached K2 or writes", prepared)
			}
			if duplicate, outcome := current.PrepareGeneratedLifecycle(context.Background(), permit, trust); duplicate != nil || outcome.Outcome != AdmissionRefused || trust.signs != 0 || store.creates != 0 || store.cas != 0 {
				t.Fatal("failed verification permit was reusable")
			}
		})
	}
}

func checkGeneratedReflectionRefusesUnqualifiedOriginalCiphertext(t *testing.T, name string) {
	t.Helper()
	var s *StateSession
	var original generatedAttempt
	switch name {
	case "create":
		s, original, _ = generatedCreateHazardState(t, 0, 0)
	case "delete":
		s, original, _, _ = generatedDeleteHazardState(t, 0)
	case "older delete":
		var g *generatedSelection
		var h contract.GeneratedHazardRecord
		s, g, h = generatedRepeatedRetirementHazardState(t, 2)
		for id, a := range g.attempts {
			if id != h.OriginalAttemptID {
				original = a
				break
			}
		}
	default:
		t.Fatal("unknown refusal condition")
	}
	admitted := generatedLifecycleFixture(t, s)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a := g.attempts[original.record.AttemptID]
	// This structural fixture contains repeated literal ciphertext bytes and
	// checks. No seed-backed transfer or authenticated payload was produced.
	var packet []byte
	if name == "create" {
		packet = generatedPublicResultFixture(t, a, contract.GeneratorDispositionCompleteCreate)
	} else {
		packet = generatedRetirementResultFixture(t, s, a, contract.GeneratorDispositionRetirementAcknowledged)
	}
	store, trust := generatedLifecycleSelectionFixture(t, s)
	key, err := format.GeneratedResultKey(store.desc.Prefix, a.record.DomainID, a.record.InboxID)
	if err != nil {
		t.Fatal(err)
	}
	store.objects[key] = stored{Body: bytes.Clone(packet), Token: contract.Token{Family: store.desc.Family, Value: `"unqualified-original"`}}
	permit, err := s.admitGeneratedReflection(context.Background(), a.record.ResultID, packet, admitted, nil)
	if err != nil {
		if permit != nil || trust.signs != 0 || store.creates != 0 || store.cas != 0 {
			t.Fatal("unqualified reflection refusal changed state or reached authority")
		}
		return
	}
	candidate, prepared := s.PrepareGeneratedLifecycle(context.Background(), permit, trust)
	if candidate != nil || prepared.Outcome != AdmissionRefused || trust.signs != 0 || store.creates != 0 || store.cas != 0 {
		t.Fatalf("unqualified original ciphertext reached K2: candidate=%t outcome=%d signs=%d creates=%d cas=%d",
			candidate != nil, prepared.Outcome, trust.signs, store.creates, store.cas)
	}
}

// full_only: false
func TestGeneratedInboxReleaseUnknownPrivateAdmissionSelectsAndReopensObligation(t *testing.T) {
	s, attempt, release := generatedInboxReleaseState(t, 0, contract.GeneratedReleasePending)
	admitted := generatedLifecycleFixture(t, s)
	base, trust := generatedLifecycleSelectionFixture(t, s)
	store := &generatedLifecycleDeleteStore{memoryStore: base, status: contract.WriteUnknown}
	s.store = store
	key, err := format.GeneratedResultKey(store.desc.Prefix, release.DomainID, release.InboxID)
	if err != nil {
		t.Fatal(err)
	}
	token := contract.Token{Family: store.desc.Family, Value: `"release-object"`}
	store.objects[key] = stored{Body: bytes.Clone(attempt.result), Token: token}
	expires := s.admission.expires
	s.admission.expires = time.Time{}
	if leaked, err := s.admitGeneratedInboxRelease(context.Background(), release.InboxID, admitted); err == nil || leaked != nil || store.deletes != 0 {
		t.Fatal("invalid private release admission reached the physical delete boundary")
	}
	s.admission.expires = expires

	permit, err := s.admitGeneratedInboxRelease(context.Background(), release.InboxID, admitted)
	if err != nil || permit == nil || permit.plan.kind != generatedLifecycleInboxReleaseUnknown || store.deletes != 1 ||
		store.deleteKey != key || store.deleteToken != token {
		t.Fatal("unknown delete reply did not create the exact private retained-obligation admission", err)
	}
	candidate, prepared := s.PrepareGeneratedLifecycle(context.Background(), permit, trust)
	if candidate == nil || prepared.Outcome != ObservedCurrent || trust.signs != 1 || store.cas != 0 {
		t.Fatal("unknown-release lifecycle preparation", prepared)
	}
	store.casMode = "lost-after"
	next, selected := s.selectCandidate(context.Background(), candidate)
	if next == nil || selected.Outcome != ObservedCurrent || store.cas != 1 {
		t.Fatal("unknown-release lost CAS reply did not read back the selected state", selected)
	}
	reopened := generatedLifecycleReopen(t, t.Context(), next, store)
	work, err := reopened.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	retained, ok := work.releases[attempt.record.AttemptID]
	if !ok || retained.release.State != contract.GeneratedReleaseUnknown ||
		retained.release.InboxID != release.InboxID || retained.release.SelectedHandoffDigest != release.SelectedHandoffDigest {
		t.Fatal("reopened unknown release lost or cleaned the exact retained obligation")
	}
	store.casMode = ""
	current := generatedContinuationContext(t, reopened, 247, 248)
	retry, err := reopened.admitGeneratedInboxRelease(context.Background(), release.InboxID, current)
	if err != nil || retry == nil || retry.plan.kind != generatedLifecycleInboxReleaseUnknown || store.deletes != 2 {
		t.Fatal("repeated unknown did not retain a new reobservation route", err)
	}
	candidate, prepared = reopened.PrepareGeneratedLifecycle(context.Background(), retry, trust)
	if candidate == nil || prepared.Outcome != ObservedCurrent {
		t.Fatal("repeated unknown release did not prepare", prepared)
	}
	repeated, selected := reopened.selectCandidate(context.Background(), candidate)
	if repeated == nil || selected.Outcome != ObservedCurrent ||
		repeated.root.RequiredSupportRecordCount != reopened.root.RequiredSupportRecordCount {
		t.Fatal("repeated unknown changed selected obligation charge", selected)
	}
	reopened = generatedLifecycleReopen(t, t.Context(), repeated, store)
	work, err = reopened.selectedGeneratedWork(context.Background())
	if err != nil || len(work.releases) != 1 {
		t.Fatal("repeated unknown lost or duplicated the obligation", err)
	}
	// The first delete can have taken effect even when its reply was lost.
	store.mu.Lock()
	delete(store.objects, key)
	readsBefore := store.reads
	store.mu.Unlock()
	current = generatedContinuationContext(t, reopened, 249, 250)
	retry, err = reopened.admitGeneratedInboxRelease(context.Background(), release.InboxID, current)
	if err != nil || retry == nil || retry.plan.kind != generatedLifecycleInboxRelease || store.deletes != 2 {
		t.Fatal("unknown retained release did not reobserve the absent exact inbox", err)
	}
	store.mu.Lock()
	readsAfter := store.reads
	store.mu.Unlock()
	if readsAfter <= readsBefore {
		t.Fatal("unknown retained release did not read Store again")
	}
	candidate, prepared = reopened.PrepareGeneratedLifecycle(context.Background(), retry, trust)
	if candidate == nil || prepared.Outcome != ObservedCurrent {
		t.Fatal("reobserved release did not prepare", prepared)
	}
	after, selected := reopened.selectCandidate(context.Background(), candidate)
	if after == nil || selected.Outcome != ObservedCurrent ||
		after.root.RequiredSupportRecordCount >= reopened.root.RequiredSupportRecordCount {
		t.Fatal("reobserved release did not recover selected capacity", selected)
	}
	work, err = generatedLifecycleReopen(t, t.Context(), after, store).selectedGeneratedWork(context.Background())
	if err != nil || len(work.releases) != 0 {
		t.Fatal("reobserved release left a selected obligation", err)
	}
}

// full_only: false
func TestGeneratedLifecyclePreparationRechecksSelectedEvidenceAfterAdmission(t *testing.T) {
	for _, tc := range []struct {
		name      string
		read      contract.ReadResult
		want      Result
		wantReads int
	}{
		{name: "healthy"},
		{name: "transport_unavailable", read: contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport},
			want: Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonTransport}, wantReads: 3},
		{name: "invalid_selected_page", read: contract.ReadResult{Status: contract.ReadInvalid},
			want: failure(IntegrityFailure, InvalidFormat), wantReads: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			env, s, original, packet := generatedAuthenticatedDeleteHazardFixture(t, false, 0)
			g, err := s.selectedGeneratedWork(ctx)
			if err != nil || s.generatedWork == nil || s.generatedWork.selection != g || len(s.fragmentFacts) == 0 {
				t.Fatal("fixture lacks authenticated cached work and selected fragment facts", err)
			}
			graph, err := g.retainedGraph(original.record.OperationID)
			if err != nil {
				t.Fatal("original retained graph", err)
			}
			location, present := g.content.locations[generatedContentKey{contract.GeneratorContentGraph, graph.UsePlan.PlanGraphID}]
			fragments := g.content.fragmentLocations[location.BlobID]
			if !present || len(fragments) == 0 {
				t.Fatal("original retained graph lacks a selected fragment")
			}
			fact, present := s.fragmentFacts[fragments[0]]
			if !present || fact.blob != location.BlobID {
				t.Fatal("original graph fragment lacks authenticated selected backing")
			}
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			selectedKey, err := format.Key(store.desc.Prefix, fact.ref)
			if err != nil {
				t.Fatal("selected graph page key", err)
			}
			inbox, err := format.GeneratedResultKey(store.desc.Prefix, original.record.DomainID, original.record.InboxID)
			if err != nil {
				t.Fatal("exact original result inbox", err)
			}
			store.objects[inbox] = stored{Body: bytes.Clone(packet), Token: contract.Token{Family: store.desc.Family, Value: `"late-original"`}}
			selectedReads, armed := 0, false
			store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
				if key != selectedKey {
					return read
				}
				selectedReads++
				if armed && tc.read.Status != 0 {
					return tc.read
				}
				if read.Status != contract.ReadOK {
					t.Error("healthy selected graph page was not readable", read.Status)
				}
				return read
			}
			defer func() { store.readHook = nil }()
			permit := admitPrivateGeneratedOriginalReflection(t, env.Custody, s, original.record.ResultID, packet, generatedPlanInputFixture(t, s).context)
			t.Logf("lifecycle admission: admitted=%t kind=%d selected_graph_reads=%d", permit != nil && !permit.used, permit.plan.kind, selectedReads)
			if permit.plan.kind != generatedLifecycleCleanupClose || selectedReads == 0 {
				t.Fatal("healthy lifecycle admission did not derive the exact cleanup-close graph")
			}
			captured := &generatedOrdinaryComparisonCrypto{inner: permit.crypto}
			permit.crypto = captured
			armed, selectedReads = true, 0
			first, err := s.generatedReflectionIsFirst(ctx, permit.plan)
			t.Logf("first-original control: first=%t selected_graph_reads=%d", first, selectedReads)
			if err != nil || !first || selectedReads != 0 {
				t.Fatal("armed selected-page fault did not remain after the first-original boundary", err)
			}
			beforeRoot, err := format.EncodeRoot(s.root)
			if err != nil {
				t.Fatal(err)
			}
			beforeBody, beforeToken, beforeHeadRoot := bytes.Clone(s.body), s.token, s.head.Core.Root
			creates, cas, signs := store.creates, store.cas, trust.signs
			public, private := env.Custody.Calls()
			candidate, result := s.PrepareGeneratedLifecycle(ctx, permit, trust)
			p, k := env.Custody.Calls()
			t.Logf("lifecycle preparation: selected_graph_reads=%d candidate=%t outcome=%d reason=%d store_reason=%d permit_used=%t session_prepared=%t crypto_exchanges=%d creates=%d cas=%d signs=%d public_key_calls=%d private_key_calls=%d",
				selectedReads, candidate != nil, result.Outcome, result.Reason, result.StoreReason, permit.used, s.prepared,
				len(captured.kinds), store.creates-creates, store.cas-cas, trust.signs-signs, p-public, k-private)
			if !permit.used || !s.prepared {
				t.Error("lifecycle preparation did not consume the permit and session")
			}
			afterRoot, err := format.EncodeRoot(s.root)
			if err != nil || !bytes.Equal(beforeRoot, afterRoot) || !bytes.Equal(beforeBody, s.body) || beforeToken != s.token || beforeHeadRoot != s.head.Core.Root {
				t.Error("lifecycle preparation changed its authenticated predecessor", err)
			}
			if tc.read.Status == 0 {
				if candidate == nil || result.Outcome != ObservedCurrent || selectedReads == 0 || trust.signs != signs+1 || store.creates <= creates || store.cas != cas ||
					!slices.Equal(captured.kinds, []contract.CryptoKind{contract.CryptoCompare, contract.CryptoPrepare}) {
					t.Error("healthy repeated derivation did not reread the graph and prepare the exact lifecycle candidate", result, captured.kinds)
				}
			} else if candidate != nil || result != tc.want || selectedReads != tc.wantReads || len(captured.kinds) != 0 ||
				store.creates != creates || store.cas != cas || trust.signs != signs || p != public || k != private {
				t.Error("late selected evidence refusal lost its exact result or reached a later private effect", result)
			}
			store.readHook = nil
			reads, exchanges := store.reads, len(captured.kinds)
			creates, cas, signs = store.creates, store.cas, trust.signs
			public, private = env.Custody.Calls()
			duplicate, refusedResult := s.PrepareGeneratedLifecycle(ctx, permit, trust)
			p, k = env.Custody.Calls()
			t.Logf("lifecycle permit reuse: candidate=%t outcome=%d reason=%d reads=%d crypto_exchanges=%d", duplicate != nil, refusedResult.Outcome, refusedResult.Reason, store.reads-reads, len(captured.kinds)-exchanges)
			if duplicate != nil || refusedResult != refused(AdmissionInvalid) || !permit.used || !s.prepared || store.reads != reads || len(captured.kinds) != exchanges ||
				store.creates != creates || store.cas != cas || trust.signs != signs || p != public || k != private {
				t.Error("consumed lifecycle permission allowed a second preparation or effect", refusedResult)
			}
		})
	}
}

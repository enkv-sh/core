package core

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

func generatedRetainedClosureEnterWithoutPacket(t *testing.T, env fixtureEnvironment, s *StateSession, prior *generatedPreparation) (*StateSession, contract.GeneratorResultExpectation) {
	t.Helper()
	producer, expected := preparePrivateGeneratedProducer(t, env, s, prior, nil)
	if !producer.reservation.candidate.bindFirstSend(producer, func(context.Context, contract.ID) contract.CryptoResultCode { return contract.CryptoSuccess }) {
		t.Fatal("attach original handoff")
	}
	entered, result := s.selectCandidate(t.Context(), producer.reservation.candidate)
	if entered == nil || result.Outcome != ObservedCurrent {
		t.Fatal("original selection", result)
	}
	env.Custody.RetireGenerated()
	return generatedLifecycleReopen(t, t.Context(), entered, env.Store), expected
}

// generatedRetainedClosureRetryCleanup uses actual private Crypto and selected Store
// transitions through failed Final, preserving the complete create ancestry.
func generatedRetainedClosureRetryCleanup(t *testing.T, class uint8, residue bool) (fixtureEnvironment, *StateSession, generatedAttempt, contract.GeneratedDeleteSource, contract.GeneratorTarget) {
	t.Helper()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, t.Context(), env, nil, false)
	profile := defaultGeneratedFixtureProfile()
	profile.CompletionClass = class
	input := generatedPlanInputForGenerations(t, f.session, generatedVectorID(230), []string{"omega"}, profile)
	prior, _ := preparePrivateGeneratedReservation(t, env, f.session, input, nil)
	selected, record, _, _ := selectActualGeneratedPacketRecord(t, env, f.session, prior, custody.GeneratedConfirmedNoEffect, false, nil)
	planned, outcome := selected.selectCandidate(t.Context(), record.reservation.candidate)
	if planned == nil || outcome.Outcome != ObservedCurrent {
		t.Fatal("no-effect selection", outcome)
	}
	env.Custody.RetireGenerated()
	prior = preparePrivateGeneratedSuccessorReservation(t, env, planned)
	if residue {
		entered, expected := generatedRetainedClosureEnterWithoutPacket(t, env, planned, prior)
		planned = selectGeneratedResiduePlan(t, t.Context(), env, entered, expected.Template.AttemptID)
		prior = preparePrivateGeneratedSuccessorReservation(t, env, planned)
	}
	selected, _, last, _ := selectActualGeneratedPacketRecord(t, env, planned, prior, custody.GeneratedTerminalFailure, true, nil)
	ctx := generatedPlanInputFixture(t, selected).context
	ctx.AdmissionID, ctx.SessionID = testID("retained closure final admission"), testID("retained closure final session")
	plan, e := selected.generatedFinalRequest(t.Context(), ctx)
	if e != nil {
		t.Fatal("failed Final plan", e)
	}
	selected, final := preparePrivateGeneratedFinal(t, env, selected, plan)
	closed, outcome := selected.selectCandidate(t.Context(), final.reservation.candidate)
	if closed == nil || outcome.Outcome != ObservedCurrent {
		t.Fatal("failed Final selection", outcome)
	}
	env.Custody.RetireGenerated()
	closed = generatedLifecycleReopen(t, t.Context(), closed, env.Store)
	g := mustSelectedGeneratedWork(t, closed)
	a := g.attempts[last.Template.AttemptID]
	row := g.records[generatedRecordKey{11, last.Template.HazardID}]
	source, e := contract.InspectGeneratedDeleteSource(row)
	if e != nil {
		t.Fatal(e)
	}
	target, e := g.generatedCleanupTarget(row.Kind, row.RecordID, source.Target)
	if e != nil {
		t.Fatal(e)
	}
	return env, closed, a, source, target
}

// full_only: false
func TestGeneratedRetainedClosureComponents(t *testing.T) {
	t.Run("late-create-keeps-immutable-unresolved-history", func(t *testing.T) {
		env, keys := genesisEnvironment(t, contract.GCP, true)
		before := newEnvironmentFixture(t, t.Context(), env, nil, false).session
		prior, _ := preparePrivateGeneratedReservation(t, env, before,
			generatedPlanInputForGenerations(t, before, generatedVectorID(230), []string{"late"}, defaultGeneratedFixtureProfile()), nil)
		producer, expected := preparePrivateGeneratedProducer(t, env, before, prior, nil)
		var packet []byte
		effects := 0
		if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
			effects++
			var code contract.CryptoResultCode
			packet, _, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
			return code
		}) {
			t.Fatal("late original capability handoff")
		}
		entered, result := before.selectCandidate(t.Context(), producer.reservation.candidate)
		if entered == nil || result.Outcome != ObservedCurrent || effects != 1 || len(packet) == 0 {
			t.Fatal("actual late original effect", result)
		}
		keys.RetireGenerated()
		// Lose the local result observation, exhaust the fixed resultless
		// path, and select Final before the original packet is adopted.
		fenced := selectGeneratedResiduePlan(t, t.Context(), env, entered, expected.Template.AttemptID)
		prior = preparePrivateGeneratedSuccessorReservation(t, env, fenced)
		unknown, retry := generatedRetainedClosureEnterWithoutPacket(t, env, fenced, prior)
		fenced = selectGeneratedResiduePlan(t, t.Context(), env, unknown, retry.Template.AttemptID)
		admitted := generatedPlanInputFixture(t, fenced).context
		admitted.AdmissionID, admitted.SessionID = testID("late create Final admission"), testID("late create Final session")
		plan, err := fenced.generatedFinalRequest(t.Context(), admitted)
		if err != nil || plan.selecting || len(plan.results) != 0 {
			t.Fatal("resultless Final before original reflection", err)
		}
		fenced, final := preparePrivateGeneratedFinal(t, env, fenced, plan)
		closed, result := fenced.selectCandidate(t.Context(), final.reservation.candidate)
		if closed == nil || result.Outcome != ObservedCurrent {
			t.Fatal("resultless Final selection", result)
		}
		keys.RetireGenerated()
		closed = generatedLifecycleReopen(t, t.Context(), closed, env.Store)
		work := mustSelectedGeneratedWork(t, closed)
		original := work.attempts[expected.Template.AttemptID]
		hazardRow := work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, expected.Template.HazardID}]
		hazard, err := contract.InspectGeneratedHazardRecord(hazardRow.Body)
		if err != nil || original.record.History.Count != 1 || hazard.History != original.record.History ||
			original.record.State != contract.GeneratedEffectClosedWithResidue || len(original.result) != 0 {
			t.Fatal("selected unresolved original history", err)
		}
		history, err := work.vectors.resolve(contract.GeneratedAttemptSupportKind, original.record.AttemptID, contract.GeneratorVectorHistory, original.record.History)
		if err != nil || len(history) != 1 {
			t.Fatal("immutable original history carrier", err)
		}
		history = [][]byte{bytes.Clone(history[0])}
		sibling := work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, retry.Template.HazardID}]
		// The returned packet arrives at its retained fixed inbox only after
		// the original parent has left selection.
		if body, present, read := closed.ReadGeneratedResult(t.Context(), original.record.AttemptID); read.Outcome != 0 || present || len(body) != 0 {
			t.Fatal("late original packet was already in the fixed inbox", read, present)
		}
		if persisted := closed.persistGeneratedResult(t.Context(), generatedResultWrite{attempt: original.record.AttemptID, body: packet}); persisted.Outcome != 0 {
			t.Fatal("late original packet arrival", persisted)
		}
		if body, present, read := closed.ReadGeneratedResult(t.Context(), original.record.AttemptID); read.Outcome != 0 || !present || !bytes.Equal(body, packet) {
			t.Fatal("exact late original packet readback", read, present)
		}
		admitted = generatedPlanInputFixture(t, closed).context
		admitted.AdmissionID, admitted.SessionID = testID("late create reflection admission"), testID("late create reflection session")
		permit := admitPrivateGeneratedOriginalReflection(t, keys, closed, original.record.ResultID, packet, admitted)
		if permit.plan.kind != generatedLifecycleReflection {
			t.Fatal("late Create was treated as a closing Delete")
		}
		candidate, result := closed.PrepareGeneratedLifecycle(t.Context(), permit, env.Trust)
		if candidate == nil || result.Outcome != ObservedCurrent {
			t.Fatal("qualified late Create reflection preparation", result)
		}
		reflected, result := closed.selectCandidate(t.Context(), candidate)
		if reflected == nil || result.Outcome != ObservedCurrent {
			t.Fatal("qualified late Create reflection selection", result)
		}
		keys.RetireGenerated()
		cold := generatedLifecycleReopen(t, t.Context(), reflected, env.Store)
		after := mustSelectedGeneratedWork(t, cold)
		retained := after.attempts[original.record.AttemptID]
		afterHazard, err := contract.InspectGeneratedHazardRecord(after.records[generatedRecordKey{contract.GeneratedHazardSupportKind, hazard.HazardID}].Body)
		if err != nil || retained.record.State != contract.GeneratedEffectClosedWithResidue || retained.record.History != original.record.History ||
			afterHazard.History != hazard.History || afterHazard.OwnerID != hazard.OwnerID || afterHazard.Fenced != 1 ||
			afterHazard.Exposure != contract.GeneratedExposureLateEffect || !bytes.Equal(retained.result, packet) ||
			!bytes.Equal(after.records[generatedRecordKey{contract.GeneratedHazardSupportKind, retry.Template.HazardID}].Body, sibling.Body) ||
			cold.root.ValueEntryCount != 0 || cold.root.Generated.Hazards != 2 || !cold.root.Generated.ActiveOwner.IsZero() || effects != 1 {
			t.Fatal("late Create rewrote original uncertainty, another owner, or effect count", err)
		}
		for _, owner := range []generatedRecordKey{{contract.GeneratedAttemptSupportKind, original.record.AttemptID}, {contract.GeneratedHazardSupportKind, hazard.HazardID}} {
			rows, err := after.vectors.resolve(owner.kind, owner.id, contract.GeneratorVectorHistory, original.record.History)
			if err != nil || len(rows) != 1 || !bytes.Equal(rows[0], history[0]) {
				t.Fatal("late reflection changed immutable unresolved history bytes", err)
			}
		}
		if _, err := cold.validateRelationsMode(t.Context(), false); err != nil {
			t.Fatal("late Create full cold relations", err)
		}
	})
	t.Run("ordinary-parked-cleanup-consumes-qualified-late-ack", func(t *testing.T) {
		env, sourceState, _, source, target := generatedRetainedClosureRetryCleanup(t, contract.GeneratedCompletionAcknowledged, false)
		input, canonical := generatedDeletePlanInputForSource(t, sourceState, generatedVectorID(234), source.Record, target)
		prior, _ := preparePrivateGeneratedReservation(t, env, sourceState, input, canonical)
		producer, expected := preparePrivateGeneratedProducer(t, env, sourceState, prior, nil)
		var packet []byte
		effects := 0
		if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
			effects++
			var code contract.CryptoResultCode
			packet, _, code = env.Custody.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
			return code
		}) {
			t.Fatal("ordinary cleanup capability handoff")
		}
		entered, result := sourceState.selectCandidate(t.Context(), producer.reservation.candidate)
		if entered == nil || result.Outcome != ObservedCurrent || effects != 1 || len(packet) == 0 {
			t.Fatal("actual ordinary cleanup ACK", result)
		}
		env.Custody.RetireGenerated()
		facts, err := contract.EncodeGeneratorSafeFacts(generatedUnknownFixtureFacts(expected, generatedTargetEvidence(t, entered, target)))
		if err != nil {
			t.Fatal(err)
		}
		permit, err := entered.admitGeneratedOrdinaryCleanupUnknown(t.Context(), expected.Template.AttemptID, facts, generatedPlanInputFixture(t, entered).context)
		if err != nil {
			t.Fatal("ordinary cleanup lost-observation admission", err)
		}
		candidate, result := entered.PrepareGeneratedLifecycle(t.Context(), permit, env.Trust)
		if candidate == nil || result.Outcome != ObservedCurrent {
			t.Fatal("ordinary cleanup parking preparation", result)
		}
		parked, result := entered.selectCandidate(t.Context(), candidate)
		if parked == nil || result.Outcome != ObservedCurrent {
			t.Fatal("ordinary cleanup parking selection", result)
		}
		parked = generatedLifecycleReopen(t, t.Context(), parked, env.Store)
		work := mustSelectedGeneratedWork(t, parked)
		if _, present := work.records[generatedRecordKey{source.Record.Kind, source.SourceID}]; !present || work.parent != nil {
			t.Fatal("ordinary cleanup lost its parked source")
		}
		// The returned packet arrives at its retained fixed inbox only after
		// the original parent has left selection.
		if body, present, read := parked.ReadGeneratedResult(t.Context(), expected.Template.AttemptID); read.Outcome != 0 || present || len(body) != 0 {
			t.Fatal("late original packet was already in the fixed inbox", read, present)
		}
		if persisted := parked.persistGeneratedResult(t.Context(), generatedResultWrite{attempt: expected.Template.AttemptID, body: packet}); persisted.Outcome != 0 {
			t.Fatal("late original packet arrival", persisted)
		}
		if body, present, read := parked.ReadGeneratedResult(t.Context(), expected.Template.AttemptID); read.Outcome != 0 || !present || !bytes.Equal(body, packet) {
			t.Fatal("exact late original packet readback", read, present)
		}
		admitted := generatedPlanInputFixture(t, parked).context
		admitted.AdmissionID, admitted.SessionID = testID("parked ordinary ACK admission"), testID("parked ordinary ACK session")
		reflection := admitPrivateGeneratedOriginalReflection(t, env.Custody, parked, expected.Use.ResultID, packet, admitted)
		if reflection.plan.kind != generatedLifecycleCleanupClose {
			t.Fatal("qualified late ordinary ACK did not close its exact owner")
		}
		candidate, result = parked.PrepareGeneratedLifecycle(t.Context(), reflection, env.Trust)
		if candidate == nil || result.Outcome != ObservedCurrent {
			t.Fatal("qualified late ordinary ACK preparation", result)
		}
		closed, result := parked.selectCandidate(t.Context(), candidate)
		if closed == nil || result.Outcome != ObservedCurrent {
			t.Fatal("qualified late ordinary ACK selection", result)
		}
		env.Custody.RetireGenerated()
		cold := generatedLifecycleReopen(t, t.Context(), closed, env.Store)
		after := mustSelectedGeneratedWork(t, cold)
		if _, present := after.records[generatedRecordKey{source.Record.Kind, source.SourceID}]; present ||
			!cold.root.Generated.ActiveOwner.IsZero() || effects != 1 {
			t.Fatal("ordinary late ACK retained its source or repeated a provider effect")
		}
		released, present := after.releases[expected.Template.AttemptID]
		if !present || released.release.State != contract.GeneratedReleasePending || released.release.SelectedHandoffDigest != contract.Hash(packet) ||
			released.release.ObjectLength != uint32(len(packet)) || after.materials[materialIdentity{contract.OperationSeedMaterialKind, expected.Plan.MaterialID}] {
			t.Fatal("ordinary late ACK lost exact release or retained dead seed custody")
		}
		if _, err := cold.validateRelationsMode(t.Context(), false); err != nil {
			t.Fatal("ordinary late ACK full cold relations", err)
		}
	})
	t.Run("retained-canonical-residue-production", func(t *testing.T) {
		env, _ := genesisEnvironment(t, contract.GCP, false)
		run := newScenarioRun(t, t.Context(), env)
		f := newEnvironmentFixture(t, t.Context(), run.env, nil, false)
		input, canonical := generatedSourcePlanInput(t, run, f, 2)
		prior, _ := preparePrivateGeneratedReservation(t, env, f.session, input, canonical)
		s, expected := generatedRetainedClosureEnterWithoutPacket(t, env, f.session, prior)
		if _, e := s.validateRelationsMode(t.Context(), false); e != nil {
			t.Fatal("actual predecessor relations", e)
		}
		p, e := s.generatedCreateResidueRequest(t.Context(), expected.Template.AttemptID, generatedPlanInputFixture(t, s).context)
		if e != nil {
			t.Fatal("residue request", e)
		}
		candidate, result := s.PrepareGeneratedCreateResidue(t.Context(), &admittedGeneratedCreateResidue{session: s, plan: p}, env.Trust)
		if candidate == nil || result.Outcome != ObservedCurrent {
			t.Fatal("retained-consumer residue refused", result)
		}
		fenced, result := s.selectCandidate(t.Context(), candidate)
		if fenced == nil || result.Outcome != ObservedCurrent {
			t.Fatal("retained-consumer residue selection", result)
		}
		fenced = generatedLifecycleReopen(t, t.Context(), fenced, env.Store)
		if _, e := fenced.validateRelationsMode(t.Context(), false); e != nil {
			t.Fatal("retained-consumer residue cold relations", e)
		}
	})
	t.Run("cleanup-ambiguity-after-retried-create", func(t *testing.T) {
		env, s, original, source, target := generatedRetainedClosureRetryCleanup(t, contract.GeneratedCompletionAcknowledged, false)
		input, canonical := generatedDeletePlanInputForSource(t, s, generatedVectorID(234), source.Record, target)
		prior, _ := preparePrivateGeneratedReservation(t, env, s, input, canonical)
		entered, expected := generatedRetainedClosureEnterWithoutPacket(t, env, s, prior)
		if _, e := entered.validateRelationsMode(t.Context(), false); e != nil {
			t.Fatal("actual cleanup predecessor relations", e)
		}
		g := mustSelectedGeneratedWork(t, entered)
		a := g.attempts[expected.Template.AttemptID]
		if original.record.History.Count != 2 {
			t.Fatal("missing retried create ancestry")
		}
		facts, e := contract.EncodeGeneratorSafeFacts(generatedUnknownFixtureFacts(a.expected, generatedTargetEvidence(t, entered, target)))
		if e != nil {
			t.Fatal(e)
		}
		permit, e := entered.admitGeneratedOrdinaryCleanupUnknown(t.Context(), a.record.AttemptID, facts, generatedPlanInputFixture(t, entered).context)
		if e != nil {
			t.Fatal("retried-create delete ambiguity refused", e)
		}
		candidate, result := entered.PrepareGeneratedLifecycle(t.Context(), permit, env.Trust)
		if candidate == nil || result.Outcome != ObservedCurrent {
			t.Fatal("retried-create delete ambiguity preparation", result)
		}
		parked, result := entered.selectCandidate(t.Context(), candidate)
		if parked == nil || result.Outcome != ObservedCurrent {
			t.Fatal("retried-create delete ambiguity selection", result)
		}
		parked = generatedLifecycleReopen(t, t.Context(), parked, env.Store)
		if _, e := parked.validateRelationsMode(t.Context(), false); e != nil {
			t.Fatal("retried-create delete ambiguity cold relations", e)
		}
	})
	t.Run("controlled-branch3-ancestry", func(t *testing.T) {
		_, s, a, source, _ := generatedRetainedClosureRetryCleanup(t, contract.GeneratedCompletionConfirmed, true)
		if a.expected.Template.Branch != contract.GeneratorBranchNoEffectThenResidue || a.record.History.Count != 3 {
			t.Fatal("wrong branch history")
		}
		if _, e := s.validateRelationsMode(t.Context(), false); e != nil {
			t.Fatal("actual source relations", e)
		}
		rows, e := s.workSupportRecords(t.Context())
		if e != nil {
			t.Fatal(e)
		}
		// Cold Open keeps fragment digest/ordinal facts, not physical bodies.
		// This contract inspector accepts complete physical records, so lend
		// each omitted row through its authenticated selected page and own the
		// exact bytes only for this small fixture's inspection.
		physicalFragments := 0
		for i := range rows {
			if rows[i].Kind != contract.GeneratedFragmentSupportKind || rows[i].Body != nil {
				continue
			}
			found := false
			for _, page := range s.supportFacts {
				for logical, fact := range page.rows {
					if fact.Kind() != rows[i].Kind || fact.RecordID() != rows[i].RecordID {
						continue
					}
					if found {
						t.Fatal("duplicate selected fragment fact")
					}
					found = true
					result, err := withAuthenticatedSupportRow(t.Context(), s.readObjectBorrowedUncached, s.root.Domain, page, uint16(logical), func(row contract.SupportRecordView) error {
						actual, err := contract.InspectSupportRecordDigest(s.root.Domain, contract.SupportRecord(row))
						if err != nil || actual != fact {
							return contract.ErrRecord
						}
						rows[i].Body = append([]byte(nil), row.Body...)
						return nil
					})
					if err != nil || result != (Result{}) || rows[i].Body == nil {
						t.Fatal("authenticated physical fragment unavailable", result, err)
					}
					physicalFragments++
				}
			}
			if !found {
				t.Fatal("missing selected fragment fact")
			}
		}
		if physicalFragments == 0 {
			t.Fatal("fixture did not exercise cold opaque fragments")
		}
		if count, e := contract.InspectGeneratedSelectedCreateAncestry(s.root.Domain, s.adminIndex.SliceSnapshot, rows, source); e != nil || count != 3 {
			t.Fatal("valid cumulative branch3 ancestry refused", count, e)
		}
	})
	t.Run("confirmed-ack-release-before-probe", func(t *testing.T) {
		for _, order := range []string{"ack-first", "probe-first"} {
			t.Run(order, func(t *testing.T) {
				env, s, duty, target := controlledParkedAcknowledgement(t, false)
				g := mustSelectedGeneratedWork(t, s)
				progress, e := g.controlledRetirementProgress(duty, nil, true)
				if e != nil {
					t.Fatal(e)
				}
				scope := contract.GeneratorControlledRetirementScope(duty.DescriptorID, duty.ConfigContractID, duty.ResultContractID)
				input, canonical := generatedDeletePlanInput(t, s, generatedVectorID(239), duty, target, 2)
				input.requestBindings[0].Digest = contract.GeneratorControlledRetirementProbeDigest(duty.DomainID, duty.ResourceID, target.ResourceDigest, scope, progress.ack.record.ResultID, contract.Hash(progress.ack.result))
				prior, _ := preparePrivateGeneratedReservation(t, env, s, input, canonical)
				responder := custody.NewControlledRetirementResponder(duty.ResourceID, target.ResourceDigest, scope)
				defer responder.Close()
				responder.DeleteExact(target.ResourceDigest)
				recorded, _, final, _ := selectActualGeneratedPacketRecord(t, env, s, prior, custody.StandardValue, true, func(ctx context.Context, c contract.GeneratedProducerCommand) []byte { return responder.Probe(ctx, c) })
				env.Custody.RetireGenerated()
				closed := selectControlledRetirementClose(t, t.Context(), env, recorded, final.Template.AttemptID)
				g = mustSelectedGeneratedWork(t, closed)
				ack := g.releases[progress.ack.record.AttemptID]
				probe := g.releases[final.Template.AttemptID]
				if len(g.releases) != 2 {
					t.Fatal("wrong complete releases")
				}
				if _, e := g.controlledReleasedProgress(probe); e != nil {
					t.Fatal("valid released predecessor join", e)
				}
				signRows := func(t *testing.T, bad *StateSession) *generatedCleanupDeleteStore {
					original := env.Store.(*memoryStore)
					memory := &memoryStore{desc: original.desc, configuration: original.configuration, objects: make(map[string]stored)}
					for key, value := range original.objects {
						memory.objects[key] = value
					}
					for i, page := range bad.support {
						pageRows := make([]contract.SupportRecord, len(page.Records))
						for j, row := range page.Records {
							pageRows[j] = contract.SupportRecord(row)
						}
						body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: pageRows})
						if err != nil {
							t.Fatal(err)
						}
						memory.put(mustKey(t, memory.desc.Prefix, bad.root.RequiredSupport[i]), body)
					}
					shards, err := format.EncodeAdministrativeIndexPages(bad.adminIndex)
					if err != nil {
						t.Fatal(err)
					}
					for _, shard := range shards {
						memory.put(mustKey(t, memory.desc.Prefix, shard.Ref), shard.Body)
					}
					rootBody, err := format.EncodeRoot(bad.root)
					if err != nil {
						t.Fatal(err)
					}
					rootRef, err := format.Reference(format.RootKind, bad.root.Domain, bad.root.Snapshot, 0, rootBody)
					if err != nil || bad.head.Generator == nil {
						t.Fatal("signed closure fixture lacks generated HEAD", err)
					}
					memory.put(mustKey(t, memory.desc.Prefix, rootRef), rootBody)
					head := bad.head
					subject := *head.Generator
					head.Generator = &subject
					head.Core.Root = rootRef
					coreBody, err := format.EncodeHeadCore(head.Core)
					if err != nil {
						t.Fatal(err)
					}
					condition, err := format.EncodeConditionalPlan(conditional(head.Core, coreBody))
					if err != nil {
						t.Fatal(err)
					}
					subject.AfterRootDigest, subject.AfterAccessDigest = rootRef.Digest, bad.root.CurrentAccess.AccessRoot
					// A valid signature must bind this exact selected identity
					// and work image, including repacked physical page Objects.
					identity := contract.IdentityPlan{Operation: subject.OperationID, Snapshot: bad.root.Snapshot,
						Transition: bad.root.Transition, Revision: head.Core.Revision}
					for _, ref := range bad.root.RequiredSupport {
						identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
					}
					subject.IdentityPlan, err = contract.GeneratorAuthorityIdentityDescriptor(identity)
					if err != nil {
						t.Fatal("signed closure exact selected identity", err)
					}
					workRows, err := bad.workSupportRecords(t.Context())
					if err != nil {
						t.Fatal("signed closure exact selected work", err)
					}
					subject.AfterWork, err = bad.workSupportDescriptor(workRows)
					if err != nil {
						t.Fatal("signed closure exact work commitment", err)
					}
					subject.HeadCoreDigest, subject.HeadCoreLength = contract.Hash(coreBody), uint32(len(coreBody))
					subject.ConditionalPlanDigest, subject.ConditionalLength = contract.Hash(condition), uint32(len(condition))
					request, err := contract.NewGeneratorRequest(subject)
					if err != nil {
						t.Fatal(err)
					}
					signed := env.Trust.Sign(t.Context(), request)
					if signed.Reason != contract.ReasonNone || len(signed.Signature) == 0 {
						t.Fatal("signed closure fixture signing refused", signed.Reason)
					}
					head.AuthorizationSignature = signed.Signature
					if !closed.verifyHeadProofs(head, currentControlOf(closed)) {
						t.Fatal("signed closure fixture authority signature is not valid")
					}
					headBody, err := format.EncodeHead(head)
					if err != nil {
						t.Fatal(err)
					}
					memory.put(memory.desc.HeadKey, headBody)
					deleteStore := &generatedCleanupDeleteStore{memoryStore: memory}
					bad.store, bad.body, bad.head, bad.token = deleteStore, headBody, head, memory.objects[memory.desc.HeadKey].Token
					bad.cache = make(map[format.Ref][]byte)
					bad.generatedWork, bad.generatedGraphs = nil, nil
					return deleteStore
				}
				// Each negative keeps physical hashes, the mandatory index and
				// authority signatures valid. Only historical ACK meaning changes.
				for _, damage := range []string{"ack-id", "ack-digest", "source-owner"} {
					t.Run(damage, func(t *testing.T) {
						bad := *closed
						ownSelectedSupportForMutationFixture(t, t.Context(), &bad)
						mapping := probe.attempt
						var replacement *contract.SupportRecord
						if damage == "source-owner" {
							mapping.OwnerID = generatedVectorID(244)
						} else {
							prefix, err := g.vectors.resolve(contract.GeneratedAttemptSupportKind, mapping.AttemptID, contract.GeneratorVectorProgress, mapping.Progress)
							if err != nil || len(prefix) != 1 {
								t.Fatal("released probe fixture lacks exact ACK prefix", err)
							}
							ackRow, err := contract.InspectGeneratorProgress(prefix[0])
							if err != nil {
								t.Fatal(err)
							}
							if damage == "ack-id" {
								ackRow.AttemptID = generatedVectorID(244)
							} else {
								ackRow.Evidence.Digest = generatedVectorID(244)
							}
							body, err := contract.EncodeGeneratorProgress(ackRow)
							if err != nil {
								t.Fatal(err)
							}
							var carriers []contract.SupportRecord
							mapping.Progress, carriers, err = generatedCarrierRows(mapping.DomainID, contract.GeneratedAttemptSupportKind, mapping.AttemptID, contract.GeneratorVectorProgress, [][]byte{body})
							if err != nil || len(carriers) != 1 {
								t.Fatal("changed prefix framing", err)
							}
							replacement = &carriers[0]
						}
						body, err := contract.EncodeGeneratedAttemptRecord(mapping)
						if err != nil {
							t.Fatal(err)
						}
						// Preserve the honestly selected physical owner/spans. A
						// production packer must refuse this contradictory meaning;
						// the negative needs raw format framing before cold admission.
						bad.root.RequiredSupport = append([]format.Ref(nil), bad.root.RequiredSupport...)
						bad.adminIndex.Pages = append([]format.AdministrativePage(nil), bad.adminIndex.Pages...)
						bad.adminIndex.Groups = append([]format.AdministrativeGroup(nil), bad.adminIndex.Groups...)
						changedAttempt, changedPrefix := 0, 0
						for i, page := range bad.support {
							for j, row := range page.Records {
								if row.Kind == contract.GeneratedAttemptSupportKind && row.RecordID == mapping.AttemptID {
									bad.support[i].Records[j].Body = body
									changedAttempt++
								}
								if replacement != nil && row.Kind == contract.GeneratorVectorSupportKind {
									carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
									if err != nil {
										t.Fatal(err)
									}
									if carrier.OwnerKind == contract.GeneratedAttemptSupportKind && carrier.OwnerID == mapping.AttemptID && carrier.VectorKind == contract.GeneratorVectorProgress {
										bad.support[i].Records[j] = contract.SupportRecordView{Kind: replacement.Kind, RecordID: replacement.RecordID, Body: replacement.Body}
										changedPrefix++
									}
								}
							}
							pageRows := make([]contract.SupportRecord, len(page.Records))
							for j, row := range bad.support[i].Records {
								pageRows[j] = contract.SupportRecord(row)
							}
							encoded, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: pageRows})
							if err != nil {
								t.Fatal("raw contradictory support framing", err)
							}
							ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, encoded)
							if err != nil {
								t.Fatal(err)
							}
							bad.root.RequiredSupport[i], bad.adminIndex.Pages[i].Ref = ref, ref
							if !bad.adminIndex.Pages[i].ReadRequired {
								bad.adminIndex.Pages[i].Rows = make([]format.AdministrativeRowSummary, len(pageRows))
								for j, row := range pageRows {
									bad.adminIndex.Pages[i].Rows[j] = format.AdministrativeRowSummary{Kind: row.Kind, RecordID: row.RecordID, BodyLength: uint32(len(row.Body))}
								}
							}
						}
						if changedAttempt != 1 || replacement != nil && changedPrefix != 1 {
							t.Fatal("contradictory fixture did not change exact owned rows", changedAttempt, changedPrefix)
						}
						for group := range bad.adminIndex.Groups {
							var count uint32
							for _, page := range bad.adminIndex.Pages {
								for _, span := range page.Spans {
									for _, owner := range span.GroupIndexes {
										if int(owner) == group {
											count += uint32(span.Count)
										}
									}
								}
							}
							digest := selectedDisposableDigest(count)
							for i, page := range bad.adminIndex.Pages {
								selected := 0
								for _, span := range page.Spans {
									for _, owner := range span.GroupIndexes {
										if int(owner) == group {
											for _, row := range bad.support[i].Records[selected : selected+int(span.Count)] {
												writeSelectedDisposableRow(digest, row.Kind, row.RecordID, uint32(len(row.Body)))
											}
										}
									}
									selected += int(span.Count)
								}
							}
							bad.adminIndex.Groups[group].Disposable = selectedDisposableDescriptor(digest, count)
						}
						shards, err := format.EncodeAdministrativeIndexPages(bad.adminIndex)
						if err != nil || len(shards) == 0 {
							t.Fatal("raw contradictory index framing", err)
						}
						bad.root.AdministrativeIndex, bad.root.AdministrativeIndexShards = shards[0].Ref, nil
						for _, shard := range shards[1:] {
							bad.root.AdministrativeIndexShards = append(bad.root.AdministrativeIndexShards, shard.Ref)
						}
						bad.recountChildren()
						deleteStore := signRows(t, &bad)
						public, private := env.Custody.Calls()
						opened, result := Open(t.Context(), OpenContext{admission: &bad.admission}, deleteStore)
						if opened != nil || result.Outcome != IntegrityFailure || result.Reason != InvalidRelation {
							t.Fatal("signed contradictory ACK evidence cold admission", result.Outcome, result.Reason)
						}
						permit, err := bad.admitGeneratedInboxRelease(t.Context(), probe.release.InboxID, generatedPlanInputFixture(t, &bad).context)
						if permit != nil || err == nil || deleteStore.deletes != 0 || deleteStore.creates != 0 || deleteStore.cas != 0 {
							t.Fatal("contradictory ACK release reached physical effects", deleteStore.deletes, deleteStore.creates, deleteStore.cas)
						}
						if p, k := env.Custody.Calls(); p != public || k != private {
							t.Fatal("contradictory ACK release reached private custody")
						}
					})
				}
				deleteStore := &generatedCleanupDeleteStore{memoryStore: env.Store.(*memoryStore)}
				first, second := ack, probe
				if order == "probe-first" {
					first, second = probe, ack
				}
				closed = selectActualGeneratedInboxRelease(t, t.Context(), env, closed, deleteStore, first.attempt.AttemptID, false)
				if len(mustSelectedGeneratedWork(t, closed).releases) != 1 {
					t.Fatal("first release lost the independent remaining inbox")
				}
				if order == "ack-first" {
					// Another close must preserve the immutable ACK graph owned
					// by the still-live probe prefix after the ACK mapping is gone.
					later := *closed
					ownSelectedSupportForMutationFixture(t, t.Context(), &later)
					remaining := mustSelectedGeneratedWork(t, &later)
					// Close constructors remove the old slice directory before
					// generatedCloseContent writes its replacement carriers.
					var closeRows []contract.SupportRecord
					for _, row := range later.supportRecords() {
						if row.Kind == contract.GeneratorVectorSupportKind {
							carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
							if err != nil {
								t.Fatal("unrelated close selected carrier", err)
							}
							if carrier.VectorKind == contract.GeneratorVectorSlices {
								continue
							}
						}
						closeRows = append(closeRows, row)
					}
					rows, locations, descriptor, err := remaining.generatedCloseContent(closeRows)
					if err != nil {
						t.Fatal("unrelated content close derivation", err)
					}
					later.root.Generated.Slices = descriptor
					// Mirror installGeneratedLifecycleSupport: pruning changes
					// both owner counts and the graph set of retained locations.
					generatedRefreshClosureCounts(&later.root.Generated, rows)
					var graphs []contract.ID
					for _, location := range locations {
						if location.ContentKind == contract.GeneratorContentGraph {
							graphs = append(graphs, location.ContentID)
						}
					}
					slices.SortFunc(graphs, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
					later.root.Generated.Graphs, err = contract.GeneratorIndexDescriptor(contract.GeneratorGraphSet, slices.Compact(graphs))
					if err != nil {
						t.Fatal("unrelated content close retained graph projection", err)
					}
					generatedRepackSupportAtLocations(t, &later, rows, remaining.bundles, locations)
					// Repacking deliberately removes the old root-bound Slice
					// proof. Verify the new physical image before its retained
					// receipt index or generated graph can be read as selected.
					generatedVerifySelectedFixtureSlices(t, &later)
					if _, err := later.validateRelationsMode(t.Context(), false); err != nil {
						t.Fatal("unrelated content close complete relation before signing", err)
					}
					store := signRows(t, &later)
					public, private := env.Custody.Calls()
					opened, result := Open(t.Context(), OpenContext{admission: &later.admission}, store)
					if opened == nil || result.Outcome != ObservedCurrent {
						t.Fatal("unrelated content close cold admission", result.Outcome, result.Reason)
					}
					// The complete cold reader qualifies receipt windows for
					// this exact root before signed work preflight consumes them.
					if _, ok := selectedGeneratedPreflight(opened.head, opened.selectedImage()); !ok {
						t.Fatal("unrelated content close signed work commitment")
					}
					if err := opened.validateGeneratedSelection(t.Context(), nil); err != nil {
						t.Fatal("unrelated content close exact signed selection", err)
					}
					if _, err := opened.validateRelationsMode(t.Context(), false); err != nil {
						t.Fatal("unrelated content close cold relations", err)
					}
					work := mustSelectedGeneratedWork(t, opened)
					retained, present := work.releases[probe.attempt.AttemptID]
					if _, err := work.controlledReleasedProgress(retained); !present || err != nil || len(work.releases) != 1 {
						t.Fatal("unrelated content close lost historical ACK ownership", present, err)
					}
					if p, k := env.Custody.Calls(); p != public || k != private || store.deletes != 0 || store.creates != 0 || store.cas != 0 {
						t.Fatal("unrelated content close used effects", store.deletes, store.creates, store.cas)
					}
				}
				closed = selectActualGeneratedInboxRelease(t, t.Context(), env, closed, deleteStore, second.attempt.AttemptID, false)
				if work := mustSelectedGeneratedWork(t, closed); len(work.releases) != 0 || deleteStore.deletes != 2 {
					t.Fatal("release order retained completed obligations", len(work.releases), deleteStore.deletes)
				}
			})
		}
	})
	t.Run("nonfinal-retirement-diagnostic-projection", func(t *testing.T) {
		env, _ := genesisEnvironment(t, contract.GCP, false)
		env = syntheticAuthorityScenarioEnvironment(t, env)
		f := newEnvironmentFixture(t, t.Context(), env, nil, false)
		profile := defaultGeneratedFixtureProfile()
		profile.CompletionClass = contract.GeneratedCompletionConfirmed
		s := selectPrivateGeneratedOperation(t, env, f.session, generatedPlanInputForGenerations(t, f.session, generatedVectorID(230), []string{"generated"}, profile), "diagnostic original")
		old := *s.valueEntry(0)
		s = selectPrivateGeneratedOperation(t, env, s, generatedStatePlanInput(t, s, generatedVectorID(231), []string{old.Name}, profile, old.Generated.Epoch+1, map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: old}), "diagnostic rotation")
		g := mustSelectedGeneratedWork(t, s)
		duty, e := contract.InspectGeneratedDutyRecord(g.records[generatedRecordKey{10, s.valueEntry(0).Generated.RetiringDutyID}].Body)
		if e != nil {
			t.Fatal(e)
		}
		target, e := g.retirementTarget(t.Context(), duty)
		if e != nil {
			t.Fatal(e)
		}
		input, canonical := generatedDeletePlanInput(t, s, generatedVectorID(232), duty, target, 2)
		prior, _ := preparePrivateGeneratedReservation(t, env, s, input, canonical)
		recorded, _, expected, _ := selectActualGeneratedPacketRecord(t, env, s, prior, custody.StandardValue, true, nil)
		env.Custody.RetireGenerated()
		plan, e := recorded.generatedRetirementClosePlan(t.Context(), expected.Template.AttemptID, generatedPlanInputFixture(t, recorded).context)
		if e != nil {
			t.Fatal(e)
		}
		detail := &changeObservation{}
		candidate, e := recorded.deriveGeneratedRetirementClose(t.Context(), plan, detail)
		if e != nil {
			t.Fatal("nonfinal derive", e)
		}
		if candidate.state.valueEntry(0).Generated.RetiringDutyID != duty.DutyID || candidate.state.valueEntry(0).Generated.RetiringDutyPresent != 1 {
			t.Fatal("nonfinal candidate pointer unexpectedly cleared")
		}
		// Compare the public entry change set of the actual candidate with the
		// subjects produced by the retirement observation's hypothetical close.
		actual := &changeObservation{}
		actualDescriptor, e := generatedChangedSubjects(t.Context(), recorded, candidate.state, actual)
		if e != nil {
			t.Fatal("candidate changed subjects", e)
		}
		if actualDescriptor.Count != 0 || len(actual.Subjects) != 0 {
			t.Fatal("nonfinal candidate unexpectedly changes public entries", actualDescriptor, actual.Subjects)
		}
		if detail.HasChangedSubjects && detail.Descriptor.Count != 0 || len(detail.Subjects) != 0 {
			t.Fatal("unexpected diagnostic subjects", detail.Descriptor, detail.Subjects)
		}
	})

}

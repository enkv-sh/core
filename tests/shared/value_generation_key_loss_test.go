package core

import (
	"bytes"
	stdcontext "context"
	"fmt"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

type generatedActualLoss struct {
	name                string
	recovery            bool
	lostBefore          bool
	operation, approval uint8
	mask                uint8
	targetRole          uint8
}

var generatedActualLosses = []generatedActualLoss{
	{name: "normal-signer", recovery: true, lostBefore: true, operation: 1, approval: contract.RecoverySigningRole, mask: 1, targetRole: contract.SuccessorNormalSigner},
	{name: "authority-kek", recovery: true, lostBefore: true, operation: 1, approval: contract.RecoverySigningRole, mask: 2},
	{name: "normal-signer-and-authority-kek", recovery: true, lostBefore: true, operation: 1, approval: contract.RecoverySigningRole, mask: 3, targetRole: contract.SuccessorNormalSigner},
	{name: "recovery-signer", recovery: true, lostBefore: true, operation: 3, approval: contract.NormalSigningRole, mask: 4, targetRole: contract.SuccessorRecoverySigner},
	{name: "recovery-kek", recovery: true, lostBefore: true, operation: 3, approval: contract.NormalSigningRole, mask: 8},
	{name: "recovery-signer-and-kek", recovery: true, lostBefore: true, operation: 3, approval: contract.NormalSigningRole, mask: 12, targetRole: contract.SuccessorRecoverySigner},
}

type generatedActualOperation struct {
	env      fixtureEnvironment
	fixture  *environmentFixture
	producer *generatedPreparation
	expected contract.GeneratorResultExpectation
	result   []byte
	sends    int
}

func newGeneratedActualOperation(t *testing.T, recovery bool, value uint8) *generatedActualOperation {
	t.Helper()
	ctx := stdcontext.Background()
	env, keys := genesisEnvironment(t, contract.GCP, recovery)
	env = syntheticAuthorityScenarioEnvironment(t, env)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	input := generatedPlanInputForGenerations(t, f.session, generatedVectorID(230), []string{"generated-loss"}, defaultGeneratedFixtureProfile())
	reservation, _ := preparePrivateGeneratedReservation(t, env, f.session, input, nil)
	producer, expected := preparePrivateGeneratedProducerValue(t, env, f.session, reservation, value, nil)
	a := &generatedActualOperation{env: env, fixture: f, producer: producer, expected: expected}
	if !producer.reservation.candidate.bindFirstSend(producer, func(ctx stdcontext.Context, authority contract.ID) contract.CryptoResultCode {
		a.sends++
		var code contract.CryptoResultCode
		a.result, _, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		return code
	}) {
		t.Fatal("generated loss producer handoff")
	}
	selected, result := f.session.selectCandidate(ctx, producer.reservation.candidate)
	if selected == nil || result.Outcome != ObservedCurrent || a.sends != 1 || len(a.result) == 0 {
		t.Fatal("generated loss producer selection", result)
	}
	keys.RetireGenerated()
	f.session = selected
	return a
}

func currentGeneratedEnvironment(t testing.TB, store contract.Store, selected *StateSession) fixtureEnvironment {
	t.Helper()
	return fixtureEnvironment{Store: store, Trust: memoryCurrentAuthoritySigner(t, selected), Custody: memoryCurrentAuthorityKeys(t, selected)}
}

func selectActualGeneratedLoss(t testing.TB, a *generatedActualOperation, loss generatedActualLoss) fixtureEnvironment {
	t.Helper()
	ctx, before := stdcontext.Background(), a.fixture.session
	beforeWork, err := before.preservedWorkSupportRecords(t.Context())
	if err != nil {
		t.Fatal("generated loss predecessor work", err)
	}
	beforePages, beforeValueEntryPages, beforeNames := before.pages, before.root.ValueEntryPages, before.root.Names
	control := currentControlOf(before)
	originalBindings := a.env.Custody.Bindings()
	oldBinding := control.AuthorityKMSBinding
	retired := a.env.Trust
	if loss.mask&8 != 0 {
		oldBinding = control.Recovery.KMS
	}
	if loss.mask&4 != 0 {
		retired = a.env.Recovery
	}
	replacement := syntheticFreshAuthorityReplacementEnvironment(t, a.env)
	actors := replacement.ReplacementActors(t, ctx, before, loss.operation, loss.mask, loss.approval)
	if loss.mask&(2|8) != 0 && actors.Keys == a.env.Custody {
		t.Fatal("generated KEK replacement reused the original occupied custody")
	}
	if loss.lostBefore && loss.mask&(2|8) != 0 {
		for _, keys := range []*custody.Fixture{actors.Keys, a.env.Custody} {
			witness := keys.PrivateWitness(ctx, oldBinding.BindingID, oldBinding, oldBinding)
			if witness.Outcome == contract.CryptoSuccess || witness.Completed != 0 {
				t.Fatal("lost generated KEK route was available before replacement", witness)
			}
		}
	}
	permit := admitAuthorityReplacement(t, before, actors.Keys, actors.After, loss.operation, loss.approval, loss.mask, actors.Source)
	if loss.lostBefore && loss.mask&(1|4) != 0 {
		probe, probeErr := contract.NewSuccessorSignerProbeRequest(contract.SuccessorProbeCore{Schema: 1, EvidenceKind: 1,
			TargetRole: loss.targetRole, DomainID: actors.After.DomainID, CoordinateID: actors.After.CoordinateID,
			AdmissionID: permit.request.AdmissionID, PredecessorFullHEADDigest: permit.request.PredecessorFullHEADDigest,
			RequestCoreDigest: permit.descriptor.Digest, SuccessorBindingDigest: permit.descriptor.Digest,
			ProbeAttemptID: fixtureID(actors.After.DomainID, "generated actual pre-replacement loss "+loss.name)})
		if probeErr != nil || retired.Sign(ctx, probe).Reason != contract.ReasonAccess {
			t.Fatal("lost generated signer route was available before replacement", probeErr)
		}
	}
	candidate, result := before.PrepareSuccession(ctx, permit, actors.Signers)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("generated occupied loss replacement preparation", result)
	}
	admission := deliverSuccessionBasis(t, candidate)
	if result = before.Select(ctx, candidate); result.Outcome != ObservedCurrent {
		t.Fatal("generated occupied loss replacement selection", result)
	}
	actors.Keys.RetireAccess()
	selected, result := Open(ctx, admission, a.env.Store)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("generated occupied loss replacement reopen", result)
	}
	actors.Activate(t, selected)
	if !reflect.DeepEqual(originalBindings, a.env.Custody.Bindings()) {
		t.Fatal("generated replacement changed original public custody bindings")
	}
	if loss.mask&(2|8) != 0 {
		for _, keys := range []*custody.Fixture{actors.Keys, a.env.Custody} {
			witness := keys.PrivateWitness(ctx, oldBinding.BindingID, oldBinding, oldBinding)
			if witness.Outcome == contract.CryptoSuccess || witness.Completed != 0 {
				t.Fatal("lost generated KEK route remained available", witness)
			}
		}
	}
	if loss.mask&(1|4) != 0 {
		probe, probeErr := contract.NewSuccessorSignerProbeRequest(contract.SuccessorProbeCore{Schema: 1, EvidenceKind: 1,
			TargetRole: loss.targetRole, DomainID: actors.After.DomainID, CoordinateID: actors.After.CoordinateID,
			AdmissionID: permit.request.AdmissionID, PredecessorFullHEADDigest: permit.request.PredecessorFullHEADDigest,
			RequestCoreDigest: permit.descriptor.Digest, SuccessorBindingDigest: permit.descriptor.Digest,
			ProbeAttemptID: fixtureID(actors.After.DomainID, "generated actual loss "+loss.name)})
		if probeErr != nil || retired.Sign(ctx, probe).Reason != contract.ReasonAccess {
			t.Fatal("lost generated signer route remained available", probeErr)
		}
	}
	afterWork, err := selected.preservedWorkSupportRecords(t.Context())
	if err != nil || !reflect.DeepEqual(beforeWork, afterWork) || !reflect.DeepEqual(beforePages, selected.pages) ||
		!reflect.DeepEqual(beforeValueEntryPages, selected.root.ValueEntryPages) || !reflect.DeepEqual(beforeNames, selected.root.Names) {
		t.Fatal("generated replacement changed work, member pages or membership", err)
	}
	checkFreshGeneratedProcess(t, requireAdmittedMemoryStore(t, a.env.Store), selected)
	a.fixture.admission, a.fixture.session = admission, selected
	return currentGeneratedEnvironment(t, a.env.Store, selected)
}

func recordAndFinalizeGeneratedActual(t *testing.T, a *generatedActualOperation, env fixtureEnvironment, result []byte, wantSends int, wantGenerated uint32) *StateSession {
	t.Helper()
	ctx := stdcontext.Background()
	recorded := selectFreshGeneratedRecord(t, a.env.Store.(*memoryStore), a.fixture.session, a.expected.Template.AttemptID, result)
	finalContext := generatedPlanInputFixture(t, recorded).context
	finalContext.AdmissionID = fixtureID(recorded.admission.domain, "generated loss final admission")
	finalContext.SessionID = fixtureID(recorded.admission.domain, "generated loss final session")
	plan, err := recorded.generatedFinalRequest(t.Context(), finalContext)
	if err != nil {
		t.Fatal("generated loss final request", err)
	}
	recorded, prepared := preparePrivateGeneratedFinal(t, env, recorded, plan)
	closed, outcome := recorded.selectCandidate(ctx, prepared.reservation.candidate)
	if closed == nil || outcome.Outcome != ObservedCurrent || closed.root.Generated.GeneratedCurrent != wantGenerated ||
		!closed.root.Generated.ActiveOwner.IsZero() || a.sends != wantSends {
		t.Fatal("generated loss continuation final selection", outcome)
	}
	checkFreshGeneratedProcess(t, a.env.Store.(*memoryStore), closed)
	return closed
}

// full_only: false
func TestGeneratedActualLossAtCreateInboxAndRecordedCuts(t *testing.T) {
	for _, loss := range generatedActualLosses {
		for _, cut := range []string{"absent-inbox", "durable-unread-inbox", "recorded-terminal-result"} {
			t.Run(fmt.Sprintf("%s/%s", loss.name, cut), func(t *testing.T) {
				a := newGeneratedActualOperation(t, loss.recovery, custody.StandardValue)
				store := a.env.Store.(*memoryStore)
				if cut == "durable-unread-inbox" {
					key := expectedGeneratedResultKey(store.desc.Prefix, a.expected)
					if write := store.Create(stdcontext.Background(), key, a.result); write.Status != contract.WriteAcknowledged {
						t.Fatal("durable generated inbox write", write)
					}
					body, present, outcome := a.fixture.session.ReadGeneratedResult(stdcontext.Background(), a.expected.Template.AttemptID)
					if !present || outcome.Outcome != 0 || !bytes.Equal(body, a.result) {
						t.Fatal("durable generated inbox unread evidence", outcome)
					}
				}
				if cut == "recorded-terminal-result" {
					a.fixture.session = selectFreshGeneratedRecord(t, store, a.fixture.session, a.expected.Template.AttemptID, a.result)
				}
				fresh := selectActualGeneratedLoss(t, a, loss)
				if cut == "recorded-terminal-result" {
					finalContext := generatedPlanInputFixture(t, a.fixture.session).context
					finalContext.AdmissionID = fixtureID(a.fixture.session.admission.domain, "recorded loss final admission")
					finalContext.SessionID = fixtureID(a.fixture.session.admission.domain, "recorded loss final session")
					plan, err := a.fixture.session.generatedFinalRequest(t.Context(), finalContext)
					if err != nil {
						t.Fatal(err)
					}
					finalBase, prepared := preparePrivateGeneratedFinal(t, fresh, a.fixture.session, plan)
					closed, outcome := finalBase.selectCandidate(stdcontext.Background(), prepared.reservation.candidate)
					if closed == nil || outcome.Outcome != ObservedCurrent || a.sends != 1 {
						t.Fatal("recorded generated loss continuation", outcome)
					}
					checkFreshGeneratedProcess(t, store, closed)
					return
				}
				body := a.result
				if cut == "durable-unread-inbox" {
					var present bool
					var outcome Result
					body, present, outcome = a.fixture.session.ReadGeneratedResult(stdcontext.Background(), a.expected.Template.AttemptID)
					if !present || outcome.Outcome != 0 {
						t.Fatal("replacement lost durable unread result", outcome)
					}
				}
				recordAndFinalizeGeneratedActual(t, a, fresh, body, 1, 1)
			})
		}
	}
}

func prepareGeneratedActualSuccessor(t *testing.T, loss generatedActualLoss) (*generatedActualOperation, *generatedPreparation, contract.GeneratorResultExpectation) {
	t.Helper()
	ctx := stdcontext.Background()
	env, keys := genesisEnvironment(t, contract.GCP, loss.recovery)
	env = syntheticAuthorityScenarioEnvironment(t, env)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	input := generatedPlanInputForGenerations(t, f.session, generatedVectorID(231), []string{"generated-successor"}, defaultGeneratedFixtureProfile())
	reservation, _ := preparePrivateGeneratedReservation(t, env, f.session, input, nil)
	firstProducer, first := preparePrivateGeneratedProducerValue(t, env, f.session, reservation, custody.GeneratedConfirmedNoEffect, nil)
	a := &generatedActualOperation{env: env, fixture: f, producer: firstProducer, expected: first}
	var firstResult []byte
	if !firstProducer.reservation.candidate.bindFirstSend(firstProducer, func(ctx stdcontext.Context, authority contract.ID) contract.CryptoResultCode {
		a.sends++
		var code contract.CryptoResultCode
		firstResult, _, code = keys.InvokeGeneratedProducer(ctx, firstProducer.operation.context.AdmissionID, firstProducer.producerLocator, authority)
		return code
	}) {
		t.Fatal("first generated successor handoff")
	}
	selected, result := f.session.selectCandidate(ctx, firstProducer.reservation.candidate)
	if selected == nil || result.Outcome != ObservedCurrent || a.sends != 1 || len(firstResult) == 0 {
		t.Fatal("first generated successor selection", result)
	}
	keys.RetireGenerated()
	context := generatedPlanInputFixture(t, selected).context
	context.AdmissionID = fixtureID(env.Domain, "generated successor record admission")
	context.SessionID = fixtureID(env.Domain, "generated successor record session")
	plan, err := selected.generatedRecordRequest(stdcontext.Background(), first.Template.AttemptID, firstResult, context)
	if err != nil {
		t.Fatal("generated successor record request", err)
	}
	if plan.phase.TransitionKind != contract.GeneratorAuthorityNoEffectBranch {
		t.Fatal("first result did not install the qualified no-effect branch")
	}
	record := preparePrivateGeneratedRecord(t, env, selected, plan)
	if record.reservation.candidate.firstSend != nil {
		t.Fatal("Record acquired a successor first send")
	}
	planned, outcome := selected.selectCandidate(ctx, record.reservation.candidate)
	if planned == nil || outcome.Outcome != ObservedCurrent || a.sends != 1 || planned.head.Generator == nil || planned.head.Generator.Purpose != contract.GeneratorAuthorityNoEffectBranch {
		t.Fatal("fixed no-effect successor installation", outcome)
	}
	work := mustSelectedGeneratedWork(t, planned)
	if len(work.bundles) != 1 || !reflect.DeepEqual(work.bundles[0].Lineages, input.graph.Lineages) {
		t.Fatal("successor loss fixture changed its complete fixed graph")
	}
	var create contract.GeneratorLineageTemplate
	creates := 0
	for _, lineage := range work.bundles[0].Lineages {
		if lineage.Purpose == contract.GeneratorLineageCreate {
			create = lineage
			creates++
		}
	}
	if creates != 1 || create.LineageID != first.Template.LineageID || create.TemplateCount != 5 {
		t.Fatal("successor loss fixture must retain one complete create lineage")
	}
	next := create.Templates[contract.GeneratorBranchNoEffect]
	original, present := work.attempts[first.Template.AttemptID]
	_, entered := work.attempts[next.AttemptID]
	if !present || original.record.State != contract.GeneratedEffectConfirmedNoEffect || !bytes.Equal(original.result, firstResult) || len(work.attempts) != 1 || entered || next.AttemptID == first.Template.AttemptID || next.LineageID != first.Template.LineageID || work.phase.FrontierAttemptID != next.AttemptID || work.phase.Branch != contract.GeneratorBranchNoEffect || work.phase.NoEffectUsed != 1 || work.phase.ResidueUsed != 0 || work.phase.Stage != contract.GeneratedStageRetainedResult {
		t.Fatal("installed successor changed its fixed node, prior result or entry state")
	}
	prior := preparePrivateGeneratedSuccessorReservation(t, env, planned)
	if prior.reservation.candidate.firstSend != nil || prior.reservation.candidate.head.Generator == nil || prior.reservation.candidate.head.Generator.Purpose != contract.GeneratorAuthorityReservation || a.sends != 1 {
		t.Fatal("successor reservation entered before producer preparation")
	}
	successor, expected := preparePrivateGeneratedProducer(t, env, planned, prior, nil)
	if !reflect.DeepEqual(expected.Template, next) || a.sends != 1 {
		t.Fatal("producer preparation changed or entered the fixed successor")
	}
	a.producer, a.expected, f.session = successor, expected, planned
	return a, successor, expected
}

// full_only: false
func TestGeneratedActualLossAtSuccessorCuts(t *testing.T) {
	for _, loss := range generatedActualLosses {
		for _, cut := range []string{"installed-before-entry", "transmitted"} {
			t.Run(fmt.Sprintf("%s/%s", loss.name, cut), func(t *testing.T) {
				ctx := t.Context()
				a, producer, expected := prepareGeneratedActualSuccessor(t, loss)
				var result []byte
				var fresh fixtureEnvironment
				if !producer.reservation.candidate.bindFirstSend(producer, func(dispatchContext stdcontext.Context, authority contract.ID) contract.CryptoResultCode {
					if cut == "installed-before-entry" {
						selected, outcome := Open(ctx, a.fixture.admission, a.env.Store)
						if selected == nil || outcome.Outcome != ObservedCurrent {
							t.Fatal("installed generated successor reopen", outcome)
						}
						a.fixture.session = selected
						fresh = selectActualGeneratedLoss(t, a, loss)
					}
					a.sends++
					var code contract.CryptoResultCode
					result, _, code = a.env.Custody.InvokeGeneratedProducer(dispatchContext, producer.operation.context.AdmissionID, producer.producerLocator, authority)
					return code
				}) {
					t.Fatal("generated successor handoff")
				}
				selected, outcome := a.fixture.session.selectCandidate(ctx, producer.reservation.candidate)
				if selected == nil || outcome.Outcome != ObservedCurrent || len(result) == 0 || a.sends != 2 {
					t.Fatal("generated successor selection", outcome)
				}
				a.env.Custody.RetireGenerated()
				if cut == "transmitted" {
					a.fixture.session = selected
					fresh = selectActualGeneratedLoss(t, a, loss)
				}
				a.expected = expected
				recordAndFinalizeGeneratedActual(t, a, fresh, result, 2, 1)
			})
		}
	}
}

// full_only: false
func TestGeneratedActualReciprocalKEKLossPreservesPendingResult(t *testing.T) {
	for _, order := range [][]generatedActualLoss{
		{generatedActualLosses[1], generatedActualLosses[4]},
		{generatedActualLosses[4], generatedActualLosses[1]},
	} {
		t.Run(order[0].name+"-then-"+order[1].name, func(t *testing.T) {
			a := newGeneratedActualOperation(t, true, custody.StandardValue)
			for index, loss := range order {
				fresh := selectActualGeneratedLoss(t, a, loss)
				control := currentControlOf(a.fixture.session)
				fresh.Trust = &fixtureTrust{Signer: testtrust.NewCurrent(t, control.NormalSigning)}
				fresh.Recovery = testtrust.NewCurrent(t, control.Recovery.Signing)
				if index == 0 && order[1].mask&2 != 0 {
					bindings, err := a.fixture.session.currentBindings()
					if err != nil {
						t.Fatal(err)
					}
					source := contract.BindingTableRow{SubjectKind: 2, SubjectID: control.Recovery.RoleID, Binding: control.Recovery.KMS}
					fresh.Custody, err = custody.NewCurrentReplacement(t, fixtureID(a.fixture.session.admission.domain, "reciprocal recovery source"), control, bindings, source)
					if err != nil {
						t.Fatal(err)
					}
				}
				a.env = fresh
			}
			recordAndFinalizeGeneratedActual(t, a, a.env, a.result, 1, 1)
		})
	}
}

// full_only: false
func TestGeneratedActualLossAtRetirementCuts(t *testing.T) {
	for _, loss := range generatedActualLosses {
		for _, cut := range []string{"transmitted", "unknown", "pending-release"} {
			t.Run(loss.name+"/"+cut, func(t *testing.T) {
				ctx := stdcontext.Background()
				env, _ := genesisEnvironment(t, contract.GCP, true)
				env = syntheticAuthorityScenarioEnvironment(t, env)
				run := newScenarioRun(t, ctx, env)
				f := newEnvironmentFixture(t, ctx, run.env, nil, false)
				selected := selectPrivateGeneratedOperation(t, env, f.session,
					generatedPlanInputForGenerations(t, f.session, generatedVectorID(210), []string{"generated"}, defaultGeneratedFixtureProfile()), "retirement loss initial")
				old := *selected.valueEntry(0)
				profile := defaultGeneratedFixtureProfile()
				profile.ConfigContractID, profile.ResourceContractID = generatedVectorID(211), generatedVectorID(212)
				selected = selectPrivateGeneratedOperation(t, env, selected,
					generatedStatePlanInput(t, selected, generatedVectorID(214), []string{old.Name}, profile, old.Generated.Epoch+1,
						map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: old}), "retirement loss rotation")
				work := mustSelectedGeneratedWork(t, selected)
				current := selected.valueEntry(0)
				row, ok := work.records[generatedRecordKey{kind: 10, id: current.Generated.RetiringDutyID}]
				if !ok {
					t.Fatal("transmitted retirement lacks selected Duty")
				}
				duty, err := contract.InspectGeneratedDutyRecord(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				target, err := work.retirementTarget(t.Context(), duty)
				if err != nil {
					t.Fatal(err)
				}
				input, inputCanonical := generatedDeletePlanInput(t, selected, generatedVectorID(215), duty, target, 2)
				prior, _ := preparePrivateGeneratedReservation(t, env, selected, input, inputCanonical)
				var entered *StateSession
				var frozen *generatedPreparation
				var expected contract.GeneratorResultExpectation
				var packet []byte
				if cut == "pending-release" {
					producer, resultExpected := preparePrivateGeneratedProducer(t, env, selected, prior, nil)
					expected = resultExpected
					calls := 0
					if !producer.reservation.candidate.bindFirstSend(producer, func(ctx stdcontext.Context, authority contract.ID) contract.CryptoResultCode {
						calls++
						var code contract.CryptoResultCode
						packet, _, code = env.Custody.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
						return code
					}) {
						t.Fatal("pending release producer handoff")
					}
					var outcome Result
					entered, outcome = selected.selectCandidate(ctx, producer.reservation.candidate)
					if entered == nil || outcome.Outcome != ObservedCurrent || calls != 1 || len(packet) == 0 {
						t.Fatal("pending release retirement entry", outcome)
					}
					env.Custody.RetireGenerated()
				} else {
					entered, frozen, expected, packet = selectActualGeneratedPacketRecord(t, env, selected, prior, custody.StandardValue, false, nil)
				}
				before := mustSelectedGeneratedWork(t, entered)
				attempt := before.attempts[expected.Template.AttemptID]
				if attempt.record.State != contract.GeneratedEffectTransmitted || len(attempt.result) != 0 {
					t.Fatal("retirement loss cut is not transmitted with an absent inbox")
				}
				f.session, _ = Open(ctx, OpenContext{admission: &entered.admission}, env.Store)
				if f.session == nil {
					t.Fatal("transmitted retirement fresh reopen")
				}
				if cut == "pending-release" {
					recorded := selectFreshGeneratedRecord(t, env.Store.(*memoryStore), f.session, expected.Template.AttemptID, packet)
					env.Custody.RetireGenerated()
					closed := selectControlledRetirementClose(t, ctx, env, recorded, expected.Template.AttemptID)
					closed = generatedLifecycleReopen(t, ctx, closed, env.Store)
					mapping, present := mustSelectedGeneratedWork(t, closed).releases[expected.Template.AttemptID]
					if !present || mapping.release.State != contract.GeneratedReleasePending || mapping.release.SelectedHandoffDigest != contract.Hash(packet) {
						t.Fatal("retirement did not retain the exact pending inbox release")
					}
					f.session = closed
					a := &generatedActualOperation{env: env, fixture: f, sends: 1}
					fresh := selectActualGeneratedLoss(t, a, loss)
					preserved, present := mustSelectedGeneratedWork(t, f.session).releases[expected.Template.AttemptID]
					if !present || preserved != mapping {
						t.Fatal("replacement changed pending inbox release ownership")
					}
					deleteStore := &generatedCleanupDeleteStore{memoryStore: env.Store.(*memoryStore)}
					released := selectActualGeneratedInboxRelease(t, ctx, fresh, f.session, deleteStore, expected.Template.AttemptID, false)
					if _, retained := mustSelectedGeneratedWork(t, released).releases[expected.Template.AttemptID]; retained || a.sends != 1 {
						t.Fatal("current replacement restored a closed effect or retained released inbox")
					}
					checkFreshGeneratedProcess(t, env.Store.(*memoryStore), released)
					return
				}
				if cut == "unknown" {
					facts, err := contract.EncodeGeneratorSafeFacts(generatedUnknownFixtureFacts(expected, generatedTargetEvidence(t, f.session, target)))
					if err != nil {
						t.Fatal(err)
					}
					permit, err := f.session.admitGeneratedRetirementUnknown(stdcontext.Background(), duty.DutyID, facts, generatedPlanInputFixture(t, f.session).context)
					if err != nil {
						t.Fatal("retirement unknown admission", err)
					}
					candidate, prepared := f.session.PrepareGeneratedLifecycle(ctx, permit, env.Trust)
					if candidate == nil || prepared.Outcome != ObservedCurrent {
						t.Fatal("retirement unknown preparation", prepared)
					}
					f.session, prepared = f.session.selectCandidate(ctx, candidate)
					if f.session == nil || prepared.Outcome != ObservedCurrent {
						t.Fatal("retirement unknown selection", prepared)
					}
					parked := mustSelectedGeneratedWork(t, f.session)
					if parked.attempts[expected.Template.AttemptID].record.State != contract.GeneratedEffectUnknown {
						t.Fatal("retirement unknown cut did not retain its original Attempt")
					}
				}
				a := &generatedActualOperation{env: env, fixture: f, sends: 1}
				fresh := selectActualGeneratedLoss(t, a, loss)
				if stale, outcome := entered.selectCandidate(ctx, frozen.reservation.candidate); stale != nil || outcome.Outcome != Contention {
					t.Fatal("retirement Record candidate crossed replacement", outcome)
				}
				if cut == "unknown" {
					parked := mustSelectedGeneratedWork(t, f.session)
					currentDuty, err := contract.InspectGeneratedDutyRecord(parked.records[generatedRecordKey{10, duty.DutyID}].Body)
					if err != nil || parked.attempts[expected.Template.AttemptID].record.State != contract.GeneratedEffectUnknown ||
						currentDuty.Status != contract.GeneratedEffectUnknown {
						t.Fatal("replacement changed original unknown retirement", err)
					}
					permit, err := f.session.admitGeneratedRetirementResidueFixture(duty.DutyID, generatedPlanInputFixture(t, f.session).context)
					if err != nil {
						t.Fatal("current retirement residue admission", err)
					}
					candidate, prepared := f.session.PrepareGeneratedLifecycle(ctx, permit, fresh.Trust)
					if candidate == nil || prepared.Outcome != ObservedCurrent {
						t.Fatal("current retirement residue preparation", prepared)
					}
					closed, outcome := f.session.selectCandidate(ctx, candidate)
					if closed == nil || outcome.Outcome != ObservedCurrent {
						t.Fatal("current retirement residue selection", outcome)
					}
					closed = generatedLifecycleReopen(t, ctx, closed, env.Store)
					final := mustSelectedGeneratedWork(t, closed)
					hazard, err := contract.InspectGeneratedHazardRecord(final.records[generatedRecordKey{11, expected.Template.HazardID}].Body)
					if err != nil || hazard.OwnerID != duty.DutyID || hazard.OriginalAttemptID != expected.Template.AttemptID ||
						closed.root.Generated.Retiring != 0 || closed.root.Generated.Duties != 0 || closed.root.Generated.Hazards != 1 || a.sends != 1 {
						t.Fatal("current authority lost unknown retirement cleanup owner", err)
					}
					if actualTarget, err := final.generatedCleanupTarget(11, hazard.HazardID, hazard.Target); err != nil || actualTarget != target {
						t.Fatal("current authority retargeted unknown retirement cleanup", err)
					}
					checkFreshGeneratedProcess(t, env.Store.(*memoryStore), closed)
					return
				}
				recorded := selectFreshGeneratedRecord(t, env.Store.(*memoryStore), f.session, expected.Template.AttemptID, packet)
				after := mustSelectedGeneratedWork(t, recorded)
				actual := after.attempts[expected.Template.AttemptID]
				if actual.record.AttemptID != attempt.record.AttemptID || actual.record.OperationID != attempt.record.OperationID ||
					actual.record.ResourceID != attempt.record.ResourceID || actual.record.RequestDigest != attempt.record.RequestDigest ||
					actual.record.CompletionClass != attempt.record.CompletionClass ||
					!bytes.Equal(actual.result, packet) {
					t.Fatal("retirement replacement changed original Attempt or result")
				}
				fresh.Custody.RetireGenerated()
				closed := selectControlledRetirementClose(t, ctx, fresh, recorded, expected.Template.AttemptID)
				closed = generatedLifecycleReopen(t, ctx, closed, env.Store)
				if closed.root.Generated.Retiring != 0 || closed.root.Generated.Duties != 0 || closed.root.Generated.Hazards != 0 || a.sends != 1 {
					t.Fatal("current authority failed to close exact transmitted retirement")
				}
				checkFreshGeneratedProcess(t, env.Store.(*memoryStore), closed)
			})
		}
	}
}

// full_only: false
func TestGeneratedActualLateOriginalAfterReplacementAndFence(t *testing.T) {
	for _, loss := range generatedActualLosses {
		for _, previous := range []int{0, 1} {
			t.Run(fmt.Sprintf("%s/previous=%d", loss.name, previous), func(t *testing.T) {
				ctx := stdcontext.Background()
				env, selected, original, packet := generatedAuthenticatedDeleteHazardFixture(t, true, previous)
				env = syntheticAuthorityScenarioEnvironment(t, env)
				before := mustSelectedGeneratedWork(t, selected)
				if before.parent != nil || before.phase != nil || len(before.attempts) != previous+1 ||
					before.attempts[original.record.AttemptID].record != original.record {
					t.Fatal("late original fixture lacks its detached original Attempt")
				}
				f := &environmentFixture{session: selected, admission: OpenContext{admission: &selected.admission}}
				a := &generatedActualOperation{env: env, fixture: f}
				fresh := selectActualGeneratedLoss(t, a, loss)
				replaced := mustSelectedGeneratedWork(t, f.session)
				if replaced.parent != nil || replaced.phase != nil || len(replaced.attempts) != previous+1 ||
					replaced.attempts[original.record.AttemptID].record != original.record {
					t.Fatal("replacement changed detached original Attempt or cleanup owner")
				}
				key, err := format.GeneratedResultKey(env.Store.Descriptor().Prefix, original.record.DomainID, original.record.InboxID)
				if err != nil {
					t.Fatal(err)
				}
				if err := env.Put(ctx, key, bytes.Clone(packet)); err != nil {
					t.Fatal("late original inbox delivery", err)
				}
				if plan, err := f.session.generatedRecordRequest(stdcontext.Background(), original.record.AttemptID, packet,
					generatedPlanInputFixture(t, f.session).context); err == nil || plan != nil {
					t.Fatal("late original escaped detached cleanup through normal Record")
				}
				permit := admitPrivateGeneratedOriginalReflection(t, fresh.Custody, f.session, original.record.ResultID, packet,
					generatedPlanInputFixture(t, f.session).context)
				candidate, result := f.session.PrepareGeneratedLifecycle(ctx, permit, fresh.Trust)
				if candidate == nil || result.Outcome != ObservedCurrent {
					t.Fatal("current authority could not verify original result", result)
				}
				closed, result := f.session.selectCandidate(ctx, candidate)
				if closed == nil || result.Outcome != ObservedCurrent {
					t.Fatal("late original reflection did not close", result)
				}
				closed = generatedLifecycleReopen(t, ctx, closed, env.Store)
				after := mustSelectedGeneratedWork(t, closed)
				if len(after.attempts) != 0 || len(after.releases) != len(before.releases)+previous+1 ||
					closed.root.Generated.Hazards != 0 || !closed.root.Generated.ActiveOwner.IsZero() {
					t.Fatal("late original reflection retained cleanup ownership")
				}
				for id, old := range before.attempts {
					release, ok := after.releases[id]
					mapped := old.record
					if id == original.record.AttemptID {
						mapped.State = contract.GeneratedEffectSucceeded
						mapped.Facts = contract.EmptyGeneratorVector(contract.GeneratorVectorFacts)
						mapped.Progress = contract.EmptyGeneratorVector(contract.GeneratorVectorProgress)
						mapped.History = contract.EmptyGeneratorVector(contract.GeneratorVectorHistory)
					}
					if !ok || release.attempt != mapped || release.template != old.expected.Template {
						t.Fatal("late original reflection changed Attempt or target")
					}
					if id == original.record.AttemptID {
						if release.release.State != contract.GeneratedReleasePending || release.release.ObjectLength != uint32(len(packet)) {
							t.Fatal("original result did not retain exact pending release")
						}
					} else if release.release.State != contract.GeneratedReleaseUnobserved || release.release.ObjectLength != 0 {
						t.Fatal("later invocation acquired fabricated acknowledgement")
					}
				}
				checkFreshGeneratedProcess(t, env.Store.(*memoryStore), closed)
			})
		}
	}
}

func generatedActualRefusalState(t *testing.T, recovery bool, recorded bool) *generatedActualOperation {
	t.Helper()
	a := newGeneratedActualOperation(t, recovery, custody.StandardValue)
	if recorded {
		a.fixture.session = selectFreshGeneratedRecord(t, a.env.Store.(*memoryStore), a.fixture.session, a.expected.Template.AttemptID, a.result)
	}
	return a
}

// full_only: false
func TestGeneratedActualRecoveryDisabledRefusesBeforeEffect(t *testing.T) {
	for _, recorded := range []bool{false, true} {
		t.Run(fmt.Sprintf("recorded-%t", recorded), func(t *testing.T) {
			a := generatedActualRefusalState(t, false, recorded)
			s := a.fixture.session
			beforeBody, beforeToken := bytes.Clone(s.body), s.token
			store := a.env.Store.(*memoryStore)
			creates, cas := store.creates, store.cas
			public, private := a.env.Custody.Calls()
			after := currentControlOf(s)
			if after.Recovery != nil {
				t.Fatal("disabled recovery fixture contains recovery control")
			}
			after.AccessGeneration++
			request, plan, admitted := s.planSuccession(t.Context(), after, 3, contract.NormalSigningRole, 8,
				fixtureID(a.env.Domain, "disabled generated actual recovery"), contract.SuccessionMaterialAuthority)
			if admitted || request.OperationID.IsZero() || request.ChangeMask != 8 || request.BeforeControl.Recovery != nil {
				t.Fatal("disabled generated recovery crossed capability admission")
			}
			if _, err := contract.SuccessionRequestDescriptor(request); err == nil {
				t.Fatal("disabled generated recovery produced a valid descriptor")
			}
			permit := &AdmittedSuccession{session: s, request: request, plan: plan}
			candidate, result := s.PrepareSuccession(stdcontext.Background(), permit, SuccessionSigners{Authorizer: a.env.Trust})
			if candidate != nil || result != refused(AdmissionInvalid) || permit.used || s.prepared {
				t.Fatal("disabled generated recovery did not refuse before preparation", result)
			}
			if store.creates != creates || store.cas != cas || !bytes.Equal(s.body, beforeBody) || s.token != beforeToken {
				t.Fatal("disabled generated recovery changed durable state")
			}
			if p, k := a.env.Custody.Calls(); p != public || k != private {
				t.Fatal("disabled generated recovery entered custody", p-public, k-private)
			}
			if body, receipt := s.MutationReceipt(stdcontext.Background(), request.OperationID); body != nil || receipt != refused(AdmissionInvalid) {
				t.Fatal("disabled generated recovery fabricated evidence", receipt)
			}
			checkFreshGeneratedProcess(t, store, s)
		})
	}
}

// full_only: false
func TestGeneratedActualAllUnsealingPathsLostRefusesBeforeEffect(t *testing.T) {
	for _, recorded := range []bool{false, true} {
		t.Run(fmt.Sprintf("recorded-%t", recorded), func(t *testing.T) {
			a := generatedActualRefusalState(t, true, recorded)
			s := a.fixture.session
			store := a.env.Store.(*memoryStore)
			beforeBody, beforeToken := bytes.Clone(s.body), s.token
			beforeWork, err := s.preservedWorkSupportRecords(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			actors := a.env.ReplacementActors(t, stdcontext.Background(), s, 1, 2, contract.RecoverySigningRole)
			permit := admitAuthorityReplacement(t, s, actors.Keys, actors.After, 1, contract.RecoverySigningRole, 2, actors.Source)
			creates, cas := store.creates, store.cas
			a.env.Custody.SetUnavailable(true)
			candidate, result := s.PrepareSuccession(stdcontext.Background(), permit, actors.Signers)
			a.env.Custody.SetUnavailable(false)
			if candidate != nil || result != failure(EvidenceUnavailable, CustodyUnavailable) {
				t.Fatal("all generated unsealing paths lost did not refuse", result)
			}
			if store.creates != creates || store.cas != cas || !bytes.Equal(s.body, beforeBody) || s.token != beforeToken {
				t.Fatal("all generated unsealing paths lost changed durable state")
			}
			afterWork, err := s.preservedWorkSupportRecords(t.Context())
			if err != nil || !reflect.DeepEqual(beforeWork, afterWork) {
				t.Fatal("all generated unsealing paths lost changed accepted work", err)
			}
			if body, receipt := s.MutationReceipt(stdcontext.Background(), permit.request.OperationID); body != nil || receipt != refused(AdmissionInvalid) {
				t.Fatal("all generated unsealing paths lost fabricated evidence", receipt)
			}
			checkFreshGeneratedProcess(t, store, s)
		})
	}
}

// full_only: false
func TestGeneratedActualLossInvalidatesFrozenFinalCandidate(t *testing.T) {
	for _, loss := range generatedActualLosses {
		t.Run(loss.name, func(t *testing.T) {
			a := newGeneratedActualOperation(t, loss.recovery, custody.StandardValue)
			store := a.env.Store.(*memoryStore)
			recorded := selectFreshGeneratedRecord(t, store, a.fixture.session, a.expected.Template.AttemptID, a.result)
			finalContext := generatedPlanInputFixture(t, recorded).context
			finalContext.AdmissionID = fixtureID(recorded.admission.domain, "frozen loss final admission")
			finalContext.SessionID = fixtureID(recorded.admission.domain, "frozen loss final session")
			plan, err := recorded.generatedFinalRequest(t.Context(), finalContext)
			if err != nil {
				t.Fatal(err)
			}
			recorded, frozen := preparePrivateGeneratedFinal(t, a.env, recorded, plan)
			frozenBody := bytes.Clone(frozen.reservation.candidate.body)
			current, outcome := Open(stdcontext.Background(), OpenContext{admission: &recorded.admission}, store)
			if current == nil || outcome.Outcome != ObservedCurrent {
				t.Fatal("frozen generated loss reopen", outcome)
			}
			a.fixture.session = current
			fresh := selectActualGeneratedLoss(t, a, loss)
			if stale, result := recorded.selectCandidate(stdcontext.Background(), frozen.reservation.candidate); stale != nil || result.Outcome != Contention ||
				result.Reason != StalePrecondition || !bytes.Equal(frozenBody, frozen.reservation.candidate.body) {
				t.Fatal("frozen final candidate rebased across key loss", result)
			}
			finalContext = generatedPlanInputFixture(t, a.fixture.session).context
			finalContext.AdmissionID = fixtureID(a.fixture.session.admission.domain, "fresh loss final admission")
			finalContext.SessionID = fixtureID(a.fixture.session.admission.domain, "fresh loss final session")
			plan, err = a.fixture.session.generatedFinalRequest(t.Context(), finalContext)
			if err != nil {
				t.Fatal(err)
			}
			finalBase, prepared := preparePrivateGeneratedFinal(t, fresh, a.fixture.session, plan)
			closed, result := finalBase.selectCandidate(stdcontext.Background(), prepared.reservation.candidate)
			if closed == nil || result.Outcome != ObservedCurrent || a.sends != 1 {
				t.Fatal("fresh final after generated loss", result)
			}
			checkFreshGeneratedProcess(t, store, closed)
		})
	}
}

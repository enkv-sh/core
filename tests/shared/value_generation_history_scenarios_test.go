package core

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	"enkv.sh/crypto/testsupport/custody"
)

type generatedHistoryFixture struct {
	run        *scenarioRun
	state      *environmentFixture
	casePlan   catalog.GeneratedHistoryCase
	producer   *generatedScenarioProducer
	inputs     generatedScenarioInputs
	result     []byte
	intent     []byte
	request    []byte
	source     contract.ID
	seed       contract.ID
	reader     contract.ID
	current    contract.ValueEntry
	currentRaw []byte
}

func enterGeneratedHistory(t testing.TB, h *generatedHistoryFixture) {
	t.Helper()
	input, canonical := generatedHistoryInput(t, h)
	h.inputs = captureGeneratedScenarioInputs(t, input, contract.ID{})
	h.seed = h.inputs.expected.Plan.MaterialID
	h.producer = mustPrepareGeneratedScenarioProducer(t, h.run.env, h.state.session, input, canonical, h.inputs)
	selected, outcome := h.producer.selectCandidate(h.run.ctx, h.state.session)
	var sends int
	h.result, sends = h.producer.observation()
	if selected == nil || outcome.Outcome != ObservedCurrent || sends != 1 || len(h.result) == 0 {
		t.Fatal("generated history first-send selection", outcome)
	}
	h.state.session = selected
	retained, err := observeGeneratedRetention(selected)
	if err != nil || !retained.active || retained.material != h.seed || !retained.seedAccess {
		t.Fatal("generated history selected seed owner or current reader", err)
	}
	h.run.env.Custody.RetireGenerated()
}

func assertGeneratedHistory(t testing.TB, h *generatedHistoryFixture, recorded bool) {
	t.Helper()
	s := h.state.session
	retained, err := observeGeneratedRetention(s)
	if err != nil || !retained.active || !retained.phased {
		t.Fatal("generated history selected work", err)
	}
	if h.seed.IsZero() || retained.material != h.seed || retained.operation != h.inputs.expected.Plan.OperationID {
		t.Fatal("generated history changed its seed owner")
	}
	if !retained.seedAccess {
		t.Fatal("generated history released the seed before its last consumer")
	}
	a, err := observeGeneratedAttempt(h.run.ctx, s, h.inputs.expected.Template.AttemptID)
	wantState, wantStage := uint8(contract.GeneratedEffectTransmitted), uint8(contract.GeneratedStageRetainedResult)
	if recorded {
		wantState, wantStage = contract.GeneratedEffectSucceeded, contract.GeneratedStageTerminal
	}
	_, sends := h.producer.observation()
	if err != nil || !a.present || a.expected != h.inputs.expected || a.record.State != wantState || a.record.Stage != wantStage ||
		h.inputs.expected.RequestDigest != hermeticCloudflareHTTPRequestDigest(h.request) || sends != 1 {
		t.Fatal("generated history changed its original attempt", err)
	}
	if recorded && !bytes.Equal(a.result, h.result) || !recorded && len(a.result) != 0 {
		t.Fatal("generated history result state differs")
	}
	if !bytes.Equal(a.intent, h.intent) {
		t.Fatal("generated history did not retain the native Cloudflare intent")
	}
	if body, code := h.producer.replay(h.run.ctx); code == contract.CryptoSuccess || len(body) != 0 {
		t.Fatal("generated history restored first-send authority")
	}
	if _, sends := h.producer.observation(); sends != 1 {
		t.Fatal("generated history repeated its first-send handoff")
	}
	if !slices.Equal(retained.sources, h.inputs.sources) || !slices.Equal(retained.entryPlans, h.inputs.entryPlans) {
		t.Fatal("generated history changed its declared source or intended entries")
	}
	if h.casePlan.SourceMode == 1 {
		if len(retained.sources) != 1 || retained.sources[0].SourceID != h.source ||
			!slices.Equal(retained.protectedSources, []contract.ID{h.source}) {
			t.Fatal("generated history sealed source protection is incomplete")
		}
		wantConsumer, err := contract.GeneratorAcceptedSourceConsumer(h.inputs.expected.Plan.OperationID, h.seed, h.inputs.sources[0])
		if err != nil || !slices.Contains(retained.consumers, wantConsumer) {
			t.Fatal("generated history sealed source consumer is incomplete", err)
		}
	}
	if h.casePlan.SourceMode != 2 {
		if retained.canonicalCount != 0 {
			t.Fatal("generated history invented a retained canonical source")
		}
		return
	}
	if retained.canonicalCount != 1 {
		t.Fatal("generated history lost its retained canonical source")
	}
	acting := h.reader
	if h.casePlan.Union {
		acting = s.admission.recipient
	}
	selection, outcome := selectGeneratedScenarioConsumer(h.run.ctx, s, contract.GeneratedDutySupportKind, h.inputs.expected.Template.DutyID, h.source, acting)
	if outcome.Outcome != ObservedCurrent {
		t.Fatal("generated history retained owner admission", outcome)
	}
	check := h.run.env.Custody.ConsumeGenerated(h.run.ctx, selection, custody.StandardValue)
	if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched || check.SinkCalls != 1 ||
		len(check.KeyUses) != 1 || check.KeyUses[0].SubjectID != acting {
		t.Fatal("generated history retained owner used another route", check)
	}
	if h.casePlan.Union {
		if denied, outcome := selectGeneratedScenarioConsumer(h.run.ctx, s, contract.GeneratedDutySupportKind, h.inputs.expected.Template.DutyID, h.source, h.reader); outcome != refused(AdmissionInvalid) || !reflect.DeepEqual(denied, contract.GeneratedCanonicalSelection{}) {
			t.Fatal("current-only reader gained generated source authority", outcome)
		}
		if admitted, outcome := s.admitConsumerSelection(h.run.ctx, []string{"secret"}, h.reader); admitted != nil || outcome != refused(AdmissionInvalid) {
			t.Fatal("planned current-only reader became active before Final", outcome)
		}
		want := []contract.ID{s.admission.recipient, h.reader}
		slices.SortFunc(want, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		membership, membershipErr := contract.GeneratorIntendedMembershipDescriptor(want)
		entryPlanIndex := slices.IndexFunc(retained.entryPlans, func(row contract.GeneratorValueEntryPlan) bool { return row.Name == "secret" })
		if membershipErr != nil || entryPlanIndex < 0 || retained.entryPlans[entryPlanIndex].IntendedMembership != membership {
			t.Fatal("generated history did not fix the current reader union", membershipErr)
		}
	} else {
		current := sessionConsumerSelection(t, s, h.reader, "secret")
		check = h.run.env.Custody.Consume(h.run.ctx, current, custody.StandardValue)
		if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched || check.SinkCalls != 1 {
			t.Fatal("original retained reader lost current material", check)
		}
	}
}

func selectGeneratedHistoryReplacement(t testing.TB, h *generatedHistoryFixture, generation int) {
	t.Helper()
	beforeSession := h.state.session
	before := currentControlOf(beforeSession)
	beforeImage := observeSelectedState(t, beforeSession)
	stages := [][3]uint8{
		{1, 3, contract.RecoverySigningRole},
		{3, 12, contract.NormalSigningRole},
		{1, 2, contract.RecoverySigningRole},
		{3, 8, contract.NormalSigningRole},
	}
	operation, mask, approval := stages[generation][0], stages[generation][1], stages[generation][2]
	var retired contract.Trust
	var targetRole uint8
	if mask&1 != 0 {
		retired, targetRole = h.run.env.Trust, contract.SuccessorNormalSigner
		if tracked, ok := retired.(scenarioTrust); ok {
			retired = tracked.Trust
		}
	} else if mask&4 != 0 {
		retired, targetRole = h.run.env.Recovery, contract.SuccessorRecoverySigner
	}
	lost := before.AuthorityKMSBinding
	if mask&8 != 0 {
		lost = before.Recovery.KMS
	}
	work, err := observePreservedGeneratedSupport(h.run.ctx, beforeSession)
	if err != nil {
		t.Fatal("generated history predecessor work", err)
	}
	actors := h.run.env.ReplacementActors(t, h.run.ctx, beforeSession, operation, mask, approval)
	permit := admitAuthorityReplacement(t, beforeSession, actors.Keys, actors.After, operation, approval, mask, actors.Source)
	candidate, outcome := beforeSession.PrepareSuccession(h.run.ctx, permit, actors.Signers)
	if candidate == nil || outcome.Outcome != ObservedCurrent {
		t.Fatal("generated history replacement preparation", outcome)
	}
	admission := deliverSuccessionBasis(t, candidate)
	if outcome = beforeSession.Select(h.run.ctx, candidate); outcome.Outcome != ObservedCurrent {
		t.Fatal("generated history replacement selection", outcome)
	}
	actors.Keys.RetireAccess()
	selected, outcome := Open(h.run.ctx, admission, h.run.env.Store)
	if selected == nil || outcome.Outcome != ObservedCurrent {
		t.Fatal("generated history replacement reopen", outcome)
	}
	actors.Activate(t, selected)
	if retired != nil {
		probe, probeErr := probeGeneratedRetiredSigner(h.run.ctx, retired, permit, actors.After, targetRole,
			fixtureID(actors.After.DomainID, fmt.Sprintf("generated history retired signer %d", generation)))
		if probeErr != nil || probe.Reason != contract.ReasonAccess {
			t.Fatal("generated history retained a lost signer route", probeErr)
		}
	}
	afterImage := observeSelectedState(t, selected)
	afterWork, err := observePreservedGeneratedSupport(h.run.ctx, selected)
	if err != nil || !reflect.DeepEqual(work, afterWork) || !reflect.DeepEqual(beforeImage.Pages, afterImage.Pages) ||
		!reflect.DeepEqual(beforeImage.Root.ValueEntryPages, afterImage.Root.ValueEntryPages) || !reflect.DeepEqual(beforeImage.Root.Names, afterImage.Root.Names) {
		t.Fatal("generated history replacement changed accepted work or current members", err)
	}
	if operation != 1 {
		checkSuccessionReceipt(t, h.run.ctx, selected, permit)
	}
	h.state.admission, h.state.session = admission, selected
	if actors.Signers.NormalSuccessor != nil {
		h.run.env.Trust = scenarioTrust{Trust: actors.Signers.NormalSuccessor, spy: h.run.spy}
	}
	if actors.Signers.RecoverySuccessor != nil {
		h.run.env.Recovery = actors.Signers.RecoverySuccessor
	}
	after := currentControlOf(h.state.session)
	wantSerials := [][2]uint64{{2, 1}, {2, 2}, {3, 2}, {3, 3}}
	wantEpochs := [][2]uint64{{2, 1}, {2, 2}, {2, 2}, {2, 2}}
	if after.AuthorityKMSBinding.BindingSerial != wantSerials[generation][0] || after.Recovery.KMS.BindingSerial != wantSerials[generation][1] ||
		after.NormalSigning.Binding.Epoch != wantEpochs[generation][0] || after.Recovery.Signing.Binding.Epoch != wantEpochs[generation][1] {
		t.Fatal("generated history activated a different current successor", after.AuthorityKMSBinding.BindingSerial, after.Recovery.KMS.BindingSerial)
	}
	if witness := h.run.env.Custody.PrivateWitness(h.run.ctx, lost.BindingID, lost, lost); witness != (custody.RouteWitness{Outcome: contract.CryptoInvalidAdmission}) {
		t.Fatal("generated history retained a lost private route", witness)
	}
	current := after.AuthorityKMSBinding
	if mask&8 != 0 {
		current = after.Recovery.KMS
	}
	if witness := h.run.env.Custody.PrivateWitness(h.run.ctx, current.BindingID, current, current); witness != (custody.RouteWitness{Outcome: contract.CryptoSuccess, Completed: 1}) {
		t.Fatal("generated history successor route is not active", witness)
	}
}

func assertGeneratedHistoryClosed(t testing.TB, h *generatedHistoryFixture) {
	t.Helper()
	s := h.state.session
	state := observeSelectedState(t, s)
	retained, err := observeGeneratedRetention(s)
	_, sends := h.producer.observation()
	if err != nil || retained.active || retained.phased || !state.Root.Generated.ActiveOwner.IsZero() || state.Root.Generated.GeneratedCurrent != 1 || sends != 1 {
		t.Fatal("generated history final did not close exactly once")
	}
	if _, present := observeMaterialAccess(s, contract.OperationSeedMaterialKind, h.seed); present {
		t.Fatal("generated history final retained the last completed seed reader")
	}
	wantEntryCount := uint32(1)
	if h.casePlan.SourceMode != 0 {
		wantEntryCount = 2
	}
	if state.Root.ValueEntryCount != wantEntryCount {
		t.Fatal("generated history final member set differs", state.Root.ValueEntryCount, wantEntryCount)
	}
	if h.casePlan.SourceMode == 2 {
		_, current := observeCurrentValueEntry(t, s, "secret")
		body, err := contract.EncodeValueEntry(current)
		if err != nil {
			t.Fatal("generated history final current source", err)
		}
		if h.casePlan.Union {
			want := []contract.ID{s.admission.recipient, h.reader}
			slices.SortFunc(want, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			if current.ValueState != h.source || !slices.Equal(current.Recipients, want) || bytes.Equal(body, h.currentRaw) {
				t.Fatal("generated history final lost its same-value reader union")
			}
			selection := sessionConsumerSelection(t, s, h.reader, "secret")
			check := h.run.env.Custody.Consume(h.run.ctx, selection, custody.StandardValue)
			if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched || check.SinkCalls != 1 {
				t.Fatal("generated history final reader union is unusable", check)
			}
		} else if !bytes.Equal(body, h.currentRaw) || !reflect.DeepEqual(current, h.current) {
			t.Fatal("generated history final replaced the current source", err)
		}
	}
}

type generatedHistoryGrantEvidence struct {
	attempt generatedAttemptObservation
	access  contract.AccessRecord
}

func captureGeneratedHistoryGrantEvidence(t testing.TB, h *generatedHistoryFixture) generatedHistoryGrantEvidence {
	t.Helper()
	if !h.casePlan.Union {
		return generatedHistoryGrantEvidence{}
	}
	attempt, err := observeGeneratedAttempt(h.run.ctx, h.state.session, h.inputs.expected.Template.AttemptID)
	state := observeSelectedState(t, h.state.session)
	if err != nil || !attempt.present || attempt.expected != h.inputs.expected ||
		attempt.record.State != contract.GeneratedEffectSucceeded || attempt.record.Stage != contract.GeneratedStageTerminal ||
		!bytes.Equal(attempt.result, h.result) || state.Root.Generated.Attempts != 1 || state.Root.Generated.Retiring != 0 {
		t.Fatal("grant receipt requires the one original successful create", err)
	}
	access, present := observeMaterialAccess(h.state.session, contract.ValueMaterialKind, h.source)
	if !present || !slices.Equal(scenarioAccessRecipients(access), h.current.Recipients) {
		t.Fatal("retained supplied source lost its prior access")
	}
	return generatedHistoryGrantEvidence{attempt: attempt, access: access}
}

func assertGeneratedHistoryGrantReceipt(t testing.TB, h *generatedHistoryFixture, before generatedHistoryGrantEvidence) {
	t.Helper()
	if !h.casePlan.Union {
		return
	}
	operation := h.inputs.expected.Plan.OperationID
	selectedBody, selectedResult := h.state.session.MutationReceipt(h.run.ctx, operation)
	cold, result := Open(h.run.ctx, OpenContext{admission: &h.state.session.admission}, h.run.env.Store)
	if cold == nil || result.Outcome != ObservedCurrent {
		t.Fatal("grant receipt cold open", result)
	}
	state := observeSelectedState(t, cold)
	current, present := observeMaterialAccess(cold, contract.ValueMaterialKind, h.source)
	wantReaders := append(slices.Clone(h.current.Recipients), h.reader)
	slices.SortFunc(wantReaders, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	if !present || current.MaterialID != before.access.MaterialID || current.MaterialContextDigest != before.access.MaterialContextDigest ||
		!slices.Equal(scenarioAccessRecipients(current), wantReaders) {
		t.Fatal("retained supplied source lost its selected reader grant")
	}
	changed, err := contract.AccessChangeDescriptor(state.Root.Domain, []contract.AccessChangeRow{{Before: before.access, After: current}})
	if err != nil || changed.Count != 1 {
		t.Fatal("retained supplied grant descriptor", err, changed)
	}
	body, receiptResult := cold.MutationReceipt(h.run.ctx, operation)
	receipt, err := contract.InspectCompactMutationReceipt(body)
	wantCounts := [12]uint32{contract.ReceiptEffectCount: 1, contract.ReceiptChangedAccessCount: 1, contract.ReceiptSummarySuccessCount: 1}
	if selectedResult.Outcome != ObservedCurrent || receiptResult.Outcome != ObservedCurrent || !bytes.Equal(selectedBody, body) || err != nil ||
		receipt.OperationID != operation || receipt.OperationKind != h.inputs.request.OperationKind || receipt.DomainID != h.inputs.request.DomainID ||
		receipt.PredecessorRevisionID != h.inputs.request.PredecessorRevisionID || receipt.RequestedRevisionID != state.Revision || receipt.ObservedRevisionID != state.Revision ||
		receipt.StateResult != 1 || receipt.CanonicalOutcome != 1 || receipt.EffectSummary != 2 || receipt.OutputSummary != 0 ||
		receipt.EvidenceCeiling != contract.ReceiptEvidenceProviderFacts || receipt.WarningBits != 0 || receipt.SummaryCounts != wantCounts ||
		receipt.AcknowledgedCount != 0 || receipt.ConfirmedCount != 0 || receipt.UnknownCount != 0 ||
		state.Root.Generated.Duties != 0 || state.Root.Generated.Hazards != 0 || state.Root.Generated.Retiring != 0 {
		t.Fatal("cold generated Final receipt changed the one-success grant outcome", receiptResult, err)
	}
	// This relation commits the independently checked original Attempt and
	// reader grant. It does not ask Final to select its own expected rows.
	attemptBody, err := contract.EncodeGeneratedAttemptRecord(before.attempt.record)
	if err != nil {
		t.Fatal("generated receipt original attempt", err)
	}
	effects, err := contract.MutationResultRecordDescriptor(contract.MutationResultEffects, state.Root.Domain,
		[]contract.SupportRecord{{Kind: contract.GeneratedAttemptSupportKind, RecordID: h.inputs.expected.Template.AttemptID, Body: attemptBody}})
	if err != nil {
		t.Fatal("generated receipt effect descriptor", err)
	}
	projection := contract.CompactMutationReceiptPlan(receipt)
	projection.RequestIdentityDigest, projection.CompleteResult = contract.ID{}, contract.GeneratorDescriptor{}
	empty := contract.EmptyMutationResultDescriptors()
	complete, err := contract.CompleteMutationResultDescriptor(contract.MutationResultProjection{Receipt: projection,
		RequestCoreDigest: h.inputs.requestCoreDigest, ChangedAccess: changed, Effects: effects,
		Outputs: empty[2], Duties: empty[3], Hazards: empty[4]})
	if err != nil || receipt.CompleteResult != complete {
		t.Fatal("cold generated Final receipt changed the retained grant digest", err)
	}
}

func runGeneratedHistoryScenario(t testing.TB, ctx context.Context, env fixtureEnvironment, c catalog.GeneratedHistoryCase) {
	t.Helper()
	if env.Custody == nil || env.FreshCurrent == nil || env.FreshGeneratedRecord == nil || env.FreshGeneratedFinal == nil || c.Reciprocal && env.ReplacementActors == nil {
		t.Fatal("generated history callbacks are incomplete")
	}
	run := newScenarioRun(t, ctx, env)
	h := &generatedHistoryFixture{run: run, casePlan: c, reader: fixtureID(env.Domain, "reader")}
	h.intent, h.request = hermeticCloudflareIntent()
	run.phase("setup", func() { h.state = newEnvironmentFixture(t, ctx, run.env, nil, false) })
	run.phase("transition", func() { enterGeneratedHistory(t, h) })
	if !c.Reciprocal {
		run.phase("verification", func() { assertGeneratedHistory(t, h, false) })
		run.phase("transition", func() {
			h.state.session = run.env.FreshGeneratedRecord(t, h.state.session, h.inputs.expected.Template.AttemptID, h.result)
		})
		run.phase("verification", func() { assertGeneratedHistory(t, h, true) })
		run.phase("reopen", func() { run.env.FreshCurrent(t, OpenContext{admission: &h.state.session.admission}, h.state.session) })
		beforeFinal := captureGeneratedHistoryGrantEvidence(t, h)
		run.phase("transition", func() { h.state.session = run.env.FreshGeneratedFinal(t, h.state.session) })
		run.phase("verification", func() {
			assertGeneratedHistoryClosed(t, h)
			assertGeneratedHistoryGrantReceipt(t, h, beforeFinal)
		})
		run.phase("reopen", func() { run.env.FreshCurrent(t, OpenContext{admission: &h.state.session.admission}, h.state.session) })
		return
	}
	var frozen *generatedScenarioFinal
	var frozenBefore generatedFinalObservation
	for generation := 0; generation < 4; generation++ {
		if generation == 2 {
			run.phase("transition", func() {
				h.state.session = run.env.FreshGeneratedRecord(t, h.state.session, h.inputs.expected.Template.AttemptID, h.result)
				assertGeneratedHistory(t, h, true)
				frozen = mustPrepareGeneratedScenarioFinal(t, run.env, h.state.session,
					fixtureID(env.Domain, "generated history frozen final admission"), fixtureID(env.Domain, "generated history frozen final session"))
				frozenBefore = frozen.observation()
				run.env.Custody.RetireGenerated()
				fresh, outcome := Open(ctx, h.state.admission, run.env.Store)
				if fresh == nil || outcome.Outcome != ObservedCurrent {
					t.Fatal("generated history independent replacement open", outcome)
				}
				h.state.session = fresh
			})
		}
		run.phase("transition", func() {
			selectGeneratedHistoryReplacement(t, h, generation)
			if generation == 2 {
				selectedBody := observeSelectedHead(h.state.session)
				selected, outcome := frozen.selectCandidate(ctx)
				after := frozen.observation()
				if selected != nil || outcome.Outcome != Contention || outcome.Reason != StalePrecondition ||
					after.condition != frozenBefore.condition || !bytes.Equal(after.body, frozenBefore.body) {
					t.Fatal("generated history stale final changed its original condition", outcome)
				}
				read := readSelectedHead(ctx, h.state.session)
				_, sends := h.producer.observation()
				if read.Status != contract.ReadOK || !bytes.Equal(read.Body, selectedBody) || sends != 1 {
					t.Fatal("generated history stale final changed selected state or effect count")
				}
			}
		})
		run.phase("verification", func() { assertGeneratedHistory(t, h, generation >= 2) })
		run.phase("reopen", func() { run.env.FreshCurrent(t, OpenContext{admission: &h.state.session.admission}, h.state.session) })
	}
	run.phase("transition", func() { h.state.session = run.env.FreshGeneratedFinal(t, h.state.session) })
	run.phase("verification", func() { assertGeneratedHistoryClosed(t, h) })
	run.phase("reopen", func() { run.env.FreshCurrent(t, OpenContext{admission: &h.state.session.admission}, h.state.session) })
}

// full_only: false
func TestGeneratedRetainedSuppliedGrantFinalReceipt(t *testing.T) {
	runStateScenario(t, t.Context(), memoryScenarioEnvironmentMode(t, true), "accepted.same-value-reader-union/source2_late_result_reader_union")
}

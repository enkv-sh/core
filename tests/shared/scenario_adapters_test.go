package core

import (
	"bytes"
	"context"
	"maps"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// allocatedTransitionInputs is the test-owned input identity record used by
// independent expectations. It contains no candidate records or references.
type allocatedTransitionInputs struct {
	revision, operation, snapshot, transition contract.ID
	valueEntryPages                           [contract.MaxValueEntryPages]contract.ID
	recipientPages                            [contract.MaxRecipientPages]contract.ID
	accessPages                               [contract.MaxChildPages]contract.ID
	supportPages                              [contract.MaxChildPages]contract.ID
	values, incarnations                      map[uint16]contract.ID
}

func captureAllocatedTransitionInputs(plan transitionPlan) allocatedTransitionInputs {
	return allocatedTransitionInputs{
		revision: plan.revision, operation: plan.operation, snapshot: plan.snapshot, transition: plan.transition,
		valueEntryPages: plan.pages, recipientPages: plan.recipientPages, accessPages: plan.accessPages, supportPages: plan.supportPages,
		values: maps.Clone(plan.values), incarnations: maps.Clone(plan.incarnations),
	}
}

func observeAllocatedTransitionInputs(permit *AdmittedParentTransition) allocatedTransitionInputs {
	if permit == nil {
		return allocatedTransitionInputs{}
	}
	return captureAllocatedTransitionInputs(permit.plan)
}

// admitTransition is compiled only into Core tests. It returns the production
// permit separately from the owned identity inputs used by expectations.
func admitTransition(t testing.TB, s *StateSession, c *Comparison) (*AdmittedParentTransition, allocatedTransitionInputs) {
	t.Helper()
	plan, err := planTransition(t.Context(), c)
	if err != nil {
		t.Fatal("identity generation")
	}
	inputs := captureAllocatedTransitionInputs(plan)
	if c.operation != nil {
		if result := s.prepareCompared(context.Background(), c, plan); result.Outcome != 0 {
			t.Fatal("prepare admitted encrypted value", result)
		}
	}
	authority, err := s.lifecycleAuthority(t.Context(), c, plan)
	if err != nil {
		t.Fatal("build admitted authority")
	}
	permit := &AdmittedParentTransition{session: s, comparison: c, predecessorDigest: contract.Hash(s.body), predecessorRevision: s.head.Core.Revision, predecessorToken: s.token, plan: plan, authority: authority}
	return permit, inputs
}

func observeSelectedState(t testing.TB, session *StateSession) stateImage {
	t.Helper()
	return sessionStateImage(t, session)
}

// These inputs are captured before reservation. Selected facts must agree with
// them; preparation and observation cannot supply their own expected Attempt.
type generatedScenarioInputs struct {
	expected          contract.GeneratorResultExpectation
	request           contract.GeneratorRequestCore
	requestCoreDigest contract.ID
	sources           []contract.GeneratorSourceUse
	entryPlans        []contract.GeneratorValueEntryPlan
	declaration       []byte
}

func captureGeneratedScenarioInputs(t testing.TB, input generatedPlanInput, targetResource contract.ID) generatedScenarioInputs {
	t.Helper()
	if len(input.requestBindings) != 1 {
		t.Fatal("generated scenario requires one original request binding")
	}
	binding := input.requestBindings[0]
	lineage := slices.IndexFunc(input.graph.Lineages, func(row contract.GeneratorLineageTemplate) bool {
		return row.LineageID == binding.LineageID
	})
	if lineage < 0 || input.graph.Lineages[lineage].TemplateCount == 0 {
		t.Fatal("generated scenario input omits the original request lineage")
	}
	template := input.graph.Lineages[lineage].Templates[0]
	use := slices.IndexFunc(input.graph.ResultUses, func(row contract.GeneratorResultUse) bool { return row.AttemptID == binding.AttemptID })
	if template.AttemptID != binding.AttemptID || use < 0 {
		t.Fatal("generated scenario input omits the original request template or result")
	}
	inputEncoding := uint8(contract.InputEncodingRaw)
	if template.Action == contract.GeneratorActionCreate {
		index := slices.IndexFunc(input.graph.ValueEntryPlans, func(row contract.GeneratorValueEntryPlan) bool {
			return row.EntryIncarnationID == input.graph.Lineages[lineage].EntryIncarnationID
		})
		if index < 0 {
			t.Fatal("generated scenario input omits the owning entry plan")
		}
		inputEncoding = input.graph.ValueEntryPlans[index].InputEncoding
	}
	return generatedScenarioInputs{
		expected: contract.GeneratorResultExpectation{InputEncoding: inputEncoding, Plan: input.graph.UsePlan, Template: template,
			Use: input.graph.ResultUses[use], RequestDigest: binding.Digest, TargetResourceDigest: targetResource},
		request: input.graph.Request, requestCoreDigest: input.graph.Header.RequestCoreDigest,
		sources: slices.Clone(input.graph.SourceUses), entryPlans: slices.Clone(input.graph.ValueEntryPlans), declaration: bytes.Clone(input.declaration),
	}
}

type generatedAttemptObservation struct {
	present  bool
	record   contract.GeneratedAttemptRecord
	expected contract.GeneratorResultExpectation
	result   []byte
	intent   []byte
}

func observeGeneratedAttempt(ctx context.Context, session *StateSession, attempt contract.ID) (generatedAttemptObservation, error) {
	work, err := session.selectedGeneratedWork(ctx)
	if err != nil {
		return generatedAttemptObservation{}, err
	}
	row, present := work.attempts[attempt]
	if !present {
		return generatedAttemptObservation{}, nil
	}
	intent, err := work.readSelectedSlice(ctx, contract.GeneratorContentIntent, row.expected.Template.IntentDigest, contract.GeneratorIntentMaxLength)
	if err != nil {
		return generatedAttemptObservation{}, err
	}
	return generatedAttemptObservation{present: true, record: row.record, expected: row.expected,
		result: bytes.Clone(row.result), intent: bytes.Clone(intent)}, nil
}

type generatedRetentionObservation struct {
	active, phased, seedAccess bool
	operation, material        contract.ID
	canonicalCount             int
	sources                    []contract.GeneratorSourceUse
	protectedSources           []contract.ID
	consumers                  []contract.GeneratorConsumer
	entryPlans                 []contract.GeneratorValueEntryPlan
}

func observeGeneratedRetention(session *StateSession) (generatedRetentionObservation, error) {
	work, err := session.selectedGeneratedWork(context.Background())
	if err != nil {
		return generatedRetentionObservation{}, err
	}
	observation := generatedRetentionObservation{active: work.parent != nil, phased: work.phase != nil, canonicalCount: len(work.canonical)}
	if work.parent == nil {
		return observation, nil
	}
	observation.operation, observation.material = work.parent.OperationID, work.parent.MaterialID
	_, observation.seedAccess = session.materialAccess(contract.OperationSeedMaterialKind, observation.material)
	observation.sources = slices.Clone(work.sources[observation.material])
	observation.consumers = slices.Clone(work.consumers[materialIdentity{contract.OperationSeedMaterialKind, observation.material}])
	if len(work.bundles) == 0 {
		return generatedRetentionObservation{}, contract.ErrRecord
	}
	observation.entryPlans = slices.Clone(work.bundles[0].ValueEntryPlans)
	if len(observation.sources) == 0 {
		return observation, nil
	}
	row, present := work.record(contract.OperationMaterialSupportKind, observation.material)
	if !present {
		return generatedRetentionObservation{}, contract.ErrRecord
	}
	material, err := contract.InspectOperationMaterialRecord(row.Body)
	if err != nil {
		return generatedRetentionObservation{}, err
	}
	protections, err := contract.InspectGeneratedSourceProtections(material, work.protected[observation.material])
	if err != nil {
		return generatedRetentionObservation{}, err
	}
	for index := 0; index < protections.Count(); index++ {
		row, err := protections.Row(index)
		if err != nil {
			return generatedRetentionObservation{}, err
		}
		observation.protectedSources = append(observation.protectedSources, row.SourceID)
	}
	return observation, nil
}

func observeGeneratedDeleteTarget(session *StateSession, attempt contract.ID) (contract.GeneratorTarget, bool, error) {
	work, err := session.selectedGeneratedWork(context.Background())
	if err != nil {
		return contract.GeneratorTarget{}, false, err
	}
	row, present := work.attempts[attempt]
	if !present {
		return contract.GeneratorTarget{}, false, nil
	}
	source, err := work.generatedDeleteSource(row.record.OwnerID)
	if err != nil {
		return contract.GeneratorTarget{}, false, err
	}
	target, err := work.generatedCleanupTarget(source.Record.Kind, source.Record.RecordID, source.Target)
	return target, err == nil, err
}

func ownScenarioValueEntry(entry contract.ValueEntry) contract.ValueEntry {
	entry.Recipients = slices.Clone(entry.Recipients)
	entry.ValueBytes = bytes.Clone(entry.ValueBytes)
	return entry
}

func observeCurrentValueEntry(t testing.TB, session *StateSession, name string) (uint16, contract.ValueEntry) {
	t.Helper()
	for _, row := range session.root.Names {
		if row.Name == name {
			entry := session.valueEntry(row.Slot)
			if entry != nil {
				return row.Slot, ownScenarioValueEntry(*entry)
			}
		}
	}
	t.Fatal("selected value entry is absent", name)
	return 0, contract.ValueEntry{}
}

func ownScenarioAccess(access contract.AccessRecord) contract.AccessRecord {
	access.Wraps = slices.Clone(access.Wraps)
	for index := range access.Wraps {
		access.Wraps[index].RSACiphertext = bytes.Clone(access.Wraps[index].RSACiphertext)
	}
	return access
}

func observeMaterialAccess(session *StateSession, kind contract.MaterialKind, material contract.ID) (contract.AccessRecord, bool) {
	access, present := session.materialAccess(kind, material)
	return ownScenarioAccess(access), present
}

func scenarioAccessRecipients(access contract.AccessRecord) []contract.ID {
	var recipients []contract.ID
	for _, wrap := range access.Wraps {
		if wrap.SubjectKind == 1 {
			recipients = append(recipients, wrap.SubjectID)
		}
	}
	return recipients
}

func observePreservedGeneratedSupport(ctx context.Context, session *StateSession) ([]contract.SupportRecord, error) {
	rows, err := session.workSupportRecords(ctx)
	if err != nil {
		return nil, err
	}
	rows = slices.Clone(rows)
	missing := make(map[generatedRecordKey]int)
	for index := range rows {
		rows[index].Body = bytes.Clone(rows[index].Body)
		if rows[index].Body == nil {
			if rows[index].Kind != contract.GeneratedFragmentSupportKind &&
				(rows[index].Kind != contract.OutputConfigurationSliceSupportKind || !session.selectedOutputComplete()) {
				return nil, contract.ErrRecord
			}
			key := generatedRecordKey{rows[index].Kind, rows[index].RecordID}
			if _, duplicate := missing[key]; duplicate {
				return nil, contract.ErrRecord
			}
			missing[key] = index
		}
	}
	if len(missing) != 0 {
		if len(session.supportFacts) != len(session.root.RequiredSupport) {
			return nil, contract.ErrRecord
		}
		for index, facts := range session.supportFacts {
			if facts.ref != session.root.RequiredSupport[index] {
				return nil, contract.ErrRecord
			}
			needed := slices.ContainsFunc(facts.rows, func(row contract.SupportRecordDigest) bool {
				_, present := missing[generatedRecordKey{row.Kind(), row.RecordID()}]
				return present
			})
			if !needed {
				continue
			}
			result, err := withAuthenticatedSupportRows(ctx, session.readObjectBorrowedUncached, session.root.Domain, facts,
				func(_ uint16, _ uint16, row contract.SupportRecordView) error {
					key := generatedRecordKey{row.Kind, row.RecordID}
					if slot, present := missing[key]; present {
						rows[slot].Body = bytes.Clone(row.Body)
						delete(missing, key)
					}
					return nil
				})
			if result != (Result{}) {
				return nil, selectedReadFailure(result)
			}
			if err != nil {
				return nil, err
			}
		}
		if len(missing) != 0 {
			return nil, contract.ErrRecord
		}
	}
	return rebindSnapshotSliceRecords(rows, session.admission.domain, session.adminIndex.SliceSnapshot, session.admission.domain)
}

func ownScenarioCanonicalSelection(selection custody.GeneratedCanonicalSelection) custody.GeneratedCanonicalSelection {
	selection.Record.Entry = ownScenarioValueEntry(selection.Record.Entry)
	selection.Selection.Entry = ownScenarioValueEntry(selection.Selection.Entry)
	selection.Selection.Payload.Ciphertext = bytes.Clone(selection.Selection.Payload.Ciphertext)
	selection.Selection.Access = ownScenarioAccess(selection.Selection.Access)
	selection.Selection.Binding.Binding.SPKI = bytes.Clone(selection.Selection.Binding.Binding.SPKI)
	selection.Owner.Body = bytes.Clone(selection.Owner.Body)
	selection.Consumers = slices.Clone(selection.Consumers)
	for index := range selection.Consumers {
		selection.Consumers[index] = bytes.Clone(selection.Consumers[index])
	}
	return selection
}

func selectGeneratedScenarioConsumer(ctx context.Context, session *StateSession, kind contract.SupportRecordKind, owner, material, recipient contract.ID) (contract.GeneratedCanonicalSelection, Result) {
	selection, result := session.generatedConsumerSelection(ctx, kind, owner, material, recipient)
	return ownScenarioCanonicalSelection(selection), result
}

func observeScenarioEffects(spy *scenarioSpy) scenarioEffects {
	spy.mu.Lock()
	defer spy.mu.Unlock()
	return spy.scenarioEffects
}

// The handle retains the real producer so replay uses the original admission.
type generatedScenarioProducer struct {
	prepared *generatedPreparation
	keys     *custody.Fixture
	sends    int
	result   []byte
}

func mustPrepareGeneratedScenarioProducer(t testing.TB, env fixtureEnvironment, session *StateSession,
	input generatedPlanInput, canonical []custody.GeneratedCanonicalSelection, inputs generatedScenarioInputs) *generatedScenarioProducer {
	t.Helper()
	reservation, _ := preparePrivateGeneratedReservation(t, env, session, input, canonical)
	prepared, expected := preparePrivateGeneratedProducer(t, env, session, reservation, nil)
	if expected != inputs.expected {
		t.Fatal("prepared producer differs from the original generated input")
	}
	producer := &generatedScenarioProducer{prepared: prepared, keys: env.Custody}
	if !prepared.reservation.candidate.bindFirstSend(prepared, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		producer.sends++
		body, _, code := producer.keys.InvokeGeneratedProducer(ctx, prepared.operation.context.AdmissionID, prepared.producerLocator, authority)
		producer.result = bytes.Clone(body)
		return code
	}) {
		t.Fatal("generated scenario first-send handoff")
	}
	return producer
}

func (producer *generatedScenarioProducer) selectCandidate(ctx context.Context, session *StateSession) (*StateSession, Result) {
	return session.selectCandidate(ctx, producer.prepared.reservation.candidate)
}

func (producer *generatedScenarioProducer) observation() ([]byte, int) {
	return bytes.Clone(producer.result), producer.sends
}

func (producer *generatedScenarioProducer) replay(ctx context.Context) ([]byte, contract.CryptoResultCode) {
	p := producer.prepared
	body, _, code := producer.keys.InvokeGeneratedProducer(ctx, p.operation.context.AdmissionID, p.producerLocator, p.reservation.candidate.generated.authority)
	return bytes.Clone(body), code
}

func claimGeneratedScenarioPreparation(ctx context.Context, session *StateSession, prepared *generatedPreparation, trust contract.Trust) (*Candidate, Result) {
	return session.ClaimGeneratedPreparation(ctx, prepared.reservation.candidate, trust)
}

func probeGeneratedRetiredSigner(ctx context.Context, trust contract.Trust, permit *AdmittedSuccession,
	after contract.ControlCore, role uint8, attempt contract.ID) (contract.SignResult, error) {
	probe, err := contract.NewSuccessorSignerProbeRequest(contract.SuccessorProbeCore{Schema: 1, EvidenceKind: contract.SuccessorSignerEvidence,
		TargetRole: role, DomainID: after.DomainID, CoordinateID: after.CoordinateID,
		AdmissionID: permit.request.AdmissionID, PredecessorFullHEADDigest: permit.request.PredecessorFullHEADDigest,
		RequestCoreDigest: permit.descriptor.Digest, SuccessorBindingDigest: permit.descriptor.Digest, ProbeAttemptID: attempt})
	if err != nil {
		return contract.SignResult{}, err
	}
	return trust.Sign(ctx, probe), nil
}

type generatedScenarioFinal struct {
	owner     *StateSession
	candidate *Candidate
}

type generatedFinalObservation struct {
	body      []byte
	condition contract.Token
}

func mustPrepareGeneratedScenarioFinal(t testing.TB, env fixtureEnvironment, session *StateSession, admission, operationSession contract.ID) *generatedScenarioFinal {
	t.Helper()
	finalContext := generatedPlanInputFixture(t, session).context
	finalContext.AdmissionID, finalContext.SessionID = admission, operationSession
	plan, err := session.generatedFinalRequest(t.Context(), finalContext)
	if err != nil {
		t.Fatal("generated scenario final request", err)
	}
	session, prepared := preparePrivateGeneratedFinal(t, env, session, plan)
	return &generatedScenarioFinal{owner: session, candidate: prepared.reservation.candidate}
}

func (final *generatedScenarioFinal) observation() generatedFinalObservation {
	return generatedFinalObservation{body: bytes.Clone(final.candidate.body), condition: final.owner.token}
}

func (final *generatedScenarioFinal) selectCandidate(ctx context.Context) (*StateSession, Result) {
	return final.owner.selectCandidate(ctx, final.candidate)
}

func observeSelectedHead(session *StateSession) []byte {
	return bytes.Clone(session.body)
}

func readSelectedHead(ctx context.Context, session *StateSession) contract.ReadResult {
	result := session.store.Read(ctx, session.admission.store.HeadKey, 64<<10)
	result.Body = bytes.Clone(result.Body)
	return result
}

func compareGeneratedScenarioWithoutEntropy(ctx context.Context, session *StateSession, entries []ApplyEntryInput, parent *AdmittedParentComparison) (*Comparison, Result, int, bool) {
	entropy := bytes.NewReader(bytes.Repeat([]byte{0x7a}, 32))
	prior := session.admission.entropy
	session.admission.entropy = entropy
	defer func() { session.admission.entropy = prior }()
	comparison, result := session.Compare(ctx, entries, parent)
	return comparison, result, entropy.Len(), session.prepared
}

func (r *scenarioRun) damageSelectedObject(ref format.Ref, corrupt bool) {
	r.t.Helper()
	key := mustKey(r.t, r.env.Store.Descriptor().Prefix, ref)
	if err := r.env.Delete(r.ctx, key); err != nil {
		r.t.Fatal("owned fixture damage failed")
	}
	if corrupt {
		if err := r.env.Put(r.ctx, key, []byte("corrupt owned child")); err != nil {
			r.t.Fatal("owned fixture corruption failed")
		}
	}
}

func (r *scenarioRun) discardCompletedWriteReply(session *StateSession, head bool) {
	r.t.Helper()
	observed, ok := r.env.Store.(scenarioStore)
	if !ok || observed.spy != r.spy {
		r.t.Fatal("scenario store observation unavailable")
	}
	loss := &completedReplyLoss{Store: observed.Store, head: head, spy: r.spy}
	session.store = scenarioStore{Store: loss, spy: r.spy}
}

// full_only: false
func TestCompletedReplyLossAdapterKeepsOneObservationLayer(t *testing.T) {
	ctx := context.Background()
	env := memoryScenarioEnvironment(t)
	run := newScenarioRun(t, ctx, env)
	session := &StateSession{store: run.env.Store}

	run.discardCompletedWriteReply(session, false)
	result := session.store.Create(ctx, "fixture/adapter-loss", []byte("body"))
	if result.Status != contract.WriteUnknown || result.Reason != contract.ReasonTransport {
		t.Fatal("completed create reply was not discarded", result)
	}
	run.spy.mu.Lock()
	creates, unknown, lost := run.spy.StoreCreate, run.spy.UnknownWrites, run.spy.InjectedLostReplies
	run.spy.mu.Unlock()
	if creates != 1 || unknown != 1 || lost != 1 {
		t.Fatalf("completed create observed %d creates, %d unknown writes and %d lost replies", creates, unknown, lost)
	}
}

// full_only: false
func TestAllocatedTransitionInputsDoNotAliasAdmissionPlan(t *testing.T) {
	plan := transitionPlan{
		revision: testID("adapter revision"), operation: testID("adapter operation"), snapshot: testID("adapter snapshot"), transition: testID("adapter transition"),
		values: map[uint16]contract.ID{1: testID("adapter value")}, incarnations: map[uint16]contract.ID{2: testID("adapter incarnation")},
	}
	plan.pages[3] = testID("adapter member page")
	plan.recipientPages[4] = testID("adapter recipient page")
	plan.accessPages[5] = testID("adapter access page")
	plan.supportPages[6] = testID("adapter support page")

	inputs := captureAllocatedTransitionInputs(plan)
	plan.revision = testID("damaged revision")
	plan.pages[3] = testID("damaged member page")
	plan.recipientPages[4] = testID("damaged recipient page")
	plan.accessPages[5] = testID("damaged access page")
	plan.supportPages[6] = testID("damaged support page")
	plan.values[1] = testID("damaged value")
	plan.incarnations[2] = testID("damaged incarnation")

	if inputs.revision == plan.revision || inputs.valueEntryPages[3] == plan.pages[3] || inputs.recipientPages[4] == plan.recipientPages[4] || inputs.accessPages[5] == plan.accessPages[5] || inputs.supportPages[6] == plan.supportPages[6] || inputs.values[1] == plan.values[1] || inputs.incarnations[2] == plan.incarnations[2] {
		t.Fatal("captured transition inputs changed with private admission state")
	}
}

func generatedHistoryInput(t testing.TB, h *generatedHistoryFixture) (generatedPlanInput, []custody.GeneratedCanonicalSelection) {
	t.Helper()
	s := h.state.session
	var sources []contract.GeneratorDeclarationEntry
	var canonical []custody.GeneratedCanonicalSelection
	switch h.casePlan.SourceMode {
	case 0:
	case 1:
		sealed := suppliedSecret(t, h.run.env, "source", "generated history sealed source", custody.StandardValue)
		envelope, err := contract.DecodeSealedInputEnvelope(sealed.InputBytes)
		if err != nil {
			t.Fatal("generated history sealed source", err)
		}
		h.source = envelope.Core.SourceID
		sources = append(sources, contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationSealed,
			Name: sealed.Name, Recipients: slices.Clone(sealed.Recipients), Payload: bytes.Clone(sealed.InputBytes)})
	case 2:
		recipients := []contract.ID{s.admission.recipient}
		if !h.casePlan.Union {
			recipients = append(recipients, h.reader)
		}
		slices.SortFunc(recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		h.run.suppliedSelection(h.state, []ApplyEntryInput{sharingSecret(t, h.run.env, "generated history V1", recipients)})
		selection := sessionConsumerSelection(t, h.state.session, h.state.session.admission.recipient, "secret")
		record := contract.RetainedCanonicalRecord{OriginalSlot: selection.Slot, Entry: selection.Entry}
		body, err := contract.EncodeRetainedCanonicalRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		intended := slices.Clone(record.Entry.Recipients)
		if h.casePlan.Union {
			intended = append(intended, h.reader)
			slices.SortFunc(intended, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		}
		sources = append(sources, contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationRetained,
			Name: record.Entry.Name, Recipients: intended, Payload: body})
		canonical = append(canonical, ownScenarioCanonicalSelection(custody.GeneratedCanonicalSelection{Selection: selection, Record: record}))
		h.source = record.Entry.ValueState
		_, current := observeCurrentValueEntry(t, h.state.session, "secret")
		body, err = contract.EncodeValueEntry(current)
		if err != nil {
			t.Fatal(err)
		}
		h.current, h.currentRaw = current, body
	default:
		t.Fatal("unknown generated history source mode")
	}
	profile := defaultGeneratedFixtureProfile()
	profile.ConfigContractID = contract.Hash([]byte("ENKV/CLOUDFLARE-ACCOUNT-TOKEN/CONFIG/v1\x00https://api.cloudflare.com/client/v4"))
	profile.ResourceContractID = hermeticCloudflareResourceContractID()
	input := generatedPlanInputForGenerationsIntent(t, h.state.session, generatedVectorID(10), []string{"generated"}, h.intent,
		profile, sources...)
	input.requestBindings[0].Digest = hermeticCloudflareHTTPRequestDigest(h.request)
	return input, canonical
}

func refuseGeneratedRecoveryWithoutConfiguredCapability(t testing.TB, ctx context.Context, run *scenarioRun, selected *StateSession) contract.ID {
	t.Helper()
	beforeBody, beforeToken := bytes.Clone(selected.body), selected.token
	beforeEffects := observeScenarioEffects(run.spy)
	beforePublic, beforePrivate := run.env.Custody.Calls()
	after := currentControlOf(selected)
	if after.Recovery != nil {
		t.Fatal("disabled recovery fixture contains a recovery capability")
	}
	after.AccessGeneration++
	request, plan, admitted := selected.planSuccession(t.Context(), after, 3, contract.NormalSigningRole, 8, fixtureID(run.env.Domain, "disabled generated recovery attempt"), contract.SuccessionMaterialAuthority)
	if admitted || request.OperationKind != 3 || request.ChangeMask != 8 || request.BeforeControl.Recovery != nil || request.OperationID.IsZero() {
		t.Fatal("disabled generated recovery request did not fail its exact capability check")
	}
	if _, err := contract.SuccessionRequestDescriptor(request); err == nil {
		t.Fatal("generated request without a recovery pair has a valid descriptor")
	}
	permit := &AdmittedSuccession{session: selected, request: request, plan: plan, deadline: time.Now().Add(time.Minute)}
	candidate, result := selected.PrepareSuccession(ctx, permit, SuccessionSigners{Authorizer: run.env.Trust})
	if candidate != nil || result != refused(AdmissionInvalid) || permit.used || selected.prepared {
		t.Fatal("disabled generated recovery crossed Product admission", result)
	}
	if body, receipt := selected.MutationReceipt(ctx, request.OperationID); body != nil || receipt != refused(AdmissionInvalid) {
		t.Fatal("refused generated recovery created a receipt", receipt)
	}
	public, private := run.env.Custody.Calls()
	if effects := observeScenarioEffects(run.spy); effects.StoreCreate != beforeEffects.StoreCreate || effects.StoreCAS != beforeEffects.StoreCAS || effects.TrustSign != beforeEffects.TrustSign ||
		public != beforePublic || private != beforePrivate || !bytes.Equal(selected.body, beforeBody) || selected.token != beforeToken {
		t.Fatal("disabled generated recovery refusal changed selected state or private effects")
	}
	return request.OperationID
}

func generatedCurrentDeclaration(t testing.TB, s *StateSession) ([]contract.GeneratorDeclarationEntry, []custody.GeneratedCanonicalSelection) {
	t.Helper()
	var entries []contract.GeneratorDeclarationEntry
	var canonical []custody.GeneratedCanonicalSelection
	var work *generatedSelection
	for _, name := range s.root.Names {
		entry := s.valueEntry(name.Slot)
		if entry == nil {
			t.Fatal("combined generated predecessor member")
		}
		if entry.ValueSource == contract.Generated {
			if work == nil {
				work = mustSelectedGeneratedWork(t, s)
			}
			entries = append(entries, generatedReferenceDeclaration(t, entry, work))
			continue
		}
		if entry.ValueSource != contract.Supplied {
			t.Fatal("combined generated predecessor member")
		}
		if entry.ConfidentialityClass == contract.Plain {
			entries = append(entries, contract.GeneratorDeclarationEntry{InputEncoding: entry.InputEncoding, OutputEncoding: entry.OutputEncoding, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationPlain,
				Name: entry.Name, Recipients: slices.Clone(entry.Recipients), Payload: bytes.Clone(entry.ValueBytes)})
			continue
		}
		record := contract.RetainedCanonicalRecord{OriginalSlot: name.Slot, Entry: ownScenarioValueEntry(*entry)}
		body, err := contract.EncodeRetainedCanonicalRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		selection := sessionConsumerSelection(t, s, s.admission.recipient, entry.Name)
		entries = append(entries, contract.GeneratorDeclarationEntry{InputEncoding: entry.InputEncoding, OutputEncoding: entry.OutputEncoding, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationRetained,
			Name: entry.Name, Recipients: slices.Clone(entry.Recipients), Payload: body})
		canonical = append(canonical, ownScenarioCanonicalSelection(custody.GeneratedCanonicalSelection{Selection: selection, Record: record}))
	}
	return entries, canonical
}

func selectGeneratedAccessReplacement(t testing.TB, ctx context.Context, run *scenarioRun, f *environmentFixture,
	operation, mask, approval uint8) (contract.ID, []byte) {
	t.Helper()
	before := f.session
	beforeImage := observeSelectedState(t, before)
	work, err := observePreservedGeneratedSupport(ctx, before)
	if err != nil {
		t.Fatal(err)
	}
	actors := run.env.ReplacementActors(t, ctx, before, operation, mask, approval)
	permit := admitAuthorityReplacement(t, before, actors.Keys, actors.After, operation, approval, mask, actors.Source)
	candidate, result := before.PrepareSuccession(ctx, permit, actors.Signers)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("generated occupied replacement preparation", result)
	}
	admission := deliverSuccessionBasis(t, candidate)
	if result = before.Select(ctx, candidate); result.Outcome != ObservedCurrent {
		t.Fatal("generated occupied replacement selection", result)
	}
	actors.Keys.RetireAccess()
	selected, result := Open(ctx, admission, run.env.Store)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("generated occupied replacement reopen", result)
	}
	actors.Activate(t, selected)
	afterImage := observeSelectedState(t, selected)
	afterWork, err := observePreservedGeneratedSupport(ctx, selected)
	if err != nil || !reflect.DeepEqual(work, afterWork) || !reflect.DeepEqual(beforeImage.Pages, afterImage.Pages) ||
		!reflect.DeepEqual(beforeImage.Root.ValueEntryPages, afterImage.Root.ValueEntryPages) || !reflect.DeepEqual(beforeImage.Root.Names, afterImage.Root.Names) ||
		beforeImage.Root.ValueEntryCount != afterImage.Root.ValueEntryCount || beforeImage.Root.RawBytes != afterImage.Root.RawBytes {
		t.Fatal("generated occupied replacement changed accepted work or current material", err)
	}
	f.admission, f.session = admission, selected
	if operation != 1 {
		return permit.request.OperationID, checkSuccessionReceipt(t, ctx, selected, permit)
	}
	return contract.ID{}, nil
}

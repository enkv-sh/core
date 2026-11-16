package core

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

type generatedFinalCheckpointExpectation struct {
	Mode                   string
	ImageID                contract.ID
	MaterializationPhaseID contract.ID
	Artifacts              map[string][]byte
}

func assertFreshFinalCheckpointBefore(t testing.TB, s *StateSession, expected *generatedFinalCheckpointExpectation) {
	t.Helper()
	work := mustSelectedGeneratedWork(t, s)
	if work.parent == nil || work.phase == nil || work.phase.Stage != contract.GeneratedStageTerminal {
		t.Fatal("fresh Final did not cold-open its terminal parent")
	}
	switch expected.Mode {
	case "reuse", "replace":
		if work.preparation == nil || work.preparation.Image.ContentID != expected.ImageID ||
			mustGeneratedPhaseID(work.preparation.MaterializationPhase) != expected.MaterializationPhaseID {
			t.Fatal("fresh Final lost the exact selected historical image")
		}
	case "orphan":
		if work.preparation != nil || !work.phase.FinalPreparationID.IsZero() {
			t.Fatal("fresh Final adopted an unselected orphan preparation")
		}
	default:
		t.Fatal("unknown checkpoint expectation")
	}
	// The fresh OS process receives only passive selected-state facts. Opaque
	// producer grants are absent and cannot be replaced by an empty permit.
	if p, result := s.PrepareGeneratedProducer(t.Context(), nil); p != nil || result != refused(AdmissionInvalid) {
		t.Fatal("fresh checkpoint process acquired a volatile producer grant", result)
	}
	if p, result := s.PrepareGeneratedOriginalProducer(t.Context(), nil); p != nil || result != refused(AdmissionInvalid) {
		t.Fatal("fresh checkpoint process acquired a complete-original grant", result)
	}
}

func assertFreshFinalCheckpointReplacement(t testing.TB, candidate *Candidate, expected *generatedFinalCheckpointExpectation) {
	t.Helper()
	if expected.Mode == "reuse" {
		t.Fatal("fresh Final rematerialized an exactly reusable selected image")
	}
	work := mustSelectedGeneratedWork(t, candidate.producer.reservation.state)
	if work.preparation == nil || work.preparation.Image.ContentID == expected.ImageID {
		t.Fatal("fresh Final reused an orphan or stale-context image")
	}
	if expected.Mode == "replace" && mustGeneratedPhaseID(work.preparation.MaterializationPhase) == expected.MaterializationPhaseID {
		t.Fatal("replacement did not create a new actual-HEAD materialization phase")
	}
}

type finalizationCheckpointFixture struct {
	env       fixtureEnvironment
	sourceEnv fixtureEnvironment
	base      *StateSession
	store     *memoryStore
	effects   *int
}

func newFinalizationCheckpointFixture(t *testing.T) finalizationCheckpointFixture {
	t.Helper()
	return newFinalizationCheckpointFixtureWithRetirement(t, false)
}

func newFinalizationCheckpointFixtureWithRetirement(t *testing.T, independentRetirement bool) finalizationCheckpointFixture {
	t.Helper()
	return newFinalizationCheckpointFixtureWithChangedSupplied(t, independentRetirement, false)
}

func newFinalizationCheckpointFixtureWithChangedSupplied(t *testing.T, independentRetirement, changedSupplied bool) finalizationCheckpointFixture {
	t.Helper()
	if independentRetirement && changedSupplied {
		t.Fatal("checkpoint fixture mixes unrelated proof cases")
	}
	env, keys := genesisEnvironment(t, contract.GCP, true)
	env = syntheticAuthorityScenarioEnvironment(t, env)
	run := newScenarioRun(t, t.Context(), env)
	fixture := newEnvironmentFixture(t, t.Context(), run.env, nil, false)
	var current *StateSession
	if independentRetirement {
		profile := defaultGeneratedFixtureProfile()
		initial := generatedPlanInputForGenerations(t, fixture.session, generatedVectorID(231), []string{"kept"}, profile)
		first := selectPrivateGeneratedOperationInProcess(t, env, fixture.session, initial, "checkpoint independent first generation")
		old := *first.valueEntry(first.root.Names[0].Slot)
		rotation := generatedStatePlanInput(t, first, generatedVectorID(232), []string{old.Name}, profile, old.Generated.Epoch+1,
			map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: old})
		current = selectPrivateGeneratedOperationInProcess(t, env, first, rotation, "checkpoint independent rotation")
		if current.root.Generated.Retiring != 1 || current.valueEntry(current.root.Names[0].Slot).Generated.RetiringDutyPresent != 1 {
			t.Fatal("checkpoint fixture did not retain an authentic independent retirement Duty")
		}
	} else {
		current = run.suppliedSelection(fixture, []ApplyEntryInput{suppliedSecret(t, env, "kept", "checkpoint current Secret", custody.StandardValue)})
	}
	sources, canonical := generatedCurrentDeclaration(t, current)
	if changedSupplied {
		changed := suppliedSecret(t, env, "kept", "checkpoint changed supplied source", custody.EmptyValue)
		sources = []contract.GeneratorDeclarationEntry{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationSealed,
			Name: changed.Name, Recipients: changed.Recipients, Payload: changed.InputBytes}}
		canonical = nil
	}
	input := generatedPlanInputForGenerations(t, current, generatedVectorID(230), []string{"checkpoint-generated"}, defaultGeneratedFixtureProfile(), sources...)
	reservation, _ := preparePrivateGeneratedReservation(t, env, current, input, canonical)
	producer, expected := preparePrivateGeneratedProducer(t, env, current, reservation, nil)
	effects := new(int)
	var packet []byte
	if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		*effects++
		var code contract.CryptoResultCode
		packet, _, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		return code
	}) {
		t.Fatal("checkpoint fixture original handoff")
	}
	selected, result := current.selectCandidate(t.Context(), producer.reservation.candidate)
	if selected == nil || result.Outcome != ObservedCurrent || *effects != 1 || len(packet) == 0 {
		t.Fatal("checkpoint fixture original effect", result)
	}
	keys.RetireGenerated()
	store := requireAdmittedMemoryStore(t, env.Store)
	base := selectFreshGeneratedRecord(t, store, selected, expected.Template.AttemptID, packet)
	if base.root.ValueEntryCount != 1 || base.root.SecretCount != 1 || len(base.accessRecords()) == 0 {
		t.Fatal("checkpoint fixture has no real retained current Secret")
	}
	return finalizationCheckpointFixture{sourceEnv: env, env: currentGeneratedEnvironment(t, env.Store, base), base: base, store: store, effects: effects}
}

func checkpointFinalPlan(t testing.TB, s *StateSession, label string) *generatedFinalPlan {
	t.Helper()
	admitted := generatedPlanInputFixture(t, s).context
	admitted.AdmissionID, admitted.SessionID = testID(label+" admission"), testID(label+" session")
	plan, err := s.generatedFinalRequest(t.Context(), admitted)
	if err != nil || plan == nil || !plan.selecting || len(plan.entryPlans) != 1 {
		t.Fatal("checkpoint fixture selecting Final request", err)
	}
	return plan
}

func prepareCheckpointFinal(t testing.TB, env fixtureEnvironment, s *StateSession, label string) *generatedPreparation {
	t.Helper()
	plan := checkpointFinalPlan(t, s, label)
	permit := admitPrivateGeneratedFinal(t, env, s, plan)
	prepared, result := s.PrepareGeneratedFinal(t.Context(), permit)
	if prepared == nil || result.Outcome != ObservedCurrent {
		t.Fatal("checkpoint private preparation", result)
	}
	if code := env.Custody.BindGeneratedCandidate(t.Context(), plan.request.Context.AdmissionID, generatedPrivateCandidate(t, prepared)); code != contract.CryptoSuccess {
		t.Fatal("checkpoint private candidate binding", code)
	}
	return prepared
}

func selectCheckpointOnly(t *testing.T, fixture finalizationCheckpointFixture) (*StateSession, generatedFinalCheckpointExpectation) {
	t.Helper()
	prepared := prepareCheckpointFinal(t, fixture.env, fixture.base, "checkpoint materialization")
	if prepared.reservation.candidate.head.Generator == nil || prepared.reservation.candidate.head.Generator.Purpose != contract.GeneratorAuthorityFinalPreparation {
		t.Fatal("generated Final did not expose a distinct preparation checkpoint")
	}
	if candidate, result := fixture.base.ClaimGeneratedPreparation(t.Context(), prepared.reservation.candidate, fixture.env.Trust); candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("checkpoint claim", result)
	}
	selected, result := fixture.base.selectCandidate(t.Context(), prepared.reservation.candidate)
	if selected == nil || result.Outcome != ObservedCurrent || !reflect.DeepEqual(selected.currentEntryInputs(), fixture.base.currentEntryInputs()) ||
		!reflect.DeepEqual(selected.accessRecords(), fixture.base.accessRecords()) || *fixture.effects != 1 {
		t.Fatal("checkpoint selection changed current state or provider effects", result)
	}
	fixture.env.Custody.RetireGenerated()
	work := mustSelectedGeneratedWork(t, selected)
	if work.preparation == nil || work.phase.FinalPreparationID != work.preparation.Image.ContentID {
		t.Fatal("checkpoint selection omitted the exact durable association")
	}
	return selected, generatedFinalCheckpointExpectation{Mode: "reuse", ImageID: work.preparation.Image.ContentID,
		MaterializationPhaseID: mustGeneratedPhaseID(work.preparation.MaterializationPhase)}
}

func checkpointArtifactBodies(t testing.TB, s *StateSession, candidate *Candidate) map[string][]byte {
	t.Helper()
	out := make(map[string][]byte, len(candidate.objects))
	for _, object := range candidate.objects {
		key, err := format.Key(s.admission.store.Prefix, object.ref)
		if err != nil || format.CheckReference(object.ref, object.body) != nil || out[key] != nil {
			t.Fatal("checkpoint artifact identity", err)
		}
		out[key] = bytes.Clone(object.body)
	}
	return out
}

func checkpointFinalInFreshProcess(t *testing.T, s *StateSession, store *memoryStore, expected generatedFinalCheckpointExpectation) *StateSession {
	t.Helper()
	input := selectedGeneratedProcessFacts(t, s)
	var err error
	input.ExpectedWork, err = s.workSupportRecords(t.Context())
	if err != nil {
		t.Fatal("checkpoint child passive work", err)
	}
	input.Objects, input.Generation, input.GeneratedFinal = store.objects, store.generation, true
	input.GeneratedFinalCheckpoint = &expected
	output := checkFreshProcessInput(t, input)
	selected := importFreshGeneratedSelection(t, s, input.Generation, output)
	if selected.root.ValueEntryCount != 2 || selected.root.Generated.GeneratedCurrent != 1 || !selected.root.Generated.ActiveOwner.IsZero() {
		t.Fatal("fresh checkpoint Final did not select the complete intended current set")
	}
	return selected
}

func cloneCheckpointStore(source *memoryStore) *memoryStore {
	source.mu.Lock()
	defer source.mu.Unlock()
	copy := &memoryStore{desc: source.desc, configuration: source.configuration, generation: source.generation, objects: make(map[string]stored, len(source.objects))}
	for key, object := range source.objects {
		object.Body = bytes.Clone(object.Body)
		copy.objects[key] = object
	}
	return copy
}

type checkpointArtifactCutStore struct {
	contract.Store
	stopAt int
	writes int
	cutKey string
}

func (s *checkpointArtifactCutStore) StoreConfiguration() contract.StoreConfiguration {
	return fixtureStoreConfiguration(s.Store)
}

func (s *checkpointArtifactCutStore) Create(ctx context.Context, key string, body []byte) contract.WriteResult {
	s.writes++
	if s.writes == s.stopAt+1 {
		s.cutKey = key
		return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport, NotSent: true}
	}
	return s.Store.Create(ctx, key, body)
}

func (s *checkpointArtifactCutStore) Read(ctx context.Context, key string, maximum uint32) contract.ReadResult {
	if s.cutKey == key {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
	}
	return s.Store.Read(ctx, key, maximum)
}

// full_only: false
func TestGeneratedFinalCheckpointSurvivesFreshProcess(t *testing.T) {
	fixture := newFinalizationCheckpointFixture(t)
	checkpoint, expected := selectCheckpointOnly(t, fixture)
	checkpointFinalInFreshProcess(t, checkpoint, fixture.store, expected)
	if *fixture.effects != 1 {
		t.Fatal("fresh checkpoint Final repeated the original provider effect")
	}
}

// full_only: false
func TestGeneratedFinalCheckpointReplaysEveryImmutableWriteCut(t *testing.T) {
	fixture := newFinalizationCheckpointFixture(t)
	checkpoint, expected := selectCheckpointOnly(t, fixture)
	captured := prepareCheckpointFinal(t, currentGeneratedEnvironment(t, fixture.store, checkpoint), checkpoint, "capture actual Final")
	if captured.reservation.candidate.head.Generator.Purpose != contract.GeneratorAuthorityFinal || len(captured.resultWrites) != 0 || len(captured.reservation.candidate.objects) < 2 {
		t.Fatal("actual Final does not have a bounded immutable artifact sequence")
	}
	expected.Artifacts = checkpointArtifactBodies(t, checkpoint, captured.reservation.candidate)
	for position := range captured.reservation.candidate.objects {
		t.Run(fmt.Sprintf("before-artifact-%d", position), func(t *testing.T) {
			store := cloneCheckpointStore(fixture.store)
			base, result := Open(t.Context(), OpenContext{admission: &checkpoint.admission}, store)
			if base == nil || result.Outcome != ObservedCurrent {
				t.Fatal("write-cut cold checkpoint", result)
			}
			env := currentGeneratedEnvironment(t, store, base)
			prepared := prepareCheckpointFinal(t, env, base, fmt.Sprintf("write cut %d", position))
			if !reflect.DeepEqual(checkpointArtifactBodies(t, base, prepared.reservation.candidate), expected.Artifacts) {
				t.Fatal("fresh private admission changed the selected image's exact Final artifacts")
			}
			cut := &checkpointArtifactCutStore{Store: store, stopAt: position}
			base.store = cut
			cas := store.cas
			candidate, result := base.ClaimGeneratedPreparation(t.Context(), prepared.reservation.candidate, env.Trust)
			base.store = store
			if candidate != nil || result.Outcome != EvidenceUnavailable || result.Reason != ReadUnavailable ||
				cut.writes != position+1 || cut.cutKey == "" || store.cas != cas {
				t.Fatal("immutable write cut missed its exact boundary", position, result, cut.writes)
			}
			for i, object := range prepared.reservation.candidate.objects[:position] {
				key, err := format.Key(store.desc.Prefix, object.ref)
				read := store.Read(t.Context(), key, object.ref.Length)
				if err != nil || read.Status != contract.ReadOK || !bytes.Equal(read.Body, object.body) {
					t.Fatal("write cut lost a successfully admitted immutable prefix", i, err)
				}
			}
			env.Custody.RetireGenerated()
			cold, observed := Open(t.Context(), OpenContext{admission: &checkpoint.admission}, store)
			if cold == nil || observed.Outcome != ObservedCurrent || !bytes.Equal(cold.body, checkpoint.body) {
				t.Fatal("interrupted Final changed checkpoint selection", observed)
			}
			checkpointFinalInFreshProcess(t, cold, store, expected)
			if *fixture.effects != 1 {
				t.Fatal("immutable replay repeated a provider effect")
			}
		})
	}
}

func checkpointSigningUnavailable(t *testing.T, env fixtureEnvironment, unavailable bool) {
	t.Helper()
	signer, ok := env.Trust.(interface{ SetUnavailable(bool) })
	if !ok {
		t.Fatal("checkpoint signing-loss fixture has no controllable actual signer")
	}
	signer.SetUnavailable(unavailable)
}

// full_only: false
func TestGeneratedFinalCheckpointReplaysAfterSigningLoss(t *testing.T) {
	fixture := newFinalizationCheckpointFixture(t)
	checkpoint, expected := selectCheckpointOnly(t, fixture)
	env := currentGeneratedEnvironment(t, fixture.store, checkpoint)
	prepared := prepareCheckpointFinal(t, env, checkpoint, "actual Final signing loss")
	expected.Artifacts = checkpointArtifactBodies(t, checkpoint, prepared.reservation.candidate)
	cas := fixture.store.cas
	checkpointSigningUnavailable(t, env, true)
	candidate, result := checkpoint.ClaimGeneratedPreparation(t.Context(), prepared.reservation.candidate, env.Trust)
	checkpointSigningUnavailable(t, env, false)
	if candidate != nil || result.Outcome != EvidenceUnavailable || result.Reason != SigningUnavailable || fixture.store.cas != cas {
		t.Fatal("actual Final did not reach loss of signing after its immutable writes", result)
	}
	accessPages, valuePages := 0, 0
	for _, object := range prepared.reservation.candidate.objects {
		key, err := format.Key(fixture.store.desc.Prefix, object.ref)
		read := fixture.store.Read(t.Context(), key, object.ref.Length)
		if err != nil || read.Status != contract.ReadOK || !bytes.Equal(read.Body, object.body) {
			t.Fatal("signing loss did not leave the exact successful immutable prefix", err)
		}
		if object.ref.Kind == format.AccessKind {
			accessPages++
		}
		if object.ref.Kind == format.ValueEntryPageKind {
			valuePages++
		}
	}
	if accessPages == 0 || valuePages == 0 {
		t.Fatal("signing-loss boundary did not follow both immutable access and value pages")
	}
	env.Custody.RetireGenerated()
	cold, observed := Open(t.Context(), OpenContext{admission: &checkpoint.admission}, fixture.store)
	if cold == nil || observed.Outcome != ObservedCurrent || !bytes.Equal(cold.body, checkpoint.body) {
		t.Fatal("signing loss changed the selected checkpoint", observed)
	}
	checkpointFinalInFreshProcess(t, cold, fixture.store, expected)
	if *fixture.effects != 1 {
		t.Fatal("signing-loss replay repeated the original provider effect")
	}
}

// full_only: false
func TestGeneratedFinalCheckpointSigningLossBeforeSelectionLeavesOnlyOrphanImage(t *testing.T) {
	fixture := newFinalizationCheckpointFixture(t)
	prepared := prepareCheckpointFinal(t, fixture.env, fixture.base, "unselected checkpoint signing loss")
	candidate := prepared.reservation.candidate
	if candidate.head.Generator == nil || candidate.head.Generator.Purpose != contract.GeneratorAuthorityFinalPreparation {
		t.Fatal("preselection signing loss did not use a preparation checkpoint")
	}
	orphan := mustSelectedGeneratedWork(t, prepared.reservation.state)
	if orphan.preparation == nil {
		t.Fatal("preselection checkpoint has no image")
	}
	expected := generatedFinalCheckpointExpectation{Mode: "orphan", ImageID: orphan.preparation.Image.ContentID,
		MaterializationPhaseID: mustGeneratedPhaseID(orphan.preparation.MaterializationPhase)}
	before := make(map[string]bool, len(fixture.store.objects))
	for key := range fixture.store.objects {
		before[key] = true
	}
	cas := fixture.store.cas
	checkpointSigningUnavailable(t, fixture.env, true)
	claimed, result := fixture.base.ClaimGeneratedPreparation(t.Context(), candidate, fixture.env.Trust)
	checkpointSigningUnavailable(t, fixture.env, false)
	if claimed != nil || result.Outcome != EvidenceUnavailable || result.Reason != SigningUnavailable || fixture.store.cas != cas {
		t.Fatal("unselected preparation signing-loss boundary", result)
	}
	permitted := checkpointArtifactBodies(t, fixture.base, candidate)
	for _, object := range candidate.objects {
		if object.ref.Kind == format.AccessKind || object.ref.Kind == format.ValueEntryPageKind {
			t.Fatal("unselected preparation wrote an actual Final access or value container")
		}
	}
	for key, object := range fixture.store.objects {
		if before[key] {
			continue
		}
		if body, ok := permitted[key]; !ok || !bytes.Equal(body, object.Body) {
			t.Fatal("unselected preparation wrote outside its exact image/checkpoint artifact set", key)
		}
	}
	fixture.env.Custody.RetireGenerated()
	cold, observed := Open(t.Context(), OpenContext{admission: &fixture.base.admission}, fixture.store)
	if cold == nil || observed.Outcome != ObservedCurrent || !bytes.Equal(cold.body, fixture.base.body) {
		t.Fatal("unselected checkpoint changed the old HEAD", observed)
	}
	checkpointFinalInFreshProcess(t, cold, fixture.store, expected)
	if *fixture.effects != 1 {
		t.Fatal("orphan-image retry repeated the original provider effect")
	}
}

type checkpointLostSelectionReplyStore struct {
	contract.Store
	committed bool
	cas       int
}

func (s *checkpointLostSelectionReplyStore) StoreConfiguration() contract.StoreConfiguration {
	return fixtureStoreConfiguration(s.Store)
}
func (s *checkpointLostSelectionReplyStore) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	s.cas++
	result := s.Store.CompareAndSwap(ctx, key, token, body)
	if result.Status == contract.WriteAcknowledged {
		s.committed = true
		return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
	}
	return result
}
func (s *checkpointLostSelectionReplyStore) Read(ctx context.Context, key string, maximum uint32) contract.ReadResult {
	if s.committed && key == s.Store.Descriptor().HeadKey {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
	}
	return s.Store.Read(ctx, key, maximum)
}

// full_only: false
func TestGeneratedFinalCheckpointLostSelectionReplyColdObservesExactFinal(t *testing.T) {
	fixture := newFinalizationCheckpointFixture(t)
	checkpoint, _ := selectCheckpointOnly(t, fixture)
	beforeReceipts, err := checkpoint.receiptWindows(t.Context())
	if err != nil {
		t.Fatal("lost Final predecessor receipt order", err)
	}
	parentOperation := checkpoint.root.Generated.ActiveOwner
	if parentOperation.IsZero() {
		t.Fatal("lost Final has no selected parent")
	}
	env := currentGeneratedEnvironment(t, fixture.store, checkpoint)
	prepared := prepareCheckpointFinal(t, env, checkpoint, "lost actual Final selection reply")
	candidate, result := checkpoint.ClaimGeneratedPreparation(t.Context(), prepared.reservation.candidate, env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("lost-reply actual Final claim", result)
	}
	artifacts := checkpointArtifactBodies(t, checkpoint, candidate)
	lost := &checkpointLostSelectionReplyStore{Store: fixture.store}
	checkpoint.store = lost
	selected, result := checkpoint.selectCandidate(t.Context(), candidate)
	checkpoint.store = fixture.store
	if selected != nil || !lost.committed || lost.cas != 1 || result.Outcome != UnresolvedCommit || !result.CommitMayHaveOccurred || result.RequestedRevision != candidate.head.Core.Revision {
		t.Fatal("lost actual Final reply did not preserve exact uncertainty", result, lost.cas)
	}
	env.Custody.RetireGenerated()
	cold, observed := Open(t.Context(), OpenContext{admission: &checkpoint.admission}, fixture.store)
	if cold == nil || observed.Outcome != ObservedCurrent || !bytes.Equal(cold.body, candidate.body) ||
		cold.root.ValueEntryCount != 2 || cold.root.Generated.GeneratedCurrent != 1 || !cold.root.Generated.ActiveOwner.IsZero() {
		t.Fatal("lost Final reply cold read did not observe the exact complete selected result", observed)
	}
	afterReceipts, err := cold.receiptWindows(t.Context())
	if err != nil || len(afterReceipts.Successes) != len(beforeReceipts.Successes)+1 || !slices.Equal(afterReceipts.Failures, beforeReceipts.Failures) || afterReceipts.Successes[len(afterReceipts.Successes)-1].OperationID != parentOperation {
		t.Fatal("cold lost Final did not select exactly its parent receipt append", err)
	}
	assertSuccessReceiptOrder(t, beforeReceipts, afterReceipts, parentOperation)
	creates, cas := fixture.store.creates, fixture.store.cas
	checkFreshGeneratedProcess(t, fixture.store, cold)
	later, laterResult := Open(t.Context(), OpenContext{admission: &checkpoint.admission}, fixture.store)
	if later == nil || laterResult.Outcome != ObservedCurrent {
		t.Fatal("later lost Final observation", laterResult)
	}
	assertGeneratedReceiptOrder(t, t.Context(), later, afterReceipts.Order)
	if fixture.store.creates != creates || fixture.store.cas != cas || *fixture.effects != 1 {
		t.Fatal("fresh lost-reply observation repeated persistence or provider effects")
	}
	for key, body := range artifacts {
		if object, ok := fixture.store.objects[key]; !ok || !bytes.Equal(object.Body, body) {
			t.Fatal("lost-reply observation changed an immutable actual Final artifact", key)
		}
	}
}

// full_only: false
func TestGeneratedFinalCheckpointSurvivesCurrentSignerAndKeyReplacement(t *testing.T) {
	fixture := newFinalizationCheckpointFixture(t)
	checkpoint, expected := selectCheckpointOnly(t, fixture)
	actual := &generatedActualOperation{env: fixture.sourceEnv, fixture: &environmentFixture{session: checkpoint, admission: OpenContext{admission: &checkpoint.admission}}}
	env := selectActualGeneratedLoss(t, actual, generatedActualLoss{name: "selected checkpoint signer and authority key", operation: contract.SuccessionReplaceAuthority,
		approval: contract.RecoverySigningRole, mask: contract.SuccessionChangeNormalSigner | contract.SuccessionChangeAuthorityKEK,
		targetRole: contract.SuccessorNormalSigner})
	replaced := actual.fixture.session
	work := mustSelectedGeneratedWork(t, replaced)
	if work.preparation == nil || work.preparation.Image.ContentID != expected.ImageID ||
		mustGeneratedPhaseID(work.preparation.MaterializationPhase) != expected.MaterializationPhaseID {
		t.Fatal("current signer/key replacement invalidated its exact historical checkpoint")
	}
	bindings, err := replaced.currentBindings()
	binding, bindingErr := contract.GeneratedFinalPreparationBindingDigest(currentControlOf(replaced), bindings)
	if err != nil || bindingErr != nil || work.preparation.ControlBindingDigest == binding {
		t.Fatal("replacement fixture did not invalidate only checkpoint reuse", err, bindingErr)
	}
	env.Custody.RetireGenerated()
	expected.Mode = "replace"
	checkpointFinalInFreshProcess(t, replaced, fixture.store, expected)
	if *fixture.effects != 1 {
		t.Fatal("replacement checkpoint repeated the original provider effect")
	}
}

// full_only: false
func TestGeneratedFinalCheckpointMissingImageStillAllowsAdministrativeEnd(t *testing.T) {
	fixture := newFinalizationCheckpointFixtureWithRetirement(t, true)
	checkpoint, expected := selectCheckpointOnly(t, fixture)
	work := mustSelectedGeneratedWork(t, checkpoint)
	retained := checkpoint.valueEntry(checkpoint.root.Names[0].Slot)
	independentDuty := retained.Generated.RetiringDutyID
	independentRecord, dutyPresent := work.records[generatedRecordKey{contract.GeneratedDutySupportKind, independentDuty}]
	if independentDuty.IsZero() || !dutyPresent || retained.Generated.RetiringDutyPresent != 1 {
		t.Fatal("missing-image End has no independent selected retirement obligation")
	}
	expectedAccess := slices.DeleteFunc(slices.Clone(checkpoint.accessRecords()), func(row contract.AccessRecord) bool {
		return row.MaterialKind == contract.OperationSeedMaterialKind && row.MaterialID == work.parent.MaterialID
	})
	// Selected fragment rows can intentionally keep opaque bodies. Read the
	// exact authenticated image through its physical selected-fragment reader
	// before simulating loss, then use validated metadata to locate its page.
	imageBody, err := work.readSelectedSlice(t.Context(), contract.GeneratorContentFinalPreparation, expected.ImageID, contract.GeneratedFinalPreparationMaxLength)
	if err != nil || len(imageBody) != int(work.preparation.Image.Length) || contract.Hash(imageBody) != expected.ImageID {
		t.Fatal("missing-image fixture did not qualify its exact physical backing", err)
	}
	fragments, err := checkpoint.selectedFragmentFactsByRecord()
	if err != nil {
		t.Fatal("missing-image fixture selected physical fragment facts", err)
	}
	imageRows := make(map[contract.ID]bool)
	for id, fragment := range fragments {
		if fragment.blob == expected.ImageID {
			imageRows[id] = true
		}
	}
	if len(imageRows) == 0 {
		t.Fatal("missing-image fixture has no authenticated physical image fragments")
	}
	var absent *format.Ref
	for _, page := range checkpoint.adminIndex.Pages {
		image := false
		for _, row := range page.Rows {
			image = image || row.Kind == contract.GeneratedFragmentSupportKind && imageRows[row.RecordID]
		}
		if !image {
			continue
		}
		mandatory := page.ReadRequired
		for _, span := range page.Spans {
			mandatory = mandatory || span.Mandatory
		}
		if !mandatory {
			ref := page.Ref
			absent = &ref
			break
		}
	}
	if absent == nil {
		t.Fatal("checkpoint has no administratively optional exact image backing page")
	}
	key, err := format.Key(fixture.store.desc.Prefix, *absent)
	if err != nil {
		t.Fatal(err)
	}
	original, present := fixture.store.objects[key]
	if !present || len(original.Body) == 0 {
		t.Fatal("missing-image boundary has no actual selected backing")
	}
	delete(fixture.store.objects, key)
	if ordinary, result := Open(t.Context(), OpenContext{admission: &checkpoint.admission}, fixture.store); ordinary != nil || result.Outcome != EvidenceUnavailable {
		t.Fatal("ordinary Final reader accepted missing selected preparation image", result)
	}
	admin, result := openAdministrative(t.Context(), OpenContext{admission: &checkpoint.admission}, fixture.store)
	if admin == nil || result.Outcome != ObservedCurrent || !bytes.Equal(admin.body, checkpoint.body) {
		t.Fatal("administrative reader required optional checkpoint image backing", result)
	}
	beforeEntries := checkpoint.currentEntryInputs()
	beforePages, beforeRecipients := checkpoint.root.ValueEntryPages, checkpoint.root.Recipients
	currentMaterial := checkpoint.valueEntry(checkpoint.root.Names[0].Slot).ValueState
	beforeMaterial, materialPresent := checkpoint.materialAccess(contract.ValueMaterialKind, currentMaterial)
	if !materialPresent {
		t.Fatal("missing-image fixture has no independently retained current value access")
	}
	public, private := fixture.env.Custody.Calls()
	end, result := prepareTestEndSelectedWork(t, admin, t.Context(), work.parent.OperationID, fixture.env.Trust)
	if end == nil || result.Outcome != ObservedCurrent || end.firstSend != nil {
		t.Fatal("End required missing optional checkpoint image", result)
	}
	ended, result := admin.selectCandidate(t.Context(), end)
	if ended == nil || result.Outcome != ObservedCurrent {
		t.Fatal("End checkpoint parent selection", result)
	}
	cold, result := Open(t.Context(), OpenContext{admission: &ended.admission}, fixture.store)
	if cold == nil {
		t.Fatal("End missing-image cold reader", result)
	}
	afterMaterial, materialPresent := cold.materialAccess(contract.ValueMaterialKind, currentMaterial)
	if !materialPresent || cold == nil || result.Outcome != ObservedCurrent || !bytes.Equal(cold.body, ended.body) ||
		!reflect.DeepEqual(cold.currentEntryInputs(), beforeEntries) || !reflect.DeepEqual(cold.root.ValueEntryPages, beforePages) ||
		!reflect.DeepEqual(cold.root.Recipients, beforeRecipients) || !reflect.DeepEqual(afterMaterial, beforeMaterial) ||
		!cold.root.Generated.ActiveOwner.IsZero() || cold.root.Generated.Retiring != 1 || len(cold.adminIndex.Groups) != 1 ||
		cold.adminIndex.Groups[0].GroupID != independentDuty || !reflect.DeepEqual(cold.accessRecords(), expectedAccess) || *fixture.effects != 1 {
		t.Fatal("End did not cold-reopen the exact retained current set without its owned checkpoint closure", result)
	}
	kept := mustSelectedGeneratedWork(t, cold)
	survivor, present := kept.records[generatedRecordKey{contract.GeneratedDutySupportKind, independentDuty}]
	if !present || !bytes.Equal(survivor.Body, independentRecord.Body) {
		t.Fatal("End changed the exact unrelated selected retirement Duty")
	}
	if kept.parent != nil || kept.phase != nil || kept.preparation != nil {
		t.Fatal("End retained selected preparation ownership")
	}
	if _, repaired := fixture.store.objects[key]; repaired {
		t.Fatal("End repaired optional missing image backing")
	}
	publicAfter, privateAfter := fixture.env.Custody.Calls()
	if publicAfter != public || privateAfter != private {
		t.Fatal("administrative End performed a provider private effect")
	}
	checkFreshGeneratedProcess(t, fixture.store, cold)
}

// full_only: false
func TestGeneratedFinalCheckpointReplaysChangedSuppliedSecretAfterSigningLoss(t *testing.T) {
	fixture := newFinalizationCheckpointFixtureWithChangedSupplied(t, false, true)
	before := fixture.base.valueEntry(fixture.base.root.Names[0].Slot)
	beforePayload, err := contract.InspectCanonicalPayload(before.ValueBytes)
	if err != nil || before.ValueSource != contract.Supplied || beforePayload.ContentLength == 0 {
		t.Fatal("mixed replay fixture did not start with the independently known nonempty supplied value", err)
	}
	checkpoint, expected := selectCheckpointOnly(t, fixture)
	work := mustSelectedGeneratedWork(t, checkpoint)
	body, err := work.readSelectedSlice(t.Context(), contract.GeneratorContentFinalPreparation, expected.ImageID, contract.GeneratedFinalPreparationMaxLength)
	if err != nil {
		t.Fatal("mixed replay selected encrypted image", err)
	}
	image, err := contract.DecodeGeneratedFinalPreparationImage(body)
	if err != nil {
		t.Fatal("mixed replay selected image codec", err)
	}
	defer image.Clear()
	if len(image.Generated) != 1 || len(image.Supplied) != 1 || image.Supplied[0].Name != before.Name {
		t.Fatal("mixed checkpoint did not retain both actual encrypted prepared row kinds")
	}
	preparedSupplied := image.Supplied[0]
	entry, err := contract.DecodeValueEntry(preparedSupplied.EntryBytes)
	payload, payloadErr := contract.InspectCanonicalPayload(entry.ValueBytes)
	access, accessErr := contract.InspectAccessRecord(preparedSupplied.AccessRecord)
	if err != nil || payloadErr != nil || accessErr != nil || entry.ValueSource != contract.Supplied || entry.ConfidentialityClass != contract.Secret ||
		entry.Incarnation != before.Incarnation || entry.ValueState == before.ValueState || payload.ContentLength != 0 ||
		payload.DataKeyID == beforePayload.DataKeyID || payload.CommitmentKeyID == beforePayload.CommitmentKeyID ||
		bytes.Equal(entry.ValueBytes, before.ValueBytes) || access.WrapCount() == 0 {
		t.Fatal("mixed replay image omitted fresh supplied key identities, random AEAD or wrapped access", err, payloadErr, accessErr)
	}
	env := currentGeneratedEnvironment(t, fixture.store, checkpoint)
	prepared := prepareCheckpointFinal(t, env, checkpoint, "mixed actual Final signing loss")
	expected.Artifacts = checkpointArtifactBodies(t, checkpoint, prepared.reservation.candidate)
	cas := fixture.store.cas
	checkpointSigningUnavailable(t, env, true)
	candidate, result := checkpoint.ClaimGeneratedPreparation(t.Context(), prepared.reservation.candidate, env.Trust)
	checkpointSigningUnavailable(t, env, false)
	if candidate != nil || result.Outcome != EvidenceUnavailable || result.Reason != SigningUnavailable || fixture.store.cas != cas {
		t.Fatal("mixed actual Final did not stop after immutable writes before signing", result)
	}
	accessPages, valuePages := 0, 0
	for _, object := range prepared.reservation.candidate.objects {
		key, err := format.Key(fixture.store.desc.Prefix, object.ref)
		read := fixture.store.Read(t.Context(), key, object.ref.Length)
		if err != nil || read.Status != contract.ReadOK || !bytes.Equal(read.Body, object.body) {
			t.Fatal("mixed signing loss did not retain the exact immutable artifact", err)
		}
		if object.ref.Kind == format.AccessKind {
			accessPages++
		}
		if object.ref.Kind == format.ValueEntryPageKind {
			valuePages++
		}
	}
	if accessPages == 0 || valuePages == 0 {
		t.Fatal("mixed signing loss missed the access/value artifact boundary")
	}
	env.Custody.RetireGenerated()
	cold, observed := Open(t.Context(), OpenContext{admission: &checkpoint.admission}, fixture.store)
	if cold == nil || observed.Outcome != ObservedCurrent || !bytes.Equal(cold.body, checkpoint.body) {
		t.Fatal("mixed interrupted Final changed checkpoint selection", observed)
	}
	selected := checkpointFinalInFreshProcess(t, cold, fixture.store, expected)
	selection := sessionConsumerSelection(t, selected, selected.admission.recipient, "kept")
	selectedBody, err := contract.EncodeValueEntry(selection.Entry)
	selectedAccess, accessErr := contract.EncodeAccessRecord(selection.Access)
	if err != nil || accessErr != nil || !bytes.Equal(selectedBody, preparedSupplied.EntryBytes) ||
		!bytes.Equal(selectedAccess, preparedSupplied.AccessRecord) || *fixture.effects != 1 {
		t.Fatal("fresh mixed Final changed the durable supplied random image or repeated its original effect", err, accessErr)
	}
	check := currentGeneratedEnvironment(t, fixture.store, selected).readerConsume(selection, custody.EmptyValue)
	if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched || check.SinkCalls != 1 {
		t.Fatal("fresh mixed Final did not deliver the independently expected changed supplied meaning", check)
	}
}

// recommitCheckpointAssociationFixture changes only the local test Store copy.
// Every changed physical object, root, conditional identity and signed subject
// is re-committed; corrupt bytes or an invalid signature cannot explain refusal.
func recommitCheckpointAssociationFixture(t *testing.T, fixture finalizationCheckpointFixture, checkpoint *StateSession, condition string) *memoryStore {
	t.Helper()
	return recommitCheckpointImageFixture(t, fixture, checkpoint, condition, nil)
}

// The retained-reader regression also changes the supplied image while keeping
// this one owner for all physical association, index and signature mechanics.
func recommitCheckpointImageFixture(t *testing.T, fixture finalizationCheckpointFixture, checkpoint *StateSession, condition string,
	edit func(*contract.GeneratedFinalPreparationImage)) *memoryStore {
	t.Helper()
	bad := *checkpoint
	bad.support = slices.Clone(checkpoint.support)
	for i := range bad.support {
		bad.support[i].Records = slices.Clone(checkpoint.support[i].Records)
	}
	generatedMaterializeFixtureSupport(t, &bad)
	work := mustSelectedGeneratedWork(t, checkpoint)
	record, phase := *work.preparation, *work.phase
	imageBody, err := work.readSelectedSlice(t.Context(), contract.GeneratorContentFinalPreparation, record.Image.ContentID, contract.GeneratedFinalPreparationMaxLength)
	if err != nil {
		t.Fatal("association fixture selected image", err)
	}
	image, err := contract.DecodeGeneratedFinalPreparationImage(imageBody)
	if err != nil {
		t.Fatal("association fixture image", err)
	}
	defer image.Clear()
	switch condition {
	case "valid":
	case "phase-image":
		phase.FinalPreparationID = testID("wrong exact selected image association")
	case "image-materialization":
		image.MaterializationPhaseID = testID("wrong original image materialization phase")
	case "image-bindings":
		image.ControlBindingDigest = testID("wrong original image binding context")
	case "different-prepared-result":
		image.Generated[0].ResultDigest[0] ^= 1
	case "private-sibling-ciphertext":
		payload, err := contract.InspectCanonicalPayload(image.Generated[0].Entry.ValueBytes)
		if err != nil || len(payload.Ciphertext) == 0 {
			t.Fatal("private sibling ciphertext fixture", err)
		}
		payload.Ciphertext[len(payload.Ciphertext)-1] ^= 1
	case "private-sibling-authority-wrap":
		wraps := image.Generated[0].Access.Wraps
		authority := slices.IndexFunc(wraps, func(wrap contract.WrapRow) bool {
			return wrap.SubjectKind == contract.OrdinaryWrapSubject && wrap.SubjectID == checkpoint.admission.recipient
		})
		if authority < 0 || len(wraps[authority].RSACiphertext) == 0 {
			t.Fatal("private sibling Authority packet fixture")
		}
		wraps[authority].RSACiphertext[0] ^= 1
	case "last-two-steps", "last-step", "exhausted":
		counter := ^uint32(0)
		if condition == "last-two-steps" {
			counter -= 2
		}
		if condition == "last-step" {
			counter--
		}
		record.MaterializationPhase.BeforePhase, record.MaterializationPhase.AfterPhase = counter-1, counter
		phase.Phase = counter
		image.MaterializationPhaseID, err = contract.GeneratorPhaseID(record.MaterializationPhase)
		if err != nil {
			t.Fatal(err)
		}
		for i := range image.Generated {
			row := &image.Generated[i]
			attempt := slices.IndexFunc(work.bundles[0].Lineages, func(lineage contract.GeneratorLineageTemplate) bool {
				for _, template := range lineage.Templates[:lineage.TemplateCount] {
					if template.ResultID == row.ResultID {
						return true
					}
				}
				return false
			})
			if attempt < 0 {
				t.Fatal("synthetic counter result has no exact template")
			}
			var slot contract.ID
			lineage := work.bundles[0].Lineages[attempt]
			for _, template := range lineage.Templates[:lineage.TemplateCount] {
				if template.ResultID == row.ResultID {
					slot = template.PlannedValueSlotID
				}
			}
			binding, bindingErr := contract.GeneratedBindingDigest(row.Entry.Generated)
			identity, identityErr := contract.DeriveGeneratedValueIdentity(slot, image.MaterializationPhaseID, row.ResultID, binding)
			if bindingErr != nil || identityErr != nil {
				t.Fatal("synthetic phase-bound entry", bindingErr, identityErr)
			}
			row.ValueCore.ValueStateID, row.ValueCore.OriginSnapshotID, row.ValueCore.OriginTransitionID = identity.ValueStateID, identity.OriginSnapshotID, identity.OriginTransitionID
			row.ValueCore.DataKeyID, row.ValueCore.CommitmentKeyID = identity.DataKeyID, identity.CommitmentKeyID
			row.Entry.ValueState, row.Entry.OriginSnapshot, row.Entry.OriginTransition = identity.ValueStateID, identity.OriginSnapshotID, identity.OriginTransitionID
			row.Entry.Generated.GenerationID = identity.ValueStateID
			payload, payloadErr := contract.DecodeCanonicalPayload(row.Entry.ValueBytes)
			if payloadErr != nil {
				t.Fatal(payloadErr)
			}
			payload.DataKeyID, payload.CommitmentKeyID = identity.DataKeyID, identity.CommitmentKeyID
			row.Entry.ValueBytes, err = contract.EncodeCanonicalPayload(payload)
			if err != nil {
				t.Fatal(err)
			}
			row.Access.MaterialID = identity.ValueStateID
			row.Access.MaterialContextDigest, err = contract.ValueMaterialContextDigest(row.ValueCore)
			if err != nil {
				t.Fatal(err)
			}
		}
	default:
		t.Fatal("unknown association fixture condition")
	}
	if edit != nil {
		edit(&image)
	}
	imageBody, err = contract.EncodeGeneratedFinalPreparationImage(image)
	if err != nil {
		t.Fatal("well-formed association image", err)
	}
	oldImage := record.Image.ContentID
	newImage := contract.Hash(imageBody)
	record.Image.ContentID, record.Image.Digest, record.Image.Length = newImage, newImage, uint32(len(imageBody))
	if condition != "phase-image" {
		phase.FinalPreparationID = newImage
	}
	checkpointPhase := record.MaterializationPhase
	checkpointPhase.TransitionKind = contract.GeneratorAuthorityFinalPreparation
	checkpointPhase.Evidence, err = contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{record.Image})
	if err != nil {
		t.Fatal("association fixture checkpoint evidence", err)
	}
	phaseID, err := contract.GeneratorPhaseID(checkpointPhase)
	if err != nil {
		t.Fatal("association fixture checkpoint identity", err)
	}
	phase.PhaseID = phaseID
	bad.root.Snapshot, err = contract.GeneratorPhaseSnapshotID(phaseID)
	if err != nil {
		t.Fatal(err)
	}
	bad.root.Transition, err = contract.GeneratorPhaseTransitionID(phaseID)
	if err != nil {
		t.Fatal(err)
	}
	bad.root.Generated.ActivePhase = phaseID
	locations, err := checkpoint.resolveSelectedGeneratedSlices()
	if err != nil {
		t.Fatal("association fixture selected slices", err)
	}
	locations = slices.Clone(locations)
	for i := range locations {
		if locations[i].ContentKind == contract.GeneratorContentFinalPreparation && locations[i].ContentID == oldImage {
			locations[i].ContentID, locations[i].BlobID, locations[i].Digest, locations[i].Length = newImage, newImage, newImage, uint32(len(imageBody))
		}
	}
	slices.SortFunc(locations, func(a, b contract.GeneratorSliceLocation) int {
		if a.ContentKind != b.ContentKind {
			return int(a.ContentKind) - int(b.ContentKind)
		}
		return bytes.Compare(a.ContentID[:], b.ContentID[:])
	})
	var sliceBodies [][]byte
	for _, location := range locations {
		body, err := contract.EncodeGeneratorSliceLocation(location)
		if err != nil {
			t.Fatal("association fixture exact location", err)
		}
		sliceBodies = append(sliceBodies, body)
	}
	descriptor, carriers, err := generatedCarrierRows(bad.root.Domain, contract.GeneratorSnapshotOwner, bad.root.Snapshot, contract.GeneratorVectorSlices, sliceBodies)
	if err != nil {
		t.Fatal("association fixture exact slice directory", err)
	}
	bad.root.Generated.Slices = descriptor
	rows := slices.DeleteFunc(bad.supportRecords(), func(row contract.SupportRecord) bool {
		if row.Kind == contract.GeneratedPhaseSupportKind && row.RecordID == record.OperationID || row.Kind == contract.GeneratedFinalPreparationSupportKind && row.RecordID == record.OperationID {
			return true
		}
		if row.Kind == contract.GeneratedFragmentSupportKind {
			fragment, err := contract.InspectGeneratedFragment(row.Body)
			if err != nil {
				t.Fatal("association fixture original fragment", err)
			}
			return fragment.BlobID == oldImage
		}
		if row.Kind == contract.GeneratorVectorSupportKind {
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				t.Fatal("association fixture original carrier", err)
			}
			return carrier.OwnerKind == contract.GeneratorSnapshotOwner && carrier.VectorKind == contract.GeneratorVectorSlices
		}
		return false
	})
	phaseBody, err := contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil {
		t.Fatal("well-formed selected phase association", err)
	}
	recordBody, err := contract.EncodeGeneratedFinalPreparationRecord(record)
	if err != nil {
		t.Fatal("well-formed image descriptor", err)
	}
	fragments, err := generatedFragmentRows(newImage, imageBody)
	if err != nil {
		t.Fatal("association fixture replacement fragments", err)
	}
	rows = append(rows, carriers...)
	rows = append(rows, fragments...)
	rows = append(rows, contract.SupportRecord{Kind: contract.GeneratedPhaseSupportKind, RecordID: record.OperationID, Body: phaseBody},
		contract.SupportRecord{Kind: contract.GeneratedFinalPreparationSupportKind, RecordID: record.OperationID, Body: recordBody})
	bad.clearSelectedSupportFacts()
	generatedRepackSupportAtLocations(t, &bad, rows, work.bundles, locations)
	for i := range bad.support {
		bad.support[i].Object, err = contract.GeneratorPhasePageID(phaseID, contract.RequiredSupportKind, bad.support[i].Index)
		if err != nil {
			t.Fatal("association fixture admitted page identity", err)
		}
	}
	generatedRefreshSupport(t, &bad, work.bundles...)
	generatedVerifySelectedFixtureSlices(t, &bad)
	store := cloneCheckpointStore(fixture.store)
	put := func(ref format.Ref, body []byte) {
		t.Helper()
		if err := format.CheckReference(ref, body); err != nil {
			t.Fatal("association fixture physical commitment", err)
		}
		key, err := format.Key(store.desc.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		store.put(key, body)
	}
	for i, page := range bad.support {
		pageRows := make([]contract.SupportRecord, len(page.Records))
		for j, row := range page.Records {
			pageRows[j] = contract.SupportRecord(row)
		}
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: pageRows})
		if err != nil {
			t.Fatal("association fixture support frame", err)
		}
		put(bad.root.RequiredSupport[i], body)
	}
	shards, err := format.EncodeAdministrativeIndexPages(bad.adminIndex)
	if err != nil {
		t.Fatal("association fixture authenticated index", err)
	}
	for _, shard := range shards {
		put(shard.Ref, shard.Body)
	}
	rootBody, err := format.EncodeRoot(bad.root)
	if err != nil {
		t.Fatal("association fixture encoded root", err)
	}
	rootRef, err := format.Reference(format.RootKind, bad.root.Domain, bad.root.Snapshot, 0, rootBody)
	if err != nil {
		t.Fatal("association fixture root reference", err)
	}
	put(rootRef, rootBody)
	head := checkpoint.head
	subject := *head.Generator
	head.Generator = &subject
	head.Core.Root = rootRef
	head.Core.Revision, err = contract.GeneratorPhaseRevisionID(phaseID)
	if err != nil {
		t.Fatal(err)
	}
	subject.PhaseID, subject.ResultVector, subject.AfterRootDigest = phaseID, checkpointPhase.Evidence, rootRef.Digest
	afterWork, err := bad.workSupportRecords(t.Context())
	if err != nil {
		t.Fatal("association fixture complete changed work support", err)
	}
	subject.AfterWork, err = bad.workSupportDescriptor(afterWork)
	if err != nil {
		t.Fatal("association fixture changed work descriptor", err)
	}
	subject.BeforePhase, subject.AfterPhase = record.MaterializationPhase.BeforePhase, record.MaterializationPhase.AfterPhase
	identity := contract.IdentityPlan{Operation: record.OperationID, Snapshot: bad.root.Snapshot, Transition: bad.root.Transition, Revision: head.Core.Revision}
	for _, ref := range bad.root.RequiredSupport {
		identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
	}
	subject.IdentityPlan, err = contract.GeneratorAuthorityIdentityDescriptor(identity)
	if err != nil {
		t.Fatal("association fixture exact signed identity plan", err)
	}
	coreBody, err := format.EncodeHeadCore(head.Core)
	if err != nil {
		t.Fatal(err)
	}
	conditionalBody, err := format.EncodeConditionalPlan(conditional(head.Core, coreBody))
	if err != nil {
		t.Fatal(err)
	}
	subject.HeadCoreDigest, subject.HeadCoreLength = contract.Hash(coreBody), uint32(len(coreBody))
	subject.ConditionalPlanDigest, subject.ConditionalLength = contract.Hash(conditionalBody), uint32(len(conditionalBody))
	request, err := contract.NewGeneratorRequest(subject)
	if err != nil {
		t.Fatal("association fixture exact signing request", err)
	}
	proof := fixture.env.Trust.Sign(t.Context(), request)
	if proof.Reason != contract.ReasonNone || len(proof.Signature) == 0 {
		t.Fatal("association fixture actual known-role signature", proof.Reason)
	}
	head.AuthorizationSignature = proof.Signature
	if !checkpoint.verifyHeadProofs(head, currentControlOf(checkpoint)) {
		t.Fatal("association fixture did not pass independent signature qualification")
	}
	headBody, err := format.EncodeHead(head)
	if err != nil {
		t.Fatal(err)
	}
	store.put(store.desc.HeadKey, headBody)
	return store
}

// full_only: false
func TestGeneratedFinalCheckpointColdReaderRefusesSignedAssociationMismatch(t *testing.T) {
	fixture := newFinalizationCheckpointFixture(t)
	checkpoint, _ := selectCheckpointOnly(t, fixture)
	for _, condition := range []string{"valid", "phase-image", "image-materialization", "image-bindings"} {
		t.Run(condition, func(t *testing.T) {
			store := recommitCheckpointAssociationFixture(t, fixture, checkpoint, condition)
			public, private := fixture.env.Custody.Calls()
			creates, cas := store.creates, store.cas
			selected, result := Open(t.Context(), OpenContext{admission: &checkpoint.admission}, store)
			if condition == "valid" {
				if selected == nil || result.Outcome != ObservedCurrent {
					t.Fatal("fully re-committed association positive control did not cold-open", result)
				}
			} else if selected != nil || result.Outcome != IntegrityFailure || result.Reason != InvalidRelation {
				t.Fatal("cold ordinary reader accepted inconsistent signed checkpoint association", result)
			}
			publicAfter, privateAfter := fixture.env.Custody.Calls()
			if publicAfter != public || privateAfter != private || store.creates != creates || store.cas != cas || *fixture.effects != 1 {
				t.Fatal("ordinary association qualification reached private/provider effects or persistence")
			}
		})
	}
}

package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"runtime"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// The signed counter image keeps the selected Generated authority subject.
// Its existing request and predecessor remain unchanged; only the new Root
// reference and the HEAD-core/conditional-plan bindings are re-signed.
func signedGeneratedCounterRoot(t *testing.T, env fixtureEnvironment, before *StateSession, root format.Root) *StateSession {
	t.Helper()
	ctx := t.Context()
	store := env.Store.(*memoryStore)
	if before.head.Generator == nil || before.head.AuthKind != format.GeneratorAuth || before.head.Core.Root.Domain != root.Domain {
		t.Fatal("counter fixture requires a selected Generated authority HEAD")
	}
	accessRoot, err := contract.AccessRoot(root.CurrentAccess.Core)
	if err != nil {
		t.Fatal("counter AccessRoot", err)
	}
	root.CurrentAccess.AccessRoot = accessRoot
	rootBody, err := format.EncodeRoot(root)
	if err != nil {
		t.Fatal("counter Root encoding", err)
	}
	ref, err := format.Reference(format.RootKind, root.Domain, root.Snapshot, 0, rootBody)
	if err != nil {
		t.Fatal(err)
	}
	key, err := format.Key(store.desc.Prefix, ref)
	if err != nil {
		t.Fatal(err)
	}
	store.put(key, rootBody)
	head := before.head
	subject := *head.Generator
	head.Generator = &subject
	head.Core.Root = ref
	core, err := format.EncodeHeadCore(head.Core)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := format.EncodeConditionalPlan(conditional(head.Core, core))
	if err != nil {
		t.Fatal(err)
	}
	subject.AfterRootDigest = ref.Digest
	subject.AfterAccessDigest = root.CurrentAccess.AccessRoot
	subject.HeadCoreDigest, subject.HeadCoreLength = contract.Hash(core), uint32(len(core))
	subject.ConditionalPlanDigest, subject.ConditionalLength = contract.Hash(plan), uint32(len(plan))
	request, err := contract.NewGeneratorRequest(subject)
	if err != nil {
		t.Fatal("counter Generated authority request", err)
	}
	signed := env.Trust.Sign(ctx, request)
	if signed.Reason != contract.ReasonNone || len(signed.Signature) == 0 {
		t.Fatal("counter Generated authority signature", signed.Reason)
	}
	head.AuthorizationSignature = signed.Signature
	headBody, err := format.EncodeHead(head)
	if err != nil {
		t.Fatal("counter Generated HEAD", err)
	}
	store.put(store.desc.HeadKey, headBody)
	opened, result := Open(ctx, OpenContext{admission: &before.admission}, store)
	if opened == nil || result.Outcome != ObservedCurrent {
		t.Fatal("signed counter image did not ordinary cold Open", result)
	}
	return opened
}

// The phase fixture starts from a real selected Record. It gives that same
// recorded evidence a maximum phase identity and rebuilds every derived page.
func signedMaximumGeneratedPhase(t *testing.T, env fixtureEnvironment, selected *StateSession) *StateSession {
	t.Helper()
	ctx := t.Context()
	store := env.Store.(*memoryStore)
	work := mustSelectedGeneratedWork(t, selected)
	if work.parent == nil || work.phase == nil || selected.head.Generator == nil ||
		selected.head.Generator.BeforePhase == 0 || selected.head.Generator.ResultDigest.IsZero() {
		t.Fatal("maximum-phase fixture needs a real selected Record predecessor")
	}
	subject := *selected.head.Generator
	attempt, ok := work.attempts[subject.AttemptID]
	if !ok || len(attempt.result) == 0 || contract.Hash(attempt.result) != subject.ResultDigest {
		t.Fatal("maximum-phase fixture lost the actual recorded result")
	}
	subject.BeforePhase, subject.AfterPhase = math.MaxUint32-1, math.MaxUint32
	phaseID, err := contract.GeneratorPhaseID(contract.GeneratorPhaseIdentity{RequestIdentityDigest: subject.RequestIdentityDigest,
		ObservedHEADDigest: subject.PreviousHEADDigest, ConditionDigest: subject.ConditionDigest, TransitionKind: subject.Purpose,
		BeforePhase: subject.BeforePhase, AfterPhase: subject.AfterPhase,
		Evidence: contract.GeneratorDescriptor{Digest: subject.ResultDigest, Length: uint64(len(attempt.result)), Count: 1}})
	if err != nil {
		t.Fatal("maximum Phase identity", err)
	}
	phase := *work.phase
	phase.Phase, phase.PhaseID = math.MaxUint32, phaseID
	body, err := contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil {
		t.Fatal("maximum Phase row encoding", err)
	}
	generatedMaterializeFixtureSupport(t, selected)
	rows := selected.supportRecords()
	var replaced bool
	for i, row := range rows {
		if row.Kind == contract.GeneratedPhaseSupportKind && row.RecordID == phase.OperationID {
			rows[i].Body, replaced = body, true
		}
	}
	if !replaced {
		t.Fatal("maximum Phase row was not selected")
	}
	next := *selected
	next.root.Snapshot, err = contract.GeneratorPhaseSnapshotID(phaseID)
	if err != nil {
		t.Fatal(err)
	}
	next.root.Transition, err = contract.GeneratorPhaseTransitionID(phaseID)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := contract.GeneratorPhaseRevisionID(phaseID)
	if err != nil {
		t.Fatal(err)
	}
	rows, err = rebindSnapshotSliceRecords(rows, selected.root.Domain, selected.adminIndex.SliceSnapshot, next.root.Snapshot)
	if err != nil {
		t.Fatal("maximum Phase snapshot carriers", err)
	}
	locations, err := selected.resolveSelectedGeneratedSlices()
	if err != nil {
		t.Fatal("maximum Phase predecessor Slice locations", err)
	}
	groups, err := generatedReservationGroupsWithSource(&next, selected, rows, locations, work.bundles)
	if err != nil {
		t.Fatal("maximum Phase authenticated ownership", err)
	}
	next.root.RequiredSupport, next.support = nil, nil
	next.root.Generated.ActivePhase = phaseID
	generatedRefreshClosureCounts(&next.root.Generated, rows)
	next.recountChildren()
	fragments, err := selected.selectedFragmentFactsByRecord()
	if err != nil {
		t.Fatal("maximum Phase predecessor fragment facts", err)
	}
	packed, err := generatedSupportPages(selected.root.Domain, groups, next.root.ChildCount, fragments)
	if err != nil {
		t.Fatal("maximum Phase support packing", err)
	}
	physicalIndexes, err := selected.generatedSupportPhysicalIndexes(packed)
	if err != nil {
		t.Fatal("maximum Phase physical page indexes", err)
	}
	pageIDs := make([]contract.ID, len(packed))
	for i := range pageIDs {
		pageIDs[i], err = contract.GeneratorPhasePageID(phaseID, contract.RequiredSupportKind, physicalIndexes[i])
		if err != nil {
			t.Fatal("maximum Phase page identity", err)
		}
	}
	materialized, err := selected.materializeGeneratedSupportPages(ctx, packed, pageIDs)
	if err != nil {
		t.Fatal("maximum Phase selected support materialization", err)
	}
	next.root.RequiredSupport, next.support = materialized.references, materialized.views
	next.root.RequiredSupportRecordCount, next.root.Generated.Fragments = materialized.recordCount, materialized.fragments
	next.clearSelectedSupportFacts()
	candidate := &Candidate{session: selected, objects: materialized.objects}
	if err := selected.installAdministrativeIndex(ctx, &next, candidate); err != nil {
		t.Fatal("maximum Phase administrative index", err)
	}
	identity := contract.IdentityPlan{Operation: subject.OperationID, Snapshot: next.root.Snapshot, Transition: next.root.Transition,
		Revision: revision, Pages: materialized.identityPages}
	subject.IdentityPlan, err = contract.GeneratorAuthorityIdentityDescriptor(identity)
	if err != nil {
		t.Fatal("maximum Phase identity plan", err)
	}
	afterRows, err := next.workSupportRecords(ctx)
	if err != nil {
		t.Fatal("maximum Phase selected work", err)
	}
	subject.AfterWork, err = next.workSupportDescriptor(afterRows)
	if err != nil {
		t.Fatal("maximum Phase selected work descriptor", err)
	}
	for _, object := range candidate.objects {
		key, err := format.Key(store.desc.Prefix, object.ref)
		if err != nil {
			t.Fatal(err)
		}
		store.put(key, object.body)
	}
	rootBody, err := format.EncodeRoot(next.root)
	if err != nil {
		t.Fatal("maximum Phase Root encoding", err)
	}
	rootRef, err := format.Reference(format.RootKind, next.root.Domain, next.root.Snapshot, 0, rootBody)
	if err != nil {
		t.Fatal(err)
	}
	rootKey, err := format.Key(store.desc.Prefix, rootRef)
	if err != nil {
		t.Fatal(err)
	}
	store.put(rootKey, rootBody)
	head := selected.head
	head.Core.Revision, head.Core.Root = revision, rootRef
	core, err := format.EncodeHeadCore(head.Core)
	if err != nil {
		t.Fatal(err)
	}
	conditionalBody, err := format.EncodeConditionalPlan(conditional(head.Core, core))
	if err != nil {
		t.Fatal(err)
	}
	subject.PhaseID, subject.AfterRootDigest = phaseID, rootRef.Digest
	subject.HeadCoreDigest, subject.HeadCoreLength = contract.Hash(core), uint32(len(core))
	subject.ConditionalPlanDigest, subject.ConditionalLength = contract.Hash(conditionalBody), uint32(len(conditionalBody))
	request, err := contract.NewGeneratorRequest(subject)
	if err != nil {
		t.Fatal("maximum Phase authority request", err)
	}
	signed := env.Trust.Sign(ctx, request)
	if signed.Reason != contract.ReasonNone || len(signed.Signature) == 0 {
		t.Fatal("maximum Phase authority signature", signed.Reason)
	}
	head.Generator = &subject
	head.AuthorizationSignature = signed.Signature
	headBody, err := format.EncodeHead(head)
	if err != nil {
		t.Fatal("maximum Phase HEAD encoding", err)
	}
	store.put(store.desc.HeadKey, headBody)
	opened, result := Open(ctx, OpenContext{admission: &selected.admission}, store)
	if opened == nil || result.Outcome != ObservedCurrent {
		t.Fatal("maximum Phase image did not ordinary cold Open", result)
	}
	got := mustSelectedGeneratedWork(t, opened)
	if got.parent == nil || got.parent.OperationID != phase.OperationID || got.phase == nil || got.phase.Phase != math.MaxUint32 ||
		opened.root.Generated.ActiveOwner != phase.OperationID || opened.root.Generated.ActivePhase != phase.PhaseID {
		t.Fatal("signed maximum Phase did not ordinary cold Open with the same parent")
	}
	return opened
}

// The owner-delivered basis remains signed by the original authorizer. Rebind
// its selected current signer to the maximum epoch before any Generated work.
func signedMaximumSigningBasis(t *testing.T) (*currentBasisFixture, *StateSession) {
	t.Helper()
	ctx := t.Context()
	f := newCurrentBasisFixture(t, contract.GCP, false)
	f.control.NormalSigning.Binding.Epoch = math.MaxUint64
	f.root.CurrentAccess.Core.CurrentControl = f.control.CurrentControl
	var err error
	f.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(f.root.CurrentAccess.Core)
	if err != nil {
		t.Fatal("maximum signer access root", err)
	}
	f.head.Core.Epoch = math.MaxUint64
	subject := &f.head.Succession.Subject
	subject.AfterControlDigest, err = contract.ControlCoreDigest(f.control)
	if err != nil {
		t.Fatal("maximum signer control digest", err)
	}
	subject.AfterAccessRoot = f.root.CurrentAccess.AccessRoot
	digest, err := contract.SigningBindingDigest(f.control.NormalSigning)
	if err != nil {
		t.Fatal("maximum signer binding digest", err)
	}
	row := &f.head.Succession.Evidence[0]
	row.Trust.SigningBindingDigest = digest
	probe, err := contract.NewSuccessorSignerProbeRequest(contract.SuccessorProbeCore{Schema: 1,
		EvidenceKind: contract.SuccessorSignerEvidence, TargetRole: contract.SuccessorNormalSigner,
		DomainID: f.head.Core.Domain, CoordinateID: f.head.Core.Coordinate,
		AdmissionID: subject.AdmissionID, PredecessorFullHEADDigest: f.head.Core.PreviousDigest,
		RequestCoreDigest: subject.RequestCoreDigest, SuccessorBindingDigest: digest,
		ProbeAttemptID: row.Trust.ProbeAttemptID})
	if err != nil {
		t.Fatal("maximum signer successor probe", err)
	}
	row.Trust.Signature = currentBasisSign(t, f.successor, probe, nil)
	subject.SuccessorEvidenceDigest, err = contract.SuccessorEvidenceDigest(f.head.Succession.Evidence)
	if err != nil {
		t.Fatal("maximum signer evidence", err)
	}
	f.signK1(t)
	f.storeRootAndHead(t)
	control, err := contract.EncodeControlCore(f.control)
	if err != nil {
		t.Fatal("maximum signer delivered control", err)
	}
	selection, err := format.EncodeHead(f.head)
	if err != nil {
		t.Fatal("maximum signer delivered selection", err)
	}
	admitted := *f.current.admission
	admitted.epoch = math.MaxUint64
	admitted.current = f.current.admission.current.clone()
	admitted.current.control, admitted.current.selection = control, selection
	f.current = OpenContext{admission: &admitted}
	opened, result := Open(ctx, f.current, f.env.Store)
	if opened == nil || result.Outcome != ObservedCurrent ||
		opened.head.Core.Epoch != math.MaxUint64 || opened.root.CurrentAccess.Core.NormalSigning.Binding.Epoch != math.MaxUint64 {
		t.Fatal("signed maximum signer basis did not ordinary cold Open", result)
	}
	// The basis fixture initialized this coordinate but did not enter further
	// private work. Close its actual initialization admission before the Plan.
	f.env.RetireInit()
	f.env.Context, f.env.Trust = ctx, f.successor
	return f, opened
}

// The fixture's selected attempts and admitted action plans establish whether
// any Delete reached transmission. Owner names and administrative flags do not.
func assertEndWorkSelectedDeletePermissionCount(t *testing.T, state *StateSession, want int) {
	t.Helper()
	work := mustSelectedGeneratedWork(t, state)
	got := 0
	for _, attempt := range work.attempts {
		if attempt.expected.Template.Action == contract.GeneratorActionDelete &&
			attempt.record.State >= contract.GeneratedEffectTransmitted {
			got++
		}
	}
	if got != want {
		t.Fatalf("selected Delete permissions: got %d, want %d", got, want)
	}
}

// full_only: false
func TestEndWorkAtMaximumSigningEpochPermitsSuccessorIncarnation(t *testing.T) {
	ctx := t.Context()
	f, before := signedMaximumSigningBasis(t)
	env := f.env
	profile := defaultGeneratedFixtureProfile()
	firstOperation := fixtureID(env.Domain, "maximum signer first generation")
	first := selectPrivateGeneratedOperationInProcess(t, env, before,
		generatedPlanInputForGenerations(t, before, firstOperation, []string{"kept"}, profile), "maximum signer first generation")
	first = generatedLifecycleReopen(t, ctx, first, env.Store)
	old := *first.valueEntry(0)
	if old.Name != "kept" || old.ValueSource != contract.Generated || old.Generated.Epoch != 0 {
		t.Fatal("maximum signer first generation was not current")
	}
	secondOperation := fixtureID(env.Domain, "maximum signer second generation")
	second := selectPrivateGeneratedOperationInProcess(t, env, first,
		generatedStatePlanInput(t, first, secondOperation, []string{old.Name}, profile, old.Generated.Epoch+1,
			map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: old}),
		"maximum signer second generation")
	second = generatedLifecycleReopen(t, ctx, second, env.Store)
	dutyID, err := contract.GeneratorDutyID(second.root.Domain, old.Generated.OriginOperationID, old.Generated.OriginAttemptID, 2)
	if err != nil || len(second.adminIndex.Groups) != 1 || second.adminIndex.Groups[0].GroupID != dutyID ||
		second.head.Core.Epoch != math.MaxUint64 {
		t.Fatal("maximum signer predecessor lacks its real detached retirement Duty", err)
	}
	assertEndWorkSelectedDeletePermissionCount(t, second, 0)
	warning := second.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
	ended := endGeneratedObligation(t, ctx, env, second, dutyID, []contract.ID{dutyID}, second.currentEntryInputs(), warning)
	if len(ended.adminIndex.Groups) != 0 || ended.head.Core.Epoch != math.MaxUint64 {
		t.Fatal("maximum signer EndWork did not dispose its old retirement owner")
	}
	if ended.adminIndex.SliceSnapshot == ended.root.Snapshot {
		t.Fatal("maximum signer exit did not retain the authenticated physical Slice owner")
	}
	control := currentControlOf(ended)
	predecessorIncarnation := control.NormalSigning.Binding.ControlIncarnationID
	successor, binding := f.successor.Successor(t, control.NormalSigning)
	if binding.Binding.Epoch != 1 || binding.Binding.ControlIncarnationID == predecessorIncarnation ||
		binding.Binding.ControlIncarnationID.IsZero() {
		t.Fatal("signer successor did not start a fresh generation-one control incarnation")
	}
	control.NormalSigning, control.AccessGeneration = binding, control.AccessGeneration+1
	permit := admitAuthorityReplacement(t, ended, env.Custody, control, contract.SuccessionReplaceAuthority,
		contract.NormalSigningRole, contract.SuccessionChangeNormalSigner, contract.BindingTableRow{})
	candidate, result := ended.PrepareSuccession(ctx, permit, SuccessionSigners{Authorizer: f.successor, NormalSuccessor: successor})
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("maximum signer replacement preparation", result)
	}
	delivered := deliverSuccessionBasis(t, candidate)
	if selected, result := ended.selectCandidate(ctx, candidate); selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("maximum signer replacement selection", result)
	}
	rolled, result := Open(ctx, delivered, env.Store)
	if rolled == nil || result.Outcome != ObservedCurrent || rolled.head.Core.Epoch != 1 ||
		rolled.root.CurrentAccess.Core.NormalSigning.Binding.ControlIncarnationID != binding.Binding.ControlIncarnationID ||
		rolled.root.WarningBits&ended.root.WarningBits != ended.root.WarningBits || len(rolled.adminIndex.Groups) != 0 {
		t.Fatal("fresh signer incarnation did not preserve the completed exit", result)
	}
	store := env.Store.(*memoryStore)
	creates, cas := store.creates, store.cas
	if stale, result := Open(ctx, OpenContext{admission: &ended.admission}, store); stale != nil || result.Outcome != EvidenceUnavailable || result.Reason != SigningUnavailable ||
		store.creates != creates || store.cas != cas {
		t.Fatal("old maximum signer basis did not preserve unavailable successor evidence", result.Outcome, result.Reason)
	}
	f.successor.SetUnavailable(true)
	env.Trust = successor
	freshGeneratedAfterObligationExit(t, ctx, env, rolled, "maximum signer fresh progress")
}

// full_only: false
func TestEndWorkThenOrdinarySignerReplacementUsesRetainedSliceOwner(t *testing.T) {
	ctx := t.Context()
	f := newCurrentBasisFixture(t, contract.GCP, false)
	f.env.RetireInit()
	env := f.env
	env.Context, env.Trust = ctx, f.successor
	before, result := Open(ctx, f.current, env.Store)
	if before == nil || result.Outcome != ObservedCurrent {
		t.Fatal("ordinary signer predecessor did not cold Open", result)
	}
	profile := defaultGeneratedFixtureProfile()
	firstOperation := fixtureID(env.Domain, "ordinary signer first generation")
	first := selectPrivateGeneratedOperationInProcess(t, env, before,
		generatedPlanInputForGenerations(t, before, firstOperation, []string{"kept"}, profile), "ordinary signer first generation")
	first = generatedLifecycleReopen(t, ctx, first, env.Store)
	old := *first.valueEntry(0)
	secondOperation := fixtureID(env.Domain, "ordinary signer second generation")
	second := selectPrivateGeneratedOperationInProcess(t, env, first,
		generatedStatePlanInput(t, first, secondOperation, []string{old.Name}, profile, old.Generated.Epoch+1,
			map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: old}),
		"ordinary signer second generation")
	second = generatedLifecycleReopen(t, ctx, second, env.Store)
	dutyID, err := contract.GeneratorDutyID(second.root.Domain, old.Generated.OriginOperationID, old.Generated.OriginAttemptID, 2)
	if err != nil || len(second.adminIndex.Groups) != 1 || second.adminIndex.Groups[0].GroupID != dutyID {
		t.Fatal("ordinary signer predecessor lacks its real retirement Duty", err)
	}
	assertEndWorkSelectedDeletePermissionCount(t, second, 0)
	warning := second.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
	ended := endGeneratedObligation(t, ctx, env, second, dutyID, []contract.ID{dutyID}, second.currentEntryInputs(), warning)
	if len(ended.adminIndex.Groups) != 0 || ended.adminIndex.SliceSnapshot == ended.root.Snapshot {
		t.Fatal("ordinary signer exit did not retain physical Slice ownership")
	}
	selectedEntry := *ended.valueEntry(0)
	selectedAccess := slices.Clone(ended.accessRecords())
	selectedWindows, err := ended.receiptWindows(ctx)
	if err != nil {
		t.Fatal("ordinary signer predecessor receipts", err)
	}
	control := currentControlOf(ended)
	priorBinding := control.NormalSigning.Binding
	successor, binding := f.successor.Successor(t, control.NormalSigning)
	if binding.Binding.Epoch != priorBinding.Epoch+1 || binding.Binding.ControlIncarnationID != priorBinding.ControlIncarnationID {
		t.Fatal("ordinary signer successor did not advance the same control incarnation")
	}
	control.NormalSigning, control.AccessGeneration = binding, control.AccessGeneration+1
	permit := admitAuthorityReplacement(t, ended, env.Custody, control, contract.SuccessionReplaceAuthority,
		contract.NormalSigningRole, contract.SuccessionChangeNormalSigner, contract.BindingTableRow{})
	candidate, result := ended.PrepareSuccession(ctx, permit, SuccessionSigners{Authorizer: f.successor, NormalSuccessor: successor})
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("ordinary signer replacement preparation after EndWork", result)
	}
	delivered := deliverSuccessionBasis(t, candidate)
	if selected, result := ended.selectCandidate(ctx, candidate); selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("ordinary signer replacement selection after EndWork", result)
	}
	rolled, result := Open(ctx, delivered, env.Store)
	if rolled == nil || result.Outcome != ObservedCurrent || rolled.head.Core.Epoch != binding.Binding.Epoch ||
		rolled.root.CurrentAccess.Core.NormalSigning.Binding.ControlIncarnationID != priorBinding.ControlIncarnationID ||
		rolled.root.WarningBits != ended.root.WarningBits || len(rolled.adminIndex.Groups) != 0 ||
		!reflect.DeepEqual(*rolled.valueEntry(0), selectedEntry) || !reflect.DeepEqual(rolled.accessRecords(), selectedAccess) {
		t.Fatal("ordinary signer successor changed retained current work or access", result)
	}
	windows, err := rolled.receiptWindows(ctx)
	if err != nil || !reflect.DeepEqual(windows, selectedWindows) {
		t.Fatal("ordinary signer replacement changed prior receipt windows", err)
	}
}

// full_only: false
func TestEndWorkRetiresMaximumGeneratedEpochBeforeFreshIncarnation(t *testing.T) {
	ctx := t.Context()
	env, keys := genesisEnvironment(t, contract.GCP, false)
	env.Context = ctx
	f := newEnvironmentFixture(t, ctx, env, nil, false)
	profile := defaultGeneratedFixtureProfile()
	initialOperation := fixtureID(env.Domain, "maximum epoch initial operation")
	initial := selectPrivateGeneratedOperationInProcess(t, env, f.session,
		generatedPlanInputForGenerations(t, f.session, initialOperation, []string{"generated"}, profile), "maximum epoch initial")
	initial = generatedLifecycleReopen(t, ctx, initial, env.Store)
	initialEntry := *initial.valueEntry(0)
	if initialEntry.Generated.Epoch != 0 || initialEntry.Name != "generated" || len(initial.adminIndex.Groups) != 0 {
		t.Fatal("maximum-epoch setup did not select an initial epoch-zero entry")
	}
	operation := fixtureID(env.Domain, "maximum epoch original operation")
	input := generatedStatePlanInput(t, initial, operation, []string{initialEntry.Name}, profile, math.MaxUint64,
		map[string]contract.ID{initialEntry.Name: initialEntry.Incarnation}, map[string]contract.ValueEntry{initialEntry.Name: initialEntry})
	current := selectPrivateGeneratedOperationInProcess(t, env, initial, input, "maximum epoch original")
	current = generatedLifecycleReopen(t, ctx, current, env.Store)
	setupDutyID, err := contract.GeneratorDutyID(current.root.Domain, initialEntry.Generated.OriginOperationID, initialEntry.Generated.OriginAttemptID, 2)
	if err != nil || len(current.adminIndex.Groups) != 1 || current.adminIndex.Groups[0].GroupID != setupDutyID {
		t.Fatal("maximum-epoch setup lacks its exact predecessor retirement Duty", err)
	}
	assertEndWorkSelectedDeletePermissionCount(t, current, 0)
	setupWarning := current.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
	current = endGeneratedObligation(t, ctx, env, current, setupDutyID, []contract.ID{setupDutyID}, current.currentEntryInputs(), setupWarning)
	old := *current.valueEntry(0)
	if old.Generated.Epoch != math.MaxUint64 || old.Name != "generated" || old.Incarnation != initialEntry.Incarnation || len(current.adminIndex.Groups) != 0 {
		t.Fatal("actual maximum-epoch generation did not select one current entry")
	}
	retiring := map[string]contract.ValueEntry{old.Name: old}
	incarnations := map[string]contract.ID{old.Name: old.Incarnation}
	store := env.Store.(*memoryStore)
	creates, cas := store.creates, store.cas
	for _, epoch := range []uint64{math.MaxUint64 - 1, math.MaxUint64} {
		nextOperation := fixtureID(env.Domain, fmt.Sprintf("maximum epoch invalid generated operation %d", epoch))
		bad := generatedStatePlanInput(t, current, nextOperation, []string{old.Name}, profile, epoch, incarnations, retiring)
		if epoch == math.MaxUint64 {
			changed := generatedReservationInputForStateIntent(t, current, nextOperation, []string{old.Name}, []byte(`{"max-epoch":"new content"}`), profile, epoch, incarnations, retiring)
			bad.graph, bad.declaration, bad.registry, bad.recoveryPolicy, bad.requestBindings = changed.graph, changed.declaration,
				changed.graph.Request.Registry, changed.graph.Request.RecoveryPolicyID, changed.requestBindings
		}
		if plan, err := current.generatedPlanRequest(ctx, bad); plan != nil || !errors.Is(err, contract.ErrRecord) ||
			store.creates != creates || store.cas != cas {
			t.Fatal("present maximum-epoch name admitted lower epoch or changed same-epoch content", epoch, err)
		}
	}
	row := staticGeneratedHandoffImplementation(t, env.Domain, profile)
	parent := admitSuppliedComparison(t, current, keys, nil, row)
	comparison, result := current.Compare(ctx, nil, parent)
	if comparison == nil || result.Outcome != ObservedCurrent {
		t.Fatal("maximum-epoch selected name removal comparison", result)
	}
	candidate, result := current.Prepare(ctx, comparison, admit(t, current, comparison), env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("maximum-epoch selected name removal preparation", result)
	}
	removed, result := current.selectCandidate(ctx, candidate)
	if removed == nil || result.Outcome != ObservedCurrent {
		t.Fatal("maximum-epoch selected name removal", result)
	}
	keys.RetireApply()
	removed = generatedLifecycleReopen(t, ctx, removed, env.Store)
	dutyID, err := contract.GeneratorDutyID(current.root.Domain, old.Generated.OriginOperationID, old.Generated.OriginAttemptID, 2)
	if err != nil || removed.root.ValueEntryCount != 0 || len(removed.root.Names) != 0 || len(removed.adminIndex.Groups) != 1 ||
		removed.adminIndex.Groups[0].GroupID != dutyID {
		t.Fatal("ordinary removal did not make the maximum-epoch name absent with one real retirement owner", err)
	}
	assertEndWorkSelectedDeletePermissionCount(t, removed, 0)
	warning := removed.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
	ended := endGeneratedObligation(t, ctx, env, removed, dutyID, []contract.ID{dutyID}, removed.currentEntryInputs(), warning)
	if ended.root.ValueEntryCount != 0 || len(ended.adminIndex.Groups) != 0 || ended.root.Generated.Retiring != 0 {
		t.Fatal("maximum-epoch retirement exit did not complete name absence")
	}
	freshIncarnation := fixtureID(env.Domain, "maximum epoch new entry incarnation")
	if freshIncarnation == old.Incarnation {
		t.Fatal("fresh maximum-epoch incarnation reuses the old identity")
	}
	freshInput := generatedStatePlanInput(t, ended, fixtureID(env.Domain, "maximum epoch fresh operation"), []string{old.Name},
		profile, 0, map[string]contract.ID{old.Name: freshIncarnation}, nil)
	fresh := selectPrivateGeneratedOperationInProcess(t, env, ended, freshInput, "maximum epoch fresh incarnation")
	fresh = generatedLifecycleReopen(t, ctx, fresh, env.Store)
	got := fresh.valueEntry(0)
	if got == nil || got.Generated.Epoch != 0 || got.Incarnation != freshIncarnation || got.Incarnation == old.Incarnation ||
		fresh.root.WarningBits&ended.root.WarningBits != ended.root.WarningBits {
		t.Fatal("actual name absence did not permit a distinct fresh epoch-zero incarnation")
	}
	check := keys.Consume(ctx, sessionConsumerSelection(t, fresh, fresh.admission.recipient, old.Name), custody.StandardValue)
	if check.Code != contract.CryptoSuccess || !check.ValueMatched || check.SinkCalls != 1 {
		t.Fatal("fresh epoch-zero current value is not privately usable", check)
	}
}

// full_only: false
func TestEndWorkRetiresMaximumGeneratedPhaseBeforeFreshWork(t *testing.T) {
	for _, stage := range []string{"record", "final"} {
		t.Run(stage, func(t *testing.T) {
			ctx := t.Context()
			var env fixtureEnvironment
			var selected *StateSession
			var attemptID contract.ID
			var packet []byte
			var dutyIDs []contract.ID
			if stage == "final" {
				actual := newGeneratedActualOperation(t, false, custody.StandardValue)
				env = actual.env
				selected = generatedLifecycleReopen(t, ctx, actual.fixture.session, env.Store)
				selected = selectFreshGeneratedRecord(t, env.Store.(*memoryStore), selected, actual.expected.Template.AttemptID, actual.result)
				selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
				attemptID, packet = actual.expected.Template.AttemptID, actual.result
				dutyIDs = []contract.ID{actual.expected.Template.DutyID}
			} else {
				env, _ = genesisEnvironment(t, contract.GCP, false)
				env.Context = ctx
				current := newNamedEnvironmentFixture(t, ctx, env, []int{4}, false, []string{"kept"}).session
				input := generatedPlanInputForGenerations(t, current, generatedVectorID(230), []string{"alpha", "omega"}, defaultGeneratedFixtureProfile())
				firstID, secondID := input.requestBindings[0].AttemptID, input.requestBindings[1].AttemptID
				prior, _ := preparePrivateGeneratedReservation(t, env, current, input, nil)
				entered, first, second, firstPacket, secondPacket := runParallelGeneratedCreates(t, ctx, env, current, prior,
					[2]contract.ID{firstID, secondID}, custody.StandardValue)
				selected = selectFreshGeneratedRecord(t, env.Store.(*memoryStore), entered, firstID, firstPacket)
				selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
				work := mustSelectedGeneratedWork(t, selected)
				if first.Template.AttemptID != firstID || second.Template.AttemptID != secondID ||
					work.phase.Stage != contract.GeneratedStageRetainedResult || work.phase.FrontierAttemptID != secondID ||
					work.attempts[secondID].record.State != contract.GeneratedEffectTransmitted || len(work.attempts[secondID].result) != 0 ||
					len(firstPacket) == 0 || len(secondPacket) == 0 {
					t.Fatal("two real packets did not leave a valid next Record stage")
				}
				attemptID, packet = secondID, secondPacket
				dutyIDs = []contract.ID{first.Template.DutyID, second.Template.DutyID}
			}
			admitted := generatedPlanInputFixture(t, selected).context
			admitted.AdmissionID = fixtureID(selected.root.Domain, "maximum phase "+stage+" admission")
			admitted.SessionID = fixtureID(selected.root.Domain, "maximum phase "+stage+" session")
			if stage == "record" {
				if plan, err := selected.generatedRecordRequest(ctx, attemptID, packet, admitted); plan == nil || err != nil {
					t.Fatal("predecessor did not permit valid Record before counter mutation", err)
				}
			} else if plan, err := selected.generatedFinalRequest(ctx, admitted); plan == nil || err != nil {
				t.Fatal("predecessor did not permit valid Final before counter mutation", err)
			}
			maximum := signedMaximumGeneratedPhase(t, env, selected)
			admitted = generatedPlanInputFixture(t, maximum).context
			admitted.AdmissionID = fixtureID(maximum.root.Domain, "maximum phase "+stage+" post admission")
			admitted.SessionID = fixtureID(maximum.root.Domain, "maximum phase "+stage+" post session")
			if stage == "record" {
				if plan, err := maximum.generatedRecordRequest(ctx, attemptID, packet, admitted); plan != nil || !errors.Is(err, contract.ErrRecord) {
					t.Fatal("maximum Phase admitted an overflowing Record", err)
				}
			} else if plan, err := maximum.generatedFinalRequest(ctx, admitted); plan != nil || !errors.Is(err, contract.ErrRecord) {
				t.Fatal("maximum Phase admitted an overflowing Final", err)
			}
			work := mustSelectedGeneratedWork(t, maximum)
			if work.parent == nil || work.phase == nil || work.phase.Phase != math.MaxUint32 ||
				work.parent.OperationID != maximum.root.Generated.ActiveOwner || work.parent.MaterialID.IsZero() {
				t.Fatal("maximum Phase has no exact live parent and operation material")
			}
			warning := maximum.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
			endedIDs := append([]contract.ID{work.parent.OperationID}, dutyIDs...)
			ended := endGeneratedObligation(t, ctx, env, maximum, work.parent.OperationID,
				endedIDs, maximum.currentEntryInputs(), warning, work.parent.MaterialID)
			kept := mustSelectedGeneratedWork(t, ended)
			if !ended.root.Generated.ActiveOwner.IsZero() || !ended.root.Generated.ActivePhase.IsZero() ||
				!ended.root.Generated.ActiveGraph.IsZero() || kept.parent != nil || kept.phase != nil ||
				len(kept.bundles) != 0 || len(ended.adminIndex.Groups) != 0 {
				t.Fatal("EndWork retained maximum Phase or exclusive parent/graph")
			}
			stale := generatedPlanInputFixture(t, ended).context
			stale.AdmissionID = fixtureID(ended.root.Domain, "maximum phase "+stage+" ended admission")
			stale.SessionID = fixtureID(ended.root.Domain, "maximum phase "+stage+" ended session")
			creates, cas := env.Store.(*memoryStore).creates, env.Store.(*memoryStore).cas
			if stage == "record" {
				if plan, err := ended.generatedRecordRequest(ctx, attemptID, packet, stale); plan != nil || !errors.Is(err, contract.ErrRecord) {
					t.Fatal("ended maximum Phase restored Record rights", err)
				}
			} else if plan, err := ended.generatedFinalRequest(ctx, stale); plan != nil || !errors.Is(err, contract.ErrRecord) {
				t.Fatal("ended maximum Phase restored Final rights", err)
			}
			if store := env.Store.(*memoryStore); store.creates != creates || store.cas != cas {
				t.Fatal("ended maximum Phase request wrote to Store")
			}
			freshGeneratedAfterObligationExit(t, ctx, env, ended, "maximum phase "+stage+" fresh")
		})
	}
}

// full_only: false
func TestEndWorkRollsMaximumAccessGenerationAndKeepsFreshWork(t *testing.T) {
	ctx := t.Context()
	env, before, original, _ := resultlessCreateObligation(t, ctx, custody.StandardValue)
	store := env.Store.(*memoryStore)
	root := before.root
	oldIncarnation := root.CurrentAccess.Core.AccessIncarnationID
	root.CurrentAccess.Core.AccessGeneration = math.MaxUint64
	selected := signedGeneratedCounterRoot(t, env, before, root)
	if selected.root.CurrentAccess.Core.AccessGeneration != math.MaxUint64 ||
		selected.root.CurrentAccess.Core.AccessIncarnationID != oldIncarnation || len(selected.adminIndex.Groups) != 1 ||
		selected.adminIndex.Groups[0].GroupID != original.expected.Template.HazardID {
		t.Fatal("signed maximum-access predecessor lacks its detached Hazard")
	}
	warning := selected.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
	after := endGeneratedObligation(t, ctx, env, selected, original.expected.Template.HazardID, []contract.ID{original.expected.Template.HazardID},
		selected.currentEntryInputs(), warning, original.material.Core.OperationMaterialID)
	if after.root.CurrentAccess.Core.AccessGeneration != 1 || after.root.CurrentAccess.Core.AccessIncarnationID == oldIncarnation ||
		after.root.CurrentAccess.AccessRoot == selected.root.CurrentAccess.AccessRoot || len(after.adminIndex.Groups) != 0 {
		t.Fatal("actual Hazard exit did not roll the changed access set to a fresh generation-one incarnation")
	}
	if reopened, observed := Open(ctx, OpenContext{admission: &selected.admission}, store); reopened == nil || observed.Outcome != ObservedCurrent {
		t.Fatal("retained general admission lost valid cold Open after access rollover", observed)
	}
	if packet, present, observed := after.ReadGeneratedResult(ctx, original.record.AttemptID); len(packet) != 0 || present || observed != refused(AdmissionInvalid) {
		t.Fatal("access rollover restored the disposed original result right", observed)
	}
	freshGeneratedAfterObligationExit(t, ctx, env, after, "maximum-access exit fresh progress")
}

// full_only: false
func TestEndWorkKeepsMaximumRecipientSerialUntilFreshBinding(t *testing.T) {
	ctx := t.Context()
	env, before, original, _ := resultlessCreateObligation(t, ctx, custody.StandardValue)
	store, keys := env.Store.(*memoryStore), env.Custody
	reader := fixtureID(env.Domain, "reader")
	root := before.root
	var changed bool
	for i, ref := range root.Recipients {
		if ref == nil {
			continue
		}
		key, err := format.Key(store.desc.Prefix, *ref)
		if err != nil {
			t.Fatal(err)
		}
		page, err := format.DecodeRecipientPage(store.objects[key].Body)
		if err != nil {
			t.Fatal("selected recipient page", err)
		}
		for _, row := range page.Slots {
			if row != nil && row.RecipientID == reader {
				if row.CurrentBinding == nil {
					t.Fatal("reader has no current binding")
				}
				row.CurrentBinding.BindingSerial = math.MaxUint64
				changed = true
			}
		}
		if !changed {
			continue
		}
		body, err := format.EncodeRecipientPage(page)
		if err != nil {
			t.Fatal("maximum recipient page", err)
		}
		newRef, err := format.Reference(format.RecipientKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal(err)
		}
		newKey, err := format.Key(store.desc.Prefix, newRef)
		if err != nil {
			t.Fatal(err)
		}
		store.put(newKey, body)
		root.Recipients[i] = &newRef
		break
	}
	if !changed {
		t.Fatal("real selected fixture has no independent reader")
	}
	refreshFixtureRecipientRefs(t, &root)
	image := *before
	image.root = root
	image.recountChildren()
	keys.SetCurrentBindingSerial(t, reader, math.MaxUint64)
	selected := signedGeneratedCounterRoot(t, env, before, image.root)
	authority := selected.admission.recipient
	shared := []contract.ID{authority, reader}
	slices.SortFunc(shared, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	run := newScenarioRun(t, ctx, env)
	priorSecrets := selected.root.SecretCount
	wrapped := *selected
	wrapped.store = run.env.Store
	f := &environmentFixture{admission: OpenContext{admission: &selected.admission}, session: &wrapped}
	secret := sharingSecretNamed(t, env, "secret", "maximum recipient retained source", shared)
	selected = run.suppliedSelection(f, append(selected.currentEntryInputs(), secret))
	if len(selected.adminIndex.Groups) != 1 || selected.adminIndex.Groups[0].GroupID != original.expected.Template.HazardID || selected.root.SecretCount != priorSecrets+1 {
		t.Fatal("retained reader value changed the detached Hazard or was not selected")
	}
	old := selected.recipientRecord(reader).CurrentBinding
	if old == nil || old.BindingSerial != math.MaxUint64 || len(selected.adminIndex.Groups) != 1 ||
		selected.adminIndex.Groups[0].GroupID != original.expected.Template.HazardID {
		t.Fatal("maximum-serial detached predecessor did not ordinary cold Open")
	}
	predecessorReader := sessionConsumerSelection(t, selected, reader, "secret")
	if check := env.readerConsume(predecessorReader, custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched || check.SinkCalls != 1 {
		t.Fatal("maximum-serial predecessor reader did not consume retained Secret", check)
	}
	warning := selected.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
	ended := endGeneratedObligation(t, ctx, env, selected, original.expected.Template.HazardID,
		[]contract.ID{original.expected.Template.HazardID}, selected.currentEntryInputs(), warning, original.material.Core.OperationMaterialID)
	if got := ended.recipientRecord(reader).CurrentBinding; got == nil || !reflect.DeepEqual(*got, *old) {
		t.Fatal("EndWork changed the independent maximum-serial reader")
	}
	successor := keys.RecipientSuccessor(t, reader)
	if successor.BindingIncarnationID == old.BindingIncarnationID || successor.BindingSerial != 1 {
		t.Fatal("reader successor did not use a fresh serial-one incarnation")
	}
	permit := admitReaderReplacement(t, ended, keys, reader, successor)
	candidate, result := ended.PrepareRecipientReplacement(ctx, permit, env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("post-exit reader replacement preparation", result)
	}
	if result := ended.Select(ctx, candidate); result.Outcome != ObservedCurrent {
		t.Fatal("post-exit reader replacement selection", result)
	}
	keys.RetireAccess()
	rolled, result := Open(ctx, OpenContext{admission: &ended.admission}, store)
	if rolled == nil || result.Outcome != ObservedCurrent || rolled.root.WarningBits&ended.root.WarningBits != ended.root.WarningBits {
		t.Fatal("post-exit reader successor did not ordinary cold Open", result)
	}
	got := rolled.recipientRecord(reader).CurrentBinding
	if got == nil || got.BindingIncarnationID != successor.BindingIncarnationID || got.BindingSerial != 1 ||
		len(rolled.adminIndex.Groups) != 0 {
		t.Fatal("post-exit selected reader binding or exited owner changed")
	}
	if err := keys.ActivateRecipientSuccessor(reader); err != nil {
		t.Fatal("selected reader successor activation", err)
	}
	if stale := env.readerConsume(predecessorReader, custody.StandardValue); stale.Code == contract.CryptoSuccess || stale.Delivery != 0 || stale.SinkCalls != 0 || stale.ValueMatched {
		t.Fatal("maximum-serial predecessor reader still delivered after successor activation", stale)
	}
	if check := env.readerSuccessorConsume(sessionConsumerSelection(t, rolled, reader, "secret"), custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched || check.SinkCalls != 1 {
		t.Fatal("maximum-serial successor reader could not consume retained Secret", check)
	}
	freshGeneratedAfterObligationExit(t, ctx, env, rolled, "maximum-recipient exit fresh progress")
}

// The complete controlled-fixture row admits an ordinary handoff. It is never
// invoked as an effect provider and makes no native or service qualification.
func staticGeneratedHandoffImplementation(t *testing.T, domain contract.ID, profile generatedFixtureProfile) contract.GeneratorImplementation {
	t.Helper()
	id := func(label string) contract.ID {
		return fixtureID(domain, "maximum epoch static implementation "+label)
	}
	routeContract := id("route contract")
	route := append([]byte{0, 1}, routeContract[:]...)
	route = append(route, 1, 0, 0, 0, 0, 0)
	preimage := append([]byte("ENKV/CREDENTIAL-ROUTE/v1\x00"), binary.BigEndian.AppendUint32(nil, uint32(len(route)))...)
	preimage = append(preimage, route...)
	row := contract.GeneratorImplementation{Schema: contract.GeneratorImplementationSchema, Kind: contract.GeneratorComponentKind,
		ConfigContractID: profile.ConfigContractID, DescriptorID: profile.DescriptorID, ProtocolID: id("protocol"), ExecutorID: profile.ExecutorID,
		ArtifactContractID: id("artifact contract"), DependencyManifestID: id("manifest"), ArtifactSHA256: id("artifact"), CredentialRoute: route,
		CredentialRouteID: sha256.Sum256(preimage), ArtifactLength: 4096, Module: "fixture", Command: ".", Version: "1.0.0", GoVersion: "go1.27.3", NativeTuple: runtime.GOOS + "/" + runtime.GOARCH}

	if err := row.Validate(); err != nil {
		t.Fatal("ordinary generated handoff lacks a valid static implementation", err)
	}
	return row
}

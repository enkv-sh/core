package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
	testtrust "enkv.sh/crypto/testsupport/trust"
	"enkv.sh/telemetry"
)

func localOperatorTelemetryRecords(recorder *telemetry.Recorder) []telemetry.DiagnosticRecord {
	var records []telemetry.DiagnosticRecord
	for {
		batch := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 64))
		if len(batch) == 0 {
			return records
		}
		records = append(records, batch...)
	}
}

type localOperatorPanicTrust struct {
	contract.Trust
	signal error
}

func (s localOperatorPanicTrust) Sign(context.Context, contract.SignRequest) contract.SignResult {
	panic(s.signal)
}

// full_only: false
func TestLocalAuthorityPreviewEndAndRecheckUseFreshCurrentAdmission(t *testing.T) {
	env, selected, _, _ := generatedAuthenticatedDeleteHazardFixture(t, false, 0)
	selected = generatedLifecycleReopen(t, t.Context(), selected, env.Store)
	capture := newPublicationDiagnosticCapture()
	recorder := capture.recorder
	ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
	store := env.Store.(*memoryStore)
	inspect, result := openAdministrativeEngineFixture(ctx, selected, store, env.Trust, LocalAuthorityInspect)
	capture.collect()
	if inspect == nil || result.Outcome != ObservedCurrent {
		t.Fatal("fresh local inspection admission", result)
	}
	view, result := inspect.Inspect(ctx)
	capture.collect()
	if result.Outcome != ObservedCurrent || len(view.Groups) == 0 || view.Revision != selected.head.Core.Revision {
		t.Fatal("local inspection omitted selected owner", result)
	}
	group := view.Groups[0].GroupID
	store.creates, store.cas = 0, 0
	preview, result := openAdministrativeEngineFixture(ctx, selected, store, env.Trust, LocalAuthorityPreview)
	capture.collect()
	if preview == nil || result.Outcome != ObservedCurrent {
		t.Fatal("fresh local preview admission", result)
	}
	decision, result := preview.Preview(ctx, group)
	capture.collect()
	if result.Outcome != ObservedCurrent || decision.Identity.IsZero() || decision.PredecessorRevision != view.Revision ||
		decision.TargetGroupID != group || store.creates != 0 || store.cas != 0 {
		t.Fatal("preview wrote or lost selected disposition", result, store.creates, store.cas)
	}
	again, result := openAdministrativeEngineFixture(ctx, selected, store, env.Trust, LocalAuthorityPreview)
	capture.collect()
	if again == nil || result.Outcome != ObservedCurrent {
		t.Fatal("fresh repeated preview admission", result)
	}
	second, result := again.Preview(ctx, group)
	capture.collect()
	if result.Outcome != ObservedCurrent || !equalEndWorkPreview(decision, second) || store.creates != 0 || store.cas != 0 {
		t.Fatal("random candidate IDs changed preview meaning", result)
	}
	if preview.state.admission.endWorkInvocation.IsZero() ||
		preview.state.admission.endWorkInvocation == again.state.admission.endWorkInvocation {
		t.Fatal("fresh preview reused a private invocation")
	}
	ender, result := openAdministrativeEngineFixture(ctx, selected, store, env.Trust, LocalAuthorityEnd)
	capture.collect()
	if ender == nil || result.Outcome != ObservedCurrent {
		t.Fatal("fresh local end admission", result)
	}
	if ender.state.admission.endWorkInvocation == preview.state.admission.endWorkInvocation ||
		ender.state.admission.endWorkInvocation == again.state.admission.endWorkInvocation {
		t.Fatal("EndWork reused an earlier preview invocation")
	}
	outcome := ender.End(ctx, decision)
	capture.collect()
	if outcome.Result.Outcome != ObservedCurrent || outcome.OperationID.IsZero() || outcome.Revision.IsZero() ||
		store.cas != 1 || store.creates == 0 {
		t.Fatal("local EndWork did not select exact preview", outcome, store.creates, store.cas)
	}
	stale, result := openAdministrativeEngineFixture(ctx, selected, store, env.Trust, LocalAuthorityEnd)
	capture.collect()
	if stale == nil || result.Outcome != ObservedCurrent {
		t.Fatal("fresh successor admission", result)
	}
	repeated := stale.End(ctx, decision)
	capture.collect()
	if repeated.Result.Outcome != AdmissionRefused || repeated.Result.Reason != StalePrecondition || store.cas != 1 {
		t.Fatal("stale preview repeated selection", repeated)
	}
	recheck, result := openAdministrativeEngineFixture(ctx, selected, store, env.Trust, LocalAuthorityRecheck)
	capture.collect()
	if recheck == nil || result.Outcome != ObservedCurrent {
		t.Fatal("fresh receipt admission", result)
	}
	receipt, result := recheck.Recheck(ctx, outcome.OperationID)
	capture.collect()
	if result.Outcome != ObservedCurrent || receipt.OperationID != outcome.OperationID || receipt.AdministrativeTargetID != decision.TargetID ||
		receipt.WarningBits != uint64(outcome.Warnings) {
		t.Fatal("local recheck lost authenticated EndWork receipt", result)
	}
	retained, err := contract.EncodeCompactMutationReceipt(receipt)
	if err != nil || len(outcome.Receipt) != contract.CompactMutationReceiptLength ||
		!bytes.Equal(outcome.Receipt, retained) || receipt.AdministrativeOriginalEvidence != decision.SelectedEvidenceSummary ||
		receipt.AdministrativeWarningChanges != decision.WarningBits&^decision.BeforeWarningBits ||
		receipt.AdministrativePageDelta != int16(decision.AfterChildCount)-int16(decision.BeforeChildCount) ||
		receipt.AdministrativeByteDelta != int64(decision.AfterChildBytes)-int64(decision.BeforeChildBytes) {
		t.Fatal("initial EndWork result did not retain its exact selected receipt and consequences", err)
	}
	if selected := stale.state.head.EndWork; selected == nil || selected.AdmissionID.IsZero() || selected.AdmissionID != ender.state.admission.endWorkInvocation {
		t.Fatal("signed invocation did not retain its fresh private admission")
	}
	records := drainNativePublicationDiagnostics(t, capture)
	operatorReturns := map[telemetry.Operation]map[telemetry.Result]int{}
	var selectedEndCall uint64
	for _, record := range records {
		if record.Validate() != nil || record.Path != "" || record.ErrorDetail != "" {
			t.Fatal("invalid or unsafe operator telemetry", record)
		}
		if record.Event == telemetry.DiagnosticReturn {
			if operatorReturns[record.Operation] == nil {
				operatorReturns[record.Operation] = make(map[telemetry.Result]int)
			}
			operatorReturns[record.Operation][record.Result]++
			if record.Operation == telemetry.OpCoreSelectEndSelectedWork && record.Result == telemetry.ResultObservedCurrent {
				selectedEndCall = record.Call
			}
		}
	}
	for _, want := range []struct {
		op     telemetry.Operation
		result telemetry.Result
		count  int
	}{{telemetry.OpCoreOpen, telemetry.ResultObservedCurrent, 6},
		{telemetry.OpCoreInspectSelectedWork, telemetry.ResultObservedCurrent, 1},
		{telemetry.OpCorePrepareEndSelectedWork, telemetry.ResultObservedCurrent, 2},
		{telemetry.OpCoreSelectEndSelectedWork, telemetry.ResultObservedCurrent, 1},
		{telemetry.OpCoreSelectEndSelectedWork, telemetry.ResultAdmissionRefused, 1},
		{telemetry.OpCoreMutationReceipt, telemetry.ResultObservedCurrent, 1}} {
		if operatorReturns[want.op][want.result] != want.count {
			t.Fatal("operator result count", want, operatorReturns)
		}
	}
	if selectedEndCall == 0 {
		t.Fatal("selected EndWork has no telemetry call")
	}
	var child bool
	for _, record := range records {
		if record.Event == telemetry.DiagnosticStart && record.ParentCall == selectedEndCall &&
			(record.Operation == telemetry.OpCoreStoreCreate || record.Operation == telemetry.OpCoreStoreCompareAndSwap) {
			child = true
		}
	}
	if !child {
		t.Fatal("EndWork Store child lost its parent", selectedEndCall)
	}
}

// full_only: false
func TestLocalAuthorityPreviewShowsCompleteOrderedDependentScope(t *testing.T) {
	ctx := t.Context()
	env, selected, original, _ := resultlessCreateObligation(t, ctx, custody.GeneratedTerminalFailure)
	work := mustSelectedGeneratedWork(t, selected)
	var successor generatedAttempt
	for id, attempt := range work.attempts {
		if id != original.record.AttemptID {
			successor = attempt
		}
	}
	want := []contract.ID{original.expected.Template.HazardID, successor.expected.Template.HazardID}
	if want[1].IsZero() || len(selected.adminIndex.Groups) != 2 {
		t.Fatal("dependent preview fixture has no exact two-group ancestry")
	}
	target := want[0]
	_, closure, err := selected.administrativeWorkClosure(target)
	if err != nil || len(closure) != 2 {
		t.Fatal("dependent preview fixture has no selected two-group closure", err, selected.adminIndex.Groups)
	}
	slices.SortFunc(want, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	store := env.Store.(*memoryStore)
	beforeCreates, beforeCAS := store.creates, store.cas
	for i := 0; i < 2; i++ {
		view, result := openAdministrativeEngineFixture(ctx, selected, store, env.Trust, LocalAuthorityPreview)
		if view == nil || result.Outcome != ObservedCurrent {
			t.Fatal("dependent preview admission", result)
		}
		preview, result := view.Preview(ctx, target)
		if result.Outcome != ObservedCurrent || !slices.Equal(preview.EndedGroupIDs, want) ||
			store.creates != beforeCreates || store.cas != beforeCAS {
			t.Fatal("preview omitted dependent scope or caused an effect", result, preview.EndedGroupIDs)
		}
	}
	previewSession, result := openAdministrativeEngineFixture(ctx, selected, store, env.Trust, LocalAuthorityPreview)
	if previewSession == nil || result.Outcome != ObservedCurrent {
		t.Fatal("scope preview admission", result)
	}
	exact, result := previewSession.Preview(ctx, target)
	if result.Outcome != ObservedCurrent {
		t.Fatal("scope preview", result)
	}
	foreign := contract.ID{0xff}
	for _, test := range []struct {
		name  string
		scope []contract.ID
	}{
		{"missing", nil},
		{"empty", []contract.ID{}},
		{"dropped", []contract.ID{exact.EndedGroupIDs[0]}},
		{"reordered", []contract.ID{exact.EndedGroupIDs[1], exact.EndedGroupIDs[0]}},
		{"duplicate", []contract.ID{exact.EndedGroupIDs[0], exact.EndedGroupIDs[0]}},
		{"foreign", []contract.ID{exact.EndedGroupIDs[0], foreign}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ender, result := openAdministrativeEngineFixture(ctx, selected, store,
				localOperatorPanicTrust{Trust: env.Trust}, LocalAuthorityEnd)
			if ender == nil || result.Outcome != ObservedCurrent {
				t.Fatal("scope End admission", result)
			}
			altered := exact
			altered.EndedGroupIDs = test.scope
			creates, cas := store.creates, store.cas
			if outcome := ender.End(ctx, altered); outcome.Result != refused(StalePrecondition) ||
				store.creates != creates || store.cas != cas {
				t.Fatal("altered scope reached signing or Store", outcome, store.creates-creates, store.cas-cas)
			}
		})
	}
	ender, result := openAdministrativeEngineFixture(ctx, selected, store, env.Trust, LocalAuthorityEnd)
	if ender == nil || result.Outcome != ObservedCurrent {
		t.Fatal("exact End admission", result)
	}
	outcome := ender.End(ctx, exact)
	if outcome.Result.Outcome != ObservedCurrent || outcome.OperationID.IsZero() {
		t.Fatal("exact dependent scope did not select", outcome)
	}
	recheck, result := openAdministrativeEngineFixture(ctx, selected, store, env.Trust, LocalAuthorityRecheck)
	if recheck == nil || result.Outcome != ObservedCurrent {
		t.Fatal("cold receipt admission", result)
	}
	receipt, result := recheck.Recheck(ctx, outcome.OperationID)
	if result.Outcome != ObservedCurrent || receipt.StateResult != contract.ReceiptStateWorkEnded ||
		receipt.ObservedRevisionID != outcome.Revision {
		t.Fatal("exact dependent scope receipt did not survive cold reopen", result, receipt)
	}
}

// full_only: false
func TestLocalAuthorityColdBodylessFragmentReadsKeepTypedFailures(t *testing.T) {
	ctx := t.Context()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	fixture := newNamedEnvironmentFixture(t, ctx, env, []int{1}, false, []string{"a-seed"})
	lifecycle := fixture.session
	storeB := selectedMemoryStoreCopy(env.Store.(*memoryStore))
	envB := env
	envB.Store = storeB
	envB.Custody = env.Custody.ForkGenerated(t)
	envB.Crypto = envB.Custody.Crypto()
	sourceB, result := Open(ctx, OpenContext{admission: &lifecycle.admission}, storeB)
	if sourceB == nil || result.Outcome != ObservedCurrent {
		t.Fatal("independent generated source", result)
	}
	filler := []ApplyEntryInput{
		{Name: "a-seed", Recipients: []contract.ID{sourceB.admission.recipient}, ValueSource: format.Supplied,
			InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ConfidentialityClass: format.Plain, InputBytes: []byte{0}},
		{Name: "b-filler", Recipients: []contract.ID{sourceB.admission.recipient}, ValueSource: format.Supplied,
			InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ConfidentialityClass: format.Plain, InputBytes: []byte{1}},
	}
	comparison, result := sourceB.Compare(ctx, filler, admitSuppliedComparison(t, sourceB, nil, filler))
	if comparison == nil || result.Outcome != ObservedCurrent {
		t.Fatal("independent source filler", result)
	}
	candidate, result := sourceB.Prepare(ctx, comparison, admit(t, sourceB, comparison), envB.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent || sourceB.Select(ctx, candidate).Outcome != ObservedCurrent {
		t.Fatal("independent source filler selection", result)
	}
	sourceB = generatedLifecycleReopen(t, ctx, sourceB, storeB)
	predecessor, original := signedCurrentIntentReleasePredecessor(t, ctx, env, lifecycle, "operator cold read")
	aSources, _ := generatedCurrentDeclaration(t, predecessor)
	selectedA := signedFullIntentSource(t, ctx, env, predecessor, fixtureID(env.Domain, "operator cold source A"),
		[]string{"alpha"}, aSources, []contract.ID{predecessor.admission.recipient}, custody.StandardValue, contract.OutputEncodingRaw, "operator cold source A", nil)
	bSources, _ := generatedCurrentDeclaration(t, sourceB)
	selectedB := signedFullIntentSource(t, ctx, envB, sourceB, fixtureID(env.Domain, "operator cold source B"),
		[]string{"omega"}, bSources, []contract.ID{sourceB.admission.recipient}, custody.StandardValue, contract.OutputEncodingRaw, "operator cold source B", nil)
	store, selected := signedCurrentIntentFixtureWithRelease(t, env, lifecycle, "operator cold release",
		original.record.AttemptID, selectedA, selectedB)
	intentBlobs := make(map[contract.ID]bool)
	for _, location := range selected.generatedSliceLocations {
		if location.ContentKind == contract.GeneratorContentIntent {
			intentBlobs[location.BlobID] = true
		}
	}
	if len(intentBlobs) == 0 {
		t.Fatal("signed cold fixture has no current Intent slices")
	}
	open := func(operation LocalAuthorityOperation) *AuthoritySession {
		t.Helper()
		view, result := openAdministrativeEngineFixture(ctx, selected, store, env.Trust, operation)
		if view == nil || result.Outcome != ObservedCurrent {
			t.Fatal("cold public Authority admission", result)
		}
		for location, fact := range view.state.fragmentFacts {
			if !intentBlobs[location.BlobID] {
				continue
			}
			position, ok := view.state.selectedSupportPosition(fact.ref)
			if !ok || int(location.RowSlot) >= len(view.state.support[position].Records) {
				t.Fatal("cold public fragment fact has no selected row")
			}
			view.state.support[position].Records[location.RowSlot].Body = nil
		}
		return view
	}
	preview := open(LocalAuthorityPreview)
	fragmentKeys := make(map[string]bool)
	for location, fact := range preview.state.fragmentFacts {
		if !intentBlobs[location.BlobID] {
			continue
		}
		position, ok := preview.state.selectedSupportPosition(fact.ref)
		if !ok || int(location.RowSlot) >= len(preview.state.support[position].Records) ||
			preview.state.support[position].Records[location.RowSlot].Body != nil {
			t.Fatal("public cold session did not retain bodyless selected fragment facts")
		}
		key, err := format.Key(preview.state.admission.store.Prefix, fact.ref)
		if err != nil {
			t.Fatal(err)
		}
		fragmentKeys[key] = true
	}
	if len(fragmentKeys) == 0 {
		t.Fatal("public cold fixture has no selected fragments")
	}
	target := selected.adminIndex.Groups[0].GroupID
	exact, result := preview.Preview(ctx, target)
	if result.Outcome != ObservedCurrent {
		t.Fatal("bodyless cold preview control", result)
	}
	for _, cut := range []struct {
		name       string
		read       contract.ReadResult
		wantReason Reason
		storeCause contract.Reason
	}{
		{"missing", contract.ReadResult{Status: contract.ReadMissing}, MissingSelectedObject, 0},
		{"unavailable", contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess},
			ReadUnavailable, contract.ReasonAccess},
	} {
		for _, operation := range []LocalAuthorityOperation{LocalAuthorityPreview, LocalAuthorityEnd} {
			t.Run(cut.name+"/"+string(operation), func(t *testing.T) {
				view := open(operation)
				hits := 0
				store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
					if fragmentKeys[key] {
						hits++
						return cut.read
					}
					return read
				}
				creates, cas := store.creates, store.cas
				var result Result
				if operation == LocalAuthorityPreview {
					_, result = view.Preview(ctx, target)
				} else {
					result = view.End(ctx, exact).Result
				}
				store.readHook = nil
				if hits == 0 || result.Outcome != EvidenceUnavailable || result.Reason != cut.wantReason ||
					result.StoreReason != cut.storeCause || store.creates != creates || store.cas != cas {
					t.Fatal("cold public caller lost typed selected-fragment read refusal", operation, result, hits,
						store.creates-creates, store.cas-cas)
				}
			})
		}
	}
}

// full_only: false
func TestInstalledAdministrativeApplyRefusesChangedCapturedSourceAfterPlan(t *testing.T) {
	selected, store, signer := installedAdministrativeWorkFixture(t)
	ctx := installedAdministrativeTestContext(t)
	pin := localAdmissionPath(t, "source-pin", []byte("captured source bytes"))
	captured, err := readLocalProtected(pin, 64)
	if err != nil {
		t.Fatal(err)
	}
	check := func(context.Context) error {
		body, err := readLocalProtected(pin, 64)
		if err != nil {
			return err
		}
		if !bytes.Equal(body, captured) {
			return errors.New("changed captured source")
		}
		return nil
	}
	source := &installedAdministrativeTestReader{store: store}
	input := installedAdministrativeReadInput(selected, source)
	input.CheckSource = check
	input.SourcePins.EditableDigest = contract.Hash(captured)
	input.SourcePins.EditableLength = uint64(len(captured))
	parent, err := NewInstalledAdministrativeReader(input, AdministrativePlan)
	if err != nil {
		t.Fatal(err)
	}
	plan := parent.Plan(ctx, generatedVectorID(211), AdministrativePlanRequest{TargetGroupID: selected.adminIndex.Groups[0].GroupID, ArtifactPath: "/independent-plan"})
	if err := parent.Close(); err != nil {
		t.Fatal(err)
	}
	if plan.Plan == nil || plan.Result.Outcome != ObservedCurrent {
		t.Fatal("installed plan", plan.Result)
	}
	creates, cas := 0, 0
	guardedStore := &installedAdministrativeStoreHook{Store: store, afterCreate: func() { creates++ }, afterCAS: func() { cas++ }}
	authority, err := NewInstalledAdministrativeAuthority(AdministrativeAuthorityInstallation{ExpectedDomain: input.ExpectedDomain, ExpectedStore: input.ExpectedStore, PublicBasis: input.PublicBasis, CompositionID: input.CompositionID, SourcePins: input.SourcePins, Store: guardedStore, Trust: signer, CheckSource: check, CloseInstalled: func() error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pin, []byte("changed source bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	signs := signer.Calls()
	outcome := authority.Apply(ctx, generatedVectorID(212), plan.Plan.Preview)
	if outcome.Result.Outcome != AdmissionRefused || creates != 0 || cas != 0 || signer.Calls() != signs {
		t.Fatal("changed source reached installed signing/selection", outcome.Result, creates, cas)
	}
	if err := authority.Close(); err == nil {
		t.Fatal("changed source cause was lost at Close")
	}
}

// full_only: false
func TestLocalAuthorityPreviewRefusesInvocationCollidingWithSelectedClosure(t *testing.T) {
	ctx := context.Background()
	env, selected, _, _ := generatedAuthenticatedDeleteHazardFixture(t, false, 0)
	selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
	store := env.Store.(*memoryStore)
	preview, result := openAdministrativeEngineFixture(ctx, selected, store, env.Trust, LocalAuthorityPreview)
	if preview == nil || result.Outcome != ObservedCurrent {
		t.Fatal("preview admission", result)
	}
	preview.state.admission.endWorkInvocation = preview.state.head.Core.Revision
	store.creates, store.cas = 0, 0
	if _, result := preview.Preview(ctx, preview.state.adminIndex.Groups[0].GroupID); result != refused(AdmissionInvalid) || store.creates != 0 || store.cas != 0 {
		t.Fatal("selected closure identity reused as private invocation", result, store.creates, store.cas)
	}
}

func localSelectedGenesis(t *testing.T, env fixtureEnvironment, admitted OpenContext) *StateSession {
	t.Helper()
	ctx := context.Background()
	init, _ := fixtureInitAdmission(t, env, admitted)
	session, result := Initialize(ctx, init, env.Store, env.Trust.(contract.QualifyingTrust), env.Recovery, env.Crypto)
	if session == nil || result.Outcome != ObservedCurrent {
		t.Fatal("signed genesis", result)
	}
	env.RetireInit()
	selected, result := Open(ctx, admitted, env.Store)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("signed genesis cold open", result)
	}
	return selected
}

func localSelectedSignerSuccessor(t *testing.T, env fixtureEnvironment, selected *StateSession) (*StateSession, *testtrust.Signer) {
	t.Helper()
	ctx := context.Background()
	after := currentControlOf(selected)
	successor, signing := env.Trust.(*fixtureTrust).Successor(t, after.NormalSigning)
	after.NormalSigning = signing
	after.AccessGeneration++
	permit := admitAuthorityReplacement(t, selected, env.Custody, after,
		contract.SuccessionReplaceAuthority, contract.NormalSigningRole, contract.SuccessionChangeNormalSigner, contract.BindingTableRow{})
	candidate, result := selected.PrepareSuccession(ctx, permit,
		SuccessionSigners{Authorizer: env.Trust, NormalSuccessor: successor})
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("signed signer successor preparation", result)
	}
	nextAdmission := deliverSuccessionBasis(t, candidate)
	if selected.Select(ctx, candidate).Outcome != ObservedCurrent {
		t.Fatal("signed signer successor selection")
	}
	next, result := Open(ctx, nextAdmission, env.Store)
	if next == nil || result.Outcome != ObservedCurrent {
		t.Fatal("signed signer successor cold open", result)
	}
	return next, successor
}

// The retained public basis format is independent of the removed connection.
// Use its actual writer/parser/protected-read path before cold admission.
func parsedAdministrativeBasisFixture(t *testing.T, selected *StateSession) (PublicBasis, int) {
	t.Helper()
	image := localBasisImage{Schema: 3, Kind: "genesis", Descriptor: selected.admission.descriptor}
	if selected.admission.current != nil {
		var err error
		image, err = testSuccessorPublicBasisImage(selected.admission.current)
		if err != nil {
			t.Fatal(err)
		}
	}
	body, err := json.Marshal(image)
	if err != nil {
		t.Fatal(err)
	}
	basis, err := ReadLocalPublicBasis(localAdmissionPath(t, "public-basis.json", body))
	if err != nil {
		t.Fatal("legal encoded public basis refused", err)
	}
	return basis, len(body)
}
func coldAdministrativeBasisFixture(t *testing.T, selected *StateSession, basis PublicBasis, store contract.Store) *StateSession {
	t.Helper()
	admitted, result := admitPublicNormal(t.Context(), selected.admission.domain, selected.admission.store, basis, store, selected.admission.composition, nil)
	if result.Outcome != ObservedCurrent {
		t.Fatal("parsed independent public basis admission", result)
	}
	opened, result := openAdministrative(t.Context(), admitted, store)
	if opened == nil || result.Outcome != ObservedCurrent {
		t.Fatal("parsed independent public basis cold open", result)
	}
	return opened
}

// full_only: false
func TestPublicSuccessorBasisAdmitsEmptySelectedEnrollmentFields(t *testing.T) {
	for _, test := range []struct{ name, display string }{{"empty-display", ""}, {"authority-display", "authority"}} {
		display := test.display
		t.Run(test.name, func(t *testing.T) {
			env, _ := genesisEnvironment(t, contract.GCP, true)
			admitted := fixtureAdmission(env)
			descriptor, err := contract.DecodeGenesisDescriptorCore(admitted.admission.descriptor)
			if err != nil {
				t.Fatal(err)
			}
			descriptor.Recipients[0].DisplayName = display
			admitted.admission.descriptor, err = contract.EncodeGenesisDescriptorCore(descriptor)
			if err != nil {
				t.Fatal(err)
			}
			selected := localSelectedGenesis(t, env, admitted)
			next, _ := localSelectedSignerSuccessor(t, env, selected)
			if len(next.admission.current.enrollment) == 0 || next.admission.current.enrollment[0].name != display {
				t.Fatal("signed successor lost selected display name")
			}
			basis, _ := parsedAdministrativeBasisFixture(t, next)
			if len(basis.Enrollment) == 0 || basis.Enrollment[0].DisplayName != display {
				t.Fatal("actual public basis parser changed display name")
			}
			_ = coldAdministrativeBasisFixture(t, next, basis, env.Store)
		})
	}
}

// full_only: true
func TestPublicBasisAdmitsLegalLargeRegistryInBothForms(t *testing.T) {
	const formerLocalBasisLimit = 256 << 10
	env, _ := genesisEnvironment(t, contract.GCP, true, contract.CryptoMaxRecipients)
	admitted := fixtureAdmission(env)
	descriptor, err := contract.DecodeGenesisDescriptorCore(admitted.admission.descriptor)
	if err != nil {
		t.Fatal(err)
	}
	for i := range descriptor.Recipients {
		descriptor.Recipients[i].DisplayName = strings.Repeat("\x01", contract.CryptoMaxName)
	}
	admitted.admission.descriptor, err = contract.EncodeGenesisDescriptorCore(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	selected := localSelectedGenesis(t, env, admitted)
	check := func(s *StateSession) {
		basis, length := parsedAdministrativeBasisFixture(t, s)
		if length <= formerLocalBasisLimit {
			t.Fatal("legal independent basis did not cross former local bound", length)
		}
		opened := coldAdministrativeBasisFixture(t, s, basis, env.Store)
		if len(opened.registry()) != contract.CryptoMaxRecipients {
			t.Fatal("legal large parsed public basis lost complete registry")
		}
	}
	check(selected)
	next, _ := localSelectedSignerSuccessor(t, env, selected)
	check(next)
}

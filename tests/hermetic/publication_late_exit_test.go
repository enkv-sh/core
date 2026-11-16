package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/telemetry"
)

type publicationHeldNativeOwner struct {
	publicationPrivateOwner
	input                          publicationOwnerInput
	held                           chan *publicationHeldNativeOwner
	release                        <-chan struct{}
	dispatch                       contract.PublicationDispatch
	wire                           contract.PublicationResult
	code                           contract.CryptoResultCode
	prepares, arms, sends, retires int
}

func (o *publicationHeldNativeOwner) Prepare(ctx context.Context, id contract.ID, selected *contract.ConsumerSelection) ([]contract.KeyUseRow, contract.CryptoResultCode) {
	o.prepares++
	return o.publicationPrivateOwner.Prepare(ctx, id, selected)
}

func (o *publicationHeldNativeOwner) Arm(ctx context.Context, id contract.ID, dispatch contract.PublicationDispatch) error {
	if err := o.publicationPrivateOwner.Arm(ctx, id, dispatch); err != nil {
		return err
	}
	o.dispatch = dispatch
	o.arms++
	return nil
}

func (o *publicationHeldNativeOwner) Send(ctx context.Context, id contract.ID) (contract.PublicationResult, contract.CryptoResultCode) {
	select {
	case o.held <- o:
	case <-ctx.Done():
		return contract.PublicationResult{}, contract.CryptoInvalidAdmission
	}
	select {
	case <-o.release:
	case <-ctx.Done():
		return contract.PublicationResult{}, contract.CryptoInvalidAdmission
	}
	o.sends++
	o.wire, o.code = o.publicationPrivateOwner.Send(ctx, id)
	return o.wire, o.code
}

func (o *publicationHeldNativeOwner) Retire(ctx context.Context) error {
	o.retires++
	return o.publicationPrivateOwner.Retire(ctx)
}

// full_only: false
func TestPublicationNativeLateExit(t *testing.T) {
	for _, deletion := range []bool{false, true} {
		name := "old_value"
		if deletion {
			name = "old_delete_reused_name"
		}
		t.Run(name, func(t *testing.T) { publicationNativeLateExit(t, deletion) })
	}
}

func publicationNativeLateExit(t *testing.T, deletion bool) {
	t.Helper()
	unrelatedConfig := installedPublicationTestConfig(t)
	f, env, input, private, staging := nativePublicationFixture(t, false)
	if err := env.Custody.InstallPublication(t.Context(), unrelatedConfig, "unrelated", publicationTestConfigContract); err != nil {
		t.Fatal("install unrelated publication child", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	recorder := newPublicationDiagnosticCapture()
	ctx = telemetry.WithCapability(ctx, telemetry.NewCapability(nil, recorder.recorder))
	input.deadline = time.Now().Add(80 * time.Second)
	birthResult := nativePublicationPlan(t, ctx, f, input, private, recorder).execute(ctx, private, recorder.current(publicationEngineCurrent(f)))
	assertNativePublicationACK(t, birthResult, 1, contract.PublicationCreateWithValue)
	assertNativePublicationJoined(t, recorder, staging, 1)
	initial := publicationEngineReopen(t, f)
	coordinateID := birthResult.output.Entries[0].CoordinateID
	birthID := birthResult.output.Entries[0].Actions[0].AttemptID
	oldCoordinate, oldBirth := initial.coordinates[coordinateID], initial.markers[birthID]
	entries := f.session.currentEntryInputs()
	if deletion {
		f.session = selectAdmittedOutputConfiguration(t, ctx, f.session, env, env.Custody, entries, &outputApplyInput{})
		input.names, input.deletes = nil, []contract.ID{coordinateID}
	} else {
		entries[0].InputBytes = []byte("updated plain data")
		parent := admitSuppliedComparison(t, f.session, env.Custody, entries)
		comparison, state := f.session.Compare(ctx, entries, parent)
		recorder.collect()
		if comparison == nil {
			t.Fatal("late value comparison", state)
		}
		candidate, state := f.session.Prepare(ctx, comparison, admit(t, f.session, comparison), env.Trust)
		recorder.collect()
		if candidate == nil {
			t.Fatal("late value preparation", state)
		}
		env.Custody.RetireApply()
		state = f.session.Select(ctx, candidate)
		recorder.collect()
		if state.Outcome != ObservedCurrent {
			t.Fatal("late value selection", state)
		}
	}
	publicationEngineReopen(t, f)
	// This multi-operation fixture must consume the bounded recorder between
	// phases. Keep every record for the final joint A/B assertion. Drain only
	// before A starts, while A is held before native Send, or after A joins.
	var heldRecords []telemetry.DiagnosticRecord
	collectDiagnostics := func() {
		heldRecords = append(heldRecords, drainNativePublicationDiagnostics(t, recorder)...)
	}
	collectDiagnostics()
	held := make(chan *publicationHeldNativeOwner, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseA := func() { releaseOnce.Do(func() { close(release) }) }
	heldPrivate := private
	heldPrivate.NewOwner = func(ctx context.Context, in publicationOwnerInput) (publicationPrivateOwner, error) {
		owner, err := private.NewOwner(ctx, in)
		if err != nil {
			return nil, err
		}
		return &publicationHeldNativeOwner{publicationPrivateOwner: owner, input: in, held: held, release: release}, nil
	}
	plan := nativePublicationPlan(t, ctx, f, input, heldPrivate, recorder)
	done := make(chan publicationOperationResult, 1)
	go func() { done <- plan.execute(ctx, heldPrivate, recorder.current(publicationEngineCurrent(f))) }()
	joined := false
	defer func() {
		if !joined {
			cancel()
			releaseA()
			<-done
		}
	}()
	var a *publicationHeldNativeOwner
	select {
	case a = <-held:
	case got := <-done:
		joined = true
		t.Fatal("A returned before native hold", got.state)
	case <-ctx.Done():
		t.Fatal("A native hold expired")
	}
	heldSelected := publicationEngineReopen(t, f)
	oldAction := uint8(contract.PublicationWriteValue)
	if deletion {
		oldAction = contract.PublicationDeleteOwned
	}
	marker, present := heldSelected.markers[a.dispatch.AttemptID]
	if !present || marker.State != contract.PublicationMayHaveEntered || marker.Projection.Action != oldAction || a.prepares != 1 || a.arms != 1 || a.sends != 0 || a.retires != 0 || a.input.Birth == nil || *a.input.Birth != oldBirth {
		t.Fatal("A did not hold the original armed qualified owner")
	}
	collectDiagnostics()
	if !deletion {
		f.session = selectAdmittedOutputConfiguration(t, ctx, f.session, env, env.Custody, entries, &outputApplyInput{})
	}
	publicationEngineReopen(t, f)
	predecessor := f.session
	removed := []generatedRecordKey{{contract.PublicationCoordinateSupportKind, coordinateID}, {contract.PublicationMarkerSupportKind, birthID}, {contract.PublicationMarkerSupportKind, a.dispatch.AttemptID}}
	actualClosure := publicationJointRetiredCoordinateRemovedRows(t, predecessor, coordinateID)
	if len(actualClosure) != len(removed) {
		t.Fatal("retired coordinate has an unexpected dependent closure")
	}
	expectedRows, err := capacityConfigurationPreservedFacts(ctx, predecessor)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range removed {
		if !slices.Contains(actualClosure, key) {
			t.Fatal("retired coordinate lacks expected dependent", key.kind, key.id)
		}
		delete(expectedRows, key)
	}
	var expectedOrder []format.PublicationCoordinateOrder
	for _, order := range predecessor.adminIndex.PublicationOrder {
		if order.CoordinateID != coordinateID {
			expectedOrder = append(expectedOrder, order)
		}
	}
	expectedWarning := predecessor.root.WarningBits | WarningPublicationOrderValue | WarningDiscardedExactEvidence | WarningPossibleStoreGarbage
	expectedWindows, err := predecessor.receiptWindows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var targetGroup format.AdministrativeGroup
	for _, group := range predecessor.adminIndex.Groups {
		if group.GroupID == coordinateID {
			targetGroup = group
		}
	}
	if targetGroup.GroupID.IsZero() {
		t.Fatal("retired coordinate owner absent")
	}
	candidate, state := prepareTestEndSelectedWork(t, predecessor, ctx, coordinateID, env.Trust)
	collectDiagnostics()
	if candidate == nil {
		t.Fatal("actual retired-coordinate EndWork preparation", state)
	}
	next, state := predecessor.selectCandidate(ctx, candidate)
	collectDiagnostics()
	if next == nil || state.Outcome != ObservedCurrent {
		t.Fatal("actual retired-coordinate EndWork selection", state)
	}
	disposed := publicationEngineReopen(t, f)
	assertPublicationJointExitPreserved(t, f.session, expectedRows, expectedOrder, removed)
	publicationJointPhysicalCharge(t, predecessor, f.session, candidate)
	for _, key := range removed {
		if key.kind == contract.PublicationCoordinateSupportKind {
			if _, present := disposed.coordinates[key.id]; present {
				t.Fatal("ended coordinate survived")
			}
		} else if _, present := disposed.markers[key.id]; present {
			t.Fatal("ended marker survived")
		}
		if slices.ContainsFunc(f.session.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == key.id }) {
			t.Fatal("ended owner survived")
		}
	}
	windows, err := f.session.receiptWindows(ctx)
	if err != nil || len(windows.Successes) != len(expectedWindows.Successes)+1 || !slices.Equal(windows.Successes[:len(expectedWindows.Successes)], expectedWindows.Successes) || !slices.Equal(windows.Failures, expectedWindows.Failures) {
		t.Fatal("coordinate exit receipt append", err)
	}
	receipt := windows.Successes[len(windows.Successes)-1]
	if receipt.OperationKind != contract.OperationEndSelectedWork || receipt.StateResult != contract.ReceiptStateWorkEnded || receipt.EffectSummary != contract.ReceiptEffectNotApplicable || receipt.OutputSummary != contract.ReceiptOutputNotApplicable || receipt.EvidenceCeiling != contract.ReceiptEvidenceCanonical || receipt.CanonicalOutcome != contract.ReceiptCanonicalSelected || receipt.DomainID != env.Domain || receipt.RequestedRevisionID != f.session.head.Core.Revision || receipt.RequestIdentityDigest != candidate.head.EndWork.RequestCoreDigest || receipt.AdministrativeDisposition != candidate.head.EndWork.RequestCoreDigest || receipt.AdministrativeWarningChanges != expectedWarning&^predecessor.root.WarningBits || receipt.AdministrativePageDelta != int16(f.session.root.ChildCount)-int16(predecessor.root.ChildCount) || receipt.AdministrativeByteDelta != int64(f.session.root.ChildEncodedBytes)-int64(predecessor.root.ChildEncodedBytes) || receipt.AcknowledgedCount != 0 || receipt.ConfirmedCount != 0 || receipt.UnknownCount != 0 || receipt.SummaryCounts != ([contract.ReceiptSummaryCount]uint32{}) {
		t.Fatal("coordinate exit exact administrative receipt fields")
	}
	if f.session.root.WarningBits != expectedWarning || receipt.AdministrativeTargetID != publicationExitTarget(predecessor, coordinateID) || receipt.AdministrativeTargetKind != targetGroup.OwnerKind || receipt.AdministrativeOriginalEvidence != targetGroup.SelectedEvidenceSummary || receipt.OperationID != candidate.head.EndWork.OperationID || receipt.PredecessorRevisionID != predecessor.head.Core.Revision || receipt.ObservedRevisionID != f.session.head.Core.Revision || receipt.WarningBits != uint64(expectedWarning) {
		t.Fatal("coordinate exit receipt or permanent warnings")
	}
	collectDiagnostics()
	entries[0].InputBytes = []byte("private data")
	f.session = selectAdmittedOutputConfiguration(t, ctx, f.session, env, env.Custody, entries, nativePublicationOutput(entries, []uint64{1, 9}))
	publicationEngineReopen(t, f)
	input.names, input.deletes = []string{"plain"}, nil
	var bInput publicationOwnerInput
	var bOwnerID contract.ID
	bOwners := 0
	bPrivate := private
	bPrivate.NewOwner = func(ctx context.Context, in publicationOwnerInput) (publicationPrivateOwner, error) {
		bInput = in
		owner, err := private.NewOwner(ctx, in)
		if err == nil {
			bOwnerID = owner.InstanceID()
			bOwners++
		}
		return owner, err
	}
	b := nativePublicationPlan(t, ctx, f, input, bPrivate, recorder).execute(ctx, bPrivate, recorder.current(publicationEngineCurrent(f)))
	assertNativePublicationACK(t, b, 1, contract.PublicationCreateWithValue)
	collectDiagnostics()
	selectedB := publicationEngineReopen(t, f)
	bRow := b.output.Entries[0].Actions[0]
	bCoordinate := selectedB.coordinates[coordinateID]
	bBirth := selectedB.markers[bRow.AttemptID]
	wantBInstance := "test-instance/plain-target/" + hex.EncodeToString(bRow.AttemptID[:])
	if b.output.Entries[0].CoordinateID != coordinateID || a.input.Target.ServiceContractID != "test-output/service/v1" || bInput.Target.ServiceContractID != "test-output/service/v1" || a.input.Target.CanonicalTarget != "plain-target" || bInput.Target.CanonicalTarget != "plain-target" || a.input.Target.ConsumerLocator != "plain-target" || bInput.Target.ConsumerLocator != "plain-target" || !bytes.Equal(a.input.Target.TargetData, []byte("target:plain-target")) || !bytes.Equal(bInput.Target.TargetData, []byte("target:plain-target")) || bCoordinate.OwnerState != contract.PublicationOwnerQualified || bCoordinate.OwnedBirthAttemptID != bRow.AttemptID || bRow.Evidence.SafeResourceID != wantBInstance || !publicationQualifiedBirthValid(env.Domain, bCoordinate, bBirth) {
		t.Fatal("fresh B exact physical slot or qualified birth")
	}
	for _, pair := range [][2]contract.ID{{a.dispatch.AttemptID, bRow.AttemptID}, {a.dispatch.OperationID, b.output.OperationID}, {oldCoordinate.LastBindingIncarnationID, bCoordinate.LastBindingIncarnationID}, {oldCoordinate.CurrentPublicationIncarnationID, bCoordinate.CurrentPublicationIncarnationID}, {birthID, bCoordinate.OwnedBirthAttemptID}, {a.InstanceID(), bOwnerID}} {
		if pair[0].IsZero() || pair[1].IsZero() || pair[0] == pair[1] {
			t.Fatal("fresh identity was reused")
		}
	}
	if bOwners != 1 || oldBirth.Evidence.SafeResourceID == wantBInstance {
		t.Fatal("TEST birth instance was reused")
	}
	beforeB := f.session
	head, token := bytes.Clone(beforeB.body), beforeB.token
	configuration, current, access, order := beforeB.root.OutputConfiguration, beforeB.currentEntryInputs(), beforeB.accessRecords(), clonePublicationWork(beforeB.adminIndex).PublicationOrder
	creates, cas := f.store.creates, f.store.cas
	releaseA()
	var late publicationOperationResult
	select {
	case late = <-done:
		joined = true
	case <-ctx.Done():
		t.Fatal("original A did not join")
	}
	if a.sends != 1 || a.retires != 1 || a.code != contract.CryptoSuccess || contract.ValidatePublicationResult(a.dispatch, a.wire) != nil || a.wire.Evidence.Class != contract.PublicationRequestAcknowledged || a.wire.Evidence.SafeResourceID != oldBirth.Evidence.SafeResourceID || a.wire.Evidence.NormalizedStatus != 204 {
		t.Fatal("original A native wire result or positive retirement")
	}
	if late.summary != contract.PublicationSummaryUnknown || late.state.Reason != DifferentSelection || len(late.output.Entries) != 1 || len(late.output.Entries[0].Actions) != 1 || late.output.Entries[0].Actions[0].AttemptID != a.dispatch.AttemptID || late.output.Entries[0].Actions[0].Disposition != contract.PublicationOutcomeUnknown {
		t.Fatal("discarded A close did not refuse DifferentSelection", late.state)
	}
	afterB := publicationEngineReopen(t, f)
	if f.store.creates != creates || f.store.cas != cas || !bytes.Equal(f.session.body, head) || f.session.token != token || !reflect.DeepEqual(afterB, selectedB) || f.session.root.OutputConfiguration != configuration || !reflect.DeepEqual(f.session.currentEntryInputs(), current) || !reflect.DeepEqual(f.session.accessRecords(), access) || !reflect.DeepEqual(f.session.adminIndex.PublicationOrder, order) || f.session.root.WarningBits != expectedWarning {
		t.Fatal("late A changed selected B or wrote to Store")
	}
	if _, present := afterB.markers[a.dispatch.AttemptID]; present {
		t.Fatal("late A marker resurrected")
	}
	collectDiagnostics()
	assertNativePublicationRecordsJoined(t, heldRecords, staging, 2)
	entries = append(entries, ApplyEntryInput{Name: "unrelated", Recipients: []contract.ID{input.acting}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("private data"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
	f.admission.admission.publicationNamespaces = append(f.admission.admission.publicationNamespaces, publicationNamespace{domain: env.Domain, service: "test-output/service/v1", physical: "unrelated-target", premise: fixtureID(env.Domain, "independent unrelated namespace")})
	f.session.admission.publicationNamespaces = f.admission.admission.publicationNamespaces
	progressOutput := nativePublicationOutput(entries[:1], []uint64{1, 9})
	unrelatedOutput := nativePublicationOutput(entries[1:], []uint64{1, 9})
	unrelatedOutput.bindings[0].destinationID = "unrelated"
	progressOutput.bindings = append(progressOutput.bindings, unrelatedOutput.bindings[0])
	progressOutput.routes = append(progressOutput.routes, outputApplyRoute{entryName: "unrelated", destinations: []string{"unrelated"}})
	f.session = selectAdmittedOutputConfiguration(t, ctx, f.session, env, env.Custody, entries, progressOutput)
	input.names = []string{"unrelated"}
	unrelated := nativePublicationPlan(t, ctx, f, input, private, recorder).execute(ctx, private, recorder.current(publicationEngineCurrent(f)))
	assertNativePublicationACK(t, unrelated, 1, contract.PublicationCreateWithValue)
	progressed := publicationEngineReopen(t, f)
	if !reflect.DeepEqual(progressed.coordinates[coordinateID], bCoordinate) || progressed.markers[bRow.AttemptID] != bBirth || f.session.root.WarningBits != expectedWarning || unrelated.output.Entries[0].CoordinateID == coordinateID || unrelated.output.Entries[0].Actions[0].AttemptID == bRow.AttemptID {
		t.Fatal("unrelated progress changed B or permanent warnings")
	}
	assertNativePublicationJoined(t, recorder, staging, 1)
}

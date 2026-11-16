package core

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// The selected fixture supplies Store/Trust/key routes and installed artifacts.
// Publication admission, fresh opens and custody are the production owners.
func installedPublicationEngine(t testing.TB, f *fixture, private publicationPrivate, captures ...*publicationDiagnosticCapture) *InstalledPublication {
	t.Helper()
	basis := f.session.admission.publicBasis()
	control, err := basis.ControlCore(f.session.root.Domain, f.store.Descriptor())
	if err != nil {
		t.Fatal("publication installation public basis", err)
	}
	i := PublicationInstallation{
		ExpectedDomain: f.session.root.Domain, ExpectedStore: f.store.Descriptor(),
		PublicBasis: basis, ExpectedControl: control,
		Store: f.store, Trust: f.trust, CompositionID: f.session.admission.composition,
		CloseInstalled: func() {},
		Namespace: func(domain contract.ID, target contract.OutputTarget) (contract.ID, error) {
			if domain != f.session.root.Domain || target.TargetContractID != "test-output/target/v1" || target.ServiceContractID != "test-output/service/v1" {
				return contract.ID{}, errors.New("installed test profile unavailable")
			}
			body := append([]byte("ENKV/OUTPUT/MANAGED-NAME-EXCLUSIVE-USE/v1\x00"), domain[:]...)
			for _, field := range []string{target.ServiceContractID, target.TargetContractID, target.CanonicalTarget} {
				body = binary.BigEndian.AppendUint32(body, uint32(len(field)))
				body = append(body, field...)
			}
			return contract.Hash(body), nil
		},
		SelectPolicyAction: func(ctx context.Context, in PublicationPolicyActionInput) (uint8, error) {
			return private.SelectPolicyAction(ctx, publicationPolicyActionInput(in))
		},
		Actions: func(ctx context.Context, target PublicationExecutionInput) (PublicationActionFacts, error) {
			facts, err := private.Actions(ctx, publicationExecutionInput(target))
			return PublicationActionFacts(facts), err
		},
		Check: func(ctx context.Context, input PublicationActionCheckInput) (PublicationActionCheckFacts, error) {
			facts, err := private.Check(ctx, publicationActionCheckInput(input))
			return PublicationActionCheckFacts(facts), err
		},
		NewOwner: func(ctx context.Context, input PublicationOwnerInput) (PublicationPrivateOwner, error) {
			return private.NewOwner(ctx, publicationOwnerInput{Projection: input.Projection, DestinationID: input.DestinationID,
				ConfigContractID: input.ConfigContractID, Target: input.Target, Coordinate: input.Coordinate, Birth: input.Birth, UncertainCreate: input.UncertainCreate,
				ActionCheck: publicationActionCheckFacts(input.ActionCheck), Deadline: input.Deadline})
		},
	}
	if len(captures) == 1 {
		i.Store = &installedPublicationCaptureStore{memoryStore: f.store, capture: captures[0]}
	}
	engine, err := NewInstalledPublication(i)
	if err != nil {
		t.Fatal("production publication construction", err)
	}
	t.Cleanup(engine.Close)
	return engine
}

type installedPublicationCaptureStore struct {
	*memoryStore
	capture *publicationDiagnosticCapture
}

func (s *installedPublicationCaptureStore) Read(ctx context.Context, key string, maximum uint32) contract.ReadResult {
	s.capture.collect()
	out := s.memoryStore.Read(ctx, key, maximum)
	s.capture.collect()
	return out
}

func assertInstalledPublicationVector(t testing.TB, result PublicPublicationResult, summary uint8, coordinates int) {
	t.Helper()
	if result.RequestID.IsZero() || result.DomainID.IsZero() || result.OperationID.IsZero() || result.RequestIdentity.IsZero() || result.Output == nil || result.Summary != summary || len(result.Output.Entries) != coordinates {
		t.Fatalf("incomplete public publication result: state=%+v summary=%d", result.Result, result.Summary)
	}
	if result.Output.DomainID != result.DomainID || result.Output.OperationID != result.OperationID {
		t.Fatal("public vector lost its admitted operation")
	}
	if _, err := contract.EncodePublicationOutcomeVector(*result.Output); err != nil {
		t.Fatal("invalid complete public vector", err)
	}
	if !ValidPublicationDescriptions(result.DomainID, result.Output, result.Descriptions) {
		t.Fatal("public result lost the complete admitted target descriptions")
	}
}

// full_only: false
func TestInstalledPublicPublicationNativeCreateNoopAndRetainedDeletion(t *testing.T) {
	f, env, input, private, staging := nativePublicationFixture(t, false)
	recorder := newPublicationDiagnosticCapture()
	ctx, cancel := context.WithTimeout(telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder.recorder)), time.Minute)
	defer cancel()
	first := installedPublicationEngine(t, f, private, recorder).Publish(ctx, fixtureID(env.Domain, "public native creation"), PublicationRequest{Names: input.names})
	assertInstalledPublicationVector(t, first, contract.PublicationSummaryComplete, 1)
	description := first.Descriptions[0]
	if description.Origin != PublicationTargetCurrent || description.EntryName == nil || *description.EntryName != "plain" || description.DestinationID == nil || *description.DestinationID != "native" || description.ServiceContractID != "test-output/service/v1" || description.CanonicalTarget != "plain-target" {
		t.Fatal("installed publication lost its exact current target", description)
	}
	if row := first.Output.Entries[0].Actions[0]; row.Action != contract.PublicationCreateWithValue || row.Disposition != contract.PublicationOutcomeAcknowledged {
		t.Fatal("native public create was not selected", row)
	}
	assertNativePublicationJoined(t, recorder, staging, 1)
	coordinate, birth := first.Output.Entries[0].CoordinateID, first.Output.Entries[0].Actions[0].AttemptID
	publicationEngineReopen(t, f)
	publicBefore, privateBefore := env.Custody.Calls()
	repeat := installedPublicationEngine(t, f, private, recorder).Publish(ctx, fixtureID(env.Domain, "public native repeat"), PublicationRequest{Names: input.names})
	assertInstalledPublicationVector(t, repeat, contract.PublicationSummaryNoChange, 1)
	publicAfter, privateAfter := env.Custody.Calls()
	if publicBefore != publicAfter || privateBefore != privateAfter || repeat.Output.Entries[0].Actions[0].Disposition != contract.PublicationNoOp || repeat.RequestIdentity == first.RequestIdentity {
		t.Fatal("public no-op used custody or restored an earlier request")
	}
	assertNativePublicationNoPrivateWork(t, recorder)
	selectOutputConfiguration(t, f, nil, &outputApplyInput{})
	retained := publicationEngineReopen(t, f).coordinates[coordinate]
	if retained.BindingState != contract.PublicationBindingRetired || retained.OwnedBirthAttemptID != birth {
		t.Fatal("source removal lost exact deletion evidence")
	}
	deleted := installedPublicationEngine(t, f, private, recorder).Publish(ctx, fixtureID(env.Domain, "public deletion only"), PublicationRequest{DeleteCoordinates: []contract.ID{coordinate}})
	assertInstalledPublicationVector(t, deleted, contract.PublicationSummaryComplete, 1)
	description = deleted.Descriptions[0]
	if description.Origin != PublicationTargetRetainedDeletion || description.EntryName != nil || description.DestinationID == nil || *description.DestinationID != "native" || description.CanonicalTarget != "plain-target" || description.CoordinateID != coordinate {
		t.Fatal("retained deletion invented a current name or lost its target", description)
	}
	if first.Descriptions[0].EntryName == nil || *first.Descriptions[0].EntryName != "plain" || first.Descriptions[0].CanonicalTarget != "plain-target" {
		t.Fatal("later selected state changed an earlier result description")
	}
	if row := deleted.Output.Entries[0].Actions[0]; row.Action != contract.PublicationDeleteOwned || row.Disposition != contract.PublicationOutcomeAcknowledged {
		t.Fatal("deletion-only did not use retained selected evidence", row)
	}
	assertNativePublicationJoined(t, recorder, staging, 1)
	after := publicationEngineReopen(t, f)
	if after.coordinates[coordinate].OwnedBirthAttemptID != birth || after.coordinates[coordinate].LastDeleteAckAttemptID != deleted.Output.Entries[0].Actions[0].AttemptID || after.coordinates[coordinate].PossibleRemoteObject != 1 {
		t.Fatal("public deletion rewrote birth or claimed remote absence")
	}
}

// full_only: false
func TestInstalledPublicPublicationRequiresEveryCurrentUnknownBlocker(t *testing.T) {
	f, env, input, private, staging := nativePublicationFixture(t, true, "plain-target-unknown-first", "secret-target")
	recorder := newPublicationDiagnosticCapture()
	ctx, cancel := context.WithTimeout(telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder.recorder)), time.Minute)
	defer cancel()
	first := installedPublicationEngine(t, f, private, recorder).Publish(ctx, fixtureID(env.Domain, "public unknown first"), PublicationRequest{Names: input.names})
	assertInstalledPublicationVector(t, first, contract.PublicationSummaryUnknown, 2)
	var unknown contract.PublicationTargetOutcome
	acknowledged := 0
	for _, target := range first.Output.Entries {
		switch target.Actions[0].Disposition {
		case contract.PublicationOutcomeUnknown:
			unknown = target
		case contract.PublicationOutcomeAcknowledged:
			acknowledged++
		}
	}
	if unknown.CoordinateID.IsZero() || acknowledged != 1 {
		t.Fatal("independent public results were not preserved")
	}
	assertNativePublicationJoined(t, recorder, staging, 2)
	publicationEngineReopen(t, f)
	blocked := installedPublicationEngine(t, f, private, recorder).Publish(ctx, fixtureID(env.Domain, "public default blocked"), PublicationRequest{Names: input.names})
	assertInstalledPublicationVector(t, blocked, contract.PublicationSummaryUnknown, 2)
	assertNativePublicationNoPrivateWork(t, recorder)
	old := unknown.Actions[0].AttemptID
	second := installedPublicationEngine(t, f, private, recorder).Publish(ctx, fixtureID(env.Domain, "public authorized new unknown"), PublicationRequest{Names: input.names, RepublishAfterUnknown: []contract.ID{old}})
	assertInstalledPublicationVector(t, second, contract.PublicationSummaryUnknown, 2)
	assertNativePublicationJoined(t, recorder, staging, 1)
	selected := publicationEngineReopen(t, f)
	blockers := publicationBlockers(selected, unknown.CoordinateID)
	if len(blockers) != 2 || !slices.Contains(blockers, old) || selected.markers[old].State != contract.PublicationUnknown || selected.coordinates[unknown.CoordinateID].LateEffectRisk == 0 {
		t.Fatal("republish lost old marker or late-effect warning")
	}
	for _, ids := range [][]contract.ID{{old}, {blockers[0], blockers[0]}, {fixtureID(env.Domain, "unrelated attempt")}} {
		refused := installedPublicationEngine(t, f, private, recorder).Publish(ctx, fixtureID(env.Domain, "public incomplete unknown set"), PublicationRequest{Names: input.names, RepublishAfterUnknown: ids})
		if refused.Result.Outcome != AdmissionRefused || refused.Output != nil {
			t.Fatal("inexact unknown authorization reached an effect", refused.Result)
		}
	}
	assertNativePublicationNoPrivateWork(t, recorder)
	exact := installedPublicationEngine(t, f, private, recorder).Publish(ctx, fixtureID(env.Domain, "public complete unknown set"), PublicationRequest{Names: input.names, RepublishAfterUnknown: blockers})
	assertInstalledPublicationVector(t, exact, contract.PublicationSummaryUnknown, 2)
	assertNativePublicationJoined(t, recorder, staging, 1)
	after := publicationEngineReopen(t, f)
	if len(publicationBlockers(after, unknown.CoordinateID)) != 3 || after.markers[old] != selected.markers[old] {
		t.Fatal("exact republish changed an old unknown")
	}
}

// full_only: false
func TestInstalledPublicPublicationRefusesInvalidSelectionBeforePrivateWork(t *testing.T) {
	f, env, input, private, _ := nativePublicationFixture(t, false)
	recorder := newPublicationDiagnosticCapture()
	ctx, cancel := context.WithTimeout(telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder.recorder)), time.Minute)
	defer cancel()
	configuration, state := f.session.currentOutputConfigurationForApply(ctx)
	if state.Outcome != 0 {
		t.Fatal(state)
	}
	target := configuration.Bindings[0].Targets[0]
	active, err := contract.PublicationCoordinateID(env.Domain, target.ServiceContractID, target.CanonicalTarget)
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []PublicationRequest{
		{}, {Names: []string{input.names[0], input.names[0]}}, {Names: []string{string([]byte{255})}},
		{Names: []string{"absent"}}, {DeleteCoordinates: []contract.ID{active}},
		{DeleteCoordinates: []contract.ID{active, active}}, {DeleteCoordinates: []contract.ID{fixtureID(env.Domain, "foreign coordinate")}},
		{Names: input.names, RepublishAfterUnknown: []contract.ID{fixtureID(env.Domain, "stale unknown")}},
	} {
		result := installedPublicationEngine(t, f, private, recorder).Publish(ctx, fixtureID(env.Domain, "public invalid selection"), request)
		if result.Result.Outcome != AdmissionRefused || result.Output != nil || !result.OperationID.IsZero() {
			t.Fatal("invalid selectors acquired a complete effect plan", result.Result)
		}
	}
	assertNativePublicationNoPrivateWork(t, recorder)
}

// full_only: false
func TestInstalledPublicPublicationCompleteGroupRejectsLaterEncodedOverflow(t *testing.T) {
	f, env, _, private, staging := nativePublicationFixture(t, false)
	entries := f.session.currentEntryInputs()
	entries = append(entries, ApplyEntryInput{Name: "oversized", ValueSource: contract.Supplied,
		ConfidentialityClass: contract.Plain, Recipients: []contract.ID{f.session.admission.recipient}, InputBytes: make([]byte, 49153), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
	configuration, state := f.session.currentOutputConfigurationForApply(t.Context())
	if state.Outcome != 0 {
		t.Fatal(state)
	}
	target := configuration.Bindings[0].Targets[0]
	// Source declarations derive their incarnation only during selection.
	target.EntryIncarnationID = contract.ID{}
	target.PayloadEncoding = contract.OutputEncodingBase64
	later := target
	later.EntryIncarnationID = contract.ID{}
	hermeticRetargetOutput(&later, "plain-target-overflow", "plain-target-overflow")
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "native", destination: configuration.Bindings[0].Destination,
		targets: []outputApplyTarget{{entryName: "plain", target: target}, {entryName: "oversized", target: later}}}},
		routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"native"}}},
		groups: [][]string{{"plain", "oversized"}}}
	f.session = selectAdmittedOutputConfiguration(t, t.Context(), f.session, env, env.Custody, entries, output)
	f.admission = OpenContext{admission: &f.session.admission}
	recorder := newPublicationDiagnosticCapture()
	ctx, cancel := context.WithTimeout(telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder.recorder)), time.Minute)
	defer cancel()
	partial := installedPublicationEngine(t, f, private, recorder).Publish(ctx, fixtureID(env.Domain, "public partial group"), PublicationRequest{Names: []string{"plain"}})
	if partial.Output != nil || partial.Result.Outcome != AdmissionRefused {
		t.Fatal("partial explicit group reached effects", partial.Result)
	}
	assertNativePublicationNoPrivateWork(t, recorder)
	beforePublic, beforePrivate := env.Custody.Calls()
	complete := installedPublicationEngine(t, f, private, recorder).Publish(ctx, fixtureID(env.Domain, "public oversized group"), PublicationRequest{Names: []string{"plain", "oversized"}})
	afterPublic, afterPrivate := env.Custody.Calls()
	// Independent padded Base64 length: 4*ceil(49153/3)=65540, over
	// the test profile's 65536-byte ceiling. No value may be released.
	if complete.Output != nil || complete.Result.Outcome != AdmissionRefused || complete.Result.Reason != CapacityExceeded || beforePublic != afterPublic || beforePrivate != afterPrivate {
		t.Fatal("later encoded overflow did not reject the complete group", complete.Result)
	}
	starts, joins := 0, 0
	for _, record := range drainNativePublicationDiagnostics(t, recorder) {
		if record.Validate() != nil {
			t.Fatal("invalid group refusal diagnostic")
		}
		if record.Provider == telemetry.ProviderCrypto {
			t.Fatal("group overflow entered private custody", record.Operation)
		}
		if record.Provider != telemetry.ProviderOutputHost {
			continue
		}
		if record.Operation == telemetry.OpOutputHostDispatch {
			t.Fatal("group overflow dispatched a value")
		}
		if record.Operation == telemetry.OpOutputHostJoin {
			if record.Event == telemetry.DiagnosticStart {
				starts++
			}
			if record.Event == telemetry.DiagnosticReturn && record.Result == telemetry.ResultSuccess {
				joins++
			}
		}
	}
	files, err := os.ReadDir(staging)
	if starts != joins || err != nil || len(files) != 0 {
		t.Fatal("passive group checks did not join", starts, joins, err)
	}
}

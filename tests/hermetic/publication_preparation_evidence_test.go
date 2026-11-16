package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
	"golang.org/x/sys/unix"
)

type publicationPreparationFaultOwner struct {
	publicationPrivateOwner
	armed   func(contract.PublicationDispatch)
	sent    func()
	retired func(error)
}

type publicationCollisionResultOwner struct{ *publicationControlledOwner }

func (owner *publicationCollisionResultOwner) Send(ctx context.Context, id contract.ID) (contract.PublicationResult, contract.CryptoResultCode) {
	result, code := owner.publicationControlledOwner.Send(ctx, id)
	if code == contract.CryptoSuccess && result.Evidence.Class == contract.PublicationQualifiedNoEffect {
		result.Evidence.NormalizedStatus = 409
	}
	return result, code
}

// full_only: false
func TestInstalledPublicationRejectedCreatePreservesEarlierEffectsAndOwnership(t *testing.T) {
	for _, condition := range []string{"sole-collision", "earlier-ack", "later-fresh-attempt"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f := newFixture(t, 1, false, 1)
			entries := f.session.currentEntryInputs()
			count := 1
			if condition == "earlier-ack" {
				count = 2
			}
			output := &outputApplyInput{}
			for i := 0; i < count; i++ {
				name := "collision-a"
				if i == 1 {
					name = "collision-b"
				}
				target := hermeticNativeOutputTarget(name, name, contract.OutputEncodingRaw, contract.OutputPolicy{})
				target.Capabilities = contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityWriteValue | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot
				target.CreateValueBounds = contract.OutputPayloadBounds{}
				output.bindings = append(output.bindings, outputApplyBinding{destinationID: name, targets: []outputApplyTarget{{entryName: entries[0].Name, target: target}}})
			}
			destinations := []string{"collision-a"}
			if count == 2 {
				destinations = append(destinations, "collision-b")
			}
			output.routes = []outputApplyRoute{{defaultRoute: true, destinations: destinations}}
			selectOutputConfiguration(t, f, entries, output)
			private := newPublicationControlledPrivate()
			var acknowledgedCoordinate, collisionCoordinate contract.ID
			var sent []contract.PublicationProjection
			private.configureOwner = func(owner *publicationControlledOwner) {
				if owner.input.Projection.Action == contract.PublicationCreateEmpty {
					if condition == "earlier-ack" && acknowledgedCoordinate.IsZero() {
						acknowledgedCoordinate = owner.input.Projection.CoordinateID
					} else {
						collisionCoordinate = owner.input.Projection.CoordinateID
						owner.evidence = contract.PublicationQualifiedNoEffect
					}
				}
				owner.onSend = func() { sent = append(sent, owner.input.Projection) }
			}
			callbacks := private.callbacks()
			newOwner := callbacks.NewOwner
			callbacks.NewOwner = func(ctx context.Context, input publicationOwnerInput) (publicationPrivateOwner, error) {
				owner, err := newOwner(ctx, input)
				if err != nil {
					return nil, err
				}
				controlled, ok := owner.(*publicationControlledOwner)
				if !ok {
					t.Fatal("controlled publication owner unavailable")
				}
				return &publicationCollisionResultOwner{publicationControlledOwner: controlled}, nil
			}
			assertOwnersSettled := func() {
				t.Helper()
				for _, owner := range private.owners {
					if owner.prepared != 1 || owner.armed != 1 || owner.sent != 1 || owner.retired != 1 {
						t.Fatal("publication owner did not consume and settle exactly once")
					}
				}
			}
			result := installedPublicationEngine(t, f, callbacks).Publish(ctx, fixtureID(f.session.root.Domain, "post-entry collision "+condition), PublicationRequest{Names: []string{entries[0].Name}})
			wantSummary := uint8(contract.PublicationSummaryFailed)
			if condition == "earlier-ack" {
				wantSummary = contract.PublicationSummaryMixedTerminal
			}
			assertInstalledPublicationVector(t, result, wantSummary, count)
			if collisionCoordinate.IsZero() || len(sent) != 2*count-1 || sent[len(sent)-1].Action != contract.PublicationCreateEmpty || sent[len(sent)-1].CoordinateID != collisionCoordinate {
				t.Fatal("post-entry collision or earlier acknowledgement was not established")
			}
			if count == 2 && (sent[0].CoordinateID != acknowledgedCoordinate || sent[0].Action != contract.PublicationCreateEmpty || sent[1].CoordinateID != acknowledgedCoordinate || sent[1].Action != contract.PublicationWriteValue) {
				t.Fatal("the earlier independent target did not complete before collision")
			}
			var rejected, acknowledged contract.PublicationTargetOutcome
			for _, row := range result.Output.Entries {
				switch row.CoordinateID {
				case collisionCoordinate:
					rejected = row
				case acknowledgedCoordinate:
					acknowledged = row
				default:
					t.Fatal("publication returned an unrelated coordinate")
				}
			}
			if len(rejected.Actions) != 2 || rejected.Actions[0].Action != contract.PublicationCreateEmpty || rejected.Actions[0].Disposition != contract.PublicationOutcomeQualifiedNoEffect || rejected.Actions[0].AttemptID.IsZero() || rejected.Actions[0].Evidence.Entry != contract.PublicationMayHaveEnteredEntry || rejected.Actions[0].Evidence.Class != contract.PublicationQualifiedNoEffect || rejected.Actions[0].Evidence.NormalizedStatus != 409 || rejected.Actions[0].Evidence.SafeResourceID != "" || rejected.Actions[0].Evidence.ConsumerLocator != "" || rejected.Actions[1].Action != contract.PublicationWriteValue || rejected.Actions[1].Disposition != contract.PublicationNotSent || !rejected.Actions[1].AttemptID.IsZero() {
				t.Fatal("rejected create lost its exact evidence or admitted a dependent write")
			}
			assertOwnersSettled()
			selected := publicationEngineReopen(t, f)
			marker := selected.markers[rejected.Actions[0].AttemptID]
			coordinate := selected.coordinates[collisionCoordinate]
			if marker.State != contract.PublicationQualifiedNoEffectState || marker.Evidence != rejected.Actions[0].Evidence || coordinate.OwnerState != contract.PublicationOwnerNone || !coordinate.OwnedBirthAttemptID.IsZero() || !coordinate.OwnedInstanceDigest.IsZero() || !coordinate.LatestUnresolvedAttemptID.IsZero() || coordinate.PossibleRemoteObject != 0 || coordinate.LateEffectRisk != 0 {
				t.Fatal("cold rejection invented ownership, uncertainty or a possible created object")
			}
			if count == 2 {
				if len(acknowledged.Actions) != 2 || acknowledged.Actions[0].Disposition != contract.PublicationOutcomeAcknowledged || acknowledged.Actions[1].Disposition != contract.PublicationOutcomeAcknowledged {
					t.Fatal("later collision replaced the earlier complete action vector")
				}
				owned := selected.coordinates[acknowledgedCoordinate]
				if owned.OwnerState != contract.PublicationOwnerQualified || owned.OwnedBirthAttemptID != acknowledged.Actions[0].AttemptID || owned.LastValueAckAttemptID != acknowledged.Actions[1].AttemptID || selected.markers[acknowledged.Actions[0].AttemptID].Evidence != acknowledged.Actions[0].Evidence || selected.markers[acknowledged.Actions[1].AttemptID].Evidence != acknowledged.Actions[1].Evidence {
					t.Fatal("cold reopen lost earlier acknowledgement or its qualified birth")
				}
			}
			if condition == "later-fresh-attempt" {
				private.configureOwner = nil
				next := installedPublicationEngine(t, f, callbacks).Publish(ctx, fixtureID(f.session.root.Domain, "fresh after rejected create"), PublicationRequest{Names: []string{entries[0].Name}})
				assertInstalledPublicationVector(t, next, contract.PublicationSummaryComplete, 1)
				if len(next.Output.Entries[0].Actions) != 2 || next.Output.Entries[0].Actions[0].Action != contract.PublicationCreateEmpty || next.Output.Entries[0].Actions[0].Disposition != contract.PublicationOutcomeAcknowledged || next.Output.Entries[0].Actions[0].AttemptID == rejected.Actions[0].AttemptID || next.Output.Entries[0].Actions[1].Disposition != contract.PublicationOutcomeAcknowledged || len(private.owners) != 3 {
					t.Fatal("rejection did not permit a new independently admitted attempt")
				}
				assertOwnersSettled()
				return
			}
			selectOutputConfiguration(t, f, entries, &outputApplyInput{})
			publicationEngineReopen(t, f)
			owners, creates, swaps, signs := len(private.owners), f.store.creates, f.store.cas, f.trust.signs
			deletion := installedPublicationEngine(t, f, callbacks).Publish(ctx, fixtureID(f.session.root.Domain, "collision grants no deletion"), PublicationRequest{DeleteCoordinates: []contract.ID{collisionCoordinate}})
			if deletion.Result.Outcome != AdmissionRefused || deletion.Output != nil || len(private.owners) != owners || f.store.creates != creates || f.store.cas != swaps || f.trust.signs != signs {
				t.Fatal("sole rejected creation granted deletion or selected private work")
			}
			if count == 2 {
				cleanup := installedPublicationEngine(t, f, callbacks).Publish(ctx, fixtureID(f.session.root.Domain, "independent earlier birth cleanup"), PublicationRequest{DeleteCoordinates: []contract.ID{acknowledgedCoordinate}})
				assertInstalledPublicationVector(t, cleanup, contract.PublicationSummaryComplete, 1)
				if len(cleanup.Output.Entries[0].Actions) != 1 || cleanup.Output.Entries[0].Actions[0].Action != contract.PublicationDeleteOwned || cleanup.Output.Entries[0].Actions[0].Disposition != contract.PublicationOutcomeAcknowledged || len(private.owners) != owners+1 {
					t.Fatal("later rejected create suppressed independently qualified cleanup")
				}
				assertOwnersSettled()
			}
		})
	}
}

func (o *publicationPreparationFaultOwner) Send(ctx context.Context, id contract.ID) (contract.PublicationResult, contract.CryptoResultCode) {
	if o.sent != nil {
		defer o.sent()
	}
	return o.publicationPrivateOwner.Send(ctx, id)
}

func (o *publicationPreparationFaultOwner) Arm(ctx context.Context, id contract.ID, dispatch contract.PublicationDispatch) error {
	if err := o.publicationPrivateOwner.Arm(ctx, id, dispatch); err != nil {
		return err
	}
	o.armed(dispatch)
	return nil
}

func publicationLimitForPipeRefusal(t *testing.T) func() {
	t.Helper()
	var original unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &original); err != nil {
		t.Fatal(err)
	}
	var held []*os.File
	var once sync.Once
	restore := func() {
		once.Do(func() {
			if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &original); err != nil {
				t.Error("restore descriptor allowance", err)
			}
			for _, file := range held {
				if err := file.Close(); err != nil {
					t.Error("close descriptor-limit fixture", err)
				}
			}
		})
	}
	t.Cleanup(restore)
	var highest uintptr
	for range 8 {
		file, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, file)
		if file.Fd() > highest {
			highest = file.Fd()
		}
	}
	// Six free descriptors admit staging's peak and the first pipe, then
	// refuse a later pipe while all earlier acquired resources remain owned.
	limited := original
	limited.Cur = uint64(highest) + 7
	if limited.Cur > original.Cur {
		t.Fatal("descriptor allowance cannot reach the intended pipe boundary")
	}
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limited); err != nil {
		t.Fatal(err)
	}
	return restore
}

func (o *publicationPreparationFaultOwner) Retire(ctx context.Context) error {
	err := o.publicationPrivateOwner.Retire(ctx)
	o.retired(err)
	return err
}

// full_only: false
func TestInstalledPublicationPreparationEvidenceSelectsExactOutcome(t *testing.T) {
	for _, condition := range []string{"stage-before-launch", "credential-input-before-launch", "pipe-before-launch", "clean-pre-arm-refusal", "wrong-refusal-correlation", "refusal-with-failed-wait", "pre-arm-refusal-cleanup-failure", "sole-executable-removal-failure"} {
		t.Run(condition, func(t *testing.T) {
			slot := "plain-target"
			if condition == "sole-executable-removal-failure" {
				slot = "plain-target-cleanup-failure-0"
			}
			f, env, input, private, staging := nativePublicationFixture(t, false, slot)
			capture := newPublicationDiagnosticCapture()
			ctx, cancel := context.WithTimeout(telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, capture.recorder)), time.Minute)
			defer cancel()
			blockedTemporary := filepath.Join(staging, "not-a-directory")
			if err := os.WriteFile(blockedTemporary, nil, 0600); err != nil {
				t.Fatal(err)
			}
			original := private.NewOwner
			armed, retired, retirementFailed, pipeRefused := 0, 0, false, false
			var retirementErr error
			var restoreDescriptors func()
			private.NewOwner = func(ctx context.Context, in publicationOwnerInput) (publicationPrivateOwner, error) {
				owner, err := original(ctx, in)
				if err != nil {
					return nil, err
				}
				return &publicationPreparationFaultOwner{publicationPrivateOwner: owner, armed: func(dispatch contract.PublicationDispatch) {
					armed++
					selected, state := Open(ctx, f.admission, f.store)
					if selected == nil || state.Outcome != ObservedCurrent {
						t.Fatal("fault did not follow an authenticated reservation", state)
					}
					facts, err := selectedPublicationRelation(selected.selectedImage())
					marker, present := facts.markers[dispatch.AttemptID]
					if err != nil || !present || marker.State != contract.PublicationMayHaveEntered || marker.OperationID != dispatch.OperationID || marker.ProjectionCommitment != dispatch.ProjectionCommitment {
						t.Fatal("fault did not follow the exact selected marker", err)
					}
					switch condition {
					case "stage-before-launch":
						t.Setenv("TMPDIR", blockedTemporary)
					case "credential-input-before-launch":
						t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", strings.Repeat("x", 65536))
					case "pipe-before-launch":
						restoreDescriptors = publicationLimitForPipeRefusal(t)
					case "clean-pre-arm-refusal":
						t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "bad credential")
					case "wrong-refusal-correlation":
						t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "test-refuse-wrong-correlation")
					case "refusal-with-failed-wait":
						t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "test-refuse-exit66")
					case "pre-arm-refusal-cleanup-failure":
						t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "test-refuse-cleanup")
					}
				}, sent: func() {
					if restoreDescriptors != nil {
						restoreDescriptors()
					}
				}, retired: func(err error) {
					retired++
					retirementErr = err
					retirementFailed = retirementFailed || err != nil
					if condition == "pipe-before-launch" {
						var call *os.SyscallError
						pipeRefused = errors.As(err, &call) && (call.Syscall == "pipe" || call.Syscall == "pipe2") && errors.Is(err, unix.EMFILE)
					}
				}}, nil
			}
			request := fixtureID(env.Domain, "preparation evidence "+condition)
			got := installedPublicationEngine(t, f, private, capture).Publish(ctx, request, PublicationRequest{Names: input.names})
			t.Setenv("TMPDIR", staging)
			t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "private credential")
			if got.RequestID != request || got.Output == nil || len(got.Output.Entries) != 1 || len(got.Output.Entries[0].Actions) != 1 || armed != 1 || retired != 1 || !retirementFailed || got.Result != refused(CustodyUnavailable) {
				t.Fatalf("preparation lost its admitted result or local failure: %+v arm=%d retire=%d failure=%t", got, armed, retired, retirementFailed)
			}
			if condition == "pipe-before-launch" && !pipeRefused {
				t.Fatal("descriptor limit did not reach the actual pipe-acquisition boundary", retirementErr)
			}
			row := got.Output.Entries[0].Actions[0]
			selected := publicationEngineReopen(t, f)
			marker, present := selected.markers[row.AttemptID]
			coordinate := selected.coordinates[got.Output.Entries[0].CoordinateID]
			wantDisposition, wantState, wantClass, wantSummary := uint8(contract.PublicationOutcomeQualifiedNoEffect), uint8(contract.PublicationQualifiedNoEffectState), uint8(contract.PublicationQualifiedNoEffect), uint8(contract.PublicationSummaryFailed)
			wantEntry := uint8(contract.PublicationNotEntered)
			unknown := condition == "wrong-refusal-correlation" || condition == "refusal-with-failed-wait" || condition == "pre-arm-refusal-cleanup-failure"
			cleanup := condition == "sole-executable-removal-failure"
			cleanupFailure := cleanup || condition == "pre-arm-refusal-cleanup-failure"
			if unknown {
				wantDisposition, wantState, wantClass, wantSummary, wantEntry = contract.PublicationOutcomeUnknown, contract.PublicationUnknown, contract.PublicationUnproved, contract.PublicationSummaryUnknown, contract.PublicationMayHaveEnteredEntry
			} else if cleanup {
				wantDisposition, wantState, wantClass, wantSummary, wantEntry = contract.PublicationOutcomeAcknowledged, contract.PublicationAcknowledged, contract.PublicationRequestAcknowledged, contract.PublicationSummaryComplete, contract.PublicationMayHaveEnteredEntry
			}
			if row.Disposition != wantDisposition || got.Summary != wantSummary || !present || marker.State != wantState || marker.Evidence != row.Evidence || row.Evidence.Entry != wantEntry || row.Evidence.Class != wantClass || marker.OperationID != got.OperationID || marker.ProjectionCommitment != row.ProjectionCommitment || row.AttemptID.IsZero() {
				t.Errorf("checked preparation facts did not reach the exact selected result: disposition=%d summary=%d marker=%+v evidence=%+v", row.Disposition, got.Summary, marker, row.Evidence)
			}
			if !unknown && (row.LateWriteRisk != 0 || coordinate.LateEffectRisk != 0 || !coordinate.LatestUnresolvedAttemptID.IsZero()) {
				t.Error("proved result invented unresolved write risk", row, coordinate)
			}
			if cleanup && (coordinate.OwnerState != contract.PublicationOwnerQualified || coordinate.OwnedBirthAttemptID != row.AttemptID || marker.Evidence.NormalizedStatus != 201 || marker.Evidence.ConsumerLocator != slot) {
				t.Error("checked creation lost its birth or acceptance ceiling", coordinate)
			}
			records := drainNativePublicationDiagnostics(t, capture)
			handshakes, joins, resultReads := 0, 0, 0
			var dispatchCall uint64
			for _, record := range records {
				if record.Provider == telemetry.ProviderOutputHost && record.Operation == telemetry.OpOutputHostDispatch && record.Event == telemetry.DiagnosticStart {
					if dispatchCall != 0 {
						t.Fatal("one attempt dispatched more than once")
					}
					dispatchCall = record.Call
				}
			}
			if dispatchCall == 0 {
				t.Fatal("fault did not reach the actual reserved dispatcher")
			}
			for _, record := range records {
				if record.Provider != telemetry.ProviderOutputHost || record.Event != telemetry.DiagnosticStart || record.ParentCall != dispatchCall {
					continue
				}
				switch record.Operation {
				case telemetry.OpOutputHostHandshake:
					handshakes++
				case telemetry.OpOutputHostJoin:
					joins++
				case telemetry.OpOutputHostResultRead:
					resultReads++
				}
			}
			noChild := condition == "stage-before-launch" || condition == "credential-input-before-launch" || condition == "pipe-before-launch"
			if noChild && (handshakes != 0 || joins != 0 || resultReads != 0) || !noChild && (handshakes < 1 || joins < 1) || !cleanup && resultReads != 0 || cleanup && resultReads != 1 {
				t.Fatalf("fault crossed another child stage: handshake=%d join=%d result=%d", handshakes, joins, resultReads)
			}
			if cleanupFailure {
				files, err := os.ReadDir(staging)
				if err != nil || len(files) != 2 {
					t.Error("sole executable cleanup failure was not retained", err)
				}
				for _, file := range files {
					if file.IsDir() {
						if err := os.Chmod(filepath.Join(staging, file.Name()), 0700); err != nil {
							t.Fatal("restore joined executable root", err)
						}
					}
				}
			}
			if err := os.Remove(blockedTemporary); err != nil {
				t.Fatal(err)
			}
			if !cleanupFailure {
				files, err := os.ReadDir(staging)
				if err != nil || len(files) != 0 {
					t.Error("completed preparation retained resources", err)
				}
			}
			if unknown {
				return
			}
			private.NewOwner = original
			next := installedPublicationEngine(t, f, private, capture).Publish(ctx, fixtureID(env.Domain, "after preparation evidence "+condition), PublicationRequest{Names: input.names})
			if cleanup {
				assertInstalledPublicationVector(t, next, contract.PublicationSummaryNoChange, 1)
				if next.Output.Entries[0].Actions[0].Disposition != contract.PublicationNoOp {
					t.Error("selected acknowledgement lost later no-op")
				}
				assertNativePublicationNoPrivateWork(t, capture)
			} else {
				assertInstalledPublicationVector(t, next, contract.PublicationSummaryComplete, 1)
				if next.Output.Entries[0].Actions[0].Disposition != contract.PublicationOutcomeAcknowledged || next.Output.Entries[0].Actions[0].AttemptID == row.AttemptID {
					t.Error("proved no effect did not permit a fresh admitted attempt")
				}
				assertNativePublicationJoined(t, capture, staging, 1)
			}
		})
	}
}

// full_only: false
func TestInstalledPublicationPreparationRefusalPreservesPriorUncertainty(t *testing.T) {
	f, env, input, private, staging := nativePublicationFixture(t, false, "plain-target-unknown-first")
	capture := newPublicationDiagnosticCapture()
	ctx, cancel := context.WithTimeout(telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, capture.recorder)), time.Minute)
	defer cancel()
	first := installedPublicationEngine(t, f, private, capture).Publish(ctx, fixtureID(env.Domain, "preparation prior unknown"), PublicationRequest{Names: input.names})
	assertInstalledPublicationVector(t, first, contract.PublicationSummaryUnknown, 1)
	oldID := first.Output.Entries[0].Actions[0].AttemptID
	coordinate := first.Output.Entries[0].CoordinateID
	before := publicationEngineReopen(t, f).markers[oldID]
	if before.State != contract.PublicationUnknown {
		t.Fatal("prior attempt did not establish uncertainty")
	}
	assertNativePublicationJoined(t, capture, staging, 1)
	t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "bad credential")
	second := installedPublicationEngine(t, f, private, capture).Publish(ctx, fixtureID(env.Domain, "preparation new refused attempt"), PublicationRequest{Names: input.names, RepublishAfterUnknown: []contract.ID{oldID}})
	if second.RequestID.IsZero() || second.DomainID != env.Domain || second.OperationID.IsZero() || second.RequestIdentity.IsZero() || second.Output == nil || len(second.Output.Entries) != 1 || len(second.Output.Entries[0].Actions) != 1 {
		t.Fatal("new refusal did not reach its admitted result boundary", second.Result)
	}
	if second.Summary != contract.PublicationSummaryFailed || second.Result != refused(CustodyUnavailable) {
		t.Error("new refusal lost its result summary or local cause", second.Summary, second.Result)
	}
	row := second.Output.Entries[0].Actions[0]
	after := publicationEngineReopen(t, f)
	if row.Disposition != contract.PublicationOutcomeQualifiedNoEffect || row.AttemptID == oldID || row.AttemptID.IsZero() || row.LateWriteRisk != 1 || row.RemoteValueMayRemain != 1 || len(row.BlockerIDs) != 1 || row.BlockerIDs[0] != oldID || after.markers[oldID] != before || after.markers[row.AttemptID].State != contract.PublicationQualifiedNoEffectState {
		t.Error("new preparation refusal erased or reused prior uncertainty", row)
	}
	blockers := publicationBlockers(after, coordinate)
	if len(blockers) != 1 || blockers[0] != oldID || after.coordinates[coordinate].LatestUnresolvedAttemptID != oldID || after.coordinates[coordinate].LateEffectRisk != 1 {
		t.Error("preparation refusal changed old blockers or late-write risk", blockers)
	}
	assertNativePublicationJoined(t, capture, staging, 1)
	t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "private credential")
	blocked := installedPublicationEngine(t, f, private, capture).Publish(ctx, fixtureID(env.Domain, "preparation old unknown still blocks"), PublicationRequest{Names: input.names})
	assertInstalledPublicationVector(t, blocked, contract.PublicationSummaryUnknown, 1)
	if got := blocked.Output.Entries[0].Actions[0].BlockerIDs; len(got) != 1 || got[0] != oldID {
		t.Error("later default publication lost the exact original blocker", got)
	}
	assertNativePublicationNoPrivateWork(t, capture)
}

// full_only: false
func TestInstalledPublicationExecutableCleanupFailureIsReported(t *testing.T) {
	for _, condition := range []string{"acknowledged", "unknown", "preparation-refusal", "clean"} {
		t.Run(condition, func(t *testing.T) {
			slot := "plain-target-cleanup-failure-0"
			switch condition {
			case "unknown":
				slot = "plain-target-unknown-cleanup-failure-0"
			case "preparation-refusal", "clean":
				slot = "plain-target"
			}
			f, env, input, private, staging := nativePublicationFixture(t, false, slot)
			if condition == "preparation-refusal" {
				t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "test-refuse-cleanup")
			}
			capture := newPublicationDiagnosticCapture()
			ctx, cancel := context.WithTimeout(telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, capture.recorder)), time.Minute)
			defer cancel()
			got := installedPublicationEngine(t, f, private, capture).Publish(ctx, fixtureID(env.Domain, "named executable cleanup failure "+condition), PublicationRequest{Names: input.names})
			wantSummary := uint8(contract.PublicationSummaryComplete)
			if condition == "unknown" || condition == "preparation-refusal" {
				wantSummary = contract.PublicationSummaryUnknown
			}
			assertInstalledPublicationVector(t, got, wantSummary, 1)
			row := got.Output.Entries[0].Actions[0]
			wantClass, wantDisposition, wantState := uint8(contract.PublicationRequestAcknowledged), uint8(contract.PublicationOutcomeAcknowledged), uint8(contract.PublicationAcknowledged)
			if condition == "unknown" || condition == "preparation-refusal" {
				wantClass, wantDisposition, wantState = contract.PublicationUnproved, contract.PublicationOutcomeUnknown, contract.PublicationUnknown
			}
			selected := publicationEngineReopen(t, f)
			if row.Evidence.Class != wantClass || row.Disposition != wantDisposition || selected.markers[row.AttemptID].State != wantState || selected.markers[row.AttemptID].Evidence != row.Evidence {
				t.Fatal("local cleanup fact changed its independently checked provider result")
			}
			wantFailure := condition != "clean"
			if wantFailure && got.Result != refused(CustodyUnavailable) || !wantFailure && got.Result.Outcome != ObservedCurrent {
				t.Error("local failure changed its operation-level disposition", got.Result)
			}
			fact := reflect.ValueOf(got).FieldByName("ExecutableCleanupFailed")
			if fact.IsValid() && fact.Kind() != reflect.Bool {
				t.Fatal("executable cleanup failure is not a bounded boolean")
			}
			if reported := fact.IsValid() && fact.Bool(); reported != wantFailure {
				t.Error("actual executable removal failure did not reach the public typed result", reported, wantFailure)
			}
			records := drainNativePublicationDiagnostics(t, capture)
			starts, joins := 0, 0
			for _, record := range records {
				if record.Operation != telemetry.OpOutputHostJoin {
					continue
				}
				if record.Event == telemetry.DiagnosticStart {
					starts++
				} else if record.Event == telemetry.DiagnosticReturn && record.Result == telemetry.ResultSuccess {
					joins++
				}
			}
			if starts == 0 || starts != joins {
				t.Error("named cleanup fact lacked complete positive process joins")
			}
			files, err := os.ReadDir(staging)
			if err != nil || wantFailure && len(files) != 1 || !wantFailure && len(files) != 0 {
				t.Error("local removal observation differs from the reported failure", err)
			}
			for _, file := range files {
				if file.IsDir() {
					if err := os.Chmod(filepath.Join(staging, file.Name()), 0700); err != nil {
						t.Error("restore joined executable root", err)
					}
				}
			}
		})
	}
}

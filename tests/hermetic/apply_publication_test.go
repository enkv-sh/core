package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

func applyPublicationNativeDeadline(t testing.TB, ctx context.Context, private publicationPrivate) publicationPrivate {
	t.Helper()
	want, finite := ctx.Deadline()
	if !finite {
		t.Fatal("combined fixture requires its original deadline")
	}
	check, owner := private.Check, private.NewOwner
	private.Check = func(callctx context.Context, input publicationActionCheckInput) (publicationActionCheckFacts, error) {
		got, finite := callctx.Deadline()
		if !finite || got != want || input.Deadline != want {
			t.Fatal("publication Check received a different deadline")
		}
		return check(callctx, input)
	}
	private.NewOwner = func(callctx context.Context, input publicationOwnerInput) (publicationPrivateOwner, error) {
		got, finite := callctx.Deadline()
		if !finite || got != want || input.Deadline != want {
			t.Fatal("publication preparation received a new time budget")
		}
		return owner(callctx, input)
	}
	return private
}

func applyPublicationAssertStage(t testing.TB, joined PublicApplyPublicationResult, summary uint8, coordinates int) PublicPublicationResult {
	t.Helper()
	if !applyPublicationComplete(joined.Apply) || joined.Publication.Stage != "evaluated" || joined.Publication.Reason != "" || joined.Publication.Result == nil {
		t.Fatal("completed apply did not retain its separate evaluated publication", joined.Apply.Result, joined.Publication)
	}
	result := *joined.Publication.Result
	assertInstalledPublicationVector(t, result, summary, coordinates)
	return result
}

// full_only: false
func TestApplyPublicationNativeChangedAndUnchangedConfirmedSelection(t *testing.T) {
	t.Run("unchanged-secret-with-acknowledged-target", func(t *testing.T) {
		f, env, selection, private, staging := nativePublicationFixture(t, true)
		recorder := newPublicationDiagnosticCapture()
		ctx, cancel := context.WithTimeout(telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder.recorder)), time.Minute)
		defer cancel()
		private = applyPublicationNativeDeadline(t, ctx, private)
		seed := installedPublicationEngine(t, f, private, recorder).Publish(ctx, fixtureID(env.Domain, "combined secret initial create"), PublicationRequest{Names: selection.names})
		assertInstalledPublicationVector(t, seed, contract.PublicationSummaryComplete, 2)
		assertNativePublicationJoined(t, recorder, staging, 2)
		publicationEngineReopen(t, f)
		input := installedApplyCurrentInput(f.session)
		a := publicPublicationApplyFixture(env, f)
		apply := a.engineWithValidator(t, f.session, input, currentApplyRecipients(f.session.registry()), installedOutputValidator(t, f.session), nil)
		_, beforePrivate := env.Custody.Calls()
		joined := apply.ApplyAndPublish(ctx, fixtureID(env.Domain, "combined secret unchanged apply"), fixtureID(env.Domain, "combined secret unchanged publication"), input, installedPublicationEngine(t, f, private, recorder), nil)
		result := applyPublicationAssertStage(t, joined, contract.PublicationSummaryNoChange, 2)
		labels := make(map[string]string)
		for _, description := range result.Descriptions {
			if description.Origin != PublicationTargetCurrent || description.EntryName == nil || description.DestinationID == nil || *description.DestinationID != "native" || description.ServiceContractID != "test-output/service/v1" {
				t.Fatal("combined result lost its captured current labels", description)
			}
			labels[*description.EntryName] = description.CanonicalTarget
		}
		if !reflect.DeepEqual(labels, map[string]string{"plain": "plain-target", "secret": "secret-target"}) {
			t.Fatal("combined result relabelled its selected entry set", labels)
		}
		_, afterPrivate := env.Custody.Calls()
		if joined.Apply.Result.Outcome != Unchanged || len(joined.Apply.Receipt) != 0 || afterPrivate <= beforePrivate {
			t.Fatal("unchanged combined apply did not retain its secret comparison")
		}
		for _, entry := range result.Output.Entries {
			if len(entry.Actions) != 1 || entry.Actions[0].Disposition != contract.PublicationNoOp || !entry.Actions[0].AttemptID.IsZero() {
				t.Fatal("combined secret publication did not preserve no-op")
			}
		}
		assertNativePublicationNoPrivateWork(t, recorder)
	})
	for _, changed := range []bool{false, true} {
		name := "unchanged-with-unpublished-target"
		if changed {
			name = "changed-with-selected-write"
		}
		t.Run(name, func(t *testing.T) {
			f, env, selection, private, staging := nativePublicationFixture(t, false)
			recorder := newPublicationDiagnosticCapture()
			ctx, cancel := context.WithTimeout(telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder.recorder)), time.Minute)
			defer cancel()
			private = applyPublicationNativeDeadline(t, ctx, private)
			if changed {
				seed := installedPublicationEngine(t, f, private, recorder).Publish(ctx, fixtureID(env.Domain, "combined native initial create"), PublicationRequest{Names: selection.names})
				assertInstalledPublicationVector(t, seed, contract.PublicationSummaryComplete, 1)
				assertNativePublicationJoined(t, recorder, staging, 1)
				publicationEngineReopen(t, f)
			}
			input := installedApplyCurrentInput(f.session)
			if changed {
				input[0].InputBytes = []byte("updated plain data")
			}
			inputBefore := bytes.Clone(input[0].InputBytes)
			a := publicPublicationApplyFixture(env, f)
			apply := a.engineWithValidator(t, f.session, input, currentApplyRecipients(f.session.registry()), installedOutputValidator(t, f.session), nil)
			joined := apply.ApplyAndPublish(ctx, fixtureID(env.Domain, "combined native apply"), fixtureID(env.Domain, "combined native publication"), input, installedPublicationEngine(t, f, private, recorder), nil)
			result := applyPublicationAssertStage(t, joined, contract.PublicationSummaryComplete, 1)
			wantAction, wantApply := uint8(contract.PublicationCreateWithValue), Unchanged
			if changed {
				wantAction, wantApply = contract.PublicationWriteValue, ObservedCurrent
				row, err := contract.InspectCompactMutationReceipt(joined.Apply.Receipt)
				if err != nil || row.OperationID != joined.Apply.OperationID || row.RequestIdentityDigest != joined.Apply.RequestIdentity || row.OutputSummary != contract.ReceiptOutputNotApplicable || row.RequestedRevisionID != row.ObservedRevisionID {
					t.Fatal("publication changed the apply receipt correlation", err)
				}
			} else if len(joined.Apply.Receipt) != 0 {
				t.Fatal("unchanged apply acquired a mutation receipt")
			}
			if joined.Apply.Result.Outcome != wantApply || len(result.Output.Entries[0].Actions) != 1 || result.Output.Entries[0].Actions[0].Action != wantAction || result.Output.Entries[0].Actions[0].Disposition != contract.PublicationOutcomeAcknowledged {
				t.Fatal("publication did not send the confirmed apply selection", joined.Apply.Result)
			}
			assertNativePublicationJoined(t, recorder, staging, 1)
			publicationEngineReopen(t, f)
			if !bytes.Equal(input[0].InputBytes, inputBefore) || !bytes.Equal(f.session.valueEntry(entrySlot(t, f.session, "plain")).ValueBytes, inputBefore) {
				t.Fatal("combined execution changed the borrowed proposal or selected another value")
			}
			beforeReceipt := bytes.Clone(joined.Apply.Receipt)
			a = publicPublicationApplyFixture(env, f)
			repeatInput := installedApplyCurrentInput(f.session)
			repeat := a.engineWithValidator(t, f.session, repeatInput, currentApplyRecipients(f.session.registry()), installedOutputValidator(t, f.session), nil)
			noOp := repeat.ApplyAndPublish(ctx, fixtureID(env.Domain, "combined native repeat apply"), fixtureID(env.Domain, "combined native repeat publication"), repeatInput, installedPublicationEngine(t, f, private, recorder), nil)
			applyPublicationAssertStage(t, noOp, contract.PublicationSummaryNoChange, 1)
			if noOp.Apply.Result.Outcome != Unchanged || noOp.Publication.Result.Output.Entries[0].Actions[0].Disposition != contract.PublicationNoOp || !bytes.Equal(joined.Apply.Receipt, beforeReceipt) {
				t.Fatal("unchanged repeat lost no-op or changed the previous apply receipt")
			}
			assertNativePublicationNoPrivateWork(t, recorder)
		})
	}
}

func applyPublicationGeneratedFixture(t *testing.T, ctx context.Context) (installedApplyTestFixture, *fixture, []ApplyEntryInput, *outputApplyInput, *GeneratedApplyInstallation, publicationPrivate, func() (int32, int32), string) {
	t.Helper()
	process, effects := configurationRecoveryLocalGeneratedProcess(t)
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	f.env.GeneratedProcess = process
	g := process.Implementation
	input := []ApplyEntryInput{
		{Name: "generated", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{f.selected.admission.recipient}, Generated: &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, Epoch: 0, RetirementMode: contract.GeneratedRetirementManual, CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent), ConfigContractID: g.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(), LifecycleMode: contract.GeneratorLifecycleManaged}},
		{Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{f.selected.admission.recipient}, InputBytes: []byte("private data")},
	}
	output := nativePublicationOutput(input, []uint64{1, 9})
	for i := range output.bindings[0].targets {
		if output.bindings[0].targets[i].entryName == "generated" {
			hermeticRetargetOutput(&output.bindings[0].targets[i].target, "generated-encoding-target", "generated-encoding-target")
			output.bindings[0].targets[i].target.PayloadEncoding = contract.OutputEncodingBase64
		}
	}
	output.groups = [][]string{{"generated", "plain"}}
	installOutputFixtureSource(t, f.selected, output)
	f.admitted = OpenContext{admission: &f.selected.admission}
	config := installedPublicationTestConfig(t)
	if err := f.keys.InstallPublication(t.Context(), config, "native", publicationTestConfigContract); err != nil {
		t.Fatal("install generated publication custody", err)
	}
	public := &fixture{store: requireAdmittedMemoryStore(t, f.env.Store), trust: f.env.Trust.(*fixtureTrust), admission: f.admitted, session: f.selected}
	callbacks := installedGeneratedTestCallbacks(t, f, process)
	final := callbacks.AdmitFinal
	want, _ := ctx.Deadline()
	callbacks.AdmitFinal = func(callctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedFinalInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
		got, finite := callctx.Deadline()
		if !finite || got != want || deadline != want {
			t.Fatal("generated Final received a different deadline")
		}
		return final(callctx, q, control, input, deadline)
	}
	return f, public, input, output, callbacks, applyPublicationNativeDeadline(t, ctx, publicationCustodyPrivate(f.keys)), effects, os.TempDir()
}

// full_only: false
func TestApplyPublicationGeneratedCompletionAndIncompleteOriginal(t *testing.T) {
	for _, name := range []string{"completed-original", "failed-original-final", "completed-original-with-publication-unknown"} {
		t.Run(name, func(t *testing.T) {
			failFinal := name == "failed-original-final"
			unknownOutput := name == "completed-original-with-publication-unknown"
			recorder := newPublicationDiagnosticCapture()
			ctx, cancel := context.WithTimeout(telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder.recorder)), 2*time.Minute)
			defer cancel()
			f, public, input, output, callbacks, private, effects, staging := applyPublicationGeneratedFixture(t, ctx)
			if unknownOutput {
				for i := range output.bindings[0].targets {
					if output.bindings[0].targets[i].entryName == "plain" {
						hermeticRetargetOutput(&output.bindings[0].targets[i].target, "plain-target-unknown-combined", "plain-target-unknown-combined")
					}
				}
				installOutputFixtureSource(t, f.selected, output)
			}
			if failFinal {
				callbacks.AdmitFinal = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedFinalInput, time.Time) (*InstalledGeneratedCustody, error) {
					return nil, contract.ErrRecord
				}
			}
			owners := 0
			original := private.NewOwner
			private.NewOwner = func(ctx context.Context, input publicationOwnerInput) (publicationPrivateOwner, error) {
				owners++
				return original(ctx, input)
			}
			engine := publicGeneratedOutputEngine(t, ctx, f, input, output, callbacks)
			engine.installation.Store = &installedPublicationCaptureStore{memoryStore: public.store, capture: recorder}
			engine, proposal := publicOutputApplyReinstall(t, engine)
			proposalBefore := ownPublicConfiguration(proposal)
			joined := engine.ApplyAndPublish(ctx, fixtureID(f.env.Domain, "generated combined apply"), fixtureID(f.env.Domain, "generated combined publication"), input, installedPublicationEngine(t, public, private, recorder), nil)
			creates, deletes := effects()
			if creates != 1 || deletes != 0 || !reflect.DeepEqual(proposal, proposalBefore) || !bytes.Equal(input[0].Generated.Intent, f.env.GeneratedProcess.Intent) || !bytes.Equal(input[1].InputBytes, []byte("private data")) {
				t.Fatal("combined generated input, effect count or source proposal changed", creates, deletes)
			}
			selected := f.open(t, ctx)
			if failFinal {
				if joined.Publication.Stage != "unstarted" || joined.Publication.Reason != "apply-incomplete" || joined.Publication.Result != nil || owners != 0 || selected.root.Generated.ActiveOwner != joined.Apply.OperationID || selected.root.ValueEntryCount != 0 || len(installedOutputConfiguration(t, ctx, selected).Bindings) != 0 {
					t.Fatal("incomplete original generated work reached publication or selected its proposal", joined.Apply.Result, joined.Publication)
				}
				publicOutputApplyAssertNoPublication(t, selected)
				assertNativePublicationNoPrivateWork(t, recorder)
				return
			}
			wantSummary := uint8(contract.PublicationSummaryComplete)
			if unknownOutput {
				wantSummary = contract.PublicationSummaryUnknown
			}
			result := applyPublicationAssertStage(t, joined, wantSummary, 2)
			if owners != 2 || selected.root.ValueEntryCount != 2 || selected.root.Generated.GeneratedCurrent != 1 || !selected.root.Generated.ActiveOwner.IsZero() || joined.Apply.Generated == nil || joined.Apply.Generated.ReceiptObservation || len(joined.Apply.Receipt) == 0 {
				t.Fatal("generated completion did not join its actual selected values to publication", joined.Apply.Result)
			}
			acknowledged, unknown := 0, 0
			for _, target := range result.Output.Entries {
				if len(target.Actions) != 1 || target.Actions[0].Action != contract.PublicationCreateWithValue {
					t.Fatal("generated combined result lost an exact action row", target)
				}
				switch target.Actions[0].Disposition {
				case contract.PublicationOutcomeAcknowledged:
					acknowledged++
				case contract.PublicationOutcomeUnknown:
					unknown++
				default:
					t.Fatal("generated combined target has an unexpected terminal fact", target)
				}
			}
			wantACK, wantUnknown := 2, 0
			if unknownOutput {
				wantACK, wantUnknown = 1, 1
			}
			if acknowledged != wantACK || unknown != wantUnknown {
				t.Fatal("publication uncertainty erased an independent target or changed the completed apply", acknowledged, unknown)
			}
			assertNativePublicationJoined(t, recorder, staging, 2)
		})
	}
}

// full_only: false
func TestApplyPublicationCompletedReceiptRequiresItsActualCurrentRevision(t *testing.T) {
	recorder := newPublicationDiagnosticCapture()
	ctx, cancel := context.WithTimeout(telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder.recorder)), 2*time.Minute)
	defer cancel()
	f, public, input, output, callbacks, private, effects, staging := applyPublicationGeneratedFixture(t, ctx)
	engine := publicGeneratedOutputEngine(t, ctx, f, input, output, callbacks)
	engine.installation.Store = &installedPublicationCaptureStore{memoryStore: public.store, capture: recorder}
	engine, _ = publicOutputApplyReinstall(t, engine)
	installation := engine.installation
	completed := engine.Apply(ctx, fixtureID(f.env.Domain, "receipt apply without publication"), input)
	engine.Close()
	if !applyPublicationComplete(completed) || len(completed.Receipt) == 0 {
		t.Fatal("receipt setup did not complete original work", completed.Result)
	}
	f.selected = f.open(t, ctx)
	public.session, public.admission = f.selected, OpenContext{admission: &f.selected.admission}
	if f.selected.head.Core.Revision != completed.Result.ObservedRevision {
		t.Fatal("receipt setup is not the exact completed selection")
	}
	installation.PublicConfiguration = contract.PublicConfiguration{}
	continuation, err := NewInstalledApply(installation)
	if err != nil {
		t.Fatal("receipt-only apply construction", err)
	}
	t.Cleanup(continuation.Close)
	current := continuation.ContinueAndPublish(ctx, fixtureID(f.env.Domain, "current receipt continuation"), completed.OperationID, fixtureID(f.env.Domain, "current receipt publication"), installedPublicationEngine(t, public, private, recorder), nil)
	applyPublicationAssertStage(t, current, contract.PublicationSummaryComplete, 2)
	if !bytes.Equal(current.Apply.Receipt, completed.Receipt) || current.Apply.Generated == nil || !current.Apply.Generated.ReceiptObservation {
		t.Fatal("current receipt publication changed the original compact result")
	}
	assertNativePublicationJoined(t, recorder, staging, 2)
	publicationEngineReopen(t, public)
	if public.session.head.Core.Revision == completed.Result.ObservedRevision {
		t.Fatal("publication did not advance the selected revision")
	}
	observer, err := NewInstalledApply(installation)
	if err != nil {
		t.Fatal("later receipt-only apply construction", err)
	}
	t.Cleanup(observer.Close)
	later := observer.ContinueAndPublish(ctx, fixtureID(f.env.Domain, "historical receipt continuation"), completed.OperationID, fixtureID(f.env.Domain, "historical receipt publication"), installedPublicationEngine(t, public, private, recorder), nil)
	if later.Publication.Stage != "unstarted" || later.Publication.Reason != "selection-unavailable" || later.Publication.Result != nil || !bytes.Equal(later.Apply.Receipt, completed.Receipt) || later.Apply.Generated == nil || !later.Apply.Generated.ReceiptObservation {
		t.Fatal("historical receipt acquired latest selected content", later.Apply.Result, later.Publication)
	}
	creates, deletes := effects()
	if creates != 1 || deletes != 0 {
		t.Fatal("receipt observation repeated original generated effects", creates, deletes)
	}
	assertNativePublicationNoPrivateWork(t, recorder)
}

// full_only: false
func TestApplyPublicationCanonicalSelectionWithOriginalRetirementPendingStartsNothing(t *testing.T) {
	recorder := newPublicationDiagnosticCapture()
	ctx, cancel := context.WithTimeout(telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder.recorder)), 2*time.Minute)
	defer cancel()
	f, public, input, output, _, private, effects, _ := applyPublicationGeneratedFixture(t, ctx)
	callbacks := installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess)
	initial := installedGeneratedTestEngine(t, ctx, f, f.selected, input, currentApplyRecipients(f.selected.registry()), callbacks)
	initial.installation.Store = &installedPublicationCaptureStore{memoryStore: public.store, capture: recorder}
	first := initial.Apply(ctx, fixtureID(f.env.Domain, "canonical pending initial generation"), input)
	initial.Close()
	if !applyPublicationComplete(first) {
		t.Fatal("initial generation did not complete", first.Result)
	}
	f.selected = f.open(t, ctx)
	before := ownScenarioValueEntry(*f.selected.valueEntry(entrySlot(t, f.selected, "generated")))
	input[0].Generated.Epoch, input[0].Generated.RetirementMode = 1, contract.GeneratedRetirementAuto
	public.session, public.admission = f.selected, OpenContext{admission: &f.selected.admission}
	rotationCallbacks := installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess)
	rotation := publicGeneratedOutputEngine(t, ctx, f, input, output, rotationCallbacks)
	rotation.installation.Store = &installedPublicationCaptureStore{memoryStore: public.store, capture: recorder}
	rotation, _ = publicOutputApplyReinstall(t, rotation)
	owners := 0
	original := private.NewOwner
	private.NewOwner = func(ctx context.Context, input publicationOwnerInput) (publicationPrivateOwner, error) {
		owners++
		return original(ctx, input)
	}
	joined := rotation.ApplyAndPublish(ctx, fixtureID(f.env.Domain, "canonical pending apply"), fixtureID(f.env.Domain, "canonical pending publication"), input, installedPublicationEngine(t, public, private, recorder), nil)
	if g := joined.Apply.Generated; g != nil {
		t.Logf("canonical pending facts: state=%q canonical=%d effect_summary=%d proof=%t receipt_observation=%t receipt_bytes=%d effects=%d duties=%d hazards=%d unknown=%d diagnostics=%d publication_owners=%d", g.StateResult, g.CanonicalOutcome, g.EffectSummary, g.HasObservedCanonicalSelection(joined.Apply.DomainID, joined.Apply.OperationID, joined.Apply.RequestIdentity), g.ReceiptObservation, len(joined.Apply.Receipt), len(g.Effects), len(g.Duties), len(g.Hazards), g.UnknownCount, len(joined.Apply.Diagnostics), owners)
	} else {
		t.Logf("canonical pending facts: generated_absent=true receipt_bytes=%d diagnostics=%d publication_owners=%d", len(joined.Apply.Receipt), len(joined.Apply.Diagnostics), owners)
	}
	for _, diagnostic := range joined.Apply.Diagnostics {
		t.Logf("canonical pending diagnostic: subject=%q outcome=%q reason=%q", diagnostic.Subject.Kind, diagnostic.Outcome, diagnostic.Reason)
	}
	recorder.collect()
	selected := f.open(t, ctx)
	recorder.collect()
	work, workErr := selected.selectedGeneratedWork(ctx)
	createsAtStop, deletesAtStop := effects()
	t.Logf("canonical pending selected: active_owner=%t generated=%d retiring=%d duties=%d hazards=%d work_valid=%t creates=%d deletes=%d", !selected.root.Generated.ActiveOwner.IsZero(), selected.root.Generated.GeneratedCurrent, selected.root.Generated.Retiring, selected.root.Generated.Duties, selected.root.Generated.Hazards, workErr == nil, createsAtStop, deletesAtStop)
	if workErr == nil && work.phase != nil {
		t.Logf("canonical pending phase: schema=%d phase=%d stage=%d lineage=%d selection_phase=%t attempts=%d declared_attempts=%d", work.phase.Schema, work.phase.Phase, work.phase.Stage, work.phase.LineageIndex, !work.phase.SelectionPhaseID.IsZero(), len(work.attempts), work.phase.Attempts.Count)
	}
	recorder.collect()
	if joined.Apply.Result.Outcome != ObservedCurrent || joined.Apply.Generated == nil || joined.Apply.Generated.StateResult != "retirement-pending" || !joined.Apply.Generated.HasObservedCanonicalSelection(joined.Apply.DomainID, joined.Apply.OperationID, joined.Apply.RequestIdentity) || joined.Publication.Stage != "unstarted" || joined.Publication.Reason != "apply-incomplete" || joined.Publication.Result != nil || owners != 0 {
		t.Fatal("canonical selection hid unfinished original work or admitted publication", joined.Apply.Result, joined.Publication)
	}
	after := selected.valueEntry(entrySlot(t, selected, "generated"))
	creates, deletes := effects()
	if creates != 2 || deletes != 1 || after.Generated.GenerationID == before.Generated.GenerationID || after.Generated.RetiringDutyPresent != 1 || len(installedOutputConfiguration(t, ctx, selected).Bindings) != 1 {
		t.Fatal("incomplete original test did not select its whole successor before retirement ambiguity", creates, deletes)
	}
	publicOutputApplyAssertNoPublication(t, selected)
	assertNativePublicationNoPrivateWork(t, recorder)
}

// full_only: false
func TestApplyPublicationFirstAutomaticSelectionRequiresCompleteOutputChangedSubjects(t *testing.T) {
	for _, condition := range []string{"healthy", "omitted-output", "tampered-output"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			f, public, input, output, _, private, effects, _ := applyPublicationGeneratedFixture(t, ctx)
			callbacks := installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess)
			initial := installedGeneratedTestEngine(t, ctx, f, f.selected, input, currentApplyRecipients(f.selected.registry()), callbacks)
			first := initial.Apply(ctx, fixtureID(f.env.Domain, "complete subjects initial "+condition), input)
			initial.Close()
			if !applyPublicationComplete(first) {
				t.Fatal("initial generation did not complete", first.Result)
			}
			f.selected = f.open(t, ctx)
			before := ownScenarioValueEntry(*f.selected.valueEntry(entrySlot(t, f.selected, "generated")))
			plainBefore := ownScenarioValueEntry(*f.selected.valueEntry(entrySlot(t, f.selected, "plain")))
			input[0].Generated.Epoch, input[0].Generated.RetirementMode = 1, contract.GeneratedRetirementAuto
			public.session, public.admission = f.selected, OpenContext{admission: &f.selected.admission}
			store := requireAdmittedMemoryStore(t, f.env.Store)
			trust, ok := underlyingAdmittedFixtureTrust(f.env.Trust)
			if !ok {
				t.Fatal("fixture signing counters unavailable")
			}
			binds, owners := 0, 0
			var code contract.CryptoResultCode
			var selectedRevision contract.ID
			var createsAtBind, casAtBind, signsAtBind int
			var providerCreatesAtBind, deletesAtBind int32
			callbacks = installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess)
			admitFinal := callbacks.AdmitFinal
			callbacks.AdmitFinal = func(callctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedFinalInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
				owner, err := admitFinal(callctx, q, control, in, deadline)
				if err != nil || owner == nil {
					return owner, err
				}
				bind := owner.BindCandidate
				owner.BindCandidate = func(bindctx context.Context, candidate contract.GeneratedCandidateInput) contract.CryptoResultCode {
					if candidate.Subject.Purpose != contract.GeneratorAuthorityFinal {
						return bind(bindctx, candidate)
					}
					binds++
					if binds != 1 || candidate.ActiveOwner != q.Parent.OperationID {
						t.Fatal("fixture did not reach the first selecting automatic Final")
					}
					selected := f.open(t, bindctx)
					selectedRevision = selected.head.Core.Revision
					createsAtBind, casAtBind, signsAtBind = store.creates, store.cas, trust.signs
					providerCreatesAtBind, deletesAtBind = effects()
					var successor contract.ValueEntry
					for _, row := range candidate.Entries {
						switch row.Entry.Name {
						case "generated":
							successor = row.Entry
						case "plain":
							if !reflect.DeepEqual(row.Entry, plainBefore) {
								t.Fatal("fixture changed its independent plain sibling")
							}
						}
					}
					if successor.Incarnation != before.Incarnation || successor.Generated.GenerationID.IsZero() || successor.Generated.GenerationID == before.Generated.GenerationID || !slices.Equal(successor.Recipients, before.Recipients) {
						t.Fatal("fixture changed its expected rotation or membership")
					}
					var rows []contract.ChangedSubjectIdentity
					add := func(kind, change uint8, primary contract.ID) {
						material := append([]byte("ENKV/CRYPTO/v2/changed-subject-identity-v1\x00"), f.env.Domain[:]...)
						material = append(material, kind)
						material = append(material, primary[:]...)
						material = append(material, make([]byte, 32)...)
						rows = append(rows, contract.ChangedSubjectIdentity{Kind: kind, Change: change, Identity: contract.ID(sha256.Sum256(material))})
					}
					add(contract.ChangedSubjectValueEntry, contract.ChangedSubjectUpdated, before.Incarnation)
					add(contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectRemoved, before.Generated.GenerationID)
					add(contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectAdded, successor.Generated.GenerationID)
					omitted, err := contract.ChangedSubjectDescriptor(rows)
					if err != nil {
						t.Fatal(err)
					}
					add(contract.ChangedSubjectOutputBinding, contract.ChangedSubjectAdded, publicOutputApplyExpectedBinding(f.env.Domain, q.Parent.OperationID, output.bindings[0].destinationID))
					complete, err := contract.ChangedSubjectDescriptor(rows)
					if err != nil || complete == omitted {
						t.Fatal("independent output change commitment missing", err)
					}
					candidate.SupportRecords = slices.Clone(candidate.SupportRecords)
					found := false
					for i, row := range candidate.SupportRecords {
						if row.Kind != contract.GeneratedPhaseSupportKind || row.RecordID != candidate.ActiveOwner {
							continue
						}
						phase, err := contract.InspectGeneratedPhaseRecord(row.Body)
						if err != nil || phase.SelectionPhaseID.IsZero() || phase.ChangedSubjects != complete {
							t.Fatal("healthy first Final omitted independently expected output changes", err)
						}
						switch condition {
						case "omitted-output":
							phase.ChangedSubjects = omitted
						case "tampered-output":
							rows[len(rows)-1].Identity[0] ^= 1
							phase.ChangedSubjects, err = contract.ChangedSubjectDescriptor(rows)
						}
						if err != nil {
							t.Fatal(err)
						}
						candidate.SupportRecords[i].Body, err = contract.EncodeGeneratedPhaseRecord(phase)
						if err != nil {
							t.Fatal("changed commitment is not structurally valid", err)
						}
						found = true
					}
					if !found {
						t.Fatal("first automatic Final has no selected Phase")
					}
					candidate.PublicState.RequiredSupport, err = contract.RequiredSupportDescriptor(candidate.PublicState.Domain, candidate.SupportRecords)
					if err != nil {
						t.Fatal("changed commitment support projection", err)
					}
					code = bind(bindctx, candidate)
					return code
				}
				return owner, nil
			}
			original := private.NewOwner
			private.NewOwner = func(ctx context.Context, input publicationOwnerInput) (publicationPrivateOwner, error) {
				owners++
				return original(ctx, input)
			}
			rotation := publicGeneratedOutputEngine(t, ctx, f, input, output, callbacks)
			rotation, _ = publicOutputApplyReinstall(t, rotation)
			joined := rotation.ApplyAndPublish(ctx, fixtureID(f.env.Domain, "complete subjects apply "+condition), fixtureID(f.env.Domain, "complete subjects publication "+condition), input, installedPublicationEngine(t, public, private, newPublicationDiagnosticCapture()), nil)
			creates, deletes := effects()
			if binds != 1 || selectedRevision.IsZero() || owners != 0 || joined.Publication.Stage != "unstarted" || joined.Publication.Reason != "apply-incomplete" {
				t.Fatal("fixture did not retain the first automatic selection boundary", binds, code, owners, joined.Publication)
			}
			cold := f.open(t, ctx)
			if condition == "healthy" {
				if code != contract.CryptoSuccess || joined.Apply.Generated == nil || joined.Apply.Generated.StateResult != "retirement-pending" || !joined.Apply.Generated.HasObservedCanonicalSelection(joined.Apply.DomainID, joined.Apply.OperationID, joined.Apply.RequestIdentity) || creates != 2 || deletes != 1 {
					t.Fatal("complete first Final did not select and retain original retirement", code, joined.Apply.Result, creates, deletes)
				}
				return
			}
			if code != contract.CryptoInvalidAdmission || store.creates != createsAtBind || store.cas != casAtBind || trust.signs != signsAtBind || creates != providerCreatesAtBind || deletes != deletesAtBind || cold.head.Core.Revision != selectedRevision || len(joined.Apply.Receipt) != 0 {
				t.Fatal("incomplete output commitment escaped Crypto or entered effects", code, joined.Apply.Result, store.creates-createsAtBind, store.cas-casAtBind, trust.signs-signsAtBind, creates-providerCreatesAtBind, deletes-deletesAtBind)
			}
			publicOutputApplyAssertNoPublication(t, cold)
		})
	}
}

// full_only: false
func TestApplyPublicationLateRelevantConflictPreservesEarlierAcknowledgement(t *testing.T) {
	for _, condition := range []string{"value", "incarnation", "group", "target", "unrelated-value", "blocker"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			f, env, _, private, _ := nativePublicationFixture(t, false)
			authority := f.session.admission.recipient
			entries := []ApplyEntryInput{
				{Name: "alpha", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{authority}, InputBytes: []byte("private data")},
				{Name: "beta", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{authority}, InputBytes: []byte("private data")},
				{Name: "outside", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{authority}, InputBytes: []byte("unrouted value")},
			}
			outputFor := func(input []ApplyEntryInput, grouped bool, changedTarget string) *outputApplyInput {
				var routed []ApplyEntryInput
				for _, entry := range input {
					if entry.Name != "outside" {
						routed = append(routed, entry)
					}
				}
				output := nativePublicationOutput(routed, []uint64{1, 9})
				output.routes = nil
				for i := range output.bindings[0].targets {
					target := &output.bindings[0].targets[i]
					slot := "plain-target-" + target.entryName
					if target.entryName == changedTarget {
						slot += "-changed"
					}
					hermeticRetargetOutput(&target.target, slot, slot)
					output.routes = append(output.routes, outputApplyRoute{entryName: target.entryName, destinations: []string{"native"}})
				}
				if changedTarget != "" {
					at := slices.IndexFunc(output.bindings[0].targets, func(row outputApplyTarget) bool { return row.entryName == changedTarget })
					if at < 0 {
						t.Fatal("changed target is absent from the complete fixture")
					}
					changed := output.bindings[0].targets[at]
					output.bindings[0].targets = slices.Delete(output.bindings[0].targets, at, at+1)
					destination := "next-" + changedTarget
					output.bindings = append(output.bindings, outputApplyBinding{destinationID: destination, targets: []outputApplyTarget{changed}})
					for i := range output.routes {
						if output.routes[i].entryName == changedTarget {
							output.routes[i].destinations = []string{destination}
						}
					}
				}
				if grouped && len(routed) == 2 {
					output.groups = [][]string{{"alpha", "beta"}}
				}
				return output
			}
			f.session = selectAdmittedOutputConfiguration(t, ctx, f.session, env, env.Custody, entries, outputFor(entries, true, ""))
			if condition == "target" {
				// One immutable installed passive table admits both old and future
				// destinations. The later conflict must follow authenticated state,
				// rather than fail because the fixture lost an interpretation.
				supported := outputFor(entries, true, "")
				for _, name := range []string{"alpha", "beta"} {
					future := outputFor(entries, true, name)
					supported.bindings = append(supported.bindings, future.bindings[1])
				}
				installOutputFixtureSource(t, f.session, supported)
			}
			f.admission = OpenContext{admission: &f.session.admission}
			if condition == "blocker" {
				seed := installedPublicationEngine(t, f, private).Publish(ctx, fixtureID(env.Domain, "late blocker existing births"), PublicationRequest{Names: []string{"alpha", "beta"}})
				assertInstalledPublicationVector(t, seed, contract.PublicationSummaryComplete, 2)
				for _, target := range seed.Output.Entries {
					if len(target.Actions) != 1 || target.Actions[0].Disposition != contract.PublicationOutcomeAcknowledged {
						t.Fatal("late blocker setup did not select both original births")
					}
				}
				publicationEngineReopen(t, f)
			}
			prepared, retired, changed := 0, 0, false
			firstName := ""
			var lateCoordinate, lateAttempt contract.ID
			var lateMarker, firstMarker contract.PublicationMarker
			original := private.NewOwner
			private.NewOwner = func(callctx context.Context, input publicationOwnerInput) (publicationPrivateOwner, error) {
				owner, err := original(callctx, input)
				if err != nil {
					return nil, err
				}
				return &publicationBetweenActionsOwner{publicationPrivateOwner: owner, prepare: func(selection *contract.ConsumerSelection) {
					prepared++
					want := []byte("private data")
					if condition == "blocker" {
						want = []byte("updated plain data")
					}
					if selection == nil || !bytes.Equal(selection.Entry.ValueBytes, want) {
						t.Fatal("publication substituted concurrent content")
					}
					if firstName == "" {
						firstName = selection.Entry.Name
					}
				}, afterRetire: func() {
					retired++
					if retired != 1 {
						return
					}
					current, state := Open(ctx, f.admission, f.store)
					if current == nil {
						t.Fatal("current before controlled conflicting selection", state)
					}
					laterName := "alpha"
					if firstName == laterName {
						laterName = "beta"
					}
					if condition == "blocker" {
						before, err := selectedPublicationRelation(current.selectedImage())
						if err != nil {
							t.Fatal("selected publication before independent blocker", err)
						}
						beforeEntries := current.currentEntryInputs()
						beforeConfiguration := current.root.OutputConfiguration
						f.session, f.admission = current, OpenContext{admission: &current.admission}
						controlled := newPublicationControlledPrivate()
						controlled.evidence = contract.PublicationUnproved
						independent := installedPublicationEngine(t, f, controlled.callbacks()).Publish(ctx, fixtureID(env.Domain, "independent later unknown write"), PublicationRequest{Names: []string{"alpha", "beta"}})
						assertInstalledPublicationVector(t, independent, contract.PublicationSummaryUnknown, 2)
						noOp := 0
						for _, target := range independent.Output.Entries {
							if len(target.Actions) != 1 {
								t.Fatal("independent blocker changed its complete action vector")
							}
							row := target.Actions[0]
							if row.Disposition == contract.PublicationNoOp {
								noOp++
								coordinate := before.coordinates[target.CoordinateID]
								firstMarker = before.markers[coordinate.LastValueAckAttemptID]
							} else if row.Disposition == contract.PublicationOutcomeUnknown && row.Action == contract.PublicationWriteValue && !row.AttemptID.IsZero() && lateAttempt.IsZero() {
								lateCoordinate, lateAttempt = target.CoordinateID, row.AttemptID
							} else {
								t.Fatal("independent publication did not add exactly one unknown write", row)
							}
						}
						if noOp != 1 || lateAttempt.IsZero() || firstMarker.AttemptID.IsZero() || len(controlled.owners) != 1 || controlled.owners[0].input.Target.EntryIncarnationID != current.valueEntry(entrySlot(t, current, laterName)).Incarnation || controlled.owners[0].prepared != 1 || controlled.owners[0].armed != 1 || controlled.owners[0].sent != 1 || controlled.owners[0].retired != 1 {
							t.Fatal("independent blocker did not join one exact later-coordinate send")
						}
						after := publicationEngineReopen(t, f)
						lateMarker = after.markers[lateAttempt]
						oldCoordinate, newCoordinate := before.coordinates[lateCoordinate], after.coordinates[lateCoordinate]
						if !reflect.DeepEqual(beforeEntries, f.session.currentEntryInputs()) || beforeConfiguration != f.session.root.OutputConfiguration || oldCoordinate.BindingState != newCoordinate.BindingState || oldCoordinate.ActiveBindingIncarnationID != newCoordinate.ActiveBindingIncarnationID || oldCoordinate.LastBindingIncarnationID != newCoordinate.LastBindingIncarnationID || oldCoordinate.LastEntryIncarnationID != newCoordinate.LastEntryIncarnationID || len(publicationBlockers(before, lateCoordinate)) != 0 || !slices.Equal(publicationBlockers(after, lateCoordinate), []contract.ID{lateAttempt}) || lateMarker.State != contract.PublicationUnknown || after.markers[firstMarker.AttemptID] != firstMarker {
							t.Fatal("independent blocker changed a fixed selection or retained binding premise")
						}
						changed = true
						return
					}
					input := installedApplyCurrentInput(current)
					grouped, target := true, ""
					switch condition {
					case "value", "unrelated-value":
						name := laterName
						if condition == "unrelated-value" {
							name = "outside"
						}
						for i := range input {
							if input[i].Name == name {
								input[i].InputBytes = []byte("later selected value")
							}
						}
					case "group":
						grouped = false
					case "target":
						target = laterName
					case "incarnation":
						removed := slices.DeleteFunc(slices.Clone(input), func(row ApplyEntryInput) bool { return row.Name == laterName })
						current = selectAdmittedOutputConfiguration(t, ctx, current, env, env.Custody, removed, outputFor(removed, false, ""))
					}
					if condition == "value" || condition == "unrelated-value" {
						beforeConfiguration := current.root.OutputConfiguration
						parent := admitSuppliedComparison(t, current, env.Custody, input)
						comparison, state := current.Compare(ctx, input, parent)
						if comparison == nil {
							t.Fatal("later value comparison", state)
						}
						candidate, state := current.Prepare(ctx, comparison, admit(t, current, comparison), env.Trust)
						if candidate == nil {
							t.Fatal("later value preparation", state)
						}
						selected, state := current.selectCandidate(ctx, candidate)
						if selected == nil || state.Outcome != ObservedCurrent {
							t.Fatal("later value selection", state)
						}
						env.Custody.RetireApply()
						f.session = generatedLifecycleReopen(t, ctx, selected, env.Store)
						if f.session.root.OutputConfiguration != beforeConfiguration {
							t.Fatal("value-only mutation changed the output configuration")
						}
					} else {
						f.session = selectAdmittedOutputConfiguration(t, ctx, current, env, env.Custody, input, outputFor(input, grouped, target))
					}
					f.admission = OpenContext{admission: &f.session.admission}
					changed = true
				}}, nil
			}
			a := publicPublicationApplyFixture(env, f)
			input := installedApplyCurrentInput(f.session)
			if condition == "blocker" {
				for i := range input {
					if input[i].Name != "outside" {
						input[i].InputBytes = []byte("updated plain data")
					}
				}
			}
			apply := a.engineWithValidator(t, f.session, input, currentApplyRecipients(f.session.registry()), installedOutputValidator(t, f.session), nil)
			joined := apply.ApplyAndPublish(ctx, fixtureID(env.Domain, "late conflict apply"), fixtureID(env.Domain, "late conflict publication"), input, installedPublicationEngine(t, f, private), nil)
			wantSummary, wantOwners := uint8(contract.PublicationSummaryMixedTerminal), 1
			if condition == "unrelated-value" {
				wantSummary, wantOwners = contract.PublicationSummaryComplete, 2
			}
			result := applyPublicationAssertStage(t, joined, wantSummary, 2)
			if !changed || prepared != wantOwners || retired != wantOwners {
				t.Fatal("later conflict reached another private owner or unrelated progress was blocked", prepared, retired)
			}
			ack, unsent := 0, 0
			for _, target := range result.Output.Entries {
				if len(target.Actions) != 1 {
					t.Fatal("late conflict changed the fixed requested action count")
				}
				action := target.Actions[0]
				if action.Disposition == contract.PublicationOutcomeAcknowledged {
					ack++
				} else if action.Disposition == contract.PublicationNotSent && action.AttemptID.IsZero() && action.CoreReason == uint16(DifferentSelection) {
					unsent++
				} else {
					t.Fatal("late conflict lost an earlier acknowledgement or sent a changed value", action)
				}
			}
			if ack != wantOwners || unsent != 2-wantOwners {
				t.Fatal("late conflict returned an incomplete ordered vector", ack, unsent)
			}
			if condition == "blocker" {
				first, later := result.Output.Entries[0], result.Output.Entries[1]
				if first.Actions[0].Disposition != contract.PublicationOutcomeAcknowledged || first.Actions[0].AttemptID != firstMarker.AttemptID || first.Actions[0].Evidence != firstMarker.Evidence || later.CoordinateID != lateCoordinate || later.Actions[0].Disposition != contract.PublicationNotSent || len(later.Actions[0].BlockerIDs) != 0 {
					t.Fatal("fresh blocker replaced the original fixed vector or earlier acknowledgement")
				}
				after := publicationEngineReopen(t, f)
				if after.markers[firstMarker.AttemptID] != firstMarker || after.markers[lateAttempt] != lateMarker || !slices.Equal(publicationBlockers(after, lateCoordinate), []contract.ID{lateAttempt}) {
					t.Fatal("combined refusal changed independent blocker or earlier acknowledgement")
				}
			}
		})
	}
}

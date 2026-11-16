package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
	"enkv.sh/telemetry"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// full_only: false
func TestInstalledReconstructionKeyMismatchRefusesAndClosesOwnership(t *testing.T) {
	env, _ := genesisEnvironment(t, contract.GCP, false)
	run := newScenarioRun(t, context.Background(), env)
	f := newEnvironmentFixture(t, context.Background(), run.env, []int{1}, false)
	store := env.Store.(*memoryStore)
	for _, condition := range []string{"mismatch", "wrapped-with-verifier", "cancel-with-verifier"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			reader := &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: store.StoreConfiguration()}
			verifier := &reconstructionVerifyProbe{}
			factories, installationCloses := 0, 0
			engine, err := NewInstalledReconstruction(ReconstructionInstallation{
				Candidate: candidateProbeForSelected(t, env, f.session), Normal: &candidateQualifierProbe{}, ExpectedDomain: env.Domain,
				Construct: func(_ context.Context, _ contract.StoreConfiguration) (PublicSelectedReader, Result) {
					return reader, Result{}
				},
				Verify: func(context.Context, contract.ReconstructionVerificationPins, time.Time) (ReconstructionVerifier, error) {
					factories++
					if condition == "mismatch" {
						return nil, ErrReconstructionKeyMismatch
					}
					if condition == "cancel-with-verifier" {
						cancel()
					}
					return verifier, fmt.Errorf("factory: %w", ErrReconstructionKeyMismatch)
				}, CloseInstalled: func() { installationCloses++ },
			})
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			creates, cas := store.creates, store.cas
			projection, result := engine.Reconstruct(ctx)
			engine.Close()
			want, wantCloses := (Result{Outcome: AdmissionRefused, Reason: ConstructionMismatch}), 0
			if condition != "mismatch" {
				wantCloses = 1
			}
			if condition == "cancel-with-verifier" {
				want = Result{Outcome: EvidenceUnavailable, Reason: CustodyUnavailable}
			}
			if projection != nil || result != want || factories != 1 || reader.closes != 1 || verifier.closes != wantCloses || verifier.calls != 0 || installationCloses != 1 || store.creates != creates || store.cas != cas {
				t.Fatal("expected-key mismatch lost its exact failure or close ownership", result, want, factories, reader.closes, verifier.closes, verifier.calls, installationCloses)
			}
		})
	}
}

// full_only: false
func TestInstalledReconstructionFactoryFailuresKeepUnavailableAndCloseOwnership(t *testing.T) {
	env, _ := genesisEnvironment(t, contract.GCP, false)
	run := newScenarioRun(t, context.Background(), env)
	f := newEnvironmentFixture(t, context.Background(), run.env, []int{1}, false)
	store := env.Store.(*memoryStore)
	for _, condition := range []string{"error", "nil", "verifier-with-error", "cancel-with-error"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			reader := &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: store.StoreConfiguration()}
			verifier := &reconstructionVerifyProbe{}
			factories, installationCloses := 0, 0
			engine, err := NewInstalledReconstruction(ReconstructionInstallation{
				Candidate: candidateProbeForSelected(t, env, f.session), Normal: &candidateQualifierProbe{}, ExpectedDomain: env.Domain,
				Construct: func(_ context.Context, _ contract.StoreConfiguration) (PublicSelectedReader, Result) {
					return reader, Result{}
				},
				Verify: func(context.Context, contract.ReconstructionVerificationPins, time.Time) (ReconstructionVerifier, error) {
					factories++
					if condition == "nil" {
						return nil, nil
					}
					if condition == "cancel-with-error" {
						cancel()
					}
					if condition == "verifier-with-error" || condition == "cancel-with-error" {
						return verifier, errors.New("unavailable factory")
					}
					return nil, errors.New("unavailable factory")
				}, CloseInstalled: func() { installationCloses++ },
			})
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			creates, cas := store.creates, store.cas
			projection, result := engine.Reconstruct(ctx)
			engine.Close()
			wantCloses := 0
			if condition == "verifier-with-error" || condition == "cancel-with-error" {
				wantCloses = 1
			}
			if projection != nil || result != (Result{Outcome: EvidenceUnavailable, Reason: CustodyUnavailable}) || factories != 1 || reader.closes != 1 || verifier.closes != wantCloses || verifier.calls != 0 || installationCloses != 1 || store.creates != creates || store.cas != cas {
				t.Fatal("factory failure changed classification or retained private ownership", result, factories, reader.closes, verifier.closes, verifier.calls, installationCloses)
			}
		})
	}
}

type blockingReconstructionTracer struct {
	trace.Tracer
	ended, release chan struct{}
}

func (t *blockingReconstructionTracer) Start(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	ctx, span := t.Tracer.Start(ctx, name, opts...)
	return ctx, &blockingReconstructionSpan{Span: span, ended: t.ended, release: t.release}
}

type blockingReconstructionSpan struct {
	trace.Span
	ended, release chan struct{}
}

func (s *blockingReconstructionSpan) End(opts ...trace.SpanEndOption) {
	close(s.ended)
	<-s.release
	s.Span.End(opts...)
}

// full_only: false
func TestInstalledReconstructionCloseJoinsTelemetryFinalizer(t *testing.T) {
	env, _ := genesisEnvironment(t, contract.GCP, false)
	run := newScenarioRun(t, context.Background(), env)
	f := newEnvironmentFixture(t, context.Background(), run.env, []int{1}, false)
	store := env.Store.(*memoryStore)
	tracer := &blockingReconstructionTracer{Tracer: noop.NewTracerProvider().Tracer("reconstruction"),
		ended: make(chan struct{}), release: make(chan struct{})}
	ctx, cancel := context.WithTimeout(telemetry.WithCapability(context.Background(),
		telemetry.NewCapabilityWithTracers(nil, nil, map[telemetry.Provider]trace.Tracer{telemetry.ProviderCore: tracer})), time.Minute)
	defer cancel()
	engine, err := NewInstalledReconstruction(ReconstructionInstallation{
		Candidate: candidateProbeForSelected(t, env, f.session), Normal: &candidateQualifierProbe{},
		Construct: func(_ context.Context, selected contract.StoreConfiguration) (PublicSelectedReader, Result) {
			return &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: selected}, Result{}
		},
		Verify: func(_ context.Context, _ contract.ReconstructionVerificationPins, _ time.Time) (ReconstructionVerifier, error) {
			return &reconstructionVerifyProbe{}, nil
		},
		CloseInstalled: func() {},
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		projection, _ := engine.Reconstruct(ctx)
		if projection != nil {
			projection.Close()
		}
		close(done)
	}()
	select {
	case <-tracer.ended:
	case <-time.After(5 * time.Second):
		t.Fatal("reconstruction did not reach telemetry finalization")
	}
	closed := make(chan struct{})
	go func() { engine.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close returned before the active telemetry finalizer")
	case <-time.After(50 * time.Millisecond):
	}
	close(tracer.release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reconstruction finalizer did not return")
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not join the complete invocation")
	}
}

type blockingReconstructionCandidate struct {
	PublicCandidateReader
	entered chan struct{}
	release chan struct{}
}

func (c *blockingReconstructionCandidate) ReadHEAD(ctx context.Context) contract.ReadResult {
	close(c.entered)
	select {
	case <-c.release:
		return c.PublicCandidateReader.ReadHEAD(ctx)
	case <-ctx.Done():
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}
	}
}

// full_only: false
func TestInstalledReconstructionOwnsFinalProjectionAndClosesAfterActiveCall(t *testing.T) {
	setup := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	run := newScenarioRun(t, setup, env)
	f := newEnvironmentFixture(t, setup, run.env, []int{1}, false)
	store := env.Store.(*memoryStore)
	ctx, cancel := context.WithTimeout(setup, time.Minute)
	defer cancel()
	originalDeadline := mustDeadline(t, ctx)
	candidate := &blockingReconstructionCandidate{PublicCandidateReader: candidateProbeForSelected(t, env, f.session),
		entered: make(chan struct{}), release: make(chan struct{})}
	var installedCloses atomic.Int32
	var matchedInvocation atomic.Bool
	engine, err := NewInstalledReconstruction(ReconstructionInstallation{
		Candidate: candidate, Normal: &candidateQualifierProbe{}, ExpectedDomain: env.Domain,
		Construct: func(_ context.Context, selected contract.StoreConfiguration) (PublicSelectedReader, Result) {
			return &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: selected}, Result{}
		},
		Verify: func(factoryCtx context.Context, _ contract.ReconstructionVerificationPins, deadline time.Time) (ReconstructionVerifier, error) {
			matchedInvocation.Store(factoryCtx.Done() == ctx.Done() && deadline.Equal(originalDeadline))
			return &reconstructionVerifyProbe{}, nil
		},
		CloseInstalled: func() { installedCloses.Add(1) },
	})
	if err != nil {
		t.Fatal("fixed reconstruction installation", err)
	}
	type answer struct {
		projection *ReconstructionProjection
		result     Result
	}
	done := make(chan answer, 1)
	go func() {
		projection, result := engine.Reconstruct(ctx)
		done <- answer{projection, result}
	}()
	select {
	case <-candidate.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("installed candidate did not start")
	}
	if duplicate, result := engine.Reconstruct(ctx); duplicate != nil || result.Outcome != AdmissionRefused ||
		result.Reason != AlreadyUsed {
		t.Fatal("second invocation waited for or entered the active reader", result)
	}
	closeDone := make(chan struct{})
	secondCloseDone := make(chan struct{})
	go func() { engine.Close(); close(closeDone) }()
	go func() { engine.Close(); close(secondCloseDone) }()
	deadlineToClose := time.After(5 * time.Second)
	for {
		engine.mu.Lock()
		closing := engine.closed
		engine.mu.Unlock()
		if closing {
			break
		}
		select {
		case <-deadlineToClose:
			t.Fatal("engine Close did not mark the route closed")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	prematureClose := false
	select {
	case <-closeDone:
		prematureClose = true
	case <-secondCloseDone:
		prematureClose = true
	case <-time.After(50 * time.Millisecond):
	}
	if installedCloses.Load() != 0 {
		t.Fatal("engine closed its private runtime during an active invocation")
	}
	if duplicate, result := engine.Reconstruct(ctx); duplicate != nil || result.Outcome != AdmissionRefused {
		t.Fatal("closed engine admitted another invocation", result)
	}
	close(candidate.release)
	var got answer
	select {
	case got = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("original finite invocation did not finish")
	}
	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("first Close did not join the installed runtime")
	}
	select {
	case <-secondCloseDone:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent Close did not join the same shutdown")
	}
	if prematureClose {
		t.Fatal("Close returned while the original invocation still owned the runtime")
	}
	if got.result.Outcome != ObservedCurrent || got.projection == nil || installedCloses.Load() != 1 ||
		!matchedInvocation.Load() {
		t.Fatal("active invocation lost its owned result or private Close", got.result)
	}
	if got.projection.PartCount() == 0 {
		t.Fatal("public result did not expose complete part count")
	}
	first, ok := got.projection.CopyPart(0)
	provenance, hasProvenance := got.projection.Provenance()
	if !ok || first.Kind != ReconstructionConfigurationPart || !hasProvenance ||
		provenance.Domain != env.Domain || provenance.Snapshot != f.session.root.Snapshot {
		t.Fatal("public result lost its selected configuration or provenance")
	}
	got.projection.Close()
	if got.projection.PartCount() != 0 || len(first.Body) == 0 {
		t.Fatal("Close changed an earlier caller-owned part")
	}
	if _, ok := got.projection.CopyPart(0); ok {
		t.Fatal("closed result exposed selected bytes")
	}
	if _, ok := got.projection.Provenance(); ok || installedCloses.Load() != 1 {
		t.Fatal("closed result exposed provenance or repeated installed Close")
	}
}

// full_only: false
func TestInstalledReconstructionTelemetryReportsResultWithoutSecret(t *testing.T) {
	setup := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, setup, env)
	f := newEnvironmentFixture(t, setup, run.env, []int{1}, false)
	const secretName = "reconstruction-private-name-canary"
	run.suppliedSelection(f, append(f.session.currentEntryInputs(),
		suppliedSecret(t, env, secretName, "private-telemetry-canary", custody.StandardValue)))
	store := env.Store.(*memoryStore)
	creates, cas := store.creates, store.cas
	recorder := telemetry.NewRecorder()
	ctx, cancel := context.WithTimeout(telemetry.WithCapability(setup, telemetry.NewCapability(nil, recorder)), time.Minute)
	defer cancel()
	engine, err := NewInstalledReconstruction(ReconstructionInstallation{
		Candidate: candidateProbeForSelected(t, env, f.session), Normal: &candidateQualifierProbe{},
		Construct: func(_ context.Context, configuration contract.StoreConfiguration) (PublicSelectedReader, Result) {
			return &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: configuration}, Result{}
		},
		Verify: func(_ context.Context, _ contract.ReconstructionVerificationPins, _ time.Time) (ReconstructionVerifier, error) {
			return &reconstructionVerifyProbe{}, nil
		},
		CloseInstalled: func() {},
	})
	if err != nil {
		t.Fatal("fixed telemetry installation", err)
	}
	projection, result := engine.Reconstruct(ctx)
	if result.Outcome != ObservedCurrent || projection == nil || store.creates != creates || store.cas != cas {
		t.Fatal("instrumented reconstruction did not observe the selected state without effects", result)
	}
	projection.Close()
	engine.Close()
	if next, refusedResult := engine.Reconstruct(ctx); next != nil || refusedResult.Outcome != AdmissionRefused {
		t.Fatal("closed instrumented engine admitted a later call", refusedResult)
	}
	records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 6))
	if len(records) != 6 || records[0].Operation != telemetry.OpCoreReconstruct ||
		records[0].Event != telemetry.DiagnosticStart || records[1].Event != telemetry.DiagnosticCheckpoint ||
		records[2].Event != telemetry.DiagnosticReturn || records[2].Result != telemetry.ResultObservedCurrent ||
		records[3].Operation != telemetry.OpCoreReconstruct || records[5].Result != telemetry.ResultAdmissionRefused {
		t.Fatal("reconstruction telemetry lost success/refusal or changed the closed event sequence", records)
	}
	for _, record := range records {
		if err := record.Validate(); err != nil {
			t.Fatal("invalid reconstruction telemetry", err)
		}
	}
	if text := fmt.Sprint(records); strings.Contains(text, secretName) ||
		strings.Contains(text, "private-telemetry-canary") {
		t.Fatal("reconstruction telemetry exposed a selected secret")
	}
}

// full_only: false
func TestReconstructionPrivateRunnerBoundsFullRestartsAndClosesReaders(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
	store := env.Store.(*memoryStore)
	beforeCreates, beforeCAS := store.creates, store.cas
	for _, tc := range []struct {
		name        string
		changeCount int
		wantOutcome Outcome
		wantReason  Reason
	}{
		{"success after two complete restarts", 2, ObservedCurrent, 0},
		{"third changed selection is terminal", 3, Contention, DifferentSelection},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := candidateProbeForSelected(t, env, f.session)
			var readers []*constructedReadProbe
			var verifiers []*reconstructionVerifyProbe
			input := reconstructionInputs{candidate: candidate, normal: &candidateQualifierProbe{},
				expectedDomain: env.Domain,
				construct: func(_ context.Context, configuration contract.StoreConfiguration) (PublicSelectedReader, Result) {
					if len(readers) > 0 && readers[len(readers)-1].closes != 1 {
						t.Fatal("a new attempt started before the old reader closed")
					}
					if configuration != store.StoreConfiguration() {
						t.Fatal("candidate chose a different Store construction")
					}
					p := &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: configuration}
					headReads := 0
					p.change = func(_ context.Context, read contract.ReadResult) contract.ReadResult {
						headReads++
						if headReads == 2 && len(readers) <= tc.changeCount {
							read.Token.Value = "9999"
						}
						return read
					}
					readers = append(readers, p)
					return p, Result{}
				},
				verifier: func(_ context.Context, _ contract.ReconstructionVerificationPins, deadline time.Time) (reconstructionVerifier, error) {
					if !deadline.Equal(mustDeadline(t, ctx)) {
						t.Fatal("private restart renewed its deadline")
					}
					p := &reconstructionVerifyProbe{}
					verifiers = append(verifiers, p)
					return p, nil
				},
			}
			projection, result := reconstructOwnedCurrent(ctx, input)
			if result.Outcome != tc.wantOutcome || result.Reason != tc.wantReason ||
				len(readers) != 3 || len(verifiers) != 3 || len(candidate.calls) != 9 ||
				store.creates != beforeCreates || store.cas != beforeCAS {
				t.Fatal("private runner skipped or exceeded the bounded complete attempts", result, len(readers), len(verifiers), candidate.calls)
			}
			if tc.wantOutcome == ObservedCurrent {
				if projection == nil || projection.partCount() == 0 {
					t.Fatal("verified final attempt did not transfer its projection")
				}
				projection.Close()
			} else if projection != nil {
				projection.Close()
				t.Fatal("changed third attempt returned a partial projection")
			}
			for i := range readers {
				if readers[i].closes != 1 || verifiers[i].closes != 1 || verifiers[i].calls != 0 {
					t.Fatal("attempt retained a reader/verifier or used a nonexistent secret", i)
				}
			}
			input.candidate = nil
			if partial, rejected := reconstructOwnedCurrent(ctx, input); partial != nil || rejected.Outcome != AdmissionRefused ||
				len(candidate.calls) != 9 || len(readers) != 3 {
				t.Fatal("missing fixed candidate reader reached public reads", rejected)
			}
		})
	}
}

// full_only: false
func TestReconstructionOwnedProjectionFollowsAllSecretAndFinalHEAD(t *testing.T) {
	setup := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, setup, env)
	f := newEnvironmentFixture(t, setup, run.env, []int{1}, false)
	run.suppliedSelection(f, append(f.session.currentEntryInputs(),
		suppliedSecret(t, env, "first", "reconstruction first", custody.StandardValue),
		suppliedSecret(t, env, "second", "reconstruction second", custody.EmptyValue)))
	store := env.Store.(*memoryStore)
	beforeCreates, beforeCAS := store.creates, store.cas
	ctx, cancel := context.WithTimeout(setup, time.Minute)
	defer cancel()
	var reader *constructedReadProbe
	var verifier *reconstructionVerifyProbe
	headReads := 0
	input := reconstructionInputs{candidate: candidateProbeForSelected(t, env, f.session),
		normal: &candidateQualifierProbe{}, expectedDomain: env.Domain,
		construct: func(_ context.Context, configuration contract.StoreConfiguration) (PublicSelectedReader, Result) {
			reader = &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: configuration}
			reader.change = func(_ context.Context, read contract.ReadResult) contract.ReadResult {
				headReads++
				if headReads == 2 && (verifier == nil || verifier.calls != 2 || verifier.closes != 1) {
					t.Fatal("final HEAD was read before every secret was verified and verifier closed")
				}
				return read
			}
			return reader, Result{}
		},
		verifier: func(_ context.Context, _ contract.ReconstructionVerificationPins, _ time.Time) (reconstructionVerifier, error) {
			verifier = &reconstructionVerifyProbe{}
			return verifier, nil
		},
	}
	projection, result := reconstructOwnedCurrent(ctx, input)
	if result.Outcome != ObservedCurrent || result.Evidence != AuthenticatedClosure || projection == nil ||
		reader == nil || reader.closes != 1 || verifier.calls != 2 || verifier.closes != 1 || headReads != 2 ||
		store.creates != beforeCreates || store.cas != beforeCAS {
		t.Fatal("complete projection was delivered before private/final checks or made an effect", result)
	}
	wantParts := len(fixedProjectionExpected(f.session.root)) + int(f.session.root.RequiredSupportRecordCount)
	if projection.partCount() != wantParts {
		t.Fatal("owned projection omitted selected rows", projection.partCount(), wantParts)
	}
	first, ok := projection.copyPart(0)
	if !ok || first.kind != reconstructionConfigurationPart || len(first.body) == 0 {
		t.Fatal("complete result lost its authenticated configuration")
	}
	first.body[0] ^= 1
	again, ok := projection.copyPart(0)
	if !ok || first.body[0] == again.body[0] {
		t.Fatal("caller changed the owned result")
	}
	cancel()
	if _, ok := projection.copyPart(projection.partCount() - 1); !ok {
		t.Fatal("post-Commit cancellation revoked the complete projection")
	}
	projection.Close()
	if projection.partCount() != 0 {
		t.Fatal("closed result retained visible selected bytes")
	}

	failedContext, failedCancel := context.WithTimeout(setup, time.Minute)
	defer failedCancel()
	input.candidate = candidateProbeForSelected(t, env, f.session)
	input.construct = func(_ context.Context, configuration contract.StoreConfiguration) (PublicSelectedReader, Result) {
		reader = &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: configuration}
		return reader, Result{}
	}
	input.verifier = func(_ context.Context, _ contract.ReconstructionVerificationPins, _ time.Time) (reconstructionVerifier, error) {
		verifier = &reconstructionVerifyProbe{failAt: 1}
		return verifier, nil
	}
	partial, result := reconstructOwnedCurrent(failedContext, input)
	if partial != nil || result.Outcome != IntegrityFailure || result.Reason != InvalidProof ||
		reader.closes != 1 || verifier.calls != 1 || verifier.closes != 1 ||
		store.creates != beforeCreates || store.cas != beforeCAS {
		t.Fatal("failed private check returned a partial result or retained a reader", result)
	}
}

// full_only: false
func TestReconstructionOwnedProjectionKeepsNonemptyConfiguration(t *testing.T) {
	setup := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, setup, env)
	f := newEnvironmentFixture(t, setup, run.env, []int{1}, false)
	run.suppliedSelection(f, append(f.session.currentEntryInputs(),
		suppliedSecret(t, env, "selected", "complete output", custody.StandardValue)))
	store, ordinary := signedNonemptyOutputSelection(t, env, f.session)
	ctx, cancel := context.WithTimeout(setup, time.Minute)
	defer cancel()
	beforeCreates, beforeCAS := store.creates, store.cas
	var reader *constructedReadProbe
	verifier := &reconstructionVerifyProbe{}
	input := reconstructionInputs{candidate: candidateProbeForSelected(t, env, ordinary),
		normal: &candidateQualifierProbe{}, expectedDomain: env.Domain,
		construct: func(_ context.Context, configuration contract.StoreConfiguration) (PublicSelectedReader, Result) {
			reader = &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: configuration}
			return reader, Result{}
		},
		verifier: func(_ context.Context, _ contract.ReconstructionVerificationPins, _ time.Time) (reconstructionVerifier, error) {
			return verifier, nil
		},
	}
	projection, result := reconstructOwnedCurrent(ctx, input)
	if result.Outcome != ObservedCurrent || projection == nil || reader.closes != 1 ||
		verifier.calls != 1 || verifier.closes != 1 ||
		store.creates != beforeCreates || store.cas != beforeCAS {
		t.Fatal("nonempty selected output did not reach a complete zero-effect projection", result)
	}
	defer projection.Close()
	var count int
	for i := 0; i < projection.partCount(); i++ {
		part, ok := projection.copyPart(i)
		if !ok {
			t.Fatal("complete owned part disappeared", i)
		}
		if part.kind != reconstructionSupportRowPart || part.supportKind != contract.OutputConfigurationSliceSupportKind {
			continue
		}
		row, err := contract.InspectOutputConfigurationSlice(part.body)
		if err != nil || row.ConfigurationDigest != ordinary.root.OutputConfiguration.ConfigurationDigest ||
			row.SliceIndex != uint16(count) || part.recordID.IsZero() {
			t.Fatal("selected nonempty configuration changed in complete result", err, count)
		}
		count++
	}
	if count != int(ordinary.root.OutputConfiguration.SliceCount) || ordinary.root.OutputConfiguration.BindingCount != 1 {
		t.Fatal("complete result omitted selected nonempty configuration")
	}
}

// full_only: false
func TestReconstructionOwnedProjectionDerivesOptionalDomain(t *testing.T) {
	setup := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, setup, env)
	f := newEnvironmentFixture(t, setup, run.env, []int{1}, false)
	store := env.Store.(*memoryStore)
	ctx, cancel := context.WithTimeout(setup, time.Minute)
	defer cancel()
	beforeCreates, beforeCAS := store.creates, store.cas
	reader := &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: store.StoreConfiguration()}
	input := reconstructionInputs{candidate: candidateProbeForSelected(t, env, f.session),
		normal: &candidateQualifierProbe{},
		construct: func(_ context.Context, _ contract.StoreConfiguration) (PublicSelectedReader, Result) {
			return reader, Result{}
		},
		verifier: func(_ context.Context, _ contract.ReconstructionVerificationPins, _ time.Time) (reconstructionVerifier, error) {
			return &reconstructionVerifyProbe{}, nil
		},
	}
	projection, result := reconstructOwnedCurrent(ctx, input)
	if result.Outcome != ObservedCurrent || projection == nil || reader.closes != 1 ||
		store.creates != beforeCreates || store.cas != beforeCAS {
		t.Fatal("optional DomainID prevented independently anchored complete reconstruction", result)
	}
	projection.Close()
	input.expectedDomain = env.Domain
	input.expectedDomain[0] ^= 1
	input.candidate = candidateProbeForSelected(t, env, f.session)
	if partial, rejected := reconstructOwnedCurrent(ctx, input); partial != nil || rejected.Outcome != IntegrityFailure ||
		rejected.Reason != ConstructionMismatch || store.creates != beforeCreates || store.cas != beforeCAS {
		t.Fatal("wrong optional DomainID passed the continuity check", rejected)
	}
}

// full_only: false
func TestReconstructionOwnedProjectionRejectsMalformedFactoryResult(t *testing.T) {
	setup := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, setup, env)
	f := newEnvironmentFixture(t, setup, run.env, []int{1}, false)
	store := env.Store.(*memoryStore)
	ctx, cancel := context.WithTimeout(setup, time.Minute)
	defer cancel()
	for _, tc := range []struct {
		name   string
		result Result
	}{
		{"zero outcome with reason", Result{Reason: ConstructionMismatch}},
		{"zero outcome with metadata", Result{ObservedRevision: env.Domain}},
		{"claimed observed current", Result{Outcome: ObservedCurrent}},
		{"claimed unchanged", Result{Outcome: Unchanged}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: store.StoreConfiguration()}
			beforeReads, beforeCreates, beforeCAS := store.reads, store.creates, store.cas
			verifierCalled := false
			input := reconstructionInputs{candidate: candidateProbeForSelected(t, env, f.session),
				normal: &candidateQualifierProbe{}, expectedDomain: env.Domain,
				construct: func(_ context.Context, _ contract.StoreConfiguration) (PublicSelectedReader, Result) {
					return reader, tc.result
				},
				verifier: func(_ context.Context, _ contract.ReconstructionVerificationPins, _ time.Time) (reconstructionVerifier, error) {
					verifierCalled = true
					return &reconstructionVerifyProbe{}, nil
				},
			}
			partial, result := reconstructOwnedCurrent(ctx, input)
			if partial != nil || result.Outcome != AdmissionRefused || result.Reason != AdmissionInvalid ||
				reader.closes != 1 || verifierCalled || store.reads != beforeReads ||
				store.creates != beforeCreates || store.cas != beforeCAS {
				t.Fatal("malformed construction reached selected reads or private verification", result)
			}
		})
	}
	t.Run("typed failure remains distinct", func(t *testing.T) {
		reader := &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: store.StoreConfiguration()}
		beforeReads := store.reads
		given := failure(EvidenceUnavailable, ReadUnavailable)
		given.StoreReason = contract.ReasonAccess
		input := reconstructionInputs{candidate: candidateProbeForSelected(t, env, f.session),
			normal: &candidateQualifierProbe{}, expectedDomain: env.Domain,
			construct: func(_ context.Context, _ contract.StoreConfiguration) (PublicSelectedReader, Result) {
				return reader, given
			},
			verifier: func(_ context.Context, _ contract.ReconstructionVerificationPins, _ time.Time) (reconstructionVerifier, error) {
				t.Fatal("typed construction failure reached private verifier")
				return nil, nil
			},
		}
		if partial, result := reconstructOwnedCurrent(ctx, input); partial != nil || result != given ||
			reader.closes != 1 || store.reads != beforeReads {
			t.Fatal("typed construction failure lost its reason or reader Close", result)
		}
	})
	t.Run("cancel during construction closes the returned reader", func(t *testing.T) {
		invocation, stop := context.WithTimeout(setup, time.Minute)
		defer stop()
		reader := &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: store.StoreConfiguration()}
		beforeReads, beforeCreates, beforeCAS := store.reads, store.creates, store.cas
		matched := false
		input := reconstructionInputs{candidate: candidateProbeForSelected(t, env, f.session),
			normal: &candidateQualifierProbe{}, expectedDomain: env.Domain,
			construct: func(received context.Context, _ contract.StoreConfiguration) (PublicSelectedReader, Result) {
				matched = received.Done() == invocation.Done()
				stop()
				return reader, Result{}
			},
			verifier: func(_ context.Context, _ contract.ReconstructionVerificationPins, _ time.Time) (reconstructionVerifier, error) {
				t.Fatal("cancelled construction reached private verifier")
				return nil, nil
			},
		}
		if partial, result := reconstructOwnedCurrent(invocation, input); partial != nil ||
			result.Outcome != EvidenceUnavailable || result.Reason != ReadUnavailable || !matched ||
			reader.closes != 1 || store.reads != beforeReads || store.creates != beforeCreates || store.cas != beforeCAS {
			t.Fatal("cancelled construction retained a reader or reached selected state", result)
		}
	})
}

// full_only: false
func TestReconstructionRegistryRequiresSelectedProvider(t *testing.T) {
	for _, provider := range []contract.Family{contract.AWS, contract.GCP} {
		t.Run(fmt.Sprintf("provider=%d", provider), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			env, _ := genesisEnvironment(t, provider, false)
			f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
			s := f.session
			if s.head.AuthKind != format.LifecycleAuth {
				t.Fatal("fixture must select a signed non-genesis closure")
			}
			materials := selectedMaterialFacts{accessLocations: s.accessLocations, valueReaders: s.valueReaders}
			if _, ok := selectedValueRelations(s.head, s.selectedImage(), s.root.CurrentAccess.Core.AuthorityRecipientID, materials); !ok {
				t.Fatal("same-provider registry control refused")
			}
			other := contract.AWS
			if provider == other {
				other = contract.GCP
			}
			foreign, _ := genesisEnvironment(t, other, false)
			state := sessionStateImage(t, s)
			var unused *contract.RecipientRecord
			for _, row := range state.Recipient.Slots {
				if row != nil && row.RecipientID != s.root.CurrentAccess.Core.AuthorityRecipientID {
					unused = row
					break
				}
			}
			if unused == nil {
				t.Fatal("fixture lacks an unused recipient")
			}
			for _, page := range state.Pages {
				if page != nil {
					for _, entry := range page.Slots {
						if entry != nil {
							for _, recipient := range entry.Recipients {
								if recipient == unused.RecipientID {
									t.Fatal("provider mismatch must not be a value member")
								}
							}
						}
					}
				}
			}
			binding := foreign.Bindings[1].Binding
			if _, err := contract.EncodeKMSBinding(binding); err != nil {
				t.Fatal("other-provider binding is malformed", err)
			}
			unused.CurrentBinding = &binding
			image := s.selectedImage()
			image.recipients[state.Recipient.Index] = &state.Recipient
			t.Run("selected-relation", func(t *testing.T) {
				if _, ok := selectedValueRelations(s.head, image, s.root.CurrentAccess.Core.AuthorityRecipientID, materials); ok {
					t.Fatal("unused recipient from a different provider passed the selected relation")
				}
			})
			// One signed complete route is enough; the relation control above
			// covers both provider directions without two complete replay fixtures.
			if provider != contract.GCP {
				return
			}
			store := env.Store.(*memoryStore)
			check := func(t *testing.T, selected *StateSession, want Result, wantPrivate int) {
				private := 0
				engine, err := NewInstalledReconstruction(ReconstructionInstallation{
					Candidate: candidateProbeForSelected(t, env, selected), Normal: &candidateQualifierProbe{}, ExpectedDomain: env.Domain,
					Construct: func(_ context.Context, configuration contract.StoreConfiguration) (PublicSelectedReader, Result) {
						return &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: configuration}, Result{}
					},
					Verify: func(context.Context, contract.ReconstructionVerificationPins, time.Time) (ReconstructionVerifier, error) {
						private++
						return &reconstructionVerifyProbe{}, nil
					}, CloseInstalled: func() {},
				})
				if err != nil {
					t.Fatal(err)
				}
				defer engine.Close()
				projection, result := engine.Reconstruct(ctx)
				if projection != nil {
					defer projection.Close()
				}
				if result.Outcome != want.Outcome || result.Reason != want.Reason || private != wantPrivate || (projection != nil) != (want.Outcome == ObservedCurrent) {
					t.Fatalf("signed registry: projection=%t result=%+v private=%d", projection != nil, result, private)
				}
			}
			t.Run("same-provider-reconstruction", func(t *testing.T) { check(t, s, Result{Outcome: ObservedCurrent}, 1) })
			writer := &fixture{store: store, trust: env.Trust.(*fixtureTrust), admission: f.admission, session: s}
			storeContractClosure(t, writer, state)
			selected := *s
			selected.body = store.objects[store.desc.HeadKey].Body
			selected.token = store.objects[store.desc.HeadKey].Token
			var err error
			selected.head, err = format.DecodeHead(selected.body)
			if err != nil {
				t.Fatal(err)
			}
			selected.root, err = format.DecodeRoot(store.objects[mustKey(t, store.desc.Prefix, selected.head.Core.Root)].Body)
			if err != nil {
				t.Fatal(err)
			}
			t.Run("ordinary-admission", func(t *testing.T) {
				if opened, result := Open(ctx, f.admission, store); opened != nil || result != (Result{Outcome: IntegrityFailure, Reason: InvalidRelation}) {
					t.Fatal("ordinary admission accepted the signed provider mismatch", result)
				}
			})
			t.Run("signed-reconstruction", func(t *testing.T) {
				check(t, &selected, Result{Outcome: IntegrityFailure, Reason: InvalidRelation}, 0)
			})
		})
	}
}

// full_only: false
func TestSelectedGeneratedSliceCachePreservesValidationGuards(t *testing.T) {
	env, s, _, _ := generatedAuthenticatedDeleteHazardFixture(t, false, 0)
	store := env.Store.(*memoryStore)
	s.generatedSlicesRoot = contract.ID{}
	if len(s.root.Generated.Fragments) == 0 || len(s.root.RequiredSupport) == 0 {
		t.Fatal("cache fixture requires selected generated fragments and support facts")
	}
	if result := s.verifySelectedGeneratedSlices(t.Context()); result != (Result{}) || s.generatedSlicesRoot.IsZero() {
		t.Fatal("valid selected generated slices did not populate the cache", result)
	}
	cached, locations := s.generatedSlicesRoot, len(s.generatedSliceLocations)
	// A cache hit and guard failures must not read Store.
	reads := store.reads
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		name string
		ctx  context.Context
	}{{"nil-context", nil}, {"cancelled-context", cancelled}} {
		t.Run(tc.name, func(t *testing.T) {
			if result := s.verifySelectedGeneratedSlices(tc.ctx); result != (Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable}) {
				t.Fatal("cache bypassed original context validation", result)
			}
		})
	}
	t.Run("nil-session", func(t *testing.T) {
		var absent *StateSession
		if result := absent.verifySelectedGeneratedSlices(t.Context()); result != (Result{Outcome: IntegrityFailure, Reason: InvalidRelation}) {
			t.Fatal("nil session bypassed selected fact validation", result)
		}
	})
	t.Run("missing-support-facts", func(t *testing.T) {
		bad := *s
		bad.supportFacts = nil
		if result := bad.verifySelectedGeneratedSlices(t.Context()); result != (Result{Outcome: IntegrityFailure, Reason: InvalidRelation}) {
			t.Fatal("cache bypassed selected support fact count", result)
		}
	})
	t.Run("valid-cache", func(t *testing.T) {
		if result := s.verifySelectedGeneratedSlices(t.Context()); result != (Result{}) || s.generatedSlicesRoot != cached || len(s.generatedSliceLocations) != locations {
			t.Fatal("valid cache did not retain verified locations without reading Store", result)
		}
	})
	if store.reads != reads {
		t.Fatal("cached calls or guard failures read Store")
	}
}

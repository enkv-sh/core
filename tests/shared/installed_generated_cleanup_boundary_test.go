package core

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/telemetry"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

type cleanupSelectionBoundaryTracer struct {
	trace.Tracer
	once sync.Once
	end  func()
}

func (t *cleanupSelectionBoundaryTracer) Start(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	ctx, span := t.Tracer.Start(ctx, name, opts...)
	if name == string(telemetry.OpCoreSelect) {
		return ctx, &cleanupSelectionBoundarySpan{Span: span, owner: t}
	}
	return ctx, span
}

type cleanupSelectionBoundarySpan struct {
	trace.Span
	owner *cleanupSelectionBoundaryTracer
}

func (s *cleanupSelectionBoundarySpan) End(opts ...trace.SpanEndOption) {
	s.Span.End(opts...)
	s.owner.once.Do(s.owner.end)
}

// full_only: false
func TestInstalledGeneratedCleanupOwnsCompleteFactsBeforeSelectionReturns(t *testing.T) {
	env, selected, original, packet := generatedAuthenticatedDeleteHazardFixture(t, false, 0)
	store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
	key, err := format.GeneratedResultKey(store.desc.Prefix, original.record.DomainID, original.record.InboxID)
	if err != nil {
		t.Fatal(err)
	}
	store.objects[key] = stored{Body: bytes.Clone(packet), Token: contract.Token{Family: store.desc.Family, Value: `"cleanup-boundary-original"`}}
	store.creates, store.cas, trust.signs = 0, 0, 0
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	boundary, readsAtBoundary := false, 0
	tracer := &cleanupSelectionBoundaryTracer{Tracer: noop.NewTracerProvider().Tracer("cleanup-selection-boundary")}
	tracer.end = func() {
		// Core's select span ends after its authenticated readback and before
		// the installed coordinator constructs its response-boundary result.
		boundary, readsAtBoundary = true, store.reads
		cancel()
	}
	ctx = telemetry.WithCapability(ctx, telemetry.NewCapabilityWithTracers(nil, nil,
		map[telemetry.Provider]trace.Tracer{telemetry.ProviderCore: tracer}))
	engine := installedGeneratedCleanupTestEngine(t, env, selected, installedGeneratedVerificationTestCallbacks(t, env))
	got := engine.CleanupGenerated(ctx, generatedVectorID(245))
	engine.Close()
	if !boundary || ctx.Err() != context.Canceled || got.Result.Outcome != ObservedCurrent || got.Result.Evidence != AuthenticatedClosure ||
		got.Result.RequestedRevision.IsZero() || got.Result.RequestedRevision != got.Result.ObservedRevision || store.cas != 1 || trust.signs != 1 {
		t.Fatal("cancellation did not occur after exact successful cleanup readback", boundary, ctx.Err(), got.Result, store.cas, trust.signs)
	}
	if store.reads != readsAtBoundary {
		t.Fatal("cleanup read Store after authenticated selection returned", store.reads-readsAtBoundary)
	}
	if got.Generated == nil || got.Generated.StateResult != "success" || len(got.Generated.Effects) != 1 ||
		got.Generated.Effects[0].Record.AttemptID != original.record.AttemptID || got.Generated.AcknowledgedCount != 1 ||
		!got.Generated.Warnings.InvalidationNotConfirmed || len(got.Receipt) != 0 {
		t.Fatal("post-readback cancellation erased exact original effect facts", got.Generated)
	}
	if got.Payload != nil {
		t.Fatal("cleanup returned TransitionPayload after exact cleanup readback")
	}
	if got.Cleanup == nil {
		t.Fatal("post-readback cancellation lost complete Core-owned CleanupPayload")
	}
	if got.Cleanup.SiblingResults.Count != 1 || got.Cleanup.SiblingResults.RootDigest.IsZero() {
		t.Fatal("cleanup omitted its complete one-sibling Product-result commitment")
	}
	if got.Cleanup.RemainingWorkBasis.HeadRevisionID != got.Result.ObservedRevision {
		t.Fatal("selected cleanup returned a predecessor remaining-work basis")
	}
	if !slices.Contains(got.Cleanup.RemainingInboxIDs, original.record.InboxID) {
		t.Fatal("selected cleanup lost its exact pending-inbox-release identity")
	}
	descriptor, err := GeneratedCleanupSiblingResults(got)
	if err != nil || descriptor != got.Cleanup.SiblingResults {
		t.Fatal("cleanup delivered a stale or invalid complete sibling commitment", err)
	}
}

// full_only: false
func TestInstalledGeneratedCleanupFinalQualificationKeepsInstallationLease(t *testing.T) {
	profile := defaultGeneratedFixtureProfile()
	profile.CompletionClass = contract.GeneratedCompletionConfirmed
	env, selected, original, packet := generatedAuthenticatedDeleteHazardFixtureForProfile(t, t.Context(), false, 0, profile)
	store := env.Store.(*memoryStore)
	key, err := format.GeneratedResultKey(store.desc.Prefix, original.record.DomainID, original.record.InboxID)
	if err != nil {
		t.Fatal(err)
	}
	store.objects[key] = stored{Body: bytes.Clone(packet), Token: contract.Token{Family: store.desc.Family, Value: `"cleanup-lease-original"`}}
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		selectionReturned, finalCalls := false, 0
		tracer := &cleanupSelectionBoundaryTracer{Tracer: noop.NewTracerProvider().Tracer("cleanup-final-qualification")}
		tracer.end = func() { selectionReturned = true }
		ctx = telemetry.WithCapability(ctx, telemetry.NewCapabilityWithTracers(nil, nil, map[telemetry.Provider]trace.Tracer{telemetry.ProviderCore: tracer}))
		callbacks := installedGeneratedVerificationTestCallbacks(t, env)
		engine := installedGeneratedCleanupTestEngine(t, env, selected, callbacks)
		disposed := make(chan struct{})
		engine.installation.CloseInstalled = func() { close(disposed) }
		engine.installation.Generated.ResolveImplementation = func(GeneratedImplementationRequest) (contract.GeneratorImplementation, error) {
			if selectionReturned {
				finalCalls++
				engine.mu.Lock()
				active := engine.activeDone != nil
				engine.mu.Unlock()
				if !active {
					t.Error("final cleanup qualification lost its installation lease")
				}
				go engine.Close()
				synctest.Wait()
				select {
				case <-disposed:
					t.Error("Close disposed installation during final cleanup qualification")
				default:
				}
			}
			return contract.GeneratorImplementation{}, contract.ErrRecord
		}
		got := engine.CleanupGenerated(ctx, generatedVectorID(243))
		engine.Close()
		<-disposed
		if finalCalls != 1 || got.Generated == nil || got.Cleanup == nil || got.Result.Outcome != ObservedCurrent {
			t.Fatal("final qualification did not preserve selected cleanup facts", finalCalls, got.Result)
		}
		if descriptor, err := GeneratedCleanupSiblingResults(got); err != nil || descriptor != got.Cleanup.SiblingResults {
			t.Fatal("cleanup released its lease before complete result refresh", err)
		}
	})
}

// full_only: false
func TestInstalledGeneratedCleanupContinuationQualificationKeepsInstallationLease(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f, selected, current, _ := installedGeneratedRetirementFixture(t, ctx, "unknown")
	retirer := installedGeneratedRetirementEngine(t, ctx, f, selected, installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess))
	parked := retirer.RetireGenerated(ctx, generatedVectorID(241), GeneratedRetirementRequest{DutyID: current.Generated.RetiringDutyID})
	retirer.Close()
	selected = f.open(t, ctx)
	work := mustSelectedGeneratedWork(t, selected)
	if parked.Generated == nil || parked.Generated.StateResult != "effect-unknown" || len(work.attempts) != 1 {
		t.Fatal("retirement uncertainty prerequisite", parked.Result)
	}
	var original contract.ID
	for id := range work.attempts {
		original = id
	}
	acceptor := installedGeneratedRetirementEngine(t, ctx, f, selected, nil)
	accepted := acceptor.AcceptGeneratedRetirementRisk(ctx, generatedVectorID(242), GeneratedRetirementRiskRequest{DutyID: current.Generated.RetiringDutyID, AttemptID: original})
	acceptor.Close()
	if accepted.Result.Outcome != ObservedCurrent {
		t.Fatal("cleanup ownership prerequisite", accepted.Result)
	}
	selected = f.open(t, ctx)
	cleaner := installedGeneratedRetirementEngine(t, ctx, f, selected, installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess))
	prior := cleaner.CleanupGenerated(ctx, generatedVectorID(243))
	cleaner.Close()
	if prior.Result.Outcome != ObservedCurrent || prior.Generated == nil || prior.Generated.StateResult != "effect-unknown" {
		t.Fatal("retained cleanup prerequisite", prior.Result)
	}
	selected = f.open(t, ctx)
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		callbacks := installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess)
		callbacks.AdmitProducer = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedProducerInput, contract.GeneratorImplementation, time.Time) (*InstalledGeneratedProducerCustody, error) {
			t.Error("observation-only continuation restored a producer")
			return nil, contract.ErrRecord
		}
		engine := installedGeneratedRetirementEngine(t, ctx, f, selected, callbacks)
		disposed := make(chan struct{})
		engine.installation.CloseInstalled = func() { close(disposed) }
		calls := 0
		engine.installation.Generated.ResolveImplementation = func(GeneratedImplementationRequest) (contract.GeneratorImplementation, error) {
			calls++
			engine.mu.Lock()
			active := engine.activeDone != nil
			engine.mu.Unlock()
			if !active {
				t.Error("continuation qualification lost its installation lease")
			}
			go engine.Close()
			synctest.Wait()
			select {
			case <-disposed:
				t.Error("Close disposed installation during continuation qualification")
			default:
			}
			return contract.GeneratorImplementation{}, contract.ErrRecord
		}
		got := engine.ContinueGeneratedCleanup(ctx, generatedVectorID(244), GeneratedCleanupContinuationRequest{OperationID: prior.OperationID})
		engine.Close()
		<-disposed
		if calls != 1 || got.Generated == nil || got.Cleanup == nil || got.Result.Outcome != ObservedCurrent || got.OperationID != prior.OperationID {
			t.Fatal("continuation did not qualify exact retained cleanup", calls, got.Result)
		}
	})
}

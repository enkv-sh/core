package core

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/telemetry"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// full_only: false
func TestInstalledGeneratedCleanupCaptureRefusalPrecedesSigning(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f, s, current, effects := installedGeneratedRetirementFixture(t, ctx, "unknown")
	callbacks := installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess)
	retiring := installedGeneratedRetirementEngine(t, ctx, f, s, callbacks)
	parked := retiring.RetireGenerated(ctx, generatedVectorID(221), GeneratedRetirementRequest{DutyID: current.Generated.RetiringDutyID})
	retiring.Close()
	if parked.Result.Outcome != ObservedCurrent || parked.Generated == nil || parked.Generated.StateResult != "effect-unknown" {
		t.Fatal("exact unknown retirement prerequisite", parked.Result)
	}
	s = f.open(t, ctx)
	work := mustSelectedGeneratedWork(t, s)
	if len(work.attempts) != 1 {
		t.Fatal("expected exactly one retained original")
	}
	var original contract.ID
	for id := range work.attempts {
		original = id
	}
	accepting := installedGeneratedRetirementEngine(t, ctx, f, s, nil)
	accepted := accepting.AcceptGeneratedRetirementRisk(ctx, generatedVectorID(222), GeneratedRetirementRiskRequest{DutyID: current.Generated.RetiringDutyID, AttemptID: original})
	accepting.Close()
	if accepted.Result.Outcome != ObservedCurrent {
		t.Fatal("exact fenced source prerequisite", accepted.Result)
	}
	s = f.open(t, ctx)
	work = mustSelectedGeneratedWork(t, s)
	selected, present, err := s.readGeneratedCleanup(ctx)
	if err != nil || !present || selected.kind != generatedCleanupHazard {
		t.Fatal("ordinary owned target prerequisite", err)
	}
	engine := installedGeneratedRetirementEngine(t, ctx, f, s, callbacks)
	deadline, _ := ctx.Deadline()
	plan, err := s.installedGeneratedCleanupPlan(ctx, engine.installation, work, selected, deadline)
	if err != nil {
		t.Fatal(err)
	}
	store, trust := f.env.Store.(*memoryStore), f.env.Trust.(*fixtureTrust)
	before := bytes.Clone(store.objects[store.desc.HeadKey].Body)
	beforeCreates, beforeDeletes := effects()
	store.creates, store.cas, trust.signs = 0, 0, 0
	calls := 0
	p, owner, result := s.prepareInstalledGeneratedDelete(ctx, engine.installation, plan, deadline, func(*generatedReservation, contract.ID) error { calls++; return contract.ErrRecordCapacity })
	if owner != nil {
		owner.Close()
	}
	engine.Close()
	if calls != 1 || p != nil || result.Outcome == ObservedCurrent {
		t.Fatal("capture refusal was not reached and returned", calls, p != nil, result)
	}
	afterCreates, afterDeletes := effects()
	if afterCreates != beforeCreates || !reflect.DeepEqual(afterDeletes, beforeDeletes) || store.cas != 0 || !bytes.Equal(before, store.objects[store.desc.HeadKey].Body) {
		t.Fatal("capture refusal changed HEAD or entered a producer")
	}
	if trust.signs != 0 || store.creates != 0 {
		t.Fatal("cleanup signed or persisted before its result capture admitted capacity", trust.signs, store.creates)
	}
}

type cleanupCloseBeforeExchange struct {
	contract.Crypto
	close func()
}

func (c *cleanupCloseBeforeExchange) Exchange(ctx context.Context, q contract.CryptoRequest) contract.CryptoResponse {
	c.close()
	return c.Crypto.Exchange(ctx, q)
}

// All public effect evidence below comes from a production sealed original and
// a real selected reservation. Closing an actual owner injects only failure.
func cleanupSelectedReservationFixture(t *testing.T, ctx context.Context) (fixtureEnvironment, *StateSession, PublicApplyResult, generatedAttempt, generatedRecordKey, *generatedSelectionCheckpoint) {
	t.Helper()
	env, s, _, _ := generatedAuthenticatedDeleteHazardFixture(t, false, 0)
	work := mustSelectedGeneratedWork(t, s)
	source, present, err := s.readGeneratedCleanup(ctx)
	if err != nil || !present || source.kind != generatedCleanupHazard {
		t.Fatal("fenced ordinary cleanup source", err)
	}
	input, canonical := generatedDeletePlanInputForSource(t, s, generatedVectorID(223), work.records[source.sourceKey()], source.target)
	prior, _ := preparePrivateGeneratedReservation(t, env, s, input, canonical)
	producer, expected := preparePrivateGeneratedProducer(t, env, s, prior, nil)
	out := PublicApplyResult{DomainID: s.root.Domain, OperationID: input.graph.Header.OperationID, RequestID: generatedVectorID(224), RequestIdentity: producer.reservation.identity.RequestIdentityDigest}
	capture, err := captureInstalledGeneratedCleanupReservation(ctx, s, work, producer.reservation, producer.attempt, source.sourceKey(), source.target)
	if err != nil {
		t.Fatal(err)
	}
	var packet []byte
	if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		var code contract.CryptoResultCode
		packet, _, code = env.Custody.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		return code
	}) {
		t.Fatal("exact original producer handoff")
	}
	store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
	store.cas, trust.signs = 0, 0
	entered, result := s.selectCandidate(ctx, producer.reservation.candidate)
	if entered == nil || result.Outcome != ObservedCurrent || result.Evidence != AuthenticatedClosure || len(packet) == 0 || store.cas != 1 {
		t.Fatal("exact reservation did not select and seal its real original", result, len(packet), store.cas)
	}
	out.Result = result
	out.Generated, err = capture.observe(ctx, entered, result)
	if err != nil {
		t.Fatal(err)
	}
	capture.attach(&out)
	if capture.observedPayload != nil || len(capture.observed.Effects) != 0 || capture.hasCandidate {
		t.Fatal("selected response retained its unused before backing")
	}
	checkpoint := &generatedSelectionCheckpoint{}
	checkpoint.recordSelected(out)
	if err := RefreshGeneratedCleanupResult(&out); err != nil {
		t.Fatal(err)
	}
	env.Custody.RetireGenerated()
	key, err := format.GeneratedResultKey(store.desc.Prefix, s.root.Domain, expected.Template.InboxID)
	if err != nil {
		t.Fatal(err)
	}
	store.objects[key] = stored{Body: bytes.Clone(packet), Token: contract.Token{Family: store.desc.Family, Value: `"cleanup-preparation-original"`}}
	actual := mustSelectedGeneratedWork(t, entered).attempts[expected.Template.AttemptID]
	return env, entered, out, actual, source.sourceKey(), checkpoint
}

// full_only: false
func TestInstalledGeneratedCleanupPreparationStopPreservesSelectedResult(t *testing.T) {
	for _, stage := range []string{"PrepareRecord", "BindCandidate", "Claim", "close"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			env, s, before, original, source, checkpoint := cleanupSelectedReservationFixture(t, ctx)
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			reached := false
			callbacks := &GeneratedApplyInstallation{AdmitAdoption: func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedAdoptionInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
				owner, err := env.Custody.NewInstalledGeneratedAdoption(q, control, input, deadline)
				if err != nil {
					return nil, err
				}
				wrapped := &InstalledGeneratedCustody{Crypto: owner, BindCandidate: owner.BindCandidate, Close: owner.Close}
				switch stage {
				case "PrepareRecord":
					wrapped.Crypto = &cleanupCloseBeforeExchange{Crypto: owner, close: func() { reached = true; owner.Close() }}
				case "BindCandidate":
					wrapped.BindCandidate = func(ctx context.Context, input contract.GeneratedCandidateInput) contract.CryptoResultCode {
						reached = true
						owner.Close()
						return owner.BindCandidate(ctx, input)
					}
				case "Claim":
					wrapped.BindCandidate = func(ctx context.Context, input contract.GeneratedCandidateInput) contract.CryptoResultCode {
						code := owner.BindCandidate(ctx, input)
						if code == contract.CryptoSuccess {
							reached = true
							owner.Close()
						}
						return code
					}
				}
				return wrapped, nil
			}}
			expected := before.Result
			if stage == "close" {
				tracer := &cleanupSelectionBoundaryTracer{Tracer: noop.NewTracerProvider().Tracer("cleanup-after-adoption-preparation")}
				tracer.end = func() {
					head, err := format.DecodeHead(store.objects[store.desc.HeadKey].Body)
					if err != nil {
						t.Fatal(err)
					}
					expected = Result{Outcome: ObservedCurrent, Evidence: AuthenticatedClosure, RequestedRevision: head.Core.Revision, ObservedRevision: head.Core.Revision, ObservedSnapshotID: head.Core.Root.Object}
					reached = true
					trust.corrupt = true
				}
				ctx = telemetry.WithCapability(ctx, telemetry.NewCapabilityWithTracers(nil, nil, map[telemetry.Provider]trace.Tracer{telemetry.ProviderCore: tracer}))
			}
			deadline, _ := ctx.Deadline()
			got := (&InstalledApply{}).driveInstalledGeneratedCleanup(ctx, before, s, ApplyInstallation{Generated: callbacks, Trust: trust}, deadline, nil, nil, checkpoint)
			trust.corrupt = false
			if !reached {
				t.Fatal("requested actual preparation boundary was not reached", got.Result)
			}
			wantCAS := 1
			if stage == "close" {
				wantCAS = 2
			}
			if store.cas != wantCAS {
				t.Fatal("unexpected selection count", store.cas, wantCAS)
			}
			if got.Result != expected {
				t.Fatal("later preparation erased actual invocation CAS result", got.Result, expected)
			}
			if got.Generated == nil || got.Cleanup == nil || got.Payload != nil || len(got.Receipt) != 0 || got.Cleanup.RemainingWorkBasis.HeadRevisionID != expected.ObservedRevision || len(got.Generated.Effects) != 1 || got.Generated.Effects[0].Record.AttemptID != original.record.AttemptID || got.Generated.Effects[0].Target == nil || got.Generated.Effects[0].Target.ResourceDigest != original.expected.TargetResourceDigest || len(got.Diagnostics) == 0 {
				t.Fatal("later preparation lost owned selected cleanup facts", got.Generated, got.Cleanup)
			}
			if stage == "close" {
				if got.Generated.StateResult != "effect-pending" || got.Generated.Effects[0].Record.State != contract.GeneratedEffectSucceeded || got.Generated.EvidenceCeiling != contract.ReceiptEvidenceAcknowledged || !containsCleanupID(got.Cleanup.RemainingHazardIDs, source.id) {
					t.Fatal("adopted original or unfinished owner was replaced", got.Generated)
				}
			} else if !reflect.DeepEqual(got.Generated, before.Generated) || got.Cleanup != before.Cleanup {
				t.Fatal("reservation checkpoint evidence was replaced")
			}
		})
	}
}

// full_only: false
func TestInstalledGeneratedCleanupReusesExactCheckpointBacking(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	env, s, before, original, _, checkpoint := cleanupSelectedReservationFixture(t, ctx)
	work := mustSelectedGeneratedWork(t, s)
	packet, present, result := s.ReadGeneratedResult(ctx, original.record.AttemptID)
	if result.Outcome != 0 || !present {
		t.Fatal("actual original inbox prerequisite", result)
	}
	deadline, _ := ctx.Deadline()
	admitted, err := installedGeneratedContext(s, deadline)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := s.generatedRecordRequest(ctx, original.record.AttemptID, packet, admitted)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := s.deriveGeneratedRecord(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	capture, err := captureInstalledGeneratedCleanupObservation(ctx, s, work, proposal, checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if capture.observedPayload != before.Cleanup || len(capture.observed.Effects) != 1 || &capture.observed.Effects[0] != &checkpoint.generated.Effects[0] {
		t.Fatal("later step copied exact checkpoint backing")
	}
	selectedBacking := capture.selectedPayload
	facts, err := capture.observe(ctx, proposal.state, Result{Outcome: Contention})
	if err != nil || facts != &capture.observed || capture.payload != before.Cleanup || capture.selectedPayload != nil || selectedBacking == nil || len(capture.selected.Effects) != 0 || capture.hasCandidate {
		t.Fatal("one-shot observation kept unused candidate backing", err)
	}
	for _, field := range []string{"head", "predecessor", "target"} {
		t.Run(field, func(t *testing.T) {
			damaged := *checkpoint
			payload := *checkpoint.cleanup
			damaged.cleanup = &payload
			switch field {
			case "head":
				payload.RemainingWorkBasis.HeadRevisionID[0] ^= 1
			case "predecessor":
				payload.PredecessorRevisionID[0] ^= 1
			case "target":
				target := *payload.Basis.Target
				target.ResourceDigest[0] ^= 1
				payload.Basis.Target = &target
			}
			if _, err := captureInstalledGeneratedCleanupObservation(ctx, s, work, proposal, &damaged); err == nil {
				t.Fatal("mismatching checkpoint payload reused")
			}
		})
	}
	if env.Store.(*memoryStore).cas != 1 {
		t.Fatal("passive capture acquired selection authority")
	}
}

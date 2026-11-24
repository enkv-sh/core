package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/telemetry"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// full_only: false
func TestInstalledGeneratedInitialReservationUnknownDoesNotInventFacts(t *testing.T) {
	for _, operation := range []string{"apply", "retire", "cleanup"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			var f installedApplyTestFixture
			var selected *StateSession
			var current contract.ValueEntry
			var input []ApplyEntryInput
			var callbacks *GeneratedApplyInstallation
			var effects func() (int, []string)
			var cleanupSource contract.ID
			var cleanupTarget contract.GeneratorTarget
			var cleanupBeforeIDs [3][]contract.ID
			if operation == "retire" || operation == "cleanup" {
				mode := "acknowledged"
				if operation == "cleanup" {
					mode = "unknown"
				}
				f, selected, current, effects = installedGeneratedRetirementFixture(t, ctx, mode)
				callbacks = installedGeneratedRetirementCallbacks(t, f, f.env.GeneratedProcess)
				if operation == "cleanup" {
					retirer := installedGeneratedRetirementEngine(t, ctx, f, selected, callbacks)
					parked := retirer.RetireGenerated(ctx, testID("cleanup loss unknown retirement"), GeneratedRetirementRequest{DutyID: current.Generated.RetiringDutyID})
					retirer.Close()
					selected = f.open(t, ctx)
					work := mustSelectedGeneratedWork(t, selected)
					if parked.Result.Outcome != ObservedCurrent || parked.Generated == nil || parked.Generated.StateResult != "effect-unknown" || work.parent != nil || len(work.attempts) != 1 {
						t.Fatal("cleanup loss prerequisite did not park one exact unknown retirement", parked.Result)
					}
					var original generatedAttempt
					for _, attempt := range work.attempts {
						original = attempt
					}
					cleanupSource = original.expected.Template.HazardID
					acceptor := installedGeneratedRetirementEngine(t, ctx, f, selected, nil)
					accepted := acceptor.AcceptGeneratedRetirementRisk(ctx, testID("cleanup loss exact risk acceptance"), GeneratedRetirementRiskRequest{DutyID: current.Generated.RetiringDutyID, AttemptID: original.record.AttemptID})
					acceptor.Close()
					if accepted.Result.Outcome != ObservedCurrent {
						t.Fatal("cleanup loss prerequisite did not accept exact qualified risk", accepted.Result)
					}
					selected = f.open(t, ctx)
					work = mustSelectedGeneratedWork(t, selected)
					hazard, err := contract.InspectGeneratedHazardRecord(work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, cleanupSource}].Body)
					if err != nil || hazard.OriginalAttemptID != original.record.AttemptID || hazard.ResourceID != original.record.ResourceID {
						t.Fatal("cleanup loss prerequisite lost its exact original Hazard", err)
					}
					targets, err := work.vectors.resolve(contract.GeneratedHazardSupportKind, cleanupSource, contract.GeneratorVectorTargets, hazard.Target)
					if err != nil || len(targets) != 1 {
						t.Fatal("cleanup loss prerequisite has no exact authenticated target", err)
					}
					cleanupTarget, err = contract.InspectGeneratorTarget(targets[0])
					if err != nil || cleanupTarget.ResourceContractID != original.expected.Template.ResourceContractID || cleanupTarget.ResourceDigest != original.expected.TargetResourceDigest {
						t.Fatal("cleanup loss prerequisite changed the original target", err)
					}
					for key := range work.records {
						switch key.kind {
						case contract.GeneratedDutySupportKind:
							cleanupBeforeIDs[0] = append(cleanupBeforeIDs[0], key.id)
						case contract.GeneratedHazardSupportKind:
							cleanupBeforeIDs[1] = append(cleanupBeforeIDs[1], key.id)
						case contract.PendingInboxReleaseSupportKind:
							cleanupBeforeIDs[2] = append(cleanupBeforeIDs[2], key.id)
						}
					}
					for _, ids := range cleanupBeforeIDs {
						slices.SortFunc(ids, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
					}
				}
			} else {
				process, count := configurationRecoveryLocalGeneratedProcess(t)
				f = newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
				f.env.GeneratedProcess = process
				selected = f.selected
				effects = func() (int, []string) { creates, deletes := count(); return int(creates), make([]string, deletes) }
				declaration := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Epoch: 0, RetirementMode: contract.GeneratedRetirementManual,
					ConfigContractID: process.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(), CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent)}
				input = []ApplyEntryInput{{Name: "generated", Recipients: []contract.ID{selected.admission.recipient}, ValueSource: contract.Generated, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ConfidentialityClass: contract.Secret, Generated: &declaration}}
				callbacks = installedGeneratedTestCallbacks(t, f, process)
			}
			var invocations atomic.Int32
			admit := callbacks.AdmitProducer
			callbacks.AdmitProducer = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedProducerInput, row contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
				owner, err := admit(ctx, q, control, input, row, deadline)
				if err == nil && owner != nil {
					invoke := owner.InvokeProducer
					owner.InvokeProducer = func(ctx context.Context, authority, transmission contract.ID) contract.GeneratedProducerResult {
						invocations.Add(1)
						return invoke(ctx, authority, transmission)
					}
				}
				return owner, err
			}
			var engine *InstalledApply
			if operation == "retire" || operation == "cleanup" {
				engine = installedGeneratedRetirementEngine(t, ctx, f, selected, callbacks)
			} else {
				engine = installedGeneratedTestEngine(t, ctx, f, selected, input, currentApplyRecipients(selected.registry()), callbacks)
			}
			store, ok := underlyingAdmittedMemoryStore(f.env.Store)
			if !ok {
				t.Fatal("fixture has no existing Store fault controls")
			}
			beforeCreates, beforeDeletes := effects()
			beforeRevision, beforeRoot := selected.head.Core.Revision, selected.head.Core.Root
			baseline := store.cas
			store.casMode = "lost-after"
			failedReads := 0
			store.readHook = func(key string, result contract.ReadResult) contract.ReadResult {
				if key == store.desc.HeadKey && store.cas > baseline {
					failedReads++
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
				}
				return result
			}
			request := fixtureID(f.env.Domain, fmt.Sprintf("%s initial reservation unknown request", operation))
			var got PublicApplyResult
			kind := uint16(contract.OperationApplyDeclaration)
			switch operation {
			case "cleanup":
				kind = contract.OperationCleanOwnedFailureResidue
				got = engine.CleanupGenerated(ctx, request)
			case "retire":
				kind = contract.OperationRetireGeneratedGeneration
				got = engine.RetireGenerated(ctx, request, GeneratedRetirementRequest{DutyID: current.Generated.RetiringDutyID})
			default:
				got = engine.Apply(ctx, request, input)
			}
			engine.Close()
			store.casMode, store.readHook = "", nil
			creates, deletes := effects()
			if got.Result.Outcome != UnresolvedCommit || !got.Result.CommitMayHaveOccurred || failedReads == 0 || store.cas != baseline+1 || invocations.Load() != 0 || creates != beforeCreates || len(deletes) != len(beforeDeletes) {
				t.Fatal("initial reservation did not remain uncertain before first-send", got.Result, failedReads, store.cas-baseline, invocations.Load(), creates-beforeCreates, len(deletes)-len(beforeDeletes))
			}
			if got.RequestID != request || got.DomainID != f.env.Domain || got.OperationID.IsZero() || got.RequestIdentity.IsZero() || got.Payload != nil || len(got.Receipt) != 0 {
				t.Fatal("unknown reservation invented a terminal payload or lost established identities", got)
			}
			cold := f.open(t, ctx)
			work := mustSelectedGeneratedWork(t, cold)
			if work.parent == nil || work.parent.OperationID != got.OperationID || work.parent.RequestIdentityDigest != got.RequestIdentity {
				t.Fatal("lost reply did not name the exact actual committed parent")
			}
			g := got.Generated
			if g == nil || g.OperationKind != kind || g.StateResult != "commit-outcome-unknown" || g.CanonicalOutcome != contract.ReceiptCanonicalNotSelected || g.EffectSummary != contract.ReceiptEffectNoChange || g.EffectsAvailable || g.RelatedWorkAvailable || g.SummaryCountsAvailable || g.ReceiptObservation {
				t.Fatal("unknown reservation invented generated result availability", g)
			}
			if g.Effects != nil || g.Duties != nil || g.Hazards != nil || g.RelatedDutyIDs != nil || g.RelatedHazardIDs != nil || g.EffectsCommitment != nil || g.RelatedDutiesCommitment != nil || g.RelatedHazardsCommitment != nil || g.SummaryCounts != [contract.ReceiptSummaryCount]uint32{} || g.AcknowledgedCount != 0 || g.ConfirmedCount != 0 || g.UnknownCount != 0 {
				t.Fatal("unobserved candidate rows or counts escaped reservation", g)
			}
			if operation == "cleanup" {
				payload := got.Cleanup
				if payload == nil || payload.PredecessorRevisionID != beforeRevision || payload.RemainingWorkBasis.HeadRevisionID != beforeRevision || payload.RemainingWorkBasis.Snapshot != beforeRoot ||
					payload.Basis.Kind != GeneratedCleanupOwnedTarget || payload.Basis.SourceKind != contract.GeneratedHazardSupportKind || payload.Basis.SourceID != cleanupSource || payload.Basis.Target == nil || *payload.Basis.Target != cleanupTarget || payload.Basis.OriginalResult != nil ||
					!slices.Equal(payload.RemainingDutyIDs, cleanupBeforeIDs[0]) || !slices.Equal(payload.RemainingHazardIDs, cleanupBeforeIDs[1]) || !slices.Equal(payload.RemainingInboxIDs, cleanupBeforeIDs[2]) {
					t.Fatal("unknown cleanup reservation lost its complete exact predecessor payload", payload)
				}
				attempt, present := work.attempts[work.phase.FrontierAttemptID]
				if !present || attempt.record.State != contract.GeneratedEffectTransmitted || attempt.expected.Template.Action != contract.GeneratorActionDelete || attempt.expected.TargetResourceDigest != cleanupTarget.ResourceDigest || attempt.expected.Template.ResourceContractID != cleanupTarget.ResourceContractID ||
					payload.Basis.PlanGraphID != work.parent.PlanGraphID || payload.Basis.OriginalOperationID != got.OperationID || payload.Basis.OriginalAttemptID != attempt.record.AttemptID || payload.Basis.OriginalOwnerID != attempt.record.OwnerID || got.Result.RequestedRevision != cold.head.Core.Revision {
					t.Fatal("unknown cleanup reservation changed its exact committed delete identity")
				}
				commitment, err := GeneratedCleanupSiblingResults(got)
				if err != nil || commitment != payload.SiblingResults || commitment.Count != 1 || commitment.RootDigest.IsZero() {
					t.Fatal("unknown cleanup reservation lost its complete sibling commitment", commitment, err)
				}
				callbacks.AdmitProducer = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedProducerInput, contract.GeneratorImplementation, time.Time) (*InstalledGeneratedProducerCustody, error) {
					t.Fatal("cold cleanup continuation restored producer admission")
					return nil, contract.ErrRecord
				}
				continuation := installedGeneratedRetirementEngine(t, ctx, f, cold, callbacks)
				continued := continuation.ContinueGeneratedCleanup(ctx, testID("cleanup loss cold continuation"), GeneratedCleanupContinuationRequest{OperationID: got.OperationID})
				continuation.Close()
				afterCreates, afterDeletes := effects()
				if store.cas != baseline+1 || invocations.Load() != 0 || afterCreates != beforeCreates || !slices.Equal(afterDeletes, beforeDeletes) || continued.Result.Outcome != ObservedCurrent || !continued.Result.RequestedRevision.IsZero() || continued.Result.CommitMayHaveOccurred ||
					continued.OperationID != got.OperationID || continued.RequestIdentity != got.RequestIdentity || continued.Payload != nil || len(continued.Receipt) != 0 || continued.Generated == nil || continued.Generated.OperationKind != contract.OperationCleanOwnedFailureResidue || continued.Generated.StateResult != "effect-unknown" ||
					continued.Generated.CanonicalOutcome != contract.ReceiptCanonicalNotSelected || !continued.Generated.EffectsAvailable || !continued.Generated.RelatedWorkAvailable || !continued.Generated.SummaryCountsAvailable || len(continued.Generated.Effects) != 1 ||
					continued.Generated.Effects[0].Record != attempt.record || continued.Generated.Effects[0].Target == nil || *continued.Generated.Effects[0].Target != cleanupTarget || continued.Cleanup == nil || continued.Cleanup.Basis.SourceID != cleanupSource || continued.Cleanup.RemainingWorkBasis.HeadRevisionID != cold.head.Core.Revision || continued.Cleanup.RemainingWorkBasis.Snapshot != cold.head.Core.Root {
					t.Fatal("cold cleanup continuation changed the fixed work or restored first send", continued.Result, continued.Generated, continued.Cleanup)
				}
				commitment, err = GeneratedCleanupSiblingResults(continued)
				if err != nil || commitment != continued.Cleanup.SiblingResults {
					t.Fatal("cold cleanup observation lost its complete sibling commitment", err)
				}
			}
		})
	}
}

type generatedTerminalSelectionTracer struct {
	trace.Tracer
	end func()
}

func (t *generatedTerminalSelectionTracer) Start(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	ctx, span := t.Tracer.Start(ctx, name, opts...)
	if name == string(telemetry.OpCoreSelect) {
		return ctx, &generatedTerminalSelectionSpan{Span: span, end: t.end}
	}
	return ctx, span
}

type generatedTerminalSelectionSpan struct {
	trace.Span
	end func()
}

func (s *generatedTerminalSelectionSpan) End(opts ...trace.SpanEndOption) {
	s.Span.End(opts...)
	s.end()
}

// full_only: false
func TestInstalledGeneratedTerminalApplyOwnsFactsBeforeSelectionReturns(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	process, effects := configurationRecoveryLocalGeneratedProcess(t)
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	f.env.GeneratedProcess = process
	selected := f.selected
	declaration := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Epoch: 0, RetirementMode: contract.GeneratedRetirementManual,
		ConfigContractID: process.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(), CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent)}
	input := []ApplyEntryInput{{Name: "generated", Recipients: []contract.ID{selected.admission.recipient}, ValueSource: contract.Generated, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ConfidentialityClass: contract.Secret, Generated: &declaration}}
	store, ok := underlyingAdmittedMemoryStore(f.env.Store)
	if !ok {
		t.Fatal("fixture Store unavailable")
	}
	boundary, readsAtBoundary := false, 0
	var finalRevision contract.ID
	tracer := &generatedTerminalSelectionTracer{Tracer: noop.NewTracerProvider().Tracer("generated-terminal-selection-boundary")}
	tracer.end = func() {
		if boundary {
			return
		}
		store.mu.Lock()
		head, err := format.DecodeHead(store.objects[store.desc.HeadKey].Body)
		if err == nil && head.Generator != nil && head.Generator.Purpose == contract.GeneratorAuthorityFinal {
			key, keyErr := format.Key(store.desc.Prefix, head.Core.Root)
			root, rootErr := format.DecodeRoot(store.objects[key].Body)
			if keyErr == nil && rootErr == nil && root.Snapshot != selected.root.Snapshot && root.Generated.ActiveOwner.IsZero() && root.Generated.GeneratedCurrent == 1 {
				boundary, readsAtBoundary, finalRevision = true, store.reads, head.Core.Revision
			}
		}
		store.mu.Unlock()
		if boundary {
			cancel()
		}
	}
	ctx = telemetry.WithCapability(ctx, telemetry.NewCapabilityWithTracers(nil, nil, map[telemetry.Provider]trace.Tracer{telemetry.ProviderCore: tracer}))
	engine := installedGeneratedTestEngine(t, ctx, f, selected, input, currentApplyRecipients(selected.registry()), installedGeneratedTestCallbacks(t, f, process))
	got := engine.Apply(ctx, fixtureID(f.env.Domain, "terminal apply response cancellation"), input)
	engine.Close()
	creates, deletes := effects()
	if !boundary || ctx.Err() != context.Canceled || creates != 1 || deletes != 0 || finalRevision.IsZero() {
		t.Fatal("fixture did not reach exact successful terminal selection", boundary, ctx.Err(), creates, deletes)
	}
	if store.reads != readsAtBoundary {
		t.Fatal("terminal apply read Store after authenticated selection returned", store.reads-readsAtBoundary)
	}
	if got.Result.Outcome != ObservedCurrent || got.Result.Evidence != AuthenticatedClosure || got.Result.RequestedRevision != finalRevision || got.Result.ObservedRevision != finalRevision || got.Result.CommitMayHaveOccurred {
		t.Fatal("post-selection cancellation erased actual terminal apply result", got.Result)
	}
	if got.Generated == nil || got.Generated.StateResult != "success" || !got.Generated.SummaryCountsAvailable || len(got.Generated.Effects) != 1 || got.Payload == nil || got.Payload.RequestedRevisionID != finalRevision || got.Payload.ObservedRevisionID != finalRevision || got.Payload.PredecessorRevisionID.IsZero() || got.Payload.ChangedSubjects.Count == 0 {
		t.Fatal("post-selection cancellation erased complete owned terminal facts", got.Generated, got.Payload)
	}
	row, err := contract.InspectCompactMutationReceipt(got.Receipt)
	if err != nil || row.RequestedRevisionID != finalRevision || row.ObservedRevisionID != finalRevision || row.OperationID != got.OperationID || row.RequestIdentityDigest != got.RequestIdentity {
		t.Fatal("terminal response lost its exact receipt", err, row)
	}
}

type installedGeneratedCheckpointFixture struct {
	f         installedApplyTestFixture
	selected  *StateSession
	current   contract.ValueEntry
	input     []ApplyEntryInput
	callbacks *GeneratedApplyInstallation
	effects   func() (int, []string)
}

func newInstalledGeneratedCheckpointFixture(t *testing.T, ctx context.Context, operation string) installedGeneratedCheckpointFixture {
	t.Helper()
	var x installedGeneratedCheckpointFixture
	if operation == "retire" {
		x.f, x.selected, x.current, x.effects = installedGeneratedRetirementFixture(t, ctx, "acknowledged")
		x.callbacks = installedGeneratedRetirementCallbacks(t, x.f, x.f.env.GeneratedProcess)
		return x
	}
	process, count := configurationRecoveryLocalGeneratedProcess(t)
	x.f = newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	x.f.env.GeneratedProcess, x.selected = process, x.f.selected
	x.effects = func() (int, []string) { creates, deletes := count(); return int(creates), make([]string, deletes) }
	declaration := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Epoch: 0, RetirementMode: contract.GeneratedRetirementManual,
		ConfigContractID: process.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(), CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent)}
	x.input = []ApplyEntryInput{{Name: "generated", Recipients: []contract.ID{x.selected.admission.recipient}, ValueSource: contract.Generated, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ConfidentialityClass: contract.Secret, Generated: &declaration}}
	x.callbacks = installedGeneratedTestCallbacks(t, x.f, process)
	return x
}

func (x installedGeneratedCheckpointFixture) invoke(t *testing.T, ctx context.Context, operation string, continuation contract.ID) PublicApplyResult {
	t.Helper()
	var engine *InstalledApply
	if operation == "retire" {
		engine = installedGeneratedRetirementEngine(t, ctx, x.f, x.selected, x.callbacks)
	} else {
		engine = installedGeneratedTestEngine(t, ctx, x.f, x.selected, x.input, currentApplyRecipients(x.selected.registry()), x.callbacks)
	}
	defer engine.Close()
	request := fixtureID(x.f.env.Domain, "checkpoint test invocation "+operation)
	if !continuation.IsZero() {
		if operation == "retire" {
			return engine.ContinueGeneratedRetirement(ctx, request, GeneratedRetirementContinuationRequest{OperationID: continuation})
		}
		return engine.Continue(ctx, request, continuation)
	}
	if operation == "retire" {
		return engine.RetireGenerated(ctx, request, GeneratedRetirementRequest{DutyID: x.current.Generated.RetiringDutyID})
	}
	return engine.Apply(ctx, request, x.input)
}

// full_only: false
func TestInstalledGeneratedPreparationFailurePreservesActualSelection(t *testing.T) {
	for _, operation := range []string{"apply", "retire"} {
		for _, stage := range []string{"reservation", "adoption"} {
			for _, fault := range []string{"cancel", "support-read", "sign"} {
				t.Run(operation+"/"+stage+"/"+fault, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
					defer cancel()
					x := newInstalledGeneratedCheckpointFixture(t, ctx, operation)
					store, ok := underlyingAdmittedMemoryStore(x.f.env.Store)
					if !ok {
						t.Fatal("fixture Store unavailable")
					}
					trust, ok := underlyingAdmittedFixtureTrust(x.f.env.Trust)
					if !ok {
						t.Fatal("fixture Trust unavailable")
					}
					purpose := contract.GeneratorAuthorityRecord
					if stage == "reservation" {
						purpose = contract.GeneratorAuthorityReservation
						if operation == "retire" {
							purpose = contract.GeneratorAuthorityRetireReserve
						}
					}
					var boundaryRevision contract.ID
					boundarySigns, failedReads := 0, 0
					tracer := &generatedTerminalSelectionTracer{Tracer: noop.NewTracerProvider().Tracer("generated-preparation-boundary")}
					tracer.end = func() {
						if !boundaryRevision.IsZero() {
							return
						}
						store.mu.Lock()
						head, err := format.DecodeHead(store.objects[store.desc.HeadKey].Body)
						if err != nil || head.Generator == nil || head.Generator.Purpose != purpose {
							store.mu.Unlock()
							return
						}
						key, keyErr := format.Key(store.desc.Prefix, head.Core.Root)
						root, rootErr := format.DecodeRoot(store.objects[key].Body)
						if keyErr != nil || rootErr != nil || root.Generated.ActiveOwner.IsZero() {
							store.mu.Unlock()
							return
						}
						boundaryRevision, boundarySigns = head.Core.Revision, trust.signs
						if fault == "support-read" {
							keys := make(map[string]bool)
							for _, ref := range root.RequiredSupport {
								key, err := format.Key(store.desc.Prefix, ref)
								if err != nil {
									store.mu.Unlock()
									t.Fatal(err)
								}
								keys[key] = true
							}
							store.readHook = func(key string, r contract.ReadResult) contract.ReadResult {
								if keys[key] {
									failedReads++
									return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
								}
								return r
							}
						}
						store.mu.Unlock()
						switch fault {
						case "cancel":
							cancel()
						case "sign":
							trust.SetUnavailable(true)
						}
					}
					ctx = telemetry.WithCapability(ctx, telemetry.NewCapabilityWithTracers(nil, nil, map[telemetry.Provider]trace.Tracer{telemetry.ProviderCore: tracer}))
					beforeCreates, beforeDeletes := x.effects()
					got := x.invoke(t, ctx, operation, contract.ID{})
					store.readHook = nil
					trust.SetUnavailable(false)
					creates, deletes := x.effects()
					if boundaryRevision.IsZero() || fault == "support-read" && failedReads == 0 || fault == "sign" && trust.signs <= boundarySigns {
						t.Fatal("fixture did not exercise a later preparation failure", boundaryRevision, failedReads, trust.signs-boundarySigns)
					}
					wantCreates, wantDeletes := beforeCreates, beforeDeletes
					if operation == "apply" {
						wantCreates++
					} else {
						wantDeletes = append(wantDeletes, "00000000000000000000000000000001")
					}
					if creates != wantCreates || !slices.Equal(deletes, wantDeletes) {
						t.Fatal("later preparation repeated an effect", creates, deletes)
					}
					if got.Result.Outcome != ObservedCurrent || got.Result.Evidence != AuthenticatedClosure || got.Result.RequestedRevision != boundaryRevision || got.Result.ObservedRevision != boundaryRevision || got.Result.CommitMayHaveOccurred {
						t.Fatal("later preparation replaced the actual invocation selection", got.Result, boundaryRevision)
					}
					if got.Generated == nil || !got.Generated.EffectsAvailable || !got.Generated.SummaryCountsAvailable || len(got.Generated.Effects) != 1 || got.Payload != nil || len(got.Receipt) != 0 {
						t.Fatal("later preparation discarded owned selected facts or invented terminal payload", got.Generated, got.Payload)
					}
					wantState := uint8(contract.GeneratedEffectTransmitted)
					if stage == "adoption" {
						wantState = contract.GeneratedEffectSucceeded
					}
					if got.Generated.Effects[0].Record.State != wantState {
						t.Fatal("checkpoint facts differ from exact selected stage", got.Generated.Effects[0].Record.State, wantState)
					}
					if len(got.Diagnostics) != 1 || got.Diagnostics[0].Outcome != contract.DiagnosticUnable || got.Diagnostics[0].Subject.Kind != contract.SubjectObservation || !slices.Equal(got.Diagnostics[0].Path, []contract.DiagnosticField{contract.FieldPresence}) {
						t.Fatal("later failure lost its closed diagnostic", got.Diagnostics)
					}
					switch got.Diagnostics[0].Reason {
					case contract.ReasonCancelled, contract.ReasonExpired, contract.ReasonEvidenceUnavailable, contract.ReasonSelectedObjectUnavailable, contract.ReasonSelectedRelationInvalid, contract.ReasonInvalidInput:
					default:
						t.Fatal("preparation failure exposed an unqualified diagnostic reason", got.Diagnostics[0].Reason)
					}
				})
			}
		}
	}
}

// full_only: false
func TestInstalledGeneratedLaterContentionReplacesSelectionCheckpoint(t *testing.T) {
	for _, operation := range []string{"apply", "retire"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			x := newInstalledGeneratedCheckpointFixture(t, ctx, operation)
			store, ok := underlyingAdmittedMemoryStore(x.f.env.Store)
			if !ok {
				t.Fatal("fixture Store unavailable")
			}
			purpose := contract.GeneratorAuthorityReservation
			if operation == "retire" {
				purpose = contract.GeneratorAuthorityRetireReserve
			}
			var reservation contract.ID
			casAtBoundary := 0
			tracer := &generatedTerminalSelectionTracer{Tracer: noop.NewTracerProvider().Tracer("generated-later-contention")}
			tracer.end = func() {
				if !reservation.IsZero() {
					return
				}
				store.mu.Lock()
				defer store.mu.Unlock()
				head, err := format.DecodeHead(store.objects[store.desc.HeadKey].Body)
				if err != nil || head.Generator == nil || head.Generator.Purpose != purpose {
					return
				}
				reservation, casAtBoundary = head.Core.Revision, store.cas
				// A changed token on the same authenticated body is a real competing
				// precondition. The next selection must retain its own contention.
				store.put(store.desc.HeadKey, bytes.Clone(store.objects[store.desc.HeadKey].Body))
			}
			ctx = telemetry.WithCapability(ctx, telemetry.NewCapabilityWithTracers(nil, nil, map[telemetry.Provider]trace.Tracer{telemetry.ProviderCore: tracer}))
			got := x.invoke(t, ctx, operation, contract.ID{})
			if reservation.IsZero() || store.cas != casAtBoundary+1 || got.Result.Outcome != Contention || got.Result.RequestedRevision.IsZero() || got.Result.RequestedRevision == reservation || got.Result.ObservedRevision != reservation || got.Result.CommitMayHaveOccurred {
				t.Fatal("actual later CAS did not replace prior selection checkpoint", got.Result, reservation, store.cas-casAtBoundary)
			}
			if got.Generated == nil || got.Generated.CanonicalOutcome != contract.ReceiptCanonicalNotSelected || got.Generated.StateResult != "contention" || got.Payload != nil || len(got.Receipt) != 0 {
				t.Fatal("later contention promoted a candidate or lost before facts", got.Generated, got.Payload)
			}
		})
	}
}

// full_only: false
func TestInstalledGeneratedPassiveContinuationDoesNotOwnEarlierSelection(t *testing.T) {
	for _, operation := range []string{"apply", "retire"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			x := newInstalledGeneratedCheckpointFixture(t, ctx, operation)
			x.callbacks.AdmitAdoption = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedAdoptionInput, time.Time) (*InstalledGeneratedCustody, error) {
				return nil, contract.ErrRecord
			}
			stopped := x.invoke(t, ctx, operation, contract.ID{})
			if stopped.OperationID.IsZero() {
				t.Fatal("fixture did not establish accepted operation", stopped.Result)
			}
			x.selected = x.f.open(t, ctx)
			store, ok := underlyingAdmittedMemoryStore(x.f.env.Store)
			if !ok {
				t.Fatal("fixture Store unavailable")
			}
			beforeCAS := store.cas
			creates, deletes := x.effects()
			got := x.invoke(t, ctx, operation, stopped.OperationID)
			if store.cas != beforeCAS || got.Result.Outcome == ObservedCurrent || got.Result.Outcome == Unchanged || !got.Result.RequestedRevision.IsZero() || got.Payload != nil || len(got.Receipt) != 0 {
				t.Fatal("passive continuation claimed an earlier invocation's CAS", got.Result, store.cas-beforeCAS)
			}
			if got.Result.Outcome != AdmissionRefused || got.Generated == nil || got.Generated.StateResult != "refused" || got.Generated.CanonicalOutcome != contract.ReceiptCanonicalNotSelected || !got.Generated.EffectsAvailable || !got.Generated.RelatedWorkAvailable || !got.Generated.SummaryCountsAvailable {
				t.Fatal("passive continuation state does not match its refusal", got.Result, got.Generated)
			}
			c, d := x.effects()
			if c != creates || !slices.Equal(d, deletes) {
				t.Fatal("passive continuation restored provider rights", c, d)
			}
		})
	}
}

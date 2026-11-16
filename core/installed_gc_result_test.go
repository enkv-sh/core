package core

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"enkv.sh/core/contract"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

// full_only: false
func TestInstalledGCCloseReportsOnlyResourceFailure(t *testing.T) {
	for _, sourceFailure := range []bool{false, true} {
		for _, closeFailure := range []bool{false, true} {
			t.Run(fmt.Sprintf("source=%v/close=%v", sourceFailure, closeFailure), func(t *testing.T) {
				state, store, input, _, encoded := gcExecutionFixture(t)
				ctx := gcReadContext(t)
				operational, cleanup := errors.New("private operation cause"), errors.New("private close cause")
				armed := false
				input.CheckSource = func(context.Context) error {
					if armed && sourceFailure {
						return operational
					}
					return nil
				}
				reader, err := NewInstalledCapacityReader(input)
				if err != nil {
					t.Fatal(err)
				}
				closes := 0
				engine, err := NewInstalledGC(GCInstallation{Reader: reader, CompositionID: state.admission.composition, ConstructMutation: func(context.Context) (GCMutationResources, error) {
					return GCMutationResources{Store: store, Trust: testtrust.New(t, contract.GCP, state.admission.trust), Close: func() error {
						closes++
						if closeFailure {
							return cleanup
						}
						return nil
					}}, operational
				}})
				if err != nil {
					t.Fatal(err)
				}
				armed = true
				out := engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: gcTestID("separate causes"), EncodedPlan: encoded})
				if !errors.Is(engine.OperationError(), operational) {
					t.Fatal("operation cause was not available before close")
				}
				err = engine.Close()
				wantClose := closeFailure && !sourceFailure
				if errors.Is(err, operational) || errors.Is(err, cleanup) != wantClose || (err != nil) != wantClose || engine.Close() != err {
					t.Fatal("operation failure became resource close failure", out.StateResult, err)
				}
				if !errors.Is(engine.OperationError(), operational) {
					t.Fatal("resource close erased retained operation cause")
				}
				wantCloses := 1
				if sourceFailure {
					wantCloses = 0
				}
				if closes != wantCloses || len(store.deletes) != 0 {
					t.Fatal("failure changed resource ownership or dispatched deletion", closes, store.deletes)
				}
			})
		}
	}
	t.Run("completed-with-close-error", func(t *testing.T) {
		state, store, input, _, encoded := gcExecutionFixture(t)
		reader, err := NewInstalledCapacityReader(input)
		if err != nil {
			t.Fatal(err)
		}
		cleanup := errors.New("private completion close cause")
		closes := 0
		engine, err := NewInstalledGC(GCInstallation{Reader: reader, CompositionID: state.admission.composition, ConstructMutation: func(context.Context) (GCMutationResources, error) {
			return GCMutationResources{Store: store, Trust: testtrust.New(t, contract.GCP, state.admission.trust), Close: func() error { closes++; return cleanup }}, nil
		}})
		if err != nil {
			t.Fatal(err)
		}
		out := engine.ApplyPlan(gcReadContext(t), GCApplyPlanRequest{RequestNonce: gcTestID("completed resource close"), EncodedPlan: encoded})
		if out.Result.Outcome != ObservedCurrent || out.StateResult != "success" || engine.OperationError() != nil {
			t.Fatal("successful GC control did not complete", out.Result, out.StateResult, engine.OperationError())
		}
		firstClose := engine.Close()
		if !errors.Is(firstClose, cleanup) || !errors.Is(engine.Close(), cleanup) || closes != 1 || engine.OperationError() != nil {
			t.Fatal("successful operation lost separate idempotent resource error", closes)
		}
	})
}

// full_only: false
func TestInstalledGCSourceCauseSurvivesClose(t *testing.T) {
	for _, route := range []string{"apply", "continue"} {
		for _, stage := range []string{"before-guard", "after-factory"} {
			t.Run(route+"/"+stage, func(t *testing.T) {
				state, store, input, plan, encoded := gcExecutionFixture(t)
				ctx := gcReadContext(t)
				if route == "continue" && stage == "after-factory" {
					reader, err := NewInstalledCapacityReader(input)
					if err != nil {
						t.Fatal(err)
					}
					proof, result := reader.ValidateGCPlan(ctx, encoded)
					if proof == nil || !proof.consume(ctx) {
						t.Fatal("real plan validation setup", result)
					}
					progress, err := gcInitialProgress(plan)
					if err != nil {
						t.Fatal(err)
					}
					candidate, result := state.prepareGCPhase(ctx, plan, gcTestID("cause-setup-admission"), contract.GCSelect, &progress)
					if candidate == nil {
						t.Fatal("real GC selection setup", result)
					}
					candidate, result = state.persistCandidate(ctx, candidate, testtrust.New(t, contract.GCP, state.admission.trust))
					if candidate == nil {
						t.Fatal("real GC persistence setup", result)
					}
					selected := state.selectGCCandidate(ctx, candidate)
					reader.Close()
					if !selected.confirmed {
						t.Fatal("real GC selected setup", selected.result)
					}
				}
				sentinel := errors.New("retained private GC source cause")
				armed := false
				sourceCalls := 0
				input.CheckSource = func(context.Context) error {
					sourceCalls++
					if armed {
						armed = false
						return sentinel
					}
					return nil
				}
				reader, err := NewInstalledCapacityReader(input)
				if err != nil {
					t.Fatal(err)
				}
				factoryCalls := 0
				engine, err := NewInstalledGC(GCInstallation{Reader: reader, CompositionID: state.admission.composition, ConstructMutation: func(context.Context) (GCMutationResources, error) {
					factoryCalls++
					if stage == "after-factory" {
						armed = true
					}
					return GCMutationResources{Store: store, Trust: testtrust.New(t, contract.GCP, state.admission.trust), Close: func() error { return nil }}, nil
				}})
				if err != nil {
					t.Fatal(err)
				}
				if stage == "before-guard" {
					armed = true
				}
				var result PublicGCResult
				if route == "apply" {
					result = engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: gcTestID("source-apply"), EncodedPlan: encoded})
				} else {
					result = engine.Continue(ctx, GCContinueRequest{RequestNonce: gcTestID("source-continue"), OperationID: plan.OperationID})
				}
				operationErr := engine.OperationError()
				closeErr := engine.Close()
				if closeErr != nil || !errors.Is(operationErr, sentinel) || !errors.Is(engine.OperationError(), sentinel) {
					t.Fatal("GC lost the separate original source cause", route, stage, result.StateResult, sourceCalls, operationErr, closeErr)
				}
				if stage == "before-guard" && factoryCalls != 0 {
					t.Fatal("source refusal constructed mutation", factoryCalls)
				}
				if len(store.deletes) != 0 {
					t.Fatal("source failure dispatched deletion", store.deletes)
				}
			})
		}
	}
}

func gcSuccessfulResultFixture(t *testing.T) PublicGCResult {
	t.Helper()
	state := generatedEmptyPredecessorForFamily(t, contract.GCP)
	plan := gcTestPlan(t, state, "result-validation")
	out := gcResultForPlan(PublicGCResult{Operation: GCApplyOperation, RequestID: gcTestID("result-request")}, plan, PublicObservation{DomainID: state.root.Domain, HeadRevisionID: state.head.Core.Revision, SnapshotID: state.root.Snapshot, RootDigest: state.head.Core.Root.Digest})
	out.Result = state.observed(ObservedCurrent)
	out.Result.RequestedRevision = out.Result.ObservedRevision
	out.StateResult = "success"
	out.Payload.Closed = true
	out.Payload.RemainingCount = 0
	out.Payload.ProgressOrdinal = 3
	out.Payload.Targets[0].Selected = contract.GCTargetProgress{Consumed: 1, Disposition: contract.GCTargetAbsent, EvidenceDigest: gcTestID("result-absence")}
	if err := RefreshGCResult(&out); err != nil {
		t.Fatal("complete result fixture", err)
	}
	return out
}

// full_only: false
func TestPublicGCResultValidationUsesClosedOutcomeAndEvidence(t *testing.T) {
	refusal := PublicGCResult{Operation: GCApplyOperation, Result: refused(AdmissionInvalid), StateResult: "refused"}
	if err := refusal.Validate(); err != nil {
		t.Error("unbound zero-nonce refusal rejected", err)
	}
	valid := gcSuccessfulResultFixture(t)
	if err := valid.Validate(); err != nil {
		t.Fatal("valid complete result rejected", err)
	}
	for _, damage := range []string{"nil-unknown-state", "nil-impossible-outcome", "unknown-state", "absent-no-evidence", "nonabsent-evidence", "commit-uncertain", "no-evidence", "no-observed-revision", "no-observed-snapshot", "no-observation", "invalid-target", "invalid-target-length", "zero-operation", "wrong-domain", "invalid-vector", "candidate-index", "candidate-duplicate"} {
		t.Run(damage, func(t *testing.T) {
			out := gcSuccessfulResultFixture(t)
			switch damage {
			case "nil-unknown-state":
				out.Payload = nil
				out.StateResult = "arbitrary"
			case "nil-impossible-outcome":
				out.Payload = nil
				out.StateResult = "refused"
				out.Result = Result{Outcome: ObservedCurrent}
			case "unknown-state":
				out.StateResult = "arbitrary"
			case "absent-no-evidence":
				out.Payload.Targets[0].Selected.EvidenceDigest = contract.ID{}
			case "nonabsent-evidence":
				out.StateResult = "gc-partial-garbage"
				out.Payload.RemainingCount = 1
				out.Payload.Targets[0].Selected.Disposition = contract.GCTargetUnknown
			case "commit-uncertain":
				out.Result.CommitMayHaveOccurred = true
			case "no-evidence":
				out.Result.Evidence = NoEvidence
			case "no-observed-revision":
				out.Result.ObservedRevision = contract.ID{}
			case "no-observed-snapshot":
				out.Result.ObservedSnapshotID = contract.ID{}
			case "no-observation":
				out.Payload.Observation = PublicObservation{}
			case "invalid-target":
				out.Payload.Targets[0].Object.ObjectID = contract.ID{}
			case "invalid-target-length":
				out.Payload.Targets[0].Length = contract.StoreObjectLimit(out.Payload.Targets[0].Object) + 1
			case "zero-operation":
				out.OperationID = contract.ID{}
			case "wrong-domain":
				out.DomainID = gcTestID("other-result-domain")
			case "invalid-vector":
				out.Payload.TargetsDescriptor.Digest = contract.ID{}
			case "candidate-index":
				out.Payload.Candidates[0].TargetIndex = 1
			case "candidate-duplicate":
				out.Payload.Candidates = append(out.Payload.Candidates, out.Payload.Candidates[0])
			}
			if gcValidateResult(out) == nil {
				t.Fatal("invalid GC result passed structural validation", damage)
			}
			if out.Validate() == nil {
				t.Fatal("invalid GC result admitted", damage)
			}
		})
	}
}

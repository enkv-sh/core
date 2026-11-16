package core

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// full_only: false
func TestApplyPublicationLateInterruptionKeepsCompletedApply(t *testing.T) {
	t.Run("unavailable-required-observation", func(t *testing.T) {
		apply := PublicApplyResult{Result: Result{Outcome: ObservedCurrent}, Diagnostics: []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonEvidenceUnavailable}}}
		if applyPublicationComplete(apply) {
			t.Fatal("genuinely unavailable required observation was treated as completed apply")
		}
	})
	for _, generated := range []bool{false, true} {
		for _, expired := range []bool{false, true} {
			t.Run(fmt.Sprintf("generated=%v/expired=%v", generated, expired), func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				if expired {
					cancel()
					ctx, cancel = context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
				} else {
					cancel()
				}
				defer cancel()
				apply := PublicApplyResult{Result: Result{Outcome: ObservedCurrent, Evidence: AuthenticatedClosure, RequestedRevision: contract.ID{1}, ObservedRevision: contract.ID{1}, ObservedSnapshotID: contract.ID{2}}}
				if generated {
					apply.Generated = &GeneratedInvocationResult{OperationKind: contract.OperationApplyDeclaration, CanonicalOutcome: contract.ReceiptCanonicalSelected, StateResult: "success", EffectSummary: contract.ReceiptEffectComplete}
				}
				appendApplyInterruptionDiagnostic(ctx, &apply)
				out := (&InstalledApply{}).finishApplyPublication(ctx, apply, contract.ID{3}, nil, nil, &applyPublicationCapture{})
				want := "selection-unavailable"
				if expired {
					want = "deadline-expired"
				}
				if !reflect.DeepEqual(out.Apply, apply) || out.Publication.Stage != "unstarted" || out.Publication.Reason != want || out.Publication.Result != nil {
					t.Fatal("late interruption rewrote completed apply or publication stage", out.Publication)
				}
				if generated {
					apply.Generated = &GeneratedInvocationResult{OperationKind: contract.OperationApplyDeclaration, CanonicalOutcome: contract.ReceiptCanonicalSelected, StateResult: "retirement-pending", EffectSummary: contract.ReceiptEffectPending}
					out = (&InstalledApply{}).finishApplyPublication(ctx, apply, contract.ID{3}, nil, nil, &applyPublicationCapture{})
					if out.Publication.Stage != "unstarted" || out.Publication.Reason != "apply-incomplete" || !reflect.DeepEqual(out.Apply, apply) {
						t.Fatal("interruption hid genuinely incomplete original work")
					}
				}
			})
		}
	}
}

// full_only: false
func TestApplyPublicationCompletionGatePreservesIncompleteOriginalWork(t *testing.T) {
	for _, test := range []struct {
		name      string
		outcome   Outcome
		state     string
		effect    uint16
		canonical uint8
		complete  bool
	}{
		{name: "ordinary selected", outcome: ObservedCurrent, complete: true},
		{name: "ordinary unchanged", outcome: Unchanged, complete: true},
		{name: "refused", outcome: AdmissionRefused},
		{name: "contention", outcome: Contention},
		{name: "unknown commit", outcome: UnresolvedCommit},
		{name: "unavailable", outcome: EvidenceUnavailable},
		{name: "generated success", outcome: ObservedCurrent, state: "success", effect: contract.ReceiptEffectComplete, canonical: contract.ReceiptCanonicalSelected, complete: true},
		{name: "normal generated support with no original effect work", outcome: ObservedCurrent, state: "success", effect: contract.ReceiptEffectNoChange, canonical: contract.ReceiptCanonicalSelected, complete: true},
		{name: "generated exact completion", outcome: ObservedCurrent, state: "exact-resume", effect: contract.ReceiptEffectComplete, canonical: contract.ReceiptCanonicalSelected, complete: true},
		{name: "canonical selected retirement pending", outcome: ObservedCurrent, state: "retirement-pending", effect: contract.ReceiptEffectPending, canonical: contract.ReceiptCanonicalSelected},
		{name: "canonical selected retirement unknown", outcome: ObservedCurrent, state: "retirement-pending", effect: contract.ReceiptEffectUnknown, canonical: contract.ReceiptCanonicalSelected},
		{name: "canonical selected terminal failure", outcome: ObservedCurrent, state: "effect-terminal-failure", effect: contract.ReceiptEffectFailed, canonical: contract.ReceiptCanonicalSelected},
		{name: "canonical selected mixed terminal", outcome: ObservedCurrent, state: "effect-terminal-failure", effect: contract.ReceiptEffectMixedTerminal, canonical: contract.ReceiptCanonicalSelected},
		{name: "generated pending", outcome: ObservedCurrent, state: "effect-pending", effect: contract.ReceiptEffectPending},
		{name: "generated partial", outcome: ObservedCurrent, state: "effect-partial", effect: contract.ReceiptEffectPartial},
		{name: "generated unknown", outcome: ObservedCurrent, state: "effect-unknown", effect: contract.ReceiptEffectUnknown},
		{name: "success token cannot hide pending work", outcome: ObservedCurrent, state: "success", effect: contract.ReceiptEffectPending, canonical: contract.ReceiptCanonicalSelected},
		{name: "effect completion cannot select canonical result", outcome: ObservedCurrent, state: "success", effect: contract.ReceiptEffectComplete},
		{name: "future generated state", outcome: ObservedCurrent, state: "future-success", effect: contract.ReceiptEffectComplete, canonical: contract.ReceiptCanonicalSelected},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := PublicApplyResult{Result: Result{Outcome: test.outcome}}
			if test.state != "" {
				result.Generated = &GeneratedInvocationResult{OperationKind: contract.OperationApplyDeclaration, StateResult: test.state, EffectSummary: test.effect, CanonicalOutcome: test.canonical}
			}
			if result.Generated != nil {
				result.Generated.Duties = []GeneratedDutyFact{{Record: contract.GeneratedDutyRecord{DutyID: contract.ID{90}}}}
				result.Generated.Hazards = []GeneratedHazardFact{{Record: contract.GeneratedHazardRecord{HazardID: contract.ID{91}}}}
			}
			if got := applyPublicationComplete(result); got != test.complete {
				t.Fatalf("completion=%t, want %t", got, test.complete)
			}
		})
	}
}

// full_only: false
func TestApplyPublicationInvocationReleaseWaitsForPublication(t *testing.T) {
	disposed := make(chan struct{})
	engine := &InstalledApply{installation: ApplyInstallation{CloseInstalled: func() { close(disposed) }}}
	capture := &applyPublicationCapture{}
	_, done, admitted := engine.beginApplyInvocation(capture)
	if !admitted || done == nil {
		t.Fatal("combined invocation did not acquire its owner")
	}
	engine.endApplyInvocation(done, capture)
	engine.mu.Lock()
	active := engine.activeDone
	engine.mu.Unlock()
	if active != done {
		t.Fatal("apply return released the route before publication")
	}
	if _, _, admitted := engine.beginApplyInvocation(nil); admitted {
		t.Fatal("plain apply overlapped the combined invocation")
	}
	closed := make(chan struct{})
	go func() {
		engine.Close()
		close(closed)
	}()
	select {
	case <-disposed:
		t.Fatal("Close disposed the route during the publication stage")
	default:
	}
	capture.close()
	capture.close()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not join the released combined invocation")
	}
	select {
	case <-done:
	default:
		t.Fatal("combined invocation did not release its completion channel")
	}
	select {
	case <-disposed:
	default:
		t.Fatal("Close did not dispose the installed route")
	}
	if _, _, admitted := (&InstalledApply{}).beginApplyInvocation(capture); admitted {
		t.Fatal("a closed capture acquired another invocation")
	}
}

// full_only: false
func TestPlainApplyInvocationReleasesAtApplyReturn(t *testing.T) {
	engine := &InstalledApply{}
	_, done, admitted := engine.beginApplyInvocation(nil)
	if !admitted || done == nil {
		t.Fatal("plain invocation did not acquire its owner")
	}
	engine.endApplyInvocation(done, nil)
	select {
	case <-done:
	default:
		t.Fatal("plain apply retained its invocation after return")
	}
	engine.mu.Lock()
	active := engine.activeDone
	engine.mu.Unlock()
	if active != nil {
		t.Fatal("plain apply retained an active owner")
	}
	if _, _, admitted := engine.beginApplyInvocation(&applyPublicationCapture{}); admitted {
		t.Fatal("a used installed apply acquired another invocation")
	}
}

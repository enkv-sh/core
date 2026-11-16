package core

import (
	"testing"
	"unsafe"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedCanonicalSelectionProofFixedLayout(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 || unsafe.Sizeof(generatedCanonicalSelectionProof{}) != 232 || unsafe.Sizeof(GeneratedInvocationResult{}) != 488 {
		t.Fatal("canonical selection owned fixed layout changed")
	}
}

// full_only: false
func TestGeneratedCanonicalSelectionRejectsUnboundPublicFacts(t *testing.T) {
	domain, operation, request := generatedVectorID(11), generatedVectorID(12), generatedVectorID(13)
	naked := &GeneratedInvocationResult{OperationKind: contract.OperationApplyDeclaration, CanonicalOutcome: contract.ReceiptCanonicalSelected, StateResult: "contention"}
	if naked.HasObservedCanonicalSelection(domain, operation, request) {
		t.Fatal("public scalar established selection provenance")
	}
	generatedInvocationStopped(naked, Result{Outcome: Contention})
	if naked.CanonicalOutcome != contract.ReceiptCanonicalNotSelected {
		t.Fatal("naked selected scalar survived stop")
	}
	state, work, _, _ := generatedInvocationFinalCaptureFixture(t)
	scope, err := generatedCurrentResultScope(t.Context(), state, work)
	if err != nil {
		t.Fatal(err)
	}
	before, err := generatedInvocationFacts(t.Context(), work, scope, scope.Effects, scope.Duties, scope.Hazards)
	if err != nil {
		t.Fatal(err)
	}
	if before.HasObservedCanonicalSelection(state.root.Domain, scope.OperationID, scope.RequestIdentity) {
		t.Fatal("pre-anchor effects established canonical selection")
	}
}

// full_only: false
func TestGeneratedCanonicalSelectionProofRejectsIdentityDamage(t *testing.T) {
	domain, operation, request := generatedVectorID(21), generatedVectorID(22), generatedVectorID(23)
	subjects, err := contract.ChangedSubjectDescriptor(nil)
	if err != nil {
		t.Fatal(err)
	}
	access, err := contract.AccessChangeDescriptor(domain, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The installed component test establishes the factory authority. This pure
	// predicate table checks each bound coordinate and the public header.
	base := GeneratedInvocationResult{OperationKind: contract.OperationApplyDeclaration, CanonicalOutcome: contract.ReceiptCanonicalSelected, canonicalSelection: generatedCanonicalSelectionProof{kind: contract.OperationApplyDeclaration, domain: domain, operation: operation, requestIdentity: request, selectionPhase: generatedVectorID(24), changedSubjects: subjects, changedAccess: access}}
	if !base.HasObservedCanonicalSelection(domain, operation, request) {
		t.Fatal("matching private proof rejected")
	}
	for _, name := range []string{"domain", "operation", "request", "kind", "proof-kind", "anchor", "subjects", "access", "receipt", "scalar"} {
		t.Run(name, func(t *testing.T) {
			damaged := base
			switch name {
			case "domain":
				damaged.canonicalSelection.domain = generatedVectorID(25)
			case "operation":
				damaged.canonicalSelection.operation = generatedVectorID(26)
			case "request":
				damaged.canonicalSelection.requestIdentity = generatedVectorID(27)
			case "kind":
				damaged.OperationKind = contract.OperationCleanOwnedFailureResidue
			case "proof-kind":
				damaged.canonicalSelection.kind = contract.OperationRotateValueEntryValue
			case "anchor":
				damaged.canonicalSelection.selectionPhase = contract.ID{}
			case "subjects":
				damaged.canonicalSelection.changedSubjects.Digest = contract.ID{}
			case "access":
				damaged.canonicalSelection.changedAccess.Digest = contract.ID{}
			case "receipt":
				damaged.ReceiptObservation = true
			case "scalar":
				damaged.CanonicalOutcome = contract.ReceiptCanonicalNotSelected
			}
			if damaged.HasObservedCanonicalSelection(domain, operation, request) {
				t.Fatal("damaged proof crossed original invocation identity")
			}
		})
	}
}

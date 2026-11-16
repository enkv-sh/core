package core

import "enkv.sh/core/contract"

// Only authenticated active Parent/Phase capture creates this fixed proof.
// It retains no selected state, graph, record bytes, or execution authority.
type generatedCanonicalSelectionProof struct {
	kind                                               uint16
	domain, operation, requestIdentity, selectionPhase contract.ID
	changedSubjects, changedAccess                     contract.GeneratorDescriptor
}

// HasObservedCanonicalSelection checks Core-owned proof of this original
// apply successor. A later operational CAS result cannot undo that selection.
func (g *GeneratedInvocationResult) HasObservedCanonicalSelection(domainID, operationID, requestIdentity contract.ID) bool {
	if g == nil || g.CanonicalOutcome != contract.ReceiptCanonicalSelected || g.ReceiptObservation {
		return false
	}
	p := g.canonicalSelection
	return (p.kind == contract.OperationApplyDeclaration || p.kind == contract.OperationRotateValueEntryValue) && g.OperationKind == p.kind &&
		!domainID.IsZero() && !operationID.IsZero() && !requestIdentity.IsZero() && p.domain == domainID && p.operation == operationID && p.requestIdentity == requestIdentity &&
		!p.selectionPhase.IsZero() && p.changedSubjects.Valid() && p.changedAccess.Valid()
}

func generatedCanonicalSelection(work *generatedSelection, scope generatedInvocationResultScope) (generatedCanonicalSelectionProof, error) {
	var proof generatedCanonicalSelectionProof
	if !generatedSelectionAnchored(work) || scope.OperationID != work.parent.OperationID ||
		scope.OperationKind != contract.OperationApplyDeclaration && scope.OperationKind != contract.OperationRotateValueEntryValue {
		return proof, nil
	}
	if work.image == nil || len(work.bundles) == 0 || work.parent.OperationID != scope.OperationID || work.parent.RequestIdentityDigest != scope.RequestIdentity ||
		work.bundles[0].Request.OperationKind != scope.OperationKind || work.bundles[0].Request.PredecessorRevisionID != scope.OriginalPredecessorRevisionID || (scope.OperationKind != contract.OperationApplyDeclaration && scope.OperationKind != contract.OperationRotateValueEntryValue) ||
		work.phase.DomainID != work.image.root.Domain || work.phase.OperationID != work.parent.OperationID || work.phase.OwnerID != work.parent.OperationID ||
		work.phase.PlanGraphID != work.parent.PlanGraphID || work.phase.UsePlanDigest != work.parent.UsePlanDigest ||
		work.phase.ChangedSubjects != scope.ChangedSubjects || work.phase.ChangedAccess != scope.ChangedAccess || !scope.CanonicalSuccessor {
		return proof, contract.ErrRecord
	}
	if work.image.root.Generated.ActiveOwner != work.parent.OperationID || work.image.root.Generated.ActivePhase != work.phase.PhaseID || work.image.root.Generated.ActiveGraph != work.phase.PlanGraphID {
		return proof, contract.ErrRecord
	}
	parentRow, parentPresent := work.records[generatedRecordKey{contract.GeneratedParentSupportKind, work.parent.OperationID}]
	if !parentPresent {
		return proof, contract.ErrRecord
	}
	parent, parentErr := contract.InspectGeneratedParentRecord(parentRow.Body)
	if parentErr != nil || parent != *work.parent {
		return proof, contract.ErrRecord
	}
	row, present := work.records[generatedRecordKey{contract.GeneratedPhaseSupportKind, work.phase.OperationID}]
	if !present {
		return proof, contract.ErrRecord
	}
	phase, err := contract.InspectGeneratedPhaseRecord(row.Body)
	if err != nil || phase != *work.phase {
		return proof, contract.ErrRecord
	}
	proof = generatedCanonicalSelectionProof{kind: scope.OperationKind, domain: work.image.root.Domain, operation: scope.OperationID, requestIdentity: scope.RequestIdentity, selectionPhase: phase.SelectionPhaseID, changedSubjects: phase.ChangedSubjects, changedAccess: phase.ChangedAccess}
	return proof, nil
}

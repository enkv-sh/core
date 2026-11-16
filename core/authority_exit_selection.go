package core

import (
	"math"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// The complete and administrative readers make the same checks on the
// successor. The administrative reader can omit disposable work bodies.
func (s *StateSession) validEndWorkSelection() bool {
	if s == nil {
		return false
	}
	return selectedEndWorkSelection(s.head, s.selectedImage(), s.admission.recipient)
}
func selectedEndWorkSelection(head format.Head, s *selectedImage, authorityID contract.ID) bool {
	if s == nil || head.AuthKind != format.AdministrativeAuth || head.EndWork == nil {
		return false
	}
	q := head.EndWork
	if q.DomainID != s.root.Domain || q.AfterWarningBits != s.root.WarningBits ||
		!s.currentRetiringPointersSelected() ||
		q.AfterAccessRoot != s.root.CurrentAccess.AccessRoot ||
		q.AfterAccessIncarnationID != s.root.CurrentAccess.Core.AccessIncarnationID ||
		q.AfterAccessGeneration != s.root.CurrentAccess.Core.AccessGeneration ||
		(q.BeforeAccessRoot != q.AfterAccessRoot && q.BeforeAccessGeneration == math.MaxUint64 &&
			q.AfterAccessIncarnationID != contract.DeriveAccessIncarnationID(q.DomainID, s.root.Transition)) ||
		uint32(q.AfterChildCount) != s.root.ChildCount || q.AfterChildBytes != s.root.ChildEncodedBytes ||
		slices.ContainsFunc(s.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == q.TargetGroupID }) {
		return false
	}
	current, err := administrativePreservedCurrent(s.root, s.pages, s.generatedCoverageRecords(), nil)
	if err != nil || current != q.PreservedCurrent {
		return false
	}
	var receipt *contract.CompactMutationReceipt
	for _, page := range s.support {
		for _, record := range page.Records {
			if record.Kind != contract.MutationReceiptSupportKind || record.RecordID != q.OperationID {
				continue
			}
			row, err := contract.InspectCompactMutationReceipt(record.Body)
			if err != nil || receipt != nil {
				return false
			}
			receipt = &row
		}
	}
	if receipt == nil {
		return false
	}
	changedID, err := contract.ChangedSubjectIdentityID(q.DomainID, contract.ChangedSubjectSelectedWork,
		q.TargetGroupID, q.TargetOwnerID)
	if err != nil {
		return false
	}
	changed, err := contract.ChangedSubjectDescriptor([]contract.ChangedSubjectIdentity{{
		Kind: contract.ChangedSubjectSelectedWork, Change: contract.ChangedSubjectRemoved, Identity: changedID,
	}})
	if err != nil || receipt.ChangedSubjects != changed {
		return false
	}
	projection := contract.CompactMutationReceiptPlan(*receipt)
	projection.RequestIdentityDigest, projection.CompleteResult = contract.ID{}, contract.GeneratorDescriptor{}
	empty := contract.EmptyMutationResultDescriptors()
	complete, err := contract.CompleteMutationResultDescriptor(contract.MutationResultProjection{
		Receipt: projection, RequestCoreDigest: q.RequestCoreDigest,
		ChangedAccess: empty[0], Effects: empty[1], Outputs: empty[2], Duties: empty[3], Hazards: empty[4],
	})
	if err != nil || receipt.CompleteResult != complete {
		return false
	}
	return receipt.DomainID == q.DomainID && receipt.OperationKind == contract.OperationEndSelectedWork &&
		receipt.RequestIdentityDigest == q.RequestCoreDigest &&
		receipt.PredecessorRevisionID == q.PredecessorRevisionID &&
		receipt.RequestedRevisionID == head.Core.Revision &&
		receipt.AdministrativeGroupID == q.TargetGroupID &&
		receipt.AdministrativeTargetID == q.TargetID && receipt.AdministrativeTargetKind == q.TargetKind &&
		receipt.AdministrativeDisposition == q.RequestCoreDigest &&
		receipt.AdministrativeOriginalEvidence == q.SelectedEvidenceSummary &&
		receipt.WarningBits == uint64(q.AfterWarningBits) &&
		receipt.AdministrativeWarningChanges == q.AfterWarningBits&^q.BeforeWarningBits &&
		receipt.AdministrativePageDelta == int16(q.AfterChildCount)-int16(q.BeforeChildCount) &&
		receipt.AdministrativeByteDelta == int64(q.AfterChildBytes)-int64(q.BeforeChildBytes)
}

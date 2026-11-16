package crypto

import (
	"slices"

	"enkv.sh/core/contract"
)

type generatedAccessIdentity struct {
	kind uint16
	id   contract.ID
}

func generatedSelectedPhase(q contract.CryptoGeneratedCompareRequest, input contract.GeneratedSessionInput) (*contract.GeneratedPhaseRecord, error) {
	if input.Output == nil || input.Output.Inspect(input.BeforePublic) != nil {
		return nil, ErrAdmission
	}
	parent := q.Parent
	if q.Purpose == contract.CryptoGeneratedReservationPurpose {
		parent = contract.GeneratedParentRecord(q.ParentPlan)
	}
	if input.SelectionPhase == nil {
		if slices.ContainsFunc(input.Output.Rows.Facts, func(fact contract.SupportRecordDigest) bool {
			return fact.Kind() == contract.GeneratedPhaseSupportKind && fact.RecordID() == parent.OperationID
		}) {
			return nil, ErrAdmission
		}
		return nil, nil
	}
	p := *input.SelectionPhase
	if p.DomainID != q.Context.DomainID || p.OperationID != parent.OperationID || p.OwnerID != p.OperationID || p.PlanGraphID != parent.PlanGraphID || p.UsePlanDigest != parent.UsePlanDigest {
		return nil, ErrAdmission
	}
	body, err := contract.EncodeGeneratedPhaseRecord(p)
	if err != nil {
		return nil, ErrAdmission
	}
	fact, err := contract.InspectSupportRecordDigest(p.DomainID, contract.SupportRecord{Kind: contract.GeneratedPhaseSupportKind, RecordID: p.OperationID, Body: body})
	if err != nil || !slices.Contains(input.Output.Rows.Facts, fact) {
		return nil, ErrAdmission
	}
	if p.SelectionPhaseID.IsZero() {
		return nil, nil
	}
	return &p, nil
}

func (a *generatedAdmission) admitAutomaticAccess(input generatedSessionAdmissionInput) bool {
	if input.BeforeAccess == nil {
		return input.SelectionPhase == nil
	}
	if a.inputOwner == nil {
		return false
	}
	owned, err := a.inputOwner.ownAccess(a.request.Context.DomainID, a.request.Context.CurrentAccessRoot, *input.BeforeAccess, input.BeforeAccessRecords)
	if err != nil {
		return false
	}
	if input.SelectionPhase != nil {
		a.selectionPhase = new(contract.GeneratedPhaseRecord)
		*a.selectionPhase = *input.SelectionPhase
	}
	a.beforeAccessRecords, a.accessPins = owned.records, owned.pins
	return true
}

func (a *generatedAdmission) candidateAutomaticAccessMatches(c generatedCandidate) bool {
	if a.selectionPhase == nil {
		return true
	}
	var phase contract.GeneratedPhaseRecord
	for _, row := range c.SupportRecords {
		if row.Kind == contract.GeneratedPhaseSupportKind && row.RecordID == a.graph.Header.OperationID {
			var err error
			phase, err = contract.InspectGeneratedPhaseRecord(row.Body)
			if err != nil {
				return false
			}
		}
	}
	before := a.selectionPhase
	if phase.SelectionPhaseID != before.SelectionPhaseID || phase.ChangedSubjects != before.ChangedSubjects || phase.ChangedAccess != before.ChangedAccess {
		return false
	}
	for _, row := range c.AccessRecords {
		digest, err := contract.AccessRecordDigest(row)
		if err != nil || a.accessPins[generatedAccessIdentity{row.MaterialKind, row.MaterialID}] != digest {
			return false
		}
	}
	return true
}

func (a *generatedAdmission) automaticAttemptAllowed(x contract.GeneratorAttemptTemplate) bool {
	if a.selectionPhase == nil {
		return true
	}
	if x.Action != contract.GeneratorActionDelete {
		return false
	}
	for _, index := range contract.GeneratedAutomaticRetirementIndices(a.graph) {
		if a.graph.Lineages[index].Templates[0].AttemptID == x.AttemptID {
			return true
		}
	}
	return false
}

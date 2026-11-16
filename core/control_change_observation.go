package core

import "enkv.sh/core/contract"

func successionObservation(request contract.SuccessionRequestCore) (changeObservation, error) {
	var projection contract.SuccessionChangedSubjectProjection
	descriptor, err := contract.ProjectSuccessionChangedSubjects(request, &projection)
	if err != nil {
		return changeObservation{}, err
	}
	out := changeObservation{Source: observationSource{DomainID: request.DomainID, AdmissionID: request.AdmissionID, OperationID: request.OperationID}, HasChangedSubjects: true, Descriptor: descriptor,
		Subjects: make([]observationSubject, len(projection.Subjects)), Succession: make([]observationSuccession, len(projection.Changes))}
	for i, row := range projection.Subjects {
		out.Subjects[i].Row = row
	}
	for i, change := range projection.Changes {
		out.Succession[i] = observationSuccession(change)
	}
	return out, nil
}

// The owner calls this only after candidate and exact-preview validation.
// It reads no object body and asserts no provider or remote cleanup outcome.
func administrativeObservation(candidate *Candidate) (changeObservation, error) {
	q, receipt := candidate.head.EndWork, candidate.endWorkReceipt
	identity, err := contract.ChangedSubjectIdentityID(q.DomainID, contract.ChangedSubjectSelectedWork, q.TargetGroupID, q.TargetOwnerID)
	if err != nil {
		return changeObservation{}, err
	}
	return changeObservation{Source: observationSource{Stage: observationCandidate, DomainID: q.DomainID, OperationID: q.OperationID},
		HasChangedSubjects: true, Descriptor: receipt.ChangedSubjects,
		Subjects:       []observationSubject{{Row: contract.ChangedSubjectIdentity{Kind: contract.ChangedSubjectSelectedWork, Change: contract.ChangedSubjectRemoved, Identity: identity}, PrimaryID: q.TargetGroupID, SecondaryID: q.TargetOwnerID}},
		Administrative: &observationAdministrative{TargetGroupID: q.TargetGroupID, TargetOwnerID: q.TargetOwnerID, TargetID: q.TargetID, DispositionID: receipt.AdministrativeDisposition, TargetKind: q.TargetKind, DutyKind: q.DutyKind, BeforeWarnings: q.BeforeWarningBits, AfterWarnings: q.AfterWarningBits, EvidenceSummary: q.SelectedEvidenceSummary}, Candidate: candidateObservationIdentity(candidate)}, nil
}

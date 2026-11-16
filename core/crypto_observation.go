package core

import "enkv.sh/core/contract"

func exchangeSource(c contract.ApplyContext) observationSource {
	return observationSource{Stage: observationExchange, DomainID: c.DomainID,
		AdmissionID: c.AdmissionID, SessionID: c.SessionID}
}

func generatedExchangeSource(q contract.CryptoGeneratedCompareRequest) observationSource {
	source := exchangeSource(q.Context)
	parent := q.Parent
	if q.Purpose == contract.CryptoGeneratedReservationPurpose {
		parent = contract.GeneratedParentRecord(q.ParentPlan)
	}
	source.OperationID = parent.OperationID

	if q.Purpose == contract.CryptoGeneratedOriginalVerificationPurpose {
		source.ParentID, source.AttemptID = q.Original.OperationID, q.Original.AttemptID
	}
	return source
}

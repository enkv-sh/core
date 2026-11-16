package contract

import "bytes"

const (
	MaxPublicationDispatchBytes               = 8 << 10
	MaxPublicationResultBytes                 = 4 << 10
	MaxPublicationOutcomeBytes                = 80 << 10
	MaxPublicationOutcomeVectorBytes          = 16 << 20
	PublicationNoOp                     uint8 = 1
	PublicationNotSent                  uint8 = 2
	PublicationOutcomeAcknowledged      uint8 = 3
	PublicationOutcomeQualifiedNoEffect uint8 = 4
	PublicationOutcomeUnknown           uint8 = 5
	PublicationSummaryNoChange          uint8 = 1
	PublicationSummaryComplete          uint8 = 2
	PublicationSummaryUnknown           uint8 = 3
	PublicationSummaryMixedTerminal     uint8 = 4
	PublicationSummaryFailed            uint8 = 5
)

type PublicationDispatch struct {
	Schema                                         uint16
	DomainID, OperationID, AttemptID, CoordinateID ID
	Projection                                     PublicationProjection
	ProjectionCommitment                           ID
	AuthoritySubjectDigest                         ID
	ExecutorID, CredentialRouteID                  string
	ResponseContractDigest                         ID
}

type PublicationResult struct {
	Schema                                         uint16
	DomainID, OperationID, AttemptID, CoordinateID ID
	ProjectionCommitment, DispatchContextDigest    ID
	Evidence                                       PublicationEvidence
}

// A target has one to three action rows in admitted order, or one no-action row.
type PublicationOutcome struct {
	Action                              uint8 // Zero only for an explicit no-action row.
	ProjectionCommitment, AttemptID     ID
	Disposition                         uint8
	CoreReason                          uint16
	RemoteValueMayRemain, LateWriteRisk uint8
	BlockerIDs                          []ID
	Evidence                            PublicationEvidence
}

type PublicationTargetOutcome struct {
	CoordinateID ID
	Actions      []PublicationOutcome
}

type PublicationOutcomeVector struct {
	Schema                                             uint16
	DomainID, OperationID, SnapshotID, SelectionDigest ID
	DomainWideWarning                                  uint8
	Entries                                            []PublicationTargetOutcome
}

func EncodePublicationDispatch(v PublicationDispatch) ([]byte, error) {
	if v.Schema != 5 || v.DomainID.IsZero() || v.OperationID.IsZero() || v.AttemptID.IsZero() || v.CoordinateID.IsZero() ||
		v.Projection.DomainID != v.DomainID || v.Projection.CoordinateID != v.CoordinateID ||
		v.AuthoritySubjectDigest.IsZero() ||
		!outputIdentifierValid(v.ExecutorID) || !outputIdentifierValid(v.CredentialRouteID) || v.ResponseContractDigest.IsZero() {
		return nil, ErrRecord
	}
	projection, err := EncodePublicationProjection(v.Projection)
	if err != nil {
		return nil, err
	}
	digest, err := PublicationProjectionCommitment(v.Projection)
	if err != nil || digest != v.ProjectionCommitment {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, len(projection)+512)}
	w.u16(v.Schema)
	w.id(v.DomainID)
	w.id(v.OperationID)
	w.id(v.AttemptID)
	w.id(v.CoordinateID)
	w.blob(projection)
	w.id(v.ProjectionCommitment)
	w.id(v.AuthoritySubjectDigest)
	w.blob([]byte(v.ExecutorID))
	w.blob([]byte(v.CredentialRouteID))
	w.id(v.ResponseContractDigest)
	if len(w.b) > MaxPublicationDispatchBytes {
		return nil, ErrRecordCapacity
	}
	return w.b, nil
}

func InspectPublicationDispatch(body []byte) (PublicationDispatch, error) {
	if len(body) > MaxPublicationDispatchBytes {
		return PublicationDispatch{}, ErrRecordCapacity
	}
	r := newRecordReader(body)
	v := PublicationDispatch{Schema: r.u16(), DomainID: r.id(), OperationID: r.id(), AttemptID: r.id(), CoordinateID: r.id()}
	projection := r.blob(MaxPublicationProjectionBytes)
	var err error
	v.Projection, err = InspectPublicationProjection(projection)
	if err != nil {
		return PublicationDispatch{}, err
	}
	v.ProjectionCommitment = r.id()
	v.AuthoritySubjectDigest = r.id()
	v.ExecutorID = outputBlobString(&r, 256)
	v.CredentialRouteID = outputBlobString(&r, 256)
	v.ResponseContractDigest = r.id()
	if r.end() != nil {
		return PublicationDispatch{}, ErrRecord
	}
	if _, err := EncodePublicationDispatch(v); err != nil {
		return PublicationDispatch{}, err
	}
	return v, nil
}

func PublicationDispatchContextDigest(v PublicationDispatch) (ID, error) {
	body, err := EncodePublicationDispatch(v)
	if err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter("ENKV/PUBLICATION/DISPATCH/v4\x00")
	w.raw(body)
	return w.result(0).Digest, nil
}

func EncodePublicationResult(v PublicationResult) ([]byte, error) {
	if v.Schema != 2 || v.DomainID.IsZero() || v.OperationID.IsZero() || v.AttemptID.IsZero() || v.CoordinateID.IsZero() ||
		v.ProjectionCommitment.IsZero() || v.DispatchContextDigest.IsZero() {
		return nil, ErrRecord
	}
	evidence, err := EncodePublicationEvidence(v.Evidence)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, 256+len(evidence))}
	w.u16(v.Schema)
	w.id(v.DomainID)
	w.id(v.OperationID)
	w.id(v.AttemptID)
	w.id(v.CoordinateID)
	w.id(v.ProjectionCommitment)
	w.id(v.DispatchContextDigest)
	w.blob(evidence)
	if len(w.b) > MaxPublicationResultBytes {
		return nil, ErrRecordCapacity
	}
	return w.b, nil
}

func InspectPublicationResult(body []byte) (PublicationResult, error) {
	if len(body) > MaxPublicationResultBytes {
		return PublicationResult{}, ErrRecordCapacity
	}
	r := newRecordReader(body)
	v := PublicationResult{Schema: r.u16(), DomainID: r.id(), OperationID: r.id(), AttemptID: r.id(), CoordinateID: r.id(), ProjectionCommitment: r.id(), DispatchContextDigest: r.id()}
	evidence := r.blob(MaxPublicationEvidenceBytes)
	var err error
	v.Evidence, err = InspectPublicationEvidence(evidence)
	if err != nil || r.end() != nil {
		return PublicationResult{}, ErrRecord
	}
	if _, err := EncodePublicationResult(v); err != nil {
		return PublicationResult{}, err
	}
	return v, nil
}

func ValidatePublicationResult(dispatch PublicationDispatch, result PublicationResult) error {
	contextDigest, err := PublicationDispatchContextDigest(dispatch)
	if err != nil || result.Schema != 2 || result.DomainID != dispatch.DomainID || result.OperationID != dispatch.OperationID ||
		result.AttemptID != dispatch.AttemptID || result.CoordinateID != dispatch.CoordinateID ||
		result.ProjectionCommitment != dispatch.ProjectionCommitment || result.DispatchContextDigest != contextDigest ||
		result.Evidence.ResponseContractDigest != dispatch.ResponseContractDigest || validatePublicationActionLocator(dispatch.Projection.Action, result.Evidence) != nil {
		return ErrRecord
	}
	_, err = EncodePublicationResult(result)
	return err
}

func outputEvidenceEmpty(e PublicationEvidence) bool { return e == (PublicationEvidence{}) }

func validatePublicationOutcome(v PublicationOutcome) error {
	if v.Action > PublicationDeleteReservedSlot || v.Disposition < PublicationNoOp || v.Disposition > PublicationOutcomeUnknown ||
		v.RemoteValueMayRemain > 1 || v.LateWriteRisk > 1 || len(v.BlockerIDs) > MaxPublicationMarkers {
		return ErrRecord
	}
	for i, id := range v.BlockerIDs {
		if id.IsZero() || i > 0 && bytes.Compare(v.BlockerIDs[i-1][:], id[:]) >= 0 {
			return ErrRecord
		}
	}
	switch v.Disposition {
	case PublicationNoOp:
		if v.Action != 0 || !v.ProjectionCommitment.IsZero() || !v.AttemptID.IsZero() || v.CoreReason != 0 ||
			v.RemoteValueMayRemain != 0 || v.LateWriteRisk != 0 || !outputEvidenceEmpty(v.Evidence) || len(v.BlockerIDs) != 0 {
			return ErrRecord
		}
	case PublicationNotSent:
		if v.Action == 0 || v.ProjectionCommitment.IsZero() || !v.AttemptID.IsZero() || v.CoreReason == 0 || !outputEvidenceEmpty(v.Evidence) {
			return ErrRecord
		}
	case PublicationOutcomeAcknowledged:
		if v.Action == 0 || v.ProjectionCommitment.IsZero() || v.AttemptID.IsZero() || v.CoreReason != 0 ||
			v.Evidence.Entry != PublicationMayHaveEnteredEntry || v.Evidence.Class != PublicationRequestAcknowledged {
			return ErrRecord
		}
	case PublicationOutcomeQualifiedNoEffect:
		if v.Action == 0 || v.ProjectionCommitment.IsZero() || v.AttemptID.IsZero() || v.CoreReason != 0 ||
			v.Evidence.Class != PublicationQualifiedNoEffect {
			return ErrRecord
		}
	case PublicationOutcomeUnknown:
		if v.Action == 0 || v.ProjectionCommitment.IsZero() || v.AttemptID.IsZero() || v.CoreReason != 0 ||
			v.Evidence.Entry != PublicationMayHaveEnteredEntry || v.Evidence.Class != PublicationUnproved {
			return ErrRecord
		}
	}
	if !outputEvidenceEmpty(v.Evidence) && (validatePublicationEvidence(v.Evidence) != nil || validatePublicationActionLocator(v.Action, v.Evidence) != nil) {
		return ErrRecord
	}
	return nil
}

func EncodePublicationOutcomeVector(v PublicationOutcomeVector) ([]byte, error) {
	if v.Schema != 2 || v.DomainID.IsZero() || v.OperationID.IsZero() || v.SnapshotID.IsZero() || v.SelectionDigest.IsZero() ||
		v.DomainWideWarning > 1 || len(v.Entries) > MaxPublicationCoordinates {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, 256+len(v.Entries)*128)}
	w.u16(v.Schema)
	w.id(v.DomainID)
	w.id(v.OperationID)
	w.id(v.SnapshotID)
	w.id(v.SelectionDigest)
	w.u8(v.DomainWideWarning)
	w.u16(uint16(len(v.Entries)))
	uniqueBlockers := make(map[ID]bool)
	admittedAttempts := make(map[ID]bool)
	for i, entry := range v.Entries {
		if entry.CoordinateID.IsZero() || len(entry.Actions) == 0 || len(entry.Actions) > 3 ||
			i > 0 && bytes.Compare(v.Entries[i-1].CoordinateID[:], entry.CoordinateID[:]) >= 0 {
			return nil, ErrRecord
		}
		start := len(w.b)
		w.id(entry.CoordinateID)
		w.u8(uint8(len(entry.Actions)))
		seenActions := make(map[uint8]bool, len(entry.Actions))
		for _, action := range entry.Actions {
			if validatePublicationOutcome(action) != nil || seenActions[action.Action] || action.Action == 0 && len(entry.Actions) != 1 {
				return nil, ErrRecord
			}
			seenActions[action.Action] = true
			if !action.AttemptID.IsZero() {
				if admittedAttempts[action.AttemptID] {
					return nil, ErrRecord
				}
				admittedAttempts[action.AttemptID] = true
			}
			w.u8(action.Action)
			w.id(action.ProjectionCommitment)
			w.id(action.AttemptID)
			w.u8(action.Disposition)
			w.u16(action.CoreReason)
			w.u8(action.RemoteValueMayRemain)
			w.u8(action.LateWriteRisk)
			w.u16(uint16(len(action.BlockerIDs)))
			for _, blocker := range action.BlockerIDs {
				w.id(blocker)
				uniqueBlockers[blocker] = true
			}
			evidence := []byte(nil)
			if !outputEvidenceEmpty(action.Evidence) {
				var err error
				evidence, err = EncodePublicationEvidence(action.Evidence)
				if err != nil {
					return nil, err
				}
			}
			w.blob(evidence)
			if len(w.b)-start > MaxPublicationOutcomeBytes || len(w.b) > MaxPublicationOutcomeVectorBytes || len(uniqueBlockers) > MaxPublicationMarkers {
				return nil, ErrRecordCapacity
			}
		}
	}
	return w.b, nil
}

func InspectPublicationOutcomeVector(body []byte) (PublicationOutcomeVector, error) {
	if len(body) > MaxPublicationOutcomeVectorBytes {
		return PublicationOutcomeVector{}, ErrRecordCapacity
	}
	r := newRecordReader(body)
	v := PublicationOutcomeVector{Schema: r.u16(), DomainID: r.id(), OperationID: r.id(), SnapshotID: r.id(), SelectionDigest: r.id(), DomainWideWarning: r.u8()}
	count := int(r.u16())
	if r.err != nil || count > MaxPublicationCoordinates || count > (len(body)-r.i)/34 {
		return PublicationOutcomeVector{}, ErrRecord
	}
	v.Entries = make([]PublicationTargetOutcome, 0, count)
	for i := 0; i < count; i++ {
		entry := PublicationTargetOutcome{CoordinateID: r.id()}
		actionCount := int(r.u8())
		if r.err != nil || actionCount < 1 || actionCount > 3 || actionCount > (len(body)-r.i)/76 {
			return PublicationOutcomeVector{}, ErrRecord
		}
		entry.Actions = make([]PublicationOutcome, 0, actionCount)
		for j := 0; j < actionCount; j++ {
			action := PublicationOutcome{Action: r.u8(), ProjectionCommitment: r.id(), AttemptID: r.id(),
				Disposition: r.u8(), CoreReason: r.u16(), RemoteValueMayRemain: r.u8(), LateWriteRisk: r.u8()}
			blockers := int(r.u16())
			if r.err != nil || blockers > MaxPublicationMarkers || blockers > (len(r.b)-r.i)/32 {
				return PublicationOutcomeVector{}, ErrRecord
			}
			action.BlockerIDs = make([]ID, blockers)
			for k := range action.BlockerIDs {
				action.BlockerIDs[k] = r.id()
			}
			evidence := r.blob(MaxPublicationEvidenceBytes)
			if r.err != nil {
				return PublicationOutcomeVector{}, ErrRecord
			}
			if len(evidence) != 0 {
				var err error
				action.Evidence, err = InspectPublicationEvidence(evidence)
				if err != nil {
					return PublicationOutcomeVector{}, err
				}
			}
			entry.Actions = append(entry.Actions, action)
		}
		v.Entries = append(v.Entries, entry)
	}
	if r.end() != nil {
		return PublicationOutcomeVector{}, ErrRecord
	}
	if _, err := EncodePublicationOutcomeVector(v); err != nil {
		return PublicationOutcomeVector{}, err
	}
	return v, nil
}

func SummarizePublication(entries []PublicationTargetOutcome) uint8 {
	if len(entries) == 0 {
		return PublicationSummaryNoChange
	}
	acknowledged, noChange, failed := false, false, false
	for _, entry := range entries {
		for _, action := range entry.Actions {
			switch action.Disposition {
			case PublicationOutcomeUnknown:
				return PublicationSummaryUnknown
			case PublicationOutcomeAcknowledged:
				acknowledged = true
			case PublicationNoOp:
				noChange = true
			case PublicationNotSent, PublicationOutcomeQualifiedNoEffect:
				failed = true
			default:
				return 0
			}
		}
	}
	if failed {
		if acknowledged || noChange {
			return PublicationSummaryMixedTerminal
		}
		return PublicationSummaryFailed
	}
	if acknowledged {
		return PublicationSummaryComplete
	}
	return PublicationSummaryNoChange
}

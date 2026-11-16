package contract

import "bytes"

const (
	MaxPublicationRequestTargetsBytes = 1427526
	MaxPublicationInvocationActions   = 1024
)

// PublicationRequestTarget binds the selected request, before any result exists.
// Empty Actions describes an acknowledged-equal or blocked selected target.
type PublicationRequestTarget struct {
	CoordinateID, BindingIncarnationID, EntryIncarnationID                              ID
	TargetRowDigest, ValueBasisDigest, PolicyDigest                                     ID
	ServiceContractID, TargetContractID                                                 string
	ProtocolID, ConfigContractDigest, ArtifactContractID, ExecutorID, CredentialRouteID ID
	BlockerIDs                                                                          []ID
	Actions                                                                             []PublicationRequestAction
}

type PublicationRequestAction struct {
	Projection PublicationProjection
	AttemptID  ID
}

func PublicationRequestTargetsDescriptor(domain ID, rows []PublicationRequestTarget) (DescriptorVector, error) {
	if domain.IsZero() || len(rows) > MaxPublicationCoordinates {
		return DescriptorVector{}, ErrRecordCapacity
	}
	length, actionCount, blockerCount := uint64(70), 0, 0
	for _, row := range rows {
		if len(row.ServiceContractID) > 256 || len(row.TargetContractID) > 256 || len(row.Actions) > 3 || len(row.BlockerIDs) > MaxPublicationMarkers {
			return DescriptorVector{}, ErrRecordCapacity
		}
		length += uint64(363 + len(row.ServiceContractID) + len(row.TargetContractID) + len(row.BlockerIDs)*32 + len(row.Actions)*455)
		actionCount += len(row.Actions)
		blockerCount += len(row.BlockerIDs)
		if length > MaxPublicationRequestTargetsBytes || actionCount > MaxPublicationInvocationActions || blockerCount > MaxPublicationMarkers {
			return DescriptorVector{}, ErrRecordCapacity
		}
	}
	w := cryptoHashWriter("ENKV/PUBLICATION/REQUEST-TARGETS/v3\x00")
	w.id(domain)
	w.u16(uint16(len(rows)))
	blockers, attempts := make(map[ID]bool), make(map[ID]bool)
	actions := 0
	for i, row := range rows {
		if !publicIDsValid(row.CoordinateID, row.BindingIncarnationID, row.EntryIncarnationID, row.TargetRowDigest,
			row.ProtocolID, row.ConfigContractDigest, row.ArtifactContractID, row.ExecutorID, row.CredentialRouteID) ||
			i > 0 && bytes.Compare(rows[i-1].CoordinateID[:], row.CoordinateID[:]) >= 0 || !outputIdentifierValid(row.ServiceContractID) ||
			!outputIdentifierValid(row.TargetContractID) || len(row.TargetContractID) > 256 || len(row.BlockerIDs) > MaxPublicationMarkers || len(row.Actions) > 3 {
			return DescriptorVector{}, ErrRecord
		}
		for _, id := range []ID{row.CoordinateID, row.BindingIncarnationID, row.EntryIncarnationID, row.TargetRowDigest, row.ValueBasisDigest, row.PolicyDigest} {
			w.id(id)
		}
		w.blob([]byte(row.ServiceContractID))
		w.blob([]byte(row.TargetContractID))
		for _, id := range []ID{row.ProtocolID, row.ConfigContractDigest, row.ArtifactContractID, row.ExecutorID, row.CredentialRouteID} {
			w.id(id)
		}
		w.u16(uint16(len(row.BlockerIDs)))
		for j, id := range row.BlockerIDs {
			if id.IsZero() || blockers[id] || j > 0 && bytes.Compare(row.BlockerIDs[j-1][:], id[:]) >= 0 {
				return DescriptorVector{}, ErrRecord
			}
			blockers[id] = true
			w.id(id)
		}
		w.u8(uint8(len(row.Actions)))
		seenActions := make(map[uint8]bool)
		for _, action := range row.Actions {
			p := action.Projection
			request, err := PublicationRequestContractDigest(row.ProtocolID, row.ConfigContractDigest, row.ServiceContractID, row.TargetContractID, p.Action)
			if err != nil || action.AttemptID.IsZero() || attempts[action.AttemptID] || seenActions[p.Action] ||
				p.DomainID != domain || p.CoordinateID != row.CoordinateID || p.BindingIncarnationID != row.BindingIncarnationID ||
				p.EntryIncarnationID != row.EntryIncarnationID || p.TargetRowDigest != row.TargetRowDigest || p.RequestContractDigest != request ||
				(p.Action == PublicationCreateWithValue || p.Action == PublicationWriteValue) && p.ValueBasisDigest != row.ValueBasisDigest ||
				p.Action <= PublicationUpdatePolicy && p.PolicyDigest != row.PolicyDigest ||
				p.Action >= PublicationDeleteOwned && (!row.ValueBasisDigest.IsZero() || !row.PolicyDigest.IsZero()) {
				return DescriptorVector{}, ErrRecord
			}
			body, err := EncodePublicationProjection(p)
			if err != nil {
				return DescriptorVector{}, err
			}
			attempts[action.AttemptID], seenActions[p.Action] = true, true
			actions++
			w.blob(body)
			w.id(action.AttemptID)
		}
		if actions > MaxPublicationInvocationActions || len(blockers) > MaxPublicationMarkers || w.n > MaxPublicationRequestTargetsBytes {
			return DescriptorVector{}, ErrRecordCapacity
		}
	}
	for id := range attempts {
		if blockers[id] {
			return DescriptorVector{}, ErrRecord
		}
	}
	return w.result(len(rows)), nil
}

type PublicationRequestObservation struct {
	DomainID, OperationID, HEADRevisionID, HEADDigest, TokenDigest ID
	Snapshot                                                       Ref
	SelectionDigest, ActingRecipientID                             ID
	Targets                                                        DescriptorVector
	Nonce                                                          ID
}

func publicationRequestTargetsValid(d DescriptorVector) bool {
	return !d.Digest.IsZero() && d.Count <= MaxPublicationCoordinates && d.Length >= 70+uint64(d.Count)*365 && d.Length <= MaxPublicationRequestTargetsBytes
}

func PublicationRequestIdentity(v PublicationRequestObservation) (ID, error) {
	if !publicIDsValid(v.DomainID, v.OperationID, v.HEADRevisionID, v.HEADDigest, v.TokenDigest, v.SelectionDigest, v.ActingRecipientID, v.Nonce) ||
		v.SelectionDigest != v.HEADDigest || v.Snapshot.Kind != RootKind || v.Snapshot.Domain != v.DomainID || !publicationRequestTargetsValid(v.Targets) || v.Targets.Count == 0 {
		return ID{}, ErrRecord
	}
	ref, err := AppendRef(nil, v.Snapshot, CanonicalSchema)
	if err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter("ENKV/PUBLICATION/REQUEST/v3\x00")
	w.u16(2)
	for _, id := range []ID{v.DomainID, v.OperationID, v.HEADRevisionID, v.HEADDigest, v.TokenDigest} {
		w.id(id)
	}
	w.raw(ref)
	w.id(v.SelectionDigest)
	w.id(v.ActingRecipientID)
	w.descriptor(v.Targets)
	w.id(v.Nonce)
	return w.result(1).Digest, nil
}

type PublicationNoWorkRequestCore struct {
	Domain, Store, Trust, Coordinate, NonBody, Interpretation ID
	Epoch                                                     uint64
	PreviousRevision, PreviousDigest                          ID
	PreviousToken                                             Token
	ActingRecipientID                                         ID
	Targets                                                   DescriptorVector
}

func PublicationNoWorkRequestDigest(v PublicationNoWorkRequestCore) (ID, error) {
	if !publicIDsValid(v.Domain, v.Store, v.Trust, v.Coordinate, v.NonBody, v.Interpretation, v.PreviousRevision, v.PreviousDigest, v.ActingRecipientID) || v.Epoch == 0 || !v.PreviousToken.Valid() || !publicationRequestTargetsValid(v.Targets) {
		return ID{}, ErrRecord
	}
	w := cryptoHashWriter("ENKV/PUBLICATION/NO-WORK-REQUEST/v1\x00")
	writeRequestScope(&w, RequestCoreFields{Domain: v.Domain, Store: v.Store, Trust: v.Trust, Coordinate: v.Coordinate, NonBody: v.NonBody, Interpretation: v.Interpretation, Epoch: v.Epoch, PreviousRevision: v.PreviousRevision, PreviousDigest: v.PreviousDigest}, v.PreviousToken)
	w.id(v.ActingRecipientID)
	w.descriptor(v.Targets)
	return w.result(1).Digest, nil
}

type PublicationNoWorkObservation struct {
	OperationID, DomainID, RequestCoreDigest, HEADRevisionID, HEADDigest, TokenDigest ID
	Snapshot                                                                          Ref
	Targets                                                                           DescriptorVector
	Nonce                                                                             ID
}

func PublicationNoWorkObservationIdentity(v PublicationNoWorkObservation) (ID, error) {
	if !publicationRequestTargetsValid(v.Targets) {
		return ID{}, ErrRecord
	}
	return noWorkObservationIdentityBounded(OperationPublishCurrentProjection, SuppliedApplyNoWorkObservation{OperationID: v.OperationID, DomainID: v.DomainID, RequestCoreDigest: v.RequestCoreDigest, HEADRevisionID: v.HEADRevisionID, HEADDigest: v.HEADDigest, TokenDigest: v.TokenDigest, Snapshot: v.Snapshot, Comparison: v.Targets, Nonce: v.Nonce}, MaxPublicationCoordinates)
}

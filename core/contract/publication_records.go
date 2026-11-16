package contract

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

const (
	MaxPublicationCoordinateRecordBytes = 8 << 10
	MaxPublicationMarkerRecordBytes     = 8 << 10
	MaxPublicationEvidenceBytes         = 3122
	MaxPublicationMarkers               = 2048
	MaxPublicationCoordinates           = 1024
	// One current incarnation and three ACK stamps per coordinate, plus markers.
	MaxPublicationIncarnations        = MaxPublicationCoordinates + MaxPublicationMarkers + 3*MaxPublicationCoordinates
	publicationCoordinateMinBodyBytes = 650
)

const (
	PublicationBindingActive          uint8 = 1
	PublicationBindingRetired         uint8 = 2
	PublicationOwnerNone              uint8 = 0
	PublicationOwnerUncertainCreate   uint8 = 1
	PublicationOwnerQualified         uint8 = 2
	PublicationMayHaveEntered         uint8 = 1
	PublicationAcknowledged           uint8 = 2
	PublicationQualifiedNoEffectState uint8 = 3
	PublicationUnknown                uint8 = 4
	PublicationNotEntered             uint8 = 1
	PublicationMayHaveEnteredEntry    uint8 = 2
	PublicationUnproved               uint8 = 0
	PublicationRequestAcknowledged    uint8 = 1
	PublicationQualifiedNoEffect      uint8 = 2
)

type PublicationCoordinate struct {
	Schema                                                                                uint16
	DomainID, CoordinateID                                                                ID
	ServiceContractID, CanonicalTarget                                                    string
	BindingState, OwnerState                                                              uint8
	ActiveBindingIncarnationID, LastBindingIncarnationID, LastEntryIncarnationID          ID
	OwnedBirthAttemptID, OwnedInstanceDigest                                              ID
	CurrentPublicationIncarnationID                                                       ID
	LastAdmissionOrdinal                                                                  uint64
	LatestUnresolvedAttemptID, LastValueAckAttemptID, LastValueDigest                     ID
	LastPolicyAckAttemptID, LastPolicyDigest, LastDeleteAckAttemptID                      ID
	LastValueAckIncarnationID, LastPolicyAckIncarnationID, LastDeleteAckIncarnationID     ID
	LastValueAckOrdinal, LastPolicyAckOrdinal, LastDeleteAckOrdinal                       uint64
	PossibleRemoteObject, LateEffectRisk                                                  uint8
	DeletionDestinationID, DeletionConsumerLocator                                        string
	DeletionTargetContractID, DeletionConfigContractID, DeletionCredentialRouteContractID string
	DeletionTargetData                                                                    []byte
	DeletionPayloadEncoding                                                               uint8
	LocatorRequiresCreation                                                               bool
	DeletionTargetRowDigest                                                               ID
}

type PublicationEvidence struct {
	Schema                                         uint16
	Entry, Class                                   uint8
	ResponseContractDigest                         ID
	NormalizedStatus                               uint16
	SafeRequestID, SafeResourceID, ConsumerLocator string
}

type PublicationMarker struct {
	Schema                                         uint16
	DomainID, OperationID, AttemptID, CoordinateID ID
	PublicationIncarnationID                       ID
	AdmissionOrdinal                               uint64
	Projection                                     PublicationProjection
	ProjectionCommitment                           ID
	AuthoritySubjectDigest                         ID
	ExecutorID, CredentialRouteID                  string
	BlockerCount                                   uint16
	BlockerDigest                                  ID
	State, LateEffectRisk                          uint8
	Evidence                                       PublicationEvidence
	BirthServiceContractID, BirthTargetContractID  string
}

func PublicationBlockerDigest(blockers []ID) (ID, error) {
	if len(blockers) > MaxPublicationMarkers {
		return ID{}, ErrRecordCapacity
	}
	if len(blockers) == 0 {
		return ID{}, nil
	}
	w := cryptoHashWriter("ENKV/PUBLICATION/BLOCKERS/v2\x00")
	w.u16(uint16(len(blockers)))
	for i, id := range blockers {
		if id.IsZero() || i > 0 && bytes.Compare(blockers[i-1][:], id[:]) >= 0 {
			return ID{}, ErrRecord
		}
		w.id(id)
	}
	return w.result(0).Digest, nil
}

func validatePublicationCoordinate(v PublicationCoordinate) error {
	if v.Schema != 5 || v.CurrentPublicationIncarnationID.IsZero() || v.DomainID.IsZero() || v.CoordinateID.IsZero() || !outputIdentifierValid(v.ServiceContractID) ||
		!outputCoordinateValid(v.CanonicalTarget) || v.BindingState < PublicationBindingActive || v.BindingState > PublicationBindingRetired ||
		v.OwnerState > PublicationOwnerQualified || v.LastBindingIncarnationID.IsZero() || v.LastEntryIncarnationID.IsZero() ||
		v.BindingState == PublicationBindingActive && v.ActiveBindingIncarnationID.IsZero() ||
		v.BindingState == PublicationBindingRetired && !v.ActiveBindingIncarnationID.IsZero() ||
		v.PossibleRemoteObject > 1 || v.LateEffectRisk > 1 ||
		v.LastValueAckAttemptID.IsZero() != v.LastValueDigest.IsZero() ||
		v.LastPolicyAckAttemptID.IsZero() != v.LastPolicyDigest.IsZero() {
		return ErrRecord
	}
	deletionFieldsPresent := !v.DeletionTargetRowDigest.IsZero()
	if deletionFieldsPresent {
		if !outputIdentifierValid(v.DeletionDestinationID) || len(v.DeletionConsumerLocator) > 1024 || !utf8.ValidString(v.DeletionConsumerLocator) || !v.LocatorRequiresCreation && v.DeletionConsumerLocator == "" ||
			!outputIdentifierValid(v.DeletionTargetContractID) || !outputIdentifierValid(v.DeletionConfigContractID) || !outputIdentifierValid(v.DeletionCredentialRouteContractID) || len(v.DeletionTargetData) > MaxOutputTargetDataBytes || (v.DeletionPayloadEncoding != OutputEncodingRaw && v.DeletionPayloadEncoding != OutputEncodingBase64) {
			return ErrRecord
		}
	} else if v.DeletionDestinationID != "" || v.DeletionConsumerLocator != "" || v.DeletionTargetContractID != "" || v.DeletionConfigContractID != "" || v.DeletionCredentialRouteContractID != "" || len(v.DeletionTargetData) != 0 || v.DeletionPayloadEncoding != 0 || v.LocatorRequiresCreation {
		return ErrRecord
	}

	if !deletionFieldsPresent && (v.OwnerState != PublicationOwnerNone || v.PossibleRemoteObject != 0 ||
		v.LateEffectRisk != 0 || !v.LatestUnresolvedAttemptID.IsZero()) {
		return ErrRecord
	}
	for _, ack := range [...]struct {
		attempt, incarnation ID
		ordinal              uint64
	}{
		{v.LastValueAckAttemptID, v.LastValueAckIncarnationID, v.LastValueAckOrdinal},
		{v.LastPolicyAckAttemptID, v.LastPolicyAckIncarnationID, v.LastPolicyAckOrdinal},
		{v.LastDeleteAckAttemptID, v.LastDeleteAckIncarnationID, v.LastDeleteAckOrdinal},
	} {
		if ack.attempt.IsZero() != ack.incarnation.IsZero() || ack.attempt.IsZero() != (ack.ordinal == 0) ||
			ack.incarnation == v.CurrentPublicationIncarnationID && ack.ordinal > v.LastAdmissionOrdinal {
			return ErrRecord
		}
	}
	switch v.OwnerState {
	case PublicationOwnerNone:
		if !v.OwnedBirthAttemptID.IsZero() || !v.OwnedInstanceDigest.IsZero() {
			return ErrRecord
		}
	case PublicationOwnerUncertainCreate:
		// The latest-unresolved cache can be cleared by exact administrative
		// disposition while another matching create proof remains selected. The
		// complete selected relation, rather than this cache, qualifies ownership.
		if !v.OwnedBirthAttemptID.IsZero() || !v.OwnedInstanceDigest.IsZero() ||
			v.PossibleRemoteObject != 1 {
			return ErrRecord
		}
	case PublicationOwnerQualified:
		if v.OwnedBirthAttemptID.IsZero() || v.OwnedInstanceDigest.IsZero() {
			return ErrRecord
		}
	}
	id, err := PublicationCoordinateID(v.DomainID, v.ServiceContractID, v.CanonicalTarget)
	if err != nil || id != v.CoordinateID {
		return ErrRecord
	}
	return nil
}

// The complete maximum is 8072 body bytes: 2 schema + 64 IDs + 1288
// service/target blobs + 2 states + 192 ownership IDs + 8 ordinal + 32 unresolved
// ID + 104 value ACK + 104 policy ACK + 72 delete ACK + 2 flags + 260 destination
// + 1028 locator + 260 target contract + 4100 target data + 260 config contract
// + 260 route contract
// + 2 encoding/locator flags + 32 target digest. Support framing adds 37.
func EncodePublicationCoordinate(v PublicationCoordinate) ([]byte, error) {
	if err := validatePublicationCoordinate(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, 512)}
	w.u16(v.Schema)
	w.id(v.DomainID)
	w.id(v.CoordinateID)
	w.blob([]byte(v.ServiceContractID))
	w.blob([]byte(v.CanonicalTarget))
	w.u8(v.BindingState)
	w.u8(v.OwnerState)
	for _, id := range [...]ID{v.ActiveBindingIncarnationID, v.LastBindingIncarnationID,
		v.LastEntryIncarnationID, v.OwnedBirthAttemptID, v.OwnedInstanceDigest, v.CurrentPublicationIncarnationID} {
		w.id(id)
	}
	w.u64(v.LastAdmissionOrdinal)
	w.id(v.LatestUnresolvedAttemptID)
	w.id(v.LastValueAckAttemptID)
	w.id(v.LastValueDigest)
	w.id(v.LastValueAckIncarnationID)
	w.u64(v.LastValueAckOrdinal)
	w.id(v.LastPolicyAckAttemptID)
	w.id(v.LastPolicyDigest)
	w.id(v.LastPolicyAckIncarnationID)
	w.u64(v.LastPolicyAckOrdinal)
	w.id(v.LastDeleteAckAttemptID)
	w.id(v.LastDeleteAckIncarnationID)
	w.u64(v.LastDeleteAckOrdinal)
	w.u8(v.PossibleRemoteObject)
	w.u8(v.LateEffectRisk)
	for _, field := range [...]string{v.DeletionDestinationID, v.DeletionConsumerLocator, v.DeletionTargetContractID} {
		w.blob([]byte(field))
	}
	w.blob(v.DeletionTargetData)
	w.blob([]byte(v.DeletionConfigContractID))
	w.blob([]byte(v.DeletionCredentialRouteContractID))
	w.u8(v.DeletionPayloadEncoding)
	if v.LocatorRequiresCreation {
		w.u8(1)
	} else {
		w.u8(0)
	}
	w.id(v.DeletionTargetRowDigest)
	if len(w.b)+SupportRecordOverhead > MaxPublicationCoordinateRecordBytes {
		return nil, ErrRecordCapacity
	}
	return w.b, nil
}

func InspectPublicationCoordinate(body []byte) (PublicationCoordinate, error) {
	if len(body)+SupportRecordOverhead > MaxPublicationCoordinateRecordBytes {
		return PublicationCoordinate{}, ErrRecordCapacity
	}
	r := newRecordReader(body)
	v := PublicationCoordinate{Schema: r.u16(), DomainID: r.id(), CoordinateID: r.id(),
		ServiceContractID: outputBlobString(&r, 256), CanonicalTarget: outputBlobString(&r, 1024), BindingState: r.u8(), OwnerState: r.u8(),
		ActiveBindingIncarnationID: r.id(), LastBindingIncarnationID: r.id(), LastEntryIncarnationID: r.id(),
		OwnedBirthAttemptID: r.id(), OwnedInstanceDigest: r.id(), CurrentPublicationIncarnationID: r.id(), LastAdmissionOrdinal: r.u64(),
		LatestUnresolvedAttemptID: r.id(), LastValueAckAttemptID: r.id(), LastValueDigest: r.id(), LastValueAckIncarnationID: r.id(), LastValueAckOrdinal: r.u64(),
		LastPolicyAckAttemptID: r.id(), LastPolicyDigest: r.id(), LastPolicyAckIncarnationID: r.id(), LastPolicyAckOrdinal: r.u64(), LastDeleteAckAttemptID: r.id(), LastDeleteAckIncarnationID: r.id(), LastDeleteAckOrdinal: r.u64(),
		PossibleRemoteObject: r.u8(), LateEffectRisk: r.u8()}
	// These fields are empty together before a container may have been entered.
	// The final coordinate validation enforces their all-or-none relation.
	deletionField := func(limit int) string {
		body := r.blob(limit)
		if !utf8.Valid(body) && r.err == nil {
			r.err = ErrRecord
		}
		return string(body)
	}
	v.DeletionDestinationID = deletionField(256)
	v.DeletionConsumerLocator = deletionField(1024)
	v.DeletionTargetContractID = deletionField(256)
	v.DeletionTargetData = append([]byte(nil), r.blob(MaxOutputTargetDataBytes)...)
	v.DeletionConfigContractID = deletionField(256)
	v.DeletionCredentialRouteContractID = deletionField(256)
	v.DeletionPayloadEncoding = r.u8()
	flag := r.u8()
	if flag > 1 {
		r.err = ErrRecord
	}
	v.LocatorRequiresCreation = flag == 1
	v.DeletionTargetRowDigest = r.id()
	if r.end() != nil || validatePublicationCoordinate(v) != nil {
		return PublicationCoordinate{}, ErrRecord
	}
	return v, nil
}

// Clone checks the complete bounded record before taking ownership of backing.
func (v PublicationCoordinate) Clone() (PublicationCoordinate, error) {
	if err := validatePublicationCoordinate(v); err != nil {
		return PublicationCoordinate{}, err
	}
	v.ServiceContractID = strings.Clone(v.ServiceContractID)
	v.CanonicalTarget = strings.Clone(v.CanonicalTarget)
	v.DeletionDestinationID = strings.Clone(v.DeletionDestinationID)
	v.DeletionConsumerLocator = strings.Clone(v.DeletionConsumerLocator)
	v.DeletionTargetContractID = strings.Clone(v.DeletionTargetContractID)
	v.DeletionConfigContractID = strings.Clone(v.DeletionConfigContractID)
	v.DeletionCredentialRouteContractID = strings.Clone(v.DeletionCredentialRouteContractID)
	if v.DeletionTargetData != nil {
		data := make([]byte, len(v.DeletionTargetData))
		copy(data, v.DeletionTargetData)
		v.DeletionTargetData = data
	}
	return v, nil
}

// Equal compares complete canonical records. Its two temporary buffers each
// remain below the 8 KiB support-record ceiling.
func (v PublicationCoordinate) Equal(other PublicationCoordinate) bool {
	a, err := EncodePublicationCoordinate(v)
	if err != nil {
		return false
	}
	b, err := EncodePublicationCoordinate(other)
	return err == nil && bytes.Equal(a, b)
}

func publicationSafeID(s string) bool { return len(s) <= 1024 && utf8.ValidString(s) }

const PublicationEvidenceSchema uint16 = 3

func validatePublicationEvidence(v PublicationEvidence) error {
	if v.Schema != PublicationEvidenceSchema || v.ResponseContractDigest.IsZero() || !publicationSafeID(v.SafeRequestID) || !publicationSafeID(v.SafeResourceID) || !publicationSafeID(v.ConsumerLocator) ||
		v.Entry != PublicationNotEntered && v.Entry != PublicationMayHaveEnteredEntry || v.Class > PublicationQualifiedNoEffect ||
		v.Class == PublicationRequestAcknowledged && (v.Entry != PublicationMayHaveEnteredEntry || v.NormalizedStatus == 0) ||
		v.Class == PublicationUnproved && (v.NormalizedStatus != 0 || v.SafeRequestID != "" || v.SafeResourceID != "" || v.ConsumerLocator != "") ||
		v.Entry == PublicationNotEntered && v.Class == PublicationRequestAcknowledged {
		return ErrRecord
	}
	if v.Class != PublicationRequestAcknowledged && v.ConsumerLocator != "" {
		return ErrRecord
	}
	return nil
}

func EncodePublicationEvidence(v PublicationEvidence) ([]byte, error) {
	if err := validatePublicationEvidence(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, 64)}
	w.u16(v.Schema)
	w.u8(v.Entry)
	w.u8(v.Class)
	w.id(v.ResponseContractDigest)
	w.u16(v.NormalizedStatus)
	w.blob([]byte(v.SafeRequestID))
	w.blob([]byte(v.SafeResourceID))
	w.blob([]byte(v.ConsumerLocator))
	if len(w.b) > MaxPublicationEvidenceBytes {
		return nil, ErrRecordCapacity
	}
	return w.b, nil
}

func InspectPublicationEvidence(body []byte) (PublicationEvidence, error) {
	if len(body) > MaxPublicationEvidenceBytes {
		return PublicationEvidence{}, ErrRecordCapacity
	}
	r := newRecordReader(body)
	v := PublicationEvidence{Schema: r.u16(), Entry: r.u8(), Class: r.u8(), ResponseContractDigest: r.id(), NormalizedStatus: r.u16(),
		SafeRequestID: string(r.blob(1024)), SafeResourceID: string(r.blob(1024)), ConsumerLocator: string(r.blob(1024))}
	if r.end() != nil || validatePublicationEvidence(v) != nil {
		return PublicationEvidence{}, ErrRecord
	}
	return v, nil
}

func validatePublicationMarker(v PublicationMarker) error {
	if v.Schema != 5 || v.PublicationIncarnationID.IsZero() || v.DomainID.IsZero() || v.OperationID.IsZero() || v.AttemptID.IsZero() || v.CoordinateID.IsZero() ||
		v.AdmissionOrdinal == 0 || v.Projection.DomainID != v.DomainID || v.Projection.CoordinateID != v.CoordinateID ||
		v.ProjectionCommitment.IsZero() ||
		v.AuthoritySubjectDigest.IsZero() || !outputIdentifierValid(v.ExecutorID) || !outputIdentifierValid(v.CredentialRouteID) ||
		v.BlockerCount > MaxPublicationMarkers || v.BlockerCount == 0 && !v.BlockerDigest.IsZero() ||
		v.BlockerCount > 0 && v.BlockerDigest.IsZero() || v.State < PublicationMayHaveEntered || v.State > PublicationUnknown ||
		v.LateEffectRisk > 1 {
		return ErrRecord
	}
	create := v.Projection.Action == PublicationCreateEmpty || v.Projection.Action == PublicationCreateWithValue
	if create != (outputIdentifierValid(v.BirthServiceContractID) && outputIdentifierValid(v.BirthTargetContractID)) ||
		!create && (v.BirthServiceContractID != "" || v.BirthTargetContractID != "") {
		return ErrRecord
	}
	commitment, err := PublicationProjectionCommitment(v.Projection)
	if err != nil || commitment != v.ProjectionCommitment || validatePublicationEvidence(v.Evidence) != nil || validatePublicationActionLocator(v.Projection.Action, v.Evidence) != nil {
		return ErrRecord
	}
	switch v.State {
	case PublicationMayHaveEntered, PublicationUnknown:
		if v.Evidence.Entry != PublicationMayHaveEnteredEntry || v.Evidence.Class != PublicationUnproved {
			return ErrRecord
		}
	case PublicationAcknowledged:
		if v.Evidence.Entry != PublicationMayHaveEnteredEntry || v.Evidence.Class != PublicationRequestAcknowledged {
			return ErrRecord
		}
	case PublicationQualifiedNoEffectState:
		if v.Evidence.Class != PublicationQualifiedNoEffect {
			return ErrRecord
		}
	}
	return nil
}

// Maximum: 2+160+8+(4+419)+32+32+260+260+2+32+2+(4+3122)+260+260
// = 4859 body bytes; support framing gives 4896, within the 8192-byte envelope.
func EncodePublicationMarker(v PublicationMarker) ([]byte, error) {
	if err := validatePublicationMarker(v); err != nil {
		return nil, err
	}
	projection, err := EncodePublicationProjection(v.Projection)
	if err != nil {
		return nil, err
	}
	evidence, err := EncodePublicationEvidence(v.Evidence)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, 512+len(projection)+len(evidence))}
	w.u16(v.Schema)
	for _, id := range [...]ID{v.DomainID, v.OperationID, v.AttemptID, v.CoordinateID, v.PublicationIncarnationID} {
		w.id(id)
	}
	w.u64(v.AdmissionOrdinal)
	w.blob(projection)
	w.id(v.ProjectionCommitment)
	w.id(v.AuthoritySubjectDigest)
	w.blob([]byte(v.ExecutorID))
	w.blob([]byte(v.CredentialRouteID))
	w.u16(v.BlockerCount)
	w.id(v.BlockerDigest)
	w.u8(v.State)
	w.u8(v.LateEffectRisk)
	w.blob(evidence)
	w.blob([]byte(v.BirthServiceContractID))
	w.blob([]byte(v.BirthTargetContractID))
	if len(w.b)+SupportRecordOverhead > MaxPublicationMarkerRecordBytes {
		return nil, ErrRecordCapacity
	}
	return w.b, nil
}

func InspectPublicationMarker(body []byte) (PublicationMarker, error) {
	if len(body)+SupportRecordOverhead > MaxPublicationMarkerRecordBytes {
		return PublicationMarker{}, ErrRecordCapacity
	}
	r := newRecordReader(body)
	v := PublicationMarker{Schema: r.u16(), DomainID: r.id(), OperationID: r.id(), AttemptID: r.id(), CoordinateID: r.id(), PublicationIncarnationID: r.id(), AdmissionOrdinal: r.u64()}
	projection := r.blob(MaxPublicationProjectionBytes)
	var err error
	v.Projection, err = InspectPublicationProjection(projection)
	if err != nil {
		return PublicationMarker{}, err
	}
	v.ProjectionCommitment = r.id()
	v.AuthoritySubjectDigest = r.id()
	v.ExecutorID, v.CredentialRouteID = outputBlobString(&r, 256), outputBlobString(&r, 256)
	v.BlockerCount, v.BlockerDigest = r.u16(), r.id()
	v.State, v.LateEffectRisk = r.u8(), r.u8()
	v.Evidence, err = InspectPublicationEvidence(r.blob(MaxPublicationEvidenceBytes))
	if err != nil {
		return PublicationMarker{}, err
	}
	v.BirthServiceContractID = string(r.blob(256))
	v.BirthTargetContractID = string(r.blob(256))
	if r.end() != nil || validatePublicationMarker(v) != nil {
		return PublicationMarker{}, ErrRecord
	}
	return v, nil
}

// CollectPublicationRecordIdentities adds the retained incarnation and operation
// identities carried inside publication records. The caller collects record,
// graph and plan identities and decides how inspection failures are reported.
func CollectPublicationRecordIdentities(row SupportRecord, used map[ID]bool) error {
	if used == nil {
		return ErrRecord
	}
	var ids []ID
	switch row.Kind {
	case PublicationCoordinateSupportKind:
		coordinate, err := InspectPublicationCoordinate(row.Body)
		if err != nil {
			return err
		}
		ids = []ID{coordinate.ActiveBindingIncarnationID, coordinate.LastBindingIncarnationID, coordinate.LastEntryIncarnationID, coordinate.CurrentPublicationIncarnationID, coordinate.LastValueAckIncarnationID, coordinate.LastPolicyAckIncarnationID, coordinate.LastDeleteAckIncarnationID}
	case PublicationMarkerSupportKind:
		marker, err := InspectPublicationMarker(row.Body)
		if err != nil {
			return err
		}
		ids = []ID{marker.OperationID, marker.PublicationIncarnationID, marker.Projection.BindingIncarnationID, marker.Projection.EntryIncarnationID}
	}
	for _, id := range ids {
		if !id.IsZero() {
			used[id] = true
		}
	}
	return nil
}

func validatePublicationActionLocator(action uint8, e PublicationEvidence) error {
	create := action == PublicationCreateEmpty || action == PublicationCreateWithValue
	if create && e.Class == PublicationRequestAcknowledged && e.SafeResourceID == "" {
		return ErrRecord
	}
	if (create && e.Class == PublicationRequestAcknowledged) != (e.ConsumerLocator != "") {
		return ErrRecord
	}
	return nil
}

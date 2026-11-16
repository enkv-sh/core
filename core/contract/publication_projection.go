package contract

import outputprotocol "enkv.sh/sdk/protocols/output"

const MaxPublicationProjectionBytes = 4 << 10
const PublicationProjectionLength = 419

// These action tags preserve the public output protocol's six operations in
// private commitments; none is a send permission by itself.
const (
	PublicationCreateEmpty        uint8 = uint8(outputprotocol.ActionCreateEmpty)
	PublicationCreateWithValue    uint8 = uint8(outputprotocol.ActionCreateWithValue)
	PublicationWriteValue         uint8 = uint8(outputprotocol.ActionWriteValue)
	PublicationUpdatePolicy       uint8 = uint8(outputprotocol.ActionUpdatePolicy)
	PublicationDeleteOwned        uint8 = uint8(outputprotocol.ActionDeleteOwned)
	PublicationDeleteReservedSlot uint8 = uint8(outputprotocol.ActionDeleteReservedSlot)
)

type PublicationValueBasis struct {
	EntryIncarnationID, ValueStateID ID
	ContentLength                    uint32
	InputEncoding                    uint8
	RetainedLength                   uint32
	ConfidentialityClass             uint8
	SemanticCommitment               ID
}

// PublicationProjection fixes the public action, selected target and value/
// policy commitments used by the private output bridge. It carries no payload
// or send authority; the dispatch must still match Core's admitted operation.
type PublicationProjection struct {
	Schema                                                                   uint16
	DomainID, ConfigurationDigest, CoordinateID                              ID
	BindingIncarnationID, EntryIncarnationID, TargetRowDigest                ID
	Action                                                                   uint8
	OwnedBirthAttemptID, UncertainCreateAttemptID, ExclusiveNamespaceDigest  ID
	ValueBasisDigest, PolicyDigest, RequestContractDigest, ActingRecipientID ID
}

// PublicationCoordinateID commits domain, semantic service and canonical
// physical target. Build identity, binding alias and target schema do not
// partition collision detection.
func PublicationCoordinateID(domain ID, service, target string) (ID, error) {
	if domain.IsZero() || !outputIdentifierValid(service) || !outputCoordinateValid(target) {
		return ID{}, ErrRecord
	}
	w := cryptoHashWriter("ENKV/PUBLICATION/COORDINATE/v3\x00")
	w.id(domain)
	w.blob([]byte(service))
	w.blob([]byte(target))
	return w.result(0).Digest, nil
}

// PublicationTargetRowDigest borrows target backing for the call and commits
// its complete canonical row with domain, destination and binding. It does not
// authenticate the plugin's interpretation of that target.
func PublicationTargetRowDigest(domain ID, destination string, binding ID, target OutputTarget) (ID, error) {
	if domain.IsZero() || !outputIdentifierValid(destination) || binding.IsZero() || !outputTargetCoreValid(target) {
		return ID{}, ErrRecord
	}
	body, err := encodeOutputTargetRow(target)
	if err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter("ENKV/OUTPUT/TARGET-ROW/v3\x00")
	w.id(domain)
	w.blob([]byte(destination))
	w.id(binding)
	w.raw(body)
	return w.result(0).Digest, nil
}

func PublicationValueBasisDigest(domain ID, destination string, binding ID, target OutputTarget, value PublicationValueBasis) (ID, error) {
	if domain.IsZero() || !outputIdentifierValid(destination) || binding.IsZero() || !outputTargetCoreValid(target) ||
		value.EntryIncarnationID != target.EntryIncarnationID || value.ValueStateID.IsZero() || value.SemanticCommitment.IsZero() ||
		InputLengths(value.InputEncoding, value.ContentLength, value.RetainedLength) != nil || value.ConfidentialityClass != Plain && value.ConfidentialityClass != Secret {
		return ID{}, ErrRecord
	}
	w := cryptoHashWriter("ENKV/PUBLICATION/VALUE-BASIS/v4\x00")
	w.id(domain)
	w.blob([]byte(destination))
	w.id(binding)
	w.id(value.EntryIncarnationID)
	w.id(value.ValueStateID)
	w.u32(value.ContentLength)
	w.u8(value.InputEncoding)
	w.u32(value.RetainedLength)
	w.u8(value.ConfidentialityClass)
	w.id(value.SemanticCommitment)
	for _, field := range []string{target.ServiceContractID, target.CanonicalTarget, target.TargetContractID} {
		w.blob([]byte(field))
	}
	w.u8(target.PayloadEncoding)
	return w.result(0).Digest, nil
}

// PublicationOwnedInstanceDigest binds a provider-reported resource identity
// to the exact admitted birth and target. Hashing the identity does not supply
// independent proof that the provider created or owns it.
func PublicationOwnedInstanceDigest(domain, coordinate, binding, entry, targetRow, birth ID, safeResourceID string) (ID, error) {
	if domain.IsZero() || coordinate.IsZero() || binding.IsZero() || entry.IsZero() || targetRow.IsZero() || birth.IsZero() ||
		!outputCoordinateValid(safeResourceID) {
		return ID{}, ErrRecord
	}
	v := outputprotocol.Command{DomainID: outputprotocol.ID(domain), CoordinateID: outputprotocol.ID(coordinate), BindingIncarnationID: outputprotocol.ID(binding),
		EntryIncarnationID: outputprotocol.ID(entry), BirthTargetRowDigest: outputprotocol.ID(targetRow), OwnedBirthAttemptID: outputprotocol.ID(birth), OwnedInstance: safeResourceID}
	return ID(v.OwnedInstanceDigest()), nil
}

func PublicationSelectedValueDigest(domain, basis, birth, owner ID) (ID, error) {
	if domain.IsZero() || basis.IsZero() || birth.IsZero() || owner.IsZero() {
		return ID{}, ErrRecord
	}
	w := cryptoHashWriter("ENKV/PUBLICATION/SELECTED-VALUE/v2\x00")
	for _, id := range [...]ID{domain, basis, birth, owner} {
		w.id(id)
	}
	return w.result(0).Digest, nil
}

func validatePublicationProjection(v PublicationProjection) error {
	if v.Schema != 4 || v.DomainID.IsZero() || v.ConfigurationDigest.IsZero() || v.CoordinateID.IsZero() ||
		v.BindingIncarnationID.IsZero() || v.EntryIncarnationID.IsZero() || v.TargetRowDigest.IsZero() ||
		v.RequestContractDigest.IsZero() || v.ActingRecipientID.IsZero() ||
		v.Action < PublicationCreateEmpty || v.Action > PublicationDeleteReservedSlot {
		return ErrRecord
	}
	switch v.Action {
	case PublicationCreateEmpty:
		if !v.OwnedBirthAttemptID.IsZero() || !v.UncertainCreateAttemptID.IsZero() ||
			!v.ExclusiveNamespaceDigest.IsZero() || !v.ValueBasisDigest.IsZero() {
			return ErrRecord
		}
	case PublicationCreateWithValue:
		if !v.OwnedBirthAttemptID.IsZero() || !v.UncertainCreateAttemptID.IsZero() ||
			!v.ExclusiveNamespaceDigest.IsZero() || v.ValueBasisDigest.IsZero() {
			return ErrRecord
		}
	case PublicationWriteValue:
		if v.OwnedBirthAttemptID.IsZero() || !v.UncertainCreateAttemptID.IsZero() ||
			!v.ExclusiveNamespaceDigest.IsZero() || v.ValueBasisDigest.IsZero() {
			return ErrRecord
		}
	case PublicationUpdatePolicy:
		if v.OwnedBirthAttemptID.IsZero() || !v.UncertainCreateAttemptID.IsZero() ||
			!v.ExclusiveNamespaceDigest.IsZero() || !v.ValueBasisDigest.IsZero() || v.PolicyDigest.IsZero() {
			return ErrRecord
		}
	case PublicationDeleteOwned:
		if v.OwnedBirthAttemptID.IsZero() || !v.UncertainCreateAttemptID.IsZero() ||
			!v.ExclusiveNamespaceDigest.IsZero() || !v.ValueBasisDigest.IsZero() || !v.PolicyDigest.IsZero() {
			return ErrRecord
		}
	case PublicationDeleteReservedSlot:
		if !v.OwnedBirthAttemptID.IsZero() || v.UncertainCreateAttemptID.IsZero() ||
			v.ExclusiveNamespaceDigest.IsZero() || !v.ValueBasisDigest.IsZero() || !v.PolicyDigest.IsZero() {
			return ErrRecord
		}
	}
	return nil
}

func EncodePublicationProjection(v PublicationProjection) ([]byte, error) {
	if err := validatePublicationProjection(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, PublicationProjectionLength)}
	w.u16(v.Schema)
	for _, id := range [...]ID{v.DomainID, v.ConfigurationDigest, v.CoordinateID, v.BindingIncarnationID,
		v.EntryIncarnationID, v.TargetRowDigest} {
		w.id(id)
	}
	w.u8(v.Action)
	for _, id := range [...]ID{v.OwnedBirthAttemptID, v.UncertainCreateAttemptID, v.ExclusiveNamespaceDigest,
		v.ValueBasisDigest, v.PolicyDigest, v.RequestContractDigest, v.ActingRecipientID} {
		w.id(id)
	}
	if len(w.b) != PublicationProjectionLength {
		return nil, ErrRecord
	}
	return w.b, nil
}

func InspectPublicationProjection(body []byte) (PublicationProjection, error) {
	if len(body) != PublicationProjectionLength {
		return PublicationProjection{}, ErrRecord
	}
	r := newRecordReader(body)
	v := PublicationProjection{Schema: r.u16(), DomainID: r.id(), ConfigurationDigest: r.id(), CoordinateID: r.id(),
		BindingIncarnationID: r.id(), EntryIncarnationID: r.id(), TargetRowDigest: r.id(), Action: r.u8(),
		OwnedBirthAttemptID: r.id(), UncertainCreateAttemptID: r.id(), ExclusiveNamespaceDigest: r.id(),
		ValueBasisDigest: r.id(), PolicyDigest: r.id(), RequestContractDigest: r.id(), ActingRecipientID: r.id()}
	if r.end() != nil || validatePublicationProjection(v) != nil {
		return PublicationProjection{}, ErrRecord
	}
	return v, nil
}

func PublicationProjectionCommitment(v PublicationProjection) (ID, error) {
	body, err := EncodePublicationProjection(v)
	if err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter("ENKV/PUBLICATION/PROJECTION/v4\x00")
	w.raw(body)
	return w.result(0).Digest, nil
}

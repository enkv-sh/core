package contract

import (
	"bytes"
	"cmp"
	"encoding/binary"
)

type GeneratorVectorKind uint8

const (
	GeneratorVectorTargets GeneratorVectorKind = iota + 1
	GeneratorVectorProgress
	GeneratorVectorHistory
	GeneratorVectorSupport
	GeneratorVectorProofs
	GeneratorVectorConsumers
	GeneratorVectorSlices
	GeneratorVectorFacts
)

const (
	GeneratorSnapshotOwner        uint8 = 128
	GeneratorCarrierFixedLength         = 120
	generatorCarrierRowOverhead         = SupportRecordOverhead + GeneratorCarrierFixedLength
	generatorCarrierMaxLength           = GeneratorCarrierFixedLength + GeneratorFactsRowMaxLength
	generatorSelectedSupportBytes       = MaxChildPages * (MaxRequiredSupportPageLength - RequiredSupportPageHeaderLength)
)

func (k GeneratorVectorKind) label() string {
	switch k {
	case GeneratorVectorTargets:
		return "targets"
	case GeneratorVectorProgress:
		return "progress"
	case GeneratorVectorHistory:
		return "history"
	case GeneratorVectorSupport:
		return "support-bindings"
	case GeneratorVectorProofs:
		return "proofs"
	case GeneratorVectorConsumers:
		return "consumers"
	case GeneratorVectorSlices:
		return "slice-index"
	case GeneratorVectorFacts:
		return "facts"
	default:
		return ""
	}
}

func (k GeneratorVectorKind) rowBounds() (int, int) {
	switch k {
	case GeneratorVectorTargets:
		return 272, GeneratorTargetMaxLength
	case GeneratorVectorProgress:
		return GeneratorProgressLength, GeneratorProgressLength
	case GeneratorVectorHistory:
		return GeneratorHistoryLength, GeneratorHistoryLength
	case GeneratorVectorSupport:
		return 103, GeneratorSupportBindingMaxLength
	case GeneratorVectorProofs:
		return 43 + GeneratorAuthoritySubjectLength + 8, GeneratorProofMaxLength
	case GeneratorVectorConsumers:
		return GeneratorConsumerLength, GeneratorConsumerLength
	case GeneratorVectorSlices:
		return GeneratorSliceLocationLength, GeneratorSliceLocationLength
	case GeneratorVectorFacts:
		return 38 + 115, GeneratorFactsRowMaxLength
	default:
		return 0, 0
	}
}

func EmptyGeneratorVector(kind GeneratorVectorKind) GeneratorDescriptor {
	if kind.label() == "" {
		return GeneratorDescriptor{}
	}
	return GeneratorDescriptor{Digest: generatorDigest(kind.label(), []byte{0, 0, 0, 0}), Length: 4}
}

func GeneratorVectorShapeValid(kind GeneratorVectorKind, d GeneratorDescriptor) bool {
	minimum, maximum := kind.rowBounds()
	if minimum == 0 || !d.Valid() {
		return false
	}
	if d.Count == 0 {
		return d == EmptyGeneratorVector(kind)
	}
	n := uint64(d.Count)
	return d.Length >= 4+(4+uint64(minimum))*n && d.Length <= 4+(4+uint64(maximum))*n &&
		d.Length-4+(generatorCarrierRowOverhead-4)*n <= generatorSelectedSupportBytes
}

func generatorVectorOwnerValid(owner uint8, kind GeneratorVectorKind) bool {
	switch owner {
	case GeneratedParentSupportKind:
		return kind == GeneratorVectorSupport || kind == GeneratorVectorProofs || kind == GeneratorVectorConsumers
	case GeneratedAttemptSupportKind:
		return kind == GeneratorVectorFacts || kind == GeneratorVectorProgress || kind == GeneratorVectorHistory
	case GeneratedDutySupportKind:
		return kind == GeneratorVectorTargets || kind == GeneratorVectorProgress || kind == GeneratorVectorHistory || kind == GeneratorVectorConsumers
	case GeneratedHazardSupportKind:
		return kind == GeneratorVectorTargets || kind == GeneratorVectorHistory || kind == GeneratorVectorConsumers
	case GeneratorSnapshotOwner:
		return kind == GeneratorVectorSlices
	default:
		return false
	}
}

func inspectGeneratorVectorRow(kind GeneratorVectorKind, b []byte) error {
	var err error
	switch kind {
	case GeneratorVectorTargets:
		_, err = InspectGeneratorTarget(b)
	case GeneratorVectorProgress:
		_, err = InspectGeneratorProgress(b)
	case GeneratorVectorHistory:
		_, err = InspectGeneratorHistory(b)
	case GeneratorVectorSupport:
		_, err = InspectGeneratorSupportBinding(b)
	case GeneratorVectorProofs:
		_, err = InspectGeneratorProof(b)
	case GeneratorVectorConsumers:
		_, err = InspectGeneratorConsumer(b)
	case GeneratorVectorSlices:
		_, err = InspectGeneratorSliceLocation(b)
	case GeneratorVectorFacts:
		_, err = InspectGeneratorFactsRow(b)
	default:
		err = ErrRecord
	}
	return err
}

// Inputs have already passed their complete closed row reader.
func generatorVectorRowCompare(kind GeneratorVectorKind, a, b []byte) int {
	switch kind {
	case GeneratorVectorTargets:
		an, bn := int(binary.BigEndian.Uint32(a[2:6])), int(binary.BigEndian.Uint32(b[2:6]))
		if c := bytes.Compare(a[6:6+an], b[6:6+bn]); c != 0 {
			return c
		}
		return bytes.Compare(a[46+an:78+an], b[46+bn:78+bn])
	case GeneratorVectorProgress:
		return bytes.Compare(a[2:66], b[2:66])
	case GeneratorVectorSupport:
		return bytes.Compare(a[2:99], b[2:99])
	case GeneratorVectorProofs:
		// Subject starts after schema, purpose and B length. The after-phase
		// is the second of its final four u32 values; PhaseID is its sixth ID.
		aSubject, bSubject := a[7:7+GeneratorAuthoritySubjectLength], b[7:7+GeneratorAuthoritySubjectLength]
		if c := cmp.Compare(binary.BigEndian.Uint32(aSubject[1128:1132]), binary.BigEndian.Uint32(bSubject[1128:1132])); c != 0 {
			return c
		}
		if c := bytes.Compare(aSubject[164:196], bSubject[164:196]); c != 0 {
			return c
		}
		if c := cmp.Compare(a[2], b[2]); c != 0 {
			return c
		}
		return bytes.Compare(a[len(a)-32:], b[len(b)-32:])
	case GeneratorVectorConsumers:
		return bytes.Compare(a[2:], b[2:])
	case GeneratorVectorSlices:
		return bytes.Compare(a[2:35], b[2:35])
	case GeneratorVectorFacts:
		return bytes.Compare(a[2:34], b[2:34])
	default:
		return 0
	}
}

func GeneratorVectorDescriptor(kind GeneratorVectorKind, rows [][]byte) (GeneratorDescriptor, error) {
	minimum, _ := kind.rowBounds()
	if minimum == 0 {
		return GeneratorDescriptor{}, ErrRecord
	}
	if len(rows) > generatorSelectedSupportBytes/(generatorCarrierRowOverhead+minimum) {
		return GeneratorDescriptor{}, ErrRecordCapacity
	}
	n := 4
	for _, row := range rows {
		if len(row) > generatorSelectedSupportBytes-n-(generatorCarrierRowOverhead-4)*len(rows) {
			return GeneratorDescriptor{}, ErrRecordCapacity
		}
		n += 4 + len(row)
	}
	var previousHistory GeneratorHistory
	var seen map[ID]bool
	if kind == GeneratorVectorHistory {
		seen = make(map[ID]bool, len(rows))
	}
	for i, row := range rows {
		if err := inspectGeneratorVectorRow(kind, row); err != nil {
			return GeneratorDescriptor{}, err
		}
		if kind == GeneratorVectorHistory {
			v, err := InspectGeneratorHistory(row)
			if err != nil {
				return GeneratorDescriptor{}, err
			}
			if seen[v.PredecessorAttemptID] || i > 0 && previousHistory.NextAttemptID != v.PredecessorAttemptID ||
				i == len(rows)-1 && !v.NextAttemptID.IsZero() {
				return GeneratorDescriptor{}, ErrRecord
			}
			seen[v.PredecessorAttemptID] = true
			previousHistory = v
		} else if i > 0 && generatorVectorRowCompare(kind, rows[i-1], row) >= 0 {
			return GeneratorDescriptor{}, ErrRecord
		}
	}
	w := generatorVectorHashWriter(kind.label(), n, len(rows))
	for _, row := range rows {
		w.blob(row)
	}
	return generatorVectorResult(&w, n, len(rows)), nil
}

func GeneratorLogicalSlicesDescriptor(rows []GeneratorLogicalSlice) (GeneratorDescriptor, error) {
	if len(rows) > generatorSelectedSupportBytes/(generatorCarrierRowOverhead+GeneratorSliceLocationLength) {
		return GeneratorDescriptor{}, ErrRecordCapacity
	}
	for i, row := range rows {
		if !row.valid() || i > 0 && (rows[i-1].ContentKind > row.ContentKind || rows[i-1].ContentKind == row.ContentKind && bytes.Compare(rows[i-1].ContentID[:], row.ContentID[:]) >= 0) {
			return GeneratorDescriptor{}, ErrRecord
		}
	}
	n := 4 + len(rows)*(4+GeneratorLogicalSliceLength)
	w := generatorVectorHashWriter("logical-slices", n, len(rows))
	for _, row := range rows {
		w.u32(GeneratorLogicalSliceLength)
		writeGeneratorLogicalSlice(&w, row)
	}
	return generatorVectorResult(&w, n, len(rows)), nil
}

// GeneratorVectorCarrier borrows Row. Whole-vector membership and selected
// ownership are checked against the authenticated descriptor anchor, not here.
type GeneratorVectorCarrier struct {
	Schema     uint16
	DomainID   ID
	OwnerKind  uint8
	OwnerID    ID
	VectorKind GeneratorVectorKind
	Ordinal    uint32
	Vector     GeneratorDescriptor
	Row        []byte
}

func (v GeneratorVectorCarrier) validate() error {
	if len(v.Row) > GeneratorFactsRowMaxLength {
		return ErrRecordCapacity
	}
	if v.Schema != GeneratorRecordSchema || !publicIDsValid(v.DomainID, v.OwnerID) || !generatorVectorOwnerValid(v.OwnerKind, v.VectorKind) ||
		!GeneratorVectorShapeValid(v.VectorKind, v.Vector) || v.Ordinal >= v.Vector.Count {
		return ErrRecord
	}
	return inspectGeneratorVectorRow(v.VectorKind, v.Row)
}

func EncodeGeneratorVectorCarrier(v GeneratorVectorCarrier) ([]byte, error) {
	if err := v.validate(); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, GeneratorCarrierFixedLength+len(v.Row))}
	w.u16(v.Schema)
	w.id(v.DomainID)
	w.u8(v.OwnerKind)
	w.id(v.OwnerID)
	w.u8(uint8(v.VectorKind))
	w.u32(v.Ordinal)
	writeGeneratorDescriptor(&w, v.Vector)
	w.blob(v.Row)
	return w.b, nil
}

func InspectGeneratorVectorCarrier(b []byte) (GeneratorVectorCarrier, error) {
	if len(b) > generatorCarrierMaxLength {
		return GeneratorVectorCarrier{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GeneratorVectorCarrier{Schema: r.u16(), DomainID: r.requiredID(), OwnerKind: r.u8(), OwnerID: r.requiredID(),
		VectorKind: GeneratorVectorKind(r.u8()), Ordinal: r.u32(), Vector: readGeneratorDescriptor(&r), Row: r.blob(GeneratorFactsRowMaxLength)}
	if err := r.end(); err != nil {
		return GeneratorVectorCarrier{}, err
	}
	if err := v.validate(); err != nil {
		return GeneratorVectorCarrier{}, err
	}
	return v, nil
}

func GeneratorVectorCarrierID(v GeneratorVectorCarrier) (ID, error) {
	if err := v.validate(); err != nil {
		return ID{}, err
	}
	w := cryptoWriter{b: make([]byte, 0, 114)}
	w.id(v.DomainID)
	w.u8(v.OwnerKind)
	w.id(v.OwnerID)
	w.u8(uint8(v.VectorKind))
	writeGeneratorDescriptor(&w, v.Vector)
	w.u32(v.Ordinal)
	return generatorDigest("support-vector-row", w.b), nil
}

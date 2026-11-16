package contract

import "bytes"

type GeneratorRecordSetKind uint8

const (
	GeneratorPhaseResults GeneratorRecordSetKind = iota + 1
	GeneratorPhaseAttempts
	GeneratorPhaseDuties
	GeneratorPhaseHazards
	GeneratorPhaseReleases
	GeneratorHazardResults
)

func (k GeneratorRecordSetKind) label() string {
	switch k {
	case GeneratorPhaseResults:
		return "phase-results"
	case GeneratorPhaseAttempts:
		return "phase-attempts"
	case GeneratorPhaseDuties:
		return "phase-duties"
	case GeneratorPhaseHazards:
		return "phase-hazards"
	case GeneratorPhaseReleases:
		return "phase-releases"
	case GeneratorHazardResults:
		return "hazard-results"
	default:
		return ""
	}
}

func (k GeneratorRecordSetKind) permits(kind uint8) bool {
	switch k {
	case GeneratorPhaseResults:
		return kind == GeneratedResultSupportKind
	case GeneratorPhaseAttempts:
		return kind == GeneratedAttemptSupportKind
	case GeneratorPhaseDuties:
		return kind == GeneratedDutySupportKind
	case GeneratorPhaseHazards:
		return kind == GeneratedHazardSupportKind
	case GeneratorPhaseReleases:
		return kind == PendingInboxReleaseSupportKind
	case GeneratorHazardResults:
		return kind == GeneratedResultSupportKind || kind == GeneratedCreateEvidenceSupportKind
	default:
		return false
	}
}

func (k GeneratorRecordSetKind) bodyBounds() (int, int) {
	switch k {
	case GeneratorPhaseResults:
		return 16 + GeneratedResultCoreLength + 115 + CanonicalPayloadOverhead + transferEnvelopeMaxLength, GeneratedResultRecordMaxLength
	case GeneratorPhaseAttempts:
		return GeneratedAttemptRecordFixedLength, GeneratedAttemptRecordBodyLength
	case GeneratorPhaseDuties:
		return GeneratedDutyRecordFixedLength, GeneratedDutyRecordBodyLength
	case GeneratorPhaseHazards:
		return GeneratedHazardRecordBodyLength, GeneratedHazardRecordBodyLength
	case GeneratorPhaseReleases:
		return PendingInboxReleaseRecordBodyLength, PendingInboxReleaseRecordBodyLength
	case GeneratorHazardResults:
		return 687, GeneratedResultRecordMaxLength
	default:
		return 0, 0
	}
}

func EmptyGeneratorRecordSet(kind GeneratorRecordSetKind) GeneratorDescriptor {
	if kind.label() == "" {
		return GeneratorDescriptor{}
	}
	return GeneratorDescriptor{Digest: generatorDigest(kind.label(), []byte{0, 0, 0, 0}), Length: 4}
}

func GeneratorRecordSetShapeValid(kind GeneratorRecordSetKind, d GeneratorDescriptor) bool {
	minimum, maximum := kind.bodyBounds()
	if minimum == 0 || !d.Valid() {
		return false
	}
	if d.Count == 0 {
		return d == EmptyGeneratorRecordSet(kind)
	}
	n := uint64(d.Count)
	return d.Length >= 4+(4+SupportRecordOverhead+uint64(minimum))*n &&
		d.Length <= 4+(4+SupportRecordOverhead+uint64(maximum))*n &&
		d.Length-4-4*n <= generatorSelectedSupportBytes
}

// GeneratorRecordSetDescriptor commits complete selected support rows without
// storing another carrier. Callers derive membership from live owner relations;
// neither this descriptor nor a row's presence establishes reachability.
func GeneratorRecordSetDescriptor(kind GeneratorRecordSetKind, domain ID, rows []SupportRecord) (GeneratorDescriptor, error) {
	minimum, _ := kind.bodyBounds()
	if domain.IsZero() || minimum == 0 {
		return GeneratorDescriptor{}, ErrRecord
	}
	if len(rows) > generatorSelectedSupportBytes/(SupportRecordOverhead+minimum) {
		return GeneratorDescriptor{}, ErrRecordCapacity
	}
	total := 0
	for _, row := range rows {
		if len(row.Body) > generatorSelectedSupportBytes-total-SupportRecordOverhead {
			return GeneratorDescriptor{}, ErrRecordCapacity
		}
		total += SupportRecordOverhead + len(row.Body)
	}
	for i, row := range rows {
		if !kind.permits(row.Kind) || i > 0 && bytes.Compare(rows[i-1].RecordID[:], row.RecordID[:]) >= 0 {
			return GeneratorDescriptor{}, ErrRecord
		}
		actual, err := SupportRecordDomain(row)
		if err != nil {
			return GeneratorDescriptor{}, err
		}
		if actual != domain {
			return GeneratorDescriptor{}, ErrRecord
		}
	}
	n := 4 + 4*len(rows) + total
	w := generatorVectorHashWriter(kind.label(), n, len(rows))
	for _, row := range rows {
		w.u32(uint32(SupportRecordOverhead + len(row.Body)))
		writeSupportRecord(&w, row.Kind, row.RecordID, len(row.Body), func(w *cryptoWriter) { w.raw(row.Body) })
	}
	return generatorVectorResult(&w, n, len(rows)), nil
}

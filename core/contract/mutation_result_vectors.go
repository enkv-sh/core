package contract

// MutationResultRecordKind selects one of the three exact live-record vectors
// carried by a mutation result. Vector order is supplied by the operation
// owner; record-page and provider-completion order do not replace it.
type MutationResultRecordKind uint8

const (
	MutationResultEffects MutationResultRecordKind = iota + 1
	MutationResultDuties
	MutationResultHazards
)

func (k MutationResultRecordKind) label() string {
	switch k {
	case MutationResultEffects:
		return "effect-results"
	case MutationResultDuties:
		return "result-duties"
	case MutationResultHazards:
		return "result-hazards"
	default:
		return ""
	}
}

func (k MutationResultRecordKind) supportKind() SupportRecordKind {
	switch k {
	case MutationResultEffects:
		return GeneratedAttemptSupportKind
	case MutationResultDuties:
		return GeneratedDutySupportKind
	case MutationResultHazards:
		return GeneratedHazardSupportKind
	default:
		return 0
	}
}

// MutationResultRecordDescriptor commits exact typed support records in
// Product result order. It does not retain another copy of those records.
func MutationResultRecordDescriptor(kind MutationResultRecordKind, domain ID, rows []SupportRecord) (GeneratorDescriptor, error) {
	label, supportKind := kind.label(), kind.supportKind()
	if label == "" || domain.IsZero() {
		return GeneratorDescriptor{}, ErrRecord
	}
	if len(rows) > generatorSelectedSupportBytes/SupportRecordMinLength {
		return GeneratorDescriptor{}, ErrRecordCapacity
	}
	seen := make(map[ID]bool, len(rows))
	total := 4
	for _, row := range rows {
		if row.Kind != supportKind || seen[row.RecordID] {
			return GeneratorDescriptor{}, ErrRecord
		}
		actual, err := SupportRecordDomain(row)
		if err != nil {
			return GeneratorDescriptor{}, err
		}
		if actual != domain {
			return GeneratorDescriptor{}, ErrRecord
		}
		if len(row.Body) > generatorSelectedSupportBytes-total-SupportRecordOverhead-4 {
			return GeneratorDescriptor{}, ErrRecordCapacity
		}
		seen[row.RecordID] = true
		total += 4 + SupportRecordOverhead + len(row.Body)
	}
	w := generatorVectorHashWriter(label, total, len(rows))
	for _, row := range rows {
		w.u32(uint32(SupportRecordOverhead + len(row.Body)))
		writeSupportRecord(&w, row.Kind, row.RecordID, len(row.Body), func(w *cryptoWriter) { w.raw(row.Body) })
	}
	return generatorVectorResult(&w, total, len(rows)), nil
}

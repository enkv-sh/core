package contract

const (
	GeneratorControlledGraphMaxLength      = 256 << 10
	GeneratorControlledResultMaxLength     = 8 << 10
	GeneratorControlledSeedAccessMaxLength = AccessRecordFixedLength + 2*WrapRowWireLength
)

type selectedGeneratorVectorKey struct {
	ownerKind uint8
	owner     ID
	kind      GeneratorVectorKind
	vector    GeneratorDescriptor
}

type selectedGeneratorVectorRows struct {
	ordinals map[uint32][]byte
	ordered  [][]byte
}

// SelectedGeneratorVectorIndex borrows one authenticated support view for one
// synchronous validation pass. It does not retain a selection or custody right.
type SelectedGeneratorVectorIndex struct {
	recordCount int
	groups      map[selectedGeneratorVectorKey]*selectedGeneratorVectorRows
}

func NewSelectedGeneratorVectorIndex(domain ID, records []SupportRecord) (*SelectedGeneratorVectorIndex, error) {
	if domain.IsZero() || len(records) > requiredSupportMaxRecords {
		return nil, ErrRecord
	}
	index := &SelectedGeneratorVectorIndex{recordCount: len(records), groups: make(map[selectedGeneratorVectorKey]*selectedGeneratorVectorRows)}
	for _, row := range records {
		if row.Kind != GeneratorVectorSupportKind {
			continue
		}
		carrier, err := InspectGeneratorVectorCarrier(row.Body)
		if err != nil || carrier.DomainID != domain {
			return nil, ErrRecord
		}
		id, err := GeneratorVectorCarrierID(carrier)
		if err != nil || id != row.RecordID {
			return nil, ErrRecord
		}
		key := selectedGeneratorVectorKey{carrier.OwnerKind, carrier.OwnerID, carrier.VectorKind, carrier.Vector}
		group := index.groups[key]
		if group == nil {
			group = &selectedGeneratorVectorRows{ordinals: make(map[uint32][]byte)}
			index.groups[key] = group
		}
		if _, duplicate := group.ordinals[carrier.Ordinal]; duplicate {
			return nil, ErrRecord
		}
		group.ordinals[carrier.Ordinal] = carrier.Row
	}
	return index, nil
}

func (index *SelectedGeneratorVectorIndex) Inspect(ownerKind uint8, owner ID, kind GeneratorVectorKind, descriptor GeneratorDescriptor, visit func(uint32, []byte) error) error {
	if index == nil || owner.IsZero() || !GeneratorVectorShapeValid(kind, descriptor) || uint64(descriptor.Count) > uint64(index.recordCount) {
		return ErrRecord
	}
	group := index.groups[selectedGeneratorVectorKey{ownerKind, owner, kind, descriptor}]
	if descriptor.Count == 0 {
		if group != nil {
			return ErrRecord
		}
		return nil
	}
	if group == nil || len(group.ordinals) != int(descriptor.Count) {
		return ErrRecord
	}
	if group.ordered == nil {
		rows := make([][]byte, descriptor.Count)
		for ordinal, row := range group.ordinals {
			if ordinal >= descriptor.Count {
				return ErrRecord
			}
			rows[ordinal] = row
		}
		for _, row := range rows {
			if row == nil {
				return ErrRecord
			}
		}
		actual, err := GeneratorVectorDescriptor(kind, rows)
		if err != nil || actual != descriptor {
			return ErrRecord
		}
		group.ordered = rows
	}
	if visit != nil {
		for ordinal, row := range group.ordered {
			if err := visit(uint32(ordinal), row); err != nil {
				return err
			}
		}
	}
	return nil
}

// GeneratedControlledPredecessor carries the exact immutable source witness and,
// for step two, its retained acknowledgement custody. It grants no authority;
// the private owner validates every binding and authenticates the result.
type GeneratedControlledPredecessor struct {
	Source                    SupportRecord
	BeforeRecords             []SupportRecord
	Graph, SeedAccess, Result []byte
	Expected                  GeneratorResultExpectation
	Material                  OperationMaterialRecord
}

// InspectGeneratorSelectedVector validates an entire descriptor-bound vector
// and visits each borrowed row synchronously. It has no retained full-vector
// copy or invocation-count limit. Complete support must be pinned by admission.
func InspectGeneratorSelectedVector(domain ID, ownerKind uint8, owner ID, kind GeneratorVectorKind, descriptor GeneratorDescriptor, records []SupportRecord, visit func(uint32, []byte) error) error {
	index, err := NewSelectedGeneratorVectorIndex(domain, records)
	if err != nil {
		return err
	}
	return index.Inspect(ownerKind, owner, kind, descriptor, visit)
}

// GeneratedDeleteSource is a decoded, closed kind-10/kind-11 record. SourceID
// identifies the retained record; OwnerID identifies its immutable lineage.
// A Hazard is never represented by a fabricated Duty.
type GeneratedDeleteSource struct {
	Record                                                                    SupportRecord
	Duty                                                                      GeneratedDutyRecord
	Hazard                                                                    GeneratedHazardRecord
	DomainID, SourceID, OwnerID, OriginalOperationID, OriginalAttemptID       ID
	ResourceID, DescriptorID, ConfigContractID, ExecutorID, CredentialRouteID ID
	ResourceContractID, ResultContractID                                      ID
	CompletionClass                                                           uint8
	CapacityReservation, Target, History, Consumers, Support                  GeneratorDescriptor
}

func InspectGeneratedDeleteSource(row SupportRecord) (GeneratedDeleteSource, error) {
	v := GeneratedDeleteSource{Record: row, SourceID: row.RecordID}
	switch row.Kind {
	case GeneratedDutySupportKind:
		d, err := InspectGeneratedDutyRecord(row.Body)
		if err != nil || d.DutyID != row.RecordID {
			return v, ErrRecord
		}
		v.Duty = d
		v.DomainID, v.OwnerID, v.OriginalOperationID, v.OriginalAttemptID = d.DomainID, d.OwnerID, d.OriginalOperationID, d.OriginalAttemptID
		v.ResourceID, v.DescriptorID, v.ConfigContractID, v.ExecutorID, v.CredentialRouteID = d.ResourceID, d.DescriptorID, d.ConfigContractID, d.ExecutorID, d.CredentialRouteID
		v.ResourceContractID, v.ResultContractID, v.CapacityReservation = d.ResourceContractID, d.ResultContractID, d.CapacityReservation
		v.CompletionClass, v.Target, v.History, v.Consumers, v.Support = d.CompletionClass, d.Target, d.History, d.Consumers, d.Support
	case GeneratedHazardSupportKind:
		h, err := InspectGeneratedHazardRecord(row.Body)
		if err != nil || h.HazardID != row.RecordID {
			return v, ErrRecord
		}
		v.Hazard = h
		v.DomainID, v.OwnerID, v.OriginalOperationID, v.OriginalAttemptID = h.DomainID, h.OwnerID, h.OriginalOperationID, h.OriginalAttemptID
		v.ResourceID, v.DescriptorID, v.ConfigContractID, v.ExecutorID, v.CredentialRouteID = h.ResourceID, h.DescriptorID, h.ConfigContractID, h.ExecutorID, h.CredentialRouteID
		v.ResourceContractID, v.ResultContractID, v.CapacityReservation = h.ResourceContractID, h.ResultContractID, h.CapacityReservation
		v.CompletionClass, v.Target, v.History, v.Consumers, v.Support = h.CompletionClass, h.Target, h.History, h.Consumers, h.Support
	default:
		return v, ErrRecord
	}
	return v, nil
}

// This closed test scope is the exact local challenge responder only. It is
// never a provider-wide invalidation claim or a dispatch capability.
func GeneratorControlledRetirementScope(descriptor, config, resultContract ID) ID {
	b := append([]byte("enkv/generated/controlled-retirement-scope/v2\x00"), descriptor[:]...)
	b = append(b, config[:]...)
	b = append(b, resultContract[:]...)
	return Hash(b)
}

func GeneratorControlledRetirementProbeDigest(domain, resource, resourceDigest, scope, result, body ID) ID {
	b := []byte("enkv/generated/controlled-retirement-probe/v2\x00")
	for _, id := range []ID{domain, resource, resourceDigest, scope, result, body} {
		b = append(b, id[:]...)
	}
	return Hash(b)
}

package contract

const (
	GeneratorCapacityCurrentValueEntries = 0
	GeneratorCapacityCurrentRecipients   = 1
	GeneratorCapacityCurrentAccess       = 2
	GeneratorCapacityOldValues           = 3
	GeneratorCapacityOldAccess           = 4
	GeneratorCapacityCandidateValues     = 5
	GeneratorCapacityCandidateAccess     = 6
	GeneratorCapacityCreateResults       = 7
	GeneratorCapacitySeedAccess          = 8
	GeneratorCapacityMaterial            = 9
	GeneratorCapacityCreates             = 10
	GeneratorCapacityDeletes             = 11
	GeneratorCapacityOwners              = 12
	GeneratorCapacityReceipts            = 13
	GeneratorCapacityIntents             = 14
	GeneratorCapacityGraph               = 15
	GeneratorCapacityAuxiliary           = 16
	GeneratorCapacityGroupCount          = 17
)

const generatorCapacityGroupLength = 1 + 8 + 8 + 4
const GeneratorCapacityEvidenceLength = 2 + 2*32 + descriptorSize + 4 + GeneratorCapacityGroupCount*generatorCapacityGroupLength

type GeneratorCapacityGroup struct {
	MaxCount, MaxFramedBytes uint64
	MaxPages                 uint32
}

// GeneratorCapacityEvidence commits Core's complete pre-effect calculation.
// Parsing establishes bounded framing, not that the charged groups cover all
// live work. Core derives the charges from the selected state and fixed graph.
type GeneratorCapacityEvidence struct {
	Schema                        uint16
	BeforeRootDigest, PlanGraphID ID
	Declaration                   GeneratorDescriptor
	Groups                        [GeneratorCapacityGroupCount]GeneratorCapacityGroup
}

func (v GeneratorCapacityEvidence) validate() error {
	if v.Schema != GeneratorRecordSchema || !publicIDsValid(v.BeforeRootDigest, v.PlanGraphID) || !v.Declaration.Valid() {
		return ErrRecord
	}
	return generatorCapacityGroupsError(&v.Groups)
}

func generatorCapacityGroupsError(groups *[GeneratorCapacityGroupCount]GeneratorCapacityGroup) error {
	pages := uint32(0)
	for _, group := range groups {
		if group.MaxPages > MaxChildPages-pages {
			return ErrRecordCapacity
		}
		if group.MaxCount == 0 || group.MaxFramedBytes == 0 || group.MaxPages == 0 {
			if group != (GeneratorCapacityGroup{}) {
				return ErrRecord
			}
		} else if group.MaxCount > group.MaxFramedBytes || group.MaxFramedBytes > uint64(group.MaxPages)*(MaxRequiredSupportPageLength-RequiredSupportPageHeaderLength) {
			return ErrRecordCapacity
		}
		pages += group.MaxPages
	}
	return nil
}

func writeGeneratorCapacityGroups(w *cryptoWriter, groups *[GeneratorCapacityGroupCount]GeneratorCapacityGroup) {
	w.u32(GeneratorCapacityGroupCount)
	for i, group := range groups {
		w.u8(uint8(i + 1))
		w.u64(group.MaxCount)
		w.u64(group.MaxFramedBytes)
		w.u32(group.MaxPages)
	}
}

func readGeneratorCapacityGroups(r *cryptoReader) (groups [GeneratorCapacityGroupCount]GeneratorCapacityGroup) {
	if r.u32() != GeneratorCapacityGroupCount {
		r.err = ErrRecord
		return groups
	}
	for i := range groups {
		if r.u8() != uint8(i+1) {
			r.err = ErrRecord
			return groups
		}
		groups[i] = GeneratorCapacityGroup{MaxCount: r.u64(), MaxFramedBytes: r.u64(), MaxPages: r.u32()}
	}
	return groups
}

func writeGeneratorCapacityEvidence(w *cryptoWriter, v GeneratorCapacityEvidence) {
	w.u16(v.Schema)
	w.id(v.BeforeRootDigest)
	w.id(v.PlanGraphID)
	writeGeneratorDescriptor(w, v.Declaration)
	writeGeneratorCapacityGroups(w, &v.Groups)
}

func EncodeGeneratorCapacityEvidence(v GeneratorCapacityEvidence) ([]byte, error) {
	if err := v.validate(); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, GeneratorCapacityEvidenceLength)}
	writeGeneratorCapacityEvidence(&w, v)
	return w.b, nil
}

func InspectGeneratorCapacityEvidence(body []byte) (GeneratorCapacityEvidence, error) {
	if len(body) > GeneratorCapacityEvidenceLength {
		return GeneratorCapacityEvidence{}, ErrRecordCapacity
	}
	r := newRecordReader(body)
	v := GeneratorCapacityEvidence{Schema: r.u16(), BeforeRootDigest: r.requiredID(), PlanGraphID: r.requiredID(), Declaration: readGeneratorDescriptor(&r)}
	v.Groups = readGeneratorCapacityGroups(&r)
	if err := r.end(); err != nil {
		return GeneratorCapacityEvidence{}, err
	}
	if err := v.validate(); err != nil {
		return GeneratorCapacityEvidence{}, err
	}
	return v, nil
}

func GeneratorCapacityDescriptor(v GeneratorCapacityEvidence) (GeneratorDescriptor, error) {
	if err := v.validate(); err != nil {
		return GeneratorDescriptor{}, err
	}
	const length = GeneratorCapacityEvidenceLength + 8
	w := generatorVectorHashWriter("capacity-reservation", length, 1)
	w.u32(GeneratorCapacityEvidenceLength)
	writeGeneratorCapacityEvidence(&w, v)
	return generatorVectorResult(&w, length, 1), nil
}

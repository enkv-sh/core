package contract

const GeneratedNormalCapacityLength = 2 + 2*32 + descriptorSize + 4 + GeneratorCapacityGroupCount*generatorCapacityGroupLength

// GeneratedNormalCapacity is closed normal-selection evidence. It is not a
// generated Parent reservation and creates no dispatch permission.
type GeneratedNormalCapacity struct {
	Schema                         uint16
	BeforeRootDigest, TransitionID ID
	Intent                         DescriptorVector
	Groups                         [GeneratorCapacityGroupCount]GeneratorCapacityGroup
}

func (v GeneratedNormalCapacity) checkedGroups() error {
	if v.Schema != 1 || !publicIDsValid(v.BeforeRootDigest, v.TransitionID) || v.Intent.Digest.IsZero() || v.Intent.Count > CryptoMaxValueEntries || v.Intent.Length == 0 || v.Intent.Length > CryptoRequestLimit {
		return ErrRecord
	}
	return generatorCapacityGroupsError(&v.Groups)
}

func writeGeneratedNormalCapacity(w *cryptoWriter, v GeneratedNormalCapacity) {
	w.u16(v.Schema)
	w.id(v.BeforeRootDigest)
	w.id(v.TransitionID)
	w.descriptor(v.Intent)
	writeGeneratorCapacityGroups(w, &v.Groups)
}

func EncodeGeneratedNormalCapacity(v GeneratedNormalCapacity) ([]byte, error) {
	if err := v.checkedGroups(); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, GeneratedNormalCapacityLength)}
	writeGeneratedNormalCapacity(&w, v)
	return w.b, nil
}

func InspectGeneratedNormalCapacity(body []byte) (GeneratedNormalCapacity, error) {
	if len(body) > GeneratedNormalCapacityLength {
		return GeneratedNormalCapacity{}, ErrRecordCapacity
	}
	r := newRecordReader(body)
	v := GeneratedNormalCapacity{Schema: r.u16(), BeforeRootDigest: r.requiredID(), TransitionID: r.requiredID(), Intent: r.descriptor()}
	v.Groups = readGeneratorCapacityGroups(&r)
	if err := r.end(); err != nil {
		return GeneratedNormalCapacity{}, err
	}
	if err := v.checkedGroups(); err != nil {
		return GeneratedNormalCapacity{}, err
	}
	return v, nil
}

func GeneratedNormalCapacityDescriptor(v GeneratedNormalCapacity) (GeneratorDescriptor, error) {
	if err := v.checkedGroups(); err != nil {
		return GeneratorDescriptor{}, err
	}
	const length = GeneratedNormalCapacityLength + 8
	w := generatorVectorHashWriter("normal-handoff-capacity", length, 1)
	w.u32(GeneratedNormalCapacityLength)
	writeGeneratedNormalCapacity(&w, v)
	return generatorVectorResult(&w, length, 1), nil
}

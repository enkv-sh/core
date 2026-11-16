package contract

import "bytes"

const (
	GenesisBootstrapLimit = 32 << 10
	genesisManifestPrefix = cryptoPurposePrefix + "genesis-bootstrap-manifest-v1\x00"
	genesisClosurePrefix  = cryptoPurposePrefix + "genesis-bootstrap-closure-v1\x00"
)

type GenesisSignerPlanRow struct {
	TargetRole           uint8
	SigningBindingDigest ID
}
type GenesisPublicBindingRow struct {
	SubjectKind                               uint8
	SubjectID, BindingID, PublicBindingDigest ID
}
type GenesisBootstrapManifestCore struct {
	DescriptorDigest, RequestCoreDigest, GenesisPlanDigest, NormalBindingSubjectDigest ID
	RecoveryMode                                                                       uint8
	K3BasisSubjectDigest, K3InitChallengeCoreDigest                                    ID
	Signers                                                                            []GenesisSignerPlanRow
	PublicBindings                                                                     []GenesisPublicBindingRow
	Probes                                                                             []InitProbePlanRow
	Immutable                                                                          []Ref
	HeadCoreDigest                                                                     ID
	HeadCoreLength                                                                     uint32
	ConditionalPlanDigest                                                              ID
}

func genesisRecoveryDigestsValid(mode uint8, basis, challenge ID) bool {
	return mode == 0 && basis.IsZero() && challenge.IsZero() || mode == 1 && !basis.IsZero() && !challenge.IsZero()
}
func genesisImmutableValid(refs []Ref) bool {
	if len(refs) < 5 || len(refs) > MaxRecipientPages+4 {
		return false
	}
	var objects [MaxRecipientPages + 4]ID
	for i, ref := range refs {
		if !ref.ValidFor(CanonicalSchema) || ref.Domain != refs[0].Domain {
			return false
		}
		if i == len(refs)-1 {
			if ref.Kind != RootKind || ref.Index != 0 {
				return false
			}
		} else if i == len(refs)-2 || i == len(refs)-3 {
			if ref.Kind != RequiredSupportKind || ref.Index != uint16(i-(len(refs)-3)) {
				return false
			}
		} else if i == len(refs)-4 {
			if ref.Kind != AdministrativeIndexKind || ref.Index != 0 {
				return false
			}
		} else if ref.Kind != RecipientKind || ref.Index != uint16(i) {
			return false
		}
		for j := 0; j < i; j++ {
			if ref.Object == objects[j] {
				return false
			}
		}
		objects[i] = ref.Object
	}
	return true
}
func genesisSignersValid(rows []GenesisSignerPlanRow, mode uint8) bool {
	if len(rows) != 1+int(mode) {
		return false
	}
	for i, row := range rows {
		if row.TargetRole != uint8(1+2*i) || row.SigningBindingDigest.IsZero() {
			return false
		}
	}
	return true
}
func genesisPublicBindingsValid(rows []GenesisPublicBindingRow, mode uint8) bool {
	ordinary := len(rows) - int(mode)
	if ordinary < 1 || ordinary > CryptoMaxRecipients {
		return false
	}
	var previous GenesisPublicBindingRow
	var ids [CryptoMaxRecipients + 1]ID
	for i, row := range rows {
		if !publicIDsValid(row.SubjectID, row.BindingID) || (i < ordinary && row.SubjectKind != OrdinaryWrapSubject) || (i >= ordinary && row.SubjectKind != RecoveryWrapSubject) || i > 0 && (row.SubjectKind < previous.SubjectKind || row.SubjectKind == previous.SubjectKind && bytes.Compare(row.SubjectID[:], previous.SubjectID[:]) <= 0) {
			return false
		}
		for j := 0; j < i; j++ {
			if ids[j] == row.BindingID {
				return false
			}
		}
		previous = row
		ids[i] = row.BindingID
	}
	return true
}
func (v GenesisBootstrapManifestCore) valid() bool {
	if !publicIDsValid(v.DescriptorDigest, v.RequestCoreDigest, v.GenesisPlanDigest, v.NormalBindingSubjectDigest, v.HeadCoreDigest, v.ConditionalPlanDigest) || !genesisRecoveryDigestsValid(v.RecoveryMode, v.K3BasisSubjectDigest, v.K3InitChallengeCoreDigest) || !genesisSignersValid(v.Signers, v.RecoveryMode) || !genesisPublicBindingsValid(v.PublicBindings, v.RecoveryMode) || !initProbesValid(v.Probes) || len(v.Probes) != 1+int(v.RecoveryMode) || !genesisImmutableValid(v.Immutable) || v.HeadCoreLength != 349 {
		return false
	}
	if len(v.Immutable) != (len(v.PublicBindings)-int(v.RecoveryMode)+7)/8+4 {
		return false
	}
	for _, probe := range v.Probes {
		found := false
		for _, binding := range v.PublicBindings {
			if binding.SubjectKind == probe.SubjectKind && binding.SubjectID == probe.SubjectID && binding.BindingID == probe.BindingID && binding.PublicBindingDigest == probe.PublicBindingDigest {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func writeGenesisRecoveryDigests(w *cryptoWriter, mode uint8, basis, challenge ID) {
	w.u8(mode)
	if mode == 1 {
		w.id(basis)
		w.id(challenge)
	}
}
func readGenesisRecoveryDigests(r *cryptoReader) (uint8, ID, ID) {
	mode := r.u8()
	if mode == 0 {
		return mode, ID{}, ID{}
	}
	if mode != 1 {
		r.err = ErrRecord
		return mode, ID{}, ID{}
	}
	return mode, r.requiredID(), r.requiredID()
}
func writeGenesisManifest(w *cryptoWriter, v GenesisBootstrapManifestCore) {
	w.raw([]byte(genesisManifestPrefix))
	w.u16(CanonicalSchema)
	w.u16(GenesisProfile)
	for _, id := range []ID{v.DescriptorDigest, v.RequestCoreDigest, v.GenesisPlanDigest, v.NormalBindingSubjectDigest} {
		w.id(id)
	}
	writeGenesisRecoveryDigests(w, v.RecoveryMode, v.K3BasisSubjectDigest, v.K3InitChallengeCoreDigest)
	w.u8(uint8(len(v.Signers)))
	for _, row := range v.Signers {
		w.u8(row.TargetRole)
		w.id(row.SigningBindingDigest)
	}
	w.u16(uint16(len(v.PublicBindings)))
	for _, row := range v.PublicBindings {
		w.u8(row.SubjectKind)
		w.id(row.SubjectID)
		w.id(row.BindingID)
		w.id(row.PublicBindingDigest)
	}
	w.u8(uint8(len(v.Probes)))
	for _, row := range v.Probes {
		writeInitProbe(w, row)
	}
	writeHeadCondition(w, AbsentHeadCondition())
	w.u16(uint16(len(v.Immutable)))
	for _, ref := range v.Immutable {
		writeRef(w, ref)
	}
	w.id(v.HeadCoreDigest)
	w.u32(v.HeadCoreLength)
	w.id(v.ConditionalPlanDigest)
}
func EncodeGenesisBootstrapManifestCore(v GenesisBootstrapManifestCore) ([]byte, error) {
	if len(v.PublicBindings) > CryptoMaxRecipients+1 || len(v.Immutable) > MaxRecipientPages+4 {
		return nil, ErrRecordCapacity
	}
	if !v.valid() {
		return nil, ErrRecord
	}
	w := cryptoWriter{}
	writeGenesisManifest(&w, v)
	if len(w.b) > GenesisBootstrapLimit {
		return nil, ErrRecordCapacity
	}
	return w.b, nil
}
func DecodeGenesisBootstrapManifestCore(b []byte) (GenesisBootstrapManifestCore, error) {
	if len(b) > GenesisBootstrapLimit {
		return GenesisBootstrapManifestCore{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	if !bytes.Equal(r.take(len(genesisManifestPrefix)), []byte(genesisManifestPrefix)) || r.u16() != CanonicalSchema || r.u16() != GenesisProfile {
		return GenesisBootstrapManifestCore{}, ErrRecord
	}
	v := GenesisBootstrapManifestCore{DescriptorDigest: r.requiredID(), RequestCoreDigest: r.requiredID(), GenesisPlanDigest: r.requiredID(), NormalBindingSubjectDigest: r.requiredID()}
	v.RecoveryMode, v.K3BasisSubjectDigest, v.K3InitChallengeCoreDigest = readGenesisRecoveryDigests(&r)
	sc := int(r.u8())
	if sc < 1 || sc > 2 {
		return GenesisBootstrapManifestCore{}, ErrRecord
	}
	var signers [2]GenesisSignerPlanRow
	for i := 0; i < sc; i++ {
		signers[i] = GenesisSignerPlanRow{TargetRole: r.u8(), SigningBindingDigest: r.requiredID()}
	}
	pc := int(r.u16())
	if pc < 1 || pc > CryptoMaxRecipients+1 {
		return GenesisBootstrapManifestCore{}, ErrRecordCapacity
	}
	var public [CryptoMaxRecipients + 1]GenesisPublicBindingRow
	for i := 0; i < pc; i++ {
		public[i] = GenesisPublicBindingRow{SubjectKind: r.u8(), SubjectID: r.requiredID(), BindingID: r.requiredID(), PublicBindingDigest: r.id()}
	}
	np := int(r.u8())
	if np < 1 || np > 2 {
		return GenesisBootstrapManifestCore{}, ErrRecord
	}
	var probes [2]InitProbePlanRow
	for i := 0; i < np; i++ {
		probes[i] = readInitProbe(&r)
	}
	if r.u8() != 0 {
		return GenesisBootstrapManifestCore{}, ErrRecord
	}
	nr := int(r.u16())
	if nr < 4 || nr > MaxRecipientPages+4 {
		return GenesisBootstrapManifestCore{}, ErrRecordCapacity
	}
	var refs [MaxRecipientPages + 4]Ref
	for i := 0; i < nr; i++ {
		refs[i] = readRef(&r, CanonicalSchema)
	}
	v.HeadCoreDigest = r.requiredID()
	v.HeadCoreLength = r.u32()
	v.ConditionalPlanDigest = r.requiredID()
	if err := r.end(); err != nil {
		return GenesisBootstrapManifestCore{}, err
	}
	v.Signers = signers[:sc]
	v.PublicBindings = public[:pc]
	v.Probes = probes[:np]
	v.Immutable = refs[:nr]
	if !v.valid() {
		return GenesisBootstrapManifestCore{}, ErrRecord
	}
	v.Signers = append([]GenesisSignerPlanRow(nil), v.Signers...)
	v.PublicBindings = append([]GenesisPublicBindingRow(nil), v.PublicBindings...)
	v.Probes = append([]InitProbePlanRow(nil), v.Probes...)
	v.Immutable = append([]Ref(nil), v.Immutable...)
	return v, nil
}

type GenesisImmutableObservation struct {
	Ref                 Ref
	ReadbackObservation uint8
}
type GenesisBootstrapClosureCore struct {
	DescriptorDigest, RequestCoreDigest, GenesisPlanDigest, ManifestDigest  ID
	DescriptorReadbackFact, ManifestReadbackFact, ConfigurationReadbackFact GenesisArtifactFact
	InitialHeadObservation                                                  uint8
	QualifiedKeys                                                           GenesisQualifiedKeysCore
	NormalBindingSubjectDigest                                              ID
	RecoveryMode                                                            uint8
	K3BasisSubjectDigest, K3InitChallengeCoreDigest                         ID
	Signers                                                                 []SigningQualificationResult
	Immutable                                                               []GenesisImmutableObservation
}

func (v GenesisBootstrapClosureCore) valid() bool {
	if !publicIDsValid(v.DescriptorDigest, v.RequestCoreDigest, v.GenesisPlanDigest, v.ManifestDigest, v.NormalBindingSubjectDigest) || !v.DescriptorReadbackFact.valid() || !v.ManifestReadbackFact.valid() || !v.ConfigurationReadbackFact.valid() || v.DescriptorReadbackFact.Kind != 1 || v.ManifestReadbackFact.Kind != 2 || v.ConfigurationReadbackFact.Kind != 3 || v.DescriptorReadbackFact.BodyDigest != v.DescriptorDigest || v.ManifestReadbackFact.BodyDigest != v.ManifestDigest || v.InitialHeadObservation != 1 || !genesisQualifiedKeysValid(v.QualifiedKeys) || v.QualifiedKeys.DescriptorDigest != v.DescriptorDigest || v.QualifiedKeys.RequestCoreDigest != v.RequestCoreDigest || v.QualifiedKeys.GenesisPlanDigest != v.GenesisPlanDigest || !genesisRecoveryDigestsValid(v.RecoveryMode, v.K3BasisSubjectDigest, v.K3InitChallengeCoreDigest) || len(v.Signers) != 1+int(v.RecoveryMode) || len(v.QualifiedKeys.Private) != 1+int(v.RecoveryMode) || len(v.Immutable) > MaxRecipientPages+4 {
		return false
	}
	for i, row := range v.Signers {
		if row.TargetRole != uint8(1+2*i) || row.SigningBindingDigest.IsZero() || !row.Provider.Valid() || row.Qualified != 1 || row.Reason != ReasonNone || i > 0 && row.Provider != v.Signers[0].Provider {
			return false
		}
	}
	var refs [MaxRecipientPages + 4]Ref
	for i, row := range v.Immutable {
		if row.ReadbackObservation != 1 {
			return false
		}
		refs[i] = row.Ref
	}
	return genesisImmutableValid(refs[:len(v.Immutable)])
}
func writeGenesisSignerQualification(w *cryptoWriter, v SigningQualificationResult) {
	w.u8(v.TargetRole)
	w.id(v.SigningBindingDigest)
	w.u8(uint8(v.Provider))
	w.u8(v.Qualified)
}
func readGenesisSignerQualification(r *cryptoReader) SigningQualificationResult {
	return SigningQualificationResult{TargetRole: r.u8(), SigningBindingDigest: r.requiredID(), Provider: Family(r.u8()), Qualified: r.u8()}
}
func writeGenesisClosure(w *cryptoWriter, v GenesisBootstrapClosureCore, keys []byte) {
	w.raw([]byte(genesisClosurePrefix))
	w.u16(CanonicalSchema)
	w.u16(GenesisProfile)
	for _, id := range []ID{v.DescriptorDigest, v.RequestCoreDigest, v.GenesisPlanDigest, v.ManifestDigest} {
		w.id(id)
	}
	writeGenesisArtifactFact(w, v.DescriptorReadbackFact)
	writeGenesisArtifactFact(w, v.ManifestReadbackFact)
	writeGenesisArtifactFact(w, v.ConfigurationReadbackFact)
	w.u8(v.InitialHeadObservation)
	w.blob(keys)
	w.id(v.NormalBindingSubjectDigest)
	writeGenesisRecoveryDigests(w, v.RecoveryMode, v.K3BasisSubjectDigest, v.K3InitChallengeCoreDigest)
	w.u8(uint8(len(v.Signers)))
	for _, row := range v.Signers {
		writeGenesisSignerQualification(w, row)
	}
	w.u16(uint16(len(v.Immutable)))
	for _, row := range v.Immutable {
		writeRef(w, row.Ref)
		w.u8(row.ReadbackObservation)
	}
}
func EncodeGenesisBootstrapClosureCore(v GenesisBootstrapClosureCore) ([]byte, error) {
	if !v.valid() {
		return nil, ErrRecord
	}
	keys, err := EncodeGenesisQualifiedKeysCore(v.QualifiedKeys)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{}
	writeGenesisClosure(&w, v, keys)
	if len(w.b) > GenesisBootstrapLimit {
		return nil, ErrRecordCapacity
	}
	return w.b, nil
}
func DecodeGenesisBootstrapClosureCore(b []byte) (GenesisBootstrapClosureCore, error) {
	if len(b) > GenesisBootstrapLimit {
		return GenesisBootstrapClosureCore{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	if !bytes.Equal(r.take(len(genesisClosurePrefix)), []byte(genesisClosurePrefix)) || r.u16() != CanonicalSchema || r.u16() != GenesisProfile {
		return GenesisBootstrapClosureCore{}, ErrRecord
	}
	v := GenesisBootstrapClosureCore{DescriptorDigest: r.requiredID(), RequestCoreDigest: r.requiredID(), GenesisPlanDigest: r.requiredID(), ManifestDigest: r.requiredID(), DescriptorReadbackFact: readGenesisArtifactFact(&r), ManifestReadbackFact: readGenesisArtifactFact(&r), ConfigurationReadbackFact: readGenesisArtifactFact(&r), InitialHeadObservation: r.u8()}
	keys := r.blob(GenesisQualifiedKeysMaxLength)
	v.NormalBindingSubjectDigest = r.requiredID()
	v.RecoveryMode, v.K3BasisSubjectDigest, v.K3InitChallengeCoreDigest = readGenesisRecoveryDigests(&r)
	ns := int(r.u8())
	if ns < 1 || ns > 2 {
		return GenesisBootstrapClosureCore{}, ErrRecord
	}
	var signers [2]SigningQualificationResult
	for i := 0; i < ns; i++ {
		signers[i] = readGenesisSignerQualification(&r)
	}
	nr := int(r.u16())
	if nr < 4 || nr > MaxRecipientPages+4 {
		return GenesisBootstrapClosureCore{}, ErrRecordCapacity
	}
	var refs [MaxRecipientPages + 4]GenesisImmutableObservation
	for i := 0; i < nr; i++ {
		refs[i] = GenesisImmutableObservation{Ref: readRef(&r, CanonicalSchema), ReadbackObservation: r.u8()}
	}
	if err := r.end(); err != nil {
		return GenesisBootstrapClosureCore{}, err
	}
	var err error
	v.QualifiedKeys, err = DecodeGenesisQualifiedKeysCore(keys)
	if err != nil {
		return GenesisBootstrapClosureCore{}, err
	}
	v.Signers = signers[:ns]
	v.Immutable = refs[:nr]
	if !v.valid() {
		return GenesisBootstrapClosureCore{}, ErrRecord
	}
	v.Signers = append([]SigningQualificationResult(nil), v.Signers...)
	v.Immutable = append([]GenesisImmutableObservation(nil), v.Immutable...)
	return v, nil
}

package contract

import "bytes"

const (
	GenesisProfile                uint16 = 1
	InitKeyContextLength                 = 280
	GenesisKEKProbeCoreLength            = 385
	InitProbePlanRowLength               = 129
	GenesisQualifiedKeysMaxLength        = 25881
	CryptoInitRequestLimit               = 512 << 10
	CryptoInitResponseLimit              = 256 << 10
	InitKeyUseRowsMaxCount               = 1036
	genesisQualifiedKeysPrefix           = cryptoPurposePrefix + "genesis-qualified-keys-v1\x00"
)

// InitKeyContext is a public copy of private parent admission. It has no
// predecessor, selected-state authority, or permission-bearing constructor.
type InitKeyContext struct {
	Schema, GenesisProfile                            uint16
	AdmissionID, SessionID, DomainID, CompatibilityID ID
	Expiry                                            uint64
	InitID, DescriptorDigest, GenesisPlanDigest       ID
	RequestDescriptor                                 DescriptorVector
}

func (v InitKeyContext) Valid() bool {
	return v.Schema == CryptoSchema && v.GenesisProfile == GenesisProfile &&
		publicIDsValid(v.AdmissionID, v.SessionID, v.DomainID, v.CompatibilityID, v.InitID, v.DescriptorDigest, v.GenesisPlanDigest, v.RequestDescriptor.Digest) &&
		v.Expiry > 0 && v.Expiry <= 1<<63-1 && v.RequestDescriptor.Length == GenesisRequestCoreLength && v.RequestDescriptor.Count == 1
}
func writeInitKeyContext(w *cryptoWriter, v InitKeyContext) {
	w.u16(v.Schema)
	w.u16(v.GenesisProfile)
	for _, id := range []ID{v.AdmissionID, v.SessionID, v.DomainID, v.CompatibilityID} {
		w.id(id)
	}
	w.u64(v.Expiry)
	for _, id := range []ID{v.InitID, v.DescriptorDigest, v.GenesisPlanDigest} {
		w.id(id)
	}
	w.descriptor(v.RequestDescriptor)
}
func readInitKeyContext(r *cryptoReader) InitKeyContext {
	v := InitKeyContext{Schema: r.u16(), GenesisProfile: r.u16(), AdmissionID: r.requiredID(), SessionID: r.requiredID(), DomainID: r.requiredID(), CompatibilityID: r.requiredID(), Expiry: r.u64(), InitID: r.requiredID(), DescriptorDigest: r.requiredID(), GenesisPlanDigest: r.requiredID(), RequestDescriptor: r.descriptor()}
	if r.err == nil && !v.Valid() {
		r.err = ErrRecord
	}
	return v
}
func EncodeInitKeyContext(v InitKeyContext) ([]byte, error) {
	if !v.Valid() {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, InitKeyContextLength)}
	writeInitKeyContext(&w, v)
	return w.b, nil
}
func DecodeInitKeyContext(b []byte) (InitKeyContext, error) {
	if len(b) > InitKeyContextLength {
		return InitKeyContext{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := readInitKeyContext(&r)
	if err := r.end(); err != nil {
		return InitKeyContext{}, err
	}
	return v, nil
}

type InitProbePlanRow struct {
	ProbeID                                   ID
	SubjectKind                               uint8
	SubjectID, BindingID, PublicBindingDigest ID
}

func AppendInitProbePlanRow(dst []byte, v InitProbePlanRow) ([]byte, error) {
	if !initProbeValid(v) {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: dst}
	writeInitProbe(&w, v)
	return w.b, nil
}
func ParseInitProbePlanRow(b []byte) (InitProbePlanRow, int, error) {
	r := newRecordReader(b)
	v := readInitProbe(&r)
	if r.err != nil {
		return InitProbePlanRow{}, 0, r.failure()
	}
	return v, r.i, nil
}

func initProbeValid(v InitProbePlanRow) bool {
	return publicIDsValid(v.ProbeID, v.SubjectID, v.BindingID) && (v.SubjectKind == OrdinaryWrapSubject || v.SubjectKind == RecoveryWrapSubject)
}
func writeInitProbe(w *cryptoWriter, v InitProbePlanRow) {
	w.id(v.ProbeID)
	w.u8(v.SubjectKind)
	w.id(v.SubjectID)
	w.id(v.BindingID)
	w.id(v.PublicBindingDigest)
}
func readInitProbe(r *cryptoReader) InitProbePlanRow {
	v := InitProbePlanRow{ProbeID: r.requiredID(), SubjectKind: r.u8(), SubjectID: r.requiredID(), BindingID: r.requiredID(), PublicBindingDigest: r.id()}
	if r.err == nil && !initProbeValid(v) {
		r.err = ErrRecord
	}
	return v
}
func initProbesValid(v []InitProbePlanRow) bool {
	if len(v) < 1 || len(v) > 2 {
		return false
	}
	for i, row := range v {
		if !initProbeValid(row) || row.SubjectKind != uint8(i+1) || i > 0 && row.ProbeID == v[i-1].ProbeID {
			return false
		}
	}
	return true
}

type GenesisKEKProbeCore struct {
	Schema, Profile                uint16
	ProbeID                        ID
	Context                        InitKeyContext
	SubjectKind                    uint8
	SubjectID, PublicBindingDigest ID
}

func writeGenesisKEKProbeCore(w *cryptoWriter, v GenesisKEKProbeCore) {
	w.u16(v.Schema)
	w.u16(v.Profile)
	w.id(v.ProbeID)
	w.u32(InitKeyContextLength)
	writeInitKeyContext(w, v.Context)
	w.u8(v.SubjectKind)
	w.id(v.SubjectID)
	w.id(v.PublicBindingDigest)
}
func genesisKEKProbeValid(v GenesisKEKProbeCore) bool {
	return v.Schema == CanonicalSchema && v.Profile == MaterialCryptoProfile && v.Context.Valid() && publicIDsValid(v.ProbeID, v.SubjectID) && (v.SubjectKind == OrdinaryWrapSubject || v.SubjectKind == RecoveryWrapSubject)
}
func EncodeGenesisKEKProbeCore(v GenesisKEKProbeCore) ([]byte, error) {
	if !genesisKEKProbeValid(v) {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, GenesisKEKProbeCoreLength)}
	writeGenesisKEKProbeCore(&w, v)
	return w.b, nil
}
func DecodeGenesisKEKProbeCore(b []byte) (GenesisKEKProbeCore, error) {
	if len(b) > GenesisKEKProbeCoreLength {
		return GenesisKEKProbeCore{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GenesisKEKProbeCore{Schema: r.u16(), Profile: r.u16(), ProbeID: r.requiredID()}
	context := r.blob(InitKeyContextLength)
	if r.err == nil {
		v.Context, r.err = DecodeInitKeyContext(context)
	}
	v.SubjectKind = r.u8()
	v.SubjectID = r.requiredID()
	v.PublicBindingDigest = r.id()
	if err := r.end(); err != nil {
		return GenesisKEKProbeCore{}, err
	}
	if !genesisKEKProbeValid(v) {
		return GenesisKEKProbeCore{}, ErrRecord
	}
	return v, nil
}
func GenesisKEKProbeMaterialDigest(v GenesisKEKProbeCore) (ID, error) {
	if !genesisKEKProbeValid(v) {
		return ID{}, ErrRecord
	}
	w := cryptoHashWriter(valueMaterialDigestPrefix)
	w.u32(GenesisKEKProbeCoreLength)
	writeGenesisKEKProbeCore(&w, v)
	return w.result(0).Digest, nil
}

type CryptoQualifyInitKeysRequest struct {
	Context  InitKeyContext
	Bindings []BindingTableRow
	Probes   []InitProbePlanRow
}

func initBindingRelations(bindings []BindingTableRow, probes []InitProbePlanRow) bool {
	if len(bindings) < 1 || len(bindings) > CryptoMaxRecipients+1 || !initProbesValid(probes) {
		return false
	}
	var ordinary, recovery int
	seenBindings := make(map[ID]bool, len(bindings))
	for i, row := range bindings {
		if row.Binding.BindingSerial != 1 || seenBindings[row.Binding.BindingID] || i > 0 && row.Binding.Provider != bindings[0].Binding.Provider {
			return false
		}
		seenBindings[row.Binding.BindingID] = true
		if row.SubjectKind == OrdinaryWrapSubject {
			ordinary++
		} else {
			recovery++
		}
		if i > 0 && row.SubjectKind == bindings[i-1].SubjectKind && row.SubjectID == bindings[i-1].SubjectID {
			return false
		}
	}
	if ordinary < 1 || ordinary > CryptoMaxRecipients || recovery != len(probes)-1 {
		return false
	}
	for _, probe := range probes {
		found := false
		for _, row := range bindings {
			if row.SubjectKind != probe.SubjectKind || row.SubjectID != probe.SubjectID {
				continue
			}
			digest, err := PublicBindingDigest(row.Binding)
			if err != nil || row.Binding.BindingID != probe.BindingID || digest != probe.PublicBindingDigest {
				return false
			}
			found = true
		}
		if !found {
			return false
		}
	}
	return true
}
func EncodeCryptoQualifyInitKeysRequest(v CryptoQualifyInitKeysRequest) ([]byte, error) {
	if !v.Context.Valid() {
		return nil, ErrRecord
	}
	if len(v.Bindings) > CryptoMaxRecipients+1 || len(v.Probes) > 2 {
		return nil, ErrRecordCapacity
	}
	n, err := BindingTableLength(v.Bindings)
	if err != nil {
		return nil, err
	}
	if !initBindingRelations(v.Bindings, v.Probes) {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, 4+InitKeyContextLength+4+n+1+InitProbePlanRowLength*len(v.Probes))}
	w.u32(InitKeyContextLength)
	writeInitKeyContext(&w, v.Context)
	w.u32(uint32(n))
	writeBindingTable(&w, v.Bindings)
	w.u8(uint8(len(v.Probes)))
	for _, row := range v.Probes {
		writeInitProbe(&w, row)
	}
	return w.b, nil
}

type initKeysView struct {
	context  InitKeyContext
	bindings BindingTableView
	probes   []InitProbePlanRow
}

func inspectCryptoQualifyInitKeysRequest(b []byte) (initKeysView, error) {
	if len(b) > CryptoInitRequestLimit-cryptoRequestHeader {
		return initKeysView{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	c := r.blob(InitKeyContextLength)
	var v initKeysView
	if r.err == nil {
		v.context, r.err = DecodeInitKeyContext(c)
	}
	table := r.blob(2 + (CryptoMaxRecipients+1)*(bindingTableRowOverhead+KMSBindingMaxLength))
	count := int(r.u8())
	if count < 1 || count > 2 {
		return initKeysView{}, ErrRecord
	}
	var probes [2]InitProbePlanRow
	for i := 0; i < count; i++ {
		probes[i] = readInitProbe(&r)
	}
	if err := r.end(); err != nil {
		return initKeysView{}, err
	}
	if !initProbesValid(probes[:count]) {
		return initKeysView{}, ErrRecord
	}
	var err error
	v.bindings, err = InspectBindingTable(table)
	if err != nil {
		return initKeysView{}, err
	}
	if v.bindings.Count < 1 || v.bindings.Count > CryptoMaxRecipients+1 {
		return initKeysView{}, ErrRecordCapacity
	}
	// One shared linear traversal checks the whole table without prefix rescans.
	rows := v.bindings.own()
	if !initBindingRelations(rows, probes[:count]) {
		return initKeysView{}, ErrRecord
	}
	v.probes = append([]InitProbePlanRow(nil), probes[:count]...)
	return v, nil
}
func DecodeCryptoQualifyInitKeysRequest(b []byte) (CryptoQualifyInitKeysRequest, error) {
	v, err := inspectCryptoQualifyInitKeysRequest(b)
	if err != nil {
		return CryptoQualifyInitKeysRequest{}, err
	}
	return CryptoQualifyInitKeysRequest{Context: v.context, Bindings: v.bindings.own(), Probes: v.probes}, nil
}

type GenesisQualifiedKeysCore struct {
	InitID, DescriptorDigest, RequestCoreDigest, GenesisPlanDigest ID
	Public                                                         []QualifiedBindingFields
	Private                                                        []QualifiedSuccessorRow
}

func qualificationBefore(a, b QualifiedBindingFields) bool {
	return a.SubjectKind < b.SubjectKind || a.SubjectKind == b.SubjectKind && bytes.Compare(a.SubjectID[:], b.SubjectID[:]) < 0
}
func genesisQualifiedKeysValid(v GenesisQualifiedKeysCore) bool {
	if !publicIDsValid(v.InitID, v.DescriptorDigest, v.RequestCoreDigest, v.GenesisPlanDigest) || len(v.Public) < 1 || len(v.Public) > CryptoMaxRecipients+1 || len(v.Private) < 1 || len(v.Private) > 2 {
		return false
	}
	for i, row := range v.Public {
		if !qualifiedBindingFieldsValid(row) || i > 0 && !qualificationBefore(v.Public[i-1], row) {
			return false
		}
	}
	for i, row := range v.Private {
		if row.ProbeID.IsZero() || !qualifiedBindingFieldsValid(row.QualifiedBindingFields) || row.SubjectKind != uint8(i+1) || i > 0 && row.ProbeID == v.Private[i-1].ProbeID {
			return false
		}
	}
	return true
}
func writeGenesisQualifiedKeysCore(w *cryptoWriter, v GenesisQualifiedKeysCore) {
	w.raw([]byte(genesisQualifiedKeysPrefix))
	w.u16(CanonicalSchema)
	w.u16(GenesisProfile)
	for _, id := range []ID{v.InitID, v.DescriptorDigest, v.RequestCoreDigest, v.GenesisPlanDigest} {
		w.id(id)
	}
	w.u16(uint16(len(v.Public)))
	for _, row := range v.Public {
		writeQualifiedBindingFields(w, row)
	}
	w.u8(uint8(len(v.Private)))
	for _, row := range v.Private {
		writeQualifiedSuccessorRow(w, row)
	}
}
func EncodeGenesisQualifiedKeysCore(v GenesisQualifiedKeysCore) ([]byte, error) {
	if len(v.Public) > CryptoMaxRecipients+1 || len(v.Private) > 2 {
		return nil, ErrRecordCapacity
	}
	if !genesisQualifiedKeysValid(v) {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, len(genesisQualifiedKeysPrefix)+4+128+3+qualifiedBindingFieldsLength*len(v.Public)+qualifiedSuccessorRowLength*len(v.Private))}
	writeGenesisQualifiedKeysCore(&w, v)
	return w.b, nil
}
func DecodeGenesisQualifiedKeysCore(b []byte) (GenesisQualifiedKeysCore, error) {
	if len(b) > GenesisQualifiedKeysMaxLength {
		return GenesisQualifiedKeysCore{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	if !bytes.Equal(r.take(len(genesisQualifiedKeysPrefix)), []byte(genesisQualifiedKeysPrefix)) || r.u16() != CanonicalSchema || r.u16() != GenesisProfile {
		return GenesisQualifiedKeysCore{}, ErrRecord
	}
	v := GenesisQualifiedKeysCore{InitID: r.requiredID(), DescriptorDigest: r.requiredID(), RequestCoreDigest: r.requiredID(), GenesisPlanDigest: r.requiredID()}
	n := int(r.u16())
	if n < 1 || n > CryptoMaxRecipients+1 {
		return GenesisQualifiedKeysCore{}, ErrRecordCapacity
	}
	public := r.take(n * qualifiedBindingFieldsLength)
	m := int(r.u8())
	if m < 1 || m > 2 {
		return GenesisQualifiedKeysCore{}, ErrRecord
	}
	private := r.take(m * qualifiedSuccessorRowLength)
	if err := r.end(); err != nil {
		return GenesisQualifiedKeysCore{}, err
	}
	// Preflight all fixed rows before allocating the retained vectors.
	pr := newRecordReader(public)
	var previous QualifiedBindingFields
	for i := 0; i < n; i++ {
		row := readQualifiedBindingFields(&pr)
		if pr.err != nil || i > 0 && !qualificationBefore(previous, row) {
			return GenesisQualifiedKeysCore{}, ErrRecord
		}
		previous = row
	}
	rr := newRecordReader(private)
	var probes [2]QualifiedSuccessorRow
	for i := 0; i < m; i++ {
		probes[i] = readQualifiedSuccessorRow(&rr)
		if rr.err != nil || probes[i].ProbeID.IsZero() || probes[i].SubjectKind != uint8(i+1) || i > 0 && probes[i].ProbeID == probes[i-1].ProbeID {
			return GenesisQualifiedKeysCore{}, ErrRecord
		}
	}
	v.Public = make([]QualifiedBindingFields, n)
	pr = newRecordReader(public)
	for i := range v.Public {
		v.Public[i] = readQualifiedBindingFields(&pr)
	}
	v.Private = append([]QualifiedSuccessorRow(nil), probes[:m]...)
	return v, nil
}
func ValidateGenesisQualifiedKeys(q CryptoQualifyInitKeysRequest, p GenesisQualifiedKeysCore) error {
	if !genesisQualifiedKeysValid(p) || p.InitID != q.Context.InitID || p.DescriptorDigest != q.Context.DescriptorDigest || p.RequestCoreDigest != q.Context.RequestDescriptor.Digest || p.GenesisPlanDigest != q.Context.GenesisPlanDigest || len(p.Public) != len(q.Bindings) || len(p.Private) != len(q.Probes) {
		return ErrRecord
	}
	for i, row := range q.Bindings {
		digest, err := PublicBindingDigest(row.Binding)
		if err != nil {
			return err
		}
		want := QualifiedBindingFields{SubjectKind: row.SubjectKind, SubjectID: row.SubjectID, BindingID: row.Binding.BindingID, PublicBindingDigest: digest, Provider: row.Binding.Provider, Qualified: 1}
		if p.Public[i] != want {
			return ErrRecord
		}
	}
	for i, row := range q.Probes {
		found := false
		for _, public := range p.Public {
			if public.SubjectKind == row.SubjectKind && public.SubjectID == row.SubjectID {
				if p.Private[i] != (QualifiedSuccessorRow{ProbeID: row.ProbeID, QualifiedBindingFields: public}) {
					return ErrRecord
				}
				found = true
			}
		}
		if !found {
			return ErrRecord
		}
	}
	return nil
}

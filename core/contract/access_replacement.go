package contract

import "bytes"

const (
	AccessBatchLimit          = 2 << 20
	AccessMaterialLimit       = MaxChildPages * AccessPageRecordLimit
	accessCoveragePrefix      = cryptoPurposePrefix + "access-coverage-v1\x00"
	accessOutputPrefix        = cryptoPurposePrefix + "access-output-rows-v1\x00"
	accessUnchangedPrefix     = cryptoPurposePrefix + "access-unchanged-material-v1\x00"
	accessCoverageFixedLength = 2 + 5*32 + 2 + 2
	accessOutputFixedLength   = 2 + 2*32 + 4
	accessUnchangedRowLength  = 2 + 5*32
)

type ReplacementRow struct {
	SubjectKind                    uint8
	SubjectID, BeforeBindingDigest ID
	SuccessorBindingIndex          uint16
}

type AccessReplacementPlanCore struct {
	DomainID, RequestCoreDigest, BeforeAccessRoot ID
	BindingTable                                  []BindingTableRow
	Replacements                                  []ReplacementRow
}

func writeReplacementRows(w *cryptoWriter, rows []ReplacementRow) {
	w.u16(uint16(len(rows)))
	for _, row := range rows {
		w.u8(row.SubjectKind)
		w.id(row.SubjectID)
		w.id(row.BeforeBindingDigest)
		w.u16(row.SuccessorBindingIndex)
	}
}

func accessPlanError(v AccessReplacementPlanCore) error {
	if !publicIDsValid(v.DomainID, v.RequestCoreDigest, v.BeforeAccessRoot) || len(v.Replacements) > 1 {
		return ErrCryptoMessage
	}
	if _, err := BindingTableLength(v.BindingTable); err != nil {
		return err
	}
	if len(v.Replacements) == 0 {
		return nil
	}
	row := v.Replacements[0]
	if (row.SubjectKind != OrdinaryWrapSubject && row.SubjectKind != RecoveryWrapSubject) || !publicIDsValid(row.SubjectID, row.BeforeBindingDigest) || int(row.SuccessorBindingIndex) >= len(v.BindingTable) {
		return ErrCryptoMessage
	}
	target := v.BindingTable[row.SuccessorBindingIndex]
	if target.SubjectKind != row.SubjectKind || target.SubjectID != row.SubjectID {
		return ErrCryptoMessage
	}
	return nil
}

func AccessReplacementPlanDescriptor(v AccessReplacementPlanCore) (DescriptorVector, error) {
	if err := accessPlanError(v); err != nil {
		return DescriptorVector{}, err
	}
	table, err := EncodeBindingTable(v.BindingTable)
	if err != nil {
		return DescriptorVector{}, err
	}
	w := cryptoHashWriter(cryptoPurposePrefix + "access-replacement-plan-v1\x00")
	w.id(v.DomainID)
	w.id(v.RequestCoreDigest)
	w.id(v.BeforeAccessRoot)
	w.blob(table)
	writeReplacementRows(&w, v.Replacements)
	return w.result(len(v.Replacements)), nil
}

type CoverageRow struct {
	MaterialKind                                                                                       MaterialKind
	MaterialID, MaterialContextDigest, ImmutableBodyDigest, BeforeAccessDigest, RequiredConsumerDigest ID
	SourceBindingIndex                                                                                 uint16
	TargetBindingIndices                                                                               []uint16
}

type CompactRow struct {
	Coverage              CoverageRow
	ValueCore             ValueCore
	OperationMaterialCore OperationMaterialCore
	BeforeAccessRecord    AccessRecord
}

type AccessOutputRow struct {
	MaterialKind                   MaterialKind
	MaterialID, BeforeAccessDigest ID
	AfterAccessRecord              AccessRecord
}

func writeCoverage(w *cryptoWriter, v CoverageRow) {
	w.u16(uint16(v.MaterialKind))
	w.id(v.MaterialID)
	w.id(v.MaterialContextDigest)
	w.id(v.ImmutableBodyDigest)
	w.id(v.BeforeAccessDigest)
	w.id(v.RequiredConsumerDigest)
	w.u16(v.SourceBindingIndex)
	w.u16(uint16(len(v.TargetBindingIndices)))
	for _, index := range v.TargetBindingIndices {
		w.u16(index)
	}
}

func coverageError(v CoverageRow) error {
	if !replacementMaterialKind(v.MaterialKind) || !publicIDsValid(v.MaterialID, v.MaterialContextDigest, v.ImmutableBodyDigest, v.BeforeAccessDigest, v.RequiredConsumerDigest) || len(v.TargetBindingIndices) != 1 || int(v.SourceBindingIndex) >= BindingTableMaxRows || int(v.TargetBindingIndices[0]) >= BindingTableMaxRows {
		return ErrCryptoMessage
	}
	return nil
}

func replacementMaterialKind(kind MaterialKind) bool {
	return kind == ValueMaterialKind || kind == OperationSeedMaterialKind
}

func materialBefore(kind MaterialKind, id ID, nextKind MaterialKind, nextID ID) bool {
	return kind < nextKind || kind == nextKind && bytes.Compare(id[:], nextID[:]) < 0
}

func compactCore(v CompactRow) (int, ID, ID, error) {
	switch v.Coverage.MaterialKind {
	case ValueMaterialKind:
		if v.OperationMaterialCore != (OperationMaterialCore{}) {
			return 0, ID{}, ID{}, ErrCryptoMessage
		}
		n, err := ValueCoreLength(v.ValueCore)
		if err != nil {
			return 0, ID{}, ID{}, err
		}
		context, err := ValueMaterialContextDigest(v.ValueCore)
		return n, v.ValueCore.ValueStateID, context, err
	case OperationSeedMaterialKind:
		if v.ValueCore != (ValueCore{}) {
			return 0, ID{}, ID{}, ErrCryptoMessage
		}
		n, err := OperationMaterialCoreLength(v.OperationMaterialCore)
		if err != nil {
			return 0, ID{}, ID{}, err
		}
		context, err := OperationMaterialContextDigest(v.OperationMaterialCore)
		return n, v.OperationMaterialCore.OperationMaterialID, context, err
	default:
		return 0, ID{}, ID{}, ErrCryptoMessage
	}
}

func compactLength(v CompactRow) (int, error) {
	if err := coverageError(v.Coverage); err != nil {
		return 0, err
	}
	core, material, context, err := compactCore(v)
	if err != nil {
		return 0, err
	}
	access, err := AccessRecordLength(v.BeforeAccessRecord)
	if err != nil {
		return 0, err
	}
	before, digestErr := AccessRecordDigest(v.BeforeAccessRecord)
	if digestErr != nil || material != v.Coverage.MaterialID || context != v.Coverage.MaterialContextDigest || before != v.Coverage.BeforeAccessDigest || v.BeforeAccessRecord.MaterialKind != v.Coverage.MaterialKind || v.BeforeAccessRecord.MaterialID != material || v.BeforeAccessRecord.MaterialContextDigest != context {
		return 0, ErrCryptoMessage
	}
	if v.Coverage.MaterialKind == OperationSeedMaterialKind {
		body, err := OperationImmutableBodyDigest(v.OperationMaterialCore, v.BeforeAccessRecord.PackageCheck)
		if err != nil || body != v.Coverage.ImmutableBodyDigest {
			return 0, ErrCryptoMessage
		}
	}
	return compactEncodedLength(v, core, access), nil
}

func compactEncodedLength(v CompactRow, core, access int) int {
	return accessCoverageFixedLength + 2*len(v.Coverage.TargetBindingIndices) + 8 + core + access
}

func writeCompact(w *cryptoWriter, v CompactRow) {
	writeCoverage(w, v.Coverage)
	if v.Coverage.MaterialKind == ValueMaterialKind {
		writeValueCoreBlob(w, v.ValueCore)
	} else {
		w.u32(operationMaterialCoreWireLength)
		writeOperationMaterialCore(w, v.OperationMaterialCore)
	}
	writeAccessRecordBlob(w, v.BeforeAccessRecord)
}

func readCompact(r *cryptoReader) CompactRow {
	c := CoverageRow{MaterialKind: MaterialKind(r.u16()), MaterialID: r.requiredID(), MaterialContextDigest: r.requiredID(), ImmutableBodyDigest: r.requiredID(), BeforeAccessDigest: r.requiredID(), RequiredConsumerDigest: r.requiredID(), SourceBindingIndex: r.u16()}
	if r.u16() != 1 {
		r.err = ErrCryptoMessage
		return CompactRow{}
	}
	c.TargetBindingIndices = []uint16{r.u16()}
	core := r.blob(valueCoreMaxLength)
	access := r.blob(MaxAccessPageLength)
	if r.err != nil {
		return CompactRow{}
	}
	v := CompactRow{Coverage: c}
	var err error
	switch c.MaterialKind {
	case ValueMaterialKind:
		v.ValueCore, err = DecodeValueCore(core)
	case OperationSeedMaterialKind:
		v.OperationMaterialCore, err = DecodeOperationMaterialCore(core)
	default:
		err = ErrCryptoMessage
	}
	if err != nil {
		r.err = err
		return v
	}
	v.BeforeAccessRecord, err = DecodeAccessRecord(access)
	if err != nil {
		r.err = err
		return v
	}
	_, r.err = compactLength(v)
	return v
}

func outputLength(v AccessOutputRow) (int, error) {
	if !replacementMaterialKind(v.MaterialKind) || !publicIDsValid(v.MaterialID, v.BeforeAccessDigest) || v.AfterAccessRecord.MaterialKind != v.MaterialKind || v.AfterAccessRecord.MaterialID != v.MaterialID {
		return 0, ErrCryptoMessage
	}
	n, err := AccessRecordLength(v.AfterAccessRecord)
	if err != nil {
		return 0, err
	}
	return accessOutputFixedLength + n, nil
}

func writeOutput(w *cryptoWriter, v AccessOutputRow) {
	w.u16(uint16(v.MaterialKind))
	w.id(v.MaterialID)
	w.id(v.BeforeAccessDigest)
	writeAccessRecordBlob(w, v.AfterAccessRecord)
}

func readOutput(r *cryptoReader) AccessOutputRow {
	v := AccessOutputRow{MaterialKind: MaterialKind(r.u16()), MaterialID: r.requiredID(), BeforeAccessDigest: r.requiredID()}
	b := r.blob(MaxAccessPageLength)
	if r.err != nil {
		return v
	}
	v.AfterAccessRecord, r.err = DecodeAccessRecord(b)
	if r.err == nil {
		_, r.err = outputLength(v)
	}
	return v
}

func CurrentValueConsumerDigest(domain ID) (ID, error) {
	if domain.IsZero() {
		return ID{}, ErrCryptoMessage
	}
	w := cryptoHashWriter(cryptoPurposePrefix + "required-consumers-v1\x00")
	w.id(domain)
	w.u32(0)
	return w.result(0).Digest, nil
}

type AccessProjectionMetadata struct{ DomainID, BeforeAccessRoot, RequestCoreDigest ID }

// AccessProjectionLengths returns exact projection lengths for a complete
// access-record byte total. It checks construction bounds, not row meaning,
// digests or the completeness of a selected snapshot.
func AccessProjectionLengths(count uint32, accessRecordBytes uint64) (coverage, output, unchanged uint64, err error) {
	if count > AccessMaterialLimit || accessRecordBytes > uint64(MaxChildPages)*MaxAccessPageLength {
		return 0, 0, 0, ErrCryptoCapacity
	}
	n := uint64(count)
	coverage = uint64(len(accessCoveragePrefix)+3*32+descriptorSize+4) + n*(accessCoverageFixedLength+2)
	output = uint64(len(accessOutputPrefix)+3*32+descriptorSize+4) + n*accessOutputFixedLength + accessRecordBytes
	unchanged = uint64(len(accessUnchangedPrefix)+3*32+4) + n*accessUnchangedRowLength
	return coverage, output, unchanged, nil
}

// AccessProjection tracks the complete public row vectors with fixed memory.
// Add accepts globally ordered rows only; it retains no access records.
type AccessProjection struct {
	coverage, output, unchanged cryptoWriter
	expected, count             uint32
	accessBytes                 uint64
	lastKind                    MaterialKind
	last                        ID
}

func NewAccessProjection(meta AccessProjectionMetadata, plan DescriptorVector, count uint32) (*AccessProjection, error) {
	if !publicIDsValid(meta.DomainID, meta.BeforeAccessRoot, meta.RequestCoreDigest, plan.Digest) || plan.Count > 1 || count > AccessMaterialLimit || plan.Count == 0 && count != 0 {
		return nil, ErrCryptoMessage
	}
	p := &AccessProjection{coverage: cryptoHashWriter(accessCoveragePrefix), output: cryptoHashWriter(accessOutputPrefix), unchanged: cryptoHashWriter(accessUnchangedPrefix), expected: count}
	for i, w := range []*cryptoWriter{&p.coverage, &p.output, &p.unchanged} {
		w.id(meta.DomainID)
		w.id(meta.BeforeAccessRoot)
		w.id(meta.RequestCoreDigest)
		if i != 2 {
			w.descriptor(plan)
		}
		w.u32(count)
	}
	return p, nil
}

// ValidateBatch checks cumulative encoded-material limits before a caller
// performs private work. It leaves the running projection unchanged.
func (p *AccessProjection) ValidateBatch(rows []CompactRow) error {
	if p == nil || uint64(p.count)+uint64(len(rows)) > uint64(p.expected) {
		return ErrCryptoMessage
	}
	accessBytes := p.accessBytes
	lastKind := p.lastKind
	last := p.last
	for _, row := range rows {
		if !last.IsZero() && !materialBefore(lastKind, last, row.Coverage.MaterialKind, row.Coverage.MaterialID) {
			return ErrCryptoMessage
		}
		if _, err := compactLength(row); err != nil {
			return err
		}
		accessBytes += uint64(accessRecordEncodedLength(row.BeforeAccessRecord))
		if accessBytes > uint64(MaxChildPages)*MaxAccessPageLength {
			return ErrCryptoCapacity
		}
		lastKind = row.Coverage.MaterialKind
		last = row.Coverage.MaterialID
	}
	return nil
}

func (p *AccessProjection) Add(row CompactRow, after AccessOutputRow) error {
	if p == nil || p.count >= p.expected || p.count != 0 && !materialBefore(p.lastKind, p.last, row.Coverage.MaterialKind, row.Coverage.MaterialID) {
		return ErrCryptoMessage
	}
	if err := p.ValidateBatch([]CompactRow{row}); err != nil {
		return err
	}
	if after.MaterialKind != row.Coverage.MaterialKind || after.MaterialID != row.Coverage.MaterialID || after.BeforeAccessDigest != row.Coverage.BeforeAccessDigest || after.AfterAccessRecord.MaterialContextDigest != row.Coverage.MaterialContextDigest || after.AfterAccessRecord.PackageCheck != row.BeforeAccessRecord.PackageCheck || len(after.AfterAccessRecord.Wraps) != len(row.BeforeAccessRecord.Wraps) {
		return ErrCryptoMessage
	}
	if _, err := outputLength(after); err != nil {
		return err
	}
	writeCoverage(&p.coverage, row.Coverage)
	writeOutput(&p.output, after)
	p.unchanged.u16(uint16(row.Coverage.MaterialKind))
	p.unchanged.id(row.Coverage.MaterialID)
	p.unchanged.id(row.Coverage.MaterialContextDigest)
	p.unchanged.id(row.Coverage.ImmutableBodyDigest)
	p.unchanged.id(row.BeforeAccessRecord.PackageCheck)
	p.unchanged.id(row.Coverage.RequiredConsumerDigest)
	p.count++
	p.accessBytes += uint64(accessRecordEncodedLength(row.BeforeAccessRecord))
	p.lastKind = row.Coverage.MaterialKind
	p.last = row.Coverage.MaterialID
	return nil
}

func (p *AccessProjection) Descriptors() (DescriptorVector, DescriptorVector, DescriptorVector, error) {
	if p == nil || p.count != p.expected {
		return DescriptorVector{}, DescriptorVector{}, DescriptorVector{}, ErrCryptoMessage
	}
	coverage, output, unchanged, err := AccessProjectionLengths(p.count, p.accessBytes)
	if err != nil || uint64(p.coverage.n) != coverage || uint64(p.output.n) != output || uint64(p.unchanged.n) != unchanged {
		return DescriptorVector{}, DescriptorVector{}, DescriptorVector{}, ErrCryptoMessage
	}
	return p.coverage.result(int(p.count)), p.output.result(int(p.count)), p.unchanged.result(int(p.count)), nil
}

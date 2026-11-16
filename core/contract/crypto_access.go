package contract

type CryptoAccessReplaceRequest struct {
	Context                    ApplyContext
	BindingTable               []BindingTableRow
	Replacements               []ReplacementRow
	ExpectedCoverageDescriptor DescriptorVector
}

type CryptoQualifiedSuccessor struct {
	BindingIndex  uint16
	Qualification QualifiedSuccessorRow
}

type CryptoAccessReplaceResult struct {
	OperationRef ID
	Qualified    []CryptoQualifiedSuccessor
}

func (v CryptoAccessReplaceRequest) Plan() AccessReplacementPlanCore {
	return AccessReplacementPlanCore{DomainID: v.Context.DomainID, RequestCoreDigest: v.Context.IntentDescriptor.Digest, BeforeAccessRoot: v.Context.CurrentAccessRoot, BindingTable: v.BindingTable, Replacements: v.Replacements}
}

func EncodeCryptoAccessReplaceRequest(v CryptoAccessReplaceRequest) ([]byte, error) {
	if v.Context.OperationClass != CryptoAccessReplacementClass || len(v.Replacements) != 1 || v.ExpectedCoverageDescriptor.Count > AccessMaterialLimit {
		return nil, ErrCryptoMessage
	}
	if err := cryptoContextError(v.Context); err != nil {
		return nil, err
	}
	if err := accessPlanError(v.Plan()); err != nil {
		return nil, err
	}
	if !accessCoverageDescriptorValid(v.ExpectedCoverageDescriptor) {
		return nil, ErrCryptoMessage
	}
	if v.ExpectedCoverageDescriptor.Count == 0 {
		plan, err := AccessReplacementPlanDescriptor(v.Plan())
		if err != nil {
			return nil, err
		}
		projection, err := NewAccessProjection(AccessProjectionMetadata{DomainID: v.Context.DomainID, BeforeAccessRoot: v.Context.CurrentAccessRoot, RequestCoreDigest: v.Context.IntentDescriptor.Digest}, plan, 0)
		if err != nil {
			return nil, err
		}
		coverage, _, _, err := projection.Descriptors()
		if err != nil || coverage != v.ExpectedCoverageDescriptor {
			return nil, ErrCryptoMessage
		}
	}
	b, err := EncodeBindingTable(v.BindingTable)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{}
	w.context(v.Context)
	w.blob(b)
	writeReplacementRows(&w, v.Replacements)
	w.descriptor(v.ExpectedCoverageDescriptor)
	return w.b, nil
}

func DecodeCryptoAccessReplaceRequest(b []byte) (CryptoAccessReplaceRequest, error) {
	if len(b) > cryptoContextBlobLength+4+BindingTableMaxLength+2+67+descriptorSize {
		return CryptoAccessReplaceRequest{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: b}
	v := CryptoAccessReplaceRequest{Context: r.context()}
	table := r.blob(BindingTableMaxLength)
	if r.u16() != 1 {
		return v, ErrCryptoMessage
	}
	v.Replacements = []ReplacementRow{{SubjectKind: r.u8(), SubjectID: r.requiredID(), BeforeBindingDigest: r.requiredID(), SuccessorBindingIndex: r.u16()}}
	v.ExpectedCoverageDescriptor = r.descriptor()
	if err := r.end(); err != nil {
		return CryptoAccessReplaceRequest{}, err
	}
	var err error
	v.BindingTable, err = DecodeBindingTable(table)
	if err != nil {
		return CryptoAccessReplaceRequest{}, err
	}
	if _, err := EncodeCryptoAccessReplaceRequest(v); err != nil {
		return CryptoAccessReplaceRequest{}, err
	}
	return v, nil
}

func EncodeCryptoAccessReplaceResult(v CryptoAccessReplaceResult) ([]byte, error) {
	if v.OperationRef.IsZero() || len(v.Qualified) > 2 {
		return nil, ErrCryptoMessage
	}
	w := cryptoWriter{}
	w.id(v.OperationRef)
	w.u32(uint32(len(v.Qualified)))
	for i, row := range v.Qualified {
		if i > 0 && (row.BindingIndex <= v.Qualified[i-1].BindingIndex || row.Qualification.ProbeID == v.Qualified[i-1].Qualification.ProbeID) || row.Qualification.PublicBindingDigest.IsZero() {
			return nil, ErrCryptoMessage
		}
		if _, err := QualifiedSuccessorRowLength(row.Qualification); err != nil {
			return nil, err
		}
		w.u16(row.BindingIndex)
		writeQualifiedSuccessorRow(&w, row.Qualification)
	}
	return w.b, nil
}

func DecodeCryptoAccessReplaceResult(b []byte) (CryptoAccessReplaceResult, error) {
	r := cryptoReader{b: b}
	v := CryptoAccessReplaceResult{OperationRef: r.requiredID()}
	n := r.u32()
	if n > 2 || len(b) != 36+133*int(n) {
		return v, ErrCryptoMessage
	}
	v.Qualified = make([]CryptoQualifiedSuccessor, n)
	for i := range v.Qualified {
		v.Qualified[i] = CryptoQualifiedSuccessor{BindingIndex: r.u16(), Qualification: readQualifiedSuccessorRow(&r)}
	}
	if err := r.end(); err != nil {
		return CryptoAccessReplaceResult{}, err
	}
	if _, err := EncodeCryptoAccessReplaceResult(v); err != nil {
		return CryptoAccessReplaceResult{}, err
	}
	return v, nil
}

func ValidateAccessReplaceResult(q CryptoAccessReplaceRequest, result CryptoAccessReplaceResult) error {
	if _, err := EncodeCryptoAccessReplaceResult(result); err != nil {
		return err
	}
	for _, qualified := range result.Qualified {
		if int(qualified.BindingIndex) >= len(q.BindingTable) {
			return ErrCryptoMessage
		}
		requested := false
		for _, replacement := range q.Replacements {
			requested = requested || replacement.SuccessorBindingIndex == qualified.BindingIndex
		}
		binding := q.BindingTable[qualified.BindingIndex]
		digest, err := PublicBindingDigest(binding.Binding)
		row := qualified.Qualification
		if !requested || err != nil || row.SubjectKind != binding.SubjectKind || row.SubjectID != binding.SubjectID || row.BindingID != binding.Binding.BindingID || row.PublicBindingDigest != digest || row.Provider != binding.Binding.Provider {
			return ErrCryptoMessage
		}
	}
	return nil
}

type CryptoAccessPrepareRequest struct {
	OperationRef ID
	Context      ApplyContext
	BatchIndex   uint32
	Final        uint8
	Rows         []CompactRow
}

type CryptoAccessPrepareResult struct {
	BatchIndex                                  uint32
	Final                                       uint8
	Rows                                        []AccessOutputRow
	InputBatchDescriptor, OutputBatchDescriptor DescriptorVector
}

func accessInputRegion(rows []CompactRow) (int, int, error) {
	if len(rows) > AccessMaterialLimit {
		return 0, 0, ErrCryptoCapacity
	}
	input, output := 4, 4
	for i, row := range rows {
		if i > 0 && !materialBefore(rows[i-1].Coverage.MaterialKind, rows[i-1].Coverage.MaterialID, row.Coverage.MaterialKind, row.Coverage.MaterialID) {
			return 0, 0, ErrCryptoMessage
		}
		in, out, err := AccessInputRowLengths(row)
		if err != nil {
			return 0, 0, err
		}
		input += in
		output += out
		if input > AccessBatchLimit || output > AccessBatchLimit {
			return 0, 0, ErrCryptoCapacity
		}
	}
	return input, output, nil
}

func AccessInputBatchLength(rows []CompactRow) (int, error) {
	n, _, err := accessInputRegion(rows)
	return n, err
}

// AccessInputRowLengths supports one linear batch packing walk. The returned
// lengths include the row's own framing, but exclude the vector count.
func AccessInputRowLengths(row CompactRow) (int, int, error) {
	n, err := compactLength(row)
	if err != nil {
		return 0, 0, err
	}
	a, err := AccessRecordLength(row.BeforeAccessRecord)
	if err != nil {
		return 0, 0, err
	}
	return 4 + n, 2 + 64 + 4 + a, nil
}

func writeAccessInputRegion(w *cryptoWriter, rows []CompactRow) {
	w.u32(uint32(len(rows)))
	for _, row := range rows {
		coreLength := operationMaterialCoreWireLength
		if row.Coverage.MaterialKind == ValueMaterialKind {
			coreLength = valueCoreEncodedLength(row.ValueCore)
		}
		w.u32(uint32(compactEncodedLength(row, coreLength, accessRecordEncodedLength(row.BeforeAccessRecord))))
		writeCompact(w, row)
	}
}

func writeAccessOutputRegion(w *cryptoWriter, rows []AccessOutputRow) {
	w.u32(uint32(len(rows)))
	for _, row := range rows {
		writeOutput(w, row)
	}
}

func AccessInputBatchDescriptor(rows []CompactRow) (DescriptorVector, error) {
	if _, _, err := accessInputRegion(rows); err != nil {
		return DescriptorVector{}, err
	}
	w := cryptoHashWriter(cryptoPurposePrefix + "access-input-batch-v1\x00")
	writeAccessInputRegion(&w, rows)
	return w.result(len(rows)), nil
}

func accessOutputRegion(rows []AccessOutputRow) (int, error) {
	if len(rows) > AccessMaterialLimit {
		return 0, ErrCryptoCapacity
	}
	n := 4
	for i, row := range rows {
		if i > 0 && !materialBefore(rows[i-1].MaterialKind, rows[i-1].MaterialID, row.MaterialKind, row.MaterialID) {
			return 0, ErrCryptoMessage
		}
		length, err := outputLength(row)
		if err != nil {
			return 0, err
		}
		n += length
		if n > AccessBatchLimit {
			return 0, ErrCryptoCapacity
		}
	}
	return n, nil
}

func AccessOutputBatchDescriptor(rows []AccessOutputRow) (DescriptorVector, error) {
	if _, err := accessOutputRegion(rows); err != nil {
		return DescriptorVector{}, err
	}
	w := cryptoHashWriter(cryptoPurposePrefix + "access-output-batch-v1\x00")
	writeAccessOutputRegion(&w, rows)
	return w.result(len(rows)), nil
}

func accessPrepareRequestLength(v CryptoAccessPrepareRequest) (int, error) {
	if v.Context.OperationClass != CryptoAccessReplacementClass || v.Final > 1 || len(v.Rows) == 0 && v.Final != 1 {
		return 0, ErrCryptoMessage
	}
	if err := cryptoStageError(v.OperationRef, v.Context); err != nil {
		return 0, err
	}
	n, _, err := accessInputRegion(v.Rows)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func EncodeCryptoAccessPrepareRequest(v CryptoAccessPrepareRequest) ([]byte, error) {
	n, err := accessPrepareRequestLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, cryptoOperationContextLength+5+n)}
	w.id(v.OperationRef)
	w.context(v.Context)
	w.u32(v.BatchIndex)
	w.u8(v.Final)
	writeAccessInputRegion(&w, v.Rows)
	return w.b, nil
}

func DecodeCryptoAccessPrepareRequest(b []byte) (CryptoAccessPrepareRequest, error) {
	if len(b) > cryptoOperationContextLength+5+AccessBatchLimit {
		return CryptoAccessPrepareRequest{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: b}
	v := CryptoAccessPrepareRequest{OperationRef: r.requiredID(), Context: r.context(), BatchIndex: r.u32(), Final: r.u8()}
	n := r.count(AccessMaterialLimit, 4+168+8+AccessRecordFixedLength)
	if r.err != nil {
		return v, r.failure()
	}
	v.Rows = make([]CompactRow, n)
	for i := range v.Rows {
		region := r.blob(AccessBatchLimit)
		if r.err != nil {
			return CryptoAccessPrepareRequest{}, r.failure()
		}
		rr := cryptoReader{b: region}
		v.Rows[i] = readCompact(&rr)
		if err := rr.end(); err != nil {
			return CryptoAccessPrepareRequest{}, err
		}
	}
	if err := r.end(); err != nil {
		return CryptoAccessPrepareRequest{}, err
	}
	if _, err := accessPrepareRequestLength(v); err != nil {
		return CryptoAccessPrepareRequest{}, err
	}
	return v, nil
}

func accessPrepareResultLength(v CryptoAccessPrepareResult) (int, error) {
	if v.Final > 1 || len(v.Rows) == 0 && v.Final != 1 || v.InputBatchDescriptor.Count != uint32(len(v.Rows)) {
		return 0, ErrCryptoMessage
	}
	n, err := accessOutputRegion(v.Rows)
	if err != nil {
		return 0, err
	}
	w := cryptoHashWriter(cryptoPurposePrefix + "access-output-batch-v1\x00")
	writeAccessOutputRegion(&w, v.Rows)
	if w.result(len(v.Rows)) != v.OutputBatchDescriptor {
		return 0, ErrCryptoMessage
	}
	return n, nil
}

func EncodeCryptoAccessPrepareResult(v CryptoAccessPrepareResult) ([]byte, error) {
	n, err := accessPrepareResultLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, 5+n+2*descriptorSize)}
	w.u32(v.BatchIndex)
	w.u8(v.Final)
	writeAccessOutputRegion(&w, v.Rows)
	w.descriptor(v.InputBatchDescriptor)
	w.descriptor(v.OutputBatchDescriptor)
	return w.b, nil
}

func DecodeCryptoAccessPrepareResult(b []byte) (CryptoAccessPrepareResult, error) {
	if len(b) > 5+AccessBatchLimit+2*descriptorSize {
		return CryptoAccessPrepareResult{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: b}
	v := CryptoAccessPrepareResult{BatchIndex: r.u32(), Final: r.u8()}
	n := r.count(AccessMaterialLimit, 2+64+4+AccessRecordFixedLength)
	if r.err != nil {
		return v, r.failure()
	}
	v.Rows = make([]AccessOutputRow, n)
	for i := range v.Rows {
		v.Rows[i] = readOutput(&r)
		if r.err != nil {
			return CryptoAccessPrepareResult{}, r.failure()
		}
	}
	v.InputBatchDescriptor = r.descriptor()
	v.OutputBatchDescriptor = r.descriptor()
	if err := r.end(); err != nil {
		return CryptoAccessPrepareResult{}, err
	}
	if _, err := accessPrepareResultLength(v); err != nil {
		return CryptoAccessPrepareResult{}, err
	}
	return v, nil
}

func ValidateAccessBatchResult(q CryptoAccessPrepareRequest, p CryptoAccessPrepareResult) error {
	d, err := AccessInputBatchDescriptor(q.Rows)
	if err != nil || q.BatchIndex != p.BatchIndex || q.Final != p.Final || d != p.InputBatchDescriptor || len(q.Rows) != len(p.Rows) {
		return ErrCryptoMessage
	}
	_, expected, err := accessInputRegion(q.Rows)
	actual, outErr := accessOutputRegion(p.Rows)
	if err != nil || outErr != nil || actual != expected {
		return ErrCryptoMessage
	}
	for i, row := range q.Rows {
		out := p.Rows[i]
		if out.MaterialKind != row.Coverage.MaterialKind || out.MaterialID != row.Coverage.MaterialID || out.BeforeAccessDigest != row.Coverage.BeforeAccessDigest || out.AfterAccessRecord.MaterialContextDigest != row.Coverage.MaterialContextDigest || out.AfterAccessRecord.PackageCheck != row.BeforeAccessRecord.PackageCheck || len(out.AfterAccessRecord.Wraps) != len(row.BeforeAccessRecord.Wraps) {
			return ErrCryptoMessage
		}
	}
	return nil
}

type CryptoAccessFreezeRequest struct {
	OperationRef                                                                                                  ID
	Context                                                                                                       ApplyContext
	IdentityPlanDescriptor, ExpectedCoverageDescriptor, AfterAccessRowsDescriptor, CandidatePublicStateDescriptor DescriptorVector
	CandidateAccessRoot                                                                                           ID
	UnchangedMaterialDescriptor                                                                                   DescriptorVector
	FinalTranscriptDigest                                                                                         ID
}

type CryptoAccessClaimRequest struct {
	CryptoAccessFreezeRequest
	FactDigest ID
}

const cryptoAccessFreezeLength = 3*32 + cryptoContextBlobLength + 5*descriptorSize

func accessCoverageDescriptorValid(d DescriptorVector) bool {
	return !d.Digest.IsZero() && d.Count <= AccessMaterialLimit && d.Length == uint64(len(accessCoveragePrefix)+96+descriptorSize+4)+168*uint64(d.Count)
}

func accessFrozenError(v CryptoAccessFreezeRequest) error {
	if v.Context.OperationClass != CryptoAccessReplacementClass || v.IdentityPlanDescriptor.Count != 0 || !accessCoverageDescriptorValid(v.ExpectedCoverageDescriptor) || v.ExpectedCoverageDescriptor.Count != v.AfterAccessRowsDescriptor.Count || v.AfterAccessRowsDescriptor.Count != v.UnchangedMaterialDescriptor.Count || v.UnchangedMaterialDescriptor.Length != uint64(len(accessUnchangedPrefix)+96+4)+162*uint64(v.UnchangedMaterialDescriptor.Count) || !publicIDsValid(v.AfterAccessRowsDescriptor.Digest, v.UnchangedMaterialDescriptor.Digest, v.CandidateAccessRoot, v.FinalTranscriptDigest) {
		return ErrCryptoMessage
	}
	if err := cryptoStageError(v.OperationRef, v.Context); err != nil {
		return err
	}
	if err := cryptoIdentityDescriptorError(v.IdentityPlanDescriptor); err != nil {
		return err
	}
	return cryptoPublicDescriptorError(v.CandidatePublicStateDescriptor)
}

func writeAccessFreeze(w *cryptoWriter, v CryptoAccessFreezeRequest) {
	w.id(v.OperationRef)
	w.context(v.Context)
	w.descriptor(v.IdentityPlanDescriptor)
	w.descriptor(v.ExpectedCoverageDescriptor)
	w.descriptor(v.AfterAccessRowsDescriptor)
	w.descriptor(v.CandidatePublicStateDescriptor)
	w.id(v.CandidateAccessRoot)
	w.descriptor(v.UnchangedMaterialDescriptor)
	w.id(v.FinalTranscriptDigest)
}

func EncodeCryptoAccessFreezeRequest(v CryptoAccessFreezeRequest) ([]byte, error) {
	if err := accessFrozenError(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{}
	writeAccessFreeze(&w, v)
	return w.b, nil
}
func EncodeCryptoAccessClaimRequest(v CryptoAccessClaimRequest) ([]byte, error) {
	b, err := EncodeCryptoAccessFreezeRequest(v.CryptoAccessFreezeRequest)
	if err != nil || v.FactDigest.IsZero() {
		return nil, ErrCryptoMessage
	}
	return append(b, v.FactDigest[:]...), nil
}

func DecodeCryptoAccessFreezeRequest(b []byte) (CryptoAccessFreezeRequest, error) {
	r := cryptoReader{b: b}
	v := CryptoAccessFreezeRequest{OperationRef: r.requiredID(), Context: r.context(), IdentityPlanDescriptor: r.descriptor(), ExpectedCoverageDescriptor: r.descriptor(), AfterAccessRowsDescriptor: r.descriptor(), CandidatePublicStateDescriptor: r.descriptor(), CandidateAccessRoot: r.requiredID(), UnchangedMaterialDescriptor: r.descriptor(), FinalTranscriptDigest: r.requiredID()}
	if err := r.end(); err != nil {
		return CryptoAccessFreezeRequest{}, err
	}
	return v, accessFrozenError(v)
}

func DecodeCryptoAccessClaimRequest(b []byte) (CryptoAccessClaimRequest, error) {
	if len(b) != cryptoAccessFreezeLength+32 {
		return CryptoAccessClaimRequest{}, ErrCryptoMessage
	}
	v, err := DecodeCryptoAccessFreezeRequest(b[:cryptoAccessFreezeLength])
	out := CryptoAccessClaimRequest{CryptoAccessFreezeRequest: v}
	copy(out.FactDigest[:], b[cryptoAccessFreezeLength:])
	if out.FactDigest.IsZero() {
		err = ErrCryptoMessage
	}
	return out, err
}

func AccessTranscriptStartDigest(instance, operation ID, c ApplyContext, plan, coverage DescriptorVector) (ID, error) {
	if instance.IsZero() || c.OperationClass != CryptoAccessReplacementClass || !accessCoverageDescriptorValid(coverage) {
		return ID{}, ErrCryptoMessage
	}
	if err := cryptoStageError(operation, c); err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter(cryptoPurposePrefix + "access-transcript-start\x00")
	w.id(instance)
	w.id(operation)
	w.context(c)
	w.descriptor(plan)
	w.descriptor(coverage)
	return w.result(0).Digest, nil
}

func AccessTranscriptStepDigest(previous ID, index uint32, final uint8, input, output DescriptorVector) (ID, error) {
	if previous.IsZero() || final > 1 || input.Count != output.Count {
		return ID{}, ErrCryptoMessage
	}
	w := cryptoHashWriter(cryptoPurposePrefix + "access-transcript-step\x00")
	w.id(previous)
	w.u32(index)
	w.u8(final)
	w.descriptor(input)
	w.descriptor(output)
	return w.result(0).Digest, nil
}

func CryptoAccessFactDigest(instance ID, v CryptoAccessFreezeRequest) (ID, error) {
	if instance.IsZero() {
		return ID{}, ErrCryptoMessage
	}
	if err := accessFrozenError(v); err != nil {
		return ID{}, err
	}
	exclusion, err := ExclusionDescriptor(v.Context.DomainID, nil)
	if err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter(cryptoFactsPrefix)
	w.id(instance)
	w.id(v.OperationRef)
	w.context(v.Context)
	w.id(v.ExpectedCoverageDescriptor.Digest)
	w.descriptor(v.IdentityPlanDescriptor)
	w.descriptor(v.CandidatePublicStateDescriptor)
	w.descriptor(v.AfterAccessRowsDescriptor)
	w.descriptor(exclusion)
	w.id(v.FinalTranscriptDigest)
	w.id(v.CandidateAccessRoot)
	w.descriptor(v.UnchangedMaterialDescriptor)
	return w.result(0).Digest, nil
}

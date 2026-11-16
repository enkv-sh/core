package contract

import "bytes"

type SupportRecordKind = uint8

const (
	OperationMaterialSupportKind         SupportRecordKind = 1
	GeneratedParentSupportKind           SupportRecordKind = 2
	GeneratedFragmentSupportKind         SupportRecordKind = 3
	GeneratedResultSupportKind           SupportRecordKind = 4
	GeneratedPhaseSupportKind            SupportRecordKind = 5
	RetainedCanonicalSupportKind         SupportRecordKind = 6
	MutationReceiptSupportKind           SupportRecordKind = 7
	GeneratedLineageSupportKind          SupportRecordKind = 8
	GeneratedAttemptSupportKind          SupportRecordKind = 9
	GeneratedDutySupportKind             SupportRecordKind = 10
	GeneratedHazardSupportKind           SupportRecordKind = 11
	PendingInboxReleaseSupportKind       SupportRecordKind = 12
	GeneratedCreateEvidenceSupportKind   SupportRecordKind = 13
	GeneratorVectorSupportKind           SupportRecordKind = 14
	PublicationCoordinateSupportKind     SupportRecordKind = 15
	PublicationMarkerSupportKind         SupportRecordKind = 16
	OutputConfigurationSliceSupportKind  SupportRecordKind = 17
	GeneratedFinalPreparationSupportKind SupportRecordKind = 18
	GCPlanSupportKind                    SupportRecordKind = 19

	SupportRecordOverhead     = 37
	SupportRecordMinLength    = SupportRecordOverhead + OutputConfigurationSliceBodyOverhead
	SupportRecordMaxLength    = SupportRecordOverhead + OutputConfigurationSliceBodyOverhead + MaxOutputConfigurationSliceBytes
	requiredSupportPrefix     = cryptoPurposePrefix + "required-support-v2\x00"
	requiredSupportBaseLength = len(requiredSupportPrefix) + 32 + 4
	requiredSupportRowLength  = 69
	requiredSupportMaxRecords = MaxChildPages * (MaxRequiredSupportPageLength - RequiredSupportPageHeaderLength) / SupportRecordMinLength
)

// SupportRecord carries one complete closed live-support record. Selection and
// ownership require separate checks against the authenticated root.
type SupportRecord struct {
	Kind     SupportRecordKind
	RecordID ID
	Body     []byte
}

// SupportRecordView borrows its exact body. Keep it unchanged through use.
type SupportRecordView SupportRecord

func supportRecordBefore(kind SupportRecordKind, id ID, nextKind SupportRecordKind, nextID ID) bool {
	return kind < nextKind || kind == nextKind && bytes.Compare(id[:], nextID[:]) < 0
}

func supportBodyLengthError(kind SupportRecordKind, n uint64) error {
	var minimum, maximum int
	switch kind {
	case GCPlanSupportKind:
		minimum, maximum = 454, GCPlanMaxLength
	case OperationMaterialSupportKind:
		minimum, maximum = operationMaterialRecordLength, operationMaterialRecordLength
	case GeneratedParentSupportKind:
		minimum, maximum = GeneratedParentRecordBodyLength, GeneratedParentRecordBodyLength
	case GeneratedFragmentSupportKind:
		minimum, maximum = 87, GeneratedFragmentMaxLength
	case GeneratedResultSupportKind:
		minimum, maximum = 16+GeneratedResultCoreLength+115+CanonicalPayloadOverhead+transferEnvelopeMaxLength, GeneratedResultRecordMaxLength
	case GeneratedPhaseSupportKind:
		minimum, maximum = GeneratedPhaseRecordBodyLength, GeneratedPhaseRecordBodyLength
	case GeneratedFinalPreparationSupportKind:
		minimum, maximum = GeneratedFinalPreparationRecordLength, GeneratedFinalPreparationRecordLength
	case RetainedCanonicalSupportKind:
		minimum, maximum = retainedCanonicalRecordMinLength, retainedCanonicalRecordMaxLength
	case MutationReceiptSupportKind:
		minimum, maximum = CompactMutationReceiptLength, CompactMutationReceiptLength
	case GeneratedLineageSupportKind:
		minimum, maximum = GeneratedLineageRecordMaxLength-CryptoMaxName, GeneratedLineageRecordMaxLength
	case GeneratedAttemptSupportKind:
		minimum, maximum = GeneratedAttemptRecordFixedLength, GeneratedAttemptRecordBodyLength
	case GeneratedDutySupportKind:
		minimum, maximum = GeneratedDutyRecordFixedLength, GeneratedDutyRecordBodyLength
	case GeneratedHazardSupportKind:
		minimum, maximum = GeneratedHazardRecordBodyLength, GeneratedHazardRecordBodyLength
	case PendingInboxReleaseSupportKind:
		minimum, maximum = PendingInboxReleaseRecordBodyLength, PendingInboxReleaseRecordBodyLength
	case GeneratedCreateEvidenceSupportKind:
		minimum, maximum = 120+GeneratedResultCoreLength+115, GeneratedCreateEvidenceMaxLength
	case GeneratorVectorSupportKind:
		minimum, maximum = GeneratorCarrierFixedLength+103, generatorCarrierMaxLength
	case PublicationCoordinateSupportKind:
		minimum, maximum = 2+32+32+4+1+4+1+1+32+32+8+32+32+1+1, MaxPublicationCoordinateRecordBytes-SupportRecordOverhead
	case PublicationMarkerSupportKind:
		minimum, maximum = 1, MaxPublicationMarkerRecordBytes-SupportRecordOverhead
	case OutputConfigurationSliceSupportKind:
		minimum, maximum = OutputConfigurationSliceBodyOverhead+1, OutputConfigurationSliceBodyOverhead+MaxOutputConfigurationSliceBytes
	default:
		return ErrRecord
	}
	if n > uint64(maximum) {
		return ErrRecordCapacity
	}
	length := int(n)
	if length < minimum {
		return ErrRecord
	}
	return nil
}

func inspectSupportBody(v SupportRecord) (ID, error) {
	if err := supportBodyLengthError(v.Kind, uint64(len(v.Body))); err != nil {
		return ID{}, err
	}
	if v.RecordID.IsZero() {
		return ID{}, ErrRecord
	}
	var domain, recordID ID
	switch v.Kind {
	case GCPlanSupportKind:
		plan, err := DecodeGCPlan(v.Body)
		if err != nil {
			return ID{}, err
		}
		domain, recordID = plan.DomainID, plan.OperationID
	case OperationMaterialSupportKind:
		body, err := InspectOperationMaterialRecord(v.Body)
		if err != nil {
			return ID{}, err
		}
		domain, recordID = body.Core.DomainID, body.Core.OperationMaterialID
	case GeneratedParentSupportKind:
		body, err := InspectGeneratedParentRecord(v.Body)
		if err != nil {
			return ID{}, err
		}
		domain, recordID = body.DomainID, body.OperationID
	case GeneratedFragmentSupportKind:
		body, err := InspectGeneratedFragment(v.Body)
		if err != nil {
			return ID{}, err
		}
		recordID, err = GeneratorFragmentID(body.BlobID, body.Index)
		if err != nil {
			return ID{}, err
		}
	case GeneratedResultSupportKind:
		body, err := InspectGeneratedResultRecord(v.Body)
		if err != nil {
			return ID{}, err
		}
		domain, recordID = body.Core.DomainID, body.Core.ResultID
	case GeneratedPhaseSupportKind:
		body, err := InspectGeneratedPhaseRecord(v.Body)
		if err != nil {
			return ID{}, err
		}
		domain, recordID = body.DomainID, body.OperationID
	case GeneratedFinalPreparationSupportKind:
		body, err := InspectGeneratedFinalPreparationRecord(v.Body)
		if err != nil {
			return ID{}, err
		}
		domain, recordID = body.DomainID, body.OperationID
	case RetainedCanonicalSupportKind:
		body, err := InspectRetainedCanonicalRecord(v.Body)
		if err != nil {
			return ID{}, err
		}
		recordID = body.Entry.ValueState
		if v.RecordID != recordID {
			w := cryptoHashWriter(retainedEntryAdmissionPrefix)
			w.raw(v.Body)
			recordID = w.result(0).Digest
		}
	case MutationReceiptSupportKind:
		body, err := InspectCompactMutationReceipt(v.Body)
		if err != nil {
			return ID{}, err
		}
		domain, recordID = body.DomainID, body.OperationID
	case GeneratedLineageSupportKind:
		body, err := InspectGeneratedLineageRecord(v.Body)
		if err != nil {
			return ID{}, err
		}
		domain, recordID = body.DomainID, body.LineageID
	case GeneratedAttemptSupportKind:
		body, err := InspectGeneratedAttemptRecord(v.Body)
		if err != nil {
			return ID{}, err
		}
		domain, recordID = body.DomainID, body.AttemptID
	case GeneratedDutySupportKind:
		body, err := InspectGeneratedDutyRecord(v.Body)
		if err != nil {
			return ID{}, ErrRecord
		}
		domain, recordID = body.DomainID, body.DutyID
	case GeneratedHazardSupportKind:
		body, err := InspectGeneratedHazardRecord(v.Body)
		if err != nil {
			return ID{}, err
		}
		domain, recordID = body.DomainID, body.HazardID
	case PendingInboxReleaseSupportKind:
		body, err := InspectPendingInboxReleaseRecord(v.Body)
		if err != nil {
			return ID{}, err
		}
		domain, recordID = body.DomainID, body.InboxID
	case GeneratedCreateEvidenceSupportKind:
		body, err := InspectGeneratedCreateEvidence(v.Body)
		if err != nil {
			return ID{}, err
		}
		core, err := InspectGeneratedResultCore(body.ResultCore)
		if err != nil {
			return ID{}, err
		}
		domain, recordID = core.DomainID, body.OriginalResultID
	case GeneratorVectorSupportKind:
		body, err := InspectGeneratorVectorCarrier(v.Body)
		if err != nil {
			return ID{}, err
		}
		recordID, err = GeneratorVectorCarrierID(body)
		if err != nil {
			return ID{}, err
		}
		domain = body.DomainID
	case PublicationCoordinateSupportKind:
		body, err := InspectPublicationCoordinate(v.Body)
		if err != nil {
			return ID{}, err
		}
		domain, recordID = body.DomainID, body.CoordinateID
	case PublicationMarkerSupportKind:
		body, err := InspectPublicationMarker(v.Body)
		if err != nil {
			return ID{}, err
		}
		domain, recordID = body.DomainID, body.AttemptID
	case OutputConfigurationSliceSupportKind:
		body, err := InspectOutputConfigurationSlice(v.Body)
		if err != nil {
			return ID{}, err
		}
		domain = body.DomainID
		recordID, err = OutputConfigurationSliceID(domain, body.ConfigurationDigest, body.SliceIndex)
		if err != nil {
			return ID{}, err
		}
	}
	if v.RecordID != recordID {
		return ID{}, ErrRecord
	}
	return domain, nil
}

func SupportRecordLength(v SupportRecord) (int, error) {
	if _, err := inspectSupportBody(v); err != nil {
		return 0, err
	}
	return SupportRecordOverhead + len(v.Body), nil
}

func writeSupportRecord(w *cryptoWriter, kind SupportRecordKind, id ID, bodyLength int, body func(*cryptoWriter)) {
	w.u8(uint8(kind))
	w.id(id)
	w.u32(uint32(bodyLength))
	body(w)
}

func AppendSupportRecord(dst []byte, v SupportRecord) ([]byte, error) {
	if _, err := SupportRecordLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeSupportRecord(&w, v.Kind, v.RecordID, len(v.Body), func(w *cryptoWriter) { w.raw(v.Body) })
	return w.b, nil
}

func AppendMutationReceiptSupportPlan(dst []byte, v CompactMutationReceiptPlan) ([]byte, error) {
	if _, err := AppendCompactMutationReceiptPlan(nil, v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeSupportRecord(&w, MutationReceiptSupportKind, v.OperationID, CompactMutationReceiptLength, func(w *cryptoWriter) {
		writeCompactMutationReceipt(w, CompactMutationReceipt(v))
	})
	return w.b, nil
}

func AppendGeneratedParentSupportPlan(dst []byte, v GeneratedParentPlan) ([]byte, error) {
	if _, err := GeneratedParentPlanLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeSupportRecord(&w, GeneratedParentSupportKind, v.OperationID, GeneratedParentRecordBodyLength, func(w *cryptoWriter) {
		writeGeneratedParentRecord(w, GeneratedParentRecord(v))
	})
	return w.b, nil
}

func ParseSupportRecord(b []byte) (SupportRecordView, int, error) {
	r := newRecordReader(b[:min(len(b), SupportRecordMaxLength)])
	v := SupportRecordView{Kind: SupportRecordKind(r.u8()), RecordID: r.requiredID()}
	n := r.u32()
	if r.err != nil {
		return SupportRecordView{}, 0, r.failure()
	}
	if err := supportBodyLengthError(v.Kind, uint64(n)); err != nil {
		return SupportRecordView{}, 0, err
	}
	v.Body = r.take(int(n))
	if r.err != nil {
		return SupportRecordView{}, 0, r.failure()
	}
	if _, err := inspectSupportBody(SupportRecord(v)); err != nil {
		return SupportRecordView{}, 0, err
	}
	return v, r.i, nil
}

// SupportRecordDomain validates the complete record before exposing its domain.
// A retained canonical entry has no embedded domain; its selected plan owns it.
func SupportRecordDomain(v SupportRecord) (ID, error) { return inspectSupportBody(v) }

// SupportRecordDigest is a typed fact from inspection of a complete support
// record. Its selected page Ref and physical ordinal are checked separately.
type SupportRecordDigest struct {
	kind       SupportRecordKind
	recordID   ID
	bodyDigest ID
	bodyLength uint32
	domain     ID
	inspected  bool
}

func (v SupportRecordDigest) Kind() SupportRecordKind { return v.kind }
func (v SupportRecordDigest) RecordID() ID            { return v.recordID }
func (v SupportRecordDigest) BodyDigest() ID          { return v.bodyDigest }
func (v SupportRecordDigest) BodyLength() uint32      { return v.bodyLength }

func InspectSupportRecordDigest(domain ID, row SupportRecord) (SupportRecordDigest, error) {
	actual, err := inspectSupportBody(row)
	if err != nil {
		return SupportRecordDigest{}, err
	}
	if domain.IsZero() || !actual.IsZero() && actual != domain {
		return SupportRecordDigest{}, ErrRecord
	}
	return SupportRecordDigest{kind: row.Kind, recordID: row.RecordID, bodyDigest: Hash(row.Body),
		bodyLength: uint32(len(row.Body)), domain: domain, inspected: true}, nil
}

// RequiredSupportDescriptorFromDigests hashes previously inspected rows. The
// caller must still bind each fact to an authenticated selected page and span.
func RequiredSupportDescriptorFromDigests(domain ID, records []SupportRecordDigest) (DescriptorVector, error) {
	if domain.IsZero() {
		return DescriptorVector{}, ErrRecord
	}
	if len(records) > requiredSupportMaxRecords {
		return DescriptorVector{}, ErrRecordCapacity
	}
	var total uint64
	for i, row := range records {
		if !row.inspected || row.domain != domain || row.kind == 0 || row.kind > GCPlanSupportKind || row.recordID.IsZero() ||
			row.bodyLength < SupportRecordMinLength-SupportRecordOverhead || row.bodyLength > SupportRecordMaxLength-SupportRecordOverhead ||
			i > 0 && (records[i-1].kind > row.kind || records[i-1].kind == row.kind && bytes.Compare(records[i-1].recordID[:], row.recordID[:]) >= 0) {
			return DescriptorVector{}, ErrRecord
		}
		total += uint64(SupportRecordOverhead) + uint64(row.bodyLength)
		if total > uint64(MaxChildPages)*(MaxRequiredSupportPageLength-RequiredSupportPageHeaderLength) {
			return DescriptorVector{}, ErrRecordCapacity
		}
	}
	w := cryptoHashWriter(requiredSupportPrefix)
	w.id(domain)
	w.u32(uint32(len(records)))
	for _, row := range records {
		w.u8(uint8(row.kind))
		w.id(row.recordID)
		w.id(row.bodyDigest)
		w.u32(row.bodyLength)
	}
	return w.result(len(records)), nil
}

func RequiredSupportDescriptor(domain ID, records []SupportRecord) (DescriptorVector, error) {
	if domain.IsZero() {
		return DescriptorVector{}, ErrRecord
	}
	if len(records) > requiredSupportMaxRecords {
		return DescriptorVector{}, ErrRecordCapacity
	}
	var total uint64
	for i, row := range records {
		actual, err := inspectSupportBody(row)
		if err != nil {
			return DescriptorVector{}, err
		}
		if !actual.IsZero() && actual != domain || i > 0 && (records[i-1].Kind > row.Kind || records[i-1].Kind == row.Kind && bytes.Compare(records[i-1].RecordID[:], row.RecordID[:]) >= 0) {
			return DescriptorVector{}, ErrRecord
		}
		total += uint64(SupportRecordOverhead + len(row.Body))
		if total > uint64(MaxChildPages)*(MaxRequiredSupportPageLength-RequiredSupportPageHeaderLength) {
			return DescriptorVector{}, ErrRecordCapacity
		}
	}
	digests := make([]SupportRecordDigest, len(records))
	for i, row := range records {
		var err error
		digests[i], err = InspectSupportRecordDigest(domain, row)
		if err != nil {
			return DescriptorVector{}, err
		}
	}
	return RequiredSupportDescriptorFromDigests(domain, digests)
}

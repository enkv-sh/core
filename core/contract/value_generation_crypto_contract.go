package contract

import (
	"bytes"
	"math"
)

const (
	CryptoGeneratedClass                       CryptoOperationClass = 4
	CryptoGeneratedCompareLimit                                     = 8 << 10
	CryptoGeneratedPartLimit                                        = 1<<20 + 1<<10
	CryptoGeneratedAdoptLimit                                       = 80 << 10
	CryptoGeneratedMaterialLimit                                    = 2 << 20
	CryptoGeneratedResponseLimit                                    = 4 << 20
	GeneratorMaximumChildCommandDurationMillis                      = 90_000
	cryptoGeneratedAdmissionLength                                  = 1 + 4 + cryptoGeneratedParentRowLength + 3*descriptorSize + 2*32
	cryptoGeneratedVerificationMaximumLength                        = 1 + 1 + 4 + SupportRecordOverhead + GeneratedAttemptRecordBodyLength + 2*descriptorSize + 3*32 + GeneratorResultReferenceLength
	cryptoGeneratedOperationContextLength                           = 32 + cryptoContextBlobLength
	cryptoGeneratedParentRowLength                                  = SupportRecordOverhead + GeneratedParentRecordBodyLength
	CryptoGeneratedFrozenLength                                     = cryptoGeneratedOperationContextLength + 4*32 + 5*descriptorSize
)

type CryptoGeneratedPurpose uint8

const (
	CryptoGeneratedReservationPurpose          CryptoGeneratedPurpose = 1
	CryptoGeneratedAdoptionPurpose             CryptoGeneratedPurpose = 2
	CryptoGeneratedFinalPreparationPurpose     CryptoGeneratedPurpose = 3
	CryptoGeneratedProducerPreparationPurpose  CryptoGeneratedPurpose = 4
	CryptoGeneratedOriginalVerificationPurpose CryptoGeneratedPurpose = 5
)

// QualifiesPendingRecipients identifies transitions that can enter a new
// effect or install membership. Recording and nonselecting Final still
// authenticate the complete registry image and current bindings.
func (p CryptoGeneratedPurpose) QualifiesPendingRecipients(selectsEntries bool) bool {
	return p == CryptoGeneratedReservationPurpose || p == CryptoGeneratedProducerPreparationPurpose ||
		p == CryptoGeneratedFinalPreparationPurpose && selectsEntries
}

func (p CryptoGeneratedPurpose) valid() bool {
	return p >= CryptoGeneratedReservationPurpose && p <= CryptoGeneratedOriginalVerificationPurpose
}

type CryptoGeneratedPrepareVariant uint8

const (
	CryptoGeneratedPreparePlanPart       CryptoGeneratedPrepareVariant = 1
	CryptoGeneratedPrepareFinishPlan     CryptoGeneratedPrepareVariant = 2
	CryptoGeneratedPrepareProducer       CryptoGeneratedPrepareVariant = 8
	CryptoGeneratedPrepareAdopt          CryptoGeneratedPrepareVariant = 4
	CryptoGeneratedPrepareValueEntries   CryptoGeneratedPrepareVariant = 5
	CryptoGeneratedPrepareSupplied       CryptoGeneratedPrepareVariant = 6
	CryptoGeneratedPrepareVerifyOriginal CryptoGeneratedPrepareVariant = 7
	CryptoGeneratedPrepareLocalFailure   CryptoGeneratedPrepareVariant = 9
)

// CryptoGeneratedPrepareRequest is the validated Prepare request union. Only
// the field selected by Variant is populated.
type CryptoGeneratedPrepareRequest struct {
	Variant        CryptoGeneratedPrepareVariant
	PlanPart       CryptoGeneratedPlanPartRequestView
	FinishPlan     CryptoGeneratedFinishPlanRequest
	Producer       CryptoGeneratedProducerRequestView
	Adopt          CryptoGeneratedAdoptRequestView
	ValueEntries   CryptoGeneratedValueEntriesRequestView
	Supplied       CryptoGeneratedSuppliedRequestView
	VerifyOriginal CryptoGeneratedVerifyRequest
	LocalFailure   CryptoGeneratedLocalFailureRequest
}

type CryptoGeneratedLocalFailureRequest struct {
	OperationRef ID
	Context      ApplyContext
	AttemptID    ID
	Reason       uint8
}

func (v CryptoGeneratedLocalFailureRequest) valid() error {
	if err := cryptoGeneratedStageError(v.OperationRef, v.Context); err != nil {
		return err
	}
	if v.AttemptID.IsZero() || !GeneratorLocalFailureReasonValid(v.Reason) {
		return ErrCryptoMessage
	}
	return nil
}

func EncodeCryptoGeneratedLocalFailureRequest(v CryptoGeneratedLocalFailureRequest) ([]byte, error) {
	if err := v.valid(); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, 452)}
	w.id(v.OperationRef)
	w.context(v.Context)
	w.u8(uint8(CryptoGeneratedPrepareLocalFailure))
	w.id(v.AttemptID)
	w.u8(v.Reason)
	return w.b, nil
}

func InspectCryptoGeneratedLocalFailureRequest(body []byte) (CryptoGeneratedLocalFailureRequest, error) {
	if len(body) > 452 {
		return CryptoGeneratedLocalFailureRequest{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: body}
	v := CryptoGeneratedLocalFailureRequest{OperationRef: r.requiredID(), Context: readCryptoGeneratedContext(&r)}
	if CryptoGeneratedPrepareVariant(r.u8()) != CryptoGeneratedPrepareLocalFailure {
		return CryptoGeneratedLocalFailureRequest{}, ErrCryptoMessage
	}
	v.AttemptID, v.Reason = r.requiredID(), r.u8()
	if err := r.end(); err != nil {
		return CryptoGeneratedLocalFailureRequest{}, err
	}
	if err := v.valid(); err != nil {
		return CryptoGeneratedLocalFailureRequest{}, err
	}
	return v, nil
}

func cryptoGeneratedVerificationLengthValid(n uint64) bool {
	return n == cryptoGeneratedVerificationMaximumLength-GeneratedAttemptRecordBodyLength+GeneratedAttemptRecordFixedLength
}

func cryptoGeneratedContextError(c ApplyContext) error {
	if c.OperationClass != CryptoGeneratedClass || c.Expiry == 0 || c.Expiry > math.MaxInt64 ||
		!publicIDsValid(c.AdmissionID, c.SessionID, c.DomainID, c.CompatibilityID,
			c.PredecessorHEADDigest, c.OriginalConditionDigest, c.CurrentAccessRoot, c.IntentDescriptor.Digest) ||
		!cryptoRefValid(c.PredecessorRootRef[:], byte(RootKind), c.DomainID) ||
		c.IntentDescriptor.Count != 1 || c.IntentDescriptor.Length != cryptoGeneratedAdmissionLength && !cryptoGeneratedVerificationLengthValid(c.IntentDescriptor.Length) {
		return ErrCryptoMessage
	}
	return nil
}

func readCryptoGeneratedContext(r *cryptoReader) ApplyContext {
	if r.u32() != CryptoApplyContextLength && r.err == nil {
		r.err = ErrCryptoMessage
	}
	c := cryptoReadContextFields(r)
	if r.err == nil {
		r.err = cryptoGeneratedContextError(c)
	}
	return c
}

func cryptoGeneratedStageError(operation ID, c ApplyContext) error {
	if operation.IsZero() {
		return ErrCryptoMessage
	}
	return cryptoGeneratedContextError(c)
}

type CryptoGeneratedCompareRequest struct {
	Context                             ApplyContext
	Purpose                             CryptoGeneratedPurpose
	ParentPlan                          GeneratedParentPlan
	Parent                              GeneratedParentRecord
	PlanGraph                           GeneratorDescriptor
	UsePlanDigest, MaterialID           ID
	AcceptedSources, IntendedEntryPlans GeneratorDescriptor
	Original                            GeneratedAttemptRecord
	OriginalResult                      GeneratorResultReference
	OriginalOwnerKind                   uint8
	OriginalOwnerID                     ID
	Target                              GeneratorDescriptor
}

func cryptoGeneratedCompareParent(v CryptoGeneratedCompareRequest) (GeneratedParentRecord, error) {
	if v.Purpose == CryptoGeneratedReservationPurpose {
		if v.Parent != (GeneratedParentRecord{}) {
			return GeneratedParentRecord{}, ErrCryptoMessage
		}
		_, err := GeneratedParentPlanLength(v.ParentPlan)
		return GeneratedParentRecord(v.ParentPlan), err
	}
	if v.Purpose < CryptoGeneratedAdoptionPurpose || v.Purpose > CryptoGeneratedProducerPreparationPurpose || v.ParentPlan != (GeneratedParentPlan{}) {
		return GeneratedParentRecord{}, ErrCryptoMessage
	}
	_, err := GeneratedParentRecordLength(v.Parent)
	return v.Parent, err
}

func cryptoGeneratedCompareFieldsError(v CryptoGeneratedCompareRequest) error {
	if v.Purpose == CryptoGeneratedOriginalVerificationPurpose {
		if v.Parent != (GeneratedParentRecord{}) || v.ParentPlan != (GeneratedParentPlan{}) ||
			v.AcceptedSources != (GeneratorDescriptor{}) || v.IntendedEntryPlans != (GeneratorDescriptor{}) ||
			!publicIDsValid(v.UsePlanDigest, v.MaterialID, v.OriginalOwnerID) || !generatedDescriptorsValid(v.PlanGraph, v.Target) ||
			(v.OriginalOwnerKind != GeneratedDutySupportKind && v.OriginalOwnerKind != GeneratedHazardSupportKind) ||
			v.Original.Schema == GeneratedAttemptRecordSchema && v.Original.LifecycleMode == GeneratorLifecycleNone || v.Original.Stage != GeneratedStageTerminal || v.OriginalResult.ResultID != v.Original.ResultID {
			return ErrCryptoMessage
		}
		if _, err := GeneratedAttemptRecordLength(v.Original); err != nil {
			return err
		}
		return generatorResultReferenceError(v.OriginalResult)
	}
	if v.Original != (GeneratedAttemptRecord{}) || v.OriginalResult != (GeneratorResultReference{}) || v.OriginalOwnerKind != 0 || !v.OriginalOwnerID.IsZero() || v.Target != (GeneratorDescriptor{}) {
		return ErrCryptoMessage
	}
	p, err := cryptoGeneratedCompareParent(v)
	if err != nil {
		return err
	}
	if v.PlanGraph != p.Graph || v.UsePlanDigest != p.UsePlanDigest || v.MaterialID != p.MaterialID ||
		v.AcceptedSources != p.SourceUses || v.IntendedEntryPlans != p.IntendedEntryPlans {
		return ErrCryptoMessage
	}
	return nil
}

func writeCryptoGeneratedCompareTail(w *cryptoWriter, v CryptoGeneratedCompareRequest) {
	if v.Purpose == CryptoGeneratedOriginalVerificationPurpose {
		w.u8(uint8(CryptoGeneratedOriginalVerificationPurpose))
		n, _ := GeneratedAttemptRecordLength(v.Original)
		w.u32(uint32(SupportRecordOverhead + n))
		writeSupportRecord(w, GeneratedAttemptSupportKind, v.Original.AttemptID, n,
			func(w *cryptoWriter) { writeGeneratedAttemptRecord(w, v.Original) })
		writeGeneratorDescriptor(w, v.PlanGraph)
		w.id(v.UsePlanDigest)
		w.id(v.MaterialID)
		w.u8(v.OriginalOwnerKind)
		w.id(v.OriginalOwnerID)
		writeGeneratorDescriptor(w, v.Target)
		writeGeneratorResultReference(w, v.OriginalResult)
		return
	}
	p := v.Parent
	if v.Purpose == CryptoGeneratedReservationPurpose {
		p = GeneratedParentRecord(v.ParentPlan)
	}
	w.u8(uint8(v.Purpose))
	w.u32(cryptoGeneratedParentRowLength)
	w.u8(uint8(GeneratedParentSupportKind))
	w.id(p.OperationID)
	w.u32(GeneratedParentRecordBodyLength)
	writeGeneratedParentRecord(w, p)
	writeGeneratorDescriptor(w, v.PlanGraph)
	w.id(v.UsePlanDigest)
	w.id(v.MaterialID)
	writeGeneratorDescriptor(w, v.AcceptedSources)
	writeGeneratorDescriptor(w, v.IntendedEntryPlans)
}

// CryptoGeneratedAdmissionDescriptor identifies public request facts only. It
// cannot create private admission or grant a producer entry right.
func CryptoGeneratedAdmissionDescriptor(v CryptoGeneratedCompareRequest) (DescriptorVector, error) {
	if err := cryptoGeneratedCompareFieldsError(v); err != nil {
		return DescriptorVector{}, err
	}
	w := cryptoHashWriter(generatorIdentityPrefix + "crypto-admission\x00")
	length := uint64(cryptoGeneratedAdmissionLength)
	if v.Purpose == CryptoGeneratedOriginalVerificationPurpose {
		n, _ := GeneratedAttemptRecordLength(v.Original)
		length = uint64(cryptoGeneratedVerificationMaximumLength - GeneratedAttemptRecordBodyLength + n)
	}
	w.u32(uint32(length))
	writeCryptoGeneratedCompareTail(&w, v)
	return DescriptorVector{Digest: w.result(0).Digest, Length: length, Count: 1}, nil
}

func cryptoGeneratedCompareError(v CryptoGeneratedCompareRequest) error {
	if err := cryptoGeneratedContextError(v.Context); err != nil {
		return err
	}
	d, err := CryptoGeneratedAdmissionDescriptor(v)
	if err != nil {
		return err
	}
	if v.Purpose == CryptoGeneratedOriginalVerificationPurpose {
		if d != v.Context.IntentDescriptor || v.Original.DomainID != v.Context.DomainID {
			return ErrCryptoMessage
		}
		return nil
	}
	p, _ := cryptoGeneratedCompareParent(v)
	if d != v.Context.IntentDescriptor || p.DomainID != v.Context.DomainID ||
		v.Purpose == CryptoGeneratedReservationPurpose && (p.InitialPredecessorDigest != v.Context.PredecessorHEADDigest || p.ConditionDigest != v.Context.OriginalConditionDigest) {
		return ErrCryptoMessage
	}
	return nil
}

func EncodeCryptoGeneratedCompareRequest(v CryptoGeneratedCompareRequest) ([]byte, error) {
	if err := cryptoGeneratedCompareError(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, cryptoContextBlobLength+cryptoGeneratedAdmissionLength)}
	w.context(v.Context)
	writeCryptoGeneratedCompareTail(&w, v)
	return w.b, nil
}

func InspectCryptoGeneratedCompareRequest(b []byte) (CryptoGeneratedCompareRequest, error) {
	if len(b) > CryptoGeneratedCompareLimit {
		return CryptoGeneratedCompareRequest{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: b}
	v := CryptoGeneratedCompareRequest{Context: readCryptoGeneratedContext(&r), Purpose: CryptoGeneratedPurpose(r.u8())}
	if !v.Purpose.valid() {
		return CryptoGeneratedCompareRequest{}, ErrCryptoMessage
	}
	if v.Purpose == CryptoGeneratedOriginalVerificationPurpose {
		row := r.blob(SupportRecordOverhead + GeneratedAttemptRecordBodyLength)
		p := cryptoReader{b: row}
		kind, attempt, body := p.u8(), p.requiredID(), p.blob(GeneratedAttemptRecordBodyLength)
		if r.err != nil || p.end() != nil || SupportRecordKind(kind) != GeneratedAttemptSupportKind {
			return CryptoGeneratedCompareRequest{}, ErrCryptoMessage
		}
		var err error
		v.Original, err = InspectGeneratedAttemptRecord(body)
		if err != nil || v.Original.AttemptID != attempt {
			return CryptoGeneratedCompareRequest{}, ErrCryptoMessage
		}
		v.PlanGraph, v.UsePlanDigest, v.MaterialID = readGeneratorDescriptor(&r), r.requiredID(), r.requiredID()
		v.OriginalOwnerKind, v.OriginalOwnerID, v.Target = r.u8(), r.requiredID(), readGeneratorDescriptor(&r)
		v.OriginalResult = GeneratorResultReference{Schema: r.u16(), ResultID: r.requiredID(), ResultBodyDigest: r.requiredID(), ResultLength: r.u32()}
		if err := r.end(); err != nil {
			return CryptoGeneratedCompareRequest{}, err
		}
		if err := cryptoGeneratedCompareError(v); err != nil {
			return CryptoGeneratedCompareRequest{}, err
		}
		return v, nil
	}
	row := r.blob(cryptoGeneratedParentRowLength)
	if r.err != nil {
		return CryptoGeneratedCompareRequest{}, r.failure()
	}
	p := cryptoReader{b: row}
	kind, operation, body := p.u8(), p.requiredID(), p.blob(GeneratedParentRecordBodyLength)
	if err := p.end(); err != nil {
		return CryptoGeneratedCompareRequest{}, err
	}
	if SupportRecordKind(kind) != GeneratedParentSupportKind {
		return CryptoGeneratedCompareRequest{}, ErrCryptoMessage
	}
	var err error
	if v.Purpose == CryptoGeneratedReservationPurpose {
		v.ParentPlan, err = InspectGeneratedParentPlan(body)
		if v.ParentPlan.OperationID != operation {
			return CryptoGeneratedCompareRequest{}, ErrCryptoMessage
		}
	} else {
		v.Parent, err = InspectGeneratedParentRecord(body)
		if v.Parent.OperationID != operation {
			return CryptoGeneratedCompareRequest{}, ErrCryptoMessage
		}
	}
	if err != nil {
		return CryptoGeneratedCompareRequest{}, err
	}
	v.PlanGraph, v.UsePlanDigest, v.MaterialID = readGeneratorDescriptor(&r), r.requiredID(), r.requiredID()
	v.AcceptedSources, v.IntendedEntryPlans = readGeneratorDescriptor(&r), readGeneratorDescriptor(&r)
	if err := r.end(); err != nil {
		return CryptoGeneratedCompareRequest{}, err
	}
	if err := cryptoGeneratedCompareError(v); err != nil {
		return CryptoGeneratedCompareRequest{}, err
	}
	return v, nil
}

type CryptoGeneratedPlanPartRequest struct {
	OperationRef ID
	Context      ApplyContext
	BlobKind     uint8
	Index, Count uint16
	Total        uint64
	WholeDigest  ID
	Offset       uint32
	Payload      []byte
}

type CryptoGeneratedPlanPartRequestView CryptoGeneratedPlanPartRequest

func cryptoGeneratedPartError(v CryptoGeneratedPlanPartRequest) error {
	if err := cryptoGeneratedStageError(v.OperationRef, v.Context); err != nil {
		return err
	}
	limit := uint64(GeneratorDeclarationMaxFramedLength)
	if v.BlobKind == GeneratorContentGraph {
		limit = GeneratorGraphMaxLength
	} else if v.BlobKind != GeneratorContentDeclaration {
		return ErrCryptoMessage
	}
	if v.Total > limit || len(v.Payload) > GeneratedFragmentMaxPayload {
		return ErrCryptoCapacity
	}
	if v.Total == 0 || v.WholeDigest.IsZero() || v.Count == 0 || v.Index >= v.Count ||
		uint64(v.Count) != (v.Total+GeneratedFragmentMaxPayload-1)/GeneratedFragmentMaxPayload ||
		uint64(v.Offset) != uint64(v.Index)*GeneratedFragmentMaxPayload || uint64(v.Offset) >= v.Total ||
		uint64(len(v.Payload)) != min(uint64(GeneratedFragmentMaxPayload), v.Total-uint64(v.Offset)) {
		return ErrCryptoMessage
	}
	return nil
}

func EncodeCryptoGeneratedPlanPartRequest(v CryptoGeneratedPlanPartRequest) ([]byte, error) {
	if err := cryptoGeneratedPartError(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, 536+len(v.Payload))}
	w.id(v.OperationRef)
	w.context(v.Context)
	w.u8(uint8(CryptoGeneratedPreparePlanPart))
	w.u8(v.BlobKind)
	w.u16(v.Index)
	w.u16(v.Count)
	w.u64(v.Total)
	w.id(v.WholeDigest)
	w.u32(v.Offset)
	w.blob(v.Payload)
	return w.b, nil
}

func InspectCryptoGeneratedPlanPartRequest(b []byte) (CryptoGeneratedPlanPartRequestView, error) {
	if len(b) > CryptoGeneratedPartLimit {
		return CryptoGeneratedPlanPartRequestView{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: b}
	v := CryptoGeneratedPlanPartRequestView{OperationRef: r.requiredID(), Context: readCryptoGeneratedContext(&r)}
	if CryptoGeneratedPrepareVariant(r.u8()) != CryptoGeneratedPreparePlanPart {
		return CryptoGeneratedPlanPartRequestView{}, ErrCryptoMessage
	}
	v.BlobKind, v.Index, v.Count, v.Total, v.WholeDigest, v.Offset, v.Payload = r.u8(), r.u16(), r.u16(), r.u64(), r.requiredID(), r.u32(), r.blob(GeneratedFragmentMaxPayload)
	if err := r.end(); err != nil {
		return CryptoGeneratedPlanPartRequestView{}, err
	}
	if err := cryptoGeneratedPartError(CryptoGeneratedPlanPartRequest(v)); err != nil {
		return CryptoGeneratedPlanPartRequestView{}, err
	}
	return v, nil
}

func (v CryptoGeneratedPlanPartRequestView) Own() (CryptoGeneratedPlanPartRequest, error) {
	if err := cryptoGeneratedPartError(CryptoGeneratedPlanPartRequest(v)); err != nil {
		return CryptoGeneratedPlanPartRequest{}, err
	}
	out := CryptoGeneratedPlanPartRequest(v)
	out.Payload = ownedBytes(v.Payload)
	return out, nil
}

type CryptoGeneratedFinishPlanRequest struct {
	OperationRef                   ID
	Context                        ApplyContext
	Declaration, Graph, SourceUses GeneratorDescriptor
}

func cryptoGeneratedFinishError(v CryptoGeneratedFinishPlanRequest) error {
	if err := cryptoGeneratedStageError(v.OperationRef, v.Context); err != nil {
		return err
	}
	if !generatedDescriptorsValid(v.Declaration, v.Graph, v.SourceUses) {
		return ErrCryptoMessage
	}
	if v.Declaration.Length > GeneratorDeclarationMaxFramedLength || v.Graph.Length > GeneratorGraphMaxLength || v.SourceUses.Count > CryptoMaxValueEntries {
		return ErrCryptoCapacity
	}
	return nil
}

func EncodeCryptoGeneratedFinishPlanRequest(v CryptoGeneratedFinishPlanRequest) ([]byte, error) {
	if err := cryptoGeneratedFinishError(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, 615)}
	w.id(v.OperationRef)
	w.context(v.Context)
	w.u8(uint8(CryptoGeneratedPrepareFinishPlan))
	writeGeneratorDescriptor(&w, v.Declaration)
	writeGeneratorDescriptor(&w, v.Graph)
	writeGeneratorDescriptor(&w, v.SourceUses)
	return w.b, nil
}

func InspectCryptoGeneratedFinishPlanRequest(b []byte) (CryptoGeneratedFinishPlanRequest, error) {
	if len(b) > 615 {
		return CryptoGeneratedFinishPlanRequest{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: b}
	v := CryptoGeneratedFinishPlanRequest{OperationRef: r.requiredID(), Context: readCryptoGeneratedContext(&r)}
	if CryptoGeneratedPrepareVariant(r.u8()) != CryptoGeneratedPrepareFinishPlan {
		return CryptoGeneratedFinishPlanRequest{}, ErrCryptoMessage
	}
	v.Declaration, v.Graph, v.SourceUses = readGeneratorDescriptor(&r), readGeneratorDescriptor(&r), readGeneratorDescriptor(&r)
	if err := r.end(); err != nil {
		return CryptoGeneratedFinishPlanRequest{}, err
	}
	if err := cryptoGeneratedFinishError(v); err != nil {
		return CryptoGeneratedFinishPlanRequest{}, err
	}
	return v, nil
}

// GeneratedProducerPreparation binds producer identity before command issuance.
// Preparation fixes the original public resource digest before command issue.
type GeneratedProducerPreparation struct {
	Schema                                                                          uint16
	DomainID, OperationID, RequestIdentityDigest, PlanGraphID, LineageID, AttemptID ID
	TransmissionID, ResultID, ResultContractID, DescriptorID, ExecutorID            ID
	RequestDigest, IntentDigest, ResourceContractID, CredentialRouteID              ID
	Action                                                                          uint8
	LifecycleMode                                                                   GeneratorLifecycleMode
	ResourceDigest                                                                  ID
}
type GeneratedProducerCommand struct {
	GeneratedProducerPreparation
	DeadlineUnixMillis    uint64
	Intent, OriginalFacts []byte
}

func generatedProducerPreparationLength(v GeneratedProducerPreparation) (int, error) {
	if v.Schema != GeneratedProducerPreparationSchema || !publicIDsValid(v.DomainID, v.OperationID, v.RequestIdentityDigest, v.PlanGraphID, v.LineageID, v.AttemptID, v.TransmissionID, v.ResultID, v.ResultContractID, v.DescriptorID, v.ExecutorID, v.RequestDigest, v.IntentDigest, v.CredentialRouteID) || !v.LifecycleMode.resourceValid(v.ResourceContractID) || (v.Action != GeneratorActionCreate || !v.ResourceDigest.IsZero()) && (v.Action != GeneratorActionDelete || v.LifecycleMode != GeneratorLifecycleManaged || v.ResourceDigest.IsZero()) {
		return 0, ErrCryptoMessage
	}
	return 516, nil
}
func writeGeneratedProducerIDs(w *cryptoWriter, v GeneratedProducerPreparation) {
	for _, id := range [...]ID{v.DomainID, v.OperationID, v.RequestIdentityDigest, v.PlanGraphID, v.LineageID, v.AttemptID, v.TransmissionID, v.ResultID, v.ResultContractID, v.DescriptorID, v.ExecutorID, v.RequestDigest, v.IntentDigest, v.ResourceContractID, v.CredentialRouteID} {
		w.id(id)
	}
}
func readGeneratedProducerIDs(r *cryptoReader, v *GeneratedProducerPreparation) {
	for _, id := range []*ID{&v.DomainID, &v.OperationID, &v.RequestIdentityDigest, &v.PlanGraphID, &v.LineageID, &v.AttemptID, &v.TransmissionID, &v.ResultID, &v.ResultContractID, &v.DescriptorID, &v.ExecutorID, &v.RequestDigest, &v.IntentDigest, &v.ResourceContractID, &v.CredentialRouteID} {
		*id = r.id()
	}
}
func writeGeneratedProducerPreparation(w *cryptoWriter, v GeneratedProducerPreparation) {
	w.u16(v.Schema)
	w.u8(v.Action)
	writeGeneratedProducerIDs(w, v)
	w.u8(uint8(v.LifecycleMode))
	w.id(v.ResourceDigest)
}
func EncodeGeneratedProducerPreparation(v GeneratedProducerPreparation) ([]byte, error) {
	n, err := generatedProducerPreparationLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeGeneratedProducerPreparation(&w, v)
	return w.b, nil
}
func InspectGeneratedProducerPreparation(body []byte) (GeneratedProducerPreparation, error) {
	if len(body) > 516 {
		return GeneratedProducerPreparation{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: body}
	v := GeneratedProducerPreparation{Schema: r.u16(), Action: r.u8()}
	readGeneratedProducerIDs(&r, &v)
	v.LifecycleMode = GeneratorLifecycleMode(r.u8())
	v.ResourceDigest = r.id()
	if err := r.end(); err != nil {
		return GeneratedProducerPreparation{}, err
	}
	if _, err := generatedProducerPreparationLength(v); err != nil {
		return GeneratedProducerPreparation{}, err
	}
	return v, nil
}
func generatedProducerCommandLength(v GeneratedProducerCommand) (int, error) {
	if _, err := generatedProducerPreparationLength(v.GeneratedProducerPreparation); err != nil {
		return 0, err
	}
	if v.Schema != GeneratedProducerCommandSchema || v.DeadlineUnixMillis == 0 || v.DeadlineUnixMillis > math.MaxInt64 {
		return 0, ErrCryptoMessage
	}
	if len(v.Intent) > GeneratorIntentMaxLength || len(v.OriginalFacts) > GeneratorSafeFactsEnvelopeLength {
		return 0, ErrCryptoCapacity
	}
	intent, err := InspectGeneratorIntent(v.Intent)
	digest, digestErr := GeneratorIntentDigest(v.Intent)
	if err != nil || digestErr != nil || digest != v.IntentDigest || intent.LifecycleMode != v.LifecycleMode || intent.ResourceContractID != v.ResourceContractID {
		return 0, ErrCryptoMessage
	}
	if v.Action == GeneratorActionCreate {
		if len(v.OriginalFacts) != 0 {
			return 0, ErrCryptoMessage
		}
	} else {
		original, err := InspectGeneratorSafeFacts(v.OriginalFacts)
		if err != nil || original.Action != GeneratorActionCreate || original.IntentDigest != v.IntentDigest || original.ResourceContractID != v.ResourceContractID || original.Disposition != GeneratorDispositionCompleteCreate && original.Disposition != GeneratorDispositionOwnedUnusableCreate {
			return 0, ErrCryptoMessage
		}
		resource, err := GeneratorResourceDigest(original.GeneratorSafeFacts)
		if err != nil || resource != v.ResourceDigest {
			return 0, ErrCryptoMessage
		}
	}
	return 500 + len(v.Intent) + len(v.OriginalFacts), nil
}
func writeGeneratedProducerCommand(w *cryptoWriter, v GeneratedProducerCommand) {
	w.u16(v.Schema)
	w.u8(v.Action)
	w.u64(v.DeadlineUnixMillis)
	writeGeneratedProducerIDs(w, v.GeneratedProducerPreparation)
	w.u8(uint8(v.LifecycleMode))
	w.blob(v.Intent)
	w.blob(v.OriginalFacts)
}
func EncodeGeneratedProducerCommand(v GeneratedProducerCommand) ([]byte, error) {
	n, err := generatedProducerCommandLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeGeneratedProducerCommand(&w, v)
	return w.b, nil
}
func InspectGeneratedProducerCommand(body []byte) (GeneratedProducerCommand, error) {
	if len(body) > 397812 {
		return GeneratedProducerCommand{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: body}
	v := GeneratedProducerCommand{GeneratedProducerPreparation: GeneratedProducerPreparation{Schema: r.u16(), Action: r.u8()}, DeadlineUnixMillis: r.u64()}
	readGeneratedProducerIDs(&r, &v.GeneratedProducerPreparation)
	v.LifecycleMode = GeneratorLifecycleMode(r.u8())
	v.Intent = r.blob(GeneratorIntentMaxLength)
	v.OriginalFacts = r.blob(GeneratorSafeFactsEnvelopeLength)
	if err := r.end(); err != nil {
		return GeneratedProducerCommand{}, err
	}
	if v.Action == GeneratorActionDelete {
		facts, err := InspectGeneratorSafeFacts(v.OriginalFacts)
		if err != nil {
			return GeneratedProducerCommand{}, err
		}
		v.ResourceDigest, err = GeneratorResourceDigest(facts.GeneratorSafeFacts)
		if err != nil {
			return GeneratedProducerCommand{}, err
		}
	}
	if _, err := generatedProducerCommandLength(v); err != nil {
		return GeneratedProducerCommand{}, err
	}
	return v, nil
}

type CryptoGeneratedDiscardRequest struct {
	OperationRef ID
	Context      ApplyContext
}

func EncodeCryptoGeneratedDiscardRequest(v CryptoGeneratedDiscardRequest) ([]byte, error) {
	if err := cryptoGeneratedStageError(v.OperationRef, v.Context); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, cryptoGeneratedOperationContextLength)}
	w.id(v.OperationRef)
	w.context(v.Context)
	return w.b, nil
}

func InspectCryptoGeneratedDiscardRequest(b []byte) (CryptoGeneratedDiscardRequest, error) {
	if len(b) > cryptoGeneratedOperationContextLength {
		return CryptoGeneratedDiscardRequest{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: b}
	v := CryptoGeneratedDiscardRequest{OperationRef: r.requiredID(), Context: readCryptoGeneratedContext(&r)}
	if err := r.end(); err != nil {
		return CryptoGeneratedDiscardRequest{}, err
	}
	return v, nil
}

type CryptoGeneratedProducerRequest struct {
	OperationRef ID
	Context      ApplyContext
	Template     GeneratorAttemptTemplate
	Material     OperationMaterialRecord
	SeedAccess   []byte
	Preparation  GeneratedProducerPreparation
	Intent       GeneratorDescriptor
}

type CryptoGeneratedProducerRequestView CryptoGeneratedProducerRequest

func cryptoGeneratedSeedAccessError(material OperationMaterialRecord, body []byte) error {
	if len(body) > AccessRecordFixedLength+seedAccessWrapLimit*WrapRowWireLength {
		return ErrCryptoCapacity
	}
	if _, err := OperationMaterialRecordLength(material); err != nil {
		return err
	}
	if material.Core.UsePlanDigest.IsZero() {
		return ErrCryptoMessage
	}
	access, err := InspectAccessRecord(body)
	if err != nil {
		return err
	}
	context, err := OperationMaterialContextDigest(material.Core)
	if err != nil {
		return err
	}
	if access.MaterialKind != OperationSeedMaterialKind || access.MaterialID != material.Core.OperationMaterialID || access.MaterialContextDigest != context || access.PackageCheck != material.SeedCheck {
		return ErrCryptoMessage
	}
	return nil
}

func cryptoGeneratedProducerLength(v CryptoGeneratedProducerRequest) (int, error) {
	if err := cryptoGeneratedStageError(v.OperationRef, v.Context); err != nil {
		return 0, err
	}
	if !v.Template.valid() {
		return 0, ErrCryptoMessage
	}
	if err := cryptoGeneratedSeedAccessError(v.Material, v.SeedAccess); err != nil {
		return 0, err
	}
	n, err := generatedProducerPreparationLength(v.Preparation)
	if err != nil {
		return 0, err
	}
	x, c, m := v.Template, v.Preparation, v.Material.Core
	if m.DomainID != v.Context.DomainID || m.CompatibilityID != v.Context.CompatibilityID || c.DomainID != m.DomainID || c.OperationID != m.OperationID ||
		c.Action != x.Action || c.LineageID != x.LineageID || c.AttemptID != x.AttemptID || c.TransmissionID != x.TransmissionID ||
		c.ResultID != x.ResultID || c.ResultContractID != x.ResultContractID || c.DescriptorID != x.DescriptorID || c.ExecutorID != x.ExecutorID ||
		c.CredentialRouteID != x.CredentialRouteID || c.IntentDigest != x.IntentDigest || c.ResourceContractID != x.ResourceContractID || c.LifecycleMode != x.LifecycleMode || x.Action == GeneratorActionDelete && !x.ResourceDigest.IsZero() && c.ResourceDigest != x.ResourceDigest ||
		v.Intent.Length == 0 || v.Intent.Count != 1 || v.Intent.Digest != x.IntentDigest {
		return 0, ErrCryptoMessage
	}
	if v.Intent.Length > GeneratorIntentMaxLength {
		return 0, ErrCryptoCapacity
	}
	return cryptoGeneratedOperationContextLength + 1 + 4 + generatorAttemptTemplateEncodedLength(v.Template) + 4 + operationMaterialRecordLength + 4 + len(v.SeedAccess) + 4 + n + GeneratorDescriptorLength, nil
}

func EncodeCryptoGeneratedProducerRequest(v CryptoGeneratedProducerRequest) ([]byte, error) {
	n, err := cryptoGeneratedProducerLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	w.id(v.OperationRef)
	w.context(v.Context)
	w.u8(uint8(CryptoGeneratedPrepareProducer))
	w.u32(uint32(generatorAttemptTemplateEncodedLength(v.Template)))
	writeGeneratorAttemptTemplate(&w, v.Template)
	w.u32(operationMaterialRecordLength)
	writeOperationMaterialRecord(&w, v.Material)
	w.blob(v.SeedAccess)
	preparationLength, _ := generatedProducerPreparationLength(v.Preparation)
	w.u32(uint32(preparationLength))
	writeGeneratedProducerPreparation(&w, v.Preparation)
	writeGeneratorDescriptor(&w, v.Intent)
	return w.b, nil
}

func InspectCryptoGeneratedProducerRequest(b []byte) (CryptoGeneratedProducerRequestView, error) {
	if len(b) > 8<<10 {
		return CryptoGeneratedProducerRequestView{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: b}
	v := CryptoGeneratedProducerRequestView{OperationRef: r.requiredID(), Context: readCryptoGeneratedContext(&r)}
	if CryptoGeneratedPrepareVariant(r.u8()) != CryptoGeneratedPrepareProducer {
		return CryptoGeneratedProducerRequestView{}, ErrCryptoMessage
	}
	template, material := r.blob(GeneratorAttemptTemplateMaxLength), r.blob(operationMaterialRecordLength)
	v.SeedAccess = r.blob(AccessRecordFixedLength + seedAccessWrapLimit*WrapRowWireLength)
	preparation := r.blob(516)
	// This field describes raw intent bytes, not a count-and-blob vector.
	v.Intent = GeneratorDescriptor{Digest: r.requiredID(), Length: r.u64(), Count: r.u32()}
	if err := r.end(); err != nil {
		return CryptoGeneratedProducerRequestView{}, err
	}
	var err error
	v.Template, err = InspectGeneratorAttemptTemplate(template)
	if err != nil {
		return CryptoGeneratedProducerRequestView{}, err
	}
	v.Material, err = InspectOperationMaterialRecord(material)
	if err != nil {
		return CryptoGeneratedProducerRequestView{}, err
	}
	v.Preparation, err = InspectGeneratedProducerPreparation(preparation)
	if err != nil {
		return CryptoGeneratedProducerRequestView{}, err
	}
	if _, err := cryptoGeneratedProducerLength(CryptoGeneratedProducerRequest(v)); err != nil {
		return CryptoGeneratedProducerRequestView{}, err
	}
	return v, nil
}

func (v CryptoGeneratedProducerRequestView) Own() (CryptoGeneratedProducerRequest, error) {
	if _, err := cryptoGeneratedProducerLength(CryptoGeneratedProducerRequest(v)); err != nil {
		return CryptoGeneratedProducerRequest{}, err
	}
	out := CryptoGeneratedProducerRequest(v)
	out.SeedAccess = ownedBytes(v.SeedAccess)
	return out, nil
}

type CryptoGeneratedAdoptRequest struct {
	OperationRef   ID
	Context        ApplyContext
	Result         []byte
	ExpectedResult GeneratorDescriptor
}

type CryptoGeneratedAdoptRequestView CryptoGeneratedAdoptRequest

func cryptoGeneratedAdoptError(v CryptoGeneratedAdoptRequest) error {
	if len(v.Result) > GeneratedResultRecordMaxLength {
		return ErrCryptoCapacity
	}
	if err := cryptoGeneratedStageError(v.OperationRef, v.Context); err != nil {
		return err
	}
	result, err := InspectGeneratedResultRecord(v.Result)
	if err != nil {
		return err
	}
	if result.Core.DomainID != v.Context.DomainID || result.Transfer.Core.CompatibilityID != v.Context.CompatibilityID ||
		v.ExpectedResult.Count != 1 || v.ExpectedResult.Length != uint64(len(v.Result)) || v.ExpectedResult.Digest != Hash(v.Result) {
		return ErrCryptoMessage
	}
	return nil
}

func EncodeCryptoGeneratedAdoptRequest(v CryptoGeneratedAdoptRequest) ([]byte, error) {
	if err := cryptoGeneratedAdoptError(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, cryptoGeneratedOperationContextLength+49+len(v.Result))}
	w.id(v.OperationRef)
	w.context(v.Context)
	w.u8(uint8(CryptoGeneratedPrepareAdopt))
	w.blob(v.Result)
	writeGeneratorDescriptor(&w, v.ExpectedResult)
	return w.b, nil
}

func InspectCryptoGeneratedAdoptRequest(b []byte) (CryptoGeneratedAdoptRequestView, error) {
	if len(b) > CryptoGeneratedAdoptLimit {
		return CryptoGeneratedAdoptRequestView{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: b}
	v := CryptoGeneratedAdoptRequestView{OperationRef: r.requiredID(), Context: readCryptoGeneratedContext(&r)}
	if CryptoGeneratedPrepareVariant(r.u8()) != CryptoGeneratedPrepareAdopt {
		return CryptoGeneratedAdoptRequestView{}, ErrCryptoMessage
	}
	v.Result = r.blob(GeneratedResultRecordMaxLength)
	v.ExpectedResult = readGeneratorDescriptor(&r)
	if err := r.end(); err != nil {
		return CryptoGeneratedAdoptRequestView{}, err
	}
	if err := cryptoGeneratedAdoptError(CryptoGeneratedAdoptRequest(v)); err != nil {
		return CryptoGeneratedAdoptRequestView{}, err
	}
	return v, nil
}

func (v CryptoGeneratedAdoptRequestView) Own() (CryptoGeneratedAdoptRequest, error) {
	if err := cryptoGeneratedAdoptError(CryptoGeneratedAdoptRequest(v)); err != nil {
		return CryptoGeneratedAdoptRequest{}, err
	}
	out := CryptoGeneratedAdoptRequest(v)
	out.Result = ownedBytes(v.Result)
	return out, nil
}

const GeneratorResultReferenceLength = 70

type GeneratorResultReference struct {
	Schema                     uint16
	ResultID, ResultBodyDigest ID
	ResultLength               uint32
}

func generatorResultReferenceError(v GeneratorResultReference) error {
	if v.ResultLength > uint32(GeneratedResultRecordMaxLength) {
		return ErrCryptoCapacity
	}
	if v.Schema != 1 || !publicIDsValid(v.ResultID, v.ResultBodyDigest) || v.ResultLength == 0 {
		return ErrCryptoMessage
	}
	return nil
}

func writeGeneratorResultReference(w *cryptoWriter, v GeneratorResultReference) {
	w.u16(v.Schema)
	w.id(v.ResultID)
	w.id(v.ResultBodyDigest)
	w.u32(v.ResultLength)
}

func EncodeGeneratorResultReference(v GeneratorResultReference) ([]byte, error) {
	if err := generatorResultReferenceError(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, GeneratorResultReferenceLength)}
	writeGeneratorResultReference(&w, v)
	return w.b, nil
}

func InspectGeneratorResultReference(b []byte) (GeneratorResultReference, error) {
	if len(b) > GeneratorResultReferenceLength {
		return GeneratorResultReference{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: b}
	v := GeneratorResultReference{Schema: r.u16(), ResultID: r.requiredID(), ResultBodyDigest: r.requiredID(), ResultLength: r.u32()}
	if err := r.end(); err != nil {
		return GeneratorResultReference{}, err
	}
	if err := generatorResultReferenceError(v); err != nil {
		return GeneratorResultReference{}, err
	}
	return v, nil
}

func GeneratorResultReferencesDescriptor(rows []GeneratorResultReference) (DescriptorVector, error) {
	if len(rows) > GeneratorMaxTemplates {
		return DescriptorVector{}, ErrCryptoCapacity
	}
	for i, row := range rows {
		if err := generatorResultReferenceError(row); err != nil {
			return DescriptorVector{}, err
		}
		if i > 0 && bytes.Compare(rows[i-1].ResultID[:], row.ResultID[:]) >= 0 {
			return DescriptorVector{}, ErrCryptoMessage
		}
	}
	n := 4 + (4+GeneratorResultReferenceLength)*len(rows)
	w := generatorVectorHashWriter("validated-results", n, len(rows))
	for _, row := range rows {
		w.u32(GeneratorResultReferenceLength)
		writeGeneratorResultReference(&w, row)
	}
	return DescriptorVector{Digest: w.result(len(rows)).Digest, Length: uint64(n), Count: uint32(len(rows))}, nil
}

func CryptoGeneratedKeyUseDescriptor(rows []KeyUseRow) (DescriptorVector, error) {
	if _, err := KeyUseRowsLength(rows); err != nil {
		return DescriptorVector{}, err
	}
	w := cryptoHashWriter("")
	writeKeyUseRows(&w, rows)
	return w.result(len(rows)), nil
}

// CandidatePublicStateDescriptor is the complete PublicStateDescriptor, including its
// AccessRoot and RequiredSupport. The other candidate descriptors traverse
// globally ordered AccessRecords and logical RequiredSupport, not pages.
type CryptoGeneratedFreezeRequest struct {
	OperationRef                                                      ID
	Context                                                           ApplyContext
	PhaseID, RequestIdentityDigest                                    ID
	CandidatePublicStateDescriptor, CandidateAccess, CandidateSupport DescriptorVector
	HeadCoreDigest, ConditionDigest                                   ID
	ActualResults, KeyUses                                            DescriptorVector
}

type CryptoGeneratedClaimRequest CryptoGeneratedFreezeRequest

func cryptoGeneratedAccessDescriptorError(domain ID, d DescriptorVector) error {
	if d.Count > MaxChildPages*AccessPageRecordLimit {
		return ErrCryptoCapacity
	}
	if d.Count == 0 {
		if d != emptyAccessRecordsDescriptor(domain) {
			return ErrCryptoMessage
		}
		return nil
	}
	n := uint64(d.Count)
	base := uint64(accessRecordsFixedLength) + (4+AccessRecordFixedLength)*n
	if d.Digest.IsZero() || d.Length < base+WrapRowWireLength*n {
		return ErrCryptoMessage
	}
	wraps := d.Length - base
	if wraps%WrapRowWireLength != 0 {
		return ErrCryptoMessage
	}
	if wraps/WrapRowWireLength > valueAccessWrapLimit*n || d.Length-uint64(accessRecordsFixedLength)-4*n > uint64(MaxChildPages)*(MaxAccessPageLength-AccessPageHeaderLength) {
		return ErrCryptoCapacity
	}
	return nil
}

func cryptoGeneratedFrozenError(v CryptoGeneratedFreezeRequest) error {
	if err := cryptoGeneratedStageError(v.OperationRef, v.Context); err != nil {
		return err
	}
	if !publicIDsValid(v.PhaseID, v.RequestIdentityDigest, v.HeadCoreDigest, v.ConditionDigest, v.CandidatePublicStateDescriptor.Digest, v.CandidateSupport.Digest, v.ActualResults.Digest, v.KeyUses.Digest) || v.ConditionDigest != v.Context.OriginalConditionDigest {
		return ErrCryptoMessage
	}
	if err := cryptoPublicDescriptorError(v.CandidatePublicStateDescriptor); err != nil {
		return err
	}
	if err := cryptoGeneratedAccessDescriptorError(v.Context.DomainID, v.CandidateAccess); err != nil {
		return err
	}
	if !requiredSupportDescriptorValid(v.CandidateSupport) {
		return ErrCryptoMessage
	}
	if v.CandidateSupport.Count == 0 {
		empty, err := RequiredSupportDescriptor(v.Context.DomainID, nil)
		if err != nil || v.CandidateSupport != empty {
			return ErrCryptoMessage
		}
	}
	if v.ActualResults.Count > GeneratorMaxTemplates || v.KeyUses.Count > KeyUseRowsMaxCount {
		return ErrCryptoCapacity
	}
	if v.ActualResults.Length != 4+74*uint64(v.ActualResults.Count) || v.KeyUses.Length != 2+KeyUseRowLength*uint64(v.KeyUses.Count) {
		return ErrCryptoMessage
	}
	if v.ActualResults.Count == 0 {
		empty, _ := GeneratorResultReferencesDescriptor(nil)
		if v.ActualResults != empty {
			return ErrCryptoMessage
		}
	}
	if v.KeyUses.Count == 0 && v.KeyUses.Digest != Hash([]byte{0, 0}) {
		return ErrCryptoMessage
	}
	return nil
}

func writeCryptoGeneratedFrozen(w *cryptoWriter, v CryptoGeneratedFreezeRequest) {
	w.id(v.OperationRef)
	w.context(v.Context)
	w.id(v.PhaseID)
	w.id(v.RequestIdentityDigest)
	w.descriptor(v.CandidatePublicStateDescriptor)
	w.descriptor(v.CandidateAccess)
	w.descriptor(v.CandidateSupport)
	w.id(v.HeadCoreDigest)
	w.id(v.ConditionDigest)
	w.descriptor(v.ActualResults)
	w.descriptor(v.KeyUses)
}

func EncodeCryptoGeneratedFreezeRequest(v CryptoGeneratedFreezeRequest) ([]byte, error) {
	if err := cryptoGeneratedFrozenError(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, CryptoGeneratedFrozenLength)}
	writeCryptoGeneratedFrozen(&w, v)
	return w.b, nil
}

// CryptoGeneratedFactDigest binds the private custody instance to every frozen
// candidate field. The closed purpose cannot be reused by another class.
func CryptoGeneratedFactDigest(instance ID, v CryptoGeneratedFreezeRequest) (ID, error) {
	if instance.IsZero() {
		return ID{}, ErrCryptoMessage
	}
	if err := cryptoGeneratedFrozenError(v); err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter(cryptoPurposePrefix + "generated-facts-v1\x00")
	w.id(instance)
	w.u32(CryptoGeneratedFrozenLength)
	writeCryptoGeneratedFrozen(&w, v)
	return w.result(0).Digest, nil
}

func InspectCryptoGeneratedFreezeRequest(b []byte) (CryptoGeneratedFreezeRequest, error) {
	if len(b) > CryptoGeneratedFrozenLength {
		return CryptoGeneratedFreezeRequest{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: b}
	v := CryptoGeneratedFreezeRequest{OperationRef: r.requiredID(), Context: readCryptoGeneratedContext(&r), PhaseID: r.requiredID(), RequestIdentityDigest: r.requiredID(), CandidatePublicStateDescriptor: r.descriptor(), CandidateAccess: r.descriptor(), CandidateSupport: r.descriptor(), HeadCoreDigest: r.requiredID(), ConditionDigest: r.requiredID(), ActualResults: r.descriptor(), KeyUses: r.descriptor()}
	if err := r.end(); err != nil {
		return CryptoGeneratedFreezeRequest{}, err
	}
	if err := cryptoGeneratedFrozenError(v); err != nil {
		return CryptoGeneratedFreezeRequest{}, err
	}
	return v, nil
}

func EncodeCryptoGeneratedClaimRequest(v CryptoGeneratedClaimRequest) ([]byte, error) {
	return EncodeCryptoGeneratedFreezeRequest(CryptoGeneratedFreezeRequest(v))
}
func InspectCryptoGeneratedClaimRequest(b []byte) (CryptoGeneratedClaimRequest, error) {
	v, err := InspectCryptoGeneratedFreezeRequest(b)
	return CryptoGeneratedClaimRequest(v), err
}

// CryptoGeneratedValueEntryPlan is a preparation projection, not an incomplete
// stored ValueEntry. Private admission fixes its graph slot and recipients.
type CryptoGeneratedValueEntryPlan struct {
	OutputEncoding uint8
	Slot           uint16
	Result         []byte
	ValueCore      ValueCore
	Generated      GeneratedEntryMetadata
	Recipients     []ID
}

type CryptoGeneratedValueEntryPlanView struct {
	OutputEncoding uint8
	Slot           uint16
	Result         []byte
	ValueCore      ValueCoreView
	Generated      GeneratedEntryMetadata
	RecipientIDs   []byte
}

type CryptoGeneratedValueEntriesRequest struct {
	OperationRef ID
	Context      ApplyContext
	PhaseID      ID
	BatchIndex   uint32
	Final        uint8
	Rows         []CryptoGeneratedValueEntryPlan
}

// Rows borrows the complete u32-counted, B(row)-framed region.
type CryptoGeneratedValueEntriesRequestView struct {
	OperationRef ID
	Context      ApplyContext
	PhaseID      ID
	BatchIndex   uint32
	Final        uint8
	Rows         []byte
}

type cryptoGeneratedValueEntryPlanTraversal struct {
	reader    cryptoReader
	remaining int
}

func (v CryptoGeneratedValueEntriesRequestView) forwardRows() cryptoGeneratedValueEntryPlanTraversal {
	r := cryptoReader{b: v.Rows}
	return cryptoGeneratedValueEntryPlanTraversal{reader: r, remaining: r.count(CryptoMaxValueEntries, 4)}
}

func (t *cryptoGeneratedValueEntryPlanTraversal) next() (CryptoGeneratedValueEntryPlanView, bool, error) {
	if t.reader.err != nil {
		return CryptoGeneratedValueEntryPlanView{}, false, t.reader.failure()
	}
	if t.remaining == 0 {
		return CryptoGeneratedValueEntryPlanView{}, false, t.reader.end()
	}
	row, err := inspectCryptoGeneratedValueEntryPlan(t.reader.blob(CryptoGeneratedMaterialLimit))
	if t.reader.err != nil {
		return CryptoGeneratedValueEntryPlanView{}, false, t.reader.failure()
	}
	if err != nil {
		return CryptoGeneratedValueEntryPlanView{}, false, err
	}
	t.remaining--
	return row, true, nil
}

func cryptoGeneratedBatchError(index uint32, final uint8, count int) error {
	if count > CryptoMaxValueEntries || index >= CryptoMaxValueEntries {
		return ErrCryptoCapacity
	}
	if final > 1 || count == 0 && (index != 0 || final != 1) {
		return ErrCryptoMessage
	}
	return nil
}

func cryptoGeneratedValueEntryPlanBinding(slot uint16, result []byte, core ValueCore, meta GeneratedEntryMetadata) error {
	if slot >= CryptoMaxValueEntries || len(result) > GeneratedResultRecordMaxLength {
		return ErrCryptoCapacity
	}
	if _, err := ValueCoreLength(core); err != nil {
		return err
	}
	binding, err := GeneratedBindingDigest(meta)
	if err != nil {
		return err
	}
	v, err := InspectGeneratedResultRecord(result)
	if err != nil {
		return err
	}
	resource, err := GeneratorResourceID(v.Core.DomainID, v.Core.OperationID, v.Core.AttemptID)
	if err != nil {
		return err
	}
	var resourceDigest ID
	if v.SafeFacts.LifecycleMode == GeneratorLifecycleManaged {
		resourceDigest, err = GeneratorResourceDigest(v.SafeFacts.GeneratorSafeFacts)
		if err != nil {
			return err
		}
	}
	if core.ValueSource != Generated || core.GeneratedBindingDigest != binding || core.ValueStateID != meta.GenerationID ||
		core.DomainID != v.Core.DomainID || core.CompatibilityID != v.Transfer.Core.CompatibilityID ||
		core.CryptoSupportID != v.Payload.CryptoSupportID || core.InputEncoding != v.Payload.InputEncoding || core.ContentLength != v.Payload.ContentLength || core.RetainedLength != v.Payload.RetainedLength || v.SafeFacts.Disposition != GeneratorDispositionCompleteCreate ||
		meta.ConfigContractID != v.Core.ConfigContractID || meta.IntentDigest != v.SafeFacts.IntentDigest ||
		meta.ResourceIncarnationID != resource || meta.OriginOperationID != v.Core.OperationID || meta.OriginAttemptID != v.Core.AttemptID ||
		meta.CreateResultID != v.Core.ResultID || meta.ResourceDigest != resourceDigest || meta.ResourceContractID != v.SafeFacts.ResourceContractID || meta.LifecycleMode != v.SafeFacts.LifecycleMode {
		return ErrCryptoMessage
	}
	return nil
}

func cryptoGeneratedValueEntryPlanLength(v CryptoGeneratedValueEntryPlan) (int, error) {
	if v.OutputEncoding != OutputEncodingRaw && v.OutputEncoding != OutputEncodingBase64 {
		return 0, ErrCryptoMessage
	}
	if err := cryptoGeneratedValueEntryPlanBinding(v.Slot, v.Result, v.ValueCore, v.Generated); err != nil {
		return 0, err
	}
	recipients, err := recipientIDsLength(v.Recipients)
	if err != nil {
		return 0, err
	}
	meta, _ := GeneratedEntryMetadataLength(v.Generated)
	return 2 + 1 + 4 + len(v.Result) + 4 + valueCoreEncodedLength(v.ValueCore) + 4 + meta + recipients, nil
}

func writeCryptoGeneratedValueEntryPlan(w *cryptoWriter, v CryptoGeneratedValueEntryPlan) {
	w.u16(v.Slot)
	w.u8(v.OutputEncoding)
	w.blob(v.Result)
	writeValueCoreBlob(w, v.ValueCore)
	n, _ := GeneratedEntryMetadataLength(v.Generated)
	w.u32(uint32(n))
	writeGeneratedEntryMetadata(w, v.Generated)
	writeRecipientIDs(w, v.Recipients)
}

func inspectCryptoGeneratedValueEntryPlan(b []byte) (CryptoGeneratedValueEntryPlanView, error) {
	r := cryptoReader{b: b}
	v := CryptoGeneratedValueEntryPlanView{Slot: r.u16(), OutputEncoding: r.u8(), Result: r.blob(GeneratedResultRecordMaxLength)}
	core, meta := r.blob(valueCoreMaxLength), r.blob(GeneratedEntryMetadataMaxLength)
	v.RecipientIDs = readRecipientIDs(&r)
	if err := r.end(); err != nil {
		return CryptoGeneratedValueEntryPlanView{}, err
	}
	var err error
	v.ValueCore, err = InspectValueCore(core)
	if err != nil {
		return CryptoGeneratedValueEntryPlanView{}, err
	}
	v.Generated, err = InspectGeneratedEntryMetadata(meta)
	if err != nil {
		return CryptoGeneratedValueEntryPlanView{}, err
	}
	if v.OutputEncoding != OutputEncodingRaw && v.OutputEncoding != OutputEncodingBase64 {
		return CryptoGeneratedValueEntryPlanView{}, ErrCryptoMessage
	}
	if err := cryptoGeneratedValueEntryPlanBinding(v.Slot, v.Result, v.ValueCore.fields(), v.Generated); err != nil {
		return CryptoGeneratedValueEntryPlanView{}, err
	}
	return v, nil
}

func (v CryptoGeneratedValueEntryPlanView) Own() (CryptoGeneratedValueEntryPlan, error) {
	if err := v.ValueCore.shapeError(); err != nil {
		return CryptoGeneratedValueEntryPlan{}, err
	}
	if err := recipientIDSpanError(v.RecipientIDs); err != nil {
		return CryptoGeneratedValueEntryPlan{}, err
	}
	if v.OutputEncoding != OutputEncodingRaw && v.OutputEncoding != OutputEncodingBase64 {
		return CryptoGeneratedValueEntryPlan{}, ErrCryptoMessage
	}
	if err := cryptoGeneratedValueEntryPlanBinding(v.Slot, v.Result, v.ValueCore.fields(), v.Generated); err != nil {
		return CryptoGeneratedValueEntryPlan{}, err
	}
	core, err := v.ValueCore.Own()
	if err != nil {
		return CryptoGeneratedValueEntryPlan{}, err
	}
	out := CryptoGeneratedValueEntryPlan{Slot: v.Slot, OutputEncoding: v.OutputEncoding, Result: ownedBytes(v.Result), ValueCore: core, Generated: v.Generated, Recipients: make([]ID, len(v.RecipientIDs)/32)}
	for i := range out.Recipients {
		out.Recipients[i] = ID(v.RecipientIDs[i*32 : (i+1)*32])
	}
	return out, nil
}

func cryptoGeneratedValueEntryPlansLength(v CryptoGeneratedValueEntriesRequest) (int, error) {
	if err := cryptoGeneratedStageError(v.OperationRef, v.Context); err != nil {
		return 0, err
	}
	if v.PhaseID.IsZero() {
		return 0, ErrCryptoMessage
	}
	if err := cryptoGeneratedBatchError(v.BatchIndex, v.Final, len(v.Rows)); err != nil {
		return 0, err
	}
	n := 4
	for i, row := range v.Rows {
		length, err := cryptoGeneratedValueEntryPlanLength(row)
		if err != nil {
			return 0, err
		}
		if i > 0 && v.Rows[i-1].Slot >= row.Slot || row.ValueCore.DomainID != v.Context.DomainID || row.ValueCore.CompatibilityID != v.Context.CompatibilityID {
			return 0, ErrCryptoMessage
		}
		for j := 0; j < i; j++ {
			if v.Rows[j].ValueCore.Name == row.ValueCore.Name {
				return 0, ErrCryptoMessage
			}
		}
		n += 4 + length
		if n > CryptoGeneratedMaterialLimit {
			return 0, ErrCryptoCapacity
		}
	}
	return n, nil
}

func EncodeCryptoGeneratedValueEntriesRequest(v CryptoGeneratedValueEntriesRequest) ([]byte, error) {
	n, err := cryptoGeneratedValueEntryPlansLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, cryptoGeneratedOperationContextLength+42+n)}
	w.id(v.OperationRef)
	w.context(v.Context)
	w.u8(uint8(CryptoGeneratedPrepareValueEntries))
	w.id(v.PhaseID)
	w.u32(v.BatchIndex)
	w.u8(v.Final)
	w.u32(uint32(n))
	w.u32(uint32(len(v.Rows)))
	for _, row := range v.Rows {
		length, _ := cryptoGeneratedValueEntryPlanLength(row)
		w.u32(uint32(length))
		writeCryptoGeneratedValueEntryPlan(&w, row)
	}
	return w.b, nil
}

func cryptoGeneratedValueEntryPlansSpanError(v CryptoGeneratedValueEntriesRequestView) error {
	if len(v.Rows) > CryptoGeneratedMaterialLimit {
		return ErrCryptoCapacity
	}
	if err := cryptoGeneratedStageError(v.OperationRef, v.Context); err != nil {
		return err
	}
	if v.PhaseID.IsZero() {
		return ErrCryptoMessage
	}
	r := cryptoReader{b: v.Rows}
	count := r.count(CryptoMaxValueEntries, 4)
	if err := cryptoGeneratedBatchError(v.BatchIndex, v.Final, count); err != nil {
		return err
	}
	var names [CryptoMaxValueEntries][]byte
	var previous uint16
	for i := 0; i < count && r.err == nil; i++ {
		row, err := inspectCryptoGeneratedValueEntryPlan(r.blob(CryptoGeneratedMaterialLimit))
		if r.err != nil {
			return r.failure()
		}
		if err != nil {
			return err
		}
		if i > 0 && previous >= row.Slot || row.ValueCore.DomainID != v.Context.DomainID || row.ValueCore.CompatibilityID != v.Context.CompatibilityID {
			return ErrCryptoMessage
		}
		for j := 0; j < i; j++ {
			if bytes.Equal(names[j], row.ValueCore.Name) {
				return ErrCryptoMessage
			}
		}
		names[i], previous = row.ValueCore.Name, row.Slot
	}
	return r.end()
}

func InspectCryptoGeneratedValueEntriesRequest(b []byte) (CryptoGeneratedValueEntriesRequestView, error) {
	if len(b) > cryptoGeneratedOperationContextLength+42+CryptoGeneratedMaterialLimit {
		return CryptoGeneratedValueEntriesRequestView{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: b}
	v := CryptoGeneratedValueEntriesRequestView{OperationRef: r.requiredID(), Context: readCryptoGeneratedContext(&r)}
	if CryptoGeneratedPrepareVariant(r.u8()) != CryptoGeneratedPrepareValueEntries {
		return CryptoGeneratedValueEntriesRequestView{}, ErrCryptoMessage
	}
	v.PhaseID, v.BatchIndex, v.Final, v.Rows = r.requiredID(), r.u32(), r.u8(), r.blob(CryptoGeneratedMaterialLimit)
	if err := r.end(); err != nil {
		return CryptoGeneratedValueEntriesRequestView{}, err
	}
	if err := cryptoGeneratedValueEntryPlansSpanError(v); err != nil {
		return CryptoGeneratedValueEntriesRequestView{}, err
	}
	return v, nil
}

func (v CryptoGeneratedValueEntriesRequestView) RowCount() int {
	r := cryptoReader{b: v.Rows}
	return r.count(CryptoMaxValueEntries, 4)
}

func (v CryptoGeneratedValueEntriesRequestView) Row(index int) (CryptoGeneratedValueEntryPlanView, error) {
	r := cryptoReader{b: v.Rows}
	count := r.count(CryptoMaxValueEntries, 4)
	if index < 0 || index >= count {
		return CryptoGeneratedValueEntryPlanView{}, ErrCryptoMessage
	}
	for i := 0; i < index; i++ {
		_ = r.blob(CryptoGeneratedMaterialLimit)
	}
	row := r.blob(CryptoGeneratedMaterialLimit)
	if r.err != nil {
		return CryptoGeneratedValueEntryPlanView{}, r.failure()
	}
	return inspectCryptoGeneratedValueEntryPlan(row)
}

func (v CryptoGeneratedValueEntriesRequestView) Own() (CryptoGeneratedValueEntriesRequest, error) {
	if err := cryptoGeneratedValueEntryPlansSpanError(v); err != nil {
		return CryptoGeneratedValueEntriesRequest{}, err
	}
	out := CryptoGeneratedValueEntriesRequest{OperationRef: v.OperationRef, Context: v.Context, PhaseID: v.PhaseID, BatchIndex: v.BatchIndex, Final: v.Final, Rows: make([]CryptoGeneratedValueEntryPlan, v.RowCount())}
	r := cryptoReader{b: v.Rows}
	_ = r.u32()
	for i := range out.Rows {
		row, err := inspectCryptoGeneratedValueEntryPlan(r.blob(CryptoGeneratedMaterialLimit))
		if err != nil {
			return CryptoGeneratedValueEntriesRequest{}, err
		}
		out.Rows[i], err = row.Own()
		if err != nil {
			return CryptoGeneratedValueEntriesRequest{}, err
		}
	}
	return out, nil
}

type CryptoGeneratedValueEntryResult struct {
	Slot                   uint16
	ResultID, ResultDigest ID
	ValueCore              ValueCore
	Entry                  ValueEntry
	Access                 AccessRecord
}

type CryptoGeneratedValueEntryResultView struct {
	Slot                   uint16
	ResultID, ResultDigest ID
	ValueCore              ValueCoreView
	Entry                  ValueEntryView
	Access                 AccessRecordView
}

type CryptoGeneratedValueEntriesResult struct {
	BatchIndex uint32
	Final      uint8
	Rows       []CryptoGeneratedValueEntryResult
}

type CryptoGeneratedValueEntriesResultView struct {
	BatchIndex uint32
	Final      uint8
	Rows       []byte
}

type cryptoGeneratedValueEntryResultTraversal struct {
	reader    cryptoReader
	remaining int
}

func (v CryptoGeneratedValueEntriesResultView) forwardRows() cryptoGeneratedValueEntryResultTraversal {
	r := cryptoReader{b: v.Rows}
	return cryptoGeneratedValueEntryResultTraversal{reader: r, remaining: r.count(CryptoMaxValueEntries, 4)}
}

func (t *cryptoGeneratedValueEntryResultTraversal) next() (CryptoGeneratedValueEntryResultView, bool, error) {
	if t.reader.err != nil {
		return CryptoGeneratedValueEntryResultView{}, false, t.reader.failure()
	}
	if t.remaining == 0 {
		return CryptoGeneratedValueEntryResultView{}, false, t.reader.end()
	}
	row, err := inspectCryptoGeneratedValueEntryResult(t.reader.blob(CryptoGeneratedMaterialLimit))
	if t.reader.err != nil {
		return CryptoGeneratedValueEntryResultView{}, false, t.reader.failure()
	}
	if err != nil {
		return CryptoGeneratedValueEntryResultView{}, false, err
	}
	t.remaining--
	return row, true, nil
}

func cryptoGeneratedValueEntryResultMatches(in CryptoGeneratedValueEntriesRequestView, out CryptoGeneratedValueEntriesResultView) error {
	if in.BatchIndex != out.BatchIndex || in.Final != out.Final {
		return ErrCryptoMessage
	}
	plans, results := in.forwardRows(), out.forwardRows()
	if plans.reader.err != nil {
		return plans.reader.failure()
	}
	if results.reader.err != nil {
		return results.reader.failure()
	}
	if plans.remaining != results.remaining {
		return ErrCryptoMessage
	}
	for {
		plan, planOK, err := plans.next()
		if err != nil {
			return err
		}
		result, resultOK, err := results.next()
		if err != nil {
			return err
		}
		if planOK != resultOK {
			return ErrCryptoMessage
		}
		if !planOK {
			return nil
		}
		if plan.Slot != result.Slot || plan.ValueCore.fields() != result.ValueCore.fields() || !bytes.Equal(plan.ValueCore.Name, result.ValueCore.Name) ||
			plan.Generated != result.Entry.Generated || !bytes.Equal(plan.RecipientIDs, result.Entry.RecipientIDs) || Hash(plan.Result) != result.ResultDigest || plan.Generated.CreateResultID != result.ResultID {
			return ErrCryptoMessage
		}
	}
}

func cryptoGeneratedSuppliedResultMatches(in CryptoGeneratedSuppliedRequestView, out CryptoGeneratedSuppliedResultView) error {
	if out.BatchIndex != in.BatchIndex || out.Final != in.Final {
		return ErrCryptoMessage
	}
	identity, err := InspectIdentityPlan(in.IdentityPlan)
	if err != nil {
		return err
	}
	if out.Descriptor.Count < uint32(in.SealedInputCount()) || out.Descriptor.Count > identity.Descriptor.Count {
		return ErrCryptoMessage
	}

	sources, identities, prepared := in.forwardSealedInputs(), identity.forwardRows(), out.forwardRows()
	source, sourceOK, err := sources.next()
	if err != nil {
		return err
	}
	identityRow, identityOK, err := identities.next()
	if err != nil {
		return err
	}
	for {
		row, ok, err := prepared.next()
		if err != nil {
			return err
		}
		if !ok {
			if sourceOK {
				return ErrCryptoMessage
			}
			return nil
		}

		if sourceOK && bytes.Compare(source.name, row.name) < 0 {
			return ErrCryptoMessage
		}
		sealed := sourceOK && bytes.Equal(source.name, row.name)
		if sealed {
			source, sourceOK, err = sources.next()
			if err != nil {
				return err
			}
		}
		for identityOK && bytes.Compare(identityRow.name, row.name) < 0 {
			identityRow, identityOK, err = identities.next()
			if err != nil {
				return err
			}
		}
		if !identityOK || !bytes.Equal(identityRow.name, row.name) || identityRow.row.Slot != row.current.slot {
			return ErrCryptoMessage
		}
		entry, err := InspectValueEntry(row.current.entryBytes)
		if err != nil || !bytes.Equal(entry.Name, row.name) || (entry.ValueSource != Supplied && entry.ValueSource != Generated) || entry.ConfidentialityClass != Secret ||
			entry.Incarnation != identityRow.row.Incarnation || entry.ValueState != identityRow.row.ValueState ||
			entry.OriginSnapshot != identityRow.row.OriginSnapshot || entry.OriginTransition != identityRow.row.OriginTransition || sealed && entry.ValueSource != Supplied {
			return ErrCryptoMessage
		}
		// Private final admission checks the declaration source and change mask;
		// Core and candidate binding require a carried generated value to remain exact.
	}
}

func cryptoGeneratedValueEntryResultBinding(slot uint16, resultID, resultDigest ID, core ValueCore, name []byte, entry ValueEntryView, access AccessRecordView) error {
	if slot >= CryptoMaxValueEntries {
		return ErrCryptoCapacity
	}
	if !publicIDsValid(resultID, resultDigest) || core.ValueSource != Generated || entry.ValueSource != Generated || entry.ConfidentialityClass != Secret ||
		resultID != entry.Generated.CreateResultID || !bytes.Equal(name, entry.Name) || core.EntryIncarnationID != entry.Incarnation ||
		core.ValueStateID != entry.ValueState || core.OriginSnapshotID != entry.OriginSnapshot || core.OriginTransitionID != entry.OriginTransition {
		return ErrCryptoMessage
	}
	p, err := InspectCanonicalPayload(entry.ValueBytes)
	if err != nil {
		return err
	}
	binding, err := GeneratedBindingDigest(entry.Generated)
	if err != nil {
		return err
	}
	context := valueMaterialContextDigest(core, name)
	if core.GeneratedBindingDigest != binding || core.Profile != p.Profile || core.CryptoSupportID != p.CryptoSupportID ||
		core.DataKeyID != p.DataKeyID || core.DataKeyEpoch != p.DataKeyEpoch || core.CommitmentKeyID != p.CommitmentKeyID ||
		core.CommitmentKeyEpoch != p.CommitmentKeyEpoch || core.InputEncoding != p.InputEncoding || core.ContentLength != p.ContentLength || core.RetainedLength != p.RetainedLength || access.MaterialKind != ValueMaterialKind ||
		access.MaterialID != core.ValueStateID || access.MaterialContextDigest != context || access.PackageCheck != p.PackageCheck {
		return ErrCryptoMessage
	}
	return nil
}

func cryptoGeneratedValueEntryResultLength(v CryptoGeneratedValueEntryResult) (int, error) {
	coreLength, err := ValueCoreLength(v.ValueCore)
	if err != nil {
		return 0, err
	}
	entryLength, err := ValueEntryLength(v.Entry)
	if err != nil {
		return 0, err
	}
	accessLength, err := AccessRecordLength(v.Access)
	if err != nil {
		return 0, err
	}
	ordinary := 0
	for _, wrap := range v.Access.Wraps {
		if wrap.SubjectKind != OrdinaryWrapSubject {
			continue
		}
		if ordinary >= len(v.Entry.Recipients) || wrap.SubjectID != v.Entry.Recipients[ordinary] {
			return 0, ErrCryptoMessage
		}
		ordinary++
	}
	if ordinary != len(v.Entry.Recipients) {
		return 0, ErrCryptoMessage
	}
	m := v.Entry
	mv := ValueEntryView{Name: []byte(m.Name), Incarnation: m.Incarnation, ValueState: m.ValueState, OriginSnapshot: m.OriginSnapshot, OriginTransition: m.OriginTransition, ValueSource: m.ValueSource, ConfidentialityClass: m.ConfidentialityClass, ValueBytes: m.ValueBytes, Generated: m.Generated}
	a := v.Access
	av := AccessRecordView{Schema: a.Schema, MaterialKind: a.MaterialKind, MaterialID: a.MaterialID, MaterialContextDigest: a.MaterialContextDigest, PackageCheck: a.PackageCheck}
	if err := cryptoGeneratedValueEntryResultBinding(v.Slot, v.ResultID, v.ResultDigest, v.ValueCore, []byte(v.ValueCore.Name), mv, av); err != nil {
		return 0, err
	}
	return 2 + 64 + 12 + coreLength + entryLength + accessLength, nil
}

func writeCryptoGeneratedValueEntryResult(w *cryptoWriter, v CryptoGeneratedValueEntryResult) {
	w.u16(v.Slot)
	w.id(v.ResultID)
	w.id(v.ResultDigest)
	writeValueCoreBlob(w, v.ValueCore)
	n, _ := ValueEntryLength(v.Entry)
	w.u32(uint32(n))
	writeValueEntry(w, v.Entry)
	writeAccessRecordBlob(w, v.Access)
}

func inspectCryptoGeneratedValueEntryResult(b []byte) (CryptoGeneratedValueEntryResultView, error) {
	r := cryptoReader{b: b}
	v := CryptoGeneratedValueEntryResultView{Slot: r.u16(), ResultID: r.requiredID(), ResultDigest: r.requiredID()}
	core, entryBytes, access := r.blob(valueCoreMaxLength), r.blob(CryptoMaxValueEntryLength), r.blob(accessRecordMaxLength)
	if err := r.end(); err != nil {
		return CryptoGeneratedValueEntryResultView{}, err
	}
	var err error
	v.ValueCore, err = InspectValueCore(core)
	if err != nil {
		return CryptoGeneratedValueEntryResultView{}, err
	}
	v.Entry, err = InspectValueEntry(entryBytes)
	if err != nil {
		return CryptoGeneratedValueEntryResultView{}, err
	}
	v.Access, err = InspectAccessRecord(access)
	if err != nil {
		return CryptoGeneratedValueEntryResultView{}, err
	}
	ordinary := 0
	for i := 0; i < v.Access.WrapCount(); i++ {
		wrap, ok := v.Access.Wrap(i)
		if !ok {
			return CryptoGeneratedValueEntryResultView{}, ErrCryptoMessage
		}
		if wrap.SubjectKind != OrdinaryWrapSubject {
			continue
		}
		recipient, ok := v.Entry.RecipientID(ordinary)
		if !ok || wrap.SubjectID != recipient {
			return CryptoGeneratedValueEntryResultView{}, ErrCryptoMessage
		}
		ordinary++
	}
	if ordinary != v.Entry.RecipientCount() {
		return CryptoGeneratedValueEntryResultView{}, ErrCryptoMessage
	}
	if err := cryptoGeneratedValueEntryResultBinding(v.Slot, v.ResultID, v.ResultDigest, v.ValueCore.fields(), v.ValueCore.Name, v.Entry, v.Access); err != nil {
		return CryptoGeneratedValueEntryResultView{}, err
	}
	return v, nil
}

func (v CryptoGeneratedValueEntryResultView) Own() (CryptoGeneratedValueEntryResult, error) {
	core, err := v.ValueCore.Own()
	if err != nil {
		return CryptoGeneratedValueEntryResult{}, err
	}
	entry, err := v.Entry.Own()
	if err != nil {
		return CryptoGeneratedValueEntryResult{}, err
	}
	access, err := v.Access.Own()
	if err != nil {
		return CryptoGeneratedValueEntryResult{}, err
	}
	out := CryptoGeneratedValueEntryResult{Slot: v.Slot, ResultID: v.ResultID, ResultDigest: v.ResultDigest, ValueCore: core, Entry: entry, Access: access}
	if _, err := cryptoGeneratedValueEntryResultLength(out); err != nil {
		return CryptoGeneratedValueEntryResult{}, err
	}
	return out, nil
}

func cryptoGeneratedValueEntryResultsLength(v CryptoGeneratedValueEntriesResult) (int, error) {
	if err := cryptoGeneratedBatchError(v.BatchIndex, v.Final, len(v.Rows)); err != nil {
		return 0, err
	}
	n := 4
	for i, row := range v.Rows {
		length, err := cryptoGeneratedValueEntryResultLength(row)
		if err != nil {
			return 0, err
		}
		if i > 0 && v.Rows[i-1].Slot >= row.Slot {
			return 0, ErrCryptoMessage
		}
		for j := 0; j < i; j++ {
			if v.Rows[j].ValueCore.Name == row.ValueCore.Name {
				return 0, ErrCryptoMessage
			}
		}
		n += 4 + length
		if n > CryptoGeneratedMaterialLimit {
			return 0, ErrCryptoCapacity
		}
	}
	return n, nil
}

func EncodeCryptoGeneratedValueEntriesResult(v CryptoGeneratedValueEntriesResult) ([]byte, error) {
	n, err := cryptoGeneratedValueEntryResultsLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, 10+n)}
	w.u8(uint8(CryptoGeneratedPrepareValueEntries))
	w.u32(v.BatchIndex)
	w.u8(v.Final)
	w.u32(uint32(n))
	w.u32(uint32(len(v.Rows)))
	for _, row := range v.Rows {
		length, _ := cryptoGeneratedValueEntryResultLength(row)
		w.u32(uint32(length))
		writeCryptoGeneratedValueEntryResult(&w, row)
	}
	return w.b, nil
}

func cryptoGeneratedValueEntryResultsSpanError(v CryptoGeneratedValueEntriesResultView) error {
	if len(v.Rows) > CryptoGeneratedMaterialLimit {
		return ErrCryptoCapacity
	}
	r := cryptoReader{b: v.Rows}
	count := r.count(CryptoMaxValueEntries, 4)
	if err := cryptoGeneratedBatchError(v.BatchIndex, v.Final, count); err != nil {
		return err
	}
	var names [CryptoMaxValueEntries][]byte
	var previous uint16
	for i := 0; i < count && r.err == nil; i++ {
		row, err := inspectCryptoGeneratedValueEntryResult(r.blob(CryptoGeneratedMaterialLimit))
		if r.err != nil {
			return r.failure()
		}
		if err != nil {
			return err
		}
		if i > 0 && previous >= row.Slot {
			return ErrCryptoMessage
		}
		for j := 0; j < i; j++ {
			if bytes.Equal(names[j], row.ValueCore.Name) {
				return ErrCryptoMessage
			}
		}
		names[i], previous = row.ValueCore.Name, row.Slot
	}
	return r.end()
}

func InspectCryptoGeneratedValueEntriesResult(b []byte) (CryptoGeneratedValueEntriesResultView, error) {
	if len(b) > 10+CryptoGeneratedMaterialLimit {
		return CryptoGeneratedValueEntriesResultView{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: b}
	if CryptoGeneratedPrepareVariant(r.u8()) != CryptoGeneratedPrepareValueEntries {
		return CryptoGeneratedValueEntriesResultView{}, ErrCryptoMessage
	}
	v := CryptoGeneratedValueEntriesResultView{BatchIndex: r.u32(), Final: r.u8(), Rows: r.blob(CryptoGeneratedMaterialLimit)}
	if err := r.end(); err != nil {
		return CryptoGeneratedValueEntriesResultView{}, err
	}
	if err := cryptoGeneratedValueEntryResultsSpanError(v); err != nil {
		return CryptoGeneratedValueEntriesResultView{}, err
	}
	return v, nil
}

func (v CryptoGeneratedValueEntriesResultView) RowCount() int {
	r := cryptoReader{b: v.Rows}
	return r.count(CryptoMaxValueEntries, 4)
}

func (v CryptoGeneratedValueEntriesResultView) Row(index int) (CryptoGeneratedValueEntryResultView, error) {
	r := cryptoReader{b: v.Rows}
	count := r.count(CryptoMaxValueEntries, 4)
	if index < 0 || index >= count {
		return CryptoGeneratedValueEntryResultView{}, ErrCryptoMessage
	}
	for i := 0; i < index; i++ {
		_ = r.blob(CryptoGeneratedMaterialLimit)
	}
	row := r.blob(CryptoGeneratedMaterialLimit)
	if r.err != nil {
		return CryptoGeneratedValueEntryResultView{}, r.failure()
	}
	return inspectCryptoGeneratedValueEntryResult(row)
}

func (v CryptoGeneratedValueEntriesResultView) Own() (CryptoGeneratedValueEntriesResult, error) {
	if err := cryptoGeneratedValueEntryResultsSpanError(v); err != nil {
		return CryptoGeneratedValueEntriesResult{}, err
	}
	out := CryptoGeneratedValueEntriesResult{BatchIndex: v.BatchIndex, Final: v.Final, Rows: make([]CryptoGeneratedValueEntryResult, v.RowCount())}
	r := cryptoReader{b: v.Rows}
	_ = r.u32()
	for i := range out.Rows {
		row, err := inspectCryptoGeneratedValueEntryResult(r.blob(CryptoGeneratedMaterialLimit))
		if err != nil {
			return CryptoGeneratedValueEntriesResult{}, err
		}
		out.Rows[i], err = row.Own()
		if err != nil {
			return CryptoGeneratedValueEntriesResult{}, err
		}
	}
	return out, nil
}

type CryptoGeneratedCompareResult struct{ OperationRef ID }

func EncodeCryptoGeneratedCompareResult(v CryptoGeneratedCompareResult) ([]byte, error) {
	if v.OperationRef.IsZero() {
		return nil, ErrCryptoMessage
	}
	return append([]byte(nil), v.OperationRef[:]...), nil
}

func InspectCryptoGeneratedCompareResult(b []byte) (CryptoGeneratedCompareResult, error) {
	if len(b) != 32 || ID(b).IsZero() {
		return CryptoGeneratedCompareResult{}, ErrCryptoMessage
	}
	return CryptoGeneratedCompareResult{OperationRef: ID(b)}, nil
}

type CryptoGeneratedPartResult struct{}

func EncodeCryptoGeneratedPartResult(CryptoGeneratedPartResult) ([]byte, error) {
	return []byte{1}, nil
}

func InspectCryptoGeneratedPartResult(b []byte) (CryptoGeneratedPartResult, error) {
	if len(b) != 1 || b[0] != 1 {
		return CryptoGeneratedPartResult{}, ErrCryptoMessage
	}
	return CryptoGeneratedPartResult{}, nil
}

type CryptoGeneratedSourceProtection struct {
	SourceID, OriginalSourceCoreDigest, OriginalEnvelopeDigest ID
	Transfer                                                   TransferEnvelope
}

type CryptoGeneratedSourceProtectionView struct {
	SourceID, OriginalSourceCoreDigest, OriginalEnvelopeDigest ID
	Transfer                                                   TransferEnvelopeView
}

type CryptoGeneratedFinishPlanResult struct {
	Material          OperationMaterialRecord
	SeedAccess        []byte
	SourceProtections []CryptoGeneratedSourceProtection
}

type CryptoGeneratedFinishPlanResultView struct {
	Material          OperationMaterialRecord
	SeedAccess        []byte
	SourceProtections []byte
}

func cryptoGeneratedSourceProtectionLength(v CryptoGeneratedSourceProtection, material OperationMaterialRecord) (int, error) {
	if !publicIDsValid(v.SourceID, v.OriginalSourceCoreDigest, v.OriginalEnvelopeDigest) {
		return 0, ErrCryptoMessage
	}
	n, err := TransferEnvelopeLength(v.Transfer)
	if err != nil {
		return 0, err
	}
	c, m := v.Transfer.Core, material.Core
	if c.UseKind != sourceTransferUse || c.SourceID != v.SourceID || c.SealedInputCoreDigest != v.OriginalSourceCoreDigest ||
		c.DomainID != m.DomainID || c.OperationID != m.OperationID || c.OperationMaterialID != m.OperationMaterialID || c.UsePlanDigest != m.UsePlanDigest ||
		c.CompatibilityID != m.CompatibilityID || c.CryptoSupportID != m.CryptoSupportID {
		return 0, ErrCryptoMessage
	}
	return 96 + 4 + n, nil
}

func writeCryptoGeneratedSourceProtection(w *cryptoWriter, v CryptoGeneratedSourceProtection) {
	w.id(v.SourceID)
	w.id(v.OriginalSourceCoreDigest)
	w.id(v.OriginalEnvelopeDigest)
	n, _ := TransferEnvelopeLength(v.Transfer)
	w.u32(uint32(n))
	writeTransferEnvelope(w, v.Transfer)
}

func inspectCryptoGeneratedSourceProtection(b []byte, material OperationMaterialRecord) (CryptoGeneratedSourceProtectionView, error) {
	r := cryptoReader{b: b}
	v := CryptoGeneratedSourceProtectionView{SourceID: r.requiredID(), OriginalSourceCoreDigest: r.requiredID(), OriginalEnvelopeDigest: r.requiredID()}
	transfer := r.blob(transferEnvelopeMaxLength)
	if err := r.end(); err != nil {
		return CryptoGeneratedSourceProtectionView{}, err
	}
	var err error
	v.Transfer, err = InspectTransferEnvelope(transfer)
	if err != nil {
		return CryptoGeneratedSourceProtectionView{}, err
	}
	if _, err := cryptoGeneratedSourceProtectionLength(CryptoGeneratedSourceProtection{SourceID: v.SourceID, OriginalSourceCoreDigest: v.OriginalSourceCoreDigest, OriginalEnvelopeDigest: v.OriginalEnvelopeDigest, Transfer: TransferEnvelope(v.Transfer)}, material); err != nil {
		return CryptoGeneratedSourceProtectionView{}, err
	}
	return v, nil
}

func cryptoGeneratedFinishPlanResultLength(v CryptoGeneratedFinishPlanResult) (int, error) {
	if err := cryptoGeneratedSeedAccessError(v.Material, v.SeedAccess); err != nil {
		return 0, err
	}
	n, err := generatedSourceProtectionsLength(v.Material, v.SourceProtections)
	if err != nil {
		return 0, err
	}
	return 1 + 4 + operationMaterialRecordLength + 4 + len(v.SeedAccess) + 4 + n, nil
}

func EncodeCryptoGeneratedFinishPlanResult(v CryptoGeneratedFinishPlanResult) ([]byte, error) {
	n, err := cryptoGeneratedFinishPlanResultLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	w.u8(uint8(CryptoGeneratedPrepareFinishPlan))
	w.u32(operationMaterialRecordLength)
	writeOperationMaterialRecord(&w, v.Material)
	w.blob(v.SeedAccess)
	w.u32(uint32(n - 1 - 4 - operationMaterialRecordLength - 4 - len(v.SeedAccess) - 4))
	writeGeneratedSourceProtections(&w, v.Material, v.SourceProtections)
	return w.b, nil
}

func cryptoGeneratedSourceProtectionsSpanError(v CryptoGeneratedFinishPlanResultView) error {
	if len(v.SourceProtections) > 1<<20 {
		return ErrCryptoCapacity
	}
	if err := cryptoGeneratedSeedAccessError(v.Material, v.SeedAccess); err != nil {
		return err
	}
	_, err := InspectGeneratedSourceProtections(v.Material, v.SourceProtections)
	return err
}

func InspectCryptoGeneratedFinishPlanResult(b []byte) (CryptoGeneratedFinishPlanResultView, error) {
	if len(b) > 1+4+operationMaterialRecordLength+4+AccessRecordFixedLength+seedAccessWrapLimit*WrapRowWireLength+4+1<<20 {
		return CryptoGeneratedFinishPlanResultView{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: b}
	if CryptoGeneratedPrepareVariant(r.u8()) != CryptoGeneratedPrepareFinishPlan {
		return CryptoGeneratedFinishPlanResultView{}, ErrCryptoMessage
	}
	material := r.blob(operationMaterialRecordLength)
	v := CryptoGeneratedFinishPlanResultView{SeedAccess: r.blob(AccessRecordFixedLength + seedAccessWrapLimit*WrapRowWireLength), SourceProtections: r.blob(1 << 20)}
	if err := r.end(); err != nil {
		return CryptoGeneratedFinishPlanResultView{}, err
	}
	var err error
	v.Material, err = InspectOperationMaterialRecord(material)
	if err != nil {
		return CryptoGeneratedFinishPlanResultView{}, err
	}
	if err := cryptoGeneratedSourceProtectionsSpanError(v); err != nil {
		return CryptoGeneratedFinishPlanResultView{}, err
	}
	return v, nil
}

func (v CryptoGeneratedFinishPlanResultView) SourceCount() int {
	return (GeneratedSourceProtectionsView{Material: v.Material, Rows: v.SourceProtections}).Count()
}

func (v CryptoGeneratedFinishPlanResultView) Source(index int) (CryptoGeneratedSourceProtectionView, error) {
	return (GeneratedSourceProtectionsView{Material: v.Material, Rows: v.SourceProtections}).Row(index)
}

func (v CryptoGeneratedFinishPlanResultView) Own() (CryptoGeneratedFinishPlanResult, error) {
	if err := cryptoGeneratedSourceProtectionsSpanError(v); err != nil {
		return CryptoGeneratedFinishPlanResult{}, err
	}
	out := CryptoGeneratedFinishPlanResult{Material: v.Material, SeedAccess: ownedBytes(v.SeedAccess), SourceProtections: make([]CryptoGeneratedSourceProtection, v.SourceCount())}
	r := cryptoReader{b: v.SourceProtections}
	_ = r.u32()
	for i := range out.SourceProtections {
		row, err := inspectCryptoGeneratedSourceProtection(r.blob(100+transferEnvelopeMaxLength), v.Material)
		if err != nil {
			return CryptoGeneratedFinishPlanResult{}, err
		}
		transfer, err := row.Transfer.Own()
		if err != nil {
			return CryptoGeneratedFinishPlanResult{}, err
		}
		out.SourceProtections[i] = CryptoGeneratedSourceProtection{SourceID: row.SourceID, OriginalSourceCoreDigest: row.OriginalSourceCoreDigest, OriginalEnvelopeDigest: row.OriginalEnvelopeDigest, Transfer: transfer}
	}
	return out, nil
}

// A ProducerLocatorID locates private preparation. It is not an entry right.
type CryptoGeneratedProducerResult struct{ ProducerLocatorID ID }

func EncodeCryptoGeneratedProducerResult(v CryptoGeneratedProducerResult) ([]byte, error) {
	if v.ProducerLocatorID.IsZero() {
		return nil, ErrCryptoMessage
	}
	return append([]byte{byte(CryptoGeneratedPrepareProducer)}, v.ProducerLocatorID[:]...), nil
}

func InspectCryptoGeneratedProducerResult(b []byte) (CryptoGeneratedProducerResult, error) {
	if len(b) != 33 || CryptoGeneratedPrepareVariant(b[0]) != CryptoGeneratedPrepareProducer || ID(b[1:]).IsZero() {
		return CryptoGeneratedProducerResult{}, ErrCryptoMessage
	}
	return CryptoGeneratedProducerResult{ProducerLocatorID: ID(b[1:])}, nil
}

type CryptoGeneratedAdoptResult struct{ Result []byte }
type CryptoGeneratedAdoptResultView CryptoGeneratedAdoptResult

func EncodeCryptoGeneratedAdoptResult(v CryptoGeneratedAdoptResult) ([]byte, error) {
	if _, err := InspectGeneratedResultRecord(v.Result); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, 5+len(v.Result))}
	w.u8(uint8(CryptoGeneratedPrepareAdopt))
	w.blob(v.Result)
	return w.b, nil
}

func InspectCryptoGeneratedAdoptResult(b []byte) (CryptoGeneratedAdoptResultView, error) {
	if len(b) > 5+GeneratedResultRecordMaxLength {
		return CryptoGeneratedAdoptResultView{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: b}
	if CryptoGeneratedPrepareVariant(r.u8()) != CryptoGeneratedPrepareAdopt {
		return CryptoGeneratedAdoptResultView{}, ErrCryptoMessage
	}
	v := CryptoGeneratedAdoptResultView{Result: r.blob(GeneratedResultRecordMaxLength)}
	if err := r.end(); err != nil {
		return CryptoGeneratedAdoptResultView{}, err
	}
	if _, err := InspectGeneratedResultRecord(v.Result); err != nil {
		return CryptoGeneratedAdoptResultView{}, err
	}
	return v, nil
}

func (v CryptoGeneratedAdoptResultView) Own() (CryptoGeneratedAdoptResult, error) {
	if _, err := InspectGeneratedResultRecord(v.Result); err != nil {
		return CryptoGeneratedAdoptResult{}, err
	}
	return CryptoGeneratedAdoptResult{Result: ownedBytes(v.Result)}, nil
}

// ValidateCryptoGeneratedRequest checks the closed class-four union. Public
// message validity does not construct private admission.
func ValidateCryptoGeneratedRequest(q CryptoRequest) error {
	if len(q.Body) > CryptoRequestLimit-cryptoRequestHeader {
		return ErrCryptoCapacity
	}
	if q.Schema != CryptoSchema || !publicIDsValid(q.RequestID, q.CustodyInstanceID) {
		return ErrCryptoMessage
	}
	return cryptoGeneratedRequestBody(q.Kind, q.Body)
}

// InspectCryptoGeneratedPrepareRequest validates the public request envelope,
// common framing, and complete variant-specific body before returning a typed
// classification.
func InspectCryptoGeneratedPrepareRequest(q CryptoRequest) (CryptoGeneratedPrepareRequest, error) {
	if q.Kind != CryptoPrepare || q.Schema != CryptoSchema || !publicIDsValid(q.RequestID, q.CustodyInstanceID) {
		return CryptoGeneratedPrepareRequest{}, ErrCryptoMessage
	}
	return inspectCryptoGeneratedPrepareBody(q.Body)
}

func inspectCryptoGeneratedPrepareBody(body []byte) (CryptoGeneratedPrepareRequest, error) {
	if len(body) > CryptoRequestLimit-cryptoRequestHeader {
		return CryptoGeneratedPrepareRequest{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: body}
	r.requiredID()
	readCryptoGeneratedContext(&r)
	variant := CryptoGeneratedPrepareVariant(r.u8())
	if r.err != nil {
		return CryptoGeneratedPrepareRequest{}, r.failure()
	}
	out := CryptoGeneratedPrepareRequest{Variant: variant}
	var err error
	switch variant {
	case CryptoGeneratedPreparePlanPart:
		out.PlanPart, err = InspectCryptoGeneratedPlanPartRequest(body)
	case CryptoGeneratedPrepareFinishPlan:
		out.FinishPlan, err = InspectCryptoGeneratedFinishPlanRequest(body)
	case CryptoGeneratedPrepareProducer:
		out.Producer, err = InspectCryptoGeneratedProducerRequest(body)
	case CryptoGeneratedPrepareAdopt:
		out.Adopt, err = InspectCryptoGeneratedAdoptRequest(body)
	case CryptoGeneratedPrepareValueEntries:
		out.ValueEntries, err = InspectCryptoGeneratedValueEntriesRequest(body)
	case CryptoGeneratedPrepareSupplied:
		out.Supplied, err = InspectCryptoGeneratedSuppliedRequest(body)
	case CryptoGeneratedPrepareVerifyOriginal:
		out.VerifyOriginal, err = InspectCryptoGeneratedVerifyRequest(body)
	case CryptoGeneratedPrepareLocalFailure:
		out.LocalFailure, err = InspectCryptoGeneratedLocalFailureRequest(body)
	default:
		return CryptoGeneratedPrepareRequest{}, ErrCryptoMessage
	}
	if err != nil {
		return CryptoGeneratedPrepareRequest{}, err
	}
	return out, nil
}

func cryptoGeneratedRequestBody(kind CryptoKind, body []byte) error {
	switch kind {
	case CryptoCompare:
		_, err := InspectCryptoGeneratedCompareRequest(body)
		return err
	case CryptoPrepare:
		_, err := inspectCryptoGeneratedPrepareBody(body)
		return err
	case CryptoFreeze:
		_, err := InspectCryptoGeneratedFreezeRequest(body)
		return err
	case CryptoClaim:
		_, err := InspectCryptoGeneratedClaimRequest(body)
		return err
	case CryptoDiscard:
		_, err := InspectCryptoGeneratedDiscardRequest(body)
		return err
	}
	return ErrCryptoMessage
}

func cryptoGeneratedSuccessBody(q CryptoRequest, body []byte) error {
	switch q.Kind {
	case CryptoCompare:
		_, err := InspectCryptoGeneratedCompareResult(body)
		return err
	case CryptoPrepare:
		in, err := inspectCryptoGeneratedPrepareBody(q.Body)
		if err != nil {
			return err
		}
		switch in.Variant {
		case CryptoGeneratedPrepareLocalFailure:
			if len(body) != 1 || body[0] != byte(CryptoGeneratedPrepareLocalFailure) {
				return ErrCryptoMessage
			}
			return nil
		case CryptoGeneratedPrepareVerifyOriginal:
			out, err := InspectGeneratorResultReference(body)
			if err != nil || out.ResultBodyDigest != in.VerifyOriginal.ExpectedResult.Digest || uint64(out.ResultLength) != in.VerifyOriginal.ExpectedResult.Length {
				return ErrCryptoMessage
			}
			result, err := InspectGeneratedResultRecord(in.VerifyOriginal.Result)
			if err != nil || out.ResultID != result.Core.ResultID {
				return ErrCryptoMessage
			}
			return nil
		case CryptoGeneratedPreparePlanPart:
			_, err := InspectCryptoGeneratedPartResult(body)
			return err
		case CryptoGeneratedPrepareFinishPlan:
			out, err := InspectCryptoGeneratedFinishPlanResult(body)
			if err != nil {
				return err
			}
			if out.Material.Core.DomainID != in.FinishPlan.Context.DomainID || out.Material.Core.CompatibilityID != in.FinishPlan.Context.CompatibilityID || uint32(out.SourceCount()) != in.FinishPlan.SourceUses.Count {
				return ErrCryptoMessage
			}
			return nil
		case CryptoGeneratedPrepareProducer:
			_, err := InspectCryptoGeneratedProducerResult(body)
			return err
		case CryptoGeneratedPrepareAdopt:
			out, err := InspectCryptoGeneratedAdoptResult(body)
			if err != nil {
				return err
			}
			if !bytes.Equal(in.Adopt.Result, out.Result) {
				return ErrCryptoMessage
			}
			return nil
		case CryptoGeneratedPrepareValueEntries:
			out, err := InspectCryptoGeneratedValueEntriesResult(body)
			if err != nil {
				return err
			}
			return cryptoGeneratedValueEntryResultMatches(in.ValueEntries, out)
		case CryptoGeneratedPrepareSupplied:
			out, err := InspectCryptoGeneratedSuppliedResult(body)
			if err != nil {
				return err
			}
			return cryptoGeneratedSuppliedResultMatches(in.Supplied, out)
		}
	case CryptoFreeze:
		_, err := DecodeCryptoFreezeResult(body)
		return err
	case CryptoClaim, CryptoDiscard:
		if len(body) == 0 {
			return nil
		}
	}
	return ErrCryptoMessage
}

func cryptoGeneratedResponseFieldsError(q CryptoRequest, schema uint16, kind CryptoKind, request, instance ID, code CryptoResultCode, body []byte) error {
	if err := ValidateCryptoGeneratedRequest(q); err != nil {
		return err
	}
	if err := cryptoResponseHeaderError(schema, kind, request, instance, code); err != nil {
		return err
	}
	if q.Schema != schema || q.Kind != kind || q.RequestID != request || q.CustodyInstanceID != instance {
		return ErrCryptoMessage
	}
	if code != CryptoSuccess {
		if len(body) != 0 {
			return ErrCryptoMessage
		}
		return nil
	}
	return cryptoGeneratedSuccessBody(q, body)
}

func ValidateCryptoGeneratedResponse(q CryptoRequest, p CryptoResponse) error {
	if len(p.Body) > CryptoGeneratedResponseLimit-cryptoResponseHeader {
		return ErrCryptoCapacity
	}
	n, err := KeyUseRowsLength(p.KeyUseRows)
	if err != nil {
		return err
	}
	if cryptoResponseHeader+n-2+len(p.Body) > CryptoGeneratedResponseLimit {
		return ErrCryptoCapacity
	}
	return cryptoGeneratedResponseFieldsError(q, p.Schema, p.Kind, p.RequestID, p.CustodyInstanceID, p.ResultCode, p.Body)
}

type CryptoGeneratedResponseView CryptoResponseView

func EncodeCryptoGeneratedResponse(q CryptoRequest, p CryptoResponse) ([]byte, error) {
	if err := ValidateCryptoGeneratedResponse(q, p); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, cryptoResponseHeader+len(p.KeyUseRows)*KeyUseRowLength+len(p.Body))}
	writeCryptoResponse(&w, p)
	return w.b, nil
}

func InspectCryptoGeneratedResponse(q CryptoRequest, b []byte) (CryptoGeneratedResponseView, error) {
	if len(b) > CryptoGeneratedResponseLimit {
		return CryptoGeneratedResponseView{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: b}
	v := CryptoGeneratedResponseView{Schema: r.u16(), Kind: CryptoKind(r.u8()), RequestID: r.requiredID(), CustodyInstanceID: r.requiredID(), ResultCode: CryptoResultCode(r.u16())}
	v.KeyUseRows = readKeyUseRows(&r)
	v.Body = r.blob(CryptoGeneratedResponseLimit - cryptoResponseHeader - len(v.KeyUseRows.Rows))
	if err := r.end(); err != nil {
		return CryptoGeneratedResponseView{}, err
	}
	if err := cryptoGeneratedResponseFieldsError(q, v.Schema, v.Kind, v.RequestID, v.CustodyInstanceID, v.ResultCode, v.Body); err != nil {
		return CryptoGeneratedResponseView{}, err
	}
	return v, nil
}

func (v CryptoGeneratedResponseView) Own(q CryptoRequest) (CryptoResponse, error) {
	if len(v.Body) > CryptoGeneratedResponseLimit-cryptoResponseHeader || len(v.KeyUseRows.Rows) > KeyUseRowsMaxLength-2 || len(v.Body)+len(v.KeyUseRows.Rows) > CryptoGeneratedResponseLimit-cryptoResponseHeader {
		return CryptoResponse{}, ErrCryptoCapacity
	}
	if err := keyUseSpanError(v.KeyUseRows.Rows); err != nil {
		return CryptoResponse{}, err
	}
	if err := cryptoGeneratedResponseFieldsError(q, v.Schema, v.Kind, v.RequestID, v.CustodyInstanceID, v.ResultCode, v.Body); err != nil {
		return CryptoResponse{}, err
	}
	rows, err := v.KeyUseRows.Own()
	if err != nil {
		return CryptoResponse{}, err
	}
	return CryptoResponse{Schema: v.Schema, Kind: v.Kind, RequestID: v.RequestID, CustodyInstanceID: v.CustodyInstanceID, ResultCode: v.ResultCode, KeyUseRows: rows, Body: ownedBytes(v.Body)}, nil
}

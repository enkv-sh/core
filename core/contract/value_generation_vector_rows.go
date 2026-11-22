package contract

import (
	"unicode/utf8"

	"enkv.sh/sdk/artifact/credentialroute"
)

const (
	GeneratorConsumerAcceptedSource          = 1
	GeneratorConsumerRetainedCanonicalValue  = 2
	GeneratorConsumerOriginalResult          = 3
	GeneratorConsumerPrepareAcceptedSource   = 1
	GeneratorConsumerUseRetainedCanonical    = 2
	GeneratorConsumerDeriveSelectedResult    = 3
	GeneratorConsumerAdoptLateOriginalResult = 4
	GeneratorAcknowledgedRequiredSteps       = 1
	GeneratorConfirmedRequiredSteps          = 2
	GeneratorProgressAcknowledged            = 1
	GeneratorProgressConfirmed               = 3
)

const (
	GeneratorTargetMaxLength         = 559
	GeneratorProgressLength          = 113
	GeneratorHistoryLength           = 164
	GeneratorSupportBindingMaxLength = 1684
	GeneratorProofMaxLength          = 1255
	GeneratorConsumerLength          = 132
	GeneratorSliceLocationLength     = 111
	GeneratorLogicalSliceLength      = 71
	GeneratorFactsRowMaxLength       = 38 + GeneratorSafeFactsEnvelopeLength
)

const (
	GeneratorContentIntent              uint8 = 1
	GeneratorContentDeclaration         uint8 = 2
	GeneratorContentGraph               uint8 = 3
	GeneratorContentSource              uint8 = 4
	GeneratorContentConfiguration       uint8 = 5
	GeneratorContentFinalPreparation    uint8 = 6
	GeneratorContentRecipientRegistry   uint8 = 7
	GeneratorContentOutputConfiguration uint8 = 8
)

type GeneratorTarget struct {
	Schema                                                                                                                     uint16
	Name                                                                                                                       string
	IncarnationID                                                                                                              ID
	Epoch                                                                                                                      uint64
	ResourceID, ConfigContractID, ResourceContractID, ResourceDigest, OriginalOperationID, OriginalAttemptID, ResultContractID ID
	LifecycleMode                                                                                                              GeneratorLifecycleMode
	CompletionClass                                                                                                            uint8
}

func (v GeneratorTarget) valid() bool {
	return v.Schema == GeneratorTargetSchema && len(v.Name) <= CryptoMaxName && utf8.ValidString(v.Name) && publicIDsValid(v.IncarnationID, v.ResourceID, v.ConfigContractID, v.OriginalOperationID, v.OriginalAttemptID, v.ResultContractID) && v.LifecycleMode.resourceValid(v.ResourceContractID) && (v.LifecycleMode == GeneratorLifecycleNone && v.ResourceDigest.IsZero() && v.CompletionClass == 0 || v.LifecycleMode == GeneratorLifecycleManaged && !v.ResourceDigest.IsZero() && generatedCompletionValid(v.CompletionClass))
}
func EncodeGeneratorTarget(v GeneratorTarget) ([]byte, error) {
	if len(v.Name) > CryptoMaxName {
		return nil, ErrRecordCapacity
	}
	if !v.valid() {
		return nil, ErrRecord
	}
	var w cryptoWriter
	w.u16(v.Schema)
	w.blob([]byte(v.Name))
	w.id(v.IncarnationID)
	w.u64(v.Epoch)
	for _, id := range [...]ID{v.ResourceID, v.ConfigContractID, v.ResourceContractID, v.ResourceDigest, v.OriginalOperationID, v.OriginalAttemptID, v.ResultContractID} {
		w.id(id)
	}
	w.u8(uint8(v.LifecycleMode))
	w.u8(v.CompletionClass)
	return w.b, nil
}
func InspectGeneratorTarget(body []byte) (GeneratorTarget, error) {
	if len(body) > GeneratorTargetMaxLength {
		return GeneratorTarget{}, ErrRecordCapacity
	}
	r := newRecordReader(body)
	v := GeneratorTarget{Schema: r.u16(), Name: string(r.name()), IncarnationID: r.requiredID(), Epoch: r.u64(), ResourceID: r.requiredID(), ConfigContractID: r.requiredID(), ResourceContractID: r.id(), ResourceDigest: r.id(), OriginalOperationID: r.requiredID(), OriginalAttemptID: r.requiredID(), ResultContractID: r.requiredID(), LifecycleMode: GeneratorLifecycleMode(r.u8()), CompletionClass: r.u8()}
	if err := r.end(); err != nil {
		return GeneratorTarget{}, err
	}
	if !v.valid() {
		return GeneratorTarget{}, ErrRecord
	}
	return v, nil
}

type GeneratorProgress struct {
	Schema                                         uint16
	AttemptID, ResultID                            ID
	Evidence                                       GeneratorDescriptor
	RequiredSteps, CompletedSteps, CompletionClass uint8
}

func (v GeneratorProgress) valid() bool {
	if v.Schema != GeneratorRecordSchema || !publicIDsValid(v.AttemptID, v.ResultID) {
		return false
	}
	if v.CompletionClass == GeneratedCompletionConfirmed {
		return v.RequiredSteps == GeneratorConfirmedRequiredSteps && (v.CompletedSteps == GeneratorProgressAcknowledged || v.CompletedSteps == GeneratorProgressConfirmed) && v.Evidence.Valid() &&
			v.Evidence.Count == 1 && v.Evidence.Length >= GeneratedResultCoreLength && v.Evidence.Length <= uint64(GeneratedResultRecordMaxLength)
	}
	return v.CompletionClass == GeneratedCompletionAcknowledged && v.RequiredSteps == GeneratorAcknowledgedRequiredSteps && v.CompletedSteps <= GeneratorProgressAcknowledged &&
		GeneratorVectorShapeValid(GeneratorVectorProofs, v.Evidence)
}

func EncodeGeneratorProgress(v GeneratorProgress) ([]byte, error) {
	if !v.valid() {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, GeneratorProgressLength)}
	w.u16(v.Schema)
	w.id(v.AttemptID)
	w.id(v.ResultID)
	writeGeneratorDescriptor(&w, v.Evidence)
	w.u8(v.RequiredSteps)
	w.u8(v.CompletedSteps)
	w.u8(v.CompletionClass)
	return w.b, nil
}

func InspectGeneratorProgress(b []byte) (GeneratorProgress, error) {
	if len(b) > GeneratorProgressLength {
		return GeneratorProgress{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GeneratorProgress{Schema: r.u16(), AttemptID: r.requiredID(), ResultID: r.requiredID(), Evidence: readGeneratorDescriptor(&r),
		RequiredSteps: r.u8(), CompletedSteps: r.u8(), CompletionClass: r.u8()}
	if err := r.end(); err != nil {
		return GeneratorProgress{}, err
	}
	if !v.valid() {
		return GeneratorProgress{}, ErrRecord
	}
	return v, nil
}

type GeneratorHistory struct {
	Schema                                                               uint16
	PredecessorAttemptID, NextAttemptID, ResultID, OwnerID, ResultDigest ID
	Outcome, Edge                                                        uint8
}

func (v GeneratorHistory) valid() bool {
	return v.Schema == GeneratorRecordSchema && publicIDsValid(v.PredecessorAttemptID, v.OwnerID) &&
		v.ResultID.IsZero() == v.ResultDigest.IsZero() && v.Outcome >= GeneratedEffectTransmitted && v.Outcome <= GeneratedEffectClosedWithResidue &&
		v.Edge <= 4 && (v.Edge == 0) == v.NextAttemptID.IsZero() && v.NextAttemptID != v.PredecessorAttemptID
}

func EncodeGeneratorHistory(v GeneratorHistory) ([]byte, error) {
	if !v.valid() {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, GeneratorHistoryLength)}
	w.u16(v.Schema)
	for _, id := range []ID{v.PredecessorAttemptID, v.NextAttemptID, v.ResultID, v.OwnerID, v.ResultDigest} {
		w.id(id)
	}
	w.u8(v.Outcome)
	w.u8(v.Edge)
	return w.b, nil
}

func InspectGeneratorHistory(b []byte) (GeneratorHistory, error) {
	if len(b) > GeneratorHistoryLength {
		return GeneratorHistory{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GeneratorHistory{Schema: r.u16(), PredecessorAttemptID: r.requiredID(), NextAttemptID: r.id(), ResultID: r.id(), OwnerID: r.requiredID(), ResultDigest: r.id(), Outcome: r.u8(), Edge: r.u8()}
	if err := r.end(); err != nil {
		return GeneratorHistory{}, err
	}
	if !v.valid() {
		return GeneratorHistory{}, ErrRecord
	}
	return v, nil
}

// GeneratorSupportBinding borrows Binding from the inspected body. It contains
// a public signing binding only for role 6; no private credential is permitted.
type GeneratorSupportBinding struct {
	Schema                                            uint16
	Role                                              uint8
	ContractID, ImplementationID, PublicBindingDigest ID
	Binding                                           []byte
}

func (v GeneratorSupportBinding) validate() error {
	if len(v.Binding) > GeneratorSupportBindingMaxLength-103 {
		return ErrRecordCapacity
	}
	if v.Schema != GeneratorSupportBindingSchema || v.Role < 1 || v.Role > 7 || !publicIDsValid(v.ContractID, v.ImplementationID, v.PublicBindingDigest) {
		return ErrRecord
	}
	if v.Role == 7 {
		route, err := credentialroute.Decode(v.Binding)
		if err != nil || ID(route.ContractID) != v.ContractID {
			return ErrRecord
		}
		id, err := credentialroute.Identity(route)
		if err != nil || ID(id) != v.PublicBindingDigest {
			return ErrRecord
		}
		return nil
	}
	if v.Role != 6 {
		if len(v.Binding) != 0 {
			return ErrRecord
		}
		return nil
	}
	if _, err := InspectPublicSigningBinding(v.Binding); err != nil {
		return err
	}
	w := cryptoHashWriter(cryptoPurposePrefix + "signing-binding-v1\x00")
	w.blob(v.Binding)
	if w.result(0).Digest != v.PublicBindingDigest {
		return ErrRecord
	}
	return nil
}

func EncodeGeneratorSupportBinding(v GeneratorSupportBinding) ([]byte, error) {
	if err := v.validate(); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, 103+len(v.Binding))}
	w.u16(v.Schema)
	w.u8(v.Role)
	w.id(v.ContractID)
	w.id(v.ImplementationID)
	w.id(v.PublicBindingDigest)
	w.blob(v.Binding)
	return w.b, nil
}

func InspectGeneratorSupportBinding(b []byte) (GeneratorSupportBinding, error) {
	if len(b) > GeneratorSupportBindingMaxLength {
		return GeneratorSupportBinding{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GeneratorSupportBinding{Schema: r.u16(), Role: r.u8(), ContractID: r.requiredID(), ImplementationID: r.requiredID(), PublicBindingDigest: r.requiredID(), Binding: r.blob(GeneratorSupportBindingMaxLength - 103)}
	if err := r.end(); err != nil {
		return GeneratorSupportBinding{}, err
	}
	if err := v.validate(); err != nil {
		return GeneratorSupportBinding{}, err
	}
	return v, nil
}

func GeneratorSupportBindingID(v GeneratorSupportBinding) (ID, error) {
	b, err := EncodeGeneratorSupportBinding(v)
	if err != nil {
		return ID{}, err
	}
	return generatorDigest("support-binding-v2", b), nil
}

// GeneratorProof borrows its public subject and signature. Structural parsing
// checks the exact subject and DER; the selected closure verifies authority.
type GeneratorProof struct {
	Schema             uint16
	Purpose            GeneratorAuthorityPurpose
	Subject, Signature []byte
	SupportBindingID   ID
}

func (v GeneratorProof) validate() (GeneratorAuthoritySubject, error) {
	if len(v.Subject) > GeneratorAuthoritySubjectLength || len(v.Signature) > MaxSignature {
		return GeneratorAuthoritySubject{}, ErrRecordCapacity
	}
	if v.Schema != GeneratorRecordSchema || v.SupportBindingID.IsZero() || !P256SignatureEncodingValid(v.Signature) {
		return GeneratorAuthoritySubject{}, ErrRecord
	}
	s, err := DecodeGeneratorAuthoritySubject(v.Subject)
	if err != nil {
		return GeneratorAuthoritySubject{}, err
	}
	if s.Purpose != v.Purpose {
		return GeneratorAuthoritySubject{}, ErrRecord
	}
	return s, nil
}

func EncodeGeneratorProof(v GeneratorProof) ([]byte, error) {
	if _, err := v.validate(); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, 43+len(v.Subject)+len(v.Signature))}
	w.u16(v.Schema)
	w.u8(uint8(v.Purpose))
	w.blob(v.Subject)
	w.blob(v.Signature)
	w.id(v.SupportBindingID)
	return w.b, nil
}

func InspectGeneratorProof(b []byte) (GeneratorProof, error) {
	if len(b) > GeneratorProofMaxLength {
		return GeneratorProof{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GeneratorProof{Schema: r.u16(), Purpose: GeneratorAuthorityPurpose(r.u8()), Subject: r.blob(GeneratorAuthoritySubjectLength), Signature: r.blob(MaxSignature), SupportBindingID: r.requiredID()}
	if err := r.end(); err != nil {
		return GeneratorProof{}, err
	}
	if _, err := v.validate(); err != nil {
		return GeneratorProof{}, err
	}
	return v, nil
}

type GeneratorConsumer struct {
	Schema                             uint16
	OwnerID, MaterialID, ContextDigest ID
	SubjectKind                        uint8
	SubjectID                          ID
	Purpose                            uint8
}

func (v GeneratorConsumer) valid() bool {
	return v.Schema == GeneratorRecordSchema && publicIDsValid(v.OwnerID, v.MaterialID, v.ContextDigest, v.SubjectID) &&
		(v.SubjectKind == GeneratorConsumerAcceptedSource && v.Purpose == GeneratorConsumerPrepareAcceptedSource || v.SubjectKind == GeneratorConsumerRetainedCanonicalValue && v.Purpose == GeneratorConsumerUseRetainedCanonical || v.SubjectKind == GeneratorConsumerOriginalResult && (v.Purpose == GeneratorConsumerDeriveSelectedResult || v.Purpose == GeneratorConsumerAdoptLateOriginalResult))
}

func EncodeGeneratorConsumer(v GeneratorConsumer) ([]byte, error) {
	if !v.valid() {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, GeneratorConsumerLength)}
	w.u16(v.Schema)
	w.id(v.OwnerID)
	w.id(v.MaterialID)
	w.id(v.ContextDigest)
	w.u8(v.SubjectKind)
	w.id(v.SubjectID)
	w.u8(v.Purpose)
	return w.b, nil
}

func InspectGeneratorConsumer(b []byte) (GeneratorConsumer, error) {
	if len(b) > GeneratorConsumerLength {
		return GeneratorConsumer{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GeneratorConsumer{Schema: r.u16(), OwnerID: r.requiredID(), MaterialID: r.requiredID(), ContextDigest: r.requiredID(), SubjectKind: r.u8(), SubjectID: r.requiredID(), Purpose: r.u8()}
	if err := r.end(); err != nil {
		return GeneratorConsumer{}, err
	}
	if !v.valid() {
		return GeneratorConsumer{}, ErrRecord
	}
	return v, nil
}

type GeneratorLogicalSlice struct {
	Schema      uint16
	ContentKind uint8
	ContentID   ID
	Length      uint32
	Digest      ID
}

func (v GeneratorLogicalSlice) valid() bool {
	return v.Schema == GeneratorRecordSchema && v.ContentKind >= GeneratorContentIntent && v.ContentKind <= GeneratorContentOutputConfiguration &&
		publicIDsValid(v.ContentID, v.Digest) && v.Length != 0
}

func writeGeneratorLogicalSlice(w *cryptoWriter, v GeneratorLogicalSlice) {
	w.u16(v.Schema)
	w.u8(v.ContentKind)
	w.id(v.ContentID)
	w.u32(v.Length)
	w.id(v.Digest)
}

func EncodeGeneratorLogicalSlice(v GeneratorLogicalSlice) ([]byte, error) {
	if !v.valid() {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, GeneratorLogicalSliceLength)}
	writeGeneratorLogicalSlice(&w, v)
	return w.b, nil
}

type GeneratorSliceLocation struct {
	Schema            uint16
	ContentKind       uint8
	ContentID, BlobID ID
	Offset            uint64
	Length            uint32
	Digest            ID
}

func (v GeneratorSliceLocation) Logical() GeneratorLogicalSlice {
	return GeneratorLogicalSlice{Schema: v.Schema, ContentKind: v.ContentKind, ContentID: v.ContentID, Length: v.Length, Digest: v.Digest}
}

func (v GeneratorSliceLocation) valid() bool {
	return v.Logical().valid() && !v.BlobID.IsZero() && v.Offset <= ^uint64(0)-uint64(v.Length)
}

func EncodeGeneratorSliceLocation(v GeneratorSliceLocation) ([]byte, error) {
	if !v.valid() {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, GeneratorSliceLocationLength)}
	w.u16(v.Schema)
	w.u8(v.ContentKind)
	w.id(v.ContentID)
	w.id(v.BlobID)
	w.u64(v.Offset)
	w.u32(v.Length)
	w.id(v.Digest)
	return w.b, nil
}

func InspectGeneratorSliceLocation(b []byte) (GeneratorSliceLocation, error) {
	if len(b) > GeneratorSliceLocationLength {
		return GeneratorSliceLocation{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GeneratorSliceLocation{Schema: r.u16(), ContentKind: r.u8(), ContentID: r.requiredID(), BlobID: r.requiredID(), Offset: r.u64(), Length: r.u32(), Digest: r.requiredID()}
	if err := r.end(); err != nil {
		return GeneratorSliceLocation{}, err
	}
	if !v.valid() {
		return GeneratorSliceLocation{}, ErrRecord
	}
	return v, nil
}

// GeneratorFactsRow borrows the closed SafeFacts body, never a raw response.
type GeneratorFactsRow struct {
	Schema   uint16
	ResultID ID
	Facts    []byte
}

func (v GeneratorFactsRow) validate() error {
	if len(v.Facts) > GeneratorSafeFactsEnvelopeLength {
		return ErrRecordCapacity
	}
	if v.Schema != GeneratorRecordSchema || v.ResultID.IsZero() {
		return ErrRecord
	}
	_, err := InspectGeneratorAttemptFacts(v.Facts)
	return err
}

func EncodeGeneratorFactsRow(v GeneratorFactsRow) ([]byte, error) {
	if err := v.validate(); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, 38+len(v.Facts))}
	w.u16(v.Schema)
	w.id(v.ResultID)
	w.blob(v.Facts)
	return w.b, nil
}

func InspectGeneratorFactsRow(b []byte) (GeneratorFactsRow, error) {
	if len(b) > GeneratorFactsRowMaxLength {
		return GeneratorFactsRow{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GeneratorFactsRow{Schema: r.u16(), ResultID: r.requiredID(), Facts: r.blob(GeneratorSafeFactsEnvelopeLength)}
	if err := r.end(); err != nil {
		return GeneratorFactsRow{}, err
	}
	if err := v.validate(); err != nil {
		return GeneratorFactsRow{}, err
	}
	return v, nil
}

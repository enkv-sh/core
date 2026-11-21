package contract

import (
	"bytes"
	"slices"

	protocol "enkv.sh/sdk/protocols/generator"
)

const (
	GeneratorDispositionCompleteCreate               = protocol.DispositionCompleteCreate
	GeneratorDispositionOwnedUnusableCreate          = protocol.DispositionOwnedUnusableCreate
	GeneratorDispositionConfirmedNoEffect            = protocol.DispositionConfirmedNoEffect
	GeneratorDispositionRetirementAcknowledged       = protocol.DispositionRetirementAcknowledged
	GeneratorDispositionUnknown                      = protocol.DispositionUnknown
	GeneratorDispositionScopedUnusability      uint8 = 6
	GeneratorDispositionContinuedUsability     uint8 = 7
	GeneratorDispositionConflictingBinding     uint8 = 8
	GeneratorReasonNone                              = protocol.ReasonNone
	GeneratorReasonMissingValue                      = protocol.ReasonMissingValue
	GeneratorReasonInvalidValue                      = protocol.ReasonInvalidValue
	GeneratorReasonControls                          = protocol.ReasonControls
	GeneratorReasonInactive                          = protocol.ReasonInactive
	GeneratorReasonMalformed                         = protocol.ReasonMalformed
	GeneratorReasonOverflow                          = protocol.ReasonOverflow
	GeneratorReasonRejected                          = protocol.ReasonRejected
	GeneratorReasonTransport                         = protocol.ReasonTransport
	GeneratorReasonDeadline                          = protocol.ReasonDeadline
	GeneratorReasonIdentityConflict                  = protocol.ReasonIdentityConflict
	GeneratedResultCoreLength                        = 452
	GeneratorSafeFactsMaxLength                      = protocol.MaximumSafeFactsBody
	GeneratorSafeFactsEnvelopeLength                 = 4096
	GeneratedResultRecordMaxLength                   = 16 + GeneratedResultCoreLength + GeneratorSafeFactsEnvelopeLength + canonicalPayloadMaxLength + transferEnvelopeMaxLength
)

type GeneratorSafeFacts struct {
	Schema                                                      uint16
	Action                                                      uint8
	LifecycleMode                                               GeneratorLifecycleMode
	Disposition, Reason                                         uint8
	RequestDigest, IntentDigest, ResourceContractID             ID
	Target, ResourceData, ProviderFacts                         []byte
	ScopeID, PrecedingResultID, PrecedingResultBodyDigest       ID
	ObservedResourceID, ObservedResourceDigest, ObservedScopeID ID
}

func (v GeneratorSafeFacts) observationIDs() [6]ID {
	return [6]ID{v.ScopeID, v.PrecedingResultID, v.PrecedingResultBodyDigest, v.ObservedResourceID, v.ObservedResourceDigest, v.ObservedScopeID}
}
func (v GeneratorSafeFacts) valid() bool {
	if v.Schema != GeneratorSafeFactsSchema {
		return false
	}
	ids := v.observationIDs()
	if v.Disposition >= GeneratorDispositionScopedUnusability {
		return v.Action == GeneratorActionDelete && v.LifecycleMode == GeneratorLifecycleManaged && !v.ResourceContractID.IsZero() && publicIDsValid(v.RequestDigest, v.IntentDigest) && len(v.Target) > 0 && len(v.ResourceData) > 0 && v.Disposition <= GeneratorDispositionConflictingBinding && v.Reason == GeneratorReasonNone && publicIDsValid(ids[:]...)
	}
	for _, id := range ids {
		if !id.IsZero() {
			return false
		}
	}
	_, err := protocol.EncodeSafeFacts(protocol.SafeFacts{Schema: protocol.Schema, Action: v.Action, LifecycleMode: uint8(v.LifecycleMode), Disposition: v.Disposition, Reason: v.Reason, RequestDigest: protocol.ID(v.RequestDigest), IntentDigest: protocol.ID(v.IntentDigest), ResourceContractID: protocol.ID(v.ResourceContractID), Target: v.Target, ResourceData: v.ResourceData, ProviderFacts: v.ProviderFacts})
	return err == nil
}
func GeneratorSafeFactsLength(v GeneratorSafeFacts) (int, error) {
	n := protocol.SafeFactsFixedLength + len(v.Target) + len(v.ResourceData) + len(v.ProviderFacts)
	limit := GeneratorSafeFactsMaxLength
	if v.Disposition >= GeneratorDispositionScopedUnusability {
		n += 6 * 32
		limit = GeneratorSafeFactsEnvelopeLength
	}
	if n > limit {
		return 0, ErrRecordCapacity
	}
	if !v.valid() {
		return 0, ErrRecord
	}
	return n, nil
}
func writeGeneratorSafeFacts(w *cryptoWriter, v GeneratorSafeFacts) {
	w.u16(v.Schema)
	w.u8(v.Action)
	w.u8(uint8(v.LifecycleMode))
	w.u8(v.Disposition)
	w.u8(v.Reason)
	w.id(v.RequestDigest)
	w.id(v.IntentDigest)
	w.id(v.ResourceContractID)
	w.blob(v.Target)
	w.blob(v.ResourceData)
	w.blob(v.ProviderFacts)
	present := v.Disposition >= GeneratorDispositionScopedUnusability
	w.u8(boolU8(present))
	if present {
		for _, id := range v.observationIDs() {
			w.id(id)
		}
	}
}
func AppendGeneratorSafeFacts(dst []byte, v GeneratorSafeFacts) ([]byte, error) {
	if _, err := GeneratorSafeFactsLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeGeneratorSafeFacts(&w, v)
	return w.b, nil
}
func EncodeGeneratorSafeFacts(v GeneratorSafeFacts) ([]byte, error) {
	return AppendGeneratorSafeFacts(nil, v)
}

type GeneratorSafeFactsView struct {
	GeneratorSafeFacts
	body []byte
}

func (v GeneratorSafeFactsView) Own() (GeneratorSafeFacts, error) {
	b, err := EncodeGeneratorSafeFacts(v.GeneratorSafeFacts)
	if err != nil || !bytes.Equal(b, v.body) {
		return GeneratorSafeFacts{}, ErrRecord
	}
	out := v.GeneratorSafeFacts
	out.Target = slices.Clone(out.Target)
	out.ResourceData = slices.Clone(out.ResourceData)
	out.ProviderFacts = slices.Clone(out.ProviderFacts)
	return out, nil
}
func InspectGeneratorSafeFacts(body []byte) (GeneratorSafeFactsView, error) {
	if len(body) > max(GeneratorSafeFactsMaxLength, GeneratorSafeFactsEnvelopeLength) {
		return GeneratorSafeFactsView{}, ErrRecordCapacity
	}
	r := newRecordReader(body)
	fieldLimit := max(GeneratorSafeFactsMaxLength, GeneratorSafeFactsEnvelopeLength) - protocol.SafeFactsFixedLength
	v := GeneratorSafeFacts{Schema: r.u16(), Action: r.u8(), LifecycleMode: GeneratorLifecycleMode(r.u8()), Disposition: r.u8(), Reason: r.u8(), RequestDigest: r.requiredID(), IntentDigest: r.requiredID(), ResourceContractID: r.id(), Target: r.blob(fieldLimit), ResourceData: r.blob(fieldLimit), ProviderFacts: r.blob(fieldLimit)}
	present := r.u8()
	if present > 1 {
		return GeneratorSafeFactsView{}, ErrRecord
	}
	if present == 1 {
		v.ScopeID = r.requiredID()
		v.PrecedingResultID = r.requiredID()
		v.PrecedingResultBodyDigest = r.requiredID()
		v.ObservedResourceID = r.requiredID()
		v.ObservedResourceDigest = r.requiredID()
		v.ObservedScopeID = r.requiredID()
	}
	if err := r.end(); err != nil {
		return GeneratorSafeFactsView{}, err
	}
	if (present == 1) != (v.Disposition >= GeneratorDispositionScopedUnusability) {
		return GeneratorSafeFactsView{}, ErrRecord
	}
	if _, err := GeneratorSafeFactsLength(v); err != nil {
		return GeneratorSafeFactsView{}, err
	}
	return GeneratorSafeFactsView{v, body}, nil
}
func DecodeGeneratorSafeFacts(body []byte) (GeneratorSafeFacts, error) {
	v, err := InspectGeneratorSafeFacts(body)
	if err != nil {
		return GeneratorSafeFacts{}, err
	}
	return v.Own()
}
func GeneratorSafeFactsDigest(v GeneratorSafeFacts) (ID, error) {
	b, err := EncodeGeneratorSafeFacts(v)
	if err != nil {
		return ID{}, err
	}
	return generatorDigest("safe-facts-v3", b), nil
}

// GeneratedResultCore fixes one original result independently of any future
// canonical value entry. It carries no public hash of a returned secret.
type GeneratedResultCore struct {
	Schema, Profile                                                                 uint16
	DomainID, OperationID, MaterialID, UsePlanDigest, PlanGraphID                   ID
	AttemptID, TransmissionID, ResultID, ExecutorID, DescriptorID, ConfigContractID ID
	ResultContractID, RequestDigest, SafeFactsDigest                                ID
}

func (v GeneratedResultCore) ids() [14]ID {
	return [14]ID{v.DomainID, v.OperationID, v.MaterialID, v.UsePlanDigest, v.PlanGraphID,
		v.AttemptID, v.TransmissionID, v.ResultID, v.ExecutorID, v.DescriptorID, v.ConfigContractID,
		v.ResultContractID, v.RequestDigest, v.SafeFactsDigest}
}

func (v GeneratedResultCore) valid() bool {
	ids := v.ids()
	return v.Schema == GeneratedResultCoreSchema && v.Profile == MaterialCryptoProfile && publicIDsValid(ids[:]...)
}

func AppendGeneratedResultCore(dst []byte, v GeneratedResultCore) ([]byte, error) {
	if !v.valid() {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: dst}
	w.u16(v.Schema)
	w.u16(v.Profile)
	for _, id := range v.ids() {
		w.id(id)
	}
	return w.b, nil
}

func EncodeGeneratedResultCore(v GeneratedResultCore) ([]byte, error) {
	return AppendGeneratedResultCore(make([]byte, 0, GeneratedResultCoreLength), v)
}

func InspectGeneratedResultCore(b []byte) (GeneratedResultCore, error) {
	if len(b) > GeneratedResultCoreLength {
		return GeneratedResultCore{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GeneratedResultCore{Schema: r.u16(), Profile: r.u16(), DomainID: r.id(), OperationID: r.id(), MaterialID: r.id(),
		UsePlanDigest: r.id(), PlanGraphID: r.id(), AttemptID: r.id(), TransmissionID: r.id(), ResultID: r.id(),
		ExecutorID: r.id(), DescriptorID: r.id(), ConfigContractID: r.id(), ResultContractID: r.id(), RequestDigest: r.id(), SafeFactsDigest: r.id()}
	if err := r.end(); err != nil {
		return GeneratedResultCore{}, err
	}
	if !v.valid() {
		return GeneratedResultCore{}, ErrRecord
	}
	return v, nil
}

func GeneratedResultCoreDigest(v GeneratedResultCore) (ID, error) {
	b, err := EncodeGeneratedResultCore(v)
	if err != nil {
		return ID{}, err
	}
	return Hash(b), nil
}

type GeneratedResultRecord struct {
	Core      GeneratedResultCore
	SafeFacts GeneratorSafeFacts
	Payload   CanonicalPayload
	Transfer  TransferEnvelope
}

type GeneratedResultRecordView struct {
	Core      GeneratedResultCore
	SafeFacts GeneratorSafeFactsView
	Payload   CanonicalPayloadView
	Transfer  TransferEnvelopeView
}

// MatchesLocalCreateAttempt binds an inspected returned result to its terminal
// resource-free CREATE. A resultless callback failure has no such handoff.
func (v GeneratedResultRecordView) MatchesLocalCreateAttempt(a GeneratedAttemptRecord) bool {
	if a.LifecycleMode != GeneratorLifecycleNone || a.Stage != GeneratedStageTerminal ||
		v.SafeFacts.LifecycleMode != GeneratorLifecycleNone || v.SafeFacts.Action != GeneratorActionCreate ||
		v.Core.DomainID != a.DomainID || v.Core.OperationID != a.OperationID || v.Core.AttemptID != a.AttemptID ||
		v.Core.TransmissionID != a.TransmissionID || v.Core.ResultID != a.ResultID || v.Core.RequestDigest != a.RequestDigest {
		return false
	}
	return a.State == GeneratedEffectSucceeded && v.SafeFacts.Disposition == GeneratorDispositionCompleteCreate ||
		a.State == GeneratedEffectConfirmedNoEffect && v.SafeFacts.Disposition == GeneratorDispositionConfirmedNoEffect
}

func generatedResultContextValid(v GeneratedResultRecord) bool {
	if v.Core.Schema != GeneratedResultCoreSchema || v.SafeFacts.Schema != GeneratorSafeFactsSchema {
		return false
	}
	digest, err := GeneratedResultCoreDigest(v.Core)
	facts, factsErr := GeneratorSafeFactsDigest(v.SafeFacts)
	data, commitment, keyErr := GeneratorResultKeyIDs(v.Core.ResultID)
	t := v.Transfer.Core
	return err == nil && factsErr == nil && keyErr == nil && facts == v.Core.SafeFactsDigest && v.SafeFacts.RequestDigest == v.Core.RequestDigest &&
		v.Payload.DataKeyID == data && v.Payload.CommitmentKeyID == commitment && v.Payload.DataKeyEpoch == 1 && v.Payload.CommitmentKeyEpoch == 1 &&
		v.SafeFacts.Disposition != GeneratorDispositionUnknown && (v.SafeFacts.Disposition == GeneratorDispositionCompleteCreate && v.Payload.ContentLength > 0 || v.SafeFacts.Disposition != GeneratorDispositionCompleteCreate && v.Payload.ContentLength == 0) &&
		t.UseKind == resultTransferUse && t.Profile == v.Core.Profile && v.Payload.Profile == v.Core.Profile &&
		v.Payload.CryptoSupportID == t.CryptoSupportID && t.DomainID == v.Core.DomainID && t.OperationID == v.Core.OperationID &&
		t.OperationMaterialID == v.Core.MaterialID && t.UsePlanDigest == v.Core.UsePlanDigest &&
		t.AttemptID == v.Core.AttemptID && t.ResultID == v.Core.ResultID && t.ResultCoreDigest == digest
}

func GeneratedResultRecordLength(v GeneratedResultRecord) (int, error) {
	if !generatedResultContextValid(v) {
		return 0, ErrRecord
	}
	facts, err := GeneratorSafeFactsLength(v.SafeFacts)
	if err != nil {
		return 0, err
	}
	payload, err := CanonicalPayloadLength(v.Payload)
	if err != nil {
		return 0, err
	}
	transfer, err := TransferEnvelopeLength(v.Transfer)
	if err != nil {
		return 0, err
	}
	return 16 + GeneratedResultCoreLength + facts + payload + transfer, nil
}

func AppendGeneratedResultRecord(dst []byte, v GeneratedResultRecord) ([]byte, error) {
	if _, err := GeneratedResultRecordLength(v); err != nil {
		return nil, err
	}
	core, err := EncodeGeneratedResultCore(v.Core)
	if err != nil {
		return nil, err
	}
	facts, err := EncodeGeneratorSafeFacts(v.SafeFacts)
	if err != nil {
		return nil, err
	}
	payloadLength, err := CanonicalPayloadLength(v.Payload)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	w.blob(core)
	w.blob(facts)
	w.u32(uint32(payloadLength))
	writeCanonicalPayload(&w, v.Payload)
	w.u32(uint32(transferEnvelopeMaxLength))
	writeTransferEnvelope(&w, v.Transfer)
	return w.b, nil
}

func EncodeGeneratedResultRecord(v GeneratedResultRecord) ([]byte, error) {
	n, err := GeneratedResultRecordLength(v)
	if err != nil {
		return nil, err
	}
	return AppendGeneratedResultRecord(make([]byte, 0, n), v)
}

func InspectGeneratedResultRecord(b []byte) (GeneratedResultRecordView, error) {
	if len(b) > GeneratedResultRecordMaxLength {
		return GeneratedResultRecordView{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	var v GeneratedResultRecordView
	var err error
	core := r.blob(GeneratedResultCoreLength)
	if r.err != nil {
		return v, r.failure()
	}
	v.Core, err = InspectGeneratedResultCore(core)
	if err != nil {
		return GeneratedResultRecordView{}, err
	}
	facts := r.blob(GeneratorSafeFactsMaxLength)
	if r.err != nil {
		return GeneratedResultRecordView{}, r.failure()
	}
	v.SafeFacts, err = InspectGeneratorSafeFacts(facts)
	if err != nil {
		return GeneratedResultRecordView{}, err
	}
	payload := r.blob(canonicalPayloadMaxLength)
	if r.err != nil {
		return GeneratedResultRecordView{}, r.failure()
	}
	v.Payload, err = InspectCanonicalPayload(payload)
	if err != nil {
		return GeneratedResultRecordView{}, err
	}
	transfer := r.blob(transferEnvelopeMaxLength)
	if r.err != nil {
		return GeneratedResultRecordView{}, r.failure()
	}
	v.Transfer, err = InspectTransferEnvelope(transfer)
	if err != nil {
		return GeneratedResultRecordView{}, err
	}
	if err := r.end(); err != nil {
		return GeneratedResultRecordView{}, err
	}
	if !generatedResultContextValid(GeneratedResultRecord{Core: v.Core, SafeFacts: v.SafeFacts.GeneratorSafeFacts, Payload: CanonicalPayload(v.Payload), Transfer: TransferEnvelope(v.Transfer)}) {
		return GeneratedResultRecordView{}, ErrRecord
	}
	return v, nil
}

func (v GeneratedResultRecordView) Own() (GeneratedResultRecord, error) {
	facts, err := v.SafeFacts.Own()
	if err != nil {
		return GeneratedResultRecord{}, err
	}
	out := GeneratedResultRecord{Core: v.Core, SafeFacts: facts, Payload: CanonicalPayload(v.Payload), Transfer: TransferEnvelope(v.Transfer)}
	if _, err := GeneratedResultRecordLength(out); err != nil {
		return GeneratedResultRecord{}, err
	}
	out.Payload.Ciphertext, out.Transfer.Ciphertext = ownedBytes(v.Payload.Ciphertext), ownedBytes(v.Transfer.Ciphertext)
	return out, nil
}

func DecodeGeneratedResultRecord(b []byte) (GeneratedResultRecord, error) {
	v, err := InspectGeneratedResultRecord(b)
	if err != nil {
		return GeneratedResultRecord{}, err
	}
	return v.Own()
}

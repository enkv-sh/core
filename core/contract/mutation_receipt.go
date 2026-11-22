package contract

const MutationReceiptSchema uint16 = 3

const (
	ReceiptStateSuccess                     = 1
	ReceiptStateExactResume                 = 4
	ReceiptStatePossibleLiveResidueAccepted = 6
	ReceiptStateRetirementPending           = 7
	ReceiptStateEffectUnknown               = 10
	ReceiptStateEffectTerminalFailure       = 11
	ReceiptStateWorkEnded                   = 12
)

const (
	ReceiptEffectNotApplicable = 0
	ReceiptEffectNoChange      = 1
	ReceiptEffectComplete      = 2
	ReceiptEffectPending       = 3
	ReceiptEffectPartial       = 4
	ReceiptEffectUnknown       = 5
	ReceiptEffectMixedTerminal = 6
	ReceiptEffectFailed        = 7
)

const (
	ReceiptCanonicalSelected    = 1
	ReceiptCanonicalNotSelected = 2
)

const ReceiptOutputNotApplicable = 0

const (
	CompactMutationReceiptLength    = 471
	MutationResultProjectionLength  = 647
	MutationReceiptWindowLimit      = 256
	MutationChangedSubjectLimit     = 16384
	contractMaxChildPagesForReceipt = int16(MaxChildPages)
	receiptMaxSelectedBytes         = int64(MaxChildPages * MaxRequiredSupportPageLength)
)

const (
	ReceiptEvidenceCanonical uint16 = iota + 1
	ReceiptEvidenceProviderFacts
	ReceiptEvidenceAcknowledged
	ReceiptEvidenceConfirmed
	ReceiptEvidenceMixedCompletion
)

// AdministrativeEvidence* are selected local facts. They do not prove that an
// unobserved remote result is absent or that an external request was canceled.
const (
	AdministrativeEvidenceMissing uint16 = 1 << iota
	AdministrativeEvidenceQualifiedUnknown
	AdministrativeEvidenceTerminalFailure
	AdministrativeEvidenceAcknowledged
	AdministrativeEvidenceContradiction
	AdministrativeEvidenceConfirmed
	AdministrativeEvidencePossibleLive
	AdministrativeEvidenceReleasePending
	AdministrativeEvidenceReleaseUnknown
	AdministrativeEvidenceReleaseUnobserved
)

const administrativeEvidenceMask = AdministrativeEvidenceMissing | AdministrativeEvidenceQualifiedUnknown |
	AdministrativeEvidenceTerminalFailure | AdministrativeEvidenceAcknowledged | AdministrativeEvidenceContradiction |
	AdministrativeEvidenceConfirmed | AdministrativeEvidencePossibleLive | AdministrativeEvidenceReleasePending |
	AdministrativeEvidenceReleaseUnknown | AdministrativeEvidenceReleaseUnobserved

func AdministrativeEvidenceValid(summary uint16) bool {
	return summary&^administrativeEvidenceMask == 0 &&
		summary&(AdministrativeEvidenceMissing|AdministrativeEvidenceQualifiedUnknown|AdministrativeEvidenceTerminalFailure|
			AdministrativeEvidenceAcknowledged|AdministrativeEvidenceContradiction|AdministrativeEvidenceConfirmed|
			AdministrativeEvidencePossibleLive) != 0
}

const (
	ReceiptWarningPossibleLive uint64 = 1 << iota
	ReceiptWarningInvalidationNotConfirmed
)

const (
	ReceiptEffectCount = iota
	ReceiptOutputCount
	ReceiptDutyCount
	ReceiptHazardCount
	ReceiptChangedAccessCount
	ReceiptSummarySuccessCount
	ReceiptSummaryFailureCount
	ReceiptSummaryNeutralCount
	ReceiptSummaryPendingCount
	ReceiptSummaryUnknownCount
	ReceiptPreservedResidueCount
	ReceiptNoEffectPredecessorCount
	ReceiptSummaryCount
)

// CompactMutationReceipt is a frozen terminal canonical outcome. Live work is
// rooted separately; receipt retention never grants effect or cleanup rights.
type CompactMutationReceipt struct {
	Schema                                                                    uint16
	OperationKind, StateResult, EffectSummary, OutputSummary, EvidenceCeiling uint16
	DomainID, OperationID, RequestIdentityDigest                              ID
	PredecessorRevisionID, RequestedRevisionID, ObservedRevisionID            ID
	CanonicalOutcome                                                          uint8
	ChangedSubjects, CompleteResult                                           GeneratorDescriptor
	WarningBits                                                               uint64
	SummaryCounts                                                             [ReceiptSummaryCount]uint32
	AcknowledgedCount, ConfirmedCount, UnknownCount                           uint32
	AdministrativeTargetKind, AdministrativeWarningChanges                    uint8
	AdministrativeTargetID, AdministrativeDisposition                         ID
	AdministrativeOriginalEvidence                                            uint16
	AdministrativePageDelta                                                   int16
	AdministrativeByteDelta                                                   int64
	AdministrativeGroupID                                                     ID
}

func compactMutationOperationValid(kind uint16) bool {
	switch kind {
	case OperationInitializeDomain, OperationApplyDeclaration, OperationRemoveSecretValueEntryAccess, OperationRotateRecipientKeyBinding, OperationRetireRecipientIdentity, OperationEnvelopeRekey, OperationRotateValueEntryValue, OperationRebindStoreConstruction, OperationConfigureCommercialAttachment, OperationReplaceRecoveryKeysAndRoot, OperationRetireGeneratedGeneration, OperationAcceptGeneratedRetirementResidue, OperationEndSelectedWork:
		return true
	}
	return false
}

func compactMutationReceiptFieldsValid(v CompactMutationReceipt) bool {
	if !CompactMutationReceiptSummaryValid(v.OperationKind, v.StateResult, v.EvidenceCeiling, v.CanonicalOutcome, v.WarningBits) {
		return false
	}
	if v.OperationKind == OperationEndSelectedWork {
		if v.Schema != MutationReceiptSchema || !publicIDsValid(v.DomainID, v.OperationID, v.PredecessorRevisionID, v.RequestedRevisionID, v.ObservedRevisionID, v.AdministrativeTargetID, v.AdministrativeDisposition, v.AdministrativeGroupID) ||
			v.RequestedRevisionID != v.ObservedRevisionID || v.EffectSummary != ReceiptEffectNotApplicable ||
			v.OutputSummary != ReceiptOutputNotApplicable ||
			v.AdministrativeTargetKind < AdministrativeGeneratedParent || v.AdministrativeTargetKind > AdministrativeGC ||
			!AdministrativeEvidenceValid(v.AdministrativeOriginalEvidence) ||
			v.AdministrativeWarningChanges & ^uint8(0x1f) != 0 ||
			uint64(v.AdministrativeWarningChanges)&^v.WarningBits != 0 ||
			v.AdministrativePageDelta < -contractMaxChildPagesForReceipt || v.AdministrativePageDelta > contractMaxChildPagesForReceipt ||
			v.AdministrativeByteDelta < -receiptMaxSelectedBytes || v.AdministrativeByteDelta > receiptMaxSelectedBytes ||
			!v.ChangedSubjects.Valid() || v.ChangedSubjects.Count != 1 ||
			v.ChangedSubjects.Length != 4+38*uint64(v.ChangedSubjects.Count) ||
			v.AcknowledgedCount != 0 || v.ConfirmedCount != 0 || v.UnknownCount != 0 {
			return false
		}
		for _, count := range v.SummaryCounts {
			if count != 0 {
				return false
			}
		}
		return true
	}
	if v.AdministrativeTargetKind != 0 || !v.AdministrativeTargetID.IsZero() || !v.AdministrativeDisposition.IsZero() ||
		v.AdministrativeOriginalEvidence != 0 || v.AdministrativeWarningChanges != 0 ||
		v.AdministrativePageDelta != 0 || v.AdministrativeByteDelta != 0 || !v.AdministrativeGroupID.IsZero() {
		return false
	}
	if v.Schema != MutationReceiptSchema ||
		!publicIDsValid(v.DomainID, v.OperationID, v.RequestedRevisionID, v.ObservedRevisionID) ||
		v.PredecessorRevisionID.IsZero() != (v.OperationKind == OperationInitializeDomain) ||
		!v.ChangedSubjects.Valid() || v.ChangedSubjects.Count > MutationChangedSubjectLimit ||
		v.ChangedSubjects.Length != 4+38*uint64(v.ChangedSubjects.Count) ||
		v.EffectSummary > ReceiptEffectFailed || v.OutputSummary != ReceiptOutputNotApplicable {
		return false
	}
	counts := v.SummaryCounts
	if counts[ReceiptOutputCount] != 0 || counts[ReceiptSummaryNeutralCount] != 0 {
		return false
	}
	var effects uint64
	for _, count := range counts[ReceiptSummarySuccessCount:] {
		effects += uint64(count)
	}
	if effects != uint64(counts[ReceiptEffectCount]) ||
		uint64(v.AcknowledgedCount)+uint64(v.ConfirmedCount)+uint64(v.UnknownCount) > effects ||
		uint64(v.UnknownCount) != uint64(counts[ReceiptSummaryUnknownCount])+uint64(counts[ReceiptPreservedResidueCount]) ||
		(v.AcknowledgedCount != 0) != (v.WarningBits&ReceiptWarningInvalidationNotConfirmed != 0) ||
		counts[ReceiptPreservedResidueCount] != 0 && v.WarningBits&ReceiptWarningPossibleLive == 0 {
		return false
	}
	summary := receiptEffectSummary(counts)
	if v.EffectSummary != summary && (v.EffectSummary != ReceiptEffectNotApplicable || effects != 0) {
		return false
	}
	ceiling := ReceiptEvidenceProviderFacts
	switch {
	case effects == 0 || v.OperationKind == OperationRetireGeneratedGeneration && effects == 1 && v.UnknownCount == 1 &&
		v.StateResult == ReceiptStateEffectUnknown && v.CanonicalOutcome == ReceiptCanonicalNotSelected && v.EvidenceCeiling == ReceiptEvidenceCanonical:
		ceiling = ReceiptEvidenceCanonical
	case v.AcknowledgedCount != 0 && v.ConfirmedCount != 0:
		ceiling = ReceiptEvidenceMixedCompletion
	case v.AcknowledgedCount != 0:
		ceiling = ReceiptEvidenceAcknowledged
	case v.ConfirmedCount != 0:
		ceiling = ReceiptEvidenceConfirmed
	}
	if v.EvidenceCeiling != ceiling {
		return false
	}
	if v.CanonicalOutcome == ReceiptCanonicalSelected {
		if v.RequestedRevisionID != v.ObservedRevisionID {
			return false
		}
		switch v.StateResult {
		case ReceiptStateSuccess, ReceiptStateExactResume:
			return v.EffectSummary <= ReceiptEffectComplete
		case ReceiptStatePossibleLiveResidueAccepted:
			return counts[ReceiptHazardCount] != 0
		case ReceiptStateRetirementPending:
			return counts[ReceiptDutyCount] != 0
		default:
			return false
		}
	}
	return v.RequestedRevisionID != v.ObservedRevisionID &&
		(v.StateResult == ReceiptStateEffectUnknown && v.EffectSummary == ReceiptEffectUnknown || v.StateResult == ReceiptStateEffectTerminalFailure && (v.EffectSummary == ReceiptEffectMixedTerminal || v.EffectSummary == ReceiptEffectFailed))
}

func receiptEffectSummary(counts [ReceiptSummaryCount]uint32) uint16 {
	success, failure, pending, unknown := counts[ReceiptSummarySuccessCount], counts[ReceiptSummaryFailureCount], counts[ReceiptSummaryPendingCount], counts[ReceiptSummaryUnknownCount]
	switch {
	case unknown != 0:
		return ReceiptEffectUnknown
	case pending != 0 && success == 0 && failure == 0:
		return ReceiptEffectPending
	case pending != 0:
		return ReceiptEffectPartial
	case success != 0 && failure != 0:
		return ReceiptEffectMixedTerminal
	case failure != 0:
		return ReceiptEffectFailed
	case success != 0:
		return ReceiptEffectComplete
	default:
		return ReceiptEffectNoChange
	}
}

func compactMutationResultShapeValid(v GeneratorDescriptor) bool {
	return v.Valid() && v.Count == 1 && v.Length == 8+MutationResultProjectionLength
}

func CompactMutationReceiptValid(v CompactMutationReceipt) bool {
	return !v.RequestIdentityDigest.IsZero() && compactMutationResultShapeValid(v.CompleteResult) && compactMutationReceiptFieldsValid(v)
}

func writeCompactMutationReceipt(w *cryptoWriter, v CompactMutationReceipt) {
	w.u16(v.Schema)
	w.u16(v.OperationKind)
	w.u16(v.StateResult)
	w.u16(v.EffectSummary)
	w.u16(v.OutputSummary)
	w.u16(v.EvidenceCeiling)
	for _, id := range []ID{v.DomainID, v.OperationID, v.RequestIdentityDigest,
		v.PredecessorRevisionID, v.RequestedRevisionID, v.ObservedRevisionID} {
		w.id(id)
	}
	w.u8(v.CanonicalOutcome)
	writeGeneratorDescriptor(w, v.ChangedSubjects)
	writeGeneratorDescriptor(w, v.CompleteResult)
	w.u64(v.WarningBits)
	for _, count := range v.SummaryCounts {
		w.u32(count)
	}
	w.u32(v.AcknowledgedCount)
	w.u32(v.ConfirmedCount)
	w.u32(v.UnknownCount)
	w.u8(v.AdministrativeTargetKind)
	w.id(v.AdministrativeTargetID)
	w.id(v.AdministrativeDisposition)
	w.u16(v.AdministrativeOriginalEvidence)
	w.u8(v.AdministrativeWarningChanges)
	w.u16(uint16(v.AdministrativePageDelta))
	w.u64(uint64(v.AdministrativeByteDelta))
	w.id(v.AdministrativeGroupID)
}

func AppendCompactMutationReceipt(dst []byte, v CompactMutationReceipt) ([]byte, error) {
	if !CompactMutationReceiptValid(v) {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: dst}
	writeCompactMutationReceipt(&w, v)
	return w.b, nil
}

func EncodeCompactMutationReceipt(v CompactMutationReceipt) ([]byte, error) {
	return AppendCompactMutationReceipt(make([]byte, 0, CompactMutationReceiptLength), v)
}

func InspectCompactMutationReceipt(b []byte) (CompactMutationReceipt, error) {
	if len(b) > CompactMutationReceiptLength {
		return CompactMutationReceipt{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := CompactMutationReceipt{Schema: r.u16(), OperationKind: r.u16(), StateResult: r.u16(), EffectSummary: r.u16(), OutputSummary: r.u16(), EvidenceCeiling: r.u16(),
		DomainID: r.requiredID(), OperationID: r.requiredID(), RequestIdentityDigest: r.requiredID(),
		PredecessorRevisionID: r.id(), RequestedRevisionID: r.requiredID(), ObservedRevisionID: r.requiredID(), CanonicalOutcome: r.u8(),
		ChangedSubjects: readGeneratorDescriptor(&r), CompleteResult: readGeneratorDescriptor(&r), WarningBits: r.u64()}
	for i := range v.SummaryCounts {
		v.SummaryCounts[i] = r.u32()
	}
	v.AcknowledgedCount, v.ConfirmedCount, v.UnknownCount = r.u32(), r.u32(), r.u32()
	v.AdministrativeTargetKind, v.AdministrativeTargetID, v.AdministrativeDisposition = r.u8(), r.id(), r.id()
	v.AdministrativeOriginalEvidence, v.AdministrativeWarningChanges = r.u16(), r.u8()
	v.AdministrativePageDelta, v.AdministrativeByteDelta = int16(r.u16()), int64(r.u64())
	v.AdministrativeGroupID = r.id()
	if err := r.end(); err != nil {
		return CompactMutationReceipt{}, err
	}
	if !CompactMutationReceiptValid(v) {
		return CompactMutationReceipt{}, ErrRecord
	}
	return v, nil
}

// CompactMutationReceiptPlan permits only the final request-identity hole.
// It is a hash input; selected support accepts actual receipts only.
type CompactMutationReceiptPlan CompactMutationReceipt

func AppendCompactMutationReceiptPlan(dst []byte, v CompactMutationReceiptPlan) ([]byte, error) {
	if !v.RequestIdentityDigest.IsZero() || !compactMutationResultShapeValid(v.CompleteResult) || !compactMutationReceiptFieldsValid(CompactMutationReceipt(v)) {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: dst}
	writeCompactMutationReceipt(&w, CompactMutationReceipt(v))
	return w.b, nil
}

// MutationResultProjection is transient. The receipt retains its commitment,
// not the request, changed-access records or complete operational vectors.
type MutationResultProjection struct {
	Receipt                                          CompactMutationReceiptPlan
	RequestCoreDigest                                ID
	ChangedAccess, Effects, Outputs, Duties, Hazards GeneratorDescriptor
}

// EmptyMutationResultDescriptors returns the five distinct present empty
// vectors in ChangedAccess, Effects, Outputs, Duties, Hazards order.
func EmptyMutationResultDescriptors() [5]GeneratorDescriptor {
	var out [5]GeneratorDescriptor
	for i, label := range []string{"changed-access", "effect-results", "output-results", "result-duties", "result-hazards"} {
		out[i] = GeneratorDescriptor{Digest: generatorDigest(label, []byte{0, 0, 0, 0}), Length: 4}
	}
	return out
}

func CompleteMutationResultDescriptor(v MutationResultProjection) (GeneratorDescriptor, error) {
	r := CompactMutationReceipt(v.Receipt)
	if !r.RequestIdentityDigest.IsZero() || r.CompleteResult != (GeneratorDescriptor{}) || v.RequestCoreDigest.IsZero() ||
		!compactMutationReceiptFieldsValid(r) || !generatedDescriptorsValid(v.ChangedAccess, v.Effects, v.Outputs, v.Duties, v.Hazards) ||
		v.ChangedAccess.Count != r.SummaryCounts[ReceiptChangedAccessCount] ||
		v.Effects.Count != r.SummaryCounts[ReceiptEffectCount] || v.Outputs.Count != r.SummaryCounts[ReceiptOutputCount] ||
		v.Duties.Count != r.SummaryCounts[ReceiptDutyCount] || v.Hazards.Count != r.SummaryCounts[ReceiptHazardCount] {
		return GeneratorDescriptor{}, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, 8+MutationResultProjectionLength)}
	w.u32(1)
	w.u32(MutationResultProjectionLength)
	w.u16(r.Schema)
	w.u16(r.OperationKind)
	for _, id := range []ID{r.DomainID, r.OperationID, v.RequestCoreDigest,
		r.PredecessorRevisionID, r.RequestedRevisionID, r.ObservedRevisionID} {
		w.id(id)
	}
	for _, value := range []uint16{r.StateResult, r.EffectSummary, r.OutputSummary, r.EvidenceCeiling} {
		w.u16(value)
	}
	w.u8(r.CanonicalOutcome)
	writeGeneratorDescriptor(&w, r.ChangedSubjects)
	w.u64(r.WarningBits)
	for _, count := range r.SummaryCounts {
		w.u32(count)
	}
	w.u32(r.AcknowledgedCount)
	w.u32(r.ConfirmedCount)
	w.u32(r.UnknownCount)
	w.u8(r.AdministrativeTargetKind)
	w.id(r.AdministrativeTargetID)
	w.id(r.AdministrativeDisposition)
	w.u16(r.AdministrativeOriginalEvidence)
	w.u8(r.AdministrativeWarningChanges)
	w.u16(uint16(r.AdministrativePageDelta))
	w.u64(uint64(r.AdministrativeByteDelta))
	for _, descriptor := range []GeneratorDescriptor{v.ChangedAccess, v.Effects, v.Outputs, v.Duties, v.Hazards} {
		writeGeneratorDescriptor(&w, descriptor)
	}
	w.id(r.AdministrativeGroupID)
	return GeneratorDescriptor{Digest: generatorDigest("complete-result", w.b), Length: uint64(len(w.b)), Count: 1}, nil
}

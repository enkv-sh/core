package contract

import "bytes"

const GenesisIdentityPlanLimit = 16 << 10

// GenesisIdentityPlanCore fixes the complete deterministic empty initialization
// construction. The receipt request identity and complete-result digest are
// typed holes; no actual ROOT, HEAD or proof digest enters this projection.
type GenesisIdentityPlanCore struct {
	DomainID, DescriptorDigest ID
	IdentityPlan               IdentityPlan
	RecoveryMode               uint8
	K3ChallengeID              ID
	Probes                     []InitProbePlanRow
}

// GenesisReceiptFields describes the fixed proof-free success template. Its
// absent request identity and result commitment make it invalid as a receipt.
func GenesisReceiptFields(domain, operation, revision ID) (CompactMutationReceipt, error) {
	changed, err := ChangedSubjectDescriptor(nil)
	if err != nil || !publicIDsValid(domain, operation, revision) {
		return CompactMutationReceipt{}, ErrRecord
	}
	return CompactMutationReceipt{Schema: MutationReceiptSchema, OperationKind: OperationInitializeDomain,
		StateResult: ReceiptStateSuccess, EffectSummary: ReceiptEffectNoChange,
		OutputSummary: ReceiptOutputNotApplicable, EvidenceCeiling: ReceiptEvidenceCanonical,
		DomainID: domain, OperationID: operation, RequestedRevisionID: revision, ObservedRevisionID: revision,
		CanonicalOutcome: ReceiptCanonicalSelected, ChangedSubjects: changed}, nil
}

func EncodeGenesisIdentityPlanCore(v GenesisIdentityPlanCore) ([]byte, error) {
	if !publicIDsValid(v.DomainID, v.DescriptorDigest) || len(v.IdentityPlan.Rows) != 0 ||
		len(v.IdentityPlan.Pages) < 4 || len(v.IdentityPlan.Pages) > MaxRecipientPages+3 ||
		v.RecoveryMode > 1 || (v.RecoveryMode == 0) != v.K3ChallengeID.IsZero() ||
		len(v.Probes) != 1+int(v.RecoveryMode) || !initProbesValid(v.Probes) {
		return nil, ErrRecord
	}
	identity, err := EncodeIdentityPlan(v.IdentityPlan)
	if err != nil {
		return nil, err
	}
	output, err := EncodeOutputConfiguration(OutputConfiguration{Schema: OutputConfigurationSchema, DomainID: v.DomainID})
	if err != nil {
		return nil, err
	}
	receipt, err := GenesisReceiptFields(v.DomainID, v.IdentityPlan.Operation, v.IdentityPlan.Revision)
	if err != nil {
		return nil, err
	}
	// The known complete-result length/count remain fixed. Only its digest and
	// the request identity are absent until the normalized request is fixed.
	receipt.CompleteResult = GeneratorDescriptor{Length: 8 + MutationResultProjectionLength, Count: 1}
	w := cryptoWriter{b: []byte(cryptoPurposePrefix + "genesis-identity-plan-v1\x00")}
	w.u16(CanonicalSchema)
	w.u16(GenesisProfile)
	w.id(v.DomainID)
	w.id(v.DescriptorDigest)
	w.blob(identity)
	w.u8(v.RecoveryMode)
	w.id(v.K3ChallengeID)
	w.u8(uint8(len(v.Probes)))
	for _, probe := range v.Probes {
		writeInitProbe(&w, probe)
	}
	// These fixed tags bind create-only semantics and the result interpretation.
	w.raw([]byte("HEAD-ABSENT\x00ProductResult/v1\x00InitPayload/v1\x00"))
	w.blob(output)
	w.raw([]byte("receipt-request-identity-hole\x00receipt-complete-result-digest-hole\x00"))
	writeCompactMutationReceipt(&w, receipt)
	if len(w.b) > GenesisIdentityPlanLimit {
		return nil, ErrRecordCapacity
	}
	return w.b, nil
}

func DecodeGenesisIdentityPlanCore(b []byte) (GenesisIdentityPlanCore, error) {
	if len(b) > GenesisIdentityPlanLimit {
		return GenesisIdentityPlanCore{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	prefix := []byte(cryptoPurposePrefix + "genesis-identity-plan-v1\x00")
	if !bytes.Equal(r.take(len(prefix)), prefix) || r.u16() != CanonicalSchema || r.u16() != GenesisProfile {
		return GenesisIdentityPlanCore{}, ErrRecord
	}
	v := GenesisIdentityPlanCore{DomainID: r.requiredID(), DescriptorDigest: r.requiredID()}
	identity := r.blob(GenesisIdentityPlanLimit)
	v.RecoveryMode, v.K3ChallengeID = r.u8(), r.id()
	count := int(r.u8())
	if count < 1 || count > 2 || r.err != nil {
		return GenesisIdentityPlanCore{}, ErrRecord
	}
	for i := 0; i < count; i++ {
		v.Probes = append(v.Probes, readInitProbe(&r))
	}
	var err error
	v.IdentityPlan, err = DecodeIdentityPlan(identity)
	if err != nil {
		return GenesisIdentityPlanCore{}, err
	}
	// Re-encoding also checks the fixed result template and every named hole;
	// there is no second parser that can admit arbitrary receipt fields.
	encoded, err := EncodeGenesisIdentityPlanCore(v)
	if err != nil || !bytes.Equal(encoded, b) {
		return GenesisIdentityPlanCore{}, ErrRecord
	}
	return v, nil
}

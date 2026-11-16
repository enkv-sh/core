package core

import (
	"encoding/binary"

	"enkv.sh/core/contract"
)

type ReplacementReadOperation string

const (
	ReplacementObserve             ReplacementReadOperation   = "keys-replace-observe"
	ReplacementReceipt             ReplacementReadOperation   = "keys-replace-receipt"
	ReplacementRootLossUnsupported contract.ReaderStateResult = "root-loss-unsupported"
)

type ReplacementQueryIdentity struct {
	Schema                                                                                          string
	Operation                                                                                       ReplacementReadOperation
	SemanticOperation                                                                               uint16
	ExpectedDomain, StoreID, CoordinateID, NonBodyID, StoreDescriptorDigest                         contract.ID
	SourceBasisDigest, SuccessorBasisDigest, AuthenticatedBasisDigest                               contract.ID
	SourcePins, OutputPins                                                                          AdministrativeSourcePins
	Observation                                                                                     *AdministrativeObservation
	RequestNonce                                                                                    contract.ID
	Target                                                                                          ReplacementTarget
	RequiredStoredKind                                                                              uint16
	Goal                                                                                            RoleReplacementGoal
	OriginalOperationID, OriginalRequestIdentity, CandidateDigest, RequestedRevisionID, RecipientID contract.ID
	Digest                                                                                          contract.ID
}
type ReplacementCurrentSelection struct {
	RequestedControl, CurrentControl         contract.ControlCore
	SuccessorSourceUsable, CandidateSelected bool
	EvidenceLimit                            string
}
type ReplacementReceiptObservation struct {
	Receipt           contract.CompactMutationReceipt
	ReceiptBytes      []byte
	CandidateSelected bool
	EvidenceLimit     string
}
type PublicReplacementObservationResult struct {
	Operation                                         ReplacementReadOperation
	Target                                            ReplacementTarget
	UnderlyingOperation                               uint16
	RequestID, OperationID, RequestIdentity, DomainID contract.ID
	PreAdmission                                      *PreAdmissionRequestIdentity
	Query                                             *ReplacementQueryIdentity
	Result                                            Result
	StateResult                                       contract.ReaderStateResult
	CurrentWarningBits                                uint8
	Selection                                         *ReplacementCurrentSelection
	Receipt                                           *ReplacementReceiptObservation
	Correlation                                       ReplacementCorrelation
}

func replacementReadOperation(target ReplacementTarget) (ReplacementReadOperation, uint16, uint16, bool) {
	switch target {
	case ReplacementTargetAuthority:
		return ReplacementObserve, 15, contract.OperationReplaceAuthorityKeys, true
	case ReplacementTargetRecovery:
		return ReplacementReceipt, 16, contract.OperationReplaceRecoveryKeysAndRoot, true
	case ReplacementTargetRecipient:
		return ReplacementReceipt, 16, contract.OperationRotateRecipientKeyBinding, true
	}
	return "", 0, 0, false
}
func replacementReadResult(result Result) Result {
	if result.Outcome == Contention {
		result.Outcome = EvidenceUnavailable
	}
	return result
}
func replacementReadState(result Result) contract.ReaderStateResult {
	switch result.Outcome {
	case ObservedCurrent:
		return contract.ReaderSuccess
	case IntegrityFailure:
		return contract.ReaderPositiveDefect
	case RootLossUnsupported:
		return ReplacementRootLossUnsupported
	case EvidenceUnavailable:
		return contract.ReaderUnavailable
	case Contention:
		return contract.ReaderUnavailable
	default:
		return contract.ReaderRefused
	}
}
func (q ReplacementQueryIdentity) digest() (contract.ID, bool) {
	op, semantic, stored, ok := replacementReadOperation(q.Target)
	if !ok || q.Schema != "QueryRequestIdentity/v1" || q.Operation != op || q.SemanticOperation != semantic || q.ExpectedDomain.IsZero() || q.StoreID.IsZero() || q.CoordinateID.IsZero() || q.NonBodyID.IsZero() || q.StoreDescriptorDigest.IsZero() || q.SourceBasisDigest.IsZero() || q.SuccessorBasisDigest.IsZero() || !q.SourcePins.Valid() || !q.OutputPins.Valid() || q.SourcePins.FileID != q.OutputPins.FileID || q.RequestNonce.IsZero() || q.OriginalOperationID.IsZero() || q.OriginalRequestIdentity.IsZero() || q.CandidateDigest.IsZero() || q.RequestedRevisionID.IsZero() {
		return contract.ID{}, false
	}
	if semantic == 15 {
		if q.RequiredStoredKind != 0 {
			return contract.ID{}, false
		}
	} else if q.RequiredStoredKind != stored {
		return contract.ID{}, false
	}
	if (q.Target == ReplacementTargetRecipient) != (!q.RecipientID.IsZero()) || len(q.Goal.SigningSelector) > contract.MaxKeySelector || len(q.Goal.EncryptionSelector) > contract.MaxKeySelector {
		return contract.ID{}, false
	}
	if q.Observation != nil && (q.AuthenticatedBasisDigest.IsZero() || q.Observation.DomainID != q.ExpectedDomain || q.Observation.Revision.IsZero() || q.Observation.Snapshot.IsZero()) {
		return contract.ID{}, false
	}
	if q.SourcePins.Format != q.OutputPins.Format || !q.SourcePins.HasGenerated || !q.OutputPins.HasGenerated || q.Goal.ApprovalRole != contract.NormalSigningRole && q.Goal.ApprovalRole != contract.RecoverySigningRole || q.Goal.SigningSelector == "" && q.Goal.EncryptionSelector == "" {
		return contract.ID{}, false
	}
	if q.Goal.EncryptionSelector == "" {
		if q.Goal.MaterialSource != 0 {
			return contract.ID{}, false
		}
	} else if q.Goal.MaterialSource != ReplacementMaterialAuthority && q.Goal.MaterialSource != ReplacementMaterialRecovery {
		return contract.ID{}, false
	}
	if q.Target == ReplacementTargetRecipient && (q.Goal.SigningSelector != "" || q.Goal.ApprovalRole != contract.NormalSigningRole || q.Goal.MaterialSource != ReplacementMaterialAuthority) {
		return contract.ID{}, false
	}
	body := []byte("ENKV/replacement-query/v1\x00")
	body = binary.LittleEndian.AppendUint16(body, q.SemanticOperation)
	body = append(body, byte(q.Target))
	body = binary.LittleEndian.AppendUint16(body, uint16(len(q.Operation)))
	body = append(body, q.Operation...)
	for _, id := range []contract.ID{q.ExpectedDomain, q.StoreID, q.CoordinateID, q.NonBodyID, q.StoreDescriptorDigest, q.SourceBasisDigest, q.SuccessorBasisDigest, q.AuthenticatedBasisDigest} {
		body = append(body, id[:]...)
	}
	for _, pins := range []AdministrativeSourcePins{q.SourcePins, q.OutputPins} {
		for _, id := range []contract.ID{pins.FileID, pins.EditableDigest, pins.GeneratedDigest} {
			body = append(body, id[:]...)
		}
		body = append(body, pins.Format)
		body = binary.LittleEndian.AppendUint64(body, pins.EditableLength)
		body = binary.LittleEndian.AppendUint64(body, pins.GeneratedLength)
		if pins.HasGenerated {
			body = append(body, 1)
		} else {
			body = append(body, 0)
		}
	}
	if q.Observation == nil {
		body = append(body, 0)
	} else {
		body = append(body, 1)
		for _, id := range []contract.ID{q.Observation.DomainID, q.Observation.Revision, q.Observation.Snapshot} {
			body = append(body, id[:]...)
		}
	}
	for _, id := range []contract.ID{q.RequestNonce, q.OriginalOperationID, q.OriginalRequestIdentity, q.CandidateDigest, q.RequestedRevisionID, q.RecipientID} {
		body = append(body, id[:]...)
	}
	body = binary.LittleEndian.AppendUint16(body, q.RequiredStoredKind)
	body = append(body, q.Goal.ApprovalRole, byte(q.Goal.MaterialSource))
	for _, selector := range []string{q.Goal.SigningSelector, q.Goal.EncryptionSelector} {
		body = binary.LittleEndian.AppendUint16(body, uint16(len(selector)))
		body = append(body, selector...)
	}
	return contract.Hash(body), true
}

// Valid checks the closed query's complete self-consistency. It grants no
// operation authority, replay right or currentness proof.
func (q ReplacementQueryIdentity) Valid() bool {
	digest, valid := q.digest()
	return valid && digest == q.Digest
}

package core

import (
	"context"
	"encoding/binary"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

const (
	ReceiptListOperation      = "receipt-list"
	ReceiptDetailOperation    = "receipt-detail"
	InspectOperation          = "inspect"
	InspectRecipientOperation = "inspect-recipient"
	InspectCapacityOperation  = "inspect-capacity"
	GCPlanOperation           = "gc-plan"
	gcPlanValidationOperation = "gc-plan-validation"
)

type PublicObservation struct {
	DomainID, HeadRevisionID, SnapshotID, RootDigest contract.ID
}

type PublicDomainWarnings struct {
	OrphanGeneratedEffect, LateDestructiveEffect, PublicationOrderValue bool
	DiscardedExactEvidence, PossibleStoreGarbage                        bool
}

func publicDomainWarnings(bits uint8) PublicDomainWarnings {
	return PublicDomainWarnings{bits&WarningOrphanGeneratedEffect != 0, bits&WarningLateDestructiveEffect != 0,
		bits&WarningPublicationOrderValue != 0, bits&WarningDiscardedExactEvidence != 0, bits&WarningPossibleStoreGarbage != 0}
}

type PublicQueryStateResult string

const (
	PublicQuerySuccess        PublicQueryStateResult = "success"
	PublicQueryRefused        PublicQueryStateResult = "refused"
	PublicQueryUnavailable    PublicQueryStateResult = "unavailable"
	PublicQueryPositiveDefect PublicQueryStateResult = "positive-defect"
	PublicQueryContention     PublicQueryStateResult = "contention"
	PublicQueryProfileBlocked PublicQueryStateResult = "profile-blocked"
	PublicQueryRootLoss       PublicQueryStateResult = "root-loss-unsupported"
)

type PublicQueryResult struct {
	Operation                                         string
	RequestID, OperationID, RequestIdentity, DomainID contract.ID
	Result                                            Result
	StateResult                                       PublicQueryStateResult
	FailureReason                                     contract.DiagnosticReason
	// Optional local parser identity; it grants no query or replay authority.
	PreAdmission *PreAdmissionRequestIdentity
}

func publicQueryState(result Result, reason contract.DiagnosticReason) PublicQueryStateResult {
	switch result.Outcome {
	case ObservedCurrent:
		return PublicQuerySuccess
	case EvidenceUnavailable:
		return PublicQueryUnavailable
	case IntegrityFailure:
		return PublicQueryPositiveDefect
	case Contention:
		return PublicQueryContention
	case RootLossUnsupported:
		return PublicQueryRootLoss
	}
	if reason == contract.ReasonUnsupportedProfile || reason == contract.ReasonUnsupportedSchema {
		return PublicQueryProfileBlocked
	}
	return PublicQueryRefused
}

// PublicQueryBasis contains the common fixed source and observation facts.
// Each operation owns a separate typed selector and result.
type PublicQueryBasis struct {
	Schema, Operation                                string
	SemanticOperation                                uint16
	ExpectedDomain, StoreID, CoordinateID, NonBodyID contract.ID
	StoreDescriptorDigest, PublicBasisDigest         contract.ID
	SourcePins                                       AdministrativeSourcePins
	RequestNonce                                     contract.ID
	Observation                                      *PublicObservation
}

func newPublicQueryBasis(reader *ReaderEngine, pins AdministrativeSourcePins, operation string, semantic uint16, nonce contract.ID) (PublicQueryBasis, bool) {
	if reader == nil {
		return PublicQueryBasis{}, false
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	basisDigest, reason := readerPublicBasisDigest(reader.publicBasis, reader.expectedDomain, reader.expectedStore)
	if reason != "" {
		return PublicQueryBasis{}, false
	}
	q := PublicQueryBasis{Schema: "QueryRequestIdentity/v1", Operation: operation, SemanticOperation: semantic,
		ExpectedDomain: reader.expectedDomain, StoreID: reader.expectedStore.Identity,
		CoordinateID: reader.expectedStore.Coordinate, NonBodyID: reader.expectedStore.NonBody,
		StoreDescriptorDigest: administrativeStoreDescriptorDigest(reader.expectedStore), PublicBasisDigest: basisDigest,
		SourcePins: pins, RequestNonce: nonce}
	return q, q.valid()
}

func (q PublicQueryBasis) valid() bool {
	if q.Schema != "QueryRequestIdentity/v1" || q.ExpectedDomain.IsZero() || q.StoreID.IsZero() || q.CoordinateID.IsZero() || q.NonBodyID.IsZero() || q.StoreDescriptorDigest.IsZero() || q.PublicBasisDigest.IsZero() || !q.SourcePins.Valid() || q.RequestNonce.IsZero() {
		return false
	}
	if q.Observation != nil && (q.Observation.DomainID != q.ExpectedDomain || q.Observation.HeadRevisionID.IsZero() || q.Observation.SnapshotID.IsZero() || q.Observation.RootDigest.IsZero()) {
		return false
	}
	return (q.Operation == InspectOperation || q.Operation == InspectRecipientOperation) && q.SemanticOperation == 15 ||
		(q.Operation == ReceiptListOperation || q.Operation == ReceiptDetailOperation) && q.SemanticOperation == 16 ||
		q.Operation == InspectCapacityOperation && q.SemanticOperation == 30 || q.Operation == GCPlanOperation && q.SemanticOperation == 40
}

func (q PublicQueryBasis) identityBytes(selector contract.ID) ([]byte, bool) {
	if !q.valid() || selector.IsZero() != (q.Operation == InspectOperation || q.Operation == ReceiptListOperation || q.Operation == InspectCapacityOperation) {
		return nil, false
	}
	body := []byte("ENKV/public-query/v1\x00")
	body = binary.LittleEndian.AppendUint16(body, q.SemanticOperation)
	body = binary.LittleEndian.AppendUint16(body, uint16(len(q.Operation)))
	body = append(body, q.Operation...)
	for _, id := range []contract.ID{q.ExpectedDomain, q.StoreID, q.CoordinateID, q.NonBodyID, q.StoreDescriptorDigest, q.PublicBasisDigest, q.SourcePins.FileID, q.SourcePins.EditableDigest, q.SourcePins.GeneratedDigest} {
		body = append(body, id[:]...)
	}
	body = append(body, q.SourcePins.Format)
	body = binary.LittleEndian.AppendUint64(body, q.SourcePins.EditableLength)
	body = binary.LittleEndian.AppendUint64(body, q.SourcePins.GeneratedLength)
	if q.SourcePins.HasGenerated {
		body = append(body, 1)
	} else {
		body = append(body, 0)
	}
	body = append(body, q.RequestNonce[:]...)
	body = append(body, selector[:]...)
	if q.Observation == nil {
		body = append(body, 0)
	} else {
		body = append(body, 1)
		for _, id := range []contract.ID{q.Observation.DomainID, q.Observation.HeadRevisionID, q.Observation.SnapshotID, q.Observation.RootDigest} {
			body = append(body, id[:]...)
		}
	}
	return body, true
}

func (q PublicQueryBasis) digest(selector contract.ID) (contract.ID, bool) {
	body, ok := q.identityBytes(selector)
	if !ok {
		return contract.ID{}, false
	}
	return contract.Hash(body), true
}

func publicQueryOperationID(identity contract.ID) contract.ID {
	return contract.Hash(append([]byte("ENKV/public-query-operation/v1\x00"), identity[:]...))
}

// Admission keeps the invocation's original binding after the result gains its
// observation identity. An interrupted callback cannot replace that failure.
func publicQueryFailure(ctx context.Context, inv *readerInvocation, failed readerFailure) readerFailure {
	if inv != nil {
		if reason := inv.admission.failure(ctx, inv.admission.operation, inv.admission.request); reason != "" {
			return readerRefusal(reason)
		}
	}
	return failed
}

func setPublicQueryFailure(out *PublicQueryResult, failed readerFailure) {
	out.Result, out.FailureReason = failed.Result, failed.diagnostic
	out.StateResult = publicQueryState(out.Result, out.FailureReason)
}

func finishPublicQueryCall(call *telemetry.Call, out PublicQueryResult) {
	if out.StateResult == PublicQueryRootLoss {
		call.FinishReason(telemetry.ResultRootLossUnsupported, telemetry.DiagnosticReason(out.FailureReason))
		return
	}
	finishReaderCall(call, contract.ReaderStateResult(out.StateResult), out.FailureReason)
}

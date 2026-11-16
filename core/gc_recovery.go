package core

import (
	"context"
	"encoding/binary"

	"enkv.sh/core/contract"
)

func gcObservation(ctx context.Context, source gcPhysicalReader, store contract.Descriptor, domain contract.ID, target contract.GCTarget) (contract.GCTargetDisposition, contract.Reason) {
	key, err := contract.StoreObjectKey(store.Prefix, domain, target.Object)
	if err != nil {
		return contract.GCTargetUnknown, contract.ReasonConstruction
	}
	read := gcReadExact(ctx, source, key, contract.StoreObjectLimit(target.Object))
	if read.Status == contract.ReadMissing {
		if gcQualifiedMissing(read) {
			return contract.GCTargetAbsent, contract.ReasonNone
		}
		return contract.GCTargetUnknown, contract.ReasonMalformed
	}
	if read.Status == contract.ReadOK {
		actual, ok := gcTargetFromRead(domain, store, target.Object, read)
		if !ok {
			return contract.GCTargetUnknown, contract.ReasonMalformed
		}
		if actual == target {
			return contract.GCTargetPending, contract.ReasonNone
		}
		return contract.GCTargetChanged, contract.ReasonCondition
	}
	if read.Status != contract.ReadUnavailable || read.Reason == contract.ReasonNone || read.Reason > contract.ReasonProof {
		return contract.GCTargetUnknown, contract.ReasonMalformed
	}
	return contract.GCTargetUnknown, read.Reason
}

func gcAbsenceEvidence(store contract.Descriptor, plan contract.GCPlan, target contract.GCTarget, ordinal uint32) contract.ID {
	body, err := contract.EncodeGCTarget(target)
	if err != nil {
		return contract.ID{}
	}
	image := []byte("ENKV/GC-ABSENCE/v1\x00")
	profile := administrativeStoreDescriptorDigest(store)
	image = append(image, profile[:]...)
	image = append(image, plan.DomainID[:]...)
	image = append(image, plan.OperationID[:]...)
	image = binary.BigEndian.AppendUint32(image, ordinal)
	image = append(image, body...)
	image = append(image, byte(contract.ReadMissing), byte(contract.ReasonNone))
	return contract.Hash(image)
}
func gcNotSentEvidence(store contract.Descriptor, plan contract.GCPlan, permission *gcDeletePermission, observed contract.GCTargetDisposition, ordinal uint32) contract.ID {
	if permission == nil || !permission.used || !permission.joined || permission.result != (contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport, NotSent: true}) || observed != contract.GCTargetPending || permission.consumed >= contract.GCTransmissionLimit {
		return contract.ID{}
	}
	body, err := contract.EncodeGCTarget(permission.target)
	if err != nil {
		return contract.ID{}
	}
	image := []byte("ENKV/GC-NOT-SENT/v1\x00")
	profile := administrativeStoreDescriptorDigest(store)
	image = append(image, profile[:]...)
	image = append(image, plan.DomainID[:]...)
	image = append(image, plan.OperationID[:]...)
	image = binary.BigEndian.AppendUint32(image, ordinal)
	image = append(image, permission.consumed)
	image = append(image, body...)
	image = append(image, byte(contract.WriteUnknown), byte(contract.ReasonTransport), 1, 1, byte(contract.GCTargetPending))
	return contract.Hash(image)
}

func gcStateResult(result Result) string {
	switch result.Outcome {
	case Contention:
		return "contention"
	case UnresolvedCommit:
		return "commit-outcome-unknown"
	case EvidenceUnavailable:
		return "unavailable"
	case IntegrityFailure:
		return "positive-defect"
	case RootLossUnsupported:
		return "root-loss-unsupported"
	case AdmissionRefused:
		if result.CommitMayHaveOccurred {
			return "commit-outcome-unknown"
		}
		if result.Reason == CapacityExceeded {
			return "snapshot-size-refusal"
		}
	}
	return "refused"
}

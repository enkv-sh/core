package core

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"slices"
	"unicode/utf8"

	"enkv.sh/core/contract"
)

type AdministrativeOperation string

const (
	AdministrativeList       AdministrativeOperation = "abandon-list"
	AdministrativePlan       AdministrativeOperation = "abandon-plan"
	AdministrativeApply      AdministrativeOperation = "abandon-apply"
	AdministrativeReceipt    AdministrativeOperation = "abandon-receipt"
	AdministrativeJSONFormat uint8                   = 1
	AdministrativeYAMLFormat uint8                   = 2
)

// AdministrativeSourcePins bind the captured installed pair. Paths and file
// handles stay with the composition's fixed-source checker.
type AdministrativeSourcePins struct {
	FileID                          contract.ID
	Format                          uint8
	EditableDigest, GeneratedDigest contract.ID
	EditableLength, GeneratedLength uint64
	HasGenerated                    bool
}

func (p AdministrativeSourcePins) Valid() bool {
	return !p.FileID.IsZero() && (p.Format == AdministrativeJSONFormat || p.Format == AdministrativeYAMLFormat) &&
		!p.EditableDigest.IsZero() && p.EditableLength != 0 &&
		(p.HasGenerated && !p.GeneratedDigest.IsZero() && p.GeneratedLength != 0 ||
			!p.HasGenerated && p.GeneratedDigest.IsZero() && p.GeneratedLength == 0)
}

type AdministrativeObservation struct{ DomainID, Revision, Snapshot contract.ID }

type AdministrativeArtifact struct {
	Path   string
	Digest contract.ID
	Length uint64
}

type AdministrativePlanRequest struct {
	TargetGroupID contract.ID
	ArtifactPath  string
}

// Valid reports whether the target and exact path can form a Plan query.
func (r AdministrativePlanRequest) Valid() bool {
	return !r.TargetGroupID.IsZero() && administrativeArtifactPathValid(r.ArtifactPath)
}

type AdministrativePlanPayload struct {
	Preview      EndWorkPreview
	ArtifactPath string
	Artifact     *AdministrativeArtifact
}

type AdministrativeEndPayload struct {
	Preview      EndWorkPreview
	Receipt      contract.CompactMutationReceipt
	ReceiptBytes []byte
}

// AdministrativeQueryIdentity has only the three installed read views. An
// absent Observation records that authentication did not produce an image.
// ArtifactPath precedes I/O; Artifact is a complete commitment issued by Bind.
// Neither form includes local delivery facts or grants mutation replay.
type AdministrativeQueryIdentity struct {
	Schema                                                                                     string
	Operation                                                                                  AdministrativeOperation
	SemanticOperation                                                                          uint16
	ExpectedDomain, StoreID, CoordinateID, NonBodyID, StoreDescriptorDigest, PublicBasisDigest contract.ID
	SourcePins                                                                                 AdministrativeSourcePins
	Observation                                                                                *AdministrativeObservation
	RequestNonce, RequestedOperationID                                                         contract.ID
	RequiredStoredKind                                                                         uint16
	TargetGroupID, PlanIdentity                                                                contract.ID
	ArtifactPath                                                                               string
	Artifact                                                                                   *AdministrativeArtifact
	Digest                                                                                     contract.ID
}

type AdministrativeStateResult string

const (
	AdministrativeSuccess        AdministrativeStateResult = "success"
	AdministrativeWorkEnded      AdministrativeStateResult = "work-ended"
	AdministrativeRefused        AdministrativeStateResult = "refused"
	AdministrativeUnavailable    AdministrativeStateResult = "unavailable"
	AdministrativePositiveDefect AdministrativeStateResult = "positive-defect"
	AdministrativeContention     AdministrativeStateResult = "contention"
	AdministrativeCommitUnknown  AdministrativeStateResult = "commit-outcome-unknown"
	AdministrativeRootLoss       AdministrativeStateResult = "root-loss-unsupported"
	AdministrativeSizeRefusal    AdministrativeStateResult = "snapshot-size-refusal"
)

type administrativePlanIssue struct {
	parent *installedAdministrativeParent
}

// PublicAdministrativeResult owns its semantic facts. Exactly one payload is
// present after successful authentication and operation-specific projection.
// Cleanup and delivery remain separate from the selected mutation fact.
type PublicAdministrativeResult struct {
	planIssue                                         *administrativePlanIssue
	Operation                                         AdministrativeOperation
	RequestID, OperationID, RequestIdentity, DomainID contract.ID
	PreAdmission                                      *PreAdmissionRequestIdentity
	Query                                             *AdministrativeQueryIdentity
	Result                                            Result
	StateResult                                       AdministrativeStateResult
	CurrentWarningBits                                uint8
	List                                              *AuthorityInspection
	Plan                                              *AdministrativePlanPayload
	End                                               *AdministrativeEndPayload
	Receipt                                           *AuthorityAbandonment
}

// AdministrativePublicBasisDigest qualifies the independent basis without
// reading Store or constructing a private capability.
func AdministrativePublicBasisDigest(domain contract.ID, store contract.Descriptor, basis PublicBasis) (contract.ID, error) {
	qualified, reason := qualifyBorrowedReaderPublicBasis(basis, domain, store)
	if reason != "" {
		return contract.ID{}, contract.ErrRecord
	}
	return qualified.digest, nil
}

func administrativeState(operation AdministrativeOperation, result Result) AdministrativeStateResult {
	switch result.Outcome {
	case ObservedCurrent:
		if operation == AdministrativeApply {
			return AdministrativeWorkEnded
		}
		return AdministrativeSuccess
	case Contention:
		return AdministrativeContention
	case UnresolvedCommit:
		return AdministrativeCommitUnknown
	case IntegrityFailure:
		return AdministrativePositiveDefect
	case EvidenceUnavailable:
		return AdministrativeUnavailable
	case RootLossUnsupported:
		return AdministrativeRootLoss
	case AdmissionRefused:
		if operation == AdministrativeApply && result.Reason == CapacityExceeded {
			return AdministrativeSizeRefusal
		}
		return AdministrativeRefused
	default:
		return AdministrativeRefused
	}
}

func appendStoreDescriptorLocation(body []byte, store contract.Descriptor) []byte {
	body = append(body, byte(store.Family))
	body = binary.LittleEndian.AppendUint32(body, uint32(len(store.Prefix)))
	body = append(body, store.Prefix...)
	body = binary.LittleEndian.AppendUint32(body, uint32(len(store.HeadKey)))
	return append(body, store.HeadKey...)
}

func appendStoreDescriptorIDs(body []byte, store contract.Descriptor) []byte {
	for _, id := range []contract.ID{store.Identity, store.Coordinate, store.NonBody} {
		body = append(body, id[:]...)
	}
	return body
}

func administrativeStoreDescriptorDigest(store contract.Descriptor) contract.ID {
	body := appendStoreDescriptorLocation([]byte("ENKV/store-descriptor/v1\x00"), store)
	return contract.Hash(appendStoreDescriptorIDs(body, store))
}

func administrativeArtifactPathValid(path string) bool {
	return path != "/" && len(path) <= 4096 && utf8.ValidString(path) && !bytes.ContainsRune([]byte(path), 0) && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func (q AdministrativeQueryIdentity) digest() (contract.ID, bool) {
	if q.Schema != "QueryRequestIdentity/v1" || q.ExpectedDomain.IsZero() || q.StoreID.IsZero() || q.CoordinateID.IsZero() || q.NonBodyID.IsZero() || q.StoreDescriptorDigest.IsZero() || q.PublicBasisDigest.IsZero() || !q.SourcePins.Valid() || q.RequestNonce.IsZero() {
		return contract.ID{}, false
	}
	if q.Observation != nil && (q.Observation.DomainID != q.ExpectedDomain || q.Observation.Revision.IsZero() || q.Observation.Snapshot.IsZero()) {
		return contract.ID{}, false
	}
	switch q.Operation {
	case AdministrativeList:
		if q.SemanticOperation != 15 || !q.RequestedOperationID.IsZero() || q.RequiredStoredKind != 0 || !q.TargetGroupID.IsZero() || !q.PlanIdentity.IsZero() || q.ArtifactPath != "" || q.Artifact != nil {
			return contract.ID{}, false
		}
	case AdministrativePlan:
		if q.SemanticOperation != 15 || !q.RequestedOperationID.IsZero() || q.RequiredStoredKind != 0 || !(AdministrativePlanRequest{TargetGroupID: q.TargetGroupID, ArtifactPath: q.ArtifactPath}).Valid() || q.Observation == nil && !q.PlanIdentity.IsZero() {
			return contract.ID{}, false
		}
		if q.Artifact != nil && (q.Observation == nil || q.PlanIdentity.IsZero() || q.Artifact.Path != q.ArtifactPath || q.Artifact.Digest.IsZero() || q.Artifact.Length == 0) {
			return contract.ID{}, false
		}
	case AdministrativeReceipt:
		if q.SemanticOperation != 16 || q.RequestedOperationID.IsZero() || q.RequiredStoredKind != contract.OperationEndSelectedWork || !q.TargetGroupID.IsZero() || !q.PlanIdentity.IsZero() || q.ArtifactPath != "" || q.Artifact != nil {
			return contract.ID{}, false
		}
	default:
		return contract.ID{}, false
	}
	body := []byte("ENKV/administrative-query/v1\x00")
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
	if q.Observation != nil {
		body = append(body, 1)
		for _, id := range []contract.ID{q.Observation.DomainID, q.Observation.Revision, q.Observation.Snapshot} {
			body = append(body, id[:]...)
		}
	} else {
		body = append(body, 0)
	}
	for _, id := range []contract.ID{q.RequestNonce, q.RequestedOperationID} {
		body = append(body, id[:]...)
	}
	body = binary.LittleEndian.AppendUint16(body, q.RequiredStoredKind)
	for _, id := range []contract.ID{q.TargetGroupID, q.PlanIdentity} {
		body = append(body, id[:]...)
	}
	body = binary.LittleEndian.AppendUint16(body, uint16(len(q.ArtifactPath)))
	body = append(body, q.ArtifactPath...)
	if q.Artifact != nil {
		body = append(body, 1)
		body = append(body, q.Artifact.Digest[:]...)
		body = binary.LittleEndian.AppendUint64(body, q.Artifact.Length)
	} else {
		body = append(body, 0)
	}
	return contract.Hash(body), true
}

// Only Plan needs a private retained snapshot. List and Receipt return their
// owned projection directly without duplicating the complete relation backing.
func cloneAdministrativePlanResult(r PublicAdministrativeResult) PublicAdministrativeResult {
	if r.Query != nil {
		q := *r.Query
		r.Query = &q
		if q.Observation != nil {
			v := *q.Observation
			r.Query.Observation = &v
		}
		if q.Artifact != nil {
			v := *q.Artifact
			r.Query.Artifact = &v
		}
	}
	if r.Plan != nil {
		v := *r.Plan
		v.Preview.EndedGroupIDs = slices.Clone(v.Preview.EndedGroupIDs)
		if v.Artifact != nil {
			p := *v.Artifact
			v.Artifact = &p
		}
		r.Plan = &v
	}
	return r
}

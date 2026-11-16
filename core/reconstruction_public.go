package core

import (
	"bytes"
	"context"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// anchoredPublicCandidate contains only bounded public facts. It cannot read
// selected children, admit a caller, decrypt material or mutate the Store.
// The complete closure and authority registry still need independent checks.
type anchoredPublicCandidate struct {
	failureReason contract.DiagnosticReason
	location      contract.StoreLocation
	configuration contract.StoreConfiguration
	configBody    []byte
	head          format.Head
	headBody      []byte
	headToken     contract.Token
	root          format.Root
	rootBody      []byte
	anchor        qualifiedCandidateAnchor
	deadline      time.Time
	done          <-chan struct{}
}

func candidateReadFailure(read contract.ReadResult, head bool) Result {
	switch read.Status {
	case contract.ReadMissing:
		if head {
			return failure(RootLossUnsupported, MissingSelectedObject)
		}
		return failure(EvidenceUnavailable, MissingSelectedObject)
	case contract.ReadUnavailable:
		return unavailableStoreRead(read)
	default:
		return failure(IntegrityFailure, InvalidFormat)
	}
}

// anchorPublicCandidate reads only the fixed public candidate set and checks
// that its selected signing proof is qualified by an independently configured
// public resource. The location comes from the same reader that issued GETs;
// no caller may pair an unrelated asserted location with those bytes.
func anchorPublicCandidate(ctx context.Context, source candidateReadSource, expectedDomain contract.ID,
	normal, recovery candidateSigningQualifier) (anchoredPublicCandidate, Result) {
	var empty anchoredPublicCandidate
	if ctx == nil || ctx.Err() != nil || source == nil || normal == nil && recovery == nil {
		return empty, refused(AdmissionInvalid)
	}
	location := source.CandidateLocation()
	if !contract.StoreLocationValid(location) {
		return empty, refused(AdmissionInvalid)
	}
	headr := readCandidateHEAD(ctx, source)
	if headr.Status != contract.ReadOK {
		return empty, candidateReadFailure(headr, true)
	}
	if headr.Token.Family != location.Provider {
		return empty, failure(IntegrityFailure, ConstructionMismatch)
	}
	h, err := format.DecodeHead(headr.Body)
	if err != nil {
		return anchoredPublicCandidate{failureReason: contract.ReasonHeadInvalid}, failure(IntegrityFailure, InvalidFormat)
	}
	if !expectedDomain.IsZero() && h.Core.Domain != expectedDomain {
		return anchoredPublicCandidate{failureReason: contract.ReasonDomainBasisInvalid}, failure(IntegrityFailure, ConstructionMismatch)
	}
	configr := readCandidateConfiguration(ctx, source, h.Core.Domain, h.Core.Store)
	if configr.Status != contract.ReadOK {
		return empty, candidateReadFailure(configr, false)
	}
	if configr.Token.Family != location.Provider {
		return empty, failure(IntegrityFailure, ConstructionMismatch)
	}
	configuration, err := contract.DecodeStoreConfiguration(configr.Body)
	if err != nil {
		return empty, failure(IntegrityFailure, InvalidFormat)
	}
	canonical, err := contract.EncodeStoreConfiguration(configuration)
	if err != nil || !bytes.Equal(canonical, configr.Body) || configuration.DomainID != h.Core.Domain ||
		configuration.Provider != location.Provider || configuration.Region != location.Region ||
		configuration.Bucket != location.Bucket || configuration.PrefixBeforeHEAD != location.PrefixBeforeHEAD ||
		location.ExpectedOwner != "" && configuration.ExpectedOwner != location.ExpectedOwner {
		return empty, failure(IntegrityFailure, ConstructionMismatch)
	}
	if h.Core.Root.Domain != h.Core.Domain {
		return empty, failure(IntegrityFailure, InvalidReference)
	}
	rootr := readCandidateRoot(ctx, source, h.Core.Root)
	if rootr.Status != contract.ReadOK {
		return empty, candidateReadFailure(rootr, false)
	}
	if rootr.Token.Family != location.Provider {
		return empty, failure(IntegrityFailure, ConstructionMismatch)
	}
	root, err := format.DecodeRoot(rootr.Body)
	if err != nil || root.Domain != h.Core.Domain || root.Snapshot != h.Core.Root.Object {
		return empty, failure(IntegrityFailure, InvalidReference)
	}
	anchor, result := qualifyCandidateSelection(ctx, h, root, normal, recovery)
	if result.Outcome != 0 {
		return empty, result
	}
	if location.Provider == contract.AWS {
		guarded, ok := source.(guardedCandidateHEADSource)
		if !ok {
			return empty, refused(AdmissionInvalid)
		}
		if ctx.Err() != nil {
			return empty, failure(EvidenceUnavailable, ReadUnavailable)
		}
		checked := ownCandidateRead(guarded.ReadHEADGuarded(ctx, configuration.ExpectedOwner), contract.MaxHeadLength, nil, 0)
		if ctx.Err() != nil {
			return empty, failure(EvidenceUnavailable, ReadUnavailable)
		}
		if checked.Status != contract.ReadOK {
			return empty, candidateReadFailure(checked, false)
		}
		if checked.Token != headr.Token || !bytes.Equal(checked.Body, headr.Body) {
			return empty, failure(Contention, DifferentSelection)
		}
	}
	deadline, _ := ctx.Deadline()
	return anchoredPublicCandidate{location: location, configuration: configuration, configBody: configr.Body,
		head: h, headBody: headr.Body, headToken: headr.Token, root: root, rootBody: rootr.Body, anchor: anchor,
		deadline: deadline, done: ctx.Done()}, Result{}
}

package core

import (
	"bytes"
	"context"

	"enkv.sh/core/contract"
)

// candidateReadSource has GET reach only to the three public objects needed
// before independent selection verification. Its results are untrusted. It is
// neither a Store nor an ordinary admission source.
type PublicCandidateReader interface {
	CandidateLocation() contract.StoreLocation
	ReadHEAD(context.Context) contract.ReadResult
	ReadConfiguration(context.Context, contract.ID, contract.ID) contract.ReadResult
	ReadRoot(context.Context, contract.Ref) contract.ReadResult
}

type candidateReadSource = PublicCandidateReader

// AWS can begin with an independently supplied owner. Otherwise Core calls
// this only with the owner from a verified StoreConfiguration. The provider
// applies the guard; it does not decide whether Core authenticated the owner.
type guardedCandidateHEADSource interface {
	candidateReadSource
	ReadHEADGuarded(context.Context, string) contract.ReadResult
}

// Keep candidate bytes stable across the next public read. Bounded candidate
// data does not become a qualified current basis or an OpenContext here.
func ownCandidateRead(result contract.ReadResult, maximum uint32, digest *contract.ID, length uint32) contract.ReadResult {
	if result.Status != contract.ReadOK {
		if result.Status != contract.ReadMissing && result.Status != contract.ReadUnavailable && result.Status != contract.ReadInvalid {
			return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}
		}
		result.Body = nil
		result.Token = contract.Token{}
		return result
	}
	if result.Reason != contract.ReasonNone || !result.Token.Valid() || len(result.Body) == 0 || uint64(len(result.Body)) > uint64(maximum) ||
		length != 0 && uint64(len(result.Body)) != uint64(length) ||
		digest != nil && contract.Hash(result.Body) != *digest {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}
	}
	result.Body = bytes.Clone(result.Body)
	return result
}

func readCandidateHEAD(ctx context.Context, source candidateReadSource) contract.ReadResult {
	if ctx == nil || source == nil {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	if ctx.Err() != nil {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}
	}
	result := source.ReadHEAD(ctx)
	if ctx.Err() != nil {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}
	}
	return ownCandidateRead(result, contract.MaxHeadLength, nil, 0)
}

func readCandidateConfiguration(ctx context.Context, source candidateReadSource, domain, storeID contract.ID) contract.ReadResult {
	if ctx == nil || source == nil || domain.IsZero() || storeID.IsZero() {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	if ctx.Err() != nil {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}
	}
	result := source.ReadConfiguration(ctx, domain, storeID)
	if ctx.Err() != nil {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}
	}
	return ownCandidateRead(result, contract.MaxStoreConfigurationLength, &storeID, 0)
}

func readCandidateRoot(ctx context.Context, source candidateReadSource, ref contract.Ref) contract.ReadResult {
	if ctx == nil || source == nil || ref.Kind != contract.RootKind || ref.Index != 0 ||
		!ref.ValidFor(contract.CanonicalSchema) {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	if ctx.Err() != nil {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}
	}
	result := source.ReadRoot(ctx, ref)
	if ctx.Err() != nil {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}
	}
	return ownCandidateRead(result, contract.MaxRootLength, &ref.Digest, ref.Length)
}

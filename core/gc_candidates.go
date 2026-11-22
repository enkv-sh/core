package core

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type gcPageObservation struct {
	targets    []contract.GCTarget
	candidates []contract.GCCandidate
	digest     contract.ID
	next       string
}

// A nominal owner admits one physical callback. It cannot be constructed from
// admittedObjectSource, whose Read already owns a recovery episode.
type gcPhysicalReader struct {
	physical func(context.Context, string, uint32) contract.ReadResult
	deadline time.Time
	done     <-chan struct{}
}

func newGCPhysicalReader(ctx context.Context, source PublicSelectedReader) (gcPhysicalReader, error) {
	if ctx == nil || source == nil {
		return gcPhysicalReader{}, contract.ErrRecord
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return gcPhysicalReader{}, contract.ErrRecord
	}
	return newGCPhysicalRead(ctx, deadline, source.Read)
}

func newGCPhysicalRead(ctx context.Context, expiry time.Time, physical func(context.Context, string, uint32) contract.ReadResult) (gcPhysicalReader, error) {
	if ctx == nil || ctx.Err() != nil || physical == nil {
		return gcPhysicalReader{}, contract.ErrRecord
	}
	if !validPrivateDeadline(expiry) {
		return gcPhysicalReader{}, contract.ErrRecord
	}
	deadline := expiry
	if caller, finite := ctx.Deadline(); finite && caller.Before(deadline) {
		deadline = caller
	}
	if !validPrivateDeadline(deadline) {
		return gcPhysicalReader{}, contract.ErrRecord
	}
	return gcPhysicalReader{physical: physical, deadline: deadline, done: ctx.Done()}, nil
}

// One logical observation uses the same recovery owner as ordinary Store reads.
// The original finite bound applies to the first physical call and all retries.
func gcReadExact(ctx context.Context, source gcPhysicalReader, key string, limit uint32) contract.ReadResult {
	if ctx == nil || ctx.Err() != nil || source.physical == nil || ctx.Done() != source.done || !validPrivateDeadline(source.deadline) {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}
	}
	bounded, cancel := context.WithDeadline(ctx, source.deadline)
	defer cancel()
	result := recoverStoreRead(bounded, &storeEpisode{}, source.deadline, func(callCtx context.Context) contract.ReadResult {
		return source.physical(callCtx, key, limit)
	})
	if bounded.Err() != nil {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}
	}
	if result.Status == contract.ReadUnavailable {
		result.Body = nil
		result.Token = contract.Token{}
	}
	return result
}

func gcObjectBytesValid(domain contract.ID, store contract.Descriptor, object contract.StoreObjectIdentity, body []byte) bool {
	if domain.IsZero() || contract.StoreObjectLimit(object) == 0 || len(body) == 0 || uint64(len(body)) > uint64(contract.StoreObjectLimit(object)) {
		return false
	}
	switch object.Namespace {
	case contract.StorePageObject:
		_, err := format.Reference(object.Kind, domain, object.ObjectID, object.Index, body)
		return err == nil
	case contract.StoreResultObject:
		result, err := contract.InspectGeneratedResultRecord(body)
		if err != nil {
			note, err := contract.InspectRetirementAmbiguity(body)
			if err != nil || note.Domain != domain {
				return false
			}
			id, err := contract.GeneratorRetirementAmbiguityID(note.Inbox)
			return err == nil && id == object.ObjectID
		}
		if result.Core.DomainID != domain {
			return false
		}
		inbox, err := contract.GeneratorInboxID(domain, result.Core.OperationID, result.Core.AttemptID, result.Core.ResultID)
		return err == nil && inbox == object.ObjectID
	case contract.StoreConfigurationObject:
		configuration, err := contract.DecodeStoreConfiguration(body)
		return err == nil && configuration.DomainID == domain && configuration.Provider == store.Family && configuration.PrefixBeforeHEAD == store.Prefix && contract.Hash(body) == object.ObjectID
	}
	return false
}

func gcTargetFromRead(domain contract.ID, store contract.Descriptor, object contract.StoreObjectIdentity, read contract.ReadResult) (contract.GCTarget, bool) {
	if read.Status != contract.ReadOK || read.Reason != contract.ReasonNone || !read.Token.Valid() || read.Token.Family != store.Family ||
		!gcObjectBytesValid(domain, store, object, read.Body) {
		return contract.GCTarget{}, false
	}
	return contract.GCTarget{Object: object, Length: uint32(len(read.Body)), Digest: contract.Hash(read.Body), Token: read.Token}, true
}

func gcQualifiedMissing(read contract.ReadResult) bool {
	return read.Status == contract.ReadMissing && read.Reason == contract.ReasonNone && len(read.Body) == 0 && read.Token == (contract.Token{})
}

func gcObservePage(ctx context.Context, source gcPhysicalReader, store contract.Descriptor, domain, headDigest contract.ID, marks gcMarkSet, input string, page contract.ListPageResult) (gcPageObservation, Result) {
	var out gcPageObservation
	if ctx == nil || source.physical == nil || marks.objects == nil || marks.pending == nil || !gcCursorScopeValid(domain, store) || headDigest.IsZero() || len(input) > contract.GCProviderCursorLimit || !utf8.ValidString(input) {
		return out, refused(AdmissionInvalid)
	}
	if ctx.Err() != nil {
		return out, failure(EvidenceUnavailable, ReadUnavailable)
	}
	if page.Status == contract.ListPageUnavailable {
		return out, unavailableStoreRead(contract.ReadResult{Status: contract.ReadUnavailable, Reason: page.Reason})
	}
	if page.Status != contract.ListPageOK || page.Reason != contract.ReasonNone || len(page.Keys) > contract.StoreListPageEntries || len(page.NextCursor) > contract.GCProviderCursorLimit || !utf8.ValidString(page.NextCursor) {
		return out, failure(IntegrityFailure, InvalidFormat)
	}
	seen := make(map[string]bool, len(page.Keys))
	for _, key := range page.Keys {
		if len(key) == 0 || len(key) > contract.StoreListKeyLength || !utf8.ValidString(key) || seen[key] {
			return gcPageObservation{}, failure(IntegrityFailure, InvalidFormat)
		}
		seen[key] = true
	}
	out.candidates = make([]contract.GCCandidate, 0, len(page.Keys))
	eligible := make(map[contract.StoreObjectIdentity]int)
	targetKeys := make(map[contract.StoreObjectIdentity]string)
	for _, key := range page.Keys {
		if ctx.Err() != nil {
			return gcPageObservation{}, failure(EvidenceUnavailable, ReadUnavailable)
		}
		candidate := contract.GCCandidate{Classification: contract.GCCandidateUnverifiable, TargetIndex: 65535, Reason: contract.GCReasonUnknownKind}
		object, err := contract.ParseStoreObjectKey(store.Prefix, domain, key)
		if err != nil {
			base := store.Prefix + "/" + hex.EncodeToString(domain[:]) + "/"
			if !strings.HasPrefix(key, base) {
				candidate.Reason = contract.GCReasonForeign
			}
			out.candidates = append(out.candidates, candidate)
			continue
		}
		candidate.KeyDigest = contract.Hash([]byte(key))
		candidate.Reason = contract.GCReasonNone
		if _, live := marks.objects[object]; live {
			candidate.Classification = contract.GCCandidateProtected
		} else if _, pending := marks.pending[object]; pending {
			candidate.Classification = contract.GCCandidateAlreadyPending
		} else {
			read := gcReadExact(ctx, source, key, contract.StoreObjectLimit(object))
			switch {
			case gcQualifiedMissing(read):
				candidate.Classification = contract.GCCandidateAbsent
			case read.Status == contract.ReadUnavailable:
				candidate.Reason = contract.GCReasonUnavailable
			case read.Status == contract.ReadOK:
				target, valid := gcTargetFromRead(domain, store, object, read)
				if valid {
					candidate.Classification = contract.GCCandidateEligible
					eligible[object] = len(out.candidates)
					targetKeys[object] = key
					out.targets = append(out.targets, target)
				} else {
					candidate.Reason = contract.GCReasonMalformed
				}
			default:
				candidate.Reason = contract.GCReasonMalformed
			}
		}
		out.candidates = append(out.candidates, candidate)
	}
	slices.SortFunc(out.targets, func(a, b contract.GCTarget) int {
		return strings.Compare(targetKeys[a.Object], targetKeys[b.Object])
	})
	for i, target := range out.targets {
		out.candidates[eligible[target.Object]].TargetIndex = uint16(i)
	}
	h := sha256.New()
	h.Write([]byte("ENKV/GC-ENUMERATION/v1\x00"))
	descriptor := administrativeStoreDescriptorDigest(store)
	h.Write(descriptor[:])
	h.Write(domain[:])
	h.Write(headDigest[:])
	gcHashBlob(h, []byte(input))
	gcHashBlob(h, []byte(page.NextCursor))
	var number [8]byte
	binary.BigEndian.PutUint16(number[:2], uint16(len(page.Keys)))
	h.Write(number[:2])
	for i, key := range page.Keys {
		gcHashBlob(h, []byte(key))
		row := out.candidates[i]
		h.Write(row.KeyDigest[:])
		h.Write([]byte{byte(row.Classification)})
		binary.BigEndian.PutUint16(number[:2], row.TargetIndex)
		h.Write(number[:2])
		h.Write([]byte{byte(row.Reason)})
		binary.BigEndian.PutUint64(number[:], row.ListedLength)
		h.Write(number[:])
	}
	copy(out.digest[:], h.Sum(nil))
	out.next = page.NextCursor
	return out, Result{}
}

func gcValidateTargetMapping(plan contract.GCPlan, store contract.Descriptor) bool {
	if !plan.Valid() || plan.StoreDescriptorDigest != administrativeStoreDescriptorDigest(store) {
		return false
	}
	for _, candidate := range plan.Candidates {
		if candidate.Classification != contract.GCCandidateEligible {
			continue
		}
		key, err := contract.StoreObjectKey(store.Prefix, plan.DomainID, plan.Targets[candidate.TargetIndex].Object)
		if err != nil || candidate.KeyDigest != contract.Hash([]byte(key)) {
			return false
		}
	}
	return true
}

func gcValidateTargets(ctx context.Context, source gcPhysicalReader, store contract.Descriptor, plan contract.GCPlan, marks gcMarkSet) Result {
	if !gcValidateTargetMapping(plan, store) || source.physical == nil || marks.objects == nil || marks.pending == nil {
		return refused(AdmissionInvalid)
	}
	for _, expected := range plan.Targets {
		if _, live := marks.objects[expected.Object]; live {
			return refused(InvalidRelation)
		}
		if _, pending := marks.pending[expected.Object]; pending {
			return refused(InvalidRelation)
		}
		key, err := contract.StoreObjectKey(store.Prefix, plan.DomainID, expected.Object)
		if err != nil {
			return refused(AdmissionInvalid)
		}
		read := gcReadExact(ctx, source, key, contract.StoreObjectLimit(expected.Object))
		if read.Status == contract.ReadUnavailable {
			return unavailableStoreRead(read)
		}
		observed, valid := gcTargetFromRead(plan.DomainID, store, expected.Object, read)
		if !valid || observed != expected {
			return failure(Contention, DifferentSelection)
		}
	}
	return Result{}
}

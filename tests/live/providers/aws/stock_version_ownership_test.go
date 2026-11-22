package core

import (
	"context"
	"encoding/hex"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	records "enkv.sh/core/internal/testrecords"
)

type stockS3ReadOriginal func(context.Context, stockS3Version) (contract.ReadResult, error)

type stockHistoryHead struct {
	core      format.HeadCore
	token     contract.Token
	genesis   bool
	generator *contract.GeneratorAuthoritySubject
}

// Account for every HEAD version between the two independently observed endpoints.
func stockHistoryHeads(ctx context.Context, selected *StateSession, e records.StockPluginEvidence, items []stockS3Version, read stockS3ReadOriginal) (map[contract.ID]stockHistoryHead, error) {
	final := contract.Hash(selected.body)
	if hex.EncodeToString(final[:]) != e.FinalHEAD {
		return nil, errInventory
	}
	heads := make(map[contract.ID]stockHistoryHead)
	for _, item := range items {
		if item.key != selected.store.Descriptor().HeadKey {
			continue
		}
		if item.marker {
			return nil, errInventory
		}
		r, err := read(ctx, item)
		if err != nil {
			return nil, err
		}
		digest := contract.Hash(r.Body)
		head, result := selected.authenticateHeadResponse(ctx, r)
		clear(head.body)
		clear(r.Body)
		if _, exists := heads[digest]; exists || result.Outcome != 0 || r.Reason != contract.ReasonNone || r.Token != item.token || len(r.Body) != int(item.length) || item.latest != (digest == final) || item.latest && item.token != selected.token {
			return nil, errInventory
		}
		heads[digest] = stockHistoryHead{head.head.Core, head.token, head.head.Genesis != nil, head.head.Generator}
	}
	for digest, n := final, 1; n <= len(heads); n++ {
		h, ok := heads[digest]
		if !ok {
			break
		}
		if h.genesis {
			if n == len(heads) && hex.EncodeToString(digest[:]) == e.GenesisHEAD {
				return heads, nil
			}
			break
		}
		before, ok := heads[h.core.PreviousDigest]
		if !ok || before.token != h.core.PreviousToken || before.core.Revision != h.core.PreviousRevision {
			break
		}
		digest = h.core.PreviousDigest
	}
	return nil, errInventory
}

type stockHistoryResult struct {
	released       bool
	inbox, attempt contract.ID
	digest         contract.ID
}

func stockHistoryResults(heads map[contract.ID]stockHistoryHead, e records.StockPluginEvidence) (map[contract.ID]stockHistoryResult, error) {
	results := make(map[contract.ID]stockHistoryResult)
	closed := make(map[string]bool)
	for hash, h := range heads {
		s := h.generator
		if s == nil {
			continue
		}
		switch s.Purpose {
		case contract.GeneratorAuthorityRetireClose:
			at := hex.EncodeToString(hash[:])
			match := false
			for _, ret := range e.Retirements {
				if ret.CloseDigest == at && ret.DutyID == hex.EncodeToString(s.OwnerID[:]) && ret.ResultDigest == hex.EncodeToString(s.ResultDigest[:]) {
					match = true
					break
				}
			}
			if !match {
				return nil, errInventory
			}
			closed[at] = true
		case contract.GeneratorAuthorityInboxRelease:
			if s.BeforePhase != 1 || s.AfterPhase != 2 {
				return nil, errInventory
			}
		case contract.GeneratorAuthorityRecord:
		default:
			continue
		}
		prev := results[s.ResultID]
		if !prev.digest.IsZero() && (prev.digest != s.ResultDigest || prev.attempt != s.AttemptID) {
			return nil, errInventory
		}
		prev.attempt = s.AttemptID
		prev.digest = s.ResultDigest
		if s.Purpose == contract.GeneratorAuthorityInboxRelease {
			if prev.released {
				return nil, errInventory
			}
			prev.released = true
			prev.inbox = s.OwnerID
		}
		results[s.ResultID] = prev
	}
	if len(closed) != len(e.Retirements) || len(results) != len(e.Creates)+len(e.Retirements) {
		return nil, errInventory
	}
	return results, nil
}

func stockHistoryResultMatches(object contract.StoreObjectIdentity, target contract.GCTarget, body []byte, marker bool, signed map[contract.ID]stockHistoryResult, account string, e records.StockPluginEvidence) (int, bool) {
	r, err := contract.InspectGeneratedResultRecord(body)
	if err != nil {
		return 0, false
	}
	s, ok := signed[r.Core.ResultID]
	if !ok || s.digest != target.Digest || s.attempt != r.Core.AttemptID || s.released != marker || marker && s.inbox != object.ObjectID {
		return 0, false
	}
	facts := r.SafeFacts.GeneratorSafeFacts
	if string(facts.Target) != account {
		return 0, false
	}
	id := func(v contract.ID) string { return hex.EncodeToString(v[:]) }
	for i, token := range e.ProviderTokenIDs {
		if string(facts.ResourceData) != token {
			continue
		}
		create, duty, ret := e.Creates[i], e.Duties[i], e.Retirements[i]
		if create.ResourceDigest != id(generatedFactsResourceDigest(facts)) || create.ResourceContractID != id(facts.ResourceContractID) {
			break
		}
		switch r.Disposition() {
		case contract.GeneratorDispositionCompleteCreate:
			if create.OperationID == id(r.Core.OperationID) && create.AttemptID == id(r.Core.AttemptID) && create.ExecutorID == id(r.Core.ExecutorID) && create.DescriptorID == id(r.Core.DescriptorID) && create.ConfigContractID == id(r.Core.ConfigContractID) && create.ResultContractID == id(r.Core.ResultContractID) {
				return 2 * i, true
			}
		case contract.GeneratorDispositionRetirementAcknowledged:
			if marker && ret.ResultDigest == id(target.Digest) && ret.ResultLength == target.Length && duty.ExecutorID == id(r.Core.ExecutorID) && duty.DescriptorID == id(r.Core.DescriptorID) && duty.ResultContractID == id(r.Core.ResultContractID) {
				return 2*i + 1, true
			}
		}
	}
	return 0, false
}

func stockS3QualifyVersions(ctx context.Context, selected *StateSession, input records.StockPluginAcceptanceInput, e records.StockPluginEvidence, items []stockS3Version, read stockS3ReadOriginal) error {
	if selected == nil || len(items) == 0 || len(items) > operatorPrefixObjects || len(e.Creates) != 3 || len(e.Duties) != 3 || len(e.Retirements) != 3 || len(e.ProviderTokenIDs) != 3 {
		return errInventory
	}
	g := selected.root.Generated
	if !g.ActiveOwner.IsZero() || !g.ActiveGraph.IsZero() || !g.ActivePhase.IsZero() || g.GeneratedCurrent != 0 || g.Retiring != 0 || g.Duties != 0 || g.Hazards != 0 {
		return errInventory
	}
	work, err := selected.selectedGeneratedWork(ctx)
	if err != nil {
		return errInventory
	}
	store, domain := selected.store.Descriptor(), selected.root.Domain
	marks, err := gcMarkSelected(work.image, work, store)
	if err != nil || len(marks.pending) != 0 {
		return errInventory
	}
	heads, err := stockHistoryHeads(ctx, selected, e, items, read)
	if err != nil {
		return err
	}
	signed, err := stockHistoryResults(heads, e)
	if err != nil {
		return err
	}
	// A retained mapping still names its original result. Check that binding
	// even when all of its consumers have already finished.
	for _, retained := range work.releases {
		r := retained.release
		s := signed[r.OriginalResultID]
		if r.DomainID != domain || s.digest != r.SelectedHandoffDigest || s.attempt != retained.attempt.AttemptID || s.released || r.ObjectLength == 0 {
			return errInventory
		}
		if err := marks.add(contract.StoreObjectIdentity{Namespace: contract.StoreResultObject, ObjectID: r.InboxID}, r.ObjectLength, r.SelectedHandoffDigest); err != nil {
			return errInventory
		}
	}
	markers := make(map[string]bool)
	for _, item := range items {
		if item.marker {
			obj, err := contract.ParseStoreObjectKey(store.Prefix, domain, item.key)
			if err != nil || obj.Namespace != contract.StoreResultObject || !item.latest || markers[item.key] {
				return errInventory
			}
			markers[item.key] = true
		}
	}
	seen := make(map[contract.StoreObjectIdentity]bool)
	results := make(map[int]bool)
	for _, item := range items {
		if item.marker || item.key == store.HeadKey {
			continue
		}
		obj, err := contract.ParseStoreObjectKey(store.Prefix, domain, item.key)
		if err != nil || seen[obj] || item.latest == markers[item.key] {
			return errInventory
		}
		seen[obj] = true
		r, err := read(ctx, item)
		if err != nil {
			return err
		}
		target, ok := gcTargetFromRead(domain, store, obj, r)
		mark := marks.objects[obj]
		valid := ok && target.Length == item.length && target.Token == item.token && (mark.length == 0 || mark.length == target.Length && mark.digest == target.Digest)
		if valid && obj.Namespace == contract.StoreResultObject {
			index, known := stockHistoryResultMatches(obj, target, r.Body, markers[item.key], signed, input.CloudflareAccount, e)
			valid = known && !results[index]
			results[index] = true
		}
		clear(r.Body)
		if !valid {
			return errInventory
		}
		delete(markers, item.key)
	}
	for obj, mark := range marks.objects {
		if mark.length != 0 && !seen[obj] {
			return errInventory
		}
	}
	if len(results) != 6 || len(markers) != 0 {
		return errInventory
	}
	return nil
}

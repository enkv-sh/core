package core

import (
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func (s *StateSession) successorState() StateSession {
	next := *s
	next.root.GrantPages, next.grantSources = nil, nil
	return next
}

// An existing secret may change encoding, source, content or keys in the
// same declaration. Its new recipients still require a selected grant.
func (c *Comparison) existingSecretGrants(p transitionPlan) (map[contract.ID][]contract.ID, int, error) {
	byMaterial := make(map[contract.ID][]contract.ID)
	count := 0
	if len(c.slots) != len(c.intent) {
		return nil, 0, contract.ErrRecord
	}
	for i, after := range c.intent {
		slot := c.slots[i]
		if int(slot) >= contract.CryptoMaxValueEntries {
			return nil, 0, contract.ErrRecord
		}
		if after.ConfidentialityClass != format.Secret || slices.Contains(c.added, slot) {
			continue
		}
		before := c.session.valueEntry(slot)
		if before == nil || before.Name != after.Name {
			return nil, 0, contract.ErrRecord
		}
		if before.ConfidentialityClass != format.Secret {
			continue
		}
		material, rotated := p.values[slot]
		if !rotated {
			material = before.ValueState
		}
		for _, recipient := range after.Recipients {
			if slices.Contains(before.Recipients, recipient) || !rotated && slices.Contains(c.session.valueReaders[before.ValueState], recipient) {
				continue
			}
			byMaterial[material] = append(byMaterial[material], recipient)
			count++
		}
	}
	if count != 0 && !format.GrantHeadFits(count, len(c.session.token.Value), len(c.session.head.K1), len(c.session.head.K3), false) {
		return nil, 0, contract.ErrRecordCapacity
	}
	return byMaterial, count, nil
}

// A session can publish the ordinary page only after it has observed the
// granting HEAD and reconstructed this exact page. A lost successor CAS can
// leave the page behind because its recipients already have selected access.
func (s *StateSession) persistSelectedGrantPages(ctx context.Context) Result {
	if len(s.root.GrantPages) != len(s.grantSources) {
		return failure(IntegrityFailure, InvalidReference)
	}
	for _, ref := range s.root.CurrentAccess.Core.AccessPageRefs {
		if _, split := s.grantSources[ref]; !split {
			continue
		}
		page := s.access[ref.Index]
		if page == nil {
			return failure(IntegrityFailure, InvalidReference)
		}
		body, err := format.EncodeAccessPage(*page)
		if err != nil || uint64(len(body)) != uint64(ref.Length) || contract.Hash(body) != ref.Digest {
			return failure(IntegrityFailure, InvalidReference)
		}
		key, err := format.Key(s.admission.store.Prefix, ref)
		if err != nil {
			return failure(IntegrityFailure, InvalidReference)
		}
		if result := s.persistImmutable(ctx, key, body, ref.Length); result.Outcome != 0 {
			return result
		}
	}
	return Result{}
}

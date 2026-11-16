package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"hash"
	"maps"
	"slices"

	"enkv.sh/core/contract"
)

// A physical intent projection is private to one authenticated predecessor.
// ValueEntry intent descriptors remain logical and do not change when their
// bytes move to another immutable fragment blob.
type generatedCurrentIntentProjection struct {
	predecessor contract.ID
	before      []contract.GeneratorSliceLocation
	after       []contract.GeneratorSliceLocation
	intents     []contract.ID
	dropBlobs   map[contract.ID]bool
	blob        contract.ID
	total       uint64
	fragments   uint16
	emit        bool
	changed     bool
}

func (p generatedCurrentIntentProjection) equal(q generatedCurrentIntentProjection) bool {
	return p.predecessor == q.predecessor && p.blob == q.blob && p.total == q.total && p.fragments == q.fragments &&
		p.emit == q.emit && p.changed == q.changed && slices.Equal(p.before, q.before) && slices.Equal(p.after, q.after) &&
		slices.Equal(p.intents, q.intents) && maps.Equal(p.dropBlobs, q.dropBlobs)
}

func selectedGeneratedLocations(selected *generatedSelection) []contract.GeneratorSliceLocation {
	locations := make([]contract.GeneratorSliceLocation, 0, len(selected.content.locations))
	for _, location := range selected.content.locations {
		locations = append(locations, location)
	}
	return locations
}

// streamLogical writes an authenticated logical slice without joining its
// containing blob or copying a cross-fragment slice.
func (c *generatedContent) streamLogical(ctx context.Context, kind uint8, id contract.ID, limit uint32, write func([]byte) error, read selectedFragmentRead) (contract.GeneratorSliceLocation, error) {
	if c == nil || write == nil {
		return contract.GeneratorSliceLocation{}, contract.ErrRecord
	}
	if c.fragmentFacts != nil {
		return c.streamSelectedSliceWith(ctx, kind, id, limit, write, read)
	}
	location, ok := c.locations[generatedContentKey{kind: kind, id: id}]
	if !ok || location.Length == 0 || location.Length > limit || location.Offset+uint64(location.Length) < location.Offset {
		return contract.GeneratorSliceLocation{}, contract.ErrRecord
	}
	fragments := c.fragments[location.BlobID]
	if len(fragments) == 0 {
		return contract.GeneratorSliceLocation{}, contract.ErrRecord
	}
	cursor, end := location.Offset, location.Offset+uint64(location.Length)
	logical := sha256.New()
	for _, fragment := range fragments {
		start := uint64(fragment.Offset)
		stop := start + uint64(len(fragment.Payload))
		if stop <= cursor || start >= end {
			continue
		}
		if start > cursor {
			return contract.GeneratorSliceLocation{}, contract.ErrRecord
		}
		last := min(stop, end)
		part := fragment.Payload[cursor-start : last-start]
		if _, err := logical.Write(part); err != nil {
			return contract.GeneratorSliceLocation{}, err
		}
		if err := write(part); err != nil {
			return contract.GeneratorSliceLocation{}, err
		}
		cursor = last
		if cursor == end {
			break
		}
	}
	if cursor != end || !bytes.Equal(logical.Sum(nil), location.Digest[:]) {
		return contract.GeneratorSliceLocation{}, contract.ErrRecord
	}
	return location, nil
}

func selectedGeneratedEntryMetadata(s *StateSession) ([]contract.GeneratedEntryMetadata, error) {
	if s == nil {
		return nil, nil
	}
	entries := make([]contract.GeneratedEntryMetadata, 0, min(len(s.root.Names), contract.GeneratedCurrentEntryLimit))
	for _, name := range s.root.Names {
		entry := s.valueEntry(name.Slot)
		if entry == nil || entry.Name != name.Name {
			return nil, contract.ErrRecord
		}
		if entry.ValueSource != contract.Generated {
			continue
		}
		if len(entries) == contract.GeneratedCurrentEntryLimit {
			return nil, contract.ErrRecordCapacity
		}
		entries = append(entries, entry.Generated)
	}
	return entries, nil
}

func generatedIntentIDs(entries []contract.GeneratedEntryMetadata) ([]contract.ID, error) {
	if len(entries) > contract.GeneratedCurrentEntryLimit {
		return nil, contract.ErrRecordCapacity
	}
	seen := make(map[contract.ID]bool)
	var ids []contract.ID
	for _, entry := range entries {
		id := entry.IntentDigest
		if id.IsZero() {
			return nil, contract.ErrRecord
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	slices.SortFunc(ids, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	return ids, nil
}

// planGeneratedCurrentIntents computes the same physical image for admission
// and construction. retained is an exact subset of the predecessor's selected
// Slice locations after an authenticated work closure; it cannot introduce a
// caller-chosen mapping.

func planGeneratedCurrentIntents(ctx context.Context, s *StateSession, selected *generatedSelection,
	retained []contract.GeneratorSliceLocation) (generatedCurrentIntentProjection, error) {
	if s == nil {
		return generatedCurrentIntentProjection{}, contract.ErrRecord
	}
	entries, err := selectedGeneratedEntryMetadata(s)
	if err != nil {
		return generatedCurrentIntentProjection{}, err
	}
	return planGeneratedCurrentIntentsForEntries(ctx, s, selected, retained, entries)
}

func planGeneratedCurrentIntentsForEntries(ctx context.Context, s *StateSession, selected *generatedSelection,
	retained []contract.GeneratorSliceLocation, entries []contract.GeneratedEntryMetadata) (generatedCurrentIntentProjection, error) {
	var plan generatedCurrentIntentProjection
	if s == nil || selected == nil || selected.session != s || selected.content == nil {
		return plan, contract.ErrRecord
	}
	plan.predecessor = contract.Hash(s.body)
	ids, err := generatedIntentIDs(entries)
	if err != nil {
		return plan, err
	}
	plan.intents = ids
	seen := make(map[generatedContentKey]bool, len(retained))
	for _, location := range retained {
		key := generatedContentKey{kind: location.ContentKind, id: location.ContentID}
		prior, ok := selected.content.locations[key]
		if !ok || seen[key] || prior != location {
			return generatedCurrentIntentProjection{}, contract.ErrRecord
		}
		seen[key] = true
		plan.before = append(plan.before, location)
	}
	slices.SortFunc(plan.before, compareGeneratedLocationKey)
	if len(ids) == 0 {
		plan.after = slices.Clone(plan.before)
		return plan, nil
	}
	plan.dropBlobs = make(map[contract.ID]bool)
	whole := sha256.New()
	for _, id := range ids {
		key := generatedContentKey{kind: contract.GeneratorContentIntent, id: id}
		if !seen[key] {
			return generatedCurrentIntentProjection{}, contract.ErrRecord
		}
		location, err := selected.streamLogical(ctx, key.kind, key.id, contract.GeneratorIntentMaxLength, hashWriter(whole))
		if err != nil {
			return generatedCurrentIntentProjection{}, err
		}
		if plan.total+uint64(location.Length) > contract.GeneratedCurrentEntryLimit*contract.GeneratorIntentMaxLength {
			return generatedCurrentIntentProjection{}, contract.ErrRecordCapacity
		}
		plan.total += uint64(location.Length)
		plan.dropBlobs[location.BlobID] = true
	}
	copy(plan.blob[:], whole.Sum(nil))
	if plan.blob.IsZero() || plan.total == 0 {
		return generatedCurrentIntentProjection{}, contract.ErrRecord
	}
	plan.fragments = uint16((plan.total + contract.GeneratedFragmentMaxPayload - 1) / contract.GeneratedFragmentMaxPayload)
	current := make(map[contract.ID]bool, len(ids))
	for _, id := range ids {
		current[id] = true
	}
	for _, location := range plan.before {
		if location.ContentKind != contract.GeneratorContentIntent || !current[location.ContentID] {
			plan.after = append(plan.after, location)
		}
	}
	var offset uint64
	for _, id := range ids {
		old := selected.content.locations[generatedContentKey{kind: contract.GeneratorContentIntent, id: id}]
		old.BlobID, old.Offset = plan.blob, offset
		plan.after = append(plan.after, old)
		offset += uint64(old.Length)
	}
	slices.SortFunc(plan.after, compareGeneratedLocationKey)
	plan.changed = !slices.Equal(plan.before, plan.after)
	referenced := make(map[contract.ID]bool, len(plan.after))
	for _, location := range plan.after {
		referenced[location.BlobID] = true
	}
	receipt, err := s.receiptIndexID()
	if err != nil {
		return generatedCurrentIntentProjection{}, err
	}
	for blob := range plan.dropBlobs {
		if referenced[blob] || blob == receipt {
			delete(plan.dropBlobs, blob)
		}
	}
	if refs := selected.content.fragmentLocations[plan.blob]; len(refs) != 0 && selected.content.fragmentFacts != nil {
		if len(refs) != int(plan.fragments) {
			return generatedCurrentIntentProjection{}, contract.ErrRecord
		}
		for i, ref := range refs {
			fact, ok := selected.content.fragmentFacts[ref]
			if !ok || fact.blob != plan.blob || fact.index != uint16(i) || fact.count != plan.fragments ||
				fact.total != plan.total || fact.whole != plan.blob || uint64(fact.offset) != uint64(i)*contract.GeneratedFragmentMaxPayload {
				return generatedCurrentIntentProjection{}, contract.ErrRecord
			}
		}
	} else if fragments := selected.content.fragments[plan.blob]; len(fragments) == 0 {
		plan.emit = true
	} else {
		// An existing BlobID is reusable only when it already names the exact
		// compact body. A selected row can carry a well-formed but different
		// physical name; its name alone is not a byte proof.
		if len(fragments) != int(plan.fragments) {
			return generatedCurrentIntentProjection{}, contract.ErrRecord
		}
		verified := sha256.New()
		for i, fragment := range fragments {
			if fragment.BlobID != plan.blob || fragment.Index != uint16(i) || fragment.Count != plan.fragments ||
				fragment.TotalLength != plan.total || fragment.WholeDigest != plan.blob ||
				uint64(fragment.Offset) != uint64(i)*contract.GeneratedFragmentMaxPayload {
				return generatedCurrentIntentProjection{}, contract.ErrRecord
			}
			if _, err := verified.Write(fragment.Payload); err != nil {
				return generatedCurrentIntentProjection{}, err
			}
		}
		if !bytes.Equal(verified.Sum(nil), plan.blob[:]) {
			return generatedCurrentIntentProjection{}, contract.ErrRecord
		}
	}
	return plan, nil
}

func compareGeneratedLocationKey(a, b contract.GeneratorSliceLocation) int {
	if a.ContentKind != b.ContentKind {
		return int(a.ContentKind) - int(b.ContentKind)
	}
	return bytes.Compare(a.ContentID[:], b.ContentID[:])
}

func hashWriter(h hash.Hash) func([]byte) error {
	return func(part []byte) error { _, err := h.Write(part); return err }
}

// emitGeneratedCurrentIntents is the second pass. Only one fragment payload
// is buffered at a time. Its output rows are the successor's retained image,
// not scratch memory.

func emitGeneratedCurrentIntents(ctx context.Context, selected *generatedSelection, plan generatedCurrentIntentProjection) ([]contract.SupportRecord, error) {
	if selected == nil || selected.content == nil || selected.session == nil || contract.Hash(selected.session.body) != plan.predecessor {
		return nil, contract.ErrRecord
	}
	if !plan.changed || !plan.emit {
		return nil, nil
	}
	rows := make([]contract.SupportRecord, 0, plan.fragments)
	whole := sha256.New()
	buffer := make([]byte, 0, contract.GeneratedFragmentMaxPayload)
	var written uint64
	emit := func() error {
		index := uint16(len(rows))
		fragment := contract.GeneratedFragment{Schema: contract.GeneratorRecordSchema, BlobID: plan.blob, Index: index,
			Count: plan.fragments, TotalLength: plan.total, WholeDigest: plan.blob,
			Offset: uint32(uint64(index) * contract.GeneratedFragmentMaxPayload), Payload: buffer}
		body, err := contract.EncodeGeneratedFragment(fragment)
		if err != nil {
			return err
		}
		id, err := contract.GeneratorFragmentID(plan.blob, index)
		if err != nil {
			return err
		}
		rows = append(rows, contract.SupportRecord{Kind: contract.GeneratedFragmentSupportKind, RecordID: id, Body: body})
		buffer = buffer[:0]
		return nil
	}
	write := func(part []byte) error {
		if _, err := whole.Write(part); err != nil {
			return err
		}
		written += uint64(len(part))
		for len(part) != 0 {
			n := min(len(part), contract.GeneratedFragmentMaxPayload-len(buffer))
			buffer = append(buffer, part[:n]...)
			part = part[n:]
			if len(buffer) == contract.GeneratedFragmentMaxPayload {
				if err := emit(); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, id := range plan.intents {
		if _, err := selected.streamLogical(ctx, contract.GeneratorContentIntent, id, contract.GeneratorIntentMaxLength, write); err != nil {
			return nil, err
		}
	}
	if len(buffer) != 0 {
		if err := emit(); err != nil {
			return nil, err
		}
	}
	if written != plan.total || len(rows) != int(plan.fragments) || !bytes.Equal(whole.Sum(nil), plan.blob[:]) {
		return nil, contract.ErrRecord
	}
	return rows, nil
}

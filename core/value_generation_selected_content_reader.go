package core

import (
	"context"
	"crypto/sha256"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type selectedFragmentRead func(context.Context, format.FragmentLocation, func([]byte) error) (Result, error)

// streamSelectedSlice checks one authenticated fragment at a time. A complete
// reader keeps only its selected row facts; the payload exists only while the
// callback runs. In-memory candidate sessions use their selected row bodies.
func (c *generatedContent) streamSelectedSliceWith(ctx context.Context, kind uint8, id contract.ID, limit uint32,
	consume func([]byte) error, read selectedFragmentRead) (contract.GeneratorSliceLocation, error) {
	if c == nil || ctx == nil || consume == nil || c.fragmentFacts != nil && read == nil {
		return contract.GeneratorSliceLocation{}, contract.ErrRecord
	}
	if ctx.Err() != nil {
		return contract.GeneratorSliceLocation{}, selectedReadFailure(failure(EvidenceUnavailable, ReadUnavailable))
	}
	location, ok := c.locations[generatedContentKey{kind, id}]
	if !ok || location.Length > limit {
		return contract.GeneratorSliceLocation{}, contract.ErrRecord
	}
	end := location.Offset + uint64(location.Length)
	if end < location.Offset {
		return contract.GeneratorSliceLocation{}, contract.ErrRecord
	}
	refs := c.fragmentLocations[location.BlobID]
	if len(refs) == 0 {
		return contract.GeneratorSliceLocation{}, contract.ErrRecord
	}
	var total uint64
	var written uint64
	var cursor uint64
	var whole contract.ID
	var expectedTotal uint64
	var expectedWhole contract.ID
	logical := sha256.New()
	for i, ref := range refs {
		if ref.BlobID != location.BlobID || ref.FragmentIndex != uint16(i) {
			return contract.GeneratorSliceLocation{}, contract.ErrRecord
		}
		var start, stop uint64
		var body []byte
		if c.fragmentFacts != nil {
			fact, found := c.fragmentFacts[ref]
			if !found || fact.blob != location.BlobID || fact.index != uint16(i) || int(fact.count) != len(refs) {
				return contract.GeneratorSliceLocation{}, contract.ErrRecord
			}
			start = uint64(fact.offset)
			stop = start + uint64(fact.payloadLength)
			total = fact.total
			whole = fact.whole
		} else {
			fragments := c.fragments[location.BlobID]
			if i >= len(fragments) || fragments[i].Index != uint16(i) || int(fragments[i].Count) != len(refs) {
				return contract.GeneratorSliceLocation{}, contract.ErrRecord
			}
			body = fragments[i].Payload
			start = uint64(fragments[i].Offset)
			stop = start + uint64(len(body))
			total = fragments[i].TotalLength
			whole = fragments[i].WholeDigest
		}
		if i == 0 {
			expectedTotal, expectedWhole = total, whole
		}
		if start != cursor || stop < start || stop > total || whole.IsZero() ||
			total != expectedTotal || whole != expectedWhole {
			return contract.GeneratorSliceLocation{}, contract.ErrRecord
		}
		cursor = stop
		if start >= end || stop <= location.Offset {
			continue
		}
		first, last := max(start, location.Offset), min(stop, end)
		emit := func(payload []byte) error {
			if uint64(len(payload)) != stop-start {
				return contract.ErrRecord
			}
			part := payload[first-start : last-start]
			if _, err := logical.Write(part); err != nil {
				return err
			}
			if err := consume(part); err != nil {
				return err
			}
			written += uint64(len(part))
			return nil
		}
		if c.fragmentFacts != nil {
			result, err := read(ctx, ref, emit)
			if result.Outcome != 0 {
				return contract.GeneratorSliceLocation{}, selectedReadFailure(result)
			}
			if err != nil {
				return contract.GeneratorSliceLocation{}, err
			}
		} else if err := emit(body); err != nil {
			return contract.GeneratorSliceLocation{}, err
		}
	}
	var digest contract.ID
	copy(digest[:], logical.Sum(nil))
	if cursor != total || end > total || written != uint64(location.Length) || digest != location.Digest {
		return contract.GeneratorSliceLocation{}, contract.ErrRecord
	}
	return location, nil
}

// readSelectedSlice makes only the requested bounded logical slice owned.
// It never exposes a Store borrow or joins a containing declaration blob.
func (c *generatedContent) readSelectedSlice(ctx context.Context, kind uint8, id contract.ID, limit uint32,
	read selectedFragmentRead) ([]byte, error) {
	if c == nil {
		return nil, contract.ErrRecord
	}
	location, ok := c.locations[generatedContentKey{kind, id}]
	if !ok || location.Length > limit {
		return nil, contract.ErrRecord
	}
	data := make([]byte, 0, int(location.Length))
	actual, err := c.streamSelectedSliceWith(ctx, kind, id, limit, func(part []byte) error {
		data = append(data, part...)
		return nil
	}, read)
	if err != nil {
		return nil, err
	}
	if actual != location || uint32(len(data)) != location.Length || contract.Hash(data) != location.Digest {
		return nil, contract.ErrRecord
	}
	return data, nil
}

func (c *generatedContent) readSelectedLogicalSlice(ctx context.Context, kind uint8, id contract.ID,
	want contract.GeneratorDescriptor, limit uint32, read selectedFragmentRead) ([]byte, error) {
	location, ok := c.locations[generatedContentKey{kind, id}]
	if !ok {
		return nil, contract.ErrRecord
	}
	descriptor, err := contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{location.Logical()})
	if err != nil || descriptor != want {
		return nil, contract.ErrRecord
	}
	return c.readSelectedSlice(ctx, kind, id, limit, read)
}

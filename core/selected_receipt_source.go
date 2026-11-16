package core

import (
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// supportBlobSelected reads only the requested authenticated blob. Complete
// cold images keep fragment facts, while in-memory candidates still hold rows.
func (s *StateSession) supportBlobSelected(ctx context.Context, id contract.ID, limit uint64) ([]byte, error) {
	if s == nil {
		return nil, contract.ErrRecord
	}
	return selectedSupportBlobWithReader(ctx, s.selectedImage(), s.withSelectedFragment, id, limit)
}

// selectedSupportBlobWithReader preserves current authenticated row reuse and
// reads bodyless fragments through the caller-owned reader.
func selectedSupportBlobWithReader(ctx context.Context, image *selectedImage, read selectedFragmentRead, id contract.ID, limit uint64) ([]byte, error) {
	if image == nil || id.IsZero() || limit == 0 {
		return nil, contract.ErrRecord
	}
	if ctx == nil {
		return nil, contract.ErrRecord
	}
	if ctx.Err() != nil {
		return nil, selectedReadFailure(failure(EvidenceUnavailable, ReadUnavailable))
	}
	if image.fragmentFacts == nil {
		return selectedSupportBlob(image.root, image.support, id, limit)
	}
	root, ok := (&selectedGeneratedProof{selectedImage: image}).generatedSelectionRoot()
	if !ok || image.generatedSlicesRoot != root {
		return nil, contract.ErrRecord
	}
	var data []byte
	var expected contract.ID
	var total uint64
	var count uint16
	for _, location := range image.root.Generated.Fragments {
		if location.BlobID != id {
			continue
		}
		if ctx.Err() != nil {
			return nil, selectedReadFailure(failure(EvidenceUnavailable, ReadUnavailable))
		}
		fact, ok := image.fragmentFacts[location]
		if !ok || fact.index != count || fact.total > limit || uint64(fact.offset) != uint64(len(data)) {
			return nil, contract.ErrRecord
		}
		if count == 0 {
			expected, total = fact.whole, fact.total
			data = make([]byte, 0, int(total))
		} else if fact.whole != expected || fact.total != total {
			return nil, contract.ErrRecord
		}
		var result Result
		var err error
		pagePosition := -1
		for i, page := range image.support {
			if page.Index == location.SupportPageIndex {
				pagePosition = i
				break
			}
		}
		if pagePosition < 0 || int(location.RowSlot) >= len(image.support[pagePosition].Records) {
			return nil, contract.ErrRecord
		}
		page := image.support[pagePosition]
		row := page.Records[location.RowSlot]
		if row.Body != nil {
			encodedRows := make([]contract.SupportRecord, len(page.Records))
			for i, selected := range page.Records {
				encodedRows[i] = contract.SupportRecord(selected)
			}
			body, encodeErr := format.EncodeRequiredSupportPage(format.RequiredSupportPage{
				Domain: page.Domain, Object: page.Object, Index: page.Index, Records: encodedRows})
			if encodeErr != nil || format.CheckReference(image.root.RequiredSupport[pagePosition], body) != nil ||
				pagePosition >= len(image.supportFacts) || image.supportFacts[pagePosition].ref != image.root.RequiredSupport[pagePosition] ||
				int(location.RowSlot) >= len(image.supportFacts[pagePosition].rows) ||
				fact.row != image.supportFacts[pagePosition].rows[location.RowSlot] {
				return nil, contract.ErrRecord
			}
			fragment, inspectErr := contract.InspectGeneratedFragment(row.Body)
			if inspectErr != nil || !fact.matches(fragment) {
				return nil, contract.ErrRecord
			}
			data = append(data, fragment.Payload...)
		} else {
			if read == nil {
				return nil, contract.ErrRecord
			}
			result, err = read(ctx, location, func(part []byte) error {
				data = append(data, part...)
				return nil
			})
		}
		if result.Outcome != 0 {
			return nil, selectedReadFailure(result)
		}
		if err != nil {
			return nil, err
		}
		count++
	}
	if ctx.Err() != nil {
		return nil, selectedReadFailure(failure(EvidenceUnavailable, ReadUnavailable))
	}
	if count == 0 || count != totalFragmentCount(total) || uint64(len(data)) != total || contract.Hash(data) != expected {
		return nil, contract.ErrRecord
	}
	return data, nil
}

func (s *StateSession) receiptWindowsFromSelectedSupport(ctx context.Context) (contract.MutationReceiptWindows, error) {
	return s.receiptWindowsWithBlob(func(id contract.ID, limit uint64) ([]byte, error) {
		return s.supportBlobSelected(ctx, id, limit)
	})
}

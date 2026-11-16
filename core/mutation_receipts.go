package core

import (
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// Only the named mandatory blob is joined. An unrelated optional fragment
// can be unreadable during an administrative end.
func (s *StateSession) administrativeSupportBlob(id contract.ID, limit uint64) ([]byte, error) {
	if s == nil || id.IsZero() || limit == 0 || !s.adminIndex.Valid() {
		return nil, contract.ErrRecord
	}
	var data []byte
	var count uint16
	var whole contract.ID
	var total uint64
	for _, location := range s.root.Generated.Fragments {
		if location.BlobID != id {
			continue
		}
		position := slices.IndexFunc(s.support, func(page format.RequiredSupportPageView) bool { return page.Index == location.SupportPageIndex })
		if position < 0 || position >= len(s.adminIndex.Pages) ||
			s.adminIndex.Pages[position].Ref.Index != location.SupportPageIndex ||
			int(location.RowSlot) >= len(s.support[position].Records) {
			return nil, contract.ErrRecord
		}
		selected, mandatory := 0, false
		for _, span := range s.adminIndex.Pages[position].Spans {
			if int(location.RowSlot) >= selected && int(location.RowSlot) < selected+int(span.Count) {
				mandatory = span.Mandatory
				break
			}
			selected += int(span.Count)
		}
		if !mandatory {
			return nil, contract.ErrRecord
		}
		row := s.support[position].Records[location.RowSlot]
		fragment, err := contract.InspectGeneratedFragment(row.Body)
		expectedID, idErr := contract.GeneratorFragmentID(id, location.FragmentIndex)
		if err != nil || idErr != nil || row.Kind != contract.GeneratedFragmentSupportKind || row.RecordID != expectedID ||
			fragment.BlobID != id || fragment.Index != location.FragmentIndex || fragment.Index != count ||
			fragment.TotalLength > limit || uint64(fragment.Offset) != uint64(len(data)) {
			return nil, contract.ErrRecord
		}
		if count == 0 {
			whole, total = fragment.WholeDigest, fragment.TotalLength
		} else if fragment.Count <= count || fragment.Count != totalFragmentCount(total) || fragment.TotalLength != total || fragment.WholeDigest != whole {
			return nil, contract.ErrRecord
		}
		data = append(data, fragment.Payload...)
		count++
	}
	if count == 0 || count != totalFragmentCount(total) || uint64(len(data)) != total || contract.Hash(data) != whole {
		return nil, contract.ErrRecord
	}
	return data, nil
}

func totalFragmentCount(total uint64) uint16 {
	return uint16((total + contract.GeneratedFragmentMaxPayload - 1) / contract.GeneratedFragmentMaxPayload)
}

func (s *StateSession) receiptIndexID() (contract.ID, error) {
	if s == nil {
		return contract.ID{}, contract.ErrRecord
	}
	return selectedReceiptIndexID(s.admission.domain, s.root)
}
func selectedReceiptIndexID(domain contract.ID, root format.Root) (contract.ID, error) {
	if domain.IsZero() || !contract.GeneratorIndexShapeValid(contract.GeneratorSuccessWindow, root.Generated.SuccessWindow) ||
		!contract.GeneratorIndexShapeValid(contract.GeneratorFailureWindow, root.Generated.FailureWindow) ||
		!contract.GeneratorIndexShapeValid(contract.GeneratorReceiptOrder, root.Generated.ReceiptOrder) ||
		root.Generated.ReceiptOrder.Count != root.Generated.SuccessWindow.Count+root.Generated.FailureWindow.Count {
		return contract.ID{}, contract.ErrRecord
	}
	if root.Generated.SuccessWindow.Count == 0 && root.Generated.FailureWindow.Count == 0 {
		return contract.ID{}, nil
	}
	return contract.MutationReceiptIndexBlobID(domain, root.Generated.SuccessWindow, root.Generated.FailureWindow, root.Generated.ReceiptOrder)
}

func (s *StateSession) supportBlob(id contract.ID, limit uint64) ([]byte, error) {
	if s == nil {
		return nil, contract.ErrRecord
	}
	return selectedSupportBlob(s.root, s.support, id, limit)
}
func selectedSupportBlob(root format.Root, support []format.RequiredSupportPageView, id contract.ID, limit uint64) ([]byte, error) {
	if id.IsZero() || limit == 0 || format.ValidateFragmentDirectory(root.Generated.Fragments, support) != nil {
		return nil, contract.ErrRecord
	}
	var data []byte
	var expected contract.ID
	for _, location := range root.Generated.Fragments {
		if location.BlobID != id {
			continue
		}
		var page *format.RequiredSupportPageView
		for i := range support {
			if support[i].Index == location.SupportPageIndex {
				page = &support[i]
				break
			}
		}
		if page == nil || int(location.RowSlot) >= len(page.Records) {
			return nil, contract.ErrRecord
		}
		fragment, err := contract.InspectGeneratedFragment(page.Records[location.RowSlot].Body)
		if err != nil || fragment.TotalLength > limit || fragment.BlobID != id || uint64(len(data)) != uint64(fragment.Offset) {
			return nil, contract.ErrRecord
		}
		if fragment.Index == 0 {
			data = make([]byte, 0, int(fragment.TotalLength))
			expected = fragment.WholeDigest
		}
		data = append(data, fragment.Payload...)
	}
	if len(data) == 0 || contract.Hash(data) != expected {
		return nil, contract.ErrRecord
	}
	return data, nil
}

// The complete reader keeps the receipt order as IDs and the already decoded
// receipt rows in mutationReceipts. This adds at most 512 IDs, not a second
// copy of the bounded receipt bodies. The facts apply only to their exact root.
func (s *StateSession) recordSelectedReceiptWindows(windows contract.MutationReceiptWindows) error {
	indexes, err := windows.Indexes()
	if s == nil || err != nil || s.head.Core.Root.Kind != format.RootKind {
		return contract.ErrRecord
	}
	s.mutationReceipts = make(map[contract.ID]contract.CompactMutationReceipt, len(windows.Successes)+len(windows.Failures))
	for _, rows := range [][]contract.CompactMutationReceipt{windows.Successes, windows.Failures} {
		for _, row := range rows {
			s.mutationReceipts[row.OperationID] = row
		}
	}
	s.selectedReceiptIndexes = indexes
	s.selectedReceiptRoot = s.head.Core.Root
	return nil
}

func (s *StateSession) retainedSelectedReceiptWindows() (contract.MutationReceiptWindows, bool, error) {
	if s == nil || s.selectedReceiptRoot.Kind != format.RootKind || s.selectedReceiptRoot != s.head.Core.Root {
		return contract.MutationReceiptWindows{}, false, nil
	}
	body, err := format.EncodeRoot(s.root)
	if err != nil {
		return contract.MutationReceiptWindows{}, true, err
	}
	ref, err := format.Reference(format.RootKind, s.root.Domain, s.root.Snapshot, 0, body)
	if err != nil || ref != s.selectedReceiptRoot {
		return contract.MutationReceiptWindows{}, false, nil
	}
	windows := contract.MutationReceiptWindows{DomainID: s.root.Domain,
		Successes: make([]contract.CompactMutationReceipt, 0, len(s.selectedReceiptIndexes.Successes)),
		Failures:  make([]contract.CompactMutationReceipt, 0, len(s.selectedReceiptIndexes.Failures)),
		Order:     slices.Clone(s.selectedReceiptIndexes.Order)}
	for class, ids := range [][]contract.ID{s.selectedReceiptIndexes.Successes, s.selectedReceiptIndexes.Failures} {
		for _, id := range ids {
			row, ok := s.mutationReceipts[id]
			if !ok || row.CanonicalOutcome != uint8(class+1) {
				return contract.MutationReceiptWindows{}, true, contract.ErrRecord
			}
			if class == 0 {
				windows.Successes = append(windows.Successes, row)
			} else {
				windows.Failures = append(windows.Failures, row)
			}
		}
	}
	if len(windows.Successes)+len(windows.Failures) != len(s.mutationReceipts) {
		return contract.MutationReceiptWindows{}, true, contract.ErrRecord
	}
	if _, err := windows.Indexes(); err != nil {
		return contract.MutationReceiptWindows{}, true, err
	}
	return windows, true, nil
}

func (s *StateSession) receiptWindows(ctx context.Context) (contract.MutationReceiptWindows, error) {
	if _, err := s.supportDescriptor(); err != nil {
		return contract.MutationReceiptWindows{}, err
	}
	if ctx != nil && ctx.Err() != nil {
		return contract.MutationReceiptWindows{}, selectedReadFailure(failure(EvidenceUnavailable, ReadUnavailable))
	}
	if windows, found, err := s.retainedSelectedReceiptWindows(); found || err != nil {
		return windows, err
	}
	if s.fragmentFacts != nil {
		windows, err := s.receiptWindowsFromSelectedSupport(ctx)
		return windows, err
	}
	return s.receiptWindowsFromValidatedSupport()
}

func (s *StateSession) receiptWindowsFromValidatedSupport() (contract.MutationReceiptWindows, error) {
	return s.receiptWindowsWithBlob(s.supportBlob)
}

// An administrative image has authenticated summaries for optional work, but
// the receipt index fragments and receipt rows themselves remain mandatory.
func (s *StateSession) receiptWindowsFromAdministrativeSupport() (contract.MutationReceiptWindows, error) {
	if windows, found, err := s.retainedSelectedReceiptWindows(); found || err != nil {
		return windows, err
	}
	return s.receiptWindowsWithBlob(s.administrativeSupportBlob)
}

// retainedMutationReceipt uses this authenticated image's complete windows.
// It owns returned bytes and never rereads HEAD or reencodes a receipt.
func (s *StateSession) retainedMutationReceipt(operation contract.ID) (contract.CompactMutationReceipt, []byte, bool, error) {
	windows, bodies, err := s.retainedMutationReceiptBodies()
	if err != nil {
		return contract.CompactMutationReceipt{}, nil, false, err
	}
	for _, window := range [][]contract.CompactMutationReceipt{windows.Successes, windows.Failures} {
		for _, row := range window {
			if row.OperationID == operation {
				return row, slices.Clone(bodies[operation]), true, nil
			}
		}
	}
	return contract.CompactMutationReceipt{}, nil, false, nil
}

func (s *StateSession) retainedMutationReceiptBodies() (*contract.MutationReceiptWindows, map[contract.ID][]byte, error) {
	if s == nil || !s.adminIndex.Valid() || len(s.support) != len(s.adminIndex.Pages) {
		return nil, nil, contract.ErrRecord
	}
	windows, err := s.receiptWindowsFromAdministrativeSupport()
	if err != nil {
		return nil, nil, err
	}
	expected := make(map[contract.ID]contract.CompactMutationReceipt, len(windows.Successes)+len(windows.Failures))
	for _, rows := range [][]contract.CompactMutationReceipt{windows.Successes, windows.Failures} {
		for _, row := range rows {
			expected[row.OperationID] = row
		}
	}
	bodies := make(map[contract.ID][]byte, len(expected))
	for i, support := range s.support {
		page := s.adminIndex.Pages[i]
		if support.Index != page.Ref.Index {
			return nil, nil, contract.ErrRecord
		}
		selected := 0
		for _, span := range page.Spans {
			for offset := 0; offset < int(span.Count); offset++ {
				logical := selected + offset
				if logical >= len(support.Records) {
					if span.Mandatory || page.ReadRequired {
						return nil, nil, contract.ErrRecord
					}
					continue
				}
				record := support.Records[logical]
				if record.Kind != contract.MutationReceiptSupportKind {
					continue
				}
				row, err := contract.InspectCompactMutationReceipt(record.Body)
				if !span.Mandatory || err != nil || row != expected[record.RecordID] || bodies[record.RecordID] != nil {
					return nil, nil, contract.ErrRecord
				}
				bodies[record.RecordID] = record.Body
			}
			selected += int(span.Count)
		}
	}
	if len(bodies) != len(expected) {
		return nil, nil, contract.ErrRecord
	}
	return &windows, bodies, nil
}

func (s *StateSession) retainedAdministrativeAbandonments() ([]AuthorityAbandonment, error) {
	windows, bodies, err := s.retainedMutationReceiptBodies()
	if err != nil {
		return nil, err
	}
	var rows []AuthorityAbandonment
	for _, window := range [][]contract.CompactMutationReceipt{windows.Successes, windows.Failures} {
		for _, receipt := range window {
			if receipt.OperationKind != contract.OperationEndSelectedWork {
				continue
			}
			row := AuthorityAbandonment{Receipt: receipt, ReceiptBytes: slices.Clone(bodies[receipt.OperationID])}
			if receipt.AdministrativeTargetKind == contract.AdministrativeGeneratedParent && receipt.AdministrativeGroupID == receipt.AdministrativeTargetID {
				row.OriginalOperation = &AdministrativeOriginalOperation{OperationID: receipt.AdministrativeGroupID}
			}
			rows = append(rows, row)
		}
	}
	return rows, nil
}

func (s *StateSession) receiptWindowsWithBlob(blob func(contract.ID, uint64) ([]byte, error)) (contract.MutationReceiptWindows, error) {
	return selectedReceiptWindows(s.admission.domain, s.root, s.support, blob)
}
func selectedReceiptWindows(domain contract.ID, root format.Root, support []format.RequiredSupportPageView, blob func(contract.ID, uint64) ([]byte, error)) (contract.MutationReceiptWindows, error) {
	id, err := selectedReceiptIndexID(domain, root)
	if err != nil {
		return contract.MutationReceiptWindows{}, err
	}
	windows := contract.MutationReceiptWindows{DomainID: domain}
	indexes := contract.MutationReceiptIndexes{}
	if !id.IsZero() {
		body, err := blob(id, contract.MutationReceiptIndexesMaxLength)
		if err != nil {
			return contract.MutationReceiptWindows{}, err
		}
		indexes, err = contract.InspectMutationReceiptIndexes(body)
		if err != nil {
			return contract.MutationReceiptWindows{}, err
		}
	}
	successes, failures, order, err := indexes.Descriptors()
	if err != nil || successes != root.Generated.SuccessWindow || failures != root.Generated.FailureWindow || order != root.Generated.ReceiptOrder {
		return contract.MutationReceiptWindows{}, contract.ErrRecord
	}
	windows.Order = slices.Clone(indexes.Order)
	rows := make(map[contract.ID]contract.CompactMutationReceipt, len(indexes.Successes)+len(indexes.Failures))
	for _, page := range support {
		for _, record := range page.Records {
			if record.Kind != contract.MutationReceiptSupportKind {
				continue
			}
			row, err := contract.InspectCompactMutationReceipt(record.Body)
			if err != nil || row.DomainID != domain || row.OperationID != record.RecordID || len(rows) >= len(indexes.Successes)+len(indexes.Failures) {
				return contract.MutationReceiptWindows{}, contract.ErrRecord
			}
			if _, exists := rows[row.OperationID]; exists {
				return contract.MutationReceiptWindows{}, contract.ErrRecord
			}
			rows[row.OperationID] = row
		}
	}
	for class, ids := range [][]contract.ID{indexes.Successes, indexes.Failures} {
		for _, id := range ids {
			row, ok := rows[id]
			if !ok || row.CanonicalOutcome != uint8(class+1) {
				return contract.MutationReceiptWindows{}, contract.ErrRecord
			}
			delete(rows, id)
			if class == 0 {
				windows.Successes = append(windows.Successes, row)
			} else {
				windows.Failures = append(windows.Failures, row)
			}
		}
	}
	if len(rows) != 0 {
		return contract.MutationReceiptWindows{}, contract.ErrRecord
	}
	return windows, nil
}

func selectedCompleteReceiptWindows(image *selectedImage) (contract.MutationReceiptWindows, error) {
	if image == nil {
		return contract.MutationReceiptWindows{}, contract.ErrRecord
	}
	if image.receiptsValidated {
		return contract.MutationReceiptWindows{DomainID: image.receiptWindows.DomainID,
			Successes: slices.Clone(image.receiptWindows.Successes), Failures: slices.Clone(image.receiptWindows.Failures),
			Order: slices.Clone(image.receiptWindows.Order)}, nil
	}
	if image.fragmentFacts != nil {
		return contract.MutationReceiptWindows{}, contract.ErrRecord
	}
	return selectedReceiptWindows(image.root.Domain, image.root, image.support, func(id contract.ID, limit uint64) ([]byte, error) {
		return selectedSupportBlob(image.root, image.support, id, limit)
	})
}

package core

import (
	"bytes"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// administrativePlannedRow keeps a selected fragment's authenticated body
// identity without retaining its payload. A nil body is allowed only when
// source names the exact unchanged predecessor page and physical row.
type administrativePlannedRow struct {
	row        contract.SupportRecord
	fact       contract.SupportRecordDigest
	bodyLength uint32
	bodyDigest contract.ID
	blob       contract.ID
	source     format.Ref
	physical   uint16
}

type administrativePlannedPage struct {
	ref  format.Ref
	rows []administrativePlannedRow
}

func (s *StateSession) administrativePagePlan(root format.Root,
	pages []format.RequiredSupportPage, parent *contract.GeneratedParentPlan,
	receiptPlans ...*contract.CompactMutationReceiptPlan) ([]administrativePlannedPage, error) {
	if s == nil || len(pages) != len(root.RequiredSupport) {
		return nil, contract.ErrRecord
	}
	if len(receiptPlans) > 1 {
		return nil, contract.ErrRecord
	}
	var receipt *contract.CompactMutationReceiptPlan
	var plannedReceiptBody []byte
	if len(receiptPlans) == 1 {
		receipt = receiptPlans[0]
	}
	if receipt != nil {
		if receipt.DomainID != root.Domain {
			return nil, contract.ErrRecord
		}
		var err error
		plannedReceiptBody, err = contract.AppendCompactMutationReceiptPlan(nil, *receipt)
		if err != nil {
			return nil, err
		}
	}
	receiptCount := 0
	var selected map[contract.ID]selectedFragmentFact
	for _, page := range pages {
		for _, row := range page.Records {
			if row.Body != nil || !opaqueSupportKind(row.Kind) {
				continue
			}
			var err error
			selected, err = s.selectedFragmentFactsByRecord()
			if err != nil {
				return nil, err
			}
			break
		}
		if selected != nil {
			break
		}
	}
	out := make([]administrativePlannedPage, len(pages))
	for i, page := range pages {
		ref := root.RequiredSupport[i]
		if page.Domain != root.Domain || page.Object != ref.Object || page.Index != ref.Index ||
			ref.Kind != contract.RequiredSupportKind {
			return nil, contract.ErrRecord
		}
		out[i] = administrativePlannedPage{ref: ref, rows: make([]administrativePlannedRow, len(page.Records))}
		for j, row := range page.Records {
			planned := administrativePlannedRow{row: row}
			if row.Body == nil && publicationSupportKind(row.Kind) {
				fact, err := s.publicationRecord(row)
				if err != nil {
					return nil, err
				}
				planned.fact, planned.bodyLength, planned.bodyDigest = fact.digest, fact.digest.BodyLength(), fact.digest.BodyDigest()
				out[i].rows[j] = planned
				continue
			}
			if row.Body == nil {
				if !opaqueSupportKind(row.Kind) {
					return nil, contract.ErrRecord
				}
				fact, ok := selected[row.RecordID]
				if !ok || fact.ref != ref || fact.row.RecordID() != row.RecordID || j > 255 || row.Kind == contract.GeneratedFragmentSupportKind &&
					!slices.Contains(root.Generated.Fragments, format.FragmentLocation{BlobID: fact.blob,
						FragmentIndex: fact.index, SupportPageIndex: ref.Index, RowSlot: uint8(j)}) {
					return nil, contract.ErrRecord
				}
				planned.fact, planned.blob = fact.row, fact.blob
				planned.bodyLength, planned.bodyDigest = fact.row.BodyLength(), fact.row.BodyDigest()
				planned.source, planned.physical = fact.ref, fact.physical
			} else {
				if parent != nil && row.Kind == contract.GeneratedParentSupportKind && row.RecordID == parent.OperationID {
					actual, err := contract.InspectGeneratedParentPlan(row.Body)
					if err != nil || actual != *parent || actual.DomainID != root.Domain {
						return nil, contract.ErrRecord
					}
				} else if receipt != nil && row.Kind == contract.MutationReceiptSupportKind && row.RecordID == receipt.OperationID {
					if !bytes.Equal(row.Body, plannedReceiptBody) {
						return nil, contract.ErrRecord
					}
					receiptCount++
				} else {
					fact, err := contract.InspectSupportRecordDigest(root.Domain, row)
					if err != nil {
						return nil, err
					}
					planned.fact = fact
				}
				planned.bodyLength, planned.bodyDigest = uint32(len(row.Body)), contract.Hash(row.Body)
				if row.Kind == contract.GeneratedFragmentSupportKind {
					fragment, err := contract.InspectGeneratedFragment(row.Body)
					if err != nil {
						return nil, err
					}
					planned.blob = fragment.BlobID
				}
			}
			out[i].rows[j] = planned
		}
	}
	if receipt != nil && receiptCount != 1 {
		return nil, contract.ErrRecord
	}
	return out, nil
}

package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

func (s *StateSession) supportRecords() []contract.SupportRecord {
	return selectedSupportRecords(s.support)
}

func (s *StateSession) workSupportRecords(ctx context.Context) ([]contract.SupportRecord, error) {
	image, err := s.completeSelectedImage(ctx)
	if err != nil {
		return nil, err
	}
	return selectedWorkSupportRecords(image)
}

func (s *StateSession) workSupportDescriptor(rows []contract.SupportRecord) (contract.GeneratorDescriptor, error) {
	return s.selectedImage().workSupportDescriptor(rows)
}
func (s *selectedImage) workSupportDescriptor(rows []contract.SupportRecord) (contract.GeneratorDescriptor, error) {
	if s == nil {
		return contract.GeneratorDescriptor{}, contract.ErrRecord
	}
	if s.supportFacts == nil && s.fragmentFacts == nil {
		for _, page := range s.support {
			for _, row := range page.Records {
				if row.Body == nil {
					return contract.GeneratorDescriptor{}, contract.ErrRecord
				}
			}
		}
		return contract.GeneratorAuthorityWorkDescriptor(s.root.Domain, rows)
	}
	index, err := selectedReceiptIndexID(s.root.Domain, s.root)
	if err != nil || len(s.supportFacts) != len(s.support) || len(s.supportFacts) != len(s.root.RequiredSupport) {
		return contract.GeneratorDescriptor{}, contract.ErrRecord
	}
	fragments := make(map[contract.ID]selectedFragmentFact, len(s.fragmentFacts))
	for location, fact := range s.fragmentFacts {
		id, err := contract.GeneratorFragmentID(fact.blob, fact.index)
		if err != nil || fact.row.Kind() != contract.GeneratedFragmentSupportKind || fact.row.RecordID() != id ||
			location.BlobID != fact.blob || location.FragmentIndex != fact.index ||
			location.SupportPageIndex != fact.ref.Index || location.RowSlot != fact.logical {
			return contract.GeneratorDescriptor{}, contract.ErrRecord
		}
		if _, duplicate := fragments[id]; duplicate {
			return contract.GeneratorDescriptor{}, contract.ErrRecord
		}
		fragments[id] = fact
	}
	facts := make([]contract.SupportRecordDigest, 0, len(rows))
	for i, page := range s.supportFacts {
		view := s.support[i]
		if page.ref != s.root.RequiredSupport[i] || view.Domain != s.root.Domain || view.Object != page.ref.Object ||
			view.Index != page.ref.Index || len(page.rows) != len(view.Records) || len(page.rows) != len(page.ordinals) {
			return contract.GeneratorDescriptor{}, contract.ErrRecord
		}
		for j, fact := range page.rows {
			row := view.Records[j]
			if fact.Kind() != row.Kind || fact.RecordID() != row.RecordID || j > 0 && page.ordinals[j-1] >= page.ordinals[j] {
				return contract.GeneratorDescriptor{}, contract.ErrRecord
			}
			if row.Body != nil {
				actual, err := contract.InspectSupportRecordDigest(s.root.Domain, contract.SupportRecord(row))
				if err != nil || actual != fact {
					return contract.GeneratorDescriptor{}, contract.ErrRecord
				}
			}
			if fact.Kind() == contract.MutationReceiptSupportKind {
				continue
			}
			if fact.Kind() == contract.GeneratedFragmentSupportKind {
				fragment, ok := fragments[fact.RecordID()]
				var blob contract.ID
				if ok {
					if fragment.ref != page.ref || fragment.row != fact || fragment.physical != page.ordinals[j] || int(fragment.logical) != j {
						return contract.GeneratorDescriptor{}, contract.ErrRecord
					}
					blob = fragment.blob
				} else {
					if row.Body == nil {
						return contract.GeneratorDescriptor{}, contract.ErrRecord
					}
					view, err := contract.InspectGeneratedFragment(row.Body)
					if err != nil {
						return contract.GeneratorDescriptor{}, contract.ErrRecord
					}
					blob = view.BlobID
				}
				if blob == index {
					continue
				}
			}
			facts = append(facts, fact)
		}
	}
	if len(facts) != len(rows) {
		return contract.GeneratorDescriptor{}, contract.ErrRecord
	}
	slices.SortFunc(facts, func(a, b contract.SupportRecordDigest) int {
		if a.Kind() < b.Kind() {
			return -1
		}
		if a.Kind() > b.Kind() {
			return 1
		}
		aID, bID := a.RecordID(), b.RecordID()
		return bytes.Compare(aID[:], bID[:])
	})
	for i, fact := range facts {
		if fact.Kind() != rows[i].Kind || fact.RecordID() != rows[i].RecordID {
			return contract.GeneratorDescriptor{}, contract.ErrRecord
		}
	}
	return contract.GeneratorAuthorityWorkDescriptorFromDigests(s.root.Domain, facts)
}

func (s *StateSession) supportDescriptor() (contract.DescriptorVector, error) {
	return s.selectedImage().supportDescriptor()
}
func (s *selectedImage) supportDescriptor() (contract.DescriptorVector, error) {
	if s == nil || len(s.support) != len(s.root.RequiredSupport) {
		return contract.DescriptorVector{}, contract.ErrRecord
	}
	var count uint32
	for i, page := range s.support {
		ref := s.root.RequiredSupport[i]
		if page.Domain != s.root.Domain || page.Object != ref.Object || page.Index != ref.Index {
			return contract.DescriptorVector{}, contract.ErrRecord
		}
		count += uint32(len(page.Records))
	}
	if count != s.root.RequiredSupportRecordCount {
		return contract.DescriptorVector{}, contract.ErrRecord
	}
	if _, err := s.resolveSelectedGeneratedSlices(); err != nil {
		return contract.DescriptorVector{}, err
	}
	if len(s.supportFacts) == len(s.support) {
		facts := make([]contract.SupportRecordDigest, 0, count)
		for i, page := range s.supportFacts {
			if page.ref != s.root.RequiredSupport[i] || len(page.rows) != len(s.support[i].Records) || len(page.rows) != len(page.ordinals) {
				return contract.DescriptorVector{}, contract.ErrRecord
			}
			facts = append(facts, page.rows...)
		}
		slices.SortFunc(facts, func(a, b contract.SupportRecordDigest) int {
			if a.Kind() < b.Kind() {
				return -1
			}
			if a.Kind() > b.Kind() {
				return 1
			}
			aID, bID := a.RecordID(), b.RecordID()
			return bytes.Compare(aID[:], bID[:])
		})
		return contract.RequiredSupportDescriptorFromDigests(s.root.Domain, facts)
	}
	return contract.RequiredSupportDescriptor(s.root.Domain, s.supportRecords())
}

// MutationReceipt authenticates current state before returning the exact
// retained original canonical outcome.
func (s *StateSession) MutationReceipt(ctx context.Context, operation contract.ID) ([]byte, Result) {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreMutationReceipt)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	body, result := s.mutationReceiptCall(ctx, operation, call)
	finishCore(call, result)
	return body, result
}

func (s *StateSession) mutationReceiptCall(ctx context.Context, operation contract.ID, call *telemetry.Call) ([]byte, Result) {
	if ctx == nil || ctx.Err() != nil {
		return nil, refused(AdmissionInvalid)
	}
	ctx = telemetry.CallContext(ctx, call)
	return s.mutationReceipt(ctx, operation)
}

func (s *StateSession) mutationReceipt(ctx context.Context, operation contract.ID) ([]byte, Result) {
	if s == nil || ctx == nil || ctx.Err() != nil || operation.IsZero() || !s.admission.valid(s.store) {
		return nil, refused(AdmissionInvalid)
	}
	current, res := s.readCurrentForReceipt(ctx)
	if current == nil {
		return nil, res
	}
	row, ok := current.mutationReceipts[operation]
	if !ok {
		return nil, refused(AdmissionInvalid)
	}

	body, err := contract.EncodeCompactMutationReceipt(row)
	if err != nil {
		return nil, failure(IntegrityFailure, InvalidFormat)
	}
	return body, res
}

func selectedWorkSupportRecords(s *selectedImage) ([]contract.SupportRecord, error) {
	if _, err := selectedCompleteReceiptWindows(s); err != nil {
		return nil, err
	}
	index, err := selectedReceiptIndexID(s.root.Domain, s.root)
	if err != nil {
		return nil, err
	}
	rows := s.supportRecords()
	fragmentBlobs := make(map[contract.ID]contract.ID, len(s.fragmentFacts))
	for _, fact := range s.fragmentFacts {
		fragmentBlobs[fact.row.RecordID()] = fact.blob
	}
	out := rows[:0]
	for _, row := range rows {
		if row.Kind == contract.MutationReceiptSupportKind {
			continue
		}
		if row.Kind == contract.GeneratedFragmentSupportKind {
			if len(fragmentBlobs) != 0 {
				blob, ok := fragmentBlobs[row.RecordID]
				if !ok {
					return nil, contract.ErrRecord
				}
				if blob == index {
					continue
				}
				out = append(out, row)
				continue
			}
			fragment, err := contract.InspectGeneratedFragment(row.Body)
			if err != nil {
				return nil, err
			}
			if fragment.BlobID == index {
				continue
			}
		}
		out = append(out, row)
	}
	return out, nil
}

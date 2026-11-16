package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"

	"enkv.sh/core/contract"
)

// plannedReceiptSupport carries a closed typed hole only for one private
// reservation copy. The corresponding SupportRecordDigest remains zero.
// A selected physical reader must never accept this carrier as evidence.
type plannedReceiptSupport struct {
	owner *StateSession
	plan  contract.CompactMutationReceiptPlan
	body  []byte
}

func (p *plannedReceiptSupport) matchesOwner(domain contract.ID, row contract.SupportRecordView) (bool, error) {
	if p == nil {
		return false, nil
	}
	if p.owner == nil || p.plan.DomainID != domain || !p.plan.RequestIdentityDigest.IsZero() {
		return false, contract.ErrRecord
	}
	canonical, err := contract.AppendCompactMutationReceiptPlan(nil, p.plan)
	if err != nil || !bytes.Equal(canonical, p.body) {
		return false, contract.ErrRecord
	}
	if row.Kind != contract.MutationReceiptSupportKind || row.RecordID != p.plan.OperationID {
		return false, nil
	}
	if !bytes.Equal(row.Body, p.body) {
		return false, contract.ErrRecord
	}
	return true, nil
}
func (p *plannedReceiptSupport) matches(s *StateSession, row contract.SupportRecordView) (bool, error) {
	if p == nil {
		return false, nil
	}
	if s == nil || p.owner != s {
		return false, contract.ErrRecord
	}
	return p.matchesOwner(s.root.Domain, row)
}

// receiptReservationCopy supplies the exact planned public rows to the slow
// first-EndWork proof. It neither seals the receipt nor changes the outgoing
// successor. Only complete rows and authenticated retained facts are rebound.
func (s *StateSession) receiptReservationCopy(ctx context.Context, next *StateSession, plan contract.CompactMutationReceiptPlan, application *receiptApplicationProjection) (*StateSession, error) {
	if ctx == nil || s == nil || next == nil || s == next || s.root.Domain != next.root.Domain || plan.DomainID != next.root.Domain ||
		!plan.RequestIdentityDigest.IsZero() || s.fragmentFacts != nil && len(s.fragmentFacts) != len(s.root.Generated.Fragments) {
		return nil, contract.ErrRecord
	}
	if ctx.Err() != nil {
		return nil, selectedReadFailure(failure(EvidenceUnavailable, ReadUnavailable))
	}
	body, err := contract.AppendCompactMutationReceiptPlan(nil, plan)
	if err != nil {
		return nil, err
	}
	view := *next
	carrier := &plannedReceiptSupport{owner: &view, plan: plan, body: body}
	storage := mutationReceiptStorage{refs: view.root.RequiredSupport, pages: view.support, generated: view.root.Generated}
	if err := storage.bindSupportFacts(s, carrier); err != nil {
		return nil, fmt.Errorf("bind reservation support: %w", err)
	}
	view.supportFacts, view.fragmentFacts = storage.facts, storage.fragments
	// Output and Slice checks still bind exact authenticated predecessor facts.
	// A support-only reservation cannot own a complete selected-image cache.
	if err := s.validateSuccessorOutputConfiguration(&view); err != nil {
		return nil, fmt.Errorf("validate reservation output: %w", err)
	}
	if application == nil {
		root, ok := view.generatedSelectionRoot()
		if !ok {
			return nil, fmt.Errorf("reservation root framing: %w", contract.ErrRecord)
		}
		view.outputConfigurationRoot = root
		if s.fragmentFacts != nil {
			if err := s.bindReceiptSuccessorSlices(&view); err != nil {
				return nil, fmt.Errorf("bind reservation slices: %w", err)
			}
		}
		view.normalReceiptSlices = nil
		return &view, nil
	}
	view.generatedWork, view.generatedSlicesRoot, view.generatedSliceLocations = nil, contract.ID{}, nil
	view.outputConfigurationRoot, view.publicationProof = contract.ID{}, nil
	view.support = slices.Clone(view.support)
	for i, page := range view.support {
		copied := false
		for j, row := range page.Records {
			if row.Kind != contract.OutputConfigurationSliceSupportKind || row.Body != nil {
				continue
			}
			body, err := s.readSelectedOutputSupportRow(ctx, row.RecordID)
			if err != nil {
				return nil, fmt.Errorf("read retained reservation output: %w", err)
			}
			if !copied {
				view.support[i].Records = slices.Clone(page.Records)
				copied = true
			}
			view.support[i].Records[j].Body = body
		}
	}
	if s.fragmentFacts != nil {
		if _, err := s.receiptSuccessorSlices(&view); err != nil {
			return nil, fmt.Errorf("validate reservation slices: %w", err)
		}
	}
	// Nested EndWork capacity uses the validated support rows directly.
	view.normalReceiptSlices = nil
	return &view, nil
}

// Capacity checks need exact facts for rebuilt publication pages. Keep the
// receipt hole private to its typed plan; no fact for it enters the successor.
func (s *StateSession) bindPlannedPublicationFacts(next *StateSession, plan contract.CompactMutationReceiptPlan) error {
	body, err := contract.AppendCompactMutationReceiptPlan(nil, plan)
	if err != nil {
		return err
	}
	carrier := &plannedReceiptSupport{owner: next, plan: plan, body: body}
	storage := mutationReceiptStorage{refs: next.root.RequiredSupport, pages: next.support, generated: next.root.Generated}
	if err := storage.bindSupportFacts(s, carrier); err != nil {
		return err
	}
	for i, page := range next.support {
		publication := slices.ContainsFunc(page.Records, func(row contract.SupportRecordView) bool {
			return row.Kind == contract.PublicationCoordinateSupportKind || row.Kind == contract.PublicationMarkerSupportKind
		})
		if publication {
			if storage.facts[i].plannedReceipt != nil {
				return contract.ErrRecord
			}
			next.supportFacts[i] = storage.facts[i]
		}
	}
	return nil
}

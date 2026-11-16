package core

import (
	"context"
	"encoding/binary"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type selectedGCObligation struct {
	group    format.AdministrativeGroup
	progress contract.GCProgress
	plan     *contract.GCPlan
}

func selectedGCState(image *selectedImage, complete bool) (map[contract.ID]selectedGCObligation, error) {
	if image == nil || !image.adminIndex.Valid() {
		return nil, contract.ErrRecord
	}
	root, index := image.root, image.adminIndex
	descriptor, err := format.GCPlansDescriptor(index)
	if err != nil || descriptor != root.GCPlans || !root.ActiveGC.IsZero() && !root.Generated.ActiveOwner.IsZero() {
		return nil, contract.ErrRecord
	}
	out := make(map[contract.ID]selectedGCObligation)
	for _, group := range index.Groups {
		if group.OwnerKind == format.AdministrativeGC {
			if group.GC == nil || group.GroupID != root.ActiveGC && group.GC.RemainingCount == 0 {
				return nil, contract.ErrRecord
			}
			out[group.GroupID] = selectedGCObligation{group: group, progress: *group.GC}
		}
	}
	if !root.ActiveGC.IsZero() {
		if _, ok := out[root.ActiveGC]; !ok {
			return nil, contract.ErrRecord
		}
	}
	found := make(map[contract.ID]bool, len(out))
	for pi, page := range index.Pages {
		offset := 0
		for _, span := range page.Spans {
			for n := 0; n < int(span.Count); n++ {
				var summary format.AdministrativeRowSummary
				var row contract.SupportRecordView
				readable := pi < len(image.support) && offset < len(image.support[pi].Records)
				if readable {
					row = image.support[pi].Records[offset]
				}
				if page.ReadRequired {
					if !readable {
						return nil, contract.ErrRecord
					}
					summary = format.AdministrativeRowSummary{Kind: row.Kind, RecordID: row.RecordID, BodyLength: uint32(len(row.Body))}
				} else {
					if offset >= len(page.Rows) {
						return nil, contract.ErrRecord
					}
					summary = page.Rows[offset]
				}
				offset++
				if summary.Kind != contract.GCPlanSupportKind {
					continue
				}
				obligation, ok := out[summary.RecordID]
				if !ok || found[summary.RecordID] || span.Mandatory || page.ReadRequired || len(span.GroupIndexes) != 1 || index.Groups[span.GroupIndexes[0]].GroupID != summary.RecordID {
					return nil, contract.ErrRecord
				}
				found[summary.RecordID] = true
				if complete {
					if !readable || row.Kind != summary.Kind || row.RecordID != summary.RecordID || uint32(len(row.Body)) != summary.BodyLength || contract.Hash(row.Body) != obligation.progress.PlanDigest {
						return nil, contract.ErrRecord
					}
					plan, e := contract.DecodeGCPlan(row.Body)
					if e != nil || plan.DomainID != root.Domain || plan.OperationID != summary.RecordID || len(plan.Targets) == 0 {
						return nil, contract.ErrRecord
					}
					targets, e := contract.GCTargetsDescriptor(plan.Targets)
					if e != nil || targets != obligation.progress.TargetsDescriptor {
						return nil, contract.ErrRecord
					}
					observation, e := contract.GCPlanObservationDigest(plan)
					if e != nil || observation != obligation.progress.ObservationDigest {
						return nil, contract.ErrRecord
					}
					request, e := contract.GCPlanRequestIdentity(plan)
					if e != nil || request != obligation.progress.RequestIdentity || obligation.group.Dependencies != administrativeDescriptor("gc-dependencies", plan.MarkDigest[:], plan.EnumerationDigest[:]) {
						return nil, contract.ErrRecord
					}
					obligation.plan = &plan
					out[summary.RecordID] = obligation
				}
			}
		}
	}
	for id := range out {
		if !found[id] {
			return nil, contract.ErrRecord
		}
	}
	return out, nil
}
func selectedGCStore(states map[contract.ID]selectedGCObligation, store contract.Descriptor) error {
	expected := administrativeStoreDescriptorDigest(store)
	for _, state := range states {
		if state.plan != nil && state.plan.StoreDescriptorDigest != expected {
			return contract.ErrRecord
		}
	}
	return nil
}
func (s *StateSession) selectedGCPlan(operation contract.ID) (contract.GCPlan, contract.GCProgress, error) {
	if s == nil || operation.IsZero() {
		return contract.GCPlan{}, contract.GCProgress{}, contract.ErrRecord
	}
	states, err := selectedGCState(s.selectedImage(), true)
	if err != nil {
		return contract.GCPlan{}, contract.GCProgress{}, err
	}
	if err := selectedGCStore(states, s.admission.store); err != nil {
		return contract.GCPlan{}, contract.GCProgress{}, err
	}
	v, ok := states[operation]
	if !ok || v.plan == nil {
		return contract.GCPlan{}, contract.GCProgress{}, contract.ErrRecord
	}
	return *v.plan, v.progress.Own(), nil
}

func selectedGCSelection(head format.Head, image *selectedImage) bool {
	if image == nil || head.AuthKind != format.GCAuth || head.GC == nil {
		return false
	}
	q := head.GC
	projected := &StateSession{root: image.root, pages: image.pages, recipients: image.recipients, access: image.access, accessFacts: image.accessFacts, support: image.support, supportFacts: image.supportFacts, adminIndex: image.adminIndex, publicationProof: image.publicationProof, publicationFacts: image.publicationFacts, fragmentFacts: image.fragmentFacts, generatedSliceLocations: image.generatedSliceLocations, selectedReceiptIndexes: image.selectedReceiptIndexes, outputConfigurationRoot: image.outputConfigurationRoot, generatedSlicesRoot: image.generatedSlicesRoot}
	preserved, err := projected.gcPreservedCurrent(context.Background(), q.OperationID)
	if err != nil || preserved.Digest != q.PreservedCurrentDigest || preserved.Length != q.PreservedCurrentLength {
		return false
	}
	if q.DomainID != image.root.Domain || q.AfterOwners != image.root.GCPlans {
		return false
	}
	states, e := selectedGCState(image, false)
	if e != nil {
		return false
	}
	state, present := states[q.OperationID]
	if q.AfterProgressDigest.IsZero() {
		return q.Phase == contract.GCClose && !present && image.root.ActiveGC.IsZero()
	}
	if !present || state.progress.RequestIdentity != q.RequestIdentity || state.progress.PlanDigest != q.PlanDigest {
		return false
	}
	digest, e := contract.GCProgressDigest(state.progress)
	if e != nil || digest != q.AfterProgressDigest {
		return false
	}
	if q.Phase == contract.GCClose {
		return image.root.ActiveGC.IsZero() && state.progress.RemainingCount != 0
	}
	return image.root.ActiveGC == q.OperationID
}
func validateGCProgressTransition(before, after *contract.GCProgress, phase contract.GCPhase) error {
	if before == nil {
		if phase != contract.GCSelect || after == nil || !after.Valid() || after.Ordinal != 1 || int(after.RemainingCount) != len(after.Targets) {
			return contract.ErrRecord
		}
		for _, row := range after.Targets {
			if row.Consumed != 0 || row.Disposition != contract.GCTargetPending || !row.EvidenceDigest.IsZero() {
				return contract.ErrRecord
			}
		}
		return nil
	}
	if !before.Valid() {
		return contract.ErrRecord
	}
	if after == nil {
		if phase != contract.GCClose || before.RemainingCount != 0 {
			return contract.ErrRecord
		}
		return nil
	}
	if !after.Valid() || before.PlanDigest != after.PlanDigest || before.TargetsDescriptor != after.TargetsDescriptor || before.RequestIdentity != after.RequestIdentity || before.ObservationDigest != after.ObservationDigest || len(before.Targets) != len(after.Targets) {
		return contract.ErrRecord
	}
	if phase == contract.GCReacquire || phase == contract.GCClose {
		if !contract.GCProgressEqual(*before, *after) {
			return contract.ErrRecord
		}
		return nil
	}
	if before.Ordinal == ^uint32(0) || after.Ordinal != before.Ordinal+1 {
		return contract.ErrRecord
	}
	changed := false
	for i, row := range before.Targets {
		next := after.Targets[i]
		changed = changed || row != next
		if row.Disposition == contract.GCTargetAbsent && next != row {
			return contract.ErrRecord
		}
		switch phase {
		case contract.GCReserve:
			if row == next {
				continue
			}
			if row.Consumed >= contract.GCTransmissionLimit || next.Consumed != row.Consumed+1 || next.Disposition != contract.GCTargetPending || !next.EvidenceDigest.IsZero() || row.Consumed != 0 && row.Disposition != contract.GCTargetRetryableNotSent {
				return contract.ErrRecord
			}
		case contract.GCRecordProgress:
			if next.Consumed != row.Consumed {
				return contract.ErrRecord
			}
		default:
			return contract.ErrRecord
		}
	}
	if !changed {
		return contract.ErrRecord
	}
	return nil
}
func (s *StateSession) gcPreservedCurrent(ctx context.Context, operation contract.ID) (contract.DigestLength, error) {
	if s == nil || operation.IsZero() {
		return contract.DigestLength{}, contract.ErrRecord
	}
	if _, err := selectedGCState(s.selectedImage(), false); err != nil {
		return contract.DigestLength{}, err
	}
	current, e := administrativePreservedCurrent(s.root, s.pages, s.generatedCoverageRecords(), nil)
	if e != nil {
		return contract.DigestLength{}, e
	}
	index := s.adminIndex
	if slices.ContainsFunc(index.Groups, func(g format.AdministrativeGroup) bool { return g.GroupID == operation }) {
		index, e = s.administrativeWorkDisposition(operation)
		if e != nil {
			return contract.DigestLength{}, e
		}
	}
	index.Object = index.Domain
	index.SliceSnapshot = index.Domain
	// Each retained GC group binds its complete plan hash, framed row charge
	// and mandatory progress. GC-only page identities describe packing, which
	// can change when another plan is added to or removed from a shared page.
	// Other selected pages retain their exact physical commitment.
	pages := make([]format.AdministrativePage, 0, len(index.Pages))
	for _, page := range index.Pages {
		if !page.ReadRequired && len(page.Rows) != 0 && !slices.ContainsFunc(page.Rows, func(row format.AdministrativeRowSummary) bool { return row.Kind != contract.GCPlanSupportKind }) {
			continue
		}
		spans := make([]format.AdministrativeSpan, 0, len(page.Spans))
		for _, span := range page.Spans {
			spans = appendAdministrativeOwnerSpan(spans, span)
		}
		page.Spans = spans
		pages = append(pages, page)
	}
	index.Pages = pages
	body, e := format.EncodeAdministrativeIndex(index)
	if e != nil {
		return contract.DigestLength{}, e
	}
	generated, e := format.EncodeGeneratedClosure(s.root.Generated)
	if e != nil {
		return contract.DigestLength{}, e
	}
	b := []byte("ENKV/GC-PRESERVED-CURRENT/v1\x00")
	b = append(b, current.Digest[:]...)
	b = binary.BigEndian.AppendUint64(b, current.Length)
	b = binary.BigEndian.AppendUint32(b, uint32(len(body)))
	b = append(b, body...)
	b = append(b, generated...)
	b = append(b, s.root.WarningBits)
	active := s.root.ActiveGC
	if active == operation {
		active = contract.ID{}
	}
	b = append(b, active[:]...)
	return contract.DigestLength{Digest: contract.Hash(b), Length: uint64(len(b))}, nil
}
func preservedGCState(base contract.DigestLength, root format.Root) (contract.DigestLength, error) {
	if !root.GCPlans.ValidOwners() {
		return contract.DigestLength{}, contract.ErrRecord
	}
	if root.GCPlans.Count == 0 && root.ActiveGC.IsZero() {
		return base, nil
	}
	b := []byte("ENKV/GC-PRESERVED-STATE/v1\x00")
	b = append(b, base.Digest[:]...)
	b = binary.BigEndian.AppendUint64(b, base.Length)
	b = append(b, root.ActiveGC[:]...)
	var err error
	b, err = contract.AppendGCDescriptor(b, root.GCPlans)
	if err != nil {
		return contract.DigestLength{}, err
	}
	return contract.DigestLength{Digest: contract.Hash(b), Length: uint64(len(b))}, nil
}

package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

const (
	WarningOrphanGeneratedEffect uint8 = 1 << iota
	WarningLateDestructiveEffect
	WarningPublicationOrderValue
	WarningDiscardedExactEvidence
	WarningPossibleStoreGarbage
)

type endWorkIDs struct {
	operation, transition, snapshot, revision contract.ID
	receipts, receiptIndex                    contract.ID
}

func (s *StateSession) freshEndWorkIDs() (endWorkIDs, error) {
	var ids endWorkIDs
	used := s.signerOnlyClosureIDs()
	if used == nil || s.admission.endWorkInvocation.IsZero() ||
		used[s.admission.endWorkInvocation] {
		return ids, contract.ErrRecord
	}
	used[s.admission.endWorkInvocation] = true
	entropy := s.admission.entropy
	if entropy == nil {
		entropy = rand.Reader
	}
	for _, id := range []*contract.ID{&ids.operation, &ids.transition, &ids.snapshot, &ids.revision,
		&ids.receipts, &ids.receiptIndex} {
		if _, err := io.ReadFull(entropy, id[:]); err != nil || id.IsZero() || used[*id] {
			return endWorkIDs{}, contract.ErrRecord
		}
		used[*id] = true
	}
	if used[administrativeIndexObject(s.root.Domain, ids.snapshot)] {
		return endWorkIDs{}, contract.ErrRecord
	}
	return ids, nil
}

func endWorkWarningBits(before uint8, scope []format.AdministrativeGroup, possibleStoreGarbage bool) uint8 {
	after := before | WarningDiscardedExactEvidence
	for _, group := range scope {
		if group.OwnerKind >= format.AdministrativeGeneratedParent && group.OwnerKind <= format.AdministrativeInboxRelease {
			after |= WarningOrphanGeneratedEffect
		}
		if (group.OwnerKind == format.AdministrativePublicationCoordinate || group.OwnerKind == format.AdministrativePublicationMarker) && group.EffectEntryCeiling != 0 {
			after |= WarningPublicationOrderValue
		}
		if group.OwnerKind == format.AdministrativeGC {
			after |= WarningPossibleStoreGarbage
		}
		if group.DestructiveEffect != 0 {
			after |= WarningLateDestructiveEffect
		}
	}
	if possibleStoreGarbage {
		after |= WarningPossibleStoreGarbage
	}
	return after
}

func endWorkSupportPage(domain, object contract.ID, index uint16, rows []contract.SupportRecord,
	plan *contract.CompactMutationReceiptPlan) (format.Ref, format.RequiredSupportPageView, []byte, error) {
	page := format.RequiredSupportPage{Domain: domain, Object: object, Index: index, Records: rows}
	var body []byte
	var err error
	if plan != nil {
		body, err = format.EncodeRequiredSupportReceiptPlan(page, *plan)
	} else {
		body, err = format.EncodeRequiredSupportPage(page)
	}
	if err != nil {
		return format.Ref{}, format.RequiredSupportPageView{}, nil, err
	}
	ref := format.Ref{Kind: contract.RequiredSupportKind, Format: format.Version, Domain: domain,
		Object: object, Index: index, Digest: contract.Hash(body), Length: uint32(len(body))}
	if plan == nil {
		ref, err = format.Reference(contract.RequiredSupportKind, domain, object, index, body)
		if err != nil {
			return format.Ref{}, format.RequiredSupportPageView{}, nil, err
		}
	} else if !ref.ValidFor(format.Version) {
		return format.Ref{}, format.RequiredSupportPageView{}, nil, contract.ErrRecord
	}
	view := format.RequiredSupportPageView{Domain: domain, Object: object, Index: index}
	for _, row := range rows {
		view.Records = append(view.Records, contract.SupportRecordView(row))
	}
	return ref, view, body, nil
}

func endWorkIndexPage(ref format.Ref, rows []contract.SupportRecord) format.AdministrativePage {
	page := format.AdministrativePage{Ref: ref, Spans: []format.AdministrativeSpan{{First: 0, Count: uint16(len(rows)), Mandatory: true}}}
	for _, row := range rows {
		page.Rows = append(page.Rows, format.AdministrativeRowSummary{Kind: row.Kind, RecordID: row.RecordID, BodyLength: uint32(len(row.Body))})
	}
	return page
}

func endWorkReceiptIndexRow(domain contract.ID, indexes contract.MutationReceiptIndexes) (contract.SupportRecord, contract.ID, error) {
	successes, failures, order, err := indexes.Descriptors()
	if err != nil {
		return contract.SupportRecord{}, contract.ID{}, err
	}
	id, err := contract.MutationReceiptIndexBlobID(domain, successes, failures, order)
	if err != nil {
		return contract.SupportRecord{}, contract.ID{}, err
	}
	body, err := contract.EncodeMutationReceiptIndexes(indexes)
	if err != nil {
		return contract.SupportRecord{}, contract.ID{}, err
	}
	fragment, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: 1, BlobID: id, Count: 1,
		TotalLength: uint64(len(body)), WholeDigest: contract.Hash(body), Payload: body})
	if err != nil {
		return contract.SupportRecord{}, contract.ID{}, err
	}
	fragmentID, err := contract.GeneratorFragmentID(id, 0)
	if err != nil {
		return contract.SupportRecord{}, contract.ID{}, err
	}
	return contract.SupportRecord{Kind: contract.GeneratedFragmentSupportKind, RecordID: fragmentID, Body: fragment}, id, nil
}

func endWorkFreePageIndexes(index format.AdministrativeIndex) (uint16, uint16, error) {
	var used [contract.MaxChildPages]bool
	for _, page := range index.Pages {
		used[page.Ref.Index] = true
	}
	var free []uint16
	for i, occupied := range used {
		if !occupied {
			free = append(free, uint16(i))
			if len(free) == 2 {
				return free[0], free[1], nil
			}
		}
	}
	return 0, 0, contract.ErrRecordCapacity
}

func endWorkReplacedSupport(before, after format.AdministrativeIndex) bool {
	for _, page := range before.Pages {
		if !slices.ContainsFunc(after.Pages, func(kept format.AdministrativePage) bool { return kept.Ref == page.Ref }) {
			return true
		}
	}
	return false
}

func endWorkPossibleStoreGarbage(before, after format.AdministrativeIndex) bool {
	if endWorkReplacedSupport(before, after) {
		return true
	}
	// An Attempt or release row can lose its local inbox mapping while its
	// immutable support page remains selected for another owner. The inbox
	// object may still exist in Store; this does not assert its deletion.
	for _, old := range before.Pages {
		if old.ReadRequired {
			continue
		}
		now := slices.IndexFunc(after.Pages, func(page format.AdministrativePage) bool { return page.Ref == old.Ref })
		row := 0
		for _, span := range old.Spans {
			for physical := uint32(span.First); physical < uint32(span.First)+uint32(span.Count); physical++ {
				summary := old.Rows[row]
				row++
				if summary.Kind != contract.GeneratedAttemptSupportKind && summary.Kind != contract.PendingInboxReleaseSupportKind {
					continue
				}
				if _, selected := administrativeSelectedOrdinal(after.Pages[now], uint16(physical)); !selected {
					return true
				}
			}
		}
	}
	return false
}

func (s *StateSession) deriveEndWorkCandidate(ctx context.Context, groupID contract.ID, ids endWorkIDs) (*Candidate, *StateSession, error) {
	if s == nil || groupID.IsZero() || s.admission.endWorkInvocation.IsZero() ||
		ids.operation.IsZero() || ids.transition.IsZero() || ids.snapshot.IsZero() ||
		ids.revision.IsZero() || ids.receipts.IsZero() || ids.receiptIndex.IsZero() {
		return nil, nil, fmt.Errorf("end selected work: input identities: %w", contract.ErrRecord)
	}
	groupPosition := slices.IndexFunc(s.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == groupID })
	if groupPosition < 0 {
		return nil, nil, fmt.Errorf("end selected work: input identities: %w", contract.ErrRecord)
	}
	group := s.adminIndex.Groups[groupPosition]
	work, endedGroups, err := s.administrativeWorkClosure(groupID)
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: administrativeWorkClosure: %w", err)
	}
	beforeWindows, err := s.receiptWindowsFromAdministrativeSupport()
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: receiptWindowsFromAdministrativeSupport: %w", err)
	}
	work, err = s.administrativeWorkWithoutOldReceipts(work)
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: administrativeWorkWithoutOldReceipts: %w", err)
	}
	intentPlan, err := s.planAdministrativeCurrentIntents(ctx, work)
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: read retained current intents: %w", err)
	}
	compactIntents := intentPlan.changed && len(intentPlan.dropBlobs) != 0
	var intentOwners []uint16
	if compactIntents {
		intentOwners, err = s.prepareAdministrativeIntentRemoval(&work, intentPlan)
		if err != nil {
			return nil, nil, fmt.Errorf("end selected work: prepareAdministrativeIntentRemoval: %w", err)
		}
	}
	retainedAccess, err := s.endWorkAccessRows(ctx, work)
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: endWorkAccessRows: %w", err)
	}
	reboundImages, reboundViews, err := s.rebindEndWorkPublication(ctx, &work, endedGroups, ids)
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: publication disposition: %w", err)
	}
	projected, selected, err := s.administrativeGeneratedProjection(work)
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: generated projection: %w", err)
	}
	if compactIntents {
		intentSelection, err := s.administrativeCurrentIntentSelection(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("end selected work: read retained current intents: %w", err)
		}
		intentImages, intentViews, directory, added, err := s.addAdministrativeCurrentIntentBlob(ctx, &work, ids, intentSelection, intentPlan, intentOwners)
		if err != nil {
			return nil, nil, fmt.Errorf("end selected work: build retained intent pages: %w", err)
		}
		if reboundImages == nil {
			reboundImages = make(map[format.Ref]objectImage)
		}
		if reboundViews == nil {
			reboundViews = make(map[format.Ref]format.RequiredSupportPageView)
		}
		for ref, image := range intentImages {
			if _, duplicate := reboundImages[ref]; duplicate {
				return nil, nil, fmt.Errorf("end selected work: duplicate retained intent image: %w", contract.ErrRecord)
			}
			reboundImages[ref] = image
		}
		for ref, view := range intentViews {
			if _, duplicate := reboundViews[ref]; duplicate {
				return nil, nil, fmt.Errorf("end selected work: duplicate retained intent view: %w", contract.ErrRecord)
			}
			reboundViews[ref] = view
		}
		projected.Fragments = append(projected.Fragments, directory...)
		slices.SortFunc(projected.Fragments, func(a, b format.FragmentLocation) int {
			if c := bytes.Compare(a.BlobID[:], b.BlobID[:]); c != 0 {
				return c
			}
			return int(a.FragmentIndex) - int(b.FragmentIndex)
		})
		selected += added
		projected.Slices, err = generatedProjectedSliceDescriptor(intentPlan.after)
		if err != nil {
			return nil, nil, fmt.Errorf("end selected work: generatedProjectedSliceDescriptor: %w", err)
		}
	}
	if projected.Slices == s.root.Generated.Slices {
		// The old snapshot still owns the exact selected Slice vector. An exit
		// that removes no location can retain its authenticated page refs.
		if reboundViews == nil {
			reboundViews = make(map[format.Ref]format.RequiredSupportPageView)
		}
		for _, page := range work.Pages {
			if !page.ReadRequired {
				continue
			}
			view, err := s.administrativeSelectedSupportPage(page)
			if err != nil {
				return nil, nil, fmt.Errorf("end selected work: administrativeSelectedSupportPage: %w", err)
			}
			reboundViews[page.Ref] = view
		}
	} else {
		var sliceImages map[format.Ref]objectImage
		var sliceViews map[format.Ref]format.RequiredSupportPageView
		if compactIntents {
			sliceImages, sliceViews, err = s.rebindEndWorkSlices(&work, ids.snapshot, ids.operation, projected.Slices, intentPlan.after)
		} else {
			sliceImages, sliceViews, err = s.rebindEndWorkSlices(&work, ids.snapshot, ids.operation, projected.Slices)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("end selected work: rebindEndWorkSlices: %w", err)
		}
		if reboundImages == nil {
			reboundImages = make(map[format.Ref]objectImage)
		}
		if reboundViews == nil {
			reboundViews = make(map[format.Ref]format.RequiredSupportPageView)
		}
		for ref, image := range sliceImages {
			reboundImages[ref] = image
		}
		for ref, view := range sliceViews {
			reboundViews[ref] = view
		}
	}
	removed, err := s.removedAdministrativeSupport(work)
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: removedAdministrativeSupport: %w", err)
	}
	next := *s
	next.cache, next.accessLocations, next.valueReaders = nil, nil, nil
	next.root = s.root
	accessImages, err := s.endWorkAccessSuccessor(&next, retainedAccess, ids.operation, ids.transition)
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: endWorkAccessSuccessor: %w", err)
	}
	valueImages, pointerClears, err := s.endWorkValueSuccessor(&next, endedGroups, ids.operation)
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: endWorkValueSuccessor: %w", err)
	}
	next.root.Snapshot, next.root.Transition = ids.snapshot, ids.transition
	next.root.Generated = projected
	next.root.GCPlans, err = format.GCPlansDescriptor(work)
	if err != nil {
		return nil, nil, err
	}
	if slices.ContainsFunc(endedGroups, func(group format.AdministrativeGroup) bool { return group.GroupID == next.root.ActiveGC }) {
		next.root.ActiveGC = contract.ID{}
	}
	next.root.RequiredSupport, next.support = nil, nil
	for _, page := range work.Pages {
		view, rebound := reboundViews[page.Ref]
		if !rebound {
			view, err = s.administrativeSelectedSupportPage(page)
			if err != nil {
				return nil, nil, fmt.Errorf("end selected work: administrativeSelectedSupportPage: %w", err)
			}
		}
		next.root.RequiredSupport = append(next.root.RequiredSupport, page.Ref)
		next.support = append(next.support, view)
	}
	if err := rechargeEndWorkGroups(&work, reboundViews); err != nil {
		return nil, nil, fmt.Errorf("end selected work: rechargeEndWorkGroups: %w", err)
	}
	next.root.RequiredSupportRecordCount = selected
	work.Object = administrativeIndexObject(s.root.Domain, ids.snapshot)
	first, second, err := endWorkFreePageIndexes(work)
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: endWorkFreePageIndexes: %w", err)
	}
	changedID, err := contract.ChangedSubjectIdentityID(s.root.Domain, contract.ChangedSubjectSelectedWork, group.GroupID, group.OwnerID)
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: ChangedSubjectIdentityID: %w", err)
	}
	changed, err := contract.ChangedSubjectDescriptor([]contract.ChangedSubjectIdentity{{Kind: contract.ChangedSubjectSelectedWork,
		Change: contract.ChangedSubjectRemoved, Identity: changedID}})
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: ChangedSubjectDescriptor: %w", err)
	}
	next.root.WarningBits = endWorkWarningBits(s.root.WarningBits, endedGroups, endWorkPossibleStoreGarbage(s.adminIndex, work))
	receipt := contract.CompactMutationReceiptPlan{Schema: contract.MutationReceiptSchema,
		OperationKind: contract.OperationEndSelectedWork, StateResult: contract.ReceiptStateWorkEnded,
		EffectSummary: contract.ReceiptEffectNotApplicable, EvidenceCeiling: contract.ReceiptEvidenceCanonical,
		DomainID: s.root.Domain, OperationID: ids.operation,
		PredecessorRevisionID: s.head.Core.Revision, RequestedRevisionID: ids.revision, ObservedRevisionID: ids.revision,
		CanonicalOutcome: contract.ReceiptCanonicalSelected, ChangedSubjects: changed,
		CompleteResult: contract.GeneratorDescriptor{Digest: ids.operation, Length: 8 + contract.MutationResultProjectionLength, Count: 1},
		WarningBits:    uint64(next.root.WarningBits), AdministrativeTargetKind: group.OwnerKind,
		AdministrativeTargetID: group.TargetID, AdministrativeGroupID: group.GroupID, AdministrativeDisposition: ids.operation,
		AdministrativeOriginalEvidence: group.SelectedEvidenceSummary,
		AdministrativeWarningChanges:   next.root.WarningBits &^ s.root.WarningBits}
	delta := contract.MutationReceiptDeltaPlan{DomainID: s.root.Domain, OperationKind: contract.OperationEndSelectedWork,
		AddedCount: 1, Before: beforeWindows, NewReceipt: receipt}
	plannedRows, err := delta.AfterSupportRecords()
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: AfterSupportRecords: %w", err)
	}
	indexes, err := delta.AfterIndexes()
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: AfterIndexes: %w", err)
	}
	fragment, blobID, err := endWorkReceiptIndexRow(s.root.Domain, indexes)
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: endWorkReceiptIndexRow: %w", err)
	}
	planRef, _, _, err := endWorkSupportPage(s.root.Domain, ids.receipts, first, plannedRows, &receipt)
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: endWorkSupportPage: %w", err)
	}
	indexRef, indexView, indexBody, err := endWorkSupportPage(s.root.Domain, ids.receiptIndex, second, []contract.SupportRecord{fragment}, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: endWorkSupportPage: %w", err)
	}
	work.Pages = append(work.Pages, endWorkIndexPage(planRef, plannedRows), endWorkIndexPage(indexRef, []contract.SupportRecord{fragment}))
	slices.SortFunc(work.Pages, func(a, b format.AdministrativePage) int { return int(a.Ref.Index) - int(b.Ref.Index) })
	next.root.RequiredSupport = append(next.root.RequiredSupport, planRef, indexRef)
	next.support = append(next.support,
		format.RequiredSupportPageView{Domain: s.root.Domain, Object: ids.receipts, Index: first}, indexView)
	for i := 1; i < len(next.root.RequiredSupport); i++ {
		for j := i; j > 0 && next.root.RequiredSupport[j-1].Index > next.root.RequiredSupport[j].Index; j-- {
			next.root.RequiredSupport[j-1], next.root.RequiredSupport[j] = next.root.RequiredSupport[j], next.root.RequiredSupport[j-1]
			next.support[j-1], next.support[j] = next.support[j], next.support[j-1]
		}
	}
	next.root.RequiredSupportRecordCount += uint32(len(plannedRows) + 1)
	next.root.Generated.SuccessWindow, next.root.Generated.FailureWindow, next.root.Generated.ReceiptOrder, err = indexes.Descriptors()
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: Descriptors: %w", err)
	}
	next.root.Generated.Fragments = append(next.root.Generated.Fragments,
		format.FragmentLocation{BlobID: blobID, SupportPageIndex: second, RowSlot: 0})
	slices.SortFunc(next.root.Generated.Fragments, func(a, b format.FragmentLocation) int {
		if c := bytes.Compare(a.BlobID[:], b.BlobID[:]); c != 0 {
			return c
		}
		return int(a.FragmentIndex) - int(b.FragmentIndex)
	})
	plannedShards, err := format.EncodeAdministrativeIndexPages(work)
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: EncodeAdministrativeIndexPages: %w", err)
	}
	next.root.AdministrativeIndex = plannedShards[0].Ref
	next.root.AdministrativeIndexShards = nil
	for _, shard := range plannedShards[1:] {
		next.root.AdministrativeIndexShards = append(next.root.AdministrativeIndexShards, shard.Ref)
	}
	next.recountChildren()
	if next.root.ChildCount > contract.MaxChildPages {
		return nil, nil, fmt.Errorf("end selected work: EncodeAdministrativeIndexPages: %w", contract.ErrRecordCapacity)
	}
	preserved, err := administrativePreservedCurrent(s.root, s.pages, retainedAccess, pointerClears)
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: administrativePreservedCurrent: %w", err)
	}
	afterPreserved, err := administrativePreservedCurrent(next.root, next.pages, next.generatedCoverageRecords(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: administrativePreservedCurrent: %w", err)
	}
	if preserved != afterPreserved {
		return nil, nil, fmt.Errorf("end selected work: administrativePreservedCurrent: %w", contract.ErrRecord)
	}
	endedIDs := make([][]byte, 0, len(endedGroups))
	for _, ended := range endedGroups {
		endedIDs = append(endedIDs, ended.GroupID[:])
	}
	q := contract.EndWorkSubject{Schema: contract.CanonicalSchema, DomainID: s.root.Domain,
		OperationID: ids.operation, AdmissionID: s.admission.endWorkInvocation,
		PredecessorRevisionID: s.head.Core.Revision, PredecessorFullHEADDigest: contract.Hash(s.body),
		PredecessorToken: s.token, TargetGroupID: group.GroupID, TargetOwnerID: group.OwnerID, TargetID: group.TargetID,
		TargetKind: group.OwnerKind, DutyKind: group.DutyKind, SelectedEvidenceSummary: group.SelectedEvidenceSummary,
		DependentGroups: administrativeDescriptor("ended-groups", endedIDs...), RemovedSupport: removed,
		PreservedCurrent: preserved, BeforeWarningBits: s.root.WarningBits, AfterWarningBits: next.root.WarningBits,
		BeforeAccessRoot: s.root.CurrentAccess.AccessRoot, AfterAccessRoot: next.root.CurrentAccess.AccessRoot,
		BeforeAccessIncarnationID: s.root.CurrentAccess.Core.AccessIncarnationID,
		AfterAccessIncarnationID:  next.root.CurrentAccess.Core.AccessIncarnationID,
		BeforeAccessGeneration:    s.root.CurrentAccess.Core.AccessGeneration,
		AfterAccessGeneration:     next.root.CurrentAccess.Core.AccessGeneration,
		BeforeChildCount:          uint16(s.root.ChildCount), AfterChildCount: uint16(next.root.ChildCount),
		BeforeChildBytes: s.root.ChildEncodedBytes, AfterChildBytes: next.root.ChildEncodedBytes}
	q.RequestCoreDigest, err = contract.EndWorkRequestCoreDigest(q)
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: EndWorkRequestCoreDigest: %w", err)
	}
	receipt.RequestIdentityDigest, receipt.AdministrativeDisposition = q.RequestCoreDigest, q.RequestCoreDigest
	receipt.AdministrativePageDelta = int16(q.AfterChildCount) - int16(q.BeforeChildCount)
	receipt.AdministrativeByteDelta = int64(q.AfterChildBytes) - int64(q.BeforeChildBytes)
	projection := receipt
	projection.RequestIdentityDigest, projection.CompleteResult = contract.ID{}, contract.GeneratorDescriptor{}
	empty := contract.EmptyMutationResultDescriptors()
	receipt.CompleteResult, err = contract.CompleteMutationResultDescriptor(contract.MutationResultProjection{
		Receipt: projection, RequestCoreDigest: q.RequestCoreDigest,
		ChangedAccess: empty[0], Effects: empty[1], Outputs: empty[2], Duties: empty[3], Hazards: empty[4]})
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: CompleteMutationResultDescriptor: %w", err)
	}
	actual := contract.CompactMutationReceipt(receipt)
	afterWindows, err := contract.AppendMutationReceipt(beforeWindows, actual)
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: AppendMutationReceipt: %w", err)
	}
	q.ReceiptDeltaDigest, err = contract.MutationReceiptDeltaDigest(contract.MutationReceiptDelta{DomainID: s.root.Domain,
		OperationKind: contract.OperationEndSelectedWork, AddedCount: 1, Before: beforeWindows, After: afterWindows})
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: MutationReceiptDeltaDigest: %w", err)
	}
	rows, err := afterWindows.SupportRecords()
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: SupportRecords: %w", err)
	}
	receiptRef, receiptView, receiptBody, err := endWorkSupportPage(s.root.Domain, ids.receipts, first, rows, nil)
	if err != nil || receiptRef.Length != planRef.Length {
		return nil, nil, fmt.Errorf("end selected work: endWorkSupportPage: %w", contract.ErrRecord)
	}
	for i := range work.Pages {
		if work.Pages[i].Ref == planRef {
			work.Pages[i] = endWorkIndexPage(receiptRef, rows)
		}
	}
	for i := range next.root.RequiredSupport {
		if next.root.RequiredSupport[i] == planRef {
			next.root.RequiredSupport[i] = receiptRef
			next.support[i] = receiptView
		}
	}
	shards, err := format.EncodeAdministrativeIndexPages(work)
	if err != nil || len(shards) != len(plannedShards) {
		return nil, nil, fmt.Errorf("end selected work: EncodeAdministrativeIndexPages: %w", contract.ErrRecord)
	}
	next.adminIndex = work
	next.root.AdministrativeIndex = shards[0].Ref
	next.root.AdministrativeIndexShards = nil
	candidate := &Candidate{session: s, endWorkReceipt: actual}
	candidate.objects = append(candidate.objects, accessImages...)
	candidate.objects = append(candidate.objects, valueImages...)
	for _, page := range work.Pages {
		if image, ok := reboundImages[page.Ref]; ok {
			candidate.objects = append(candidate.objects, image)
		}
	}
	candidate.objects = append(candidate.objects, objectImage{ref: receiptRef, body: receiptBody}, objectImage{ref: indexRef, body: indexBody})
	for _, shard := range shards {
		candidate.objects = append(candidate.objects, objectImage{ref: shard.Ref, body: shard.Body})
		if shard.Ref.Index != 0 {
			next.root.AdministrativeIndexShards = append(next.root.AdministrativeIndexShards, shard.Ref)
		}
	}
	next.recountChildren()
	if next.root.ChildCount != uint32(q.AfterChildCount) || next.root.ChildEncodedBytes != q.AfterChildBytes {
		return nil, nil, fmt.Errorf("end selected work: EncodeAdministrativeIndexPages: %w", contract.ErrRecord)
	}
	if err := s.bindEndWorkSupportFacts(&next, candidate.objects); err != nil {
		return nil, nil, fmt.Errorf("end selected work: selected support binding: %w", err)
	}
	if s.fragmentFacts == nil {
		// Body-backed fixture construction has no authenticated physical facts.
		// The legacy binder can assign compact ordinals only to compact new pages.
		for i, page := range next.adminIndex.Pages {
			if slices.Contains(s.root.RequiredSupport, page.Ref) {
				continue
			}
			physical := uint32(0)
			for _, span := range page.Spans {
				if uint32(span.First) != physical {
					return nil, nil, fmt.Errorf("end selected work: sparse unbound support: %w", contract.ErrRecord)
				}
				physical += uint32(span.Count)
			}
			if i >= len(next.support) || physical != uint32(len(next.support[i].Records)) {
				return nil, nil, fmt.Errorf("end selected work: unbound support count: %w", contract.ErrRecord)
			}
		}
		if err := s.bindPreservedOutputConfiguration(&next); err != nil {
			return nil, nil, fmt.Errorf("end selected work: bindPreservedOutputConfiguration: %w", err)
		}
	} else {
		if err := s.validatePreservedOutputConfiguration(&next); err != nil {
			return nil, nil, fmt.Errorf("end selected work: preserved output: %w", err)
		}
		root, err := format.EncodeRoot(next.root)
		if err != nil {
			return nil, nil, fmt.Errorf("end selected work: preserved output root: %w", err)
		}
		next.outputConfigurationRoot, next.publicationProof = contract.Hash(root), nil
	}
	// Complete publication proof is deliberately not issued by a partial exit.
	coordinates, err := next.publicationCoordinatesForDisposition()
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: publication coordinate relation: %w", err)
	}
	if _, err := publicationIncarnationOrder(next.adminIndex, coordinates, false); err != nil {
		return nil, nil, fmt.Errorf("end selected work: publication order relation: %w", err)
	}
	// An administrative successor can itself have another selected exit. Check
	// its first-exit allowance from the final authenticated receipt and index,
	// so repeated exits do not spend the reserved margin cumulatively.
	if err := next.reserveFirstEndWork(ctx); err != nil {
		return nil, nil, fmt.Errorf("end selected work: successor exit capacity: %w", err)
	}
	rootBody, err := format.EncodeRoot(next.root)
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: EncodeRoot: %w", err)
	}
	rootRef, err := format.Reference(format.RootKind, s.root.Domain, ids.snapshot, 0, rootBody)
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: Reference: %w", err)
	}
	candidate.objects = append(candidate.objects, objectImage{ref: rootRef, body: rootBody})
	head := s.successorCore(transitionPlan{revision: ids.revision})
	head.Root = rootRef
	coreBody, err := format.EncodeHeadCore(head)
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: EncodeHeadCore: %w", err)
	}
	q.HeadCoreDigest, q.HeadCoreLength = contract.Hash(coreBody), uint32(len(coreBody))
	condition, err := format.EncodeConditionalPlan(conditional(head, coreBody))
	if err != nil {
		return nil, nil, fmt.Errorf("end selected work: EncodeConditionalPlan: %w", err)
	}
	q.ConditionalPlanDigest = contract.Hash(condition)
	if _, err := contract.EncodeEndWorkSubject(q); err != nil {
		return nil, nil, fmt.Errorf("end selected work: EncodeEndWorkSubject: %w", err)
	}
	candidate.head = format.Head{Core: head, AuthKind: format.AdministrativeAuth, EndWork: &q,
		K1: bytes.Clone(s.head.K1), K3: bytes.Clone(s.head.K3)}
	next.head = candidate.head
	if !next.validEndWorkSelection() || !ordinaryCandidateCapacity(candidate) {
		return nil, nil, fmt.Errorf("end selected work: EncodeEndWorkSubject: %w", contract.ErrRecord)
	}
	return candidate, &next, nil
}

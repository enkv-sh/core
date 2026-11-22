package core

import (
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// The plan owns signed widths and the exact physical peers that a publication
// rewrite must retain. Missing optional detail supplies capacity, never action
// authority or a body that the ordinary encoders can consume.
type publicationRewritePlan struct {
	predecessor          contract.ID
	index                format.Ref
	indexBytes           uint64
	work                 format.AdministrativeIndex
	widths               map[generatedRecordKey]uint64
	peers                []format.AdministrativePage
	framed, maximumWidth uint64
	oldPages             uint32
	unresolved           bool
}

type publicationCapacity struct {
	pages                                  uint32
	framedBytes, physicalBytes, indexBytes uint64
	pageDelta                              int64
}

func publicationPageBound(count, framed, width uint64) (uint32, error) {
	pages, err := publicationPageCapacityBound(count, framed, width)
	if err != nil {
		return 0, err
	}
	if pages > contract.MaxChildPages {
		return 0, contract.ErrRecordCapacity
	}
	return uint32(pages), nil
}

func publicationPageCapacityBound(count, framed, width uint64) (uint64, error) {
	if count == 0 {
		if framed != 0 || width != 0 {
			return 0, contract.ErrRecord
		}
		return 0, nil
	}
	payload := uint64(contract.MaxRequiredSupportPageLength - contract.RequiredSupportPageHeaderLength)
	if width == 0 || width > uint64(format.RequiredSupportGroupLimit(format.OwnerSupport)) || framed < width {
		return 0, contract.ErrRecordCapacity
	}
	// Subtraction follows nonzero validation. Division precedes addition, and
	// a count of at most two needs no possibly overflowing slack addition.
	if count <= 2 {
		return count, nil
	}
	packed := (framed - 1) / (payload - width + 1)
	if packed >= count-2 {
		return count, nil
	}
	return packed + 2, nil
}

func clonePublicationWork(index format.AdministrativeIndex) format.AdministrativeIndex {
	if index.Groups != nil {
		groups := make([]format.AdministrativeGroup, len(index.Groups))
		copy(groups, index.Groups)
		index.Groups = groups
	}
	for i := range index.Groups {
		index.Groups[i] = index.Groups[i].Own()

	}
	if index.Pages != nil {
		pages := make([]format.AdministrativePage, len(index.Pages))
		copy(pages, index.Pages)
		index.Pages = pages
	}
	for i := range index.Pages {
		if index.Pages[i].Rows != nil {
			rows := make([]format.AdministrativeRowSummary, len(index.Pages[i].Rows))
			copy(rows, index.Pages[i].Rows)
			index.Pages[i].Rows = rows
		}
		if index.Pages[i].Spans != nil {
			spans := make([]format.AdministrativeSpan, len(index.Pages[i].Spans))
			copy(spans, index.Pages[i].Spans)
			index.Pages[i].Spans = spans
		}
		for j := range index.Pages[i].Spans {
			if index.Pages[i].Spans[j].GroupIndexes != nil {
				groups := make([]uint16, len(index.Pages[i].Spans[j].GroupIndexes))
				copy(groups, index.Pages[i].Spans[j].GroupIndexes)
				index.Pages[i].Spans[j].GroupIndexes = groups
			}
		}
	}
	if index.PublicationOrder != nil {
		order := make([]format.PublicationCoordinateOrder, len(index.PublicationOrder))
		copy(order, index.PublicationOrder)
		index.PublicationOrder = order
	}
	for i := range index.PublicationOrder {
		if index.PublicationOrder[i].Incarnations != nil {
			ids := make([]contract.ID, len(index.PublicationOrder[i].Incarnations))
			copy(ids, index.PublicationOrder[i].Incarnations)
			index.PublicationOrder[i].Incarnations = ids
		}
	}
	return index
}

func samePublicationWork(a, b format.AdministrativeIndex) bool {
	if a.Domain != b.Domain || a.Object != b.Object || a.SliceSnapshot != b.SliceSnapshot ||
		(a.Groups == nil) != (b.Groups == nil) || len(a.Groups) != len(b.Groups) ||
		(a.Pages == nil) != (b.Pages == nil) || len(a.Pages) != len(b.Pages) ||
		(a.PublicationOrder == nil) != (b.PublicationOrder == nil) || len(a.PublicationOrder) != len(b.PublicationOrder) {
		return false
	}
	for i := range a.Groups {
		left, right := &a.Groups[i], &b.Groups[i]
		if left.GroupID != right.GroupID || left.OwnerID != right.OwnerID || left.TargetID != right.TargetID ||
			left.OwnerKind != right.OwnerKind || left.DutyKind != right.DutyKind || left.EffectEntryCeiling != right.EffectEntryCeiling ||
			left.SelectedEvidenceSummary != right.SelectedEvidenceSummary || left.DestructiveEffect != right.DestructiveEffect ||
			left.UncertainCreateProof != right.UncertainCreateProof || left.ReferencesOwnedBirth != right.ReferencesOwnedBirth || left.Affected != right.Affected ||
			left.Dependencies != right.Dependencies || left.Disposable != right.Disposable ||
			left.ChargedPages != right.ChargedPages || left.ChargedBytes != right.ChargedBytes ||
			left.PublicationIncarnationID != right.PublicationIncarnationID || left.AdmissionOrdinal != right.AdmissionOrdinal || !format.SameGCProgress(left.GC, right.GC) ||
			(left.RelatedGroupIndexes == nil) != (right.RelatedGroupIndexes == nil) || !slices.Equal(left.RelatedGroupIndexes, right.RelatedGroupIndexes) {
			return false
		}
	}
	for i := range a.Pages {
		left, right := a.Pages[i], b.Pages[i]
		if (left.Rows == nil) != (right.Rows == nil) || (left.Spans == nil) != (right.Spans == nil) || !samePublicationPage(left, right) {
			return false
		}
		for j := range left.Spans {
			if (left.Spans[j].GroupIndexes == nil) != (right.Spans[j].GroupIndexes == nil) {
				return false
			}
		}
	}
	for i, left := range a.PublicationOrder {
		right := b.PublicationOrder[i]
		if left.CoordinateID != right.CoordinateID || (left.Incarnations == nil) != (right.Incarnations == nil) || !slices.Equal(left.Incarnations, right.Incarnations) {
			return false
		}
	}
	return true
}

func (s *StateSession) publicationWorkIsSelected(work format.AdministrativeIndex) bool {
	if samePublicationWork(s.adminIndex, work) {
		return true
	}
	retained := make(map[contract.ID]bool, len(work.Groups))
	for _, group := range work.Groups {
		retained[group.GroupID] = true
	}
	for _, group := range s.adminIndex.Groups {
		if retained[group.GroupID] {
			continue
		}
		closure, _, err := s.administrativeWorkClosure(group.GroupID)
		if err != nil {
			continue
		}
		closure, err = s.administrativeWorkWithoutOldReceipts(closure)
		if err == nil && samePublicationWork(closure, work) {
			return true
		}
	}
	return false
}

func publicationMarkerEvidence(marker contract.PublicationMarker) uint16 {
	var bits uint16
	switch marker.State {
	case contract.PublicationMayHaveEntered, contract.PublicationUnknown:
		bits = contract.AdministrativeEvidenceQualifiedUnknown
	case contract.PublicationAcknowledged:
		bits = contract.AdministrativeEvidenceAcknowledged
	case contract.PublicationQualifiedNoEffectState:
		bits = contract.AdministrativeEvidenceConfirmed
	}
	if marker.LateEffectRisk != 0 {
		bits |= contract.AdministrativeEvidencePossibleLive
	}
	return bits
}

func (s *StateSession) planPublicationRewrite(ctx context.Context, work format.AdministrativeIndex) (*publicationRewritePlan, error) {
	return s.publicationRewritePlan(ctx, work, true)
}

// Full generated admission validates selected publication support separately
// from generated byte accounting. Only scalar charges outlive the borrowed plan.
func (s *StateSession) generatedPublicationCapacity(ctx context.Context,
	groups [contract.GeneratorCapacityGroupCount]contract.GeneratorCapacityGroup) ([contract.GeneratorCapacityGroupCount]contract.GeneratorCapacityGroup, error) {
	var empty [contract.GeneratorCapacityGroupCount]contract.GeneratorCapacityGroup
	if s == nil {
		return empty, contract.ErrRecord
	}
	publication, err := s.publicationRewritePlan(ctx, s.adminIndex, false)
	if err != nil {
		return empty, err
	}
	if publication.unresolved {
		future, err := publication.capacity()
		if err != nil {
			return empty, err
		}
		owners := &groups[contract.GeneratorCapacityOwners]
		shared, err := publicationPageBound(owners.MaxCount, owners.MaxFramedBytes, min(owners.MaxFramedBytes, uint64(format.RequiredSupportGroupLimit(format.OwnerSupport))))
		if err != nil || uint64(shared)+uint64(future.pages) > contract.MaxChildPages {
			return empty, contract.ErrRecordCapacity
		}
		// The original population stays at its original widths. Its physical
		// pages can retain publication dead bytes beside nonpublication peers.
		owners.MaxPages = shared + future.pages
		owners.MaxFramedBytes += future.framedBytes
	}
	return groups, nil
}

// A retained materialization plan owns the complete input. Synchronous capacity
// checks borrow it only until capacity returns and never publish the plan.
func (s *StateSession) publicationRewritePlan(ctx context.Context, work format.AdministrativeIndex, owned bool) (*publicationRewritePlan, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !s.adminIndex.Valid() || !work.Valid() ||
		s.adminIndex.Domain != s.root.Domain || s.adminIndex.Object != s.root.AdministrativeIndex.Object ||
		!s.publicationWorkIsSelected(work) {
		return nil, contract.ErrRecord
	}
	hasPublication := false
	for _, page := range work.Pages {
		for _, row := range page.Rows {
			if row.Kind == contract.PublicationCoordinateSupportKind || row.Kind == contract.PublicationMarkerSupportKind {
				hasPublication = true
			}
		}
	}
	for _, group := range work.Groups {
		if group.OwnerKind == format.AdministrativePublicationCoordinate || group.OwnerKind == format.AdministrativePublicationMarker {
			hasPublication = true
		}
	}
	for _, page := range s.support {
		for _, row := range page.Records {
			if row.Kind == contract.PublicationCoordinateSupportKind || row.Kind == contract.PublicationMarkerSupportKind {
				hasPublication = true
			}
		}
	}
	length, err := format.AdministrativeIndexEncodedLength(work)
	if err != nil {
		return nil, err
	}
	if !hasPublication {
		return &publicationRewritePlan{predecessor: contract.Hash(s.body), index: s.root.AdministrativeIndex, indexBytes: length}, nil
	}
	_, loaded, err := s.publicationLoadedRowsForDisposition()
	if err != nil {
		return nil, err
	}
	coordinates, err := s.publicationCoordinatesForDisposition()
	if err != nil {
		return nil, err
	}
	return publicationRewritePlanFromFacts(ctx, s.root.Domain, s.root.AdministrativeIndex, contract.Hash(s.body), work, length, loaded, coordinates, owned)
}

func publicationRewritePlanFromFacts(ctx context.Context, domain contract.ID, index format.Ref, predecessor contract.ID, work format.AdministrativeIndex, length uint64, loaded map[generatedRecordKey]selectedPublicationRecord, coordinates map[contract.ID]contract.PublicationCoordinate, owned bool) (*publicationRewritePlan, error) {
	if ctx == nil || !work.Valid() || domain != work.Domain || index.Object != work.Object {
		return nil, contract.ErrRecord
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if owned {
		work = clonePublicationWork(work)
	}
	p := &publicationRewritePlan{predecessor: predecessor, index: index,
		work: work, indexBytes: length, widths: make(map[generatedRecordKey]uint64)}
	selectedGroups := make(map[contract.ID]bool)
	for _, page := range work.Pages {
		logical, hasPublication, peerRows, peerSpans := 0, false, 0, 0
		for _, span := range page.Spans {
			publication := false
			for offset := 0; offset < int(span.Count); offset++ {
				if page.ReadRequired {
					continue
				}
				if logical >= len(page.Rows) {
					return nil, contract.ErrRecord
				}
				row := page.Rows[logical]
				logical++
				if row.Kind != contract.PublicationCoordinateSupportKind && row.Kind != contract.PublicationMarkerSupportKind {
					peerRows++
					continue
				}
				if span.Count != 1 || len(span.GroupIndexes) != 1 || publication {
					return nil, contract.ErrRecord
				}
				publication, hasPublication = true, true
				group := work.Groups[span.GroupIndexes[0]]
				if group.GroupID != row.RecordID || selectedGroups[row.RecordID] {
					return nil, contract.ErrRecord
				}
				selectedGroups[row.RecordID] = true
				key := generatedRecordKey{row.Kind, row.RecordID}
				actual, present := loaded[key]
				width := uint64(contract.SupportRecordOverhead) + uint64(row.BodyLength)
				if present && actual.digest.BodyLength() != row.BodyLength {
					return nil, contract.ErrRecord
				}
				if row.Kind == contract.PublicationCoordinateSupportKind {
					coordinate, ok := coordinates[row.RecordID]
					if !ok || !present || !span.Mandatory || group.OwnerKind != format.AdministrativePublicationCoordinate ||
						group.SelectedEvidenceSummary != publicationCoordinateEvidence(coordinate) {
						return nil, contract.ErrRecord
					}
					if coordinate.LocatorRequiresCreation {
						width += uint64(1024 - len(coordinate.DeletionConsumerLocator))
					}
				} else {
					if group.OwnerKind != format.AdministrativePublicationMarker || group.OwnerID != group.TargetID ||
						coordinates[group.OwnerID].CoordinateID.IsZero() {
						return nil, contract.ErrRecord
					}
					bits := group.SelectedEvidenceSummary &^ contract.AdministrativeEvidencePossibleLive
					if bits != contract.AdministrativeEvidenceQualifiedUnknown && bits != contract.AdministrativeEvidenceAcknowledged &&
						bits != contract.AdministrativeEvidenceConfirmed {
						return nil, contract.ErrRecord
					}
					if present {
						marker := actual.marker
						if marker == nil || marker.DomainID != domain || marker.AttemptID != row.RecordID || marker.CoordinateID != group.OwnerID ||
							marker.PublicationIncarnationID != group.PublicationIncarnationID || marker.AdmissionOrdinal != group.AdmissionOrdinal ||
							publicationMarkerEvidence(*marker) != group.SelectedEvidenceSummary ||
							group.ReferencesOwnedBirth != !marker.Projection.OwnedBirthAttemptID.IsZero() ||
							group.UncertainCreateProof != boolByte(publicationMarkerProvesUncertainCreate(*marker, coordinates[group.OwnerID])) {
							return nil, contract.ErrRecord
						}
					} else if span.Mandatory {
						return nil, contract.ErrRecord
					}
					if bits == contract.AdministrativeEvidenceQualifiedUnknown {
						width += 3072
						p.unresolved = true
					}
				}
				if width > contract.MaxPublicationMarkerRecordBytes || width > uint64(format.RequiredSupportGroupLimit(format.OwnerSupport)) {
					return nil, contract.ErrRecordCapacity
				}
				p.widths[key], p.framed, p.maximumWidth = width, p.framed+width, max(p.maximumWidth, width)
			}
			if !publication {
				peerSpans++
			}
		}
		if hasPublication {
			p.oldPages++
			if page.ReadRequired {
				return nil, contract.ErrRecord
			}
		}
		if peerSpans == 0 {
			continue
		}
		peer := page
		if hasPublication {
			peer.Rows = make([]format.AdministrativeRowSummary, 0, peerRows)
			peer.Spans = make([]format.AdministrativeSpan, 0, peerSpans)
			logical = 0
			for _, span := range page.Spans {
				rows := page.Rows[logical : logical+int(span.Count)]
				logical += int(span.Count)
				if rows[0].Kind == contract.PublicationCoordinateSupportKind || rows[0].Kind == contract.PublicationMarkerSupportKind {
					continue
				}
				peer.Rows = append(peer.Rows, rows...)
				peer.Spans = append(peer.Spans, span)
			}
		}
		p.peers = append(p.peers, peer)
	}
	for _, group := range work.Groups {
		if (group.OwnerKind == format.AdministrativePublicationCoordinate || group.OwnerKind == format.AdministrativePublicationMarker) &&
			!selectedGroups[group.GroupID] {
			return nil, contract.ErrRecord
		}
	}
	return p, nil
}

func (p *publicationRewritePlan) capacity() (publicationCapacity, error) {
	capacity, err := p.capacityBound()
	if err != nil {
		return publicationCapacity{}, err
	}
	if capacity.pages > contract.MaxChildPages {
		return publicationCapacity{}, contract.ErrRecordCapacity
	}
	return capacity, nil
}

func (p *publicationRewritePlan) capacityBound() (publicationCapacity, error) {
	if p == nil {
		return publicationCapacity{}, contract.ErrRecord
	}
	length := p.indexBytes
	capacity := publicationCapacity{indexBytes: length}
	if !p.unresolved {
		return capacity, nil
	}
	pageBound, err := publicationPageCapacityBound(uint64(len(p.widths)), p.framed, p.maximumWidth)
	if err != nil {
		return publicationCapacity{}, err
	}
	if pageBound > uint64(^uint32(0)) {
		return publicationCapacity{}, contract.ErrRecordCapacity
	}
	pages := uint32(pageBound)
	var dropped uint32
	for _, page := range p.work.Pages {
		if !slices.ContainsFunc(p.peers, func(peer format.AdministrativePage) bool { return peer.Ref == page.Ref }) {
			dropped++
		}
	}
	capacity.pages, capacity.framedBytes = pages, p.framed
	capacity.pageDelta = int64(pages) - int64(dropped)
	futureLength := int64(length) + 108*capacity.pageDelta
	if futureLength < 0 {
		return publicationCapacity{}, contract.ErrRecord
	}
	capacity.indexBytes = uint64(futureLength)
	for _, peer := range p.peers {
		capacity.physicalBytes += uint64(peer.Ref.Length)
	}
	capacity.physicalBytes += p.framed + uint64(pages)*contract.RequiredSupportPageHeaderLength
	return capacity, nil
}

func (s *StateSession) reserveOrdinaryPublicationRewrite(ctx context.Context) error {
	_, err := s.reservePublicationRewrite(ctx, s.adminIndex, ordinaryChildPageLimit)
	return err
}

type selectedPublicationCapacityBound struct {
	publicationCapacity
	growth     map[continuationGroupKey]uint64
	unresolved bool
}

// The complete public reader already owns the selected rows. The same rewrite
// calculation used by mutation needs no session, Store or signing authority.
func selectedPublicationCapacity(ctx context.Context, image *selectedImage) (selectedPublicationCapacityBound, error) {
	var out selectedPublicationCapacityBound
	if ctx == nil || image == nil {
		return out, contract.ErrRecord
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	selected, err := selectedPublicationRelation(image)
	if err != nil {
		return out, err
	}
	length, err := format.AdministrativeIndexEncodedLength(image.adminIndex)
	if err != nil {
		return out, err
	}
	loaded := make(map[generatedRecordKey]selectedPublicationRecord)
	for _, page := range image.support {
		for _, row := range page.Records {
			if row.Kind == contract.PublicationCoordinateSupportKind || row.Kind == contract.PublicationMarkerSupportKind {
				fact, err := image.publicationRecord(contract.SupportRecord(row))
				if err != nil {
					return out, err
				}
				loaded[generatedRecordKey{row.Kind, row.RecordID}] = fact
			}
		}
	}
	plan, err := publicationRewritePlanFromFacts(ctx, image.root.Domain, image.root.AdministrativeIndex, contract.ID{}, image.adminIndex, length, loaded, selected.coordinates, false)
	if err != nil {
		return out, err
	}
	out.publicationCapacity, err = plan.capacityBound()
	if err != nil {
		return out, err
	}
	out.unresolved = plan.unresolved
	out.growth = make(map[continuationGroupKey]uint64)
	for _, page := range image.adminIndex.Pages {
		logical := 0
		for _, span := range page.Spans {
			if page.ReadRequired {
				logical += int(span.Count)
				continue
			}
			for n := 0; n < int(span.Count); n++ {
				row := page.Rows[logical]
				logical++
				if row.Kind != contract.PublicationMarkerSupportKind {
					continue
				}
				key := generatedRecordKey{row.Kind, row.RecordID}
				width, ok := plan.widths[key]
				actual := uint64(contract.SupportRecordOverhead + row.BodyLength)
				if !ok || width < actual {
					return out, contract.ErrRecord
				}
				if width != actual {
					out.growth[continuationGroupKey{class: format.OwnerSupport, owner: row.RecordID, mandatory: span.Mandatory}] = width - actual
				}
			}
		}
	}
	return out, nil
}

func (s *StateSession) reservePublicationRewrite(ctx context.Context, work format.AdministrativeIndex, childLimit uint32) (publicationCapacity, error) {
	plan, err := s.publicationRewritePlan(ctx, work, false)
	if err != nil {
		return publicationCapacity{}, err
	}
	capacity, err := plan.capacity()
	if err != nil {
		return publicationCapacity{}, err
	}
	if !plan.unresolved {
		return capacity, nil
	}
	beforeLength, err := format.AdministrativeIndexEncodedLength(work)
	if err != nil {
		return publicationCapacity{}, err
	}
	beforeShards, err := format.AdministrativeIndexShardCount(beforeLength)
	if err != nil {
		return publicationCapacity{}, err
	}
	afterShards, err := format.AdministrativeIndexShardCount(capacity.indexBytes)
	if err != nil {
		return publicationCapacity{}, contract.ErrRecordCapacity
	}
	children := int64(s.root.ChildCount) + capacity.pageDelta + int64(afterShards) - int64(beforeShards)
	if children < 0 || children > int64(childLimit) {
		return publicationCapacity{}, contract.ErrRecordCapacity
	}
	return capacity, nil
}

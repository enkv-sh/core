package core

import (
	"bytes"
	"context"
	"math"
	"slices"
	"sync"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// ReconstructionProjection owns one copy of every accepted encrypted or
// public part. It contains no private admission, plaintext, or Store reach.
// Its backing transfers from one attempt at Commit and is released by Close.
type ReconstructionProjection struct {
	mu              sync.Mutex
	parts           []reconstructionProjectionPart
	signingAnchor   []byte
	provenance      reconstructionProjectionProvenance
	pendingRegistry contract.ID
	sliceSnapshot   contract.ID
	slices          contract.GeneratorDescriptor
	closed          bool
}

// ReconstructionPartKind names one exact selected part in a complete owned
// reconstruction projection. The body is encrypted or public selected bytes.
type ReconstructionPartKind uint8

const (
	ReconstructionConfigurationPart ReconstructionPartKind = ReconstructionPartKind(reconstructionConfigurationPart)
	ReconstructionHEADPart          ReconstructionPartKind = ReconstructionPartKind(reconstructionHEADPart)
	ReconstructionRootPart          ReconstructionPartKind = ReconstructionPartKind(reconstructionRootPart)
	ReconstructionValuePagePart     ReconstructionPartKind = ReconstructionPartKind(reconstructionValuePagePart)
	ReconstructionRecipientPagePart ReconstructionPartKind = ReconstructionPartKind(reconstructionRecipientPagePart)
	ReconstructionAccessPagePart    ReconstructionPartKind = ReconstructionPartKind(reconstructionAccessPagePart)
	ReconstructionIndexPagePart     ReconstructionPartKind = ReconstructionPartKind(reconstructionIndexPagePart)
	ReconstructionSupportRowPart    ReconstructionPartKind = ReconstructionPartKind(reconstructionSupportRowPart)
)

// ReconstructionPart is one caller-owned copy. Editing Body cannot change the
// projection or another copy. PhysicalOrdinal applies only to support rows.
type ReconstructionPart struct {
	Kind            ReconstructionPartKind
	Ref             format.Ref
	PhysicalOrdinal uint16
	SupportKind     contract.SupportRecordKind
	RecordID        contract.ID
	Body            []byte
}

// ReconstructionPartInfo identifies a selected part without copying its body.
type ReconstructionPartInfo struct {
	Kind            ReconstructionPartKind
	Ref             format.Ref
	PhysicalOrdinal uint16
	SupportKind     contract.SupportRecordKind
	RecordID        contract.ID
	BodyLength      uint32
}

// PartInfo permits a caller to skip encrypted or unrelated selected bodies.
func (p *ReconstructionProjection) PartInfo(index int) (ReconstructionPartInfo, bool) {
	if p == nil {
		return ReconstructionPartInfo{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || index < 0 || index >= len(p.parts) {
		return ReconstructionPartInfo{}, false
	}
	v := p.parts[index]
	return ReconstructionPartInfo{Kind: ReconstructionPartKind(v.kind), Ref: v.ref, PhysicalOrdinal: v.physicalOrdinal, SupportKind: v.supportKind, RecordID: v.recordID, BodyLength: uint32(len(v.body))}, true
}

// CopyGeneratedIntent returns only the exact public intent bytes. Selected
// fragment bodies stay borrowed under the projection lock. At most 513 record
// headers, 512 fragment views, one crossing scratch and the returned intent
// coexist; each intent/scratch is at most GeneratorIntentMaxLength bytes.
func (p *ReconstructionProjection) CopyGeneratedIntent(ctx context.Context, digest contract.ID) ([]byte, error) {
	if p == nil || ctx == nil || digest.IsZero() {
		return nil, ErrLocalAuthorityAdmission
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.sliceSnapshot.IsZero() || ctx.Err() != nil {
		return nil, ErrLocalAuthorityAdmission
	}
	body, err := p.generatedSliceLocked(ctx, contract.GeneratorContentIntent, digest, contract.GeneratorIntentMaxLength)
	if err != nil {
		return nil, err
	}
	return bytes.Clone(body), nil
}

// CopyPendingRecipientCreations returns only recipients awaiting first selection
// in the authenticated active apply. They carry preparation facts for a surviving
// declaration. Current recipients come from the selected recipient pages.
func (p *ReconstructionProjection) CopyPendingRecipientCreations(ctx context.Context) ([]contract.ApplyRecipientInput, error) {
	if p == nil || ctx == nil {
		return nil, ErrLocalAuthorityAdmission
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.provenance.domain.IsZero() || ctx.Err() != nil {
		return nil, ErrLocalAuthorityAdmission
	}
	if p.pendingRegistry.IsZero() {
		return nil, nil
	}
	body, err := p.generatedSliceLocked(ctx, contract.GeneratorContentRecipientRegistry, p.pendingRegistry, contract.GeneratedRecipientRegistryMaxLength)
	if err != nil {
		return nil, err
	}
	image, err := contract.DecodeGeneratedRecipientRegistryImage(body)
	if err != nil || image.DomainID != p.provenance.domain || image.OperationID != p.pendingRegistry {
		return nil, contract.ErrRecord
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return slices.DeleteFunc(image.Recipients, func(row contract.ApplyRecipientInput) bool {
		return !slices.Contains(image.InitiallyAbsent, row.Recipient.RecipientID)
	}), nil
}

// A contiguous slice borrows projection backing until the caller releases the lock.
func (p *ReconstructionProjection) generatedSliceLocked(ctx context.Context, kind uint8, id contract.ID, limit uint32) ([]byte, error) {
	var location contract.GeneratorSliceLocation
	var selected contract.SupportRecord
	found := false
	for _, part := range p.parts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if part.kind != reconstructionSupportRowPart || part.supportKind != contract.GeneratorVectorSupportKind {
			continue
		}
		carrier, err := contract.InspectGeneratorVectorCarrier(part.body)
		if err != nil {
			return nil, err
		}
		if carrier.OwnerKind != contract.GeneratorSnapshotOwner || carrier.OwnerID != p.sliceSnapshot || carrier.VectorKind != contract.GeneratorVectorSlices || carrier.Vector != p.slices {
			continue
		}
		candidate, err := contract.InspectGeneratorSliceLocation(carrier.Row)
		if err != nil {
			return nil, err
		}
		if candidate.ContentKind != kind || candidate.ContentID != id {
			continue
		}
		if found || candidate.Length > limit {
			return nil, contract.ErrRecord
		}
		location, found = candidate, true
		selected = contract.SupportRecord{Kind: part.supportKind, RecordID: part.recordID, Body: part.body}
	}
	if !found {
		return nil, contract.ErrRecord
	}
	rows := make([]contract.SupportRecord, 1, contract.GeneratedFragmentLocationLimit+1)
	rows[0] = selected
	for _, part := range p.parts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if part.kind != reconstructionSupportRowPart || part.supportKind != contract.GeneratedFragmentSupportKind {
			continue
		}
		fragment, err := contract.InspectGeneratedFragment(part.body)
		if err != nil {
			return nil, err
		}
		if fragment.BlobID != location.BlobID {
			continue
		}
		if len(rows) == contract.GeneratedFragmentLocationLimit+1 {
			return nil, contract.ErrRecordCapacity
		}
		rows = append(rows, contract.SupportRecord{Kind: part.supportKind, RecordID: part.recordID, Body: part.body})
	}
	body, err := contract.InspectGeneratedImmutableSlice(p.provenance.domain, p.sliceSnapshot, rows, location, limit)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return body, nil
}

// ReconstructionProvenance identifies the exact selected HEAD and snapshot.
type ReconstructionProvenance struct {
	Domain, Revision, Snapshot contract.ID
	HEADDigest                 contract.ID
	HEADToken                  contract.Token
}

// PartCount returns zero after Close. It is safe to call concurrently with
// CopyPart and Close; a copy completed before Close remains caller-owned.
func (p *ReconstructionProjection) PartCount() int { return p.partCount() }

// CopyPart returns one bounded copy. It refuses an invalid index or a closed
// projection without exposing any owned backing.
func (p *ReconstructionProjection) CopyPart(index int) (ReconstructionPart, bool) {
	part, ok := p.copyPart(index)
	if !ok {
		return ReconstructionPart{}, false
	}
	return ReconstructionPart{Kind: ReconstructionPartKind(part.kind), Ref: part.ref,
		PhysicalOrdinal: part.physicalOrdinal, SupportKind: part.supportKind,
		RecordID: part.recordID, Body: part.body}, true
}

// Provenance is available only while the projection owns its parts.
func (p *ReconstructionProjection) Provenance() (ReconstructionProvenance, bool) {
	if p == nil {
		return ReconstructionProvenance{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ReconstructionProvenance{}, false
	}
	v := p.provenance
	return ReconstructionProvenance{Domain: v.domain, Revision: v.revision,
		Snapshot: v.snapshot, HEADDigest: v.headDigest, HEADToken: v.headToken}, true
}

func (p *ReconstructionProjection) partCount() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0
	}
	return len(p.parts)
}

// copyPart exposes only a copy. A later public projection can offer this
// bounded one-part operation without exposing the owner's mutable backing.
func (p *ReconstructionProjection) copyPart(index int) (reconstructionProjectionPart, bool) {
	if p == nil {
		return reconstructionProjectionPart{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || index < 0 || index >= len(p.parts) {
		return reconstructionProjectionPart{}, false
	}
	part := p.parts[index]
	part.body = bytes.Clone(part.body)
	return part, true
}

func (p *ReconstructionProjection) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	for i := range p.parts {
		clear(p.parts[i].body)
		p.parts[i].body = nil
	}
	p.parts = nil
	clear(p.signingAnchor)
	p.signingAnchor = nil
	p.provenance = reconstructionProjectionProvenance{}
	p.pendingRegistry = contract.ID{}
	p.sliceSnapshot, p.slices = contract.ID{}, contract.GeneratorDescriptor{}
	p.closed = true
}

// A projection attempt owns only provisional bytes. A failed or changed
// selection must Abort before another attempt begins. The same backing moves
// to the result after all parts and the authenticated final HEAD observation.
type reconstructionProjectionAttempt struct {
	anchor        anchoredPublicCandidate
	provenance    reconstructionProjectionProvenance
	sliceSnapshot contract.ID
	parts         []reconstructionProjectionPart
	partLimit     uint32
	byteLimit     uint64
	bytes         uint64
	committed     *ReconstructionProjection
	state         uint8
}

const (
	projectionActive uint8 = iota
	projectionAborted
	projectionCommitted
)

func projectionProvenance(selected *publicSelection) reconstructionProjectionProvenance {
	return reconstructionProjectionProvenance{domain: selected.image.root.Domain,
		revision: selected.basis.anchor.head.Core.Revision, snapshot: selected.image.root.Snapshot,
		headDigest: contract.Hash(selected.basis.anchor.headBody), headToken: selected.basis.anchor.headToken}
}

func beginReconstructionProjection(selected *publicSelection) (*reconstructionProjectionAttempt, Result) {
	if selected == nil || !selected.complete || selected.basis.reader.source == nil ||
		selected.image.root.Domain != selected.basis.reader.domain ||
		len(selected.image.supportFacts) != len(selected.image.root.RequiredSupport) ||
		len(selected.image.adminIndex.Pages) != len(selected.image.root.RequiredSupport) {
		return nil, refused(AdmissionInvalid)
	}
	root := selected.image.root
	count := uint64(3 + 1 + len(root.CurrentAccess.Core.AccessPageRefs) + len(root.AdministrativeIndexShards))
	for _, ref := range root.ValueEntryPages {
		if ref != nil {
			count++
		}
	}
	for _, ref := range root.Recipients {
		if ref != nil {
			count++
		}
	}
	var selectedRows uint64
	for i, facts := range selected.image.supportFacts {
		if facts.ref != root.RequiredSupport[i] || selected.image.adminIndex.Pages[i].Ref != facts.ref ||
			len(facts.rows) != len(facts.ordinals) {
			return nil, failure(IntegrityFailure, InvalidRelation)
		}
		selectedRows += uint64(len(facts.rows))
	}
	if selectedRows != uint64(root.RequiredSupportRecordCount) ||
		selectedRows > math.MaxUint32 || count > math.MaxUint32-selectedRows {
		return nil, failure(IntegrityFailure, InvalidRelation)
	}
	anchor := selected.basis.anchor
	if len(anchor.configBody) == 0 || len(anchor.configBody) > contract.MaxStoreConfigurationLength ||
		len(anchor.headBody) == 0 || len(anchor.headBody) > contract.MaxHeadLength ||
		len(anchor.rootBody) == 0 || len(anchor.rootBody) > contract.MaxRootLength ||
		format.CheckReference(anchor.head.Core.Root, anchor.rootBody) != nil {
		return nil, failure(IntegrityFailure, InvalidReference)
	}
	fixed := uint64(len(anchor.configBody)) + uint64(len(anchor.headBody)) + uint64(len(anchor.rootBody))
	if root.ChildEncodedBytes > math.MaxUint64-fixed {
		return nil, failure(IntegrityFailure, InvalidRelation)
	}
	return &reconstructionProjectionAttempt{anchor: anchor, provenance: projectionProvenance(selected), sliceSnapshot: selected.image.adminIndex.SliceSnapshot,
		parts: make([]reconstructionProjectionPart, 0, int(count+selectedRows)), partLimit: uint32(count + selectedRows), byteLimit: root.ChildEncodedBytes + fixed}, Result{}
}

func projectionPartLimit(kind reconstructionProjectionKind) uint32 {
	switch kind {
	case reconstructionConfigurationPart:
		return contract.MaxStoreConfigurationLength
	case reconstructionHEADPart:
		return contract.MaxHeadLength
	case reconstructionRootPart:
		return contract.MaxRootLength
	case reconstructionValuePagePart:
		return format.MaxValueEntryPage
	case reconstructionRecipientPagePart:
		return format.MaxRecipientPage
	case reconstructionAccessPagePart:
		return contract.MaxAccessPageLength
	case reconstructionIndexPagePart:
		return contract.MaxRequiredSupportPageLength
	case reconstructionSupportRowPart:
		return contract.SupportRecordMaxLength - contract.SupportRecordOverhead
	default:
		return 0
	}
}

func (a *reconstructionProjectionAttempt) Accept(ctx context.Context, part reconstructionProjectionPart) Result {
	if a == nil || a.state != projectionActive {
		return refused(AdmissionInvalid)
	}
	if !reconstructionInvocationCurrent(ctx, a.anchor) {
		return failure(EvidenceUnavailable, ReadUnavailable)
	}
	if part.kind == reconstructionSupportRowPart {
		if part.ref.Kind != contract.RequiredSupportKind || part.supportKind == 0 ||
			part.supportKind > contract.GCPlanSupportKind || part.recordID.IsZero() {
			return refused(AdmissionInvalid)
		}
	} else if part.supportKind != 0 || !part.recordID.IsZero() || part.physicalOrdinal != 0 {
		return refused(AdmissionInvalid)
	}
	if a.bytes > a.byteLimit ||
		len(part.body) == 0 || uint64(len(part.body)) > uint64(projectionPartLimit(part.kind)) ||
		uint64(len(part.body)) > a.byteLimit-a.bytes ||
		uint64(len(a.parts)) >= uint64(a.partLimit) {
		return refused(AdmissionInvalid)
	}
	owned := reconstructionProjectionPart{kind: part.kind, ref: part.ref,
		physicalOrdinal: part.physicalOrdinal, supportKind: part.supportKind,
		recordID: part.recordID, body: bytes.Clone(part.body)}
	if !reconstructionInvocationCurrent(ctx, a.anchor) {
		clear(owned.body)
		return failure(EvidenceUnavailable, ReadUnavailable)
	}
	if a.parts == nil {
		a.parts = make([]reconstructionProjectionPart, 0, a.partLimit)
	}
	a.parts = append(a.parts, owned)
	a.bytes += uint64(len(owned.body))
	return Result{}
}

// Commit accepts only Core's verified all-secret, same-HEAD observation. A
// consumer callback cannot supply or mint this result. No copy is made here.
func (a *reconstructionProjectionAttempt) Commit(ctx context.Context, observed Result) Result {
	if a == nil || a.state != projectionActive {
		return refused(AdmissionInvalid)
	}
	if !reconstructionInvocationCurrent(ctx, a.anchor) {
		return failure(EvidenceUnavailable, ReadUnavailable)
	}
	want := Result{Outcome: ObservedCurrent, Evidence: AuthenticatedClosure,
		ObservedRevision: a.provenance.revision, ObservedSnapshotID: a.provenance.snapshot}
	if a.committed != nil || observed != want || uint64(len(a.parts)) != uint64(a.partLimit) {
		return refused(AdmissionInvalid)
	}
	signingAnchor, err := contract.EncodePublicSigningBinding(a.anchor.anchor.binding)
	if err != nil || a.anchor.anchor.binding.Role != a.anchor.anchor.role {
		return refused(AdmissionInvalid)
	}
	a.committed = &ReconstructionProjection{signingAnchor: signingAnchor, parts: a.parts, provenance: a.provenance, sliceSnapshot: a.sliceSnapshot, slices: a.anchor.root.Generated.Slices}
	a.parts = nil
	a.anchor = anchoredPublicCandidate{}
	a.state = projectionCommitted
	return Result{}
}

func (a *reconstructionProjectionAttempt) takeCommitted() *ReconstructionProjection {
	if a == nil || a.state != projectionCommitted {
		return nil
	}
	result := a.committed
	a.committed = nil
	return result
}

func (a *reconstructionProjectionAttempt) Abort() {
	if a == nil || a.state != projectionActive {
		return
	}
	for i := range a.parts {
		clear(a.parts[i].body)
		a.parts[i].body = nil
	}
	a.parts = nil
	a.anchor = anchoredPublicCandidate{}
	a.provenance = reconstructionProjectionProvenance{}
	a.state = projectionAborted
}

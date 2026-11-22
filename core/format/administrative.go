package format

import (
	"bytes"
	"encoding/binary"

	"enkv.sh/core/contract"
)

const (
	AdministrativeGeneratedParent       = contract.AdministrativeGeneratedParent
	AdministrativeGeneratedDuty         = contract.AdministrativeGeneratedDuty
	AdministrativeGeneratedHazard       = contract.AdministrativeGeneratedHazard
	AdministrativeInboxRelease          = contract.AdministrativeInboxRelease
	AdministrativePublicationCoordinate = contract.AdministrativePublicationCoordinate
	AdministrativePublicationMarker     = contract.AdministrativePublicationMarker
	AdministrativeGC                    = contract.AdministrativeGC
)

const administrativeGroupMinimumLength = 247
const administrativeBaseLength = contract.RequiredSupportPageHeaderLength + 32 + 6 + 2
const administrativePageLength = 108
const administrativeSpanLength = 7
const (
	administrativeProofReferences                    = 5
	administrativeProofReferencesWithMaterials       = 6
	ownedBirthReferenceFlag                    uint8 = 2
)

const administrativeRowSummaryLength = 37
const administrativeLogicalMaxLength = contract.MaxChildPages * contract.MaxRequiredSupportPageLength

// AdministrativeGroup is mandatory selected ownership metadata. Its three
// descriptors bind the affected selection, retained dependencies, and work
// detail that a later Authority disposition may discard.
type AdministrativeGroup struct {
	GroupID, OwnerID, TargetID              ID
	OwnerKind, DutyKind, EffectEntryCeiling uint8
	SelectedEvidenceSummary                 uint16
	DestructiveEffect, UncertainCreateProof uint8
	ReferencesOwnedBirth                    bool
	Affected, Dependencies, Disposable      contract.GeneratorDescriptor
	ChargedPages                            uint16
	ChargedBytes                            uint64
	RelatedGroupIndexes                     []uint16
	PublicationIncarnationID                ID
	AdmissionOrdinal                        uint64
	GC                                      *contract.GCProgress
}

// Each marker has one coordinate edge. Its optional second edge names the
// Create involved in an owned action or a reserved-slot deletion.
func (marker AdministrativeGroup) PublicationReference(groups []AdministrativeGroup) (ID, bool) {
	var related ID
	var haveCoordinate bool
	for _, i := range marker.RelatedGroupIndexes {
		if int(i) >= len(groups) {
			return ID{}, false
		}
		group := groups[i]
		switch group.OwnerKind {
		case AdministrativePublicationCoordinate:
			if haveCoordinate || group.GroupID != marker.OwnerID {
				return ID{}, false
			}
			haveCoordinate = true
		case AdministrativePublicationMarker:
			if !related.IsZero() || group.OwnerID != marker.OwnerID {
				return ID{}, false
			}
			related = group.GroupID
		default:
			return ID{}, false
		}
	}
	if !haveCoordinate || marker.ReferencesOwnedBirth && related.IsZero() {
		return ID{}, false
	}
	return related, true
}

// AdministrativeSpan selects a contiguous ordinal range in the immutable
// support page. A later index can omit a range without rewriting the page.
type AdministrativeSpan struct {
	First, Count uint16
	Mandatory    bool
	GroupIndexes []uint16
}

// AdministrativeRowSummary preserves the exact selected row identity and
// charge when its optional page cannot be read during an Authority exit.
type AdministrativeRowSummary struct {
	Kind       uint8
	RecordID   ID
	BodyLength uint32
	MaterialID ID
}

// AdministrativePage binds an existing support page to its live logical
// records. A page may remain selected when only one of several owners ends.
type AdministrativePage struct {
	Ref          Ref
	ReadRequired bool
	Spans        []AdministrativeSpan
	Rows         []AdministrativeRowSummary
}

type PublicationCoordinateOrder struct {
	CoordinateID ID
	Incarnations []ID
}

type AdministrativeIndex struct {
	Domain, Object, SliceSnapshot ID
	Groups                        []AdministrativeGroup
	Pages                         []AdministrativePage
	PublicationOrder              []PublicationCoordinateOrder
}

// RetainedMaterialID resolves the implicit material identity of historical
// canonical summaries. Callers use it only for retained canonical rows.
func (v AdministrativeRowSummary) RetainedMaterialID() ID {
	if v.MaterialID.IsZero() {
		return v.RecordID
	}
	return v.MaterialID
}

func AdministrativeSummary(row contract.SupportRecord) (AdministrativeRowSummary, error) {
	v := AdministrativeRowSummary{Kind: row.Kind, RecordID: row.RecordID, BodyLength: uint32(len(row.Body))}
	if row.Kind == contract.RetainedCanonicalSupportKind {
		canonical, err := contract.InspectRetainedCanonicalRecord(row.Body)
		if err != nil {
			return AdministrativeRowSummary{}, err
		}
		if canonical.Entry.ValueState != row.RecordID {
			v.MaterialID = canonical.Entry.ValueState
		}
	}
	return v, nil
}

func (v AdministrativeRowSummary) MatchesRecord(row contract.SupportRecord) bool {
	actual, err := AdministrativeSummary(row)
	return err == nil && actual == v
}

func (v AdministrativeIndex) HasRetainedMaterialIDs() bool {
	for _, page := range v.Pages {
		for _, row := range page.Rows {
			if row.Kind == contract.RetainedCanonicalSupportKind && !row.MaterialID.IsZero() {
				return true
			}
		}
	}
	return false
}

func administrativeIndexValid(v AdministrativeIndex) bool {
	if v.Domain.IsZero() || v.Object.IsZero() || v.SliceSnapshot.IsZero() || len(v.Groups) > 0xffff || len(v.Pages) > contract.MaxChildPages {
		return false
	}
	explicitMaterials := v.HasRetainedMaterialIDs()
	encoded := administrativeBaseLength + administrativeGroupMinimumLength*len(v.Groups)
	if encoded > administrativeLogicalMaxLength {
		return false
	}
	for i, group := range v.Groups {
		if group.GC != nil {
			body, err := contract.EncodeGCProgress(*group.GC)
			if err != nil {
				return false
			}
			encoded += len(body)
		}
		if group.OwnerKind == AdministrativePublicationMarker {
			if group.PublicationIncarnationID.IsZero() || group.AdmissionOrdinal == 0 {
				return false
			}
			encoded += 40
		} else if !group.PublicationIncarnationID.IsZero() || group.AdmissionOrdinal != 0 {
			return false
		}
		encoded += 2 * len(group.RelatedGroupIndexes)
		if !GCGroupValid(group) || encoded > administrativeLogicalMaxLength || group.GroupID.IsZero() || group.OwnerID.IsZero() || group.TargetID.IsZero() || group.OwnerKind < AdministrativeGeneratedParent || group.OwnerKind > AdministrativeGC ||
			!contract.AdministrativeEvidenceValid(group.SelectedEvidenceSummary) ||
			(group.OwnerKind == AdministrativeGeneratedDuty && (group.DutyKind < contract.GeneratedDutyCreate || group.DutyKind > contract.GeneratedDutyUnselectedCleanup) ||
				group.OwnerKind != AdministrativeGeneratedDuty && group.DutyKind != 0) ||
			group.DestructiveEffect > 1 || group.UncertainCreateProof > 1 ||
			group.DestructiveEffect != 0 && group.OwnerKind > AdministrativeInboxRelease ||
			(group.UncertainCreateProof != 0 || group.ReferencesOwnedBirth) && group.OwnerKind != AdministrativePublicationMarker ||
			group.EffectEntryCeiling > 1 || !group.Affected.Valid() || !group.Dependencies.Valid() || !group.Disposable.Valid() ||
			group.ChargedPages > contract.MaxChildPages || len(group.RelatedGroupIndexes) > 0xffff ||
			i > 0 && bytes.Compare(v.Groups[i-1].GroupID[:], group.GroupID[:]) >= 0 {
			return false
		}
		if group.ReferencesOwnedBirth {
			if _, valid := group.PublicationReference(v.Groups); !valid || group.UncertainCreateProof != 0 {
				return false
			}
		}
		for j, related := range group.RelatedGroupIndexes {
			if int(related) >= len(v.Groups) || int(related) == i || j > 0 && group.RelatedGroupIndexes[j-1] >= related {
				return false
			}
		}
	}
	// Every mandatory group relation must terminate at another selected group.
	// Reject cycles without recursion so a maximum-size index has bounded stack.
	colors := make([]uint8, len(v.Groups))
	type frame struct{ group, next int }
	for i := range v.Groups {
		if colors[i] != 0 {
			continue
		}
		stack := []frame{{group: i}}
		colors[i] = 1
		for len(stack) != 0 {
			top := &stack[len(stack)-1]
			related := v.Groups[top.group].RelatedGroupIndexes
			if top.next == len(related) {
				colors[top.group] = 2
				stack = stack[:len(stack)-1]
				continue
			}
			j := int(related[top.next])
			top.next++
			if colors[j] == 1 {
				return false
			}
			if colors[j] == 0 {
				colors[j] = 1
				stack = append(stack, frame{group: j})
			}
		}
	}
	for i, page := range v.Pages {
		encoded += administrativePageLength
		if encoded > administrativeLogicalMaxLength {
			return false
		}
		if page.Ref.Kind != contract.RequiredSupportKind || !page.Ref.ValidFor(Version) || page.Ref.Domain != v.Domain ||
			i > 0 && v.Pages[i-1].Ref.Index >= page.Ref.Index || len(page.Spans) == 0 || len(page.Spans) > 0xffff {
			return false
		}
		selected := 0
		for j, span := range page.Spans {
			encoded += administrativeSpanLength + 2*len(span.GroupIndexes)
			selected += int(span.Count)
			last := uint32(span.First) + uint32(span.Count)
			if encoded > administrativeLogicalMaxLength || span.Count == 0 || len(span.GroupIndexes) > 0xffff ||
				!span.Mandatory && len(span.GroupIndexes) == 0 ||
				last > uint32((page.Ref.Length-contract.RequiredSupportPageHeaderLength)/contract.SupportRecordMinLength) ||
				j > 0 && uint32(page.Spans[j-1].First)+uint32(page.Spans[j-1].Count) > uint32(span.First) {
				return false
			}
			for k, group := range span.GroupIndexes {
				if int(group) >= len(v.Groups) || k > 0 && span.GroupIndexes[k-1] >= group {
					return false
				}
			}
		}
		if page.ReadRequired {
			if len(page.Rows) != 0 {
				return false
			}
		} else {
			if len(page.Rows) != selected {
				return false
			}
			encoded += administrativeRowSummaryLength * selected
			if encoded > administrativeLogicalMaxLength {
				return false
			}
			for _, row := range page.Rows {
				if !row.MaterialID.IsZero() && (row.Kind != contract.RetainedCanonicalSupportKind || row.MaterialID == row.RecordID) {
					return false
				}
				if explicitMaterials && row.Kind == contract.RetainedCanonicalSupportKind {
					encoded += 32
				}
				if encoded > administrativeLogicalMaxLength || row.Kind == 0 || row.Kind > contract.GCPlanSupportKind || row.RecordID.IsZero() ||
					row.BodyLength < contract.SupportRecordMinLength-contract.SupportRecordOverhead ||
					row.BodyLength > contract.SupportRecordMaxLength-contract.SupportRecordOverhead {
					return false
				}
			}
		}
	}
	if len(v.PublicationOrder) > contract.MaxPublicationCoordinates {
		return false
	}
	ids := make(map[ID]bool)
	for i, row := range v.PublicationOrder {
		if row.CoordinateID.IsZero() || len(row.Incarnations) == 0 || len(row.Incarnations) > contract.MaxPublicationIncarnations || i > 0 && bytes.Compare(v.PublicationOrder[i-1].CoordinateID[:], row.CoordinateID[:]) >= 0 {
			return false
		}
		encoded += 34 + 32*len(row.Incarnations)
		if encoded > administrativeLogicalMaxLength {
			return false
		}
		for _, id := range row.Incarnations {
			if id.IsZero() || ids[id] || len(ids) == contract.MaxPublicationIncarnations {
				return false
			}
			ids[id] = true
		}
	}
	return true
}

func (v AdministrativeIndex) Valid() bool { return administrativeIndexValid(v) }

// AdministrativeIndexEncodedLength gives the exact logical wire length
// without allocating its body. Admission uses it to charge authenticated
// index shards before private work.
func AdministrativeIndexEncodedLength(v AdministrativeIndex) (uint64, error) {
	if !v.Valid() {
		return 0, ErrFormat
	}
	explicitMaterials := v.HasRetainedMaterialIDs()
	length := uint64(administrativeBaseLength + administrativeGroupMinimumLength*len(v.Groups) + administrativePageLength*len(v.Pages))
	for _, group := range v.Groups {
		if group.GC != nil {
			body, err := contract.EncodeGCProgress(*group.GC)
			if err != nil {
				return 0, ErrFormat
			}
			length += uint64(len(body))
		}
		length += 2 * uint64(len(group.RelatedGroupIndexes))
		if group.OwnerKind == AdministrativePublicationMarker {
			length += 40
		}
	}
	for _, page := range v.Pages {
		for _, span := range page.Spans {
			length += administrativeSpanLength + 2*uint64(len(span.GroupIndexes))
		}
		length += administrativeRowSummaryLength * uint64(len(page.Rows))
		if explicitMaterials {
			for _, row := range page.Rows {
				if row.Kind == contract.RetainedCanonicalSupportKind {
					length += 32
				}
			}
		}
	}
	for _, row := range v.PublicationOrder {
		length += 34 + 32*uint64(len(row.Incarnations))
	}
	return length, nil
}

func EncodeAdministrativeIndex(v AdministrativeIndex) ([]byte, error) {
	length, err := AdministrativeIndexEncodedLength(v)
	if err != nil {
		return nil, ErrFormat
	}
	w := start(byte(contract.AdministrativeIndexKind))
	w.b = append(make([]byte, 0, int(length)), w.b...)
	w.id(v.Domain)
	w.id(v.Object)
	w.id(v.SliceSnapshot)
	w.u16(0xffff)
	w.u16(0xffff)
	explicitMaterials := v.HasRetainedMaterialIDs()
	if explicitMaterials {
		w.u16(administrativeProofReferencesWithMaterials)
	} else {
		w.u16(administrativeProofReferences)
	}
	w.u16(uint16(len(v.Groups)))
	w.u16(uint16(len(v.Pages)))
	for _, group := range v.Groups {
		w.u8(group.OwnerKind)
		w.u8(group.DutyKind)
		w.id(group.GroupID)
		w.id(group.OwnerID)
		w.id(group.TargetID)
		w.u8(group.EffectEntryCeiling)
		w.u16(group.SelectedEvidenceSummary)
		w.u8(group.DestructiveEffect)
		flags := group.UncertainCreateProof
		if group.ReferencesOwnedBirth {
			flags |= ownedBirthReferenceFlag
		}
		w.u8(flags)
		for _, descriptor := range []contract.GeneratorDescriptor{group.Affected, group.Dependencies, group.Disposable} {
			var err error
			w.b, err = contract.AppendGeneratorDescriptor(w.b, descriptor)
			if err != nil {
				return nil, ErrFormat
			}
		}
		w.u16(group.ChargedPages)
		w.u64(group.ChargedBytes)
		w.u16(uint16(len(group.RelatedGroupIndexes)))
		for _, related := range group.RelatedGroupIndexes {
			w.u16(related)
		}
		if group.OwnerKind == AdministrativePublicationMarker {
			w.id(group.PublicationIncarnationID)
			w.u64(group.AdmissionOrdinal)
		}
		if group.OwnerKind == AdministrativeGC {
			body, err := contract.EncodeGCProgress(*group.GC)
			if err != nil {
				return nil, ErrFormat
			}
			w.b = append(w.b, body...)
		}
	}
	for _, page := range v.Pages {
		w.ref(page.Ref)
		if page.ReadRequired {
			w.u8(1)
		} else {
			w.u8(0)
		}
		w.u16(uint16(len(page.Spans)))
		for _, span := range page.Spans {
			w.u16(span.First)
			w.u16(span.Count)
			if span.Mandatory {
				w.u8(1)
			} else {
				w.u8(0)
			}
			w.u16(uint16(len(span.GroupIndexes)))
			for _, group := range span.GroupIndexes {
				w.u16(group)
			}
		}
		for _, row := range page.Rows {
			w.u8(row.Kind)
			w.id(row.RecordID)
			w.u32(row.BodyLength)
			if explicitMaterials && row.Kind == contract.RetainedCanonicalSupportKind {
				w.id(row.RetainedMaterialID())
			}
		}
	}
	w.u16(uint16(len(v.PublicationOrder)))
	for _, row := range v.PublicationOrder {
		w.id(row.CoordinateID)
		w.u16(uint16(len(row.Incarnations)))
		for _, id := range row.Incarnations {
			w.id(id)
		}
	}
	if uint64(len(w.b)) != length {
		return nil, ErrFormat
	}
	return w.result()
}

func DecodeAdministrativeIndex(body []byte) (AdministrativeIndex, error) {
	r := begin(body, byte(contract.AdministrativeIndexKind), administrativeLogicalMaxLength)
	return decodeAdministrativeIndex(r, len(body))
}

type administrativeDecodeReader interface {
	take(int) []byte
	u8() byte
	u16() uint16
	u32() uint32
	u64() uint64
	id() ID
	ref() Ref
	remaining() int
	end() bool
	badFormat()
}

func decodeAdministrativeIndex(r administrativeDecodeReader, length int) (AdministrativeIndex, error) {
	v := AdministrativeIndex{Domain: r.id(), Object: r.id(), SliceSnapshot: r.id()}
	if r.u16() != 0xffff {
		return AdministrativeIndex{}, ErrFormat
	}
	if r.u16() != 0xffff {
		return AdministrativeIndex{}, ErrFormat
	}
	marker := r.u16()
	if marker != administrativeProofReferences && marker != administrativeProofReferencesWithMaterials {
		return AdministrativeIndex{}, ErrFormat
	}
	groups, pages := int(r.u16()), int(r.u16())
	if pages > contract.MaxChildPages || length < contract.RequiredSupportPageHeaderLength+32 ||
		groups > (length-contract.RequiredSupportPageHeaderLength-32)/administrativeGroupMinimumLength {
		return AdministrativeIndex{}, ErrFormat
	}
	v.Groups = make([]AdministrativeGroup, groups)
	for i := range v.Groups {
		group := AdministrativeGroup{OwnerKind: r.u8(), DutyKind: r.u8(), GroupID: r.id(), OwnerID: r.id(), TargetID: r.id(), EffectEntryCeiling: r.u8(), SelectedEvidenceSummary: r.u16(), DestructiveEffect: r.u8()}
		flags := r.u8()
		if flags&^(1|ownedBirthReferenceFlag) != 0 {
			return AdministrativeIndex{}, ErrFormat
		}
		group.UncertainCreateProof = flags & 1
		group.ReferencesOwnedBirth = flags&ownedBirthReferenceFlag != 0
		for _, descriptor := range []*contract.GeneratorDescriptor{&group.Affected, &group.Dependencies, &group.Disposable} {
			var err error
			*descriptor, err = contract.DecodeGeneratorDescriptor(r.take(contract.GeneratorDescriptorLength))
			if err != nil {
				r.badFormat()
			}
		}
		group.ChargedPages, group.ChargedBytes = r.u16(), r.u64()
		related := int(r.u16())
		if related > r.remaining()/2 {
			return AdministrativeIndex{}, ErrFormat
		}
		if related != 0 {
			group.RelatedGroupIndexes = make([]uint16, related)
			for j := range group.RelatedGroupIndexes {
				group.RelatedGroupIndexes[j] = r.u16()
			}
		}
		if group.OwnerKind == AdministrativePublicationMarker {
			group.PublicationIncarnationID, group.AdmissionOrdinal = r.id(), r.u64()
		}
		if group.OwnerKind == AdministrativeGC {
			header := r.take(150)
			if len(header) != 150 {
				return AdministrativeIndex{}, ErrFormat
			}
			count := int(binary.BigEndian.Uint16(header[142:144]))
			if count == 0 || count > contract.GCTargetLimit || count > r.remaining()/34 {
				return AdministrativeIndex{}, ErrFormat
			}
			body := append(append([]byte{}, header...), r.take(count*34)...)
			progress, err := contract.DecodeGCProgress(body)
			if err != nil {
				return AdministrativeIndex{}, ErrFormat
			}
			group.GC = &progress
		}
		v.Groups[i] = group
	}
	v.Pages = make([]AdministrativePage, pages)
	for i := range v.Pages {
		page := AdministrativePage{Ref: r.ref()}
		readRequired := r.u8()
		if readRequired > 1 {
			return AdministrativeIndex{}, ErrFormat
		}
		page.ReadRequired = readRequired == 1
		count := int(r.u16())
		if count > r.remaining()/7 || page.Ref.Length < contract.RequiredSupportPageHeaderLength ||
			count > int((page.Ref.Length-contract.RequiredSupportPageHeaderLength)/contract.SupportRecordMinLength) {
			return AdministrativeIndex{}, ErrFormat
		}
		page.Spans = make([]AdministrativeSpan, count)
		selected := 0
		for j := range page.Spans {
			span := AdministrativeSpan{First: r.u16(), Count: r.u16()}
			selected += int(span.Count)
			mandatory := r.u8()
			if mandatory > 1 {
				r.badFormat()
			}
			span.Mandatory = mandatory == 1
			owners := int(r.u16())
			if owners > len(v.Groups) || owners > r.remaining()/2 {
				return AdministrativeIndex{}, ErrFormat
			}
			span.GroupIndexes = make([]uint16, owners)
			for k := range span.GroupIndexes {
				span.GroupIndexes[k] = r.u16()
			}
			page.Spans[j] = span
		}
		if !page.ReadRequired {
			if selected > r.remaining()/administrativeRowSummaryLength {
				return AdministrativeIndex{}, ErrFormat
			}
			page.Rows = make([]AdministrativeRowSummary, selected)
			for j := range page.Rows {
				row := AdministrativeRowSummary{Kind: r.u8(), RecordID: r.id(), BodyLength: r.u32()}
				if marker == administrativeProofReferencesWithMaterials && row.Kind == contract.RetainedCanonicalSupportKind {
					material := r.id()
					if material.IsZero() {
						return AdministrativeIndex{}, ErrFormat
					}
					if material != row.RecordID {
						row.MaterialID = material
					}
				}
				page.Rows[j] = row
			}
		}
		v.Pages[i] = page
	}
	count := int(r.u16())
	if count > contract.MaxPublicationCoordinates || count > r.remaining()/66 {
		return AdministrativeIndex{}, ErrFormat
	}
	if count > 0 {
		v.PublicationOrder = make([]PublicationCoordinateOrder, count)
	}
	totalIDs := 0
	for i := range v.PublicationOrder {
		row := PublicationCoordinateOrder{CoordinateID: r.id()}
		n := int(r.u16())
		totalIDs += n
		if n == 0 || totalIDs > contract.MaxPublicationIncarnations || n > r.remaining()/32 {
			return AdministrativeIndex{}, ErrFormat
		}
		row.Incarnations = make([]ID, n)
		for j := range row.Incarnations {
			row.Incarnations[j] = r.id()
		}
		v.PublicationOrder[i] = row
	}
	if !r.end() || !v.Valid() || (marker == administrativeProofReferencesWithMaterials) != v.HasRetainedMaterialIDs() {
		return AdministrativeIndex{}, ErrFormat
	}
	return v, nil
}

// PublicationIndexPlanningGrowth bounds new publication metadata without
// constructing rows or granting ownership. Markers have one span/row, two
// prerequisite indexes and at most one fresh order incarnation. Coordinate
// groups have one span/row and one new order row with its current incarnation.
// Existing metadata is charged separately, including retained dependencies.
func PublicationIndexPlanningGrowth(markers, coordinates, pages uint32) (uint64, error) {
	if markers > contract.MaxPublicationMarkers || coordinates > contract.MaxPublicationCoordinates || pages > contract.MaxChildPages {
		return 0, contract.ErrRecordCapacity
	}
	marker := uint64(administrativeGroupMinimumLength + 40 + administrativeSpanLength + 2 + administrativeRowSummaryLength + 2*2 + 32)
	coordinate := uint64(administrativeGroupMinimumLength + administrativeSpanLength + 2 + administrativeRowSummaryLength + 34 + 32)
	return uint64(markers)*marker + uint64(coordinates)*coordinate + uint64(pages)*administrativePageLength, nil
}

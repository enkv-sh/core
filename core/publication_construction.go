package core

import (
	"bytes"
	"context"
	"slices"
	"sort"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// This input belongs only to one reserve or close construction. The row bodies
// and sorted facts are private; callers get values, never mutable fact maps.
type publicationConstruction struct {
	head            format.HeadCore
	token           contract.Token
	root            contract.ID
	rewrite         *publicationRewritePlan
	rows            []contract.SupportRecord
	facts           []contract.SupportRecordDigest
	coordinates     []contract.PublicationCoordinate
	markers         []contract.PublicationMarker
	order           []format.PublicationCoordinateOrder
	packed          [][]contract.SupportRecord
	emitted         []format.Ref
	snapshot        contract.ID
	transition      contract.ID
	consumed        bool
	emissionChecked bool
}

// Raw-row callers keep their own inputs. The construction owns exact-length
// copies, including when the typed builder uses the shared row encoders.
func (s *StateSession) preparePublicationConstruction(ctx context.Context, rows []contract.SupportRecord) (*publicationConstruction, error) {
	if err := publicationRowBounds(rows, true); err != nil {
		return nil, err
	}
	owned := make([]contract.SupportRecord, len(rows))
	for i, row := range rows {
		owned[i] = row
		owned[i].Body = make([]byte, len(row.Body))
		copy(owned[i].Body, row.Body)
	}
	return s.admitPublicationConstruction(ctx, owned)
}

func (s *StateSession) admitPublicationConstruction(ctx context.Context, rows []contract.SupportRecord) (*publicationConstruction, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || s.store == nil {
		return nil, contract.ErrRecord
	}
	selected, err := inspectPublicationRows(s.root.Domain, rows)
	if err != nil {
		return nil, err
	}
	order, err := publicationOrderForRelation(selected, s.adminIndex.PublicationOrder)
	if err != nil {
		return nil, err
	}
	if _, err := publicationTypedRelation(s.root.Domain, selected, order); err != nil {
		return nil, err
	}
	rewrite, err := s.planPublicationRewrite(ctx, s.adminIndex)
	if err != nil {
		return nil, err
	}
	root, err := publicationRootDigest(s.root)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(rows, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	in := &publicationConstruction{head: s.head.Core, token: s.token, root: root,
		rewrite: rewrite, rows: rows, order: order,
		facts: make([]contract.SupportRecordDigest, len(rows))}
	var mandatory administrativeMandatorySupport
	mandatory.bindPublicationRelation(selected)
	groups := make([]format.RequiredSupportGroup, 0, len(rows))
	for i, row := range rows {
		in.facts[i], err = contract.InspectSupportRecordDigest(s.root.Domain, row)
		if err != nil {
			return nil, err
		}
		required, err := mandatory.row(row)
		if err != nil {
			return nil, err
		}
		groups = append(groups, format.RequiredSupportGroup{Class: format.OwnerSupport, Owner: row.RecordID, Mandatory: required, Records: []contract.SupportRecord{row}})
	}
	in.coordinates = make([]contract.PublicationCoordinate, 0, len(selected.coordinates))
	in.markers = make([]contract.PublicationMarker, 0, len(selected.markers))
	for _, row := range rows {
		if row.Kind == contract.PublicationCoordinateSupportKind {
			in.coordinates = append(in.coordinates, selected.coordinates[row.RecordID])
		} else {
			in.markers = append(in.markers, selected.markers[row.RecordID])
		}
	}
	in.packed, err = format.PackRequiredSupportRows(s.root.Domain, groups, uint32(len(rewrite.peers)))
	if err != nil {
		return nil, err
	}
	return in, nil
}

func (in *publicationConstruction) pageCount() int { return len(in.packed) }

func (in *publicationConstruction) relation() selectedPublication {
	selected := selectedPublication{coordinates: make(map[contract.ID]contract.PublicationCoordinate, len(in.coordinates)), markers: make(map[contract.ID]contract.PublicationMarker, len(in.markers))}
	for _, coordinate := range in.coordinates {
		selected.coordinates[coordinate.CoordinateID] = coordinate
	}
	for _, marker := range in.markers {
		selected.markers[marker.AttemptID] = marker
	}
	return selected
}

func (in *publicationConstruction) coordinate(id contract.ID) (contract.PublicationCoordinate, bool) {
	i := sort.Search(len(in.coordinates), func(i int) bool { return bytes.Compare(in.coordinates[i].CoordinateID[:], id[:]) >= 0 })
	if i == len(in.coordinates) || in.coordinates[i].CoordinateID != id {
		return contract.PublicationCoordinate{}, false
	}
	return in.coordinates[i], true
}

func (in *publicationConstruction) marker(id contract.ID) (contract.PublicationMarker, bool) {
	i := sort.Search(len(in.markers), func(i int) bool { return bytes.Compare(in.markers[i].AttemptID[:], id[:]) >= 0 })
	if i == len(in.markers) || in.markers[i].AttemptID != id {
		return contract.PublicationMarker{}, false
	}
	return in.markers[i], true
}

func (in *publicationConstruction) group(row contract.SupportRecord) (format.AdministrativeGroup, bool, error) {
	if _, err := in.fact(row); err != nil {
		return format.AdministrativeGroup{}, false, err
	}
	if row.Kind == contract.PublicationCoordinateSupportKind {
		coordinate, present := in.coordinate(row.RecordID)
		if !present {
			return format.AdministrativeGroup{}, false, contract.ErrRecord
		}
		return administrativePublicationCoordinateGroup(coordinate), true, nil
	}
	marker, present := in.marker(row.RecordID)
	if !present || row.Kind != contract.PublicationMarkerSupportKind {
		return format.AdministrativeGroup{}, false, contract.ErrRecord
	}
	return administrativePublicationMarkerGroup(marker), true, nil
}

func clonePublicationOrder(order []format.PublicationCoordinateOrder) []format.PublicationCoordinateOrder {
	owned := slices.Clone(order)
	for i := range owned {
		owned[i].Incarnations = slices.Clone(order[i].Incarnations)
	}
	return owned
}

func (in *publicationConstruction) fact(row contract.SupportRecord) (contract.SupportRecordDigest, error) {
	i, ok := slices.BinarySearchFunc(in.rows, row, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	if !ok {
		return contract.SupportRecordDigest{}, contract.ErrRecord
	}
	return in.facts[i], nil
}

func (in *publicationConstruction) checkedFact(row contract.SupportRecord) (contract.SupportRecordDigest, error) {
	fact, err := in.fact(row)
	if err != nil || fact.BodyLength() != uint32(len(row.Body)) || fact.BodyDigest() != contract.Hash(row.Body) {
		return contract.SupportRecordDigest{}, contract.ErrRecord
	}
	return fact, nil
}

func (in *publicationConstruction) rowFact(domain contract.ID, row contract.SupportRecord) (contract.SupportRecordDigest, error) {
	if in != nil && (row.Kind == contract.PublicationCoordinateSupportKind || row.Kind == contract.PublicationMarkerSupportKind) {
		if domain != in.head.Domain {
			return contract.SupportRecordDigest{}, contract.ErrRecord
		}
		return in.fact(row)
	}
	return contract.InspectSupportRecordDigest(domain, row)
}

func (in *publicationConstruction) matches(s *StateSession) bool {
	if in == nil || s == nil || in.head != s.head.Core || in.token != s.token ||
		in.rewrite.predecessor != contract.Hash(s.body) || in.rewrite.index != s.root.AdministrativeIndex ||
		!samePublicationWork(in.rewrite.work, s.adminIndex) {
		return false
	}
	root, err := publicationRootDigest(s.root)
	return err == nil && root == in.root
}

func (in *publicationConstruction) begin(ctx context.Context, s *StateSession, next *StateSession, candidate *Candidate) error {
	if in == nil || in.consumed {
		return contract.ErrRecord
	}
	in.consumed = true
	if ctx == nil || ctx.Err() != nil || !in.matches(s) || next == nil || candidate == nil || candidate.session != s ||
		!s.root.Generated.ActiveOwner.IsZero() || next.root.Domain != s.root.Domain || next.root.OutputConfiguration != s.root.OutputConfiguration ||
		next.root.Snapshot.IsZero() || next.root.Transition.IsZero() || next.root.Snapshot == next.root.Transition {
		return contract.ErrRecord
	}
	expected := s.root
	expected.Snapshot, expected.Transition = next.root.Snapshot, next.root.Transition
	want, err := publicationRootDigest(expected)
	if err != nil {
		return err
	}
	actual, err := publicationRootDigest(next.root)
	if err != nil || actual != want {
		return contract.ErrRecord
	}
	in.snapshot, in.transition = next.root.Snapshot, next.root.Transition
	return nil
}

// The actual page bytes must still name the exact page emitted from the owned
// packing. No second complete page image is retained for this check.
func (in *publicationConstruction) physical(ref format.Ref, body []byte) ([]contract.SupportRecordView, error) {
	i := slices.Index(in.emitted, ref)
	if i < 0 || i >= len(in.packed) || uint32(len(body)) != ref.Length {
		return nil, contract.ErrRecord
	}
	rows := make([]contract.SupportRecordView, len(in.packed[i]))
	for j, row := range in.packed[i] {
		if _, err := in.fact(row); err != nil {
			return nil, err
		}
		rows[j] = contract.SupportRecordView(row)
	}
	return rows, nil
}

func (in *publicationConstruction) bindEmission(next *StateSession, candidate *Candidate) (selectedPublication, error) {
	if in == nil || !in.consumed || next == nil || candidate == nil ||
		next.root.Snapshot != in.snapshot || next.root.Transition != in.transition {
		return selectedPublication{}, contract.ErrRecord
	}
	seen := make(map[generatedRecordKey]bool, len(in.rows))
	for _, page := range next.support {
		for _, row := range page.Records {
			if row.Kind != contract.PublicationCoordinateSupportKind && row.Kind != contract.PublicationMarkerSupportKind {
				continue
			}
			key := generatedRecordKey{kind: row.Kind, id: row.RecordID}
			if seen[key] {
				return selectedPublication{}, contract.ErrRecord
			}
			seen[key] = true
			if _, err := in.checkedFact(contract.SupportRecord(row)); err != nil {
				return selectedPublication{}, err
			}
		}
	}
	if len(seen) != len(in.rows) {
		return selectedPublication{}, contract.ErrRecord
	}
	if !in.emissionChecked {
		for _, ref := range in.emitted {
			found := false
			for _, image := range candidate.objects {
				if image.ref == ref {
					if found || uint32(len(image.body)) != ref.Length || contract.Hash(image.body) != ref.Digest {
						return selectedPublication{}, contract.ErrRecord
					}
					found = true
				}
			}
			if !found || !slices.Contains(next.root.RequiredSupport, ref) {
				return selectedPublication{}, contract.ErrRecord
			}
		}
	}
	selected := in.relation()
	if err := validatePublicationIndexRelation(next.selectedImage(), selected); err != nil {
		return selectedPublication{}, err
	}
	return selected, nil
}

func (in *publicationConstruction) bindProof(ctx context.Context, s, next *StateSession, candidate *Candidate) error {
	selected, err := in.bindEmission(next, candidate)
	if err != nil {
		return err
	}
	reader, err := s.preservedPublicationReader(next)
	if err != nil {
		return err
	}
	image := next.selectedImage()
	checks, err := newPublicationChecksFromRelation(image, nil, selected)
	if err != nil {
		return err
	}
	_, state, err := validatePublicationChecks(ctx, image, reader, checks)
	if state.Outcome != 0 {
		return selectedReadFailure(state)
	}
	if err != nil {
		return err
	}
	rows, err := publicationSelectedRowProofs(image)
	if err != nil || len(rows) != len(in.rows) {
		return contract.ErrRecord
	}
	for key, row := range rows {
		fact, err := in.fact(contract.SupportRecord{Kind: key.kind, RecordID: key.id})
		if err != nil || fact.BodyLength() != row.length || fact.BodyDigest() != row.bodyDigest {
			return contract.ErrRecord
		}
	}
	digest, err := publicationRootDigest(next.root)
	if err != nil {
		return err
	}
	next.publicationProof = &selectedPublicationProof{rootDigest: digest, indexRef: next.root.AdministrativeIndex, rows: rows}
	return nil
}

// The proof was issued immediately above from this construction's exact emitted
// bytes. No callback or mutable caller alias occurs before this family check.
func (in *publicationConstruction) validOutputSelection(next *StateSession) bool {
	if in == nil || !in.consumed || next == nil || next.publicationProof == nil ||
		next.publicationProof.indexRef != next.root.AdministrativeIndex {
		return false
	}
	digest, err := publicationRootDigest(next.root)
	if err != nil || digest != next.publicationProof.rootDigest {
		return false
	}
	if reserve := next.head.OutputReserve; next.head.AuthKind == format.OutputReserveAuth && reserve != nil {
		marker, present := in.marker(reserve.AttemptID)
		coordinate, found := in.coordinate(reserve.CoordinateID)
		if !present || !found || !publicationReserveSelectionMatches(*reserve, next.root, marker, coordinate) {
			return false
		}
		if !reserve.OwnedBirthAttemptID.IsZero() {
			birth, present := in.marker(reserve.OwnedBirthAttemptID)
			return present && reserve.BirthTargetRowDigest == birth.Projection.TargetRowDigest
		}
		return true
	}
	if closeSubject := next.head.OutputClose; next.head.AuthKind == format.OutputCloseAuth && closeSubject != nil {
		marker, present := in.marker(closeSubject.AttemptID)
		return present && publicationCloseSelectionMatches(*closeSubject, next.root, marker)
	}
	return false
}

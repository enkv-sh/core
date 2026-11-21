package core

import (
	"bytes"
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// A complete publication proof is local selected-state evidence. It grants no
// action. In particular, an administrative partial read cannot make one.
type selectedPublicationProof struct {
	rootDigest contract.ID
	indexRef   format.Ref
	rows       map[generatedRecordKey]selectedPublicationRowProof
}

type selectedPublicationRowProof struct {
	ref        format.Ref
	physical   uint16
	length     uint32
	bodyDigest contract.ID
}

func publicationBirthAfterDelete(coordinate contract.PublicationCoordinate, birth contract.PublicationMarker, selected selectedPublication, orders []format.PublicationCoordinateOrder) (bool, error) {
	var lastDelete *contract.PublicationMarker
	if marker, ok := selected.markers[coordinate.LastDeleteAckAttemptID]; ok {
		lastDelete = &marker
	}
	return publicationBirthAvailable(coordinate, birth, lastDelete, orders)
}

func publicationBirthAvailable(coordinate contract.PublicationCoordinate, birth contract.PublicationMarker, deleted *contract.PublicationMarker, orders []format.PublicationCoordinateOrder) (bool, error) {
	if birth.DomainID != coordinate.DomainID || !publicationQualifiedBirthValid(coordinate.DomainID, coordinate, birth) {
		return false, contract.ErrRecord
	}
	var order []contract.ID
	for _, row := range orders {
		if row.CoordinateID == coordinate.CoordinateID {
			order = row.Incarnations
			break
		}
	}
	if len(order) == 0 {
		return false, contract.ErrRecord
	}
	if coordinate.LastDeleteAckAttemptID.IsZero() || publicationStampAfter(order, birth.PublicationIncarnationID, birth.AdmissionOrdinal, coordinate.LastDeleteAckIncarnationID, coordinate.LastDeleteAckOrdinal) {
		return true, nil
	}
	if deleted == nil {
		return false, selectedReadFailure(failure(EvidenceUnavailable, ReadUnavailable))
	}
	if deleted.DomainID != coordinate.DomainID || deleted.CoordinateID != coordinate.CoordinateID || deleted.AttemptID != coordinate.LastDeleteAckAttemptID ||
		deleted.PublicationIncarnationID != coordinate.LastDeleteAckIncarnationID || deleted.AdmissionOrdinal != coordinate.LastDeleteAckOrdinal ||
		deleted.State != contract.PublicationAcknowledged || deleted.Evidence.Class != contract.PublicationRequestAcknowledged ||
		deleted.Projection.Action != contract.PublicationDeleteOwned && deleted.Projection.Action != contract.PublicationDeleteReservedSlot {
		return false, contract.ErrRecord
	}
	if deleted.Projection.Action != contract.PublicationDeleteOwned || deleted.Projection.OwnedBirthAttemptID != birth.AttemptID {
		return true, nil
	}
	if deleted.Projection.BindingIncarnationID != birth.Projection.BindingIncarnationID || deleted.Projection.EntryIncarnationID != birth.Projection.EntryIncarnationID ||
		deleted.Projection.TargetRowDigest != birth.Projection.TargetRowDigest || !publicationStampAfter(order, deleted.PublicationIncarnationID, deleted.AdmissionOrdinal, birth.PublicationIncarnationID, birth.AdmissionOrdinal) {
		return false, contract.ErrRecord
	}
	return false, nil
}

type selectedPublicationChecks struct {
	selected     selectedPublication
	entries      map[contract.ID]bool
	active       map[contract.ID]bool
	destinations map[string]uint64
	targets      map[contract.ID]uint64
	routes       map[contract.ID]uint64
}

func publicationRootDigest(root format.Root) (contract.ID, error) {
	body, err := format.EncodeRoot(root)
	if err != nil {
		return contract.ID{}, err
	}
	return contract.Hash(body), nil
}

// A receipt reservation has admitted entry identities before canonical secret
// entries exist. These facts are used only for that preview.
type plannedPublicationEntry struct {
	incarnation contract.ID
}

func newSelectedPublicationChecks(image *selectedImage) (*selectedPublicationChecks, error) {
	return newPublicationChecks(image, nil)
}

func newPublicationChecks(image *selectedImage, planned []plannedPublicationEntry) (*selectedPublicationChecks, error) {
	selected, err := selectedPublicationRelation(image)
	if err != nil {
		return nil, err
	}
	return newPublicationChecksFromRelation(image, planned, selected)
}

func newPublicationChecksFromRelation(image *selectedImage, planned []plannedPublicationEntry, selected selectedPublication) (*selectedPublicationChecks, error) {
	checks := &selectedPublicationChecks{selected: selected,
		entries:      make(map[contract.ID]bool, image.root.ValueEntryCount),
		active:       make(map[contract.ID]bool, len(selected.coordinates)),
		destinations: make(map[string]uint64, contract.MaxOutputBindings),
		targets:      make(map[contract.ID]uint64, image.root.ValueEntryCount),
		routes:       make(map[contract.ID]uint64, image.root.ValueEntryCount+1)}
	addEntry := func(incarnation contract.ID) error {
		if incarnation.IsZero() || checks.entries[incarnation] {
			return contract.ErrRecord
		}
		checks.entries[incarnation] = true
		return nil
	}
	if planned != nil {
		for _, entry := range planned {
			if err := addEntry(entry.incarnation); err != nil {
				return nil, err
			}
		}
	} else {
		for _, page := range image.pages {
			if page == nil {
				continue
			}
			for _, entry := range page.Slots {
				if entry != nil {
					if err := addEntry(entry.Incarnation); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	return checks, nil
}

func (c *selectedPublicationChecks) visitor(image *selectedImage) contract.OutputConfigurationVisit {
	return contract.OutputConfigurationVisit{
		Binding: func(_ contract.ID, destination string, _ contract.OutputDestination) error {
			if _, present := c.destinations[destination]; present {
				return contract.ErrRecord
			}
			if len(c.destinations) >= contract.MaxOutputBindings {
				return contract.ErrRecord
			}
			c.destinations[destination] = uint64(1) << uint(len(c.destinations))
			return nil
		},
		Group: func(group []contract.ID) error {
			for _, entry := range group {
				if !c.entries[entry] {
					return contract.ErrRecord
				}
			}
			return nil
		},
		Target: func(binding, entry, id contract.ID, destination string) error {
			coordinate, present := c.selected.coordinates[id]
			if !present || !c.entries[entry] || c.active[id] ||
				coordinate.BindingState != contract.PublicationBindingActive ||
				coordinate.ActiveBindingIncarnationID != binding {
				return contract.ErrRecord
			}
			bit, present := c.destinations[destination]
			if !present {
				if len(c.destinations) >= contract.MaxOutputBindings {
					return contract.ErrRecord
				}
				bit = uint64(1) << uint(len(c.destinations))
				c.destinations[destination] = bit
			}
			c.targets[entry] |= bit
			c.active[id] = true
			return nil
		},
		Route: func(entry contract.ID, destinations []string) error {
			if !entry.IsZero() && !c.entries[entry] {
				return contract.ErrRecord
			}
			if _, present := c.routes[entry]; present {
				return contract.ErrRecord
			}
			var mask uint64
			for _, destination := range destinations {
				bit, present := c.destinations[destination]
				if !present {
					return contract.ErrRecord
				}
				mask |= bit
			}
			c.routes[entry] = mask
			return nil
		},
	}
}

func (c *selectedPublicationChecks) complete() error {
	for id, coordinate := range c.selected.coordinates {
		if coordinate.BindingState == contract.PublicationBindingActive && !c.active[id] {
			return contract.ErrRecord
		}
	}
	defaultMask, present := c.routes[contract.ID{}]
	if !present {
		return contract.ErrRecord
	}
	for entry := range c.entries {
		effective, overridden := c.routes[entry]
		if !overridden {
			effective = defaultMask
		}
		if effective != c.targets[entry] {
			return contract.ErrRecord
		}
	}
	return nil
}

func publicationSelectedRowProofs(image *selectedImage) (map[generatedRecordKey]selectedPublicationRowProof, error) {
	if image == nil || len(image.support) != len(image.root.RequiredSupport) ||
		len(image.adminIndex.Pages) != len(image.support) {
		return nil, contract.ErrRecord
	}
	rows := make(map[generatedRecordKey]selectedPublicationRowProof)
	for i, page := range image.support {
		ref := image.root.RequiredSupport[i]
		if page.Domain != image.root.Domain || page.Object != ref.Object || page.Index != ref.Index ||
			image.adminIndex.Pages[i].Ref != ref {
			return nil, contract.ErrRecord
		}
		if len(image.supportFacts) == len(image.support) && len(image.supportFacts[i].rows) != 0 {
			facts := image.supportFacts[i]
			if facts.ref != ref || len(facts.rows) != len(facts.ordinals) {
				return nil, contract.ErrRecord
			}
			for j, fact := range facts.rows {
				if fact.Kind() != contract.PublicationCoordinateSupportKind && fact.Kind() != contract.PublicationMarkerSupportKind {
					continue
				}
				if j >= len(page.Records) || page.Records[j].Kind != fact.Kind() || page.Records[j].RecordID != fact.RecordID() {
					return nil, contract.ErrRecord
				}
				body := page.Records[j].Body
				if body != nil && (uint32(len(body)) != fact.BodyLength() || contract.Hash(body) != fact.BodyDigest()) {
					return nil, contract.ErrRecord
				}
				key := generatedRecordKey{kind: fact.Kind(), id: fact.RecordID()}
				if _, duplicate := rows[key]; duplicate {
					return nil, contract.ErrRecord
				}
				rows[key] = selectedPublicationRowProof{ref: ref, physical: facts.ordinals[j],
					length: fact.BodyLength(), bodyDigest: fact.BodyDigest()}
			}
			continue
		}
		logical := 0
		for _, span := range image.adminIndex.Pages[i].Spans {
			for physical := uint32(span.First); physical < uint32(span.First)+uint32(span.Count); physical++ {
				if logical >= len(page.Records) {
					return nil, contract.ErrRecord
				}
				row := page.Records[logical]
				logical++
				if row.Kind != contract.PublicationCoordinateSupportKind && row.Kind != contract.PublicationMarkerSupportKind {
					continue
				}
				if len(row.Body) == 0 {
					return nil, contract.ErrRecord
				}
				key := generatedRecordKey{kind: row.Kind, id: row.RecordID}
				if _, duplicate := rows[key]; duplicate {
					return nil, contract.ErrRecord
				}
				rows[key] = selectedPublicationRowProof{ref: ref, physical: uint16(physical),
					length: uint32(len(row.Body)), bodyDigest: contract.Hash(row.Body)}
			}
		}
		if logical != len(page.Records) {
			return nil, contract.ErrRecord
		}
	}
	return rows, nil
}

func validateSelectedPublicationConfigurationRelations(ctx context.Context, image *selectedImage,
	reader selectedConfigurationReader) (*selectedPublicationChecks, Result, error) {
	return validatePublicationConfigurationRelations(ctx, image, reader, nil)
}

func validatePublicationConfigurationRelations(ctx context.Context, image *selectedImage,
	reader selectedConfigurationReader, planned []plannedPublicationEntry) (*selectedPublicationChecks, Result, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, failure(EvidenceUnavailable, ReadUnavailable), nil
	}
	checks, err := newPublicationChecks(image, planned)
	if err != nil {
		return nil, Result{}, err
	}
	return validatePublicationChecks(ctx, image, reader, checks)
}

func validatePublicationChecks(ctx context.Context, image *selectedImage, reader selectedConfigurationReader, checks *selectedPublicationChecks) (*selectedPublicationChecks, Result, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, failure(EvidenceUnavailable, ReadUnavailable), nil
	}
	visit := checks.visitor(image)
	if reader != nil {
		result := reader.validateSelectedOutputConfigurationRelations(ctx, &visit)
		if result.Outcome != 0 {
			return nil, result, nil
		}
	} else {
		source, err := selectedOutputConfigurationBodySource(image)
		if err != nil {
			return nil, Result{}, err
		}
		if err := contract.VisitOutputConfigurationSource(image.root.Domain, image.root.OutputConfiguration, source, visit); err != nil {
			return nil, Result{}, err
		}
	}
	if err := checks.complete(); err != nil {
		return nil, Result{}, err
	}
	return checks, Result{}, nil
}

// Completion publishes a proof only after the complete relation passes.
func validateSelectedPublicationConfiguration(ctx context.Context, image *selectedImage,
	reader selectedConfigurationReader) (*selectedPublicationProof, Result, error) {
	checks, result, err := validateSelectedPublicationConfigurationRelations(ctx, image, reader)
	if err != nil || result.Outcome != 0 {
		return nil, result, err
	}
	rows, err := publicationSelectedRowProofs(image)
	if err != nil || len(rows) != len(checks.selected.coordinates)+len(checks.selected.markers) {
		return nil, Result{}, contract.ErrRecord
	}
	digest, err := publicationRootDigest(image.root)
	if err != nil {
		return nil, Result{}, err
	}
	return &selectedPublicationProof{rootDigest: digest, indexRef: image.root.AdministrativeIndex, rows: rows}, Result{}, nil
}

func (p *selectedPublicationProof) validFor(image *selectedImage) bool {
	_, valid := p.selectedRelation(image)
	return valid
}

// selectedRelation borrows immutable byte fields for synchronous validation.
// Its maps are private to the caller; no byte field may be changed.
func (p *selectedPublicationProof) selectedRelation(image *selectedImage) (selectedPublication, bool) {
	if p == nil || image == nil || !p.matchesSelectedRows(image) {
		return selectedPublication{}, false
	}
	selected, err := selectedPublicationRelation(image)
	return selected, err == nil
}

func (p *selectedPublicationProof) relationFor(image *selectedImage) (selectedPublication, bool) {
	selected, valid := p.selectedRelation(image)
	if !valid {
		return selectedPublication{}, false
	}
	for id, coordinate := range selected.coordinates {
		coordinate.DeletionTargetData = bytes.Clone(coordinate.DeletionTargetData)
		selected.coordinates[id] = coordinate
	}
	return selected, true
}

func (p *selectedPublicationProof) matchesSelectedRows(image *selectedImage) bool {
	if p == nil || image == nil || p.indexRef != image.root.AdministrativeIndex {
		return false
	}
	digest, err := publicationRootDigest(image.root)
	if err != nil || digest != p.rootDigest {
		return false
	}
	rows, err := publicationSelectedRowProofs(image)
	if err != nil || len(rows) != len(p.rows) {
		return false
	}
	for key, row := range rows {
		if p.rows[key] != row {
			return false
		}
	}
	return true
}

// validOutputSelection verifies an already selected signed family. It creates
// no reservation and grants no permission to execute an output action.
func (s *StateSession) validOutputSelection() bool {
	if s == nil {
		return false
	}
	return selectedOutputSelection(s.head, s.selectedImage())
}
func selectedOutputSelection(head format.Head, s *selectedImage) bool {
	if s == nil {
		return false
	}
	selected, valid := s.publicationProof.selectedRelation(s)
	if !valid {
		return false
	}
	return selectedOutputSelectionRelation(head, s, selected)
}

func selectedOutputSelectionRelation(head format.Head, s *selectedImage, selected selectedPublication) bool {
	if reserve := head.OutputReserve; head.AuthKind == format.OutputReserveAuth && reserve != nil {
		marker, ok := selected.markers[reserve.AttemptID]
		coordinate, present := selected.coordinates[reserve.CoordinateID]
		if !ok || !present || !publicationReserveSelectionMatches(*reserve, s.root, marker, coordinate) {
			return false
		}
		if !reserve.OwnedBirthAttemptID.IsZero() {
			birth, ok := selected.markers[reserve.OwnedBirthAttemptID]
			if !ok || reserve.BirthTargetRowDigest != birth.Projection.TargetRowDigest {
				return false
			}
		}
		return true
	}
	if closeSubject := head.OutputClose; head.AuthKind == format.OutputCloseAuth && closeSubject != nil {
		marker, ok := selected.markers[closeSubject.AttemptID]
		return ok && publicationCloseSelectionMatches(*closeSubject, s.root, marker)
	}
	return false
}

func publicationReserveSelectionMatches(reserve contract.OutputReserveSubject, root format.Root,
	marker contract.PublicationMarker, coordinate contract.PublicationCoordinate) bool {
	if marker.State != contract.PublicationMayHaveEntered || coordinate.LatestUnresolvedAttemptID != marker.AttemptID ||
		reserve.CurrentAccessRoot != root.CurrentAccess.AccessRoot || reserve.ConfigurationDigest != root.OutputConfiguration.ConfigurationDigest ||
		reserve.PublicationIncarnationID != coordinate.CurrentPublicationIncarnationID || reserve.AdmissionOrdinal != coordinate.LastAdmissionOrdinal {
		return false
	}
	digest, err := contract.OutputReserveAdmissionDigest(reserve, marker)
	return err == nil && digest == marker.AuthoritySubjectDigest
}

func publicationCloseSelectionMatches(closeSubject contract.OutputCloseSubject, root format.Root, marker contract.PublicationMarker) bool {
	if closeSubject.CurrentAccessRoot != root.CurrentAccess.AccessRoot || closeSubject.ConfigurationDigest != root.OutputConfiguration.ConfigurationDigest ||
		closeSubject.DomainID != marker.DomainID || closeSubject.OperationID != marker.OperationID || closeSubject.CoordinateID != marker.CoordinateID ||
		closeSubject.ReservationAdmissionDigest != marker.AuthoritySubjectDigest || closeSubject.ActionProjectionCommitment != marker.ProjectionCommitment ||
		closeSubject.Action != marker.Projection.Action || closeSubject.BindingIncarnationID != marker.Projection.BindingIncarnationID ||
		closeSubject.EntryIncarnationID != marker.Projection.EntryIncarnationID || closeSubject.TargetRowDigest != marker.Projection.TargetRowDigest ||
		closeSubject.OwnedBirthAttemptID != marker.Projection.OwnedBirthAttemptID || closeSubject.UncertainCreateAttemptID != marker.Projection.UncertainCreateAttemptID ||
		closeSubject.ExclusiveNamespaceDigest != marker.Projection.ExclusiveNamespaceDigest || closeSubject.EntryClass != marker.Evidence.Entry ||
		closeSubject.ResultClass != marker.Evidence.Class || closeSubject.LateRisk != marker.LateEffectRisk {
		return false
	}
	body, err := contract.EncodePublicationEvidence(marker.Evidence)
	return err == nil && contract.Hash(body) == closeSubject.ResultEvidenceDigest
}

func (s *StateSession) bindPreservedPublication(ctx context.Context, next *StateSession) error {
	if s == nil || next == nil || !s.selectedOutputComplete() || !next.selectedOutputComplete() || next.root.OutputConfiguration != s.root.OutputConfiguration {
		return contract.ErrRecord
	}
	reader, err := s.preservedPublicationReader(next)
	if err != nil {
		return err
	}
	proof, result, err := validateSelectedPublicationConfiguration(ctx, next.selectedImage(), reader)
	if result.Outcome != 0 {
		return selectedReadFailure(result)
	}
	if err != nil {
		return err
	}
	next.publicationProof = proof
	return nil
}

func (s *StateSession) preservedPublicationReader(next *StateSession) (selectedConfigurationReader, error) {
	var reader selectedConfigurationReader
	if _, err := next.outputConfigurationBodySource(); err != nil {
		if len(s.supportFacts) != len(s.root.RequiredSupport) {
			return nil, contract.ErrRecord
		}
		borrowed := *s
		reader = &borrowed
	}
	return reader, nil
}

func (s *StateSession) validatePreservedPublicationPlan(ctx context.Context, next *StateSession, planned []plannedPublicationEntry) error {
	reader, err := s.preservedPublicationReader(next)
	if err != nil {
		return err
	}
	_, result, err := validatePublicationConfigurationRelations(ctx, next.selectedImage(), reader, planned)
	if result.Outcome != 0 {
		return selectedReadFailure(result)
	}
	return err
}

type selectedConfigurationReader interface {
	validateSelectedOutputConfigurationRelations(context.Context, *contract.OutputConfigurationVisit) Result
}

func validateSelectedPublicationConfigurationWithReader(ctx context.Context, image *selectedImage, reader selectedObjectReader) (*selectedPublicationProof, Result, error) {
	return validateSelectedPublicationConfiguration(ctx, image, selectedOutputConfigurationReader{image, reader})
}

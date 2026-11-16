package core

import (
	"bytes"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func publicationRelationID(n byte) contract.ID {
	var id contract.ID
	id[0] = n
	return id
}

func publicationRelationFixture(t *testing.T) (contract.ID, contract.PublicationCoordinate, contract.PublicationMarker,
	[]contract.SupportRecord) {
	t.Helper()
	return publicationRelationFixtureForDomain(t, publicationRelationID(1))
}

func publicationRelationFixtureForDomain(t *testing.T, domain contract.ID) (contract.ID,
	contract.PublicationCoordinate, contract.PublicationMarker, []contract.SupportRecord) {
	t.Helper()
	coordinateID, err := contract.PublicationCoordinateID(domain, "provider", "account/slot")
	if err != nil {
		t.Fatal(err)
	}
	binding, entry, attempt := publicationRelationID(2), publicationRelationID(3), publicationRelationID(4)
	coordinate := contract.PublicationCoordinate{Schema: 5, DomainID: domain, CoordinateID: coordinateID,
		ServiceContractID: "provider", CanonicalTarget: "account/slot", BindingState: contract.PublicationBindingActive,
		OwnerState: contract.PublicationOwnerUncertainCreate, ActiveBindingIncarnationID: binding,
		LastBindingIncarnationID: binding, LastEntryIncarnationID: entry, CurrentPublicationIncarnationID: publicationRelationID(14), LastAdmissionOrdinal: 1,
		LatestUnresolvedAttemptID: attempt, PossibleRemoteObject: 1,
		DeletionDestinationID: "destination", DeletionConsumerLocator: "locator", DeletionTargetContractID: "profile",
		DeletionConfigContractID: "2", DeletionCredentialRouteContractID: "route/v1", DeletionPayloadEncoding: contract.OutputEncodingRaw,
		DeletionTargetRowDigest: publicationRelationID(5)}
	projection := contract.PublicationProjection{Schema: 4, DomainID: domain,
		ConfigurationDigest: publicationRelationID(6), CoordinateID: coordinateID,
		BindingIncarnationID: binding, EntryIncarnationID: entry, TargetRowDigest: coordinate.DeletionTargetRowDigest,
		Action: contract.PublicationCreateEmpty, PolicyDigest: publicationRelationID(7),
		RequestContractDigest: publicationRelationID(8), ActingRecipientID: publicationRelationID(9)}
	commitment, err := contract.PublicationProjectionCommitment(projection)
	if err != nil {
		t.Fatal(err)
	}
	marker := contract.PublicationMarker{Schema: 5, DomainID: domain, OperationID: publicationRelationID(10),
		AttemptID: attempt, CoordinateID: coordinateID, PublicationIncarnationID: publicationRelationID(14), AdmissionOrdinal: 1, Projection: projection,
		ProjectionCommitment:   commitment,
		AuthoritySubjectDigest: publicationRelationID(12), ExecutorID: "executor", CredentialRouteID: "route",
		State: contract.PublicationUnknown, Evidence: contract.PublicationEvidence{Schema: 3,
			Entry: contract.PublicationMayHaveEnteredEntry, Class: contract.PublicationUnproved,
			ResponseContractDigest: publicationRelationID(13)}, BirthServiceContractID: "provider", BirthTargetContractID: "profile"}
	rows := publicationRelationRows(t, coordinate, marker)
	return domain, coordinate, marker, rows
}

func publicationRelationRows(t *testing.T, coordinate contract.PublicationCoordinate,
	marker contract.PublicationMarker) []contract.SupportRecord {
	t.Helper()
	coordinateBody, err := contract.EncodePublicationCoordinate(coordinate)
	if err != nil {
		t.Fatal(err)
	}
	markerBody, err := contract.EncodePublicationMarker(marker)
	if err != nil {
		t.Fatal(err)
	}
	return []contract.SupportRecord{
		{Kind: contract.PublicationCoordinateSupportKind, RecordID: coordinate.CoordinateID, Body: coordinateBody},
		{Kind: contract.PublicationMarkerSupportKind, RecordID: marker.AttemptID, Body: markerBody},
	}
}

// full_only: false
func TestSelectedPublicationRelations(t *testing.T) {
	domain, coordinate, marker, rows := publicationRelationFixture(t)
	if _, err := publicationFixtureRowsRelation(domain, rows); err != nil {
		t.Fatalf("selected uncertain create refused: %v", err)
	}
	t.Run("missing coordinate", func(t *testing.T) {
		if _, err := publicationFixtureRowsRelation(domain, rows[1:]); err == nil {
			t.Fatal("orphan marker accepted")
		}
	})
	t.Run("missing uncertain create", func(t *testing.T) {
		if _, err := publicationFixtureRowsRelation(domain, rows[:1]); err == nil {
			t.Fatal("uncertain owner without create marker accepted")
		}
	})
	t.Run("wrong admission ordinal", func(t *testing.T) {
		next := marker
		next.AdmissionOrdinal = 2
		if _, err := publicationFixtureRowsRelation(domain, publicationRelationRows(t, coordinate, next)); err == nil {
			t.Fatal("marker beyond selected coordinate ordinal accepted")
		}
	})
	t.Run("qualified birth", func(t *testing.T) {
		nextCoordinate, nextMarker := coordinate, marker
		nextMarker.State = contract.PublicationAcknowledged
		nextMarker.Evidence.Class = contract.PublicationRequestAcknowledged
		nextMarker.Evidence.NormalizedStatus = 201
		nextMarker.Evidence.SafeResourceID = "exact-resource"
		nextMarker.Evidence.ConsumerLocator = "locator"
		nextCoordinate.OwnerState = contract.PublicationOwnerQualified
		nextCoordinate.LatestUnresolvedAttemptID = contract.ID{}
		nextCoordinate.OwnedBirthAttemptID = marker.AttemptID
		var err error
		nextCoordinate.OwnedInstanceDigest, err = contract.PublicationOwnedInstanceDigest(domain,
			coordinate.CoordinateID, marker.Projection.BindingIncarnationID, marker.Projection.EntryIncarnationID,
			marker.Projection.TargetRowDigest, marker.AttemptID, nextMarker.Evidence.SafeResourceID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := publicationFixtureRowsRelation(domain, publicationRelationRows(t, nextCoordinate, nextMarker)); err != nil {
			t.Fatalf("qualified birth refused: %v", err)
		}
		nextCoordinate.OwnedInstanceDigest = publicationRelationID(99)
		if _, err := publicationFixtureRowsRelation(domain, publicationRelationRows(t, nextCoordinate, nextMarker)); err == nil {
			t.Fatal("unmatched owned instance accepted")
		}
	})
}

// full_only: false
func TestSelectedPublicationEnteredActionsRequireDeletionInputs(t *testing.T) {
	for _, action := range []struct {
		name string
		kind uint8
	}{
		{"create_empty", contract.PublicationCreateEmpty},
		{"create_with_value", contract.PublicationCreateWithValue},
		{"write_value", contract.PublicationWriteValue},
		{"update_policy", contract.PublicationUpdatePolicy},
		{"delete_owned", contract.PublicationDeleteOwned},
		{"delete_reserved_slot", contract.PublicationDeleteReservedSlot},
	} {
		t.Run(action.name, func(t *testing.T) {
			for _, state := range []struct {
				name string
				kind uint8
			}{{"may_have_entered", contract.PublicationMayHaveEntered}, {"unknown", contract.PublicationUnknown}} {
				t.Run(state.name, func(t *testing.T) {
					for _, retired := range []bool{false, true} {
						name := "active_zero_pointer"
						if retired {
							name = "retired_zero_pointer"
						}
						t.Run(name, func(t *testing.T) {
							domain, coordinate, marker, _ := publicationRelationFixture(t)
							dependency := marker
							marker.State = state.kind
							marker.Projection.Action = action.kind
							switch action.kind {
							case contract.PublicationCreateWithValue:
								marker.Projection.ValueBasisDigest = publicationRelationID(70)
							case contract.PublicationWriteValue, contract.PublicationUpdatePolicy, contract.PublicationDeleteOwned:
								dependency.State = contract.PublicationAcknowledged
								dependency.Evidence.Class = contract.PublicationRequestAcknowledged
								dependency.Evidence.NormalizedStatus = 201
								dependency.Evidence.SafeResourceID = "exact-resource"
								dependency.Evidence.ConsumerLocator = "locator"
								marker.Projection.OwnedBirthAttemptID = dependency.AttemptID
								if action.kind == contract.PublicationWriteValue {
									marker.Projection.ValueBasisDigest = publicationRelationID(70)
								}
								if action.kind == contract.PublicationDeleteOwned {
									marker.Projection.PolicyDigest = contract.ID{}
								}
							case contract.PublicationDeleteReservedSlot:
								dependency.State = state.kind
								marker.Projection.UncertainCreateAttemptID = dependency.AttemptID
								marker.Projection.ExclusiveNamespaceDigest = publicationRelationID(71)
								marker.Projection.PolicyDigest = contract.ID{}
							}
							if action.kind != contract.PublicationCreateEmpty && action.kind != contract.PublicationCreateWithValue {
								marker.AttemptID = publicationRelationID(72)
								marker.AdmissionOrdinal = 2
								marker.BirthServiceContractID, marker.BirthTargetContractID = "", ""
								marker.Evidence.ConsumerLocator = ""
							}
							var err error
							marker.ProjectionCommitment, err = contract.PublicationProjectionCommitment(marker.Projection)
							if err != nil {
								t.Fatal(err)
							}
							coordinate.OwnerState = contract.PublicationOwnerNone
							coordinate.LatestUnresolvedAttemptID = contract.ID{}
							coordinate.PossibleRemoteObject, coordinate.LateEffectRisk = 0, 0
							coordinate.LastAdmissionOrdinal = marker.AdmissionOrdinal
							if retired {
								coordinate.BindingState = contract.PublicationBindingRetired
								coordinate.ActiveBindingIncarnationID = contract.ID{}
							}
							rows := publicationRelationRows(t, coordinate, marker)
							if marker.AttemptID != dependency.AttemptID {
								body, err := contract.EncodePublicationMarker(dependency)
								if err != nil {
									t.Fatal(err)
								}
								rows = append(rows, contract.SupportRecord{Kind: contract.PublicationMarkerSupportKind,
									RecordID: dependency.AttemptID, Body: body})
							}
							if _, err := publicationFixtureRowsRelation(domain, rows); err != nil {
								t.Fatalf("retained deletion inputs refused: %v", err)
							}
							coordinate.DeletionDestinationID, coordinate.DeletionConsumerLocator = "", ""
							coordinate.DeletionTargetContractID, coordinate.DeletionConfigContractID = "", ""
							coordinate.DeletionCredentialRouteContractID, coordinate.DeletionPayloadEncoding = "", 0
							coordinate.DeletionTargetRowDigest = contract.ID{}
							rows[0].Body, err = contract.EncodePublicationCoordinate(coordinate)
							if err != nil {
								t.Fatalf("coordinate-local fixture refused: %v", err)
							}
							if _, err := publicationFixtureRowsRelation(domain, rows); err == nil {
								t.Fatal("entered action accepted without retained deletion inputs")
							}
						})
					}
				})
			}
		})
	}
}

// full_only: false
func TestSelectedPublicationNoObligationAllowsAbsentDeletionInputs(t *testing.T) {
	for _, name := range []string{"never_entered_active", "retired", "compacted_terminal_ack"} {
		t.Run(name, func(t *testing.T) {
			domain, coordinate, _, _ := publicationRelationFixture(t)
			coordinate.OwnerState = contract.PublicationOwnerNone
			coordinate.LatestUnresolvedAttemptID = contract.ID{}
			coordinate.PossibleRemoteObject, coordinate.LateEffectRisk = 0, 0
			coordinate.DeletionDestinationID, coordinate.DeletionConsumerLocator = "", ""
			coordinate.DeletionTargetContractID, coordinate.DeletionConfigContractID = "", ""
			coordinate.DeletionCredentialRouteContractID, coordinate.DeletionPayloadEncoding = "", 0
			coordinate.DeletionTargetRowDigest = contract.ID{}
			switch name {
			case "never_entered_active":
				coordinate.LastAdmissionOrdinal = 0
			case "retired":
				coordinate.BindingState = contract.PublicationBindingRetired
				coordinate.ActiveBindingIncarnationID = contract.ID{}
			case "compacted_terminal_ack":
				coordinate.LastPolicyAckAttemptID, coordinate.LastPolicyDigest = publicationRelationID(80), publicationRelationID(81)
				coordinate.LastPolicyAckIncarnationID = coordinate.CurrentPublicationIncarnationID
				coordinate.LastPolicyAckOrdinal = coordinate.LastAdmissionOrdinal
			}
			body, err := contract.EncodePublicationCoordinate(coordinate)
			if err != nil {
				t.Fatal(err)
			}
			rows := []contract.SupportRecord{{Kind: contract.PublicationCoordinateSupportKind,
				RecordID: coordinate.CoordinateID, Body: body}}
			if _, err := publicationFixtureRowsRelation(domain, rows); err != nil {
				t.Fatalf("no-obligation coordinate refused: %v", err)
			}
		})
	}
}

// full_only: false
func TestSelectedPublicationTerminalAckSummaries(t *testing.T) {
	domain, coordinate, birth, _ := publicationRelationFixture(t)
	birth.Projection.Action = contract.PublicationCreateWithValue
	birth.Projection.ValueBasisDigest = publicationRelationID(70)
	var err error
	birth.ProjectionCommitment, err = contract.PublicationProjectionCommitment(birth.Projection)
	if err != nil {
		t.Fatal(err)
	}
	birth.State = contract.PublicationAcknowledged
	birth.Evidence.Class = contract.PublicationRequestAcknowledged
	birth.Evidence.NormalizedStatus = 201
	birth.Evidence.SafeResourceID = "exact-resource"
	birth.Evidence.ConsumerLocator = "locator"
	coordinate.OwnerState = contract.PublicationOwnerQualified
	coordinate.LatestUnresolvedAttemptID = contract.ID{}
	coordinate.OwnedBirthAttemptID = birth.AttemptID
	coordinate.OwnedInstanceDigest, err = contract.PublicationOwnedInstanceDigest(domain,
		coordinate.CoordinateID, birth.Projection.BindingIncarnationID, birth.Projection.EntryIncarnationID,
		birth.Projection.TargetRowDigest, birth.AttemptID, birth.Evidence.SafeResourceID)
	if err != nil {
		t.Fatal(err)
	}
	coordinate.LastValueAckAttemptID = birth.AttemptID
	coordinate.LastValueAckIncarnationID, coordinate.LastValueAckOrdinal = birth.PublicationIncarnationID, birth.AdmissionOrdinal
	coordinate.LastValueDigest, err = contract.PublicationSelectedValueDigest(domain,
		birth.Projection.ValueBasisDigest, birth.AttemptID, coordinate.OwnedInstanceDigest)
	if err != nil {
		t.Fatal(err)
	}
	coordinate.LastPolicyAckAttemptID, coordinate.LastPolicyDigest = birth.AttemptID, birth.Projection.PolicyDigest
	coordinate.LastPolicyAckIncarnationID, coordinate.LastPolicyAckOrdinal = birth.PublicationIncarnationID, birth.AdmissionOrdinal
	if _, err := publicationFixtureRowsRelation(domain, publicationRelationRows(t, coordinate, birth)); err != nil {
		t.Fatalf("matched selected ACK summaries refused: %v", err)
	}
	changedValue := coordinate
	changedValue.LastValueDigest = publicationRelationID(71)
	if _, err := publicationFixtureRowsRelation(domain, publicationRelationRows(t, changedValue, birth)); err == nil {
		t.Fatal("selected value ACK accepted with another digest")
	}
	changedPolicy := coordinate
	changedPolicy.LastPolicyDigest = publicationRelationID(72)
	if _, err := publicationFixtureRowsRelation(domain, publicationRelationRows(t, changedPolicy, birth)); err == nil {
		t.Fatal("selected policy ACK accepted with another digest")
	}
	wrongDelete := coordinate
	wrongDelete.LastDeleteAckAttemptID = birth.AttemptID
	wrongDelete.LastDeleteAckIncarnationID, wrongDelete.LastDeleteAckOrdinal = birth.PublicationIncarnationID, birth.AdmissionOrdinal
	if _, err := publicationFixtureRowsRelation(domain, publicationRelationRows(t, wrongDelete, birth)); err == nil {
		t.Fatal("create ACK accepted as delete ACK")
	}
	// A later terminal value marker can be compacted after its exact signed
	// summary is retained. Its absence must not erase that historical fact.
	write := birth
	write.AttemptID = publicationRelationID(73)
	write.AdmissionOrdinal = 2
	write.Projection.Action = contract.PublicationWriteValue
	write.Projection.OwnedBirthAttemptID = birth.AttemptID
	write.Projection.ValueBasisDigest = publicationRelationID(74)
	write.BirthServiceContractID, write.BirthTargetContractID = "", ""
	write.Evidence.ConsumerLocator = ""
	write.ProjectionCommitment, err = contract.PublicationProjectionCommitment(write.Projection)
	if err != nil {
		t.Fatal(err)
	}
	coordinate.LastAdmissionOrdinal = 2
	coordinate.LastValueAckAttemptID = write.AttemptID
	coordinate.LastValueAckIncarnationID, coordinate.LastValueAckOrdinal = write.PublicationIncarnationID, write.AdmissionOrdinal
	coordinate.LastValueDigest, err = contract.PublicationSelectedValueDigest(domain,
		write.Projection.ValueBasisDigest, birth.AttemptID, coordinate.OwnedInstanceDigest)
	if err != nil {
		t.Fatal(err)
	}
	rows := publicationRelationRows(t, coordinate, birth)
	if _, err := publicationFixtureRowsRelation(domain, rows); err != nil {
		t.Fatalf("compacted terminal value ACK refused: %v", err)
	}
	writeBody, err := contract.EncodePublicationMarker(write)
	if err != nil {
		t.Fatal(err)
	}
	rows = append(rows, contract.SupportRecord{Kind: contract.PublicationMarkerSupportKind, RecordID: write.AttemptID, Body: writeBody})
	if _, err := publicationFixtureRowsRelation(domain, rows); err != nil {
		t.Fatalf("retained terminal value marker refused: %v", err)
	}
	write.Projection.ValueBasisDigest = publicationRelationID(75)
	write.ProjectionCommitment, err = contract.PublicationProjectionCommitment(write.Projection)
	if err != nil {
		t.Fatal(err)
	}
	rows[2].Body, err = contract.EncodePublicationMarker(write)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publicationFixtureRowsRelation(domain, rows); err == nil {
		t.Fatal("retained value marker accepted with a different selected basis")
	}
}

func publicationSelectedImageFixture(t *testing.T) selectedImage {
	t.Helper()
	domain, _, _, rows := publicationRelationFixture(t)
	return publicationSelectedImageFromRows(t, domain, rows)
}

func publicationSelectedImageFromRows(t *testing.T, domain contract.ID, rows []contract.SupportRecord) selectedImage {
	t.Helper()
	if len(rows) < 2 {
		t.Fatal("publication rows missing")
	}
	coordinate, err := contract.InspectPublicationCoordinate(rows[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	requiredBirths := make(map[contract.ID]bool)
	if coordinate.OwnerState == contract.PublicationOwnerQualified {
		requiredBirths[coordinate.OwnedBirthAttemptID] = true
	}
	for _, row := range rows[1:] {
		marker, err := contract.InspectPublicationMarker(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !marker.Projection.OwnedBirthAttemptID.IsZero() {
			requiredBirths[marker.Projection.OwnedBirthAttemptID] = true
		}
	}
	groups := make([]format.AdministrativeGroup, len(rows))
	for i, row := range rows {
		group, present, err := administrativeGroupFromRow(row, nil)
		if err != nil || !present {
			t.Fatalf("publication group: present=%t err=%v", present, err)
		}
		group.Disposable = administrativeDescriptor("selected-disposable", []byte{row.Kind})
		group.SelectedEvidenceSummary = contract.AdministrativeEvidenceQualifiedUnknown
		if row.Kind == contract.PublicationMarkerSupportKind {
			marker, err := contract.InspectPublicationMarker(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			if marker.State == contract.PublicationAcknowledged {
				group.SelectedEvidenceSummary = contract.AdministrativeEvidenceAcknowledged
			}
			group.UncertainCreateProof = boolByte(publicationMarkerProvesUncertainCreate(marker, coordinate))
		}
		if row.Kind == contract.PublicationCoordinateSupportKind && coordinate.OwnerState == contract.PublicationOwnerQualified {
			group.SelectedEvidenceSummary = contract.AdministrativeEvidenceAcknowledged
		}
		groups[i] = group
	}
	slices.SortFunc(groups, func(a, b format.AdministrativeGroup) int {
		return bytes.Compare(a.GroupID[:], b.GroupID[:])
	})
	find := func(id contract.ID) uint16 {
		for i, group := range groups {
			if group.GroupID == id {
				return uint16(i)
			}
		}
		t.Fatal("missing group")
		return 0
	}
	for _, row := range rows {
		if row.Kind != contract.PublicationMarkerSupportKind {
			continue
		}
		marker, err := contract.InspectPublicationMarker(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		related := []uint16{find(marker.CoordinateID)}
		if !marker.Projection.OwnedBirthAttemptID.IsZero() {
			related = append(related, find(marker.Projection.OwnedBirthAttemptID))
		}
		if marker.Projection.Action == contract.PublicationDeleteReservedSlot {
			related = append(related, find(marker.Projection.UncertainCreateAttemptID))
		}
		slices.Sort(related)
		groups[find(marker.AttemptID)].RelatedGroupIndexes = related
	}
	page := format.RequiredSupportPage{Domain: domain, Object: publicationRelationID(20), Records: rows}
	body, err := format.EncodeRequiredSupportPage(page)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(contract.RequiredSupportKind, domain, page.Object, 0, body)
	if err != nil {
		t.Fatal(err)
	}
	index := format.AdministrativeIndex{Domain: domain, Object: publicationRelationID(21),
		SliceSnapshot: publicationRelationID(22), Groups: groups,
		PublicationOrder: []format.PublicationCoordinateOrder{{CoordinateID: coordinate.CoordinateID, Incarnations: []contract.ID{publicationRelationID(14)}}},
		Pages:            []format.AdministrativePage{{Ref: ref}},
	}
	for i, row := range rows {
		mandatory := row.Kind == contract.PublicationCoordinateSupportKind ||
			requiredBirths[row.RecordID]
		index.Pages[0].Spans = append(index.Pages[0].Spans, format.AdministrativeSpan{
			First: uint16(i), Count: 1, Mandatory: mandatory, GroupIndexes: []uint16{find(row.RecordID)}})
		index.Pages[0].Rows = append(index.Pages[0].Rows, format.AdministrativeRowSummary{
			Kind: row.Kind, RecordID: row.RecordID, BodyLength: uint32(len(row.Body))})
	}
	if !index.Valid() {
		t.Fatal("fixture index invalid")
	}
	view := format.RequiredSupportPageView{Domain: domain, Object: page.Object}
	for _, row := range rows {
		view.Records = append(view.Records, contract.SupportRecordView(row))
	}
	return selectedImage{root: format.Root{Domain: domain, AdministrativeIndex: format.Ref{Object: index.Object},
		RequiredSupport: []format.Ref{ref}}, support: []format.RequiredSupportPageView{view}, adminIndex: index}
}

// full_only: false
func TestSelectedPublicationIndexRequiresExactOwnerAndMandatoryCoordinate(t *testing.T) {
	base := publicationSelectedImageFixture(t)
	if _, err := selectedPublicationRelation(&base); err != nil {
		t.Fatalf("valid selected relation refused: %v", err)
	}
	missingOwner := base
	missingOwner.adminIndex.Pages = slices.Clone(base.adminIndex.Pages)
	missingOwner.adminIndex.Pages[0].Spans = slices.Clone(base.adminIndex.Pages[0].Spans)
	missingOwner.adminIndex.Pages[0].Spans[0].GroupIndexes = slices.Clone(base.adminIndex.Pages[0].Spans[0].GroupIndexes)
	missingOwner.adminIndex.Pages[0].Spans[0].GroupIndexes[0] = base.adminIndex.Pages[0].Spans[1].GroupIndexes[0]
	if _, err := selectedPublicationRelation(&missingOwner); err == nil {
		t.Fatal("coordinate assigned to marker group")
	}
	optionalActive := base
	optionalActive.adminIndex.Pages = slices.Clone(base.adminIndex.Pages)
	optionalActive.adminIndex.Pages[0].Spans = slices.Clone(base.adminIndex.Pages[0].Spans)
	optionalActive.adminIndex.Pages[0].Spans[0].Mandatory = false
	if _, err := selectedPublicationRelation(&optionalActive); err == nil {
		t.Fatal("active coordinate made disposable")
	}
}

// full_only: false
func TestActivePublicationCoordinateCannotEndAsDisposableWork(t *testing.T) {
	image := publicationSelectedImageFixture(t)
	coordinateID := image.support[0].Records[0].RecordID
	state := StateSession{root: image.root, support: image.support, adminIndex: image.adminIndex}
	if _, _, err := state.administrativeWorkClosure(coordinateID); err == nil {
		t.Fatal("active output coordinate ended as auxiliary work")
	}
}

// full_only: false
func TestQualifiedPublicationBirthCannotEndAsDisposableWork(t *testing.T) {
	domain, coordinate, marker, _ := publicationRelationFixture(t)
	marker.State = contract.PublicationAcknowledged
	marker.Evidence.Class = contract.PublicationRequestAcknowledged
	marker.Evidence.NormalizedStatus = 201
	marker.Evidence.SafeResourceID = "exact-resource"
	marker.Evidence.ConsumerLocator = "locator"
	coordinate.OwnerState = contract.PublicationOwnerQualified
	coordinate.LatestUnresolvedAttemptID = contract.ID{}
	coordinate.OwnedBirthAttemptID = marker.AttemptID
	var err error
	coordinate.OwnedInstanceDigest, err = contract.PublicationOwnedInstanceDigest(domain, coordinate.CoordinateID,
		marker.Projection.BindingIncarnationID, marker.Projection.EntryIncarnationID,
		marker.Projection.TargetRowDigest, marker.AttemptID, marker.Evidence.SafeResourceID)
	if err != nil {
		t.Fatal(err)
	}
	image := publicationSelectedImageFromRows(t, domain, publicationRelationRows(t, coordinate, marker))
	state := StateSession{root: image.root, support: image.support, adminIndex: image.adminIndex}
	if _, _, err := state.administrativeWorkClosure(marker.AttemptID); err == nil {
		t.Fatal("qualified publication birth ended while its coordinate remains")
	}
}

// full_only: false
func TestReservedSlotDeleteDependsOnExactUncertainCreate(t *testing.T) {
	domain, coordinate, uncertain, _ := publicationRelationFixture(t)
	reserved := uncertain
	reserved.AttemptID = publicationRelationID(50)
	reserved.AdmissionOrdinal = 2
	reserved.Projection.Action = contract.PublicationDeleteReservedSlot
	reserved.Projection.PolicyDigest = contract.ID{}
	reserved.Projection.UncertainCreateAttemptID = uncertain.AttemptID
	reserved.Projection.ExclusiveNamespaceDigest = publicationRelationID(51)
	reserved.BirthServiceContractID, reserved.BirthTargetContractID = "", ""
	reserved.Evidence.ConsumerLocator = ""
	var err error
	reserved.ProjectionCommitment, err = contract.PublicationProjectionCommitment(reserved.Projection)
	if err != nil {
		t.Fatal(err)
	}
	coordinate.LastAdmissionOrdinal = 2
	coordinate.LatestUnresolvedAttemptID = reserved.AttemptID
	rows := publicationRelationRows(t, coordinate, uncertain)
	body, err := contract.EncodePublicationMarker(reserved)
	if err != nil {
		t.Fatal(err)
	}
	rows = append(rows, contract.SupportRecord{Kind: contract.PublicationMarkerSupportKind, RecordID: reserved.AttemptID, Body: body})
	image := publicationSelectedImageFromRows(t, domain, rows)
	if _, err := selectedPublicationRelation(&image); err != nil {
		t.Fatalf("complete reserved-slot relation refused: %v", err)
	}
	state := StateSession{root: image.root, support: image.support, adminIndex: image.adminIndex}
	_, scope, err := state.administrativeWorkClosure(uncertain.AttemptID)
	if err != nil || len(scope) != 2 ||
		!slices.ContainsFunc(scope, func(group format.AdministrativeGroup) bool { return group.GroupID == reserved.AttemptID }) {
		t.Fatalf("reserved delete survived uncertain-create exit: scope=%d err=%v", len(scope), err)
	}
	broken := image
	broken.adminIndex.Groups = slices.Clone(image.adminIndex.Groups)
	coordinateGroup := -1
	for i, group := range broken.adminIndex.Groups {
		if group.GroupID == coordinate.CoordinateID {
			coordinateGroup = i
		}
	}
	if coordinateGroup < 0 {
		t.Fatal("coordinate group missing")
	}
	for i := range broken.adminIndex.Groups {
		if broken.adminIndex.Groups[i].GroupID == reserved.AttemptID {
			broken.adminIndex.Groups[i].RelatedGroupIndexes = []uint16{uint16(coordinateGroup)}
		}
	}
	if !broken.adminIndex.Valid() {
		t.Fatal("missing-edge fixture is not a valid index")
	}
	if _, err := selectedPublicationRelation(&broken); err == nil {
		t.Fatal("reserved delete without exact uncertain-create dependency accepted")
	}
}

// full_only: false
func TestRetainedOwnedActionKeepsBirthThroughActiveReadd(t *testing.T) {
	domain, coordinate, original, _ := publicationRelationFixture(t)
	oldBirth := original
	oldBirth.State = contract.PublicationAcknowledged
	oldBirth.Evidence.Class = contract.PublicationRequestAcknowledged
	oldBirth.Evidence.NormalizedStatus = 201
	oldBirth.Evidence.SafeResourceID = "old-resource"
	oldBirth.Evidence.ConsumerLocator = "locator"
	oldAction := original
	oldAction.AttemptID = publicationRelationID(60)
	oldAction.AdmissionOrdinal = 2
	oldAction.Projection.Action = contract.PublicationWriteValue
	oldAction.Projection.OwnedBirthAttemptID = oldBirth.AttemptID
	oldAction.Projection.ValueBasisDigest = publicationRelationID(61)
	oldAction.BirthServiceContractID, oldAction.BirthTargetContractID = "", ""
	oldAction.Evidence.ConsumerLocator = ""
	var err error
	oldAction.ProjectionCommitment, err = contract.PublicationProjectionCommitment(oldAction.Projection)
	if err != nil {
		t.Fatal(err)
	}
	coordinate.OwnerState = contract.PublicationOwnerQualified
	coordinate.LastAdmissionOrdinal = 2
	coordinate.LatestUnresolvedAttemptID = oldAction.AttemptID
	coordinate.ActiveBindingIncarnationID = publicationRelationID(63)
	coordinate.OwnedBirthAttemptID = oldBirth.AttemptID
	coordinate.OwnedInstanceDigest, err = contract.PublicationOwnedInstanceDigest(domain, coordinate.CoordinateID,
		oldBirth.Projection.BindingIncarnationID, oldBirth.Projection.EntryIncarnationID,
		oldBirth.Projection.TargetRowDigest, oldBirth.AttemptID, oldBirth.Evidence.SafeResourceID)
	if err != nil {
		t.Fatal(err)
	}
	rows := publicationRelationRows(t, coordinate, oldBirth)
	body, err := contract.EncodePublicationMarker(oldAction)
	if err != nil {
		t.Fatal(err)
	}
	rows = append(rows, contract.SupportRecord{Kind: contract.PublicationMarkerSupportKind, RecordID: oldAction.AttemptID, Body: body})
	image := publicationSelectedImageFromRows(t, domain, rows)
	if _, err := selectedPublicationRelation(&image); err != nil {
		t.Fatalf("old owner proof refused after active re-add: %v", err)
	}
	mutated := image
	mutated.adminIndex.Pages = slices.Clone(image.adminIndex.Pages)
	mutated.adminIndex.Pages[0].Spans = slices.Clone(image.adminIndex.Pages[0].Spans)
	mutated.adminIndex.Pages[0].Spans[1].Mandatory = false
	if _, err := selectedPublicationRelation(&mutated); err == nil {
		t.Fatal("old birth proof made optional while its owned action remains")
	}
}

// These fixtures use one fixed incarnation. Cross-incarnation tests supply
// their complete expected ordered table directly to the relation checker.
func publicationFixtureRowsRelation(domain contract.ID, rows []contract.SupportRecord) (selectedPublication, error) {
	id, err := contract.PublicationCoordinateID(domain, "provider", "account/slot")
	if err != nil {
		return selectedPublication{}, err
	}
	return publicationRowsRelation(domain, rows, []format.PublicationCoordinateOrder{{CoordinateID: id, Incarnations: []contract.ID{publicationRelationID(14)}}})
}

// full_only: false
func TestSelectedPublicationKeepsOrderedIncarnationsAndExactACKStamps(t *testing.T) {
	domain, coordinate, birth, _ := publicationRelationFixture(t)
	birth.State, birth.Evidence.Class, birth.Evidence.NormalizedStatus, birth.Evidence.SafeResourceID = contract.PublicationAcknowledged, contract.PublicationRequestAcknowledged, 201, "exact-resource"
	birth.Evidence.ConsumerLocator = "locator"
	coordinate.OwnerState, coordinate.LatestUnresolvedAttemptID, coordinate.OwnedBirthAttemptID = contract.PublicationOwnerQualified, contract.ID{}, birth.AttemptID
	var err error
	coordinate.OwnedInstanceDigest, err = contract.PublicationOwnedInstanceDigest(domain, coordinate.CoordinateID, birth.Projection.BindingIncarnationID, birth.Projection.EntryIncarnationID, birth.Projection.TargetRowDigest, birth.AttemptID, birth.Evidence.SafeResourceID)
	if err != nil {
		t.Fatal(err)
	}
	historical, current := publicationRelationID(15), publicationRelationID(16)
	write := birth
	write.AttemptID, write.PublicationIncarnationID, write.AdmissionOrdinal = publicationRelationID(73), historical, 1
	write.Projection.Action, write.Projection.OwnedBirthAttemptID, write.Projection.ValueBasisDigest = contract.PublicationWriteValue, birth.AttemptID, publicationRelationID(74)
	write.BirthServiceContractID, write.BirthTargetContractID = "", ""
	write.Evidence.ConsumerLocator = ""
	write.ProjectionCommitment, err = contract.PublicationProjectionCommitment(write.Projection)
	if err != nil {
		t.Fatal(err)
	}
	deletion := write
	deletion.AttemptID, deletion.AdmissionOrdinal, deletion.Projection.Action = publicationRelationID(75), 2, contract.PublicationDeleteOwned
	deletion.Projection.ValueBasisDigest, deletion.Projection.PolicyDigest = contract.ID{}, contract.ID{}
	deletion.ProjectionCommitment, err = contract.PublicationProjectionCommitment(deletion.Projection)
	if err != nil {
		t.Fatal(err)
	}
	coordinate.CurrentPublicationIncarnationID, coordinate.LastAdmissionOrdinal = current, 3
	coordinate.LastValueAckAttemptID, coordinate.LastValueAckIncarnationID, coordinate.LastValueAckOrdinal = write.AttemptID, historical, 1
	coordinate.LastValueDigest, err = contract.PublicationSelectedValueDigest(domain, write.Projection.ValueBasisDigest, birth.AttemptID, coordinate.OwnedInstanceDigest)
	if err != nil {
		t.Fatal(err)
	}
	coordinate.LastPolicyAckAttemptID, coordinate.LastPolicyAckIncarnationID, coordinate.LastPolicyAckOrdinal, coordinate.LastPolicyDigest = write.AttemptID, historical, 1, write.Projection.PolicyDigest
	coordinate.LastDeleteAckAttemptID, coordinate.LastDeleteAckIncarnationID, coordinate.LastDeleteAckOrdinal = deletion.AttemptID, historical, 2
	order := []format.PublicationCoordinateOrder{{CoordinateID: coordinate.CoordinateID, Incarnations: []contract.ID{birth.PublicationIncarnationID, historical, current}}}
	rows := func(t *testing.T, c contract.PublicationCoordinate, w contract.PublicationMarker) []contract.SupportRecord {
		t.Helper()
		out := publicationRelationRows(t, c, birth)
		for _, marker := range []contract.PublicationMarker{w, deletion} {
			body, err := contract.EncodePublicationMarker(marker)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, contract.SupportRecord{Kind: contract.PublicationMarkerSupportKind, RecordID: marker.AttemptID, Body: body})
		}
		return out
	}
	selected, err := publicationRowsRelation(domain, rows(t, coordinate, write), order)
	if err != nil || !selected.coordinates[coordinate.CoordinateID].Equal(coordinate) || !reflect.DeepEqual(selected.markers[write.AttemptID], write) {
		t.Fatal("exact historical ACKs or ordered births refused", err)
	}
	for name, change := range map[string]func(*contract.PublicationCoordinate){
		"value incarnation":  func(c *contract.PublicationCoordinate) { c.LastValueAckIncarnationID = current },
		"value ordinal":      func(c *contract.PublicationCoordinate) { c.LastValueAckOrdinal = 2 },
		"policy incarnation": func(c *contract.PublicationCoordinate) { c.LastPolicyAckIncarnationID = current },
		"policy ordinal":     func(c *contract.PublicationCoordinate) { c.LastPolicyAckOrdinal = 2 },
		"delete incarnation": func(c *contract.PublicationCoordinate) { c.LastDeleteAckIncarnationID = current },
		"delete ordinal":     func(c *contract.PublicationCoordinate) { c.LastDeleteAckOrdinal = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := coordinate
			change(&changed)
			if _, err := publicationRowsRelation(domain, rows(t, changed, write), order); err == nil {
				t.Fatal("ACK accepted another exact incarnation/ordinal")
			}
		})
	}
	t.Run("birth after action", func(t *testing.T) {
		reordered := []format.PublicationCoordinateOrder{{CoordinateID: coordinate.CoordinateID, Incarnations: []contract.ID{historical, birth.PublicationIncarnationID, current}}}
		if _, err := publicationRowsRelation(domain, rows(t, coordinate, write), reordered); err == nil {
			t.Fatal("owned action accepted before its retained birth")
		}
	})
	t.Run("duplicate stamp", func(t *testing.T) {
		duplicate := write
		duplicate.AdmissionOrdinal = deletion.AdmissionOrdinal
		if _, err := publicationRowsRelation(domain, rows(t, coordinate, duplicate), order); err == nil {
			t.Fatal("distinct attempts shared one admission stamp")
		}
	})
	t.Run("unknown incarnation", func(t *testing.T) {
		unknown := write
		unknown.PublicationIncarnationID = publicationRelationID(99)
		if _, err := publicationRowsRelation(domain, rows(t, coordinate, unknown), order); err == nil {
			t.Fatal("marker acquired an unselected incarnation")
		}
	})
}

// full_only: false
func TestSelectedPublicationZeroLatestCacheRequiresExactCreateProof(t *testing.T) {
	for _, state := range []uint8{contract.PublicationMayHaveEntered, contract.PublicationUnknown} {
		t.Run(map[uint8]string{contract.PublicationMayHaveEntered: "permitted", contract.PublicationUnknown: "unknown"}[state], func(t *testing.T) {
			domain, coordinate, marker, _ := publicationRelationFixture(t)
			coordinate.LatestUnresolvedAttemptID = contract.ID{}
			marker.State = state
			rows := publicationRelationRows(t, coordinate, marker)
			selected, err := publicationFixtureRowsRelation(domain, rows)
			if err != nil || !selected.coordinates[coordinate.CoordinateID].Equal(coordinate) {
				t.Fatalf("exact retained create proof refused with zero cache: %+v %v", selected, err)
			}
			image := publicationSelectedImageFromRows(t, domain, rows)
			for _, group := range image.adminIndex.Groups {
				if group.GroupID == marker.AttemptID && group.UncertainCreateProof != 1 {
					t.Fatal("exact open create lacks mandatory qualification metadata")
				}
			}
			if complete, err := selectedPublicationRelation(&image); err != nil || !complete.coordinates[coordinate.CoordinateID].Equal(coordinate) {
				t.Fatalf("indexed zero-cache exact proof refused: %+v %v", complete, err)
			}
		})
	}
	for _, condition := range []string{"missing", "wrong-binding", "wrong-entry", "wrong-target", "acknowledged", "qualified-no-effect"} {
		t.Run(condition, func(t *testing.T) {
			domain, coordinate, marker, _ := publicationRelationFixture(t)
			coordinate.LatestUnresolvedAttemptID = contract.ID{}
			switch condition {
			case "wrong-binding":
				marker.Projection.BindingIncarnationID = publicationRelationID(90)
			case "wrong-entry":
				marker.Projection.EntryIncarnationID = publicationRelationID(91)
			case "wrong-target":
				marker.Projection.TargetRowDigest = publicationRelationID(92)
			case "acknowledged":
				marker.State = contract.PublicationAcknowledged
				marker.Evidence.Class = contract.PublicationRequestAcknowledged
				marker.Evidence.NormalizedStatus = 201
				marker.Evidence.SafeResourceID = "exact-resource"
				marker.Evidence.ConsumerLocator = "locator"
			case "qualified-no-effect":
				marker.State = contract.PublicationQualifiedNoEffectState
				marker.Evidence.Class = contract.PublicationQualifiedNoEffect
			}
			var err error
			marker.ProjectionCommitment, err = contract.PublicationProjectionCommitment(marker.Projection)
			if err != nil {
				t.Fatal(err)
			}
			rows := publicationRelationRows(t, coordinate, marker)
			if condition == "missing" {
				rows = rows[:1]
			}
			// A cleared cache conveys no proof. Only an open create at this exact
			// binding, entry and target can retain uncertain ownership.
			if _, err := publicationFixtureRowsRelation(domain, rows); err == nil {
				t.Fatal("zero cache accepted absent or unrelated uncertain-create proof")
			}
		})
	}
}

// full_only: false
func TestPublicationDispositionRequiresMandatoryUncertainProofWithUnreadableMarker(t *testing.T) {
	for _, condition := range []string{"exact-proof", "missing-proof", "proof-on-nonuncertain-coordinate"} {
		t.Run(condition, func(t *testing.T) {
			state := publicationCapacityState(t)
			coordinatePosition := slices.IndexFunc(state.support, func(page format.RequiredSupportPageView) bool {
				return len(page.Records) == 1 && page.Records[0].Kind == contract.PublicationCoordinateSupportKind
			})
			if coordinatePosition < 0 {
				t.Fatal("fixture has no separate mandatory coordinate page")
			}
			coordinate, err := contract.InspectPublicationCoordinate(state.support[coordinatePosition].Records[0].Body)
			if err != nil {
				t.Fatal("selected coordinate", err)
			}
			coordinate.LatestUnresolvedAttemptID = contract.ID{}
			if condition == "proof-on-nonuncertain-coordinate" {
				coordinate.OwnerState = contract.PublicationOwnerNone
			}
			body, err := contract.EncodePublicationCoordinate(coordinate)
			if err != nil {
				t.Fatal("zero-cache selected coordinate", err)
			}
			state.support[coordinatePosition].Records[0].Body = body
			generatedRefreshSupport(t, state)
			generatedInstallFixtureSupportReader(t, state)
			markerPosition := slices.IndexFunc(state.support, func(page format.RequiredSupportPageView) bool {
				return len(page.Records) == 1 && page.Records[0].Kind == contract.PublicationMarkerSupportKind
			})
			if markerPosition < 0 || markerPosition == coordinatePosition {
				t.Fatal("fixture has no separate optional matching marker page")
			}
			markerID := state.support[markerPosition].Records[0].RecordID
			position := slices.IndexFunc(state.adminIndex.Groups, func(group format.AdministrativeGroup) bool {
				return group.GroupID == markerID
			})
			wantProof := uint8(1)
			if coordinate.OwnerState == contract.PublicationOwnerNone {
				wantProof = 0
			}
			if position < 0 || state.adminIndex.Groups[position].UncertainCreateProof != wantProof ||
				!state.adminIndex.Valid() || !state.adminIndex.Pages[coordinatePosition].Spans[0].Mandatory ||
				state.adminIndex.Pages[markerPosition].ReadRequired || state.adminIndex.Pages[markerPosition].Spans[0].Mandatory {
				t.Fatal("fixture lost correct proof facts or mandatory/optional page classification")
			}
			got, err := state.publicationCoordinatesForDisposition()
			if err != nil || len(got) != 1 || !got[coordinate.CoordinateID].Equal(coordinate) {
				t.Fatal("complete positive fixture refused before mutation", got, err)
			}
			// An unavailable whole optional page keeps its authenticated Ref,
			// span and row summary, with no loaded body or row facts.
			state.support[markerPosition].Records = nil
			state.supportFacts[markerPosition].rows, state.supportFacts[markerPosition].ordinals = nil, nil
			_, loaded, err := state.publicationLoadedRowsForDisposition()
			if err != nil || len(loaded) != 1 {
				t.Fatal("partial fixture lost its selected coordinate", err)
			}
			if _, present := loaded[generatedRecordKey{kind: contract.PublicationMarkerSupportKind, id: markerID}]; present {
				t.Fatal("partial fixture still loads the optional marker body")
			}
			got, err = state.publicationCoordinatesForDisposition()
			if err != nil || len(got) != 1 || !got[coordinate.CoordinateID].Equal(coordinate) {
				t.Fatal("partial positive fixture refused before mutation", got, err)
			}
			switch condition {
			case "missing-proof":
				state.adminIndex.Groups[position].UncertainCreateProof = 0
			case "proof-on-nonuncertain-coordinate":
				state.adminIndex.Groups[position].UncertainCreateProof = 1
			}
			got, err = state.publicationCoordinatesForDisposition()
			if condition == "exact-proof" {
				if err != nil || len(got) != 1 || !got[coordinate.CoordinateID].Equal(coordinate) {
					t.Fatal("authenticated exact proof or zero-cache ownership was lost", got, err)
				}
			} else if err == nil {
				t.Fatal("partial disposition accepted inconsistent mandatory proof provenance", condition)
			}
		})
	}
}

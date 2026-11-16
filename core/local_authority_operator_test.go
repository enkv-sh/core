package core

import (
	"bytes"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func administrativeHistoryFixture(t *testing.T) *StateSession {
	t.Helper()
	s, ordinary, _ := receiptStateFixture(t)
	windows := contract.MutationReceiptWindows{DomainID: s.root.Domain, Successes: []contract.CompactMutationReceipt{ordinary}, Order: []contract.ID{ordinary.OperationID}}
	for i := byte(0); i < 3; i++ {
		row := ordinary
		row.OperationID = contract.ID{60 + i}
		row.OperationKind, row.StateResult = contract.OperationEndSelectedWork, contract.ReceiptStateWorkEnded
		row.AdministrativeGroupID, row.AdministrativeTargetID = contract.ID{70 + i}, contract.ID{80}
		row.AdministrativeTargetKind = contract.AdministrativeGeneratedDuty
		row.AdministrativeDisposition, row.AdministrativeOriginalEvidence = contract.ID{81}, contract.AdministrativeEvidenceMissing
		row.WarningBits = uint64(1 + i%2)
		row.ChangedSubjects = contract.GeneratorDescriptor{Digest: contract.ID{82}, Length: 42, Count: 1}
		if i == 2 {
			row.AdministrativeTargetKind = contract.AdministrativeGeneratedParent
			row.AdministrativeTargetID = row.AdministrativeGroupID
		}
		windows.Successes = append(windows.Successes, row)
		windows.Order = append(windows.Order, row.OperationID)
	}
	indexes, err := windows.Indexes()
	if err != nil {
		t.Fatal(err)
	}
	s.root.Generated.SuccessWindow, s.root.Generated.FailureWindow, s.root.Generated.ReceiptOrder, err = indexes.Descriptors()
	if err != nil {
		t.Fatal(err)
	}
	indexID, err := contract.MutationReceiptIndexBlobID(s.root.Domain, s.root.Generated.SuccessWindow, s.root.Generated.FailureWindow, s.root.Generated.ReceiptOrder)
	if err != nil {
		t.Fatal(err)
	}
	indexBody, err := contract.EncodeMutationReceiptIndexes(indexes)
	if err != nil {
		t.Fatal(err)
	}
	fragmentBody, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: 1, BlobID: indexID,
		Count: 1, TotalLength: uint64(len(indexBody)), WholeDigest: contract.Hash(indexBody), Payload: indexBody})
	if err != nil {
		t.Fatal(err)
	}
	fragmentID, err := contract.GeneratorFragmentID(indexID, 0)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := windows.SupportRecords()
	if err != nil {
		t.Fatal(err)
	}
	s.root.Generated.Fragments = []format.FragmentLocation{{BlobID: indexID, SupportPageIndex: 1}}
	s.support, s.root.RequiredSupport, s.adminIndex.Pages = nil, nil, nil
	for i, records := range [][]contract.SupportRecord{rows, {{Kind: contract.GeneratedFragmentSupportKind, RecordID: fragmentID, Body: fragmentBody}}} {
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: s.root.Domain,
			Object: contract.ID{100 + byte(i)}, Index: uint16(i), Records: records})
		if err != nil {
			t.Fatal(err)
		}
		view, err := format.InspectRequiredSupportPage(body)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, s.root.Domain, view.Object, view.Index, body)
		if err != nil {
			t.Fatal(err)
		}
		s.support = append(s.support, view)
		s.root.RequiredSupport = append(s.root.RequiredSupport, ref)
		page := format.AdministrativePage{Ref: ref, Spans: []format.AdministrativeSpan{{Count: uint16(len(records)), Mandatory: true}}}
		for _, record := range records {
			page.Rows = append(page.Rows, format.AdministrativeRowSummary{Kind: record.Kind, RecordID: record.RecordID, BodyLength: uint32(len(record.Body))})
		}
		s.adminIndex.Pages = append(s.adminIndex.Pages, page)
	}
	descriptor := contract.GeneratorDescriptor{Digest: contract.ID{101}, Length: 4}
	for i := byte(0); i < 3; i++ {
		group := format.AdministrativeGroup{GroupID: contract.ID{90 + i}, OwnerID: contract.ID{90 + i}, TargetID: contract.ID{80},
			OwnerKind: format.AdministrativeGeneratedDuty, DutyKind: contract.GeneratedDutyCreate,
			SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing, Affected: descriptor, Dependencies: descriptor, Disposable: descriptor}
		switch i {
		case 0:
			group.OwnerKind, group.DutyKind, group.TargetID = format.AdministrativeGeneratedParent, 0, group.GroupID
		case 1:
			group.RelatedGroupIndexes = []uint16{0}
		}
		s.adminIndex.Groups = append(s.adminIndex.Groups, group)
	}
	ref := format.Ref{Kind: contract.RequiredSupportKind, Format: format.Version, Domain: s.root.Domain,
		Object: contract.ID{102}, Index: 2, Length: 1024, Digest: contract.ID{103}}
	page := format.AdministrativePage{Ref: ref}
	for i := uint16(0); i < 3; i++ {
		kind := uint8(contract.GeneratedDutySupportKind)
		if i == 0 {
			kind = contract.GeneratedParentSupportKind
		}
		page.Spans = append(page.Spans, format.AdministrativeSpan{First: i, Count: 1, GroupIndexes: []uint16{i}})
		page.Rows = append(page.Rows, format.AdministrativeRowSummary{Kind: kind, RecordID: s.adminIndex.Groups[i].GroupID, BodyLength: 87})
	}
	s.adminIndex.Pages = append(s.adminIndex.Pages, page)
	s.root.RequiredSupport = append(s.root.RequiredSupport, ref)
	s.support = append(s.support, format.RequiredSupportPageView{Domain: s.root.Domain, Object: ref.Object, Index: ref.Index})
	s.root.Generated.ActiveOwner, s.root.WarningBits = s.adminIndex.Groups[0].GroupID, 4
	s.head.Core.Revision = contract.ID{110}
	if !s.adminIndex.Valid() {
		t.Fatal("administrative history fixture index")
	}
	return s
}

// full_only: false
func TestAdministrativeInspectionReportsExactTargetsAndRetainedAbandonments(t *testing.T) {
	s := administrativeHistoryFixture(t)
	session := &AuthoritySession{state: s, mode: LocalAuthorityInspect}
	view, result := session.Inspect(t.Context())
	if result.Outcome != ObservedCurrent || len(view.Groups) != 3 || len(view.Abandonments) != 3 || view.WarningBits != 4 {
		t.Fatal("incomplete administrative image", result, len(view.Groups), len(view.Abandonments))
	}
	parent, child, isolated := view.Groups[0], view.Groups[1], view.Groups[2]
	if !parent.Selectable || parent.OriginalOperation == nil || parent.OriginalOperation.OperationID != parent.GroupID ||
		child.Selectable || child.RequiredParentGroupID != parent.GroupID || !reflect.DeepEqual(child.RelatedGroupIndexes, []uint16{0}) || view.Groups[child.RelatedGroupIndexes[0]].GroupID != parent.GroupID ||
		!isolated.Selectable || !isolated.RequiredParentGroupID.IsZero() || isolated.TargetID != child.TargetID || isolated.GroupID == child.GroupID ||
		child.OriginalOperation != nil || isolated.OriginalOperation != nil {
		t.Fatal("target, parent eligibility or typed original operation changed")
	}
	for i, row := range view.Abandonments {
		if row.Receipt.OperationID != (contract.ID{60 + byte(i)}) || row.Receipt.AdministrativeGroupID != (contract.ID{70 + byte(i)}) ||
			row.Receipt.WarningBits != uint64(1+byte(i)%2) {
			t.Fatal("retained target correlation or historical warnings changed", i)
		}
		encoded, err := contract.EncodeCompactMutationReceipt(row.Receipt)
		if err != nil || !bytes.Equal(encoded, row.ReceiptBytes) {
			t.Fatal("history did not return exact canonical retained bytes", err)
		}
		if i < 2 && row.OriginalOperation != nil || i == 2 && (row.OriginalOperation == nil || row.OriginalOperation.OperationID != row.Receipt.AdministrativeGroupID) {
			t.Fatal("history guessed or lost a typed original operation", i)
		}
	}
	if view.Abandonments[0].Receipt.AdministrativeTargetID != view.Abandonments[1].Receipt.AdministrativeTargetID ||
		view.Abandonments[0].Receipt.AdministrativeGroupID == view.Abandonments[1].Receipt.AdministrativeGroupID {
		t.Fatal("same resource duties lost distinct retained GroupIDs")
	}
	view.Groups[1].RelatedGroupIndexes[0] = 2
	view.Groups[0].OriginalOperation.OperationID[0] ^= 1
	view.Abandonments[0].ReceiptBytes[0] ^= 1
	view.Abandonments[0].Receipt.AdministrativeGroupID[0] ^= 1
	view.Abandonments[2].OriginalOperation.OperationID[0] ^= 1
	again, result := session.Inspect(t.Context())
	want, wantResult := (&AuthoritySession{state: administrativeHistoryFixture(t), mode: LocalAuthorityInspect}).Inspect(t.Context())
	if result.Outcome != ObservedCurrent || wantResult.Outcome != ObservedCurrent || !reflect.DeepEqual(again, want) {
		t.Fatal("caller edits changed authenticated state or another read")
	}
	s.root.WarningBits = 5
	if again.WarningBits != 4 || again.Abandonments[0].Receipt.WarningBits != 1 {
		t.Fatal("later state changed a returned image")
	}
}

// full_only: false
func TestAdministrativeInspectionRefusesIncompleteMandatoryHistory(t *testing.T) {
	for name, damage := range map[string]func(*StateSession){
		"missing receipt": func(s *StateSession) { s.support[0].Records = s.support[0].Records[1:] },
		"missing index":   func(s *StateSession) { s.support[1].Records = nil },
		"damaged index": func(s *StateSession) {
			s.support[1].Records[0].Body = bytes.Clone(s.support[1].Records[0].Body)
			s.support[1].Records[0].Body[len(s.support[1].Records[0].Body)-1] ^= 1
		},
		"optional receipt": func(s *StateSession) {
			s.adminIndex.Pages[0].Spans[0].Mandatory = false
			s.adminIndex.Pages[0].Spans[0].GroupIndexes = []uint16{0}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := administrativeHistoryFixture(t)
			damage(s)
			view, result := (&AuthoritySession{state: s, mode: LocalAuthorityInspect}).Inspect(t.Context())
			if result.Outcome != IntegrityFailure || !reflect.DeepEqual(view, AuthorityInspection{}) {
				t.Fatal("partial administrative view escaped mandatory damage", result)
			}
		})
	}
}

// full_only: false
func TestAdministrativeInspectionDoesNotInferOriginalOperationFromUntypedIDs(t *testing.T) {
	s := administrativeHistoryFixture(t)
	s.adminIndex.Groups[0].OwnerID = contract.ID{104}
	s.adminIndex.Pages[2].Rows[0].Kind = contract.GeneratedDutySupportKind
	rows := s.support[0].Records
	parent, err := contract.InspectCompactMutationReceipt(rows[3].Body)
	if err != nil {
		t.Fatal(err)
	}
	parent.AdministrativeTargetID = contract.ID{105}
	rows[3].Body, err = contract.EncodeCompactMutationReceipt(parent)
	if err != nil {
		t.Fatal(err)
	}
	view, result := (&AuthoritySession{state: s, mode: LocalAuthorityInspect}).Inspect(t.Context())
	if result.Outcome != ObservedCurrent || view.Groups[0].OriginalOperation != nil || view.Abandonments[2].OriginalOperation != nil {
		t.Fatal("unproved identity became an original operation", result)
	}
}

// full_only: false
func TestAdministrativeInspectionKeepsPublicationTargetRestrictions(t *testing.T) {
	for _, qualified := range []bool{false, true} {
		name := "active-coordinate"
		if qualified {
			name = "qualified-birth"
		}
		t.Run(name, func(t *testing.T) {
			domain, coordinate, marker, _ := publicationRelationFixture(t)
			if qualified {
				marker.State, marker.Evidence.Class, marker.Evidence.NormalizedStatus = contract.PublicationAcknowledged, contract.PublicationRequestAcknowledged, 201
				marker.Evidence.SafeResourceID = "exact-resource"
				marker.Evidence.ConsumerLocator = "locator"
				coordinate.OwnerState, coordinate.LatestUnresolvedAttemptID, coordinate.OwnedBirthAttemptID = contract.PublicationOwnerQualified, contract.ID{}, marker.AttemptID
				var err error
				coordinate.OwnedInstanceDigest, err = contract.PublicationOwnedInstanceDigest(domain, coordinate.CoordinateID,
					marker.Projection.BindingIncarnationID, marker.Projection.EntryIncarnationID, marker.Projection.TargetRowDigest,
					marker.AttemptID, marker.Evidence.SafeResourceID)
				if err != nil {
					t.Fatal(err)
				}
			}
			image := publicationSelectedImageFromRows(t, domain, publicationRelationRows(t, coordinate, marker))
			image.root.Generated = format.EmptyGeneratedClosure()
			state := &StateSession{admission: openAdmission{domain: domain}, root: image.root, support: image.support, adminIndex: image.adminIndex}
			view, result := (&AuthoritySession{state: state, mode: LocalAuthorityInspect}).Inspect(t.Context())
			if result.Outcome != ObservedCurrent || len(view.Groups) != 2 {
				t.Fatal("publication target listing refused", result)
			}
			for _, group := range view.Groups {
				if group.GroupID == coordinate.CoordinateID && group.Selectable || qualified && group.GroupID == marker.AttemptID && group.Selectable {
					t.Fatal("listing admitted protected publication target", group.GroupID)
				}
				if !qualified && group.GroupID == marker.AttemptID && !group.Selectable {
					t.Fatal("listing blocked the disposable unknown marker")
				}
			}
		})
	}
}

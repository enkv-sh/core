package core

import (
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestInspectionMetadataScopesAndOwnsEntries(t *testing.T) {
	recipient, other := publicationRelationID(2), publicationRelationID(3)
	image := selectedImage{}
	image.root.Domain, image.root.Snapshot = publicationRelationID(1), publicationRelationID(4)
	image.root.Names = []format.NameEntry{{Name: "", Slot: 0}, {Name: "hidden", Slot: 1}}
	image.root.RecipientCount = 2
	image.pages[0] = &format.ValueEntryPage{}
	image.pages[0].Slots[0] = &contract.ValueEntry{Name: "", Incarnation: publicationRelationID(5), ValueState: publicationRelationID(6), ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, ValueBytes: []byte("hello"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 5, RetainedLength: 5, Recipients: []contract.ID{recipient}}
	image.pages[0].Slots[1] = &contract.ValueEntry{Name: "hidden", Incarnation: publicationRelationID(7), ValueState: publicationRelationID(8), ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, ValueBytes: []byte("private"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 7, RetainedLength: 7, Recipients: []contract.ID{other}}
	image.recipients[0] = &format.RecipientPage{}
	image.recipients[0].Slots[0] = &contract.RecipientRecord{RecipientID: recipient, Status: contract.CurrentRecipient, DisplayName: "first", CurrentBinding: &contract.KMSBinding{BindingID: publicationRelationID(9), BindingSerial: 1, Fingerprint: publicationRelationID(10)}}
	image.recipients[0].Slots[1] = &contract.RecipientRecord{RecipientID: other, Status: contract.CurrentRecipient, DisplayName: "second", CurrentBinding: &contract.KMSBinding{BindingID: publicationRelationID(11), BindingSerial: 1, Fingerprint: publicationRelationID(12)}}
	selected := publicSelection{image: image, complete: true}
	entries, recipients, err := projectInspectionMetadata(t.Context(), &selected)
	if err != nil || len(entries) != 2 || entries[0].Name != "" || entries[0].RawLength != 5 || !reflect.DeepEqual(entries[1].RecipientIDs, []contract.ID{other}) || len(recipients) != 2 || recipients[0].BindingFingerprint != publicationRelationID(10) {
		t.Fatal("complete metadata changed", err, entries, recipients)
	}
	scoped, err := projectRecipientInspection(t.Context(), &selected, recipient)
	if err != nil || !reflect.DeepEqual(scoped.Entries, []RecipientInspectionEntry{{Name: "", IncarnationID: publicationRelationID(5), ValueStateID: publicationRelationID(6), ValueSource: contract.Supplied, RawLength: 5}}) || cap(scoped.Entries) != len(scoped.Entries) {
		t.Fatal("scope returned ungranted fields or count", err, scoped)
	}
	scoped.Observation = PublicObservation{DomainID: publicationRelationID(1), HeadRevisionID: publicationRelationID(13), SnapshotID: publicationRelationID(4), RootDigest: publicationRelationID(14)}
	if err := scoped.Validate(); err != nil {
		t.Fatal("valid empty entry name refused", err)
	}
	entries[0].RecipientIDs[0] = other
	again, _, err := projectInspectionMetadata(t.Context(), &selected)
	if err != nil || again[0].RecipientIDs[0] != recipient {
		t.Fatal("result changed selected membership backing", err)
	}
	selected.image.recipients[0].Slots[0].Status = contract.RetiredRecipient
	if _, err := projectRecipientInspection(t.Context(), &selected, recipient); err == nil {
		t.Fatal("retired recipient retained metadata grant")
	}
}

// full_only: false
func TestInspectionAdministrativeRelationsPreserveCompactIndexes(t *testing.T) {
	state := publicationCapacityState(t)
	facts, err := selectedPublicationRelation(state.selectedImage())
	if err != nil {
		t.Fatal(err)
	}
	view, err := projectInspectionWork(state.root, state.adminIndex, facts.coordinates)
	if err != nil || len(view.Groups) != len(state.adminIndex.Groups) || !reflect.DeepEqual(view.Pages, state.adminIndex.Pages) || !reflect.DeepEqual(view.PublicationOrder, state.adminIndex.PublicationOrder) {
		t.Fatal("work relation changed", err)
	}
	for i, row := range view.Groups {
		if !reflect.DeepEqual(row, state.adminIndex.Groups[i]) || view.GroupSelections[i].Selectable != administrativeTargetSelectable(state.root, state.adminIndex, row, facts.coordinates) {
			t.Fatal("work group lost owner fields")
		}
	}
	for i := range view.Pages {
		if len(view.Pages[i].Spans) != 0 && len(view.Pages[i].Spans[0].GroupIndexes) != 0 {
			before := state.adminIndex.Pages[i].Spans[0].GroupIndexes[0]
			view.Pages[i].Spans[0].GroupIndexes[0] ^= 1
			if state.adminIndex.Pages[i].Spans[0].GroupIndexes[0] != before {
				t.Fatal("returned work relation borrows selected index")
			}
			return
		}
	}
	t.Fatal("fixture did not contain a compact page relation")
}

package core

import (
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestAdministrativeDispositionKeepsMandatoryAndCommitsRemovedRows(t *testing.T) {
	s := generatedReservationState(t)
	var dutyID contract.ID
	for _, group := range s.adminIndex.Groups {
		if group.DutyKind != 0 {
			dutyID = group.GroupID
		}
	}
	if dutyID.IsZero() {
		t.Fatal("fixture has no selected duty")
	}
	if _, err := s.administrativeWorkDisposition(dutyID); err == nil {
		t.Fatal("active child was independently disposable")
	}
	after, _, err := s.administrativeWorkClosure(s.root.Generated.ActiveOwner)
	if err != nil {
		t.Fatal(err)
	}
	after, err = s.administrativeWorkWithoutOldReceipts(after)
	if err != nil {
		t.Fatal(err)
	}
	removed, err := s.removedAdministrativeSupport(after)
	if err != nil || !removed.Valid() || removed.Count == 0 {
		t.Fatalf("removed rows have no commitment: %+v %v", removed, err)
	}
	for _, page := range after.Pages {
		view, err := s.administrativeSelectedSupportPage(page)
		if err != nil || len(view.Records) == 0 {
			t.Fatalf("retained selected page unreadable: %+v %v", page.Ref, err)
		}
	}
}

package core

import (
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestCapacityInspectionReportsActualEncodedUsageAndReservationBasis(t *testing.T) {
	s, store, basis := gcInstalledFixture(t)
	lists, closes := 0, 0
	reader, err := NewInstalledCapacityReader(gcInstalledInput(s, store, basis, contract.ListPageResult{Status: contract.ListPageOK}, &lists, &closes))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	ctx := gcReadContext(t)
	got := reader.InspectCapacity(ctx, CapacityInspectionRequest{RequestNonce: gcTestID("capacity-exact-measurement")})
	if got.StateResult != PublicQuerySuccess || got.View == nil || got.Validate() != nil {
		t.Fatal("authentic capacity observation refused", got.Result, got.FailureReason)
	}
	wantCounts := map[string]uint64{"current-value-entries": 0, "current-generated-value-entries": 0, "current-raw-value-bytes": 0, "current-recipients": 1, "current-memberships": 0, "selected-child-pages": 4, "retained-success-receipts": 1, "retained-failure-receipts": 0, "common-receipt-order": 1, "administrative-groups-format": 0}
	if len(got.View.Counts) != len(wantCounts) {
		t.Fatal("capacity count vector incomplete")
	}
	for _, row := range got.View.Counts {
		want, present := wantCounts[row.Name]
		if !present || row.Used != want || row.Margin != row.Limit-want {
			t.Fatal("capacity count or margin differs", row)
		}
	}
	var childBytes uint64
	for _, ref := range s.root.Recipients {
		if ref != nil {
			key := gcObjectTestKey(t, store.descriptor, s.root.Domain, gcPageIdentity(*ref))
			childBytes += uint64(len(store.objects[key]))
		}
	}
	for _, ref := range s.root.RequiredSupport {
		key := gcObjectTestKey(t, store.descriptor, s.root.Domain, gcPageIdentity(ref))
		childBytes += uint64(len(store.objects[key]))
	}
	indexKey := gcObjectTestKey(t, store.descriptor, s.root.Domain, gcPageIdentity(s.root.AdministrativeIndex))
	childBytes += uint64(len(store.objects[indexKey]))
	rootKey := gcObjectTestKey(t, store.descriptor, s.root.Domain, gcPageIdentity(s.head.Core.Root))
	if got.View.Encoded.ChildBytes != childBytes || got.View.Encoded.RootBytes != uint64(len(store.objects[rootKey])) || got.View.Encoded.HEADBytes != uint64(len(store.objects[store.descriptor.HeadKey])) || got.View.Encoded.AdministrativeIndexBytes != uint64(len(store.objects[indexKey])) || len(got.View.Encoded.Objects) != 7 {
		t.Fatal("measured physical bytes differ", got.View.Encoded)
	}
	if got.View.Continuation.RootDigest != s.head.Core.Root.Digest || got.View.Continuation.Remaining.Status != "not-applicable" || got.View.Continuation.FirstExit.Status != "not-applicable" || got.View.Continuation.AdministrativeGroupCountQualification == "" || got.View.Continuation.AdministrativeExitQualification == "" {
		t.Fatal("capacity basis or accepted limit omitted", got.View.Continuation)
	}
	if lists != 1 || closes != 1 || got.View.Garbage.ObservationLimit != "one-page-no-snapshot" {
		t.Fatal("observation grew beyond one page", lists, closes)
	}
	changed := got
	view := *got.View
	changed.View = &view
	view.Counts = slices.Clone(got.View.Counts)
	view.Counts[0].Margin++
	if changed.Validate() == nil {
		t.Fatal("inconsistent displayed margin accepted")
	}
}

// full_only: false
func TestCapacityObservationDamageRefusesBeforeEnumeration(t *testing.T) {
	s, store, basis := gcInstalledFixture(t)
	lists, closes := 0, 0
	key := gcObjectTestKey(t, store.descriptor, s.root.Domain, gcPageIdentity(s.root.RequiredSupport[0]))
	delete(store.objects, key)
	reader, err := NewInstalledCapacityReader(gcInstalledInput(s, store, basis, contract.ListPageResult{Status: contract.ListPageOK}, &lists, &closes))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	got := reader.InspectCapacity(gcReadContext(t), CapacityInspectionRequest{RequestNonce: gcTestID("missing-selected-capacity-child")})
	if got.StateResult != PublicQueryUnavailable || got.View != nil || lists != 0 || closes != 1 || got.Validate() != nil {
		t.Fatal("partial selected image disclosed a capacity page", got.Result, got.FailureReason, lists, closes)
	}
}

// full_only: false
func TestCapacityQueryBindsNormalizedPageAndObservation(t *testing.T) {
	store := gcCursorTestStore()
	cursor, err := EncodeGCCursor("next", contract.ID{1}, store)
	if err != nil {
		t.Fatal(err)
	}
	q := PublicQueryBasis{Schema: "QueryRequestIdentity/v1", Operation: InspectCapacityOperation, SemanticOperation: 30, ExpectedDomain: contract.ID{1}, StoreID: store.Identity, CoordinateID: store.Coordinate, NonBodyID: store.NonBody, StoreDescriptorDigest: administrativeStoreDescriptorDigest(store), PublicBasisDigest: contract.ID{6}, SourcePins: installedAdministrativeTestPins(), RequestNonce: contract.ID{7}}
	first, ok := gcQueryDigest(q, "", contract.ID{}, contract.ID{}, contract.ID{})
	if !ok {
		t.Fatal("first query refused")
	}
	next, ok := gcQueryDigest(q, cursor, contract.ID{}, contract.ID{}, contract.ID{})
	if !ok || first == next {
		t.Fatal("query omitted page continuation")
	}
	q.Observation = &PublicObservation{DomainID: contract.ID{1}, HeadRevisionID: contract.ID{8}, SnapshotID: contract.ID{9}, RootDigest: contract.ID{10}}
	observed, ok := gcQueryDigest(q, cursor, contract.ID{}, contract.ID{11}, contract.ID{12})
	if !ok || observed == next {
		t.Fatal("query omitted complete observation")
	}
	changed, ok := gcQueryDigest(q, cursor, contract.ID{}, contract.ID{13}, contract.ID{12})
	if !ok || changed == observed {
		t.Fatal("query omitted physical mark")
	}
	if _, ok := gcQueryDigest(q, cursor, contract.ID{}, contract.ID{}, contract.ID{12}); ok {
		t.Fatal("partial observation commitment accepted")
	}
	if _, ok := gcQueryDigest(q, cursor, contract.ID{14}, contract.ID{11}, contract.ID{12}); ok {
		t.Fatal("capacity query acquired a GC operation selector")
	}
}

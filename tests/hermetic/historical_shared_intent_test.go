package core

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

const sharedIntentHistoricalCaptureSHA256 = "a1bbd6939112ea79c8b3e725ae86381651376e062656cb725433f6e6d0fcdd7a"

// full_only: false
func TestHistoricalSharedIntentRetirementKeepsSignerAndPublicationExit(t *testing.T) {
	body, err := os.ReadFile(sharedIntentHistoricalFixturePath)
	if err != nil {
		t.Fatal("exact historical capture", err)
	}
	want, err := hex.DecodeString(sharedIntentHistoricalCaptureSHA256)
	got := contract.Hash(body)
	if err != nil || len(want) != len(got) || !slices.Equal(want, got[:]) {
		t.Fatal("historical capture has no matching retained digest")
	}
	var capture sharedIntentHistoricalCapture
	if err := json.Unmarshal(body, &capture); err != nil {
		t.Fatal(err)
	}
	input := capture.Checkpoint
	store := &memoryStore{desc: input.Descriptor, configuration: input.Configuration, objects: input.Objects, generation: input.Generation}
	admission := processPublicAdmission(input.Domain, input.Trust, input.Descriptor, input.PublicKey, input.DomainBasis)
	if input.CurrentBasis != nil {
		admission.admission.current, admission.admission.epoch = input.CurrentBasis.owned(), input.Epoch
	}
	if old, result := openAdministrative(t.Context(), admission, store); old != nil || result != refused(AdmissionInvalid) || store.reads != 0 {
		t.Fatal("obsolete historical shared Intent assembly gained current admission", result)
	}
	// This independent current producer reaches all deep checks below. The
	// exact historical bytes above remain only archival refusal evidence.
	capture, selected, env := currentSharedIntentRetirementCapture(t)
	input = capture.Checkpoint
	store = requireAdmittedMemoryStore(t, env.Store)
	fixture := sharedIntentRetirementFixture{env, selected, capture.Current, capture.A, capture.B, capture.DutyA, capture.DutyB, capture.Release, capture.Marker, capture.LocationA, capture.LocationB, input.GeneratedOutputBindings, capture.Evidence, capture.BeforeA}
	assertSharedIntentRetirement(t, fixture, selected, true)
	assertSharedIntentCapturedReceipts(t, selected, input.Receipts)
	priorSupport, priorGenerated, priorIndex, priorShards, priorSliceSnapshot := slices.Clone(selected.root.RequiredSupport), selected.root.Generated, selected.root.AdministrativeIndex, slices.Clone(selected.root.AdministrativeIndexShards), selected.adminIndex.SliceSnapshot
	priorGenerated.Fragments = slices.Clone(priorGenerated.Fragments)
	selected, successor := installedRecoverySignerFromSelected(t, env, selected)
	if complete, result := Open(t.Context(), OpenContext{admission: &selected.admission}, store); complete != nil || result != failure(IntegrityFailure, InvalidRelation) {
		t.Fatal("signer replacement activated complete historical work", result)
	}
	if !slices.Equal(selected.root.RequiredSupport, priorSupport) || !reflect.DeepEqual(selected.root.Generated, priorGenerated) || selected.root.AdministrativeIndex != priorIndex || !slices.Equal(selected.root.AdministrativeIndexShards, priorShards) || selected.adminIndex.SliceSnapshot != priorSliceSnapshot {
		t.Fatal("signer restoration changed preserved work commitments")
	}
	assertSharedIntentRetirement(t, fixture, selected, true)
	assertSharedIntentCapturedReceipts(t, selected, input.Receipts)
	installFreshGeneratedOutputSources(t, selected, input.GeneratedOutputBindings)
	proved, err := selected.publicationExitNeedsNoIntentCompaction(t.Context())
	if err != nil {
		t.Fatal("historical publication shortcut eligibility", err)
	}
	_, ownershipChanged, err := selected.administrativeDispositionPages()
	if err != nil || !ownershipChanged {
		t.Fatal("historical publication closure lost its ownership correction", err)
	}
	old, err := selected.planAdministrativeCurrentIntents(t.Context(), selected.adminIndex)
	if err != nil || !old.changed || len(old.dropBlobs) != 0 {
		t.Fatal("historical predecessor no longer reaches the no-drop shortcut", err)
	}
	closure, _, err := selected.administrativeWorkClosure(capture.Marker)
	if err != nil {
		t.Fatal("actual marker closure", err)
	}
	projected, err := selected.planAdministrativeCurrentIntents(t.Context(), closure)
	if err != nil || !projected.changed || !projected.dropBlobs[capture.LocationA.BlobID] || projected.dropBlobs[capture.LocationB.BlobID] {
		t.Fatal("publication closure did not expose only the A current blob", err)
	}
	_, locations, err := selected.administrativeSelectedSummaries(closure)
	if err != nil || slices.ContainsFunc(locations, func(location contract.GeneratorSliceLocation) bool {
		return location.ContentKind == contract.GeneratorContentIntent && location.ContentID == capture.A.Generated.IntentDigest
	}) || !slices.Contains(locations, capture.LocationB) {
		t.Fatal("publication closure changed surviving B or retained obsolete A carrier", err)
	}
	if proved {
		t.Error("historical changed ownership qualified the predecessor-only publication shortcut")
	}
	selected = endSharedIntentWork(t, selected, capture.Marker, successor)
	assertSharedIntentGroupIDs(t, selected, fixture.groups, fixture.dutyA, fixture.marker)
	assertSharedIntentReleaseEvidence(t, selected, fixture.evidence)
	for _, entry := range capture.Current {
		if got := selected.valueEntry(entrySlot(t, selected, entry.Name)); got == nil || !reflect.DeepEqual(*got, entry) {
			t.Fatal("historical publication exit changed exact current entry", entry.Name)
		}
	}
	for _, id := range []contract.ID{capture.Release, capture.DutyB} {
		if !slices.ContainsFunc(selected.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == id }) {
			t.Fatal("historical publication exit lost independent group", id)
		}
	}
	if _, _, _, found := sharedIntentCarrier(t, selected, capture.A.Generated.IntentDigest); found {
		t.Fatal("historical publication exit kept obsolete A")
	}
	if location, mandatory, owners, found := sharedIntentCarrier(t, selected, capture.B.Generated.IntentDigest); !found || location != capture.LocationB || mandatory || !slices.Equal(owners, []contract.ID{capture.DutyB}) {
		t.Fatal("historical publication exit changed B retirement Intent")
	}
	selected = generatedLifecycleReopen(t, t.Context(), selected, store)
	_ = mustSelectedGeneratedWork(t, selected)
}

func assertSharedIntentCapturedReceipts(t *testing.T, selected *StateSession, want []receiptExpectation) {
	t.Helper()
	windows, err := selected.receiptWindowsFromAdministrativeSupport()
	if err != nil {
		t.Fatal("restored administrative receipt facts", err)
	}
	rows := slices.Concat(windows.Successes, windows.Failures)
	if len(rows) != len(want) {
		t.Fatal("restored administrative receipt count changed")
	}
	for i, row := range rows {
		body, err := contract.EncodeCompactMutationReceipt(row)
		if err != nil || row.OperationID != want[i].OperationID || !bytes.Equal(body, want[i].Body) {
			t.Fatal("restored administrative receipt body changed", i, err)
		}
	}
}

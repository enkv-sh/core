package core

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: true
// Proves actual 256/256 history through public reads, reconstruction and selected exits.
func TestPublicationMarkerExitsPreserveAuthenticFullReceiptWindows(t *testing.T) {
	deadline, finite := t.Deadline()
	if !finite || !time.Now().Before(deadline) || t.Context().Err() != nil {
		t.Fatal("authentic full-window publication requires a live finite deadline")
	}
	ctx, cancel := context.WithDeadline(t.Context(), deadline)
	defer cancel()
	env := memoryScenarioEnvironment(t)
	env.Context = ctx
	store := env.Store.(*memoryStore)
	if err := store.useFileBodies(filepath.Join(t.TempDir(), "bodies")); err != nil {
		t.Fatal("authentic full-window publication file Store", err)
	}
	initial := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	selected := initial.session
	selected.admission = *capacityFixtureAdmission(t, OpenContext{admission: &selected.admission}).admission
	if ctx.Err() != nil || !time.Now().Before(deadline) || selected.admission.expires != deadline || !selected.admission.valid(store) {
		t.Fatal("authentic receipt prefix finite admission is not live before first producer")
	}
	beforeCAS := store.cas
	selected, incoming, originalBodies := actualFullReceiptWindows(t, env, selected)
	if len(incoming.Successes) != 256 || len(incoming.Failures) != 256 || selected.root.WarningBits != 0x19 || store.cas != beforeCAS+1024 {
		t.Fatal("authentic receipt prefix did not reach both complete windows")
	}
	selected = generatedLifecycleReopen(t, ctx, selected, store)
	assertFullReceiptHistoryBytes(t, selected, incoming, originalBodies)
	assertPublicFullReceiptHistory(t, env, selected, incoming, originalBodies, "cold full history")
	assertReconstructedFullReceiptHistory(t, env, selected, incoming, originalBodies)
	assertPublicFullReceiptHistory(t, env, selected, incoming, originalBodies, "after full history reconstruction")
	publicationDisposalWindows(t, selected, incoming)
	t.Logf("authentic full-window prefix complete CAS_delta=%d children=%d store_objects=%d file_bytes=%d file_count=%d", store.cas-beforeCAS, selected.root.ChildCount, len(store.objects), store.fileBodies.used, store.fileBodies.next)

	// Keep only the original result objects and their owned packets. This is
	// not a Store copy; all obsolete immutable page objects remain untouched.
	type originalInbox struct {
		token contract.Token
		body  []byte
	}
	inboxes := make(map[string]originalInbox)
	failureOperations := make(map[contract.ID]bool)
	for _, receipt := range incoming.Failures {
		failureOperations[receipt.OperationID] = true
	}
	probeID := fixtureID(env.Domain, "full-window result key prefix")
	probeKey, err := format.GeneratedResultKey(store.desc.Prefix, env.Domain, probeID)
	if err != nil {
		t.Fatal("authentic full-window inbox key prefix", err)
	}
	resultPrefix := probeKey[:strings.LastIndex(probeKey, "/")+1]
	seenFailures := make(map[contract.ID]bool)
	for key, value := range store.objects {
		if !strings.HasPrefix(key, resultPrefix) {
			continue
		}
		read := readFixtureStoredBody(value, uint32(contract.GeneratedResultRecordMaxLength))
		result, inspectErr := contract.InspectGeneratedResultRecord(read.Body)
		inboxID, identityErr := contract.GeneratorInboxID(env.Domain, result.Core.OperationID, result.Core.AttemptID, result.Core.ResultID)
		wantKey, keyErr := format.GeneratedResultKey(store.desc.Prefix, env.Domain, inboxID)
		if read.Status != contract.ReadOK || inspectErr != nil || identityErr != nil || keyErr != nil || key != wantKey || result.Core.DomainID != env.Domain || !failureOperations[result.Core.OperationID] || seenFailures[result.Core.OperationID] || result.SafeFacts.Disposition != contract.GeneratorDispositionOwnedUnusableCreate || len(result.SafeFacts.Target) == 0 || len(result.SafeFacts.ResourceData) == 0 {
			t.Fatal("authentic prefix original inbox identity or terminal fact", read.Status, inspectErr, identityErr, keyErr)
		}
		seenFailures[result.Core.OperationID] = true
		inboxes[key] = originalInbox{token: value.Token, body: bytes.Clone(read.Body)}
	}
	if len(inboxes) != 256 || len(seenFailures) != 256 {
		t.Fatal("authentic prefix lost original immutable failure packets")
	}
	seed := sessionStateImage(t, selected)
	seedSlot := entrySlot(t, selected, "member-000")
	seedEntry := seed.Pages[seedSlot/format.PageSlots].Slots[seedSlot%format.PageSlots]
	entries := selected.currentEntryInputs()
	for i := 1; i < 3; i++ {
		entries = append(entries, ApplyEntryInput{Name: fmt.Sprintf("member-%03d", i), Recipients: []contract.ID{selected.admission.recipient}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte{byte(i)}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
	}
	parent := admitSuppliedOutputComparison(t, selected, env.Custody, entries, nil)
	comparison, state := selected.compareWithOutput(ctx, entries, nil, parent)
	if comparison == nil || state.Outcome != ObservedCurrent {
		t.Fatal("full-window ordinary Plain expansion comparison", state)
	}
	candidate, state := selected.Prepare(ctx, comparison, admit(t, selected, comparison), env.Trust)
	if candidate == nil || state.Outcome != ObservedCurrent {
		t.Fatal("full-window ordinary Plain expansion preparation", state)
	}
	selected, state = selected.selectCandidate(ctx, candidate)
	if selected == nil || state.Outcome != ObservedCurrent || store.cas != beforeCAS+1025 {
		t.Fatal("full-window ordinary Plain expansion selection", state)
	}
	env.Custody.RetireApply()
	selected = generatedLifecycleReopen(t, ctx, selected, store)
	if !reflect.DeepEqual(selected.currentEntryInputs(), entries) || entrySlot(t, selected, "member-000") != seedSlot || !reflect.DeepEqual(selected.valueEntry(seedSlot), seedEntry) || !reflect.DeepEqual(selected.root.CurrentAccess, seed.Root.CurrentAccess) || !reflect.DeepEqual(selected.root.Recipients, seed.Root.Recipients) || selected.root.OutputConfiguration != seed.Root.OutputConfiguration || selected.root.WarningBits != 0x19 || len(selected.adminIndex.Groups) != 0 || selected.root.AccessRecordCount != 0 {
		t.Fatal("full-window expansion changed the original Plain seed, authority or work")
	}
	publicationDisposalWindows(t, selected, incoming)
	work := mustSelectedGeneratedWork(t, selected)
	if work.parent != nil || work.phase != nil || len(work.attempts) != 0 || len(work.releases) != 0 || len(work.materials) != 0 || len(work.bundles) != 0 || !selected.root.Generated.ActiveOwner.IsZero() || selected.root.Generated.GeneratedCurrent != 0 || selected.root.Generated.Retiring != 0 || selected.root.Generated.Duties != 0 || selected.root.Generated.Hazards != 0 || selected.root.Generated.Results != 0 || selected.root.Generated.Graphs.Count != 0 {
		t.Fatal("full-window expansion retained live generated work")
	}
	for _, location := range work.content.locations {
		if location.ContentKind == contract.GeneratorContentIntent || location.ContentKind == contract.GeneratorContentGraph {
			t.Fatal("full-window expansion retained an old logical Intent or graph")
		}
	}
	prefix := actualPublicationUnknownCoordinates(t, env, selected, 3)
	if !slices.Equal(prefix.windows.Successes, incoming.Successes) || !slices.Equal(prefix.windows.Failures, incoming.Failures) || !slices.Equal(prefix.windows.Order, incoming.Order) || prefix.warning != 0x19 {
		t.Fatal("full-window publication source changed exact incoming receipts or warning")
	}
	t.Logf("authentic full-window publication complete CAS_delta=%d owners=%d children=%d store_objects=%d file_bytes=%d file_count=%d", store.cas-beforeCAS, len(prefix.controlled.owners), prefix.f.session.root.ChildCount, len(store.objects), store.fileBodies.used, store.fileBodies.next)
	exitReceipts := publicationThreeCoordinateExits(t, env, prefix)
	if len(exitReceipts) != 3 {
		t.Fatal("full-window publication did not return three checked new receipts")
	}
	wantFinal := contract.MutationReceiptWindows{DomainID: env.Domain, Successes: append(slices.Clone(incoming.Successes[3:]), exitReceipts...), Failures: slices.Clone(incoming.Failures)}
	for _, id := range incoming.Order {
		if id != incoming.Successes[0].OperationID && id != incoming.Successes[1].OperationID && id != incoming.Successes[2].OperationID {
			wantFinal.Order = append(wantFinal.Order, id)
		}
	}
	for _, receipt := range exitReceipts {
		wantFinal.Order = append(wantFinal.Order, receipt.OperationID)
	}
	selected = prefix.f.session
	final, err := selected.receiptWindows(ctx)
	if err != nil || len(final.Successes) != 256 || len(final.Failures) != 256 || !slices.Equal(final.Successes, wantFinal.Successes) || !slices.Equal(final.Failures, wantFinal.Failures) || !slices.Equal(final.Order, wantFinal.Order) || selected.root.WarningBits != 0x1d || store.cas != beforeCAS+1035 {
		t.Fatal("full-window publication exits changed exact receipt eviction or finite inventory", err)
	}
	publicationDisposalWindows(t, selected, wantFinal)
	for _, receipt := range incoming.Successes[:3] {
		delete(originalBodies, receipt.OperationID)
	}
	for _, receipt := range exitReceipts {
		originalBodies[receipt.OperationID] = actualGeneratedReceipt(t, selected, receipt.OperationID, contract.ReceiptCanonicalSelected)
	}
	assertFullReceiptHistoryBytes(t, selected, wantFinal, originalBodies)
	for i, row := range exitReceipts {
		if row.OperationKind != contract.OperationEndSelectedWork || row.AdministrativeTargetKind != contract.AdministrativePublicationMarker || row.AdministrativeTargetID != prefix.coordinateIDs[i] {
			t.Fatal("full-window publication newest receipt target/order", i)
		}
	}
	for _, receipt := range incoming.Successes[:3] {
		if body, state := selected.MutationReceipt(ctx, receipt.OperationID); body != nil || state != refused(AdmissionInvalid) {
			t.Fatal("full-window publication replayed an evicted old success", state)
		}
	}
	for _, rows := range [][]contract.CompactMutationReceipt{wantFinal.Successes, wantFinal.Failures} {
		for _, want := range rows {
			body, state := selected.MutationReceipt(ctx, want.OperationID)
			actual, inspectErr := contract.InspectCompactMutationReceipt(body)
			if state.Outcome != ObservedCurrent || inspectErr != nil || actual != want {
				t.Fatal("full-window publication changed a retained public receipt", state, inspectErr)
			}
		}
	}
	for key, want := range inboxes {
		value, present := store.objects[key]
		read := readFixtureStoredBody(value, uint32(len(want.body)))
		if !present || value.Token != want.token || read.Status != contract.ReadOK || !bytes.Equal(read.Body, want.body) {
			t.Fatal("full-window publication exit deleted or changed a warned original packet")
		}
	}
	t.Logf("authentic full-window publication exits complete CAS_delta=%d owners=%d children=%d store_objects=%d file_bytes=%d file_count=%d", store.cas-beforeCAS, len(prefix.controlled.owners), selected.root.ChildCount, len(store.objects), store.fileBodies.used, store.fileBodies.next)

	// A real failed Final exercises the opposite eviction direction while its
	// independently retained Hazard and immutable result remain selected.
	operation := fixtureID(env.Domain, "full history opposite-class eviction")
	selected, original := selectPublicationReceiptFailure(t, ctx, env, selected, operation, "full history opposite-class eviction")
	selected = generatedLifecycleReopen(t, ctx, selected, store)
	body := actualGeneratedReceipt(t, selected, operation, contract.ReceiptCanonicalNotSelected)
	failure, err := contract.InspectCompactMutationReceipt(body)
	if err != nil {
		t.Fatal("opposite-class selected failure", err)
	}
	evicted := wantFinal.Failures[0].OperationID
	wantFinal.Failures = append(slices.Clone(wantFinal.Failures[1:]), failure)
	wantFinal.Order = slices.DeleteFunc(slices.Clone(wantFinal.Order), func(id contract.ID) bool { return id == evicted })
	wantFinal.Order = append(wantFinal.Order, operation)
	delete(originalBodies, evicted)
	originalBodies[operation] = bytes.Clone(body)
	work = mustSelectedGeneratedWork(t, selected)
	hazard := original.expected.Template.HazardID
	if selected.root.WarningBits != 0x1d || selected.root.Generated.Hazards != 1 || len(selected.adminIndex.Groups) != len(prefix.coordinateIDs)+1 || !slices.ContainsFunc(selected.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == hazard }) || !bytes.Equal(work.attempts[original.record.AttemptID].result, original.result) {
		t.Fatal("failure eviction removed remaining work, current warnings or original result")
	}
	assertFullReceiptHistoryBytes(t, selected, wantFinal, originalBodies)
	assertReconstructedFullReceiptHistory(t, env, selected, wantFinal, originalBodies)
	assertPublicFullReceiptHistory(t, env, selected, wantFinal, originalBodies, "opposite-class full history eviction")
	reader, _ := installedReceiptFixture(t, installedApplyTestFixture{env: env, basis: selected.admission.publicBasis(), composition: selected.admission.composition, selected: selected})
	defer reader.Close()
	for _, id := range []contract.ID{incoming.Successes[0].OperationID, evicted} {
		missing := reader.Detail(ctx, ReceiptDetailRequest{fixtureID(env.Domain, fmt.Sprintf("evicted detail %x", id)), id})
		if missing.StateResult != PublicQueryUnavailable || missing.Payload != nil || missing.Validate() != nil {
			t.Fatal("evicted detail claimed an unavailable original outcome", missing.StateResult)
		}
	}
}

// full_only: false
func TestPublicationTerminalFailurePreservesCurrentEntriesAndOutput(t *testing.T) {
	deadline, finite := t.Deadline()
	if !finite || !time.Now().Before(deadline) {
		t.Fatal("publication failure preservation requires a live finite deadline")
	}
	ctx, cancel := context.WithDeadline(t.Context(), deadline)
	defer cancel()
	env := memoryScenarioEnvironment(t)
	env.Context = ctx
	initial := newEnvironmentFixture(t, ctx, env, []int{1, 1, 1}, false)
	prefix := actualPublicationUnknownCoordinates(t, env, initial.session, 3)
	publicationThreeCoordinateExits(t, env, prefix)
	before, err := prefix.f.session.receiptWindows(ctx)
	if err != nil || len(before.Successes) != 4 || len(before.Failures) != 0 {
		t.Fatal("publication failure predecessor history", err)
	}
	operation := fixtureID(env.Domain, "small publication failure")
	selected, _ := selectPublicationReceiptFailure(t, ctx, env, prefix.f.session, operation, "small publication failure")
	after, err := selected.receiptWindows(ctx)
	if err != nil || !slices.Equal(after.Successes, before.Successes) || len(after.Failures) != 1 || after.Failures[0].OperationID != operation || !slices.Equal(after.Order, append(slices.Clone(before.Order), operation)) {
		t.Fatal("publication failure did not append exactly its failure and common-order position", err)
	}
}

func selectPublicationReceiptFailure(t *testing.T, ctx context.Context, env fixtureEnvironment, selected *StateSession, operation contract.ID, label string) (*StateSession, generatedAttempt) {
	t.Helper()
	before := sessionStateImage(t, selected)
	configuration, state := selected.currentOutputConfigurationForApply(ctx)
	configurationBody, err := contract.EncodeOutputConfiguration(configuration)
	publication, publicationErr := selectedPublicationRelation(selected.selectedImage())
	if state.Outcome != 0 || err != nil || publicationErr != nil || len(before.Root.Names) != 3 || len(publication.coordinates) != 3 || len(publication.markers) != 0 {
		t.Fatal("publication failure requires three current Plain targets after their marker exits", state, err, publicationErr)
	}
	// The selected fallback also applies to the prospective generated entry.
	// Its passive target is required for a valid whole-set proposal, even
	// though the failed Final must preserve the selected configuration.
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "publication"}}}
	for i, entry := range before.entryInputs() {
		if entry.Name != fmt.Sprintf("member-%03d", i) || entry.ValueSource != contract.Supplied || entry.ConfidentialityClass != contract.Plain {
			t.Fatal("publication failure current Plain declaration differs", i)
		}
		output.bindings[0].targets = append(output.bindings[0].targets, outputConfigurationTarget(entry.Name, fmt.Sprintf("slot-%03d", i)))
	}
	output.bindings[0].targets = append(output.bindings[0].targets, outputConfigurationTarget("receipt-failure", "receipt-failure"))
	installOutputFixtureSource(t, selected, output)
	sources := generatedWriterCurrentDeclarations(t, selected, nil)
	closed, original := selectActualTerminalFailureReceipt(t, ctx, env, selected, operation, label, false, sources...)
	afterConfiguration, state := closed.currentOutputConfigurationForApply(ctx)
	afterBody, err := contract.EncodeOutputConfiguration(afterConfiguration)
	afterPublication, publicationErr := selectedPublicationRelation(closed.selectedImage())
	if state.Outcome != 0 || err != nil || publicationErr != nil || !reflect.DeepEqual(closed.currentEntryInputs(), before.entryInputs()) || !reflect.DeepEqual(closed.root.ValueEntryPages, before.Root.ValueEntryPages) || !reflect.DeepEqual(closed.root.Names, before.Root.Names) || !reflect.DeepEqual(closed.root.Recipients, before.Root.Recipients) || closed.root.OutputConfiguration != before.Root.OutputConfiguration || !bytes.Equal(afterBody, configurationBody) || !reflect.DeepEqual(afterPublication, publication) || !reflect.DeepEqual(closed.adminIndex.PublicationOrder, before.AdministrativeIndex.PublicationOrder) {
		t.Fatal("failed Final changed current Plain state, output configuration or publication rows", state, err, publicationErr)
	}
	if len(closed.adminIndex.Groups) != len(before.AdministrativeIndex.Groups)+1 {
		t.Fatal("failed Final did not retain the publication groups plus one Hazard")
	}
	for _, prior := range before.AdministrativeIndex.Groups {
		index := slices.IndexFunc(closed.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == prior.GroupID })
		if index < 0 || !reflect.DeepEqual(closed.adminIndex.Groups[index], prior) {
			t.Fatal("failed Final changed a retained publication group")
		}
	}
	return closed, original
}

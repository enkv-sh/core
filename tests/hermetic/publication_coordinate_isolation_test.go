package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"maps"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func publicationCoordinatePhysicalRows(t *testing.T, s *StateSession) (format.Ref, []contract.SupportRecord) {
	t.Helper()
	var ref format.Ref
	for _, page := range s.adminIndex.Pages {
		for _, summary := range page.Rows {
			if summary.Kind != contract.PublicationCoordinateSupportKind {
				continue
			}
			if page.ReadRequired || !ref.Object.IsZero() && ref != page.Ref {
				t.Fatal("fixture coordinates do not share one mandatory physical page")
			}
			ref = page.Ref
		}
	}
	body, state := s.readObjectBorrowedUncached(t.Context(), ref)
	if state.Outcome != 0 || format.CheckReference(ref, body) != nil {
		t.Fatal("coordinate physical page read", state)
	}
	view, err := format.InspectRequiredSupportPage(body)
	if err != nil || view.Domain != ref.Domain || view.Object != ref.Object || view.Index != ref.Index {
		t.Fatal("coordinate physical page identity", err)
	}
	rows := make([]contract.SupportRecord, len(view.Records))
	for i, row := range view.Records {
		rows[i] = contract.SupportRecord{Kind: row.Kind, RecordID: row.RecordID, Body: bytes.Clone(row.Body)}
	}
	return ref, rows
}

func publicationCoordinateCopiedRows(t *testing.T, before, after []contract.SupportRecord, want contract.PublicationCoordinate) {
	t.Helper()
	if len(after) != len(before) {
		t.Fatal("coordinate copy changed physical row count")
	}
	matched := 0
	for i, row := range after {
		old := before[i]
		if row.Kind != old.Kind || row.RecordID != old.RecordID || len(row.Body) != len(old.Body) {
			t.Fatal("coordinate copy changed physical row identity/order/length", i)
		}
		if row.Kind == contract.PublicationCoordinateSupportKind && row.RecordID == want.CoordinateID {
			actual, err := contract.InspectPublicationCoordinate(row.Body)
			if err != nil || !reflect.DeepEqual(actual, want) || len(row.Body) != 772 {
				t.Fatal("coordinate copy changed the complete expected coordinate", i, err)
			}
			matched++
		} else if !bytes.Equal(row.Body, old.Body) {
			t.Fatal("coordinate copy changed an unrelated raw peer body", i)
		}
	}
	if matched != 1 {
		t.Fatal("coordinate copy did not replace exactly one expected coordinate")
	}
}

func publicationCoordinateRemovedSupport(t *testing.T, before *StateSession, coordinatePage format.Ref, marker contract.ID) contract.GeneratorDescriptor {
	t.Helper()
	var removed [][]byte
	for _, page := range before.adminIndex.Pages {
		if page.ReadRequired {
			t.Fatal("publication fixture unexpectedly contains generated Slice rows")
		}
		row := 0
		for _, span := range page.Spans {
			for offset := uint16(0); offset < span.Count; offset++ {
				summary := page.Rows[row]
				row++
				if page.Ref != coordinatePage && summary.Kind != contract.MutationReceiptSupportKind && summary.Kind != contract.GeneratedFragmentSupportKind && (summary.Kind != contract.PublicationMarkerSupportKind || summary.RecordID != marker) {
					continue
				}
				item := append([]byte(nil), page.Ref.Digest[:]...)
				item = binary.BigEndian.AppendUint16(item, page.Ref.Index)
				item = binary.BigEndian.AppendUint16(item, span.First+offset)
				item = append(item, summary.Kind)
				item = append(item, summary.RecordID[:]...)
				item = binary.BigEndian.AppendUint32(item, summary.BodyLength)
				removed = append(removed, item)
			}
		}
	}
	return publicationDisposalAdminDescriptor("removed-selected-support", removed)
}

type publicationUnknownCoordinateFixture struct {
	f                        *fixture
	entries                  []ApplyEntryInput
	baseline                 stateImage
	coordinateIDs, markerIDs []contract.ID
	controlled               *publicationControlledPrivate
	beforeSetupCAS           int
	checkCurrent             func()
	windows                  contract.MutationReceiptWindows
	warning                  uint8
}

func actualPublicationUnknownCoordinates(t *testing.T, env fixtureEnvironment, initial *StateSession, count int) publicationUnknownCoordinateFixture {
	t.Helper()
	ctx := t.Context()
	deadline, finite := t.Deadline()
	if !finite || !time.Now().Before(deadline) {
		t.Fatal("coordinate isolation requires a live finite test deadline")
	}
	if count != 3 && count != 264 || initial == nil || initial.store != env.Store || env.Context == nil || env.Context.Err() != nil {
		t.Fatal("coordinate prefix requires one of its two admitted Plain fixture sizes")
	}
	admission := capacityFixtureAdmission(t, OpenContext{admission: &initial.admission})
	initial.admission = *admission.admission
	f := &fixture{store: env.Store.(*memoryStore), trust: env.Trust.(*fixtureTrust), admission: admission, session: initial}
	if count == 264 && f.store.fileBodies == nil {
		t.Fatal("accumulated coordinate prefix requires the caller's file Store")
	}
	beforeSetupCAS := f.store.cas
	windows, err := f.session.receiptWindows(ctx)
	if err != nil || windows.DomainID != env.Domain {
		t.Fatal("coordinate prefix incoming receipt windows", err)
	}
	windows.Successes, windows.Failures = slices.Clone(windows.Successes), slices.Clone(windows.Failures)
	warning := f.session.root.WarningBits
	reservationRisk := uint8(0)
	if warning&(WarningPublicationOrderValue|WarningDiscardedExactEvidence) != 0 {
		reservationRisk = 1
	}
	entries := f.session.currentEntryInputs()
	if len(entries) != count {
		t.Fatal("coordinate prefix current entry count")
	}
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "publication"}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"publication"}}}}
	for i, entry := range entries {
		if entry.Name != fmt.Sprintf("member-%03d", i) || entry.ValueSource != contract.Supplied || entry.ConfidentialityClass != contract.Plain || !bytes.Equal(entry.InputBytes, []byte{byte(i)}) {
			t.Fatal("coordinate isolation initial Plain source", i)
		}
		slot := fmt.Sprintf("slot-%03d", i)
		output.bindings[0].targets = append(output.bindings[0].targets, outputConfigurationTarget(entry.Name, slot))
		initial.admission.publicationNamespaces = append(initial.admission.publicationNamespaces, publicationNamespace{domain: env.Domain, service: "aws", physical: slot, premise: contract.Hash([]byte("independently qualified namespace " + slot))})
	}
	parent := admitSuppliedOutputComparison(t, f.session, env.Custody, entries, output)
	comparison, state := f.session.compareWithOutput(ctx, entries, output, parent)
	if comparison == nil || state.Outcome != ObservedCurrent {
		t.Fatal("coordinate isolation output comparison", state)
	}
	candidate, state := f.session.Prepare(ctx, comparison, admit(t, f.session, comparison), env.Trust)
	if candidate == nil || state.Outcome != ObservedCurrent {
		t.Fatal("coordinate isolation output preparation", state)
	}
	f.session, state = f.session.selectCandidate(ctx, candidate)
	if f.session == nil || state.Outcome != ObservedCurrent || f.store.cas != beforeSetupCAS+1 {
		t.Fatal("coordinate isolation output selection", state)
	}
	env.Custody.RetireApply()
	f.admission = OpenContext{admission: &f.session.admission}
	configured := publicationEngineReopen(t, f)
	configuration, state := f.session.currentOutputConfigurationForApply(ctx)
	if state.Outcome != 0 || len(configuration.Bindings) != 1 || len(configuration.Bindings[0].Targets) != count || len(configured.coordinates) != count || len(configured.markers) != 0 {
		t.Fatal("coordinate isolation configured target set", state)
	}
	baseline := sessionStateImage(t, f.session)
	checkCurrent := func() {
		t.Helper()
		if !reflect.DeepEqual(f.session.currentEntryInputs(), entries) || !reflect.DeepEqual(f.session.pages, baseline.Pages) || !reflect.DeepEqual(f.session.root.ValueEntryPages, baseline.Root.ValueEntryPages) || !reflect.DeepEqual(f.session.root.Names, baseline.Root.Names) || !reflect.DeepEqual(f.session.root.Recipients, baseline.Root.Recipients) || !reflect.DeepEqual(f.session.root.CurrentAccess, baseline.Root.CurrentAccess) || f.session.root.OutputConfiguration != baseline.Root.OutputConfiguration || f.session.root.ValueEntryCount != uint32(count) || f.session.root.RawBytes != uint64(count) || f.session.root.SecretCount != 0 || f.session.root.AccessRecordCount != 0 {
			t.Fatal("coordinate isolation changed exact current state/configuration/access")
		}
	}
	publicationDisposalWindows(t, f.session, windows)
	if f.session.root.WarningBits != warning {
		t.Fatal("coordinate output configuration changed the incoming warning")
	}
	controlled := newPublicationControlledPrivate()
	controlled.evidence = contract.PublicationUnproved
	coordinateIDs, markerIDs := make([]contract.ID, count), make([]contract.ID, count)
	for i, entry := range entries {
		if files := f.store.fileBodies; files != nil {
			t.Logf("publication prefix target=%d/%d children=%d child_bytes=%d CAS_delta=%d creates=%d store_objects=%d file_bytes=%d file_count=%d", i+1, count, f.session.root.ChildCount, f.session.root.ChildEncodedBytes, f.store.cas-beforeSetupCAS, f.store.creates, len(f.store.objects), files.used, files.next)
		}
		slot := fmt.Sprintf("slot-%03d", i)
		preimage := append([]byte("ENKV/PUBLICATION/COORDINATE/v3\x00"), env.Domain[:]...)
		preimage = publicationDisposalBlob(preimage, []byte("aws"))
		coordinateIDs[i] = publicationDisposalHash(publicationDisposalBlob(preimage, []byte(slot)))
		want, present := configured.coordinates[coordinateIDs[i]]
		if !present || want.BindingState != contract.PublicationBindingActive || want.OwnerState != contract.PublicationOwnerNone || want.LateEffectRisk != 0 || want.LastAdmissionOrdinal != 0 || !want.DeletionTargetRowDigest.IsZero() || want.ActiveBindingIncarnationID != configuration.Bindings[0].IncarnationID || want.LastEntryIncarnationID != f.session.valueEntry(entrySlot(t, f.session, entry.Name)).Incarnation {
			t.Fatal("coordinate isolation independently selected target relation", i)
		}
		sendDeadline := time.Now().Add(30 * time.Second)
		if deadline.Before(sendDeadline) {
			sendDeadline = deadline
		}
		input := publicationInput{names: []string{entry.Name}, acting: f.session.admission.recipient, deadline: sendDeadline}
		plan := publicationEnginePlan(t, f, input, controlled)
		if len(plan.targets) != 1 || plan.targets[0].coordinate != coordinateIDs[i] || !slices.Equal(plan.targets[0].actions, []uint8{contract.PublicationCreateWithValue}) {
			t.Fatal("coordinate isolation did not admit one exact create action", i)
		}
		target := plan.targets[0].target
		wantTarget := outputConfigurationTarget(entry.Name, slot).target
		wantTarget.EntryIncarnationID = want.LastEntryIncarnationID
		if !reflect.DeepEqual(target, wantTarget) {
			t.Fatal("coordinate isolation changed the independently supplied target", i)
		}
		targetDigest, err := contract.PublicationTargetRowDigest(env.Domain, "publication", configuration.Bindings[0].IncarnationID, wantTarget)
		prior, priorErr := selectedPublicationRelation(f.session.selectedImage())
		if err != nil || priorErr != nil {
			t.Fatal("coordinate isolation target/predecessor", i)
		}
		want.OwnerState, want.PossibleRemoteObject = contract.PublicationOwnerUncertainCreate, 1
		want.LastAdmissionOrdinal = 1
		want.DeletionDestinationID, want.DeletionConsumerLocator = "publication", target.ConsumerLocator
		want.DeletionTargetContractID, want.DeletionConfigContractID = target.TargetContractID, configuration.Bindings[0].Destination.ConfigContractID
		want.DeletionCredentialRouteContractID, want.DeletionPayloadEncoding = controlled.facts.CredentialRouteContractID, target.PayloadEncoding
		want.DeletionTargetData = bytes.Clone(target.TargetData)
		want.DeletionTargetRowDigest = targetDigest
		beforeCAS := f.store.cas
		var reserved contract.PublicationMarker
		controlled.onSend = func() {
			selected := publicationEngineReopen(t, f)
			for _, marker := range selected.markers {
				if marker.CoordinateID == coordinateIDs[i] {
					reserved = marker
				}
			}
			want.LatestUnresolvedAttemptID = reserved.AttemptID
			if reserved.AttemptID.IsZero() || reserved.State != contract.PublicationMayHaveEntered || reserved.LateEffectRisk != reservationRisk || reserved.Projection.Action != contract.PublicationCreateWithValue || reserved.Projection.EntryIncarnationID != target.EntryIncarnationID || reserved.Projection.TargetRowDigest != want.DeletionTargetRowDigest || reserved.BlockerCount != 0 || !reserved.BlockerDigest.IsZero() || !reflect.DeepEqual(selected.coordinates[coordinateIDs[i]], want) || len(selected.markers) != i+1 || f.store.cas != beforeCAS+1 {
				t.Fatal("coordinate isolation send did not follow exact selected reservation", i)
			}
		}
		got := plan.execute(ctx, controlled.callbacks(), publicationEngineCurrent(f))
		controlled.onSend = nil
		if got.state.Outcome != ObservedCurrent || got.summary != contract.PublicationSummaryUnknown || len(got.output.Entries) != 1 || len(got.output.Entries[0].Actions) != 1 || got.output.Entries[0].Actions[0].Disposition != contract.PublicationOutcomeUnknown || got.output.Entries[0].Actions[0].AttemptID != reserved.AttemptID || len(controlled.owners) != i+1 || f.store.cas != beforeCAS+2 {
			t.Fatal("coordinate isolation actual unknown lifecycle", i)
		}
		selected := publicationEngineReopen(t, f)
		want.LateEffectRisk = 1
		reserved.State, reserved.LateEffectRisk = contract.PublicationUnknown, 1
		if !reflect.DeepEqual(selected.coordinates[coordinateIDs[i]], want) || selected.markers[reserved.AttemptID] != reserved || reserved.Evidence.Class != contract.PublicationUnproved || reserved.Evidence.Entry != contract.PublicationMayHaveEnteredEntry || reserved.Evidence.NormalizedStatus != 0 || reserved.Evidence.SafeRequestID != "" || reserved.Evidence.SafeResourceID != "" || f.session.root.WarningBits != warning {
			t.Fatal("coordinate isolation changed exact unknown close", i)
		}
		for id, coordinate := range prior.coordinates {
			if id != coordinateIDs[i] && !reflect.DeepEqual(selected.coordinates[id], coordinate) {
				t.Fatal("coordinate isolation create changed another coordinate", i)
			}
		}
		for id, marker := range prior.markers {
			if selected.markers[id] != marker {
				t.Fatal("coordinate isolation create changed an earlier marker", i)
			}
		}
		markerIDs[i] = reserved.AttemptID
		checkCurrent()
		publicationDisposalWindows(t, f.session, windows)
	}
	checkOwners := func() {
		t.Helper()
		if len(controlled.owners) != count {
			t.Fatal("coordinate prefix changed its fixed owner count")
		}
		seenOwners := make(map[contract.ID]bool)
		for _, owner := range controlled.owners {
			if seenOwners[owner.id] || owner.id.IsZero() || owner.prepared != 1 || owner.armed != 1 || owner.sent != 1 || owner.retired != 1 {
				t.Fatalf("coordinate isolation owner lifecycle prepared=%d armed=%d sent=%d retired=%d", owner.prepared, owner.armed, owner.sent, owner.retired)
			}
			seenOwners[owner.id] = true
		}
	}
	checkOwners()
	t.Cleanup(checkOwners)
	return publicationUnknownCoordinateFixture{f: f, entries: entries, baseline: baseline, coordinateIDs: coordinateIDs, markerIDs: markerIDs, controlled: controlled, beforeSetupCAS: beforeSetupCAS, checkCurrent: checkCurrent, windows: windows, warning: warning}
}

// full_only: false
func TestPublicationMarkerExitReplacesSharedCoordinatePage(t *testing.T) {
	ctx := t.Context()
	if deadline, finite := t.Deadline(); !finite || !time.Now().Before(deadline) {
		t.Fatal("coordinate isolation requires a live finite test deadline")
	}
	env := memoryScenarioEnvironment(t)
	env.Context = ctx
	initial := newEnvironmentFixture(t, ctx, env, []int{1, 1, 1}, false)
	incoming, err := initial.session.receiptWindows(ctx)
	if err != nil || incoming.DomainID != env.Domain || len(incoming.Successes) != 1 || incoming.Successes[0].OperationKind != contract.OperationInitializeDomain || len(incoming.Failures) != 0 {
		t.Fatal("small coordinate source lacks its exact initialization history", err)
	}
	incoming.Successes, incoming.Failures = slices.Clone(incoming.Successes), slices.Clone(incoming.Failures)
	prefix := actualPublicationUnknownCoordinates(t, env, initial.session, 3)
	if !slices.Equal(prefix.windows.Successes, incoming.Successes) || !slices.Equal(prefix.windows.Failures, incoming.Failures) || !slices.Equal(prefix.windows.Order, incoming.Order) || prefix.warning != 0 {
		t.Fatal("small coordinate source changed its authenticated history")
	}
	publicationThreeCoordinateExits(t, env, prefix)
}

// The two callers retain either initialization history or the paired full-window
// prefix. Both use the same complete three-coordinate exit oracle.
func publicationThreeCoordinateExits(t *testing.T, env fixtureEnvironment, prefix publicationUnknownCoordinateFixture) []contract.CompactMutationReceipt {
	t.Helper()
	ctx := t.Context()
	full := len(prefix.windows.Successes) == 256 && len(prefix.windows.Failures) == 256 && prefix.warning == 0x19
	initialized := len(prefix.windows.Successes) == 1 && prefix.windows.Successes[0].OperationKind == contract.OperationInitializeDomain && len(prefix.windows.Failures) == 0 && prefix.warning == 0
	if len(prefix.entries) != 3 || len(prefix.coordinateIDs) != 3 || len(prefix.markerIDs) != 3 || !full && !initialized {
		t.Fatal("three-coordinate exit proof has an unsupported actual source history")
	}
	f, entries := prefix.f, prefix.entries
	baseline, checkCurrent := prefix.baseline, prefix.checkCurrent
	coordinateIDs, markerIDs := prefix.coordinateIDs, prefix.markerIDs
	controlled, beforeSetupCAS := prefix.controlled, prefix.beforeSetupCAS
	windows := prefix.windows
	windows.Successes, windows.Failures = slices.Clone(windows.Successes), slices.Clone(windows.Failures)
	original := sessionStateImage(t, f.session)
	selected := publicationEngineReopen(t, f)
	expectedCoordinates := maps.Clone(selected.coordinates)
	expectedMarkers := maps.Clone(selected.markers)
	expectedGroups := make(map[contract.ID]format.AdministrativeGroup)
	for _, group := range original.AdministrativeIndex.Groups {
		group.RelatedGroupIndexes = nil
		expectedGroups[group.GroupID] = group
	}
	type location struct {
		ref       format.Ref
		ordinal   uint16
		mandatory bool
	}
	originalLocations := make(map[generatedRecordKey]location)
	var coordinatePage, markerPage format.Ref
	for _, page := range original.AdministrativeIndex.Pages {
		if page.ReadRequired {
			t.Fatal("coordinate isolation unexpectedly requires generated slice payload")
		}
		row := 0
		for _, span := range page.Spans {
			for offset := uint16(0); offset < span.Count; offset++ {
				summary := page.Rows[row]
				row++
				switch summary.Kind {
				case contract.PublicationCoordinateSupportKind, contract.PublicationMarkerSupportKind, contract.OutputConfigurationSliceSupportKind:
					originalLocations[generatedRecordKey{summary.Kind, summary.RecordID}] = location{page.Ref, span.First + offset, span.Mandatory}
				case contract.MutationReceiptSupportKind, contract.GeneratedFragmentSupportKind:
					// EndWork replaces these two dedicated pages; their exact
					// logical contents and new physical pair are checked below.
				default:
					t.Fatal("three-coordinate predecessor has an unexpected support kind", summary.Kind)
				}
				switch summary.Kind {
				case contract.PublicationCoordinateSupportKind:
					if summary.BodyLength != 772 || !span.Mandatory || !coordinatePage.Object.IsZero() && coordinatePage != page.Ref {
						t.Fatal("three coordinates did not share one mandatory page")
					}
					coordinatePage = page.Ref
				case contract.PublicationMarkerSupportKind:
					if summary.BodyLength != 911 || span.Mandatory || !markerPage.Object.IsZero() && markerPage != page.Ref {
						t.Fatal("three unknown markers did not share one optional page")
					}
					markerPage = page.Ref
				}
			}
		}
	}
	if coordinatePage == markerPage || coordinatePage.Length != 2502 || markerPage.Length != 2919 {
		t.Fatal("coordinate isolation initial shared-page framing")
	}
	coordinateNow, expectedPhysicalRows := publicationCoordinatePhysicalRows(t, f.session)
	if coordinateNow != coordinatePage || len(expectedPhysicalRows) != 3 {
		t.Fatal("three-coordinate physical predecessor")
	}
	var changedCoordinate contract.ID
	seenCoordinateObjects := map[contract.ID]bool{coordinatePage.Object: true}
	var currentBytes uint64
	for _, ref := range baseline.Root.ValueEntryPages {
		if ref != nil {
			currentBytes += uint64(ref.Length)
		}
	}
	for _, ref := range baseline.Root.Recipients {
		if ref != nil {
			currentBytes += uint64(ref.Length)
		}
	}
	var previousReceiptPage, previousReceiptIndex format.Ref
	checkPhysical := func(ended int) {
		t.Helper()
		// Coordinate bodies use 648 fixed bytes plus 124 fixture bytes. Markers
		// use 763 fixed bytes, 128 hex-ID bytes and 20 birth-identity bytes.
		// Configuration images use 225 fixed bytes plus 143 per target; the
		// slice adds 78 bytes. Page/row framing adds 75/37, totaling 6265 here.
		// A receipt/index pair adds 299 bytes plus 508+72 per retained outcome.
		n := len(windows.Successes) + len(windows.Failures)
		wantChildren := uint32(6)
		wantSupport := uint64(6265)
		wantIndex := uint32(2681 - 335*ended)
		wantRows := uint32(7 - ended)
		if n != 0 {
			wantChildren += 2
			wantSupport += uint64(299 + 580*n)
			wantIndex += uint32(267 + 37*n)
			wantRows += uint32(n + 1)
		}
		if ended == 3 {
			wantChildren--
			wantSupport -= 2919
			wantIndex -= 108
		}
		var supportBytes uint64
		for _, ref := range f.session.root.RequiredSupport {
			supportBytes += uint64(ref.Length)
		}
		if f.session.root.ChildCount != wantChildren || len(f.session.root.RequiredSupport) != int(wantChildren)-3 || supportBytes != wantSupport || f.session.root.AdministrativeIndex.Length != wantIndex || len(f.session.root.AdministrativeIndexShards) != 0 || f.session.root.ChildEncodedBytes != currentBytes+wantSupport+uint64(wantIndex) || f.session.root.RequiredSupportRecordCount != wantRows {
			t.Fatalf("coordinate isolation phase=%d children=%d support=%d index=%d bytes=%d", ended, f.session.root.ChildCount, supportBytes, f.session.root.AdministrativeIndex.Length, f.session.root.ChildEncodedBytes)
		}
		physicalRef, physicalRows := publicationCoordinatePhysicalRows(t, f.session)
		if physicalRef.Index != coordinatePage.Index || physicalRef.Length != coordinatePage.Length {
			t.Fatal("coordinate replacement changed physical page index/width", ended)
		}
		if ended == 0 {
			if !reflect.DeepEqual(physicalRows, expectedPhysicalRows) {
				t.Fatal("coordinate physical predecessor changed")
			}
		} else {
			publicationCoordinateCopiedRows(t, expectedPhysicalRows, physicalRows, expectedCoordinates[changedCoordinate])
		}
		if ended > 0 {
			if seenCoordinateObjects[physicalRef.Object] || slices.Contains(f.session.root.RequiredSupport, coordinateNow) {
				t.Fatal("coordinate replacement did not use a fresh whole page", ended)
			}
			seenCoordinateObjects[physicalRef.Object] = true
		}
		coordinateNow = physicalRef
		if slices.Contains(f.session.root.RequiredSupport, coordinatePage) != (ended == 0) || slices.Contains(f.session.root.RequiredSupport, markerPage) != (ended < 3) {
			t.Fatal("coordinate replacement retained an obsolete Ref or lost an optional peer page", ended)
		}
		var receiptPage, receiptIndex format.Ref
		receiptRows, indexRows := 0, 0
		for _, page := range f.session.adminIndex.Pages {
			if page.ReadRequired {
				t.Fatal("coordinate isolation unexpectedly introduced generated slice payload", ended)
			}
			row := 0
			for _, span := range page.Spans {
				for offset := uint16(0); offset < span.Count; offset++ {
					summary := page.Rows[row]
					row++
					key := generatedRecordKey{summary.Kind, summary.RecordID}
					switch summary.Kind {
					case contract.PublicationCoordinateSupportKind, contract.PublicationMarkerSupportKind, contract.OutputConfigurationSliceSupportKind:
						old, exists := originalLocations[key]
						if !exists {
							t.Fatal("coordinate exit introduced an unexpected immutable peer", ended)
						}
						wantRef := old.ref
						if key.kind == contract.PublicationCoordinateSupportKind {
							wantRef = coordinateNow
						}
						if page.Ref != wantRef || span.First+offset != old.ordinal || span.Mandatory != old.mandatory {
							t.Fatal("coordinate replacement changed a retained physical ordinal/selection", ended)
						}
					case contract.MutationReceiptSupportKind:
						if n == 0 || summary.BodyLength != 471 || len(page.Rows) != n || len(page.Spans) != 1 || span.First != 0 || int(span.Count) != n || !span.Mandatory || len(span.GroupIndexes) != 0 || !receiptPage.Object.IsZero() && receiptPage != page.Ref {
							t.Fatal("coordinate exit receipt rows do not occupy their exact pure mandatory page", ended)
						}
						receiptPage = page.Ref
						receiptRows++
					case contract.GeneratedFragmentSupportKind:
						if n == 0 || summary.BodyLength != uint32(112+72*n) || len(page.Rows) != 1 || len(page.Spans) != 1 || span.First != 0 || span.Count != 1 || !span.Mandatory || len(span.GroupIndexes) != 0 {
							t.Fatal("coordinate exit receipt index does not occupy its exact dense mandatory page", ended)
						}
						receiptIndex = page.Ref
						indexRows++
					default:
						t.Fatal("three-coordinate exit has an unexpected support kind", ended, summary.Kind)
					}
				}
			}
		}
		if n == 0 {
			if receiptRows != 0 || indexRows != 0 || !receiptPage.Object.IsZero() || !receiptIndex.Object.IsZero() {
				t.Fatal("empty coordinate history gained receipt pages", ended)
			}
		} else if receiptRows != n || indexRows != 1 || receiptPage == receiptIndex || receiptPage.Length != uint32(75+508*n) || receiptIndex.Length != uint32(224+72*n) {
			t.Fatal("coordinate exit receipt/index pair framing or count", ended)
		}
		if ended > 0 {
			for _, old := range []format.Ref{previousReceiptPage, previousReceiptIndex} {
				if !old.Object.IsZero() && slices.Contains(f.session.root.RequiredSupport, old) {
					t.Fatal("coordinate exit retained an old dedicated receipt/index Ref", ended)
				}
			}
		}
		previousReceiptPage, previousReceiptIndex = receiptPage, receiptIndex
		expectedPhysicalRows = physicalRows
	}
	checkPhysical(0)
	var exitReceipts []contract.CompactMutationReceipt
	for i, markerID := range markerIDs {
		warning := prefix.warning | uint8(0x1c)
		wantRemoved := publicationCoordinateRemovedSupport(t, f.session, coordinateNow, markerID)
		beforeCAS := f.store.cas
		f.session = endGeneratedObligation(t, ctx, env, f.session, markerID, []contract.ID{markerID}, entries, warning)
		f.admission = OpenContext{admission: &f.session.admission}
		var err error
		selected, err = selectedPublicationRelation(f.session.selectedImage())
		want := expectedCoordinates[coordinateIDs[i]]
		want.OwnerState, want.LatestUnresolvedAttemptID = contract.PublicationOwnerNone, contract.ID{}
		expectedCoordinates[coordinateIDs[i]] = want
		changedCoordinate = coordinateIDs[i]
		// The whole three-coordinate page and selected marker are replaced,
		// together with every retained receipt and its single index fragment.
		wantRemovedCount := uint32(5 + len(windows.Successes) + len(windows.Failures))
		if f.session.head.EndWork.RemovedSupport != wantRemoved || wantRemoved.Count != wantRemovedCount {
			t.Fatal("coordinate replacement exact removed old physical support", i)
		}
		delete(expectedMarkers, markerID)
		delete(expectedGroups, markerID)
		group := expectedGroups[coordinateIDs[i]]
		zero := contract.ID{}
		group.Dependencies = publicationDisposalAdminDescriptor("publication-coordinate-dependencies", [][]byte{zero[:], zero[:]})
		group.SelectedEvidenceSummary = 0x41
		expectedGroups[coordinateIDs[i]] = group
		if err != nil || !reflect.DeepEqual(selected.coordinates, expectedCoordinates) || !reflect.DeepEqual(selected.markers, expectedMarkers) || f.session.root.WarningBits != warning || f.store.cas != beforeCAS+1 || len(f.session.adminIndex.Groups) != 5-i || !reflect.DeepEqual(f.session.adminIndex.PublicationOrder, original.AdministrativeIndex.PublicationOrder) {
			t.Fatal("coordinate isolation exact retained owner/marker/order relation", i, err)
		}
		for _, actual := range f.session.adminIndex.Groups {
			if actual.OwnerKind == format.AdministrativePublicationMarker {
				if len(actual.RelatedGroupIndexes) != 1 || f.session.adminIndex.Groups[actual.RelatedGroupIndexes[0]].GroupID != actual.OwnerID {
					t.Fatal("coordinate isolation changed marker prerequisite", i)
				}
			} else if len(actual.RelatedGroupIndexes) != 0 {
				t.Fatal("coordinate isolation changed coordinate prerequisites", i)
			}
			actual.RelatedGroupIndexes = nil
			if !reflect.DeepEqual(actual, expectedGroups[actual.GroupID]) {
				t.Fatal("coordinate isolation changed an exact owner summary", i)
			}
		}
		row, present := f.session.mutationReceipts[f.session.head.EndWork.OperationID]
		if !present {
			t.Fatal("three-coordinate exit has no selected new receipt", i)
		}
		exitReceipts = append(exitReceipts, row) // Fully checked against q by endGeneratedObligation.
		windows.Successes = append(slices.Clone(windows.Successes), row)
		windows.Order = append(slices.Clone(windows.Order), row.OperationID)
		if len(windows.Successes) > 256 {
			evicted := windows.Successes[0].OperationID
			windows.Successes = windows.Successes[len(windows.Successes)-256:]
			windows.Order = slices.DeleteFunc(windows.Order, func(id contract.ID) bool { return id == evicted })
		}
		publicationDisposalWindows(t, f.session, windows)
		checkCurrent()
		checkPhysical(i + 1)
	}
	wantSuccesses := min(len(prefix.windows.Successes)+3, contract.MutationReceiptWindowLimit)
	wantFailures := len(prefix.windows.Failures)
	if f.store.cas != beforeSetupCAS+10 || len(controlled.owners) != 3 || len(windows.Successes) != wantSuccesses || len(windows.Failures) != wantFailures {
		t.Fatal("coordinate isolation complete finite operation inventory")
	}
	return exitReceipts
}

// full_only: true
// This actual 264-marker history requires every independent marker exit to fit.
func TestPublicationEveryMarkerExitRetainsRemainingExits(t *testing.T) {
	ctx := t.Context()
	if deadline, finite := t.Deadline(); !finite || !time.Now().Before(deadline) {
		t.Fatal("accumulated marker exits require a live finite deadline")
	}
	env := memoryScenarioEnvironment(t)
	env.Context = ctx
	store := env.Store.(*memoryStore)
	if err := store.useFileBodies(filepath.Join(t.TempDir(), "bodies")); err != nil {
		t.Fatal("accumulated publication file Store", err)
	}
	sizes := make([]int, 264)
	for i := range sizes {
		sizes[i] = 1
	}
	initial := newEnvironmentFixture(t, ctx, env, sizes, false)
	incoming, err := initial.session.receiptWindows(ctx)
	if err != nil || incoming.DomainID != env.Domain || len(incoming.Successes) != 1 || incoming.Successes[0].OperationKind != contract.OperationInitializeDomain || len(incoming.Failures) != 0 {
		t.Fatal("accumulated coordinate source lacks its exact initialization history", err)
	}
	incoming.Successes, incoming.Failures = slices.Clone(incoming.Successes), slices.Clone(incoming.Failures)
	prefix := actualPublicationUnknownCoordinates(t, env, initial.session, 264)
	if !slices.Equal(prefix.windows.Successes, incoming.Successes) || !slices.Equal(prefix.windows.Failures, incoming.Failures) || !slices.Equal(prefix.windows.Order, incoming.Order) || prefix.warning != 0 {
		t.Fatal("accumulated coordinate source changed its authenticated history")
	}
	f := prefix.f
	original := sessionStateImage(t, f.session)
	selected, err := selectedPublicationRelation(f.session.selectedImage())
	if err != nil {
		t.Fatal("accumulated publication selected relation", err)
	}
	expectedCoordinates, expectedMarkers := maps.Clone(selected.coordinates), maps.Clone(selected.markers)
	expectedGroups := make(map[contract.ID]format.AdministrativeGroup)
	for _, group := range original.AdministrativeIndex.Groups {
		group.RelatedGroupIndexes = nil
		expectedGroups[group.GroupID] = group
	}
	type markerLocation struct {
		ref     format.Ref
		ordinal uint16
	}
	markerLocations := make(map[contract.ID]markerLocation)
	var coordinatePage, markerPage, configurationPage format.Ref
	var receiptPage, receiptIndex format.Ref
	incomingCount := len(incoming.Successes) + len(incoming.Failures)
	receiptRows, indexRows := 0, 0
	for _, page := range original.AdministrativeIndex.Pages {
		if page.ReadRequired {
			t.Fatal("accumulated publication unexpectedly needs generated payload")
		}
		row := 0
		for _, span := range page.Spans {
			for offset := uint16(0); offset < span.Count; offset++ {
				summary := page.Rows[row]
				row++
				switch summary.Kind {
				case contract.PublicationCoordinateSupportKind:
					if summary.BodyLength != 772 || !span.Mandatory || !coordinatePage.Object.IsZero() && coordinatePage != page.Ref {
						t.Fatal("accumulated mandatory coordinate layout")
					}
					coordinatePage = page.Ref
				case contract.PublicationMarkerSupportKind:
					if summary.BodyLength != 911 || span.Mandatory || !markerPage.Object.IsZero() && markerPage != page.Ref {
						t.Fatal("accumulated optional marker layout")
					}
					markerPage = page.Ref
					markerLocations[summary.RecordID] = markerLocation{page.Ref, span.First + offset}
				case contract.OutputConfigurationSliceSupportKind:
					if !span.Mandatory || !configurationPage.Object.IsZero() {
						t.Fatal("accumulated output configuration layout")
					}
					configurationPage = page.Ref
				case contract.MutationReceiptSupportKind:
					if summary.BodyLength != 471 || !span.Mandatory || len(span.GroupIndexes) != 0 || len(page.Spans) != 1 || span.First != 0 || int(span.Count) != incomingCount || len(page.Rows) != incomingCount || !receiptPage.Object.IsZero() && receiptPage != page.Ref {
						t.Fatal("accumulated initial receipt page layout")
					}
					receiptPage = page.Ref
					receiptRows++
				case contract.GeneratedFragmentSupportKind:
					if summary.BodyLength != uint32(112+72*incomingCount) || !span.Mandatory || len(span.GroupIndexes) != 0 || len(page.Spans) != 1 || span.First != 0 || span.Count != 1 || len(page.Rows) != 1 {
						t.Fatal("accumulated initial receipt index layout")
					}
					receiptIndex = page.Ref
					indexRows++
				default:
					t.Fatal("accumulated publication initial support family", summary.Kind)
				}
			}
		}
	}
	valuePages, recipientPages := 0, 0
	var valueBytes, recipientBytes uint64
	for _, ref := range original.Root.ValueEntryPages {
		if ref != nil {
			valuePages++
			valueBytes += uint64(ref.Length)
		}
	}
	for _, ref := range original.Root.Recipients {
		if ref != nil {
			recipientPages++
			recipientBytes += uint64(ref.Length)
		}
	}
	// The three publication pages total502165; receipt/index framing adds299
	// plus508+72 per outcome. Two mandatory pages add267+37*N index bytes.
	initialSupport := uint64(502165 + 299 + 580*incomingCount)
	initialIndex := uint32(183815 + 267 + 37*incomingCount)
	if receiptRows != incomingCount || indexRows != 1 || receiptPage == receiptIndex || receiptPage.Length != uint32(75+508*incomingCount) || receiptIndex.Length != uint32(224+72*incomingCount) || recipientPages != 1 || original.Root.ChildEncodedBytes != valueBytes+recipientBytes+initialSupport+uint64(initialIndex) || valuePages != 17 || valueBytes != 50643 || len(original.Root.RequiredSupport) != 5 || original.Root.RequiredSupportRecordCount != uint32(529+incomingCount+1) || len(original.AdministrativeIndex.Groups) != 528 || len(markerLocations) != 264 || coordinatePage.Length != 213651 || markerPage.Length != 250347 || configurationPage.Length != 38167 || original.Root.ChildCount != 24 || original.Root.AdministrativeIndex.Length != initialIndex || len(original.Root.AdministrativeIndexShards) != 0 {
		t.Fatal("accumulated publication exact initial encoded shape")
	}
	coordinateNow, expectedPhysicalRows := publicationCoordinatePhysicalRows(t, f.session)
	if coordinateNow != coordinatePage || len(expectedPhysicalRows) != 264 {
		t.Fatal("accumulated coordinate physical predecessor")
	}
	seenCoordinateObjects := map[contract.ID]bool{coordinatePage.Object: true}
	windows := contract.MutationReceiptWindows{DomainID: incoming.DomainID,
		Successes: slices.Clone(incoming.Successes), Failures: slices.Clone(incoming.Failures), Order: slices.Clone(incoming.Order)}
	var selectedExitIDs []contract.ID
	for i, markerID := range prefix.markerIDs {
		files := store.fileBodies
		t.Logf("publication marker exit=%d/264 children=%d child_bytes=%d index_bytes=%d groups=%d owners=%d CAS_delta=%d creates=%d store_objects=%d file_bytes=%d file_count=%d", i+1, f.session.root.ChildCount, f.session.root.ChildEncodedBytes, f.session.root.AdministrativeIndex.Length, len(f.session.adminIndex.Groups), len(prefix.controlled.owners), store.cas-prefix.beforeSetupCAS, store.creates, len(store.objects), files.used, files.next)
		beforeCAS := store.cas
		warning := uint8(0x1c)
		wantRemoved := publicationCoordinateRemovedSupport(t, f.session, coordinateNow, markerID)
		f.session = endGeneratedObligation(t, ctx, env, f.session, markerID, []contract.ID{markerID}, prefix.entries, warning)
		f.admission = OpenContext{admission: &f.session.admission}
		selected, err = selectedPublicationRelation(f.session.selectedImage())
		want := expectedCoordinates[prefix.coordinateIDs[i]]
		want.OwnerState, want.LatestUnresolvedAttemptID = contract.PublicationOwnerNone, contract.ID{}
		expectedCoordinates[prefix.coordinateIDs[i]] = want
		physicalRef, physicalRows := publicationCoordinatePhysicalRows(t, f.session)
		publicationCoordinateCopiedRows(t, expectedPhysicalRows, physicalRows, want)
		if physicalRef.Index != coordinatePage.Index || physicalRef.Length != coordinatePage.Length || seenCoordinateObjects[physicalRef.Object] || slices.Contains(f.session.root.RequiredSupport, coordinateNow) || f.session.head.EndWork.RemovedSupport != wantRemoved {
			t.Fatal("accumulated coordinate whole physical copy/disposition", i+1)
		}
		seenCoordinateObjects[physicalRef.Object] = true
		coordinateNow = physicalRef
		delete(expectedMarkers, markerID)
		delete(expectedGroups, markerID)
		group := expectedGroups[prefix.coordinateIDs[i]]
		zero := contract.ID{}
		group.Dependencies = publicationDisposalAdminDescriptor("publication-coordinate-dependencies", [][]byte{zero[:], zero[:]})
		group.SelectedEvidenceSummary = 0x41
		expectedGroups[prefix.coordinateIDs[i]] = group
		if err != nil || !reflect.DeepEqual(selected.coordinates, expectedCoordinates) || !reflect.DeepEqual(selected.markers, expectedMarkers) || len(f.session.adminIndex.Groups) != 527-i || f.session.root.WarningBits != warning || store.cas != beforeCAS+1 || !reflect.DeepEqual(f.session.adminIndex.PublicationOrder, original.AdministrativeIndex.PublicationOrder) {
			t.Fatal("accumulated marker exit changed exact independent owners/order", i+1, err)
		}
		for _, actual := range f.session.adminIndex.Groups {
			if actual.OwnerKind == format.AdministrativePublicationMarker {
				if len(actual.RelatedGroupIndexes) != 1 || f.session.adminIndex.Groups[actual.RelatedGroupIndexes[0]].GroupID != actual.OwnerID {
					t.Fatal("accumulated marker prerequisite changed", i+1)
				}
			} else if len(actual.RelatedGroupIndexes) != 0 {
				t.Fatal("accumulated coordinate prerequisites changed", i+1)
			}
			actual.RelatedGroupIndexes = nil
			if !reflect.DeepEqual(actual, expectedGroups[actual.GroupID]) {
				t.Fatal("accumulated marker exit changed exact owner summary", i+1)
			}
		}
		for _, page := range f.session.adminIndex.Pages {
			if page.ReadRequired {
				t.Fatal("accumulated marker exit added generated payload", i+1)
			}
			row := 0
			for _, span := range page.Spans {
				for offset := uint16(0); offset < span.Count; offset++ {
					summary := page.Rows[row]
					row++
					if summary.Kind == contract.PublicationMarkerSupportKind {
						old, present := markerLocations[summary.RecordID]
						if !present || page.Ref != old.ref || span.First+offset != old.ordinal || span.Mandatory {
							t.Fatal("accumulated marker exit moved an optional peer", i+1)
						}
					}
				}
			}
		}
		if !slices.Contains(f.session.root.RequiredSupport, configurationPage) || slices.Contains(f.session.root.RequiredSupport, markerPage) != (i < 263) {
			t.Fatal("accumulated marker exit lost a retained immutable object", i+1)
		}
		op := f.session.head.EndWork.OperationID
		r, exists := f.session.mutationReceipts[op]
		if !exists {
			t.Fatal("accumulated marker exit has no selected receipt", i+1)
		}
		windows.Successes = append(slices.Clone(windows.Successes), r)
		windows.Order = append(slices.Clone(windows.Order), r.OperationID)
		if len(windows.Successes) > 256 {
			evicted := windows.Successes[0].OperationID
			windows.Successes = windows.Successes[len(windows.Successes)-256:]
			windows.Order = slices.DeleteFunc(windows.Order, func(id contract.ID) bool { return id == evicted })
		}
		selectedExitIDs = append(selectedExitIDs, op)
		publicationDisposalWindows(t, f.session, windows)
		prefix.checkCurrent()
		refs := make(map[format.Ref]bool)
		add := func(ref format.Ref) {
			if ref.Length == 0 || refs[ref] {
				t.Fatal("accumulated marker exit duplicate/empty child", i+1)
			}
			refs[ref] = true
		}
		for _, ref := range f.session.root.ValueEntryPages {
			if ref != nil {
				add(*ref)
			}
		}
		for _, ref := range f.session.root.Recipients {
			if ref != nil {
				add(*ref)
			}
		}
		for _, ref := range f.session.root.CurrentAccess.Core.AccessPageRefs {
			add(ref)
		}
		for _, ref := range f.session.root.RequiredSupport {
			add(ref)
		}
		add(f.session.root.AdministrativeIndex)
		for _, ref := range f.session.root.AdministrativeIndexShards {
			add(ref)
		}
		var childBytes uint64
		for ref := range refs {
			childBytes += uint64(ref.Length)
		}
		n, successes := i+1, min(len(incoming.Successes)+i+1, 256)
		wantChildren := uint32(24)
		wantSupport := uint64(502464 + 580*successes)
		wantIndex := uint32(183966 - 335*n + 37*successes + 116)
		if n == 264 {
			wantChildren--
			wantSupport -= 250347
			wantIndex -= 108
		}
		var supportBytes uint64
		for _, ref := range f.session.root.RequiredSupport {
			supportBytes += uint64(ref.Length)
		}
		if f.session.root.ChildCount != wantChildren || supportBytes != wantSupport || f.session.root.AdministrativeIndex.Length != wantIndex || f.session.root.ChildEncodedBytes != valueBytes+recipientBytes+wantSupport+uint64(wantIndex) {
			t.Fatal("accumulated coordinate whole-page physical arithmetic", n)
		}
		if len(refs) > 256 || f.session.root.ChildCount != uint32(len(refs)) || f.session.root.ChildEncodedBytes != childBytes || len(f.session.root.AdministrativeIndexShards) != 0 || f.session.root.RequiredSupportRecordCount != uint32(529-n+successes+1) {
			t.Fatal("accumulated marker exit physical charge differs from selected refs/rows", i+1)
		}
		expectedPhysicalRows = physicalRows
	}
	if store.cas != prefix.beforeSetupCAS+793 || len(expectedMarkers) != 0 || len(expectedCoordinates) != 264 || len(windows.Successes) != 256 || len(windows.Failures) != 0 || len(selectedExitIDs) != 264 {
		t.Fatal("accumulated marker exit fixed completed inventory")
	}
	for _, id := range selectedExitIDs[:8] {
		if _, exists := f.session.mutationReceipts[id]; exists {
			t.Fatal("accumulated marker exit retained an evicted old lookup")
		}
	}
	for _, row := range incoming.Successes {
		if _, exists := f.session.mutationReceipts[row.OperationID]; exists {
			t.Fatal("accumulated marker exit retained evicted initialization history")
		}
	}
	for i, row := range windows.Successes {
		if row.OperationID != selectedExitIDs[i+8] {
			t.Fatal("accumulated marker exit final receipt selection order", i)
		}
	}
}

package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestPublicationDisposalCycles(t *testing.T) {
	for _, test := range []struct {
		name  string
		count int
		full  bool
	}{
		{"one_cycle", 1, false},
		{"full_windows_one_cycle", 1, true},
		{"warm_batch", 32, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Run("marker_exit", func(t *testing.T) {
				publicationDisposalCycles(t, test.count, test.full, false)
			})
			t.Run("coordinate_exit", func(t *testing.T) {
				publicationDisposalCycles(t, test.count, test.full, true)
			})
		})
	}
}

// full_only: true
// These real histories prove disposal beyond the retained marker/coordinate bounds.
func TestPublicationDisposalAccumulatedHistory(t *testing.T) {
	for _, test := range []struct {
		name    string
		count   int
		retired bool
	}{
		{"unknown_4097", 4097, false},
		{"retired_1025", 1025, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			publicationDisposalCycles(t, test.count, true, test.retired)
		})
	}
}

func publicationDisposalOutput(slot string) *outputApplyInput {
	target := outputConfigurationTarget("member-000", slot)

	return &outputApplyInput{
		bindings: []outputApplyBinding{{destinationID: "publication", targets: []outputApplyTarget{target}}},
		routes:   []outputApplyRoute{{entryName: "member-000", destinations: []string{"publication"}}},
	}
}

func publicationDisposalCycles(t *testing.T, count int, full, retired bool) {
	t.Helper()
	start := time.Now()
	env := memoryScenarioEnvironment(t)
	env.Context = t.Context()
	initial := newEnvironmentFixture(t, t.Context(), env, []int{1}, false)
	windows, err := initial.session.receiptWindows(t.Context())
	if err != nil || windows.DomainID != env.Domain {
		t.Fatal("disposal source receipt history", err)
	}
	windows.Successes, windows.Failures = slices.Clone(windows.Successes), slices.Clone(windows.Failures)
	if full {
		windows = seedBothFullReceiptWindows(t, env, initial)
		t.Log("initial 512 receipts are signed fixture history, not executed operations")
	}
	f := &fixture{store: env.Store.(*memoryStore), trust: env.Trust.(*fixtureTrust), admission: initial.admission, session: initial.session}
	if err := f.store.useFileBodies(filepath.Join(t.TempDir(), "bodies")); err != nil {
		t.Fatal("file-backed immutable history", err)
	}
	input := publicationInput{names: []string{"member-000"}, acting: f.session.admission.recipient, deadline: time.Now().Add(30 * time.Second)}
	private := newPublicationControlledPrivate()
	private.evidence = contract.PublicationUnproved
	entries := f.session.currentEntryInputs()
	entries = append(entries, ApplyEntryInput{Name: "member-001", Recipients: []contract.ID{f.session.admission.recipient}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte{1}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
	output := publicationDisposalOutput("publication")
	configuration := selectOutputConfiguration(t, f, entries, output)
	publicationDisposalWindows(t, f.session, windows)
	publicationDisposalPhysical(t, f.session, "configured", len(windows.Successes)+len(windows.Failures))
	t.Logf("setup duration=%s", time.Since(start))
	setupEnd := time.Now()
	var coldDuration time.Duration
	coldOpens := 0
	reopen := func() selectedPublication {
		started := time.Now()
		selected := publicationEngineReopen(t, f)
		coldDuration += time.Since(started)
		coldOpens++
		return selected
	}
	seen := make(map[contract.ID]string, count*10)
	seenSlots := make(map[string]bool)
	remember := func(id contract.ID, role string) {
		t.Helper()
		if old, exists := seen[id]; id.IsZero() || exists {
			t.Fatalf("identity reused: role=%s previous=%s zero=%t", role, old, id.IsZero())
		}
		seen[id] = role
	}
	var fixed contract.PublicationCoordinate
	for cycle := 1; cycle <= count; cycle++ {
		cycleStart := time.Now()
		warnings := uint8(0x1c)
		if cycle == 1 {
			warnings = 0
		}
		slot := "publication"
		if retired && cycle > 1 {
			slot = fmt.Sprintf("cycle-%05d", cycle)
			output = publicationDisposalOutput(slot)
			configuration = selectOutputConfiguration(t, f, f.session.currentEntryInputs(), output)
			publicationDisposalWindows(t, f.session, windows)
			publicationDisposalPhysical(t, f.session, "configured", len(windows.Successes)+len(windows.Failures))
		}
		f.admission.admission.publicationNamespaces = []publicationNamespace{{domain: env.Domain, service: "aws", physical: slot, premise: contract.Hash([]byte("independently qualified namespace"))}}
		f.session.admission.publicationNamespaces = f.admission.admission.publicationNamespaces
		input.deadline = time.Now().Add(30 * time.Second)
		selected := reopen()
		if f.session.root.WarningBits != warnings {
			t.Fatal("initial permanent warning changed", cycle, f.session.root.WarningBits, warnings)
		}
		if len(selected.coordinates) != 1 || len(selected.markers) != 0 {
			t.Fatalf("cycle %d initial publication families: coordinates=%d markers=%d", cycle, len(selected.coordinates), len(selected.markers))
		}
		var coordinate contract.PublicationCoordinate
		for _, coordinate = range selected.coordinates {
		}
		if retired {
			if seenSlots[slot] || len(slot) != 11 {
				t.Fatal("retired target name reused or changed width", cycle)
			}
			seenSlots[slot] = true
			remember(coordinate.CoordinateID, "coordinate")
			remember(coordinate.ActiveBindingIncarnationID, "binding")
			remember(coordinate.CurrentPublicationIncarnationID, "publication incarnation")
			if coordinate.LastAdmissionOrdinal != 0 {
				t.Fatal("fresh coordinate ordinal", cycle, coordinate.LastAdmissionOrdinal)
			}
		} else if cycle == 1 {
			fixed = coordinate
		} else if !reflect.DeepEqual(coordinate, fixed) || coordinate.LastAdmissionOrdinal != uint64(cycle-1) {
			t.Fatal("fixed coordinate changed binding/incarnation or reset ordinal", cycle)
		}
		coordinatePreimage := append([]byte("ENKV/PUBLICATION/COORDINATE/v3\x00"), env.Domain[:]...)
		coordinatePreimage = publicationDisposalBlob(coordinatePreimage, []byte("aws"))
		coordinatePreimage = publicationDisposalBlob(coordinatePreimage, []byte(slot))
		if coordinate.CoordinateID != publicationDisposalHash(coordinatePreimage) || coordinate.LastEntryIncarnationID != f.session.valueEntry(0).Incarnation {
			t.Fatal("coordinate does not have the independently selected target/entry relation", cycle)
		}
		binding := configuration.Bindings[0]
		target := binding.Targets[0]
		targetDigest, err := contract.PublicationTargetRowDigest(env.Domain, binding.DestinationID, binding.IncarnationID, target)
		if err != nil {
			t.Fatal("selected target digest", err)
		}
		want := coordinate
		want.OwnerState = contract.PublicationOwnerUncertainCreate
		want.LastAdmissionOrdinal++
		want.PossibleRemoteObject = 1
		want.DeletionDestinationID, want.DeletionConsumerLocator = "publication", slot+"?stage=AWSCURRENT"
		want.DeletionTargetContractID, want.DeletionConfigContractID = target.TargetContractID, binding.Destination.ConfigContractID
		want.DeletionCredentialRouteContractID, want.DeletionPayloadEncoding = private.facts.CredentialRouteContractID, target.PayloadEncoding
		want.DeletionTargetData = bytes.Clone(target.TargetData)
		want.DeletionTargetRowDigest = targetDigest
		beforeEntries := f.session.currentEntryInputs()
		beforeAccess := slices.Clone(f.session.accessRecords())
		cas := f.store.cas
		var reservedMarker contract.PublicationMarker
		private.onSend = func() {
			t.Helper()
			reservation := reopen()
			if len(reservation.markers) != 1 || len(reservation.coordinates) != 1 {
				t.Fatal("reservation family set")
			}
			var marker contract.PublicationMarker
			for _, marker = range reservation.markers {
			}
			reservedMarker = marker
			remember(marker.OperationID, "publication operation")
			remember(marker.AttemptID, "publication attempt")
			want.LatestUnresolvedAttemptID = marker.AttemptID
			if marker.State != contract.PublicationMayHaveEntered || marker.PublicationIncarnationID != want.CurrentPublicationIncarnationID || marker.AdmissionOrdinal != want.LastAdmissionOrdinal || marker.Projection.Action != contract.PublicationCreateWithValue || marker.Projection.TargetRowDigest != targetDigest || marker.BlockerCount != 0 || !marker.BlockerDigest.IsZero() || !reflect.DeepEqual(reservation.coordinates[coordinate.CoordinateID], want) || f.store.cas != cas+1 || f.session.root.WarningBits != warnings {
				t.Fatalf("cycle %d reservation mismatch: state=%d ordinal=%d cas_delta=%d coordinate_equal=%t", cycle, marker.State, marker.AdmissionOrdinal, f.store.cas-cas, reflect.DeepEqual(reservation.coordinates[coordinate.CoordinateID], want))
			}
			publicationDisposalWindows(t, f.session, windows)
			publicationDisposalPhysical(t, f.session, "active_unknown", len(windows.Successes)+len(windows.Failures))
		}
		result := publicationEnginePlan(t, f, input, private).execute(t.Context(), private.callbacks(), publicationEngineCurrent(f))
		private.onSend = nil
		if len(private.owners) != 1 || private.owners[0].prepared != 1 || private.owners[0].armed != 1 || private.owners[0].sent != 1 || private.owners[0].retired != 1 || result.state.Outcome != ObservedCurrent || len(result.output.Entries) != 1 || len(result.output.Entries[0].Actions) != 1 || result.output.Entries[0].Actions[0].Disposition != contract.PublicationOutcomeUnknown || f.store.cas != cas+2 {
			t.Fatalf("cycle %d actual unknown lifecycle: owners=%d cas_delta=%d state=%d", cycle, len(private.owners), f.store.cas-cas, result.state.Outcome)
		}
		private.owners = nil
		selected = reopen()
		want.LateEffectRisk = 1
		marker := selected.markers[want.LatestUnresolvedAttemptID]
		reservedMarker.State, reservedMarker.LateEffectRisk = contract.PublicationUnknown, 1
		if !reflect.DeepEqual(selected.coordinates[coordinate.CoordinateID], want) || len(selected.markers) != 1 || marker.State != contract.PublicationUnknown || marker.LateEffectRisk != 1 || marker.Evidence.Class != contract.PublicationUnproved || marker.Evidence.Entry != contract.PublicationMayHaveEnteredEntry || marker.Evidence.NormalizedStatus != 0 || marker.Evidence.SafeRequestID != "" || marker.Evidence.SafeResourceID != "" || f.session.root.WarningBits != warnings {
			t.Fatalf("cycle %d unknown closure mismatch: coordinate_equal=%t state=%d risk=%d", cycle, reflect.DeepEqual(selected.coordinates[coordinate.CoordinateID], want), marker.State, marker.LateEffectRisk)
		}
		if marker != reservedMarker {
			t.Fatal("unknown close changed original marker identity/projection/evidence", cycle)
		}
		publicationDisposalWindows(t, f.session, windows)
		publicationDisposalPhysical(t, f.session, "active_unknown", len(windows.Successes)+len(windows.Failures))
		if !reflect.DeepEqual(f.session.currentEntryInputs(), beforeEntries) || !reflect.DeepEqual(f.session.accessRecords(), beforeAccess) {
			t.Fatal("publication changed current entries/access", cycle)
		}
		groupID := marker.AttemptID
		if retired {
			selectOutputConfiguration(t, f, f.session.currentEntryInputs(), &outputApplyInput{})
			selected = reopen()
			want.BindingState, want.ActiveBindingIncarnationID = contract.PublicationBindingRetired, contract.ID{}
			if !reflect.DeepEqual(selected.coordinates[coordinate.CoordinateID], want) || selected.markers[marker.AttemptID] != marker || f.session.root.WarningBits != warnings {
				t.Fatal("retirement changed frozen coordinate/marker", cycle)
			}
			publicationDisposalWindows(t, f.session, windows)
			publicationDisposalPhysical(t, f.session, "retired_unknown", len(windows.Successes)+len(windows.Failures))
			groupID = coordinate.CoordinateID
		}
		before := f.session
		admin, state := openAdministrative(t.Context(), f.admission, f.store)
		if admin == nil || state.Outcome != ObservedCurrent {
			t.Fatal("administrative cold open", state)
		}
		publicCalls, privateCalls := env.Custody.Calls()
		cas = f.store.cas
		candidate, state := prepareTestEndSelectedWork(t, admin, t.Context(), groupID, f.trust)
		if candidate == nil || state.Outcome != ObservedCurrent || candidate.firstSend != nil || f.store.cas != cas {
			t.Fatal("exit preparation", cycle, state)
		}
		remember(candidate.head.EndWork.OperationID, "exit operation")
		remember(admin.admission.endWorkInvocation, "exit invocation")
		remember(candidate.head.Core.Revision, "exit revision")
		remember(candidate.head.Core.Root.Object, "exit snapshot")
		var root format.Root
		for _, object := range candidate.objects {
			if object.ref == candidate.head.Core.Root {
				root, err = format.DecodeRoot(object.body)
				if err != nil {
					t.Fatal("prepared root", err)
				}
			}
		}
		remember(root.Transition, "exit transition")
		// Fresh candidate identities are inputs. No candidate outcome or receipt
		// supplies the expected disposition, warning, delta or window.
		expectedSubject, receipt := publicationDisposalExpectedExit(t, before, admin.admission.endWorkInvocation, candidate.head.EndWork.OperationID, candidate.head.Core.Revision, coordinate.CoordinateID, marker.AttemptID, retired, windows)
		q := *candidate.head.EndWork
		q.ReceiptDeltaDigest, q.HeadCoreDigest, q.HeadCoreLength, q.ConditionalPlanDigest = contract.ID{}, contract.ID{}, 0, contract.ID{}
		if q != expectedSubject || candidate.endWorkReceipt != receipt {
			t.Fatalf("cycle %d pre-CAS exit mismatch: subject_equal=%t receipt_equal=%t warning=%02x/%02x pages=%d/%d bytes=%d/%d removed=%d/%d preserved_equal=%t core_equal=%t result_equal=%t", cycle, q == expectedSubject, candidate.endWorkReceipt == receipt, q.AfterWarningBits, expectedSubject.AfterWarningBits, candidate.endWorkReceipt.AdministrativePageDelta, receipt.AdministrativePageDelta, candidate.endWorkReceipt.AdministrativeByteDelta, receipt.AdministrativeByteDelta, q.RemovedSupport.Count, expectedSubject.RemovedSupport.Count, q.PreservedCurrent == expectedSubject.PreservedCurrent, q.RequestCoreDigest == expectedSubject.RequestCoreDigest, candidate.endWorkReceipt.CompleteResult == receipt.CompleteResult)
		}
		var evicted contract.ID
		if len(windows.Successes) == 256 {
			evicted = windows.Successes[0].OperationID
			windows.Successes = windows.Successes[1:]
		}
		windows.Successes = append(slices.Clone(windows.Successes), receipt)
		windows.Order = append(slices.Clone(windows.Order), receipt.OperationID)
		if !evicted.IsZero() {
			windows.Order = slices.DeleteFunc(windows.Order, func(id contract.ID) bool { return id == evicted })
		}
		after, state := admin.selectCandidate(t.Context(), candidate)
		if after == nil || state.Outcome != ObservedCurrent || f.store.cas != cas+1 {
			t.Fatal("exact exit CAS", cycle, state)
		}
		selected = reopen()
		if a, b := env.Custody.Calls(); a != publicCalls || b != privateCalls {
			t.Fatal("exit used a key route", cycle)
		}
		if !reflect.DeepEqual(before.currentEntryInputs(), f.session.currentEntryInputs()) || !reflect.DeepEqual(before.accessRecords(), f.session.accessRecords()) || !reflect.DeepEqual(before.root.Recipients, f.session.root.Recipients) || !reflect.DeepEqual(before.root.ValueEntryPages, f.session.root.ValueEntryPages) || before.root.OutputConfiguration != f.session.root.OutputConfiguration || !reflect.DeepEqual(before.root.CurrentAccess, f.session.root.CurrentAccess) {
			t.Fatal("exit changed exact current state", cycle)
		}
		want.OwnerState, want.LatestUnresolvedAttemptID = contract.PublicationOwnerNone, contract.ID{}
		if len(selected.markers) != 0 || retired && (len(selected.coordinates) != 0 || len(f.session.adminIndex.Groups) != 0 || len(f.session.adminIndex.PublicationOrder) != 0) || !retired && (len(selected.coordinates) != 1 || !reflect.DeepEqual(selected.coordinates[coordinate.CoordinateID], want) || len(f.session.adminIndex.Groups) != 1 || len(f.session.adminIndex.PublicationOrder) != 1 || !slices.Equal(f.session.adminIndex.PublicationOrder[0].Incarnations, []contract.ID{want.CurrentPublicationIncarnationID})) || f.session.root.WarningBits != 0x1c {
			t.Fatal("exit retained closure or changed exact warning/frozen inputs", cycle)
		}
		if !retired {
			fixed = want
		}
		phase := "marker_exit"
		if retired {
			phase = "coordinate_exit"
		}
		publicationDisposalWindows(t, f.session, windows)
		publicationDisposalPhysical(t, f.session, phase, len(windows.Successes)+len(windows.Failures))
		if !evicted.IsZero() {
			if _, exists := f.session.mutationReceipts[evicted]; exists {
				t.Fatal("evicted historical lookup retained", cycle)
			}
		}
		if publicationDisposalCheckpoint(cycle) || cycle == count {
			// This is a real supplied selection on an unrelated entry. Its route
			// does not add a second publication target or a terminal receipt.
			progress := f.session.currentEntryInputs()
			progress[1].InputBytes = []byte{byte(cycle%255 + 2)}
			preserved := f.session.valueEntry(0)
			warnings := f.session.root.WarningBits
			configurationBefore := f.session.root.OutputConfiguration
			parent := admitSuppliedComparison(t, f.session, nil, progress)
			comparison, state := f.session.Compare(t.Context(), progress, parent)
			if comparison == nil || state.Outcome != ObservedCurrent {
				t.Fatal("unrelated supplied comparison", cycle, state)
			}
			candidate, state := f.session.Prepare(t.Context(), comparison, admit(t, f.session, comparison), f.trust)
			if candidate == nil || state.Outcome != ObservedCurrent {
				t.Fatal("unrelated supplied preparation", cycle, state)
			}
			if state = f.session.Select(t.Context(), candidate); state.Outcome != ObservedCurrent {
				t.Fatal("unrelated supplied selection", cycle, state)
			}
			afterProgress := reopen()
			if f.session.root.OutputConfiguration != configurationBefore || !reflect.DeepEqual(afterProgress, selected) {
				t.Fatal("unrelated supplied progress changed configuration/publication closure", cycle)
			}
			if !reflect.DeepEqual(f.session.valueEntry(0), preserved) || !bytes.Equal(f.session.valueEntry(1).ValueBytes, progress[1].InputBytes) || f.session.root.WarningBits != warnings {
				t.Fatal("unrelated supplied progress changed fixed entry/warnings", cycle)
			}
			publicationDisposalWindows(t, f.session, windows)
			publicationDisposalPhysical(t, f.session, phase, len(windows.Successes)+len(windows.Failures))
			files := f.store.fileBodies
			files.mu.Lock()
			historyBytes, historyObjects := files.used, files.next
			files.mu.Unlock()
			t.Logf("checkpoint cycle=%d duration=%s elapsed=%s explicit_cold_open_duration=%s explicit_cold_opens=%d rows=%d children=%d child_bytes=%d success=%d failure=%d history_bytes=%d history_objects=%d", cycle, time.Since(cycleStart), time.Since(setupEnd), coldDuration, coldOpens, f.session.root.RequiredSupportRecordCount, f.session.root.ChildCount, f.session.root.ChildEncodedBytes, len(windows.Successes), len(windows.Failures), historyBytes, historyObjects)
		}
	}
	wantIdentities := count * 7
	if retired {
		wantIdentities += count * 3
	}
	if len(seen) != wantIdentities {
		t.Fatal("actual cycle identity inventory", len(seen), wantIdentities)
	}
	if retired && len(seenSlots) != count {
		t.Fatal("distinct retired target count", len(seenSlots), count)
	}
	t.Logf("completed actual cycles=%d loop_duration=%s", count, time.Since(setupEnd))
}

func publicationDisposalCheckpoint(cycle int) bool {
	return slices.Contains([]int{1, 255, 256, 257, 1024, 1025, 4096, 4097}, cycle)
}

type publicationDisposalSize struct {
	rows, pages, children int
	support, index, bytes uint64
}

// These widths follow the fixed two-plain-entry recipe and schema framing.
// N is independently maintained receipt history, not a successor count.
// The two recipient records contain no former two-byte caller counts.
// Each receipt is 471 bytes plus its 37-byte support row frame.
func publicationDisposalSizes(phase string, n int) publicationDisposalSize {
	// B(n) is a four-byte length plus n bytes. Destination fields are
	// B(29), B(3), B(29), absent B(policy) and one capability byte.
	destination := 4 + 29 + 4 + 3 + 4 + 29 + 4 + 1
	// Target: entry ID, five B(fields), three flags, four u32 bounds,
	// and absent B(policy). Declaration includes one binding and no groups.
	target := 32 + 5*4 + 3 + 17 + 11 + 28 + 18 + 3 + 4*4 + 4
	declaration, routing := 4+15+32+destination+4+target+2, 6+65+4+11
	configuration := 75 + 37 + 78 + declaration + 4 + routing
	// Coordinate fixed fields648 include the variable-field length prefixes.
	// The retained six public fields add11+28+17+18+29+16 bytes.
	coordinate, markers := 75+37+648+3+11+11+28+17+18+29+16, 0
	// Marker includes the419-byte projection, two64-byte IDs,50-byte
	// evidence and exact birth service/target lengths3/17.
	markerBody := 2 + 5*32 + 8 + 4 + 419 + 2*32 + 2*(4+64) + 2 + 32 + 2 + 4 + 50 + 4 + 3 + 4 + 17
	markerPage := 75 + 37 + markerBody
	// Each coordinate group adds two mandatory exposure bytes; a marker
	// adds two more. A coordinate exit retains no groups.
	rows, index := 2, 1117+37*n
	switch phase {
	case "configured":
		coordinate = 774
	case "active_unknown":
		markers, rows, index = markerPage, 3, 1560+37*n
	case "retired_unknown":
		configuration, markers, rows, index = 206, markerPage, 3, 1560+37*n
	case "coordinate_exit":
		configuration, coordinate, rows, index = 206, 0, 1, 650+37*n
	}
	pages, support := rows, configuration+coordinate+markers
	if n == 0 {
		index -= 267
	} else {
		rows += n + 1
		pages += 2
		support += 75 + 508*n + 224 + 72*n
	}
	return publicationDisposalSize{rows: rows, pages: pages, children: pages + 3, support: uint64(support), index: uint64(index), bytes: uint64(1919 + support + index)}
}

func publicationDisposalPhysical(t *testing.T, s *StateSession, phase string, n int) {
	t.Helper()
	want := publicationDisposalSizes(phase, n)
	refs := make(map[format.Ref]bool)
	add := func(ref format.Ref) {
		t.Helper()
		if ref.Length == 0 || refs[ref] {
			t.Fatal("empty or duplicate child reference")
		}
		refs[ref] = true
	}
	for _, ref := range s.root.ValueEntryPages {
		if ref != nil {
			add(*ref)
		}
	}
	for _, ref := range s.root.Recipients {
		if ref != nil {
			add(*ref)
		}
	}
	for _, ref := range s.root.CurrentAccess.Core.AccessPageRefs {
		add(ref)
	}
	var support uint64
	for _, ref := range s.root.RequiredSupport {
		add(ref)
		support += uint64(ref.Length)
	}
	add(s.root.AdministrativeIndex)
	for _, ref := range s.root.AdministrativeIndexShards {
		add(ref)
	}
	var total uint64
	for ref := range refs {
		total += uint64(ref.Length)
	}
	if s.root.RequiredSupportRecordCount != uint32(want.rows) || len(s.root.RequiredSupport) != want.pages || support != want.support || s.root.AdministrativeIndex.Length != uint32(want.index) || len(s.root.AdministrativeIndexShards) != 0 || len(refs) != want.children || s.root.ChildCount != uint32(want.children) || total != want.bytes || s.root.ChildEncodedBytes != want.bytes {
		t.Fatalf("physical phase=%s receipts=%d rows=%d/%d support_pages=%d/%d support_bytes=%d/%d index_bytes=%d/%d children=%d/%d child_bytes=%d/%d root_bytes=%d", phase, n, s.root.RequiredSupportRecordCount, want.rows, len(s.root.RequiredSupport), want.pages, support, want.support, s.root.AdministrativeIndex.Length, want.index, len(refs), want.children, total, want.bytes, s.root.ChildEncodedBytes)
	}
	families := make(map[contract.SupportRecordKind]int)
	for _, page := range s.support {
		for _, row := range page.Records {
			families[row.Kind]++
		}
	}
	wantFamilies := map[contract.SupportRecordKind]int{contract.OutputConfigurationSliceSupportKind: 1}
	if phase != "coordinate_exit" {
		wantFamilies[contract.PublicationCoordinateSupportKind] = 1
	}
	if phase == "active_unknown" || phase == "retired_unknown" {
		wantFamilies[contract.PublicationMarkerSupportKind] = 1
	}
	if n > 0 {
		wantFamilies[contract.MutationReceiptSupportKind] = n
		wantFamilies[contract.GeneratedFragmentSupportKind] = 1
	}
	if !reflect.DeepEqual(families, wantFamilies) {
		t.Fatal("complete support family set", phase, families, wantFamilies)
	}
	g := s.root.Generated
	if g.Attempts != 0 || g.Duties != 0 || g.Hazards != 0 || g.Materials != 0 || g.Results != 0 || g.PendingReleases != 0 || g.GeneratedCurrent != 0 || g.Retiring != 0 || !g.ActiveOwner.IsZero() || g.LiveOwners.Count != 0 || g.Graphs.Count != 0 {
		t.Fatal("publication fixture retained generated work")
	}
}

func publicationDisposalHash(b []byte) contract.ID { return contract.ID(sha256.Sum256(b)) }
func publicationDisposalBlob(b, value []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(value)))
	return append(b, value...)
}
func publicationDisposalDescriptorBytes(b []byte, d contract.GeneratorDescriptor) []byte {
	b = append(b, d.Digest[:]...)
	b = binary.BigEndian.AppendUint64(b, d.Length)
	return binary.BigEndian.AppendUint32(b, d.Count)
}
func publicationDisposalGeneratorDescriptor(label string, body []byte, count int) contract.GeneratorDescriptor {
	preimage := publicationDisposalBlob([]byte("ENKV/GENERATOR/v1/"+label+"\x00"), body)
	return contract.GeneratorDescriptor{Digest: publicationDisposalHash(preimage), Length: uint64(len(body)), Count: uint32(count)}
}
func publicationDisposalAdminDescriptor(label string, items [][]byte) contract.GeneratorDescriptor {
	body := binary.BigEndian.AppendUint32(nil, uint32(len(items)))
	for _, item := range items {
		body = publicationDisposalBlob(body, item)
	}
	return contract.GeneratorDescriptor{Digest: publicationDisposalHash(append([]byte("ENKV/admin-descriptor/v1/"+label+"\x00"), body...)), Length: uint64(len(body)), Count: uint32(len(items))}
}

func publicationDisposalWindows(t *testing.T, s *StateSession, want contract.MutationReceiptWindows) {
	t.Helper()
	got, err := s.receiptWindows(t.Context())
	if err != nil || !slices.Equal(got.Successes, want.Successes) || !slices.Equal(got.Failures, want.Failures) || !slices.Equal(got.Order, want.Order) {
		t.Fatal("exact receipt windows/order", len(got.Successes), len(got.Failures), len(got.Order), len(want.Successes), len(want.Failures), len(want.Order), err)
	}
	indexBody := binary.BigEndian.AppendUint16(nil, 2)
	var descriptors [3]contract.GeneratorDescriptor
	for i, rows := range [][]contract.CompactMutationReceipt{want.Successes, want.Failures} {
		body := binary.BigEndian.AppendUint32(nil, uint32(len(rows)))
		for _, row := range rows {
			body = publicationDisposalBlob(body, row.OperationID[:])
		}
		label := "success-window"
		if i == 1 {
			label = "failure-window"
		}
		descriptors[i] = publicationDisposalGeneratorDescriptor(label, body, len(rows))
		indexBody = publicationDisposalBlob(indexBody, body)
	}
	order := binary.BigEndian.AppendUint32(nil, uint32(len(want.Order)))
	for _, id := range want.Order {
		order = publicationDisposalBlob(order, id[:])
	}
	descriptors[2] = publicationDisposalGeneratorDescriptor("receipt-order", order, len(want.Order))
	indexBody = publicationDisposalBlob(indexBody, order)
	if s.root.Generated.SuccessWindow != descriptors[0] || s.root.Generated.FailureWindow != descriptors[1] || s.root.Generated.ReceiptOrder != descriptors[2] {
		t.Fatal("independent receipt window descriptors")
	}
	n := len(want.Successes) + len(want.Failures)
	if n == 0 {
		return
	}
	body := append([]byte(nil), s.root.Domain[:]...)
	for _, descriptor := range descriptors {
		body = publicationDisposalDescriptorBytes(body, descriptor)
	}
	blob := publicationDisposalGeneratorDescriptor("receipt-index", body, 0).Digest
	fragmentBody := append([]byte(nil), blob[:]...)
	fragmentBody = binary.BigEndian.AppendUint16(fragmentBody, 0)
	fragmentID := publicationDisposalGeneratorDescriptor("fragment", fragmentBody, 0).Digest
	matched := 0
	for _, location := range s.root.Generated.Fragments {
		if location.BlobID != blob {
			continue
		}
		fact, exists := s.fragmentFacts[location]
		if !exists || location.FragmentIndex != 0 || location.RowSlot != 0 || fact.row.RecordID() != fragmentID || fact.count != 1 || fact.total != uint64(26+72*n) || fact.whole != publicationDisposalHash(indexBody) || fact.payloadLength != uint32(26+72*n) || fact.ref.Length != uint32(224+72*n) {
			t.Fatal("receipt index selected fragment identity/width")
		}
		called := false
		state, err := s.withSelectedFragment(t.Context(), location, func(payload []byte) error {
			called = true
			if !bytes.Equal(payload, indexBody) {
				return contract.ErrRecord
			}
			return nil
		})
		if state.Outcome != 0 || err != nil || !called {
			t.Fatal("exact independent receipt index payload", state, err)
		}
		matched++
	}
	if matched != 1 || len(s.root.Generated.Fragments) != 1 || len(s.mutationReceipts) != n {
		t.Fatal("complete receipt lookup/index set", matched, len(s.root.Generated.Fragments), len(s.mutationReceipts), n)
	}
}

func publicationDisposalExpectedExit(t *testing.T, before *StateSession, invocation, operation, revision, coordinate, attempt contract.ID, retired bool, windows contract.MutationReceiptWindows) (contract.EndWorkSubject, contract.CompactMutationReceipt) {
	t.Helper()
	n := len(windows.Successes) + len(windows.Failures)
	nextN := min(len(windows.Successes)+1, 256) + len(windows.Failures)
	predecessorPhase, successorPhase := "active_unknown", "marker_exit"
	group, kind := attempt, uint8(6)
	ended := []contract.ID{attempt}
	if retired {
		predecessorPhase, successorPhase, group, kind = "retired_unknown", "coordinate_exit", coordinate, 5
		ended = append(ended, coordinate)
	}
	slices.SortFunc(ended, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	endedItems := make([][]byte, len(ended))
	for i := range ended {
		endedItems[i] = ended[i][:]
	}
	var removed [][]byte
	for _, page := range before.adminIndex.Pages {
		row := 0
		for _, span := range page.Spans {
			for ordinal := int(span.First); ordinal < int(span.First)+int(span.Count); ordinal++ {
				summary := page.Rows[row]
				row++
				if summary.Kind == contract.OutputConfigurationSliceSupportKind {
					continue
				}
				item := append([]byte(nil), page.Ref.Digest[:]...)
				item = binary.BigEndian.AppendUint16(item, page.Ref.Index)
				item = binary.BigEndian.AppendUint16(item, uint16(ordinal))
				item = append(item, summary.Kind)
				item = append(item, summary.RecordID[:]...)
				item = binary.BigEndian.AppendUint32(item, summary.BodyLength)
				removed = append(removed, item)
			}
		}
	}
	wantRemoved := 2
	if n > 0 {
		wantRemoved = n + 3
	}
	if len(removed) != wantRemoved {
		t.Fatal("predecessor physical removal inventory", len(removed), wantRemoved)
	}
	oldSize, newSize := publicationDisposalSizes(predecessorPhase, n), publicationDisposalSizes(successorPhase, nextN)
	access := before.root.CurrentAccess
	q := contract.EndWorkSubject{Schema: contract.CanonicalSchema, DomainID: before.root.Domain, OperationID: operation, AdmissionID: invocation,
		PredecessorRevisionID: before.head.Core.Revision, PredecessorFullHEADDigest: publicationDisposalHash(before.body), PredecessorToken: before.token,
		TargetGroupID: group, TargetOwnerID: coordinate, TargetID: coordinate, TargetKind: kind, SelectedEvidenceSummary: 0x42,
		DependentGroups: publicationDisposalAdminDescriptor("ended-groups", endedItems), RemovedSupport: publicationDisposalAdminDescriptor("removed-selected-support", removed),
		PreservedCurrent: publicationDisposalPreserved(t, before), BeforeAccessRoot: access.AccessRoot, AfterAccessRoot: access.AccessRoot,
		BeforeAccessIncarnationID: access.Core.AccessIncarnationID, AfterAccessIncarnationID: access.Core.AccessIncarnationID,
		BeforeAccessGeneration: access.Core.AccessGeneration, AfterAccessGeneration: access.Core.AccessGeneration,
		BeforeWarningBits: before.root.WarningBits, AfterWarningBits: 0x1c,
		BeforeChildCount: uint16(oldSize.children), AfterChildCount: uint16(newSize.children), BeforeChildBytes: oldSize.bytes, AfterChildBytes: newSize.bytes}
	q.RequestCoreDigest = publicationDisposalCore(q)
	identity := append([]byte("ENKV/CRYPTO/v2/changed-subject-identity-v1\x00"), before.root.Domain[:]...)
	identity = append(identity, 9)
	identity = append(identity, group[:]...)
	identity = append(identity, coordinate[:]...)
	changedID := publicationDisposalHash(identity)
	changedBody := binary.BigEndian.AppendUint32(nil, 1)
	changedBody = binary.BigEndian.AppendUint32(changedBody, 34)
	changedBody = append(changedBody, 9, 2)
	changedBody = append(changedBody, changedID[:]...)
	r := contract.CompactMutationReceipt{Schema: contract.MutationReceiptSchema, OperationKind: contract.OperationEndSelectedWork, StateResult: 12, EvidenceCeiling: 1,
		DomainID: before.root.Domain, OperationID: operation,
		RequestIdentityDigest: q.RequestCoreDigest, PredecessorRevisionID: before.head.Core.Revision, RequestedRevisionID: revision, ObservedRevisionID: revision,
		CanonicalOutcome: 1, ChangedSubjects: publicationDisposalGeneratorDescriptor("changed-subjects", changedBody, 1), WarningBits: 0x1c,
		AdministrativeTargetKind: kind, AdministrativeTargetID: coordinate, AdministrativeDisposition: q.RequestCoreDigest, AdministrativeOriginalEvidence: 0x42, AdministrativeGroupID: group,
		AdministrativeWarningChanges: 0x1c &^ before.root.WarningBits, AdministrativePageDelta: int16(newSize.children - oldSize.children), AdministrativeByteDelta: int64(newSize.bytes) - int64(oldSize.bytes)}
	r.CompleteResult = publicationDisposalCompleteResult(r)
	return q, r
}

func publicationDisposalCore(q contract.EndWorkSubject) contract.ID {
	b := binary.BigEndian.AppendUint16([]byte("ENKV/K2-END-WORK/core/v6\x00"), q.Schema)
	for _, id := range []contract.ID{q.DomainID, q.OperationID, q.AdmissionID, q.PredecessorRevisionID, q.PredecessorFullHEADDigest} {
		b = append(b, id[:]...)
	}
	b = append(b, byte(q.PredecessorToken.Family))
	b = publicationDisposalBlob(b, []byte(q.PredecessorToken.Value))
	for _, id := range []contract.ID{q.TargetGroupID, q.TargetOwnerID, q.TargetID} {
		b = append(b, id[:]...)
	}
	b = append(b, q.TargetKind, q.DutyKind)
	b = binary.BigEndian.AppendUint16(b, q.SelectedEvidenceSummary)
	b = publicationDisposalDescriptorBytes(b, q.DependentGroups)
	b = publicationDisposalDescriptorBytes(b, q.RemovedSupport)
	b = append(b, q.PreservedCurrent.Digest[:]...)
	b = binary.BigEndian.AppendUint64(b, q.PreservedCurrent.Length)
	for _, id := range []contract.ID{q.BeforeAccessRoot, q.AfterAccessRoot, q.BeforeAccessIncarnationID, q.AfterAccessIncarnationID} {
		b = append(b, id[:]...)
	}
	b = binary.BigEndian.AppendUint64(b, q.BeforeAccessGeneration)
	b = binary.BigEndian.AppendUint64(b, q.AfterAccessGeneration)
	b = append(b, q.BeforeWarningBits, q.AfterWarningBits)
	b = binary.BigEndian.AppendUint16(b, q.BeforeChildCount)
	b = binary.BigEndian.AppendUint16(b, q.AfterChildCount)
	b = binary.BigEndian.AppendUint64(b, q.BeforeChildBytes)
	b = binary.BigEndian.AppendUint64(b, q.AfterChildBytes)
	return publicationDisposalHash(b)
}

func publicationDisposalCompleteResult(r contract.CompactMutationReceipt) contract.GeneratorDescriptor {
	b := binary.BigEndian.AppendUint32(nil, 1)
	b = binary.BigEndian.AppendUint32(b, 647)
	b = binary.BigEndian.AppendUint16(b, r.Schema)
	b = binary.BigEndian.AppendUint16(b, r.OperationKind)
	for _, id := range []contract.ID{r.DomainID, r.OperationID, r.RequestIdentityDigest, r.PredecessorRevisionID, r.RequestedRevisionID, r.ObservedRevisionID} {
		b = append(b, id[:]...)
	}
	for _, v := range []uint16{r.StateResult, r.EffectSummary, r.OutputSummary, r.EvidenceCeiling} {
		b = binary.BigEndian.AppendUint16(b, v)
	}
	b = append(b, r.CanonicalOutcome)
	b = publicationDisposalDescriptorBytes(b, r.ChangedSubjects)
	b = binary.BigEndian.AppendUint64(b, r.WarningBits)
	for _, v := range r.SummaryCounts {
		b = binary.BigEndian.AppendUint32(b, v)
	}
	for _, v := range []uint32{r.AcknowledgedCount, r.ConfirmedCount, r.UnknownCount} {
		b = binary.BigEndian.AppendUint32(b, v)
	}
	b = append(b, r.AdministrativeTargetKind)
	b = append(b, r.AdministrativeTargetID[:]...)
	b = append(b, r.AdministrativeDisposition[:]...)
	b = binary.BigEndian.AppendUint16(b, r.AdministrativeOriginalEvidence)
	b = append(b, r.AdministrativeWarningChanges)
	b = binary.BigEndian.AppendUint16(b, uint16(r.AdministrativePageDelta))
	b = binary.BigEndian.AppendUint64(b, uint64(r.AdministrativeByteDelta))
	for _, label := range []string{"changed-access", "effect-results", "output-results", "result-duties", "result-hazards"} {
		b = publicationDisposalDescriptorBytes(b, publicationDisposalGeneratorDescriptor(label, []byte{0, 0, 0, 0}, 0))
	}
	b = append(b, r.AdministrativeGroupID[:]...)
	return publicationDisposalGeneratorDescriptor("complete-result", b, 1)
}

// Project only the authenticated predecessor. Existing leaf encoders serialize
// its current records; no successor encoder or disposition rule is called.
func publicationDisposalPreserved(t *testing.T, s *StateSession) contract.DigestLength {
	t.Helper()
	access := s.root.CurrentAccess
	access.Core.AccessPageRefs = nil
	access.Core.AccessIncarnationID = publicationDisposalHash(append([]byte("ENKV/administrative-preserved-current/access-order/v1\x00"), s.root.Domain[:]...))
	access.Core.AccessGeneration = 1
	var err error
	access.Core.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(s.root.Domain, nil)
	if err != nil {
		t.Fatal("empty access descriptor", err)
	}
	access.AccessRoot, err = contract.AccessRoot(access.Core)
	if err != nil {
		t.Fatal("normalized access root", err)
	}
	accessBody, err := contract.EncodeCurrentAccessSection(access)
	if err != nil {
		t.Fatal("current access leaf", err)
	}
	b := binary.BigEndian.AppendUint16([]byte("ENKV/administrative-preserved-current/v1\x00"), 10)
	b = append(b, s.root.Domain[:]...)
	for _, page := range s.pages {
		if page == nil {
			b = append(b, 0)
			continue
		}
		b = append(b, 1)
		for _, entry := range page.Slots {
			if entry == nil {
				b = append(b, 0)
				continue
			}
			b = append(b, 1)
			encoded, err := contract.AppendValueEntry(nil, *entry)
			if err != nil {
				t.Fatal("current entry leaf", err)
			}
			b = publicationDisposalBlob(b, encoded)
		}
	}
	for _, ref := range s.root.Recipients {
		if ref == nil {
			b = append(b, 0)
			continue
		}
		b = append(b, 1)
		b, err = contract.AppendRef(b, *ref, format.Version)
		if err != nil {
			t.Fatal("current recipient leaf", err)
		}
	}
	b = publicationDisposalBlob(b, accessBody)
	if len(s.accessRecords()) != 0 {
		t.Fatal("plain fixture has access records")
	}
	b = binary.BigEndian.AppendUint32(b, 0)
	b = binary.BigEndian.AppendUint32(b, uint32(len(s.root.Names)))
	for _, named := range s.root.Names {
		b = binary.BigEndian.AppendUint16(b, named.Slot)
		b = binary.BigEndian.AppendUint16(b, uint16(len(named.Name)))
		b = append(b, named.Name...)
	}
	for _, value := range []uint32{s.root.ValueEntryCount, s.root.SecretCount} {
		b = binary.BigEndian.AppendUint32(b, value)
	}
	b = binary.BigEndian.AppendUint64(b, s.root.RawBytes)
	b = binary.BigEndian.AppendUint32(b, s.root.MembershipCount)
	b = binary.BigEndian.AppendUint32(b, s.root.SecretOrdinaryWrapCount)
	b = binary.BigEndian.AppendUint16(b, s.root.RecipientCount)
	return contract.DigestLength{Digest: publicationDisposalHash(b), Length: uint64(len(b))}
}

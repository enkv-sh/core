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

// The controlled response source supplies a bounded public request identity.
// An invalid delegated response remains invalid; this source cannot repair it.
type publicationPackedRequestOwner struct {
	*publicationControlledOwner
	request string
}

func (owner *publicationPackedRequestOwner) Send(ctx context.Context, id contract.ID) (contract.PublicationResult, contract.CryptoResultCode) {
	result, code := owner.publicationControlledOwner.Send(ctx, id)
	if code != contract.CryptoSuccess || contract.ValidatePublicationResult(owner.dispatch, result) != nil {
		return result, code
	}
	result.Evidence.SafeRequestID = owner.request
	return result, code
}

func publicationPackedPrivate(controlled *publicationControlledPrivate, requestLength int) publicationPrivate {
	private := controlled.callbacks()
	newOwner := private.NewOwner
	private.NewOwner = func(ctx context.Context, input publicationOwnerInput) (publicationPrivateOwner, error) {
		owner, err := newOwner(ctx, input)
		if err != nil || owner == nil {
			return owner, err
		}
		return &publicationPackedRequestOwner{publicationControlledOwner: owner.(*publicationControlledOwner), request: strings.Repeat("q", requestLength)}, nil
	}
	return private
}

func publicationPackedMutation(t *testing.T, env fixtureEnvironment, f *fixture, output *outputApplyInput, name, value string) {
	t.Helper()
	entries := f.session.currentEntryInputs()
	matched := false
	for i := range entries {
		if entries[i].Name == name {
			if entries[i].ValueSource != contract.Supplied || entries[i].ConfidentialityClass != contract.Plain {
				t.Fatal("packed publication source is not the selected plain entry")
			}
			entries[i].InputBytes = []byte(value)
			matched = true
		}
	}
	if !matched {
		t.Fatal("packed publication source entry is absent")
	}
	beforeCAS := f.store.cas
	parent := admitSuppliedOutputComparison(t, f.session, env.Custody, entries, output)
	comparison, state := f.session.compareWithOutput(t.Context(), entries, output, parent)
	if comparison == nil || state.Outcome != ObservedCurrent {
		t.Fatal("packed ordinary comparison", state)
	}
	candidate, state := f.session.Prepare(t.Context(), comparison, admit(t, f.session, comparison), env.Trust)
	if candidate == nil || state.Outcome != ObservedCurrent {
		t.Fatal("packed ordinary preparation", state)
	}
	selected, state := f.session.selectCandidate(t.Context(), candidate)
	if selected == nil || state.Outcome != ObservedCurrent || f.store.cas != beforeCAS+1 {
		t.Fatal("packed ordinary selection", state)
	}
	env.Custody.RetireApply()
	f.session = generatedLifecycleReopen(t, t.Context(), selected, env.Store)
	f.admission = OpenContext{admission: &f.session.admission}
}

func publicationPackedSend(t *testing.T, f *fixture, controlled *publicationControlledPrivate, name string, requestLength int, actions ...uint8) *publicationPlan {
	t.Helper()
	private := publicationPackedPrivate(controlled, requestLength)
	input := publicationInput{names: []string{name}, acting: f.session.admission.recipient, deadline: time.Now().Add(30 * time.Second)}
	entries, access, generated := f.session.currentEntryInputs(), f.session.root.CurrentAccess, f.session.root.Generated
	windows, err := f.session.receiptWindows(t.Context())
	if err != nil {
		t.Fatal("packed publication predecessor receipt windows", err)
	}
	beforeOwners, beforeCAS := len(controlled.owners), f.store.cas
	plan, state := f.session.planPublication(t.Context(), input, private)
	if plan == nil || state.Outcome != ObservedCurrent || len(plan.targets) != 1 || !slices.Equal(plan.targets[0].actions, actions) || len(plan.vector.Entries) != 1 || len(plan.vector.Entries[0].Actions) != len(actions) {
		t.Fatalf("packed publication fixed plan present=%t outcome=%d reason=%d expected_actions=%v", plan != nil, state.Outcome, state.Reason, actions)
	}
	if len(actions) == 2 {
		rewrite, err := f.session.planPublicationRewrite(t.Context(), f.session.adminIndex)
		if err != nil {
			t.Fatal("packed whole-invocation selected widths", err)
		}
		pages, err := publicationPageBound(uint64(len(rewrite.widths)+2), rewrite.framed+2*8192, max(rewrite.maximumWidth, uint64(8192)))
		if err != nil || pages != 3 {
			t.Fatal("packed whole-invocation three-page bound", err)
		}
		growth, err := format.PublicationIndexPlanningGrowth(2, 0, pages)
		if err != nil {
			t.Fatal("packed whole-invocation index growth", err)
		}
		beforeShards, beforeErr := format.AdministrativeIndexShardCount(rewrite.indexBytes)
		afterShards, afterErr := format.AdministrativeIndexShardCount(rewrite.indexBytes + growth)
		if beforeErr != nil || afterErr != nil || beforeShards != afterShards {
			t.Fatal("packed whole-invocation unexpectedly crosses an index shard")
		}
	}
	got := plan.execute(t.Context(), private, publicationEngineCurrent(f))
	if got.summary != contract.PublicationSummaryComplete || len(got.output.Entries) != 1 || len(got.output.Entries[0].Actions) != len(actions) || len(controlled.owners) != beforeOwners+len(actions) || f.store.cas != beforeCAS+2*len(actions) {
		t.Fatalf("packed publication result summary=%d owners=%d expected=%d CAS_delta=%d", got.summary, len(controlled.owners)-beforeOwners, len(actions), f.store.cas-beforeCAS)
	}
	selected := publicationEngineReopen(t, f)
	for i, action := range actions {
		row, owner := got.output.Entries[0].Actions[i], controlled.owners[beforeOwners+i]
		marker, present := selected.markers[row.AttemptID]
		if row.Action != action || row.Disposition != contract.PublicationOutcomeAcknowledged || !present || marker.State != contract.PublicationAcknowledged || marker.Projection != owner.dispatch.Projection || marker.ProjectionCommitment != owner.dispatch.ProjectionCommitment || marker.AuthoritySubjectDigest != owner.dispatch.AuthoritySubjectDigest || marker.Evidence.SafeRequestID != strings.Repeat("q", requestLength) || marker.Evidence.SafeResourceID != strings.Repeat("r", 1024) {
			t.Fatal("packed publication did not select the exact controlled ACK")
		}
		if owner.prepared != 1 || owner.armed != 1 || owner.sent != 1 || owner.retired != 1 {
			t.Fatalf("packed publication lifecycle prepared=%d armed=%d sent=%d retired=%d", owner.prepared, owner.armed, owner.sent, owner.retired)
		}
	}
	afterWindows, err := f.session.receiptWindows(t.Context())
	if err != nil || !reflect.DeepEqual(windows, afterWindows) || !reflect.DeepEqual(entries, f.session.currentEntryInputs()) || !reflect.DeepEqual(access, f.session.root.CurrentAccess) || !reflect.DeepEqual(generated, f.session.root.Generated) {
		t.Fatal("packed publication changed current entries, access, generated work or receipts", err)
	}
	return plan
}

// This prefix uses only the existing ordinary writer and publication engine.
// Its caller can supply an authentic generated-pressure predecessor later.
func publicationPackedHistory(t *testing.T, env fixtureEnvironment, before *StateSession, name string) (*fixture, *publicationControlledPrivate, *outputApplyInput) {
	t.Helper()
	f := &fixture{store: env.Store.(*memoryStore), trust: env.Trust.(*fixtureTrust), admission: OpenContext{admission: &before.admission}, session: before}
	beforeCAS := f.store.cas
	window, err := before.receiptWindows(t.Context())
	if err != nil {
		t.Fatal("packed history predecessor receipts", err)
	}
	entryCount := before.root.ValueEntryCount
	target := publicationEngineTarget(name, "publication")
	target.target.Policy = hermeticTextPolicy("controlled-policy", []string{"consumer-a"})
	target.target.Capabilities &^= contract.OutputCapabilityWriteSetsPolicy
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "publication", targets: []outputApplyTarget{target}}}, routes: []outputApplyRoute{{entryName: name, destinations: []string{"publication"}}}}
	before.admission.publicationNamespaces = append(slices.Clone(before.admission.publicationNamespaces), publicationNamespace{domain: before.root.Domain, service: "controlled-provider", physical: "publication", premise: fixtureID(before.root.Domain, "packed publication independent namespace")})
	publicationPackedMutation(t, env, f, output, name, "packed-value-0000")
	controlled := newPublicationControlledPrivate()

	controlled.configureOwner = func(owner *publicationControlledOwner) { owner.resource = strings.Repeat("r", 1024) }
	publicationPackedSend(t, f, controlled, name, 1024, contract.PublicationCreateWithValue)
	for i := 1; i <= 701; i++ {
		publicationPackedMutation(t, env, f, output, name, fmt.Sprintf("packed-value-%04d", i))
		requestLength := 1024
		if i >= 695 {
			requestLength = 0
		}
		publicationPackedSend(t, f, controlled, name, requestLength, contract.PublicationWriteValue)
	}
	if len(controlled.owners) != 702 || f.store.cas-beforeCAS != 2106 || f.session.root.ValueEntryCount != entryCount {
		t.Fatalf("packed history count owners=%d CAS_delta=%d entries=%d", len(controlled.owners), f.store.cas-beforeCAS, f.session.root.ValueEntryCount)
	}
	afterWindow, err := f.session.receiptWindows(t.Context())
	if err != nil || !reflect.DeepEqual(window, afterWindow) {
		t.Fatal("ordinary/publication prefix changed retained receipt windows", err)
	}
	return f, controlled, output
}

func publicationPackedRows(t *testing.T, s *StateSession, expectedMarkers int, expectedFramed uint64) map[contract.ID][]byte {
	t.Helper()
	selected, err := selectedPublicationRelation(s.selectedImage())
	if err != nil || len(selected.coordinates) != 1 || len(selected.markers) != expectedMarkers {
		t.Fatal("packed selected publication relation", err)
	}
	for _, coordinate := range selected.coordinates {
		if coordinate.BindingState != contract.PublicationBindingActive || coordinate.OwnerState != contract.PublicationOwnerQualified || coordinate.LastAdmissionOrdinal != uint64(expectedMarkers) || !coordinate.LatestUnresolvedAttemptID.IsZero() || coordinate.LastValueAckOrdinal != uint64(expectedMarkers) || coordinate.LastValueAckIncarnationID != coordinate.CurrentPublicationIncarnationID {
			t.Fatal("packed exact selected coordinate or terminal ACK stamps changed")
		}
	}
	_, loaded, err := s.publicationLoadedRowsForDisposition()
	if err != nil || len(loaded) != expectedMarkers+1 {
		t.Fatal("packed selected raw publication rows", err)
	}
	var framed uint64
	bodies := make(map[contract.ID][]byte, len(loaded))
	for key, row := range loaded {
		body, err := row.body()
		if err != nil {
			t.Fatal(err)
		}
		rowLength := 37 + len(body)
		if key.kind == contract.PublicationCoordinateSupportKind {
			// Coordinate/v5: 648 fixed bytes, 149 bytes of fixture strings/data,
			// and the 37-byte support-record frame.
			if rowLength != 834 {
				t.Fatalf("packed coordinate framing=%d expected=834", rowLength)
			}
		} else {
			marker := selected.markers[key.id]
			// Projection/v3 has 13 IDs and one action. Evidence/v3 has three
			// framed strings. Executor and route IDs each use 64 hex bytes.
			const projectionBytes = 2 + 13*32 + 1
			const evidenceFixed = 2 + 1 + 1 + 32 + 2 + 3*4
			const markerBase = 2 + 5*32 + 8 + 4 + projectionBytes + 2*32 + 2*(4+64) + 2 + 32 + 2 + 4 + evidenceFixed + 2*4 + 37
			wantLength := markerBase + len(marker.Evidence.SafeRequestID) + len(marker.Evidence.SafeResourceID)
			if marker.Projection.Action == contract.PublicationCreateWithValue {
				if marker.BirthServiceContractID != "controlled-provider" || marker.BirthTargetContractID != "fixture/target/v1" || marker.Evidence.ConsumerLocator != "publication?stage=AWSCURRENT" {
					t.Fatal("packed birth changed its exact contracts or consumer locator")
				}
				wantLength += 19 + 17 + 28
			} else if marker.BirthServiceContractID != "" || marker.BirthTargetContractID != "" || marker.Evidence.ConsumerLocator != "" {
				t.Fatal("packed nonbirth ACK retained birth fields")
			}
			if rowLength != wantLength {
				t.Fatalf("packed marker framing=%d expected=%d", rowLength, wantLength)
			}
		}
		framed += uint64(rowLength)
		bodies[key.id] = bytes.Clone(body)
	}
	if framed != expectedFramed {
		t.Fatalf("packed selected framing=%d expected=%d", framed, expectedFramed)
	}
	var publicationPages, mandatoryPages, optionalPages, mandatoryRows, optionalRows int
	for _, page := range s.adminIndex.Pages {
		var hasPublication bool
		for _, row := range page.Rows {
			hasPublication = hasPublication || row.Kind == contract.PublicationCoordinateSupportKind || row.Kind == contract.PublicationMarkerSupportKind
		}
		if !hasPublication {
			continue
		}
		publicationPages++
		mandatory := page.Spans[0].Mandatory
		if mandatory {
			mandatoryPages++
		} else {
			optionalPages++
		}
		for _, span := range page.Spans {
			if span.Mandatory != mandatory {
				t.Fatal("packed page mixed mandatory and optional publication rows")
			}
		}
		physicalLength := uint64(75)
		for _, row := range page.Rows {
			body, err := loaded[generatedRecordKey{row.Kind, row.RecordID}].body()
			if err != nil {
				t.Fatal(err)
			}
			physicalLength += uint64(37 + len(body))
			if uint32(len(body)) != row.BodyLength {
				t.Fatal("packed selected summary changed its actual row length")
			}
			if row.Kind != contract.PublicationCoordinateSupportKind && row.Kind != contract.PublicationMarkerSupportKind {
				t.Fatal("packed publication page retained a nonpublication peer")
			}
			wantMandatory := row.Kind == contract.PublicationCoordinateSupportKind
			if row.Kind == contract.PublicationMarkerSupportKind {
				marker := selected.markers[row.RecordID]
				wantMandatory = selected.coordinates[marker.CoordinateID].OwnedBirthAttemptID == marker.AttemptID
			}
			if mandatory != wantMandatory {
				t.Fatal("packed birth/coordinate ownership classification changed")
			}
			if mandatory {
				mandatoryRows++
			} else {
				optionalRows++
			}
		}
		if physicalLength != uint64(page.Ref.Length) {
			t.Fatal("packed physical page framing differs from its real selected rows")
		}
	}
	if publicationPages != 2 || mandatoryPages != 1 || optionalPages != 1 || mandatoryRows != 2 || optionalRows != expectedMarkers-1 {
		t.Fatalf("packed publication pages=%d mandatory=%d optional=%d mandatory_rows=%d optional_rows=%d", publicationPages, mandatoryPages, optionalPages, mandatoryRows, optionalRows)
	}
	return bodies
}

// full_only: true
func TestPublicationPackedActionReserveBoundary(t *testing.T) {
	env := memoryScenarioEnvironmentMode(t, false)
	env.Context = t.Context()
	initial := newEnvironmentFixture(t, t.Context(), env, []int{1}, false)
	initial.admission = capacityFixtureAdmission(t, initial.admission)
	initial.session.admission = *initial.admission.admission
	initialWindows, err := initial.session.receiptWindows(t.Context())
	if err != nil || initialWindows.DomainID != env.Domain || len(initialWindows.Successes) != 1 ||
		initialWindows.Successes[0].OperationKind != contract.OperationInitializeDomain || len(initialWindows.Failures) != 0 ||
		!slices.Equal(initialWindows.Order, []contract.ID{initialWindows.Successes[0].OperationID}) {
		t.Fatal("packed plain seed lacks its exact initialization history", err)
	}
	beforePublic, beforePrivate := env.Custody.Calls()
	store := env.Store.(*memoryStore)
	if err := store.useFileBodies(filepath.Join(t.TempDir(), "packed-publication-bodies")); err != nil {
		t.Fatal("packed publication file-backed history", err)
	}
	f, commonOwners, _ := publicationPackedHistory(t, env, initial.session, "member-000")
	// Independent schema arithmetic: coordinate834; birth3040;
	// 694 maximal write ACKs2976 each; seven write ACKs1952 each.
	commonRows := publicationPackedRows(t, f.session, 702, 2_082_882)
	commonEntries := f.session.currentEntryInputs()
	if len(commonEntries) != 1 || commonEntries[0].Name != "member-000" || commonEntries[0].ValueSource != contract.Supplied || commonEntries[0].ConfidentialityClass != contract.Plain || !bytes.Equal(commonEntries[0].InputBytes, []byte("packed-value-0701")) || f.session.root.Generated.GeneratedCurrent != 0 {
		t.Fatal("packed common prefix changed its exact current plain entry")
	}
	if len(f.session.adminIndex.Groups) != 703 || len(commonOwners.owners) != 702 {
		t.Fatal("packed common prefix did not select every real owner group")
	}
	var branchIndexLength uint64
	for _, requestLength := range []int{340, 341} {
		t.Run(fmt.Sprintf("request-%d", requestLength), func(t *testing.T) {
			branchStore := selectedMemoryStoreCopy(store)
			branchEnv := env
			branchEnv.Store = branchStore
			current, state := Open(t.Context(), OpenContext{admission: &f.session.admission}, branchStore)
			if current == nil || state.Outcome != ObservedCurrent {
				t.Fatal("packed independent branch Open", state)
			}
			branch := &fixture{store: branchStore, trust: f.trust, admission: OpenContext{admission: &current.admission}, session: current}
			private := newPublicationControlledPrivate()

			private.configureOwner = func(owner *publicationControlledOwner) { owner.resource = strings.Repeat("r", 1024) }
			target := publicationEngineTarget("member-000", "publication")
			target.target.Policy = hermeticTextPolicy("controlled-policy", []string{"consumer-a"})
			target.target.Capabilities &^= contract.OutputCapabilityWriteSetsPolicy
			output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "publication", targets: []outputApplyTarget{target}}}, routes: []outputApplyRoute{{entryName: "member-000", destinations: []string{"publication"}}}}
			publicationPackedMutation(t, branchEnv, branch, output, "member-000", "packed-value-0702")
			publicationPackedSend(t, branch, private, "member-000", 0, contract.PublicationWriteValue)
			publicationPackedMutation(t, branchEnv, branch, output, "member-000", "packed-value-0703")
			publicationPackedSend(t, branch, private, "member-000", requestLength, contract.PublicationWriteValue)
			framed := uint64(2_082_882 + 2*1952 + requestLength)
			rows := publicationPackedRows(t, branch.session, 704, framed)
			commonSelected, err := selectedPublicationRelation(f.session.selectedImage())
			if err != nil {
				t.Fatal("packed common marker identity map", err)
			}
			for id, original := range commonRows {
				if _, marker := commonSelected.markers[id]; marker && !bytes.Equal(original, rows[id]) {
					t.Fatal("packed adjacent branch changed an old marker body")
				}
			}
			if len(branch.session.adminIndex.Groups) != 705 {
				t.Fatal("packed adjacent branch group count")
			}
			indexLength, err := format.AdministrativeIndexEncodedLength(branch.session.adminIndex)
			if err != nil {
				t.Fatal("packed adjacent branch index length", err)
			}
			if branchIndexLength == 0 {
				branchIndexLength = indexLength
			} else if indexLength != branchIndexLength {
				t.Fatal("one public request byte changed index framing")
			}
			// One real canonical change forces exactly the separate policy and value actions.
			output.bindings[0].targets[0].target.Policy = hermeticTextPolicy("controlled-policy", []string{"consumer-b"})
			output.bindings[0].destination.Policy = hermeticTextPolicy("controlled-policy", []string{"consumer-b"})
			publicationPackedMutation(t, branchEnv, branch, output, "member-000", "packed-value-final")
			policy, state := branch.session.currentOutputConfigurationForApply(t.Context())
			if state.Outcome != 0 || len(policy.Bindings) != 1 || !bytes.Equal(policy.Bindings[0].Targets[0].Policy.Data, []byte(`["consumer-b"]`)) {
				t.Fatal("packed current policy did not select the changed request", state)
			}
			var bounds []uint32
			private.onSend = func() {
				observed, state := Open(t.Context(), branch.admission, branchStore)
				if observed == nil || state.Outcome != ObservedCurrent {
					t.Fatal("packed selected reservation Open", state)
				}
				rewrite, err := observed.planPublicationRewrite(t.Context(), observed.adminIndex)
				if err != nil {
					t.Fatal("packed actual reservation rewrite", err)
				}
				capacity, err := rewrite.capacity()
				if err != nil {
					t.Fatal("packed actual reservation capacity", err)
				}
				bounds = append(bounds, capacity.pages)
				// The unresolved marker reserves all three 1024-byte evidence
				// strings. The second action retains the first selected ACK.
				expectedFramed := framed + 928 + 3*1024
				if len(bounds) == 2 {
					expectedFramed += 1952
				}
				if rewrite.framed != expectedFramed || rewrite.maximumWidth != 4000 {
					t.Fatalf("packed reservation framing=%d expected=%d maximum_width=%d", rewrite.framed, expectedFramed, rewrite.maximumWidth)
				}
				if len(bounds) == 2 {
					selected, err := selectedPublicationRelation(observed.selectedImage())
					first := private.owners[2].dispatch.AttemptID
					if err != nil || selected.markers[first].State != contract.PublicationAcknowledged {
						t.Fatal("packed second reservation preceded the first selected ACK", err)
					}
				}
			}
			plan := publicationPackedSend(t, branch, private, "member-000", 0, contract.PublicationUpdatePolicy, contract.PublicationWriteValue)
			wantBounds := []uint32{2, 2}
			// The two-page endpoint is 2097077-4000+1 = 2093078.
			// The second reservation lands exactly there, then one byte over.
			if requestLength == 341 {
				wantBounds[1] = 3
			}
			if !slices.Equal(bounds, wantBounds) || len(private.owners) != 4 || branchStore.cas != 11 {
				t.Fatalf("packed adjacent actions bounds=%v expected=%v owners=%d CAS=%d", bounds, wantBounds, len(private.owners), branchStore.cas)
			}
			if plan.vector.Entries[0].CoordinateID != private.owners[2].dispatch.CoordinateID || private.owners[2].dispatch.CoordinateID != private.owners[3].dispatch.CoordinateID {
				t.Fatal("packed two-action plan changed its single coordinate")
			}
			publicationPackedRows(t, branch.session, 706, framed+2*1952)
			if len(branch.session.adminIndex.Groups) != 707 {
				t.Fatal("packed final group count")
			}
		})
	}
	public, private := env.Custody.Calls()
	if public != beforePublic || private != beforePrivate {
		t.Fatal("plain publication boundary added a public or private KMS use")
	}
	store.fileBodies.mu.Lock()
	bodyBytes, bodyFiles := store.fileBodies.used, store.fileBodies.next
	store.fileBodies.mu.Unlock()
	t.Logf("packed actual controlled sends=710 ordinary_selections=708 successful_CAS=2128 selected_markers_per_branch=706 shared_immutable_file_bytes=%d shared_immutable_files=%d", bodyBytes, bodyFiles)
}

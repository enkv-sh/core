package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	catalog "enkv.sh/core/internal/testcatalog"
	"enkv.sh/crypto/testsupport/custody"
)

func publicationFixturePolicyData(subjects []uint64) []byte {
	values := make([]string, len(subjects))
	for i, subject := range subjects {
		values[i] = strconv.FormatUint(subject, 10)
	}
	return []byte(strings.Join(values, ","))
}

func publicationScenarioCoordinate(domain contract.ID, slot string) contract.ID {
	return publicationExpectedCoordinate(domain, "test-output/service/v1", slot)
}
func publicationScenarioOrderedSlot(t testing.TB, domain contract.ID, prefix string, otherSlots []string, later bool) string {
	t.Helper()
	for i := 0; i < 1024; i++ {
		slot := fmt.Sprintf("%s%d", prefix, i)
		id := publicationScenarioCoordinate(domain, slot)
		matched := true
		for _, otherSlot := range otherSlots {
			other := publicationScenarioCoordinate(domain, otherSlot)
			if (bytes.Compare(id[:], other[:]) > 0) != later {
				matched = false
				break
			}
		}
		if matched {
			return slot
		}
	}
	t.Fatal("cannot select fixed fault coordinate order")
	return ""
}

func publicationScenarioCommitment(t testing.TB, plan *publicationPlan, target publicationTargetPlan, action uint8) (contract.ID, contract.ID) {
	t.Helper()
	expectedPolicy := contract.OutputPolicy{ContractID: "test-policy", Data: []byte("1,9")}
	if action == contract.PublicationUpdatePolicy {
		expectedPolicy.Data = []byte("1")
	}
	if action < contract.PublicationDeleteOwned && !reflect.DeepEqual(target.target.Policy, expectedPolicy) {
		t.Fatal("publication planned policy differs from complete selected policy")
	}
	if target.target.ServiceContractID != "test-output/service/v1" || target.target.ConsumerLocator != target.target.CanonicalTarget || target.target.TargetContractID != "test-output/target/v1" || !bytes.Equal(target.target.TargetData, []byte("target:"+target.target.CanonicalTarget)) || target.target.PayloadEncoding != contract.OutputEncodingRaw {
		t.Fatal("publication changed fixed target meaning")
	}
	expectedTarget := contract.OutputTarget{EntryIncarnationID: target.target.EntryIncarnationID, ServiceContractID: "test-output/service/v1", TargetContractID: "test-output/target/v1", CanonicalTarget: target.target.CanonicalTarget, ConsumerLocator: target.target.CanonicalTarget, TargetData: []byte("target:" + target.target.CanonicalTarget), PayloadEncoding: contract.OutputEncodingRaw, Capabilities: contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot | contract.OutputCapabilityCreateSetsPolicy | contract.OutputCapabilityWriteSetsPolicy, CreateValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, Policy: expectedPolicy}
	_, commitment, response := publicationExpectedProjection(t, plan, target, action, expectedTarget, target.retained.OwnedBirthAttemptID, target.retained.DeletionTargetRowDigest)
	return commitment, response
}

// full_only: false
func TestPublicationPreviewRetainsUnroutedCoordinatesWithoutActions(t *testing.T) {
	for _, condition := range []string{"entry-override", "explicit-empty"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f := newFixture(t, 1, false, 1)
			entries := f.session.currentEntryInputs()
			authority := f.session.root.CurrentAccess.Core.AuthorityRecipientID
			other := fixtureID(f.session.root.Domain, "reader")
			if f.session.recipientRecord(other) == nil || other == authority {
				t.Fatal("independent recipient fixture unavailable")
			}
			entries[0].Recipients = []contract.ID{authority, other}
			slices.SortFunc(entries[0].Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			output := &outputApplyInput{bindings: []outputApplyBinding{
				{destinationID: "authority", targets: []outputApplyTarget{publicationEngineTarget(entries[0].Name, "authority-slot")}},
				{destinationID: "other", targets: []outputApplyTarget{publicationEngineTarget(entries[0].Name, "other-slot")}},
			}, routes: []outputApplyRoute{{entryName: entries[0].Name, destinations: []string{"authority", "other"}}}}
			selectOutputConfiguration(t, f, entries, output)
			output.routes[0].destinations = []string{"authority"}
			if condition == "explicit-empty" {
				output.routes[0].destinations = []string{}
			}
			selectOutputConfiguration(t, f, entries, output)

			validator := NewPublicConfigurationValidator(f.session.admission.outputInterpreter)
			actual, failed := projectSelectedPublicConfiguration(ctx, f.session.selectedImage(), f.session.selectedObjectReader(), f.store.StoreConfiguration(), authority, validator)
			if failed.Outcome != 0 || !actual.Valid || !actual.Complete {
				t.Fatal("authenticated routed configuration unavailable", failed, actual.Diagnostics)
			}
			selected := publicSelection{complete: true, image: *f.session.selectedImage(), authorityID: authority,
				basis: publicReadBasis{reader: f.session.selectedObjectReader()}}
			facts, failed := readPublicationPreviewFacts(ctx, &selected)
			if failed.Outcome != 0 || len(facts.coordinates) != len(output.bindings) || len(facts.markers) != 0 {
				t.Fatal("active never-sent routed coordinates unavailable", failed)
			}
			for _, coordinate := range facts.coordinates {
				if coordinate.OwnerState != contract.PublicationOwnerNone {
					t.Fatal("route fixture unexpectedly owns a remote object")
				}
			}
			creates, cas, signs := f.store.creates, f.store.cas, f.trust.signs
			reader := ReaderEngine{validator: validator}
			preview, _, failed := reader.projectPublicationPreview(ctx, &selected, actual, actual)
			want := 0
			if condition == "entry-override" {
				want = 1
			}
			if failed.Outcome != 0 || !preview.Complete || preview.ReasonCode != 0 || len(preview.Entries) != want {
				t.Fatal("non-Authority target became a write or retained-deletion preview", preview, failed)
			}
			if want == 1 && (preview.Entries[0].DestinationID == nil || *preview.Entries[0].DestinationID != "authority" || preview.Entries[0].PhysicalTarget != "authority-slot" || !slices.Equal(preview.Entries[0].Actions, []uint8{contract.PublicationCreateWithValue})) {
				t.Fatal("Authority route changed its exact action or coordinate", preview.Entries)
			}
			if f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs {
				t.Fatal("passive publication preview entered mutation authority")
			}
		})
	}
}

// full_only: false
func TestCapturedPublicationPreservesEarlierAcknowledgementAcrossCurrentChanges(t *testing.T) {
	for _, condition := range []string{"unrelated-binding", "selected-value", "selected-target", "selected-group"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f := newFixture(t, 2, false, 1)
			entries := f.session.currentEntryInputs()
			output := &outputApplyInput{bindings: []outputApplyBinding{
				{destinationID: "publication-a", targets: []outputApplyTarget{publicationEngineTarget(entries[0].Name, "first-slot")}},
				{destinationID: "publication-b", targets: []outputApplyTarget{publicationEngineTarget(entries[1].Name, "second-slot")}},
			}, routes: []outputApplyRoute{
				{entryName: entries[0].Name, destinations: []string{"publication-a"}},
				{entryName: entries[1].Name, destinations: []string{"publication-b"}},
			}}
			selectOutputConfiguration(t, f, entries, output)
			f.admission.admission.publicationNamespaces = []publicationNamespace{
				{domain: f.session.root.Domain, service: "controlled-provider", physical: "first-slot", premise: fixtureID(f.session.root.Domain, "first exclusive namespace")},
				{domain: f.session.root.Domain, service: "controlled-provider", physical: "second-slot", premise: fixtureID(f.session.root.Domain, "second exclusive namespace")},
			}
			f.session.admission.publicationNamespaces = f.admission.admission.publicationNamespaces
			handoff, err := captureApplyPublicationSelection(ctx, f.session)
			if err != nil {
				t.Fatal("capture complete selected publication", err)
			}
			defer handoff.close()
			private := newPublicationControlledPrivate()
			callbacks := private.callbacks()
			input := publicationInput{names: handoff.names(), acting: handoff.acting, deadline: time.Now().Add(30 * time.Second), captured: handoff}
			plan, state := f.session.planPublication(ctx, input, callbacks)
			if plan == nil || len(plan.targets) != 2 || len(plan.targets[0].actions) != 1 || len(plan.targets[1].actions) != 1 {
				t.Fatal("two fixed one-action targets unavailable", state)
			}
			later := plan.targets[1]
			calls, changed := 0, false
			got := plan.execute(ctx, callbacks, func(ctx context.Context) (*StateSession, contract.Trust, Result) {
				current, state := Open(ctx, f.admission, f.store)
				if current == nil {
					t.Fatal("fresh current publication unavailable", state)
				}
				calls++
				if changed || len(private.owners) != 1 || private.owners[0].sent != 1 || private.owners[0].retired != 1 {
					return current, f.trust, state
				}
				facts, err := selectedPublicationRelation(current.selectedImage())
				first, present := facts.markers[plan.targets[0].attempts[0]]
				if err != nil || !present || first.State != contract.PublicationAcknowledged {
					t.Fatalf("first action was not acknowledged and settled before progress: reads=%d owners=%d sent=%d retired=%d marker_present=%t marker_state=%d relation_failed=%t", calls, len(private.owners), private.owners[0].sent, private.owners[0].retired, present, first.State, err != nil)
				}
				f.session = current
				before := current.root.OutputConfiguration.ConfigurationDigest
				switch condition {
				case "unrelated-binding":
					output.bindings = append(output.bindings, outputApplyBinding{destinationID: "unrelated", destination: outputFixtureDestination("unrelated", "controlled-provider", output.bindings[0].targets[0].target.Capabilities, output.bindings[0].targets[0].target.Policy)})
				case "selected-value":
					for i := range entries {
						if entries[i].Name == later.selection.Entry.Name {
							entries[i].InputBytes = []byte("different selected value")
						}
					}
				case "selected-target":
					for i := range output.bindings {
						if output.bindings[i].destinationID == later.destination {
							output.bindings[i].targets[0].target.TargetData = []byte("different selected target")
						}
					}
				case "selected-group":
					output.groups = [][]string{{entries[0].Name, entries[1].Name}}
				}
				if condition == "selected-value" {
					parent := admitSuppliedComparison(t, f.session, nil, entries)
					comparison, state := f.session.Compare(ctx, entries, parent)
					if comparison == nil || state.Outcome != ObservedCurrent {
						t.Fatalf("plain value progress comparison refused: outcome=%d reason=%d", state.Outcome, state.Reason)
					}
					candidate, state := f.session.Prepare(ctx, comparison, admit(t, f.session, comparison), f.trust)
					if candidate == nil || state.Outcome != ObservedCurrent {
						t.Fatalf("plain value progress preparation refused: outcome=%d reason=%d", state.Outcome, state.Reason)
					}
					if state = f.session.Select(ctx, candidate); state.Outcome != ObservedCurrent {
						t.Fatalf("plain value progress selection refused: outcome=%d reason=%d", state.Outcome, state.Reason)
					}
					admission := OpenContext{admission: &f.session.admission}
					f.session, state = Open(ctx, admission, f.store)
					if f.session == nil || state.Outcome != ObservedCurrent {
						t.Fatalf("plain value progress cold open refused: outcome=%d reason=%d", state.Outcome, state.Reason)
					}
					f.admission = OpenContext{admission: &f.session.admission}
					entry := selectedPlanningEntry(f.session.selectedImage(), later.selection.Entry.Name)
					_, state = handoff.checkCurrent(ctx, f.session, later)
					if entry == nil || !bytes.Equal(entry.ValueBytes, []byte("different selected value")) || before != f.session.root.OutputConfiguration.ConfigurationDigest || state.Outcome != AdmissionRefused || state.Reason != DifferentSelection {
						t.Fatalf("authenticated plain progress did not establish the fixed-value conflict: entry_present=%t same_output=%t outcome=%d reason=%d", entry != nil, before == f.session.root.OutputConfiguration.ConfigurationDigest, state.Outcome, state.Reason)
					}
				} else {
					selectOutputConfiguration(t, f, entries, output)
				}
				if condition != "selected-value" && before == f.session.root.OutputConfiguration.ConfigurationDigest {
					t.Fatal("configuration progress fixture did not change")
				}
				changed = true
				return f.session, f.trust, f.session.observed(ObservedCurrent)
			})
			if !changed || len(got.output.Entries) != 2 || len(got.output.Entries[0].Actions) != 1 || len(got.output.Entries[1].Actions) != 1 {
				t.Fatalf("current-state interleaving did not reach the second action: changed=%t reads=%d owners=%d target_rows=%d outcome=%d reason=%d summary=%d", changed, calls, len(private.owners), len(got.output.Entries), got.state.Outcome, got.state.Reason, got.summary)
			}
			first, second := got.output.Entries[0].Actions[0], got.output.Entries[1].Actions[0]
			if first.Disposition != contract.PublicationOutcomeAcknowledged || first.AttemptID != plan.targets[0].attempts[0] || first.Evidence.Class != contract.PublicationRequestAcknowledged {
				t.Error("later current-state progress erased the first acknowledgement", first)
			}
			wantOwners := 1
			if condition == "unrelated-binding" {
				wantOwners = 2
				if got.state.Outcome != ObservedCurrent || got.summary != contract.PublicationSummaryComplete || second.Disposition != contract.PublicationOutcomeAcknowledged || second.AttemptID != later.attempts[0] {
					t.Error("unrelated progress prevented the fixed second action", got.state, got.summary, second)
				}
			} else if got.state.Outcome != AdmissionRefused || got.state.Reason != DifferentSelection || got.summary != contract.PublicationSummaryMixedTerminal || second.Disposition != contract.PublicationNotSent || second.CoreReason != uint16(DifferentSelection) {
				t.Error("relevant conflict changed prior evidence or adopted current content", got.state, got.summary, second)
			}
			if len(private.owners) != wantOwners {
				t.Fatal("publication acquired an unexpected effect owner", len(private.owners), wantOwners)
			}
			for _, owner := range private.owners {
				if owner.prepared != 1 || owner.armed != 1 || owner.sent != 1 || owner.retired != 1 {
					t.Error("publication did not consume and settle its exact owner once")
				}
			}
		})
	}
}

type publicationScenario struct {
	run                                *scenarioRun
	fixture                            *environmentFixture
	entries                            []ApplyEntryInput
	slots                              []string
	input                              publicationInput
	private                            publicationPrivate
	staging                            string
	callsStarted, callsReturned, sends atomic.Int64
	owners, retired                    atomic.Int64
}

// full_only: false
func TestPublicationLateBirthRetainsColdCleanup(t *testing.T) {
	for _, rollover := range []bool{false, true} {
		name := "same-incarnation"
		if rollover {
			name = "rollover"
		}
		t.Run(name, func(t *testing.T) { publicationLateBirthColdCleanup(t, rollover) })
	}
}

func publicationLateBirthColdCleanup(t *testing.T, rollover bool) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f, input, private := publicationEngineFixture(t)
	if rollover {
		publicationSeedLastAdmission(t, f, ^uint64(0)-1)
	}
	callbacks := private.callbacks()
	reopen := func() selectedPublication {
		t.Helper()
		var result Result
		f.session, result = Open(ctx, f.admission, f.store)
		if f.session == nil {
			t.Fatal("cold publication selection", result)
		}
		selected, err := selectedPublicationRelation(f.session.selectedImage())
		if err != nil {
			t.Fatal("cold publication relation", err)
		}
		return selected
	}
	planFor := func(request publicationInput) *publicationPlan {
		t.Helper()
		plan, result := f.session.planPublication(ctx, request, callbacks)
		if plan == nil || len(plan.targets) != 1 || len(plan.targets[0].actions) != 1 {
			t.Fatal("one exact publication action", result)
		}
		return plan
	}
	selectCandidate := func(candidate *Candidate) {
		t.Helper()
		persisted, result := f.session.persistCandidate(ctx, candidate, f.trust)
		if persisted == nil {
			t.Fatal("persist publication transition", result)
		}
		selected, result := f.session.selectCandidate(ctx, persisted)
		if selected == nil {
			t.Fatal("select publication transition", result)
		}
		f.session = selected
	}
	reserve := func(plan *publicationPlan) *publicationPreparation {
		t.Helper()
		target := plan.targets[0]
		candidate, preparation, result := plan.reserveCandidate(ctx, f.session, target, target.actions[0], callbacks)
		if candidate == nil {
			t.Fatal("reserve exact publication action", result)
		}
		selectCandidate(candidate)
		if !preparation.armed {
			t.Fatal("selected reservation has no original send permission")
		}
		t.Cleanup(func() {
			if !preparation.retired {
				if err := preparation.retire(ctx); err != nil {
					t.Error("retire retained publication owner", err)
				}
			}
		})
		return preparation
	}
	acknowledge := func(plan *publicationPlan, preparation *publicationPreparation) {
		t.Helper()
		result, code := preparation.send(ctx)
		if code != contract.CryptoSuccess || result.Evidence.Class != contract.PublicationRequestAcknowledged {
			t.Fatal("controlled provider acknowledgement", code, result.Evidence.Class)
		}
		candidate, state := plan.closeCandidate(ctx, f.session, preparation, result)
		if candidate == nil {
			t.Fatal("close acknowledged action", state)
		}
		selectCandidate(candidate)
		if err := preparation.retire(ctx); err != nil {
			t.Fatal("join acknowledged owner", err)
		}
	}
	firstPlan := planFor(input)
	first := reserve(firstPlan)
	coordinateID := first.original.marker.CoordinateID
	input.republish = map[contract.ID][]contract.ID{coordinateID: {first.original.marker.AttemptID}}
	secondPlan := planFor(input)
	second := reserve(secondPlan)
	if rollover && first.original.marker.PublicationIncarnationID == second.original.marker.PublicationIncarnationID {
		t.Fatal("second reservation did not enter a fresh publication incarnation")
	}
	acknowledge(firstPlan, first)
	selectOutputConfiguration(t, f, f.session.currentEntryInputs(), &outputApplyInput{})
	deletionInput := publicationInput{deletes: []contract.ID{coordinateID}, acting: input.acting, deadline: input.deadline, republish: map[contract.ID][]contract.ID{coordinateID: {second.original.marker.AttemptID}}}
	deleteFirstPlan := planFor(deletionInput)
	deleteFirst := reserve(deleteFirstPlan)
	if deleteFirst.original.marker.Projection.OwnedBirthAttemptID != first.original.marker.AttemptID {
		t.Fatal("first deletion did not bind the first birth")
	}
	acknowledge(deleteFirstPlan, deleteFirst)
	acknowledge(secondPlan, second)
	selected := reopen()
	coordinate := selected.coordinates[coordinateID]
	if coordinate.OwnedBirthAttemptID != second.original.marker.AttemptID || coordinate.LastDeleteAckAttemptID != deleteFirst.original.marker.AttemptID || selected.markers[first.original.marker.AttemptID].State != contract.PublicationAcknowledged || selected.markers[deleteFirst.original.marker.AttemptID].State != contract.PublicationAcknowledged {
		t.Fatal("late birth lost exact ownership or historical evidence")
	}
	warnings := f.session.root.WarningBits
	handoff, err := captureApplyPublicationSelection(ctx, f.session)
	if err != nil || handoff == nil {
		t.Fatal("capture cold combined selection", err)
	}
	if len(handoff.deletions) != 1 || handoff.deletions[0].coordinate.CoordinateID != coordinateID || handoff.deletions[0].marker.AttemptID != second.original.marker.AttemptID {
		t.Error("unrelated acknowledged deletion suppressed cold combined cleanup")
	}
	handoff.close()
	deletionInput.republish = nil
	deleteSecondPlan := planFor(deletionInput)
	deleteSecond := reserve(deleteSecondPlan)
	wantBirth := second.original.marker.AttemptID
	planned := deleteSecondPlan.vector.Entries[0].Actions[0]
	marker := deleteSecond.original.marker
	if marker.Projection.Action != contract.PublicationDeleteOwned || planned.ProjectionCommitment != marker.ProjectionCommitment ||
		marker.Projection.OwnedBirthAttemptID != wantBirth || deleteSecond.original.reserve.OwnedBirthAttemptID != wantBirth ||
		deleteSecond.original.dispatch.Projection != marker.Projection {
		t.Fatal("planned delete, reservation and dispatch did not retain the same birth")
	}
	acknowledge(deleteSecondPlan, deleteSecond)
	selected = reopen()
	closed := selected.markers[marker.AttemptID]
	if selected.coordinates[coordinateID].LastDeleteAckAttemptID != marker.AttemptID || closed.State != contract.PublicationAcknowledged ||
		closed.Projection != marker.Projection || f.session.root.WarningBits != warnings || len(selected.markers) != 4 {
		t.Fatal("exact second deletion changed history or warnings")
	}
	handoff, err = captureApplyPublicationSelection(ctx, f.session)
	if err != nil || handoff == nil || len(handoff.deletions) != 0 {
		t.Fatal("exact second deletion did not suppress its own cleanup", err)
	}
	handoff.close()
	for _, owner := range private.owners {
		if owner.prepared != 1 || owner.armed != 1 || owner.sent != 1 || owner.retired != 1 {
			t.Fatal("publication owner did not consume and settle once")
		}
	}
}

// Seed the finite counter boundary in an independently signed selected fixture;
// all reservations, acknowledgements and cold reads after it use real writers.
func publicationSeedLastAdmission(t *testing.T, f *fixture, ordinal uint64) {
	t.Helper()
	s := f.session
	for i, ref := range s.root.RequiredSupport {
		key, err := format.Key(f.store.desc.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		read := f.store.Read(t.Context(), key, ref.Length)
		if read.Status != contract.ReadOK {
			t.Fatal("read counter-boundary fixture support")
		}
		s.support[i], err = format.InspectRequiredSupportPage(read.Body)
		if err != nil {
			t.Fatal(err)
		}
		for j, row := range s.support[i].Records {
			if row.Kind != contract.PublicationCoordinateSupportKind {
				continue
			}
			coordinate, err := contract.InspectPublicationCoordinate(row.Body)
			if err != nil || coordinate.LastAdmissionOrdinal != 0 {
				t.Fatal("counter fixture must precede first publication", err)
			}
			coordinate.LastAdmissionOrdinal = ordinal
			s.support[i].Records[j].Body, err = contract.EncodePublicationCoordinate(coordinate)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	generatedRefreshSupport(t, s)
	publicationStoreSelectedFixture(t, f)
}

func publicationStoreSelectedFixture(t *testing.T, f *fixture) {
	t.Helper()
	s := f.session
	for _, page := range s.support {
		rows := make([]contract.SupportRecord, len(page.Records))
		for i, row := range page.Records {
			rows[i] = contract.SupportRecord(row)
		}
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: rows})
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal(err)
		}
		f.store.put(mustKey(t, f.store.desc.Prefix, ref), body)
	}
	indexes, err := format.EncodeAdministrativeIndexPages(s.adminIndex)
	if err != nil {
		t.Fatal(err)
	}
	for _, page := range indexes {
		f.store.put(mustKey(t, f.store.desc.Prefix, page.Ref), page.Body)
	}
	body, err := format.EncodeRoot(s.root)
	if err != nil {
		t.Fatal(err)
	}
	root, err := format.Reference(format.RootKind, s.root.Domain, s.root.Snapshot, 0, body)
	if err != nil {
		t.Fatal(err)
	}
	f.store.put(mustKey(t, f.store.desc.Prefix, root), body)
	s.head.Core.Root = root
	if !s.indexSelectedMaterials() || s.head.AuthKind != format.LifecycleAuth {
		t.Fatal("signed publication fixture lost normal selected state")
	}
	head := s.head
	head.Subject.Normal.PublicState = s.publicState()
	head.Subject.Request = requestCommitment(head.Core, head.Subject)
	core, err := format.EncodeHeadCore(head.Core)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := format.EncodeConditionalPlan(conditional(head.Core, core))
	if err != nil {
		t.Fatal(err)
	}
	head.Subject.HeadCore, head.Subject.HeadCoreLength, head.Subject.ConditionalPlan = contract.Hash(core), uint32(len(core)), contract.Hash(plan)
	request, err := contract.NewLifecycleRequest(head.Subject)
	head.AuthorizationSignature = currentBasisSign(t, f.trust, request, err)
	body, err = format.EncodeHead(head)
	if err != nil {
		t.Fatal(err)
	}
	f.store.put(f.store.desc.HeadKey, body)
	f.session, _ = Open(t.Context(), f.admission, f.store)
	if f.session == nil {
		t.Fatal("independently signed publication fixture did not cold-open")
	}
}

// full_only: false
func TestPublicationMissingDeletionEvidenceStaysUnavailable(t *testing.T) {
	for _, condition := range []string{"compacted-delete", "contradictory-present-delete"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f, input, private := publicationEngineFixture(t)
			callbacks := private.callbacks()
			current := func(ctx context.Context) (*StateSession, contract.Trust, Result) {
				s, result := Open(ctx, f.admission, f.store)
				return s, f.trust, result
			}
			open := func() {
				t.Helper()
				var result Result
				f.session, result = Open(ctx, f.admission, f.store)
				if f.session == nil {
					t.Fatal("cold publication fixture", result)
				}
			}
			plan, result := f.session.planPublication(ctx, input, callbacks)
			if plan == nil {
				t.Fatal("initial creation plan", result)
			}
			created := plan.execute(ctx, callbacks, current)
			if created.summary != contract.PublicationSummaryComplete || len(created.output.Entries) != 1 {
				t.Fatal("initial acknowledged birth", created.state)
			}
			coordinateID := created.output.Entries[0].CoordinateID
			open()
			selectOutputConfiguration(t, f, f.session.currentEntryInputs(), &outputApplyInput{})
			input.names, input.deletes = nil, []contract.ID{coordinateID}
			plan, result = f.session.planPublication(ctx, input, callbacks)
			if plan == nil {
				t.Fatal("owned deletion plan", result)
			}
			deleted := plan.execute(ctx, callbacks, current)
			if deleted.summary != contract.PublicationSummaryComplete || len(deleted.output.Entries) != 1 || len(deleted.output.Entries[0].Actions) != 1 || deleted.output.Entries[0].Actions[0].Action != contract.PublicationDeleteOwned {
				t.Fatal("exact acknowledged deletion", deleted.state)
			}
			deleteAttempt := deleted.output.Entries[0].Actions[0].AttemptID
			open()
			if condition == "compacted-delete" {
				before, err := selectedPublicationRelation(f.session.selectedImage())
				if err != nil {
					t.Fatal(err)
				}
				warnings := f.session.root.WarningBits
				admin, result := openAdministrative(ctx, f.admission, f.store)
				if admin == nil {
					t.Fatal("acknowledged deletion administrative admission", result)
				}
				candidate, result := prepareTestEndSelectedWork(t, admin, ctx, deleteAttempt, f.trust)
				if candidate == nil {
					t.Fatal("acknowledged deletion exact end-work preparation", result)
				}
				if selected, result := admin.selectCandidate(ctx, candidate); selected == nil {
					t.Fatal("acknowledged deletion end-work selection", result)
				}
				open()
				after, err := selectedPublicationRelation(f.session.selectedImage())
				if err != nil || !after.coordinates[coordinateID].Equal(before.coordinates[coordinateID]) || f.session.root.WarningBits&warnings != warnings || f.session.root.WarningBits&(WarningPublicationOrderValue|WarningDiscardedExactEvidence) != WarningPublicationOrderValue|WarningDiscardedExactEvidence {
					t.Fatal("supported compaction changed birth/deletion summary or lost permanent warnings", err)
				}
			} else {
				candidate := prepare(t, f, changed(t, f.session, 0))
				if result := f.session.Select(ctx, candidate); result.Outcome != ObservedCurrent {
					t.Fatal("normal fixture predecessor", result)
				}
				open()
				generatedMaterializeFixtureSupport(t, f.session)
				found := false
				for i := range f.session.support {
					for j, row := range f.session.support[i].Records {
						if row.Kind != contract.PublicationMarkerSupportKind || row.RecordID != deleteAttempt {
							continue
						}
						found = true
						marker, err := contract.InspectPublicationMarker(row.Body)
						if err != nil {
							t.Fatal(err)
						}
						marker.Projection.TargetRowDigest = publicationRelationID(88)
						marker.ProjectionCommitment, err = contract.PublicationProjectionCommitment(marker.Projection)
						if err != nil {
							t.Fatal(err)
						}
						row.Body, err = contract.EncodePublicationMarker(marker)
						if err != nil {
							t.Fatal(err)
						}
						f.session.support[i].Records[j] = row
					}
				}
				if !found {
					t.Fatal("fixture lacks acknowledged delete marker")
				}
				generatedRefreshSupport(t, f.session)
				publicationStoreSelectedFixture(t, f)
			}
			selected, err := selectedPublicationRelation(f.session.selectedImage())
			if err != nil || selected.coordinates[coordinateID].LastDeleteAckAttemptID != deleteAttempt || selected.coordinates[coordinateID].OwnerState != contract.PublicationOwnerQualified {
				t.Fatal("fixture lost authenticated birth/deletion summary", err)
			}
			_, present := selected.markers[deleteAttempt]
			if present != (condition == "contradictory-present-delete") {
				t.Fatal("fixture did not isolate missing versus contradictory evidence")
			}
			want := refused(InvalidIntent)
			if condition == "compacted-delete" {
				want = failure(EvidenceUnavailable, ReadUnavailable)
			}
			checks, owners := private.checks, len(private.owners)
			creates, cas, signs := f.store.creates, f.store.cas, f.trust.signs
			plan, result = f.session.planPublication(ctx, input, callbacks)
			if plan != nil || result.Outcome != want.Outcome || result.Reason != want.Reason {
				t.Error("standalone planning confused missing evidence with a present contradiction", result)
			}
			basis := f.session.admission.publicBasis()
			control, err := basis.ControlCore(f.session.root.Domain, f.store.Descriptor())
			if err != nil {
				t.Fatal(err)
			}
			engine, err := NewInstalledPublication(PublicationInstallation{ExpectedDomain: f.session.root.Domain, ExpectedStore: f.store.Descriptor(), PublicBasis: basis, ExpectedControl: control, Store: f.store, Trust: f.trust, CompositionID: f.session.admission.composition, CloseInstalled: func() {},
				SelectPolicyAction: func(context.Context, PublicationPolicyActionInput) (uint8, error) {
					t.Error("unavailable publication requested policy selection")
					return 0, contract.ErrRecord
				},
				Namespace: func(contract.ID, contract.OutputTarget) (contract.ID, error) {
					t.Error("unavailable publication requested a namespace")
					return contract.ID{}, contract.ErrRecord
				},
				Actions: func(context.Context, PublicationExecutionInput) (PublicationActionFacts, error) {
					t.Error("unavailable publication requested execution facts")
					return PublicationActionFacts{}, contract.ErrRecord
				},
				Check: func(context.Context, PublicationActionCheckInput) (PublicationActionCheckFacts, error) {
					t.Error("unavailable publication requested an action check")
					return PublicationActionCheckFacts{}, contract.ErrRecord
				},
				NewOwner: func(context.Context, PublicationOwnerInput) (PublicationPrivateOwner, error) {
					t.Error("unavailable publication constructed an owner")
					return nil, contract.ErrRecord
				},
			})
			if err != nil {
				t.Fatal("installed publication admission", err)
			}
			defer engine.Close()
			requestID := publicationRelationID(89)
			out := engine.Publish(ctx, requestID, PublicationRequest{DeleteCoordinates: []contract.ID{coordinateID}})
			if out.RequestID != requestID || out.DomainID != f.session.root.Domain || out.Result.Outcome != want.Outcome || out.Result.Reason != want.Reason || out.Output != nil || out.Summary != 0 || !out.OperationID.IsZero() || !out.RequestIdentity.IsZero() {
				t.Error("public publication result lost the exact unavailable/refusal classification", out)
			}
			if private.checks != checks || len(private.owners) != owners || f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs {
				t.Fatal("missing or contradictory evidence acquired work or changed selected state")
			}
		})
	}
}

func newPublicationScenario(t testing.TB, ctx context.Context, env fixtureEnvironment, condition string) *publicationScenario {
	r := newScenarioRun(t, ctx, env)
	p := &publicationScenario{run: r}
	r.phase("setup", func() {
		p.fixture = newEnvironmentFixture(t, r.ctx, r.env, []int{1}, false)
		p.entries = []ApplyEntryInput{{Name: "plain", Recipients: []contract.ID{p.fixture.admission.admission.recipient}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, InputBytes: []byte("private data")}, suppliedSecret(t, r.env, "secret", "publication source", custody.StandardValue)}
		if condition == "unauthorized-later-member" {
			p.entries[0].Recipients = append(p.entries[0].Recipients, fixtureID(env.Domain, "reader"))
			slices.SortFunc(p.entries[0].Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		}
		p.slots = []string{"plain-target", "secret-target"}
		switch condition {
		case "ack-then-unknown", "unknown-then-ack":
			p.slots = []string{"plain-target-a", "secret-target-a", "plain-target-b", "secret-target-b"}
			p.slots[0] = publicationScenarioOrderedSlot(t, env.Domain, "plain-target-unknown-", p.slots[1:], condition == "ack-then-unknown")
		case "unqualified-create":
			p.slots[0] = "plain-target-unqualified-0"
		case "cleanup-failure":
			p.slots[0] = publicationScenarioOrderedSlot(t, env.Domain, "plain-target-cleanup-failure-", p.slots[1:], true)
		case "cancel-child":
			p.slots[0] = publicationScenarioOrderedSlot(t, env.Domain, "plain-target-sleep-", p.slots[1:], false)
		}
		for _, slot := range p.slots {
			p.fixture.admission.admission.publicationNamespaces = append(p.fixture.admission.admission.publicationNamespaces, publicationNamespace{domain: env.Domain, service: "test-output/service/v1", physical: slot, premise: fixtureID(env.Domain, "independent namespace "+slot)})
		}
		p.fixture.session.admission.publicationNamespaces = p.fixture.admission.admission.publicationNamespaces
		p.selectEntries(p.entries, p.output([]uint64{1, 9}))
		config := installedPublicationTestConfig(t)
		p.staging = os.TempDir()
		for _, binding := range p.output([]uint64{1, 9}).bindings {
			if err := env.Custody.InstallPublication(ctx, config, binding.destinationID, publicationTestConfigContract); err != nil {
				t.Fatal("install selected child", err)
			}
		}
		p.private = p.observePrivate(publicationCustodyPrivate(env.Custody))
		p.input = publicationInput{names: []string{"plain", "secret"}, acting: p.fixture.admission.admission.recipient, deadline: time.Now().Add(30 * time.Second)}
		if condition == "unauthorized-later-member" {
			p.input.acting = fixtureID(env.Domain, "reader")
		}
	})
	return p
}
func (p *publicationScenario) output(subjects []uint64) *outputApplyInput {
	targets := make([]outputApplyTarget, len(p.slots))
	for i, slot := range p.slots {
		entry := p.entries[i%2]
		targets[i] = outputApplyTarget{entryName: entry.Name, target: contract.OutputTarget{ServiceContractID: "test-output/service/v1", TargetContractID: "test-output/target/v1", CanonicalTarget: slot, ConsumerLocator: slot, TargetData: []byte("target:" + slot), PayloadEncoding: contract.OutputEncodingRaw, Capabilities: contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot | contract.OutputCapabilityCreateSetsPolicy | contract.OutputCapabilityWriteSetsPolicy, CreateValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, Policy: contract.OutputPolicy{ContractID: "test-policy", Data: publicationFixturePolicyData(slices.Clone(subjects))}}}
	}
	if len(targets) == 4 {
		return &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "publication-a", targets: targets[:2]}, {destinationID: "publication-b", targets: targets[2:]}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"publication-a", "publication-b"}}}}
	}
	return &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "publication", targets: targets}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"publication"}}}}
}
func (p *publicationScenario) reopen() *StateSession {
	p.run.t.Helper()
	p.fixture.session = p.run.open(p.fixture.admission)
	return p.fixture.session
}
func (p *publicationScenario) selectEntries(entries []ApplyEntryInput, output *outputApplyInput) {
	t := p.run.t
	t.Helper()
	s := p.fixture.session
	parent := admitSuppliedOutputComparison(t, s, p.run.env.Custody, entries, output)
	c, result := s.compareWithOutput(p.run.ctx, entries, output, parent)
	if c == nil || result.Outcome != ObservedCurrent {
		t.Fatal("publication selected comparison", result)
	}
	candidate, result := s.Prepare(p.run.ctx, c, admit(t, s, c), p.run.env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("publication selected preparation", result)
	}
	p.run.env.Custody.RetireApply()
	if result = s.Select(p.run.ctx, candidate); result.Outcome != ObservedCurrent {
		t.Fatal("publication selected transition", result)
	}
	p.fixture.admission = OpenContext{admission: &s.admission}
	p.reopen()
}
func (p *publicationScenario) current(ctx context.Context) (*StateSession, contract.Trust, Result) {
	s, result := Open(ctx, p.fixture.admission, p.run.env.Store)
	return s, p.run.env.Trust, result
}
func (p *publicationScenario) plan() *publicationPlan {
	p.run.t.Helper()
	p.input.deadline = time.Now().Add(30 * time.Second)
	plan, result := p.fixture.session.planPublication(p.run.ctx, p.input, p.private)
	if plan == nil || result.Outcome != ObservedCurrent {
		p.run.t.Fatal("publication scenario plan", result)
	}
	return plan
}
func publicationScenarioTargets(domain contract.ID, slots []string, targets []publicationTargetPlan) ([]publicationTargetPlan, error) {
	refused := errors.New("publication target inventory differs")
	if len(targets) != len(slots) {
		return nil, refused
	}
	ordered := slices.Clone(slots)
	slices.SortFunc(ordered, func(a, b string) int {
		left, right := publicationScenarioCoordinate(domain, a), publicationScenarioCoordinate(domain, b)
		return bytes.Compare(left[:], right[:])
	})
	for i, slot := range ordered {
		if slot == "" || i > 0 && slot == ordered[i-1] || targets[i].target.CanonicalTarget != slot || targets[i].coordinate != publicationScenarioCoordinate(domain, slot) {
			return nil, refused
		}
	}
	return targets, nil
}

// full_only: false
func TestPublicationScenarioOracleRequiresCompleteTargetSet(t *testing.T) {
	domain := contract.Hash([]byte("publication scenario target membership"))
	slots := []string{"plain-target", "secret-target"}
	targets := make([]publicationTargetPlan, len(slots))
	for i, slot := range slots {
		targets[i] = publicationTargetPlan{coordinate: publicationScenarioCoordinate(domain, slot), target: contract.OutputTarget{CanonicalTarget: slot}}
	}
	slices.SortFunc(targets, func(a, b publicationTargetPlan) int { return bytes.Compare(a.coordinate[:], b.coordinate[:]) })
	if _, err := publicationScenarioTargets(domain, slots, targets); err != nil {
		t.Fatal("complete requested target set refused")
	}
	t.Run("omitted_noop_target", func(t *testing.T) {
		if _, err := publicationScenarioTargets(domain, slots, targets[:1]); err == nil {
			t.Fatal("oracle accepted an omitted requested no-op target")
		}
	})
	for _, name := range []string{"extra", "duplicate", "wrong_slot", "wrong_coordinate", "reordered"} {
		t.Run(name, func(t *testing.T) {
			changed := slices.Clone(targets)
			switch name {
			case "extra":
				changed = append(changed, targets[0])
			case "duplicate":
				changed[1] = changed[0]
			case "wrong_slot":
				changed[0].target.CanonicalTarget = "different-target"
			case "wrong_coordinate":
				changed[0].coordinate = contract.Hash([]byte("different coordinate"))
			case "reordered":
				changed[0], changed[1] = changed[1], changed[0]
			}
			if _, err := publicationScenarioTargets(domain, slots, changed); err == nil {
				t.Fatal("oracle accepted a changed requested target set")
			}
		})
	}
	if _, err := publicationScenarioTargets(domain, []string{slots[0], slots[0]}, []publicationTargetPlan{targets[0], targets[0]}); err == nil {
		t.Fatal("oracle accepted duplicate requested slots")
	}
}

func (p *publicationScenario) expected(plan *publicationPlan, action uint8, unknownSlot string, closedUnknown bool) contract.PublicationOutcomeVector {
	t := p.run.t
	t.Helper()
	targets, err := publicationScenarioTargets(p.run.env.Domain, p.slots, plan.targets)
	if err != nil {
		t.Fatal("publication plan differs from requested target set", err)
	}
	v := contract.PublicationOutcomeVector{Schema: 2, DomainID: p.run.env.Domain, OperationID: plan.operation, SnapshotID: plan.session.root.Snapshot, SelectionDigest: sha256.Sum256(plan.session.body)}
	for _, target := range targets {
		row := contract.PublicationOutcome{Disposition: contract.PublicationNoOp}
		if action != 0 {
			if len(target.attempts) != 1 || len(target.actions) != 1 || target.actions[0] != action {
				t.Fatal("unexpected selected action chain", target.actions)
			}
			commitment, response := publicationScenarioCommitment(t, plan, target, action)
			resource := "test-instance/" + target.target.CanonicalTarget + "/" + hex.EncodeToString(target.retained.OwnedBirthAttemptID[:])
			status := uint16(204)
			if action == contract.PublicationCreateWithValue {
				resource = "test-instance/" + target.target.CanonicalTarget + "/" + hex.EncodeToString(target.attempts[0][:])
				status = 201
			}
			row = contract.PublicationOutcome{Action: action, ProjectionCommitment: commitment, AttemptID: target.attempts[0], Disposition: contract.PublicationOutcomeAcknowledged, RemoteValueMayRemain: 1, Evidence: contract.PublicationEvidence{Schema: 3, Entry: contract.PublicationMayHaveEnteredEntry, Class: contract.PublicationRequestAcknowledged, ResponseContractDigest: response, NormalizedStatus: status, SafeResourceID: resource}}
			if action == contract.PublicationCreateWithValue {
				row.Evidence.ConsumerLocator = target.target.ConsumerLocator
			}
			if target.target.CanonicalTarget == unknownSlot {
				row.Disposition = contract.PublicationOutcomeUnknown
				if closedUnknown {
					row.LateWriteRisk = 1
				}
				row.Evidence.Class = contract.PublicationUnproved
				row.Evidence.NormalizedStatus = 0
				row.Evidence.SafeResourceID = ""
				row.Evidence.ConsumerLocator = ""
			}
		}
		v.Entries = append(v.Entries, contract.PublicationTargetOutcome{CoordinateID: publicationScenarioCoordinate(v.DomainID, target.target.CanonicalTarget), Actions: []contract.PublicationOutcome{row}})
	}
	slices.SortFunc(v.Entries, func(a, b contract.PublicationTargetOutcome) int {
		return bytes.Compare(a.CoordinateID[:], b.CoordinateID[:])
	})
	return v
}
func assertPublicationScenarioVector(t testing.TB, got publicationOperationResult, want contract.PublicationOutcomeVector, summary uint8) {
	t.Helper()
	if got.summary != summary || !reflect.DeepEqual(got.output, want) {
		for i, entry := range got.output.Entries {
			for _, a := range entry.Actions {
				t.Logf("result[%d] coordinate=%x action=%d disposition=%d attempt=%x reason=%d entry=%d class=%d status=%d residue=%d risk=%d blockers=%d", i, entry.CoordinateID, a.Action, a.Disposition, a.AttemptID, a.CoreReason, a.Evidence.Entry, a.Evidence.Class, a.Evidence.NormalizedStatus, a.RemoteValueMayRemain, a.LateWriteRisk, len(a.BlockerIDs))
			}
		}
		t.Fatalf("publication vector mismatch summary=%d expected=%d equal=%t", got.summary, summary, reflect.DeepEqual(got.output, want))
	}
}
func (p *publicationScenario) execute(action uint8, unknownSlot string, summary uint8) publicationOperationResult {
	plan := p.plan()
	want := p.expected(plan, action, unknownSlot, true)
	got := plan.execute(p.run.ctx, p.private, p.current)
	assertPublicationScenarioVector(p.run.t, got, want, summary)
	p.reopen()
	return got
}

// The real custody and native host calls are synchronous and join their owned
// work before return. Count those returns without replacing the worker's
// telemetry context: its diagnostic recorder can drop records by contract.
func (p *publicationScenario) observePrivate(private publicationPrivate) publicationPrivate {
	check, newOwner := private.Check, private.NewOwner
	private.Check = func(ctx context.Context, in publicationActionCheckInput) (publicationActionCheckFacts, error) {
		p.callsStarted.Add(1)
		facts, err := check(ctx, in)
		p.callsReturned.Add(1)
		return facts, err
	}
	private.NewOwner = func(ctx context.Context, in publicationOwnerInput) (publicationPrivateOwner, error) {
		owner, err := newOwner(ctx, in)
		if err != nil || owner == nil {
			return owner, err
		}
		p.owners.Add(1)
		return &publicationScenarioOwner{publicationPrivateOwner: owner, scenario: p}, nil
	}
	return private
}

type publicationScenarioOwner struct {
	publicationPrivateOwner
	scenario *publicationScenario
	retired  sync.Once
}

func (owner *publicationScenarioOwner) Send(ctx context.Context, id contract.ID) (contract.PublicationResult, contract.CryptoResultCode) {
	p := owner.scenario
	p.callsStarted.Add(1)
	p.sends.Add(1)
	result, code := owner.publicationPrivateOwner.Send(ctx, id)
	p.callsReturned.Add(1)
	return result, code
}
func (owner *publicationScenarioOwner) Retire(ctx context.Context) error {
	err := owner.publicationPrivateOwner.Retire(ctx)
	owner.retired.Do(func() { owner.scenario.retired.Add(1) })
	return err
}
func (p *publicationScenario) assertJoins(sends int, cleanupFailed bool) {
	t := p.run.t
	t.Helper()
	files, err := os.ReadDir(p.staging)
	started, returned, sent := p.callsStarted.Load(), p.callsReturned.Load(), p.sends.Load()
	owners, retired := p.owners.Load(), p.retired.Load()
	if sent != int64(sends) || started != returned || owners != retired || started == 0 && sends != 0 || err != nil || !cleanupFailed && len(files) != 0 {
		t.Fatalf("publication native lifetime sends=%d expected=%d calls_started=%d calls_returned=%d owners=%d retired=%d staging=%d read_error=%v", sent, sends, started, returned, owners, retired, len(files), err)
	}
	t.Logf("publication native lifetime: sends=%d completed_calls=%d retired_owners=%d retained_staging=%d cleanup_failure=%t", sent, returned, retired, len(files), cleanupFailed)
	p.callsStarted.Store(0)
	p.callsReturned.Store(0)
	p.sends.Store(0)
	p.owners.Store(0)
	p.retired.Store(0)
}
func (p *publicationScenario) verify() {
	p.run.phase("verification", func() {
		p.reopen()
		selected, err := selectedPublicationRelation(p.fixture.session.selectedImage())
		if err != nil || len(selected.coordinates) != len(p.slots) {
			p.run.t.Fatal("complete publication state", err)
		}
		config, result := p.fixture.session.currentOutputConfigurationForApply(p.run.ctx)
		if result.Outcome != 0 {
			p.run.t.Fatal("selected output retained", result)
		}
		if len(config.Bindings) > len(p.slots)/2 {
			p.run.t.Fatal("logical group split")
		}
	})
	p.run.phase("reopen", func() {
		if p.run.env.FreshCurrent == nil {
			p.run.t.Fatal("publication scenario requires fresh child")
		}
		p.run.env.FreshCurrent(p.run.t, p.fixture.admission, p.fixture.session)
	})
}
func (p *publicationScenario) zeroPrivate() publicationPrivate {
	t := p.run.t
	t.Helper()
	return publicationPrivate{Actions: func(context.Context, publicationExecutionInput) (publicationActionFacts, error) {
		t.Error("zero-work Actions")
		return publicationActionFacts{}, contract.ErrRecord
	}, Check: func(context.Context, publicationActionCheckInput) (publicationActionCheckFacts, error) {
		t.Error("zero-work Check")
		return publicationActionCheckFacts{}, contract.ErrRecord
	}, NewOwner: func(context.Context, publicationOwnerInput) (publicationPrivateOwner, error) {
		t.Error("zero-work NewOwner")
		return nil, contract.ErrRecord
	}}
}
func runPublicationScenario(t testing.TB, ctx context.Context, env fixtureEnvironment, name string) {
	t.Helper()
	row, known := catalog.Publication(name)
	if !known {
		t.Fatal("unknown publication case", name)
	}
	condition := row.Condition
	p := newPublicationScenario(t, ctx, env, condition)
	p.run.phase("transition", func() {
		switch condition {
		case "unauthorized-later-member":
			// Normal Authority admits an acting reader that is absent from the later secret member.
			p.private = p.zeroPrivate()
			before := p.run.spy.scenarioEffects
			if plan, result := p.fixture.session.planPublication(p.run.ctx, p.input, p.private); plan != nil || result != refused(AdmissionInvalid) {
				t.Fatal("later group member admitted", result)
			}
			if p.run.spy.StoreCreate != before.StoreCreate || p.run.spy.StoreCAS != before.StoreCAS || p.run.spy.TrustSign != before.TrustSign {
				t.Fatal("group refusal caused selected writes")
			}
		case "lost-process":
			p.reserveWithoutSend()
		case "cancel-child":
			p.cancelChild()
		case "cleanup-failure":
			result := p.execute(contract.PublicationCreateWithValue, "", contract.PublicationSummaryComplete)
			if result.state != refused(CustodyUnavailable) {
				t.Fatal("cleanup failure lost", result.state)
			}
			p.assertJoins(len(p.slots), true)
			selected, err := selectedPublicationRelation(p.fixture.session.selectedImage())
			if err != nil {
				t.Fatal(err)
			}
			coordinate := selected.coordinates[publicationScenarioCoordinate(env.Domain, p.slots[0])]
			birth := selected.markers[coordinate.OwnedBirthAttemptID]
			if coordinate.OwnerState != contract.PublicationOwnerQualified || coordinate.OwnedInstanceDigest.IsZero() || birth.State != contract.PublicationAcknowledged || birth.Evidence.Class != contract.PublicationRequestAcknowledged || coordinate.LateEffectRisk != 0 || !coordinate.LatestUnresolvedAttemptID.IsZero() {
				t.Fatal("sole executable removal failure changed checked creation evidence")
			}
		case "ack-then-unknown", "unknown-then-ack", "unqualified-create":
			p.execute(contract.PublicationCreateWithValue, p.slots[0], contract.PublicationSummaryUnknown)
			p.assertJoins(len(p.slots), false)
			selected, err := selectedPublicationRelation(p.fixture.session.selectedImage())
			if err != nil {
				t.Fatal(err)
			}
			coordinate := selected.coordinates[publicationScenarioCoordinate(env.Domain, p.slots[0])]
			if coordinate.OwnerState != contract.PublicationOwnerUncertainCreate || !coordinate.OwnedBirthAttemptID.IsZero() || !coordinate.OwnedInstanceDigest.IsZero() {
				t.Fatal("unqualified creation established ownership")
			}
		default:
			p.execute(contract.PublicationCreateWithValue, "", contract.PublicationSummaryComplete)
			p.assertJoins(len(p.slots), false)
			if condition == "separate-values-and-noop" {
				calls, privateCalls := env.Custody.Calls()
				before := p.run.spy.scenarioEffects
				p.private = p.zeroPrivate()
				p.execute(0, "", contract.PublicationSummaryNoChange)
				after, afterPrivate := env.Custody.Calls()
				if calls != after || privateCalls != afterPrivate || p.run.spy.StoreCreate != before.StoreCreate || p.run.spy.StoreCAS != before.StoreCAS || p.run.spy.TrustSign != before.TrustSign {
					t.Fatal("no-op caused private or selected work")
				}
				if p.callsStarted.Load() != 0 || p.sends.Load() != 0 {
					t.Fatal("no-op made child work")
				}
				p.assertJoins(0, false)
			} else {
				p.entries[0].InputBytes = []byte("updated plain data")
				p.entries[1] = suppliedSecret(t, p.run.env, "secret", "publication updated source", custody.AlternateStandardValue)
				before, result := p.fixture.session.currentOutputConfigurationForApply(p.run.ctx)
				if result.Outcome != 0 {
					t.Fatal(result)
				}
				p.selectEntries(p.entries, nil)
				after, result := p.fixture.session.currentOutputConfigurationForApply(p.run.ctx)
				if result.Outcome != 0 || !reflect.DeepEqual(before, after) {
					t.Fatal("value transition changed output configuration", result)
				}
				if condition == "wrong-instance" {
					p.refuseWrongInstance()
				} else {
					p.execute(contract.PublicationWriteValue, "", contract.PublicationSummaryComplete)
					p.assertJoins(len(p.slots), false)
				}
				if condition == "value-policy-delete" {
					p.selectEntries(p.entries, p.output([]uint64{1}))
					p.execute(contract.PublicationUpdatePolicy, "", contract.PublicationSummaryComplete)
					p.assertJoins(len(p.slots), false)
					p.selectEntries(p.entries, &outputApplyInput{})
					p.input.names = nil
					for _, slot := range p.slots {
						p.input.deletes = append(p.input.deletes, publicationScenarioCoordinate(env.Domain, slot))
					}
					p.execute(contract.PublicationDeleteOwned, "", contract.PublicationSummaryComplete)
					p.assertJoins(len(p.slots), false)
				}
			}
		}
	})
	p.verify()
}

func (p *publicationScenario) reserveWithoutSend() {
	t := p.run.t
	t.Helper()
	plan := p.plan()
	for _, target := range plan.targets {
		s, trust, result := p.current(p.run.ctx)
		if s == nil {
			t.Fatal("reservation current", result)
		}
		candidate, preparation, result := plan.reserveCandidate(p.run.ctx, s, target, contract.PublicationCreateWithValue, p.private)
		if candidate == nil {
			t.Fatal("lost-process reservation", result)
		}
		persisted, result := s.persistCandidate(p.run.ctx, candidate, trust)
		if persisted == nil {
			t.Fatal("lost-process persist", result)
		}
		selected, result := s.selectCandidate(p.run.ctx, persisted)
		if selected == nil || !preparation.armed {
			t.Fatal("lost-process selection", result)
		}
		if err := preparation.retire(p.run.ctx); err != nil {
			t.Fatal("lost-process retire", err)
		}
		p.fixture.session = selected
	}
	p.assertJoins(0, false)
	checkPublicationFreshPlan(t, p.run.ctx, p.reopen(), "lost-process")
}

// The actual fresh child calls this without a custody or executable route.
func checkPublicationFreshPlan(t testing.TB, ctx context.Context, s *StateSession, condition string) {
	t.Helper()
	if strings.TrimPrefix(condition, "publication.") != "lost-process" {
		return
	}
	selected, err := selectedPublicationRelation(s.selectedImage())
	if err != nil {
		t.Fatal("fresh publication relation", err)
	}
	if len(selected.coordinates) != 2 || len(selected.markers) != 2 {
		t.Fatal("fresh lost-process shape", len(selected.coordinates), len(selected.markers))
	}
	private := publicationPrivate{Actions: func(context.Context, publicationExecutionInput) (publicationActionFacts, error) {
		t.Error("fresh planning Actions")
		return publicationActionFacts{}, contract.ErrRecord
	}, Check: func(context.Context, publicationActionCheckInput) (publicationActionCheckFacts, error) {
		t.Error("fresh planning Check")
		return publicationActionCheckFacts{}, contract.ErrRecord
	}, NewOwner: func(context.Context, publicationOwnerInput) (publicationPrivateOwner, error) {
		t.Error("fresh planning NewOwner")
		return nil, contract.ErrRecord
	}}
	input := publicationInput{names: []string{"plain", "secret"}, acting: s.admission.recipient, deadline: time.Now().Add(30 * time.Second)}
	want := contract.PublicationOutcomeVector{Schema: 2, DomainID: s.root.Domain, SnapshotID: s.root.Snapshot, SelectionDigest: sha256.Sum256(s.body)}
	for _, slot := range []string{"plain-target", "secret-target"} {
		id := publicationScenarioCoordinate(s.root.Domain, slot)
		coordinate, present := selected.coordinates[id]
		if !present || coordinate.OwnerState != contract.PublicationOwnerUncertainCreate || !coordinate.OwnedBirthAttemptID.IsZero() {
			t.Fatal("fresh uncertain coordinate", present)
		}
		var marker contract.PublicationMarker
		for _, m := range selected.markers {
			if m.CoordinateID == id {
				if !marker.AttemptID.IsZero() {
					t.Fatal("fresh duplicate reservation")
				}
				marker = m
			}
		}
		if marker.AttemptID.IsZero() || marker.State != contract.PublicationMayHaveEntered || marker.Projection.Action != contract.PublicationCreateWithValue || marker.Evidence.Class != contract.PublicationUnproved {
			t.Fatal("fresh marker state")
		}
		want.Entries = append(want.Entries, contract.PublicationTargetOutcome{CoordinateID: id, Actions: []contract.PublicationOutcome{{Action: contract.PublicationCreateWithValue, ProjectionCommitment: marker.ProjectionCommitment, AttemptID: marker.AttemptID, Disposition: contract.PublicationOutcomeUnknown, RemoteValueMayRemain: 1, BlockerIDs: []contract.ID{marker.AttemptID}, Evidence: contract.PublicationEvidence{Schema: 3, Entry: contract.PublicationMayHaveEnteredEntry, Class: contract.PublicationUnproved, ResponseContractDigest: marker.Evidence.ResponseContractDigest}}}})
	}
	slices.SortFunc(want.Entries, func(a, b contract.PublicationTargetOutcome) int {
		return bytes.Compare(a.CoordinateID[:], b.CoordinateID[:])
	})
	before := bytes.Clone(s.body)
	plan, result := s.planPublication(ctx, input, private)
	if plan == nil || result.Outcome != ObservedCurrent {
		t.Fatal("fresh blocker plan", result)
	}
	want.OperationID = plan.operation
	got := plan.execute(ctx, private, func(context.Context) (*StateSession, contract.Trust, Result) {
		t.Error("fresh plan requested current writer")
		return nil, nil, refused(AdmissionInvalid)
	})
	assertPublicationScenarioVector(t, got, want, contract.PublicationSummaryUnknown)
	if !bytes.Equal(before, s.body) {
		t.Fatal("fresh planning changed current selection")
	}
}

func (p *publicationScenario) cancelChild() {
	t := p.run.t
	t.Helper()
	plan := p.plan()
	want := p.expected(plan, contract.PublicationCreateWithValue, p.slots[0], false)
	ctx, cancel := context.WithCancel(p.run.ctx)
	defer cancel()
	done := make(chan publicationOperationResult, 1)
	joined := false
	t.Cleanup(func() {
		cancel()
		if !joined {
			select {
			case <-done:
				joined = true
			case <-time.After(5 * time.Second):
				t.Error("cancel child cleanup did not join")
			}
		}
	})
	go func() { done <- plan.execute(ctx, p.private, p.current) }()
	deadline := time.NewTimer(12 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	entered := false
	for !entered {
		select {
		case <-deadline.C:
			t.Fatal("child did not enter selected Execute")
		case got := <-done:
			joined = true
			t.Fatal("child ended before cancel", got.summary)
		case <-ticker.C:
			var err error
			entered, err = publicationTestChildEntered(p.staging)
			if err != nil {
				t.Fatal("cancel barrier", err)
			}
		}
	}
	cancel()
	// Only the first coordinate reaches the child; cancellation refuses the later
	// selected action before a marker or private owner can be acquired.
	for i := range want.Entries {
		if i == 0 {
			continue
		}
		row := &want.Entries[i].Actions[0]
		row.AttemptID = contract.ID{}
		row.Disposition = contract.PublicationNotSent
		row.CoreReason = uint16(AdmissionInvalid)
		row.RemoteValueMayRemain = 0
		row.Evidence = contract.PublicationEvidence{}
	}
	select {
	case got := <-done:
		joined = true
		assertPublicationScenarioVector(t, got, want, contract.PublicationSummaryUnknown)
	case <-time.After(5 * time.Second):
		t.Fatal("cancel did not positively join")
	}
	p.assertJoins(1, false)
	p.reopen()
}

func (p *publicationScenario) refuseWrongInstance() {
	t := p.run.t
	t.Helper()
	before, err := selectedPublicationRelation(p.fixture.session.selectedImage())
	if err != nil {
		t.Fatal(err)
	}
	selectedBody := bytes.Clone(p.fixture.session.body)
	effects := p.run.spy.scenarioEffects
	original := p.private
	checks, owners := 0, 0
	p.private.Check = func(ctx context.Context, in publicationActionCheckInput) (publicationActionCheckFacts, error) {
		checks++
		if in.Birth == nil {
			t.Fatal("wrong-instance probe has no qualified birth")
		}
		birth := *in.Birth
		birth.Evidence.SafeResourceID = "test-instance/other-target/" + hex.EncodeToString(birth.AttemptID[:])
		in.Birth = &birth
		digest, err := contract.PublicationOwnedInstanceDigest(birth.DomainID, birth.CoordinateID, birth.Projection.BindingIncarnationID, birth.Projection.EntryIncarnationID, birth.Projection.TargetRowDigest, birth.AttemptID, birth.Evidence.SafeResourceID)
		if err != nil {
			t.Fatal("wrong-instance generic precondition", err)
		}
		in.Coordinate.OwnedInstanceDigest = digest
		return original.Check(ctx, in)
	}
	p.private.NewOwner = func(context.Context, publicationOwnerInput) (publicationPrivateOwner, error) {
		owners++
		t.Error("wrong-instance refusal acquired owner")
		return nil, contract.ErrRecord
	}
	p.input.deadline = time.Now().Add(30 * time.Second)
	if plan, result := p.fixture.session.planPublication(p.run.ctx, p.input, p.private); plan != nil || result != refused(InvalidIntent) {
		t.Fatal("wrong-instance passive profile admitted", result)
	}
	after, err := selectedPublicationRelation(p.fixture.session.selectedImage())
	if err != nil || checks != 1 || owners != 0 || !reflect.DeepEqual(before, after) || !bytes.Equal(selectedBody, p.fixture.session.body) || p.run.spy.StoreCreate != effects.StoreCreate || p.run.spy.StoreCAS != effects.StoreCAS || p.run.spy.TrustSign != effects.TrustSign {
		t.Fatal("wrong-instance refusal changed selected birth or markers", err, checks, owners)
	}
	p.assertJoins(0, false)
}

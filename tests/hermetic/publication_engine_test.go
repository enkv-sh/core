package core

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	testtrust "enkv.sh/crypto/testsupport/trust"
	"enkv.sh/telemetry"
)

func publicationEngineCurrent(f *fixture) publicationCurrent {
	return func(ctx context.Context) (*StateSession, contract.Trust, Result) {
		s, r := Open(ctx, f.admission, f.store)
		return s, f.trust, r
	}
}
func publicationEnginePlan(t *testing.T, f *fixture, input publicationInput, p *publicationControlledPrivate) *publicationPlan {
	t.Helper()
	plan, r := f.session.planPublication(t.Context(), input, p.callbacks())
	if plan == nil {
		t.Fatalf("plan: outcome=%d reason=%d", r.Outcome, r.Reason)
	}
	return plan
}

func hermeticPublicationTargetFacts(t *testing.T, f *fixture, update func(*contract.OutputTarget)) {
	t.Helper()
	configuration, result := f.session.currentOutputConfigurationForApply(t.Context())
	if result.Outcome != 0 {
		t.Fatal("current publication target facts unavailable", result)
	}
	names := make(map[contract.ID]string)
	for _, named := range f.session.root.Names {
		names[f.session.valueEntry(named.Slot).Incarnation] = named.Name
	}
	output := &outputApplyInput{}
	for _, source := range configuration.Bindings {
		binding := outputApplyBinding{destinationID: source.DestinationID, destination: source.Destination}
		for _, target := range source.Targets {
			name, ok := names[target.EntryIncarnationID]
			if !ok {
				t.Fatal("publication target entry unavailable")
			}
			target.EntryIncarnationID = contract.ID{}
			update(&target)
			binding.destination.Capabilities = target.Capabilities
			binding.targets = append(binding.targets, outputApplyTarget{entryName: name, target: target})
		}
		output.bindings = append(output.bindings, binding)
	}
	output.routes = append(output.routes, outputApplyRoute{defaultRoute: true, destinations: slices.Clone(configuration.DefaultDestinations)})
	for _, route := range configuration.Routes {
		output.routes = append(output.routes, outputApplyRoute{entryName: names[route.EntryIncarnationID], destinations: slices.Clone(route.Destinations)})
	}
	for _, group := range configuration.Groups {
		var members []string
		for _, id := range group {
			members = append(members, names[id])
		}
		output.groups = append(output.groups, members)
	}
	selectOutputConfiguration(t, f, f.session.currentEntryInputs(), output)
}

type publicationNotSentStore struct {
	*memoryStore
	afterNotSent func()
}

func (store *publicationNotSentStore) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	result := store.memoryStore.CompareAndSwap(ctx, key, token, body)
	if store.afterNotSent != nil {
		after := store.afterNotSent
		store.afterNotSent = nil
		after()
	}
	return result
}

// full_only: false
func TestPublicationFirstSendRequiresSelectedMarker(t *testing.T) {
	for _, mode := range []string{"direct_ack_one_target", "lost_selection_reply", "unselected", "wrong_correlation", "unknown_create_stops_later_actions", "not_sent_predecessor", "not_sent_competing_selection"} {
		t.Run(mode, func(t *testing.T) {
			f, input, p := publicationEngineFixture(t)
			if mode == "unknown_create_stops_later_actions" {
				hermeticPublicationTargetFacts(t, f, func(target *contract.OutputTarget) {
					target.Capabilities &^= contract.OutputCapabilityCreateWithValue
					target.Capabilities |= contract.OutputCapabilityCreateEmpty
					target.CreateValueBounds = contract.OutputPayloadBounds{}
					target.Capabilities &^= contract.OutputCapabilityCreateSetsPolicy
					target.Capabilities &^= contract.OutputCapabilityWriteSetsPolicy
					target.Capabilities |= contract.OutputCapabilityUpdatePolicy
				})
				p.evidence = contract.PublicationUnproved
			}
			plan := publicationEnginePlan(t, f, input, p)
			if mode == "lost_selection_reply" {
				f.store.casMode = "lost-after"
			}
			if mode == "unselected" {
				f.store.casMode = "refused"
			}
			if mode == "wrong_correlation" {
				p.corrupt = true
			}
			current := publicationEngineCurrent(f)
			if mode == "not_sent_predecessor" || mode == "not_sent_competing_selection" {
				store := &publicationNotSentStore{memoryStore: f.store}
				if mode == "not_sent_competing_selection" {
					entries := f.session.currentEntryInputs()
					entries[0].InputBytes = []byte("competing value")
					parent := admitSuppliedComparison(t, f.session, nil, entries)
					comparison, state := f.session.Compare(t.Context(), entries, parent)
					if comparison == nil {
						t.Fatal("competing comparison", state)
					}
					competing, state := f.session.Prepare(t.Context(), comparison, admit(t, f.session, comparison), f.trust)
					if competing == nil {
						t.Fatal("competing preparation", state)
					}
					store.afterNotSent = func() {
						f.store.casMode = ""
						selected, state := f.session.selectCandidate(t.Context(), competing)
						if selected == nil || state.Outcome != ObservedCurrent {
							t.Fatal("competing selection", state)
						}
						f.store.casMode = "lost-before"
					}
				}
				f.store.casMode = "lost-before"
				current = func(ctx context.Context) (*StateSession, contract.Trust, Result) {
					session, state := Open(ctx, f.admission, store)
					return session, f.trust, state
				}
			}
			got := plan.execute(t.Context(), p.callbacks(), current)
			if len(p.owners) != 1 || p.owners[0].prepared != 1 || p.owners[0].retired != 1 {
				t.Fatalf("owner lifecycle owners=%d result=%+v", len(p.owners), got.state)
			}
			want := uint8(contract.PublicationOutcomeAcknowledged)
			sends := 1
			if mode == "lost_selection_reply" || mode == "wrong_correlation" || mode == "unknown_create_stops_later_actions" {
				want = contract.PublicationOutcomeUnknown
			}
			if mode == "lost_selection_reply" {
				sends = 0
			}
			if mode == "unselected" || mode == "not_sent_predecessor" || mode == "not_sent_competing_selection" {
				want = contract.PublicationNotSent
				sends = 0
			}
			row := got.output.Entries[0].Actions[0]
			if row.Disposition != want || p.owners[0].armed != sends || p.owners[0].sent != sends {
				t.Fatalf("disposition=%d want=%d arms=%d sends=%d state=%+v", row.Disposition, want, p.owners[0].armed, p.owners[0].sent, got.state)
			}
			if _, err := contract.EncodePublicationOutcomeVector(got.output); err != nil {
				t.Fatal("complete vector", err)
			}
			if mode == "unknown_create_stops_later_actions" {
				if len(got.output.Entries[0].Actions) != 3 {
					t.Fatal("missing fixed later actions")
				}
				for _, later := range got.output.Entries[0].Actions[1:] {
					if later.Disposition != contract.PublicationNotSent || !later.AttemptID.IsZero() {
						t.Fatal("later action acquired rights", later)
					}
				}
			}
			reopened, r := Open(t.Context(), f.admission, f.store)
			if reopened == nil {
				t.Fatal("reopen", r)
			}
			selected, e := selectedPublicationRelation(reopened.selectedImage())
			if e != nil {
				t.Fatal(e)
			}
			if want == contract.PublicationNotSent {
				if _, exists := selected.markers[plan.targets[0].attempts[0]]; exists {
					t.Fatal("unsent reservation selected a marker")
				}
				if !row.AttemptID.IsZero() || row.CoreReason == 0 || row.Evidence.Entry != 0 {
					t.Fatal("unsent action acquired entry evidence", row)
				}
			}
			if want == contract.PublicationOutcomeAcknowledged {
				marker := selected.markers[row.AttemptID]
				if marker.State != contract.PublicationAcknowledged {
					t.Fatal("ACK was not selected", marker.State)
				}
			}
		})
	}
}

// full_only: false
func TestPublicationResultPreservesCurrentState(t *testing.T) {
	t.Run("canonical_change_during_send", func(t *testing.T) {
		f, input, p := publicationEngineFixture(t)
		plan := publicationEnginePlan(t, f, input, p)
		var changed *StateSession
		p.onSend = func() {
			current, r := Open(t.Context(), f.admission, f.store)
			if current == nil {
				t.Fatal(r)
			}
			f.session = current
			entries := current.currentEntryInputs()
			entries[0].InputBytes = []byte("replacement")
			parent := admitSuppliedComparison(t, current, nil, entries)
			comparison, r := current.Compare(t.Context(), entries, parent)
			if comparison == nil {
				t.Fatal("canonical comparison", r)
			}
			candidate, r := current.Prepare(t.Context(), comparison, admit(t, current, comparison), f.trust)
			if candidate == nil {
				t.Fatal("canonical prepare", r)
			}
			selected, r := current.selectCandidate(t.Context(), candidate)
			if selected == nil {
				t.Fatal("canonical selection", r)
			}
			f.session = selected

			changed = f.session
		}
		got := plan.execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
		if got.output.Entries[0].Actions[0].Disposition != contract.PublicationOutcomeAcknowledged {
			t.Fatal("original result did not close", got.state)
		}
		after, r := Open(t.Context(), f.admission, f.store)
		if after == nil {
			t.Fatal(r)
		}
		if !reflect.DeepEqual(changed.pages, after.pages) || !reflect.DeepEqual(changed.root.CurrentAccess, after.root.CurrentAccess) || changed.root.OutputConfiguration != after.root.OutputConfiguration {
			t.Fatal("close replaced current state")
		}
	})
}

// full_only: false
func TestPublicationFullActionChain(t *testing.T) {
	f, input, p := publicationEngineFixture(t)
	hermeticPublicationTargetFacts(t, f, func(target *contract.OutputTarget) {
		target.Capabilities &^= contract.OutputCapabilityCreateWithValue
		target.Capabilities |= contract.OutputCapabilityCreateEmpty
		target.CreateValueBounds = contract.OutputPayloadBounds{}
		target.Capabilities &^= contract.OutputCapabilityCreateSetsPolicy
		target.Capabilities &^= contract.OutputCapabilityWriteSetsPolicy
		target.Capabilities |= contract.OutputCapabilityUpdatePolicy
	})
	plan := publicationEnginePlan(t, f, input, p)
	if len(plan.vector.Entries[0].Actions) != 3 {
		t.Fatal("preflight omitted actions")
	}
	got := plan.execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
	if got.summary != contract.PublicationSummaryComplete || len(p.owners) != 3 {
		t.Fatalf("chain result=%+v owners=%d", got.state, len(p.owners))
	}
	attempts := map[contract.ID]bool{}
	for i, row := range got.output.Entries[0].Actions {
		if row.Disposition != contract.PublicationOutcomeAcknowledged || row.AttemptID.IsZero() || attempts[row.AttemptID] || p.owners[i].armed != 1 || p.owners[i].sent != 1 || p.owners[i].retired != 1 {
			t.Fatal("per-action result/right", i, row, p.owners[i])
		}
		attempts[row.AttemptID] = true
	}
	after, r := Open(t.Context(), f.admission, f.store)
	if after == nil {
		t.Fatal(r)
	}
	f.session = after
	beforeChecks := p.checks
	noOp := publicationEnginePlan(t, f, input, p)
	if noOp.vector.Entries[0].Actions[0].Disposition != contract.PublicationNoOp {
		t.Fatal("separate selected value and policy ACKs did not establish equality")
	}
	beforeOwners := len(p.owners)
	got = noOp.execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
	if got.summary != contract.PublicationSummaryNoChange || len(p.owners) != beforeOwners || p.checks != beforeChecks {
		t.Fatal("no-op prepared private work")
	}
}

// full_only: false
func TestPublicationRepublish(t *testing.T) {
	t.Run("rejects_stale_blocker_set", func(t *testing.T) {
		f, input, p := publicationEngineFixture(t)
		p.evidence = contract.PublicationUnproved
		first := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
		s, r := Open(t.Context(), f.admission, f.store)
		if s == nil {
			t.Fatal(r)
		}
		f.session = s
		id := first.output.Entries[0].CoordinateID
		input.republish = map[contract.ID][]contract.ID{id: {publicationRelationID(88)}}
		owners := len(p.owners)
		if plan, r := s.planPublication(t.Context(), input, p.callbacks()); plan != nil || r.Reason != InvalidIntent || len(p.owners) != owners {
			t.Fatal("stale blocker admitted", r)
		}
	})
	t.Run("retains_old_unknown_after_new_ack", func(t *testing.T) {
		f, input, p := publicationEngineFixture(t)
		p.evidence = contract.PublicationUnproved
		first := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
		s, r := Open(t.Context(), f.admission, f.store)
		if s == nil {
			t.Fatal(r)
		}
		f.session = s
		id := first.output.Entries[0].CoordinateID
		old := first.output.Entries[0].Actions[0].AttemptID
		input.republish = map[contract.ID][]contract.ID{id: {old}}
		p.evidence = contract.PublicationRequestAcknowledged
		got := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
		if got.summary != contract.PublicationSummaryComplete || got.output.Entries[0].Actions[0].Disposition != contract.PublicationOutcomeAcknowledged || got.output.Entries[0].Actions[0].LateWriteRisk != 1 {
			t.Fatal("fresh ACK classification", got.summary, got.state)
		}
		s, r = Open(t.Context(), f.admission, f.store)
		if s == nil {
			t.Fatal(r)
		}
		selected, e := selectedPublicationRelation(s.selectedImage())
		if e != nil || selected.markers[old].State != contract.PublicationUnknown {
			t.Fatal("republish closed old blocker", e)
		}
		f.session = s
		input.republish = nil
		blocked := publicationEnginePlan(t, f, input, p)
		if blocked.vector.Entries[0].Actions[0].Disposition != contract.PublicationOutcomeUnknown {
			t.Fatal("ACK erased blocking precedence")
		}
	})
}

// full_only: false
func TestPublicationNamespaceAdmission(t *testing.T) {
	for _, damage := range []string{"absent", "wrong_domain", "wrong_slot"} {
		t.Run(damage, func(t *testing.T) {
			f, input, p := publicationEngineFixture(t)
			switch damage {
			case "absent":
				f.session.admission.publicationNamespaces = nil
			case "wrong_domain":
				f.session.admission.publicationNamespaces[0].domain = publicationRelationID(95)
			case "wrong_slot":
				f.session.admission.publicationNamespaces[0].physical = "other"
			}
			if plan, r := f.session.planPublication(t.Context(), input, p.callbacks()); plan != nil || r.Reason != AdmissionInvalid || len(p.owners) != 0 {
				t.Fatal("unqualified create admitted", r)
			}
		})
	}
}

// full_only: false
func TestPublicationGroupAdmission(t *testing.T) {
	for _, grouped := range []bool{false, true} {
		t.Run(strconv.FormatBool(grouped), func(t *testing.T) {
			f := newFixture(t, 2, false, 1)
			entries := f.session.currentEntryInputs()
			targets := []outputApplyTarget{publicationEngineTarget(entries[0].Name, "first"), publicationEngineTarget(entries[1].Name, "second")}
			output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "destination", targets: targets}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"destination"}}}}
			if grouped {
				output.groups = [][]string{{entries[0].Name, entries[1].Name}}
			}
			selectOutputConfiguration(t, f, entries, output)
			pins := []publicationNamespace{{domain: f.session.root.Domain, service: "controlled-provider", physical: "first", premise: publicationRelationID(99)}, {domain: f.session.root.Domain, service: "controlled-provider", physical: "second", premise: publicationRelationID(99)}}
			f.admission.admission.publicationNamespaces = pins
			f.session.admission.publicationNamespaces = pins
			input := publicationInput{names: []string{entries[0].Name}, acting: f.session.admission.recipient, deadline: time.Now().Add(30 * time.Second)}
			p := newPublicationControlledPrivate()
			plan, result := f.session.planPublication(t.Context(), input, p.callbacks())
			if grouped {
				if plan != nil || result.Reason != AdmissionInvalid || len(p.owners) != 0 {
					t.Fatal("partial explicit group admitted", result)
				}
				return
			}
			if plan == nil || len(plan.targets) != 1 {
				t.Fatal("independent peer expanded destination selection", result)
			}
			before, err := selectedPublicationRelation(f.session.selectedImage())
			if err != nil {
				t.Fatal(err)
			}
			peer, err := contract.PublicationCoordinateID(f.session.root.Domain, "controlled-provider", "second")
			if err != nil {
				t.Fatal(err)
			}
			got := plan.execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
			if got.summary != contract.PublicationSummaryComplete || len(p.owners) != 1 {
				t.Fatal("independent entry did not publish alone", got.state)
			}
			publicationEngineReopen(t, f)
			after, err := selectedPublicationRelation(f.session.selectedImage())
			if err != nil || !reflect.DeepEqual(after.coordinates[peer], before.coordinates[peer]) {
				t.Fatal("independent publication changed peer ownership", err)
			}
		})
	}
}

// full_only: false
func TestPublicationWriteMinimumPrecedesCreateEmpty(t *testing.T) {
	for _, encoding := range []uint8{contract.OutputEncodingRaw, contract.OutputEncodingBase64} {
		for _, length := range []int{0, 1} {
			t.Run("encoding="+strconv.Itoa(int(encoding))+"/raw="+strconv.Itoa(length), func(t *testing.T) {
				f, input, p := publicationEngineFixture(t)
				entries := f.session.currentEntryInputs()
				entries[0].InputBytes = bytes.Repeat([]byte{'x'}, length)
				target := publicationEngineTarget(entries[0].Name, "publication")
				target.target.Capabilities = contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityWriteValue | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot
				target.target.CreateValueBounds = contract.OutputPayloadBounds{}
				target.target.WriteValueBounds = contract.OutputPayloadBounds{Minimum: 1, Maximum: 65536}
				target.target.Policy = contract.OutputPolicy{}
				target.target.PayloadEncoding = encoding
				entries[0].OutputEncoding = encoding
				selectOutputConfiguration(t, f, entries, &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "publication", targets: []outputApplyTarget{target}}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"publication"}}}})
				creates, cas, signs := f.store.creates, f.store.cas, f.trust.signs
				body := bytes.Clone(f.session.body)
				plan, result := f.session.planPublication(t.Context(), input, p.callbacks())
				if length == 0 {
					if plan != nil || result.Outcome != AdmissionRefused || result.Reason != CapacityExceeded || p.checks != 0 || len(p.owners) != 0 || f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs || !bytes.Equal(f.session.body, body) {
						t.Fatal("empty later write did not refuse before create, private work and selection", result, p.checks, len(p.owners))
					}
					return
				}
				if plan == nil || len(plan.targets) != 1 || !slices.Equal(plan.targets[0].actions, []uint8{contract.PublicationCreateEmpty, contract.PublicationWriteValue}) {
					t.Fatal("one-byte control did not schedule create then write", result)
				}
				got := plan.execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
				if got.summary != contract.PublicationSummaryComplete || len(p.owners) != 2 {
					t.Fatal("one-byte control did not complete both actions", got.state, len(p.owners))
				}
				for _, owner := range p.owners {
					if owner.prepared != 1 || owner.armed != 1 || owner.sent != 1 || owner.retired != 1 {
						t.Fatal("one-byte control owner lifecycle")
					}
				}
			})
		}
	}
}

// full_only: false
func TestPublicationCapacityPrecedesPrivateWork(t *testing.T) {
	t.Run("projected_page_limit", func(t *testing.T) {
		f, input, p := publicationEngineFixture(t)
		hermeticPublicationTargetFacts(t, f, func(target *contract.OutputTarget) {
			target.Capabilities &^= contract.OutputCapabilityCreateWithValue
			target.Capabilities |= contract.OutputCapabilityCreateEmpty
			target.CreateValueBounds = contract.OutputPayloadBounds{}
			target.Capabilities &^= contract.OutputCapabilityCreateSetsPolicy
			target.Capabilities &^= contract.OutputCapabilityWriteSetsPolicy
			target.Capabilities |= contract.OutputCapabilityUpdatePolicy
		})
		plan := publicationEnginePlan(t, f, input, p)
		if len(plan.targets) != 1 || len(plan.targets[0].actions) != 3 {
			t.Fatal("expected create, policy and value plan")
		}
		// Exercise the scalar capacity boundary directly. This changed count is
		// not an authenticated selected image and must not be passed to admission.
		f.session.root.ChildCount = ordinaryChildPageLimit
		if err := f.session.publicationInvocationCapacity(t.Context(), plan.targets, 3); !errors.Is(err, contract.ErrRecordCapacity) {
			t.Fatal("projected pages escaped the ordinary limit", err)
		}
		if len(p.owners) != 0 {
			t.Fatal("capacity preflight allocated a private owner")
		}
	})
	t.Run("complete_plan_marker_limit", func(t *testing.T) {
		// Two targets per entry need 342*2*3=2052 markers for their full
		// create/policy/value chains, although the 684 first actions fit.
		f := newFixture(t, 342, false, 1)
		entries := f.session.currentEntryInputs()
		output := &outputApplyInput{routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"first", "second"}}}}
		var namespaces []publicationNamespace
		for _, destination := range []string{"first", "second"} {
			binding := outputApplyBinding{destinationID: destination}
			for _, entry := range entries {
				target := publicationEngineTarget(entry.Name, destination+"/"+entry.Name)

				binding.targets = append(binding.targets, target)
				namespaces = append(namespaces, publicationNamespace{domain: f.session.root.Domain, service: target.target.ServiceContractID, physical: target.target.CanonicalTarget, premise: publicationRelationID(99)})
			}
			output.bindings = append(output.bindings, binding)
		}
		selectOutputConfiguration(t, f, entries, output)
		f.session.admission.publicationNamespaces = namespaces
		input := publicationInput{acting: f.session.admission.recipient, deadline: time.Now().Add(30 * time.Second)}
		for _, entry := range entries {
			input.names = append(input.names, entry.Name)
		}
		p := newPublicationControlledPrivate()
		hermeticPublicationTargetFacts(t, f, func(target *contract.OutputTarget) {
			target.Capabilities = (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot)
			target.CreateValueBounds = contract.OutputPayloadBounds{}
		})
		if plan, r := f.session.planPublication(t.Context(), input, p.callbacks()); plan != nil || r.Reason != CapacityExceeded {
			t.Fatal("full action plan did not refuse marker capacity", r)
		}
		if len(p.owners) != 0 {
			t.Fatal("full plan capacity refusal allocated a private owner")
		}
	})
}

// full_only: true
func TestPublicationRetainedBlockerCapacityPrecedesOwner(t *testing.T) {
	f, input, p := publicationEngineFixture(t)
	created := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
	if created.summary != contract.PublicationSummaryComplete {
		t.Fatal("native acknowledged birth", created.state)
	}
	publicationEngineReopen(t, f)
	entries := f.session.currentEntryInputs()
	entries[0].InputBytes = []byte("changed value")
	configuration, state := f.session.currentOutputConfigurationForApply(t.Context())
	if state.Outcome != 0 || len(configuration.Bindings) != 1 {
		t.Fatal("native unchanged output configuration", state)
	}
	target := publicationEngineTarget(entries[0].Name, "publication")
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "publication", destination: configuration.Bindings[0].Destination, targets: []outputApplyTarget{target}}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"publication"}}}}
	installOutputFixtureSource(t, f.session, output)
	parent := admitSuppliedOutputComparison(t, f.session, nil, entries, output)
	comparison, state := f.session.compareWithOutput(t.Context(), entries, output, parent)
	if comparison == nil || state.Outcome != ObservedCurrent {
		t.Fatal("native changed-value comparison", state)
	}
	candidate, state := f.session.Prepare(t.Context(), comparison, admit(t, f.session, comparison), f.trust)
	if candidate == nil || state.Outcome != ObservedCurrent {
		t.Fatal("native changed-value preparation", state)
	}
	if state := f.session.Select(t.Context(), candidate); state.Outcome != ObservedCurrent {
		t.Fatal("native changed-value selection", state)
	}
	publicationEngineReopen(t, f)
	p.evidence = contract.PublicationUnproved
	unknown := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
	if len(unknown.output.Entries) != 1 || len(unknown.output.Entries[0].Actions) != 1 || unknown.output.Entries[0].Actions[0].Action != contract.PublicationWriteValue || unknown.output.Entries[0].Actions[0].Disposition != contract.PublicationOutcomeUnknown {
		t.Fatal("native unknown write", unknown.state)
	}
	publicationEngineReopen(t, f)
	selected, err := selectedPublicationRelation(f.session.selectedImage())
	if err != nil {
		t.Fatal(err)
	}
	coordinateID := unknown.output.Entries[0].CoordinateID
	template := selected.markers[unknown.output.Entries[0].Actions[0].AttemptID]
	// A changed policy requires visibility and value actions on the same owned
	// coordinate. The old birth and every old unknown write stay selected.
	target.target.Policy = hermeticNumberPolicy("controlled-policy", []uint64{7})
	output.bindings[0].destination.Policy = target.target.Policy
	output.bindings[0].targets = []outputApplyTarget{target}
	selectOutputConfiguration(t, f, entries, output)
	current := *f.session
	current.support = slices.Clone(current.support)
	coordinate := selected.coordinates[coordinateID]
	rows := make([]contract.SupportRecord, 0, 1278)
	blockers := make([]contract.ID, 0, 1276)
	for _, marker := range selected.markers {
		if marker.AttemptID == template.AttemptID {
			continue
		}
		body, err := contract.EncodePublicationMarker(marker)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, contract.SupportRecord{Kind: contract.PublicationMarkerSupportKind, RecordID: marker.AttemptID, Body: body})
	}
	for i := range 1276 {
		marker := template
		marker.AttemptID = fixtureID(current.root.Domain, "capacity unknown attempt "+strconv.Itoa(i))
		marker.OperationID = fixtureID(current.root.Domain, "capacity unknown operation "+strconv.Itoa(i))
		marker.AdmissionOrdinal = uint64(i + 2)
		projection := marker.Projection
		reserve := contract.OutputReserveSubject{Schema: 5, Action: projection.Action, DomainID: marker.DomainID, OperationID: marker.OperationID, AttemptID: marker.AttemptID,
			PredecessorRevisionID: current.head.Core.Revision, PredecessorFullHEADDigest: contract.Hash(current.body), PredecessorToken: current.token,
			CurrentAccessRoot: current.root.CurrentAccess.AccessRoot, ConfigurationDigest: projection.ConfigurationDigest, CoordinateID: marker.CoordinateID, PublicationIncarnationID: marker.PublicationIncarnationID, AdmissionOrdinal: marker.AdmissionOrdinal,
			BindingIncarnationID: projection.BindingIncarnationID, EntryIncarnationID: projection.EntryIncarnationID, TargetRowDigest: projection.TargetRowDigest, BirthTargetRowDigest: coordinate.DeletionTargetRowDigest,
			OwnedBirthAttemptID: projection.OwnedBirthAttemptID, UncertainCreateAttemptID: projection.UncertainCreateAttemptID, ExclusiveNamespaceDigest: projection.ExclusiveNamespaceDigest,
			ValueBasisDigest: projection.ValueBasisDigest, PolicyDigest: projection.PolicyDigest, RequestContractDigest: projection.RequestContractDigest, BlockerCount: marker.BlockerCount, BlockerDigest: marker.BlockerDigest}
		marker.AuthoritySubjectDigest, err = contract.OutputReserveAdmissionDigest(reserve, marker)
		if err != nil {
			t.Fatal("independent retained reservation construction", err)
		}
		body, err := contract.EncodePublicationMarker(marker)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, contract.SupportRecord{Kind: contract.PublicationMarkerSupportKind, RecordID: marker.AttemptID, Body: body})
		blockers = append(blockers, marker.AttemptID)
		coordinate.LatestUnresolvedAttemptID = marker.AttemptID
	}
	coordinate.LastAdmissionOrdinal = 1277
	body, err := contract.EncodePublicationCoordinate(coordinate)
	if err != nil {
		t.Fatal(err)
	}
	rows = append(rows, contract.SupportRecord{Kind: contract.PublicationCoordinateSupportKind, RecordID: coordinateID, Body: body})
	publicationBoundsInstallRows(t, &current, rows)
	current.root.Snapshot, current.root.Transition = fixtureID(current.root.Domain, "capacity retained snapshot"), fixtureID(current.root.Domain, "capacity retained transition")
	env := fixtureEnvironment{Store: f.store, Trust: f.trust, Domain: current.root.Domain, Put: func(_ context.Context, key string, value []byte) error {
		f.store.mu.Lock()
		defer f.store.mu.Unlock()
		return f.store.putSelected(key, value)
	}}
	admitted := &environmentFixture{admission: f.admission, session: f.session}
	seedSignedOutputState(t, env, admitted, &current)
	f.session = admitted.session
	complete, err := selectedPublicationRelation(f.session.selectedImage())
	if err != nil || len(complete.markers) != 1277 || complete.coordinates[coordinateID].OwnedBirthAttemptID != coordinate.OwnedBirthAttemptID {
		t.Fatal("complete native retained history", err)
	}
	if f.session.root.OutputConfiguration.BindingCount != 1 || !f.session.selectedOutputComplete() {
		t.Fatal("native configuration admission omitted")
	}
	slices.SortFunc(blockers, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	input.republish = map[contract.ID][]contract.ID{coordinateID: blockers}
	input.deadline = time.Now().Add(30 * time.Second)
	hermeticPublicationTargetFacts(t, f, func(target *contract.OutputTarget) {
		target.Capabilities &^= contract.OutputCapabilityWriteSetsPolicy
		target.Capabilities |= contract.OutputCapabilityUpdatePolicy
	})
	owners, creates, cas := len(p.owners), f.store.creates, f.store.cas
	plan, result := f.session.planPublication(t.Context(), input, p.callbacks())
	if plan != nil || result.Reason != CapacityExceeded {
		t.Fatalf("complete admitted two-action target did not refuse future per-target evidence growth: plan=%v result=%+v", plan != nil, result)
	}
	if len(p.owners) != owners || f.store.creates != creates || f.store.cas != cas {
		t.Fatal("capacity refusal allocated owner or wrote selected state")
	}
	// Admission above, rather than this field-only arithmetic, is the regression
	// evidence: 33 target bytes +2*(76+1276*32) fit80KiB; two maximum evidence
	// rows add2*2128 and exceed it. The16MiB whole-vector bound still has room.
}

// full_only: false
func TestPublicationResultSummaries(t *testing.T) {
	t.Run("acknowledged_with_old_blockers", func(t *testing.T) {
		f, input, p := publicationEngineFixture(t)
		p.evidence = contract.PublicationUnproved
		first := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
		f.session, _ = Open(t.Context(), f.admission, f.store)
		row := first.output.Entries[0]
		input.republish = map[contract.ID][]contract.ID{row.CoordinateID: {row.Actions[0].AttemptID}}
		p.evidence = contract.PublicationRequestAcknowledged
		got := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
		if got.summary != contract.PublicationSummaryComplete || len(got.output.Entries[0].Actions[0].BlockerIDs) != 1 {
			t.Fatal("old unknown changed fresh result summary", got.summary)
		}
	})
	for _, tc := range []struct {
		name    string
		actions []uint8
		want    uint8
	}{{"empty", nil, contract.PublicationSummaryNoChange}, {"no_op", []uint8{contract.PublicationNoOp}, contract.PublicationSummaryNoChange}, {"ack_and_no_op", []uint8{contract.PublicationOutcomeAcknowledged, contract.PublicationNoOp}, contract.PublicationSummaryComplete}, {"ack_and_rejected", []uint8{contract.PublicationOutcomeAcknowledged, contract.PublicationOutcomeQualifiedNoEffect}, contract.PublicationSummaryMixedTerminal}, {"not_sent", []uint8{contract.PublicationNotSent}, contract.PublicationSummaryFailed}, {"unknown_over_ack", []uint8{contract.PublicationOutcomeAcknowledged, contract.PublicationOutcomeUnknown}, contract.PublicationSummaryUnknown}} {
		t.Run(tc.name, func(t *testing.T) {
			var entries []contract.PublicationTargetOutcome
			for _, d := range tc.actions {
				entries = append(entries, contract.PublicationTargetOutcome{Actions: []contract.PublicationOutcome{{Disposition: d}}})
			}
			if got := contract.SummarizePublication(entries); got != tc.want {
				t.Fatal(got, tc.want)
			}
		})
	}
}

func publicationEngineReopen(t *testing.T, f *fixture) selectedPublication {
	t.Helper()
	var result Result
	f.session, result = Open(t.Context(), f.admission, f.store)
	if f.session == nil {
		t.Fatal("cold reopen", result)
	}
	selected, err := selectedPublicationRelation(f.session.selectedImage())
	if err != nil {
		t.Fatal("cold publication", err)
	}
	return selected
}

// full_only: false
func TestPublicationCancellationAndCloseFailures(t *testing.T) {
	for _, cut := range []string{"before_reserve", "after_arm_before_entry", "after_entry", "close_refused", "close_lost_before", "close_lost_after"} {
		t.Run(cut, func(t *testing.T) {
			f, input, p := publicationEngineFixture(t)
			plan := publicationEnginePlan(t, f, input, p)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch cut {
			case "before_reserve":
				cancel()
			case "after_arm_before_entry":
				p.configureOwner = func(o *publicationControlledOwner) { o.onArm = cancel }
			case "after_entry":
				p.onSend = cancel
			default:
				p.onSend = func() {
					f.store.casMode = map[string]string{"close_refused": "refused", "close_lost_before": "lost-before", "close_lost_after": "lost-after"}[cut]
				}
			}
			got := plan.execute(ctx, p.callbacks(), publicationEngineCurrent(f))
			row := got.output.Entries[0].Actions[0]
			if cut == "before_reserve" {
				if row.Disposition != contract.PublicationNotSent || !row.AttemptID.IsZero() || len(p.owners) != 0 {
					t.Fatal("unselected cancellation acquired attempt", row, len(p.owners))
				}
			} else {
				want := uint8(contract.PublicationOutcomeUnknown)
				if cut == "close_lost_after" {
					want = contract.PublicationOutcomeAcknowledged
				}
				if row.Disposition != want || row.AttemptID.IsZero() || len(p.owners) != 1 || p.owners[0].armed != 1 || p.owners[0].retired != 1 {
					t.Fatal("entered lifecycle", row, len(p.owners), got.state)
				}
				sends := 1
				if cut == "after_arm_before_entry" {
					sends = 0
				}
				if p.owners[0].sent != sends {
					t.Fatal("send count", p.owners[0].sent, sends)
				}
			}
			f.store.casMode = ""
			selected := publicationEngineReopen(t, f)
			if cut == "before_reserve" {
				if len(selected.markers) != 0 {
					t.Fatal("unselected cancellation retained marker")
				}
			} else {
				marker, ok := selected.markers[row.AttemptID]
				if !ok {
					t.Fatal("selected attempt lost")
				}
				want := uint8(contract.PublicationMayHaveEntered)
				if cut == "close_lost_after" {
					want = contract.PublicationAcknowledged
				}
				if marker.State != want {
					t.Fatal("cold marker state", marker.State, want)
				}
			}
			// Cold observation must not acquire the old volatile permission.
			owners := len(p.owners)
			if len(selected.markers) > 0 && cut != "close_lost_after" {
				blocked := publicationEnginePlan(t, f, input, p)
				resumed := blocked.execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
				if resumed.summary != contract.PublicationSummaryUnknown || len(p.owners) != owners {
					t.Fatal("cold open restored send", resumed.summary)
				}
			}
		})
	}
}

// full_only: false
func TestPublicationQualifiedNoEffectAndMixedResults(t *testing.T) {
	t.Run("qualified_no_effect_restores_no_owner", func(t *testing.T) {
		f, input, p := publicationEngineFixture(t)
		p.evidence = contract.PublicationQualifiedNoEffect
		got := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
		row := got.output.Entries[0].Actions[0]
		selected := publicationEngineReopen(t, f)
		coordinate := selected.coordinates[got.output.Entries[0].CoordinateID]
		if got.summary != contract.PublicationSummaryFailed || row.Disposition != contract.PublicationOutcomeQualifiedNoEffect || selected.markers[row.AttemptID].State != contract.PublicationQualifiedNoEffectState || coordinate.OwnerState != contract.PublicationOwnerNone || coordinate.PossibleRemoteObject != 0 || !coordinate.LastValueAckAttemptID.IsZero() || !coordinate.LastPolicyAckAttemptID.IsZero() || !coordinate.LatestUnresolvedAttemptID.IsZero() {
			t.Fatal("no-effect supplied ownership/equality", got.summary, row.Disposition, coordinate)
		}
	})
	t.Run("ack_then_other_coordinate_no_effect", func(t *testing.T) {
		f, input, p := publicationEngineFixture(t)
		entries := f.session.currentEntryInputs()
		a := publicationEngineTarget(entries[0].Name, "first")

		b := publicationEngineTarget(entries[0].Name, "second")

		selectOutputConfiguration(t, f, entries, &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "first", targets: []outputApplyTarget{a}}, {destinationID: "second", targets: []outputApplyTarget{b}}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"first", "second"}}}})
		pins := []publicationNamespace{{domain: f.session.root.Domain, service: "controlled-provider", physical: "first", premise: publicationRelationID(99)}, {domain: f.session.root.Domain, service: "controlled-provider", physical: "second", premise: publicationRelationID(99)}}
		f.admission.admission.publicationNamespaces = pins
		f.session.admission.publicationNamespaces = pins
		p.configureOwner = func(o *publicationControlledOwner) {
			if len(p.owners) == 1 {
				o.evidence = contract.PublicationQualifiedNoEffect
			}
		}
		got := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
		if got.summary != contract.PublicationSummaryMixedTerminal || len(got.output.Entries) != 2 || len(p.owners) != 2 {
			t.Fatal("complete mixed vector", got.summary, len(got.output.Entries), len(p.owners))
		}
		selected := publicationEngineReopen(t, f)
		for i, entry := range got.output.Entries {
			if i > 0 && bytes.Compare(got.output.Entries[i-1].CoordinateID[:], entry.CoordinateID[:]) >= 0 {
				t.Fatal("coordinate order")
			}
			want := uint8(contract.PublicationOutcomeAcknowledged)
			if i == 1 {
				want = contract.PublicationOutcomeQualifiedNoEffect
			}
			if len(entry.Actions) != 1 || entry.Actions[0].Disposition != want || p.owners[i].retired != 1 || p.owners[i].sent != 1 {
				t.Fatal("mixed row", i, entry)
			}
			coordinate := selected.coordinates[entry.CoordinateID]
			if i == 0 && coordinate.OwnerState != contract.PublicationOwnerQualified || i == 1 && coordinate.OwnerState != contract.PublicationOwnerNone {
				t.Fatal("coordinate results crossed", i, coordinate.OwnerState)
			}
		}
	})
}

// full_only: false
func TestPublicationSeveralSameActionBlockers(t *testing.T) {
	f, input, p := publicationEngineFixture(t)
	p.evidence = contract.PublicationUnproved
	var coordinate contract.ID
	var blockers []contract.ID
	for range 5 {
		if len(blockers) > 0 {
			input.republish = map[contract.ID][]contract.ID{coordinate: slices.Clone(blockers)}
		}
		got := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
		coordinate = got.output.Entries[0].CoordinateID
		row := got.output.Entries[0].Actions[0]
		if row.Disposition != contract.PublicationOutcomeUnknown || row.AttemptID.IsZero() {
			t.Fatal("unknown republish", row, got.state)
		}
		blockers = append(blockers, row.AttemptID)
		slices.SortFunc(blockers, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		publicationEngineReopen(t, f)
	}
	input.republish = nil
	owners, checks := len(p.owners), p.checks
	got := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
	rows := got.output.Entries[0].Actions
	if len(rows) != 1 || rows[0].AttemptID != blockers[0] || !slices.Equal(rows[0].BlockerIDs, blockers) || rows[0].Disposition != contract.PublicationOutcomeUnknown || got.summary != contract.PublicationSummaryUnknown || len(p.owners) != owners || p.checks != checks {
		t.Fatal("complete blockers not one deterministic old row", rows, got.state)
	}
}

// full_only: false
func TestPublicationRetiredDeletion(t *testing.T) {
	for _, mode := range []string{"owned_binding_removed", "owned_entry_removed", "reserved_binding_removed"} {
		t.Run(mode, func(t *testing.T) {
			f, input, p := publicationEngineFixture(t)
			if mode == "reserved_binding_removed" {
				p.evidence = contract.PublicationUnproved
			}
			first := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
			before := publicationEngineReopen(t, f)
			id := first.output.Entries[0].CoordinateID
			birth := first.output.Entries[0].Actions[0].AttemptID
			original := before.coordinates[id]
			entries := f.session.currentEntryInputs()
			if mode == "owned_entry_removed" {
				entries = nil
				input.names = nil
			}
			selectOutputConfiguration(t, f, entries, &outputApplyInput{})
			retired := publicationEngineReopen(t, f).coordinates[id]
			want := original
			want.BindingState = contract.PublicationBindingRetired
			want.ActiveBindingIncarnationID = contract.ID{}
			if !reflect.DeepEqual(retired, want) {
				t.Fatal("removal changed deletion inputs/ownership", retired, want)
			}
			input.deletes = []contract.ID{id}
			input.republish = nil
			if mode == "reserved_binding_removed" {
				input.republish = map[contract.ID][]contract.ID{id: {birth}}
			}
			p.evidence = contract.PublicationRequestAcknowledged
			count := len(p.owners)
			got := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
			if got.summary != contract.PublicationSummaryComplete || len(p.owners) != count+1 || got.output.Entries[0].Actions[0].Disposition != contract.PublicationOutcomeAcknowledged {
				t.Fatal("retired delete", got.summary, got.state, len(p.owners))
			}
			o := p.owners[count]
			action := uint8(contract.PublicationDeleteOwned)
			if mode == "reserved_binding_removed" {
				action = contract.PublicationDeleteReservedSlot
			}
			if o.input.Projection.Action != action || !reflect.DeepEqual(o.input.Target.Policy, contract.OutputPolicy{}) || o.input.Target.CanonicalTarget != original.CanonicalTarget || o.input.Target.ConsumerLocator != original.DeletionConsumerLocator || o.input.Projection.TargetRowDigest != original.DeletionTargetRowDigest || !o.input.Projection.ValueBasisDigest.IsZero() || !o.input.Projection.PolicyDigest.IsZero() || o.prepared != 1 || o.armed != 1 || o.sent != 1 || o.retired != 1 {
				t.Fatal("delete did not use minimal exact retained input", o.input)
			}
			if mode == "reserved_binding_removed" {
				if o.input.UncertainCreate == nil || o.input.UncertainCreate.AttemptID != birth || o.input.Birth != nil || o.input.Projection.UncertainCreateAttemptID != birth || o.input.Projection.ExclusiveNamespaceDigest.IsZero() {
					t.Fatal("reserved delete lacks exact uncertain marker/premise", o.input)
				}
			} else if o.input.Birth == nil || o.input.Birth.AttemptID != birth || o.input.Projection.OwnedBirthAttemptID != birth {
				t.Fatal("owned delete lacks birth", o.input)
			}
			after := publicationEngineReopen(t, f)
			coordinate := after.coordinates[id]
			if coordinate.BindingState != contract.PublicationBindingRetired || !coordinate.ActiveBindingIncarnationID.IsZero() || coordinate.DeletionTargetRowDigest != original.DeletionTargetRowDigest || coordinate.LastDeleteAckAttemptID != got.output.Entries[0].Actions[0].AttemptID || coordinate.PossibleRemoteObject != 1 {
				t.Fatal("delete claimed absence or restored active binding", coordinate)
			}
			if mode == "reserved_binding_removed" && after.markers[birth].State != contract.PublicationUnknown {
				t.Fatal("reserved delete closed uncertain birth")
			}
			if mode != "reserved_binding_removed" {
				beforeChecks, beforeOwners := p.checks, len(p.owners)
				if plan, result := f.session.planPublication(t.Context(), input, p.callbacks()); plan != nil || result.Reason != InvalidIntent {
					t.Fatal("later delete ACK retained obsolete owned-delete authority", result)
				}
				if p.checks != beforeChecks || len(p.owners) != beforeOwners {
					t.Fatal("obsolete deletion reached private work")
				}
			}
		})
	}
}

// full_only: false
func TestPublicationFreshReaddAndPolicyChange(t *testing.T) {
	t.Run("fresh_readd_does_not_inherit_qualified_owner", func(t *testing.T) {
		f, input, p := publicationEngineFixture(t)
		first := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
		publicationEngineReopen(t, f)
		entries := f.session.currentEntryInputs()
		before, _ := f.session.currentOutputConfigurationForApply(t.Context())
		selectOutputConfiguration(t, f, entries, &outputApplyInput{})
		target := publicationEngineTarget(entries[0].Name, "publication")

		after := selectOutputConfiguration(t, f, entries, &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "publication", targets: []outputApplyTarget{target}}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"publication"}}}})
		if before.Bindings[0].IncarnationID == after.Bindings[0].IncarnationID {
			t.Fatal("readd reused incarnation")
		}
		owners := len(p.owners)
		if plan, r := f.session.planPublication(t.Context(), input, p.callbacks()); plan != nil || r.Reason != InvalidIntent || len(p.owners) != owners {
			t.Fatal("fresh binding inherited old owner/equality", r)
		}
		selected := publicationEngineReopen(t, f)
		if selected.coordinates[first.output.Entries[0].CoordinateID].OwnedBirthAttemptID != first.output.Entries[0].Actions[0].AttemptID {
			t.Fatal("readd discarded old ownership obligation")
		}
	})
	t.Run("partial_policy_removal_only_updates_policy", func(t *testing.T) {
		f, input, p := publicationEngineFixture(t)
		entries := f.session.currentEntryInputs()
		target := publicationEngineTarget(entries[0].Name, "publication")

		target.target.Policy = hermeticTextPolicy("controlled-policy", []string{"consumer-a", "consumer-b"})
		output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "publication", targets: []outputApplyTarget{target}}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"publication"}}}}
		selectOutputConfiguration(t, f, entries, output)
		hermeticPublicationTargetFacts(t, f, func(target *contract.OutputTarget) {
			target.Capabilities &^= contract.OutputCapabilityWriteSetsPolicy
			target.Capabilities |= contract.OutputCapabilityUpdatePolicy
		})
		first := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
		before := publicationEngineReopen(t, f)
		id := first.output.Entries[0].CoordinateID
		coordinate := before.coordinates[id]
		output.bindings[0].targets[0].target.Policy.Data = []byte(`["consumer-a"]`)
		output.bindings[0].destination.Policy.Data = []byte(`["consumer-a"]`)
		config := selectOutputConfiguration(t, f, entries, output)
		policy, err := contract.OutputPolicyDigest(f.session.root.Domain, config.Bindings[0].Targets[0].Policy)
		if err != nil {
			t.Fatal(err)
		}
		owners := len(p.owners)
		plan := publicationEnginePlan(t, f, input, p)
		if !slices.Equal(plan.targets[0].actions, []uint8{contract.PublicationUpdatePolicy}) {
			t.Fatal("policy change resends equal value", plan.targets[0].actions)
		}
		got := plan.execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
		after := publicationEngineReopen(t, f).coordinates[id]
		if got.summary != contract.PublicationSummaryComplete || len(p.owners) != owners+1 || p.owners[owners].input.Projection.Action != contract.PublicationUpdatePolicy || after.LastPolicyDigest != policy || after.LastValueAckAttemptID != coordinate.LastValueAckAttemptID || after.LastValueDigest != coordinate.LastValueDigest || after.OwnedBirthAttemptID != coordinate.OwnedBirthAttemptID {
			t.Fatal("policy update lost equal value/owner", got.state, after)
		}
	})
}

// full_only: false
func TestPublicationHeldRightAcrossCurrentChanges(t *testing.T) {
	t.Run("current_key_replacement_before_loaded_send", func(t *testing.T) {
		env, keys := genesisEnvironment(t, contract.GCP, false)
		env = syntheticAuthorityScenarioEnvironment(t, env)
		base := newEnvironmentFixture(t, t.Context(), env, []int{1}, false)
		f, input, p := publicationEngineFixture(t, &fixture{store: env.Store.(*memoryStore), trust: env.Trust.(*fixtureTrust), admission: base.admission, session: base.session})
		plan := publicationEnginePlan(t, f, input, p)
		var changed *StateSession
		p.configureOwner = func(o *publicationControlledOwner) {
			o.onArm = func() {
				current, _ := Open(t.Context(), f.admission, f.store)
				if current == nil {
					t.Fatal("current before replacement")
				}
				selected, err := selectedPublicationRelation(current.selectedImage())
				if err != nil {
					t.Fatal(err)
				}
				retained := selected.markers[o.dispatch.AttemptID]
				if retained.State != contract.PublicationMayHaveEntered || o.sent != 0 {
					t.Fatal("right not held before replacement")
				}
				actors := env.ReplacementActors(t, t.Context(), current, contract.SuccessionReplaceAuthority, contract.SuccessionChangeNormalSigner|contract.SuccessionChangeAuthorityKEK, contract.NormalSigningRole)
				permit := admitAuthorityReplacement(t, current, actors.Keys, actors.After, contract.SuccessionReplaceAuthority, contract.NormalSigningRole, contract.SuccessionChangeNormalSigner|contract.SuccessionChangeAuthorityKEK, actors.Source)
				candidate, result := current.PrepareSuccession(t.Context(), permit, actors.Signers)
				if candidate == nil {
					t.Fatal("held-right key replacement", result)
				}
				admission := deliverSuccessionBasis(t, candidate)
				if result := current.Select(t.Context(), candidate); result.Outcome != ObservedCurrent {
					t.Fatal("replacement select", result)
				}
				changed, result = Open(t.Context(), admission, env.Store)
				if changed == nil {
					t.Fatal("replacement cold open", result)
				}
				keys.RetireAccess()
				actors.Activate(t, changed)
				f.admission = admission
				f.trust = &fixtureTrust{Signer: actors.Signers.NormalSuccessor.(*testtrust.Signer)}
			}
		}
		got := plan.execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
		if got.output.Entries[0].Actions[0].Disposition != contract.PublicationOutcomeAcknowledged || len(p.owners) != 1 || p.owners[0].sent != 1 || p.owners[0].retired != 1 {
			t.Fatal("loaded send did not close under current keys", got.state)
		}
		selected := publicationEngineReopen(t, f)
		if changed == nil || !reflect.DeepEqual(changed.pages, f.session.pages) || !reflect.DeepEqual(changed.root.CurrentAccess, f.session.root.CurrentAccess) || changed.root.OutputConfiguration != f.session.root.OutputConfiguration || selected.markers[got.output.Entries[0].Actions[0].AttemptID].Projection != p.owners[0].input.Projection {
			t.Fatal("replacement or original projection lost")
		}
	})
	t.Run("canonical_owner_occupation_during_send", func(t *testing.T) {
		env, _ := genesisEnvironment(t, contract.GCP, false)
		base := newEnvironmentFixture(t, t.Context(), env, []int{1}, false)
		f, input, p := publicationEngineFixture(t, &fixture{store: env.Store.(*memoryStore), trust: env.Trust.(*fixtureTrust), admission: base.admission, session: base.session})
		entries := f.session.currentEntryInputs()
		target := publicationEngineTarget(entries[0].Name, "publication")
		target.target.PayloadEncoding = contract.OutputEncodingRaw
		configuration := selectOutputConfiguration(t, f, entries, &outputApplyInput{
			bindings: []outputApplyBinding{{destinationID: "publication", targets: []outputApplyTarget{target}}},
			routes:   []outputApplyRoute{{entryName: entries[0].Name, destinations: []string{"publication"}}},
		})
		plan := publicationEnginePlan(t, f, input, p)
		var occupied *StateSession
		p.onSend = func() {
			current, result := Open(t.Context(), f.admission, f.store)
			if current == nil {
				t.Fatal(result)
			}
			generated := generatedPlanInputForGenerations(t, current, publicationRelationID(81), []string{"generated"}, defaultGeneratedFixtureProfile())
			prior, _ := preparePrivateGeneratedReservation(t, env, current, generated, nil)
			occupied, _, _, _ = selectActualGeneratedPacketRecord(t, env, current, prior, custody.StandardValue, true, nil)
			selectedConfiguration, result := occupied.currentOutputConfigurationForApply(t.Context())
			if result.Outcome != 0 || occupied.root.Generated.ActiveOwner.IsZero() ||
				!reflect.DeepEqual(occupied.pages, current.pages) || !reflect.DeepEqual(occupied.root.Names, current.root.Names) ||
				occupied.root.OutputConfiguration != current.root.OutputConfiguration || !reflect.DeepEqual(selectedConfiguration, configuration) {
				t.Fatal("actual generation did not retain the current publication entry, target and binding while occupying canonical owner", result)
			}
		}
		got := plan.execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
		row := got.output.Entries[0].Actions[0]
		if row.Disposition != contract.PublicationOutcomeUnknown || p.owners[0].sent != 1 || p.owners[0].retired != 1 {
			t.Fatal("occupied owner allowed close", got.state, row)
		}
		selected := publicationEngineReopen(t, f)
		if occupied == nil || f.session.head.Core.Revision != occupied.head.Core.Revision || f.session.root.Generated.ActiveOwner != occupied.root.Generated.ActiveOwner || selected.markers[row.AttemptID].State != contract.PublicationMayHaveEntered {
			t.Fatal("close changed occupied predecessor")
		}
	})
}

// full_only: false
func TestPublicationFreshCreateRetainsUncertainty(t *testing.T) {
	for _, mode := range []string{"unknown", "empty_create_unknown", "unclosed", "ack", "after_uncertain_disposal"} {
		t.Run(mode, func(t *testing.T) {
			f, input, p := publicationEngineFixture(t)
			if mode == "empty_create_unknown" {
				hermeticPublicationTargetFacts(t, f, func(target *contract.OutputTarget) {
					target.Capabilities &^= contract.OutputCapabilityCreateWithValue
					target.Capabilities |= contract.OutputCapabilityCreateEmpty
					target.CreateValueBounds = contract.OutputPayloadBounds{}
					target.Capabilities &^= contract.OutputCapabilityCreateSetsPolicy
					target.Capabilities &^= contract.OutputCapabilityWriteSetsPolicy
					target.Capabilities |= contract.OutputCapabilityUpdatePolicy
				})
			}
			p.evidence = contract.PublicationQualifiedNoEffect
			if mode == "after_uncertain_disposal" {
				p.evidence = contract.PublicationUnproved
			}
			first := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
			selected := publicationEngineReopen(t, f)
			id := first.output.Entries[0].CoordinateID
			old := first.output.Entries[0].Actions[0].AttemptID
			originalMarker := selected.markers[old]
			if mode == "after_uncertain_disposal" {
				admin, r := openAdministrative(t.Context(), f.admission, f.store)
				if admin == nil {
					t.Fatal("disposal open", r)
				}
				candidate, r := prepareTestEndSelectedWork(t, admin, t.Context(), old, f.trust)
				if candidate == nil {
					t.Fatal("disposal preparation", r)
				}
				if ended, r := admin.selectCandidate(t.Context(), candidate); ended == nil {
					t.Fatal("disposal selection", r)
				}
				selected = publicationEngineReopen(t, f)
				if _, exists := selected.markers[old]; exists || f.session.root.WarningBits&(WarningPublicationOrderValue|WarningDiscardedExactEvidence) == 0 {
					t.Fatal("disposal did not retain warning/remove exact marker")
				}
			}
			retained := selected.coordinates[id]
			warnings := f.session.root.WarningBits
			if retained.OwnerState != contract.PublicationOwnerNone {
				t.Fatal("precondition owner", retained.OwnerState)
			}
			p.evidence = contract.PublicationUnproved
			p.onSend = nil
			if mode == "ack" {
				p.evidence = contract.PublicationRequestAcknowledged
			}
			if mode == "unclosed" {
				p.onSend = func() { f.store.casMode = "refused" }
			}
			next := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
			f.store.casMode = ""
			selected = publicationEngineReopen(t, f)
			coordinate := selected.coordinates[id]
			row := next.output.Entries[0].Actions[0]
			if row.AttemptID.IsZero() || row.AttemptID == old || coordinate.PossibleRemoteObject != 1 || coordinate.DeletionTargetRowDigest != retained.DeletionTargetRowDigest || coordinate.DeletionDestinationID != retained.DeletionDestinationID || coordinate.DeletionConsumerLocator != retained.DeletionConsumerLocator || coordinate.DeletionTargetContractID != retained.DeletionTargetContractID || coordinate.DeletionConfigContractID != retained.DeletionConfigContractID || coordinate.DeletionCredentialRouteContractID != retained.DeletionCredentialRouteContractID || coordinate.DeletionPayloadEncoding != retained.DeletionPayloadEncoding || coordinate.LastBindingIncarnationID != retained.LastBindingIncarnationID || coordinate.LastEntryIncarnationID != retained.LastEntryIncarnationID || f.session.root.WarningBits != warnings || coordinate.LateEffectRisk < retained.LateEffectRisk {
				t.Fatal("new create replaced retained safety relation", mode, row.Disposition, coordinate.OwnerState)
			}
			if mode == "ack" {
				if row.Disposition != contract.PublicationOutcomeAcknowledged || coordinate.OwnerState != contract.PublicationOwnerQualified || coordinate.OwnedBirthAttemptID != row.AttemptID || coordinate.LastValueAckAttemptID != row.AttemptID {
					t.Fatal("fresh ACK continuation", row, coordinate.OwnerState)
				}
			} else {
				if row.Disposition != contract.PublicationOutcomeUnknown || coordinate.OwnerState != contract.PublicationOwnerUncertainCreate {
					t.Fatal("fresh create did not retain uncertainty", row.Disposition, coordinate.OwnerState)
				}
				if mode == "unclosed" && selected.markers[row.AttemptID].State != contract.PublicationMayHaveEntered {
					t.Fatal("unclosed marker not preserved")
				}
			}
			if mode != "after_uncertain_disposal" && selected.markers[old] != originalMarker {
				t.Fatal("fresh create rewrote old no-effect")
			}
			if mode == "ack" {
				return
			}
			selectOutputConfiguration(t, f, f.session.currentEntryInputs(), &outputApplyInput{})
			publicationEngineReopen(t, f)
			input.deletes = []contract.ID{id}
			input.republish = map[contract.ID][]contract.ID{id: {row.AttemptID}}
			p.evidence = contract.PublicationRequestAcknowledged
			p.onSend = nil
			cleanup := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
			if cleanup.output.Entries[0].Actions[0].Disposition != contract.PublicationOutcomeAcknowledged || p.owners[len(p.owners)-1].input.Projection.Action != contract.PublicationDeleteReservedSlot || p.owners[len(p.owners)-1].input.Projection.UncertainCreateAttemptID != row.AttemptID {
				t.Fatal("fresh uncertain creation cannot be deleted", cleanup.state)
			}
			after := publicationEngineReopen(t, f)
			if after.markers[row.AttemptID].State != selected.markers[row.AttemptID].State || after.coordinates[id].PossibleRemoteObject != 1 || f.session.root.WarningBits != warnings {
				t.Fatal("delete erased earlier uncertainty or warning")
			}
		})
	}
}

// full_only: false
func TestPublicationRetirementFailurePersists(t *testing.T) {
	t.Run("ack_first_action_then_policy_and_value", func(t *testing.T) {
		f, input, p := publicationEngineFixture(t)
		hermeticPublicationTargetFacts(t, f, func(target *contract.OutputTarget) {
			target.Capabilities &^= contract.OutputCapabilityCreateWithValue
			target.Capabilities |= contract.OutputCapabilityCreateEmpty
			target.CreateValueBounds = contract.OutputPayloadBounds{}
			target.Capabilities &^= contract.OutputCapabilityCreateSetsPolicy
			target.Capabilities &^= contract.OutputCapabilityWriteSetsPolicy
			target.Capabilities |= contract.OutputCapabilityUpdatePolicy
		})
		p.configureOwner = func(o *publicationControlledOwner) {
			if len(p.owners) == 0 {
				o.retireError = errors.New("controlled disposal failure")
			}
		}
		got := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
		if got.state.Reason != CustodyUnavailable || got.state.Outcome != AdmissionRefused || len(p.owners) != 3 {
			t.Fatal("later action erased retirement failure", got.state, len(p.owners))
		}
		selected := publicationEngineReopen(t, f)
		for i, row := range got.output.Entries[0].Actions {
			if row.Disposition != contract.PublicationOutcomeAcknowledged || row.CoreReason != 0 || selected.markers[row.AttemptID].State != contract.PublicationAcknowledged || p.owners[i].armed != 1 || p.owners[i].sent != 1 || p.owners[i].retired != 1 {
				t.Fatal("retirement failure changed selected ACK/right", i, row)
			}
		}
	})
	for _, mode := range []string{"ack", "unknown", "failed_reserve", "unarmed"} {
		t.Run("earlier_coordinate_"+mode, func(t *testing.T) {
			f, input, p := publicationEngineFixture(t)
			entries := f.session.currentEntryInputs()
			a := publicationEngineTarget(entries[0].Name, "first")

			b := publicationEngineTarget(entries[0].Name, "second")

			selectOutputConfiguration(t, f, entries, &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "first", targets: []outputApplyTarget{a}}, {destinationID: "second", targets: []outputApplyTarget{b}}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"first", "second"}}}})
			pins := []publicationNamespace{{domain: f.session.root.Domain, service: "controlled-provider", physical: "first", premise: publicationRelationID(99)}, {domain: f.session.root.Domain, service: "controlled-provider", physical: "second", premise: publicationRelationID(99)}}
			f.admission.admission.publicationNamespaces = pins
			f.session.admission.publicationNamespaces = pins
			p.configureOwner = func(o *publicationControlledOwner) {
				if len(p.owners) == 0 {
					o.retireError = errors.New("controlled disposal failure")
					o.onRetire = func() { f.store.createMode = ""; f.store.casMode = "" }
					switch mode {
					case "unknown":
						o.evidence = contract.PublicationUnproved
					case "failed_reserve":
						f.store.createMode = "conflict"
					case "unarmed":
						f.store.casMode = "lost-after"
					}
				}
			}
			got := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
			if got.state.Reason != CustodyUnavailable || got.state.Outcome != AdmissionRefused || len(p.owners) != 2 {
				t.Fatal("later coordinate erased retirement failure", got.state, len(p.owners))
			}
			first := got.output.Entries[0].Actions[0]
			last := got.output.Entries[1].Actions[0]
			want := uint8(contract.PublicationOutcomeAcknowledged)
			sends := 1
			arms := 1
			if mode == "unknown" || mode == "unarmed" {
				want = contract.PublicationOutcomeUnknown
			}
			if mode == "failed_reserve" {
				want = contract.PublicationNotSent
				arms = 0
			}
			if mode == "failed_reserve" || mode == "unarmed" {
				sends = 0
				arms = 0
			}
			if first.Disposition != want || last.Disposition != contract.PublicationOutcomeAcknowledged || last.CoreReason != 0 || p.owners[0].armed != arms || p.owners[0].sent != sends || p.owners[0].retired != 1 || p.owners[1].armed != 1 || p.owners[1].sent != 1 || p.owners[1].retired != 1 {
				t.Fatal("mixed rights/results", mode, first.Disposition, last.Disposition)
			}
			if _, err := contract.EncodePublicationOutcomeVector(got.output); err != nil {
				t.Fatal("closed vector", err)
			}
		})
	}
}

// full_only: false
func TestPublicationSafeFreshReadd(t *testing.T) {
	for _, mode := range []string{"never_entered_same_slot", "fresh_physical_slot"} {
		t.Run(mode, func(t *testing.T) {
			f, input, p := publicationEngineFixture(t)
			originalPlan := publicationEnginePlan(t, f, input, p)
			var first contract.PublicationOutcomeVector
			if mode == "fresh_physical_slot" {
				first = originalPlan.execute(t.Context(), p.callbacks(), publicationEngineCurrent(f)).output
				publicationEngineReopen(t, f)
			}
			entries := f.session.currentEntryInputs()
			before, _ := f.session.currentOutputConfigurationForApply(t.Context())
			id := originalPlan.targets[0].coordinate
			selected, err := selectedPublicationRelation(f.session.selectedImage())
			if err != nil {
				t.Fatal(err)
			}
			old, present := selected.coordinates[id]
			if !present {
				t.Fatal("selected controlled publication coordinate missing")
			}
			selectOutputConfiguration(t, f, entries, &outputApplyInput{})
			slot := "publication"
			if mode == "fresh_physical_slot" {
				slot = "fresh"
			}
			target := publicationEngineTarget(entries[0].Name, slot)

			after := selectOutputConfiguration(t, f, entries, &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "publication", targets: []outputApplyTarget{target}}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"publication"}}}})
			if after.Bindings[0].IncarnationID == before.Bindings[0].IncarnationID {
				t.Fatal("readd reused binding")
			}
			if mode == "fresh_physical_slot" {
				pin := publicationNamespace{domain: f.session.root.Domain, service: "controlled-provider", physical: "fresh", premise: publicationRelationID(99)}
				f.admission.admission.publicationNamespaces = append(f.admission.admission.publicationNamespaces, pin)
				f.session.admission.publicationNamespaces = f.admission.admission.publicationNamespaces
			}
			owners := len(p.owners)
			got := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
			row := got.output.Entries[0].Actions[0]
			if row.Disposition != contract.PublicationOutcomeAcknowledged || row.AttemptID.IsZero() || row.AttemptID == originalPlan.targets[0].attempts[0] || len(p.owners) != owners+1 || p.owners[owners].input.Projection.BindingIncarnationID != after.Bindings[0].IncarnationID || p.owners[owners].sent != 1 || p.owners[owners].retired != 1 {
				t.Fatal("safe readd inherited equality/right", row.Disposition, got.state)
			}
			selected = publicationEngineReopen(t, f)
			if mode == "fresh_physical_slot" {
				old.BindingState, old.ActiveBindingIncarnationID = contract.PublicationBindingRetired, contract.ID{}
				if got.output.Entries[0].CoordinateID == id || !reflect.DeepEqual(selected.coordinates[id], old) || selected.markers[first.Entries[0].Actions[0].AttemptID].State != contract.PublicationAcknowledged {
					t.Fatal("fresh target changed old obligation")
				}
			}
		})
	}
}

// full_only: false
func TestPublicationReaddContinuesFixedActionChain(t *testing.T) {
	for _, chain := range []string{"create-empty-write", "create-empty-visibility-write"} {
		for _, condition := range []string{"fresh", "never-entered-readd"} {
			t.Run(chain+"/"+condition, func(t *testing.T) {
				f, input, p := publicationEngineFixture(t)
				hermeticPublicationTargetFacts(t, f, func(target *contract.OutputTarget) {
					target.Capabilities &^= contract.OutputCapabilityCreateWithValue
					target.Capabilities |= contract.OutputCapabilityCreateEmpty
					target.CreateValueBounds = contract.OutputPayloadBounds{}
					target.Capabilities |= contract.OutputCapabilityCreateSetsPolicy
					target.Capabilities |= contract.OutputCapabilityWriteSetsPolicy
				})
				wantActions := []uint8{contract.PublicationCreateEmpty, contract.PublicationWriteValue}
				if chain == "create-empty-visibility-write" {
					hermeticPublicationTargetFacts(t, f, func(target *contract.OutputTarget) {
						target.Capabilities &^= contract.OutputCapabilityCreateSetsPolicy
						target.Capabilities &^= contract.OutputCapabilityWriteSetsPolicy
						target.Capabilities |= contract.OutputCapabilityUpdatePolicy
					})
					wantActions = []uint8{contract.PublicationCreateEmpty, contract.PublicationUpdatePolicy, contract.PublicationWriteValue}
				}
				before, state := f.session.currentOutputConfigurationForApply(t.Context())
				if state.Outcome != 0 {
					t.Fatal(state)
				}
				if condition == "never-entered-readd" {
					entries := f.session.currentEntryInputs()
					selectOutputConfiguration(t, f, entries, &outputApplyInput{})
					target := before.Bindings[0].Targets[0]
					target.EntryIncarnationID = contract.ID{}
					selectOutputConfiguration(t, f, entries, &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "publication", destination: before.Bindings[0].Destination, targets: []outputApplyTarget{{entryName: entries[0].Name, target: target}}}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"publication"}}}})
				}
				after, state := f.session.currentOutputConfigurationForApply(t.Context())
				if state.Outcome != 0 || condition == "never-entered-readd" && before.Bindings[0].IncarnationID == after.Bindings[0].IncarnationID {
					t.Fatal("remove/readd did not select a fresh binding", state)
				}
				plan := publicationEnginePlan(t, f, input, p)
				if len(plan.targets) != 1 || !slices.Equal(plan.targets[0].actions, wantActions) {
					t.Fatal("fixed preflight omitted a required action")
				}
				// Execute this one admitted plan. A second plan cannot supply a new
				// continuation right after the acknowledged create.
				got := plan.execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
				if got.summary != contract.PublicationSummaryComplete || len(p.owners) != len(wantActions) {
					t.Fatalf("fixed chain stopped after readd: summary=%d state=%+v owners=%d actions=%+v", got.summary, got.state, len(p.owners), got.output.Entries[0].Actions)
				}
				selected := publicationEngineReopen(t, f)
				coordinate := selected.coordinates[plan.targets[0].coordinate]
				rows := got.output.Entries[0].Actions
				if coordinate.ActiveBindingIncarnationID != after.Bindings[0].IncarnationID || coordinate.LastBindingIncarnationID != after.Bindings[0].IncarnationID || coordinate.OwnedBirthAttemptID != rows[0].AttemptID {
					t.Fatal("selected ownership did not retain the exact readded binding and birth")
				}
				for i, action := range wantActions {
					row, owner := rows[i], p.owners[i]
					marker, present := selected.markers[row.AttemptID]
					if row.Action != action || row.Disposition != contract.PublicationOutcomeAcknowledged || row.AttemptID != plan.targets[0].attempts[i] || !present || marker.State != contract.PublicationAcknowledged || marker.Projection.BindingIncarnationID != after.Bindings[0].IncarnationID || marker.Projection.Action != action || owner.prepared != 1 || owner.armed != 1 || owner.sent != 1 || owner.retired != 1 {
						t.Fatalf("action %d did not complete exactly once under the fixed plan", action)
					}
				}
			})
		}
	}
}

// full_only: false
func TestPublicationFreshCreateRefusesChangedFrozenRelation(t *testing.T) {
	f, input, p := publicationEngineFixture(t)
	p.evidence = contract.PublicationQualifiedNoEffect
	first := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
	before := publicationEngineReopen(t, f)
	id := first.output.Entries[0].CoordinateID
	entries := f.session.currentEntryInputs()
	target := publicationEngineTarget(entries[0].Name, "publication")

	target.target.ConsumerLocator = "changed-consumer"
	selectOutputConfiguration(t, f, entries, &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "publication", targets: []outputApplyTarget{target}}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"publication"}}}})
	owners := len(p.owners)
	revision := f.session.head.Core.Revision
	got := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
	row := got.output.Entries[0].Actions[0]
	after := publicationEngineReopen(t, f)
	if row.Disposition != contract.PublicationNotSent || !row.AttemptID.IsZero() || len(p.owners) != owners || f.session.head.Core.Revision != revision || !reflect.DeepEqual(after.coordinates[id], before.coordinates[id]) {
		t.Fatal("fresh create replaced frozen relation", got.state, row.Disposition)
	}
}

// full_only: false
func TestPublicationEncodingChangeRetainsUnknown(t *testing.T) {
	f, input, p := publicationEngineFixture(t)
	first := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
	if first.summary != contract.PublicationSummaryComplete {
		t.Fatal("raw ownership create", first.state)
	}
	selected := publicationEngineReopen(t, f)
	coordinateID := first.output.Entries[0].CoordinateID
	birth := selected.coordinates[coordinateID]
	canonical, access := f.session.currentEntryInputs(), f.session.root.CurrentAccess
	output := func(encoding string) *outputApplyInput {
		target := publicationEngineTarget(canonical[0].Name, "publication")
		target.target.PayloadEncoding = hermeticOutputEncoding(encoding)
		return &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "publication", targets: []outputApplyTarget{target}}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"publication"}}}}
	}
	encodedInput := slices.Clone(canonical)
	encodedInput[0].OutputEncoding = contract.OutputEncodingBase64
	selectOutputConfiguration(t, f, encodedInput, output("base64"))
	p.evidence = contract.PublicationUnproved
	encoded := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
	if encoded.summary != contract.PublicationSummaryUnknown || encoded.output.Entries[0].CoordinateID != coordinateID || encoded.output.Entries[0].Actions[0].Action != contract.PublicationWriteValue {
		t.Fatal("encoded write did not retain unknown evidence", encoded.state)
	}
	selected = publicationEngineReopen(t, f)
	unknownID := encoded.output.Entries[0].Actions[0].AttemptID
	unknown := selected.markers[unknownID]
	if unknown.State != contract.PublicationUnknown || unknown.Projection.TargetRowDigest == birth.DeletionTargetRowDigest {
		t.Fatal("unknown write did not bind the changed encoding")
	}
	selectOutputConfiguration(t, f, canonical, output("raw"))
	owners, checks := len(p.owners), p.checks
	creates, cas, signs := f.store.creates, f.store.cas, f.trust.signs
	blocked := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
	if blocked.summary != contract.PublicationSummaryUnknown || len(blocked.output.Entries) != 1 || blocked.output.Entries[0].CoordinateID != coordinateID || len(blocked.output.Entries[0].Actions) != 1 || blocked.output.Entries[0].Actions[0].Disposition != contract.PublicationOutcomeUnknown || blocked.output.Entries[0].Actions[0].AttemptID != unknownID || len(p.owners) != owners || p.checks != checks || f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs {
		t.Fatal("return to raw encoding erased the blocker or acquired new rights", blocked.state)
	}
	selected = publicationEngineReopen(t, f)
	if selected.markers[unknownID] != unknown || !reflect.DeepEqual(f.session.currentEntryInputs(), canonical) || !reflect.DeepEqual(f.session.root.CurrentAccess, access) {
		t.Fatal("encoding change modified unknown evidence or canonical state")
	}
	input.republish = map[contract.ID][]contract.ID{coordinateID: {unknownID}}
	p.evidence = contract.PublicationRequestAcknowledged
	republished := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
	row := republished.output.Entries[0].Actions[0]
	if republished.summary != contract.PublicationSummaryComplete || row.Action != contract.PublicationWriteValue || row.Disposition != contract.PublicationOutcomeAcknowledged || row.AttemptID == unknownID || row.LateWriteRisk != 1 || !slices.Equal(row.BlockerIDs, []contract.ID{unknownID}) || len(p.owners) != owners+1 {
		t.Fatal("encoding republish did not bind the exact retained blocker", republished.state)
	}
	selected = publicationEngineReopen(t, f)
	coordinate := selected.coordinates[coordinateID]
	if selected.markers[unknownID] != unknown || coordinate.ActiveBindingIncarnationID != birth.ActiveBindingIncarnationID || coordinate.OwnedBirthAttemptID != birth.OwnedBirthAttemptID || coordinate.OwnedInstanceDigest != birth.OwnedInstanceDigest || coordinate.DeletionTargetRowDigest != birth.DeletionTargetRowDigest || coordinate.DeletionPayloadEncoding != contract.OutputEncodingRaw || !reflect.DeepEqual(f.session.currentEntryInputs(), canonical) || !reflect.DeepEqual(f.session.root.CurrentAccess, access) {
		t.Fatal("fresh raw ACK erased earlier uncertainty, ownership or canonical facts")
	}
	for _, owner := range p.owners {
		if owner.prepared != 1 || owner.armed != 1 || owner.sent != 1 || owner.retired != 1 {
			t.Fatal("encoding attempt did not use and retire exactly one private owner")
		}
	}
	input.republish = nil
	owners = len(p.owners)
	again := publicationEnginePlan(t, f, input, p).execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
	if again.summary != contract.PublicationSummaryUnknown || again.output.Entries[0].Actions[0].AttemptID != unknownID || len(p.owners) != owners {
		t.Fatal("later ACK incorrectly removed unknown precedence", again.state)
	}
}

// full_only: false
func TestPublicationGroupEncodedLimitPrecedesPrivateWork(t *testing.T) {
	for _, maximum := range []uint32{65536, 48000} {
		for _, secret := range []bool{false, true} {
			t.Run(strconv.FormatUint(uint64(maximum), 10)+"/secret="+strconv.FormatBool(secret), func(t *testing.T) {
				env := memoryScenarioEnvironment(t)
				initial := newEnvironmentFixture(t, t.Context(), env, nil, false)
				entries := []ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "alpha", Recipients: []contract.ID{initial.session.admission.recipient}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte{0}}, {InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "omega", Recipients: []contract.ID{initial.session.admission.recipient}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte{0}}}
				if secret {
					entries[0] = suppliedSecret(t, env, "alpha", "group initial alpha", custody.StandardValue)
					entries[1] = suppliedSecret(t, env, "omega", "group initial omega", custody.StandardValue)
				}
				// Seed values with ordinary apply; the selected empty output has no output transition.
				parent := admitSuppliedComparison(t, initial.session, env.Custody, entries)
				comparison, state := initial.session.Compare(t.Context(), entries, parent)
				if comparison == nil || state.Outcome != ObservedCurrent {
					t.Fatal("group initial value comparison", state)
				}
				candidate, state := initial.session.Prepare(t.Context(), comparison, admit(t, initial.session, comparison), env.Trust)
				if candidate == nil || state.Outcome != ObservedCurrent {
					t.Fatal("group initial value preparation", state)
				}
				selected, state := initial.session.selectCandidate(t.Context(), candidate)
				if selected == nil || state.Outcome != ObservedCurrent {
					t.Fatal("group initial value selection", state)
				}
				env.Custody.RetireApply()
				initial.session = generatedLifecycleReopen(t, t.Context(), selected, env.Store)
				f := &fixture{store: env.Store.(*memoryStore), trust: env.Trust.(*fixtureTrust), admission: initial.admission, session: initial.session}
				// Configuration targets are ordered by authenticated entry incarnation.
				// Assign the overflow to the later target, independent of random IDs.
				first, later := 0, 1
				if slices.Compare(f.session.valueEntry(f.session.root.Names[0].Slot).Incarnation[:], f.session.valueEntry(f.session.root.Names[1].Slot).Incarnation[:]) > 0 {
					first, later = later, first
				}
				fitRaw, overflowRaw := uint32(49152), uint32(49153)
				fitEncoded, overflowEncoded := uint32(65536), uint32(65540)
				if maximum == 48000 {
					fitRaw, overflowRaw, fitEncoded, overflowEncoded = 36000, 36001, 48000, 48004
				}
				if secret {
					overflowRaw, fitEncoded, overflowEncoded = 65536, 40, 87384
					entries[first] = suppliedSecret(t, env, entries[first].Name, "group fitting secret", custody.StandardValue)
					entries[later] = suppliedSecret(t, env, entries[later].Name, "group overflowing secret", custody.MaximumValue)
				} else {
					entries[first].InputBytes = bytes.Repeat([]byte{0xa5}, int(fitRaw))
					entries[later].InputBytes = bytes.Repeat([]byte{0x5a}, int(overflowRaw))
				}
				output := func(encoding string) *outputApplyInput {
					targets := []outputApplyTarget{publicationEngineTarget(entries[0].Name, "group-alpha"), publicationEngineTarget(entries[1].Name, "group-omega")}
					for i := range targets {
						targets[i].target.PayloadEncoding = hermeticOutputEncoding(encoding)
						targets[i].target.CreateValueBounds.Maximum, targets[i].target.WriteValueBounds.Maximum = maximum, maximum
					}
					return &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "group", targets: targets}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"group"}}}, groups: [][]string{{entries[0].Name, entries[1].Name}}}
				}
				namespaces := []publicationNamespace{{domain: env.Domain, service: "controlled-provider", physical: "group-alpha", premise: fixtureID(env.Domain, "group namespace alpha")}, {domain: env.Domain, service: "controlled-provider", physical: "group-omega", premise: fixtureID(env.Domain, "group namespace omega")}}
				f.admission.admission.publicationNamespaces, f.session.admission.publicationNamespaces = namespaces, namespaces
				selectEncoding := func(encoding string) {
					f.session = selectAdmittedOutputConfiguration(t, t.Context(), f.session, env, env.Custody, entries, output(encoding))
					f.admission = OpenContext{admission: &f.session.admission}
				}
				selectEncoding("raw")
				p := newPublicationControlledPrivate()
				sends := 0
				p.onSend = func() { sends++ }
				input := publicationInput{names: []string{entries[0].Name, entries[1].Name}, acting: f.session.admission.recipient, deadline: time.Now().Add(30 * time.Second)}
				if overflowRaw <= maximum {
					raw := publicationEnginePlan(t, f, input, p)
					if len(raw.targets) != 2 {
						t.Fatal("raw control did not include the complete group")
					}
					got := raw.execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
					if got.summary != contract.PublicationSummaryComplete || len(p.owners) != 2 || sends != 2 {
						t.Fatal("admissible raw control lost effects", got.state)
					}
					for _, owner := range p.owners {
						if owner.prepared != 1 || owner.armed != 1 || owner.sent != 1 || owner.retired != 1 {
							t.Fatal("raw control custody lifecycle")
						}
					}
					publicationEngineReopen(t, f)
				}
				selectEncoding("base64")
				configuration, result := f.session.currentOutputConfigurationForApply(t.Context())
				if result.Outcome != 0 || len(configuration.Groups) != 1 || len(configuration.Groups[0]) != 2 || len(configuration.Bindings) != 1 || len(configuration.Bindings[0].Targets) != 2 || configuration.Bindings[0].Targets[0].EntryIncarnationID != f.session.valueEntry(f.session.root.Names[first].Slot).Incarnation {
					t.Fatal("fixture did not place the fitting target before the group overflow", result)
				}
				if fitEncoded > maximum || overflowEncoded <= maximum {
					t.Fatal("independent group length literals do not straddle the limit")
				}
				callbacks := p.callbacks()
				originalActions, originalCheck := callbacks.Actions, callbacks.Check
				var passiveTargets []contract.ID
				var checkedLengths []uint32
				callbacks.Actions = func(ctx context.Context, target publicationExecutionInput) (publicationActionFacts, error) {
					passiveTargets = append(passiveTargets, target.Target.EntryIncarnationID)
					return originalActions(ctx, target)
				}
				callbacks.Check = func(ctx context.Context, in publicationActionCheckInput) (publicationActionCheckFacts, error) {
					checkedLengths = append(checkedLengths, in.PayloadLength)
					return originalCheck(ctx, in)
				}
				creates, cas, signs := f.store.creates, f.store.cas, f.trust.signs
				owners, effects := len(p.owners), sends
				publicCalls, privateCalls := env.Custody.Calls()
				selectedBody, prepared := contract.Hash(f.session.body), f.session.prepared
				before, err := selectedPublicationRelation(f.session.selectedImage())
				if err != nil {
					t.Fatal(err)
				}
				recorder := newPublicationDiagnosticCapture()
				ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder.recorder))
				plan, refusal := f.session.planPublication(ctx, input, callbacks)
				afterPublic, afterPrivate := env.Custody.Calls()
				if plan != nil || refusal.Reason != CapacityExceeded || len(passiveTargets) != 2 || passiveTargets[0] != configuration.Bindings[0].Targets[0].EntryIncarnationID || passiveTargets[1] != configuration.Bindings[0].Targets[1].EntryIncarnationID || !slices.Equal(checkedLengths, []uint32{fitEncoded}) {
					t.Fatal("later encoded overflow was not refused after the fitting target's passive check", refusal, passiveTargets, checkedLengths)
				}
				after, err := selectedPublicationRelation(f.session.selectedImage())
				if err != nil || !reflect.DeepEqual(before, after) || f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs || len(p.owners) != owners || sends != effects || publicCalls != afterPublic || privateCalls != afterPrivate || contract.Hash(f.session.body) != selectedBody || f.session.prepared != prepared {
					t.Fatal("complete group overflow caused private work, effects, selection or ownership changes", err)
				}
				assertNativePublicationNoPrivateWork(t, recorder)
			})
		}
	}
}

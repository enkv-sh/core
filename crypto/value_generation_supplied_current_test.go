package crypto

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

// Keep one real generated sibling and independently sealed current Supplied
// entries. The existing graph helper validates the complete declaration and
// effect graph after every source addition. Shared tests own the connected
// reservation, original producer result, checkpoint and selecting Final path.
func generatedSuppliedCollectionFixture(t *testing.T, count int) (*generatedAdmission, []generatedMembershipSelection, []byte, *consumerTestRoute) {
	t.Helper()
	f := generatedRuntimeEffectFixture(t, false)
	authority := f.reservation.Session.Bindings[applyBindingIndex(f.reservation.Session.Bindings, f.base.control.AuthorityRecipientID)]
	root, err := contract.DecodeRef(f.compare.Context.PredecessorRootRef[:], contract.CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := contract.DecodeSealedInputEnvelope(f.base.q.SealedInputs[0].EnvelopeBytes)
	if err != nil {
		t.Fatal(err)
	}
	var carriers []generatedMembershipSelection
	var entries []generatedCandidateEntry
	public := f.reservation.Session.BeforePublic
	for i := range count {
		name := fmt.Sprintf("supplied-%03d", i)
		id := func(suffix string) contract.ID { return consumerID(name + " " + suffix) }
		core := contract.ValueCore{Schema: contract.CanonicalSchema, Profile: 2, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(),
			DomainID: public.Domain, Name: name, ValueSource: contract.Supplied, EntryIncarnationID: id("incarnation"), ValueStateID: id("value"),
			OriginSnapshotID: id("snapshot"), OriginTransitionID: id("transition"), DataKeyID: id("data"), DataKeyEpoch: 1,
			CommitmentKeyID: id("commitment"), CommitmentKeyEpoch: 1, ContentLength: 3, InputEncoding: contract.InputEncodingRaw, RetainedLength: 3}
		payload, keys, err := custody.SealValue(core, []byte("old"))
		if err != nil {
			t.Fatal(err)
		}
		wrapCore, err := custody.ValueWrapCore(core, authority)
		if err != nil {
			clear(keys)
			t.Fatal(err)
		}
		wrap, err := custody.Wrap(wrapCore, authority.Binding, keys)
		clear(keys)
		if err != nil {
			t.Fatal(err)
		}
		value, err := contract.EncodeCanonicalPayload(payload)
		if err != nil {
			t.Fatal(err)
		}
		entry := contract.ValueEntry{Name: name, Incarnation: core.EntryIncarnationID, ValueState: core.ValueStateID,
			OriginSnapshot: core.OriginSnapshotID, OriginTransition: core.OriginTransitionID, ValueSource: contract.Supplied,
			ConfidentialityClass: contract.Secret, ValueBytes: value, Recipients: []contract.ID{authority.SubjectID}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len(value) - contract.CanonicalPayloadOverhead), RetainedLength: uint32(len(value) - contract.CanonicalPayloadOverhead)}
		slot := uint16(i + 1)
		digest, err := contract.PublicValueEntryDigest(public.Domain, slot, entry)
		if err != nil {
			t.Fatal(err)
		}
		public.Rows = append(public.Rows, contract.PublicStateRow{Slot: slot, Name: name, EntryDigest: digest})
		entries = append(entries, generatedCandidateEntry{Slot: slot, Entry: entry})
		carriers = append(carriers, generatedMembershipSelection{Selection: contract.ConsumerSelection{
			DomainID: public.Domain, SnapshotID: root.Object, HEADDigest: f.compare.Context.PredecessorHEADDigest, AccessRoot: f.compare.Context.CurrentAccessRoot,
			Root: root, HEADRevision: consumerID("generated predecessor revision"), HEADToken: contract.Token{Family: contract.GCP, Value: "1"},
			Slot: slot, EntryDigest: digest, Entry: entry, Core: core, Payload: payload, Binding: authority,
			Access: contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: contract.ValueMaterialKind, MaterialID: entry.ValueState,
				MaterialContextDigest: wrapCore.MaterialContextDigest, PackageCheck: payload.PackageCheck, Wraps: []contract.WrapRow{wrap}}}})
		sourceCore := envelope.Core
		sourceCore.Name, sourceCore.SourceID, sourceCore.DataKeyID, sourceCore.ContentLength = name, id("source"), id("source data"), 3
		sourceCore.RetainedLength = 3
		sealed, err := custody.SealInput(sourceCore, authority, []byte("old"))
		if err != nil {
			t.Fatal(err)
		}
		body, err := contract.EncodeSealedInputEnvelope(sealed)
		if err != nil {
			t.Fatal(err)
		}
		readers := []contract.ID{authority.SubjectID, consumerID("reader")}
		slices.SortFunc(readers, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		generatedAddDeclarationSource(t, &f, contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationSealed, Name: name, Recipients: readers, Payload: body},
			contract.GeneratorValueEntryPlan{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorValueEntryPlanSchema, Slot: slot, Name: name, ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret,
				EntryIncarnationID: entry.Incarnation, ChangeMask: contract.GeneratorValueChangeMembership})
	}
	output := generatedEmptyOutputWitness(t, &public, entries, nil)
	graph, err := contract.DecodeGeneratorPlanBundle(f.graph)
	if err != nil {
		t.Fatal(err)
	}
	a := &generatedAdmission{request: f.compare, control: f.base.control, bindings: f.reservation.Session.Bindings, graph: graph, before: public,
		purpose: generatedPurposeState{output: output, final: &generatedFinalPreparationState{}}, routeID: f.base.route.CredentialRoute()}
	for _, binding := range a.bindings {
		digest, err := contract.PublicBindingDigest(binding.Binding)
		if err != nil {
			t.Fatal(err)
		}
		a.bindingDigests = append(a.bindingDigests, digest)
	}
	declaration, err := contract.InspectGeneratorDeclaration(f.declaration)
	if err != nil {
		t.Fatal(err)
	}
	for i := range graph.ValueEntryPlans {
		entry, _, err := declaration.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		var readers []contract.ID
		for j := 0; j < len(entry.RecipientIDs); j += 32 {
			readers = append(readers, contract.ID(entry.RecipientIDs[j:j+32]))
		}
		a.purpose.final.plan.recipients = append(a.purpose.final.plan.recipients, readers)
	}
	for _, carrier := range carriers {
		if _, _, ok := checkConsumerSelection(carrier.Selection, contract.GCP); !ok {
			t.Fatal("supplied capacity fixture selection is invalid")
		}
	}
	return a, carriers, f.declaration, f.base.route
}

// full_only: false
func TestGeneratedSuppliedCurrentCollectionUsesTotalEntryBound(t *testing.T) {
	for _, count := range []int{128, 129} {
		t.Run(fmt.Sprintf("supplied%d-plus-one-generated", count), func(t *testing.T) {
			a, carriers, declaration, route := generatedSuppliedCollectionFixture(t, count)
			a.purpose.reservation = &generatedReservationState{plan: a.purpose.final.plan}
			a.purpose.final = nil
			input := make([]contract.ConsumerSelection, len(carriers))
			for i, carrier := range carriers {
				input[i] = carrier.Selection
			}
			public, private := route.publicCalls, route.privateCalls
			if !a.admitCurrentValues(input, declaration) || len(a.purpose.reservation.plan.currentValues) != count {
				t.Fatal("valid Supplied current collection used the Generated-only bound", count)
			}
			for i, got := range a.purpose.reservation.plan.currentValues {
				if !reflect.DeepEqual(got, input[i]) {
					t.Fatal("current collection changed exact supplied selection", i)
				}
			}
			if route.publicCalls != public || route.privateCalls != private {
				t.Fatal("current collection admission performed key work")
			}
			a.clear()
		})
	}
}

// full_only: false
func TestGeneratedSuppliedCollectionsRefuseAboveTotalEntryBound(t *testing.T) {
	a, _, declaration, route := generatedSuppliedCollectionFixture(t, 1)
	public, private := route.publicCalls, route.privateCalls
	if a.admitMembership(make([]generatedMembershipSelection, contract.CryptoMaxValueEntries+1), nil) || len(a.purpose.final.membership) != 0 {
		t.Fatal("membership collection admitted more than the complete value-entry bound")
	}
	a.purpose.reservation = &generatedReservationState{plan: a.purpose.final.plan}
	a.purpose.final = nil
	if a.admitCurrentValues(make([]contract.ConsumerSelection, contract.CryptoMaxValueEntries+1), declaration) || len(a.purpose.reservation.plan.currentValues) != 0 {
		t.Fatal("Supplied current collection admitted more than the complete value-entry bound")
	}
	if route.publicCalls != public || route.privateCalls != private {
		t.Fatal("over-limit collection reached key work")
	}
	a.clear()
}

// generatedCurrentConversionSelection adds the old Supplied value at the
// Generated output's slot. Its new incarnation makes this a source conversion,
// so the graph still has one create and needs no old Generated retirement.
func generatedCurrentConversionSelection(t *testing.T, a *generatedAdmission, prototype contract.ConsumerSelection) contract.ConsumerSelection {
	t.Helper()
	plan := a.graph.ValueEntryPlans[slices.IndexFunc(a.graph.ValueEntryPlans, func(p contract.GeneratorValueEntryPlan) bool { return p.ValueSource == contract.Generated })]
	readers := []contract.ID{a.control.AuthorityRecipientID, consumerID("reader")}
	selected := generatedCurrentFixtureSelection(t, a, prototype, plan.Name, plan.Slot, consumerID("old converted incarnation"), readers)
	a.before.Rows = append(a.before.Rows, contract.PublicStateRow{Slot: selected.Slot, Name: selected.Entry.Name, EntryDigest: selected.EntryDigest})
	var entries []generatedCandidateEntry
	for i, row := range a.purpose.output.EntriesBefore {
		entry, err := contract.DecodeValueEntry(a.purpose.output.EntryBodies[i])
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, generatedCandidateEntry{Slot: row.Slot, Entry: entry})
	}
	entries = append(entries, generatedCandidateEntry{Slot: selected.Slot, Entry: selected.Entry})
	slices.SortFunc(entries, func(x, y generatedCandidateEntry) int {
		return bytes.Compare([]byte(x.Entry.Name), []byte(y.Entry.Name))
	})
	slices.SortFunc(a.before.Rows, func(x, y contract.PublicStateRow) int { return bytes.Compare([]byte(x.Name), []byte(y.Name)) })
	a.purpose.output = generatedEmptyOutputWitness(t, &a.before, entries, nil)
	return selected
}

func generatedCurrentFixtureSelection(t *testing.T, a *generatedAdmission, prototype contract.ConsumerSelection, name string, slot uint16, incarnation contract.ID, readers []contract.ID) contract.ConsumerSelection {
	t.Helper()
	core := prototype.Core
	core.Name, core.EntryIncarnationID = name, incarnation
	core.ValueStateID, core.OriginSnapshotID, core.OriginTransitionID = consumerID(name+" old current value"), consumerID(name+" old current snapshot"), consumerID(name+" old current transition")
	core.DataKeyID, core.CommitmentKeyID = consumerID(name+" old current data"), consumerID(name+" old current commitment")
	payload, keys, err := custody.SealValue(core, []byte("old"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keys[:cap(keys)])
	entry := prototype.Entry
	entry.Name, entry.Incarnation, entry.ValueState = name, incarnation, core.ValueStateID
	entry.OriginSnapshot, entry.OriginTransition = core.OriginSnapshotID, core.OriginTransitionID
	entry.Recipients = slices.Clone(readers)
	slices.SortFunc(entry.Recipients, func(x, y contract.ID) int { return bytes.Compare(x[:], y[:]) })
	entry.ValueBytes, err = contract.EncodeCanonicalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	access := contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: contract.ValueMaterialKind, MaterialID: entry.ValueState, PackageCheck: payload.PackageCheck}
	for _, binding := range a.bindings {
		if binding.SubjectKind == contract.OrdinaryWrapSubject && !slices.Contains(readers, binding.SubjectID) {
			continue
		}
		wrapCore, err := custody.ValueWrapCore(core, binding)
		if err != nil {
			t.Fatal(err)
		}
		access.MaterialContextDigest = wrapCore.MaterialContextDigest
		wrap, err := custody.Wrap(wrapCore, binding.Binding, keys)
		if err != nil {
			t.Fatal(err)
		}
		access.Wraps = append(access.Wraps, wrap)
	}
	selected := prototype
	selected.Slot, selected.Entry, selected.Core, selected.Payload, selected.Access = slot, entry, core, payload, access
	selected.EntryDigest, err = contract.PublicValueEntryDigest(selected.DomainID, slot, entry)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := checkConsumerSelection(selected, a.control.Provider); !ok {
		t.Fatal("old-current fixture selection")
	}
	return selected
}

// full_only: false
func TestGeneratedCurrentValuesCollectionAdmitsAllCurrentSlots(t *testing.T) {
	a, carriers, declaration, route := generatedSuppliedCollectionFixture(t, 511)
	input := make([]contract.ConsumerSelection, 0, 512)
	for _, carrier := range carriers {
		input = append(input, carrier.Selection)
	}
	input = append(input, generatedCurrentConversionSelection(t, a, input[0]))
	slices.SortFunc(input, func(x, y contract.ConsumerSelection) int { return int(x.Slot) - int(y.Slot) })
	view, err := contract.InspectGeneratorDeclaration(declaration)
	if err != nil || contract.ValidateGeneratorEffectGraph(a.graph) != nil || contract.ValidateGeneratorDeclarationGraph(view, a.graph) != nil || a.purpose.output.Inspect(a.before) != nil {
		t.Fatal("complete 512-slot graph and predecessor", err)
	}
	public, private := route.publicCalls, route.privateCalls
	if !a.admitCurrentValues(input, declaration) || len(a.purpose.final.plan.currentValues) != 512 {
		t.Fatal("512 old current selections refused")
	}
	for _, selected := range a.purpose.final.plan.currentValues {
		at := slices.IndexFunc(input, func(row contract.ConsumerSelection) bool { return row.Slot == selected.Slot })
		if at < 0 || !reflect.DeepEqual(selected, input[at]) {
			t.Fatal("512-slot selection changed")
		}
	}
	if route.publicCalls != public || route.privateCalls != private {
		t.Fatal("collection admission performed key work")
	}
	a.purpose.clear()
}

// full_only: false
func TestGeneratedMixedCurrentSelectionsOwnAndClearTheirBuffers(t *testing.T) {
	for _, damage := range []string{"exact", "missing Generated", "missing Sealed", "stale Generated body", "stale Sealed body", "wrong Generated binding", "wrong Sealed binding"} {
		t.Run(damage, func(t *testing.T) {
			a, carriers, declaration, route := generatedSuppliedCollectionFixture(t, 2)
			input := []contract.ConsumerSelection{carriers[0].Selection, carriers[1].Selection}
			input = append(input, generatedCurrentConversionSelection(t, a, input[0]))
			// The first Sealed row loses an additional registered ordinary recipient.
			extra := a.bindings[applyBindingIndex(a.bindings, a.control.AuthorityRecipientID)]
			extra.SubjectID = consumerID("extra old current reader")
			extra.Binding.BindingID, extra.Binding.BindingIncarnationID = consumerID("extra old binding"), consumerID("extra old binding incarnation")
			a.bindings = append(a.bindings, extra)
			slices.SortFunc(a.bindings, func(x, y contract.BindingTableRow) int {
				if x.SubjectKind != y.SubjectKind {
					return int(x.SubjectKind) - int(y.SubjectKind)
				}
				return bytes.Compare(x.SubjectID[:], y.SubjectID[:])
			})
			a.bindingDigests = nil
			for _, binding := range a.bindings {
				digest, err := contract.PublicBindingDigest(binding.Binding)
				if err != nil {
					t.Fatal(err)
				}
				a.bindingDigests = append(a.bindingDigests, digest)
			}
			readers := []contract.ID{a.control.AuthorityRecipientID, consumerID("reader"), extra.SubjectID}
			input[0] = generatedCurrentFixtureSelection(t, a, input[0], input[0].Entry.Name, input[0].Slot, input[0].Entry.Incarnation, readers)
			at := slices.IndexFunc(a.before.Rows, func(row contract.PublicStateRow) bool { return row.Slot == input[0].Slot })
			a.before.Rows[at].EntryDigest = input[0].EntryDigest
			a.purpose.output.EntriesBefore[at].EntryDigest = input[0].EntryDigest
			a.purpose.output.EntriesBefore[at].Recipients = slices.Clone(input[0].Entry.Recipients)
			body, err := contract.EncodeValueEntry(input[0].Entry)
			if err != nil {
				t.Fatal(err)
			}
			a.purpose.output.EntryBodies[at] = body
			at = slices.IndexFunc(a.graph.ValueEntryPlans, func(p contract.GeneratorValueEntryPlan) bool { return p.Slot == input[0].Slot })
			a.graph.ValueEntryPlans[at].ChangeMask |= contract.GeneratorValueChangeContent
			a.graph.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(a.graph.Header, a.graph.ValueEntryPlans, a.graph.Lineages, a.graph.Edges)
			if err != nil {
				t.Fatal(err)
			}
			view, err := contract.InspectGeneratorDeclaration(declaration)
			if err != nil || contract.ValidateGeneratorEffectGraph(a.graph) != nil || contract.ValidateGeneratorDeclarationGraph(view, a.graph) != nil || a.purpose.output.Inspect(a.before) != nil {
				t.Fatal("mixed graph and predecessor", err)
			}
			slices.SortFunc(input, func(x, y contract.ConsumerSelection) int { return int(x.Slot) - int(y.Slot) })
			target := 0
			if damage == "missing Sealed" || damage == "stale Sealed body" || damage == "wrong Sealed binding" {
				target = 1
			}
			switch damage {
			case "missing Generated", "missing Sealed":
				input = slices.Delete(input, target, target+1)
			case "stale Generated body", "stale Sealed body":
				input[target].Entry.ValueBytes = bytes.Clone(input[target].Entry.ValueBytes)
				input[target].Entry.ValueBytes[len(input[target].Entry.ValueBytes)-1] ^= 1
			case "wrong Generated binding", "wrong Sealed binding":
				input[target].Binding.Binding.BindingSerial++
			}
			public, private := route.publicCalls, route.privateCalls
			admitted := a.admitCurrentValues(input, declaration)
			if admitted != (damage == "exact") {
				t.Fatal("mixed old-current admission", damage, admitted)
			}
			if route.publicCalls != public || route.privateCalls != private {
				t.Fatal("mixed admission reached key work")
			}
			if !admitted {
				a.purpose.clear()
				return
			}
			if len(a.purpose.final.plan.currentValues) != 3 {
				t.Fatal("changed Generated, changed Sealed and unchanged Sealed must all be selected")
			}
			var owned [][]byte
			caller := make(map[uint16][][]byte)
			for _, selected := range a.purpose.final.plan.currentValues {
				at := slices.IndexFunc(input, func(row contract.ConsumerSelection) bool { return row.Slot == selected.Slot })
				expected := bytes.Clone(selected.Entry.ValueBytes)
				input[at].Entry.ValueBytes[0] ^= 1
				if !bytes.Equal(selected.Entry.ValueBytes, expected) {
					t.Fatal("current payload borrows caller backing")
				}
				input[at].Entry.ValueBytes[0] ^= 1
				if len(selected.Payload.Ciphertext) == 0 || &selected.Payload.Ciphertext[0] != &selected.Entry.ValueBytes[len(selected.Entry.ValueBytes)-len(selected.Payload.Ciphertext)] {
					t.Fatal("payload view is not the owned Entry span")
				}
				owned = append(owned, selected.Entry.ValueBytes[:cap(selected.Entry.ValueBytes)])
				caller[selected.Slot] = [][]byte{bytes.Clone(input[at].Entry.ValueBytes)}
				for j, wrap := range selected.Access.Wraps {
					expected := bytes.Clone(wrap.RSACiphertext)
					input[at].Access.Wraps[j].RSACiphertext[0] ^= 1
					if !bytes.Equal(wrap.RSACiphertext, expected) {
						t.Fatal("current access borrows caller backing")
					}
					input[at].Access.Wraps[j].RSACiphertext[0] ^= 1
					owned = append(owned, wrap.RSACiphertext[:cap(wrap.RSACiphertext)])
					caller[selected.Slot] = append(caller[selected.Slot], bytes.Clone(input[at].Access.Wraps[j].RSACiphertext))
				}
			}
			a.purpose.clear()
			for _, buffer := range owned {
				if !bytes.Equal(buffer, make([]byte, len(buffer))) {
					t.Fatal("current-value disposal left owned capacity")
				}
			}
			for _, selected := range input {
				snapshot := caller[selected.Slot]
				if !bytes.Equal(selected.Entry.ValueBytes, snapshot[0]) {
					t.Fatal("disposal changed caller payload")
				}
				for j, wrap := range selected.Access.Wraps {
					if !bytes.Equal(wrap.RSACiphertext, snapshot[j+1]) {
						t.Fatal("disposal changed caller access")
					}
				}
				if _, _, ok := checkConsumerSelection(selected, a.control.Provider); !ok {
					t.Fatal("disposal changed caller selection")
				}
			}
			if len(caller) != 3 {
				t.Fatal("missing caller payload snapshots")
			}
		})
	}
}

// full_only: false
func TestGeneratedOriginalSealedCurrentWitnessRequiredBeforeSelection(t *testing.T) {
	a, carriers, declaration, route := generatedSuppliedCollectionFixture(t, 1)
	defer a.clear()
	public, private := route.publicCalls, route.privateCalls
	if a.admitCurrentValues(nil, declaration) || len(a.purpose.final.plan.currentValues) != 0 {
		t.Fatal("original sealed declaration admitted without its current-value witness")
	}
	if !a.admitCurrentValues([]contract.ConsumerSelection{carriers[0].Selection}, declaration) || len(a.purpose.final.plan.currentValues) != 1 {
		t.Fatal("complete original sealed current-value witness refused")
	}
	if route.publicCalls != public || route.privateCalls != private {
		t.Fatal("current-value witness admission performed private work")
	}
}

// full_only: false
func TestGeneratedCurrentPlainInputClassRequiresContentChange(t *testing.T) {
	for _, oldInput := range []uint8{contract.InputEncodingRaw, contract.InputEncodingBase64} {
		for _, changed := range []bool{false, true} {
			t.Run(fmt.Sprintf("input%d/reclassified%t", oldInput, changed), func(t *testing.T) {
				domain, operation, recipient := consumerID("plain domain"), consumerID("plain operation"), consumerID("plain recipient")
				current := contract.ValueEntry{Name: "plain", Incarnation: consumerID("plain incarnation"), ValueState: consumerID("plain state"),
					OriginSnapshot: consumerID("plain snapshot"), OriginTransition: consumerID("plain transition"), ValueSource: contract.Supplied,
					ConfidentialityClass: contract.Plain, InputEncoding: oldInput, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 4, RetainedLength: 4,
					Recipients: []contract.ID{recipient}, ValueBytes: []byte("QUJD")}
				if oldInput == contract.InputEncodingBase64 {
					current.ContentLength = 3
				}
				input := oldInput
				if changed {
					if input == contract.InputEncodingRaw {
						input = contract.InputEncodingBase64
					} else {
						input = contract.InputEncodingRaw
					}
				}
				body, err := contract.EncodeValueEntry(current)
				if err != nil {
					t.Fatal(err)
				}
				membership, err := contract.GeneratorIntendedMembershipDescriptor(current.Recipients)
				if err != nil {
					t.Fatal(err)
				}
				declaration, err := contract.EncodeGeneratorDeclaration(contract.GeneratorDeclaration{Schema: 1, DomainID: domain, OperationID: operation,
					Entries: []contract.GeneratorDeclarationEntry{{Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationPlain,
						Name: current.Name, InputEncoding: input, OutputEncoding: current.OutputEncoding, Recipients: current.Recipients, Payload: current.ValueBytes}}})
				if err != nil {
					t.Fatal(err)
				}
				plan := contract.GeneratorValueEntryPlan{Schema: contract.GeneratorValueEntryPlanSchema, Name: current.Name, Slot: 0, EntryIncarnationID: current.Incarnation,
					ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputEncoding: input, OutputEncoding: current.OutputEncoding, IntendedMembership: membership}
				a := generatedAdmission{graph: contract.GeneratorPlanBundle{ValueEntryPlans: []contract.GeneratorValueEntryPlan{plan}},
					before:  contract.PublicState{Domain: domain, Rows: []contract.PublicStateRow{{Name: current.Name, Slot: 0}}},
					purpose: generatedPurposeState{output: &contract.GeneratedOutputTransition{EntryBodies: [][]byte{body}}, final: &generatedFinalPreparationState{plan: generatedPlanState{recipients: [][]contract.ID{current.Recipients}}}}}
				if actual := a.admitCurrentValues(nil, declaration); actual != !changed {
					t.Fatal("private current input class join differs", actual, !changed)
				}
			})
		}
	}
}

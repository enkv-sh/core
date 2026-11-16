package crypto

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

// This fixture isolates one carried row at final preparation. The native mixed
// operation tests own complete Core admission and the new sibling effect.
func generatedMembershipStageFixture(t *testing.T, addition, retained, embedded bool, source uint8) (*generatedAdmission, generatedMembershipSelection, *consumerTestRoute, []contract.ID, contract.GeneratedCurrentIntentSelection) {
	t.Helper()
	f := generatedCurrentIntentPlanFixture(t, embedded)
	graph, err := contract.DecodeGeneratorPlanBundle(f.graph)
	if err != nil {
		t.Fatal(err)
	}
	old, err := contract.DecodeValueEntry(f.reservation.Session.Output.EntryBodies[0])
	if err != nil {
		t.Fatal(err)
	}
	if source == contract.Supplied {
		old.ValueSource, old.Generated = contract.Supplied, contract.GeneratedEntryMetadata{}
		graph.ValueEntryPlans[0].ValueSource = contract.Supplied
	}
	authority, reader := f.base.control.AuthorityRecipientID, consumerID("reader")
	before := []contract.ID{authority}
	after := []contract.ID{authority, reader}
	if !addition {
		before, after = after, before
	}
	slices.SortFunc(before, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	slices.SortFunc(after, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	old.Recipients = slices.Clone(before)
	core, err := contract.ValueCoreForEntry(f.compare.Context.DomainID, f.compare.Context.CompatibilityID, old)
	if err != nil {
		t.Fatal(err)
	}
	payload, keys, err := custody.SealValue(core, []byte("old"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keys[:cap(keys)])
	old.ValueBytes, err = contract.EncodeCanonicalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	material, err := contract.ValueMaterialContextDigest(core)
	if err != nil {
		t.Fatal(err)
	}
	access := contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: contract.ValueMaterialKind,
		MaterialID: old.ValueState, MaterialContextDigest: material, PackageCheck: payload.PackageCheck}
	var record *contract.SupportRecord
	readers := slices.Clone(before)
	if retained {
		// Overlap is deliberate: the removed reader is BOTH current and retained.
		historical := old
		historical.Recipients = []contract.ID{authority, reader}
		slices.SortFunc(historical.Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		body, err := contract.EncodeRetainedCanonicalRecord(contract.RetainedCanonicalRecord{OriginalSlot: graph.ValueEntryPlans[0].Slot, Entry: historical})
		if err != nil {
			t.Fatal(err)
		}
		record = &contract.SupportRecord{Kind: contract.RetainedCanonicalSupportKind, RecordID: old.ValueState, Body: body}
		readers = append(readers, historical.Recipients...)
	}
	slices.SortFunc(readers, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	readers = slices.Compact(readers)
	for _, binding := range f.reservation.Session.Bindings {
		if !slices.Contains(readers, binding.SubjectID) {
			continue
		}
		wrapCore, err := custody.ValueWrapCore(core, binding)
		if err != nil {
			t.Fatal(err)
		}
		wrap, err := custody.Wrap(wrapCore, binding.Binding, keys)
		if err != nil {
			t.Fatal(err)
		}
		access.Wraps = append(access.Wraps, wrap)
	}
	digest, err := contract.PublicValueEntryDigest(core.DomainID, graph.ValueEntryPlans[0].Slot, old)
	if err != nil {
		t.Fatal(err)
	}
	public := f.reservation.Session.BeforePublic
	public.Rows = []contract.PublicStateRow{{Name: old.Name, Slot: graph.ValueEntryPlans[0].Slot, EntryDigest: digest}}
	var records []contract.SupportRecord
	if record != nil {
		records = append(records, *record)
	}
	output := generatedEmptyOutputWitness(t, &public, []generatedCandidateEntry{{Slot: graph.ValueEntryPlans[0].Slot, Entry: old}}, records)
	graph.ValueEntryPlans[0].ChangeMask = contract.GeneratorValueChangeMembership
	graph.ValueEntryPlans[0].IntendedMembership, err = contract.GeneratorIntendedMembershipDescriptor(after)
	if err != nil {
		t.Fatal(err)
	}
	selected := f.reservation.Plan.CurrentIntents[0]
	selected.Row = public.Rows[0]
	a := &generatedAdmission{request: f.compare, control: f.base.control, bindings: f.reservation.Session.Bindings,
		graph: graph, before: public, purpose: generatedPurposeState{output: output, final: &generatedFinalPreparationState{
			phaseID: consumerID("membership phase"), materializationPhaseID: consumerID("membership phase"),
			plan: generatedPlanState{recipients: [][]contract.ID{slices.Clone(after)}}}}, routeID: f.base.route.CredentialRoute()}
	for _, binding := range a.bindings {
		d, err := contract.PublicBindingDigest(binding.Binding)
		if err != nil {
			t.Fatal(err)
		}
		a.bindingDigests = append(a.bindingDigests, d)
	}
	selection := contract.ConsumerSelection{DomainID: core.DomainID, SnapshotID: selected.Root.Object, HEADDigest: selected.HEADDigest,
		AccessRoot: selected.AccessRoot, EntryDigest: digest, Root: selected.Root, HEADRevision: selected.HEADRevision, HEADToken: selected.HEADToken,
		Slot: graph.ValueEntryPlans[0].Slot, Entry: old, Core: core, Payload: payload, Access: access,
		Binding: a.bindings[applyBindingIndex(a.bindings, authority)]}
	carrier := generatedMembershipSelection{Selection: selection}
	if !a.admitMembership([]generatedMembershipSelection{carrier}, []contract.GeneratedCurrentIntentSelection{selected}) {
		t.Fatal("exact current membership selection refused")
	}
	return a, carrier, f.base.route, after, selected
}

func generatedValueKeys(t *testing.T, route KeyAccess, binding contract.BindingTableRow, core contract.ValueCore, access contract.AccessRecord) []byte {
	t.Helper()
	wrapCore, err := custody.ValueWrapCore(core, binding)
	if err != nil {
		t.Fatal(err)
	}
	index := slices.IndexFunc(access.Wraps, func(w contract.WrapRow) bool {
		return w.SubjectKind == binding.SubjectKind && w.SubjectID == binding.SubjectID
	})
	if index < 0 {
		t.Fatal("missing private fixture wrap")
	}
	keys, code := openMaterialPacket(t.Context(), route, binding, wrapCore, access.Wraps[index], contract.CryptoStoredAuthenticationFailed, &contract.CryptoResponse{})
	if code != contract.CryptoSuccess || len(keys) != 64 {
		t.Fatal("private material open failed", code)
	}
	t.Cleanup(func() { clear(keys[:cap(keys)]) })
	return keys
}

func generatedExclusionFixture(t *testing.T, source uint8, recovery, mixed bool) (*generatedAdmission, generatedMembershipSelection, *consumerTestRoute, []contract.ID) {
	t.Helper()
	a, selected, route, wanted, intent := generatedMembershipStageFixture(t, false, true, false, source)
	if mixed {
		binding := a.bindings[applyBindingIndex(a.bindings, consumerID("reader"))]
		binding.SubjectID = consumerID("new current reader")
		binding.Binding.BindingID = consumerID("new current reader binding")
		binding.Binding.BindingIncarnationID = consumerID("new current reader binding incarnation")
		binding.Binding.KeySelector = "projects/test-project/locations/us-central1/keyRings/test/cryptoKeys/new-current/cryptoKeyVersions/1"
		a.bindings = append(a.bindings, binding)
		wanted = append(slices.Clone(wanted), binding.SubjectID)
		slices.SortFunc(wanted, func(x, y contract.ID) int { return bytes.Compare(x[:], y[:]) })
		a.purpose.final.plan.recipients[0] = slices.Clone(wanted)
		var err error
		a.graph.ValueEntryPlans[0].IntendedMembership, err = contract.GeneratorIntendedMembershipDescriptor(wanted)
		if err != nil {
			t.Fatal(err)
		}
		if len(selected.Selection.Entry.Recipients) != len(wanted) {
			t.Fatal("mixed fixture does not preserve the recipient count")
		}
	}
	if recovery {
		f := applyFixture(t, true)
		binding := f.q.Bindings[len(f.q.Bindings)-1]
		a.control.Recovery = f.control.Recovery
		a.bindings = append(a.bindings, binding)
		keys := generatedValueKeys(t, route, selected.Selection.Binding, selected.Selection.Core, selected.Selection.Access)
		core, err := custody.ValueWrapCore(selected.Selection.Core, binding)
		if err != nil {
			t.Fatal(err)
		}
		wrap, err := custody.Wrap(core, binding.Binding, keys)
		if err != nil {
			t.Fatal(err)
		}
		selected.Selection.Access.Wraps = append(slices.Clone(selected.Selection.Access.Wraps), wrap)
	}
	if recovery || mixed {
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
		for _, row := range a.purpose.final.membership {
			for _, wrap := range row.Selection.Access.Wraps {
				clear(wrap.RSACiphertext[:cap(wrap.RSACiphertext)])
			}
		}
		a.purpose.final.membership = nil
		if !a.admitMembership([]generatedMembershipSelection{selected}, []contract.GeneratedCurrentIntentSelection{intent}) {
			t.Fatal("complete exclusion fixture refused before preparation")
		}
	}
	return a, selected, route, wanted
}

func checkGeneratedFreshProtection(t *testing.T, a *generatedAdmission, route KeyAccess, before contract.ConsumerSelection,
	entry contract.ValueEntry, body []byte, wanted []contract.ID) {
	t.Helper()
	access, err := contract.DecodeAccessRecord(body)
	if err != nil {
		t.Fatal(err)
	}
	core, err := contract.ValueCoreForEntry(before.DomainID, before.Core.CompatibilityID, entry)
	if err != nil {
		t.Fatal(err)
	}
	oldKeys := generatedValueKeys(t, route, before.Binding, before.Core, before.Access)
	newKeys := generatedValueKeys(t, route, before.Binding, core, access)
	if bytes.Equal(oldKeys[:32], newKeys[:32]) || bytes.Equal(oldKeys[32:], newKeys[32:]) {
		t.Fatal("reader removal reused the actual data or commitment key")
	}
	payload, err := contract.InspectCanonicalPayload(entry.ValueBytes)
	if err != nil {
		t.Fatal(err)
	}
	if entry.ValueState == before.Entry.ValueState || bytes.Equal(payload.Ciphertext, before.Payload.Ciphertext) || payload.SemanticCommitment == before.Payload.SemanticCommitment {
		t.Fatal("reader removal preserved public protection")
	}
	metadata := before.Entry.Generated
	if before.Entry.ValueSource == contract.Generated {
		metadata.GenerationID = entry.ValueState
		data, commitment, err := contract.GeneratorValueKeyIDs(entry.ValueState)
		if err != nil || core.DataKeyID != data || core.CommitmentKeyID != commitment {
			t.Fatal("fresh generated protection has invalid key identities", err)
		}
	}
	if entry.Generated != metadata || entry.Incarnation != before.Entry.Incarnation || entry.ValueSource != before.Entry.ValueSource {
		t.Fatal("fresh protection changed entry/provider/create/lifecycle meaning")
	}
	plain, err := custody.OpenValue(core, contract.CanonicalPayload(payload), newKeys)
	if plain != nil {
		defer clear(plain[:cap(plain)])
	}
	if err != nil || !bytes.Equal(plain, []byte("old")) {
		t.Fatal("exclusion changed the authenticated semantic value")
	}
	oldPlain, err := custody.OpenValue(core, contract.CanonicalPayload(payload), oldKeys)
	if oldPlain != nil {
		clear(oldPlain[:cap(oldPlain)])
	}
	if err == nil {
		t.Fatal("old keys decrypted the new current value")
	}
	count := len(wanted)
	if a.control.Recovery != nil {
		count++
	}
	if !slices.Equal(entry.Recipients, wanted) || len(access.Wraps) != count {
		t.Fatal("new current material grants an old-only reader or omits required access")
	}
	for i, id := range wanted {
		if access.Wraps[i].SubjectKind != contract.OrdinaryWrapSubject || access.Wraps[i].SubjectID != id {
			t.Fatal("fresh protection has an unintended ordinary wrap")
		}
	}
	if a.control.Recovery != nil && (access.Wraps[count-1].SubjectKind != contract.RecoveryWrapSubject || access.Wraps[count-1].SubjectID != a.control.Recovery.RoleID) {
		t.Fatal("fresh protection lost the separate Recovery wrap")
	}
}

// full_only: false
func TestGeneratedMembershipRemovalUsesFreshProtection(t *testing.T) {
	for _, source := range []uint8{contract.Supplied, contract.Generated} {
		for _, recovery := range []bool{false, true} {
			for _, mixed := range []bool{false, true} {
				t.Run(fmt.Sprintf("source_%d/recovery_%v/mixed_%v", source, recovery, mixed), func(t *testing.T) {
					a, carrier, route, wanted := generatedExclusionFixture(t, source, recovery, mixed)
					defer a.clear()
					reply := &contract.CryptoResponse{}
					entry, body, code := a.prepareMembership(t.Context(), route, 0, reply)
					if code != contract.CryptoSuccess {
						t.Fatal("exclusion preparation failed", code)
					}
					checkGeneratedFreshProtection(t, a, route, carrier.Selection, entry, body, wanted)
					opens, wraps := uint32(0), uint32(0)
					for _, use := range reply.KeyUseRows {
						if use.Outcome != contract.KeyUseCompleted {
							t.Fatal("fresh exclusion reported an incomplete key use")
						}
						switch use.Purpose {
						case contract.KeyUseMaterialOpen:
							opens += use.Count
						case contract.KeyUseMaterialWrap:
							wraps += use.Count
						}
					}
					count := len(wanted)
					if recovery {
						count++
					}
					if opens != 1 || wraps != uint32(count) {
						t.Fatal("fresh exclusion did not account for its source open and every new wrap", opens, wraps, count)
					}
				})
			}
		}
	}
}

// full_only: false
func TestGeneratedMembershipExclusionCancellationAndWrapRefusalLeaveNoResult(t *testing.T) {
	for _, mode := range []string{"cancelled after open", "invalid successor binding"} {
		t.Run(mode, func(t *testing.T) {
			a, _, route, _ := generatedExclusionFixture(t, contract.Generated, false, true)
			defer a.clear()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			route.override = func(ctx context.Context, binding contract.KMSBinding, ciphertext []byte, length uint16) PrivateResult {
				result := route.testKeyAccess.Decrypt(ctx, binding, ciphertext, length)
				if mode == "cancelled after open" {
					cancel()
				} else {
					at := applyBindingIndex(a.bindings, consumerID("new current reader"))
					a.bindings[at].Binding.SPKI = bytes.Clone(a.bindings[at].Binding.SPKI)
					a.bindings[at].Binding.SPKI[0] ^= 1
				}
				return result
			}
			reply := &contract.CryptoResponse{}
			entry, body, code := a.prepareMembership(ctx, route, 0, reply)
			want := contract.CryptoCancelled
			if mode == "invalid successor binding" {
				want = contract.CryptoCustodyUnavailable
			}
			if code != want || !reflect.DeepEqual(entry, contract.ValueEntry{}) || body != nil || len(a.purpose.final.supplied) != 0 {
				t.Fatal("failed exclusion returned or installed partial protected material", code, want)
			}
			if len(route.returned) == 0 || !bytes.Equal(route.returned, make([]byte, len(route.returned))) {
				t.Fatal("failed exclusion retained an opened private packet")
			}
		})
	}
}

// full_only: false
func TestGeneratedMembershipPreparationPreservesCanonicalAndArchive(t *testing.T) {
	for _, embedded := range []bool{false, true} {
		for _, mode := range []string{"addition", "retained_addition", "membership_and_retirement_mask"} {
			t.Run(map[bool]string{false: "reference", true: "embedded"}[embedded]+"/"+mode, func(t *testing.T) {
				a, carrier, route, wanted, _ := generatedMembershipStageFixture(t, true, mode == "retained_addition", embedded, contract.Generated)
				if mode == "membership_and_retirement_mask" {
					a.graph.ValueEntryPlans[0].ChangeMask |= contract.GeneratorValueChangeRetirement
				}
				before := carrier.Selection
				publicCalls, privateCalls := route.publicCalls, route.privateCalls
				reply := &contract.CryptoResponse{}
				entry, body, code := a.prepareMembership(context.Background(), route, 0, reply)
				if code != contract.CryptoSuccess {
					t.Fatal("current membership preparation", code)
				}
				expected := before.Entry
				expected.Recipients = wanted
				access, err := contract.DecodeAccessRecord(body)
				readers := slices.Clone(wanted)

				if err != nil || !reflect.DeepEqual(entry, expected) || access.PackageCheck != before.Access.PackageCheck || access.MaterialContextDigest != before.Access.MaterialContextDigest || len(access.Wraps) != len(readers) {
					t.Fatal("membership changed canonical bytes/metadata/material or archive reader union", err)
				}
				for i, id := range readers {
					if access.Wraps[i].SubjectID != id {
						t.Fatal("wrap reader differs")
					}
					old := slices.IndexFunc(before.Access.Wraps, func(w contract.WrapRow) bool { return w.SubjectID == id })
					if old >= 0 && !reflect.DeepEqual(access.Wraps[i], before.Access.Wraps[old]) {
						t.Fatal("existing archive/current wrap regenerated")
					}
				}
				if route.publicCalls != publicCalls || route.privateCalls != privateCalls+1 {
					t.Fatal("membership skipped or repeated private material open")
				}
				var expectedUses []contract.KeyUseRow
				for i, binding := range a.bindings {
					purpose := uint8(0)
					if binding.SubjectID == a.control.AuthorityRecipientID {
						purpose = contract.KeyUseMaterialOpen
					} else if (mode == "addition" || mode == "membership_and_retirement_mask") && binding.SubjectID == consumerID("reader") {
						purpose = contract.KeyUseMaterialWrap
					}
					if purpose != 0 {
						expectedUses = append(expectedUses, contract.KeyUseRow{BindingID: binding.Binding.BindingID, PublicBindingDigest: a.bindingDigests[i],
							SubjectKind: binding.SubjectKind, SubjectID: binding.SubjectID, Provider: binding.Binding.Provider,
							Purpose: purpose, Outcome: contract.KeyUseCompleted, Count: 1})
					}
				}
				if len(reply.KeyUseRows) != len(expectedUses) {
					t.Fatal("membership key-use count differs", reply.KeyUseRows)
				}
				for _, use := range expectedUses {
					if !slices.Contains(reply.KeyUseRows, use) {
						t.Fatal("membership key-use binding, purpose, result or count differs", reply.KeyUseRows)
					}
				}
				a.clear()
			})
		}
	}
}

// full_only: false
func TestGeneratedMembershipRefusesChangedSelectionsBeforePrivateWork(t *testing.T) {
	for _, mode := range []string{"root", "condition", "access_root", "material", "missing_retained", "changed_retained", "duplicate", "surplus_retained"} {
		t.Run(mode, func(t *testing.T) {
			withRetained := mode != "surplus_retained"
			a, carrier, route, _, intent := generatedMembershipStageFixture(t, false, withRetained, false, contract.Generated)
			s := carrier.Selection
			// Calibrate re-admission with the complete unmodified current-intent
			// witness before each altered selection, within this final owner.
			reset := func() {
				for _, row := range a.purpose.final.membership {
					for _, wrap := range row.Selection.Access.Wraps {
						clear(wrap.RSACiphertext[:cap(wrap.RSACiphertext)])
					}
				}
				a.purpose.final.membership = nil
			}
			reset()
			publicCalls, privateCalls := route.publicCalls, route.privateCalls
			if !a.admitMembership([]generatedMembershipSelection{carrier}, []contract.GeneratedCurrentIntentSelection{intent}) || len(a.purpose.final.membership) != 1 || route.publicCalls != publicCalls || route.privateCalls != privateCalls {
				t.Fatal("unmodified current/retained selection did not re-admit")
			}
			reset()
			input := []generatedMembershipSelection{carrier}
			switch mode {
			case "root":
				input[0].Selection.Root.Digest = consumerID("unselected root")
			case "condition":
				input[0].Selection.HEADToken.Value = "stale"
			case "access_root":
				input[0].Selection.AccessRoot = consumerID("unselected access root")
			case "material":
				input[0].Selection.Core.ValueStateID = consumerID("other material")
			case "missing_retained":
				a.purpose.output.Retained = nil
			case "changed_retained":
				row := a.purpose.output.Retained[0]
				row.Body = bytes.Clone(row.Body)
				row.Body[len(row.Body)-1] ^= 1
				a.purpose.output.Retained = []contract.SupportRecord{row}
			case "duplicate":
				input = append(input, carrier)
			case "surplus_retained":
				body, err := contract.EncodeRetainedCanonicalRecord(contract.RetainedCanonicalRecord{OriginalSlot: s.Slot, Entry: s.Entry})
				if err != nil {
					t.Fatal(err)
				}
				a.purpose.output.Retained = []contract.SupportRecord{{Kind: contract.RetainedCanonicalSupportKind, RecordID: s.Entry.ValueState, Body: body}}
			}
			if a.admitMembership(input, []contract.GeneratedCurrentIntentSelection{intent}) || len(a.purpose.final.membership) != 0 || route.publicCalls != publicCalls || route.privateCalls != privateCalls {
				t.Fatal("changed current/retained selection admitted or reached private work", mode)
			}
			a.clear()
		})
	}
}

// full_only: false
func TestGeneratedMembershipAuthenticationFailurePrecedesWrapAndResult(t *testing.T) {
	for _, mode := range []string{"package_mac", "ciphertext", "packet_context"} {
		t.Run(mode, func(t *testing.T) {
			a, carrier, route, _, intent := generatedMembershipStageFixture(t, true, false, false, contract.Generated)
			if mode == "packet_context" {
				route.override = func(ctx context.Context, binding contract.KMSBinding, ciphertext []byte, length uint16) PrivateResult {
					result := route.testKeyAccess.Decrypt(ctx, binding, ciphertext, length)
					result.Packet[4] ^= 1
					return result
				}
			} else {
				// Isolate custody authentication after structural selected-row
				// admission. Native mixed-operation tests own the signed root.
				for _, row := range a.purpose.final.membership {
					for _, wrap := range row.Selection.Access.Wraps {
						clear(wrap.RSACiphertext[:cap(wrap.RSACiphertext)])
					}
				}
				a.purpose.final.membership = nil
				carrier.Selection.Payload.Ciphertext = bytes.Clone(carrier.Selection.Payload.Ciphertext)
				if mode == "package_mac" {
					carrier.Selection.Payload.PackageCheck[0] ^= 1
					carrier.Selection.Access.PackageCheck = carrier.Selection.Payload.PackageCheck
				} else {
					carrier.Selection.Payload.Ciphertext[0] ^= 1
				}
				refreshConsumerSelection(t, &carrier.Selection)
				a.before.Rows[0].EntryDigest = carrier.Selection.EntryDigest
				intent.Row = a.before.Rows[0]
				a.purpose.output = generatedEmptyOutputWitness(t, &a.before, []generatedCandidateEntry{{Slot: carrier.Selection.Slot, Entry: carrier.Selection.Entry}}, nil)
				if !a.admitMembership([]generatedMembershipSelection{carrier}, []contract.GeneratedCurrentIntentSelection{intent}) {
					t.Fatal("structurally complete authentication control refused before custody")
				}
			}
			publicCalls, privateCalls := route.publicCalls, route.privateCalls
			reply := &contract.CryptoResponse{}
			entry, body, code := a.prepareMembership(context.Background(), route, 0, reply)
			binding := carrier.Selection.Binding
			digest, err := contract.PublicBindingDigest(binding.Binding)
			if err != nil {
				t.Fatal(err)
			}
			wantUse := contract.KeyUseRow{BindingID: binding.Binding.BindingID, PublicBindingDigest: digest,
				SubjectKind: binding.SubjectKind, SubjectID: binding.SubjectID, Provider: binding.Binding.Provider,
				Purpose: contract.KeyUseMaterialOpen, Outcome: contract.KeyUseCompleted, Count: 1}
			if code != contract.CryptoStoredAuthenticationFailed || !reflect.DeepEqual(entry, contract.ValueEntry{}) || body != nil || route.publicCalls != publicCalls || route.privateCalls != privateCalls+1 || !reflect.DeepEqual(reply.KeyUseRows, []contract.KeyUseRow{wantUse}) {
				t.Fatal("failed authentication returned value/access, wrapped a reader or changed key-use facts", code, reply.KeyUseRows)
			}
			if !bytes.Equal(route.returned, make([]byte, len(route.returned))) {
				t.Fatal("failed private packet capacity retained")
			}
			a.clear()
		})
	}
}

// full_only: false
func TestGeneratedSuppliedMembershipCollectionUsesTotalEntryBound(t *testing.T) {
	for _, count := range []int{128, 129} {
		t.Run(fmt.Sprintf("supplied%d-plus-one-generated", count), func(t *testing.T) {
			a, carriers, _, route := generatedSuppliedCollectionFixture(t, count)
			public, private := route.publicCalls, route.privateCalls
			if !a.admitMembership(carriers, nil) || len(a.purpose.final.membership) != count {
				t.Fatal("valid Supplied membership collection used the Generated-only bound", count)
			}
			if route.publicCalls != public || route.privateCalls != private {
				t.Fatal("membership admission performed key work")
			}
			for _, carrier := range carriers {
				before := carrier.Selection
				planIndex := slices.IndexFunc(a.graph.ValueEntryPlans, func(plan contract.GeneratorValueEntryPlan) bool { return plan.Slot == before.Slot })
				reply := &contract.CryptoResponse{}
				entry, body, code := a.prepareMembership(t.Context(), route, planIndex, reply)
				if code != contract.CryptoSuccess {
					t.Fatal("valid Supplied membership collection preparation", before.Slot, code)
				}
				want := before.Entry
				want.Recipients = a.purpose.final.plan.recipients[planIndex]
				access, err := contract.DecodeAccessRecord(body)
				if err != nil || !reflect.DeepEqual(entry, want) || access.MaterialContextDigest != before.Access.MaterialContextDigest || access.PackageCheck != before.Access.PackageCheck || len(access.Wraps) != len(want.Recipients) {
					t.Fatal("Supplied membership collection changed canonical bytes or complete recipients", before.Slot, err)
				}
				for i, wrap := range access.Wraps {
					if wrap.SubjectKind != contract.OrdinaryWrapSubject || wrap.SubjectID != want.Recipients[i] {
						t.Fatal("Supplied membership collection has an unintended wrap", before.Slot)
					}
					if wrap.SubjectID == a.control.AuthorityRecipientID && !reflect.DeepEqual(wrap, before.Access.Wraps[0]) {
						t.Fatal("Supplied membership collection replaced the selected authority wrap", before.Slot)
					}
				}
				if len(reply.KeyUseRows) != 2 {
					t.Fatal("Supplied membership collection key-use rows differ", before.Slot, reply.KeyUseRows)
				}
				for _, use := range reply.KeyUseRows {
					purpose := contract.KeyUseMaterialWrap
					if use.SubjectID == a.control.AuthorityRecipientID {
						purpose = contract.KeyUseMaterialOpen
					}
					if use.Purpose != purpose || use.Outcome != contract.KeyUseCompleted || use.Count != 1 {
						t.Fatal("Supplied membership collection key-use purpose or count differs", before.Slot, use)
					}
				}
			}
			if route.publicCalls != public || route.privateCalls != private+count {
				t.Fatal("Supplied membership collection did not open each selected material exactly once", route.privateCalls-private, count)
			}
			a.clear()
		})
	}
}

// full_only: false
func TestGeneratedFinalAccessChecksClosedCanonicalProjection(t *testing.T) {
	for _, retained := range []bool{false, true} {
		t.Run(fmt.Sprintf("retained_%v", retained), func(t *testing.T) {
			checkGeneratedFinalAccessClosedCanonicalProjection(t, retained)
		})
	}
}

func checkGeneratedFinalAccessClosedCanonicalProjection(t *testing.T, retained bool) {
	t.Helper()
	a, carrier, route, wanted, _ := generatedMembershipStageFixture(t, false, retained, false, contract.Generated)
	defer a.clear()
	entry, body, code := a.prepareMembership(t.Context(), route, 0, &contract.CryptoResponse{})
	if code != contract.CryptoSuccess {
		t.Fatal("prepare authenticated predecessor union", code)
	}
	prepared, err := contract.DecodeAccessRecord(body)
	if err != nil || len(prepared.Wraps) != 1 || len(wanted) != 1 || prepared.MaterialID == carrier.Selection.Access.MaterialID {
		t.Fatal("preparation did not select separate current material and exact intended access", err)
	}
	plan := a.graph.ValueEntryPlans[0]
	state := generatedSuppliedPreparation{plan: 0, identity: contract.IdentityRow{Name: entry.Name, Slot: plan.Slot, ValueState: entry.ValueState},
		access: contract.DigestLength{Digest: contract.Hash(body), Length: uint64(len(body))}}
	candidate := generatedCandidate{Subject: contract.GeneratorAuthoritySubject{Purpose: contract.GeneratorAuthorityFinal, DomainID: a.request.Context.DomainID},
		PublicState: contract.PublicState{Rows: []contract.PublicStateRow{{Name: plan.Name, Slot: plan.Slot}}}}
	want := prepared
	if !a.suppliedFinalAccessMatches(candidate, state, want) {
		t.Fatal("exact current protection refused after the last canonical consumer ended")
	}

	damages := []string{"old extra reader", "changed required ciphertext", "missing required wrap"}
	for _, damage := range damages {
		t.Run(damage, func(t *testing.T) {
			bad, c := want, candidate
			bad.Wraps = slices.Clone(want.Wraps)
			switch damage {
			case "old extra reader":
				bad = carrier.Selection.Access
			case "changed required ciphertext":
				bad.Wraps[0].RSACiphertext = bytes.Clone(bad.Wraps[0].RSACiphertext)
				bad.Wraps[0].RSACiphertext[0] ^= 1
			case "missing required wrap":
				bad.Wraps = nil
			}
			if a.suppliedFinalAccessMatches(c, state, bad) {
				t.Fatal("Final accepted an inexact successor", damage)
			}
		})
	}
}

// full_only: false
func TestGeneratedFinalRetainedReadersKeepRequestedMaterialAuthority(t *testing.T) {
	for _, mode := range []string{"declared-only unrelated", "selected unrelated", "malformed unrelated source", "malformed unrelated owner", "missing matching source"} {
		t.Run(mode, func(t *testing.T) {
			// These private stage fixtures establish the predecessor/declared
			// relation only. Connected tests own selection and cold reopening.
			a, candidate, _, route := generatedSurvivingFinalAccessFixture(t, contract.GeneratedHazardSupportKind, false, contract.Supplied)
			other, carriers, _, _ := generatedSuppliedCollectionFixture(t, 1)
			t.Cleanup(other.clear)
			selected := carriers[0].Selection
			if selected.DomainID != candidate.Subject.DomainID {
				t.Fatal("independent source has a different domain")
			}
			record := contract.RetainedCanonicalRecord{OriginalSlot: selected.Slot, Entry: selected.Entry}
			body, err := contract.EncodeRetainedCanonicalRecord(record)
			if err != nil {
				t.Fatal(err)
			}
			id, err := contract.AdmissionEntryDigest(record)
			if err != nil {
				t.Fatal(err)
			}
			row := contract.SupportRecord{Kind: contract.RetainedCanonicalSupportKind, RecordID: id, Body: body}
			core, err := contract.ValueCoreForEntry(candidate.Subject.DomainID, a.request.Context.CompatibilityID, record.Entry)
			if err != nil {
				t.Fatal(err)
			}
			contextID, err := contract.ValueMaterialContextDigest(core)
			if err != nil {
				t.Fatal(err)
			}
			owner, _ := generatedCanonicalFixture(t, contract.GeneratedDutySupportKind)
			unrelated := generatedCandidate{Subject: candidate.Subject}
			generatedFinalAccessOwner(t, &unrelated, row, owner, contract.GeneratorConsumer{Schema: 1, OwnerID: owner.Owner.RecordID,
				MaterialID: core.ValueStateID, ContextDigest: contextID, SubjectKind: contract.GeneratorConsumerRetainedCanonicalValue,
				SubjectID: id, Purpose: contract.GeneratorConsumerUseRetainedCanonical})
			candidate.SupportRecords = append(slices.Clone(candidate.SupportRecords), unrelated.SupportRecords...)
			a.purpose.final.plan.canonicals = append(a.purpose.final.plan.canonicals, generatedCanonicalSource{sourceID: id, body: contract.Hash(body)})
			value := a.purpose.final.membership[0].Selection.Entry.ValueState
			if value == core.ValueStateID {
				t.Fatal("fixture requires two distinct materials")
			}
			switch mode {
			case "selected unrelated":
				fact, err := contract.InspectSupportRecordDigest(candidate.Subject.DomainID, row)
				if err != nil {
					t.Fatal(err)
				}
				output := a.purpose.output
				output.Retained = append(output.Retained, row)
				output.Rows.Facts = append(output.Rows.Facts, fact)
				slices.SortFunc(output.Retained, func(x, y contract.SupportRecord) int { return bytes.Compare(x.RecordID[:], y.RecordID[:]) })
				slices.SortFunc(output.Rows.Facts, func(x, y contract.SupportRecordDigest) int {
					if x.Kind() != y.Kind() {
						return int(x.Kind()) - int(y.Kind())
					}
					xID, yID := x.RecordID(), y.RecordID()
					return bytes.Compare(xID[:], yID[:])
				})
				a.before.RequiredSupport, err = contract.RequiredSupportDescriptorFromDigests(a.before.Domain, output.Rows.Facts)
				if err != nil {
					t.Fatal(err)
				}
				if err := output.Inspect(a.before); err != nil {
					t.Fatal("complete two-material predecessor witness", err)
				}
			case "malformed unrelated source":
				at := slices.IndexFunc(candidate.SupportRecords, func(r contract.SupportRecord) bool { return r.RecordID == id })
				candidate.SupportRecords[at].Body = []byte{1}
			case "malformed unrelated owner":
				at := slices.IndexFunc(candidate.SupportRecords, func(r contract.SupportRecord) bool {
					return r.Kind == owner.Owner.Kind && r.RecordID == owner.Owner.RecordID
				})
				candidate.SupportRecords[at].Body = []byte{1}
			case "missing matching source":
				candidate.SupportRecords = slices.DeleteFunc(candidate.SupportRecords, func(r contract.SupportRecord) bool { return r.Kind == contract.RetainedCanonicalSupportKind })
			}
			var callerDone chan struct{}
			if mode == "selected unrelated" {
				deadline := time.Now().Add(time.Minute)
				sessionContext, cancelSession := context.WithDeadline(t.Context(), deadline)
				t.Cleanup(cancelSession)
				a.session = &session{ctx: sessionContext, deadline: deadline}
				callerDone = make(chan struct{})
				candidate.retainedCensus = &generatedFinalRetainedCensus{callerDone: callerDone}
			}
			public, private := route.publicCalls, route.privateCalls
			readers, ok := a.finalRetainedReaders(candidate, value)
			want := mode == "declared-only unrelated" || mode == "selected unrelated"
			wantReaders := []contract.ID{a.control.AuthorityRecipientID, consumerID("reader")}
			slices.SortFunc(wantReaders, func(x, y contract.ID) int { return bytes.Compare(x[:], y[:]) })
			if ok != want || ok && !slices.Equal(readers, wantReaders) {
				t.Fatal("requested material lost its exact authority or readers", ok)
			}
			if want {
				broad, broadOK := a.candidateCanonicalReaders(candidate)
				if !broadOK || !slices.Equal(broad[core.ValueStateID], selected.Entry.Recipients) {
					t.Fatal("broad declaration authority rejected the independent source")
				}
				got, otherOK := a.finalRetainedReaders(candidate, core.ValueStateID)
				if otherOK != (mode == "selected unrelated") || otherOK && !slices.Equal(got, selected.Entry.Recipients) {
					t.Fatal("broad authority became predecessor authority", otherOK)
				}
			}
			if callerDone != nil {
				if !candidate.retainedCensus.built || !candidate.retainedCensus.valid || a.ctx.Err() != nil {
					t.Fatal("two valid materials did not populate a live shared census")
				}
				close(callerDone)
				for _, queried := range []contract.ID{value, core.ValueStateID} {
					if got, ok := a.finalRetainedReaders(candidate, queried); ok || got != nil {
						t.Fatal("cached material readers survived caller cancellation")
					}
				}
			}
			if route.publicCalls != public || route.privateCalls != private {
				t.Fatal("reader census performed private work")
			}
		})
	}
}

// full_only: false
func TestGeneratedMembershipWitnessesFollowFinalSelection(t *testing.T) {
	for _, selecting := range []bool{false, true} {
		for _, supplied := range []bool{false, true} {
			t.Run(fmt.Sprintf("selecting=%t/witness=%t", selecting, supplied), func(t *testing.T) {
				a, carrier, route, _, intent := generatedMembershipStageFixture(t, true, false, false, contract.Generated)
				defer a.clear()
				a.purpose.final.nonselecting = !selecting
				for _, owned := range a.purpose.final.membership {
					for _, wrap := range owned.Selection.Access.Wraps {
						clear(wrap.RSACiphertext[:cap(wrap.RSACiphertext)])
					}
				}
				a.purpose.final.membership = nil
				var input []generatedMembershipSelection
				if supplied {
					input = []generatedMembershipSelection{carrier}
				}
				public, private := route.publicCalls, route.privateCalls
				if got := a.admitMembership(input, []contract.GeneratedCurrentIntentSelection{intent}); got != (selecting == supplied) {
					t.Fatal("Final selection did not require its exact membership witness set", got)
				}
				if route.publicCalls != public || route.privateCalls != private {
					t.Fatal("membership admission performed private work")
				}
			})
		}
	}
}

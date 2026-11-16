package crypto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGeneratedAutomaticSelectionFreezesExactChangedDescriptors(t *testing.T) {
	id := consumerID
	domain := id("automatic changed descriptor domain")
	entry := func(name string) contract.ValueEntry {
		return contract.ValueEntry{Name: name, Incarnation: id(name + " incarnation"), ValueState: id(name + " state"),
			OriginSnapshot: id("old snapshot"), OriginTransition: id("old transition"), ValueSource: contract.Supplied,
			ConfidentialityClass: contract.Plain, Recipients: []contract.ID{id("old reader")}, ValueBytes: []byte("before"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len([]byte("before"))), RetainedLength: uint32(len([]byte("before")))}
	}
	oldA, oldB, newC := entry("a"), entry("b"), entry("c")
	newA := oldA
	newA.ValueBytes, newA.Recipients = []byte("after"), []contract.ID{id("new reader")}
	output := &contract.GeneratedOutputTransition{Before: contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: domain}}
	for slot, old := range []contract.ValueEntry{oldA, oldB} {
		body, err := contract.EncodeValueEntry(old)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := contract.PublicValueEntryDigest(domain, uint16(slot), old)
		if err != nil {
			t.Fatal(err)
		}
		output.EntryBodies = append(output.EntryBodies, body)
		output.EntriesBefore = append(output.EntriesBefore, contract.MembershipRow{Name: old.Name, Slot: uint16(slot), Incarnation: old.Incarnation, EntryDigest: digest, Recipients: old.Recipients})
	}
	a := &generatedAdmission{purpose: generatedPurposeState{output: output}, graph: contract.GeneratorPlanBundle{
		Header:          contract.GeneratorGraphHeader{OperationID: id("automatic changed descriptor operation")},
		ValueEntryPlans: []contract.GeneratorValueEntryPlan{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: newA.Name, Slot: 0, EntryIncarnationID: newA.Incarnation}, {InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: newC.Name, Slot: 2, EntryIncarnationID: newC.Incarnation}},
	}}
	candidate := generatedCandidate{PublicState: contract.PublicState{Domain: domain}, Entries: []generatedCandidateEntry{{Slot: 0, Entry: newA}, {Slot: 2, Entry: newC}}}
	var expected []contract.ChangedSubjectIdentity
	add := func(kind, change uint8, primary, secondary contract.ID) {
		identity, err := contract.ChangedSubjectIdentityID(domain, kind, primary, secondary)
		if err != nil {
			t.Fatal(err)
		}
		expected = append(expected, contract.ChangedSubjectIdentity{Kind: kind, Change: change, Identity: identity})
	}
	add(contract.ChangedSubjectValueEntry, contract.ChangedSubjectUpdated, oldA.Incarnation, contract.ID{})
	add(contract.ChangedSubjectValueEntry, contract.ChangedSubjectRemoved, oldB.Incarnation, contract.ID{})
	add(contract.ChangedSubjectValueEntry, contract.ChangedSubjectAdded, newC.Incarnation, contract.ID{})
	add(contract.ChangedSubjectMembership, contract.ChangedSubjectRemoved, oldA.Incarnation, id("old reader"))
	add(contract.ChangedSubjectMembership, contract.ChangedSubjectAdded, oldA.Incarnation, id("new reader"))
	add(contract.ChangedSubjectMembership, contract.ChangedSubjectRemoved, oldB.Incarnation, id("old reader"))
	add(contract.ChangedSubjectMembership, contract.ChangedSubjectAdded, newC.Incarnation, id("old reader"))
	want, err := contract.ChangedSubjectDescriptor(expected)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := a.candidateAutomaticChangedSubjects(candidate); !ok || got != want {
		t.Fatal("first selection changed-subject meaning differs", got, want, ok)
	}
	candidate.Entries[0].Entry.Recipients = oldA.Recipients
	if got, ok := a.candidateAutomaticChangedSubjects(candidate); !ok || got == want {
		t.Fatal("changed membership did not change frozen subjects", got, ok)
	}

	candidate.Entries[0].Entry.Recipients = newA.Recipients
	for _, condition := range []string{"v4-empty", "v4-added", "v4-removed", "v4-updated", "v3-preserved", "invalid-plan", "invalid-before"} {
		t.Run(condition, func(t *testing.T) {
			owned := *output
			admission := *a
			admission.graph.Request.Schema = contract.GeneratorApplyRequestCoreSchema
			admission.purpose.output = &owned
			target := contract.OutputTarget{EntryIncarnationID: oldA.Incarnation, ServiceContractID: "provider", CanonicalTarget: "slot", ConsumerLocator: "locator", TargetContractID: "profile", PayloadEncoding: contract.OutputEncodingRaw}
			binding := contract.OutputBinding{DestinationID: "dest", IncarnationID: id("old output binding"), Destination: contract.OutputDestination{CanonicalSettings: []byte(`{}`), ServiceContractID: "provider", ConfigContractID: "profile"}, Targets: []contract.OutputTarget{target}}
			target.EntryIncarnationID = contract.ID{}
			desired := contract.NormalOutputBinding{DestinationID: binding.DestinationID, Destination: binding.Destination, Targets: []contract.NormalOutputTarget{{Name: oldA.Name, Target: target}}}
			change := uint8(0)
			bindingID := binding.IncarnationID
			switch condition {
			case "v4-added":
				owned.Bindings = []contract.NormalOutputBinding{desired}
				material := append([]byte("ENKV/OUTPUT/APPLY-BINDING/v1\x00"), domain[:]...)
				material = append(material, admission.graph.Header.OperationID[:]...)
				material = binary.BigEndian.AppendUint32(material, 4)
				material = append(material, "dest"...)
				bindingID, change = contract.ID(sha256.Sum256(material)), contract.ChangedSubjectAdded
			case "v4-removed":
				owned.Before.Bindings = []contract.OutputBinding{binding}
				change = contract.ChangedSubjectRemoved
			case "v4-updated":
				owned.Before.Bindings = []contract.OutputBinding{binding}
				desired.Targets[0].Target.CanonicalTarget = "changed-slot"
				owned.Bindings = []contract.NormalOutputBinding{desired}
				change = contract.ChangedSubjectUpdated
			case "v3-preserved":
				admission.graph.Request.Schema = contract.GeneratorPublicRequestCoreSchema
				owned.Before.Bindings, owned.Bindings = []contract.OutputBinding{binding}, []contract.NormalOutputBinding{desired}
			case "invalid-plan":
				desired.Targets[0].Name = "absent"
				owned.Bindings = []contract.NormalOutputBinding{desired}
			case "invalid-before":
				owned.Before.Schema = 0
			}
			got, ok := admission.candidateAutomaticChangedSubjects(candidate)
			if condition == "invalid-plan" || condition == "invalid-before" {
				if ok {
					t.Fatal("invalid output facts were omitted instead of refused", got)
				}
				return
			}
			rows := slices.Clone(expected)
			if change != 0 {
				material := append([]byte("ENKV/CRYPTO/v2/changed-subject-identity-v1\x00"), domain[:]...)
				material = append(material, byte(5))
				material = append(material, bindingID[:]...)
				material = append(material, make([]byte, 32)...)
				rows = append(rows, contract.ChangedSubjectIdentity{Kind: contract.ChangedSubjectOutputBinding, Change: change, Identity: contract.ID(sha256.Sum256(material))})
			}
			complete, err := contract.ChangedSubjectDescriptor(rows)
			if err != nil || !ok || got != complete {
				t.Fatal("automatic output changed subjects differ", got, complete, ok, err)
			}
			if change != 0 {
				if got == want {
					t.Fatal("omitted output changed subject matched")
				}
				rows[len(rows)-1].Identity[0] ^= 1
				tampered, err := contract.ChangedSubjectDescriptor(rows)
				if err != nil || got == tampered {
					t.Fatal("tampered output changed subject matched", err)
				}
			}
		})
	}

	old := contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: contract.OperationSeedMaterialKind, MaterialID: id("seed"), MaterialContextDigest: id("seed context"), PackageCheck: id("seed check"),
		Wraps: []contract.WrapRow{{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: id("authority"), BindingID: id("binding"), BindingSerial: 1, PublicBindingDigest: id("public binding"), RSACiphertext: bytes.Repeat([]byte{0xa5}, 384)}}}
	next := old
	next.Wraps = slices.Clone(old.Wraps)
	next.Wraps[0].RSACiphertext = bytes.Clone(old.Wraps[0].RSACiphertext)
	next.Wraps[0].RSACiphertext[0] ^= 1
	removed, added := old, old
	removed.MaterialID, added.MaterialID = id("removed whole record"), id("added whole record")
	a.beforeAccessRecords = []contract.AccessRecord{old, removed}
	slices.SortFunc(a.beforeAccessRecords, func(a, b contract.AccessRecord) int { return bytes.Compare(a.MaterialID[:], b.MaterialID[:]) })
	candidate.AccessRecords = []contract.AccessRecord{next, added}
	wantAccess, err := contract.AccessChangeDescriptor(domain, []contract.AccessChangeRow{{Before: old, After: next}})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := a.candidateAutomaticChangedAccess(candidate); !ok || got != wantAccess {
		t.Fatal("first selection did not freeze exact surviving-record changes", got, wantAccess, ok)
	}
	candidate.AccessRecords[0] = old
	if got, ok := a.candidateAutomaticChangedAccess(candidate); !ok || got == wantAccess {
		t.Fatal("changed access did not change frozen descriptor", got, ok)
	}
}

// full_only: false
func TestGeneratedAutomaticSelectionRetainsExactGraphSlice(t *testing.T) {
	f, prepared, _, _ := generatedEntriesFixture(t, false)
	candidate := generatedFinalConservationCandidate(t, f, prepared)
	generatedFinalConservationGraph(t, f, &candidate)
	head, err := format.DecodeHeadCore(candidate.HeadCore)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := contract.DecodeGeneratorPlanBundle(f.graph)
	if err != nil {
		t.Fatal(err)
	}
	expected := contract.DigestLength{Digest: contract.Hash(f.graph), Length: uint64(len(f.graph))}
	matches := func() bool {
		return generatedCandidateContentMatches(candidate.SupportRecords, candidate.PublicState.Domain, head.Root.Object, contract.GeneratorContentGraph, graph.UsePlan.PlanGraphID, expected, nil, true)
	}
	if !matches() {
		t.Fatal("actual retained graph slice refused")
	}
	expected.Digest[0] ^= 1
	if matches() {
		t.Fatal("another graph digest accepted")
	}
	expected.Digest[0] ^= 1
	for i, row := range candidate.SupportRecords {
		if row.Kind != contract.GeneratedFragmentSupportKind {
			continue
		}
		fragment, err := contract.DecodeGeneratedFragment(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		fragment.Payload = bytes.Clone(fragment.Payload)
		fragment.Payload[0] ^= 1
		candidate.SupportRecords[i].Body, err = contract.EncodeGeneratedFragment(fragment)
		if err != nil {
			t.Fatal(err)
		}
		if matches() {
			t.Fatal("changed graph fragment accepted")
		}
		return
	}
	t.Fatal("retained graph fixture has no fragment")
}

// full_only: false
func TestGeneratedAutomaticDutyBindsExactDisplacedGeneration(t *testing.T) {
	f, _, plan, evidence := generatedEntriesFixture(t, false)
	r := f.finalRuntime(t)
	t.Cleanup(r.retireGenerated)
	op, _ := generatedAdoptionCompare(t, r, f)
	reply := applyCall(r, context.Background(), contract.CryptoPrepare, generatedEntriesBody(t, f, op, []contract.CryptoGeneratedValueEntryPlan{plan}, 0, 1))
	if reply.ResultCode != contract.CryptoSuccess {
		t.Fatal("actual generated value preparation", reply.ResultCode)
	}
	view, err := contract.InspectCryptoGeneratedValueEntriesResult(reply.Body)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := view.Own()
	if err != nil || len(prepared.Rows) != 1 {
		t.Fatal("actual generated entry", err)
	}
	old := prepared.Rows[0].Entry
	body, err := contract.EncodeValueEntry(old)
	if err != nil {
		t.Fatal(err)
	}
	core, err := contract.InspectGeneratedResultCore(evidence.ResultCore)
	if err != nil {
		t.Fatal(err)
	}
	x := f.final.Results[0].Expected.Template
	x.Action, x.DutyID, x.ResultContractID = contract.GeneratorActionDelete, consumerID("automatic old resource duty"), consumerID("exact delete result contract")
	x.ResourceIncarnationID, x.ResourceContractID = old.Generated.ResourceIncarnationID, old.Generated.ResourceContractID
	lineage := contract.GeneratorLineageTemplate{Name: old.Name, EntryIncarnationID: old.Incarnation, Epoch: old.Generated.Epoch, Templates: [5]contract.GeneratorAttemptTemplate{x}, TemplateCount: 1, Purpose: contract.GeneratorLineageRetirement}
	a := &generatedAdmission{graph: contract.GeneratorPlanBundle{Header: contract.GeneratorGraphHeader{DomainID: f.compare.Context.DomainID}}, request: contract.CryptoGeneratedCompareRequest{Parent: f.compare.Parent},
		purpose: generatedPurposeState{output: &contract.GeneratedOutputTransition{EntriesBefore: []contract.MembershipRow{{Name: old.Name}}, EntryBodies: [][]byte{body}}}}
	evidenceBody, err := contract.EncodeGeneratedCreateEvidence(evidence)
	if err != nil {
		t.Fatal(err)
	}
	for _, damage := range []string{"exact", "token", "incarnation", "epoch", "delete contract", "original contract", "consumer", "entered", "support"} {
		t.Run(damage, func(t *testing.T) {
			m := old.Generated
			target := contract.GeneratorTarget{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratorTargetSchema, Name: old.Name, IncarnationID: old.Incarnation, Epoch: m.Epoch, ResourceID: m.ResourceIncarnationID, ResourceDigest: m.ResourceDigest,
				ConfigContractID: m.ConfigContractID, ResourceContractID: m.ResourceContractID, OriginalOperationID: m.OriginOperationID, OriginalAttemptID: m.OriginAttemptID, ResultContractID: core.ResultContractID, CompletionClass: m.CompletionClass}
			empty := contract.EmptyGeneratorVector
			duty := contract.GeneratedDutyRecord{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratedDutyRecordSchema, DomainID: f.compare.Context.DomainID, DutyID: x.DutyID, OwnerID: x.DutyID, OriginalOperationID: m.OriginOperationID, OriginalAttemptID: m.OriginAttemptID,
				ResourceID: m.ResourceIncarnationID, DescriptorID: x.DescriptorID, ConfigContractID: m.ConfigContractID, ExecutorID: x.ExecutorID, CredentialRouteID: x.CredentialRouteID, ResourceContractID: x.ResourceContractID,
				ResultContractID: x.ResultContractID, Kind: contract.GeneratedDutyRetirement, CompletionClass: m.CompletionClass, Step: 1, Status: contract.GeneratedEffectNotStarted, CapacityReservation: a.request.Parent.Capacity,
				Progress: empty(contract.GeneratorVectorProgress), History: empty(contract.GeneratorVectorHistory), Support: m.RequiredSupport, Consumers: empty(contract.GeneratorVectorConsumers)}
			switch damage {
			case "token":
				target.ResourceDigest[0] ^= 1
			case "incarnation":
				target.IncarnationID[0] ^= 1
			case "epoch":
				target.Epoch++
			case "delete contract":
				duty.ResultContractID = core.ResultContractID
			case "original contract":
				target.ResultContractID = x.ResultContractID
			case "consumer":
				duty.Consumers = contract.GeneratorDescriptor{Digest: consumerID("unexpected create consumer"), Length: 140, Count: 1}
			case "entered":
				duty.Status = contract.GeneratedEffectTransmitted
			case "support":
				duty.Support.Digest[0] ^= 1
			}
			targetBody, err := contract.EncodeGeneratorTarget(target)
			if err != nil {
				t.Fatal(err)
			}
			duty.Target, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorTargets, [][]byte{targetBody})
			if err != nil {
				t.Fatal(err)
			}
			dutyBody, err := contract.EncodeGeneratedDutyRecord(duty)
			if err != nil {
				t.Fatal(err)
			}
			row := contract.SupportRecord{Kind: contract.GeneratedDutySupportKind, RecordID: duty.DutyID, Body: dutyBody}
			candidate := generatedCandidate{SupportRecords: []contract.SupportRecord{row, {Kind: contract.GeneratedCreateEvidenceSupportKind, RecordID: m.CreateResultID, Body: evidenceBody}}}
			candidate.SupportRecords = append(candidate.SupportRecords, generatedVectorSupport(t, duty.DomainID, row.Kind, row.RecordID, contract.GeneratorVectorTargets, [][]byte{targetBody})...)
			if got := a.candidateAutomaticDutyMatches(candidate, lineage, row); got != (damage == "exact") {
				t.Fatal("automatic Duty lost exact old resource meaning", got)
			}
		})
	}
}

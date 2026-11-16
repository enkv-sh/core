package crypto

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func generatedEntriesFixture(t *testing.T, recovery bool) (generatedRuntimeFixture, contract.CryptoGeneratedFinishPlanResult, contract.CryptoGeneratedValueEntryPlan, contract.GeneratedCreateEvidence) {
	t.Helper()
	f, prepared, body := generatedAdoptionFixture(t, recovery)
	f.compare.Purpose = 3
	var err error
	f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
	if err != nil {
		t.Fatal(err)
	}
	f.final = generatedFinalAdmissionInput{
		Session: f.adoption.Session, Plan: f.adoption.Plan, Phase: f.adoption.Phase, Target: f.adoption.Target,
		Material: f.adoption.Material, SeedAccess: f.adoption.SeedAccess, SourceProtections: f.adoption.SourceProtections,
		Results: []generatedResultAdmission{f.adoption.Result}, ResultBodies: [][]byte{body}, ControlledPredecessor: f.adoption.ControlledPredecessor,
	}
	f.final.Phase.TransitionKind = contract.GeneratorAuthorityFinal
	phase, err := contract.GeneratorPhaseID(f.final.Phase)
	if err != nil {
		t.Fatal(err)
	}
	g, err := contract.DecodeGeneratorPlanBundle(f.graph)
	if err != nil {
		t.Fatal(err)
	}
	result, err := contract.DecodeGeneratedResultRecord(body)
	if err != nil {
		t.Fatal(err)
	}
	x := f.final.Results[0].Expected.Template
	coreBody, err := contract.EncodeGeneratedResultCore(result.Core)
	if err != nil {
		t.Fatal(err)
	}
	factsBody, err := contract.EncodeGeneratorSafeFacts(result.SafeFacts)
	if err != nil {
		t.Fatal(err)
	}
	intent := generatedFixtureIntent(x.ConfigContractID, x.ResourceContractID, x.LifecycleMode, `{"name":"token"}`)
	intentDescriptor, err := contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{{Schema: 1, ContentKind: contract.GeneratorContentIntent,
		ContentID: x.IntentDigest, Length: uint32(len(intent)), Digest: contract.Hash(intent)}})
	if err != nil {
		t.Fatal(err)
	}
	evidence := contract.GeneratedCreateEvidence{Schema: contract.GeneratedCreateEvidenceSchema, LifecycleMode: contract.GeneratorLifecycleManaged, OriginalResultID: x.ResultID, CredentialRouteID: x.CredentialRouteID, ResultCore: coreBody, SafeFacts: factsBody,
		Intent: intentDescriptor, CompletionClass: x.CompletionClass}
	evidenceDescriptor, err := contract.GeneratedCreateEvidenceDescriptor(evidence)
	if err != nil {
		t.Fatal(err)
	}
	meta := contract.GeneratedEntryMetadata{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratedEntryMetadataSchema, Epoch: 1, ConfigContractID: x.ConfigContractID, ResourceContractID: x.ResourceContractID, IntentDigest: x.IntentDigest,
		ResourceIncarnationID: x.ResourceIncarnationID, OriginOperationID: prepared.Material.Core.OperationID, OriginAttemptID: x.AttemptID,
		GenerationID: consumerID("unresolved member identity"), ResourceDigest: generatedFixtureResourceDigest(t, result.SafeFacts), CreateResultID: x.ResultID,
		CreateEvidence: evidenceDescriptor, RequiredSupport: contract.EmptyGeneratorVector(contract.GeneratorVectorSupport), CompletionClass: x.CompletionClass, RetirementMode: 1}
	binding, err := contract.GeneratedBindingDigest(meta)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := contract.DeriveGeneratedValueIdentity(x.PlannedValueSlotID, phase, x.ResultID, binding)
	if err != nil {
		t.Fatal(err)
	}
	meta.GenerationID = identity.ValueStateID
	core := contract.ValueCore{Schema: contract.CanonicalSchema, Profile: 2, DomainID: f.compare.Context.DomainID, CompatibilityID: f.compare.Context.CompatibilityID,
		CryptoSupportID: contract.CryptoSupportID(), Name: g.ValueEntryPlans[0].Name, EntryIncarnationID: g.ValueEntryPlans[0].EntryIncarnationID,
		ValueStateID: identity.ValueStateID, OriginSnapshotID: identity.OriginSnapshotID, OriginTransitionID: identity.OriginTransitionID,
		DataKeyID: identity.DataKeyID, DataKeyEpoch: 1, CommitmentKeyID: identity.CommitmentKeyID, CommitmentKeyEpoch: 1,
		ContentLength: result.Payload.ContentLength, ValueSource: contract.Generated, GeneratedBindingDigest: binding, InputEncoding: contract.InputEncodingRaw, RetainedLength: result.Payload.ContentLength}
	plan := contract.CryptoGeneratedValueEntryPlan{OutputEncoding: contract.OutputEncodingRaw, Slot: g.ValueEntryPlans[0].Slot, Result: body, ValueCore: core, Generated: meta,
		Recipients: []contract.ID{f.final.Session.Control.AuthorityRecipientID}}
	f.final.EntryAdmissions = []generatedEntryAdmission{{Slot: plan.Slot, Generated: meta}}
	return f, prepared, plan, evidence
}

func generatedEntriesBody(t *testing.T, f generatedRuntimeFixture, op contract.ID, rows []contract.CryptoGeneratedValueEntryPlan, index uint32, final uint8) []byte {
	t.Helper()
	phase, err := contract.GeneratorPhaseID(f.final.Phase)
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeCryptoGeneratedValueEntriesRequest(contract.CryptoGeneratedValueEntriesRequest{OperationRef: op, Context: f.compare.Context,
		PhaseID: phase, BatchIndex: index, Final: final, Rows: rows})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func generatedEntriesCandidate(t *testing.T, f generatedRuntimeFixture, prepared contract.CryptoGeneratedFinishPlanResult, preparedEntry contract.CryptoGeneratedValueEntryResult, evidence contract.GeneratedCreateEvidence) generatedCandidate {
	t.Helper()
	initial := f
	initial.compare.ParentPlan = contract.GeneratedParentPlan(f.compare.Parent)
	initial.compare.ParentPlan.RequestIdentityDigest = contract.ID{}
	c := generatedPlanCandidate(t, initial, prepared)
	body, err := contract.EncodeGeneratedCreateEvidence(evidence)
	if err != nil {
		t.Fatal(err)
	}
	c.SupportRecords = slices.DeleteFunc(c.SupportRecords, func(row contract.SupportRecord) bool {
		return row.Kind == contract.OperationMaterialSupportKind || row.Kind == contract.GeneratedParentSupportKind
	})
	c.SupportRecords = append(c.SupportRecords, contract.SupportRecord{Kind: 13, RecordID: preparedEntry.ResultID, Body: body})
	generatedCanonicalizeCandidateSupport(t, &c)
	digest, err := contract.PublicValueEntryDigest(c.PublicState.Domain, preparedEntry.Slot, preparedEntry.Entry)
	if err != nil {
		t.Fatal(err)
	}
	c.Entries = []generatedCandidateEntry{{Slot: preparedEntry.Slot, Entry: preparedEntry.Entry}}
	c.PublicState.Rows = []contract.PublicStateRow{{Slot: preparedEntry.Slot, Name: preparedEntry.Entry.Name, EntryDigest: digest}}
	c.AccessRecords = []contract.AccessRecord{preparedEntry.Access}
	c.CurrentAccess.CurrentControl = f.final.Session.Control.CurrentControl
	c.CurrentAccess.AccessGeneration++
	c.CurrentAccess.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(c.PublicState.Domain, c.AccessRecords)
	if err != nil {
		t.Fatal(err)
	}
	access, err := contract.EncodeAccessRecord(preparedEntry.Access)
	if err != nil {
		t.Fatal(err)
	}
	c.CurrentAccess.AccessPageRefs[0].Object = consumerID("final member access page")
	c.CurrentAccess.AccessPageRefs[0].Length = uint32(75 + len(access))
	c.PublicState.AccessRoot, err = contract.AccessRoot(c.CurrentAccess)
	if err != nil {
		t.Fatal(err)
	}
	phase, err := contract.GeneratorPhaseID(f.final.Phase)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := contract.GeneratorPhaseSnapshotID(phase)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := contract.GeneratorPhaseRevisionID(phase)
	if err != nil {
		t.Fatal(err)
	}
	generatedRewriteHead(t, &c, func(head *format.HeadCore) { head.Revision, head.Root.Object = revision, snapshot })
	c.Subject.Purpose, c.Subject.PhaseID = contract.GeneratorAuthorityFinal, phase
	c.Subject.BeforePhase, c.Subject.AfterPhase = f.final.Phase.BeforePhase, f.final.Phase.AfterPhase
	c.Subject.AfterAccessDigest = c.PublicState.AccessRoot
	return c
}

// full_only: false
func TestGeneratedMembersFinalHandoffUsesIndependentCurrentAccess(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		f, prepared, plan, evidence := generatedEntriesFixture(t, recovery)
		r := f.finalRuntime(t)
		op, opened := generatedAdoptionCompare(t, r, f)
		reply := applyCall(r, context.Background(), contract.CryptoPrepare, generatedEntriesBody(t, f, op, []contract.CryptoGeneratedValueEntryPlan{plan}, 0, 1))
		if reply.ResultCode != contract.CryptoSuccess {
			t.Fatal("prepare members", reply.ResultCode)
		}
		view, err := contract.InspectCryptoGeneratedValueEntriesResult(reply.Body)
		if err != nil {
			t.Fatal(err)
		}
		result, err := view.Own()
		if err != nil || len(result.Rows) != 1 {
			t.Fatal("members result", err)
		}
		preparedEntry := result.Rows[0]
		want := 1
		if recovery {
			want++
		}
		if len(preparedEntry.Access.Wraps) != want || len(reply.KeyUseRows) != want {
			t.Fatal("member protection subjects")
		}
		c := generatedEntriesCandidate(t, f, prepared, preparedEntry, evidence)
		if code := r.bindGeneratedCandidate(context.Background(), f.compare.Context.AdmissionID, c); code != contract.CryptoSuccess {
			t.Fatal("final candidate", code)
		}
		uses := contract.CryptoResponse{KeyUseRows: opened}
		for _, row := range reply.KeyUseRows {
			index := applyBindingIndex(f.final.Session.Bindings, row.SubjectID)
			if row.SubjectKind == 2 {
				index = len(f.final.Session.Bindings) - 1
			}
			binding := f.final.Session.Bindings[index]
			if !appendKeyUses(&uses, binding, row.Purpose, KeyUses{Completed: row.Count}, uint64(row.Count)) {
				t.Fatal("test use aggregation")
			}
		}
		q := generatedCandidateRequest(t, f, op, c, []contract.GeneratorResultReference{f.final.Results[0].Reference}, uses.KeyUseRows)
		if out := generatedFreeze(t, r, q); out.ResultCode != contract.CryptoSuccess {
			t.Fatal("freeze final", out.ResultCode)
		}
		claim, err := contract.EncodeCryptoGeneratedClaimRequest(contract.CryptoGeneratedClaimRequest(q))
		if err != nil {
			t.Fatal(err)
		}
		if out := applyCall(r, context.Background(), contract.CryptoClaim, claim); out.ResultCode != contract.CryptoSuccess {
			t.Fatal("claim final", out.ResultCode)
		}
		r.retireGenerated()
		// The final value has no operation seed or result dependency.
		consumer := newConsumerRuntime(t, f.base.route)
		head, err := format.DecodeHeadCore(c.HeadCore)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := contract.DecodeCanonicalPayload(preparedEntry.Entry.ValueBytes)
		if err != nil {
			t.Fatal(err)
		}
		selection := contract.ConsumerSelection{DomainID: c.PublicState.Domain,
			SnapshotID: head.Root.Object, HEADDigest: consumerID("fresh final HEAD"), AccessRoot: c.PublicState.AccessRoot, EntryDigest: c.PublicState.Rows[0].EntryDigest,
			Root: head.Root, HEADRevision: head.Revision, HEADToken: head.PreviousToken, Slot: preparedEntry.Slot, Entry: preparedEntry.Entry, Core: preparedEntry.ValueCore,
			Payload: payload, Access: preparedEntry.Access, Binding: f.final.Session.Bindings[applyBindingIndex(f.final.Session.Bindings, f.final.Session.Control.AuthorityRecipientID)]}
		sink := &consumerTestSink{id: consumerID("member sink")}
		id := consumerID("member consumer admission")
		if err := consumer.admitConsumer(id, consumerID("member purpose"), sink.id, f.final.Session.RouteID, selection, sink, f.base.deadline); err != nil {
			t.Fatal(err)
		}
		if out := consumer.consumeSelected(context.Background(), id); out.code != contract.CryptoSuccess || sink.accepted != contract.Hash([]byte("provider-secret")) {
			t.Fatal("independent final member", out.code)
		}
		if bytes.Equal(preparedEntry.Entry.ValueBytes, plan.Result) {
			t.Fatal("result-only ciphertext used as member")
		}
	}
}

// full_only: false
func TestGeneratedMembersRejectChangedPrivateContextBeforeWrapping(t *testing.T) {
	f, _, plan, evidence := generatedEntriesFixture(t, false)
	for _, tc := range []struct {
		name   string
		change func(*contract.CryptoGeneratedValueEntryPlan)
	}{
		{"slot", func(p *contract.CryptoGeneratedValueEntryPlan) { p.Slot++ }},
		{"name", func(p *contract.CryptoGeneratedValueEntryPlan) { p.ValueCore.Name = "different" }},
		{"incarnation", func(p *contract.CryptoGeneratedValueEntryPlan) {
			p.ValueCore.EntryIncarnationID = consumerID("another incarnation")
		}},
		{"membership", func(p *contract.CryptoGeneratedValueEntryPlan) {
			p.Recipients = []contract.ID{consumerID("not an admitted reader")}
		}},
		{"retirement policy", func(p *contract.CryptoGeneratedValueEntryPlan) { p.Generated.RetirementMode = 2 }},
		{"required support", func(p *contract.CryptoGeneratedValueEntryPlan) { p.Generated.RequiredSupport.Digest[0] ^= 1 }},
		{"create evidence", func(p *contract.CryptoGeneratedValueEntryPlan) { p.Generated.CreateEvidence.Digest[0] ^= 1 }},
		{"credential route", func(p *contract.CryptoGeneratedValueEntryPlan) {
			changed := evidence
			changed.CredentialRouteID = consumerID("another original credential route")
			var err error
			p.Generated.CreateEvidence, err = contract.GeneratedCreateEvidenceDescriptor(changed)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"origin phase", func(p *contract.CryptoGeneratedValueEntryPlan) {
			p.ValueCore.OriginSnapshotID = consumerID("other phase")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := plan
			tc.change(&changed)
			r := f.finalRuntime(t)
			op, _ := generatedAdoptionCompare(t, r, f)
			out := applyCall(r, context.Background(), contract.CryptoPrepare, generatedEntriesBody(t, f, op, []contract.CryptoGeneratedValueEntryPlan{changed}, 0, 1))
			if out.ResultCode == contract.CryptoSuccess || len(out.KeyUseRows) != 0 || len(out.Body) != 0 {
				t.Fatal("changed member context prepared", out.ResultCode)
			}
		})
	}
}

// full_only: false
func TestGeneratedMembersAuthenticateActualEvidenceAndCiphertext(t *testing.T) {
	for _, field := range []string{"evidence", "ciphertext"} {
		t.Run(field, func(t *testing.T) {
			f, _, plan, _ := generatedEntriesFixture(t, false)
			if field == "evidence" {
				plan.Generated.CreateEvidence.Digest[0] ^= 1
				f.final.EntryAdmissions[0].Generated = plan.Generated
			} else {
				result, err := contract.DecodeGeneratedResultRecord(plan.Result)
				if err != nil {
					t.Fatal(err)
				}
				result.Payload.Ciphertext[0] ^= 1
				plan.Result, err = contract.EncodeGeneratedResultRecord(result)
				if err != nil {
					t.Fatal(err)
				}
				f.final.Results[0].Reference.ResultBodyDigest = contract.Hash(plan.Result)
				f.final.ResultBodies = [][]byte{plan.Result}
			}
			r := f.finalRuntime(t)
			if field == "ciphertext" {
				body, err := contract.EncodeCryptoGeneratedCompareRequest(f.compare)
				if err != nil {
					t.Fatal(err)
				}
				out := applyCall(r, t.Context(), contract.CryptoCompare, body)
				if out.ResultCode != contract.CryptoStoredAuthenticationFailed || len(out.Body) != 0 || len(out.KeyUseRows) != 1 {
					t.Fatal("complete result body was not authenticated before entry preparation", out.ResultCode)
				}
				return
			}
			op, _ := generatedAdoptionCompare(t, r, f)
			out := applyCall(r, context.Background(), contract.CryptoPrepare, generatedEntriesBody(t, f, op, []contract.CryptoGeneratedValueEntryPlan{plan}, 0, 1))
			if out.ResultCode == contract.CryptoSuccess || len(out.Body) != 0 || len(out.KeyUseRows) != 0 {
				t.Fatal("supplied assertion bypassed validation", out.ResultCode)
			}
		})
	}
}

// full_only: false
func TestGeneratedMembersRejectBatchAndOutputOverflow(t *testing.T) {
	f, _, plan, _ := generatedEntriesFixture(t, false)
	for _, tc := range []struct {
		name  string
		index uint32
		final uint8
		rows  []contract.CryptoGeneratedValueEntryPlan
	}{
		{"wrong batch", 1, 1, []contract.CryptoGeneratedValueEntryPlan{plan}},
		{"unfinished marker after last row", 0, 0, []contract.CryptoGeneratedValueEntryPlan{plan}},
		{"missing required member", 0, 1, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := f.finalRuntime(t)
			op, _ := generatedAdoptionCompare(t, r, f)
			out := applyCall(r, context.Background(), contract.CryptoPrepare, generatedEntriesBody(t, f, op, tc.rows, tc.index, tc.final))
			if out.ResultCode != contract.CryptoInvalidAdmission || len(out.KeyUseRows) != 0 {
				t.Fatal("incorrect batch admitted", out.ResultCode)
			}
		})
	}
	// This is a wire-capacity probe: the complete input fits, but its public
	// recipient counts predict too much output before any row-specific custody.
	recipients := make([]contract.ID, contract.CryptoMaxValueEntryRecipients)
	for i := range recipients {
		recipients[i] = consumerID(fmt.Sprintf("capacity recipient %d", i))
	}
	slices.SortFunc(recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	rows := make([]contract.CryptoGeneratedValueEntryPlan, 70)
	for i := range rows {
		rows[i] = plan
		rows[i].Slot, rows[i].ValueCore.Name, rows[i].Recipients = uint16(i), fmt.Sprintf("token-%03d", i), recipients
	}
	r := f.finalRuntime(t)
	op, _ := generatedAdoptionCompare(t, r, f)
	out := applyCall(r, context.Background(), contract.CryptoPrepare, generatedEntriesBody(t, f, op, rows, 0, 1))
	if out.ResultCode != contract.CryptoCapacityExceeded || len(out.KeyUseRows) != 0 || len(out.Body) != 0 {
		t.Fatal("oversized output reached custody", out.ResultCode)
	}
}

// full_only: false
func TestGeneratedMembersReplayReproducesOnlyExactImmutablePayload(t *testing.T) {
	f, _, plan, _ := generatedEntriesFixture(t, false)
	var first contract.CryptoGeneratedValueEntryResult
	for i := 0; i < 2; i++ {
		r := f.finalRuntime(t)
		op, _ := generatedAdoptionCompare(t, r, f)
		body := generatedEntriesBody(t, f, op, []contract.CryptoGeneratedValueEntryPlan{plan}, 0, 1)
		out := applyCall(r, context.Background(), contract.CryptoPrepare, body)
		if out.ResultCode != contract.CryptoSuccess {
			t.Fatal("member replay", out.ResultCode)
		}
		view, err := contract.InspectCryptoGeneratedValueEntriesResult(out.Body)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := view.Own()
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = rows.Rows[0]
		} else if !bytes.Equal(first.Entry.ValueBytes, rows.Rows[0].Entry.ValueBytes) || first.ValueCore != rows.Rows[0].ValueCore {
			t.Fatal("same immutable result/phase changed its member payload")
		}
		if again := applyCall(r, context.Background(), contract.CryptoPrepare, body); again.ResultCode != contract.CryptoAlreadyUsed || len(again.KeyUseRows) != 0 {
			t.Fatal("same owner prepared a second batch after final", again.ResultCode)
		}
		r.retireGenerated()
	}
}

// full_only: false
func TestGeneratedMembersCandidateRejectsChangedPreparedMemberAndAccess(t *testing.T) {
	for _, field := range []string{"member", "access"} {
		f, prepared, plan, evidence := generatedEntriesFixture(t, false)
		r := f.finalRuntime(t)
		op, _ := generatedAdoptionCompare(t, r, f)
		out := applyCall(r, context.Background(), contract.CryptoPrepare, generatedEntriesBody(t, f, op, []contract.CryptoGeneratedValueEntryPlan{plan}, 0, 1))
		if out.ResultCode != contract.CryptoSuccess {
			t.Fatal(out.ResultCode)
		}
		view, err := contract.InspectCryptoGeneratedValueEntriesResult(out.Body)
		if err != nil {
			t.Fatal(err)
		}
		result, err := view.Own()
		if err != nil {
			t.Fatal(err)
		}
		preparedEntry := result.Rows[0]
		valid := generatedEntriesCandidate(t, f, prepared, preparedEntry, evidence)
		if _, ok := r.generated.inspectCandidate(valid, nil); !ok {
			t.Fatal("unchanged prepared candidate refused", field)
		}
		if field == "member" {
			payload, err := contract.DecodeCanonicalPayload(preparedEntry.Entry.ValueBytes)
			if err != nil {
				t.Fatal(err)
			}
			payload.Ciphertext[0] ^= 1
			preparedEntry.Entry.ValueBytes, err = contract.EncodeCanonicalPayload(payload)
			if err != nil {
				t.Fatal(err)
			}
		} else {
			preparedEntry.Access.Wraps[0].RSACiphertext[0] ^= 1
		}
		candidate := generatedEntriesCandidate(t, f, prepared, preparedEntry, evidence)
		if code := r.bindGeneratedCandidate(context.Background(), f.compare.Context.AdmissionID, candidate); code != contract.CryptoInvalidAdmission {
			t.Fatal("changed prepared candidate accepted", field, code)
		}
	}
}

// full_only: false
func TestGeneratedMembersEmptyNonselectingFinalRequiresTerminalSupport(t *testing.T) {
	f, prepared, _, _ := generatedEntriesFixture(t, false)
	f.final.EntryAdmissions, f.final.Results, f.final.ResultBodies = nil, nil, nil
	r := f.finalRuntime(t)
	op, _ := generatedAdoptionCompare(t, r, f)
	out := applyCall(r, context.Background(), contract.CryptoPrepare, generatedEntriesBody(t, f, op, nil, 0, 1))
	if out.ResultCode != contract.CryptoSuccess || len(out.KeyUseRows) != 0 {
		t.Fatal("empty final", out.ResultCode)
	}
	initial := f
	initial.compare.ParentPlan = contract.GeneratedParentPlan(f.compare.Parent)
	initial.compare.ParentPlan.RequestIdentityDigest = contract.ID{}
	c := generatedPlanCandidate(t, initial, prepared)
	phase, err := contract.GeneratorPhaseID(f.final.Phase)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := contract.GeneratorPhaseSnapshotID(phase)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := contract.GeneratorPhaseRevisionID(phase)
	if err != nil {
		t.Fatal(err)
	}
	generatedRewriteHead(t, &c, func(head *format.HeadCore) { head.Root.Object, head.Revision = snapshot, revision })
	c.Subject.Purpose, c.Subject.PhaseID, c.Subject.BeforePhase, c.Subject.AfterPhase = contract.GeneratorAuthorityFinal, phase, f.final.Phase.BeforePhase, f.final.Phase.AfterPhase
	if code := r.bindGeneratedCandidate(context.Background(), f.compare.Context.AdmissionID, c); code != contract.CryptoInvalidAdmission {
		t.Fatal("result-free final without exact terminal support accepted", code)
	}
}

// full_only: false
func TestGeneratedMembersEmptyFinalRefusesSuccessfulAggregate(t *testing.T) {
	f, prepared, plan, _ := generatedEntriesFixture(t, false)
	f.final.EntryAdmissions = nil
	f.final.ResultBodies = [][]byte{plan.Result}
	r := f.finalRuntime(t)
	op, _ := generatedAdoptionCompare(t, r, f)
	out := applyCall(r, t.Context(), contract.CryptoPrepare, generatedEntriesBody(t, f, op, nil, 0, 1))
	if out.ResultCode != contract.CryptoSuccess {
		t.Fatal("empty entry preparation", out.ResultCode)
	}
	initial := f
	initial.compare.ParentPlan = contract.GeneratedParentPlan(f.compare.Parent)
	initial.compare.ParentPlan.RequestIdentityDigest = contract.ID{}
	candidate := generatedPlanCandidate(t, initial, prepared)
	candidate.SupportRecords = nil
	if r.generated.candidateTerminalUncertain(candidate) {
		t.Fatal("all-success result bodies proved nonselection without exact terminal ownership")
	}
	f.final.Results = nil
	r = newConsumerRuntime(t, f.base.route)
	if err := r.admitGeneratedFinal(f.compare, f.final, f.base.deadline); err == nil || r.slot != nil {
		t.Fatal("unpaired nonselecting result admitted or left a private slot")
	}
}

// full_only: false
func TestGeneratedNonselectingResultShapeRefusesBeforeInstallingSession(t *testing.T) {
	f, _, plan, _ := generatedEntriesFixture(t, false)
	for _, tc := range []struct {
		name    string
		results int
		bodies  [][]byte
	}{
		{name: "result absent but body present", bodies: [][]byte{plan.Result}},
		{name: "result present but body absent", results: 1},
		{name: "extra body", results: 1, bodies: [][]byte{plan.Result, plan.Result}},
		{name: "changed body", results: 1, bodies: [][]byte{[]byte("invalid result")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := f.final
			input.EntryAdmissions = nil
			input.Results = slices.Clone(f.final.Results[:tc.results])
			input.ResultBodies = tc.bodies
			r := newConsumerRuntime(t, f.base.route)
			if err := r.admitGeneratedFinal(f.compare, input, f.base.deadline); err == nil || r.slot != nil {
				t.Fatal("malformed nonselecting result installed private session", err)
			}
		})
	}
}

// full_only: false
func TestGeneratedNonselectingFinalPreservesExactPredecessorMembers(t *testing.T) {
	before := []contract.PublicStateRow{
		{Name: "alpha", Slot: 7, EntryDigest: consumerID("nonselecting alpha")},
		{Name: "omega", Slot: 19, EntryDigest: consumerID("nonselecting omega")},
	}
	a := &generatedAdmission{before: contract.PublicState{Rows: slices.Clone(before)},
		purpose: generatedPurposeState{final: &generatedFinalPreparationState{nonselecting: true, suppliedFinal: true}}}
	rows, ok := a.preparedPublicStateRows(generatedCandidate{})
	if !ok || !slices.Equal(rows, before) {
		t.Fatal("nonselecting final did not preserve the exact predecessor member projection")
	}
	rows[0].Name = "changed"
	if a.before.Rows[0].Name != "alpha" {
		t.Fatal("nonselecting final returned an aliased predecessor member projection")
	}
	a.purpose.final.entryPreparations = []generatedEntryPreparation{{}}
	if rows, ok := a.preparedPublicStateRows(generatedCandidate{}); ok || rows != nil {
		t.Fatal("nonselecting final admitted prepared member output")
	}
}

// full_only: false
func TestGeneratedSelectingFinalQualifiesCompleteResultBodies(t *testing.T) {
	f, prepared, plan, evidence := generatedEntriesFixture(t, false)
	// This carrier is the complete returned-result set. Entry preparation
	// selects a subset of it and must not add a second copy of any reference.
	f.final.ResultBodies = [][]byte{plan.Result}
	r := f.finalRuntime(t)
	op, _ := generatedAdoptionCompare(t, r, f)
	want := []contract.GeneratorResultReference{f.final.Results[0].Reference}
	if !slices.Equal(r.generated.purpose.final.validated, want) {
		t.Fatal("complete result evidence was not qualified when seed custody opened")
	}
	out := applyCall(r, t.Context(), contract.CryptoPrepare, generatedEntriesBody(t, f, op, []contract.CryptoGeneratedValueEntryPlan{plan}, 0, 1))
	if out.ResultCode != contract.CryptoSuccess {
		t.Fatal("selecting entry preparation", out.ResultCode)
	}
	view, err := contract.InspectCryptoGeneratedValueEntriesResult(out.Body)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := view.Own()
	if err != nil || len(owned.Rows) != 1 {
		t.Fatal(err)
	}
	candidate := generatedEntriesCandidate(t, f, prepared, owned.Rows[0], evidence)
	if code := r.bindGeneratedCandidate(t.Context(), f.compare.Context.AdmissionID, candidate); code != contract.CryptoSuccess || !slices.Equal(r.generated.purpose.final.validated, want) {
		t.Fatal("entry subset changed complete result set", code)
	}
}

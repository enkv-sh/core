package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/internal/custody"
)

func generatedRuntimeEffectFixture(t *testing.T, recovery bool, createResultContract ...contract.ID) generatedRuntimeFixture {
	t.Helper()
	return generatedRuntimeEffectFixtureForEncoding(t, recovery, contract.InputEncodingRaw, createResultContract...)
}

func generatedRuntimeEffectFixtureForEncoding(t *testing.T, recovery bool, encoding uint8, createResultContract ...contract.ID) generatedRuntimeFixture {
	t.Helper()
	if len(createResultContract) > 1 {
		t.Fatal("more than one create result contract")
	}
	f := generatedRuntimePlanFixture(t, recovery)
	g, err := contract.DecodeGeneratorPlanBundle(f.graph)
	if err != nil {
		t.Fatal(err)
	}
	id := consumerID
	_, routeID := generatedFixtureRoute(t)
	intent := generatedFixtureIntent(id("configuration contract"), id("resource contract"), contract.GeneratorLifecycleManaged, `{"name":"token"}`)
	intentID, err := contract.GeneratorIntentDigest(intent)
	if err != nil {
		t.Fatal(err)
	}
	meta := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Epoch: 1, RetirementMode: 1, ConfigContractID: id("configuration contract"), ResourceContractID: id("resource contract"), CompletionClass: 1, Intent: intent}
	payload, err := contract.EncodeGeneratorDeclaredGeneration(meta)
	if err != nil {
		t.Fatal(err)
	}
	recipients := []contract.ID{f.base.control.AuthorityRecipientID}
	declaration := contract.GeneratorDeclaration{Schema: 1, DomainID: g.Header.DomainID, OperationID: g.Header.OperationID,
		Entries: []contract.GeneratorDeclarationEntry{{InputEncoding: encoding, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationGenerated, Name: "token", Recipients: recipients, Payload: payload}}}
	f.declaration, err = contract.EncodeGeneratorDeclaration(declaration)
	if err != nil {
		t.Fatal(err)
	}
	g.Request.Declaration, err = contract.GeneratorDeclarationDescriptor(declaration)
	if err != nil {
		t.Fatal(err)
	}
	x := contract.GeneratorLineageTemplate{Schema: contract.GeneratorLineageTemplateSchema, Purpose: 1, DomainID: g.Header.DomainID, OperationID: g.Header.OperationID,
		Name: "token", EntryIncarnationID: id("member incarnation"), Epoch: 1, IntentDigest: intentID, TemplateCount: 5}
	x.LineageID, err = contract.GeneratorLineageID(x.DomainID, x.OperationID, x.Name, x.EntryIncarnationID, x.Epoch, x.IntentDigest)
	if err != nil {
		t.Fatal(err)
	}
	for i := range x.Templates {
		v := contract.GeneratorAttemptTemplate{Schema: contract.GeneratorAttemptTemplateSchema, Branch: uint8(i), Action: 1, LineageID: x.LineageID, DescriptorID: id("descriptor"),
			ConfigContractID: meta.ConfigContractID, ExecutorID: id("executor"), CredentialRouteID: routeID,
			ResourceContractID: meta.ResourceContractID, ResultContractID: id("create result contract"), IntentDigest: intentID,
			LifecycleMode: meta.LifecycleMode, ResultReaderID: contract.GeneratorResultReaderFor(1, 1, encoding), TargetKind: 1, TargetSourceID: intentID, CompletionClass: 1, RequiredAuthoritySet: 1}
		if len(createResultContract) == 1 {
			v.ResultContractID = createResultContract[0]
		}
		v.AttemptID, err = contract.GeneratorAttemptID(x.LineageID, v.Branch)
		if err != nil {
			t.Fatal(err)
		}
		if i != 0 {
			branch := uint8(0)
			if i > 2 {
				branch = uint8(i - 2)
			}
			v.PredecessorAttemptID, err = contract.GeneratorAttemptID(x.LineageID, branch)
			if err != nil {
				t.Fatal(err)
			}
		}
		v.ResourceIncarnationID, err = contract.GeneratorResourceID(x.DomainID, x.OperationID, v.AttemptID)
		if err != nil {
			t.Fatal(err)
		}
		v.PlannedValueSlotID, err = contract.GeneratorValueSlotID(x.DomainID, x.OperationID, v.AttemptID)
		if err != nil {
			t.Fatal(err)
		}
		v.DutyID, err = contract.GeneratorDutyID(x.DomainID, x.OperationID, v.AttemptID, 1)
		if err != nil {
			t.Fatal(err)
		}
		v.HazardID, err = contract.GeneratorHazardID(x.DomainID, v.AttemptID)
		if err != nil {
			t.Fatal(err)
		}
		v.TransmissionID, err = contract.GeneratorTransmissionID(v.AttemptID, 1)
		if err != nil {
			t.Fatal(err)
		}
		v.ResultID, err = contract.GeneratorResultID(x.DomainID, x.OperationID, v.AttemptID, v.TransmissionID, 1)
		if err != nil {
			t.Fatal(err)
		}
		v.InboxID, err = contract.GeneratorInboxID(x.DomainID, x.OperationID, v.AttemptID, v.ResultID)
		if err != nil {
			t.Fatal(err)
		}
		v.RequestPlanDigest, err = contract.GeneratorRequestPlanDigest(v)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 || i == 2 {
			v.NoEffectBudget = 1
		}
		if i == 0 || i == 1 {
			v.ResidueBudget = 1
		}
		x.Templates[i] = v
	}
	g.Lineages = []contract.GeneratorLineageTemplate{x}
	for _, create := range x.Templates {
		cleanup := contract.GeneratorLineageTemplate{Schema: contract.GeneratorLineageTemplateSchema, Purpose: 3, DomainID: x.DomainID, OperationID: x.OperationID, Name: x.Name,
			EntryIncarnationID: x.EntryIncarnationID, Epoch: x.Epoch, IntentDigest: intentID, ResourceIncarnationID: create.ResourceIncarnationID, TemplateCount: 1}
		cleanup.LineageID, err = contract.GeneratorObligationLineageID(x.DomainID, x.OperationID, cleanup.ResourceIncarnationID, 3)
		if err != nil {
			t.Fatal(err)
		}
		v := create
		v.ResultReaderID = contract.GeneratorResultReaderFor(contract.GeneratorActionDelete, v.CompletionClass, contract.InputEncodingRaw)
		v.Action, v.Branch, v.NoEffectBudget, v.ResidueBudget, v.TargetKind = 2, 0, 0, 0, 3
		v.LineageID, v.TargetSourceID, v.PredecessorAttemptID, v.ResultContractID = cleanup.LineageID, create.ResultID, contract.ID{}, id("delete result contract")
		v.AttemptID, err = contract.GeneratorAttemptID(v.LineageID, 0)
		if err != nil {
			t.Fatal(err)
		}
		v.PlannedValueSlotID, err = contract.GeneratorValueSlotID(x.DomainID, x.OperationID, v.AttemptID)
		if err != nil {
			t.Fatal(err)
		}
		v.HazardID, err = contract.GeneratorHazardID(x.DomainID, v.AttemptID)
		if err != nil {
			t.Fatal(err)
		}
		v.TransmissionID, err = contract.GeneratorTransmissionID(v.AttemptID, 2)
		if err != nil {
			t.Fatal(err)
		}
		v.ResultID, err = contract.GeneratorResultID(x.DomainID, x.OperationID, v.AttemptID, v.TransmissionID, 2)
		if err != nil {
			t.Fatal(err)
		}
		v.InboxID, err = contract.GeneratorInboxID(x.DomainID, x.OperationID, v.AttemptID, v.ResultID)
		if err != nil {
			t.Fatal(err)
		}
		v.RequestPlanDigest, err = contract.GeneratorRequestPlanDigest(v)
		if err != nil {
			t.Fatal(err)
		}
		cleanup.Templates[0] = v
		g.Lineages = append(g.Lineages, cleanup)
	}
	slices.SortFunc(g.Lineages, func(a, b contract.GeneratorLineageTemplate) int {
		if a.Purpose != b.Purpose {
			return int(a.Purpose) - int(b.Purpose)
		}
		return bytes.Compare(a.ResourceIncarnationID[:], b.ResourceIncarnationID[:])
	})
	membership, err := contract.GeneratorIntendedMembershipDescriptor(recipients)
	if err != nil {
		t.Fatal(err)
	}
	g.ValueEntryPlans = []contract.GeneratorValueEntryPlan{{InputEncoding: encoding, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorValueEntryPlanSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Name: x.Name, ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, EntryIncarnationID: x.EntryIncarnationID,
		Epoch: 1, IntentDigest: intentID, PlannedValueSlotID: x.Templates[0].PlannedValueSlotID, IntendedMembership: membership, LineageID: x.LineageID, RetirementMode: 1, ChangeMask: 1}}
	g.Header.ValueEntryPlanCount, g.Header.LineageCount, g.Header.TemplateCount = 1, 1, 10
	g.Header.RequestCoreDigest, err = contract.GeneratorRequestCoreDigest(g.Request)
	if err != nil {
		t.Fatal(err)
	}
	join, err := contract.GeneratorCompleteJoinID(g.Header.RequestCoreDigest)
	if err != nil {
		t.Fatal(err)
	}
	for _, lineage := range g.Lineages {
		for _, v := range lineage.Templates[:lineage.TemplateCount] {
			source, err := contract.GeneratorTemplateID(v)
			if err != nil {
				t.Fatal(err)
			}
			for guard := uint8(1); guard <= 4; guard++ {
				branch, destination := v.Branch, join
				if guard < 3 {
					if v.Action != 1 {
						continue
					}
					next, present, err := contract.GeneratorSuccessorBranch(v.Branch, guard)
					if err != nil {
						t.Fatal(err)
					}
					if !present {
						continue
					}
					branch = next
					destination, err = contract.GeneratorTemplateID(lineage.Templates[next])
					if err != nil {
						t.Fatal(err)
					}
				}
				n, r := uint8(0), uint8(0)
				if branch == 1 || branch == 3 || branch == 4 {
					n = 1
				}
				if branch >= 2 {
					r = 1
				}
				g.Edges = append(g.Edges, contract.GeneratorEdge{Schema: 1, SourceTemplateID: source, DestinationTemplateID: destination, Guard: guard, ResultSlotID: v.ResultID, RequiredAuthoritySet: 1, NoEffectUsed: n, ResidueUsed: r})
			}
			maximum := uint32(65536)
			if v.Action == 2 {
				maximum = 0
			}
			g.ResultUses = append(g.ResultUses, contract.GeneratorResultUse{Schema: 1, AttemptID: v.AttemptID, ResultID: v.ResultID, InboxID: v.InboxID, ExecutorID: v.ExecutorID,
				ResultContractID: v.ResultContractID, PlannedValueSlotID: v.PlannedValueSlotID, MaterialID: g.Header.MaterialID, Purpose: 1, MaxSecret: maximum, MaxFacts: 4096})
		}
	}
	slices.SortFunc(g.Edges, func(a, b contract.GeneratorEdge) int {
		if c := bytes.Compare(a.SourceTemplateID[:], b.SourceTemplateID[:]); c != 0 {
			return c
		}
		return int(a.Guard) - int(b.Guard)
	})
	slices.SortFunc(g.ResultUses, func(a, b contract.GeneratorResultUse) int { return bytes.Compare(a.AttemptID[:], b.AttemptID[:]) })
	g.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(g.Header, g.ValueEntryPlans, g.Lineages, g.Edges)
	if err != nil {
		t.Fatal(err)
	}
	g.UsePlan.ResultUses, err = contract.GeneratorResultUsesDescriptor(g.ResultUses)
	if err != nil {
		t.Fatal(err)
	}
	if err := contract.ValidateGeneratorEffectGraph(g); err != nil {
		t.Fatal(err)
	}
	return generatedRuntimeEffectGraphFixture(t, f, g)
}

func generatedRuntimeEffectGraphFixture(t *testing.T, f generatedRuntimeFixture, g contract.GeneratorPlanBundle) generatedRuntimeFixture {
	t.Helper()
	var err error
	f.graph, err = contract.EncodeGeneratorPlanBundle(g)
	if err != nil {
		t.Fatal(err)
	}
	f.compare.PlanGraph, err = contract.GeneratorPlanBundleDescriptor(g)
	if err != nil {
		t.Fatal(err)
	}
	f.compare.IntendedEntryPlans, err = contract.GeneratorValueEntryPlansDescriptor(g.ValueEntryPlans)
	if err != nil {
		t.Fatal(err)
	}
	f.compare.UsePlanDigest, err = contract.GeneratorUsePlanDigest(g.UsePlan)
	if err != nil {
		t.Fatal(err)
	}
	p := &f.compare.ParentPlan
	p.ValueEntryPlanCount, p.LineageCount, p.TemplateCount = g.Header.ValueEntryPlanCount, g.Header.LineageCount, g.Header.TemplateCount
	p.RequestCoreDigest, p.PlanGraphID, p.UsePlanDigest = g.Header.RequestCoreDigest, g.UsePlan.PlanGraphID, f.compare.UsePlanDigest
	p.Declaration, p.Graph, p.IntendedEntryPlans = g.Request.Declaration, f.compare.PlanGraph, f.compare.IntendedEntryPlans
	f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
	if err != nil {
		t.Fatal(err)
	}
	f.reservation.Plan.Declaration, f.reservation.Session.Graph = f.declaration, f.graph
	return f
}

func generatedTestSeed(t *testing.T, f generatedRuntimeFixture, result contract.CryptoGeneratedFinishPlanResult) []byte {
	t.Helper()
	access, err := contract.DecodeAccessRecord(result.SeedAccess)
	if err != nil {
		t.Fatal(err)
	}
	wrap := access.Wraps[0]
	i := applyBindingIndex(f.base.q.Bindings, wrap.SubjectID)
	core, err := custody.SeedWrapCore(result.Material.Core, f.base.q.Bindings[i])
	if err != nil {
		t.Fatal(err)
	}
	packet, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, f.base.keys[wrap.SubjectID], wrap.RSACiphertext, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(packet[:cap(packet)])
	digest, err := contract.RSAPacketContextDigest(core)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := custody.PacketKeys(packet, core.PacketKind, digest)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(keys)
}

func generatedAdoptionFixture(t *testing.T, recovery bool) (generatedRuntimeFixture, contract.CryptoGeneratedFinishPlanResult, []byte) {
	t.Helper()
	return generatedAdoptionFixtureWithValue(t, recovery, contract.InputEncodingRaw, []byte("provider-secret"), false)
}

func generatedAdoptionFixtureWithValue(t *testing.T, recovery bool, encoding uint8, value []byte, fillFacts bool) (generatedRuntimeFixture, contract.CryptoGeneratedFinishPlanResult, []byte) {
	t.Helper()
	f := generatedRuntimeEffectFixtureForEncoding(t, recovery, encoding)
	r := f.reservationRuntime(t)
	op := generatedCompare(t, r, f)
	generatedPlanParts(t, r, f, op)
	prepared := generatedFinishPlan(t, r, f, op)
	seed := generatedTestSeed(t, f, prepared)
	defer clear(seed)
	g, err := contract.DecodeGeneratorPlanBundle(f.graph)
	if err != nil {
		t.Fatal(err)
	}
	template := g.Lineages[0].Templates[0]
	use := g.ResultUses[slices.IndexFunc(g.ResultUses, func(row contract.GeneratorResultUse) bool { return row.ResultID == template.ResultID })]
	expected := contract.GeneratorResultExpectation{InputEncoding: g.ValueEntryPlans[0].InputEncoding, Plan: g.UsePlan, Template: template, Use: use, RequestDigest: consumerID("HTTP request")}
	facts := generatedProducerFacts(expected)
	if fillFacts {
		facts.ProviderFacts = make([]byte, 4096-115-len(facts.Target)-len(facts.ResourceData))
	}
	result, err := custody.SealGeneratedResult(expected, prepared.Material, facts, seed, value)
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeGeneratedResultRecord(result)
	if err != nil {
		t.Fatal(err)
	}
	ref := contract.GeneratorResultReference{Schema: 1, ResultID: template.ResultID, ResultBodyDigest: contract.Hash(body), ResultLength: uint32(len(body))}
	current := generatedPlanCandidate(t, f, prepared)
	session := f.reservation.Session
	session.Control.CurrentControl, session.BeforePublic = current.CurrentAccess.CurrentControl, current.PublicState
	session.Output = generatedEmptyOutputWitness(t, &session.BeforePublic, current.Entries, current.SupportRecords)
	f.compare.Context.CurrentAccessRoot = current.PublicState.AccessRoot
	f.compare.Parent = contract.GeneratedParentRecord(f.compare.ParentPlan)
	f.compare.Parent.RequestIdentityDigest = consumerID("final generated request")
	f.compare.ParentPlan = contract.GeneratedParentPlan{}
	f.compare.Purpose = 2
	f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
	if err != nil {
		t.Fatal(err)
	}
	phase := contract.GeneratorPhaseIdentity{RequestIdentityDigest: f.compare.Parent.RequestIdentityDigest, ObservedHEADDigest: f.compare.Context.PredecessorHEADDigest,
		ConditionDigest: f.compare.Context.OriginalConditionDigest, TransitionKind: contract.GeneratorAuthorityRecord, BeforePhase: 1, AfterPhase: 2,
		Evidence: contract.GeneratorDescriptor{Digest: contract.Hash(body), Length: uint64(len(body)), Count: 1}}
	f.adoption = generatedAdoptionAdmissionInput{
		Session: session, Plan: f.reservation.Plan, Phase: phase, Target: f.reservation.Target,
		Material: prepared.Material, SeedAccess: prepared.SeedAccess,
		Result:                generatedResultAdmission{Expected: expected, Reference: ref},
		ControlledPredecessor: f.reservation.ControlledPredecessor,
	}
	r.retireGenerated()
	return f, prepared, body
}

func generatedAdoptionCompare(t *testing.T, r *Runtime, f generatedRuntimeFixture) (contract.ID, []contract.KeyUseRow) {
	t.Helper()
	body, err := contract.EncodeCryptoGeneratedCompareRequest(f.compare)
	if err != nil {
		t.Fatal(err)
	}
	reply := applyCall(r, context.Background(), contract.CryptoCompare, body)
	if reply.ResultCode != contract.CryptoSuccess || len(reply.KeyUseRows) != 1 || reply.KeyUseRows[0].Purpose != contract.KeyUseMaterialOpen {
		t.Fatal("current seed", reply.ResultCode, reply.KeyUseRows)
	}
	operation, err := contract.InspectCryptoGeneratedCompareResult(reply.Body)
	if err != nil {
		t.Fatal(err)
	}
	return operation.OperationRef, reply.KeyUseRows
}

func generatedAdoptBody(t *testing.T, f generatedRuntimeFixture, operation contract.ID, result []byte) []byte {
	t.Helper()
	body, err := contract.EncodeCryptoGeneratedAdoptRequest(contract.CryptoGeneratedAdoptRequest{OperationRef: operation, Context: f.compare.Context, Result: result,
		ExpectedResult: contract.GeneratorDescriptor{Digest: contract.Hash(result), Length: uint64(len(result)), Count: 1}})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func generatedAdoptionCandidate(t *testing.T, f generatedRuntimeFixture, prepared contract.CryptoGeneratedFinishPlanResult, result []byte) generatedCandidate {
	t.Helper()
	initial := f
	initial.reservation.Session.BeforePublic.Rows = nil
	initial.compare.ParentPlan = contract.GeneratedParentPlan(f.compare.Parent)
	initial.compare.ParentPlan.RequestIdentityDigest = contract.ID{}
	c := generatedPlanCandidate(t, initial, prepared)
	p := f.adoption.Phase
	phase, err := contract.GeneratorPhaseID(p)
	if err != nil {
		t.Fatal(err)
	}
	head, err := format.DecodeHeadCore(c.HeadCore)
	if err != nil {
		t.Fatal(err)
	}
	head.Revision, err = contract.GeneratorPhaseRevisionID(phase)
	if err != nil {
		t.Fatal(err)
	}
	head.Root.Object, err = contract.GeneratorPhaseSnapshotID(phase)
	if err != nil {
		t.Fatal(err)
	}
	c.HeadCore, err = format.EncodeHeadCore(head)
	if err != nil {
		t.Fatal(err)
	}
	conditional, err := format.DecodeConditionalPlan(c.Conditional)
	if err != nil {
		t.Fatal(err)
	}
	conditional.HeadCore = contract.Hash(c.HeadCore)
	c.Conditional, err = format.EncodeConditionalPlan(conditional)
	if err != nil {
		t.Fatal(err)
	}
	x, ref := f.adoption.Result.Expected.Template, f.adoption.Result.Reference
	c.Subject.Purpose, c.Subject.PhaseID, c.Subject.BeforePhase, c.Subject.AfterPhase = p.TransitionKind, phase, p.BeforePhase, p.AfterPhase
	c.Subject.LineageID, c.Subject.AttemptID, c.Subject.ResultID, c.Subject.ResultDigest = x.LineageID, x.AttemptID, ref.ResultID, ref.ResultBodyDigest
	c.Subject.DescriptorID, c.Subject.ConfigContractID, c.Subject.ResultContractID = x.DescriptorID, x.ConfigContractID, x.ResultContractID
	c.Subject.HeadCoreDigest, c.Subject.ConditionalPlanDigest = contract.Hash(c.HeadCore), contract.Hash(c.Conditional)
	c.SupportRecords = append(c.SupportRecords, contract.SupportRecord{Kind: 4, RecordID: ref.ResultID, Body: bytes.Clone(result)})
	generatedCanonicalizeCandidateSupport(t, &c)
	return c
}

// full_only: false
func TestGeneratedRuntimeAdoptsExactOriginalResult(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		f, prepared, body := generatedAdoptionFixture(t, recovery)
		ref := f.adoption.Result.Reference
		r := f.adoptionRuntime(t)
		request, err := contract.EncodeCryptoGeneratedCompareRequest(f.compare)
		if err != nil {
			t.Fatal(err)
		}
		compare := applyCall(r, context.Background(), contract.CryptoCompare, request)
		if compare.ResultCode != contract.CryptoSuccess || len(compare.KeyUseRows) != 1 || compare.KeyUseRows[0].Purpose != contract.KeyUseMaterialOpen {
			t.Fatal("current seed", compare.ResultCode, compare.KeyUseRows)
		}
		operation, err := contract.InspectCryptoGeneratedCompareResult(compare.Body)
		if err != nil {
			t.Fatal(err)
		}
		request, err = contract.EncodeCryptoGeneratedAdoptRequest(contract.CryptoGeneratedAdoptRequest{OperationRef: operation.OperationRef, Context: f.compare.Context, Result: body,
			ExpectedResult: contract.GeneratorDescriptor{Digest: ref.ResultBodyDigest, Length: uint64(ref.ResultLength), Count: 1}})
		if err != nil {
			t.Fatal(err)
		}
		adopt := applyCall(r, context.Background(), contract.CryptoPrepare, request)
		if adopt.ResultCode != contract.CryptoSuccess || len(adopt.KeyUseRows) != 0 {
			t.Fatal("adopt", adopt.ResultCode)
		}
		validated, err := contract.InspectCryptoGeneratedAdoptResult(adopt.Body)
		if err != nil || !bytes.Equal(validated.Result, body) {
			t.Fatal("adoption changed original bytes", err)
		}
		candidate := generatedAdoptionCandidate(t, f, prepared, body)
		if code := r.bindGeneratedCandidate(context.Background(), f.compare.Context.AdmissionID, candidate); code != contract.CryptoSuccess {
			t.Fatal("adopt candidate", code)
		}
		q := generatedCandidateRequest(t, f, operation.OperationRef, candidate, []contract.GeneratorResultReference{ref}, compare.KeyUseRows)
		if reply := generatedFreeze(t, r, q); reply.ResultCode != contract.CryptoSuccess {
			t.Fatal("adopt freeze", reply.ResultCode)
		}
		claim, err := contract.EncodeCryptoGeneratedClaimRequest(contract.CryptoGeneratedClaimRequest(q))
		if err != nil {
			t.Fatal(err)
		}
		if reply := applyCall(r, context.Background(), contract.CryptoClaim, claim); reply.ResultCode != contract.CryptoSuccess {
			t.Fatal("adopt claim", reply.ResultCode)
		}
	}
}

// full_only: false
func TestGeneratedAdoptionRejectsUnauthenticatedOriginalResult(t *testing.T) {
	f, _, original := generatedAdoptionFixture(t, false)
	for _, test := range []struct {
		name   string
		repin  bool
		mutate func(*contract.GeneratedResultRecord)
	}{
		{"unselected physical object", false, func(v *contract.GeneratedResultRecord) { v.Payload.Ciphertext[0] ^= 1 }},
		{"result AEAD", true, func(v *contract.GeneratedResultRecord) { v.Payload.Ciphertext[0] ^= 1 }},
		{"result HMAC", true, func(v *contract.GeneratedResultRecord) { v.Payload.SemanticCommitment[0] ^= 1 }},
		{"result transfer", true, func(v *contract.GeneratedResultRecord) { v.Transfer.Ciphertext[0] ^= 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed, err := contract.DecodeGeneratedResultRecord(original)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&changed)
			body, err := contract.EncodeGeneratedResultRecord(changed)
			if err != nil {
				t.Fatal(err)
			}
			x := f
			x.adoption.Result = f.adoption.Result
			want := contract.CryptoInvalidAdmission
			if test.repin {
				x.adoption.Result.Reference.ResultBodyDigest = contract.Hash(body)
				want = contract.CryptoStoredAuthenticationFailed
			}
			r := x.adoptionRuntime(t)
			operation, _ := generatedAdoptionCompare(t, r, x)
			reply := applyCall(r, context.Background(), contract.CryptoPrepare, generatedAdoptBody(t, x, operation, body))
			if reply.ResultCode != want || len(reply.Body) != 0 || len(reply.KeyUseRows) != 0 {
				t.Fatal("changed original result", reply.ResultCode, want)
			}
		})
	}
}

// full_only: false
func TestGeneratedAdoptionChecksExactCurrentSeedAndGraph(t *testing.T) {
	f, _, _ := generatedAdoptionFixture(t, true)
	for _, test := range []struct {
		name   string
		mutate func(*generatedAdoptionAdmissionInput)
	}{
		{"missing recovery", func(v *generatedAdoptionAdmissionInput) {
			a, e := contract.DecodeAccessRecord(v.SeedAccess)
			if e != nil {
				t.Fatal(e)
			}
			a.Wraps = a.Wraps[:1]
			v.SeedAccess, e = contract.EncodeAccessRecord(a)
			if e != nil {
				t.Fatal(e)
			}
		}},
		{"wrong current binding", func(v *generatedAdoptionAdmissionInput) {
			a, e := contract.DecodeAccessRecord(v.SeedAccess)
			if e != nil {
				t.Fatal(e)
			}
			a.Wraps[0].BindingSerial++
			v.SeedAccess, e = contract.EncodeAccessRecord(a)
			if e != nil {
				t.Fatal(e)
			}
		}},
		{"changed graph template", func(v *generatedAdoptionAdmissionInput) {
			v.Result.Expected.Template.CredentialRouteID = consumerID("another provider route")
		}},
		{"changed graph use", func(v *generatedAdoptionAdmissionInput) { v.Result.Expected.Use.MaxSecret-- }},
		{"changed graph input class", func(v *generatedAdoptionAdmissionInput) {
			v.Result.Expected.InputEncoding = contract.InputEncodingBase64
		}},
		{"changed phase predecessor", func(v *generatedAdoptionAdmissionInput) {
			v.Phase.ObservedHEADDigest = consumerID("another predecessor")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			x := f
			x.adoption.Result = f.adoption.Result
			test.mutate(&x.adoption)
			r := newConsumerRuntime(t, f.base.route)
			if err := r.admitGeneratedAdoption(x.compare, x.adoption, x.base.deadline); err == nil || r.slot != nil {
				t.Fatal("invalid continuation admitted", err)
			}
		})
	}
}

// full_only: false
func TestGeneratedAdoptionDuplicateAndCancellation(t *testing.T) {
	f, _, body := generatedAdoptionFixture(t, false)
	t.Run("duplicate", func(t *testing.T) {
		r := f.adoptionRuntime(t)
		op, _ := generatedAdoptionCompare(t, r, f)
		request := generatedAdoptBody(t, f, op, body)
		if reply := applyCall(r, context.Background(), contract.CryptoPrepare, request); reply.ResultCode != contract.CryptoSuccess {
			t.Fatal(reply.ResultCode)
		}
		if reply := applyCall(r, context.Background(), contract.CryptoPrepare, request); reply.ResultCode != contract.CryptoAlreadyUsed || len(reply.Body) != 0 {
			t.Fatal(reply.ResultCode)
		}
	})
	t.Run("cancel", func(t *testing.T) {
		r := f.adoptionRuntime(t)
		op, _ := generatedAdoptionCompare(t, r, f)
		a := r.generated
		seed := a.seed
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		reply := applyCall(r, ctx, contract.CryptoPrepare, generatedAdoptBody(t, f, op, body))
		if reply.ResultCode != contract.CryptoCancelled || len(reply.Body) != 0 {
			t.Fatal(reply.ResultCode)
		}
		select {
		case <-a.done:
		case <-time.After(time.Second):
			t.Fatal("cancel did not join")
		}
		for _, b := range seed {
			if b != 0 {
				t.Fatal("seed not cleared")
			}
		}
	})
}

// full_only: false
func TestGeneratedAdoptionAbandonedStagesExpireWithoutAnotherCall(t *testing.T) {
	for _, stage := range []string{"compare", "adopt", "freeze"} {
		t.Run(stage, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f, prepared, body := generatedAdoptionFixture(t, true)
				r := f.adoptionRuntime(t)
				a := r.generated
				op, uses := generatedAdoptionCompare(t, r, f)
				r.mu.Lock()
				seed := a.seed[:cap(a.seed)]
				loaded := len(seed) != 0 && !bytes.Equal(seed, make([]byte, len(seed)))
				r.mu.Unlock()
				if !loaded {
					t.Fatal("adoption did not retain its private seed")
				}
				if stage != "compare" {
					if reply := applyCall(r, context.Background(), contract.CryptoPrepare, generatedAdoptBody(t, f, op, body)); reply.ResultCode != contract.CryptoSuccess {
						t.Fatal("adopt", reply.ResultCode)
					}
				}
				if stage == "freeze" {
					candidate := generatedAdoptionCandidate(t, f, prepared, body)
					if code := r.bindGeneratedCandidate(context.Background(), f.compare.Context.AdmissionID, candidate); code != contract.CryptoSuccess {
						t.Fatal("bind candidate", code)
					}
					q := generatedCandidateRequest(t, f, op, candidate, []contract.GeneratorResultReference{f.adoption.Result.Reference}, uses)
					if reply := generatedFreeze(t, r, q); reply.ResultCode != contract.CryptoSuccess {
						t.Fatal("freeze", reply.ResultCode)
					}
				}
				public, private := f.base.route.publicCalls, f.base.route.privateCalls
				synctest.Wait()
				select {
				case <-a.done:
					t.Fatal("abandoned owner disposed before its deadline")
				default:
				}
				time.Sleep(time.Until(f.base.deadline))
				synctest.Wait()
				select {
				case <-a.done:
				default:
					t.Fatal("abandoned owner did not join at its deadline")
				}
				if !bytes.Equal(seed, make([]byte, len(seed))) || len(a.seed) != 0 || len(a.graph.ValueEntryPlans) != 0 || len(a.bindings) != 0 ||
					a.candidate != nil || a.purpose.valid(a.request.Purpose) {
					t.Fatal("expired owner retained private material or phase state")
				}
				if f.base.route.publicCalls != public || f.base.route.privateCalls != private {
					t.Fatal("expiry repeated private work")
				}
			})
		})
	}
}

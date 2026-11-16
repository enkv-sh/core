package contract

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// Field-by-field Python struct/hashlib derivation uses domainR1, operationR2,
// entry incarnationR3, name 'local', epoch7, configR6, descriptorR5,
// executorR11, routeR12 and resultContractR10. Intent is schema1/configR6/
// lifecycleNone/zeroResource/B("{}"). D frames each exact purpose preimage.
const localTemplateV2Hex = "0003010001470d1eb64320db29218cb191cc7f5b5372a257483b5cf1ee9666495449d400f59a673ec8a6cf4dfd92f8c0124868fa71cfe8a49c6c905fdc9eaefc71425ed4ae0000000000000000000000000000000000000000000000000000000000000000d2562d1bea02d1b09697acc6780866e9bc69fba62958a7f15d19b72ef76d78441549c24297f24642b5b30a05934156cf54f66989decc27a77c0f17cd122048dfb38e7bea1feb4d6ccf832388ed95d1072559d3cba0b83bcfed9c029d128490b7000000000000000000000000000000000000000000000000000000000000000087074d38dba2c8f9ab1c4f9d3b8485d5fac3fadb20920c83ba5f9993a0e893a49e3dba24fe99754cbf5671f49f6fe9a84c4638310d4a90f56e9ae86849720ae1a5d9a1bfe99916c0c45151d8eb6f3c848cb41fbe07831e39b24f9c1a491bada5050505050505050505050505050505050505050505050505050505050505050506060606060606060606060606060606060606060606060606060606060606060b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00000000000000000000000000000000000000000000000000000000000000000a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0ae8a59f84c8979f4ef92150321dc447c0b4fb044fc172fe5f2505cdb6c5d44d58dfcb8a54c9b7bb0949b823bee773863ecd8fa6076338e783f1b7b86630a2435d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000125688804097da352e9559dced75dee8085acf065855c3cc7ec5c46c106c0022e"

func localTemplateFixture(t *testing.T) GeneratorAttemptTemplate {
	t.Helper()
	body, err := hex.DecodeString(localTemplateV2Hex)
	if err != nil {
		t.Fatal(err)
	}
	v, err := InspectGeneratorAttemptTemplate(body)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// full_only: false
func TestGeneratorDeclarationOwnerDisambiguatesRetainedEpoch(t *testing.T) {
	current := GeneratorDeclaredGeneration{Schema: GeneratorDeclaredGenerationSchema, LifecycleMode: GeneratorLifecycleManaged,
		Epoch: 0x0002000000000000, RetirementMode: GeneratedRetirementManual, ConfigContractID: generatedRecordID(2), ResourceContractID: generatedRecordID(3), CompletionClass: GeneratedCompletionAcknowledged,
		Intent: generatorIntentFixture(t, generatedRecordID(2), generatedRecordID(3), GeneratorLifecycleManaged, []byte("{}"))}
	body, err := EncodeGeneratorDeclaredGeneration(current)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := InspectGeneratorDeclaredGenerationForEntry(GeneratorDeclarationEntrySchema, body)
	if err != nil || decoded.Epoch != current.Epoch || decoded.Schema != GeneratorDeclaredGenerationSchema {
		t.Fatal("epoch changed interpretation", err)
	}
	for _, owner := range []uint16{1, 2} {
		if _, err := InspectGeneratorDeclaredGenerationForEntry(owner, body); err == nil {
			t.Fatal("superseded owner admitted new payload", owner)
		}
	}
	for _, schema := range []byte{1, 2} {
		old := bytes.Clone(body)
		old[1] = schema
		if _, err := InspectGeneratorDeclaredGenerationForEntry(GeneratorDeclarationEntrySchema, old); err == nil {
			t.Fatal("new owner inferred superseded payload", schema)
		}
	}
	local := GeneratorDeclaredGeneration{
		Schema:           GeneratorDeclaredGenerationSchema,
		LifecycleMode:    GeneratorLifecycleNone,
		Epoch:            7,
		ConfigContractID: generatedRecordID(2),
		Intent:           generatorIntentFixture(t, generatedRecordID(2), ID{}, GeneratorLifecycleNone, []byte("{}")),
	}
	payload, err := EncodeGeneratorDeclaredGeneration(local)
	if err != nil || len(payload) != 154 {
		t.Fatal("local declaration bound", err)
	}
	recipients := make([]ID, CryptoMaxValueEntryRecipients)
	for i := range recipients {
		recipients[i] = generatedRecordID(byte(i + 1))
	}
	row := GeneratorDeclarationEntry{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Schema: GeneratorDeclarationEntrySchema, Kind: GeneratorDeclarationGenerated, Name: strings.Repeat("x", CryptoMaxName), Recipients: recipients, Payload: payload}
	encoded, err := EncodeGeneratorDeclarationEntry(row)
	if err != nil || len(encoded) != 2473 {
		t.Fatal("local row maximum", len(encoded), err)
	}
	current.Intent = generatorIntentLengthFixture(t, current.ConfigContractID, current.ResourceContractID, current.LifecycleMode, GeneratorIntentMaxLength)
	row.Payload, err = EncodeGeneratorDeclaredGeneration(current)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = EncodeGeneratorDeclarationEntry(row)
	if err != nil || len(encoded) != 395616 {
		t.Fatal("managed row maximum", len(encoded), err)
	}
}

// full_only: false
func TestLocalGeneratorTemplateIndependentReaderBinding(t *testing.T) {
	v := localTemplateFixture(t)
	body, err := EncodeGeneratorAttemptTemplate(v)
	want, _ := hex.DecodeString(localTemplateV2Hex)
	if err != nil || len(body) != 682 || !bytes.Equal(body, want) || Hash(body) != profileLiteralID(t, "9317a3014e516dafca25910db4c81c13e6125ae748d0b783dc9e39becea11759") {
		t.Fatal("template differs from independent bytes", err)
	}
	id, err := GeneratorTemplateID(v)
	if err != nil || id != profileLiteralID(t, "7deb7342d88e6a5180ab4f73c80a37e5b0ee0566dae4a18227d3ebed51009334") {
		t.Fatal("template digest differs", err)
	}
	v.ResultReaderID = Hash([]byte("superseded result reader"))
	if _, err := EncodeGeneratorAttemptTemplate(v); err == nil {
		t.Fatal("local selected old result reader")
	}
}

func localGraphFixture(t *testing.T) (GeneratorDeclaration, GeneratorPlanBundle) {
	t.Helper()
	x := localTemplateFixture(t)
	declared := GeneratorDeclaredGeneration{
		Schema:           GeneratorDeclaredGenerationSchema,
		LifecycleMode:    GeneratorLifecycleNone,
		Epoch:            7,
		ConfigContractID: x.ConfigContractID,
		Intent:           generatorIntentFixture(t, x.ConfigContractID, ID{}, GeneratorLifecycleNone, []byte("{}")),
	}
	payload, err := EncodeGeneratorDeclaredGeneration(declared)
	if err != nil {
		t.Fatal(err)
	}
	d := GeneratorDeclaration{Schema: 1, DomainID: generatedRecordID(1), OperationID: generatedRecordID(2), Entries: []GeneratorDeclarationEntry{{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Schema: GeneratorDeclarationEntrySchema, Kind: GeneratorDeclarationGenerated, Name: "local", Recipients: []ID{generatedRecordID(30)}, Payload: payload}}}
	descriptor, err := GeneratorDeclarationDescriptor(d)
	if err != nil {
		t.Fatal(err)
	}
	empty := generatedRecordDescriptor(0xee)
	request := GeneratorRequestCore{Schema: GeneratorRequestCoreSchema, OperationKind: OperationApplyDeclaration, DomainID: d.DomainID, OperationID: d.OperationID, PredecessorRevisionID: generatedRecordID(20), PredecessorHEADDigest: generatedRecordID(21), ConditionDigest: generatedRecordID(22), CallerNonce: generatedRecordID(23), Declaration: descriptor, Registry: empty, CompatibilityID: generatedRecordID(24), RecoveryPolicyID: GeneratorRecoveryPolicyID()}
	requestID, err := GeneratorRequestCoreDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	material, err := GeneratorMaterialID(d.DomainID, d.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	header := GeneratorGraphHeader{Schema: GeneratorGraphHeaderSchema, DomainID: d.DomainID, OperationID: d.OperationID, MaterialID: material, RequestCoreDigest: requestID, RecoveryPolicyID: request.RecoveryPolicyID, ValueEntryPlanCount: 1, LineageCount: 1, TemplateCount: 1}
	membership, err := GeneratorIntendedMembershipDescriptor([]ID{generatedRecordID(30)})
	if err != nil {
		t.Fatal(err)
	}
	plan := GeneratorValueEntryPlan{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Schema: GeneratorValueEntryPlanSchema, LifecycleMode: GeneratorLifecycleNone, Name: "local", ValueSource: Generated, ConfidentialityClass: Secret, EntryIncarnationID: generatedRecordID(3), Epoch: 7, IntentDigest: x.IntentDigest, PlannedValueSlotID: x.PlannedValueSlotID, IntendedMembership: membership, LineageID: x.LineageID, ChangeMask: GeneratorValueChangeContent | GeneratorValueChangeMembership}
	lineage := GeneratorLineageTemplate{Schema: GeneratorLineageTemplateSchema, Purpose: GeneratorLineageCreate, DomainID: d.DomainID, OperationID: d.OperationID, Name: "local", EntryIncarnationID: plan.EntryIncarnationID, Epoch: 7, IntentDigest: x.IntentDigest, LineageID: x.LineageID, TemplateCount: 1, Templates: [5]GeneratorAttemptTemplate{x}}
	templateID, err := GeneratorTemplateID(x)
	if err != nil {
		t.Fatal(err)
	}
	join, err := GeneratorCompleteJoinID(requestID)
	if err != nil {
		t.Fatal(err)
	}
	edges := []GeneratorEdge{{Schema: 1, SourceTemplateID: templateID, DestinationTemplateID: join, Guard: GeneratorGuardQualifiedSuccess, ResultSlotID: x.ResultID, RequiredAuthoritySet: 1}, {Schema: 1, SourceTemplateID: templateID, DestinationTemplateID: join, Guard: GeneratorGuardTerminalParent, ResultSlotID: x.ResultID, RequiredAuthoritySet: 1}}
	graphID, err := GeneratorGraphID(header, []GeneratorValueEntryPlan{plan}, []GeneratorLineageTemplate{lineage}, edges)
	if err != nil {
		t.Fatal(err)
	}
	uses := []GeneratorResultUse{{Schema: 1, AttemptID: x.AttemptID, ResultID: x.ResultID, InboxID: x.InboxID, ExecutorID: x.ExecutorID, ResultContractID: x.ResultContractID, PlannedValueSlotID: x.PlannedValueSlotID, MaterialID: material, Purpose: GeneratorUseGeneratedResult, MaxSecret: CryptoMaxRawValue, MaxFacts: GeneratorSafeFactsMaxLength}}
	resultUses, err := GeneratorResultUsesDescriptor(uses)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := GeneratorSourceUsesDescriptor(nil)
	if err != nil {
		t.Fatal(err)
	}
	return d, GeneratorPlanBundle{Request: request, Header: header, ValueEntryPlans: []GeneratorValueEntryPlan{plan}, Lineages: []GeneratorLineageTemplate{lineage}, Edges: edges, ResultUses: uses, UsePlan: GeneratorUsePlanCore{DomainID: d.DomainID, OperationID: d.OperationID, MaterialID: material, PlanGraphID: graphID, ResultUses: resultUses, SourceUses: sources, ValueDerivationID: GeneratorValueDerivationID()}}
}

// full_only: false
func TestLocalGeneratorDeclarationAndSingleTemplateGraph(t *testing.T) {
	d, graph := localGraphFixture(t)
	body, err := EncodeGeneratorDeclaration(d)
	if err != nil {
		t.Fatal(err)
	}
	view, err := InspectGeneratorDeclaration(body)
	if err != nil || ValidateGeneratorDeclarationGraph(view, graph) != nil {
		t.Fatal("local declaration/graph join", err)
	}
	slices, err := view.Slices()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, slice := range slices {
		if slice.Logical.ContentKind == GeneratorContentIntent {
			found = true
			if !bytes.Equal(body[slice.Offset:slice.Offset+slice.Logical.Length], generatorIntentFixture(t, graph.Lineages[0].Templates[0].ConfigContractID, ID{}, GeneratorLifecycleNone, []byte("{}"))) {
				t.Fatal("local intent offset")
			}
		}
	}
	if !found {
		t.Fatal("local intent missing")
	}
	encoded, err := EncodeGeneratorPlanBundle(graph)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeGeneratorPlanBundle(encoded)
	if err != nil || decoded.Header.Schema != GeneratorGraphHeaderSchema || decoded.Lineages[0].TemplateCount != 1 {
		t.Fatal("new bundle round trip", err)
	}
	graph.UsePlan.ValueDerivationID = Hash([]byte("superseded derivation"))
	if _, err := EncodeGeneratorPlanBundle(graph); err == nil {
		t.Fatal("new graph admitted old derivation")
	}
}

// full_only: false
func TestLocalGeneratorEffectGraphHasNoRemoteCleanup(t *testing.T) {
	_, graph := localGraphFixture(t)
	if len(graph.Lineages) != 1 || graph.Lineages[0].Purpose != GeneratorLineageCreate || graph.Lineages[0].TemplateCount != 1 {
		t.Fatal("local fixture has a remote continuation")
	}
	if err := ValidateGeneratorEffectGraph(graph); err != nil {
		t.Fatal("local create required remote cleanup coverage", err)
	}
}

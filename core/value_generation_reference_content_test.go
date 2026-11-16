package core

import (
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedContentParentClaimsSelectedReference(t *testing.T) {
	id := generatedVectorID
	fixed := func(v contract.ID, err error) contract.ID {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	descriptor := func(v contract.GeneratorDescriptor, err error) contract.GeneratorDescriptor {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	body := func(v []byte, err error) []byte {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	intent := generatedFixtureCanonicalIntent(t, []byte(`{"selected":"carried intent"}`), defaultGeneratedFixtureProfile())
	logical := contract.GeneratorLogicalSlice{Schema: 1, ContentKind: contract.GeneratorContentIntent,
		ContentID: fixed(contract.GeneratorIntentDigest(intent)), Length: uint32(len(intent)), Digest: contract.Hash(intent)}
	bundle, declaration, parent := generatedContentPlanFixture(t)
	declaration.Entries[0].Kind = contract.GeneratorDeclarationGeneratedReference
	declaration.Entries[0].Payload = body(contract.EncodeGeneratorDeclaredGenerationReference(contract.GeneratorDeclaredGenerationReference{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratorDeclaredReferenceSchema,
		Epoch: 1, RetirementMode: contract.GeneratedRetirementManual, ConfigContractID: id(41), ResourceContractID: id(42),
		CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: logical}))
	m := &bundle.ValueEntryPlans[0]
	m.ValueSource, m.ConfidentialityClass, m.ChangeMask = contract.Generated, contract.Secret, 0
	m.Epoch, m.IntentDigest, m.LifecycleMode = 1, logical.ContentID, contract.GeneratorLifecycleManaged
	m.RetirementMode = contract.GeneratedRetirementManual
	m.SourceSlice = descriptor(contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{logical}))
	bundle.Request.Declaration = descriptor(contract.GeneratorDeclarationDescriptor(declaration))
	bundle.Header.RequestCoreDigest = fixed(contract.GeneratorRequestCoreDigest(bundle.Request))
	bundle.UsePlan.PlanGraphID = fixed(contract.GeneratorGraphID(bundle.Header, bundle.ValueEntryPlans, nil, nil))
	parent.RequestCoreDigest, parent.PlanGraphID = bundle.Header.RequestCoreDigest, bundle.UsePlan.PlanGraphID
	parent.UsePlanDigest = fixed(contract.GeneratorUsePlanDigest(bundle.UsePlan))
	parent.Declaration, parent.Graph = bundle.Request.Declaration, descriptor(contract.GeneratorPlanBundleDescriptor(bundle))
	parent.IntendedEntryPlans = descriptor(contract.GeneratorValueEntryPlansDescriptor(bundle.ValueEntryPlans))
	declarationBody := body(contract.EncodeGeneratorDeclaration(declaration))
	view, err := contract.InspectGeneratorDeclaration(declarationBody)
	if err != nil || contract.ValidateGeneratorDeclarationGraph(view, bundle) != nil {
		t.Fatal("valid reference fixture", err)
	}
	graphBody := body(contract.EncodeGeneratorPlanBundle(bundle))
	state := generatedContentState(t, []generatedContentFixtureBlob{{id(31), graphBody}, {id(32), declarationBody}, {id(33), intent}},
		[]contract.GeneratorSliceLocation{
			{Schema: 1, ContentKind: contract.GeneratorContentGraph, ContentID: parent.PlanGraphID, BlobID: id(31), Length: uint32(len(graphBody)), Digest: contract.Hash(graphBody)},
			{Schema: 1, ContentKind: contract.GeneratorContentDeclaration, ContentID: parent.OperationID, BlobID: id(32), Length: uint32(len(declarationBody)), Digest: contract.Hash(declarationBody)},
			{Schema: 1, ContentKind: logical.ContentKind, ContentID: logical.ContentID, BlobID: id(33), Length: logical.Length, Digest: logical.Digest},
		})
	content, err := newGeneratedContentValidation(t.Context(), state)
	if err != nil {
		t.Fatal("selected content", err)
	}
	if _, err := content.parent(parent); err != nil {
		t.Fatal("reference parent", err)
	}
	if !content.complete(contract.ID{}) {
		t.Fatal("accepted parent did not claim its selected referenced intent")
	}
}

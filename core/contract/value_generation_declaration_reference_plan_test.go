package contract

import (
	"bytes"
	"testing"
)

func declarationReferenceGraphFixture(t *testing.T) (GeneratorDeclaration, GeneratorPlanBundle) {
	t.Helper()
	declaration, bundle := declarationGraphFixture(t)
	declaration.Entries[1].Kind = GeneratorDeclarationGeneratedReference
	declaration.Entries[1].Payload = generatorDeclarationReferencePayload(t)
	bundle.Lineages = nil
	bundle.Header.LineageCount, bundle.Header.TemplateCount = 0, 0
	plan := &bundle.ValueEntryPlans[1]
	plan.Epoch = 7
	plan.ChangeMask = 0
	plan.LineageID, plan.PlannedValueSlotID = ID{}, ID{}
	plan.SourceSlice = GeneratorDescriptor{Digest: generatedCryptoHexID(t, "3183f634a9f1b713fa31b4afd17c922f6a88d29c943c2142765040a162d71465"), Length: 79, Count: 1}
	refreshDeclarationGraph(t, declaration, &bundle)
	return declaration, bundle
}

// full_only: false
func TestGeneratorDeclarationReferenceGraphCorrespondence(t *testing.T) {
	validate := func(declaration GeneratorDeclaration, bundle GeneratorPlanBundle) error {
		t.Helper()
		body, err := EncodeGeneratorDeclaration(declaration)
		if err != nil {
			t.Fatal(err)
		}
		view, err := InspectGeneratorDeclaration(body)
		if err != nil {
			t.Fatal(err)
		}
		return ValidateGeneratorDeclarationGraph(view, bundle)
	}
	for _, mask := range []uint8{0, GeneratorValueChangeMembership} {
		declaration, bundle := declarationReferenceGraphFixture(t)
		bundle.ValueEntryPlans[1].ChangeMask = mask
		refreshDeclarationGraph(t, declaration, &bundle)
		if err := validate(declaration, bundle); err != nil {
			t.Fatal("unchanged reference or access-only change refused", mask, err)
		}
	}
	declaration, bundle := declarationReferenceGraphFixture(t)
	reference, err := InspectGeneratorDeclaredGenerationReference(declaration.Entries[1].Payload)
	if err != nil {
		t.Fatal(err)
	}
	referenceDescriptor := bundle.Request.Declaration
	declaration.Entries[1].Kind = GeneratorDeclarationGenerated
	declaration.Entries[1].Payload, err = EncodeGeneratorDeclaredGeneration(GeneratorDeclaredGeneration{
		Schema:             GeneratorDeclaredGenerationSchema,
		LifecycleMode:      reference.LifecycleMode,
		Epoch:              reference.Epoch,
		RetirementMode:     reference.RetirementMode,
		ConfigContractID:   reference.ConfigContractID,
		ResourceContractID: reference.ResourceContractID,
		CompletionClass:    reference.CompletionClass,
		Intent:             generatorIntentFixture(t, reference.ConfigContractID, reference.ResourceContractID, reference.LifecycleMode, []byte("{}")),
	})
	if err != nil {
		t.Fatal(err)
	}
	refreshDeclarationGraph(t, declaration, &bundle)
	if err := validate(declaration, bundle); err != nil || bundle.Request.Declaration == referenceDescriptor {
		t.Fatal("equal embedded logical intent refused or transport identity unchanged", err)
	}
	for name, edit := range map[string]func(*GeneratorPlanBundle){
		"name":            func(v *GeneratorPlanBundle) { v.ValueEntryPlans[1].Name = "other" },
		"epoch":           func(v *GeneratorPlanBundle) { v.ValueEntryPlans[1].Epoch++ },
		"retirement":      func(v *GeneratorPlanBundle) { v.ValueEntryPlans[1].RetirementMode = GeneratedRetirementAuto },
		"intent identity": func(v *GeneratorPlanBundle) { v.ValueEntryPlans[1].IntentDigest = generatedRecordID(91) },
		"source digest":   func(v *GeneratorPlanBundle) { v.ValueEntryPlans[1].SourceSlice.Digest = generatedRecordID(91) },
		"source length":   func(v *GeneratorPlanBundle) { v.ValueEntryPlans[1].SourceSlice.Length++ },
		"source count":    func(v *GeneratorPlanBundle) { v.ValueEntryPlans[1].SourceSlice.Count++ },
		"membership":      func(v *GeneratorPlanBundle) { v.ValueEntryPlans[1].IntendedMembership.Digest = generatedRecordID(91) },
	} {
		t.Run(name, func(t *testing.T) {
			declaration, bundle := declarationReferenceGraphFixture(t)
			edit(&bundle)
			refreshDeclarationGraph(t, declaration, &bundle)
			if err := validate(declaration, bundle); err == nil {
				t.Fatal("independently valid unequal reference plan admitted")
			}
		})
	}
	for name, edit := range map[string]func(*GeneratorDeclaration){
		"domain":    func(v *GeneratorDeclaration) { v.DomainID = generatedRecordID(91) },
		"operation": func(v *GeneratorDeclaration) { v.OperationID = generatedRecordID(91) },
		"recipient": func(v *GeneratorDeclaration) { v.Entries[1].Recipients = []ID{generatedRecordID(91)} },
	} {
		t.Run(name, func(t *testing.T) {
			declaration, bundle := declarationReferenceGraphFixture(t)
			edit(&declaration)
			refreshDeclarationGraph(t, declaration, &bundle)
			if err := validate(declaration, bundle); err == nil {
				t.Fatal("unequal declaration identity or recipients admitted")
			}
		})
	}
	for _, damage := range []string{"missing", "extra", "duplicate"} {
		t.Run(damage, func(t *testing.T) {
			declaration, bundle := declarationReferenceGraphFixture(t)
			switch damage {
			case "missing":
				bundle.ValueEntryPlans = bundle.ValueEntryPlans[:1]
			case "extra":
				bundle.ValueEntryPlans = append(bundle.ValueEntryPlans, bundle.ValueEntryPlans[1])
			case "duplicate":
				bundle.ValueEntryPlans[1] = bundle.ValueEntryPlans[0]
			}
			if err := validate(declaration, bundle); err == nil {
				t.Fatal("incomplete or duplicate graph collection admitted")
			}
		})
	}
	declaration, bundle = declarationGraphFixture(t)
	g, err := InspectGeneratorDeclaredGeneration(declaration.Entries[1].Payload)
	if err != nil {
		t.Fatal(err)
	}
	reference, err = InspectGeneratorDeclaredGenerationReference(generatorDeclarationReferencePayload(t))
	if err != nil {
		t.Fatal(err)
	}
	reference.Epoch, reference.ResourceContractID = g.Epoch, g.ResourceContractID
	declaration.Entries[1].Kind = GeneratorDeclarationGeneratedReference
	declaration.Entries[1].Payload, err = EncodeGeneratorDeclaredGenerationReference(reference)
	if err != nil {
		t.Fatal(err)
	}
	refreshDeclarationGraph(t, declaration, &bundle)
	if err := validate(declaration, bundle); err == nil {
		t.Fatal("reference with a valid content-changing graph admitted")
	}
}

// full_only: false
func TestGeneratorDeclarationMixedReferencesAndEmbeddedSlices(t *testing.T) {
	v := generatorDeclarationFixture(t)
	reference := GeneratorDeclarationEntry{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Schema: GeneratorDeclarationEntrySchema, Kind: GeneratorDeclarationGeneratedReference, Name: "token-2", Recipients: []ID{generatedRecordID(3)}, Payload: generatorDeclarationReferencePayload(t)}
	v.Entries = append(v.Entries, reference)
	reference.Name = "token-3"
	v.Entries = append(v.Entries, reference)
	body, err := EncodeGeneratorDeclaration(v)
	if err != nil {
		t.Fatal(err)
	}
	view, err := InspectGeneratorDeclaration(body)
	if err != nil {
		t.Fatal(err)
	}
	physical, err := view.Slices()
	if err != nil || len(physical) != 3 {
		t.Fatal("only declaration, plain entry and embedded intent have offsets", physical, err)
	}
	logical, err := view.LogicalSlices()
	if err != nil || len(logical) != 3 {
		t.Fatal("equal full and reference logical descriptions did not share content", logical, err)
	}
	for i, row := range physical {
		if logical[i] != row.Logical || Hash(body[row.Offset:uint64(row.Offset)+uint64(row.Logical.Length)]) != row.Logical.Digest {
			t.Fatal("embedded logical mapping differs", i)
		}
	}
	owned, err := view.Own()
	if err != nil {
		t.Fatal(err)
	}
	again, err := EncodeGeneratorDeclaration(owned)
	if err != nil || !bytes.Equal(again, body) {
		t.Fatal("mixed collection round trip", err)
	}
	for _, damage := range []string{"length", "digest"} {
		t.Run(damage, func(t *testing.T) {
			ref, err := InspectGeneratorDeclaredGenerationReference(generatorDeclarationReferencePayload(t))
			if err != nil {
				t.Fatal(err)
			}
			if damage == "length" {
				ref.Intent.Length++
			} else {
				ref.Intent.Digest = generatedRecordID(91)
			}
			bad := owned
			bad.Entries = append([]GeneratorDeclarationEntry(nil), owned.Entries...)
			bad.Entries[2].Payload, err = EncodeGeneratorDeclaredGenerationReference(ref)
			if err != nil {
				t.Fatal(err)
			}
			body, err := EncodeGeneratorDeclaration(bad)
			if err != nil {
				t.Fatal(err)
			}
			view, err := InspectGeneratorDeclaration(body)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := view.LogicalSlices(); err != ErrRecord {
				t.Fatal("conflicting logical content admitted", err)
			}
		})
	}
}

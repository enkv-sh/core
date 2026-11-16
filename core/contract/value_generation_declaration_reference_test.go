package contract

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
)

func generatorDeclarationReferencePayload(t testing.TB) []byte {
	t.Helper()
	// Python struct/hashlib, independently concatenated: schema4, epoch7,
	// manual1, configR6/resourceR9, managed2/class1, then logical schema1,
	// kind1, D("intent-v3", complete canonical intent), length73 and SHA256.
	body, err := hex.DecodeString("0004000000000000000701060606060606060606060606060606060606060606060606060606060606060609090909090909090909090909090909090909090909090909090909090909090201000101baed83394dc997bf5b1e252e7c1e8efca8750b80304d2f304e60a209548a0810000000497b408d3a313809d0a9ae73a583b45a83b27331ed281caa0403da06dbf97774a5")
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// full_only: false
func TestGeneratorDeclarationReferenceIndependentWire(t *testing.T) {
	id := generatedRecordID
	payload := generatorDeclarationReferencePayload(t)
	reference, err := InspectGeneratorDeclaredGenerationReference(payload)
	if err != nil || reference.Intent.Length != 73 || reference.Intent.ContentID != generatedCryptoHexID(t, "baed83394dc997bf5b1e252e7c1e8efca8750b80304d2f304e60a209548a0810") ||
		reference.Intent.Digest != generatedCryptoHexID(t, "7b408d3a313809d0a9ae73a583b45a83b27331ed281caa0403da06dbf97774a5") {
		t.Fatal("independent reference payload", reference, err)
	}
	encoded, err := EncodeGeneratorDeclaredGenerationReference(reference)
	if err != nil || !bytes.Equal(encoded, payload) || len(encoded) != GeneratorDeclaredGenerationReferenceLength {
		t.Fatal("reference payload encoding differs", err)
	}
	v := GeneratorDeclaration{Schema: 1, DomainID: id(1), OperationID: id(2), Entries: []GeneratorDeclarationEntry{
		{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Schema: GeneratorDeclarationEntrySchema, Kind: 5, Name: "token", Recipients: []ID{id(3)}, Payload: payload},
	}}
	body, err := EncodeGeneratorDeclaration(v)
	if err != nil {
		t.Fatal("valid unchanged generated reference refused", err)
	}
	// Independent declaration: header70 + B4 + entry15 + name5 + recipient32
	// + header77 + logical71 =274; descriptor includes another8 bytes.
	if len(payload) != 148 || len(body) != 274 || Hash(body) != generatedCryptoHexID(t, "9e84eed6a743d13e618c41ac0342dcbd2202e0e8a6b1ad9860262b84b1f798d4") {
		t.Fatal("reference declaration bytes differ", len(payload), len(body))
	}
	d, err := GeneratorDeclarationDescriptor(v)
	if err != nil || d.Length != 282 || d.Count != 1 || d.Digest != generatedCryptoHexID(t, "783ea61b04b8a29cbae3e885259996fa79cdc46fedd2b53575199863a447d44b") {
		t.Fatal("reference declaration commitment differs", d, err)
	}
	view, err := InspectGeneratorDeclaration(body)
	if err != nil {
		t.Fatal(err)
	}
	entry, _, err := view.Entry(0)
	if err != nil || entry.ValueSource() != Generated || entry.ConfidentialityClass() != Secret {
		t.Fatal("reference source and confidentiality", err)
	}
	physical, err := view.Slices()
	if err != nil || len(physical) != 1 || physical[0].Logical.ContentKind != GeneratorContentDeclaration {
		t.Fatal("reference acquired a fabricated declaration offset", physical, err)
	}
	logical, err := view.LogicalSlices()
	if err != nil || len(logical) != 2 || logical[0] != reference.Intent || logical[1] != physical[0].Logical {
		t.Fatal("complete logical reference mapping", logical, err)
	}
	intentDescriptor, err := GeneratorLogicalSlicesDescriptor(logical[:1])
	if err != nil || intentDescriptor.Length != 79 || intentDescriptor.Count != 1 || intentDescriptor.Digest != generatedCryptoHexID(t, "3183f634a9f1b713fa31b4afd17c922f6a88d29c943c2142765040a162d71465") {
		t.Fatal("independent referenced intent commitment differs", intentDescriptor, err)
	}
	owned, err := view.Own()
	if err != nil {
		t.Fatal(err)
	}
	clear(body)
	again, err := EncodeGeneratorDeclaration(owned)
	if err != nil || Hash(again) != generatedCryptoHexID(t, "9e84eed6a743d13e618c41ac0342dcbd2202e0e8a6b1ad9860262b84b1f798d4") {
		t.Fatal("owned reference retained borrowed bytes", err)
	}
}

// full_only: false
func TestGeneratorDeclarationReferenceClosedFields(t *testing.T) {
	body := generatorDeclarationReferencePayload(t)
	v, err := InspectGeneratorDeclaredGenerationReference(body)
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*GeneratorDeclaredGenerationReference){
		"retirement":      func(v *GeneratorDeclaredGenerationReference) { v.RetirementMode = 0 },
		"lifecycle":       func(v *GeneratorDeclaredGenerationReference) { v.LifecycleMode = 0 },
		"assumption":      func(v *GeneratorDeclaredGenerationReference) { v.ConfigContractID = ID{} },
		"account":         func(v *GeneratorDeclaredGenerationReference) { v.ResourceContractID = ID{} },
		"completion":      func(v *GeneratorDeclaredGenerationReference) { v.CompletionClass = 0 },
		"logical schema":  func(v *GeneratorDeclaredGenerationReference) { v.Intent.Schema++ },
		"logical kind":    func(v *GeneratorDeclaredGenerationReference) { v.Intent.ContentKind = GeneratorContentSource },
		"intent identity": func(v *GeneratorDeclaredGenerationReference) { v.Intent.ContentID = ID{} },
		"length":          func(v *GeneratorDeclaredGenerationReference) { v.Intent.Length = 0 },
		"digest":          func(v *GeneratorDeclaredGenerationReference) { v.Intent.Digest = ID{} },
	} {
		t.Run(name, func(t *testing.T) {
			bad := v
			edit(&bad)
			if _, err := EncodeGeneratorDeclaredGenerationReference(bad); err != ErrRecord {
				t.Fatal("invalid reference admitted", err)
			}
		})
	}
	for n := range body {
		if _, err := InspectGeneratorDeclaredGenerationReference(body[:n]); err == nil {
			t.Fatal("reference truncation admitted", n)
		}
	}
	if _, err := InspectGeneratorDeclaredGenerationReference(append(bytes.Clone(body), 0)); err != ErrRecordCapacity {
		t.Fatal("reference suffix admitted", err)
	}
	for _, damage := range []struct{ start, end int }{{0, 2}, {10, 11}, {11, 43}, {43, 75}, {75, 76}, {76, 77}, {77, 79}, {79, 80}, {80, 112}, {112, 116}, {116, 148}} {
		bad := bytes.Clone(body)
		clear(bad[damage.start:damage.end])
		if _, err := InspectGeneratorDeclaredGenerationReference(bad); err == nil {
			t.Fatal("malformed reference wire field admitted", damage)
		}
	}
	v.Intent.Length = 393216
	if _, err := EncodeGeneratorDeclaredGenerationReference(v); err != nil {
		t.Fatal("maximum logical intent length refused", err)
	}
	v.Intent.Length++
	if _, err := EncodeGeneratorDeclaredGenerationReference(v); err != ErrRecordCapacity {
		t.Fatal("oversized logical intent length admitted", err)
	}
	bad := bytes.Clone(body)
	binary.BigEndian.PutUint32(bad[112:116], 393217)
	if _, err := InspectGeneratorDeclaredGenerationReference(bad); err != ErrRecordCapacity {
		t.Fatal("oversized logical intent wire length admitted", err)
	}
}

// full_only: false
func TestGeneratorDeclarationReferenceCountsAndCollectionFraming(t *testing.T) {
	id := generatedRecordID
	entry := GeneratorDeclarationEntry{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Schema: GeneratorDeclarationEntrySchema, Kind: GeneratorDeclarationGeneratedReference, Recipients: []ID{id(3)}, Payload: generatorDeclarationReferencePayload(t)}
	v := GeneratorDeclaration{Schema: 1, DomainID: id(1), OperationID: id(2), Entries: []GeneratorDeclarationEntry{entry}}
	body, err := EncodeGeneratorDeclaration(v)
	if err != nil {
		t.Fatal("empty reference name refused", err)
	}
	for n := range body {
		if _, err := InspectGeneratorDeclaration(body[:n]); err == nil {
			t.Fatal("reference declaration truncation admitted", n)
		}
	}
	for _, offset := range []int{1, 66, 70, 75, 76} {
		bad := bytes.Clone(body)
		bad[offset] ^= 0x80
		if _, err := InspectGeneratorDeclaration(bad); err == nil {
			t.Fatal("changed reference declaration framing admitted", offset)
		}
	}
	if _, err := InspectGeneratorDeclaration(append(bytes.Clone(body), 0)); err == nil {
		t.Fatal("reference declaration suffix admitted")
	}
	v.Entries = make([]GeneratorDeclarationEntry, 128)
	for i := range v.Entries {
		v.Entries[i] = entry
		v.Entries[i].Name = fmt.Sprintf("%03d", i)
	}
	body, err = EncodeGeneratorDeclaration(v)
	if err != nil {
		t.Fatal("128 referenced generated entries refused", err)
	}
	if view, err := InspectGeneratorDeclaration(body); err != nil || view.EntryCount() != 128 {
		t.Fatal("128 referenced entries cannot be inspected", err)
	}
	full := generatorDeclarationFixture(t).Entries[1]
	full.Name = "128"
	v.Entries = append(v.Entries, full)
	if _, err := EncodeGeneratorDeclaration(v); err != ErrRecordCapacity {
		t.Fatal("mixed full and reference count exceeded 128", err)
	}
}

// full_only: true
// Proves the aggregate declaration refusal for 128 distinct maximum intents.
func TestGeneratorDeclarationMaximumIntentsExceedEncodedLimit(t *testing.T) {
	id := generatedRecordID
	v := GeneratorDeclaration{Schema: 1, DomainID: id(1), OperationID: id(2), Entries: make([]GeneratorDeclarationEntry, 128)}
	seen := make(map[ID]bool, len(v.Entries))
	for i := range v.Entries {
		intent := generatorIntentLengthFixture(t, id(byte(i+1)), id(5), GeneratorLifecycleManaged, GeneratorIntentMaxLength)
		digest, err := GeneratorIntentDigest(intent)
		if err != nil || seen[digest] {
			t.Fatal("intent is not independently valid and distinct", i, err)
		}
		seen[digest] = true
		payload, err := EncodeGeneratorDeclaredGeneration(GeneratorDeclaredGeneration{
			Schema:             GeneratorDeclaredGenerationSchema,
			LifecycleMode:      GeneratorLifecycleManaged,
			Epoch:              uint64(i),
			RetirementMode:     1,
			ConfigContractID:   id(byte(i + 1)),
			ResourceContractID: id(5),
			CompletionClass:    1,
			Intent:             intent,
		})
		if err != nil {
			t.Fatal("individual maximum intent refused", i, err)
		}
		v.Entries[i] = GeneratorDeclarationEntry{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Schema: GeneratorDeclarationEntrySchema, Kind: GeneratorDeclarationGenerated, Name: fmt.Sprintf("%03d", i), Recipients: []ID{id(6)}, Payload: payload}
		body, err := EncodeGeneratorDeclarationEntry(v.Entries[i])
		if err != nil || len(body) != 393347 {
			t.Fatal("individual maximum entry refused", i, len(body), err)
		}
		if _, err := InspectGeneratorDeclarationEntry(body); err != nil {
			t.Fatal("individual maximum entry cannot be read", i, err)
		}
	}
	// Independently: framing8 + header70 + 128*(B4 + entry15 + name3 +
	// recipient32 + metadata77 + B4 + intent393216) = 50,349,006 bytes.
	const framed = 8 + 70 + 128*(4+15+3+32+77+4+393216)
	if framed != 50349006 || framed <= GeneratorDeclarationMaxFramedLength {
		t.Fatal("aggregate bound derivation differs", framed)
	}
	if _, err := EncodeGeneratorDeclaration(v); err != ErrRecordCapacity {
		t.Fatal("aggregate encoder did not retain the declaration barrier", err)
	}
}

package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// The resource hash fixture independently frames the fixed target and the
// selected opaque resource bytes. It does not encode or inspect a Product row.
func generatedFixtureResourceDigest(resourceContract, data contract.ID) contract.ID {
	blob := func(dst, value []byte) []byte {
		dst = binary.BigEndian.AppendUint32(dst, uint32(len(value)))
		return append(dst, value...)
	}
	resource := append([]byte(nil), resourceContract[:]...)
	resource = blob(resource, []byte("fixture-target"))
	resource = blob(resource, data[:])
	return sha256.Sum256(blob([]byte("ENKV/GENERATOR/v1/resource-v1\x00"), resource))
}

// full_only: false
func TestGeneratedFixtureFrames128CurrentIntentReferences(t *testing.T) {
	for _, mode := range []contract.GeneratorLifecycleMode{contract.GeneratorLifecycleManaged, contract.GeneratorLifecycleNone} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			profile := defaultGeneratedFixtureProfile()
			profile.LifecycleMode = mode
			completion := uint8(contract.GeneratedCompletionAcknowledged)
			retirement := uint8(contract.GeneratedRetirementManual)
			if mode == contract.GeneratorLifecycleNone {
				profile.ResourceContractID = contract.ID{}
				completion, retirement = 0, 0
			}
			sources := make([]contract.GeneratorDeclarationEntry, 128)
			incarnations := make(map[string]contract.ID, 128)
			references := make([]contract.GeneratorDeclaredGenerationReference, 128)
			for i := range sources {
				name := fmt.Sprintf("current-%03d", i)
				references[i] = contract.GeneratorDeclaredGenerationReference{Schema: contract.GeneratorDeclaredReferenceSchema, LifecycleMode: mode, Epoch: 1, RetirementMode: retirement,
					ConfigContractID: profile.ConfigContractID, ResourceContractID: profile.ResourceContractID, CompletionClass: completion,
					Intent: contract.GeneratorLogicalSlice{Schema: 1, ContentKind: contract.GeneratorContentIntent, ContentID: contract.Hash([]byte("intent " + name)), Length: 393216, Digest: contract.Hash([]byte("content " + name))}}
				payload, err := contract.EncodeGeneratorDeclaredGenerationReference(references[i])
				if err != nil {
					t.Fatal("reference input", err)
				}
				sources[i] = contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationGeneratedReference, Name: name, Recipients: []contract.ID{generatedVectorID(11)}, Payload: payload}
				incarnations[name] = contract.Hash([]byte("incarnation " + name))
			}
			before := slices.Clone(sources)
			for i := range before {
				before[i].Payload = bytes.Clone(before[i].Payload)
				before[i].Recipients = slices.Clone(before[i].Recipients)
			}
			graph, declaration, _ := generatedEffectPlanForGenerationMembershipStateWithIntents(t, nil, generatedVectorID(11), []contract.ID{generatedVectorID(11)}, nil,
				func(string) []byte { t.Fatal("reference construction entered an author"); return nil }, profile, 0, incarnations, nil, sources...)
			encoded, err := contract.EncodeGeneratorDeclaration(declaration)
			if err != nil {
				t.Fatal("128 reference declaration", err)
			}
			// Header70; each row4+2+1+1+1+(4+11)+(2+32)+4+148=210 bytes.
			if len(encoded) != 26950 || graph.Header.Schema != contract.GeneratorGraphHeaderSchema || graph.Header.ValueEntryPlanCount != 128 || graph.Header.LineageCount != 0 || graph.Header.TemplateCount != 0 || len(graph.ValueEntryPlans) != 128 || len(graph.Lineages) != 0 {
				t.Fatal("reference count or independently derived framing differs", len(encoded), graph.Header)
			}
			view, err := contract.InspectGeneratorDeclaration(encoded)
			if err != nil || view.EntryCount() != 128 {
				t.Fatal("128 reference decode", err)
			}
			recipient := generatedVectorID(11)
			for i := 0; i < view.EntryCount(); i++ {
				entry, _, err := view.Entry(i)
				if err != nil {
					t.Fatal("decoded row", i, err)
				}
				name := fmt.Sprintf("current-%03d", i)
				if entry.Schema != contract.GeneratorDeclarationEntrySchema || string(entry.Name) != name || entry.Kind != contract.GeneratorDeclarationGeneratedReference || !bytes.Equal(entry.RecipientIDs, recipient[:]) || graph.ValueEntryPlans[i].Schema != contract.GeneratorValueEntryPlanSchema || graph.ValueEntryPlans[i].Name != name {
					t.Fatal("reference row changed", i)
				}
				reference, err := contract.InspectGeneratorDeclaredGenerationReferenceForEntry(entry.Schema, entry.Payload)
				if err != nil || reference != references[i] {
					t.Fatal("complete original semantics changed", i, err)
				}
			}
			if !reflect.DeepEqual(sources, before) {
				t.Fatal("fixture changed caller-owned source rows")
			}
			extra := declaration
			extra.Entries = append(slices.Clone(declaration.Entries), declaration.Entries[127])
			extra.Entries[128].Name = "current-128"
			if _, err := contract.EncodeGeneratorDeclaration(extra); err != contract.ErrRecordCapacity {
				t.Fatal("129 reference rows bypassed count bound", err)
			}
		})
	}
}

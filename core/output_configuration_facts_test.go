package core

import (
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestSelectedOutputFactsByRecordPreservesBindings(t *testing.T) {
	before := generatedEmptyPredecessor(t)
	selected := *before
	if err := before.bindPreservedOutputConfiguration(&selected); err != nil {
		t.Fatal(err)
	}
	configurationDigest := selectedConversionLiteralID(t, "b6ebf3ec634bccca8adc79b2475c1b952e135676f84ebd8828eae1d7a6394a16")
	recordID := selectedConversionLiteralID(t, "5abe180a7fe425259d49d3c8cfaedda15f0e5f47ee64457c4ce75c6ab29fd3bb")
	if before.root.OutputConfiguration.ConfigurationDigest != configurationDigest || before.support[0].Records[0].RecordID != recordID {
		t.Fatal("empty configuration differs from independent metadata")
	}
	rowDigest, err := contract.InspectSupportRecordDigest(before.root.Domain, contract.SupportRecord(before.support[0].Records[0]))
	if err != nil {
		t.Fatal(err)
	}
	wantFact := selectedFragmentFact{ref: before.root.RequiredSupport[0], row: rowDigest, physical: 0, logical: 0, blob: configurationDigest}
	_, _, _, fillerRows := publicationRelationFixtureForDomain(t, before.root.Domain)
	filler := fillerRows[1]
	fillerDigest, err := contract.InspectSupportRecordDigest(before.root.Domain, filler)
	if err != nil {
		t.Fatal(err)
	}
	for _, condition := range []string{"complete", "body-backed without root proof", "bodyless", "nil receiver", "zero receiver",
		"absent descriptor", "nil facts with exact proof", "empty facts with exact proof", "wrong ref", "extra facts page", "missing support page",
		"missing ordinal", "extra ordinal", "duplicate identity", "logical index 255", "logical index 256", "incomplete proof", "wrong root proof",
		"sparse physical ordinal"} {
		t.Run(condition, func(t *testing.T) {
			state := selected
			state.supportFacts = slices.Clone(selected.supportFacts)
			state.supportFacts[0].rows = slices.Clone(selected.supportFacts[0].rows)
			state.supportFacts[0].ordinals = slices.Clone(selected.supportFacts[0].ordinals)
			receiver := &state
			want := map[contract.ID]selectedFragmentFact{recordID: wantFact}
			wantError, wantNil := false, false
			switch condition {
			case "body-backed without root proof":
				state.outputConfigurationRoot = contract.ID{}
			case "bodyless":
				state.support = selectedConversionBodylessSupport(state.support)
			case "nil receiver":
				receiver, want, wantError, wantNil = nil, nil, true, true
			case "zero receiver":
				receiver, want, wantError, wantNil = &StateSession{}, nil, true, true
			case "absent descriptor":
				state.root.OutputConfiguration = contract.OutputConfigurationDescriptor{}
				wantError = true
			case "nil facts with exact proof":
				state.supportFacts, want = nil, map[contract.ID]selectedFragmentFact{}
			case "empty facts with exact proof":
				state.supportFacts, want = []selectedSupportPageFacts{}, map[contract.ID]selectedFragmentFact{}
			case "wrong ref":
				state.supportFacts[0].ref.Digest[0] ^= 1
				wantError = true
			case "extra facts page":
				state.supportFacts = append(state.supportFacts, selectedSupportPageFacts{})
				wantError = true
			case "missing support page":
				state.support = nil
				wantError = true
			case "missing ordinal":
				state.supportFacts[0].ordinals = nil
				wantError = true
			case "extra ordinal":
				state.supportFacts[0].ordinals = []uint16{0, 1}
				wantError = true
			case "duplicate identity":
				state.supportFacts[0].rows = append(state.supportFacts[0].rows, rowDigest)
				state.supportFacts[0].ordinals = append(state.supportFacts[0].ordinals, 1)
				wantError = true
			case "logical index 255", "logical index 256":
				logical := 255
				if condition == "logical index 256" {
					logical, wantError = 256, true
				}
				page := &state.supportFacts[0]
				page.rows = make([]contract.SupportRecordDigest, logical+1)
				page.ordinals = make([]uint16, logical+1)
				for i := range page.rows {
					page.rows[i], page.ordinals[i] = fillerDigest, uint16(i)
				}
				page.rows[logical] = rowDigest
				fact := wantFact
				fact.logical, fact.physical = uint8(logical), uint16(logical)
				want[recordID] = fact
			case "incomplete proof", "wrong root proof":
				state.support = selectedConversionBodylessSupport(state.support)
				state.outputConfigurationRoot = contract.ID{}
				if condition == "wrong root proof" {
					state.outputConfigurationRoot = generatedVectorID(99)
				}
				wantError = true
			case "sparse physical ordinal":
				body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: state.root.Domain, Object: generatedVectorID(7), Index: 7,
					Records: []contract.SupportRecord{filler, contract.SupportRecord(before.support[0].Records[0])}})
				if err != nil {
					t.Fatal(err)
				}
				ref, err := format.Reference(contract.RequiredSupportKind, state.root.Domain, generatedVectorID(7), 7, body)
				if err != nil {
					t.Fatal(err)
				}
				state.root.RequiredSupport = []format.Ref{ref}
				state.support = selectedConversionBodylessSupport(state.support)
				state.support[0].Object, state.support[0].Index = ref.Object, 7
				state.supportFacts[0].ref, state.supportFacts[0].ordinals[0] = ref, 1
				state.recountChildren()
				root, err := format.EncodeRoot(state.root)
				if err != nil {
					t.Fatal(err)
				}
				state.outputConfigurationRoot = contract.Hash(root)
				fact := wantFact
				fact.ref, fact.physical, fact.logical = ref, 1, 0
				want[recordID] = fact
			}
			if wantError {
				want, wantNil = nil, true
			}
			for _, entry := range []string{"session", "selected image"} {
				t.Run(entry, func(t *testing.T) {
					convert := receiver.selectedOutputFactsByRecord
					snapshot := func() selectedConversionInputSnapshot { return selectedConversionSnapshot(receiver) }
					if entry == "selected image" {
						var image *selectedImage
						if receiver != nil {
							image = &selectedImage{root: receiver.root, support: receiver.support, supportFacts: receiver.supportFacts,
								outputConfigurationRoot: receiver.outputConfigurationRoot}
						}
						convert = image.selectedOutputFactsByRecord
						snapshot = func() selectedConversionInputSnapshot { return selectedConversionImageSnapshot(image) }
					}
					input := snapshot()
					got, err := convert()
					selectedConversionAssertResult(t, got, err, want, wantError, wantNil)
					if !reflect.DeepEqual(snapshot(), input) {
						t.Fatal("conversion changed its input facts")
					}
					if !wantError {
						selectedConversionDamageResult(got)
						again, err := convert()
						selectedConversionAssertResult(t, again, err, want, false, false)
						if !reflect.DeepEqual(snapshot(), input) {
							t.Fatal("result-map mutation changed input facts")
						}
					}
				})
			}
		})
	}
}

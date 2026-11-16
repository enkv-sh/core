package core

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func generatedSealedSource(t testing.TB, name string) contract.GeneratorDeclarationEntry {
	t.Helper()
	id := generatedVectorID
	source := contract.SealedInputEnvelope{Core: contract.SealedInputCore{SealedInputCoreFields: contract.SealedInputCoreFields{Schema: contract.SealedInputSchema, Profile: 2,
		CompatibilityID: contract.CompatibilityID(), DomainID: id(1), FileIdentity: id(72), SourceID: contract.Hash([]byte("fixture source " + name)),
		CryptoSupportID: contract.CryptoSupportID(), DataKeyID: id(75), DataKeyEpoch: 1, ContentLength: 4, InputEncoding: contract.InputEncodingRaw, RetainedLength: 4}, Name: name},
		Ciphertext: bytes.Repeat([]byte{76}, 20), AuthorityWrap: contract.WrapRow{SubjectKind: 1, SubjectID: id(11), BindingID: id(77),
			BindingSerial: 1, PublicBindingDigest: id(78), RSACiphertext: bytes.Repeat([]byte{79}, 384)}}
	body, err := contract.EncodeSealedInputEnvelope(source)
	if err != nil {
		t.Fatal(err)
	}
	return contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationSealed, Name: name, Recipients: []contract.ID{id(11)}, Payload: body}
}

// full_only: false
func TestGeneratedReservationRetainsOriginalSealedSources(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for _, entries := range [][]contract.GeneratorDeclarationEntry{{generatedSealedSource(t, "alpha")},
			{generatedSealedSource(t, "alpha"), generatedSealedSource(t, "omega")}} {
			s := generatedReservationState(t, entries...)
			if recovery {
				binding := generatedPublicBinding(t, 82)
				binding.Provider, binding.ProtectionClass = contract.AWS, contract.HardwareProtection
				binding.KeySelector = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000082"
				binding, signing := generatedFixtureIndependentRecovery(t, s, binding, "sealed source fixture recovery signing binding/v1")
				digest, err := contract.PublicBindingDigest(binding)
				if err != nil {
					t.Fatal(err)
				}
				s.root.CurrentAccess.Core.Recovery = &contract.RecoveryBindings{RoleID: generatedVectorID(83), Signing: signing, KMS: binding}
				s.access[0].Records[0].Wraps = append(s.access[0].Records[0].Wraps, contract.WrapRow{SubjectKind: 2, SubjectID: generatedVectorID(83),
					BindingID: binding.BindingID, BindingSerial: binding.BindingSerial, PublicBindingDigest: digest, RSACiphertext: bytes.Repeat([]byte{84}, 384)})
			}
			generatedSealSelectedFixture(t, s)
			selected, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal("valid accepted source reservation refused", err)
			}
			material := materialIdentity{3, selected.parent.MaterialID}
			if len(selected.materials) != 1 || len(selected.consumers[material]) != 2+len(entries) {
				t.Fatal("source consumer or shared seed missing")
			}
			for _, entry := range entries {
				source, err := contract.InspectSealedInputEnvelope(entry.Payload)
				if err != nil {
					t.Fatal(err)
				}
				body, err := selected.readSelectedSlice(t.Context(), contract.GeneratorContentSource, source.Core.SourceID, contract.GeneratorDeclarationEntryMaxLength)
				if err != nil || !bytes.Equal(body, entry.Payload) {
					t.Fatal("original source envelope changed", err)
				}
			}
			// A selected source keeps its original wrapping claim as public history.
			// Continued use needs the selected seed's current route, not that claim.
			binding := generatedPublicBinding(t, 81)
			s.recipients[0].Slots[0].CurrentBinding = &binding
			wrap := &s.access[0].Records[0].Wraps[0]
			wrap.BindingID, wrap.BindingSerial = binding.BindingID, binding.BindingSerial
			wrap.PublicBindingDigest, err = contract.PublicBindingDigest(binding)
			if err != nil {
				t.Fatal(err)
			}
			generatedSealSelectedFixture(t, s)
			if _, err := s.selectedGeneratedWork(context.Background()); err != nil {
				t.Fatal("current seed binding requires the old source route", err)
			}
		}
	}
}

// Rebind the actual stored fragment and its complete location vector so that
// negative cases reach the source-owner checks, not a stale outer hash.
func generatedReplaceConfiguration(t testing.TB, s *StateSession, id contract.ID, body []byte) {
	t.Helper()
	var locations [][]byte
	carrierPage := -1
	found := false
	for i, page := range s.support {
		for j, row := range page.Records {
			if row.Kind == 3 {
				fragment, err := contract.InspectGeneratedFragment(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				if fragment.BlobID != id {
					continue
				}
				if fragment.Count != 1 || found {
					t.Fatal("configuration fixture is not one fragment")
				}
				fragment.Payload, fragment.TotalLength, fragment.WholeDigest = body, uint64(len(body)), contract.Hash(body)
				s.support[i].Records[j].Body, err = contract.EncodeGeneratedFragment(contract.GeneratedFragment(fragment))
				if err != nil {
					t.Fatal(err)
				}
				found = true
			}
			if row.Kind != contract.GeneratorVectorSupportKind {
				continue
			}
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			if carrier.VectorKind != contract.GeneratorVectorSlices {
				continue
			}
			if carrierPage != -1 && carrierPage != i {
				t.Fatal("configuration fixture location vector is not one page")
			}
			carrierPage = i
			if locations == nil {
				locations = make([][]byte, carrier.Vector.Count)
			}
			location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
			if err != nil {
				t.Fatal(err)
			}
			if location.ContentKind == contract.GeneratorContentConfiguration && location.ContentID == id {
				location.Length, location.Digest = uint32(len(body)), contract.Hash(body)
			}
			locations[carrier.Ordinal], err = contract.EncodeGeneratorSliceLocation(location)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if !found || carrierPage < 0 {
		t.Fatal("configuration fixture missing")
	}
	descriptor, rows := generatedVectorRows(t, contract.GeneratorSnapshotOwner, s.root.Snapshot, contract.GeneratorVectorSlices, locations)
	s.root.Generated.Slices = descriptor
	s.support[carrierPage].Records = nil
	for _, row := range rows {
		s.support[carrierPage].Records = append(s.support[carrierPage].Records, contract.SupportRecordView(row))
	}
	generatedRefreshSupport(t, s)
}

// full_only: false
func TestGeneratedSourceProtectionRejectsRepinnedWrongOriginalAndMaterial(t *testing.T) {
	id := generatedVectorID
	for name, change := range map[string]func(*contract.OperationMaterialRecord, *[]contract.CryptoGeneratedSourceProtection){
		"missing source": func(_ *contract.OperationMaterialRecord, rows *[]contract.CryptoGeneratedSourceProtection) {
			*rows = nil
		},
		"other source": func(_ *contract.OperationMaterialRecord, rows *[]contract.CryptoGeneratedSourceProtection) {
			(*rows)[0].SourceID, (*rows)[0].Transfer.Core.SourceID = id(90), id(90)
		},
		"other original core": func(_ *contract.OperationMaterialRecord, rows *[]contract.CryptoGeneratedSourceProtection) {
			(*rows)[0].OriginalSourceCoreDigest, (*rows)[0].Transfer.Core.SealedInputCoreDigest = id(90), id(90)
		},
		"other envelope": func(_ *contract.OperationMaterialRecord, rows *[]contract.CryptoGeneratedSourceProtection) {
			(*rows)[0].OriginalEnvelopeDigest = id(90)
		},
		"other operation": func(m *contract.OperationMaterialRecord, rows *[]contract.CryptoGeneratedSourceProtection) {
			m.Core.OperationID, (*rows)[0].Transfer.Core.OperationID = id(90), id(90)
		},
		"other material": func(m *contract.OperationMaterialRecord, rows *[]contract.CryptoGeneratedSourceProtection) {
			m.Core.OperationMaterialID, (*rows)[0].Transfer.Core.OperationMaterialID = id(90), id(90)
		},
		"other use plan": func(m *contract.OperationMaterialRecord, rows *[]contract.CryptoGeneratedSourceProtection) {
			m.Core.UsePlanDigest, (*rows)[0].Transfer.Core.UsePlanDigest = id(90), id(90)
		},
		"other compatibility": func(m *contract.OperationMaterialRecord, rows *[]contract.CryptoGeneratedSourceProtection) {
			m.Core.CompatibilityID, (*rows)[0].Transfer.Core.CompatibilityID = id(90), id(90)
		},
		"other crypto support": func(m *contract.OperationMaterialRecord, rows *[]contract.CryptoGeneratedSourceProtection) {
			m.Core.CryptoSupportID, (*rows)[0].Transfer.Core.CryptoSupportID = id(90), id(90)
		},
		"surplus source": func(_ *contract.OperationMaterialRecord, rows *[]contract.CryptoGeneratedSourceProtection) {
			extra := (*rows)[0]
			extra.SourceID, extra.Transfer.Core.SourceID = id(90), id(90)
			*rows = append(*rows, extra)
			slices.SortFunc(*rows, func(a, b contract.CryptoGeneratedSourceProtection) int {
				return bytes.Compare(a.SourceID[:], b.SourceID[:])
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := generatedReservationState(t, generatedSealedSource(t, "alpha"))
			selected, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			material, err := contract.InspectOperationMaterialRecord(selected.records[generatedRecordKey{contract.OperationMaterialSupportKind, selected.parent.MaterialID}].Body)
			if err != nil {
				t.Fatal(err)
			}
			protected, err := contract.InspectGeneratedSourceProtections(material, selected.protected[material.Core.OperationMaterialID])
			if err != nil {
				t.Fatal(err)
			}
			row, err := protected.Row(0)
			if err != nil {
				t.Fatal(err)
			}
			rows := []contract.CryptoGeneratedSourceProtection{{SourceID: row.SourceID, OriginalSourceCoreDigest: row.OriginalSourceCoreDigest,
				OriginalEnvelopeDigest: row.OriginalEnvelopeDigest, Transfer: contract.TransferEnvelope(row.Transfer)}}
			change(&material, &rows)
			body, err := contract.EncodeGeneratedSourceProtections(material, rows)
			if err != nil {
				t.Fatal(err)
			}
			generatedReplaceConfiguration(t, s, selected.parent.MaterialID, body)
			if _, err := format.ResolveGeneratedSlices(s.root.Domain, s.root.Snapshot, s.root.Generated, s.support); err != nil {
				t.Fatal("repinned outer storage invalid", err)
			}
			if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
				t.Fatal("different accepted source protection selected")
			}
		})
	}
}

package core

import (
	"bytes"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestInstalledGeneratedCurrentDeclarationKeepsExactProfileFraming(t *testing.T) {
	// This tests construction from fixed input rows. It grants no selected-state authority.
	for _, cell := range []struct {
		name          string
		schema        uint16
		kind          contract.GeneratorLifecycleMode
		input, output uint8
	}{
		{"managed/raw", contract.GeneratedEntryMetadataSchema, contract.GeneratorLifecycleManaged, contract.InputEncodingRaw, contract.OutputEncodingRaw},
		{"managed/base64", contract.GeneratedEntryMetadataSchema, contract.GeneratorLifecycleManaged, contract.InputEncodingBase64, contract.OutputEncodingBase64},
		{"none/raw", contract.GeneratedEntryMetadataSchema, contract.GeneratorLifecycleNone, contract.InputEncodingRaw, contract.OutputEncodingRaw},
		{"none/base64", contract.GeneratedEntryMetadataSchema, contract.GeneratorLifecycleNone, contract.InputEncodingBase64, contract.OutputEncodingBase64},
	} {
		t.Run(cell.name, func(t *testing.T) {
			id := generatedVectorID
			profile := generatedFixtureProfile{LifecycleMode: cell.kind, ConfigContractID: id(20), ResourceContractID: id(21)}
			if cell.kind == contract.GeneratorLifecycleNone {
				profile.ResourceContractID = contract.ID{}
			}
			intent := generatedFixtureCanonicalIntent(t, []byte(`{}`), profile)
			intentID, err := contract.GeneratorIntentDigest(intent)
			if err != nil {
				t.Fatal(err)
			}
			location := contract.GeneratorSliceLocation{Schema: 1, ContentKind: contract.GeneratorContentIntent, ContentID: intentID, BlobID: id(90), Length: uint32(len(intent)), Digest: contract.Hash(intent)}
			meta := contract.GeneratedEntryMetadata{Schema: cell.schema, LifecycleMode: cell.kind, Epoch: 7, ConfigContractID: id(20), ResourceContractID: profile.ResourceContractID, IntentDigest: intentID, RetirementMode: contract.GeneratedRetirementManual, CompletionClass: contract.GeneratedCompletionAcknowledged}
			if cell.kind == contract.GeneratorLifecycleNone {
				meta.RetirementMode, meta.CompletionClass = 0, 0
			}
			member := id(11)
			_, retained := generatedCanonicalSource(t)
			retained.Entry.Name = "supplied"
			rows := []contract.ValueEntry{
				{Name: "", Incarnation: id(30), ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{member}, ValueBytes: []byte("original generated ciphertext"), InputEncoding: cell.input, OutputEncoding: cell.output, ContentLength: 0, RetainedLength: 0, Generated: meta},
				{Name: "plain", Incarnation: id(31), ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{member}, ValueBytes: []byte("plain value"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 11, RetainedLength: 11},
				retained.Entry,
			}
			s := &StateSession{root: format.Root{Domain: id(1)}}
			s.pages[0] = &format.ValueEntryPage{}
			for at := range rows {
				s.pages[0].Slots[at] = &rows[at]
				s.root.Names = append(s.root.Names, format.NameEntry{Name: rows[at].Name, Slot: uint16(at)})
			}
			work := &generatedSelection{content: &generatedContent{locations: map[generatedContentKey]contract.GeneratorSliceLocation{{contract.GeneratorContentIntent, intentID}: location}}}
			before := make([]contract.ValueEntry, len(rows))
			for at, v := range rows {
				before[at] = v
				before[at].ValueBytes = bytes.Clone(v.ValueBytes)
				before[at].Recipients = append([]contract.ID(nil), v.Recipients...)
			}
			wantKind := cell.kind
			if wantKind == 0 {
				wantKind = contract.GeneratorLifecycleManaged
			}
			declaration, plans, err := s.installedGeneratedCurrentDeclaration(work, id(2))
			if err != nil {
				t.Fatal("current declaration construction refused", err)
			}
			if !reflect.DeepEqual(rows, before) {
				t.Fatal("construction rewrote original metadata or ciphertext")
			}
			body, err := contract.EncodeGeneratorDeclaration(declaration)
			if err != nil {
				t.Fatal(err)
			}
			view, err := contract.InspectGeneratorDeclaration(body)
			if err != nil || view.EntryCount() != 3 || len(plans) != 3 {
				t.Fatal("whole row set differs", err)
			}
			for at := 0; at < 3; at++ {
				row, _, err := view.Entry(at)
				var recipients []byte
				for _, recipient := range before[at].Recipients {
					recipients = append(recipients, recipient[:]...)
				}
				if err != nil || row.Schema != contract.GeneratorDeclarationEntrySchema || plans[at].Schema != contract.GeneratorValueEntryPlanSchema || string(row.Name) != before[at].Name || !bytes.Equal(row.RecipientIDs, recipients) {
					t.Fatal("current row framing differs", at, err)
				}

				if row.InputEncoding != before[at].InputEncoding || row.OutputEncoding != before[at].OutputEncoding || plans[at].InputEncoding != before[at].InputEncoding || plans[at].OutputEncoding != before[at].OutputEncoding {
					t.Errorf("current representation changed: row=%d/%d plan=%d/%d want=%d/%d", row.InputEncoding, row.OutputEncoding, plans[at].InputEncoding, plans[at].OutputEncoding, before[at].InputEncoding, before[at].OutputEncoding)
				}
				if _, err := contract.EncodeGeneratorValueEntryPlan(plans[at]); err != nil {
					t.Error("current entry plan cannot be encoded", at, err)
				}
				switch at {
				case 0:
					reference, err := contract.InspectGeneratorDeclaredGenerationReferenceForEntry(row.Schema, row.Payload)
					want := contract.GeneratorDeclaredGenerationReference{Schema: contract.GeneratorDeclaredReferenceSchema, LifecycleMode: wantKind, Epoch: 7, RetirementMode: meta.RetirementMode, ConfigContractID: id(20), ResourceContractID: meta.ResourceContractID, CompletionClass: meta.CompletionClass, Intent: location.Logical()}
					if err != nil || reference != want || plans[at].LifecycleMode != wantKind {
						t.Fatal("exact original profile/content changed", err)
					}
				case 1:
					if row.Kind != contract.GeneratorDeclarationPlain || !bytes.Equal(row.Payload, []byte("plain value")) || plans[at].LifecycleMode != 0 {
						t.Fatal("plain source changed")
					}
				default:
					got, err := contract.DecodeRetainedCanonicalRecord(row.Payload)
					if err != nil || got.OriginalSlot != 2 || !reflect.DeepEqual(got.Entry, before[2]) || plans[at].LifecycleMode != 0 {
						t.Fatal("retained source changed", err)
					}
				}
			}
			delete(work.content.locations, generatedContentKey{contract.GeneratorContentIntent, intentID})
			if _, _, err := s.installedGeneratedCurrentDeclaration(work, id(2)); err == nil {
				t.Fatal("missing selected logical intent accepted")
			}
		})
	}
}

// full_only: false
func TestInstalledApplyCarriersBindEntryRepresentation(t *testing.T) {
	for _, input := range []uint8{contract.InputEncodingRaw, contract.InputEncodingBase64} {
		configuration := publicConfigurationFixture(t)
		recipients := configuration.Recipients.Value
		configured := []contract.ApplyRecipientInput{}
		for _, recipient := range recipients {
			encryption := recipient.Encryption
			configured = append(configured, contract.ApplyRecipientInput{Recipient: contract.RecipientRecord{RecipientID: recipient.RecipientID, Status: contract.CurrentRecipient, DisplayName: recipient.DisplayName.Value, CurrentBinding: &contract.KMSBinding{Provider: encryption.Provider.Value, KeySelector: encryption.Selector.Value, SPKI: encryption.PublicKey.Value, Fingerprint: encryption.Fingerprint.Value, WrapProfile: encryption.WrapProfile.Value, ProtectionClass: encryption.ProtectionClass.Value}}})
		}
		entry := contract.PublicEntry{Name: "plain", Class: publicPresent(uint8(contract.Plain)), Source: publicPresent(uint8(contract.Supplied)), Memberships: publicPresent([]contract.ID{recipients[0].RecipientID}), PlainValue: publicPresent([]byte("QUJD")), InputEncoding: publicPresent(input), OutputEncoding: publicPresent(uint8(contract.OutputEncodingRaw))}
		configuration.Entries = publicPresent([]contract.PublicEntry{entry})
		before := ApplyEntryInput{Name: entry.Name, ValueSource: entry.Source.Value, ConfidentialityClass: entry.Class.Value, Recipients: entry.Memberships.Value, InputBytes: bytes.Clone(entry.PlainValue.Value), InputEncoding: input, OutputEncoding: contract.OutputEncodingRaw}
		if !installedApplyConfigurationCarriers(configuration, []ApplyEntryInput{before}, configured) {
			t.Fatal("matching representation carrier refused")
		}
		for _, field := range []string{"input", "output"} {
			changed := before
			if field == "output" {
				changed.OutputEncoding = contract.OutputEncodingBase64
			} else if input == contract.InputEncodingRaw {
				changed.InputEncoding = contract.InputEncodingBase64
			} else {
				changed.InputEncoding = contract.InputEncodingRaw
			}
			if installedApplyConfigurationCarriers(configuration, []ApplyEntryInput{changed}, configured) {
				t.Error("configuration carrier ignored representation", input, field)
			}
		}
	}
}

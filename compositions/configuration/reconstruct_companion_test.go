//go:build darwin || linux

package configuration

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestCompanionMergeQualifiesRecipientSourceIdentity(t *testing.T) {
	for _, condition := range []string{"renamed-reference", "selector-conflict", "another-current-key", "unknown-id", "missing-id"} {
		t.Run(condition, func(t *testing.T) {
			path, _, original, _ := companionReconstructionSource(t, YAML, false)
			material := preparationMaterial(t)
			currentKey := kmsKey(material.Encryption)
			recovered := reconstructionModel(t, "recovered")
			recovered.Recipients = []Recipient{{Reference: "remote-reference", DisplayName: "Current label", Selector: currentKey.Selector, ID: material.RecipientID, Encryption: currentKey}}
			id, selector := preparedSourceRecipientID, sourceEncryptionSelector
			switch condition {
			case "selector-conflict":
				selector = sourceSigningSelector
			case "another-current-key":
				selector = "arn:aws:kms:us-east-1:123456789012:key/77777777-1111-1111-1111-111111111111"
				other := recovered.Recipients[0]
				other.Reference, other.ID, other.Selector, other.Encryption.Selector = "other-current", contract.ID{7}, selector, selector
				other.Encryption.Binding.ID, other.Encryption.Binding.Incarnation = contract.ID{8}, contract.ID{9}
				recovered.Recipients = append(recovered.Recipients, other)
			case "unknown-id":
				id = strings.Repeat("07", 32)
			}
			row := `{"id":"` + id + `","display_name":"Pending label","encryption_key":"` + selector + `"}`
			if condition == "missing-id" {
				row = `{"display_name":"Pending label","encryption_key":"` + selector + `"}`
			}
			body := strings.Replace(original, `recipients: {}`, `recipients: {"local-reference":`+row+`}`, 1)
			if body == original {
				t.Fatal("recipient source fixture did not change")
			}
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			output, source, err := BeginCompanionReconstruction(t.Context(), path, YAML)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { *source = Model{}; closeSourceOwner(t, output) })
			merged, err := MergeReconstructedCompanion(t.Context(), source, recovered)
			if !reflect.DeepEqual(*recovered, Model{}) {
				t.Fatal("merge retained the consumed recovered model")
			}
			if condition != "renamed-reference" {
				if err == nil || merged != nil || !reflect.DeepEqual(*source, Model{}) {
					t.Fatal("recipient identity conflict inferred another recipient or retained consumed state", err)
				}
			} else {
				if err != nil || merged != source || len(merged.Recipients) != 1 {
					t.Fatal("exact source ID could not join a renamed local reference", err)
				}
				row := merged.Recipients[0]
				if row.Reference != "local-reference" || row.DisplayName != "Pending label" || row.ID != material.RecipientID || !reflect.DeepEqual(row.Encryption, currentKey) || row.Creation != nil {
					t.Fatal("recipient merge changed desired metadata or selected facts by name/key")
				}
				if _, err := output.Stage(t.Context(), merged); err != nil {
					t.Fatal("source-ID-joined companion did not form a valid staged pair", err)
				}
			}
			if readSource(t, path) != body {
				t.Fatal("recipient merge changed surviving source bytes")
			}
		})
	}
}

// full_only: false
func TestCompanionMergeRestoresAcceptedRecipientCreation(t *testing.T) {
	for _, variant := range []string{"exact", "wrong nonce", "wrong first binding", "missing proof"} {
		t.Run(variant, func(t *testing.T) {
			path, _, original, _ := companionReconstructionSource(t, YAML, false)
			recovered := reconstructionModel(t, "recovered")
			creation := Creation{Snapshot: contract.ID{1}, Nonce: contract.ID{2}}
			id, err := contract.RecipientCreationID(recovered.DomainID, creation.Snapshot, creation.Nonce)
			if err != nil {
				t.Fatal(err)
			}
			key := kmsKey(preparationMaterial(t).Encryption)
			key.Binding.ID, key.Binding.Incarnation, err = contract.RecipientInitialBindingIDs(recovered.DomainID, id)
			if err != nil {
				t.Fatal(err)
			}
			key.Binding.Serial = 1
			recovered.GeneratedRecipients = []Recipient{{ID: id, Encryption: key, Creation: &creation}}
			switch variant {
			case "wrong nonce":
				recovered.GeneratedRecipients[0].Creation = &Creation{Snapshot: creation.Snapshot, Nonce: contract.ID{3}}
			case "wrong first binding":
				recovered.GeneratedRecipients[0].Encryption.Binding.ID = contract.ID{4}
			case "missing proof":
				recovered.GeneratedRecipients[0].Creation = nil
			}
			row := `{"id":"` + hex.EncodeToString(id[:]) + `","display_name":"New label","encryption_key":"` + key.Selector + `"}`
			body := strings.Replace(original, `recipients: {}`, `recipients: {"new-reader":`+row+`}`, 1)
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			out, source, err := BeginCompanionReconstruction(t.Context(), path, YAML)
			if err != nil {
				t.Fatal(err)
			}
			defer closeSourceOwner(t, out)
			merged, err := MergeReconstructedCompanion(t.Context(), source, recovered)
			if variant != "exact" {
				if err == nil || merged != nil || readSource(t, path) != body {
					t.Fatal("invalid creation facts restored the companion")
				}
				return
			}
			if err != nil {
				t.Fatal("accepted creation could not restore its local record", err)
			}
			if _, err := out.Stage(t.Context(), merged); err != nil {
				t.Fatal("could not stage restored recipient", err)
			}
			if delivery, err := out.Commit(t.Context()); err != nil || delivery == nil {
				t.Fatal("could not deliver restored recipient", err)
			}
			closeSourceOwner(t, out)
			pair, err := Capture(t.Context(), path, YAML)
			if err != nil {
				t.Fatal(err)
			}
			defer pair.Close()
			restored, err := ParseForAcceptedWork(t.Context(), pair)
			if err != nil || len(restored.Recipients) != 1 {
				t.Fatal("fresh accepted-work invocation could not read the pair", err)
			}
			got := restored.Recipients[0]
			if got.ID != id || got.Reference != "new-reader" || got.DisplayName != "New label" ||
				got.Encryption.Selector != key.Selector || got.Encryption.Binding != key.Binding || !bytes.Equal(got.Encryption.PublicKey, key.PublicKey) || got.Creation == nil || *got.Creation != creation || readSource(t, path) != body {
				t.Fatal("restoration changed preparation or source")
			}
		})
	}
}

// These inert fixtures isolate typed metadata joins. Full composition tests
// separately authenticate selected state before offering its recovered model.
// full_only: false
func TestCompanionMergeChecksFixedRecoverySelectors(t *testing.T) {
	const signing = "arn:aws:kms:us-east-1:123456789012:key/77777777-1111-1111-1111-111111111111"
	const encryption = "arn:aws:kms:us-east-1:123456789012:key/88888888-1111-1111-1111-111111111111"
	for _, condition := range []string{"matching", "signing", "encryption"} {
		t.Run(condition, func(t *testing.T) {
			path, _, original, _ := companionReconstructionSource(t, YAML, false)
			body := strings.Replace(original, `enabled: false`, `enabled: true`+"\n    signing_key: \""+signing+"\"\n    encryption_key: \""+encryption+"\"", 1)
			if body == original {
				t.Fatal("recovery source fixture did not change")
			}
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			output, source, err := BeginCompanionReconstruction(t.Context(), path, YAML)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { *source = Model{}; closeSourceOwner(t, output) })
			recovered := reconstructionModel(t, "recovered")
			recovered.RecoveryEnabled = true
			recovered.Recovery = recovered.Authority
			recovered.Recovery.ID = contract.ID{9}
			recovered.Recovery.SigningSelector, recovered.Recovery.Signing.Selector = signing, signing
			recovered.Recovery.EncryptionSelector, recovered.Recovery.Encryption.Selector = encryption, encryption
			recovered.Recovery.Encryption.Binding.ID, recovered.Recovery.Encryption.Binding.Incarnation = contract.ID{10}, contract.ID{11}
			if condition == "signing" {
				recovered.Recovery.SigningSelector = sourceSigningSelector
			}
			if condition == "encryption" {
				recovered.Recovery.EncryptionSelector = sourceEncryptionSelector
			}
			merged, err := MergeReconstructedCompanion(t.Context(), source, recovered)
			if condition == "matching" {
				if err != nil || merged == nil || !merged.RecoveryEnabled || merged.Recovery.ID != (contract.ID{9}) || merged.Recovery.Signing.Selector != signing || merged.Recovery.Encryption.Selector != encryption {
					t.Fatal("matching fixed Recovery facts did not join", err)
				}
			} else if merged != nil || err == nil {
				t.Fatal("fixed Recovery selector conflict was accepted", err)
			}
			if readSource(t, path) != body {
				t.Fatal("Recovery metadata join changed source")
			}
		})
	}
}

// full_only: false
func TestCompanionMergeRestoresOnlySuppliedSecretPins(t *testing.T) {
	for _, kind := range []string{"supplied-secret", "base64-supplied-secret", "input-encoding-conflict", "plain", "generated"} {
		t.Run(kind, func(t *testing.T) {
			path, _, original, _ := companionReconstructionSource(t, YAML, false)
			sourceEncoding, wantedEncoding := "raw", contract.InputEncodingRaw
			if kind == "base64-supplied-secret" || kind == "input-encoding-conflict" {
				sourceEncoding, wantedEncoding = "base64", contract.InputEncodingBase64
			}
			// This source contains no input bytes: its explicit encoding selects
			// the representation of the exact committed pin, not a new value.
			body := strings.Replace(original, `entries: {}`, `entries: {"known":{"confidentiality":"secret","output_encoding":"raw","recipients":[],"source":{"kind":"supplied","encoding":"`+sourceEncoding+`"}}}`, 1)
			if body == original {
				t.Fatal("supplied-secret source fixture did not change")
			}
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			output, source, err := BeginCompanionReconstruction(t.Context(), path, YAML)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { *source = Model{}; closeSourceOwner(t, output) })
			recovered := reconstructionModel(t, "recovered")
			pin := Pin{Incarnation: contract.ID{4}, Material: contract.ID{5}}
			currentEncoding := contract.InputEncodingRaw
			if kind == "base64-supplied-secret" {
				currentEncoding = contract.InputEncodingBase64
			}
			current := Entry{Name: "known", Secret: true, InputEncoding: currentEncoding, OutputEncoding: contract.OutputEncodingRaw, Retained: &pin}
			if kind == "plain" {
				current = Entry{Name: "known", Plain: []byte("current public value"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
			}
			if kind == "generated" {
				current = Entry{Name: "known", Secret: true, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Generated: &Generator{Intent: sourceCanonicalIntent(t, false), Epoch: 7}}
			}
			recovered.Entries = []Entry{current}
			merged, err := MergeReconstructedCompanion(t.Context(), source, recovered)
			if kind == "supplied-secret" || kind == "base64-supplied-secret" {
				if err != nil || merged == nil || len(merged.Entries) != 1 {
					t.Fatal("matching committed supplied-secret input did not join", err)
				}
				got := merged.Entries[0]
				if !got.Secret || got.Generated != nil || got.Retained == nil || *got.Retained != pin || len(got.Sealed) != 0 || len(got.Plain) != 0 || len(got.Recipients) != 0 || got.InputEncoding != wantedEncoding || got.OutputEncoding != contract.OutputEncodingRaw || len(merged.MissingInputs) != 0 {
					t.Fatal("exact committed pin or surviving representation changed")
				}
			} else {
				var diagnostic *Diagnostic
				if merged != nil || !errors.As(err, &diagnostic) || diagnostic.Field != "entries.source" || diagnostic.Reason != "sealed-context-mismatch" {
					t.Fatal("incompatible current input was not refused at the source join", err)
				}
			}
			if readSource(t, path) != body {
				t.Fatal("pin reconstruction changed exact surviving source bytes")
			}
		})
	}
}

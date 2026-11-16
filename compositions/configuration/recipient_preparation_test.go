package configuration

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

func preparationRecipientRow() string {
	return `{"id":"` + strings.Repeat("06", 32) + `","encryption":{"selector":"` + sourceEncryptionSelector + `","public_key":"` + sourceEncryptionSPKI + `","binding":{"id":"` + sourceID4 + `","incarnation":"` + sourceID5 + `","serial":1,"protection":"software"}}}`
}

// full_only: false
func TestRecipientPreparationRefusesInvalidMaterialAndOwnership(t *testing.T) {
	declaration := `{"chosen":{"display_name":"","encryption_key":"` + sourceEncryptionSelector + `"}}`
	for _, condition := range []string{"provider", "selector", "public-key", "fingerprint", "binding", "creation", "authority-id", "wrong-model", "closed-pair", "existing-declaration", "absent-declaration"} {
		t.Run(condition, func(t *testing.T) {
			pair := writePair(t, preparationEditable(JSON, declaration), sourceGeneratedJSON, JSON)
			model, err := ParseForRecipientPreparation(t.Context(), pair, "chosen")
			if err != nil {
				t.Fatal(err)
			}
			material := preparationMaterial(t)
			var declared *RecipientDeclaration
			reference := "chosen"
			switch condition {
			case "provider":
				material.Encryption.Provider = contract.GCP
			case "selector":
				material.Encryption.KeySelector = sourceSigningSelector
			case "public-key":
				material.Encryption.SPKI = []byte{1}
			case "fingerprint":
				material.Encryption.Fingerprint = contract.ID{1}
			case "binding":
				material.Encryption.BindingSerial = 0
			case "creation":
				material.Creation = &Creation{Snapshot: contract.ID{1}}
			case "authority-id":
				material.RecipientID = model.Authority.ID
			case "wrong-model":
				other := writePair(t, preparationEditable(JSON, declaration), sourceGeneratedJSON, JSON)
				model, err = ParseForRecipientPreparation(t.Context(), other, "chosen")
				if err != nil {
					t.Fatal(err)
				}
			case "closed-pair":
				if err := pair.Close(); err != nil {
					t.Fatal(err)
				}
			case "existing-declaration":
				declared = &RecipientDeclaration{EncryptionSelector: sourceEncryptionSelector}
			case "absent-declaration":
				reference = "absent"
			}
			if _, err := PrepareRecipientEdit(t.Context(), pair, model, reference, declared, material); err == nil {
				t.Fatal("invalid material, declaration or owner admitted")
			}
		})
	}
	t.Run("closed-after-preparation", func(t *testing.T) {
		pair := writePair(t, preparationEditable(JSON, declaration), sourceGeneratedJSON, JSON)
		model, err := ParseForRecipientPreparation(t.Context(), pair, "chosen")
		if err != nil {
			t.Fatal(err)
		}
		edit, err := PrepareRecipientEdit(t.Context(), pair, model, "chosen", nil, preparationMaterial(t))
		if err != nil {
			t.Fatal(err)
		}
		if err := pair.Close(); err != nil {
			t.Fatal(err)
		}
		if err := edit.EmitEditable(t.Context(), io.Discard, model.Generated); err == nil {
			t.Fatal("editor consumed a closed pair")
		}
		if err := edit.EmitGenerated(t.Context(), io.Discard); err == nil {
			t.Fatal("generated editor consumed a closed pair")
		}
	})
}

func preparationMaterial(t *testing.T) RecipientPreparationMaterial {
	t.Helper()
	spki, err := base64.StdEncoding.DecodeString(sourceEncryptionSPKI)
	if err != nil {
		t.Fatal(err)
	}
	var recipient, binding, incarnation contract.ID
	for i := range recipient {
		recipient[i], binding[i], incarnation[i] = 6, 4, 5
	}
	return RecipientPreparationMaterial{RecipientID: recipient, Encryption: contract.KMSBinding{BindingID: binding, BindingIncarnationID: incarnation, BindingSerial: 1, Provider: contract.AWS, WrapProfile: contract.RSAOAEPWrapProfile, ProtectionClass: contract.SoftwareProtection, KeySelector: sourceEncryptionSelector, SPKI: spki, Fingerprint: contract.Hash(spki)}}
}

func preparationEditable(format Format, recipients string) string {
	if format == JSON {
		return strings.Replace(sourceSetupJSON, `"recipients":{}`, `"recipients":`+recipients, 1)
	}
	return strings.Replace(sourceSetupYAML, "recipients: {}", "recipients: "+recipients+" # keep recipient comment", 1)
}

// full_only: false
func TestRecipientPreparationSelectedJoins(t *testing.T) {
	declaration := `{"chosen":{"display_name":"","encryption_key":"` + sourceEncryptionSelector + `"}}`
	for _, format := range []Format{JSON, YAML} {
		for _, existing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/existing-%v", format, existing), func(t *testing.T) {
				generated := sourceGeneratedJSON
				if existing {
					old := strings.Replace(preparationRecipientRow(), sourceEncryptionSelector, sourceSigningSelector, 1)
					generated = strings.Replace(generated, `"recipients":{}`, `"recipients":{"chosen":`+old+`}`, 1)
				}
				edited := declaration
				if existing {
					edited = strings.Replace(edited, `"chosen":{`, `"chosen":{"id":"`+preparedSourceRecipientID+`",`, 1)
				}
				pair := writePair(t, preparationEditable(format, edited), generated, format)
				if _, err := Parse(t.Context(), pair); err == nil {
					t.Fatal("ordinary parse admitted incomplete recipient preparation")
				}
				reference := "chosen"
				if existing {
					var id contract.ID
					for i := range id {
						id[i] = 6
					}
					var err error
					reference, err = RecipientReferenceByID(t.Context(), pair, id)
					if err != nil || reference != "chosen" {
						t.Fatal("exact ID lost selected-row repair", reference, err)
					}
				}
				model, err := ParseForRecipientPreparation(t.Context(), pair, reference)
				if err != nil || !model.Resolved || len(model.Recipients) != 1 || model.Authority.ID.IsZero() || len(model.Basis.Descriptor) != 1 {
					t.Fatal("selected recipient preparation refused complete unrelated joins", err)
				}
				if existing && model.Recipients[0].Encryption.Selector != sourceSigningSelector {
					t.Fatal("selected parse lost old generated selector")
				}
			})
		}
	}
	for _, damage := range []string{"other-missing", "authority-selector", "basis", "selected-key"} {
		t.Run(damage, func(t *testing.T) {
			editable := preparationEditable(JSON, declaration)
			generated := sourceGeneratedJSON
			switch damage {
			case "other-missing":
				editable = preparationEditable(JSON, `{"chosen":{"display_name":"","encryption_key":"`+sourceEncryptionSelector+`"},"other":{"display_name":"","encryption_key":"`+sourceEncryptionSelector+`"}}`)
			case "authority-selector":
				generated = strings.Replace(generated, sourceSigningSelector, sourceEncryptionSelector, 1)
			case "basis":
				generated = strings.Replace(generated, `"descriptor":"AQ=="`, `"descriptor":""`, 1)
			case "selected-key":
				row := strings.Replace(preparationRecipientRow(), sourceEncryptionSPKI, "AQ==", 1)
				generated = strings.Replace(generated, `"recipients":{}`, `"recipients":{"chosen":`+row+`}`, 1)
			}
			if _, err := ParseForRecipientPreparation(t.Context(), writePair(t, editable, generated, JSON), "chosen"); err == nil {
				t.Fatal("selected preparation hid an unrelated or malformed join")
			}
		})
	}
}

// full_only: false
func TestRecipientPreparationEmitsCompleteCandidate(t *testing.T) {
	for _, format := range []Format{JSON, YAML} {
		for _, declare := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/declare-%v", format, declare), func(t *testing.T) {
				editable := preparationEditable(format, `{"chosen":{"id":"`+preparedSourceRecipientID+`","display_name":"","encryption_key":"`+sourceEncryptionSelector+`"}}`)
				var declaration *RecipientDeclaration
				if declare {
					editable = preparationEditable(format, `{}`)
					declaration = &RecipientDeclaration{EncryptionSelector: sourceEncryptionSelector}
				}
				secret := `"untouched" : { "sealed" : "` + base64.StdEncoding.EncodeToString(sourceEditEnvelope(t, "untouched")) + `" }`
				generated := strings.Replace(sourceGeneratedJSON, `"secrets":{}`, `"secrets":{`+secret+`}`, 1)
				generated = strings.Replace(generated, `"recipients":{}`, `"recipients":{"unused":`+preparationRecipientRow()+`}`, 1)
				if !declare {
					generated = strings.Replace(generated, `"recipients":{`, `"recipients":{"chosen":`+preparationRecipientRow()+`,`, 1)
				}
				pair := writePair(t, editable, generated, format)
				model, err := ParseForRecipientPreparation(t.Context(), pair, "chosen")
				if err != nil {
					t.Fatal(err)
				}
				material := preparationMaterial(t)
				edit, err := PrepareRecipientEdit(t.Context(), pair, model, "chosen", declaration, material)
				if err != nil {
					t.Fatal("recipient edit did not prepare candidate", err)
				}
				var nextEditable, nextGenerated bytes.Buffer
				if err := edit.EmitGenerated(t.Context(), &nextGenerated); err != nil {
					t.Fatal(err)
				}
				if err := edit.EmitEditable(t.Context(), &nextEditable, model.Generated); err != nil {
					t.Fatal(err)
				}
				after, err := Parse(t.Context(), captureEditableEmission(t, nextEditable.Bytes(), nextGenerated.Bytes(), format, model.Generated))
				if err != nil || len(after.Recipients) != 1 || after.Recipients[0].ID != material.RecipientID || after.Recipients[0].DisplayName != "" || after.Recipients[0].Encryption.Selector != material.Encryption.KeySelector {
					t.Fatal("recipient candidate lost exact prepared facts", err)
				}
				if len(after.GeneratedRecipients) != 1 || !bytes.Contains(nextGenerated.Bytes(), []byte(secret)) || after.FileID != model.FileID || after.DomainID != model.DomainID {
					t.Fatal("preparation retained inactive recipients or changed encrypted record/identity")
				}
				if format == YAML && !strings.Contains(nextEditable.String(), "# keep recipient comment") {
					t.Fatal("recipient declaration removed YAML comment")
				}
			})
		}
	}
}

// full_only: false
func TestRecipientPreparationRefreshesOldSelectorAndPreservesCreation(t *testing.T) {
	for _, format := range []Format{JSON, YAML} {
		t.Run(fmt.Sprint(format), func(t *testing.T) {
			declaration := `{"chosen":{"id":"` + preparedSourceRecipientID + `","display_name":"unchanged","encryption_key":"` + sourceEncryptionSelector + `"}}`
			old := strings.Replace(preparationRecipientRow(), sourceEncryptionSelector, sourceSigningSelector, 1)
			generated := strings.Replace(sourceGeneratedJSON, `"recipients":{}`, `"recipients":{"chosen":`+old+`}`, 1)
			pair := writePair(t, preparationEditable(format, declaration), generated, format)
			model, err := ParseForRecipientPreparation(t.Context(), pair, "chosen")
			if err != nil {
				t.Fatal(err)
			}
			material := preparationMaterial(t)
			material.Creation = &Creation{Snapshot: contract.ID{1}, Nonce: contract.ID{2}}
			edit, err := PrepareRecipientEdit(t.Context(), pair, model, "chosen", nil, material)
			if err != nil {
				t.Fatal(err)
			}
			var nextEditable, nextGenerated bytes.Buffer
			if err := edit.EmitEditable(t.Context(), &nextEditable, ".enkv/prod.generated.json"); err != nil {
				t.Fatal(err)
			}
			if err := edit.EmitGenerated(t.Context(), &nextGenerated); err != nil {
				t.Fatal(err)
			}
			after, err := Parse(t.Context(), captureEditableEmission(t, nextEditable.Bytes(), nextGenerated.Bytes(), format, ".enkv/prod.generated.json"))
			if err != nil || after.Recipients[0].Encryption.Selector != sourceEncryptionSelector || after.Recipients[0].Creation == nil || *after.Recipients[0].Creation != *material.Creation {
				t.Fatal("refresh lost exact selected key or creation proof", err)
			}
			if nextEditable.String() != readSource(t, pair.Editable.OriginalPath()) || after.Recipients[0].DisplayName != "unchanged" {
				t.Fatal("refresh changed editable source metadata")
			}
		})
	}
}

// full_only: false
func TestRecipientDeclarationPreservesExistingRowsAndBlockComments(t *testing.T) {
	for _, format := range []Format{JSON, YAML} {
		t.Run(fmt.Sprint(format), func(t *testing.T) {
			editable := preparationEditable(format, `{"z":{"id":"`+strings.Repeat("07", 32)+`","display_name":"existing","encryption_key":"`+sourceEncryptionSelector+`"}}`)
			if format == YAML {
				editable = strings.Replace(sourceSetupYAML, "recipients: {}", "recipients:\n  # recipient heading\n  z: {id: \""+strings.Repeat("07", 32)+"\", display_name: existing, encryption_key: "+sourceEncryptionSelector+"} # existing row", 1)
			}
			row := `"z" : ` + strings.Replace(preparationRecipientRow(), strings.Repeat("06", 32), strings.Repeat("07", 32), 1)
			generated := strings.Replace(sourceGeneratedJSON, `"recipients":{}`, `"recipients":{`+row+`}`, 1)
			pair := writePair(t, editable, generated, format)
			model, err := ParseForRecipientPreparation(t.Context(), pair, "alpha")
			if err != nil {
				t.Fatal(err)
			}
			edit, err := PrepareRecipientEdit(t.Context(), pair, model, "alpha", &RecipientDeclaration{EncryptionSelector: sourceEncryptionSelector}, preparationMaterial(t))
			if err != nil {
				t.Fatal(err)
			}
			var declaration, satellite bytes.Buffer
			if err := edit.EmitEditable(t.Context(), &declaration, ".enkv/prod.generated.json"); err != nil {
				t.Fatal(err)
			}
			if err := edit.EmitGenerated(t.Context(), &satellite); err != nil {
				t.Fatal(err)
			}
			after, err := Parse(t.Context(), captureEditableEmission(t, declaration.Bytes(), satellite.Bytes(), format, ".enkv/prod.generated.json"))
			if err != nil || len(after.Recipients) != 2 || after.Recipients[0].Reference != "alpha" || after.Recipients[1].Reference != "z" {
				t.Fatal("declaration candidate lost existing or new row", err)
			}
			if !bytes.Contains(satellite.Bytes(), []byte(row)) || bytes.Index(satellite.Bytes(), []byte(`"alpha"`)) > bytes.Index(satellite.Bytes(), []byte(row)) {
				t.Fatal("generated insertion changed existing row bytes or deterministic position")
			}
			if format == YAML && (!strings.Contains(declaration.String(), "# recipient heading") || !strings.Contains(declaration.String(), "# existing row")) {
				t.Fatal("declaration removed block-map comments")
			}
		})
	}
}

// full_only: false
func TestRecipientDeclarationPreservesBlockAndFlowBoundaries(t *testing.T) {
	for _, layout := range []string{"flow", "flow-trailing", "block-before-entries", "block-eof"} {
		t.Run(layout, func(t *testing.T) {
			const reference = ".enkv/prod.generated.json"
			block := "recipients:\n  z:\n    id: \"" + strings.Repeat("07", 32) + "\"\n    encryption_key: " + sourceEncryptionSelector + "\n    display_name: Existing\n"
			recipients := `{z: {id: "` + strings.Repeat("07", 32) + `", display_name: Existing, encryption_key: ` + sourceEncryptionSelector + `}}`
			if layout == "flow-trailing" {
				recipients = strings.TrimSuffix(recipients, "}") + ",}"
			}
			editable := strings.Replace(sourceSetupYAML, "recipients: {}", "recipients: "+recipients, 1)
			if strings.HasPrefix(layout, "block-") {
				editable = strings.Replace(sourceSetupYAML, "recipients: {}\n", block, 1)
			}
			if layout == "block-eof" {
				editable = strings.Replace(sourceSetupYAML, "recipients: {}\n", "", 1) + block
			}
			editable = "generated: '" + reference + "'\n" + editable
			row := strings.Replace(preparationRecipientRow(), strings.Repeat("06", 32), strings.Repeat("07", 32), 1)
			generated := strings.Replace(sourceGeneratedJSON, `"recipients":{}`, `"recipients":{"z":`+row+`}`, 1)
			pair := captureEditableEmission(t, []byte(editable), []byte(generated), YAML, reference)
			before, err := Parse(t.Context(), pair)
			if err != nil || len(before.Recipients) != 1 {
				t.Fatal("recipient boundary fixture refused", err)
			}
			model, err := ParseForRecipientPreparation(t.Context(), pair, "alpha")
			if err != nil {
				t.Fatal(err)
			}
			edit, err := PrepareRecipientEdit(t.Context(), pair, model, "alpha", &RecipientDeclaration{EncryptionSelector: sourceEncryptionSelector}, preparationMaterial(t))
			if err != nil {
				t.Fatal(err)
			}
			var declaration, satellite bytes.Buffer
			if err := edit.EmitEditable(t.Context(), &declaration, reference); err != nil {
				t.Fatal(err)
			}
			if err := edit.EmitGenerated(t.Context(), &satellite); err != nil {
				t.Fatal(err)
			}
			const newBlockRow = "  alpha:\n    id: \"" + preparedSourceRecipientID + "\"\n    display_name: \"\"\n    encryption_key: " + sourceEncryptionSelector + "\n"
			want := ""
			if strings.HasPrefix(layout, "flow") {
				existing := "recipients: \n  z:\n    id: \"" + strings.Repeat("07", 32) + "\"\n    display_name: Existing\n    encryption_key: " + sourceEncryptionSelector + "\n"
				want = strings.Replace(editable, "recipients: "+recipients, existing+strings.TrimSuffix(newBlockRow, "\n"), 1)
			} else if layout == "block-eof" {
				want = editable + newBlockRow
			} else {
				want = strings.Replace(editable, "entries: {}", newBlockRow+"entries: {}", 1)
			}
			if declaration.String() != want {
				t.Errorf("recipient insertion bytes differ: got %q want %q", declaration.String(), want)
			}
			after, err := Parse(t.Context(), captureEditableEmission(t, declaration.Bytes(), satellite.Bytes(), YAML, reference))
			if err != nil || len(after.Recipients) != 2 || len(after.Entries) != len(before.Entries) || len(after.Outputs) != len(before.Outputs) || len(after.Routes) != len(before.Routes) {
				t.Fatal("recipient insertion candidate refused or unrelated set changed", err)
			}
			if after.Recipients[0].Reference != "alpha" || after.Recipients[1].Reference != "z" || after.Recipients[1].DisplayName != before.Recipients[0].DisplayName || after.Recipients[1].ID != before.Recipients[0].ID {
				t.Fatal("recipient insertion changed existing identity/display meaning")
			}
			if !bytes.Contains(satellite.Bytes(), []byte(row)) || !bytes.Equal(maintenanceImageBytes(t, pair.Editable), []byte(editable)) {
				t.Fatal("recipient insertion changed old generated row or source")
			}
		})
	}
}

// full_only: false
func TestRecipientDeclarationPreservesTrailingBlankLines(t *testing.T) {
	const reference = ".enkv/prod.generated.json"
	const newRow = "  alpha:\n    id: \"" + preparedSourceRecipientID + "\"\n    display_name: \"\"\n    encryption_key: " + sourceEncryptionSelector + "\n"
	for _, tc := range []struct {
		name, blanks, lineBreak string
		eof                     bool
	}{
		{"before-section", "\n", "\n", false},
		{"crlf-eof", "\n\n", "\r\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			block := "recipients:\n  z:\n    id: \"" + strings.Repeat("07", 32) + "\"\n    encryption_key: " + sourceEncryptionSelector + "\n    display_name: Existing\n" + tc.blanks
			editable := strings.Replace(sourceSetupYAML, "recipients: {}\n", block+"# retained entries comment\n", 1)
			if tc.eof {
				editable = strings.Replace(sourceSetupYAML, "recipients: {}\n", "", 1) + block
			}
			editable = strings.ReplaceAll("generated: '"+reference+"'\n"+editable, "\n", tc.lineBreak)
			want := strings.Replace(editable, "display_name: Existing"+tc.lineBreak, "display_name: Existing"+tc.lineBreak+newRow, 1)
			row := strings.Replace(preparationRecipientRow(), strings.Repeat("06", 32), strings.Repeat("07", 32), 1)
			generated := strings.Replace(sourceGeneratedJSON, `"recipients":{}`, `"recipients":{"z":`+row+`}`, 1)
			pair := captureEditableEmission(t, []byte(editable), []byte(generated), YAML, reference)
			before, err := Parse(t.Context(), pair)
			if err != nil || len(before.Recipients) != 1 || before.Recipients[0].DisplayName != "Existing" {
				t.Fatal("trailing-blank fixture meaning differs", err)
			}
			model, err := ParseForRecipientPreparation(t.Context(), pair, "alpha")
			if err != nil {
				t.Fatal(err)
			}
			edit, err := PrepareRecipientEdit(t.Context(), pair, model, "alpha", &RecipientDeclaration{EncryptionSelector: sourceEncryptionSelector}, preparationMaterial(t))
			if err != nil {
				t.Fatal(err)
			}
			var declaration, satellite bytes.Buffer
			if err := edit.EmitEditable(t.Context(), &declaration, reference); err != nil {
				t.Fatal(err)
			}
			if err := edit.EmitGenerated(t.Context(), &satellite); err != nil {
				t.Fatal(err)
			}
			if declaration.String() != want {
				t.Errorf("declaration bytes %q, want %q", declaration.String(), want)
			}
			after, err := Parse(t.Context(), captureEditableEmission(t, declaration.Bytes(), satellite.Bytes(), YAML, reference))
			if err != nil {
				t.Fatal(err)
			}
			if len(after.Recipients) != 2 || after.Recipients[0].Reference != "alpha" || after.Recipients[0].DisplayName != "" || after.Recipients[0].ID != preparationMaterial(t).RecipientID || after.Recipients[1].Reference != "z" || after.Recipients[1].DisplayName != "Existing" || after.Recipients[1].ID != before.Recipients[0].ID || len(after.Entries) != 0 {
				t.Fatal("declaration changed complete recipient or entry set")
			}
			if !bytes.Contains(satellite.Bytes(), []byte(row)) || !bytes.Equal(maintenanceImageBytes(t, pair.Editable), []byte(editable)) {
				t.Fatal("declaration changed existing row or predecessor")
			}
		})
	}
}

// full_only: false
func TestNewRecipientDeclarationUsesReadableLayout(t *testing.T) {
	for _, format := range []Format{YAML, JSON} {
		t.Run(fmt.Sprint(format), func(t *testing.T) {
			editable := sourceSetupYAML
			if format == JSON {
				editable = sourceSetupJSON
			}
			pair := writePair(t, editable, sourceGeneratedJSON, format)
			model, err := ParseForRecipientPreparation(t.Context(), pair, "new")
			if err != nil {
				t.Fatal(err)
			}
			edit, err := PrepareRecipientEdit(t.Context(), pair, model, "new", &RecipientDeclaration{DisplayName: "new", EncryptionSelector: sourceEncryptionSelector}, preparationMaterial(t))
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := edit.EmitEditable(t.Context(), &out, model.Generated); err != nil {
				t.Fatal(err)
			}
			want := "recipients: \n  new:\n    id: \"" + preparedSourceRecipientID + "\"\n    display_name: new\n    encryption_key: " + sourceEncryptionSelector
			if format == JSON {
				want = "\"recipients\":{\n    \"new\": {\n      \"id\": \"" + preparedSourceRecipientID + "\",\n      \"display_name\": \"new\",\n      \"encryption_key\": \"" + sourceEncryptionSelector + "\"\n    }\n  }"
			}
			if !strings.Contains(out.String(), want) {
				t.Fatalf("new recipient layout differs:\n%s", out.String())
			}
		})
	}
}

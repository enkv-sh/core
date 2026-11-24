package configuration

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func acceptedWorkSource(format Format, recipients, entries string) string {
	editable := preparationEditable(format, recipients)
	if format == JSON {
		return strings.Replace(editable, `"entries":{}`, `"entries":`+entries, 1)
	}
	return strings.Replace(editable, "entries: {}", "entries: "+entries, 1)
}

// full_only: false
func TestAcceptedWorkParseAllowsUnpreparedDraftsAndPreservesSource(t *testing.T) {
	const draftSecret = `{"draft":{"confidentiality":"secret","recipients":[],"source":{"kind":"supplied"}}}`
	const draftRecipient = `{"draft":{"display_name":"Draft","encryption_key":"` + sourceEncryptionSelector + `"}}`
	const draftGenerated = `"generated-draft":{"confidentiality":"secret","recipients":[],"source":{"kind":"generated","plugin":"unavailable-draft","epoch":0,"retirement":"manual","settings":{}}}`
	const outputs = `{"destinations":{"archive":{"plugin":"unavailable-output","settings":{}}},"routing":{}}`
	for _, format := range []Format{JSON, YAML} {
		for _, pending := range []string{"secret", "recipient", "both"} {
			t.Run(fmt.Sprint(format)+"/"+pending, func(t *testing.T) {
				entries, recipients := "{}", "{}"
				if pending != "recipient" {
					entries = draftSecret
				}
				if entries == "{}" {
					entries = "{" + draftGenerated + "}"
				} else {
					entries = strings.TrimSuffix(entries, "}") + "," + draftGenerated + "}"
				}
				if pending != "secret" {
					recipients = draftRecipient
				}
				editable := sourceWithPlugins(acceptedWorkSource(format, recipients, entries), format, `{"unavailable-draft":{"version":"1.2.3"}}`)
				if format == JSON {
					editable = strings.Replace(editable, `"outputs":{"destinations":{},"routing":{}}`, `"outputs":`+outputs, 1)
				} else {
					editable = strings.Replace(editable, "outputs:\n  destinations: {}\n  routing: {}", "outputs: "+outputs, 1)
				}
				pair := writePair(t, editable, sourceGeneratedJSON, format)
				beforeEditable, beforeGenerated := maintenanceImageBytes(t, pair.Editable), maintenanceImageBytes(t, pair.Generated)
				if _, err := Parse(t.Context(), pair); err == nil {
					t.Fatal("fresh parse admitted an unprepared proposal")
				}
				m, err := ParseForAcceptedWork(t.Context(), pair)
				if err != nil || m == nil || !m.Resolved || m.DomainID.IsZero() || m.Authority.Signing.Selector != sourceSigningSelector || m.Authority.Encryption.Selector != sourceEncryptionSelector {
					t.Fatal("accepted work did not retain its exact trusted construction", err)
				}
				if len(m.Plugins) != 1 || m.Plugins[0].Name != "unavailable-draft" || m.Plugins[0].Version != "1.2.3" {
					t.Fatal("accepted parse lost local plugin requirements")
				}
				if len(m.Outputs) != 1 || m.Outputs[0].DestinationID != "archive" || m.Outputs[0].Plugin != "unavailable-output" || !bytes.Equal(m.Outputs[0].Settings, []byte("{}")) {
					t.Fatal("accepted parse lost local publication requirements")
				}
				if pending != "recipient" && (len(m.MissingInputs) != 1 || m.MissingInputs[0] != "draft") {
					t.Fatal("missing draft secret was not retained")
				}
				if pending != "secret" && (len(m.Recipients) != 1 || !m.Recipients[0].ID.IsZero() || !m.Recipients[0].Encryption.Binding.ID.IsZero()) {
					t.Fatal("draft recipient gained a prepared identity")
				}
				if !bytes.Equal(beforeEditable, maintenanceImageBytes(t, pair.Editable)) || !bytes.Equal(beforeGenerated, maintenanceImageBytes(t, pair.Generated)) {
					t.Fatal("accepted parse changed captured source bytes")
				}
			})
		}
	}
}

// full_only: false
func TestAcceptedWorkParseRetainsPreparedAndStructuralJoins(t *testing.T) {
	const preparedID = "0606060606060606060606060606060606060606060606060606060606060606"
	const recipientWithoutID = `{"draft":{"display_name":"Draft","encryption_key":"` + sourceEncryptionSelector + `"}}`
	const preparedRecipient = `{"draft":{"id":"` + preparedID + `","display_name":"Draft","encryption_key":"` + sourceEncryptionSelector + `"}}`
	for _, format := range []Format{JSON, YAML} {
		for _, condition := range []string{"prepared", "id-without-row", "row-without-id", "wrong-id", "wrong-selector", "malformed-secret", "sealed-context", "unknown-field"} {
			t.Run(fmt.Sprint(format)+"/"+condition, func(t *testing.T) {
				recipients, entries, generated := preparedRecipient, "{}", strings.Replace(sourceGeneratedJSON, `"recipients":{}`, `"recipients":{"draft":`+preparationRecipientRow()+`}`, 1)
				switch condition {
				case "id-without-row":
					generated = sourceGeneratedJSON
				case "row-without-id":
					recipients = recipientWithoutID
				case "wrong-id":
					recipients = strings.Replace(recipients, preparedID, sourceID4, 1)
				case "wrong-selector":
					recipients = strings.Replace(recipients, sourceEncryptionSelector, sourceSigningSelector, 1)
				case "malformed-secret", "sealed-context":
					entries = `{"secret":{"confidentiality":"secret","recipients":[],"source":{"kind":"supplied"}}}`
					sealed := "AQ=="
					if condition == "sealed-context" {
						sealed = base64.StdEncoding.EncodeToString(sourceEditEnvelope(t, "other"))
					}
					generated = strings.Replace(generated, `"secrets":{}`, `"secrets":{"secret":{"sealed":"`+sealed+`"}}`, 1)
				case "unknown-field":
					entries = `{"draft":{"confidentiality":"secret","recipients":[],"source":{"kind":"supplied","extra":true}}}`
				}
				pair := captureRecipientIdentityImages(t, acceptedWorkSource(format, recipients, entries), generated, format)
				beforeEditable, beforeGenerated := maintenanceImageBytes(t, pair.Editable), maintenanceImageBytes(t, pair.Generated)
				model, err := ParseForAcceptedWork(t.Context(), pair)
				if condition == "prepared" {
					fresh, freshErr := Parse(t.Context(), pair)
					if err != nil || freshErr != nil || model == nil || !reflect.DeepEqual(model.Public, fresh.Public) {
						t.Fatal("accepted parse changed prepared public facts", err, freshErr)
					}
				} else if err == nil || model != nil {
					t.Fatal("accepted parse ignored a present or structural conflict")
				}
				if !bytes.Equal(beforeEditable, maintenanceImageBytes(t, pair.Editable)) || !bytes.Equal(beforeGenerated, maintenanceImageBytes(t, pair.Generated)) {
					t.Fatal("refused parse changed source bytes")
				}
			})
		}
	}
}

// full_only: false
func TestAcceptedWorkParseRequiresCapturedResolvedCompanion(t *testing.T) {
	pair := writePair(t, sourceSetupJSON, "", JSON)
	if m, err := ParseForAcceptedWork(t.Context(), pair); err == nil || m != nil {
		t.Fatal("accepted work admitted a companion-free source")
	}
	resolved := writePair(t, sourceSetupJSON, sourceGeneratedJSON, JSON)
	var absentContext context.Context
	if m, err := ParseForAcceptedWork(absentContext, resolved); err == nil || m != nil {
		t.Fatal("accepted work admitted a nil context")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if m, err := ParseForAcceptedWork(ctx, resolved); err == nil || m != nil {
		t.Fatal("accepted work admitted cancelled input")
	}
}

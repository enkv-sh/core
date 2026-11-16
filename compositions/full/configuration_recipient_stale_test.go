package compositionfull

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
)

// full_only: false
func TestRecipientStalePreparationRequiresFreshCreationWithoutSealedRetarget(t *testing.T) {
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		for _, condition := range []string{"current-refused", "fresh-create", "sealed-preserved"} {
			t.Run(fmt.Sprintf("%d/%s", format, condition), func(t *testing.T) {
				var oldID contract.ID
				oldSnapshot := contract.ID(sha256.Sum256([]byte("previous selected snapshot")))
				oldNonce := contract.ID(sha256.Sum256([]byte("previous creation nonce")))
				var public []byte
				var protection uint8
				source := configurationReaderPair(t, "aws", format, func(editable, generated map[string]any) {
					rows := editable["recipients"].(map[string]any)
					prepared := generated["recipients"].(map[string]any)
					var sample map[string]any
					var sampleKey map[string]any
					for reference, value := range rows {
						sample = value.(map[string]any)
						sampleKey = prepared[reference].(map[string]any)["encryption"].(map[string]any)
						break
					}
					domain := preparationLiteralID(t, generated["domain"].(map[string]any)["id"].(string))
					preimage := append([]byte("ENKV/recipient-creation/v1\x00"), domain[:]...)
					preimage = append(preimage, oldSnapshot[:]...)
					preimage = append(preimage, oldNonce[:]...)
					oldID = contract.ID(sha256.Sum256(preimage))
					bindingInput := append(append([]byte("ENKV/recipient-initial-binding/v1\x00"), domain[:]...), oldID[:]...)
					incarnationInput := append(append([]byte("ENKV/recipient-initial-incarnation/v1\x00"), domain[:]...), oldID[:]...)
					binding, incarnation := contract.ID(sha256.Sum256(bindingInput)), contract.ID(sha256.Sum256(incarnationInput))
					public = bytes.Clone(sampleKey["public_key"].([]byte))
					protectionName := sampleKey["binding"].(map[string]any)["protection"].(string)
					protection = contract.HardwareProtection
					if protectionName == "software" {
						protection = contract.SoftwareProtection
					}
					rows["pending-reader"] = map[string]any{"id": readerID(oldID), "display_name": sample["display_name"], "encryption_key": sample["encryption_key"]}
					prepared["pending-reader"] = map[string]any{"id": readerID(oldID), "creation": map[string]string{"snapshot": readerID(oldSnapshot), "nonce": readerID(oldNonce)},
						"encryption": map[string]any{"selector": sample["encryption_key"], "public_key": public, "binding": map[string]any{"id": readerID(binding), "incarnation": readerID(incarnation), "serial": uint64(1), "protection": protectionName}}}
					entry := editable["entries"].(map[string]any)["secret"].(map[string]any)
					entry["recipients"] = append(entry["recipients"].([]string), "pending-reader")
				})
				configurationSetWritable(t, source)
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				if condition == "sealed-preserved" {
					if _, err := SetConfiguration(ctx, source.path, format, "secret", io.NopCloser(strings.NewReader("private stale binding fixture")), SetOptions{Confidential: true}); err != nil {
						t.Fatal("stale-bound sealed fixture could not be prepared", err)
					}
				}
				beforeEditable, err := os.ReadFile(source.path)
				if err != nil {
					t.Fatal(err)
				}
				beforeEntry := configurationSetEntry(t, configurationSetModel(t, source.path, format), "secret")
				beforeGenerated, err := os.ReadFile(source.generated)
				if err != nil {
					t.Fatal(err)
				}
				h := &readerHTTPFixture{archive: source.archive, reads: map[string]int{}}
				opens, lookups := 0, 0
				open := configurationReaderOpener(t, source, h, &opens)
				resolve := func(context.Context, *configuration.Model, string) ([]byte, uint8, error) {
					lookups++
					return bytes.Clone(public), protection, nil
				}
				mode := RecipientPreparationCreate
				if condition == "current-refused" {
					mode = RecipientPreparationCurrent
				}
				result, err := prepareConfigurationRecipient(ctx, source.path, format, "pending-reader", RecipientPreparationOptions{Mode: mode}, open, resolve, bytes.NewReader(bytes.Repeat([]byte{0x66}, 32)))
				if condition != "current-refused" {
					if err != nil || LocalEditExitCode(result, err) != 0 {
						t.Fatal("explicit creation could not replace stale absent preparation", err)
					}
					after := configurationSetModel(t, source.path, format)
					found := false
					for _, row := range after.Recipients {
						if row.Reference == "pending-reader" {
							found = true
							if row.ID == oldID || row.Creation == nil || row.Creation.Snapshot == oldSnapshot || row.Creation.Nonce == oldNonce {
								t.Fatal("fresh creation retained stale identity or proof")
							}
						}
					}
					if !found {
						t.Fatal("fresh creation removed the selected reference")
					}
					if condition == "sealed-preserved" {
						afterEntry := configurationSetEntry(t, after, "secret")
						old, oldErr := contract.InspectSealedInputEnvelope(beforeEntry.Sealed)
						preserved, preservedErr := contract.InspectSealedInputEnvelope(afterEntry.Sealed)
						exactEnvelope := bytes.Equal(beforeEntry.Sealed, afterEntry.Sealed)
						exactContext := old.Core.SealedInputCoreFields == preserved.Core.SealedInputCoreFields && bytes.Equal(old.Core.Name, preserved.Core.Name)
						t.Logf("fresh preparation: selected_reference_present=%t envelope_exact=%t context_exact=%t parse_failed=%t", found, exactEnvelope, exactContext, oldErr != nil || preservedErr != nil)
						if oldErr != nil || preservedErr != nil || !exactEnvelope || !exactContext || !slices.Equal(beforeEntry.Recipients, afterEntry.Recipients) {
							t.Fatal("fresh creation retargeted the old sealed envelope")
						}
						if _, err := SetConfiguration(ctx, source.path, format, "secret", io.NopCloser(strings.NewReader("private new binding fixture")), SetOptions{Confidential: true}); err != nil {
							t.Fatal("set could not replace input after fresh binding preparation", err)
						}
						repaired := configurationSetEntry(t, configurationSetModel(t, source.path, format), "secret")
						current, currentErr := contract.InspectSealedInputEnvelope(repaired.Sealed)
						t.Logf("explicit set: new_envelope=%t new_binding_digest=%t parse_failed=%t", !bytes.Equal(repaired.Sealed, beforeEntry.Sealed), current.Core.IntendedRecipientBindingSetDigest != old.Core.IntendedRecipientBindingSetDigest, currentErr != nil)
						if currentErr != nil || bytes.Equal(repaired.Sealed, beforeEntry.Sealed) || current.Core.IntendedRecipientBindingSetDigest == old.Core.IntendedRecipientBindingSetDigest || current.Core.DomainID != old.Core.DomainID || current.Core.FileIdentity != old.Core.FileIdentity || !bytes.Equal(current.Core.Name, old.Core.Name) {
							t.Fatal("set did not create a new sealed target for the prepared bindings")
						}
					}
				} else {
					if err == nil || LocalEditExitCode(result, err) != 2 {
						t.Fatal("stale absent identity was resolved as current")
					}
					for path, want := range map[string][]byte{source.path: beforeEditable, source.generated: beforeGenerated} {
						body, readErr := os.ReadFile(path)
						if readErr != nil || !bytes.Equal(body, want) {
							t.Fatal("refusal changed source or sealed bytes", readErr)
						}
					}
				}
				wantLookups := 1
				if condition == "current-refused" {
					wantLookups = 0
				}
				if opens != 1 || lookups != wantLookups {
					t.Fatal("stale preparation bypassed exact current authentication", opens, lookups)
				}
				h.assertNoEffects(t)
			})
		}
	}
}

package compositionfull

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
)

// full_only: false
func TestRecipientCurrentRefreshUsesExactIDAndAuthenticatedBinding(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		for _, condition := range []string{"stale-cache", "sealed-current", "stale-sealed", "absent-id", "create-current", "wrong-selector", "wrong-public", "lookup-failure", "selection-failure"} {
			t.Run(family+"/"+condition, func(t *testing.T) {
				t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
				t.Setenv("EXPERIMENTAL_GOOGLE_API_USE_S2A", "false")
				var reference string
				var current contract.KMSBinding
				source := configurationReaderPair(t, family, configuration.JSON, func(editable, generated map[string]any) {
					recipients := generated["recipients"].(map[string]any)
					var references []string
					for key := range recipients {
						references = append(references, key)
					}
					sort.Strings(references)
					reference = references[0]
					row := recipients[reference].(map[string]any)
					basis, err := contract.DecodeGenesisDescriptorCore(generated["public_basis"].(map[string]any)["descriptor"].([]byte))
					if err != nil {
						t.Fatal(err)
					}
					for _, recipient := range basis.Recipients {
						if readerID(recipient.RecipientID) == row["id"] {
							current = *recipient.CurrentBinding
						}
					}
					switch condition {
					case "stale-cache", "stale-sealed":
						binding := row["encryption"].(map[string]any)["binding"].(map[string]any)
						binding["id"], binding["incarnation"] = readerID(contract.Hash([]byte("old binding"))), readerID(contract.Hash([]byte("old incarnation")))
					case "absent-id":
						row["id"] = readerID(contract.Hash([]byte("absent recipient")))
						editable["recipients"].(map[string]any)[reference].(map[string]any)["id"] = row["id"]
					case "wrong-selector":
						selector := "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555"
						if family == "gcp" {
							selector = "projects/another-project/locations/us-central1/keyRings/another-ring/cryptoKeys/another-key/cryptoKeyVersions/1"
						}
						editable["recipients"].(map[string]any)[reference].(map[string]any)["encryption_key"] = selector
					}
					if condition == "stale-sealed" || condition == "sealed-current" {
						entry := editable["entries"].(map[string]any)["secret"].(map[string]any)
						members := entry["recipients"].([]string)
						if !slices.Contains(members, reference) {
							entry["recipients"] = append(members, reference)
						}
					}
				})
				configurationSetWritable(t, source)
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				var beforeSealed []byte
				if condition == "stale-sealed" || condition == "sealed-current" {
					if _, err := SetConfiguration(ctx, source.path, configuration.JSON, "secret", io.NopCloser(strings.NewReader("private old binding fixture")), SetOptions{Confidential: true}); err != nil {
						t.Fatal("old binding fixture could not be sealed", err)
					}
					var err error
					source.editableBytes, err = os.ReadFile(source.path)
					if err != nil {
						t.Fatal(err)
					}
					beforeSealed = configurationSetEntry(t, configurationSetModel(t, source.path, configuration.JSON), "secret").Sealed
					source.generatedBytes, err = os.ReadFile(source.generated)
					if err != nil {
						t.Fatal(err)
					}
				}
				h := &readerHTTPFixture{archive: source.archive, reads: map[string]int{}, unavailable: condition == "selection-failure"}
				opens, lookups := 0, 0
				open := configurationReaderOpener(t, source, h, &opens)
				resolve := func(context.Context, *configuration.Model, string) ([]byte, uint8, error) {
					lookups++
					if condition == "lookup-failure" {
						return nil, 0, errors.New("private-lookup-error-sentinel")
					}
					if condition == "wrong-public" {
						return []byte("not-the-current-public-key"), current.ProtectionClass, nil
					}
					return bytes.Clone(current.SPKI), current.ProtectionClass, nil
				}
				mode := RecipientPreparationCurrent
				if condition == "create-current" {
					mode = RecipientPreparationCreate
				}
				result, err := prepareConfigurationRecipient(ctx, source.path, configuration.JSON, reference, RecipientPreparationOptions{Mode: mode}, open, resolve, bytes.NewReader(bytes.Repeat([]byte{7}, 32)))
				if condition == "stale-cache" || condition == "sealed-current" || condition == "stale-sealed" {
					if err != nil || LocalEditExitCode(result, err) != 0 {
						t.Fatal("exact current binding could not refresh stale public cache", err)
					}
					after := configurationSetModel(t, source.path, configuration.JSON)
					for _, row := range after.Recipients {
						if row.Reference == reference && !setBindingEqual(setSourceBinding(after.Provider, row.Encryption, row.Selector), current) {
							t.Fatal("refresh installed a binding other than exact authenticated current")
						}
					}
					if (condition == "sealed-current" || condition == "stale-sealed") && !bytes.Equal(beforeSealed, configurationSetEntry(t, after, "secret").Sealed) {
						t.Fatal("current public refresh rewrote sealed input")
					}
				} else {
					if err == nil || LocalEditExitCode(result, err) != 2 {
						t.Fatal("unqualified binding or identity was admitted")
					}
					source.assertUnchanged(t)
				}
				wantLookups := 0
				if condition == "stale-cache" || condition == "sealed-current" || condition == "stale-sealed" || condition == "wrong-public" || condition == "lookup-failure" {
					wantLookups = 1
				}
				if opens != 1 || lookups != wantLookups {
					t.Fatal("public lookup preceded authenticated identity/binding admission", opens, lookups)
				}
				body, renderErr := RenderLocalEditJSON(result, err)
				if renderErr != nil || bytes.Contains(body, []byte("private-lookup-error-sentinel")) || bytes.Contains(body, current.SPKI) {
					t.Fatal("local result exposed provider data", renderErr)
				}
				h.assertNoEffects(t)
			})
		}
	}
}

// full_only: false
func TestRecipientDeclarationAndMissingPreparationBoundaries(t *testing.T) {
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		for _, declaration := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/declaration-%t", format, declaration), func(t *testing.T) {
				var reference string
				var expected configuration.Recipient
				expectedMemberships := map[string][]string{}
				source := configurationReaderPair(t, "aws", format, func(editable, generated map[string]any) {
					rows := editable["recipients"].(map[string]any)
					var references []string
					for key := range rows {
						references = append(references, key)
					}
					sort.Strings(references)
					reference = references[0]
					row := rows[reference].(map[string]any)
					expected = configuration.Recipient{Reference: reference, Selector: row["encryption_key"].(string), DisplayName: ""}
					generatedRow := generated["recipients"].(map[string]any)[reference].(map[string]any)
					key := generatedRow["encryption"].(map[string]any)
					expected.Encryption.PublicKey = key["public_key"].([]byte)
					expected.Encryption.Binding.Protection = contract.HardwareProtection
					if key["binding"].(map[string]any)["protection"] == "software" {
						expected.Encryption.Binding.Protection = contract.SoftwareProtection
					}
					delete(generated["recipients"].(map[string]any), reference)
					if declaration {
						delete(rows, reference)
						// Remove membership references while preserving shared routes.
						for _, entry := range editable["entries"].(map[string]any) {
							members := entry.(map[string]any)["recipients"].([]string)
							kept := make([]string, 0, len(members))
							for _, member := range members {
								if member != reference {
									kept = append(kept, member)
								}
							}
							entry.(map[string]any)["recipients"] = kept
						}
					} else {
						delete(row, "id")
					}
					for name, entry := range editable["entries"].(map[string]any) {
						expectedMemberships[name] = slices.Clone(entry.(map[string]any)["recipients"].([]string))
					}
				})
				configurationSetWritable(t, source)
				h := &readerHTTPFixture{archive: source.archive, reads: map[string]int{}}
				opens, lookups := 0, 0
				open := configurationReaderOpener(t, source, h, &opens)
				resolve := func(context.Context, *configuration.Model, string) ([]byte, uint8, error) {
					lookups++
					return bytes.Clone(expected.Encryption.PublicKey), expected.Encryption.Binding.Protection, nil
				}
				options := RecipientPreparationOptions{Mode: RecipientPreparationCreate}
				if declaration {
					options.Declaration = &configuration.RecipientDeclaration{DisplayName: "", EncryptionSelector: expected.Selector}
				}
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				result, err := prepareConfigurationRecipient(ctx, source.path, format, reference, options, open, resolve, bytes.NewReader(bytes.Repeat([]byte{5}, 32)))
				if err != nil || LocalEditExitCode(result, err) != 0 || opens != 1 || lookups != 1 {
					t.Fatal("explicit fresh preparation refused missing selected facts", err, opens, lookups)
				}
				after := configurationSetModel(t, source.path, format)
				found := false
				for _, row := range after.Recipients {
					if row.Reference == reference {
						found = row.Creation != nil && row.Selector == expected.Selector && (!declaration || row.DisplayName == "")
					}
				}
				if !found {
					t.Fatal("new reference lost declaration or creation material")
				}
				if len(after.Entries) != len(expectedMemberships) {
					t.Fatal("preparation changed the entry set")
				}
				for _, entry := range after.Entries {
					if !slices.Equal(entry.Recipients, expectedMemberships[entry.Name]) {
						t.Fatal("preparation changed requested memberships")
					}
				}
				h.assertNoEffects(t)
			})
		}
	}
}

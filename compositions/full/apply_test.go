package compositionfull

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
)

func configurationApplyPair(t *testing.T, family string, format configuration.Format, edit func(map[string]any, map[string]any)) configurationReaderSource {
	t.Helper()
	// This current-compatible public basis reuses fixture public keys only.
	// No signed archive is changed and no selected-state success is claimed.
	return configurationSetPair(t, family, format, func(editable, generated map[string]any) {
		editable["outputs"] = map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}}
		delete(generated, "canonical_records")
		if edit != nil {
			edit(editable, generated)
		}
	})
}

type configurationApplyFileImage struct {
	Mode fs.FileMode
	Body []byte
}

func configurationApplySourceImage(t testing.TB, directory string) map[string]configurationApplyFileImage {
	t.Helper()
	image := map[string]configurationApplyFileImage{}
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return errors.New("source fixture is not a regular tree")
		}
		relative, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		row := configurationApplyFileImage{Mode: info.Mode()}
		if info.Mode().IsRegular() {
			row.Body, err = os.ReadFile(path)
		}
		image[relative] = row
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return image
}

func configurationApplyAssertUnchanged(t testing.TB, directory string, before map[string]configurationApplyFileImage) {
	t.Helper()
	if !reflect.DeepEqual(before, configurationApplySourceImage(t, directory)) {
		t.Fatal("apply changed source bytes, modes or local file inventory")
	}
}

func configurationApplyAssertUnavailable(t testing.TB, result core.PublicApplyResult) {
	t.Helper()
	if result.Result.Outcome != core.EvidenceUnavailable || result.Result.Reason != core.CustodyUnavailable || result.Payload != nil || len(result.Receipt) != 0 || result.Result.CommitMayHaveOccurred || result.OperationID.IsZero() || !result.RequestIdentity.IsZero() {
		t.Fatal("construction-only control claimed an admitted apply or receipt")
	}
	if result.PreAdmission == nil || result.PreAdmission.Stage != "construction" || result.PreAdmission.Code != "evidence-unavailable" {
		t.Fatal("construction failure lost its exact pre-admission stage or code")
	}
}

// full_only: false
func TestConfigurationApplyCompleteSuppliedMappingBeforeOpen(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
			t.Run(fmt.Sprintf("%s/%d", family, format), func(t *testing.T) {
				source := configurationApplyPair(t, family, format, nil)
				if err := source.pair.Close(); err != nil {
					t.Fatal(err)
				}
				configurationSetWritable(t, source)
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				plain := []byte{0, 255, 10, 65}
				input := &configurationSetInput{Reader: bytes.NewReader(plain)}
				sealed, err := SetConfiguration(ctx, source.path, format, "sealed", input, SetOptions{Confidential: true})
				if err != nil || sealed == nil || sealed.StateResult != SetSuccess || input.closes != 1 {
					t.Fatal("real local sealed proposal unavailable", err)
				}
				for _, path := range []string{source.path, sealed.GeneratedPath} {
					if os.Chmod(path, 0444) != nil {
						t.Fatal("read-only source fixture unavailable")
					}
				}
				for _, path := range []string{filepath.Dir(source.path), filepath.Dir(sealed.GeneratedPath)} {
					if os.Chmod(path, 0555) != nil {
						t.Fatal("read-only source fixture unavailable")
					}
				}
				pair, err := configuration.Capture(ctx, source.path, format)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := pair.Close(); err != nil {
						t.Error(err)
					}
				}()
				model, err := configuration.Parse(ctx, pair)
				if err != nil {
					t.Fatal(err)
				}
				installation, entries, err := configurationApplyInput(model)
				if err != nil {
					t.Fatal("valid supplied mapping refused", err)
				}
				basis, err := contract.DecodeGenesisDescriptorCore(model.Basis.Descriptor)
				if err != nil {
					t.Fatal(err)
				}
				if installation.ExpectedDomain != basis.DomainID || installation.FileIdentity != contract.Hash([]byte("Reader file fixture")) || installation.CompositionID != CompatibilityManifest().Identity || installation.Store != nil || installation.Trust != nil || installation.AdmitCustody != nil || len(entries) != 5 || len(installation.DesiredRecipients) != len(basis.Recipients) {
					t.Fatal("pure source mapping invented capabilities or lost complete input")
				}
				wantRegistry := slices.Clone(basis.Recipients)
				slices.SortFunc(wantRegistry, func(a, b contract.RecipientRecord) int { return bytes.Compare(a.RecipientID[:], b.RecipientID[:]) })
				gotRegistry := make([]contract.RecipientRecord, len(installation.DesiredRecipients))
				for i, row := range installation.DesiredRecipients {
					gotRegistry[i] = row.Recipient
				}
				slices.SortFunc(gotRegistry, func(a, b contract.RecipientRecord) int { return bytes.Compare(a.RecipientID[:], b.RecipientID[:]) })
				for i, want := range wantRegistry {
					wantBody, err := contract.EncodeRecipientRecord(want)
					if err != nil {
						t.Fatal(err)
					}
					gotBody, err := contract.EncodeRecipientRecord(gotRegistry[i])
					if err != nil || !bytes.Equal(gotBody, wantBody) {
						t.Fatal("complete registry mapping differs", err)
					}
				}
				members := []contract.ID{basis.AuthorityRecipientID, readerFixtureTarget(basis.DomainID)}
				slices.SortFunc(members, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
				for i, entry := range entries {
					if entry.ValueSource != contract.Supplied || i > 0 && entries[i-1].Name >= entry.Name {
						t.Fatal("supplied mapping order or source differs")
					}
					if entry.Name == "sealed" {
						parsed := configurationSetEntry(t, model, "sealed")
						view, err := contract.InspectSealedInputEnvelope(entry.InputBytes)
						if err != nil || !bytes.Equal(entry.InputBytes, parsed.Sealed) || entry.ConfidentialityClass != contract.Secret || entry.Retained != nil || !slices.Equal(entry.Recipients, []contract.ID{basis.AuthorityRecipientID}) || view.Core.ContentLength != uint32(len(plain)) {
							t.Fatal("sealed supplied bytes or recipient mapping differs", err)
						}
						continue
					}
					if !slices.Equal(entry.Recipients, members) {
						t.Fatal("declared membership mapping differs")
					}
					switch entry.Name {
					case "", "a/\n雪":
						want := []byte{}
						if entry.Name != "" {
							want = []byte{0, 10, 65}
						}
						if entry.ConfidentialityClass != contract.Plain || entry.Retained != nil || !bytes.Equal(entry.InputBytes, want) {
							t.Fatal("plain binary/empty mapping differs")
						}
					case "encoded", "secret":
						if entry.ConfidentialityClass != contract.Secret || len(entry.InputBytes) != 0 || entry.Retained == nil || entry.Retained.Incarnation != contract.Hash([]byte("fixture incarnation "+entry.Name)) || entry.Retained.Material != contract.Hash([]byte("fixture material "+entry.Name)) {
							t.Fatal("retained pin mapping differs")
						}
					default:
						t.Fatal("unexpected source entry")
					}
				}
				before := configurationApplySourceImage(t, filepath.Dir(source.path))
				calls := 0
				request := contract.Hash([]byte("source mapping construction control"))
				result := applyConfiguration(ctx, request, pair, func(_ context.Context, opened *configuration.Model, installed core.ApplyInstallation, _ *configurationInstalledPlugins) (*core.InstalledApply, error) {
					calls++
					if opened.FileID != model.FileID || installed.ExpectedDomain != installation.ExpectedDomain || len(installed.DesiredRecipients) != len(wantRegistry) {
						t.Fatal("opener received another source installation")
					}
					return nil, errors.New("bounded construction control")
				})
				if calls != 1 || result.RequestID != request {
					t.Fatal("complete source did not reach exactly one construction boundary")
				}
				configurationApplyAssertUnavailable(t, result)
				configurationApplyAssertUnchanged(t, filepath.Dir(source.path), before)
			})
		}
	}
}

// full_only: false
func TestConfigurationApplyPureRefusalsPrecedeOpen(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
			for _, condition := range []string{"missing-prepared", "malformed-prepared", "key-edit", "mode-edit"} {
				t.Run(fmt.Sprintf("%s/%d/%s", family, format, condition), func(t *testing.T) {
					source := configurationApplyPair(t, family, format, func(editable, generated map[string]any) {
						switch condition {
						case "missing-prepared":
							delete(generated["secrets"].(map[string]any), "secret")
						case "malformed-prepared":
							generated["secrets"].(map[string]any)["secret"] = map[string]any{"sealed": "AQ=="}
						case "key-edit":
							editable["domain"].(map[string]any)["authority"].(map[string]any)["signing_key"] = editable["domain"].(map[string]any)["authority"].(map[string]any)["encryption_key"]
						case "mode-edit":
							authority := editable["domain"].(map[string]any)["authority"].(map[string]any)
							editable["domain"].(map[string]any)["recovery"] = map[string]any{"enabled": true, "signing_key": authority["signing_key"], "encryption_key": authority["encryption_key"]}
							keys := generated["domain"].(map[string]any)["authority"].(map[string]any)
							generated["domain"].(map[string]any)["recovery"] = map[string]any{"enabled": true, "signing": keys["signing"], "encryption": keys["encryption"]}
						}
					})
					ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
					defer cancel()
					before := configurationApplySourceImage(t, filepath.Dir(source.path))
					calls := 0
					result := applyConfiguration(ctx, contract.Hash([]byte("source refusal")), source.pair, func(context.Context, *configuration.Model, core.ApplyInstallation, *configurationInstalledPlugins) (*core.InstalledApply, error) {
						calls++
						return nil, errors.New("must not construct")
					})
					if calls != 0 || result.Payload != nil || len(result.Receipt) != 0 || result.Result.CommitMayHaveOccurred || len(result.Diagnostics) == 0 {
						t.Fatal("pure source refusal reached construction or fabricated acceptance")
					}
					configurationApplyAssertUnchanged(t, filepath.Dir(source.path), before)
				})
			}
		}
	}
}

// full_only: false
func TestConfigurationApplyContextRefusesBeforeOpen(t *testing.T) {
	for _, condition := range []string{"cancelled", "expired", "no-deadline", "zero-request"} {
		t.Run(condition, func(t *testing.T) {
			source := configurationApplyPair(t, "aws", configuration.JSON, nil)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			request := contract.Hash([]byte("context refusal"))
			switch condition {
			case "cancelled":
				cancel()
			case "expired":
				var stop context.CancelFunc
				ctx, stop = context.WithDeadline(t.Context(), time.Unix(1, 0))
				defer stop()
			case "no-deadline":
				ctx = context.Background()
			case "zero-request":
				request = contract.ID{}
			}
			before := configurationApplySourceImage(t, filepath.Dir(source.path))
			calls := 0
			result := applyConfiguration(ctx, request, source.pair, func(context.Context, *configuration.Model, core.ApplyInstallation, *configurationInstalledPlugins) (*core.InstalledApply, error) {
				calls++
				return nil, errors.New("must not construct")
			})
			if calls != 0 || result.Payload != nil || len(result.Receipt) != 0 || result.Result.CommitMayHaveOccurred {
				t.Fatal("invalid invocation context reached construction")
			}
			configurationApplyAssertUnchanged(t, filepath.Dir(source.path), before)
		})
	}
}

// full_only: false
func TestConfigurationApplyRegistryMappingDoesNotInventOmittedRows(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			source := configurationApplyPair(t, family, configuration.JSON, func(editable, generated map[string]any) {
				editable["recipients"] = map[string]any{}
				for _, entry := range editable["entries"].(map[string]any) {
					entry.(map[string]any)["recipients"] = []string{}
				}
			})
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			before := configurationApplySourceImage(t, filepath.Dir(source.path))
			calls := 0
			result := applyConfiguration(ctx, contract.Hash([]byte("registry construction control")), source.pair, func(_ context.Context, model *configuration.Model, installed core.ApplyInstallation, _ *configurationInstalledPlugins) (*core.InstalledApply, error) {
				calls++
				if len(installed.DesiredRecipients) != 1 || installed.DesiredRecipients[0].Recipient.RecipientID != model.Authority.ID {
					t.Fatal("source omission silently restored a registry row")
				}
				return nil, errors.New("bounded construction control")
			})
			if calls != 1 {
				t.Fatal("source registry declaration did not reach public construction")
			}
			configurationApplyAssertUnavailable(t, result)
			configurationApplyAssertUnchanged(t, filepath.Dir(source.path), before)
			// Actual selected-registry comparison is owned by InstalledApply. It
			// must refuse mismatch before custody/private/write admission; this
			// construction-only test grants no authenticated selected-state fact.
		})
	}
}

// full_only: false
func TestConfigurationApplyForwardsCompleteRecipientAndPassiveIntent(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
			for _, condition := range []string{"creation", "display", "generated", "outputs"} {
				t.Run(fmt.Sprintf("%s/%d/%s", family, format, condition), func(t *testing.T) {
					snapshot, nonce := contract.Hash([]byte("prepared snapshot")), contract.Hash([]byte("prepared nonce"))
					source := configurationApplyPair(t, family, format, func(editable, generated map[string]any) {
						switch condition {
						case "creation":
							for _, row := range generated["recipients"].(map[string]any) {
								row.(map[string]any)["creation"] = map[string]any{"snapshot": readerID(snapshot), "nonce": readerID(nonce)}
							}
						case "display":
							editable["domain"].(map[string]any)["authority"].(map[string]any)["display_name"] = "Authority display proposal"
							for _, row := range editable["recipients"].(map[string]any) {
								row.(map[string]any)["display_name"] = "Recipient display proposal"
							}
						case "generated":
							editable["entries"].(map[string]any)["generated"] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": dependencyCanonicalGeneratorSource(generated, "generated", true)}
						case "outputs":
							editable["outputs"] = map[string]any{"destinations": map[string]any{"unused": dependencyCanonicalOutputSource(t, generated, "unused")}, "routing": map[string]any{}}
						}
					})
					ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
					defer cancel()
					before := configurationApplySourceImage(t, filepath.Dir(source.path))
					calls := 0
					result := applyConfiguration(ctx, contract.Hash([]byte("complete passive mapping")), source.pair, func(_ context.Context, model *configuration.Model, installed core.ApplyInstallation, _ *configurationInstalledPlugins) (*core.InstalledApply, error) {
						calls++
						if !reflect.DeepEqual(installed.PublicConfiguration, model.Public) || len(installed.DesiredRecipients) != len(model.Recipients)+1 {
							t.Fatal("complete source declaration was not forwarded")
						}
						for _, row := range installed.DesiredRecipients {
							if row.Recipient.RecipientID == model.Authority.ID {
								if row.Creation != nil || row.Recipient.DisplayName != model.Authority.DisplayName {
									t.Fatal("Authority metadata mapping differs")
								}
								continue
							}
							if condition == "creation" && (row.Creation == nil || row.Creation.Snapshot != snapshot || row.Creation.Nonce != nonce) {
								t.Fatal("recipient creation proof was lost")
							}
							if condition == "display" && row.Recipient.DisplayName != "Recipient display proposal" {
								t.Fatal("recipient display proposal was lost")
							}
						}
						if condition == "generated" {
							_, entries, err := configurationApplyInput(model)
							index := slices.IndexFunc(entries, func(row core.ApplyEntryInput) bool { return row.Name == "generated" })
							if err != nil || index < 0 || entries[index].ValueSource != contract.Generated || entries[index].ConfidentialityClass != contract.Secret || len(entries[index].InputBytes) != 0 || entries[index].Retained != nil {
								t.Fatal("generated proposal invented current payload or omitted intent", err)
							}
							declaration := entries[index].Generated
							if declaration == nil {
								t.Fatal("generated proposal omitted its complete declaration")
							}
							wanted := configurationSetEntry(t, model, "generated").Generated
							if declaration.Epoch != wanted.Epoch || declaration.RetirementMode != contract.GeneratedRetirementManual || !bytes.Equal(declaration.ConfigContractID[:], bytes.Repeat([]byte{0x45}, 32)) || !bytes.Equal(declaration.ResourceContractID[:], bytes.Repeat([]byte{0x46}, 32)) || declaration.LifecycleMode != contract.GeneratorLifecycleManaged || declaration.CompletionClass != contract.GeneratedCompletionAcknowledged || !bytes.Equal(declaration.Intent, wanted.Intent) {
								t.Fatal("generated declaration lost canonical settings, epoch, policy or contracts")
							}
						}
						return nil, errors.New("bounded construction control")
					})
					if calls != 1 {
						t.Fatal("complete proposal did not reach installed admission")
					}
					configurationApplyAssertUnavailable(t, result)
					configurationApplyAssertUnchanged(t, filepath.Dir(source.path), before)
				})
			}
		}
	}
}

// full_only: false
func TestConfigurationApplyRecipientQualificationHasOnlyAbsentPublicRoutes(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			ctx, aws, gcp := localConfigs(t)
			source := configurationApplyPair(t, family, configuration.JSON, nil)
			model, err := configuration.Parse(ctx, source.pair)
			if err != nil {
				t.Fatal(err)
			}
			installation, _, err := configurationApplyInput(model)
			if err != nil {
				t.Fatal(err)
			}
			config := Config{Family: model.Provider, AWS: &aws}
			if family == "gcp" {
				config.AWS, config.GCP = nil, &gcp
			}
			var current []contract.RecipientRecord
			for _, row := range installation.DesiredRecipients {
				if row.Recipient.RecipientID == model.Authority.ID {
					current = append(current, row.Recipient)
				}
			}
			public, err := configurationApplyPublicKeys(ctx, config, current, installation.DesiredRecipients)
			if err != nil || len(public) != len(installation.DesiredRecipients)-1 || public[model.Authority.ID] != nil {
				t.Fatal("absent recipient public route set differs", err)
			}
			for _, row := range installation.DesiredRecipients {
				if row.Recipient.RecipientID == model.Authority.ID {
					continue
				}
				qualifier := public[row.Recipient.RecipientID]
				if qualifier == nil || qualifier.Family() != model.Provider || qualifier.CredentialRoute().IsZero() {
					t.Fatal("new recipient has no exact public route")
				}
				if _, private := qualifier.(enkvcrypto.KeyAccess); private {
					t.Fatal("public qualification route acquired private reach")
				}
			}
			for _, row := range installation.DesiredRecipients {
				if row.Recipient.RecipientID != model.Authority.ID {
					current = append(current, row.Recipient)
				}
			}
			public, err = configurationApplyPublicKeys(ctx, config, current, installation.DesiredRecipients)
			if err != nil || len(public) != 0 || len(aws.KeyAccess) != 1 || len(gcp.KeyAccess) != 1 {
				t.Fatal("current recipient created another route or changed private installation", err)
			}
		})
	}
}

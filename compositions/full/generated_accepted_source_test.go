package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

type acceptedSourceStore struct {
	configurationObservationStore
	key   string
	limit uint32
}

func (s *acceptedSourceStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	s.key, s.limit = key, limit
	return s.configurationObservationStore.Read(ctx, key, limit)
}

func acceptedSourceProposal(t *testing.T, format configuration.Format, condition string) (configurationReaderSource, contract.ID, bool) {
	t.Helper()
	source := configurationAcceptedWorkPair(t, "aws", format)
	m, err := configuration.Parse(t.Context(), source.pair)
	if err != nil {
		t.Fatal(err)
	}
	domain := m.DomainID
	var editableJSON bytes.Buffer
	if err := configuration.EmitEditable(&editableJSON, m, configuration.JSON); err != nil {
		t.Fatal(err)
	}
	var editable, generated map[string]any
	if json.Unmarshal(editableJSON.Bytes(), &editable) != nil || json.Unmarshal(source.generatedBytes, &generated) != nil {
		t.Fatal("source fixture is not a complete pair")
	}
	if err := source.pair.Close(); err != nil {
		t.Fatal(err)
	}
	secret := func() {
		editable["entries"].(map[string]any)["draft-secret"] = map[string]any{"confidentiality": "secret", "recipients": []any{}, "source": map[string]any{"kind": "supplied"}}
	}
	plugin := func() {
		editable["entries"].(map[string]any)["draft-generated"] = map[string]any{"confidentiality": "secret", "recipients": []any{}, "source": map[string]any{"kind": "generated", "plugin": "unavailable-draft-generator", "epoch": 0, "retirement": "manual", "settings": map[string]any{"draft": true}}}
	}
	recipient := func(prepared bool) {
		row := map[string]any{"display_name": "Draft recipient", "encryption_key": "arn:aws:kms:us-east-1:123456789012:key/00000003-1111-1111-1111-111111111111"}
		if prepared {
			row["id"] = readerID(contract.Hash([]byte("missing prepared recipient")))
		}
		editable["recipients"].(map[string]any)["draft"] = row
	}
	wantOpen := true
	switch condition {
	case "clean":
	case "unprepared-secret":
		secret()
	case "unavailable-plugin":
		plugin()
	case "unprepared-recipient":
		recipient(false)
	case "combined-draft":
		secret()
		plugin()
		recipient(false)
		for _, name := range []string{"draft-secret", "draft-generated"} {
			editable["entries"].(map[string]any)[name].(map[string]any)["recipients"] = []any{"draft"}
		}
	case "missing-prepared-recipient":
		recipient(true)
		wantOpen = false
	case "wrong-domain":
		generated["domain"].(map[string]any)["id"] = readerID(contract.Hash([]byte("other domain")))
		wantOpen = false
	case "wrong-store":
		editable["domain"].(map[string]any)["store"].(map[string]any)["bucket"] = "other-fixture-bucket"
		wantOpen = false
	case "wrong-authority":
		selector := "arn:aws:kms:us-east-1:123456789012:key/00000004-1111-1111-1111-111111111111"
		editable["domain"].(map[string]any)["authority"].(map[string]any)["signing_key"] = selector
		generated["domain"].(map[string]any)["authority"].(map[string]any)["signing"].(map[string]any)["selector"] = selector
		wantOpen = false
	case "malformed-entry":
		secret()
		editable["entries"].(map[string]any)["draft-secret"].(map[string]any)["confidentiality"] = 42
		wantOpen = false
	default:
		t.Fatal("unknown source condition")
	}
	var body bytes.Buffer
	if format == configuration.JSON {
		if err := json.NewEncoder(&body).Encode(editable); err != nil {
			t.Fatal(err)
		}
	} else {
		for _, key := range []string{"schema", "domain", "recipients", "entries", "outputs", "plugins", "generated"} {
			value, ok := editable[key]
			if !ok {
				continue
			}
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprintf(&body, "%s: %s\n", key, encoded); err != nil {
				t.Fatal(err)
			}
		}
	}
	companion, err := json.Marshal(generated)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source.path, body.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source.generated, companion, 0600); err != nil {
		t.Fatal(err)
	}
	source.editableBytes, source.generatedBytes = bytes.Clone(body.Bytes()), companion
	return source, domain, wantOpen
}

func acceptedSourceCases() []string {
	return []string{"clean", "unprepared-secret", "unavailable-plugin", "unprepared-recipient", "combined-draft", "missing-prepared-recipient", "wrong-domain", "wrong-store", "wrong-authority", "malformed-entry"}
}

// full_only: false
func TestAcceptedGeneratedMutationIgnoresUnpreparedProposal(t *testing.T) {
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		for _, condition := range acceptedSourceCases() {
			t.Run(configurationSourceFormat(format)+"/"+condition, func(t *testing.T) {
				source, domain, wantOpen := acceptedSourceProposal(t, format, condition)
				before := configurationApplySourceImage(t, filepath.Dir(source.path))
				for _, operation := range []string{"continue", "cleanup"} {
					ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
					store := &acceptedSourceStore{configurationObservationStore: configurationObservationStore{result: contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}}}
					var trust *configurationObservationTrust
					opened, invoked, closes, private := 0, 0, 0, 0
					open := func(_ context.Context, m *configuration.Model, i core.ApplyInstallation) (*core.InstalledApply, error) {
						opened++
						if i.ExpectedDomain != domain || m.DomainID != domain || len(i.PublicConfiguration.Entries.Value) != 0 || len(i.GeneratorImplementations) != 0 || len(i.DesiredRecipients) != 1 || i.DesiredRecipients[0].Recipient.RecipientID != m.Authority.ID {
							t.Fatal("draft source reached installed construction")
						}
						store.descriptor = i.ExpectedStore
						trust = &configurationObservationTrust{id: i.ExpectedControl.NormalSigning.Binding.Trust, family: i.ExpectedControl.Provider}
						i.Store, i.Trust = store, trust
						i.ConfigurationValidator = core.NewPublicConfigurationValidator(nil)
						i.CloseInstalled = func() { closes++ }
						i.AdmitCustody = func(context.Context, contract.CryptoCompareRequest, contract.ControlCore, []contract.RecipientRecord, []contract.MembershipRow, contract.DescriptorVector, *contract.GeneratedSupportTransition, contract.ID, contract.MutationReceiptWindows, uint8, time.Time) (*core.InstalledApplyCustody, error) {
							private++
							return nil, contract.ErrRecord
						}
						return core.NewInstalledApply(i)
					}
					request, operationID := contract.ID{31}, contract.ID{32}
					out := configurationGeneratedMutationFile(ctx, request, source.path, format, func(pair *configuration.Pair) ConfigurationApplyResult {
						return ConfigurationApplyResult{PublicApplyResult: configurationGeneratedMutation(ctx, request, pair, func(e *core.InstalledApply) core.PublicApplyResult {
							invoked++
							if operation == "continue" {
								return e.Continue(ctx, request, operationID)
							}
							return e.CleanupGenerated(ctx, request)
						}, open)}
					})
					cancel()
					if wantOpen {
						if opened != 1 || invoked != 1 || closes != 1 || store.reads != 1 || store.key != store.descriptor.HeadKey || store.limit != contract.MaxHeadLength || out.Result.Outcome != core.EvidenceUnavailable || out.Result.Reason != core.ReadUnavailable || out.Result.StoreReason != contract.ReasonAccess || out.PreAdmission == nil || out.PreAdmission.Code != string(contract.ReasonEvidenceUnavailable) {
							t.Fatal("accepted work did not reach its exact Store observation", operation, opened, invoked, closes, store.reads, out.Result, out.PreAdmission)
						}
					} else if opened != 0 || invoked != 0 || store.reads != 0 || out.Result.Outcome != core.AdmissionRefused {
						t.Fatal("invalid trusted source reached installed work", operation, opened, invoked, out.Result)
					}
					if store.writes != 0 || private != 0 || trust != nil && trust.signs != 0 || out.Result.CommitMayHaveOccurred || out.Payload != nil || out.Cleanup != nil || len(out.Receipt) != 0 {
						t.Fatal("source check changed selected or private state")
					}
					configurationApplyAssertUnchanged(t, filepath.Dir(source.path), before)
				}
			})
		}
	}
}

// full_only: false
func TestContinuedApplyPublicationIgnoresUnpreparedProposal(t *testing.T) {
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		for _, condition := range acceptedSourceCases() {
			t.Run(configurationSourceFormat(format)+"/"+condition, func(t *testing.T) {
				source, domain, wantOpen := acceptedSourceProposal(t, format, condition)
				before := configurationApplySourceImage(t, filepath.Dir(source.path))
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				store := &acceptedSourceStore{configurationObservationStore: configurationObservationStore{result: contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}}}
				var trust *configurationObservationTrust
				opened, closes, private := 0, 0, 0
				open := func(_ context.Context, m *configuration.Model, i core.ApplyInstallation, plugins *configurationInstalledPlugins) (*core.InstalledApply, error) {
					opened++
					if i.ExpectedDomain != domain || m.DomainID != domain || len(i.PublicConfiguration.Entries.Value) != 0 || len(i.GeneratorImplementations) != 0 || len(i.DesiredRecipients) != 1 || i.DesiredRecipients[0].Recipient.RecipientID != m.Authority.ID || plugins != nil {
						t.Fatal("draft source reached continued combined construction")
					}
					store.descriptor = i.ExpectedStore
					trust = &configurationObservationTrust{id: i.ExpectedControl.NormalSigning.Binding.Trust, family: i.ExpectedControl.Provider}
					i.Store, i.Trust = store, trust
					i.ConfigurationValidator = core.NewPublicConfigurationValidator(nil)
					i.CloseInstalled = func() { closes++ }
					i.AdmitCustody = func(context.Context, contract.CryptoCompareRequest, contract.ControlCore, []contract.RecipientRecord, []contract.MembershipRow, contract.DescriptorVector, *contract.GeneratedSupportTransition, contract.ID, contract.MutationReceiptWindows, uint8, time.Time) (*core.InstalledApplyCustody, error) {
						private++
						return nil, contract.ErrRecord
					}
					return core.NewInstalledApply(i)
				}
				pair, err := configuration.Capture(ctx, source.path, format)
				if err != nil {
					var diagnostic *configuration.Diagnostic
					if condition != "malformed-entry" || !errors.As(err, &diagnostic) || diagnostic.Reason != "string-required" {
						t.Fatal("source capture failed before its expected boundary", err)
					}
					configurationApplyAssertUnchanged(t, filepath.Dir(source.path), before)
					return
				}
				defer func() {
					if err := pair.Close(); err != nil {
						t.Error(err)
					}
				}()
				out := configurationApplyPublication(ctx, contract.ID{31}, contract.ID{33}, pair, contract.ID{32}, ApplyPublicationOptions{}, open, nil)
				if wantOpen {
					if opened != 1 || closes != 1 || store.reads != 1 || store.key != store.descriptor.HeadKey || store.limit != contract.MaxHeadLength || out.Apply.Result.Outcome != core.EvidenceUnavailable || out.Apply.Result.Reason != core.ReadUnavailable || out.Apply.Result.StoreReason != contract.ReasonAccess || out.Apply.PreAdmission == nil || out.Apply.PreAdmission.Code != string(contract.ReasonEvidenceUnavailable) {
						t.Fatal("combined continuation did not reach exact Store observation", opened, closes, store.reads, out.Apply.Result, out.Apply.PreAdmission)
					}
				} else if opened != 0 || store.reads != 0 || out.Apply.Result.Outcome != core.AdmissionRefused {
					t.Fatal("invalid trusted source reached combined work", opened, out.Apply.Result)
				}
				if store.writes != 0 || private != 0 || trust != nil && trust.signs != 0 || out.Apply.Result.CommitMayHaveOccurred || out.Apply.Payload != nil || len(out.Apply.Receipt) != 0 || out.Publication.Stage != "unstarted" || out.Publication.Reason != "apply-incomplete" || out.Publication.Result != nil {
					t.Fatal("source check changed combined operation effects", out.Publication)
				}
				configurationApplyAssertUnchanged(t, filepath.Dir(source.path), before)
			})
		}
	}
}

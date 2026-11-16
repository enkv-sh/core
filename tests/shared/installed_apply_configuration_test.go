package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

func installedApplyPassiveConfiguration(t testing.TB, ctx context.Context, selected *StateSession, validator *PublicConfigurationValidator) contract.PublicConfiguration {
	t.Helper()
	stored, ok := selected.store.(contract.StoreConfigurationSource)
	if !ok {
		t.Fatal("fixture has no installed Store configuration")
	}
	projected, failed := projectSelectedPublicConfiguration(ctx, selected.selectedImage(), selected.selectedObjectReader(), stored.StoreConfiguration(), selected.admission.recipient, validator)
	if failed.Outcome != 0 || !projected.Valid || !projected.Complete || !projected.DiagnosticsComplete {
		t.Fatal("complete selected passive configuration unavailable", failed.Result, projected.Diagnostics)
	}
	return projected.Configuration
}

func installedApplyPassiveRecipients(selected *StateSession) []contract.ApplyRecipientInput {
	rows := selected.registry()
	input := make([]contract.ApplyRecipientInput, len(rows))
	for at, row := range rows {
		input[at] = contract.ApplyRecipientInput{Recipient: row}
	}
	return input
}

// full_only: false
func TestInstalledApplyGeneratedConfigurationRequiresExactPassiveIntent(t *testing.T) {
	for _, inputEncoding := range []uint8{contract.InputEncodingRaw, contract.InputEncodingBase64} {
		t.Run(fmt.Sprintf("input=%d", inputEncoding), func(t *testing.T) {

			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
			profile := defaultGeneratedFixtureProfile()
			if inputEncoding == contract.InputEncodingBase64 {
				implementation := generatedQualificationImplementation(t)
				profile.InputEncoding = inputEncoding
				profile.ConfigContractID, profile.ExecutorID = implementation.ConfigContractID, implementation.ExecutorID
				profile.CredentialRouteID, profile.DescriptorID = implementation.CredentialRouteID, implementation.DescriptorID
				var err error
				profile.CreateResultContractID, err = contract.GeneratedResultContractID(implementation, contract.GeneratorActionCreate, contract.GeneratedCompletionAcknowledged, contract.CryptoMaxRawValue, contract.GeneratorSafeFactsEnvelopeLength, inputEncoding)
				if err != nil {
					t.Fatal("original Base64 create contract", err)
				}
				profile.DeleteResultContractID, err = contract.GeneratedResultContractID(implementation, contract.GeneratorActionDelete, contract.GeneratedCompletionAcknowledged, 0, contract.GeneratorSafeFactsEnvelopeLength, contract.InputEncodingRaw)
				if err != nil {
					t.Fatal("empty raw delete contract", err)
				}
			}
			selected := configurationRecoveryGenerated(t, ctx, f.env, f.selected, "generated-final", profile)
			entry := selected.valueEntry(selected.root.Names[0].Slot)
			if entry == nil || entry.ValueSource != contract.Generated || entry.Generated.ConfigContractID.IsZero() || entry.Generated.ResourceContractID.IsZero() {
				t.Fatal("fixture has no current generated entry")
			}
			// The private StandardValue fixture has 28 logical bytes. Raw retains
			// 28 bytes; padded Base64 retains 40 bytes. Crypto owns the actual bytes.
			retained := uint32(28)
			if inputEncoding == contract.InputEncodingBase64 {
				retained = 40
			}
			for _, named := range selected.root.Names {
				row := selected.valueEntry(named.Slot)
				payload, err := contract.InspectCanonicalPayload(row.ValueBytes)
				if err != nil || row.InputEncoding != inputEncoding || row.ContentLength != 28 || row.RetainedLength != retained || payload.InputEncoding != inputEncoding || payload.ContentLength != 28 || payload.RetainedLength != retained {
					t.Fatal("private original generation lost declared C/tag/R", err)
				}
			}
			validator := NewPublicConfigurationValidator(selected.admission.outputInterpreter)
			configuration := installedApplyPassiveConfiguration(t, ctx, selected, validator)
			original := selected.currentEntryInputs()
			for at := range original {
				if original[at].ValueSource == contract.Generated {
					original[at].InputBytes = nil
					current := selected.valueEntry(selected.root.Names[at].Slot)
					public := configuration.Entries.Value[at].Generated
					original[at].Generated = &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: current.Generated.SemanticLifecycleMode(), Epoch: public.Epoch.Value, RetirementMode: public.Retirement.Value,
						ConfigContractID: current.Generated.ConfigContractID, ResourceContractID: public.ResourceContractID.Value,
						CompletionClass: public.Completion.Value, Intent: public.ContentIntent.Value}
				}
			}
			store := requireAdmittedMemoryStore(t, selected.store)
			creates, cas, before := store.creates, store.cas, contract.Hash(selected.body)
			for _, condition := range []string{"exact", "output-only", "input-encoding", "epoch", "lifecycle", "config-contract", "resource-contract", "content", "retirement", "completion", "removed", "source", "carrier-class", "carrier-membership", "carrier-payload", "carrier-registry"} {
				t.Run(condition, func(t *testing.T) {
					proposal := ownPublicConfiguration(configuration)
					input := slices.Clone(original)
					desired := installedApplyPassiveRecipients(selected)
					generated := proposal.Entries.Value[0].Generated
					switch condition {
					case "output-only":
						proposal.Entries.Value[0].OutputEncoding.Value = contract.OutputEncodingBase64
						input[0].OutputEncoding = contract.OutputEncodingBase64
					case "input-encoding":
						changed := uint8(contract.InputEncodingBase64)
						if inputEncoding == contract.InputEncodingBase64 {
							changed = contract.InputEncodingRaw
						}
						proposal.Entries.Value[0].InputEncoding.Value = changed
						input[0].InputEncoding = changed
					case "epoch":
						generated.Epoch.Value++
					case "lifecycle":
						generated.LifecycleMode.Value = contract.GeneratorLifecycleNone
					case "config-contract":
						generated.ConfigContractID.Value = fixtureID(f.env.Domain, "other passive config")
					case "resource-contract":
						generated.ResourceContractID.Value = fixtureID(f.env.Domain, "other passive resource")
					case "content":
						generated.ContentIntent.Value = append(generated.ContentIntent.Value, 0)
					case "retirement":
						generated.Retirement.Value = contract.GeneratedRetirementAuto
						if configuration.Entries.Value[0].Generated.Retirement.Value == generated.Retirement.Value {
							generated.Retirement.Value = contract.GeneratedRetirementManual
						}
					case "completion":
						generated.Completion.Value = contract.GeneratedCompletionConfirmed
						if configuration.Entries.Value[0].Generated.Completion.Value == generated.Completion.Value {
							generated.Completion.Value = contract.GeneratedCompletionAcknowledged
						}
					case "removed":
						proposal.Entries.Value = proposal.Entries.Value[1:]
						input = input[1:]
					case "source":
						proposal.Entries.Value[0].Source.Value = contract.Supplied
						proposal.Entries.Value[0].Generated = nil
						input[0].ValueSource = contract.Supplied
						input[0].Generated = nil
					case "carrier-class":
						input[0].ConfidentialityClass = contract.Plain
					case "carrier-membership":
						input[0].Recipients = nil
					case "carrier-payload":
						input[0].InputBytes = []byte("unselected payload")
					case "carrier-registry":
						desired[0].Recipient.DisplayName += " changed outside public proposal"
					}
					installation := ApplyInstallation{Store: selected.store, PublicConfiguration: proposal, ConfigurationValidator: validator, DesiredRecipients: desired}
					mapped, _, result := selected.installedApplyInputs(ctx, installation, input)
					if condition == "removed" || condition == "source" {
						if result.Outcome != 0 || len(mapped) != len(input) {
							t.Fatal("generated removal or source conversion refused before normal handoff", result)
						}
						return
					}
					if condition == "input-encoding" {
						if mapped != nil || result != refused(GeneratedIntentConflict) {
							t.Fatal("same epoch input classification change did not refuse exactly", result)
						}
						return
					}
					if condition != "exact" && condition != "output-only" {
						if mapped != nil || result.Outcome != AdmissionRefused {
							t.Fatal("changed passive intent or inconsistent carrier was accepted", result)
						}
						return
					}
					if result.Outcome != 0 || len(mapped) != len(original) {
						t.Fatal("exact passive generated configuration refused", result)
					}
					for at, row := range mapped {
						current := selected.valueEntry(selected.root.Names[at].Slot)
						if !bytes.Equal(row.InputBytes, current.ValueBytes) || original[at].InputBytes != nil || row.InputEncoding != current.InputEncoding || row.OutputEncoding != input[at].OutputEncoding || installedGeneratedCreates(mapped) {
							t.Fatal("generated mapping did not use exact authenticated current bytes")
						}
					}
				})
			}
			if store.creates != creates || store.cas != cas || contract.Hash(selected.body) != before {
				t.Fatal("passive admission changed selected state")
			}
		})
	}
}

// full_only: false
func TestInstalledApplyOutputConfigurationAdmitsCompleteDesiredIntent(t *testing.T) {
	f := newFixture(t, 1, false, 1)
	input := f.session.currentEntryInputs()
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{outputConfigurationTarget(input[0].Name, "app")}}}}
	selectOutputConfiguration(t, f, input, output)
	selected := f.session
	validator := NewPublicConfigurationValidator(selected.admission.outputInterpreter)
	configuration := installedApplyPassiveConfiguration(t, t.Context(), selected, validator)
	creates, cas, signs := f.store.creates, f.store.cas, f.trust.signs
	for _, condition := range []string{"exact", "binding-removed", "route-removed", "groups", "encoding", "policy"} {
		t.Run(condition, func(t *testing.T) {
			proposal := ownPublicConfiguration(configuration)
			switch condition {
			case "binding-removed":
				proposal.OutputBindings.Value = nil
				proposal.Routing.Value = nil
			case "route-removed":
				proposal.Routing.Value = nil
			case "groups":
				proposal.Groups.Value = [][]string{{input[0].Name}}
			case "encoding":
				proposal.OutputBindings.Value[0].Targets.Value[0].PayloadEncoding.Value = contract.OutputEncodingBase64
			case "policy":
				proposal.OutputBindings.Value[0].Targets.Value[0].ConsumerPolicy.State = contract.PublicUnavailable
			}
			mapped, _, result := selected.installedApplyInputs(t.Context(), ApplyInstallation{Store: selected.store, PublicConfiguration: proposal, ConfigurationValidator: validator, DesiredRecipients: installedApplyPassiveRecipients(selected)}, input)
			if condition == "exact" || condition == "binding-removed" || condition == "groups" {
				if result.Outcome != 0 || len(mapped) != len(input) {
					t.Fatal("exact passive output configuration refused", result)
				}
			} else if mapped != nil || result.Outcome != AdmissionRefused {
				t.Fatal("inconsistent passive output assertions accepted", result)
			}
		})
	}
	if f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs {
		t.Fatal("passive output admission caused effects")
	}
}

// full_only: false
func TestInstalledApplyPublicConfigurationMatchesCompleteCarriers(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	validator := NewPublicConfigurationValidator(nil)
	configuration := installedApplyPassiveConfiguration(t, ctx, f.selected, validator)
	authority := f.selected.admission.recipient
	configuration.Entries.Value = []contract.PublicEntry{{Name: "proposed", Class: observedPublicField(contract.Plain), Source: observedPublicField(contract.Supplied), PlainValue: observedPublicField([]byte("plain proposal")), Memberships: observedPublicField([]contract.ID{authority})}}
	for _, condition := range []string{"exact", "display", "missing-validator", "incomplete", "name", "class", "source", "plain", "membership", "registry", "control", "store"} {
		t.Run(condition, func(t *testing.T) {
			proposal := ownPublicConfiguration(configuration)
			input := []ApplyEntryInput{{Name: "proposed", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("plain proposal"), Recipients: []contract.ID{authority}}}
			desired := installedApplyPassiveRecipients(f.selected)
			installedValidator := validator
			switch condition {
			case "display":
				proposal.Recipients.Value[0].DisplayName.Value += " edited"
				desired[0].Recipient.DisplayName = proposal.Recipients.Value[0].DisplayName.Value
			case "missing-validator":
				installedValidator = nil
			case "incomplete":
				proposal.Entries.State = contract.PublicUnavailable
				proposal.Entries.Value = nil
			case "name":
				input[0].Name = "another"
			case "class":
				input[0].ConfidentialityClass = contract.Secret
			case "source":
				input[0].ValueSource = contract.Generated
			case "plain":
				input[0].InputBytes = []byte("another")
			case "membership":
				input[0].Recipients = nil
			case "registry":
				desired[0].Recipient.DisplayName += " another"
			case "control":
				proposal.Authority.Signing.Selector.Value = "projects/fixture-project/locations/us-central1/keyRings/ring/cryptoKeys/another/cryptoKeyVersions/1"
			case "store":
				proposal.Store.Bucket.Value = "another-fixture-bucket"
			}
			mapped, _, result := f.selected.installedApplyInputs(ctx, ApplyInstallation{Store: f.env.Store, PublicConfiguration: proposal, ConfigurationValidator: installedValidator, DesiredRecipients: desired}, input)
			if condition == "exact" || condition == "display" {
				if result.Outcome != 0 || len(mapped) != 1 || !bytes.Equal(mapped[0].InputBytes, input[0].InputBytes) {
					t.Fatal("complete supplied proposal refused", result)
				}
			} else if mapped != nil || result.Outcome != AdmissionRefused {
				t.Fatal("inconsistent or unvalidated complete proposal accepted", result)
			}
		})
	}
}

package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicGeneratedPlanningReportsRequestedCreation(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			t.Setenv("CLOUDFLARE_API_TOKEN", "")
			t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
			t.Setenv("EXPERIMENTAL_GOOGLE_API_USE_S2A", "false")
			source := configurationReaderPair(t, family, configuration.JSON, nil)
			h := &readerHTTPFixture{archive: source.archive, reads: map[string]int{}}
			calls := 0
			open := configurationReaderOpener(t, source, h, &calls)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			model, err := configuration.Parse(ctx, source.pair)
			if err != nil {
				t.Fatal(err)
			}
			config, err := configurationReaderConfig(model)
			if err != nil {
				t.Fatal(err)
			}
			reader, err := open(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()

			intent := dependencyCanonicalIntent(true)
			var configID, resourceID contract.ID
			for i := range configID {
				configID[i] = 0x45
				resourceID[i] = 0x46
			}

			const name = "next-token/\n雪"
			proposed := model.Public
			proposed.Entries.Value = append(proposed.Entries.Value, contract.PublicEntry{
				Name: name, Class: readerPresent(contract.Secret), Source: readerPresent(contract.Generated),
				Memberships: readerPresent([]contract.ID{model.Public.Authority.RecipientID.Value}),
				Generated: &contract.PublicGeneratedSettings{
					Epoch: readerPresent(uint64(0)), ConfigContractID: readerPresent(configID), ResourceContractID: readerPresent(resourceID), LifecycleMode: readerPresent(contract.GeneratorLifecycleManaged), ContentIntent: readerPresent(intent),
					Retirement: readerPresent(contract.GeneratedRetirementManual), Completion: readerPresent(contract.GeneratedCompletionAcknowledged),
				},
			})
			result := ConfigurationComparisonResult{PublicComparisonResult: reader.Compare(ctx, contract.Hash([]byte("public requested generated creation")), proposed), InstallationRequirements: InstallationRequirementComparison{Differences: []InstallationRequirementDifference{}}}
			h.assertNoEffects(t)
			source.assertUnchanged(t)
			if result.StateResult != contract.ReaderSuccess || result.Verdict != contract.ComparisonMismatch || result.Observation == nil || !result.DiagnosticsComplete || calls != 1 {
				t.Fatalf("public generated proposal did not complete: state=%s verdict=%s observed=%t complete=%t calls=%d", result.StateResult, result.Verdict, result.Observation != nil, result.DiagnosticsComplete, calls)
			}
			body, err := RenderComparisonJSON(result)
			if err != nil {
				t.Fatal(err)
			}
			var decoded struct {
				Payload struct {
					Entries []struct {
						Name           string          `json:"name"`
						Action         string          `json:"requested_action"`
						CurrentEpoch   json.RawMessage `json:"current_epoch"`
						RequestedEpoch *uint64         `json:"requested_epoch"`
					} `json:"generated_entries"`
				} `json:"payload"`
			}
			if err := json.Unmarshal(body, &decoded); err != nil {
				t.Fatal(err)
			}
			if len(decoded.Payload.Entries) != 1 {
				t.Fatalf("requested generated creation is missing from the public result: got %d generated rows, want 1", len(decoded.Payload.Entries))
			}
			row := decoded.Payload.Entries[0]
			if row.Name != name || row.Action != "create" || string(row.CurrentEpoch) != "null" || row.RequestedEpoch == nil || *row.RequestedEpoch != 0 {
				t.Fatalf("requested generated creation facts differ: name=%q action=%q current_epoch=%s requested_epoch_present=%t", row.Name, row.Action, row.CurrentEpoch, row.RequestedEpoch != nil)
			}
		})
	}
}

// full_only: false
func TestConfigurationPlanningKeepsGeneratedIntentAndSuppliedInputs(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			trusted := configurationReaderPair(t, family, configuration.JSON, nil)
			candidate := configurationReaderPair(t, family, configuration.YAML, func(editable, generated map[string]any) {
				editable["entries"].(map[string]any)["future"] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": dependencyCanonicalGeneratorSource(generated, "future", true)}
			})
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			model, err := configuration.Parse(ctx, candidate.pair)
			if err != nil {
				t.Fatal(err)
			}
			inputs := configurationPlanningInputs(model)
			if len(inputs) != 2 {
				t.Fatal("generated proposal entered private supplied scope", len(inputs))
			}
			for _, input := range inputs {
				if (input.Name != "encoded" && input.Name != "secret") || input.Form != contract.PlanningRetained || len(input.SealedInput) != 0 {
					t.Fatal("mixed source lost its exact supplied form", input.Name, input.Form)
				}
			}
			found := false
			for _, entry := range model.Public.Entries.Value {
				if entry.Name == "future" {
					found = true
					if entry.Source.Value != contract.Generated || entry.Generated == nil || entry.Generated.ConfigContractID.Value != (contract.ID{0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45}) || entry.Generated.LifecycleMode.Value != contract.GeneratorLifecycleManaged || entry.Generated.Epoch.Value != 0 || entry.Generated.Retirement.Value != contract.GeneratedRetirementManual || !bytes.Equal(entry.Generated.ContentIntent.Value, dependencyCanonicalIntent(true)) {
						t.Fatal("mixed declaration lost normalized generated intent")
					}
				}
			}
			if !found {
				t.Fatal("generated proposal omitted from public scope")
			}
			digest, err := core.PlanningInputDigest(model.Public, inputs)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			got := planConfiguration(ctx, contract.Hash([]byte("mixed captured planning sources")), trusted.pair, candidate.pair, contract.PlanningOptions{Purpose: contract.PlanningEquality}, nil, func(_ context.Context, c PlanningConfig) (*core.InstalledPlanning, error) {
				calls++
				if c.InputDigest != digest || c.Sources.Trusted.EditableDigest == c.Sources.Proposed.EditableDigest || c.Reader.Family != trusted.archive.Family || c.DisplayFactory != nil {
					t.Fatal("mixed planning lost complete captured input or trusted construction")
				}
				return nil, errors.New("controlled unavailable planning construction")
			})
			if calls != 1 || got.StateResult != contract.ReaderUnavailable || got.PrivateComplete || got.CompletedRecords != 0 {
				t.Fatal("mixed source preflight did not reach its fixed planning construction", calls, got.StateResult)
			}
			trusted.assertUnchanged(t)
			candidate.assertUnchanged(t)
		})
	}
}

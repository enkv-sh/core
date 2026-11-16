package compositionfull

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/compositions/full/plugininstallation"
	"enkv.sh/core/contract"
)

// Canonical intent framing is built directly from its documented schema: u16,
// config ID, lifecycle byte, resource ID and u32-length-prefixed settings.
func dependencyCanonicalIntent(managed bool) []byte {
	body := append([]byte{0, 1}, bytes.Repeat([]byte{0x45}, 32)...)
	lifecycle, resource := byte(1), make([]byte, 32)
	if managed {
		lifecycle = 2
		resource = bytes.Repeat([]byte{0x46}, 32)
	}
	body = append(body, lifecycle)
	body = append(body, resource...)
	settings := []byte(`{"size":17}`)
	body = binary.BigEndian.AppendUint32(body, uint32(len(settings)))
	return append(body, settings...)
}

func dependencyGeneratorSource(t *testing.T, account string) map[string]any {
	t.Helper()
	return map[string]any{"kind": "generated", "plugin": "cloudflare-account-token", "epoch": 0, "retirement": "manual", "settings": map[string]any{"account": account, "name": "future-token", "policies": []any{map[string]any{"effect": "allow", "permission_groups": []string{"123456789abcdef0123456789abcdef0"}, "resources": []any{map[string]string{"kind": "account", "id": account}}}}}}
}

func dependencyCanonicalGeneratorSource(generated map[string]any, name string, managed bool) map[string]any {
	configurationCanonicalBacking(generated, "generators", name, dependencyCanonicalIntent(managed))
	source := map[string]any{"kind": "generated", "plugin": nil, "epoch": 0, "canonical": map[string]any{"settings": json.RawMessage(`{"size":17}`)}}
	if managed {
		source["retirement"] = "manual"
	}
	return source
}

func dependencyCanonicalOutputSource(t testing.TB, generated map[string]any, id string) map[string]any {
	t.Helper()
	binding := contract.NormalOutputBinding{DestinationID: id, Destination: readerFixtureDestination(readerFixtureProfiles()[0])}
	body, err := contract.EncodeNormalOutputBinding(binding)
	if err != nil {
		t.Fatal(err)
	}
	configurationCanonicalBacking(generated, "outputs", id, body)
	return map[string]any{"plugin": nil, "canonical": map[string]any{"settings": json.RawMessage(binding.Destination.CanonicalSettings)}}
}

func dependencyPluginName(value string) *string { return &value }

// full_only: false
func TestPrepareDependenciesIncludesUnappliedDeclarationsWithoutCredentials(t *testing.T) {
	savedKeys, savedCLIKey := installedPluginKeys, installedCLIVerificationKey
	installedPluginKeys, installedCLIVerificationKey = "", ""
	t.Cleanup(func() { installedPluginKeys, installedCLIVerificationKey = savedKeys, savedCLIKey })
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	source := configurationSetPair(t, "aws", configuration.JSON, func(editable, generated map[string]any) {
		entries := editable["entries"].(map[string]any)
		for i, account := range []string{"0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210"} {
			entries[fmt.Sprintf("future-%d", i)] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": dependencyGeneratorSource(t, account)}
		}
		for _, name := range []string{"local-a", "local-b"} {
			entries[name] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": map[string]any{"kind": "generated", "plugin": "local-random-secret", "epoch": 0, "settings": map[string]any{}}}
		}
		retained := dependencyCanonicalGeneratorSource(generated, "retained-selector", true)
		entries["retained-selector"] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": retained}
		destinations := editable["outputs"].(map[string]any)["destinations"].(map[string]any)
		destinations["unused-aws"] = map[string]any{"plugin": "aws-secrets-manager", "settings": map[string]string{"account": "987654321098", "region": "us-west-2"}}
	})
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	model, err := configuration.Parse(ctx, source.pair)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("parsed-mixed-declarations", func(t *testing.T) {
		want := []PrepareDependencyRequirement{
			{Role: "generator", Subjects: []uint16{3, 4}, Plugin: dependencyPluginName("cloudflare-account-token"), ProtocolVersion: 5, Status: "unavailable", Reason: "unavailable"},
			{Role: "generator", Subjects: []uint16{5, 6}, Plugin: dependencyPluginName("local-random-secret"), ProtocolVersion: 5, Status: "unavailable", Reason: "unavailable"},
			{Role: "generator", Subjects: []uint16{7}, Contract: strings.Repeat("45", 32), ProtocolVersion: 5, Status: "missing", Reason: "selection-required"},
			{Role: "output", Subjects: []uint16{5}, Plugin: dependencyPluginName("aws-secrets-manager"), ProtocolVersion: 6, Status: "unavailable", Reason: "unavailable"},
		}
		// Recovered output bindings have no local installation selection.
		for i, profile := range readerFixtureProfiles() {
			want = append(want, PrepareDependencyRequirement{Role: "output", Subjects: []uint16{uint16(i)}, Contract: readerFixtureDestination(profile).ConfigContractID, ProtocolVersion: 6, Status: "missing", Reason: "selection-required"})
		}
		slices.SortFunc(want, func(a, b PrepareDependencyRequirement) int {
			if a.Role != b.Role {
				return strings.Compare(a.Role, b.Role)
			}
			if a.Contract != b.Contract {
				return strings.Compare(a.Contract, b.Contract)
			}
			return strings.Compare(prepareDependencyPlugin(a), prepareDependencyPlugin(b))
		})
		wantChecks := make([]PrepareDependencyRequirement, 0, len(want))
		for _, row := range want {
			if row.Plugin != nil {
				row.Status, row.Reason = "", "none"
			}
			wantChecks = append(wantChecks, row)
		}
		checks, err := configurationDependencyChecks(model)
		if err != nil || !reflect.DeepEqual(checks, wantChecks) {
			t.Fatalf("declared generator installation names differ: got=%+v want=%+v err=%v", checks, wantChecks, err)
		}
		wantNames := []string{"aws-secrets-manager", "cloudflare-account-token", "local-random-secret"}
		wantInstallations := make([]plugininstallation.Requirement, 0, len(wantNames))
		for _, name := range wantNames {
			wantInstallations = append(wantInstallations, plugininstallation.Requirement{Name: name})
		}
		requirements, err := configurationPluginRequirements(model)
		if err != nil || !reflect.DeepEqual(requirements, wantInstallations) {
			t.Fatal("declared generators captured another installation", requirements, err)
		}
		got, err := prepareDependencies(ctx, source.pair, model, false)
		if !errors.Is(err, plugininstallation.ErrInvalid) {
			t.Fatal("unconfigured distribution lost its dependency error", err)
		}
		if got.Assessment != "incomplete" || !got.MinimumAdministrativeReady || got.AllDeclaredReady || got.SettingsFailure != nil || !reflect.DeepEqual(got.Requirements, want) || len(got.Installations) != 0 {
			t.Fatalf("incomplete dependency set or effect dependency blocked administration: got=%+v want=%+v", got, want)
		}
	})
	t.Run("unknown-plugin", func(t *testing.T) {
		index := -1
		for i := range model.Entries {
			if model.Entries[i].Generated != nil {
				index = i
				break
			}
		}
		if index < 0 {
			t.Fatal("parsed fixture has no generated entry")
		}
		original := model.Entries[index].Generated
		changed := *original
		changed.Plugin = "unknown-generator"
		model.Entries[index].Generated = &changed
		defer func() { model.Entries[index].Generated = original }()
		checks, err := configurationDependencyChecks(model)
		if err != nil || !slices.ContainsFunc(checks, func(row PrepareDependencyRequirement) bool {
			return prepareDependencyPlugin(row) == "unknown-generator" && row.Role == "generator"
		}) {
			t.Fatal("new plugin ID was rejected", checks, err)
		}
		requirements, err := configurationPluginRequirements(model)
		if err != nil || !slices.ContainsFunc(requirements, func(row plugininstallation.Requirement) bool { return row.Name == "unknown-generator" }) {
			t.Fatal("new plugin ID did not remain an explicit dependency", requirements, err)
		}
		changed.Plugin = "../untrusted"
		if checks, err := configurationDependencyChecks(model); err == nil || checks != nil {
			t.Fatal("path obtained plugin authority", checks, err)
		}
		if requirements, err := configurationPluginRequirements(model); err == nil || requirements != nil {
			t.Fatal("path obtained installation authority", requirements, err)
		}

	})
	source.assertUnchanged(t)
}

// full_only: false
func TestPrepareDependenciesSeparatesAdministrationAndSourceStability(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
			source := configurationApplyPair(t, family, configuration.JSON, func(editable, _ map[string]any) {
				editable["outputs"] = map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}}
			})
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			model, err := configuration.Parse(ctx, source.pair)
			if err != nil {
				t.Fatal(err)
			}
			got, err := prepareDependencies(ctx, source.pair, model, false)
			if err != nil || got.Assessment != "complete" || !got.MinimumAdministrativeReady || !got.AllDeclaredReady || len(got.Requirements) != 0 || len(got.Installations) != 0 {
				t.Fatal("artifact-free administration was blocked", got, err)
			}
			directory, dirErr := os.UserConfigDir()
			if dirErr != nil {
				t.Fatal(dirErr)
			}
			if _, statErr := os.Stat(directory); !os.IsNotExist(statErr) {
				t.Fatal("artifact-free preparation captured installation storage", statErr)
			}
			source.assertUnchanged(t)
			configurationSetWritable(t, source)
			if err := os.Chmod(source.path, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(source.path, append(append([]byte(nil), source.editableBytes...), '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			changed, err := prepareDependencies(ctx, source.pair, model, false)
			if !errors.Is(err, ErrPrepareSourceCheck) || changed.MinimumAdministrativeReady || changed.AllDeclaredReady || changed.Assessment != "incomplete" || len(changed.Requirements) != 0 || len(changed.Installations) != 0 {
				t.Fatal("changed source retained readiness or lost assessed facts", changed, err)
			}
			result, err := NewPrepareRefusal()
			if err != nil {
				t.Fatal(err)
			}
			result.facts.Branch = "existing"
			result.facts.Diagnostics = []prepareDiagnostic{}
			err = assessPrepareDependencies(ctx, source.pair, model, result, false)
			record := prepareResultWire(t, result)
			if err == nil || PrepareExitCode(result, nil) != 2 || record["outcome"] != "incomplete" || !reflect.DeepEqual(result.facts.Dependencies, changed) || !reflect.DeepEqual(result.facts.Diagnostics, []prepareDiagnostic{{Reason: "source-changed", Subject: "source"}}) {
				t.Fatal("confirmed source change lost its known failure classification", record, err)
			}
		})
	}
}

// full_only: true
// Proves 512 total values (128 generated) plus 64 output bindings before deduplication.
func TestPrepareDependenciesDeduplicatesMaximumDeclarations(t *testing.T) {
	savedKeys, savedCLIKey := installedPluginKeys, installedCLIVerificationKey
	installedPluginKeys, installedCLIVerificationKey = "", ""
	t.Cleanup(func() { installedPluginKeys, installedCLIVerificationKey = savedKeys, savedCLIKey })
	source := configurationApplyPair(t, "aws", configuration.JSON, func(editable, generated map[string]any) {
		entries := map[string]any{}
		for i := 0; i < 512; i++ {
			entry := map[string]any{"confidentiality": "plain", "recipients": []string{}, "source": map[string]any{"kind": "supplied", "bytes": []byte{}}}
			if i < 128 {
				entry["confidentiality"] = "secret"
				entry["source"] = dependencyGeneratorSource(t, "0123456789abcdef0123456789abcdef")
			}
			entries[fmt.Sprintf("future-%03d", i)] = entry
		}
		editable["entries"] = entries
		generated["secrets"] = map[string]any{}
		destinations := map[string]any{}
		for i := 0; i < 64; i++ {
			destinations[fmt.Sprintf("unused-%02d", i)] = map[string]any{"plugin": "aws-secrets-manager", "settings": map[string]string{"account": "123456789012", "region": "us-east-1"}}
		}
		editable["outputs"] = map[string]any{"destinations": destinations, "routing": map[string]any{}}
	})
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	model, err := configuration.Parse(ctx, source.pair)
	if err != nil {
		t.Fatal(err)
	}
	generatedCount := 0
	for _, entry := range model.Entries {
		if entry.Generated != nil {
			generatedCount++
		}
	}
	if len(model.Entries) != 512 || generatedCount != 128 || len(model.Public.OutputBindings.Value) != 64 {
		t.Fatal("maximum fixture does not reach its independent declaration bounds", len(model.Entries), generatedCount, len(model.Public.OutputBindings.Value))
	}
	got, err := prepareDependencies(ctx, source.pair, model, false)
	want := []PrepareDependencyRequirement{{Role: "generator", Subjects: []uint16{0}, Plugin: dependencyPluginName("cloudflare-account-token"), ProtocolVersion: 5, Status: "unavailable", Reason: "unavailable"}, {Role: "output", Subjects: []uint16{0}, Plugin: dependencyPluginName("aws-secrets-manager"), ProtocolVersion: 6, Status: "unavailable", Reason: "unavailable"}}
	want[0].Subjects = make([]uint16, 128)
	for i := range want[0].Subjects {
		want[0].Subjects[i] = uint16(i)
	}
	want[1].Subjects = make([]uint16, 64)
	for i := range want[1].Subjects {
		want[1].Subjects[i] = uint16(i)
	}

	if !errors.Is(err, plugininstallation.ErrInvalid) || got.Assessment != "incomplete" || !got.MinimumAdministrativeReady || got.AllDeclaredReady || got.SettingsFailure != nil || !reflect.DeepEqual(got.Requirements, want) || len(got.Installations) != 0 {
		t.Fatal("maximum declaration set was truncated or not deduplicated", got, err)
	}
	for _, excess := range []string{"entries", "outputs"} {
		t.Run("first-excess-"+excess, func(t *testing.T) {
			entries, bindings := model.Entries, model.Outputs
			if excess == "entries" {
				model.Entries = append(model.Entries, configuration.Entry{Name: "first-excess"})
			} else {
				model.Outputs = append(model.Outputs, model.Outputs[0])
			}
			refused, err := prepareDependencies(ctx, source.pair, model, false)
			model.Entries, model.Outputs = entries, bindings
			if err == nil || refused.Assessment != "incomplete" || refused.MinimumAdministrativeReady || refused.AllDeclaredReady || len(refused.Requirements) != 0 {
				t.Fatal("first-excess declaration emitted a truncated assessment", refused, err)
			}
		})
	}
	source.assertUnchanged(t)
}

// full_only: false
func TestPrepareDependenciesPreservesPendingSourceRefusal(t *testing.T) {
	source := configurationApplyPair(t, "aws", configuration.JSON, nil)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	model, err := configuration.Parse(ctx, source.pair)
	if err != nil {
		t.Fatal(err)
	}
	configurationSetWritable(t, source)
	directory := filepath.Join(filepath.Dir(source.path), ".enkv-pending")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(directory, filepath.Base(source.path))
	if err := os.WriteFile(marker, []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := prepareDependencies(ctx, source.pair, model, false)
	if !errors.Is(err, ErrPrepareSourceCheck) || !errors.Is(err, configuration.ErrPendingEdit) || got.Assessment != "incomplete" || got.MinimumAdministrativeReady || got.AllDeclaredReady || len(got.Requirements) != 0 || len(got.Installations) != 0 {
		t.Fatal("source check erased pending cause or retained readiness", got, err)
	}
	source.assertUnchanged(t)
}

package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestCanonicalSourceRoutingChangesRebuildOnlyAffectedBindings(t *testing.T) {
	target := func(destination, slot string) contract.OutputTarget {
		return contract.OutputTarget{ServiceContractID: destination, TargetContractID: "private-target", CanonicalTarget: slot, ConsumerLocator: slot,
			TargetData: []byte{0, 255}, PayloadEncoding: contract.OutputEncodingRaw, Capabilities: 63,
			CreateValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536}}
	}
	known := map[string]contract.OutputTarget{
		"fixed/FIXED": target("fixed", "fixed/kept"), "gcp/INHERITED": target("gcp", "gcp/inherited"),
		"gcp/PINNED": target("gcp", "gcp/pinned"), "gcp/RENAMED": target("gcp", "gcp/renamed"),
		"gcp/": target("gcp", "gcp/empty-name"), "repository/INHERITED": target("repository", "repository/inherited"),
	}
	baseline := map[string][]contract.NormalOutputTarget{
		"fixed":      {{Name: "FIXED", Target: known["fixed/FIXED"]}},
		"gcp":        {{Name: "INHERITED", Target: known["gcp/INHERITED"]}, {Name: "PINNED", Target: known["gcp/PINNED"]}},
		"repository": {},
	}
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		for _, condition := range []struct {
			name            string
			unavailable     []string
			calls           []string
			gcp, repository []string
		}{
			{"unchanged", nil, nil, []string{"INHERITED", "PINNED"}, nil},
			{"changed-default", []string{"gcp", "repository"}, []string{"gcp/PINNED", "repository/INHERITED"}, []string{"PINNED"}, []string{"INHERITED"}},
			{"empty-override", []string{"gcp"}, []string{"gcp/PINNED"}, []string{"PINNED"}, nil},
			{"equal-default-override", nil, nil, []string{"INHERITED", "PINNED"}, nil},
			{"renamed-entry", []string{"gcp"}, []string{"gcp/PINNED", "gcp/RENAMED"}, []string{"PINNED", "RENAMED"}, nil},
			{"empty-entry-name", []string{"gcp"}, []string{"gcp/", "gcp/PINNED"}, []string{"", "PINNED"}, nil},
			{"removed-entry", []string{"gcp"}, []string{"gcp/PINNED"}, []string{"PINNED"}, nil},
		} {
			t.Run(configurationSourceFormat(format)+"/"+condition.name, func(t *testing.T) {
				records := make(map[string][]byte)
				source := configurationApplyPair(t, "aws", format, func(editable, generated map[string]any) {
					entries := make(map[string]any)
					for _, name := range []string{"EMPTY", "FIXED", "INHERITED", "PINNED"} {
						entries[name] = map[string]any{"confidentiality": "plain", "recipients": []string{}, "source": map[string]any{"kind": "supplied", "value": "public"}}
					}
					overrides := map[string]any{"EMPTY": []string{}, "FIXED": []string{"fixed"}, "PINNED": []string{"gcp"}}
					defaults := []string{"gcp"}
					switch condition.name {
					case "changed-default":
						defaults = []string{"repository"}
					case "empty-override":
						overrides["INHERITED"] = []string{}
					case "equal-default-override":
						overrides["INHERITED"] = []string{"gcp"}
					case "renamed-entry", "empty-entry-name":
						name := "RENAMED"
						if condition.name == "empty-entry-name" {
							name = ""
						}
						entries[name] = entries["INHERITED"]
						delete(entries, "INHERITED")
					case "removed-entry":
						delete(entries, "INHERITED")
					}
					editable["entries"] = entries
					generated["secrets"] = map[string]any{}
					destinations := make(map[string]any)
					for _, id := range []string{"fixed", "gcp", "repository"} {
						destination := contract.OutputDestination{ConfigContractID: "private-config", ServiceContractID: id, CanonicalSettings: []byte(`{"n":1.00}`), Capabilities: 63}
						body, err := contract.EncodeNormalOutputBinding(contract.NormalOutputBinding{DestinationID: id, Destination: destination, Targets: baseline[id]})
						if err != nil {
							t.Fatal(err)
						}
						records[id] = body
						configurationCanonicalBacking(generated, "outputs", id, body)
						destinations[id] = map[string]any{"plugin": "private-output", "canonical": map[string]any{"settings": json.RawMessage(destination.CanonicalSettings)}}
					}
					editable["outputs"] = map[string]any{"destinations": destinations, "routing": map[string]any{"default": defaults, "entries": overrides}}
				})
				beforeFiles := configurationApplySourceImage(t, filepath.Dir(source.path))
				model, err := configuration.Parse(t.Context(), source.pair)
				if err != nil {
					t.Fatal(err)
				}
				for _, binding := range model.Public.OutputBindings.Value {
					want := contract.PublicPresent
					if slices.Contains(condition.unavailable, binding.DestinationID) {
						want = contract.PublicUnavailable
					}
					if binding.Targets.State != want || want == contract.PublicUnavailable && binding.Targets.Value != nil {
						t.Fatal("saved targets claimed a different proposed target set", binding.DestinationID)
					}
				}
				var calls []string
				validator := core.NewPublicConfigurationValidator(func(_ context.Context, id string, destination contract.OutputDestination, name string, encoding uint8) (contract.OutputTarget, error) {
					key := id + "/" + name
					calls = append(calls, key)
					value, present := known[key]
					if !present || encoding != contract.OutputEncodingRaw || destination.ServiceContractID != id || string(destination.CanonicalSettings) != `{"n":1.00}` {
						return contract.OutputTarget{}, contract.ErrRecord
					}
					return value, nil
				})
				validated := validator.Validate(t.Context(), model.Public)
				if !validated.Valid || !validated.Complete || !validated.DiagnosticsComplete || len(validated.Diagnostics) != 0 || !slices.Equal(calls, condition.calls) {
					t.Fatal("current routing did not derive its complete target set", validated.Diagnostics, calls)
				}
				for _, binding := range model.Outputs {
					body, err := contract.EncodeNormalOutputBinding(binding.Binding)
					if err != nil || !bytes.Equal(body, records[binding.DestinationID]) {
						t.Fatal("projection changed exact canonical backing", err)
					}
				}
				if len(validated.Configuration.OutputBindings.Value) != 3 {
					t.Fatal("routing edit changed the destination set")
				}
				wanted := map[string][]string{"fixed": {"FIXED"}, "gcp": condition.gcp, "repository": condition.repository}
				for _, binding := range validated.Configuration.OutputBindings.Value {
					var names []string
					for _, value := range binding.Targets.Value {
						names = append(names, value.EntryName)
					}
					if !slices.Equal(names, wanted[binding.DestinationID]) {
						t.Fatal("routing edit produced a different complete target set", binding.DestinationID, names)
					}
					for _, value := range binding.Targets.Value {
						if !reflect.DeepEqual(configurationCanonicalTarget(value), known[binding.DestinationID+"/"+value.EntryName]) {
							t.Fatal("derived target fields or unaffected canonical facts changed")
						}
					}
				}
				configurationApplyAssertUnchanged(t, filepath.Dir(source.path), beforeFiles)
			})
		}
	}
}

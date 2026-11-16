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

func configurationMissingInputPair(t *testing.T, format configuration.Format, names []string) configurationReaderSource {
	t.Helper()
	return configurationSetPair(t, "aws", format, func(editable, generated map[string]any) {
		entries := make(map[string]any, len(names))
		for _, name := range names {
			entries[name] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": map[string]any{"kind": "supplied"}}
		}
		editable["entries"] = entries
		editable["outputs"] = map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}, "groups": []any{}}
		generated["secrets"] = map[string]any{}
		delete(generated, "canonical_records")
	})
}

func configurationMissingInputRecords(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var image struct {
		Secrets map[string]json.RawMessage `json:"secrets"`
	}
	if err := json.Unmarshal(body, &image); err != nil || image.Secrets == nil {
		t.Fatal("generated input map is not a closed object", err)
	}
	for name, record := range image.Secrets {
		var fields map[string]json.RawMessage
		var sealed []byte
		if json.Unmarshal(record, &fields) != nil || len(fields) != 1 || json.Unmarshal(fields["sealed"], &sealed) != nil || len(sealed) == 0 {
			t.Fatal("record is not a real sealed input", name)
		}
	}
	return image.Secrets
}

func configurationMissingInputsStayStrict(t *testing.T, path string, format configuration.Format) {
	t.Helper()
	pair, err := configuration.Capture(t.Context(), path, format)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := pair.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := configuration.Parse(t.Context(), pair); err == nil {
		t.Fatal("ordinary source parse accepted a missing supplied input")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	opens := 0
	refusal := errors.New("unexpected missing-input consumer construction")
	applied := applyConfiguration(ctx, contract.ID{0x51}, pair, func(context.Context, *configuration.Model, core.ApplyInstallation, *configurationInstalledPlugins) (*core.InstalledApply, error) {
		opens++
		return nil, refusal
	})
	planned := planConfiguration(ctx, contract.ID{0x52}, pair, nil, contract.PlanningOptions{Purpose: contract.PlanningEquality}, nil, func(context.Context, PlanningConfig) (*core.InstalledPlanning, error) {
		opens++
		return nil, refusal
	})
	outPath := filepath.Join(t.TempDir(), "application.env")
	materialized := materializeConfiguration(ctx, contract.MaterializationRequest{RequestNonce: contract.ID{0x53}, Names: []string{""}}, pair, outPath, func(context.Context, MaterializationConfig) (*core.InstalledMaterialization, error) {
		opens++
		return nil, refusal
	})
	if opens != 0 || applied.Result.Outcome != core.AdmissionRefused || planned.Result.Outcome != core.AdmissionRefused || materialized.StateResult != contract.MaterializationRefused || applied.PreAdmission == nil || planned.PreAdmission == nil || materialized.PreAdmission == nil || applied.PreAdmission.Stage != "parse" || planned.PreAdmission.Stage != "parse" || materialized.PreAdmission.Stage != "parse" {
		t.Fatal("ordinary consumer did not refuse at complete-pair parsing", opens, applied.PreAdmission, planned.PreAdmission, materialized.PreAdmission)
	}
	if _, err := os.Lstat(outPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("materialization created output before complete input admission", err)
	}
}

// full_only: false
func TestConfigurationSetFillsMissingInputsIndependently(t *testing.T) {
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		for _, order := range [][]string{{"", "sibling"}, {"sibling", ""}} {
			t.Run(fmt.Sprintf("%d/%q-first", format, order[0]), func(t *testing.T) {
				source := configurationMissingInputPair(t, format, []string{"", "sibling"})
				configurationSetWritable(t, source)
				configurationMissingInputsStayStrict(t, source.path, format)
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				previous := map[string]json.RawMessage{}
				for step, name := range order {
					value := []byte("actual input for " + name)
					input := &configurationSetInput{Reader: bytes.NewReader(value)}
					result, err := SetConfiguration(ctx, source.path, format, name, input, SetOptions{Confidential: true})
					if err != nil || result == nil || result.StateResult != SetSuccess {
						t.Fatal("targeted set could not fill one missing input", name, err)
					}
					if input.closes != 1 || input.reads == 0 {
						t.Fatal("targeted input ownership differs")
					}
					records := configurationMissingInputRecords(t, source.generated)
					if len(records) != step+1 || records[name] == nil {
						t.Fatal("targeted set invented missing sibling records or lost its selected record")
					}
					for sibling, record := range previous {
						if !bytes.Equal(record, records[sibling]) {
							t.Fatal("later set changed a previously supplied input", sibling)
						}
					}
					previous = records
					if step == 0 {
						configurationMissingInputsStayStrict(t, source.path, format)
					}
				}
				model := configurationSetModel(t, source.path, format)
				if len(model.Entries) != 2 {
					t.Fatal("completed pair changed the desired entry set")
				}
				for _, name := range []string{"", "sibling"} {
					entry := configurationSetEntry(t, model, name)
					view, err := contract.DecodeSealedInputEnvelope(entry.Sealed)
					if err != nil || !entry.Secret || entry.Generated != nil || entry.Retained != nil || view.Core.Name != name || view.Core.ContentLength != uint32(len("actual input for "+name)) {
						t.Fatal("completed pair has wrong supplied-input association", name, err)
					}
				}
			})
		}
	}
}

// full_only: false
func TestConfigurationSetChargesOnlyPresentInputsAtCapacity(t *testing.T) {
	names := make([]string, 512)
	for i := range names {
		names[i] = fmt.Sprintf("missing-%03d", i)
	}
	source := configurationMissingInputPair(t, configuration.JSON, names)
	configurationSetWritable(t, source)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	input := &configurationSetInput{Reader: bytes.NewReader(bytes.Repeat([]byte{0xa7}, 65536))}
	result, err := SetConfiguration(ctx, source.path, configuration.JSON, names[0], input, SetOptions{Confidential: true})
	if err != nil || result == nil || result.StateResult != SetSuccess || input.reads == 0 || input.closes != 1 {
		t.Fatal("absent siblings consumed capacity for real selected input", err)
	}
	records := configurationMissingInputRecords(t, source.generated)
	if len(records) != 1 || records[names[0]] == nil {
		t.Fatal("capacity set fabricated records for absent sibling inputs")
	}
	configurationMissingInputsStayStrict(t, source.path, configuration.JSON)
}

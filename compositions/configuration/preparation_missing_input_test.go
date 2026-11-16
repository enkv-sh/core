package configuration

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"
)

// full_only: false
func TestSetPreparationKeepsCompleteMissingInputSet(t *testing.T) {
	for _, count := range []int{2, 512} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			entries := make(map[string]any, count)
			for i := 0; i < count; i++ {
				name := ""
				if i != 0 {
					name = fmt.Sprintf("missing-%03d", i)
				}
				entries[name] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": map[string]any{"kind": "supplied"}}
			}
			body, err := json.Marshal(entries)
			if err != nil {
				t.Fatal(err)
			}
			editable := strings.Replace(sourceSetupJSON, `"entries":{}`, `"entries":`+string(body), 1)
			pair := writePair(t, editable, sourceGeneratedJSON, JSON)
			wantMissing := make([]string, 0, count)
			for name := range entries {
				wantMissing = append(wantMissing, name)
			}
			sort.Strings(wantMissing)
			if ordinary, err := Parse(t.Context(), pair); err == nil {
				if ordinary != nil {
					releaseReconstructionModel(ordinary)
				}
				t.Fatal("ordinary admission accepted absent supplied-input records")
			}
			for _, selected := range []string{"", "missing-001"} {
				t.Run(fmt.Sprintf("selected-%q", selected), func(t *testing.T) {
					model, err := ParseForSet(t.Context(), pair, selected)
					if err != nil {
						t.Fatal("targeted preparation refused an independently missing sibling", err)
					}
					defer releaseReconstructionModel(model)
					if !model.Resolved || len(model.Entries) != count || model.SelectedSecretPresent || !slices.Equal(model.MissingInputs, wantMissing) {
						t.Fatal("preparation lost the complete declaration or invented selected input")
					}
					seen := make(map[string]bool, count)
					for _, entry := range model.Entries {
						if _, expected := entries[entry.Name]; !expected || seen[entry.Name] || !entry.Secret || entry.Generated != nil || entry.Retained != nil || len(entry.Sealed) != 0 {
							t.Fatal("preparation invented a record or changed a missing entry", entry.Name)
						}
						seen[entry.Name] = true
					}
				})
			}
		})
	}
}

// full_only: false
func TestSetPreparationValidatesEveryPresentInputRecord(t *testing.T) {
	secret := `{"confidentiality":"secret","recipients":[],"source":{"kind":"supplied"}}`
	editable := strings.Replace(sourceSetupJSON, `"entries":{}`, `"entries":{"selected":`+secret+`,"sibling":`+secret+`}`, 1)
	for _, name := range []string{"selected", "sibling"} {
		for _, row := range []string{`{}`, `{"missing":true}`, `{"sealed":"AQ=="}`, `{"retained":{"incarnation":"` + sourceID4 + `","material":"` + sourceID5 + `"},"sealed":"AQ=="}`} {
			t.Run(name+"/"+row, func(t *testing.T) {
				generated := strings.Replace(sourceGeneratedJSON, `"secrets":{}`, `"secrets":{"`+name+`":`+row+`}`, 1)
				model, err := ParseForSet(t.Context(), writePair(t, editable, generated, JSON), "selected")
				if model != nil {
					releaseReconstructionModel(model)
				}
				if err == nil {
					t.Fatal("preparation hid malformed present input behind the missing set")
				}
			})
		}
	}
}

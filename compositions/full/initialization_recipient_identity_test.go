package compositionfull

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
)

// full_only: false
func TestInitializationWritesAllocatedSourceRecipientIdentity(t *testing.T) {
	for _, layout := range []string{"json", "yaml-flow", "yaml-block"} {
		t.Run(layout, func(t *testing.T) {
			body := initializationSetupSource(t, "aws", false, false)
			format := configuration.JSON
			if layout != "json" {
				format = configuration.YAML
			}
			if layout == "yaml-block" {
				var source map[string]any
				if err := json.Unmarshal(body, &source); err != nil {
					t.Fatal(err)
				}
				var block strings.Builder
				for _, name := range []string{"schema", "domain"} {
					value, err := json.Marshal(source[name])
					if err != nil {
						t.Fatal(err)
					}
					fmt.Fprintf(&block, "%s: %s\n", name, value)
				}
				recipient := source["recipients"].(map[string]any)["recipient"].(map[string]any)
				fmt.Fprintf(&block, "recipients:\n  recipient:\n    display_name: Recipient # preserve recipient metadata\n    encryption_key: %s\nentries: {}\noutputs: {destinations: {}, routing: {}}\n", recipient["encryption_key"])
				body = []byte(block.String())
			}
			path := filepath.Join(t.TempDir(), "configuration")
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			pair, err := configuration.Capture(t.Context(), path, format)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := pair.Close(); err != nil {
					t.Error(err)
				}
			}()
			model, err := configuration.Parse(t.Context(), pair)
			if err != nil || model.Resolved || len(model.Recipients) != 1 {
				t.Fatal("unprepared recipient fixture refused", err)
			}
			// This fixed ID stands for the initializer's already allocated ID.
			// No allocation, provider lookup or infrastructure effect is needed.
			model.Recipients[0].ID = contract.ID{6}
			wantID := hex.EncodeToString(model.Recipients[0].ID[:])
			var emitted bytes.Buffer
			if err := emitInitializationReference(t.Context(), &emitted, pair.Editable, format, model, ".enkv/prod.generated.json"); err != nil {
				t.Fatal(err)
			}
			if layout == "json" {
				var source struct {
					Recipients map[string]struct {
						ID string `json:"id"`
					} `json:"recipients"`
				}
				if err := json.Unmarshal(emitted.Bytes(), &source); err != nil || source.Recipients["recipient"].ID != wantID {
					t.Fatal("initialization omitted its allocated source recipient ID", err)
				}
			} else if !strings.Contains(emitted.String(), `id: "`+wantID+`"`) {
				t.Fatal("initialization omitted its allocated YAML source recipient ID")
			}
			if layout == "yaml-block" && !strings.Contains(emitted.String(), "# preserve recipient metadata") {
				t.Fatal("initialization changed unrelated recipient metadata")
			}
			if original, err := os.ReadFile(path); err != nil || !bytes.Equal(original, body) {
				t.Fatal("editable emission changed the original file", err)
			}
		})
	}
}

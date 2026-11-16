package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
)

// full_only: false
func TestConfigurationSetCanonicalConversionStagesCompanion(t *testing.T) {
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		for _, confidential := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%t", format, confidential), func(t *testing.T) {
				source := configurationSetPair(t, "aws", format, func(editable, generated map[string]any) {
					entries := editable["entries"].(map[string]any)
					routes := editable["outputs"].(map[string]any)["routing"].(map[string]any)["entries"].(map[string]any)
					for _, name := range []string{"convert", "keep"} {
						entries[name] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": dependencyCanonicalGeneratorSource(generated, name, false)}
						routes[name] = []string{}
					}
				})
				configurationSetWritable(t, source)
				readRecords := func() map[string]map[string]string {
					t.Helper()
					body, err := os.ReadFile(source.generated)
					if err != nil {
						t.Fatal(err)
					}
					var carrier struct {
						Records map[string]map[string]string `json:"canonical_records"`
					}
					if err := json.Unmarshal(body, &carrier); err != nil {
						t.Fatal(err)
					}
					return carrier.Records
				}
				before := readRecords()
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				checked := validateInstalledConfiguration(ctx, configurationSetModel(t, source.path, format).Public)
				if !checked.Valid || !checked.DiagnosticsComplete {
					t.Fatalf("Set fixture public facts invalid: %+v", checked.Diagnostics)
				}
				value := []byte("new supplied input")
				input := &configurationSetInput{Reader: bytes.NewReader(value)}
				result, err := SetConfiguration(ctx, source.path, format, "convert", input, SetOptions{Confidential: confidential})
				if err != nil {
					t.Fatal(err)
				}
				if result.GeneratedPath != source.generated || input.closes != 1 || input.reads == 0 {
					t.Fatal("companion delivery or input ownership differs")
				}
				after := readRecords()
				delete(before["generators"], "convert")
				if !reflect.DeepEqual(after, before) {
					t.Fatal("selected canonical backing retained or other exact records changed")
				}
				m := configurationSetModel(t, source.path, format)
				entry := configurationSetEntry(t, m, "convert")
				if entry.Generated != nil || entry.Secret != confidential || !confidential && !bytes.Equal(entry.Plain, value) || confidential && len(entry.Sealed) == 0 {
					t.Fatal("delivered supplied entry differs")
				}
				if !bytes.Equal(configurationSetEntry(t, m, "keep").Generated.Intent, dependencyCanonicalIntent(false)) {
					t.Fatal("unselected exact generator intent changed")
				}
			})
		}
	}
}

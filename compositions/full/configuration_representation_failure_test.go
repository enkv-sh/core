package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
)

// full_only: false
func TestSetRepresentationRefusalKeepsSafeSourceFailure(t *testing.T) {
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		for _, row := range []struct{ encoding, value, reason string }{
			{"rot13", "private-source-value-must-not-appear", "invalid-encoding"},
			{"base64", "YR==", "invalid-input-representation"},
		} {
			t.Run(fmt.Sprintf("%d/%s", format, row.reason), func(t *testing.T) {
				const name = "private-entry-name-must-not-appear"
				validSource := map[string]any{"kind": "supplied", "encoding": "raw", "value": "unique-valid-source-placeholder"}
				source := configurationSetPair(t, "aws", format, func(editable, _ map[string]any) {
					editable["entries"].(map[string]any)[name] = map[string]any{
						"confidentiality": "plain", "recipients": []any{},
						"source": validSource,
					}
				})
				configurationSetWritable(t, source)
				before, err := json.Marshal(validSource)
				if err != nil {
					t.Fatal(err)
				}
				after, err := json.Marshal(map[string]any{"kind": "supplied", "encoding": row.encoding, "value": row.value})
				if err != nil || bytes.Count(source.editableBytes, before) != 1 {
					t.Fatal("source damage must select exactly one entry", err)
				}
				if err := os.Chmod(source.path, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(source.path, bytes.Replace(source.editableBytes, before, after, 1), 0600); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				input := &configurationSetInput{Reader: strings.NewReader("unread-input-must-not-appear")}
				result, failure := SetConfiguration(ctx, source.path, format, "target", input, SetOptions{})
				var diagnostic *configuration.Diagnostic
				if !errors.As(failure, &diagnostic) || diagnostic.Reason != row.reason || input.reads != 0 || input.closes != 1 {
					t.Fatal("representation refusal lost its source cause or input ownership", failure, input.reads, input.closes)
				}
				body, err := RenderSetJSON(result, failure)
				var wire struct {
					SourceFailure *ConfigurationSourceFailure `json:"source_failure"`
				}
				if err != nil || json.Unmarshal(body, &wire) != nil || wire.SourceFailure == nil || wire.SourceFailure.SourceID != "source" || wire.SourceFailure.Reason != row.reason {
					t.Fatal("representation refusal cannot render its safe source facts", err)
				}
				human, err := RenderSetHuman(result, failure)
				if err != nil || !strings.Contains(string(human), "Input source: "+row.reason) {
					t.Fatal("human representation refusal lost its source facts", err)
				}
				for _, rendered := range []string{string(body), string(human)} {
					for _, excluded := range []string{name, row.value, "unread-input-must-not-appear"} {
						if strings.Contains(rendered, excluded) {
							t.Fatal("representation diagnostic disclosed source content")
						}
					}
				}
			})
		}
	}
}

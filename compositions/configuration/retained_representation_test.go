package configuration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// full_only: false
func TestSourceRetainedInputAndSharedOutputMatrix(t *testing.T) {
	for _, format := range []Format{JSON, YAML} {
		for _, tc := range []struct {
			name, input, output, retained string
		}{
			{"raw-raw", "raw", "raw", "ABC"},
			{"raw-base64", "raw", "base64", "ABC"},
			{"base64-raw", "base64", "raw", "QUJD"},
			{"base64-base64", "base64", "base64", "QUJD"},
			{"raw-literal-base64-text", "raw", "raw", "QUJD"},
		} {
			fields := []string{`"kind":"supplied"`, fmt.Sprintf(`"encoding":%q`, tc.input), fmt.Sprintf(`"value":%q`, tc.retained)}
			for order, indexes := range [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
				t.Run(fmt.Sprintf("%d/%s/order-%d", format, tc.name, order), func(t *testing.T) {
					source := "{" + fields[indexes[0]] + "," + fields[indexes[1]] + "," + fields[indexes[2]] + "}"
					row := fmt.Sprintf(`{"confidentiality":"plain","recipients":[],"source":%s,"output_encoding":%q}`, source, tc.output)
					if order%2 != 0 {
						row = fmt.Sprintf(`{"output_encoding":%q,"source":%s,"recipients":[],"confidentiality":"plain"}`, tc.output, source)
					}
					editable := strings.Replace(sourceSetupJSON, `"entries":{}`, `"entries":{"VALUE":`+row+`}`, 1)
					pair := writePair(t, editable, "", format)
					model, err := Parse(context.Background(), pair)
					if err != nil {
						t.Fatal("explicit input/output representation refused", err)
					}
					if len(model.Entries) != 1 || !bytes.Equal(model.Entries[0].Plain, []byte(tc.retained)) {
						t.Fatal("source parsing transcoded exact retained bytes")
					}
				})
			}
		}
		for _, source := range []string{`{"kind":"supplied","value":"QUJD"}`, `{"value":"QUJD","kind":"supplied","encoding":"raw"}`, `{"bytes":"UVVKRA==","encoding":"raw","kind":"supplied"}`} {
			t.Run(fmt.Sprintf("%d/raw-default/%s", format, source), func(t *testing.T) {
				row := `{"source":` + source + `,"recipients":[],"confidentiality":"plain"}`
				editable := strings.Replace(sourceSetupJSON, `"entries":{}`, `"entries":{"VALUE":`+row+`}`, 1)
				model, err := Parse(context.Background(), writePair(t, editable, "", format))
				if err != nil || len(model.Entries) != 1 || !bytes.Equal(model.Entries[0].Plain, []byte("QUJD")) {
					t.Fatal("raw omission or bytes carrier changed retained content", err)
				}
			})
		}
	}
}

// full_only: false
func TestSourceRepresentationRefusesAmbiguousOrInvalidInput(t *testing.T) {
	for _, source := range []string{
		`{"kind":"supplied","encoding":"base64","value":"YR=="}`,
		`{"value":"YR==","kind":"supplied","encoding":"base64"}`,
		`{"value":"YQ","encoding":"base64","kind":"supplied"}`,
		`{"encoding":"base64","value":"Y Q=","kind":"supplied"}`,
		`{"kind":"supplied","encoding":"base64","value":"YQ==="}`,
		`{"value":"____","kind":"supplied","encoding":"base64"}`,
		`{"value":"YQ==","encoding":"base64","bytes":"YQ==","kind":"supplied"}`,
		`{"kind":"supplied","encoding":"raw","encoding":"base64","value":"YQ=="}`,
		`{"kind":"supplied","encoding":"base64","value":"YQ==\n"}`,
		`{"kind":"supplied","encoding":"base64","bytes":"YQ=="}`,
		`{"kind":"supplied","encoding":"base64url","value":"YQ=="}`,
		`{"kind":"supplied","encoding":"","value":"YQ=="}`,
		`{"kind":"supplied","encoding":2,"value":"YQ=="}`,
	} {
		t.Run(source, func(t *testing.T) {
			row := `{"confidentiality":"plain","recipients":[],"source":` + source + `}`
			editable := strings.Replace(sourceSetupJSON, `"entries":{}`, `"entries":{"VALUE":`+row+`}`, 1)
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(editable), 0600); err != nil {
				t.Fatal(err)
			}
			image, err := capture(context.Background(), path, MaxPairBytes)
			if err != nil {
				t.Fatal(err)
			}
			pair := &Pair{Editable: image, Format: JSON}
			defer func() {
				if err := pair.Close(); err != nil {
					t.Error(err)
				}
			}()
			if err := sealPair(pair); err != nil {
				t.Fatal(err)
			}
			if _, err := Parse(context.Background(), pair); !errors.Is(err, ErrSourceInvalid) {
				t.Fatal("invalid representation did not produce a source grammar refusal", err)
			}
		})
	}
}

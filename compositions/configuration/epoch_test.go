package configuration

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
)

func epochEditable(format Format, name string, epoch uint64) string {
	entries := `{` + strconv.Quote(name) + `:{"confidentiality":"secret","recipients":[],"source":{"settings":` + pluginSettings + `,"epoch":` + strconv.FormatUint(epoch, 10) + `,"retirement":"manual","plugin":"private-generator","kind":"generated"}}}`
	if format == JSON {
		return strings.Replace(sourceSetupJSON, `"entries":{}`, `"entries":`+entries, 1)
	}
	return strings.Replace(sourceSetupYAML, "entries: {}", "entries: "+entries+" # preserve epoch comment", 1)
}

// full_only: false
func TestGeneratedEpochParsingPreservesDeclaredValue(t *testing.T) {
	for _, format := range []Format{JSON, YAML} {
		for _, name := range []string{"token", ""} {
			for _, epoch := range []uint64{0, 41, math.MaxUint64} {
				for _, generated := range []string{"", sourceGeneratedJSON} {
					t.Run(fmt.Sprintf("%d/%q/%d/resolved-%t", format, name, epoch, generated != ""), func(t *testing.T) {
						pair := writePair(t, epochEditable(format, name, epoch), generated, format)
						model, err := Parse(t.Context(), pair)
						if err != nil || len(model.Entries) != 1 || model.Entries[0].Name != name || model.Entries[0].Generated == nil || model.Entries[0].Generated.Epoch != epoch || model.Resolved != (generated != "") {
							t.Fatal("declared generated epoch did not parse exactly", err)
						}
					})
				}
			}
		}
	}
}

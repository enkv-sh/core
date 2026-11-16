package configuration

import (
	"strings"
	"testing"
)

// full_only: false
func TestPluginSettingsDepthIsIndependentOfOuterSource(t *testing.T) {
	for _, format := range []Format{JSON, YAML} {
		t.Run(map[Format]string{JSON: "json", YAML: "yaml"}[format], func(t *testing.T) {
			exact := strings.Repeat("[", 10000) + "1.00" + strings.Repeat("]", 10000)
			p := newParser(t.Context(), strings.NewReader(exact), format)
			p.depth = MaxDepth
			got := parseSettings(p, 393145)
			if err := p.done(); err != nil || string(got) != exact {
				t.Fatalf("admitted settings nesting reduced: length=%d: %v", len(got), err)
			}
			if p.depth != MaxDepth {
				t.Fatal("settings traversal changed outer structural depth")
			}
		})
	}
}

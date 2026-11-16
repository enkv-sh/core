package configuration

import (
	"bytes"
	"strings"
	"testing"
)

// full_only: false
func TestSettingsTraversalKeepsReadableTypesAndTokens(t *testing.T) {
	for _, tc := range []struct {
		name, source, want string
		format             Format
	}{
		{"json", `{"null":null,"bool":true,"text":"null","n":1.00,"list":[{},[],false]}`, `{"null":null,"bool":true,"text":"null","n":1.00,"list":[{},[],false]}`, JSON},
		{"yaml_flow", `{"null": null, "bool": true, "text": "null", "n": 1.00, "list": [{}, [], false]}`, `{"null":null,"bool":true,"text":"null","n":1.00,"list":[{},[],false]}`, YAML},
		{"yaml_block", "\"null\": null\nbool: true\ntext: \"null\"\nn: 1.00\nlist:\n  - {}\n  - []\n  - false\n", `{"null":null,"bool":true,"text":"null","n":1.00,"list":[{},[],false]}`, YAML},
		{"yaml_nested_mapping", "tree:\n  before: 1.00\n  after:\n    - nested: \"x\"\n      empty: {}\n", `{"tree":{"before":1.00,"after":[{"nested":"x","empty":{}}]}}`, YAML},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newParser(t.Context(), strings.NewReader(tc.source), tc.format)
			got := parseSettingsIterative(p, 393145)
			if err := p.done(); err != nil || string(got) != tc.want {
				t.Fatalf("converted=%q want=%q: %v", got, tc.want, err)
			}
		})
	}
	for _, source := range []string{`{"a":{"x":1,"\u0078":2}}`, `"\ud800"`, `[1,]`, `{"x":1,}`, "x:\nvalue: 1\n"} {
		p := newParser(t.Context(), strings.NewReader(source), JSON)
		parseSettingsIterative(p, 393145)
		if p.done() == nil {
			t.Fatal("invalid settings accepted")
		}
	}
}

// full_only: false
func TestSettingsViewCountsAndEmitsReadableNestedValues(t *testing.T) {
	exact := []byte(`{"n":1.00,"list":[null,{},[]],"text":"\u0078"}`)
	for _, format := range []Format{JSON, YAML} {
		t.Run(map[Format]string{JSON: "json", YAML: "yaml"}[format], func(t *testing.T) {
			var output bytes.Buffer
			writer := editableWriter{generatedWriter: generatedWriter{out: &output}, format: format, level: 1}
			writer.frames[0].first = true
			writer.item("settings")
			writer.settingsValueIterative(exact, 393145)
			if writer.err != nil {
				t.Fatal(writer.err)
			}
			source := output.String()
			if format == JSON {
				source = "{" + source + "\n}"
			}
			p := newParser(t.Context(), strings.NewReader(source), format)
			var got []byte
			p.object(1, func(key string) {
				if key != "settings" {
					t.Fatal("wrong emitted field")
				}
				got = parseSettingsIterative(p, 393145)
			})
			if err := p.done(); err != nil || string(got) != `{"n":1.00,"list":[null,{},[]],"text":"x"}` {
				t.Fatalf("emission failed to reparse: %q: %v", got, err)
			}
			if !strings.Contains(source, "\n") {
				t.Fatal("nested view is not readable")
			}
		})
	}
}

// full_only: false
func TestSettingsViewRefusesOversizedReadableExpansionBeforeWriting(t *testing.T) {
	exact := []byte(strings.Repeat("[", 9999) + "[" + strings.Repeat("0,", 9999) + "0]" + strings.Repeat("]", 9999))
	for _, format := range []Format{JSON, YAML} {
		t.Run(map[Format]string{JSON: "json", YAML: "yaml"}[format], func(t *testing.T) {
			var output bytes.Buffer
			writer := editableWriter{generatedWriter: generatedWriter{out: &output}, format: format, level: 5}
			writer.settingsValueIterative(exact, 393145)
			if writer.err == nil || output.Len() != 0 || !strings.Contains(writer.err.Error(), "pair-size-limit") {
				t.Fatal("oversized readable settings did not refuse before output", output.Len(), writer.err)
			}
		})
	}
}

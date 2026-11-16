package configuration

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const pluginSettings = `{"opaque":{"names":["one","two"],"enabled":true},"limit":9007199254740993}`

// full_only: false
func TestPluginSettingsPreserveCommonJSONValues(t *testing.T) {
	for _, tc := range []struct {
		name, source, want string
		format             Format
	}{
		{"json", `{"list":[true,false,null,-1.25e+8,9007199254740993],"text":"\u0061"}`, `{"list":[true,false,null,-1.25e+8,9007199254740993],"text":"a"}`, JSON},
		{"yaml-flow", `{list: [true, false, null, -1.25e+8, 9007199254740993], text: a}`, `{"list":[true,false,null,-1.25e+8,9007199254740993],"text":"a"}`, YAML},
		{"yaml-block", "list:\n  - true\n  - null\ntext: |-\n  first\n  second\n", `{"list":[true,null],"text":"first\nsecond"}`, YAML},
		{"yaml-quoted", "\"text\": \"null\"\n", `{"text":"null"}`, YAML},
		{"yaml-null", "~", `null`, YAML},
		{"long-key", `{"` + strings.Repeat("k", 300) + `":0}`, `{"` + strings.Repeat("k", 300) + `":0}`, JSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newParser(t.Context(), strings.NewReader(tc.source), tc.format)
			got := parseSettings(p, 4096)
			if err := p.done(); err != nil || string(got) != tc.want {
				t.Fatalf("settings %q, want %q, error %v", got, tc.want, err)
			}
		})
	}
}

// full_only: false
func TestPluginSettingsRejectInvalidSyntaxAndExcess(t *testing.T) {
	for _, source := range []string{`{"x":1,"\u0078":2}`, `[01]`, `{"x":}`, `[NaN]`, `"bad\uD800"`, strings.Repeat("[", 10001) + strings.Repeat("]", 10001)} {
		p := newParser(t.Context(), strings.NewReader(source), JSON)
		parseSettings(p, maxGeneratorSettings)
		if p.done() == nil {
			t.Fatalf("invalid settings accepted: %q", source)
		}
	}
	for _, extra := range []int{0, 1} {
		source := `"` + strings.Repeat("x", 1022+extra) + `"`
		p := newParser(t.Context(), strings.NewReader(source), JSON)
		got := parseSettings(p, 1024)
		err := p.done()
		if extra == 0 && (err != nil || !bytes.Equal(got, []byte(source))) || extra != 0 && (err == nil || len(got) != 0) {
			t.Fatal("complete encoded settings bound", extra, len(got), err)
		}
	}
}

// full_only: false
func TestGeneratorSourceRejectsInvalidCommonEnvelope(t *testing.T) {
	for _, source := range []string{
		`{"kind":"generated","epoch":0,"settings":{}}`,
		`{"kind":"generated","plugin":null,"epoch":0,"settings":{}}`,
		`{"kind":"generated","plugin":"","epoch":0,"settings":{}}`,
		`{"kind":"generated","plugin":"../private","epoch":0,"settings":{}}`,
		`{"kind":"generated","plugin":"private","epoch":0,"settings":{},"canonical":{"settings":{}}}`,
		`{"kind":"generated","plugin":"private","epoch":0,"settings":{},"retirement":"later"}`,
		`{"kind":"generated","generator":{"name":"old","version":"1"},"epoch":0,"spec":{}}`,
		`{"kind":"generated","plugin":"private","epoch":0,"settings":{},"path":"/tmp/plugin"}`,
	} {
		for _, format := range []Format{JSON, YAML} {
			entries := `{"private":{"confidentiality":"secret","recipients":[],"source":` + source + `}}`
			p := newParser(t.Context(), strings.NewReader(entries), format)
			parseEntries(p, &Model{})
			if p.done() == nil {
				t.Fatalf("invalid common source accepted: %s", source)
			}
		}
	}
}

// full_only: false
func TestPrivateGeneratorSelectionAndSettingsStaySourceLocal(t *testing.T) {
	name := strings.Repeat("p", 255)
	source := `{"private":{"confidentiality":"secret","recipients":[],"source":{"kind":"generated","plugin":"` + name + `","epoch":0,"settings":null}}}`
	for _, format := range []Format{JSON, YAML} {
		m := &Model{}
		p := newParser(t.Context(), strings.NewReader(source), format)
		parseEntries(p, m)
		if err := p.done(); err != nil || len(m.Entries) != 1 || m.Entries[0].Generated.Plugin != name || string(m.Entries[0].Generated.Settings) != "null" || m.Entries[0].Generated.Intent != nil {
			t.Fatal("new local selection or public JSON value refused", err)
		}
	}
}

// full_only: false
func TestPluginSettingsSequenceItemsRequireOwnedValues(t *testing.T) {
	for _, tc := range []struct {
		name, source, want string
		refuse             bool
	}{
		{"sibling-dashes", "-\n- a\n- b\n", "", true},
		{"comment-before-sibling", "- # absent item\n- a\n", "", true},
		{"empty-final-item", "- a\n-\n", "", true},
		{"dedented-key", "list:\n  -\nother: value\n", "", true},
		{"nested-array", "-\n  - a\n  - b\n", `[["a","b"]]`, false},
		{"compact-nested-array", "- - a\n  - b\n", `[["a","b"]]`, false},
		{"nested-object", "-\n  a: one\n  b: two\n", `[{"a":"one","b":"two"}]`, false},
		{"inline-array", "- [a, b]\n", `[["a","b"]]`, false},
		{"explicit-null", "- null\n", `[null]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newParser(t.Context(), strings.NewReader(tc.source), YAML)
			got := parseSettings(p, 1024)
			err := p.done()
			if tc.refuse {
				if !errors.Is(err, ErrSourceInvalid) {
					t.Fatal("absent sequence value acquired sibling content", string(got), err)
				}
			} else if err != nil || string(got) != tc.want {
				t.Fatal("owned nested settings changed", string(got), tc.want, err)
			}
		})
	}
}

// full_only: false
func TestPluginSettingsKeysUseSameRulesFirstAndLater(t *testing.T) {
	for _, tc := range []struct {
		name, source, want, reason string
	}{
		{"first-merge", "<<: value\n", "", "merge-forbidden"},
		{"later-merge", "first: value\n<<: other\n", "", "merge-forbidden"},
		{"flow-merge", "{<<: value}", "", "merge-forbidden"},
		{"first-quoted", "\"<<\": value\n", `{"<<":"value"}`, ""},
		{"single-quoted", "'<<': value\n", `{"<<":"value"}`, ""},
		{"later-quoted", "first: value\n\"<<\": other\n", `{"first":"value","<<":"other"}`, ""},
		{"flow-quoted", "{\"<<\": value}", `{"<<":"value"}`, ""},
		{"nested-merge", "outer:\n  <<: value\n", "", "merge-forbidden"},
		{"first-typed", "true: value\n", "", "string-required"},
		{"later-typed", "first: value\ntrue: other\n", "", "string-required"},
		{"duplicate", "first: value\nfirst: other\n", "", "duplicate-key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newParser(t.Context(), strings.NewReader(tc.source), YAML)
			got := parseSettings(p, 1024)
			err := p.done()
			if tc.reason != "" {
				var diagnostic *Diagnostic
				if !errors.Is(err, ErrSourceInvalid) || !errors.As(err, &diagnostic) || diagnostic.Reason != tc.reason {
					t.Fatal("settings key bypassed the common key rule", string(got), err)
				}
			} else if err != nil || string(got) != tc.want {
				t.Fatal("literal settings key changed", string(got), tc.want, err)
			}
		})
	}
}

// full_only: false
func TestPluginSelectorsPreserveSchemaScalarTypes(t *testing.T) {
	for _, text := range []string{"true", "false", "123", "00123", "1.5", "1e3", "0x2"} {
		for _, format := range []Format{YAML, JSON} {
			t.Run(fmt.Sprintf("%d/plain/%s", format, text), func(t *testing.T) {
				p := newParser(t.Context(), strings.NewReader(text), format)
				parsePluginSelection(p)
				if err := p.done(); !errors.Is(err, ErrSourceInvalid) {
					t.Fatal("typed selector became a local plugin ID", text, err)
				}
			})
			t.Run(fmt.Sprintf("%d/quoted/%s", format, text), func(t *testing.T) {
				p := newParser(t.Context(), strings.NewReader(`"`+text+`"`), format)
				if got := parsePluginSelection(p); p.done() != nil || got != text {
					t.Fatal("explicit textual plugin ID changed", got, p.err)
				}
			})
		}
	}
	for _, format := range []Format{YAML, JSON} {
		t.Run(fmt.Sprintf("%d/canonical-null", format), func(t *testing.T) {
			p := newParser(t.Context(), strings.NewReader("null"), format)
			if got := parsePluginSelection(p); p.done() != nil || got != "" {
				t.Fatal("explicit unset canonical selector changed", got, p.err)
			}
		})
	}
	for _, selector := range []string{"true", "123", "\"123\""} {
		for _, format := range []Format{YAML, JSON} {
			t.Run(fmt.Sprintf("%d/callers/%s", format, selector), func(t *testing.T) {
				entry := `{"token":{"confidentiality":"secret","recipients":[],"source":{"kind":"generated","plugin":` + selector + `,"epoch":0,"settings":{}}}}`
				p := newParser(t.Context(), strings.NewReader(entry), format)
				model := &Model{}
				parseEntries(p, model)
				err := p.done()
				if selector != `"123"` {
					if !errors.Is(err, ErrSourceInvalid) {
						t.Error("generated source admitted a typed selector", err)
					}
				} else if err != nil || len(model.Entries) != 1 || model.Entries[0].Generated.Plugin != "123" {
					t.Error("generated source changed a quoted selector", err)
				}
				p = newParser(t.Context(), strings.NewReader(`{"plugin":`+selector+`,"settings":{}}`), format)
				output, _ := parseOutputBinding(p, "destination")
				err = p.done()
				if selector != `"123"` {
					if !errors.Is(err, ErrSourceInvalid) {
						t.Error("output source admitted a typed selector", err)
					}
				} else if err != nil || output.Plugin != "123" {
					t.Error("output source changed a quoted selector", err)
				}
			})
		}
	}
}

// full_only: false
func TestPluginSettingsBooleanLookingTextKeepsItsType(t *testing.T) {
	for _, tc := range []struct{ name, source, want string }{
		{"capitalized", "[True, TRUE, False, FALSE]", `["True","TRUE","False","FALSE"]`},
		{"lowercase", "[true, false]", `[true,false]`},
		{"quoted", `["true", 'false']`, `["true","false"]`},
		{"nested", "outer:\n  - enabled: True\n    nested: [FALSE, false, true]\n  - False\n", `{"outer":[{"enabled":"True","nested":["FALSE",false,true]},"False"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newParser(t.Context(), strings.NewReader(tc.source), YAML)
			got := parseSettings(p, 1024)
			if err := p.done(); err != nil || string(got) != tc.want {
				t.Fatal("common settings changed a scalar type", string(got), tc.want, err)
			}
		})
	}
	const settings = `{value: True, list: [TRUE, False, FALSE, true, false], quoted: "true"}`
	const want = `{"value":"True","list":["TRUE","False","FALSE",true,false],"quoted":"true"}`
	model := &Model{}
	p := newParser(t.Context(), strings.NewReader(`{"token":{"confidentiality":"secret","recipients":[],"source":{"kind":"generated","plugin":"private-generator","epoch":0,"settings":`+settings+`}}}`), YAML)
	parseEntries(p, model)
	if err := p.done(); err != nil || len(model.Entries) != 1 || string(model.Entries[0].Generated.Settings) != want {
		t.Fatal("generator source changed common settings types", err)
	}
	p = newParser(t.Context(), strings.NewReader(`{"plugin":"private-output","settings":`+settings+`}`), YAML)
	output, _ := parseOutputBinding(p, "destination")
	if err := p.done(); err != nil || string(output.Settings) != want {
		t.Fatal("output source changed common settings types", err)
	}
}

// full_only: false
func TestPluginSettingsCommonSyntaxRefusesBeforeCaptureReturns(t *testing.T) {
	for _, tc := range []struct{ name, settings, reason string }{
		{"empty-sequence-item", "-\n- a\n- b\n", ""},
		{"first-merge-key", "<<: value\n", "merge-forbidden"},
		{"later-merge-key", "first: value\n<<: other\n", "merge-forbidden"},
	} {
		for _, output := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/output=%v", tc.name, output), func(t *testing.T) {
				settings := strings.ReplaceAll(strings.TrimSuffix(tc.settings, "\n"), "\n", "\n        ")
				declaration := "entries:\n  token:\n    confidentiality: secret\n    recipients: []\n    source:\n      kind: generated\n      plugin: private-generator\n      epoch: 0\n      settings:\n        " + settings + "\n"
				source := strings.Replace(sourceSetupYAML, "entries: {}\n", declaration, 1)
				field := "entries.item.source.settings"
				if output {
					settings = strings.ReplaceAll(strings.TrimSuffix(tc.settings, "\n"), "\n", "\n        ")
					declaration = "outputs:\n  destinations:\n    destination:\n      plugin: private-output\n      settings:\n        " + settings + "\n  routing: {}\n"
					source = strings.Replace(sourceSetupYAML, "outputs:\n  destinations: {}\n  routing: {}\n", declaration, 1)
					field = "outputs.destinations.item.settings"
				}
				path := filepath.Join(t.TempDir(), "configuration")
				if err := os.WriteFile(path, []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
				pair, err := Capture(t.Context(), path, YAML)
				if pair != nil {
					defer closeSourceOwner(t, pair)
				}
				var diagnostic *Diagnostic
				if pair != nil || !errors.Is(err, ErrSourceInvalid) || !errors.As(err, &diagnostic) || diagnostic.Field != field || tc.reason != "" && diagnostic.Reason != tc.reason {
					t.Fatal("common settings syntax escaped source admission", err)
				}
			})
		}
	}
}

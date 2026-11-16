package configuration

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestEditableYAMLStringSpellings(t *testing.T) {
	for _, tc := range []struct {
		name, value, want string
	}{
		{"ordinary", "ordinary text", "ordinary text"},
		{"empty", "", `""`},
		{"leading-space", " text", `" text"`},
		{"trailing-space", "text ", `"text "`},
		{"number", "00123", `"00123"`},
		{"decimal", "1.0e2", `"1.0e2"`},
		{"boolean", "true", `"true"`},
		{"null", "null", `"null"`},
		{"null-short", "~", `"~"`},
		{"indicator", "*alias", `"*alias"`},
		{"anchor", "&anchor", `"&anchor"`},
		{"tag", "!tag", `"!tag"`},
		{"directive", "%yaml", `"%yaml"`},
		{"literal", "|literal", `"|literal"`},
		{"folded", ">folded", `">folded"`},
		{"quoted-start", `'text`, `"'text"`},
		{"sequence", "-", `"-"`},
		{"question", "?", `"?"`},
		{"mapping", "a: b", `"a: b"`},
		{"colon", "a:", `"a:"`},
		{"comment", "a # b", `"a # b"`},
		{"hash", "a#b", "a#b"},
		{"quote", `a"b`, `a"b`},
		{"backslash", `a\b`, `a\b`},
		{"unicode", "雪", "雪"},
		{"internal-tab", "a\tb", "a\tb"},
		{"control", "a\x01b", `"a\u0001b"`},
		{"line-breaks", "a\r\nb", `"a\r\nb"`},
		{"block-delimiters", "a,b[c]{d}", "a,b[c]{d}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			w := &editableWriter{generatedWriter: generatedWriter{out: &out}, format: YAML}
			w.object("", 1, func() { w.text("value", tc.value) })
			if w.err != nil || out.String() != "value: "+tc.want+"\n" {
				t.Fatalf("spelling = %q, want %q; error: %v", out.String(), "value: "+tc.want+"\n", w.err)
			}
			p := newParser(t.Context(), strings.NewReader(out.String()), YAML)
			var got string
			p.object(1, func(key string) {
				if key != "value" {
					t.Fatalf("key = %q", key)
				}
				got = p.text(1024, false, false)
			})
			if err := p.done(); err != nil || got != tc.value {
				t.Fatalf("decoded = %q, want %q; error: %v", got, tc.value, err)
			}
		})
	}
}

// full_only: false
func TestYAMLBinaryStringSpellings(t *testing.T) {
	for _, tc := range []struct{ encoded, want string }{
		{"/wBB", "/wBB"},
		{"/w==", "/w=="},
		{"1234", `"1234"`},
		{"true", `"true"`},
		{"null", `"null"`},
		{"", `""`},
	} {
		t.Run(tc.encoded, func(t *testing.T) {
			body, err := base64.StdEncoding.Strict().DecodeString(tc.encoded)
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := emitYAMLPlainScalar(&out, body, true, false); err != nil || out.String() != tc.want {
				t.Fatalf("spelling = %q, want %q; error: %v", out.String(), tc.want, err)
			}
			p := newParser(t.Context(), strings.NewReader(out.String()), YAML)
			got := p.base64(1024)
			if err := p.done(); err != nil || !bytes.Equal(got, body) {
				t.Fatalf("binary value changed: %x, want %x; error: %v", got, body, err)
			}
		})
	}
	if err := emitYAMLPlainScalar(&shortGeneratedWriter{}, []byte("ordinary"), false, false); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("plain short write cause lost", err)
	}
	if err := emitYAMLPlainScalar(&shortGeneratedWriter{}, []byte{255, 0, 65}, true, false); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("binary short write cause lost", err)
	}
}

// full_only: false
func TestRecipientReferenceYAMLStringPositions(t *testing.T) {
	for _, layout := range []string{"block", "flow", "mixed"} {
		t.Run(layout, func(t *testing.T) {
			declarations := "recipients:\n  old:\n    id: \"" + preparedSourceRecipientID + "\"\n    display_name: Same label\n    encryption_key: " + sourceEncryptionSelector
			members := "\n      - old"
			if layout != "block" {
				members = " [old]"
			}
			if layout == "flow" {
				declarations = `recipients: {"old":{"id":"` + preparedSourceRecipientID + `","display_name":"Same label","encryption_key":"` + sourceEncryptionSelector + `"}}`
			}
			entry := "entries:\n  item:\n    confidentiality: plain\n    recipients:" + members + "\n    source: {kind: supplied, value: unchanged}"
			editable := strings.Replace(sourceSetupYAML, "recipients: {}", declarations, 1)
			editable = strings.Replace(editable, "entries: {}", entry, 1)
			generated := strings.Replace(sourceGeneratedJSON, `"recipients":{}`, `"recipients":{"old":`+preparationRecipientRow()+`}`, 1)
			pair := writePair(t, editable, generated, YAML)
			editable = string(maintenanceImageBytes(t, pair.Editable))
			edit, err := PrepareRecipientReferenceEdit(t.Context(), pair, "old", "a,b")
			if err != nil {
				t.Fatal(err)
			}
			var out, companion bytes.Buffer
			if err := edit.EmitEditable(t.Context(), &out, ".enkv/prod.generated.json"); err != nil {
				t.Fatal(err)
			}
			if err := edit.EmitGenerated(t.Context(), &companion); err != nil {
				t.Fatal(err)
			}
			want := strings.Replace(editable, "  old:", "  a,b:", 1)
			if layout == "flow" {
				want = strings.Replace(editable, `"old":`, `"a,b":`, 1)
			}
			if layout == "block" {
				want = strings.Replace(want, "- old", "- a,b", 1)
			} else {
				want = strings.Replace(want, "[old]", `["a,b"]`, 1)
			}
			if out.String() != want {
				t.Fatalf("position or unchanged bytes differ:\ngot: %s\nwant: %s", out.String(), want)
			}
			again, err := Parse(t.Context(), captureEditableEmission(t, out.Bytes(), companion.Bytes(), YAML, ".enkv/prod.generated.json"))
			if err != nil || len(again.Recipients) != 1 || again.Recipients[0].Reference != "a,b" || len(again.Entries) != 1 || len(again.Entries[0].Recipients) != 1 || again.Entries[0].Recipients[0] != "a,b" {
				t.Fatal("reference joins changed", err)
			}
		})
	}
}

// full_only: false
func TestSuppliedYAMLStringPositions(t *testing.T) {
	for _, tc := range []struct {
		name, source, value, want string
	}{
		{"block-delimiters", "\n      value: old\n      kind: supplied", "a,b[c]{d}", "value: a,b[c]{d}"},
		{"flow-delimiters", " {value: old, kind: supplied}", "a,b[c]{d}", `value: "a,b[c]{d}"`},
		{"block-ordinary", "\n      value: old\n      kind: supplied", "new text", "value: new text"},
		{"flow-ordinary", " {value: old, kind: supplied}", "new text", "value: new text"},
		{"block-numeric", "\n      value: old\n      kind: supplied", "00123", `value: "00123"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			class := "plain"
			if tc.name == "flow-ordinary" {
				class = `"plain"`
			}
			entry := "entries:\n  item:\n    confidentiality: " + class + " # keep class\n    recipients: []\n    source:" + tc.source + "\n"
			editable := strings.Replace(sourceSetupYAML, "entries: {}\n", entry, 1)
			pair := writePair(t, editable, sourceGeneratedJSON, YAML)
			editable = string(maintenanceImageBytes(t, pair.Editable))
			model, err := ParseForSet(t.Context(), pair, "item")
			if err != nil {
				t.Fatal(err)
			}
			edit, err := PrepareSuppliedEdit(pair, model, "item", false, contract.InputEncodingRaw)
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := edit.EmitEditable(t.Context(), &out, model.Generated, []byte(tc.value)); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), tc.want) || !strings.Contains(out.String(), "# keep class") {
				t.Fatalf("changed spelling or comment: %s", out.String())
			}
			if want := strings.Replace(editable, "value: old", tc.want, 1); out.String() != want {
				t.Fatalf("bytes outside the selected scalar changed:\ngot: %s\nwant: %s", out.String(), want)
			}
			again, err := Parse(t.Context(), captureEditableEmission(t, out.Bytes(), []byte(sourceGeneratedJSON), YAML, model.Generated))
			if err != nil || len(again.Entries) != 1 || string(again.Entries[0].Plain) != tc.value {
				t.Fatalf("changed value meaning: %v", err)
			}
		})
	}
}

// full_only: false
func TestYAMLStringKeyAndFlowPositions(t *testing.T) {
	for _, tc := range []struct {
		name, value, want string
		key, flow         bool
	}{
		{"block-key", "ordinary", "ordinary", true, false},
		{"merge-key", "<<", `"<<"`, true, false},
		{"merge-value", "<<", "<<", false, false},
		{"typed-key", "00123", `"00123"`, true, false},
		{"colon-key", "a:", "a:", true, false},
		{"indicator-key", "-", "-", true, false},
		{"flow-text", "ordinary text", "ordinary text", false, true},
		{"flow-delimiters", "a,b[c]{d}", `"a,b[c]{d}"`, false, true},
		{"block-key-delimiters", "a,b[c]{d}", "a,b[c]{d}", true, false},
		{"flow-key-delimiters", "a,b[c]{d}", `"a,b[c]{d}"`, true, true},
		{"flow-colon", "a:b", "a:b", false, true},
		{"flow-separated-colon", "a:,b", `"a:,b"`, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			w := &generatedWriter{out: &out}
			w.yamlString(tc.value, 1024, tc.key, tc.flow)
			if w.err != nil || out.String() != tc.want || w.count != int64(len(tc.want)) || yamlStringLength(tc.value, tc.key, tc.flow) != int64(len(tc.want)) {
				t.Fatalf("spelling = %q, want %q; error: %v", out.String(), tc.want, w.err)
			}
			body := "value: " + out.String()
			if tc.key {
				body = out.String() + ": value"
			}
			if tc.flow {
				body = "{" + body + "}"
			}
			p := newParser(t.Context(), strings.NewReader(body), YAML)
			var got string
			p.object(1, func(key string) {
				value := p.text(1024, false, false)
				got = value
				if tc.key {
					got = key
				}
			})
			if err := p.done(); err != nil || got != tc.value {
				t.Fatalf("decoded = %q, want %q; error: %v", got, tc.value, err)
			}
		})
	}
}

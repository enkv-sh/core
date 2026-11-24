package configuration

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"enkv.sh/core/contract"
)

const sourceSigningSelector = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-1111-1111-111111111111"
const sourceEncryptionSelector = "arn:aws:kms:us-east-1:123456789012:key/22222222-2222-2222-2222-222222222222"
const sourceSetupJSON = `{"schema":"enkv/configuration/v3","domain":{"name":"prod","provider":"aws","store":{"region":"us-east-1","bucket":"fixture-bucket","prefix":"fixture","expected_owner":"123456789012"},"authority":{"display_name":"","signing_key":"` + sourceSigningSelector + `","encryption_key":"` + sourceEncryptionSelector + `"},"recovery":{"enabled":false}},"recipients":{},"entries":{},"outputs":{"destinations":{},"routing":{}}}`
const sourceSetupYAML = `schema: enkv/configuration/v3
domain:
  name: prod
  provider: aws
  store:
    region: us-east-1
    bucket: fixture-bucket
    prefix: fixture
    expected_owner: '123456789012'
  authority:
    display_name: ''
    signing_key: ` + sourceSigningSelector + `
    encryption_key: ` + sourceEncryptionSelector + `
  recovery: {enabled: false}
recipients: {}
entries: {}
outputs:
  destinations: {}
  routing: {}
`
const sourceSigningSPKI = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQTzYWEkW1iOq4qApEvP1XY9AOHHdWk7mMxJdPPvdF8UC10LFN2Ca8RTA+Uy1nTwf1BBL7q+gidu39bDviUJEJw=="
const sourceEncryptionSPKI = "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEArQ4yfWElR37fxikvGbZTz0GfK0v2ONmOuRGQsVL3BpjA3L9bL0ehNVDl+Te5dvr/xuHnNAA/m/9JzKSgEC80BdkGvocFDWOpYzajbzOF0cq+TaAdQBW/5+6TIHzMIrfckTiHtCLaqWEHbLK9O7labv7Ly2BtNSDS+yCXVhzX2RqwkOntM2E3GDq1bLiT0ScfqBNru5w/dCdBl02xBRumsO4dEY1wjhL3Kzu1hkApV7hHdxy9wzkeuKEfNryvoaycMTQFPus0smOovV/rwviM17mbGXfNq5/foZJO8y0WnGjFBJOXA0mVC4brBo1ONNNvPg68opt2jguVl6z+T868lnt/TOPEkbgMgq3YwAGcTY3uMp052ryWk8AFCjDx3iiUghOLbHTUx30APvg4PszrtIh3/X9euECFR2GvtuKbVRbFupEt65MQoh5644hBJSfDqg/EIHHYEiDZeGcTLltjloujU672hr6bOg0w2b1HE4dMCPWYJhcy1GOKR/l2C5YhAgMBAAE="

// SPKIs are fixed public test literals. The one-byte basis is deliberately
// only source-shaped; it cannot pass Core's independent basis authentication.
const sourceGeneratedJSON = `{"schema":"enkv/generated/v2","file_id":"` + sourceID1 + `","domain":{"id":"` + sourceID2 + `","authority":{"id":"` + sourceID3 + `","signing":{"selector":"` + sourceSigningSelector + `","public_key":"` + sourceSigningSPKI + `"},"encryption":{"selector":"` + sourceEncryptionSelector + `","public_key":"` + sourceEncryptionSPKI + `","binding":{"id":"` + sourceID4 + `","incarnation":"` + sourceID5 + `","serial":1,"protection":"software"}}},"recovery":{"enabled":false}},"recipients":{},"secrets":{},"public_basis":{"kind":"genesis","descriptor":"AQ=="}}`
const sourceID1 = "0101010101010101010101010101010101010101010101010101010101010101"
const sourceID2 = "0202020202020202020202020202020202020202020202020202020202020202"
const sourceID3 = "0303030303030303030303030303030303030303030303030303030303030303"
const sourceID4 = "0404040404040404040404040404040404040404040404040404040404040404"
const sourceID5 = "0505050505050505050505050505050505050505050505050505050505050505"

func writePair(t *testing.T, editable, generated string, format Format) *Pair {
	t.Helper()
	dir := t.TempDir()
	if generated != "" {
		ref := ".enkv/prod.generated.json"
		if format == JSON {
			editable = strings.TrimSuffix(editable, "}") + `,"generated":"` + ref + `"}`
		} else {
			editable += "generated: '" + ref + "'\n"
		}
		if e := os.Mkdir(filepath.Join(dir, ".enkv"), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(filepath.Join(dir, ref), []byte(generated), 0600); e != nil {
			t.Fatal(e)
		}
	}
	path := filepath.Join(dir, "config")
	if e := os.WriteFile(path, []byte(editable), 0600); e != nil {
		t.Fatal(e)
	}
	pair, e := Capture(context.Background(), path, format)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := pair.Close(); e != nil {
			t.Error(e)
		}
	})
	return pair
}

// full_only: false
func TestSourceRepresentationParity(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		format      Format
	}{{"json", sourceSetupJSON, JSON}, {"yaml", sourceSetupYAML, YAML}, {"yaml-commented-json-flow", "# Portable manifest source\n" + sourceSetupJSON, YAML}} {
		t.Run(tc.name, func(t *testing.T) {
			p := writePair(t, tc.input, "", tc.format)
			m, e := Parse(context.Background(), p)
			if e != nil {
				t.Fatal(e)
			}
			want := contract.StoreLocation{Provider: contract.AWS, Region: "us-east-1", Bucket: "fixture-bucket", PrefixBeforeHEAD: "fixture", ExpectedOwner: "123456789012"}
			if m.Store != want || m.Resolved || m.Authority.SigningSelector != sourceSigningSelector || m.RecoveryEnabled {
				t.Fatalf("wrong normalized setup: %+v", m.Store)
			}
		})
	}
}

// full_only: false
func TestSourceYAMLScalarSemantics(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
		key, refuse       bool
	}{{"text-after-digit", "123abc", "123abc", false, false}, {"timestamp", "2026-10-18T00:00:00Z", "2026-10-18T00:00:00Z", false, false}, {"numeric-key", "123:", "", true, true}, {"boolean-key", "true:", "", true, true}, {"quoted-merge-key", `"<<":`, "<<", true, false}, {"folded", ">-\n  first\n  second\nnext: x\n", "first second", false, false}, {"literal", "|\n  first\n  second\nnext: x\n", "first\nsecond\n", false, false}, {"explicit-indent", "|2-\n  first\nnext: x\n", "first", false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			p := newParser(context.Background(), strings.NewReader(tc.input), YAML)
			got := p.text(65536, tc.key, true)
			if (p.err != nil) != tc.refuse || !tc.refuse && got != tc.want {
				t.Fatalf("got %q err %v, want %q refuse %v", got, p.err, tc.want, tc.refuse)
			}
		})
	}
}

// full_only: false
func TestSourceScalarBoundaries(t *testing.T) {
	for _, n := range []int{WindowBytes, WindowBytes + 1} {
		t.Run(fmt.Sprintf("yaml-pending-spaces/%d", n), func(t *testing.T) {
			want := strings.Repeat(" ", n)
			p := newParser(t.Context(), strings.NewReader(`"`+want+`"`), YAML)
			got := p.text(WindowBytes+1, false, false)
			err := p.done()
			if n == WindowBytes {
				if err != nil || got != want || p.off != int64(n+2) {
					t.Fatal("pending whitespace exact bound changed", err, len(got), p.off)
				}
				return
			}
			var diagnostic *Diagnostic
			if !errors.As(err, &diagnostic) || diagnostic.Reason != "scalar-limit" || diagnostic.Offset != int64(n+2) || got != "" {
				t.Fatal("pending whitespace first excess changed", err, len(got), p.off)
			}
		})
	}
	for _, format := range []Format{JSON, YAML} {
		for _, n := range []int{65536, 65537} {
			t.Run(fmt.Sprintf("%d/%d", format, n), func(t *testing.T) {
				p := newParser(context.Background(), strings.NewReader(`"`+strings.Repeat("x", n)+`"`), format)
				got := p.bytes(65536, false)
				if (p.err != nil) != (n == 65537) || n == 65536 && len(got) != n {
					t.Fatalf("length %d error %v", len(got), p.err)
				}
			})
		}
	}
	for _, n := range []int{65536, 65537} {
		p := newParser(context.Background(), strings.NewReader(`"`+base64.StdEncoding.EncodeToString(make([]byte, n))+`"`), JSON)
		got := p.base64(65536)
		if (p.err != nil) != (n == 65537) || n == 65536 && !bytes.Equal(got, make([]byte, n)) {
			t.Fatalf("base64 length %d error %v", len(got), p.err)
		}
	}
	for _, token := range []string{`"Zh=="`, `"Zg"`, `"Zg== "`, `"Zg-_"`, `"\ud800"`, `"\udc00"`} {
		p := newParser(context.Background(), strings.NewReader(token), JSON)
		if strings.Contains(token, "ud") {
			p.text(256, false, false)
		} else {
			p.base64(256)
		}
		if p.err == nil {
			t.Fatalf("accepted %s", token)
		}
	}
}

// full_only: false
func TestSourceStructuralLimits(t *testing.T) {
	for _, depth := range []int{16, 17} {
		p := newParser(context.Background(), strings.NewReader(strings.Repeat(`{"a":`, depth)+`"x"`+strings.Repeat("}", depth)), JSON)
		var walk func(int)
		walk = func(n int) {
			if n == 0 {
				p.text(1, false, false)
				return
			}
			p.object(1, func(string) { walk(n - 1) })
		}
		walk(depth)
		if (p.done() != nil) != (depth == 17) {
			t.Fatalf("depth %d error %v", depth, p.err)
		}
	}
	for _, n := range []int{512, 513} {
		p := newParser(context.Background(), strings.NewReader("["+strings.TrimSuffix(strings.Repeat(`"x",`, n), ",")+"]"), JSON)
		count := 0
		p.array(512, func(int) { count++; p.text(1, false, false) })
		if (p.done() != nil) != (n == 513) || count != min(n, 512) {
			t.Fatalf("count %d error %v", count, p.err)
		}
	}
	if unsafe.Sizeof(Span{}) != 64 || unsafe.Sizeof(Recipient{})+unsafe.Sizeof(Creation{}) > 352 || unsafe.Sizeof(Role{}) > 352 || unsafe.Sizeof(Pin{}) != 64 || 256*352+512*unsafe.Sizeof(Pin{})+2048 > 131072 {
		t.Fatal("source owner layouts exceed declared accounts")
	}
}

// full_only: false
func TestPairCaptureAndGeneratedJoins(t *testing.T) {
	t.Run("bounded-path-backing", func(t *testing.T) {
		for _, tc := range []struct {
			name, editable string
			format         Format
		}{{"json", sourceSetupJSON, JSON}, {"yaml", sourceSetupYAML, YAML}} {
			t.Run(tc.name, func(t *testing.T) {
				fixture := writePair(t, tc.editable, sourceGeneratedJSON, tc.format)
				path := fixture.Editable.OriginalPath()
				alias := filepath.Join(t.TempDir(), "source")
				if err := os.Symlink(filepath.Dir(path), alias); err != nil {
					t.Fatal(err)
				}
				for _, selected := range []struct{ name, path string }{
					{"direct", path}, {"parent-alias", filepath.Join(alias, filepath.Base(path))},
				} {
					t.Run(selected.name, func(t *testing.T) {
						const padding = 1 << 20
						backing := strings.Repeat("x", padding) + selected.path + strings.Repeat("x", padding)
						input := backing[padding : padding+len(selected.path)]
						captured, err := Capture(t.Context(), input, tc.format)
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() {
							if err := captured.Close(); err != nil {
								t.Error(err)
							}
						})
						if captured.aliasParent != filepath.Dir(selected.path) {
							t.Error("captured source parent differs from selected parent")
						}
						if unsafe.StringData(captured.aliasParent) == unsafe.StringData(input) {
							t.Error("captured source parent retains oversized caller backing")
						}
						if captured.Editable.OriginalPath() != path || captured.Generated.OriginalPath() != fixture.Generated.OriginalPath() {
							t.Error("captured source paths differ from canonical pair")
						}
						if err := captured.CheckUnchanged(t.Context()); err != nil {
							t.Error("unchanged captured source refused", err)
						}
					})
				}
			})
		}
	})
	pair := writePair(t, sourceSetupJSON, sourceGeneratedJSON, JSON)
	m, e := Parse(context.Background(), pair)
	if e != nil {
		t.Fatal(e)
	}
	if !m.Resolved || m.FileID != (contract.ID{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}) || len(m.Public.Recipients.Value) != 1 || !bytes.Equal(m.Basis.Descriptor, []byte{1}) {
		t.Fatal("wrong joined public and source fields")
	}
	original := pair.Editable.Digest()
	if e := os.WriteFile(pair.Editable.OriginalPath(), []byte("changed later"), 0600); e != nil {
		t.Fatal(e)
	}
	again, e := Parse(context.Background(), pair)
	if e != nil || again.FileID != m.FileID || pair.Editable.Digest() != original {
		t.Fatal("later source mutation changed frozen invocation")
	}
	generatedPath := pair.Generated.OriginalPath()
	if e := os.WriteFile(generatedPath, []byte(sourceGeneratedJSON+" "), 0600); e != nil {
		t.Fatal(e)
	}
	if p, e := Capture(context.Background(), pair.Editable.OriginalPath(), JSON); e == nil {
		closeSourceOwner(t, p)
		t.Fatal("accepted changed source")
	}
}

// full_only: false
func TestSourceClosedSchemaRefusals(t *testing.T) {
	cases := []struct {
		name, input string
		format      Format
	}{
		{"unknown-root", strings.TrimSuffix(sourceSetupJSON, "}") + `,"extra":true}`, JSON},
		{"duplicate-decoded-key", strings.Replace(sourceSetupJSON, `"schema":`, `"sch\u0065ma":"enkv/configuration/v3","schema":`, 1), JSON},
		{"null-map", strings.Replace(sourceSetupJSON, `"entries":{}`, `"entries":null`, 1), JSON},
		{"missing-generated-fields", strings.Replace(sourceSetupJSON, `"entries":{}`, `"entries":{"s":{"confidentiality":"secret","recipients":[],"source":{"kind":"generated"}}}`, 1), JSON},
		{"yaml-anchor", strings.Replace(sourceSetupYAML, "entries: {}", "entries: &entries {}", 1), YAML},
		{"yaml-extra-document", sourceSetupYAML + "---\nentries: {}\n", YAML},
		{"yaml-unquoted-integer", strings.Replace(sourceSetupYAML, "entries: {}", "entries: {x: {confidentiality: plain, recipients: [], source: {kind: supplied, value: 123}}}", 1), YAML},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Errorf("malformed source panicked instead of safe refusal")
				}
			}()
			dir := t.TempDir()
			path := filepath.Join(dir, "config")
			if err := os.WriteFile(path, []byte(tc.input), 0600); err != nil {
				t.Fatal(err)
			}
			pair, err := Capture(context.Background(), path, tc.format)
			if err == nil {
				closeSourceOwner(t, pair)
				t.Fatal("malformed source accepted")
			}
		})
	}
}

// full_only: false
func TestSourceYAMLObjectsRequireValues(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		refuse      bool
	}{
		{"missing-plugins", sourceSetupYAML + "plugins:\n", true},
		{"missing-plugin-requirement", sourceSetupYAML + "plugins:\n  generic-json:\n", true},
		{"missing-recipients", strings.Replace(sourceSetupYAML, "recipients: {}\n", "", 1) + "recipients:\n", true},
		{"missing-entries", strings.Replace(sourceSetupYAML, "entries: {}\n", "", 1) + "entries:\n", true},
		{"missing-routing", strings.Replace(sourceSetupYAML, "  routing: {}\n", "  routing:\n", 1), true},
		{"missing-destinations", strings.Replace(sourceSetupYAML, "  destinations: {}\n  routing: {}\n", "  routing: {}\n  destinations:\n", 1), true},
		{"same-indent-root-sibling", sourceSetupYAML + "plugins:\ngeneric-json: {}\n", true},
		{"same-indent-plugin-sibling", sourceSetupYAML + "plugins:\n  generic-json:\n  version: 1.2.3\n", true},
		{"same-line-block-map", sourceSetupYAML + "plugins: generic-json: {}\n", true},
		{"dedented-flow-plugins", sourceSetupYAML + "plugins:\n{}\n", true},
		{"dedented-flow-requirement", sourceSetupYAML + "plugins:\n  generic-json:\n  {}\n", true},
		{"explicit-empty-maps", sourceSetupYAML + "plugins: {}\n", false},
		{"explicit-empty-plugin-requirement", sourceSetupYAML + "plugins:\n  generic-json: {}\n", false},
		{"inline-flow-plugins", sourceSetupYAML + "plugins: {generic-json: {}}\n", false},
		{"flow-key-child-object", sourceSetupYAML + "plugins: {generic-json:\n  {version: 1.2.3}}\n", false},
		{"indented-flow-plugins", sourceSetupYAML + "plugins:\n  {}\n", false},
		{"indented-flow-requirement", sourceSetupYAML + "plugins:\n  generic-json:\n    {}\n", false},
		{"populated-plugin-requirement", sourceSetupYAML + "plugins:\n  generic-json:\n    version: 1.2.3\n", false},
		{"populated-recipients", strings.Replace(sourceSetupYAML, "recipients: {}\n", "recipients:\n  chosen:\n    display_name: Reader\n    encryption_key: "+sourceEncryptionSelector+"\n", 1), false},
		{"populated-entries", strings.Replace(sourceSetupYAML, "entries: {}\n", "entries:\n  item:\n    confidentiality: plain\n    recipients: []\n    source:\n      kind: supplied\n      value: example\n", 1), false},
		{"populated-routing", strings.Replace(sourceSetupYAML, "  routing: {}\n", "  routing:\n    default: []\n", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "configuration")
			if err := os.WriteFile(path, []byte(tc.input), 0600); err != nil {
				t.Fatal(err)
			}
			pair, err := Capture(t.Context(), path, YAML)
			if pair != nil {
				defer closeSourceOwner(t, pair)
			}
			if tc.refuse {
				if pair != nil || !errors.Is(err, ErrSourceInvalid) {
					t.Fatal("absent YAML object value accepted", err)
				}
				return
			}
			if err != nil {
				t.Fatal("explicit YAML object refused", err)
			}
			if _, err := Parse(t.Context(), pair); err != nil {
				t.Fatal("explicit YAML object did not parse", err)
			}
		})
	}
}

// full_only: false
func TestSourceYAMLObjectLayouts(t *testing.T) {
	for _, tc := range []struct {
		name, input      string
		sequence, refuse bool
	}{
		{"root-block", "name: first\nvalue: one\n", false, false},
		{"root-flow", "{name: first, value: one}\n", false, false},
		{"compact-sequence", "items:\n  - name: first\n    value: one\n  - name: first\n    value: one\n", true, false},
		{"expanded-sequence", "items:\n  -\n    name: first\n    value: one\n  -\n    name: first\n    value: one\n", true, false},
		{"flow-sequence", "items: [{name: first, value: one}, {name: first, value: one}]\n", true, false},
		{"compact-sequence-nested-block", "items:\n  - nested:\n      key: first\n    value: one\n  - nested: {key: first}\n    value: one\n", true, false},
		{"same-line-nested-block", "items:\n  - nested: key: value\n", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newParser(t.Context(), strings.NewReader(tc.input), YAML)
			var rows [][2]string
			readRow := func() {
				var row [2]string
				readField := func(key string) {
					switch key {
					case "name", "key":
						row[0] = p.text(32, false, false)
					case "value":
						row[1] = p.text(32, false, false)
					default:
						p.fail("unknown-field")
					}
				}
				p.object(2, func(key string) {
					if key == "nested" {
						p.object(1, readField)
						return
					}
					readField(key)
				})
				rows = append(rows, row)
			}
			wantCount := 1
			if tc.sequence {
				wantCount = 2
				p.object(1, func(key string) {
					if key != "items" {
						p.fail("unknown-field")
						return
					}
					p.array(2, func(int) { readRow() })
				})
			} else {
				readRow()
			}
			err := p.done()
			if tc.refuse {
				if !errors.Is(err, ErrSourceInvalid) {
					t.Fatal("invalid YAML object layout accepted", err)
				}
				return
			}
			if err != nil || len(rows) != wantCount {
				t.Fatal("valid YAML object layout refused", err, rows)
			}
			for _, row := range rows {
				if row != [2]string{"first", "one"} {
					t.Fatal("YAML object layout changed field values", row)
				}
			}
		})
	}
}

// full_only: false
func TestSourceLexicalSemantics(t *testing.T) {
	cases := []struct {
		name, input, want string
		format            Format
		refuse, array     bool
	}{
		{"json-empty-quote", `{"a":""}`, "", JSON, false, false},
		{"yaml-pending-escape-close", "a: \"one \\u0041 \"\n", "one A ", YAML, false, false},
		{"json-trailing-nul", "{}\x00ignored", "", JSON, true, false},
		{"yaml-invalid-comment-unicode", "a: b\n# \xff\n", "", YAML, true, false},
		{"yaml-block-punctuation", "a: hello, world [x]\n", "hello, world [x]", YAML, false, false},
		{"yaml-attached-hash-text", "a: prefix#suffix\n", "prefix#suffix", YAML, false, false},
		{"yaml-escaped-crlf-value", "a: \"first\\r\\nsecond\"\n", "first\r\nsecond", YAML, false, false},
		{"json-escaped-crlf-value", `{"a":"first\r\nsecond"}`, "first\r\nsecond", JSON, false, false},
		{"yaml-colon-separation", "a: a: b\n", "", YAML, true, false},
		{"yaml-complex-key", "? key: b\n", "", YAML, true, false},
		{"yaml-null-case", "a: Null\n", "", YAML, true, false},
		{"yaml-multiline-quote", "a: \"first\n  second\"\n", "first second", YAML, false, false},
		{"yaml-multiline-plain", "a: first\n  second\nb: next\n", "first second", YAML, false, false},
		{"yaml-quoted-escapes", "a: \"\\0\\x41\\U0001F642\"\n", "\x00A🙂", YAML, false, false},
		{"yaml-flow-trailing-comma", "a: [\"x\",]\n", "x", YAML, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newParser(context.Background(), strings.NewReader(tc.input), tc.format)
			got := ""
			p.object(2, func(key string) {
				if tc.array {
					p.array(1, func(int) { got = p.text(256, false, false) })
				} else {
					value := p.text(256, false, false)
					if key == "a" {
						got = value
					}
				}
			})
			err := p.done()
			if (err != nil) != tc.refuse || !tc.refuse && got != tc.want {
				t.Fatalf("value %q error %v, want %q refusal %v", got, err, tc.want, tc.refuse)
			}
		})
	}
}

// full_only: false
func TestGeneratedUnusedRecipientIdentityIsInert(t *testing.T) {
	row := `{"id":"` + sourceID3 + `","encryption":{"selector":"` + sourceEncryptionSelector + `","public_key":"` + sourceEncryptionSPKI + `","binding":{"id":"` + sourceID4 + `","incarnation":"` + sourceID5 + `","serial":1,"protection":"software"}}}`
	generated := strings.Replace(sourceGeneratedJSON, `"recipients":{}`, `"recipients":{"unused":`+row+`}`, 1)
	for _, active := range []bool{false, true} {
		t.Run(fmt.Sprint(active), func(t *testing.T) {
			editable := sourceSetupJSON
			if active {
				editable = strings.Replace(editable, `"recipients":{}`, `"recipients":{"unused":{"id":"`+sourceID3+`","display_name":"Unused","encryption_key":"`+sourceEncryptionSelector+`"}}`, 1)
			}
			pair := writePair(t, editable, generated, JSON)
			model, err := Parse(context.Background(), pair)
			if (err != nil) != active {
				t.Fatalf("active=%v error %v", active, err)
			}
			if !active && len(model.Public.Recipients.Value) != 1 {
				t.Fatal("inactive identity entered desired registry")
			}
		})
	}
}

// full_only: false
func TestParseRefusesRecombinedPair(t *testing.T) {
	a := writePair(t, sourceSetupJSON, sourceGeneratedJSON, JSON)
	b := writePair(t, sourceSetupJSON, sourceGeneratedJSON+"\n", JSON)
	unresolved := writePair(t, sourceSetupJSON, "", JSON)
	for _, tc := range []struct {
		name string
		pair Pair
	}{
		{"different-exact-dependency", Pair{Editable: a.Editable, Generated: b.Generated, Format: JSON}},
		{"missing-dependency", Pair{Editable: a.Editable, Format: JSON}},
		{"undeclared-dependency", Pair{Editable: unresolved.Editable, Generated: b.Generated, Format: JSON}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(context.Background(), &tc.pair); err == nil {
				t.Fatal("consumption accepted a pair not fixed by the editable reference")
			}
		})
	}
	t.Run("aggregate-before-traversal", func(t *testing.T) {
		oversized := *a.Generated
		oversized.size = MaxPairBytes
		pair := Pair{Editable: a.Editable, Generated: &oversized, Format: JSON}
		if _, err := Parse(context.Background(), &pair); err == nil {
			t.Fatal("consumption did not enforce aggregate image size")
		}
	})
}

// full_only: false
func TestSourceFlowAndControlRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		refuse      bool
	}{
		{"flow-open-bracket", "{a: ab[cd}", true},
		{"flow-open-brace", "{a: ab{cd}", true},
		{"plain-control", "a: before\x01after\n", true},
		{"comment-control", "a: value\n# before\x01after\n", true},
		{"escaped-control", "a: \"\\x01\"\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newParser(context.Background(), strings.NewReader(tc.input), YAML)
			p.object(1, func(string) { p.text(256, false, false) })
			if (p.done() != nil) != tc.refuse {
				t.Fatalf("refusal %v error %v", tc.refuse, p.err)
			}
		})
	}
}

// full_only: false
func TestSourceLongPlainBase64Typing(t *testing.T) {
	for _, tc := range []struct {
		name, token string
		refuse      bool
	}{{"hex-number", "0x" + strings.Repeat("a", 62), true}, {"scientific-number", "1e" + strings.Repeat("1", 62), true}, {"textual-prefix", "0xg" + strings.Repeat("A", 61), false}} {
		t.Run(tc.name, func(t *testing.T) {
			want, e := base64.StdEncoding.Strict().DecodeString(tc.token)
			if e != nil {
				t.Fatal(e)
			}
			p := newParser(context.Background(), strings.NewReader(tc.token), YAML)
			got := p.base64(128)
			if (p.done() != nil) != tc.refuse || !tc.refuse && !bytes.Equal(got, want) {
				t.Fatalf("refusal %v error %v", tc.refuse, p.err)
			}
		})
	}
}

// full_only: false
func TestSourceMalformedBase64ReturnsFirstDiagnostic(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		format      Format
		offset      int64
	}{
		{"yaml-quoted-spaces", `"     "`, YAML, 7},
		{"yaml-plain-pending-spaces", "AAAA    A", YAML, 9},
		{"yaml-escaped-unicode", `"AAA\u00e9"`, YAML, 10},
		{"json-escaped-unicode", `"AAA\u00e9"`, JSON, 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatal("malformed Base64 panicked instead of returning a diagnostic", recovered)
				}
			}()
			p := newParser(t.Context(), strings.NewReader(tc.input), tc.format)
			p.base64(16)
			err := p.done()
			var diagnostic *Diagnostic
			if !errors.Is(err, ErrSourceInvalid) || !errors.As(err, &diagnostic) || diagnostic.Reason != "invalid-base64" || diagnostic.Offset != 0 || diagnostic.Line != 1 || diagnostic.Column != 1 || p.off != tc.offset {
				t.Fatal("malformed Base64 lost its first error or consumed more source", err, p.off)
			}
		})
	}
	for _, format := range []Format{JSON, YAML} {
		t.Run(fmt.Sprintf("valid/%d", format), func(t *testing.T) {
			p := newParser(t.Context(), strings.NewReader(`"QUJD"`), format)
			if got := p.base64(3); p.done() != nil || !bytes.Equal(got, []byte("ABC")) {
				t.Fatal("valid exact-bound Base64 changed", got, p.err)
			}
		})
	}
}

// full_only: false
func TestSourceCaptureRefusesMalformedBase64WithoutPanic(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		format      Format
	}{
		{"yaml-spaces", strings.Replace(sourceSetupYAML, "entries: {}", "entries: {plain: {confidentiality: plain, recipients: [], source: {kind: supplied, bytes: \"     \"}}}", 1), YAML},
		{"yaml-unicode", strings.Replace(sourceSetupYAML, "entries: {}", `entries: {plain: {confidentiality: plain, recipients: [], source: {kind: supplied, bytes: "AAA\u00e9"}}}`, 1), YAML},
		{"json-unicode", strings.Replace(sourceSetupJSON, `"entries":{}`, `"entries":{"plain":{"confidentiality":"plain","recipients":[],"source":{"kind":"supplied","bytes":"AAA\u00e9"}}}`, 1), JSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatal("source capture panicked on malformed Base64", recovered)
				}
			}()
			path := filepath.Join(t.TempDir(), "configuration")
			if err := os.WriteFile(path, []byte(tc.input), 0600); err != nil {
				t.Fatal(err)
			}
			pair, err := Capture(t.Context(), path, tc.format)
			if pair != nil {
				defer closeSourceOwner(t, pair)
			}
			var diagnostic *Diagnostic
			if pair != nil || !errors.Is(err, ErrSourceInvalid) || !errors.As(err, &diagnostic) || diagnostic.Reason != "invalid-base64" || diagnostic.Field != "entries.item.source.bytes" {
				t.Fatal("capture did not return the bounded source refusal", err)
			}
		})
	}
}

// full_only: false
func TestSourceYAMLBlockContentPreservesExactBytes(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
		refuse            bool
	}{
		{"literal-clip", "|\n  A\n    \n  B\n\nnext: x\n", "A\n  \nB\n", false},
		{"literal-strip", "|-\n  A\n    \n  B\n\nnext: x\n", "A\n  \nB", false},
		{"literal-keep", "|+\n  A\n    \n  B\n\nnext: x\n", "A\n  \nB\n\n", false},
		{"folded-clip", ">\n  A\n    \n  B\n\nnext: x\n", "A\n  \nB\n", false},
		{"folded-strip", ">-\n  A\n    \n  B\n\nnext: x\n", "A\n  \nB", false},
		{"folded-keep", ">+\n  A\n    \n  B\n\nnext: x\n", "A\n  \nB\n\n", false},
		{"literal-clip-space-eof", "|\n  A\n    \n", "A\n  \n", false},
		{"literal-strip-space-eof", "|-\n  A\n    \n", "A\n  ", false},
		{"folded-keep-space-eof", ">+\n  A\n    \n\n", "A\n  \n\n", false},
		{"literal-no-final-break", "|\n  A\n    ", "A\n  ", false},
		{"folded-ordinary", ">-\n  A\n  B\n  C\n", "A B C", false},
		{"folded-space-content", ">-\n  A\n   B\n  C\n", "A\n B\nC", false},
		{"folded-tab-content", ">-\n  A\n  \tB\n  C\n", "A\n\tB\nC", false},
		{"tab-indentation", ">-\n\tA\n", "", true},
	} {
		for _, lineBreak := range []struct{ name, bytes string }{{"lf", "\n"}, {"crlf", "\r\n"}, {"cr", "\r"}} {
			t.Run(tc.name+"/"+lineBreak.name, func(t *testing.T) {
				p := newParser(t.Context(), strings.NewReader(strings.ReplaceAll(tc.input, "\n", lineBreak.bytes)), YAML)
				got := p.bytes(65536, true)
				p.skip()
				if tc.refuse {
					var diagnostic *Diagnostic
					if !errors.As(p.err, &diagnostic) || diagnostic.Reason != "tab-indentation" {
						t.Fatal("indentation tab did not refuse", p.err)
					}
					return
				}
				if p.err != nil || !bytes.Equal(got, []byte(tc.want)) {
					t.Fatalf("block bytes %q, want %q, error %v", got, tc.want, p.err)
				}
			})
		}
	}
}

// full_only: false
func TestSourceYAMLScalarMeaningReachesParsedModel(t *testing.T) {
	for _, tc := range []struct{ name, value, want string }{
		{"space-content", "|-\n        A\n          \n        B\n", "A\n  \nB"},
		{"tab-content", ">-\n        A\n        \tB\n        C\n", "A\n\tB\nC"},
	} {
		for _, lineBreak := range []struct{ name, bytes string }{{"lf", "\n"}, {"crlf", "\r\n"}, {"cr", "\r"}} {
			t.Run(tc.name+"/"+lineBreak.name, func(t *testing.T) {
				entry := "entries:\n  plain:\n    confidentiality: plain\n    recipients: []\n    source:\n      kind: supplied\n      value: " + tc.value
				source := strings.Replace(sourceSetupYAML, "entries: {}\n", entry, 1)
				pair := writePair(t, strings.ReplaceAll(source, "\n", lineBreak.bytes), "", YAML)
				model, err := Parse(t.Context(), pair)
				if err != nil || len(model.Entries) != 1 || model.Entries[0].Name != "plain" || model.Entries[0].PlainBase64 || !bytes.Equal(model.Entries[0].Plain, []byte(tc.want)) {
					t.Fatal("parsed source changed supplied scalar meaning", err)
				}
			})
		}
	}
}

// full_only: false
func TestSourceTypedScalarsRequireCommentSeparation(t *testing.T) {
	for _, tc := range []struct {
		name, value, reason string
		integer, refuse     bool
	}{
		{"boolean-attached", "false#x", "boolean-required", false, true},
		{"integer-attached", "2#x", "integer-required", true, true},
		{"boolean-separated", "false #x", "", false, false},
		{"integer-separated", "2 #x", "", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newParser(t.Context(), strings.NewReader(tc.value), YAML)
			if tc.integer {
				if got := p.integer(); !tc.refuse && got != 2 {
					t.Fatal("separated integer changed", got)
				}
			} else if p.boolean() && !tc.refuse {
				t.Fatal("separated false changed")
			}
			err := p.done()
			if tc.refuse {
				var diagnostic *Diagnostic
				if !errors.As(err, &diagnostic) || diagnostic.Reason != tc.reason || !errors.Is(err, ErrSourceInvalid) {
					t.Fatal("attached comment suffix became a typed scalar", err)
				}
			} else if err != nil {
				t.Fatal("separated comment refused", err)
			}
		})
	}
	for _, source := range []string{`{"enabled":false#x}`, `{"epoch":2#x}`} {
		p := newParser(t.Context(), strings.NewReader(source), JSON)
		p.object(1, func(key string) {
			if key == "enabled" {
				p.boolean()
			} else {
				p.integer()
			}
		})
		if err := p.done(); !errors.Is(err, ErrSourceInvalid) {
			t.Fatal("JSON accepted a typed prefix before a hash", err)
		}
	}
	for _, field := range []string{"boolean", "integer"} {
		for _, attached := range []bool{false, true} {
			t.Run(fmt.Sprintf("capture/%s/attached=%v", field, attached), func(t *testing.T) {
				suffix := " #x"
				if attached {
					suffix = "#x"
				}
				source, reason := strings.Replace(sourceSetupYAML, "enabled: false}", "enabled: false"+suffix+"\n  }", 1), "boolean-required"
				if field == "integer" {
					entry := "entries:\n  generated:\n    confidentiality: secret\n    recipients: []\n    source:\n      kind: generated\n      plugin: private-generator\n      epoch: 2" + suffix + "\n      settings: {}\n"
					source, reason = strings.Replace(sourceSetupYAML, "entries: {}\n", entry, 1), "integer-required"
				}
				path := filepath.Join(t.TempDir(), "configuration")
				if err := os.WriteFile(path, []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
				pair, err := Capture(t.Context(), path, YAML)
				if pair != nil {
					defer closeSourceOwner(t, pair)
				}
				if attached {
					var diagnostic *Diagnostic
					if pair != nil || !errors.As(err, &diagnostic) || diagnostic.Reason != reason || !errors.Is(err, ErrSourceInvalid) {
						t.Fatal("capture admitted attached typed suffix", err)
					}
				} else if err != nil || pair == nil {
					t.Fatal("capture refused separated typed comment", err)
				}
			})
		}
	}
}

// full_only: false
func TestSourceSchemaDiagnosticUsesValueOrigin(t *testing.T) {
	for _, tc := range []struct {
		name, source string
		format       Format
		offset       int64
		line, column uint64
	}{
		{"yaml-first", "schema: enkv/configuration/v99\ndomain: {}\n", YAML, 8, 1, 9},
		{"yaml-later-crlf", "# comment\r\n\r\nschema: enkv/configuration/v99\r\ndomain: {}\r\n", YAML, 21, 3, 9},
		{"json-later", "{\n  \"schema\": \"enkv/configuration/v99\",\n  \"domain\": {}\n}\n", JSON, 14, 2, 13},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "configuration")
			if err := os.WriteFile(path, []byte(tc.source), 0600); err != nil {
				t.Fatal(err)
			}
			pair, err := Capture(t.Context(), path, tc.format)
			if pair != nil {
				defer func() {
					if err := pair.Close(); err != nil {
						t.Error(err)
					}
				}()
				_, err = Parse(t.Context(), pair)
			}
			var diagnostic *Diagnostic
			if !errors.As(err, &diagnostic) || diagnostic.Reason != "unsupported-schema" || diagnostic.Field != "schema" || diagnostic.Offset != tc.offset || diagnostic.Line != tc.line || diagnostic.Column != tc.column {
				t.Fatalf("schema fault lost value origin: %+v", diagnostic)
			}
		})
	}
}

// full_only: false
func TestSourceSingleYAMLDocumentEnvelope(t *testing.T) {
	for _, newline := range []string{"\n", "\r\n"} {
		for _, envelope := range []struct{ name, prefix, suffix string }{
			{"none", "# before\n", "# after\n"}, {"leading", "# before\n--- # start\n", "# after\n"},
			{"closing", "# before\n", "... # end\n# after\n"}, {"both", "# before\n---\n", "...\n# after\n"},
		} {
			t.Run(fmt.Sprintf("%q/%s", newline, envelope.name), func(t *testing.T) {
				source := strings.ReplaceAll(envelope.prefix+sourceSetupYAML+envelope.suffix, "\n", newline)
				pair := writePair(t, source, "", YAML)
				model, err := Parse(t.Context(), pair)
				if err != nil || model.DomainName != "prod" || model.Store.Bucket != "fixture-bucket" {
					t.Fatalf("single document mapping changed: %v", err)
				}
			})
		}
	}
	for _, tc := range []struct{ name, tail, reason string }{
		{"second-document", "---\nschema: enkv/configuration/v3\n", "additional-document"},
		{"directive", "%YAML 1.2\n", "directive-forbidden"},
		{"after-close", "...\nother: data\n", "trailing-content"},
		{"second-close", "...\n...\n", "trailing-content"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "config.yaml")
			if err := os.WriteFile(path, []byte(sourceSetupYAML+tc.tail), 0600); err != nil {
				t.Fatal(err)
			}
			pair, err := Capture(t.Context(), path, YAML)
			if pair != nil {
				defer func() {
					if err := pair.Close(); err != nil {
						t.Error(err)
					}
				}()
				_, err = Parse(t.Context(), pair)
			}
			var diagnostic *Diagnostic
			line := uint64(20)
			if strings.HasPrefix(tc.tail, "...\n") {
				line++
			}
			if !errors.As(err, &diagnostic) || diagnostic.Reason != tc.reason || diagnostic.Line != line || diagnostic.Column != 1 {
				t.Fatalf("document tail diagnostic lost position: %+v", diagnostic)
			}
		})
	}
}

// full_only: false
func TestSourceMarkerTextStaysScalarData(t *testing.T) {
	for _, scalar := range []struct{ source, value string }{
		{`"---"`, "---"}, {`'...'`, "..."}, {"|-\n      ---\n      ...", "---\n..."},
		{"\"first\n---\nlast\"", "first --- last"}, {"---suffix", "---suffix"}, {"...suffix", "...suffix"},
	} {
		t.Run(scalar.source, func(t *testing.T) {
			source := strings.Replace(sourceSetupYAML, "entries: {}", "entries:\n  sample:\n    confidentiality: plain\n    recipients: []\n    source:\n      kind: supplied\n      value: "+strings.ReplaceAll(scalar.source, "      ---\n      ...", "        ---\n        ..."), 1)
			pair := writePair(t, source, "", YAML)
			model, err := Parse(t.Context(), pair)
			if err != nil {
				t.Fatal(err)
			}
			if string(model.Entries[0].Plain) != scalar.value {
				t.Fatalf("marker text changed scalar data: %q", model.Entries[0].Plain)
			}
		})
	}
}

// full_only: false
func TestSourceSemanticDiagnosticUsesOffendingField(t *testing.T) {
	for _, tc := range []struct {
		name, editable, generated, field, token, reason string
		format                                          Format
		generatedImage                                  bool
	}{
		{"owner", strings.Replace(sourceSetupYAML, "'123456789012'", "''", 1), "", "domain.store.expected_owner", "''", "invalid-owner", YAML, false},
		{"class", strings.Replace(sourceSetupJSON, `"entries":{}`, `"entries":{"item":{"confidentiality":"bad","recipients":[],"source":{"kind":"supplied","value":"x"}}}`, 1), "", "entries.item.confidentiality", `"bad"`, "invalid-confidentiality", JSON, false},
		{"public-key", sourceSetupJSON, strings.Replace(sourceGeneratedJSON, sourceSigningSPKI, "AQ==", 1), "domain.authority.signing.public_key", `"AQ=="`, "invalid-public-key", JSON, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "configuration")
			source := tc.editable
			if tc.generatedImage {
				source = tc.generated
			}
			at := strings.Index(source, tc.token)
			if at < 0 {
				t.Fatal("fault token missing from fixture")
			}
			line := uint64(1 + strings.Count(source[:at], "\n"))
			column := uint64(at - strings.LastIndex(source[:at], "\n"))
			var err error
			if tc.generatedImage {
				pair := writePair(t, tc.editable, tc.generated, tc.format)
				_, err = Parse(t.Context(), pair)
			} else {
				if err := os.WriteFile(path, []byte(tc.editable), 0600); err != nil {
					t.Fatal(err)
				}
				var pair *Pair
				pair, err = Capture(t.Context(), path, tc.format)
				if pair != nil {
					defer func() {
						if err := pair.Close(); err != nil {
							t.Error(err)
						}
					}()
					_, err = Parse(t.Context(), pair)
				}
			}
			var d *Diagnostic
			if !errors.As(err, &d) || d.Field != tc.field || d.Reason != tc.reason || d.Line != line || d.Column != column || d.Generated != tc.generatedImage || d.Context {
				t.Fatalf("semantic fault lost field origin: %+v", d)
			}
		})
	}
}

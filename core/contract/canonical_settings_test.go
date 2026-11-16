package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"testing"
)

// full_only: false
func TestGeneratorCanonicalSettingsGrammarAcrossStoredAdmission(t *testing.T) {
	for _, tc := range canonicalSettingsCases() {
		t.Run(tc.name, func(t *testing.T) {
			v := GeneratorIntent{Schema: 1, ConfigContractID: ID{1}, LifecycleMode: GeneratorLifecycleNone, Settings: []byte(tc.text)}
			body := []byte{0, 1}
			body = append(body, v.ConfigContractID[:]...)
			body = append(body, 1)
			body = append(body, make([]byte, 32)...)
			body = binary.BigEndian.AppendUint32(body, uint32(len(tc.text)))
			body = append(body, tc.text...)
			for name, check := range map[string]func(*testing.T) error{
				"encode": func(t *testing.T) error {
					got, err := EncodeGeneratorIntent(v)
					if err == nil && !bytes.Equal(got, body) {
						t.Fatal("settings bytes changed")
					}
					return err
				},
				"inspect": func(t *testing.T) error {
					got, err := InspectGeneratorIntent(body)
					if err == nil && !bytes.Equal(got.Settings, []byte(tc.text)) {
						t.Fatal("stored settings changed")
					}
					return err
				},
				"digest": func(t *testing.T) error { _, err := GeneratorIntentDigest(body); return err },
			} {
				t.Run(name, func(t *testing.T) {
					if err := check(t); (err == nil) != tc.valid {
						t.Fatalf("canonical admission validity = %t, want %t: %v", err == nil, tc.valid, err)
					}
				})
			}
		})
	}
}

// full_only: false
func TestOutputCanonicalSettingsGrammarAcrossStoredAndStreamAdmission(t *testing.T) {
	for _, tc := range canonicalSettingsCases() {
		t.Run(tc.name, func(t *testing.T) {
			domain := ID{1}
			binding := ID{2}
			destination := OutputDestination{ConfigContractID: "c", ServiceContractID: "s", CanonicalSettings: []byte(tc.text)}
			v := OutputConfiguration{Schema: 5, DomainID: domain, Bindings: []OutputBinding{{DestinationID: "d", IncarnationID: binding, Destination: destination}}}
			blob := func(dst []byte, s string) []byte {
				dst = binary.BigEndian.AppendUint32(dst, uint32(len(s)))
				return append(dst, s...)
			}
			// Schema 5, one target-free binding, no groups, and empty schema-3 routing.
			body := blob([]byte{0, 5, 0, 1}, "d")
			body = append(body, binding[:]...)
			for _, field := range []string{"c", "s", tc.text, ""} {
				body = blob(body, field)
			}
			body = append(body, 0, 0, 0, 0, 0)
			body = blob(body, string([]byte{0, 3, 0, 0, 0}))
			preimage := append([]byte("ENKV/OUTPUT/CONFIGURATION/v5\x00"), domain[:]...)
			preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(body)))
			digest := sha256.Sum256(append(preimage, body...))
			descriptor := OutputConfigurationDescriptor{Schema: 5, ConfigurationDigest: digest, TotalLength: uint32(len(body)), SliceCount: 1, BindingCount: 1, RoutingLength: 5}
			part := OutputConfigurationSlice{Schema: 5, DomainID: domain, ConfigurationDigest: digest, SliceCount: 1, TotalLength: uint32(len(body)), SliceBytes: body}
			source := func(uint16) (OutputConfigurationSlice, error) { return part, nil }
			for name, check := range map[string]func(*testing.T) error{
				"encode": func(t *testing.T) error {
					got, err := EncodeOutputConfiguration(v)
					if err == nil && !bytes.Equal(got, body) {
						t.Fatal("settings bytes changed")
					}
					return err
				},
				"counter":             func(t *testing.T) error { _, err := OutputConfigurationLength(v); return err },
				"destination_counter": func(t *testing.T) error { _, err := OutputDestinationLength(destination); return err },
				"inspect": func(t *testing.T) error {
					got, _, err := InspectOutputConfiguration(domain, body)
					if err == nil && !bytes.Equal(got.Bindings[0].Destination.CanonicalSettings, []byte(tc.text)) {
						t.Fatal("stored settings changed")
					}
					return err
				},
				"stream_validation": func(t *testing.T) error { return ValidateOutputConfigurationSource(domain, descriptor, source) },
				"stream_materialization": func(t *testing.T) error {
					_, err := InspectOutputConfigurationSource(domain, descriptor, source)
					return err
				},
				"stream_visitor": func(t *testing.T) error {
					called := false
					err := VisitOutputConfigurationSource(domain, descriptor, source, OutputConfigurationVisit{Binding: func(_ ID, _ string, d OutputDestination) error {
						called = true
						if !bytes.Equal(d.CanonicalSettings, []byte(tc.text)) {
							t.Fatal("visited settings changed")
						}
						return nil
					}})
					if called && !tc.valid {
						t.Fatal("invalid canonical settings reached visitor")
					}
					if err == nil && !called {
						t.Fatal("valid binding was not visited")
					}
					return err
				},
			} {
				t.Run(name, func(t *testing.T) {
					if err := check(t); (err == nil) != tc.valid {
						t.Fatalf("canonical admission validity = %t, want %t: %v", err == nil, tc.valid, err)
					}
				})
			}
		})
	}
}

func canonicalSettingsCases() []struct {
	name, text string
	valid      bool
} {
	return []struct {
		name, text string
		valid      bool
	}{
		{"duplicate", `{"x":1,"x":2}`, false},
		{"nested_duplicate", `{"outer":{"x":1,"x":2}}`, false},
		{"array_duplicate", `[{"x":1,"x":2}]`, false},
		{"escaped_key_collision", `{"x":1,"\u0078":2}`, false},
		{"high_surrogate", `"\ud800"`, false},
		{"low_surrogate", `"\udfff"`, false},
		{"reversed_surrogates", `"\udc00\ud800"`, false},
		{"surrogate_key", `{"\ud800":1}`, false},
		{"invalid_utf8", "\"\xff\"", false},
		{"scalar_number", `1.00e+09`, true},
		{"scalar_boolean", `true`, true},
		{"scalar_null", `null`, true},
		{"surrogate_pair", `{"\ud83d\ude00":"\ud83d\ude00"}`, true},
		{"escaped_spelling", ` { "z": "\u0078\/", "a": 1.00 } `, true},
		{"separate_object_keys", `[{"x":1},{"x":2}]`, true},
		{"maximum_depth", strings.Repeat("[", 10000) + "0" + strings.Repeat("]", 10000), true},
	}
}

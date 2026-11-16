package configuration

import (
	"context"
	"strings"
	"testing"
)

// full_only: false
func TestSourceYAMLBlockValueSeparation(t *testing.T) {
	for _, tc := range []struct {
		name, body       string
		flowValue, valid bool
	}{
		{"quoted-block-scalar", `"key":"scalar"`, false, false},
		{"quoted-block-flow", `"key":{}`, true, false},
		{"plain-block-scalar", `key:"scalar"`, false, false},
		{"plain-block-flow", `key:{}`, true, false},
		{"quoted-separated-scalar", `"key": "scalar"`, false, true},
		{"quoted-separated-flow", `"key": {}`, true, true},
		{"plain-separated-scalar", `key: "scalar"`, false, true},
		{"plain-separated-flow", `key: {}`, true, true},
		{"quoted-flow-adjacent-scalar", `{"key":"scalar"}`, false, true},
		{"quoted-flow-adjacent-flow", `{"key":{}}`, true, true},
		{"plain-flow-adjacent-flow", `{key:{}}`, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newParser(context.Background(), strings.NewReader(tc.body), YAML)
			key, value := "", ""
			p.object(1, func(k string) {
				key = k
				if tc.flowValue {
					p.object(1, func(string) { p.fail("unexpected-child") })
				} else {
					value = p.text(32, false, false)
				}
			})
			err := p.done()
			if tc.valid {
				if err != nil || key != "key" || !tc.flowValue && value != "scalar" {
					t.Fatal("valid separated block or adjacent flow mapping refused", err)
				}
			} else if err == nil {
				t.Fatal("adjacent YAML block mapping value accepted")
			}
		})
	}
}

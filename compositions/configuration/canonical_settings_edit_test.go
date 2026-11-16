package configuration

import (
	"bytes"
	"strings"
	"testing"
)

// full_only: false
func TestCanonicalSettingsEditsRetainExactSpans(t *testing.T) {
	for _, tc := range []struct{ name, original, edited, want string }{
		{"formatting_and_key_order", ` { "z":1.00,"a":"\u0078" } `, `{"a":"x","z":1.00}`, ` { "z":1.00,"a":"\u0078" } `},
		{"changed_number_token", `{"n":1.00,"s":"\u0078"}`, `{"s":"x","n":1.0}`, `{"n":1.0,"s":"\u0078"}`},
		{"nested_leaf", ` {"n":1.00,"tree":{"a":1,"b":"\u0078"}} `, `{"tree":{"b":"x","a":2},"n":1.00}`, ` {"n":1.00,"tree":{"a":2,"b":"\u0078"}} `},
		{"removed_and_added_members", `{"b":1,"a":2}`, `{"d":4,"a":2,"c":3}`, `{"a":2,"d":4,"c":3}`},
		{"array_positions", `[1.00,"\u0078",{"a":1}]`, `[1.00,"x",{"a":2},null]`, `[1.00,"\u0078",{"a":2},null]`},
		{"replacement_collection", `{"v":[1,2]}`, `{"v":{"x":1}}`, `{"v":{"x":1}}`},
		{"empty_objects", `{"x":{}}`, `{"x":{}}`, `{"x":{}}`},
		{"empty_arrays", `[]`, `[null]`, `[null]`},
		{"scalar_null", ` null `, `false`, ` false `},
		{"empty_member_name", `{"":1,"a":2}`, `{"a":2,"":3}`, `{"":3,"a":2}`},
		{"unicode_member_name", `{"\ud83d\ude00":1}`, `{"😀":2}`, `{"\ud83d\ude00":2}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := []byte(tc.original)
			got, err := editedCanonicalSettings(original, []byte(tc.edited), 393145)
			if err != nil || string(got) != tc.want {
				t.Fatalf("candidate=%q want=%q: %v", got, tc.want, err)
			}
			if tc.want == tc.original && len(got) > 0 && &got[0] != &original[0] {
				t.Fatal("unchanged settings did not reuse exact backing")
			}
			if !bytes.Equal(original, []byte(tc.original)) {
				t.Fatal("baseline bytes changed")
			}
		})
	}
}

// full_only: false
func TestCanonicalSettingsEditDepthAndByteLimits(t *testing.T) {
	prefix, suffix := strings.Repeat("[", 10000), strings.Repeat("]", 10000)
	got, err := editedCanonicalSettings([]byte(prefix+"0"+suffix), []byte(prefix+"1"+suffix), 20001)
	if err != nil || string(got) != prefix+"1"+suffix {
		t.Fatal("admitted nesting reduced", err)
	}
	for _, edited := range []string{`{"x":1,"x":2}`, `"\ud800"`, `"` + string([]byte{255}) + `"`, prefix + "[0]" + suffix} {
		if _, err := editedCanonicalSettings([]byte(`{}`), []byte(edited), 393145); err == nil {
			t.Fatal("invalid edited settings accepted")
		}
	}
	if _, err := editedCanonicalSettings([]byte(`{}`), []byte(`{"x":1}`), 6); err == nil {
		t.Fatal("first byte excess accepted")
	}
}

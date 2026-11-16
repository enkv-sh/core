package core

import (
	"encoding/base64"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

func gcCursorTestStore() contract.Descriptor {
	return contract.Descriptor{Family: contract.GCP, Identity: contract.ID{2}, Coordinate: contract.ID{3}, NonBody: contract.ID{4}, Prefix: "fixture", HeadKey: "fixture/HEAD"}
}

// full_only: false
func TestGCCursorBindsExactStoreAndDomain(t *testing.T) {
	store := gcCursorTestStore()
	// Independently derived with Python struct/hashlib/base64: the existing
	// Store descriptor uses LE length fields; the cursor uses BE schema/length.
	const expected = "RU5LVi9HQy1DVVJTT1IvdjEAAAECAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA3Vv23WDfKzrs3mdbPHHHVkBcnsRiZfGJQf7SiC_gGzQAAAAorY3Vyc29yL86x"
	got, err := EncodeGCCursor("+cursor/α", contract.ID{1}, store)
	if err != nil || got != expected {
		t.Fatal("independent cursor bytes differ", err, got)
	}
	if raw, err := DecodeGCCursor(expected, contract.ID{1}, store); err != nil || raw != "+cursor/α" {
		t.Fatal("exact cursor refused", err)
	}
	for _, cursor := range []string{expected + "=", expected + "A", "!", strings.Repeat("a", GCCursorMaxLength+1)} {
		if _, err := DecodeGCCursor(cursor, contract.ID{1}, store); err == nil {
			t.Fatal("noncanonical cursor accepted")
		}
	}
	for _, change := range []func(*contract.Descriptor){func(s *contract.Descriptor) { s.Family = contract.AWS }, func(s *contract.Descriptor) { s.Identity[0]++ }, func(s *contract.Descriptor) { s.Coordinate[0]++ }, func(s *contract.Descriptor) { s.NonBody[0]++ }, func(s *contract.Descriptor) { s.Prefix = "other"; s.HeadKey = "other/HEAD" }} {
		other := store
		change(&other)
		if _, err := DecodeGCCursor(expected, contract.ID{1}, other); err == nil {
			t.Fatal("cursor changed Store scope")
		}
	}
	if _, err := DecodeGCCursor(expected, contract.ID{8}, store); err == nil {
		t.Fatal("cursor changed domain")
	}
	body, err := base64.RawURLEncoding.DecodeString(expected)
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{0, len(gcCursorTag), len(gcCursorTag) + 2, len(body) - 11} {
		damaged := append([]byte(nil), body...)
		damaged[offset] ^= 255
		if _, err := DecodeGCCursor(base64.RawURLEncoding.EncodeToString(damaged), contract.ID{1}, store); err == nil {
			t.Fatal("damaged cursor accepted", offset)
		}
	}
	maximum, err := EncodeGCCursor(strings.Repeat("x", contract.GCProviderCursorLimit), contract.ID{1}, store)
	if err != nil || len(maximum) != GCCursorMaxLength {
		t.Fatal("cursor maximum differs", len(maximum), err)
	}
	if _, err := EncodeGCCursor(strings.Repeat("x", contract.GCProviderCursorLimit+1), contract.ID{1}, store); err == nil {
		t.Fatal("oversized provider cursor accepted")
	}
	if first, err := DecodeGCCursor("", contract.ID{1}, store); err != nil || first != "" {
		t.Fatal("first page refused", err)
	}
	if next, err := EncodeGCCursor("", contract.ID{1}, store); err != nil || next != "" {
		t.Fatal("empty wrapped cursor emitted", err)
	}
}

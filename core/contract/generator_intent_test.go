package contract

import (
	"bytes"
	"encoding/hex"
	"testing"

	protocol "enkv.sh/sdk/protocols/generator"
)

// full_only: false
func TestGeneratorCanonicalIntentIndependentBytes(t *testing.T) {
	// Derived with Python struct.pack(">H",1), 32 repeated config bytes,
	// one lifecycle byte, 32 resource bytes, pack(">I",2), and b"{}".
	// Hashes use hashlib.sha256(domain + pack(">I",len(body)) + body).
	cases := []struct {
		mode         GeneratorLifecycleMode
		resource     byte
		body, digest string
	}{
		{GeneratorLifecycleNone, 0, "00010101010101010101010101010101010101010101010101010101010101010101010000000000000000000000000000000000000000000000000000000000000000000000027b7d", "f273025db27a60f1f310e1f7070eaa9127f7fafc99456390b31f9de2ec220820"},
		{GeneratorLifecycleManaged, 2, "00010101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020202000000027b7d", "3366d7e4276040e8f69b62d48769d8343f49817b4fbfa2de5752190718addabe"},
	}
	for _, tc := range cases {
		config := ID(bytes.Repeat([]byte{1}, 32))
		resource := ID(bytes.Repeat([]byte{tc.resource}, 32))
		v := GeneratorIntent{Schema: 1, ConfigContractID: config, LifecycleMode: tc.mode, ResourceContractID: resource, Settings: []byte("{}")}
		body, err := EncodeGeneratorIntent(v)
		if err != nil {
			t.Fatal(err)
		}
		expected, err := hex.DecodeString(tc.body)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(body, expected) {
			t.Fatalf("mode %d bytes %x", tc.mode, body)
		}
		shared, err := protocol.EncodeIntent(protocol.Intent{Schema: 1, ConfigContractID: protocol.ID(config), LifecycleMode: uint8(tc.mode),
			ResourceContractID: protocol.ID(resource), Settings: []byte("{}")})
		if err != nil || !bytes.Equal(shared, expected) {
			t.Fatal("public intent differs from the independent record", err)
		}
		digest, err := GeneratorIntentDigest(body)
		if err != nil || hex.EncodeToString(digest[:]) != tc.digest {
			t.Fatalf("mode %d digest %x: %v", tc.mode, digest, err)
		}
		got, err := InspectGeneratorIntent(expected)
		if err != nil || got.Schema != 1 || got.ConfigContractID != config || got.ResourceContractID != resource || got.LifecycleMode != tc.mode || !bytes.Equal(got.Settings, []byte("{}")) {
			t.Fatalf("inspect mode %d: %+v %v", tc.mode, got, err)
		}
	}
}

// full_only: false
func TestGeneratorCanonicalIntentBoundsAndClosedLifecycle(t *testing.T) {
	v := GeneratorIntent{Schema: 1, ConfigContractID: ID{1}, LifecycleMode: GeneratorLifecycleNone, Settings: append(append([]byte{'"'}, bytes.Repeat([]byte{'x'}, GeneratorIntentMaxLength-73)...), '"')}
	body, err := EncodeGeneratorIntent(v)
	if err != nil || len(body) != GeneratorIntentMaxLength {
		t.Fatal("complete maximum", len(body), err)
	}
	if shared, err := protocol.DecodeIntent(body); err != nil || len(shared.Settings) != len(v.Settings) {
		t.Fatal("public intent rejected the same complete maximum", err)
	}
	v.Settings = append(v.Settings[:len(v.Settings)-1], 'x', '"')
	if _, err := EncodeGeneratorIntent(v); err != ErrRecordCapacity {
		t.Fatal("one excess byte", err)
	}
	v.Settings = []byte("{}")
	for _, mutate := range []func(*GeneratorIntent){func(v *GeneratorIntent) { v.Schema = 2 }, func(v *GeneratorIntent) { v.ConfigContractID = ID{} }, func(v *GeneratorIntent) { v.ResourceContractID = ID{2} }, func(v *GeneratorIntent) { v.LifecycleMode = GeneratorLifecycleManaged }, func(v *GeneratorIntent) { v.Settings = []byte{0xff} }, func(v *GeneratorIntent) { v.Settings = []byte("{") }} {
		bad := v
		mutate(&bad)
		if _, err := EncodeGeneratorIntent(bad); err == nil {
			t.Fatal("invalid intent accepted", bad)
		}
		if _, err := protocol.EncodeIntent(protocol.Intent{Schema: bad.Schema, ConfigContractID: protocol.ID(bad.ConfigContractID),
			LifecycleMode: uint8(bad.LifecycleMode), ResourceContractID: protocol.ID(bad.ResourceContractID), Settings: bad.Settings}); err == nil {
			t.Fatal("public intent accepted an invalid contract field")
		}
	}
}

// full_only: false
func TestGeneratorFactsUseOneCompleteBudgetAndNativeAcknowledgement(t *testing.T) {
	facts := GeneratorSafeFacts{Schema: GeneratorSafeFactsSchema, Action: GeneratorActionCreate, LifecycleMode: GeneratorLifecycleManaged, Disposition: GeneratorDispositionCompleteCreate, RequestDigest: ID{1}, IntentDigest: ID{2}, ResourceContractID: ID{3}, Target: []byte("t"), ResourceData: []byte("r"), ProviderFacts: bytes.Repeat([]byte{'p'}, 3979)}
	body, err := EncodeGeneratorSafeFacts(facts)
	if err != nil || len(body) != 4096 {
		t.Fatal("ordinary aggregate maximum", len(body), err)
	}
	facts.ProviderFacts = append(facts.ProviderFacts, 'p')
	if _, err := EncodeGeneratorSafeFacts(facts); err != ErrRecordCapacity {
		t.Fatal("aggregate overflow", err)
	}
	facts.ProviderFacts = nil
	facts.Action = GeneratorActionDelete
	facts.Disposition = GeneratorDispositionRetirementAcknowledged
	native, err := EncodeNativeGeneratorSafeFacts(facts)
	if err != nil {
		t.Fatal(err)
	}
	got, err := InspectNativeGeneratorSafeFacts(native)
	if err != nil || got.Disposition != GeneratorDispositionRetirementAcknowledged || !got.ScopeID.IsZero() {
		t.Fatal("native acknowledgement", got, err)
	}
	facts.Disposition = GeneratorDispositionScopedUnusability
	facts.ScopeID = ID{4}
	facts.PrecedingResultID = ID{5}
	facts.PrecedingResultBodyDigest = ID{6}
	facts.ObservedResourceID = ID{7}
	facts.ObservedResourceDigest = ID{8}
	facts.ObservedScopeID = ID{9}
	facts.ProviderFacts = bytes.Repeat([]byte{'p'}, 3787)
	body, err = EncodeGeneratorSafeFacts(facts)
	if err != nil || len(body) != 4096 {
		t.Fatal("controlled aggregate maximum", len(body), err)
	}
	if _, err := EncodeNativeGeneratorSafeFacts(facts); err == nil {
		t.Fatal("private observation encoded as native facts")
	}
	facts.PrecedingResultBodyDigest = ID{}
	if _, err := EncodeGeneratorSafeFacts(facts); err == nil {
		t.Fatal("missing preceding result digest accepted")
	}
}

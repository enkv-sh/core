package installedarchive

import (
	"bytes"
	"encoding/json"
	"testing"
)

// full_only: false
func TestRecoveryFixtureRejectsIncompleteParentCarrier(t *testing.T) {
	fixture := RecoveryFixture{Archive: Load(t, "gcp"), Values: []ExpectedValue{{Name: "installed-positive-secret", Bytes: []byte("enkv first secret test value")}}, Secrets: 1}
	encoded, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeRecoveryFixture(bytes.NewReader(encoded)); err != nil {
		t.Fatal("complete parent carrier refused", err)
	}
	for _, name := range []string{"count", "bytes-zero", "bytes-short", "bytes-long", "bytes-overflow", "duplicate-object", "foreign-object", "digest", "token", "secrets", "missing-value", "duplicate-value", "unknown-value", "mixed-oracles", "relative-oracle", "duplicate-oracle-path", "trailing", "unknown-field"} {
		t.Run(name, func(t *testing.T) {
			var current RecoveryFixture
			if err := json.Unmarshal(encoded, &current); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "count":
				current.Archive.ObjectCount++
			case "bytes-zero":
				current.Archive.ObjectFileBytes = 0
			case "bytes-short":
				current.Archive.ObjectFileBytes--
			case "bytes-long":
				current.Archive.ObjectFileBytes++
			case "bytes-overflow":
				current.Archive.ObjectFileBytes = ^uint64(0)
			case "duplicate-object":
				current.Archive.Objects = append(current.Archive.Objects, current.Archive.Objects[0])
				current.Archive.ObjectCount++
			case "foreign-object":
				current.Archive.Objects[0].Key = "foreign/HEAD"
			case "digest":
				current.Archive.Objects[0].Body[0] ^= 1
			case "token":
				current.Archive.Objects[0].TokenWire = nil
			case "secrets":
				current.Secrets = 0
			case "missing-value":
				current.Values = nil
			case "duplicate-value":
				current.Values = append(current.Values, current.Values[0])
			case "unknown-value":
				current.Values[0].Name = "unselected"
			case "mixed-oracles":
				current.Oracles = []PrivateValue{{Name: current.Values[0].Name, Path: "/owner/value", Length: 28}}
			case "relative-oracle":
				current.Oracles = []PrivateValue{{Name: current.Values[0].Name, Path: "value", Length: 28}}
				current.Values = nil
			case "duplicate-oracle-path":
				current.Oracles = []PrivateValue{{Name: current.Values[0].Name, Path: "/owner/value", Length: 28}, {Name: "another", Path: "/owner/value", Length: 28}}
				current.Values = nil
			}
			body, err := json.Marshal(current)
			if err != nil {
				t.Fatal(err)
			}
			if name == "trailing" {
				body = append(body, []byte(" {}")...)
			}
			if name == "unknown-field" {
				body = append([]byte(`{"unexpected":0,`), body[1:]...)
			}
			if _, err := decodeRecoveryFixture(bytes.NewReader(body)); err == nil {
				t.Fatal("incomplete parent carrier accepted")
			}
		})
	}
}

// full_only: false
func TestRecoveryFixtureBothProviderObjectFileTotals(t *testing.T) {
	// These fixed layout terms were independently counted from UTF-8 keys,
	// decoded token bytes and decoded bodies, without reading ObjectFileBytes.
	// Each of the thirteen object files also owns its 28-byte framing header.
	for _, row := range []struct {
		provider                     string
		keyBytes, tokenBytes, bodies uint64
	}{{"aws", 1782, 109, 12229}, {"gcp", 1782, 83, 12458}} {
		t.Run(row.provider, func(t *testing.T) {
			want := uint64(13*28) + row.keyBytes + row.tokenBytes + row.bodies
			fixture := RecoveryFixture{Archive: Load(t, row.provider), Values: []ExpectedValue{{Name: "installed-positive-secret", Bytes: []byte("enkv first secret test value")}}, Secrets: 1}
			if fixture.Archive.ObjectFileBytes != want {
				t.Fatal("fixed object-file total differs")
			}
			body, err := json.Marshal(fixture)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := decodeRecoveryFixture(bytes.NewReader(body))
			if err != nil || decoded.Archive.ObjectFileBytes != want {
				t.Fatal("valid exact object-file total refused")
			}
		})
	}
}

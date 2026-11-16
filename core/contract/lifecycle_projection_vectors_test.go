package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type lifecycleProjectionVector struct {
	valueAccessVector
	Domain ID
}

func checkLifecycleProjection[T any](t *testing.T, v valueAccessVector, decode func([]byte) ([]T, error), encode func([]T) ([]byte, error), descriptor func([]T) (DescriptorVector, error)) {
	t.Helper()
	checkValueAccessVector(t, v, decode, encode)
	var rows []T
	if err := json.Unmarshal(v.Value, &rows); err != nil {
		t.Fatal(err)
	}
	wire, err := hex.DecodeString(v.Hex)
	if err != nil {
		t.Fatal(err)
	}
	want := DescriptorVector{Digest: ID(sha256.Sum256(wire)), Length: uint64(len(wire)), Count: uint32(len(rows))}
	got, err := descriptor(rows)
	if err != nil || got != want {
		t.Fatal("descriptor differs from independent wire literal", err)
	}
}

// full_only: false
func TestLifecycleIndependentProjectionVectors(t *testing.T) {
	data, err := os.ReadFile("../../tests/shared/testdata/lifecycle-projections-schema11.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []lifecycleProjectionVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("empty lifecycle fixture")
	}
	for _, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			v, domain := vector.valueAccessVector, vector.Domain
			switch v.Schema {
			case "comparison":
				checkLifecycleProjection(t, v, DecodeCryptoComparison, EncodeCryptoComparison, CryptoComparisonDescriptor)
			case "comparison-result":
				checkValueAccessVector(t, v, DecodeCryptoCompareResult, EncodeCryptoCompareResult)
			case "union":
				checkLifecycleProjection(t, v,
					func(b []byte) ([]UnionRow, error) { return DecodeUnion(b, domain) },
					func(rows []UnionRow) ([]byte, error) { return EncodeUnion(domain, rows) },
					func(rows []UnionRow) (DescriptorVector, error) { return UnionDescriptor(domain, rows) })
			case "grants":
				checkLifecycleProjection(t, v,
					func(b []byte) ([]MembershipRow, error) { return DecodeGrants(b, domain) },
					func(rows []MembershipRow) ([]byte, error) { return EncodeGrants(domain, rows) },
					func(rows []MembershipRow) (DescriptorVector, error) { return GrantDescriptor(domain, rows) })
			case "exclusions":
				checkLifecycleProjection(t, v,
					func(b []byte) ([]ExclusionRow, error) { return DecodeExclusions(b, domain) },
					func(rows []ExclusionRow) ([]byte, error) { return EncodeExclusions(domain, rows) },
					func(rows []ExclusionRow) (DescriptorVector, error) { return ExclusionDescriptor(domain, rows) })
			case "prepared":
				checkLifecycleProjection(t, v, DecodeCryptoPreparedRows, EncodeCryptoPreparedRows, CryptoPreparedRowsDescriptor)
			default:
				t.Fatal("unknown lifecycle projection")
			}
		})
	}
}

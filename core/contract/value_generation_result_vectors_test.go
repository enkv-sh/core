package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
)

// These answers were calculated once from explicit big-endian fields with
// Node.js Buffer and SHA-256, without a production encoder. B(x) is
// u32be(len(x)) || x. Generator hashes are SHA256(L(label) || B(body)),
// where L(label) is ASCII ENKV/GENERATOR/v1/ || label || NUL.
// IDs in these public vectors repeat their stated octet 32 times.
const generatedVectorCoreHex = "000400020101010101010101010101010101010101010101010101010101010101010101020202020202020202020202" +
	"020202020202020202020202020202020202020203030303030303030303030303030303030303030303030303030303" +
	"030303030404040404040404040404040404040404040404040404040404040404040404050505050505050505050505" +
	"050505050505050505050505050505050505050506060606060606060606060606060606060606060606060606060606" +
	"060606060707070707070707070707070707070707070707070707070707070707070707080808080808080808080808" +
	"080808080808080808080808080808080808080809090909090909090909090909090909090909090909090909090909" +
	"090909090a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0b0b0b0b0b0b0b0b0b0b0b0b" +
	"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c" +
	"0c0c0c0c0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0e0e0e0e0e0e0e0e0e0e0e0e" +
	"0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e"

const generatedVectorFactsCreateHex = "000401020100030303030303030303030303030303030303030303030303030303030303030304040404040404040404" +
	"040404040404040404040404040404040404040404040909090909090909090909090909090909090909090909090909" +
	"0909090909090000000e6163636f756e742f7461726765740000000300ff020000000000"

const generatedVectorFactsResidueHex = "000401020201030303030303030303030303030303030303030303030303030303030303030304040404040404040404" +
	"040404040404040404040404040404040404040404040909090909090909090909090909090909090909090909090909" +
	"0909090909090000000e6163636f756e742f7461726765740000000300ff020000000000"

const generatedVectorFactsDeleteHex = "000402020400030303030303030303030303030303030303030303030303030303030303030304040404040404040404" +
	"040404040404040404040404040404040404040404040909090909090909090909090909090909090909090909090909" +
	"0909090909090000000e6163636f756e742f7461726765740000000300ff020000000000"

const generatedVectorFactsUnknownHex = "000401020508030303030303030303030303030303030303030303030303030303030303030304040404040404040404" +
	"040404040404040404040404040404040404040404040909090909090909090909090909090909090909090909090909" +
	"0909090909090000000e6163636f756e742f7461726765740000000300ff020000000000"

const generatedVectorFactsMaximumPrefixHex = "000401020508030303030303030303030303030303030303030303030303030303030303030304040404040404040404" +
	"040404040404040404040404040404040404040404040909090909090909090909090909090909090909090909090909" +
	"090909090909000000807474747474747474747474747474747474747474747474747474747474747474747474747474" +
	"747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474747474" +
	"747474747474747474747474747474747474747474747474747474747474747474747474747474747474000000407272" +
	"727272727272727272727272727272727272727272727272727272727272727272727272727272727272727272727272" +
	"727272727272727272727272727200000ecd"

func generatedVectorMaximumBytes(t testing.TB) []byte {
	t.Helper()
	// The literal prefix includes provider length3789. Its repeated data and
	// final absent-observation tag complete the independent4096-byte body.
	body := generatedVectorBytes(t, generatedVectorFactsMaximumPrefixHex)
	body = append(body, bytes.Repeat([]byte{'p'}, 3789)...)
	return append(body, 0)
}

func generatedVectorBytes(t testing.TB, literal string) []byte {
	t.Helper()
	b, err := hex.DecodeString(literal)
	if err != nil {
		t.Fatal("invalid independent hex literal")
	}
	return b
}

func generatedVectorID(t testing.TB, literal string) ID {
	t.Helper()
	b := generatedVectorBytes(t, literal)
	if len(b) != 32 {
		t.Fatal("invalid independent ID length")
	}
	return ID(b)
}

// full_only: false
func TestGeneratedVectorResultCoreDigestAndKeyIDs(t *testing.T) {
	core := generatedResultCoreFixture()
	want := generatedVectorBytes(t, generatedVectorCoreHex)
	digest := generatedVectorID(t, "8f4911c40353ecf63f4a8685c534fd680ad4fe82d50c03a3f9ff0de1dd5e5af7")
	if len(want) != 452 || sha256.Sum256(want) != digest {
		t.Fatal("invalid fixed result-core vector")
	}
	got, err := EncodeGeneratedResultCore(core)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("result core differs from independent bytes")
	}
	decoded, err := InspectGeneratedResultCore(want)
	if err != nil || decoded != core {
		t.Fatal("fixed result core changed public fields")
	}
	if got, err := GeneratedResultCoreDigest(core); err != nil || got != digest {
		t.Fatal("result core differs from independent SHA-256")
	}
	for _, row := range []struct {
		result           ID
		data, commitment string
	}{
		{generatedRecordID(8), "9d408ddce1b91f55cbaccfca43a58e903912aa3516de4d0c81044591798e3b77", "50738e0c6b5677df146cb4a0c0701ef56a466a9a73e80d902224a71bd0c5f72b"},
		{generatedRecordID(9), "13b0d6fc7e41cc9ddb35ad633c911777cf8e3f5e3c74282b0a0a8065564042cf", "1fd7b1269169f7e5cfcf5eaede179e8c7c1a5f0fa7eaeff2c8b69e25ea12a4e1"},
	} {
		data, commitment, err := GeneratorResultKeyIDs(row.result)
		if err != nil || data != generatedVectorID(t, row.data) || commitment != generatedVectorID(t, row.commitment) || data == commitment {
			t.Fatal("result-only key IDs differ from independent purpose hashes")
		}
	}
	if _, _, err := GeneratorResultKeyIDs(ID{}); err == nil {
		t.Fatal("zero result received key identities")
	}
	// Every nonzero context change must enter the result commitment.
	for i := range 14 {
		changed := core
		fields := []*ID{&changed.DomainID, &changed.OperationID, &changed.MaterialID, &changed.UsePlanDigest,
			&changed.PlanGraphID, &changed.AttemptID, &changed.TransmissionID, &changed.ResultID, &changed.ExecutorID,
			&changed.DescriptorID, &changed.ConfigContractID, &changed.ResultContractID, &changed.RequestDigest, &changed.SafeFactsDigest}
		fields[i][0] ^= 0x80
		if got, err := GeneratedResultCoreDigest(changed); err != nil || got == digest {
			t.Fatalf("result commitment omitted context field %d", i)
		}
	}
}

// full_only: false
func TestGeneratedVectorSafeFactsClosedBytesAndDigests(t *testing.T) {
	for _, row := range []struct {
		name            string
		disposition     uint8
		literal, digest string
		length          int
	}{
		{"create", 1, generatedVectorFactsCreateHex, "58dc047ebf23a747a9b5ce595bab3b10ae4a014e9e8a46d5417183b8eccfd491", 132},
		{"residue", 2, generatedVectorFactsResidueHex, "a3425b227bbdc01ca4c7fc57eb8013d8c41df3b2c7f24426e753db79eafa34c1", 132},
		{"delete", 4, generatedVectorFactsDeleteHex, "798825bdc41b1aa3c45daa8b200ecfebe20c7909dcb6044da19061c571e6e1d9", 132},
		{"unknown", 5, generatedVectorFactsUnknownHex, "c346e327c22ee288222c79e27121b79082184ae3b81234edba445e5ad2858492", 132},
	} {
		t.Run(row.name, func(t *testing.T) {
			expected := generatedSafeFactsFixture(row.disposition)
			want := generatedVectorBytes(t, row.literal)
			got, err := EncodeGeneratorSafeFacts(expected)
			if err != nil || len(want) != row.length || !bytes.Equal(got, want) {
				t.Fatal("facts differ from independent closed fields", err)
			}
			decoded, err := DecodeGeneratorSafeFacts(want)
			if err != nil || !reflect.DeepEqual(decoded, expected) {
				t.Fatal("fixed facts changed public fields", err)
			}
			if got, err := GeneratorSafeFactsDigest(expected); err != nil || got != generatedVectorID(t, row.digest) {
				t.Fatal("facts differ from independent purpose hash", err)
			}
			for cut := range len(want) {
				if _, err := InspectGeneratorSafeFacts(want[:cut]); err == nil {
					t.Fatalf("accepted fixed facts truncation %d", cut)
				}
			}
			if _, err := InspectGeneratorSafeFacts(append(bytes.Clone(want), 0)); err == nil {
				t.Fatal("accepted trailing facts")
			}
		})
	}
}

func generatedVectorMaximumFacts() GeneratorSafeFacts {
	f := generatedSafeFactsFixture(GeneratorDispositionUnknown)
	f.Target, f.ResourceData, f.ProviderFacts = bytes.Repeat([]byte{'t'}, 128), bytes.Repeat([]byte{'r'}, 64), bytes.Repeat([]byte{'p'}, 3789)
	return f
}

// full_only: false
func TestGeneratedVectorSafeFactsReachesExactMaximum(t *testing.T) {
	facts := generatedVectorMaximumFacts()
	want := generatedVectorMaximumBytes(t)
	// Independent Python struct/hashlib: fixed115 + target128 + resource64
	// + provider3789 =4096. All variable fields coexist at their joint limit.
	if len(want) != 4096 || GeneratorSafeFactsMaxLength != 4096 || sha256.Sum256(want) != generatedVectorID(t, "71aa9157cdbe86f55353b353e2aaf2f191589fde56b5bbfbee5c07f265efb8e2") {
		t.Fatal("invalid fixed maximum facts vector")
	}
	if n, err := GeneratorSafeFactsLength(facts); err != nil || n != 4096 {
		t.Fatal("facts did not reach exact maximum", err)
	}
	encoded, err := EncodeGeneratorSafeFacts(facts)
	if err != nil || !bytes.Equal(encoded, want) {
		t.Fatal("maximum facts differ from independent bytes", err)
	}
	if got, err := GeneratorSafeFactsDigest(facts); err != nil || got != generatedVectorID(t, "59b6ec6977aa934c5f83d2d2032af12464fbbb2c41e74d52f9d15ff25608ce89") {
		t.Fatal("maximum facts differ from independent digest", err)
	}
	view, err := InspectGeneratorSafeFacts(want)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := view.Own()
	if err != nil || !reflect.DeepEqual(owned, facts) {
		t.Fatal("maximum facts changed public fields", err)
	}
	clear(want)
	if _, err := view.Own(); err == nil {
		t.Fatal("changed borrowed facts accepted")
	}
	encoded, err = EncodeGeneratorSafeFacts(owned)
	if err != nil || !bytes.Equal(encoded, generatedVectorMaximumBytes(t)) {
		t.Fatal("owned facts retained borrowed bytes", err)
	}
	for _, field := range []string{"target", "resource", "provider"} {
		bad := generatedVectorMaximumFacts()
		switch field {
		case "target":
			bad.Target = append(bad.Target, 1)
		case "resource":
			bad.ResourceData = append(bad.ResourceData, 1)
		case "provider":
			bad.ProviderFacts = append(bad.ProviderFacts, 1)
		}
		if _, err := EncodeGeneratorSafeFacts(bad); !errors.Is(err, ErrRecordCapacity) {
			t.Fatal("joint first excess did not preserve capacity refusal", field, err)
		}
	}
	if _, err := InspectGeneratorSafeFacts(append(generatedVectorMaximumBytes(t), 0)); !errors.Is(err, ErrRecordCapacity) {
		t.Fatal("maximum plus suffix did not preserve capacity refusal", err)
	}
	for disposition := uint8(6); disposition <= 8; disposition++ {
		facts := generatedSafeFactsFixture(disposition)
		facts.ProviderFacts = bytes.Repeat([]byte{0xff}, 3789-len(facts.Target)-len(facts.ResourceData))
		body, err := EncodeGeneratorSafeFacts(facts)
		if err != nil || len(body) != 4096 {
			t.Fatal("controlled joint maximum", disposition, len(body), err)
		}
		view, err := InspectGeneratorSafeFacts(body)
		if err != nil {
			t.Fatal(err)
		}
		owned, err := view.Own()
		if err != nil || !reflect.DeepEqual(owned, facts) {
			t.Fatal("controlled ownership", disposition, err)
		}
		facts.ProviderFacts = append(facts.ProviderFacts, 1)
		if _, err := EncodeGeneratorSafeFacts(facts); !errors.Is(err, ErrRecordCapacity) {
			t.Fatal("controlled first excess", disposition, err)
		}
	}
	for _, row := range []struct {
		name   string
		offset int
		value  byte
	}{
		{"schema", 1, 3}, {"action", 2, 0}, {"lifecycle", 3, 0}, {"disposition", 4, 9}, {"reason", 5, 255},
		{"target length", 102, 255}, {"resource length", 234, 255}, {"provider length", 302, 255}, {"observation tag", 4095, 2},
	} {
		t.Run(row.name, func(t *testing.T) {
			bad := generatedVectorMaximumBytes(t)
			bad[row.offset] = row.value
			if _, err := InspectGeneratorSafeFacts(bad); err == nil {
				t.Fatal("invalid closed facts accepted")
			}
		})
	}
	for cut := range 4096 {
		if _, err := InspectGeneratorSafeFacts(generatedVectorMaximumBytes(t)[:cut]); err == nil {
			t.Fatalf("accepted maximum facts truncation %d", cut)
		}
	}
}

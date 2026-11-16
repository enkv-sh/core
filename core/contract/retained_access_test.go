package contract

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func seedAccessRow(t testing.TB) CompactRow {
	t.Helper()
	id := func(b byte) ID { return ID(bytes.Repeat([]byte{b}, 32)) }
	fixed := func(s string) ID {
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 32 {
			t.Fatal("invalid fixed hash", err)
		}
		return ID(b)
	}
	context := fixed("ffe405a2c6745769632b1e636fbc1d8c7556696a64d3129165c0395809edf58a")
	core := OperationMaterialCore{Schema: CanonicalSchema, Profile: 2, CompatibilityID: id(1), CryptoSupportID: id(2), DomainID: id(3), OperationID: id(4), OperationMaterialID: id(5), UsePlanDigest: id(6), SeedEpoch: 7}
	access := AccessRecord{Schema: CanonicalSchema, MaterialKind: 3, MaterialID: id(5), MaterialContextDigest: context, PackageCheck: id(8), Wraps: []WrapRow{
		{SubjectKind: 1, SubjectID: id(9), BindingID: id(10), BindingSerial: 11, PublicBindingDigest: id(12), RSACiphertext: bytes.Repeat([]byte{13}, 384)},
		{SubjectKind: 2, SubjectID: id(14), BindingID: id(15), BindingSerial: 16, PublicBindingDigest: id(17), RSACiphertext: bytes.Repeat([]byte{18}, 384)},
	}}
	return CompactRow{Coverage: CoverageRow{MaterialKind: 3, MaterialID: id(5), MaterialContextDigest: context,
		ImmutableBodyDigest:    fixed("16820b4567513303728fcd70bce569c352ece93f755a2e22720c6bb05126edc1"),
		BeforeAccessDigest:     fixed("df5f1ab66744597243d94c47574e1e718aa8686ac8cf011e20cdf9d1414382d9"),
		RequiredConsumerDigest: id(19), SourceBindingIndex: 0, TargetBindingIndices: []uint16{1}}, OperationMaterialCore: core, BeforeAccessRecord: access}
}

// full_only: false
func TestRetainedSeedCompactIndependentDigest(t *testing.T) {
	row := seedAccessRow(t)
	got, err := AccessInputBatchDescriptor([]CompactRow{row})
	if err != nil {
		t.Fatal(err)
	}
	// The one-shot derive-remaining-contract-fields.py reproduces all old hashes
	// before deriving schema11 with independent Python integers and SHA-256.
	// Core: u16(11,2), IDs 01..06 repeated 32 times, u64(7).
	// Material H: L("material") || B(core). Immutable H:
	// L("immutable-material-body-v1") || u16(3) || B(core) || 08*32.
	// Access: u16(11,3), ID05, context, ID08, u16(2), then the two literal
	// wraps above. Coverage: kind3, ID05, context, immutable H, access H,
	// ID19, u16(0,1,1). Batch: L("access-input-batch-v1"), u32(1),
	// B(coverage || B(core204) || B(access1080)). Total: 1505 bytes.
	if got.Length != 1505 || got.Count != 1 || hex.EncodeToString(got.Digest[:]) != "d914d5572cb164078521926d2670eb0720dd8a07743e97ac7881844a181da686" {
		t.Fatal("seed compact independent digest differs", got)
	}
}

// full_only: false
func TestRetainedSeedCompactRejectsChangedContext(t *testing.T) {
	for name, damage := range map[string]func(*CompactRow){
		"inactive value core": func(v *CompactRow) { v.ValueCore.DataKeyEpoch = 1 },
		"seed epoch":          func(v *CompactRow) { v.OperationMaterialCore.SeedEpoch++ },
		"material kind":       func(v *CompactRow) { v.Coverage.MaterialKind = 2 },
		"material id":         func(v *CompactRow) { v.Coverage.MaterialID[0]++ },
		"material context":    func(v *CompactRow) { v.Coverage.MaterialContextDigest[0]++ },
		"immutable body":      func(v *CompactRow) { v.Coverage.ImmutableBodyDigest[0]++ },
		"before access":       func(v *CompactRow) { v.Coverage.BeforeAccessDigest[0]++ },
		"seed check":          func(v *CompactRow) { v.BeforeAccessRecord.PackageCheck[0]++ },
		"extra target":        func(v *CompactRow) { v.Coverage.TargetBindingIndices = []uint16{1, 2} },
	} {
		t.Run(name, func(t *testing.T) {
			row := seedAccessRow(t)
			damage(&row)
			if _, err := AccessInputBatchDescriptor([]CompactRow{row}); err == nil {
				t.Fatal("changed seed context accepted")
			}
		})
	}
}

// full_only: false
func TestAccessOrderUsesKindAndID(t *testing.T) {
	seed := seedAccessRow(t)
	value := accessStructuralRow(t, 0, 2, 0)
	value.ValueCore.ValueStateID = seed.Coverage.MaterialID
	value.Coverage.MaterialID = seed.Coverage.MaterialID
	value.BeforeAccessRecord.MaterialID = seed.Coverage.MaterialID
	var err error
	value.Coverage.MaterialContextDigest, err = ValueMaterialContextDigest(value.ValueCore)
	if err != nil {
		t.Fatal(err)
	}
	value.BeforeAccessRecord.MaterialContextDigest = value.Coverage.MaterialContextDigest
	value.Coverage.BeforeAccessDigest, err = AccessRecordDigest(value.BeforeAccessRecord)
	if err != nil {
		t.Fatal(err)
	}
	for _, rows := range [][]CompactRow{{value, seed}, {seed, value}, {seed, seed}} {
		_, err := AccessInputBatchDescriptor(rows)
		valid := rows[0].Coverage.MaterialKind == 1
		if (err == nil) != valid {
			t.Fatalf("kind/id order validity=%v error=%v", valid, err)
		}
	}
	meta := AccessProjectionMetadata{DomainID: seed.OperationMaterialCore.DomainID, BeforeAccessRoot: Hash([]byte("access")), RequestCoreDigest: Hash([]byte("request"))}
	p, err := NewAccessProjection(meta, DescriptorVector{Digest: Hash([]byte("plan")), Length: 999, Count: 1}, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []CompactRow{value, seed} {
		if err := p.Add(row, AccessOutputRow{MaterialKind: row.Coverage.MaterialKind, MaterialID: row.Coverage.MaterialID, BeforeAccessDigest: row.Coverage.BeforeAccessDigest, AfterAccessRecord: row.BeforeAccessRecord}); err != nil {
			t.Fatal("same ID in different material kinds refused", err)
		}
	}
	if _, _, _, err := p.Descriptors(); err != nil {
		t.Fatal(err)
	}
}

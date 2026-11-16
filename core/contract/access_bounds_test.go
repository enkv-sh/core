package contract

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

// full_only: false
func TestCurrentAccessChecksPerPageRecordAndByteLimits(t *testing.T) {
	control := successionTestRequest(t, 1, 1, 1, true).BeforeControl.CurrentControl
	for _, tc := range []struct {
		name           string
		records, wraps uint32
		pages          int
		valid          bool
	}{
		{"one-full-page", 16, 16 * 65, 1, true},
		{"two-full-pages", 32, 32 * 65, 2, true},
		{"beyond-current-member-packing", 17, 17 * 2, 1, true},
		{"near-page-byte-limit", 477, 4189, 1, true},
		{"first-encodable-length-over-page-byte-limit", 175, 4252, 1, false},
		{"over-page-byte-limit", 478, 4189, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A page has 75 fixed bytes, then raw records: 102 bytes per
			// record and 489 per wrap. The descriptor adds a 4-byte blob
			// prefix per record. These equations do not use an encoder.
			payload := uint64(102*tc.records + 489*tc.wraps)
			refs := make([]Ref, tc.pages)
			for i := range refs {
				refs[i] = Ref{Kind: AccessKind, Format: CanonicalSchema, Domain: control.DomainID, Object: Hash([]byte(fmt.Sprint("page", i))), Index: uint16(i), Length: 75 + uint32(payload/uint64(tc.pages)), Digest: Hash([]byte("page digest"))}
			}
			v := CurrentAccessCore{
				CurrentControl:          control,
				RecipientRefsDescriptor: DescriptorVector{Count: 1, Length: uint64(recipientRefsFixedLength + RefLength), Digest: Hash([]byte("recipient refs"))},
				AccessRecordsDescriptor: DescriptorVector{Count: tc.records, Length: uint64(accessRecordsFixedLength) + 4*uint64(tc.records) + payload, Digest: Hash([]byte("access records"))},
				AccessPageRefs:          refs,
			}
			body, err := EncodeCurrentAccessCore(v)
			if (err == nil) != tc.valid {
				t.Fatalf("per-page admission: valid=%v error=%v", tc.valid, err)
			}
			if tc.valid {
				if _, err := InspectCurrentAccessCore(body); err != nil {
					t.Fatal("encoded access failed inspection", err)
				}
			}
		})
	}
}

func accessStructuralRow(t testing.TB, index, wrapCount, nameLength int) CompactRow {
	t.Helper()
	id := func(n uint32) ID { var v ID; binary.BigEndian.PutUint32(v[28:], n); return v }
	core := ValueCore{ValueSource: 1, Schema: CanonicalSchema, Profile: 2, CompatibilityID: id(1), CryptoSupportID: id(2), DomainID: id(3), Name: strings.Repeat("a", nameLength), EntryIncarnationID: id(uint32(index + 1000)), ValueStateID: id(uint32(index + 1)), OriginSnapshotID: id(4), OriginTransitionID: id(5), DataKeyID: id(6), DataKeyEpoch: 1, CommitmentKeyID: id(7), CommitmentKeyEpoch: 1, InputEncoding: InputEncodingRaw, RetainedLength: 0}
	context, err := ValueMaterialContextDigest(core)
	if err != nil {
		t.Fatal(err)
	}
	access := AccessRecord{Schema: CanonicalSchema, MaterialKind: 1, MaterialID: core.ValueStateID, MaterialContextDigest: context, PackageCheck: id(9)}
	for i := 0; i < wrapCount; i++ {
		kind := uint8(1)
		if i == 64 {
			kind = 2
		}
		access.Wraps = append(access.Wraps, WrapRow{SubjectKind: kind, SubjectID: id(uint32(i + 1)), BindingID: id(uint32(i + 100)), BindingSerial: 1, PublicBindingDigest: id(10), RSACiphertext: make([]byte, 384)})
	}
	before, err := AccessRecordDigest(access)
	if err != nil {
		t.Fatal(err)
	}
	return CompactRow{Coverage: CoverageRow{MaterialKind: 1, MaterialID: core.ValueStateID, MaterialContextDigest: context, ImmutableBodyDigest: id(11), BeforeAccessDigest: before, RequiredConsumerDigest: id(12), SourceBindingIndex: 0, TargetBindingIndices: []uint16{1}}, ValueCore: core, BeforeAccessRecord: access}
}

// full_only: false
func TestAccessBatchExactAndOneByteOver(t *testing.T) {
	rows := make([]CompactRow, 65)
	for i := range rows {
		wraps, name := 65, 0
		if i == 64 {
			wraps, name = 48, 176
		}
		rows[i] = accessStructuralRow(t, i, wraps, name)
	}
	// Independent equation: region=4+65*604+4208*489+176 = 2 MiB.
	if n, err := AccessInputBatchLength(rows); err != nil || n != 2<<20 {
		t.Fatalf("exact batch: length=%d error=%v", n, err)
	}
	rows[64] = accessStructuralRow(t, 64, 48, 177)
	if _, err := AccessInputBatchLength(rows); err != ErrCryptoCapacity {
		t.Fatal("one byte over batch accepted", err)
	}
}

// full_only: false
func TestAccessProjectionAggregateBoundsAndOrder(t *testing.T) {
	id := func(b byte) ID { return ID(bytes.Repeat([]byte{b}, 32)) }
	meta := AccessProjectionMetadata{DomainID: id(1), BeforeAccessRoot: id(2), RequestCoreDigest: id(3)}
	plan := DescriptorVector{Digest: id(4), Length: 999, Count: 1}
	for _, test := range []struct{ recovery, over bool }{{false, false}, {false, true}, {true, false}, {true, true}} {
		t.Run(fmt.Sprint(test), func(t *testing.T) {
			p, err := NewAccessProjection(meta, plan, 512)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 512; i++ {
				wraps := 8
				if test.recovery {
					wraps++
				}
				if test.over && i == 511 {
					wraps++
				}
				row := accessStructuralRow(t, i, wraps, 0)
				if test.recovery {
					row.BeforeAccessRecord.Wraps[wraps-1].SubjectKind = 2
					row.Coverage.BeforeAccessDigest, err = AccessRecordDigest(row.BeforeAccessRecord)
					if err != nil {
						t.Fatal(err)
					}
				}
				preflight := p.ValidateBatch([]CompactRow{row})
				if preflight != nil {
					t.Fatal("valid batch failed private-work preflight", preflight)
				}
				err = p.Add(row, AccessOutputRow{MaterialKind: 1, MaterialID: row.Coverage.MaterialID, BeforeAccessDigest: row.Coverage.BeforeAccessDigest, AfterAccessRecord: row.BeforeAccessRecord})
				if err != nil {
					t.Fatal(i, err)
				}
			}
			if _, _, _, err := p.Descriptors(); err != nil {
				t.Fatal(err)
			}
		})
	}
	// A retained value and a seed can add records beyond the current-entry
	// maximum. The projection limit follows page bytes, not current membership.
	if _, err := NewAccessProjection(meta, plan, 514); err != nil {
		t.Fatal("complete retained-material count refused", err)
	}
	if _, err := NewAccessProjection(meta, plan, 908289); err == nil {
		t.Fatal("page-derived material count overflow accepted")
	}
	p, err := NewAccessProjection(meta, plan, 2)
	if err != nil {
		t.Fatal(err)
	}
	row := accessStructuralRow(t, 1, 2, 0)
	after := AccessOutputRow{MaterialKind: 1, MaterialID: row.Coverage.MaterialID, BeforeAccessDigest: row.Coverage.BeforeAccessDigest, AfterAccessRecord: row.BeforeAccessRecord}
	if err := p.Add(row, after); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := p.Descriptors(); err == nil {
		t.Fatal("incomplete projection accepted")
	}
	if err := p.Add(row, after); err == nil {
		t.Fatal("duplicate projection row accepted")
	}
}

// full_only: false
func TestAccessProjectionEncodedBudgetPrecedesPrivateWork(t *testing.T) {
	meta := AccessProjectionMetadata{DomainID: Hash([]byte("domain")), BeforeAccessRoot: Hash([]byte("access")), RequestCoreDigest: Hash([]byte("request"))}
	plan := DescriptorVector{Digest: Hash([]byte("plan")), Length: 999, Count: 1}
	row := accessStructuralRow(t, 0, 65, 0)
	// Each record has 102 fixed bytes and 489 bytes per wrap. The aggregate
	// wire budget is 256 child pages of 2 MiB, independently of material count.
	length := uint64(102 + 65*489)
	for _, over := range []uint64{0, 1} {
		p, err := NewAccessProjection(meta, plan, 20000)
		if err != nil {
			t.Fatal(err)
		}
		p.accessBytes = 256*(2<<20) - length + over
		before := p.accessBytes
		err = p.ValidateBatch([]CompactRow{row})
		if over == 0 && err != nil || over == 1 && err != ErrCryptoCapacity {
			t.Fatalf("encoded limit: over=%d err=%v", over, err)
		}
		if p.accessBytes != before {
			t.Fatal("preflight consumed the projection")
		}
	}
}

// full_only: false
func TestAccessEmptyProjectionIndependentHashes(t *testing.T) {
	id := func(b byte) ID { return ID(bytes.Repeat([]byte{b}, 32)) }
	p, err := NewAccessProjection(AccessProjectionMetadata{DomainID: id(1), BeforeAccessRoot: id(2), RequestCoreDigest: id(3)}, DescriptorVector{Digest: id(4), Length: 999, Count: 1}, 0)
	if err != nil {
		t.Fatal(err)
	}
	a, b, c, err := p.Descriptors()
	if err != nil {
		t.Fatal(err)
	}
	// Python hashlib.sha256 over ASCII ENKV/CRYPTO/v2/<label> NUL,
	// IDs 01*32,02*32,03*32, optional 04*32+BE64(999)+BE32(1), BE32(0).
	for i, test := range []struct {
		value  DescriptorVector
		length uint64
		hash   string
	}{{a, 178, "5ad2e743559291902ad0dd88dac4e20d172c9a24de75a9fc9eef9b52e23fb9dc"}, {b, 181, "3d9809c3bea93daaa58ae872268505eec740d476faea623be092827f16d83fa5"}, {c, 144, "fa37e2becd2df7a9cedfcd0ac7b62113f251315f8a61e48d8675b68f25267147"}} {
		if test.value.Length != test.length || test.value.Count != 0 || fmt.Sprintf("%x", test.value.Digest) != test.hash {
			t.Fatal("independent empty projection differs", i, test.value)
		}
	}
}

// full_only: false
func TestRetainedAccessUsesRegistryBoundWithoutExpandingCurrentMembers(t *testing.T) {
	row := accessStructuralRow(t, 1, 1, 1).BeforeAccessRecord
	row.Wraps = nil
	for i := 0; i < CryptoMaxRecipients; i++ {
		var id ID
		binary.BigEndian.PutUint32(id[28:], uint32(i+1))
		row.Wraps = append(row.Wraps, WrapRow{SubjectKind: 1, SubjectID: id, BindingID: Hash(append([]byte("retained binding"), id[:]...)), BindingSerial: 1, PublicBindingDigest: Hash([]byte("binding digest")), RSACiphertext: make([]byte, 384)})
	}
	row.Wraps = append(row.Wraps, WrapRow{SubjectKind: 2, SubjectID: Hash([]byte("recovery")), BindingID: Hash([]byte("recovery binding")), BindingSerial: 1, PublicBindingDigest: Hash([]byte("recovery digest")), RSACiphertext: make([]byte, 384)})
	body, err := EncodeAccessRecord(row)
	if err != nil || len(body) != 102+489*257 {
		t.Fatal("registry-bounded retained reader union refused", err)
	}
	if _, err := DecodeAccessRecord(body); err != nil {
		t.Fatal(err)
	}
	var extra ID
	binary.BigEndian.PutUint32(extra[28:], 257)
	last := row.Wraps[len(row.Wraps)-1]
	row.Wraps = append(row.Wraps[:256], WrapRow{SubjectKind: 1, SubjectID: extra, BindingID: Hash([]byte("extra")), BindingSerial: 1, PublicBindingDigest: Hash([]byte("extra digest")), RSACiphertext: make([]byte, 384)}, last)
	if _, err := AccessRecordLength(row); err == nil {
		t.Fatal("retained reader union exceeds registry")
	}
	entry := ValueEntry{Name: "still bounded", Incarnation: Hash([]byte("incarnation")), ValueState: Hash([]byte("value")), OriginSnapshot: Hash([]byte("snapshot")), OriginTransition: Hash([]byte("transition")), ValueSource: Supplied, ConfidentialityClass: Plain, Recipients: make([]ID, 65), InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
	for i := range entry.Recipients {
		binary.BigEndian.PutUint32(entry.Recipients[i][28:], uint32(i+1))
	}
	if _, err := ValueEntryLength(entry); err == nil {
		t.Fatal("retained access extension widened current member recipients")
	}
}

package contract

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"testing"
)

func preservedFixture(t testing.TB) (ControlCore, ValueEntry, []RecipientRecord, AccessRecord) {
	t.Helper()
	c := successionTestRequest(t, 1, 2, 1, true).BeforeControl
	id := func(s string) ID { return Hash([]byte(s)) }
	m := ValueEntry{Name: "plain", Incarnation: id("incarnation"), ValueState: id("state"), OriginSnapshot: id("snapshot"), OriginTransition: id("transition"), ValueSource: Supplied, ConfidentialityClass: Plain, Recipients: []ID{c.AuthorityRecipientID}, ValueBytes: []byte("preserved payload"), InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, ContentLength: uint32(len([]byte("preserved payload"))), RetainedLength: uint32(len([]byte("preserved payload")))}
	reader := successionTestKMS(t, 8)
	registry := []RecipientRecord{{RecipientID: c.AuthorityRecipientID, Status: CurrentRecipient, CurrentBinding: &c.AuthorityKMSBinding}, {RecipientID: id("reader"), Status: CurrentRecipient, CurrentBinding: &reader}}
	a := AccessRecord{Schema: CanonicalSchema, MaterialKind: 1, MaterialID: id("material"), MaterialContextDigest: id("material context"), PackageCheck: id("key confirmation"), Wraps: []WrapRow{{SubjectKind: 1, SubjectID: c.AuthorityRecipientID, BindingID: c.AuthorityKMSBinding.BindingID, BindingSerial: 1, PublicBindingDigest: id("public authority"), RSACiphertext: bytes.Repeat([]byte{1}, 384)}, {SubjectKind: 2, SubjectID: c.Recovery.RoleID, BindingID: c.Recovery.KMS.BindingID, BindingSerial: 1, PublicBindingDigest: id("public recovery"), RSACiphertext: bytes.Repeat([]byte{2}, 384)}}}
	return c, m, registry, a
}

func projectPreservedFixture(t testing.TB, c ControlCore, mask uint8, m ValueEntry, registry []RecipientRecord, access AccessRecord, support ...SupportRecord) DigestLength {
	t.Helper()
	p, err := NewPreservedStateProjection(c, mask, 1, 2, 1, uint32(len(support)))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AddValueEntry(3, m); err != nil {
		t.Fatal(err)
	}
	for i, row := range registry {
		if err := p.AddRecipient(uint16(i+2), row); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.AddAccess(access); err != nil {
		t.Fatal(err)
	}
	for _, row := range support {
		if err := p.AddWorkSupport(row); err != nil {
			t.Fatal(err)
		}
	}
	d, err := p.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// full_only: false
func TestPreservedStateIndependentAuthorityOmission(t *testing.T) {
	c, m, recipients, access := preservedFixture(t)
	got := projectPreservedFixture(t, c, 2, m, recipients, access)
	// Direct field order and standard integer appends derive this nonproduction
	// preimage. No production projection, entry, recipient or access writer is
	// used to build the expected bytes.
	want := []byte("ENKV/CRYPTO/v2/succession-preserved-state-v2\x00")
	want = append(want, 0, 11)
	want = successionExpectedIDs(want, c.DomainID)
	want = append(want, 2)
	want = successionExpectedIDs(want, c.CryptoSupportID, c.CompatibilityID)
	want = append(want, byte(c.Provider))
	want = successionExpectedIDs(want, c.StoreID, c.CoordinateID, c.NonBodyID, c.TrustInterpretationID, c.AuthorityRecipientID)
	want = append(want, 1)
	want = successionExpectedIDs(want, c.Recovery.RoleID)
	want = append(want, 0, 1, 0, 3)
	entryBytes := successionExpectedBlob(nil, []byte(m.Name))
	entryBytes = successionExpectedIDs(entryBytes, m.Incarnation, m.ValueState, m.OriginSnapshot, m.OriginTransition)
	entryBytes = append(entryBytes, byte(m.ValueSource), byte(m.ConfidentialityClass), 1)
	entryBytes = binary.BigEndian.AppendUint32(entryBytes, m.ContentLength)
	entryBytes = binary.BigEndian.AppendUint32(entryBytes, m.RetainedLength)
	entryBytes = append(entryBytes, 1, 0, 1)
	entryBytes = successionExpectedIDs(entryBytes, c.AuthorityRecipientID)
	entryBytes = successionExpectedBlob(entryBytes, m.ValueBytes)
	entryBytes = append(entryBytes, 0, 0, 0, 0)
	want = successionExpectedBlob(want, entryBytes)
	want = append(want, 0, 2)
	for i, recipient := range recipients {
		want = binary.BigEndian.AppendUint16(want, uint16(i+2))
		row := successionExpectedIDs(nil, recipient.RecipientID)
		row = append(row, 1, 0, 0, 0, 0)
		var binding []byte
		if i != 0 {
			binding = successionExpectedKMS(*recipient.CurrentBinding)
		}
		row = successionExpectedBlob(row, binding)
		want = successionExpectedBlob(want, row)
	}
	want = append(want, 0, 0, 0, 1)
	row := []byte{0, 11, 0, 1}
	row = successionExpectedIDs(row, access.MaterialID, access.MaterialContextDigest, access.PackageCheck)
	row = append(row, 0, 1)
	wrap := access.Wraps[1]
	row = append(row, wrap.SubjectKind)
	row = successionExpectedIDs(row, wrap.SubjectID, wrap.BindingID)
	row = binary.BigEndian.AppendUint64(row, wrap.BindingSerial)
	row = successionExpectedIDs(row, wrap.PublicBindingDigest)
	row = append(row, wrap.RSACiphertext...)
	want = successionExpectedBlob(want, row)
	want = append(want, 0, 0, 0, 0)
	if got.Digest != Hash(want) || got.Length != uint64(len(want)) {
		t.Fatalf("preserved bytes differ: got length=%d want=%d", got.Length, len(want))
	}
}

// full_only: false
func TestPreservedStateAllowsOnlyNamedKEKFields(t *testing.T) {
	c, m, registry, access := preservedFixture(t)
	before := projectPreservedFixture(t, c, 2, m, registry, access)
	next := successionTestKMS(t, 9)
	next.BindingSerial = 2
	c.AuthorityKMSBinding = next
	registry[0].CurrentBinding = &next
	access.Wraps[0].BindingID = next.BindingID
	access.Wraps[0].BindingSerial = 2
	access.Wraps[0].PublicBindingDigest = Hash([]byte("new authority"))
	access.Wraps[0].RSACiphertext = bytes.Repeat([]byte{3}, 384)
	if after := projectPreservedFixture(t, c, 2, m, registry, access); after != before {
		t.Fatal("authorized authority KEK change altered preserved material")
	}
	access.Wraps[1].RSACiphertext = bytes.Repeat([]byte{4}, 384)
	if after := projectPreservedFixture(t, c, 2, m, registry, access); after.Digest == before.Digest {
		t.Fatal("unaffected recovery wrap omitted")
	}
	access.Wraps[1].RSACiphertext = bytes.Repeat([]byte{2}, 384)
	m.ValueBytes = []byte("altered payload")
	m.ContentLength, m.RetainedLength = uint32(len(m.ValueBytes)), uint32(len(m.ValueBytes))
	if after := projectPreservedFixture(t, c, 2, m, registry, access); after.Digest == before.Digest {
		t.Fatal("member payload omitted")
	}
}

// full_only: false
func TestPreservedStateRequiresCompleteOrderedWalk(t *testing.T) {
	c, m, registry, access := preservedFixture(t)
	p, err := NewPreservedStateProjection(c, 2, 1, 2, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Digest(); err == nil {
		t.Fatal("incomplete projection finalized")
	}
	if err := p.AddAccess(access); err == nil {
		t.Fatal("reordered section accepted")
	}
	if err := p.AddValueEntry(3, m); err == nil {
		t.Fatal("failed projection resumed")
	}
	p, err = NewPreservedStateProjection(c, 2, 0, 2, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AddRecipient(2, registry[0]); err != nil {
		t.Fatal(err)
	}
	if err := p.AddRecipient(2, registry[1]); err == nil {
		t.Fatal("duplicate recipient slot accepted")
	}
}

// full_only: false
func TestPreservedStateKeepsSeedAndAcceptedMeaning(t *testing.T) {
	c, entry, registry, access := preservedFixture(t)
	access.MaterialKind = 3
	work := generatedRecordPhase()
	work.DomainID = c.DomainID
	body, err := EncodeGeneratedPhaseRecord(work)
	if err != nil {
		t.Fatal(err)
	}
	support := SupportRecord{Kind: 5, RecordID: work.OperationID, Body: body}
	before := projectPreservedFixture(t, c, 2, entry, registry, access, support)
	access.Wraps[0].RSACiphertext = bytes.Repeat([]byte{3}, 384)
	if after := projectPreservedFixture(t, c, 2, entry, registry, access, support); after != before {
		t.Fatal("authorized seed wrapper change altered preserved work")
	}
	access.PackageCheck[0]++
	if after := projectPreservedFixture(t, c, 2, entry, registry, access, support); after.Digest == before.Digest {
		t.Fatal("seed confirmation omitted from preserved state")
	}
	access.PackageCheck[0]--
	work.OperationID = Hash([]byte("different operation"))
	body, err = EncodeGeneratedPhaseRecord(work)
	if err != nil {
		t.Fatal(err)
	}
	support = SupportRecord{Kind: 5, RecordID: work.OperationID, Body: body}
	if after := projectPreservedFixture(t, c, 2, entry, registry, access, support); after.Digest == before.Digest {
		t.Fatal("accepted operation identity omitted from preserved state")
	}
	if after := projectPreservedFixture(t, c, 2, entry, registry, access); after.Digest == before.Digest {
		t.Fatal("accepted work removal omitted from preserved state")
	}
}

// full_only: false
func TestPreservedStateKeepsDetachedOwnersAndPendingInboxRelease(t *testing.T) {
	c, entry, registry, access := preservedFixture(t)
	var records []SupportRecord
	duty := generatedRecordDuty()
	duty.DomainID = c.DomainID
	body, err := EncodeGeneratedDutyRecord(duty)
	if err != nil {
		t.Fatal(err)
	}
	records = append(records, SupportRecord{Kind: 10, RecordID: duty.DutyID, Body: body})
	hazard := generatedRecordHazard()
	hazard.DomainID = c.DomainID
	body, err = EncodeGeneratedHazardRecord(hazard)
	if err != nil {
		t.Fatal(err)
	}
	records = append(records, SupportRecord{Kind: 11, RecordID: hazard.HazardID, Body: body})
	release := generatedRecordRelease()
	release.DomainID = c.DomainID
	body, err = EncodePendingInboxReleaseRecord(release)
	if err != nil {
		t.Fatal(err)
	}
	records = append(records, SupportRecord{Kind: 12, RecordID: release.InboxID, Body: body})
	before := projectPreservedFixture(t, c, 2, entry, registry, access, records...)
	for i := range records {
		retained := append([]SupportRecord(nil), records[:i]...)
		retained = append(retained, records[i+1:]...)
		if after := projectPreservedFixture(t, c, 2, entry, registry, access, retained...); after == before {
			t.Fatal("live owner or pending release omitted", records[i].Kind)
		}
	}
	wrong := records[2]
	release.DomainID[0] ^= 1
	wrong.Body, err = EncodePendingInboxReleaseRecord(release)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPreservedStateProjection(c, 2, 0, 2, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i, recipient := range registry {
		if err := p.AddRecipient(uint16(i), recipient); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.AddWorkSupport(wrong); err == nil {
		t.Fatal("cross-domain live owner accepted")
	}
}

// full_only: false
func TestPreservedStateRequiresCompleteWorkSupport(t *testing.T) {
	c, _, registry, _ := preservedFixture(t)
	p, err := NewPreservedStateProjection(c, 2, 0, 2, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i, row := range registry {
		if err := p.AddRecipient(uint16(i), row); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Digest(); err == nil {
		t.Fatal("incomplete work support finalized")
	}
	if err := p.AddWorkSupport(SupportRecord{Kind: 7, RecordID: Hash([]byte("receipt"))}); err == nil {
		t.Fatal("receipt admitted as unchanged work support")
	}
}

// full_only: false
func TestPreservedStateKeepsCompleteRetainedReaderUnion(t *testing.T) {
	c, entry, registry, access := preservedFixture(t)
	access.Wraps = nil
	for i := 0; i < CryptoMaxRecipients; i++ {
		var subject ID
		binary.BigEndian.PutUint32(subject[28:], uint32(i+1))
		access.Wraps = append(access.Wraps, WrapRow{SubjectKind: 1, SubjectID: subject,
			BindingID: Hash(subject[:]), BindingSerial: 1, PublicBindingDigest: Hash([]byte("binding")), RSACiphertext: bytes.Repeat([]byte{byte(i)}, 384)})
	}
	access.Wraps = append(access.Wraps, WrapRow{SubjectKind: 2, SubjectID: c.Recovery.RoleID,
		BindingID: c.Recovery.KMS.BindingID, BindingSerial: 1, PublicBindingDigest: Hash([]byte("recovery")), RSACiphertext: bytes.Repeat([]byte{3}, 384)})
	before := projectPreservedFixture(t, c, 1, entry, registry, access)
	access.Wraps[CryptoMaxRecipients-1].RSACiphertext[0]++
	if after := projectPreservedFixture(t, c, 1, entry, registry, access); after == before {
		t.Fatal("last ordinary reader omitted from complete projection")
	}
}

// full_only: false
func TestPreservedStateCountsLogicalBase64Content(t *testing.T) {
	control, entry, registry, access := preservedFixture(t)
	projection, err := NewPreservedStateProjection(control, 2, 512, 2, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	var content, retained uint64
	for slot := 0; slot < 512; slot++ {
		length := 1
		if slot < 127 {
			length = 65536
		} else if slot == 511 {
			length = 65152
		}
		row := entry
		row.Name = fmt.Sprintf("value%03d", slot)
		row.Incarnation, row.ValueState = Hash([]byte(row.Name+" incarnation")), Hash([]byte(row.Name+" material"))
		row.InputEncoding = InputEncodingBase64
		row.ContentLength = uint32(length)
		row.ValueBytes = []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'d'}, length)))
		row.RetainedLength = uint32(len(row.ValueBytes))
		content += uint64(length)
		retained += uint64(len(row.ValueBytes))
		if err := projection.AddValueEntry(uint16(slot), row); err != nil {
			t.Fatal("logical Base64 set was charged retained bytes", slot, err)
		}
	}
	if content != 8388608 || retained != 11186176 {
		t.Fatal("independent padding construction changed", content, retained)
	}
	for i, row := range registry {
		if err := projection.AddRecipient(uint16(i+2), row); err != nil {
			t.Fatal(err)
		}
	}
	if err := projection.AddAccess(access); err != nil {
		t.Fatal(err)
	}
	if _, err := projection.Digest(); err != nil {
		t.Fatal("complete logical Base64 walk refused", err)
	}
}

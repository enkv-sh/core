package contract

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

func successorEvidenceVector() ([]SuccessorEvidenceRow, []byte, []byte) {
	id := successionTestID
	sig := []byte{0x30, 6, 2, 1, 1, 2, 1, 1}
	rows := []SuccessorEvidenceRow{{TargetRole: 1, EvidenceKind: 1, Trust: SuccessorTrustEvidence{SuccessorSignerFields: SuccessorSignerFields{ProbeAttemptID: id(1), SigningBindingDigest: id(2)}, Signature: sig}},
		{TargetRole: 2, EvidenceKind: 2, KEK: QualifiedSuccessorRow{ProbeID: id(3), QualifiedBindingFields: QualifiedBindingFields{SubjectKind: 1, SubjectID: id(4), BindingID: id(5), PublicBindingDigest: id(6), Provider: GCP, Qualified: 1}}}}
	b := successionExpectedIDs([]byte{2, 1, 1}, id(1), id(2))
	b = append(b, 0, 8)
	b = append(b, sig...)
	keK := successionExpectedIDs([]byte{2, 2}, id(3))
	keK = append(keK, 1)
	keK = successionExpectedIDs(keK, id(4), id(5), id(6))
	keK = append(keK, 2, 1)
	b = append(b, keK...)
	plan := []byte("ENKV/CRYPTO/v2/successor-evidence-plan-v1\x00")
	plan = successionExpectedIDs(append(plan, 2, 1, 1), id(1), id(2))
	plan = append(plan, keK...)
	return rows, b, plan
}

// full_only: false
func TestSuccessorEvidenceIndependentBytesAndOwnership(t *testing.T) {
	rows, want, planWant := successorEvidenceVector()
	got, err := EncodeSuccessorEvidenceVector(rows)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("evidence differs from independent bytes", err)
	}
	d, err := SuccessorEvidenceDigest(rows)
	core := successionExpectedBlob([]byte("ENKV/CRYPTO/v2/successor-evidence-v1\x00"), want)
	if err != nil || d != Hash(core) {
		t.Fatal("evidence digest differs")
	}
	decoded, err := DecodeSuccessorEvidenceVector(want)
	if err != nil || !reflect.DeepEqual(decoded, rows) {
		t.Fatal("evidence decode differs", err)
	}
	clear(want)
	if !reflect.DeepEqual(decoded, rows) {
		t.Fatal("decoded signatures borrow input")
	}
	plan, err := PlanSuccessorEvidence(rows)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := EncodeSuccessorEvidencePlanCore(plan)
	if err != nil || !bytes.Equal(actual, planWant) {
		t.Fatal("evidence plan differs")
	}
	pd, err := EvidencePlanDigest(plan)
	if err != nil || pd != Hash(planWant) || pd == d {
		t.Fatal("plan hash differs or purpose collided")
	}
	rows[0].Trust.Signature = []byte{0x30, 6, 2, 1, 2, 2, 1, 1}
	other, err := PlanSuccessorEvidence(rows)
	if err != nil || !reflect.DeepEqual(other, plan) {
		t.Fatal("signature randomness changed proof-free plan")
	}
	d2, err := SuccessorEvidenceDigest(rows)
	if err != nil || d == d2 {
		t.Fatal("actual evidence omitted signature")
	}
	if _, err := DecodeSuccessorEvidenceVector(actual); err == nil {
		t.Fatal("plan accepted as actual evidence")
	}
}

// full_only: false
func TestSuccessorEvidenceRefusesMalformedAndMixedRows(t *testing.T) {
	for name, change := range map[string]func([]SuccessorEvidenceRow){
		"duplicate role": func(v []SuccessorEvidenceRow) { v[1] = v[0] }, "wrong kind": func(v []SuccessorEvidenceRow) { v[0].EvidenceKind = 2 },
		"zero binding digest": func(v []SuccessorEvidenceRow) { v[0].Trust.SigningBindingDigest = ID{} },
		"zero probe":          func(v []SuccessorEvidenceRow) { v[1].KEK.ProbeID = ID{} }, "zero KEK digest": func(v []SuccessorEvidenceRow) { v[1].KEK.PublicBindingDigest = ID{} },
		"wrong KEK subject": func(v []SuccessorEvidenceRow) { v[1].KEK.SubjectKind = 2 }, "unqualified": func(v []SuccessorEvidenceRow) { v[1].KEK.Qualified = 0 },
		"missing signature": func(v []SuccessorEvidenceRow) { v[0].Trust.Signature = nil }, "bad signature": func(v []SuccessorEvidenceRow) { v[0].Trust.Signature = []byte{1} },
		"oversize signature": func(v []SuccessorEvidenceRow) { v[0].Trust.Signature = make([]byte, 73) },
		"hidden KEK":         func(v []SuccessorEvidenceRow) { v[0].KEK = v[1].KEK }, "hidden signer": func(v []SuccessorEvidenceRow) { v[1].Trust = v[0].Trust },
	} {
		t.Run(name, func(t *testing.T) {
			v, _, _ := successorEvidenceVector()
			change(v)
			if _, err := EncodeSuccessorEvidenceVector(v); err == nil {
				t.Fatal("invalid evidence admitted")
			}
		})
	}
	_, wire, _ := successorEvidenceVector()
	for n := 0; n < len(wire); n++ {
		if _, err := DecodeSuccessorEvidenceVector(wire[:n]); err == nil {
			t.Fatalf("truncation accepted %d", n)
		}
	}
	if _, err := DecodeSuccessorEvidenceVector(append(bytes.Clone(wire), 0)); err == nil {
		t.Fatal("suffix accepted")
	}
	if _, err := DecodeSuccessorEvidenceVector([]byte{3}); err == nil {
		t.Fatal("excess rows admitted")
	}
}

// full_only: false
func TestSuccessorSigningProbeIndependentBytesAndRequiredIDs(t *testing.T) {
	id := successionTestID
	v := SuccessorProbeCore{Schema: 1, EvidenceKind: 1, TargetRole: 1, DomainID: id(1), CoordinateID: id(2), AdmissionID: id(3), PredecessorFullHEADDigest: id(4), RequestCoreDigest: id(5), SuccessorBindingDigest: id(6), ProbeAttemptID: id(7)}
	want := []byte{0, 1, 1, 1}
	for n := byte(1); n <= 7; n++ {
		want = append(want, bytes.Repeat([]byte{n}, 32)...)
	}
	got, err := EncodeSuccessorProbeCore(v)
	if err != nil || len(got) != 228 || !bytes.Equal(got, want) {
		t.Fatal("signing probe bytes differ", err)
	}
	preimage := []byte("ENKV/CRYPTO/v2/successor-signer-probe\x00")
	preimage = binary.BigEndian.AppendUint32(preimage, 228)
	preimage = append(preimage, want...)
	q, err := NewSuccessorSignerProbeRequest(v)
	if err != nil || q.Purpose() != 7 || q.Digest() != Hash(preimage) {
		t.Fatal("probe signing purpose/digest differs")
	}
	for i := 0; i < 7; i++ {
		bad := v
		fields := []*ID{&bad.DomainID, &bad.CoordinateID, &bad.AdmissionID, &bad.PredecessorFullHEADDigest, &bad.RequestCoreDigest, &bad.SuccessorBindingDigest, &bad.ProbeAttemptID}
		*fields[i] = ID{}
		if _, err := NewSuccessorSignerProbeRequest(bad); err == nil {
			t.Fatalf("probe zero field %d admitted", i)
		}
	}
	for _, role := range []uint8{0, 2, 4, 255} {
		bad := v
		bad.TargetRole = role
		if _, err := NewSuccessorSignerProbeRequest(bad); err == nil {
			t.Fatal("nonsigner target admitted")
		}
	}
	v.TargetRole = 3
	recovery, err := NewSuccessorSignerProbeRequest(v)
	if err != nil || recovery.Digest() == q.Digest() {
		t.Fatal("probe omitted role")
	}
	// Role is in the typed digest. Both Trust role allowlists admit the probe
	// purpose; the accepting caller must also match this exact target role.
	if !SigningPurposeAllowed(1, q.Purpose()) || !SigningPurposeAllowed(2, q.Purpose()) {
		t.Fatal("probe purpose is unavailable to a signer")
	}
}

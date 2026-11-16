package contract

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"testing"
)

func successionTestID(n byte) (id ID) {
	for i := range id {
		id[i] = n
	}
	return id
}

// Every ID is one repeated byte. The expected image follows the specified
// field order with standard big-endian writes, independent of production.
func successionSubjectVector() (SuccessionSubject, []byte) {
	id := successionTestID
	v := SuccessionSubject{Schema: CanonicalSchema, OperationKind: 1, ApprovalRole: 1, OperationID: id(1), AdmissionID: id(3), RequestCoreDigest: id(4), RequestIdentityDigest: id(2), IdentityPlanDigest: id(5), BeforeControlDigest: id(6), AfterControlDigest: id(7), BeforeAccessRoot: id(8), AfterAccessRoot: id(9), PreservedStateDigest: id(10), CoverageDigest: id(11), ReplacementPlanDigest: id(12), SuccessorEvidenceDigest: id(13), ReceiptDeltaDigest: id(14), HeadCoreDigest: id(15), ConditionalPlanDigest: id(16), IdentityPlanLength: uint32(identityBaseLength), HeadCoreLength: 420, CoverageCount: 2, ReplacementCount: 2, SuccessorEvidenceCount: 2, ChangeMask: 3, MaterialSourceRole: SuccessionMaterialAuthority}
	b := []byte("ENKV/SUCCESSION/v9\x00")
	b = append(b, 0, 11, 1, 1)
	for n := byte(1); n <= 16; n++ {
		if n == 2 {
			continue
		}
		b = append(b, bytes.Repeat([]byte{n}, 32)...)
		if n == 4 {
			b = append(b, bytes.Repeat([]byte{2}, 32)...)
		}
	}
	b = binary.BigEndian.AppendUint32(b, uint32(len("ENKV/LIFECYCLE-ID-PLAN/v7\x00")+4*32+8))
	b = binary.BigEndian.AppendUint32(b, 420)
	b = binary.BigEndian.AppendUint32(b, 2)
	b = append(b, 0, 2, 2, 0, 3, 1)
	return v, b
}

// full_only: false
func TestSuccessionSubjectIndependentBytesAndPurposes(t *testing.T) {
	v, want := successionSubjectVector()
	got, err := EncodeSuccessionSubject(v)
	if err != nil || len(got) != 553 || !bytes.Equal(got, want) {
		t.Fatal("subject differs from independent bytes", err)
	}
	decoded, err := DecodeSuccessionSubject(want)
	if err != nil || decoded != v {
		t.Fatal("subject decode differs", err)
	}
	k2, err := NewK2SuccessionRequest(v)
	if err != nil || k2.Purpose() != 4 || k2.Digest() != Hash(want) {
		t.Fatal("K2 subject purpose/digest differs")
	}
	digest := k2.Digest()
	if hex.EncodeToString(digest[:]) != "4be85274511296f5b6e79d3f8968dbe1ba7764ddf63306f5c2c58d7f68d1b97b" {
		t.Fatal("K2 differs from independent SHA256 literal")
	}
	if _, err := NewK3SuccessionRequest(v); err == nil {
		t.Fatal("K3 accepted K2 approval role")
	}
	v.ApprovalRole = 2
	want[len("ENKV/SUCCESSION/v9\x00")+3] = 2
	k3, err := NewK3SuccessionRequest(v)
	if err != nil || k3.Purpose() != 5 || k3.Digest() != Hash(want) || k3.Digest() == k2.Digest() {
		t.Fatal("K3 subject purpose/digest differs")
	}
	digest = k3.Digest()
	if hex.EncodeToString(digest[:]) != "27c4d2628a0bed4f63fe64142f5eb1c17b70e0cab2db04323faabe2eb3cb3467" {
		t.Fatal("K3 differs from independent SHA256 literal")
	}
	if _, err := NewK2SuccessionRequest(v); err == nil {
		t.Fatal("K2 accepted K3 approval role")
	}
	for n := 0; n < len(want); n++ {
		if _, err := DecodeSuccessionSubject(want[:n]); err == nil {
			t.Fatalf("truncation accepted at %d", n)
		}
	}
	if _, err := DecodeSuccessionSubject(append(bytes.Clone(want), 0)); err == nil {
		t.Fatal("subject suffix accepted")
	}
}

// full_only: false
func TestSuccessionSubjectRefusesCoverageCountsAndHoles(t *testing.T) {
	for name, change := range map[string]func(*SuccessionSubject){
		"schema": func(v *SuccessionSubject) { v.Schema = 3 }, "approval": func(v *SuccessionSubject) { v.ApprovalRole = 3 },
		"unknown mask": func(v *SuccessionSubject) { v.ChangeMask = 16 }, "wrong mask": func(v *SuccessionSubject) { v.ChangeMask = 4 },
		"omitted replacement": func(v *SuccessionSubject) { v.ReplacementCount = 1 }, "omitted evidence": func(v *SuccessionSubject) { v.SuccessorEvidenceCount = 1 },
		"normal receipt": func(v *SuccessionSubject) { v.ReceiptDeltaCount = 1 }, "recovery receipt omitted": func(v *SuccessionSubject) { v.OperationKind = 3; v.ChangeMask = 12 },
		"signer private coverage": func(v *SuccessionSubject) { v.ChangeMask = 1; v.ReplacementCount = 1; v.SuccessorEvidenceCount = 1 },
		"coverage excess":         func(v *SuccessionSubject) { v.CoverageCount = AccessMaterialLimit + 1 },
		"identity length":         func(v *SuccessionSubject) { v.IdentityPlanLength++ }, "head short": func(v *SuccessionSubject) { v.HeadCoreLength = 418 }, "head large": func(v *SuccessionSubject) { v.HeadCoreLength = 675 },
	} {
		t.Run(name, func(t *testing.T) {
			v, _ := successionSubjectVector()
			change(&v)
			if _, err := EncodeSuccessionSubject(v); err == nil {
				t.Fatal("invalid subject admitted")
			}
		})
	}
	for i := 0; i < 16; i++ {
		v, _ := successionSubjectVector()
		fields := []*ID{&v.OperationID, &v.AdmissionID, &v.RequestCoreDigest, &v.RequestIdentityDigest, &v.IdentityPlanDigest, &v.BeforeControlDigest, &v.AfterControlDigest, &v.BeforeAccessRoot, &v.AfterAccessRoot, &v.PreservedStateDigest, &v.CoverageDigest, &v.ReplacementPlanDigest, &v.SuccessorEvidenceDigest, &v.ReceiptDeltaDigest, &v.HeadCoreDigest, &v.ConditionalPlanDigest}
		*fields[i] = ID{}
		if _, err := NewK2SuccessionRequest(v); err == nil {
			t.Fatalf("zero subject field %d admitted", i)
		}
	}
}

// full_only: false
func TestSuccessionAuthorizationPlanHasOnlyNamedHoles(t *testing.T) {
	s, _ := successionSubjectVector()
	s.RequestIdentityDigest, s.HeadCoreDigest, s.ConditionalPlanDigest = ID{}, ID{}, ID{}
	v := SuccessionAuthorizationPlan{Subject: SuccessionAuthorizationSubject(s), Authorizer: successionTestSigning(t, 1, 1)}
	got, err := EncodeSuccessionAuthorizationPlan(v)
	if err != nil {
		t.Fatal(err)
	}
	_, subject := successionSubjectVector()
	clear(subject[len("ENKV/SUCCESSION/v9\x00")+4+3*32 : len("ENKV/SUCCESSION/v9\x00")+4+4*32])
	clear(subject[len("ENKV/SUCCESSION/v9\x00")+4+14*32 : len("ENKV/SUCCESSION/v9\x00")+4+16*32])
	want := successionExpectedBlob([]byte{1}, successionExpectedSigning(v.Authorizer))
	want = append(want, subject...)
	if !bytes.Equal(got, want) {
		t.Fatal("authorization plan changed another field")
	}
	d, err := SuccessionAuthorizationPlanDigest(v)
	if err != nil || d != Hash(want) {
		t.Fatal("authorization plan hash differs")
	}
	if _, err := NewK2SuccessionRequest(s); err == nil {
		t.Fatal("plan used as signing subject")
	}
	for _, change := range []func(*SuccessionAuthorizationPlan){func(x *SuccessionAuthorizationPlan) { x.Subject.RequestIdentityDigest = successionTestID(2) }, func(x *SuccessionAuthorizationPlan) { x.Subject.HeadCoreDigest = successionTestID(9) }, func(x *SuccessionAuthorizationPlan) { x.Subject.ConditionalPlanDigest = successionTestID(9) }, func(x *SuccessionAuthorizationPlan) { x.Authorizer = successionTestSigning(t, 2, 2) }} {
		bad := v
		change(&bad)
		if _, err := EncodeSuccessionAuthorizationPlan(bad); err == nil {
			t.Fatal("invalid authorization plan admitted")
		}
	}
	clone := v
	clone.Authorizer.Binding.Epoch++
	b, err := EncodeSuccessionAuthorizationPlan(clone)
	if err != nil || reflect.DeepEqual(got, b) {
		t.Fatal("plan omitted authorizer epoch")
	}
}

// full_only: false
func TestSuccessionSubjectRefusesRetiredKind(t *testing.T) {
	for _, approval := range []uint8{1, 2} {
		v, wire := successionSubjectVector()
		v.OperationKind, v.ChangeMask, v.ApprovalRole = 3, 4, approval
		v.CoverageCount, v.ReplacementCount, v.SuccessorEvidenceCount, v.ReceiptDeltaCount = 0, 1, 1, 1
		v.MaterialSourceRole = SuccessionMaterialNone
		wire[len("ENKV/SUCCESSION/v9\x00")+2], wire[len("ENKV/SUCCESSION/v9\x00")+3] = 3, approval
		// The last ten bytes are coverage count, replacement count, evidence
		// count, receipt count and mask, in the specified big-endian order.
		copy(wire[len(wire)-10:], []byte{0, 0, 0, 0, 0, 1, 1, 1, 4, 0})
		if got, err := EncodeSuccessionSubject(v); err != nil || !bytes.Equal(got, wire) {
			t.Fatal("supported recovery signer subject differs", err)
		}
		if got, err := DecodeSuccessionSubject(wire); err != nil || got != v {
			t.Fatal("supported recovery signer subject refused", err)
		}
		v.OperationKind = 2
		wire[len("ENKV/SUCCESSION/v9\x00")+2] = 2
		if _, err := EncodeSuccessionSubject(v); err == nil {
			t.Errorf("approval %d: retired subject kind encoded", approval)
		}
		if _, err := DecodeSuccessionSubject(wire); err == nil {
			t.Errorf("approval %d: valid-length retired subject kind decoded", approval)
		}
	}
}

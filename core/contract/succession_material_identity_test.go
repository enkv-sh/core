package contract

import (
	"bytes"
	"testing"
)

// full_only: false
func TestSuccessionRequestCommitsFixedMaterialRouteWithoutMaterialRows(t *testing.T) {
	for _, choice := range [][2]uint8{{1, 1}, {1, 2}, {1, 3}, {3, 4}, {3, 8}, {3, 12}} {
		for _, role := range []uint8{0, 1, 2, 3} {
			q := successionTestRequest(t, choice[0], choice[1], 1, true)
			q.MaterialSourceRole = role
			want := role < 3 && (choice[1]&10 != 0 && role != 0 || choice[1] == 1 || choice[1] == 4 && role == 0)
			body, err := EncodeSuccessionRequestCore(q)
			if (err == nil) != want {
				t.Fatal("material role shape changed", choice, role, err)
			}
			if want && (len(body) <= len("ENKV/CRYPTO/v2/succession-request-core-v2\x00")+5 || body[len("ENKV/CRYPTO/v2/succession-request-core-v2\x00")+5] != role) {
				t.Fatal("fixed material role missing from request framing")
			}
		}
	}
	q := successionTestRequest(t, 1, 2, 1, true)
	q.MaterialSourceRole = SuccessionMaterialAuthority
	a, err := SuccessionRequestDescriptor(q)
	if err != nil {
		t.Fatal(err)
	}
	q.MaterialSourceRole = SuccessionMaterialRecovery
	b, err := SuccessionRequestDescriptor(q)
	if err != nil || a == b {
		t.Fatal("different fixed routes shared request identity", err)
	}
	q = successionTestRequest(t, 1, 1, 1, false)
	q.MaterialSourceRole = SuccessionMaterialRecovery
	if _, err := SuccessionRequestDescriptor(q); err == nil {
		t.Fatal("disabled Recovery source admitted")
	}
}

// full_only: false
func TestSuccessionFinalIdentityIsSignedAndOnlyTypedPlanMayOmitIt(t *testing.T) {
	subject, wire := successionSubjectVector()
	if len(wire) != 553 {
		t.Fatal("independent subject width", len(wire))
	}
	base, err := NewK2SuccessionRequest(subject)
	if err != nil {
		t.Fatal(err)
	}
	alteredRole := subject
	alteredRole.MaterialSourceRole = 3
	if _, err := EncodeSuccessionSubject(alteredRole); err == nil {
		t.Fatal("unknown source role encoded")
	}
	alteredRole.MaterialSourceRole = SuccessionMaterialNone
	if _, err := EncodeSuccessionSubject(alteredRole); err == nil {
		t.Fatal("changed KEK accepted absent source")
	}
	altered := subject
	altered.RequestIdentityDigest[0] ^= 1
	changed, err := NewK2SuccessionRequest(altered)
	if err != nil || changed.Digest() == base.Digest() {
		t.Fatal("final request identity not signed", err)
	}
	altered = subject
	altered.MaterialSourceRole = SuccessionMaterialRecovery
	changed, err = NewK2SuccessionRequest(altered)
	if err != nil || changed.Digest() == base.Digest() {
		t.Fatal("fixed material route not signed", err)
	}
	subject.RequestIdentityDigest = ID{}
	if _, err := EncodeSuccessionSubject(subject); err == nil {
		t.Fatal("actual subject accepted identity hole")
	}
	if _, err := NewK2SuccessionRequest(subject); err == nil {
		t.Fatal("identity hole granted signing")
	}
	subject.HeadCoreDigest, subject.ConditionalPlanDigest = ID{}, ID{}
	plan := SuccessionAuthorizationPlan{Subject: SuccessionAuthorizationSubject(subject), Authorizer: successionTestSigning(t, 1, 1)}
	first, err := EncodeSuccessionAuthorizationPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	plan.Subject.MaterialSourceRole = SuccessionMaterialRecovery
	second, err := EncodeSuccessionAuthorizationPlan(plan)
	if err != nil || bytes.Equal(first, second) {
		t.Fatal("authorization plan omitted non-hole material route", err)
	}
	plan.Subject.RequestIdentityDigest = successionTestID(2)
	if _, err := EncodeSuccessionAuthorizationPlan(plan); err == nil {
		t.Fatal("plan allowed final identity to feed its graph")
	}
	// The prior closed subject revision is not a compatibility parser branch.
	old := append([]byte("ENKV/SUCCESSION/v8\x00"), wire[len("ENKV/SUCCESSION/v9\x00"):]...)
	if _, err := DecodeSuccessionSubject(old); err == nil {
		t.Fatal("retired subject prefix decoded")
	}
}

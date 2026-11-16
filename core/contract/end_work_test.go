package contract

import (
	"bytes"
	"strings"
	"testing"
)

func endWorkSubjectFixture() EndWorkSubject {
	id := func(b byte) ID {
		var out ID
		for i := range out {
			out[i] = b
		}
		return out
	}
	descriptor := func(b byte, count uint32) GeneratorDescriptor {
		return GeneratorDescriptor{Digest: id(b), Length: uint64(4 + 38*count), Count: count}
	}
	s := EndWorkSubject{Schema: CanonicalSchema, DomainID: id(1), OperationID: id(2), AdmissionID: id(4),
		PredecessorRevisionID: id(6), PredecessorFullHEADDigest: id(7),
		PredecessorToken: Token{Family: AWS, Value: `"old-etag"`},
		TargetGroupID:    id(8), TargetOwnerID: id(9), TargetID: id(10), TargetKind: 2, DutyKind: GeneratedDutyCreate,
		SelectedEvidenceSummary: AdministrativeEvidenceMissing,
		DependentGroups:         descriptor(11, 1), RemovedSupport: descriptor(12, 1),
		PreservedCurrent: DigestLength{Digest: id(13), Length: 1200},
		BeforeAccessRoot: id(17), AfterAccessRoot: id(18),
		BeforeAccessIncarnationID: id(19), AfterAccessIncarnationID: id(19),
		BeforeAccessGeneration: 2, AfterAccessGeneration: 3,
		BeforeWarningBits: 1, AfterWarningBits: 3, BeforeChildCount: 32, AfterChildCount: 31,
		BeforeChildBytes: 140000, AfterChildBytes: 139000, ReceiptDeltaDigest: id(14),
		HeadCoreDigest: id(15), HeadCoreLength: SuccessorHeadCoreMinLength,
		ConditionalPlanDigest: id(16)}
	var err error
	s.RequestCoreDigest, err = EndWorkRequestCoreDigest(s)
	if err != nil {
		panic(err)
	}
	return s
}

// full_only: false
func TestEndWorkSubjectMaximumTokenBoundary(t *testing.T) {
	s := endWorkSubjectFixture()
	s.PredecessorToken.Value = `"` + strings.Repeat("x", maxTokenValue-2) + `"`
	var err error
	s.RequestCoreDigest, err = EndWorkRequestCoreDigest(s)
	if err != nil {
		t.Fatal(err)
	}
	body, err := EncodeEndWorkSubject(s)
	// The fixed wire is 713 bytes; the 10-byte fixture token makes it 723.
	// Replacing that token with 256 bytes gives the exact 969-byte maximum.
	if err != nil || len(body) != 969 || len(body) > EndWorkSubjectMaxLength {
		t.Fatal("maximum predecessor token did not fit end-work subject", len(body), err)
	}
	if got, err := DecodeEndWorkSubject(body); err != nil || got != s {
		t.Fatal("maximum predecessor token did not round-trip", err)
	}
	s.PredecessorToken.Value = `"` + strings.Repeat("x", maxTokenValue-1) + `"`
	if _, err := EndWorkRequestCoreDigest(s); err == nil {
		t.Fatal("257-byte predecessor token entered the signing core")
	}
	if _, err := EncodeEndWorkSubject(s); err == nil {
		t.Fatal("257-byte predecessor token entered the signed subject")
	}
}

// full_only: false
func TestEndWorkSubjectClosedWireAndSigningPurpose(t *testing.T) {
	s := endWorkSubjectFixture()
	b, err := EncodeEndWorkSubject(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 723 || !bytes.Equal(b[457:489], s.BeforeAccessRoot[:]) ||
		!bytes.Equal(b[489:521], s.AfterAccessRoot[:]) ||
		!bytes.Equal(b[521:553], s.BeforeAccessIncarnationID[:]) ||
		!bytes.Equal(b[553:585], s.AfterAccessIncarnationID[:]) ||
		!bytes.Equal(b[585:601], []byte{0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3}) {
		t.Fatal("end-work access transition changed fixed wire layout")
	}
	got, err := DecodeEndWorkSubject(b)
	if err != nil || got != s {
		t.Fatalf("decoded=%#v err=%v", got, err)
	}
	request, err := NewEndWorkRequest(got)
	if err != nil || !request.Valid() || request.Purpose() != EndWorkPurpose ||
		!SigningPurposeAllowed(NormalSigningRole, request.Purpose()) || SigningPurposeAllowed(RecoverySigningRole, request.Purpose()) {
		t.Fatal("end-work request escaped the current Authority signing role", err)
	}
	if _, err := DecodeEndWorkSubject(append(bytes.Clone(b), 0)); err == nil {
		t.Fatal("trailing subject byte accepted")
	}
	if _, err := DecodeEndWorkSubject(b[:len(b)-1]); err == nil {
		t.Fatal("truncated subject accepted")
	}
	changed := s
	changed.PredecessorToken.Value = `"new-etag"`
	changed.RequestCoreDigest, err = EndWorkRequestCoreDigest(changed)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewEndWorkRequest(changed)
	if err != nil || other.Digest() == request.Digest() {
		t.Fatal("predecessor token did not bind signing request", err)
	}
	changed = s
	changed.AfterAccessRoot[0] ^= 1
	changed.RequestCoreDigest, err = EndWorkRequestCoreDigest(changed)
	if err != nil {
		t.Fatal(err)
	}
	other, err = NewEndWorkRequest(changed)
	if err != nil || other.Digest() == request.Digest() {
		t.Fatal("successor access root did not bind signing request", err)
	}
}

// full_only: false
func TestEndWorkSubjectRejectsUnsupportedTargetAndWarningRollback(t *testing.T) {
	s := endWorkSubjectFixture()
	for name, change := range map[string]func(*EndWorkSubject){
		"missing evidence":                func(s *EndWorkSubject) { s.SelectedEvidenceSummary = 0 },
		"wrong core digest":               func(s *EndWorkSubject) { s.RequestCoreDigest[0] ^= 1 },
		"reserved owner":                  func(s *EndWorkSubject) { s.TargetKind = 8 },
		"wrong duty":                      func(s *EndWorkSubject) { s.DutyKind = 0 },
		"missing predecessor":             func(s *EndWorkSubject) { s.PredecessorFullHEADDigest = ID{} },
		"warning rollback":                func(s *EndWorkSubject) { s.AfterWarningBits = 0 },
		"missing removed row":             func(s *EndWorkSubject) { s.RemovedSupport.Count = 0 },
		"access step skipped":             func(s *EndWorkSubject) { s.AfterAccessGeneration = 4 },
		"access root unchanged with step": func(s *EndWorkSubject) { s.AfterAccessRoot = s.BeforeAccessRoot },
		"zero predecessor generation":     func(s *EndWorkSubject) { s.BeforeAccessGeneration = 0 },
		"zero successor generation":       func(s *EndWorkSubject) { s.AfterAccessGeneration = 0 },
		"unchanged zero generations": func(s *EndWorkSubject) {
			s.AfterAccessRoot = s.BeforeAccessRoot
			s.AfterAccessIncarnationID = s.BeforeAccessIncarnationID
			s.BeforeAccessGeneration, s.AfterAccessGeneration = 0, 0
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := s
			change(&bad)
			if _, err := EncodeEndWorkSubject(bad); err == nil {
				t.Fatal("invalid administrative authority encoded")
			}
		})
	}
}

// full_only: false
func TestEndWorkSubjectAcceptsPublicationAndGCOwners(t *testing.T) {
	for _, kind := range []uint8{5, 6, 7} {
		s := endWorkSubjectFixture()
		s.TargetKind, s.DutyKind = kind, 0
		var err error
		s.RequestCoreDigest, err = EndWorkRequestCoreDigest(s)
		if err != nil {
			t.Fatalf("publication or GC owner kind=%d signing core: %v", kind, err)
		}
		body, err := EncodeEndWorkSubject(s)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := DecodeEndWorkSubject(body); err != nil || got != s {
			t.Fatalf("publication or GC owner kind=%d roundtrip: %v", kind, err)
		}
		s.DutyKind = GeneratedDutyCreate
		if _, err := EndWorkRequestCoreDigest(s); err == nil {
			t.Fatal("publication or GC owner accepted generated duty")
		}
	}
	for _, kind := range []uint8{0, 8} {
		s := endWorkSubjectFixture()
		s.TargetKind, s.DutyKind = kind, 0
		if _, err := EndWorkRequestCoreDigest(s); err == nil {
			t.Fatalf("invalid owner kind=%d entered signing core", kind)
		}
	}
}

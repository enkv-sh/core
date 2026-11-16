package contract

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func gcTestID(n byte) ID { return ID(bytes.Repeat([]byte{n}, 32)) }

func gcLiteralID(t testing.TB, text string) ID {
	t.Helper()
	b, err := hex.DecodeString(text)
	if err != nil || len(b) != 32 {
		t.Fatal("invalid fixed digest", err)
	}
	return ID(b)
}

func gcPlanFixture(t testing.TB) GCPlan {
	t.Helper()
	return GCPlan{
		DomainID: gcTestID(1), OperationID: gcTestID(2), RequestNonce: gcTestID(3),
		StoreDescriptorDigest: gcTestID(4), PublicBasisDigest: gcTestID(5), SourcePinsDigest: gcTestID(6),
		HeadRevisionID: gcTestID(7), FullHEADDigest: gcTestID(8), SnapshotID: gcTestID(9), RootDigest: gcTestID(10),
		MarkDigest: gcTestID(11), EnumerationDigest: gcTestID(12),
		TargetsDigest:    gcLiteralID(t, "4bd82cc6c8aa08e754007aef6b53dfc1412174f5bf31e0e7ad74314eb6121784"),
		PredecessorToken: Token{Family: AWS, Value: `"t"`}, InputProviderCursor: "in", NextProviderCursor: "next",
		Targets: []GCTarget{{Object: StoreObjectIdentity{Namespace: StorePageObject, Kind: ValueEntryPageKind, Index: 2, ObjectID: gcTestID(13)},
			Length: 17, Digest: gcTestID(14), Token: Token{Family: AWS, Value: `"t"`}}},
		Candidates: []GCCandidate{{KeyDigest: gcTestID(21), Classification: GCCandidateEligible, TargetIndex: 0, ListedLength: 17}},
	}
}

func gcProgressFixture(t testing.TB) GCProgress {
	t.Helper()
	return GCProgress{
		PlanDigest:        gcLiteralID(t, "d13b7b9dfa9338efbae1e1757c2070099695f52f7561ed8d75eb74f99a490a7c"),
		TargetsDescriptor: GCDescriptor{Digest: gcLiteralID(t, "4bd82cc6c8aa08e754007aef6b53dfc1412174f5bf31e0e7ad74314eb6121784"), Length: 101, Count: 1},
		RequestIdentity:   gcTestID(15), ObservationDigest: gcTestID(16), RemainingCount: 1, Ordinal: 1,
		Targets: []GCTargetProgress{{Disposition: GCTargetPending}},
	}
}

func gcSubjectFixture(t testing.TB) GCSubject {
	t.Helper()
	return GCSubject{
		DomainID: gcTestID(1), OperationID: gcTestID(2), AdmissionID: gcTestID(17), RequestIdentity: gcTestID(15), Phase: GCSelect,
		PredecessorRevisionID: gcTestID(7), PredecessorFullHEADDigest: gcTestID(8), PredecessorToken: Token{Family: AWS, Value: `"t"`},
		BeforeOwners:           GCDescriptor{Digest: gcLiteralID(t, "cdb948f1a5d68497d5ca9d8e62d147efbc8bb546fc8c9a26e9bced30eea364da"), Length: 22},
		AfterOwners:            GCDescriptor{Digest: gcLiteralID(t, "80c448e9470c2cd511eac0b731da3accf70cfbc8aedb1291b3a61327309f285c"), Length: 242, Count: 1},
		PlanDigest:             gcLiteralID(t, "d13b7b9dfa9338efbae1e1757c2070099695f52f7561ed8d75eb74f99a490a7c"),
		AfterProgressDigest:    gcLiteralID(t, "2caa92f3db6386fb2a161489080613386704e9aa1e0f81a9d0cf2ecba424fcae"),
		PreservedCurrentDigest: gcTestID(18), PreservedCurrentLength: 1234, HeadCoreDigest: gcTestID(19), HeadCoreLength: 419, ConditionalPlanDigest: gcTestID(20),
	}
}

func gcRejectIncomplete(t *testing.T, body []byte, decode func([]byte) error) {
	t.Helper()
	for n := range body {
		if err := decode(body[:n]); err == nil {
			t.Fatalf("accepted truncated frame at %d of %d", n, len(body))
		}
	}
	if err := decode(append(bytes.Clone(body), 0)); err == nil {
		t.Fatal("accepted trailing frame byte")
	}
}

// full_only: false
func TestGCFixedCommitmentsAndPlanWire(t *testing.T) {
	// Fixed hashes come from struct.pack/hashlib field assembly in the local
	// codec-literals derivation. No production encoder supplied their values.
	emptyOwners := EmptyGCOwnersDescriptor()
	if emptyOwners.Length != 22 || emptyOwners.Count != 0 || fmt.Sprintf("%x", emptyOwners.Digest) != "cdb948f1a5d68497d5ca9d8e62d147efbc8bb546fc8c9a26e9bced30eea364da" || !emptyOwners.ValidOwners() || emptyOwners.ValidTargets() {
		t.Fatal("empty GC owner commitment changed", emptyOwners)
	}
	emptyTargets := GCTargetsEmptyDescriptor()
	if emptyTargets.Length != 21 || emptyTargets.Count != 0 || fmt.Sprintf("%x", emptyTargets.Digest) != "de2513225bfa3a375520461c2d7293042f206f8b8d639df2be6ba9292b8624dc" || !emptyTargets.ValidTargets() || emptyTargets.ValidOwners() {
		t.Fatal("empty GC target commitment changed", emptyTargets)
	}
	for _, d := range []GCDescriptor{emptyOwners, emptyTargets} {
		body, err := AppendGCDescriptor(nil, d)
		got, decodeErr := DecodeGCDescriptor(body)
		if err != nil || decodeErr != nil || len(body) != 44 || got != d {
			t.Fatal("GC descriptor framing", err, decodeErr)
		}
		gcRejectIncomplete(t, body, func(b []byte) error { _, err := DecodeGCDescriptor(b); return err })
	}
	if (GCDescriptor{}).ValidOwners() || (GCDescriptor{}).ValidTargets() {
		t.Fatal("zero descriptor supplied an empty commitment")
	}
	p := gcPlanFixture(t)
	target, err := EncodeGCTarget(p.Targets[0])
	if err != nil || len(target) != 80 || fmt.Sprintf("%x", Hash(target)) != "59c24ad5ae721ec95d8fca5b2dda14f227f735fbc044d77cc1012ceaa032ab09" {
		t.Fatal("exact target field order changed", len(target), err)
	}
	d, err := GCTargetsDescriptor(p.Targets)
	if err != nil || d.Digest != p.TargetsDigest || d.Length != 101 || d.Count != 1 {
		t.Fatal("exact target vector changed", d, err)
	}
	body, err := EncodeGCPlan(p)
	if err != nil || len(body) != 586 || fmt.Sprintf("%x", Hash(body)) != "d13b7b9dfa9338efbae1e1757c2070099695f52f7561ed8d75eb74f99a490a7c" {
		t.Fatal("exact plan field order changed", len(body), err)
	}
	if n, err := GCPlanEncodedLength(p); err != nil || n != 586 {
		t.Fatal("plan byte projection", n, err)
	}
	got, err := DecodeGCPlan(body)
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatal("complete plan round trip", err)
	}
	observation, err := GCPlanObservationDigest(p)
	if err != nil || fmt.Sprintf("%x", observation) != "09cafebb9045c4164a775c91a312c75398f19dd3390db8ad0125ab700931aa40" {
		t.Fatal("fixed observation commitment changed", observation, err)
	}
	request, err := GCPlanRequestIdentity(p)
	if err != nil || fmt.Sprintf("%x", request) != "ec9de64f1260e0074bd774d03251b6e6431664f9ffa2d57c296e351675ee8ba5" {
		t.Fatal("fixed request identity changed", request, err)
	}
	gcRejectIncomplete(t, body, func(b []byte) error { _, err := DecodeGCPlan(b); return err })
	clear(body)
	if !reflect.DeepEqual(got, p) {
		t.Fatal("decoded plan retained mutable input bytes")
	}
}

// full_only: false
func TestGCPlanRejectsUntrustedShape(t *testing.T) {
	mutations := map[string]func(*GCPlan){
		"zero-domain":           func(p *GCPlan) { p.DomainID = ID{} },
		"zero-source-pins":      func(p *GCPlan) { p.SourcePinsDigest = ID{} },
		"zero-request":          func(p *GCPlan) { p.RequestNonce = ID{} },
		"zero-operation":        func(p *GCPlan) { p.OperationID = ID{} },
		"target-digest":         func(p *GCPlan) { p.TargetsDigest[0] ^= 1 },
		"unmapped-target":       func(p *GCPlan) { p.Candidates = nil },
		"duplicate-eligible":    func(p *GCPlan) { p.Candidates = append(p.Candidates, p.Candidates[0]) },
		"eligible-index":        func(p *GCPlan) { p.Candidates[0].TargetIndex = 1 },
		"eligible-reason":       func(p *GCPlan) { p.Candidates[0].Reason = GCReasonUnavailable },
		"eligible-key":          func(p *GCPlan) { p.Candidates[0].KeyDigest = ID{} },
		"unknown-class":         func(p *GCPlan) { p.Candidates[0].Classification = 7 },
		"unknown-reason":        func(p *GCPlan) { p.Candidates[0].Reason = 6 },
		"noneligible-index":     func(p *GCPlan) { p.Candidates[0].Classification = GCCandidateProtected },
		"foreign-token-family":  func(p *GCPlan) { p.PredecessorToken = Token{Family: GCP, Value: "1"} },
		"weak-predecessor":      func(p *GCPlan) { p.PredecessorToken.Value = `W/"t"` },
		"oversize-input-cursor": func(p *GCPlan) { p.InputProviderCursor = strings.Repeat("x", 4097) },
		"oversize-next-cursor":  func(p *GCPlan) { p.NextProviderCursor = strings.Repeat("x", 4097) },
		"invalid-unicode":       func(p *GCPlan) { p.InputProviderCursor = string([]byte{0xff}) },
		"too-many-candidates":   func(p *GCPlan) { p.Candidates = make([]GCCandidate, 257) },
	}
	for name, change := range mutations {
		t.Run(name, func(t *testing.T) {
			p := gcPlanFixture(t)
			change(&p)
			if p.Valid() {
				t.Fatal("invalid plan declared valid")
			}
			if _, err := EncodeGCPlan(p); err == nil {
				t.Fatal("invalid plan encoded")
			}
		})
	}
	p := gcPlanFixture(t)
	body, err := EncodeGCPlan(p)
	if err != nil {
		t.Fatal(err)
	}
	for name, offset := range map[string]int{"magic": 0, "plan-schema": 17, "canonical-schema": 19} {
		t.Run(name, func(t *testing.T) {
			bad := bytes.Clone(body)
			bad[offset] ^= 1
			if _, err := DecodeGCPlan(bad); err == nil {
				t.Fatal("unknown wire identity accepted")
			}
		})
	}
	bad := bytes.Clone(body)
	binary.BigEndian.PutUint16(bad[444:446], 257)
	if _, err := DecodeGCPlan(bad); err == nil {
		t.Fatal("over-limit wire target count accepted")
	}
	if _, err := DecodeGCPlan(make([]byte, 105414)); err == nil {
		t.Fatal("over-limit plan envelope accepted")
	}
	p.Targets, p.Candidates, p.TargetsDigest = nil, []GCCandidate{{Classification: GCCandidateUnverifiable, TargetIndex: 65535, Reason: GCReasonForeign}}, GCTargetsEmptyDescriptor().Digest
	if !p.Valid() {
		t.Fatal("empty declared vector lost its undisclosed foreign candidate")
	}
	empty, err := EncodeGCPlan(p)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeGCPlan(empty); err != nil || len(got.Targets) != 0 || len(got.Candidates) != 1 || got.Candidates[0] != p.Candidates[0] {
		t.Fatal("empty plan candidate record changed", err)
	}
}

func gcMaximumPlan(t testing.TB) GCPlan {
	t.Helper()
	p := gcPlanFixture(t)
	p.PredecessorToken.Value = `"` + strings.Repeat("x", 254) + `"`
	p.InputProviderCursor, p.NextProviderCursor = strings.Repeat("a", 4096), strings.Repeat("b", 4096)
	p.Targets, p.Candidates = make([]GCTarget, 256), make([]GCCandidate, 256)
	for i := range p.Targets {
		var id ID
		binary.BigEndian.PutUint32(id[28:], uint32(i+1))
		p.Targets[i] = GCTarget{Object: StoreObjectIdentity{Namespace: StorePageObject, Kind: ValueEntryPageKind, ObjectID: id}, Length: 2 << 20, Digest: gcTestID(14), Token: p.PredecessorToken}
		p.Candidates[i] = GCCandidate{KeyDigest: id, Classification: GCCandidateEligible, TargetIndex: uint16(i), ListedLength: 2 << 20}
	}
	p.TargetsDigest = gcLiteralID(t, "1a377b491bde771cb4a3c80427a450b5300261d1c8fc97f1a3f15560c7b63030")
	return p
}

// full_only: false
func TestGCPlanMaximumPackedBounds(t *testing.T) {
	if GCPlanMaxLength != 105413 {
		t.Fatal("declared plan limit differs from independent maximum", GCPlanMaxLength)
	}
	if GCProgressMaxLength != 8854 {
		t.Fatal("declared progress limit differs from independent maximum", GCProgressMaxLength)
	}
	p := gcMaximumPlan(t)
	d, err := GCTargetsDescriptor(p.Targets)
	if err != nil || d.Length != 85269 || d.Count != 256 || d.Digest != p.TargetsDigest {
		t.Fatal("maximum target vector", d, err)
	}
	body, err := EncodeGCPlan(p)
	if err != nil || len(body) != 105413 || fmt.Sprintf("%x", Hash(body)) != "14681977b75d7a9e58db1ab20f3aadc53346b853d662cb8276d1bcf2999a2680" {
		t.Fatal("maximum plan", len(body), err)
	}
	got, err := DecodeGCPlan(body)
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatal("maximum plan round trip", err)
	}
	framed, err := AppendSupportRecord(nil, SupportRecord{Kind: GCPlanSupportKind, RecordID: p.OperationID, Body: body})
	if err != nil || len(framed) != 105450 {
		t.Fatal("maximum optional support framing", len(framed), err)
	}
	progress := gcProgressFixture(t)
	progress.PlanDigest, progress.TargetsDescriptor = gcLiteralID(t, "14681977b75d7a9e58db1ab20f3aadc53346b853d662cb8276d1bcf2999a2680"), d
	progress.RemainingCount, progress.Targets = 256, make([]GCTargetProgress, 256)
	for i := range progress.Targets {
		progress.Targets[i].Disposition = GCTargetPending
	}
	b, err := EncodeGCProgress(progress)
	if err != nil || len(b) != 8854 || fmt.Sprintf("%x", Hash(b)) != "a739c3a88dcb88f2527bf681be4c13a2f8e674b75e55cce69afc1533892c9666" {
		t.Fatal("maximum progress", len(b), err)
	}
	if decoded, err := DecodeGCProgress(b); err != nil || !GCProgressEqual(decoded, progress) {
		t.Fatal("maximum progress round trip", err)
	}
	p.Targets = append(p.Targets, p.Targets[255])
	if _, err := GCTargetsDescriptor(p.Targets); err == nil {
		t.Fatal("257th target accepted")
	}
}

// full_only: false
func TestGCTargetVectorUsesPhysicalKeyOrder(t *testing.T) {
	a := gcPlanFixture(t).Targets[0]
	b := a
	a.Object.Index, b.Object.Index = 2, 10
	// Decimal key bytes place index10 before index2, unlike numeric index order.
	if _, err := GCTargetsDescriptor([]GCTarget{b, a}); err != nil {
		t.Fatal("physical key order refused", err)
	}
	for name, rows := range map[string][]GCTarget{"numeric-order": {a, b}, "duplicate": {a, a}} {
		t.Run(name, func(t *testing.T) {
			if _, err := GCTargetsDescriptor(rows); err == nil {
				t.Fatal("noncanonical target order accepted")
			}
		})
	}
	mutations := map[string]func(*GCTarget){
		"head-kind":         func(v *GCTarget) { v.Object.Kind = HeadKind },
		"zero-object":       func(v *GCTarget) { v.Object.ObjectID = ID{} },
		"unknown-namespace": func(v *GCTarget) { v.Object.Namespace = 4 },
		"zero-length":       func(v *GCTarget) { v.Length = 0 },
		"over-length":       func(v *GCTarget) { v.Length = 2<<20 + 1 },
		"zero-digest":       func(v *GCTarget) { v.Digest = ID{} },
		"weak-token":        func(v *GCTarget) { v.Token.Value = `W/"t"` },
	}
	for name, change := range mutations {
		t.Run(name, func(t *testing.T) {
			v := a
			change(&v)
			if v.Valid() {
				t.Fatal("invalid target accepted")
			}
			if _, err := EncodeGCTarget(v); err == nil {
				t.Fatal("invalid target encoded")
			}
		})
	}
}

// full_only: false
func TestGCProgressEvidenceAndOwnership(t *testing.T) {
	p := gcProgressFixture(t)
	body, err := EncodeGCProgress(p)
	if err != nil || len(body) != 184 || fmt.Sprintf("%x", Hash(body)) != "2caa92f3db6386fb2a161489080613386704e9aa1e0f81a9d0cf2ecba424fcae" {
		t.Fatal("fixed progress changed", len(body), err)
	}
	got, err := DecodeGCProgress(body)
	if err != nil || !GCProgressEqual(got, p) {
		t.Fatal("progress round trip", err)
	}
	gcRejectIncomplete(t, body, func(b []byte) error { _, err := DecodeGCProgress(b); return err })
	if parsed, n, err := ParseGCProgress(append(bytes.Clone(body), 7)); err != nil || n != 184 || !GCProgressEqual(parsed, p) {
		t.Fatal("embedded progress consumed unrelated bytes", n, err)
	}
	owned := p.Own()
	owned.Targets[0].Consumed = 1
	if p.Targets[0].Consumed != 0 || GCProgressEqual(owned, p) {
		t.Fatal("owned progress aliases its source")
	}
	for _, disposition := range []GCTargetDisposition{GCTargetPending, GCTargetUnknown, GCTargetAbsent, GCTargetChanged, GCTargetTerminalFailure, GCTargetRetryableNotSent} {
		v := p.Own()
		v.Targets[0] = GCTargetProgress{Consumed: 1, Disposition: disposition}
		if disposition == GCTargetAbsent {
			v.RemainingCount, v.Targets[0].EvidenceDigest = 0, gcTestID(30)
		}
		if disposition == GCTargetRetryableNotSent {
			v.Targets[0].EvidenceDigest = gcTestID(31)
		}
		if !v.Valid() {
			t.Fatal("closed disposition refused", disposition)
		}
		v.Targets[0].EvidenceDigest[0] ^= 1
		if disposition != GCTargetAbsent && disposition != GCTargetRetryableNotSent && v.Valid() {
			t.Fatal("ordinary disposition accepted proof bytes", disposition)
		}
	}
	invalid := map[string]func(*GCProgress){
		"zero-plan":           func(v *GCProgress) { v.PlanDigest = ID{} },
		"zero-ordinal":        func(v *GCProgress) { v.Ordinal = 0 },
		"count":               func(v *GCProgress) { v.TargetsDescriptor.Count = 2 },
		"remaining":           func(v *GCProgress) { v.RemainingCount = 0 },
		"empty":               func(v *GCProgress) { v.Targets = nil },
		"excess-consumption":  func(v *GCProgress) { v.Targets[0].Consumed = 4 },
		"unknown-disposition": func(v *GCProgress) { v.Targets[0].Disposition = 7 },
		"unproved-absence":    func(v *GCProgress) { v.Targets[0].Disposition, v.RemainingCount = GCTargetAbsent, 0 },
		"unproved-not-sent":   func(v *GCProgress) { v.Targets[0].Consumed, v.Targets[0].Disposition = 1, GCTargetRetryableNotSent },
		"not-sent-without-allowance": func(v *GCProgress) {
			v.Targets[0].Disposition, v.Targets[0].EvidenceDigest = GCTargetRetryableNotSent, gcTestID(31)
		},
		"exhausted-not-sent": func(v *GCProgress) {
			v.Targets[0] = GCTargetProgress{Consumed: 3, Disposition: GCTargetRetryableNotSent, EvidenceDigest: gcTestID(31)}
		},
	}
	for name, change := range invalid {
		t.Run(name, func(t *testing.T) {
			v := p.Own()
			change(&v)
			if v.Valid() {
				t.Fatal("invalid progress declared valid")
			}
			if _, err := EncodeGCProgress(v); err == nil {
				t.Fatal("invalid progress encoded")
			}
		})
	}
	bad := bytes.Clone(body)
	bad[1]++
	if _, err := DecodeGCProgress(bad); err == nil {
		t.Fatal("unknown progress schema accepted")
	}
	bad = bytes.Clone(body)
	binary.BigEndian.PutUint16(bad[142:144], 257)
	if _, err := DecodeGCProgress(bad); err == nil {
		t.Fatal("over-limit progress count accepted")
	}
}

// full_only: false
func TestGCOwnersDescriptorOrderingAndMandatoryProgress(t *testing.T) {
	p := gcProgressFixture(t)
	row := GCOwner{OperationID: gcTestID(2), Progress: p}
	d, err := GCOwnersDescriptor([]GCOwner{row})
	if err != nil || d.Length != 242 || d.Count != 1 || fmt.Sprintf("%x", d.Digest) != "80c448e9470c2cd511eac0b731da3accf70cfbc8aedb1291b3a61327309f285c" {
		t.Fatal("fixed owner commitment changed", d, err)
	}
	other := row
	other.OperationID = gcTestID(3)
	if _, err := GCOwnersDescriptor([]GCOwner{row, other}); err != nil {
		t.Fatal("sorted owner summaries refused", err)
	}
	for name, rows := range map[string][]GCOwner{"duplicate": {row, row}, "reversed": {other, row}, "zero-owner": {{Progress: p}}, "invalid-progress": {{OperationID: row.OperationID}}} {
		t.Run(name, func(t *testing.T) {
			if _, err := GCOwnersDescriptor(rows); err == nil {
				t.Fatal("invalid mandatory owner commitment accepted")
			}
		})
	}
	for _, bad := range []GCDescriptor{{Digest: d.Digest, Length: 241, Count: 1}, {Digest: d.Digest, Length: d.Length, Count: 65536}, {Digest: d.Digest, Length: 22}, {Digest: d.Digest, Length: 1 << 30, Count: 1}} {
		if bad.ValidOwners() {
			t.Fatal("invalid owner bounds accepted", bad)
		}
	}
	changed := row
	changed.Progress = row.Progress.Own()
	changed.Progress.Targets[0].Consumed = 1
	changed.Progress.Ordinal++
	d2, err := GCOwnersDescriptor([]GCOwner{changed})
	if err != nil || d2.Digest == d.Digest {
		t.Fatal("selected budget omitted from owner commitment", err)
	}
}

// full_only: false
func TestGCSubjectClosedPhasesAndSigning(t *testing.T) {
	if GCSubjectMaxLength != 762 {
		t.Fatal("declared subject limit differs from independent maximum", GCSubjectMaxLength)
	}
	s := gcSubjectFixture(t)
	body, err := EncodeGCSubject(s)
	if err != nil || len(body) != 509 || fmt.Sprintf("%x", Hash(body)) != "4bd74cd97a609a5bd5ce31e1ff49e53c095231860e3abb5c7e5c6dad0eb0baab" {
		t.Fatal("fixed subject changed", len(body), err)
	}
	if got, err := DecodeGCSubject(body); err != nil || got != s {
		t.Fatal("subject round trip", err)
	}
	gcRejectIncomplete(t, body, func(b []byte) error { _, err := DecodeGCSubject(b); return err })
	request, err := NewGCRequest(s)
	if err != nil || !request.Valid() || request.Purpose() != Purpose(17) || request.Digest() != Hash(body) || !SigningPurposeAllowed(NormalSigningRole, request.Purpose()) || SigningPurposeAllowed(RecoverySigningRole, request.Purpose()) {
		t.Fatal("GC signing purpose or route", err)
	}
	maximum := s
	maximum.PredecessorToken.Value = `"` + strings.Repeat("x", 254) + `"`
	maxBody, err := EncodeGCSubject(maximum)
	if err != nil || len(maxBody) != 762 {
		t.Fatal("maximum subject bound", len(maxBody), err)
	}
	if _, err := DecodeGCSubject(append(maxBody, 0)); err == nil {
		t.Fatal("oversize subject accepted")
	}
	invalid := map[string]func(*GCSubject){
		"zero-domain":              func(v *GCSubject) { v.DomainID = ID{} },
		"zero-request":             func(v *GCSubject) { v.RequestIdentity = ID{} },
		"unknown-phase":            func(v *GCSubject) { v.Phase = 6 },
		"select-before-progress":   func(v *GCSubject) { v.BeforeProgressDigest = gcTestID(30) },
		"select-no-after-progress": func(v *GCSubject) { v.AfterProgressDigest = ID{} },
		"select-no-new-owner":      func(v *GCSubject) { v.AfterOwners = v.BeforeOwners },
		"zero-preserved-length":    func(v *GCSubject) { v.PreservedCurrentLength = 0 },
		"short-core":               func(v *GCSubject) { v.HeadCoreLength = 418 },
		"long-core":                func(v *GCSubject) { v.HeadCoreLength = 675 },
	}
	for name, change := range invalid {
		t.Run(name, func(t *testing.T) {
			v := s
			change(&v)
			if v.Valid() {
				t.Fatal("invalid subject declared valid")
			}
			if _, err := NewGCRequest(v); err == nil {
				t.Fatal("invalid subject reached signing")
			}
		})
	}
	for _, phase := range []GCPhase{GCReacquire, GCReserve, GCRecordProgress, GCClose} {
		v := s
		v.Phase, v.BeforeOwners = phase, s.AfterOwners
		v.BeforeProgressDigest = s.AfterProgressDigest
		if phase == GCReserve || phase == GCRecordProgress {
			v.AfterProgressDigest = gcTestID(31)
		}
		if !v.Valid() {
			t.Fatal("valid phase refused", phase)
		}
		t.Run(fmt.Sprintf("phase-%d-zero-owners", phase), func(t *testing.T) {
			withoutOwner := v
			withoutOwner.BeforeOwners, withoutOwner.AfterOwners = s.BeforeOwners, s.BeforeOwners
			if withoutOwner.Valid() {
				t.Fatal("continuation phase accepted progress without a selected owner")
			}
			if _, err := NewGCRequest(withoutOwner); err == nil {
				t.Fatal("ownerless continuation reached GC signing")
			}
		})
		bad := v
		if phase == GCReserve || phase == GCRecordProgress {
			bad.AfterProgressDigest = bad.BeforeProgressDigest
		} else {
			bad.AfterProgressDigest = gcTestID(31)
		}
		if bad.Valid() {
			t.Fatal("invalid phase progress relation accepted", phase)
		}
		bad = v
		bad.AfterOwners = s.BeforeOwners
		if bad.Valid() {
			t.Fatal("phase changed owner count", phase)
		}
		if phase == GCClose {
			v.AfterOwners, v.AfterProgressDigest = s.BeforeOwners, ID{}
			if !v.Valid() {
				t.Fatal("complete close refused")
			}
			v.AfterOwners = v.BeforeOwners
			if v.Valid() {
				t.Fatal("zero progress without owner removal accepted")
			}
		}
	}
	for name, offset := range map[string]int{"magic": 0, "schema": 15} {
		t.Run(name, func(t *testing.T) {
			bad := bytes.Clone(body)
			bad[offset] ^= 1
			if _, err := DecodeGCSubject(bad); err == nil {
				t.Fatal("unknown subject framing accepted")
			}
		})
	}
	changed := s
	changed.PredecessorToken.Value = `"u"`
	other, err := NewGCRequest(changed)
	if err != nil || other.Digest() == request.Digest() {
		t.Fatal("predecessor condition omitted from GC signing", err)
	}
}

// full_only: false
func TestGCProgressPublicEvidenceUsesMandatoryRows(t *testing.T) {
	p := gcProgressFixture(t)
	if p.EvidenceSummary() != AdministrativeEvidenceMissing || p.EffectEntryCeiling() != 0 {
		t.Fatal("fresh progress evidence")
	}
	p.Targets = []GCTargetProgress{{Consumed: 1, Disposition: GCTargetUnknown}, {Disposition: GCTargetAbsent, EvidenceDigest: gcTestID(30)}, {Disposition: GCTargetChanged}, {Disposition: GCTargetTerminalFailure}, {Consumed: 1, Disposition: GCTargetRetryableNotSent, EvidenceDigest: gcTestID(31)}}
	want := AdministrativeEvidenceMissing | AdministrativeEvidenceQualifiedUnknown | AdministrativeEvidenceConfirmed | AdministrativeEvidenceContradiction | AdministrativeEvidenceTerminalFailure
	if p.EvidenceSummary() != want || p.EffectEntryCeiling() != 1 {
		t.Fatal("mandatory progress evidence lost a distinct outcome", p.EvidenceSummary())
	}
	owned := p.Own()
	if !slices.Equal(owned.Targets, p.Targets) {
		t.Fatal("owned progress changed its rows")
	}
}

package format

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

func gcFormatID(n byte) ID { return ID(bytes.Repeat([]byte{n}, 32)) }
func gcFormatDigest(t testing.TB, text string) ID {
	t.Helper()
	b, err := hex.DecodeString(text)
	if err != nil || len(b) != 32 {
		t.Fatal("invalid fixed GC digest", err)
	}
	return ID(b)
}
func gcFormatProgress(t testing.TB) contract.GCProgress {
	t.Helper()
	return contract.GCProgress{
		PlanDigest:        gcFormatDigest(t, "595b4b2fca75dc30033c783019541e617ec85523e2ba3b26d1bdb88712508810"),
		TargetsDescriptor: contract.GCDescriptor{Digest: gcFormatDigest(t, "4bd82cc6c8aa08e754007aef6b53dfc1412174f5bf31e0e7ad74314eb6121784"), Length: 101, Count: 1},
		RequestIdentity:   gcFormatID(15), ObservationDigest: gcFormatID(16), RemainingCount: 1, Ordinal: 1,
		Targets: []contract.GCTargetProgress{{Disposition: contract.GCTargetPending}},
	}
}
func gcFormatOwners(t testing.TB) contract.GCDescriptor {
	t.Helper()
	return contract.GCDescriptor{Digest: gcFormatDigest(t, "464bfbb8976c56de6236d16f27ea021a925d288bf47a50f4ec57bc7989ff40b0"), Length: 242, Count: 1}
}
func gcFormatIndex(t testing.TB) AdministrativeIndex {
	t.Helper()
	progress := gcFormatProgress(t)
	d := contract.GeneratorDescriptor{Digest: gcFormatID(25), Length: 4}
	affected := contract.GeneratorDescriptor{Digest: progress.TargetsDescriptor.Digest, Length: progress.TargetsDescriptor.Length, Count: progress.TargetsDescriptor.Count}
	return AdministrativeIndex{Domain: gcFormatID(1), Object: gcFormatID(24), SliceSnapshot: gcFormatID(9),
		Groups: []AdministrativeGroup{{GroupID: gcFormatID(2), OwnerID: gcFormatID(2), TargetID: gcFormatID(2), OwnerKind: AdministrativeGC,
			SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing, Affected: affected, Dependencies: d, Disposable: d, ChargedPages: 1, ChargedBytes: 698, GC: &progress}},
		Pages: []AdministrativePage{{Ref: Ref{Kind: contract.RequiredSupportKind, Format: Version, Domain: gcFormatID(1), Object: gcFormatID(22), Digest: gcFormatID(23), Length: 698},
			Spans: []AdministrativeSpan{{Count: 1, GroupIndexes: []uint16{0}}}, Rows: []AdministrativeRowSummary{{Kind: contract.GCPlanSupportKind, RecordID: gcFormatID(2), BodyLength: 586}}}},
	}
}

// full_only: false
func TestGCRootSuffixAndActiveOwnerExclusion(t *testing.T) {
	root := rootFixture(t)
	body, err := EncodeRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString(strings.Repeat("00", 32) + "cdb948f1a5d68497d5ca9d8e62d147efbc8bb546fc8c9a26e9bced30eea364da000000000000001600000000")
	if err != nil || len(want) != 76 || !bytes.Equal(body[len(body)-76:], want) {
		t.Fatal("idle GC root suffix changed", err)
	}
	got, err := DecodeRoot(body)
	if err != nil || got.ActiveGC != (ID{}) || got.GCPlans != contract.EmptyGCOwnersDescriptor() {
		t.Fatal("idle GC root round trip", err)
	}
	root.ActiveGC = fid(90)
	if _, err := EncodeRoot(root); err == nil {
		t.Fatal("active GC without an owner accepted")
	}
	root.GCPlans = gcFormatOwners(t)
	active, err := EncodeRoot(root)
	if err != nil {
		t.Fatal("structural active GC root refused", err)
	}
	if got, err := DecodeRoot(active); err != nil || got.ActiveGC != root.ActiveGC || got.GCPlans != root.GCPlans {
		t.Fatal("active root round trip", err)
	}
	root.Generated.ActiveOwner, root.Generated.ActivePhase, root.Generated.ActiveGraph = fid(91), fid(92), fid(93)
	if _, err := EncodeRoot(root); err == nil {
		t.Fatal("canonical and GC owners overlap")
	}
	root.ActiveGC = ID{}
	if _, err := EncodeRoot(root); err != nil {
		t.Fatal("pending GC improperly blocks canonical owner shape", err)
	}
	for name, change := range map[string]func([]byte){
		"missing-GC-fields":     func(b []byte) { clear(b[len(b)-44:]) },
		"wrong-empty-length":    func(b []byte) { binary.BigEndian.PutUint64(b[len(b)-12:len(b)-4], 4) },
		"old-schema":            func(b []byte) { b[6] = 9 },
		"owner-without-summary": func(b []byte) { b[len(b)-76] = 90 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := bytes.Clone(body)
			change(bad)
			if _, err := DecodeRoot(bad); err == nil {
				t.Fatal("invalid GC root bytes accepted")
			}
		})
	}
	for _, n := range []int{len(body) - 76, len(body) - 1} {
		if _, err := DecodeRoot(body[:n]); err == nil {
			t.Fatal("missing GC root suffix accepted", n)
		}
	}
}

// full_only: false
func TestGCAdministrativeExtensionAndOwnedCopies(t *testing.T) {
	index := gcFormatIndex(t)
	body, err := EncodeAdministrativeIndex(index)
	// Independently assembled header, kind7 group, 184-byte extension, Ref,
	// optional span and row summary form exactly 700 bytes.
	if err != nil || len(body) != 700 || fmt.Sprintf("%x", contract.Hash(body)) != "1d8f809fdef417dd38af14cbd6a5d488a265897ef75e52be5c63f1d021fa452b" {
		t.Fatal("fixed administrative GC bytes changed", len(body), err)
	}
	if n, err := AdministrativeIndexEncodedLength(index); err != nil || n != 700 {
		t.Fatal("GC extension omitted from administrative byte account", n, err)
	}
	got, err := DecodeAdministrativeIndex(body)
	if err != nil || !reflect.DeepEqual(got, index) {
		t.Fatal("mandatory GC extension round trip", err)
	}
	d, err := GCPlansDescriptor(index)
	if err != nil || d != gcFormatOwners(t) {
		t.Fatal("mandatory owner descriptor changed", d, err)
	}
	owned := index.Groups[0].Own()
	owned.GC.Targets[0].Consumed = 1
	if index.Groups[0].GC.Targets[0].Consumed != 0 || SameGCProgress(owned.GC, index.Groups[0].GC) {
		t.Fatal("owned administrative group aliases GC counters")
	}
	for name, change := range map[string]func(*AdministrativeGroup){
		"missing-extension": func(g *AdministrativeGroup) { g.GC = nil },
		"wrong-owner":       func(g *AdministrativeGroup) { g.OwnerID = gcFormatID(30) },
		"wrong-target":      func(g *AdministrativeGroup) { g.TargetID = gcFormatID(31) },
		"duty":              func(g *AdministrativeGroup) { g.DutyKind = contract.GeneratedDutyCreate },
		"publication-stamp": func(g *AdministrativeGroup) { g.PublicationIncarnationID = gcFormatID(32) },
		"evidence":          func(g *AdministrativeGroup) { g.SelectedEvidenceSummary = contract.AdministrativeEvidenceConfirmed },
		"entry-ceiling":     func(g *AdministrativeGroup) { g.EffectEntryCeiling = 1 },
		"foreign-extension": func(g *AdministrativeGroup) { g.OwnerKind = AdministrativeGeneratedParent },
		"affected-digest":   func(g *AdministrativeGroup) { g.Affected.Digest[0] ^= 1 },
		"affected-length":   func(g *AdministrativeGroup) { g.Affected.Length++ },
		"affected-count":    func(g *AdministrativeGroup) { g.Affected.Count++ },
	} {
		t.Run(name, func(t *testing.T) {
			bad := gcFormatIndex(t)
			change(&bad.Groups[0])
			if _, err := EncodeAdministrativeIndex(bad); err == nil {
				t.Fatal("invalid GC group relation accepted")
			}
		})
	}
	for _, n := range []int{360, 510, 543, 544, len(body) - 1} {
		if _, err := DecodeAdministrativeIndex(body[:n]); err == nil {
			t.Fatal("truncated mandatory GC extension accepted", n)
		}
	}
	bad := bytes.Clone(body)
	binary.BigEndian.PutUint16(bad[502:504], 257)
	if _, err := DecodeAdministrativeIndex(bad); err == nil {
		t.Fatal("over-limit mandatory GC target count accepted")
	}
	if _, err := DecodeAdministrativeIndex(append(bytes.Clone(body), 0)); err == nil {
		t.Fatal("trailing administrative bytes accepted")
	}
}

func gcFormatHead(t testing.TB) Head {
	t.Helper()
	h := headFixture(t)
	core, err := EncodeHeadCore(h.Core)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := EncodeConditionalPlan(ConditionalPlan{Family: h.Core.PreviousToken.Family, Store: h.Core.Store, Coordinate: h.Core.Coordinate, NonBody: h.Core.NonBody, Condition: conditionFixture(h.Core.PreviousToken), HeadCore: contract.Hash(core), HeadCoreLength: uint32(len(core))})
	if err != nil {
		t.Fatal(err)
	}
	q := contract.GCSubject{DomainID: h.Core.Domain, OperationID: fid(20), AdmissionID: fid(21), RequestIdentity: fid(22), Phase: contract.GCSelect,
		PredecessorRevisionID: h.Core.PreviousRevision, PredecessorFullHEADDigest: h.Core.PreviousDigest, PredecessorToken: h.Core.PreviousToken,
		BeforeOwners: contract.EmptyGCOwnersDescriptor(), AfterOwners: gcFormatOwners(t), PlanDigest: fid(23), AfterProgressDigest: fid(24),
		PreservedCurrentDigest: fid(25), PreservedCurrentLength: 1234, HeadCoreDigest: contract.Hash(core), HeadCoreLength: uint32(len(core)), ConditionalPlanDigest: contract.Hash(plan)}
	h.AuthKind, h.Subject, h.GC = GCAuth, contract.LifecycleSubject{}, &q
	return h
}

// full_only: false
func TestGCHeadAuthorizationBindsExactCore(t *testing.T) {
	h := gcFormatHead(t)
	body, err := EncodeHead(h)
	if err != nil {
		t.Fatal("GC HEAD refused", err)
	}
	got, err := DecodeHead(body)
	if err != nil || got.AuthKind != GCAuth || got.GC == nil || *got.GC != *h.GC || got.Core != h.Core {
		t.Fatal("GC HEAD round trip", err)
	}
	for name, change := range map[string]func(*Head){
		"wrong-kind":        func(h *Head) { h.AuthKind = LifecycleAuth },
		"missing-subject":   func(h *Head) { h.GC = nil },
		"other-domain":      func(h *Head) { h.GC.DomainID = fid(30) },
		"other-predecessor": func(h *Head) { h.GC.PredecessorRevisionID = fid(31) },
		"other-token":       func(h *Head) { h.GC.PredecessorToken.Value = `"other"` },
		"other-core":        func(h *Head) { h.GC.HeadCoreDigest = fid(32) },
		"other-condition":   func(h *Head) { h.GC.ConditionalPlanDigest = fid(33) },
		"lifecycle-subject": func(h *Head) { h.Subject.Operation = fid(34) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := gcFormatHead(t)
			change(&bad)
			if _, err := EncodeHead(bad); err == nil {
				t.Fatal("unrelated GC authorization admitted")
			}
		})
	}
	if _, err := DecodeHead(body[:len(body)-1]); err == nil {
		t.Fatal("truncated GC HEAD accepted")
	}
	if _, err := DecodeHead(append(bytes.Clone(body), 0)); err == nil {
		t.Fatal("trailing GC HEAD bytes accepted")
	}
}

// full_only: false
func TestGCOptionalPlanPageMaximumFraming(t *testing.T) {
	var p contract.GCPlan
	p.DomainID, p.OperationID, p.RequestNonce = gcFormatID(1), gcFormatID(2), gcFormatID(3)
	p.StoreDescriptorDigest, p.PublicBasisDigest, p.SourcePinsDigest = gcFormatID(4), gcFormatID(5), gcFormatID(6)
	p.HeadRevisionID, p.FullHEADDigest, p.SnapshotID, p.RootDigest = gcFormatID(7), gcFormatID(8), gcFormatID(9), gcFormatID(10)
	p.MarkDigest, p.EnumerationDigest = gcFormatID(11), gcFormatID(12)
	p.TargetsDigest = gcFormatDigest(t, "1a377b491bde771cb4a3c80427a450b5300261d1c8fc97f1a3f15560c7b63030")
	p.PredecessorToken = contract.Token{Family: contract.AWS, Value: `"` + strings.Repeat("x", 254) + `"`}
	p.InputProviderCursor, p.NextProviderCursor = strings.Repeat("a", 4096), strings.Repeat("b", 4096)
	for i := 0; i < 256; i++ {
		var id ID
		binary.BigEndian.PutUint32(id[28:], uint32(i+1))
		p.Targets = append(p.Targets, contract.GCTarget{Object: contract.StoreObjectIdentity{Namespace: contract.StorePageObject, Kind: contract.ValueEntryPageKind, ObjectID: id}, Length: 2 << 20, Digest: gcFormatID(14), Token: p.PredecessorToken})
		p.Candidates = append(p.Candidates, contract.GCCandidate{KeyDigest: id, Classification: contract.GCCandidateEligible, TargetIndex: uint16(i), ListedLength: 2 << 20})
	}
	body, err := contract.EncodeGCPlan(p)
	if err != nil || len(body) != 105413 || fmt.Sprintf("%x", contract.Hash(body)) != "14681977b75d7a9e58db1ab20f3aadc53346b853d662cb8276d1bcf2999a2680" {
		t.Fatal("maximum plan fixture", len(body), err)
	}
	row := contract.SupportRecord{Kind: contract.GCPlanSupportKind, RecordID: p.OperationID, Body: body}
	page := RequiredSupportPage{Domain: p.DomainID, Object: gcFormatID(22), Records: []contract.SupportRecord{row}}
	encoded, err := EncodeRequiredSupportPage(page)
	if err != nil || len(encoded) != 105525 {
		t.Fatal("maximum packed plan page", len(encoded), err)
	}
	decoded, err := InspectRequiredSupportPage(encoded)
	if err != nil || len(decoded.Records) != 1 || decoded.Records[0].Kind != contract.GCPlanSupportKind || decoded.Records[0].RecordID != p.OperationID || !bytes.Equal(decoded.Records[0].Body, body) {
		t.Fatal("maximum optional payload page round trip", err)
	}
	page.Records[0].RecordID = gcFormatID(30)
	if _, err := EncodeRequiredSupportPage(page); err == nil {
		t.Fatal("plan payload accepted another record owner")
	}
}

package format

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestAdministrativeIndexLogicalEncodingOwnsExactCapacity(t *testing.T) {
	index := gcFormatIndex(t)
	body, err := EncodeAdministrativeIndex(index)
	if err != nil {
		t.Fatal(err)
	}
	if cap(body) != len(body) {
		t.Errorf("logical index retains unused encoded backing: length=%d capacity=%d", len(body), cap(body))
	}
	decoded, err := DecodeAdministrativeIndex(body)
	if err != nil || !reflect.DeepEqual(decoded, index) {
		t.Fatal("exact-capacity encoding changed the canonical logical index", err)
	}
}

// full_only: false
func TestAdministrativeIndexCanonicalSharedPageAndBounds(t *testing.T) {
	domain := fid(1)
	shared := Ref{Kind: contract.RequiredSupportKind, Format: Version, Domain: domain,
		Object: fid(4), Digest: fid(5), Length: 1024}
	descriptor := contract.GeneratorDescriptor{Digest: fid(6), Length: 4}
	index := AdministrativeIndex{Domain: domain, Object: fid(7), SliceSnapshot: fid(10), Groups: []AdministrativeGroup{
		{GroupID: fid(2), OwnerID: fid(8), TargetID: fid(8), OwnerKind: AdministrativeGeneratedParent,
			Affected: descriptor, Dependencies: descriptor, Disposable: descriptor, ChargedBytes: 1024,
			SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing},
		{GroupID: fid(3), OwnerID: fid(9), TargetID: fid(9), OwnerKind: AdministrativeGeneratedDuty, DutyKind: contract.GeneratedDutyCreate,
			Affected: descriptor, Dependencies: descriptor, Disposable: descriptor, ChargedBytes: 1024,
			SelectedEvidenceSummary: contract.AdministrativeEvidenceAcknowledged},
	}, Pages: []AdministrativePage{{Ref: shared, Rows: []AdministrativeRowSummary{
		{Kind: contract.OperationMaterialSupportKind, RecordID: fid(11), BodyLength: 87},
		{Kind: contract.GeneratedPhaseSupportKind, RecordID: fid(12), BodyLength: 87},
	}, Spans: []AdministrativeSpan{
		{First: 0, Count: 1, GroupIndexes: []uint16{0}},
		{First: 1, Count: 1, GroupIndexes: []uint16{1}},
	}}}}
	body, err := EncodeAdministrativeIndex(index)
	if err != nil {
		t.Fatal(err)
	}
	const expectedLength = 115 + 2*247 + 108 + 2*(7+2) + 2*37
	if len(body) != expectedLength {
		t.Fatalf("administrative index framing: got %d want %d", len(body), expectedLength)
	}
	if length, err := AdministrativeIndexEncodedLength(index); err != nil || length != expectedLength {
		t.Fatalf("administrative length projection: got %d want %d: %v", length, expectedLength, err)
	}
	// Independently assembled schema-11 field bytes (ENKV tag/version, two fixed
	// groups, one shared Ref and two ordinal spans) hash to this fixed vector.
	if got := fmt.Sprintf("%x", sha256.Sum256(body)); got != "d2b57267c85947d170caf4cb3167e604425d76bcde87bc40fc433e6e0f0a0ba4" {
		t.Fatal("administrative index field order changed", got)
	}
	withDependency := index
	withDependency.Groups = append([]AdministrativeGroup(nil), index.Groups...)
	withDependency.Groups[1].RelatedGroupIndexes = []uint16{0}
	dependentBody, err := EncodeAdministrativeIndex(withDependency)
	if err != nil {
		t.Fatal("selected dependency relation refused", err)
	}
	if length, err := AdministrativeIndexEncodedLength(withDependency); err != nil || length != uint64(len(dependentBody)) || length != expectedLength+2 {
		t.Fatal("dependency bytes omitted from index projection", length, err)
	}
	sharedOwners := index
	sharedOwners.Pages = []AdministrativePage{{Ref: shared, Rows: slices.Clone(index.Pages[0].Rows), Spans: []AdministrativeSpan{{First: 0, Count: 2, GroupIndexes: []uint16{0, 1}}}}}
	sharedBody, err := EncodeAdministrativeIndex(sharedOwners)
	if err != nil {
		t.Fatal(err)
	}
	if length, err := AdministrativeIndexEncodedLength(sharedOwners); err != nil || length != uint64(len(sharedBody)) || length != expectedLength-7 {
		t.Fatal("multiowner span bytes omitted from index projection", length, err)
	}
	withDependency.Groups[0].RelatedGroupIndexes = []uint16{1}
	if _, err := EncodeAdministrativeIndex(withDependency); err == nil {
		t.Fatal("cyclic ownership relation accepted")
	}
	decoded, err := DecodeAdministrativeIndex(body)
	if err != nil || decoded.Domain != index.Domain || decoded.Object != index.Object ||
		!reflect.DeepEqual(decoded.Groups, index.Groups) || !reflect.DeepEqual(decoded.Pages, index.Pages) {
		t.Fatal("administrative index round trip", err)
	}
	bad := slices.Clone(body)
	bad[6]++
	if _, err := DecodeAdministrativeIndex(bad); err == nil {
		t.Fatal("unknown stored schema accepted")
	}
	bad = slices.Clone(body)
	bad = append(bad, 0)
	if _, err := DecodeAdministrativeIndex(bad); err == nil {
		t.Fatal("trailing index bytes accepted")
	}
}

// full_only: false
func TestAdministrativeIndexCannotSelectRowsBeyondAuthenticatedPageLength(t *testing.T) {
	ref := Ref{Kind: contract.RequiredSupportKind, Format: Version, Domain: fid(1),
		Object: fid(2), Digest: fid(3), Length: contract.RequiredSupportPageHeaderLength + 2*contract.SupportRecordMinLength}
	index := AdministrativeIndex{Domain: fid(1), Object: fid(4), SliceSnapshot: fid(5), Pages: []AdministrativePage{{Ref: ref,
		Spans: []AdministrativeSpan{{First: 2, Count: 1, Mandatory: true}}}}}
	if _, err := EncodeAdministrativeIndex(index); err == nil {
		t.Fatal("authenticated page is too short for selected ordinal")
	}
}

// full_only: false
func TestAdministrativeIndexPagesRoundTripBeyondOnePage(t *testing.T) {
	domain := fid(1)
	descriptor := contract.GeneratorDescriptor{Digest: fid(6), Length: 4}
	index := AdministrativeIndex{Domain: domain, Object: fid(7), SliceSnapshot: fid(10)}
	spans := make([]AdministrativeSpan, 10000)
	for i := range spans {
		var id ID
		binary.BigEndian.PutUint32(id[28:], uint32(i+1))
		index.Groups = append(index.Groups, AdministrativeGroup{GroupID: id, OwnerID: id, TargetID: id,
			OwnerKind: AdministrativeGeneratedDuty, DutyKind: contract.GeneratedDutyCreate, Affected: descriptor, Dependencies: descriptor, Disposable: descriptor,
			SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing})
		spans[i] = AdministrativeSpan{First: uint16(i), Count: 1, GroupIndexes: []uint16{uint16(i)}}
	}
	ref := Ref{Kind: contract.RequiredSupportKind, Format: Version, Domain: domain, Object: fid(8), Digest: fid(9),
		Length: contract.RequiredSupportPageHeaderLength + 10000*contract.SupportRecordMinLength}
	index.Pages = []AdministrativePage{{Ref: ref, ReadRequired: true, Spans: spans}}
	logical, err := EncodeAdministrativeIndex(index)
	if err != nil || len(logical) <= contract.MaxRequiredSupportPageLength {
		t.Fatal("large logical index was not representable", err)
	}
	pages, err := EncodeAdministrativeIndexPages(index)
	if err != nil || len(pages) != 2 {
		t.Fatal("large logical index did not require two bounded shards", err, len(pages))
	}
	for i, page := range pages {
		if page.Ref.Index != uint16(i) || len(page.Body) > contract.MaxRequiredSupportPageLength || CheckReference(page.Ref, page.Body) != nil {
			t.Fatal("noncanonical administrative shard", i)
		}
	}
	decoded, err := DecodeAdministrativeIndexPages(pages)
	if err != nil || len(decoded.Groups) != len(index.Groups) || len(decoded.Pages) != 1 ||
		len(decoded.Pages[0].Spans) != len(spans) || decoded.Object != index.Object {
		t.Fatal("administrative shard round trip", err)
	}
	missing := append([]AdministrativeIndexPage(nil), pages[:1]...)
	if _, err := DecodeAdministrativeIndexPages(missing); err == nil {
		t.Fatal("missing mandatory shard accepted")
	}
	wrong := append([]AdministrativeIndexPage(nil), pages...)
	wrong[0], wrong[1] = wrong[1], wrong[0]
	if _, err := DecodeAdministrativeIndexPages(wrong); err == nil {
		t.Fatal("reordered mandatory shards accepted")
	}
	decodeBorrowed := func(pages []AdministrativeIndexPage, fail int) (AdministrativeIndex, error) {
		refs := make([]Ref, len(pages))
		for i, page := range pages {
			refs[i] = page.Ref
		}
		workspace := make([]byte, contract.MaxRequiredSupportPageLength)
		next := 0
		return DecodeAdministrativeIndexSource(refs, func(ref Ref) ([]byte, error) {
			if next == fail {
				return nil, errors.New("unavailable next index shard")
			}
			if next == len(pages) || ref != pages[next].Ref {
				t.Fatal("source changed ordered shard reference")
			}
			// A Store is allowed to reuse its response on the next read.
			clear(workspace)
			body := workspace[:len(pages[next].Body)]
			copy(body, pages[next].Body)
			next++
			return body, nil
		})
	}
	streamed, err := decodeBorrowed(pages, -1)
	if err != nil || !reflect.DeepEqual(streamed, decoded) {
		t.Fatal("borrowed source changed cross-shard fields", err)
	}
	if _, err := decodeBorrowed(pages, 1); err == nil || err.Error() != "unavailable next index shard" {
		t.Fatal("source lost next-read failure", err)
	}
	if _, err := decodeBorrowed(wrong, -1); err == nil {
		t.Fatal("source accepted reordered shard references")
	}
	badDigest := slices.Clone(pages)
	for i := range badDigest {
		badDigest[i].Body = bytes.Clone(pages[i].Body)
		badDigest[i].Body[80] ^= 0x80
		badDigest[i].Ref, err = Reference(contract.AdministrativeIndexKind, domain, pages[i].Ref.Object, uint16(i), badDigest[i].Body)
		if err != nil {
			t.Fatal("authenticated wrong whole digest", err)
		}
	}
	if _, err := decodeBorrowed(badDigest, -1); err == nil {
		t.Fatal("source accepted wrong logical whole digest")
	}
	// 113 +8489*247 +20*2 places the first page Ref100 bytes before
	// the physical boundary. The normal fixture crosses a descriptor.
	refIndex := index
	refIndex.Groups = slices.Clone(index.Groups[:8489])
	refIndex.Groups[0].RelatedGroupIndexes = make([]uint16, 20)
	for i := range refIndex.Groups[0].RelatedGroupIndexes {
		refIndex.Groups[0].RelatedGroupIndexes[i] = uint16(i + 1)
	}
	refIndex.Pages = slices.Clone(index.Pages)
	refIndex.Pages[0].Spans = slices.Clone(spans[:8489])
	refPages, err := EncodeAdministrativeIndexPages(refIndex)
	if err != nil {
		t.Fatal("cross-shard Ref fixture", err)
	}
	streamed, err = decodeBorrowed(refPages, -1)
	if err != nil || !reflect.DeepEqual(streamed.Pages, refIndex.Pages) {
		t.Fatal("borrowed source changed cross-shard Ref", err)
	}
	// A maximum GC target vector crosses the first physical boundary. Its
	// borrowed header must be copied before the target read replaces it.
	progress := gcFormatProgress(t)
	progress.Targets = make([]contract.GCTargetProgress, contract.GCTargetLimit)
	for i := range progress.Targets {
		progress.Targets[i].Disposition = contract.GCTargetPending
	}
	progress.RemainingCount = contract.GCTargetLimit
	progress.TargetsDescriptor.Count = contract.GCTargetLimit
	progress.TargetsDescriptor.Length = 21 + contract.GCTargetLimit*78
	group := &index.Groups[8455]
	group.OwnerKind, group.DutyKind, group.GC = AdministrativeGC, 0, &progress
	group.Affected = contract.GeneratorDescriptor{Digest: progress.TargetsDescriptor.Digest, Length: progress.TargetsDescriptor.Length, Count: progress.TargetsDescriptor.Count}
	gcPages, err := EncodeAdministrativeIndexPages(index)
	if err != nil {
		t.Fatal("cross-shard GC fixture", err)
	}
	streamed, err = decodeBorrowed(gcPages, -1)
	if err != nil || !reflect.DeepEqual(streamed.Groups[8455].GC, &progress) {
		t.Fatal("borrowed source changed cross-shard GC body", err)
	}
}

// full_only: false
func TestAdministrativeIndexAddedPageCrossesExactShardBoundary(t *testing.T) {
	const groups = 8190
	const extraMandatorySpans = 22
	domain := fid(1)
	descriptor := contract.GeneratorDescriptor{Digest: fid(6), Length: 4}
	index := AdministrativeIndex{Domain: domain, Object: fid(7), SliceSnapshot: fid(10)}
	spans := make([]AdministrativeSpan, 0, groups+extraMandatorySpans)
	for i := 0; i < groups; i++ {
		var id ID
		binary.BigEndian.PutUint32(id[28:], uint32(i+1))
		index.Groups = append(index.Groups, AdministrativeGroup{GroupID: id, OwnerID: id, TargetID: id,
			OwnerKind: AdministrativeGeneratedDuty, DutyKind: contract.GeneratedDutyCreate, Affected: descriptor, Dependencies: descriptor, Disposable: descriptor,
			SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing})
		spans = append(spans, AdministrativeSpan{First: uint16(i), Count: 1, GroupIndexes: []uint16{uint16(i)}})
	}
	for i := 0; i < extraMandatorySpans; i++ {
		spans = append(spans, AdministrativeSpan{First: uint16(groups + i), Count: 1, Mandatory: true})
	}
	index.Pages = []AdministrativePage{{Ref: Ref{Kind: contract.RequiredSupportKind, Format: Version,
		Domain: domain, Object: fid(8), Digest: fid(9),
		Length: contract.RequiredSupportPageHeaderLength + (groups+extraMandatorySpans)*contract.SupportRecordMinLength}, ReadRequired: true, Spans: spans}}
	before, err := EncodeAdministrativeIndex(index)
	if err != nil || len(before) != 2097017 {
		t.Fatalf("predecessor logical index: %d, %v", len(before), err)
	}
	if length, err := AdministrativeIndexEncodedLength(index); err != nil || length != uint64(len(before)) {
		t.Fatalf("predecessor index length: %d, %v", length, err)
	}
	if count, err := AdministrativeIndexShardCount(uint64(len(before))); err != nil || count != 1 {
		t.Fatalf("predecessor shard projection: %d, %v", count, err)
	}
	shards, err := EncodeAdministrativeIndexPages(index)
	if err != nil || len(shards) != 1 {
		t.Fatalf("predecessor shard count: %d, %v", len(shards), err)
	}
	index.Pages = append(index.Pages, AdministrativePage{Ref: Ref{Kind: contract.RequiredSupportKind, Format: Version,
		Domain: domain, Object: fid(11), Index: 1, Digest: fid(12),
		Length: contract.RequiredSupportPageHeaderLength + contract.SupportRecordMinLength}, ReadRequired: true,
		Spans: []AdministrativeSpan{{First: 0, Count: 1, Mandatory: true}}})
	after, err := EncodeAdministrativeIndex(index)
	if err != nil || len(after) != len(before)+115 {
		t.Fatalf("successor logical index: %d, %v", len(after), err)
	}
	if length, err := AdministrativeIndexEncodedLength(index); err != nil || length != uint64(len(after)) {
		t.Fatalf("successor index length: %d, %v", length, err)
	}
	if count, err := AdministrativeIndexShardCount(uint64(len(after))); err != nil || count != 2 {
		t.Fatalf("successor shard projection: %d, %v", count, err)
	}
	shards, err = EncodeAdministrativeIndexPages(index)
	if err != nil || len(shards) != 2 {
		t.Fatalf("successor shard count: %d, %v", len(shards), err)
	}
}

// full_only: false
func TestAdministrativeOwnerKindsMatchWireValues(t *testing.T) {
	kinds := []uint8{AdministrativeGeneratedParent, AdministrativeGeneratedDuty, AdministrativeGeneratedHazard, AdministrativeInboxRelease, AdministrativePublicationCoordinate, AdministrativePublicationMarker, AdministrativeGC}
	for i, kind := range kinds {
		if kind != uint8(i+1) {
			t.Fatalf("owner kind position=%d value=%d", i, kind)
		}
	}
}

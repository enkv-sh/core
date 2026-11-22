package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// Keep the existing content fixture's exact bodies, but expose fragments only
// through fresh selected Ref reads with one overwritten Store borrow.
func selectedSliceVerificationFixture(t testing.TB, blobs []generatedContentFixtureBlob,
	locations []contract.GeneratorSliceLocation, wrongWhole contract.ID) (*selectedImage, selectedObjectReader, *readFailureStore, map[string][]byte, []byte) {
	t.Helper()
	state := generatedContentState(t, blobs, slices.Clone(locations))
	image := state.selectedImage()
	image.fragmentFacts = make(map[format.FragmentLocation]selectedFragmentFact)
	bodies := make(map[string][]byte)
	const prefix = "selected-slice-verification"
	for i := range image.support {
		page := &image.support[i]
		rows := make([]contract.SupportRecord, len(page.Records))
		for j, row := range page.Records {
			rows[j] = contract.SupportRecord(row)
			if row.Kind != contract.GeneratedFragmentSupportKind {
				continue
			}
			fragment, err := contract.InspectGeneratedFragment(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			if fragment.BlobID != wrongWhole {
				continue
			}
			fragment.WholeDigest = generatedVectorID(90)
			rows[j].Body, err = contract.EncodeGeneratedFragment(contract.GeneratedFragment(fragment))
			if err != nil {
				t.Fatal(err)
			}
		}
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: rows})
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal(err)
		}
		key, err := format.Key(prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		bodies[key] = body
		image.root.RequiredSupport = append(image.root.RequiredSupport, ref)
		facts := selectedSupportPageFacts{ref: ref}
		for j, row := range rows {
			digest, err := contract.InspectSupportRecordDigest(image.root.Domain, row)
			if err != nil {
				t.Fatal(err)
			}
			facts.rows = append(facts.rows, digest)
			facts.ordinals = append(facts.ordinals, uint16(j))
			page.Records[j] = contract.SupportRecordView(row)
			if row.Kind != contract.GeneratedFragmentSupportKind {
				continue
			}
			fragment, err := contract.InspectGeneratedFragment(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			location := format.FragmentLocation{BlobID: fragment.BlobID, FragmentIndex: fragment.Index,
				SupportPageIndex: page.Index, RowSlot: uint8(j)}
			image.fragmentFacts[location] = selectedFragmentFact{ref: ref, row: digest, physical: uint16(j), logical: uint16(j),
				blob: fragment.BlobID, index: fragment.Index, count: fragment.Count, total: fragment.TotalLength,
				whole: fragment.WholeDigest, offset: fragment.Offset, payloadLength: uint32(len(fragment.Payload))}
			page.Records[j].Body = nil
		}
		image.supportFacts = append(image.supportFacts, facts)
	}
	borrowed := make([]byte, format.MaxRequiredSupportPage)
	store := &readFailureStore{}
	store.onReadCtx = func(context.Context) (contract.ReadResult, bool) {
		body, found := bodies[store.keys[len(store.keys)-1]]
		if !found {
			return contract.ReadResult{Status: contract.ReadMissing}, true
		}
		copy(borrowed, body)
		return contract.ReadResult{Status: contract.ReadOK, Body: borrowed[:len(body)]}, true
	}
	reader := selectedObjectReader{domain: image.root.Domain, descriptor: contract.Descriptor{Prefix: prefix}, source: store}
	return image, reader, store, bodies, borrowed
}

// full_only: false
func TestSelectedGeneratedSliceVerificationReadsEachFragmentOnce(t *testing.T) {
	blob := bytes.Repeat([]byte{13}, contract.GeneratedFragmentMaxPayload+17)
	blob[contract.GeneratedFragmentMaxPayload] = 14
	blobID, unmappedID := generatedVectorID(3), generatedVectorID(8)
	blobs := []generatedContentFixtureBlob{{blobID, blob}, {unmappedID, []byte("unmapped receipt-index-like blob")}}
	// Commit the exact expected byte spans with the standard SHA-256 primitive,
	// independently of the generated-content verification implementation.
	digest := func(body []byte) contract.ID { return contract.ID(sha256.Sum256(body)) }
	locations := []contract.GeneratorSliceLocation{
		{Schema: 1, ContentKind: contract.GeneratorContentSource, ContentID: generatedVectorID(4), BlobID: blobID,
			Offset: 1, Length: 32, Digest: digest(blob[1:33])},
		{Schema: 1, ContentKind: contract.GeneratorContentIntent, ContentID: generatedVectorID(5), BlobID: blobID,
			Offset: 9, Length: 16, Digest: digest(blob[9:25])},
		{Schema: 1, ContentKind: contract.GeneratorContentSource, ContentID: generatedVectorID(6), BlobID: blobID,
			Offset: contract.GeneratedFragmentMaxPayload - 8, Length: 16,
			Digest: digest(blob[contract.GeneratedFragmentMaxPayload-8 : contract.GeneratedFragmentMaxPayload+8])},
	}
	t.Run("overlapping and cross-fragment slices", func(t *testing.T) {
		image, reader, store, _, borrowed := selectedSliceVerificationFixture(t, blobs, locations, contract.ID{})
		want := slices.Clone(locations)
		slices.SortFunc(want, func(a, b contract.GeneratorSliceLocation) int {
			if a.ContentKind != b.ContentKind {
				return int(a.ContentKind) - int(b.ContentKind)
			}
			return bytes.Compare(a.ContentID[:], b.ContentID[:])
		})
		for invocation := 1; invocation <= 2; invocation++ {
			if result := verifySelectedGeneratedSlices(t.Context(), image, reader); result != (Result{}) {
				t.Fatal("complete selected slices refused", result)
			}
			if !slices.Equal(image.generatedSliceLocations, want) {
				t.Fatal("completed logical locations differ")
			}
			if got, want := len(store.keys), invocation*len(image.root.Generated.Fragments); got != want {
				t.Fatalf("physical fragment reads = %d, want %d; logical overlap must not reread payload pages", got, want)
			}
			for i, location := range image.root.Generated.Fragments {
				fact := image.fragmentFacts[location]
				key, err := format.Key(reader.descriptor.Prefix, fact.ref)
				call := (invocation-1)*len(image.root.Generated.Fragments) + i
				if err != nil || store.keys[call] != key || store.limits[call] != fact.ref.Length {
					t.Fatal("fragment read changed the exact selected Ref", call, err)
				}
			}
			// A later Store operation can overwrite the borrow. Only authenticated
			// metadata and owned Slice carrier bodies may survive verification.
			for i := range borrowed {
				borrowed[i] = 0xa5
			}
			if len(image.cache) != 0 {
				t.Fatal("verification retained payload page backing")
			}
			for _, page := range image.support {
				for _, row := range page.Records {
					if row.Kind == contract.GeneratedFragmentSupportKind && row.Body != nil {
						t.Fatal("verification retained fragment payload backing")
					}
				}
			}
		}
	})
	for _, damage := range []string{"logical digest", "whole digest", "unmapped whole digest", "unknown blob", "slice past blob"} {
		t.Run(damage, func(t *testing.T) {
			changed := slices.Clone(locations)
			var wrongWhole contract.ID
			switch damage {
			case "logical digest":
				changed[1].Digest[0] ^= 1
			case "whole digest":
				wrongWhole = blobID
			case "unmapped whole digest":
				wrongWhole = unmappedID
			case "unknown blob":
				changed[1].BlobID = generatedVectorID(91)
			case "slice past blob":
				changed[1].Offset = uint64(len(blob))
			}
			image, reader, _, _, _ := selectedSliceVerificationFixture(t, blobs, changed, wrongWhole)
			if result := verifySelectedGeneratedSlices(t.Context(), image, reader); result.Outcome != IntegrityFailure || result.Reason != InvalidRelation {
				t.Fatal("invalid independently committed digest or location accepted", damage, result)
			}
			if image.generatedSliceLocations != nil {
				t.Fatal("failed verification published logical locations")
			}
		})
	}
	for _, damage := range []string{"noncontiguous blob", "missing final fragment"} {
		t.Run(damage, func(t *testing.T) {
			image, reader, _, _, _ := selectedSliceVerificationFixture(t, blobs, locations, contract.ID{})
			fragments := slices.Clone(image.root.Generated.Fragments)
			switch damage {
			case "noncontiguous blob":
				image.root.Generated.Fragments = []format.FragmentLocation{fragments[0], fragments[2], fragments[1]}
			case "missing final fragment":
				// Keep selected-row/fact counts consistent so the final group's
				// missing successor is the failing relation, rather than a count.
				delete(image.fragmentFacts, fragments[1])
				position := int(fragments[1].SupportPageIndex)
				image.support[position].Records = nil
				image.supportFacts[position].rows, image.supportFacts[position].ordinals = nil, nil
				image.root.Generated.Fragments = []format.FragmentLocation{fragments[2], fragments[0]}
			}
			if result := verifySelectedGeneratedSlices(t.Context(), image, reader); result.Outcome != IntegrityFailure || result.Reason != InvalidRelation {
				t.Fatal("incomplete or repeated fragment group accepted", damage, result)
			}
			if image.generatedSliceLocations != nil {
				t.Fatal("invalid fragment directory published logical locations")
			}
		})
	}
	t.Run("repeated blob group", func(t *testing.T) {
		repeated := append(slices.Clone(blobs), blobs[1])
		image, reader, store, _, _ := selectedSliceVerificationFixture(t, repeated, locations, contract.ID{})
		if result := verifySelectedGeneratedSlices(t.Context(), image, reader); result != failure(IntegrityFailure, InvalidRelation) || len(store.keys) != 3 {
			t.Fatal("repeated complete blob group was not refused before its first read", result, len(store.keys))
		}
		if image.generatedSliceLocations != nil {
			t.Fatal("repeated blob group published logical locations")
		}
	})
	t.Run("whole blob without logical slices", func(t *testing.T) {
		image, reader, store, _, _ := selectedSliceVerificationFixture(t, blobs, nil, contract.ID{})
		if result := verifySelectedGeneratedSlices(t.Context(), image, reader); result != (Result{}) || len(store.keys) != len(image.root.Generated.Fragments) {
			t.Fatal("whole unmapped blobs were not verified", result, len(store.keys))
		}
	})
	for _, fault := range []string{"short later page", "missing later page", "later access refusal", "pre-canceled", "canceled after first read", "canceled after final read"} {
		t.Run(fault, func(t *testing.T) {
			image, reader, store, bodies, borrowed := selectedSliceVerificationFixture(t, blobs, locations, contract.ID{})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			want := failure(EvidenceUnavailable, ReadUnavailable)
			wantReads := 1
			switch fault {
			case "short later page":
				want, wantReads = failure(IntegrityFailure, InvalidReference), 2
			case "missing later page":
				want, wantReads = failure(EvidenceUnavailable, MissingSelectedObject), 2
			case "later access refusal":
				want, wantReads = unavailableStoreRead(contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}), 2
			case "canceled after final read":
				wantReads = len(image.root.Generated.Fragments)
			case "pre-canceled":
				cancel()
				wantReads = 0
			}
			store.onReadCtx = func(context.Context) (contract.ReadResult, bool) {
				call := len(store.keys)
				body := bodies[store.keys[call-1]]
				if fault == "missing later page" && call == 2 {
					return contract.ReadResult{Status: contract.ReadMissing}, true
				}
				if fault == "later access refusal" && call == 2 {
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}, true
				}
				copy(borrowed, body)
				if fault == "short later page" && call == 2 {
					body = body[:len(body)-1]
				}
				if fault == "canceled after first read" && call == 1 || fault == "canceled after final read" && call == len(image.root.Generated.Fragments) {
					cancel()
				}
				return contract.ReadResult{Status: contract.ReadOK, Body: borrowed[:len(body)]}, true
			}
			if result := verifySelectedGeneratedSlices(ctx, image, reader); result != want || len(store.keys) != wantReads {
				t.Fatal("selected read failure changed or crossed the failing boundary", fault, result, want, len(store.keys))
			}
			if image.generatedSliceLocations != nil {
				t.Fatal("failed read published logical locations")
			}
		})
	}
}

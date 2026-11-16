package format

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func FuzzCanonicalRecords(f *testing.F) {
	valueEntryPageBytes, err := EncodeValueEntryPage(valueEntryPageFixture())
	if err != nil {
		f.Fatal(err)
	}
	recipient, err := EncodeRecipientPage(recipientFixture(f))
	if err != nil {
		f.Fatal(err)
	}
	root, err := EncodeRoot(rootFixture(f))
	if err != nil {
		f.Fatal(err)
	}
	h := headFixture(f)
	head, err := EncodeHead(h)
	if err != nil {
		f.Fatal(err)
	}
	core, err := EncodeHeadCore(h.Core)
	if err != nil {
		f.Fatal(err)
	}
	lifecycle, err := contract.LifecycleBytes(h.Subject)
	if err != nil {
		f.Fatal(err)
	}
	access, err := EncodeAccessPage(accessFixture())
	if err != nil {
		f.Fatal(err)
	}
	genesis, err := EncodeGenesisPlanCore(genesisPlanFixture(f))
	if err != nil {
		f.Fatal(err)
	}
	for _, b := range [][]byte{valueEntryPageBytes, recipient, root, head, core, lifecycle, access, genesis, nil, {255}, {'E', 'N', 'K', 'V', 1, 0, 1, 255, 255, 255, 255}} {
		f.Add(b)
	}
	for _, seed := range retiredVectors(f) {
		f.Add(seed)
	}
	for _, seed := range canonicalBoundarySeeds(f) {
		f.Add(seed)
	}
	for _, seed := range currentKeyBoundarySeeds(f) {
		f.Add(seed)
	}
	for _, maximum := range []bool{false, true} {
		for _, purpose := range []contract.GeneratorAuthorityPurpose{contract.GeneratorAuthorityRecord, contract.GeneratorAuthorityFinal} {
			h := generatedHeadFixture(f, maximum)
			h.Generator.Purpose = purpose
			if purpose == contract.GeneratorAuthorityRecord {
				h.Generator.LineageID, h.Generator.AttemptID, h.Generator.ResultID = fid(60), fid(61), fid(62)
				h.Generator.ResultDigest, h.Generator.DescriptorID, h.Generator.ConfigContractID, h.Generator.ResultContractID = fid(63), fid(64), fid(65), fid(66)
			}
			body, err := EncodeHead(h)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(body)
		}
	}
	for _, seed := range hostileRecords(f) {
		f.Add(seed.body)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		check := func(encoded []byte, err error) {
			t.Helper()
			if err != nil || !bytes.Equal(encoded, b) {
				t.Fatal("accepted a noncanonical record")
			}
		}
		if p, err := DecodeValueEntryPage(b); err == nil {
			check(EncodeValueEntryPage(p))
		}
		if p, err := DecodeRecipientPage(b); err == nil {
			check(EncodeRecipientPage(p))
		}
		if p, err := DecodeAccessPage(b); err == nil {
			check(EncodeAccessPage(p))
		}
		if p, err := InspectRequiredSupportPage(b); err == nil {
			records := make([]contract.SupportRecord, len(p.Records))
			for i, row := range p.Records {
				records[i] = contract.SupportRecord(row)
			}
			check(EncodeRequiredSupportPage(RequiredSupportPage{Domain: p.Domain, Object: p.Object, Index: p.Index, Records: records}))
		}
		if p, err := DecodeGenesisPlanCore(b); err == nil {
			check(EncodeGenesisPlanCore(p))
		}
		if p, err := DecodeRoot(b); err == nil {
			check(EncodeRoot(p))
		}
		if p, err := DecodeHeadCore(b); err == nil {
			check(EncodeHeadCore(p))
		}
		if p, err := DecodeHead(b); err == nil {
			check(EncodeHead(p))
			for i := range b {
				b[i] ^= 255
			}
			owned, err := EncodeHead(p)
			for i := range b {
				b[i] ^= 255
			}
			check(owned, err)
		}
		if p, err := DecodeLifecycleSubject(b); err == nil {
			check(contract.LifecycleBytes(p))
		}
	})
}

func currentKeyBoundarySeeds(t testing.TB) [][]byte {
	t.Helper()
	wire, _, _, _ := successionWireFixture(t)
	seeds := [][]byte{wire}
	add := func(body []byte, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		seeds = append(seeds, body)
	}
	// The shared fixture covers both prior authorizers, provider token forms,
	// and the six allowed operation/change-mask pairs.
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, approval := range []uint8{1, 2} {
			for _, change := range [][2]uint8{{1, 1}, {1, 2}, {1, 3}, {3, 4}, {3, 8}, {3, 12}} {
				h := successionHeadCase(t, change[0], change[1], approval, family)
				add(EncodeHead(h))
			}
		}
	}
	for _, count := range []int{1, 256} {
		page := receiptSupportFixture(t, count)
		for _, index := range []uint16{0, contract.MaxChildPages - 1} {
			page.Index = index
			body, err := EncodeRequiredSupportPage(page)
			if err != nil || len(body) != 75+508*count {
				t.Fatal("support boundary seed differs", err)
			}
			seeds = append(seeds, body, body[:len(body)-1], append(bytes.Clone(body), 0))
		}
	}
	return seeds
}

func canonicalBoundarySeeds(t testing.TB) [][]byte {
	t.Helper()
	var seeds [][]byte
	add := func(body []byte, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		seeds = append(seeds, body)
	}
	for _, size := range []int{0, contract.CryptoMaxRawValue} {
		page := valueEntryPageFixture()
		page.Index = contract.MaxValueEntryPages - 1
		for i := range page.Slots {
			entry := *page.Slots[0]
			entry.Name = fmt.Sprintf("%02d", i) + strings.Repeat("x", contract.CryptoMaxName-2)
			entry.Incarnation, entry.ValueState = fid(byte(32+i)), fid(byte(64+i))
			entry.ValueBytes = bytes.Repeat([]byte{0xff}, size)
			entry.ContentLength, entry.RetainedLength = uint32(size), uint32(size)
			page.Slots[i] = &entry
		}
		add(EncodeValueEntryPage(page))
	}
	rp := recipientFixture(t)
	rp.Index = contract.MaxRecipientPages - 1
	rp.Slots[7] = rp.Slots[2]
	rp.Slots[2] = nil
	add(EncodeRecipientPage(rp))
	r := rootFixture(t)
	r.ValueEntryPages = [contract.MaxValueEntryPages]*Ref{}
	r.Names = nil
	for i := 0; i < contract.MaxValueEntryPages; i++ {
		r.ValueEntryPages[i] = &Ref{Kind: ValueEntryPageKind, Domain: r.Domain, Object: fid(byte(80 + i)), Digest: fid(190), Format: Version, Length: 100, Index: uint16(i)}
	}
	for i := 0; i < contract.CryptoMaxValueEntries; i++ {
		r.Names = append(r.Names, NameEntry{Name: fmt.Sprintf("%03d", i) + strings.Repeat("x", contract.CryptoMaxName-3), Slot: uint16(i)})
	}
	r.ValueEntryCount, r.RawBytes, r.ChildCount = contract.CryptoMaxValueEntries, contract.CryptoMaxRawSet, contract.MaxValueEntryPages+3
	r.MembershipCount = contract.CryptoMaxValueEntries
	r.ChildEncodedBytes = uint64(contract.MaxValueEntryPages*100) + uint64(r.Recipients[4].Length) + uint64(r.AdministrativeIndex.Length) + uint64(r.RequiredSupport[0].Length)
	add(EncodeRoot(r))
	h := headFixture(t)
	h.Core.PreviousToken.Value = "\"" + strings.Repeat("x", 254) + "\""
	core, err := EncodeHeadCore(h.Core)
	if err != nil {
		t.Fatal(err)
	}
	h.Subject.HeadCore, h.Subject.HeadCoreLength = contract.Hash(core), uint32(len(core))
	plan, err := EncodeConditionalPlan(ConditionalPlan{Family: contract.AWS, Store: h.Core.Store, Coordinate: h.Core.Coordinate, NonBody: h.Core.NonBody, Condition: conditionFixture(h.Core.PreviousToken), HeadCore: h.Subject.HeadCore, HeadCoreLength: h.Subject.HeadCoreLength})
	if err != nil {
		t.Fatal(err)
	}
	h.Subject.ConditionalPlan = contract.Hash(plan)
	setMaximumLifecycle(&h.Subject)
	add(EncodeHeadCore(h.Core))
	add(contract.LifecycleBytes(h.Subject))
	add(EncodeHead(h))
	return seeds
}

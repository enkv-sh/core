package contract

import (
	"encoding/hex"
	"testing"
)

// Independent Python SHA-256 derivation: hash each existing projection preimage,
// then encode its hash || u64(preimage length) || u32(row count) as one 44-byte
// row. Hash ENKV/GENERATOR/v1/<label>\0 || u32(52) || u32(1) || u32(44) || row.
// Empty union/work preimages are their exact purpose || ID(1) || u32(0).
// The identity preimage is ENKV/LIFECYCLE-ID-PLAN/v6\0 || IDs(2,3,4,5) ||
// u32(0) || u32(page count), optionally followed by u8(7)||u16(0)||ID(8).
// ID(n) is 32 repeated n bytes. The nonempty union has name "key", both
// presence bits set, and two sides: slot 7, incarnation ID(2), entry ID(3)
// before and ID(4)/ID(3)/zero after, and u16(2)||IDs(5,6) as recipients.
// full_only: false
func TestGeneratorAuthorityProjectionIndependentHashes(t *testing.T) {
	id := generatedRecordID
	plan := IdentityPlan{Operation: id(2), Transition: id(3), Snapshot: id(4), Revision: id(5)}
	withPage := plan
	withPage.Pages = []IdentityPage{{Kind: AccessKind, Object: id(8)}}
	union := func(after ID) []UnionRow {
		return []UnionRow{{Name: "key", BeforePresent: true, AfterPresent: true,
			Before: MembershipSide{Slot: 7, Incarnation: id(2), EntryDigest: id(3), Recipients: []ID{id(5), id(6)}},
			After:  MembershipSide{Slot: 7, Incarnation: id(2), EntryDigest: after, Recipients: []ID{id(5), id(6)}}}}
	}
	for _, tc := range []struct {
		name, want string
		project    func() (GeneratorDescriptor, error)
	}{
		{"empty-members", "689f6b4c6022f0cff0287b289e629154bfb0e24984c0dda148f974f9d44b37ee", func() (GeneratorDescriptor, error) { return GeneratorAuthorityValueEntriesDescriptor(id(1), nil) }},
		{"empty-membership-plan", "5f26baa66caa062a7d429ff41b92b7d5c6c77e425f8758afa9c2ae4376a57c79", func() (GeneratorDescriptor, error) { return GeneratorAuthorityMembershipDescriptor(id(1), nil) }},
		{"empty-work", "9d511d547a48d066b19f1e886af4e96a8e4006abd33e19ea5c6f2fe9f4610e15", func() (GeneratorDescriptor, error) { return GeneratorAuthorityWorkDescriptor(id(1), nil) }},
		{"empty-identity", "710ef37f641cd9095114013095a617f60f46f5545a108acdfb2e84b3d87bc86f", func() (GeneratorDescriptor, error) { return GeneratorAuthorityIdentityDescriptor(plan) }},
		{"identity-page", "1b7c359b1d6b6f1889e3b9b9ccce1c4ea2c7d388ed1ac1f617d3ff22566fad39", func() (GeneratorDescriptor, error) { return GeneratorAuthorityIdentityDescriptor(withPage) }},
		{"members", "0c18247fa15fdbc128468bc785b7c1b2f5127f46107847a96b582055652ba44b", func() (GeneratorDescriptor, error) {
			return GeneratorAuthorityValueEntriesDescriptor(id(1), union(id(4)))
		}},
		{"unchanged", "3d52b1d7368e65ab7b9c7274ab7ddd59a2ee796a5852af630072e80836fc436d", func() (GeneratorDescriptor, error) {
			return GeneratorAuthorityValueEntriesDescriptor(id(1), union(id(3)))
		}},
		{"membership-plan", "a0b037e1b6ee88686c676e8bda4841cdd0a5fcb2b20dcdd3dc487f861e4b1042", func() (GeneratorDescriptor, error) { return GeneratorAuthorityMembershipDescriptor(id(1), union(ID{})) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.project()
			if err != nil || !got.Valid() || got.Length != 52 || got.Count != 1 || hex.EncodeToString(got.Digest[:]) != tc.want {
				t.Fatalf("authority projection = %+v, %v", got, err)
			}
		})
	}
}

// full_only: false
func TestGeneratorAuthorityProjectionSeparatesActualAndPlannedMembers(t *testing.T) {
	id := generatedRecordID
	row := UnionRow{Name: "key", BeforePresent: true, AfterPresent: true,
		Before: MembershipSide{Incarnation: id(2), EntryDigest: id(3), Recipients: []ID{id(5)}},
		After:  MembershipSide{Incarnation: id(2), EntryDigest: id(4), Recipients: []ID{id(5)}}}
	if _, err := GeneratorAuthorityValueEntriesDescriptor(id(1), []UnionRow{row}); err != nil {
		t.Fatal(err)
	}
	if _, err := GeneratorAuthorityMembershipDescriptor(id(1), []UnionRow{row}); err == nil {
		t.Fatal("planned membership accepted an actual after-member digest")
	}
	row.After.EntryDigest = ID{}
	if _, err := GeneratorAuthorityMembershipDescriptor(id(1), []UnionRow{row}); err != nil {
		t.Fatal(err)
	}
	if _, err := GeneratorAuthorityValueEntriesDescriptor(id(1), []UnionRow{row}); err == nil {
		t.Fatal("actual union accepted an unfilled after member")
	}
	row.Before.EntryDigest = ID{}
	if _, err := GeneratorAuthorityMembershipDescriptor(id(1), []UnionRow{row}); err == nil {
		t.Fatal("planned membership accepted an unfilled before member")
	}
	if _, err := GeneratorAuthorityWorkDescriptor(ID{}, nil); err == nil {
		t.Fatal("work without a domain accepted")
	}
	if _, err := GeneratorAuthorityWorkDescriptor(id(1), []SupportRecord{{Kind: MutationReceiptSupportKind}}); err == nil {
		t.Fatal("receipt included in live work")
	}
	if _, err := GeneratorAuthorityIdentityDescriptor(IdentityPlan{}); err == nil {
		t.Fatal("identity plan without identities accepted")
	}
}

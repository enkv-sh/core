package core

import (
	"context"
	"fmt"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestOpenRejectsSignedRecipientSlotOutsidePage(t *testing.T) {
	for _, slot := range []uint8{192, 0, 193} {
		t.Run(fmt.Sprintf("mask-%d", slot), func(t *testing.T) {
			f := newFixture(t, 1, false, 1)
			page := f.session.recipient
			page.Slots[6], page.Slots[7] = page.Slots[0], page.Slots[1]
			page.Slots[0], page.Slots[1] = nil, nil
			body, err := format.EncodeRecipientPage(page)
			if err != nil {
				t.Fatal(err)
			}
			ref, err := format.Reference(format.RecipientKind, page.Domain, page.Object, page.Index, body)
			if err != nil {
				t.Fatal(err)
			}
			// Start with two records in slots 6 and 7. A zero mask or another occupancy
			// bit without another record must fail after the signed root is read.
			const slotOffset = 7 + 32 + 32 + 2 // header, domain, object, page index
			body[slotOffset] = slot
			ref.Digest = contract.Hash(body)
			key, err := format.Key(f.store.desc.Prefix, ref)
			if err != nil {
				t.Fatal(err)
			}
			f.store.put(key, body)
			root := f.session.root
			root.Recipients[page.Index] = &ref
			refreshFixtureRecipientRefs(t, &root)
			body, err = format.EncodeRoot(root)
			if err != nil {
				t.Fatal(err)
			}
			rootRef, err := format.Reference(format.RootKind, root.Domain, root.Snapshot, 0, body)
			if err != nil {
				t.Fatal(err)
			}
			key, err = format.Key(f.store.desc.Prefix, rootRef)
			if err != nil {
				t.Fatal(err)
			}
			f.store.put(key, body)
			head := f.session.head
			head.Core.Root = rootRef
			selected := *f.session
			selected.root = root
			head.Subject.Normal.PublicState = selected.publicState()
			head.Subject.AfterAccessRoot = root.CurrentAccess.AccessRoot
			storeHead(t, f, head, true)
			f.trust.signs = 0
			f.trust.SetUnavailable(true)
			reads := f.store.reads
			s, r := Open(context.Background(), f.admission, f.store)
			if slot == 192 {
				if s == nil || r.Outcome != ObservedCurrent || s.recipient.Slots[6] == nil || s.recipient.Slots[7] == nil || s.recipient.Slots[0] != nil || s.recipient.Slots[1] != nil {
					t.Fatalf("valid signed recipient slot refused: %+v", r)
				}
			} else if s != nil || r.Outcome != IntegrityFailure || r.Reason != InvalidReference {
				t.Fatalf("invalid signed recipient slot accepted: %+v", r)
			}
			wantReads := 4 // HEAD, Root, entry page, then the invalid recipient page.
			if slot == 192 {
				wantReads = len(processPlainReadRequests(t, f.store.desc, fixtureStateImage(t, f)))
			}
			if f.store.reads-reads != wantReads {
				t.Fatal("fixture did not reach recipient page validation")
			}
			if f.trust.signs != 0 || f.store.creates != 0 || f.store.cas != 0 {
				t.Fatal("recipient page validation signed or wrote data")
			}
		})
	}
}

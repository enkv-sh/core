package format

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
)

func applyRecipientPageFixture(t testing.TB, count int) ([]contract.RecipientRecord, contract.IdentityPlan) {
	t.Helper()
	row := *recipientFixture(t).Slots[2]
	rows := make([]contract.RecipientRecord, count)
	for i := range rows {
		rows[i] = row
		rows[i].RecipientID = ID{}
		binary.BigEndian.PutUint16(rows[i].RecipientID[30:], uint16(i+1))
	}
	plan := contract.IdentityPlan{Operation: fid(50), Transition: fid(51), Snapshot: fid(52), Revision: fid(53)}
	for i := 0; i < (count+RecipientSlots-1)/RecipientSlots; i++ {
		plan.Pages = append(plan.Pages, contract.IdentityPage{Kind: RecipientKind, Index: uint16(i), Object: fid(byte(100 + i))})
	}
	return rows, plan
}

// full_only: false
func TestApplyRecipientPagesCanonicalPackingAndClosure(t *testing.T) {
	for _, count := range []int{1, 8, 9, 256} {
		rows, plan := applyRecipientPageFixture(t, count)
		pages, refs, err := ApplyRecipientPages(fid(1), rows, plan)
		if err != nil || len(pages) != (count+7)/8 || len(refs) != len(pages) {
			t.Fatal("canonical page count", count, err)
		}
		for i, page := range pages {
			if page.Domain != fid(1) || page.Object != plan.Pages[i].Object || page.Index != uint16(i) {
				t.Fatal("page identity differs", i)
			}
			for slot, row := range page.Slots {
				at := i*8 + slot
				if at >= count {
					if row != nil {
						t.Fatal("unused canonical slot occupied", at)
					}
					continue
				}
				if row == nil || !reflect.DeepEqual(*row, rows[at]) {
					t.Fatal("canonical registry order changed", at)
				}
			}
			body, err := EncodeRecipientPage(page)
			if err != nil {
				t.Fatal(err)
			}
			if refs[i].Digest != contract.Hash(body) || refs[i].Length != uint32(len(body)) || CheckReference(refs[i], body) != nil {
				t.Fatal("page ref does not commit exact body", i)
			}
			if i == len(pages)-1 && count%8 != 0 && body[73] != byte((1<<(count%8))-1) {
				t.Fatal("last page has noncanonical slot mask")
			}
		}
		if _, err := contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: fid(1), Refs: refs}); err != nil {
			t.Fatal("constructed refs do not close", err)
		}
		before, _ := contract.EncodeRecipientRecord(rows[0])
		pages[0].Slots[0].DisplayName = "local"
		after, _ := contract.EncodeRecipientRecord(rows[0])
		if !bytes.Equal(before, after) {
			t.Fatal("returned row struct aliases supplied row")
		}
	}
}

// full_only: false
func TestApplyRecipientPagesRejectsIncompleteOrUnsortedInputs(t *testing.T) {
	for _, condition := range []string{"empty", "reverse", "duplicate", "retired", "missing page", "extra page", "page index", "page identity", "later page identity", "zero domain"} {
		t.Run(condition, func(t *testing.T) {
			rows, plan := applyRecipientPageFixture(t, 9)
			if condition == "later page identity" {
				rows, plan = applyRecipientPageFixture(t, 17)
			}
			domain := fid(1)
			switch condition {
			case "empty":
				rows = nil
			case "reverse":
				rows[0], rows[1] = rows[1], rows[0]
			case "duplicate":
				rows[1].RecipientID = rows[0].RecipientID
			case "retired":
				rows[0].Status, rows[0].CurrentBinding = contract.RetiredRecipient, nil
			case "missing page":
				plan.Pages = plan.Pages[:1]
			case "extra page":
				plan.Pages = append(plan.Pages, contract.IdentityPage{Kind: RecipientKind, Index: 2, Object: fid(102)})
			case "page index":
				plan.Pages[1].Index = 2
			case "page identity":
				plan.Pages[1].Object = plan.Pages[0].Object
			case "later page identity":
				plan.Pages[2].Object = plan.Pages[1].Object
			case "zero domain":
				domain = ID{}
			}
			if _, _, err := ApplyRecipientPages(domain, rows, plan); err == nil {
				t.Fatal("incomplete or noncanonical page input accepted")
			}
		})
	}
}

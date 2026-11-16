package core

import (
	"bytes"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestMutationReceiptStorageRebasesColdRetainedFragmentSlots(t *testing.T) {
	for _, mode := range []string{"planned", "sealed"} {
		t.Run(mode, func(t *testing.T) {
			source := successionReceiptCapacityFixture(t)
			generatedInstallFixtureSupportReader(t, source)
			if result := source.validateSelectedOutputConfiguration(t.Context()); result.Outcome != 0 {
				t.Fatal("authenticate compaction predecessor output", result)
			}
			before, err := source.receiptWindows(t.Context())
			if err != nil || len(before.Successes) != 1 || len(before.Failures) != 0 {
				t.Fatal("exact compaction predecessor receipt window", err)
			}
			receipt, retainedBlob := before.Successes[0], (contract.ID{30})
			var original format.FragmentLocation
			for _, location := range source.root.Generated.Fragments {
				if location.BlobID == retainedBlob {
					original = location
				}
			}
			originalPosition, present := source.selectedSupportPosition(source.fragmentFacts[original].ref)
			if !present || original.BlobID != retainedBlob || original.RowSlot != 1 || source.fragmentFacts[original].physical != 1 {
				t.Fatal("fixture lacks retained fragment after the receipt index at original physical slot one")
			}
			receipt.OperationID, receipt.RequestIdentityDigest = contract.ID{70}, contract.ID{}
			delta := contract.MutationReceiptDeltaPlan{DomainID: receipt.DomainID, OperationKind: receipt.OperationKind, AddedCount: 1,
				Before: before, NewReceipt: contract.CompactMutationReceiptPlan(receipt)}
			indexes, err := source.mutationReceiptPageIndexes(t.Context())
			if err != nil {
				t.Fatal("plan compaction support indexes", err)
			}
			plan := transitionPlan{snapshot: contract.ID{73}}
			for _, index := range indexes {
				plan.supportPages[index] = contract.ID{80, byte(index)}
			}
			var identity contract.ID
			if mode == "sealed" {
				identity = contract.ID{71}
			}
			hot, err := source.encodeMutationReceiptSupport(t.Context(), plan, delta, identity)
			if err != nil {
				t.Fatal("complete-body compaction control", err)
			}
			cold := *source
			cold.support = slices.Clone(source.support)
			for i := range cold.support {
				cold.support[i].Records = slices.Clone(source.support[i].Records)
				for j, row := range cold.support[i].Records {
					if opaqueSupportKind(row.Kind) {
						cold.support[i].Records[j].Body = nil
					}
				}
			}
			beforeCold := receiptReservationInputSnapshot(t, &cold)
			compacted, err := cold.encodeMutationReceiptSupport(t.Context(), plan, delta, identity)
			if err != nil {
				t.Fatal("authenticated original-slot-one fragment could not compact to successor slot zero", err)
			}
			if !reflect.DeepEqual(hot.objects, compacted.objects) || !slices.Equal(hot.refs, compacted.refs) || !reflect.DeepEqual(hot.generated, compacted.generated) || hot.count != compacted.count || !reflect.DeepEqual(receiptReservationInputSnapshot(t, &cold), beforeCold) || cold.support[originalPosition].Records[original.RowSlot].Body != nil {
				t.Fatal("cold compaction differs from complete bodies or changes predecessor facts")
			}
			found, matchedPages := 0, 0
			for _, location := range compacted.generated.Fragments {
				if location.BlobID != retainedBlob {
					continue
				}
				found++
				if location.SupportPageIndex != original.SupportPageIndex || location.RowSlot != 0 {
					t.Fatal("successor retained fragment did not use its new compacted slot")
				}
				for _, page := range compacted.pages {
					if page.Index != location.SupportPageIndex {
						continue
					}
					matchedPages++
					if int(location.RowSlot) >= len(page.Records) {
						t.Fatal("compacted fragment slot is outside its exact successor page")
					}
					fragment, err := contract.InspectGeneratedFragment(page.Records[location.RowSlot].Body)
					if err != nil || fragment.BlobID != retainedBlob || !bytes.Equal(fragment.Payload, []byte("retained source bytes")) {
						t.Fatal("compaction substituted the receipt-index payload for retained source bytes", err)
					}
				}
			}
			if found != 1 || matchedPages != 1 {
				t.Fatal("retained fragment directory/page join lost or duplicated")
			}
			for _, damage := range []string{"original logical slot", "original physical slot"} {
				t.Run(damage, func(t *testing.T) {
					changed := cold
					if damage == "original logical slot" {
						changed.fragmentFacts = make(map[format.FragmentLocation]selectedFragmentFact, len(cold.fragmentFacts))
						for location, fact := range cold.fragmentFacts {
							changed.fragmentFacts[location] = fact
						}
						fact := changed.fragmentFacts[original]
						fact.logical = 0
						changed.fragmentFacts[original] = fact
					} else {
						changed.supportFacts = slices.Clone(cold.supportFacts)
						changed.supportFacts[originalPosition].ordinals = slices.Clone(cold.supportFacts[originalPosition].ordinals)
						changed.supportFacts[originalPosition].ordinals[original.RowSlot] = 0
					}
					if _, err := changed.encodeMutationReceiptSupport(t.Context(), plan, delta, identity); err == nil {
						t.Fatal("changed original source coordinate passed authenticated compaction")
					}
				})
			}
		})
	}
}

package core

import (
	"bytes"
	"context"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestSignedAggregateRejectsOversizedPageClosureBeforeFetch(t *testing.T) {
	for _, observation := range []bool{false, true} {
		name := "cold-open"
		if observation {
			name = "final-observation"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, contract.CryptoMaxValueEntries, false, contract.CryptoMaxRawSet/contract.CryptoMaxValueEntries)
			input := f.session.currentEntryInputs()
			for i := range input {
				input[i].InputBytes[0] ^= 255
			}
			c, result := f.session.Compare(context.Background(), input, admitSuppliedComparison(t, f.session, nil, input))
			if c == nil {
				t.Fatal(result)
			}
			candidate := prepare(t, f, c)
			originalHead := f.store.objects[f.store.desc.HeadKey]
			state := fixtureStateImage(t, f)
			state.Root.Snapshot = testID("oversized observed root")
			for i, page := range state.Pages {
				page.Object = testID(string(rune(i)) + " oversized page")
				for _, entry := range page.Slots {
					entry.ValueBytes = bytes.Repeat([]byte{42}, contract.CryptoMaxRawValue)
				}
			}
			// Each page is valid; the signed root still declares the admitted eight MiB.
			storeContractClosure(t, f, state)
			hostile := f.store.objects[f.store.desc.HeadKey]
			priorCache := len(f.session.cache)
			reads := f.store.reads
			if observation {
				f.store.objects[f.store.desc.HeadKey] = originalHead
				f.store.readHook = func(key string, r contract.ReadResult) contract.ReadResult {
					if key == f.store.desc.HeadKey {
						return contract.ReadResult{Status: contract.ReadOK, Body: bytes.Clone(hostile.Body), Token: contract.Token{Family: contract.GCP, Value: "987654321"}}
					}
					return r
				}
				result = f.session.Select(context.Background(), candidate)
				if result.Outcome != UnresolvedCommit || result.Reason != InvalidRelation || result.Evidence != NoEvidence || !result.CommitMayHaveOccurred {
					t.Fatalf("oversized observation: %+v", result)
				}
			} else {
				session, r := Open(context.Background(), f.admission, f.store)
				result = r
				if session != nil || result != (Result{Outcome: IntegrityFailure, Reason: InvalidRelation}) {
					t.Fatalf("oversized selected closure: %+v", result)
				}
			}
			if f.store.reads-reads != 2 {
				t.Fatalf("read %d objects before aggregate refusal; want HEAD and root only", f.store.reads-reads)
			}
			if len(f.session.cache) != priorCache {
				t.Fatal("invalid aggregate retained page buffers")
			}
		})
	}
}

// full_only: false
func TestSignedAggregateChecksDecodedPageBeforeCaching(t *testing.T) {
	for _, name := range []string{"actual-member-count", "actual-raw-bytes"} {
		t.Run(name, func(t *testing.T) {
			count, raw := 2, 0
			if name == "actual-raw-bytes" {
				count, raw = 1, 1
			}
			f := newFixture(t, count, false, raw)
			state := fixtureStateImage(t, f)
			if name == "actual-raw-bytes" {
				state.Root.Names[0].Name = string(bytes.Repeat([]byte{'n'}, contract.CryptoMaxName))
				state.Pages[0].Slots[0].Name = state.Root.Names[0].Name
				storeContractClosure(t, f, state)
				control, result := Open(context.Background(), f.admission, f.store)
				if control == nil || result.Outcome != ObservedCurrent {
					t.Fatal("valid raw-byte aggregate control", result)
				}
				f.session = control
				state = fixtureStateImage(t, f)
			}
			state.Pages[0].Object = testID("decoded aggregate page/" + name)
			if name == "actual-member-count" {
				state.Root.Names = state.Root.Names[:1]
				state.Root.ValueEntryCount = 1
				// Keep the signed aggregate plausible until the decoded page reveals
				// the omitted second entry. Its fixed fields and one recipient are
				// charged as declared raw bytes.
				state.Root.RawBytes = uint64(contract.ValueEntryFixedLength + 32 + len(state.Pages[0].Slots[1].Name))
			} else {
				// Preserve the page length while replacing name bytes with raw bytes.
				// The valid control keeps the closed signed projection well formed.
				state.Pages[0].Slots[0].Name = ""
				state.Pages[0].Slots[0].ValueBytes = bytes.Repeat([]byte{42}, contract.CryptoMaxName+1)
			}
			state.Root.MembershipCount = 1
			storeContractClosure(t, f, state)
			before := len(f.session.cache)
			reads := f.store.reads
			session, result := f.session.readCurrent(context.Background())
			if session != nil || result != (Result{Outcome: IntegrityFailure, Reason: InvalidRelation}) {
				t.Fatalf("decoded aggregate admitted: %+v", result)
			}
			if f.store.reads-reads != 3 {
				t.Fatalf("decoded page did not refuse before remaining closure: %d reads", f.store.reads-reads)
			}
			if len(f.session.cache) != before {
				t.Fatal("invalid decoded page entered authenticated cache")
			}
		})
	}
}

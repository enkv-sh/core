package crypto

import (
	"context"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestApplyPlainPredecessorSlotsAndExactExclusions(t *testing.T) {
	base := applyFixture(t, false)
	authority := base.control.AuthorityRecipientID
	reader := consumerID("reader")
	before := []contract.MembershipRow{
		{Name: "keep", Slot: 10, Incarnation: consumerID("keep incarnation"), EntryDigest: consumerID("keep before member"), Recipients: slices.Clone(base.q.Intent[0].Recipients)},
		{Name: "removed", Slot: 11, Incarnation: consumerID("removed incarnation"), EntryDigest: consumerID("removed before member"), Recipients: slices.Clone(base.q.Intent[0].Recipients)},
	}
	for _, damage := range []string{"valid", "wrong-retained-slot", "missing-exclusion", "wrong-exclusion-path"} {
		t.Run(damage, func(t *testing.T) {
			f := cloneApplyFixture(t, base)
			digest, err := contract.PlainInputDigest([]byte("plain"))
			if err != nil {
				t.Fatal(err)
			}
			f.q.Intent = append(f.q.Intent, contract.CryptoIntentRow{Name: "keep", Recipients: []contract.ID{authority}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, ContentLength: 5, PayloadLength: 5, PayloadDigest: digest, InputEncoding: contract.InputEncodingRaw, RetainedLength: 5, OutputEncoding: contract.OutputEncodingRaw})
			f.q.Context.IntentDescriptor, err = contract.CompleteApplyIntentDescriptor(f.q.Context.DomainID, f.q.Intent, f.q.Recipients)
			if err != nil {
				t.Fatal(err)
			}
			r := f.runtime(t, before)
			comparison := applyCompare(t, r, f)
			plan := applyPlan(f)
			// Existing plain value has no fresh identity. Core owns its complete
			// changed membership body; Crypto retains its admitted slot.
			plan.Rows = plan.Rows[:2]
			prepared := applyPrepare(t, r, f, comparison, plan)
			freeze := applyFreezeRequest(t, f, comparison, plan, prepared)
			public, err := contract.DecodePublicState(freeze.CandidatePublicState, f.q.Context.DomainID)
			if err != nil {
				t.Fatal(err)
			}
			slot := uint16(10)
			if damage == "wrong-retained-slot" {
				slot = 12
			}
			public.Rows = append(public.Rows, contract.PublicStateRow{Name: "keep", Slot: slot, EntryDigest: consumerID("Core checked changed plain member")})
			freeze.CandidatePublicState, err = contract.EncodePublicState(public)
			if err != nil {
				t.Fatal(err)
			}
			// These explicit expected removed sets are independent of the runtime
			// set-difference loop. Both paths use the shared canonical writer.
			var exclusions []contract.ExclusionRow
			for i, removed := range [][]contract.ID{{reader}, before[1].Recipients} {
				row := before[i]
				row.Recipients = removed
				path, err := contract.PlainExclusionDigest(contract.PlainExclusionPath{Domain: f.q.Context.DomainID, Name: row.Name, Slot: row.Slot, Incarnation: row.Incarnation, EntryDigest: row.EntryDigest, RemovedRecipients: removed})
				if err != nil {
					t.Fatal(err)
				}
				exclusions = append(exclusions, contract.ExclusionRow{MembershipRow: row, Path: path})
			}
			if damage == "missing-exclusion" {
				exclusions = exclusions[1:]
			}
			if damage == "wrong-exclusion-path" {
				exclusions[0].Path[0] ^= 1
			}
			freeze.Exclusions, err = contract.EncodeExclusions(f.q.Context.DomainID, exclusions)
			if err != nil {
				t.Fatal(err)
			}
			body, err := contract.EncodeCryptoFreezeRequest(freeze)
			if err != nil {
				t.Fatal(err)
			}
			reply := applyCall(r, context.Background(), contract.CryptoFreeze, body)
			if damage == "valid" {
				if reply.ResultCode != contract.CryptoSuccess {
					t.Fatalf("valid mixed first selection refused: %v", reply.ResultCode)
				}
				claimBody, err := contract.EncodeCryptoClaimRequest(r.apply.frozen)
				if err != nil {
					t.Fatal(err)
				}
				if reply := applyCall(r, context.Background(), contract.CryptoClaim, claimBody); reply.ResultCode != contract.CryptoSuccess {
					t.Fatal("mixed selection Claim failed")
				}
			} else if reply.ResultCode == contract.CryptoSuccess || len(reply.Body) != 0 {
				t.Fatal("edited plain facts frozen")
			}
			<-r.apply.done
			if f.route.privateCalls != 4 {
				t.Fatal("plain predecessor used a private route")
			}
		})
	}
}

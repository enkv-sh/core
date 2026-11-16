package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

// full_only: false
func TestApplyMixedGrantExclusionPreservesRequiredAccess(t *testing.T) {
	applyMixedGrantExclusionPreservesRequiredAccess(t, false, false)
}

// full_only: false
func TestApplyOriginalSealedExclusionStagesPreserveRequiredAccess(t *testing.T) {
	applyMixedGrantExclusionPreservesRequiredAccess(t, false, true)
}

func applyMixedGrantExclusionPreservesRequiredAccess(t *testing.T, retained, original bool) {
	t.Helper()
	f := retainedApplyFixture(t)
	authority, reader := f.control.AuthorityRecipientID, consumerID("reader")
	// Alpha starts authority-only and gains reader; beta loses reader.
	entry, err := contract.DecodeValueEntry(f.q.Current[0].EntryBytes)
	if err != nil {
		t.Fatal(err)
	}
	entry.Recipients = []contract.ID{authority}
	f.q.Current[0].EntryBytes, err = contract.EncodeValueEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	access, err := contract.DecodeAccessRecord(f.q.Current[0].AccessRecord)
	if err != nil {
		t.Fatal(err)
	}
	access.Wraps = slices.DeleteFunc(access.Wraps, func(row contract.WrapRow) bool { return row.SubjectID == reader })
	f.q.Current[0].AccessRecord, err = contract.EncodeAccessRecord(access)
	if err != nil {
		t.Fatal(err)
	}
	f.q.Intent[0].OutputEncoding = contract.OutputEncodingBase64
	f.q.Intent[1].Recipients = []contract.ID{authority}
	envelope, err := contract.DecodeSealedInputEnvelope(f.q.SealedInputs[1].EnvelopeBytes)
	if err != nil {
		t.Fatal(err)
	}
	binding := f.q.Bindings[applyBindingIndex(f.q.Bindings, authority)]
	digest, err := contract.PublicBindingDigest(binding.Binding)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Core.IntendedRecipientBindingSetDigest, err = contract.IntendedRecipientBindingSetDigest(f.q.Context.DomainID, authority, []contract.RecipientBindingReference{{RecipientID: authority, PublicBindingDigest: digest}})
	if err != nil {
		t.Fatal(err)
	}
	if !original {
		envelope, err = custody.SealInput(envelope.Core, binding, nil)
		if err != nil {
			t.Fatal(err)
		}
		replaceApplySource(t, &f, 1, envelope)
	} else {
		f.q.Context.IntentDescriptor, err = contract.CompleteApplyIntentDescriptor(f.q.Context.DomainID, f.q.Intent, f.q.Recipients)
		if err != nil {
			t.Fatal(err)
		}
	}
	sealedBefore := bytes.Clone(f.q.SealedInputs[1].EnvelopeBytes)
	if retained {
		useExactRetainedInputs(t, &f)
	}
	r := f.runtime(t, nil)
	body, err := contract.EncodeCryptoCompareRequest(f.q)
	if err != nil {
		t.Fatal(err)
	}
	reply := applyCall(r, context.Background(), contract.CryptoCompare, body)
	if reply.ResultCode != contract.CryptoSuccess {
		t.Fatal("sharing comparison", reply.ResultCode)
	}
	comparison, err := contract.DecodeCryptoCompareResult(reply.Body)
	if err != nil || len(comparison.Rows) != 2 || comparison.Rows[0].Relation != contract.CryptoEqual || comparison.Rows[1].Relation != contract.CryptoEqual || !comparison.Rows[0].ExclusionPathDigest.IsZero() || comparison.Rows[1].ExclusionPathDigest.IsZero() {
		t.Fatal("mixed comparison lost equality or exclusion", err)
	}
	plan := applyPlan(f)
	plan.Operation, plan.Transition, plan.Snapshot, plan.Revision = consumerID("sharing operation"), consumerID("sharing transition"), consumerID("sharing snapshot"), consumerID("sharing revision")
	plan.Rows = plan.Rows[1:]
	plan.Rows[0].ValueState, plan.Rows[0].OriginSnapshot, plan.Rows[0].OriginTransition = consumerID("exclusion value"), plan.Snapshot, plan.Transition
	identity, err := contract.EncodeIdentityPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	body, err = contract.EncodeCryptoPrepareRequest(contract.CryptoPrepareRequest{OperationRef: comparison.OperationRef, Context: f.q.Context, IdentityPlan: identity})
	if err != nil {
		t.Fatal(err)
	}
	reply = applyCall(r, context.Background(), contract.CryptoPrepare, body)
	if reply.ResultCode != contract.CryptoSuccess {
		t.Fatal("sharing prepare", reply.ResultCode)
	}
	prepared, err := contract.DecodeCryptoPrepareResult(reply.Body)
	if err != nil || len(prepared.Rows) != 2 || r.apply.identityDescriptor.Count != 1 || r.apply.preparedDescriptor.Count != 2 {
		t.Fatal("membership-only prepared row was lost", err)
	}
	var opens, wraps uint32
	for _, use := range reply.KeyUseRows {
		switch use.Purpose {
		case contract.KeyUseMaterialOpen:
			if use.SubjectID != authority {
				t.Fatal("authority grant used reader private key")
			}
			opens += use.Count
		case contract.KeyUseMaterialWrap:
			wraps += use.Count
		}
	}
	if opens != 2 || wraps != 3 {
		t.Fatal("grant rewrapped retained keys or did extra private work", opens, wraps)
	}
	for i, row := range prepared.Rows {
		current, ok := r.apply.current(contract.CryptoCurrentSecret{Slot: row.Slot, EntryBytes: row.EntryBytes, AccessRecord: row.AccessRecord})
		if !ok {
			t.Fatal("prepared sharing access is incomplete")
		}
		before, ok := r.apply.current(f.q.Current[i])
		if !ok {
			t.Fatal("invalid before fixture")
		}
		if current.entry.OutputEncoding != f.q.Intent[i].OutputEncoding {
			t.Fatal("sharing result lost the requested output encoding", current.entry.Name, current.entry.OutputEncoding, f.q.Intent[i].OutputEncoding)
		}
		if i == 0 {
			if current.core != before.core || !bytes.Equal(current.entry.ValueBytes, before.entry.ValueBytes) {
				t.Fatal("grant replaced immutable payload or value core")
			}
			for _, old := range before.access.Wraps {
				j := slices.IndexFunc(current.access.Wraps, func(wrap contract.WrapRow) bool {
					return wrap.SubjectID == old.SubjectID && wrap.SubjectKind == old.SubjectKind
				})
				if j < 0 || !reflect.DeepEqual(old, current.access.Wraps[j]) {
					t.Fatal("grant replaced ordinary or recovery protection")
				}
			}
		} else if current.core.EntryIncarnationID != before.core.EntryIncarnationID || current.core.ValueStateID == before.core.ValueStateID || current.core.DataKeyID == before.core.DataKeyID || current.core.CommitmentKeyID == before.core.CommitmentKeyID || bytes.Equal(current.entry.ValueBytes, before.entry.ValueBytes) {
			t.Fatal("exclusion reused protected material")
		}
		for _, wrap := range current.access.Wraps {
			packet, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, f.keys[wrap.SubjectID], wrap.RSACiphertext, nil)
			if err != nil {
				t.Fatal(err)
			}
			j := slices.IndexFunc(f.q.Bindings, func(binding contract.BindingTableRow) bool {
				return binding.SubjectKind == wrap.SubjectKind && binding.SubjectID == wrap.SubjectID
			})
			core, err := custody.ValueWrapCore(current.core, f.q.Bindings[j])
			if err != nil {
				t.Fatal(err)
			}
			contextDigest, err := contract.RSAPacketContextDigest(core)
			if err != nil {
				t.Fatal(err)
			}
			keys, err := custody.PacketKeys(packet, 1, contextDigest)
			if err != nil {
				t.Fatal(err)
			}
			plain, err := custody.OpenValue(current.core, current.payload, keys)
			if err != nil {
				t.Fatal(err)
			}
			want := []byte("first secret")
			if i == 1 {
				want = nil
			}
			matches := bytes.Equal(plain, want)
			clear(plain[:cap(plain)])
			clear(packet[:cap(packet)])
			if !matches {
				t.Fatal("remaining recipient or recovery cannot open sharing result")
			}
		}
	}
	freeze := applyFreezeRequest(t, f, comparison, plan, prepared)
	before, ok := r.apply.current(f.q.Current[1])
	if !ok {
		t.Fatal("invalid exclusion predecessor")
	}
	exclusions := []contract.ExclusionRow{{MembershipRow: contract.MembershipRow{Name: before.entry.Name, Slot: before.row.Slot, Incarnation: before.entry.Incarnation, EntryDigest: before.entryDigest, Recipients: []contract.ID{reader}}, Path: comparison.Rows[1].ExclusionPathDigest}}
	freeze.Exclusions, err = contract.EncodeExclusions(f.q.Context.DomainID, exclusions)
	if err != nil {
		t.Fatal(err)
	}
	body, err = contract.EncodeCryptoFreezeRequest(freeze)
	if err != nil {
		t.Fatal(err)
	}
	reply = applyCall(r, context.Background(), contract.CryptoFreeze, body)
	if reply.ResultCode != contract.CryptoSuccess {
		t.Fatal("mixed sharing freeze", reply.ResultCode)
	}
	claimBody, err := contract.EncodeCryptoClaimRequest(r.apply.frozen)
	if err != nil {
		t.Fatal(err)
	}
	if reply := applyCall(r, context.Background(), contract.CryptoClaim, claimBody); reply.ResultCode != contract.CryptoSuccess {
		t.Fatal("mixed sharing claim", reply.ResultCode)
	}
	if original {
		if !bytes.Equal(f.q.SealedInputs[1].EnvelopeBytes, sealedBefore) {
			t.Fatal("exclusion stages rewrote the original source")
		}
		for i, row := range prepared.Rows {
			f.q.Current[i] = contract.CryptoCurrentSecret{Slot: row.Slot, EntryBytes: row.EntryBytes, AccessRecord: row.AccessRecord}
		}
		f.q.Context.AdmissionID, f.q.Context.SessionID = consumerID("original repeat admission"), consumerID("original repeat session")
		repeat := f.runtime(t, nil)
		body, err := contract.EncodeCryptoCompareRequest(f.q)
		if err != nil {
			t.Fatal(err)
		}
		reply := applyCall(repeat, t.Context(), contract.CryptoCompare, body)
		if reply.ResultCode != contract.CryptoSuccess {
			t.Fatal("original source repeat comparison", reply.ResultCode)
		}
		checked, err := contract.DecodeCryptoCompareResult(reply.Body)
		if err != nil || len(checked.Rows) != 2 {
			t.Fatal("incomplete original source repeat", err)
		}
		for _, row := range checked.Rows {
			if row.Relation != contract.CryptoEqual || !row.ExclusionPathDigest.IsZero() {
				t.Fatal("original source repeat changed semantic or exclusion facts")
			}
		}
	}
}

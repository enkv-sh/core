package crypto

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

func cloneApplyRecipients(t *testing.T, rows []contract.RecipientRecord) []contract.RecipientRecord {
	t.Helper()
	out := make([]contract.RecipientRecord, len(rows))
	for i, row := range rows {
		body, err := contract.EncodeRecipientRecord(row)
		if err != nil {
			t.Fatal(err)
		}
		out[i], err = contract.DecodeRecipientRecord(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func applyProposedRecipients(q contract.CryptoCompareRequest) []contract.RecipientRecord {
	out := make([]contract.RecipientRecord, len(q.Recipients))
	for i, row := range q.Recipients {
		out[i] = row.Recipient
	}
	return out
}

func refreshApplyIntent(t *testing.T, f *applyTestFixture) {
	t.Helper()
	var err error
	f.q.Context.IntentDescriptor, err = contract.CompleteApplyIntentDescriptor(f.q.Context.DomainID, f.q.Intent, f.q.Recipients)
	if err != nil {
		t.Fatal(err)
	}
}

type applyRecipientQualifier struct {
	binding contract.KMSBinding
	result  KeyResult
	calls   int
}

func (q *applyRecipientQualifier) Family() contract.Family { return q.binding.Provider }
func (q *applyRecipientQualifier) CredentialRoute() contract.ID {
	return consumerID("creation public route")
}
func (q *applyRecipientQualifier) Qualify(_ context.Context, binding contract.KMSBinding) KeyResult {
	q.calls++
	if !sameApplyBinding(binding, q.binding) {
		return KeyResult{Status: KeyInvalid}
	}
	return q.result
}

func prepareApplyRecipient(t *testing.T, f *applyTestFixture) contract.ID {
	t.Helper()
	index := slices.IndexFunc(f.q.Recipients, func(row contract.ApplyRecipientInput) bool {
		return row.Recipient.RecipientID != f.control.AuthorityRecipientID
	})
	if index < 0 {
		t.Fatal("ordinary recipient fixture is absent")
	}
	ref, err := contract.DecodeRef(f.q.Context.PredecessorRootRef[:], contract.CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	proof := &contract.RecipientCreationProof{Snapshot: ref.Object, Nonce: consumerID("creation nonce")}
	id, err := contract.RecipientCreationID(f.q.Context.DomainID, proof.Snapshot, proof.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	old := f.q.Recipients[index].Recipient.RecipientID
	binding := *f.q.Recipients[index].Recipient.CurrentBinding
	binding.BindingID, binding.BindingIncarnationID, err = contract.RecipientInitialBindingIDs(f.q.Context.DomainID, id)
	if err != nil {
		t.Fatal(err)
	}
	binding.BindingSerial = 1
	f.current = slices.DeleteFunc(f.current, func(row contract.RecipientRecord) bool { return row.RecipientID == old })
	f.q.Recipients[index] = contract.ApplyRecipientInput{Recipient: contract.RecipientRecord{RecipientID: id, Status: contract.CurrentRecipient, DisplayName: "created recipient", CurrentBinding: &binding}, Creation: proof}
	f.q.Bindings[applyBindingIndex(f.q.Bindings, old)] = contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: id, Binding: binding}
	slices.SortFunc(f.q.Bindings, func(a, b contract.BindingTableRow) int {
		if a.SubjectKind != b.SubjectKind {
			return int(a.SubjectKind) - int(b.SubjectKind)
		}
		return bytes.Compare(a.SubjectID[:], b.SubjectID[:])
	})
	slices.SortFunc(f.q.Recipients, func(a, b contract.ApplyRecipientInput) int {
		return bytes.Compare(a.Recipient.RecipientID[:], b.Recipient.RecipientID[:])
	})
	for i := range f.q.Intent {
		for j := range f.q.Intent[i].Recipients {
			if f.q.Intent[i].Recipients[j] == old {
				f.q.Intent[i].Recipients[j] = id
			}
		}
		slices.SortFunc(f.q.Intent[i].Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	}
	refreshApplyIntent(t, f)
	return id
}

// full_only: false
func TestApplyNewRecipientPublicQualification(t *testing.T) {
	base := applyFixture(t, false)
	for _, plain := range []bool{false, true} {
		for _, outcome := range []string{"qualified", "denied", "unavailable", "mismatch"} {
			name := "unassigned/" + outcome
			if plain {
				name = "plain-membership/" + outcome
			}
			t.Run(name, func(t *testing.T) {
				f := cloneApplyFixture(t, base)
				id := prepareApplyRecipient(t, &f)
				f.q.Intent, f.q.SealedInputs, f.accepted = nil, nil, nil
				if plain {
					digest, err := contract.PlainInputDigest([]byte("plain"))
					if err != nil {
						t.Fatal(err)
					}
					readers := []contract.ID{f.control.AuthorityRecipientID, id}
					slices.SortFunc(readers, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
					f.q.Intent = []contract.CryptoIntentRow{{Name: "plain", Recipients: readers, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, ContentLength: 5, InputEncoding: contract.InputEncodingRaw, RetainedLength: 5, OutputEncoding: contract.OutputEncodingRaw, PayloadLength: 5, PayloadDigest: digest}}
				}
				refreshApplyIntent(t, &f)
				binding := f.q.Bindings[applyBindingIndex(f.q.Bindings, id)].Binding
				public := &applyRecipientQualifier{binding: binding, result: KeyResult{Status: KeyOK, Uses: KeyUses{Completed: 3}}}
				want := contract.CryptoSuccess
				switch outcome {
				case "denied":
					public.result = KeyResult{Status: KeyDenied, Uses: KeyUses{Denied: 1}}
					want = contract.CryptoPrivateRouteUnavailable
				case "unavailable":
					public.result = KeyResult{Status: KeyUnavailable, Uses: KeyUses{Failed: 1}}
					want = contract.CryptoCustodyUnavailable
				case "mismatch":
					public.binding.KeySelector += "-different"
					want = contract.CryptoPrivateRouteUnavailable
				}
				r := newConsumerRuntime(t, f.route)
				if err := r.admitApply(f.q, f.control, f.current, map[contract.ID]PublicKeyQualifier{id: public}, f.route.CredentialRoute(), f.accepted, nil, f.support, f.deadline); err != nil {
					t.Fatal("public creation admission", err)
				}
				body, err := contract.EncodeCryptoCompareRequest(f.q)
				if err != nil {
					t.Fatal(err)
				}
				reply := applyCall(r, t.Context(), contract.CryptoCompare, body)
				if reply.ResultCode != want || public.calls != 1 || f.route.publicCalls != 0 || f.route.privateCalls != 0 {
					t.Fatalf("creation qualification code=%v want=%v public=%d authority=%d/%d", reply.ResultCode, want, public.calls, f.route.publicCalls, f.route.privateCalls)
				}
				if outcome == "mismatch" {
					if len(reply.KeyUseRows) != 0 {
						t.Fatal("mismatched key acquired use facts")
					}
					return
				}
				use := independentKeyUseRow(f.q.Bindings[applyBindingIndex(f.q.Bindings, id)], contract.KeyUsePublicKeyRead, contract.KeyUseCompleted, 3)
				if outcome == "denied" {
					use.Outcome, use.Count = contract.KeyUseDenied, 1
				}
				if outcome == "unavailable" {
					use.Outcome, use.Count = contract.KeyUseFailed, 1
				}
				if !slices.Equal(reply.KeyUseRows, []contract.KeyUseRow{use}) {
					t.Fatal("inexact public qualification evidence", reply.KeyUseRows)
				}
			})
		}
	}
}

// full_only: false
func TestApplyCompleteRecipientIntentPinsAdmissionAndExchange(t *testing.T) {
	base := applyFixture(t, false)
	for _, stage := range []string{"admission", "exchange", "owned-copy"} {
		t.Run(stage, func(t *testing.T) {
			f := cloneApplyFixture(t, base)
			r := newConsumerRuntime(t, f.route)
			if stage == "admission" {
				f.q.Recipients[0].Recipient.DisplayName = "substituted"
				if err := r.admitApply(f.q, f.control, f.current, nil, f.route.CredentialRoute(), f.accepted, nil, f.support, f.deadline); err == nil {
					t.Fatal("uncommitted recipient metadata admitted")
				}
				return
			}
			body, err := contract.EncodeCryptoCompareRequest(f.q)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.admitApply(f.q, f.control, f.current, nil, f.route.CredentialRoute(), f.accepted, nil, f.support, f.deadline); err != nil {
				t.Fatal(err)
			}
			f.q.Recipients[0].Recipient.DisplayName = "substituted"
			if stage == "owned-copy" {
				f.q.Recipients[0].Recipient.CurrentBinding.SPKI[0] ^= 1
				if len(r.apply.request.Recipients) != len(base.q.Recipients) {
					t.Fatal("admission omitted the complete owned recipient registry")
				}
				for i, input := range r.apply.request.Recipients {
					want, err := contract.EncodeRecipientRecord(base.q.Recipients[i].Recipient)
					got, gotErr := contract.EncodeRecipientRecord(input.Recipient)
					if err != nil || gotErr != nil || !bytes.Equal(got, want) {
						t.Fatal("admission borrowed nested recipient registry bytes")
					}
				}
			} else {
				refreshApplyIntent(t, &f)
				body, err = contract.EncodeCryptoCompareRequest(f.q)
				if err != nil {
					t.Fatal(err)
				}
			}
			reply := applyCall(r, t.Context(), contract.CryptoCompare, body)
			if stage == "owned-copy" {
				if reply.ResultCode != contract.CryptoSuccess {
					t.Fatal("admission borrowed registry", reply.ResultCode)
				}
			} else if reply.ResultCode == contract.CryptoSuccess || f.route.privateCalls != 0 {
				t.Fatal("substituted recipient request reached private work")
			}
		})
	}
}

// full_only: false
func TestApplyFreezePinsCompleteRecipientRegistry(t *testing.T) {
	f := applyFixture(t, false)
	r := f.runtime(t, nil)
	comparison := applyCompare(t, r, f)
	plan := applyPlan(f)
	prepared := applyPrepare(t, r, f, comparison, plan)
	freeze := applyFreezeRequest(t, f, comparison, plan, prepared)
	freeze.Recipients = cloneApplyRecipients(t, freeze.Recipients)
	freeze.Recipients[0].DisplayName = "substituted candidate label"
	body, err := contract.EncodeCryptoFreezeRequest(freeze)
	if err != nil {
		t.Fatal(err)
	}
	before := f.route.privateCalls
	reply := applyCall(r, t.Context(), contract.CryptoFreeze, body)
	if reply.ResultCode == contract.CryptoSuccess || len(reply.Body) != 0 || f.route.privateCalls != before {
		t.Fatal("substituted candidate registry frozen")
	}
}

// full_only: false
func TestApplyFreshRecipientBindingRejectsOldSealedInputBeforePrivate(t *testing.T) {
	f := applyFixture(t, false)
	original := bytes.Clone(f.q.SealedInputs[0].EnvelopeBytes)
	id := prepareApplyRecipient(t, &f)
	public := &applyRecipientQualifier{binding: f.q.Bindings[applyBindingIndex(f.q.Bindings, id)].Binding, result: KeyResult{Status: KeyOK, Uses: KeyUses{Completed: 3}}}
	r := newConsumerRuntime(t, f.route)
	if err := r.admitApply(f.q, f.control, f.current, map[contract.ID]PublicKeyQualifier{id: public}, f.route.CredentialRoute(), f.accepted, nil, f.support, f.deadline); err != ErrAdmission {
		t.Fatal("old envelope binding admitted", err)
	}
	if f.route.privateCalls != 0 || public.calls != 0 || !bytes.Equal(original, f.q.SealedInputs[0].EnvelopeBytes) {
		t.Fatal("stale binding changed source or reached dependent work")
	}
}

// full_only: false
func TestApplyRecipientMetadataAuthenticatesEveryCurrentSecret(t *testing.T) {
	base := exactRetainedFixture(t)
	for _, damaged := range []bool{false, true} {
		name := "preserve-encrypted-state"
		if damaged {
			name = "last-secret-corruption"
		}
		t.Run(name, func(t *testing.T) {
			f := cloneApplyFixture(t, base)
			f.q.Recipients[0].Recipient.DisplayName = "changed display metadata"
			if damaged {
				entry, err := contract.DecodeValueEntry(f.q.Current[1].EntryBytes)
				if err != nil {
					t.Fatal(err)
				}
				entry.ValueBytes[len(entry.ValueBytes)-1] ^= 1
				f.q.Current[1].EntryBytes, err = contract.EncodeValueEntry(entry)
				if err != nil {
					t.Fatal(err)
				}
				useExactRetainedInputs(t, &f)
			}
			refreshApplyIntent(t, &f)
			original := make([]contract.CryptoCurrentSecret, len(f.q.Current))
			for i, row := range f.q.Current {
				original[i] = contract.CryptoCurrentSecret{Slot: row.Slot, EntryBytes: bytes.Clone(row.EntryBytes), AccessRecord: bytes.Clone(row.AccessRecord)}
			}
			r := f.runtime(t, nil)
			body, err := contract.EncodeCryptoCompareRequest(f.q)
			if err != nil {
				t.Fatal(err)
			}
			reply := applyCall(r, t.Context(), contract.CryptoCompare, body)
			want := contract.CryptoSuccess
			if damaged {
				want = contract.CryptoStoredAuthenticationFailed
			}
			if reply.ResultCode != want || f.route.privateCalls != 2 {
				t.Fatal("metadata skipped complete private validation", reply.ResultCode, f.route.privateCalls)
			}
			for i, row := range f.q.Current {
				if !bytes.Equal(row.EntryBytes, original[i].EntryBytes) || !bytes.Equal(row.AccessRecord, original[i].AccessRecord) {
					t.Fatal("metadata changed encrypted records")
				}
			}
			if damaged {
				if len(reply.Body) != 0 {
					t.Fatal("last secret failure returned partial comparison")
				}
				return
			}
			comparison, err := contract.DecodeCryptoCompareResult(reply.Body)
			if err != nil {
				t.Fatal(err)
			}
			plan := applyPlan(f)
			plan.Rows = nil
			plan.Pages = []contract.IdentityPage{{Kind: contract.RecipientKind, Index: 0, Object: consumerID("metadata recipient page")}}
			prepared := applyPrepare(t, r, f, comparison, plan)
			if len(prepared.Rows) != 0 {
				t.Fatal("metadata prepared replacement encrypted material")
			}
		})
	}
}

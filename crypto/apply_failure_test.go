package crypto

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

func cloneApplyFixture(t *testing.T, f applyTestFixture) applyTestFixture {
	t.Helper()
	body, err := contract.EncodeCryptoCompareRequest(f.q)
	if err != nil {
		t.Fatal(err)
	}
	f.q, err = contract.DecodeCryptoCompareRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	f.current = cloneApplyRecipients(t, f.current)
	control, err := contract.EncodeControlCore(f.control)
	if err != nil {
		t.Fatal(err)
	}
	f.control, err = contract.DecodeControlCore(control)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(map[contract.ID]contract.SealedInputCore, len(f.accepted))
	for digest, core := range f.accepted {
		accepted[digest] = core
	}
	f.accepted = accepted
	f.route = &consumerTestRoute{testKeyAccess: &testKeyAccess{key: f.route.key, binding: f.route.binding}}
	return f
}

func replaceApplySource(t *testing.T, f *applyTestFixture, index int, envelope contract.SealedInputEnvelope) {
	t.Helper()
	delete(f.accepted, contract.Hash(f.q.SealedInputs[index].EnvelopeBytes))
	body, err := contract.EncodeSealedInputEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	f.q.SealedInputs[index].EnvelopeBytes = body
	f.accepted[contract.Hash(body)] = envelope.Core
	preimage := append([]byte("ENKV/SEALED-INPUT/v1\x00"), binary.BigEndian.AppendUint32(nil, uint32(len(body)))...)
	preimage = append(preimage, body...)
	intent := slices.IndexFunc(f.q.Intent, func(row contract.CryptoIntentRow) bool { return row.Name == f.q.SealedInputs[index].Name })
	f.q.Intent[intent].PayloadDigest = contract.Hash(preimage)
	f.q.Intent[intent].PayloadLength = uint32(len(body))
	f.q.Intent[intent].ContentLength = envelope.Core.ContentLength
	f.q.Intent[intent].InputEncoding = envelope.Core.InputEncoding
	f.q.Intent[intent].RetainedLength = envelope.Core.RetainedLength
	f.q.Context.IntentDescriptor, err = contract.CompleteApplyIntentDescriptor(f.q.Context.DomainID, f.q.Intent, f.q.Recipients)
	if err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestApplyPrivateAdmissionPinsCompleteSourcesAndRegistry(t *testing.T) {
	base := applyFixture(t, false)
	for _, name := range []string{"current-secret", "missing-source-admission", "wrong-original-file", "wrong-source-set", "wrong-authority-wrap", "wrong-authority-binding", "wrong-control-domain", "wrong-support", "wrong-route", "wrong-deadline", "plain-to-secret", "duplicate-current-binding", "generated-input"} {
		t.Run(name, func(t *testing.T) {
			f := cloneApplyFixture(t, base)
			var before []contract.MembershipRow
			routeID := f.route.CredentialRoute()
			switch name {
			case "current-secret":
				f.q.Current = []contract.CryptoCurrentSecret{{}}
			case "missing-source-admission":
				delete(f.accepted, contract.Hash(f.q.SealedInputs[1].EnvelopeBytes))
			case "wrong-original-file":
				digest := contract.Hash(f.q.SealedInputs[1].EnvelopeBytes)
				core := f.accepted[digest]
				core.FileIdentity = consumerID("unaccepted file")
				f.accepted[digest] = core
			case "wrong-source-set", "wrong-authority-wrap":
				envelope, err := contract.DecodeSealedInputEnvelope(f.q.SealedInputs[1].EnvelopeBytes)
				if err != nil {
					t.Fatal(err)
				}
				if name == "wrong-source-set" {
					envelope.Core.IntendedRecipientBindingSetDigest[0] ^= 1
				} else {
					envelope.AuthorityWrap.BindingSerial++
				}
				replaceApplySource(t, &f, 1, envelope)
			case "wrong-authority-binding":
				f.control.AuthorityKMSBinding.BindingSerial++
			case "wrong-control-domain":
				f.control.DomainID = consumerID("other domain")
			case "wrong-support":
				f.control.CryptoSupportID = consumerID("unsupported")
			case "wrong-route":
				routeID = consumerID("uninstalled")
			case "wrong-deadline":
				f.q.Context.Expiry++
			case "plain-to-secret":
				before = []contract.MembershipRow{{Name: f.q.Intent[0].Name, Slot: 17, Incarnation: consumerID("plain incarnation"), EntryDigest: consumerID("plain member"), Recipients: f.q.Intent[0].Recipients}}
			case "duplicate-current-binding":
				row := f.q.Bindings[len(f.q.Bindings)-1]
				row.Binding.BindingSerial++
				row.Binding.BindingID = consumerID("successor")
				f.q.Bindings = append(f.q.Bindings, row)
			case "generated-input":
				f.q.Intent[1].ValueSource = contract.Generated
				if _, err := contract.CompleteApplyIntentDescriptor(f.q.Context.DomainID, f.q.Intent, f.q.Recipients); err != contract.ErrCryptoMessage {
					t.Fatal("unsupported generated input obtained a canonical descriptor")
				}
			}
			r := newConsumerRuntime(t, f.route)
			if err := r.admitApply(f.q, f.control, f.current, nil, routeID, f.accepted, before, f.support, f.deadline); err == nil {
				t.Fatal("invalid private facts admitted")
			}
			if r.slot != nil || f.route.privateCalls != 0 {
				t.Fatal("admission failure retained operation or used KMS")
			}
		})
	}
}

// full_only: false
func TestApplyInvalidLaterSourceReturnsNoComparison(t *testing.T) {
	f := applyFixture(t, false)
	envelope, err := contract.DecodeSealedInputEnvelope(f.q.SealedInputs[1].EnvelopeBytes)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Ciphertext[0] ^= 1
	replaceApplySource(t, &f, 1, envelope)
	r := f.runtime(t, nil)
	body, err := contract.EncodeCryptoCompareRequest(f.q)
	if err != nil {
		t.Fatal(err)
	}
	reply := applyCall(r, context.Background(), contract.CryptoCompare, body)
	<-r.apply.done
	if reply.ResultCode != contract.CryptoSourceAuthenticationFailed || len(reply.Body) != 0 || len(reply.KeyUseRows) != 1 || reply.KeyUseRows[0].Count != 2 || reply.KeyUseRows[0].Outcome != contract.KeyUseCompleted || f.route.privateCalls != 2 {
		t.Fatalf("later invalid input hidden: %+v", reply)
	}
	if r.apply.request.SealedInputs != nil || !bytes.Equal(f.route.returned, make([]byte, len(f.route.returned))) {
		t.Fatal("failed complete input retained owners")
	}
}

// full_only: false
func TestApplyChangedAdmissionOrIdentityStopsBeforePreparation(t *testing.T) {
	base := applyFixture(t, false)
	for _, damage := range []string{"compare-context", "missing-secret-identity", "wrong-origin", "duplicate-stage", "stage-order"} {
		t.Run(damage, func(t *testing.T) {
			f := cloneApplyFixture(t, base)
			r := f.runtime(t, nil)
			if damage == "compare-context" {
				q := f.q
				q.Context.AdmissionID = consumerID("body admission")
				body, err := contract.EncodeCryptoCompareRequest(q)
				if err != nil {
					t.Fatal(err)
				}
				reply := applyCall(r, context.Background(), contract.CryptoCompare, body)
				<-r.apply.done
				if reply.ResultCode != contract.CryptoInvalidAdmission || f.route.privateCalls != 0 {
					t.Fatal("body edited admission")
				}
				return
			}
			comparison := applyCompare(t, r, f)
			var body []byte
			var err error
			kind := contract.CryptoPrepare
			switch damage {
			case "duplicate-stage":
				kind = contract.CryptoCompare
				body, err = contract.EncodeCryptoCompareRequest(f.q)
			case "stage-order":
				kind = contract.CryptoClaim
				body = []byte{1}
			default:
				plan := applyPlan(f)
				if damage == "missing-secret-identity" {
					plan.Rows = plan.Rows[:1]
				} else {
					plan.Rows[1].OriginSnapshot = consumerID("other origin")
				}
				identity, e := contract.EncodeIdentityPlan(plan)
				if e != nil {
					t.Fatal(e)
				}
				body, err = contract.EncodeCryptoPrepareRequest(contract.CryptoPrepareRequest{OperationRef: comparison.OperationRef, Context: f.q.Context, IdentityPlan: identity})
			}
			if err != nil {
				t.Fatal(err)
			}
			reply := applyCall(r, context.Background(), kind, body)
			<-r.apply.done
			if reply.ResultCode == contract.CryptoSuccess || len(reply.Body) != 0 || f.route.privateCalls != 2 || r.apply.prepared != nil {
				t.Fatal("failed stage prepared or retained usable material")
			}
		})
	}
}

// full_only: false
func TestApplyFreezeAndClaimRefuseEditedFacts(t *testing.T) {
	base := applyFixture(t, false)
	for _, damage := range []string{"member", "slot", "access-root", "support", "identity-descriptor", "prepared-descriptor", "extra-exclusion", "claim"} {
		t.Run(damage, func(t *testing.T) {
			f := cloneApplyFixture(t, base)
			r := f.runtime(t, nil)
			comparison := applyCompare(t, r, f)
			plan := applyPlan(f)
			prepared := applyPrepare(t, r, f, comparison, plan)
			freeze := applyFreezeRequest(t, f, comparison, plan, prepared)
			if damage == "identity-descriptor" {
				freeze.IdentityPlanDescriptor.Digest[0] ^= 1
			} else if damage == "prepared-descriptor" {
				freeze.CanonicalRowsDescriptor.Digest[0] ^= 1
			} else if damage == "extra-exclusion" {
				var err error
				freeze.Exclusions, err = contract.EncodeExclusions(f.q.Context.DomainID, []contract.ExclusionRow{{MembershipRow: contract.MembershipRow{Name: "old-secret", Slot: 19, Incarnation: consumerID("old incarnation"), EntryDigest: consumerID("old member"), Recipients: []contract.ID{f.control.AuthorityRecipientID}}, Path: consumerID("unsupported secret exclusion")}})
				if err != nil {
					t.Fatal(err)
				}
			} else if damage != "claim" {
				public, err := contract.DecodePublicState(freeze.CandidatePublicState, f.q.Context.DomainID)
				if err != nil {
					t.Fatal(err)
				}
				switch damage {
				case "member":
					public.Rows[0].EntryDigest[0] ^= 1
				case "slot":
					public.Rows[0].Slot = 51
				case "access-root":
					public.AccessRoot = contract.ID{}
				case "support":
					public.RequiredSupport.Digest[0] ^= 1
				}
				freeze.CandidatePublicState, err = contract.EncodePublicState(public)
				if err != nil {
					t.Fatal(err)
				}
			}
			body, err := contract.EncodeCryptoFreezeRequest(freeze)
			if err != nil {
				t.Fatal(err)
			}
			reply := applyCall(r, context.Background(), contract.CryptoFreeze, body)
			if damage == "claim" {
				if reply.ResultCode != contract.CryptoSuccess {
					t.Fatal("valid Freeze failed")
				}
				claim := r.apply.frozen
				claim.FactDigest[0] ^= 1
				body, err = contract.EncodeCryptoClaimRequest(claim)
				if err != nil {
					t.Fatal(err)
				}
				reply = applyCall(r, context.Background(), contract.CryptoClaim, body)
			}
			<-r.apply.done
			if reply.ResultCode == contract.CryptoSuccess || len(reply.Body) != 0 || f.route.privateCalls != 4 || r.apply.prepared != nil {
				t.Fatalf("edited facts remained usable: %+v", reply)
			}
		})
	}
	t.Run("unprepared-output-setting", func(t *testing.T) {
		base := exactRetainedFixture(t)
		for _, damage := range []string{"valid", "value-state", "ciphertext", "membership", "output-encoding", "slot", "digest"} {
			t.Run(damage, func(t *testing.T) {
				f := cloneApplyFixture(t, base)
				f.q.Intent[0].OutputEncoding = contract.OutputEncodingBase64
				refreshApplyIntent(t, &f)
				r := f.runtime(t, nil)
				body, err := contract.EncodeCryptoCompareRequest(f.q)
				if err != nil {
					t.Fatal(err)
				}
				reply := applyCall(r, t.Context(), contract.CryptoCompare, body)
				if reply.ResultCode != contract.CryptoSuccess {
					t.Fatal("retained output comparison", reply.ResultCode)
				}
				comparison, err := contract.DecodeCryptoCompareResult(reply.Body)
				if err != nil {
					t.Fatal(err)
				}
				plan := applyPlan(f)
				plan.Rows = nil
				prepared := applyPrepare(t, r, f, comparison, plan)
				if len(prepared.Rows) != 0 {
					t.Fatal("output-only change prepared secret material")
				}
				freeze := applyFreezeRequest(t, f, comparison, plan, prepared)
				public, err := contract.DecodePublicState(freeze.CandidatePublicState, f.q.Context.DomainID)
				if err != nil {
					t.Fatal(err)
				}
				for i, current := range f.q.Current {
					entry, err := contract.DecodeValueEntry(current.EntryBytes)
					if err != nil {
						t.Fatal(err)
					}
					if i == 0 {
						entry.OutputEncoding = contract.OutputEncodingBase64
						switch damage {
						case "value-state":
							entry.ValueState[0] ^= 1
						case "ciphertext":
							entry.ValueBytes = bytes.Clone(entry.ValueBytes)
							entry.ValueBytes[len(entry.ValueBytes)-1] ^= 1
						case "membership":
							entry.Recipients = []contract.ID{f.control.AuthorityRecipientID}
						case "output-encoding":
							entry.OutputEncoding = contract.OutputEncodingRaw
						}
					}
					slot := current.Slot
					if i == 0 && damage == "slot" {
						slot = 51
					}
					digest, err := contract.PublicValueEntryDigest(public.Domain, slot, entry)
					if err != nil {
						t.Fatal("candidate damage is not a valid public entry", err)
					}
					if i == 0 && damage == "digest" {
						digest[0] ^= 1
					}
					public.Rows = append(public.Rows, contract.PublicStateRow{Name: entry.Name, Slot: slot, EntryDigest: digest})
				}
				freeze.CandidatePublicState, err = contract.EncodePublicState(public)
				if err != nil {
					t.Fatal(err)
				}
				body, err = contract.EncodeCryptoFreezeRequest(freeze)
				if err != nil {
					t.Fatal(err)
				}
				privateCalls := f.route.privateCalls
				reply = applyCall(r, t.Context(), contract.CryptoFreeze, body)
				if damage == "valid" {
					if reply.ResultCode != contract.CryptoSuccess {
						t.Fatal("exact output-only candidate was refused", reply.ResultCode)
					}
					body, err = contract.EncodeCryptoClaimRequest(r.apply.frozen)
					if err != nil {
						t.Fatal(err)
					}
					if reply = applyCall(r, t.Context(), contract.CryptoClaim, body); reply.ResultCode != contract.CryptoSuccess {
						t.Fatal("exact output-only Claim was refused", reply.ResultCode)
					}
				} else if reply.ResultCode != contract.CryptoInvalidInput || len(reply.Body) != 0 {
					t.Fatal("forged retained output candidate was not refused", reply.ResultCode)
				}
				<-r.apply.done
				if f.route.privateCalls != privateCalls || r.apply.prepared != nil {
					t.Fatal("output-only Freeze used private keys or retained prepared material")
				}
			})
		}
	})

}

// full_only: false
func TestApplyDeadlineDiscardAndCancellationJoin(t *testing.T) {
	base := applyFixture(t, false)
	for _, stage := range []contract.CryptoKind{contract.CryptoCompare, contract.CryptoPrepare, contract.CryptoFreeze} {
		t.Run(fmt.Sprint(stage), func(t *testing.T) {
			f := cloneApplyFixture(t, base)
			f.deadline = time.Now().Add(time.Second)
			f.q.Context.Expiry = uint64(f.deadline.UnixNano())
			r := f.runtime(t, nil)
			comparison := applyCompare(t, r, f)
			if stage >= contract.CryptoPrepare {
				plan := applyPlan(f)
				prepared := applyPrepare(t, r, f, comparison, plan)
				if stage == contract.CryptoFreeze {
					freeze := applyFreezeRequest(t, f, comparison, plan, prepared)
					body, err := contract.EncodeCryptoFreezeRequest(freeze)
					if err != nil {
						t.Fatal(err)
					}
					if reply := applyCall(r, context.Background(), contract.CryptoFreeze, body); reply.ResultCode != contract.CryptoSuccess {
						t.Fatal("Freeze failed")
					}
				}
			}
			select {
			case <-r.apply.done:
			case <-time.After(2 * time.Second):
				t.Fatal("abandoned apply did not expire")
			}
			if r.apply.request.SealedInputs != nil || r.apply.prepared != nil || r.apply.sealedInputCores != nil {
				t.Fatal("expiry retained encrypted work")
			}
		})
	}
	t.Run("discard", func(t *testing.T) {
		f := cloneApplyFixture(t, base)
		r := f.runtime(t, nil)
		comparison := applyCompare(t, r, f)
		body, err := contract.EncodeCryptoDiscardRequest(contract.CryptoDiscardRequest{OperationRef: comparison.OperationRef, Context: f.q.Context})
		if err != nil {
			t.Fatal(err)
		}
		reply := applyCall(r, context.Background(), contract.CryptoDiscard, body)
		<-r.apply.done
		if reply.ResultCode != contract.CryptoSuccess || len(reply.Body) != 0 || r.apply.request.SealedInputs != nil {
			t.Fatal("Discard did not release Compared")
		}
	})
	t.Run("cancelled-entry", func(t *testing.T) {
		f := cloneApplyFixture(t, base)
		r := f.runtime(t, nil)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		body, err := contract.EncodeCryptoCompareRequest(f.q)
		if err != nil {
			t.Fatal(err)
		}
		reply := applyCall(r, ctx, contract.CryptoCompare, body)
		<-r.apply.done
		if reply.ResultCode != contract.CryptoCancelled || len(reply.Body) != 0 || len(reply.KeyUseRows) != 0 || f.route.privateCalls != 0 {
			t.Fatal("cancelled Compare entered KMS")
		}
	})
	t.Run("concurrent-cancel-close", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := cloneApplyFixture(t, base)
			release := make(chan struct{})
			f.route.started = make(chan struct{})
			f.route.release = release
			r := f.runtime(t, nil)
			released := false
			t.Cleanup(func() {
				if !released {
					close(release)
				}
			})
			body, err := contract.EncodeCryptoCompareRequest(f.q)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan contract.CryptoResponse, 1)
			go func() { done <- applyCall(r, ctx, contract.CryptoCompare, body) }()
			<-f.route.started
			if reply := applyCall(r, context.Background(), contract.CryptoCompare, body); reply.ResultCode != contract.CryptoAlreadyUsed {
				t.Fatal("overlapping Compare accepted twice")
			}
			cancel()
			closed := make(chan struct{})
			go func() { r.Close(); close(closed) }()
			synctest.Wait()
			select {
			case <-closed:
				t.Fatal("Close did not join accepted private call")
			default:
			}
			close(release)
			released = true
			reply := <-done
			<-closed
			if reply.ResultCode != contract.CryptoCancelled || len(reply.Body) != 0 || len(reply.KeyUseRows) != 1 || reply.KeyUseRows[0].Outcome != contract.KeyUseCompleted || reply.KeyUseRows[0].Count != 1 || r.apply.request.SealedInputs != nil {
				t.Fatal("cancelled private call lost evidence or retained work")
			}
		})
	})
}

// full_only: false
func TestApplyRawAggregateBeforePrivateCalls(t *testing.T) {
	f := applyFixture(t, false)
	template := f.accepted[contract.Hash(f.q.SealedInputs[0].EnvelopeBytes)]
	authority := f.q.Bindings[applyBindingIndex(f.q.Bindings, f.control.AuthorityRecipientID)]
	recipients := f.q.Intent[0].Recipients
	f.q.Intent = nil
	f.q.SealedInputs = nil
	f.accepted = make(map[contract.ID]contract.SealedInputCore)
	plain := make([]byte, contract.CryptoMaxRawValue)
	defer clear(plain)
	for i := 0; i < 128; i++ {
		core := template
		core.Name = fmt.Sprintf("s%03d", i)
		core.SourceID = consumerID(core.Name)
		core.DataKeyID = consumerID(core.Name + " data")
		core.ContentLength = contract.CryptoMaxRawValue
		core.RetainedLength = contract.CryptoMaxRawValue
		envelope, err := custody.SealInput(core, authority, plain)
		if err != nil {
			t.Fatal(err)
		}
		body, err := contract.EncodeSealedInputEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		preimage := append([]byte("ENKV/SEALED-INPUT/v1\x00"), binary.BigEndian.AppendUint32(nil, uint32(len(body)))...)
		preimage = append(preimage, body...)
		f.q.SealedInputs = append(f.q.SealedInputs, contract.CryptoSealedInput{Name: core.Name, EnvelopeBytes: body})
		f.q.Intent = append(f.q.Intent, contract.CryptoIntentRow{Name: core.Name, Recipients: recipients, ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret, ContentLength: core.ContentLength, PayloadDigest: contract.Hash(preimage), PayloadLength: uint32(len(body)), InputEncoding: contract.InputEncodingRaw, RetainedLength: core.ContentLength, OutputEncoding: contract.OutputEncodingRaw})
		f.accepted[contract.Hash(body)] = core
	}
	var err error
	f.q.Context.IntentDescriptor, err = contract.CompleteApplyIntentDescriptor(f.q.Context.DomainID, f.q.Intent, f.q.Recipients)
	if err != nil {
		t.Fatal(err)
	}
	r := f.runtime(t, nil)
	if f.route.privateCalls != 0 {
		t.Fatal("maximum admission entered KMS")
	}
	r.Close()
	extra := f.q.Intent[127]
	extra.Name = "s128"
	f.q.Intent = append(f.q.Intent, extra)
	if _, err := contract.CompleteApplyIntentDescriptor(f.q.Context.DomainID, f.q.Intent, f.q.Recipients); err != contract.ErrCryptoCapacity {
		t.Fatal("test did not cross raw aggregate bound")
	}
	other := newConsumerRuntime(t, f.route)
	if err := other.admitApply(f.q, f.control, f.current, nil, f.route.CredentialRoute(), f.accepted, nil, f.support, f.deadline); err == nil || f.route.privateCalls != 0 {
		t.Fatal("over-limit complete input entered KMS")
	}
}

// full_only: false
func TestApplyFreezePreservesAdmittedReceiptDescriptor(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		base := applyFixture(t, recovery)
		receipt := contract.CompactMutationReceipt{Schema: contract.MutationReceiptSchema, OperationKind: 2, DomainID: base.q.Context.DomainID,
			OperationID:           consumerID("receipt operation"),
			RequestIdentityDigest: consumerID("receipt identity"), PredecessorRevisionID: consumerID("receipt predecessor"),
			RequestedRevisionID: consumerID("receipt selected"), ObservedRevisionID: consumerID("receipt selected"), StateResult: 1, EvidenceCeiling: 1, CanonicalOutcome: 1,
			ChangedSubjects: contract.GeneratorDescriptor{Digest: consumerID("receipt subjects"), Length: 42, Count: 1},
			CompleteResult:  contract.GeneratorDescriptor{Digest: consumerID("receipt result"), Length: 8 + contract.MutationResultProjectionLength, Count: 1}}
		body, err := contract.EncodeCompactMutationReceipt(receipt)
		if err != nil {
			t.Fatal(err)
		}
		base.support, err = contract.RequiredSupportDescriptor(base.q.Context.DomainID, []contract.SupportRecord{{Kind: 7, RecordID: receipt.OperationID, Body: body}})
		if err != nil {
			t.Fatal(err)
		}
		for _, damage := range []string{"none", "omit", "change"} {
			t.Run(damage, func(t *testing.T) {
				f := cloneApplyFixture(t, base)
				r := f.runtime(t, nil)
				comparison := applyCompare(t, r, f)
				plan := applyPlan(f)
				prepared := applyPrepare(t, r, f, comparison, plan)
				freeze := applyFreezeRequest(t, f, comparison, plan, prepared)
				public, err := contract.DecodePublicState(freeze.CandidatePublicState, f.q.Context.DomainID)
				if err != nil {
					t.Fatal(err)
				}
				switch damage {
				case "omit":
					public.RequiredSupport, err = contract.EmptyRequiredSupportDescriptor(f.q.Context.DomainID)
					if err != nil {
						t.Fatal(err)
					}
				case "change":
					public.RequiredSupport.Digest[0] ^= 1
				}
				freeze.CandidatePublicState, err = contract.EncodePublicState(public)
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := contract.EncodeCryptoFreezeRequest(freeze)
				if err != nil {
					t.Fatal(err)
				}
				reply := applyCall(r, context.Background(), contract.CryptoFreeze, encoded)
				want := contract.CryptoInvalidInput
				if damage == "none" {
					want = contract.CryptoSuccess
				}
				if reply.ResultCode != want {
					t.Fatal("receipt projection freeze", reply.ResultCode, want)
				}
			})
		}
	}
}

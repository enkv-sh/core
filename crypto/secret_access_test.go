package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/internal/custody"
)

func secretAccessFixture(t *testing.T, base applyTestFixture, operation uint16) applyTestFixture {
	t.Helper()
	f := cloneApplyFixture(t, base)
	entry, err := contract.DecodeValueEntry(f.q.Current[0].EntryBytes)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := contract.PublicValueEntryDigest(f.q.Context.DomainID, f.q.Current[0].Slot, entry)
	if err != nil {
		t.Fatal(err)
	}
	f.q.SecretAccess = &contract.CryptoSecretAccessIntent{OperationKind: operation, Target: contract.SecretAccessTarget{Slot: f.q.Current[0].Slot, Name: entry.Name, Incarnation: entry.Incarnation, Material: entry.ValueState, BeforePublicEntryDigest: digest}}
	refreshSecretAccessIntent(t, &f)
	return f
}

func refreshSecretAccessIntent(t *testing.T, f *applyTestFixture) {
	t.Helper()
	var err error
	f.q.Context.IntentDescriptor, err = contract.SecretAccessIntentDescriptor(f.q.Context.DomainID, f.q.Intent, f.q.Recipients, *f.q.SecretAccess)
	if err != nil {
		t.Fatal(err)
	}
}

func secretAccessWitness(t *testing.T, f *applyTestFixture) *contract.GeneratedSupportTransition {
	t.Helper()
	ref, err := contract.DecodeRef(f.q.Context.PredecessorRootRef[:], contract.CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	w := &contract.GeneratedSupportTransition{Schema: 1, DomainID: f.q.Context.DomainID, BeforeSnapshot: ref.Object, BeforeSliceSnapshot: ref.Object, BeforeRootDigest: ref.Digest, BeforeSupport: f.support}
	for _, row := range f.q.Current {
		access, err := contract.DecodeAccessRecord(row.AccessRecord)
		if err != nil {
			t.Fatal(err)
		}
		w.AccessRecords = append(w.AccessRecords, access)
	}
	slices.SortFunc(w.AccessRecords, func(a, b contract.AccessRecord) int { return bytes.Compare(a.MaterialID[:], b.MaterialID[:]) })
	for i, row := range w.AccessRecords {
		readers := contract.GeneratedSupportReaders{Access: uint32(i)}
		for _, wrap := range row.Wraps {
			binding := contract.RecipientBindingReference{RecipientID: wrap.SubjectID, PublicBindingDigest: wrap.PublicBindingDigest}
			if wrap.SubjectKind == contract.RecoveryWrapSubject {
				readers.Recovery = &binding
			} else {
				readers.Current = append(readers.Current, wrap.SubjectID)
				readers.Bindings = append(readers.Bindings, binding)
			}
		}
		w.Readers = append(w.Readers, readers)
	}
	recipients, err := contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: w.DomainID, Refs: []contract.Ref{{Kind: contract.RecipientKind, Format: contract.CanonicalSchema, Domain: w.DomainID, Object: consumerID("secret access recipient page"), Digest: consumerID("secret access recipient page digest"), Length: 1024}}})
	if err != nil {
		t.Fatal(err)
	}
	access, err := contract.AccessRecordsDescriptor(w.DomainID, w.AccessRecords)
	if err != nil {
		t.Fatal(err)
	}
	w.BeforeAccess = contract.CurrentAccessCore{CurrentControl: f.control.CurrentControl, RecipientRefsDescriptor: recipients, AccessRecordsDescriptor: access}
	length := contract.AccessPageHeaderLength
	for _, row := range w.AccessRecords {
		n, err := contract.AccessRecordLength(row)
		if err != nil {
			t.Fatal(err)
		}
		length += n
	}
	if len(w.AccessRecords) != 0 {
		w.BeforeAccess.AccessPageRefs = []contract.Ref{{Kind: contract.AccessKind, Format: contract.CanonicalSchema, Domain: w.DomainID, Object: consumerID("secret access current access page"), Digest: consumerID("secret access current access digest"), Length: uint32(length)}}
	}
	f.q.Context.CurrentAccessRoot, err = contract.AccessRoot(w.BeforeAccess)
	if err != nil || w.Inspect() != nil {
		t.Fatal("secret access witness", err)
	}
	return w
}

func secretAccessOwner(t *testing.T, f *applyTestFixture, plain []contract.MembershipRow) (*Runtime, *ApplyCustody) {
	t.Helper()
	ctx, cancel := context.WithDeadline(t.Context(), f.deadline)
	t.Cleanup(cancel)
	f.ctx = ctx
	w := secretAccessWitness(t, f)
	r := newConsumerRuntime(t, f.route)
	owner, err := NewEnvelopeRekeyCustody(r, f.q, f.control, f.current, f.route.CredentialRoute(), plain, f.support, w, consumerID("secret access predecessor revision"), contract.MutationReceiptWindows{DomainID: f.q.Context.DomainID}, 0, f.deadline)
	if err != nil {
		t.Fatal("secret access custody", err)
	}
	t.Cleanup(owner.Close)
	return r, owner
}

func secretAccessFreeze(t *testing.T, f applyTestFixture, a *applyAdmission, comparison contract.CryptoCompareResult, plan contract.IdentityPlan, prepared contract.CryptoPrepareResult) contract.CryptoFreezeRequest {
	t.Helper()
	var plain []contract.PublicStateRow
	for _, row := range a.plainBefore {
		plain = append(plain, contract.PublicStateRow{Name: row.Name, Slot: row.Slot, EntryDigest: row.EntryDigest})
	}
	return accessMutationFreeze(t, f, a, comparison, plan, prepared, plain, nil)
}

func accessMutationFreeze(t *testing.T, f applyTestFixture, a *applyAdmission, comparison contract.CryptoCompareResult, plan contract.IdentityPlan, prepared contract.CryptoPrepareResult, plain []contract.PublicStateRow, exclusions []contract.ExclusionRow) contract.CryptoFreezeRequest {
	t.Helper()
	public := contract.PublicState{Domain: f.q.Context.DomainID, RequiredSupport: f.support}
	for _, current := range f.q.Current {
		entry, err := contract.DecodeValueEntry(current.EntryBytes)
		if err != nil {
			t.Fatal(err)
		}
		slot := current.Slot
		if i := slices.IndexFunc(prepared.Rows, func(row contract.CryptoPreparedSecret) bool { return row.Name == entry.Name }); i >= 0 {
			entry, err = contract.DecodeValueEntry(prepared.Rows[i].EntryBytes)
			if err != nil {
				t.Fatal(err)
			}
			slot = prepared.Rows[i].Slot
		}
		digest, err := contract.PublicValueEntryDigest(public.Domain, slot, entry)
		if err != nil {
			t.Fatal(err)
		}
		public.Rows = append(public.Rows, contract.PublicStateRow{Name: entry.Name, Slot: slot, EntryDigest: digest})
	}
	public.Rows = append(public.Rows, plain...)
	slices.SortFunc(public.Rows, func(a, b contract.PublicStateRow) int { return bytes.Compare([]byte(a.Name), []byte(b.Name)) })
	access, err := a.supportTransition.AccessAfter(f.q.Intent, f.q.Current, prepared.Rows)
	if err != nil {
		t.Fatal(err)
	}
	core, _, err := a.supportTransition.AccessCoreAfter(access, plan)
	if err != nil {
		t.Fatal(err)
	}
	if f.q.Retirement != nil {
		_, refs, err := format.ApplyRecipientPages(f.q.Context.DomainID, applyProposedRecipients(f.q), plan)
		if err != nil {
			t.Fatal(err)
		}
		core.RecipientRefsDescriptor, err = contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: f.q.Context.DomainID, Refs: refs})
		if err != nil {
			t.Fatal(err)
		}
		if core.AccessRecordsDescriptor == a.supportTransition.BeforeAccess.AccessRecordsDescriptor {
			if err := contract.AdvanceAccessGeneration(&core, plan.Transition); err != nil {
				t.Fatal(err)
			}
		}
		if core.AccessGeneration != a.supportTransition.BeforeAccess.AccessGeneration+1 {
			t.Fatal("recipient retirement did not advance access generation exactly once")
		}
	}
	public.AccessRoot, err = contract.AccessRoot(core)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := contract.IdentityPlanDescriptor(plan)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := contract.CryptoPreparedRowsDescriptor(prepared.Rows)
	if err != nil {
		t.Fatal(err)
	}
	exclusion, err := contract.EncodeExclusions(public.Domain, exclusions)
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodePublicState(public)
	if err != nil {
		t.Fatal(err)
	}
	return contract.CryptoFreezeRequest{OperationRef: comparison.OperationRef, Context: f.q.Context, IdentityPlanDescriptor: identity, CanonicalRowsDescriptor: canonical, CandidatePublicState: body, Exclusions: exclusion, Recipients: applyProposedRecipients(f.q)}
}

func secretAccessCompare(t *testing.T, r *Runtime, f applyTestFixture) contract.CryptoCompareResult {
	t.Helper()
	body, err := contract.EncodeCryptoCompareRequest(f.q)
	if err != nil {
		t.Fatal(err)
	}
	reply := applyCall(r, t.Context(), contract.CryptoCompare, body)
	authority := f.q.Bindings[applyBindingIndex(f.q.Bindings, f.control.AuthorityRecipientID)]
	wantUses := []contract.KeyUseRow{independentKeyUseRow(authority, contract.KeyUseMaterialOpen, contract.KeyUseCompleted, 1)}
	if reply.ResultCode != contract.CryptoSuccess || !slices.Equal(reply.KeyUseRows, wantUses) {
		t.Fatal("secret access comparison or exact private-use facts", reply.ResultCode, reply.KeyUseRows)
	}
	comparison, err := contract.DecodeCryptoCompareResult(reply.Body)
	if err != nil || len(comparison.Rows) != 1 {
		t.Fatal("secret access returned unrelated comparison rows", err)
	}
	row := comparison.Rows[0]
	target := f.q.SecretAccess.Target
	if row.Name != target.Name || !row.BeforePresent || !row.AfterPresent || row.Relation != contract.CryptoEqual || row.BeforePublicEntryDigest != target.BeforePublicEntryDigest || row.SourceDigest != f.q.Intent[0].PayloadDigest || row.AfterRawLength != f.q.Intent[0].ContentLength || !row.ExclusionPathDigest.IsZero() {
		t.Fatal("secret access comparison changed target identity or plaintext relation", row)
	}
	return comparison
}

func secretAccessPlan(f applyTestFixture) contract.IdentityPlan {
	target := f.q.SecretAccess.Target
	plan := contract.IdentityPlan{Operation: consumerID("secret access operation"), Transition: consumerID("secret access transition"), Snapshot: consumerID("secret access snapshot"), Revision: consumerID("secret access revision")}
	plan.Rows = []contract.IdentityRow{{Name: target.Name, Slot: target.Slot, Incarnation: target.Incarnation, ValueState: consumerID("secret access fresh material"), OriginSnapshot: plan.Snapshot, OriginTransition: plan.Transition}}
	plan.Pages = []contract.IdentityPage{{Kind: contract.AccessKind, Index: 0, Object: consumerID("secret access fresh access page")}}
	return plan
}

func secretAccessPrepare(t *testing.T, r *Runtime, f applyTestFixture, comparison contract.CryptoCompareResult, plan contract.IdentityPlan) contract.CryptoPrepareResult {
	t.Helper()
	identity, err := contract.EncodeIdentityPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeCryptoPrepareRequest(contract.CryptoPrepareRequest{OperationRef: comparison.OperationRef, Context: f.q.Context, IdentityPlan: identity})
	if err != nil {
		t.Fatal(err)
	}
	reply := applyCall(r, t.Context(), contract.CryptoPrepare, body)
	expected := []contract.KeyUseRow{independentKeyUseRow(f.q.Bindings[applyBindingIndex(f.q.Bindings, f.control.AuthorityRecipientID)], contract.KeyUseMaterialOpen, contract.KeyUseCompleted, 1)}
	for _, binding := range f.q.Bindings {
		if binding.SubjectKind == contract.RecoveryWrapSubject || slices.Contains(f.q.Intent[0].Recipients, binding.SubjectID) {
			expected = append(expected, independentKeyUseRow(binding, contract.KeyUseMaterialWrap, contract.KeyUseCompleted, 1))
		}
	}
	if reply.ResultCode != contract.CryptoSuccess || len(reply.KeyUseRows) != len(expected) {
		t.Fatal("secret access preparation failed or key-use count differs", reply.ResultCode, reply.KeyUseRows)
	}
	for _, row := range expected {
		if !slices.Contains(reply.KeyUseRows, row) {
			t.Fatal("secret access preparation omitted exact key use", row, reply.KeyUseRows)
		}
	}
	prepared, err := contract.DecodeCryptoPrepareResult(reply.Body)
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

// full_only: false
func TestSecretAccessComparesOnlyTargetAndRefreshesEqualMaterial(t *testing.T) {
	base := exactRetainedFixture(t)
	for _, kind := range []uint16{contract.OperationEnvelopeRekey} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			f := secretAccessFixture(t, base, kind)
			// Public current validation remains complete, but this unrelated
			// ciphertext must not cause a private authentication attempt.
			entry, err := contract.DecodeValueEntry(f.q.Current[1].EntryBytes)
			if err != nil {
				t.Fatal(err)
			}
			entry.ValueBytes[len(entry.ValueBytes)-1] ^= 1
			f.q.Current[1].EntryBytes, err = contract.EncodeValueEntry(entry)
			if err != nil {
				t.Fatal(err)
			}
			f.q.Intent[1].PayloadDigest = contract.Hash(entry.ValueBytes)
			refreshSecretAccessIntent(t, &f)
			r, _ := secretAccessOwner(t, &f, nil)
			comparison := secretAccessCompare(t, r, f)
			plan := secretAccessPlan(f)
			prepared := secretAccessPrepare(t, r, f, comparison, plan)
			if len(prepared.Rows) != 1 || prepared.Rows[0].Name != f.q.SecretAccess.Target.Name {
				t.Fatal("secret access prepared unrelated material")
			}
			before, err := contract.DecodeValueEntry(f.q.Current[0].EntryBytes)
			if err != nil {
				t.Fatal(err)
			}
			after, err := contract.DecodeValueEntry(prepared.Rows[0].EntryBytes)
			if err != nil {
				t.Fatal(err)
			}
			oldPayload, _ := contract.DecodeCanonicalPayload(before.ValueBytes)
			payload, err := contract.DecodeCanonicalPayload(after.ValueBytes)
			if err != nil || after.Incarnation != before.Incarnation || after.ValueState != plan.Rows[0].ValueState || after.OriginSnapshot != plan.Snapshot || after.OriginTransition != plan.Transition || payload.DataKeyID == oldPayload.DataKeyID || payload.CommitmentKeyID == oldPayload.CommitmentKeyID || payload.SemanticCommitment == oldPayload.SemanticCommitment || bytes.Equal(after.ValueBytes, before.ValueBytes) || !slices.Equal(after.Recipients, f.q.Intent[0].Recipients) {
				t.Fatal("equal target did not receive fresh independent envelope material", err)
			}
			access, err := contract.DecodeAccessRecord(prepared.Rows[0].AccessRecord)
			if err != nil {
				t.Fatal(err)
			}
			core, err := contract.ValueCoreForEntry(f.q.Context.DomainID, f.q.Context.CompatibilityID, after)
			if err != nil {
				t.Fatal(err)
			}
			for _, wrap := range access.Wraps {
				packet, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, f.keys[wrap.SubjectID], wrap.RSACiphertext, nil)
				if err != nil {
					t.Fatal(err)
				}
				binding := slices.IndexFunc(f.q.Bindings, func(row contract.BindingTableRow) bool {
					return row.SubjectKind == wrap.SubjectKind && row.SubjectID == wrap.SubjectID
				})
				wc, err := custody.ValueWrapCore(core, f.q.Bindings[binding])
				if err != nil {
					t.Fatal(err)
				}
				digest, _ := contract.RSAPacketContextDigest(wc)
				keys, err := custody.PacketKeys(packet, 1, digest)
				if err != nil {
					t.Fatal(err)
				}
				plain, err := custody.OpenValue(core, payload, keys)
				equal := bytes.Equal(plain, []byte("first secret"))
				clear(plain)
				clear(packet)
				if err != nil || !equal {
					t.Fatal("target plaintext changed during envelope refresh", err)
				}
			}
			if f.route.privateCalls != 2 {
				t.Fatal("standalone work opened unrelated or repeated material", f.route.privateCalls)
			}
		})
	}
}

// full_only: false
func TestSecretAccessAdmissionRejectsTargetAndUnrelatedChanges(t *testing.T) {
	base := exactRetainedFixture(t)
	for _, damage := range []string{"slot", "name", "incarnation", "material", "digest", "kind", "display", "proof", "unrelated-readers", "unrelated-input", "authority", "sealed-input"} {
		t.Run(damage, func(t *testing.T) {
			f := secretAccessFixture(t, base, contract.OperationEnvelopeRekey)
			w := secretAccessWitness(t, &f)
			switch damage {
			case "slot":
				f.q.SecretAccess.Target.Slot++
			case "name":
				f.q.SecretAccess.Target.Name = "absent"
			case "incarnation":
				f.q.SecretAccess.Target.Incarnation[0] ^= 1
			case "material":
				f.q.SecretAccess.Target.Material[0] ^= 1
			case "digest":
				f.q.SecretAccess.Target.BeforePublicEntryDigest[0] ^= 1
			case "kind":
				f.q.SecretAccess.OperationKind = contract.OperationRemoveSecretValueEntryAccess
				f.q.SecretAccess.RemovedRecipients = []contract.ID{f.q.Intent[0].Recipients[0]}
			case "display":
				f.q.Recipients[0].Recipient.DisplayName += " changed"
			case "proof":
				f.q.Recipients[0].Creation = &contract.RecipientCreationProof{Snapshot: consumerID("unused proof"), Nonce: consumerID("unused nonce")}
			case "unrelated-readers":
				f.q.Intent[1].Recipients = []contract.ID{f.control.AuthorityRecipientID}
			case "unrelated-input":
				f.q.Intent[1].PayloadDigest[0] ^= 1
			case "authority":
				f.q.SecretAccess.RemovedRecipients = []contract.ID{f.control.AuthorityRecipientID}
			case "sealed-input":
				f.q.SealedInputs = []contract.CryptoSealedInput{{Name: "alpha"}}
			}
			if damage != "proof" && damage != "authority" {
				refreshSecretAccessIntent(t, &f)
			}
			f.route.override = func(context.Context, contract.KMSBinding, []byte, uint16) PrivateResult {
				t.Fatal("invalid standalone target or unrelated change used a private key")
				return PrivateResult{}
			}
			r := newConsumerRuntime(t, f.route)
			owner, err := NewEnvelopeRekeyCustody(r, f.q, f.control, f.current, f.route.CredentialRoute(), nil, f.support, w, consumerID("revision"), contract.MutationReceiptWindows{DomainID: f.q.Context.DomainID}, 0, f.deadline)
			if err != ErrAdmission || owner != nil || r.apply != nil {
				t.Fatal("standalone invalid target or unrelated edit admitted", err)
			}
		})
	}
}

// full_only: false
func TestSecretAccessPreparationRequiresOnlyFreshTarget(t *testing.T) {
	base := exactRetainedFixture(t)
	for _, damage := range []string{"missing", "extra", "other", "incarnation", "old-material", "old-origin"} {
		t.Run(damage, func(t *testing.T) {
			f := secretAccessFixture(t, base, contract.OperationEnvelopeRekey)
			r, _ := secretAccessOwner(t, &f, nil)
			comparison := secretAccessCompare(t, r, f)
			plan := secretAccessPlan(f)
			switch damage {
			case "missing":
				plan.Rows = nil
			case "extra":
				row := applyPlan(f).Rows[1]
				row.ValueState = consumerID("unrelated fresh material")
				row.OriginSnapshot, row.OriginTransition = plan.Snapshot, plan.Transition
				plan.Rows = append(plan.Rows, row)
			case "other":
				plan.Rows[0].Name = f.q.Intent[1].Name
			case "incarnation":
				plan.Rows[0].Incarnation[0] ^= 1
			case "old-material":
				plan.Rows[0].ValueState = f.q.SecretAccess.Target.Material
			case "old-origin":
				entry, err := contract.DecodeValueEntry(f.q.Current[0].EntryBytes)
				if err != nil {
					t.Fatal(err)
				}
				plan.Transition = entry.OriginTransition
				plan.Rows[0].OriginTransition = plan.Transition
			}
			identity, err := contract.EncodeIdentityPlan(plan)
			if err != nil {
				t.Fatal("plan mutation is not structurally valid", err)
			}
			body, err := contract.EncodeCryptoPrepareRequest(contract.CryptoPrepareRequest{OperationRef: comparison.OperationRef, Context: f.q.Context, IdentityPlan: identity})
			if err != nil {
				t.Fatal(err)
			}
			reply := applyCall(r, t.Context(), contract.CryptoPrepare, body)
			if reply.ResultCode != contract.CryptoInvalidInput || len(reply.KeyUseRows) != 0 || f.route.privateCalls != 1 {
				t.Fatal("invalid standalone freshness reached private preparation", reply.ResultCode, reply.KeyUseRows)
			}
		})
	}
}

// full_only: false
func TestSecretAccessFreezePinsUntouchedPublicState(t *testing.T) {
	base := exactRetainedFixture(t)
	for _, damage := range []string{"exact", "untouched-secret", "untouched-plain", "registry", "target-context"} {
		t.Run(damage, func(t *testing.T) {
			f := secretAccessFixture(t, base, contract.OperationEnvelopeRekey)
			plain := contract.MembershipRow{Name: "plain", Slot: 2, Incarnation: consumerID("unchanged plain incarnation"), EntryDigest: consumerID("unchanged plain public digest"), Recipients: []contract.ID{f.control.AuthorityRecipientID}}
			f.q.Intent = append(f.q.Intent, contract.CryptoIntentRow{Name: plain.Name, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, ContentLength: 3, PayloadLength: 3, PayloadDigest: contract.Hash([]byte("old")), Recipients: slices.Clone(plain.Recipients), InputEncoding: contract.InputEncodingRaw, RetainedLength: 3, OutputEncoding: contract.OutputEncodingRaw})
			refreshSecretAccessIntent(t, &f)
			r, owner := secretAccessOwner(t, &f, []contract.MembershipRow{plain})
			comparison := secretAccessCompare(t, r, f)
			plan := secretAccessPlan(f)
			prepared := secretAccessPrepare(t, r, f, comparison, plan)
			q := secretAccessFreeze(t, f, r.apply, comparison, plan, prepared)
			view, err := contract.InspectPublicState(q.CandidatePublicState, f.q.Context.DomainID)
			if err != nil {
				t.Fatal(err)
			}
			public, err := view.Own()
			if err != nil {
				t.Fatal(err)
			}
			switch damage {
			case "untouched-secret":
				public.Rows[1].EntryDigest[0] ^= 1
			case "untouched-plain":
				public.Rows[2].EntryDigest[0] ^= 1
			case "registry":
				q.Recipients[0].DisplayName += " changed"
			case "target-context":
				q.Context.IntentDescriptor.Digest[0] ^= 1
			}
			q.CandidatePublicState, err = contract.EncodePublicState(public)
			if err != nil {
				t.Fatal(err)
			}
			row := receiptHistoryRow(f.q.Context.DomainID, "standalone selected", true)
			row.OperationKind, row.EffectSummary = contract.OperationEnvelopeRekey, contract.ReceiptEffectNotApplicable
			row.OperationID, row.PredecessorRevisionID = plan.Operation, owner.predecessorRevision
			row.RequestedRevisionID, row.ObservedRevisionID, row.ChangedSubjects = plan.Revision, plan.Revision, secretAccessExpectedSubjects(t, f)
			receipt, q := secretAccessReceiptAdmission(t, f, owner, comparison, q, row)
			if err := owner.BindReceipt(f.ctx, receipt); err != nil {
				t.Fatal("exact receipt for candidate under test", err)
			}
			body, err := contract.EncodeCryptoFreezeRequest(q)
			if err != nil {
				t.Fatal(err)
			}
			reply := applyCall(r, t.Context(), contract.CryptoFreeze, body)
			if (reply.ResultCode == contract.CryptoSuccess) != (damage == "exact") || len(reply.KeyUseRows) != 0 || f.route.privateCalls != 2 {
				t.Fatal("standalone freeze changed authenticated untouched state", reply.ResultCode, reply.KeyUseRows)
			}
		})
	}
}

// full_only: false
func TestSecretAccessScopeIsOwnedAndCheckedBeforePrivateOpen(t *testing.T) {
	base := exactRetainedFixture(t)
	for _, damage := range []string{"owned", "exchange", "direct-open", "ordinary-factory"} {
		t.Run(damage, func(t *testing.T) {
			f := secretAccessFixture(t, base, contract.OperationEnvelopeRekey)
			if damage == "ordinary-factory" {
				w := secretAccessWitness(t, &f)
				r := newConsumerRuntime(t, f.route)
				before := contract.MutationReceiptWindows{DomainID: f.q.Context.DomainID}
				var err error
				_, err = NewApplyCustody(r, f.q, f.control, f.current, nil, f.route.CredentialRoute(), consumerID("source file"), nil, f.support, w, consumerID("revision"), before, 0, f.deadline)
				if err != ErrAdmission || r.apply != nil || f.route.privateCalls != 0 {
					t.Fatal("operation entered a different static factory", err)
				}
				return
			}
			r, _ := secretAccessOwner(t, &f, nil)
			if damage == "direct-open" {
				current, ok := r.apply.current(r.apply.request.Current[1])
				if !ok {
					t.Fatal("unrelated current fixture is invalid")
				}
				reply := contract.CryptoResponse{Kind: contract.CryptoCompare}
				keys, code := r.apply.openCurrent(t.Context(), f.route, current, &reply)
				if code != contract.CryptoInvalidAdmission || keys != nil || len(reply.KeyUseRows) != 0 || f.route.privateCalls != 0 {
					t.Fatal("private consuming boundary accepted unrelated current material", code)
				}
				return
			}
			original := r.apply.request.SecretAccess.Target
			f.q.SecretAccess.Target.Material[0] ^= 1
			if r.apply.request.SecretAccess.Target != original {
				t.Fatal("caller mutation changed installed target")
			}
			if damage == "owned" {
				f.q.SecretAccess = r.apply.request.SecretAccess
				secretAccessCompare(t, r, f)
				return
			}
			refreshSecretAccessIntent(t, &f)
			body, err := contract.EncodeCryptoCompareRequest(f.q)
			if err != nil {
				t.Fatal(err)
			}
			reply := applyCall(r, t.Context(), contract.CryptoCompare, body)
			if reply.ResultCode != contract.CryptoInvalidAdmission || len(reply.KeyUseRows) != 0 || f.route.privateCalls != 0 {
				t.Fatal("Compare substituted admitted typed target", reply.ResultCode)
			}
		})
	}
}

func secretAccessExpectedSubjects(t *testing.T, f applyTestFixture) contract.GeneratorDescriptor {
	t.Helper()
	target := f.q.SecretAccess.Target
	entryID, err := contract.ChangedSubjectIdentityID(f.q.Context.DomainID, contract.ChangedSubjectValueEntry, target.Incarnation, contract.ID{})
	if err != nil {
		t.Fatal(err)
	}
	rows := []contract.ChangedSubjectIdentity{{Kind: contract.ChangedSubjectValueEntry, Change: contract.ChangedSubjectUpdated, Identity: entryID}}
	for _, removed := range f.q.SecretAccess.RemovedRecipients {
		id, err := contract.ChangedSubjectIdentityID(f.q.Context.DomainID, contract.ChangedSubjectMembership, target.Incarnation, removed)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, contract.ChangedSubjectIdentity{Kind: contract.ChangedSubjectMembership, Change: contract.ChangedSubjectRemoved, Identity: id})
	}
	subjects, err := contract.ChangedSubjectDescriptor(rows)
	if err != nil {
		t.Fatal(err)
	}
	return subjects
}

func secretAccessReceiptAdmission(t *testing.T, f applyTestFixture, owner *ApplyCustody, comparison contract.CryptoCompareResult, freeze contract.CryptoFreezeRequest, row contract.CompactMutationReceipt) (contract.CryptoApplyReceiptAdmission, contract.CryptoFreezeRequest) {
	t.Helper()
	after, err := contract.AppendMutationReceipt(owner.before, row)
	if err != nil {
		t.Fatal("standalone receipt fixture", err)
	}
	records, err := after.SupportRecords()
	if err != nil {
		t.Fatal(err)
	}
	records = append([]contract.SupportRecord{installedReceiptIndexRecord(t, after)}, records...)
	support, err := contract.RequiredSupportDescriptor(f.q.Context.DomainID, records)
	if err != nil {
		t.Fatal(err)
	}
	view, err := contract.InspectPublicState(freeze.CandidatePublicState, f.q.Context.DomainID)
	if err != nil {
		t.Fatal(err)
	}
	public, err := view.Own()
	if err != nil {
		t.Fatal(err)
	}
	public.RequiredSupport = support
	freeze.CandidatePublicState, err = contract.EncodePublicState(public)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := contract.PublicStateDescriptor(public)
	if err != nil {
		t.Fatal(err)
	}
	empty := contract.EmptyMutationResultDescriptors()
	q := contract.CryptoApplyReceiptAdmission{OperationKind: row.OperationKind, ChangedSubjects: row.ChangedSubjects, LiveDuties: empty[3], LiveHazards: empty[4], Context: f.q.Context, OperationRef: comparison.OperationRef, IdentityPlanDescriptor: freeze.IdentityPlanDescriptor,
		Delta: contract.MutationReceiptDelta{DomainID: f.q.Context.DomainID, OperationKind: row.OperationKind, AddedCount: 1, Before: owner.before, After: after}, AfterSupport: support, CandidatePublicState: candidate}
	return q, freeze
}

// full_only: false
func TestSecretAccessReceiptPinsOperationAndExactSubjects(t *testing.T) {
	base := exactRetainedFixture(t)
	for _, kind := range []uint16{contract.OperationEnvelopeRekey} {
		for _, damage := range []string{"exact", "kind", "subjects", "effects"} {
			t.Run(fmt.Sprintf("%d/%s", kind, damage), func(t *testing.T) {
				f := secretAccessFixture(t, base, kind)
				r, owner := secretAccessOwner(t, &f, nil)
				comparison := secretAccessCompare(t, r, f)
				plan := secretAccessPlan(f)
				prepared := secretAccessPrepare(t, r, f, comparison, plan)
				freeze := secretAccessFreeze(t, f, r.apply, comparison, plan, prepared)
				subjects := secretAccessExpectedSubjects(t, f)
				row := receiptHistoryRow(f.q.Context.DomainID, "standalone selected", true)
				row.OperationKind, row.EffectSummary = kind, contract.ReceiptEffectNotApplicable
				row.OperationID, row.PredecessorRevisionID = plan.Operation, owner.predecessorRevision
				row.RequestedRevisionID, row.ObservedRevisionID, row.ChangedSubjects = plan.Revision, plan.Revision, subjects
				switch damage {
				case "kind":
					row.OperationKind = contract.OperationApplyDeclaration
				case "subjects":
					row.ChangedSubjects.Digest[0] ^= 1
				case "effects":
					row.EffectSummary = contract.ReceiptEffectNoChange
				}
				q, freeze := secretAccessReceiptAdmission(t, f, owner, comparison, freeze, row)
				if err := owner.BindReceipt(f.ctx, q); (err == nil) != (damage == "exact") {
					t.Fatal("standalone receipt operation, state or subjects were not exact", damage, err)
				}
				if damage != "exact" {
					return
				}
				body, err := contract.EncodeCryptoFreezeRequest(freeze)
				if err != nil {
					t.Fatal(err)
				}
				reply := applyCall(r, f.ctx, contract.CryptoFreeze, body)
				if reply.ResultCode != contract.CryptoSuccess || f.route.privateCalls != 2 {
					t.Fatal("exact standalone receipt did not bind frozen candidate", reply.ResultCode)
				}
				frozen := r.apply.frozen
				body, err = contract.EncodeCryptoClaimRequest(frozen)
				if err != nil {
					t.Fatal(err)
				}
				if reply := applyCall(r, f.ctx, contract.CryptoClaim, body); reply.ResultCode != contract.CryptoSuccess || len(reply.KeyUseRows) != 0 {
					t.Fatal("exact standalone claim failed", reply.ResultCode)
				}
			})
		}
	}
}

func generatedRefreshFixture(t *testing.T, f *applyTestFixture) contract.ValueEntry {
	t.Helper()
	before, err := contract.DecodeValueEntry(f.q.Current[0].EntryBytes)
	if err != nil {
		t.Fatal(err)
	}
	before.ValueSource = contract.Generated
	before.Generated = generatedConsumerMetadata(before.ValueState)
	core, err := contract.ValueCoreForEntry(f.q.Context.DomainID, f.q.Context.CompatibilityID, before)
	if err != nil {
		t.Fatal(err)
	}
	core.DataKeyID, core.CommitmentKeyID, err = contract.GeneratorValueKeyIDs(before.ValueState)
	if err != nil {
		t.Fatal(err)
	}
	reply := contract.CryptoResponse{Kind: contract.CryptoPrepare}
	before, access, code := sealValueForRecipients(t.Context(), core, before.Generated, before.OutputEncoding, before.Recipients, f.q.Bindings, []byte("first secret"), &reply)
	if code != contract.CryptoSuccess {
		t.Fatal("generated current envelope fixture", code)
	}
	f.q.Current[0].EntryBytes, err = contract.EncodeValueEntry(before)
	if err != nil {
		t.Fatal(err)
	}
	f.q.Current[0].AccessRecord, err = contract.EncodeAccessRecord(access)
	if err != nil {
		t.Fatal(err)
	}
	intent := &f.q.Intent[0]
	intent.ValueSource, intent.Retained = contract.Generated, contract.RetainedSecretInput{}
	intent.PayloadDigest, intent.PayloadLength = contract.Hash(before.ValueBytes), uint32(len(before.ValueBytes))
	return before
}

// full_only: false
func TestSecretAccessGeneratedEnvelopePreservesResourceMetadata(t *testing.T) {
	base := exactRetainedFixture(t)
	for _, kind := range []uint16{contract.OperationEnvelopeRekey} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			f := secretAccessFixture(t, base, kind)
			before := generatedRefreshFixture(t, &f)
			core, err := contract.ValueCoreForEntry(f.q.Context.DomainID, f.q.Context.CompatibilityID, before)
			if err != nil {
				t.Fatal(err)
			}
			f.q.SecretAccess.Target.BeforePublicEntryDigest, err = contract.PublicValueEntryDigest(f.q.Context.DomainID, f.q.Current[0].Slot, before)
			if err != nil {
				t.Fatal(err)
			}
			refreshSecretAccessIntent(t, &f)
			// This mechanism check starts after authenticated generated support
			// admission. Installed Core tests exercise the complete support proof.
			a := &applyAdmission{request: f.q, control: f.control, operationKind: kind, authorityIndex: applyBindingIndex(f.q.Bindings, f.control.AuthorityRecipientID), routeID: f.route.CredentialRoute(), supportTransition: &contract.GeneratedSupportTransition{}}
			if !a.secretAccessAdmission(f.current, false) {
				t.Fatal("exact generated target projection was refused")
			}
			reply := contract.CryptoResponse{Kind: contract.CryptoCompare}
			if code := a.compare(t.Context(), f.route, &reply); code != contract.CryptoSuccess || len(a.comparison) != 1 || a.comparison[0].Relation != contract.CryptoEqual {
				t.Fatal("generated target plaintext relation changed", code)
			}
			plan := secretAccessPlan(f)
			identity, err := contract.EncodeIdentityPlan(plan)
			if err != nil {
				t.Fatal(err)
			}
			reply = contract.CryptoResponse{Kind: contract.CryptoPrepare}
			if code := a.prepare(t.Context(), f.route, contract.CryptoPrepareRequest{IdentityPlan: identity}, &reply); code != contract.CryptoSuccess || len(a.prepared) != 1 {
				t.Fatal("generated current envelope did not refresh", code)
			}
			after, err := contract.DecodeValueEntry(a.prepared[0].EntryBytes)
			if err != nil {
				t.Fatal(err)
			}
			expected := before.Generated
			expected.GenerationID = plan.Rows[0].ValueState
			afterCore, err := contract.ValueCoreForEntry(f.q.Context.DomainID, f.q.Context.CompatibilityID, after)
			if err != nil || after.Generated != expected || afterCore.GeneratedBindingDigest != core.GeneratedBindingDigest || after.ValueSource != contract.Generated || after.Incarnation != before.Incarnation || after.ValueState != expected.GenerationID || f.route.privateCalls != 2 {
				t.Fatal("envelope refresh changed generated resource identity or original evidence", err)
			}
			var expectedSubjects []contract.ChangedSubjectIdentity
			for _, subject := range []struct {
				kind, change uint8
				primary      contract.ID
			}{{contract.ChangedSubjectValueEntry, contract.ChangedSubjectUpdated, before.Incarnation}, {contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectRemoved, before.Generated.GenerationID}, {contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectAdded, expected.GenerationID}} {
				id, err := contract.ChangedSubjectIdentityID(f.q.Context.DomainID, subject.kind, subject.primary, contract.ID{})
				if err != nil {
					t.Fatal(err)
				}
				expectedSubjects = append(expectedSubjects, contract.ChangedSubjectIdentity{Kind: subject.kind, Change: subject.change, Identity: id})
			}

			want, err := contract.ChangedSubjectDescriptor(expectedSubjects)
			got, gotErr := a.secretAccessSubjects()
			if err != nil || gotErr != nil || got != want {
				t.Fatal("generated envelope subjects did not replace the exact current generation", err, gotErr)
			}
		})
	}
}

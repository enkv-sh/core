package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

func useExactRetainedInputs(t *testing.T, f *applyTestFixture) {
	t.Helper()
	for i := range f.q.Intent {
		row := &f.q.Intent[i]
		at := slices.IndexFunc(f.q.Current, func(current contract.CryptoCurrentSecret) bool {
			entry, err := contract.InspectValueEntry(current.EntryBytes)
			return err == nil && string(entry.Name) == row.Name
		})
		if at < 0 {
			t.Fatal("retained current fixture absent")
		}
		entry, err := contract.DecodeValueEntry(f.q.Current[at].EntryBytes)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := contract.InspectCanonicalPayload(entry.ValueBytes)
		if err != nil {
			t.Fatal(err)
		}
		row.Retained = contract.RetainedSecretInput{Incarnation: entry.Incarnation, Material: entry.ValueState}
		row.PayloadDigest, row.PayloadLength, row.ContentLength = contract.ID(sha256.Sum256(entry.ValueBytes)), uint32(len(entry.ValueBytes)), payload.ContentLength
		row.InputEncoding, row.RetainedLength = payload.InputEncoding, payload.RetainedLength
	}
	f.q.SealedInputs, f.accepted = nil, nil
	var err error
	f.q.Context.IntentDescriptor, err = contract.CompleteApplyIntentDescriptor(f.q.Context.DomainID, f.q.Intent, f.q.Recipients)
	if err != nil {
		t.Fatal(err)
	}
}

func exactRetainedFixture(t *testing.T) applyTestFixture {
	t.Helper()
	f := retainedApplyFixture(t)
	useExactRetainedInputs(t, &f)
	return f
}

// full_only: false
func TestApplyExactRetainedComparisonAuthenticatesEveryCurrentSecret(t *testing.T) {
	base := exactRetainedFixture(t)
	for _, name := range []string{"equal", "later-ciphertext", "private-denial"} {
		t.Run(name, func(t *testing.T) {
			f := cloneApplyFixture(t, base)
			want, opens := contract.CryptoSuccess, uint32(2)
			if name == "later-ciphertext" {
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
				want = contract.CryptoStoredAuthenticationFailed
			}
			if name == "private-denial" {
				f.route.override = func(context.Context, contract.KMSBinding, []byte, uint16) PrivateResult {
					return PrivateResult{Status: KeyDenied, Uses: KeyUses{Denied: 1}}
				}
				want, opens = contract.CryptoPrivateRouteUnavailable, 1
			}
			r := f.runtime(t, nil)
			body, err := contract.EncodeCryptoCompareRequest(f.q)
			if err != nil {
				t.Fatal(err)
			}
			reply := applyCall(r, t.Context(), contract.CryptoCompare, body)
			if reply.ResultCode != want || len(reply.KeyUseRows) != 1 || reply.KeyUseRows[0].Count != opens || reply.KeyUseRows[0].SubjectID != f.control.AuthorityRecipientID {
				t.Fatal("retained comparison skipped private current validation", reply.ResultCode, reply.KeyUseRows)
			}
			if want != contract.CryptoSuccess {
				if len(reply.Body) != 0 {
					t.Fatal("failed later private validation returned partial equality")
				}
				return
			}
			got, err := contract.DecodeCryptoCompareResult(reply.Body)
			if err != nil || len(got.Rows) != 2 {
				t.Fatal("incomplete retained comparison", err)
			}
			for i, row := range got.Rows {
				if row.Relation != contract.CryptoEqual || row.SourceDigest != f.q.Intent[i].PayloadDigest || row.AfterRawLength != f.q.Intent[i].ContentLength || !row.BeforePresent || !row.AfterPresent || !row.ExclusionPathDigest.IsZero() {
					t.Fatal("retained equality lost its exact source or membership")
				}
			}
			if len(r.apply.prepared) != 0 || len(r.apply.plan.Rows) != 0 {
				t.Fatal("retained comparison prepared identities or material")
			}
		})
	}
}

// full_only: false
func TestApplyExactRetainedAdmissionRejectsChangedPins(t *testing.T) {
	base := exactRetainedFixture(t)
	for _, name := range []string{"missing", "incarnation", "material", "readded", "payload", "raw-length", "sealed-source"} {
		t.Run(name, func(t *testing.T) {
			f := cloneApplyFixture(t, base)
			switch name {
			case "missing":
				f.q.Current = f.q.Current[:1]
			case "incarnation":
				f.q.Intent[1].Retained.Incarnation[0] ^= 1
			case "material":
				f.q.Intent[1].Retained.Material[0] ^= 1
			case "readded":
				entry, err := contract.DecodeValueEntry(f.q.Current[1].EntryBytes)
				if err != nil {
					t.Fatal(err)
				}
				entry.Incarnation[0] ^= 1
				entry.ValueState[0] ^= 1
				f.q.Current[1].EntryBytes, err = contract.EncodeValueEntry(entry)
				if err != nil {
					t.Fatal(err)
				}
			case "payload":
				f.q.Intent[1].PayloadDigest[0] ^= 1
			case "raw-length":
				f.q.Intent[1].ContentLength++
				f.q.Intent[1].RetainedLength++
				f.q.Intent[1].PayloadLength++
			case "sealed-source":
				f.q.SealedInputs = []contract.CryptoSealedInput{{Name: f.q.Intent[1].Name}}
			}
			var err error
			f.q.Context.IntentDescriptor, err = contract.CompleteApplyIntentDescriptor(f.q.Context.DomainID, f.q.Intent, f.q.Recipients)
			if err != nil {
				t.Fatal(err)
			}
			f.route.override = func(context.Context, contract.KMSBinding, []byte, uint16) PrivateResult {
				t.Fatal("invalid retained pin reached private key")
				return PrivateResult{}
			}
			r := newConsumerRuntime(t, f.route)
			if err := r.admitApply(f.q, f.control, f.current, nil, f.route.CredentialRoute(), f.accepted, nil, f.support, f.deadline); err != ErrAdmission || r.apply != nil {
				t.Fatal("invalid exact current pin admitted", err)
			}
		})
	}
}

// full_only: false
func TestApplyExactRetainedAndSealedInputsKeepSeparatePreparation(t *testing.T) {
	f := retainedApplyFixture(t)
	// Retain alpha; beta remains a sealed input with a real value change.
	sealed := f.q.SealedInputs[1]
	core := f.accepted[contract.Hash(sealed.EnvelopeBytes)]
	want := []byte("replacement beta")
	core.ContentLength = uint32(len(want))
	core.RetainedLength = uint32(len(want))
	envelope, err := custody.SealInput(core, f.q.Bindings[applyBindingIndex(f.q.Bindings, f.control.AuthorityRecipientID)], want)
	if err != nil {
		t.Fatal(err)
	}
	replaceApplySource(t, &f, 1, envelope)
	sealed = f.q.SealedInputs[1]
	sealedIntent := f.q.Intent[1]
	useExactRetainedInputs(t, &f)
	f.q.Intent[1] = sealedIntent
	f.q.SealedInputs = []contract.CryptoSealedInput{sealed}
	f.accepted = map[contract.ID]contract.SealedInputCore{contract.Hash(sealed.EnvelopeBytes): core}
	f.q.Context.IntentDescriptor, err = contract.CompleteApplyIntentDescriptor(f.q.Context.DomainID, f.q.Intent, f.q.Recipients)
	if err != nil {
		t.Fatal(err)
	}
	r := f.runtime(t, nil)
	body, err := contract.EncodeCryptoCompareRequest(f.q)
	if err != nil {
		t.Fatal(err)
	}
	beforeCalls := f.route.privateCalls
	reply := applyCall(r, t.Context(), contract.CryptoCompare, body)
	authority := f.q.Bindings[applyBindingIndex(f.q.Bindings, f.control.AuthorityRecipientID)]
	compareUses := []contract.KeyUseRow{independentKeyUseRow(authority, contract.KeyUseMaterialOpen, contract.KeyUseCompleted, 3)}
	if reply.ResultCode != contract.CryptoSuccess || f.route.privateCalls-beforeCalls != 3 || !slices.Equal(reply.KeyUseRows, compareUses) {
		t.Fatal("mixed input comparison used wrong source or current facts", reply.ResultCode, f.route.privateCalls-beforeCalls, reply.KeyUseRows)
	}
	comparison, err := contract.DecodeCryptoCompareResult(reply.Body)
	if err != nil || len(comparison.Rows) != 2 || comparison.Rows[0].Relation != contract.CryptoEqual || comparison.Rows[1].Relation != contract.CryptoChanged {
		t.Fatal("mixed retained and sealed relations differ", err)
	}
	plan := applyPlan(f)
	plan.Rows = plan.Rows[1:]
	plan.Operation, plan.Transition, plan.Snapshot, plan.Revision = consumerID("mixed operation"), consumerID("mixed transition"), consumerID("mixed snapshot"), consumerID("mixed revision")
	plan.Rows[0].ValueState = consumerID("mixed replacement beta")
	plan.Rows[0].OriginSnapshot, plan.Rows[0].OriginTransition = plan.Snapshot, plan.Transition
	identity, err := contract.EncodeIdentityPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	body, err = contract.EncodeCryptoPrepareRequest(contract.CryptoPrepareRequest{OperationRef: comparison.OperationRef, Context: f.q.Context, IdentityPlan: identity})
	if err != nil {
		t.Fatal(err)
	}
	reply = applyCall(r, t.Context(), contract.CryptoPrepare, body)
	if reply.ResultCode != contract.CryptoSuccess || f.route.privateCalls-beforeCalls != 4 {
		t.Fatal("mixed preparation treated retained alpha as a sealed source", reply.ResultCode, f.route.privateCalls-beforeCalls)
	}
	prepareOpen := independentKeyUseRow(authority, contract.KeyUseMaterialOpen, contract.KeyUseCompleted, 1)
	if len(reply.KeyUseRows) != len(f.q.Bindings)+1 || !slices.Contains(reply.KeyUseRows, prepareOpen) {
		t.Fatal("mixed preparation omitted exact current key-use facts", reply.KeyUseRows)
	}
	for _, binding := range f.q.Bindings {
		wrap := independentKeyUseRow(binding, contract.KeyUseMaterialWrap, contract.KeyUseCompleted, 1)
		if !slices.Contains(reply.KeyUseRows, wrap) {
			t.Fatal("mixed preparation changed exact recipient wrap facts", reply.KeyUseRows)
		}
	}
	prepared, err := contract.DecodeCryptoPrepareResult(reply.Body)
	if err != nil || len(prepared.Rows) != 1 || prepared.Rows[0].Name != "beta" {
		t.Fatal("mixed preparation changed retained alpha", err)
	}
	current, ok := r.apply.current(contract.CryptoCurrentSecret{Slot: prepared.Rows[0].Slot, EntryBytes: prepared.Rows[0].EntryBytes, AccessRecord: prepared.Rows[0].AccessRecord})
	if !ok {
		t.Fatal("mixed changed value lacks complete current protection")
	}
	keys, code := r.apply.openCurrent(t.Context(), f.route, current, &contract.CryptoResponse{})
	if keys != nil {
		defer clear(keys[:cap(keys)])
	}
	if code != contract.CryptoSuccess {
		t.Fatal("mixed changed value cannot open", code)
	}
	plain, err := custody.OpenValue(current.core, current.payload, keys)
	if plain != nil {
		defer clear(plain[:cap(plain)])
	}
	if err != nil || !bytes.Equal(plain, want) {
		t.Fatal("mixed preparation selected wrong supplied bytes", err)
	}
}

// full_only: false
func TestApplyExactRetainedSharingPreservesRequiredAccess(t *testing.T) {
	applyMixedGrantExclusionPreservesRequiredAccess(t, true, false)
}

// full_only: false
func TestApplyExactRetainedRequiresEnabledRecoveryProtection(t *testing.T) {
	base := exactRetainedFixture(t)
	for _, name := range []string{"missing-binding", "missing-wrap", "mode-change"} {
		t.Run(name, func(t *testing.T) {
			f := cloneApplyFixture(t, base)
			switch name {
			case "missing-binding":
				f.q.Bindings = slices.DeleteFunc(f.q.Bindings, func(row contract.BindingTableRow) bool { return row.SubjectKind == contract.RecoveryWrapSubject })
			case "missing-wrap":
				access, err := contract.DecodeAccessRecord(f.q.Current[1].AccessRecord)
				if err != nil {
					t.Fatal(err)
				}
				access.Wraps = slices.DeleteFunc(access.Wraps, func(row contract.WrapRow) bool { return row.SubjectKind == contract.RecoveryWrapSubject })
				f.q.Current[1].AccessRecord, err = contract.EncodeAccessRecord(access)
				if err != nil {
					t.Fatal(err)
				}
			case "mode-change":
				f.control.Recovery = nil
			}
			f.route.override = func(context.Context, contract.KMSBinding, []byte, uint16) PrivateResult {
				t.Fatal("incomplete Recovery protection used private key")
				return PrivateResult{}
			}
			r := newConsumerRuntime(t, f.route)
			if err := r.admitApply(f.q, f.control, f.current, nil, f.route.CredentialRoute(), f.accepted, nil, f.support, f.deadline); err != ErrAdmission || r.apply != nil {
				t.Fatal("missing enabled Recovery protection changed mode or admitted", err)
			}
		})
	}
}

// full_only: false
func TestApplyExactRetainedUsesReplacementCurrentAccess(t *testing.T) {
	f := exactRetainedFixture(t)
	old := &applyAdmission{request: f.q, control: f.control}
	oldKey := f.route.key
	index := applyBindingIndex(f.q.Bindings, f.control.AuthorityRecipientID)
	replacement := f.q.Bindings[index]
	key := f.keys[consumerID("reader")]
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	replacement.Binding.BindingID = consumerID("replacement authority binding")
	replacement.Binding.BindingIncarnationID = consumerID("replacement authority incarnation")
	replacement.Binding.BindingSerial++
	replacement.Binding.KeySelector = "projects/test-project/locations/us-central1/keyRings/test/cryptoKeys/replacement/cryptoKeyVersions/1"
	replacement.Binding.SPKI, replacement.Binding.Fingerprint = spki, contract.Hash(spki)
	for i, row := range f.q.Current {
		current, ok := old.current(row)
		if !ok {
			t.Fatal("invalid old current fixture")
		}
		packet, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, oldKey, current.access.Wraps[current.wrapIndex].RSACiphertext, nil)
		if err != nil {
			t.Fatal(err)
		}
		keys, err := custody.PacketKeys(packet, 1, current.packetContext)
		if err != nil {
			t.Fatal(err)
		}
		wc, err := custody.ValueWrapCore(current.core, replacement)
		if err != nil {
			t.Fatal(err)
		}
		wrap, err := custody.Wrap(wc, replacement.Binding, keys)
		clear(packet[:cap(packet)])
		if err != nil {
			t.Fatal(err)
		}
		current.access.Wraps[current.wrapIndex] = wrap
		f.q.Current[i].AccessRecord, err = contract.EncodeAccessRecord(current.access)
		if err != nil {
			t.Fatal(err)
		}
	}
	f.q.Bindings[index] = replacement
	for i := range f.current {
		if f.current[i].RecipientID == replacement.SubjectID {
			binding := replacement.Binding
			f.current[i].CurrentBinding = &binding
		}
	}
	for i := range f.q.Recipients {
		if f.q.Recipients[i].Recipient.RecipientID == replacement.SubjectID {
			binding := replacement.Binding
			f.q.Recipients[i].Recipient.CurrentBinding = &binding
		}
	}
	refreshApplyIntent(t, &f)
	f.control.AuthorityKMSBinding = replacement.Binding
	f.route = &consumerTestRoute{testKeyAccess: &testKeyAccess{key: key, binding: replacement.Binding}}
	f.route.override = func(ctx context.Context, binding contract.KMSBinding, ciphertext []byte, length uint16) PrivateResult {
		if binding.BindingID != replacement.Binding.BindingID {
			t.Fatal("retained input used replaced private key or Recovery")
		}
		return f.route.testKeyAccess.Decrypt(ctx, binding, ciphertext, length)
	}
	r := f.runtime(t, nil)
	body, err := contract.EncodeCryptoCompareRequest(f.q)
	if err != nil {
		t.Fatal(err)
	}
	reply := applyCall(r, t.Context(), contract.CryptoCompare, body)
	if reply.ResultCode != contract.CryptoSuccess || f.route.privateCalls != 2 {
		t.Fatal("preserved material could not use replacement current access", reply.ResultCode)
	}
	got, err := contract.DecodeCryptoCompareResult(reply.Body)
	if err != nil || len(got.Rows) != 2 || slices.ContainsFunc(got.Rows, func(row contract.CryptoComparisonRow) bool { return row.Relation != contract.CryptoEqual }) {
		t.Fatal("access replacement changed retained semantic relation", err)
	}
}

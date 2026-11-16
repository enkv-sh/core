package crypto

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

func retainedApplyFixture(t *testing.T) applyTestFixture {
	t.Helper()
	f := applyFixture(t, true)
	r := f.runtime(t, nil)
	comparison := applyCompare(t, r, f)
	prepared := applyPrepare(t, r, f, comparison, applyPlan(f))
	r.retireApply()
	for _, row := range prepared.Rows {
		f.q.Current = append(f.q.Current, contract.CryptoCurrentSecret{Slot: row.Slot, EntryBytes: row.EntryBytes, AccessRecord: row.AccessRecord})
	}
	f.q.Context.AdmissionID = consumerID("retained admission")
	f.q.Context.SessionID = consumerID("retained session")
	return f
}

// full_only: false
func TestApplyCurrentAccessRequiresExactProtection(t *testing.T) {
	base := retainedApplyFixture(t)
	for _, name := range []string{"missing-authority", "missing-reader", "missing-recovery", "extra-wrap", "material-id", "material-context", "package-check", "wrap-binding", "wrap-key", "wrap-epoch"} {
		t.Run(name, func(t *testing.T) {
			f := cloneApplyFixture(t, base)
			access, err := contract.DecodeAccessRecord(f.q.Current[1].AccessRecord)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "missing-authority", "missing-reader", "missing-recovery":
				index := slices.IndexFunc(access.Wraps, func(w contract.WrapRow) bool {
					if name == "missing-recovery" {
						return w.SubjectKind == 2
					}
					return w.SubjectKind == 1 && (w.SubjectID == f.control.AuthorityRecipientID) == (name == "missing-authority")
				})
				if index < 0 {
					t.Fatal("required current protection fixture is absent")
				}
				access.Wraps = slices.Delete(access.Wraps, index, index+1)
			case "extra-wrap":
				row := access.Wraps[0]
				row.SubjectID = consumerID("extra current recipient")
				access.Wraps = append(access.Wraps, row)
				slices.SortFunc(access.Wraps, func(a, b contract.WrapRow) int {
					if a.SubjectKind != b.SubjectKind {
						return int(a.SubjectKind) - int(b.SubjectKind)
					}
					return bytes.Compare(a.SubjectID[:], b.SubjectID[:])
				})
			case "material-id":
				access.MaterialID[0] ^= 1
			case "material-context":
				access.MaterialContextDigest[0] ^= 1
			case "package-check":
				access.PackageCheck[0] ^= 1
			case "wrap-binding":
				access.Wraps[0].PublicBindingDigest[0] ^= 1
			case "wrap-key":
				access.Wraps[0].BindingID[0] ^= 1
			case "wrap-epoch":
				access.Wraps[0].BindingSerial++
			}
			f.q.Current[1].AccessRecord, err = contract.EncodeAccessRecord(access)
			if err != nil {
				t.Fatal("current protection mutation is not structurally valid", err)
			}
			r := newConsumerRuntime(t, f.route)
			f.route.override = func(context.Context, contract.KMSBinding, []byte, uint16) PrivateResult {
				t.Fatal("invalid current protection used a private route")
				return PrivateResult{}
			}
			if err := r.admitApply(f.q, f.control, f.current, nil, f.route.CredentialRoute(), f.accepted, nil, f.support, f.deadline); err != ErrAdmission || r.apply != nil {
				t.Fatal("current protection differs from admitted registry or value context", err)
			}
		})
	}
}

// full_only: false
func TestApplyRetainedSecretComparison(t *testing.T) {
	f := retainedApplyFixture(t)
	r := f.runtime(t, nil)
	body, err := contract.EncodeCryptoCompareRequest(f.q)
	if err != nil {
		t.Fatal(err)
	}
	reply := applyCall(r, context.Background(), contract.CryptoCompare, body)
	if reply.ResultCode != contract.CryptoSuccess {
		t.Fatalf("retained comparison code %v", reply.ResultCode)
	}
	got, err := contract.DecodeCryptoCompareResult(reply.Body)
	if err != nil || len(got.Rows) != 2 {
		t.Fatalf("incomplete retained comparison: %v", err)
	}
	for _, row := range got.Rows {
		if row.Relation != contract.CryptoEqual || !row.BeforePresent || !row.AfterPresent || row.BeforePublicEntryDigest.IsZero() || !row.ExclusionPathDigest.IsZero() {
			t.Fatal("retained equal value lost its relation or predecessor")
		}
	}
}

// full_only: false
func TestApplyRetainedComparisonValidatesEveryPrivateValue(t *testing.T) {
	base := retainedApplyFixture(t)
	for _, name := range []string{"randomized-equal", "changed-value", "later-source-corruption", "later-current-corruption"} {
		t.Run(name, func(t *testing.T) {
			f := cloneApplyFixture(t, base)
			want := contract.CryptoSuccess
			relation := contract.CryptoEqual
			if name == "later-current-corruption" {
				entry, err := contract.DecodeValueEntry(f.q.Current[1].EntryBytes)
				if err != nil {
					t.Fatal(err)
				}
				entry.ValueBytes[len(entry.ValueBytes)-1] ^= 1
				f.q.Current[1].EntryBytes, err = contract.EncodeValueEntry(entry)
				if err != nil {
					t.Fatal(err)
				}
				want = contract.CryptoStoredAuthenticationFailed
			} else {
				envelope, err := contract.DecodeSealedInputEnvelope(f.q.SealedInputs[1].EnvelopeBytes)
				if err != nil {
					t.Fatal(err)
				}
				if name == "later-source-corruption" {
					envelope.Ciphertext[0] ^= 1
					want = contract.CryptoSourceAuthenticationFailed
				} else {
					plain := []byte{}
					if name == "changed-value" {
						plain = []byte("different value")
						relation = contract.CryptoChanged
					}
					envelope.Core.ContentLength = uint32(len(plain))
					envelope.Core.RetainedLength = uint32(len(plain))
					envelope, err = custody.SealInput(envelope.Core, f.q.Bindings[applyBindingIndex(f.q.Bindings, f.control.AuthorityRecipientID)], plain)
					if err != nil {
						t.Fatal(err)
					}
				}
				replaceApplySource(t, &f, 1, envelope)
				if bytes.Equal(base.q.SealedInputs[1].EnvelopeBytes, f.q.SealedInputs[1].EnvelopeBytes) {
					t.Fatal("changed source bytes were not constructed")
				}
			}
			r := f.runtime(t, nil)
			body, err := contract.EncodeCryptoCompareRequest(f.q)
			if err != nil {
				t.Fatal(err)
			}
			reply := applyCall(r, context.Background(), contract.CryptoCompare, body)
			if reply.ResultCode != want {
				t.Fatalf("complete comparison code %v, want %v", reply.ResultCode, want)
			}
			if want != contract.CryptoSuccess {
				if len(reply.Body) != 0 {
					t.Fatal("later corruption returned partial comparison")
				}
				return
			}
			got, err := contract.DecodeCryptoCompareResult(reply.Body)
			if err != nil || len(got.Rows) != 2 || got.Rows[0].Relation != contract.CryptoEqual || got.Rows[1].Relation != relation {
				t.Fatal("incorrect complete comparison", err)
			}
			if len(r.apply.prepared) != 0 || len(r.apply.plan.Rows) != 0 {
				t.Fatal("comparison allocated canonical material")
			}
		})
	}
}

// full_only: false
func TestApplyPacketRefusalClearsPrivateCapacity(t *testing.T) {
	f := retainedApplyFixture(t)
	for _, source := range []bool{true, false} {
		for _, damage := range []string{"kind", "length"} {
			name := "current/" + damage
			if source {
				name = "source/" + damage
			}
			t.Run(name, func(t *testing.T) {
				expectedLength := uint16(100)
				wantCode := contract.CryptoStoredAuthenticationFailed
				if source {
					expectedLength = 68
					wantCode = contract.CryptoSourceAuthenticationFailed
				}
				f.route.override = func(ctx context.Context, b contract.KMSBinding, ciphertext []byte, length uint16) PrivateResult {
					if length != expectedLength {
						t.Fatalf("private packet length %d, want %d", length, expectedLength)
					}
					got := f.route.testKeyAccess.Decrypt(ctx, b, ciphertext, length)
					if got.Status != KeyOK || len(got.Packet) != int(expectedLength) {
						t.Fatal("valid private packet fixture refused before damage")
					}
					if damage == "kind" {
						got.Packet[3] = 4
					} else {
						got.Packet = got.Packet[:len(got.Packet)-1]
					}
					return got
				}
				r := f.runtime(t, nil)
				defer r.retireApply()
				reply := contract.CryptoResponse{Kind: contract.CryptoCompare}
				var value []byte
				var code contract.CryptoResultCode
				calls := f.route.privateCalls
				if source {
					value, code = r.apply.openSealedInput(context.Background(), f.route, 0, &reply)
				} else {
					current, ok := r.apply.current(f.q.Current[0])
					if !ok {
						t.Fatal("valid current fixture refused")
					}
					value, code = r.apply.openCurrent(context.Background(), f.route, current, &reply)
				}
				row := f.q.Bindings[r.apply.authorityIndex]
				wantRows := []contract.KeyUseRow{independentKeyUseRow(row, 3, 1, 1)}
				if value != nil || code != wantCode || f.route.privateCalls != calls+1 || !slices.Equal(reply.KeyUseRows, wantRows) {
					t.Fatalf("packet refusal differs: code=%v calls=%d rows=%+v", code, f.route.privateCalls-calls, reply.KeyUseRows)
				}
				if len(f.route.returned) <= int(expectedLength) || !bytes.Equal(f.route.returned, make([]byte, len(f.route.returned))) {
					t.Fatal("packet refusal retained private capacity")
				}
			})
		}
	}
}

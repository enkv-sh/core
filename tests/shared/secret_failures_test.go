package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type changedCryptoReply struct {
	inner     contract.Crypto
	kind      contract.CryptoKind
	change    func(contract.CryptoResponse) contract.CryptoResponse
	calls     int
	exchanges int
}

func (c *changedCryptoReply) InstanceID() contract.ID { return c.inner.InstanceID() }
func (c *changedCryptoReply) Exchange(ctx context.Context, q contract.CryptoRequest) contract.CryptoResponse {
	c.exchanges++
	r := c.inner.Exchange(ctx, q)
	if q.Kind == c.kind {
		c.calls++
		return c.change(r)
	}
	return r
}

func firstSecretInput(t *testing.T, env fixtureEnvironment, s *StateSession) []ApplyEntryInput {
	t.Helper()
	recipients := []contract.ID{s.admission.recipient}
	return append(s.currentEntryInputs(), sharingSecretNamed(t, env, "secret", "secret source", recipients))
}

// full_only: false
func TestFirstSecretRejectsChangedCustodyRepliesBeforeWrites(t *testing.T) {
	cases := []struct {
		name   string
		kind   contract.CryptoKind
		change func(contract.CryptoResponse) contract.CryptoResponse
		want   Result
	}{
		{"compare-correlation", contract.CryptoCompare, func(r contract.CryptoResponse) contract.CryptoResponse { r.RequestID[0] ^= 1; return r }, refused(AdmissionInvalid)},
		{"prepare-output-encoding", contract.CryptoPrepare, nil, refused(AdmissionInvalid)},
		{"prepare-input-encoding", contract.CryptoPrepare, nil, refused(AdmissionInvalid)},
		{"prepare-unknown", contract.CryptoPrepare, func(r contract.CryptoResponse) contract.CryptoResponse {
			r.ResultCode = contract.CryptoResponseUnknown
			r.Body = nil
			return r
		}, failure(EvidenceUnavailable, CustodyUnavailable)},
		{"freeze-facts", contract.CryptoFreeze, func(r contract.CryptoResponse) contract.CryptoResponse { r.Body[0] ^= 1; return r }, refused(AdmissionInvalid)},
		{"claim-framing", contract.CryptoClaim, func(r contract.CryptoResponse) contract.CryptoResponse { r.Body = []byte{1}; return r }, refused(AdmissionInvalid)},
		{"compare-open-count", contract.CryptoCompare, func(r contract.CryptoResponse) contract.CryptoResponse { r.KeyUseRows[0].Count++; return r }, refused(AdmissionInvalid)},
		{"compare-missing-open", contract.CryptoCompare, func(r contract.CryptoResponse) contract.CryptoResponse { r.KeyUseRows = nil; return r }, refused(AdmissionInvalid)},
		{"compare-duplicate-open", contract.CryptoCompare, func(r contract.CryptoResponse) contract.CryptoResponse {
			r.KeyUseRows = append(r.KeyUseRows, r.KeyUseRows[0])
			return r
		}, refused(AdmissionInvalid)},
		{"compare-wrong-purpose", contract.CryptoCompare, func(r contract.CryptoResponse) contract.CryptoResponse {
			r.KeyUseRows[0].Purpose = contract.KeyUseMaterialWrap
			return r
		}, refused(AdmissionInvalid)},
		{"compare-incomplete-open", contract.CryptoCompare, func(r contract.CryptoResponse) contract.CryptoResponse {
			r.KeyUseRows[0].Outcome = contract.KeyUseUnknown
			return r
		}, refused(AdmissionInvalid)},
		{"compare-open-undercount", contract.CryptoCompare, func(r contract.CryptoResponse) contract.CryptoResponse {
			r.KeyUseRows[0].Count--
			return r
		}, refused(AdmissionInvalid)},
		{"prepare-wrap-count", contract.CryptoPrepare, func(r contract.CryptoResponse) contract.CryptoResponse {
			for i := range r.KeyUseRows {
				if r.KeyUseRows[i].Purpose == contract.KeyUseMaterialWrap {
					r.KeyUseRows[i].Count++
				}
			}
			return r
		}, refused(AdmissionInvalid)},
		{"prepare-missing-open", contract.CryptoPrepare, func(r contract.CryptoResponse) contract.CryptoResponse {
			r.KeyUseRows = slices.DeleteFunc(r.KeyUseRows, func(row contract.KeyUseRow) bool { return row.Purpose == contract.KeyUseMaterialOpen })
			return r
		}, refused(AdmissionInvalid)},
		{"prepare-missing-wrap", contract.CryptoPrepare, func(r contract.CryptoResponse) contract.CryptoResponse {
			removed := false
			r.KeyUseRows = slices.DeleteFunc(r.KeyUseRows, func(row contract.KeyUseRow) bool {
				if !removed && row.Purpose == contract.KeyUseMaterialWrap {
					removed = true
					return true
				}
				return false
			})
			return r
		}, refused(AdmissionInvalid)},
		{"prepare-open-undercount", contract.CryptoPrepare, func(r contract.CryptoResponse) contract.CryptoResponse {
			for i := range r.KeyUseRows {
				if r.KeyUseRows[i].Purpose == contract.KeyUseMaterialOpen {
					r.KeyUseRows[i].Count--
				}
			}
			return r
		}, refused(AdmissionInvalid)},
		{"prepare-wrap-undercount", contract.CryptoPrepare, func(r contract.CryptoResponse) contract.CryptoResponse {
			for i := range r.KeyUseRows {
				if r.KeyUseRows[i].Purpose == contract.KeyUseMaterialWrap {
					r.KeyUseRows[i].Count--
					break
				}
			}
			return r
		}, refused(AdmissionInvalid)},
		{"prepare-wrong-binding", contract.CryptoPrepare, func(r contract.CryptoResponse) contract.CryptoResponse {
			first, second := -1, -1
			for i := range r.KeyUseRows {
				if r.KeyUseRows[i].Purpose != contract.KeyUseMaterialWrap {
					continue
				}
				if first < 0 {
					first = i
				} else {
					second = i
					break
				}
			}
			if first >= 0 && second >= 0 {
				r.KeyUseRows[first].BindingID = r.KeyUseRows[second].BindingID
				r.KeyUseRows[first].PublicBindingDigest = r.KeyUseRows[second].PublicBindingDigest
			}
			return r
		}, refused(AdmissionInvalid)},
		{"freeze-extra-use", contract.CryptoFreeze, func(r contract.CryptoResponse) contract.CryptoResponse {
			r.KeyUseRows = []contract.KeyUseRow{{BindingID: contract.Hash([]byte("foreign binding")), PublicBindingDigest: contract.Hash([]byte("foreign public binding")), SubjectKind: 1, SubjectID: contract.Hash([]byte("foreign recipient")), Provider: contract.GCP, Purpose: contract.KeyUseMaterialOpen, Outcome: contract.KeyUseCompleted, Count: 1}}
			return r
		}, refused(AdmissionInvalid)},
	}
	multiple := map[string]bool{
		"compare-open-undercount": true,
		"prepare-open-undercount": true,
		"prepare-wrap-undercount": true,
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			env, keys := genesisEnvironment(t, contract.GCP, true)
			f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
			input := firstSecretInput(t, env, f.session)
			if multiple[tc.name] {
				recipients := []contract.ID{f.session.admission.recipient}
				input = append(f.session.currentEntryInputs(), sharingSecretNamed(t, env, "secret-a", "secret-a source", recipients), sharingSecretNamed(t, env, "secret-b", "secret-b source", recipients))
			}
			parent := admitSuppliedComparison(t, f.session, keys, input)
			change := tc.change
			if tc.name == "prepare-output-encoding" || tc.name == "prepare-input-encoding" {
				change = func(reply contract.CryptoResponse) contract.CryptoResponse {
					prepared, err := contract.DecodeCryptoPrepareResult(reply.Body)
					if err != nil || len(prepared.Rows) != 1 {
						t.Fatal("prepared representation fixture", err)
					}
					entry, err := contract.DecodeValueEntry(prepared.Rows[0].EntryBytes)
					if err != nil {
						t.Fatal(err)
					}
					if tc.name == "prepare-output-encoding" {
						entry.OutputEncoding = contract.OutputEncodingBase64
					} else {
						payload, err := contract.DecodeCanonicalPayload(entry.ValueBytes)
						if err != nil {
							t.Fatal(err)
						}
						entry.InputEncoding, payload.InputEncoding = contract.InputEncodingBase64, contract.InputEncodingBase64
						entry.RetainedLength = 4 * ((payload.ContentLength + 2) / 3)
						payload.RetainedLength = entry.RetainedLength
						payload.Ciphertext = bytes.Repeat([]byte{91}, int(payload.RetainedLength)+16)
						entry.ValueBytes, err = contract.EncodeCanonicalPayload(payload)
						if err != nil {
							t.Fatal("input representation damage is not a valid canonical payload", err)
						}
					}
					prepared.Rows[0].EntryBytes, err = contract.EncodeValueEntry(entry)
					if err != nil {
						t.Fatal("representation damage is not a valid prepared entry", err)
					}
					reply.Body, err = contract.EncodeCryptoPrepareResult(prepared)
					if err != nil {
						t.Fatal(err)
					}
					return reply
				}
			}
			changed := &changedCryptoReply{inner: parent.crypto, kind: tc.kind, change: change}
			parent.crypto = changed
			store := env.Store.(*memoryStore)
			trust := env.Trust.(*fixtureTrust)
			creates, cas, signs := store.creates, store.cas, trust.signs
			before := contract.Hash(f.session.body)
			comparison, res := f.session.Compare(ctx, input, parent)
			if comparison != nil {
				plan, err := planTransition(t.Context(), comparison)
				if err != nil {
					t.Fatal("plan fixture")
				}
				res = f.session.prepareCompared(ctx, comparison, plan)
				if tc.name == "prepare-output-encoding" || tc.name == "prepare-input-encoding" {
					if res != tc.want || changed.exchanges != 2 || comparison.preparedRows != nil || f.session.prepared {
						t.Fatal("wrong prepared representation crossed its admission boundary", res, changed.exchanges)
					}
				}
				if res.Outcome == 0 {
					authority, err := f.session.lifecycleAuthority(t.Context(), comparison, plan)
					if err != nil {
						t.Fatal("authority fixture")
					}
					permit := &AdmittedParentTransition{session: f.session, comparison: comparison, predecessorDigest: before, predecessorRevision: f.session.head.Core.Revision, predecessorToken: f.session.token, plan: plan, authority: authority}
					candidate, result := f.session.Prepare(ctx, comparison, permit, env.Trust)
					res = result
					if candidate != nil {
						t.Fatal("changed custody response produced candidate")
					}
					if candidate, _ := f.session.Prepare(ctx, comparison, permit, env.Trust); candidate != nil {
						t.Fatal("failed preparation repeated")
					}
				}
			}
			if res != tc.want || changed.calls != 1 || store.creates != creates || store.cas != cas || trust.signs != signs {
				t.Fatalf("custody failure crossed write boundary: result=%+v calls=%d creates=%d cas=%d signs=%d", res, changed.calls, store.creates-creates, store.cas-cas, trust.signs-signs)
			}
			opened, result := Open(ctx, f.admission, env.Store)
			if opened == nil || result.Outcome != ObservedCurrent || contract.Hash(opened.body) != before {
				t.Fatal("failed custody changed selected state", result)
			}
		})
	}
}

// full_only: false
func TestExistingSecretGrantRejectsPrepareWrapUndercountBeforeWrites(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			ctx := context.Background()
			env, keys := genesisEnvironment(t, contract.GCP, recovery)
			run := newScenarioRun(t, ctx, env)
			f := newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
			authority, reader := f.session.admission.recipient, fixtureID(env.Domain, "reader")
			initial := append(f.session.currentEntryInputs(), sharingSecret(t, env, "existing grant initial", []contract.ID{authority}))
			run.suppliedSelection(f, initial)
			shared := []contract.ID{authority, reader}
			slices.SortFunc(shared, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			grant := f.session.currentEntryInputs()
			for i := range grant {
				if grant[i].Name == "secret" {
					grant[i] = sharingSecret(t, env, "existing grant equal source", shared)
				}
			}
			parent := admitSuppliedComparison(t, f.session, keys, grant)
			changed := &changedCryptoReply{inner: parent.crypto, kind: contract.CryptoPrepare, change: func(r contract.CryptoResponse) contract.CryptoResponse {
				for i := range r.KeyUseRows {
					if r.KeyUseRows[i].Purpose == contract.KeyUseMaterialWrap {
						r.KeyUseRows[i].Count--
						return r
					}
				}
				t.Fatal("grant-only preparation returned no wrap fact")
				return r
			}}
			parent.crypto = changed
			comparison, result := f.session.Compare(ctx, grant, parent)
			if comparison == nil {
				t.Fatal("existing secret grant comparison", result)
			}
			plan, err := planTransition(t.Context(), comparison)
			if err != nil {
				t.Fatal("existing secret grant plan")
			}
			slot, _ := lifecycleEntry(t, f.session, "secret")
			if !slices.Contains(comparison.changed, slot) {
				t.Fatal("existing secret grant was not classified as a membership change")
			}
			if _, fresh := plan.values[slot]; fresh {
				t.Fatal("existing secret grant was classified as fresh value material")
			}
			store := env.Store.(*memoryStore)
			trust := env.Trust.(*fixtureTrust)
			creates, cas, signs := store.creates, store.cas, trust.signs
			before := contract.Hash(f.session.body)
			result = f.session.prepareCompared(ctx, comparison, plan)
			if result != refused(AdmissionInvalid) || changed.calls != 1 || store.creates != creates || store.cas != cas || trust.signs != signs || f.session.prepared {
				t.Fatalf("grant wrap undercount crossed write boundary: result=%+v calls=%d creates=%d cas=%d signs=%d", result, changed.calls, store.creates-creates, store.cas-cas, trust.signs-signs)
			}
			if result = f.session.prepareCompared(ctx, comparison, plan); result != refused(AdmissionInvalid) || changed.calls != 1 {
				t.Fatal("failed grant preparation repeated custody work", result)
			}
			opened, result := Open(ctx, f.admission, env.Store)
			if opened == nil || result.Outcome != ObservedCurrent || contract.Hash(opened.body) != before {
				t.Fatal("failed grant preparation changed selected state", result)
			}
		})
	}
}

// full_only: false
func TestFirstSecretChecksLaterInputBeforeCustody(t *testing.T) {
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.AWS, false)
	f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	input := firstSecretInput(t, env, f.session)
	parent := admitSuppliedComparison(t, f.session, keys, input)
	public, private := keys.Calls()
	input = append(input, ApplyEntryInput{Name: "zz-invalid-source", Recipients: []contract.ID{f.session.admission.recipient}, ValueSource: format.Supplied, ConfidentialityClass: format.Secret, InputBytes: []byte{1}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
	comparison, result := f.session.Compare(ctx, input, parent)
	if comparison != nil || result != refused(InvalidIntent) || parent.used {
		t.Fatal("invalid complete request accepted", result)
	}
	if p, k := keys.Calls(); p != public || k != private {
		t.Fatal("later invalid source caused a private call")
	}
}

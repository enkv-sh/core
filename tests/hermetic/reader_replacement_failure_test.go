package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

type replacementFault struct {
	contract.Crypto
	mutate        func(contract.CryptoRequest) contract.CryptoRequest
	mutateReply   func(contract.CryptoResponse) contract.CryptoResponse
	unknown       bool
	freeze, claim int
}

func (f *replacementFault) Exchange(ctx context.Context, q contract.CryptoRequest) contract.CryptoResponse {
	if q.Kind == contract.CryptoFreeze {
		f.freeze++
	}
	if q.Kind == contract.CryptoClaim {
		f.claim++
	}
	original := q
	if f.mutate != nil {
		q = f.mutate(q)
	}
	reply := f.Crypto.Exchange(ctx, q)
	if f.mutateReply != nil {
		reply = f.mutateReply(reply)
	}
	if f.unknown && original.Kind == contract.CryptoPrepare {
		reply.ResultCode = contract.CryptoResponseUnknown
		reply.Body = nil
	}
	return reply
}

// full_only: false
func TestReaderReplacementFailedBatchesCannotActivate(t *testing.T) {
	for _, fault := range []string{"omitted", "duplicate", "reordered", "wrong-batch", "incomplete-final", "unknown-response", "cancelled", "private-route-denied", "missing-open", "missing-wrap", "extra-open", "extra-wrap"} {
		t.Run(fault, func(t *testing.T) {
			env, keys := genesisEnvironment(t, contract.GCP, true)
			run := newScenarioRun(t, context.Background(), env)
			f := newEnvironmentFixture(t, context.Background(), run.env, []int{1}, false)
			reader := fixtureID(env.Domain, "reader")
			recipients := []contract.ID{f.session.admission.recipient, reader}
			slices.SortFunc(recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			input := append(f.session.currentEntryInputs(), sharingSecretNamed(t, env, "alpha", "batch alpha", recipients), sharingSecretNamed(t, env, "beta", "batch beta", recipients))
			run.suppliedSelection(f, input)
			successor := keys.RecipientSuccessor(t, reader)
			permit := admitReaderReplacement(t, f.session, keys, reader, successor)
			defer keys.RetireAccess()
			adapter := &replacementFault{Crypto: keys.Crypto(), unknown: fault == "unknown-response"}
			permit.crypto = adapter
			adapter.mutateReply = func(reply contract.CryptoResponse) contract.CryptoResponse {
				if reply.Kind != contract.CryptoPrepare || reply.ResultCode != contract.CryptoSuccess {
					return reply
				}
				purpose := uint8(0)
				switch fault {
				case "missing-open", "extra-open":
					purpose = contract.KeyUseMaterialOpen
				case "missing-wrap", "extra-wrap":
					purpose = contract.KeyUseMaterialWrap
				}
				for i, use := range reply.KeyUseRows {
					if use.Purpose != purpose {
						continue
					}
					reply.KeyUseRows = slices.Clone(reply.KeyUseRows)
					if fault == "missing-open" || fault == "missing-wrap" {
						reply.KeyUseRows = slices.Delete(reply.KeyUseRows, i, i+1)
					} else {
						reply.KeyUseRows[i].Count++
					}
					break
				}
				return reply
			}
			adapter.mutate = func(q contract.CryptoRequest) contract.CryptoRequest {
				if q.Kind != contract.CryptoPrepare {
					return q
				}
				q.Body = bytes.Clone(q.Body)
				// OperationRef and B(ApplyContext) precede the batch fields.
				const contextLength = 1 + 4*32 + 8 + 32 + 105 + 32 + 44 + 32
				const batchOffset = 32 + 4 + contextLength
				const finalOffset = batchOffset + 4
				const countOffset = finalOffset + 1
				const rowOffset = countOffset + 4
				if len(q.Body) < rowOffset || binary.BigEndian.Uint32(q.Body[32:36]) != contextLength {
					t.Fatal("replacement batch differs from its independent framing")
				}
				switch fault {
				case "omitted", "duplicate", "reordered":
					if binary.BigEndian.Uint32(q.Body[countOffset:rowOffset]) < 2 || len(q.Body)-rowOffset < 4 {
						t.Fatal("replacement damage requires at least two framed rows")
					}
					n := binary.BigEndian.Uint32(q.Body[rowOffset : rowOffset+4])
					if uint64(n) > uint64(len(q.Body)-rowOffset-4) {
						t.Fatal("replacement first row exceeds its request")
					}
					firstEnd := rowOffset + 4 + int(n)
					if fault == "omitted" {
						q.Body = q.Body[:firstEnd]
						binary.BigEndian.PutUint32(q.Body[countOffset:rowOffset], 1)
						break
					}
					if len(q.Body)-firstEnd < 4 {
						t.Fatal("replacement second row has no length")
					}
					n = binary.BigEndian.Uint32(q.Body[firstEnd : firstEnd+4])
					if uint64(n) > uint64(len(q.Body)-firstEnd-4) {
						t.Fatal("replacement second row exceeds its request")
					}
					secondEnd := firstEnd + 4 + int(n)
					first := bytes.Clone(q.Body[rowOffset:firstEnd])
					second := bytes.Clone(q.Body[firstEnd:secondEnd])
					rest := bytes.Clone(q.Body[secondEnd:])
					q.Body = q.Body[:rowOffset]
					if fault == "duplicate" {
						q.Body = append(q.Body, first...)
						q.Body = append(q.Body, first...)
					} else {
						q.Body = append(q.Body, second...)
						q.Body = append(q.Body, first...)
					}
					q.Body = append(q.Body, rest...)
				case "wrong-batch":
					binary.BigEndian.PutUint32(q.Body[batchOffset:finalOffset], 1)
				case "incomplete-final":
					q.Body[finalOffset] = 0
				}
				return q
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if fault == "cancelled" {
				cancel()
			}
			if fault == "private-route-denied" {
				keys.SetDenied(f.session.admission.recipient, true)
			}
			creates, cas, signs := run.spy.StoreCreate, run.spy.StoreCAS, run.spy.TrustSign
			candidate, result := f.session.PrepareRecipientReplacement(ctx, permit, run.env.Trust)
			if candidate != nil || result.Outcome == ObservedCurrent || adapter.freeze != 0 || adapter.claim != 0 || run.spy.StoreCreate != creates || run.spy.StoreCAS != cas || run.spy.TrustSign != signs {
				t.Fatal("failed batch yielded a candidate or canonical effect", result)
			}
			current, result := Open(context.Background(), f.admission, run.env.Store)
			if current == nil || current.head.Core.Revision != f.session.head.Core.Revision {
				t.Fatal("failed replacement changed selection", result)
			}
		})
	}
}

// full_only: false
func TestReaderReplacementUsesOriginalConditionAfterCompetingSelection(t *testing.T) {
	env, keys := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, context.Background(), env, []int{1}, false)
	reader := fixtureID(env.Domain, "reader")
	successor := keys.RecipientSuccessor(t, reader)
	permit := admitReaderReplacement(t, f.session, keys, reader, successor)
	candidate, result := f.session.PrepareRecipientReplacement(context.Background(), permit, env.Trust)
	if candidate == nil {
		t.Fatal(result)
	}
	keys.RetireAccess()
	other, result := Open(context.Background(), f.admission, env.Store)
	if other == nil {
		t.Fatal(result)
	}
	input := other.currentEntryInputs()
	input[0].InputBytes = []byte("competing plain value")
	comparison, result := other.Compare(context.Background(), input, admitSuppliedComparison(t, other, nil, input))
	if comparison == nil {
		t.Fatal(result)
	}
	normal := admit(t, other, comparison)
	competing, result := other.Prepare(context.Background(), comparison, normal, env.Trust)
	if competing == nil {
		t.Fatal(result)
	}
	if result = other.Select(context.Background(), competing); result.Outcome != ObservedCurrent {
		t.Fatal(result)
	}
	if result = f.session.Select(context.Background(), candidate); result.Outcome != Contention || result.Reason != StalePrecondition {
		t.Fatal("stale reader replacement rebased", result)
	}
}

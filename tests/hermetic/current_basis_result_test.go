package core

import (
	"bytes"
	"context"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func sameEpochBasisFixture(t *testing.T, operation, mask uint8) (fixtureEnvironment, *environmentFixture, *Candidate, successionActors) {
	t.Helper()
	ctx := t.Context()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	if f.session.head.AuthKind != format.LifecycleAuth || f.session.root.ValueEntryCount != 1 {
		t.Fatal("basis fixture needs one ordinary plain entry")
	}
	env = syntheticAuthorityScenarioEnvironment(t, env)
	actors := env.ReplacementActors(t, ctx, f.session, operation, mask, contract.NormalSigningRole)
	permit := admitAuthorityReplacement(t, f.session, actors.Keys, actors.After, operation, contract.NormalSigningRole, mask, actors.Source)
	candidate, result := f.session.PrepareSuccession(ctx, permit, actors.Signers)
	if candidate == nil || result.Outcome != ObservedCurrent || candidate.head.Core.Epoch != f.session.head.Core.Epoch {
		t.Fatal("same-epoch candidate preparation", result)
	}
	_ = deliverSuccessionBasis(t, candidate)
	return env, f, candidate, actors
}

// full_only: false
func TestCurrentObservationKeepsCompleteBasisResult(t *testing.T) {
	for _, change := range []struct {
		name            string
		operation, mask uint8
	}{
		{"authority KEK", contract.SuccessionReplaceAuthority, contract.SuccessionChangeAuthorityKEK},
		{"recovery KEK", contract.SuccessionReplaceRecoveryBasis, contract.SuccessionChangeRecoveryKEK},
		{"recovery signer", contract.SuccessionReplaceRecoveryBasis, contract.SuccessionChangeRecoverySigner},
	} {
		t.Run(change.name, func(t *testing.T) {
			env, f, candidate, actors := sameEpochBasisFixture(t, change.operation, change.mask)
			before := f.session
			store := env.Store.(*memoryStore)
			creates, cas, signs := store.creates, store.cas, env.Trust.(*fixtureTrust).Calls()
			if observed, result := Open(t.Context(), OpenContext{admission: candidate.succession.selectionAdmission}, store); observed != nil || result != failure(EvidenceUnavailable, SigningUnavailable) {
				t.Error("successor observer misclassified ordinary predecessor basis", result)
			}
			if store.creates != creates || store.cas != cas || env.Trust.(*fixtureTrust).Calls() != signs {
				t.Fatal("out-of-basis observation reached writes or signing")
			}
			selected, result := before.selectCandidate(t.Context(), candidate)
			if selected == nil || result.Outcome != ObservedCurrent {
				t.Fatal("select exact qualified successor", result)
			}
			actors.Keys.RetireAccess()
			actors.Activate(t, selected)
			reader := fixtureID(env.Domain, "reader")
			replacement := env.Custody.RecipientSuccessor(t, reader)
			permit := admitReaderReplacement(t, selected, env.Custody, reader, replacement)
			next, result := selected.PrepareRecipientReplacement(t.Context(), permit, env.Trust)
			if next == nil {
				t.Fatal("prepare ordinary successor", result)
			}
			later, result := selected.selectCandidate(t.Context(), next)
			if later == nil || result.Outcome != ObservedCurrent || later.head.AuthKind != format.LifecycleAuth {
				t.Fatal("select ordinary successor", result)
			}
			creates, cas, signs = store.creates, store.cas, env.Trust.(*fixtureTrust).Calls()
			if observed, result := Open(t.Context(), OpenContext{admission: &before.admission}, store); observed != nil || result != failure(EvidenceUnavailable, SigningUnavailable) {
				t.Error("stale same-epoch basis became corruption or current state", result)
			}
			current, result := Open(t.Context(), OpenContext{admission: &later.admission}, store)
			if current == nil || result != later.observed(ObservedCurrent) {
				t.Fatal("current independent basis refused exact ordinary selection", result)
			}
			for _, proof := range []string{"normal binding", "authorization", "recovery binding"} {
				t.Run(proof+" signature failure", func(t *testing.T) {
					head, err := format.DecodeHead(later.body)
					if err != nil {
						t.Fatal(err)
					}
					var signature *[]byte
					switch proof {
					case "normal binding":
						signature = &head.K1
					case "authorization":
						signature = &head.AuthorizationSignature
					case "recovery binding":
						signature = &head.K3
					}
					*signature = bytes.Clone(*signature)
					(*signature)[len(*signature)-1] ^= 1
					body, err := format.EncodeHead(head)
					if err != nil {
						t.Fatal("bad signature must remain structurally valid", err)
					}
					original := store.objects[store.desc.HeadKey]
					store.put(store.desc.HeadKey, body)
					defer func() { store.objects[store.desc.HeadKey] = original }()
					if observed, result := Open(t.Context(), OpenContext{admission: &before.admission}, store); observed != nil || result != failure(IntegrityFailure, InvalidProof) {
						t.Fatal("basis mismatch concealed an actual required proof failure", result)
					}
				})
			}
			if store.creates != creates || store.cas != cas || env.Trust.(*fixtureTrust).Calls() != signs {
				t.Fatal("basis reads reached writes or signing")
			}
		})
	}
}

// full_only: false
func TestSuccessionObservationKeepsCompleteBasisResult(t *testing.T) {
	for _, change := range []struct {
		name            string
		operation, mask uint8
	}{
		{"authority KEK", contract.SuccessionReplaceAuthority, contract.SuccessionChangeAuthorityKEK},
		{"recovery KEK", contract.SuccessionReplaceRecoveryBasis, contract.SuccessionChangeRecoveryKEK},
		{"recovery signer", contract.SuccessionReplaceRecoveryBasis, contract.SuccessionChangeRecoverySigner},
	} {
		for _, condition := range []struct {
			name        string
			write       contract.WriteResult
			competing   bool
			outcome     Outcome
			possible    bool
			storeReason contract.Reason
		}{
			{"conflict", contract.WriteResult{Status: contract.WriteConflict, Reason: contract.ReasonCondition}, false, UnresolvedCommit, true, contract.ReasonNone},
			{"unknown access", contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonAccess}, false, UnresolvedCommit, true, contract.ReasonNone},
			{"not sent with concurrent ordinary selection", contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport, NotSent: true}, true, EvidenceUnavailable, false, contract.ReasonNone},
			{"unknown with concurrent ordinary selection", contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}, true, UnresolvedCommit, true, contract.ReasonTransport},
		} {
			t.Run(change.name+"/"+condition.name, func(t *testing.T) {
				env, f, candidate, _ := sameEpochBasisFixture(t, change.operation, change.mask)
				before := f.session
				if condition.competing {
					competing, result := Open(t.Context(), f.admission, env.Store)
					if competing == nil {
						t.Fatal("open competing predecessor-basis invocation", result)
					}
					input := competing.currentEntryInputs()
					input[0].InputBytes = []byte("competing predecessor-basis selection")
					compared, result := competing.Compare(t.Context(), input, admitSuppliedComparison(t, competing, nil, input))
					if compared == nil {
						t.Fatal(result)
					}
					other, result := competing.Prepare(t.Context(), compared, admit(t, competing, compared), env.Trust)
					if other == nil {
						t.Fatal(result)
					}
					if selected, result := competing.selectCandidate(t.Context(), other); selected == nil || result.Outcome != ObservedCurrent {
						t.Fatal("select competing predecessor basis", result)
					}
				}
				memory := env.Store.(*memoryStore)
				creates, cas, signs := memory.creates, memory.cas, env.Trust.(*fixtureTrust).Calls()
				store := &recordingCASStore{Store: memory}
				store.write = func(context.Context, string, contract.Token, []byte) contract.WriteResult { return condition.write }
				before.store = store
				want := Result{Outcome: condition.outcome, Reason: SigningUnavailable, RequestedRevision: candidate.head.Core.Revision,
					CommitMayHaveOccurred: condition.possible, StoreReason: condition.storeReason}
				selected, result := before.selectCandidate(t.Context(), candidate)
				if selected != nil || result != want || store.calls != 1 || memory.creates != creates || memory.cas != cas || env.Trust.(*fixtureTrust).Calls() != signs {
					t.Fatal("succession observer lost complete-basis class or repeated work", result, want, store.calls)
				}
			})
		}
	}
}

package core

import (
	"bytes"
	"context"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

func suppliedFaultFixture(t *testing.T) (fixtureEnvironment, *environmentFixture, []ApplyEntryInput) {
	t.Helper()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, context.Background(), env)
	f := newEnvironmentFixture(t, context.Background(), run.env, []int{1, 1}, false)
	input := append(f.session.currentEntryInputs(), suppliedSecret(t, env, "secret", "fault initial", custody.StandardValue), suppliedSecret(t, env, "zz-retained", "fault retained", custody.EmptyValue))
	run.suppliedSelection(f, input)
	input[0].InputBytes = []byte("changed plain")
	input[2] = suppliedSecret(t, env, "secret", "fault changed", custody.EmptyValue)
	return env, f, input
}

// full_only: false
func TestMixedSuppliedPreparationRefusesChangedComparison(t *testing.T) {
	for _, field := range []string{"relation", "source", "member", "exclusion", "length", "missing-row", "image"} {
		t.Run(field, func(t *testing.T) {
			env, f, input := suppliedFaultFixture(t)
			defer env.Custody.RetireApply()
			parent := admitSuppliedComparison(t, f.session, env.Custody, input)
			comparison, result := f.session.Compare(context.Background(), input, parent)
			if comparison == nil {
				t.Fatal(result)
			}
			permit := admit(t, f.session, comparison)
			switch field {
			case "relation":
				comparison.secretRows[0].Relation = contract.CryptoEqual
			case "source":
				comparison.secretRows[0].SourceDigest[0] ^= 1
			case "member":
				comparison.secretRows[0].BeforePublicEntryDigest[0] ^= 1
			case "exclusion":
				comparison.secretRows[0].ExclusionPathDigest[0] ^= 1
			case "length":
				comparison.secretRows[0].AfterRawLength++
			case "missing-row":
				comparison.secretRows = comparison.secretRows[:1]
			case "image":
				comparison.desiredEntries[0].InputBytes[0] ^= 1
			}
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			creates, cas, signs := store.creates, store.cas, trust.signs
			public, private := env.Custody.Calls()
			candidate, result := f.session.Prepare(context.Background(), comparison, permit, env.Trust)
			if candidate != nil || result != refused(AdmissionInvalid) || store.creates != creates || store.cas != cas || trust.signs != signs {
				t.Fatal("changed compared facts crossed preparation", result)
			}
			if p, k := env.Custody.Calls(); p != public || k != private {
				t.Fatal("changed comparison used private custody")
			}
		})
	}
}

// full_only: false
func TestMixedSuppliedPreparationFaultsKeepPredecessor(t *testing.T) {
	for _, fault := range []string{"private-route-unavailable", "readback-different", "readback-unavailable", "signing-refused"} {
		t.Run(fault, func(t *testing.T) {
			env, f, input := suppliedFaultFixture(t)
			defer env.Custody.RetireApply()
			before := sessionStateImage(t, f.session)
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			cas, signs := store.cas, trust.signs
			parent := admitSuppliedComparison(t, f.session, env.Custody, input)
			want := refused(AdmissionInvalid)
			if fault == "private-route-unavailable" {
				env.Custody.SetUnavailable(true)
				want = failure(EvidenceUnavailable, CustodyUnavailable)
			}
			comparison, result := f.session.Compare(context.Background(), input, parent)
			var candidate *Candidate
			if fault != "private-route-unavailable" {
				if comparison == nil {
					t.Fatal(result)
				}
				permit := admit(t, f.session, comparison)
				signer := env.Trust
				if fault == "signing-refused" {
					signer = &signResultTrust{Trust: env.Trust, result: contract.SignResult{Reason: contract.ReasonProof}}
					want = failure(IntegrityFailure, InvalidProof)
				} else {
					planned, r := f.session.buildSuccessor(t.Context(), comparison, permit.plan)
					if planned == nil {
						t.Fatal(r)
					}
					target := ""
					for _, object := range planned.objects {
						if object.ref.Kind == format.AccessKind {
							target = mustKey(t, store.desc.Prefix, object.ref)
						}
					}
					if target == "" {
						t.Fatal("mixed successor has no changed access page")
					}
					mode := "readback-different-equal-length"
					want = failure(IntegrityFailure, ImmutableConflict)
					if fault == "readback-unavailable" {
						mode, want = "readback-unavailable", failure(EvidenceUnavailable, ReadUnavailable)
						want.StoreReason = contract.ReasonTransport
					}
					f.session.store = &preparationFaultStore{memoryStore: store, target: target, mode: mode}
				}
				candidate, result = f.session.Prepare(context.Background(), comparison, permit, signer)
			}
			if candidate != nil || result != want || store.cas != cas || trust.signs != signs {
				t.Fatal("mixed preparation failure changed selection", result, want)
			}
			env.Custody.SetUnavailable(false)
			opened, result := Open(context.Background(), f.admission, env.Store)
			if opened == nil {
				t.Fatal(result)
			}
			assertStateImage(t, opened, before)
			env.FreshOpen(t, before)
		})
	}
}

// full_only: false
func TestMixedSuppliedFreshProcessAtEveryWriteBoundary(t *testing.T) {
	for _, mode := range []string{"acknowledged", "lost-after"} {
		t.Run(mode, func(t *testing.T) {
			env, f, input := suppliedFaultFixture(t)
			defer env.Custody.RetireApply()
			ctx := context.Background()
			before := sessionStateImage(t, f.session)
			parent := admitSuppliedComparison(t, f.session, env.Custody, input)
			comparison, result := f.session.Compare(ctx, input, parent)
			if comparison == nil {
				t.Fatal(result)
			}
			permit := admit(t, f.session, comparison)
			next, err := f.session.deriveSuccessor(ctx, comparison, permit.plan)
			if err != nil {
				t.Fatal("mixed successor fixture unavailable")
			}
			authority, err := f.session.authorityFrom(next, comparison, permit.plan)
			if err != nil {
				t.Fatal("mixed successor authority", err)
			}
			planned, result := f.session.encodeSuccessor(ctx, next, permit.plan, authority)
			if planned == nil {
				t.Fatal(result)
			}
			if len(next.root.AdministrativeIndexShards) != 0 {
				t.Fatal("mixed fresh-process fixture exceeds one administrative index shard")
			}
			after := sessionStateImage(t, next)
			after.Revision = permit.plan.revision
			after.Operation = permit.plan.operation
			after.RootRef = planned.head.Core.Root
			store := env.Store.(*memoryStore)
			selected, creates, selects := false, 0, 0
			f.session.store = boundaryStore{Store: store, after: func(method, _ string) {
				if method == "CREATE" {
					creates++
				}
				if method == "CAS" {
					selected = true
					selects++
				}
				want := before
				if selected {
					want = after
				}
				env.FreshOpen(t, want)
			}}
			originalPlain := bytes.Clone(input[0].InputBytes)
			clear(input[0].InputBytes)
			clear(input[2].InputBytes)
			candidate, result := f.session.Prepare(ctx, comparison, permit, env.Trust)
			if candidate == nil || !bytes.Equal(next.valueEntry(0).ValueBytes, originalPlain) || selected {
				t.Fatal("caller alias changed prepared mixed set", result)
			}
			env.FreshOpen(t, before)
			store.casMode = mode
			if result := f.session.Select(ctx, candidate); result.Outcome != ObservedCurrent || result.CommitMayHaveOccurred || creates != len(planned.objects) || selects != 1 {
				t.Fatal("mixed set did not cross exactly one selected boundary", result)
			}
			env.FreshOpen(t, after)
		})
	}
}

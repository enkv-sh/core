package core

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestAccessGenerationTracksChangedAccessAcrossIncarnationRollover(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for _, generation := range []uint64{1, 7, math.MaxUint64 - 1, math.MaxUint64} {
			t.Run(fmt.Sprintf("recovery=%t/generation=%d", recovery, generation), func(t *testing.T) {
				ctx := context.Background()
				env, keys := genesisEnvironment(t, contract.GCP, recovery)
				base := newEnvironmentFixture(t, ctx, env, []int{1}, false)
				f := &fixture{store: env.Store.(*memoryStore), trust: env.Trust.(*fixtureTrust), admission: base.admission, session: base.session}
				root := f.session.root
				root.CurrentAccess.Core.AccessGeneration = generation
				storeContractRoot(t, f, root, f.session.currentEntryInputs())
				opened, result := Open(ctx, f.admission, f.store)
				if opened == nil || opened.root.CurrentAccess.Core.AccessGeneration != generation {
					t.Fatal("authenticated current generation was refused", result)
				}
				f.session = opened
				beforeIncarnation := opened.root.CurrentAccess.Core.AccessIncarnationID
				if c, result := opened.Compare(ctx, opened.currentEntryInputs(), admitSuppliedComparison(t, opened, nil, opened.currentEntryInputs())); c != nil || result.Outcome != Unchanged || opened.root.CurrentAccess.Core.AccessGeneration != generation {
					t.Fatal("no-op changed access generation", result)
				}
				candidate := prepare(t, f, changed(t, opened, 0))
				if result := opened.Select(ctx, candidate); result.Outcome != ObservedCurrent {
					t.Fatal("plain selection", result)
				}
				opened, result = Open(ctx, f.admission, f.store)
				if opened == nil || opened.root.CurrentAccess.Core.AccessGeneration != generation || opened.root.CurrentAccess.AccessRoot != f.session.root.CurrentAccess.AccessRoot {
					t.Fatal("plain update changed access", result)
				}
				f.session = opened
				before, err := format.EncodeRoot(opened.root)
				if err != nil {
					t.Fatal(err)
				}
				input := firstSecretInput(t, env, opened)
				parent := admitSuppliedComparison(t, opened, keys, input)
				comparison, result := opened.Compare(ctx, input, parent)
				if comparison == nil {
					t.Fatal("secret comparison", result)
				}
				plan, err := planTransition(t.Context(), comparison)
				if err != nil {
					t.Fatal("identity plan")
				}
				if result := opened.prepareCompared(ctx, comparison, plan); result.Outcome != 0 {
					t.Fatal("private preparation", result)
				}
				permit := &AdmittedParentTransition{session: opened, comparison: comparison, predecessorDigest: contract.Hash(opened.body), predecessorRevision: opened.head.Core.Revision, predecessorToken: opened.token, plan: plan}
				permit.authority, err = opened.lifecycleAuthority(t.Context(), comparison, plan)
				if err != nil {
					t.Fatal("access generation rollover admission")
				}
				candidate, result = opened.Prepare(ctx, comparison, permit, f.trust)
				after, err := format.EncodeRoot(opened.root)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("preparation changed predecessor access")
				}
				if candidate == nil {
					t.Fatal("secret preparation", result)
				}
				if result := opened.Select(ctx, candidate); result.Outcome != ObservedCurrent {
					t.Fatal("secret selection", result)
				}
				keys.RetireApply()
				keys.SetUnavailable(true)
				f.trust.SetUnavailable(true)
				selected, result := Open(ctx, f.admission, f.store)
				wantGeneration := generation + 1
				wantNewIncarnation := false
				if generation == math.MaxUint64 {
					wantGeneration, wantNewIncarnation = 1, true
				}
				if selected == nil || selected.root.CurrentAccess.Core.AccessGeneration != wantGeneration ||
					(selected.root.CurrentAccess.Core.AccessIncarnationID != beforeIncarnation) != wantNewIncarnation ||
					selected.root.CurrentAccess.AccessRoot == opened.root.CurrentAccess.AccessRoot {
					t.Fatal("secret access generation did not advance exactly once", result)
				}
			})
		}
	}
}

// full_only: false
func TestCurrentAccessGenerationPreservesFixedControlChecks(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			env, _ := genesisEnvironment(t, contract.GCP, recovery)
			base := newEnvironmentFixture(t, context.Background(), env, []int{1}, false)
			f := &fixture{store: env.Store.(*memoryStore), trust: env.Trust.(*fixtureTrust), admission: base.admission, session: base.session}
			root := f.session.root
			root.CurrentAccess.Core.AccessGeneration = 7
			storeContractRoot(t, f, root, f.session.currentEntryInputs())
			current, result := Open(t.Context(), f.admission, f.store)
			if current == nil || result.Outcome != ObservedCurrent || current.root.CurrentAccess.Core.AccessGeneration != 7 {
				t.Fatal("valid current generation control was refused", result)
			}
			for _, field := range []string{"valid", "zero-generation", "domain", "provider", "store", "coordinate", "non-body", "interpretation", "authority", "signing", "recovery"} {
				t.Run(field, func(t *testing.T) {
					selected := *current
					control := &selected.root.CurrentAccess.Core
					switch field {
					case "zero-generation":
						control.AccessGeneration = 0
					case "domain":
						control.DomainID[0] ^= 1
					case "provider":
						control.Provider = contract.AWS
					case "store":
						control.StoreID[0] ^= 1
					case "coordinate":
						control.CoordinateID[0] ^= 1
					case "non-body":
						control.NonBodyID[0] ^= 1
					case "interpretation":
						control.TrustInterpretationID[0] ^= 1
					case "authority":
						control.AuthorityRecipientID[0] ^= 1
					case "signing":
						control.NormalSigning.Binding.Epoch++
					case "recovery":
						if recovery {
							copy := *control.Recovery
							copy.RoleID[0] ^= 1
							control.Recovery = &copy
						} else {
							control.Recovery = &contract.RecoveryBindings{}
						}
					}
					if _, err := selected.validateRelationsMode(t.Context(), false); (err == nil) != (field == "valid") {
						t.Fatal("current generation changed fixed control validation")
					}
				})
			}
		})
	}
}

// full_only: false
func TestAccessGenerationCountsAccessMeaningChanges(t *testing.T) {
	f := newFixture(t, 1, false, 1)
	for _, generation := range []uint64{7, math.MaxUint64} {
		for _, change := range []string{"none", "snapshot", "signing", "recipient-references", "both"} {
			t.Run(fmt.Sprintf("%d/%s", generation, change), func(t *testing.T) {
				before := *f.session
				before.root.CurrentAccess.Core.AccessGeneration = generation
				next := before
				switch change {
				case "snapshot":
					next.root.Snapshot[0] ^= 1
				case "signing", "both":
					next.root.CurrentAccess.Core.NormalSigning.Binding.Epoch++
				}
				if change == "recipient-references" || change == "both" {
					next.root.CurrentAccess.Core.RecipientRefsDescriptor.Digest[0] ^= 1
				}
				changed := change != "none" && change != "snapshot"
				if changed && generation == math.MaxUint64 {
					unseeded := next
					if unseeded.deriveAccess(&Comparison{session: &before}, transitionPlan{}) {
						t.Fatal("exhausted access counter advanced without a fresh transition")
					}
				}
				ok := next.deriveAccess(&Comparison{session: &before}, transitionPlan{transition: contract.Hash([]byte("fresh transition"))})
				want := generation
				if changed {
					if generation == math.MaxUint64 {
						want = 1
					} else {
						want++
					}
				}
				if !ok || next.root.CurrentAccess.Core.AccessGeneration != want || before.root.CurrentAccess.Core.AccessGeneration != generation ||
					(next.root.CurrentAccess.Core.AccessIncarnationID != before.root.CurrentAccess.Core.AccessIncarnationID) != (changed && generation == math.MaxUint64) {
					t.Fatal("generation must track access meaning exactly once")
				}
			})
		}
	}
}

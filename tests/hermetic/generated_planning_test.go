package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestGeneratedPlanningPreservesSuppliedDisplayBarrier(t *testing.T) {
	for _, condition := range []string{"equal", "pending-replacement", "display", "generated-after-supplied-selection", "later-private-source-invalid", "private-route-denied", "later-public-source-invalid", "head-advanced"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			env, keys := genesisEnvironment(t, contract.GCP, false)
			env.Context = ctx
			run := newScenarioRun(t, ctx, env)
			f := newEnvironmentFixture(t, ctx, run.env, nil, false)
			alpha := suppliedSecret(t, env, "alpha", "mixed plan alpha", custody.StandardValue)
			omega := suppliedSecret(t, env, "omega", "mixed plan omega", custody.StandardValue)
			run.suppliedSelection(f, []ApplyEntryInput{alpha, omega})
			public := comparisonCurrentInput(t, env, f.session)
			profile := defaultGeneratedFixtureProfile()
			intent := generatedFixtureCanonicalIntent(t, []byte(`{"value":"future"}`), profile)
			public.Entries.Value = append(public.Entries.Value, contract.PublicEntry{Name: "future", Class: publicPresent(contract.Secret), Source: publicPresent(contract.Generated),
				Memberships: publicPresent([]contract.ID{public.Authority.RecipientID.Value}), Generated: &contract.PublicGeneratedSettings{Epoch: publicPresent(uint64(0)),
					ConfigContractID: publicPresent(profile.ConfigContractID), ResourceContractID: publicPresent(profile.ResourceContractID), LifecycleMode: publicPresent(profile.LifecycleMode),
					ContentIntent: publicPresent(intent), Retirement: publicPresent(contract.GeneratedRetirementManual), Completion: publicPresent(contract.GeneratedCompletionAcknowledged)}})
			inputs := []contract.PlanningInput{{Name: "alpha", Form: contract.PlanningSealed, SealedInput: bytes.Clone(alpha.InputBytes)}, {Name: "omega", Form: contract.PlanningSealed, SealedInput: bytes.Clone(omega.InputBytes)}}
			if condition == "pending-replacement" {
				replacement := suppliedSecret(t, env, "omega", "mixed plan pending omega", custody.AlternateStandardValue)
				inputs[1].SealedInput = bytes.Clone(replacement.InputBytes)
			}
			if condition == "later-private-source-invalid" {
				inputs[1].SealedInput[len(inputs[1].SealedInput)-1] ^= 1
			}
			if condition == "later-public-source-invalid" {
				public.Entries.Value[len(public.Entries.Value)-1].Generated.ConfigContractID.Value = contract.ID{}
			}
			original := [][]byte{bytes.Clone(inputs[0].SealedInput), bytes.Clone(inputs[1].SealedInput)}
			validator := NewPublicConfigurationValidator(nil)
			display := custody.NewPlanningDisplay(custody.StandardValue)
			options := contract.PlanningOptions{Purpose: contract.PlanningDisplay, SelectedNames: []string{"alpha"}, SinkID: display.Identity()}
			if condition == "equal" || condition == "pending-replacement" {
				options = contract.PlanningOptions{Purpose: contract.PlanningEquality}
			}
			if condition == "generated-after-supplied-selection" {
				options.SelectedNames = []string{"alpha", "future"}
			}
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			creates, cas, signs := store.creates, store.cas, trust.signs
			publicCalls, _ := keys.Calls()
			observed := f.session.root.Snapshot
			factories := 0
			planner, candidate, _ := installedPlanningFixture(t, env, f.session, public, inputs, func(c context.Context, q contract.PlanningAdmission) (PlanningCustody, error) {
				factories++
				if len(q.Targets) != 2 || q.Targets[0].Input.Name != "alpha" || q.Targets[1].Input.Name != "omega" || q.SnapshotID != observed {
					t.Fatal("mixed plan changed fixed supplied scope")
				}
				if condition == "head-advanced" {
					replacement := suppliedSecret(t, env, "omega", "mixed plan later selected omega", custody.AlternateStandardValue)
					run.suppliedSelection(f, []ApplyEntryInput{alpha, replacement})
					creates, cas, signs = store.creates, store.cas, trust.signs
					publicCalls, _ = keys.Calls()
				}
				if options.Purpose == contract.PlanningDisplay {
					return env.Custody.NewPlanningDisplayCustody(c, q, display)
				}
				return env.Custody.NewPlanningCustody(c, q)
			})
			planner.reader.validator = validator
			if condition == "private-route-denied" {
				env.Custody.SetDenied(public.Authority.RecipientID.Value, true)
			}
			got := planner.Plan(ctx, fixtureID(env.Domain, "mixed generated planning request"), public, inputs, options)
			planner.Close()
			if store.creates != creates || store.cas != cas || trust.signs != signs {
				t.Fatal("planning mutated or signed state")
			}
			if calls, _ := keys.Calls(); calls != publicCalls {
				t.Fatal("planning qualified a private/public key for generated work")
			}
			if !bytes.Equal(inputs[0].SealedInput, original[0]) || !bytes.Equal(inputs[1].SealedInput, original[1]) {
				t.Fatal("planning changed captured source bytes")
			}
			success := condition == "equal" || condition == "pending-replacement" || condition == "display" || condition == "head-advanced"
			if success {
				if got.StateResult != contract.ReaderSuccess || got.Verdict != contract.ComparisonMismatch || !got.PrivateComplete || got.Observation == nil || got.Observation.SnapshotID != observed || len(got.GeneratedEntries) != 1 || got.GeneratedEntries[0].Name != "future" || got.GeneratedEntries[0].Action != contract.GeneratedPlanningCreate || len(got.PrivateEntries) != 2 || factories != 1 {
					t.Fatal("supported mixed plan did not complete at its fixed observation", got.StateResult, got.Verdict, factories)
				}
				wantOmega := contract.PlanningEqual
				if condition == "pending-replacement" {
					wantOmega = contract.PlanningChanged
				}
				if got.PrivateEntries[0].Relation != contract.PlanningEqual || got.PrivateEntries[1].Relation != wantOmega {
					t.Fatal("supplied equality/replacement semantics changed", got.PrivateEntries)
				}
				if options.Purpose == contract.PlanningDisplay && (got.DisplayDelivery != contract.PlanningDeliveryComplete || got.CompletedRecords != 1 || display.Acquisitions != 1 || display.Records != 1 || display.Closes != 1 || !display.Cleared() || !slices.Equal(display.Names, []string{"alpha"})) {
					t.Fatal("unavailable future generated content prevented real supplied display")
				}
				if condition == "head-advanced" && f.session.root.Snapshot == observed {
					t.Fatal("fixture did not advance HEAD")
				}
			} else {
				if got.StateResult == contract.ReaderSuccess || got.Verdict != contract.ComparisonUnable || got.PrivateComplete || display.Acquisitions != 0 || display.Records != 0 || display.Closes != 0 || got.CompletedRecords != 0 {
					t.Fatal("failed later check crossed the first-output barrier", got.StateResult, condition)
				}
				if condition == "generated-after-supplied-selection" && (factories != 0 || len(candidate.calls) != 0) {
					t.Fatal("generated selector reached public/private acquisition")
				}
			}
		})
	}
}

// full_only: false
func TestGeneratedPlanningUsesFixedObservationWithoutEffects(t *testing.T) {
	ctx, cancel, env, selected, public := comparisonGeneratedFixture(t)
	defer cancel()
	validator := NewPublicConfigurationValidator(nil)
	for _, epoch := range []uint64{0, 1, 2} {
		t.Run(fmt.Sprint(epoch), func(t *testing.T) {
			desired := ownPublicConfiguration(public)
			for at := range desired.Entries.Value {
				if desired.Entries.Value[at].Name == "generated" {
					desired.Entries.Value[at].Generated.Epoch.Value = epoch
				}
			}
			reader, _, _ := readerEngineFixture(t, env, selected)
			reader.validator = validator
			defer readerCapacityNoEffects(t, env)()
			got := reader.Compare(ctx, fixtureID(env.Domain, fmt.Sprintf("generated observed plan %d", epoch)), desired)
			if got.StateResult != contract.ReaderSuccess || got.Observation == nil || got.Observation.SnapshotID != selected.root.Snapshot || len(got.GeneratedEntries) != 1 {
				t.Fatal("complete generated observation missing", got.StateResult)
			}
			row := got.GeneratedEntries[0]
			entry := selected.valueEntry(namedSlot(t, selected, "generated"))
			if row.Name != "generated" || row.CurrentEpoch != 1 || row.RequestedEpoch != epoch || row.CurrentIncarnation != entry.Incarnation || row.CurrentGeneration != entry.Generated.GenerationID {
				t.Fatal("planning identities do not describe exact selected generation")
			}
			if epoch == 1 && (row.Action != contract.GeneratedPlanningUnchanged || got.Verdict != contract.ComparisonMatch || row.Blockers != 0) || epoch != 1 && (row.Action != contract.GeneratedPlanningRotate || got.Verdict != contract.ComparisonMismatch) || epoch == 0 && row.Blockers&contract.GeneratedPlanningStaleEpoch == 0 {
				t.Fatal("requested epoch meaning differs", row.Action, row.Blockers)
			}
			planner, _, _ := installedPlanningFixture(t, env, selected, desired, nil, func(context.Context, contract.PlanningAdmission) (PlanningCustody, error) {
				t.Fatal("generated-only plan acquired private custody")
				return nil, nil
			})
			planner.reader.validator = validator
			private := planner.Plan(ctx, fixtureID(env.Domain, fmt.Sprintf("generated-only private plan %d", epoch)), desired, nil, contract.PlanningOptions{Purpose: contract.PlanningEquality})
			planner.Close()
			if private.StateResult != contract.ReaderSuccess || !private.PrivateComplete || len(private.PrivateEntries) != 0 || private.Observation == nil || private.Observation.SnapshotID != selected.root.Snapshot || !slices.Equal(private.GeneratedEntries, got.GeneratedEntries) {
				t.Fatal("unavailable generated content invalidated empty supported private scope")
			}
		})
	}
}

// full_only: false
func TestPublicGeneratedVisitorFailureDiscardsProvisionalSelection(t *testing.T) {
	for _, condition := range []string{"unavailable", "capacity", "invalid", "cancelled", "outer-admission-invalid"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			env, _ := genesisEnvironment(t, contract.GCP, false)
			f := newEnvironmentFixture(t, ctx, env, nil, false)
			reader, _, source := readerEngineFixture(t, env, f.session)
			inv := readerInvocationFixture(t, reader, ctx)
			defer readerCapacityNoEffects(t, env)()
			visits := 0
			selected, failed := inv.loadPublicSelection(ctx, contract.ReaderCompareOperation, inv.admission.request, func(_ context.Context, g *generatedSelection) error {
				visits++
				if g == nil || g.image == nil || g.image.root.Snapshot != f.session.root.Snapshot {
					t.Fatal("visitor did not receive the authenticated fixed selection")
				}
				switch condition {
				case "unavailable":
					return selectedReadFailure(failure(EvidenceUnavailable, MissingSelectedObject))
				case "capacity":
					return contract.ErrRecordCapacity
				case "invalid":
					return contract.ErrRecord
				case "cancelled":
					cancel()
				case "outer-admission-invalid":
					inv.admission.issued = false
				}
				return nil
			})
			if visits != 1 || failed.Outcome == 0 || selected.complete || inv.selection.complete || len(selected.image.root.Names) != 0 {
				t.Fatal("failed visitor/outer load published provisional selection", visits, failed)
			}
			if condition == "unavailable" && (failed.Result != failure(EvidenceUnavailable, MissingSelectedObject) || failed.diagnostic != contract.ReasonSelectedObjectUnavailable) {
				t.Fatal("selected-read failure was flattened", failed)
			}
			if condition == "capacity" && (failed.Result != refused(CapacityExceeded) || failed.diagnostic != contract.ReasonLimitExceeded) {
				t.Fatal("capacity failure was flattened", failed)
			}
			if condition == "invalid" && failed.Result != failure(IntegrityFailure, InvalidRelation) {
				t.Fatal("invalid visitor did not refuse integrity", failed)
			}
			inv.Close()
			if source.closes != 1 {
				t.Fatal("failed read was not joined exactly once", source.closes)
			}
		})
	}
}

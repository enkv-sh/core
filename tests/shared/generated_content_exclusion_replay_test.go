package core

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestGeneratedContentExclusionCheckpointReplaysExactProtection(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for _, supplied := range []bool{false, true} {
			t.Run(fmt.Sprintf("recovery=%t/supplied=%t", recovery, supplied), func(t *testing.T) {
				env, keys := genesisEnvironment(t, contract.GCP, recovery)
				env = syntheticAuthorityScenarioEnvironment(t, env)
				run := newScenarioRun(t, t.Context(), env)
				f := newEnvironmentFixture(t, t.Context(), run.env, nil, false)
				readers := []contract.ID{f.session.admission.recipient, fixtureID(env.Domain, "reader")}
				slices.SortFunc(readers, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
				var before *StateSession
				if supplied {
					entry := suppliedSecret(t, env, "generated", "shared supplied predecessor", custody.StandardValue, readers...)
					before = run.suppliedSelection(f, []ApplyEntryInput{entry})
				} else {
					initial := generatedPlanInputForGenerationsMembershipIntent(t, f.session, testID(t.Name()+" original"), []string{"generated"}, readers,
						[]byte(`{"name":"generated"}`), defaultGeneratedFixtureProfile())
					before = selectPrivateGeneratedOperationInProcess(t, env, f.session, initial, "shared generated predecessor")
				}
				old := ownScenarioValueEntry(*before.valueEntry(0))
				epoch := old.Generated.Epoch + 1
				incarnations, retiring := map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: old}
				if supplied {
					epoch, incarnations, retiring = 0, nil, nil
				}
				input := generatedStatePlanInput(t, before, testID(t.Name()+" rotation"), []string{old.Name}, defaultGeneratedFixtureProfile(), epoch, incarnations, retiring)
				oldMembership, err := contract.GeneratorIntendedMembershipDescriptor(old.Recipients)
				if err != nil || input.graph.Request.OperationKind != contract.OperationApplyDeclaration || len(input.graph.ValueEntryPlans) != 1 ||
					input.graph.ValueEntryPlans[0].Name != old.Name || input.graph.ValueEntryPlans[0].ChangeMask != contract.GeneratorValueChangeContent ||
					input.graph.ValueEntryPlans[0].IntendedMembership == oldMembership {
					t.Fatal("generated Content removal must change declared readers in ApplyDeclaration", err)
				}
				input.graph.ValueEntryPlans[0].ChangeMask |= contract.GeneratorValueChangeMembership
				input.graph.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(input.graph.Header, input.graph.ValueEntryPlans, input.graph.Lineages, input.graph.Edges)
				if err != nil || contract.ValidateGeneratorEffectGraph(input.graph) != nil {
					t.Fatal("generated Content and Membership graph", err)
				}
				prior, _ := preparePrivateGeneratedReservation(t, env, before, input, nil)
				recorded, _, _, _ := selectActualGeneratedPacketRecord(t, env, before, prior, custody.StandardValue, true, nil)
				ctx := generatedPlanInputFixture(t, recorded).context
				ctx.AdmissionID, ctx.SessionID = testID(t.Name()+" fresh final"), testID(t.Name()+" fresh session")
				plan, err := recorded.generatedFinalRequest(t.Context(), ctx)
				if err != nil {
					t.Fatal(err)
				}
				checkpoint, final := preparePrivateGeneratedFinal(t, env, recorded, plan)
				objects := checkpointArtifactBodies(t, checkpoint, final.reservation.candidate)
				keys.RetireGenerated()
				checkpoint = generatedLifecycleReopen(t, t.Context(), checkpoint, env.Store)
				ctx = generatedPlanInputFixture(t, checkpoint).context
				ctx.AdmissionID, ctx.SessionID = testID(t.Name()+" replay"), testID(t.Name()+" replay session")
				plan, err = checkpoint.generatedFinalRequest(t.Context(), ctx)
				if err != nil || plan.materialization == nil {
					t.Fatal("fresh generated exclusion image not reusable", err)
				}
				checkpoint, replayed := preparePrivateGeneratedFinal(t, env, checkpoint, plan)
				opens := uint32(0)
				for _, use := range replayed.keyUses {
					if use.Purpose == contract.KeyUseMaterialOpen {
						if use.Outcome != contract.KeyUseCompleted {
							t.Fatal("generated replay source open did not complete")
						}
						opens += use.Count
					}
				}
				if opens != 3 {
					t.Fatal("generated exclusion replay must open seed, saved value and old current packet", opens)
				}
				if !reflect.DeepEqual(objects, checkpointArtifactBodies(t, checkpoint, replayed.reservation.candidate)) {
					t.Fatal("generated replay changed immutable Final bytes")
				}
				selected, result := checkpoint.selectCandidate(t.Context(), replayed.reservation.candidate)
				if selected == nil || result.Outcome != ObservedCurrent {
					t.Fatal(result)
				}
				selected = generatedLifecycleReopen(t, t.Context(), selected, env.Store)
				current := selected.valueEntry(0)
				if current == nil {
					t.Fatal("generated current value absent")
				}
				oldPayload, err := contract.InspectCanonicalPayload(old.ValueBytes)
				if err != nil {
					t.Fatal(err)
				}
				payload, err := contract.InspectCanonicalPayload(current.ValueBytes)
				if err != nil {
					t.Fatal(err)
				}
				if supplied && current.Incarnation == old.Incarnation || current.ValueState == old.ValueState || current.OriginSnapshot == old.OriginSnapshot || current.OriginTransition == old.OriginTransition ||
					payload.DataKeyID == oldPayload.DataKeyID || payload.DataKeyID == oldPayload.CommitmentKeyID || payload.CommitmentKeyID == oldPayload.DataKeyID || payload.CommitmentKeyID == oldPayload.CommitmentKeyID ||
					bytes.Equal(payload.Ciphertext, oldPayload.Ciphertext) || payload.SemanticCommitment == oldPayload.SemanticCommitment || !slices.Equal(current.Recipients, []contract.ID{selected.admission.recipient}) {
					t.Fatal("generated Content removal reused old protection or membership")
				}
				if check := keys.Consume(t.Context(), sessionConsumerSelection(t, selected, selected.admission.recipient, current.Name), custody.StandardValue); check.Code != contract.CryptoSuccess || !check.ValueMatched || check.Delivery != 1 {
					t.Fatal("replayed generated result semantic value", check)
				}
				keys.RetireGenerated()
			})
		}
	}
}

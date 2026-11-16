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

func assertGeneratedWriterState(t *testing.T, s *StateSession, intents map[string][]byte) {
	t.Helper()
	work := mustSelectedGeneratedWork(t, s)
	if int(s.root.ValueEntryCount) != len(intents) || int(s.root.Generated.GeneratedCurrent) != len(intents) ||
		len(s.root.Names) != len(intents) || !s.root.Generated.ActiveOwner.IsZero() {
		t.Fatal("writer complete current set differs")
	}
	binding := *s.authority().CurrentBinding
	for _, row := range s.root.Names {
		intent, exists := intents[row.Name]
		entry := s.valueEntry(row.Slot)
		id, err := contract.GeneratorIntentDigest(hermeticGeneratorIntent(intent))
		if !exists || err != nil || entry.Generated.IntentDigest != id {
			t.Fatal("writer current identity differs", row.Name, err)
		}
		actual, err := work.readSelectedSlice(t.Context(), contract.GeneratorContentIntent, id, contract.GeneratorIntentMaxLength)
		if err != nil || !bytes.Equal(actual, hermeticGeneratorIntent(intent)) {
			t.Fatal("writer current intent differs", row.Name, err)
		}
		checkSuccessorConsumer(t, s, successorConsumerInput{Name: row.Name, Value: custody.StandardValue,
			Binding: contract.BindingTableRow{SubjectKind: 1, SubjectID: s.admission.recipient, Binding: binding}})
	}
}

func closeGeneratedWriterRetirement(t *testing.T, env fixtureEnvironment, s *StateSession, name string, operation contract.ID) *StateSession {
	t.Helper()
	work := mustSelectedGeneratedWork(t, s)
	var entry *contract.ValueEntry
	for _, row := range s.root.Names {
		if row.Name == name {
			entry = s.valueEntry(row.Slot)
		}
	}
	if entry == nil || entry.Generated.RetiringDutyPresent != 1 {
		t.Fatal("writer old resource has no exact retirement")
	}
	dutyRow := work.records[generatedRecordKey{contract.GeneratedDutySupportKind, entry.Generated.RetiringDutyID}]
	duty, err := contract.InspectGeneratedDutyRecord(dutyRow.Body)
	if err != nil {
		t.Fatal("writer retirement Duty", err)
	}
	target, err := work.retirementTarget(t.Context(), duty)
	if err != nil {
		t.Fatal("writer retirement target", err)
	}
	input, inputCanonical := generatedDeletePlanInput(t, s, operation, duty, target, contract.GeneratorLineageRetirement)
	prior, _ := preparePrivateGeneratedReservation(t, env, s, input, inputCanonical)
	recorded, _, expected, _ := selectActualGeneratedPacketRecord(t, env, s, prior, custody.StandardValue, true, nil)
	permit, err := recorded.admitGeneratedRetirementClose(t.Context(), expected.Template.AttemptID, generatedPlanInputFixture(t, recorded).context)
	if err != nil {
		t.Fatal("writer retirement close", err)
	}
	candidate, result := recorded.PrepareGeneratedLifecycle(t.Context(), permit, env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("writer retirement close preparation", result)
	}
	closed, result := recorded.selectCandidate(t.Context(), candidate)
	if closed == nil || result.Outcome != ObservedCurrent || closed.root.Generated.Retiring != 0 {
		t.Fatal("writer retirement close selection", result)
	}
	env.Custody.RetireGenerated()
	return generatedLifecycleReopen(t, t.Context(), closed, env.Store)
}

// full_only: false
func TestGeneratedWriterReferencesCompleteSmallFreshProcessCycles(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("recovery%t", recovery), func(t *testing.T) {
			env, _ := genesisEnvironment(t, contract.GCP, recovery)
			fixture := newEnvironmentFixture(t, t.Context(), env, nil, false)
			s := fixture.session
			store := env.Store.(*memoryStore)
			if err := store.useFileBodies(t.TempDir() + "/bodies"); err != nil {
				t.Fatal(err)
			}
			intents := map[string][]byte{"alpha": hermeticGeneratorIntent([]byte("alpha intent first")), "beta": hermeticGeneratorIntent([]byte("beta intent first"))}
			first := generatedWriterPlanInput(t, s, fixtureID(env.Domain, "small writer first"), []string{"alpha"},
				func(name string) []byte { return intents[name] }, 0, nil)
			s = selectPrivateGeneratedOperationInProcess(t, env, s, first, "small writer first")
			s = generatedLifecycleReopen(t, t.Context(), s, env.Store)
			assertGeneratedWriterState(t, s, map[string][]byte{"alpha": intents["alpha"]})
			old := *s.valueEntry(0)
			s = selectFreshGeneratedWriter(t, store, s, fixtureID(env.Domain, "small writer add"), "beta", intents["beta"], 0)
			if !reflect.DeepEqual(*s.valueEntry(0), old) {
				t.Fatal("carried alpha value identity changed")
			}
			assertGeneratedWriterState(t, s, intents)
			checkFreshGeneratedProcess(t, store, s)
			for epoch := uint64(2); epoch <= 3; epoch++ {
				beta := *s.valueEntry(1)
				oldAlpha := *s.valueEntry(0)
				intents["alpha"] = hermeticGeneratorIntent([]byte(fmt.Sprintf("alpha intent replacement %d", epoch)))
				s = selectFreshGeneratedWriter(t, store, s, fixtureID(env.Domain, fmt.Sprintf("small writer replacement %d", epoch)),
					"alpha", intents["alpha"], epoch)
				alpha := *s.valueEntry(0)
				if alpha.Incarnation != oldAlpha.Incarnation || alpha.Generated.Epoch != epoch || alpha.ValueState == oldAlpha.ValueState ||
					!reflect.DeepEqual(*s.valueEntry(1), beta) || alpha.Generated.RetiringDutyPresent != 1 {
					t.Fatal("writer replacement identities differ")
				}
				assertGeneratedWriterState(t, s, intents)
				s = closeGeneratedWriterRetirement(t, env, s, "alpha", fixtureID(env.Domain, fmt.Sprintf("small writer retirement %d", epoch)))
				assertGeneratedWriterState(t, s, intents)
				work := mustSelectedGeneratedWork(t, s)
				if _, retained := work.content.locations[generatedContentKey{contract.GeneratorContentIntent, oldAlpha.Generated.IntentDigest}]; retained {
					t.Fatal("closed old resource retained its dead intent")
				}
				checkFreshGeneratedProcess(t, store, s)
			}
			// Carry-only work uses the ordinary no-op and access paths.
			input := s.currentEntryInputs()
			parent := admitSuppliedComparison(t, s, env.Custody, input)
			cas := store.cas
			if c, result := s.Compare(t.Context(), input, parent); c != nil || result.Outcome != Unchanged || store.cas != cas {
				t.Fatal("writer current set no-op", result)
			}
			env.Custody.RetireApply()
			input[0].Recipients = append(input[0].Recipients, fixtureID(env.Domain, "reader"))
			slices.SortFunc(input[0].Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			parent = admitSuppliedComparison(t, s, env.Custody, input)
			comparison, result := s.Compare(t.Context(), input, parent)
			if comparison == nil {
				t.Fatal("writer current access comparison", result)
			}
			candidate, result := s.Prepare(t.Context(), comparison, admit(t, s, comparison), env.Trust)
			if candidate == nil {
				t.Fatal("writer current access preparation", result)
			}
			s, result = s.selectCandidate(t.Context(), candidate)
			if s == nil || result.Outcome != ObservedCurrent {
				t.Fatal("writer current access selection", result)
			}
			env.Custody.RetireApply()
			s = generatedLifecycleReopen(t, t.Context(), s, env.Store)
			assertGeneratedWriterState(t, s, intents)
			checkFreshGeneratedProcess(t, store, s)
		})
	}
}

package core

import (
	"maps"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGeneratedSelectedParentEndsOnlyItsCreateSourceConsumers(t *testing.T) {
	for _, canonical := range []bool{false, true} {
		name := "sealed"
		if canonical {
			name = "canonical"
		}
		t.Run(name, func(t *testing.T) {
			var state *StateSession
			var independent contract.GeneratorConsumer
			if canonical {
				var consumers []contract.GeneratorConsumer
				state, _, consumers = generatedCanonicalState(t, false)
				independent = consumers[len(consumers)-1]
			} else {
				state = generatedReservationState(t, generatedSealedSource(t, "alpha"))
			}
			selected := mustSelectedGeneratedWork(t, state)
			for _, anchored := range []bool{false, true} {
				facts := *selected
				phase := *facts.phase
				facts.phase = &phase
				if anchored {
					phase.SelectionPhaseID = generatedVectorID(245)
					var err error
					phase.ChangedSubjects, err = contract.ChangedSubjectDescriptor(nil)
					if err != nil {
						t.Fatal(err)
					}
					phase.ChangedAccess, err = contract.AccessChangeDescriptor(state.root.Domain, nil)
					if err != nil {
						t.Fatal(err)
					}
				}
				facts.records = maps.Clone(facts.records)
				facts.sources = make(map[contract.ID][]contract.GeneratorSourceUse)
				facts.protected = make(map[contract.ID][]byte)
				facts.canonical = make(map[contract.ID]generatedCanonical)
				facts.consumers = make(map[materialIdentity][]contract.GeneratorConsumer)
				for key := range facts.records {
					if key.kind == contract.RetainedCanonicalSupportKind {
						delete(facts.records, key)
					}
				}
				content, err := newGeneratedContentValidation(t.Context(), state)
				if err != nil {
					t.Fatal("selected source locations", err)
				}
				for key := range content.facts.locations {
					if key.kind == contract.GeneratorContentSource || key.kind == contract.GeneratorContentConfiguration {
						delete(content.facts.locations, key)
					}
				}
				facts.content = content.facts
				builder := &generatedSelectionBuilder{facts: &facts, content: content, claimed: make(map[generatedRecordKey]bool)}
				if canonical {
					err = builder.resolveActiveCanonicals()
				} else {
					err = builder.resolveActiveSources()
				}
				if (err == nil) != anchored {
					t.Fatal("CREATE source lifetime did not follow canonical selection", anchored, err)
				}
				if len(facts.sources) != 0 || len(facts.protected) != 0 || len(facts.canonical) != 0 || len(facts.consumers) != 0 {
					t.Fatal("historical CREATE declaration acquired live source ownership")
				}
				if anchored && canonical {
					if err := builder.claimCanonicalConsumer(contract.GeneratedDutySupportKind, independent.OwnerID, false, independent); err == nil {
						t.Fatal("selected Parent excused a missing independent Duty source")
					}
				}
			}
		})
	}
}

// full_only: false
func TestGeneratedSelectionAccessCommitmentIgnoresUnchangedTemporarySeed(t *testing.T) {
	before := generatedReservationState(t)
	seed := before.access[0].Records[0]
	if seed.MaterialKind != contract.OperationSeedMaterialKind {
		t.Fatal("reservation fixture has no shared Parent seed")
	}
	value := seed
	value.MaterialKind, value.MaterialID = contract.ValueMaterialKind, generatedVectorID(244)
	before.access[0] = &format.AccessPage{Records: []contract.AccessRecord{value, seed}}
	before.root.AccessRecordCount = 2
	changed := value
	changed.Wraps = slices.Clone(value.Wraps)
	changed.Wraps[0].RSACiphertext = slices.Clone(value.Wraps[0].RSACiphertext)
	changed.Wraps[0].RSACiphertext[0] ^= 1
	selected := *before
	selected.access[0] = &format.AccessPage{Records: []contract.AccessRecord{changed, seed}}
	frozen, err := generatedFinalChangedAccess(before, &selected)
	want, wantErr := contract.AccessChangeDescriptor(before.root.Domain, []contract.AccessChangeRow{{Before: value, After: changed}})
	if err != nil || wantErr != nil || frozen != want || frozen.Count != 1 {
		t.Fatal("frozen access omitted the real surviving-value change or included the unchanged seed", err, wantErr)
	}
	terminal := selected
	terminal.access[0] = &format.AccessPage{Records: []contract.AccessRecord{changed}}
	terminal.root.AccessRecordCount = 1
	afterRemoval, err := generatedFinalChangedAccess(before, &terminal)
	if err != nil || afterRemoval != frozen {
		t.Fatal("terminal whole-seed removal changed the frozen value-access commitment", err)
	}
	empty, err := contract.AccessChangeDescriptor(before.root.Domain, nil)
	if err != nil {
		t.Fatal(err)
	}
	between, err := generatedFinalChangedAccess(&selected, &terminal)
	if err != nil || between != empty {
		t.Fatal("whole-seed removal fabricated a changed-access row", err)
	}
}

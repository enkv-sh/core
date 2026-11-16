package core

import (
	"bytes"
	"maps"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedCurrentIntentSelectionRequiresExactCurrentEntry(t *testing.T) {
	s := generatedSelectedEntryState(t)
	selected, err := s.selectedGeneratedWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	current := s.valueEntry(0)
	logical := selected.content.locations[generatedContentKey{contract.GeneratorContentIntent, current.Generated.IntentDigest}].Logical()
	plan := contract.GeneratorValueEntryPlan{InputEncoding: current.InputEncoding, OutputEncoding: current.OutputEncoding, Schema: contract.GeneratorValueEntryPlanSchema, Name: current.Name, ValueSource: contract.Generated,
		ConfidentialityClass: contract.Secret, EntryIncarnationID: current.Incarnation, Epoch: current.Generated.Epoch,
		IntentDigest: current.Generated.IntentDigest, RetirementMode: current.Generated.RetirementMode}
	before := bytes.Clone(s.body)
	fact, err := s.generatedCurrentIntentSelection(t.Context(), selected, plan, logical)
	if err != nil || fact.Intent != logical || fact.Generated != current.Generated || fact.Incarnation != current.Incarnation ||
		fact.HEADDigest != contract.Hash(before) || fact.Root != s.head.Core.Root || fact.Row.Name != current.Name {
		t.Fatal("exact selected intent", err)
	}
	for name, damage := range map[string]func(*contract.GeneratorValueEntryPlan, *contract.GeneratorLogicalSlice){
		"absent name": func(p *contract.GeneratorValueEntryPlan, _ *contract.GeneratorLogicalSlice) { p.Name = "absent" },
		"slot":        func(p *contract.GeneratorValueEntryPlan, _ *contract.GeneratorLogicalSlice) { p.Slot++ },
		"incarnation": func(p *contract.GeneratorValueEntryPlan, _ *contract.GeneratorLogicalSlice) {
			p.EntryIncarnationID = generatedVectorID(250)
		},
		"lower epoch": func(p *contract.GeneratorValueEntryPlan, _ *contract.GeneratorLogicalSlice) { p.Epoch-- },
		"newer epoch": func(p *contract.GeneratorValueEntryPlan, _ *contract.GeneratorLogicalSlice) { p.Epoch++ },
		"changed intent": func(p *contract.GeneratorValueEntryPlan, _ *contract.GeneratorLogicalSlice) {
			p.IntentDigest = generatedVectorID(250)
		},
		"retirement mode": func(p *contract.GeneratorValueEntryPlan, _ *contract.GeneratorLogicalSlice) {
			p.RetirementMode = contract.GeneratedRetirementAuto
		},
		"new content": func(p *contract.GeneratorValueEntryPlan, _ *contract.GeneratorLogicalSlice) {
			p.ChangeMask = contract.GeneratorValueChangeContent
		},
		"length": func(_ *contract.GeneratorValueEntryPlan, l *contract.GeneratorLogicalSlice) { l.Length++ },
		"digest": func(_ *contract.GeneratorValueEntryPlan, l *contract.GeneratorLogicalSlice) {
			l.Digest = generatedVectorID(250)
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, l := plan, logical
			damage(&p, &l)
			if _, err := s.generatedCurrentIntentSelection(t.Context(), selected, p, l); err == nil {
				t.Fatal("different current fact admitted")
			}
			if !bytes.Equal(s.body, before) {
				t.Fatal("refusal changed selected HEAD")
			}
		})
	}
	facts := *selected.content
	facts.locations = maps.Clone(facts.locations)
	delete(facts.locations, generatedContentKey{contract.GeneratorContentIntent, current.Generated.IntentDigest})
	unselected := *selected
	unselected.content = &facts
	if _, err := s.generatedCurrentIntentSelection(t.Context(), &unselected, plan, logical); err == nil {
		t.Fatal("valid bytes outside the selected logical closure admitted")
	}
}

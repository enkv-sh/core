package contract

import (
	"testing"
)

// full_only: false
func TestGeneratorDeleteGraphPurposeTargetAndProducer(t *testing.T) {
	for _, tc := range []struct {
		name       string
		purpose    GeneratorLineagePurpose
		target     uint8
		withCreate bool
		wrongOwner bool
		want       bool
	}{
		{"external cleanup", GeneratorLineageCleanup, GeneratorTargetResultResourceSlot, false, false, true},
		{"owned retirement", GeneratorLineageRetirement, GeneratorTargetOwnedResource, false, false, true},
		{"owned cleanup", GeneratorLineageCleanup, GeneratorTargetOwnedResource, false, false, false},
		{"result-slot retirement", GeneratorLineageRetirement, GeneratorTargetResultResourceSlot, false, false, false},
		{"same-graph cleanup", GeneratorLineageCleanup, GeneratorTargetResultResourceSlot, true, false, true},
		{"same-graph owned cleanup", GeneratorLineageCleanup, GeneratorTargetOwnedResource, true, false, false},
		{"same-graph wrong producer", GeneratorLineageCleanup, GeneratorTargetResultResourceSlot, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := completeEffectGraphFixture(t, -1)
			index := -1
			var create GeneratorLineageTemplate
			for i, row := range v.Lineages {
				if row.Purpose == GeneratorLineageCreate {
					create = row
				} else if index == -1 {
					index = i
				}
			}
			if index < 0 {
				t.Fatal("fixture has no cleanup")
			}
			row := v.Lineages[index]
			if !tc.withCreate {
				row = generatorGraphDeleteFixture(t, create, 0, uint8(tc.purpose), create.Templates[0].ResourceIncarnationID)
				v.ValueEntryPlans, v.Lineages = nil, []GeneratorLineageTemplate{row}
				v.Header.ValueEntryPlanCount, v.Header.LineageCount, v.Header.TemplateCount = 0, 0, 1
				index = 0
			}
			x := &row.Templates[0]
			x.TargetKind = tc.target
			if tc.target == GeneratorTargetOwnedResource {
				x.TargetSourceID = x.ResourceIncarnationID
				x.ResourceDigest = generatedRecordID(11)
			}
			if tc.wrongOwner {
				x.DutyID = generatedRecordID(250)
			}
			var err error
			x.RequestPlanDigest, err = GeneratorRequestPlanDigest(*x)
			if err != nil {
				t.Fatal("target recipe", err)
			}
			if _, err := EncodeGeneratorLineageTemplate(row); err != nil {
				t.Fatal("target relation must reach graph validation", err)
			}
			v.Lineages[index] = row
			v.Edges = generatorGraphEdgesFixture(t, v.Header, v.Lineages)
			v.ResultUses = generatorGraphUsesFixture(v.Header, v.Lineages)
			v.UsePlan.ResultUses, err = GeneratorResultUsesDescriptor(v.ResultUses)
			if err != nil {
				t.Fatal(err)
			}
			graph, graphErr := GeneratorGraphID(v.Header, v.ValueEntryPlans, v.Lineages, v.Edges)
			if graphErr == nil {
				v.UsePlan.PlanGraphID = graph
			}
			_, bundleErr := GeneratorPlanBundleLength(v)
			effectErr := ValidateGeneratorEffectGraph(v)
			for _, boundary := range []struct {
				name string
				err  error
			}{{"graph identity", graphErr}, {"complete carrier", bundleErr}, {"effect admission", effectErr}} {
				if (boundary.err == nil) != tc.want {
					t.Errorf("%s: accepted=%t, want %t: %v", boundary.name, boundary.err == nil, tc.want, boundary.err)
				}
			}
		})
	}
}

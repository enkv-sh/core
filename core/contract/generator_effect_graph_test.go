package contract

import (
	"slices"
	"testing"
)

func completeEffectGraphFixture(t *testing.T, omitted int) GeneratorPlanBundle {
	t.Helper()
	v := generatorBundleFixture(t, true)
	create := v.Lineages[0]
	for branch := range 5 {
		if branch != omitted {
			v.Lineages = append(v.Lineages, generatorGraphDeleteFixture(t, create, uint8(branch), 3, create.Templates[branch].ResourceIncarnationID))
		}
	}
	slices.SortFunc(v.Lineages, generatorLineageCompare)
	v.Header.TemplateCount = uint16(5 + len(v.Lineages) - 1)
	v.Edges = generatorGraphEdgesFixture(t, v.Header, v.Lineages)
	v.ResultUses = generatorGraphUsesFixture(v.Header, v.Lineages)
	var err error
	v.UsePlan.PlanGraphID, err = GeneratorGraphID(v.Header, v.ValueEntryPlans, v.Lineages, v.Edges)
	if err != nil {
		t.Fatal(err)
	}
	v.UsePlan.ResultUses, err = GeneratorResultUsesDescriptor(v.ResultUses)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// full_only: false
func TestGeneratorEffectGraphRequiresEveryCreateCleanup(t *testing.T) {
	complete := completeEffectGraphFixture(t, -1)
	if err := ValidateGeneratorEffectGraph(complete); err != nil {
		t.Fatal("complete reachable cleanup", err)
	}
	for branch := range 5 {
		incomplete := completeEffectGraphFixture(t, branch)
		if _, err := GeneratorPlanBundleLength(incomplete); err != nil {
			t.Fatal("structural fixture is invalid", err)
		}
		if err := ValidateGeneratorEffectGraph(incomplete); err == nil {
			t.Fatal("effect admission omitted cleanup", branch)
		}
	}
	if err := ValidateGeneratorEffectGraph(generatorBundleFixture(t, true)); err == nil {
		t.Fatal("create-only graph admitted")
	}
	for _, damage := range []func(*GeneratorPlanBundle){
		func(v *GeneratorPlanBundle) { v.ResultUses = v.ResultUses[:len(v.ResultUses)-1] },
		func(v *GeneratorPlanBundle) { v.Edges = v.Edges[:len(v.Edges)-1] },
		func(v *GeneratorPlanBundle) { v.UsePlan.PlanGraphID[0] ^= 1 },
		func(v *GeneratorPlanBundle) { v.Lineages[1].Templates[0].DutyID[0] ^= 1 },
		func(v *GeneratorPlanBundle) { v.Lineages[1].Templates[0].ResourceIncarnationID[0] ^= 1 },
	} {
		bad := completeEffectGraphFixture(t, -1)
		damage(&bad)
		if err := ValidateGeneratorEffectGraph(bad); err == nil {
			t.Fatal("changed cleanup closure admitted")
		}
	}
	if err := ValidateGeneratorEffectGraph(generatorBundleFixture(t, false)); err != nil {
		t.Fatal("no create has no cleanup dependency", err)
	}
}

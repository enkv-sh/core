package compositionfull

import (
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedLocalRejectsValidRemoteFacts(t *testing.T) {
	for _, owner := range []string{"effect", "create Duty"} {
		for _, field := range []string{"target", "progress"} {
			t.Run(owner+"/"+field, func(t *testing.T) {
				r := localResultList()
				effect, duty := localResultEffect(), localResultDuty()
				r.View.Effects = []core.GeneratedEffectFact{effect}
				r.View.Duties = []core.GeneratedDutyFact{duty}
				if body, err := RenderGeneratedListJSON(r); err != nil || len(body) == 0 {
					t.Fatal("valid local facts refused", err)
				}

				target := generatedRendererTarget()
				target.ResourceID, target.ConfigContractID, target.ResourceContractID = effect.Record.ResourceID, effect.Record.ConfigContractID, effect.Record.ResourceContractID
				target.LifecycleMode, target.ResourceDigest, target.CompletionClass = contract.GeneratorLifecycleNone, contract.ID{}, 0
				progress := []contract.GeneratorProgress{{
					Schema: 1, AttemptID: effect.Record.AttemptID, ResultID: effect.Record.ResultID,
					Evidence:      contract.EmptyGeneratorVector(contract.GeneratorVectorProofs),
					RequiredSteps: 1, CompletedSteps: 1, CompletionClass: 1,
				}}
				switch field {
				case "target":
					if !validGeneratedTarget(&target, effect.Record.ResourceID, effect.Record.ConfigContractID, effect.Record.ResourceContractID, effect.Record.LifecycleMode) ||
						!validGeneratedTarget(&target, duty.Record.ResourceID, duty.Record.ConfigContractID, duty.Record.ResourceContractID, duty.Record.LifecycleMode) {
						t.Fatal("target must pass general validation before the local absence check")
					}
				case "progress":
					if !validGeneratedProgress(progress) {
						t.Fatal("progress must pass general validation before the local absence check")
					}
				}
				switch owner + "/" + field {
				case "effect/target":
					r.View.Effects[0].Target = &target
				case "effect/progress":
					r.View.Effects[0].Progress = progress
				case "create Duty/target":
					r.View.Duties[0].Target = &target
				case "create Duty/progress":
					r.View.Duties[0].Progress = progress
				}
				if body, err := RenderGeneratedListJSON(r); err == nil || body != nil {
					t.Fatal("local facts admitted remote target or progress")
				}
			})
		}
	}
}

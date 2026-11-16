package core

import (
	"enkv.sh/core/contract"
	"testing"
)

// full_only: false
func TestGeneratedCreateRecordsUseTheAuthenticatedTemplateVersion(t *testing.T) {
	state := generatedEmptyPredecessor(t)
	input := generatedReservationInputFixture(t, state)
	original := input.graph.Lineages[0].Templates[0]
	for _, kind := range []contract.GeneratorLifecycleMode{contract.GeneratorLifecycleManaged, contract.GeneratorLifecycleNone} {
		t.Run(map[contract.GeneratorLifecycleMode]string{contract.GeneratorLifecycleManaged: "managed", contract.GeneratorLifecycleNone: "none"}[kind], func(t *testing.T) {
			x := original
			if kind != 0 {
				x.Schema, x.LifecycleMode, x.ResultReaderID = contract.GeneratorAttemptTemplateSchema, kind, contract.GeneratorResultReaderID()
			}
			if kind == contract.GeneratorLifecycleNone {
				x.ResourceContractID, x.HazardID, x.TargetSourceID = contract.ID{}, contract.ID{}, contract.ID{}
				x.CompletionClass, x.NoEffectBudget, x.ResidueBudget, x.TargetKind = 0, 0, 0, 0
			}
			var err error
			x.RequestPlanDigest, err = contract.GeneratorRequestPlanDigest(x)
			if err != nil {
				t.Fatal(err)
			}
			_, use, ok := generatedTemplate(input.graph, original.AttemptID)
			if !ok {
				t.Fatal("original result use missing")
			}
			consumers := contract.EmptyGeneratorVector(contract.GeneratorVectorConsumers)
			a, d, err := generatedCreateRecords(contract.GeneratedParentRecord(input.parent), x, generatedVectorID(90), consumers)
			if err != nil {
				t.Fatal(err)
			}
			encodedA, err := contract.EncodeGeneratedAttemptRecord(a)
			if err != nil {
				t.Fatal(err)
			}
			encodedD, err := contract.EncodeGeneratedDutyRecord(d)
			if err != nil {
				t.Fatal(err)
			}
			schema := contract.GeneratedAttemptRecordSchema
			if a.Schema != schema || d.Schema != schema || a.LifecycleMode != kind || d.LifecycleMode != kind || d.Consumers != consumers {
				t.Fatal("template version or caller consumers changed")
			}
			later, err := generatedScheduledCreateRows(contract.GeneratedParentRecord(input.parent), x, use, generatedVectorID(90))
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range later {
				switch row.Kind {
				case contract.GeneratedAttemptSupportKind:
					actual, err := contract.InspectGeneratedAttemptRecord(row.Body)
					if err != nil || actual != a {
						t.Fatal("later original changed common Attempt", err)
					}
				case contract.GeneratedDutySupportKind:
					actual, err := contract.InspectGeneratedDutyRecord(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					actual.Consumers = consumers
					if actual != d {
						t.Fatal("later original changed common Duty")
					}
				}
			}
			if kind == contract.GeneratorLifecycleNone {
				if len(encodedA) != 760 || len(encodedD) != 655 || a.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) || d.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) || d.Target != contract.EmptyGeneratorVector(contract.GeneratorVectorTargets) {
					t.Fatal("local records acquired remote fields")
				}
			} else if a.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) || d.Target != contract.EmptyGeneratorVector(contract.GeneratorVectorTargets) {
				t.Fatal("CF canonical empty fields changed")
			}
		})
	}
}

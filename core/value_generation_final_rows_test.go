package core

import (
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedFinalCheckpointChecksCompletePreparedRelation(t *testing.T) {
	for _, condition := range []string{"exact", "different result", "different current binding", "different intended readers", "different selected output"} {
		t.Run(condition, func(t *testing.T) {
			s, plan := observationFinalFixture(t, "generated")
			g := mustSelectedGeneratedWork(t, s)
			row := generatedPreparedValueEntryFixture(t, s, plan.entryPlans[0])
			switch condition {
			case "different selected output":
				row.Entry.OutputEncoding = contract.OutputEncodingBase64
			case "different result":
				row.ResultDigest[0] ^= 1
			case "different current binding":
				row.Access.Wraps[0].BindingSerial++
			case "different intended readers":
				row.Entry.Recipients = []contract.ID{generatedVectorID(199)}
				row.Access.Wraps[0].SubjectID = row.Entry.Recipients[0]
			}
			bindings, err := s.currentBindings()
			if err != nil {
				t.Fatal(err)
			}
			binding, err := contract.GeneratedFinalPreparationBindingDigest(currentControlOf(s), bindings)
			if err != nil {
				t.Fatal(err)
			}
			image := contract.GeneratedFinalPreparationImage{Schema: 1, DomainID: s.root.Domain, OperationID: g.parent.OperationID,
				MaterializationPhaseID: mustGeneratedPhaseID(plan.phase), ControlBindingDigest: binding, Generated: []contract.CryptoGeneratedValueEntryResult{row}}
			encoded, err := contract.EncodeGeneratedFinalPreparationImage(image)
			if err != nil {
				t.Fatal("semantic challenge did not pass the image codec", err)
			}
			decoded, err := contract.DecodeGeneratedFinalPreparationImage(encoded)
			if err != nil {
				t.Fatal("semantic challenge did not round trip", err)
			}
			defer decoded.Clear()
			prepared, err := s.deriveGeneratedFinalPreparation(t.Context(), g, plan, decoded.Generated, nil, decoded.GrantSeals)
			if condition == "exact" {
				if err != nil || prepared == nil {
					t.Fatal("complete public relation refused", err)
				}
			} else if err == nil || prepared != nil {
				t.Fatal("checkpoint accepted a different prepared relation", condition)
			}
			if s.prepared {
				t.Fatal("public validation entered private preparation")
			}
		})
	}
}

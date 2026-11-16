package crypto

import (
	"bytes"
	"fmt"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedAdmissionUsesExactDeclarationPayloadSpans(t *testing.T) {
	for _, retained := range []bool{false, true} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("retained=%t/recovery=%t", retained, recovery), func(t *testing.T) {
				var f generatedRuntimeFixture
				if retained {
					f = generatedCanonicalPlanFixture(t, recovery)
				} else {
					f = generatedSealedPlanFixture(t, recovery)
				}
				view, err := contract.InspectGeneratorDeclaration(f.declaration)
				if err != nil {
					t.Fatal(err)
				}
				entry, offset, err := view.Entry(0)
				if err != nil || offset != 74 || string(entry.Name) != "alpha" || len(entry.RecipientIDs) != 64 {
					t.Fatal("independent first-entry framing", offset, err)
				}
				// Header70 + entry frame4 + fixed13 + name5 + two recipient IDs64.
				// Recovery is a separate binding, so it adds no ordinary recipient.
				const payloadOffset = 156
				r := f.reservationRuntime(t)
				defer r.retireGenerated()
				plan := r.generated.purpose.plan()
				if retained {
					if entry.Kind != contract.GeneratorDeclarationRetained || len(plan.canonicals) != 1 || len(plan.sources) != 0 {
						t.Fatal("retained source family changed")
					}
					source := plan.canonicals[0]
					if source.offset != payloadOffset || source.length != uint32(len(entry.Payload)) || source.body != contract.Hash(entry.Payload) ||
						!bytes.Equal(f.declaration[payloadOffset:payloadOffset+source.length], entry.Payload) {
						t.Fatal("retained source does not name the exact payload")
					}
				} else {
					if entry.Kind != contract.GeneratorDeclarationSealed || len(plan.sources) != 1 || len(plan.canonicals) != 0 {
						t.Fatal("sealed source family changed")
					}
					source := plan.sources[0]
					if source.offset != payloadOffset || source.length != uint32(len(entry.Payload)) || source.envelope != contract.Hash(entry.Payload) ||
						!bytes.Equal(f.declaration[payloadOffset:payloadOffset+source.length], f.base.q.SealedInputs[0].EnvelopeBytes) {
						t.Fatal("sealed source does not name the exact original envelope")
					}
				}
				op := generatedCompare(t, r, f)
				generatedPlanParts(t, r, f, op)
				if !retained && (len(plan.sources[0].keys) != 32 || len(plan.sources[0].buffer) != 0) {
					t.Fatal("sealed payload authentication did not settle its input buffer")
				}
				result := generatedFinishPlan(t, r, f, op)
				if retained {
					if len(result.SourceProtections) != 0 || !plan.canonicals[0].opened || f.base.route.privateCalls != 1 {
						t.Fatal("exact retained payload was not authenticated once")
					}
				} else if len(result.SourceProtections) != 1 || len(plan.sources[0].keys) != 0 || len(plan.sources[0].buffer) != 0 || f.base.route.privateCalls != 1 {
					t.Fatal("exact sealed payload was not authenticated once")
				}
			})
		}
	}
}

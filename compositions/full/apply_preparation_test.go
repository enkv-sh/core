package compositionfull

import (
	"bytes"
	"encoding/json"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func setApplyPreparation(t testing.TB, out *core.PublicApplyResult, ack, verified uint64, possible bool) {
	t.Helper()
	out.Preparation = &core.ApplyPreparationFacts{AcknowledgedCreates: ack, VerifiedPreparations: verified, PossibleUnacknowledgedCreate: possible}
}

// full_only: false
func TestApplyPreparationProjectionKeepsIndependentInvocationFacts(t *testing.T) {
	for _, family := range []string{"ordinary", "generated", "early-generated", "combined"} {
		t.Run(family, func(t *testing.T) {
			r := suppliedApplyResultFixture(t)
			operation := uint16(contract.OperationApplyDeclaration)
			if family == "generated" {
				r.Receipt = nil
				r.Generated = &core.GeneratedInvocationResult{OperationKind: operation, StateResult: "success", CanonicalOutcome: contract.ReceiptCanonicalSelected, EffectSummary: contract.ReceiptEffectNoChange, EvidenceCeiling: contract.ReceiptEvidenceCanonical}
			}
			if family == "early-generated" {
				r.Receipt, r.Payload = nil, nil
				r.Result.Outcome = core.EvidenceUnavailable
				operation = contract.OperationRetireGeneratedGeneration
			}
			setApplyPreparation(t, &r, 0, 1, true)
			var machine, human []byte
			var err error
			switch family {
			case "combined":
				combined := core.PublicApplyPublicationResult{Apply: r, Publication: core.ApplyPublicationStage{Stage: "unstarted", Reason: "selection-unavailable"}}
				var jsonOut, humanOut bytes.Buffer
				if err := WriteApplyPublicationJSON(&jsonOut, combined); err != nil {
					t.Fatal(err)
				}
				if err := WriteApplyPublicationHuman(&humanOut, combined); err != nil {
					t.Fatal(err)
				}
				var doc struct{ Apply json.RawMessage }
				if json.Unmarshal(jsonOut.Bytes(), &doc) != nil {
					t.Fatal("combined result encoding differs")
				}
				machine, human = doc.Apply, humanOut.Bytes()
			case "early-generated":
				machine, err = RenderGeneratedMutationJSON(r, operation)
				if err == nil {
					human, err = RenderGeneratedMutationHuman(r, operation)
				}
			default:
				machine, err = RenderApplyJSON(r)
				if err == nil {
					human, err = RenderApplyHuman(r)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]json.RawMessage
			if json.Unmarshal(machine, &doc) != nil {
				t.Fatal("apply result encoding differs")
			}
			const facts = `{"acknowledged_creates":0,"verified_preparations":1,"possible_unacknowledged_create":true}`
			if !resultJSONFactsEqual(doc["preparation"], []byte(facts)) || bytes.Contains(human, []byte("Local preparations:")) || !bytes.Contains(human, []byte("Warning: a local preparation create may have occurred without acknowledgement.\n")) {
				t.Fatalf("JSON/human lost independent preparation facts: json=%s human_has_record=%t", doc["preparation"], bytes.Contains(human, []byte(facts)))
			}
			if family == "ordinary" && (!bytes.Contains(machine, []byte(`"receipt_hex": "`)) || !bytes.Contains(machine, []byte(`"state_result": "success"`))) {
				t.Fatal("preparation facts replaced terminal apply evidence")
			}
		})
	}
}

// full_only: false
func TestApplyPreparationProjectionOmitsUnavailableAndChecksFiniteBound(t *testing.T) {
	for _, generated := range []bool{false, true} {
		r := suppliedApplyResultFixture(t)
		if generated {
			r.Receipt = nil
			r.Generated = &core.GeneratedInvocationResult{OperationKind: contract.OperationApplyDeclaration, StateResult: "success", CanonicalOutcome: contract.ReceiptCanonicalSelected, EffectSummary: contract.ReceiptEffectNoChange, EvidenceCeiling: contract.ReceiptEvidenceCanonical}
		}
		for _, render := range []func(core.PublicApplyResult) ([]byte, error){RenderApplyJSON, RenderApplyHuman} {
			body, err := render(r)
			if err != nil || bytes.Contains(body, []byte("preparation")) {
				t.Fatal("unavailable preparation facts were invented", generated, err)
			}
		}
		for _, counts := range [][2]uint64{{794250, 0}, {0, 794250}, {794250, 794250}} {
			setApplyPreparation(t, &r, counts[0], counts[1], false)
			if _, err := RenderApplyJSON(r); err != nil {
				t.Fatal("finite independent preparation counter refused", generated, counts, err)
			}
		}
		for _, counts := range [][2]uint64{{794251, 0}, {0, 794251}, {^uint64(0), ^uint64(0)}} {
			setApplyPreparation(t, &r, counts[0], counts[1], false)
			for _, render := range []func(core.PublicApplyResult) ([]byte, error){RenderApplyJSON, RenderApplyHuman} {
				if body, err := render(r); err == nil || body != nil {
					t.Fatal("out-of-bound preparation counter rendered", generated, counts)
				}
			}
		}
	}
}

// full_only: false
func TestApplyPreparationByteBoundsIncludeWholeRecord(t *testing.T) {
	const record = `{"acknowledged_creates":794250,"verified_preparations":794250,"possible_unacknowledged_create":false}`
	if len(`,"preparation":`+record) != 116 || len("preparation: "+record+"\n") != 115 {
		t.Fatal("independent maximum preparation field framing changed")
	}
	// Diagnostic framing is independent of the 116-byte preparation field.
	const applyMaximum = uint64(65536 + 8192*(1408+128) + 2*471 + 32*(256*(2097152-75)) + 116 + 3081*3428 + 512*core.GeneratedResultAttemptLimit + 2048 + 1024)
	if generatedResultOutputLimit != applyMaximum || MaxApplyPublicationApplyBytes != applyMaximum {
		t.Fatal("apply result bound omitted the new complete preparation record")
	}
	if applyPublicationCompactLimit != applyMaximum+publicationCompactResultLimit+256 || MaxApplyPublicationJSONBytes != 67*applyPublicationCompactLimit || MaxApplyPublicationHumanBytes != applyPublicationCompactLimit {
		t.Fatal("combined result bound omitted one complete stage or final framing")
	}
}

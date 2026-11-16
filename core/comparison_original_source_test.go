package core

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestComparisonOriginalSealedInputRequiresEqualResult(t *testing.T) {
	for _, condition := range []string{"removal", "repeat", "changed-result", "same-name-readd", "absent", "plain-current", "generated-current", "addition"} {
		t.Run(condition, func(t *testing.T) {
			s, _ := observationTestSession(t)
			members := []contract.ID{s.admission.recipient, generatedVectorID(200)}
			observationCurrentSecret(t, s, members, generatedVectorID(201))
			if condition == "repeat" || condition == "addition" {
				observationCurrentSecret(t, s, members[:1], generatedVectorID(201))
			}
			if condition == "same-name-readd" {
				observationCurrentSecret(t, s, members, generatedVectorID(202))
			}
			generatedSealSelectedFixture(t, s)
			custody := &observationExchangeCustody{instance: generatedVectorID(105)}
			input, _, _ := observationComparisonPermit(t, s, custody)
			envelope, err := contract.DecodeSealedInputEnvelope(input[0].InputBytes)
			if err != nil {
				t.Fatal(err)
			}
			envelope.Core.IntendedRecipientBindingSetDigest = generatedVectorID(137)
			input[0].InputBytes, err = contract.EncodeSealedInputEnvelope(envelope)
			if err != nil {
				t.Fatal(err)
			}
			original := bytes.Clone(input[0].InputBytes)
			switch condition {
			case "absent":
				s.root.Names = nil
				s.pages = [contract.MaxValueEntryPages]*format.ValueEntryPage{}
				s.access = [contract.MaxChildPages]*format.AccessPage{}
			case "plain-current":
				s.valueEntry(0).ConfidentialityClass = contract.Plain
				s.valueEntry(0).ValueBytes = []byte("public current")
				s.valueEntry(0).ContentLength, s.valueEntry(0).RetainedLength = uint32(len("public current")), uint32(len("public current"))
				s.access = [contract.MaxChildPages]*format.AccessPage{}
			case "generated-current":
				entry := s.valueEntry(0)
				entry.ValueSource = contract.Generated
				entry.Generated = generatedSelectedEntryState(t).valueEntry(0).Generated
				entry.Generated.GenerationID = entry.ValueState
				payload, err := contract.DecodeCanonicalPayload(entry.ValueBytes)
				if err != nil {
					t.Fatal(err)
				}
				payload.DataKeyID, payload.CommitmentKeyID, err = contract.GeneratorValueKeyIDs(entry.ValueState)
				if err != nil {
					t.Fatal(err)
				}
				entry.ValueBytes, err = contract.EncodeCanonicalPayload(payload)
				if err != nil {
					t.Fatal(err)
				}
				core, err := contract.ValueCoreForEntry(s.root.Domain, contract.CompatibilityID(), *entry)
				if err != nil {
					t.Fatal(err)
				}
				s.access[0].Records[0].MaterialContextDigest, err = contract.ValueMaterialContextDigest(core)
				if err != nil {
					t.Fatal(err)
				}
			case "addition":
				input[0].Recipients = slices.Clone(members)
			}
			generatedSealSelectedFixture(t, s)
			if !s.admission.valid(s.store) {
				t.Fatal("selected predecessor admission is invalid")
			}
			var diagnostic *contract.Diagnostic
			comparison, result := s.compareEntryInputsWithRetirement(t.Context(), input, currentApplyRecipients(s.registry()), nil, &diagnostic)
			if condition == "absent" || condition == "plain-current" || condition == "generated-current" || condition == "addition" {
				if comparison != nil || result != refused(InvalidIntent) {
					t.Fatal("ineligible original source admitted", result)
				}
				if diagnostic == nil || diagnostic.Subject.Kind != contract.SubjectEntry || diagnostic.Subject.Name != "secret" || diagnostic.Reason != contract.ReasonStaleSealedInputBinding || !slices.Equal(diagnostic.Path, []contract.DiagnosticField{contract.FieldSource}) {
					t.Fatal("rejected binding lost its exact subject or cause", diagnostic)
				}
				return
			}
			if comparison == nil || diagnostic != nil {
				t.Fatal("equal-only original source refused before private comparison", result)
			}
			relation := contract.CryptoEqual
			if condition == "changed-result" {
				relation = contract.CryptoChanged
			}
			body := observationComparedBody(t, comparison, relation, condition != "repeat")
			checked, err := contract.DecodeCryptoCompareResult(body)
			if err != nil {
				t.Fatal(err)
			}
			if accepted := comparisonMatches(comparison, checked); accepted != (relation == contract.CryptoEqual) {
				t.Fatal("Core did not independently enforce original-source equality", accepted)
			}
			if !bytes.Equal(input[0].InputBytes, original) {
				t.Fatal("comparison rewrote the original source")
			}
		})
	}
}

// full_only: false
func TestGeneratedAdmissionStillRefusesOriginalSealedBindingMismatch(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(map[bool]string{false: "matching", true: "mismatch"}[mismatch], func(t *testing.T) {
			s, _ := observationTestSession(t)
			input, _, _ := observationComparisonPermit(t, s, &observationExchangeCustody{instance: generatedVectorID(105)})
			if mismatch {
				envelope, err := contract.DecodeSealedInputEnvelope(input[0].InputBytes)
				if err != nil {
					t.Fatal(err)
				}
				envelope.Core.IntendedRecipientBindingSetDigest = generatedVectorID(137)
				input[0].InputBytes, err = contract.EncodeSealedInputEnvelope(envelope)
				if err != nil {
					t.Fatal(err)
				}
			}
			source := contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationSealed, Name: "secret", Recipients: []contract.ID{s.admission.recipient}, Payload: input[0].InputBytes}
			planInput := generatedPlanInputFixture(t, s, source)
			plan, err := s.generatedPlanRequest(t.Context(), planInput)
			if mismatch {
				if plan != nil || !errors.Is(err, contract.ErrRecord) {
					t.Fatal("generated admission accepted original binding mismatch", err)
				}
			} else if plan == nil || err != nil {
				t.Fatal("matching generated source fixture refused", err)
			}
		})
	}
}

// full_only: false
func TestGeneratedOriginalSealedInputRequiresEqualOnlyCurrentSubset(t *testing.T) {
	for _, condition := range []string{"removal", "repeat", "content-change", "addition", "absent", "conversion"} {
		t.Run(condition, func(t *testing.T) {
			s, _ := observationTestSession(t)
			members := []contract.ID{s.admission.recipient, generatedVectorID(200)}
			observationCurrentSecret(t, s, members, generatedVectorID(201))
			if condition == "repeat" || condition == "addition" {
				observationCurrentSecret(t, s, members[:1], generatedVectorID(201))
			}
			generatedSealSelectedFixture(t, s)
			input, _, _ := observationComparisonPermit(t, s, &observationExchangeCustody{instance: generatedVectorID(105)})
			envelope, err := contract.DecodeSealedInputEnvelope(input[0].InputBytes)
			if err != nil {
				t.Fatal(err)
			}
			envelope.Core.IntendedRecipientBindingSetDigest = generatedVectorID(137)
			input[0].InputBytes, err = contract.EncodeSealedInputEnvelope(envelope)
			if err != nil {
				t.Fatal(err)
			}
			readers := []contract.ID{s.admission.recipient}
			if condition == "addition" {
				readers = slices.Clone(members)
			}
			if condition == "absent" {
				s.root.Names = nil
				s.pages = [contract.MaxValueEntryPages]*format.ValueEntryPage{}
				s.access = [contract.MaxChildPages]*format.AccessPage{}
				generatedSealSelectedFixture(t, s)
			}
			source := contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationSealed, Name: "secret", Recipients: readers, Payload: input[0].InputBytes}
			original := bytes.Clone(source.Payload)
			candidate := generatedPlanInputFixture(t, s, source)
			for at := range candidate.graph.ValueEntryPlans {
				row := &candidate.graph.ValueEntryPlans[at]
				if row.Name != source.Name {
					continue
				}
				row.ChangeMask = contract.GeneratorValueChangeMembership
				if condition == "repeat" || condition == "absent" {
					row.ChangeMask = 0
				}
				if condition == "content-change" {
					row.ChangeMask |= contract.GeneratorValueChangeContent
				}
				if condition == "conversion" {
					row.EntryIncarnationID = generatedVectorID(203)
				}
			}
			candidate.graph.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(candidate.graph.Header, candidate.graph.ValueEntryPlans, candidate.graph.Lineages, candidate.graph.Edges)
			if err != nil {
				t.Fatal(err)
			}
			declaration := bytes.Clone(candidate.declaration)
			plan, err := s.generatedPlanRequest(t.Context(), candidate)
			eligible := condition == "removal" || condition == "repeat"
			if (plan != nil && err == nil) != eligible {
				t.Fatal("generated original-source eligibility differs", condition, err)
			}
			if condition == "addition" {
				var binding *sealedInputBindingError
				if !errors.As(err, &binding) || binding.name != "secret" || !errors.Is(err, contract.ErrRecord) {
					t.Fatal("generated binding refusal lost its exact source subject", err)
				}
			}
			if !bytes.Equal(source.Payload, original) {
				t.Fatal("generated admission rewrote the original source")
			}
			if !bytes.Equal(candidate.declaration, declaration) {
				t.Fatal("generated admission rewrote the encoded declaration")
			}
			if plan != nil && !bytes.Equal(plan.input.declaration, declaration) {
				t.Fatal("generated plan did not retain the original declaration")
			}
		})
	}
}

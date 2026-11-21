package crypto

import (
	"bytes"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

func generatedLocalFinalSibling(t *testing.T, g contract.GeneratorPlanBundle) contract.GeneratorLineageTemplate {
	t.Helper()
	lineage := g.Lineages[0]
	lineage.Name, lineage.EntryIncarnationID = "omega", consumerID("local Final sibling incarnation")
	var err error
	lineage.LineageID, err = contract.GeneratorLineageID(lineage.DomainID, lineage.OperationID, lineage.Name, lineage.EntryIncarnationID, lineage.Epoch, lineage.IntentDigest)
	if err != nil {
		t.Fatal(err)
	}
	x := lineage.Templates[0]
	x.LineageID = lineage.LineageID
	x.AttemptID, err = contract.GeneratorAttemptID(x.LineageID, contract.GeneratorBranchInitial)
	if err != nil {
		t.Fatal(err)
	}
	x.ResourceIncarnationID, err = contract.GeneratorResourceID(lineage.DomainID, lineage.OperationID, x.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	x.PlannedValueSlotID, err = contract.GeneratorValueSlotID(lineage.DomainID, lineage.OperationID, x.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	x.DutyID, err = contract.GeneratorDutyID(lineage.DomainID, lineage.OperationID, x.AttemptID, contract.GeneratedDutyCreate)
	if err != nil {
		t.Fatal(err)
	}
	x.TransmissionID, err = contract.GeneratorTransmissionID(x.AttemptID, contract.GeneratorActionCreate)
	if err != nil {
		t.Fatal(err)
	}
	x.ResultID, err = contract.GeneratorResultID(lineage.DomainID, lineage.OperationID, x.AttemptID, x.TransmissionID, contract.GeneratorActionCreate)
	if err != nil {
		t.Fatal(err)
	}
	x.InboxID, err = contract.GeneratorInboxID(lineage.DomainID, lineage.OperationID, x.AttemptID, x.ResultID)
	if err != nil {
		t.Fatal(err)
	}
	x.RequestPlanDigest, err = contract.GeneratorRequestPlanDigest(x)
	if err != nil {
		t.Fatal(err)
	}
	lineage.Templates[0] = x
	return lineage
}

// The gate receives an already admitted graph and result set. This fixture
// exercises its complete inherited-row relation; it does not grant a new send.
func generatedLocalFinalGateFixture(t *testing.T, returnedDisposition uint8) (*generatedAdmission, generatedFinalAdmissionInput, generatedCandidate, []byte) {
	t.Helper()
	f, prepared, _ := generatedProducerPlanFixture(t, generatedRuntimeLocalEffectFixture(t))
	g, err := contract.DecodeGeneratorPlanBundle(f.graph)
	if err != nil {
		t.Fatal(err)
	}
	original := f.producer.Producer.Attempt
	original.State, original.Stage, original.FailureReason = contract.GeneratedEffectFailedTerminal, contract.GeneratedStageTerminal, contract.GeneratorFailureUnavailable
	failure := original
	if returnedDisposition != 0 {
		lineage := generatedLocalFinalSibling(t, g)
		g.Lineages = append(g.Lineages, lineage)
		x := lineage.Templates[0]
		failure.LineageID, failure.AttemptID, failure.OwnerID = x.LineageID, x.AttemptID, x.DutyID
		failure.ResourceID, failure.TransmissionID, failure.ResultID, failure.InboxID = x.ResourceIncarnationID, x.TransmissionID, x.ResultID, x.InboxID
		failure.TemplateDigest, err = contract.GeneratorTemplateID(x)
		if err != nil {
			t.Fatal(err)
		}
	}
	failureHistory, err := contract.EncodeGeneratorHistory(contract.GeneratorHistory{Schema: 1,
		PredecessorAttemptID: failure.AttemptID, OwnerID: failure.OwnerID, Outcome: contract.GeneratedEffectTransmitted})
	if err != nil {
		t.Fatal(err)
	}
	failure.History, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorHistory, [][]byte{failureHistory})
	if err != nil {
		t.Fatal(err)
	}
	failureCarriers := generatedVectorSupport(t, g.Header.DomainID, contract.GeneratedAttemptSupportKind, failure.AttemptID, contract.GeneratorVectorHistory, [][]byte{failureHistory})
	failureBody, err := contract.EncodeGeneratedAttemptRecord(failure)
	if err != nil {
		t.Fatal(err)
	}
	failedRow := contract.SupportRecord{Kind: contract.GeneratedAttemptSupportKind, RecordID: failure.AttemptID, Body: failureBody}
	state := &generatedFinalPreparationState{nonselecting: true, phaseID: consumerID("local nonselecting Final phase")}
	a := &generatedAdmission{request: f.compare, graph: g, material: prepared.Material, control: f.base.control, bindings: f.base.q.Bindings,
		purpose: generatedPurposeState{final: state, output: &contract.GeneratedOutputTransition{}}}
	input := generatedFinalAdmissionInput{CheckpointSupport: []contract.SupportRecord{failedRow}}
	before := append(slices.Clone(failureCarriers), failedRow)
	candidate := generatedCandidate{}
	seed := generatedTestSeed(t, f, prepared)
	defer clear(seed)
	expected := f.producer.Producer.Expected
	facts := generatedProducerFacts(expected)
	value := []byte("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
	stateCode := uint8(contract.GeneratedEffectSucceeded)
	if returnedDisposition == contract.GeneratorDispositionConfirmedNoEffect {
		facts.Disposition, facts.Reason = returnedDisposition, contract.GeneratorReasonRejected
		stateCode, value = contract.GeneratedEffectConfirmedNoEffect, nil
	}
	result, err := custody.SealGeneratedResult(expected, prepared.Material, facts, seed, value)
	if err != nil {
		t.Fatal(err)
	}
	resultBody, err := contract.EncodeGeneratedResultRecord(result)
	if err != nil {
		t.Fatal(err)
	}
	if returnedDisposition != 0 {
		success := f.producer.Producer.Attempt
		success.State, success.Stage = stateCode, contract.GeneratedStageTerminal
		binding, err := contract.EncodeGeneratorSupportBinding(contract.GeneratorSupportBinding{Schema: contract.GeneratorSupportBindingSchema, Role: 1,
			ContractID: consumerID("local Final support contract"), ImplementationID: consumerID("local Final support implementation"), PublicBindingDigest: consumerID("local Final support binding")})
		if err != nil {
			t.Fatal(err)
		}
		success.Support, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorSupport, [][]byte{binding})
		if err != nil {
			t.Fatal(err)
		}
		support := generatedVectorSupport(t, g.Header.DomainID, contract.GeneratedParentSupportKind, g.Header.OperationID, contract.GeneratorVectorSupport, [][]byte{binding})
		encodedFacts, err := contract.EncodeGeneratorSafeFacts(result.SafeFacts)
		if err != nil {
			t.Fatal(err)
		}
		factBody, err := contract.EncodeGeneratorFactsRow(contract.GeneratorFactsRow{Schema: 1, ResultID: success.ResultID, Facts: encodedFacts})
		if err != nil {
			t.Fatal(err)
		}
		success.Facts, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorFacts, [][]byte{factBody})
		if err != nil {
			t.Fatal(err)
		}
		historyBody, err := contract.EncodeGeneratorHistory(contract.GeneratorHistory{Schema: 1,
			PredecessorAttemptID: success.AttemptID, OwnerID: success.OwnerID, Outcome: success.State,
			ResultID: success.ResultID, ResultDigest: contract.Hash(resultBody)})
		if err != nil {
			t.Fatal(err)
		}
		success.History, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorHistory, [][]byte{historyBody})
		if err != nil {
			t.Fatal(err)
		}
		before = append(before, generatedVectorSupport(t, g.Header.DomainID, contract.GeneratedAttemptSupportKind, success.AttemptID, contract.GeneratorVectorFacts, [][]byte{factBody})...)
		before = append(before, generatedVectorSupport(t, g.Header.DomainID, contract.GeneratedAttemptSupportKind, success.AttemptID, contract.GeneratorVectorHistory, [][]byte{historyBody})...)
		before = append(before, generatedVectorSupport(t, g.Header.DomainID, contract.GeneratedDutySupportKind, success.OwnerID, contract.GeneratorVectorHistory, [][]byte{historyBody})...)
		successBody, err := contract.EncodeGeneratedAttemptRecord(success)
		if err != nil {
			t.Fatal(err)
		}
		duty := f.producer.Producer.Duty
		duty.Status, duty.Support, duty.History = success.State, success.Support, success.History
		dutyBody, err := contract.EncodeGeneratedDutyRecord(duty)
		if err != nil {
			t.Fatal(err)
		}
		successRow := contract.SupportRecord{Kind: contract.GeneratedAttemptSupportKind, RecordID: success.AttemptID, Body: successBody}
		dutyRow := contract.SupportRecord{Kind: contract.GeneratedDutySupportKind, RecordID: duty.DutyID, Body: dutyBody}
		input.CheckpointSupport = append(input.CheckpointSupport, successRow, dutyRow)
		before = append(before, successRow, dutyRow, contract.SupportRecord{Kind: contract.GeneratedResultSupportKind, RecordID: success.ResultID, Body: resultBody})
		before = append(before, support...)
		ref := contract.GeneratorResultReference{Schema: 1, ResultID: success.ResultID, ResultBodyDigest: contract.Hash(resultBody), ResultLength: uint32(len(resultBody))}
		state.results, state.validated, state.resultBodies = []generatedResultAdmission{{Expected: expected, Reference: ref}}, []contract.GeneratorResultReference{ref}, [][]byte{resultBody}
		mapping := success
		mapping.Facts, mapping.History = contract.EmptyGeneratorVector(contract.GeneratorVectorFacts), contract.EmptyGeneratorVector(contract.GeneratorVectorHistory)
		mappingBody, err := contract.EncodeGeneratedAttemptRecord(mapping)
		if err != nil {
			t.Fatal(err)
		}
		revision, err := contract.GeneratorPhaseRevisionID(state.phaseID)
		if err != nil {
			t.Fatal(err)
		}
		releaseBody, err := contract.EncodePendingInboxReleaseRecord(contract.PendingInboxReleaseRecord{Schema: 1, DomainID: success.DomainID,
			InboxID: success.InboxID, OriginalResultID: success.ResultID, SelectedHandoffDigest: contract.Hash(resultBody), ObjectLength: uint32(len(resultBody)),
			HandoffRevisionID: revision, CapacityReservation: duty.CapacityReservation, State: contract.GeneratedReleasePending})
		if err != nil {
			t.Fatal(err)
		}
		candidate.SupportRecords = append(slices.Clone(support), contract.SupportRecord{Kind: contract.GeneratedAttemptSupportKind, RecordID: success.AttemptID, Body: mappingBody},
			contract.SupportRecord{Kind: contract.PendingInboxReleaseSupportKind, RecordID: success.InboxID, Body: releaseBody})
	}
	for _, row := range before {
		fact, err := contract.InspectSupportRecordDigest(g.Header.DomainID, row)
		if err != nil {
			t.Fatal(err)
		}
		a.purpose.output.Rows.Facts = append(a.purpose.output.Rows.Facts, fact)
	}
	return a, input, candidate, resultBody
}

// full_only: false
func TestGeneratedLocalFailedFinalRequiresPinnedTerminalBodies(t *testing.T) {
	for _, damage := range []string{"exact", "missing", "duplicate", "foreign_id", "reason", "before_result", "admitted_result", "candidate_result", "candidate_release"} {
		t.Run(damage, func(t *testing.T) {
			a, input, candidate, resultBody := generatedLocalFinalGateFixture(t, 0)
			failed, err := contract.InspectGeneratedAttemptRecord(input.CheckpointSupport[0].Body)
			if err != nil {
				t.Fatal(err)
			}
			switch damage {
			case "missing":
				input.CheckpointSupport = nil
			case "duplicate":
				input.CheckpointSupport = append(input.CheckpointSupport, input.CheckpointSupport[0])
			case "foreign_id":
				input.CheckpointSupport[0].RecordID = consumerID("foreign failed body")
			case "reason":
				input.CheckpointSupport[0].Body = bytes.Clone(input.CheckpointSupport[0].Body)
				input.CheckpointSupport[0].Body[7+16*32+3] = 0
			case "before_result":
				fact, err := contract.InspectSupportRecordDigest(a.graph.Header.DomainID, contract.SupportRecord{Kind: contract.GeneratedResultSupportKind, RecordID: failed.ResultID, Body: resultBody})
				if err != nil {
					t.Fatal(err)
				}
				a.purpose.output.Rows.Facts = append(a.purpose.output.Rows.Facts, fact)
			case "admitted_result":
				a.purpose.final.resultBodies = [][]byte{resultBody}
			case "candidate_result":
				candidate.SupportRecords = append(candidate.SupportRecords, contract.SupportRecord{Kind: contract.GeneratedResultSupportKind, RecordID: failed.ResultID, Body: resultBody})
			case "candidate_release":
				body, err := contract.EncodePendingInboxReleaseRecord(contract.PendingInboxReleaseRecord{Schema: 1, DomainID: failed.DomainID,
					InboxID: consumerID("foreign inbox naming failed result"), OriginalResultID: failed.ResultID, SelectedHandoffDigest: contract.Hash(resultBody), ObjectLength: uint32(len(resultBody)),
					HandoffRevisionID: consumerID("foreign release revision"), CapacityReservation: contract.GeneratorDescriptor{Digest: consumerID("capacity"), Length: 4}, State: contract.GeneratedReleasePending})
				if err != nil {
					t.Fatal(err)
				}
				candidate.SupportRecords = append(candidate.SupportRecords, contract.SupportRecord{Kind: contract.PendingInboxReleaseSupportKind, RecordID: consumerID("foreign inbox naming failed result"), Body: body})
			}
			admitted := a.admitFinalPreparation(input)
			accepted := admitted && a.candidateTerminalUncertain(candidate)
			if damage == "exact" && !accepted {
				t.Fatal("exact pure local failure could not close without fabricated result or remote owner")
			}
			if damage != "exact" && accepted {
				t.Fatal("Final discarded local failure without exact inherited absence/body evidence")
			}
		})
	}
}

// full_only: false
func TestGeneratedLocalNonselectingFinalFreezesExactSuccessRelease(t *testing.T) {
	checkGeneratedLocalFinalRelease(t, contract.GeneratorDispositionCompleteCreate)
}

// full_only: false
func TestGeneratedLocalNonselectingFinalFreezesExactNoEffectRelease(t *testing.T) {
	checkGeneratedLocalFinalRelease(t, contract.GeneratorDispositionConfirmedNoEffect)
}

func checkGeneratedLocalFinalRelease(t *testing.T, disposition uint8) {
	t.Helper()
	for _, damage := range []string{"exact", "missing_handoff", "wrong_state", "missing_body", "missing_duty", "duty_capacity", "missing_mapping", "missing_release", "capacity", "revision", "length", "digest", "foreign_row_id", "foreign_inbox", "mapping_support", "mapping_history", "missing_support"} {
		t.Run(damage, func(t *testing.T) {
			a, input, candidate, _ := generatedLocalFinalGateFixture(t, disposition)
			id := a.purpose.final.results[0].Expected.Template.AttemptID
			if damage == "missing_handoff" {
				input.CheckpointSupport = slices.DeleteFunc(input.CheckpointSupport, func(row contract.SupportRecord) bool {
					return row.RecordID == id || row.Kind == contract.GeneratedDutySupportKind
				})
				candidate.SupportRecords = nil
			}
			if damage == "wrong_state" {
				record, present := generatedFinalCheckpointAttempt(input.CheckpointSupport, id)
				if !present {
					t.Fatal("missing returned attempt")
				}
				if record.State == contract.GeneratedEffectSucceeded {
					record.State = contract.GeneratedEffectConfirmedNoEffect
				} else {
					record.State = contract.GeneratedEffectSucceeded
				}
				if a.finalLocalCheckpointAttempt(record) {
					t.Fatal("returned disposition authenticated a different terminal state")
				}
				return
			}
			if damage == "missing_body" {
				a.purpose.final.resultBodies = nil
			}
			if damage == "missing_duty" {
				input.CheckpointSupport = slices.DeleteFunc(input.CheckpointSupport, func(row contract.SupportRecord) bool { return row.Kind == contract.GeneratedDutySupportKind })
			}
			if damage == "duty_capacity" {
				for i, row := range input.CheckpointSupport {
					if row.Kind == contract.GeneratedDutySupportKind {
						duty, err := contract.InspectGeneratedDutyRecord(row.Body)
						if err != nil {
							t.Fatal(err)
						}
						duty.CapacityReservation.Digest = consumerID("changed Duty capacity")
						input.CheckpointSupport[i].Body, err = contract.EncodeGeneratedDutyRecord(duty)
						if err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			for i, row := range candidate.SupportRecords {
				if row.Kind == contract.PendingInboxReleaseSupportKind {
					release, err := contract.InspectPendingInboxReleaseRecord(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					switch damage {
					case "capacity":
						release.CapacityReservation.Digest = consumerID("changed release capacity")
					case "revision":
						release.HandoffRevisionID = consumerID("predecessor rather than Final revision")
					case "length":
						release.ObjectLength++
					case "digest":
						release.SelectedHandoffDigest = consumerID("different Result body")
					case "foreign_row_id":
						candidate.SupportRecords[i].RecordID = consumerID("different wrapper InboxID")
					case "foreign_inbox":
						release.InboxID = consumerID("different embedded InboxID")
						candidate.SupportRecords[i].RecordID = release.InboxID
					}
					candidate.SupportRecords[i].Body, err = contract.EncodePendingInboxReleaseRecord(release)
					if err != nil {
						t.Fatal(err)
					}
				}
				if row.Kind == contract.GeneratedAttemptSupportKind && (damage == "mapping_support" || damage == "mapping_history") {
					mapping, err := contract.InspectGeneratedAttemptRecord(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					if damage == "mapping_support" {
						mapping.Support = contract.EmptyGeneratorVector(contract.GeneratorVectorSupport)
					} else {
						index := slices.IndexFunc(input.CheckpointSupport, func(row contract.SupportRecord) bool {
							return row.Kind == contract.GeneratedAttemptSupportKind && row.RecordID == mapping.AttemptID
						})
						if index < 0 {
							t.Fatal("original success body missing")
						}
						original, err := contract.InspectGeneratedAttemptRecord(input.CheckpointSupport[index].Body)
						if err != nil {
							t.Fatal(err)
						}
						mapping.History = original.History
					}
					candidate.SupportRecords[i].Body, err = contract.EncodeGeneratedAttemptRecord(mapping)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			candidate.SupportRecords = slices.DeleteFunc(candidate.SupportRecords, func(row contract.SupportRecord) bool {
				return damage == "missing_mapping" && row.Kind == contract.GeneratedAttemptSupportKind ||
					damage == "missing_release" && row.Kind == contract.PendingInboxReleaseSupportKind || damage == "missing_support" && row.Kind == contract.GeneratorVectorSupportKind
			})
			accepted := a.admitFinalPreparation(input) && a.candidateTerminalUncertain(candidate)
			if damage == "exact" && !accepted {
				t.Fatal("returned local result lost its exact release mapping beside a failed sibling")
			}
			if damage != "exact" && accepted {
				t.Fatal("changed local release escaped the original selected Duty/Attempt/Result relation")
			}
		})
	}
}

// full_only: false
func TestGeneratedLocalNonselectingFinalKeepsCloudflareSiblingCustody(t *testing.T) {
	for _, damage := range []string{"exact", "seed", "material", "result", "owner"} {
		t.Run(damage, func(t *testing.T) {
			f, prepared, candidate := generatedOwnedUnusableFinalFixture(t, false)
			graph, err := contract.DecodeGeneratorPlanBundle(f.graph)
			if err != nil {
				t.Fatal(err)
			}
			local, input, localCandidate, _ := generatedLocalFinalGateFixture(t, contract.GeneratorDispositionCompleteCreate)
			failed, err := contract.InspectGeneratedAttemptRecord(input.CheckpointSupport[0].Body)
			if err != nil {
				t.Fatal(err)
			}
			failureHistory, err := contract.EncodeGeneratorHistory(contract.GeneratorHistory{Schema: 1,
				PredecessorAttemptID: failed.AttemptID, OwnerID: failed.OwnerID, Outcome: contract.GeneratedEffectTransmitted})
			if err != nil {
				t.Fatal(err)
			}
			failedRows := map[contract.ID]bool{failed.AttemptID: true}
			for _, row := range generatedVectorSupport(t, failed.DomainID, contract.GeneratedAttemptSupportKind, failed.AttemptID, contract.GeneratorVectorHistory, [][]byte{failureHistory}) {
				failedRows[row.RecordID] = true
			}
			input.CheckpointSupport = slices.DeleteFunc(input.CheckpointSupport, func(row contract.SupportRecord) bool { return failedRows[row.RecordID] })
			local.purpose.output.Rows.Facts = slices.DeleteFunc(local.purpose.output.Rows.Facts, func(fact contract.SupportRecordDigest) bool { return failedRows[fact.RecordID()] })
			if graph.Header.DomainID != local.graph.Header.DomainID || graph.Header.OperationID != local.graph.Header.OperationID {
				t.Fatal("sibling fixtures do not have the same operation")
			}
			graph.Lineages = append(graph.Lineages, local.graph.Lineages[0])
			phase, err := contract.GeneratorPhaseID(f.final.Phase)
			if err != nil {
				t.Fatal(err)
			}
			state := &generatedFinalPreparationState{nonselecting: true, phaseID: phase,
				results:      append(slices.Clone(f.final.Results), local.purpose.final.results...),
				resultBodies: append(slices.Clone(f.final.ResultBodies), local.purpose.final.resultBodies...)}
			for i, row := range localCandidate.SupportRecords {
				if row.Kind == contract.PendingInboxReleaseSupportKind {
					release, err := contract.InspectPendingInboxReleaseRecord(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					release.HandoffRevisionID, err = contract.GeneratorPhaseRevisionID(phase)
					if err != nil {
						t.Fatal(err)
					}
					localCandidate.SupportRecords[i].Body, err = contract.EncodePendingInboxReleaseRecord(release)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			candidate.SupportRecords = append(candidate.SupportRecords, localCandidate.SupportRecords...)
			for _, result := range state.results {
				state.validated = append(state.validated, result.Reference)
			}
			a := &generatedAdmission{request: f.compare, graph: graph, material: prepared.Material, control: f.base.control, bindings: f.base.q.Bindings,
				purpose: generatedPurposeState{final: state, output: f.final.Session.Output}}
			a.purpose.output.Rows.Facts = append(slices.Clone(a.purpose.output.Rows.Facts), local.purpose.output.Rows.Facts...)
			if !a.admitFinalPreparation(input) {
				t.Fatal("exact local success handoff refused beside real Cloudflare failure closure")
			}
			switch damage {
			case "seed":
				candidate.AccessRecords = slices.DeleteFunc(candidate.AccessRecords, func(row contract.AccessRecord) bool {
					return row.MaterialKind == contract.OperationSeedMaterialKind && row.MaterialID == a.request.MaterialID
				})
			case "material":
				candidate.SupportRecords = slices.DeleteFunc(candidate.SupportRecords, func(row contract.SupportRecord) bool {
					return row.Kind == contract.OperationMaterialSupportKind && row.RecordID == a.request.MaterialID
				})
			case "result":
				candidate.SupportRecords = slices.DeleteFunc(candidate.SupportRecords, func(row contract.SupportRecord) bool {
					return row.Kind == contract.GeneratedResultSupportKind && row.RecordID == state.results[0].Expected.Template.ResultID
				})
			case "owner":
				candidate.SupportRecords = slices.DeleteFunc(candidate.SupportRecords, func(row contract.SupportRecord) bool {
					return row.Kind == contract.GeneratedHazardSupportKind && row.RecordID == state.results[0].Expected.Template.HazardID
				})
			}
			accepted := a.candidateTerminalUncertain(candidate)
			if damage == "exact" && !accepted {
				t.Fatal("local success handoff changed the required real Cloudflare sibling closure")
			}
			if damage != "exact" && accepted {
				t.Fatal("local success handoff let Final discard real Cloudflare custody")
			}
		})
	}
}

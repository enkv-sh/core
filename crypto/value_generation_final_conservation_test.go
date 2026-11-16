package crypto

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/internal/custody"
)

func generatedFinalConservationCandidate(t *testing.T, f generatedRuntimeFixture, prepared contract.CryptoGeneratedFinishPlanResult) generatedCandidate {
	t.Helper()
	initial := f
	initial.compare.ParentPlan = contract.GeneratedParentPlan(f.compare.Parent)
	initial.compare.ParentPlan.RequestIdentityDigest = contract.ID{}
	c := generatedPlanCandidate(t, initial, prepared)
	c.SupportRecords = slices.DeleteFunc(c.SupportRecords, func(row contract.SupportRecord) bool {
		return row.Kind == contract.GeneratedParentSupportKind && row.RecordID == f.compare.Parent.OperationID
	})
	phase, err := contract.GeneratorPhaseID(f.final.Phase)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := contract.GeneratorPhaseSnapshotID(phase)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := contract.GeneratorPhaseRevisionID(phase)
	if err != nil {
		t.Fatal(err)
	}
	generatedRewriteHead(t, &c, func(head *format.HeadCore) { head.Root.Object, head.Revision = snapshot, revision })
	c.Subject.Purpose, c.Subject.PhaseID = contract.GeneratorAuthorityFinal, phase
	c.Subject.BeforePhase, c.Subject.AfterPhase = f.final.Phase.BeforePhase, f.final.Phase.AfterPhase
	c.CurrentAccess.CurrentControl = f.final.Session.Control.CurrentControl
	c.CurrentAccess.AccessGeneration++
	return c
}

func generatedFinalConservationDescriptors(t *testing.T, c *generatedCandidate) {
	t.Helper()
	generatedCanonicalizeCandidateSupport(t, c)
	slices.SortFunc(c.AccessRecords, func(a, b contract.AccessRecord) int {
		if a.MaterialKind != b.MaterialKind {
			return int(a.MaterialKind) - int(b.MaterialKind)
		}
		return bytes.Compare(a.MaterialID[:], b.MaterialID[:])
	})
	var err error
	if len(c.AccessRecords) == 0 {
		c.CurrentAccess.AccessPageRefs = nil
	} else {
		if len(c.CurrentAccess.AccessPageRefs) != 1 {
			t.Fatal("small final fixture must have one access page")
		}
		page := format.AccessPage{Domain: c.PublicState.Domain, Object: c.CurrentAccess.AccessPageRefs[0].Object,
			Index: 0, Records: c.AccessRecords}
		body, err := format.EncodeAccessPage(page)
		if err != nil {
			t.Fatal("coherent candidate access page", err)
		}
		ref, err := format.Reference(format.AccessKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal("coherent candidate access page reference", err)
		}
		c.CurrentAccess.AccessPageRefs = []contract.Ref{ref}
	}
	c.CurrentAccess.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(c.PublicState.Domain, c.AccessRecords)
	if err != nil {
		t.Fatal("coherent candidate access", err)
	}
	c.PublicState.AccessRoot, err = contract.AccessRoot(c.CurrentAccess)
	if err != nil {
		t.Fatal("coherent candidate access root", err)
	}
	c.Subject.AfterAccessDigest = c.PublicState.AccessRoot
	for _, row := range c.SupportRecords {
		if _, err := contract.InspectSupportRecordDigest(c.PublicState.Domain, row); err != nil {
			t.Fatal("coherent candidate support row", row.Kind, err)
		}
	}
}

func generatedFinalConservationGraph(t *testing.T, f generatedRuntimeFixture, c *generatedCandidate) {
	t.Helper()
	head, err := format.DecodeHeadCore(c.HeadCore)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := contract.DecodeGeneratorPlanBundle(f.graph)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.graph) > contract.GeneratedFragmentMaxPayload {
		t.Fatal("small closure fixture exceeded one graph fragment")
	}
	blob := contract.Hash(f.graph)
	fragment, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: 1, BlobID: blob, Count: 1,
		TotalLength: uint64(len(f.graph)), WholeDigest: blob, Payload: f.graph})
	if err != nil {
		t.Fatal(err)
	}
	fragmentID, err := contract.GeneratorFragmentID(blob, 0)
	if err != nil {
		t.Fatal(err)
	}
	location, err := contract.EncodeGeneratorSliceLocation(contract.GeneratorSliceLocation{Schema: 1,
		ContentKind: contract.GeneratorContentGraph, ContentID: graph.UsePlan.PlanGraphID, BlobID: blob,
		Length: uint32(len(f.graph)), Digest: blob})
	if err != nil {
		t.Fatal(err)
	}
	c.SupportRecords = append(c.SupportRecords, contract.SupportRecord{Kind: contract.GeneratedFragmentSupportKind, RecordID: fragmentID, Body: fragment})
	c.SupportRecords = append(c.SupportRecords, generatedVectorSupport(t, c.PublicState.Domain, contract.GeneratorSnapshotOwner,
		head.Root.Object, contract.GeneratorVectorSlices, [][]byte{location})...)
}

func generatedFinalConservationOwner(t *testing.T, f generatedRuntimeFixture, selected generatedResultAdmission, body []byte,
	state uint8, cleanup bool) []contract.SupportRecord {
	t.Helper()
	x := selected.Expected.Template
	result, err := contract.DecodeGeneratedResultRecord(body)
	if err != nil {
		t.Fatal(err)
	}
	template, err := contract.GeneratorTemplateID(x)
	if err != nil {
		t.Fatal(err)
	}
	empty := contract.EmptyGeneratorVector
	attempt := contract.GeneratedAttemptRecord{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratedAttemptRecordSchema, DomainID: f.compare.Context.DomainID, OperationID: f.compare.Parent.OperationID,
		LineageID: x.LineageID, AttemptID: x.AttemptID, TemplateDigest: template, PredecessorAttemptID: x.PredecessorAttemptID,
		OwnerID: x.DutyID, ResourceID: x.ResourceIncarnationID, TransmissionID: x.TransmissionID, ResultID: x.ResultID, InboxID: x.InboxID,
		DescriptorID: x.DescriptorID, ConfigContractID: x.ConfigContractID, ExecutorID: x.ExecutorID, CredentialRouteID: x.CredentialRouteID,
		ResourceContractID: x.ResourceContractID, ResultContractID: x.ResultContractID, RequestDigest: selected.Expected.RequestDigest,
		State: state, Stage: contract.GeneratedStageTerminal, CompletionClass: x.CompletionClass,
		Facts: empty(contract.GeneratorVectorFacts), Progress: empty(contract.GeneratorVectorProgress),
		Support: empty(contract.GeneratorVectorSupport), History: empty(contract.GeneratorVectorHistory)}
	graph, err := contract.DecodeGeneratorPlanBundle(f.graph)
	if err != nil {
		t.Fatal(err)
	}
	lineage := graph.Lineages[slices.IndexFunc(graph.Lineages, func(row contract.GeneratorLineageTemplate) bool { return row.LineageID == x.LineageID })]
	target, err := contract.EncodeGeneratorTarget(contract.GeneratorTarget{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratorTargetSchema, Name: lineage.Name,
		IncarnationID: lineage.EntryIncarnationID, Epoch: lineage.Epoch, ResourceID: x.ResourceIncarnationID,
		ResourceDigest: generatedFixtureResourceDigest(t, result.SafeFacts), ConfigContractID: x.ConfigContractID, ResourceContractID: x.ResourceContractID,
		OriginalOperationID: f.compare.Parent.OperationID, OriginalAttemptID: x.AttemptID, ResultContractID: x.ResultContractID,
		CompletionClass: x.CompletionClass})
	if err != nil {
		t.Fatal(err)
	}
	ownerKind, ownerID := uint8(contract.GeneratedHazardSupportKind), x.HazardID
	if cleanup {
		ownerKind, ownerID = contract.GeneratedDutySupportKind, x.DutyID
	}
	use, err := contract.GeneratorResultUseDigest(selected.Expected.Use)
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := contract.EncodeGeneratorConsumer(contract.GeneratorConsumer{Schema: 1, OwnerID: ownerID,
		MaterialID: f.compare.MaterialID, ContextDigest: use, SubjectKind: contract.GeneratorConsumerOriginalResult,
		SubjectID: x.ResultID, Purpose: contract.GeneratorConsumerAdoptLateOriginalResult})
	if err != nil {
		t.Fatal(err)
	}
	targets, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorTargets, [][]byte{target})
	if err != nil {
		t.Fatal(err)
	}
	consumers, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorConsumers, [][]byte{consumer})
	if err != nil {
		t.Fatal(err)
	}
	facts, err := contract.EncodeGeneratorSafeFacts(result.SafeFacts)
	if err != nil {
		t.Fatal(err)
	}
	fact, err := contract.EncodeGeneratorFactsRow(contract.GeneratorFactsRow{Schema: 1, ResultID: x.ResultID, Facts: facts})
	if err != nil {
		t.Fatal(err)
	}
	attempt.Facts, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorFacts, [][]byte{fact})
	if err != nil {
		t.Fatal(err)
	}
	attemptBody, err := contract.EncodeGeneratedAttemptRecord(attempt)
	if err != nil {
		t.Fatal(err)
	}
	rows := []contract.SupportRecord{{Kind: contract.GeneratedAttemptSupportKind, RecordID: x.AttemptID, Body: attemptBody},
		{Kind: contract.GeneratedResultSupportKind, RecordID: x.ResultID, Body: bytes.Clone(body)}}
	var owner []byte
	if cleanup {
		owner, err = contract.EncodeGeneratedDutyRecord(contract.GeneratedDutyRecord{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratedDutyRecordSchema, DomainID: attempt.DomainID,
			DutyID: ownerID, OwnerID: x.DutyID, OriginalOperationID: attempt.OperationID, OriginalAttemptID: x.AttemptID,
			ResourceID: x.ResourceIncarnationID, DescriptorID: x.DescriptorID, ConfigContractID: x.ConfigContractID, ExecutorID: x.ExecutorID,
			CredentialRouteID: x.CredentialRouteID, ResourceContractID: x.ResourceContractID, ResultContractID: x.ResultContractID,
			Kind: contract.GeneratedDutyUnselectedCleanup, CompletionClass: x.CompletionClass, Step: 1, Status: contract.GeneratedEffectSucceeded,
			CapacityReservation: f.compare.Parent.Capacity, Target: targets, Progress: empty(contract.GeneratorVectorProgress),
			History: attempt.History, Support: empty(contract.GeneratorVectorSupport), Consumers: consumers})
	} else {
		originals, descriptorErr := contract.GeneratorRecordSetDescriptor(contract.GeneratorHazardResults, attempt.DomainID, rows[1:])
		if descriptorErr != nil {
			t.Fatal(descriptorErr)
		}
		owner, err = contract.EncodeGeneratedHazardRecord(contract.GeneratedHazardRecord{Schema: contract.GeneratedHazardRecordSchema, DomainID: attempt.DomainID,
			HazardID: ownerID, OwnerID: x.DutyID, OriginalOperationID: attempt.OperationID, OriginalAttemptID: x.AttemptID,
			ResourceID: x.ResourceIncarnationID, DescriptorID: x.DescriptorID, ConfigContractID: x.ConfigContractID, ExecutorID: x.ExecutorID,
			CredentialRouteID: x.CredentialRouteID, ResourceContractID: x.ResourceContractID, ResultContractID: x.ResultContractID,
			Exposure: contract.GeneratedExposureLateEffect, CompletionClass: x.CompletionClass, Fenced: 1, Eligibility: contract.GeneratedExposureLateEffect,
			CapacityReservation: f.compare.Parent.Capacity, OriginalResults: originals, Target: targets, History: attempt.History,
			Support: empty(contract.GeneratorVectorSupport), Consumers: consumers})
	}
	if err != nil {
		t.Fatal(err)
	}
	rows = append(rows, contract.SupportRecord{Kind: ownerKind, RecordID: ownerID, Body: owner})
	rows = append(rows, generatedVectorSupport(t, attempt.DomainID, ownerKind, ownerID, contract.GeneratorVectorTargets, [][]byte{target})...)
	rows = append(rows, generatedVectorSupport(t, attempt.DomainID, ownerKind, ownerID, contract.GeneratorVectorConsumers, [][]byte{consumer})...)
	rows = append(rows, generatedVectorSupport(t, attempt.DomainID, contract.GeneratedAttemptSupportKind, x.AttemptID, contract.GeneratorVectorFacts, [][]byte{fact})...)
	return rows
}

func generatedOwnedUnusableFinalFixture(t *testing.T, recovery bool) (generatedRuntimeFixture, contract.CryptoGeneratedFinishPlanResult, generatedCandidate) {
	t.Helper()
	f, prepared, _, _ := generatedEntriesFixture(t, recovery)
	expected := f.final.Results[0].Expected
	seed := generatedTestSeed(t, f, prepared)
	defer clear(seed)
	facts := generatedProducerFacts(expected)
	facts.Disposition, facts.Reason = contract.GeneratorDispositionOwnedUnusableCreate, contract.GeneratorReasonMissingValue
	result, err := custody.SealGeneratedResult(expected, prepared.Material, facts, seed, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeGeneratedResultRecord(result)
	if err != nil {
		t.Fatal(err)
	}
	f.final.Results = []generatedResultAdmission{{Expected: expected, Reference: contract.GeneratorResultReference{Schema: 1,
		ResultID: expected.Template.ResultID, ResultBodyDigest: contract.Hash(body), ResultLength: uint32(len(body))}}}
	f.final.ResultBodies, f.final.EntryAdmissions = [][]byte{body}, nil
	descriptor, err := contract.GeneratorResultReferencesDescriptor([]contract.GeneratorResultReference{f.final.Results[0].Reference})
	if err != nil {
		t.Fatal(err)
	}
	f.final.Phase.Evidence = contract.GeneratorDescriptor(descriptor)
	c := generatedFinalConservationCandidate(t, f, prepared)
	owners := generatedFinalConservationOwner(t, f, f.final.Results[0], body, contract.GeneratedEffectFailedTerminal, false)
	c.SupportRecords = append(c.SupportRecords, owners...)
	generatedFinalConservationGraph(t, f, &c)
	generatedFinalConservationDescriptors(t, &c)
	before := slices.Clone(c.SupportRecords)
	before = slices.DeleteFunc(before, func(row contract.SupportRecord) bool {
		if row.Kind == contract.GeneratorVectorSupportKind {
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			return carrier.OwnerKind != contract.GeneratedAttemptSupportKind
		}
		return row.Kind == contract.GeneratedFragmentSupportKind || row.Kind == contract.GeneratedHazardSupportKind
	})
	var hazard contract.GeneratedHazardRecord
	var target []byte
	for _, row := range owners {
		switch row.Kind {
		case contract.GeneratedHazardSupportKind:
			hazard, err = contract.InspectGeneratedHazardRecord(row.Body)
			if err != nil {
				t.Fatal(err)
			}
		case contract.GeneratorVectorSupportKind:
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			if carrier.OwnerKind == contract.GeneratedHazardSupportKind && carrier.VectorKind == contract.GeneratorVectorTargets {
				target = carrier.Row
			}
		}
	}
	x := expected.Template
	use, err := contract.GeneratorResultUseDigest(expected.Use)
	if err != nil {
		t.Fatal(err)
	}
	var consumers [][]byte
	for _, purpose := range []uint8{contract.GeneratorConsumerDeriveSelectedResult, contract.GeneratorConsumerAdoptLateOriginalResult} {
		consumer, err := contract.EncodeGeneratorConsumer(contract.GeneratorConsumer{Schema: 1, OwnerID: x.DutyID,
			MaterialID: f.compare.MaterialID, ContextDigest: use, SubjectKind: contract.GeneratorConsumerOriginalResult,
			SubjectID: x.ResultID, Purpose: purpose})
		if err != nil {
			t.Fatal(err)
		}
		consumers = append(consumers, consumer)
	}
	consumerDescriptor, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorConsumers, consumers)
	if err != nil {
		t.Fatal(err)
	}
	duty, err := contract.EncodeGeneratedDutyRecord(contract.GeneratedDutyRecord{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratedDutyRecordSchema, DomainID: hazard.DomainID,
		DutyID: x.DutyID, OwnerID: x.DutyID, OriginalOperationID: hazard.OriginalOperationID, OriginalAttemptID: x.AttemptID,
		ResourceID: x.ResourceIncarnationID, DescriptorID: x.DescriptorID, ConfigContractID: x.ConfigContractID, ExecutorID: x.ExecutorID,
		CredentialRouteID: x.CredentialRouteID, ResourceContractID: x.ResourceContractID, ResultContractID: x.ResultContractID,
		Kind: contract.GeneratedDutyCreate, CompletionClass: x.CompletionClass, Step: 1, Status: contract.GeneratedEffectFailedTerminal,
		CapacityReservation: hazard.CapacityReservation, Target: hazard.Target, History: hazard.History, Support: hazard.Support,
		Progress: contract.EmptyGeneratorVector(contract.GeneratorVectorProgress), Consumers: consumerDescriptor})
	if err != nil {
		t.Fatal(err)
	}
	parent, err := contract.EncodeGeneratedParentRecord(f.compare.Parent)
	if err != nil {
		t.Fatal(err)
	}
	before = append(before, contract.SupportRecord{Kind: contract.GeneratedDutySupportKind, RecordID: x.DutyID, Body: duty},
		contract.SupportRecord{Kind: contract.GeneratedParentSupportKind, RecordID: f.compare.Parent.OperationID, Body: parent})
	before = append(before, generatedVectorSupport(t, hazard.DomainID, contract.GeneratedDutySupportKind, x.DutyID, contract.GeneratorVectorTargets, [][]byte{target})...)
	before = append(before, generatedVectorSupport(t, hazard.DomainID, contract.GeneratedDutySupportKind, x.DutyID, contract.GeneratorVectorConsumers, consumers)...)
	f.final.Session.Output = generatedEmptyOutputWitness(t, &f.final.Session.BeforePublic, f.entries, before)
	return f, prepared, c
}

func generatedFinalConservationExchange(t *testing.T, f generatedRuntimeFixture, c generatedCandidate, plans []contract.CryptoGeneratedValueEntryPlan,
	want contract.CryptoResultCode) {
	t.Helper()
	r := f.finalRuntime(t)
	op, uses := generatedAdoptionCompare(t, r, f)
	prepared := applyCall(r, t.Context(), contract.CryptoPrepare, generatedEntriesBody(t, f, op, plans, 0, 1))
	if prepared.ResultCode != contract.CryptoSuccess {
		t.Fatal("final preparation did not reach candidate binding", prepared.ResultCode)
	}
	for _, row := range prepared.KeyUseRows {
		index := slices.IndexFunc(f.final.Session.Bindings, func(binding contract.BindingTableRow) bool {
			return binding.SubjectKind == row.SubjectKind && binding.SubjectID == row.SubjectID
		})
		if index < 0 {
			t.Fatal("prepared key use has no binding")
		}
		combined := contract.CryptoResponse{KeyUseRows: uses}
		if !appendKeyUses(&combined, f.final.Session.Bindings[index], row.Purpose, KeyUses{Completed: row.Count}, uint64(row.Count)) {
			t.Fatal("could not account for preparation key use")
		}
		uses = combined.KeyUseRows
	}
	generatedFinalConservationDescriptors(t, &c)
	refs := make([]contract.GeneratorResultReference, len(f.final.Results))
	for i, result := range f.final.Results {
		refs[i] = result.Reference
	}
	slices.SortFunc(refs, func(a, b contract.GeneratorResultReference) int { return bytes.Compare(a.ResultID[:], b.ResultID[:]) })
	q := generatedCandidateRequest(t, f, op, c, refs, uses)
	code := r.bindGeneratedCandidate(t.Context(), f.compare.Context.AdmissionID, c)
	freeze := generatedFreeze(t, r, q)
	claimBody, err := contract.EncodeCryptoGeneratedClaimRequest(contract.CryptoGeneratedClaimRequest(q))
	if err != nil {
		t.Fatal("coherent candidate claim request", err)
	}
	claim := applyCall(r, t.Context(), contract.CryptoClaim, claimBody)
	if code != want {
		t.Fatalf("candidate binding: got %v, want %v; Freeze=%v Claim=%v", code, want, freeze.ResultCode, claim.ResultCode)
	}
	if want == contract.CryptoSuccess {
		if freeze.ResultCode != contract.CryptoSuccess || claim.ResultCode != contract.CryptoSuccess {
			t.Fatal("healthy final did not Freeze and Claim", freeze.ResultCode, claim.ResultCode)
		}
	} else if freeze.ResultCode != contract.CryptoAlreadyUsed || claim.ResultCode != contract.CryptoAlreadyUsed ||
		len(freeze.Body) != 0 || len(freeze.KeyUseRows) != 0 || len(claim.Body) != 0 || len(claim.KeyUseRows) != 0 {
		t.Fatal("refused final retained Freeze or Claim rights", freeze.ResultCode, claim.ResultCode)
	}
}

// full_only: false
func TestGeneratedFinalPreservesOwnedUnusableClosure(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for _, missing := range []string{"none", "result", "attempt", "owner", "material", "seed access", "material and seed access", "late consumer", "whole relation", "whole relation except result"} {
			t.Run(fmt.Sprintf("recovery=%t/%s", recovery, missing), func(t *testing.T) {
				f, _, c := generatedOwnedUnusableFinalFixture(t, recovery)
				if missing == "late consumer" {
					for i, row := range c.SupportRecords {
						if row.Kind != contract.GeneratedHazardSupportKind {
							continue
						}
						hazard, err := contract.InspectGeneratedHazardRecord(row.Body)
						if err != nil {
							t.Fatal(err)
						}
						hazard.Consumers = contract.EmptyGeneratorVector(contract.GeneratorVectorConsumers)
						c.SupportRecords[i].Body, err = contract.EncodeGeneratedHazardRecord(hazard)
						if err != nil {
							t.Fatal(err)
						}
					}
				}
				whole := missing == "whole relation" || missing == "whole relation except result"
				c.SupportRecords = slices.DeleteFunc(c.SupportRecords, func(row contract.SupportRecord) bool {
					switch row.Kind {
					case contract.GeneratedResultSupportKind:
						return missing == "result" || missing == "whole relation"
					case contract.GeneratedAttemptSupportKind:
						return missing == "attempt" || whole
					case contract.GeneratedHazardSupportKind:
						return missing == "owner" || whole
					case contract.OperationMaterialSupportKind:
						return missing == "material" || missing == "material and seed access" || whole
					case contract.GeneratorVectorSupportKind:
						carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
						if err != nil {
							t.Fatal(err)
						}
						return carrier.OwnerKind == contract.GeneratedHazardSupportKind &&
							(missing == "owner" || whole || missing == "late consumer" && carrier.VectorKind == contract.GeneratorVectorConsumers) ||
							carrier.OwnerKind == contract.GeneratedAttemptSupportKind && (missing == "attempt" || whole)
					}
					return false
				})
				if missing == "seed access" || missing == "material and seed access" || whole {
					c.AccessRecords = nil
				}
				want := contract.CryptoInvalidAdmission
				if missing == "none" {
					want = contract.CryptoSuccess
				}
				generatedFinalConservationExchange(t, f, c, nil, want)
			})
		}
	}
}

// full_only: false
func TestGeneratedSelectingFinalRefusesSelectedCreateCleanup(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("recovery=%t", recovery), func(t *testing.T) {
			f, prepared, plan, evidence := generatedEntriesFixture(t, recovery)
			r := f.finalRuntime(t)
			op, uses := generatedAdoptionCompare(t, r, f)
			reply := applyCall(r, t.Context(), contract.CryptoPrepare, generatedEntriesBody(t, f, op, []contract.CryptoGeneratedValueEntryPlan{plan}, 0, 1))
			if reply.ResultCode != contract.CryptoSuccess {
				t.Fatal("selecting preparation", reply.ResultCode)
			}
			view, err := contract.InspectCryptoGeneratedValueEntriesResult(reply.Body)
			if err != nil {
				t.Fatal(err)
			}
			output, err := view.Own()
			if err != nil || len(output.Rows) != 1 {
				t.Fatal("selecting prepared output", err)
			}
			c := generatedEntriesCandidate(t, f, prepared, output.Rows[0], evidence)
			material, err := contract.EncodeOperationMaterialRecord(prepared.Material)
			if err != nil {
				t.Fatal(err)
			}
			seedAccess, err := contract.DecodeAccessRecord(prepared.SeedAccess)
			if err != nil {
				t.Fatal(err)
			}
			c.SupportRecords = append(c.SupportRecords, contract.SupportRecord{Kind: contract.OperationMaterialSupportKind,
				RecordID: f.compare.MaterialID, Body: material})
			c.AccessRecords = append(c.AccessRecords, seedAccess)
			c.SupportRecords = append(c.SupportRecords, generatedFinalConservationOwner(t, f, f.final.Results[0], f.final.ResultBodies[0], contract.GeneratedEffectSucceeded, true)...)
			generatedFinalConservationGraph(t, f, &c)
			generatedFinalConservationDescriptors(t, &c)
			combined := contract.CryptoResponse{KeyUseRows: uses}
			for _, row := range reply.KeyUseRows {
				index := slices.IndexFunc(f.final.Session.Bindings, func(binding contract.BindingTableRow) bool {
					return binding.SubjectKind == row.SubjectKind && binding.SubjectID == row.SubjectID
				})
				if index < 0 || !appendKeyUses(&combined, f.final.Session.Bindings[index], row.Purpose, KeyUses{Completed: row.Count}, uint64(row.Count)) {
					t.Fatal("selecting key use")
				}
			}
			q := generatedCandidateRequest(t, f, op, c, []contract.GeneratorResultReference{f.final.Results[0].Reference}, combined.KeyUseRows)
			code := r.bindGeneratedCandidate(t.Context(), f.compare.Context.AdmissionID, c)
			freeze := generatedFreeze(t, r, q)
			claimBody, err := contract.EncodeCryptoGeneratedClaimRequest(contract.CryptoGeneratedClaimRequest(q))
			if err != nil {
				t.Fatal(err)
			}
			claim := applyCall(r, context.Background(), contract.CryptoClaim, claimBody)
			if code != contract.CryptoInvalidAdmission {
				t.Fatal("fulfilled selected create gained cleanup ownership", code, "Freeze", freeze.ResultCode, "Claim", claim.ResultCode)
			}
			if freeze.ResultCode != contract.CryptoAlreadyUsed || claim.ResultCode != contract.CryptoAlreadyUsed ||
				len(freeze.Body) != 0 || len(freeze.KeyUseRows) != 0 || len(claim.Body) != 0 || len(claim.KeyUseRows) != 0 {
				t.Fatal("selected-create cleanup refusal left Freeze or Claim rights", freeze.ResultCode, claim.ResultCode)
			}
		})
	}
}

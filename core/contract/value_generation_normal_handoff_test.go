package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"reflect"
	"slices"
	"testing"

	protocol "enkv.sh/sdk/protocols/generator"
)

// full_only: false
func TestGeneratedSelectedCreateAncestryPreservesAggregateBounds(t *testing.T) {
	for _, maximum := range []bool{false, true} {
		for _, cross := range []bool{false, true} {
			t.Run(fmt.Sprintf("maximum%t/cross%t", maximum, cross), func(t *testing.T) {
				records, source, snapshot := selectedCreateAncestryFixture(t, maximum, cross)
				if count, err := InspectGeneratedSelectedCreateAncestry(source.DomainID, snapshot, records, source); err != nil || count != 2 {
					t.Fatal("complete selected actual create prefix", count, err)
				}
				for _, fault := range []string{"snapshot", "carrier", "graph", "prefix", "missing-fragment", "bridge"} {
					t.Run(fault, func(t *testing.T) {
						bad := slices.Clone(records)
						badSource, badSnapshot := source, snapshot
						switch fault {
						case "snapshot":
							badSnapshot = generatedRecordID(99)
						case "missing-fragment":
							for i, row := range bad {
								if row.Kind == 3 {
									bad = append(bad[:i], bad[i+1:]...)
									break
								}
							}
						case "carrier":
							for i, row := range bad {
								if row.Kind != GeneratorVectorSupportKind {
									continue
								}
								c, _ := InspectGeneratorVectorCarrier(row.Body)
								if c.VectorKind == GeneratorVectorSlices {
									bad[i].RecordID = generatedRecordID(99)
									break
								}
							}
						case "graph":
							for i, row := range bad {
								if row.Kind == 3 {
									bad[i].Body = bytes.Clone(row.Body)
									bad[i].Body[len(row.Body)-1] ^= 1
									break
								}
							}
						case "prefix", "bridge":
							var prefix [][]byte
							if err := InspectGeneratorSelectedVector(source.DomainID, 11, source.SourceID, GeneratorVectorHistory, source.History, bad, func(_ uint32, body []byte) error { prefix = append(prefix, bytes.Clone(body)); return nil }); err != nil {
								t.Fatal(err)
							}
							index := 0
							if fault == "bridge" {
								index = 1
							}
							h, _ := InspectGeneratorHistory(prefix[index])
							if fault == "prefix" {
								h.OwnerID = source.OwnerID
							} else {
								h.Edge, h.NextAttemptID = 2, generatedRecordID(98)
								suffix, err := EncodeGeneratorHistory(GeneratorHistory{Schema: 1, PredecessorAttemptID: h.NextAttemptID, OwnerID: source.OwnerID, Outcome: GeneratedEffectTransmitted})
								if err != nil {
									t.Fatal(err)
								}
								prefix = append(prefix, suffix)
							}
							prefix[index], _ = EncodeGeneratorHistory(h)
							var kept []SupportRecord
							for _, row := range bad {
								if row.Kind == 11 {
									continue
								}
								if row.Kind == GeneratorVectorSupportKind {
									c, _ := InspectGeneratorVectorCarrier(row.Body)
									if c.OwnerKind == 11 && c.OwnerID == source.SourceID {
										continue
									}
								}
								kept = append(kept, row)
							}
							badSource.Hazard.History, bad = selectedAncestryVector(t, kept, source.DomainID, 11, source.SourceID, GeneratorVectorHistory, prefix)
							badSource.Record.Body, _ = EncodeGeneratedHazardRecord(badSource.Hazard)
							badSource, _ = InspectGeneratedDeleteSource(badSource.Record)
							bad = append(bad, badSource.Record)
						}
						if _, err := InspectGeneratedSelectedCreateAncestry(source.DomainID, badSnapshot, bad, badSource); err == nil {
							t.Fatal("changed complete ancestry accepted")
						}
					})
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedSelectedCreateAncestryBindsRetainedPredecessor(t *testing.T) {
	for _, released := range []bool{false, true} {
		t.Run(fmt.Sprintf("released%t", released), func(t *testing.T) {
			for _, fault := range []string{"", "attempt-domain", "attempt-operation", "packet-domain", "packet-operation", "packet-attempt", "release-domain", "release-result", "release-inbox"} {
				if released && (fault == "packet-domain" || fault == "packet-operation" || fault == "packet-attempt") || !released && (fault == "release-domain" || fault == "release-result" || fault == "release-inbox") {
					continue
				}
				t.Run(fault, func(t *testing.T) {
					records, source, snapshot := selectedCreateAncestryFixture(t, false, false)
					records, source = selectedRetainedCreatePredecessor(t, records, source, snapshot, released, fault)
					count, err := InspectGeneratedSelectedCreateAncestry(source.DomainID, snapshot, records, source)
					if fault == "" && (err != nil || count != 2) || fault != "" && err == nil {
						t.Fatal("retained predecessor identity binding", count, err)
					}
				})
			}
		})
	}
	t.Run("detached", func(t *testing.T) {
		entry, evidence, _ := generatedEntryEvidenceFixture(t, GeneratorBranchInitial)
		core, err := InspectGeneratedResultCore(evidence.ResultCore)
		if err != nil {
			t.Fatal("original detached result core", err)
		}
		original := generatorGraphCreateIntentFixture(t, entry.Name, entry.Generated.IntentDigest).Templates[GeneratorBranchInitial]
		if original.AttemptID != core.AttemptID {
			t.Fatal("detached original template differs")
		}
		body, err := EncodeGeneratedCreateEvidence(evidence)
		if err != nil {
			t.Fatal("original detached evidence", err)
		}
		evidenceRow := SupportRecord{Kind: GeneratedCreateEvidenceSupportKind, RecordID: core.ResultID, Body: body}
		owner, err := GeneratorDutyID(core.DomainID, core.OperationID, core.AttemptID, GeneratedDutyCreate)
		if err != nil {
			t.Fatal(err)
		}
		hazard, err := GeneratorHazardID(core.DomainID, core.AttemptID)
		if err != nil {
			t.Fatal(err)
		}
		originalResults, err := GeneratorRecordSetDescriptor(GeneratorHazardResults, core.DomainID, []SupportRecord{evidenceRow})
		if err != nil {
			t.Fatal("detached original result set", err)
		}
		target, err := EncodeGeneratorTarget(GeneratorTarget{Schema: GeneratorTargetSchema, LifecycleMode: GeneratorLifecycleManaged,
			Name: entry.Name, IncarnationID: entry.Incarnation, Epoch: entry.Generated.Epoch, ResourceID: entry.Generated.ResourceIncarnationID,
			ResourceDigest: entry.Generated.ResourceDigest, ConfigContractID: core.ConfigContractID, ResourceContractID: entry.Generated.ResourceContractID,
			OriginalOperationID: core.OperationID, OriginalAttemptID: core.AttemptID, ResultContractID: core.ResultContractID, CompletionClass: evidence.CompletionClass})
		if err != nil {
			t.Fatal("detached original target", err)
		}
		targets, records := selectedAncestryVector(t, []SupportRecord{evidenceRow}, core.DomainID, GeneratedHazardSupportKind, hazard, GeneratorVectorTargets, [][]byte{target})
		h := GeneratedHazardRecord{Schema: GeneratedHazardRecordSchema, DomainID: core.DomainID, HazardID: hazard,
			OriginalOperationID: core.OperationID, OriginalAttemptID: core.AttemptID, OwnerID: owner, ResourceID: entry.Generated.ResourceIncarnationID,
			DescriptorID: core.DescriptorID, ConfigContractID: core.ConfigContractID, ExecutorID: core.ExecutorID, CredentialRouteID: original.CredentialRouteID,
			ResourceContractID: entry.Generated.ResourceContractID, ResultContractID: core.ResultContractID,
			Exposure: GeneratedExposureLateEffect, CompletionClass: evidence.CompletionClass, Fenced: 1, Eligibility: GeneratedExposureLateEffect,
			CapacityReservation: generatedRecordDescriptor(75), OriginalResults: originalResults, Target: targets,
			History: EmptyGeneratorVector(GeneratorVectorHistory), Support: EmptyGeneratorVector(GeneratorVectorSupport), Consumers: EmptyGeneratorVector(GeneratorVectorConsumers)}
		for _, fault := range []string{"exact", "descriptor", "executor", "route"} {
			t.Run(fault, func(t *testing.T) {
				changed := h
				switch fault {
				case "descriptor":
					changed.DescriptorID = generatedRecordID(99)
				case "executor":
					changed.ExecutorID = generatedRecordID(99)
				case "route":
					changed.CredentialRouteID = generatedRecordID(99)
				}
				body, err := EncodeGeneratedHazardRecord(changed)
				if err != nil {
					t.Fatal("detached source record", err)
				}
				row := SupportRecord{Kind: GeneratedHazardSupportKind, RecordID: hazard, Body: body}
				source, err := InspectGeneratedDeleteSource(row)
				if err != nil {
					t.Fatal("detached decoded source", err)
				}
				selected := append(slices.Clone(records), row)
				count, err := InspectGeneratedSelectedCreateAncestry(core.DomainID, generatedRecordID(61), selected, source)
				if fault == "exact" && (err != nil || count != 0) || fault != "exact" && err == nil {
					t.Fatal("detached original implementation binding", count, err)
				}
			})
		}
	})
}

// full_only: false
func TestGeneratedSelectedCreateAncestryPreservesLateNoEffectResidue(t *testing.T) {
	for _, fault := range []string{"", "release-unknown", "release-missing", "release-domain", "release-result", "release-inbox", "release-unobserved", "release-capacity", "release-evidence", "attempt-operation", "attempt-domain", "attempt-delete-result", "attempt-facts", "residue-history-result", "residue-history-edge"} {
		t.Run(fault, func(t *testing.T) {
			records, source, snapshot := selectedCreateAncestryFixture(t, false, false, true)
			records, source = selectedRetainedCreatePredecessor(t, records, source, snapshot, true, fault)
			count, err := InspectGeneratedSelectedCreateAncestry(source.DomainID, snapshot, records, source)
			valid := fault == "" || fault == "release-unknown"
			if valid && (err != nil || count != 2) || !valid && err == nil {
				t.Fatal("late no-effect release did not preserve only the qualified residue prefix", count, err)
			}
		})
	}
}

func selectedRetainedCreatePredecessor(t *testing.T, records []SupportRecord, source GeneratedDeleteSource, snapshot ID, released bool, fault string) ([]SupportRecord, GeneratedDeleteSource) {
	t.Helper()
	var original GeneratedAttemptRecord
	var packet GeneratedResultRecord
	var location GeneratorSliceLocation
	for _, row := range records {
		switch row.Kind {
		case 9:
			original, _ = InspectGeneratedAttemptRecord(row.Body)
		case 4:
			packet, _ = DecodeGeneratedResultRecord(row.Body)
		case GeneratorVectorSupportKind:
			c, _ := InspectGeneratorVectorCarrier(row.Body)
			if c.VectorKind == GeneratorVectorSlices {
				location, _ = InspectGeneratorSliceLocation(c.Row)
			}
		}
	}
	graphBody, err := InspectGeneratedImmutableSlice(source.DomainID, snapshot, records, location, GeneratorGraphMaxLength)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := DecodeGeneratorPlanBundle(graphBody)
	if err != nil {
		t.Fatal(err)
	}
	x := graph.Lineages[0].Templates[0]
	a := original
	a.AttemptID, a.TemplateDigest, a.PredecessorAttemptID, a.OwnerID, a.ResourceID = x.AttemptID, ID{}, x.PredecessorAttemptID, x.DutyID, x.ResourceIncarnationID
	a.TemplateDigest, _ = GeneratorTemplateID(x)
	a.TransmissionID, a.ResultID, a.InboxID, a.State = x.TransmissionID, x.ResultID, x.InboxID, GeneratedEffectConfirmedNoEffect
	a.History = EmptyGeneratorVector(GeneratorVectorHistory)
	packet.SafeFacts = generatedSafeFactsFixture(3)
	packet.SafeFacts.ResourceContractID, packet.SafeFacts.IntentDigest, packet.SafeFacts.RequestDigest = x.ResourceContractID, x.IntentDigest, a.RequestDigest
	packet.Core.AttemptID, packet.Core.TransmissionID, packet.Core.ResultID = a.AttemptID, a.TransmissionID, a.ResultID
	packet.Core.SafeFactsDigest, _ = GeneratorSafeFactsDigest(packet.SafeFacts)
	switch fault {
	case "packet-domain":
		packet.Core.DomainID = generatedRecordID(98)
	case "packet-operation":
		packet.Core.OperationID = generatedRecordID(98)
	case "packet-attempt":
		packet.Core.AttemptID = generatedRecordID(98)
	}
	packet.Transfer.Core.DomainID, packet.Transfer.Core.OperationID, packet.Transfer.Core.AttemptID, packet.Transfer.Core.ResultID = packet.Core.DomainID, packet.Core.OperationID, packet.Core.AttemptID, packet.Core.ResultID
	packet.Transfer.Core.ResultCoreDigest, _ = GeneratedResultCoreDigest(packet.Core)
	packet.Payload.DataKeyID, packet.Payload.CommitmentKeyID, _ = GeneratorResultKeyIDs(a.ResultID)
	packetBody, err := EncodeGeneratedResultRecord(packet)
	if err != nil {
		t.Fatal(err)
	}
	switch fault {
	case "attempt-domain":
		a.DomainID = generatedRecordID(98)
	case "attempt-operation":
		a.OperationID = generatedRecordID(98)
	case "attempt-delete-result":
		a.ResultID, _ = GeneratorResultID(a.DomainID, a.OperationID, a.AttemptID, a.TransmissionID, GeneratorActionDelete)
	case "attempt-facts":
		a.Facts = GeneratorDescriptor{Digest: generatedRecordID(98), Length: 8, Count: 1}
	}
	aBody, err := EncodeGeneratedAttemptRecord(a)
	if err != nil {
		t.Fatal(err)
	}
	var bodies [][]byte
	if err := InspectGeneratorSelectedVector(source.DomainID, 9, original.AttemptID, GeneratorVectorHistory, original.History, records, func(index uint32, body []byte) error {
		h, err := InspectGeneratorHistory(body)
		if index == 0 {
			if fault == "residue-history-result" {
				h.ResultID = a.ResultID
			}
			if !h.ResultID.IsZero() {
				h.ResultDigest = Hash(packetBody)
			}
			if fault == "residue-history-edge" {
				h.Edge = GeneratorGuardQualifiedNoEffect
			}
		}
		wire, wireErr := EncodeGeneratorHistory(h)
		if err != nil || wireErr != nil {
			return ErrRecord
		}
		bodies = append(bodies, wire)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var kept []SupportRecord
	for _, row := range records {
		if row.Kind == 11 || row.Kind == 9 && row.RecordID == original.AttemptID {
			continue
		}
		if row.Kind == GeneratorVectorSupportKind {
			c, _ := InspectGeneratorVectorCarrier(row.Body)
			if c.VectorKind == GeneratorVectorHistory && (c.OwnerKind == 9 && c.OwnerID == original.AttemptID || c.OwnerKind == 11 && c.OwnerID == source.SourceID) {
				continue
			}
		}
		kept = append(kept, row)
	}
	original.History, kept = selectedAncestryVector(t, kept, source.DomainID, 9, original.AttemptID, GeneratorVectorHistory, bodies)
	originalBody, _ := EncodeGeneratedAttemptRecord(original)
	kept = append(kept, SupportRecord{Kind: 9, RecordID: original.AttemptID, Body: originalBody}, SupportRecord{Kind: 9, RecordID: x.AttemptID, Body: aBody})
	if released {
		r := PendingInboxReleaseRecord{Schema: 1, DomainID: source.DomainID, InboxID: x.InboxID, OriginalResultID: x.ResultID, SelectedHandoffDigest: Hash(packetBody), HandoffRevisionID: generatedRecordID(97), CapacityReservation: source.CapacityReservation, ObjectLength: uint32(len(packetBody)), State: GeneratedReleasePending}
		switch fault {
		case "release-domain":
			r.DomainID = generatedRecordID(98)
		case "release-result":
			r.OriginalResultID = generatedRecordID(98)
		case "release-inbox":
			r.InboxID = generatedRecordID(98)
		case "release-unknown":
			r.State = GeneratedReleaseUnknown
		case "release-unobserved":
			r.State, r.ObjectLength = GeneratedReleaseUnobserved, 0
		case "release-capacity":
			r.CapacityReservation.Digest = generatedRecordID(98)
		case "release-evidence":
			r.SelectedHandoffDigest = ID{}
		}
		body, err := EncodePendingInboxReleaseRecord(r)
		if fault == "release-evidence" {
			if err == nil {
				t.Fatal("empty release evidence must fail its wire contract")
			}
		} else if err != nil {
			t.Fatal("release relation fixture must remain encodable", err)
		}
		if fault != "release-missing" {
			kept = append(kept, SupportRecord{Kind: 12, RecordID: x.InboxID, Body: body})
		}
	} else {
		kept = append(kept, SupportRecord{Kind: 4, RecordID: x.ResultID, Body: packetBody})
	}
	source.Hazard.History, kept = selectedAncestryVector(t, kept, source.DomainID, 11, source.SourceID, GeneratorVectorHistory, bodies)
	source.Record.Body, _ = EncodeGeneratedHazardRecord(source.Hazard)
	source, _ = InspectGeneratedDeleteSource(source.Record)
	return append(kept, source.Record), source
}

func selectedAncestryVector(t *testing.T, records []SupportRecord, domain ID, kind uint8, owner ID, vector GeneratorVectorKind, bodies [][]byte) (GeneratorDescriptor, []SupportRecord) {
	t.Helper()
	desc, err := GeneratorVectorDescriptor(vector, bodies)
	if err != nil {
		t.Fatal(err)
	}
	for i, body := range bodies {
		c := GeneratorVectorCarrier{Schema: 1, DomainID: domain, OwnerKind: kind, OwnerID: owner, VectorKind: vector, Vector: desc, Ordinal: uint32(i), Row: body}
		wire, err := EncodeGeneratorVectorCarrier(c)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := GeneratorVectorCarrierID(c)
		records = append(records, SupportRecord{Kind: GeneratorVectorSupportKind, RecordID: id, Body: wire})
	}
	return desc, records
}

func selectedCreateAncestryFixture(t *testing.T, maximum, cross bool, residue ...bool) ([]SupportRecord, GeneratedDeleteSource, ID) {
	t.Helper()
	graph := generatorBundleFixture(t, true)
	if maximum {
		graph.Header = generatorGraphHeaderFixture(t, 512, 128, 1408)
		graph.ValueEntryPlans, graph.Lineages = nil, nil
		for i := 0; i < 128; i++ {
			create := generatorGraphCreateFixture(t, fmt.Sprintf("%03d", i))
			graph.ValueEntryPlans = append(graph.ValueEntryPlans, generatorGraphEntryPlanFixture(create, uint16(i)))
			graph.Lineages = append(graph.Lineages, create, generatorGraphDeleteFixture(t, create, 0, 2, generatedRecordID(byte(i+1))))
			for branch := uint8(0); branch < 5; branch++ {
				graph.Lineages = append(graph.Lineages, generatorGraphDeleteFixture(t, create, branch, 3, create.Templates[branch].ResourceIncarnationID))
			}
		}
		for i := 128; i < 512; i++ {
			graph.ValueEntryPlans = append(graph.ValueEntryPlans, GeneratorValueEntryPlan{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Schema: GeneratorValueEntryPlanSchema, Slot: uint16(i), Name: fmt.Sprintf("%03d", i), ValueSource: Supplied, ConfidentialityClass: Plain, EntryIncarnationID: generatedRecordID(1), SourceSlice: generatedRecordDescriptor(2), IntendedMembership: generatedRecordDescriptor(3)})
		}
		slices.SortFunc(graph.Lineages, generatorLineageCompare)
		graph.Edges = generatorGraphEdgesFixture(t, graph.Header, graph.Lineages)
		graph.ResultUses = generatorGraphUsesFixture(graph.Header, graph.Lineages)
		graph.UsePlan.PlanGraphID, _ = GeneratorGraphID(graph.Header, graph.ValueEntryPlans, graph.Lineages, graph.Edges)
		graph.UsePlan.ResultUses, _ = GeneratorResultUsesDescriptor(graph.ResultUses)
	}
	lineage := graph.Lineages[0]
	branch := GeneratorBranchNoEffect
	if len(residue) != 0 && residue[0] {
		branch = GeneratorBranchResidue
	}
	first, original := lineage.Templates[0], lineage.Templates[branch]
	wire, err := EncodeGeneratorPlanBundle(graph)
	if err != nil {
		t.Fatal(err)
	}
	if maximum && len(wire) <= 256<<10 {
		t.Fatal("aggregate did not exceed standalone ACK ceiling")
	}
	lineageWire, _ := EncodeGeneratorLineageTemplate(lineage)
	offset := uint64(0)
	if cross {
		offset = uint64(GeneratedFragmentMaxPayload - (bytes.Index(wire, lineageWire) % GeneratedFragmentMaxPayload) - 100)
	}
	blob := append(bytes.Repeat([]byte{'x'}, int(offset)), wire...)
	location := GeneratorSliceLocation{Schema: 1, ContentKind: GeneratorContentGraph, ContentID: graph.UsePlan.PlanGraphID, BlobID: Hash(blob), Offset: offset, Length: uint32(len(wire)), Digest: Hash(wire)}
	locationWire, _ := EncodeGeneratorSliceLocation(location)
	snapshot := generatedRecordID(61)
	_, records := selectedAncestryVector(t, nil, graph.Header.DomainID, GeneratorSnapshotOwner, snapshot, GeneratorVectorSlices, [][]byte{locationWire})
	count := (len(blob) + GeneratedFragmentMaxPayload - 1) / GeneratedFragmentMaxPayload
	for i := 0; i < count; i++ {
		start, stop := i*GeneratedFragmentMaxPayload, min(len(blob), (i+1)*GeneratedFragmentMaxPayload)
		f := GeneratedFragment{Schema: 1, BlobID: location.BlobID, Index: uint16(i), Count: uint16(count), TotalLength: uint64(len(blob)), WholeDigest: Hash(blob), Offset: uint32(start), Payload: blob[start:stop]}
		body, _ := EncodeGeneratedFragment(f)
		id, _ := GeneratorFragmentID(f.BlobID, f.Index)
		records = append(records, SupportRecord{Kind: 3, RecordID: id, Body: body})
	}
	history := []GeneratorHistory{{Schema: 1, PredecessorAttemptID: first.AttemptID, NextAttemptID: original.AttemptID, ResultID: first.ResultID, OwnerID: first.DutyID, ResultDigest: generatedRecordID(70), Outcome: GeneratedEffectConfirmedNoEffect, Edge: 1}, {Schema: 1, PredecessorAttemptID: original.AttemptID, ResultID: original.ResultID, OwnerID: original.DutyID, ResultDigest: generatedRecordID(71), Outcome: GeneratedEffectFailedTerminal}}
	if branch == GeneratorBranchResidue {
		history[0].ResultID, history[0].ResultDigest = ID{}, ID{}
		history[0].Outcome, history[0].Edge = GeneratedEffectClosedWithResidue, GeneratorGuardResidue
	}
	var bodies [][]byte
	for _, h := range history {
		body, _ := EncodeGeneratorHistory(h)
		bodies = append(bodies, body)
	}
	originalHistory, records := selectedAncestryVector(t, records, graph.Header.DomainID, 9, original.AttemptID, GeneratorVectorHistory, bodies)
	digest, _ := GeneratorTemplateID(original)
	a := GeneratedAttemptRecord{
		Schema:               GeneratedAttemptRecordSchema,
		DomainID:             graph.Header.DomainID,
		OperationID:          graph.Header.OperationID,
		LineageID:            original.LineageID,
		AttemptID:            original.AttemptID,
		TemplateDigest:       digest,
		PredecessorAttemptID: original.PredecessorAttemptID,
		OwnerID:              original.DutyID,
		ResourceID:           original.ResourceIncarnationID,
		TransmissionID:       original.TransmissionID,
		ResultID:             original.ResultID,
		InboxID:              original.InboxID,
		DescriptorID:         original.DescriptorID,
		ConfigContractID:     original.ConfigContractID,
		ExecutorID:           original.ExecutorID,
		CredentialRouteID:    original.CredentialRouteID,
		ResourceContractID:   original.ResourceContractID,
		ResultContractID:     original.ResultContractID,
		RequestDigest:        generatedRecordID(72),
		State:                GeneratedEffectFailedTerminal,
		Stage:                GeneratedStageTerminal,
		CompletionClass:      original.CompletionClass,
		Facts:                EmptyGeneratorVector(GeneratorVectorFacts),
		Progress:             EmptyGeneratorVector(GeneratorVectorProgress),
		Support:              EmptyGeneratorVector(GeneratorVectorSupport),
		History:              originalHistory,
		LifecycleMode:        GeneratorLifecycleManaged,
	}
	abody, _ := EncodeGeneratedAttemptRecord(a)
	records = append(records, SupportRecord{Kind: 9, RecordID: a.AttemptID, Body: abody})
	_, material, result := generatedResultFixture(t, 2)
	result.Core.DomainID, result.Core.OperationID, result.Core.PlanGraphID, result.Core.MaterialID = a.DomainID, a.OperationID, graph.UsePlan.PlanGraphID, graph.Header.MaterialID
	result.Core.UsePlanDigest, _ = GeneratorUsePlanDigest(graph.UsePlan)
	result.Core.AttemptID, result.Core.TransmissionID, result.Core.ResultID = a.AttemptID, a.TransmissionID, a.ResultID
	result.Core.ExecutorID, result.Core.DescriptorID, result.Core.ConfigContractID, result.Core.ResultContractID, result.Core.RequestDigest = a.ExecutorID, a.DescriptorID, a.ConfigContractID, a.ResultContractID, a.RequestDigest
	result.SafeFacts.ResourceContractID, result.SafeFacts.IntentDigest, result.SafeFacts.RequestDigest = original.ResourceContractID, original.IntentDigest, a.RequestDigest
	result.Core.SafeFactsDigest, _ = GeneratorSafeFactsDigest(result.SafeFacts)
	material.Core.DomainID, material.Core.OperationID, material.Core.OperationMaterialID, material.Core.UsePlanDigest = a.DomainID, a.OperationID, graph.Header.MaterialID, result.Core.UsePlanDigest
	materialBody, _ := EncodeOperationMaterialRecord(material)
	records = append(records, SupportRecord{Kind: 1, RecordID: graph.Header.MaterialID, Body: materialBody})
	result.Transfer.Core.DomainID, result.Transfer.Core.OperationID, result.Transfer.Core.OperationMaterialID, result.Transfer.Core.UsePlanDigest = a.DomainID, a.OperationID, graph.Header.MaterialID, result.Core.UsePlanDigest
	result.Transfer.Core.AttemptID, result.Transfer.Core.ResultID = a.AttemptID, a.ResultID
	result.Transfer.Core.ResultCoreDigest, _ = GeneratedResultCoreDigest(result.Core)
	result.Payload.DataKeyID, result.Payload.CommitmentKeyID, _ = GeneratorResultKeyIDs(a.ResultID)
	resultBody, err := EncodeGeneratedResultRecord(result)
	if err != nil {
		t.Fatal("actual original packet fixture", err)
	}
	records = append(records, SupportRecord{Kind: 4, RecordID: a.ResultID, Body: resultBody})
	// Replace the final history digest with the exact stored original packet.
	history[1].ResultDigest = Hash(resultBody)
	bodies[1], _ = EncodeGeneratorHistory(history[1])
	var kept []SupportRecord
	for _, row := range records {
		if row.Kind != GeneratorVectorSupportKind {
			kept = append(kept, row)
			continue
		}
		c, _ := InspectGeneratorVectorCarrier(row.Body)
		if c.VectorKind != GeneratorVectorHistory {
			kept = append(kept, row)
		}
	}
	a.History, records = selectedAncestryVector(t, kept, a.DomainID, 9, a.AttemptID, GeneratorVectorHistory, bodies)
	abody, _ = EncodeGeneratedAttemptRecord(a)
	for i := range records {
		if records[i].Kind == 9 {
			records[i].Body = abody
		}
	}
	h := GeneratedHazardRecord{Schema: GeneratedHazardRecordSchema, DomainID: a.DomainID, HazardID: original.HazardID, OriginalOperationID: a.OperationID, OriginalAttemptID: a.AttemptID, OwnerID: a.OwnerID, ResourceID: a.ResourceID, DescriptorID: a.DescriptorID, ConfigContractID: a.ConfigContractID, ExecutorID: a.ExecutorID, CredentialRouteID: a.CredentialRouteID, ResourceContractID: a.ResourceContractID, ResultContractID: a.ResultContractID, Exposure: GeneratedExposureLateEffect, CompletionClass: a.CompletionClass, Fenced: 1, Eligibility: GeneratedExposureLateEffect, CapacityReservation: generatedRecordDescriptor(75), Target: EmptyGeneratorVector(GeneratorVectorTargets), Support: EmptyGeneratorVector(GeneratorVectorSupport), Consumers: EmptyGeneratorVector(GeneratorVectorConsumers), OriginalResults: EmptyGeneratorRecordSet(GeneratorHazardResults)}
	h.OriginalResults, _ = GeneratorRecordSetDescriptor(GeneratorHazardResults, a.DomainID, []SupportRecord{{Kind: 4, RecordID: a.ResultID, Body: resultBody}})
	targetBody, _ := EncodeGeneratorTarget(GeneratorTarget{
		Schema:              GeneratorTargetSchema,
		Name:                lineage.Name,
		IncarnationID:       lineage.EntryIncarnationID,
		Epoch:               lineage.Epoch,
		ResourceID:          a.ResourceID,
		ConfigContractID:    a.ConfigContractID,
		OriginalOperationID: a.OperationID,
		OriginalAttemptID:   a.AttemptID,
		ResultContractID:    a.ResultContractID,
		CompletionClass:     a.CompletionClass,
		ResourceContractID:  original.ResourceContractID,
		ResourceDigest:      generatorResourceFixtureDigest(t, result.SafeFacts),
		LifecycleMode:       GeneratorLifecycleManaged,
	})
	h.Target, records = selectedAncestryVector(t, records, h.DomainID, 11, h.HazardID, GeneratorVectorTargets, [][]byte{targetBody})
	h.History, records = selectedAncestryVector(t, records, h.DomainID, 11, h.HazardID, GeneratorVectorHistory, bodies)
	hBody, err := EncodeGeneratedHazardRecord(h)
	if err != nil {
		t.Fatal("actual source fixture", err)
	}
	row := SupportRecord{Kind: 11, RecordID: h.HazardID, Body: hBody}
	records = append(records, row)
	source, err := InspectGeneratedDeleteSource(row)
	if err != nil {
		t.Fatal(err)
	}
	return records, source, snapshot
}

func generatedTransitionIntentFixture(t *testing.T, cross bool) (*GeneratedSupportTransition, GeneratorSliceLocation, []byte) {
	t.Helper()
	canonical := generatorIntentFixture(t, generatedRecordID(6), generatedRecordID(9), GeneratorLifecycleManaged, []byte("{}"))
	blob := bytes.Repeat([]byte{'x'}, GeneratedFragmentMaxPayload+len(canonical))
	offset := uint64(7)
	if cross {
		offset = GeneratedFragmentMaxPayload - 16
	}
	copy(blob[offset:], canonical)
	intent := blob[offset : offset+uint64(len(canonical))]
	id, err := GeneratorIntentDigest(intent)
	if err != nil {
		t.Fatal(err)
	}
	location := GeneratorSliceLocation{Schema: 1, ContentKind: GeneratorContentIntent, ContentID: id, BlobID: generatedRecordID(60), Offset: offset, Length: uint32(len(canonical)), Digest: Hash(intent)}
	row, err := EncodeGeneratorSliceLocation(location)
	if err != nil {
		t.Fatal(err)
	}
	desc, err := GeneratorVectorDescriptor(GeneratorVectorSlices, [][]byte{row})
	if err != nil {
		t.Fatal(err)
	}
	v := &GeneratedSupportTransition{DomainID: generatedRecordID(1), BeforeSnapshot: generatedRecordID(61)}
	c := GeneratorVectorCarrier{Schema: 1, DomainID: v.DomainID, OwnerKind: GeneratorSnapshotOwner, OwnerID: v.BeforeSnapshot, VectorKind: GeneratorVectorSlices, Vector: desc, Row: row}
	body, err := EncodeGeneratorVectorCarrier(c)
	if err != nil {
		t.Fatal(err)
	}
	carrierID, err := GeneratorVectorCarrierID(c)
	if err != nil {
		t.Fatal(err)
	}
	v.Records = append(v.Records, SupportRecord{Kind: GeneratorVectorSupportKind, RecordID: carrierID, Body: body})
	for i := 0; i < 2; i++ {
		start := i * GeneratedFragmentMaxPayload
		stop := min(len(blob), start+GeneratedFragmentMaxPayload)
		f := GeneratedFragment{Schema: 1, BlobID: location.BlobID, Index: uint16(i), Count: 2, TotalLength: uint64(len(blob)), WholeDigest: Hash(blob), Offset: uint32(start), Payload: blob[start:stop]}
		body, err := EncodeGeneratedFragment(f)
		if err != nil {
			t.Fatal(err)
		}
		id, err := GeneratorFragmentID(f.BlobID, f.Index)
		if err != nil {
			t.Fatal(err)
		}
		v.Records = append(v.Records, SupportRecord{Kind: 3, RecordID: id, Body: body})
	}
	return v, location, intent
}

// full_only: false
func TestNormalSupportIntentChecksCompleteBlobBeforeBorrow(t *testing.T) {
	for _, cross := range []bool{false, true} {
		v, location, want := generatedTransitionIntentFixture(t, cross)
		got, err := InspectGeneratedImmutableSlice(v.DomainID, v.BeforeSnapshot, v.Records, location, GeneratorIntentMaxLength)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("exact slice join", cross, err)
		}
		if !cross {
			f, err := InspectGeneratedFragment(v.Records[1].Body)
			if err != nil || &got[0] != &f.Payload[location.Offset] {
				t.Fatal("contiguous slice was copied", err)
			}
		}
		for _, fault := range []string{"missing", "duplicate", "tampered-last", "whole-digest", "carrier-owner", "carrier-duplicate", "ordinal"} {
			t.Run(fault, func(t *testing.T) {
				bad := *v
				bad.Records = slices.Clone(v.Records)
				switch fault {
				case "missing":
					bad.Records = bad.Records[:2]
				case "duplicate":
					bad.Records = append(bad.Records, bad.Records[1])
				case "tampered-last":
					bad.Records[2].Body = bytes.Clone(bad.Records[2].Body)
					bad.Records[2].Body[len(bad.Records[2].Body)-1] ^= 1
				case "whole-digest":
					bad.Records[2].Body = bytes.Clone(bad.Records[2].Body)
					bad.Records[2].Body[46] ^= 1
				case "carrier-owner":
					c, err := InspectGeneratorVectorCarrier(bad.Records[0].Body)
					if err != nil {
						t.Fatal(err)
					}
					c.OwnerID = generatedRecordID(62)
					bad.Records[0].Body, err = EncodeGeneratorVectorCarrier(c)
					if err != nil {
						t.Fatal(err)
					}
				case "carrier-duplicate":
					bad.Records = append(bad.Records, bad.Records[0])
				case "ordinal":
					bad.Records[2].Body = bytes.Clone(bad.Records[2].Body)
					bad.Records[2].Body[35] = 0
				}
				if _, err := InspectGeneratedImmutableSlice(bad.DomainID, bad.BeforeSnapshot, bad.Records, location, GeneratorIntentMaxLength); err == nil {
					t.Fatal("incomplete or changed blob accepted", cross)
				}
			})
		}
	}
}

// full_only: false
func TestNormalSupportKeepsExactOriginalOperationVector(t *testing.T) {
	entry, _, _ := generatedEntryEvidenceFixture(t, 0)
	var bindings [][]byte
	for i := uint8(0); i < 2; i++ {
		row, err := EncodeGeneratorSupportBinding(GeneratorSupportBinding{Schema: GeneratorSupportBindingSchema, Role: 1, ContractID: generatedRecordID(70 + i), ImplementationID: generatedRecordID(72 + i), PublicBindingDigest: generatedRecordID(74 + i)})
		if err != nil {
			t.Fatal(err)
		}
		bindings = append(bindings, row)
	}
	descriptor, err := GeneratorVectorDescriptor(GeneratorVectorSupport, bindings)
	if err != nil {
		t.Fatal(err)
	}
	entry.Generated.RequiredSupport = descriptor
	v := &GeneratedSupportTransition{DomainID: generatedRecordID(1)}
	for i, row := range bindings {
		carrier := GeneratorVectorCarrier{Schema: 1, DomainID: v.DomainID, OwnerKind: 2, OwnerID: entry.Generated.OriginOperationID, VectorKind: GeneratorVectorSupport, Vector: descriptor, Ordinal: uint32(i), Row: row}
		body, err := EncodeGeneratorVectorCarrier(carrier)
		if err != nil {
			t.Fatal(err)
		}
		id, err := GeneratorVectorCarrierID(carrier)
		if err != nil {
			t.Fatal(err)
		}
		v.Records = append(v.Records, SupportRecord{Kind: GeneratorVectorSupportKind, RecordID: id, Body: body})
	}
	if err := v.currentSupport(entry.Generated); err != nil {
		t.Fatal("original support vector", err)
	}
	for _, fault := range []string{"missing", "duplicate", "owner", "id", "ordinal", "vector"} {
		t.Run(fault, func(t *testing.T) {
			bad := *v
			bad.Records = slices.Clone(v.Records)
			switch fault {
			case "missing":
				bad.Records = bad.Records[:1]
			case "duplicate":
				bad.Records = append(bad.Records, bad.Records[0])
			case "id":
				bad.Records[0].RecordID = generatedRecordID(76)
			default:
				carrier, err := InspectGeneratorVectorCarrier(bad.Records[0].Body)
				if err != nil {
					t.Fatal(err)
				}
				switch fault {
				case "owner":
					carrier.OwnerID = generatedRecordID(77)
				case "ordinal":
					carrier.Ordinal = 1
				case "vector":
					carrier.Vector.Digest = generatedRecordID(78)
				}
				bad.Records[0].Body, err = EncodeGeneratorVectorCarrier(carrier)
				if err != nil {
					t.Fatal(err)
				}
				bad.Records[0].RecordID, err = GeneratorVectorCarrierID(carrier)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := bad.currentSupport(entry.Generated); err == nil {
				t.Fatal("changed original vector admitted")
			}
		})
	}
}

// full_only: false
func TestNormalSupportNewRetirementKeepsDistinctOriginalAndSelectedSupport(t *testing.T) {
	entry, evidence, intent := generatedEntryEvidenceFixture(t, 0)
	creator, err := InspectGeneratedResultCore(evidence.ResultCore)
	if err != nil {
		t.Fatal(err)
	}
	selected := generatorImplementationFixture()

	// Derive expected support from the wire fields and standard SHA-256.
	// A one-row vector is count4 + blob32(row); its commitment also frames
	// that complete vector length before its count and row bytes.
	support := func(contract, executor ID, route []byte) (GeneratorSupportBinding, []byte, GeneratorDescriptor) {
		t.Helper()
		preimage := append([]byte("ENKV/CREDENTIAL-ROUTE/v1\x00"), binary.BigEndian.AppendUint32(nil, uint32(len(route)))...)
		preimage = append(preimage, route...)
		routeID := ID(sha256.Sum256(preimage))
		binding := GeneratorSupportBinding{Schema: GeneratorSupportBindingSchema, Role: 7,
			ContractID: contract, ImplementationID: executor, PublicBindingDigest: routeID, Binding: route}
		row := binary.BigEndian.AppendUint16(nil, GeneratorSupportBindingSchema)
		row = append(row, 7)
		for _, id := range []ID{contract, executor, routeID} {
			row = append(row, id[:]...)
		}
		row = binary.BigEndian.AppendUint32(row, uint32(len(route)))
		row = append(row, route...)
		length := uint32(8 + len(row))
		preimage = []byte("ENKV/GENERATOR/v1/support-bindings\x00")
		preimage = binary.BigEndian.AppendUint32(preimage, length)
		preimage = binary.BigEndian.AppendUint32(preimage, 1)
		preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(row)))
		preimage = append(preimage, row...)
		return binding, row, GeneratorDescriptor{Count: 1, Length: uint64(length), Digest: ID(sha256.Sum256(preimage))}
	}
	originalRoute := bytes.Clone(selected.CredentialRoute)
	originalContract := generatedRecordID(81)
	copy(originalRoute[2:34], originalContract[:])
	_, originalRow, originalSupport := support(originalContract, creator.ExecutorID, originalRoute)
	selectedBinding, selectedRow, selectedSupport := support(generatedRecordID(80), selected.ExecutorID, selected.CredentialRoute)
	if selectedBinding.PublicBindingDigest != selected.CredentialRouteID || selectedSupport == originalSupport || selected.DescriptorID == creator.DescriptorID {
		t.Fatal("fixture must have distinct creator and selected support")
	}
	entry.Generated.RequiredSupport = originalSupport
	entryBytes, err := EncodeValueEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	domain, snapshot, root := creator.DomainID, generatedRecordID(61), generatedRecordID(62)
	v := &GeneratedSupportTransition{Schema: 1, DomainID: domain, BeforeSnapshot: snapshot,
		BeforeSliceSnapshot: snapshot, BeforeRootDigest: root}
	actual, records := selectedAncestryVector(t, nil, domain, GeneratedParentSupportKind, entry.Generated.OriginOperationID, GeneratorVectorSupport, [][]byte{originalRow})
	if actual != originalSupport {
		t.Fatal("independent original support descriptor differs", actual, originalSupport)
	}
	v.Records = records
	originalCarrier := v.Records[0]
	evidenceBody, err := EncodeGeneratedCreateEvidence(evidence)
	if err != nil {
		t.Fatal(err)
	}
	v.Records = append(v.Records, SupportRecord{Kind: GeneratedCreateEvidenceSupportKind, RecordID: entry.Generated.CreateResultID, Body: evidenceBody})
	location := GeneratorSliceLocation{Schema: 1, ContentKind: GeneratorContentIntent, ContentID: entry.Generated.IntentDigest,
		BlobID: generatedRecordID(63), Length: uint32(len(intent)), Digest: Hash(intent)}
	locationBody, err := EncodeGeneratorSliceLocation(location)
	if err != nil {
		t.Fatal(err)
	}
	_, v.Records = selectedAncestryVector(t, v.Records, domain, GeneratorSnapshotOwner, snapshot, GeneratorVectorSlices, [][]byte{locationBody})
	slices.SortFunc(v.Records, func(a, b SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	current := GeneratedSupportCurrent{EntryBytes: entryBytes, Intent: location,
		Target: GeneratorTarget{Schema: GeneratorTargetSchema, Name: entry.Name, IncarnationID: entry.Incarnation, Epoch: entry.Generated.Epoch,
			ResourceID: entry.Generated.ResourceIncarnationID, ConfigContractID: entry.Generated.ConfigContractID,
			ResourceContractID: entry.Generated.ResourceContractID, ResourceDigest: entry.Generated.ResourceDigest,
			OriginalOperationID: entry.Generated.OriginOperationID, OriginalAttemptID: entry.Generated.OriginAttemptID,
			ResultContractID: creator.ResultContractID, LifecycleMode: GeneratorLifecycleManaged, CompletionClass: entry.Generated.CompletionClass}}
	for i, row := range v.Records {
		fact, err := InspectSupportRecordDigest(domain, row)
		if err != nil {
			t.Fatal(err)
		}
		v.RecordFacts = append(v.RecordFacts, fact)
		switch row.Kind {
		case GeneratedCreateEvidenceSupportKind:
			current.EvidenceRecord = uint32(i)
		case GeneratorVectorSupportKind:
			carrier, err := InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			if carrier.VectorKind == GeneratorVectorSlices {
				current.CarrierRecord = uint32(i)
			}
		}
	}
	current, err = ProveGeneratedSupportCurrent(domain, snapshot, root, current, v.Records[current.EvidenceRecord], v.Records[current.CarrierRecord], intent)
	if err != nil {
		t.Fatal("selected original evidence", err)
	}
	v.CurrentGenerated = []GeneratedSupportCurrent{current}
	v.BeforeSupport, err = RequiredSupportDescriptorFromDigests(domain, v.RecordFacts)
	if err != nil {
		t.Fatal(err)
	}
	v.BeforeAccess = selectionAcceptanceFixture(t).CurrentAccess.Core
	v.BeforeAccess.DomainID = domain
	v.BeforeAccess.NormalSigning.Binding.Domain = domain
	v.BeforeAccess.RecipientRefsDescriptor, err = RecipientRefsDescriptor(RecipientRefsProjection{DomainID: domain,
		Refs: []Ref{{Kind: RecipientKind, Format: CanonicalSchema, Domain: domain,
			Object: generatedRecordID(66), Digest: generatedRecordID(67), Length: recipientPageMinLength}}})
	if err != nil {
		t.Fatal(err)
	}
	v.BeforeAccess.AccessRecordsDescriptor, err = AccessRecordsDescriptor(domain, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AccessRoot(v.BeforeAccess); err != nil {
		t.Fatal("selected access context", err)
	}
	facts, err := InspectGeneratorSafeFacts(evidence.SafeFacts)
	if err != nil {
		t.Fatal(err)
	}
	native, err := EncodeNativeGeneratorSafeFacts(facts.GeneratorSafeFacts)
	if err != nil {
		t.Fatal(err)
	}
	request := protocol.RetirementCompatibilityRequest{Schema: 1, DeadlineUnixMillis: 4102444800000,
		CompletionClass: entry.Generated.CompletionClass, Intent: intent, OriginalFacts: native}
	request.InputDigest, err = protocol.RetirementCompatibilityInputDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	requestBody, err := protocol.EncodeRetirementCompatibilityRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := protocol.EncodeValidationResponse(protocol.ValidationResponse{Schema: 1, InputDigest: request.InputDigest, Accepted: true})
	if err != nil {
		t.Fatal(err)
	}
	v.Handoffs = []GeneratedSupportHandoff{{Implementation: selected, CompatibilityRequest: requestBody,
		CompatibilityResponse: responseBody, Support: []GeneratorSupportBinding{selectedBinding}}}
	if err := v.IntentError(nil); err != nil {
		t.Fatal("valid new retirement input", err)
	}
	plan := IdentityPlan{Transition: generatedRecordID(64), Snapshot: generatedRecordID(65)}
	after, err := v.SupportAfter(plan, nil)
	if err != nil {
		t.Fatal("new retirement with selected credential support", err)
	}
	var duties, originalCarriers, selectedCarriers int
	for _, row := range after.Records {
		switch row.Kind {
		case GeneratedDutySupportKind:
			duty, err := InspectGeneratedDutyRecord(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			duties++
			if duty.Kind != GeneratedDutyRetirement || duty.OriginalOperationID != entry.Generated.OriginOperationID ||
				duty.OriginalAttemptID != entry.Generated.OriginAttemptID || duty.DescriptorID != selected.DescriptorID ||
				duty.ExecutorID != selected.ExecutorID || duty.CredentialRouteID != selected.CredentialRouteID || duty.Support != selectedSupport {
				t.Fatal("new retirement did not freeze exact selected support", duty)
			}
		case GeneratorVectorSupportKind:
			carrier, err := InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			if carrier.VectorKind != GeneratorVectorSupport {
				continue
			}
			if carrier.OwnerKind != GeneratedParentSupportKind || carrier.OwnerID != entry.Generated.OriginOperationID || carrier.Ordinal != 0 {
				t.Fatal("support carrier lost original operation ownership", carrier)
			}
			switch carrier.Vector {
			case originalSupport:
				originalCarriers++
				if row.RecordID != originalCarrier.RecordID || !bytes.Equal(row.Body, originalCarrier.Body) {
					t.Fatal("new retirement changed original support")
				}
			case selectedSupport:
				selectedCarriers++
				if !bytes.Equal(carrier.Row, selectedRow) {
					t.Fatal("selected support binding changed")
				}
			default:
				t.Fatal("unexpected retirement support descriptor")
			}
		}
	}
	if duties != 1 || originalCarriers != 1 || selectedCarriers != 1 {
		t.Fatal("new retirement lost distinct original and selected support", duties, originalCarriers, selectedCarriers)
	}

	// Derive carrier bodies and IDs directly from their wire fields. Carrier
	// identity commits to the vector and ordinal, but not to the row body.
	expectedCarrier := func(ownerKind uint8, owner ID, kind GeneratorVectorKind, vector GeneratorDescriptor, row []byte) SupportRecord {
		descriptor := append([]byte(nil), vector.Digest[:]...)
		descriptor = binary.BigEndian.AppendUint64(descriptor, vector.Length)
		descriptor = binary.BigEndian.AppendUint32(descriptor, vector.Count)
		identity := binary.BigEndian.AppendUint32([]byte("ENKV/GENERATOR/v1/support-vector-row\x00"), 114)
		identity = append(identity, domain[:]...)
		identity = append(identity, ownerKind)
		identity = append(identity, owner[:]...)
		identity = append(identity, byte(kind))
		identity = append(identity, descriptor...)
		identity = binary.BigEndian.AppendUint32(identity, 0)
		body := binary.BigEndian.AppendUint16(nil, 1)
		body = append(body, domain[:]...)
		body = append(body, ownerKind)
		body = append(body, owner[:]...)
		body = append(body, byte(kind))
		body = binary.BigEndian.AppendUint32(body, 0)
		body = append(body, descriptor...)
		body = binary.BigEndian.AppendUint32(body, uint32(len(row)))
		body = append(body, row...)
		return SupportRecord{Kind: GeneratorVectorSupportKind, RecordID: ID(sha256.Sum256(identity)), Body: body}
	}
	selectedCarrier := expectedCarrier(GeneratedParentSupportKind, entry.Generated.OriginOperationID, GeneratorVectorSupport, selectedSupport, selectedRow)
	for _, test := range []struct {
		name                       string
		shared, retained, conflict bool
	}{
		{name: "shared selected support", shared: true},
		{name: "retained selected support", retained: true},
		{name: "shared retained selected support", shared: true, retained: true},
		{name: "conflicting retained selected support", retained: true, conflict: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			witness, err := v.CopyMetadata()
			if err != nil {
				t.Fatal(err)
			}
			if test.shared {
				mustID := func(id ID, err error) ID {
					t.Helper()
					if err != nil {
						t.Fatal(err)
					}
					return id
				}
				second := entry
				second.Name, second.Incarnation = "generated-second", generatedRecordID(82)
				lineage := mustID(GeneratorLineageID(domain, second.Generated.OriginOperationID, second.Name, second.Incarnation, second.Generated.Epoch, second.Generated.IntentDigest))
				second.Generated.OriginAttemptID = mustID(GeneratorAttemptID(lineage, GeneratorBranchInitial))
				second.Generated.ResourceIncarnationID = mustID(GeneratorResourceID(domain, second.Generated.OriginOperationID, second.Generated.OriginAttemptID))
				secondCore := creator
				secondCore.AttemptID = second.Generated.OriginAttemptID
				secondCore.TransmissionID = mustID(GeneratorTransmissionID(secondCore.AttemptID, GeneratorActionCreate))
				secondCore.ResultID = mustID(GeneratorResultID(domain, secondCore.OperationID, secondCore.AttemptID, secondCore.TransmissionID, GeneratorActionCreate))
				secondEvidence := evidence
				secondEvidence.OriginalResultID = secondCore.ResultID
				secondEvidence.ResultCore, err = EncodeGeneratedResultCore(secondCore)
				if err != nil {
					t.Fatal(err)
				}
				second.Generated.CreateResultID = secondCore.ResultID
				second.Generated.CreateEvidence, err = GeneratedCreateEvidenceDescriptor(secondEvidence)
				if err != nil {
					t.Fatal(err)
				}
				binding := mustID(GeneratedBindingDigest(second.Generated))
				slot := mustID(GeneratorValueSlotID(domain, secondCore.OperationID, secondCore.AttemptID))
				identity, err := DeriveGeneratedValueIdentity(slot, generatedRecordID(31), secondCore.ResultID, binding)
				if err != nil {
					t.Fatal(err)
				}
				second.ValueState, second.OriginSnapshot, second.OriginTransition = identity.ValueStateID, identity.OriginSnapshotID, identity.OriginTransitionID
				second.Generated.GenerationID = identity.ValueStateID
				payload, err := DecodeCanonicalPayload(second.ValueBytes)
				if err != nil {
					t.Fatal(err)
				}
				payload.DataKeyID, payload.CommitmentKeyID = identity.DataKeyID, identity.CommitmentKeyID
				second.ValueBytes, err = EncodeCanonicalPayload(payload)
				if err != nil {
					t.Fatal(err)
				}
				secondBytes, err := EncodeValueEntry(second)
				if err != nil {
					t.Fatal(err)
				}
				secondEvidenceBody, err := EncodeGeneratedCreateEvidence(secondEvidence)
				if err != nil {
					t.Fatal(err)
				}
				witness.Records = append(witness.Records, SupportRecord{Kind: GeneratedCreateEvidenceSupportKind, RecordID: second.Generated.CreateResultID, Body: secondEvidenceBody})
				secondCurrent := current
				secondCurrent.Slot, secondCurrent.EntryBytes = 1, secondBytes
				secondCurrent.Target.Name, secondCurrent.Target.IncarnationID = second.Name, second.Incarnation
				secondCurrent.Target.ResourceID, secondCurrent.Target.OriginalAttemptID = second.Generated.ResourceIncarnationID, second.Generated.OriginAttemptID
				witness.CurrentGenerated = append(witness.CurrentGenerated, secondCurrent)
				secondHandoff := witness.Handoffs[0]
				secondHandoff.Current = 1
				witness.Handoffs = append(witness.Handoffs, secondHandoff)
			}
			if test.retained {
				retained := selectedCarrier
				if test.conflict {
					conflictingBinding := selectedBinding
					conflictingBinding.ImplementationID = generatedRecordID(83)
					conflictingRow, err := EncodeGeneratorSupportBinding(conflictingBinding)
					if err != nil {
						t.Fatal(err)
					}
					retained = expectedCarrier(GeneratedParentSupportKind, entry.Generated.OriginOperationID, GeneratorVectorSupport, selectedSupport, conflictingRow)
					if retained.RecordID != selectedCarrier.RecordID || bytes.Equal(retained.Body, selectedCarrier.Body) {
						t.Fatal("conflict must retain the same ID and change the complete body")
					}
				}
				witness.Records = append(witness.Records, retained)
			}
			slices.SortFunc(witness.Records, func(a, b SupportRecord) int {
				if a.Kind != b.Kind {
					return int(a.Kind) - int(b.Kind)
				}
				return bytes.Compare(a.RecordID[:], b.RecordID[:])
			})
			witness.RecordFacts = nil
			for i, row := range witness.Records {
				fact, err := InspectSupportRecordDigest(domain, row)
				if err != nil {
					t.Fatal("complete predecessor record", err)
				}
				witness.RecordFacts = append(witness.RecordFacts, fact)
				for j := range witness.CurrentGenerated {
					selected := &witness.CurrentGenerated[j]
					metadata, err := InspectValueEntry(selected.EntryBytes)
					if err != nil {
						t.Fatal(err)
					}
					if row.Kind == GeneratedCreateEvidenceSupportKind && row.RecordID == metadata.Generated.CreateResultID {
						selected.EvidenceRecord = uint32(i)
					}
					if row.Kind == GeneratorVectorSupportKind {
						carrier, err := InspectGeneratorVectorCarrier(row.Body)
						if err != nil {
							t.Fatal(err)
						}
						if carrier.VectorKind == GeneratorVectorSlices {
							selected.CarrierRecord = uint32(i)
						}
					}
				}
			}
			for i, row := range witness.CurrentGenerated {
				witness.CurrentGenerated[i], err = ProveGeneratedSupportCurrent(domain, snapshot, root, row, witness.Records[row.EvidenceRecord], witness.Records[row.CarrierRecord], intent)
				if err != nil {
					t.Fatal("exact selected current proof", i, err)
				}
			}
			witness.BeforeSupport, err = RequiredSupportDescriptorFromDigests(domain, witness.RecordFacts)
			if err != nil {
				t.Fatal(err)
			}
			if err := witness.IntentError(nil); err != nil {
				t.Fatal("shared or retained carrier must reach support construction", err)
			}
			before, err := witness.CopyMetadata()
			if err != nil {
				t.Fatal(err)
			}
			for i := range before.Records {
				before.Records[i].Body = bytes.Clone(before.Records[i].Body)
			}
			got, supportErr := witness.SupportAfter(plan, nil)
			if !reflect.DeepEqual(witness, before) {
				t.Fatal("support construction changed its caller's complete witness")
			}
			if test.conflict {
				if supportErr != ErrRecord || len(got.Records) != 0 || len(got.Facts) != 0 {
					t.Fatal("conflicting same-ID support must refuse without a partial result", supportErr)
				}
				return
			}
			if supportErr != nil {
				t.Fatal("identical operation-owned support must be reused", supportErr)
			}

			// The expected set is the complete predecessor, one selected support
			// carrier, and one complete Duty/target pair for each distinct entry.
			want := slices.Clone(before.Records)
			for i, row := range want {
				if row.Kind != GeneratorVectorSupportKind {
					continue
				}
				carrier, err := InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				if carrier.VectorKind == GeneratorVectorSlices {
					want[i] = expectedCarrier(GeneratorSnapshotOwner, plan.Snapshot, GeneratorVectorSlices, carrier.Vector, carrier.Row)
				}
			}
			if !test.retained {
				want = append(want, selectedCarrier)
			}
			intentDescriptor, err := CryptoIntentDescriptor(domain, nil)
			if err != nil {
				t.Fatal(err)
			}
			capacity, err := GeneratedNormalCapacityDescriptor(GeneratedNormalCapacity{Schema: 1, BeforeRootDigest: root, TransitionID: plan.Transition, Intent: intentDescriptor, Groups: witness.Groups})
			if err != nil {
				t.Fatal(err)
			}
			resultContract, err := GeneratedResultContractID(selected, GeneratorActionDelete, entry.Generated.CompletionClass, 0, GeneratorSafeFactsEnvelopeLength, InputEncodingRaw)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range before.CurrentGenerated {
				m, err := InspectValueEntry(row.EntryBytes)
				if err != nil {
					t.Fatal(err)
				}
				preimage := binary.BigEndian.AppendUint32([]byte("ENKV/GENERATOR/v1/duty\x00"), 97)
				preimage = append(preimage, domain[:]...)
				preimage = append(preimage, m.Generated.OriginOperationID[:]...)
				preimage = append(preimage, m.Generated.OriginAttemptID[:]...)
				preimage = append(preimage, GeneratedDutyRetirement)
				dutyID := ID(sha256.Sum256(preimage))
				targetBody, err := EncodeGeneratorTarget(row.Target)
				if err != nil {
					t.Fatal(err)
				}
				preimage = []byte("ENKV/GENERATOR/v1/targets\x00")
				preimage = binary.BigEndian.AppendUint32(preimage, uint32(8+len(targetBody)))
				preimage = binary.BigEndian.AppendUint32(preimage, 1)
				preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(targetBody)))
				preimage = append(preimage, targetBody...)
				targets := GeneratorDescriptor{Count: 1, Length: uint64(8 + len(targetBody)), Digest: ID(sha256.Sum256(preimage))}
				duty := GeneratedDutyRecord{Schema: GeneratedDutyRecordSchema, LifecycleMode: GeneratorLifecycleManaged,
					DomainID: domain, DutyID: dutyID, OwnerID: dutyID,
					OriginalOperationID: m.Generated.OriginOperationID, OriginalAttemptID: m.Generated.OriginAttemptID,
					ResourceID: m.Generated.ResourceIncarnationID, DescriptorID: selected.DescriptorID,
					ConfigContractID: m.Generated.ConfigContractID, ExecutorID: selected.ExecutorID,
					CredentialRouteID: selected.CredentialRouteID, ResourceContractID: m.Generated.ResourceContractID,
					ResultContractID: resultContract, Kind: GeneratedDutyRetirement, CompletionClass: m.Generated.CompletionClass,
					Step: 1, Status: GeneratedEffectNotStarted, CapacityReservation: capacity, Target: targets,
					Progress: EmptyGeneratorVector(GeneratorVectorProgress), History: EmptyGeneratorVector(GeneratorVectorHistory),
					Support: selectedSupport, Consumers: EmptyGeneratorVector(GeneratorVectorConsumers)}
				dutyBody, err := EncodeGeneratedDutyRecord(duty)
				if err != nil {
					t.Fatal(err)
				}
				want = append(want, SupportRecord{Kind: GeneratedDutySupportKind, RecordID: dutyID, Body: dutyBody},
					expectedCarrier(GeneratedDutySupportKind, dutyID, GeneratorVectorTargets, targets, targetBody))
			}
			slices.SortFunc(want, func(a, b SupportRecord) int {
				if a.Kind != b.Kind {
					return int(a.Kind) - int(b.Kind)
				}
				return bytes.Compare(a.RecordID[:], b.RecordID[:])
			})
			if !reflect.DeepEqual(got.Records, want) || len(got.Facts) != len(want) {
				t.Fatal("complete canonical support set differs", len(got.Records), len(want), len(got.Facts))
			}
			for i, row := range want {
				fact := SupportRecordDigest{kind: row.Kind, recordID: row.RecordID, bodyDigest: ID(sha256.Sum256(row.Body)), bodyLength: uint32(len(row.Body)), domain: domain, inspected: true}
				if got.Facts[i] != fact {
					t.Fatal("support fact lost its exact row or canonical position", i)
				}
			}
		})
	}
}

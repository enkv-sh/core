package core

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedPlanAdmissionRejectsAdditionalOwnedResourceCleanup(t *testing.T) {
	s := generatedEmptyPredecessor(t)
	input := generatedPlanInputFixture(t, s)
	if _, err := s.generatedPlanRequest(t.Context(), input); err != nil {
		t.Fatal("complete result-slot cleanup plan refused", err)
	}
	g := cloneGeneratorPlanBundle(input.graph)
	index := slices.IndexFunc(g.Lineages, func(row contract.GeneratorLineageTemplate) bool {
		return row.Purpose == contract.GeneratorLineageCleanup
	})
	if index < 0 {
		t.Fatal("fixture has no result-slot cleanup")
	}
	extra := g.Lineages[index]
	extra.ResourceIncarnationID = generatedVectorID(240)
	var err error
	extra.LineageID, err = contract.GeneratorObligationLineageID(extra.DomainID, extra.OperationID, extra.ResourceIncarnationID, extra.Purpose)
	if err != nil {
		t.Fatal(err)
	}
	x := &extra.Templates[0]
	x.LineageID, x.ResourceIncarnationID = extra.LineageID, extra.ResourceIncarnationID
	x.TargetKind, x.TargetSourceID = contract.GeneratorTargetOwnedResource, extra.ResourceIncarnationID
	x.ResourceDigest = generatedVectorID(241)
	x.AttemptID, err = contract.GeneratorAttemptID(extra.LineageID, 0)
	if err != nil {
		t.Fatal(err)
	}
	x.PlannedValueSlotID, err = contract.GeneratorValueSlotID(extra.DomainID, extra.OperationID, x.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	x.HazardID, err = contract.GeneratorHazardID(extra.DomainID, x.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	x.TransmissionID, err = contract.GeneratorTransmissionID(x.AttemptID, x.Action)
	if err != nil {
		t.Fatal(err)
	}
	x.ResultID, err = contract.GeneratorResultID(extra.DomainID, extra.OperationID, x.AttemptID, x.TransmissionID, x.Action)
	if err != nil {
		t.Fatal(err)
	}
	x.InboxID, err = contract.GeneratorInboxID(extra.DomainID, extra.OperationID, x.AttemptID, x.ResultID)
	if err != nil {
		t.Fatal(err)
	}
	x.RequestPlanDigest, err = contract.GeneratorRequestPlanDigest(*x)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := contract.EncodeGeneratorLineageTemplate(extra); err != nil {
		t.Fatal("extra cleanup must reach the complete graph boundary", err)
	}
	use := g.ResultUses[slices.IndexFunc(g.ResultUses, func(use contract.GeneratorResultUse) bool {
		return use.AttemptID == g.Lineages[index].Templates[0].AttemptID
	})]
	use.AttemptID, use.ResultID, use.InboxID, use.PlannedValueSlotID = x.AttemptID, x.ResultID, x.InboxID, x.PlannedValueSlotID
	g.Lineages = append(g.Lineages, extra)
	g.Header.TemplateCount++
	slices.SortFunc(g.Lineages, func(a, b contract.GeneratorLineageTemplate) int {
		if a.Name != b.Name {
			return strings.Compare(a.Name, b.Name)
		}
		if a.Purpose != b.Purpose {
			return int(a.Purpose) - int(b.Purpose)
		}
		return bytes.Compare(a.ResourceIncarnationID[:], b.ResourceIncarnationID[:])
	})
	g.ResultUses = append(g.ResultUses, use)
	slices.SortFunc(g.ResultUses, func(a, b contract.GeneratorResultUse) int { return bytes.Compare(a.AttemptID[:], b.AttemptID[:]) })
	g.UsePlan.ResultUses, err = contract.GeneratorResultUsesDescriptor(g.ResultUses)
	if err != nil {
		t.Fatal(err)
	}
	template, err := contract.GeneratorTemplateID(*x)
	if err != nil {
		t.Fatal(err)
	}
	join, err := contract.GeneratorCompleteJoinID(g.Header.RequestCoreDigest)
	if err != nil {
		t.Fatal(err)
	}
	for _, guard := range []uint8{contract.GeneratorGuardQualifiedSuccess, contract.GeneratorGuardTerminalParent} {
		g.Edges = append(g.Edges, contract.GeneratorEdge{Schema: 1, SourceTemplateID: template, DestinationTemplateID: join,
			Guard: guard, ResultSlotID: x.ResultID, RequiredAuthoritySet: x.RequiredAuthoritySet})
	}
	slices.SortFunc(g.Edges, func(a, b contract.GeneratorEdge) int {
		if order := bytes.Compare(a.SourceTemplateID[:], b.SourceTemplateID[:]); order != 0 {
			return order
		}
		return int(a.Guard) - int(b.Guard)
	})
	if graph, err := contract.GeneratorGraphID(g.Header, g.ValueEntryPlans, g.Lineages, g.Edges); err == nil {
		g.UsePlan.PlanGraphID = graph
	} else if err != contract.ErrRecord {
		t.Fatal("extra cleanup graph refused for an unrelated reason", err)
	}
	input.graph = g
	input.requestBindings = generatedFixtureRequestBindings(g, generatedVectorID(61))
	if _, err := s.generatedPlanRequest(t.Context(), input); err == nil {
		t.Fatal("additional owned-resource cleanup entered a create plan")
	}
}

// full_only: false
func TestGeneratedCleanCapacityChargesCompleteEncodedGraph(t *testing.T) {
	profile := defaultGeneratedFixtureProfile()
	old := contract.ValueEntry{Name: strings.Repeat("z", 256), Incarnation: generatedVectorID(201),
		Generated: contract.GeneratedEntryMetadata{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratedEntryMetadataSchema, OriginOperationID: generatedVectorID(202), OriginAttemptID: generatedVectorID(203),
			ResourceIncarnationID: generatedVectorID(204), ResourceDigest: generatedVectorID(206), IntentDigest: generatedVectorID(205), Epoch: 1,
			ConfigContractID: profile.ConfigContractID, ResourceContractID: profile.ResourceContractID, CompletionClass: contract.GeneratedCompletionAcknowledged}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
	mixed, declaration, _ := generatedEffectPlanForGenerationState(t, nil, generatedVectorID(11), []string{strings.Repeat("a", 256)},
		[]byte(`{"name":"generated"}`), profile, 1, nil, map[string]contract.ValueEntry{old.Name: old})
	declarationBody, err := contract.EncodeGeneratorDeclaration(declaration)
	if err != nil {
		t.Fatal(err)
	}
	s, source := generatedOrdinaryCleanupSourceState(t, contract.GeneratedCompletionAcknowledged, false)
	external := generatedOrdinaryCleanupReservationInput(t, s, source, generatedVectorID(206))
	for _, tc := range []struct {
		name  string
		graph contract.GeneratorPlanBundle
		shape generatedCapacityShape
	}{
		{"create cleanup and retirement", mixed, generatedCapacityShape{ValueEntryCount: 1, ValueEntryPageCount: 1, Recipients: 1,
			Secrets: 1, Memberships: 1, SecretMemberships: 1, Generated: 1, Creates: 1, Retirements: 1,
			ValueEntryPlanCount: 1, DeclarationBytes: uint64(len(declarationBody))}},
		{"external cleanup", external.graph, generatedCapacityShape{Recipients: 1, Cleanups: 1, DeclarationBytes: uint64(len(external.declaration))}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := contract.ValidateGeneratorEffectGraph(tc.graph); err != nil {
				t.Fatal("admitted graph relation", err)
			}
			body, err := contract.EncodeGeneratorPlanBundle(tc.graph)
			if err != nil {
				t.Fatal(err)
			}
			// Fixed wire widths are from the documented schema, independent of
			// the production length and capacity helpers. Include every row.
			wantLength, templates := 798, 0
			for _, row := range tc.graph.ValueEntryPlans {
				wantLength += 240 + len(row.Name)
				if row.ValueSource == contract.Generated {
					wantLength++
				}
			}
			for _, row := range tc.graph.Lineages {
				wantLength += 212 + len(row.Name) + int(row.TemplateCount)*686
				templates += int(row.TemplateCount)
			}
			wantLength += 106*len(tc.graph.Edges) + 239*len(tc.graph.ResultUses) + 191*len(tc.graph.SourceUses)
			if len(body) != wantLength || templates != int(tc.graph.Header.TemplateCount) {
				t.Fatalf("complete graph length=%d, want %d; templates=%d, header=%d", len(body), wantLength, templates, tc.graph.Header.TemplateCount)
			}
			groups, err := generatedCleanCapacity(tc.shape)
			if err != nil {
				t.Fatal(err)
			}
			fragments, err := generatedFragmentRows(contract.Hash(body), body)
			if err != nil {
				t.Fatal(err)
			}
			var framed uint64
			for _, row := range fragments {
				framed += uint64(contract.SupportRecordOverhead + len(row.Body))
			}
			carriers := uint64(4*templates + len(tc.graph.ValueEntryPlans))
			framed += carriers * uint64(contract.SupportRecordOverhead+contract.GeneratorCarrierFixedLength+contract.GeneratorSliceLocationLength)
			charged := groups[contract.GeneratorCapacityGraph]
			if charged.MaxCount < uint64(len(fragments))+carriers || charged.MaxFramedBytes < framed || charged.MaxPages < uint32((len(fragments)+1)/2) {
				t.Fatalf("complete encoded graph and carriers exceed charge: bytes=%d rows=%d, charge=%+v", framed, uint64(len(fragments))+carriers, charged)
			}
		})
	}
}

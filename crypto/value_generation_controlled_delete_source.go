package crypto

import (
	"bytes"
	"slices"

	"enkv.sh/core/contract"
)

func generatedSelectedRecord(records []contract.SupportRecord, kind uint8, id contract.ID) contract.SupportRecord {
	for _, row := range records {
		if row.Kind == kind && row.RecordID == id {
			return row
		}
	}
	return contract.SupportRecord{}
}

type controlledGeneratedSliceIndex struct {
	domain    contract.ID
	snapshot  contract.ID
	locations map[contract.GeneratorSliceLocation][]contract.SupportRecord
	fragments map[contract.ID][]contract.SupportRecord
	graphs    []contract.GeneratorSliceLocation
}

type controlledRecordKey struct {
	kind uint8
	id   contract.ID
}

type controlledGraph struct {
	body   []byte
	bundle contract.GeneratorPlanBundle
}

type controlledResult struct {
	record contract.SupportRecord
	value  contract.GeneratedResultRecordView
	digest contract.ID
}

type controlledSourceView struct {
	records    map[controlledRecordKey]contract.SupportRecord
	attempts   map[contract.ID]contract.GeneratedAttemptRecord
	results    map[contract.ID]controlledResult
	vectors    *contract.SelectedGeneratorVectorIndex
	graphs     map[contract.ID]controlledGraph
	operations map[contract.ID]controlledGraph
	consumers  map[contract.ID][]contract.GeneratorConsumer
}

func (a *generatedAdmission) newControlledSourceView(records []contract.SupportRecord) (*controlledSourceView, error) {
	view := &controlledSourceView{records: make(map[controlledRecordKey]contract.SupportRecord, len(records)),
		attempts: make(map[contract.ID]contract.GeneratedAttemptRecord), results: make(map[contract.ID]controlledResult),
		graphs: make(map[contract.ID]controlledGraph), operations: make(map[contract.ID]controlledGraph)}
	for _, row := range records {
		key := controlledRecordKey{row.Kind, row.RecordID}
		if _, duplicate := view.records[key]; duplicate {
			return nil, contract.ErrRecord
		}
		view.records[key] = row
		switch row.Kind {
		case contract.GeneratedAttemptSupportKind:
			attempt, err := contract.InspectGeneratedAttemptRecord(row.Body)
			if err != nil || attempt.AttemptID != row.RecordID {
				return nil, contract.ErrRecord
			}
			view.attempts[row.RecordID] = attempt
		case contract.GeneratedResultSupportKind:
			result, err := contract.InspectGeneratedResultRecord(row.Body)
			if err != nil || result.Core.ResultID != row.RecordID {
				return nil, contract.ErrRecord
			}
			view.results[row.RecordID] = controlledResult{record: row, value: result, digest: contract.Hash(row.Body)}
		}
	}
	var err error
	view.vectors, err = contract.NewSelectedGeneratorVectorIndex(a.request.Context.DomainID, records)
	if err != nil {
		return nil, err
	}
	slicesIndex, err := a.controlledSliceIndex(records)
	if err != nil {
		return nil, err
	}
	for _, location := range slicesIndex.graphs {
		if _, duplicate := view.graphs[location.ContentID]; duplicate {
			return nil, contract.ErrRecord
		}
		body, err := slicesIndex.inspect(location, contract.GeneratorGraphMaxLength-8)
		if err != nil {
			return nil, err
		}
		bundle, err := contract.DecodeGeneratorPlanBundle(body)
		if err != nil || contract.ValidateGeneratorEffectGraph(bundle) != nil || bundle.UsePlan.PlanGraphID != location.ContentID {
			return nil, contract.ErrRecord
		}
		if _, duplicate := view.operations[bundle.Header.OperationID]; duplicate {
			return nil, contract.ErrRecord
		}
		graph := controlledGraph{body: body, bundle: bundle}
		view.graphs[location.ContentID] = graph
		view.operations[bundle.Header.OperationID] = graph
	}
	return view, nil
}

func (view *controlledSourceView) record(kind uint8, id contract.ID) contract.SupportRecord {
	return view.records[controlledRecordKey{kind, id}]
}

func (a *generatedAdmission) controlledGraphFromView(view *controlledSourceView, id contract.ID) (contract.GeneratorPlanBundle, error) {
	graph, found := view.graphs[id]
	if !found || len(graph.body) > contract.GeneratorControlledGraphMaxLength || a.validateControlledGraph(graph.bundle, id) != nil {
		return contract.GeneratorPlanBundle{}, contract.ErrRecord
	}
	return graph.bundle, nil
}

func newControlledGeneratedSliceIndex(domain, snapshot contract.ID, records []contract.SupportRecord) (*controlledGeneratedSliceIndex, error) {
	index := &controlledGeneratedSliceIndex{domain: domain, snapshot: snapshot,
		locations: make(map[contract.GeneratorSliceLocation][]contract.SupportRecord), fragments: make(map[contract.ID][]contract.SupportRecord)}
	for _, row := range records {
		switch row.Kind {
		case contract.GeneratorVectorSupportKind:
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				return nil, err
			}
			if carrier.VectorKind != contract.GeneratorVectorSlices {
				continue
			}
			location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
			if err != nil {
				return nil, err
			}
			index.locations[location] = append(index.locations[location], row)
			if location.ContentKind == contract.GeneratorContentGraph {
				index.graphs = append(index.graphs, location)
			}
		case contract.GeneratedFragmentSupportKind:
			fragment, err := contract.InspectGeneratedFragment(row.Body)
			if err != nil {
				return nil, err
			}
			index.fragments[fragment.BlobID] = append(index.fragments[fragment.BlobID], row)
		}
	}
	return index, nil
}

func (i *controlledGeneratedSliceIndex) inspect(location contract.GeneratorSliceLocation, limit uint32) ([]byte, error) {
	records := make([]contract.SupportRecord, 0, len(i.locations[location])+len(i.fragments[location.BlobID]))
	records = append(records, i.locations[location]...)
	records = append(records, i.fragments[location.BlobID]...)
	return contract.InspectGeneratedImmutableSlice(i.domain, i.snapshot, records, location, limit)
}

func (a *generatedAdmission) controlledSliceIndex(records []contract.SupportRecord) (*controlledGeneratedSliceIndex, error) {
	ref, err := contract.DecodeRef(a.request.Context.PredecessorRootRef[:], contract.CanonicalSchema)
	if err != nil {
		return nil, err
	}
	return newControlledGeneratedSliceIndex(a.request.Context.DomainID, ref.Object, records)
}

func (a *generatedAdmission) controlledSelectedGraph(records []contract.SupportRecord, id contract.ID, claimed []byte) (contract.GeneratorPlanBundle, error) {
	index, err := a.controlledSliceIndex(records)
	if err != nil {
		return contract.GeneratorPlanBundle{}, err
	}
	return a.controlledSelectedGraphFromIndex(index, id, claimed)
}

func (a *generatedAdmission) controlledSelectedGraphFromIndex(index *controlledGeneratedSliceIndex, id contract.ID, claimed []byte) (contract.GeneratorPlanBundle, error) {
	var location contract.GeneratorSliceLocation
	for _, candidate := range index.graphs {
		if candidate.ContentID == id {
			if !location.ContentID.IsZero() {
				return contract.GeneratorPlanBundle{}, contract.ErrRecord
			}
			location = candidate
		}
	}
	body, err := index.inspect(location, contract.GeneratorControlledGraphMaxLength)
	if err != nil || claimed != nil && !bytes.Equal(body, claimed) {
		return contract.GeneratorPlanBundle{}, contract.ErrRecord
	}
	return a.controlledGraph(body, id)
}

func (a *generatedAdmission) controlledGraph(body []byte, id contract.ID) (contract.GeneratorPlanBundle, error) {
	g, err := contract.DecodeGeneratorPlanBundle(body)
	if err != nil || a.validateControlledGraph(g, id) != nil {
		return contract.GeneratorPlanBundle{}, contract.ErrRecord
	}
	return g, nil
}

func (a *generatedAdmission) validateControlledGraph(g contract.GeneratorPlanBundle, id contract.ID) error {
	if contract.ValidateGeneratorEffectGraph(g) != nil || g.Header.DomainID != a.request.Context.DomainID || g.UsePlan.PlanGraphID != id ||
		len(g.Lineages) != 1 || g.Lineages[0].Purpose != contract.GeneratorLineageRetirement && g.Lineages[0].Purpose != contract.GeneratorLineageCleanup || g.Lineages[0].TemplateCount != 1 ||
		g.Header.TemplateCount != 1 || g.Header.LineageCount != 0 || len(g.ResultUses) != 1 || len(g.SourceUses) != 0 || len(g.Edges) != 2 {
		return contract.ErrRecord
	}
	return nil
}

// A result-free deleting attempt still belongs to one exact standalone delete
// operation. Its profile and completion class do not identify that operation:
// bind the selected graph, template, result use, material and consumer edge.
func (a *generatedAdmission) controlledResultFreeDelete(view *controlledSourceView, source contract.GeneratedDeleteSource, attempt contract.GeneratedAttemptRecord) error {
	expectedTarget := a.deleteTarget()
	selected, found := view.operations[attempt.OperationID]
	if expectedTarget == nil || !found {
		return contract.ErrRecord
	}
	graph := selected.bundle
	if a.validateControlledGraph(graph, graph.UsePlan.PlanGraphID) != nil {
		return contract.ErrRecord
	}
	x := graph.Lineages[0].Templates[0]
	tmp := *a
	tmp.graph = graph
	if !generatedUncertainAttemptMatches(attempt, x, graph.Header.DomainID, graph.Header.OperationID) || !tmp.deleteTargetSourceMatches(source, x) {
		return contract.ErrRecord
	}
	material, err := contract.InspectOperationMaterialRecord(view.record(contract.OperationMaterialSupportKind, graph.Header.MaterialID).Body)
	expected := contract.GeneratorResultExpectation{InputEncoding: contract.InputEncodingRaw, Plan: graph.UsePlan, Template: x, Use: graph.ResultUses[0],
		RequestDigest: attempt.RequestDigest, TargetResourceDigest: expectedTarget.ResourceDigest}
	if err != nil || expected.Validate(material) != nil {
		return contract.ErrRecord
	}
	context, err := contract.GeneratorResultUseDigest(expected.Use)
	if err != nil {
		return contract.ErrRecord
	}
	consumers := view.consumers[attempt.ResultID]
	if len(consumers) != 1 || consumers[0].MaterialID != graph.Header.MaterialID ||
		consumers[0].ContextDigest != context || consumers[0].Purpose != contract.GeneratorConsumerAdoptLateOriginalResult {
		return contract.ErrRecord
	}
	return nil
}

// BeforeRecords is used synchronously and never retained. Its complete canonical
// descriptor pins every source, history, Attempt, fact, progress and result join.
func (a *generatedAdmission) controlledSelectedSource(input *contract.GeneratedControlledPredecessor) (contract.GeneratedDeleteSource, [][]byte, error) {
	fail := func() (contract.GeneratedDeleteSource, [][]byte, error) {
		return contract.GeneratedDeleteSource{}, nil, contract.ErrRecord
	}
	expectedTarget := a.deleteTarget()
	if expectedTarget == nil {
		return fail()
	}
	descriptor, err := contract.RequiredSupportDescriptor(a.request.Context.DomainID, input.BeforeRecords)
	if err != nil || descriptor != a.before.RequiredSupport {
		return fail()
	}
	view, err := a.newControlledSourceView(input.BeforeRecords)
	if err != nil {
		return fail()
	}
	source, err := contract.InspectGeneratedDeleteSource(input.Source)
	selected := view.record(input.Source.Kind, input.Source.RecordID)
	if err != nil || !bytes.Equal(selected.Body, input.Source.Body) || source.CompletionClass != contract.GeneratedCompletionConfirmed ||
		source.DomainID != a.request.Context.DomainID || source.ResourceID != expectedTarget.ResourceID || source.ConfigContractID != expectedTarget.ConfigContractID || source.ResourceContractID != expectedTarget.ResourceContractID {
		return fail()
	}
	if source.Record.Kind == contract.GeneratedDutySupportKind && (source.Duty.Kind != contract.GeneratedDutyRetirement && source.Duty.Kind != contract.GeneratedDutyUnselectedCleanup ||
		source.Duty.Step != 1 && source.Duty.Step != 2) || source.Record.Kind == contract.GeneratedHazardSupportKind &&
		(source.Hazard.Fenced != 1 || source.Hazard.Eligibility == 0 || source.Hazard.Eligibility != source.Hazard.Exposure) {
		return fail()
	}
	view.consumers = make(map[contract.ID][]contract.GeneratorConsumer)
	if err := view.vectors.Inspect(source.Record.Kind, source.SourceID, contract.GeneratorVectorConsumers, source.Consumers,
		func(_ uint32, body []byte) error {
			consumer, err := contract.InspectGeneratorConsumer(body)
			if err != nil || consumer.OwnerID != source.SourceID {
				return contract.ErrRecord
			}
			if consumer.SubjectKind == contract.GeneratorConsumerOriginalResult {
				view.consumers[consumer.SubjectID] = append(view.consumers[consumer.SubjectID], consumer)
			}
			return nil
		}); err != nil {
		return fail()
	}
	if err := view.vectors.Inspect(source.Record.Kind, source.SourceID, contract.GeneratorVectorTargets, source.Target,
		func(_ uint32, body []byte) error {
			target, err := contract.InspectGeneratorTarget(body)
			if err != nil || target != *expectedTarget || source.Target.Count != 1 {
				return contract.ErrRecord
			}
			return nil
		}); err != nil || source.Target.Count != 1 {
		return fail()
	}
	if a.purpose.reservation != nil {
		kind := contract.GeneratorPhaseDuties
		if source.Record.Kind == contract.GeneratedHazardSupportKind {
			kind = contract.GeneratorPhaseHazards
		}
		evidence, err := contract.GeneratorRecordSetDescriptor(kind, source.DomainID, []contract.SupportRecord{source.Record})
		if err != nil || a.purpose.reservation.phase == nil || a.purpose.reservation.phase.Evidence != evidence || len(a.graph.Lineages) != 1 ||
			!a.deleteTargetSourceMatches(source, a.graph.Lineages[0].Templates[0]) ||
			source.Record.Kind == contract.GeneratedDutySupportKind && source.Duty.Kind == contract.GeneratedDutyRetirement && a.graph.Lineages[0].Purpose != contract.GeneratorLineageRetirement ||
			(source.Record.Kind == contract.GeneratedHazardSupportKind || source.Duty.Kind == contract.GeneratedDutyUnselectedCleanup) && a.graph.Lineages[0].Purpose != contract.GeneratorLineageCleanup {
			return fail()
		}
	}
	var progress [][]byte
	acks := make(map[contract.ID]contract.GeneratorProgress)
	contradiction := false
	ref, err := contract.DecodeRef(a.request.Context.PredecessorRootRef[:], contract.CanonicalSchema)
	if err != nil {
		return fail()
	}
	createPrefix, err := contract.InspectGeneratedSelectedCreateAncestry(source.DomainID, ref.Object, input.BeforeRecords, source)
	if err != nil {
		return fail()
	}
	// A late ACK may be selected after its historical outcome was sealed. Build
	// the selected ACK set first, then bind each probe to the prefix retained in
	// that probe's own Attempt. Selection order alone grants no predecessor.
	err = view.vectors.Inspect(source.Record.Kind, source.SourceID, contract.GeneratorVectorHistory, source.History,
		func(ordinal uint32, body []byte) error {
			if ordinal < createPrefix {
				return nil
			}
			h, err := contract.InspectGeneratorHistory(body)
			if err != nil {
				return err
			}
			v, found := view.attempts[h.PredecessorAttemptID]
			if !found {
				return contract.ErrRecord
			}
			result := view.results[v.ResultID]
			if len(result.record.Body) == 0 {
				return nil
			}
			r := result.value
			if r.SafeFacts.Disposition == contract.GeneratorDispositionRetirementAcknowledged {
				acks[v.ResultID] = contract.GeneratorProgress{Schema: 1, AttemptID: v.AttemptID, ResultID: v.ResultID,
					Evidence:      contract.GeneratorDescriptor{Digest: result.digest, Length: uint64(len(result.record.Body)), Count: 1},
					RequiredSteps: contract.GeneratorConfirmedRequiredSteps, CompletedSteps: contract.GeneratorProgressAcknowledged, CompletionClass: source.CompletionClass}
			}
			return nil
		})
	if err != nil {
		return fail()
	}
	err = view.vectors.Inspect(source.Record.Kind, source.SourceID, contract.GeneratorVectorHistory, source.History,
		func(ordinal uint32, body []byte) error {
			if ordinal < createPrefix {
				// Independently bound complete create ancestry is not delete progress.
				return nil
			}
			h, err := contract.InspectGeneratorHistory(body)
			v, found := view.attempts[h.PredecessorAttemptID]
			if err != nil || !found || v.DomainID != source.DomainID || v.OwnerID != source.OwnerID || v.ResourceID != source.ResourceID ||
				v.DescriptorID != source.DescriptorID || v.ConfigContractID != source.ConfigContractID || v.ExecutorID != source.ExecutorID || v.CredentialRouteID != source.CredentialRouteID ||
				v.ResourceContractID != source.ResourceContractID || v.CompletionClass != source.CompletionClass || h.OwnerID != source.OwnerID || h.Outcome != v.State {
				return contract.ErrRecord
			}
			result := view.results[v.ResultID]
			recorded := !h.ResultID.IsZero()
			if len(result.record.Body) == 0 && (recorded || !h.ResultDigest.IsZero()) || recorded && len(result.record.Body) != 0 && (h.ResultID != v.ResultID || h.ResultDigest != result.digest) ||
				!recorded && !h.ResultDigest.IsZero() {
				return contract.ErrRecord
			}
			deleteID, err := contract.GeneratorResultID(v.DomainID, v.OperationID, v.AttemptID, v.TransmissionID, contract.GeneratorActionDelete)
			if err != nil {
				return err
			}
			if v.ResultID != deleteID {
				return contract.ErrRecord
			}
			want := h
			want.NextAttemptID, want.Edge = contract.ID{}, 0
			if err := view.vectors.Inspect(contract.GeneratedAttemptSupportKind, v.AttemptID, contract.GeneratorVectorHistory, v.History,
				func(_ uint32, row []byte) error {
					entry, err := contract.InspectGeneratorHistory(row)
					if err != nil || v.History.Count != 1 || entry != want {
						return contract.ErrRecord
					}
					return nil
				}); err != nil || v.History.Count != 1 || !h.NextAttemptID.IsZero() && h.Edge != 4 {
				return contract.ErrRecord
			}
			var facts contract.GeneratorSafeFacts
			if err := view.vectors.Inspect(contract.GeneratedAttemptSupportKind, v.AttemptID, contract.GeneratorVectorFacts, v.Facts,
				func(_ uint32, body []byte) error {
					row, err := contract.InspectGeneratorFactsRow(body)
					if err != nil || v.Facts.Count != 1 || row.ResultID != v.ResultID {
						return contract.ErrRecord
					}
					// A retained host rejection cannot authorize a controlled cleanup.
					f, err := contract.InspectGeneratorSafeFacts(row.Facts)
					facts = f.GeneratorSafeFacts
					return err
				}); err != nil {
				return err
			}
			var attemptProgress [][]byte
			if err := view.vectors.Inspect(contract.GeneratedAttemptSupportKind, v.AttemptID, contract.GeneratorVectorProgress, v.Progress,
				func(_ uint32, body []byte) error {
					attemptProgress = append(attemptProgress, bytes.Clone(body))
					return nil
				}); err != nil || len(attemptProgress) > 2 {
				return contract.ErrRecord
			}
			var admittedAck contract.GeneratorProgress
			completed := false
			for _, body := range attemptProgress {
				p, err := contract.InspectGeneratorProgress(body)
				if err != nil || p.CompletionClass != source.CompletionClass || p.RequiredSteps != contract.GeneratorConfirmedRequiredSteps {
					return contract.ErrRecord
				}
				switch p.CompletedSteps {
				case contract.GeneratorProgressAcknowledged:
					ack, ok := acks[p.ResultID]
					if !ok || !admittedAck.AttemptID.IsZero() || p != ack {
						return contract.ErrRecord
					}
					admittedAck = ack
				case contract.GeneratorProgressConfirmed:
					if completed || p.AttemptID != v.AttemptID || p.ResultID != v.ResultID ||
						p.Evidence.Digest != result.digest || p.Evidence.Length != uint64(len(result.record.Body)) {
						return contract.ErrRecord
					}
					completed = true
				default:
					return contract.ErrRecord
				}
			}
			if completed && admittedAck.AttemptID.IsZero() {
				return contract.ErrRecord
			}
			if !admittedAck.AttemptID.IsZero() && admittedAck.AttemptID != v.AttemptID {
				scope := contract.GeneratorControlledRetirementScope(v.DescriptorID, v.ConfigContractID, v.ResultContractID)
				want := contract.GeneratorControlledRetirementProbeDigest(source.DomainID, source.ResourceID, expectedTarget.ResourceDigest,
					scope, admittedAck.ResultID, admittedAck.Evidence.Digest)
				if v.RequestDigest != want {
					return contract.ErrRecord
				}
			}
			if facts.Disposition == contract.GeneratorDispositionUnknown {
				resourceDigest, resourceErr := contract.GeneratorResourceDigest(facts)
				contradiction = contradiction || facts.Reason == contract.GeneratorReasonIdentityConflict || len(facts.Target) != 0 && (resourceErr != nil || resourceDigest != expectedTarget.ResourceDigest)
			}
			if len(result.record.Body) == 0 {
				if err := a.controlledResultFreeDelete(view, source, v); err != nil {
					return contract.ErrRecord
				}
				if completed || v.State == contract.GeneratedEffectTransmitted {
					if completed || v.Facts.Count != 0 || !h.NextAttemptID.IsZero() {
						return contract.ErrRecord
					}
				} else if v.State != contract.GeneratedEffectUnknown && v.State != contract.GeneratedEffectClosedWithResidue || v.Facts.Count != 1 || facts.Disposition != contract.GeneratorDispositionUnknown || facts.RequestDigest != v.RequestDigest {
					return contract.ErrRecord
				}
			} else {
				r := result.value
				if v.Facts.Count != 1 {
					return contract.ErrRecord
				}
				if recorded {
					factBody, err := contract.EncodeGeneratorSafeFacts(facts)
					resultFacts, factsErr := contract.EncodeGeneratorSafeFacts(r.SafeFacts.GeneratorSafeFacts)
					if err != nil || factsErr != nil || !bytes.Equal(factBody, resultFacts) {
						return contract.ErrRecord
					}
				} else if facts.Disposition != contract.GeneratorDispositionUnknown || facts.RequestDigest != v.RequestDigest ||
					v.State != contract.GeneratedEffectUnknown && v.State != contract.GeneratedEffectClosedWithResidue {
					return contract.ErrRecord
				}
				graph, err := a.controlledGraphFromView(view, r.Core.PlanGraphID)
				material, materialErr := contract.InspectOperationMaterialRecord(view.record(contract.OperationMaterialSupportKind, r.Core.MaterialID).Body)
				if err != nil || materialErr != nil || graph.Header.OperationID != v.OperationID {
					return contract.ErrRecord
				}
				x := graph.Lineages[0].Templates[0]
				expected := contract.GeneratorResultExpectation{InputEncoding: contract.InputEncodingRaw, Plan: graph.UsePlan, Template: x, Use: graph.ResultUses[0], RequestDigest: v.RequestDigest, TargetResourceDigest: expectedTarget.ResourceDigest}
				core, err := contract.ExpectedGeneratedResultCore(expected, material, r.SafeFacts.GeneratorSafeFacts)
				digest, digestErr := contract.GeneratorTemplateID(x)
				if err != nil || digestErr != nil || r.Core != core || v.TemplateDigest != digest || x.AttemptID != v.AttemptID || x.DutyID != source.OwnerID || x.ResourceIncarnationID != source.ResourceID ||
					v.Stage != contract.GeneratedStageTerminal || !h.NextAttemptID.IsZero() && recorded && v.State != contract.GeneratedEffectSucceeded && v.State != contract.GeneratedEffectFailedTerminal {
					return contract.ErrRecord
				}
				switch r.SafeFacts.Disposition {
				case contract.GeneratorDispositionRetirementAcknowledged:
					if recorded && (v.State != contract.GeneratedEffectSucceeded || admittedAck.AttemptID != v.AttemptID || completed) ||
						!recorded && admittedAck.AttemptID == v.AttemptID {
						return contract.ErrRecord
					}
					if len(progress) == 0 {
						body, err := contract.EncodeGeneratorProgress(acks[v.ResultID])
						if err != nil {
							return err
						}
						progress = [][]byte{body}
					}
				case contract.GeneratorDispositionScopedUnusability, contract.GeneratorDispositionContinuedUsability, contract.GeneratorDispositionConflictingBinding:
					f := r.SafeFacts
					if admittedAck.AttemptID.IsZero() || f.PrecedingResultID != admittedAck.ResultID || f.PrecedingResultBodyDigest != admittedAck.Evidence.Digest ||
						f.ScopeID != contract.GeneratorControlledRetirementScope(v.DescriptorID, v.ConfigContractID, v.ResultContractID) ||
						recorded && (f.Disposition == contract.GeneratorDispositionScopedUnusability && v.State != contract.GeneratedEffectSucceeded || f.Disposition != contract.GeneratorDispositionScopedUnusability && v.State != contract.GeneratedEffectFailedTerminal || completed != (f.Disposition == contract.GeneratorDispositionScopedUnusability)) ||
						!recorded && completed {
						return contract.ErrRecord
					}
					contradiction = contradiction || f.Disposition != contract.GeneratorDispositionScopedUnusability
					if f.Disposition == contract.GeneratorDispositionScopedUnusability && !contradiction {
						p := admittedAck
						p.AttemptID, p.ResultID, p.Evidence, p.CompletedSteps = v.AttemptID, v.ResultID, contract.GeneratorDescriptor{Digest: result.digest, Length: uint64(len(result.record.Body)), Count: 1}, contract.GeneratorProgressConfirmed
						body, err := contract.EncodeGeneratorProgress(p)
						ackBody, ackErr := contract.EncodeGeneratorProgress(admittedAck)
						if err != nil {
							return err
						}
						if ackErr != nil {
							return ackErr
						}
						progress = [][]byte{ackBody, body}
						slices.SortFunc(progress, func(a, b []byte) int { return bytes.Compare(a[2:66], b[2:66]) })
					}
				default:
					return contract.ErrRecord
				}
			}
			return nil
		})
	if err != nil || contradiction || len(progress) > 1 {
		return fail()
	}
	if source.Record.Kind == contract.GeneratedDutySupportKind && (source.Duty.Step != uint8(1+len(progress)) || generatedSelectedProgress(view.vectors, contract.GeneratedDutySupportKind, source.SourceID, source.Duty.Progress, progress) != nil) {
		return fail()
	}
	return source, progress, nil
}

func generatedSelectedProgress(vectors *contract.SelectedGeneratorVectorIndex, kind uint8, owner contract.ID, descriptor contract.GeneratorDescriptor, progress [][]byte) error {
	want, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorProgress, progress)
	if err != nil || descriptor != want {
		return contract.ErrRecord
	}
	return vectors.Inspect(kind, owner, contract.GeneratorVectorProgress, descriptor, nil)
}

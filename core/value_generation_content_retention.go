package core

import "enkv.sh/core/contract"

// generatedCloseContent keeps the content roots required by the surviving
// owners. Closing one owner cannot discard a sibling graph, result or intent.
func (g *generatedSelection) generatedCloseContent(rows []contract.SupportRecord) ([]contract.SupportRecord,
	[]contract.GeneratorSliceLocation, contract.GeneratorDescriptor, error) {
	if g == nil || g.session == nil || g.session.adminIndex.SliceSnapshot.IsZero() {
		return nil, nil, contract.GeneratorDescriptor{}, contract.ErrRecord
	}
	wanted := make(map[generatedContentKey]bool)
	vectors, err := newGeneratedVectorSet(g.image.root.Domain, rows)
	if err != nil {
		return nil, nil, contract.GeneratorDescriptor{}, err
	}
	support, err := g.generatedSupportOwners(rows, vectors)
	if err != nil {
		return nil, nil, contract.GeneratorDescriptor{}, err
	}
	for _, row := range rows {
		switch row.Kind {
		case contract.GeneratedParentSupportKind:
			p, err := contract.InspectGeneratedParentRecord(row.Body)
			if err != nil {
				return nil, nil, contract.GeneratorDescriptor{}, err
			}
			wanted[generatedContentKey{contract.GeneratorContentDeclaration, p.OperationID}] = true
			wanted[generatedContentKey{contract.GeneratorContentGraph, p.PlanGraphID}] = true
			if _, ok := g.content.locations[generatedContentKey{contract.GeneratorContentOutputConfiguration, p.OperationID}]; ok {
				wanted[generatedContentKey{contract.GeneratorContentOutputConfiguration, p.OperationID}] = true
			}
			if _, ok := g.content.locations[generatedContentKey{contract.GeneratorContentRecipientRegistry, p.OperationID}]; ok {
				wanted[generatedContentKey{contract.GeneratorContentRecipientRegistry, p.OperationID}] = true
			}
		case contract.GeneratedAttemptSupportKind:
			a, err := contract.InspectGeneratedAttemptRecord(row.Body)
			if err != nil {
				return nil, nil, contract.GeneratorDescriptor{}, err
			}
			graph, err := g.retainedGraph(a.OperationID)
			if err != nil {
				return nil, nil, contract.GeneratorDescriptor{}, err
			}
			wanted[generatedContentKey{contract.GeneratorContentGraph, graph.UsePlan.PlanGraphID}] = true
			var progress [][]byte
			if a.SemanticLifecycleMode() == contract.GeneratorLifecycleNone {
				if a.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) {
					return nil, nil, contract.GeneratorDescriptor{}, contract.ErrRecord
				}
			} else {
				progress, err = vectors.resolve(contract.GeneratedAttemptSupportKind, a.AttemptID, contract.GeneratorVectorProgress, a.Progress)
				if err != nil {
					return nil, nil, contract.GeneratorDescriptor{}, err
				}
			}
			for _, body := range progress {
				prefix, err := contract.InspectGeneratorProgress(body)
				if err != nil {
					return nil, nil, contract.GeneratorDescriptor{}, err
				}
				if prefix.AttemptID == a.AttemptID {
					continue
				}
				if prefix.CompletionClass != contract.GeneratedCompletionConfirmed || prefix.CompletedSteps != contract.GeneratorProgressAcknowledged {
					return nil, nil, contract.GeneratorDescriptor{}, contract.ErrRecord
				}
				// The ACK mapping may have been physically released. Its exact
				// selected template graph remains owned by this probe prefix.
				var retained contract.ID
				for _, bundle := range g.bundles {
					x, _, present := generatedTemplate(bundle, prefix.AttemptID)
					if !present {
						continue
					}
					if !retained.IsZero() || x.Action != contract.GeneratorActionDelete || x.ResultID != prefix.ResultID || x.DutyID != a.OwnerID ||
						x.ResourceIncarnationID != a.ResourceID || x.ConfigContractID != a.ConfigContractID || x.ResourceContractID != a.ResourceContractID ||
						x.ResultContractID != a.ResultContractID || x.CompletionClass != a.CompletionClass {
						return nil, nil, contract.GeneratorDescriptor{}, contract.ErrRecord
					}
					retained = bundle.UsePlan.PlanGraphID
				}
				if retained.IsZero() {
					return nil, nil, contract.GeneratorDescriptor{}, contract.ErrRecord
				}
				wanted[generatedContentKey{contract.GeneratorContentGraph, retained}] = true
			}
			if _, releasing := g.records[generatedRecordKey{contract.PendingInboxReleaseSupportKind, a.InboxID}]; !releasing {
				for _, candidate := range rows {
					if candidate.Kind == contract.PendingInboxReleaseSupportKind && candidate.RecordID == a.InboxID {
						releasing = true
						break
					}
				}
				if x, _, ok := generatedTemplate(graph, a.AttemptID); ok && x.Action == contract.GeneratorActionCreate && !releasing {
					wanted[generatedContentKey{contract.GeneratorContentIntent, x.IntentDigest}] = true
				}
			}
		case contract.GeneratedCreateEvidenceSupportKind:
			e, err := contract.InspectGeneratedCreateEvidence(row.Body)
			if err != nil {
				return nil, nil, contract.GeneratorDescriptor{}, err
			}
			facts, err := contract.InspectGeneratorSafeFacts(e.SafeFacts)
			if err != nil {
				return nil, nil, contract.GeneratorDescriptor{}, err
			}
			wanted[generatedContentKey{contract.GeneratorContentIntent, facts.IntentDigest}] = true
		}
	}
	var locations []contract.GeneratorSliceLocation
	for key := range wanted {
		location, ok := g.content.locations[key]
		if !ok {
			return nil, nil, contract.GeneratorDescriptor{}, contract.ErrRecord
		}
		locations = append(locations, location)
	}
	locations, err = generatedUniqueLocations(locations)
	if err != nil {
		return nil, nil, contract.GeneratorDescriptor{}, err
	}
	used := make(map[contract.ID]bool)
	index, err := g.session.receiptIndexID()
	if err != nil {
		return nil, nil, contract.GeneratorDescriptor{}, err
	}
	used[index] = true
	var bodies [][]byte
	for _, location := range locations {
		used[location.BlobID] = true
		body, err := contract.EncodeGeneratorSliceLocation(location)
		if err != nil {
			return nil, nil, contract.GeneratorDescriptor{}, err
		}
		bodies = append(bodies, body)
	}
	out := make([]contract.SupportRecord, 0, len(rows))
	selectedFragments, err := g.session.selectedFragmentFactsByRecord()
	if err != nil {
		return nil, nil, contract.GeneratorDescriptor{}, err
	}
	for _, row := range rows {
		if row.Kind == contract.GeneratorVectorSupportKind {
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				return nil, nil, contract.GeneratorDescriptor{}, err
			}
			if carrier.VectorKind == contract.GeneratorVectorSupport && !support[generatedVectorKey{carrier.OwnerKind, carrier.OwnerID, carrier.VectorKind, carrier.Vector}] {
				continue
			}
		}
		if row.Kind == contract.GeneratedFragmentSupportKind {
			var blob contract.ID
			if len(row.Body) == 0 {
				fact, ok := selectedFragments[row.RecordID]
				if !ok {
					return nil, nil, contract.GeneratorDescriptor{}, contract.ErrRecord
				}
				blob = fact.blob
			} else {
				fragment, err := contract.InspectGeneratedFragment(row.Body)
				if err != nil {
					return nil, nil, contract.GeneratorDescriptor{}, err
				}
				blob = fragment.BlobID
			}
			if !used[blob] {
				continue
			}
		}
		out = append(out, row)
	}
	descriptor, carriers, err := generatedCarrierRows(g.image.root.Domain, contract.GeneratorSnapshotOwner,
		g.session.adminIndex.SliceSnapshot, contract.GeneratorVectorSlices, bodies)
	return append(out, carriers...), locations, descriptor, err
}

func (g *generatedSelection) generatedSupportOwners(rows []contract.SupportRecord, vectors generatedVectorSet) (map[generatedVectorKey]bool, error) {
	if g == nil || g.image == nil || g.session == nil {
		return nil, contract.ErrRecord
	}
	retainedConsumers, err := generatedRetainedCanonicalConsumers(rows)
	if err != nil {
		return nil, err
	}
	support := make(map[generatedVectorKey]bool)
	retain := func(operation contract.ID, descriptor contract.GeneratorDescriptor) {
		support[generatedVectorKey{contract.GeneratedParentSupportKind, operation, contract.GeneratorVectorSupport, descriptor}] = true
	}
	for _, entry := range g.image.root.Names {
		value := g.session.valueEntry(entry.Slot)
		if value == nil {
			return nil, contract.ErrRecord
		}
		if value.ValueSource == contract.Generated {
			retain(value.Generated.OriginOperationID, value.Generated.RequiredSupport)
		}
	}
	for _, row := range rows {
		switch row.Kind {
		case contract.GeneratedAttemptSupportKind:
			attempt, err := contract.InspectGeneratedAttemptRecord(row.Body)
			if err != nil {
				return nil, err
			}
			retain(attempt.OperationID, attempt.Support)
		case contract.GeneratedDutySupportKind:
			duty, err := contract.InspectGeneratedDutyRecord(row.Body)
			if err != nil {
				return nil, err
			}
			retain(duty.OriginalOperationID, duty.Support)
		case contract.GeneratedHazardSupportKind:
			hazard, err := contract.InspectGeneratedHazardRecord(row.Body)
			if err != nil {
				return nil, err
			}
			owner, err := generatedHazardSupportOwner(hazard, g.bundles, vectors)
			if err != nil {
				return nil, err
			}
			retain(owner, hazard.Support)
		case contract.RetainedCanonicalSupportKind:
			canonical, err := contract.InspectRetainedCanonicalRecord(row.Body)
			if err != nil {
				return nil, err
			}
			if canonical.Entry.ValueSource == contract.Generated && retainedConsumers[row.RecordID] {
				retain(canonical.Entry.Generated.OriginOperationID, canonical.Entry.Generated.RequiredSupport)
			}
		}
	}
	return support, nil
}

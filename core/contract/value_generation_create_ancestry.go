package contract

import (
	"bytes"
	"encoding/binary"
)

// GeneratedReleasedCreatePreservesResidueHistory joins a later no-effect
// closure to the unchanged residue edge that admitted a CREATE successor.
// The release is evidence only; it grants no branch, custody or send right.
func GeneratedReleasedCreatePreservesResidueHistory(a GeneratedAttemptRecord, x GeneratorAttemptTemplate, h GeneratorHistory, r PendingInboxReleaseRecord) bool {
	if _, err := GeneratedAttemptRecordLength(a); err != nil {
		return false
	}
	if _, err := PendingInboxReleaseRecordLength(r); err != nil {
		return false
	}
	return x.Action == GeneratorActionCreate && x.SemanticLifecycleMode() == GeneratorLifecycleManaged && generatedAncestryAttemptMatches(a, x) &&
		a.State == GeneratedEffectConfirmedNoEffect && a.Stage == GeneratedStageTerminal && a.RetryUsed == 0 &&
		a.Facts == EmptyGeneratorVector(GeneratorVectorFacts) && a.Progress == EmptyGeneratorVector(GeneratorVectorProgress) && a.History == EmptyGeneratorVector(GeneratorVectorHistory) &&
		h.valid() && h.PredecessorAttemptID == a.AttemptID && h.OwnerID == a.OwnerID && h.Outcome == GeneratedEffectClosedWithResidue &&
		h.ResultID.IsZero() && h.ResultDigest.IsZero() && h.Edge == GeneratorGuardResidue && !h.NextAttemptID.IsZero() &&
		r.DomainID == a.DomainID && r.InboxID == a.InboxID && r.OriginalResultID == a.ResultID &&
		(r.State == GeneratedReleasePending || r.State == GeneratedReleaseUnknown) && r.ObjectLength != 0
}

// InspectGeneratedSelectedCreateAncestry checks the complete immutable create
// prefix of one actual selected cleanup source. It grants no invocation right.
// All backing is borrowed for this call. Only a crossing row (<=3924 bytes),
// the five-template target lineage and its branch edges need owned scratch.
func InspectGeneratedSelectedCreateAncestry(domain, snapshot ID, records []SupportRecord, source GeneratedDeleteSource) (uint32, error) {
	find := func(kind uint8, id ID) SupportRecord {
		for _, row := range records {
			if row.Kind == kind && row.RecordID == id {
				return row
			}
		}
		return SupportRecord{}
	}
	if source.DomainID != domain || !bytes.Equal(find(source.Record.Kind, source.SourceID).Body, source.Record.Body) {
		return 0, ErrRecord
	}
	if source.Record.Kind == GeneratedDutySupportKind && source.Duty.Kind == GeneratedDutyRetirement {
		return 0, nil
	}
	row := find(GeneratedAttemptSupportKind, source.OriginalAttemptID)
	if len(row.Body) == 0 {
		// A detached kind-13 source has no live create Attempt to reconstruct.
		if source.Record.Kind != GeneratedHazardSupportKind {
			return 0, ErrRecord
		}
		transmission, err := GeneratorTransmissionID(source.OriginalAttemptID, GeneratorActionCreate)
		if err != nil {
			return 0, err
		}
		id, err := GeneratorResultID(domain, source.OriginalOperationID, source.OriginalAttemptID, transmission, GeneratorActionCreate)
		if err != nil {
			return 0, err
		}
		evidence := find(GeneratedCreateEvidenceSupportKind, id)
		descriptor, err := GeneratorRecordSetDescriptor(GeneratorHazardResults, domain, []SupportRecord{evidence})
		if err != nil || descriptor != source.Hazard.OriginalResults || len(find(GeneratedResultSupportKind, id).Body) != 0 {
			return 0, ErrRecord
		}
		create, err := InspectGeneratedCreateEvidence(evidence.Body)
		if err != nil {
			return 0, err
		}
		core, err := InspectGeneratedResultCore(create.ResultCore)
		if err != nil || core.DescriptorID != source.DescriptorID || core.ExecutorID != source.ExecutorID || create.CredentialRouteID != source.CredentialRouteID {
			return 0, ErrRecord
		}
		return 0, nil
	}
	original, err := InspectGeneratedAttemptRecord(row.Body)
	if err != nil || original.DomainID != domain || original.OperationID != source.OriginalOperationID {
		return 0, ErrRecord
	}
	deleteID, err := GeneratorResultID(domain, original.OperationID, original.AttemptID, original.TransmissionID, GeneratorActionDelete)
	if err != nil {
		return 0, err
	}
	if original.ResultID == deleteID {
		return 0, nil
	}
	createID, err := GeneratorResultID(domain, original.OperationID, original.AttemptID, original.TransmissionID, GeneratorActionCreate)
	if err != nil || original.ResultID != createID || original.OwnerID != source.OwnerID || original.ResourceID != source.ResourceID ||
		original.DescriptorID != source.DescriptorID || original.ConfigContractID != source.ConfigContractID || original.ExecutorID != source.ExecutorID ||
		original.CredentialRouteID != source.CredentialRouteID || original.ResourceContractID != source.ResourceContractID ||
		original.ResultContractID != source.ResultContractID || original.CompletionClass != source.CompletionClass ||
		original.Stage != GeneratedStageTerminal || original.History.Count > GeneratorMaxEnteredCreateAttempts {
		return 0, ErrRecord
	}
	result, err := InspectGeneratedResultRecord(find(GeneratedResultSupportKind, original.ResultID).Body)
	if err != nil || result.Core.DomainID != domain || result.Core.OperationID != original.OperationID || result.Core.AttemptID != original.AttemptID ||
		result.Core.ResultID != original.ResultID || result.Core.TransmissionID != original.TransmissionID || result.Core.RequestDigest != original.RequestDigest {
		return 0, ErrRecord
	}
	if source.Record.Kind == GeneratedHazardSupportKind {
		descriptor, err := GeneratorRecordSetDescriptor(GeneratorHazardResults, domain, []SupportRecord{find(GeneratedResultSupportKind, original.ResultID)})
		if err != nil || descriptor != source.Hazard.OriginalResults || original.State != GeneratedEffectFailedTerminal && original.State != GeneratedEffectClosedWithResidue {
			return 0, ErrRecord
		}
	} else if original.State != GeneratedEffectSucceeded {
		return 0, ErrRecord
	}
	var location GeneratorSliceLocation
	for _, row := range records {
		if row.Kind != GeneratorVectorSupportKind {
			continue
		}
		c, err := InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			return 0, err
		}
		if c.VectorKind != GeneratorVectorSlices {
			continue
		}
		l, err := InspectGeneratorSliceLocation(c.Row)
		if err != nil {
			return 0, err
		}
		if l.ContentKind == GeneratorContentGraph && l.ContentID == result.Core.PlanGraphID {
			if !location.ContentID.IsZero() {
				return 0, ErrRecord
			}
			location = l
		}
	}
	if location.ContentID.IsZero() || uint64(location.Length)+8 > GeneratorGraphMaxLength {
		return 0, ErrRecordCapacity
	}
	backing, err := inspectGeneratedImmutableSlice(domain, snapshot, records, location)
	if err != nil {
		return 0, err
	}
	v := generatedAncestryBundle{backing: backing}
	schema := v.u16()
	if schema != GeneratorRecordSchema && schema != GeneratorPlanBundleSchema {
		return 0, ErrRecord
	}
	request, err := InspectGeneratorRequestCore(v.blob(GeneratorRequestCoreLength, GeneratorApplyRequestCoreLength))
	if err != nil {
		return 0, err
	}
	header, err := InspectGeneratorGraphHeader(v.blob(GeneratorGraphHeaderLength, GeneratorGraphHeaderLength))
	if err != nil || header.Schema != schema || ValidateGeneratorGraphRequest(request, header) != nil || header.DomainID != domain || header.OperationID != original.OperationID {
		return 0, ErrRecord
	}
	minimumPlan, minimumLineage := 238, 208+4+GeneratorAttemptTemplateLength
	if schema == GeneratorPlanBundleSchema {
		minimumPlan, minimumLineage = 238, 734
	}
	var previousName string
	var slots [CryptoMaxValueEntries]bool
	var selectedEntryPlan GeneratorValueEntryPlan
	entryPlansDescriptor, err := v.vector("member-plans", CryptoMaxValueEntries, minimumPlan, GeneratorValueEntryPlanMaxLength, func(body []byte) error {
		m, err := InspectGeneratorValueEntryPlan(body)
		if err != nil || m.Schema != GeneratorValueEntryPlanSchema || slots[m.Slot] || previousName != "" && previousName >= string(m.Name) {
			return ErrRecord
		}
		slots[m.Slot], previousName = true, string(m.Name)
		if m.LineageID == original.LineageID {
			selectedEntryPlan, err = m.Own()
			return err
		}
		return nil
	})
	if err != nil || entryPlansDescriptor.Count != uint32(header.ValueEntryPlanCount) {
		return 0, ErrRecord
	}
	var selectedLineage, previousLineage GeneratorLineageTemplate
	var creates, templates uint32
	lineages, err := v.vector("lineage-templates", GeneratorMaxLineageTemplates, minimumLineage, GeneratorLineageTemplateMaxLength, func(body []byte) error {
		l, err := InspectGeneratorLineageTemplate(body)
		if err != nil || l.Schema != schema || l.DomainID != domain || l.OperationID != original.OperationID {
			return ErrRecord
		}
		owned, err := l.Own()
		if err != nil || !previousLineage.LineageID.IsZero() && generatorLineageCompare(previousLineage, owned) >= 0 {
			return ErrRecord
		}
		// Only ordering metadata survives this row, not every graph lineage.
		previousLineage = GeneratorLineageTemplate{Name: owned.Name, Purpose: owned.Purpose, ResourceIncarnationID: owned.ResourceIncarnationID, LineageID: owned.LineageID}
		templates += uint32(l.TemplateCount)
		if l.Purpose == GeneratorLineageCreate {
			creates++
		}
		if l.LineageID == original.LineageID {
			if !selectedLineage.LineageID.IsZero() || l.Purpose != GeneratorLineageCreate {
				return ErrRecord
			}
			selectedLineage = owned
		}
		return nil
	})
	if err != nil || creates != uint32(header.LineageCount) || creates > GeneratorMaxCreateLineages || templates != uint32(header.TemplateCount) || templates > GeneratorMaxTemplates ||
		selectedLineage.LineageID.IsZero() || selectedEntryPlan.LineageID != selectedLineage.LineageID || selectedEntryPlan.Name != selectedLineage.Name || selectedEntryPlan.EntryIncarnationID != selectedLineage.EntryIncarnationID ||
		selectedEntryPlan.Epoch != selectedLineage.Epoch || selectedEntryPlan.IntentDigest != selectedLineage.IntentDigest {
		return 0, ErrRecord
	}
	var needed [20]GeneratorEdge
	neededCount := 0
	var previousEdge GeneratorEdge
	edges, err := v.vector("transition-rules", GeneratorMaxTemplates*4, GeneratorEdgeLength, GeneratorEdgeLength, func(body []byte) error {
		e, err := InspectGeneratorEdge(body)
		if err != nil || !previousEdge.SourceTemplateID.IsZero() && generatorEdgeCompare(previousEdge, e) >= 0 {
			return ErrRecord
		}
		previousEdge = e
		for _, x := range selectedLineage.Templates[:selectedLineage.TemplateCount] {
			id, err := GeneratorTemplateID(x)
			if err != nil {
				return err
			}
			if id == e.SourceTemplateID {
				if neededCount == len(needed) {
					return ErrRecordCapacity
				}
				needed[neededCount], neededCount = e, neededCount+1
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	var previousUse GeneratorResultUse
	var originalUse GeneratorResultUse
	var lineageUses [5]GeneratorResultUse
	uses, err := v.vector("result-uses", GeneratorMaxTemplates, GeneratorResultUseLength, GeneratorResultUseLength, func(body []byte) error {
		u, err := InspectGeneratorResultUse(body)
		if err != nil || !previousUse.AttemptID.IsZero() && (bytes.Compare(previousUse.AttemptID[:], u.AttemptID[:]) > 0 || previousUse.AttemptID == u.AttemptID && bytes.Compare(previousUse.ResultID[:], u.ResultID[:]) >= 0) {
			return ErrRecord
		}
		previousUse = u
		if u.AttemptID == original.AttemptID {
			originalUse = u
		}
		for i, x := range selectedLineage.Templates[:selectedLineage.TemplateCount] {
			if u.AttemptID == x.AttemptID {
				lineageUses[i] = u
			}
		}
		return nil
	})
	if err != nil || uses.Count != templates {
		return 0, ErrRecord
	}
	var previousSource GeneratorSourceUse
	sources, err := v.vector("source-uses", CryptoMaxValueEntries, GeneratorSourceUseLength, GeneratorSourceUseLength, func(body []byte) error {
		s, err := InspectGeneratorSourceUse(body)
		if err != nil || !previousSource.SourceID.IsZero() && bytes.Compare(previousSource.SourceID[:], s.SourceID[:]) >= 0 {
			return ErrRecord
		}
		previousSource = s
		return nil
	})
	if err != nil {
		return 0, err
	}
	plan, err := InspectGeneratorUsePlanCore(v.blob(GeneratorUsePlanCoreLength, GeneratorUsePlanCoreLength))
	if err != nil || v.err != nil || v.offset != location.Length || plan.DomainID != domain || plan.OperationID != header.OperationID || plan.MaterialID != header.MaterialID ||
		plan.ResultUses != uses || plan.SourceUses != sources || plan.ValueDerivationID != generatorGraphValueDerivationID(schema) {
		return 0, ErrRecord
	}
	w := cryptoHashWriter(generatorIdentityPrefix + "graph\x00")
	w.u32(GeneratorGraphHeaderLength + 3*GeneratorDescriptorLength)
	writeGeneratorGraphHeader(&w, header)
	writeGeneratorDescriptor(&w, entryPlansDescriptor)
	writeGeneratorDescriptor(&w, lineages)
	writeGeneratorDescriptor(&w, edges)
	graphID := w.result(0).Digest
	useDigest, err := GeneratorUsePlanDigest(plan)
	if err != nil || graphID != location.ContentID || graphID != plan.PlanGraphID || useDigest != result.Core.UsePlanDigest || header.MaterialID != result.Core.MaterialID {
		return 0, ErrRecord
	}
	var path [GeneratorMaxEnteredCreateAttempts]GeneratorAttemptTemplate
	n := 0
	x := selectedLineage.Templates[0]
	found := false
	for _, candidate := range selectedLineage.Templates[:selectedLineage.TemplateCount] {
		if candidate.AttemptID == original.AttemptID {
			x, found = candidate, true
		}
	}
	digest, err := GeneratorTemplateID(x)
	if !found || err != nil || digest != original.TemplateDigest || !generatedAncestryAttemptMatches(original, x) || originalUse.ResultID != original.ResultID || originalUse.MaterialID != header.MaterialID ||
		originalUse.InboxID != original.InboxID || originalUse.ExecutorID != original.ExecutorID || originalUse.ResultContractID != original.ResultContractID || originalUse.PlannedValueSlotID != x.PlannedValueSlotID {
		return 0, ErrRecord
	}
	material, err := InspectOperationMaterialRecord(find(OperationMaterialSupportKind, header.MaterialID).Body)
	expected := GeneratorResultExpectation{InputEncoding: selectedEntryPlan.InputEncoding, Plan: plan, Template: x, Use: originalUse, RequestDigest: original.RequestDigest}
	core, coreErr := ExpectedGeneratedResultCore(expected, material, result.SafeFacts.GeneratorSafeFacts)
	if err != nil || coreErr != nil || result.Core != core || result.SafeFacts.IntentDigest != x.IntentDigest ||
		source.Record.Kind == GeneratedDutySupportKind && result.SafeFacts.Disposition != GeneratorDispositionCompleteCreate ||
		source.Record.Kind == GeneratedHazardSupportKind && result.SafeFacts.Disposition != GeneratorDispositionCompleteCreate && result.SafeFacts.Disposition != GeneratorDispositionOwnedUnusableCreate {
		return 0, ErrRecord
	}
	resourceDigest, err := GeneratorResourceDigest(result.SafeFacts.GeneratorSafeFacts)
	if err != nil {
		return 0, err
	}
	if err := InspectGeneratorSelectedVector(domain, source.Record.Kind, source.SourceID, GeneratorVectorTargets, source.Target, records, func(_ uint32, body []byte) error {
		target, err := InspectGeneratorTarget(body)
		if err != nil || source.Target.Count != 1 || target.OriginalOperationID != original.OperationID || target.OriginalAttemptID != original.AttemptID ||
			target.ResourceID != x.ResourceIncarnationID || target.Name != selectedLineage.Name || target.IncarnationID != selectedLineage.EntryIncarnationID ||
			target.Epoch != selectedLineage.Epoch || target.ConfigContractID != x.ConfigContractID || target.ResultContractID != x.ResultContractID ||
			target.CompletionClass != x.CompletionClass || target.ResourceContractID != x.ResourceContractID || target.LifecycleMode != x.LifecycleMode || target.ResourceDigest != resourceDigest {
			return ErrRecord
		}
		return nil
	}); err != nil || source.Target.Count != 1 {
		return 0, ErrRecord
	}
	// The actual first invocation can have an empty immutable create history.
	// Its graph/template/result binding still precedes the deleting suffix.
	if original.History.Count == 0 {
		if !original.PredecessorAttemptID.IsZero() {
			return 0, ErrRecord
		}
		return 0, nil
	}
	for {
		if n == len(path) {
			return 0, ErrRecordCapacity
		}
		path[n], n = x, n+1
		if x.PredecessorAttemptID.IsZero() {
			break
		}
		found = false
		for _, candidate := range selectedLineage.Templates[:selectedLineage.TemplateCount] {
			if candidate.AttemptID == x.PredecessorAttemptID {
				x, found = candidate, true
				break
			}
		}
		if !found {
			return 0, ErrRecord
		}
	}
	if original.History.Count != uint32(n) || source.History.Count < uint32(n) {
		return 0, ErrRecord
	}
	var prefix [GeneratorMaxEnteredCreateAttempts]GeneratorHistory
	err = InspectGeneratorSelectedVector(domain, GeneratedAttemptSupportKind, original.AttemptID, GeneratorVectorHistory, original.History, records, func(index uint32, body []byte) error {
		h, err := InspectGeneratorHistory(body)
		x := path[n-int(index)-1]
		if err != nil || h.PredecessorAttemptID != x.AttemptID || h.OwnerID != x.DutyID || !h.ResultID.IsZero() && h.ResultID != x.ResultID {
			return ErrRecord
		}
		if index+1 < uint32(n) {
			next := path[n-int(index)-2]
			guard, outcome := uint8(GeneratorGuardResidue), uint8(GeneratedEffectClosedWithResidue)
			if next.Branch == GeneratorBranchNoEffect || next.Branch == GeneratorBranchResidueThenNoEffect {
				guard, outcome = GeneratorGuardQualifiedNoEffect, GeneratedEffectConfirmedNoEffect
			}
			src, _ := GeneratorTemplateID(x)
			dst, _ := GeneratorTemplateID(next)
			matched := false
			for _, e := range needed[:neededCount] {
				noEffect, residue := uint8(0), uint8(0)
				if next.Branch == GeneratorBranchNoEffect || next.Branch >= GeneratorBranchNoEffectThenResidue {
					noEffect = 1
				}
				if next.Branch >= GeneratorBranchResidue {
					residue = 1
				}
				matched = matched || e.SourceTemplateID == src && e.DestinationTemplateID == dst && e.Guard == guard && e.ResultSlotID == x.ResultID && e.RequiredAuthoritySet == x.RequiredAuthoritySet && e.NoEffectUsed == noEffect && e.ResidueUsed == residue
			}
			if !matched || h.Edge != guard || h.Outcome != outcome || h.NextAttemptID != next.AttemptID || guard == GeneratorGuardQualifiedNoEffect && h.ResultID.IsZero() {
				return ErrRecord
			}
		} else {
			reflected := source.Record.Kind == GeneratedHazardSupportKind && source.Hazard.Exposure == GeneratedExposureLateEffect && source.Hazard.Fenced == 1 &&
				original.State == GeneratedEffectClosedWithResidue && h.ResultID.IsZero() && h.ResultDigest.IsZero()
			if h.Outcome != original.State || !reflected && (h.ResultID != original.ResultID || h.ResultDigest != Hash(find(GeneratedResultSupportKind, original.ResultID).Body)) || !h.NextAttemptID.IsZero() || h.Edge != 0 {
				return ErrRecord
			}
		}
		retained := find(GeneratedAttemptSupportKind, x.AttemptID)
		if len(retained.Body) != 0 {
			a, err := InspectGeneratedAttemptRecord(retained.Body)
			if err != nil || a.DomainID != domain || a.OperationID != header.OperationID || !generatedAncestryAttemptMatches(a, x) {
				return ErrRecord
			}
			lateNoEffect := a.State != h.Outcome
			if lateNoEffect {
				r, err := InspectPendingInboxReleaseRecord(find(PendingInboxReleaseSupportKind, a.InboxID).Body)
				if err != nil || r.CapacityReservation != source.CapacityReservation || !GeneratedReleasedCreatePreservesResidueHistory(a, x, h, r) {
					return ErrRecord
				}
			}
			packet := find(GeneratedResultSupportKind, a.ResultID)
			if len(packet.Body) != 0 {
				if lateNoEffect {
					return ErrRecord
				}
				reflected := false
				if a.State == GeneratedEffectClosedWithResidue && h.ResultID.IsZero() && h.ResultDigest.IsZero() {
					hazard, err := InspectGeneratedHazardRecord(find(GeneratedHazardSupportKind, x.HazardID).Body)
					descriptor, descriptorErr := GeneratorRecordSetDescriptor(GeneratorHazardResults, domain, []SupportRecord{packet})
					reflected = err == nil && descriptorErr == nil && hazard.OriginalResults == descriptor && hazard.Fenced == 1 &&
						hazard.Exposure == GeneratedExposureLateEffect && hazard.OriginalOperationID == a.OperationID && hazard.OriginalAttemptID == a.AttemptID &&
						hazard.OwnerID == a.OwnerID && hazard.ResourceID == a.ResourceID
				}
				r, err := InspectGeneratedResultRecord(packet.Body)
				var use GeneratorResultUse
				for _, candidate := range lineageUses {
					if candidate.AttemptID == a.AttemptID {
						use = candidate
					}
				}
				core, coreErr := ExpectedGeneratedResultCore(GeneratorResultExpectation{InputEncoding: selectedEntryPlan.InputEncoding, Plan: plan, Template: x, Use: use, RequestDigest: a.RequestDigest}, material, r.SafeFacts.GeneratorSafeFacts)
				if err != nil || coreErr != nil || r.Core != core || !reflected && (h.ResultID != a.ResultID || h.ResultDigest != Hash(packet.Body)) ||
					h.Outcome == GeneratedEffectConfirmedNoEffect && r.SafeFacts.Disposition != GeneratorDispositionConfirmedNoEffect {
					return ErrRecord
				}
			}
			if len(packet.Body) == 0 && !h.ResultID.IsZero() {
				r, err := InspectPendingInboxReleaseRecord(find(PendingInboxReleaseSupportKind, a.InboxID).Body)
				if err != nil || r.DomainID != domain || r.InboxID != x.InboxID || r.OriginalResultID != x.ResultID || r.OriginalResultID != h.ResultID ||
					r.SelectedHandoffDigest != h.ResultDigest || r.CapacityReservation != source.CapacityReservation || r.State == GeneratedReleaseUnobserved || r.ObjectLength == 0 {
					return ErrRecord
				}
			}
		} else if h.Outcome != GeneratedEffectConfirmedNoEffect {
			return ErrRecord
		}
		prefix[index] = h
		return nil
	})
	if err != nil {
		return 0, err
	}
	var firstDelete ID
	if source.History.Count > uint32(n) {
		err = InspectGeneratorSelectedVector(domain, source.Record.Kind, source.SourceID, GeneratorVectorHistory, source.History, records, func(index uint32, body []byte) error {
			if index == uint32(n) {
				h, err := InspectGeneratorHistory(body)
				firstDelete = h.PredecessorAttemptID
				return err
			}
			return nil
		})
		if err != nil || firstDelete.IsZero() {
			return 0, ErrRecord
		}
	}
	err = InspectGeneratorSelectedVector(domain, source.Record.Kind, source.SourceID, GeneratorVectorHistory, source.History, records, func(index uint32, body []byte) error {
		if index >= uint32(n) {
			return nil
		}
		h, err := InspectGeneratorHistory(body)
		if err != nil {
			return err
		}
		if index+1 == uint32(n) && !firstDelete.IsZero() {
			if h.Edge != 4 || h.NextAttemptID != firstDelete {
				return ErrRecord
			}
			h.Edge, h.NextAttemptID = 0, ID{}
		}
		if h != prefix[index] {
			return ErrRecord
		}
		return nil
	})
	return uint32(n), err
}

func generatedAncestryAttemptMatches(a GeneratedAttemptRecord, x GeneratorAttemptTemplate) bool {
	digest, err := GeneratorTemplateID(x)
	return err == nil && a.TemplateDigest == digest && a.LineageID == x.LineageID && a.AttemptID == x.AttemptID && a.PredecessorAttemptID == x.PredecessorAttemptID &&
		a.OwnerID == x.DutyID && a.ResourceID == x.ResourceIncarnationID && a.TransmissionID == x.TransmissionID && a.ResultID == x.ResultID && a.InboxID == x.InboxID &&
		a.DescriptorID == x.DescriptorID && a.ConfigContractID == x.ConfigContractID && a.ExecutorID == x.ExecutorID && a.CredentialRouteID == x.CredentialRouteID &&
		a.ResourceContractID == x.ResourceContractID && a.LifecycleMode == x.LifecycleMode && a.ResultContractID == x.ResultContractID && a.CompletionClass == x.CompletionClass
}

// This private framing walk uses the existing row inspectors and hash recipes.
// It never decodes or copies a complete aggregate graph image or row set.
type generatedAncestryBundle struct {
	backing *generatedImmutableSlice
	offset  uint32
	err     error
}

func (v *generatedAncestryBundle) take(n uint32) []byte {
	if v.err != nil {
		return nil
	}
	body, err := v.backing.span(v.offset, n)
	if err != nil {
		v.err = err
		return nil
	}
	v.offset += n
	return body
}
func (v *generatedAncestryBundle) u16() uint16 {
	b := v.take(2)
	if len(b) != 2 {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}
func (v *generatedAncestryBundle) u32() uint32 {
	b := v.take(4)
	if len(b) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
func (v *generatedAncestryBundle) blob(minimum, maximum uint32) []byte {
	n := v.u32()
	if n < minimum || n > maximum {
		v.err = ErrRecord
		return nil
	}
	return v.take(n)
}
func (v *generatedAncestryBundle) vector(label string, maximum, minimumRow, maximumRow int, inspect func([]byte) error) (GeneratorDescriptor, error) {
	count := v.u32()
	if v.err != nil || count > uint32(maximum) {
		return GeneratorDescriptor{}, ErrRecordCapacity
	}
	start := v.offset
	n := uint64(4)
	for i := uint32(0); i < count; i++ {
		length := v.u32()
		if v.err != nil || length < uint32(minimumRow) || length > uint32(maximumRow) || uint64(v.offset)+uint64(length) > uint64(v.backing.location.Length) {
			return GeneratorDescriptor{}, ErrRecord
		}
		v.offset += length
		n += 4 + uint64(length)
	}
	if n > GeneratorGraphMaxLength {
		return GeneratorDescriptor{}, ErrRecordCapacity
	}
	end := v.offset
	v.offset = start
	w := generatorVectorHashWriter(label, int(n), int(count))
	for i := uint32(0); i < count; i++ {
		body := v.blob(uint32(minimumRow), uint32(maximumRow))
		if v.err != nil {
			return GeneratorDescriptor{}, v.err
		}
		if err := inspect(body); err != nil {
			return GeneratorDescriptor{}, err
		}
		w.blob(body)
	}
	if v.err != nil || v.offset != end {
		return GeneratorDescriptor{}, ErrRecord
	}
	return generatorVectorResult(&w, int(n), int(count)), nil
}

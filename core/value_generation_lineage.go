package core

import "enkv.sh/core/contract"

func generatedFirstCreateIndex(bundle contract.GeneratorPlanBundle) (uint16, bool) {
	for i, lineage := range bundle.Lineages {
		if lineage.Purpose == contract.GeneratorLineageCreate {
			return uint16(i), true
		}
	}
	return 0, false
}

func generatedLineageDefinition(bundle contract.GeneratorPlanBundle, lineage contract.GeneratorLineageTemplate, intent contract.GeneratorLogicalSlice) (contract.GeneratedLineageRecord, error) {
	if lineage.Purpose != contract.GeneratorLineageCreate || intent.ContentKind != contract.GeneratorContentIntent || intent.ContentID != lineage.IntentDigest {
		return contract.GeneratedLineageRecord{}, contract.ErrRecord
	}
	v := contract.GeneratedLineageRecord{Schema: 1, DomainID: lineage.DomainID, OperationID: lineage.OperationID, LineageID: lineage.LineageID,
		IncarnationID: lineage.EntryIncarnationID, Name: lineage.Name, Epoch: lineage.Epoch}
	var err error
	v.Intent, err = contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{intent})
	if err != nil {
		return v, err
	}
	v.Templates, err = contract.GeneratorLineageTemplatesDescriptor([]contract.GeneratorLineageTemplate{lineage})
	if err != nil {
		return v, err
	}
	for _, entryPlan := range bundle.ValueEntryPlans {
		if entryPlan.LineageID == lineage.LineageID {
			v.Membership = entryPlan.IntendedMembership
			return v, nil
		}
	}
	return v, contract.ErrRecord
}

func generatedInitialLineageRows(bundle contract.GeneratorPlanBundle, declaration contract.GeneratorDeclarationView) ([]contract.SupportRecord, error) {
	slices, err := declaration.Slices()
	if err != nil {
		return nil, err
	}
	intents := make(map[contract.ID]contract.GeneratorLogicalSlice)
	for _, slice := range slices {
		if slice.Logical.ContentKind == contract.GeneratorContentIntent {
			intents[slice.Logical.ContentID] = slice.Logical
		}
	}
	var rows []contract.SupportRecord
	for _, lineage := range bundle.Lineages {
		if lineage.Purpose != contract.GeneratorLineageCreate {
			continue
		}
		v, err := generatedLineageDefinition(bundle, lineage, intents[lineage.IntentDigest])
		if err != nil {
			return nil, err
		}
		body, err := contract.EncodeGeneratedLineageRecord(v)
		if err != nil {
			return nil, err
		}
		rows = append(rows, contract.SupportRecord{Kind: contract.GeneratedLineageSupportKind, RecordID: lineage.LineageID, Body: body})
	}
	return rows, nil
}

func (b *generatedSelectionBuilder) validateActiveLineages() error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	g := b.facts
	if g.parent == nil {
		return nil
	}
	entered := make(map[contract.ID]uint8)
	for _, a := range g.attempts {
		if a.record.OperationID == g.parent.OperationID && a.expected.Template.Action == contract.GeneratorActionCreate {
			entered[a.record.LineageID] = max(entered[a.record.LineageID], a.expected.Template.Branch)
		}
	}
	for _, a := range g.releases {
		if a.attempt.OperationID == g.parent.OperationID && a.template.Action == contract.GeneratorActionCreate {
			entered[a.attempt.LineageID] = max(entered[a.attempt.LineageID], a.template.Branch)
		}
	}
	bundle := g.bundles[0]
	for i, lineage := range bundle.Lineages {
		if lineage.Purpose != contract.GeneratorLineageCreate {
			continue
		}
		row, ok := b.claimRecord(contract.GeneratedLineageSupportKind, lineage.LineageID)
		if !ok {
			return contract.ErrRecord
		}
		v, err := contract.DecodeGeneratedLineageRecord(row.Body)
		if err != nil {
			return err
		}
		location, ok := g.content.locations[generatedContentKey{contract.GeneratorContentIntent, lineage.IntentDigest}]
		if !ok {
			return contract.ErrRecord
		}
		want, err := generatedLineageDefinition(bundle, lineage, location.Logical())
		if err != nil {
			return err
		}
		want.Branch, want.Frontier = v.Branch, entered[lineage.LineageID]
		if want.Branch != want.Frontier {
			guard, outcome := uint8(contract.GeneratorGuardResidue), uint8(contract.GeneratedEffectClosedWithResidue)
			if want.Branch == contract.GeneratorBranchNoEffect || want.Branch == contract.GeneratorBranchResidueThenNoEffect {
				guard, outcome = contract.GeneratorGuardQualifiedNoEffect, contract.GeneratedEffectConfirmedNoEffect
			}
			next, present, err := lineage.Templates[want.Frontier].SuccessorBranch(guard)
			if err != nil || !present || next != want.Branch {
				return contract.ErrRecord
			}
			x := lineage.Templates[want.Frontier]
			original := g.attempts[x.AttemptID].record
			if released, ok := g.releases[x.AttemptID]; ok {
				original = released.attempt
			}
			if original.State != outcome || original.Stage != contract.GeneratedStageTerminal {
				return contract.ErrRecord
			}
			if guard == contract.GeneratorGuardResidue {
				row, ok := g.records[generatedRecordKey{contract.GeneratedHazardSupportKind, x.HazardID}]
				if !ok {
					return contract.ErrRecord
				}
				h, err := contract.InspectGeneratedHazardRecord(row.Body)
				if err != nil || h.Fenced != 1 || h.OriginalAttemptID != original.AttemptID || h.OriginalOperationID != original.OperationID {
					return contract.ErrRecord
				}
			}
		}
		if want.Branch == contract.GeneratorBranchNoEffect || want.Branch >= contract.GeneratorBranchNoEffectThenResidue {
			want.NoEffectUsed = 1
		}
		if want.Branch >= contract.GeneratorBranchResidue {
			want.ResidueUsed = 1
		}
		if v != want || int(g.phase.LineageIndex) == i && (g.phase.Branch != v.Branch || g.phase.NoEffectUsed != v.NoEffectUsed || g.phase.ResidueUsed != v.ResidueUsed) {
			return contract.ErrRecord
		}
		if _, err := b.content.readLogical(contract.GeneratorContentIntent, lineage.IntentDigest, v.Intent, contract.GeneratorIntentMaxLength); err != nil {
			return err
		}
	}
	return nil
}

func (b *generatedSelectionBuilder) validateEnteredCreateBranches() error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	g := b.facts
	const noEffectThenResidue uint8 = 1<<contract.GeneratorBranchInitial | 1<<contract.GeneratorBranchNoEffect | 1<<contract.GeneratorBranchNoEffectThenResidue
	const residueThenNoEffect uint8 = 1<<contract.GeneratorBranchInitial | 1<<contract.GeneratorBranchResidue | 1<<contract.GeneratorBranchResidueThenNoEffect
	entered := make(map[contract.ID]uint8)
	include := func(x contract.GeneratorAttemptTemplate) bool {
		if x.Action != contract.GeneratorActionCreate {
			return true
		}
		branches := entered[x.LineageID] | 1<<x.Branch
		// Earlier closed rows may no longer be retained. The remaining set
		// must still fit one path, not a union of reserved alternatives.
		if branches & ^noEffectThenResidue != 0 && branches & ^residueThenNoEffect != 0 {
			return false
		}
		entered[x.LineageID] = branches
		return true
	}
	for _, attempt := range g.attempts {
		if !include(attempt.expected.Template) {
			return contract.ErrRecord
		}
	}
	for _, released := range g.releases {
		if !include(released.template) {
			return contract.ErrRecord
		}
	}
	digests := make(map[contract.ID]contract.ID)
	check := func(lineage, digest contract.ID) bool {
		if digest.IsZero() {
			return false
		}
		if prior, present := digests[lineage]; present && prior != digest {
			return false
		}
		digests[lineage] = digest
		return true
	}
	for _, attempt := range g.attempts {
		if attempt.expected.Template.Action == contract.GeneratorActionCreate && !attempt.record.AttemptID.IsZero() &&
			!check(attempt.record.LineageID, attempt.record.RequestDigest) {
			return contract.ErrRecord
		}
	}
	for _, released := range g.releases {
		if released.template.Action == contract.GeneratorActionCreate && !released.attempt.AttemptID.IsZero() &&
			!check(released.attempt.LineageID, released.attempt.RequestDigest) {
			return contract.ErrRecord
		}
	}
	return nil
}

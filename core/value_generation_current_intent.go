package core

import (
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func (s *StateSession) generatedCurrentIntentSelection(ctx context.Context, selected *generatedSelection,
	plan contract.GeneratorValueEntryPlan, logical contract.GeneratorLogicalSlice) (contract.GeneratedCurrentIntentSelection, error) {
	fail := func() (contract.GeneratedCurrentIntentSelection, error) {
		return contract.GeneratedCurrentIntentSelection{}, contract.ErrRecord
	}
	if s == nil || selected == nil || selected.session != s || selected.content == nil ||
		plan.ValueSource != contract.Generated || plan.ChangeMask&contract.GeneratorValueChangeContent != 0 ||
		!slices.Contains(s.root.Names, format.NameEntry{Name: plan.Name, Slot: plan.Slot}) {
		return fail()
	}
	current := s.valueEntry(plan.Slot)
	if current == nil || current.Name != plan.Name || current.Incarnation != plan.EntryIncarnationID ||
		current.ValueSource != contract.Generated || current.ConfidentialityClass != contract.Secret ||
		current.Generated.Epoch != plan.Epoch || current.Generated.IntentDigest != plan.IntentDigest ||
		current.Generated.RetirementMode != plan.RetirementMode {
		return fail()
	}
	location, ok := selected.content.locations[generatedContentKey{contract.GeneratorContentIntent, plan.IntentDigest}]
	if !ok || location.Logical() != logical {
		return fail()
	}
	body, err := selected.readSelectedSlice(ctx, contract.GeneratorContentIntent, plan.IntentDigest, contract.GeneratorIntentMaxLength)
	if err != nil {
		return contract.GeneratedCurrentIntentSelection{}, err
	}
	id, err := contract.GeneratorIntentDigest(body)
	if err != nil || id != logical.ContentID || uint32(len(body)) != logical.Length || contract.Hash(body) != logical.Digest {
		return fail()
	}
	digest, err := contract.PublicValueEntryDigest(s.root.Domain, plan.Slot, *current)
	if err != nil {
		return fail()
	}
	return contract.GeneratedCurrentIntentSelection{DomainID: s.root.Domain,
		HEADDigest: contract.Hash(s.body), AccessRoot: s.root.CurrentAccess.AccessRoot, Root: s.head.Core.Root,
		HEADRevision: s.head.Core.Revision, HEADToken: s.token,
		Row:         contract.PublicStateRow{Name: current.Name, Slot: plan.Slot, EntryDigest: digest},
		Incarnation: current.Incarnation, Generated: current.Generated, Intent: logical}, nil
}

func (s *StateSession) generatedPlanCurrentIntents(ctx context.Context, graph contract.GeneratorPlanBundle,
	declaration contract.GeneratorDeclarationView) ([]contract.GeneratedCurrentIntentSelection, error) {
	if contract.ValidateGeneratorDeclarationGraph(declaration, graph) != nil {
		return nil, contract.ErrRecord
	}
	logical, err := declaration.LogicalSlices()
	if err != nil {
		return nil, err
	}
	var selected *generatedSelection
	var out []contract.GeneratedCurrentIntentSelection
	for _, plan := range graph.ValueEntryPlans {
		if plan.ValueSource != contract.Generated || plan.ChangeMask&contract.GeneratorValueChangeContent != 0 {
			continue
		}
		if selected == nil {
			selected, err = s.selectedGeneratedWork(ctx)
			if err != nil {
				return nil, err
			}
		}
		index := slices.IndexFunc(logical, func(row contract.GeneratorLogicalSlice) bool {
			return row.ContentKind == contract.GeneratorContentIntent && row.ContentID == plan.IntentDigest
		})
		if index < 0 {
			return nil, contract.ErrRecord
		}
		fact, err := s.generatedCurrentIntentSelection(ctx, selected, plan, logical[index])
		if err != nil {
			return nil, err
		}
		out = append(out, fact)
	}
	return out, nil
}

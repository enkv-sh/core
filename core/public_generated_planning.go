package core

import (
	"bytes"
	"context"
	"slices"
	"strings"

	"enkv.sh/core/contract"
)

type generatedPlanningRetirement struct {
	name                                            string
	duty, incarnation, resource, operation, attempt contract.ID
	epoch                                           uint64
}

func publicEntryNamed(entries []contract.PublicEntry, name string) *contract.PublicEntry {
	at, found := slices.BinarySearchFunc(entries, name, func(row contract.PublicEntry, name string) int { return strings.Compare(row.Name, name) })
	if !found {
		return nil
	}
	return &entries[at]
}

func selectedPlanningEntry(image *selectedImage, name string) *contract.ValueEntry {
	for _, row := range image.root.Names {
		if row.Name == name {
			return image.valueEntry(row.Slot)
		}
	}
	return nil
}

// The domain can retain more than one graph's retirement allowance. Inspect all
// authenticated Duties, but retain only names in this plan's generated union.
func collectGeneratedPlanningRetirements(ctx context.Context, g *generatedSelection, desired PublicConfigurationValidation) ([]generatedPlanningRetirement, error) {
	if !desired.Valid || !desired.Complete || !desired.DiagnosticsComplete {
		return nil, nil
	}
	if g == nil || g.image == nil {
		return nil, contract.ErrRecord
	}
	var out []generatedPlanningRetirement
	for _, record := range g.records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if record.Kind != contract.GeneratedDutySupportKind {
			continue
		}
		duty, err := contract.InspectGeneratedDutyRecord(record.Body)
		if err != nil {
			return nil, err
		}
		if duty.Kind != contract.GeneratedDutyRetirement {
			continue
		}
		target, err := g.retirementTarget(ctx, duty)
		if err != nil {
			return nil, err
		}
		before := selectedPlanningEntry(g.image, target.Name)
		after := publicEntryNamed(desired.Configuration.Entries.Value, target.Name)
		if (before == nil || before.ValueSource != contract.Generated) && (after == nil || after.Source.Value != contract.Generated) {
			continue
		}
		if len(out) == contract.MaxGeneratedPlanningEntries {
			return nil, contract.ErrRecordCapacity
		}
		if out == nil {
			out = make([]generatedPlanningRetirement, 0, min(int(g.image.root.Generated.Retiring), contract.MaxGeneratedPlanningEntries))
		}
		out = append(out, generatedPlanningRetirement{name: strings.Clone(target.Name), duty: duty.DutyID, incarnation: target.IncarnationID,
			resource: target.ResourceID, operation: target.OriginalOperationID, attempt: target.OriginalAttemptID, epoch: target.Epoch})
	}
	slices.SortFunc(out, func(a, b generatedPlanningRetirement) int { return strings.Compare(a.name, b.name) })
	for at := 1; at < len(out); at++ {
		if out[at-1].name == out[at].name {
			return nil, contract.ErrRecord
		}
	}
	return out, nil
}

func generatedPlanningEntries(desired, actual PublicConfigurationValidation, selected *publicSelection, retirements []generatedPlanningRetirement) []contract.GeneratedPlanningEntry {
	if !desired.Valid || !desired.Complete || !actual.Valid || !actual.Complete || !desired.DiagnosticsComplete || !actual.DiagnosticsComplete {
		return nil
	}
	want, before := desired.Configuration.Entries.Value, actual.Configuration.Entries.Value
	count := 0
	for _, rows := range [][]contract.PublicEntry{want, before} {
		for _, entry := range rows {
			if entry.Source.Value == contract.Generated {
				count++
			}
		}
	}
	out := make([]contract.GeneratedPlanningEntry, 0, count)
	i, j := 0, 0
	for i < len(want) || j < len(before) {
		var w, a *contract.PublicEntry
		switch {
		case j == len(before) || i < len(want) && want[i].Name < before[j].Name:
			w = &want[i]
			i++
		case i == len(want) || before[j].Name < want[i].Name:
			a = &before[j]
			j++
		default:
			w, a = &want[i], &before[j]
			i++
			j++
		}
		if (w == nil || w.Source.Value != contract.Generated) && (a == nil || a.Source.Value != contract.Generated) {
			continue
		}
		row := classifyGeneratedPlanningEntry(w, a)
		if selected != nil {
			row.ActiveOperation = selected.image.root.Generated.ActiveOwner
			if !row.ActiveOperation.IsZero() {
				row.Blockers |= contract.GeneratedPlanningActiveOperation
			}
			if current := selectedPlanningEntry(&selected.image, row.Name); current != nil {
				row.CurrentIncarnation = current.Incarnation
				if current.ValueSource == contract.Generated {
					row.CurrentGeneration = current.Generated.GenerationID
					row.CurrentLifecycleMode = current.Generated.LifecycleMode
				}
			}
		}
		if at, found := slices.BinarySearchFunc(retirements, row.Name, func(r generatedPlanningRetirement, name string) int { return strings.Compare(r.name, name) }); found {
			r := retirements[at]
			row.RetiringDutyID, row.RetiringIncarnation, row.RetiringResource = r.duty, r.incarnation, r.resource
			row.RetiringOriginalOperation, row.RetiringOriginalAttempt, row.RetiringEpoch = r.operation, r.attempt, r.epoch
			row.Blockers |= contract.GeneratedPlanningRetiring
		}
		out = append(out, row)
	}
	return out
}

func classifyGeneratedPlanningEntry(w, a *contract.PublicEntry) contract.GeneratedPlanningEntry {
	var row contract.GeneratedPlanningEntry
	if a != nil {
		row.Name, row.CurrentSource, row.CurrentClass = strings.Clone(a.Name), a.Source.Value, a.Class.Value
		if a.Generated != nil {
			row.CurrentEpoch, row.CurrentPolicy = a.Generated.Epoch.Value, a.Generated.Retirement.Value
			row.CurrentLifecycleMode = a.Generated.LifecycleMode.Value
		}
	}
	if w != nil {
		if a == nil {
			row.Name = strings.Clone(w.Name)
		}
		row.ProposedSource, row.ProposedClass = w.Source.Value, w.Class.Value
		if w.Generated != nil {
			row.RequestedEpoch, row.ProposedPolicy = w.Generated.Epoch.Value, w.Generated.Retirement.Value
			row.ProposedLifecycleMode = w.Generated.LifecycleMode.Value
		}
	}
	if w == nil || a == nil {
		row.ChangedFields = contract.GeneratedPlanningPresence
	} else {
		if w.Class.Value != a.Class.Value {
			row.ChangedFields |= contract.GeneratedPlanningClass
		}
		if w.Source.Value != a.Source.Value {
			row.ChangedFields |= contract.GeneratedPlanningSource
		}
		if !slices.Equal(w.Memberships.Value, a.Memberships.Value) {
			row.ChangedFields |= contract.GeneratedPlanningMemberships
		}
		if w.Generated != nil && a.Generated != nil {
			x, y := w.Generated, a.Generated
			for _, change := range []struct {
				differs bool
				bit     uint16
			}{
				{x.Epoch.Value != y.Epoch.Value, contract.GeneratedPlanningEpoch},
				{x.ConfigContractID.Value != y.ConfigContractID.Value, contract.GeneratedPlanningConfigContract},
				{x.ResourceContractID.Value != y.ResourceContractID.Value, contract.GeneratedPlanningResourceContract},
				{x.LifecycleMode.Value != y.LifecycleMode.Value, contract.GeneratedPlanningLifecycle},
				{!bytes.Equal(x.ContentIntent.Value, y.ContentIntent.Value), contract.GeneratedPlanningContentIntent},
				{x.Retirement.Value != y.Retirement.Value, contract.GeneratedPlanningRetirementPolicy},
				{x.Completion.Value != y.Completion.Value, contract.GeneratedPlanningCompletion},
			} {
				if change.differs {
					row.ChangedFields |= change.bit
				}
			}
		}
	}
	row.Action, row.Retirement, row.Blockers = contract.ClassifyGeneratedPlanningEntry(row)
	return row
}

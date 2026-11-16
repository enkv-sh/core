package core

import (
	"slices"
	"strings"

	"enkv.sh/core/contract"
)

type sealedInputBindingError struct{ name string }

func (e *sealedInputBindingError) Error() string { return "sealed input recipient binding refused" }
func (e *sealedInputBindingError) Unwrap() error { return contract.ErrRecord }

func staleSealedInputBindingDiagnostic(name string) contract.Diagnostic {
	return contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: strings.Clone(name)}, Path: []contract.DiagnosticField{contract.FieldSource}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonStaleSealedInputBinding}
}

func refuseSealedInputBinding(name string, diagnostic **contract.Diagnostic) Result {
	if diagnostic != nil {
		row := staleSealedInputBindingDiagnostic(name)
		*diagnostic = &row
	}
	return refused(InvalidIntent)
}

// ChangedSubjectCommitment is the bounded audit anchor. The transient subject
// rows contain no names or value material and do not escape the operation.
type ChangedSubjectCommitment struct {
	Count              uint32
	IdentityRootDigest contract.ID
}

type TransitionPayload struct {
	PredecessorRevisionID, RequestedRevisionID, ObservedRevisionID contract.ID
	ChangedSubjects                                                ChangedSubjectCommitment
	LiveDutyIDs, LiveHazardIDs                                     []contract.ID
}

func installedApplyChangedSubjects(c *Comparison, p transitionPlan) (contract.GeneratorDescriptor, error) {
	if c == nil || c.session == nil || len(c.slots) != len(c.desiredEntries) {
		return contract.GeneratorDescriptor{}, contract.ErrRecord
	}
	s := c.session
	rows := make([]contract.ChangedSubjectIdentity, 0)
	appendRow := func(kind, change uint8, primary, secondary contract.ID) error {
		if len(rows) == contract.MutationChangedSubjectLimit {
			return contract.ErrRecordCapacity
		}
		id, err := contract.ChangedSubjectIdentityID(s.root.Domain, kind, primary, secondary)
		if err != nil {
			return err
		}
		rows = append(rows, contract.ChangedSubjectIdentity{Kind: kind, Change: change, Identity: id})
		return nil
	}
	for _, slot := range c.removed {
		before := s.valueEntry(slot)
		if before == nil || before.ValueSource != contract.Supplied && before.ValueSource != contract.Generated {
			return contract.GeneratorDescriptor{}, contract.ErrRecord
		}
		if err := appendRow(contract.ChangedSubjectValueEntry, contract.ChangedSubjectRemoved, before.Incarnation, contract.ID{}); err != nil {
			return contract.GeneratorDescriptor{}, err
		}
		if before.ValueSource == contract.Generated {
			if err := appendRow(contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectRemoved, before.Generated.GenerationID, contract.ID{}); err != nil {
				return contract.GeneratorDescriptor{}, err
			}
		}
		for _, recipient := range before.Recipients {
			if err := appendRow(contract.ChangedSubjectMembership, contract.ChangedSubjectRemoved, before.Incarnation, recipient); err != nil {
				return contract.GeneratorDescriptor{}, err
			}
		}
	}
	for i, entry := range c.desiredEntries {
		slot := c.slots[i]
		before := s.valueEntry(slot)
		if !slices.Contains(c.changed, slot) && (before == nil || before.OutputEncoding == entry.OutputEncoding) {
			continue
		}
		if entry.ValueSource != contract.Supplied && entry.ValueSource != contract.Generated {
			return contract.GeneratorDescriptor{}, contract.ErrRecord
		}
		incarnation := p.incarnations[slot]
		added := slices.Contains(c.added, slot)
		if added {
			before = nil
		} else if before == nil {
			return contract.GeneratorDescriptor{}, contract.ErrRecord
		} else if incarnation.IsZero() {
			if before.ValueSource != entry.ValueSource {
				return contract.GeneratorDescriptor{}, contract.ErrRecord
			}
			incarnation = before.Incarnation
		}
		if incarnation.IsZero() {
			return contract.GeneratorDescriptor{}, contract.ErrRecord
		}
		change := uint8(contract.ChangedSubjectUpdated)
		if before == nil || before.Incarnation != incarnation {
			change = contract.ChangedSubjectAdded
		}
		if before != nil && before.Incarnation != incarnation {
			if err := appendRow(contract.ChangedSubjectValueEntry, contract.ChangedSubjectRemoved, before.Incarnation, contract.ID{}); err != nil {
				return contract.GeneratorDescriptor{}, err
			}
			if before.ValueSource == contract.Generated && entry.ValueSource != contract.Generated {
				if err := appendRow(contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectRemoved, before.Generated.GenerationID, contract.ID{}); err != nil {
					return contract.GeneratorDescriptor{}, err
				}
			}
		}
		if err := appendRow(contract.ChangedSubjectValueEntry, change, incarnation, contract.ID{}); err != nil {
			return contract.GeneratorDescriptor{}, err
		}
		if entry.ValueSource == contract.Generated {
			if before == nil || before.Generated.GenerationID.IsZero() {
				return contract.GeneratorDescriptor{}, contract.ErrRecord
			}
			next := before.Generated.GenerationID
			if fresh, ok := p.values[slot]; ok {
				next = fresh
			}
			if next != before.Generated.GenerationID {
				if err := appendRow(contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectRemoved, before.Generated.GenerationID, contract.ID{}); err != nil {
					return contract.GeneratorDescriptor{}, err
				}
				if err := appendRow(contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectAdded, next, contract.ID{}); err != nil {
					return contract.GeneratorDescriptor{}, err
				}
			} else if err := appendRow(contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectUpdated, next, contract.ID{}); err != nil {
				return contract.GeneratorDescriptor{}, err
			}
		}
		if before != nil {
			for _, recipient := range before.Recipients {
				if before.Incarnation != incarnation || !slices.Contains(entry.Recipients, recipient) {
					if err := appendRow(contract.ChangedSubjectMembership, contract.ChangedSubjectRemoved, before.Incarnation, recipient); err != nil {
						return contract.GeneratorDescriptor{}, err
					}
				}
			}
		}
		for _, recipient := range entry.Recipients {
			if before == nil || before.Incarnation != incarnation || !slices.Contains(before.Recipients, recipient) {
				if err := appendRow(contract.ChangedSubjectMembership, contract.ChangedSubjectAdded, incarnation, recipient); err != nil {
					return contract.GeneratorDescriptor{}, err
				}
			}
		}
	}
	for _, id := range c.recipientChanges {
		change := uint8(contract.ChangedSubjectUpdated)
		if c.retirement != nil && c.retirement.RecipientID == id {
			change = contract.ChangedSubjectRemoved
		} else if s.recipientRecord(id) == nil {
			change = contract.ChangedSubjectAdded
		}
		if err := appendRow(contract.ChangedSubjectRecipient, change, id, contract.ID{}); err != nil {
			return contract.GeneratorDescriptor{}, err
		}
	}
	if c.outputChanged {
		if c.outputAfter == nil || c.outputAfter.transition == nil {
			return contract.GeneratorDescriptor{}, contract.ErrRecord
		}
		before := c.outputAfter.transition.Before
		after, _, _, err := c.outputAfter.transition.ConfigurationAfter(identityPlan(c, p))
		if err != nil {
			return contract.GeneratorDescriptor{}, err
		}
		output, err := contract.OutputConfigurationChangedSubjects(before, after)
		if err != nil {
			return contract.GeneratorDescriptor{}, err
		}
		rows = append(rows, output...)
	}
	return contract.ChangedSubjectDescriptor(rows)
}

type installedApplyRetainedWork struct {
	duties, hazards    contract.GeneratorDescriptor
	dutyIDs, hazardIDs []contract.ID
	relatedDutyRows    []contract.SupportRecord
}

func (c *Comparison) retainedWorkResult(p transitionPlan) (installedApplyRetainedWork, error) {
	var result installedApplyRetainedWork
	var duties, hazards []contract.SupportRecord
	after, err := generatedNormalSupportRows(c, p)
	if err != nil {
		return result, err
	}
	for start := 0; start < len(after.Records); {
		end := start + 1
		kind := after.Records[start].Kind
		for end < len(after.Records) && after.Records[end].Kind == kind {
			end++
		}
		switch kind {
		case contract.GeneratedDutySupportKind:
			duties = after.Records[start:end]
			for _, row := range duties {
				result.dutyIDs = append(result.dutyIDs, row.RecordID)
			}
		case contract.GeneratedHazardSupportKind:
			hazards = after.Records[start:end]
			for _, row := range hazards {
				result.hazardIDs = append(result.hazardIDs, row.RecordID)
			}
		}
		start = end
	}
	result.duties, err = contract.MutationResultRecordDescriptor(contract.MutationResultDuties, c.session.root.Domain, duties)
	if err != nil {
		return result, err
	}
	result.hazards, err = contract.MutationResultRecordDescriptor(contract.MutationResultHazards, c.session.root.Domain, hazards)
	if err != nil {
		return result, err
	}
	expectedDuties := c.session.root.Generated.Duties
	if c.support != nil {
		expectedDuties += uint32(len(c.support.Handoffs))
	}
	if result.duties.Count != expectedDuties || result.hazards.Count != c.session.root.Generated.Hazards {
		return result, contract.ErrRecord
	}
	if c.support != nil {
		for _, handoff := range c.support.Handoffs {
			if int(handoff.Current) >= len(c.support.CurrentGenerated) {
				return result, contract.ErrRecord
			}
			entry, err := contract.InspectValueEntry(c.support.CurrentGenerated[handoff.Current].EntryBytes)
			if err != nil {
				return result, err
			}
			id, err := contract.GeneratorDutyID(c.session.root.Domain, entry.Generated.OriginOperationID, entry.Generated.OriginAttemptID, contract.GeneratedDutyRetirement)
			if err != nil {
				return result, err
			}
			at := slices.IndexFunc(duties, func(row contract.SupportRecord) bool { return row.RecordID == id })
			if at < 0 {
				return result, contract.ErrRecord
			}
			duty, err := contract.InspectGeneratedDutyRecord(duties[at].Body)
			if err != nil || duty.Kind != contract.GeneratedDutyRetirement || duty.OriginalOperationID != entry.Generated.OriginOperationID ||
				duty.OriginalAttemptID != entry.Generated.OriginAttemptID || duty.ResourceID != entry.Generated.ResourceIncarnationID {
				return result, contract.ErrRecord
			}
			result.relatedDutyRows = append(result.relatedDutyRows, duties[at])
		}
	}
	if result.dutyIDs == nil {
		result.dutyIDs = []contract.ID{}
	}
	if result.hazardIDs == nil {
		result.hazardIDs = []contract.ID{}
	}
	return result, nil
}

// The selected session already authenticated these fixed support identities.
// A failed selection must not expose the proposed successor's work inventory.
func installedApplyObservedWorkIDs(s *StateSession) ([]contract.ID, []contract.ID) {
	duties, hazards := []contract.ID{}, []contract.ID{}
	for _, page := range s.support {
		for _, row := range page.Records {
			switch row.Kind {
			case contract.GeneratedDutySupportKind:
				duties = append(duties, row.RecordID)
			case contract.GeneratedHazardSupportKind:
				hazards = append(hazards, row.RecordID)
			}
		}
	}
	slices.SortFunc(duties, compareGeneratedIDs)
	slices.SortFunc(hazards, compareGeneratedIDs)
	return duties, hazards
}

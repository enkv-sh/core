package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
)

// This projection uses checked content relations, independently of material
// freshness, encoded-entry differences and membership differences.
func comparisonObservation(c *Comparison) changeObservation {
	out := changeObservation{Source: observationSource{Stage: observationComparison}}
	if c.operation != nil {
		out.Source = c.operation.source
		out.Source.Stage = observationComparison
	}
	count := len(c.session.root.Names) + len(c.desiredEntries)
	out.Entries = make([]observationEntry, 0, count)
	out.Names = make([]observationName, 0, count)
	memberships := 0
	for _, named := range c.session.root.Names {
		memberships += len(c.session.valueEntry(named.Slot).Recipients)
	}
	for _, entry := range c.desiredEntries {
		memberships += len(entry.Recipients)
	}
	out.Memberships = make([]observationMembership, 0, memberships)
	for beforeIndex, afterIndex, rowIndex := 0, 0, 0; beforeIndex < len(c.session.root.Names) || afterIndex < len(c.desiredEntries); {
		var prior *contract.ValueEntry
		var next ApplyEntryInput
		var name string
		present := false
		if beforeIndex < len(c.session.root.Names) {
			name = c.session.root.Names[beforeIndex].Name
		}
		if afterIndex < len(c.desiredEntries) && (beforeIndex == len(c.session.root.Names) || c.desiredEntries[afterIndex].Name < name) {
			name = c.desiredEntries[afterIndex].Name
		}
		if beforeIndex < len(c.session.root.Names) && c.session.root.Names[beforeIndex].Name == name {
			prior = c.session.valueEntry(c.session.root.Names[beforeIndex].Slot)
			beforeIndex++
		}
		if afterIndex < len(c.desiredEntries) && c.desiredEntries[afterIndex].Name == name {
			next = c.desiredEntries[afterIndex]
			present = true
			afterIndex++
		}
		entry := observationEntry{BeforePresent: prior != nil, AfterPresent: present}
		if prior != nil {
			entry.BeforeIncarnationID, entry.BeforeSource, entry.BeforeConfidentiality = prior.Incarnation, prior.ValueSource, prior.ConfidentialityClass
			out.Names = append(out.Names, observationName{EntryIncarnationID: prior.Incarnation, Name: name, Side: observationBefore})
		}
		if present {
			entry.AfterSource, entry.AfterConfidentiality = next.ValueSource, next.ConfidentialityClass
			if prior != nil && prior.ValueSource == next.ValueSource {
				entry.AfterIncarnationID = prior.Incarnation
				out.Names = append(out.Names, observationName{EntryIncarnationID: prior.Incarnation, Name: name, Side: observationAfter})
			} else {
				entry.ProposedName = name
			}
		}
		if prior != nil && present {
			if prior.ConfidentialityClass == contract.Plain {
				entry.Relation = observationChanged
				if bytes.Equal(prior.ValueBytes, next.InputBytes) {
					entry.Relation = observationEqual
				}
			} else {
				for rowIndex < len(c.secretRows) && c.secretRows[rowIndex].Name < name {
					rowIndex++
				}
				if rowIndex < len(c.secretRows) && c.secretRows[rowIndex].Name == name {
					switch c.secretRows[rowIndex].Relation {
					case contract.CryptoEqual:
						entry.Relation = observationEqual
					case contract.CryptoChanged:
						entry.Relation = observationChanged
					}
				}

			}
		}
		index := uint16(len(out.Entries))
		out.Entries = append(out.Entries, entry)
		if prior != nil {
			for _, recipient := range prior.Recipients {
				if !present || entry.AfterIncarnationID.IsZero() || !slices.Contains(next.Recipients, recipient) {
					out.Memberships = append(out.Memberships, observationMembership{EntryIncarnationID: prior.Incarnation, RecipientID: recipient, Change: contract.ChangedSubjectRemoved})
				}
			}
		}
		if present {
			for _, recipient := range next.Recipients {
				if prior == nil || entry.AfterIncarnationID.IsZero() || !slices.Contains(prior.Recipients, recipient) {
					out.Memberships = append(out.Memberships, observationMembership{EntryIncarnationID: entry.AfterIncarnationID, EntryIndex: index, RecipientID: recipient, Change: contract.ChangedSubjectAdded})
				}
			}
		}
	}
	return out
}

// Candidate fields describe the validated image, not a checked content relation
// or proof that the image became selected.
func ordinaryCandidateObservation(before, after *StateSession) changeObservation {
	count := len(before.root.Names) + len(after.root.Names)
	out := changeObservation{Entries: make([]observationEntry, 0, count), Names: make([]observationName, 0, count)}
	for oldIndex, newIndex := 0, 0; oldIndex < len(before.root.Names) || newIndex < len(after.root.Names); {
		var prior, next *contract.ValueEntry
		var name string
		if oldIndex < len(before.root.Names) {
			name = before.root.Names[oldIndex].Name
		}
		if newIndex < len(after.root.Names) && (oldIndex == len(before.root.Names) || after.root.Names[newIndex].Name < name) {
			name = after.root.Names[newIndex].Name
		}
		if oldIndex < len(before.root.Names) && before.root.Names[oldIndex].Name == name {
			prior = before.valueEntry(before.root.Names[oldIndex].Slot)
			oldIndex++
		}
		if newIndex < len(after.root.Names) && after.root.Names[newIndex].Name == name {
			next = after.valueEntry(after.root.Names[newIndex].Slot)
			newIndex++
		}
		entry := observationEntry{BeforePresent: prior != nil, AfterPresent: next != nil, Fields: entryObservationFields(prior, next)}
		if prior != nil {
			entry.BeforeIncarnationID, entry.BeforeSource, entry.BeforeConfidentiality = prior.Incarnation, prior.ValueSource, prior.ConfidentialityClass
			out.Names = append(out.Names, observationName{EntryIncarnationID: prior.Incarnation, Name: name, Side: observationBefore})
		}
		if next != nil {
			entry.AfterIncarnationID, entry.AfterSource, entry.AfterConfidentiality = next.Incarnation, next.ValueSource, next.ConfidentialityClass
			out.Names = append(out.Names, observationName{EntryIncarnationID: next.Incarnation, Name: name, Side: observationAfter})
		}
		out.Entries = append(out.Entries, entry)
	}
	return out
}

func entryObservationFields(before, after *contract.ValueEntry) observationFields {
	if before == nil || after == nil || before.Incarnation != after.Incarnation {
		fields := observationFieldSource | observationFieldConfidentiality | observationFieldMembership | observationFieldEncodedMaterial
		if before != nil && before.ValueSource == contract.Generated || after != nil && after.ValueSource == contract.Generated {
			fields |= observationFieldGeneration
		}
		return fields
	}
	var fields observationFields
	if before.ValueSource != after.ValueSource {
		fields |= observationFieldSource
	}
	if before.ConfidentialityClass != after.ConfidentialityClass {
		fields |= observationFieldConfidentiality
	}
	if !slices.Equal(before.Recipients, after.Recipients) {
		fields |= observationFieldMembership
	}
	if before.ValueState != after.ValueState || before.OriginSnapshot != after.OriginSnapshot || before.OriginTransition != after.OriginTransition || !bytes.Equal(before.ValueBytes, after.ValueBytes) {
		fields |= observationFieldEncodedMaterial
	}
	if before.Generated != after.Generated {
		fields |= observationFieldGeneration
	}
	return fields
}

// Generation metadata and plan intent are separate source facts. Supplied
// plans and retained generated plans need not allocate a generation ID.
func addGeneratedPlanObservation(out *changeObservation, bundle contract.GeneratorPlanBundle) {
	count := 0
	for _, plan := range bundle.ValueEntryPlans {
		if plan.ChangeMask != 0 {
			count++
		}
	}
	rows := make([]observationGeneration, len(out.Generations), len(out.Generations)+count)
	copy(rows, out.Generations)
	out.Generations = rows
	for _, plan := range bundle.ValueEntryPlans {
		if plan.ChangeMask == 0 {
			continue
		}
		out.Generations = append(out.Generations, observationGeneration{EntryIncarnationID: plan.EntryIncarnationID, PlanID: bundle.UsePlan.PlanGraphID, Side: observationAfter,
			PlannedContent: plan.ChangeMask&contract.GeneratorValueChangeContent != 0, PlannedMembership: plan.ChangeMask&contract.GeneratorValueChangeMembership != 0, PlannedRetirement: plan.ChangeMask&contract.GeneratorValueChangeRetirement != 0})
	}
}

func candidateObservationIdentity(candidate *Candidate) observationCandidateIdentity {
	return observationCandidateIdentity{RevisionID: candidate.head.Core.Revision, SnapshotID: candidate.head.Core.Root.Object, PredecessorRevisionID: candidate.session.head.Core.Revision, PredecessorDigest: contract.Hash(candidate.session.body)}
}

func generatedObservationOriginal(detail *changeObservation, request contract.GeneratorRequestCore, attempt contract.GeneratedAttemptRecord) {
	detail.Source.ParentID, detail.Source.AttemptID = attempt.OperationID, attempt.AttemptID

}

// Candidate ownership is fixed at its enclosing preparation, including when
// that operation has no observer. A later producer cannot redirect it.
func (c *Candidate) bindObservation(owner *operationObservation, source observationSource) {
	if c == nil || c.observationBound {
		return
	}
	c.observationBound = true
	if owner == nil || c.session == nil || !owner.sourceMatches(source) || owner.source.DomainID != c.session.admission.domain {
		return
	}
	c.observation, c.observationSource = owner, owner.sourceFor(source)
}

func (s *StateSession) candidateObservationReady(c *Candidate) bool {
	return s != nil && c != nil && c.session == s && !c.used && len(c.body) != 0 && c.observation.enabled() && s.admission.valid(s.store) && c.observation.source.DomainID == s.admission.domain
}

func (c *Candidate) offerSelection(ctx context.Context, result Result) {
	source := c.observationSource
	source.Stage = observationSelection
	c.observation.offerChange(ctx, changeObservation{Source: source, Candidate: candidateObservationIdentity(c), Result: result})
}

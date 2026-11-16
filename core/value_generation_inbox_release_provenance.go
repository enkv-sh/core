package core

import (
	"bytes"

	"enkv.sh/core/contract"
)

type generatedReleasedAttempt struct {
	attempt  contract.GeneratedAttemptRecord
	template contract.GeneratorAttemptTemplate
	release  contract.PendingInboxReleaseRecord
}

func generatedInboxAttempts(rows []contract.SupportRecord) (map[contract.ID]contract.ID, error) {
	inboxes := make(map[contract.ID]contract.ID)
	for _, row := range rows {
		if row.Kind != contract.GeneratedAttemptSupportKind {
			continue
		}
		a, err := contract.InspectGeneratedAttemptRecord(row.Body)
		if err != nil || !inboxes[a.InboxID].IsZero() {
			return nil, contract.ErrRecord
		}
		inboxes[a.InboxID] = a.AttemptID
	}
	return inboxes, nil
}

func (b *generatedSelectionBuilder) resolveInboxReleases(rows []contract.SupportRecord) error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	g := b.facts
	inboxes, err := generatedInboxAttempts(rows)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.Kind != contract.PendingInboxReleaseSupportKind {
			continue
		}
		r, err := contract.InspectPendingInboxReleaseRecord(row.Body)
		if err != nil || r.DomainID != g.image.root.Domain {
			return contract.ErrRecord
		}
		attempt := inboxes[r.InboxID]
		if _, adoptable := g.attempts[attempt]; adoptable {
			return contract.ErrRecord
		}
		if _, retained := g.records[generatedRecordKey{contract.GeneratedResultSupportKind, r.OriginalResultID}]; retained {
			return contract.ErrRecord
		}
		original, ok := b.claimRecord(contract.GeneratedAttemptSupportKind, attempt)
		if !ok {
			return contract.ErrRecord
		}
		a, err := contract.InspectGeneratedAttemptRecord(original.Body)
		if err != nil || a.DomainID != r.DomainID || a.InboxID != r.InboxID || a.ResultID != r.OriginalResultID ||
			a.Stage != contract.GeneratedStageTerminal || a.RetryUsed != 0 {
			return contract.ErrRecord
		}
		bundle, err := b.retainedGraph(a.OperationID)
		if err != nil {
			return err
		}
		if bundle.Header.DomainID != a.DomainID {
			return contract.ErrRecord
		}
		x, use, ok := generatedTemplate(bundle, a.AttemptID)
		if !ok || !generatedAttemptMatches(a, x) {
			return contract.ErrRecord
		}
		if r.State == contract.GeneratedReleaseUnobserved {
			if x.Action != contract.GeneratorActionDelete || a.State != contract.GeneratedEffectUnknown && a.State != contract.GeneratedEffectClosedWithResidue || a.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) {
				return contract.ErrRecord
			}
			original := generatedAttempt{record: a, expected: contract.GeneratorResultExpectation{Template: x, Use: use}}
			if b.validateDeleteHistory(original, contract.GeneratedAttemptSupportKind, a.AttemptID, a.History) != nil {
				return contract.ErrRecord
			}
			facts, err := b.vectors.resolve(contract.GeneratedAttemptSupportKind, a.AttemptID, contract.GeneratorVectorFacts, a.Facts)
			if err != nil || len(facts) > 1 || a.State == contract.GeneratedEffectUnknown && len(facts) != 1 {
				return contract.ErrRecord
			}
			for _, body := range facts {
				row, err := contract.InspectGeneratorFactsRow(body)
				fact, factErr := contract.InspectGeneratorSafeFacts(row.Facts)
				if err != nil || factErr != nil || row.ResultID != a.ResultID || uint32(len(row.Facts)) > use.MaxFacts ||
					fact.Disposition != contract.GeneratorDispositionUnknown || fact.Reason == contract.GeneratorReasonIdentityConflict || !generatedFactsMatchTemplate(fact.GeneratorSafeFacts, x) || fact.RequestDigest != a.RequestDigest || fact.IntentDigest != x.IntentDigest {
					return contract.ErrRecord
				}
			}
		} else if x.Action == contract.GeneratorActionDelete && a.CompletionClass == contract.GeneratedCompletionConfirmed {
			facts, err := b.vectors.resolve(contract.GeneratedAttemptSupportKind, a.AttemptID, contract.GeneratorVectorFacts, a.Facts)
			if err != nil || len(facts) != 1 {
				return contract.ErrRecord
			}
			row, err := contract.InspectGeneratorFactsRow(facts[0])
			if err != nil || row.ResultID != a.ResultID {
				return contract.ErrRecord
			}
			fact, err := contract.InspectGeneratorSafeFacts(row.Facts)
			if err != nil || !generatedFactsMatchTemplate(fact.GeneratorSafeFacts, x) || fact.RequestDigest != a.RequestDigest || fact.IntentDigest != x.IntentDigest || fact.Disposition != contract.GeneratorDispositionRetirementAcknowledged && fact.Disposition != contract.GeneratorDispositionScopedUnusability {
				return contract.ErrRecord
			}
			if fact.Disposition == contract.GeneratorDispositionScopedUnusability && fact.ScopeID != contract.GeneratorControlledRetirementScope(x.DescriptorID, x.ConfigContractID, x.ResultContractID) {
				return contract.ErrRecord
			}
			progress, err := b.vectors.resolve(contract.GeneratedAttemptSupportKind, a.AttemptID, contract.GeneratorVectorProgress, a.Progress)
			if err != nil || fact.Disposition == contract.GeneratorDispositionRetirementAcknowledged && len(progress) != 0 ||
				fact.Disposition == contract.GeneratorDispositionScopedUnusability && len(progress) != 1 {
				return contract.ErrRecord
			}
			if len(progress) == 1 {
				ack, err := contract.InspectGeneratorProgress(progress[0])
				if err != nil {
					return err
				}
				var operation contract.ID
				for key := range b.content.facts.locations {
					if key.kind != contract.GeneratorContentGraph {
						continue
					}
					graph, err := b.content.validatedGraph(key.id)
					if err != nil {
						return err
					}
					if _, _, present := generatedTemplate(graph.bundle, ack.AttemptID); present {
						if !operation.IsZero() {
							return contract.ErrRecord
						}
						operation = graph.bundle.Header.OperationID
					}
				}
				if operation.IsZero() {
					return contract.ErrRecord
				}
				if _, err := b.retainedGraph(operation); err != nil {
					return err
				}
			}
			if a.State == contract.GeneratedEffectSucceeded {
				if a.History != contract.EmptyGeneratorVector(contract.GeneratorVectorHistory) {
					return contract.ErrRecord
				}
			} else {
				if a.State != contract.GeneratedEffectUnknown && a.State != contract.GeneratedEffectClosedWithResidue ||
					b.validateDeleteHistory(generatedAttempt{record: a}, contract.GeneratedAttemptSupportKind, a.AttemptID, a.History) != nil {
					return contract.ErrRecord
				}
			}
		} else if a.SemanticLifecycleMode() == contract.GeneratorLifecycleNone {
			if a.Schema != contract.GeneratedAttemptRecordSchema || x.Schema != contract.GeneratorAttemptTemplateSchema ||
				x.Action != contract.GeneratorActionCreate || x.Branch != contract.GeneratorBranchInitial ||
				!a.PredecessorAttemptID.IsZero() || a.State != contract.GeneratedEffectSucceeded || a.FailureReason != 0 ||
				a.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) || a.Facts != contract.EmptyGeneratorVector(contract.GeneratorVectorFacts) ||
				a.History != contract.EmptyGeneratorVector(contract.GeneratorVectorHistory) {
				return contract.ErrRecord
			}
		} else if a.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) || a.Facts != contract.EmptyGeneratorVector(contract.GeneratorVectorFacts) ||
			a.History != contract.EmptyGeneratorVector(contract.GeneratorVectorHistory) ||
			a.State != contract.GeneratedEffectSucceeded && a.State != contract.GeneratedEffectFailedTerminal && a.State != contract.GeneratedEffectClosedWithResidue &&
				(a.State != contract.GeneratedEffectConfirmedNoEffect || x.Action != contract.GeneratorActionCreate) {
			return contract.ErrRecord
		}
		// Release provenance is authenticated selected data. It is not a live
		// result consumer and cannot reopen private custody or an inbox reader.
		b.claimRecord(contract.PendingInboxReleaseSupportKind, r.InboxID)
		g.releases[a.AttemptID] = generatedReleasedAttempt{attempt: a, template: x, release: r}
	}
	for _, released := range g.releases {
		if released.template.Action == contract.GeneratorActionDelete && released.attempt.CompletionClass == contract.GeneratedCompletionConfirmed && released.release.State != contract.GeneratedReleaseUnobserved {
			if _, err := g.controlledReleasedProgress(released); err != nil {
				return err
			}
		}
	}
	return nil
}

// This projection is historical selected evidence. It has no result packet,
// seed access, inbox reader or new dispatch/adoption authority.
func (g *generatedSelection) controlledReleasedProgress(a generatedReleasedAttempt) ([][]byte, error) {
	facts, err := g.vectors.resolve(contract.GeneratedAttemptSupportKind, a.attempt.AttemptID, contract.GeneratorVectorFacts, a.attempt.Facts)
	if err != nil || len(facts) != 1 {
		return nil, contract.ErrRecord
	}
	row, err := contract.InspectGeneratorFactsRow(facts[0])
	if err != nil || row.ResultID != a.attempt.ResultID {
		return nil, contract.ErrRecord
	}
	f, err := contract.InspectGeneratorSafeFacts(row.Facts)
	if err != nil {
		return nil, err
	}
	resourceDigest, err := contract.GeneratorResourceDigest(f.GeneratorSafeFacts)
	if err != nil {
		return nil, err
	}
	encode := func(x generatedReleasedAttempt, mask uint8) ([]byte, error) {
		return contract.EncodeGeneratorProgress(contract.GeneratorProgress{Schema: 1, AttemptID: x.attempt.AttemptID, ResultID: x.attempt.ResultID, Evidence: contract.GeneratorDescriptor{Digest: x.release.SelectedHandoffDigest, Length: uint64(x.release.ObjectLength), Count: 1}, RequiredSteps: contract.GeneratorConfirmedRequiredSteps, CompletedSteps: mask, CompletionClass: contract.GeneratedCompletionConfirmed})
	}
	if f.Disposition == contract.GeneratorDispositionRetirementAcknowledged {
		body, err := encode(a, contract.GeneratorProgressAcknowledged)
		return [][]byte{body}, err
	}
	if f.Disposition != contract.GeneratorDispositionScopedUnusability || f.ScopeID != contract.GeneratorControlledRetirementScope(a.template.DescriptorID, a.template.ConfigContractID, a.template.ResultContractID) ||
		f.ObservedResourceID != a.template.ResourceIncarnationID || f.ObservedResourceDigest != resourceDigest || f.ObservedScopeID != f.ScopeID ||
		a.attempt.RequestDigest != contract.GeneratorControlledRetirementProbeDigest(a.attempt.DomainID, a.attempt.ResourceID, resourceDigest, f.ScopeID, f.PrecedingResultID, f.PrecedingResultBodyDigest) {
		return nil, contract.ErrRecord
	}
	retained, err := g.vectors.resolve(contract.GeneratedAttemptSupportKind, a.attempt.AttemptID, contract.GeneratorVectorProgress, a.attempt.Progress)
	if err != nil || len(retained) != 1 {
		return nil, contract.ErrRecord
	}
	ack, err := contract.InspectGeneratorProgress(retained[0])
	if err != nil || ack.ResultID != f.PrecedingResultID || ack.Evidence.Digest != f.PrecedingResultBodyDigest ||
		ack.RequiredSteps != contract.GeneratorConfirmedRequiredSteps || ack.CompletedSteps != contract.GeneratorProgressAcknowledged || ack.CompletionClass != contract.GeneratedCompletionConfirmed {
		return nil, contract.ErrRecord
	}
	matched := false
	for _, bundle := range g.bundles {
		for _, lineage := range bundle.Lineages {
			for _, x := range lineage.Templates[:lineage.TemplateCount] {
				if x.AttemptID != ack.AttemptID {
					continue
				}
				if matched || x.Action != contract.GeneratorActionDelete || x.ResultID != ack.ResultID || x.DutyID != a.attempt.OwnerID ||
					x.ResourceIncarnationID != a.attempt.ResourceID || x.ConfigContractID != a.attempt.ConfigContractID || x.ResourceContractID != a.attempt.ResourceContractID ||
					x.ResultContractID != a.attempt.ResultContractID || x.CompletionClass != a.attempt.CompletionClass {
					return nil, contract.ErrRecord
				}
				matched = true
			}
		}
	}
	if !matched {
		return nil, contract.ErrRecord
	}
	var predecessor generatedReleasedAttempt
	for _, p := range g.releases {
		if p.attempt.ResultID == f.PrecedingResultID {
			if !predecessor.attempt.AttemptID.IsZero() {
				return nil, contract.ErrRecord
			}
			predecessor = p
		}
	}
	if !predecessor.attempt.AttemptID.IsZero() {
		if predecessor.release.State == contract.GeneratedReleaseUnobserved || predecessor.release.SelectedHandoffDigest != f.PrecedingResultBodyDigest ||
			predecessor.attempt.OwnerID != a.attempt.OwnerID || predecessor.attempt.ResourceID != a.attempt.ResourceID || predecessor.attempt.ConfigContractID != a.attempt.ConfigContractID || predecessor.attempt.ResourceContractID != a.attempt.ResourceContractID || predecessor.attempt.ResultContractID != a.attempt.ResultContractID || predecessor.attempt.CompletionClass != a.attempt.CompletionClass {
			return nil, contract.ErrRecord
		}
		priorFacts, err := g.vectors.resolve(contract.GeneratedAttemptSupportKind, predecessor.attempt.AttemptID, contract.GeneratorVectorFacts, predecessor.attempt.Facts)
		if err != nil || len(priorFacts) != 1 {
			return nil, contract.ErrRecord
		}
		priorRow, err := contract.InspectGeneratorFactsRow(priorFacts[0])
		if err != nil {
			return nil, err
		}
		prior, err := contract.InspectGeneratorSafeFacts(priorRow.Facts)
		if err != nil || prior.Disposition != contract.GeneratorDispositionRetirementAcknowledged || !generatedResourceFactsMatch(prior.GeneratorSafeFacts, resourceDigest) || a.attempt.RequestDigest != contract.GeneratorControlledRetirementProbeDigest(a.attempt.DomainID, a.attempt.ResourceID, resourceDigest, f.ScopeID, predecessor.attempt.ResultID, predecessor.release.SelectedHandoffDigest) {
			return nil, contract.ErrRecord
		}
		first, err := encode(predecessor, contract.GeneratorProgressAcknowledged)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(first, retained[0]) {
			return nil, contract.ErrRecord
		}
	}
	first := retained[0]
	last, err := encode(a, contract.GeneratorProgressConfirmed)
	if err != nil {
		return nil, err
	}
	if bytes.Compare(first[2:66], last[2:66]) > 0 {
		return [][]byte{last, first}, nil
	}
	return [][]byte{first, last}, nil
}

package core

import (
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// recipientReplacementSubjects projects owners of exactly the materials whose
// nominated Recipient wraps change. Retained canonical aliases can repeat the
// same owner; each canonical subject occurs once in the complete vector.
func (s *StateSession) recipientReplacementSubjects(ctx context.Context, intent contract.RecipientReplacementIntent, rows []contract.CompactRow) (contract.GeneratorDescriptor, error) {
	affected := make(map[contract.ID]bool)
	for _, row := range rows {
		if row.Coverage.MaterialKind == contract.ValueMaterialKind {
			affected[row.Coverage.MaterialID] = false
		}
	}
	subjects := make([]contract.ChangedSubjectIdentity, 0, 1+2*len(affected))
	seen := make(map[contract.ChangedSubjectIdentity]bool)
	add := func(kind uint8, primary contract.ID) error {
		id, err := contract.ChangedSubjectIdentityID(s.root.Domain, kind, primary, contract.ID{})
		if err != nil {
			return err
		}
		subject := contract.ChangedSubjectIdentity{Kind: kind, Change: contract.ChangedSubjectUpdated, Identity: id}
		if seen[subject] {
			return nil
		}
		if len(subjects) == contract.MutationChangedSubjectLimit {
			return contract.ErrRecordCapacity
		}
		seen[subject] = true
		subjects = append(subjects, subject)
		return nil
	}
	if err := add(contract.ChangedSubjectRecipient, intent.RecipientID); err != nil {
		return contract.GeneratorDescriptor{}, err
	}
	owner := func(entry *contract.ValueEntry) error {
		if entry == nil {
			return contract.ErrRecord
		}
		if _, changed := affected[entry.ValueState]; !changed {
			return nil
		}
		if entry.ConfidentialityClass != contract.Secret {
			return contract.ErrRecord
		}
		affected[entry.ValueState] = true
		if err := add(contract.ChangedSubjectValueEntry, entry.Incarnation); err != nil {
			return err
		}
		if entry.ValueSource == contract.Generated {
			return add(contract.ChangedSubjectGeneratedValue, entry.Generated.GenerationID)
		}
		return nil
	}
	for _, name := range s.root.Names {
		if err := owner(s.valueEntry(name.Slot)); err != nil {
			return contract.GeneratorDescriptor{}, err
		}
	}
	generated, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return contract.GeneratorDescriptor{}, err
	}
	for _, canonical := range generated.canonical {
		if err := owner(&canonical.record.Entry); err != nil {
			return contract.GeneratorDescriptor{}, err
		}
	}
	for _, found := range affected {
		if !found {
			return contract.GeneratorDescriptor{}, contract.ErrRecord
		}
	}
	return contract.ChangedSubjectDescriptor(subjects)
}

func (s *StateSession) recipientReplacementReceiptPlan(ctx context.Context, p transitionPlan, subjects, access contract.GeneratorDescriptor, request contract.ID) (contract.MutationReceiptDeltaPlan, error) {
	before, err := s.receiptWindows(ctx)
	if err != nil {
		return contract.MutationReceiptDeltaPlan{}, err
	}
	warnings, err := contract.EncodeReceiptWarningBits(contract.OperationRotateRecipientKeyBinding, s.root.WarningBits, 0)
	if err != nil {
		return contract.MutationReceiptDeltaPlan{}, err
	}
	row := contract.CompactMutationReceiptPlan{Schema: contract.MutationReceiptSchema, OperationKind: contract.OperationRotateRecipientKeyBinding,
		DomainID: s.root.Domain, OperationID: p.operation, PredecessorRevisionID: s.head.Core.Revision,
		RequestedRevisionID: p.revision, ObservedRevisionID: p.revision, StateResult: contract.ReceiptStateSuccess,
		EffectSummary: contract.ReceiptEffectNoChange, OutputSummary: contract.ReceiptOutputNotApplicable,
		EvidenceCeiling: contract.ReceiptEvidenceCanonical, CanonicalOutcome: contract.ReceiptCanonicalSelected,
		ChangedSubjects: subjects, WarningBits: warnings}
	row.SummaryCounts[contract.ReceiptChangedAccessCount] = access.Count
	empty := contract.EmptyMutationResultDescriptors()
	row.CompleteResult, err = contract.CompleteMutationResultDescriptor(contract.MutationResultProjection{Receipt: row,
		RequestCoreDigest: request, ChangedAccess: access, Effects: empty[1], Outputs: empty[2], Duties: empty[3], Hazards: empty[4]})
	return contract.MutationReceiptDeltaPlan{DomainID: s.root.Domain, OperationKind: contract.OperationRotateRecipientKeyBinding,
		AddedCount: 1, Before: before, NewReceipt: row}, err
}

func (s *StateSession) encodeRecipientReplacement(ctx context.Context, intent contract.RecipientReplacementIntent, p transitionPlan, request contract.RequestCore, next *StateSession, subjects contract.GeneratorDescriptor) (*Candidate, Result) {
	fail := func(err error) (*Candidate, Result) { return nil, installedApplyPreparationFailure(err) }
	access, err := installedApplyAccessChanges(s.accessRecords(), next.accessRecords(), s.root.Domain)
	if err != nil {
		return fail(err)
	}
	requestDigest, err := contract.RequestDigest(request)
	if err != nil {
		return fail(err)
	}
	delta, err := s.recipientReplacementReceiptPlan(ctx, p, subjects, access, requestDigest)
	if err != nil {
		return fail(err)
	}
	descriptor, err := contract.RecipientReplacementIntentDescriptor(intent)
	if err != nil {
		return fail(err)
	}
	comparison := &Comparison{session: s, operationKind: contract.OperationRotateRecipientKeyBinding, desired: descriptor.Digest, desiredLength: descriptor.Length}
	encoded, result := s.encodeLifecycleReceiptCandidate(ctx, comparison, next, p, request, delta)
	if encoded == nil {
		return nil, result
	}
	encoded.candidate.requestIdentity, encoded.candidate.replacementState = encoded.identity, next
	return encoded.candidate, Result{}
}

func (s *StateSession) projectedRecipientReplacementRoot(ctx context.Context, p transitionPlan, subjects contract.GeneratorDescriptor, request contract.ID) (format.Root, error) {
	empty := contract.EmptyMutationResultDescriptors()
	delta, err := s.recipientReplacementReceiptPlan(ctx, p, subjects, empty[0], request)
	if err != nil {
		return format.Root{}, err
	}
	storage, err := s.encodeMutationReceiptSupport(ctx, p, delta, contract.ID{})
	if err != nil {
		return format.Root{}, err
	}
	next := *s
	next.root.Snapshot, next.root.Transition = p.snapshot, p.transition
	storage.install(&next)
	if err := s.installAdministrativeIndex(ctx, &next, &Candidate{session: s}, &delta.NewReceipt); err != nil {
		return format.Root{}, err
	}
	if _, err := format.EncodeRoot(next.root); err != nil {
		return format.Root{}, err
	}
	return next.root, nil
}

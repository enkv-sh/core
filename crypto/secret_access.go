package crypto

import (
	"slices"
	"time"

	"enkv.sh/core/contract"
)

func NewEnvelopeRekeyCustody(r *Runtime, q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord,
	route contract.ID, plainBefore []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, predecessorRevision contract.ID, before contract.MutationReceiptWindows, warningBits uint8, deadline time.Time) (*ApplyCustody, error) {
	if r == nil || predecessorRevision.IsZero() || before.DomainID != q.Context.DomainID || witness == nil || len(witness.Handoffs) != 0 {
		return nil, ErrAdmission
	}
	if _, err := contract.EncodeReceiptWarningBits(contract.OperationEnvelopeRekey, warningBits, 0); err != nil {
		return nil, ErrAdmission
	}
	if _, err := before.Descriptors(); err != nil {
		return nil, ErrAdmission
	}
	before.Successes = slices.Clone(before.Successes)
	before.Failures = slices.Clone(before.Failures)
	before.Order = slices.Clone(before.Order)
	return newApplyCustody(r, predecessorRevision, before, warningBits, func() (*applyAdmission, error) {
		return r.admitApplyOperationOwned(contract.OperationEnvelopeRekey, nil, q, control, current, nil, route, nil, plainBefore, support, deadline, true, witness)
	})
}

func applyOperationIntentDescriptor(q contract.CryptoCompareRequest) (contract.DescriptorVector, error) {
	if q.Retirement != nil {
		return contract.RecipientRetirementIntentDescriptor(q.Context.DomainID, q.Intent, q.Recipients, *q.Retirement)
	}
	if q.SecretAccess != nil {
		return contract.SecretAccessIntentDescriptor(q.Context.DomainID, q.Intent, q.Recipients, *q.SecretAccess)
	}
	return contract.CompleteApplyIntentDescriptor(q.Context.DomainID, q.Intent, q.Recipients)
}

func (a *applyAdmission) secretAccessAdmission(current []contract.RecipientRecord, registryChanged bool) bool {
	q := a.request
	if q.SecretAccess == nil || registryChanged || len(q.SealedInputs) != 0 || len(q.Recipients) != len(current) || len(q.Intent) != len(q.Current)+len(a.plainBefore) {
		return false
	}
	for i, input := range q.Recipients {
		if input.Creation != nil || !sameApplyRecipient(input.Recipient, current[i]) {
			return false
		}
	}
	access := q.SecretAccess
	if access.OperationKind != contract.OperationEnvelopeRekey || len(access.RemovedRecipients) != 0 {
		return false
	}
	targetFound := false
	for _, row := range q.Current {
		before, ok := a.current(row)
		if !ok {
			return false
		}
		i := slices.IndexFunc(q.Intent, func(intent contract.CryptoIntentRow) bool { return intent.Name == before.entry.Name })
		if i < 0 {
			return false
		}
		intent := q.Intent[i]
		if !sameCurrentSecretIntent(before, intent) {
			return false
		}
		expected := before.entry.Recipients
		if before.entry.Name == access.Target.Name {
			if targetFound || !a.secretAccessTarget(before) {
				return false
			}
			targetFound = true

		}
		if !slices.Equal(intent.Recipients, expected) {
			return false
		}
	}
	for _, before := range a.plainBefore {
		i := slices.IndexFunc(q.Intent, func(intent contract.CryptoIntentRow) bool { return intent.Name == before.Name })
		if i < 0 || q.Intent[i].ConfidentialityClass != contract.Plain || !slices.Equal(q.Intent[i].Recipients, before.Recipients) {
			return false
		}
	}
	return targetFound
}

func sameCurrentSecretIntent(before applyCurrent, intent contract.CryptoIntentRow) bool {
	return intent.ConfidentialityClass == contract.Secret && intent.ValueSource == before.entry.ValueSource && intent.InputEncoding == before.payload.InputEncoding && intent.RetainedLength == before.payload.RetainedLength && intent.ContentLength == before.payload.ContentLength && intent.PayloadLength == uint32(len(before.entry.ValueBytes)) && intent.PayloadDigest == contract.Hash(before.entry.ValueBytes) &&
		(intent.ValueSource != contract.Supplied || intent.Retained == (contract.RetainedSecretInput{Incarnation: before.entry.Incarnation, Material: before.entry.ValueState}))
}

func (a *applyAdmission) currentPrivateTarget(current applyCurrent) bool {
	if a.request.Retirement != nil {
		return slices.Contains(current.entry.Recipients, a.request.Retirement.RecipientID)
	}
	return a.secretAccessTarget(current)
}

func (a *applyAdmission) secretAccessTarget(current applyCurrent) bool {
	if a.request.SecretAccess == nil {
		return true
	}
	target := a.request.SecretAccess.Target
	return current.row.Slot == target.Slot && current.entry.Name == target.Name && current.entry.Incarnation == target.Incarnation && current.entry.ValueState == target.Material && current.entryDigest == target.BeforePublicEntryDigest
}

func (a *applyAdmission) secretAccessSubjects() (contract.GeneratorDescriptor, error) {
	if a.request.SecretAccess == nil || len(a.plan.Rows) != 1 {
		return contract.GeneratorDescriptor{}, ErrAdmission
	}
	target := a.request.SecretAccess.Target
	var rows []contract.ChangedSubjectIdentity
	add := func(kind, change uint8, primary, secondary contract.ID) error {
		id, err := contract.ChangedSubjectIdentityID(a.request.Context.DomainID, kind, primary, secondary)
		if err != nil {
			return err
		}
		rows = append(rows, contract.ChangedSubjectIdentity{Kind: kind, Change: change, Identity: id})
		return nil
	}
	if err := add(contract.ChangedSubjectValueEntry, contract.ChangedSubjectUpdated, target.Incarnation, contract.ID{}); err != nil {
		return contract.GeneratorDescriptor{}, err
	}

	for _, row := range a.request.Current {
		current, ok := a.current(row)
		if !ok {
			return contract.GeneratorDescriptor{}, ErrAdmission
		}
		if !a.secretAccessTarget(current) || current.entry.ValueSource != contract.Generated {
			continue
		}
		if err := add(contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectRemoved, current.entry.Generated.GenerationID, contract.ID{}); err != nil {
			return contract.GeneratorDescriptor{}, err
		}
		if err := add(contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectAdded, a.plan.Rows[0].ValueState, contract.ID{}); err != nil {
			return contract.GeneratorDescriptor{}, err
		}
	}
	return contract.ChangedSubjectDescriptor(rows)
}

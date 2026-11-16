package crypto

import (
	"slices"
	"time"

	"enkv.sh/core/contract"
)

func NewRecipientRetirementCustody(r *Runtime, q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, retiredSlot uint16,
	route contract.ID, plainBefore []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, predecessorRevision contract.ID, before contract.MutationReceiptWindows, warningBits uint8, deadline time.Time) (*ApplyCustody, error) {
	if r == nil || predecessorRevision.IsZero() || before.DomainID != q.Context.DomainID || witness == nil || len(witness.Handoffs) != 0 || q.Retirement == nil {
		return nil, ErrAdmission
	}
	if _, err := contract.EncodeReceiptWarningBits(contract.OperationRetireRecipientIdentity, warningBits, 0); err != nil {
		return nil, ErrAdmission
	}
	if _, err := before.Descriptors(); err != nil {
		return nil, ErrAdmission
	}
	// A surviving old material consumer cannot lose its registry route.
	// The parent proves the complete blocker census before this handoff.
	for _, readers := range witness.Readers {
		if slices.Contains(readers.Retained, q.Retirement.RecipientID) {
			return nil, ErrAdmission
		}
	}
	before.Successes = slices.Clone(before.Successes)
	before.Failures = slices.Clone(before.Failures)
	before.Order = slices.Clone(before.Order)
	return newApplyCustody(r, predecessorRevision, before, warningBits, func() (*applyAdmission, error) {
		return r.admitApplyOperationOwned(contract.OperationRetireRecipientIdentity, &retiredSlot, q, control, current, nil, route, nil, plainBefore, support, deadline, true, witness)
	})
}

func recipientRetirementAdmission(q contract.CryptoCompareRequest, current []contract.RecipientRecord, retiredSlot uint16, control contract.ControlCore) bool {
	if q.Retirement == nil || q.Retirement.Slot != retiredSlot || q.Retirement.RecipientID == control.AuthorityRecipientID || len(q.SealedInputs) != 0 || !validApplyCurrentRecipients(current, control) || len(q.Recipients)+1 != len(current) {
		return false
	}
	retired, after := false, 0
	for _, before := range current {
		binding := applyBindingIndex(q.Bindings, before.RecipientID)
		if binding < 0 || !sameApplyBinding(*before.CurrentBinding, q.Bindings[binding].Binding) {
			return false
		}
		if before.RecipientID == q.Retirement.RecipientID {
			row, err := contract.NewRecipientRetirementRow(retiredSlot, before)
			if err != nil || row != *q.Retirement {
				return false
			}
			retired = true
			continue
		}
		if after >= len(q.Recipients) || q.Recipients[after].Creation != nil || !sameApplyRecipient(before, q.Recipients[after].Recipient) {
			return false
		}
		after++
	}
	return retired && after == len(q.Recipients)
}

func (a *applyAdmission) recipientRetirementCensus() bool {
	q := a.request
	if q.Retirement == nil || len(q.Intent) != len(q.Current)+len(a.plainBefore) {
		return false
	}
	retired := q.Retirement.RecipientID
	for _, row := range q.Current {
		before, ok := a.current(row)
		if !ok {
			return false
		}
		i := slices.IndexFunc(q.Intent, func(intent contract.CryptoIntentRow) bool { return intent.Name == before.entry.Name })
		if i < 0 || !sameCurrentSecretIntent(before, q.Intent[i]) || !sameRecipientsWithout(before.entry.Recipients, q.Intent[i].Recipients, retired) {
			return false
		}
	}
	for _, before := range a.plainBefore {
		i := slices.IndexFunc(q.Intent, func(intent contract.CryptoIntentRow) bool { return intent.Name == before.Name })
		if i < 0 || q.Intent[i].ConfidentialityClass != contract.Plain || !sameRecipientsWithout(before.Recipients, q.Intent[i].Recipients, retired) {
			return false
		}
	}
	return true
}

func sameRecipientsWithout(before, after []contract.ID, removed contract.ID) bool {
	i := 0
	for _, id := range before {
		if id == removed {
			continue
		}
		if i >= len(after) || after[i] != id {
			return false
		}
		i++
	}
	return i == len(after)
}

func (a *applyAdmission) checkRetirementIdentityPlan(plan contract.IdentityPlan, current []applyCurrent) bool {
	expected := 0
	for _, before := range current {
		if !a.currentPrivateTarget(before) {
			continue
		}
		expected++
		i := slices.IndexFunc(plan.Rows, func(row contract.IdentityRow) bool { return row.Name == before.entry.Name })
		if i < 0 || plan.Rows[i].Slot != before.row.Slot || plan.Rows[i].Incarnation != before.entry.Incarnation {
			return false
		}
	}
	return len(plan.Rows) == expected
}

func (a *applyAdmission) recipientRetirementSubjects() (contract.GeneratorDescriptor, error) {
	if a.request.Retirement == nil {
		return contract.GeneratorDescriptor{}, ErrAdmission
	}
	retired := a.request.Retirement.RecipientID
	var rows []contract.ChangedSubjectIdentity
	add := func(kind, change uint8, primary, secondary contract.ID) error {
		id, err := contract.ChangedSubjectIdentityID(a.request.Context.DomainID, kind, primary, secondary)
		if err == nil {
			rows = append(rows, contract.ChangedSubjectIdentity{Kind: kind, Change: change, Identity: id})
		}
		return err
	}
	if err := add(contract.ChangedSubjectRecipient, contract.ChangedSubjectRemoved, retired, contract.ID{}); err != nil {
		return contract.GeneratorDescriptor{}, err
	}
	member := func(incarnation contract.ID) error {
		if err := add(contract.ChangedSubjectValueEntry, contract.ChangedSubjectUpdated, incarnation, contract.ID{}); err != nil {
			return err
		}
		return add(contract.ChangedSubjectMembership, contract.ChangedSubjectRemoved, incarnation, retired)
	}
	for _, before := range a.plainBefore {
		if slices.Contains(before.Recipients, retired) {
			if err := member(before.Incarnation); err != nil {
				return contract.GeneratorDescriptor{}, err
			}
		}
	}
	for _, row := range a.request.Current {
		current, ok := a.current(row)
		if !ok {
			return contract.GeneratorDescriptor{}, ErrAdmission
		}
		if !a.currentPrivateTarget(current) {
			continue
		}
		if err := member(current.entry.Incarnation); err != nil {
			return contract.GeneratorDescriptor{}, err
		}
		if current.entry.ValueSource != contract.Generated {
			continue
		}
		i := slices.IndexFunc(a.plan.Rows, func(row contract.IdentityRow) bool { return row.Name == current.entry.Name })
		if i < 0 {
			return contract.GeneratorDescriptor{}, ErrAdmission
		}
		if err := add(contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectRemoved, current.entry.Generated.GenerationID, contract.ID{}); err != nil {
			return contract.GeneratorDescriptor{}, err
		}
		if err := add(contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectAdded, a.plan.Rows[i].ValueState, contract.ID{}); err != nil {
			return contract.GeneratorDescriptor{}, err
		}
	}
	if a.supportTransition != nil && a.supportTransition.Output != nil {
		output := a.supportTransition.Output
		after, _, _, err := output.ConfigurationAfter(a.plan)
		if err != nil {
			return contract.GeneratorDescriptor{}, err
		}
		changed, err := contract.OutputConfigurationChangedSubjects(output.Before, after)
		if err != nil {
			return contract.GeneratorDescriptor{}, err
		}
		rows = append(rows, changed...)
	}
	return contract.ChangedSubjectDescriptor(rows)
}

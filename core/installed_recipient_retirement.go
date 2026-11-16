package core

import (
	"bytes"
	"context"
	"slices"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/telemetry"
)

const RecipientRetirementBlockerLimit = 64

type RecipientRetirementBlocker struct {
	MaterialID contract.ID
	OwnerKind  contract.SupportRecordKind
	OwnerID    contract.ID
}

type RecipientRetirementBlockers struct {
	Total uint32
	Rows  []RecipientRetirementBlocker
}

type RecipientRetirementInstallation struct {
	AccessMutationInstallation
	Recipient    contract.RecipientBindingReference
	AdmitCustody func(context.Context, contract.CryptoCompareRequest, contract.ControlCore, []contract.RecipientRecord, uint16, []contract.MembershipRow, contract.DescriptorVector, *contract.GeneratedSupportTransition, contract.ID, contract.MutationReceiptWindows, uint8, time.Time) (*InstalledApplyCustody, error)
}

type installedRecipientRetirement struct {
	recipient contract.RecipientBindingReference
	admit     func(context.Context, contract.CryptoCompareRequest, contract.ControlCore, []contract.RecipientRecord, uint16, []contract.MembershipRow, contract.DescriptorVector, *contract.GeneratedSupportTransition, contract.ID, contract.MutationReceiptWindows, uint8, time.Time) (*InstalledApplyCustody, error)
}

type InstalledRecipientRetirement struct{ engine *InstalledApply }

func NewInstalledRecipientRetirement(i RecipientRetirementInstallation) (*InstalledRecipientRetirement, error) {
	if i.Recipient.RecipientID.IsZero() || i.Recipient.PublicBindingDigest.IsZero() || i.AdmitCustody == nil {
		return nil, contract.ErrRecord
	}
	common := i.AccessMutationInstallation
	engine, err := newInstalledApply(ApplyInstallation{ExpectedDomain: common.ExpectedDomain, ExpectedStore: common.ExpectedStore, PublicBasis: common.PublicBasis, ExpectedControl: common.ExpectedControl,
		Store: common.Store, Trust: common.Trust, CompositionID: common.CompositionID, ConfigurationValidator: common.ConfigurationValidator, CloseInstalled: common.CloseInstalled, Maintenance: common.Maintenance}, nil, &installedRecipientRetirement{recipient: i.Recipient, admit: i.AdmitCustody})
	if err != nil {
		return nil, err
	}
	return &InstalledRecipientRetirement{engine: engine}, nil
}

func (e *InstalledRecipientRetirement) Retire(ctx context.Context, requestID contract.ID) PublicApplyResult {
	var engine *InstalledApply
	if e != nil {
		engine = e.engine
	}
	return installedSecretAccessRun(ctx, requestID, engine, telemetry.OpCoreRetireRecipient)
}

func (e *InstalledRecipientRetirement) Close() {
	if e != nil {
		e.engine.Close()
	}
}

func (s *StateSession) selectedRecipientSlot(id contract.ID) (uint16, *contract.RecipientRecord) {
	for _, page := range s.recipients {
		if page == nil {
			continue
		}
		for at, row := range page.Slots {
			if row != nil && row.RecipientID == id {
				return page.Index*format.RecipientSlots + uint16(at), row
			}
		}
	}
	return 0, nil
}

func (s *StateSession) authenticatedRecipientRetirement(row contract.RecipientRetirementRow) bool {
	if s == nil || row.RecipientID == s.admission.recipient {
		return false
	}
	slot, record := s.selectedRecipientSlot(row.RecipientID)
	if record == nil {
		return false
	}
	actual, err := contract.NewRecipientRetirementRow(slot, *record)
	return err == nil && actual == row
}

func (s *StateSession) installedRecipientRetirementInputs(ctx context.Context, i ApplyInstallation, retirement *installedRecipientRetirement) ([]ApplyEntryInput, *contract.RecipientRetirementRow, *RecipientRetirementBlockers, Result) {
	fail := func(result Result) ([]ApplyEntryInput, *contract.RecipientRetirementRow, *RecipientRetirementBlockers, Result) {
		return nil, nil, nil, result
	}
	if retirement == nil {
		return fail(refused(AdmissionInvalid))
	}
	if result := s.installedAccessSelectionResult(ctx, i); result.Outcome != 0 {
		return fail(result)
	}
	slot, old := s.selectedRecipientSlot(retirement.recipient.RecipientID)
	if old == nil || old.CurrentBinding == nil || old.RecipientID == s.admission.recipient {
		return fail(refused(InvalidIntent))
	}
	digest, err := contract.PublicBindingDigest(*old.CurrentBinding)
	if err != nil || digest != retirement.recipient.PublicBindingDigest {
		return fail(refused(InvalidIntent))
	}
	row, err := contract.NewRecipientRetirementRow(slot, *old)
	if err != nil {
		return fail(installedApplyPreparationFailure(err))
	}
	work, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return fail(installedApplyPreparationFailure(err))
	}
	blockers, err := work.recipientRetirementBlockers(old.RecipientID)
	if err != nil {
		return fail(installedApplyPreparationFailure(err))
	}
	if blockers != nil {
		return nil, nil, blockers, refused(InvalidRelation)
	}
	if !s.root.Generated.ActiveOwner.IsZero() {
		result := s.observed(Contention)
		result.Reason = DifferentSelection
		return fail(result)
	}
	var input []ApplyEntryInput
	for _, named := range s.root.Names {
		before := s.valueEntry(named.Slot)
		if before == nil {
			return fail(refused(InvalidRelation))
		}
		members := slices.DeleteFunc(slices.Clone(before.Recipients), func(id contract.ID) bool { return id == old.RecipientID })
		entry := ApplyEntryInput{Name: before.Name, Recipients: members, ValueSource: before.ValueSource, ConfidentialityClass: before.ConfidentialityClass, InputEncoding: before.InputEncoding, OutputEncoding: before.OutputEncoding, InputBytes: before.ValueBytes}
		if before.ValueSource == contract.Supplied && before.ConfidentialityClass == contract.Secret {
			entry.Retained = &contract.RetainedSecretInput{Incarnation: before.Incarnation, Material: before.ValueState}
			entry.InputBytes = nil
		}
		input = append(input, entry)
	}
	return input, &row, nil, Result{}
}

func (s *StateSession) compareRecipientRetirement(c *Comparison, retirement contract.RecipientRetirementRow) (*Comparison, Result) {
	if c == nil || !s.authenticatedRecipientRetirement(retirement) || len(c.desiredEntries) != len(s.root.Names) || len(c.added)+len(c.removed) != 0 || !slices.Equal(c.recipientChanges, []contract.ID{retirement.RecipientID}) {
		return nil, refused(InvalidIntent)
	}
	for at, after := range c.desiredEntries {
		before := s.valueEntry(c.slots[at])
		if before == nil || after.Name != before.Name || after.ValueSource != before.ValueSource || after.ConfidentialityClass != before.ConfidentialityClass || !bytes.Equal(after.InputBytes, before.ValueBytes) {
			return nil, refused(InvalidIntent)
		}
		members := slices.DeleteFunc(slices.Clone(before.Recipients), func(id contract.ID) bool { return id == retirement.RecipientID })
		if !slices.Equal(after.Recipients, members) {
			return nil, refused(InvalidIntent)
		}
	}
	descriptor, err := contract.RecipientRetirementIntentDescriptor(s.root.Domain, c.intent, c.recipients, retirement)
	if err != nil {
		return nil, installedApplyPreparationFailure(err)
	}
	c.retirement, c.operationKind = &retirement, contract.OperationRetireRecipientIdentity
	c.desired, c.desiredLength = descriptor.Digest, descriptor.Length
	return c, s.observed(ObservedCurrent)
}

func (c *Comparison) retirementCommitment() contract.DescriptorVector {
	if c.retirement == nil {
		return retirementCommitment(c.session.root.Domain)
	}
	descriptor, err := contract.RetirementDescriptor(c.session.root.Domain, []contract.RecipientRetirementRow{*c.retirement})
	if err != nil {
		return contract.DescriptorVector{}
	}
	return descriptor
}

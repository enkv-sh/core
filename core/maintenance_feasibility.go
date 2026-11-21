package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"slices"
	"sync"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func maintenanceSourcePair(p AdministrativeSourcePins) contract.PlanningSourcePair {
	return contract.PlanningSourcePair{FileIdentity: p.FileID, EditableDigest: p.EditableDigest, GeneratedDigest: p.GeneratedDigest, EditableLength: p.EditableLength, GeneratedLength: p.GeneratedLength}
}

func maintenancePublicConfiguration(source contract.PublicConfiguration, retired contract.ID) contract.PublicConfiguration {
	after := ownPublicConfiguration(source)
	if retired.IsZero() {
		return after
	}
	after.Recipients.Value = slices.DeleteFunc(after.Recipients.Value, func(row contract.PublicRecipient) bool { return row.RecipientID == retired })
	for i := range after.Entries.Value {
		row := &after.Entries.Value[i]
		row.Memberships.Value = slices.DeleteFunc(row.Memberships.Value, func(id contract.ID) bool { return id == retired })
	}
	return after
}

func maintenanceCurrentRecipientsMatch(s *StateSession, proposed []contract.ApplyRecipientInput) bool {
	if len(proposed) != len(s.registry()) {
		return false
	}
	for _, row := range proposed {
		_, current := s.selectedRecipientSlot(row.Recipient.RecipientID)
		if current == nil || current.CurrentBinding == nil || row.Recipient.CurrentBinding == nil || !kmsBindingEqual(*current.CurrentBinding, *row.Recipient.CurrentBinding) {
			return false
		}
	}
	return true
}

func (s *StateSession) maintenanceSourceFeasibility(ctx context.Context, requestID contract.ID, m *MaintenanceInstallation, c *Comparison, retirement *installedRecipientRetirement, validator *PublicConfigurationValidator) Result {
	if m == nil || c == nil || ctx == nil || ctx.Err() != nil || m.SourceUnchanged(ctx) != nil {
		return refused(AdmissionInvalid)
	}
	digest, err := PlanningInputDigest(m.Configuration, m.Inputs)
	if err != nil || digest != m.InputDigest {
		return refused(InvalidIntent)
	}
	// Display edits and old creation facts remain inert. Complete current
	// identity and binding coverage is required for later source adoption.
	if !maintenanceCurrentRecipientsMatch(s, m.Recipients) || !s.maintenanceOutputCapacity(m, c) {
		return refused(InvalidIntent)
	}
	retired := contract.ID{}
	if retirement != nil {
		retired = retirement.recipient.RecipientID
	}
	public := maintenancePublicConfiguration(m.Configuration, retired)
	if validator == nil {
		return refused(AdmissionInvalid)
	}
	validation := validator.ValidateProposed(ctx, public)
	if !validation.Valid || !validation.Complete || !validation.DiagnosticsComplete {
		return refused(InvalidIntent)
	}
	if !planningInputScopeMatches(public, m.Inputs) {
		return refused(InvalidIntent)
	}
	control := currentControlOf(s)
	authority := contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: control.AuthorityRecipientID, Binding: control.AuthorityKMSBinding}
	pair := maintenanceSourcePair(m.SourcePins)
	q := contract.PlanningAdmission{RequestID: requestID, DomainID: s.root.Domain, HEADDigest: contract.Hash(s.body), HEADRevision: s.head.Core.Revision,
		SnapshotID: s.root.Snapshot, Root: s.head.Core.Root, HEADToken: s.token, AccessRoot: s.root.CurrentAccess.AccessRoot, CredentialRoute: m.CredentialRoute,
		Sources: contract.PlanningSources{Trusted: pair, Proposed: pair}, Control: control, Authority: authority, Options: contract.PlanningOptions{Purpose: contract.PlanningEquality}}
	if retirement != nil {
		q.Options.Purpose = contract.PlanningRetirementFeasibility
		q.Retirement = &contract.PlanningRetirementBinding{Recipient: retirement.recipient}
	}
	for _, input := range m.Inputs {
		index := slices.IndexFunc(public.Entries.Value, func(row contract.PublicEntry) bool { return row.Name == input.Name })
		if index < 0 || public.Entries.Value[index].Memberships.State != contract.PublicPresent {
			return refused(InvalidIntent)
		}
		members := public.Entries.Value[index].Memberships.Value
		var current *format.ValueEntry
		var slot uint16
		for _, named := range s.root.Names {
			if named.Name == input.Name {
				slot, current = named.Slot, s.valueEntry(named.Slot)
				break
			}
		}
		if input.Form == contract.PlanningRetained {
			if current == nil || current.ValueSource != contract.Supplied || current.ConfidentialityClass != contract.Secret || current.Incarnation != input.Retained.Incarnation || current.ValueState != input.Retained.Material {
				return refused(InvalidIntent)
			}
			continue
		}
		view, err := contract.InspectSealedInputEnvelope(input.SealedInput)
		if err != nil || view.Core.DomainID != s.root.Domain || view.Core.FileIdentity != m.SourcePins.FileID || !bytes.Equal(view.Core.Name, []byte(input.Name)) ||
			view.Core.CompatibilityID != control.CompatibilityID || view.Core.CryptoSupportID != control.CryptoSupportID {
			return refused(InvalidIntent)
		}
		binding, err := contract.PublicBindingDigest(authority.Binding)
		if err != nil || view.AuthorityWrap.SubjectKind != authority.SubjectKind || view.AuthorityWrap.SubjectID != authority.SubjectID ||
			view.AuthorityWrap.BindingID != authority.Binding.BindingID || view.AuthorityWrap.BindingSerial != authority.Binding.BindingSerial || view.AuthorityWrap.PublicBindingDigest != binding {
			return refused(InvalidIntent)
		}
		refs := make([]contract.RecipientBindingReference, len(members))
		for i, id := range members {
			row := slices.IndexFunc(m.Recipients, func(row contract.ApplyRecipientInput) bool { return row.Recipient.RecipientID == id })
			if row < 0 || m.Recipients[row].Recipient.CurrentBinding == nil {
				return refused(InvalidIntent)
			}
			digest, err := contract.PublicBindingDigest(*m.Recipients[row].Recipient.CurrentBinding)
			if err != nil {
				return refused(InvalidIntent)
			}
			refs[i] = contract.RecipientBindingReference{RecipientID: id, PublicBindingDigest: digest}
		}
		expected, err := contract.IntendedRecipientBindingSetDigest(s.root.Domain, authority.SubjectID, refs)
		if err != nil {
			return refused(InvalidIntent)
		}
		if expected == view.Core.IntendedRecipientBindingSetDigest {
			continue
		}
		if current == nil || current.ValueSource != contract.Supplied || current.ConfidentialityClass != contract.Secret || slices.Contains(members, retired) && !retired.IsZero() {
			return refused(InvalidIntent)
		}
		for _, id := range members {
			if !slices.Contains(current.Recipients, id) {
				return refused(InvalidIntent)
			}
		}
		core, payload, access, ok := s.selectedValue(slot)
		entryDigest, err := contract.PublicValueEntryDigest(s.root.Domain, slot, *current)
		if !ok || err != nil {
			return failure(IntegrityFailure, InvalidRelation)
		}
		selection := &contract.ConsumerSelection{DomainID: q.DomainID, SnapshotID: q.SnapshotID, HEADDigest: q.HEADDigest, AccessRoot: q.AccessRoot,
			EntryDigest: entryDigest, Root: q.Root, HEADRevision: q.HEADRevision, HEADToken: q.HEADToken, Slot: slot, Entry: *current, Core: core, Payload: payload, Access: access, Binding: authority}
		q.Targets = append(q.Targets, contract.PlanningTarget{Input: input, ProposedRecipients: slices.Clone(members), CurrentPresent: true, CurrentValueSource: contract.Supplied, CurrentConfidentialityClass: contract.Secret, Current: selection})
	}
	if len(q.Targets) != 0 {
		if _, err := rand.Read(q.SessionID[:]); err != nil || q.SessionID.IsZero() {
			return refused(AdmissionInvalid)
		}
		custody, err := m.AdmitFeasibility(ctx, q)
		var closeCustody func()
		if custody != nil {
			closeCustody = sync.OnceFunc(custody.Close)
			defer closeCustody()
		}
		if err != nil || custody == nil {
			return failure(EvidenceUnavailable, CustodyUnavailable)
		}
		checked := custody.Check(ctx)
		closeCustody()
		if !planningCheckMatches(q.Targets, checked) || !checked.Complete || checked.Code != contract.CryptoSuccess {
			if checked.Code != contract.CryptoSuccess {
				return planningCryptoFailure(checked.Code).Result
			}
			return refused(InvalidRelation)
		}
		for _, row := range checked.Rows {
			if row.Relation != contract.PlanningEqual {
				return refused(InvalidIntent)
			}
		}
	}
	if ctx.Err() != nil || m.SourceUnchanged(ctx) != nil {
		return refused(AdmissionInvalid)
	}
	return Result{}
}

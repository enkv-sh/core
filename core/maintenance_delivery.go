package core

import (
	"bytes"
	"cmp"
	"context"
	"reflect"
	"slices"
	"strings"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func maintenancePreparedPinDeltas(s *StateSession, c *Comparison) ([]MaintenancePinDelta, error) {
	var deltas []MaintenancePinDelta
	for _, prepared := range c.preparedRows {
		before := s.valueEntry(prepared.Slot)
		if before == nil || before.ValueSource != contract.Supplied || before.ConfidentialityClass != contract.Secret {
			continue
		}
		after, err := contract.DecodeValueEntry(prepared.EntryBytes)
		if err != nil || prepared.Name != before.Name || after.Name != before.Name || after.Incarnation != before.Incarnation || after.ValueSource != contract.Supplied || after.ConfidentialityClass != contract.Secret {
			return nil, contract.ErrRecord
		}
		if after.ValueState != before.ValueState {
			deltas = append(deltas, MaintenancePinDelta{Name: before.Name, Before: contract.RetainedSecretInput{Incarnation: before.Incarnation, Material: before.ValueState}, After: contract.RetainedSecretInput{Incarnation: after.Incarnation, Material: after.ValueState}})
		}
	}
	slices.SortFunc(deltas, func(a, b MaintenancePinDelta) int { return strings.Compare(a.Name, b.Name) })
	for i := 1; i < len(deltas); i++ {
		if deltas[i-1].Name == deltas[i].Name {
			return nil, contract.ErrRecord
		}
	}
	return deltas, nil
}

func (s *StateSession) maintenanceCandidatePage(candidate *Candidate, root format.Root, index uint16) (*format.ValueEntryPage, error) {
	if int(index) >= len(root.ValueEntryPages) || root.ValueEntryPages[index] == nil {
		return nil, contract.ErrRecord
	}
	ref := *root.ValueEntryPages[index]
	for _, object := range candidate.objects {
		if object.ref != ref {
			continue
		}
		page, err := format.DecodeValueEntryPage(object.body)
		if err != nil || format.CheckReference(ref, object.body) != nil || page.Index != index || page.Domain != s.root.Domain {
			return nil, contract.ErrRecord
		}
		return &page, nil
	}
	if s.root.ValueEntryPages[index] == nil || *s.root.ValueEntryPages[index] != ref {
		return nil, contract.ErrRecord
	}
	return s.pages[index], nil
}

func (s *StateSession) validateMaintenanceCandidatePins(candidate *Candidate, deltas []MaintenancePinDelta) bool {
	var root *format.Root
	for _, object := range candidate.objects {
		if object.ref == candidate.head.Core.Root {
			decoded, err := format.DecodeRoot(object.body)
			if err != nil || format.CheckReference(object.ref, object.body) != nil {
				return false
			}
			root = &decoded
			break
		}
	}
	if root == nil || !slices.Equal(root.Names, s.root.Names) {
		return false
	}
	var actual []MaintenancePinDelta
	names := slices.Clone(root.Names)
	slices.SortFunc(names, func(a, b format.NameEntry) int { return cmp.Compare(a.Slot, b.Slot) })
	pageIndex := uint16(contract.MaxValueEntryPages)
	var page *format.ValueEntryPage
	for _, named := range names {
		before := s.valueEntry(named.Slot)
		if before == nil {
			return false
		}
		if before.ValueSource != contract.Supplied || before.ConfidentialityClass != contract.Secret {
			continue
		}
		index := named.Slot / format.PageSlots
		if index != pageIndex {
			var err error
			page, err = s.maintenanceCandidatePage(candidate, *root, index)
			if err != nil || page == nil {
				return false
			}
			pageIndex = index
		}
		after := page.Slots[named.Slot%format.PageSlots]
		if after == nil || after.Name != before.Name || after.Incarnation != before.Incarnation || after.ValueSource != before.ValueSource || after.ConfidentialityClass != before.ConfidentialityClass {
			return false
		}
		if after.ValueState != before.ValueState {
			actual = append(actual, MaintenancePinDelta{Name: before.Name, Before: contract.RetainedSecretInput{Incarnation: before.Incarnation, Material: before.ValueState}, After: contract.RetainedSecretInput{Incarnation: after.Incarnation, Material: after.ValueState}})
		}
	}
	slices.SortFunc(actual, func(a, b MaintenancePinDelta) int { return strings.Compare(a.Name, b.Name) })
	return slices.Equal(actual, deltas)
}

func maintenanceExpectedInputs(inputs []contract.PlanningInput, deltas []MaintenancePinDelta) ([]contract.PlanningInput, error) {
	expected, err := ownPlanningInputs(inputs)
	if err != nil {
		return nil, err
	}
	for i := range expected {
		input := &expected[i]
		if input.Form != contract.PlanningRetained {
			continue
		}
		for _, delta := range deltas {
			if input.Name != delta.Name {
				continue
			}
			if input.Retained != delta.Before {
				return nil, contract.ErrRecord
			}
			input.Retained = delta.After
		}
	}
	return expected, nil
}

func maintenanceRecipientsEqual(a, b []contract.ApplyRecipientInput) bool {
	left, err := ownMaintenanceRecipients(a)
	if err != nil {
		return false
	}
	right, err := ownMaintenanceRecipients(b)
	if err != nil || len(left) != len(right) {
		return false
	}
	for i, row := range left {
		l, err := contract.EncodeRecipientRecord(row.Recipient)
		if err != nil {
			return false
		}
		r, err := contract.EncodeRecipientRecord(right[i].Recipient)
		if err != nil || !bytes.Equal(l, r) || !reflect.DeepEqual(row.Creation, right[i].Creation) {
			return false
		}
	}
	return true
}

func (s *StateSession) deliverMaintenanceSuccessor(ctx context.Context, c *Comparison, candidate *Candidate, i ApplyInstallation, guard *installedMutationGuard) (*MaintenanceSuccessor, Result) {
	m := i.Maintenance
	if m == nil || guard == nil || candidate == nil || c.applyReceipt == nil || c.applyReceipt.identity.IsZero() || len(candidate.body) > contract.MaxHeadLength {
		return nil, refused(AdmissionInvalid)
	}
	head, err := format.DecodeHead(candidate.body)
	if err != nil || head.AuthKind != format.LifecycleAuth || head.Subject.OperationKind != c.lifecycleOperationKind() || head.Core != candidate.head.Core || !selectedHeadProofs(head, currentControlOf(s), nil) {
		return nil, failure(IntegrityFailure, InvalidProof)
	}
	deltas, err := maintenancePreparedPinDeltas(s, c)
	if err != nil || !s.validateMaintenanceCandidatePins(candidate, deltas) {
		return nil, failure(IntegrityFailure, InvalidRelation)
	}
	correlation := MaintenanceSuccessor{OperationKind: c.lifecycleOperationKind(), FileIdentity: m.SourcePins.FileID, DomainID: s.root.Domain,
		OperationID: head.Subject.Operation, RequestIdentity: c.applyReceipt.identity, SignedCandidate: bytes.Clone(candidate.body), PinDeltas: deltas}
	retired := contract.ID{}
	if c.retirement != nil {
		row := *c.retirement
		correlation.Retirement = &row
		retired = row.RecipientID
		record := s.recipientRecord(retired)
		if record == nil || record.CurrentBinding == nil {
			return nil, refused(InvalidRelation)
		}
		digest, err := contract.PublicBindingDigest(*record.CurrentBinding)
		if err != nil {
			return nil, refused(InvalidRelation)
		}
		correlation.Recipient = contract.RecipientBindingReference{RecipientID: retired, PublicBindingDigest: digest}
	} else if c.secretAccess != nil && c.secretAccess.OperationKind == contract.OperationEnvelopeRekey {
		target := c.secretAccess.Target
		correlation.Name, correlation.RekeyTarget = target.Name, &target
	} else {
		return nil, refused(InvalidIntent)
	}
	if !s.prepareMaintenanceMaterial(c, candidate, &correlation, m.materialBounds) || !maintenanceCorrelationValid(correlation, s.root.Domain, s.head.Core.Store, m.SourcePins.FileID) {
		return nil, failure(IntegrityFailure, InvalidRelation)
	}
	expected := maintenancePublicConfiguration(m.Configuration, retired)
	expectedInputs, err := maintenanceExpectedInputs(m.Inputs, deltas)
	if err != nil {
		return nil, refused(InvalidIntent)
	}
	expectedDigest, err := PlanningInputDigest(expected, expectedInputs)
	if err != nil {
		return nil, refused(InvalidIntent)
	}
	expectedRecipients := slices.DeleteFunc(slices.Clone(m.Recipients), func(row contract.ApplyRecipientInput) bool {
		return row.Recipient.RecipientID == retired && !retired.IsZero()
	})
	if guard.check(ctx) != contract.ReasonNone {
		return nil, refused(AdmissionInvalid)
	}
	readback, err := m.PublishSuccessor(ctx, ownMaintenanceSuccessor(correlation))
	if err != nil || guard.check(ctx) != contract.ReasonNone {
		return nil, refused(AdmissionInvalid)
	}
	if readback.SourcePins != m.SourcePins || !readback.OutputPins.Valid() || !readback.OutputPins.HasGenerated || readback.OutputPins.FileID != m.SourcePins.FileID || readback.OutputPins.Format != m.SourcePins.Format || readback.OutputPath != m.OutputPath ||
		!maintenanceSuccessorEqual(correlation, readback.Correlation) || !sameReplacementBasis(i.PublicBasis, readback.Basis) || !maintenanceRecipientsEqual(expectedRecipients, readback.Recipients) {
		return nil, refused(InvalidRelation)
	}
	digest, err := PlanningInputDigest(readback.Configuration, readback.Inputs)
	if err != nil || digest != expectedDigest {
		return nil, refused(InvalidRelation)
	}
	current, result := s.readAuthenticatedHead(ctx)
	if result.Outcome != 0 {
		return nil, result
	}
	if current.token != s.token || !bytes.Equal(current.body, s.body) {
		result := s.observed(Contention)
		result.Reason, result.ObservedRevision, result.ObservedSnapshotID = DifferentSelection, current.head.Core.Revision, current.head.Core.Root.Object
		return &correlation, result
	}
	return &correlation, Result{}
}

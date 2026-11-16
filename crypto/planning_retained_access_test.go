package crypto

import (
	"bytes"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

type retainedAccessValue struct {
	name string
	raw  []byte
}

// The supplied selections stand for already authenticated retained-reader
// unions. This fixture does not claim a current producer can create such a
// history. Every current payload and wrap has its actual cryptographic context.
func planningRetainedAccessFixture(t *testing.T, ordinary, current []int, values []retainedAccessValue) (contract.PlanningAdmission, *consumerTestRoute) {
	t.Helper()
	if len(ordinary) != len(current) || values != nil && len(values) != len(ordinary) {
		t.Fatal("invalid access fixture dimensions")
	}
	a, route := planningFixture(t)
	recovery := applyFixture(t, true)
	a.Control.Recovery = recovery.control.Recovery
	recoveryBinding := contract.BindingTableRow{SubjectKind: contract.RecoveryWrapSubject, SubjectID: a.Control.Recovery.RoleID, Binding: a.Control.Recovery.KMS}
	bindings := []contract.BindingTableRow{a.Authority}
	for i := 1; i < contract.CryptoMaxRecipients; i++ {
		binding := a.Authority
		binding.SubjectID = consumerID(fmt.Sprintf("retained union recipient %03d", i))
		binding.Binding.BindingID = consumerID(fmt.Sprintf("retained union binding %03d", i))
		binding.Binding.BindingIncarnationID = consumerID(fmt.Sprintf("retained union binding incarnation %03d", i))
		bindings = append(bindings, binding)
	}
	base := *a.Targets[0].Current
	a.Targets = nil
	for i := range ordinary {
		if ordinary[i] > len(bindings) || current[i] < 1 || current[i] > ordinary[i] {
			t.Fatal("invalid access fixture count")
		}
		name := fmt.Sprintf("retained-%03d", i)
		var raw []byte
		if values != nil {
			name, raw = values[i].name, values[i].raw
		}
		core := base.Core
		core.Name, core.ContentLength, core.RetainedLength = name, uint32(len(raw)), uint32(len(raw))
		core.EntryIncarnationID = consumerID(name + " incarnation")
		core.ValueStateID = consumerID(name + " material")
		core.DataKeyID, core.CommitmentKeyID = consumerID(name+" data"), consumerID(name+" commitment")
		payload, keys, err := custody.SealValue(core, raw)
		if err != nil {
			t.Fatal(err)
		}
		selection := base
		selection.Slot, selection.Core, selection.Payload = uint16(i), core, payload
		selection.Entry = contract.ValueEntry{Name: name, Incarnation: core.EntryIncarnationID, ValueState: core.ValueStateID,
			OriginSnapshot: core.OriginSnapshotID, OriginTransition: core.OriginTransitionID,
			ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
		for _, binding := range bindings[:current[i]] {
			selection.Entry.Recipients = append(selection.Entry.Recipients, binding.SubjectID)
		}
		slices.SortFunc(selection.Entry.Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		selection.Access = contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: contract.ValueMaterialKind, MaterialID: core.ValueStateID, PackageCheck: payload.PackageCheck}
		for _, binding := range append(slices.Clone(bindings[:ordinary[i]]), recoveryBinding) {
			wrapCore, err := custody.ValueWrapCore(core, binding)
			if err != nil {
				clear(keys[:cap(keys)])
				t.Fatal(err)
			}
			wrap, err := custody.Wrap(wrapCore, binding.Binding, keys)
			if err != nil {
				clear(keys[:cap(keys)])
				t.Fatal(err)
			}
			selection.Access.MaterialContextDigest = wrapCore.MaterialContextDigest
			selection.Access.Wraps = append(selection.Access.Wraps, wrap)
		}
		clear(keys[:cap(keys)])
		slices.SortFunc(selection.Access.Wraps, func(a, b contract.WrapRow) int {
			if a.SubjectKind != b.SubjectKind {
				return int(a.SubjectKind) - int(b.SubjectKind)
			}
			return bytes.Compare(a.SubjectID[:], b.SubjectID[:])
		})
		refreshConsumerSelection(t, &selection)
		if _, err := contract.AccessRecordLength(selection.Access); err != nil {
			t.Fatal("invalid retained union row", err)
		}
		if _, _, ok := checkConsumerSelection(selection, a.Control.Provider); !ok {
			t.Fatal("invalid current selection fixture")
		}
		a.Targets = append(a.Targets, contract.PlanningTarget{
			Input:              contract.PlanningInput{Name: name, Form: contract.PlanningRetained, Retained: contract.RetainedSecretInput{Incarnation: core.EntryIncarnationID, Material: core.ValueStateID}},
			ProposedRecipients: []contract.ID{a.Authority.SubjectID}, CurrentPresent: true, CurrentValueSource: contract.Supplied, CurrentConfidentialityClass: contract.Secret, Current: &selection,
		})
	}
	return a, route
}

// full_only: false
func TestPlanningRetainedAccessUnionKeepsCurrentMembershipBound(t *testing.T) {
	t.Run("retained-union-exceeds-current-only-wrap-count", func(t *testing.T) {
		ordinary, current := make([]int, 18), make([]int, 18)
		for i := range ordinary {
			ordinary[i], current[i] = 256, 1
		}
		ordinary[17] = 239
		a, route := planningRetainedAccessFixture(t, ordinary, current, nil)
		wraps, members := 0, 0
		for _, target := range a.Targets {
			wraps += len(target.Current.Access.Wraps)
			members += len(target.Current.Entry.Recipients)
		}
		if wraps != 4609 || members != 18 {
			t.Fatal("wrong independent fixture dimensions", wraps, members)
		}
		owner, err := NewPlanningCustody(planningContext(t), route, a)
		if owner != nil {
			owner.Close()
		}
		if err != nil {
			t.Fatal("authenticated retained-reader union was limited as current-only access", err)
		}
		if route.privateCalls != 0 || route.publicCalls != 0 {
			t.Fatal("admission used a key route")
		}
	})
	t.Run("current-memberships-exceed-complete-set-bound", func(t *testing.T) {
		ordinary, current := make([]int, 65), make([]int, 65)
		for i := range ordinary {
			ordinary[i], current[i] = 64, 64
		}
		ordinary[64], current[64] = 1, 1
		a, route := planningRetainedAccessFixture(t, ordinary, current, nil)
		wraps, members := 0, 0
		for _, target := range a.Targets {
			wraps += len(target.Current.Access.Wraps)
			members += len(target.Current.Entry.Recipients)
		}
		if wraps != 4162 || members != 4097 {
			t.Fatal("wrong independent fixture dimensions", wraps, members)
		}
		owner, err := NewPlanningCustody(planningContext(t), route, a)
		if owner != nil {
			owner.Close()
		}
		if err != ErrAdmission {
			t.Fatal("actual current-membership overflow was admitted", err)
		}
		if route.privateCalls != 0 || route.publicCalls != 0 {
			t.Fatal("refused admission used a key route")
		}
	})
}

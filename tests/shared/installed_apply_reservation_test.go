package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

type installedApplyReservationStore struct {
	contract.Store
	keys  map[string]bool
	reads int
}

func (s *installedApplyReservationStore) Read(ctx context.Context, key string, maximum uint32) contract.ReadResult {
	if s.keys[key] {
		s.reads++
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
	}
	return s.Store.Read(ctx, key, maximum)
}

// full_only: false
func TestInstalledApplyReservationPreservesSelectedReadFailureCategory(t *testing.T) {
	for _, condition := range []string{"unavailable", "cancelled"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f := newInstalledApplyTestFixture(t, ctx, contract.AWS, false)
			s := f.selected
			input := []ApplyEntryInput{{Name: "plain", Recipients: []contract.ID{s.admission.recipient}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("value")}}
			public, result := s.compareEntryInputs(input)
			if public == nil {
				t.Fatal(result)
			}
			deadline, _ := ctx.Deadline()
			parent, owner, result := s.installedApplyComparison(ctx, public, ApplyInstallation{}, nil, deadline)
			if owner != nil || result.Outcome != 0 {
				t.Fatal("plain reservation precondition", result)
			}
			c, result := s.Compare(ctx, input, parent)
			if c == nil {
				t.Fatal("changed reservation precondition", result)
			}
			before, err := s.receiptWindows(ctx)
			if err != nil {
				t.Fatal(err)
			}
			c.applyReceipt = &installedApplyReceipt{before: before}
			p, err := planTransition(ctx, c)
			if err != nil {
				t.Fatal(err)
			}
			c.applyReceipt.subjects, err = installedApplyChangedSubjects(c, p)
			if err != nil {
				t.Fatal(err)
			}
			fault := &installedApplyReservationStore{Store: s.store, keys: make(map[string]bool)}
			for _, ref := range s.root.RequiredSupport {
				key, err := format.Key(s.admission.store.Prefix, ref)
				if err != nil {
					t.Fatal(err)
				}
				fault.keys[key] = true
			}
			s.store = fault
			reservationCtx := ctx
			if condition == "cancelled" {
				var stop context.CancelFunc
				reservationCtx, stop = context.WithCancel(ctx)
				stop()
			}
			err = s.reserveInstalledApplyReceipt(reservationCtx, c, p)
			original, selected := selectedReadResult(err)
			if !selected || original.Outcome != EvidenceUnavailable || original.Reason != ReadUnavailable || condition == "unavailable" && fault.reads == 0 {
				t.Fatal("fault did not reach exact selected reservation read", err, original, fault.reads)
			}
			if got := installedApplyPreparationFailure(err); got != original {
				t.Fatal("reservation changed original selected-read category", condition, got, original)
			}
		})
	}
}

// full_only: false
func TestInstalledApplyReservationDistinguishesCapacityAndInvalidRelation(t *testing.T) {
	if got := installedApplyPreparationFailure(contract.ErrRecordCapacity); got != refused(CapacityExceeded) {
		t.Fatal("true receipt capacity category", got)
	}
	if got := installedApplyPreparationFailure(contract.ErrRecord); got != refused(InvalidRelation) {
		t.Fatal("invalid receipt relation became capacity refusal", got)
	}
}

// full_only: false
func TestInstalledApplySelectionPreservesOutputReadFailureCategory(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.AWS, false)
	s := f.selected
	installation := ApplyInstallation{ExpectedControl: currentControlOf(s), DesiredRecipients: currentApplyRecipients(s.registry())}
	fault := &installedApplyReservationStore{Store: s.store, keys: make(map[string]bool)}
	for _, ref := range s.root.RequiredSupport {
		key, err := format.Key(s.admission.store.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		fault.keys[key] = true
	}
	s.store = fault
	_, original := s.currentOutputConfigurationForApply(ctx)
	if original.Outcome != EvidenceUnavailable || original.Reason != ReadUnavailable || fault.reads == 0 {
		t.Fatal("fault did not reach selected output read", original, fault.reads)
	}
	if got := s.installedApplySelectionResult(ctx, installation); got != original {
		t.Fatal("selection changed original output-read category", got, original)
	}
}

// full_only: false
func TestInstalledApplyReceiptReadPreservesCancellationCategory(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.AWS, false)
	cancelled, stop := context.WithCancel(ctx)
	stop()
	_, err := f.selected.receiptWindows(cancelled)
	original, selected := selectedReadResult(err)
	if !selected || original.Outcome != EvidenceUnavailable || original.Reason != ReadUnavailable {
		t.Fatal("cancelled receipt read precondition", err, original)
	}
	if _, got := f.selected.installedApplyReceiptWindows(cancelled); got != original {
		t.Fatal("apply receipt read changed cancellation category", got, original)
	}
}

// full_only: false
func TestInstalledApplyPlanPreservesSelectedReadCancellationCategory(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.AWS, false)
	s := f.selected
	input := []ApplyEntryInput{{Name: "plain", Recipients: []contract.ID{s.admission.recipient}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("value")}}
	public, result := s.compareEntryInputs(input)
	if public == nil {
		t.Fatal(result)
	}
	deadline, _ := ctx.Deadline()
	parent, owner, result := s.installedApplyComparison(ctx, public, ApplyInstallation{}, nil, deadline)
	if owner != nil || result.Outcome != 0 {
		t.Fatal("plain plan precondition", result)
	}
	c, result := s.Compare(ctx, input, parent)
	if c == nil {
		t.Fatal("changed plan precondition", result)
	}
	before, err := s.receiptWindows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c.applyReceipt = &installedApplyReceipt{before: before}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	_, err = planTransition(cancelled, c)
	original, selected := selectedReadResult(err)
	if !selected || original.Outcome != EvidenceUnavailable || original.Reason != ReadUnavailable {
		t.Fatal("cancelled plan did not preserve selected-read failure", err, original)
	}
	if got := installedApplyPreparationFailure(err); got != original {
		t.Fatal("apply plan changed original selected-read category", got, original)
	}
}

// full_only: false
func TestInstalledApplyComparisonPreservesSelectedReadCancellationCategory(t *testing.T) {
	for _, condition := range []string{"cached support", "cold support"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f := newInstalledApplyTestFixture(t, ctx, contract.AWS, false)
			s := f.selected
			input := []ApplyEntryInput{suppliedSecret(t, f.env, "alpha", "comparison cancellation source", custody.StandardValue, s.admission.recipient)}
			c, result := s.compareEntryInputs(input)
			if c == nil {
				t.Fatal("legal sealed comparison precondition", result)
			}
			witness, err := s.generatedSupportTransition(ctx, c, nil)
			if err != nil || witness == nil {
				t.Fatal("authenticated support precondition", err)
			}
			if condition == "cached support" {
				g, err := s.selectedGeneratedWork(ctx)
				root, ok := s.generatedSelectionRoot()
				if err != nil || !ok {
					t.Fatal("authenticated derived cache precondition", err)
				}
				// Retain the real validated projection for this exact immutable
				// root; no selected bytes or authority facts change.
				s.generatedWork = &validatedGeneratedSelection{session: s, root: root, selection: g}
			} else {
				s.generatedWork = nil
			}
			cancelled, stop := context.WithCancel(ctx)
			stop()
			_, err = s.receiptWindows(cancelled)
			original, selected := selectedReadResult(err)
			if !selected || original.Outcome != EvidenceUnavailable || original.Reason != ReadUnavailable {
				t.Fatal("cancelled selected receipt precondition", err, original)
			}
			var custodyCalls int
			installation := ApplyInstallation{AdmitCustody: func(context.Context, contract.CryptoCompareRequest, contract.ControlCore, []contract.RecipientRecord, []contract.MembershipRow, contract.DescriptorVector, *contract.GeneratedSupportTransition, contract.ID, contract.MutationReceiptWindows, uint8, time.Time) (*InstalledApplyCustody, error) {
				custodyCalls++
				return nil, contract.ErrRecord
			}}
			deadline, _ := cancelled.Deadline()
			parent, owner, got := s.installedApplyComparison(cancelled, c, installation, nil, deadline)
			if parent != nil || owner != nil || custodyCalls != 0 {
				t.Fatal("cancelled support reached private custody", custodyCalls)
			}
			if got != original {
				t.Fatal("comparison admission changed selected-read cancellation category", got, original)
			}
		})
	}
}

// full_only: false
func TestInstalledApplyNoWorkFinalizerPreservesCancellationCategory(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.AWS, false)
	s := f.selected
	c, result := s.compareEntryInputs(nil)
	if c == nil {
		t.Fatal("empty complete requested set precondition", result)
	}
	deadline, _ := ctx.Deadline()
	parent, owner, result := s.installedApplyComparison(ctx, c, ApplyInstallation{}, nil, deadline)
	if parent == nil || owner != nil || result.Outcome != 0 {
		t.Fatal("real no-work comparison admission", result)
	}
	parent.trackNoWork = true
	comparison, result := s.Compare(ctx, nil, parent)
	if comparison != nil || result.Outcome != Unchanged || parent.noWorkBasis.Digest.IsZero() {
		t.Fatal("admitted equality basis precondition", result)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	operation, identity, err := s.installedApplyNoWorkIdentity(cancelled, parent)
	got := installedApplyPreparationFailure(err)
	if !operation.IsZero() || !identity.IsZero() || !errors.Is(err, context.Canceled) || got != failure(EvidenceUnavailable, ReadUnavailable) {
		t.Fatal("no-work finalizer changed canceled context into an invalid relation", err, got)
	}
}

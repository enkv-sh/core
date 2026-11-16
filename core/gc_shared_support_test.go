package core

import (
	"bytes"
	"slices"
	"strconv"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

// full_only: false
func TestGCSharedSupportPreservesPendingOwnerAndExactEnding(t *testing.T) {
	s, first := gcStateFixture(t, true)
	_, originalProgress, err := s.selectedGCPlan(first.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	beforeReceipts, err := s.receiptWindows(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	second := gcTestPlan(t, s, "shared-second")
	s = gcTestSelectState(t, s, second, gcTestProgress(t, second), contract.GCSelect, true, true)
	var shared format.Ref
	for _, page := range s.adminIndex.Pages {
		if len(page.Rows) == 2 && page.Rows[0].Kind == contract.GCPlanSupportKind && page.Rows[1].Kind == contract.GCPlanSupportKind {
			shared = page.Ref
		}
	}
	if shared.Object.IsZero() {
		t.Fatal("selected plans do not share a physical support page")
	}
	_, progress, err := s.selectedGCPlan(first.OperationID)
	if err != nil || !contract.GCProgressEqual(progress, originalProgress) {
		t.Fatal("packing changed unrelated pending rights", err)
	}
	currentReceipts, err := s.receiptWindows(t.Context())
	if err != nil || !slices.Equal(beforeReceipts.Order, currentReceipts.Order) || !slices.Equal(beforeReceipts.Successes, currentReceipts.Successes) || !slices.Equal(beforeReceipts.Failures, currentReceipts.Failures) {
		t.Fatal("GC selection changed receipt history or common order", err)
	}
	s.admission.endWorkInvocation = gcTestID("shared-end-invocation")
	ids := endWorkIDs{operation: gcTestID("shared-end-op"), transition: gcTestID("shared-end-transition"), snapshot: gcTestID("shared-end-snapshot"), revision: gcTestID("shared-end-revision"), receipts: gcTestID("shared-end-receipts"), receiptIndex: gcTestID("shared-end-receipt-index")}
	candidate, next, err := s.deriveEndWorkCandidate(t.Context(), second.OperationID, ids)
	if err != nil || candidate == nil || next == nil {
		t.Fatal("end shared GC owner", err)
	}
	if !slices.Contains(next.root.RequiredSupport, shared) || !next.root.ActiveGC.IsZero() || next.root.GCPlans.Count != 1 || len(next.adminIndex.Groups) != len(s.adminIndex.Groups)-1 {
		t.Fatal("ending removed shared support or unrelated ownership")
	}
	if next.root.CurrentAccess.AccessRoot != s.root.CurrentAccess.AccessRoot || next.root.ValueEntryCount != s.root.ValueEntryCount {
		t.Fatal("ending changed current values or access")
	}
	signer := testtrust.New(t, s.admission.store.Family, s.admission.trust)
	candidate, result := s.persistCandidate(t.Context(), candidate, signer)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("persist shared ending", result)
	}
	selected, result := s.selectCandidate(t.Context(), candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("select shared ending", result)
	}
	selected, result = Open(t.Context(), OpenContext{admission: &selected.admission}, selected.store)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("cold complete read after shared ending", result)
	}
	gotPlan, gotProgress, err := selected.selectedGCPlan(first.OperationID)
	wantBytes, _ := contract.EncodeGCPlan(first)
	gotBytes, _ := contract.EncodeGCPlan(gotPlan)
	if err != nil || !bytes.Equal(wantBytes, gotBytes) || !contract.GCProgressEqual(originalProgress, gotProgress) {
		t.Fatal("cold selected ending changed retained shared plan", err)
	}
	afterReceipts, err := selected.receiptWindows(t.Context())
	if err != nil || len(afterReceipts.Order) != len(beforeReceipts.Order)+1 || !slices.Equal(afterReceipts.Order[:len(beforeReceipts.Order)], beforeReceipts.Order) {
		t.Fatal("ending replaced prior receipt order", err)
	}
	for _, prior := range append(slices.Clone(beforeReceipts.Successes), beforeReceipts.Failures...) {
		all := append(slices.Clone(afterReceipts.Successes), afterReceipts.Failures...)
		if !slices.Contains(all, prior) {
			t.Fatal("ending changed an original receipt body", prior.OperationID)
		}
	}
}

func gcTestSharedSpentState(t testing.TB) (*StateSession, contract.GCPlan, contract.GCPlan, format.Ref) {
	t.Helper()
	s, first := gcStateFixture(t, false)
	spend := func(s *StateSession, plan contract.GCPlan) *StateSession {
		_, progress, err := s.selectedGCPlan(plan.OperationID)
		if err != nil {
			t.Fatal(err)
		}
		progress.Ordinal++
		progress.Targets[0].Consumed = 1
		s = gcTestSelectState(t, s, plan, progress, contract.GCReserve, true)
		progress.Ordinal++
		progress.Targets[0].Disposition = contract.GCTargetUnknown
		return gcTestSelectState(t, s, plan, progress, contract.GCRecordProgress, true)
	}
	s = spend(s, first)
	_, progress, err := s.selectedGCPlan(first.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	s = gcTestSelectState(t, s, first, progress, contract.GCClose, false)
	second := gcTestPlan(t, s, "shared-spent-second")
	s = gcTestSelectState(t, s, second, gcTestProgress(t, second), contract.GCSelect, true, true)
	s = spend(s, second)
	for _, page := range s.adminIndex.Pages {
		if len(page.Rows) == 2 && page.Rows[0].Kind == contract.GCPlanSupportKind && page.Rows[1].Kind == contract.GCPlanSupportKind {
			return s, first, second, page.Ref
		}
	}
	t.Fatal("spent plans have no shared page")
	return nil, contract.GCPlan{}, contract.GCPlan{}, format.Ref{}
}

// full_only: false
func TestGCSharedSupportEndingOrdersKeepSpentUnknownRights(t *testing.T) {
	for _, missing := range []bool{false, true} {
		for _, reverse := range []bool{false, true} {
			t.Run("missing="+strconv.FormatBool(missing)+"/reverse="+strconv.FormatBool(reverse), func(t *testing.T) {
				s, first, second, shared := gcTestSharedSpentState(t)
				store := s.store.(*observationSelectionStore)
				beforeReceipts, err := s.receiptWindows(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if missing {
					key, err := format.Key(s.admission.store.Prefix, shared)
					if err != nil {
						t.Fatal(err)
					}
					delete(store.objects, key)
				}
				order := []contract.GCPlan{first, second}
				if reverse {
					slices.Reverse(order)
				}
				for step, plan := range order {
					admitted := OpenContext{admission: &s.admission}
					opened, result := openAdministrative(t.Context(), admitted, store)
					if opened == nil || result.Outcome != ObservedCurrent {
						t.Fatal("cold administrative shared read", result)
					}
					s = opened
					label := "shared-order/" + strconv.Itoa(step)
					s.admission.endWorkInvocation = gcTestID(label + "/invocation")
					ids := endWorkIDs{operation: gcTestID(label + "/op"), transition: gcTestID(label + "/transition"), snapshot: gcTestID(label + "/snapshot"), revision: gcTestID(label + "/revision"), receipts: gcTestID(label + "/receipts"), receiptIndex: gcTestID(label + "/receipt-index")}
					candidate, next, err := s.deriveEndWorkCandidate(t.Context(), plan.OperationID, ids)
					if err != nil || candidate == nil || next == nil {
						t.Fatal("derive shared exact ending", step, err)
					}
					if step == 0 {
						if !slices.Contains(next.root.RequiredSupport, shared) || next.root.GCPlans.Count != 1 {
							t.Fatal("first ending removed the shared physical page")
						}
						active := contract.ID{}
						if plan.OperationID == first.OperationID {
							active = second.OperationID
						}
						if next.root.ActiveGC != active {
							t.Fatal("first ending changed the unrelated active slot")
						}
						remaining := order[1].OperationID
						position := slices.IndexFunc(next.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == remaining })
						if position < 0 || next.adminIndex.Groups[position].GC == nil || next.adminIndex.Groups[position].GC.Targets[0].Consumed != 1 || next.adminIndex.Groups[position].GC.Targets[0].Disposition != contract.GCTargetUnknown || next.adminIndex.Groups[position].GC.Ordinal != 3 || next.adminIndex.Groups[position].GC.RemainingCount != 1 {
							t.Fatal("first ending reset surviving spent unknown rights")
						}
					}
					candidate, result = s.persistCandidate(t.Context(), candidate, testtrust.New(t, s.admission.store.Family, s.admission.trust))
					if candidate == nil || result.Outcome != ObservedCurrent {
						t.Fatal("persist shared order", step, result)
					}
					s, result = s.selectCandidate(t.Context(), candidate)
					if s == nil || result.Outcome != ObservedCurrent {
						t.Fatal("select shared order", step, result)
					}
				}
				if !s.root.ActiveGC.IsZero() || s.root.GCPlans != contract.EmptyGCOwnersDescriptor() || slices.Contains(s.root.RequiredSupport, shared) {
					t.Fatal("last ending retained shared continuation rights")
				}
				full, result := Open(t.Context(), OpenContext{admission: &s.admission}, store)
				if full == nil || result.Outcome != ObservedCurrent {
					t.Fatal("cold complete read after both endings", result)
				}
				afterReceipts, err := full.receiptWindows(t.Context())
				if err != nil || len(afterReceipts.Order) != len(beforeReceipts.Order)+2 || !slices.Equal(afterReceipts.Order[:len(beforeReceipts.Order)], beforeReceipts.Order) {
					t.Fatal("shared endings changed original common receipt order", err)
				}
			})
		}
	}
}

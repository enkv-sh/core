package core

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

// full_only: false
func TestInstalledGCAdministrativeListPlanApply(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		pending bool
		missing bool
		warned  bool
	}{{"active", false, false, false}, {"pending", true, false, false}, {"active missing plan", false, true, false}, {"pending missing plan", true, true, false}, {"active saturated GC warnings", false, false, true}, {"pending saturated GC warnings", true, false, true}} {
		t.Run(scenario.name, func(t *testing.T) {
			var s *StateSession
			var plan contract.GCPlan
			if scenario.warned {
				s, plan = gcTestSaturatedWarningState(t, scenario.pending)
			} else {
				s, plan = gcStateFixture(t, scenario.pending)
			}
			store, ok := s.store.(*observationSelectionStore)
			if !ok {
				t.Fatal("fixture does not own the selected Store")
			}
			if scenario.missing {
				for _, page := range s.adminIndex.Pages {
					if slices.ContainsFunc(page.Rows, func(row format.AdministrativeRowSummary) bool {
						return row.Kind == contract.GCPlanSupportKind && row.RecordID == plan.OperationID
					}) {
						key, err := format.Key(s.admission.store.Prefix, page.Ref)
						if err != nil {
							t.Fatal(err)
						}
						delete(store.objects, key)
					}
				}
			}
			ctx := installedAdministrativeTestContext(t)
			reader := &installedAdministrativeTestReader{store: store}
			list, err := NewInstalledAdministrativeReader(installedAdministrativeReadInput(s, reader), AdministrativeList)
			if err != nil {
				t.Fatal(err)
			}
			listed := list.List(ctx, gcTestID("installed-gc-list"))
			if err := list.Close(); err != nil {
				t.Fatal(err)
			}
			if listed.StateResult != AdministrativeSuccess || listed.List == nil {
				t.Fatal("selected GC not listed", listed.Result)
			}
			position := slices.IndexFunc(listed.List.Groups, func(group AuthorityGroup) bool { return group.GroupID == plan.OperationID })
			if position < 0 || !listed.List.Groups[position].Selectable || listed.List.Groups[position].OwnerKind != contract.AdministrativeGC || listed.List.Groups[position].GC == nil || listed.List.Groups[position].GC.PlanDigest != gcTestProgress(t, plan).PlanDigest {
				t.Fatal("listed GC lost mandatory ownership")
			}
			reader = &installedAdministrativeTestReader{store: store}
			planner, err := NewInstalledAdministrativeReader(installedAdministrativeReadInput(s, reader), AdministrativePlan)
			if err != nil {
				t.Fatal(err)
			}
			planned := planner.Plan(ctx, gcTestID("installed-gc-plan"), AdministrativePlanRequest{TargetGroupID: plan.OperationID, ArtifactPath: "/protected/gc-ending.json"})
			if err := planner.Close(); err != nil {
				t.Fatal(err)
			}
			warnings := uint8(WarningDiscardedExactEvidence | WarningPossibleStoreGarbage)
			if planned.StateResult != AdministrativeSuccess || planned.Plan == nil || planned.Plan.Preview.TargetKind != contract.AdministrativeGC || planned.Plan.Preview.WarningBits&warnings != warnings || !slices.Equal(planned.Plan.Preview.EndedGroupIDs, []contract.ID{plan.OperationID}) {
				t.Fatal("GC exact ending plan refused", planned.Result)
			}
			if scenario.warned && (s.root.WarningBits != warnings || planned.Plan.Preview.WarningBits != s.root.WarningBits) {
				t.Fatal("ending did not saturate existing GC warnings")
			}
			signer := testtrust.New(t, s.admission.store.Family, s.admission.trust)
			authority, err := NewInstalledAdministrativeAuthority(AdministrativeAuthorityInstallation{ExpectedDomain: s.admission.domain, ExpectedStore: s.admission.store, PublicBasis: s.admission.publicBasis(), CompositionID: generatedVectorID(204), SourcePins: installedAdministrativeTestPins(), Store: store, Trust: signer, CheckSource: func(context.Context) error { return nil }, CloseInstalled: func() error { return nil }})
			if err != nil {
				t.Fatal(err)
			}
			before := store.sends
			ended := authority.Apply(ctx, gcTestID("installed-gc-apply"), planned.Plan.Preview)
			if err := authority.Close(); err != nil {
				t.Fatal(err)
			}
			if ended.StateResult != AdministrativeWorkEnded || ended.End == nil || ended.Result.Outcome != ObservedCurrent || store.sends-before != 1 || signer.Calls() != 1 || ended.End.Receipt.AdministrativeTargetKind != contract.AdministrativeGC || ended.End.Receipt.WarningBits&uint64(warnings) != uint64(warnings) {
				t.Fatal("installed GC ending refused", ended.Result)
			}
			freshReader := &installedAdministrativeTestReader{store: store}
			fresh, err := NewInstalledAdministrativeReader(installedAdministrativeReadInput(s, freshReader), AdministrativeList)
			if err != nil {
				t.Fatal(err)
			}
			current := fresh.List(ctx, gcTestID("installed-gc-after"))
			if err := fresh.Close(); err != nil {
				t.Fatal(err)
			}
			if current.StateResult != AdministrativeSuccess || current.List == nil || slices.ContainsFunc(current.List.Groups, func(group AuthorityGroup) bool { return group.GroupID == plan.OperationID }) || current.CurrentWarningBits&warnings != warnings {
				t.Fatal("ended GC retained local continuation rights", current.Result)
			}
			if bytes.Equal(ended.End.ReceiptBytes, nil) {
				t.Fatal("exact administrative ending lost its receipt")
			}
		})
	}
}

func gcTestSaturatedWarningState(t testing.TB, pending bool) (*StateSession, contract.GCPlan) {
	t.Helper()
	s, old := gcStateFixture(t, false)
	s.admission.endWorkInvocation = gcTestID("warning-seed-invocation")
	ids := endWorkIDs{operation: gcTestID("warning-seed-op"), transition: gcTestID("warning-seed-transition"), snapshot: gcTestID("warning-seed-snapshot"), revision: gcTestID("warning-seed-revision"), receipts: gcTestID("warning-seed-receipts"), receiptIndex: gcTestID("warning-seed-receipt-index")}
	candidate, _, err := s.deriveEndWorkCandidate(t.Context(), old.OperationID, ids)
	if err != nil {
		t.Fatal("derive authentic warning predecessor", err)
	}
	candidate, result := s.persistCandidate(t.Context(), candidate, testtrust.New(t, s.admission.store.Family, s.admission.trust))
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("persist authentic warning predecessor", result)
	}
	s, result = s.selectCandidate(t.Context(), candidate)
	if s == nil || result.Outcome != ObservedCurrent || s.root.WarningBits != WarningDiscardedExactEvidence|WarningPossibleStoreGarbage {
		t.Fatal("select authentic warning predecessor", result)
	}
	plan := gcTestPlan(t, s, "warned")
	progress := gcTestProgress(t, plan)
	s = gcTestSelectState(t, s, plan, progress, contract.GCSelect, true)
	if pending {
		s = gcTestSelectState(t, s, plan, progress, contract.GCClose, false)
	}
	return s, plan
}

// full_only: false
func TestGCAdministrativeMandatoryIndexDamageRefuses(t *testing.T) {
	s, _ := gcStateFixture(t, false)
	store := s.store.(*observationSelectionStore)
	key, err := format.Key(s.admission.store.Prefix, s.root.AdministrativeIndex)
	if err != nil {
		t.Fatal(err)
	}
	broken := bytes.Clone(store.objects[key])
	if len(broken) == 0 {
		t.Fatal("fixture has no encoded mandatory index")
	}
	broken[len(broken)-1] ^= 1
	store.objects[key] = broken
	reader := &installedAdministrativeTestReader{store: store}
	session, err := NewInstalledAdministrativeReader(installedAdministrativeReadInput(s, reader), AdministrativeList)
	if err != nil {
		t.Fatal(err)
	}
	out := session.List(installedAdministrativeTestContext(t), gcTestID("damaged-mandatory-index"))
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if out.Result.Outcome != IntegrityFailure || out.List != nil {
		t.Fatal("administrative reader accepted damaged mandatory GC metadata", out.Result)
	}
}

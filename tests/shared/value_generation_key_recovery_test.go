package core

import (
	"context"
	"fmt"
	"testing"

	"enkv.sh/core/contract"
)

// This table is deliberately independent of the succession implementation.
// It checks that every occupied generated owner contributes its exact retained
// material/consumer relation to the replacement engine's selected projection.
// TestGeneratedActualLossAtCreateInboxAndRecordedCuts checks physical inbox cuts.
// Process-connected replacement tests exercise the resulting private opens.
// full_only: false
func TestGeneratedKeyRecoveryMatrixCoversEveryOccupiedOwner(t *testing.T) {
	selectedState := func(t testing.TB, retirement bool) *StateSession {
		t.Helper()
		ctx := context.Background()
		env, _ := genesisEnvironment(t, contract.GCP, false)
		run := newScenarioRun(t, ctx, env)
		f := newEnvironmentFixture(t, ctx, run.env, nil, false)
		s := selectPrivateGeneratedOperation(t, env, f.session,
			generatedPlanInputForGenerations(t, f.session, generatedVectorID(210), []string{"generated"}, defaultGeneratedFixtureProfile()), "matrix initial")
		if retirement {
			old := *s.valueEntry(0)
			profile := defaultGeneratedFixtureProfile()
			profile.ConfigContractID, profile.ResourceContractID = generatedVectorID(211), generatedVectorID(212)
			s = selectPrivateGeneratedOperation(t, env, s,
				generatedStatePlanInput(t, s, generatedVectorID(214), []string{old.Name}, profile, old.Generated.Epoch+1,
					map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: old}), "matrix rotation")
			if s.valueEntry(0).Generated.RetiringDutyPresent != 1 || s.root.Generated.Retiring != 1 {
				t.Fatal("matrix rotation omitted its selected retirement Duty")
			}
		}
		if s.root.Generated.GeneratedCurrent != 1 || s.root.SecretCount != 1 || !s.root.Generated.ActiveOwner.IsZero() {
			t.Fatal("matrix selected generation is not actual current secret state")
		}
		checkFreshGeneratedProcess(t, env.Store.(*memoryStore), s)
		return s
	}
	type stateCase struct {
		name  string
		state func(*testing.T) *StateSession
	}
	cases := []stateCase{
		{"create-transmitted-material-projection", func(t *testing.T) *StateSession { return generatedReservationState(t) }},
		{"successor-installed-before-entry", func(t *testing.T) *StateSession {
			s, _ := generatedPlannedResidueSuccessorState(t)
			return s
		}},
		{"successor-transmitted", func(t *testing.T) *StateSession {
			s, _, _ := generatedBoundResidueSuccessorState(t)
			return s
		}},
		{"result-recorded-unselected-cleanup", func(t *testing.T) *StateSession { s, _ := generatedUnselectedCleanupState(t, 0); return s }},
		{"final-candidate-predecessor", func(t *testing.T) *StateSession { s, _ := generatedUnselectedCleanupState(t, 1); return s }},
		{"selected-generated-member", func(t *testing.T) *StateSession { return selectedState(t, false) }},
		{"selected-generation-with-retirement", func(t *testing.T) *StateSession { return selectedState(t, true) }},
		{"active-create-with-detached-retirement", func(t *testing.T) *StateSession {
			s, _ := generatedActiveRetirementState(t)
			return s
		}},
		{"retirement-transmitted", func(t *testing.T) *StateSession { s, _, _, _ := generatedEnteredRetirementState(t, false); return s }},
		{"retirement-recorded", func(t *testing.T) *StateSession { s, _, _, _ := generatedEnteredRetirementState(t, true); return s }},
		{"retirement-unknown", func(t *testing.T) *StateSession { s, _, _ := generatedParkedRetirementState(t); return s }},
		{"create-hazard", func(t *testing.T) *StateSession { s, _, _ := generatedCreateHazardState(t, 0, 0); return s }},
		{"retirement-hazard", func(t *testing.T) *StateSession { s, _, _, _ := generatedDeleteHazardState(t, 0); return s }},
		{"cleanup-pending-release", func(t *testing.T) *StateSession {
			s, _, _ := generatedInboxReleaseState(t, 0, contract.GeneratedReleasePending)
			return s
		}},
		{"cleanup-unknown-release", func(t *testing.T) *StateSession {
			s, _, _ := generatedInboxReleaseState(t, 0, contract.GeneratedReleaseUnknown)
			return s
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.state(t)
			g, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal("occupied generated closure refused", err)
			}
			indexes, err := s.generatedSnapshotPageIndexes()
			if err != nil || len(indexes) == 0 {
				t.Fatal("generated support is absent from the replacement snapshot", err)
			}
			target := contract.BindingTableRow{SubjectKind: 1, SubjectID: s.admission.recipient, Binding: generatedPublicBinding(t, 245)}
			rows, err := s.replacementMaterialRows(t.Context(), 0, 1, target)
			if err != nil || len(rows) != len(g.materials) || len(rows) != int(s.root.AccessRecordCount) {
				t.Fatalf("replacement coverage differs: rows=%d materials=%d access=%d", len(rows), len(g.materials), s.root.AccessRecordCount)
			}
			seen := make(map[string]bool, len(rows))
			for _, row := range rows {
				key := fmt.Sprintf("%d/%x", row.Coverage.MaterialKind, row.Coverage.MaterialID)
				if seen[key] || row.Coverage.RequiredConsumerDigest.IsZero() || row.Coverage.BeforeAccessDigest.IsZero() ||
					len(row.Coverage.TargetBindingIndices) != 1 || row.Coverage.TargetBindingIndices[0] != 1 {
					t.Fatal("replacement row lost exact material, consumers or target", key)
				}
				seen[key] = true
			}
		})
	}
}

// full_only: false
func TestGeneratedRecoveryKEKReplacementCoversCurrentAndRetainedMaterial(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state func(testing.TB) *StateSession
	}{
		{"selected", func(t testing.TB) *StateSession { s, _, _ := generatedCanonicalState(t, true); return s }},
		{"hazard", func(t testing.TB) *StateSession { s, _, _ := generatedCreateHazardState(t, 2, 0); return s }},
		{"pending-release", func(t testing.TB) *StateSession {
			s, _, _ := generatedInboxReleaseState(t, 2, contract.GeneratedReleasePending)
			return s
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.state(t)
			g, err := s.selectedGeneratedWork(context.Background())
			if err != nil || s.root.CurrentAccess.Core.Recovery == nil {
				t.Fatal("enabled recovery closure refused", err)
			}
			recovery := s.root.CurrentAccess.Core.Recovery
			target := contract.BindingTableRow{SubjectKind: 2, SubjectID: recovery.RoleID, Binding: generatedPublicBinding(t, 246)}
			rows, err := s.replacementMaterialRows(t.Context(), 0, 1, target)
			if err != nil || len(rows) != len(g.materials) || len(rows) != int(s.root.AccessRecordCount) {
				t.Fatal("recovery replacement omitted current or retained generated material", err, len(rows), len(g.materials), s.root.AccessRecordCount)
			}
		})
	}
}

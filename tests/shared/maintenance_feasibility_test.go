package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

type maintenanceReadClose struct {
	PlanningCustody
	closed *bool
}

func (c *maintenanceReadClose) Close() { c.PlanningCustody.Close(); *c.closed = true }

// full_only: false
func TestMaintenanceFeasibilitySeparatesReadFromMutation(t *testing.T) {
	for _, operation := range []string{"retire", "rekey"} {
		for _, condition := range []string{"matching-pending-different", "mismatch-equal", "mismatch-changed", "original-after-removal"} {
			if operation == "retire" && condition == "original-after-removal" {
				continue
			}
			t.Run(operation+"/"+condition, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
				authority := f.selected.admission.recipient
				var reader contract.ID
				for _, row := range f.selected.registry() {
					if row.RecipientID != authority {
						reader = row.RecipientID
						break
					}
				}
				if reader.IsZero() {
					t.Fatal("current reader absent")
				}
				original := suppliedSecret(t, f.env, "target", "maintenance original seal", custody.StandardValue, authority, reader)
				setup := f.engine(t, f.selected, []ApplyEntryInput{original}, nil)
				if got := setup.Apply(ctx, fixtureID(f.env.Domain, "maintenance feasibility setup"), []ApplyEntryInput{original}); got.Result.Outcome != ObservedCurrent {
					t.Fatal(got.Result)
				}
				setup.Close()
				selected := f.open(t, ctx)
				ref := installedSecretAccessTestRef(t, selected, reader)
				if condition == "original-after-removal" {
					got := installedRetirementTestRun(t, ctx, f, selected, ref, "prior maintenance removal", nil)
					if got.Result.Outcome != ObservedCurrent {
						t.Fatal(got.Result)
					}
					selected = f.open(t, ctx)
				}
				proposed := original
				if condition == "matching-pending-different" || condition == "mismatch-changed" {
					members := []contract.ID{authority, reader}
					if operation == "retire" && condition == "matching-pending-different" {
						members = []contract.ID{authority}
					}
					proposed = suppliedSecret(t, f.env, "target", "maintenance pending seal", custody.AlternateStandardValue, members...)
				}
				validator := installedApplyGeneratedValidator(t, selected)
				m := installedMaintenanceTestInstallation(t, f, selected, validator, contract.PlanningInput{Name: "target", Form: contract.PlanningSealed, SealedInput: proposed.InputBytes})
				if operation == "rekey" && (condition == "mismatch-equal" || condition == "mismatch-changed") {
					m.Configuration.Entries.Value[0].Memberships.Value = []contract.ID{authority}
					var err error
					m.InputDigest, err = PlanningInputDigest(m.Configuration, m.Inputs)
					if err != nil {
						t.Fatal(err)
					}
				}
				reads, mutations := 0, 0
				readClosed := false
				m.AdmitFeasibility = func(ctx context.Context, q contract.PlanningAdmission) (PlanningCustody, error) {
					reads++
					want := contract.PlanningEquality
					if operation == "retire" {
						want = contract.PlanningRetirementFeasibility
					}
					if q.Options.Purpose != want || q.HEADDigest != contract.Hash(selected.body) || q.Root != selected.head.Core.Root || q.Sources.Proposed != maintenanceSourcePair(m.SourcePins) {
						t.Fatal("read admission lost exact source or predecessor")
					}
					owner, err := f.keys.NewPlanningCustody(ctx, q)
					if err != nil {
						return nil, err
					}
					return &maintenanceReadClose{PlanningCustody: owner, closed: &readClosed}, nil
				}
				var delivered MaintenanceReadback
				publish := m.PublishSuccessor
				m.PublishSuccessor = func(ctx context.Context, c MaintenanceSuccessor) (MaintenanceReadback, error) {
					r, err := publish(ctx, c)
					delivered = r
					return r, err
				}
				store := f.env.Store.(*memoryStore)
				cas := store.cas
				var got PublicApplyResult
				if operation == "retire" {
					installation := installedRetirementTestInstallation(t, f, selected, ref, func(q contract.CryptoCompareRequest, _ uint16) {
						mutations++
						if len(q.SealedInputs) != 0 || reads != 0 && !readClosed {
							t.Fatal("mutation admitted before read owner joined or with sealed proposals")
						}
					})
					installation.Maintenance = m
					engine, err := NewInstalledRecipientRetirement(installation)
					if err != nil {
						t.Fatal(err)
					}
					got = engine.Retire(ctx, fixtureID(f.env.Domain, operation+condition))
					engine.Close()
				} else {
					installation := installedSecretAccessTestInstallation(t, f, selected, validator, nil, nil)
					installation.Maintenance = m
					admit := installation.AdmitCustody
					installation.AdmitCustody = func(ctx context.Context, q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, plain []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, revision contract.ID, before contract.MutationReceiptWindows, warnings uint8, deadline time.Time) (*InstalledApplyCustody, error) {
						mutations++
						if len(q.SealedInputs) != 0 || reads != 0 && !readClosed {
							t.Fatal("mutation admitted before read owner joined or with sealed proposals")
						}
						return admit(ctx, q, control, current, plain, support, witness, revision, before, warnings, deadline)
					}
					engine, err := NewInstalledEnvelopeRekey(EnvelopeRekeyInstallation{AccessMutationInstallation: installation.AccessMutationInstallation, AdmitCustody: installation.AdmitCustody, Name: "target"})
					if err != nil {
						t.Fatal(err)
					}
					got = engine.Rekey(ctx, fixtureID(f.env.Domain, operation+condition))
					engine.Close()
				}
				wantReads := 1
				if condition == "matching-pending-different" {
					wantReads = 0
				}
				if reads != wantReads || reads != 0 && !readClosed {
					t.Fatal("wrong read-owner lifecycle", reads, readClosed)
				}
				if condition == "mismatch-changed" {
					if got.Result.Outcome == ObservedCurrent || mutations != 0 || store.cas != cas || got.Successor != nil {
						t.Fatal("different mismatched source reached mutation", got.Result, mutations)
					}
					return
				}
				if got.Result.Outcome != ObservedCurrent || mutations != 1 || len(delivered.Inputs) != 1 || !bytes.Equal(delivered.Inputs[0].SealedInput, proposed.InputBytes) {
					t.Fatal("feasible source was changed or refused", got.Result, mutations)
				}
				for _, page := range delivered.Correlation.CandidatePages {
					if uint64(len(page.Body)) > uint64(selected.root.ValueEntryPages[page.Index].Length) {
						t.Fatal("maintenance codec page grew beyond admitted predecessor length")
					}
				}
			})
		}
	}
}

// full_only: false
func TestMaintenanceSourcePreflightRefusesUnadoptableInputs(t *testing.T) {
	for _, condition := range []string{"stale-pin", "absent-preparation", "capacity"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f, _, _ := maintenanceObserverFixture(t, ctx, false)
			selected := f.open(t, ctx)
			private := 0
			i := installedSecretAccessTestInstallation(t, f, selected, installedApplyGeneratedValidator(t, selected), nil, &private)
			m := i.Maintenance
			switch condition {
			case "stale-pin":
				m.Inputs[0].Retained.Material = fixtureID(f.env.Domain, "stale maintenance material")
			case "absent-preparation":
				rows := installedApplyPreparedRecipient(t, selected, "absent maintenance preparation")
				for _, row := range rows {
					if _, current := selected.selectedRecipientSlot(row.Recipient.RecipientID); current == nil {
						m.Recipients = append(m.Recipients, row)
					}
				}
			case "capacity":
				m.SourcePins.GeneratedLength = contract.MaxConfigurationPairLength - m.SourcePins.EditableLength
			}
			var err error
			m.InputDigest, err = PlanningInputDigest(m.Configuration, m.Inputs)
			if err != nil {
				t.Fatal(err)
			}
			reads := 0
			m.AdmitFeasibility = func(context.Context, contract.PlanningAdmission) (PlanningCustody, error) {
				reads++
				return nil, contract.ErrRecord
			}
			engine, err := NewInstalledEnvelopeRekey(EnvelopeRekeyInstallation{AccessMutationInstallation: i.AccessMutationInstallation, AdmitCustody: i.AdmitCustody, Name: "target"})
			if err != nil {
				t.Fatal(err)
			}
			store := f.env.Store.(*memoryStore)
			cas := store.cas
			got := engine.Rekey(ctx, fixtureID(f.env.Domain, condition))
			engine.Close()
			if got.Result.Outcome != AdmissionRefused || private != 0 || reads != 0 || store.cas != cas || got.Successor != nil {
				t.Fatal("unadoptable source passed pre-custody gate", got.Result, private, reads)
			}
		})
	}
}

// full_only: false
func TestMaintenanceRegistryAllowsPendingDisplayAndInertCreation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f, _, _ := maintenanceObserverFixture(t, ctx, false)
	selected := f.open(t, ctx)
	i := installedSecretAccessTestInstallation(t, f, selected, installedApplyGeneratedValidator(t, selected), nil, nil)
	m := i.Maintenance
	row := &m.Recipients[0]
	row.Recipient.DisplayName = "pending display name"
	row.Creation = &contract.RecipientCreationProof{Snapshot: fixtureID(f.env.Domain, "old inert snapshot"), Nonce: fixtureID(f.env.Domain, "old inert nonce")}
	index := slices.IndexFunc(m.Configuration.Recipients.Value, func(p contract.PublicRecipient) bool { return p.RecipientID == row.Recipient.RecipientID })
	m.Configuration.Recipients.Value[index].DisplayName = contract.PublicField[string]{State: contract.PublicPresent, Value: row.Recipient.DisplayName}
	var err error
	m.InputDigest, err = PlanningInputDigest(m.Configuration, m.Inputs)
	if err != nil {
		t.Fatal(err)
	}
	var delivered MaintenanceReadback
	publish := m.PublishSuccessor
	m.PublishSuccessor = func(ctx context.Context, c MaintenanceSuccessor) (MaintenanceReadback, error) {
		r, err := publish(ctx, c)
		delivered = r
		return r, err
	}
	engine, err := NewInstalledEnvelopeRekey(EnvelopeRekeyInstallation{AccessMutationInstallation: i.AccessMutationInstallation, AdmitCustody: i.AdmitCustody, Name: "target"})
	if err != nil {
		t.Fatal(err)
	}
	got := engine.Rekey(ctx, fixtureID(f.env.Domain, "pending maintenance display"))
	engine.Close()
	if got.Result.Outcome != ObservedCurrent {
		t.Fatal("display or inert creation over-refused", got.Result)
	}
	if !maintenanceCurrentSourceUsable(f.open(t, ctx), m.SourcePins.FileID, delivered.Configuration, delivered.Inputs, delivered.Recipients) {
		t.Fatal("display or inert creation made exact current source unusable")
	}
}

// full_only: false
func TestMaintenanceOutputCapacityChargesBothWitnessSidesBeforeCustody(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	authority := f.selected.admission.recipient
	var reader contract.ID
	for _, row := range f.selected.registry() {
		if row.RecipientID != authority {
			reader = row.RecipientID
			break
		}
	}
	if reader.IsZero() {
		t.Fatal("current recipient for guarded retirement absent")
	}
	original := suppliedSecret(t, f.env, "target", "maintenance capacity current secret", custody.StandardValue, authority, reader)
	setup := f.engine(t, f.selected, []ApplyEntryInput{original}, nil)
	if out := setup.Apply(ctx, fixtureID(f.env.Domain, "capacity current material"), []ApplyEntryInput{original}); out.Result.Outcome != ObservedCurrent {
		t.Fatal(out.Result)
	}
	setup.Close()
	selected := f.open(t, ctx)
	for _, sealed := range []bool{false, true} {
		for _, excess := range []uint64{0, 1} {
			t.Run(fmt.Sprintf("sealed=%v/excess=%d", sealed, excess), func(t *testing.T) {
				validator := installedApplyGeneratedValidator(t, selected)
				installation := installedSecretAccessTestInstallation(t, f, selected, validator, nil, nil)
				m := installation.Maintenance
				if sealed {
					m = installedMaintenanceTestInstallation(t, f, selected, validator, contract.PlanningInput{Name: "target", Form: contract.PlanningSealed, SealedInput: original.InputBytes})
					installation.Maintenance = m
				}
				slot, entry := lifecycleEntry(t, selected, "target")
				ref := selected.root.ValueEntryPages[slot/16]
				if entry == nil || ref == nil {
					t.Fatal("actual retained target/page missing")
				}
				padded := func(n uint64) uint64 { return 4 * ((n + 2) / 3) }
				nameCopies := uint64(18)
				if sealed {
					nameCopies = 6
				}
				reserved := uint64(8192) + 6*(uint64(len(m.OutputPath))+256) + 2*padded(65536) + 2*padded(262144) + 2*padded(uint64(ref.Length)) + 2*128 + 512 + nameCopies*uint64(len(entry.Name))
				if reserved+uint64(m.SourcePins.EditableLength) >= 268435456 {
					t.Fatal("small target unexpectedly exhausted representation budget")
				}
				m.SourcePins.GeneratedLength = 268435456 - reserved - m.SourcePins.EditableLength + excess
				reads, mutations, publications := 0, 0, 0
				m.AdmitFeasibility = func(context.Context, contract.PlanningAdmission) (PlanningCustody, error) {
					reads++
					return nil, contract.ErrRecord
				}
				m.PublishSuccessor = func(context.Context, MaintenanceSuccessor) (MaintenanceReadback, error) {
					publications++
					return MaintenanceReadback{}, contract.ErrRecord
				}
				installation.AdmitCustody = func(context.Context, contract.CryptoCompareRequest, contract.ControlCore, []contract.RecipientRecord, []contract.MembershipRow, contract.DescriptorVector, *contract.GeneratedSupportTransition, contract.ID, contract.MutationReceiptWindows, uint8, time.Time) (*InstalledApplyCustody, error) {
					mutations++
					return nil, contract.ErrRecord
				}
				store := f.env.Store.(*memoryStore)
				creates, cas := store.creates, store.cas
				var out PublicApplyResult
				if sealed {
					retirement := installedRetirementTestInstallation(t, f, selected, installedSecretAccessTestRef(t, selected, reader), nil)
					retirement.Maintenance = m
					retirement.AdmitCustody = func(context.Context, contract.CryptoCompareRequest, contract.ControlCore, []contract.RecipientRecord, uint16, []contract.MembershipRow, contract.DescriptorVector, *contract.GeneratedSupportTransition, contract.ID, contract.MutationReceiptWindows, uint8, time.Time) (*InstalledApplyCustody, error) {
						mutations++
						return nil, contract.ErrRecord
					}
					engine, err := NewInstalledRecipientRetirement(retirement)
					if err != nil {
						t.Fatal(err)
					}
					out = engine.Retire(ctx, fixtureID(f.env.Domain, fmt.Sprintf("capacity guarded retirement excess=%d", excess)))
					engine.Close()
				} else {
					engine, err := NewInstalledEnvelopeRekey(EnvelopeRekeyInstallation{AccessMutationInstallation: installation.AccessMutationInstallation, AdmitCustody: installation.AdmitCustody, Name: "target"})
					if err != nil {
						t.Fatal(err)
					}
					out = engine.Rekey(ctx, fixtureID(f.env.Domain, fmt.Sprintf("capacity retained rekey excess=%d", excess)))
					engine.Close()
				}
				wantReads, wantMutations := 0, 0
				if excess == 0 {
					if sealed {
						wantReads = 1
					} else {
						wantMutations = 1
					}
				}
				if reads != wantReads || mutations != wantMutations || publications != 0 || store.creates != creates || store.cas != cas || out.Successor != nil || out.Result.Outcome == ObservedCurrent {
					t.Fatal("complete output capacity was not settled before custody", reads, mutations, publications, out.Result)
				}
			})
		}
	}
}

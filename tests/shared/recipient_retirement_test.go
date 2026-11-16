package core

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

func installedRetirementTestInstallation(t testing.TB, f installedApplyTestFixture, selected *StateSession, recipient contract.RecipientBindingReference, observe func(contract.CryptoCompareRequest, uint16), validators ...*PublicConfigurationValidator) RecipientRetirementInstallation {
	t.Helper()
	validator := installedApplyGeneratedValidator(t, selected)
	if len(validators) == 1 {
		validator = validators[0]
	}
	return RecipientRetirementInstallation{AccessMutationInstallation: AccessMutationInstallation{ExpectedDomain: f.env.Domain, ExpectedStore: f.env.Store.Descriptor(), PublicBasis: f.basis, ExpectedControl: currentControlOf(selected), Store: f.env.Store, Trust: f.env.Trust, CompositionID: f.composition, ConfigurationValidator: validator, Maintenance: installedMaintenanceTestInstallation(t, f, selected, validator), CloseInstalled: func() {}}, Recipient: recipient,
		AdmitCustody: func(ctx context.Context, q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, retiredSlot uint16, plain []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, revision contract.ID, before contract.MutationReceiptWindows, warningBits uint8, deadline time.Time) (*InstalledApplyCustody, error) {
			if observe != nil {
				observe(q, retiredSlot)
			}
			owner, err := f.keys.NewRecipientRetirementCustody(q, control, current, retiredSlot, plain, support, witness, revision, before, warningBits, deadline)
			if err != nil {
				return nil, err
			}
			return &InstalledApplyCustody{Crypto: owner, BindReceipt: owner.BindReceipt, Close: owner.Close}, nil
		}}
}

func installedRetirementTestRun(t testing.TB, ctx context.Context, f installedApplyTestFixture, selected *StateSession, ref contract.RecipientBindingReference, label string, observe func(contract.CryptoCompareRequest, uint16)) PublicApplyResult {
	t.Helper()
	engine, err := NewInstalledRecipientRetirement(installedRetirementTestInstallation(t, f, selected, ref, observe))
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	return engine.Retire(ctx, fixtureID(f.env.Domain, label))
}

func installedRetirementReenrollment(t testing.TB, selected *StateSession, old contract.RecipientRecord, label string) []contract.ApplyRecipientInput {
	t.Helper()
	nonce := fixtureID(selected.root.Domain, label)
	id, err := contract.RecipientCreationID(selected.root.Domain, selected.root.Snapshot, nonce)
	if err != nil {
		t.Fatal(err)
	}
	binding, incarnation, err := contract.RecipientInitialBindingIDs(selected.root.Domain, id)
	if err != nil {
		t.Fatal(err)
	}
	key := *old.CurrentBinding
	key.BindingID, key.BindingIncarnationID, key.BindingSerial = binding, incarnation, 1
	rows := currentApplyRecipients(selected.registry())
	rows = append(rows, contract.ApplyRecipientInput{Recipient: contract.RecipientRecord{RecipientID: id, Status: contract.CurrentRecipient, DisplayName: old.DisplayName, CurrentBinding: &key}, Creation: &contract.RecipientCreationProof{Snapshot: selected.root.Snapshot, Nonce: nonce}})
	slices.SortFunc(rows, func(a, b contract.ApplyRecipientInput) int {
		return bytes.Compare(a.Recipient.RecipientID[:], b.Recipient.RecipientID[:])
	})
	return rows
}

// full_only: false
func TestInstalledRecipientRetirementDerivesCompleteMembershipCensus(t *testing.T) {
	for _, cell := range []struct {
		name     string
		plain    bool
		secrets  int
		family   contract.Family
		recovery bool
	}{{"unassigned", false, 0, contract.AWS, false}, {"plain", true, 0, contract.AWS, false}, {"secret", false, 2, contract.AWS, false}, {"mixed_recovery", true, 2, contract.GCP, true}} {
		t.Run(cell.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f := newInstalledApplyTestFixture(t, ctx, cell.family, cell.recovery)
			authority, reader := f.selected.admission.recipient, fixtureID(f.env.Domain, "reader")
			members := []contract.ID{authority, reader}
			slices.SortFunc(members, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			input := []ApplyEntryInput{suppliedSecret(t, f.env, "unrelated", "retirement unrelated source", custody.StandardValue, authority)}
			plainMembers := []contract.ID{authority}
			if cell.plain {
				plainMembers = members
			}
			input = append(input, ApplyEntryInput{Name: "plain", Recipients: plainMembers, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("preserved public bytes"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
			for i := range cell.secrets {
				input = append(input, sharingSecretNamed(t, f.env, fmt.Sprintf("affected-%d", i), fmt.Sprintf("retirement affected source %d", i), members))
			}
			setup := f.engine(t, f.selected, input, nil)
			if result := setup.Apply(ctx, fixtureID(f.env.Domain, "retirement census setup"), input); result.Result.Outcome != ObservedCurrent {
				t.Fatal(result.Result)
			}
			setup.Close()
			selected := f.open(t, ctx)
			ref := installedSecretAccessTestRef(t, selected, reader)
			oldRecipient := *selected.recipientRecord(reader)
			oldEntries := make(map[string]contract.ValueEntry)
			oldAccess := selected.accessRecords()
			for _, named := range selected.root.Names {
				oldEntries[named.Name] = ownScenarioValueEntry(*selected.valueEntry(named.Slot))
			}
			f.keys.SetDenied(reader, true)
			if cell.recovery {
				f.keys.SetDenied(f.keys.RecoveryID(), true)
				f.env.Recovery.(*testtrust.Signer).SetUnavailable(true)
			}
			store := f.env.Store.(*memoryStore)
			cas := store.cas
			_, private := f.keys.Calls()
			called := 0
			result := installedRetirementTestRun(t, ctx, f, selected, ref, "retire complete census", func(q contract.CryptoCompareRequest, slot uint16) {
				called++
				body, err := contract.EncodeRecipientRecord(oldRecipient)
				actualSlot, _ := selected.selectedRecipientSlot(reader)
				if err != nil || q.Retirement == nil || q.Retirement.Slot != actualSlot || slot != actualSlot || q.Retirement.BeforeRecordDigest != contract.Hash(body) || q.Retirement.BeforeRecordLength != uint32(len(body)) || len(q.Current) != cell.secrets+1 {
					t.Fatal("retirement did not bind exact before row/slot and full public secret image")
				}
			})
			_, afterPrivate := f.keys.Calls()
			count := uint32(1 + 2*cell.secrets + 2*boolInt(cell.plain))
			if result.Result.Outcome != ObservedCurrent || result.Payload == nil || result.Payload.ChangedSubjects.Count != count || result.RetirementBlockers != nil || called != 1 || store.cas != cas+1 || afterPrivate-private != 2*cell.secrets {
				t.Fatal("retirement did not select exact census with only affected private opens", result.Result, called, store.cas-cas, afterPrivate-private)
			}
			assertPositiveApplyPreparation(t, result)
			fresh := f.open(t, ctx)
			if fresh.recipientRecord(reader) != nil || fresh.root.RecipientCount+1 != selected.root.RecipientCount || fresh.root.ValueEntryCount != selected.root.ValueEntryCount || fresh.root.SecretCount != selected.root.SecretCount || fresh.root.RawBytes != selected.root.RawBytes {
				t.Fatal("retirement did not remove exactly its registry row")
			}
			for _, named := range fresh.root.Names {
				current, before := fresh.valueEntry(named.Slot), oldEntries[named.Name]
				if slices.Contains(current.Recipients, reader) || current.Incarnation != before.Incarnation || current.Name != before.Name || current.ValueSource != before.ValueSource || current.ConfidentialityClass != before.ConfidentialityClass {
					t.Fatal("retirement omitted membership or changed unrelated entry identity")
				}
				if current.ConfidentialityClass == contract.Secret && slices.Contains(before.Recipients, reader) {
					if current.ValueState == before.ValueState || bytes.Equal(current.ValueBytes, before.ValueBytes) {
						t.Fatal("affected secret kept old protected material")
					}
					if check := f.keys.Consume(ctx, sessionConsumerSelection(t, fresh, authority, current.Name), custody.StandardValue); check.Code != contract.CryptoSuccess || !check.ValueMatched || check.Delivery != 1 {
						t.Fatal("affected secret plaintext changed", check)
					}
				} else {
					want := before
					want.Recipients = slices.DeleteFunc(slices.Clone(want.Recipients), func(id contract.ID) bool { return id == reader })
					if !reflect.DeepEqual(*current, want) {
						t.Fatal("plain or unrelated secret material/origin/bytes changed")
					}
				}
			}
			for _, before := range oldAccess {
				if slices.ContainsFunc(oldEntriesSlice(oldEntries), func(entry contract.ValueEntry) bool {
					return entry.ValueState == before.MaterialID && slices.Contains(entry.Recipients, reader)
				}) {
					continue
				}
				after, ok := fresh.materialAccess(before.MaterialKind, before.MaterialID)
				if !ok || !reflect.DeepEqual(after, before) {
					t.Fatal("unrelated secret access/wraps changed")
				}
			}
			receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
			if err != nil || receipt.OperationKind != contract.OperationRetireRecipientIdentity || receipt.StateResult != contract.ReceiptStateSuccess || receipt.EffectSummary != contract.ReceiptEffectNotApplicable || receipt.ChangedSubjects.Count != count || receipt.ChangedSubjects.Digest != result.Payload.ChangedSubjects.IdentityRootDigest || fresh.head.Subject.Exclusion.Retirements.Count != 1 {
				t.Fatal("retirement receipt or signed retirement descriptor differs", err)
			}
			cas = store.cas
			_, private = f.keys.Calls()
			absent := installedRetirementTestRun(t, ctx, f, fresh, ref, "absent new retirement", nil)
			_, afterPrivate = f.keys.Calls()
			if absent.Result.Outcome != AdmissionRefused || store.cas != cas || afterPrivate != private {
				t.Fatal("absent identity was retired again", absent.Result)
			}
		})
	}
}

func oldEntriesSlice(entries map[string]contract.ValueEntry) []contract.ValueEntry {
	rows := make([]contract.ValueEntry, 0, len(entries))
	for _, row := range entries {
		rows = append(rows, row)
	}
	return rows
}

// full_only: false
func TestInstalledRecipientRetirementBlocksRetainedReadersUntilRealWorkCloses(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	retained := newRetainedReaderFixture(t, true, 2)
	selected := retained.selected
	f := installedApplyTestFixture{env: retained.env, keys: retained.keys, basis: selected.admission.publicBasis(), composition: selected.admission.composition, admitted: OpenContext{admission: &selected.admission}, selected: selected}
	reader := fixtureID(f.env.Domain, "reader")
	ref := installedSecretAccessTestRef(t, selected, reader)
	stable := installedApplyStableWork(t, ctx, selected)
	store := f.env.Store.(*memoryStore)
	cas := store.cas
	_, private := f.keys.Calls()
	called := false
	blocked := installedRetirementTestRun(t, ctx, f, selected, ref, "blocked historical reader retirement", func(contract.CryptoCompareRequest, uint16) { called = true })
	_, privateAfter := f.keys.Calls()
	if blocked.Result.Outcome != AdmissionRefused || blocked.RetirementBlockers == nil || blocked.RetirementBlockers.Total != 2 || len(blocked.RetirementBlockers.Rows) != 2 || called || store.cas != cas || privateAfter != private || blocked.Payload != nil || len(blocked.Receipt) != 0 || blocked.Result.CommitMayHaveOccurred {
		t.Fatal("retained route removal did not refuse with exact bounded pre-custody blockers", blocked.Result)
	}
	for _, row := range blocked.RetirementBlockers.Rows {
		if row.MaterialID != retained.value.ValueState || row.OwnerKind != contract.GeneratedHazardSupportKind || retained.owners[row.OwnerID] == nil {
			t.Fatal("blocker does not name exact authenticated retained material/owner")
		}
	}
	if !reflect.DeepEqual(stable, installedApplyStableWork(t, ctx, f.open(t, ctx))) {
		t.Fatal("blocked retirement changed unrelated retained work")
	}
	work := mustSelectedGeneratedWork(t, selected)
	remaining := make(map[contract.ID]contract.ID, len(blocked.RetirementBlockers.Rows))
	for _, blocker := range blocked.RetirementBlockers.Rows {
		hazard, err := contract.InspectGeneratedHazardRecord(work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, blocker.OwnerID}].Body)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := work.attempts[hazard.OriginalAttemptID]; !ok {
			t.Fatal("original retained owner attempt absent")
		}
		if _, duplicate := remaining[blocker.OwnerID]; duplicate {
			t.Fatal("retirement report duplicated a retained owner")
		}
		remaining[blocker.OwnerID] = hazard.OriginalAttemptID
	}
	deleteStore := &generatedCleanupDeleteStore{memoryStore: store}
	for at := range blocked.RetirementBlockers.Rows {
		cleanup, present, err := selected.readGeneratedCleanup(ctx)
		original, expected := remaining[cleanup.hazard.HazardID]
		if err != nil || !present || cleanup.kind != generatedCleanupHazard || !expected || cleanup.hazard.OriginalAttemptID != original || cleanup.attempt.record.AttemptID != original {
			t.Fatal("selected cleanup differs from the remaining exact retained owners", err)
		}
		selected = closeAndReleaseActualCleanup(t, f.env, selected, deleteStore, cleanup.attempt, contract.GeneratedHazardSupportKind, cleanup.hazard.HazardID, at)
		selected = generatedLifecycleReopen(t, ctx, selected, f.env.Store)
		delete(remaining, cleanup.hazard.HazardID)
	}
	if len(remaining) != 0 {
		t.Fatal("actual cleanup did not close every reported retained owner")
	}
	f.basis, f.admitted = selected.admission.publicBasis(), OpenContext{admission: &selected.admission}
	cas = store.cas
	_, private = f.keys.Calls()
	result := installedRetirementTestRun(t, ctx, f, selected, ref, "retirement after real owner closure", nil)
	_, privateAfter = f.keys.Calls()
	if result.Result.Outcome != ObservedCurrent || result.RetirementBlockers != nil || store.cas != cas+1 || privateAfter != private || f.open(t, ctx).recipientRecord(reader) != nil {
		t.Fatal("real owner closure did not release retirement with zero unrelated private opens", result.Result)
	}
}

// full_only: false
func TestInstalledRecipientRetirementReportsActiveParentBlockerBeforeOccupiedGate(t *testing.T) {
	prefix := newCurrentRetainedFinalPrefix(t, 0, contract.GeneratorValueChangeMembership, true)
	selected := prefix.recorded
	if selected.root.Generated.ActiveOwner.IsZero() {
		t.Fatal("actual accepted parent setup absent")
	}
	f := installedApplyTestFixture{env: prefix.env, keys: prefix.keys, basis: selected.admission.publicBasis(), composition: selected.admission.composition, admitted: OpenContext{admission: &selected.admission}, selected: selected}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	called := false
	result := installedRetirementTestRun(t, ctx, f, selected, installedSecretAccessTestRef(t, selected, prefix.reader), "active retained parent retirement", func(contract.CryptoCompareRequest, uint16) { called = true })
	if result.Result.Outcome != AdmissionRefused || result.RetirementBlockers == nil || called || !slices.ContainsFunc(result.RetirementBlockers.Rows, func(row RecipientRetirementBlocker) bool {
		return row.OwnerKind == contract.GeneratedParentSupportKind && row.OwnerID == selected.root.Generated.ActiveOwner && row.MaterialID == prefix.original.ValueState
	}) {
		t.Fatal("active retained parent was hidden by generic occupied-owner result", result.Result)
	}
	work := mustSelectedGeneratedWork(t, selected)
	if !slices.ContainsFunc(result.RetirementBlockers.Rows, func(row RecipientRetirementBlocker) bool {
		_, present := work.records[generatedRecordKey{contract.GeneratedDutySupportKind, row.OwnerID}]
		return present && row.OwnerKind == contract.GeneratedDutySupportKind && row.MaterialID == prefix.original.ValueState
	}) {
		t.Fatal("actual accepted create Duty lost its typed canonical reader blocker")
	}
}

// full_only: false
func TestInstalledRecipientRetirementDoesNotReviveOldPreparationOrLateCandidate(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.AWS, false)
	desired := installedApplyPreparedRecipient(t, f.selected, "retired creation proof")
	created := slices.IndexFunc(desired, func(row contract.ApplyRecipientInput) bool { return row.Creation != nil })
	old := desired[created]
	create := f.engineWithRecipients(t, f.selected, nil, desired, nil)
	if result := create.Apply(ctx, fixtureID(f.env.Domain, "old preparation creation"), nil); result.Result.Outcome != ObservedCurrent {
		t.Fatal(result.Result)
	}
	create.Close()
	selected := f.open(t, ctx)
	store := f.env.Store.(*memoryStore)
	lateDesired := currentApplyRecipients(selected.registry())
	for at := range lateDesired {
		if lateDesired[at].Recipient.RecipientID == old.Recipient.RecipientID {
			lateDesired[at].Recipient.DisplayName = "late old candidate"
		}
	}
	store.casMode = "delayed"
	pending := f.engineWithRecipients(t, selected, nil, lateDesired, nil)
	unknown := pending.Apply(ctx, fixtureID(f.env.Domain, "old delayed candidate"), nil)
	pending.Close()
	store.casMode = ""
	if unknown.Result.Outcome != UnresolvedCommit || !unknown.Result.CommitMayHaveOccurred || store.late == nil {
		t.Fatal("actual old candidate did not reach deferred conditional write", unknown.Result)
	}
	late := store.late
	retired := installedRetirementTestRun(t, ctx, f, selected, installedSecretAccessTestRef(t, selected, old.Recipient.RecipientID), "retire before delayed candidate", nil)
	if retired.Result.Outcome != ObservedCurrent {
		t.Fatal(retired.Result)
	}
	selected = f.open(t, ctx)
	readd := installedRetirementReenrollment(t, selected, old.Recipient, "same resource new enrollment")
	freshID := readd[slices.IndexFunc(readd, func(row contract.ApplyRecipientInput) bool { return row.Creation != nil })].Recipient.RecipientID
	if freshID == old.Recipient.RecipientID {
		t.Fatal("reenrollment reused retired identity")
	}
	engine := f.engineWithRecipients(t, selected, nil, readd, nil)
	if result := engine.Apply(ctx, fixtureID(f.env.Domain, "reenroll same resource"), nil); result.Result.Outcome != ObservedCurrent {
		t.Fatal(result.Result)
	}
	engine.Close()
	selected = f.open(t, ctx)
	wantRevision := selected.head.Core.Revision
	if err := late(); err != nil {
		t.Fatal(err)
	}
	selected = f.open(t, ctx)
	if selected.head.Core.Revision != wantRevision || selected.recipientRecord(old.Recipient.RecipientID) != nil || selected.recipientRecord(freshID) == nil {
		t.Fatal("late pre-retirement candidate revived the old registry")
	}
	for _, damage := range []string{"old preparation", "current snapshot with old ID", "old binding"} {
		proposal := currentApplyRecipients(selected.registry())
		absent := old
		proof := *old.Creation
		absent.Creation = &proof
		if damage != "old preparation" {
			proof.Snapshot = selected.root.Snapshot
		}
		if damage == "old binding" {
			id, err := contract.RecipientCreationID(selected.root.Domain, proof.Snapshot, proof.Nonce)
			if err != nil {
				t.Fatal(err)
			}
			absent.Recipient.RecipientID = id
		}
		proposal = append(proposal, absent)
		slices.SortFunc(proposal, func(a, b contract.ApplyRecipientInput) int {
			return bytes.Compare(a.Recipient.RecipientID[:], b.Recipient.RecipientID[:])
		})
		cas := store.cas
		_, private := f.keys.Calls()
		engine := f.engineWithRecipients(t, selected, nil, proposal, nil)
		result := engine.Apply(ctx, fixtureID(f.env.Domain, damage), nil)
		engine.Close()
		_, afterPrivate := f.keys.Calls()
		if result.Result.Outcome != AdmissionRefused || store.cas != cas || afterPrivate != private || f.open(t, ctx).recipientRecord(old.Recipient.RecipientID) != nil {
			t.Fatal("old identity, preparation or binding regained authority", damage, result.Result)
		}
	}
	cas := store.cas
	result := installedRetirementTestRun(t, ctx, f, selected, installedSecretAccessTestRef(t, selected, selected.admission.recipient), "authority retirement refuses", nil)
	if result.Result.Outcome != AdmissionRefused || store.cas != cas || result.RetirementBlockers != nil {
		t.Fatal("Authority retirement did not refuse", result.Result)
	}
}

// full_only: false
func TestRecipientRetirementRefusesSuppliedContentChangeComparisonTag(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.AWS, false)
	authority, reader := f.selected.admission.recipient, fixtureID(f.env.Domain, "reader")
	members := []contract.ID{authority, reader}
	slices.SortFunc(members, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	input := []ApplyEntryInput{sharingSecretNamed(t, f.env, "secret", "retirement equal tag source", members)}
	engine := f.engine(t, f.selected, input, nil)
	if result := engine.Apply(ctx, fixtureID(f.env.Domain, "retirement relation setup"), input); result.Result.Outcome != ObservedCurrent {
		t.Fatal(result.Result)
	}
	engine.Close()
	selected := f.open(t, ctx)
	slot, recipient := selected.selectedRecipientSlot(reader)
	retirement, err := contract.NewRecipientRetirementRow(slot, *recipient)
	if err != nil {
		t.Fatal(err)
	}
	input = installedApplyCurrentInput(selected)
	input[0].Recipients = []contract.ID{authority}
	recipients := slices.DeleteFunc(currentApplyRecipients(selected.registry()), func(row contract.ApplyRecipientInput) bool { return row.Recipient.RecipientID == reader })
	comparison, result := selected.compareEntryInputsForMutation(ctx, input, recipients, nil, &retirement, nil)
	if comparison == nil {
		t.Fatal(result)
	}
	before := selected.valueEntry(comparison.slots[0])
	row := contract.CryptoComparisonRow{Name: before.Name, BeforePresent: true, AfterPresent: true, Relation: contract.CryptoEqual, BeforePublicEntryDigest: publicEntryDigest(selected.root.Domain, comparison.slots[0], before), SourceDigest: comparison.intent[0].PayloadDigest, AfterRawLength: comparison.intent[0].ContentLength, ExclusionPathDigest: fixtureID(f.env.Domain, "admitted exclusion proof boundary")}
	got := contract.CryptoCompareResult{OperationRef: fixtureID(f.env.Domain, "comparison operation"), Rows: []contract.CryptoComparisonRow{row}}
	if !comparisonMatches(comparison, got) {
		t.Fatal("exact retirement equal-row shape refused")
	}
	got.Rows[0].Relation = contract.CryptoChanged
	if comparisonMatches(comparison, got) {
		t.Fatal("retirement accepted content replacement relation")
	}
}

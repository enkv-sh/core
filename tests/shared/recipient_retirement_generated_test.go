package core

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

// full_only: false
func TestInstalledRecipientRetirementRefreshesGeneratedMembershipAndPreservesParkedWork(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	retained := newRetainedReaderFixture(t, true, 2)
	selected := retained.selected
	if !selected.root.Generated.ActiveOwner.IsZero() || selected.root.Generated.GeneratedCurrent != 1 || selected.root.Generated.Hazards != 2 || selected.root.Generated.Duties != 0 {
		t.Fatal("actual current-generated and unrelated parked-work setup differs")
	}
	f := installedApplyTestFixture{env: retained.env, keys: retained.keys, basis: selected.admission.publicBasis(), composition: selected.admission.composition, admitted: OpenContext{admission: &selected.admission}, selected: selected}
	validator := installedApplyGeneratedValidator(t, selected)
	_, original := lifecycleEntry(t, selected, "generated")
	originalEntry := ownScenarioValueEntry(*original)
	originalWork := installedApplyStableWork(t, ctx, selected)
	desired := installedApplyPreparedRecipient(t, selected, "fresh current-generated reader")
	created := slices.IndexFunc(desired, func(row contract.ApplyRecipientInput) bool { return row.Creation != nil })
	if created < 0 {
		t.Fatal("fresh prepared recipient absent")
	}
	recipient := desired[created].Recipient.RecipientID
	input := installedApplyCurrentInput(selected)
	for at := range input {
		if input[at].Name == "generated" {
			input[at].Recipients = append(slices.Clone(input[at].Recipients), recipient)
			slices.SortFunc(input[at].Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		}
	}
	grant := f.engineWithValidator(t, selected, input, desired, validator, nil)
	granted := grant.Apply(ctx, fixtureID(f.env.Domain, "enroll and grant current-generated reader"), input)
	grant.Close()
	if granted.Result.Outcome != ObservedCurrent || granted.Payload == nil || granted.Payload.ChangedSubjects.Count != 4 {
		t.Fatal("fresh recipient was not atomically enrolled into current generated membership", granted.Result)
	}
	selected = f.open(t, ctx)
	slot, current := lifecycleEntry(t, selected, "generated")
	before := ownScenarioValueEntry(*current)
	wantGranted := originalEntry
	wantGranted.Recipients = slices.Clone(before.Recipients)
	if !slices.Contains(before.Recipients, recipient) || !reflect.DeepEqual(before, wantGranted) || !reflect.DeepEqual(originalWork, installedApplyStableWork(t, ctx, selected)) {
		t.Fatal("setup grant changed generated material/resource or unrelated parked work")
	}
	work := mustSelectedGeneratedWork(t, selected)
	for _, canonical := range work.canonical {
		if slices.Contains(canonical.record.Entry.Recipients, recipient) || canonical.record.Entry.ValueState == before.ValueState {
			t.Fatal("fixture target reader/material unexpectedly has a historical retained claim")
		}
	}
	outputTarget := outputConfigurationTarget("generated", "retained-generated-secret")
	outputTarget.target.PayloadEncoding = contract.OutputEncodingBase64
	f.selected = selected
	f = installedOutputSelect(t, ctx, f, &outputApplyInput{
		bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{outputTarget}}},
		routes:   []outputApplyRoute{{entryName: "generated", destinations: []string{"app"}}},
		groups:   [][]string{{"generated"}},
	})
	selected = f.selected
	// Installing the output configuration selects base64 delivery for this
	// entry. Retirement must bind the entry from that selected predecessor.
	slot, current = lifecycleEntry(t, selected, "generated")
	before = ownScenarioValueEntry(*current)
	beforeOutput := installedOutputConfiguration(t, ctx, selected)
	beforeEntries := make(map[string]contract.ValueEntry, len(selected.root.Names))
	for _, named := range selected.root.Names {
		beforeEntries[named.Name] = ownScenarioValueEntry(*selected.valueEntry(named.Slot))
	}
	beforeRegistry := selected.registry()
	wantRegistry := slices.DeleteFunc(slices.Clone(beforeRegistry), func(row contract.RecipientRecord) bool { return row.RecipientID == recipient })
	beforeWork := installedApplyStableWork(t, ctx, selected)
	beforeAccess := selected.accessRecords()
	beforeReceipts, err := selected.receiptWindows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	beforePayload, err := contract.InspectCanonicalPayload(before.ValueBytes)
	if err != nil {
		t.Fatal(err)
	}
	var hazards []contract.ID
	for id := range retained.owners {
		hazards = append(hazards, id)
	}
	slices.SortFunc(hazards, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	if len(hazards) != 2 {
		t.Fatal("exact parked hazard owner set absent")
	}
	f.keys.SetDenied(recipient, true)
	f.keys.SetDenied(f.keys.RecoveryID(), true)
	recoverySigner := f.env.Recovery.(*testtrust.Signer)
	recoveryCalls := recoverySigner.Calls()
	recoverySigner.SetUnavailable(true)
	installation := installedRetirementTestInstallation(t, f, selected, installedSecretAccessTestRef(t, selected, recipient), nil, installedOutputValidator(t, selected))
	admit := installation.AdmitCustody
	var stages []contract.CryptoKind
	var trace *installedSecretAccessTrace
	installation.AdmitCustody = func(ctx context.Context, q contract.CryptoCompareRequest, control contract.ControlCore, registry []contract.RecipientRecord, retiredSlot uint16, plain []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, revision contract.ID, windows contract.MutationReceiptWindows, warnings uint8, deadline time.Time) (*InstalledApplyCustody, error) {
		if q.Retirement == nil || q.Retirement.RecipientID != recipient || witness == nil || len(witness.CurrentGenerated) != 1 || len(witness.Handoffs) != 0 || witness.Output != nil || !reflect.DeepEqual(registry, beforeRegistry) {
			t.Fatal("retirement admission lacks exact current-generated proof or gained effect/output handoff")
		}
		provedCurrent, err := contract.DecodeValueEntry(witness.CurrentGenerated[0].EntryBytes)
		if err != nil || !reflect.DeepEqual(provedCurrent, before) || witness.CurrentGenerated[0].Slot != slot {
			t.Fatal("retirement proof does not describe the exact authenticated generated predecessor", err)
		}
		owner, err := admit(ctx, q, control, registry, retiredSlot, plain, support, witness, revision, windows, warnings, deadline)
		if err != nil {
			return nil, err
		}
		trace = &installedSecretAccessTrace{t: t, Crypto: installedApplyObservedCrypto{Crypto: owner.Crypto, observe: func(kind contract.CryptoKind) { stages = append(stages, kind) }}}
		owner.Crypto = trace
		return owner, nil
	}
	engine, err := NewInstalledRecipientRetirement(installation)
	if err != nil {
		t.Fatal(err)
	}
	store := f.env.Store.(*memoryStore)
	cas := store.cas
	public, private := f.keys.Calls()
	result := engine.Retire(ctx, fixtureID(f.env.Domain, "retire current-generated-only reader"))
	engine.Close()
	publicAfter, privateAfter := f.keys.Calls()
	if result.Result.Outcome != ObservedCurrent || result.Payload == nil || result.RetirementBlockers != nil || store.cas != cas+1 || publicAfter != public || privateAfter-private != 2 || recoverySigner.Calls() != recoveryCalls {
		t.Fatal("generated retirement did not select once with only target Authority opens", result.Result, store.cas-cas, publicAfter-public, privateAfter-private)
	}
	if !slices.Equal(stages, []contract.CryptoKind{contract.CryptoCompare, contract.CryptoPrepare, contract.CryptoFreeze, contract.CryptoClaim}) || trace == nil || len(trace.comparison) != 1 || len(trace.identities) != 1 {
		t.Fatal("generated retirement used a different private scope or operation path")
	}
	comparison, identity := trace.comparison[0], trace.identities[0]
	if comparison.Name != before.Name || comparison.Relation != contract.CryptoEqual || !comparison.BeforePresent || !comparison.AfterPresent || comparison.BeforePublicEntryDigest != publicEntryDigest(selected.root.Domain, slot, &before) || comparison.SourceDigest != contract.Hash(before.ValueBytes) || comparison.AfterRawLength != beforePayload.ContentLength || comparison.ExclusionPathDigest.IsZero() || identity.Name != before.Name || identity.Slot != slot || identity.Incarnation != before.Incarnation {
		t.Fatal("generated retirement did not compare exactly the unchanged current plaintext and its exclusion")
	}
	fresh := f.open(t, ctx)
	_, after := lifecycleEntry(t, fresh, "generated")
	wantGenerated := before.Generated
	wantGenerated.GenerationID = after.ValueState
	wantMembers := slices.DeleteFunc(slices.Clone(before.Recipients), func(id contract.ID) bool { return id == recipient })
	if after.Name != before.Name || after.ValueSource != contract.Generated || after.ConfidentialityClass != contract.Secret || after.Incarnation != before.Incarnation || after.ValueState == before.ValueState || after.Generated != wantGenerated || !slices.Equal(after.Recipients, wantMembers) || after.OriginSnapshot != fresh.root.Snapshot || after.OriginTransition != fresh.root.Transition || identity.ValueState != after.ValueState || identity.OriginSnapshot != after.OriginSnapshot || identity.OriginTransition != after.OriginTransition || !reflect.DeepEqual(fresh.registry(), wantRegistry) {
		t.Fatal("generated retirement changed resource identity or omitted fresh target protection/row deletion")
	}
	afterPayload, err := contract.InspectCanonicalPayload(after.ValueBytes)
	if err != nil || afterPayload.DataKeyID == beforePayload.DataKeyID || afterPayload.CommitmentKeyID == beforePayload.CommitmentKeyID || afterPayload.DataKeyEpoch != 1 || afterPayload.CommitmentKeyEpoch != 1 || afterPayload.ContentLength != beforePayload.ContentLength || bytes.Equal(afterPayload.Ciphertext, beforePayload.Ciphertext) {
		t.Fatal("generated retirement did not refresh data/commitment keys and ciphertext", err)
	}
	for _, named := range fresh.root.Names {
		if named.Name != before.Name && !reflect.DeepEqual(*fresh.valueEntry(named.Slot), beforeEntries[named.Name]) {
			t.Fatal("generated retirement changed an unrelated current value entry")
		}
	}
	afterReceipts, err := fresh.receiptWindows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assertSuccessReceiptOrder(t, beforeReceipts, afterReceipts, result.OperationID)
	beforeClosure, afterClosure := selected.root.Generated, fresh.root.Generated
	beforeClosure.Fragments, afterClosure.Fragments = nil, nil
	beforeClosure.SuccessWindow, afterClosure.SuccessWindow = contract.GeneratorDescriptor{}, contract.GeneratorDescriptor{}
	beforeClosure.ReceiptOrder, afterClosure.ReceiptOrder = contract.GeneratorDescriptor{}, contract.GeneratorDescriptor{}
	if !reflect.DeepEqual(beforeWork, installedApplyStableWork(t, ctx, fresh)) || !reflect.DeepEqual(beforeClosure, afterClosure) || !slices.Equal(fresh.generatedSliceLocations, selected.generatedSliceLocations) || fresh.root.OutputConfiguration != selected.root.OutputConfiguration || !reflect.DeepEqual(installedOutputConfiguration(t, ctx, fresh), beforeOutput) || fresh.root.WarningBits != selected.root.WarningBits || result.WarningBits != selected.root.WarningBits {
		t.Fatal("generated retirement changed exact retained Attempts, owners, targets, seeds, duties, hazards, markers or warnings")
	}
	if len(fresh.accessRecords()) != len(beforeAccess) {
		t.Fatal("generated retirement changed unrelated material inventory")
	}
	for _, old := range beforeAccess {
		if old.MaterialKind == contract.ValueMaterialKind && old.MaterialID == before.ValueState {
			if _, present := fresh.materialAccess(old.MaterialKind, old.MaterialID); present {
				t.Fatal("unowned old current-generated material remained selected")
			}
			continue
		}
		current, present := fresh.materialAccess(old.MaterialKind, old.MaterialID)
		if !present || !reflect.DeepEqual(current, old) {
			t.Fatal("generated retirement changed an unrelated current, seed or retained access record/wrap")
		}
	}
	access, present := fresh.materialAccess(contract.ValueMaterialKind, after.ValueState)
	if !present || len(access.Wraps) != 2 || len(wantMembers) != 1 || wantMembers[0] != fresh.admission.recipient {
		t.Fatal("fresh generated target lacks exact Authority and independent Recovery protection")
	}
	for _, row := range fresh.accessRecords() {
		for _, wrap := range row.Wraps {
			if wrap.SubjectKind == contract.OrdinaryWrapSubject && wrap.SubjectID == recipient {
				t.Fatal("retired reader retained an active or historical wrap")
			}
		}
	}
	bindings, err := fresh.currentBindings()
	if err != nil {
		t.Fatal(err)
	}
	for _, wrap := range access.Wraps {
		at := slices.IndexFunc(bindings, func(row contract.BindingTableRow) bool {
			return row.SubjectKind == wrap.SubjectKind && row.SubjectID == wrap.SubjectID
		})
		if at < 0 || wrap.SubjectKind == contract.OrdinaryWrapSubject && wrap.SubjectID != fresh.admission.recipient || wrap.SubjectKind == contract.RecoveryWrapSubject && wrap.SubjectID != f.keys.RecoveryID() {
			t.Fatal("fresh generated wrap selected an unrelated subject")
		}
		digest, err := contract.PublicBindingDigest(bindings[at].Binding)
		if err != nil || wrap.BindingID != bindings[at].Binding.BindingID || wrap.BindingSerial != bindings[at].Binding.BindingSerial || wrap.PublicBindingDigest != digest {
			t.Fatal("fresh generated wrap does not bind the exact selected public key", err)
		}
	}
	// Derive the five semantic subject tuples from the before/after fixture
	// identities, independently of Core's installed changed-subject projector.
	var subjects []contract.ChangedSubjectIdentity
	for _, row := range []struct {
		kind, change       uint8
		primary, secondary contract.ID
	}{{contract.ChangedSubjectValueEntry, contract.ChangedSubjectUpdated, before.Incarnation, contract.ID{}}, {contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectRemoved, before.Generated.GenerationID, contract.ID{}}, {contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectAdded, after.Generated.GenerationID, contract.ID{}}, {contract.ChangedSubjectMembership, contract.ChangedSubjectRemoved, before.Incarnation, recipient}, {contract.ChangedSubjectRecipient, contract.ChangedSubjectRemoved, recipient, contract.ID{}}} {
		id, err := contract.ChangedSubjectIdentityID(f.env.Domain, row.kind, row.primary, row.secondary)
		if err != nil {
			t.Fatal(err)
		}
		subjects = append(subjects, contract.ChangedSubjectIdentity{Kind: row.kind, Change: row.change, Identity: id})
	}
	expectedSubjects, err := contract.ChangedSubjectDescriptor(subjects)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
	if err != nil || receipt.OperationKind != contract.OperationRetireRecipientIdentity || receipt.StateResult != contract.ReceiptStateSuccess || receipt.EffectSummary != contract.ReceiptEffectNotApplicable || receipt.OutputSummary != contract.ReceiptOutputNotApplicable || receipt.ChangedSubjects != expectedSubjects || result.Payload.ChangedSubjects.Count != expectedSubjects.Count || result.Payload.ChangedSubjects.IdentityRootDigest != expectedSubjects.Digest || receipt.RequestIdentityDigest != result.RequestIdentity || receipt.OperationID != result.OperationID || receipt.RequestedRevisionID != fresh.head.Core.Revision || receipt.PredecessorRevisionID != selected.head.Core.Revision || result.Payload.RequestedRevisionID != fresh.head.Core.Revision || result.Payload.PredecessorRevisionID != selected.head.Core.Revision {
		t.Fatal("generated retirement receipt/result differs from the exact five changed subjects", err)
	}
	domainWarnings, effectWarnings, err := contract.DecodeReceiptWarningBits(receipt.OperationKind, receipt.WarningBits)
	if err != nil || domainWarnings != selected.root.WarningBits || effectWarnings != contract.ReceiptWarningPossibleLive || receipt.SummaryCounts[contract.ReceiptDutyCount] != 0 || receipt.SummaryCounts[contract.ReceiptHazardCount] != 2 || receipt.SummaryCounts[contract.ReceiptEffectCount] != 0 || !slices.Equal(result.Payload.LiveHazardIDs, hazards) || len(result.Payload.LiveDutyIDs) != 0 {
		t.Fatal("generated retirement lost exact live-work or warning facts", err)
	}
	wantSuccesses := append(slices.Clone(beforeReceipts.Successes), receipt)
	if len(wantSuccesses) > contract.MutationReceiptWindowLimit {
		wantSuccesses = wantSuccesses[len(wantSuccesses)-contract.MutationReceiptWindowLimit:]
	}
	if afterReceipts.DomainID != beforeReceipts.DomainID || !slices.Equal(afterReceipts.Successes, wantSuccesses) || !slices.Equal(afterReceipts.Failures, beforeReceipts.Failures) {
		t.Fatal("generated retirement changed prior receipts or failed to append exactly its receipt")
	}
	if check := f.keys.Consume(ctx, sessionConsumerSelection(t, fresh, fresh.admission.recipient, "generated"), custody.StandardValue); check.Code != contract.CryptoSuccess || !check.ValueMatched || check.Delivery != 1 {
		t.Fatal("cold generated retirement changed plaintext", check)
	}
}

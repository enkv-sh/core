package core

import (
	"bytes"
	"fmt"
	"math"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// The caller owns the finite admission and file-backed Store. The fixed prefix
// precedes retained pressure, so its generated reservations cannot compact it.
func actualFullReceiptWindows(t *testing.T, env fixtureEnvironment, selected *StateSession) (*StateSession, contract.MutationReceiptWindows, map[contract.ID][]byte) {
	t.Helper()
	store, memory := env.Store.(*memoryStore)
	deadline, finite := t.Deadline()
	if contract.MutationReceiptWindowLimit != 256 || !memory || store == nil || store.fileBodies == nil || selected == nil || selected.store != store || env.Context == nil || env.Context.Err() != nil || !finite || !time.Now().Before(deadline) || selected.admission.expires.After(deadline) || !selected.admission.valid(store) {
		t.Fatal("actual receipt prefix requires the caller's file Store and finite live admission")
	}
	baseline := sessionStateImage(t, selected)
	entries := baseline.entryInputs()
	if len(entries) != 1 || entries[0].ValueSource != contract.Supplied || entries[0].ConfidentialityClass != contract.Plain || baseline.Root.WarningBits != 0 || baseline.Root.CurrentAccess.Core.AccessGeneration > math.MaxUint64-512 {
		t.Fatal("actual receipt prefix requires one unchanged Plain seed without prior warnings")
	}
	basis := selected.admission.current.clone()
	control, valid := selected.admission.currentControl()
	controlBody, err := contract.EncodeControlCore(control)
	if !valid || err != nil {
		t.Fatal("actual receipt prefix has no independent control baseline")
	}
	control, err = contract.DecodeControlCore(controlBody)
	if err != nil {
		t.Fatal("actual receipt prefix could not own its control baseline")
	}
	descriptor, publicKey := bytes.Clone(selected.admission.descriptor), bytes.Clone(selected.admission.publicKey)
	authority, trust, epoch, incarnation := selected.admission.recipient, selected.admission.trust, selected.admission.epoch, selected.admission.controlIncarnation
	lastGeneration := baseline.Root.CurrentAccess.Core.AccessGeneration
	checkCurrent := func(current *StateSession) {
		t.Helper()
		if !reflect.DeepEqual(current.currentEntryInputs(), entries) || !reflect.DeepEqual(current.pages, baseline.Pages) || !reflect.DeepEqual(current.root.ValueEntryPages, baseline.Root.ValueEntryPages) || !reflect.DeepEqual(current.root.Names, baseline.Root.Names) || !reflect.DeepEqual(current.root.Recipients, baseline.Root.Recipients) || current.root.OutputConfiguration != baseline.Root.OutputConfiguration || current.root.ValueEntryCount != baseline.Root.ValueEntryCount || current.root.RawBytes != baseline.Root.RawBytes || current.root.MembershipCount != baseline.Root.MembershipCount {
			t.Fatal("actual receipt prefix changed its complete current Plain/configuration/access state")
		}
		actualControl, valid := current.admission.currentControl()
		actualControl.CurrentControl = current.root.CurrentAccess.Core.CurrentControl
		if !valid || actualControl.AccessIncarnationID != control.AccessIncarnationID || actualControl.AccessGeneration < lastGeneration {
			t.Fatal("actual receipt prefix changed access ordering outside the finite generation range")
		}
		lastGeneration = actualControl.AccessGeneration
		actualControl.AccessGeneration = control.AccessGeneration
		actualBody, err := contract.EncodeControlCore(actualControl)
		if err != nil || !bytes.Equal(actualBody, controlBody) || !reflect.DeepEqual(current.admission.current, basis) || !bytes.Equal(current.admission.descriptor, descriptor) || !bytes.Equal(current.admission.publicKey, publicKey) || current.admission.recipient != authority || current.admission.trust != trust || current.admission.epoch != epoch || current.admission.controlIncarnation != incarnation {
			t.Fatal("actual receipt prefix changed its independent current authority")
		}
	}
	checkNoWork := func(current *StateSession) {
		t.Helper()
		work := mustSelectedGeneratedWork(t, current)
		g := current.root.Generated
		if len(current.adminIndex.Groups) != 0 || work.parent != nil || work.phase != nil || len(work.attempts) != 0 || len(work.releases) != 0 || len(work.materials) != 0 || len(work.bundles) != 0 || !g.ActiveOwner.IsZero() || g.GeneratedCurrent != 0 || g.Retiring != 0 || g.Attempts != 0 || g.Duties != 0 || g.Hazards != 0 || g.Results != 0 || g.Materials != 0 || g.PendingReleases != 0 || g.Graphs.Count != 0 || current.root.AccessRecordCount != 0 {
			t.Fatal("actual receipt prefix retained live generated work")
		}
		if len(current.root.CurrentAccess.Core.AccessPageRefs) != 0 || current.root.CurrentAccess.Core.AccessRecordsDescriptor != baseline.Root.CurrentAccess.Core.AccessRecordsDescriptor || len(current.accessRecords()) != 0 {
			t.Fatal("actual receipt prefix changed the empty current access set")
		}
		for _, location := range work.content.locations {
			if location.ContentKind == contract.GeneratorContentIntent || location.ContentKind == contract.GeneratorContentGraph {
				t.Fatal("actual receipt prefix retained a logical Intent or graph")
			}
		}
	}
	incoming, err := selected.receiptWindows(t.Context())
	if err != nil || incoming.DomainID != env.Domain || len(incoming.Successes) != 1 || incoming.Successes[0].OperationKind != contract.OperationInitializeDomain || len(incoming.Failures) != 0 {
		t.Fatal("actual receipt prefix requires its authenticated initialization history", err)
	}
	successes, failures := slices.Clone(incoming.Successes), slices.Clone(incoming.Failures)
	order := []contract.ID{incoming.Successes[0].OperationID}
	bodies := map[contract.ID][]byte{order[0]: actualGeneratedReceipt(t, selected, order[0], contract.ReceiptCanonicalSelected)}
	checkWindows := func(current *StateSession) {
		t.Helper()
		windows, err := current.receiptWindows(t.Context())
		if err != nil || len(windows.Successes) != len(successes) || len(windows.Failures) != len(failures) || !slices.Equal(windows.Order, order) {
			t.Fatal("actual receipt prefix changed its exact receipt counts", err)
		}
		assertRetainedReceiptBytes(t, current, bodies)
		for i, row := range windows.Successes {
			if row != successes[i] {
				t.Fatal("actual receipt prefix changed complete success rows or selection order", i)
			}
		}
		for i, row := range windows.Failures {
			if row != failures[i] {
				t.Fatal("actual receipt prefix changed complete failure rows or selection order", i)
			}
		}
	}
	checkCurrent(selected)
	checkNoWork(selected)
	checkWindows(selected)
	beforeCAS := store.cas
	for i := 0; i < 256; i++ {
		t.Logf("actual receipt prefix cycle=%d/256 CAS_delta=%d", i+1, store.cas-beforeCAS)
		label := fmt.Sprintf("full receipt prefix failure %03d", i)
		operation := fixtureID(env.Domain, label)
		var original generatedAttempt
		selected, original = selectActualTerminalFailureReceipt(t, t.Context(), env, selected, operation, label, false)
		selected = generatedLifecycleReopen(t, t.Context(), selected, store)
		work := mustSelectedGeneratedWork(t, selected)
		hazardID := original.expected.Template.HazardID
		hazard, err := contract.InspectGeneratedHazardRecord(work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, hazardID}].Body)
		result, resultErr := contract.InspectGeneratedResultRecord(original.result)
		actual := work.attempts[original.record.AttemptID]
		if err != nil || resultErr != nil || result.SafeFacts.Disposition != contract.GeneratorDispositionOwnedUnusableCreate || len(result.SafeFacts.Target) == 0 || len(result.SafeFacts.ResourceData) == 0 || hazard.HazardID != hazardID || hazard.OriginalAttemptID != original.record.AttemptID || hazard.OriginalOperationID != operation || len(selected.adminIndex.Groups) != 1 || selected.adminIndex.Groups[0].GroupID != hazardID || selected.adminIndex.Groups[0].OwnerKind != format.AdministrativeGeneratedHazard || work.parent != nil || work.phase != nil || len(work.attempts) != 1 || len(work.releases) != 0 || selected.root.Generated.Duties != 0 || selected.root.Generated.Hazards != 1 || selected.root.Generated.Materials != 1 || selected.root.AccessRecordCount != 1 || actual.record != original.record || !bytes.Equal(actual.result, original.result) || store.cas != beforeCAS+4*i+3 {
			t.Fatal("actual receipt prefix failed Final lost its exact single original Hazard", i)
		}
		failureBody := actualGeneratedReceipt(t, selected, operation, contract.ReceiptCanonicalNotSelected)
		failure, err := contract.InspectCompactMutationReceipt(failureBody)
		if err != nil || failure.StateResult != contract.ReceiptStateEffectTerminalFailure || failure.EffectSummary != contract.ReceiptEffectFailed || failure.SummaryCounts[contract.ReceiptEffectCount] != 1 || failure.SummaryCounts[contract.ReceiptSummaryFailureCount] != 1 || failure.SummaryCounts[contract.ReceiptHazardCount] != 1 || failure.SummaryCounts[contract.ReceiptDutyCount] != 0 {
			t.Fatal("actual receipt prefix changed its known failed terminal result", i)
		}
		failures = append(failures, failure)
		order = append(order, operation)
		bodies[operation] = bytes.Clone(failureBody)
		checkCurrent(selected)
		checkWindows(selected)
		inboxKey, err := format.GeneratedResultKey(selected.admission.store.Prefix, selected.root.Domain, original.record.InboxID)
		inbox, present := store.objects[inboxKey]
		if err != nil || !present {
			t.Fatal("actual receipt prefix lost the original immutable inbox", i)
		}
		read := readFixtureStoredBody(inbox, uint32(len(original.result)))
		if read.Status != contract.ReadOK || !bytes.Equal(read.Body, original.result) {
			t.Fatal("actual receipt prefix changed the original immutable packet", i)
		}
		seed := original.material.Core.OperationMaterialID
		if _, present := selected.materialAccess(contract.OperationSeedMaterialKind, seed); !present {
			t.Fatal("actual receipt prefix lost its original operation seed before exit", i)
		}
		warning := selected.root.WarningBits | WarningOrphanGeneratedEffect | WarningDiscardedExactEvidence | WarningPossibleStoreGarbage
		selected = endGeneratedObligation(t, t.Context(), env, selected, hazardID, []contract.ID{hazardID}, entries, warning, seed)
		if selected.root.WarningBits != 0x19 || store.cas != beforeCAS+4*(i+1) {
			t.Fatal("actual receipt prefix changed its fixed warning/CAS result", i)
		}
		if _, present := selected.materialAccess(contract.OperationSeedMaterialKind, seed); present {
			t.Fatal("actual receipt prefix retained discarded seed access", i)
		}
		retained, present := store.objects[inboxKey]
		if !present || retained.Token != inbox.Token {
			t.Fatal("signer-only exit deleted or replaced the original immutable inbox", i)
		}
		read = readFixtureStoredBody(retained, uint32(len(original.result)))
		if read.Status != contract.ReadOK || !bytes.Equal(read.Body, original.result) {
			t.Fatal("signer-only exit changed the warned original inbox", i)
		}
		q := selected.head.EndWork
		successBody := actualGeneratedReceipt(t, selected, q.OperationID, contract.ReceiptCanonicalSelected)
		success, err := contract.InspectCompactMutationReceipt(successBody)
		if err != nil {
			t.Fatal("actual receipt prefix has no checked EndWork receipt", i)
		}
		if len(successes) == contract.MutationReceiptWindowLimit {
			evicted := successes[0].OperationID
			order = slices.DeleteFunc(order, func(id contract.ID) bool { return id == evicted })
			delete(bodies, evicted)
			successes = successes[1:]
		}
		successes = append(slices.Clone(successes), success)
		order = append(order, q.OperationID)
		bodies[q.OperationID] = bytes.Clone(successBody)
		checkCurrent(selected)
		checkNoWork(selected)
		checkWindows(selected)
	}
	if len(successes) != 256 || len(failures) != 256 || store.cas-beforeCAS != 1024 {
		t.Fatal("actual receipt prefix did not complete the fixed 256 paired cycles")
	}
	for _, row := range successes {
		if row.OperationKind != contract.OperationEndSelectedWork {
			t.Fatal("actual receipt prefix retained an outcome outside its 256 real exits")
		}
	}
	if _, retained := selected.mutationReceipts[incoming.Successes[0].OperationID]; retained {
		t.Fatal("actual receipt prefix retained evicted initialization history")
	}
	return selected, contract.MutationReceiptWindows{DomainID: env.Domain, Successes: successes, Failures: failures, Order: order}, bodies
}

func assertRetainedReceiptBytes(t *testing.T, selected *StateSession, want map[contract.ID][]byte) {
	t.Helper()
	_, bodies, err := selected.retainedMutationReceiptBodies()
	if err != nil || len(bodies) != len(want) {
		t.Fatal("complete retained receipt byte set", len(bodies), len(want), err)
	}
	for id, original := range want {
		if len(original) != 471 || !bytes.Equal(bodies[id], original) {
			t.Fatal("retained receipt changed its original encoded bytes", id)
		}
	}
}

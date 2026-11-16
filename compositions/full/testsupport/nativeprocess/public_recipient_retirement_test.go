package nativeprocess

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	stateformat "enkv.sh/core/format"
	observer "enkv.sh/core/testsupport/nativeprocess"
)

func nativeRecipientRetirementAndReenrollment(t *testing.T, cli, helper string, f nativeSequenceFixture, source workflowPair, retired contract.ID) {
	t.Helper()
	s := f.server
	before, _ := workflowHead(t, s)
	registry := nativeLifecycleRecipients(t, s, workflowRoot(t, s, before))
	oldRow := registry[retired]
	expectedEntries := nativeLifecycleEntries(t, s, workflowRoot(t, s, before))
	restore := workflowReadOnlyPair(t, f.source, source)
	removalSource, removalPair := nativeRecipientRemovalProposal(t, source, "new-reader")
	removalRestore := workflowReadOnlyPair(t, removalSource, removalPair)
	for _, change := range []struct {
		kind   uint16
		source string
		args   []string
	}{
		{contract.OperationApplyDeclaration, removalSource, []string{"apply"}},
		{contract.OperationEnvelopeRekey, f.source, []string{"rekey", "--name", "binary"}},
	} {
		args := append(change.args, "--source", change.source, "--source-format", "json", "--json")
		if change.kind == contract.OperationEnvelopeRekey {
			args = append(args, "--out", nativeMaintenanceOutput(t))
		}
		child := workflowRun(t, s, cli, "change", observer.Policy{SuccessorKEK: s.selector(7)}, nil, args...)
		receipt := workflowReceipt(t, workflowResult(t, child, "success").Receipt, change.kind)
		workflowOneHeadAttempt(t, child, true, 200)
		workflowNoRecovery(t, child)
		head, _ := workflowHead(t, s)
		root := workflowRoot(t, s, head)
		current := nativeLifecycleEntries(t, s, root)
		old := expectedEntries["binary"]
		next := current["binary"]
		wantMembers := slices.Clone(old.Recipients)
		wantSubjects := uint32(1)
		wantEffect := uint16(contract.ReceiptEffectNotApplicable)
		if change.kind == contract.OperationApplyDeclaration {
			wantEffect = contract.ReceiptEffectNoChange
			wantMembers = slices.DeleteFunc(wantMembers, func(id contract.ID) bool { return id == retired })
			wantSubjects++
		}
		if next.Incarnation != old.Incarnation || next.ValueState == old.ValueState || bytes.Equal(next.ValueBytes, old.ValueBytes) || !slices.Equal(next.Recipients, wantMembers) || !reflect.DeepEqual(registry, nativeLifecycleRecipients(t, s, root)) || receipt.ChangedSubjects.Count != wantSubjects || receipt.EffectSummary != wantEffect || receipt.OutputSummary != contract.ReceiptOutputNotApplicable {
			t.Fatal("access change did not preserve the exact registry and unaffected memberships")
		}
		// The selected material and its origin must be fresh; all other entry
		// fields and every unrelated entry retain their independent predecessor.
		if next.OriginSnapshot != root.Snapshot || next.OriginTransition != root.Transition {
			t.Fatal("refreshed material does not name its exact selected origin")
		}
		old.Recipients, old.ValueState, old.ValueBytes = wantMembers, next.ValueState, next.ValueBytes
		old.OriginSnapshot, old.OriginTransition = root.Snapshot, root.Transition
		expectedEntries["binary"] = old
		if !reflect.DeepEqual(current, expectedEntries) {
			t.Fatal("access change altered another entry or unrelated field")
		}
		workflowRecoveryWraps(t, s, root, true)
		workflowUnchanged(t, f.source, source)
		workflowUnchanged(t, removalSource, removalPair)
	}
	removalRestore()
	before, _ = workflowHead(t, s)
	beforeEntries := nativeLifecycleEntries(t, s, workflowRoot(t, s, before))
	retirementOutput := nativeMaintenanceOutput(t)
	retirementArgs := []string{"recipients", "retire", "--recipient", "new-reader", "--source", f.source, "--source-format", "json", "--out", retirementOutput, "--json"}
	if s.family == "aws" {
		retirementArgs[2], retirementArgs[3] = "--recipient-id", hex.EncodeToString(retired[:])
	}
	child := workflowRun(t, s, cli, "change", observer.Policy{SuccessorKEK: s.selector(7)}, nil, retirementArgs...)
	workflowResult(t, child, "success")
	nativeMaintenanceDelivered(t, child, retirementOutput)
	nativeObserveMaintenance(t, s, cli, retirementArgs, true)
	workflowResult(t, workflowRun(t, s, cli, "noop", observer.Policy{SuccessorKEK: s.selector(7)}, nil, "apply", "--source", retirementOutput, "--source-format", "json", "--json"), "no-op")
	receipt := workflowReceipt(t, workflowResult(t, child, "success").Receipt, contract.OperationRetireRecipientIdentity)
	workflowOneHeadAttempt(t, child, true, 200)
	workflowNoRecovery(t, child)
	// The original seal still includes the removed secret reader. Its separate
	// feasibility read opens the proposal and current value before mutation.
	decrypts, mutationStarted := 0, false
	for _, event := range child.capture.Events {
		if event.Kind != "http-start" {
			continue
		}
		switch event.Operation {
		case "kms-decrypt":
			decrypts++
			if event.Role != "authority" || mutationStarted {
				t.Fatal("source feasibility used another route or continued into mutation")
			}
		case "kms-sign", "store-write", "head-write":
			mutationStarted = true
			if decrypts != 2 {
				t.Fatal("mutation began without the exact source feasibility reads", decrypts)
			}
		}
	}
	if decrypts != 2 || !mutationStarted {
		t.Fatal("retirement did not complete separate source feasibility before mutation", decrypts)
	}
	after, afterObject := workflowHead(t, s)
	root := workflowRoot(t, s, after)
	entries := nativeLifecycleEntries(t, s, root)
	delete(registry, retired)
	plain := beforeEntries["public"]
	plain.Recipients = []contract.ID{root.CurrentAccess.Core.AuthorityRecipientID}
	beforeEntries["public"] = plain
	if !reflect.DeepEqual(entries, beforeEntries) || !reflect.DeepEqual(registry, nativeLifecycleRecipients(t, s, root)) || receipt.ChangedSubjects.Count != 3 || after.Subject.Exclusion.Retirements.Count != 1 || after.Subject.Exclusion.Retirements.Length != 136 {
		t.Fatal("retirement did not remove exactly the current row and plain membership")
	}
	workflowUnchanged(t, f.source, source)

	for _, args := range [][]string{{"recipients", "retire", "--recipient", "new-reader"}, {"apply"}} {
		args = append(args, "--source", f.source, "--source-format", "json", "--json")
		if args[0] == "recipients" {
			args = append(args, "--out", nativeMaintenanceOutput(t))
		}
		objects := s.objectCount()
		refused := workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, args...)
		var result struct {
			State   string `json:"state_result"`
			Receipt string `json:"receipt_hex"`
		}
		if refused.code != 2 || json.Unmarshal(refused.out, &result) != nil || result.State != "refused" || result.Receipt != "" || s.objectCount() != objects {
			t.Fatal("retired source revived old identity or invented repeat success")
		}
		workflowGETOnly(t, refused)
		_, current := workflowHead(t, s)
		if !reflect.DeepEqual(current, afterObject) {
			t.Fatal("retired source refusal changed HEAD")
		}
		workflowUnchanged(t, f.source, source)
	}
	reconstructed := nativeReconstructedPair(t, s, cli, helper, f.source, source, f.value)
	workflowUnchanged(t, f.source, source)
	restore()
	prepared := workflowRun(t, s, cli, "change", observer.Policy{SuccessorKEK: s.selector(7)}, nil, "recipients", "add", "--source", reconstructed, "--source-format", "json", "--recipient", "new-reader", "--mode", "create", "--display-name", "Changed display", "--encryption-key", s.selector(7), "--json")
	if prepared.code != 0 {
		t.Fatal("fresh preparation after retirement refused", prepared.summary)
	}
	proposal := workflowReadPair(t, reconstructed)
	restore = workflowReadOnlyPair(t, reconstructed, proposal)
	priorIndexes, priorReceipts := nativeLifecycleReceiptState(t, s, root)
	created := workflowRun(t, s, cli, "apply", observer.Policy{SuccessorKEK: s.selector(7)}, nil, "apply", "--source", reconstructed, "--source-format", "json", "--json")
	createdReceipt := workflowReceipt(t, workflowResult(t, created, "success").Receipt, contract.OperationApplyDeclaration)
	workflowOneHeadAttempt(t, created, true, 200)
	currentHead, _ := workflowHead(t, s)
	currentRoot := workflowRoot(t, s, currentHead)
	currentRegistry := nativeLifecycleRecipients(t, s, currentRoot)
	beforeControl := contract.ControlCore{CurrentControl: root.CurrentAccess.Core.CurrentControl, AuthorityKMSBinding: *registry[root.CurrentAccess.Core.AuthorityRecipientID].CurrentBinding}
	afterControl := contract.ControlCore{CurrentControl: currentRoot.CurrentAccess.Core.CurrentControl, AuthorityKMSBinding: *currentRegistry[currentRoot.CurrentAccess.Core.AuthorityRecipientID].CurrentBinding}
	if beforeControl.AccessGeneration == ^uint64(0) {
		t.Fatal("lifecycle fixture exceeds its ordinary access-generation bound")
	}
	beforeControl.AccessGeneration++
	beforeControlBytes, beforeControlErr := contract.EncodeControlCore(beforeControl)
	afterControlBytes, afterControlErr := contract.EncodeControlCore(afterControl)
	for _, selected := range []stateformat.Root{root, currentRoot} {
		index, err := contract.MutationReceiptIndexBlobID(selected.Domain, selected.Generated.SuccessWindow, selected.Generated.FailureWindow, selected.Generated.ReceiptOrder)
		if err != nil || len(selected.Generated.Fragments) == 0 {
			t.Fatal("fresh enrollment receipt-index identity unavailable")
		}
		for _, location := range selected.Generated.Fragments {
			if location.BlobID != index {
				t.Fatal("fresh enrollment selected unrelated generated support")
			}
		}
		expected := stateformat.EmptyGeneratedClosure()
		expected.SuccessWindow, expected.FailureWindow, expected.ReceiptOrder = selected.Generated.SuccessWindow, selected.Generated.FailureWindow, selected.Generated.ReceiptOrder
		expected.Fragments = selected.Generated.Fragments
		if !reflect.DeepEqual(selected.Generated, expected) {
			t.Fatal("fresh enrollment changed the empty generated-work closure")
		}
	}
	if !reflect.DeepEqual(root.Names, currentRoot.Names) || root.ValueEntryCount != currentRoot.ValueEntryCount || root.SecretCount != currentRoot.SecretCount ||
		root.RawBytes != currentRoot.RawBytes || root.WarningBits != currentRoot.WarningBits || root.OutputConfiguration != currentRoot.OutputConfiguration ||
		beforeControlErr != nil || afterControlErr != nil || !bytes.Equal(beforeControlBytes, afterControlBytes) ||
		root.MembershipCount != currentRoot.MembershipCount || root.SecretOrdinaryWrapCount != currentRoot.SecretOrdinaryWrapCount {
		t.Fatal("fresh unassigned enrollment changed unrelated selected state")
	}
	nextIndexes, nextReceipts := nativeLifecycleReceiptState(t, s, currentRoot)
	if len(priorIndexes.Successes) >= contract.MutationReceiptWindowLimit ||
		!slices.Equal(nextIndexes.Successes, append(slices.Clone(priorIndexes.Successes), createdReceipt.OperationID)) ||
		!slices.Equal(nextIndexes.Failures, priorIndexes.Failures) ||
		!slices.Equal(nextIndexes.Order, append(slices.Clone(priorIndexes.Order), createdReceipt.OperationID)) ||
		len(nextReceipts) != len(priorReceipts)+1 || priorReceipts[createdReceipt.OperationID] != nil {
		t.Fatal("fresh enrollment changed prior receipt windows or omitted its one new terminal")
	}
	for id, body := range priorReceipts {
		if !bytes.Equal(nextReceipts[id], body) {
			t.Fatal("fresh enrollment changed an original frozen receipt body")
		}
	}
	newBody, err := hex.DecodeString(workflowResult(t, created, "success").Receipt)
	if err != nil || !bytes.Equal(nextReceipts[createdReceipt.OperationID], newBody) {
		t.Fatal("fresh enrollment changed its new selected receipt bytes")
	}
	var added contract.RecipientRecord
	for id, row := range currentRegistry {
		if _, existed := registry[id]; !existed {
			if !added.RecipientID.IsZero() {
				t.Fatal("fresh enrollment added more than one row")
			}
			added = row
		}
	}
	if len(currentRegistry) != 3 || added.RecipientID.IsZero() || added.RecipientID == retired || added.DisplayName != oldRow.DisplayName || added.CurrentBinding == nil || oldRow.CurrentBinding == nil || added.CurrentBinding.KeySelector != oldRow.CurrentBinding.KeySelector || !bytes.Equal(added.CurrentBinding.SPKI, oldRow.CurrentBinding.SPKI) || added.CurrentBinding.BindingID == oldRow.CurrentBinding.BindingID || added.CurrentBinding.BindingIncarnationID == oldRow.CurrentBinding.BindingIncarnationID || createdReceipt.ChangedSubjects.Count != 1 || !reflect.DeepEqual(entries, nativeLifecycleEntries(t, s, currentRoot)) {
		t.Fatal("reused label and key failed to create a fresh unassigned identity")
	}
	registry[added.RecipientID] = added
	if !reflect.DeepEqual(registry, currentRegistry) {
		t.Fatal("fresh enrollment changed a surviving registry row")
	}
	if _, revived := currentRegistry[retired]; revived {
		t.Fatal("retired identity revived")
	}
	workflowUnchanged(t, reconstructed, proposal)
	final := nativeReconstructedPair(t, s, cli, helper, reconstructed, proposal, f.value)
	finalPair := workflowReadPair(t, final)
	finalRestore := workflowReadOnlyPair(t, final, finalPair)
	workflowResult(t, workflowRun(t, s, cli, "noop", observer.Policy{SuccessorKEK: s.selector(7)}, nil, "apply", "--source", final, "--source-format", "json", "--json"), "no-op")
	workflowUnchanged(t, final, finalPair)
	finalRestore()
	restore()
}

// The bounded lifecycle history fits in one receipt-index fragment. Read its
// complete selected directory and exact receipt bodies without re-encoding them.
func nativeLifecycleReceiptState(t *testing.T, s *workflowServer, root stateformat.Root) (contract.MutationReceiptIndexes, map[contract.ID][]byte) {
	t.Helper()
	indexID, err := contract.MutationReceiptIndexBlobID(root.Domain, root.Generated.SuccessWindow, root.Generated.FailureWindow, root.Generated.ReceiptOrder)
	if err != nil || root.Generated.ReceiptOrder.Count > 32 {
		t.Fatal("lifecycle receipt fixture bound or index unavailable")
	}
	var pages []stateformat.RequiredSupportPageView
	var index []byte
	bodies := map[contract.ID][]byte{}
	for _, ref := range root.RequiredSupport {
		key, err := stateformat.Key(s.prefix, ref)
		if err != nil {
			t.Fatal("lifecycle selected support key unavailable")
		}
		body := s.object(t, key).body
		page, err := stateformat.InspectRequiredSupportPage(body)
		if err != nil || stateformat.CheckReference(ref, body) != nil {
			t.Fatal("lifecycle selected support bytes unavailable")
		}
		pages = append(pages, page)
		for _, row := range page.Records {
			switch row.Kind {
			case contract.MutationReceiptSupportKind:
				receipt, err := contract.InspectCompactMutationReceipt(row.Body)
				if err != nil || receipt.DomainID != root.Domain || receipt.OperationID != row.RecordID || bodies[row.RecordID] != nil {
					t.Fatal("lifecycle selected receipt identity unavailable")
				}
				bodies[row.RecordID] = bytes.Clone(row.Body)
			case contract.GeneratedFragmentSupportKind:
				fragment, err := contract.InspectGeneratedFragment(row.Body)
				if err != nil || fragment.BlobID != indexID || fragment.Count != 1 || index != nil {
					t.Fatal("lifecycle receipt-only fragment bound or identity unavailable")
				}
				index = bytes.Clone(fragment.Payload)
			}
		}
	}
	if stateformat.ValidateFragmentDirectory(root.Generated.Fragments, pages) != nil {
		t.Fatal("lifecycle complete receipt fragment directory unavailable")
	}
	indexes, err := contract.InspectMutationReceiptIndexes(index)
	successes, failures, order, descriptorErr := indexes.Descriptors()
	if err != nil || descriptorErr != nil || successes != root.Generated.SuccessWindow || failures != root.Generated.FailureWindow || order != root.Generated.ReceiptOrder || len(bodies) != len(indexes.Order) {
		t.Fatal("lifecycle exact receipt windows unavailable")
	}
	for class, ids := range [][]contract.ID{indexes.Successes, indexes.Failures} {
		for _, id := range ids {
			row, err := contract.InspectCompactMutationReceipt(bodies[id])
			if err != nil || row.CanonicalOutcome != uint8(class+1) {
				t.Fatal("lifecycle selected receipt class unavailable")
			}
		}
	}
	return indexes, bodies
}

func nativeReconstructedPair(t *testing.T, s *workflowServer, cli, helper, source string, pair workflowPair, value []byte) string {
	t.Helper()
	output := nativeMergePair(t, pair)
	sum := sha256.Sum256(value)
	_, before := workflowHead(t, s)
	objects := s.objectCount()
	child := workflowRun(t, s, helper, "authority", observer.Policy{ExpectedSHA256: map[string]string{"binary": hex.EncodeToString(sum[:])}, SuccessorKEK: s.selector(7)}, nil, "--source", source, "--source-format", "json", "--reconstruct-output", output)
	if child.code != 0 {
		t.Fatal("complete fresh-process reconstruction output refused", child.summary)
	}
	workflowPlaintext(t, child, "plaintext")
	_, after := workflowHead(t, s)
	if !reflect.DeepEqual(before, after) || s.objectCount() != objects {
		t.Fatal("reconstruction output changed selected state")
	}
	workflowUnchanged(t, source, pair)
	compared := workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, "plan", "--trusted", output, "--trusted-format", "json", "--json")
	if workflowResult(t, compared, "success").Payload.Verdict != "match" {
		t.Fatal("reconstructed current configuration did not match public planning")
	}
	workflowGETOnly(t, compared)
	return output
}

// full_only: false
func TestPublicNativeReconstructionOutputSupportsBothRecoveryModes(t *testing.T) {
	cli, helper := workflowExecutables(t)
	for _, family := range []string{"aws", "gcp"} {
		for _, recovery := range []bool{false, true} {
			mode := "disabled"
			if recovery {
				mode = "enabled"
			}
			t.Run(family+"/"+mode, func(t *testing.T) {
				f := nativeSequenceSetupRecovery(t, cli, family, recovery)
				restore := workflowReadOnlyPair(t, f.source, f.pair)
				output := nativeReconstructedPair(t, f.server, cli, helper, f.source, f.pair, f.value)
				pair := workflowReadPair(t, output)
				if (pair.descriptor.Recovery != nil) != recovery {
					t.Fatal("reconstruction changed Recovery mode")
				}
				workflowUnchanged(t, f.source, f.pair)
				restore()
				f.server.clean(t)
			})
		}
	}
}

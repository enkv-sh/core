package nativeprocess

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	observer "enkv.sh/core/testsupport/nativeprocess"
)

// full_only: false
func TestPublicNativeRecipientMutationsPreserveSourceAcrossFaults(t *testing.T) {
	cli, helper := workflowExecutables(t)
	for _, cell := range []struct {
		family, operation string
		kind              uint16
		command           []string
	}{
		{"aws", "envelope-rekey", contract.OperationEnvelopeRekey, []string{"rekey", "--name", "binary"}},
		{"gcp", "envelope-rekey", contract.OperationEnvelopeRekey, []string{"rekey", "--name", "binary"}},
		{"aws", "apply-declaration", contract.OperationApplyDeclaration, []string{"apply"}},
		{"aws", "retire-recipient-identity", contract.OperationRetireRecipientIdentity, []string{"recipients", "retire", "--recipient", "reader"}},
	} {
		t.Run(cell.family+"/"+cell.operation, func(t *testing.T) {
			f := nativeSequenceSetup(t, cli, cell.family)
			s := f.server
			before, beforeObject := workflowHead(t, s)
			beforeRoot := workflowRoot(t, s, before)
			beforeEntry := workflowEntry(t, s, beforeRoot)
			wantEntries := nativeLifecycleEntries(t, s, beforeRoot)
			wantRegistry := nativeLifecycleRecipients(t, s, beforeRoot)
			var reader contract.ID
			for id, row := range wantRegistry {
				if row.CurrentBinding != nil && row.CurrentBinding.KeySelector == s.selector(5) {
					reader = id
				}
			}
			if reader.IsZero() || !slices.Contains(beforeEntry.Recipients, reader) {
				t.Fatal("fault fixture lacks its exact current reader")
			}
			source, pair := f.source, f.pair
			if cell.kind == contract.OperationApplyDeclaration {
				source, pair = nativeRecipientRemovalProposal(t, f.pair, "reader")
			}
			args := append(append([]string{}, cell.command...), "--source", source, "--source-format", "json", "--json")
			restore := workflowReadOnlyPair(t, source, pair)
			baseArgs := slices.Clone(args)
			if cell.kind != contract.OperationApplyDeclaration {
				args = append(slices.Clone(baseArgs), "--out", nativeMaintenanceOutput(t))
			}
			contended := workflowRun(t, s, cli, "apply", observer.Policy{Fault: "head-contention", FaultOrdinal: 1}, nil, args...)
			contention := workflowMutationFaultResult(t, contended, cell.operation, "contention", false)
			workflowOneHeadAttempt(t, contended, false, 412)
			workflowNoRecovery(t, contended)
			_, current := workflowHead(t, s)
			if !reflect.DeepEqual(current, beforeObject) || contention.Payload.Predecessor != hex.EncodeToString(before.Core.Revision[:]) {
				t.Fatal("contention changed selected state or lost its exact predecessor")
			}
			workflowUnchanged(t, source, pair)
			workflowUnchanged(t, f.source, f.pair)
			if cell.kind != contract.OperationApplyDeclaration {
				nativeObserveMaintenance(t, s, cli, args, false)
				args = append(slices.Clone(baseArgs), "--out", nativeMaintenanceOutput(t))
			}

			objects, counts := s.objectCount(), s.snapshot("apply")
			canceled := workflowRun(t, s, cli, "apply", observer.Policy{Fault: "cancel-private-return", FaultOrdinal: 1}, nil, args...)
			var refusal struct {
				Schema    string
				Operation string `json:"operation_kind"`
				State     string `json:"state_result"`
				Receipt   string `json:"receipt_hex"`
				Uncertain bool   `json:"commit_may_have_occurred"`
				Payload   any
			}
			if canceled.code != 2 || json.Unmarshal(canceled.out, &refusal) != nil || refusal.Schema != "ProductResult/v1" || refusal.Operation != cell.operation || refusal.State != "refused" || refusal.Receipt != "" || refusal.Uncertain || refusal.Payload != nil {
				t.Fatal("canceled private return invented transition evidence")
			}
			uses, signaled, joined := canceled.cancellationState()
			if uses != 1 || !signaled || !joined {
				t.Fatal("cancellation did not join its exact private-return barrier")
			}
			for _, event := range canceled.capture.Events {
				if event.Kind == "plaintext" || event.Kind == "recovery-plaintext" || event.Kind == "http-start" && (event.Operation == "head-write" || event.Operation == "store-write" || event.Operation == "kms-sign") {
					t.Fatal("canceled mutation released plaintext or attempted a write")
				}
			}
			afterCounts := s.snapshot("apply")
			_, current = workflowHead(t, s)
			if !reflect.DeepEqual(current, beforeObject) || s.objectCount() != objects || afterCounts.calls["Decrypt/authority"]-counts.calls["Decrypt/authority"] != 1 || afterCounts.calls["Sign/normal"] != counts.calls["Sign/normal"] {
				t.Fatal("canceled mutation changed state or repeated private access")
			}
			workflowNoRecovery(t, canceled)
			workflowUnchanged(t, source, pair)
			workflowUnchanged(t, f.source, f.pair)

			if cell.kind != contract.OperationApplyDeclaration {
				args = append(slices.Clone(baseArgs), "--out", nativeMaintenanceOutput(t))
			}
			unknown := workflowRun(t, s, cli, "apply", observer.Policy{Fault: "lose-head-reply-and-observation", FaultOrdinal: 1}, nil, args...)
			uncertain := workflowMutationFaultResult(t, unknown, cell.operation, "commit-outcome-unknown", true)
			workflowOneHeadAttempt(t, unknown, true, 200)
			workflowNoRecovery(t, unknown)
			returned, refusedReads := false, 0
			for _, event := range unknown.capture.Events {
				if event.Kind == "http-return" && event.Operation == "head-write" {
					returned = true
				}
				if returned && event.Operation == "head-read" {
					if event.Sent || event.Status != 0 {
						t.Fatal("unknown invocation recovered an exact HEAD observation")
					}
					if event.Kind == "http-return" {
						refusedReads++
					}
				}
			}
			selected, selectedObject := workflowHead(t, s)
			root := workflowRoot(t, s, selected)
			entry := workflowEntry(t, s, root)
			if refusedReads == 0 || uncertain.Requested != hex.EncodeToString(selected.Core.Revision[:]) || uncertain.Payload.Predecessor != hex.EncodeToString(before.Core.Revision[:]) || selected.Subject.OperationKind != cell.kind || selected.Core.PreviousDigest != contract.Hash(beforeObject.body) || selected.Core.PreviousToken.Value != beforeObject.etag || selectedObject.etag == beforeObject.etag || entry.Incarnation != beforeEntry.Incarnation || entry.ValueState == beforeEntry.ValueState || bytes.Equal(entry.ValueBytes, beforeEntry.ValueBytes) {
				t.Fatal("independent inspection did not find the exact requested successor")
			}
			wantEntry := beforeEntry
			wantEntry.Recipients = slices.Clone(beforeEntry.Recipients)
			if cell.kind != contract.OperationEnvelopeRekey {
				wantEntry.Recipients = slices.DeleteFunc(wantEntry.Recipients, func(id contract.ID) bool { return id == reader })
			}
			if cell.kind == contract.OperationRetireRecipientIdentity {
				delete(wantRegistry, reader)
			}
			wantEntry.ValueState, wantEntry.ValueBytes = entry.ValueState, entry.ValueBytes
			wantEntry.OriginSnapshot, wantEntry.OriginTransition = root.Snapshot, root.Transition
			wantEntries[beforeEntry.Name] = wantEntry
			if !reflect.DeepEqual(nativeLifecycleEntries(t, s, root), wantEntries) || !reflect.DeepEqual(nativeLifecycleRecipients(t, s, root), wantRegistry) {
				t.Fatal("unknown successor changed an unrelated entry, membership or surviving registry row")
			}
			if cell.kind != contract.OperationApplyDeclaration {
				nativeObserveMaintenance(t, s, cli, args, true)
			}
			workflowRecoveryWraps(t, s, root, true)
			nativeSequenceColdValue(t, s, helper, f.source, f.value, false)
			workflowUnchanged(t, source, pair)
			workflowUnchanged(t, f.source, f.pair)
			restore()
			s.clean(t)
		})
	}
}

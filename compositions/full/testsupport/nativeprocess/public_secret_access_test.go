package nativeprocess

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	observer "enkv.sh/core/testsupport/nativeprocess"
)

// full_only: false
func TestPublicNativeRekeyAndExclusionPreserveSourceAndPlaintext(t *testing.T) {
	cli, helper := workflowExecutables(t)
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			f := nativeSequenceSetup(t, cli, family)
			s := f.server
			head, _ := workflowHead(t, s)
			root := workflowRoot(t, s, head)
			before := workflowEntry(t, s, root)
			registry := nativeLifecycleRecipients(t, s, root)
			var reader contract.ID
			for _, id := range before.Recipients {
				if id != root.CurrentAccess.Core.AuthorityRecipientID {
					reader = id
				}
			}
			if reader.IsZero() {
				t.Fatal("ordinary selected reader absent")
			}
			restore := workflowReadOnlyPair(t, f.source, f.pair)
			for n := 0; n < 2; n++ {
				output := nativeMaintenanceOutput(t)
				args := []string{"rekey", "--source", f.source, "--source-format", "json", "--name", "binary", "--out", output, "--json"}
				child := workflowRun(t, s, cli, "change", observer.Policy{}, nil, args...)
				nativeMaintenanceDelivered(t, child, output)
				nativeObserveMaintenance(t, s, cli, args, true)
				workflowResult(t, workflowRun(t, s, cli, "noop", observer.Policy{}, nil, "apply", "--source", output, "--source-format", "json", "--json"), "no-op")
				receipt := workflowReceipt(t, workflowResult(t, child, "success").Receipt, contract.OperationEnvelopeRekey)
				workflowOneHeadAttempt(t, child, true, 200)
				workflowNoRecovery(t, child)
				head, _ = workflowHead(t, s)
				root = workflowRoot(t, s, head)
				after := workflowEntry(t, s, root)
				if after.Incarnation != before.Incarnation || after.ValueState == before.ValueState || bytes.Equal(after.ValueBytes, before.ValueBytes) || !slices.Equal(after.Recipients, before.Recipients) || !reflect.DeepEqual(registry, nativeLifecycleRecipients(t, s, root)) || receipt.ChangedSubjects.Count != 1 || receipt.EffectSummary != contract.ReceiptEffectNotApplicable || receipt.OutputSummary != contract.ReceiptOutputNotApplicable {
					t.Fatal("rekey did not refresh exact selected protection")
				}
				workflowRecoveryWraps(t, s, root, true)
				workflowUnchanged(t, f.source, f.pair)
				nativeSequenceColdValue(t, s, helper, f.source, f.value, false)
				before = after
			}
			proposal, pair := nativeRecipientRemovalProposal(t, f.pair, "reader")
			proposalRestore := workflowReadOnlyPair(t, proposal, pair)
			child := workflowRun(t, s, cli, "change", observer.Policy{}, nil, "apply", "--source", proposal, "--source-format", "json", "--json")
			receipt := workflowReceipt(t, workflowResult(t, child, "success").Receipt, contract.OperationApplyDeclaration)
			workflowOneHeadAttempt(t, child, true, 200)
			workflowNoRecovery(t, child)
			head, selectedObject := workflowHead(t, s)
			root = workflowRoot(t, s, head)
			after := workflowEntry(t, s, root)
			if after.Incarnation != before.Incarnation || after.ValueState == before.ValueState || bytes.Equal(after.ValueBytes, before.ValueBytes) || !slices.Equal(after.Recipients, []contract.ID{root.CurrentAccess.Core.AuthorityRecipientID}) || !reflect.DeepEqual(registry, nativeLifecycleRecipients(t, s, root)) || receipt.ChangedSubjects.Count != 2 || receipt.EffectSummary != contract.ReceiptEffectNoChange || receipt.OutputSummary != contract.ReceiptOutputNotApplicable {
				t.Fatal("exclusion changed another subject or retained old protected material")
			}
			workflowRecoveryWraps(t, s, root, true)
			nativeSequenceColdValue(t, s, helper, f.source, f.value, false)
			binding := nativeReplacementRecipientBinding(t, s, root, reader)
			encoded, err := contract.EncodeBindingTable([]contract.BindingTableRow{{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: reader, Binding: binding}})
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(f.value)
			oracle := workflowRun(t, s, helper, "recovery", observer.Policy{ExpectedSHA256: map[string]string{"binary": hex.EncodeToString(sum[:])}, RecipientOracle: true, RecipientBinding: encoded, RecipientKEK: binding.KeySelector}, nil, "--source", f.source, "--source-format", "json")
			absent := 0
			for _, event := range oracle.capture.Events {
				if event.Kind == "recipient-plaintext" {
					if !event.WrapAbsent || event.Matched || event.Count != 0 {
						t.Fatal("excluded recipient retained a current wrap")
					}
					absent++
				}
				if event.Kind == "http-start" && event.Operation == "kms-decrypt" {
					t.Fatal("absent current reader attempted private decryption")
				}
			}
			if oracle.code != 2 || absent != 1 {
				t.Fatal("excluded current access was not independently observed")
			}
			objects := s.objectCount()
			repeated := workflowRun(t, s, cli, "noop", observer.Policy{}, nil, "apply", "--source", proposal, "--source-format", "json", "--json")
			if result := workflowResult(t, repeated, "no-op"); result.Receipt != "" {
				t.Fatal("unchanged exclusion declaration invented a receipt")
			}
			privateOpens := 0
			for _, event := range repeated.capture.Events {
				if event.Kind == "http-start" && event.Operation == "kms-decrypt" {
					privateOpens++
					if event.Role != "authority" {
						t.Fatal("repeat apply used another private route")
					}
				}
				if event.Kind == "http-start" && (event.Operation == "head-write" || event.Operation == "store-write" || event.Operation == "kms-sign") {
					t.Fatal("unchanged exclusion declaration attempted a mutation")
				}
			}
			if privateOpens != 2 {
				t.Fatal("repeat apply did not authenticate current and original supplied values")
			}
			workflowNoRecovery(t, repeated)
			_, lastObject := workflowHead(t, s)
			if !reflect.DeepEqual(selectedObject, lastObject) || s.objectCount() != objects {
				t.Fatal("exclusion observation or repeat apply changed selected HEAD")
			}
			workflowUnchanged(t, proposal, pair)
			workflowUnchanged(t, f.source, f.pair)
			proposalRestore()
			restore()
			s.clean(t)
		})
	}
}

func nativeRecipientRemovalProposal(t *testing.T, source workflowPair, recipient string) (string, workflowPair) {
	t.Helper()
	path := nativeMergePair(t, source)
	var editable map[string]any
	if json.Unmarshal(source.editable, &editable) != nil {
		t.Fatal("recipient removal source unavailable")
	}
	entry := editable["entries"].(map[string]any)["binary"].(map[string]any)
	members := entry["recipients"].([]any)
	filtered := slices.DeleteFunc(members, func(member any) bool { return member == recipient })
	if len(filtered)+1 != len(members) {
		t.Fatal("recipient removal must name one declared membership")
	}
	entry["recipients"] = filtered
	body, err := json.MarshalIndent(editable, "", "  ")
	if err != nil || os.WriteFile(path, append(body, '\n'), 0600) != nil {
		t.Fatal("recipient removal declaration failed", err)
	}
	pair := workflowReadPair(t, path)
	if !bytes.Equal(pair.generated, source.generated) || !bytes.Equal(pair.sealed, source.sealed) || len(pair.sealed) == 0 {
		t.Fatal("recipient removal changed its original sealed source")
	}
	return path, pair
}

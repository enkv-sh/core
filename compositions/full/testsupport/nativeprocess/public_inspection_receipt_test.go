package nativeprocess

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	stateformat "enkv.sh/core/format"
	observer "enkv.sh/core/testsupport/nativeprocess"
)

// full_only: false
func TestPublicNativeInspectionAndReceiptsUseOnlyObjectReads(t *testing.T) {
	cli, _ := workflowExecutables(t)
	for _, family := range []string{"aws", "gcp"} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/recovery-%t", family, recovery), func(t *testing.T) {
				s := newWorkflowServer(t, family, recovery)
				// Three joined setup children, then seven independent public reads
				// or syntax refusals. One cell also checks three retired HEAD formats.
				expectedChildren := 10
				oldFormat := family == "aws" && !recovery
				if oldFormat {
					expectedChildren += 4
				}
				s.childLimit = expectedChildren
				f := nativeSequenceSetupOnServer(t, cli, s, recovery)
				head, beforeHead := workflowHead(t, s)
				root := workflowRoot(t, s, head)
				beforeObjects := s.objectCount()
				restore := workflowReadOnlyPair(t, f.source, f.pair)
				defer restore()
				original := map[uint16][]byte{}
				for _, ref := range root.RequiredSupport {
					key, err := stateformat.Key(s.prefix, ref)
					if err != nil {
						t.Fatal(err)
					}
					page, err := stateformat.InspectRequiredSupportPage(s.object(t, key).body)
					if err != nil {
						t.Fatal("selected original support", err)
					}
					for _, row := range page.Records {
						if row.Kind != contract.MutationReceiptSupportKind {
							continue
						}
						r, err := contract.InspectCompactMutationReceipt(row.Body)
						if err != nil || original[r.OperationKind] != nil {
							t.Fatal("setup did not select distinct original receipts", err)
						}
						original[r.OperationKind] = bytes.Clone(row.Body)
					}
				}
				if len(original) != 2 || original[contract.OperationInitializeDomain] == nil || original[contract.OperationApplyDeclaration] == nil {
					t.Fatal("setup did not retain initialization and supplied Apply")
				}
				run := func(command string, extra ...string) workflowChild {
					args := []string{command, "--source", f.source, "--source-format", "json"}
					return workflowRun(t, s, cli, "reader", observer.Policy{}, nil, append(args, extra...)...)
				}
				decode := func(child workflowChild, operation, form string) map[string]json.RawMessage {
					t.Helper()
					var result struct {
						Schema    string
						Operation string `json:"operation_kind"`
						State     string `json:"state_result"`
						Payload   map[string]json.RawMessage
					}
					if child.code != 0 || json.Unmarshal(child.out, &result) != nil || result.Schema != "ProductResult/v1" || result.Operation != operation || result.State != "success" {
						t.Fatal("public query did not return its closed success", child.summary, child.code)
					}
					var actualForm string
					var observation struct{ Domain, Revision, Snapshot, Digest string }
					var fields map[string]string
					if json.Unmarshal(result.Payload["form"], &actualForm) != nil || actualForm != form || json.Unmarshal(result.Payload["observation"], &fields) != nil {
						t.Fatal("public query form or observation differs")
					}
					observation.Domain, observation.Revision = fields["domain_id"], fields["head_revision_id"]
					observation.Snapshot, observation.Digest = fields["snapshot_id"], fields["root_digest"]
					if observation.Domain != hex.EncodeToString(root.Domain[:]) || observation.Revision != hex.EncodeToString(head.Core.Revision[:]) || observation.Snapshot != hex.EncodeToString(root.Snapshot[:]) || observation.Digest != hex.EncodeToString(head.Core.Root.Digest[:]) {
						t.Fatal("public query did not identify the complete current observation")
					}
					workflowGETOnly(t, child)
					if bytes.Contains(child.out, f.value) || bytes.Contains(child.diagnostic, f.value) {
						t.Fatal("public query disclosed selected secret bytes")
					}
					workflowUnchanged(t, f.source, f.pair)
					return result.Payload
				}
				list := decode(run("receipt", "--json"), "receipt-list", "list")
				var rows []struct {
					OperationID   string `json:"operation_id"`
					OperationKind uint16 `json:"operation_kind"`
				}
				if json.Unmarshal(list["receipts"], &rows) != nil || len(rows) != 2 {
					t.Fatal("public list omitted a retained receipt")
				}
				// Expected order comes from setup's selected transition sequence.
				for i, kind := range []uint16{contract.OperationApplyDeclaration, contract.OperationInitializeDomain} {
					stored, err := contract.InspectCompactMutationReceipt(original[kind])
					if err != nil || rows[i].OperationKind != kind || rows[i].OperationID != hex.EncodeToString(stored.OperationID[:]) {
						t.Fatal("public list changed terminal selection order or identity")
					}
					detail := decode(run("receipt", "--operation", rows[i].OperationID, "--json"), "receipt-detail", "detail")
					var body []byte
					if json.Unmarshal(detail["encoded_receipt"], &body) != nil || !bytes.Equal(body, original[kind]) {
						t.Fatal("detail changed original selected receipt bytes")
					}
				}
				domain := decode(run("inspect", "--json"), "inspect", "domain")
				var entries []struct {
					Name      string
					RawLength uint32 `json:"raw_length"`
				}
				var recipients []json.RawMessage
				if json.Unmarshal(domain["entries"], &entries) != nil || len(entries) != 1 || entries[0].Name != "binary" || entries[0].RawLength != uint32(len(f.value)) || json.Unmarshal(domain["recipients"], &recipients) != nil || len(recipients) != 2 {
					t.Fatal("inspection lost selected metadata")
				}
				var readerID contract.ID
				for _, row := range f.pair.descriptor.Recipients {
					if row.RecipientID != f.pair.descriptor.AuthorityRecipientID {
						readerID = row.RecipientID
					}
				}
				if readerID.IsZero() {
					t.Fatal("setup has no ordinary Recipient identity")
				}
				recipient := hex.EncodeToString(readerID[:])
				recipientFlag, recipientTarget := "--recipient-id", recipient
				if family == "gcp" {
					recipientFlag, recipientTarget = "--recipient", "reader"
				}
				scoped := decode(run("inspect", recipientFlag, recipientTarget, "--json"), "inspect-recipient", "recipient")
				if len(scoped) != 5 || json.Unmarshal(scoped["entries"], &entries) != nil || len(entries) != 1 || entries[0].Name != "binary" || scoped["work"] != nil || scoped["warnings"] != nil || scoped["output"] != nil || scoped["recipients"] != nil {
					t.Fatal("Recipient inspection disclosed domain-wide facts or lost granted metadata")
				}
				human := run("receipt")
				if human.code != 0 || !bytes.Contains(human.out, []byte(rows[0].OperationID)) || !bytes.Contains(human.out, []byte(rows[1].OperationID)) {
					t.Fatal("human list omitted retained identities")
				}
				workflowGETOnly(t, human)
				duplicate := run("receipt", "--operation", rows[0].OperationID, "--operation", rows[1].OperationID, "--json")
				if duplicate.code != 2 {
					t.Fatal("duplicate selector was accepted")
				}
				for _, event := range duplicate.capture.Events {
					if event.Kind == "http-start" {
						t.Fatal("invalid selector reached credentials or Store")
					}
				}
				if oldFormat {
					if len(beforeHead.body) < 7 || beforeHead.body[5] != 0 || beforeHead.body[6] != 12 {
						t.Fatal("fixture is not current canonical schema")
					}
					for _, retired := range []byte{8, 9, 10, 11} {
						old := beforeHead
						old.body = bytes.Clone(old.body)
						old.body[6] = retired
						s.mu.Lock()
						s.objects[s.prefix+"/HEAD"] = old
						s.mu.Unlock()
						refused := run("inspect", "--json")
						s.mu.Lock()
						s.objects[s.prefix+"/HEAD"] = beforeHead
						s.mu.Unlock()
						var result struct {
							State   string `json:"state_result"`
							Payload json.RawMessage
						}
						if refused.code == 0 || json.Unmarshal(refused.out, &result) != nil || result.State == "success" || !bytes.Equal(result.Payload, []byte("null")) {
							t.Fatalf("retired canonical version %d supplied a public view", retired)
						}
						workflowGETOnly(t, refused)
					}
				}
				workflowUnchanged(t, f.source, f.pair)
				_, afterHead := workflowHead(t, s)
				if !reflect.DeepEqual(beforeHead, afterHead) || beforeObjects != s.objectCount() || s.children != expectedChildren {
					t.Fatal("public queries changed state or lost joined process inventory")
				}
			})
		}
	}
}

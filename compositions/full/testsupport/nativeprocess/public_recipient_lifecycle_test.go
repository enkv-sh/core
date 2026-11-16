package nativeprocess

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	stateformat "enkv.sh/core/format"
	observer "enkv.sh/core/testsupport/nativeprocess"
)

// full_only: false
func TestPublicNativeRecipientLifecycle(t *testing.T) {
	cli, helper := workflowExecutables(t)
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			s := newWorkflowServer(t, family, true)
			// 3 setup + 7 creation/display/cold-read + 14 retirement/re-enrollment:
			// exactly 24 joined children, each with its existing 512-request cap.
			const expectedChildren = 24
			s.childLimit = expectedChildren
			f := nativeSequenceSetupOnServer(t, cli, s, true)
			_, original := workflowHead(t, s)
			objects := s.objectCount()
			prepared := workflowRun(t, s, cli, "change", observer.Policy{SuccessorKEK: s.selector(7)}, nil,
				"recipients", "add", "--source", f.source, "--source-format", "json", "--recipient", "new-reader", "--mode", "create", "--display-name", "New reader", "--encryption-key", s.selector(7), "--json")
			var local struct {
				Schema, Outcome string
				Delivery        struct{ Outcome string } `json:"local_delivery"`
			}
			if prepared.code != 0 || json.Unmarshal(prepared.out, &local) != nil || local.Schema != "LocalEditResult/v1" || local.Outcome != "edited" || local.Delivery.Outcome != "recorded" {
				t.Fatal("public recipient preparation did not confirm local delivery", prepared.summary)
			}
			publicCalls := 0
			for _, event := range prepared.capture.Events {
				if event.Kind != "http-start" {
					continue
				}
				switch event.Operation {
				case "head-read", "store-read":
				case "kms-public":
					if event.Role != "successor-private" || !event.Sent {
						t.Fatal("preparation used another public key")
					}
					publicCalls++
				default:
					t.Fatal("recipient preparation used private or mutation capability", event.Operation)
				}
			}
			_, afterPreparation := workflowHead(t, s)
			pair := workflowReadPair(t, f.source)
			if publicCalls == 0 || !reflect.DeepEqual(original, afterPreparation) || s.objectCount() != objects || !bytes.Equal(pair.sealed, f.pair.sealed) {
				t.Fatal("local preparation changed canonical state or existing sealed input")
			}
			var generated struct {
				Recipients map[string]struct {
					ID       string
					Creation struct{ Snapshot, Nonce string }
				}
			}
			if json.Unmarshal(pair.generated, &generated) != nil {
				t.Fatal("prepared registry is not JSON")
			}
			preparedRow := generated.Recipients["new-reader"]
			rawID, err := hex.DecodeString(preparedRow.ID)
			if err != nil || len(rawID) != 32 || len(preparedRow.Creation.Snapshot) != 64 || len(preparedRow.Creation.Nonce) != 64 {
				t.Fatal("prepared creation identity or proof absent")
			}
			var recipient contract.ID
			copy(recipient[:], rawID)
			for _, old := range f.pair.descriptor.Recipients {
				if recipient == old.RecipientID {
					t.Fatal("creation reused an existing identity")
				}
			}
			var editable map[string]any
			if json.Unmarshal(pair.editable, &editable) != nil {
				t.Fatal("editable source unavailable")
			}
			entries := editable["entries"].(map[string]any)
			entries["binary"].(map[string]any)["recipients"] = []string{"reader", "new-reader"}
			entries["public"] = map[string]any{"confidentiality": "plain", "recipients": []string{"new-reader"}, "source": map[string]any{"kind": "supplied", "value": "public membership value"}}
			body, err := json.MarshalIndent(editable, "", "  ")
			if err != nil || os.WriteFile(f.source, append(body, '\n'), 0600) != nil {
				t.Fatal("complete membership declaration failed", err)
			}
			pair = workflowPrepare(t, s, cli, f.source, "set-change", workflowReadPair(t, f.source), f.value)
			restore := workflowReadOnlyPair(t, f.source, pair)
			applied := workflowRun(t, s, cli, "apply", observer.Policy{SuccessorKEK: s.selector(7)}, nil, "apply", "--source", f.source, "--source-format", "json", "--json")
			result := workflowResult(t, applied, "success")
			receipt := workflowReceipt(t, result.Receipt, contract.OperationApplyDeclaration)
			workflowOneHeadAttempt(t, applied, true, 200)
			workflowNoRecovery(t, applied)
			workflowUnchanged(t, f.source, pair)
			head, _ := workflowHead(t, s)
			root := workflowRoot(t, s, head)
			selected := nativeLifecycleEntries(t, s, root)
			registry := nativeLifecycleRecipients(t, s, root)
			expectedSecret := append([]contract.ID{}, f.pair.descriptor.Recipients[0].RecipientID, f.pair.descriptor.Recipients[1].RecipientID, recipient)
			slices.SortFunc(expectedSecret, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			expectedPlain := []contract.ID{root.CurrentAccess.Core.AuthorityRecipientID, recipient}
			slices.SortFunc(expectedPlain, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			if receipt.ObservedRevisionID != head.Core.Revision || len(registry) != 3 || root.ValueEntryCount != 2 || root.SecretCount != 1 || len(selected) != 2 || !slices.Equal(selected["binary"].Recipients, expectedSecret) || !slices.Equal(selected["public"].Recipients, expectedPlain) || registry[recipient].DisplayName != "New reader" || registry[recipient].CurrentBinding == nil || registry[recipient].CurrentBinding.KeySelector != s.selector(7) {
				t.Fatal("one Apply did not select complete creation and both memberships")
			}
			workflowRecoveryWraps(t, s, root, true)
			noop := workflowRun(t, s, cli, "noop", observer.Policy{SuccessorKEK: s.selector(7)}, nil, "apply", "--source", f.source, "--source-format", "json", "--json")
			workflowResult(t, noop, "no-op")
			for _, event := range noop.capture.Events {
				if event.Kind == "http-start" && (event.Operation == "head-write" || event.Operation == "store-write" || event.Operation == "kms-sign") {
					t.Fatal("repeat creation attempted a mutation")
				}
			}
			workflowUnchanged(t, f.source, pair)
			restore()
			if json.Unmarshal(pair.editable, &editable) != nil {
				t.Fatal("display source unavailable")
			}
			editable["recipients"].(map[string]any)["new-reader"].(map[string]any)["display_name"] = "Changed display"
			body, err = json.MarshalIndent(editable, "", "  ")
			if err != nil || os.WriteFile(f.source, append(body, '\n'), 0600) != nil {
				t.Fatal("display edit failed", err)
			}
			displayPair := workflowReadPair(t, f.source)
			restore = workflowReadOnlyPair(t, f.source, displayPair)
			display := workflowRun(t, s, cli, "change", observer.Policy{SuccessorKEK: s.selector(7)}, nil, "apply", "--source", f.source, "--source-format", "json", "--json")
			displayResult := workflowResult(t, display, "success")
			workflowReceipt(t, displayResult.Receipt, contract.OperationApplyDeclaration)
			workflowOneHeadAttempt(t, display, true, 200)
			displayHead, _ := workflowHead(t, s)
			displayRoot := workflowRoot(t, s, displayHead)
			afterRegistry := nativeLifecycleRecipients(t, s, displayRoot)
			expectedRow := registry[recipient]
			expectedRow.DisplayName = "Changed display"
			registry[recipient] = expectedRow
			if !reflect.DeepEqual(selected, nativeLifecycleEntries(t, s, displayRoot)) || !reflect.DeepEqual(registry, afterRegistry) || !slices.Equal(root.CurrentAccess.Core.AccessPageRefs, displayRoot.CurrentAccess.Core.AccessPageRefs) {
				t.Fatal("display update changed identity, values, memberships or access")
			}
			workflowUnchanged(t, f.source, displayPair)
			workflowResult(t, workflowRun(t, s, cli, "noop", observer.Policy{SuccessorKEK: s.selector(7)}, nil, "apply", "--source", f.source, "--source-format", "json", "--json"), "no-op")
			workflowUnchanged(t, f.source, displayPair)
			nativeSequenceColdValue(t, s, helper, f.source, f.value, false)
			restore()
			nativeRecipientRetirementAndReenrollment(t, cli, helper, f, displayPair, recipient)
			s.mu.Lock()
			children, limit, requests := s.children, s.childLimit, s.requests
			s.mu.Unlock()
			if children != expectedChildren || limit != expectedChildren || requests > expectedChildren*workflowChildRequestLimit {
				t.Fatalf("lifecycle finite inventory: children=%d limit=%d requests=%d", children, limit, requests)
			}
			s.clean(t)
		})
	}
}

func nativeLifecycleEntries(t *testing.T, s *workflowServer, root stateformat.Root) map[string]contract.ValueEntry {
	t.Helper()
	rows := make(map[string]contract.ValueEntry, len(root.Names))
	for _, name := range root.Names {
		ref := root.ValueEntryPages[int(name.Slot)/stateformat.PageSlots]
		if ref == nil {
			t.Fatal("selected entry page absent")
		}
		key, err := stateformat.Key(s.prefix, *ref)
		if err != nil {
			t.Fatal(err)
		}
		page, err := stateformat.DecodeValueEntryPage(s.object(t, key).body)
		if err != nil || page.Slots[int(name.Slot)%stateformat.PageSlots] == nil {
			t.Fatal("selected entry invalid", err)
		}
		entry := *page.Slots[int(name.Slot)%stateformat.PageSlots]
		if entry.Name != name.Name {
			t.Fatal("selected name table disagrees")
		}
		rows[name.Name] = entry
	}
	return rows
}

func nativeLifecycleRecipients(t *testing.T, s *workflowServer, root stateformat.Root) map[contract.ID]contract.RecipientRecord {
	t.Helper()
	rows := map[contract.ID]contract.RecipientRecord{}
	for _, ref := range root.Recipients {
		if ref == nil {
			continue
		}
		key, err := stateformat.Key(s.prefix, *ref)
		if err != nil {
			t.Fatal(err)
		}
		page, err := stateformat.DecodeRecipientPage(s.object(t, key).body)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range page.Slots {
			if row != nil {
				if _, ok := rows[row.RecipientID]; ok {
					t.Fatal("duplicate selected recipient")
				}
				rows[row.RecipientID] = *row
			}
		}
	}
	return rows
}

package nativeprocess

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	stateformat "enkv.sh/core/format"
	observer "enkv.sh/core/testsupport/nativeprocess"
)

func workflowGCReadOnly(t *testing.T, child workflowChild) {
	t.Helper()
	lists, reads := 0, 0
	for _, event := range child.capture.Events {
		if event.Kind != "http-start" {
			continue
		}
		if !event.Sent {
			t.Fatal("capacity reader did not send its admitted request")
		}
		switch event.Operation {
		case "head-read", "store-read":
			reads++
		case "store-list":
			lists++
		default:
			t.Fatal("capacity reader opened a mutation or KMS capability", event.Operation)
		}
	}
	if lists != 1 || reads == 0 {
		t.Fatal("capacity reader did not use exactly one bounded LIST and selected GETs", lists, reads)
	}
}

func workflowGCResult(t *testing.T, child workflowChild, state string, code int) map[string]json.RawMessage {
	t.Helper()
	var result struct {
		Schema, Operation, State, Kind string
		Payload                        map[string]json.RawMessage
	}
	var envelope map[string]json.RawMessage
	if child.code != code || json.Unmarshal(child.out, &envelope) != nil || json.Unmarshal(envelope["schema"], &result.Schema) != nil ||
		json.Unmarshal(envelope["operation_kind"], &result.Operation) != nil || json.Unmarshal(envelope["state_result"], &result.State) != nil ||
		json.Unmarshal(envelope["operation_payload"], &result.Kind) != nil || json.Unmarshal(envelope["payload"], &result.Payload) != nil ||
		result.Schema != "ProductResult/v1" || result.Operation != "gc-apply" || result.State != state || result.Kind != "CleanupPayload/v1" || result.Payload == nil {
		t.Fatal("native GC did not return its exact closed public result", child.summary, child.code, state)
	}
	if envelope["receipt_hex"] != nil || bytes.Contains(child.out, []byte(`"token"`)) || bytes.Contains(child.out, []byte(`"Token"`)) {
		t.Fatal("native GC fabricated a receipt or disclosed provider tokens")
	}
	return result.Payload
}

func workflowGCMutationCapabilities(t *testing.T, child workflowChild) {
	t.Helper()
	signs := 0
	for _, event := range child.capture.Events {
		if event.Kind == "plaintext" || event.Kind == "recovery-plaintext" {
			t.Fatal("native GC entered plaintext custody")
		}
		if event.Kind == "construction" {
			if event.Role != "normal" || event.Operation != "signer" && event.Operation != "signing-metadata" {
				t.Fatal("native GC constructed an unrelated capability", event.Operation, event.Role)
			}
		}
		if event.Kind != "http-start" {
			continue
		}
		if !event.Sent {
			t.Fatal("native GC opened an unadmitted provider route", event.Operation)
		}
		switch event.Operation {
		case "head-read", "store-read", "store-write", "head-write", "store-delete":
		case "kms-public", "kms-sign":
			if event.Role != "normal" {
				t.Fatal("native GC entered another signing role", event.Role)
			}
			if event.Operation == "kms-sign" {
				signs++
			}
		default:
			t.Fatal("native GC opened LIST, decryption or another private route", event.Operation)
		}
	}
	if signs == 0 {
		t.Fatal("native GC mutation did not sign a selected phase")
	}
}

// full_only: false
func TestPublicNativeCapacityGCPlanApplyAndPendingContinuation(t *testing.T) {
	cli, helper := workflowExecutables(t)
	manifest := nativeManifestProductionBuild(t)
	plugins := newNativePluginFixture(t, manifest)
	for _, family := range []string{"aws", "gcp"} {
		for _, unknown := range []bool{false, true} {
			name := "acknowledged"
			if unknown {
				name = "transmitted_unknown_then_absent"
			}
			t.Run(family+"/"+name, func(t *testing.T) {
				s := newWorkflowServer(t, family, false)
				t.Cleanup(func() { t.Log("native GC retained inventory:", s.summary("reader"), s.summary("apply")) })
				s.objectLimit = 128
				s.childLimit = 7
				if unknown {
					s.childLimit += 7
				}
				f := nativeSequenceSetupOnServer(t, cli, s, false)
				head, originalHEAD := workflowHead(t, s)
				root := workflowRoot(t, s, head)
				page := stateformat.RecipientPage{}
				ref := *root.Recipients[0]
				selectedKey, err := stateformat.Key(s.prefix, ref)
				if err != nil {
					t.Fatal(err)
				}
				page, err = stateformat.DecodeRecipientPage(s.object(t, selectedKey).body)
				if err != nil {
					t.Fatal(err)
				}
				page.Object = contract.Hash([]byte("offline native GC orphan " + family + " " + name))
				body, err := stateformat.EncodeRecipientPage(page)
				if err != nil {
					t.Fatal(err)
				}
				ref.Object, ref.Digest, ref.Length = page.Object, contract.Hash(body), uint32(len(body))
				key, err := stateformat.Key(s.prefix, ref)
				if err != nil {
					t.Fatal(err)
				}
				token := `"offline-orphan-unique"`
				if family == "gcp" {
					token = "987654321"
				}
				s.mu.Lock()
				s.objects[key] = workflowObject{body: bytes.Clone(body), etag: token}
				s.gcListPrefix = s.prefix + "/" + hex.EncodeToString(root.Domain[:]) + "/"
				s.gcListKeys = []string{key}
				s.gcUnknownDelete = unknown
				s.mu.Unlock()
				restore := workflowReadOnlyPair(t, f.source, f.pair)
				defer restore()
				policy := observer.Policy{NoKMS: true, ListPrefix: s.gcListPrefix}
				capacity := workflowRun(t, s, cli, "reader", policy, nil, "inspect", "--source", f.source, "--source-format", "json", "--capacity", "--json")
				var capacityResult struct {
					State   string `json:"state_result"`
					Payload struct{ Schema string }
				}
				if capacity.code != 0 || json.Unmarshal(capacity.out, &capacityResult) != nil || capacityResult.State != "success" || capacityResult.Payload.Schema != "CapacityPayload/v1" {
					t.Fatal("native capacity inspection failed", capacity.summary, capacity.code)
				}
				workflowGCReadOnly(t, capacity)
				path := filepath.Join(administrativeReplacementDirectory(t), "candidate.GCPlan")
				preview := workflowRun(t, s, cli, "reader", policy, nil, "gc", "plan", "--source", f.source, "--source-format", "json", "--out", path, "--json")
				workflowGCReadOnly(t, preview)
				encoded, err := os.ReadFile(path)
				if err != nil {
					t.Fatal("native GC artifact unavailable", err)
				}
				artifact, err := os.Stat(path)
				plan, decodeErr := contract.DecodeGCPlan(encoded)
				if preview.code != 0 || err != nil || artifact.Mode().Perm() != 0600 || len(encoded) > contract.GCPlanMaxLength || decodeErr != nil || len(plan.Targets) != 1 || plan.Targets[0].Token.Value != token || plan.Targets[0].Digest != ref.Digest || plan.HeadRevisionID != head.Core.Revision {
					t.Fatal("native preview did not retain the exact protected original plan", preview.code, err, decodeErr)
				}
				plannedKey, err := contract.StoreObjectKey(s.prefix, root.Domain, plan.Targets[0].Object)
				if err != nil || plannedKey != key {
					t.Fatal("native preview changed the original target coordinate", err)
				}
				_, unchanged := workflowHead(t, s)
				if !reflect.DeepEqual(originalHEAD, unchanged) || bytes.Contains(preview.out, []byte(token)) {
					t.Fatal("native preview changed selection or disclosed its protected token")
				}
				counts := s.snapshot("apply")
				applied := workflowRun(t, s, cli, "apply", observer.Policy{ListPrefix: s.gcListPrefix}, nil, "gc", "apply", "--source", f.source, "--source-format", "json", "--plan", path, "--json")
				state, code := "success", 0
				if unknown {
					state, code = "gc-partial-garbage", 3
				}
				payload := workflowGCResult(t, applied, state, code)
				workflowGCMutationCapabilities(t, applied)
				var active, closed bool
				var remaining uint16
				if json.Unmarshal(payload["active"], &active) != nil || json.Unmarshal(payload["closed"], &closed) != nil || json.Unmarshal(payload["remaining_count"], &remaining) != nil || active || !closed || remaining != map[bool]uint16{false: 0, true: 1}[unknown] {
					t.Fatal("native apply lost its exact selected terminal state")
				}
				after := s.snapshot("apply")
				if after.deletes-counts.deletes != 1 || after.lists != counts.lists || after.headUpdates-counts.headUpdates != 4 {
					t.Fatal("native GC did not use one delete, four phase selections and no relist", s.summary("apply"))
				}
				deletes := 0
				for _, event := range applied.capture.Events {
					if event.Kind == "http-start" && event.Operation == "store-delete" {
						deletes++
						if !event.Sent || event.ObjectKeySHA256 != workflowDigest([]byte(key)) || event.LogicalConditionKind != "match" || string(event.LogicalConditionValue) != token || string(event.WireConditionValue) != token {
							t.Fatal("native GC changed its original physical delete condition")
						}
					}
				}
				if deletes != 1 {
					t.Fatal("native GC did not retain one actual delete transmission")
				}
				if unknown {
					pendingHEAD, pendingObject := workflowHead(t, s)
					pendingRoot := workflowRoot(t, s, pendingHEAD)
					if !pendingRoot.ActiveGC.IsZero() || pendingRoot.GCPlans.Count != 1 {
						t.Fatal("unknown delete did not retain one closed pending GC obligation")
					}
					pendingParts := nativePublicationSelectedParts(t, s)
					beforeInspection := nativePrepareReadFacts(t, workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, "inspect", "--source", f.source, "--source-format", "json", "--json"))
					beforeReceipts := nativePrepareReadFacts(t, workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, "receipt", "--source", f.source, "--source-format", "json", "--json"))
					restore()
					for _, directory := range []string{filepath.Dir(f.source), filepath.Dir(path)} {
						if err := os.RemoveAll(directory); err != nil {
							t.Fatal("pending GC local-loss removal failed", err)
						}
						if _, err := os.Lstat(directory); !os.IsNotExist(err) {
							t.Fatal("pending GC loss retained a source or saved plan directory")
						}
					}
					f.source = filepath.Join(t.TempDir(), "recovered.json")
					sum := sha256.Sum256(f.value)
					environment := plugins.Environment(t, f.source)
					prepared := workflowRunEnvironment(t, s, cli, "authority", observer.Policy{ExpectedSHA256: map[string]string{"binary": hex.EncodeToString(sum[:])}}, nil, environment, nativePrepareArgs(s, f.source, "gc-restored", "--normal-signing-key", s.selector(1))...)
					preparation := nativePrepareResult(t, prepared, "reconstruction")
					if preparation.Recovery.Head != workflowDigest(pendingObject.body) || preparation.Delivery.Outcome != "recorded" {
						t.Fatal("pending GC recovery did not deliver its exact selected observation")
					}
					workflowPlaintext(t, prepared, "plaintext")
					nativePrepareReadOnly(t, prepared)
					f.pair = workflowReadNamedPair(t, f.source, "gc-restored")
					restore = workflowReadOnlyPair(t, f.source, f.pair)
					defer restore()
					compared := workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, "plan", "--trusted", f.source, "--trusted-format", "json", "--json")
					if workflowResult(t, compared, "success").Payload.Verdict != "match" {
						t.Fatal("fresh pending GC reader did not match the recovered pair")
					}
					workflowGETOnly(t, compared)
					afterInspection := nativePrepareReadFacts(t, workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, "inspect", "--source", f.source, "--source-format", "json", "--json"))
					afterReceipts := nativePrepareReadFacts(t, workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, "receipt", "--source", f.source, "--source-format", "json", "--json"))
					_, recoveredHEAD := workflowHead(t, s)
					if !reflect.DeepEqual(beforeInspection, afterInspection) || !reflect.DeepEqual(beforeReceipts, afterReceipts) || !reflect.DeepEqual(pendingParts, nativePublicationSelectedParts(t, s)) || !reflect.DeepEqual(pendingObject, recoveredHEAD) {
						t.Fatal("public recovery changed pending GC progress, exact receipts or warnings")
					}
					// Complete the original controlled remote action after the first
					// child has joined. Its exact condition still names this object.
					s.mu.Lock()
					object, present := s.objects[key]
					if present && object.etag == token {
						delete(s.objects, key)
					}
					s.mu.Unlock()
					if !present || object.etag != token {
						t.Fatal("deferred original native delete lost its exact target")
					}
					continued := workflowRun(t, s, cli, "apply", observer.Policy{ListPrefix: s.gcListPrefix}, nil, "gc", "apply", "--source", f.source, "--source-format", "json", "--operation", hex.EncodeToString(plan.OperationID[:]), "--json")
					workflowGCResult(t, continued, "success", 0)
					workflowGCMutationCapabilities(t, continued)
					settled := s.snapshot("apply")
					if settled.deletes != after.deletes || settled.lists != after.lists {
						t.Fatal("fresh-process continuation retransmitted unknown work or relisted")
					}
				}
				currentHEAD, _ := workflowHead(t, s)
				currentRoot := workflowRoot(t, s, currentHEAD)
				if !reflect.DeepEqual(currentRoot.ValueEntryPages, root.ValueEntryPages) || !reflect.DeepEqual(currentRoot.Names, root.Names) || currentRoot.GCPlans.Count != 0 || !currentRoot.ActiveGC.IsZero() {
					t.Fatal("native GC changed application ownership or retained a completed GC owner")
				}
				workflowUnchanged(t, f.source, f.pair)
				if unknown {
					_, beforeCold := workflowHead(t, s)
					objects := s.objectCount()
					sum := sha256.Sum256(f.value)
					cold := workflowRun(t, s, helper, "authority", observer.Policy{ExpectedSHA256: map[string]string{"binary": hex.EncodeToString(sum[:])}}, nil, "--source", f.source, "--source-format", "json")
					if cold.code != 0 {
						t.Fatal("recovered pending GC pair did not admit fresh private consumption")
					}
					workflowPlaintext(t, cold, "plaintext")
					nativeReplacementReadDecrypt(t, cold, "authority", "normal")
					workflowUnchanged(t, f.source, f.pair)
					_, afterCold := workflowHead(t, s)
					if !reflect.DeepEqual(beforeCold, afterCold) || s.objectCount() != objects {
						t.Fatal("fresh recovered GC consumer changed selected state")
					}
				} else {
					nativeSequenceColdValue(t, s, helper, f.source, f.value, false)
				}
				if s.children != s.childLimit {
					t.Fatal("native GC child inventory differs", s.children, s.childLimit)
				}
				t.Logf("native GC joined children=%d original_deletes=1 continuation_deletes=0 partial=%t", s.children, unknown)
			})
		}
	}
}

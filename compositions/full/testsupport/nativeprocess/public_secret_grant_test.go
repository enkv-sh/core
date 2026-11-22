package nativeprocess

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	observer "enkv.sh/core/testsupport/nativeprocess"
)

// full_only: false
func TestPublicNativeExistingSecretGrantAtSelection(t *testing.T) {
	cli, _ := workflowExecutables(t)
	for _, operation := range []struct{ family, next string }{{"aws", "apply"}, {"gcp", "gc"}, {"aws", "replace"}} {
		family := operation.family
		t.Run(family+"/"+operation.next, func(t *testing.T) {
			s := newWorkflowServer(t, family, true)
			source := filepath.Join(t.TempDir(), "configuration.json")
			if err := os.WriteFile(source, workflowSetup(t, s, true), 0600); err != nil {
				t.Fatal(err)
			}
			workflowResult(t, workflowRun(t, s, cli, "init", observer.Policy{}, nil, "init", "--source", source, "--source-format", "json", "--json"), "success")
			// The beta.1 decoder requires ENKV, kind 4, then uint16(11).
			// All actual HEADs must fence that decoder, including after the
			// grant rows have been carried forward to ordinary pages.
			checkVersion := func() {
				t.Helper()
				_, object := workflowHead(t, s)
				if !bytes.HasPrefix(object.body, []byte{'E', 'N', 'K', 'V', 4, 0, 12}) {
					t.Fatal("selected HEAD lacks the fresh-domain format boundary")
				}
			}
			checkVersion()
			nativePublicationSource(t, source, func(editable map[string]any) {
				editable["entries"] = map[string]any{"binary": map[string]any{"confidentiality": "secret",
					"recipients": []string{}, "source": map[string]any{"kind": "supplied"}}}
			})
			value := []byte("selected-grant-fixture")
			workflowPrepare(t, s, cli, source, "set", workflowReadPair(t, source), value)
			apply := func(policy observer.Policy) workflowChild {
				return workflowRun(t, s, cli, "apply", policy, nil, "apply", "--source", source, "--source-format", "json", "--json")
			}
			workflowResult(t, apply(observer.Policy{}), "success")
			before, _ := workflowHead(t, s)
			entry := workflowEntry(t, s, workflowRoot(t, s, before))
			if len(entry.Recipients) != 1 {
				t.Fatal("initial secret must have only its Authority recipient")
			}
			nativePublicationSource(t, source, func(editable map[string]any) {
				editable["entries"].(map[string]any)["binary"].(map[string]any)["recipients"] = []string{"reader"}
			})
			workflowPrepare(t, s, cli, source, "set-change", workflowReadPair(t, source), value)
			contended := apply(observer.Policy{Fault: "head-contention", FaultOrdinal: 1})
			workflowFaultResult(t, contended, "contention", false)
			workflowOneHeadAttempt(t, contended, false, 412)
			unchanged, _ := workflowHead(t, s)
			if unchanged.Core != before.Core {
				t.Fatal("contended grant changed selected state")
			}
			// Inspect only the public shape of the staged page. The approved
			// holder's private key is used later, after successful selection.
			staged := 0
			var residue string
			s.mu.Lock()
			objects := make([]workflowObject, 0, len(s.objects))
			for _, obj := range s.objects {
				objects = append(objects, obj)
			}
			s.mu.Unlock()
			for _, object := range objects {
				root, err := format.DecodeRoot(object.body)
				if err != nil || len(root.GrantPages) == 0 {
					continue
				}
				for _, base := range root.GrantPages {
					key, err := format.Key(s.prefix, base)
					if err != nil {
						t.Fatal(err)
					}
					residue = key
					page, err := format.DecodeAccessPage(s.object(t, key).body)
					if err != nil {
						t.Fatal(err)
					}
					for _, record := range page.Records {
						for _, wrap := range record.Wraps {
							if wrap.SubjectKind == contract.OrdinaryWrapSubject && wrap.SubjectID != entry.Recipients[0] {
								if !bytes.Equal(wrap.RSACiphertext, make([]byte, contract.RSACiphertextLength)) {
									t.Fatal("staged grant slot contains ciphertext")
								}
								staged++
							}
						}
					}
				}
			}
			if staged != 1 {
				t.Fatal("expected exactly one staged grant slot", staged)
			}
			if operation.next == "replace" {
				apply(observer.Policy{Fault: "exit-after-head-write", FaultOrdinal: 1})
			} else {
				unknown := apply(observer.Policy{Fault: "lose-head-reply-and-observation", FaultOrdinal: 1})
				workflowFaultResult(t, unknown, "commit-outcome-unknown", true)
				workflowOneHeadAttempt(t, unknown, true, 200)
			}
			selected, _ := workflowHead(t, s)
			checkVersion()
			if selected.Core.PreviousRevision != before.Core.Revision || len(selected.GrantWraps) != format.GrantWrapLength {
				t.Fatal("selected grant omitted the exact new row")
			}
			read := func() {
				dest := filepath.Join(t.TempDir(), "selected.env")
				child := workflowRun(t, s, cli, "materialize", observer.Policy{RecipientKEK: s.selector(5)}, nil,
					"materialize", "--source", source, "--source-format", "json", "--out", dest, "--recipient", "reader", "--name", "binary", "--json")
				nativeMaterializationResult(t, child, "success", true)
				b, err := os.ReadFile(dest)
				if err != nil || !bytes.Equal(b, []byte("binary=selected-grant-fixture\n")) {
					t.Fatal("authorized cold read changed selected content", err)
				}
			}
			read()
			root := workflowRoot(t, s, selected)
			live, err := format.Key(s.prefix, root.GrantPages[0])
			if err != nil || live == residue {
				t.Fatal("live grant base", err)
			}
			s.mu.Lock()
			s.gcListPrefix = s.prefix + "/" + hex.EncodeToString(root.Domain[:]) + "/"
			s.gcListKeys = []string{residue, live}
			slices.Sort(s.gcListKeys)
			s.mu.Unlock()
			policy := observer.Policy{NoKMS: true, ListPrefix: s.gcListPrefix}
			capacity := workflowRun(t, s, cli, "reader", policy, nil, "inspect", "--source", source, "--source-format", "json", "--capacity", "--json")
			if capacity.code != 0 {
				t.Fatal("capacity inspection of grant", capacity.code, capacity.summary)
			}
			workflowGCReadOnly(t, capacity)
			switch operation.next {
			case "gc":
				// A successor can normalize a selected grant and then lose its
				// CAS. GC must preserve both authenticated page coordinates.
				sources, err := root.GrantSources(selected)
				if err != nil || len(sources) != 1 {
					t.Fatal("expected one split page", err)
				}
				for logical, split := range sources {
					base, err := format.DecodeAccessPage(s.object(t, live).body)
					if err != nil {
						t.Fatal(err)
					}
					_, ordinary, err := format.RestoreGrantPage(logical, base, split.Rows)
					if err != nil {
						t.Fatal(err)
					}
					key, err := format.Key(s.prefix, logical)
					if err != nil || key == live || key == residue {
						t.Fatal("invalid logical page coordinate", err)
					}
					s.mu.Lock()
					s.objects[key] = workflowObject{body: ordinary, etag: "987654321"}
					s.gcListKeys = append(s.gcListKeys, key)
					slices.Sort(s.gcListKeys)
					s.mu.Unlock()
				}
				path := filepath.Join(administrativeReplacementDirectory(t), "grant.GCPlan")
				preview := workflowRun(t, s, cli, "reader", policy, nil, "gc", "plan", "--source", source, "--source-format", "json", "--out", path, "--json")
				workflowGCReadOnly(t, preview)
				body, err := os.ReadFile(path)
				if preview.code != 0 || err != nil {
					t.Fatal("grant GC plan", err)
				}
				plan, err := contract.DecodeGCPlan(body)
				if err != nil || len(plan.Targets) != 1 {
					t.Fatal("expected only the unselected base", err)
				}
				key, err := contract.StoreObjectKey(s.prefix, root.Domain, plan.Targets[0].Object)
				if err != nil || key != residue {
					t.Fatal("selected grant base entered GC plan", err)
				}
				applied := workflowRun(t, s, cli, "apply", observer.Policy{ListPrefix: s.gcListPrefix}, nil, "gc", "apply", "--source", source, "--source-format", "json", "--plan", path, "--json")
				workflowGCResult(t, applied, "success", 0)
			case "replace":
				out := filepath.Join(administrativeReplacementDirectory(t), "successor.json")
				child := workflowRun(t, s, cli, "successor", observer.Policy{}, nil, "keys", "replace", "--source", source, "--source-format", "json",
					"--target", "recovery", "--authorizer", "authority", "--signing", s.selector(6), "--out", out, "--json")
				reply := nativeReplacementDecode(t, child, "keys-replace-recovery", "TransitionPayload/v1")
				if reply.StoredReceipt == nil || reply.Delivery.Status != "delivered" {
					t.Fatal("replacement did not select and deliver its successor")
				}
				source = out
			case "apply":
				nativePublicationSource(t, source, func(editable map[string]any) {
					editable["entries"].(map[string]any)["extra"] = map[string]any{"confidentiality": "plain", "recipients": []string{},
						"source": map[string]any{"kind": "supplied", "value": "next"}}
				})
				workflowResult(t, apply(observer.Policy{}), "success")
			}
			successor, _ := workflowHead(t, s)
			checkVersion()
			if successor.Core.Revision == selected.Core.Revision || len(successor.GrantWraps) != 0 {
				t.Fatal("unrelated successor retained per-grant HEAD bytes")
			}
			read()
		})
	}
}

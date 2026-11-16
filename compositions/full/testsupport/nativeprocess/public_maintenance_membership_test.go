package nativeprocess

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	observer "enkv.sh/core/testsupport/nativeprocess"
)

// full_only: false
func TestPublicNativeExclusionMaintenancePreservesPendingChanges(t *testing.T) {
	cli, _ := workflowExecutables(t)
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			f := nativeSequenceSetup(t, cli, family)
			s := f.server
			const children = 9
			s.childLimit, s.requestLimit = children, children*workflowChildRequestLimit
			prepared := workflowRun(t, s, cli, "change", observer.Policy{SuccessorKEK: s.selector(7)}, nil,
				"recipients", "add", "--source", f.source, "--source-format", "json", "--recipient", "turnover", "--mode", "create", "--display-name", "Turnover", "--encryption-key", s.selector(7), "--json")
			if prepared.code != 0 {
				t.Fatal("maintenance recipient preparation failed", prepared.summary)
			}
			edit := func(path string, update func(map[string]any)) {
				t.Helper()
				var document map[string]any
				if json.Unmarshal(workflowReadPair(t, path).editable, &document) != nil {
					t.Fatal("maintenance source unavailable")
				}
				update(document)
				body, err := json.MarshalIndent(document, "", "  ")
				if err != nil || os.WriteFile(path, append(body, '\n'), 0600) != nil {
					t.Fatal("maintenance proposal write failed", err)
				}
			}
			edit(f.source, func(document map[string]any) {
				document["entries"].(map[string]any)["binary"].(map[string]any)["recipients"] = []string{"reader", "turnover"}
			})
			original := workflowPrepare(t, s, cli, f.source, "set-change", workflowReadPair(t, f.source), f.value)
			workflowResult(t, workflowRun(t, s, cli, "apply", observer.Policy{SuccessorKEK: s.selector(7)}, nil, "apply", "--source", f.source, "--source-format", "json", "--json"), "success")
			exclusion, exclusionPair := nativeRecipientRemovalProposal(t, original, "reader")
			workflowResult(t, workflowRun(t, s, cli, "change", observer.Policy{}, nil, "apply", "--source", exclusion, "--source-format", "json", "--json"), "success")
			workflowResult(t, workflowRun(t, s, cli, "noop", observer.Policy{}, nil, "apply", "--source", exclusion, "--source-format", "json", "--json"), "no-op")
			workflowUnchanged(t, exclusion, exclusionPair)
			_, beforeRefusal := workflowHead(t, s)
			objects := s.objectCount()
			refused := workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, "recipients", "retire", "--source", f.source, "--source-format", "json", "--recipient", "turnover", "--out", nativeMaintenanceOutput(t), "--json")
			var refusal workflowOutput
			if refused.code != 2 || json.Unmarshal(refused.out, &refusal) != nil || refusal.State != "refused" || refusal.Receipt != "" {
				t.Fatal("stale membership grant was not refused")
			}
			workflowGETOnly(t, refused)
			_, afterRefusal := workflowHead(t, s)
			if !reflect.DeepEqual(beforeRefusal, afterRefusal) || s.objectCount() != objects {
				t.Fatal("stale grant refusal changed canonical state")
			}
			pending := nativeMergePair(t, exclusionPair)
			edit(pending, func(document map[string]any) {
				document["entries"].(map[string]any)["pending"] = map[string]any{"confidentiality": "plain", "recipients": []string{}, "source": map[string]any{"kind": "supplied", "value": "unapplied pending bytes"}}
				document["recipients"].(map[string]any)["reader"].(map[string]any)["display_name"] = "Pending reader display"
			})
			pendingPair := workflowReadPair(t, pending)
			for _, path := range []string{pending, filepath.Join(filepath.Dir(pending), pendingPair.reference)} {
				if err := os.Chmod(path, 0400); err != nil {
					t.Fatal("source pair protection failed", err)
				}
			}
			rekeyed := nativeMaintenanceOutput(t)
			rekey := workflowRun(t, s, cli, "change", observer.Policy{}, nil, "rekey", "--source", pending, "--source-format", "json", "--name", "binary", "--out", rekeyed, "--json")
			workflowResult(t, rekey, "success")
			nativeMaintenanceDelivered(t, rekey, rekeyed)
			retired := nativeMaintenanceOutput(t)
			retirement := workflowRun(t, s, cli, "change", observer.Policy{}, nil, "recipients", "retire", "--source", rekeyed, "--source-format", "json", "--recipient", "turnover", "--out", retired, "--json")
			workflowResult(t, retirement, "success")
			nativeMaintenanceDelivered(t, retirement, retired)
			output := workflowReadPair(t, retired)
			var document map[string]any
			if json.Unmarshal(output.editable, &document) != nil || document["entries"].(map[string]any)["pending"].(map[string]any)["source"].(map[string]any)["value"] != "unapplied pending bytes" || document["recipients"].(map[string]any)["reader"].(map[string]any)["display_name"] != "Pending reader display" || !bytes.Equal(output.sealed, original.sealed) {
				t.Fatal("maintenance changed pending proposals or original seal")
			}
			head, _ := workflowHead(t, s)
			if _, applied := nativeLifecycleEntries(t, s, workflowRoot(t, s, head))["pending"]; applied {
				t.Fatal("maintenance applied pending declaration")
			}
			workflowUnchanged(t, pending, pendingPair)
			workflowUnchanged(t, f.source, original)
			stale := nativeMergePair(t, original)
			for _, path := range []string{stale, filepath.Join(filepath.Dir(stale), original.reference)} {
				for _, directory := range []string{".enkv-locks", ".enkv-pending"} {
					if err := os.Mkdir(filepath.Join(filepath.Dir(path), directory), 0700); err != nil {
						t.Fatal("stale source coordination directory unavailable", err)
					}
				}
				if err := os.WriteFile(filepath.Join(filepath.Dir(path), ".enkv-locks", filepath.Base(path)), nil, 0600); err != nil {
					t.Fatal("stale source coordination lock unavailable", err)
				}
				if err := os.Chmod(path, 0400); err != nil {
					t.Fatal("stale source protection failed", err)
				}
			}
			staleImage := workflowSuccessorImage(t, filepath.Dir(stale))
			staleOutput := nativeMaintenanceOutput(t)
			_, beforeStale := workflowHead(t, s)
			objects = s.objectCount()
			staleChild := workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, "recipients", "retire", "--source", stale, "--source-format", "json", "--recipient", "turnover", "--out", staleOutput, "--json")
			var staleRefusal workflowOutput
			if staleChild.code != 2 || json.Unmarshal(staleChild.out, &staleRefusal) != nil || staleRefusal.State != "refused" || staleRefusal.Receipt != "" {
				t.Fatal("retired identity was not refused from its old portable pair")
			}
			workflowGETOnly(t, staleChild)
			if _, err := os.Lstat(staleOutput); !os.IsNotExist(err) {
				t.Fatal("retired identity refusal delivered an output")
			}
			_, afterStale := workflowHead(t, s)
			if !reflect.DeepEqual(beforeStale, afterStale) || objects != s.objectCount() {
				t.Fatal("retired identity refusal changed canonical state")
			}
			workflowUnchanged(t, stale, original)
			if !reflect.DeepEqual(staleImage, workflowSuccessorImage(t, filepath.Dir(stale))) {
				t.Fatal("retired identity refusal changed portable source inventory")
			}
			if s.children != children {
				t.Fatal("maintenance child inventory differs", s.children)
			}
		})
	}
}

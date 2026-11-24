package nativeprocess

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	observer "enkv.sh/core/testsupport/nativeprocess"
)

// full_only: false
func TestPublicApplyPublisherConstructionFailurePreservesSelectedReceipt(t *testing.T) {
	cli, ledger := nativeApplyPublisherFailureExecutable(t)
	for _, condition := range []string{"missing", "partial"} {
		t.Run(condition, func(t *testing.T) {
			s := newWorkflowServer(t, "aws", false)
			path := filepath.Join(t.TempDir(), "configuration.json")
			if err := os.WriteFile(path, workflowSetup(t, s, false), 0600); err != nil {
				t.Fatal(err)
			}
			workflowResult(t, workflowRun(t, s, cli, "init", observer.Policy{}, nil, "init", "--source", path, "--source-format", "json", "--json"), "success")
			before, _ := workflowHead(t, s)
			nativePublicationSource(t, path, func(source map[string]any) {
				source["entries"] = map[string]any{"binary": map[string]any{"confidentiality": "plain", "recipients": []any{}, "source": map[string]any{"kind": "supplied", "value": "publisher failure keeps this selected value"}}}
			})
			pair := workflowReadPair(t, path)
			if err := os.WriteFile(ledger, nil, 0600); err != nil {
				t.Fatal(err)
			}
			child := workflowRunDeclaredEnvironment(t, s, cli, "apply", observer.Policy{}, nil,
				[]string{"ENKV_TEST_PUBLICATION_FACTORY=" + condition}, []string{"ENKV_TEST_PUBLICATION_FACTORY"},
				"apply", "--publish", "--source", path, "--source-format", "json", "--json")
			var result struct {
				Schema string
				Apply  struct {
					workflowOutput
					Requested   string `json:"requested_revision_id"`
					Observed    string `json:"observed_revision_id"`
					Identity    string `json:"request_identity"`
					OperationID string `json:"operation_id"`
					Diagnostics []struct {
						Subject map[string]string                          `json:"subject"`
						Path    []struct{ Field contract.DiagnosticField } `json:"path"`
						Outcome contract.DiagnosticOutcome                 `json:"outcome"`
						Reason  contract.DiagnosticReason                  `json:"reason"`
					} `json:"diagnostics"`
				}
				Publication struct {
					Stage, Reason string
					Result        json.RawMessage
				}
			}
			if child.code != 3 || json.Unmarshal(child.out, &result) != nil || result.Schema != "ApplyPublicationResult/v1" || result.Apply.Schema != "ProductResult/v1" || result.Apply.State != "success" || result.Publication.Stage != "unstarted" || result.Publication.Reason != "selection-unavailable" || string(result.Publication.Result) != "null" {
				t.Fatalf("publisher construction gated apply or changed the closed stage: exit=%d %s", child.code, child.summary)
			}
			receipt := workflowReceipt(t, result.Apply.Receipt, contract.OperationApplyDeclaration)
			head, _ := workflowHead(t, s)
			root := workflowRoot(t, s, head)
			if head.Core.PreviousRevision != before.Core.Revision || receipt.PredecessorRevisionID != before.Core.Revision || receipt.RequestedRevisionID != head.Core.Revision || receipt.ObservedRevisionID != head.Core.Revision || receipt.OperationID != head.Subject.Operation || result.Apply.Requested != hex.EncodeToString(head.Core.Revision[:]) || result.Apply.Observed != result.Apply.Requested || result.Apply.OperationID != hex.EncodeToString(receipt.OperationID[:]) || result.Apply.Identity != hex.EncodeToString(receipt.RequestIdentityDigest[:]) || root.ValueEntryCount != 1 || root.SecretCount != 0 {
				t.Fatal("publisher failure changed the actual selected apply facts")
			}
			entry := workflowEntry(t, s, root)
			if entry.Name != "binary" || string(entry.ValueBytes) != "publisher failure keeps this selected value" {
				t.Fatal("publisher failure changed the selected plain value")
			}
			foundReceipt := false
			for _, part := range nativePublicationSelectedParts(t, s) {
				if part.SupportKind == contract.PublicationCoordinateSupportKind || part.SupportKind == contract.PublicationMarkerSupportKind {
					t.Fatal("unstarted publication left selected output effects")
				}
				if part.SupportKind == contract.MutationReceiptSupportKind && part.RecordID == receipt.OperationID {
					foundReceipt = hex.EncodeToString(part.Body) == result.Apply.Receipt
				}
			}
			counts := s.snapshot("apply")
			if !foundReceipt || counts.headUpdates != 1 || counts.headCreates != 0 {
				t.Fatal("apply did not retain exactly its real selected receipt and one HEAD update", counts)
			}
			workflowUnchanged(t, path, pair)
			ownership, err := os.ReadFile(ledger)
			wantOwnership := "N"
			if condition == "partial" {
				wantOwnership = "CX"
			}
			if err != nil || string(ownership) != wantOwnership {
				t.Fatalf("publisher construction ownership differs: got=%q want=%q err=%v", ownership, wantOwnership, err)
			}
			if bytes.Contains(child.out, []byte(path)) || bytes.Contains(child.out, []byte(ledger)) {
				t.Fatal("public construction diagnosis exposed a local path")
			}
			diagnostics := result.Apply.Diagnostics
			if len(diagnostics) != 1 || len(diagnostics[0].Subject) != 1 || diagnostics[0].Subject["kind"] != string(contract.SubjectOutputBinding) || len(diagnostics[0].Path) != 1 || diagnostics[0].Path[0].Field != contract.FieldPresence || diagnostics[0].Outcome != contract.DiagnosticUnable || diagnostics[0].Reason != contract.ReasonEvidenceUnavailable {
				t.Fatal("actual publisher construction failure lost its bounded safe diagnosis", diagnostics)
			}
		})
	}
}

func nativeApplyPublisherFailureExecutable(t *testing.T) (string, string) {
	t.Helper()
	root, private := nativeRepository(t), t.TempDir()
	overlay, err := observer.BuildOverlay(root, filepath.Join(private, "overlay"))
	if err != nil {
		t.Fatal(err)
	}
	var mapping struct{ Replace map[string]string }
	var sources []observer.Source
	nativeGeneratedReadJSON(t, overlay.Path, &mapping)
	nativeGeneratedReadJSON(t, overlay.Manifest, &sources)
	ledger := filepath.Join(private, "publisher-ownership")
	for _, edit := range []struct{ relative, anchor, replacement string }{
		{"compositions/full/apply_publication.go", "import (\n\t\"context\"", "import (\n\t\"context\"\n\t\"os\""},
		{"compositions/full/apply_publication.go", "return openConfigurationPublication(ctx, pair, m, i, choices, captured)", `if os.Getenv("ENKV_TEST_PUBLICATION_FACTORY") == "missing" { nativePublisherOwnership('N'); return nil, ErrCell }
 owner, err := openConfigurationPublication(ctx, pair, m, i, choices, captured)
 if err != nil || owner == nil { return owner, err }
 nativePublisherOwnership('C')
 return owner, ErrCell`},
		{"compositions/full/publication.go", "i.CloseInstalled = runtime.Close", "i.CloseInstalled = func() { runtime.Close(); nativePublisherOwnership('X') }"},
	} {
		target := nativeGeneratedSourcePath(root, edit.relative)
		original, err := os.ReadFile(target)
		selected := original
		if previous, present := mapping.Replace[target]; present {
			selected, err = os.ReadFile(previous)
		}
		if err != nil || strings.Count(string(selected), edit.anchor) != 1 {
			t.Fatal("publisher construction overlay anchor differs", edit.relative)
		}
		body := []byte(strings.Replace(string(selected), edit.anchor, edit.replacement, 1))
		if edit.relative == "compositions/full/apply_publication.go" && strings.Contains(edit.anchor, "return openConfigurationPublication") {
			body = append(body, []byte(`
func nativePublisherOwnership(event byte) {
 file, err := os.OpenFile(`+strconv.Quote(ledger)+`, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
 if err != nil { panic(err) }
 n, writeErr := file.Write([]byte{event})
 closeErr := file.Close()
 if writeErr != nil || closeErr != nil || n != 1 { panic(os.ErrInvalid) }
}
`)...)
		}
		path := filepath.Join(private, "overlay", strings.ReplaceAll(edit.relative, "/", "_"))
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		mapping.Replace[target] = path
		at := slices.IndexFunc(sources, func(source observer.Source) bool { return source.Target == target })
		source := observer.Source{Target: target, OriginalSHA256: workflowDigest(original), Replacement: path, ReplacementSHA256: workflowDigest(body)}
		if at < 0 {
			sources = append(sources, source)
		} else {
			sources[at] = source
		}
	}
	slices.SortFunc(sources, func(a, b observer.Source) int { return strings.Compare(a.Target, b.Target) })
	nativeGeneratedWriteJSON(t, overlay.Path, mapping)
	nativeGeneratedWriteJSON(t, overlay.Manifest, sources)
	cli := filepath.Join(private, "enkv")
	args := nativeGoArguments("build", "-mod=readonly", "-tags=netgo", "-trimpath", "-buildvcs=false", "-overlay="+overlay.Path, "-ldflags="+nativePluginLinkerFlags(), "-o", cli, "./cmd/enkv")
	nativeGeneratedGo(t, root, "compositions/full", args...)
	nativeRequireRaceMode(t, cli)
	t.Logf("publisher construction overlay=%s sources=%s", overlay.Path, overlay.Manifest)
	return cli, ledger
}

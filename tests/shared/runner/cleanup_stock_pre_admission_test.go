package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestStockRecoveryPreAdmissionTerminalPreservesTypedNoEffectBoundary(t *testing.T) {
	f := newStockJoinedReadmissionFixture(t)
	if err := stockRecoveryJoinedPreAdmissionTerminal(f.state, f.joinedRun); err != nil {
		t.Fatal("complete joined PreAdmission terminal relation refused", err)
	}
}

// full_only: false
func TestStockRecoveryAdditionalDiagnosticParserPreservesReadReservation(t *testing.T) {
	f := newStockJoinedReadmissionFixture(t)
	facts, err := stockRecoveryAdditionalDiagnostic(f.state, *f.plan.StockRecovery)
	if err != nil || facts.Reservation != (records.BudgetReservation{Requests: 1, BodyBytes: 65537}) || facts.Elapsed != time.Second || facts.Commands != 1 || facts.Verifications != 1 {
		t.Fatal("Sent0 diagnostic refunded reservation, elapsed interval or slots", err)
	}
	if f.plan.StockRecovery.ProductRemaining.Requests != 359 || f.plan.StockRecovery.ProductRemaining.BodyBytes != 989790207 || f.plan.StockRecovery.ProductRemaining.ElapsedSeconds != 2756 || f.plan.StockRecovery.PriorCommands != 6 || f.plan.StockRecovery.PriorVerifications != 1 {
		t.Fatal("independent compact accounting literals changed")
	}
}

// full_only: false
func TestStockRecoveryPreAdmissionTerminalRejectsDamagedEvidence(t *testing.T) {
	for _, condition := range []string{"admitted-identity", "identity-stage", "identity-code", "identity-operation", "identity-nonce", "payload", "commit-possible", "effect-unknown", "requested-revision", "partial-digest", "stdout-overflow", "stderr-overflow", "timeout", "unjoined-command", "missing-wait", "start-save-failed", "changed-cli", "extra-command", "changed-original-prefix", "missing-diagnostic", "prefix-intent", "unjoined-worker", "incomplete-worker-reservation"} {
		t.Run(condition, func(t *testing.T) {
			f := newStockJoinedReadmissionFixture(t)
			path := filepath.Join(f.joinedOutput, "stock-result-02.json")
			var diagnostic map[string]any
			if records.ReadJSON(path, &diagnostic) != nil {
				t.Fatal("joined diagnostic unavailable")
			}
			product := diagnostic["result"].(map[string]any)
			identity := product["request_identity"].(map[string]any)
			switch condition {
			case "admitted-identity":
				product["request_identity"] = strings.Repeat("f", 64)
			case "identity-stage":
				identity["stage"] = "dispatch"
			case "identity-code":
				identity["code"] = "invalid-input"
			case "identity-operation":
				identity["operation_kind"] = "apply-declaration"
			case "identity-nonce":
				identity["request_nonce"] = strings.Repeat("f", 64)
			case "payload":
				product["payload"] = map[string]any{}
			case "commit-possible":
				product["commit_may_have_occurred"] = true
			case "effect-unknown":
				product["effect_summary"] = "effect-unknown"
			case "requested-revision":
				product["requested_revision_id"] = strings.Repeat("f", 64)
			case "partial-digest":
				diagnostic["digest_scope"] = "captured-prefix"
			case "stdout-overflow", "stderr-overflow", "start-save-failed":
				diagnostic[strings.ReplaceAll(condition, "-", "_")] = true
			case "timeout":
				diagnostic["timed_out"] = true
			case "unjoined-command":
				diagnostic["product_joined"] = false
			case "missing-wait":
				diagnostic["wait_returned"] = false
			case "changed-cli":
				diagnostic["cli_sha256"] = strings.Repeat("f", 64)
			}
			productBody, err := json.Marshal(product)
			if err != nil {
				t.Fatal(err)
			}
			productDigest := sha256.Sum256(productBody)
			productSHA256 := hex.EncodeToString(productDigest[:])
			diagnostic["result_sha256"], diagnostic["captured_bytes"] = productSHA256, len(productBody)
			if err := records.WriteJSON(path, diagnostic, 0600); err != nil {
				t.Fatal(err)
			}
			diagnosticBody, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			diagnosticDigest := sha256.Sum256(diagnosticBody)
			indexPath := filepath.Join(f.joinedOutput, "stock-plugin-evidence.json")
			var reboundIndex records.StockPluginEvidence
			var reboundProof records.StockPluginRecoveryEvidence
			proofPath := filepath.Join(f.joinedOutput, "stock-recovery.json")
			if records.ReadJSON(indexPath, &reboundIndex) != nil || records.ReadJSON(proofPath, &reboundProof) != nil {
				t.Fatal("dependent command and proof unavailable")
			}
			command := &reboundIndex.Commands[len(reboundIndex.Commands)-1]
			command.ResultSHA256, command.DiagnosticSHA256, command.DiagnosticBytes = productSHA256, hex.EncodeToString(diagnosticDigest[:]), uint32(len(diagnosticBody))
			reboundProof.ProductResultSHA256, reboundProof.Commands = productSHA256, []records.StockPluginCommand{*command}
			if records.WriteJSON(indexPath, reboundIndex, 0600) != nil || records.WriteJSON(proofPath, reboundProof, 0600) != nil {
				t.Fatal("dependent semantic proof could not be retained")
			}
			switch condition {
			case "extra-command", "changed-original-prefix":
				path = filepath.Join(f.joinedOutput, "stock-plugin-evidence.json")
				var index records.StockPluginEvidence
				if records.ReadJSON(path, &index) != nil {
					t.Fatal("joined command index unavailable")
				}
				if condition == "extra-command" {
					index.Commands = append(index.Commands, index.Commands[len(index.Commands)-1])
				} else {
					index.Commands[0].ResultSHA256 = strings.Repeat("f", 64)
				}
				if err := records.WriteJSON(path, index, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-diagnostic":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "prefix-intent":
				if err := os.WriteFile(filepath.Join(f.joinedOutput, "stock-prefix-cleanup.json"), []byte("{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unjoined-worker", "incomplete-worker-reservation":
				path = filepath.Join(f.joinedRun, "run.json")
				var run runRecord
				if records.ReadJSON(path, &run) != nil {
					t.Fatal("joined coordinator unavailable")
				}
				if condition == "unjoined-worker" {
					run.Scenarios[0].CleanupWorker.Joined = false
				} else {
					run.Scenarios[0].Cleanup.BudgetReserved = nil
				}
				if err := records.WriteJSON(path, run, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if stockRecoveryJoinedPreAdmissionTerminal(f.state, f.joinedRun) == nil {
				t.Fatal("damaged joined pre-admission proof entered a new admission", condition)
			}
		})
	}
}

// full_only: false
func TestStockRecoveryAdditionalDiagnosticParserRejectsDamagedEvidence(t *testing.T) {
	for _, condition := range []string{"missing-sidecar", "incomplete", "foreign-original", "foreign-successor", "different-base", "missing-intent", "missing-completion", "not-started", "unjoined", "exit-failure", "zero-time", "negative-time", "over-time", "clock-overflow", "missing-deadline", "null-deadline", "duplicate-completion-field", "completion-symlink", "unsafe-mode", "deadline", "stdout-overflow", "stderr-overflow", "excess-requests", "excess-body", "unknown-field", "wrong-operation", "source-mismatch", "missing-root", "missing-subtest", "unjoined-native-command", "nonempty-stderr", "changed-stdout", "missing-footer", "settlement-conflict"} {
		t.Run(condition, func(t *testing.T) {
			f := newStockJoinedReadmissionFixture(t)
			path := filepath.Join(f.state, "stock-recovery-additional-accounting.json")
			var sidecar map[string]json.RawMessage
			if records.ReadJSON(path, &sidecar) != nil {
				t.Fatal("additional accounting unavailable")
			}
			if condition == "missing-sidecar" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else {
				var field string
				switch condition {
				case "incomplete":
					sidecar["complete"] = json.RawMessage("false")
				case "foreign-original":
					sidecar["original_run_id"] = json.RawMessage(`"` + strings.Repeat("f", 32) + `"`)
				case "foreign-successor":
					sidecar["failed_recovery_run_id"] = json.RawMessage(`"` + strings.Repeat("f", 32) + `"`)
				case "different-base":
					sidecar["base_accounting"] = json.RawMessage(`null`)
				case "missing-intent":
					delete(sidecar, "intent")
				case "missing-completion":
					delete(sidecar, "completion")
				case "not-started", "unjoined", "exit-failure", "zero-time", "negative-time", "over-time", "clock-overflow", "missing-deadline", "null-deadline", "duplicate-completion-field", "completion-symlink", "unsafe-mode", "deadline", "stdout-overflow", "stderr-overflow", "unknown-field":
					field = "completion"
				case "excess-requests", "excess-body", "wrong-operation":
					field = "intent"
				case "source-mismatch":
					field = "source_archive"
				case "missing-root", "missing-subtest", "unjoined-native-command":
					field = "terminal"
				case "nonempty-stderr":
					field = "stderr"
				case "changed-stdout":
					field = "stdout"
				case "missing-footer":
					field = "capture"
				case "settlement-conflict":
					field = "settlement"
				}
				if field != "" {
					var ref records.StockPluginFile
					if json.Unmarshal(sidecar[field], &ref) != nil {
						t.Fatal("diagnostic reference unavailable")
					}
					body, err := os.ReadFile(ref.Path)
					if err != nil {
						t.Fatal(err)
					}
					if field == "source_archive" || field == "stderr" {
						body = []byte("unexpected bytes\n")
					} else if field == "capture" {
						body = nil
					} else {
						var value map[string]any
						if json.Unmarshal(body, &value) != nil {
							t.Fatal("diagnostic object unavailable")
						}
						switch condition {
						case "not-started":
							value["Started"] = false
						case "unjoined":
							value["Joined"] = false
						case "exit-failure":
							value["ExitCode"] = 1
						case "zero-time":
							value["ElapsedNanos"] = 0
						case "negative-time":
							value["ElapsedNanos"] = -1
						case "over-time":
							value["ElapsedNanos"] = int64(126*time.Second) + 1
						case "clock-overflow":
							value["ElapsedNanos"] = int64(1<<63 - 1)
						case "missing-deadline":
							delete(value, "Deadline")
						case "null-deadline":
							value["Deadline"] = nil
						case "deadline":
							value["Deadline"] = true
						case "stdout-overflow":
							value["StdoutOverflow"] = true
						case "stderr-overflow":
							value["StderrOverflow"] = true
						case "unknown-field":
							value["Unknown"] = true
						case "excess-requests":
							value["ReservedRequests"] = 2
						case "excess-body":
							value["ReservedBodyBytes"] = 65538
						case "wrong-operation":
							value["Probe"].(map[string]any)["operation"] = "aws-store-object"
						case "missing-root":
							value["ordinary"].(map[string]any)["tests"] = []any{}
						case "missing-subtest":
							ordinary := value["ordinary"].(map[string]any)
							ordinary["tests"] = ordinary["tests"].([]any)[:1]
						case "unjoined-native-command":
							value["ordinary"].(map[string]any)["diagnostics"].(map[string]any)["commands"].([]any)[0].(map[string]any)["joined"] = false
						case "changed-stdout":
							value["operation"] = "aws-store-object"
						case "settlement-conflict":
							value["stock_consumed"].(map[string]any)["body_bytes"] = 1
						}
						body, err = json.Marshal(value)
						if err != nil {
							t.Fatal(err)
						}
						if condition == "duplicate-completion-field" {
							body = append([]byte(`{"Started":true,`), body[1:]...)
						}
						body = append(body, '\n')
					}
					if err := os.WriteFile(ref.Path, body, 0600); err != nil {
						t.Fatal(err)
					}
					if condition == "completion-symlink" {
						retained := ref.Path + ".retained"
						if os.Rename(ref.Path, retained) != nil || os.Symlink(retained, ref.Path) != nil {
							t.Fatal("symlink fixture unavailable")
						}
					}
					if condition == "unsafe-mode" && os.Chmod(ref.Path, 0644) != nil {
						t.Fatal("unsafe mode fixture unavailable")
					}
					digest := sha256.Sum256(body)
					ref.SHA256, ref.Length = hex.EncodeToString(digest[:]), uint64(len(body))
					sidecar[field], err = json.Marshal(ref)
					if err != nil {
						t.Fatal(err)
					}
					if field == "terminal" {
						var logRef, provenanceRef records.StockPluginFile
						var provenance map[string]any
						if json.Unmarshal(sidecar["terminal_log"], &logRef) != nil || json.Unmarshal(sidecar["terminal_provenance"], &provenanceRef) != nil || records.ReadJSON(provenanceRef.Path, &provenance) != nil {
							t.Fatal("terminal provenance unavailable")
						}
						logBody := append([]byte("synthetic native terminal\n"), body...)
						if os.WriteFile(logRef.Path, logBody, 0600) != nil {
							t.Fatal("terminal log unavailable")
						}
						logDigest := sha256.Sum256(logBody)
						logRef.SHA256, logRef.Length = hex.EncodeToString(logDigest[:]), uint64(len(logBody))
						provenance["source_bytes"], provenance["source_sha256"] = logRef.Length, logRef.SHA256
						event := provenance["events"].([]any)[0].(map[string]any)
						event["byte_end"], event["bytes"], event["sha256"] = len(logBody), ref.Length, ref.SHA256
						provenanceBody, err := json.Marshal(provenance)
						if err != nil {
							t.Fatal(err)
						}
						provenanceBody = append(provenanceBody, '\n')
						if os.WriteFile(provenanceRef.Path, provenanceBody, 0600) != nil {
							t.Fatal("terminal provenance unavailable")
						}
						provenanceDigest := sha256.Sum256(provenanceBody)
						provenanceRef.SHA256, provenanceRef.Length = hex.EncodeToString(provenanceDigest[:]), uint64(len(provenanceBody))
						sidecar["terminal_log"], err = json.Marshal(logRef)
						if err != nil {
							t.Fatal(err)
						}
						sidecar["terminal_provenance"], err = json.Marshal(provenanceRef)
						if err != nil {
							t.Fatal(err)
						}
					}
				}
				if records.WriteJSON(path, sidecar, 0600) != nil {
					t.Fatal("damaged accounting could not be retained")
				}
			}
			if _, err := stockRecoveryAdditionalDiagnostic(f.state, *f.plan.StockRecovery); err == nil {
				t.Fatal("incomplete additional diagnostic or refilled allowance entered third admission", condition)
			}
		})
	}
}

// full_only: false
func TestStockRecoveryHistoricalProducerCompatibilityIsExact(t *testing.T) {
	f := newStockJoinedReadmissionFixture(t)
	var input workerInput
	if records.ReadJSON(f.first.OriginalInput.Path, &input) != nil {
		t.Fatal("producer metadata unavailable")
	}
	exact := input.PublicConfiguration.Stock.Artifact
	for _, condition := range []string{"reviewed", "cli", "length", "algorithm", "revision", "tree", "dirty", "incomplete"} {
		t.Run(condition, func(t *testing.T) {
			value := exact
			switch condition {
			case "cli":
				value.CLI.SHA256 = strings.Repeat("f", 64)
			case "length":
				value.CLI.Length--
			case "algorithm":
				value.Source.Algorithm = "other-source"
			case "revision":
				value.Source.Revision = strings.Repeat("f", 40)
			case "tree":
				value.Source.Tree = strings.Repeat("f", 40)
			case "dirty":
				value.Source.Dirty = true
			case "incomplete":
				value.Source.ObservationIncomplete = true
			}
			if records.StockPluginRecoveryProducerCompatible(value) != (condition == "reviewed") {
				t.Fatal("historical producer compatibility changed", condition)
			}
		})
	}
}

// full_only: false
func TestStockRecoveryAdditionalDiagnosticParserRoundsBoundedChildTime(t *testing.T) {
	for _, test := range []struct {
		name    string
		elapsed int64
		seconds uint64
	}{
		{"minimum-positive", 1, 1},
		{"exact-second", int64(time.Second), 1},
		{"one-over-second", int64(time.Second) + 1, 2},
		{"maximum-settlement-interval", int64(126 * time.Second), 126},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newStockJoinedReadmissionFixture(t)
			path := filepath.Join(f.state, "stock-recovery-additional-accounting.json")
			var sidecar map[string]json.RawMessage
			if records.ReadJSON(path, &sidecar) != nil {
				t.Fatal("accounting sidecar unavailable")
			}
			for _, field := range []string{"completion", "settlement"} {
				var ref records.StockPluginFile
				var value map[string]any
				if json.Unmarshal(sidecar[field], &ref) != nil || records.ReadJSON(ref.Path, &value) != nil {
					t.Fatal("child clock evidence unavailable")
				}
				if field == "completion" {
					value["ElapsedNanos"] = test.elapsed
				} else {
					value["stock_consumed"].(map[string]any)["elapsed_seconds"] = test.seconds
					value["stock_remaining_after"].(map[string]any)["elapsed_seconds"] = 2757 - test.seconds
					row := value["diagnostic_results"].([]any)[0].(map[string]any)
					row["completion"].(map[string]any)["ElapsedNanos"] = test.elapsed
					row["consumed"].(map[string]any)["elapsed_seconds"] = test.seconds
				}
				body, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				body = append(body, '\n')
				if err := os.WriteFile(ref.Path, body, 0600); err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(body)
				ref.SHA256, ref.Length = hex.EncodeToString(digest[:]), uint64(len(body))
				sidecar[field], err = json.Marshal(ref)
				if err != nil {
					t.Fatal(err)
				}
			}
			if records.WriteJSON(path, sidecar, 0600) != nil {
				t.Fatal("child clock relation unavailable")
			}
			facts, err := stockRecoveryAdditionalDiagnostic(f.state, *f.plan.StockRecovery)
			if err != nil || facts.Elapsed != time.Duration(test.seconds)*time.Second || facts.Commands != 1 || facts.Verifications != 1 {
				t.Fatal("bounded positive joined child time was not rounded once", err)
			}
		})
	}
}

// full_only: false
func TestStockRecoveryAdditionalDiagnosticParserReadsImmutableOwnerInput(t *testing.T) {
	f := newStockJoinedReadmissionFixture(t)
	if err := os.Chmod(f.first.OriginalInput.Path, 0400); err != nil {
		t.Fatal(err)
	}
	facts, err := stockRecoveryAdditionalDiagnostic(f.state, *f.plan.StockRecovery)
	if err != nil || facts.Reservation != (records.BudgetReservation{Requests: 1, BodyBytes: 65537}) {
		t.Fatal("owner-read-only retained input was refused", err)
	}
}

// full_only: false
func TestStockRecoveryPreAdmissionCaptureRequiresHistoricalPipeBound(t *testing.T) {
	for _, field := range []string{"captured_bytes", "stderr_captured_bytes"} {
		for _, test := range []struct {
			name string
			size int
		}{{"exact-cap", 64 << 10}, {"one-over-cap", 64<<10 + 1}} {
			t.Run(field+"/"+test.name, func(t *testing.T) {
				size := test.size
				f := newStockJoinedReadmissionFixture(t)
				path := filepath.Join(f.joinedOutput, "stock-result-02.json")
				var diagnostic map[string]any
				if records.ReadJSON(path, &diagnostic) != nil {
					t.Fatal("diagnostic unavailable")
				}
				diagnostic[field] = size
				if field == "captured_bytes" {
					raw := map[string]any{}
					for key, value := range diagnostic["result"].(map[string]any) {
						raw[key] = value
					}
					raw["warning_summary"] = []string{""}
					empty, err := json.Marshal(raw)
					if err != nil || len(empty) > size {
						t.Fatal("independent full-output fixture unavailable")
					}
					raw["warning_summary"] = []string{strings.Repeat("x", size-len(empty))}
					complete, err := json.Marshal(raw)
					if err != nil || len(complete) != size {
						t.Fatal("full-output fixture length differs")
					}
					digest := sha256.Sum256(complete)
					diagnostic["result_sha256"] = hex.EncodeToString(digest[:])
				}
				if records.WriteJSON(path, diagnostic, 0600) != nil {
					t.Fatal("diagnostic unavailable")
				}
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(body)
				var index records.StockPluginEvidence
				var proof records.StockPluginRecoveryEvidence
				indexPath, proofPath := filepath.Join(f.joinedOutput, "stock-plugin-evidence.json"), filepath.Join(f.joinedOutput, "stock-recovery.json")
				if records.ReadJSON(indexPath, &index) != nil || records.ReadJSON(proofPath, &proof) != nil {
					t.Fatal("proof unavailable")
				}
				command := &index.Commands[len(index.Commands)-1]
				command.DiagnosticSHA256, command.DiagnosticBytes = hex.EncodeToString(digest[:]), uint32(len(body))
				command.ResultSHA256 = diagnostic["result_sha256"].(string)
				proof.ProductResultSHA256 = command.ResultSHA256
				proof.Commands = []records.StockPluginCommand{*command}
				if records.WriteJSON(indexPath, index, 0600) != nil || records.WriteJSON(proofPath, proof, 0600) != nil {
					t.Fatal("proof unavailable")
				}
				err = stockRecoveryJoinedPreAdmissionTerminal(f.state, f.joinedRun)
				if (err == nil) != (size == 64<<10) {
					t.Fatal("historical capture bound changed", size, err)
				}
			})
		}
	}
}

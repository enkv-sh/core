//go:build darwin || linux

package configuration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// full_only: false
func TestTransactionProcessExitRecovery(t *testing.T) {
	const childExit = 79
	if path := os.Getenv("ENKV_TRANSACTION_EXIT_PATH"); path != "" {
		selected, err := strconv.Atoi(os.Getenv("ENKV_TRANSACTION_EXIT_FORMAT"))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()
		var session *EditSession
		var candidate *EditCandidate
		var reconstructed *ReconstructionOutput
		wanted := os.Getenv("ENKV_TRANSACTION_EXIT_PHASE")
		if strings.HasPrefix(os.Getenv("ENKV_TRANSACTION_EXIT_KIND"), "reconstruction") {
			reconstructed, err = BeginReconstruction(ctx, path, Format(selected), "recovered")
			if err == nil {
				session = reconstructed.editor
				if wanted == "staging" {
					session.io.write = func(*os.File, []byte) (int, error) {
						if _, err := fmt.Fprintln(os.Stdout, "transaction-checkpoint=staging"); err != nil {
							return 0, err
						}
						os.Exit(childExit)
						return 0, nil
					}
				}
				_, err = reconstructed.Stage(ctx, reconstructionModel(t, "recovered"))
				candidate = session.candidate
			}
		} else if os.Getenv("ENKV_TRANSACTION_EXIT_KIND") == "rename" {
			session, err = BeginRename(ctx, path, Format(selected), "staging")
			if err == nil {
				candidate, _, err = session.StageRename(ctx)
			}
		} else {
			session, err = BeginEdit(ctx, path, Format(selected))
			if err == nil {
				candidate, _ = stageSourceEdit(t, session, sourceGeneratedJSON+"\n")
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := session.Close(); err != nil {
				t.Error(err)
			}
		}()
		session.io.phase = func(phase string) error {
			if phase == wanted {
				if _, err := fmt.Fprintln(os.Stdout, "transaction-checkpoint="+phase); err != nil {
					return err
				}
				os.Exit(childExit)
			}
			return nil
		}
		if reconstructed != nil {
			_, err = reconstructed.Commit(ctx)
		} else {
			_, err = session.Commit(ctx, candidate)
		}
		t.Fatal("child did not exit at the selected transaction checkpoint", err)
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []struct {
		kind   string
		format Format
		setup  string
	}{{"edit", JSON, sourceSetupJSON}, {"rename", YAML, sourceSetupYAML}, {"reconstruction-json", JSON, ""}, {"reconstruction-yaml", YAML, ""}} {
		phases := []string{"record-durable", "marker-durable", "markers-durable", "installation-truncated", "installation-copied", "generated-installed", "editable-installed", "pair-verified", "staging-cleaned", "marker-cleaned", "markers-cleared", "record-cleaned"}
		if operation.kind == "rename" {
			phases = append(phases, "before-obsolete-cleanup", "obsolete-cleaned")
		}
		if strings.HasPrefix(operation.kind, "reconstruction") {
			phases = append([]string{"staging", "before-candidate-flush", "candidate-flushed", "before-record"}, phases...)
		}
		for _, phase := range phases {
			t.Run(operation.kind+"/"+phase, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "configuration")
				originalGenerated, generated, wantEditable, wantGenerated := "", "", "", ""
				reconstruction := strings.HasPrefix(operation.kind, "reconstruction")
				if reconstruction {
					generated = filepath.Join(filepath.Dir(path), ".enkv/recovered.generated.json")
					wantEditable = reconstructionEditableJSON
					if operation.format == YAML {
						wantEditable = reconstructionEditableYAML()
					}
					wantGenerated = reconstructionGeneratedLiteral()
				} else {
					pair := writePair(t, operation.setup, sourceGeneratedJSON, operation.format)
					path, originalGenerated = pair.Editable.OriginalPath(), pair.Generated.OriginalPath()
					original := readSource(t, path)
					generated = originalGenerated
					wantEditable = strings.Replace(original, `"display_name":""`, `"display_name":"changed"`, 1)
					wantGenerated = sourceGeneratedJSON + "\n"
					if operation.kind == "rename" {
						generated = filepath.Join(filepath.Dir(path), ".enkv/staging.generated.json")
						wantEditable = strings.Replace(original, "  name: prod\n", "  name: staging\n", 1)
						wantEditable = strings.Replace(wantEditable, "generated: '.enkv/prod.generated.json'", "generated: .enkv/staging.generated.json", 1)
						wantGenerated = sourceGeneratedJSON
					}
					if err := pair.Close(); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
				defer cancel()
				child := exec.CommandContext(ctx, executable, "-test.run=^TestTransactionProcessExitRecovery$")
				child.Env = append(os.Environ(), "ENKV_TRANSACTION_EXIT_PATH="+path,
					"ENKV_TRANSACTION_EXIT_FORMAT="+strconv.Itoa(int(operation.format)),
					"ENKV_TRANSACTION_EXIT_KIND="+operation.kind, "ENKV_TRANSACTION_EXIT_PHASE="+phase,
					"TMPDIR="+t.TempDir())
				output, err := child.CombinedOutput()
				var exit *exec.ExitError
				if ctx.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != childExit || string(output) != "transaction-checkpoint="+phase+"\n" {
					t.Fatalf("transaction child did not join at its selected checkpoint: %v, %s", err, output)
				}
				t.Logf("child joined: checkpoint=%s exit=%d", phase, exit.ExitCode())
				if reconstruction && (phase == "staging" || phase == "before-candidate-flush" || phase == "candidate-flushed" || phase == "before-record") {
					for _, destination := range []string{path, generated, coordinationPath(path, ".enkv-pending")} {
						if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
							t.Fatal("private process exit published visible pair ownership", err)
						}
					}
					if delivered, err := RecoverEdit(t.Context(), path, operation.format); delivered != nil || err == nil {
						t.Fatal("private process exit allowed stray candidate adoption", err)
					}
					return
				}
				captured, captureErr := Capture(t.Context(), path, operation.format)
				if errors.Is(captureErr, ErrPendingEdit) {
					if captured != nil {
						t.Fatal("pending capture returned a pair")
					}
					if delivery, err := RecoverEdit(t.Context(), path, operation.format); err != nil || delivery == nil {
						t.Fatal("new process could not complete the saved candidate", err)
					}
				} else {
					if captureErr != nil || captured == nil {
						t.Fatal("process exit left neither a complete pair nor recoverable state", captureErr)
					}
					if err := captured.Close(); err != nil {
						t.Fatal(err)
					}
				}
				if got := readSource(t, path); got != wantEditable {
					t.Fatal("recovery did not preserve the exact candidate editable bytes")
				}
				if got := readSource(t, generated); got != wantGenerated {
					t.Fatal("recovery did not preserve the exact candidate generated bytes")
				}
				if operation.kind == "rename" {
					if _, err := os.Lstat(originalGenerated); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("recovery retained the obsolete rename satellite", err)
					}
				}
				complete, err := Capture(t.Context(), path, operation.format)
				if err != nil {
					t.Fatal("recovered pair cannot be captured", err)
				}
				if _, err := Parse(t.Context(), complete); err != nil {
					t.Fatal("recovered pair cannot be parsed", err)
				}
				if err := complete.Close(); err != nil {
					t.Fatal(err)
				}
				if delivery, err := RecoverEdit(t.Context(), path, operation.format); delivery != nil || err == nil {
					t.Fatal("recovery replayed without pending ownership", err)
				}
			})
		}
	}
}

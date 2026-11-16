package compositionfull

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func prepareResultWire(t *testing.T, result *PrepareResult) map[string]any {
	t.Helper()
	return prepareResultWireWithSourceFailure(t, result, nil)
}

func prepareResultWireWithSourceFailure(t *testing.T, result *PrepareResult, wantSourceFailure map[string]any) map[string]any {
	t.Helper()
	body, err := RenderPrepareJSON(result)
	if err != nil {
		t.Fatal("prepare result did not render", err)
	}
	var record map[string]any
	if err := json.Unmarshal(body, &record); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(record))
	for key := range record {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	want := []string{"branch", "dependencies", "diagnostics", "local_delivery", "missing_inputs", "operation", "outcome", "recovery", "request_id", "schema"}
	if wantSourceFailure != nil {
		want = append(want, "source_failure")
	}
	if !reflect.DeepEqual(keys, want) || record["schema"] != "enkv/prepare-result/v2" || record["operation"] != "prepare" {
		t.Fatal("prepare result changed its exact public members", keys)
	}
	if wantSourceFailure != nil && !reflect.DeepEqual(record["source_failure"], wantSourceFailure) {
		t.Fatal("prepare result changed its exact source failure", record["source_failure"])
	}
	if _, ok := record["missing_inputs"].([]any); !ok {
		t.Fatal("prepare result lacks its complete missing-input vector")
	}
	id, ok := record["request_id"].(string)
	if !ok || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(id) || id == strings.Repeat("0", 64) {
		t.Fatal("prepare result lacks fresh nonzero correlation")
	}
	return record
}

func prepareRecoveryRequestForTest(source configurationReaderSource, path string, format configuration.Format) PrepareRequest {
	prefix, normal := source.archive.Location.PrefixBeforeHEAD, source.archive.SignerSelector
	return PrepareRequest{Source: path, Format: format, Recovery: &PrepareRecoveryRequest{Name: "restored", Provider: source.archive.Family,
		Bucket: source.archive.Location.Bucket, Region: source.archive.Location.Region, Prefix: &prefix, NormalSigningKey: &normal}}
}

// full_only: false
func TestPrepareSourceStabilityFailureKeepsNativeEvidenceAndPrecedence(t *testing.T) {
	changed := errors.Join(configuration.ErrCapture, configuration.ErrEdit, configuration.ErrSourceChanged)
	for _, tc := range []struct {
		name, reason string
		cause        error
		code         int
	}{
		{"positive-change", "source-changed", changed, 2},
		{"capture-only", "source-unavailable", configuration.ErrCapture, 3},
		{"edit-only", "source-unavailable", configuration.ErrEdit, 3},
		{"inspection-unavailable", "source-unavailable", errors.Join(configuration.ErrCapture, os.ErrPermission), 3},
		{"pending", "pending-edit", errors.Join(changed, configuration.ErrPendingEdit), 3},
		{"locked", "contention", errors.Join(changed, configuration.ErrEditLocked), 3},
		{"cancelled", "cancelled", errors.Join(changed, context.Canceled), 2},
		{"deadline", "cancelled", errors.Join(changed, context.DeadlineExceeded), 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := NewPrepareRefusal()
			if err != nil {
				t.Fatal(err)
			}
			result.facts.Branch = "existing"
			result.facts.Diagnostics = nil
			result.sourceFailure(t.Context(), tc.cause, true)
			record := prepareResultWire(t, result)
			if record["outcome"] != "incomplete" || PrepareExitCode(result, nil) != tc.code || !reflect.DeepEqual(result.facts.Diagnostics, []prepareDiagnostic{{Reason: tc.reason, Subject: "source"}}) {
				t.Fatal("source stability classification exceeded its native evidence", record)
			}
		})
	}
}

// full_only: false
func TestPrepareAbsentOccupiedSatelliteRefusesWithoutConstruction(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			source := configurationApplyPair(t, family, configuration.JSON, nil)
			dir := t.TempDir()
			generated := filepath.Join(dir, ".enkv", "restored.generated.json")
			if err := os.Mkdir(filepath.Dir(generated), 0700); err != nil {
				t.Fatal(err)
			}
			foreign := []byte("foreign-unowned-satellite-sentinel")
			if err := os.WriteFile(generated, foreign, 0600); err != nil {
				t.Fatal(err)
			}
			request := prepareRecoveryRequestForTest(source, filepath.Join(dir, "configuration.json"), configuration.JSON)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			calls := 0
			result, err := prepareConfiguration(ctx, request, func(context.Context, ReconstructionConfig) (*core.ReconstructionEngine, error) {
				calls++
				return nil, errors.New("private-constructor-sentinel")
			})
			record := prepareResultWire(t, result)
			if err == nil || calls != 0 || PrepareExitCode(result, nil) != 2 || record["outcome"] != "refused" || record["branch"] != "unclassified" || !reflect.DeepEqual(record["diagnostics"], []any{map[string]any{"reason": "target-occupied", "subject": "generated"}}) {
				t.Fatal("occupied satellite lost its known refusal", calls, record, err)
			}
			after, readErr := os.ReadFile(generated)
			if readErr != nil || !bytes.Equal(after, foreign) {
				t.Fatal("prepare changed foreign satellite", readErr)
			}
			if _, err := os.Lstat(request.Source); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("prepare created editable source", err)
			}
		})
	}
}

type prepareCancelAfterSelectedClose struct {
	core.PublicSelectedReader
	cancel context.CancelFunc
}

func (r *prepareCancelAfterSelectedClose) Close() {
	r.PublicSelectedReader.Close()
	r.cancel()
}

// full_only: false
func TestPrepareCancellationAfterCommittedProjectionPreservesRecovery(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			projection, _, selected := configurationReconstructionProjection(t, family)
			projection.Close()
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			source := configurationReaderSource{archive: selected.archive}
			request := prepareRecoveryRequestForTest(source, filepath.Join(t.TempDir(), "configuration.json"), configuration.JSON)
			result, err := prepareConfiguration(ctx, request, func(context.Context, ReconstructionConfig) (*core.ReconstructionEngine, error) {
				return core.NewInstalledReconstruction(core.ReconstructionInstallation{Candidate: selected, Normal: selected,
					Construct: func(context.Context, contract.StoreConfiguration) (core.PublicSelectedReader, core.Result) {
						return &prepareCancelAfterSelectedClose{PublicSelectedReader: selected, cancel: cancel}, core.Result{}
					},
					Verify: func(_ context.Context, pins contract.ReconstructionVerificationPins, _ time.Time) (core.ReconstructionVerifier, error) {
						return &configurationReconstructionVerifier{source: selected, pins: pins}, nil
					}, CloseInstalled: func() {}})
			})
			record := prepareResultWire(t, result)
			recovery := record["recovery"].(map[string]any)
			head := selected.archive.MustObject(t, selected.archive.Location.PrefixBeforeHEAD+"/HEAD")
			digest := sha256.Sum256(head.Body)
			if err == nil || !errors.Is(err, context.Canceled) || !errors.Is(ctx.Err(), context.Canceled) || recovery["status"] != "complete" || recovery["domain"] != readerID(selected.archive.Domain) || recovery["head"] != hex.EncodeToString(digest[:]) || record["outcome"] != "incomplete" || PrepareExitCode(result, nil) != 2 || !reflect.DeepEqual(record["diagnostics"], []any{map[string]any{"reason": "cancelled", "subject": "recovery"}}) {
				t.Fatal("late cancellation erased committed recovery or became unavailable state", record, err)
			}
			if _, err := os.Lstat(request.Source); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("cancelled recovery installed a partial pair", err)
			}
		})
	}
}

// full_only: false
func TestPrepareRecoveredPairSurvivesDependencyFailureAndUsesExistingBranch(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		for _, encoding := range []configuration.Format{configuration.JSON, configuration.YAML} {
			t.Run(fmt.Sprintf("%s/%d", family, encoding), func(t *testing.T) {
				projection, _, selected := configurationReconstructionProjection(t, family)
				projection.Close()
				request := prepareRecoveryRequestForTest(configurationReaderSource{archive: selected.archive}, filepath.Join(t.TempDir(), "chosen-local-name"), encoding)
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				calls := 0
				open := func(_ context.Context, config ReconstructionConfig) (*core.ReconstructionEngine, error) {
					calls++
					if config.Family != selected.archive.Family {
						t.Fatal("independent provider changed")
					}
					if family == "aws" {
						if config.AWS == nil || config.GCP != nil || config.AWS.Candidate.Bucket != selected.archive.Location.Bucket || config.AWS.Candidate.Prefix != selected.archive.Location.PrefixBeforeHEAD || config.AWS.Normal == nil || config.AWS.Normal.KeyARN != selected.archive.SignerSelector || config.AWS.Recovery != nil {
							t.Fatal("AWS recovery inputs changed")
						}
					} else {
						if config.GCP == nil || config.AWS != nil || config.GCP.Candidate.Bucket != selected.archive.Location.Bucket || config.GCP.Candidate.Prefix != selected.archive.Location.PrefixBeforeHEAD || config.GCP.Normal == nil || config.GCP.Normal.KeyVersion != selected.archive.SignerSelector || config.GCP.Recovery != nil {
							t.Fatal("GCP recovery inputs changed")
						}
					}
					return core.NewInstalledReconstruction(core.ReconstructionInstallation{Candidate: selected, Normal: selected,
						Construct: func(context.Context, contract.StoreConfiguration) (core.PublicSelectedReader, core.Result) {
							return selected, core.Result{}
						},
						Verify: func(_ context.Context, pins contract.ReconstructionVerificationPins, _ time.Time) (core.ReconstructionVerifier, error) {
							return &configurationReconstructionVerifier{source: selected, pins: pins}, nil
						}, CloseInstalled: func() {}})
				}
				result, err := prepareConfiguration(ctx, request, open)
				if err != nil {
					t.Fatal("unselected recovered dependencies constructed an installation", err)
				}
				record := prepareResultWire(t, result)
				delivery := record["local_delivery"].(map[string]any)
				dependencies := record["dependencies"].(map[string]any)
				wantRequirements := []any{}
				for i, semantic := range []string{"fixture/aws/config/v1", "fixture/gcp/config/v1", "fixture/github-environment/config/v1", "fixture/github-organization/config/v1", "fixture/github-repository/config/v1"} {
					wantRequirements = append(wantRequirements, map[string]any{"role": "output", "plugin": nil, "contract": semantic, "protocol_version": float64(6), "artifact": nil, "status": "missing", "reason": "selection-required", "subjects": []any{float64(i)}})
				}
				wantDependencies := map[string]any{"assessment": "complete", "minimum_administrative_ready": true, "all_declared_ready": false, "requirements": wantRequirements, "installations": []any{}, "settings_failure": nil}
				if calls != 1 || record["branch"] != "reconstruction" || record["outcome"] != "incomplete" || PrepareExitCode(result, nil) != 2 || delivery["outcome"] != "recorded" || delivery["cleanup_failed"] != false || delivery["recovery_source"] != nil || !reflect.DeepEqual(dependencies, wantDependencies) || !reflect.DeepEqual(record["diagnostics"], []any{map[string]any{"reason": "dependency-missing", "subject": "dependencies"}}) {
					t.Fatal("dependency failure erased recovered delivery or administrative readiness", record)
				}
				for key, path := range map[string]string{"editable_digest": request.Source, "generated_digest": filepath.Join(filepath.Dir(request.Source), ".enkv", "restored.generated.json")} {
					body, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					digest := sha256.Sum256(body)
					if delivery["readback"].(map[string]any)[key] != hex.EncodeToString(digest[:]) {
						t.Fatal("prepare readback lost the exact installed bytes")
					}
				}
				before := configurationApplySourceImage(t, filepath.Dir(request.Source))
				request.Recovery = nil
				again, err := prepareConfiguration(ctx, request, open)
				if err != nil || calls != 1 {
					t.Fatal("rerun repeated reconstruction", calls, err)
				}
				next := prepareResultWire(t, again)
				if next["branch"] != "existing" || next["outcome"] != "incomplete" || !reflect.DeepEqual(next["dependencies"], dependencies) {
					t.Fatal("existing rerun changed declared dependency facts", next)
				}
				configurationApplyAssertUnchanged(t, filepath.Dir(request.Source), before)
			})
		}
	}
}

// full_only: false
func TestPrepareInvalidRecoveryInputsAndContextsNeverConstruct(t *testing.T) {
	source := configurationApplyPair(t, "aws", configuration.JSON, nil)
	for _, condition := range []string{"omitted-prefix", "empty-normal-key", "zero-domain", "wrong-provider", "empty-owner", "nonfinite", "cancelled"} {
		t.Run(condition, func(t *testing.T) {
			request := prepareRecoveryRequestForTest(source, filepath.Join(t.TempDir(), "configuration.json"), configuration.JSON)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			invocation := ctx
			empty := ""
			zero := contract.ID{}
			switch condition {
			case "omitted-prefix":
				request.Recovery.Prefix = nil
			case "empty-normal-key":
				request.Recovery.NormalSigningKey = &empty
			case "zero-domain":
				request.Recovery.ExpectedDomain = &zero
			case "wrong-provider":
				request.Recovery.Provider = 255
			case "empty-owner":
				request.Recovery.ExpectedOwner = &empty
			case "nonfinite":
				invocation = context.Background()
			case "cancelled":
				cancel()
			}
			calls := 0
			result, err := prepareConfiguration(invocation, request, func(context.Context, ReconstructionConfig) (*core.ReconstructionEngine, error) {
				calls++
				return nil, errors.New("private-constructor-sentinel")
			})
			record := prepareResultWire(t, result)
			if err == nil || calls != 0 || record["branch"] != "unclassified" || PrepareExitCode(result, nil) != 2 {
				t.Fatal("invalid preflight reached construction", record, calls, err)
			}
			if _, err := os.Lstat(filepath.Join(filepath.Dir(request.Source), ".enkv")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid request reached native absence owner", err)
			}
		})
	}
}

// full_only: false
func TestPrepareUnsafeExistingLayoutRefusesWithoutConstruction(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		for _, condition := range []string{"generated-parent-symlink", "coordination-parent-symlink", "lock-image-symlink", "reserved-editable-parent"} {
			t.Run(family+"/"+condition, func(t *testing.T) {
				source := configurationApplyPair(t, family, configuration.JSON, nil)
				configurationSetWritable(t, source)
				path := source.path
				foreignPath := ""
				switch condition {
				case "generated-parent-symlink":
					original := filepath.Dir(source.generated)
					foreign := filepath.Join(t.TempDir(), "foreign-generated")
					if err := os.Rename(original, foreign); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if err := os.Remove(original); err != nil && !errors.Is(err, os.ErrNotExist) {
							t.Error(err)
						}
						if err := os.Rename(foreign, original); err != nil {
							t.Error(err)
						}
					})
					if err := os.Symlink(foreign, original); err != nil {
						t.Fatal(err)
					}
					foreignPath = filepath.Join(foreign, filepath.Base(source.generated))
				case "coordination-parent-symlink":
					foreign := t.TempDir()
					foreignPath = filepath.Join(foreign, "foreign")
					if err := os.WriteFile(foreignPath, source.generatedBytes, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(foreign, filepath.Join(filepath.Dir(path), ".enkv-locks")); err != nil {
						t.Fatal(err)
					}
				case "lock-image-symlink":
					foreignPath = filepath.Join(t.TempDir(), "foreign-lock")
					if err := os.WriteFile(foreignPath, source.generatedBytes, 0600); err != nil {
						t.Fatal(err)
					}
					locks := filepath.Join(filepath.Dir(path), ".enkv-locks")
					if err := os.Mkdir(locks, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(foreignPath, filepath.Join(locks, filepath.Base(path))); err != nil {
						t.Fatal(err)
					}
				default:
					path = filepath.Join(t.TempDir(), ".enkv-transactions", "configuration.json")
					if err := os.Mkdir(filepath.Dir(path), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, source.editableBytes, 0600); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				calls := 0
				result, err := prepareConfiguration(ctx, PrepareRequest{Source: path, Format: configuration.JSON}, func(context.Context, ReconstructionConfig) (*core.ReconstructionEngine, error) {
					calls++
					return nil, errors.New("private-constructor-sentinel")
				})
				var wantSourceFailure map[string]any
				if condition == "generated-parent-symlink" {
					offset := bytes.Index(source.editableBytes, []byte(`".enkv/prod.generated.json"`))
					if offset < 0 {
						t.Fatal("source fixture lacks its generated reference token")
					}
					prefix := source.editableBytes[:offset]
					wantSourceFailure = map[string]any{"source_id": "source", "field": "generated", "reason": "invalid-generated-path",
						"line": float64(bytes.Count(prefix, []byte{'\n'}) + 1), "column": float64(offset - bytes.LastIndexByte(prefix, '\n')), "precision": "context"}
				}
				if wantSourceFailure != nil {
					wantSourceFailure["path"] = path
				}
				record := prepareResultWireWithSourceFailure(t, result, wantSourceFailure)
				if err == nil || calls != 0 || record["branch"] != "unclassified" || record["outcome"] != "refused" || PrepareExitCode(result, nil) != 2 {
					t.Fatal("unsafe existing layout became unavailable or selected reconstruction", calls, record, err)
				}
				after, readErr := os.ReadFile(path)
				if readErr != nil || !bytes.Equal(after, source.editableBytes) {
					t.Fatal("prepare changed unsafe editable source", readErr)
				}
				if foreignPath != "" {
					after, readErr := os.ReadFile(foreignPath)
					if readErr != nil || !bytes.Equal(after, source.generatedBytes) {
						t.Fatal("prepare changed foreign generated bytes", readErr)
					}
				}
			})
		}
	}
}

// full_only: false
func TestPrepareUnsafeAbsentLayoutRefusesWithoutConstruction(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		for _, condition := range []string{"reserved-editable-parent", "generated-parent-symlink", "generated-parent-file", "lock-parent-symlink", "lock-file-directory", "lock-file-symlink", "lock-file-nonempty", "lock-file-multiple-links", "pending-parent-symlink", "source-pending-precedes-generated-parent-file", "transaction-parent-file", "temporary-storage-unavailable"} {
			t.Run(family+"/"+condition, func(t *testing.T) {
				source := configurationApplyPair(t, family, configuration.JSON, nil)
				dir := t.TempDir()
				path := filepath.Join(dir, "configuration.json")
				foreignPath := ""
				foreign := []byte("foreign-native-layout-sentinel")
				switch condition {
				case "reserved-editable-parent":
					parent := filepath.Join(dir, ".enkv-transactions")
					if err := os.Mkdir(parent, 0700); err != nil {
						t.Fatal(err)
					}
					path, foreignPath = filepath.Join(parent, "configuration.json"), filepath.Join(parent, "foreign")
				case "generated-parent-file":
					foreignPath = filepath.Join(dir, ".enkv")
				case "source-pending-precedes-generated-parent-file":
					foreignPath = filepath.Join(dir, ".enkv")
					pending := filepath.Join(dir, ".enkv-pending")
					if err := os.Mkdir(pending, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(pending, filepath.Base(path)), []byte("foreign-pending-marker"), 0600); err != nil {
						t.Fatal(err)
					}
				case "transaction-parent-file":
					foreignPath = filepath.Join(dir, ".enkv-transactions")
				case "lock-file-nonempty", "lock-file-multiple-links":
					locks := filepath.Join(dir, ".enkv-locks")
					if err := os.Mkdir(locks, 0700); err != nil {
						t.Fatal(err)
					}
					foreignPath = filepath.Join(locks, filepath.Base(path))
					if condition == "lock-file-multiple-links" {
						foreign = []byte{}
						foreignPath = filepath.Join(t.TempDir(), "foreign-lock")
						if err := os.WriteFile(foreignPath, foreign, 0600); err != nil {
							t.Fatal(err)
						}
						if err := os.Link(foreignPath, filepath.Join(locks, filepath.Base(path))); err != nil {
							t.Fatal(err)
						}
					}
				case "lock-file-directory", "lock-file-symlink":
					locks := filepath.Join(dir, ".enkv-locks")
					if err := os.Mkdir(locks, 0700); err != nil {
						t.Fatal(err)
					}
					lock := filepath.Join(locks, filepath.Base(path))
					if condition == "lock-file-directory" {
						if err := os.Mkdir(lock, 0700); err != nil {
							t.Fatal(err)
						}
						foreignPath = filepath.Join(lock, "foreign")
					} else {
						foreignPath = filepath.Join(t.TempDir(), "foreign-lock")
						if err := os.Symlink(foreignPath, lock); err != nil {
							t.Fatal(err)
						}
					}
				case "generated-parent-symlink", "lock-parent-symlink", "pending-parent-symlink":
					parent := t.TempDir()
					foreignPath = filepath.Join(parent, "foreign")
					name := map[string]string{"generated-parent-symlink": ".enkv", "lock-parent-symlink": ".enkv-locks", "pending-parent-symlink": ".enkv-pending"}[condition]
					if err := os.Symlink(parent, filepath.Join(dir, name)); err != nil {
						t.Fatal(err)
					}
				case "temporary-storage-unavailable":
					t.Setenv("TMPDIR", filepath.Join(dir, "absent-temporary-directory"))
				}
				if foreignPath != "" {
					if err := os.WriteFile(foreignPath, foreign, 0600); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				calls := 0
				result, err := prepareConfiguration(ctx, prepareRecoveryRequestForTest(source, path, configuration.JSON), func(context.Context, ReconstructionConfig) (*core.ReconstructionEngine, error) {
					calls++
					return nil, errors.New("private-constructor-sentinel")
				})
				record := prepareResultWire(t, result)
				wantCode, wantOutcome := 2, "refused"
				if condition == "temporary-storage-unavailable" {
					wantCode, wantOutcome = 3, "incomplete"
					if !errors.Is(err, os.ErrNotExist) || errors.Is(err, configuration.ErrSourceInvalid) {
						t.Fatal("temporary failure lost original unavailable cause", err)
					}
				}
				if condition == "source-pending-precedes-generated-parent-file" {
					wantCode, wantOutcome = 3, "incomplete"
					if !errors.Is(err, configuration.ErrPendingEdit) || record["local_delivery"].(map[string]any)["recovery_source"] != nil {
						t.Fatal("unsafe later parent hid pending ownership or inferred a recovery source", record, err)
					}
				}
				if err == nil || calls != 0 || record["branch"] != "unclassified" || record["outcome"] != wantOutcome || PrepareExitCode(result, nil) != wantCode {
					t.Fatal("absent native preflight confused known refusal with unavailable evidence", calls, record, err)
				}
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("refused absent preparation installed editable source", err)
				}
				if foreignPath != "" {
					after, err := os.ReadFile(foreignPath)
					if err != nil || !bytes.Equal(after, foreign) {
						t.Fatal("prepare changed foreign native-layout bytes", err)
					}
				}
			})
		}
	}
}

// full_only: false
func TestPrepareConstructorCancellationKeepsFailedPhaseCause(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			source := configurationApplyPair(t, family, configuration.JSON, nil)
			request := prepareRecoveryRequestForTest(source, filepath.Join(t.TempDir(), "configuration.json"), configuration.JSON)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			cause := errors.New("private-credential-failure-sentinel")
			calls := 0
			result, err := prepareConfiguration(ctx, request, func(context.Context, ReconstructionConfig) (*core.ReconstructionEngine, error) {
				calls++
				cancel()
				return nil, cause
			})
			record := prepareResultWire(t, result)
			if calls != 1 || !errors.Is(err, cause) || !errors.Is(err, context.Canceled) || record["outcome"] != "incomplete" || PrepareExitCode(result, nil) != 2 || !reflect.DeepEqual(record["recovery"], map[string]any{"status": "failed"}) || !reflect.DeepEqual(record["diagnostics"], []any{map[string]any{"reason": "cancelled", "subject": "recovery"}}) {
				t.Fatal("constructor cancellation lost failed-phase facts", calls, record, err)
			}
		})
	}
}

// full_only: false
func TestPrepareExistingBranchHasNoRemoteConstruction(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
			for _, condition := range []string{"valid", "invalid-editable", "invalid-output-reference", "missing-generated", "recovery-options"} {
				t.Run(fmt.Sprintf("%s/%d/%s", family, format, condition), func(t *testing.T) {
					source := configurationApplyPair(t, family, format, nil)
					configurationSetWritable(t, source)
					switch condition {
					case "invalid-output-reference":
						body := bytes.Replace(source.editableBytes, []byte(`"routing":{}`), []byte(`"routing":{"default":["missing"]}`), 1)
						if bytes.Equal(body, source.editableBytes) {
							t.Fatal("output-reference fixture did not change its intended route")
						}
						if err := os.Chmod(source.path, 0600); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(source.path, body, 0600); err != nil {
							t.Fatal(err)
						}
					case "invalid-editable":
						if err := os.Chmod(source.path, 0600); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(source.path, []byte("private-invalid-source-sentinel"), 0600); err != nil {
							t.Fatal(err)
						}
					case "missing-generated":
						if err := os.Remove(source.generated); err != nil {
							t.Fatal(err)
						}
					}
					request := PrepareRequest{Source: source.path, Format: format}
					if condition == "recovery-options" {
						prefix, normal := source.archive.Location.PrefixBeforeHEAD, source.archive.SignerSelector
						request.Recovery = &PrepareRecoveryRequest{Name: "restored", Provider: source.archive.Family,
							Bucket: source.archive.Location.Bucket, Region: source.archive.Location.Region, Prefix: &prefix, NormalSigningKey: &normal}
					}
					before := configurationApplySourceImage(t, filepath.Dir(source.path))
					ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
					defer cancel()
					calls := 0
					result, resultErr := prepareConfiguration(ctx, request, func(context.Context, ReconstructionConfig) (*core.ReconstructionEngine, error) {
						calls++
						return nil, errors.New("private-constructor-sentinel")
					})
					if result == nil || calls != 0 {
						t.Fatal("present source reached remote construction", calls, resultErr)
					}
					var wantSourceFailure map[string]any
					switch condition {
					case "invalid-editable":
						reason, column := "object-required", 1
						if format == configuration.YAML {
							reason, column = "unexpected-token", len("private-invalid-source-sentinel")+1
						}
						wantSourceFailure = map[string]any{"source_id": "source", "reason": reason, "line": float64(1), "column": float64(column), "precision": "exact"}
					case "invalid-output-reference":
						wantSourceFailure = map[string]any{"source_id": "source", "field": "outputs", "reason": "invalid-output-reference"}
					case "missing-generated":
						quotedReference := []byte(`".enkv/prod.generated.json"`)
						offset := bytes.Index(source.editableBytes, quotedReference)
						if offset < 0 {
							t.Fatal("source fixture lacks its generated reference token")
						}
						prefix := source.editableBytes[:offset]
						wantSourceFailure = map[string]any{"source_id": "source", "field": "generated", "reason": "restore-exact-generated-file",
							"line": float64(bytes.Count(prefix, []byte{'\n'}) + 1), "column": float64(offset - bytes.LastIndexByte(prefix, '\n')), "precision": "context"}
					}
					if wantSourceFailure != nil {
						wantSourceFailure["path"] = source.path
					}
					record := prepareResultWireWithSourceFailure(t, result, wantSourceFailure)
					wantBranch, wantOutcome, wantCode := "unclassified", "refused", 2
					wantDependencies := map[string]any{"assessment": "not-attempted", "minimum_administrative_ready": false, "all_declared_ready": false, "requirements": []any{}, "installations": []any{}, "settings_failure": nil}
					switch condition {
					case "valid":
						wantBranch, wantOutcome, wantCode = "existing", "complete", 0
						wantDependencies = map[string]any{"assessment": "complete", "minimum_administrative_ready": true, "all_declared_ready": true, "requirements": []any{}, "installations": []any{}, "settings_failure": nil}
						if resultErr != nil || !reflect.DeepEqual(record["diagnostics"], []any{}) {
							t.Fatal("artifact-free existing pair did not complete preparation", resultErr)
						}
					case "recovery-options":
						wantBranch = "existing"
					}
					if record["branch"] != wantBranch || record["outcome"] != wantOutcome || PrepareExitCode(result, nil) != wantCode || !reflect.DeepEqual(record["dependencies"], wantDependencies) {
						t.Fatal("existing branch changed preparation facts", record, resultErr)
					}
					if !reflect.DeepEqual(record["recovery"], map[string]any{"status": "not-attempted"}) || !reflect.DeepEqual(record["local_delivery"], map[string]any{"outcome": "not-recorded", "cleanup_failed": false}) {
						t.Fatal("existing branch claimed reconstruction or delivery", record)
					}
					configurationApplyAssertUnchanged(t, filepath.Dir(source.path), before)
				})
			}
		}
	}
}

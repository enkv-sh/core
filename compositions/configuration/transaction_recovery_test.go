//go:build darwin || linux

package configuration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// full_only: false
func TestPairCaptureProvenance(t *testing.T) {
	for _, damage := range []string{"assembled", "copied", "editable-replaced", "generated-replaced", "generated-removed", "format-changed", "closed"} {
		t.Run(damage, func(t *testing.T) {
			pair := writePair(t, sourceSetupJSON, sourceGeneratedJSON, JSON)
			if _, err := Parse(t.Context(), pair); err != nil {
				t.Fatal("coherent captured pair refused", err)
			}
			editable, generated, format := pair.Editable, pair.Generated, pair.Format
			defer func() { pair.Editable, pair.Generated, pair.Format = editable, generated, format }()
			offered := pair
			switch damage {
			case "assembled":
				offered = &Pair{Editable: editable, Generated: generated, Format: format}
			case "copied":
				copy := *pair
				offered = &copy
			case "editable-replaced":
				other := writePair(t, sourceSetupJSON, sourceGeneratedJSON, JSON)
				pair.Editable = other.Editable
			case "generated-replaced":
				other := writePair(t, sourceSetupJSON, sourceGeneratedJSON, JSON)
				pair.Generated = other.Generated
			case "generated-removed":
				pair.Generated = nil
			case "format-changed":
				pair.Format = YAML
			case "closed":
				if err := pair.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if model, err := Parse(t.Context(), offered); model != nil || !errors.Is(err, ErrCapture) {
				t.Fatalf("incoherent pair reached parsing: model %v, error %v", model != nil, err)
			}
		})
	}
}

// full_only: false
func TestTransactionRecoveryPhases(t *testing.T) {
	for _, interruption := range []struct {
		phase string
		at    int
	}{
		{"before-candidate-flush", 1}, {"candidate-flushed", 1}, {"before-record", 1},
		{"record-durable", 1}, {"marker-durable", 1}, {"markers-durable", 1},
		{"before-generated-install", 1}, {"installation-truncated", 1}, {"installation-copied", 1}, {"generated-installed", 1},
		{"before-editable-install", 1}, {"editable-installed", 1}, {"pair-verified", 1},
		{"staging-cleaned", 1}, {"staging-cleaned", 2},
		{"marker-cleaned", 1}, {"marker-cleaned", 2}, {"markers-cleared", 1}, {"record-cleaned", 1},
	} {
		t.Run(fmt.Sprintf("%s-%d", interruption.phase, interruption.at), func(t *testing.T) {
			session, path := beginSourceEdit(t, JSON, true)
			original := readSource(t, path)
			generatedPath := session.Pair().Generated.path
			candidate, want := stageSourceEdit(t, session, sourceGeneratedJSON+"\n")
			fault := errors.New("controlled transaction interruption")
			hits := 0
			session.io.phase = func(phase string) error {
				if phase == interruption.phase {
					hits++
					if hits == interruption.at {
						return fault
					}
				}
				return nil
			}
			_, err := session.Commit(t.Context(), candidate)
			if !errors.Is(err, fault) || hits != interruption.at {
				t.Fatal("selected interruption was not established", err)
			}
			var unknown *UnknownEdit
			if errors.As(err, &unknown) {
				if closeErr := unknown.Observation.Close(); closeErr != nil {
					t.Fatal(closeErr)
				}
			}
			if err := session.Close(); err != nil {
				t.Fatal(err)
			}
			marker := coordinationPath(path, ".enkv-pending")
			_, markerErr := os.Lstat(marker)
			captured, captureErr := Capture(t.Context(), path, JSON)
			if markerErr == nil {
				if captured != nil || !errors.Is(captureErr, ErrPendingEdit) {
					t.Fatal("consumer admitted a pending transaction", captureErr)
				}
				if !candidate.durable {
					t.Fatal("pending ownership did not retain its candidate")
				}
				delivery, err := RecoverEdit(t.Context(), path, JSON)
				if err != nil || delivery == nil {
					t.Fatal("exact saved candidate could not be recovered", err)
				}
				if readSource(t, path) != want || readSource(t, generatedPath) != sourceGeneratedJSON+"\n" {
					t.Fatal("recovery changed or replaced the saved candidate")
				}
				if _, err := RecoverEdit(t.Context(), path, JSON); err == nil {
					t.Fatal("completed recovery replayed without a pending marker")
				}
			} else {
				if !errors.Is(markerErr, os.ErrNotExist) || captureErr != nil || captured == nil {
					t.Fatal("interruption left neither a complete pair nor pending ownership", captureErr)
				}
				editableBytes, generatedBytes := readSource(t, path), readSource(t, generatedPath)
				oldPair := editableBytes == original && generatedBytes == sourceGeneratedJSON
				newPair := editableBytes == want && generatedBytes == sourceGeneratedJSON+"\n"
				if !oldPair && !newPair {
					t.Fatal("unmarked transaction exposed a mixed pair")
				}
			}
			if captured != nil {
				if err := captured.Close(); err != nil {
					t.Fatal(err)
				}
			}
			complete, err := Capture(t.Context(), path, JSON)
			if err != nil {
				t.Fatal("complete final pair refused", err)
			}
			if _, err := Parse(t.Context(), complete); err != nil {
				t.Fatal("interruption exposed a mixed pair", err)
			}
			if err := complete.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func interruptedTransaction(t *testing.T, phase string) (*EditCandidate, string, string) {
	t.Helper()
	session, path := beginSourceEdit(t, JSON, true)
	generated := session.Pair().Generated.path
	candidate, _ := stageSourceEdit(t, session, sourceGeneratedJSON+"\n")
	fault := errors.New("controlled pending edit")
	session.io.phase = func(at string) error {
		if at == phase {
			return fault
		}
		return nil
	}
	_, err := session.Commit(t.Context(), candidate)
	var unknown *UnknownEdit
	if !errors.Is(err, fault) || !errors.As(err, &unknown) || !errors.Is(err, ErrPendingEdit) {
		t.Fatal("pending transaction was not established", err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := unknown.Observation.Close(); err != nil {
		t.Fatal(err)
	}
	return candidate, path, generated
}

// full_only: false
func TestRecoveryRefusesForeignOrMissingEvidence(t *testing.T) {
	for _, damage := range []string{"editable", "generated", "staging-missing", "staging-changed", "marker", "record-hash", "record-field", "record-path-count", "record-size"} {
		t.Run(damage, func(t *testing.T) {
			candidate, path, generated := interruptedTransaction(t, "generated-installed")
			marker, err := readMarker(t.Context(), coordinationPath(path, ".enkv-pending"))
			if err != nil {
				t.Fatal(err)
			}
			switch damage {
			case "editable", "generated":
				target := path
				if damage == "generated" {
					target = generated
				}
				if err := os.WriteFile(target, []byte("foreign image"), 0600); err != nil {
					t.Fatal(err)
				}
			case "staging-missing":
				if err := os.Remove(candidate.editableTemp); err != nil {
					t.Fatal(err)
				}
			case "staging-changed":
				if err := os.WriteFile(candidate.editableTemp, []byte("foreign staging"), 0600); err != nil {
					t.Fatal(err)
				}
			case "marker":
				if err := os.WriteFile(coordinationPath(generated, ".enkv-pending"), []byte(`{"record":"/foreign","digest":"wrong"}`), 0600); err != nil {
					t.Fatal(err)
				}
			default:
				body, err := os.ReadFile(marker.Record)
				if err != nil {
					t.Fatal(err)
				}
				var record map[string]any
				if err := json.Unmarshal(body, &record); err != nil {
					t.Fatal(err)
				}
				switch damage {
				case "record-hash":
					record["digest"] = strings.Repeat("0", 64)
				case "record-field":
					record["foreign"] = true
				case "record-path-count":
					description := record["description"].(map[string]any)
					paths := description["paths"].([]any)
					description["paths"] = append(paths, paths[0], paths[0], paths[0])
				}
				body, err = json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
				if damage == "record-size" {
					body = append(body, []byte(strings.Repeat(" ", maxPendingBytes))...)
				}
				if err := os.WriteFile(marker.Record, body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			beforeEditable, beforeGenerated := readSource(t, path), readSource(t, generated)
			if delivery, err := RecoverEdit(t.Context(), path, JSON); err == nil || delivery != nil {
				t.Fatal("recovery admitted foreign or missing evidence", err)
			}
			if readSource(t, path) != beforeEditable || readSource(t, generated) != beforeGenerated {
				t.Fatal("refused recovery changed visible images")
			}
		})
	}
}

// full_only: false
func TestTransactionDiskPreflightPrecedesEmitters(t *testing.T) {
	session, path := beginSourceEdit(t, JSON, true)
	before := readSource(t, path)
	session.io.freeBytes = func(string) (uint64, uint64, error) { return 0, 4096, nil }
	called := false
	if candidate, _, err := session.Stage(t.Context(), func(io.Writer) error { called = true; return nil }, func(io.Writer, string) error { called = true; return nil }); candidate != nil || !errors.Is(err, ErrEditBounds) || called {
		t.Fatal("disk preflight did not precede candidate custody", err)
	}
	if readSource(t, path) != before {
		t.Fatal("failed disk preflight changed the source")
	}
}

// full_only: false
func TestSharedSatelliteWriterContention(t *testing.T) {
	pair := writePair(t, sourceSetupJSON, sourceGeneratedJSON, JSON)
	firstPath := pair.Editable.OriginalPath()
	secondPath := filepath.Join(filepath.Dir(firstPath), "second-config")
	if err := os.WriteFile(secondPath, []byte(readSource(t, firstPath)), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := BeginEdit(t.Context(), firstPath, JSON)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := first.Close(); err != nil {
			t.Error(err)
		}
	})
	second, err := BeginEdit(t.Context(), secondPath, JSON)
	if second != nil {
		if closeErr := second.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}
	if second != nil || !errors.Is(err, ErrEditLocked) {
		t.Fatalf("distinct editable names acquired one satellite concurrently: editor %v, error %v", second != nil, err)
	}
}

// pairCaptureInterleaving acts after the editable image is frozen and before
// the first generated-image read. File state selects the boundary, not timing.
type pairCaptureInterleaving struct {
	context.Context
	directory string
	action    func()
	fired     bool
	problem   error
}

func (c *pairCaptureInterleaving) Err() error {
	if !c.fired && c.problem == nil {
		entries, err := os.ReadDir(c.directory)
		if err != nil {
			c.problem = err
		} else if len(entries) == 2 {
			var complete, empty int
			for _, entry := range entries {
				info, err := entry.Info()
				if err != nil {
					c.problem = err
					break
				}
				if info.Size() == 0 {
					empty++
				} else {
					complete++
				}
			}
			if c.problem == nil && complete == 1 && empty == 1 {
				c.fired = true
				c.action()
			}
		}
	}
	return errors.Join(c.Context.Err(), c.problem)
}

// full_only: false
func TestCaptureCompletedWriterInterleaving(t *testing.T) {
	pair := writePair(t, sourceSetupJSON, sourceGeneratedJSON, JSON)
	path := pair.Editable.OriginalPath()
	private := t.TempDir()
	t.Setenv("TMPDIR", private)
	completed := false
	var want string
	ctx := &pairCaptureInterleaving{Context: t.Context(), directory: private}
	ctx.action = func() {
		writer, err := BeginEdit(context.Background(), path, JSON)
		if err != nil {
			t.Fatal("writer could not start during initially unlocked capture", err)
		}
		defer func() {
			if err := writer.Close(); err != nil {
				t.Error(err)
			}
		}()
		// Reusing generated bytes leaves the generated directory unchanged.
		candidate, expected := stageSourceEdit(t, writer, "")
		want = expected
		if _, err := writer.Commit(context.Background(), candidate); err != nil {
			t.Fatal("controlled writer did not complete", err)
		}
		completed = true
	}
	captured, err := Capture(ctx, path, JSON)
	if captured != nil {
		if closeErr := captured.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	}
	if !ctx.fired || !completed || ctx.problem != nil {
		t.Fatalf("controlled complete-writer boundary was not established: fired %v, complete %v, error %v", ctx.fired, completed, ctx.problem)
	}
	if readSource(t, path) != want {
		t.Fatal("controlled writer's complete editable image is missing")
	}
	if captured != nil || !errors.Is(err, ErrCapture) {
		t.Fatalf("capture admitted input after a complete intervening writer: pair %v, error %v", captured != nil, err)
	}
}

// full_only: false
func TestCaptureExistingLocksExcludeWriter(t *testing.T) {
	pair := writePair(t, sourceSetupJSON, sourceGeneratedJSON, JSON)
	path := pair.Editable.OriginalPath()
	prior, err := BeginEdit(t.Context(), path, JSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := prior.Close(); err != nil {
		t.Fatal(err)
	}
	private := t.TempDir()
	t.Setenv("TMPDIR", private)
	var writerErr error
	writerAcquired := false
	ctx := &pairCaptureInterleaving{Context: t.Context(), directory: private}
	ctx.action = func() {
		writer, err := BeginEdit(context.Background(), path, JSON)
		writerErr = err
		if writer != nil {
			writerAcquired = true
			if err := writer.Close(); err != nil {
				t.Error(err)
			}
		}
	}
	captured, err := Capture(ctx, path, JSON)
	if captured != nil {
		defer func() {
			if err := captured.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	if !ctx.fired || ctx.problem != nil {
		t.Fatalf("shared-capture boundary was not established: fired %v, error %v", ctx.fired, ctx.problem)
	}
	if writerAcquired || !errors.Is(writerErr, ErrEditLocked) {
		t.Fatalf("writer acquired existing locks during shared capture: editor %v, error %v", writerAcquired, writerErr)
	}
	if captured == nil || err != nil {
		t.Fatal("unchanged capture failed after refusing the writer", err)
	}
}

// full_only: false
func TestRecoveryLeavesReleasedObsoletePathWithLaterWriter(t *testing.T) {
	for _, later := range []string{"completed", "pending", "live"} {
		t.Run(later, func(t *testing.T) {
			pair := writePair(t, sourceSetupJSON, sourceGeneratedJSON, JSON)
			path, obsolete := pair.Editable.OriginalPath(), pair.Generated.OriginalPath()
			original := readSource(t, path)
			first, err := BeginRename(t.Context(), path, JSON, "staging")
			if err != nil {
				t.Fatal(err)
			}
			defer closeSourceOwner(t, first)
			candidate, _, err := first.StageRename(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			wantFirst := readSource(t, candidate.editableTemp)
			fault := errors.New("controlled released-path cleanup interruption")
			first.io.phase = func(phase string) error {
				if phase == "marker-cleaned" {
					if _, err := os.Lstat(coordinationPath(obsolete, ".enkv-pending")); errors.Is(err, os.ErrNotExist) {
						return fault
					}
				}
				return nil
			}
			delivery, err := first.Commit(t.Context(), candidate)
			var unknown *UnknownEdit
			if delivery == nil || !delivery.CleanupFailed() || !errors.Is(err, fault) || !errors.As(err, &unknown) {
				t.Fatal("verified cleanup interruption was not established", err)
			}
			closeSourceOwner(t, unknown.Observation)
			closeSourceOwner(t, first)
			if _, err := os.Lstat(obsolete); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("obsolete image was not removed", err)
			}
			if _, err := os.Lstat(coordinationPath(obsolete, ".enkv-pending")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("obsolete marker was not released", err)
			}
			marker, err := readMarker(t.Context(), coordinationPath(path, ".enkv-pending"))
			if err != nil {
				t.Fatal("source marker was not retained", err)
			}
			record, err := readRecord(t.Context(), marker.Record)
			if err != nil || record.Phase != "verified" {
				t.Fatal("saved edit was not verified", err)
			}

			secondPath := filepath.Join(filepath.Dir(path), "second-config")
			secondGenerated := filepath.Join(filepath.Dir(obsolete), "spare.generated.json")
			secondSource := strings.Replace(original, `"name":"prod"`, `"name":"spare"`, 1)
			secondSource = strings.Replace(secondSource, ".enkv/prod.generated.json", ".enkv/spare.generated.json", 1)
			for name, body := range map[string]string{secondPath: secondSource, secondGenerated: sourceGeneratedJSON + "\n"} {
				if err := os.WriteFile(name, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			second, err := BeginRename(t.Context(), secondPath, JSON, "prod")
			if err != nil {
				t.Fatal("released name was not available to a cooperating writer", err)
			}
			defer closeSourceOwner(t, second)
			next, _, err := second.StageRename(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if later != "live" {
				if later == "pending" {
					second.io.phase = func(phase string) error {
						if phase == "pair-verified" {
							return fault
						}
						return nil
					}
				}
				_, err := second.Commit(t.Context(), next)
				if later == "pending" {
					if !errors.Is(err, fault) || !errors.As(err, &unknown) {
						t.Fatal("second pending owner was not established", err)
					}
					closeSourceOwner(t, unknown.Observation)
				} else if err != nil {
					t.Fatal("second cooperating writer did not complete", err)
				}
				closeSourceOwner(t, second)
			}
			wantSecond := readSource(t, secondPath)
			var wantReused, wantMarker string
			if later != "live" {
				wantReused = readSource(t, obsolete)
				if wantReused != sourceGeneratedJSON+"\n" {
					t.Fatal("later writer did not install its distinct saved bytes")
				}
			}
			if later == "pending" {
				wantMarker = readSource(t, coordinationPath(obsolete, ".enkv-pending"))
			}
			if _, err := RecoverEdit(t.Context(), path, JSON); err != nil {
				t.Fatal("released path blocked exact source cleanup", err)
			}
			if readSource(t, path) != wantFirst || readSource(t, filepath.Join(filepath.Dir(obsolete), "staging.generated.json")) != sourceGeneratedJSON || readSource(t, secondPath) != wantSecond {
				t.Fatal("source cleanup changed a completed pair or later writer")
			}
			if later == "live" {
				if readSource(t, secondGenerated) != sourceGeneratedJSON+"\n" {
					t.Fatal("source cleanup changed the live writer's predecessor")
				}
			} else if readSource(t, obsolete) != wantReused {
				t.Fatal("source cleanup removed the reused name")
			}
			if later == "pending" && readSource(t, coordinationPath(obsolete, ".enkv-pending")) != wantMarker {
				t.Fatal("source cleanup changed the later pending marker")
			}
			if _, err := os.Lstat(coordinationPath(path, ".enkv-pending")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("source cleanup retained its marker", err)
			}
			if _, err := os.Lstat(marker.Record); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("source cleanup retained its record", err)
			}
			for name, domain := range map[string]string{path: "staging", secondPath: "prod"} {
				if name == secondPath && later != "completed" {
					continue
				}
				complete, err := Capture(t.Context(), name, JSON)
				if err != nil {
					t.Fatal("completed pair was not admitted after source cleanup", err)
				}
				model, parseErr := Parse(t.Context(), complete)
				closeSourceOwner(t, complete)
				if parseErr != nil || model.DomainName != domain || model.Generated != ".enkv/"+domain+".generated.json" {
					t.Fatal("completed pair changed its exact name or reference", parseErr)
				}
			}
			if later == "live" {
				if err := second.CheckUnchanged(t.Context()); err != nil {
					t.Fatal("source cleanup invalidated a live cooperating writer", err)
				}
			}
		})
	}
}

// full_only: false
func TestRecoveryKeepsIncompleteObsoletePathOwned(t *testing.T) {
	for _, condition := range []string{"cleanup-incomplete", "marker-retained"} {
		t.Run(condition, func(t *testing.T) {
			pair := writePair(t, sourceSetupJSON, sourceGeneratedJSON, JSON)
			path, obsolete := pair.Editable.OriginalPath(), pair.Generated.OriginalPath()
			session, err := BeginRename(t.Context(), path, JSON, "staging")
			if err != nil {
				t.Fatal(err)
			}
			defer closeSourceOwner(t, session)
			candidate, _, err := session.StageRename(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			fault := errors.New("controlled retained obsolete ownership")
			obsoleteMarker := coordinationPath(obsolete, ".enkv-pending")
			if condition == "cleanup-incomplete" {
				session.io.phase = func(phase string) error {
					if phase == "pair-verified" {
						return fault
					}
					return nil
				}
			} else {
				session.io.remove = func(name string) error {
					if name == obsoleteMarker {
						return fault
					}
					return os.Remove(name)
				}
			}
			_, err = session.Commit(t.Context(), candidate)
			var unknown *UnknownEdit
			if !errors.Is(err, fault) || !errors.As(err, &unknown) {
				t.Fatal("retained cleanup boundary was not established", err)
			}
			closeSourceOwner(t, unknown.Observation)
			closeSourceOwner(t, session)
			if condition == "cleanup-incomplete" {
				if err := os.Remove(obsoleteMarker); err != nil {
					t.Fatal(err)
				}
			} else if _, err := readMarker(t.Context(), obsoleteMarker); err != nil {
				t.Fatal("original marker was not retained", err)
			}
			if err := os.WriteFile(obsolete, []byte("foreign retained-path bytes"), 0600); err != nil {
				t.Fatal(err)
			}
			before := readSource(t, path)
			if delivery, err := RecoverEdit(t.Context(), path, JSON); delivery != nil || err == nil {
				t.Fatal("incomplete cleanup released an owned obsolete path", err)
			}
			if readSource(t, path) != before || readSource(t, obsolete) != "foreign retained-path bytes" {
				t.Fatal("refused recovery changed visible bytes")
			}
			if _, err := readMarker(t.Context(), coordinationPath(path, ".enkv-pending")); err != nil {
				t.Fatal("refused recovery lost its exact source ownership", err)
			}
		})
	}
}

// full_only: false
func TestPendingInspectionRequiresObservedMarker(t *testing.T) {
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, ".enkv-pending"), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "config")
	if err := refusePending([]string{path}); err != nil {
		t.Fatal("absent marker was not admitted", err)
	}
	if err := os.WriteFile(coordinationPath(path, ".enkv-pending"), []byte("observed marker"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := refusePending([]string{path}); !errors.Is(err, ErrCapture) || !errors.Is(err, ErrPendingEdit) {
		t.Fatal("observed marker lost pending classification", err)
	}
	path = filepath.Join(directory, strings.Repeat("a", 256))
	if _, err := os.Lstat(coordinationPath(path, ".enkv-pending")); !errors.Is(err, syscall.ENAMETOOLONG) {
		t.Fatal("bounded marker lookup failure was not established", err)
	}
	for _, caller := range []string{"inspection", "capture", "edit"} {
		t.Run(caller, func(t *testing.T) {
			var err error
			switch caller {
			case "inspection":
				err = refusePending([]string{path})
			case "capture":
				var pair *Pair
				pair, err = Capture(t.Context(), path, JSON)
				if pair != nil {
					closeSourceOwner(t, pair)
					t.Fatal("failed marker lookup returned a captured pair")
				}
			case "edit":
				var session *EditSession
				session, err = BeginEdit(t.Context(), path, JSON)
				if session != nil {
					closeSourceOwner(t, session)
					t.Fatal("failed marker lookup returned an editor")
				}
			}
			if !errors.Is(err, ErrCapture) || !errors.Is(err, syscall.ENAMETOOLONG) || errors.Is(err, ErrPendingEdit) {
				t.Fatal("inspection failure acquired a positive pending fact", err)
			}
		})
	}
}

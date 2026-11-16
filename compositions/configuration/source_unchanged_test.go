package configuration

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func unchangedPairFixture(t *testing.T, readOnly bool) *Pair {
	t.Helper()
	dir := t.TempDir()
	generatedDirectory := filepath.Join(dir, ".enkv")
	if err := os.Mkdir(generatedDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	reference := ".enkv/prod.generated.json"
	generatedPath := filepath.Join(dir, reference)
	if err := os.WriteFile(generatedPath, []byte(sourceGeneratedJSON), 0600); err != nil {
		t.Fatal(err)
	}
	editable := strings.TrimSuffix(sourceSetupJSON, "}") + `,"generated":"` + reference + `"}`
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte(editable), 0600); err != nil {
		t.Fatal(err)
	}
	if readOnly {
		for _, file := range []string{path, generatedPath} {
			if err := os.Chmod(file, 0444); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chmod(generatedDirectory, 0555); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		if err := os.Chmod(generatedDirectory, 0700); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Error(err)
		}
	})
	pair, err := Capture(t.Context(), path, JSON)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pair.Close(); err != nil {
			t.Error(err)
		}
	})
	return pair
}

// full_only: false
func TestCapturedPairUnchangedAllowsUnrelatedGeneratedMembers(t *testing.T) {
	for _, readOnly := range []bool{false, true} {
		name := "writable"
		if readOnly {
			name = "read-only"
		}
		t.Run(name, func(t *testing.T) {
			pair := unchangedPairFixture(t, readOnly)
			if err := pair.CheckUnchanged(t.Context()); err != nil {
				t.Fatal("unchanged captured source refused", err)
			}
			if readOnly {
				return
			}
			directory := filepath.Dir(pair.Generated.OriginalPath())
			other := filepath.Join(directory, "unrelated.json")
			if err := os.WriteFile(other, []byte(`{"unrelated":true}`), 0600); err != nil {
				t.Fatal(err)
			}
			if err := pair.CheckUnchanged(t.Context()); err != nil {
				t.Fatal("unrelated generated member changed source pins", err)
			}
			if err := os.Remove(other); err != nil {
				t.Fatal(err)
			}
			stamp := time.Unix(123456789, 0)
			if err := os.Chtimes(directory, stamp, stamp); err != nil {
				t.Fatal(err)
			}
			if err := pair.CheckUnchanged(t.Context()); err != nil {
				t.Fatal("directory timestamps changed source pins", err)
			}
		})
	}
	pair := writePair(t, sourceSetupJSON, "", JSON)
	if err := pair.CheckUnchanged(t.Context()); err != nil {
		t.Fatal("captured source without generated dependency refused", err)
	}
}

// full_only: false
func TestCapturedPairUnchangedRefusesChangedMembers(t *testing.T) {
	for _, member := range []string{"editable", "generated"} {
		for _, damage := range []string{"replaced", "rewritten", "truncated", "mode", "timestamp", "missing"} {
			t.Run(member+"/"+damage, func(t *testing.T) {
				pair := unchangedPairFixture(t, false)
				image := pair.Editable
				if member == "generated" {
					image = pair.Generated
				}
				path := image.OriginalPath()
				body, err := os.ReadFile(path)
				if err != nil || len(body) == 0 {
					t.Fatal("source member unavailable", err)
				}
				switch damage {
				case "replaced":
					replacement := path + ".new"
					if err := os.WriteFile(replacement, body, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(replacement, path); err != nil {
						t.Fatal(err)
					}
				case "rewritten":
					body[len(body)-1] ^= 1
					if err := os.WriteFile(path, body, 0600); err != nil {
						t.Fatal(err)
					}
				case "truncated":
					if err := os.Truncate(path, int64(len(body)-1)); err != nil {
						t.Fatal(err)
					}
				case "mode":
					if err := os.Chmod(path, 0400); err != nil {
						t.Fatal(err)
					}
				case "timestamp":
					stamp := time.Unix(123456789, 0)
					if err := os.Chtimes(path, stamp, stamp); err != nil {
						t.Fatal(err)
					}
				case "missing":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
				err = pair.CheckUnchanged(t.Context())
				if !errors.Is(err, ErrCapture) || !errors.Is(err, ErrSourceChanged) || damage == "missing" && !errors.Is(err, os.ErrNotExist) {
					t.Fatal("changed source member accepted or cause lost", err)
				}
			})
		}
	}
}

// full_only: false
func TestCapturedPairUnchangedRefusesChangedGeneratedDirectory(t *testing.T) {
	for _, damage := range []string{"replaced", "symlink", "mode", "changed-during-check"} {
		t.Run(damage, func(t *testing.T) {
			pair := unchangedPairFixture(t, false)
			directory := filepath.Dir(pair.Generated.OriginalPath())
			replace := func() {
				t.Helper()
				moved := directory + ".old"
				if err := os.Rename(directory, moved); err != nil {
					t.Fatal(err)
				}
				if damage == "replaced" {
					if err := os.Mkdir(directory, 0700); err != nil {
						t.Fatal(err)
					}
					return
				}
				if err := os.Symlink(moved, directory); err != nil {
					t.Fatal(err)
				}
			}
			ctx := t.Context()
			switch damage {
			case "mode":
				if err := os.Chmod(directory, 0777); err != nil {
					t.Fatal(err)
				}
			case "changed-during-check":
				ctx = &captureStepContext{Context: ctx, at: 2, action: replace}
			default:
				replace()
			}
			if err := pair.CheckUnchanged(ctx); !errors.Is(err, ErrCapture) || !errors.Is(err, ErrSourceChanged) {
				t.Fatal("changed generated directory accepted", err)
			}
		})
	}
}

// full_only: false
func TestCapturedPairUnchangedRefusesClosedAndCanceledInputs(t *testing.T) {
	pair := unchangedPairFixture(t, false)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := pair.CheckUnchanged(ctx); !errors.Is(err, ErrCapture) || !errors.Is(err, context.Canceled) || errors.Is(err, ErrSourceChanged) {
		t.Fatal("cancellation cause lost", err)
	}
	var absentContext context.Context
	if err := pair.CheckUnchanged(absentContext); !errors.Is(err, ErrCapture) || errors.Is(err, ErrSourceChanged) {
		t.Fatal("nil context accepted", err)
	}
	if err := (*Pair)(nil).CheckUnchanged(t.Context()); !errors.Is(err, ErrCapture) || errors.Is(err, ErrSourceChanged) {
		t.Fatal("nil pair accepted", err)
	}
	if err := pair.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pair.CheckUnchanged(t.Context()); !errors.Is(err, ErrCapture) || errors.Is(err, ErrSourceChanged) {
		t.Fatal("closed captured source accepted", err)
	}
}

// full_only: false
func TestCapturedPairUnchangedReportsSourceParentAndAliasChanges(t *testing.T) {
	for _, damage := range []string{"replaced", "symlink", "mode", "missing"} {
		t.Run("parent/"+damage, func(t *testing.T) {
			pair := unchangedPairFixture(t, false)
			directory := filepath.Dir(pair.Editable.path)
			if damage == "mode" {
				if err := os.Chmod(directory, 0777); err != nil {
					t.Fatal(err)
				}
			} else {
				moved := directory + ".old"
				if err := os.Rename(directory, moved); err != nil {
					t.Fatal(err)
				}
				switch damage {
				case "replaced":
					if err := os.Mkdir(directory, 0700); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					if err := os.Symlink(moved, directory); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := pair.CheckUnchanged(t.Context()); !errors.Is(err, ErrCapture) || !errors.Is(err, ErrSourceChanged) || damage == "missing" && !errors.Is(err, os.ErrNotExist) {
				t.Fatal("positive source-parent mismatch lost its evidence", err)
			}
		})
	}
	for _, damage := range []string{"retargeted", "missing", "inspection-error"} {
		t.Run("alias/"+damage, func(t *testing.T) {
			original := unchangedPairFixture(t, false)
			alias := filepath.Join(t.TempDir(), "selected")
			if err := os.Symlink(filepath.Dir(original.Editable.path), alias); err != nil {
				t.Fatal(err)
			}
			pair, err := Capture(t.Context(), filepath.Join(alias, filepath.Base(original.Editable.path)), JSON)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := pair.Close(); err != nil {
					t.Error(err)
				}
			}()
			if err := os.Remove(alias); err != nil {
				t.Fatal(err)
			}
			if damage != "missing" {
				target := alias
				if damage == "retargeted" {
					target = t.TempDir()
				}
				if err := os.Symlink(target, alias); err != nil {
					t.Fatal(err)
				}
			}
			err = pair.CheckUnchanged(t.Context())
			if !errors.Is(err, ErrCapture) || errors.Is(err, ErrSourceChanged) != (damage != "inspection-error") || damage == "inspection-error" && !errors.Is(err, syscall.ELOOP) || damage == "missing" && !errors.Is(err, os.ErrNotExist) {
				t.Fatal("alias inspection confused a positive change with unavailable evidence", err)
			}
		})
	}
}

// full_only: false
func TestCapturedPairUnchangedKeepsCoordinationFailuresDistinct(t *testing.T) {
	for _, condition := range []string{"invalid-lock-directory", "locked", "pending-with-changed-member"} {
		t.Run(condition, func(t *testing.T) {
			pair := unchangedPairFixture(t, false)
			want := ErrSourceInvalid
			switch condition {
			case "invalid-lock-directory":
				if err := os.WriteFile(filepath.Join(filepath.Dir(pair.Editable.path), ".enkv-locks"), []byte("occupied"), 0600); err != nil {
					t.Fatal(err)
				}
			case "locked":
				session, err := BeginEdit(t.Context(), pair.Editable.path, JSON)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := session.Close(); err != nil {
						t.Error(err)
					}
				}()
				want = ErrEditLocked
			case "pending-with-changed-member":
				directory := filepath.Join(filepath.Dir(pair.Editable.path), ".enkv-pending")
				if err := os.Mkdir(directory, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(coordinationPath(pair.Editable.path, ".enkv-pending"), []byte("owned marker"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(pair.Editable.path, 0400); err != nil {
					t.Fatal(err)
				}
				want = ErrPendingEdit
			}
			if err := pair.CheckUnchanged(t.Context()); !errors.Is(err, ErrCapture) || !errors.Is(err, want) || errors.Is(err, ErrSourceChanged) {
				t.Fatal("coordination failure invented source-change evidence or lost its cause", err)
			}
		})
	}
}

// full_only: false
func TestCapturedImageComparisonReportsObservedByteChange(t *testing.T) {
	pair := unchangedPairFixture(t, false)
	body, err := os.ReadFile(pair.Editable.path)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)-1] ^= 1
	ctx := &captureStepContext{Context: t.Context(), at: 1, action: func() {
		if err := os.WriteFile(pair.Editable.path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}}
	if err := compareEditImage(ctx, pair.Editable.path, pair.Editable, true); !errors.Is(err, ErrEdit) || !errors.Is(err, ErrSourceChanged) {
		t.Fatal("observed bytes changed after metadata checks without a positive fact", err)
	}
}

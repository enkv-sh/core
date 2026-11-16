//go:build (darwin && arm64) || (linux && amd64)

package crypto

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

func materializationTestTarget(t *testing.T, path string, protected ...string) *MaterializationFileTarget {
	t.Helper()
	target, err := NewMaterializationFileTarget(contract.MaterializationTarget{Path: path, SurfaceID: contract.ID{1}, Format: contract.MaterializationDotenvFormat, NativeProfile: contract.MaterializationNativeFileProfile}, protected)
	if err != nil {
		t.Fatal("synthetic native target refused")
	}
	return target
}
func materializationTestEnv(t *testing.T, value string) materializationEnv {
	t.Helper()
	env, err := prepareMaterializationEnv([]materializationValue{{name: "A", raw: []byte(value)}})
	if err != nil {
		t.Fatal("synthetic native value refused")
	}
	return env
}
func materializationAssertCompletion(t *testing.T, completion contract.MaterializationCompletion) {
	t.Helper()
	if completion.Validate() != nil {
		t.Fatalf("invalid safe native tuple: %+v failure=%+v cleanup=%+v", completion, completion.Facts.Failure, completion.Facts.CleanupFailure)
	}
}
func materializationAssertBody(t *testing.T, path, want string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(body, []byte(want)) {
		t.Fatal("complete synthetic surface differs")
	}
}
func materializationCandidates(t *testing.T, parent string) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(parent, materializationCandidatePrefix+"*"))
	if err != nil {
		t.Fatal("candidate inventory unavailable")
	}
	return paths
}

// full_only: false
func TestMaterializationFileInstallsCompletePrivateSurface(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "existing"}[existing], func(t *testing.T) {
			parent := t.TempDir()
			path := filepath.Join(parent, "application.env")
			var old *os.File
			if existing {
				if os.WriteFile(path, []byte("A=old\n"), 0644) != nil {
					t.Fatal("old fixture unavailable")
				}
				var err error
				old, err = os.Open(path)
				if err != nil {
					t.Fatal("old descriptor unavailable")
				}
				t.Cleanup(func() {
					if old.Close() != nil {
						t.Error("old descriptor close failed")
					}
				})
			}
			target := materializationTestTarget(t, path)
			copy := target.Target()
			copy.Path = filepath.Join(parent, "changed.env")
			if target.Target().Path != path || target.Identity() != (contract.ID{1}) || !target.matches(target.Target()) {
				t.Fatal("target pins changed")
			}
			result := target.install(t.Context(), materializationTestEnv(t, "new\nsecond"), nil)
			materializationAssertCompletion(t, result)
			if result.StateResult != contract.MaterializationSuccess {
				t.Fatalf("complete install failed at %+v", result.Facts.Failure)
			}
			materializationAssertBody(t, path, "A='new\nsecond'\n")
			info, err := os.Stat(path)
			if err != nil || info.Mode() != 0600 || len(materializationCandidates(t, parent)) != 0 {
				t.Fatal("private exact mode or candidate cleanup differs")
			}
			if old != nil {
				body, err := io.ReadAll(old)
				if err != nil || !bytes.Equal(body, []byte("A=old\n")) {
					t.Fatal("already-open reader did not retain complete old file")
				}
			}
			reused := target.install(t.Context(), materializationTestEnv(t, "again"), nil)
			materializationAssertCompletion(t, reused)
			if reused.StateResult != contract.MaterializationRefused || reused.Facts.Disclosure != contract.MaterializationDisclosureNone {
				t.Fatal("native target reused")
			}
		})
	}
}

// full_only: false
func TestMaterializationFileRefusesAliasesAndInvalidTargets(t *testing.T) {
	parent := t.TempDir()
	source := filepath.Join(parent, "source.yaml")
	satelliteDir := filepath.Join(parent, ".enkv")
	if os.WriteFile(source, []byte("source fixture"), 0600) != nil || os.Mkdir(satelliteDir, 0700) != nil {
		t.Fatal("source fixtures unavailable")
	}
	satellite := filepath.Join(satelliteDir, "generated.json")
	if os.WriteFile(satellite, []byte("satellite fixture"), 0600) != nil {
		t.Fatal("satellite fixture unavailable")
	}
	hardlink := filepath.Join(parent, "source-hardlink")
	symlink := filepath.Join(parent, "source-symlink")
	fifo := filepath.Join(parent, "fifo")
	if os.Link(source, hardlink) != nil || os.Symlink(source, symlink) != nil || syscall.Mkfifo(fifo, 0600) != nil {
		t.Fatal("native alias/type fixtures unavailable")
	}
	for _, path := range []string{source, satellite, hardlink, symlink, parent, fifo, "/dev/null", filepath.Join(parent, "missing", "out.env"), filepath.Join(parent, ".enkv-pending", "record"), filepath.Join(parent, ".enkv-transactions", "record"), filepath.Join(parent, ".enkv-locks", "lock"), filepath.Join(satelliteDir, "other.env")} {
		target := contract.MaterializationTarget{Path: path, SurfaceID: contract.ID{1}, Format: contract.MaterializationDotenvFormat, NativeProfile: contract.MaterializationNativeFileProfile}
		if _, err := NewMaterializationFileTarget(target, []string{source, satellite}); !errors.Is(err, ErrMaterializationTarget) {
			t.Fatal("invalid target or source alias admitted")
		}
	}
	for _, owner := range []struct{ name, parent string }{{"editable", parent}, {"generated", satelliteDir}} {
		for _, prefix := range []string{".enkv-editable-", ".enkv-generated-", ".ENKV-EDITABLE-", ".ENKV-GENERATED-"} {
			for _, exists := range []bool{false, true} {
				state := "absent"
				if exists {
					state = "existing"
				}
				t.Run(owner.name+"-candidate-"+prefix+state, func(t *testing.T) {
					path := filepath.Join(owner.parent, prefix+state)
					if exists && os.WriteFile(path, []byte("owned source candidate"), 0600) != nil {
						t.Fatal("source candidate fixture unavailable")
					}
					candidateTarget := contract.MaterializationTarget{Path: path, SurfaceID: contract.ID{1}, Format: contract.MaterializationDotenvFormat, NativeProfile: contract.MaterializationNativeFileProfile}
					if _, err := NewMaterializationFileTarget(candidateTarget, []string{source, satellite}); !errors.Is(err, ErrMaterializationTarget) {
						t.Fatal("owned source candidate coordinate admitted")
					}
				})
			}
		}
	}
	unrelated := t.TempDir()
	for _, prefix := range []string{".enkv-editable-", ".enkv-generated-", ".ENKV-EDITABLE-", ".ENKV-GENERATED-"} {
		for _, exists := range []bool{false, true} {
			state := "absent"
			if exists {
				state = "existing"
			}
			t.Run("unrelated-parent-"+prefix+state, func(t *testing.T) {
				path := filepath.Join(unrelated, prefix+state)
				if exists && os.WriteFile(path, []byte("unrelated file"), 0600) != nil {
					t.Fatal("unrelated target fixture unavailable")
				}
				candidateTarget := contract.MaterializationTarget{Path: path, SurfaceID: contract.ID{1}, Format: contract.MaterializationDotenvFormat, NativeProfile: contract.MaterializationNativeFileProfile}
				if _, err := NewMaterializationFileTarget(candidateTarget, []string{source, satellite}); err != nil {
					t.Fatal("unrelated parent inherited source namespace exclusion")
				}
			})
		}
	}
	for _, owner := range []struct{ name, parent string }{{"editable", parent}, {"generated", satelliteDir}, {"unrelated", unrelated}} {
		for _, directory := range []string{".ENKV-PENDING", ".ENKV-TRANSACTIONS"} {
			reserved := filepath.Join(owner.parent, directory)
			if err := os.MkdirAll(reserved, 0700); err != nil {
				t.Fatal("case-variant directory fixture unavailable")
			}
			for _, exists := range []bool{false, true} {
				state := "absent"
				if exists {
					state = "existing"
				}
				t.Run(owner.name+"-directory-"+directory+"-"+state, func(t *testing.T) {
					path := filepath.Join(reserved, state)
					if exists && os.WriteFile(path, []byte("owned directory artifact"), 0600) != nil {
						t.Fatal("directory artifact fixture unavailable")
					}
					candidateTarget := contract.MaterializationTarget{Path: path, SurfaceID: contract.ID{1}, Format: contract.MaterializationDotenvFormat, NativeProfile: contract.MaterializationNativeFileProfile}
					_, err := NewMaterializationFileTarget(candidateTarget, []string{source, satellite})
					if owner.name == "unrelated" {
						if err != nil {
							t.Fatal("unrelated parent inherited reserved directory exclusion")
						}
					} else if !errors.Is(err, ErrMaterializationTarget) {
						t.Fatal("case-variant owned artifact directory admitted")
					}
				})
			}
		}
	}
	t.Run("case-parent-identity", func(t *testing.T) {
		root := t.TempDir()
		sourceParent, otherParent := filepath.Join(root, "source"), filepath.Join(root, "SOURCE")
		if os.Mkdir(sourceParent, 0700) != nil {
			t.Fatal("source parent fixture unavailable")
		}
		if err := os.Mkdir(otherParent, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			t.Fatal("case sibling fixture unavailable")
		}
		left, leftErr := os.Stat(sourceParent)
		right, rightErr := os.Stat(otherParent)
		if leftErr != nil || rightErr != nil {
			t.Fatal("case sibling identity unavailable")
		}
		protected := filepath.Join(sourceParent, "source.yaml")
		if os.WriteFile(protected, []byte("source fixture"), 0600) != nil {
			t.Fatal("case source fixture unavailable")
		}
		name := "distinct-case-parent-is-unrelated"
		if os.SameFile(left, right) {
			name = "same-native-parent-owns-namespace"
		}
		t.Run(name, func(t *testing.T) {
			candidateTarget := contract.MaterializationTarget{Path: filepath.Join(otherParent, ".ENKV-EDITABLE-target"), SurfaceID: contract.ID{1}, Format: contract.MaterializationDotenvFormat, NativeProfile: contract.MaterializationNativeFileProfile}
			_, err := NewMaterializationFileTarget(candidateTarget, []string{protected})
			if os.SameFile(left, right) {
				if !errors.Is(err, ErrMaterializationTarget) {
					t.Fatal("same native source parent lost its artifact namespace")
				}
			} else if err != nil {
				t.Fatal("distinct case-sensitive sibling treated as the source parent")
			}
		})
	})
	t.Run("reserved-directory-symlink-original-coordinate", func(t *testing.T) {
		root := t.TempDir()
		sourceParent := filepath.Join(root, "source")
		otherParent := filepath.Join(root, "unrelated")
		sourceDestination := filepath.Join(root, "source-destination")
		otherDestination := filepath.Join(root, "other-destination")
		for _, directory := range []string{sourceParent, otherParent, sourceDestination, otherDestination} {
			if os.Mkdir(directory, 0700) != nil {
				t.Fatal("symlink namespace fixture unavailable")
			}
		}
		protected := filepath.Join(sourceParent, "source.yaml")
		if os.WriteFile(protected, []byte("source fixture"), 0600) != nil {
			t.Fatal("symlink source fixture unavailable")
		}
		if os.Symlink(sourceDestination, filepath.Join(sourceParent, ".ENKV-PENDING")) != nil || os.Symlink(otherDestination, filepath.Join(otherParent, ".ENKV-PENDING")) != nil {
			t.Fatal("reserved directory symlink fixture unavailable")
		}
		sourceInfo, err := os.Stat(protected)
		if err != nil {
			t.Fatal("symlink source identity unavailable")
		}
		original := filepath.Join(sourceParent, ".ENKV-PENDING", "application.env")
		resolved, err := materializationCanonicalPath(original)
		if err != nil {
			t.Fatal("reserved original coordinate did not resolve")
		}
		coordinate := contract.MaterializationTarget{Path: original, SurfaceID: contract.ID{1}, Format: contract.MaterializationDotenvFormat, NativeProfile: contract.MaterializationNativeFileProfile}
		t.Run("native-constructor", func(t *testing.T) {
			if _, err := NewMaterializationFileTarget(coordinate, []string{protected}); !errors.Is(err, ErrMaterializationTarget) {
				t.Fatal("reserved original coordinate hidden by directory symlink")
			}
		})
		t.Run("case-sensitive-constructor-facts", func(t *testing.T) {
			// On a case-sensitive filesystem the lowercase reserved directory is absent.
			// These are that constructor's source and resolved-target facts; this is not a native Linux run.
			fixture := &MaterializationFileTarget{target: coordinate, path: resolved, io: nativeMaterializationFileIO(), protected: []materializationProtectedPath{{path: protected, info: sourceInfo}}}
			if err := fixture.checkTarget(); !errors.Is(err, ErrMaterializationTarget) {
				t.Fatal("case-sensitive original reservation lost after resolution")
			}
		})
		t.Run("unrelated-parent-remains-valid", func(t *testing.T) {
			other := coordinate
			other.Path = filepath.Join(otherParent, ".ENKV-PENDING", "application.env")
			if _, err := NewMaterializationFileTarget(other, []string{protected}); err != nil {
				t.Fatal("unrelated directory symlink inherited source reservation")
			}
			resolvedOther, err := materializationCanonicalPath(other.Path)
			if err != nil {
				t.Fatal("unrelated original coordinate did not resolve")
			}
			fixture := &MaterializationFileTarget{target: other, path: resolvedOther, io: nativeMaterializationFileIO(), protected: []materializationProtectedPath{{path: protected, info: sourceInfo}}}
			if err := fixture.checkTarget(); err != nil {
				t.Fatal("unrelated native parent inherited original reservation")
			}
		})
	})
	valid := contract.MaterializationTarget{Path: filepath.Join(parent, "out.env"), SurfaceID: contract.ID{1}, Format: contract.MaterializationDotenvFormat, NativeProfile: contract.MaterializationNativeFileProfile}
	for _, path := range []string{"-", "relative.env", filepath.Join(parent, "..", filepath.Base(parent), "out.env") + "/../other", strings.Repeat("x", 4097), string([]byte{'/', 0xff}), "/bad\x00path"} {
		changed := valid
		changed.Path = path
		if _, err := NewMaterializationFileTarget(changed, nil); !errors.Is(err, ErrMaterializationTarget) {
			t.Fatal("malformed target path admitted")
		}
	}
	for _, protected := range [][]string{{source, satellite, source}, {"relative"}, {strings.Repeat("x", 4097)}} {
		if _, err := NewMaterializationFileTarget(valid, protected); !errors.Is(err, ErrMaterializationTarget) {
			t.Fatal("unbounded or malformed source exclusions admitted")
		}
	}
	if _, err := NewMaterializationFileTarget(valid, []string{filepath.Join(parent, "missing-source")}); !errors.Is(err, ErrMaterializationFileIO) {
		t.Fatal("unavailable source inspection lost its safe class")
	}
	changed := valid
	changed.SurfaceID = contract.ID{}
	if _, err := NewMaterializationFileTarget(changed, nil); !errors.Is(err, ErrMaterializationTarget) {
		t.Fatal("zero surface identity admitted")
	}
	changed = valid
	changed.NativeProfile = "unsupported"
	if _, err := NewMaterializationFileTarget(changed, nil); !errors.Is(err, ErrMaterializationProfile) {
		t.Fatal("unsupported profile admitted")
	}
	target := materializationTestTarget(t, valid.Path, source, satellite)
	if os.Symlink(source, valid.Path) != nil {
		t.Fatal("ordinary target change unavailable")
	}
	result := target.install(t.Context(), materializationTestEnv(t, "new"), nil)
	materializationAssertCompletion(t, result)
	if result.StateResult != contract.MaterializationRefused || result.Facts.Failure.Reason != contract.MaterializationInvalidTarget || len(materializationCandidates(t, parent)) != 0 {
		t.Fatal("changed target was staged")
	}
	materializationAssertBody(t, source, "source fixture")
	materializationAssertBody(t, satellite, "satellite fixture")
	if _, err := os.Stat(filepath.Join(parent, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing parent created")
	}
}

type materializationFaultCase struct {
	name         string
	inject       func(*MaterializationFileTarget)
	stage        contract.MaterializationStage
	state        contract.MaterializationStateResult
	replacement  contract.MaterializationReplacement
	candidate    contract.MaterializationVerification
	installed    contract.MaterializationVerification
	disclosure   contract.MaterializationDisclosure
	cleanup      contract.MaterializationCandidateCleanup
	cleanupStage contract.MaterializationStage
}

// full_only: false
func TestMaterializationFilePreservesFaultAndCleanupFacts(t *testing.T) {
	ioFailure := errors.New("synthetic native failure")
	cases := []materializationFaultCase{
		{name: "create denied", inject: func(target *MaterializationFileTarget) {
			target.io.create = func(string) (*os.File, error) { return nil, syscall.EACCES }
		}, stage: contract.MaterializationStaging, disclosure: contract.MaterializationDisclosureNone, cleanup: contract.MaterializationCandidateNotCreated},
		{name: "chmod", inject: func(target *MaterializationFileTarget) {
			target.io.chmod = func(*os.File, os.FileMode) error { return ioFailure }
		}, stage: contract.MaterializationStaging, disclosure: contract.MaterializationDisclosureUnknown},
		{name: "short write", inject: func(target *MaterializationFileTarget) {
			target.io.write = func(f *os.File, p []byte) (int, error) { return f.Write(p[:len(p)-1]) }
		}, stage: contract.MaterializationStaging},
		{name: "full disk", inject: func(target *MaterializationFileTarget) {
			target.io.write = func(*os.File, []byte) (int, error) { return 0, syscall.ENOSPC }
		}, stage: contract.MaterializationStaging, disclosure: contract.MaterializationDisclosureUnknown},
		{name: "denied write", inject: func(target *MaterializationFileTarget) {
			target.io.write = func(*os.File, []byte) (int, error) { return 0, syscall.EACCES }
		}, stage: contract.MaterializationStaging, disclosure: contract.MaterializationDisclosureUnknown},
		{name: "file sync", inject: func(target *MaterializationFileTarget) {
			target.io.syncFile = func(*os.File) error { return ioFailure }
		}, stage: contract.MaterializationCandidateSync},
		{name: "candidate close", inject: func(target *MaterializationFileTarget) {
			close := target.io.close
			target.io.close = func(f *os.File, stage contract.MaterializationStage) error {
				err := close(f, stage)
				if stage == contract.MaterializationCandidateClose {
					return errors.Join(err, ioFailure)
				}
				return err
			}
		}, stage: contract.MaterializationCandidateClose},
		{name: "candidate read", inject: func(target *MaterializationFileTarget) {
			target.io.read = func(*os.File, []byte, contract.MaterializationStage) (int, error) { return 0, ioFailure }
		}, stage: contract.MaterializationCandidateVerification, candidate: contract.MaterializationVerificationFailed},
		{name: "candidate bytes", inject: func(target *MaterializationFileTarget) {
			syncFile := target.io.syncFile
			target.io.syncFile = func(f *os.File) error {
				if _, err := f.WriteAt([]byte("X"), 0); err != nil {
					return err
				}
				return syncFile(f)
			}
		}, stage: contract.MaterializationCandidateVerification, state: contract.MaterializationPositiveDefect, candidate: contract.MaterializationVerificationFailed},
		{name: "candidate length", inject: func(target *MaterializationFileTarget) {
			syncFile := target.io.syncFile
			target.io.syncFile = func(f *os.File) error {
				if err := f.Truncate(1); err != nil {
					return err
				}
				return syncFile(f)
			}
		}, stage: contract.MaterializationCandidateVerification, state: contract.MaterializationPositiveDefect, candidate: contract.MaterializationVerificationFailed},
		{name: "candidate mode", inject: func(target *MaterializationFileTarget) {
			syncFile := target.io.syncFile
			target.io.syncFile = func(f *os.File) error {
				if err := f.Chmod(0644); err != nil {
					return err
				}
				return syncFile(f)
			}
		}, stage: contract.MaterializationCandidateVerification, state: contract.MaterializationPositiveDefect, candidate: contract.MaterializationVerificationFailed},
		{name: "readback close", inject: func(target *MaterializationFileTarget) {
			close := target.io.close
			count := 0
			target.io.close = func(f *os.File, stage contract.MaterializationStage) error {
				err := close(f, stage)
				if stage == contract.MaterializationCandidateClose {
					count++
					if count == 2 {
						return errors.Join(err, ioFailure)
					}
				}
				return err
			}
		}, stage: contract.MaterializationCandidateClose, candidate: contract.MaterializationVerified},
		{name: "rename refused", inject: func(target *MaterializationFileTarget) {
			target.io.rename = func(string, string) (contract.MaterializationReplacement, error) {
				return contract.MaterializationNotReplaced, syscall.EACCES
			}
		}, stage: contract.MaterializationRename, candidate: contract.MaterializationVerified},
		{name: "rename unknown", inject: func(target *MaterializationFileTarget) {
			target.io.rename = func(string, string) (contract.MaterializationReplacement, error) {
				return contract.MaterializationReplacementUnknown, syscall.EIO
			}
		}, stage: contract.MaterializationRename, candidate: contract.MaterializationVerified, replacement: contract.MaterializationReplacementUnknown},
		{name: "directory sync", inject: func(target *MaterializationFileTarget) { target.io.syncDir = func(*os.File) error { return ioFailure } }, stage: contract.MaterializationDirectorySync, replacement: contract.MaterializationReplaced, candidate: contract.MaterializationVerified},
		{name: "installed open", inject: func(target *MaterializationFileTarget) {
			open := target.io.open
			target.io.open = func(path string, stage contract.MaterializationStage) (*os.File, error) {
				if stage == contract.MaterializationInstalledVerification {
					return nil, ioFailure
				}
				return open(path, stage)
			}
		}, stage: contract.MaterializationInstalledVerification, replacement: contract.MaterializationReplaced, candidate: contract.MaterializationVerified, installed: contract.MaterializationVerificationFailed},
		{name: "installed read", inject: func(target *MaterializationFileTarget) {
			read := target.io.read
			target.io.read = func(f *os.File, p []byte, stage contract.MaterializationStage) (int, error) {
				if stage == contract.MaterializationInstalledVerification {
					return 0, ioFailure
				}
				return read(f, p, stage)
			}
		}, stage: contract.MaterializationInstalledVerification, replacement: contract.MaterializationReplaced, candidate: contract.MaterializationVerified, installed: contract.MaterializationVerificationFailed},
		{name: "installed close", inject: func(target *MaterializationFileTarget) {
			close := target.io.close
			target.io.close = func(f *os.File, stage contract.MaterializationStage) error {
				err := close(f, stage)
				if stage == contract.MaterializationInstalledClose {
					return errors.Join(err, ioFailure)
				}
				return err
			}
		}, stage: contract.MaterializationInstalledClose, replacement: contract.MaterializationReplaced, candidate: contract.MaterializationVerified, installed: contract.MaterializationVerified},
		{name: "directory close", inject: func(target *MaterializationFileTarget) {
			close := target.io.close
			target.io.close = func(f *os.File, stage contract.MaterializationStage) error {
				err := close(f, stage)
				if stage == contract.MaterializationDirectoryClose {
					return errors.Join(err, ioFailure)
				}
				return err
			}
		}, stage: contract.MaterializationDirectoryClose, replacement: contract.MaterializationReplaced, candidate: contract.MaterializationVerified, installed: contract.MaterializationVerified},
		{name: "write and remove", inject: func(target *MaterializationFileTarget) {
			target.io.write = func(*os.File, []byte) (int, error) { return 0, ioFailure }
			target.io.remove = func(string) error { return syscall.EACCES }
		}, stage: contract.MaterializationStaging, disclosure: contract.MaterializationDisclosureUnknown, cleanup: contract.MaterializationCandidateCleanupFailed, cleanupStage: contract.MaterializationCleanup},
		{name: "write close and remove", inject: func(target *MaterializationFileTarget) {
			target.io.write = func(*os.File, []byte) (int, error) { return 0, ioFailure }
			close := target.io.close
			target.io.close = func(f *os.File, stage contract.MaterializationStage) error {
				return errors.Join(close(f, stage), ioFailure)
			}
			target.io.remove = func(string) error { return syscall.EACCES }
		}, stage: contract.MaterializationStaging, disclosure: contract.MaterializationDisclosureUnknown, cleanup: contract.MaterializationCandidateCleanupFailed, cleanupStage: contract.MaterializationSinkClose},
		{name: "write and close removed", inject: func(target *MaterializationFileTarget) {
			target.io.write = func(*os.File, []byte) (int, error) { return 0, ioFailure }
			close := target.io.close
			target.io.close = func(f *os.File, stage contract.MaterializationStage) error {
				return errors.Join(close(f, stage), ioFailure)
			}
		}, stage: contract.MaterializationStaging, disclosure: contract.MaterializationDisclosureUnknown, cleanupStage: contract.MaterializationSinkClose},
		{name: "installed read and close", inject: func(target *MaterializationFileTarget) {
			read := target.io.read
			target.io.read = func(f *os.File, p []byte, stage contract.MaterializationStage) (int, error) {
				if stage == contract.MaterializationInstalledVerification {
					return 0, ioFailure
				}
				return read(f, p, stage)
			}
			close := target.io.close
			target.io.close = func(f *os.File, stage contract.MaterializationStage) error {
				err := close(f, stage)
				if stage == contract.MaterializationInstalledClose {
					return errors.Join(err, ioFailure)
				}
				return err
			}
		}, stage: contract.MaterializationInstalledVerification, replacement: contract.MaterializationReplaced, candidate: contract.MaterializationVerified, installed: contract.MaterializationVerificationFailed, cleanupStage: contract.MaterializationInstalledClose},
	}
	cases = append(cases,
		materializationFaultCase{name: "candidate open", inject: func(target *MaterializationFileTarget) {
			open := target.io.open
			target.io.open = func(path string, stage contract.MaterializationStage) (*os.File, error) {
				if stage == contract.MaterializationCandidateVerification {
					return nil, ioFailure
				}
				return open(path, stage)
			}
		}, stage: contract.MaterializationCandidateVerification, candidate: contract.MaterializationVerificationFailed},
		materializationFaultCase{name: "candidate stat", inject: func(target *MaterializationFileTarget) {
			stat := target.io.stat
			target.io.stat = func(f *os.File, stage contract.MaterializationStage) (os.FileInfo, error) {
				if stage == contract.MaterializationCandidateVerification {
					return nil, ioFailure
				}
				return stat(f, stage)
			}
		}, stage: contract.MaterializationCandidateVerification, candidate: contract.MaterializationVerificationFailed},
		materializationFaultCase{name: "initial stat", inject: func(target *MaterializationFileTarget) {
			target.io.stat = func(*os.File, contract.MaterializationStage) (os.FileInfo, error) { return nil, ioFailure }
		}, stage: contract.MaterializationStaging, disclosure: contract.MaterializationDisclosureUnknown, cleanup: contract.MaterializationCandidateCleanupUnknown, cleanupStage: contract.MaterializationCleanup},
		materializationFaultCase{name: "directory open", inject: func(target *MaterializationFileTarget) {
			open := target.io.open
			target.io.open = func(path string, stage contract.MaterializationStage) (*os.File, error) {
				if stage == contract.MaterializationDirectorySync {
					return nil, ioFailure
				}
				return open(path, stage)
			}
		}, stage: contract.MaterializationDirectorySync, replacement: contract.MaterializationReplaced, candidate: contract.MaterializationVerified},
		materializationFaultCase{name: "installed stat", inject: func(target *MaterializationFileTarget) {
			stat := target.io.stat
			target.io.stat = func(f *os.File, stage contract.MaterializationStage) (os.FileInfo, error) {
				if stage == contract.MaterializationInstalledVerification {
					return nil, ioFailure
				}
				return stat(f, stage)
			}
		}, stage: contract.MaterializationInstalledVerification, replacement: contract.MaterializationReplaced, candidate: contract.MaterializationVerified, installed: contract.MaterializationVerificationFailed},
		materializationFaultCase{name: "installed bytes", inject: func(target *MaterializationFileTarget) {
			read := target.io.read
			target.io.read = func(f *os.File, p []byte, stage contract.MaterializationStage) (int, error) {
				n, err := read(f, p, stage)
				if stage == contract.MaterializationInstalledVerification && n > 0 {
					p[0] ^= 1
				}
				return n, err
			}
		}, stage: contract.MaterializationInstalledVerification, state: contract.MaterializationPositiveDefect, replacement: contract.MaterializationReplaced, candidate: contract.MaterializationVerified, installed: contract.MaterializationVerificationFailed},
		materializationFaultCase{name: "installed mode", inject: func(target *MaterializationFileTarget) {
			syncDir := target.io.syncDir
			target.io.syncDir = func(f *os.File) error {
				if err := syncDir(f); err != nil {
					return err
				}
				return os.Chmod(target.path, 0644)
			}
		}, stage: contract.MaterializationInstalledVerification, state: contract.MaterializationPositiveDefect, replacement: contract.MaterializationReplaced, candidate: contract.MaterializationVerified, installed: contract.MaterializationVerificationFailed},
		materializationFaultCase{name: "candidate trailing readback", inject: func(target *MaterializationFileTarget) {
			read := target.io.read
			target.io.read = func(f *os.File, p []byte, stage contract.MaterializationStage) (int, error) {
				n, err := read(f, p, stage)
				if stage == contract.MaterializationCandidateVerification && n == 0 && err == io.EOF {
					p[0] = 'X'
					return 1, nil
				}
				return n, err
			}
		}, stage: contract.MaterializationCandidateVerification, state: contract.MaterializationPositiveDefect, candidate: contract.MaterializationVerificationFailed},
		materializationFaultCase{name: "cleanup inspection", inject: func(target *MaterializationFileTarget) {
			target.io.write = func(*os.File, []byte) (int, error) { return 0, ioFailure }
			lstat := target.io.lstat
			target.io.lstat = func(path string) (os.FileInfo, error) {
				if strings.HasPrefix(filepath.Base(path), materializationCandidatePrefix) {
					return nil, ioFailure
				}
				return lstat(path)
			}
		}, stage: contract.MaterializationStaging, disclosure: contract.MaterializationDisclosureUnknown, cleanup: contract.MaterializationCandidateCleanupUnknown, cleanupStage: contract.MaterializationCleanup},
	)
	cases = append(cases,
		materializationFaultCase{name: "identity acquisition keeps writer through cleanup", inject: func(target *MaterializationFileTarget) {
			create, open, remove := target.io.create, target.io.open, target.io.remove
			var writer *os.File
			target.io.create = func(parent string) (*os.File, error) { file, err := create(parent); writer = file; return file, err }
			target.io.open = func(path string, stage contract.MaterializationStage) (*os.File, error) {
				if stage == contract.MaterializationStaging {
					return nil, ioFailure
				}
				return open(path, stage)
			}
			target.io.remove = func(path string) error {
				if _, err := writer.Stat(); err != nil {
					return errors.New("writer identity closed before candidate cleanup")
				}
				return remove(path)
			}
		}, stage: contract.MaterializationStaging, disclosure: contract.MaterializationDisclosureUnknown},
		materializationFaultCase{name: "identity stat", inject: func(target *MaterializationFileTarget) {
			open, stat := target.io.open, target.io.stat
			var identity *os.File
			target.io.open = func(path string, stage contract.MaterializationStage) (*os.File, error) {
				file, err := open(path, stage)
				if stage == contract.MaterializationStaging {
					identity = file
				}
				return file, err
			}
			target.io.stat = func(file *os.File, stage contract.MaterializationStage) (os.FileInfo, error) {
				if file == identity {
					return nil, ioFailure
				}
				return stat(file, stage)
			}
		}, stage: contract.MaterializationStaging, disclosure: contract.MaterializationDisclosureUnknown},
		materializationFaultCase{name: "identity mismatch", inject: func(target *MaterializationFileTarget) {
			open := target.io.open
			target.io.open = func(path string, stage contract.MaterializationStage) (*os.File, error) {
				if stage == contract.MaterializationStaging {
					return open(target.path, stage)
				}
				return open(path, stage)
			}
		}, stage: contract.MaterializationStaging, disclosure: contract.MaterializationDisclosureUnknown},
		materializationFaultCase{name: "identity close after installed verification", inject: func(target *MaterializationFileTarget) {
			close := target.io.close
			target.io.close = func(file *os.File, stage contract.MaterializationStage) error {
				err := close(file, stage)
				if stage == contract.MaterializationSinkClose {
					return errors.Join(err, ioFailure)
				}
				return err
			}
		}, stage: contract.MaterializationSinkClose, replacement: contract.MaterializationReplaced, candidate: contract.MaterializationVerified, installed: contract.MaterializationVerified},
		materializationFaultCase{name: "readback failure and identity close", inject: func(target *MaterializationFileTarget) {
			open, read, close, remove := target.io.open, target.io.read, target.io.close, target.io.remove
			var identity *os.File
			target.io.open = func(path string, stage contract.MaterializationStage) (*os.File, error) {
				file, err := open(path, stage)
				if stage == contract.MaterializationStaging {
					identity = file
				}
				return file, err
			}
			target.io.read = func(file *os.File, p []byte, stage contract.MaterializationStage) (int, error) {
				if stage == contract.MaterializationCandidateVerification {
					return 0, ioFailure
				}
				return read(file, p, stage)
			}
			target.io.remove = func(path string) error {
				if _, err := identity.Stat(); err != nil {
					return errors.New("identity closed before candidate cleanup")
				}
				return remove(path)
			}
			target.io.close = func(file *os.File, stage contract.MaterializationStage) error {
				err := close(file, stage)
				if file == identity {
					return errors.Join(err, ioFailure)
				}
				return err
			}
		}, stage: contract.MaterializationCandidateVerification, candidate: contract.MaterializationVerificationFailed, cleanupStage: contract.MaterializationSinkClose},
	)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			path := filepath.Join(parent, "application.env")
			if os.WriteFile(path, []byte("A=old\n"), 0644) != nil {
				t.Fatal("old fixture unavailable")
			}
			target := materializationTestTarget(t, path)
			tc.inject(target)
			result := target.install(t.Context(), materializationTestEnv(t, "new"), nil)
			materializationAssertCompletion(t, result)
			state := tc.state
			if state == "" {
				state = contract.MaterializationUnavailable
			}
			replacement := tc.replacement
			if replacement == "" {
				replacement = contract.MaterializationNotReplaced
			}
			candidate := tc.candidate
			if candidate == "" {
				candidate = contract.MaterializationNotObserved
			}
			installed := tc.installed
			if installed == "" {
				installed = contract.MaterializationNotObserved
			}
			disclosure := tc.disclosure
			if disclosure == "" {
				disclosure = contract.MaterializationDisclosureOccurred
			}
			cleanup := tc.cleanup
			if cleanup == "" {
				cleanup = contract.MaterializationCandidateRemoved
				if replacement == contract.MaterializationReplaced {
					cleanup = contract.MaterializationCandidateRenamed
				}
			}
			facts := result.Facts
			reason := contract.MaterializationIOFailure
			if state == contract.MaterializationPositiveDefect {
				reason = contract.MaterializationVerificationMismatch
			}
			if result.StateResult != state || facts.Replacement != replacement || facts.CandidateVerification != candidate || facts.InstalledVerification != installed || facts.NativeCompletion != contract.MaterializationIncomplete || facts.Disclosure != disclosure || facts.Cleanup != cleanup || facts.Failure == nil || facts.Failure.Stage != tc.stage || facts.Failure.Reason != reason {
				t.Fatalf("fault facts differ: %+v failure=%+v", facts, facts.Failure)
			}
			if tc.cleanupStage == "" && facts.CleanupFailure != nil || tc.cleanupStage != "" && (facts.CleanupFailure == nil || facts.CleanupFailure.Stage != tc.cleanupStage) {
				t.Fatal("independent cleanup failure lost")
			}
			if facts.CleanupFailure != nil {
				cleanupReason := contract.MaterializationIOFailure
				if tc.cleanupStage == contract.MaterializationCleanup {
					cleanupReason = contract.MaterializationCleanupFailure
				}
				if facts.CleanupFailure.Reason != cleanupReason {
					t.Fatal("cleanup failure reason differs")
				}
			}
			if cleanup == contract.MaterializationCandidateCleanupFailed || cleanup == contract.MaterializationCandidateCleanupUnknown {
				paths := materializationCandidates(t, parent)
				if len(paths) != 1 || facts.ResiduePath != paths[0] {
					t.Fatal("exact private residue not retained")
				}
			} else if facts.ResiduePath != "" || len(materializationCandidates(t, parent)) != 0 {
				t.Fatal("unexpected residue or candidate")
			}
			want := "A=old\n"
			if replacement == contract.MaterializationReplaced {
				want = "A=new\n"
			}
			materializationAssertBody(t, path, want)
		})
	}
}

// full_only: false
func TestMaterializationFilePreservesAmbiguousEffectsAndExactCleanupOwnership(t *testing.T) {
	t.Run("rename effect unknown after actual replacement", func(t *testing.T) {
		parent := t.TempDir()
		path := filepath.Join(parent, "application.env")
		if os.WriteFile(path, []byte("A=old\n"), 0600) != nil {
			t.Fatal("old fixture unavailable")
		}
		target := materializationTestTarget(t, path)
		rename := target.io.rename
		var candidate string
		target.io.rename = func(from, to string) (contract.MaterializationReplacement, error) {
			candidate = from
			if _, err := rename(from, to); err != nil {
				return contract.MaterializationReplacementUnknown, err
			}
			return contract.MaterializationReplacementUnknown, syscall.EIO
		}
		result := target.install(t.Context(), materializationTestEnv(t, "new"), nil)
		materializationAssertCompletion(t, result)
		if result.StateResult != contract.MaterializationUnavailable || result.Facts.Replacement != contract.MaterializationReplacementUnknown || result.Facts.Cleanup != contract.MaterializationCandidateCleanupUnknown || result.Facts.ResiduePath != candidate || result.Facts.Failure.Stage != contract.MaterializationRename || result.Facts.CleanupFailure == nil {
			t.Fatal("unknown effect converted to preservation or erasure")
		}
		materializationAssertBody(t, path, "A=new\n")
		if len(materializationCandidates(t, parent)) != 0 {
			t.Fatal("known consumed pathname re-created")
		}
	})
	t.Run("foreign file at candidate name", func(t *testing.T) {
		parent := t.TempDir()
		path := filepath.Join(parent, "application.env")
		target := materializationTestTarget(t, path)
		var candidate string
		target.io.write = func(f *os.File, _ []byte) (int, error) {
			candidate = f.Name()
			if err := os.Remove(candidate); err != nil {
				return 0, err
			}
			if err := os.WriteFile(candidate, []byte("foreign complete file"), 0600); err != nil {
				return 0, err
			}
			return 0, syscall.EIO
		}
		result := target.install(t.Context(), materializationTestEnv(t, "new"), nil)
		materializationAssertCompletion(t, result)
		if result.Facts.Cleanup != contract.MaterializationCandidateCleanupUnknown || result.Facts.ResiduePath != candidate || result.Facts.CleanupFailure == nil {
			t.Fatal("foreign candidate ownership claimed")
		}
		materializationAssertBody(t, candidate, "foreign complete file")
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("foreign candidate became destination")
		}
	})
	t.Run("expired and unprepared invocation", func(t *testing.T) {
		for _, prepared := range []bool{false, true} {
			parent := t.TempDir()
			target := materializationTestTarget(t, filepath.Join(parent, "application.env"))
			ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
			env := materializationEnv{}
			if prepared {
				env = materializationTestEnv(t, "new")
			}
			result := target.install(ctx, env, nil)
			cancel()
			materializationAssertCompletion(t, result)
			if result.Facts.Cleanup != contract.MaterializationCandidateNotCreated || result.Facts.Disclosure != contract.MaterializationDisclosureNone || len(materializationCandidates(t, parent)) != 0 {
				t.Fatal("invalid invocation staged a candidate")
			}
			if prepared && result.Facts.Failure.Reason != contract.MaterializationDeadlineExceeded {
				t.Fatal("deadline reason lost")
			}
			if !prepared && result.Facts.Failure.Reason != contract.MaterializationInvalidAdmission {
				t.Fatal("unprepared representation admitted")
			}
		}
	})
}

// full_only: false
func TestMaterializationFileCancellationWaitsForNativeSettlement(t *testing.T) {
	for _, cut := range []string{"before staging", "after create", "during write", "before rename", "after rename", "during installed close", "during directory close", "during candidate inspection", "during directory open", "during installed open", "during identity open", "during identity close"} {
		t.Run(cut, func(t *testing.T) {
			parent := t.TempDir()
			path := filepath.Join(parent, "application.env")
			if os.WriteFile(path, []byte("A=old\n"), 0600) != nil {
				t.Fatal("old fixture unavailable")
			}
			target := materializationTestTarget(t, path)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			entered, release := make(chan struct{}), make(chan struct{})
			normalStepAfterCancel := false
			if cut == "before staging" {
				cancel()
			}
			if cut == "after create" {
				create := target.io.create
				target.io.create = func(parent string) (*os.File, error) { f, err := create(parent); cancel(); return f, err }
			}
			if cut == "during write" {
				write := target.io.write
				var once sync.Once
				target.io.write = func(f *os.File, p []byte) (int, error) {
					once.Do(func() { close(entered); <-release })
					return write(f, p)
				}
			}
			if cut == "before rename" {
				closeFile := target.io.close
				count := 0
				target.io.close = func(f *os.File, stage contract.MaterializationStage) error {
					err := closeFile(f, stage)
					if stage == contract.MaterializationCandidateClose {
						count++
						if count == 2 {
							cancel()
						}
					}
					return err
				}
			}
			if cut == "after rename" {
				rename := target.io.rename
				target.io.rename = func(from, to string) (contract.MaterializationReplacement, error) {
					replacement, err := rename(from, to)
					cancel()
					return replacement, err
				}
			}
			if cut == "during installed close" || cut == "during directory close" {
				closeFile := target.io.close
				target.io.close = func(f *os.File, stage contract.MaterializationStage) error {
					err := closeFile(f, stage)
					if cut == "during installed close" && stage == contract.MaterializationInstalledClose || cut == "during directory close" && stage == contract.MaterializationDirectoryClose {
						cancel()
					}
					return err
				}
			}
			if cut == "during candidate inspection" {
				lstat, open := target.io.lstat, target.io.open
				target.io.lstat = func(path string) (os.FileInfo, error) {
					info, err := lstat(path)
					if err == nil && strings.HasPrefix(filepath.Base(path), materializationCandidatePrefix) {
						cancel()
					}
					return info, err
				}
				target.io.open = func(path string, stage contract.MaterializationStage) (*os.File, error) {
					if stage == contract.MaterializationCandidateVerification && ctx.Err() != nil {
						normalStepAfterCancel = true
					}
					return open(path, stage)
				}
			}
			if cut == "during directory open" {
				open, syncDir := target.io.open, target.io.syncDir
				target.io.open = func(path string, stage contract.MaterializationStage) (*os.File, error) {
					file, err := open(path, stage)
					if stage == contract.MaterializationDirectorySync && err == nil {
						cancel()
					}
					return file, err
				}
				target.io.syncDir = func(file *os.File) error {
					if ctx.Err() != nil {
						normalStepAfterCancel = true
					}
					return syncDir(file)
				}
			}
			if cut == "during installed open" {
				open, stat := target.io.open, target.io.stat
				target.io.open = func(path string, stage contract.MaterializationStage) (*os.File, error) {
					file, err := open(path, stage)
					if stage == contract.MaterializationInstalledVerification && err == nil {
						cancel()
					}
					return file, err
				}
				target.io.stat = func(file *os.File, stage contract.MaterializationStage) (os.FileInfo, error) {
					if stage == contract.MaterializationInstalledVerification && ctx.Err() != nil {
						normalStepAfterCancel = true
					}
					return stat(file, stage)
				}
			}
			if cut == "during identity open" || cut == "during identity close" {
				open, stat, closeFile := target.io.open, target.io.stat, target.io.close
				var identity *os.File
				target.io.open = func(path string, stage contract.MaterializationStage) (*os.File, error) {
					file, err := open(path, stage)
					if stage == contract.MaterializationStaging && err == nil {
						identity = file
						if cut == "during identity open" {
							cancel()
						}
					}
					return file, err
				}
				target.io.stat = func(file *os.File, stage contract.MaterializationStage) (os.FileInfo, error) {
					if file == identity && ctx.Err() != nil {
						normalStepAfterCancel = true
					}
					return stat(file, stage)
				}
				target.io.close = func(file *os.File, stage contract.MaterializationStage) error {
					err := closeFile(file, stage)
					if cut == "during identity close" && file == identity {
						cancel()
					}
					return err
				}
			}
			returned := make(chan contract.MaterializationCompletion, 1)
			env := materializationTestEnv(t, "new")
			go func() { returned <- target.install(ctx, env, nil) }()
			if cut == "during write" {
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("native write barrier not entered")
				}
				cancel()
				select {
				case <-returned:
					close(release)
					t.Fatal("cancellation released unsettled native write")
				default:
				}
				close(release)
			}
			var result contract.MaterializationCompletion
			select {
			case result = <-returned:
			case <-time.After(5 * time.Second):
				t.Fatal("native settlement did not join")
			}
			materializationAssertCompletion(t, result)
			if normalStepAfterCancel {
				t.Fatal("new normal native step started after canceled inspection settled")
			}
			if result.StateResult != contract.MaterializationUnavailable || result.Facts.Failure.Reason != contract.MaterializationCanceled || len(materializationCandidates(t, parent)) != 0 {
				t.Fatal("cancellation facts or cleanup differ")
			}
			if cut == "after rename" || cut == "during installed close" || cut == "during directory close" || cut == "during directory open" || cut == "during installed open" || cut == "during identity close" {
				if result.Facts.Replacement != contract.MaterializationReplaced || result.Facts.Cleanup != contract.MaterializationCandidateRenamed {
					t.Fatal("late replacement fact lost")
				}
				materializationAssertBody(t, path, "A=new\n")
			} else {
				if result.Facts.Replacement != contract.MaterializationNotReplaced {
					t.Fatal("early cancellation replaced destination")
				}
				materializationAssertBody(t, path, "A=old\n")
			}
			if cut == "before staging" && (result.Facts.Cleanup != contract.MaterializationCandidateNotCreated || result.Facts.Disclosure != contract.MaterializationDisclosureNone) {
				t.Fatal("pre-staging cancellation disclosed")
			}
			if (cut == "after create" || cut == "during identity open") && result.Facts.Disclosure != contract.MaterializationDisclosureUnknown {
				t.Fatal("empty candidate falsely proves plaintext write")
			}
		})
	}
	t.Run("canceled write and denied cleanup", func(t *testing.T) {
		parent := t.TempDir()
		path := filepath.Join(parent, "application.env")
		if os.WriteFile(path, []byte("A=old\n"), 0600) != nil {
			t.Fatal("old fixture unavailable")
		}
		target := materializationTestTarget(t, path)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		target.io.write = func(*os.File, []byte) (int, error) { cancel(); return 0, context.Canceled }
		target.io.remove = func(string) error { return syscall.EACCES }
		result := target.install(ctx, materializationTestEnv(t, "new"), nil)
		materializationAssertCompletion(t, result)
		paths := materializationCandidates(t, parent)
		if result.Facts.Failure.Reason != contract.MaterializationCanceled || result.Facts.Cleanup != contract.MaterializationCandidateCleanupFailed || result.Facts.CleanupFailure == nil || result.Facts.CleanupFailure.Stage != contract.MaterializationCleanup || len(paths) != 1 || result.Facts.ResiduePath != paths[0] || result.Facts.Disclosure != contract.MaterializationDisclosureUnknown {
			t.Fatal("cancellation or exact failed cleanup facts lost")
		}
		materializationAssertBody(t, path, "A=old\n")
	})
}

// full_only: false
func TestMaterializationFileConcurrentReplacementObservesCompleteCandidates(t *testing.T) {
	t.Run("modeled-inode-reuse-after-complete-replacements", func(t *testing.T) {
		parent := t.TempDir()
		path := filepath.Join(parent, "application.env")
		first, middle, last := materializationTestTarget(t, path), materializationTestTarget(t, path), materializationTestTarget(t, path)
		originalEnv := materializationTestEnv(t, "same")
		middleEnv := materializationTestEnv(t, "middle")
		create, open, closeFile := first.io.create, first.io.open, first.io.close
		stat, lstat, syncDir := first.io.stat, first.io.lstat, first.io.syncDir
		liveOriginal := make(map[*os.File]bool)
		var originalInfo, completeOriginal os.FileInfo
		candidateCloses, cutReached, reuseEnabled := 0, false, false
		first.io.create = func(parent string) (*os.File, error) {
			file, err := create(parent)
			if err == nil {
				originalInfo, err = file.Stat()
				liveOriginal[file] = true
			}
			return file, err
		}
		first.io.open = func(path string, stage contract.MaterializationStage) (*os.File, error) {
			file, err := open(path, stage)
			if err == nil && !cutReached {
				info, statErr := file.Stat()
				if statErr == nil && os.SameFile(originalInfo, info) {
					liveOriginal[file] = true
				}
			}
			return file, err
		}
		first.io.close = func(file *os.File, stage contract.MaterializationStage) error {
			original := liveOriginal[file]
			err := closeFile(file, stage)
			if err == nil {
				delete(liveOriginal, file)
				if original && stage == contract.MaterializationCandidateClose {
					candidateCloses++
				}
			}
			return err
		}
		first.io.stat = func(file *os.File, stage contract.MaterializationStage) (os.FileInfo, error) {
			info, err := stat(file, stage)
			if err == nil && stage == contract.MaterializationCandidateVerification {
				completeOriginal = info
			}
			if err == nil && stage == contract.MaterializationInstalledVerification && reuseEnabled {
				return completeOriginal, nil
			}
			return info, err
		}
		first.io.lstat = func(path string) (os.FileInfo, error) {
			info, err := lstat(path)
			if err == nil && path == first.path && reuseEnabled {
				return completeOriginal, nil
			}
			return info, err
		}
		var middleResult, lastResult contract.MaterializationCompletion
		first.io.syncDir = func(directory *os.File) error {
			if err := syncDir(directory); err != nil {
				return err
			}
			if candidateCloses != 2 || completeOriginal == nil {
				return errors.New("required candidate closes or observation missing")
			}
			cutReached = true
			middleResult = middle.install(t.Context(), middleEnv, nil)
			if middleResult.Validate() != nil || middleResult.StateResult != contract.MaterializationSuccess {
				return errors.New("middle native replacement incomplete")
			}
			body, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(body, []byte("A=middle\n")) {
				return errors.New("middle native surface differs")
			}
			lastResult = last.install(t.Context(), originalEnv, nil)
			if lastResult.Validate() != nil || lastResult.StateResult != contract.MaterializationSuccess {
				return errors.New("last native replacement incomplete")
			}
			body, err = os.ReadFile(path)
			if err != nil || !bytes.Equal(body, []byte("A=same\n")) {
				return errors.New("last native surface differs")
			}
			actual, err := os.Stat(path)
			if err != nil || actual.Mode() != completeOriginal.Mode() || actual.Size() != completeOriginal.Size() {
				return errors.New("modeled metadata preconditions differ")
			}
			// Only installed metadata models inode reuse, and only after every
			// live reference to A is gone. B and C use complete native installs.
			reuseEnabled = len(liveOriginal) == 0
			if !reuseEnabled && os.SameFile(originalInfo, actual) {
				return errors.New("live original identity was reused")
			}
			return nil
		}
		result := first.install(t.Context(), originalEnv, nil)
		materializationAssertCompletion(t, middleResult)
		materializationAssertCompletion(t, lastResult)
		materializationAssertCompletion(t, result)
		if !cutReached || middleResult.StateResult != contract.MaterializationSuccess || lastResult.StateResult != contract.MaterializationSuccess {
			t.Fatal("actual competing replacement interleaving incomplete")
		}
		if len(liveOriginal) != 0 {
			t.Fatal("original candidate handles did not positively close")
		}
		if result.StateResult != contract.MaterializationUnavailable || result.Facts.Failure == nil || result.Facts.Failure.Reason != contract.MaterializationCompetingReplacement || result.Facts.Replacement != contract.MaterializationReplaced || result.Facts.CandidateVerification != contract.MaterializationVerified || result.Facts.InstalledVerification != contract.MaterializationVerificationFailed || result.Facts.Cleanup != contract.MaterializationCandidateRenamed {
			t.Fatalf("own-candidate result=%s replacement=%s candidate=%s installed=%s completion=%s disclosure=%s cleanup=%s reuse_modeled=%t candidate_closes=%d", result.StateResult, result.Facts.Replacement, result.Facts.CandidateVerification, result.Facts.InstalledVerification, result.Facts.NativeCompletion, result.Facts.Disclosure, result.Facts.Cleanup, reuseEnabled, candidateCloses)
		}
		materializationAssertBody(t, path, "A=same\n")
		if len(materializationCandidates(t, parent)) != 0 {
			t.Fatal("competing native operations retained a candidate")
		}
	})
	t.Run("identical-bytes-different-inode", func(t *testing.T) {
		parent := t.TempDir()
		path := filepath.Join(parent, "application.env")
		first, second := materializationTestTarget(t, path), materializationTestTarget(t, path)
		env := materializationTestEnv(t, "same")
		syncDir := first.io.syncDir
		var competitor contract.MaterializationCompletion
		var originalInfo, competitorInfo os.FileInfo
		first.io.syncDir = func(directory *os.File) error {
			if err := syncDir(directory); err != nil {
				return err
			}
			var err error
			originalInfo, err = os.Stat(path)
			if err != nil {
				return err
			}
			competitor = second.install(t.Context(), env, nil)
			if competitor.StateResult != contract.MaterializationSuccess {
				return errors.New("synthetic competing installation failed")
			}
			competitorInfo, err = os.Stat(path)
			return err
		}
		result := first.install(t.Context(), env, nil)
		materializationAssertCompletion(t, competitor)
		materializationAssertCompletion(t, result)
		if originalInfo == nil || competitorInfo == nil || os.SameFile(originalInfo, competitorInfo) {
			t.Fatal("competing fixture did not replace the original inode")
		}
		if competitor.StateResult != contract.MaterializationSuccess || result.StateResult != contract.MaterializationUnavailable || result.Facts.Failure == nil || result.Facts.Failure.Reason != contract.MaterializationCompetingReplacement || result.Facts.Replacement != contract.MaterializationReplaced || result.Facts.CandidateVerification != contract.MaterializationVerified || result.Facts.InstalledVerification != contract.MaterializationVerificationFailed || result.Facts.Cleanup != contract.MaterializationCandidateRenamed {
			t.Fatal("identical competing bytes falsely satisfied own-candidate verification")
		}
		materializationAssertBody(t, path, "A=same\n")
		if len(materializationCandidates(t, parent)) != 0 {
			t.Fatal("identical competing installation retained a candidate")
		}
	})
	parent := t.TempDir()
	path := filepath.Join(parent, "application.env")
	if os.WriteFile(path, []byte("A=old\n"), 0600) != nil {
		t.Fatal("old fixture unavailable")
	}
	first := materializationTestTarget(t, path)
	second := materializationTestTarget(t, path)
	firstRenamed, secondFinished := make(chan struct{}), make(chan struct{})
	rename := first.io.rename
	first.io.rename = func(from, to string) (contract.MaterializationReplacement, error) {
		replacement, err := rename(from, to)
		close(firstRenamed)
		<-secondFinished
		return replacement, err
	}
	valueA, valueB := strings.Repeat("a", 65536), strings.Repeat("b", 65536)
	envA, envB := materializationTestEnv(t, valueA), materializationTestEnv(t, valueB)
	wantOld, wantA, wantB := []byte("A=old\n"), []byte("A="+valueA+"\n"), []byte("A="+valueB+"\n")
	readerDone, readerStop := make(chan bool, 1), make(chan struct{})
	firstRead, observedA, observedB := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseReader sync.Once
	defer func() {
		releaseReader.Do(func() { close(readerStop) })
		select {
		case valid := <-readerDone:
			if !valid {
				t.Error("reader observed partial or mixed surface")
			}
		case <-time.After(5 * time.Second):
			t.Error("native reader did not join")
		}
	}()
	go func() {
		valid, initial, sawA, sawB := true, true, false, false
		for {
			select {
			case <-readerStop:
				readerDone <- valid
				return
			default:
			}
			body, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(body, wantOld) && !bytes.Equal(body, wantA) && !bytes.Equal(body, wantB) {
				valid = false
			}
			if initial {
				initial = false
				close(firstRead)
			}
			if !sawA && bytes.Equal(body, wantA) {
				sawA = true
				close(observedA)
			}
			if !sawB && bytes.Equal(body, wantB) {
				sawB = true
				close(observedB)
			}
		}
	}()
	select {
	case <-firstRead:
	case <-time.After(5 * time.Second):
		t.Fatal("old surface reader did not start")
	}
	firstDone := make(chan contract.MaterializationCompletion, 1)
	var releaseSecond sync.Once
	firstJoined := false
	defer func() {
		releaseSecond.Do(func() { close(secondFinished) })
		if !firstJoined {
			select {
			case <-firstDone:
			case <-time.After(5 * time.Second):
				t.Error("first native replacement did not join")
			}
		}
	}()
	go func() { firstDone <- first.install(t.Context(), envA, nil) }()
	select {
	case <-firstRenamed:
	case <-firstDone:
		firstJoined = true
		t.Fatal("first operation stopped before controlled rename")
	case <-time.After(5 * time.Second):
		t.Fatal("first rename barrier not entered")
	}
	select {
	case <-observedA:
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not observe complete first candidate")
	}
	secondResult := second.install(t.Context(), envB, nil)
	releaseSecond.Do(func() { close(secondFinished) })
	var firstResult contract.MaterializationCompletion
	select {
	case firstResult = <-firstDone:
		firstJoined = true
	case <-time.After(5 * time.Second):
		t.Fatal("competing operation did not join")
	}
	select {
	case <-observedB:
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not observe complete second candidate")
	}
	materializationAssertCompletion(t, firstResult)
	materializationAssertCompletion(t, secondResult)
	if secondResult.StateResult != contract.MaterializationSuccess || firstResult.StateResult != contract.MaterializationUnavailable || firstResult.Facts.Failure.Reason != contract.MaterializationCompetingReplacement || firstResult.Facts.Replacement != contract.MaterializationReplaced || firstResult.Facts.Cleanup != contract.MaterializationCandidateRenamed {
		t.Fatal("competing replacement facts differ")
	}
	materializationAssertBody(t, path, string(wantB))
	if len(materializationCandidates(t, parent)) != 0 {
		t.Fatal("operation removed or retained a foreign candidate")
	}
}

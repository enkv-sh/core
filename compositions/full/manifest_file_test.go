//go:build (darwin && arm64) || (linux && amd64)

package compositionfull

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"enkv.sh/core/contract"
)

func manifestTestTarget(t *testing.T, path string, protected ...string) *manifestFileTarget {
	t.Helper()
	target, facts := newManifestFileTarget(path, protected, nil)
	if target == nil || facts.Failure != nil {
		t.Fatalf("synthetic native target refused: %+v", facts)
	}
	return target
}

func manifestAssertBody(t *testing.T, path string, want []byte) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(body, want) {
		t.Fatal("complete synthetic manifest differs")
	}
}

// full_only: false
func TestManifestFileInstallsCompleteArtifact(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "existing"}[existing], func(t *testing.T) {
			parent := t.TempDir()
			path := filepath.Join(parent, "manifest.json")
			var old *os.File
			if existing {
				if err := os.WriteFile(path, []byte("old complete artifact"), 0644); err != nil {
					t.Fatal(err)
				}
				var err error
				old, err = os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := old.Close(); err != nil {
						t.Error(err)
					}
				})
			}
			artifact := []byte(`{"synthetic":"complete"}`)
			target := manifestTestTarget(t, path)
			result := target.install(t.Context(), manifestTestArtifactIdentity(manifestTestFormat), artifact, nil)
			if result.NativeCompletion != ManifestNativeComplete || result.Replacement != ManifestReplaced || result.CandidateVerification != ManifestVerified || result.InstalledVerification != ManifestVerified || result.CandidateCleanup != ManifestCandidateRenamed || result.Failure != nil || result.ResiduePath != "" {
				t.Fatalf("complete native delivery facts differ: %+v", result)
			}
			manifestAssertBody(t, path, artifact)
			digest := sha256.Sum256(artifact)
			if result.Artifact == nil || result.Artifact.Digest != contract.ID(digest) || result.Artifact.Length != uint64(len(artifact)) || result.Artifact.FormatContractID != manifestTestFormat {
				t.Fatal("artifact identity differs")
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode() != 0600 {
				t.Fatal("installed mode differs")
			}
			if old != nil {
				body, err := io.ReadAll(old)
				if err != nil || !bytes.Equal(body, []byte("old complete artifact")) {
					t.Fatal("open reader did not retain complete old artifact")
				}
			}
			refused := target.install(t.Context(), manifestTestArtifactIdentity(manifestTestFormat), []byte("second artifact"), nil)
			if refused.Failure == nil || refused.Failure.Stage != ManifestPreflightStage || refused.Replacement != ManifestReplacementNotAttempted || refused.CandidateCleanup != ManifestCandidateNotCreated {
				t.Fatal("one-use target delivered a second time")
			}
			manifestAssertBody(t, path, artifact)
		})
	}
}

// full_only: false
func TestManifestFileSourceReservationsUseNativeParentIdentity(t *testing.T) {
	root := t.TempDir()
	sourceParent, otherParent := filepath.Join(root, "source"), filepath.Join(root, "SOURCE")
	if err := os.Mkdir(sourceParent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(otherParent, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	left, leftErr := os.Stat(sourceParent)
	right, rightErr := os.Stat(otherParent)
	if leftErr != nil || rightErr != nil {
		t.Fatal("case parent identities unavailable")
	}
	source := filepath.Join(sourceParent, "source.yaml")
	if err := os.WriteFile(source, []byte("source original"), 0600); err != nil {
		t.Fatal(err)
	}
	target, facts := newManifestFileTarget(filepath.Join(otherParent, ".ENKV-EDITABLE-target"), []string{source}, nil)
	if os.SameFile(left, right) {
		if target != nil || facts.Failure == nil || facts.Failure.Reason != ManifestReservedPath {
			t.Fatal("same native parent lost reservation")
		}
	} else if target == nil || facts.Failure != nil {
		t.Fatal("distinct case-sensitive parent inherited reservation")
	}
	reservedDestination := t.TempDir()
	if os.Symlink(reservedDestination, filepath.Join(sourceParent, ".enkv-pending")) != nil {
		t.Fatal("reserved symlink unavailable")
	}
	for _, path := range []string{filepath.Join(sourceParent, ".enkv-pending", "artifact"), filepath.Join(reservedDestination, "artifact")} {
		if target, facts := newManifestFileTarget(path, []string{source}, nil); target != nil || facts.Failure == nil || facts.Failure.Reason != ManifestReservedPath {
			t.Fatal("resolved owned namespace alias admitted")
		}
	}
	for _, paths := range [][]string{{source, source, source}, {"relative"}, {strings.Repeat("x", manifestMaxPath+1)}, {filepath.Join(sourceParent, "missing")}} {
		if target, facts := newManifestFileTarget(filepath.Join(root, "out"), paths, nil); target != nil || facts.Failure == nil {
			t.Fatal("invalid source exclusions admitted")
		}
	}
}

// full_only: false
func TestManifestFileExpiredInvocationCreatesNoCandidate(t *testing.T) {
	parent := t.TempDir()
	target := manifestTestTarget(t, filepath.Join(parent, "manifest.json"))
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	result := target.install(ctx, manifestTestArtifactIdentity(manifestTestFormat), []byte("complete artifact"), nil)
	if result.Failure == nil || result.Failure.Reason != ManifestDeadlineExceeded || result.Replacement != ManifestReplacementNotAttempted || result.CandidateCleanup != ManifestCandidateNotCreated || len(manifestCandidates(t, parent)) != 0 {
		t.Fatalf("expired invocation staged a candidate: %+v", result)
	}
}

func manifestCandidates(t *testing.T, parent string) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(parent, manifestCandidatePrefix+"*"))
	if err != nil {
		t.Fatal(err)
	}
	return paths
}

// full_only: false
func TestManifestFileRefusesAliasesNamespacesAndUnsafeTargets(t *testing.T) {
	t.Run("bounded-target-path-backing", func(t *testing.T) {
		for _, existingParent := range []bool{true, false} {
			t.Run(map[bool]string{true: "successful-constructor", false: "missing-parent-refusal"}[existingParent], func(t *testing.T) {
				parent, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				if !existingParent {
					parent = filepath.Join(parent, "missing")
				}
				value := filepath.Join(parent, "manifest.json")
				const padding = 1 << 20
				backing := strings.Repeat("x", padding) + value + strings.Repeat("x", padding)
				input := backing[padding : padding+len(value)]
				target, facts := newManifestFileTarget(input, nil, nil)
				if existingParent {
					if target == nil || facts.Failure != nil || target.original != input {
						t.Fatalf("valid target path capture failed: %+v", facts)
					}
					if unsafe.StringData(target.original) == unsafe.StringData(input) {
						t.Error("captured original path retains oversized caller backing")
					}
				} else if target != nil || facts.Failure == nil || facts.Failure.Stage != ManifestPreflightStage || facts.Failure.Reason != ManifestInvalidTarget {
					t.Fatalf("missing parent refusal differs: %+v", facts)
				}
				if facts.TargetPath != input {
					t.Fatal("validated captured target path differs")
				}
				if unsafe.StringData(facts.TargetPath) == unsafe.StringData(input) {
					t.Error("returned target path retains oversized caller backing")
				}
			})
		}
	})
	parent := t.TempDir()
	satelliteParent := filepath.Join(parent, ".enkv")
	if err := os.Mkdir(satelliteParent, 0700); err != nil {
		t.Fatal(err)
	}
	source, satellite := filepath.Join(parent, "source.yaml"), filepath.Join(satelliteParent, "generated.json")
	for _, path := range []string{source, satellite} {
		if err := os.WriteFile(path, []byte("preserved source"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	hardlink, symlink, fifo := filepath.Join(parent, "hardlink"), filepath.Join(parent, "symlink"), filepath.Join(parent, "fifo")
	if os.Link(source, hardlink) != nil || os.Symlink(source, symlink) != nil || syscall.Mkfifo(fifo, 0600) != nil {
		t.Fatal("native alias fixtures unavailable")
	}
	for _, path := range []string{source, satellite, hardlink, symlink, fifo, parent, "/dev/null", filepath.Join(parent, "missing", "out"), "relative", "-", "/invalid\x00path", string([]byte{'/', 0xff}), strings.Repeat("x", manifestMaxPath+1)} {
		target, facts := newManifestFileTarget(path, []string{source, satellite}, nil)
		if target != nil || facts.Failure == nil || facts.Replacement != ManifestReplacementNotAttempted || facts.CandidateCleanup != ManifestCandidateNotCreated {
			t.Fatalf("unsafe target admitted: %+v", facts)
		}
		if !manifestPathValid(path) && facts.TargetPath != "" {
			t.Fatal("unvalidated target echoed")
		}
	}
	for _, owner := range []string{parent, satelliteParent} {
		for _, name := range []string{".enkv", ".ENKV-LOCKS", ".enkv-pending", ".ENKV-TRANSACTIONS", ".enkv-editable-candidate", ".ENKV-GENERATED-candidate"} {
			for _, existing := range []bool{false, true} {
				path := filepath.Join(owner, name)
				if strings.HasSuffix(name, "candidate") {
					if existing {
						if err := os.WriteFile(path, []byte("reserved"), 0600); err != nil {
							t.Fatal(err)
						}
					}
				} else {
					if err := os.MkdirAll(path, 0700); err != nil {
						t.Fatal(err)
					}
					path = filepath.Join(path, "record")
					if existing {
						if err := os.WriteFile(path, []byte("reserved"), 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
				if target, facts := newManifestFileTarget(path, []string{source, satellite}, nil); target != nil || facts.Failure == nil || facts.Failure.Reason != ManifestReservedPath {
					t.Fatalf("reserved source namespace admitted: %+v", facts)
				}
			}
		}
	}
	unrelated := t.TempDir()
	manifestTestTarget(t, filepath.Join(unrelated, ".ENKV-EDITABLE-unrelated"), source, satellite)
	aliasParent := filepath.Join(unrelated, "source-alias")
	if os.Symlink(parent, aliasParent) != nil {
		t.Fatal("parent alias unavailable")
	}
	if target, facts := newManifestFileTarget(filepath.Join(aliasParent, ".ENKV-GENERATED-alias"), []string{source, satellite}, nil); target != nil || facts.Failure.Reason != ManifestReservedPath {
		t.Fatal("native source parent alias lost namespace reservation")
	}
	for _, path := range []string{source, satellite} {
		manifestAssertBody(t, path, []byte("preserved source"))
	}
	if len(manifestCandidates(t, parent)) != 0 || len(manifestCandidates(t, satelliteParent)) != 0 {
		t.Fatal("refusal staged a candidate")
	}
}

// full_only: false
func TestManifestFileRechecksSourceTargetAndParentBeforeRename(t *testing.T) {
	for _, change := range []string{"source-alias", "target-symlink", "source-identity", "source-check", "parent-identity", "legal-regular-replacement"} {
		t.Run(change, func(t *testing.T) {
			root := t.TempDir()
			parent, sourceParent := filepath.Join(root, "output"), filepath.Join(root, "source")
			if os.Mkdir(parent, 0700) != nil || os.Mkdir(sourceParent, 0700) != nil {
				t.Fatal("parent fixtures unavailable")
			}
			source, path := filepath.Join(sourceParent, "source.yaml"), filepath.Join(parent, "manifest.json")
			if os.WriteFile(source, []byte("source original"), 0600) != nil || os.WriteFile(path, []byte("old complete"), 0600) != nil {
				t.Fatal("file fixtures unavailable")
			}
			checks := 0
			checkSource := func(context.Context) error {
				checks++
				if checks != 2 {
					return nil
				}
				switch change {
				case "source-alias":
					if err := os.Remove(path); err != nil {
						return err
					}
					return os.Link(source, path)
				case "target-symlink":
					if err := os.Remove(path); err != nil {
						return err
					}
					return os.Symlink(source, path)
				case "source-identity":
					if err := os.Rename(source, source+".saved"); err != nil {
						return err
					}
					return os.WriteFile(source, []byte("changed source"), 0600)
				case "source-check":
					return errors.New("synthetic unchanged check failure")
				case "parent-identity":
					if err := os.Rename(parent, parent+".saved"); err != nil {
						return err
					}
					return os.Mkdir(parent, 0700)
				case "legal-regular-replacement":
					other := path + ".other"
					if err := os.WriteFile(other, []byte("other complete"), 0600); err != nil {
						return err
					}
					return os.Rename(other, path)
				}
				return nil
			}
			target, facts := newManifestFileTarget(path, []string{source}, checkSource)
			if target == nil {
				t.Fatalf("fixture refused: %+v", facts)
			}
			renames := 0
			rename := target.io.rename
			target.io.rename = func(from, to string) (ManifestReplacement, error) { renames++; return rename(from, to) }
			result := target.install(t.Context(), manifestTestArtifactIdentity(manifestTestFormat), []byte("new complete"), nil)
			if change == "legal-regular-replacement" {
				if result.NativeCompletion != ManifestNativeComplete || renames != 1 {
					t.Fatalf("independent legal replacement refused: %+v", result)
				}
				manifestAssertBody(t, path, []byte("new complete"))
				return
			}
			if checks != 2 || renames != 0 || result.Failure == nil || result.Failure.Stage != ManifestPreflightStage || result.CandidateVerification != ManifestVerified || result.Replacement != ManifestNotReplaced || result.NativeCompletion != ManifestNativeIncomplete {
				t.Fatalf("late change escaped final safety check: %+v", result)
			}
			if change == "source-alias" || change == "target-symlink" {
				manifestAssertBody(t, source, []byte("source original"))
			} else if change != "parent-identity" {
				manifestAssertBody(t, path, []byte("old complete"))
			} else {
				manifestAssertBody(t, filepath.Join(parent+".saved", "manifest.json"), []byte("old complete"))
				if result.CandidateCleanup != ManifestCandidateCleanupUnknown || result.ResiduePath == "" {
					t.Fatal("moved parent cleanup facts lost")
				}
			}
		})
	}
}

type manifestFaultCase struct {
	name        string
	inject      func(*manifestFileTarget)
	stage       ManifestFileStage
	reason      ManifestFileReason
	replacement ManifestReplacement
	candidate   ManifestVerification
	installed   ManifestVerification
	cleanup     ManifestCandidateCleanup
}

// full_only: false
func TestManifestFilePreservesFaultVerificationAndCleanupFacts(t *testing.T) {
	failure := errors.New("synthetic native failure")
	cases := []manifestFaultCase{
		{name: "create", stage: ManifestCandidateCreateStage, replacement: ManifestReplacementNotAttempted, cleanup: ManifestCandidateNotCreated, inject: func(t *manifestFileTarget) {
			t.io.create = func(string) (*os.File, error) { return nil, syscall.EACCES }
		}},
		{name: "short-write", stage: ManifestCandidateWriteStage, inject: func(t *manifestFileTarget) {
			t.io.write = func(f *os.File, p []byte) (int, error) { return f.Write(p[:len(p)-1]) }
		}},
		{name: "disk-full", stage: ManifestCandidateWriteStage, inject: func(t *manifestFileTarget) {
			t.io.write = func(*os.File, []byte) (int, error) { return 0, syscall.ENOSPC }
		}},
		{name: "chmod", stage: ManifestCandidateCreateStage, inject: func(t *manifestFileTarget) {
			t.io.chmod = func(*os.File, os.FileMode) error { return failure }
		}},
		{name: "file-sync", stage: ManifestCandidateSyncStage, inject: func(t *manifestFileTarget) {
			t.io.syncFile = func(*os.File) error { return failure }
		}},
		{name: "candidate-corrupt", stage: ManifestCandidateVerifyStage, reason: ManifestVerificationMismatch, candidate: ManifestVerificationFailed, inject: func(t *manifestFileTarget) {
			syncFile := t.io.syncFile
			t.io.syncFile = func(f *os.File) error {
				if _, err := f.WriteAt([]byte("X"), 0); err != nil {
					return err
				}
				return syncFile(f)
			}
		}},
		{name: "candidate-truncated", stage: ManifestCandidateVerifyStage, reason: ManifestVerificationMismatch, candidate: ManifestVerificationFailed, inject: func(t *manifestFileTarget) {
			syncFile := t.io.syncFile
			t.io.syncFile = func(f *os.File) error {
				if err := f.Truncate(1); err != nil {
					return err
				}
				return syncFile(f)
			}
		}},
		{name: "candidate-mode", stage: ManifestCandidateVerifyStage, reason: ManifestVerificationMismatch, candidate: ManifestVerificationFailed, inject: func(t *manifestFileTarget) {
			syncFile := t.io.syncFile
			t.io.syncFile = func(f *os.File) error {
				if err := f.Chmod(0644); err != nil {
					return err
				}
				return syncFile(f)
			}
		}},
		{name: "rename-known-no-effect", stage: ManifestRenameStage, candidate: ManifestVerified, inject: func(t *manifestFileTarget) {
			t.io.rename = func(string, string) (ManifestReplacement, error) { return ManifestNotReplaced, syscall.EACCES }
		}},
		{name: "rename-unknown-no-observed-effect", stage: ManifestRenameStage, replacement: ManifestReplacementUnknown, candidate: ManifestVerified, inject: func(t *manifestFileTarget) {
			t.io.rename = func(string, string) (ManifestReplacement, error) { return ManifestReplacementUnknown, syscall.EIO }
		}},
		{name: "directory-sync", stage: ManifestDirectorySyncStage, replacement: ManifestReplaced, candidate: ManifestVerified, inject: func(t *manifestFileTarget) {
			t.io.syncDir = func(*os.File) error { return failure }
		}},
		{name: "write-and-remove", stage: ManifestCandidateWriteStage, cleanup: ManifestCandidateCleanupFailed, inject: func(t *manifestFileTarget) {
			t.io.write = func(*os.File, []byte) (int, error) { return 0, failure }
			t.io.remove = func(string) error { return syscall.EACCES }
		}},
		{name: "initial-stat", stage: ManifestCandidateCreateStage, cleanup: ManifestCandidateCleanupUnknown, inject: func(t *manifestFileTarget) {
			stat := t.io.stat
			t.io.stat = func(f *os.File, stage ManifestFileStage) (os.FileInfo, error) {
				if stage == ManifestCandidateCreateStage {
					return nil, failure
				}
				return stat(f, stage)
			}
		}},
	}
	for _, stage := range []ManifestFileStage{ManifestCandidateCreateStage, ManifestCandidateVerifyStage, ManifestInstalledVerifyStage} {
		for _, operation := range []string{"open", "stat", "read"} {
			if stage == ManifestCandidateCreateStage && operation != "open" {
				continue
			}
			stage, operation := stage, operation
			row := manifestFaultCase{name: string(stage) + "-" + operation, stage: stage}
			if stage == ManifestInstalledVerifyStage {
				row.replacement, row.candidate = ManifestReplaced, ManifestVerified
			}
			row.inject = func(target *manifestFileTarget) {
				switch operation {
				case "open":
					open := target.io.open
					target.io.open = func(path string, at ManifestFileStage) (*os.File, error) {
						if at == stage {
							return nil, failure
						}
						return open(path, at)
					}
				case "stat":
					stat := target.io.stat
					target.io.stat = func(f *os.File, at ManifestFileStage) (os.FileInfo, error) {
						if at == stage {
							return nil, failure
						}
						return stat(f, at)
					}
				case "read":
					read := target.io.read
					target.io.read = func(f *os.File, p []byte, at ManifestFileStage) (int, error) {
						if at == stage {
							return 0, failure
						}
						return read(f, p, at)
					}
				}
			}
			cases = append(cases, row)
		}
	}
	cases = append(cases,
		manifestFaultCase{name: "directory-open", stage: ManifestPreflightStage, replacement: ManifestReplacementNotAttempted, cleanup: ManifestCandidateNotCreated, inject: func(target *manifestFileTarget) {
			open := target.io.open
			target.io.open = func(path string, stage ManifestFileStage) (*os.File, error) {
				if stage == ManifestPreflightStage {
					return nil, failure
				}
				return open(path, stage)
			}
		}},
		manifestFaultCase{name: "candidate-lstat", stage: ManifestCandidateVerifyStage, inject: func(target *manifestFileTarget) {
			lstat, failed := target.io.lstat, false
			target.io.lstat = func(path string) (os.FileInfo, error) {
				if strings.HasPrefix(filepath.Base(path), manifestCandidatePrefix) && !failed {
					failed = true
					return nil, failure
				}
				return lstat(path)
			}
		}},
		manifestFaultCase{name: "installed-lstat", stage: ManifestInstalledVerifyStage, replacement: ManifestReplaced, candidate: ManifestVerified, inject: func(target *manifestFileTarget) {
			lstat, syncDir, renamed := target.io.lstat, target.io.syncDir, false
			target.io.syncDir = func(f *os.File) error { renamed = true; return syncDir(f) }
			target.io.lstat = func(path string) (os.FileInfo, error) {
				if path == target.path && renamed {
					return nil, failure
				}
				return lstat(path)
			}
		}},
		manifestFaultCase{name: "candidate-extra-byte-at-eof", stage: ManifestCandidateVerifyStage, reason: ManifestVerificationMismatch, candidate: ManifestVerificationFailed, inject: func(target *manifestFileTarget) {
			read := target.io.read
			target.io.read = func(f *os.File, p []byte, stage ManifestFileStage) (int, error) {
				n, err := read(f, p, stage)
				if stage == ManifestCandidateVerifyStage && n == 0 && err == io.EOF {
					p[0] = 'X'
					return 1, nil
				}
				return n, err
			}
		}},
		manifestFaultCase{name: "installed-content-mismatch", stage: ManifestInstalledVerifyStage, reason: ManifestVerificationMismatch, replacement: ManifestReplaced, candidate: ManifestVerified, installed: ManifestVerificationFailed, inject: func(target *manifestFileTarget) {
			read := target.io.read
			target.io.read = func(f *os.File, p []byte, stage ManifestFileStage) (int, error) {
				n, err := read(f, p, stage)
				if stage == ManifestInstalledVerifyStage && n > 0 {
					p[0] ^= 1
				}
				return n, err
			}
		}},
		manifestFaultCase{name: "write-and-cleanup-lstat", stage: ManifestCandidateWriteStage, cleanup: ManifestCandidateCleanupUnknown, inject: func(target *manifestFileTarget) {
			target.io.write = func(*os.File, []byte) (int, error) { return 0, failure }
			lstat := target.io.lstat
			target.io.lstat = func(path string) (os.FileInfo, error) {
				if strings.HasPrefix(filepath.Base(path), manifestCandidatePrefix) {
					return nil, failure
				}
				return lstat(path)
			}
		}},
	)
	for _, closeAt := range []int{1, 2, 3, 4, 5} {
		closeAt := closeAt
		row := manifestFaultCase{name: "close-" + string(rune('0'+closeAt)), stage: ManifestCloseStage}
		if closeAt >= 2 {
			row.candidate = ManifestVerified
		}
		if closeAt >= 3 {
			row.replacement, row.installed = ManifestReplaced, ManifestVerified
		}
		row.inject = func(target *manifestFileTarget) {
			closeFile, count := target.io.close, 0
			target.io.close = func(f *os.File, stage ManifestFileStage) error {
				count++
				err := closeFile(f, stage)
				if count == closeAt {
					return errors.Join(err, failure)
				}
				return err
			}
		}
		cases = append(cases, row)
	}
	for _, row := range cases {
		t.Run(row.name, func(t *testing.T) {
			parent := t.TempDir()
			path := filepath.Join(parent, "manifest.json")
			if err := os.WriteFile(path, []byte("old complete"), 0644); err != nil {
				t.Fatal(err)
			}
			target := manifestTestTarget(t, path)
			row.inject(target)
			closed := make(map[*os.File]bool)
			closeFile := target.io.close
			target.io.close = func(f *os.File, stage ManifestFileStage) error {
				if closed[f] {
					t.Error("descriptor close retried")
				}
				closed[f] = true
				return closeFile(f, stage)
			}
			result := target.install(t.Context(), manifestTestArtifactIdentity(manifestTestFormat), []byte("new complete"), nil)
			want := row
			if want.replacement == "" {
				want.replacement = ManifestNotReplaced
			}
			if want.reason == "" {
				want.reason = ManifestIOFailure
			}
			if want.candidate == "" {
				want.candidate = ManifestVerificationNotObserved
			}
			if want.installed == "" {
				want.installed = ManifestVerificationNotObserved
			}
			if want.cleanup == "" {
				want.cleanup = ManifestCandidateRemoved
				if want.replacement == ManifestReplaced {
					want.cleanup = ManifestCandidateRenamed
				}
			}
			if result.Failure == nil || result.Failure.Stage != want.stage || result.Failure.Reason != want.reason || result.Replacement != want.replacement || result.CandidateVerification != want.candidate || result.InstalledVerification != want.installed || result.CandidateCleanup != want.cleanup || result.NativeCompletion != ManifestNativeIncomplete {
				t.Fatalf("fault facts differ: got=%+v failure=%+v want=%+v", result, result.Failure, want)
			}
			body := []byte("old complete")
			if want.replacement == ManifestReplaced {
				body = []byte("new complete")
			}
			manifestAssertBody(t, path, body)
			paths := manifestCandidates(t, parent)
			if want.cleanup == ManifestCandidateCleanupUnknown || want.cleanup == ManifestCandidateCleanupFailed {
				if len(paths) != 1 || result.ResiduePath != paths[0] {
					t.Fatal("exact residue fact lost")
				}
				if err := os.Remove(paths[0]); err != nil {
					t.Fatal(err)
				}
			} else if len(paths) != 0 || result.ResiduePath != "" {
				t.Fatal("settled cleanup retained residue")
			}
		})
	}
}

// full_only: false
func TestManifestFileKeepsUnknownReplacementAndCandidateOwnership(t *testing.T) {
	for _, effect := range []string{"rename-then-error", "candidate-theft", "same-bytes-competitor"} {
		t.Run(effect, func(t *testing.T) {
			parent := t.TempDir()
			path := filepath.Join(parent, "manifest.json")
			if err := os.WriteFile(path, []byte("old complete"), 0600); err != nil {
				t.Fatal(err)
			}
			target := manifestTestTarget(t, path)
			artifact := []byte("new complete")
			var candidate string
			var candidateInfo os.FileInfo
			live := make(map[*os.File]bool)
			create, open, closeFile := target.io.create, target.io.open, target.io.close
			target.io.create = func(parent string) (*os.File, error) {
				file, err := create(parent)
				if file != nil {
					candidate = file.Name()
					candidateInfo, err = file.Stat()
					live[file] = true
				}
				return file, err
			}
			target.io.open = func(path string, stage ManifestFileStage) (*os.File, error) {
				file, err := open(path, stage)
				if file != nil && candidateInfo != nil {
					info, statErr := file.Stat()
					if statErr == nil && os.SameFile(candidateInfo, info) {
						live[file] = true
					}
				}
				return file, err
			}
			target.io.close = func(file *os.File, stage ManifestFileStage) error {
				err := closeFile(file, stage)
				delete(live, file)
				return err
			}
			switch effect {
			case "rename-then-error":
				rename := target.io.rename
				target.io.rename = func(from, to string) (ManifestReplacement, error) {
					if _, err := rename(from, to); err != nil {
						return ManifestReplacementUnknown, err
					}
					return ManifestReplacementUnknown, syscall.EIO
				}
			case "candidate-theft":
				target.io.write = func(file *os.File, p []byte) (int, error) {
					if err := os.Remove(file.Name()); err != nil {
						return 0, err
					}
					if err := os.WriteFile(file.Name(), []byte("foreign complete"), 0600); err != nil {
						return 0, err
					}
					return 0, syscall.EIO
				}
			case "same-bytes-competitor":
				syncDir := target.io.syncDir
				target.io.syncDir = func(directory *os.File) error {
					if err := syncDir(directory); err != nil {
						return err
					}
					if len(live) != 1 {
						return errors.New("candidate identity was not pinned alone across replacement")
					}
					for file := range live {
						info, err := file.Stat()
						if err != nil || !os.SameFile(candidateInfo, info) {
							return errors.New("candidate pin changed")
						}
					}
					middle := manifestTestTarget(t, path)
					if result := middle.install(t.Context(), manifestTestArtifactIdentity(manifestTestFormat), []byte("middle complete"), nil); result.NativeCompletion != ManifestNativeComplete {
						return errors.New("first competing replacement incomplete")
					}
					last := manifestTestTarget(t, path)
					if result := last.install(t.Context(), manifestTestArtifactIdentity(manifestTestFormat), artifact, nil); result.NativeCompletion != ManifestNativeComplete {
						return errors.New("second competing replacement incomplete")
					}
					return nil
				}
			}
			result := target.install(t.Context(), manifestTestArtifactIdentity(manifestTestFormat), artifact, nil)
			if len(live) != 0 || result.NativeCompletion != ManifestNativeIncomplete || result.Failure == nil {
				t.Fatalf("failed ownership did not settle: %+v", result)
			}
			switch effect {
			case "rename-then-error":
				if result.Replacement != ManifestReplacementUnknown || result.CandidateCleanup != ManifestCandidateCleanupUnknown || result.ResiduePath != candidate || result.InstalledVerification != ManifestVerificationNotObserved || result.Failure.Stage != ManifestRenameStage {
					t.Fatalf("uncertain effect erased: %+v", result)
				}
				manifestAssertBody(t, path, artifact)
			case "candidate-theft":
				if result.Replacement != ManifestNotReplaced || result.CandidateCleanup != ManifestCandidateCleanupUnknown || result.ResiduePath != candidate {
					t.Fatal("foreign candidate ownership claimed")
				}
				manifestAssertBody(t, candidate, []byte("foreign complete"))
				manifestAssertBody(t, path, []byte("old complete"))
				if err := os.Remove(candidate); err != nil {
					t.Fatal(err)
				}
			case "same-bytes-competitor":
				if result.Replacement != ManifestReplaced || result.CandidateCleanup != ManifestCandidateRenamed || result.CandidateVerification != ManifestVerified || result.InstalledVerification != ManifestVerificationFailed || result.Failure.Reason != ManifestCompetingReplacement {
					t.Fatalf("different inode with same bytes accepted: %+v", result)
				}
				manifestAssertBody(t, path, artifact)
			}
			if len(manifestCandidates(t, parent)) != 0 {
				t.Fatal("settled operation left an unexpected candidate")
			}
		})
	}
}

// full_only: false
func TestManifestFileCancellationWaitsForNativeSettlement(t *testing.T) {
	for _, cut := range []string{"before-staging", "after-create", "during-write", "before-rename", "after-rename", "during-installed-read", "during-identity-close"} {
		t.Run(cut, func(t *testing.T) {
			parent := t.TempDir()
			path := filepath.Join(parent, "manifest.json")
			if err := os.WriteFile(path, []byte("old complete"), 0600); err != nil {
				t.Fatal(err)
			}
			target := manifestTestTarget(t, path)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			entered, release := make(chan struct{}), make(chan struct{})
			artifact := []byte("new complete")
			blocked := cut == "during-write" || cut == "during-installed-read" || cut == "during-identity-close"
			if cut == "before-staging" {
				cancel()
			}
			if cut == "after-create" {
				create := target.io.create
				target.io.create = func(parent string) (*os.File, error) { file, err := create(parent); cancel(); return file, err }
			}
			if cut == "during-write" {
				write := target.io.write
				target.io.write = func(file *os.File, p []byte) (int, error) {
					if &p[0] != &artifact[0] || len(p) != len(artifact) {
						return 0, errors.New("artifact backing was copied")
					}
					close(entered)
					<-release
					return write(file, p)
				}
			}
			if cut == "before-rename" {
				checks := 0
				target.checkSource = func(context.Context) error {
					checks++
					if checks == 2 {
						cancel()
					}
					return nil
				}
			}
			if cut == "after-rename" {
				rename := target.io.rename
				target.io.rename = func(from, to string) (ManifestReplacement, error) {
					replacement, err := rename(from, to)
					cancel()
					return replacement, err
				}
			}
			if cut == "during-installed-read" {
				read, once := target.io.read, false
				target.io.read = func(file *os.File, p []byte, stage ManifestFileStage) (int, error) {
					if stage == ManifestInstalledVerifyStage && !once {
						once = true
						close(entered)
						<-release
					}
					return read(file, p, stage)
				}
			}
			if cut == "during-identity-close" {
				open, closeFile := target.io.open, target.io.close
				var identity *os.File
				target.io.open = func(path string, stage ManifestFileStage) (*os.File, error) {
					file, err := open(path, stage)
					if stage == ManifestCandidateCreateStage {
						identity = file
					}
					return file, err
				}
				target.io.close = func(file *os.File, stage ManifestFileStage) error {
					if file == identity {
						close(entered)
						<-release
					}
					return closeFile(file, stage)
				}
			}
			returned := make(chan ManifestDelivery, 1)
			joined := false
			var releaseOnce sync.Once
			releaseIO := func() { releaseOnce.Do(func() { close(release) }) }
			defer func() {
				cancel()
				releaseIO()
				if !joined {
					select {
					case <-returned:
					case <-time.After(5 * time.Second):
						t.Error("failed native test did not positively join")
					}
				}
			}()
			go func() {
				returned <- target.install(ctx, manifestTestArtifactIdentity(manifestTestFormat), artifact, nil)
			}()
			if blocked {
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("native barrier not reached")
				}
				cancel()
				select {
				case <-returned:
					joined = true
					releaseIO()
					t.Fatal("cancellation returned while native I/O still borrowed artifact")
				default:
				}
				releaseIO()
			}
			var result ManifestDelivery
			select {
			case result = <-returned:
				joined = true
			case <-time.After(5 * time.Second):
				t.Fatal("native I/O did not positively join")
			}
			if result.Failure == nil || result.Failure.Reason != ManifestCanceled || result.NativeCompletion != ManifestNativeIncomplete || len(manifestCandidates(t, parent)) != 0 {
				t.Fatalf("canceled native facts differ: %+v", result)
			}
			late := cut == "after-rename" || cut == "during-installed-read" || cut == "during-identity-close"
			if late {
				if result.Replacement != ManifestReplaced || result.CandidateCleanup != ManifestCandidateRenamed {
					t.Fatal("late cancellation erased known rename")
				}
				manifestAssertBody(t, path, artifact)
			} else {
				manifestAssertBody(t, path, []byte("old complete"))
				if cut == "before-staging" {
					if result.Replacement != ManifestReplacementNotAttempted || result.CandidateCleanup != ManifestCandidateNotCreated {
						t.Fatal("pre-staging cancellation created candidate")
					}
				} else if result.Replacement != ManifestNotReplaced {
					t.Fatal("early cancellation replaced destination")
				}
			}
			clear(artifact)
		})
	}
}

// full_only: false
func TestManifestFileReusesBoundedReadbackAndPreservesLateReadFailure(t *testing.T) {
	for _, lateFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "late-installed-read-error"}[lateFailure], func(t *testing.T) {
			parent := t.TempDir()
			path := filepath.Join(parent, "manifest.json")
			target := manifestTestTarget(t, path)
			// This synthetic multi-window body proves sink mechanics, not an encoder maximum.
			artifact := bytes.Repeat([]byte{'a'}, 3*manifestReadbackBytes+9)
			read, write, open, create, closeFile := target.io.read, target.io.write, target.io.open, target.io.create, target.io.close
			var window *byte
			candidateReads, installedReads := 0, 0
			live := make(map[*os.File]bool)
			target.io.create = func(parent string) (*os.File, error) {
				f, err := create(parent)
				if f != nil {
					live[f] = true
				}
				return f, err
			}
			target.io.open = func(path string, stage ManifestFileStage) (*os.File, error) {
				f, err := open(path, stage)
				if f != nil {
					live[f] = true
				}
				return f, err
			}
			target.io.close = func(f *os.File, stage ManifestFileStage) error {
				err := closeFile(f, stage)
				delete(live, f)
				return err
			}
			target.io.write = func(f *os.File, p []byte) (int, error) {
				if &p[0] != &artifact[0] || len(p) != len(artifact) {
					return 0, errors.New("artifact write uses another backing")
				}
				return write(f, p)
			}
			target.io.read = func(f *os.File, p []byte, stage ManifestFileStage) (int, error) {
				if len(p) == 0 || cap(p) > manifestReadbackBytes || len(p) > manifestReadbackBytes {
					return 0, errors.New("unbounded readback")
				}
				if window == nil {
					window = &p[0]
				} else if window != &p[0] {
					return 0, errors.New("readback allocated another window")
				}
				if stage == ManifestCandidateVerifyStage {
					candidateReads++
				} else {
					installedReads++
					if lateFailure && installedReads == 2 {
						return 0, syscall.EIO
					}
				}
				return read(f, p, stage)
			}
			result := target.install(t.Context(), manifestTestArtifactIdentity(manifestTestFormat), artifact, nil)
			if len(live) != 0 || candidateReads < 4 || installedReads < 2 || result.CandidateVerification != ManifestVerified || result.Replacement != ManifestReplaced || result.CandidateCleanup != ManifestCandidateRenamed {
				t.Fatalf("bounded readback ownership differs: %+v", result)
			}
			if lateFailure {
				if result.NativeCompletion != ManifestNativeIncomplete || result.InstalledVerification != ManifestVerificationNotObserved || result.Failure == nil || result.Failure.Stage != ManifestInstalledVerifyStage {
					t.Fatal("late I/O incorrectly became a verification verdict")
				}
			} else if result.NativeCompletion != ManifestNativeComplete || result.InstalledVerification != ManifestVerified || result.Failure != nil {
				t.Fatalf("bounded readback failed: %+v", result)
			}
			manifestAssertBody(t, path, artifact)
			clear(artifact)
		})
	}
}

// full_only: false
func TestManifestFileRetainsBuildAndFormatInDeliveryFacts(t *testing.T) {
	for _, profile := range []string{manifestTestFormat, "private-format/v2"} {
		t.Run(profile, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.json")
			target := manifestTestTarget(t, path)
			body := []byte("already verified artifact")
			got := target.install(t.Context(), manifestTestArtifactIdentity(profile), body, nil)
			if got.NativeCompletion != ManifestNativeComplete || got.Artifact == nil || got.Artifact.FormatContractID != profile || got.Artifact.Length != uint64(len(body)) || got.Artifact.Digest != contract.Hash(body) {
				t.Fatal("delivery stamped another format", got)
			}
			manifestAssertBody(t, path, body)
		})
	}
	path := filepath.Join(t.TempDir(), "unknown.json")
	target := manifestTestTarget(t, path)
	got := target.install(t.Context(), ManifestArtifact{FormatContractID: "unlisted-format/v1"}, []byte("artifact"), nil)
	if got.Artifact != nil || got.NativeCompletion == ManifestNativeComplete || got.CandidateCleanup != ManifestCandidateNotCreated {
		t.Fatal("missing build identity reached native staging")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing build identity created destination", err)
	}
}

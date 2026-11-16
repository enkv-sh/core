package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	records "enkv.sh/core/internal/testrecords"
	"time"
)

// full_only: false
func TestToolDirectoriesPreserveExistingSourceAndSharePreparedDirectories(t *testing.T) {
	root, locks := toolDirectoryFixture(t)
	if err := os.MkdirAll(filepath.Join(root, "core/internal/existing"), 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "core/internal/existing/source.go")
	if err := os.WriteFile(source, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	cleanup, err := prepareToolDirectories(context.Background(), locks, root)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	second, err := prepareToolDirectories(ctx, locks, root)
	if err != nil {
		if closeErr := cleanup.Release(context.Background(), true); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatalf("nested read-only overlay use blocked: %v", err)
	}
	finished := make(chan error, 1)
	go func() { finished <- cleanup.Release(context.Background(), true) }()
	select {
	case err := <-finished:
		if closeErr := second.Release(context.Background(), true); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatalf("cleanup did not wait for the active nested user: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	if err := second.Release(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"testmain", "testrecords", "testcatalog"} {
		if _, err := os.Lstat(filepath.Join(root, "core/internal", name)); !os.IsNotExist(err) {
			t.Fatal("temporary tool directory remains")
		}
	}
	if body, err := os.ReadFile(source); err != nil || string(body) != "preserve" {
		t.Fatal("existing source changed")
	}
}

// full_only: false
func TestToolDirectoryOwnerCancellationStillJoinsOtherUser(t *testing.T) {
	root, locks := toolDirectoryFixture(t)
	if err := os.Mkdir(filepath.Join(root, "core"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	owner, err := prepareToolDirectories(ctx, locks, root)
	if err != nil {
		t.Fatal(err)
	}
	other, err := prepareToolDirectories(context.Background(), locks, root)
	if err != nil {
		if err := owner.Release(context.Background(), true); err != nil {
			t.Error(err)
		}
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- owner.Release(context.Background(), true) }()
	select {
	case err := <-finished:
		if err := other.Release(context.Background(), true); err != nil {
			t.Error(err)
		}
		t.Fatalf("creator did not wait for the other user: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-finished:
		if err := other.Release(context.Background(), true); err != nil {
			t.Error(err)
		}
		t.Fatalf("canceled creator did not wait for the other user: %v", err)
	case <-time.After(31 * time.Second):
	}
	if err := other.Release(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("creator cleanup after other user exited: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("creator did not finish cleanup after other user exited")
	}
	if _, err := os.Stat(filepath.Join(root, "core/internal")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("creator retained temporary directories after both users exited: %v", err)
	}
}

// full_only: false
func TestToolDirectoriesRefuseSymlinkAndPreserveNewFiles(t *testing.T) {
	root, locks := toolDirectoryFixture(t)
	if err := os.Mkdir(filepath.Join(root, "core"), 0700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "core/internal")); err != nil {
		t.Fatal(err)
	}
	if cleanup, err := prepareToolDirectories(context.Background(), locks, root); err == nil {
		if err := cleanup.Release(context.Background(), true); err != nil {
			t.Error(err)
		}
		t.Fatal("symlink admitted for tool preparation")
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Fatal("refused preparation changed the symlink destination")
	}
	if err := os.Remove(filepath.Join(root, "core/internal")); err != nil {
		t.Fatal(err)
	}
	cleanup, err := prepareToolDirectories(context.Background(), locks, root)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "core/internal/testmain/preserve.go")
	if err := os.WriteFile(path, []byte("new source"), 0600); err != nil {
		t.Fatal(err)
	}
	if cleanup.Release(context.Background(), true) == nil {
		t.Fatal("cleanup did not report a nonempty directory")
	}
	if body, err := os.ReadFile(path); err != nil || string(body) != "new source" {
		t.Fatal("cleanup removed new source")
	}
}

// full_only: false
func TestToolDirectoryCleanupPreservesReplacementFile(t *testing.T) {
	root, locks := toolDirectoryFixture(t)
	if err := os.Mkdir(filepath.Join(root, "core"), 0700); err != nil {
		t.Fatal(err)
	}
	cleanup, err := prepareToolDirectories(context.Background(), locks, root)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "core/internal/testmain")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if cleanup.Release(context.Background(), true) == nil {
		t.Fatal("changed directory identity was not reported")
	}
	if body, err := os.ReadFile(path); err != nil || string(body) != "replacement" {
		t.Fatal("replacement file was removed")
	}
}

// full_only: false
func TestToolDirectoriesRetainUnjoinedProcessStateAndReleaseLock(t *testing.T) {
	root, locks := toolDirectoryFixture(t)
	if err := os.Mkdir(filepath.Join(root, "core"), 0700); err != nil {
		t.Fatal(err)
	}
	cleanup, err := prepareToolDirectories(context.Background(), locks, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanup.Release(context.Background(), false); err == nil {
		t.Fatal("unsettled group retained no cleanup error")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	second, err := prepareToolDirectories(ctx, locks, root)
	if err != nil {
		t.Fatalf("unsettled group left the checkout lock held: %v", err)
	}
	if err := second.Release(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"testmain", "testrecords", "testcatalog"} {
		if info, err := os.Stat(filepath.Join(root, "core/internal", name)); err != nil || !info.IsDir() {
			t.Fatal("a later invocation removed retained directories it did not create")
		}
	}
}

// full_only: false
func TestUnjoinedNestedUserPreventsOwnerCleanup(t *testing.T) {
	root, locks := toolDirectoryFixture(t)
	if err := os.Mkdir(filepath.Join(root, "core"), 0700); err != nil {
		t.Fatal(err)
	}
	owner, err := prepareToolDirectories(context.Background(), locks, root)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	nested, err := prepareToolDirectories(ctx, locks, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := nested.Release(context.Background(), false); err == nil {
		t.Error("unjoined nested user reported success")
	}
	if err := owner.Release(context.Background(), true); err == nil {
		t.Error("owner did not report retained unjoined state")
	}
	for _, name := range []string{"testmain", "testrecords", "testcatalog"} {
		if info, err := os.Stat(filepath.Join(root, "core/internal", name)); err != nil || !info.IsDir() {
			t.Fatal("owner removed a directory still used by an unjoined nested process")
		}
	}
}

func toolDirectoryFixture(t *testing.T) (string, *resourceLocks) {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "checkout")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	locks, err := openResourceLocks(filepath.Join(parent, "resources"))
	if err != nil {
		t.Fatal(err)
	}
	return root, locks
}

// full_only: false
func TestToolDirectoryLockIgnoresTemporaryDirectory(t *testing.T) {
	root, locks := toolDirectoryFixture(t)
	if err := os.Mkdir(filepath.Join(root, "core"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", t.TempDir())
	first, err := prepareToolDirectories(t.Context(), locks, root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := first.ReleaseAfterSettlement(context.Background()); err != nil {
			t.Error(err)
		}
	})
	before, err := first.lock.Stat()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", t.TempDir())
	second, err := prepareToolDirectories(t.Context(), locks, root)
	if err != nil {
		t.Fatal(err)
	}
	after, err := second.lock.Stat()
	if err != nil || !records.SameLocalFile(before, after) {
		t.Fatal("temporary directory changed lock inode", err)
	}
	if err := second.Release(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if err := first.Release(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	current, err := os.Stat(filepath.Join(locks.directory, "tool-"+fmt.Sprintf("%x", sha256.Sum256([]byte(root)))+".lock"))
	if err != nil || !records.SameLocalFile(before, current) {
		t.Fatal("release removed or replaced lock inode", err)
	}
}

// full_only: false
func TestToolDirectoryCleanupDeadlinePreservesCreatedPaths(t *testing.T) {
	root, locks := toolDirectoryFixture(t)
	if err := os.Mkdir(filepath.Join(root, "core"), 0700); err != nil {
		t.Fatal(err)
	}
	owner, err := prepareToolDirectories(t.Context(), locks, root)
	if err != nil {
		t.Fatal(err)
	}
	other, err := prepareToolDirectories(t.Context(), locks, root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := other.ReleaseAfterSettlement(context.Background()); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if err := owner.Release(ctx, true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cleanup did not honor shared tail", err)
	}
	if _, err := os.Stat(filepath.Join(root, "core/internal/testmain")); err != nil {
		t.Fatal("deadline removed owned path", err)
	}
}

// full_only: false
func TestToolDirectoryFailedVetoRetainsLeaseUntilSettlement(t *testing.T) {
	root, locks := toolDirectoryFixture(t)
	if err := os.Mkdir(filepath.Join(root, "core"), 0700); err != nil {
		t.Fatal(err)
	}
	owner, err := prepareToolDirectories(t.Context(), locks, root)
	if err != nil {
		t.Fatal(err)
	}
	// A real read-only descriptor preserves SH ownership but refuses WriteAt.
	readonly, err := os.Open(owner.lock.Name())
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(readonly.Fd()), syscall.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	if err := owner.lock.Close(); err != nil {
		t.Fatal(err)
	}
	owner.lock = readonly
	t.Cleanup(func() {
		if err := owner.ReleaseAfterSettlement(context.Background()); err != nil {
			t.Error(err)
		}
	})
	if err := owner.Release(t.Context(), false); err == nil {
		t.Fatal("failed veto was silent")
	}
	probe, err := os.OpenFile(readonly.Name(), os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := probe.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); !errors.Is(err, syscall.EWOULDBLOCK) {
		t.Fatal("failed veto released protective lease", err)
	}
	if err := owner.Release(t.Context(), true); err == nil {
		t.Fatal("boolean retry replaced positive settlement")
	}
	if err := owner.ReleaseAfterSettlement(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal("settled owner retained descriptor", err)
	}
	if _, err := os.Stat(filepath.Join(root, "core/internal/testmain")); err != nil {
		t.Fatal("settlement close removed paths", err)
	}
}

// full_only: false
func TestBorrowedToolPhaseReportsJoinsWithoutOwningCleanup(t *testing.T) {
	root, locks := toolDirectoryFixture(t)
	if err := os.Mkdir(filepath.Join(root, "core"), 0700); err != nil {
		t.Fatal(err)
	}
	actual, err := prepareToolDirectories(t.Context(), locks, root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := actual.ReleaseAfterSettlement(context.Background()); err != nil {
			t.Error(err)
		}
	})
	ctx, phase, err := withBorrowedToolDirectoryPhase(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	report, found, err := borrowToolDirectoryPhase(ctx, root)
	if err != nil || !found {
		t.Fatal("borrowed phase unavailable", err)
	}
	report(false)
	if err := phase.Release(t.Context(), true); err == nil {
		t.Fatal("unjoined borrower became readiness")
	}
	if err := phase.ReleaseAfterSettlement(t.Context()); err == nil {
		t.Fatal("borrowed phase claimed physical authority")
	}
	if err := phase.reopenBorrowed(); err == nil {
		t.Fatal("unjoined borrower admitted another resource phase")
	}
	probe, err := locks.openFile(filepath.Base(actual.lock.Name()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := probe.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); !errors.Is(err, syscall.EWOULDBLOCK) {
		t.Fatal("borrow release closed native lease", err)
	}
	if _, err := os.Stat(filepath.Join(root, "core/internal/testmain")); err != nil {
		t.Fatal("borrow release removed physical path", err)
	}
	for _, active := range []bool{false, true} {
		child, next, err := withBorrowedToolDirectoryPhase(t.Context(), root)
		if err != nil {
			t.Fatal(err)
		}
		if err := next.reopenBorrowed(); err == nil {
			t.Fatal("active phase reopened without release")
		}
		report, found, err := borrowToolDirectoryPhase(child, root)
		if err != nil || !found {
			t.Fatal(err)
		}
		if active {
			if err := next.Release(t.Context(), true); err == nil {
				t.Fatal("active command admitted a resource transition")
			}
			report(true)
			if err := next.reopenBorrowed(); err == nil {
				t.Fatal("late completion repaired an unsettled phase")
			}
			continue
		}
		report(true)
		if err := next.Release(t.Context(), true); err != nil {
			t.Fatal(err)
		}
		if err := next.reopenBorrowed(); err != nil {
			t.Fatal("joined phase did not reopen", err)
		}
		report, found, err = borrowToolDirectoryPhase(child, root)
		if err != nil || !found {
			t.Fatal("captured context did not see the new phase", err)
		}
		report(true)
		if err := next.Release(t.Context(), true); err != nil {
			t.Fatal(err)
		}
	}
}

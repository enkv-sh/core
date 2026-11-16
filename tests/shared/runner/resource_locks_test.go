package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	records "enkv.sh/core/internal/testrecords"
)

func resourceLockFixture(t *testing.T) *resourceLocks {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	locks, err := openResourceLocks(filepath.Join(parent, "resources"))
	if err != nil {
		t.Fatal(err)
	}
	return locks
}

// full_only: false
func TestResourceMachineSharedOwnersAndExclusiveWait(t *testing.T) {
	locks := resourceLockFixture(t)
	first, err := locks.acquireMachine(t.Context(), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := first.Close(); err != nil {
			t.Error(err)
		}
	})
	second, err := locks.acquireMachine(t.Context(), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := second.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	completed := false
	done := make(chan *resourceLease, 1)
	failed := make(chan error, 1)
	t.Cleanup(func() {
		cancel()
		if !completed {
			select {
			case lease := <-done:
				if err := lease.Close(); err != nil {
					t.Error(err)
				}
			case <-failed:
			case <-time.After(time.Second):
				t.Error("exclusive lock waiter did not join")
			}
		}
	})
	go func() {
		lease, err := locks.acquireMachine(ctx, true)
		if err != nil {
			failed <- err
			return
		}
		done <- lease
	}()
	select {
	case lease := <-done:
		completed = true
		lease.Close()
		t.Fatal("exclusive owner overlapped shared owners")
	case err := <-failed:
		completed = true
		t.Fatal(err)
	case <-time.After(30 * time.Millisecond):
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case lease := <-done:
		completed = true
		lease.Close()
		t.Fatal("exclusive owner overlapped second shared owner")
	case err := <-failed:
		completed = true
		t.Fatal(err)
	case <-time.After(30 * time.Millisecond):
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case lease := <-done:
		completed = true
		blocked, stop := context.WithTimeout(t.Context(), 30*time.Millisecond)
		shared, sharedErr := locks.acquireMachine(blocked, false)
		stop()
		if shared != nil {
			if err := shared.Close(); err != nil {
				t.Error(err)
			}
		}
		if !errors.Is(sharedErr, context.DeadlineExceeded) {
			t.Error("normal owner entered beside exclusive owner", sharedErr)
		}
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
	case err := <-failed:
		completed = true
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal("exclusive waiter did not enter", ctx.Err())
	}
}

// full_only: false
func TestResourceLiveWaitCancellationDoesNotBlockMachine(t *testing.T) {
	locks := resourceLockFixture(t)
	live, err := locks.acquireLive(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := live.Close(); err != nil {
			t.Error(err)
		}
	})
	machine, err := locks.acquireMachine(t.Context(), false)
	if err != nil {
		t.Fatal("live ownership blocked normal machine acquisition", err)
	}
	t.Cleanup(func() {
		if err := machine.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if lease, err := locks.acquireLive(ctx); !errors.Is(err, context.DeadlineExceeded) {
		if lease != nil {
			lease.Close()
		}
		t.Fatal("second live owner did not wait for cancellation", err)
	}
	if err := live.Close(); err != nil {
		t.Fatal(err)
	}
	later, err := locks.acquireLive(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := later.Close(); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestResourceLeaseKeepsFileIdentityAndClosesOnExec(t *testing.T) {
	locks := resourceLockFixture(t)
	lease, err := locks.acquireMachine(t.Context(), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := lease.Close(); err != nil {
			t.Error(err)
		}
	})
	before, err := lease.file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	descriptor := strconv.Itoa(int(lease.file.Fd()))
	command := exec.Command("/bin/sh", "-c", "test ! -e /dev/fd/"+descriptor)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("resource descriptor survived exec: %v %s", err, output)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	later, err := locks.acquireMachine(t.Context(), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := later.Close(); err != nil {
			t.Error(err)
		}
	})
	after, err := later.file.Stat()
	if err != nil || !records.SameLocalFile(before, after) {
		t.Fatal("release changed lock inode", err)
	}
}

// full_only: false
func TestResourceLockRefusesSymlinkAndDirectoryReplacement(t *testing.T) {
	t.Run("file_symlink", func(t *testing.T) {
		locks := resourceLockFixture(t)
		target := filepath.Join(t.TempDir(), "outside")
		if err := os.WriteFile(target, []byte("preserve"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(locks.directory, "machine.lock")); err != nil {
			t.Fatal(err)
		}
		if lease, err := locks.acquireMachine(t.Context(), true); err == nil {
			lease.Close()
			t.Fatal("lock symlink admitted")
		}
		if body, err := os.ReadFile(target); err != nil || string(body) != "preserve" {
			t.Fatal("outside lock target changed", err)
		}
	})
	t.Run("directory_replacement", func(t *testing.T) {
		locks := resourceLockFixture(t)
		if err := os.Rename(locks.directory, locks.directory+".original"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(locks.directory, 0700); err != nil {
			t.Fatal(err)
		}
		if lease, err := locks.acquireMachine(t.Context(), true); err == nil {
			lease.Close()
			t.Fatal("replacement directory admitted")
		}
		entries, err := os.ReadDir(locks.directory)
		if err != nil || len(entries) != 0 {
			t.Fatal("replacement directory changed", err)
		}
	})
}

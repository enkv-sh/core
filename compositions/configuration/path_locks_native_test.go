//go:build darwin || linux

package configuration

import (
	"errors"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"syscall"
	"testing"
)

// full_only: false
func TestPathLockAcquisitionFailureReleasesOwnedDescriptors(t *testing.T) {
	// Cleanup must be complete before a finalizer can release a leaked owner.
	priorGC := debug.SetGCPercent(-1)
	t.Cleanup(func() { debug.SetGCPercent(priorGC) })
	for _, mode := range []struct {
		name           string
		shared, create bool
	}{
		{name: "reader", shared: true},
		{name: "recovery"},
		{name: "writer", create: true},
	} {
		for _, failure := range []string{"after-open", "after-lock"} {
			t.Run(mode.name+"-"+failure, func(t *testing.T) {
				directory, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				lockDirectory := filepath.Join(directory, ".enkv-locks")
				if err := os.Mkdir(lockDirectory, 0700); err != nil {
					t.Fatal(err)
				}
				paths := []string{filepath.Join(directory, "first"), filepath.Join(directory, "second")}
				identities := make([]syscall.Stat_t, len(paths))
				for i, path := range paths {
					name := filepath.Join(lockDirectory, filepath.Base(path))
					if err := os.WriteFile(name, nil, 0600); err != nil {
						t.Fatal(err)
					}
					if err := syscall.Stat(name, &identities[i]); err != nil {
						t.Fatal(err)
					}
				}
				if identities[0].Dev != identities[1].Dev || identities[0].Ino == identities[1].Ino {
					t.Fatal("fixture requires two distinct lock inodes on one device")
				}
				if identities[0].Ino > identities[1].Ino {
					paths[0], paths[1] = paths[1], paths[0]
					identities[0], identities[1] = identities[1], identities[0]
				}
				firstLock := filepath.Join(lockDirectory, filepath.Base(paths[0]))
				secondLock := filepath.Join(lockDirectory, filepath.Base(paths[1]))
				selected := []string{paths[0], "relative-refusal"}
				wantError, wantSecondDescriptors := ErrEdit, 0
				if failure == "after-lock" {
					blocker, err := os.OpenFile(secondLock, os.O_RDWR, 0)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if err := blocker.Close(); err != nil {
							t.Error(err)
						}
					})
					if err := syscall.Flock(int(blocker.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
						t.Fatal(err)
					}
					selected = paths
					wantError, wantSecondDescriptors = ErrEditLocked, 1
				}

				set, err := openPathLocks(selected, mode.shared, mode.create)
				if set != nil {
					t.Cleanup(func() {
						if err := set.close(); err != nil {
							t.Error(err)
						}
					})
				}
				if set != nil || !errors.Is(err, wantError) {
					t.Fatalf("failed acquisition must return no owner and its refusal: owner=%t error=%v", set != nil, err)
				}
				if count := nativeLockDescriptorCount(t, identities[0]); count != 0 {
					t.Errorf("failed acquisition retained %d first-path descriptors", count)
				}
				if count := nativeLockDescriptorCount(t, identities[1]); count != wantSecondDescriptors {
					t.Errorf("second-path descriptor count is %d, want only %d foreign owner", count, wantSecondDescriptors)
				}
				probeNativeLock(t, firstLock, false)
				if failure == "after-lock" {
					probeNativeLock(t, secondLock, true)
				}
			})
		}
	}
}

func nativeLockDescriptorCount(t *testing.T, identity syscall.Stat_t) int {
	t.Helper()
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		var current syscall.Stat_t
		if err := syscall.Fstat(fd, &current); err != nil {
			// ReadDir has already closed its own listed descriptor.
			if errors.Is(err, syscall.EBADF) {
				continue
			}
			t.Fatal(err)
		}
		if current.Dev == identity.Dev && current.Ino == identity.Ino {
			count++
		}
	}
	return count
}

func probeNativeLock(t *testing.T, path string, wantBlocked bool) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	lockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if wantBlocked {
		if !errors.Is(lockErr, syscall.EWOULDBLOCK) {
			t.Errorf("failed acquisition changed the foreign lock owner: %v", lockErr)
		}
	} else if lockErr != nil {
		t.Errorf("failed acquisition retained an earlier lock: %v", lockErr)
	}
	if err := file.Close(); err != nil {
		t.Error(err)
	}
}

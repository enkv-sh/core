package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	records "enkv.sh/core/internal/testrecords"
)

const fileLockPollInterval = 20 * time.Millisecond

type resourceLocks struct {
	directory string
	identity  os.FileInfo
}

type resourceLease struct {
	mu   sync.Mutex
	file *os.File
}

type resourceLocksContextKey struct{}

func withResourceLocks(ctx context.Context, locks *resourceLocks) context.Context {
	return context.WithValue(ctx, resourceLocksContextKey{}, locks)
}

func resourceLocksFromContext(ctx context.Context) (*resourceLocks, error) {
	if value := ctx.Value(resourceLocksContextKey{}); value != nil {
		locks, ok := value.(*resourceLocks)
		if !ok || locks == nil {
			return nil, errors.New("resource lock owner unavailable")
		}
		return locks, nil
	}
	return defaultResourceLocks()
}

func defaultResourceLocks() (*resourceLocks, error) {
	parent, err := filepath.EvalSymlinks("/var/tmp")
	if err != nil {
		return nil, err
	}
	return openResourceLocks(filepath.Join(parent, fmt.Sprintf("enkv-test-resources-%d", os.Getuid())))
}

func openResourceLocks(directory string) (*resourceLocks, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("resource lock directory refused")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(directory))
	if err != nil || parent != filepath.Dir(directory) {
		return nil, errors.New("resource lock parent refused")
	}
	if err := os.Mkdir(directory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !ownedLockFile(info, true, 0700) {
		return nil, errors.New("resource lock directory owner or mode refused")
	}
	return &resourceLocks{directory: directory, identity: info}, nil
}

func ownedLockFile(info os.FileInfo, directory bool, mode os.FileMode) bool {
	if info == nil || info.IsDir() != directory || info.Mode().Perm() != mode ||
		!directory && !info.Mode().IsRegular() {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Getuid())
}

func (locks *resourceLocks) openFile(name string) (*os.File, error) {
	if locks == nil || filepath.Base(name) != name || name == "." || name == ".." {
		return nil, errors.New("resource lock file refused")
	}
	current, err := os.Lstat(locks.directory)
	if err != nil || !ownedLockFile(current, true, 0700) || !records.SameLocalFile(locks.identity, current) {
		return nil, errors.New("resource lock directory changed")
	}
	path := filepath.Join(locks.directory, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	info, statErr := file.Stat()
	entry, entryErr := os.Lstat(path)
	if statErr != nil || entryErr != nil || !ownedLockFile(info, false, 0600) ||
		!records.SameLocalFile(info, entry) {
		return nil, errors.Join(errors.New("resource lock file owner or identity refused"), statErr, entryErr, file.Close())
	}
	return file, nil
}

func (locks *resourceLocks) acquireMachine(ctx context.Context, exclusive bool) (*resourceLease, error) {
	mode := syscall.LOCK_SH
	if exclusive {
		mode = syscall.LOCK_EX
	}
	return locks.acquire(ctx, "machine.lock", mode)
}

func (locks *resourceLocks) acquireLive(ctx context.Context) (*resourceLease, error) {
	return locks.acquire(ctx, "live.lock", syscall.LOCK_EX)
}

func (locks *resourceLocks) acquire(ctx context.Context, name string, mode int) (*resourceLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := locks.openFile(name)
	if err != nil {
		return nil, err
	}
	if err := waitFileLock(ctx, file, mode); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return &resourceLease{file: file}, nil
}

func (lease *resourceLease) Close() error {
	if lease == nil {
		return nil
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.file == nil {
		return nil
	}
	file := lease.file
	lease.file = nil
	return file.Close()
}

func waitFileLock(ctx context.Context, file *os.File, mode int) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := syscall.Flock(int(file.Fd()), mode|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return fmt.Errorf("resource lock failed: %w", err)
		}
		timer := time.NewTimer(fileLockPollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

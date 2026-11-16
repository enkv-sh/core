package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	records "enkv.sh/core/internal/testrecords"
)

type toolDirectoryLease struct {
	mu       sync.Mutex
	lock     *os.File
	created  []toolDirectoryPath
	retained bool
}

type toolDirectoryPath struct {
	path string
	info os.FileInfo
}

type toolDirectoryPhase struct {
	mu       sync.Mutex
	root     string
	lease    *toolDirectoryLease
	joined   bool
	released bool
	active   int
}

type toolDirectoryPhaseContextKey struct{}

func toolPackageDirectories() []string {
	return []string{"core/internal/testmain", "core/internal/testrecords", "core/internal/testcatalog"}
}

func canonicalToolRoot(root string) (string, error) {
	root, err := filepath.EvalSymlinks(root)
	if err != nil || !filepath.IsAbs(root) {
		return "", errors.New("test tool root unavailable")
	}
	return root, nil
}

func prepareToolDirectoryPhase(ctx context.Context, locks *resourceLocks, root string) (context.Context, *toolDirectoryPhase, error) {
	root, err := canonicalToolRoot(root)
	if err != nil {
		return ctx, nil, err
	}
	lease, err := prepareToolDirectories(ctx, locks, root)
	if err != nil {
		return ctx, nil, err
	}
	phase := &toolDirectoryPhase{root: root, lease: lease, joined: true}
	return context.WithValue(ctx, toolDirectoryPhaseContextKey{}, phase), phase, nil
}

// Only the direct runner composition installs borrowing for native-owned leases.
func withBorrowedToolDirectoryPhase(ctx context.Context, root string) (context.Context, *toolDirectoryPhase, error) {
	root, err := canonicalToolRoot(root)
	if err != nil {
		return ctx, nil, err
	}
	phase := &toolDirectoryPhase{root: root, joined: true}
	return context.WithValue(ctx, toolDirectoryPhaseContextKey{}, phase), phase, nil
}

func borrowToolDirectoryPhase(ctx context.Context, root string) (func(bool), bool, error) {
	phase, _ := ctx.Value(toolDirectoryPhaseContextKey{}).(*toolDirectoryPhase)
	if phase == nil {
		return nil, false, nil
	}
	root, err := canonicalToolRoot(root)
	if err != nil {
		return nil, true, err
	}
	phase.mu.Lock()
	defer phase.mu.Unlock()
	if phase.root != root || phase.released {
		return nil, true, errors.New("test tool phase owner differs or is released")
	}
	phase.active++
	reported := false
	return func(joined bool) {
		phase.mu.Lock()
		defer phase.mu.Unlock()
		if reported {
			phase.joined = false
			return
		}
		reported = true
		phase.active--
		phase.joined = phase.joined && joined
	}, true, nil
}

func (phase *toolDirectoryPhase) Release(ctx context.Context, joined bool) error {
	phase.mu.Lock()
	defer phase.mu.Unlock()
	if phase.released {
		return errors.New("test tool phase already released")
	}
	phase.released = true
	phase.joined = phase.joined && joined && phase.active == 0
	if phase.lease != nil {
		return phase.lease.Release(ctx, phase.joined)
	}
	if !phase.joined {
		return errors.New("test tool phase has an unsettled consumer")
	}
	return nil
}

func (phase *toolDirectoryPhase) reopenBorrowed() error {
	phase.mu.Lock()
	defer phase.mu.Unlock()
	if phase.lease != nil || !phase.released || !phase.joined || phase.active != 0 {
		return errors.New("test tool phase cannot reopen before settlement")
	}
	phase.released = false
	return nil
}

func (phase *toolDirectoryPhase) ReleaseAfterSettlement(ctx context.Context) error {
	phase.mu.Lock()
	defer phase.mu.Unlock()
	if phase.lease == nil {
		return errors.New("borrowed test tool phase has no physical lease")
	}
	return phase.lease.ReleaseAfterSettlement(ctx)
}

// Each actual lease owns only the empty physical directories it created.
func prepareToolDirectories(ctx context.Context, locks *resourceLocks, root string) (*toolDirectoryLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := canonicalToolRoot(root)
	if err != nil {
		return nil, err
	}
	id := sha256.Sum256([]byte(root))
	lock, err := locks.openFile(fmt.Sprintf("tool-%x.lock", id[:]))
	if err != nil {
		return nil, fmt.Errorf("test tool lock unavailable: %w", err)
	}
	lease := &toolDirectoryLease{lock: lock}
	if err := waitFileLock(ctx, lock, syscall.LOCK_SH); err != nil {
		return nil, errors.Join(err, lease.close())
	}
	directories := append([]string{"core", "core/internal"}, toolPackageDirectories()...)
	missing, err := toolDirectoriesMissing(root, directories)
	if err != nil {
		return nil, errors.Join(err, lease.Release(ctx, true))
	}
	if !missing {
		return lease, nil
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
		return nil, errors.Join(err, lease.close())
	}
	for {
		err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.Join(err, lease.close())
		}
		// A shared caller may already have supplied the physical directories.
		if err := waitFileLock(ctx, lock, syscall.LOCK_SH); err != nil {
			return nil, errors.Join(err, lease.close())
		}
		missing, err := toolDirectoriesMissing(root, directories)
		if err != nil {
			return nil, errors.Join(err, lease.Release(ctx, true))
		}
		if !missing {
			return lease, nil
		}
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
			return nil, errors.Join(err, lease.close())
		}
		timer := time.NewTimer(fileLockPollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, errors.Join(ctx.Err(), lease.close())
		case <-timer.C:
		}
	}
	for _, relative := range directories {
		path := filepath.Join(root, relative)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) && relative != "core" {
			if err := os.Mkdir(path, 0700); err != nil {
				return nil, errors.Join(err, lease.Release(ctx, true))
			}
			info, err := os.Lstat(path)
			if err != nil || !info.IsDir() {
				return nil, errors.Join(errors.New("test tool directory changed during preparation"), lease.Release(ctx, true))
			}
			lease.created = append(lease.created, toolDirectoryPath{path, info})
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.Join(errors.New("test tool directory refused"), lease.Release(ctx, true))
		}
	}
	if err := waitFileLock(ctx, lock, syscall.LOCK_SH); err != nil {
		return nil, errors.Join(err, lease.Release(ctx, true))
	}
	return lease, nil
}

func (lease *toolDirectoryLease) close() error {
	if lease.lock == nil {
		return nil
	}
	lock := lease.lock
	lease.lock = nil
	return lock.Close()
}

func (lease *toolDirectoryLease) Release(ctx context.Context, joined bool) error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.lock == nil {
		return nil
	}
	if lease.retained {
		return errors.New("test tool lease requires positive consumer settlement")
	}
	if !joined {
		failure := errors.New("test tool directories retained for an unsettled process group")
		n, err := lease.lock.WriteAt([]byte{1}, 0)
		if err == nil && n != 1 {
			err = io.ErrShortWrite
		}
		if err != nil {
			lease.retained = true
			return errors.Join(failure, fmt.Errorf("test tool retention marker failed: %w", err))
		}
		return errors.Join(failure, lease.close())
	}
	if len(lease.created) != 0 {
		if err := syscall.Flock(int(lease.lock.Fd()), syscall.LOCK_UN); err != nil {
			return errors.Join(err, lease.close())
		}
		if err := waitFileLock(ctx, lease.lock, syscall.LOCK_EX); err != nil {
			return errors.Join(errors.New("test tool directory cleanup lock failed"), err, lease.close())
		}
		info, err := lease.lock.Stat()
		if err != nil || info.Size() != 0 {
			return errors.Join(errors.New("test tool directories retained after an unsettled user"), err, lease.close())
		}
	}
	var failure error
	for index := len(lease.created) - 1; index >= 0; index-- {
		item := lease.created[index]
		current, err := os.Lstat(item.path)
		if err != nil || !current.IsDir() || !records.SameLocalFile(item.info, current) {
			failure = errors.Join(failure, errors.New("test tool directory changed before cleanup"))
			continue
		}
		if err := syscall.Rmdir(item.path); err != nil {
			failure = errors.Join(failure, fmt.Errorf("test tool directory cleanup failed: %w", err))
		}
	}
	return errors.Join(failure, lease.close())
}

// The caller supplies new positive physical facts; this never removes paths.
func (lease *toolDirectoryLease) ReleaseAfterSettlement(_ context.Context) error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.lock == nil {
		return nil
	}
	return lease.close()
}

func toolDirectoriesMissing(root string, directories []string) (bool, error) {
	missing := false
	for _, relative := range directories {
		info, err := os.Lstat(filepath.Join(root, relative))
		if errors.Is(err, os.ErrNotExist) {
			missing = true
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false, errors.New("test tool directory refused")
		}
	}
	return missing, nil
}

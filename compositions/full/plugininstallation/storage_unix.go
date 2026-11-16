//go:build darwin || linux

package plugininstallation

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"
)

func lock(ctx context.Context, path string) (func() error, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err := sameLockedFile(path, file); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	timer := time.NewTicker(10 * time.Millisecond)
	defer timer.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(err, file.Close())
		}
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return nil, errors.Join(err, file.Close())
		}
		select {
		case <-ctx.Done():
			return nil, errors.Join(ctx.Err(), file.Close())
		case <-timer.C:
		}
	}
	if err := sameLockedFile(path, file); err != nil {
		return nil, errors.Join(err, syscall.Flock(int(file.Fd()), syscall.LOCK_UN), file.Close())
	}
	return func() error {
		return errors.Join(sameLockedFile(path, file), syscall.Flock(int(file.Fd()), syscall.LOCK_UN), file.Close())
	}, nil
}

func sameLockedFile(path string, file *os.File) error {
	held, err := file.Stat()
	if err != nil {
		return err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := held.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || !current.Mode().IsRegular() || !os.SameFile(held, current) {
		return ErrIdentity
	}
	return nil
}

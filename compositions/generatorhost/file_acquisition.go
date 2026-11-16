package generatorhost

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

type acquisitionError struct {
	cause   error
	settled bool
}

func (e *acquisitionError) Error() string { return e.cause.Error() }
func (e *acquisitionError) Unwrap() error { return e.cause }

func acquisitionFailure(err error, settled bool) error {
	if err == nil {
		return nil
	}
	return &acquisitionError{cause: err, settled: settled}
}

func acquisitionSettled(err error) bool {
	failure, ok := err.(*acquisitionError)
	return ok && failure != nil && failure.settled
}

func openNativeFile(ctx context.Context, path string, flags int, mode uint32) (*os.File, error) {
	return openNativeFileWith(ctx, path, flags, mode, unix.Open)
}

func openNativeFileWith(ctx context.Context, path string, flags int, mode uint32, open func(string, int, uint32) (int, error)) (*os.File, error) {
	for {
		if ctx != nil && ctx.Err() != nil {
			return nil, acquisitionFailure(ctx.Err(), true)
		}
		fd, err := open(path, flags|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, acquisitionFailure(err, true)
		}
		file := os.NewFile(uintptr(fd), path)
		if file == nil {
			closeErr := unix.Close(fd)
			return nil, acquisitionFailure(errors.Join(unix.EBADF, closeErr), closeErr == nil)
		}
		if ctx != nil && ctx.Err() != nil {
			closeErr := file.Close()
			return nil, acquisitionFailure(errors.Join(ctx.Err(), closeErr), closeErr == nil)
		}
		return file, nil
	}
}

func openNativeAt(ctx context.Context, parent *os.File, name string, flags int, mode uint32) (*os.File, error) {
	return openNativeFileWith(ctx, filepath.Join(parent.Name(), name), flags, mode, func(_ string, flags int, mode uint32) (int, error) {
		return unix.Openat(int(parent.Fd()), name, flags, mode)
	})
}

type acquiredFile struct {
	file *os.File
	info os.FileInfo
}

func acquireRegularFile(ctx context.Context, path string) (*acquiredFile, error) {
	if !filepath.IsAbs(path) {
		return nil, acquisitionFailure(ErrAdmission, true)
	}
	file, err := openNativeFile(ctx, path, unix.O_RDONLY, 0)
	if err != nil {
		return nil, acquisitionFailure(errors.Join(ErrAdmission, err), acquisitionSettled(err))
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		closeErr := file.Close()
		return nil, acquisitionFailure(errors.Join(ErrAdmission, err, closeErr), closeErr == nil)
	}
	return &acquiredFile{file: file, info: info}, nil
}

func (a *acquiredFile) unchanged(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	after, err := a.file.Stat()
	named, namedErr := os.Lstat(a.file.Name())
	if err != nil || namedErr != nil || !named.Mode().IsRegular() || !os.SameFile(a.info, after) || !os.SameFile(after, named) || a.info.Size() != after.Size() || a.info.ModTime() != after.ModTime() || a.info.Mode() != after.Mode() || after.Mode() != named.Mode() {
		return errors.Join(ErrAdmission, err, namedErr)
	}
	return nil
}

func (a *acquiredFile) close() error {
	return a.file.Close()
}

func fileOwnedByCurrentUID(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Uid) == uint64(os.Geteuid()) && info.Mode().Perm()&0077 == 0
}

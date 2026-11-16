package outputhost

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func openNativeFile(ctx context.Context, path string, flags int, mode uint32) (*os.File, error) {
	return openNativeFileWith(ctx, path, flags, mode, unix.Open)
}

func openNativeFileWith(ctx context.Context, path string, flags int, mode uint32, open func(string, int, uint32) (int, error)) (*os.File, error) {
	for {
		if ctx != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		fd, err := open(path, flags|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		file := os.NewFile(uintptr(fd), path)
		if file == nil {
			_ = unix.Close(fd)
			return nil, unix.EBADF
		}
		if ctx != nil && ctx.Err() != nil {
			return nil, errors.Join(ctx.Err(), file.Close())
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

func acquireRegularFile(ctx context.Context, path string) (source *acquiredFile, cleanupErr, resultErr error) {
	if !filepath.IsAbs(path) {
		return nil, nil, ErrAdmission
	}
	file, err := openNativeFile(ctx, path, unix.O_RDONLY, 0)
	if err != nil {
		return nil, nil, errors.Join(ErrAdmission, err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		cleanupErr := file.Close()
		return nil, cleanupErr, errors.Join(ErrAdmission, err, cleanupErr)
	}
	return &acquiredFile{file: file, info: info}, nil, nil
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

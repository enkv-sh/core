//go:build darwin || linux

package awsprovider

import (
	"context"
	"golang.org/x/sys/unix"
	"os"
)

func openCredentialFile(ctx context.Context, path string) (*os.File, error) {
	return openCredentialFileWith(ctx, path, unix.Open)
}

func openCredentialFileWith(ctx context.Context, path string, open func(string, int, uint32) (int, error)) (*os.File, error) {
	if ctx == nil {
		return nil, unix.EINVAL
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fd, err := open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		f := os.NewFile(uintptr(fd), path)
		if f == nil {
			_ = unix.Close(fd)
			return nil, unix.EBADF
		}
		if err := ctx.Err(); err != nil {
			_ = f.Close()
			return nil, err
		}
		return f, nil
	}
}

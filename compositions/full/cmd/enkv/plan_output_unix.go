//go:build unix

package main

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// Use the same open description for admission, telemetry and the last write,
// even if the caller later closes or redirects its own descriptor.
func duplicatePlanStream(source *os.File) (*os.File, error) {
	raw, err := source.SyscallConn()
	if err != nil {
		return nil, err
	}
	var dup int
	var dupErr error
	err = raw.Control(func(fd uintptr) {
		dup, dupErr = unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 0)
	})
	if err != nil || dupErr != nil {
		return nil, errors.Join(err, dupErr)
	}
	return os.NewFile(uintptr(dup), "plan-output"), nil
}

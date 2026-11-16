package configuration

import (
	"golang.org/x/sys/unix"
	"os"
	"syscall"
)

func syncEditFile(f *os.File) error {
	if err := f.Sync(); err != nil {
		return err
	}
	_, _, err := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_FULLFSYNC, 0)
	if err != 0 {
		return err
	}
	return nil
}

func renameEditAbsent(from, to string) error {
	return unix.RenameatxNp(unix.AT_FDCWD, from, unix.AT_FDCWD, to, unix.RENAME_EXCL)
}

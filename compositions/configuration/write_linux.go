package configuration

import (
	"golang.org/x/sys/unix"
	"os"
)

func syncEditFile(f *os.File) error { return f.Sync() }

func renameEditAbsent(from, to string) error {
	return unix.Renameat2(unix.AT_FDCWD, from, unix.AT_FDCWD, to, unix.RENAME_NOREPLACE)
}

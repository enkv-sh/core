package crypto

import (
	"os"
	"syscall"
)

func syncMaterializationFile(f *os.File) error {
	if err := f.Sync(); err != nil {
		return err
	}
	_, _, err := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_FULLFSYNC, 0)
	if err != 0 {
		return err
	}
	return nil
}

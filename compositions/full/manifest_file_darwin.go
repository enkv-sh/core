package compositionfull

import (
	"os"
	"syscall"
)

func syncManifestFile(file *os.File) error {
	if err := file.Sync(); err != nil {
		return err
	}
	_, _, err := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), syscall.F_FULLFSYNC, 0)
	if err != 0 {
		return err
	}
	return nil
}

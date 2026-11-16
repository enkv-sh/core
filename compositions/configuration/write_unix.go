//go:build darwin || linux

package configuration

import (
	"errors"
	"os"
	"syscall"
)

func openNativeLock(path string, create bool) (*os.File, error) {
	flags := os.O_RDONLY | syscall.O_NOFOLLOW
	if create {
		flags = os.O_RDWR | os.O_CREATE | syscall.O_NOFOLLOW
	}
	f, err := os.OpenFile(path, flags, 0600)
	if err != nil {
		return nil, errors.Join(ErrEdit, err)
	}
	return f, nil
}

func lockNativeFile(file *os.File, shared bool) error {
	mode := syscall.LOCK_EX
	if shared {
		mode = syscall.LOCK_SH
	}
	if err := syscall.Flock(int(file.Fd()), mode|syscall.LOCK_NB); err != nil {
		kind := ErrEdit
		if errors.Is(err, syscall.EWOULDBLOCK) {
			kind = ErrEditLocked
		}
		return errors.Join(kind, err)
	}
	return nil
}

func fileIdentity(info os.FileInfo) (nativeIdentity, bool) {
	if info == nil {
		return nativeIdentity{}, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nativeIdentity{}, false
	}
	return nativeIdentity{uint64(stat.Dev), uint64(stat.Ino)}, true
}

func singleLink(info os.FileInfo) bool {
	if info == nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}

func availableEditBytes(path string) (uint64, uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0, err
	}
	return uint64(stat.Bavail) * uint64(stat.Bsize), uint64(stat.Bsize), nil
}

func releaseEditLock(f *os.File) error {
	return errors.Join(syscall.Flock(int(f.Fd()), syscall.LOCK_UN), f.Close())
}

func openNativeInstallation(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, editError(err)
	}
	return file, nil
}

func openNativeScratch(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, editError(err)
	}
	return file, nil
}

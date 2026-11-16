//go:build linux

package awsprovider

import (
	"os"
	"syscall"
)

func credentialFileInfoStable(before, after os.FileInfo) bool {
	a, aok := before.Sys().(*syscall.Stat_t)
	b, bok := after.Sys().(*syscall.Stat_t)
	return aok && bok &&
		a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Nlink == b.Nlink &&
		a.Uid == b.Uid && a.Gid == b.Gid && a.Rdev == b.Rdev && a.Size == b.Size &&
		a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

// Command fdprobe checks the native generator descriptor vector and empty environment.
package main

import (
	"os"
	"strconv"
	"syscall"
)

func main() {
	if len(os.Args) != 2 || len(os.Environ()) != 0 {
		os.Exit(20)
	}
	count, err := strconv.Atoi(os.Args[1])
	if err != nil || count < 5 || count > 7 {
		os.Exit(21)
	}
	for fd := 0; fd < count; fd++ {
		var stat syscall.Stat_t
		if syscall.Fstat(fd, &stat) != nil {
			os.Exit(22)
		}
		want := uint32(syscall.S_IFIFO)
		if fd < 3 {
			want = syscall.S_IFCHR
		}
		if uint32(stat.Mode)&syscall.S_IFMT != want {
			os.Exit(23)
		}
	}
	directory, err := os.Open("/dev/fd")
	if err != nil {
		os.Exit(24)
	}
	names, readErr := directory.Readdirnames(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		os.Exit(25)
	}
	for _, name := range names {
		fd, err := strconv.Atoi(name)
		if err != nil || fd < count {
			continue
		}
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
		if errno == 0 && flags&syscall.FD_CLOEXEC == 0 || errno != 0 && errno != syscall.EBADF {
			os.Exit(26)
		}
	}
}

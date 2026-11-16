//go:build linux

package credentials

import (
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func credentialTestTerminal(t *testing.T) (*os.File, string) {
	t.Helper()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	master := os.NewFile(uintptr(fd), "test pty master")
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		if closeErr := master.Close(); closeErr != nil {
			t.Error("close terminal master after setup failure", closeErr)
		}
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		if closeErr := master.Close(); closeErr != nil {
			t.Error("close terminal master after setup failure", closeErr)
		}
		t.Fatal(err)
	}
	return master, fmt.Sprintf("/dev/pts/%d", number)
}

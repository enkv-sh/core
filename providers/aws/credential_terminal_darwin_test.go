//go:build darwin

package awsprovider

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
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
	fail := func(err error) {
		if closeErr := master.Close(); closeErr != nil {
			t.Error("close terminal master after setup failure", closeErr)
		}
		t.Fatal(err)
	}
	if err := unix.IoctlSetInt(fd, unix.TIOCPTYGRANT, 0); err != nil {
		fail(err)
	}
	if err := unix.IoctlSetInt(fd, unix.TIOCPTYUNLK, 0); err != nil {
		fail(err)
	}
	// x/sys v0.33.0 has no typed Darwin PTY-name wrapper. This test-only
	// fixture calls libSystem ioctl with its actual 128-byte buffer.
	helper := filepath.Join(t.TempDir(), "terminal-name")
	build := exec.CommandContext(t.Context(), "cc", "-Wall", "-Wextra", "-Werror", "-o", helper, "testdata/terminal_name.c")
	if output, err := build.CombinedOutput(); err != nil {
		if closeErr := master.Close(); closeErr != nil {
			t.Error("close terminal master after helper build failure", closeErr)
		}
		t.Fatalf("build terminal-name fixture: %v\n%s", err, output)
	}
	command := exec.CommandContext(t.Context(), helper)
	command.ExtraFiles = []*os.File{master}
	name, err := command.Output()
	if err != nil {
		fail(err)
	}
	if len(name) < 1 || len(name) >= 128 || !filepath.IsAbs(string(name)) || bytes.IndexByte(name, 0) >= 0 {
		fail(unix.EINVAL)
	}
	t.Log("terminal_name_compile_joined=true terminal_name_query_joined=true parent_master_retained=true")
	return master, string(name)
}

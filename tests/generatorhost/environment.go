package generatorhost

import (
	"io"

	protocol "enkv.sh/sdk/protocols/generator"
	"golang.org/x/sys/unix"
)

// TestReportEnvironmentPipeClosed injects a transport error after handing the
// frame to the test child. The error alone cannot attest to callback entry.
func TestReportEnvironmentPipeClosed(l *NativeLauncher, observe func()) {
	l.writeEnvironment = func(w io.Writer, frame protocol.Frame) error {
		if err := protocol.WriteFrame(w, frame); err != nil {
			return err
		}
		observe()
		return unix.EPIPE
	}
}

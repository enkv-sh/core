//go:build unix

package compositionfull

import (
	"context"
	"errors"
	"os"
	"sync"
	"syscall"

	privatecrypto "enkv.sh/crypto"
	"golang.org/x/sys/unix"
)

// NewPlanningDisplayFile leaves the supplied descriptor open. The acquired sink
// owns a duplicate and temporarily owns nonblocking status for the shared open
// description. Close joins writes and restores that status before result output.
// The caller must make no other use of the description during display.
func NewPlanningDisplayFile(out *os.File, structured bool) (privatecrypto.PlanningDisplayFactory, error) {
	if out == nil {
		return nil, errPlanningDisplay
	}
	return newPlanningDisplayWriter(func(ctx context.Context) (planningDisplayOutput, error) { return openPlanningDisplayFile(ctx, out) }, structured)
}

type planningFileOutput struct {
	file     *os.File
	original syscall.RawConn
	flags    int
	restore  bool
	once     sync.Once
	closeErr error
}

func openPlanningDisplayFile(ctx context.Context, original *os.File) (output planningDisplayOutput, err error) {
	if ctx == nil {
		return nil, errPlanningDisplay
	}
	deadline, finite := ctx.Deadline()
	if !finite || ctx.Err() != nil {
		return nil, errPlanningDisplay
	}
	info, err := original.Stat()
	if err != nil {
		return nil, err
	}
	raw, err := original.SyscallConn()
	if err != nil {
		return nil, err
	}
	duplicate, flags := -1, 0
	var setupErr error
	err = raw.Control(func(fd uintptr) {
		flags, setupErr = unix.FcntlInt(fd, unix.F_GETFL, 0)
		if setupErr != nil {
			return
		}
		duplicate, setupErr = unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 0)
		if setupErr != nil {
			return
		}
		if !info.Mode().IsRegular() {
			setupErr = unix.SetNonblock(duplicate, true)
		}
	})
	if duplicate < 0 {
		return nil, errors.Join(err, setupErr)
	}
	file := os.NewFile(uintptr(duplicate), "planning-display")
	if file == nil {
		return nil, errors.Join(unix.Close(duplicate), err, setupErr)
	}
	owned := &planningFileOutput{file: file, original: raw, flags: flags, restore: !info.Mode().IsRegular()}
	defer func() {
		if err != nil {
			err = errors.Join(err, owned.Close())
		}
	}()
	if err = errors.Join(err, setupErr); err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		if err = file.SetWriteDeadline(deadline); err != nil {
			return nil, err
		}
	}
	return owned, nil
}
func (o *planningFileOutput) WriteContext(ctx context.Context, body []byte) (n int, err error) {
	if ctx == nil || ctx.Err() != nil {
		return 0, errPlanningDisplay
	}
	// Cancellation closes the owned duplicate. File.Close interrupts pollable
	// writes; regular-file writes retain their backing until the kernel returns.
	joined := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(joined); o.close() })
	n, err = o.file.Write(body)
	if !stop() {
		<-joined
	}
	if ctx.Err() != nil {
		err = errors.Join(err, ctx.Err())
	}
	return n, err
}
func (o *planningFileOutput) close() {
	o.once.Do(func() {
		// Close must precede status restoration: changing a still-entered pollable
		// write back to blocking mode would remove its cancellation guarantee.
		closeErr := o.file.Close()
		var restoreErr error
		if o.restore {
			controlErr := o.original.Control(func(fd uintptr) { _, restoreErr = unix.FcntlInt(fd, unix.F_SETFL, o.flags) })
			restoreErr = errors.Join(controlErr, restoreErr)
		}
		o.closeErr = errors.Join(closeErr, restoreErr)
	})
}
func (o *planningFileOutput) Close() error {
	o.close()
	return o.closeErr
}

// WritePlanningResult owns only the final safe write. It uses a fresh native
// output owner after secret display is finalized and never repeats that display.
func WritePlanningResult(ctx context.Context, out *os.File, body []byte) error {
	if out == nil {
		return errPlanningDisplay
	}
	owner, err := openPlanningDisplayFile(ctx, out)
	if err != nil {
		return errPlanningDisplay
	}
	n, writeErr := owner.WriteContext(ctx, body)
	closeErr := owner.Close()
	if writeErr != nil || closeErr != nil || n != len(body) {
		return errPlanningDisplay
	}
	return nil
}

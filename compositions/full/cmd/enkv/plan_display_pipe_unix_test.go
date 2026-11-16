//go:build unix

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"golang.org/x/sys/unix"
)

// full_only: false
func TestPlanTerminalCancellationJoinsBlockedNativeWrite(t *testing.T) {
	fds := make([]int, 2)
	if err := unix.Pipe(fds); err != nil {
		t.Fatal(err)
	}
	reader, writer := os.NewFile(uintptr(fds[0]), "terminal-read"), os.NewFile(uintptr(fds[1]), "terminal-write")
	readerClosed := false
	defer func() {
		if !readerClosed {
			if err := reader.Close(); err != nil {
				t.Error(err)
			}
		}
	}()
	defer func() {
		if err := writer.Close(); err != nil {
			t.Error(err)
		}
	}()
	result := completePlanningResult()
	result.DisplayDelivery = contract.PlanningDeliveryComplete
	result.SelectedRecords = 1
	result.CompletedRecords = 1
	for i := 0; i < 512; i++ {
		result.PrivateEntries = append(result.PrivateEntries, contract.PlanningRelation{Name: fmt.Sprintf("%04d", i) + strings.Repeat("a", 252), Form: contract.PlanningSealed, Relation: contract.PlanningEqual, Code: contract.CryptoSuccess})
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var diagnostic bytes.Buffer
	done := make(chan int, 1)
	go func() { done <- writePlanningOutcome(ctx, result, true, true, writer, &diagnostic) }()
	prefix := make([]byte, 1)
	if _, err := reader.Read(prefix); err != nil {
		cancel()
		<-done
		t.Fatal("terminal did not enter native Write", err)
	}
	cancel()
	select {
	case code := <-done:
		if code != 2 {
			t.Fatal("cancelled terminal reported success")
		}
	case <-time.After(250 * time.Millisecond):
		readerClosed = true
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
		<-done
		t.Fatal("cancelled final plan result did not join its native Write")
	}
	raw, err := writer.SyscallConn()
	if err != nil {
		t.Fatal("stdout descriptor closed")
	}
	var flags int
	var statusErr error
	if err := raw.Control(func(fd uintptr) { flags, statusErr = unix.FcntlInt(fd, unix.F_GETFL, 0) }); err != nil || statusErr != nil || flags&unix.O_NONBLOCK != 0 {
		t.Fatal("stdout status not restored")
	}
}

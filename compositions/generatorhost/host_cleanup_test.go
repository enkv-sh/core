package generatorhost

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	protocol "enkv.sh/sdk/protocols/generator"
	"enkv.sh/telemetry"
	"golang.org/x/sys/unix"
)

func refuseLaunchRemoval(launcher *NativeLauncher, refusal error) *int {
	attempts := new(int)
	launcher.removeLaunchDir = func(string) error {
		(*attempts)++
		return refusal
	}
	return attempts
}

func assertClosedResultWriter(t *testing.T, writer *os.File) {
	t.Helper()
	if _, err := writer.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("result writer remained open")
	}
}

func assertNoLaunchDescriptors(t *testing.T, artifact string) {
	t.Helper()
	root := os.TempDir()
	launches, err := filepath.Glob(filepath.Join(root, "enkv-generator-*", ".launch-*"))
	if err != nil {
		t.Fatal("launch inventory unavailable")
	}
	paths := []string{artifact, artifact + ".old", root}
	for _, launch := range launches {
		paths = append(paths, launch, filepath.Join(launch, "generator"))
	}
	var owned []unix.Stat_t
	for _, path := range paths {
		var stat unix.Stat_t
		if err := unix.Stat(path, &stat); err == nil {
			owned = append(owned, stat)
		} else if !errors.Is(err, unix.ENOENT) {
			t.Fatal("launch identity unavailable")
		}
	}
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Fatal("descriptor inventory unavailable")
	}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); errors.Is(err, unix.EBADF) {
			continue
		} else if err != nil {
			t.Fatal("descriptor identity unavailable")
		}
		for _, file := range owned {
			if stat.Dev == file.Dev && stat.Ino == file.Ino {
				t.Fatal("host retained an owned launch descriptor")
			}
		}
	}
}

// full_only: false
func TestStartStagingRefusalRetainsRemovalCause(t *testing.T) {
	launcher, command, artifact := testLauncher(t, "success", []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
	removal := &os.PathError{Op: "remove", Path: "private-staging-path", Err: errors.New("private-removal-cause")}
	attempts := refuseLaunchRemoval(launcher, removal)
	launcher.afterSourceCopy = func() {
		if err := os.Rename(artifact, artifact+".old"); err != nil {
			t.Fatal("could not force the source identity refusal")
		}
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFile(reader)
	run, err := launcher.Start(context.Background(), command, writer)
	t.Logf("staged_refusal=true removal_attempts=%d run_returned=%t admission_cause=%t removal_cause=%t", *attempts, run != nil, errors.Is(err, ErrAdmission), errors.Is(err, removal))
	assertClosedResultWriter(t, writer)
	assertNoLaunchDescriptors(t, artifact)
	if ProvesNotStarted(command, err) || run != nil || !errors.Is(err, ErrAdmission) || !errors.Is(err, removal) || !errors.Is(err, errStagingCleanup) || *attempts != 1 {
		t.Fatal("staging refusal lost an original or removal cause")
	}
}

// full_only: false
func TestStartChildRefusalRetainsJoinedRemovalCause(t *testing.T) {
	for _, tc := range []struct {
		name, mode string
		credential []byte
		cause      error
	}{
		{"handshake", "bad-handshake", []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ"), ErrAdmission},
		{"credential", "success", bytes.Repeat([]byte("private-credential-sentinel"), 3000), ErrCredential},
	} {
		t.Run(tc.name, func(t *testing.T) {
			launcher, command, artifact := testLauncher(t, tc.mode, tc.credential)
			removal := errors.New("private post-child removal cause")
			attempts := refuseLaunchRemoval(launcher, removal)
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			run, err := launcher.Start(context.Background(), command, writer)
			_, eof := protocol.ReadFrame(reader, protocol.MaximumResultBody)
			closeFile(reader)
			t.Logf("child_refusal=true removal_attempts=%d result_eof=%t refusal_cause=%t removal_cause=%t", *attempts, errors.Is(eof, io.EOF), errors.Is(err, tc.cause), errors.Is(err, removal))
			assertClosedResultWriter(t, writer)
			assertNoLaunchDescriptors(t, artifact)
			var exit *exec.ExitError
			if ProvesNotStarted(command, err) || run != nil || !errors.Is(err, tc.cause) || !errors.Is(err, removal) || !errors.As(err, &exit) || *attempts != 1 || !errors.Is(eof, io.EOF) {
				t.Fatal("post-child refusal lost settled causes or child descriptor completion")
			}
		})
	}
}

// full_only: false
func TestHelloEncodingRefusalJoinsChildBeforeCredentialOrCommand(t *testing.T) {
	launcher, command, artifact := testLauncher(t, "success", []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
	removal := errors.New("private hello refusal removal cause")
	attempts := refuseLaunchRemoval(launcher, removal)
	launcher.afterSourceCopy = func() {
		// Production admission excludes zero Hello IDs. This private cut
		// exercises the local encoder refusal after ownership transfer.
		clear(launcher.config.Artifact.ProtocolID[:])
	}
	recorder := telemetry.NewRecorder()
	ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	run, err := launcher.Start(ctx, command, writer)
	_, eof := protocol.ReadFrame(reader, protocol.MaximumResultBody)
	closeFile(reader)
	assertClosedResultWriter(t, writer)
	assertNoLaunchDescriptors(t, artifact)
	var exit *exec.ExitError
	joined := errors.As(err, &exit)
	t.Logf("hello_refused=%t child_joined=%t removal_attempts=%d result_eof=%t removal_cause=%t",
		errors.Is(err, protocol.ErrProtocol), joined, *attempts, errors.Is(eof, io.EOF), errors.Is(err, removal))
	if run != nil || !errors.Is(err, protocol.ErrProtocol) || !errors.Is(err, removal) || !errors.Is(err, errStagingCleanup) || !joined || *attempts != 1 || !errors.Is(eof, io.EOF) {
		t.Error("Hello encoding refusal lost its original cause or settled ownership")
	}
	select {
	case <-launcher.commandSent:
		t.Error("Hello encoding refusal crossed the command boundary")
	default:
	}
	starts, returns := 0, 0
	for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32)) {
		if err := record.Validate(); err != nil {
			t.Fatal("invalid host diagnostic", err)
		}
		if record.Operation == telemetry.OpGeneratorHostCommandSend {
			t.Error("Hello encoding refusal entered credential or command handling")
		}
		if record.Operation != telemetry.OpGeneratorHostHandshake {
			continue
		}
		switch record.Event {
		case telemetry.DiagnosticStart:
			starts++
		case telemetry.DiagnosticReturn:
			returns++
			if record.ErrorClass != telemetry.DiagnosticReasonInvalidFormat || record.ErrorDetail != protocol.ErrProtocol.Error() || record.ErrorDetailStatus != "reviewed" {
				t.Error("Hello encoder refusal lost its safe handshake classification")
			}
		}
	}
	if starts != 1 || returns != 1 {
		t.Error("Hello encoding refusal did not finish exactly one handshake diagnostic")
	}
}

// full_only: false
func TestNativeCompletionRetainsAllCausesAndSettlesOnce(t *testing.T) {
	for _, tc := range []struct {
		name, mode         string
		remove, read, wait bool
		disposal           string
	}{
		{"successful-sibling", "success", false, false, false, ""},
		{"successful-child-removal-refusal", "success", true, false, false, ""},
		{"removal-and-descriptor-refusal", "success", true, false, false, "descriptor"},
		{"removal-and-root-identity-refusal", "success", true, false, false, "root"},
		{"status-and-child-and-removal-refusal", "exit-after-result", true, true, true, ""},
		{"invalid-status-and-removal-refusal", "duplicate-status", true, true, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			launcher, command, _ := testLauncher(t, tc.mode, []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
			removal := errors.New("private completed removal cause")
			attempts, joinedAtRemoval := 0, false
			var native *nativeRun
			launcher.removeLaunchDir = func(path string) error {
				attempts++
				joinedAtRemoval = native.cmd.ProcessState != nil
				if tc.remove {
					return removal
				}
				return os.RemoveAll(path)
			}
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			run, err := launcher.Start(context.Background(), command, writer)
			if err != nil {
				closeFile(reader)
				t.Fatal("fixture did not reach admitted run")
			}
			native = run.(*nativeRun)
			body, readErr := protocol.ReadExpectedFrame(reader, protocol.KindResult, run.CommandID(), protocol.MaximumResultBody)
			if readErr == nil {
				readErr = protocol.RequireEOF(reader)
			}
			clear(body)
			closeFile(reader)
			if readErr != nil {
				_ = run.Cancel()
				t.Fatal("fixture did not reach complete result")
			}
			var rootPath string
			if tc.disposal == "descriptor" {
				if err := native.stage.executable.Close(); err != nil {
					t.Fatal("controlled executable close", err)
				}
			}
			if tc.disposal == "root" {
				rootPath = native.stage.rootFile.Name()
				if err := os.Rename(rootPath, rootPath+".moved"); err != nil {
					t.Fatal("controlled root move", err)
				}
				defer func() {
					if err := os.Rename(rootPath+".moved", rootPath); err != nil {
						t.Error("restore root", err)
					}
				}()
			}
			status, settled := run.Wait(context.Background())
			repeatedStatus, repeated := run.Wait(context.Background())
			canceled := run.Cancel()
			var exit *exec.ExitError
			waitCause := errors.As(settled, &exit)
			childSuccess := native.cmd.ProcessState != nil && native.cmd.ProcessState.Success()
			readCause := errors.Is(settled, io.EOF)
			if tc.mode == "duplicate-status" {
				readCause = errors.Is(settled, protocol.ErrProtocol)
			}
			t.Logf("complete_result=true child_joined=%t child_success=%t removal_attempts=%d read_cause=%t wait_cause=%t removal_cause=%t", joinedAtRemoval, childSuccess, attempts, readCause, waitCause, errors.Is(settled, removal))
			assertClosedResultWriter(t, writer)
			if !joinedAtRemoval || attempts != 1 || repeated != settled || canceled != settled || repeatedStatus != status || errors.Is(settled, removal) != tc.remove || readCause != tc.read || waitCause != tc.wait {
				t.Fatal("completion lost causes or changed its settled outcome")
			}
			if childSuccess == tc.wait {
				t.Fatal("completion fixture did not establish the expected child exit")
			}
			if (tc.read || tc.wait || tc.disposal != "") && status != (protocol.Status{}) {
				t.Fatal("unsettled native disposal published a status", status)
			}
			if !tc.read && !tc.wait && tc.disposal == "" && status != (protocol.Status{Stage: protocol.StatusStageReturn, Category: protocol.StatusOK}) {
				t.Fatal("valid status changed")
			}
			if !tc.remove && settled != nil || tc.remove && settled == nil {
				t.Fatal("cleanup refusal accompanied a success")
			}
			if tc.remove && (!errors.Is(settled, ErrProcess) || !errors.Is(settled, errStagingCleanup)) {
				t.Fatal("removal failure lost its safe generator classification")
			}
			if tc.wait && !errors.Is(settled, ErrProcess) {
				t.Fatal("child exit lost its safe process classification")
			}
			qualified := tc.remove && !tc.read && !tc.wait && tc.disposal == ""
			if PreservesCompletion(command, run.CommandID(), status, settled) != qualified || ProvesNotStarted(command, settled) {
				t.Fatal("host completion qualification differs from its actual settlement")
			}
			if qualified {
				changed := command
				changed.DeadlineUnixMillis++
				wrongID := run.CommandID()
				wrongID[0] ^= 1
				for _, candidate := range []error{fmt.Errorf("wrapped: %w", settled), errors.Join(settled), errors.Join(settled, removal), removal} {
					if PreservesCompletion(command, run.CommandID(), status, candidate) {
						t.Error("foreign or composed error supplied completion proof")
					}
				}
				if PreservesCompletion(changed, run.CommandID(), status, settled) || PreservesCompletion(command, wrongID, status, settled) ||
					PreservesCompletion(command, run.CommandID(), protocol.Status{}, settled) {
					t.Error("completion proof accepted a changed command, correlation, or status")
				}
			}

		})
	}
}

// full_only: false
func TestNativeFailureStatusRequiresCompleteJoinedDisposal(t *testing.T) {
	for _, name := range []string{"clean", "removal refusal", "handle close refusal", "trailing status", "missing process state"} {
		t.Run(name, func(t *testing.T) {
			mode := "execution-failure"
			if name == "trailing status" {
				mode = "execution-failure-trailing"
			}
			launcher, command, _ := testLauncher(t, mode, []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
			removal := errors.New("fixed removal refusal")
			if name == "removal refusal" {
				launcher.removeLaunchDir = func(string) error { return removal }
			}
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			run, err := launcher.Start(context.Background(), command, writer)
			if err != nil {
				closeFile(reader)
				t.Fatal("fixture did not reach admitted run", err)
			}
			defer func() {
				canceled := run.Cancel()
				_, waited := run.Wait(context.Background())
				if canceled != waited {
					t.Error("cleanup changed joined failure", canceled, waited)
				}
			}()
			body, readErr := protocol.ReadExpectedFrame(reader, protocol.KindResult, run.CommandID(), protocol.MaximumResultBody)
			closeFile(reader)
			if readErr != io.EOF || len(body) != 0 {
				t.Fatal("closed execution failure emitted result bytes", readErr)
			}
			native := run.(*nativeRun)
			if name == "handle close refusal" {
				if native.stage.executable == nil {
					t.Fatal("fixture has no held executable")
				}
				if err := native.stage.executable.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if name == "missing process state" {
				state, err := native.cmd.Process.Wait()
				if err != nil || state == nil {
					t.Fatal("fixture did not consume its independent wait", err)
				}
			}
			status, settled := run.Wait(context.Background())
			if settled == nil {
				t.Fatal("nonzero execution exit lost its error")
			}
			if name == "clean" {
				var exit *exec.ExitError
				if status != (protocol.Status{Stage: 3, Category: 2}) || !errors.Is(settled, ErrProcess) || !errors.As(settled, &exit) || exit.ExitCode() != 29 || native.cmd.ProcessState == nil {
					t.Fatal("qualified failure status lost its joined execution exit", status, settled)
				}
			} else if status != (protocol.Status{}) {
				t.Fatal("unsettled disposal published failure status", status)
			}
			if name == "removal refusal" && !errors.Is(settled, removal) {
				t.Fatal("removal cause lost")
			}
			if name == "handle close refusal" && !errors.Is(settled, os.ErrClosed) {
				t.Fatal("handle close cause lost", settled)
			}
			if name == "trailing status" && !errors.Is(settled, protocol.ErrProtocol) {
				t.Fatal("status EOF refusal lost", settled)
			}
			repeatedStatus, repeated := run.Wait(context.Background())
			if repeatedStatus != status || repeated != settled || run.Cancel() != settled {
				t.Fatal("settled outcome changed after join")
			}
		})
	}
}

// full_only: false
func TestCanceledWaitRetainsContextAndRemovalCauses(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "canceled", true: "expired"}[expired], func(t *testing.T) {
			launcher, command, _ := testLauncher(t, "hang", []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
			removal := errors.New("private canceled removal cause")
			attempts := refuseLaunchRemoval(launcher, removal)
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer closeFile(reader)
			run, err := launcher.Start(context.Background(), command, writer)
			if err != nil {
				t.Fatal("fixture did not reach admitted run")
			}
			var ctx context.Context
			var cancel context.CancelFunc
			want := context.Canceled
			if expired {
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				want = context.DeadlineExceeded
			} else {
				ctx, cancel = context.WithCancel(context.Background())
				cancel()
			}
			defer cancel()
			status, err := run.Wait(ctx)
			_, settled := run.Wait(context.Background())
			cancelErr := run.Cancel()
			native := run.(*nativeRun)
			t.Logf("wait_context_done=true child_joined=%t removal_attempts=%d context_cause=%t removal_cause=%t", native.cmd.ProcessState != nil, *attempts, errors.Is(err, want), errors.Is(err, removal))
			assertClosedResultWriter(t, writer)
			var exit *exec.ExitError
			if PreservesCompletion(command, run.CommandID(), status, err) || ProvesNotStarted(command, err) || status != (protocol.Status{}) || !errors.Is(err, want) || !errors.Is(err, removal) || !errors.As(err, &exit) || !errors.Is(settled, removal) || cancelErr != settled || native.cmd.ProcessState == nil || *attempts != 1 {
				t.Fatal("canceled Wait lost context, completion causes or positive join")
			}
		})
	}
}

// full_only: false
func TestHostCleanupTelemetryRetainsSafeClassification(t *testing.T) {
	for _, tc := range []struct {
		name      string
		admission bool
	}{{"admission", true}, {"cancellation", false}} {
		for _, enabled := range []bool{false, true} {
			t.Run(tc.name+map[bool]string{false: "-disabled", true: "-enabled"}[enabled], func(t *testing.T) {
				mode := "success"
				if !tc.admission {
					mode = "hang-handshake"
				}
				credential := []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ")
				launcher, command, artifact := testLauncher(t, mode, credential)
				removal := &os.PathError{Op: "remove", Path: "private-cleanup-path", Err: errors.New("private-cleanup-error")}
				attempts := refuseLaunchRemoval(launcher, removal)
				if tc.admission {
					launcher.afterSourceCopy = func() {
						if err := os.Rename(artifact, artifact+".old"); err != nil {
							t.Fatal(err)
						}
					}
				}
				recorder := telemetry.NewRecorder()
				base := context.Background()
				if enabled {
					base = telemetry.WithCapability(base, telemetry.NewCapability(nil, recorder))
				}
				ctx := base
				var cancel context.CancelFunc
				if !tc.admission {
					ctx, cancel = context.WithTimeout(base, time.Second)
					defer cancel()
				}
				reader, writer, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				_, err = launcher.Start(ctx, command, writer)
				closeFile(reader)
				records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32))
				t.Logf("cleanup_refusal=true enabled=%t removal_attempts=%d retained_private_cause=%t diagnostic_records=%d", enabled, *attempts, errors.Is(err, removal), len(records))
				if !errors.Is(err, removal) || *attempts != 1 {
					t.Fatal("cleanup cause was unavailable at the private return boundary")
				}
				if tc.admission && !errors.Is(err, ErrAdmission) {
					t.Fatal("admission cause lost")
				}
				if !tc.admission && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("blocked-handshake deadline cause lost")
				}
				if !enabled && len(records) != 0 {
					t.Fatal("disabled telemetry emitted records")
				}
				returns := 0
				for _, record := range records {
					if err := record.Validate(); err != nil {
						t.Fatal("invalid telemetry record")
					}
					if record.Event == telemetry.DiagnosticReturn && (record.Operation == telemetry.OpGeneratorHostStart || record.Operation == telemetry.OpGeneratorHostJoin) {
						returns++
						if record.Result != telemetry.ResultEvidenceUnavailable || record.ErrorClass != telemetry.DiagnosticReasonEvidenceUnavailable || record.ErrorDetail != "generator staging cleanup failed" || record.ErrorDetailStatus != "reviewed" {
							t.Fatal("joined refusal hid the safe cleanup classification")
						}
					}
				}
				if enabled && returns == 0 {
					t.Fatal("missing cleanup return diagnostic")
				}
				encoded, err := json.Marshal(records)
				if err != nil {
					t.Fatal(err)
				}
				for _, secret := range [][]byte{credential, command.Intent, []byte("private-cleanup-path"), []byte("private-cleanup-error")} {
					for _, value := range [][]byte{secret, []byte(hex.EncodeToString(secret)), []byte(base64.StdEncoding.EncodeToString(secret))} {
						if bytes.Contains(encoded, value) {
							t.Fatal("private cleanup or credential content reached telemetry")
						}
					}
				}
			})
		}
	}
}

// full_only: false
func TestOwnedEndpointReleaseJoinsEnteredCancellation(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := writer.Close(); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithCancel(t.Context())
	endpoint := ownEndpoint(ctx, reader)
	if !endpoint.stop() {
		t.Fatal("original endpoint callback entered before controlled replacement")
	}
	callbackEntered := make(chan struct{})
	endpoint.done = make(chan struct{})
	endpoint.stop = context.AfterFunc(ctx, func() {
		defer close(endpoint.done)
		close(callbackEntered)
		if err := endpoint.close(); err != nil {
			t.Error(err)
		}
	})
	closeEntered, allowClose, closeDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	releaseClose := func() { unblock.Do(func() { close(allowClose) }) }
	done := make(chan error, 1)
	started, joined := false, false
	t.Cleanup(func() {
		releaseClose()
		cancel()
		waitEndpointSignal(t, closeDone, "controlled close did not join")
		waitEndpointSignal(t, endpoint.done, "cancellation callback did not join")
		if started && !joined {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("endpoint release did not settle")
			}
		}
	})
	go func() {
		endpoint.closeOnce.Do(func() {
			close(closeEntered)
			<-allowClose
			endpoint.closeErr = endpoint.Close()
		})
		close(closeDone)
	}()
	if !waitEndpointSignal(t, closeEntered, "controlled close did not enter") {
		return
	}
	cancel()
	if !waitEndpointSignal(t, callbackEntered, "controlled cancellation callback did not enter") {
		return
	}
	started = true
	go func() { done <- endpoint.release() }()
	select {
	case err := <-done:
		joined = true
		t.Error("release returned while cancellation close was entered", err)
		return
	case <-time.After(50 * time.Millisecond):
	}
	if _, err := reader.Stat(); err != nil {
		t.Error("descriptor closed before the controlled close completed", err)
	}
	releaseClose()
	select {
	case err := <-done:
		joined = true
		if err != nil {
			t.Error(err)
		}
	case <-time.After(5 * time.Second):
		t.Error("release did not join the entered cancellation close")
		return
	}
	select {
	case <-endpoint.done:
	default:
		t.Error("release did not join the cancellation callback")
	}
}

func waitEndpointSignal(t *testing.T, signal <-chan struct{}, failure string) bool {
	t.Helper()
	select {
	case <-signal:
		return true
	case <-time.After(5 * time.Second):
		t.Error(failure)
		return false
	}
}

// full_only: false
func TestOwnedEndpointReleaseRetainsCloseFailure(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal close", true: "cancellation close"}[canceled], func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := writer.Close(); err != nil {
					t.Error(err)
				}
			}()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			endpoint := ownEndpoint(ctx, reader)
			if err := reader.Close(); err != nil {
				t.Fatal(err)
			}
			if canceled {
				cancel()
				if !waitEndpointSignal(t, endpoint.done, "canceled close-fault callback did not join") {
					return
				}
			}
			done := make(chan [2]error, 1)
			go func() { done <- [2]error{endpoint.release(), endpoint.release()} }()
			select {
			case result := <-done:
				if !errors.Is(result[0], os.ErrClosed) || result[0] != result[1] {
					t.Fatal("required descriptor close failure was lost or replaced", result[0], result[1])
				}
			case <-time.After(5 * time.Second):
				t.Fatal("repeated release did not settle")
			}
		})
	}
}

// full_only: false
func TestNativeRunKeepsCredentialBackingUntilEnteredCallbackJoins(t *testing.T) {
	launcher, command, _ := testLauncher(t, "success", []byte("private callback-held credential"))
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	run, err := launcher.Start(ctx, command, writer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		done := make(chan error, 1)
		go func() { done <- run.Cancel() }()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("controlled native run cleanup did not join")
		}
	})
	if _, err := io.Copy(io.Discard, reader); err != nil {
		t.Fatal(err)
	}
	native := run.(*nativeRun)
	if !native.cancel() {
		t.Fatal("original cancellation callback entered before the controlled replacement")
	}
	backing := native.credential
	want := bytes.Clone(backing)
	defer clear(want)
	callbackContext, cancelCallback := context.WithCancel(t.Context())
	defer cancelCallback()
	entered, release, inspected := make(chan struct{}), make(chan struct{}), make(chan bool, 1)
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	native.cancelDone = make(chan struct{})
	native.cancel = context.AfterFunc(callbackContext, func() {
		defer close(native.cancelDone)
		close(entered)
		<-release
		inspected <- bytes.Equal(backing, want)
		if err := native.kill(); err != nil {
			t.Error(err)
		}
	})
	cancelCallback()
	if !waitEndpointSignal(t, entered, "controlled native callback did not enter") {
		return
	}
	done := make(chan error, 1)
	go func() { _, err := run.Wait(t.Context()); done <- err }()
	select {
	case err := <-done:
		unblock()
		waitEndpointSignal(t, native.cancelDone, "controlled native callback did not join")
		t.Fatal("run returned before its entered callback joined", err)
	case <-time.After(50 * time.Millisecond):
	}
	unblock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run failed to join its released callback")
	}
	select {
	case preserved := <-inspected:
		if !preserved || native.credential != nil || !bytes.Equal(backing, make([]byte, len(backing))) {
			t.Fatal("credential backing was cleared before callback join or retained afterward")
		}
	default:
		t.Fatal("native return preceded its callback observation")
	}
}

// full_only: false
func TestNativePreStartProofRequiresExactCommandAndCompleteDisposal(t *testing.T) {
	launcher, command, artifact := testLauncher(t, "success", []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
	launcher.afterSourceCopy = func() {
		if err := os.Rename(artifact, artifact+".old"); err != nil {
			t.Fatal(err)
		}
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFile(reader)
	run, failure := launcher.Start(t.Context(), command, writer)
	if run != nil || failure == nil {
		t.Fatal("fixture did not stop before child start")
	}
	if !ProvesNotStarted(command, failure) {
		t.Fatal("complete pre-start disposal lost exact proof", failure)
	}
	changed := command
	changed.AttemptID[0] ^= 1
	if ProvesNotStarted(changed, failure) {
		t.Error("changed command accepted")
	}
	for _, candidate := range []error{fmt.Errorf("wrapped: %w", failure), errors.Join(failure), errors.Join(failure, ErrProcess), ErrAdmission} {
		if ProvesNotStarted(command, candidate) {
			t.Error("foreign or composed failure accepted")
		}
	}
	assertClosedResultWriter(t, writer)
	assertNoLaunchDescriptors(t, artifact)
	r2, w2, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer closeFile(r2)
	run, repeated := launcher.Start(t.Context(), command, w2)
	if run != nil || ProvesNotStarted(command, repeated) {
		t.Error("consumed launcher issued another proof")
	}
}

// full_only: false
func TestPreStartAcquisitionRefusalUsesCompleteOwnerEvidence(t *testing.T) {
	for _, nonregular := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "nonregular"}[nonregular], func(t *testing.T) {
			launcher, command, artifact := testLauncher(t, "success", []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
			if err := os.Rename(artifact, artifact+".old"); err != nil {
				t.Fatal(err)
			}
			if nonregular {
				if err := unix.Mkfifo(artifact, 0500); err != nil {
					t.Fatal(err)
				}
			}
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer closeFile(reader)
			run, failure := launcher.Start(t.Context(), command, writer)
			if run != nil || !ProvesNotStarted(command, failure) {
				t.Fatal("clean source acquisition refusal lost exact no-child proof", failure)
			}
			assertClosedResultWriter(t, writer)
			select {
			case <-launcher.commandSent:
				t.Fatal("pre-start source refusal delivered permission")
			default:
			}
		})
	}
}

// full_only: false
func TestNativePreStartProofRefusesIncompleteCloseAndParentDisposal(t *testing.T) {
	for _, parentIdentity := range []bool{false, true} {
		t.Run(map[bool]string{false: "writer-close", true: "parent-identity"}[parentIdentity], func(t *testing.T) {
			launcher, command, _ := testLauncher(t, "success", []byte("Bearer_value_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer closeFile(reader)
			var moved, original string
			if parentIdentity {
				launcher.afterSourceCopy = func() {
					commandCopy := launcher.config.ArtifactPath
					if err := os.Rename(commandCopy, commandCopy+".old"); err != nil {
						t.Fatal(err)
					}
				}
				launcher.removeLaunchDir = func(path string) error {
					original, moved = filepath.Dir(path), filepath.Dir(path)+".moved"
					if err := os.Rename(original, moved); err != nil {
						return err
					}
					return os.RemoveAll(filepath.Join(moved, filepath.Base(path)))
				}
				defer func() {
					if moved != "" {
						if err := os.Remove(moved); err != nil {
							t.Error("controlled moved parent cleanup", err)
						}
					}
				}()
			} else if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			run, failure := launcher.Start(t.Context(), command, writer)
			if run != nil || failure == nil || ProvesNotStarted(command, failure) {
				t.Fatal("incomplete disposal gained no-child proof", failure)
			}
			if parentIdentity && !errors.Is(failure, ErrArtifactUnavailable) || !parentIdentity && !errors.Is(failure, os.ErrClosed) {
				t.Fatal("original disposal cause was lost", failure)
			}
			assertClosedResultWriter(t, writer)
		})
	}
}

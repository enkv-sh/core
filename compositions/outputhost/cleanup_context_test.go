package outputhost

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"enkv.sh/telemetry"
)

// full_only: false
func TestOutputHostCancellationKeepsConcurrentStagingCleanupFailure(t *testing.T) {
	for _, tc := range []struct {
		name      string
		passive   bool
		operation telemetry.Operation
	}{
		{"passive", true, telemetry.OpOutputHostPublicCheck},
		{"send", false, telemetry.OpOutputHostDispatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := testArtifactAndConfig(t)
			staging := ""
			callFinished := false
			defer func() {
				if !callFinished || staging == "" {
					// A failed watchdog has not proved child termination. Keep
					// the failure evidence until outer test supervision ends.
					return
				}
				if err := os.Chmod(staging, 0700); err != nil {
					t.Errorf("restore staging permission after child join: %v", err)
				}
			}()

			recorder := telemetry.NewRecorder()
			base := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
			ctx, cancel := context.WithCancel(base)
			defer cancel()
			finished := make(chan error, 1)
			if tc.passive {
				validator, err := NewPublicValidator(t.Context(), config.ArtifactPath, config.Installation)
				if err != nil {
					t.Fatal(err)
				}
				request, policy := testPublicRequest(t, config.Installation.Artifact(), "deny-cleanup")
				request.Target.CanonicalTarget, request.Target.ConsumerLocator = "deny-cleanup-public-sleep", "deny-cleanup-public-sleep"
				request.DeadlineUnixMillis = uint64(time.Now().Add(30 * time.Second).UnixMilli())
				go func() {
					_, err := validator.CheckAction(ctx, request, policy)
					finished <- err
				}()
			} else {
				native, err := NewNative(t.Context(), config)
				if err != nil {
					t.Fatal(err)
				}
				command, policy, payload := testOutputCommand(t, config.Installation.Artifact(), "deny-cleanup-sleep")
				command.DeadlineUnixMillis = uint64(time.Now().Add(30 * time.Second).UnixMilli())
				go func() {
					_, err := native.Dispatch(ctx, command, policy, payload)
					finished <- err
				}()
			}
			entered := false
			watchdog := time.NewTimer(15 * time.Second)
			defer watchdog.Stop()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for !entered {
				select {
				case err := <-finished:
					callFinished = true
					t.Fatalf("child returned before entry evidence: %v", err)
				case <-watchdog.C:
					cancel()
					select {
					case <-finished:
						callFinished = true
					case <-time.After(5 * time.Second):
						t.Fatal("child did not join after watchdog cancellation")
					}
					t.Fatal("child did not enter before watchdog")
				case <-ticker.C:
					for _, path := range stagedOutputRoots(t, config.ArtifactPath) {
						info, err := os.Stat(path)
						if err == nil && info.Mode().Perm() == 0500 {
							staging = path
							break
						}
					}
					info, err := os.Stat(staging)
					entered = err == nil && info.Mode().Perm() == 0500
					if entered && !tc.passive {
						markers, globErr := filepath.Glob(filepath.Join(staging, ".launch-*", ".entered-execute"))
						entered = globErr == nil && len(markers) == 1
					}
				}
			}
			cancel()
			var callErr error
			select {
			case callErr = <-finished: // Both child Wait and cleanup have completed.
				callFinished = true
			case <-time.After(5 * time.Second):
				t.Fatal("child did not join after controlled cancellation")
			}
			joined, dispatched, credential := false, false, false
			var disposition telemetry.Result
			for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32)) {
				if err := record.Validate(); err != nil {
					t.Fatal(err)
				}
				if record.Event != telemetry.DiagnosticReturn {
					continue
				}
				switch record.Operation {
				case telemetry.OpOutputHostJoin:
					joined = true
					if record.Result == telemetry.ResultSuccess {
						t.Fatal("expired child was reported as successful child completion")
					}
				case tc.operation:
					dispatched = true
					disposition = record.Result
				case telemetry.OpOutputHostCredentialGate:
					credential = record.Result == telemetry.ResultSuccess
				}
			}
			if !joined || !dispatched || (!tc.passive && !credential) {
				t.Fatalf("missing entered child, positive join, or credential gate: joined=%t dispatch=%t credential=%t", joined, dispatched, credential)
			}
			if !errors.Is(callErr, context.Canceled) || !errors.Is(callErr, ErrProcess) || !errors.Is(callErr, errStagingCleanup) {
				t.Fatalf("cancellation and cleanup causes must both survive: %v", callErr)
			}
			if disposition != telemetry.ResultEvidenceUnavailable {
				t.Fatalf("cleanup evidence hidden in %s diagnostic: %s", tc.operation, disposition)
			}
		})
	}
}

// full_only: false
func TestOutputHostCleanupFailureOutranksExpiredContext(t *testing.T) {
	combined := errors.Join(context.DeadlineExceeded, ErrProcess, errStagingCleanup)
	if !errors.Is(combined, context.DeadlineExceeded) || !errors.Is(combined, ErrProcess) || !errors.Is(combined, errStagingCleanup) {
		t.Fatal("combined expiration and cleanup lost a typed cause")
	}
	recorder := telemetry.NewRecorder()
	ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
	call := telemetry.Start(ctx, telemetry.ProviderOutputHost, telemetry.OpOutputHostDispatch)
	finishOutputCall(call, combined, nil)
	for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 2)) {
		if err := record.Validate(); err != nil {
			t.Fatal(err)
		}
		if record.Event == telemetry.DiagnosticReturn && record.Result != telemetry.ResultEvidenceUnavailable {
			t.Fatalf("expired context hid cleanup failure: %s", record.Result)
		}
	}
}

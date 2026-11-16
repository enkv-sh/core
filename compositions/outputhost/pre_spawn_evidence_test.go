package outputhost

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	protocol "enkv.sh/sdk/protocols/output"
	"enkv.sh/telemetry"
)

// full_only: false
func TestNativeOutputNotStartedKeepsExactNoEffectEvidence(t *testing.T) {
	for _, condition := range []string{"changed-executable", "credential-input-over-limit"} {
		t.Run(condition, func(t *testing.T) {
			config := testArtifactAndConfig(t)
			native, err := NewNative(t.Context(), config)
			if err != nil {
				t.Fatal(err)
			}
			command, policy, payload := testOutputCommand(t, config.Installation.Artifact(), "fixture")
			wantCause := ErrCredential
			if condition == "changed-executable" {
				body, err := os.ReadFile(config.ArtifactPath)
				if err != nil {
					t.Fatal(err)
				}
				body[len(body)-1] ^= 1
				if err := os.WriteFile(config.ArtifactPath, body, 0500); err != nil {
					t.Fatal(err)
				}
				wantCause = ErrArtifactIdentity
			} else {
				t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", strings.Repeat("x", 65536))
			}
			recorder := telemetry.NewRecorder()
			ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
			result, err := native.Dispatch(ctx, command, policy, payload)
			if !errors.Is(err, wantCause) {
				t.Fatalf("local preparation lost its cause: %v", err)
			}
			want := command.NewResult()
			want.Entry, want.Class = protocol.EntryNotEntered, protocol.ClassQualifiedNoEffect
			if result != want {
				t.Errorf("proved unstarted attempt lost its exact no-effect result: %+v", result)
			}
			changed := want
			changed.AttemptID[0] ^= 1
			if !PreservesResult(want, err) || PreservesResult(changed, err) || PreservesResult(want, wantCause) || PreservesResult(want, errors.Join(err, errors.New("another local failure"))) {
				t.Error("qualification did not bind the exact result and sole host failure")
			}
			for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 16)) {
				if record.Validate() != nil {
					t.Fatal("invalid diagnostic")
				}
				if record.Operation != telemetry.OpOutputHostDispatch {
					t.Fatalf("preparation entered a child phase: %s", record.Operation)
				}
			}
			assertNoStagedChild(t, config.ArtifactPath)
			if _, err := native.Dispatch(ctx, command, policy, payload); !errors.Is(err, ErrAdmission) {
				t.Fatal("local refusal granted a second dispatch", err)
			}
		})
	}
}

// full_only: false
func TestNativeOutputCheckedResultSurvivesSoleExecutableRemovalFailure(t *testing.T) {
	for _, condition := range []string{"acknowledged", "unknown", "failed-wait", "trailing-result"} {
		t.Run(condition, func(t *testing.T) {
			config := testArtifactAndConfig(t)
			native, err := NewNative(t.Context(), config)
			if err != nil {
				t.Fatal(err)
			}
			target := "plain-target-cleanup-failure-0"
			class := protocol.ClassAcknowledged
			switch condition {
			case "unknown":
				target = "plain-target-unknown-cleanup-failure-0"
				class = protocol.ClassUnproved
			case "failed-wait":
				t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "test-result-exit66")
			case "trailing-result":
				t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "test-result-trailing-byte")
			}
			command, policy, payload := testOutputCommand(t, config.Installation.Artifact(), target)
			recorder := telemetry.NewRecorder()
			ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
			result, err := native.Dispatch(ctx, command, policy, payload)
			if !errors.Is(err, errStagingCleanup) {
				t.Fatalf("missing executable removal failure: %v", err)
			}
			roots := stagedOutputRoots(t, config.ArtifactPath)
			defer func() {
				for _, path := range roots {
					if err := os.Chmod(path, 0700); err != nil {
						t.Error("restore joined staging root", err)
					}
				}
			}()
			if len(roots) != 1 {
				t.Fatalf("expected one failed executable removal, got %d", len(roots))
			}
			complete := condition == "acknowledged" || condition == "unknown"
			if complete {
				want := command.NewResult()
				want.Entry, want.Class = protocol.EntryMayHaveEntered, class
				if class == protocol.ClassAcknowledged {
					want.NormalizedStatus, want.ConsumerLocator = 201, command.Target.ConsumerLocator
					want.SafeResourceID = "test-instance/" + target + "/" + hex.EncodeToString(command.AttemptID[:])
				}
				if result != want {
					t.Errorf("sole executable removal failure erased or changed the checked result: %+v", result)
				}
			} else if result != (protocol.Result{}) {
				t.Error("incomplete result acquired cleanup exception", result)
			}
			resultRead, joined, failedJoin := false, false, false
			readResult := telemetry.ResultSuccess
			if condition == "unknown" {
				readResult = telemetry.ResultUnknown
			}
			for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32)) {
				if record.Validate() != nil {
					t.Fatal("invalid diagnostic")
				}
				if record.Event != telemetry.DiagnosticReturn {
					continue
				}
				if record.Operation == telemetry.OpOutputHostResultRead {
					resultRead = record.Result == readResult
				}
				if record.Operation == telemetry.OpOutputHostJoin {
					joined = record.Result == telemetry.ResultSuccess
					failedJoin = record.Result == telemetry.ResultFailure
				}
			}
			if complete && (!resultRead || !joined) || condition == "failed-wait" && (!resultRead || !failedJoin) || condition == "trailing-result" && resultRead {
				t.Fatal("cleanup exception did not retain its exact result, EOF and Wait conditions")
			}
		})
	}
}

// full_only: false
func TestNativeOutputCheckedResultKeepsOriginalLifetime(t *testing.T) {
	for _, condition := range []string{"expiry", "cancellation"} {
		t.Run(condition, func(t *testing.T) {
			config := testArtifactAndConfig(t)
			native, err := NewNative(t.Context(), config)
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "test-result-sleep-after-close")
			command, policy, payload := testOutputCommand(t, config.Installation.Artifact(), "plain-target")
			if condition == "expiry" {
				command.DeadlineUnixMillis = uint64(time.Now().Add(2 * time.Second).UnixMilli())
			}
			recorder := telemetry.NewRecorder()
			ctx, cancel := context.WithCancel(telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder)))
			defer cancel()
			type returned struct {
				result protocol.Result
				err    error
			}
			finished := make(chan returned, 1)
			go func() {
				result, err := native.Dispatch(ctx, command, policy, payload)
				finished <- returned{result, err}
			}()
			var records []telemetry.DiagnosticRecord
			read := false
			deadline := time.NewTimer(5 * time.Second)
			defer deadline.Stop()
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			for !read {
				select {
				case got := <-finished:
					t.Fatal("child returned before the controlled lifetime boundary", got.err)
				case <-deadline.C:
					cancel()
					select {
					case <-finished:
					case <-time.After(5 * time.Second):
						t.Fatal("child failed to join after watchdog cancellation")
					}
					t.Fatal("checked result was not reached")
				case <-ticker.C:
					batch := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32))
					records = append(records, batch...)
					for _, record := range batch {
						if record.Operation == telemetry.OpOutputHostResultRead && record.Event == telemetry.DiagnosticReturn && record.Result == telemetry.ResultSuccess {
							read = true
						}
					}
				}
			}
			want := context.DeadlineExceeded
			if condition == "cancellation" {
				want = context.Canceled
				cancel()
			}
			select {
			case got := <-finished:
				if got.result != (protocol.Result{}) || !errors.Is(got.err, want) {
					t.Error("checked result extended its original lifetime", got.result, got.err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("child did not join at original lifetime boundary")
			}
			records = append(records, recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32))...)
			joined := false
			for _, record := range records {
				if record.Validate() != nil {
					t.Fatal("invalid diagnostic")
				}
				if record.Operation == telemetry.OpOutputHostJoin && record.Event == telemetry.DiagnosticReturn {
					joined = true
					if record.Result == telemetry.ResultSuccess {
						t.Error("expired or cancelled Wait was reported successful")
					}
				}
			}
			if !joined {
				t.Fatal("missing positive child join")
			}
			assertNoStagedChild(t, config.ArtifactPath)
		})
	}
}

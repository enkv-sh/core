package outputhost

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/output"
	"enkv.sh/telemetry"
)

// full_only: false
func TestNativeOutputCapturedEnvironmentWithoutFile(t *testing.T) {
	config := testArtifactAndConfig(t)
	native, err := NewNative(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	command, policy, payload := testOutputCommand(t, config.Installation.Artifact(), "fixture")
	body, err := os.ReadFile(config.ArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)-1] ^= 1
	if err := os.WriteFile(config.ArtifactPath, body, 0500); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", strings.Repeat("x", 65536))
	if _, err := native.Dispatch(t.Context(), command, policy, payload); !errors.Is(err, ErrArtifactIdentity) || errors.Is(err, ErrCredential) {
		t.Fatal("changed executable reached environment capture", err)
	}
	assertNoStagedChild(t, config.ArtifactPath)
	config = testArtifactAndConfig(t)
	for range 2 {
		t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "private credential")
		native, err = NewNative(t.Context(), config)
		if err != nil {
			t.Fatal(err)
		}
		command, policy, payload = testOutputCommand(t, config.Installation.Artifact(), "fixture")
		result, err := native.Dispatch(t.Context(), command, policy, payload)
		if err != nil || result.Class != protocol.ClassAcknowledged {
			t.Fatal("current environment input refused", err)
		}
		if _, err := native.Dispatch(t.Context(), command, policy, payload); !errors.Is(err, ErrAdmission) {
			t.Fatal("used launcher captured credentials again", err)
		}
	}
	assertNoStagedChild(t, config.ArtifactPath)
}

// full_only: false
func TestNativeOutputCapturedEnvironmentMaximumIsBounded(t *testing.T) {
	config := testArtifactAndConfig(t)
	// u16 schema +u8 count +u8 name length +name +u8 presence +u32 value length.
	maximum := 65536 - (3 + 6 + len("ENKV_OUTPUT_TEST_CREDENTIAL"))
	for _, extra := range []int{0, 1} {
		t.Run(map[int]string{0: "exact", 1: "over"}[extra], func(t *testing.T) {
			t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", strings.Repeat("x", maximum+extra))
			native, err := NewNative(t.Context(), config)
			if err != nil {
				t.Fatal(err)
			}
			command, policy, payload := testOutputCommand(t, config.Installation.Artifact(), "fixture")
			recorder := telemetry.NewRecorder()
			ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
			if _, err := native.Dispatch(ctx, command, policy, payload); !errors.Is(err, ErrCredential) {
				t.Fatal("invalid private input not refused", err)
			}
			joined := false
			for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32)) {
				if record.Event == telemetry.DiagnosticReturn && record.Operation == telemetry.OpOutputHostJoin {
					joined = true
				}
			}
			if joined != (extra == 0) {
				t.Fatal("complete private input boundary checked at wrong owner")
			}
			assertNoStagedChild(t, config.ArtifactPath)
		})
	}
}

// full_only: false
func TestNativeOutputCommandDeadlineJoinsChildBeforeDisposal(t *testing.T) {
	config := testArtifactAndConfig(t)
	native, err := NewNative(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	command, policy, payload := testOutputCommand(t, config.Installation.Artifact(), "sleep")
	command.DeadlineUnixMillis = uint64(time.Now().Add(time.Second).UnixMilli())
	recorder := telemetry.NewRecorder()
	ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
	if _, err := native.Dispatch(ctx, command, policy, payload); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("command deadline did not bound child", err)
	}
	joined := false
	for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32)) {
		if record.Validate() != nil {
			t.Fatal("invalid diagnostic")
		}
		if record.Event == telemetry.DiagnosticReturn && record.Operation == telemetry.OpOutputHostJoin {
			joined = true
		}
	}
	if !joined {
		t.Fatal("expired action did not join")
	}
	assertNoStagedChild(t, config.ArtifactPath)
}

// full_only: false
func TestEnvironmentCaptureRefusalHasNoOwnedOutput(t *testing.T) {
	config := testArtifactAndConfig(t)
	route, err := config.Installation.CredentialRoute()
	if err != nil {
		t.Fatal(err)
	}
	for _, condition := range []string{"cancelled", "over-capacity"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if condition == "cancelled" {
				cancel()
			} else {
				t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", strings.Repeat("x", 65536))
			}
			body, err := captureEnvironment(ctx, route)
			if err == nil || body != nil {
				clear(body)
				t.Fatal("unusable input returned owned bytes")
			}
		})
	}
	for _, condition := range []string{"absent", "empty", "present"} {
		t.Run(condition, func(t *testing.T) {
			t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "")
			switch condition {
			case "absent":
				if err := os.Unsetenv("ENKV_OUTPUT_TEST_CREDENTIAL"); err != nil {
					t.Fatal(err)
				}
			case "present":
				t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "private credential")
			}
			body, err := captureEnvironment(t.Context(), route)
			if err != nil {
				t.Fatal(err)
			}
			inputs, err := credentialroute.DecodeInputs(route, body)
			if err != nil {
				t.Fatal(err)
			}
			if len(inputs) != 1 || inputs[0].Present != (condition != "absent") || !bytes.Equal(inputs[0].Value, []byte(os.Getenv("ENKV_OUTPUT_TEST_CREDENTIAL"))) {
				t.Fatal("absence or value changed")
			}
			clear(body)
		})
	}
}

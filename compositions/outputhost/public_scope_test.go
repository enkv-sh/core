package outputhost

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	protocol "enkv.sh/sdk/protocols/output"
	"enkv.sh/telemetry"
)

func scopedPublicContext() (context.Context, *telemetry.Recorder) {
	recorder := telemetry.NewRecorder()
	return telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder)), recorder
}

func scopedPublicJoins(t *testing.T, recorder *telemetry.Recorder, want int) {
	t.Helper()
	joins := 0
	for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 256)) {
		if err := record.Validate(); err != nil {
			t.Fatal(err)
		}
		if record.Operation == telemetry.OpOutputHostCredentialGate || record.Operation == telemetry.OpOutputHostDispatch {
			t.Fatal("passive scope entered private output work")
		}
		if record.Event == telemetry.DiagnosticReturn && record.Operation == telemetry.OpOutputHostJoin {
			joins++
		}
		if want == 0 && record.Operation == telemetry.OpOutputHostHandshake {
			t.Fatal("refused artifact started a public child")
		}
	}
	if joins != want {
		t.Fatalf("public child joins=%d want %d", joins, want)
	}
}

// full_only: false
func TestPublicValidationScopeKeepsExactRequestsAndPrivateChildren(t *testing.T) {
	config := testArtifactAndConfig(t)
	t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "")
	var scope PublicValidationScope
	validator, err := scope.NewValidator(t.Context(), config.ArtifactPath, config.Installation)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := scope.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx, recorder := scopedPublicContext()
	var destination protocol.Destination
	for _, prefix := range []string{"alpha", "beta"} {
		settings := []byte(`{"prefix":"` + prefix + `"}`)
		got, err := validator.Normalize(ctx, protocol.NormalizeRequest{Schema: 1, DeadlineUnixMillis: testDeadline(), Settings: settings})
		want := protocol.Destination{ConfigContractID: "test-output/config/v1", ServiceContractID: "test-output/service/v1", CanonicalSettings: settings,
			Policy: protocol.Policy{ContractID: "test-policy", Data: []byte("1,9")}, Capabilities: 255}
		if err != nil || !got.Accepted || !reflect.DeepEqual(got.Destination, want) {
			t.Fatalf("exact normalization differs: got=%+v err=%v", got, err)
		}
		destination = got.Destination
		canonical, err := validator.ValidateCanonical(ctx, protocol.CanonicalRequest{Schema: 1, DeadlineUnixMillis: testDeadline(), Destination: destination})
		if err != nil || !canonical.Accepted || !bytes.Equal(destination.CanonicalSettings, settings) {
			t.Fatal("canonical validation rewrote its input", err)
		}
		interpreted, err := validator.InterpretTarget(ctx, protocol.InterpretRequest{Schema: 1, DeadlineUnixMillis: testDeadline(), Destination: destination, EntryName: "value", PayloadEncoding: protocol.EncodingRaw})
		wantTarget := protocol.Target{ServiceContractID: "test-output/service/v1", TargetContractID: "test-output/target/v1", CanonicalTarget: prefix + "/value", ConsumerLocator: prefix + "/value",
			TargetData: []byte("public"), PayloadEncoding: protocol.EncodingRaw, Capabilities: 255,
			CreateValueBounds: protocol.PayloadBounds{Maximum: protocol.MaximumPayloadBytes}, WriteValueBounds: protocol.PayloadBounds{Maximum: protocol.MaximumPayloadBytes}}
		if err != nil || !interpreted.Accepted || !reflect.DeepEqual(interpreted.Target, wantTarget) {
			t.Fatalf("different request reused another target: got=%+v err=%v", interpreted, err)
		}
	}
	pids := make(map[int]bool)
	for range 2 {
		result, err := validator.InterpretTarget(ctx, protocol.InterpretRequest{Schema: 1, DeadlineUnixMillis: testDeadline(), Destination: destination, EntryName: "private-workspace", PayloadEncoding: protocol.EncodingRaw})
		if err != nil || !result.Accepted || result.Target.CanonicalTarget != result.Target.ConsumerLocator {
			t.Fatal("child reused a populated working directory", err)
		}
		pid, err := strconv.Atoi(strings.TrimPrefix(result.Target.CanonicalTarget, "beta/private-workspace/"))
		if err != nil || pid <= 0 || pids[pid] {
			t.Fatal("calls did not use distinct child processes", pid, err)
		}
		pids[pid] = true
	}
	request, policy := testPublicRequest(t, config.Installation.Artifact(), "fixture")
	result, err := validator.CheckAction(ctx, request, policy)
	if err != nil || !result.Accepted || result.PayloadBounds != (protocol.PayloadBounds{Maximum: 65536}) {
		t.Fatal("exact action bounds changed", result, err)
	}
	scopedPublicJoins(t, recorder, 9)
	roots := stagedOutputRoots(t, config.ArtifactPath)
	if len(roots) != 1 || roots[0] != validator.retained.stage.ownedRoot {
		t.Fatal("completed calls retained a private workspace", roots)
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	assertNoStagedChild(t, config.ArtifactPath)
	ctx, recorder = scopedPublicContext()
	if result, err := validator.CheckAction(ctx, request, policy); !errors.Is(err, ErrArtifactUnavailable) || result.Accepted {
		t.Fatal("closed scope launched through ordinary staging", result, err)
	}
	if _, err := scope.NewValidator(ctx, config.ArtifactPath, config.Installation); !errors.Is(err, ErrAdmission) {
		t.Fatal("closed scope acquired another validator", err)
	}
	scopedPublicJoins(t, recorder, 0)
}

// full_only: false
func TestPublicValidationScopeReauthenticatesSourceAndExecutable(t *testing.T) {
	config := testArtifactAndConfig(t)
	original, err := os.ReadFile(config.ArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, condition := range []string{"source-bytes", "source-mode", "source-symlink", "stage-bytes", "stage-mode", "stage-replaced", "stage-symlink", "stage-root-replaced", "compiled-closure"} {
		t.Run(condition, func(t *testing.T) {
			var scope PublicValidationScope
			validator, err := scope.NewValidator(t.Context(), config.ArtifactPath, config.Installation)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := scope.Close(); err != nil {
					t.Error(err)
				}
			}()
			request, policy := testPublicRequest(t, config.Installation.Artifact(), "fixture")
			if result, err := validator.CheckAction(t.Context(), request, policy); err != nil || !result.Accepted {
				t.Fatal("first call refused", err)
			}
			stage := validator.retained.stage
			path := stage.target
			if strings.HasPrefix(condition, "source-") {
				path = config.ArtifactPath
			}
			switch condition {
			case "source-bytes", "stage-bytes":
				changed := bytes.Clone(original)
				changed[len(changed)-1] ^= 1
				if err := os.Chmod(path, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, changed, 0500); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0500); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := os.Chmod(path, 0700); err != nil {
						t.Error(err)
					} else if err := os.WriteFile(path, original, 0700); err != nil {
						t.Error(err)
					}
				}()
			case "source-mode", "stage-mode":
				mode := os.FileMode(0700)
				if condition == "source-mode" {
					mode = 0770
				}
				if err := os.Chmod(path, mode); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := os.Chmod(path, 0500); err != nil {
						t.Error(err)
					}
				}()
			case "source-symlink", "stage-symlink", "stage-replaced":
				moved := path + "-held"
				if err := os.Rename(path, moved); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := errors.Join(os.Remove(path), os.Rename(moved, path)); err != nil {
						t.Error(err)
					}
				}()
				if condition == "stage-replaced" {
					err = os.WriteFile(path, original, 0500)
				} else {
					err = os.Symlink(moved, path)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "stage-root-replaced":
				moved := stage.ownedRoot + "-held"
				if err := os.Rename(stage.ownedRoot, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(stage.ownedRoot, 0700); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := errors.Join(os.Remove(stage.ownedRoot), os.Rename(moved, stage.ownedRoot)); err != nil {
						t.Error(err)
					}
				}()
			case "compiled-closure":
				changed := *config.Installation
				facts := *changed.manifest.Facts
				facts.Command += "/other"
				changed.manifest.Facts = &facts
				validator.config.Installation = &changed
			}
			ctx, recorder := scopedPublicContext()
			result, err := validator.CheckAction(ctx, request, policy)
			want := ErrArtifactIdentity
			switch condition {
			case "source-symlink":
				want = ErrAdmission
			case "compiled-closure":
				want = ErrArtifactIncompatible
			}
			if !errors.Is(err, want) || result.Accepted || errors.Is(err, ErrPassiveRefused) {
				t.Fatal("later call reused stale artifact evidence", result, err)
			}
			scopedPublicJoins(t, recorder, 0)
		})
	}
	assertNoStagedChild(t, config.ArtifactPath)
}

// full_only: false
func TestPublicValidationScopeKeepsCancellationAndCleanupFailures(t *testing.T) {
	config := testArtifactAndConfig(t)
	t.Run("cancelled-acquisition", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		var scope PublicValidationScope
		if _, err := scope.NewValidator(ctx, config.ArtifactPath, config.Installation); !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled acquisition lost its cause", err)
		}
		if err := scope.Close(); err != nil {
			t.Fatal(err)
		}
		assertNoStagedChild(t, config.ArtifactPath)
	})
	for _, condition := range []string{"cancelled-call", "cancelled-call-cleanup", "call-cleanup", "final-cleanup", "later-acquisition"} {
		t.Run(condition, func(t *testing.T) {
			var scope PublicValidationScope
			validator, err := scope.NewValidator(t.Context(), config.ArtifactPath, config.Installation)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := scope.Close(); err != nil {
					t.Error(err)
				}
			}()
			request, policy := testPublicRequest(t, config.Installation.Artifact(), "fixture")
			ctx, recorder := scopedPublicContext()
			if condition == "final-cleanup" || condition == "later-acquisition" {
				if _, err := validator.CheckAction(ctx, request, policy); err != nil {
					t.Fatal(err)
				}
				scopedPublicJoins(t, recorder, 1)
				if condition == "later-acquisition" {
					if _, err := scope.NewValidator(ctx, config.ArtifactPath+"-missing", config.Installation); !errors.Is(err, ErrArtifactMissing) {
						t.Fatal("later acquisition lost its missing artifact cause", err)
					}
					changed := *config.Installation
					changed.artifact.SHA256[0] ^= 1
					if _, err := scope.NewValidator(ctx, config.ArtifactPath, &changed); !errors.Is(err, ErrArtifactIdentity) {
						t.Fatal("another installation reused authenticated bytes", err)
					}
					changed = *config.Installation
					facts := *changed.manifest.Facts
					facts.Command += "/other"
					changed.manifest.Facts = &facts
					if _, err := scope.NewValidator(ctx, config.ArtifactPath, &changed); !errors.Is(err, ErrArtifactIncompatible) {
						t.Fatal("another installation reused compiled closure proof", err)
					}
					if roots := stagedOutputRoots(t, config.ArtifactPath); len(roots) != 1 || roots[0] != validator.retained.stage.ownedRoot {
						t.Fatal("failed provisional acquisition left a new stage", roots)
					}
					if err := scope.Close(); err != nil {
						t.Fatal(err)
					}
					assertNoStagedChild(t, config.ArtifactPath)
					return
				}
				root := validator.retained.stage.ownedRoot
				if err := os.Chmod(root, 0500); err != nil {
					t.Fatal(err)
				}
				defer restorePublicTestRoot(t, root)
				if err := scope.Close(); !errors.Is(err, ErrProcess) || !errors.Is(err, errStagingCleanup) {
					t.Fatal("final cleanup failure disappeared", err)
				}
				return
			}
			if condition == "call-cleanup" {
				request.Target.CanonicalTarget, request.Target.ConsumerLocator = "deny-cleanup", "deny-cleanup"
			} else {
				target := "public-sleep"
				if condition == "cancelled-call-cleanup" {
					target = "deny-cleanup-public-sleep"
				}
				request.Target.CanonicalTarget, request.Target.ConsumerLocator = target, target
				request.DeadlineUnixMillis = uint64(time.Now().Add(30 * time.Second).UnixMilli())
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Second)
				defer cancel()
			}
			_, err = validator.CheckAction(ctx, request, policy)
			if condition != "call-cleanup" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("call cancellation cause disappeared", err)
			}
			if condition != "cancelled-call" && (!errors.Is(err, ErrProcess) || !errors.Is(err, errStagingCleanup)) {
				t.Fatal("per-call cleanup failure disappeared", err)
			}
			scopedPublicJoins(t, recorder, 1)
			for _, root := range stagedOutputRoots(t, config.ArtifactPath) {
				if root != validator.retained.stage.ownedRoot {
					restorePublicTestRoot(t, root)
				}
			}
			next, _ := testPublicRequest(t, config.Installation.Artifact(), "fixture")
			if _, err := validator.CheckAction(t.Context(), next, policy); err != nil {
				t.Fatal("joined earlier failure poisoned a later request", err)
			}
			if err := scope.Close(); err != nil {
				t.Fatal(err)
			}
			assertNoStagedChild(t, config.ArtifactPath)
		})
	}
}

func restorePublicTestRoot(t *testing.T, root string) {
	t.Helper()
	if err := os.Chmod(root, 0700); err != nil {
		t.Error(err)
		return
	}
	if err := os.RemoveAll(root); err != nil {
		t.Error(err)
	}
}

package outputhost

import (
	"context"
	"crypto/sha256"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	protocol "enkv.sh/sdk/protocols/output"
	"enkv.sh/telemetry"
	"golang.org/x/sys/unix"
)

// full_only: false
func TestNativeProcessClosesCompleteDescriptorRangePreservesParent(t *testing.T) {
	artifact := filepath.Join(t.TempDir(), "fd-probe")
	build := exec.Command("go", "build", "-trimpath", "-o", artifact, "./testdata/fdprobe")
	build.Env = append(os.Environ(), "GOWORK=off")
	prepareNativeModule(t, "../..", build, artifact+".mod")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build descriptor probe: %v\n%s", err, output)
	}
	sentinel, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := sentinel.Close(); err != nil {
			t.Error("close sentinel", err)
		}
	}()
	high, err := unix.FcntlInt(sentinel.Fd(), unix.F_DUPFD, 512)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Close(high); err != nil {
			t.Error("close inherited descriptor", err)
		}
	}()
	flags, err := unix.FcntlInt(uintptr(high), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC != 0 {
		t.Fatal("non-close-on-exec sentinel absent")
	}
	for _, count := range []int{5, 6, 7} {
		t.Run("assigned-"+strconv.Itoa(count), func(t *testing.T) {
			null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := null.Close(); err != nil {
					t.Error("close null", err)
				}
			}()
			files := []*os.File{null, null, null}
			var owned []*os.File
			defer func() {
				for _, file := range owned {
					if err := file.Close(); err != nil {
						t.Error("close owned pipe", err)
					}
				}
			}()
			for len(files) < count {
				read, write, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				owned = append(owned, read, write)
				files = append(files, read)
			}
			child, err := startNativeChild(t.Context(), artifact, filepath.Dir(artifact), strconv.Itoa(count), files)
			if err != nil {
				t.Fatal("descriptor setup refused", err)
			}
			waitErr := child.Wait()
			after, err := unix.FcntlInt(uintptr(high), unix.F_GETFD, 0)
			if err != nil || after != flags {
				t.Fatal("caller descriptor was closed or changed")
			}
			t.Logf("assigned_descriptors=%d inherited_high_descriptor_closed_in_child=true parent_descriptor_preserved=true child_joined=%t", count, child.ProcessState != nil)
			if waitErr != nil {
				t.Fatal("child received extra/missing descriptors", waitErr)
			}
		})
	}
}

// full_only: false
func TestNativeLaunchFromRelativeTemporaryRootUsesAbsoluteExecutable(t *testing.T) {
	fixtureDirectory := t.TempDir()
	const fixtureSource = `package main
import (
 "os"
 "time"
)
func main() {
 if len(os.Args) != 2 || len(os.Environ()) != 0 { os.Exit(20) }
 switch os.Args[1] {
 case "complete":
  if _, err := os.Stdout.WriteString("intended-executable\n"); err != nil { os.Exit(21) }
 case "failure":
  os.Exit(23)
 case "cancelled":
  if _, err := os.Stdout.WriteString("ready\n"); err != nil { os.Exit(22) }
  time.Sleep(time.Hour)
 default:
  os.Exit(24)
 }
}
`
	for name, body := range map[string]string{"go.mod": "module example.test/native-stage-fixture\n\ngo 1.27.0\n", "main.go": fixtureSource} {
		if err := os.WriteFile(filepath.Join(fixtureDirectory, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(fixtureDirectory, "native-stage-fixture")
	buildContext, cancelBuild := context.WithTimeout(t.Context(), time.Minute)
	defer cancelBuild()
	build := exec.CommandContext(buildContext, "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", executable, ".")
	build.Dir = fixtureDirectory
	for _, setting := range os.Environ() {
		name, _, _ := strings.Cut(setting, "=")
		if !strings.HasPrefix(name, "GO") && name != "CGO_ENABLED" && name != "PWD" {
			build.Env = append(build.Env, setting)
		}
	}
	build.Env = append(build.Env, "PWD="+fixtureDirectory, "GOWORK=off", "GOTOOLCHAIN=local", "CGO_ENABLED=0", "GOPROXY=off", "GOSUMDB=off", "GONOSUMDB=*", "GOFLAGS=", "GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build native staging fixture: %v\n%s", err, output)
	}
	body, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	root := filepath.Join(parent, "relative-temporary-root")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(parent)
	t.Setenv("TMPDIR", "relative-temporary-root")
	for _, condition := range []string{"complete", "failure", "cancelled"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			stage, cleanupErr, err := newTemporaryArtifactStage(ctx, ".launch-test", "plugin")
			if err != nil || cleanupErr != nil {
				t.Fatal("relative temporary root refused staging", err, cleanupErr)
			}
			if err := os.WriteFile(stage.target, body, 0500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := stage.close(); err != nil {
					t.Error("staging cleanup failed", err)
				}
			})
			if !filepath.IsAbs(stage.path) || !filepath.IsAbs(stage.target) || stage.target != filepath.Join(stage.path, "plugin") || filepath.Dir(stage.path) != stage.ownedRoot || filepath.Dir(stage.ownedRoot) != root {
				t.Error("staging did not bind the exact absolute executable before child chdir")
			}
			if err := stage.authenticate(ctx, sha256.Sum256(body), uint64(len(body))); err != nil {
				t.Fatal(err)
			}
			null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := null.Close(); err != nil {
					t.Error(err)
				}
			}()
			read, write, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := read.Close(); err != nil {
					t.Error(err)
				}
			}()
			child, launchErr := startNativeChild(ctx, stage.target, stage.path, condition, []*os.File{null, write, null})
			closeErr := write.Close()
			if launchErr != nil || closeErr != nil {
				t.Fatal("exact staged executable failed after chdir", launchErr, closeErr)
			}
			child.WatchCancellation(ctx)
			if condition == "cancelled" {
				ready := make([]byte, len("ready\n"))
				if _, err := io.ReadFull(read, ready); err != nil || string(ready) != "ready\n" {
					cancel()
					waitErr := child.Wait()
					t.Fatal("native child did not enter its cancellation wait", err, waitErr)
				}
				cancel()
			}
			waitErr := child.Wait()
			if child.ProcessState == nil {
				t.Fatal("native child did not retain its joined result", waitErr)
			}
			switch condition {
			case "complete":
				if waitErr != nil || child.ProcessState.ExitCode() != 0 {
					t.Fatal("native child did not complete normally", waitErr)
				}
			case "failure":
				if waitErr == nil || child.ProcessState.ExitCode() != 23 {
					t.Fatal("native child lost its exact failure exit", waitErr)
				}
			case "cancelled":
				if waitErr == nil || child.ProcessState.ExitCode() != -1 || ctx.Err() != context.Canceled {
					t.Fatal("native cancellation did not kill and join the ready child", waitErr)
				}
			}
			got, err := io.ReadAll(io.LimitReader(read, 128))
			want := ""
			if condition == "complete" {
				want = "intended-executable\n"
			}
			if err != nil || string(got) != want {
				t.Fatal("native launch ran different executable bytes", err)
			}
			if err := stage.close(); err != nil {
				t.Fatal(err)
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 0 {
				t.Fatal("joined native launch retained staging", err)
			}
		})
	}
}

// full_only: false
func TestOutputProtocolsFromRelativeTemporaryRootJoinAndClean(t *testing.T) {
	config := testArtifactAndConfig(t)
	parent := t.TempDir()
	root := filepath.Join(parent, "relative-temporary-root")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(parent)
	t.Setenv("TMPDIR", "relative-temporary-root")
	assertEmpty := func() {
		t.Helper()
		entries, err := os.ReadDir(root)
		if err != nil || len(entries) != 0 {
			t.Fatal("completed protocol retained temporary staging", err)
		}
	}
	for range 2 {
		native, err := NewNative(t.Context(), config)
		if err != nil {
			t.Fatal(err)
		}
		command, policy, payload := testOutputCommand(t, config.Installation.Artifact(), "fixture")
		recorder := telemetry.NewRecorder()
		ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
		result, err := native.Dispatch(ctx, command, policy, payload)
		if err != nil || result.Class != protocol.ClassAcknowledged || result.NormalizedStatus != 201 {
			t.Fatal("private protocol did not complete exact acknowledged action", err)
		}
		joins := 0
		for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 64)) {
			if err := record.Validate(); err != nil {
				t.Fatal(err)
			}
			if record.Operation == telemetry.OpOutputHostJoin && record.Event == telemetry.DiagnosticReturn {
				joins++
			}
		}
		if joins != 1 {
			t.Fatal("private protocol did not report one positive child join", joins)
		}
		assertEmpty()
	}
	t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "")
	for _, retained := range []bool{false, true} {
		t.Run("retained-"+strconv.FormatBool(retained), func(t *testing.T) {
			var scope PublicValidationScope
			var validator *PublicValidator
			var err error
			if retained {
				validator, err = scope.NewValidator(t.Context(), config.ArtifactPath, config.Installation)
			} else {
				validator, err = NewPublicValidator(t.Context(), config.ArtifactPath, config.Installation)
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := scope.Close(); err != nil {
					t.Error(err)
				}
			})
			ctx, recorder := scopedPublicContext()
			for range 2 {
				settings := []byte(`{"prefix":"exact"}`)
				result, err := validator.Normalize(ctx, protocol.NormalizeRequest{Schema: 1, DeadlineUnixMillis: testDeadline(), Settings: settings})
				want := protocol.Destination{ConfigContractID: "test-output/config/v1", ServiceContractID: "test-output/service/v1", CanonicalSettings: settings, Policy: protocol.Policy{ContractID: "test-policy", Data: []byte("1,9")}, Capabilities: 255}
				if err != nil || !result.Accepted || !reflect.DeepEqual(result.Destination, want) {
					t.Fatal("public protocol did not preserve exact normalization result", err)
				}
				entries, err := os.ReadDir(root)
				wantEntries := 0
				if retained {
					wantEntries = 1
				}
				if err != nil || len(entries) != wantEntries {
					t.Fatal("public call retained its private workspace", err)
				}
			}
			scopedPublicJoins(t, recorder, 2)
			if err := scope.Close(); err != nil {
				t.Fatal(err)
			}
			assertEmpty()
		})
	}
}

package manifesthost

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"enkv.sh/sdk/artifact"
	manifest "enkv.sh/sdk/manifest-generator"
)

// full_only: false
func TestManifestLaunchCopyHasExactBytesAndOwnedCleanup(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	source := filepath.Join(t.TempDir(), "plugin")
	body := []byte("exact immutable launch bytes")
	if err := os.WriteFile(source, body, 0500); err != nil {
		t.Fatal(err)
	}
	identity := artifact.DigestLength{SHA256: artifact.Hash(body), Length: uint64(len(body))}
	stage, err := stageExecutable(ctx, source, identity)
	if err != nil {
		t.Fatal(err)
	}
	path := stage.path
	if err := stage.authenticate(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(stage.target)
	if err != nil || string(got) != string(body) {
		t.Fatal(string(got), err)
	}
	if err := stage.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("owned stage remains", err)
	}
	if got, err := os.ReadFile(source); err != nil || string(got) != string(body) {
		t.Fatal("borrowed source changed", err)
	}
}

// full_only: false
func TestManifestLaunchCopyRefusesSubstitutionAndForeignCleanup(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	for _, condition := range []string{"digest", "length", "symlink", "writable", "target-replaced", "directory-replaced"} {
		t.Run(condition, func(t *testing.T) {
			source := filepath.Join(t.TempDir(), "plugin")
			body := []byte("original")
			if err := os.WriteFile(source, body, 0500); err != nil {
				t.Fatal(err)
			}
			identity := artifact.DigestLength{SHA256: artifact.Hash(body), Length: uint64(len(body))}
			switch condition {
			case "digest":
				identity.SHA256[0] ^= 1
			case "length":
				identity.Length++
			case "symlink":
				link := source + "-link"
				if err := os.Symlink(source, link); err != nil {
					t.Fatal(err)
				}
				source = link
			case "writable":
				if err := os.Chmod(source, 0522); err != nil {
					t.Fatal(err)
				}
			}
			stage, err := stageExecutable(ctx, source, identity)
			if condition != "target-replaced" && condition != "directory-replaced" {
				if err == nil {
					_ = stage.close()
					t.Fatal("invalid source accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if condition == "target-replaced" {
				if err := os.Rename(stage.target, stage.target+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(stage.target, body, 0500); err != nil {
					t.Fatal(err)
				}
				if err := stage.authenticate(ctx); err == nil {
					t.Fatal("replacement inode accepted")
				}
				if err := stage.close(); err != nil {
					t.Fatal(err)
				}
				return
			}
			moved := stage.path + "-original"
			if err := os.Rename(stage.path, moved); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.RemoveAll(moved); err != nil {
					t.Error(err)
				}
			})
			if err := os.Mkdir(stage.path, 0700); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.RemoveAll(stage.path); err != nil {
					t.Error(err)
				}
			})
			foreign := filepath.Join(stage.path, "foreign")
			if err := os.WriteFile(foreign, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := stage.close(); err == nil {
				t.Fatal("foreign directory cleanup accepted")
			}
			if got, err := os.ReadFile(foreign); err != nil || string(got) != "keep" {
				t.Fatal("foreign directory removed", err)
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
			identity := artifact.DigestLength{SHA256: artifact.Hash(body), Length: uint64(len(body))}
			stage, err := stageExecutable(ctx, executable, identity)
			if err != nil {
				t.Fatal("relative temporary root refused staging", err)
			}
			t.Cleanup(func() {
				if err := stage.close(); err != nil {
					t.Error("staging cleanup failed", err)
				}
			})
			if !filepath.IsAbs(stage.path) || !filepath.IsAbs(stage.target) || stage.target != filepath.Join(stage.path, "plugin") || filepath.Dir(stage.path) != root {
				t.Error("staging did not bind the exact absolute executable before child chdir")
			}
			if err := stage.authenticate(ctx); err != nil {
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
func TestManifestProtocolFromRelativeTemporaryRootJoinsAndCleans(t *testing.T) {
	fixture := buildNativeFixture(t, false, false, testFormat)
	parent := t.TempDir()
	root := filepath.Join(parent, "relative-temporary-root")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(parent)
	t.Setenv("TMPDIR", "relative-temporary-root")
	admissionContext, cancelAdmission := context.WithTimeout(t.Context(), time.Minute)
	defer cancelAdmission()
	native, err := NewNative(admissionContext, fixture.path, fixture.metadata, fixture.dependency)
	if err != nil {
		t.Fatal(err)
	}
	for _, condition := range []string{"complete", "failure", "cancelled", "complete"} {
		t.Run(condition, func(t *testing.T) {
			for _, path := range []string{fixture.pid, fixture.ready} {
				if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			projection := nativeProjection(condition)
			var result manifest.Result
			if condition == "cancelled" {
				result = cancelNativeAfterReady(t, native, ctx, cancel, projection, fixture.ready)
			} else {
				result = native.Render(ctx, manifest.Borrow(projection))
			}
			defer clear(result.Artifact[:cap(result.Artifact)])
			wantFailure, wantBody := manifest.Failure(""), "private:"+testFormat+":complete"
			if condition == "failure" {
				wantFailure, wantBody = manifest.InvalidInput, ""
			}
			if condition == "cancelled" {
				wantFailure, wantBody = manifest.Cancelled, ""
			}
			if result.Failure != wantFailure || string(result.Artifact) != wantBody {
				t.Fatal("native manifest protocol result differs", result.Failure)
			}
			assertNativeSettled(t, fixture, root)
		})
	}
}

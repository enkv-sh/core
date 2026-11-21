package custody

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/generatorhost"
	"enkv.sh/crypto/testsupport/installedarchive"
	"enkv.sh/sdk/artifact"
)

// BuildInstalledLocalAuthor builds one actual public local implementation with
// the stock public CLI, then verifies its exact installed metadata. The facade
// returns no synthetic callback or plaintext result.
func BuildInstalledLocalAuthor(t testing.TB, root string, rebuilt bool) GeneratedProcessConfig {
	t.Helper()
	replacement := ""
	if rebuilt {
		replacement = "func(body []byte) (int, error) { return rand.Read(body) }(entropy[:])"
	}
	return buildInstalledLocalAuthor(t, root, replacement, "", false, false)
}

func BuildInstalledCleanupRefusedLocalAuthor(t testing.TB, root string) GeneratedProcessConfig {
	t.Helper()
	replacement := "func(body []byte) (int, error) { _ = rand.Read; for i := range body { body[i] = byte(i) }; return len(body), nil }(entropy[:])"
	return buildInstalledLocalAuthor(t, root, replacement, "", true, false)
}

// BuildInstalledTrailingCleanupRefusedLocalAuthor retains the real SDK result
// and status, then appends one invalid secret-stream byte before successful exit.
func BuildInstalledTrailingCleanupRefusedLocalAuthor(t testing.TB, root string) GeneratedProcessConfig {
	t.Helper()
	return buildInstalledLocalAuthor(t, root, "", "", true, true)
}

// BuildInstalledUnavailableLocalAuthor uses an actual source revision whose
// entropy reader returns an error. The public SDK owns its status/exit mapping.
func BuildInstalledUnavailableLocalAuthor(t testing.TB, root string) GeneratedProcessConfig {
	t.Helper()
	return buildInstalledLocalAuthor(t, root, "func([]byte) (int, error) { _ = rand.Read; return 0, io.ErrUnexpectedEOF }(entropy[:])", "", false, false)
}

// BuildInstalledInvalidLocalAuthor returns a protocol error from the actual
// local callback; the public SDK owns its status/exit mapping.
func BuildInstalledInvalidLocalAuthor(t testing.TB, root string) GeneratedProcessConfig {
	t.Helper()
	return buildInstalledLocalAuthor(t, root, "func([]byte) (int, error) { _ = rand.Read; return 0, protocol.ErrProtocol }(entropy[:])", "", false, false)
}

// BuildInstalledCancelledLocalAuthor returns cancellation from the actual
// local callback while its caller remains live.
func BuildInstalledCancelledLocalAuthor(t testing.TB, root string) GeneratedProcessConfig {
	t.Helper()
	return buildInstalledLocalAuthor(t, root, "func([]byte) (int, error) { _ = rand.Read; return 0, context.Canceled }(entropy[:])", "", false, false)
}

// BuildInstalledUnknownLocalAuthor returns valid unknown facts and no value
// from the actual native callback. It reports neither an execution error nor
// a managed-resource retirement promise.
func BuildInstalledUnknownLocalAuthor(t testing.TB, root string) GeneratedProcessConfig {
	t.Helper()
	return buildInstalledLocalAuthor(t, root, "", "protocol.DispositionUnknown, protocol.ReasonTransport", false, false)
}

// BuildInstalledNoEffectLocalAuthor returns confirmed no-effect from the native callback.
func BuildInstalledNoEffectLocalAuthor(t testing.TB, root string) GeneratedProcessConfig {
	t.Helper()
	return buildInstalledLocalAuthor(t, root, "", "protocol.DispositionConfirmedNoEffect, protocol.ReasonRejected", false, false)
}

func buildInstalledLocalAuthor(t testing.TB, root, replacement, returnedFacts string, removalFailure, trailingResult bool) GeneratedProcessConfig {
	t.Helper()
	directory, command := filepath.Join(root, "plugins/generators/local-random-secret"), "./cmd/enkv-generator-local-random-secret"
	workspace := filepath.Join(root, "go.work")
	if replacement != "" || returnedFacts != "" || removalFailure || trailingResult {
		// Rebuild the same public author module with a different source revision.
		// Its request and entropy contract are unchanged.
		staged, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.CopyFS(staged, os.DirFS(directory)); err != nil {
			t.Fatal(err)
		}
		mainPath := filepath.Join(staged, "execute.go")
		body, err := os.ReadFile(mainPath)
		if err != nil {
			t.Fatal(err)
		}
		if replacement != "" {
			before := "rand.Read(entropy[:])"
			if strings.Count(string(body), before) != 1 {
				t.Fatal("public author rebuild source changed")
			}
			body = []byte(strings.Replace(string(body), before, replacement, 1))
			if strings.Contains(replacement, "io.ErrUnexpectedEOF") {
				body = []byte(strings.Replace(string(body), "import (", "import (\n\t\"io\"", 1))
			}
		}
		if returnedFacts != "" {
			before := "return command.NewFacts(protocol.DispositionCompleteCreate, protocol.ReasonNone), value, nil"
			if strings.Count(string(body), before) != 1 {
				t.Fatal("public author result source changed")
			}
			body = []byte(strings.Replace(string(body), before, "clear(value); return command.NewFacts("+returnedFacts+"), nil, nil", 1))
		}
		if removalFailure {
			before := "return command.NewFacts(protocol.DispositionCompleteCreate, protocol.ReasonNone), value, nil"
			if strings.Count(string(body), before) != 1 {
				t.Fatal("public author completion source changed")
			}
			body = []byte(strings.Replace(string(body), "import (", "import (\n\t\"os\"\n\t\"path/filepath\"\n\t\"strconv\"", 1))
			after := `directory := filepath.Dir(os.Args[0])
	if err := os.WriteFile(filepath.Join(directory, "completion.pid"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		clear(value); return protocol.SafeFacts{}, nil, err
	}
	if err := os.Chmod(directory, 0500); err != nil {
		clear(value); return protocol.SafeFacts{}, nil, err
	}
	` + before
			body = []byte(strings.Replace(string(body), before, after, 1))
		}
		if err := os.WriteFile(mainPath, body, 0600); err != nil {
			t.Fatal(err)
		}
		if trailingResult {
			commandPath := filepath.Join(staged, "cmd/enkv-generator-local-random-secret/main.go")
			commandBody, err := os.ReadFile(commandPath)
			if err != nil {
				t.Fatal(err)
			}
			const before = "os.Exit(generator.Main(implementation))"
			if strings.Count(string(commandBody), before) != 1 {
				t.Fatal("public author command source changed")
			}
			commandBody = []byte(strings.Replace(string(commandBody), "\"os\"", "\"context\"\n\t\"os\"\n\t\"syscall\"\n\tprotocol \"enkv.sh/sdk/protocols/generator\"", 1))
			const after = `// Keep one process-owned, non-inheritable duplicate after the SDK closes fd 5.
	resultFD, err := syscall.Dup(protocol.SecretResultDescriptor)
	if err != nil { os.Exit(21) }
	syscall.CloseOnExec(resultFD)
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(resultFD), uintptr(syscall.F_GETFD), 0)
	if errno != 0 || flags & syscall.FD_CLOEXEC == 0 { os.Exit(21) }
	result := os.NewFile(uintptr(resultFD), "trailing private result")
	create, created := implementation.Create, false
	implementation.Create = func(ctx context.Context, invocation generator.Invocation) (protocol.SafeFacts, []byte, error) {
		facts, value, err := create(ctx, invocation)
		created = err == nil
		return facts, value, err
	}
	status := generator.Main(implementation)
	// Corrupt only the completed create result; public readiness must remain valid.
	var writeErr error
	if created && status == 0 {
		_, writeErr = result.Write([]byte{0x7f})
	}
	closeErr := result.Close()
	if writeErr != nil || closeErr != nil { os.Exit(21) }
	os.Exit(status)`
			commandBody = []byte(strings.Replace(string(commandBody), before, after, 1))
			if err := os.WriteFile(commandPath, commandBody, 0600); err != nil {
				t.Fatal(err)
			}
		}
		directory = staged
		var work strings.Builder
		work.WriteString("go 1.27.3\n\nuse (\n")
		for _, module := range []string{directory, filepath.Join(root, "sdk/artifact"), filepath.Join(root, "sdk/generator"), filepath.Join(root, "sdk/protocols/generator")} {
			physical, err := filepath.EvalSymlinks(module)
			if err != nil {
				t.Fatal(err)
			}
			work.WriteString(strconv.Quote(physical) + "\n")
		}
		work.WriteString(")\n\nreplace (\n")
		for _, relative := range []string{"sdk/artifact", "sdk/generator", "sdk/protocols/generator"} {
			physical, err := filepath.EvalSymlinks(filepath.Join(root, relative))
			if err != nil {
				t.Fatal(err)
			}
			work.WriteString("enkv.sh/" + relative + " v0.1.0 => " + strconv.Quote(physical) + "\n")
		}
		work.WriteString(")\n")
		workspace = filepath.Join(staged, "go.work")
		if err := os.WriteFile(workspace, []byte(work.String()), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GOFLAGS", "")
	output := t.TempDir()
	buildctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	builder := exec.CommandContext(buildctx, "go", "run", "-mod=readonly", "enkv.sh/sdk/artifact/cmd/enkv-plugin-build", "-directory", directory, "-descriptor", "cmd/enkv-generator-local-random-secret/plugin.json", "-command", command, "-output", output, "-workspace", workspace)
	builder.WaitDelay = 5 * time.Second
	builder.Dir = root
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key != "GOWORK" && key != "GOTOOLCHAIN" {
			builder.Env = append(builder.Env, entry)
		}
	}
	builder.Env = append(builder.Env, "GOWORK="+workspace, "GOTOOLCHAIN=local")
	var diagnostic installedarchive.ChildOutput
	builder.Stdout, builder.Stderr = &diagnostic, &diagnostic
	if err := builder.Run(); err != nil {
		body := diagnostic.Bytes()
		defer clear(body[:cap(body)])
		t.Fatalf("public local author build: %v\n%s", err, body[:min(len(body), 64<<10)])
	}
	markerBytes, err := os.ReadFile(filepath.Join(output, "build.json"))
	if err != nil {
		t.Fatal(err)
	}
	marker, err := artifact.DecodeBuildMarker(markerBytes)
	if err != nil {
		t.Fatal(err)
	}
	build := filepath.Join(output, filepath.FromSlash(marker.Directory))
	t.Cleanup(func() {
		for _, path := range []string{build, filepath.Join(output, "builds")} {
			if err := os.Chmod(path, 0700); err != nil && !os.IsNotExist(err) {
				t.Error(err)
			}
		}
	})
	metadata, err := artifact.VerifyBuild(t.Context(), output)
	if err != nil {
		t.Fatal(err)
	}
	dependency, err := os.ReadFile(filepath.Join(build, "dependencies.bin"))
	if err != nil {
		t.Fatal(err)
	}
	installed, err := generatorhost.NewInstallation(metadata, dependency)
	if err != nil {
		t.Fatal(err)
	}
	row := installed.Artifact()
	encoded, err := artifact.EncodeMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	return GeneratedProcessConfig{ArtifactPath: filepath.Join(build, "plugin"), Artifact: row, Metadata: encoded, Dependency: dependency}
}

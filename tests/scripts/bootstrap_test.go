package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// full_only: false
func TestLauncherRequiresInstalledSupervisorBeforeGo(t *testing.T) {
	launcher, err := os.ReadFile(filepath.Join(bootstrapSourceRoot(t), "tests/scripts/test"))
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"list"},
		{"plan", "--workflow", "missing.json", "--step", "runner", "--test", "TestSelected"},
		{"cleanup", strings.Repeat("a", 32), "--limits", "missing.json"},
	} {
		t.Run(args[0], func(t *testing.T) {
			root, temporary, commands := t.TempDir(), t.TempDir(), t.TempDir()
			writeBootstrapFixture(t, filepath.Join(root, "tests/scripts/test"), launcher, 0700)
			if err := os.Mkdir(filepath.Join(root, "core"), 0700); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(commands, "go-started")
			writeBootstrapFixture(t, filepath.Join(commands, "go"), []byte("#!/bin/sh\nprintf started > \"$ENKV_SETUP_REFUSAL_MARKER\"\nexit 7\n"), 0700)
			t.Setenv("PATH", commands+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("ENKV_SETUP_REFUSAL_MARKER", marker)
			stdout, stderr, status := runBootstrapProcess(t, root, temporary, filepath.Join(root, "tests/scripts/test"), args...)
			if status == 0 || stdout != "" || !strings.Contains(stderr, "supervisor") || !strings.Contains(stderr, "setup-supervisor") {
				t.Errorf("missing supervisor did not give the setup refusal: status=%d stdout=%q stderr=%q", status, stdout, stderr)
			}
			if _, err := os.Lstat(marker); !os.IsNotExist(err) {
				t.Error("missing supervisor allowed Go to start", err)
			}
		})
	}
}

// full_only: false
func TestLauncherOwnsBootstrapFiles(t *testing.T) {
	for _, tc := range []struct {
		name       string
		args       []string
		status     int
		diagnostic string
		file, body string
	}{
		{name: "list", args: []string{"list"}},
		{name: "empty command", status: 1, diagnostic: "usage: tests/scripts/test"},
		{name: "invalid command", args: []string{"invalid-command"}, status: 1, diagnostic: "usage: tests/scripts/test"},
		{name: "invalid leading flag", args: []string{"--invalid-flag"}, status: 1, diagnostic: "usage: tests/scripts/test"},
		{name: "empty root override", args: []string{"--root", ""}, status: 1, diagnostic: "usage: tests/scripts/test"},
		{name: "replaced root", args: []string{"--root", "core/internal/preserved", "list"}, status: 1, diagnostic: "usage: tests/scripts/test"},
		{name: "missing root", args: []string{"--root"}, status: 1, diagnostic: "usage: tests/scripts/test"},
		{name: "empty bootstrap override", args: []string{"--bootstrap-dir", "", "list"}, status: 1, diagnostic: "usage: tests/scripts/test"},
		{name: "replaced bootstrap directory", args: []string{"--bootstrap-dir", "core/internal/preserved", "list"}, status: 1, diagnostic: "usage: tests/scripts/test"},
		{name: "missing bootstrap directory", args: []string{"--bootstrap-dir"}, status: 1, diagnostic: "usage: tests/scripts/test"},
		{name: "run command flags", args: []string{"run", "--suite=tests/suites/state-smoke.json"}, status: 1, diagnostic: "suite selection and environment must be nonempty"},
		{
			name: "runner build failure", args: []string{"list"}, status: 1,
			diagnostic: "undefined: bootstrapMissingSymbol",
			file:       "tests/shared/runner/bootstrap_failure.go",
			body:       "package main\nvar bootstrapFailure = bootstrapMissingSymbol\n",
		},
		{
			name: "existing Core file", args: []string{"list"}, status: 1,
			diagnostic: "test tool overlay cannot replace a Core file",
			file:       "core/internal/testmain/main.go",
			body:       "package main\nvar existingCoreSource = true\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, temporary := bootstrapFixture(t)
			if tc.file != "" {
				writeBootstrapFixture(t, filepath.Join(root, tc.file), []byte(tc.body), 0600)
			}
			beforeRepository := bootstrapTree(t, root)
			beforeTemporary := bootstrapTree(t, temporary)

			stdout, stderr, status := runBootstrapProcess(t, root, temporary, filepath.Join(root, "tests/scripts/test"), tc.args...)
			if status != tc.status {
				t.Errorf("launcher status = %d, want %d; stderr:\n%s", status, tc.status, stderr)
			}
			if tc.status == 0 {
				if !strings.HasPrefix(stdout, "state.identical-input-keeps-current-state/members_32\t") || !strings.Contains(stdout, "state.single-value-update-preserves-other-values/members_32\t") || !strings.Contains(stdout, "\tfixed fixture\t") || !strings.Contains(stdout, "state.single-value-update-preserves-other-values/members_1\t") || !strings.Contains(stdout, "state.single-value-update-preserves-other-values/members_64\t") || !strings.Contains(stdout, "roles=authority,recovery,observer") || !strings.Contains(stdout, "secret.shared-reader-survives-restart/plain_neighbor_shared_secret\t") || !strings.Contains(stdout, "roles=authority,recovery,reader") || stderr != "" {
					t.Errorf("scenario list missing or unexpected diagnostics: stdout=%q stderr=%q", stdout, stderr)
				}
			} else if stdout != "" || !strings.Contains(stderr, tc.diagnostic) {
				t.Errorf("failure did not reach the expected launcher path: stdout=%q stderr=%q", stdout, stderr)
			}
			assertBootstrapTree(t, "repository", beforeRepository, bootstrapTree(t, root))
			assertBootstrapTree(t, "temporary directory", beforeTemporary, bootstrapTree(t, temporary))
		})
	}
}

// full_only: false
func TestLauncherPreservesInvocationDirectory(t *testing.T) {
	root, temporary := bootstrapFixture(t)
	for path, source := range map[string]string{
		"tests/shared/runner/relative_plan_test.go":  "package main\nimport \"testing\"\n// full_only: false\nfunc TestRelativePlanRunner(t *testing.T){}\n",
		"tests/shared/records/relative_plan_test.go": "package records\nimport \"testing\"\n// full_only: false\nfunc TestRelativePlanRecords(t *testing.T){}\n",
		"tests/shared/catalog/relative_plan_test.go": "package catalog\nimport \"testing\"\n// full_only: false\nfunc TestRelativePlanCatalog(t *testing.T){}\n",
		"tests/scripts/bootstrap_test.go":            "package main\nimport \"testing\"\n// full_only: false\nfunc TestRelativePlanScripts(t *testing.T){}\n",
	} {
		writeBootstrapFixture(t, filepath.Join(root, path), []byte(source), 0600)
	}
	writeBootstrapFixture(t, filepath.Join(root, "tests/workflows/relative.json"),
		[]byte(`{"schema_version":1,"name":"relative","steps":[{"id":"runner","kind":"runner-tests","tests":["TestRelativePlanRunner"]}]}`), 0600)
	beforeRepository, beforeTemporary := bootstrapTree(t, root), bootstrapTree(t, temporary)
	stdout, stderr, status := runBootstrapProcess(t, filepath.Join(root, "tests"), temporary,
		filepath.Join(root, "tests/scripts/test"), "plan", "--workflow=workflows/relative.json")
	var plan struct {
		Kind       string   `json:"kind"`
		Name       string   `json:"name"`
		Unresolved []string `json:"unresolved"`
		Steps      []struct {
			ID       string   `json:"id"`
			Selected bool     `json:"selected"`
			Tests    []string `json:"tests"`
		} `json:"steps"`
	}
	if status != 0 || stderr != "" || json.Unmarshal([]byte(stdout), &plan) != nil || plan.Kind != "selection_preview" || plan.Name != "relative" || len(plan.Unresolved) == 0 || len(plan.Steps) != 1 || plan.Steps[0].ID != "runner" || !plan.Steps[0].Selected || len(plan.Steps[0].Tests) != 1 || plan.Steps[0].Tests[0] != "TestRelativePlanRunner" {
		t.Fatalf("relative preview did not preserve the invocation directory: status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	assertBootstrapTree(t, "repository", beforeRepository, bootstrapTree(t, root))
	assertBootstrapTree(t, "temporary directory", beforeTemporary, bootstrapTree(t, temporary))
}

// full_only: false
func TestRunnerArgumentFailureCleansBootstrap(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "invalid flag", args: []string{"--invalid-flag"}},
		{name: "empty root", args: []string{"--root", ""}},
		{name: "missing root", args: []string{"--root"}},
		{name: "missing bootstrap directory", args: []string{"--bootstrap-dir"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, temporary := bootstrapFixtureConfigured(t, func(root string) {
				filename := filepath.Join(root, "tests/shared/runner/supervisor_invocation.go")
				body, err := os.ReadFile(filename)
				if err != nil {
					t.Fatal(err)
				}
				from := `runnerArgs = append(append(runnerArgs, "--"), args...)`
				if strings.Count(string(body), from) != 1 {
					t.Fatal("runner invocation source changed")
				}
				// Keep the real root channel and supervisor ownership. Only the
				// internal argument vector is damaged in this copied source.
				to := fmt.Sprintf("runnerArgs = append(runnerArgs, %#v...)", tc.args)
				if err := os.WriteFile(filename, []byte(strings.Replace(string(body), from, to, 1)), 0600); err != nil {
					t.Fatal(err)
				}
			})
			beforeRepository := bootstrapTree(t, root)
			beforeTemporary := bootstrapTree(t, temporary)
			stdout, stderr, status := runBootstrapProcess(t, root, temporary, filepath.Join(root, "tests/scripts/test"), "list")
			if status == 0 || !strings.Contains(stderr, "invalid launcher arguments") {
				t.Errorf("runner did not reject invalid internal arguments: status=%d stdout=%q stderr=%q", status, stdout, stderr)
			}
			assertBootstrapTree(t, "repository", beforeRepository, bootstrapTree(t, root))
			assertBootstrapTree(t, "temporary directory", beforeTemporary, bootstrapTree(t, temporary))
		})
	}
}

// full_only: false
func TestLintFindingsExitNonzeroThroughLauncherWorkflowAndMake(t *testing.T) {
	for _, command := range []string{"lint", "workflow", "make"} {
		t.Run(command, func(t *testing.T) {
			root, temporary := bootstrapFixture(t)
			marker := filepath.Join(t.TempDir(), "witness")
			// Vet accepts this ordinary unit test; errcheck must reject it without executing it.
			body := "package telemetry\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\n// full_only: false\nfunc TestUnchecked(t *testing.T) {\n\tos.Chdir(\".\")\n\tpanic(\"lint executed a test\")\n}\n"
			writeBootstrapFixture(t, filepath.Join(root, "telemetry/lint_failure_test.go"), []byte(body), 0600)
			witness := fmt.Sprintf(`package witness

import (
	"os"
	"testing"
)

// full_only: false
func TestLintContinuationWitness(t *testing.T) {
	if err := os.WriteFile(%q, []byte("independent witness\n"), 0600); err != nil {
		t.Fatal(err)
	}
}
`, marker)
			writeBootstrapFixture(t, filepath.Join(root, "telemetry/witness/witness_test.go"), []byte(witness), 0600)
			program, args := filepath.Join(root, "tests/scripts/test"), []string{command}
			if command == "workflow" {
				workflow := filepath.Join(root, "tests/workflows/lint-failure.json")
				writeBootstrapFixture(t, workflow, []byte(`{"schema_version":1,"name":"lint-failure","profile":"dev","steps":[{"id":"lint","kind":"lint"},{"id":"witness","kind":"unit","packages":["telemetry/witness"],"package":"telemetry/witness","tests":["TestLintContinuationWitness"]}]}`), 0600)
				args = []string{"run", "--workflow", workflow}
			} else if command == "make" {
				program, args = "make", []string{"lint"}
			}
			stdout, stderr, status := runBootstrapProcess(t, root, temporary, program, args...)
			diagnostic := stdout + stderr
			if status == 0 || !strings.Contains(diagnostic, "errcheck") || !strings.Contains(diagnostic, "os.Chdir") {
				t.Fatalf("lint finding did not reach command exit: status=%d stdout=%q stderr=%q", status, stdout, stderr)
			}
			if strings.Contains(diagnostic, "panic: lint executed") {
				t.Fatal("lint executed the unchecked test body")
			}
			if command == "workflow" {
				body, err := os.ReadFile(marker)
				if err != nil || string(body) != "independent witness\n" || !strings.Contains(stdout, "Workflow failed") {
					t.Fatal("failed lint workflow lost independent execution or its terminal failure", string(body), err, stdout, stderr)
				}
				for _, phase := range []string{"test", "conversion"} {
					terminals := 0
					for _, line := range strings.Split(stdout, "\n") {
						if !strings.HasPrefix(line, "Check phase="+phase+" scope=enkv.sh/telemetry/witness ") {
							continue
						}
						terminals++
						if !strings.Contains(line, " process=passed started=true joined=true ") || !strings.Contains(line, " events=valid ") || phase == "test" && !strings.HasSuffix(line, " requested_node=passed") {
							t.Fatal("independent witness lost its passed joined terminal", line)
						}
					}
					if terminals != 1 {
						t.Fatal("independent witness terminal count differs", phase, terminals, stdout)
					}
				}
			} else {
				if strings.Contains(stdout, "Testing") {
					t.Fatal("lint command executed tests")
				}
				if _, err := os.Lstat(marker); !os.IsNotExist(err) {
					t.Fatal("lint command entered the witness body", err)
				}
			}
			for _, name := range []string{"tests/hermetic/runs", "tests/live/runs"} {
				if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
					t.Fatal("lint failure started a component run")
				}
			}
		})
	}
}

// full_only: false
func TestLintCommandsKeepBootstrapOffline(t *testing.T) {
	for _, command := range []string{"lint", "check", "make"} {
		t.Run(command, func(t *testing.T) {
			root, temporary := bootstrapFixture(t)
			var requests atomic.Int64
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusNotFound)
			}))
			defer proxy.Close()
			// Override the test helper's offline environment before entering the public command.
			body := "#!/bin/sh\nexport GOPROXY=" + proxy.URL + " GOSUMDB=off GONOPROXY=none\nexport GOMODCACHE=\"$PWD/empty-module-cache\"\n"
			if command == "make" {
				body += "exec make lint\n"
			} else {
				body += fmt.Sprintf("exec ./tests/scripts/test %s --parallel=%d\n", command, bootstrapFixtureParallel(t))
			}
			wrapper := filepath.Join(root, "offline-check")
			writeBootstrapFixture(t, wrapper, []byte(body), 0700)
			stdout, stderr, status := runBootstrapProcess(t, root, temporary, wrapper)
			if status == 0 || !strings.Contains(stderr, "GOPROXY=off") {
				t.Fatalf("missing cache did not fail offline: status=%d stdout=%q stderr=%q", status, stdout, stderr)
			}
			if requests.Load() != 0 {
				t.Fatalf("lint contacted the module proxy %d times", requests.Load())
			}
		})
	}
}

func bootstrapFixtureParallel(t *testing.T) int {
	t.Helper()
	setting := flag.Lookup("test.parallel")
	if setting == nil {
		t.Fatal("test parallel allowance unavailable")
	}
	parallel, err := strconv.Atoi(setting.Value.String())
	if err != nil || parallel < 1 {
		t.Fatal("invalid test parallel allowance", err)
	}
	return min(parallel, 4)
}

func runBootstrapProcess(t *testing.T, directory, temporary, program string, args ...string) (string, string, int) {
	t.Helper()
	args = append([]string{}, args...)
	if strings.HasSuffix(filepath.ToSlash(program), "/tests/scripts/test") && len(args) != 0 {
		switch args[0] {
		case "plan", "run", "cleanup":
			args = append(args, fmt.Sprintf("--parallel=%d", bootstrapFixtureParallel(t)))
		case "unit", "runner-tests", "list", "check", "dev", "fuzz", "fmt", "fmt-check", "lint":
			args = append([]string{args[0], fmt.Sprintf("--parallel=%d", bootstrapFixtureParallel(t))}, args[1:]...)
		}
	}
	if program == "go" && len(args) != 0 && args[0] == "run" {
		args = append([]string{"run", fmt.Sprintf("-p=%d", bootstrapFixtureParallel(t))}, args[1:]...)
	}
	allowance := 2 * time.Minute
	if strings.HasSuffix(filepath.ToSlash(program), "/tests/scripts/test") && len(args) != 0 && args[0] == "check" {
		// Complete check preparation now compiles every selected later owner.
		allowance = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), allowance)
	defer cancel()
	command := exec.CommandContext(ctx, program, args...)
	command.Dir = directory
	command.Env = bootstrapEnvironment(temporary)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }
	command.WaitDelay = 5 * time.Second
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	if ctx.Err() != nil {
		t.Fatalf("bootstrap process exceeded its time limit: %v; stderr:\n%s", err, stderr.String())
	}
	status := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("bootstrap process failed: %v; stderr:\n%s", err, stderr.String())
		}
		status = exit.ExitCode()
	}
	if command.Process != nil && !errors.Is(syscall.Kill(-command.Process.Pid, 0), syscall.ESRCH) {
		t.Fatal("launcher process group remains present after Wait")
	}
	// Exec.Wait joined the direct child. The native supervisor must also have
	// positively settled its branches, released resource descriptors and removed its invocation stage.
	assertBootstrapResourcesSettled(t, temporary)
	return stdout.String(), stderr.String(), status
}

func bootstrapResourcesReleased(directory string) error {
	if _, err := os.Lstat(directory); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	for _, name := range []string{"machine.lock", "live.lock"} {
		file, err := os.OpenFile(filepath.Join(directory, name), os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return errors.Join(statErr, errors.New("fixture resource lock identity refused"), file.Close())
		}
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			return errors.Join(errors.New("fixture resource lock remains occupied after process join"), err, file.Close())
		}
		if err := file.Close(); err != nil {
			return err
		}
	}
	return nil
}

func assertBootstrapResourcesSettled(t *testing.T, temporary string) {
	t.Helper()
	resources := filepath.Join(filepath.Dir(temporary), "a")
	if _, err := os.Lstat(resources); os.IsNotExist(err) {
		return
	}
	if err := bootstrapResourcesReleased(resources); err != nil {
		t.Fatal(err)
	}
	stageParent := bootstrapInvocationStageParent(t, temporary)
	stages, err := filepath.Glob(filepath.Join(stageParent, "invoke.*"))
	if err != nil || len(stages) != 0 {
		t.Fatal("launcher fixture retained an invocation stage", stages, err)
	}
	if body, err := os.ReadFile(filepath.Join(stageParent, "kept-private")); err != nil || string(body) != "test-owned stage sibling\n" {
		t.Fatal("launcher changed an unrelated stage-parent sibling", err)
	}
}

func bootstrapInvocationStageParent(t *testing.T, temporary string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(filepath.Dir(temporary), "invocation-stage-parent"))
	parent := string(body)
	if err != nil || !filepath.IsAbs(parent) || filepath.Clean(parent) != parent {
		t.Fatal("launcher fixture stage parent unavailable", err)
	}
	if info, err := os.Lstat(parent); err != nil || !info.IsDir() {
		t.Fatal("launcher fixture stage parent changed", err)
	}
	return parent
}

func bootstrapSourceRoot(t *testing.T) string {
	t.Helper()
	source, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if info, err := os.Stat(filepath.Join(source, "tests/scripts/test")); err == nil && info.Mode().IsRegular() {
			break
		}
		parent := filepath.Dir(source)
		if parent == source {
			t.Fatal("launcher source repository unavailable")
		}
		source = parent
	}
	return source
}

func bootstrapFixture(t *testing.T) (root, temporary string) {
	t.Helper()
	return bootstrapFixtureConfigured(t, nil)
}

func bootstrapFixtureConfigured(t *testing.T, configure func(string)) (root, temporary string) {
	t.Helper()
	source := bootstrapSourceRoot(t)
	// The copied checkout has its own source-bound supervisor and test-only
	// resource directory. The outer test still owns its host resources and counts
	// this entire descendant tree against its memory limit.
	parent, err := filepath.EvalSymlinks("/var/tmp")
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.MkdirTemp(parent, "enkv-launcher-")
	if err != nil {
		t.Fatal(err)
	}
	root, temporary = filepath.Join(fixture, "r"), filepath.Join(fixture, "t")
	resources := filepath.Join(fixture, "a")
	stageParent, err := os.MkdirTemp("", "enkv-launcher-stages-")
	if err != nil {
		t.Fatal(err)
	}
	stageParent, err = filepath.EvalSymlinks(stageParent)
	if err != nil {
		t.Fatal(err)
	}
	stageIdentity, err := os.Lstat(stageParent)
	if err != nil {
		t.Fatal(err)
	}
	writeBootstrapFixture(t, filepath.Join(fixture, "invocation-stage-parent"), []byte(stageParent), 0600)
	writeBootstrapFixture(t, filepath.Join(stageParent, "kept-private"), []byte("test-owned stage sibling\n"), 0600)
	t.Cleanup(func() {
		resourceErr := bootstrapResourcesReleased(resources)
		stages, stageErr := filepath.Glob(filepath.Join(stageParent, "invoke.*"))
		if t.Failed() || resourceErr != nil || stageErr != nil || len(stages) != 0 {
			t.Log("launcher fixture retained:", fixture, stageParent)
			return
		}
		current, err := os.Lstat(stageParent)
		before, beforeOK := stageIdentity.Sys().(*syscall.Stat_t)
		if err != nil {
			t.Error("launcher fixture stage parent unavailable", err)
			return
		}
		after, afterOK := current.Sys().(*syscall.Stat_t)
		if !beforeOK || !afterOK || before.Ino == 0 || before.Ino != after.Ino || before.Uid != after.Uid || !current.IsDir() || current.Mode().Perm() != 0700 {
			t.Error("launcher fixture stage parent ownership changed")
			return
		}
		if err := os.RemoveAll(stageParent); err != nil {
			t.Error("remove settled launcher stage fixture", err)
			return
		}
		if err := os.RemoveAll(fixture); err != nil {
			t.Error("remove settled launcher fixture", err)
		}
	})
	copyFile := func(path string) {
		t.Helper()
		info, err := os.Stat(filepath.Join(source, path))
		if err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(filepath.Join(source, path))
		if err != nil {
			t.Fatal(err)
		}
		writeBootstrapFixture(t, filepath.Join(root, path), body, info.Mode().Perm())
	}
	for _, directory := range []string{"core", "crypto", "telemetry", "tests/fixtures", "providers", "compositions", "tests/shared/runner", "tests/shared/records", "tests/shared/catalog"} {
		err := filepath.WalkDir(filepath.Join(source, directory), func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			relative, err := filepath.Rel(source, path)
			if err != nil {
				return err
			}
			// Keep source and embedded data together; each caller supplies its
			// own test inventory below.
			if strings.HasSuffix(entry.Name(), "_test.go") {
				return nil
			}
			copyFile(relative)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	for _, public := range []string{"sdk", "plugins", "distribution"} {
		owner := filepath.Join(filepath.Dir(source), "enkv-extensions", public)
		err := filepath.WalkDir(owner, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() {
				return fmt.Errorf("public source fixture is not regular")
			}
			relative, err := filepath.Rel(owner, path)
			if err != nil {
				return err
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			writeBootstrapFixture(t, filepath.Join(filepath.Dir(root), "enkv-extensions", public, relative), body, info.Mode().Perm())
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	workspace, err := os.ReadFile(filepath.Join(filepath.Dir(source), "enkv-extensions/go.work"))
	if err != nil {
		t.Fatal(err)
	}
	writeBootstrapFixture(t, filepath.Join(filepath.Dir(root), "enkv-extensions/go.work"), workspace, 0600)
	copyFile("tests/scripts/test")
	copyFile("tests/scripts/bootstrap.go")
	copyFile("tests/scripts/setup-supervisor")
	copyFile("tests/scripts/supervisor-sources.tsv")
	for _, path := range []string{
		"core/internal/testmain/.keep",
		"core/internal/testrecords/.keep",
		"core/internal/testcatalog/.keep",
	} {
		copyFile(path)
	}
	copyFile("tests/crypto/admission.go")
	copyFile("tests/gcp/admission.go")
	copyFile("tests/gcpcredentials/admission.go")
	copyFile("tests/full/admission.go")
	copyFile("tests/hermetic/hermetic.mod")
	copyFile("tests/hermetic/hermetic.sum")
	for _, group := range []string{"tests/shared", "tests/hermetic"} {
		entries, err := os.ReadDir(filepath.Join(source, group))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), "_test.go") {
				copyFile(filepath.Join(group, entry.Name()))
			}
		}
	}
	telemetryConfigs, err := filepath.Glob(filepath.Join(source, "tests/telemetry/*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, config := range telemetryConfigs {
		relative, err := filepath.Rel(source, config)
		if err != nil {
			t.Fatal(err)
		}
		copyFile(relative)
	}
	copyFile(".golangci.yml")
	copyFile(".gitignore")
	copyFile("Makefile")
	makefile := filepath.Join(root, "Makefile")
	makebody, err := os.ReadFile(makefile)
	if err != nil || strings.Count(string(makebody), "tests/scripts/test lint") != 1 {
		t.Fatal("copied lint make target changed", err)
	}
	writeBootstrapFixture(t, makefile, []byte(strings.Replace(string(makebody), "tests/scripts/test lint", fmt.Sprintf("tests/scripts/test lint --parallel=%d", bootstrapFixtureParallel(t)), 1)), 0600)
	copyFile("tests/workflows/check.json")
	suites, err := filepath.Glob(filepath.Join(source, "tests/suites/*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, suite := range suites {
		relative, err := filepath.Rel(source, suite)
		if err != nil {
			t.Fatal(err)
		}
		copyFile(relative)
	}
	copyFile("tests/environments/hermetic.json")
	writeBootstrapFixture(t, filepath.Join(root, "core/internal/preserved/sentinel"), []byte("existing Core file"), 0600)
	writeBootstrapFixture(t, filepath.Join(temporary, "enkv-test-unrelated/sentinel"), []byte("unrelated temporary file"), 0600)
	for _, args := range [][]string{{"init", "--quiet"}, {"add", ".gitignore"}, {"-c", "user.name=Local Test", "-c", "user.email=local@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Fixture"}} {
		command := exec.Command("git", args...)
		command.Dir = root
		if body, err := command.CombinedOutput(); err != nil {
			t.Fatalf("fixture source identity: %v\n%s", err, body)
		}
	}
	rolePath := filepath.Join(fixture, "setup-role-pids")
	roleLiteral := "'" + strings.ReplaceAll(rolePath, "'", "'\"'\"'") + "'"
	// Changes apply only to this source-bound copied fixture.
	for _, replacement := range []struct{ path, from, to string }{
		{"tests/scripts/bootstrap.go", `exec.Command("go", "build",`,
			fmt.Sprintf(`exec.Command("go", "build", "-p=%d",`, bootstrapFixtureParallel(t))},
		{"tests/scripts/setup-supervisor", `GOFLAGS="-trimpath -p=4"`,
			fmt.Sprintf(`GOFLAGS="-trimpath -p=%d"`, bootstrapFixtureParallel(t))},
		{"tests/shared/runner/resource_locks.go",
			`return openResourceLocks(filepath.Join(parent, fmt.Sprintf("enkv-test-resources-%d", os.Getuid())))`,
			fmt.Sprintf(`return openResourceLocks(filepath.Join(parent, fmt.Sprintf("%%s", %q)))`, filepath.Join(filepath.Base(fixture), "a"))},
		{"tests/scripts/setup-supervisor",
			`resource_root="$resource_parent/enkv-test-resources-$(id -u)"`,
			fmt.Sprintf(`resource_root=%q`, resources)},
		{"tests/shared/runner/supervisor_invocation.go",
			`supervisorInvocationStageParent(root, os.TempDir(), home)`,
			fmt.Sprintf(`supervisorInvocationStageParent(root, %q, home)`, stageParent)},
		{"tests/scripts/setup-supervisor", `owner_pid=$$`,
			"owner_pid=$$\nprintf 'owner=%s\\n' \"$owner_pid\" > " + roleLiteral},
		{"tests/scripts/setup-supervisor", `compiler=$!`,
			"compiler=$!\nprintf 'compiler=%s\\n' \"$compiler\" >> " + roleLiteral},
		{"tests/scripts/setup-supervisor", `finalizer=$!`,
			"finalizer=$!\nprintf 'finalizer=%s\\n' \"$finalizer\" >> " + roleLiteral},
	} {
		path := filepath.Join(root, replacement.path)
		body, err := os.ReadFile(path)
		if err != nil || strings.Count(string(body), replacement.from) != 1 {
			t.Fatal("fixture resource source changed", replacement.path, err)
		}
		if err := os.WriteFile(path, []byte(strings.Replace(string(body), replacement.from, replacement.to, 1)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if configure != nil {
		configure(root)
	}
	stdout, stderr, status := runBootstrapProcess(t, root, temporary, "/bin/bash", filepath.Join(root, "tests/scripts/setup-supervisor"))
	if status != 0 || stderr != "" || !strings.Contains(stdout, "Supervisor setup complete:") {
		owner, compiler, finalizer, fields := bootstrapSetupRolePIDs(rolePath)
		t.Fatalf("fixture supervisor setup: status=%d stdout=%q stderr=%q role_pid_fields=%d owner_pid=%d compiler_pid=%d finalizer_pid=%d", status, stdout, stderr, fields, owner, compiler, finalizer)
	}
	assertBootstrapResourcesSettled(t, temporary)
	return root, temporary
}

func bootstrapSetupRolePIDs(path string) (owner, compiler, finalizer, fields int) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	body, readErr := io.ReadAll(io.LimitReader(file, 129))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(body) > 128 {
		return
	}
	fields, err = fmt.Sscanf(string(body), "owner=%d\ncompiler=%d\nfinalizer=%d", &owner, &compiler, &finalizer)
	if err != nil && !errors.Is(err, io.EOF) || owner < 0 || compiler < 0 || finalizer < 0 {
		return 0, 0, 0, 0
	}
	return
}

func writeBootstrapFixture(t *testing.T, path string, body []byte, mode fs.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, mode); err != nil {
		t.Fatal(err)
	}
}

func bootstrapEnvironment(temporary string) []string {
	overrides := map[string]string{
		"TMPDIR": temporary, "GOTMPDIR": temporary,
		"GOWORK": "off", "GOTOOLCHAIN": "local", "GOFLAGS": "-trimpath",
		"GOPROXY": "off", "GOSUMDB": "off", "GONOPROXY": "none",
		// Go VCS stamping must observe the copied index without refreshing it.
		"GIT_OPTIONAL_LOCKS": "0",
	}
	var result []string
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if _, replaced := overrides[key]; !replaced {
			result = append(result, item)
		}
	}
	for key, value := range overrides {
		result = append(result, key+"="+value)
	}
	return result
}

type bootstrapFile struct {
	mode fs.FileMode
	hash [sha256.Size]byte
}

func bootstrapTree(t *testing.T, root string) map[string]bootstrapFile {
	t.Helper()
	files := make(map[string]bootstrapFile)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		var body []byte
		if info.Mode()&os.ModeSymlink != 0 {
			target, readErr := os.Readlink(path)
			if readErr != nil {
				return readErr
			}
			body = []byte(target)
		} else if !entry.IsDir() {
			body, err = os.ReadFile(path)
			if err != nil {
				return err
			}
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files[relative] = bootstrapFile{mode: info.Mode(), hash: sha256.Sum256(body)}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func assertBootstrapTree(t *testing.T, name string, before, after map[string]bootstrapFile) {
	t.Helper()
	for path, want := range before {
		if got, exists := after[path]; !exists || got != want {
			t.Errorf("%s changed existing path %s", name, path)
		}
	}
	for path := range after {
		if _, exists := before[path]; !exists {
			t.Errorf("%s retained new path %s", name, path)
		}
	}
}

// full_only: false
func TestLauncherOrdinaryFocusUsesResolvedArtifact(t *testing.T) {
	root, temporary := bootstrapFixture(t)
	for path, source := range map[string]string{
		"tests/shared/runner/focus_fixture_test.go":  "package main\nimport \"testing\"\n// full_only: false\nfunc TestRunnerArtifact(t *testing.T){t.Run(\"child\",func(t *testing.T){})}\n// full_only: false\nfunc TestDuplicateArtifact(t *testing.T){}\n",
		"tests/shared/records/focus_fixture_test.go": "package records\nimport \"testing\"\n// full_only: false\nfunc TestRecordArtifact(t *testing.T){}\n",
		"tests/shared/catalog/focus_fixture_test.go": "package catalog\nimport \"testing\"\n// full_only: false\nfunc TestCatalogArtifact(t *testing.T){}\n",
		"tests/scripts/bootstrap_test.go":            "package main\nimport \"testing\"\n// full_only: false\nfunc TestLauncherArtifact(t *testing.T){t.Run(\"empty\",func(t *testing.T){})}\n// full_only: false\nfunc TestDuplicateArtifact(t *testing.T){}\n",
	} {
		writeBootstrapFixture(t, filepath.Join(root, path), []byte(source), 0600)
	}
	workflow := filepath.Join(root, "tests/workflows/focus.json")
	writeBootstrapFixture(t, workflow, []byte(`{"schema_version":1,"name":"focus","steps":[{"id":"runner","kind":"runner-tests"}]}`), 0600)
	launcher := filepath.Join(root, "tests/scripts/test")
	// The fixture resource owner keeps one stable tool lock inode across invocations.
	lockID := sha256.Sum256([]byte(root))
	lockPath := filepath.Join(filepath.Dir(temporary), "a", fmt.Sprintf("tool-%x.lock", lockID[:]))
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if os.IsExist(err) {
		lock, err = os.OpenFile(lockPath, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	}
	if err != nil {
		t.Fatal(err)
	}
	lockIdentity, statErr := lock.Stat()
	if closeErr := lock.Close(); statErr != nil || closeErr != nil || !lockIdentity.Mode().IsRegular() || lockIdentity.Size() != 0 {
		t.Fatal("fixture tool lock invalid", statErr, closeErr)
	}
	beforeTemporary := bootstrapTree(t, temporary)
	for _, row := range []struct {
		name, request, owner string
		valid                bool
	}{
		{"runner", "TestRunnerArtifact/child", "tests/shared/runner", true},
		{"launcher", "TestLauncherArtifact/empty", "tests/scripts/bootstrap.go+bootstrap_test.go", true},
		{"records", "TestRecordArtifact", "tests/shared/records", true},
		{"catalog", "TestCatalogArtifact", "tests/shared/catalog", true},
		{"duplicate", "TestDuplicateArtifact", "", false},
		{"unknown", "TestMissingArtifact", "", false},
		{"missing-child", "TestRunnerArtifact/missing", "", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			for _, command := range []string{"plan", "run"} {
				stdout, stderr, status := runBootstrapProcess(t, root, temporary, launcher, command, "--workflow", workflow, "--step", "runner", "--test", row.request)
				// Preview leaves compiled ownership and dynamic child existence unresolved.
				valid := row.valid || command == "plan"
				if (status == 0) != valid {
					t.Fatalf("artifact selection differs: command=%s status=%d stdout=%q stderr=%q", command, status, stdout, stderr)
				}
				if valid && command == "plan" && (!strings.Contains(stdout, `"kind": "selection_preview"`) || !strings.Contains(stdout, `"unresolved"`) || strings.Contains(stdout, `"ordinary_preparation"`)) {
					t.Fatal("preview omitted unresolved facts or claimed compilation", stdout)
				}
				if valid && command == "run" {
					owner := ""
					for _, line := range strings.Split(stdout, "\n") {
						var result struct {
							Type     string `json:"type"`
							Ordinary struct {
								Focus struct {
									Artifact string `json:"artifact"`
								} `json:"focus"`
							} `json:"ordinary"`
						}
						if json.Unmarshal([]byte(line), &result) == nil && result.Type == "test_result" {
							owner = result.Ordinary.Focus.Artifact
						}
					}
					if owner != row.owner {
						t.Fatal("run omitted its actual resolved artifact owner", owner, stdout)
					}
				}
				if command == "plan" && valid && (strings.Contains(stdout, root) || strings.Contains(stdout, temporary)) {
					t.Fatal("ordinary plan exposed a private absolute input path", stdout)
				}
				if !valid && row.name != "missing-child" && strings.Contains(stdout, "Validated") {
					t.Fatal("invalid owner executed tests", stdout)
				}
				assertBootstrapTree(t, "temporary directory", beforeTemporary, bootstrapTree(t, temporary))
				current, err := os.Lstat(lockPath)
				before, beforeOK := lockIdentity.Sys().(*syscall.Stat_t)
				if err != nil {
					t.Fatal(err)
				}
				after, afterOK := current.Sys().(*syscall.Stat_t)
				if !beforeOK || !afterOK || before.Ino == 0 || before.Ino != after.Ino || before.Uid != after.Uid || !current.Mode().IsRegular() || current.Mode().Perm() != 0600 {
					t.Fatal("invocation replaced its stable fixture tool lock")
				}
			}
		})
	}
}

// full_only: false
func TestFreshLauncherPathsDoNotReadHistoricalResults(t *testing.T) {
	root, temporary := bootstrapFixture(t)
	for path, source := range map[string]string{
		"tests/shared/records/history_probe_test.go": "package records\nimport \"testing\"\n// full_only: false\nfunc TestHistoryRecordProbe(t *testing.T){}\n",
		"tests/shared/catalog/history_probe_test.go": "package catalog\nimport \"testing\"\n// full_only: false\nfunc TestHistoryCatalogProbe(t *testing.T){}\n",
		"tests/scripts/bootstrap_test.go":            "package main\nimport \"testing\"\n// full_only: false\nfunc TestHistoryLauncherProbe(t *testing.T){}\n",
	} {
		writeBootstrapFixture(t, filepath.Join(root, path), []byte(source), 0600)
	}
	marker := filepath.Join(filepath.Dir(root), "history-lookups")
	layout := filepath.Join(root, "tests/shared/records/layout.go")
	body, err := os.ReadFile(layout)
	if err != nil {
		t.Fatal(err)
	}
	declaration := "func ResolveRun(root, id string) (string, error) {\n"
	if bytes.Count(body, []byte(declaration)) != 1 {
		t.Fatal("historical lookup fixture no longer identifies one entry point")
	}
	probe := fmt.Sprintf(`
	lookup, auditErr := os.OpenFile(%q, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if auditErr != nil { return "", auditErr }
	_, auditErr = lookup.WriteString(id + "\n")
	closeErr := lookup.Close()
	if auditErr != nil { return "", auditErr }
	if closeErr != nil { return "", closeErr }
`, marker)
	writeBootstrapFixture(t, layout, bytes.Replace(body, []byte(declaration), []byte(declaration+probe), 1), 0600)
	// The instrumentation exists only in the copied source. Reinstallation binds
	// the fixture supervisor to those exact bytes before it launches any command.
	stdout, stderr, status := runBootstrapProcess(t, root, temporary, "/bin/bash", filepath.Join(root, "tests/scripts/setup-supervisor"))
	if status != 0 {
		t.Fatalf("instrumented supervisor setup failed: status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	fixture := fmt.Sprintf(`package main
import (
 "io"
 "os"
 "path/filepath"
 "strings"
 "testing"
 records "enkv.sh/core/internal/testrecords"
)
// full_only: false
func TestHistoryCurrentPreparation(t *testing.T) {
 for _, suite := range []string{"hermetic", "live"} {
  state, err := newRunState(%q, runRequest{Suite:suite,Provider:"memory"}, records.Source{}, "fixture")
  if err != nil { t.Fatal(err) }
  if err := state.save(); err != nil { t.Fatal(err) }
  if err := state.privateOwner.verify(); err != nil { t.Fatal(err) }
  if suite == "hermetic" {
   if err := state.finishCurrentRun(io.Discard,nil); err != nil { t.Fatal(err) }
   if _,err := os.Stat(state.directory); !os.IsNotExist(err) { t.Fatal("hermetic current files survived",err) }
  } else {
   // This fixture starts no worker or provider operation. It owns this newly
   // created empty packet and removes only that packet after the check.
   if err := state.privateOwner.remove(); err != nil { t.Fatal(err) }
   if err := os.RemoveAll(state.directory); err != nil { t.Fatal(err) }
  }
 }
}
// full_only: false
func TestHistoryExactRecoveryLookup(t *testing.T) {
 root,err:=filepath.EvalSymlinks(t.TempDir());if err!=nil{t.Fatal(err)}
 id:=strings.Repeat("b",32)
 want:=filepath.Join(root,"tests/live/runs/undated",id)
 if err:=os.MkdirAll(want,0700);err!=nil{t.Fatal(err)}
 saved:=[]byte("original exact recovery input\n")
 if err:=os.WriteFile(filepath.Join(want,"input.json"),saved,0600);err!=nil{t.Fatal(err)}
 got,err:=runPath(root,"live","runs",id)
 if err!=nil || got!=want {t.Fatal("exact recovery lookup failed",got,err)}
 body,err:=os.ReadFile(filepath.Join(got,"input.json"))
 if err!=nil || string(body)!=string(saved){t.Fatal("exact original input changed",err)}
}
`, root)
	writeBootstrapFixture(t, filepath.Join(root, "tests/shared/runner/history_fixture_test.go"), []byte(fixture), 0600)
	workflow := filepath.Join(root, "tests/workflows/history.json")
	writeBootstrapFixture(t, workflow, []byte(`{"schema_version":1,"name":"history","profile":"dev","steps":[{"id":"current","kind":"runner-tests"}]}`), 0600)

	malformed := filepath.Join(root, "tests/workflows/runs/2000-01-01/broken/workflow.json")
	malformedBytes := []byte("{ malformed historical record\n")
	writeBootstrapFixture(t, malformed, malformedBytes, 0600)
	unreadable := filepath.Join(root, "tests/live/runs/2000-01-01")
	unreadableFile := filepath.Join(unreadable, "old-input.json")
	unreadableBytes := []byte("unresolved original input\n")
	writeBootstrapFixture(t, unreadableFile, unreadableBytes, 0600)
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(unreadable, 0700); err != nil {
			t.Error("restore synthetic history permissions", err)
		}
	})
	foreign, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeBootstrapFixture(t, filepath.Join(foreign, "sentinel"), []byte("foreign historical contents"), 0600)
	link := filepath.Join(root, "tests/hermetic/runs/2000-01-01")
	if err := os.MkdirAll(filepath.Dir(link), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(foreign, link); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(root, "tests/scripts/test")
	for _, args := range [][]string{
		{"list"},
		{"plan", "--workflow", workflow, "--step", "current", "--test", "TestHistoryCurrentPreparation"},
		{"run", "--workflow", workflow, "--step", "current", "--test", "TestHistoryCurrentPreparation"},
	} {
		stdout, stderr, status := runBootstrapProcess(t, root, temporary, launcher, args...)
		if status != 0 {
			t.Fatalf("fresh %s depended on old results: status=%d stdout=%q stderr=%q", args[0], status, stdout, stderr)
		}
		if audit, err := os.ReadFile(marker); !os.IsNotExist(err) {
			t.Fatalf("fresh %s entered historical lookup: rows=%q err=%v", args[0], audit, err)
		}
	}
	if body, err := os.ReadFile(malformed); err != nil || !bytes.Equal(body, malformedBytes) {
		t.Fatal("fresh command changed malformed history", err)
	}
	if info, err := os.Lstat(unreadable); err != nil || info.Mode().Perm() != 0 {
		t.Fatal("fresh command changed historical permissions", err)
	}
	if err := os.Chmod(unreadable, 0700); err != nil {
		t.Fatal(err)
	}
	if body, err := os.ReadFile(unreadableFile); err != nil || !bytes.Equal(body, unreadableBytes) {
		t.Fatal("fresh command changed unresolved input", err)
	}
	if got, err := os.Readlink(link); err != nil || got != foreign {
		t.Fatal("fresh command changed historical symlink", err)
	}
	if body, err := os.ReadFile(filepath.Join(foreign, "sentinel")); err != nil || string(body) != "foreign historical contents" {
		t.Fatal("fresh command changed foreign historical contents", err)
	}
	stdout, stderr, status = runBootstrapProcess(t, root, temporary, launcher, "run", "--workflow", workflow, "--step", "current", "--test", "TestHistoryExactRecoveryLookup")
	if status != 0 {
		t.Fatalf("exact historical control failed: status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	audit, err := os.ReadFile(marker)
	if err != nil || string(audit) != strings.Repeat("b", 32)+"\n" {
		t.Fatalf("historical access probe lacked its positive control: rows=%q err=%v", audit, err)
	}
}

// full_only: false
func TestLauncherCurrentResultsAndFailuresRemainVisible(t *testing.T) {
	root, temporary := bootstrapFixture(t)
	fixture := fmt.Sprintf(`package main
import("os";"path/filepath";"testing")
// full_only: false
func TestCurrentResultTransport(t *testing.T) {
 t.Run("passed",func(t *testing.T){})
 t.Run("failed",func(t *testing.T){t.Fatal("hermetic transport assertion: expected 7, observed 9")})
 t.Run("source_changed",func(t *testing.T){if err:=os.WriteFile(filepath.Join(%q,"current-source-change.txt"),[]byte("changed source\n"),0600);err!=nil{t.Fatal(err)}})
}
`, root)
	writeBootstrapFixture(t, filepath.Join(root, "tests/shared/runner/current_result_fixture_test.go"), []byte(fixture), 0600)
	for path, source := range map[string]string{
		"tests/shared/records/current_result_test.go": "package records\nimport \"testing\"\n// full_only: false\nfunc TestCurrentRecordProbe(t *testing.T){}\n",
		"tests/shared/catalog/current_result_test.go": "package catalog\nimport \"testing\"\n// full_only: false\nfunc TestCurrentCatalogProbe(t *testing.T){}\n",
		"tests/scripts/bootstrap_test.go":             "package main\nimport \"testing\"\n// full_only: false\nfunc TestCurrentLauncherProbe(t *testing.T){}\n",
	} {
		writeBootstrapFixture(t, filepath.Join(root, path), []byte(source), 0600)
	}
	workflow := filepath.Join(root, "tests/workflows/current-results.json")
	writeBootstrapFixture(t, workflow, []byte(`{"schema_version":1,"name":"current-results","profile":"dev","steps":[{"id":"current","kind":"runner-tests","repetitions":2}]}`), 0600)
	launcher := filepath.Join(root, "tests/scripts/test")
	for _, condition := range []string{"passed", "failed", "source_changed", "runner_compile_failed", "bootstrap_compile_failed"} {
		t.Run(condition, func(t *testing.T) {
			requested := condition
			if condition == "runner_compile_failed" {
				requested = "passed"
				broken := filepath.Join(root, "tests/shared/runner/current_result_broken.go")
				writeBootstrapFixture(t, broken, []byte("package main\nfunc broken(\n"), 0600)
				t.Cleanup(func() {
					if err := os.Remove(broken); err != nil {
						t.Error(err)
					}
				})
			}
			if condition == "bootstrap_compile_failed" {
				requested = "passed"
				writeBootstrapFixture(t, filepath.Join(root, "tests/scripts/bootstrap.go"), []byte("package main\nfunc broken(\n"), 0600)
				stdout, stderr, status := runBootstrapProcess(t, root, temporary, "/bin/bash", filepath.Join(root, "tests/scripts/setup-supervisor"))
				if status != 0 || stderr != "" || !strings.Contains(stdout, "Supervisor setup complete:") {
					t.Fatalf("bound bootstrap asset setup: status=%d stdout=%q stderr=%q", status, stdout, stderr)
				}
				assertBootstrapResourcesSettled(t, temporary)
			}
			requested = "TestCurrentResultTransport/" + requested
			stdout, stderr, status := runBootstrapProcess(t, root, temporary, launcher, "run", "--race", "--workflow", workflow, "--step", "current", "--test", requested)
			passed := condition == "passed" || condition == "source_changed"
			if (status == 0) != passed {
				t.Fatalf("current result terminal differs: status=%d stdout=%q stderr=%q", status, stdout, stderr)
			}
			assertBootstrapResourcesSettled(t, temporary)
			type currentResult struct {
				Type, Step, Outcome string
				Ordinary            struct {
					Race  *bool
					Tests []struct{ Name, Outcome string }
				}
			}
			var results []currentResult
			for _, line := range strings.Split(stdout, "\n") {
				var result currentResult
				if json.Unmarshal([]byte(line), &result) == nil && result.Type == "test_result" {
					results = append(results, result)
				}
			}
			if condition == "runner_compile_failed" || condition == "bootstrap_compile_failed" {
				marker := "current_result_broken.go"
				if condition == "bootstrap_compile_failed" {
					marker = "bootstrap.go"
				}
				if len(results) != 0 || !strings.Contains(stdout+stderr, marker) {
					t.Fatal("compiler failure lost its diagnostic or invented test results", stdout, stderr)
				}
			} else {
				if len(results) != 2 {
					t.Fatal("explicit repetitions lost current results", len(results), stdout)
				}
				for _, result := range results {
					want, terminal := "passed", "pass"
					if !passed {
						want, terminal = "failed", "fail"
					}
					if result.Step == "" || result.Outcome != want || result.Ordinary.Race == nil || !*result.Ordinary.Race {
						t.Fatal("current result lost selection outcome or accepted race setting", result)
					}
					found := false
					for _, test := range result.Ordinary.Tests {
						if test.Name == requested && test.Outcome == terminal {
							found = true
						}
					}
					if !found {
						t.Fatal("current result omitted its requested terminal", result)
					}
				}
			}
			if condition == "source_changed" && !strings.Contains(stdout, "Source changed during execution") {
				t.Fatal("source edit lost its informational note", stdout)
			}
			if condition == "failed" && !strings.Contains(stdout+stderr, "expected 7, observed 9") {
				t.Fatal("failed attempt lost hermetic assertion text")
			}
			for _, relative := range []string{"tests/qualification", "tests/workflows/runs", "tests/hermetic/runs", "tests/components/runs"} {
				if _, err := os.Lstat(filepath.Join(root, relative)); !os.IsNotExist(err) {
					t.Fatal("current result recreated an old result tree", relative, err)
				}
			}
		})
	}
}

// full_only: false
func TestBootstrapLocalModfileCapturesOverlayAndRegisteredOwners(t *testing.T) {
	root, temporary, input, overlay := bootstrapModuleFixture(t)
	output := filepath.Join(t.TempDir(), "captured.mod")
	stdout, stderr, status := runBootstrapProcess(t, root, temporary, "go", "run", "-mod=readonly", filepath.Join(bootstrapSourceRoot(t), "tests/scripts/bootstrap.go"), "modfile", root, filepath.Join(root, "core"), input, overlay, output)
	if status != 0 || stdout != "" || stderr != "" {
		t.Fatalf("prepare local module: status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "require enkv.sh/telemetry v0.1.0") || strings.Contains(string(body), "example.invalid/original") || !strings.Contains(string(body), "replace enkv.sh/sdk/generator => ../../enkv-extensions/sdk/generator") {
		t.Fatal("effective module source or registered owner differs", string(body))
	}
	sum, err := os.ReadFile(strings.TrimSuffix(output, ".mod") + ".sum")
	if err != nil || string(sum) != "example.invalid/captured v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n" {
		t.Fatal("effective module checksum source differs", err, string(sum))
	}
	// The retained capture has its own identity after its source overlay changes.
	writeBootstrapFixture(t, filepath.Join(root, "backing.mod"), []byte("module example.invalid/changed\n"), 0600)
	again, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(body, again) {
		t.Fatal("retained module input changed", err)
	}
	// Ask stock Go to load the exact locally pinned dependency from this capture.
	stdout, stderr, status = runBootstrapProcess(t, filepath.Join(root, "core"), temporary, "go", "list", "-mod=readonly", "-modfile="+output, "-m", "-json", "enkv.sh/telemetry")
	var dependency struct {
		Path, Version string
		Replace       *struct{ Path, Dir string }
	}
	if status != 0 || stderr != "" || json.Unmarshal([]byte(stdout), &dependency) != nil || dependency.Path != "enkv.sh/telemetry" || dependency.Version != "v0.1.0" || dependency.Replace == nil || dependency.Replace.Path != "../telemetry" || dependency.Replace.Dir != filepath.Join(root, "telemetry") {
		t.Fatalf("captured local dependency differs: status=%d stdout=%q stderr=%q", status, stdout, stderr)
	}
}

// full_only: false
func TestBootstrapLocalModfileRefusesUnownedAndAmbiguousInputs(t *testing.T) {
	for _, name := range []string{"quoted versioned replacement", "commented replacement block", "wrong main identity", "unknown directory", "duplicate inventory field", "overlapping inventory owner", "source symlink", "owned output", "owned checksum output"} {
		t.Run(name, func(t *testing.T) {
			root, temporary, input, overlay := bootstrapModuleFixture(t)
			directory := filepath.Join(root, "core")
			output := filepath.Join(t.TempDir(), "captured.mod")
			inventory := filepath.Join(filepath.Dir(root), "enkv-extensions/distribution/modules.json")
			diagnostic := ""
			switch name {
			case "quoted versioned replacement":
				diagnostic = "first-party replacement"
				writeBootstrapFixture(t, filepath.Join(root, "backing.mod"), []byte("module enkv.sh/core\n\ngo 1.27.0\nreplace \"enkv.sh/telemetry\" v0.0.0 => ../foreign\n"), 0600)
			case "commented replacement block":
				diagnostic = "first-party replacement"
				writeBootstrapFixture(t, filepath.Join(root, "backing.mod"), []byte("module enkv.sh/core\n\ngo 1.27.0\nreplace ( // valid module syntax\n enkv.sh/telemetry => ../foreign\n)\n"), 0600)
			case "wrong main identity":
				diagnostic = "main module identity differs"
				writeBootstrapFixture(t, filepath.Join(root, "backing.mod"), []byte("module enkv.sh/crypto\n\ngo 1.27.0\n"), 0600)
			case "unknown directory":
				diagnostic = "module directory is not registered"
				directory = filepath.Join(root, "unregistered")
				if err := os.Mkdir(directory, 0700); err != nil {
					t.Fatal(err)
				}
			case "duplicate inventory field":
				diagnostic = "duplicate inventory field"
				body, err := os.ReadFile(inventory)
				if err != nil {
					t.Fatal(err)
				}
				writeBootstrapFixture(t, inventory, bytes.Replace(body, []byte(`"schema_version": 1`), []byte(`"schema_version": 1, "schema_version": 1`), 1), 0600)
			case "overlapping inventory owner":
				diagnostic = "overlapping module ownership"
				var inv map[string]any
				body, err := os.ReadFile(inventory)
				if err != nil || json.Unmarshal(body, &inv) != nil {
					t.Fatal("read inventory", err)
				}
				rows := inv["modules"].([]any)
				duplicate := make(map[string]any)
				for key, value := range rows[0].(map[string]any) {
					duplicate[key] = value
				}
				duplicate["selector"] = "other-core"
				rows = append(rows, duplicate)
				inv["modules"] = rows
				body, err = json.Marshal(inv)
				if err != nil {
					t.Fatal(err)
				}
				writeBootstrapFixture(t, inventory, body, 0600)
			case "source symlink":
				diagnostic = "module source path refused"
				if err := os.Rename(filepath.Join(root, "telemetry"), filepath.Join(root, "telemetry-target")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(root, "telemetry-target"), filepath.Join(root, "telemetry")); err != nil {
					t.Fatal(err)
				}
			case "owned output":
				diagnostic = "local modfile output already exists"
				writeBootstrapFixture(t, output, []byte("foreign output"), 0600)
			case "owned checksum output":
				diagnostic = "local modfile output already exists"
				writeBootstrapFixture(t, strings.TrimSuffix(output, ".mod")+".sum", []byte("foreign checksum"), 0600)
			}
			before := bootstrapTree(t, root)
			beforeDocs := bootstrapTree(t, filepath.Join(filepath.Dir(root), "enkv-extensions"))
			stdout, stderr, status := runBootstrapProcess(t, root, temporary, "go", "run", "-mod=readonly", filepath.Join(bootstrapSourceRoot(t), "tests/scripts/bootstrap.go"), "modfile", root, directory, input, overlay, output)
			if status == 0 || stdout != "" || !strings.Contains(stderr, diagnostic) {
				t.Fatalf("damaged module input accepted: status=%d stdout=%q stderr=%q", status, stdout, stderr)
			}
			assertBootstrapTree(t, "source", before, bootstrapTree(t, root))
			assertBootstrapTree(t, "inventory", beforeDocs, bootstrapTree(t, filepath.Join(filepath.Dir(root), "enkv-extensions")))
			if name == "owned output" {
				body, err := os.ReadFile(output)
				if err != nil || string(body) != "foreign output" {
					t.Fatal("overwrote foreign output", err)
				}
			}
			if name == "owned checksum output" {
				body, err := os.ReadFile(strings.TrimSuffix(output, ".mod") + ".sum")
				if err != nil || string(body) != "foreign checksum" {
					t.Fatal("overwrote foreign checksum", err)
				}
			}
		})
	}
}

func bootstrapModuleFixture(t *testing.T) (root, temporary, input, overlay string) {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root = filepath.Join(parent, "enkv-core")
	temporary = filepath.Join(parent, "tmp")
	if err := os.MkdirAll(temporary, 0700); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(filepath.Dir(bootstrapSourceRoot(t)), "enkv-extensions/distribution/modules.json"))
	if err != nil {
		t.Fatal(err)
	}
	writeBootstrapFixture(t, filepath.Join(parent, "enkv-extensions/distribution/modules.json"), body, 0600)
	writeBootstrapFixture(t, filepath.Join(root, "core/go.mod"), []byte("module enkv.sh/core\n\ngo 1.27.0\n"), 0600)
	writeBootstrapFixture(t, filepath.Join(root, "telemetry/go.mod"), []byte("module enkv.sh/telemetry\n\ngo 1.27.0\n"), 0600)
	input = filepath.Join(root, "selected.mod")
	writeBootstrapFixture(t, input, []byte("module enkv.sh/core\n\ngo 1.27.0\nrequire example.invalid/original v0.0.0\n"), 0600)
	writeBootstrapFixture(t, strings.TrimSuffix(input, ".mod")+".sum", []byte("example.invalid/original v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"), 0600)
	backing := filepath.Join(root, "backing.mod")
	sum := filepath.Join(root, "backing.sum")
	writeBootstrapFixture(t, backing, []byte("module enkv.sh/core\n\ngo 1.27.0\nrequire enkv.sh/telemetry v0.1.0\n"), 0600)
	writeBootstrapFixture(t, sum, []byte("example.invalid/captured v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"), 0600)
	mapping := struct{ Replace map[string]string }{map[string]string{input: backing, strings.TrimSuffix(input, ".mod") + ".sum": sum}}
	body, err = json.Marshal(mapping)
	if err != nil {
		t.Fatal(err)
	}
	overlay = filepath.Join(root, "overlay.json")
	writeBootstrapFixture(t, overlay, body, 0600)
	return
}

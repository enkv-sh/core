package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func supervisorFixtureParallel(t *testing.T) int {
	t.Helper()
	value := flag.Lookup("test.parallel")
	if value == nil {
		t.Fatal("assigned test parallel setting unavailable")
	}
	parallel, err := strconv.Atoi(value.Value.String())
	if err != nil || parallel < 1 {
		t.Fatal("assigned test parallel setting invalid", value.Value.String(), err)
	}
	return min(parallel, maximumExecutionParallel)
}

// Copied bound sources use one private directory for setup and installed roots.
func copiedSupervisorSetupFixture(t *testing.T) (root, resources, controls, script string) {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root, resources, controls = filepath.Join(parent, "checkout"), filepath.Join(parent, "resources"), filepath.Join(parent, "controls")
	if err := os.Mkdir(controls, 0700); err != nil {
		t.Fatal(err)
	}
	ps := filepath.Join(controls, "ps")
	if err := os.WriteFile(ps, []byte("#!/bin/bash\nprintf 'unexpected ps invocation\\n' > \"$0.called\"\nexit 97\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", controls+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Cleanup(func() {
		if _, err := os.Lstat(ps + ".called"); !errors.Is(err, os.ErrNotExist) {
			t.Error("setup invoked ps", err)
		}
	})
	source := filepath.Clean(filepath.Join(filepath.Dir(savedWorkflowPath(t, "dev")), "../.."))
	for _, name := range supervisorFixturePaths {
		body, err := os.ReadFile(filepath.Join(source, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		destination := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destination, body, 0700); err != nil {
			t.Fatal(err)
		}
	}
	copyModuleInventoryFixture(t, root)
	script = filepath.Join(root, "tests/scripts/setup-supervisor")
	body, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	original := `resource_root="$resource_parent/enkv-test-resources-$(id -u)"`
	if strings.Count(string(body), original) != 1 {
		t.Fatal("copied setup resource construction changed")
	}
	body = []byte(strings.Replace(string(body), original, "resource_root='"+strings.ReplaceAll(resources, "'", "'\"'\"'")+"'", 1))
	compilerFlags := `GOFLAGS="-trimpath -p=4"`
	if strings.Count(string(body), compilerFlags) != 1 {
		t.Fatal("copied setup compiler allowance changed")
	}
	assignedFlags := fmt.Sprintf(`GOFLAGS="-trimpath -p=%d"`, supervisorFixtureParallel(t))
	body = []byte(strings.Replace(string(body), compilerFlags, assignedFlags, 1))
	if err := os.WriteFile(script, body, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "tests/shared/runner/resource_locks.go")
	body, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(body), "func defaultResourceLocks() (*resourceLocks, error) {")
	end := strings.Index(string(body), "\nfunc openResourceLocks(")
	if start < 0 || end <= start {
		t.Fatal("copied native resource construction changed")
	}
	replacement := fmt.Sprintf("func defaultResourceLocks() (*resourceLocks, error) {\n return openResourceLocks(%q)\n}\n", resources)
	body = []byte(string(body[:start]) + replacement + string(body[end:]))
	if err := os.WriteFile(path, body, 0700); err != nil {
		t.Fatal(err)
	}
	return root, resources, controls, script
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

func installControlledSetupRoles(t *testing.T, controls, mode string) {
	t.Helper()
	t.Setenv("ENKV_SETUP_FIXTURE_CONTROL", controls)
	t.Setenv("ENKV_SETUP_FIXTURE_MODE", mode)
	compiler := `#!/bin/bash
set -euo pipefail
if [ -e /dev/fd/8 ]; then printf 'compiler inherited fd8\n' >&2; exit 19; fi
if [ -e /dev/fd/9 ]; then printf 'compiler inherited fd9\n' >&2; exit 19; fi
stage=${GOCACHE%/cache}
if [ ! -f "$stage/compiler.release" ] || [ ! "$stage/core/go.mod" -ef "$stage/core/internal/supervisor/setup-inputs/core/go.mod.source" ]; then exit 18; fi
printf '%s\n%s\n%s\n' "$$" "$GOFLAGS" "$*" > "$ENKV_SETUP_FIXTURE_CONTROL/compiler"
if [ "$ENKV_SETUP_FIXTURE_MODE" = compiler_body_died ]; then
 /bin/sleep 30 &
 printf '%s\n' "$!" > "$ENKV_SETUP_FIXTURE_CONTROL/compiler.child"
fi
while [ ! -f "$ENKV_SETUP_FIXTURE_CONTROL/compiler.release" ]; do /bin/sleep 0.01; done
if [ "$ENKV_SETUP_FIXTURE_MODE" = compiler_body_died ]; then kill -KILL "$$"; fi
if [ "$ENKV_SETUP_FIXTURE_MODE" = compiler_status_three ]; then exit 3; fi
if [ "$ENKV_SETUP_FIXTURE_MODE" = compiler_stopped ]; then kill -STOP "$$"; fi
if [ "$ENKV_SETUP_FIXTURE_MODE" = compiler_failed ]; then exit 7; fi
cp "$ENKV_SETUP_FIXTURE_CONTROL/candidate" "$stage/supervisor-candidate"
chmod 700 "$stage/supervisor-candidate"
`
	finalizer := `#!/bin/bash
set -euo pipefail
if [ -e /dev/fd/8 ]; then printf 'finalizer inherited fd8\n' >&2; exit 20; fi
if [ -e /dev/fd/9 ]; then printf 'finalizer inherited fd9\n' >&2; exit 20; fi
stage=
root=
while [ "$#" -gt 0 ]; do
 case "$1" in --stage) stage=$2; shift ;; --root) root=$2; shift ;; esac
 shift
done
if [ "$ENKV_SETUP_FIXTURE_MODE" = finalizer_body_died ]; then
 /bin/sleep 30 &
 printf '%s\n' "$!" > "$ENKV_SETUP_FIXTURE_CONTROL/finalizer.child"
fi
printf '%s\n' "$$" > "$ENKV_SETUP_FIXTURE_CONTROL/finalizer"
while [ ! -f "$ENKV_SETUP_FIXTURE_CONTROL/finalizer.release" ]; do /bin/sleep 0.01; done
if [ "$ENKV_SETUP_FIXTURE_MODE" = finalizer_stopped ]; then kill -STOP "$$"; fi
if [ "$ENKV_SETUP_FIXTURE_MODE" = finalizer_failed ] || [ "$ENKV_SETUP_FIXTURE_MODE" = finalizer_verified_then_shell_failed ]; then printf 'setup failed after settlement verified: controlled failure\n' >&2; exit 3; fi
if [ "$ENKV_SETUP_FIXTURE_MODE" = finalizer_unverified_failed ]; then exit 9; fi
if [ "$ENKV_SETUP_FIXTURE_MODE" = finalizer_body_died ]; then kill -KILL "$$"; fi
cp "$0" "$root/tests/.supervisor/supervisor"
rm -rf "$stage"
`
	if err := os.WriteFile(filepath.Join(controls, "go"), []byte(compiler), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(controls, "candidate"), []byte(finalizer), 0700); err != nil {
		t.Fatal(err)
	}
}

type setupScriptOutput struct {
	mu     sync.Mutex
	output limitedOutput
}

func (output *setupScriptOutput) Write(body []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	return output.output.Write(body)
}
func (output *setupScriptOutput) String() string {
	output.mu.Lock()
	defer output.mu.Unlock()
	return output.output.String()
}
func (output *setupScriptOutput) Overflow() bool {
	output.mu.Lock()
	defer output.mu.Unlock()
	return output.output.overflow
}

type setupScriptProcess struct {
	command        *exec.Cmd
	done           chan error
	joined         bool
	result         error
	known          map[int]processIdentity
	stdout, stderr *setupScriptOutput
}

func startSetupScript(t *testing.T, root, script string) *setupScriptProcess {
	t.Helper()
	p := &setupScriptProcess{command: exec.Command("/bin/bash", script), done: make(chan error, 1), known: make(map[int]processIdentity), stdout: new(setupScriptOutput), stderr: new(setupScriptOutput)}
	p.command.Dir = root
	p.command.Stdout, p.command.Stderr = p.stdout, p.stderr
	p.command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	p.command.WaitDelay = time.Second
	if err := p.command.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.done <- p.command.Wait() }()
	t.Cleanup(func() {
		for pid, id := range p.known {
			info, err := nativeProcessIdentity(pid)
			if err == nil && info.identity == id {
				if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
					t.Error("fallback role stop", err)
				}
				if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
					t.Error("fallback role PID stop", err)
				}
			} else if err != nil && !errors.Is(err, syscall.ESRCH) {
				t.Error("fallback role identity", err)
			}
		}
		if !p.joined {
			if err := syscall.Kill(-p.command.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
				t.Error("fallback setup stop", err)
			}
			select {
			case <-p.done:
				p.joined = true
			case <-time.After(10 * time.Second):
				t.Error("fallback setup did not join")
			}
		}
		for pid := range p.known {
			if joined, err := groupStopped(pid, nil); !joined {
				t.Error("fallback role group did not settle", pid, err)
			}
		}
	})
	return p
}

func (p *setupScriptProcess) marker(t *testing.T, path string) []byte {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		if body, err := os.ReadFile(path); err == nil && len(body) > 0 && body[len(body)-1] == '\n' {
			return body
		}
		select {
		case err := <-p.done:
			p.joined = true
			t.Fatalf("setup returned before %s: %v stderr=%s", filepath.Base(path), err, p.stderr.String())
		case <-deadline.C:
			t.Fatal("setup marker missing", filepath.Base(path))
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (p *setupScriptProcess) observe(t *testing.T, pid, parent int) processIdentityInfo {
	t.Helper()
	info, err := nativeProcessIdentity(pid)
	if err == nil && info.identity.start != 0 {
		p.known[pid] = info.identity
	}
	if err != nil || info.parent != parent || info.group != pid || info.identity.start == 0 {
		t.Fatal("setup role parent/group identity differs", pid, parent, info, err)
	}
	p.known[pid] = info.identity
	return info
}

func (p *setupScriptProcess) wait(t *testing.T) error {
	t.Helper()
	if p.joined {
		return p.result
	}
	select {
	case err := <-p.done:
		p.joined = true
		p.result = err
		return err
	case <-time.After(20 * time.Second):
		t.Fatal("setup did not return")
		return nil
	}
}

func (p *setupScriptProcess) absent(t *testing.T) {
	t.Helper()
	for pid, id := range p.known {
		info, err := nativeProcessIdentity(pid)
		if err == nil && info.identity == id || err != nil && !errors.Is(err, syscall.ESRCH) {
			t.Error("role remains before fallback", pid, err)
		}
		if !errors.Is(syscall.Kill(-pid, 0), syscall.ESRCH) {
			t.Error("role group remains before fallback", pid)
		}
	}
	if p.stdout.Overflow() || p.stderr.Overflow() {
		t.Error("setup output overflowed")
	}
}

func (p *setupScriptProcess) retained(t *testing.T, resources string) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for !strings.Contains(p.stderr.String(), "native process-group settlement unavailable; machine lock retained") {
		select {
		case err := <-p.done:
			p.joined = true
			p.result = err
			t.Fatalf("unknown setup released its owner: %v stderr=%s", err, p.stderr.String())
		case <-deadline.C:
			t.Fatal("setup did not report retained unknown settlement", p.stderr.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
	locks, err := openResourceLocks(resources)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	lease, err := locks.acquireMachine(ctx, false)
	if lease != nil {
		lease.Close()
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("unknown settlement did not retain machine exclusion", err)
	}
	// This test has native observation; the initial Bash owner does not.
	for pid, id := range p.known {
		deadline := time.Now().Add(processGroupSettlementTimeout)
		for {
			info, err := nativeProcessIdentity(pid)
			if errors.Is(err, syscall.ESRCH) || err == nil && info.identity != id {
				break
			}
			if err != nil {
				t.Fatal("retained role identity unavailable", pid, err)
			}
			if time.Now().After(deadline) {
				t.Fatal("role survived setup stop attempts", pid)
			}
			time.Sleep(processGroupPollInterval)
		}
		if stopped, err := groupStopped(pid, nil); !stopped {
			t.Fatal("role group survived setup stop attempts", pid, err)
		}
	}
	if err := p.command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := p.wait(t); err == nil {
		t.Fatal("terminated incomplete setup passed")
	}
}

// full_only: false
func TestSupervisorSetupScriptJoinsBeforeLockRelease(t *testing.T) {
	for _, mode := range []string{"passed", "compiler_failed", "compiler_status_three", "finalizer_failed", "finalizer_verified_then_shell_failed", "finalizer_unverified_failed", "post_spawn_gate_failed", "compiler_stopped", "finalizer_stopped", "compiler_body_died", "finalizer_body_died", "compiler_hung", "finalizer_hung"} {
		t.Run(mode, func(t *testing.T) {
			root, resources, controls, script := copiedSupervisorSetupFixture(t)
			installControlledSetupRoles(t, controls, mode)
			if strings.HasSuffix(mode, "_hung") {
				body, err := os.ReadFile(script)
				if err != nil {
					t.Fatal(err)
				}
				boundary := "\nstage=\n"
				if strings.Count(string(body), boundary) != 1 {
					t.Fatal("setup staging boundary changed")
				}
				body = []byte(strings.Replace(string(body), boundary, "\nsetup_command_timeout_seconds=2\nstage=\n", 1))
				if err := os.WriteFile(script, body, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "post_spawn_gate_failed" {
				body, err := os.ReadFile(script)
				if err != nil {
					t.Fatal(err)
				}
				gate := `: > "$stage/compiler.release"`
				if strings.Count(string(body), gate) != 1 {
					t.Fatal("compiler release gate changed")
				}
				body = []byte(strings.Replace(string(body), gate, "printf 'ready\\n' > \"$ENKV_SETUP_FIXTURE_CONTROL/postspawn.ready\"\nwhile [ ! -f \"$ENKV_SETUP_FIXTURE_CONTROL/postspawn.release\" ]; do /bin/sleep 0.01 9>&-; done\nfalse\n"+gate, 1))
				if err := os.WriteFile(script, body, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "finalizer_verified_then_shell_failed" {
				body, err := os.ReadFile(script)
				if err != nil {
					t.Fatal(err)
				}
				boundary := "# Status 3 is emitted only by the native finalizer after positive verification."
				if strings.Count(string(body), boundary) != 1 {
					t.Fatal("native finalizer result boundary changed")
				}
				body = []byte(strings.Replace(string(body), boundary, "false\n"+boundary, 1))
				if err := os.WriteFile(script, body, 0700); err != nil {
					t.Fatal(err)
				}
			}
			p := startSetupScript(t, root, script)
			if mode == "post_spawn_gate_failed" {
				p.marker(t, filepath.Join(controls, "postspawn.ready"))
				files, err := filepath.Glob(filepath.Join(root, "tests/.supervisor/setup.*/compiler.ready"))
				if err != nil || len(files) != 1 {
					t.Fatal("compiler ready fact missing", files, err)
				}
				body, err := os.ReadFile(files[0])
				pid, parseErr := strconv.Atoi(strings.TrimSpace(string(body)))
				if err != nil || parseErr != nil {
					t.Fatal("compiler ready identity malformed", err, parseErr)
				}
				p.observe(t, pid, p.command.Process.Pid)
				if err := os.WriteFile(filepath.Join(controls, "postspawn.release"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				fields := strings.Split(strings.TrimSpace(string(p.marker(t, filepath.Join(controls, "compiler")))), "\n")
				if len(fields) != 3 {
					t.Fatal("compiler fact fields differ", fields)
				}
				compilerPID, err := strconv.Atoi(fields[0])
				if err != nil {
					t.Fatal(err)
				}
				p.observe(t, compilerPID, p.command.Process.Pid)
				if fields[1] != fmt.Sprintf("-trimpath -p=%d", supervisorFixtureParallel(t)) || !strings.HasPrefix(fields[2], "build -mod=readonly -tags=enkv_supervisor -o ") {
					t.Fatal("compiler command differs", fields)
				}
				observeDescendant := func(role string, parent int) {
					t.Helper()
					pid, err := strconv.Atoi(strings.TrimSpace(string(p.marker(t, filepath.Join(controls, role+".child")))))
					if err != nil {
						t.Fatal(err)
					}
					info, err := nativeProcessIdentity(pid)
					if err != nil || info.parent != parent || info.group != parent {
						t.Fatal("role descendant lacks exact branch identity", pid, info, err)
					}
					p.known[pid] = info.identity
				}
				if mode == "compiler_body_died" {
					observeDescendant("compiler", compilerPID)
				}
				if mode != "compiler_hung" {
					if err := os.WriteFile(filepath.Join(controls, "compiler.release"), nil, 0600); err != nil {
						t.Fatal(err)
					}
				}
				stoppedPID := 0
				if mode == "compiler_stopped" {
					stoppedPID = compilerPID
				}
				needsFinalizer := strings.HasPrefix(mode, "finalizer_") || mode == "passed"
				if needsFinalizer {
					pid, err := strconv.Atoi(strings.TrimSpace(string(p.marker(t, filepath.Join(controls, "finalizer")))))
					if err != nil {
						t.Fatal(err)
					}
					p.observe(t, pid, p.command.Process.Pid)
					if mode == "finalizer_body_died" {
						observeDescendant("finalizer", pid)
					}
					locks, err := openResourceLocks(resources)
					if err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
					lease, err := locks.acquireMachine(ctx, false)
					cancel()
					if lease != nil {
						lease.Close()
					}
					if !errors.Is(err, context.DeadlineExceeded) {
						t.Fatal("setup released exclusion before finalizer Wait", err)
					}
					if mode != "finalizer_hung" {
						if err := os.WriteFile(filepath.Join(controls, "finalizer.release"), nil, 0600); err != nil {
							t.Fatal(err)
						}
					}
					if mode == "finalizer_stopped" {
						stoppedPID = pid
					}
				}
				if stoppedPID != 0 {
					deadline := time.Now().Add(5 * time.Second)
					for {
						info, err := nativeProcessIdentity(stoppedPID)
						if errors.Is(err, syscall.ESRCH) {
							break
						}
						if err != nil {
							t.Fatal(err)
						}
						if info.state == 'T' {
							if err := p.command.Process.Signal(syscall.SIGTERM); err != nil {
								t.Fatal(err)
							}
							break
						}
						if time.Now().After(deadline) {
							t.Fatal("role did not stop")
						}
						time.Sleep(10 * time.Millisecond)
					}
				}
			}
			if mode == "passed" || mode == "finalizer_failed" || mode == "finalizer_verified_then_shell_failed" {
				err := p.wait(t)
				if mode == "passed" && err != nil || mode != "passed" && err == nil {
					t.Fatalf("setup outcome differs: %s %v stderr=%s", mode, err, p.stderr.String())
				}
				if strings.Contains(p.stderr.String(), "machine lock retained") {
					t.Fatal("native verified failure was reported unknown", p.stderr.String())
				}
			} else {
				p.retained(t, resources)
			}
			if strings.HasSuffix(mode, "_hung") {
				role := strings.TrimSuffix(mode, "_hung")
				if !strings.Contains(p.stderr.String(), role+" deadline exceeded") {
					t.Fatal("hung setup role lost deadline failure", p.stderr.String())
				}
				if _, err := os.Lstat(filepath.Join(root, "tests/.supervisor/supervisor")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("hung setup published supervisor", err)
				}
				stages, err := filepath.Glob(filepath.Join(root, "tests/.supervisor/setup.*"))
				if err != nil || len(stages) != 1 {
					t.Fatal("hung setup did not retain its stage", stages, err)
				}
			}
			p.absent(t)
			locks, err := openResourceLocks(resources)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			lease, err := locks.acquireMachine(ctx, true)
			if err != nil {
				t.Fatal("joined/explicitly terminated setup retained lock", err)
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// full_only: false
func TestSupervisorSetupWaitCancellationStartsNoCompiler(t *testing.T) {
	root, resources, controls, script := copiedSupervisorSetupFixture(t)
	installControlledSetupRoles(t, controls, "passed")
	locks, err := openResourceLocks(resources)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := locks.acquireMachine(t.Context(), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	})
	p := startSetupScript(t, root, script)
	select {
	case err := <-p.done:
		p.joined = true
		t.Fatal("setup did not wait", err, p.stderr.String())
	case <-time.After(50 * time.Millisecond):
	}
	if _, err := os.Stat(filepath.Join(controls, "compiler")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("compiler started before admission", err)
	}
	if err := p.command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := p.wait(t); err == nil {
		t.Fatal("canceled setup passed")
	}
	if _, err := os.Stat(filepath.Join(controls, "compiler")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("canceled waiter started compiler", err)
	}
	p.absent(t)
}

// full_only: false
func TestSupervisorSetupRefusesUnsupportedLockUtilityBeforeCompiler(t *testing.T) {
	root, _, controls, script := copiedSupervisorSetupFixture(t)
	installControlledSetupRoles(t, controls, "passed")
	bad := filepath.Join(controls, "flock")
	if err := os.WriteFile(bad, []byte("#!/bin/bash\nexit 64\n"), 0700); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	// Linux selects controls/flock through the fixture PATH. Darwin uses the
	// same executable through this copied absolute lockf replacement.
	quoted := "'" + strings.ReplaceAll(bad, "'", "'\"'\"'") + "'"
	body = []byte(strings.ReplaceAll(string(body), "/usr/bin/lockf", quoted))
	if err := os.WriteFile(script, body, 0700); err != nil {
		t.Fatal(err)
	}
	p := startSetupScript(t, root, script)
	if err := p.wait(t); err == nil {
		t.Fatal("unsupported lock utility admitted compiler")
	}
	if !strings.Contains(p.stderr.String(), "native machine lock failed: 64") {
		t.Fatal("lock utility failure was hidden", p.stderr.String())
	}
	if _, err := os.Stat(filepath.Join(controls, "compiler")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("compiler started after lock utility failure", err)
	}
	p.absent(t)
}

// full_only: false
func TestSupervisorSetupNativeFailurePreservesVerifiedSettlement(t *testing.T) {
	root, _, _, script := copiedSupervisorSetupFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	setup := exec.Command("/bin/bash", script)
	setup.Dir = root
	output := new(setupScriptOutput)
	setup.Stdout, setup.Stderr = output, output
	result := superviseProcess(ctx, setup)
	if result.Status != "passed" || !result.Started || !result.Joined || output.Overflow() {
		t.Fatalf("native setup failed: %+v %s", result, output.String())
	}
	binary := filepath.Join(root, "tests/.supervisor/supervisor")
	original, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	completed := exec.Command("/bin/sleep", "0.01")
	result = superviseProcess(ctx, completed)
	if result.Status != "passed" || !result.Joined {
		t.Fatal("compiler-group fixture did not settle", result)
	}
	invoke := func(group int) (processResult, string) {
		t.Helper()
		command := exec.Command(binary, "finalize-setup", "--root", root, "--stage", filepath.Join(root, "absent-stage"), "--owner-pid", strconv.Itoa(os.Getpid()), "--compiler-group", strconv.Itoa(group))
		captured := new(setupScriptOutput)
		command.Stdout, command.Stderr = captured, captured
		result := superviseProcess(ctx, command)
		if captured.Overflow() || !result.Started || !result.Joined {
			t.Fatal("native finalizer did not join", result)
		}
		return result, captured.String()
	}
	result, text := invoke(completed.Process.Pid)
	var exit *exec.ExitError
	if !errors.As(result.Cause, &exit) || exit.ExitCode() != 3 || !strings.Contains(text, "setup failed after settlement verified") {
		t.Fatalf("verified failure lost its distinct outcome: %+v %s", result, text)
	}
	current, err := os.ReadFile(binary)
	if err != nil || !bytes.Equal(current, original) {
		t.Fatal("failed finalizer changed installed target", err)
	}

	// A live compiler group refuses before verification and cannot emit status 3.
	active := exec.Command("/bin/sleep", "30")
	active.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := active.Start(); err != nil {
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() { waited <- active.Wait() }()
	joined := false
	t.Cleanup(func() {
		if !joined {
			if err := syscall.Kill(-active.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
				t.Error(err)
			}
			select {
			case <-waited:
			case <-time.After(processGroupSettlementTimeout):
				t.Error("active compiler fixture did not join")
			}
		}
	})
	result, text = invoke(active.Process.Pid)
	exit = nil
	if !errors.As(result.Cause, &exit) || exit.ExitCode() != 1 || strings.Contains(text, "after settlement verified") {
		t.Fatalf("unverified failure became settled: %+v %s", result, text)
	}
	if err := syscall.Kill(-active.Process.Pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	select {
	case <-waited:
		joined = true
	case <-ctx.Done():
		t.Fatal("active compiler did not join", ctx.Err())
	}
	if stopped, err := groupStopped(active.Process.Pid, nil); !stopped {
		t.Fatal("active compiler group remains", err)
	}
}

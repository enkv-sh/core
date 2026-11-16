package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func configureSupervisorGuardQuit(t *testing.T, fixture *supervisorResourceFixture) {
	t.Helper()
	rewrite := func(name string, edit func(string) string) {
		t.Helper()
		path := filepath.Join(fixture.root, "tests/shared/runner", name)
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(edit(string(body))), 0700); err != nil {
			t.Fatal(err)
		}
	}
	replace := func(body, old, next string) string {
		t.Helper()
		if strings.Count(body, old) != 1 {
			t.Fatal("copied guard quit source anchor changed", old)
		}
		return strings.Replace(body, old, next, 1)
	}
	rewrite("process_memory.go", func(body string) string {
		body = replace(body, "observed, err := g.watcher.observe(nativeProcessMemory)", `reader := nativeProcessMemory
 if g.stopping { reader = guardQuitFixtureRead }
 observed, err := g.watcher.observe(reader)`)
		start := strings.Index(supervisorGuardQuitProbeSource, "// This helper")
		if start < 0 {
			t.Fatal("copied guard quit helper body missing")
		}
		return body + "\n" + supervisorGuardQuitProbeSource[start:]
	})
	rewrite("supervisor_invocation.go", func(body string) string {
		// This forces one permitted selection when quit, failure and hard.Done are
		// simultaneously ready. The actual current quit body remains unchanged.
		body = replace(body, "defer close(guardDone)\n\t\t\tselect {", `defer close(guardDone)
 if os.Getenv("ENKV_RESOURCE_FIXTURE_OPERATION") != "earlier_monitor_late_child" { <-guardQuit }
 select {`)
		body = replace(body, "case <-guard.failure():", "case <-guardQuitFixtureEvent(guard.failure()):")
		body = replace(body, "case <-life.hard.Done():", "case <-guardQuitFixtureEvent(life.hard.Done()):")
		body = replace(body, "var lateErr error", "var lateErr error\n var probe *guardQuitFixtureProbe")
		body = replace(body, "sample, err := guard.stop()", `if os.Getenv("ENKV_RESOURCE_FIXTURE_OPERATION") == "earlier_monitor_late_child" {
 life.hardStop()
 <-guardDone
 lateErr = errors.Join(lateErr, guardQuitFixtureMarker("earlier",fmt.Sprintf("stopped=%t error=%t",hardStopped,hardStopErr!=nil)))
 }
 var probeErr error
 probe, probeErr = guardQuitFixtureStart(guard)
 lateErr = errors.Join(lateErr, probeErr)
 if probe != nil { defer func(){ retErr = errors.Join(retErr, probe.cleanup()) }() }
 if os.Getenv("ENKV_RESOURCE_FIXTURE_OPERATION") == "hard_cancel" { life.hardStop() }
 sample, err := guard.stop()`)
		const finalBoundary = "// A failed/unknown invocation never claims quiescence from descriptor close."
		body = replace(body, finalBoundary, `if guard != nil { lateErr = errors.Join(lateErr, guardQuitFixtureObserve(guard, probe, life.hard.Err(), joined, hardStopErr)) }
 `+finalBoundary)
		return body
	})
}

// full_only: false
func TestSupervisorGuardQuitFoldsTerminalFailureBeforeRelease(t *testing.T) {
	t.Setenv("ENKV_RESOURCE_FIXTURE_CONTROL", "")
	t.Setenv("ENKV_RESOURCE_FIXTURE_OPERATION", "")
	fixture := newConfiguredSupervisorResourceFixture(t, configureSupervisorGuardQuit)
	fixture.initializeEvidence(t)
	for _, row := range []struct {
		name, want string
		passed     bool
	}{
		{"guard_success", "settled=true guard_error=false hard=false joined=true stop_error=false", true},
		{"final_guard_failure", "settled=true guard_error=true hard=true joined=true stop_error=false", false},
		{"hard_cancel", "settled=true guard_error=false hard=true joined=true stop_error=false", false},
		{"earlier_monitor_late_child", "settled=true guard_error=false hard=true joined=true stop_error=false", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			invocation := fixture.start(t, fixture.root, row.name, row.name, false, false, false, "known_passed")
			if entered := invocation.marker(t, "entered"); entered != row.name {
				t.Fatal("fixture operation differs", entered)
			}
			invocation.gate(t, "release")
			invocation.wait(t, row.passed, 30*time.Second)
			if !row.passed {
				body, err := os.ReadFile(filepath.Join(invocation.control, "guard-quit-child"))
				if err != nil {
					t.Fatal(err)
				}
				var pid, group int
				var start uint64
				if _, err := fmt.Sscanf(string(body), "%d %d %d", &pid, &start, &group); err != nil || pid <= 0 || group <= 0 || start == 0 {
					t.Fatal("actual child generation missing", string(body), err)
				}
				observed, err := os.ReadFile(filepath.Join(invocation.control, "guard-quit-observed"))
				if err != nil || string(observed) != "observed\n" {
					t.Fatal("actual final census never owned child generation", string(observed), err)
				}
				cleanup, err := os.ReadFile(filepath.Join(invocation.control, "guard-quit-cleanup"))
				if err != nil || string(cleanup) != "passed\n" {
					t.Fatal("actual fallback child Wait/absence not established", string(cleanup), err)
				}
				info, err := nativeProcessIdentity(pid)
				if !errors.Is(err, syscall.ESRCH) && (err != nil || info.identity == (processIdentity{pid: pid, start: start})) {
					t.Fatal("owned child generation remains after actual cleanup", info, err)
				}
				if !errors.Is(syscall.Kill(-group, 0), syscall.ESRCH) {
					t.Fatal("native/child group remains after actual cleanup", group)
				}
			}
			if row.name == "earlier_monitor_late_child" {
				prior, err := os.ReadFile(filepath.Join(invocation.control, "guard-quit-earlier"))
				if err != nil || string(prior) != "stopped=true error=false\n" {
					t.Fatal("earlier monitor did not establish its own positive stop before new child", string(prior), err)
				}
			}
			// These facts precede the intended red monitor assertion, so even a red
			// proves the fallback's actual Wait and physical absence above.
			monitor, err := os.ReadFile(filepath.Join(invocation.control, "guard-quit-monitor"))
			if err != nil || strings.TrimSpace(string(monitor)) != row.want {
				t.Fatal("quit bypassed terminal failure settlement", string(monitor), err, "want", row.want)
			}

		})
	}
}

const supervisorGuardQuitProbeSource = `package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// This helper exists only in the finite native source copy.
type guardQuitFixtureProbe struct {
	process  *os.Process
	identity processIdentity
	done     chan struct{}
	waitErr  error
}

func guardQuitFixtureEvent(event <-chan struct{}) <-chan struct{} {
	if os.Getenv("ENKV_RESOURCE_FIXTURE_OPERATION") == "earlier_monitor_late_child" {
		return event
	}
	return nil
}

func guardQuitFixtureMarker(name, value string) error {
	control := os.Getenv("ENKV_RESOURCE_FIXTURE_CONTROL")
	if control == "" {
		return errors.New("guard quit control unavailable")
	}
	return os.WriteFile(control+"/guard-quit-"+name, []byte(value+"\n"), 0600)
}

func guardQuitFixtureStart(g *invocationMemoryGuard) (ownedProbe *guardQuitFixtureProbe, retErr error) {
	mode := os.Getenv("ENKV_RESOURCE_FIXTURE_OPERATION")
	if mode == "guard_success" {
		return nil, nil
	}
	process, err := os.StartProcess("/bin/sleep", []string{"sleep", "30"}, &os.ProcAttr{Env: os.Environ(), Files: []*os.File{os.Stdin, os.Stdout, os.Stderr}})
	if err != nil {
		return nil, err
	}
	probe := &guardQuitFixtureProbe{process: process, done: make(chan struct{})}
	go func() {
		state, err := process.Wait()
		if state == nil {
			err = errors.Join(err, errors.New("guard quit probe has no actual Wait state"))
		}
		probe.waitErr = err
		close(probe.done)
	}()
	ready := false
	defer func() {
		if !ready {
			retErr = errors.Join(retErr, probe.cleanup())
		}
	}()
	info, err := nativeProcessIdentity(process.Pid)
	if err != nil || info.identity.start == 0 || info.group != syscall.Getpgrp() {
		return nil, errors.Join(errors.New("guard quit child is not protected by native group"), err)
	}
	probe.identity = info.identity
	if err := guardQuitFixtureMarker("child", fmt.Sprintf("%d %d %d", info.identity.pid, info.identity.start, info.group)); err != nil {
		return nil, err
	}
	g.mu.Lock()
	g.observeLocked()
	_, owned := g.watcher.owned[probe.identity]
	censusErr := g.err
	g.mu.Unlock()
	if censusErr != nil || !owned {
		return nil, errors.Join(errors.New("guard quit child generation was not actually observed"), censusErr)
	}
	if err := guardQuitFixtureMarker("observed", "observed"); err != nil {
		return nil, err
	}
	if mode == "final_guard_failure" {
		if err := guardQuitFixtureMarker("arm", "armed"); err != nil {
			return nil, err
		}
	} else if mode != "hard_cancel" && mode != "earlier_monitor_late_child" {
		return nil, errors.New("guard quit fixture mode differs")
	}
	ready = true
	return probe, nil
}

func guardQuitFixtureRead(pid int) (processMemoryInfo, error) {
	if os.Getenv("ENKV_RESOURCE_FIXTURE_OPERATION") == "final_guard_failure" && pid == os.Getpid() {
		if _, err := os.Stat(os.Getenv("ENKV_RESOURCE_FIXTURE_CONTROL") + "/guard-quit-arm"); err == nil {
			return processMemoryInfo{}, errors.New("controlled final guard quit observation failure")
		} else if !os.IsNotExist(err) {
			return processMemoryInfo{}, err
		}
	}
	return nativeProcessMemory(pid)
}

func (probe *guardQuitFixtureProbe) settled() (bool, error) {
	info, err := nativeProcessIdentity(probe.process.Pid)
	if !errors.Is(err, syscall.ESRCH) {
		if err != nil {
			return false, err
		}
		if info.identity == probe.identity {
			return false, nil
		}
	}
	// Native absence may precede scheduling of the one actual Wait goroutine.
	// A still-live expected-red child above never receives this extra allowance.
	select {
	case <-probe.done:
	case <-time.After(processGroupSettlementTimeout):
		return false, errors.New("guard quit absent generation has no completed Wait")
	}
	return probe.waitErr == nil, probe.waitErr
}

func (probe *guardQuitFixtureProbe) cleanup() error {
	killErr := probe.process.Kill()
	if errors.Is(killErr, os.ErrProcessDone) || errors.Is(killErr, syscall.ESRCH) {
		killErr = nil
	}
	select {
	case <-probe.done:
	case <-time.After(processGroupSettlementTimeout):
		return errors.Join(killErr, errors.New("guard quit cleanup Wait did not finish"))
	}
	settled, err := probe.settled()
	if !settled || err != nil {
		return errors.Join(killErr, err, errors.New("guard quit cleanup generation remains"))
	}
	return errors.Join(killErr, guardQuitFixtureMarker("cleanup", "passed"))
}

func guardQuitFixtureObserve(g *invocationMemoryGuard, probe *guardQuitFixtureProbe, hard error, joined bool, hardStopErr error) error {
	_, guardErr := g.result()
	settled := true
	var err error
	if probe != nil {
		settled, err = probe.settled()
	}
	state := fmt.Sprintf("settled=%t guard_error=%t hard=%t joined=%t stop_error=%t", settled, guardErr != nil, hard != nil, joined, hardStopErr != nil)
	markerErr := guardQuitFixtureMarker("monitor", state)
	_, printErr := fmt.Fprintln(os.Stdout, "fixture_guard_quit_monitor "+state)
	return errors.Join(err, markerErr, printErr)
}
`

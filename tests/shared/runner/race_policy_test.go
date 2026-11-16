package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const raceFixture = `package racefixture

import (
 "os"
 "os/exec"
 "strings"
 "testing"
 "time"
)

const accepted = "log_path=stderr exitcode=66 halt_on_error=0 atexit_sleep_ms=1000"

// full_only: false
func TestKnownRace(t *testing.T) {
 var value int
 start := make(chan struct{})
 done := make(chan struct{})
 go func() {
  <-start
  value = 1
  close(done)
 }()
 close(start)
 value = 2
 <-done
 if value != 1 && value != 2 { t.Fatal("joined race child lost both writes") }
 t.Log("race child final sentinel")
}

// full_only: false
func TestRaceFree(t *testing.T) {
 if os.Getenv("GORACE") != accepted { t.Fatal("race-free child has wrong policy") }
 t.Log("race-free final sentinel")
}

// full_only: false
func TestShutdownRace(t *testing.T) {
 marker := os.Getenv("RACE_SHUTDOWN_MARKER")
 if marker == "" { t.Fatal("shutdown marker missing") }
 var value int
 go func() {
  time.Sleep(300 * time.Millisecond)
  value = 1
  _ = os.WriteFile(marker, []byte("background access complete"), 0600)
 }()
 value = 2
 if value != 2 { t.Fatal("shutdown test write lost") }
 t.Log("shutdown test events complete")
}

// full_only: false
func TestNestedWorker(t *testing.T) {
 if os.Getenv("GORACE") != accepted { t.Fatal("worker has wrong policy") }
 binary, err := os.Executable()
 if err != nil { t.Fatal(err) }
 command := exec.Command(binary, "-test.run=^TestNestedFreshChild$", "-test.v")
 output, err := command.CombinedOutput()
 if err != nil || !strings.Contains(string(output), "nested child final sentinel") { t.Fatalf("nested child did not finish: %v %s", err, output) }
}

// full_only: false
func TestNestedFreshChild(t *testing.T) {
 if os.Getenv("GORACE") != accepted { t.Fatal("nested child has wrong policy") }
 t.Log("nested child final sentinel")
}

`

func raceFixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/racefixture\n\ngo 1.27.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "race_test.go"), []byte(raceFixture), 0600); err != nil {
		t.Fatal(err)
	}
	return root
}

// full_only: false
func TestRaceConfigurationCannotSuppressFailure(t *testing.T) {
	t.Setenv("GORACE", "halt_on_error=1 exitcode=0 log_path=/tmp/hidden atexit_sleep_ms=0")
	root := raceFixtureRoot(t)
	body, err := runGo(context.Background(), root, ".", "test", "-mod=readonly", "-race", "-count=1", "-json", "-run=^TestKnownRace$", ".")
	if err == nil {
		t.Fatal("known race reported success under hostile inherited settings")
	}
	var failure *toolFailure
	if !errors.As(err, &failure) || failure.process.Status != "process_failed" || !failure.process.Joined {
		t.Fatalf("known race did not produce a joined failed process: %v", err)
	}
	if failure.facts == nil || failure.facts.RaceObservation != "observed" || !failure.facts.Joined {
		t.Error("joined stdout/stderr race observation was lost")
	}
	if len(body) != 0 {
		t.Fatal("failed command returned successful output")
	}
	events, err := ordinaryEventsFrom(failure.stdout)
	if err != nil {
		t.Fatal(err)
	}
	var diagnostic, sentinel, failed bool
	for _, event := range events {
		diagnostic = diagnostic || strings.Contains(event.Output, "DATA RACE")
		sentinel = sentinel || strings.Contains(event.Output, "race child final sentinel")
		failed = failed || event.Test == "TestKnownRace" && event.Action == "fail"
	}
	if !diagnostic || !sentinel || !failed {
		t.Fatalf("race report, final sentinel, or terminal failure missing: diagnostic=%t sentinel=%t failed=%t", diagnostic, sentinel, failed)
	}

	body, err = runGo(context.Background(), root, ".", "test", "-mod=readonly", "-race", "-count=1", "-json", "-run=^TestRaceFree$", ".")
	if err != nil {
		t.Fatal(err)
	}
	results, err := validateOrdinaryEvents(body, map[string][]string{"example.test/racefixture": {"TestRaceFree"}}, nil)
	if err != nil || len(results) != 1 || results[0].Outcome != "pass" || !strings.Contains(string(body), "race-free final sentinel") {
		t.Fatalf("race-free control lacks complete events: results=%+v error=%v", results, err)
	}
}

// full_only: false
func TestRaceExitWaitReportsShutdownRace(t *testing.T) {
	root := raceFixtureRoot(t)
	marker := filepath.Join(root, "shutdown.marker")
	t.Setenv("RACE_SHUTDOWN_MARKER", marker)
	t.Setenv("GORACE", "halt_on_error=1 exitcode=0 log_path=/tmp/hidden atexit_sleep_ms=0")
	body, err := runGo(context.Background(), root, ".", "test", "-mod=readonly", "-race", "-count=1", "-json", "-run=^TestShutdownRace$", ".")
	if err == nil {
		events, parseErr := ordinaryEventsFrom(body)
		if parseErr != nil {
			t.Fatal("accepted shutdown control has invalid test events", parseErr)
		}
		var completed, terminal, diagnostic bool
		for _, event := range events {
			completed = completed || strings.Contains(event.Output, "shutdown test events complete")
			terminal = terminal || event.Test == "TestShutdownRace" && event.Action == "pass"
			diagnostic = diagnostic || strings.Contains(event.Output, "DATA RACE")
		}
		background, readErr := os.ReadFile(marker)
		t.Fatalf("shutdown race was accepted: process=passed test_events=%t terminal=%t background=%t diagnostic=%t",
			completed, terminal, readErr == nil && string(background) == "background access complete", diagnostic)
	}
	if len(body) != 0 {
		t.Fatal("failed shutdown race returned a successful result body")
	}
	var failure *toolFailure
	if !errors.As(err, &failure) || failure.process.Status != "process_failed" || !failure.process.Joined {
		t.Fatalf("shutdown race did not fail in a joined process: %v", err)
	}
	events, err := ordinaryEventsFrom(failure.stdout)
	if err != nil {
		t.Fatal(err)
	}
	var completed, diagnostic, terminal bool
	for _, event := range events {
		completed = completed || strings.Contains(event.Output, "shutdown test events complete")
		diagnostic = diagnostic || strings.Contains(event.Output, "DATA RACE")
		terminal = terminal || event.Test == "TestShutdownRace" && event.Action == "pass"
	}
	background, readErr := os.ReadFile(marker)
	if !completed || !terminal || !diagnostic || readErr != nil || string(background) != "background access complete" {
		t.Fatalf("shutdown race facts incomplete: test_events=%t terminal=%t background=%t diagnostic=%t", completed, terminal,
			readErr == nil && string(background) == "background access complete", diagnostic)
	}
}

// full_only: false
func TestRaceConfigurationReachesEveryChild(t *testing.T) {
	t.Setenv("GORACE", "halt_on_error=1 exitcode=0")
	root := raceFixtureRoot(t)
	binary := filepath.Join(root, "worker.test")
	if _, err := runGo(context.Background(), root, ".", "test", "-mod=readonly", "-race", "-c", "-o", binary, "."); err != nil {
		t.Fatal(err)
	}
	result := runProcess(withRacePolicy(context.Background(), true), binary, root, []string{"-test.run=^TestNestedWorker$", "-test.v"}, workerEnvironment(""), 30*time.Second)
	if result.Status != "passed" || !result.Joined {
		t.Fatalf("worker or its nested fresh child missed the accepted race policy: %+v", result)
	}
}

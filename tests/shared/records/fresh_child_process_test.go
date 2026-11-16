package records

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
)

// full_only: false
func TestFreshChildProcessRetainsActualStartAndWait(t *testing.T) {
	for _, row := range []struct {
		name, script string
		want         FreshChildProcess
	}{
		{"successful-exit", "exit 0", FreshChildProcess{Started: true, Joined: true, Outcome: "passed"}},
		{"failed-exit", "exit 7", FreshChildProcess{Started: true, Joined: true, Outcome: "process_failed"}},
		{"start-failure", "", FreshChildProcess{Joined: true, Outcome: "not_started"}},
	} {
		for _, route := range []string{"Run", "CombinedOutput"} {
			t.Run(row.name+"/"+route, func(t *testing.T) {
				binary, args := "/bin/sh", []string{"-c", row.script}
				if row.script == "" {
					binary, args = filepath.Join(t.TempDir(), "absent"), nil
				}
				command := exec.CommandContext(t.Context(), binary, args...)
				var runErr error
				if route == "Run" {
					runErr = command.Run()
				} else {
					_, runErr = command.CombinedOutput()
				}
				if got := ObserveFreshChildProcess(command, runErr); got != row.want || got.Validate() != nil {
					t.Fatalf("process fact = %+v, want %+v", got, row.want)
				}
			})
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	command := exec.CommandContext(ctx, "/bin/sh", "-c", "exit 0")
	runErr := command.Run()
	want := FreshChildProcess{Joined: true, Outcome: "not_started"}
	if got := ObserveFreshChildProcess(command, runErr); got != want {
		t.Fatalf("canceled-before-start fact = %+v, want %+v", got, want)
	}
}

// full_only: false
func TestFreshChildProcessCannotInventAnUnobservedWait(t *testing.T) {
	command := exec.CommandContext(t.Context(), "/bin/sh", "-c", "exit 0")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	// Wait is intentionally delayed until after the observation. Register it
	// first so that a failed assertion cannot leave this real child unjoined.
	defer func() {
		if err := command.Wait(); err != nil {
			t.Error(err)
		}
	}()
	want := FreshChildProcess{Started: true, Outcome: "unknown"}
	if got := ObserveFreshChildProcess(command, nil); got != want || got.Validate() != nil {
		t.Fatalf("unobserved wait fact = %+v, want %+v", got, want)
	}
	for _, invalid := range []FreshChildProcess{
		{Started: false, Joined: true, Outcome: "passed"},
		{Started: true, Joined: false, Outcome: "passed"},
		{Started: false, Joined: true, Outcome: "process_failed"},
		{Started: true, Joined: true, Outcome: "not_started"},
		{Started: true, Joined: true, Outcome: "unknown"},
		{Started: true, Joined: true, Outcome: "other"},
	} {
		if invalid.Validate() == nil {
			t.Errorf("impossible process fact admitted: %+v", invalid)
		}
	}
}

// full_only: false
func TestFreshChildInvocationKeepsMissingProcessUnavailable(t *testing.T) {
	for _, body := range []string{
		`{"worker":"past-child","invocation":"private/child/invocation.json"}`,
		`{"worker":"past-child","invocation":"private/child/invocation.json","process":null}`,
	} {
		var child ChildInvocation
		if err := json.Unmarshal([]byte(body), &child); err != nil || child.Worker != "past-child" || child.Process != nil {
			t.Fatalf("missing historical process observation changed: %+v, %v", child, err)
		}
	}
}

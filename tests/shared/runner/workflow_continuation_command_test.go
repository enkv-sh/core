package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// full_only: false
func TestLocalWorkflowPublishesFailedCollection(t *testing.T) {
	if root := os.Getenv("ENKV_CONTINUATION_COMMAND_ROOT"); root != "" {
		locks, err := openResourceLocks(os.Getenv("ENKV_CONTINUATION_COMMAND_RESOURCES"))
		if err != nil {
			t.Fatal(err)
		}
		ctx := withRacePolicy(withResourceLocks(withExecutionParallel(t.Context(), 1), locks), os.Getenv("ENKV_CONTINUATION_COMMAND_RACE") == "true")

		err = runCommand(ctx, root, os.Getenv("ENKV_CONTINUATION_COMMAND_BOOTSTRAP"), []string{"run", "--workflow=" + os.Getenv("ENKV_CONTINUATION_COMMAND_WORKFLOW")}, os.Stdout)
		if err != nil {
			os.Exit(7)
		}
		os.Exit(0)
	}
	for _, race := range []bool{false, true} {
		t.Run(fmt.Sprintf("race-%t", race), func(t *testing.T) {
			ctx, root, bootstrap, witness, workflow, _ := completePreparationFixture(t, "")
			writeLocalGoFixture(t, root, "tests/hermetic/hermetic.mod", "module "+componentPackage+"\n\ngo 1.27.0\n")
			body := `package witness
import ("os"; "testing")
func witness(t *testing.T) {
 t.Helper()
 f,err:=os.OpenFile(os.Getenv("ENKV_PREPARATION_WITNESS"),os.O_CREATE|os.O_WRONLY|os.O_APPEND,0600)
 if err!=nil { t.Fatal(err) }
 if _,err:=f.WriteString(t.Name()+"\n");err!=nil { t.Fatal(err) }
 if err:=f.Close();err!=nil { t.Fatal(err) }
}
// full_only: false
func TestFirstFailure(t *testing.T) { witness(t); t.Fatal("first intended assertion") }
// full_only: false
func TestSecondFailure(t *testing.T) { witness(t); t.Fatal("second intended assertion") }
// full_only: false
func TestThirdPass(t *testing.T) { witness(t) }
`
			writeLocalGoFixture(t, root, "telemetry/witness/witness_test.go", body)
			writeLocalGoFixture(t, root, "telemetry/later/later_test.go", strings.ReplaceAll(strings.Split(body, "// full_only: false")[0]+"// full_only: false\nfunc TestLaterPass(t *testing.T) { witness(t) }\n", "package witness", "package later"))
			saveSelection(t, workflow, map[string]any{"schema_version": 1, "name": "continued-failed-collection", "profile": "dev", "execution": map[string]any{"parallel": 1}, "steps": []any{
				map[string]any{"id": "first", "kind": "unit", "packages": []string{"telemetry/witness"}},
				map[string]any{"id": "later", "kind": "unit", "packages": []string{"telemetry/later"}},
			}})

			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			command := exec.Command(executable, "-test.run=^TestLocalWorkflowPublishesFailedCollection$", "-test.timeout=3m")
			command.Dir = root
			command.Env = environment(os.Environ(), map[string]string{
				"ENKV_CONTINUATION_COMMAND_ROOT":      root,
				"ENKV_CONTINUATION_COMMAND_RESOURCES": filepath.Join(t.TempDir(), "resource-locks"),
				"ENKV_CONTINUATION_COMMAND_BOOTSTRAP": bootstrap,
				"ENKV_CONTINUATION_COMMAND_WORKFLOW":  workflow,
				"ENKV_CONTINUATION_COMMAND_RACE":      fmt.Sprint(race),
			})
			stdout, stderr := &limitedOutput{}, &limitedOutput{}
			command.Stdout, command.Stderr = stdout, stderr
			child, cancel := context.WithTimeout(ctx, 3*time.Minute)
			defer cancel()
			process := superviseProcess(child, command)
			var exit *exec.ExitError
			if !settledLocalProcessFailure(ctx, process) || !errors.As(process.Cause, &exit) || exit.ExitCode() != 7 || stdout.overflow || stderr.overflow {
				t.Fatal("real command did not fail and settle as expected", process, string(stdout.Bytes()), string(stderr.Bytes()))
			}
			observed, err := os.ReadFile(witness)
			if err != nil || string(observed) != "TestFirstFailure\nTestSecondFailure\nTestThirdPass\nTestLaterPass\n" {
				t.Fatal("failed collection omitted, retried or reordered a body", string(observed), err, string(stdout.Bytes()))
			}
			for _, message := range []string{"first intended assertion", "second intended assertion", "Step later", "Workflow failed"} {
				if !bytes.Contains(stdout.Bytes(), []byte(message)) {
					t.Fatal("terminal lost failure or later work", message)
				}
			}
			if _, err := os.Stat(filepath.Join(root, "tests/qualification")); !os.IsNotExist(err) {
				t.Fatal("ordinary invocation created qualification", err)
			}

		})
	}
}

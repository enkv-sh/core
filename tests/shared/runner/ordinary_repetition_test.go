package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type ordinaryRepetitionObservation struct {
	PID              int    `json:"pid"`
	InitialState     int    `json:"initial_state"`
	Binary           string `json:"binary"`
	BinarySHA256     string `json:"binary_sha256"`
	Fixture          string `json:"fixture"`
	WorkingDirectory string `json:"working_directory"`
	PWD              string `json:"pwd"`
	Go               string `json:"go"`
	ChildEntered     bool   `json:"child_entered"`
	ParentSuffix     bool   `json:"parent_suffix"`
}

const ordinaryRepetitionWitnessSource = `package witness

import (
 "bytes"
 "crypto/sha256"
 "encoding/json"
 "fmt"
 "os"
 "os/exec"
 "path/filepath"
 "testing"
)

var entered int

type observation struct {
 PID int ` + "`json:\"pid\"`" + `
 InitialState int ` + "`json:\"initial_state\"`" + `
 Binary string ` + "`json:\"binary\"`" + `
 BinarySHA256 string ` + "`json:\"binary_sha256\"`" + `
 Fixture string ` + "`json:\"fixture\"`" + `
 WorkingDirectory string ` + "`json:\"working_directory\"`" + `
 PWD string ` + "`json:\"pwd\"`" + `
 Go string ` + "`json:\"go\"`" + `
 ChildEntered bool ` + "`json:\"child_entered\"`" + `
 ParentSuffix bool ` + "`json:\"parent_suffix\"`" + `
}

// full_only: false
func TestRepetitionProcessWitness(t *testing.T) {
 entered++
 if entered != 1 { t.Fatal("mutable process state was reused") }
 path := os.Getenv("ENKV_ORDINARY_REPETITION_WITNESS")
 if path == "" { t.Fatal("test-owned witness output missing") }
 var history []observation
 body, err := os.ReadFile(path)
 if err == nil {
  if len(body) == 0 || body[len(body)-1] != '\n' { t.Fatal("incomplete witness row") }
  for _, line := range bytes.Split(body, []byte{'\n'}) {
   if len(line) == 0 { continue }
   var prior observation
   if err := json.Unmarshal(line, &prior); err != nil { t.Fatal(err) }
   if _, err := os.Stat(prior.Fixture); !os.IsNotExist(err) { t.Fatal("prior disposable fixture survived into next execution", err) }
   history = append(history, prior)
  }
 } else if !os.IsNotExist(err) { t.Fatal(err) }
 fixture := t.TempDir()
 if err := os.WriteFile(filepath.Join(fixture, "mutable"), []byte("new fixture"), 0600); err != nil { t.Fatal(err) }
 reached := false
 t.Run("leaf[a]+b", func(t *testing.T) {
  reached = true
  if os.Getenv("ENKV_ORDINARY_REPETITION_FAIL_SECOND") == "1" && len(history) == 1 { t.Error("controlled joined execution two assertion") }
 })
 binary, err := os.Executable()
 if err != nil { t.Fatal(err) }
 binaryBody, err := os.ReadFile(binary)
 if err != nil { t.Fatal(err) }
 cwd, err := os.Getwd()
 if err != nil { t.Fatal(err) }
 goPath, err := exec.LookPath("go")
 if err != nil { t.Fatal(err) }
 goPath, err = filepath.EvalSymlinks(goPath)
 if err != nil { t.Fatal(err) }
 row := observation{PID: os.Getpid(), InitialState: entered, Binary: binary, BinarySHA256: fmt.Sprintf("%x", sha256.Sum256(binaryBody)), Fixture: fixture, WorkingDirectory: cwd, PWD: os.Getenv("PWD"), Go: goPath, ChildEntered: reached, ParentSuffix: true}
 output, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
 if err != nil { t.Fatal(err) }
 writeErr := json.NewEncoder(output).Encode(row)
 closeErr := output.Close()
 if writeErr != nil || closeErr != nil { t.Fatal(writeErr, closeErr) }
}
`

// full_only: false
func TestOrdinaryWorkflowRepetitionsKeepFreshExecutionAndOnePreparation(t *testing.T) {
	for _, selected := range []struct {
		name, focus string
		failSecond  bool
	}{{"passed", "test", false}, {"failure2", "test", true}, {"package-only", "package", false}, {"whole-unit", "", false}} {
		t.Run(selected.name, func(t *testing.T) {
			failSecond := selected.failSecond
			root, _, _ := overlayFixture(t)
			writeLocalGoFixture(t, root, "telemetry/go.mod", "module "+modulePrefix+"telemetry\n\ngo 1.27.0\n")
			witnessSource := ordinaryRepetitionWitnessSource
			profile := "full"
			if selected.focus == "" || selected.focus == "package" {
				profile = "dev"
				witnessSource += "\n// full_only: true\nfunc TestFullOnlyWitnessMustNotExecute(t *testing.T) { t.Fatal(\"full-only test executed in repeated dev unit\") }\n"
			}
			writeLocalGoFixture(t, root, "telemetry/witness/witness_test.go", witnessSource)
			initializeWorkflowExecutionFixture(t, root)
			observations := t.TempDir()
			witness := filepath.Join(observations, "executions.jsonl")
			commands := filepath.Join(observations, "go-commands")
			realGo, err := exec.LookPath("go")
			if err != nil {
				t.Fatal(err)
			}
			realGo, err = filepath.EvalSymlinks(realGo)
			if err != nil {
				t.Fatal(err)
			}
			// Observe actual tool invocations, then exec the installed tool without
			// changing its output or supplying any inventory/test result.
			bin := t.TempDir()
			observer := "#!/bin/sh\nprintf 'BEGIN\\n' >> \"$ENKV_ORDINARY_GO_COMMAND_LOG\"\nprintf '%s\\n' \"$PWD\" \"$@\" >> \"$ENKV_ORDINARY_GO_COMMAND_LOG\"\nprintf 'END\\n' >> \"$ENKV_ORDINARY_GO_COMMAND_LOG\"\nexec '" + strings.ReplaceAll(realGo, "'", "'\"'\"'") + "' \"$@\"\n"
			if err := os.WriteFile(filepath.Join(bin, "go"), []byte(observer), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("ENKV_ORDINARY_GO_COMMAND_LOG", commands)
			t.Setenv("ENKV_ORDINARY_REPETITION_WITNESS", witness)
			failureControl := "0"
			if failSecond {
				failureControl = "1"
			}
			t.Setenv("ENKV_ORDINARY_REPETITION_FAIL_SECOND", failureControl)
			path := filepath.Join(observations, "workflow.json")
			step := map[string]any{"id": "focused", "kind": "unit", "packages": []string{"telemetry/witness"}, "repetitions": 3}
			if selected.focus != "" {
				step["package"] = "telemetry/witness"
			}
			if selected.focus == "test" {
				step["tests"] = []string{"TestRepetitionProcessWitness/leaf[a]+b"}
			}
			steps := []any{step}
			planned := 3
			if failSecond {
				steps = append(steps, map[string]any{"id": "later", "kind": "unit", "packages": []string{"telemetry/witness"}, "package": "telemetry/witness", "tests": []string{"TestRepetitionProcessWitness/leaf[a]+b"}})
				planned++
			}
			saveSelection(t, path, map[string]any{"schema_version": 1, "name": "fresh-ordinary", "profile": profile, "execution": map[string]any{"parallel": 1}, "steps": steps})
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
			defer cancel()
			plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path})
			if err != nil || len(plan.Steps) != planned {
				t.Fatal("actual repetition selection unavailable", err)
			}
			var output bytes.Buffer
			result, runErr := runWorkflow(ctx, root, "", plan, &output)
			if failSecond && !strings.Contains(output.String(), "controlled joined execution two assertion") {
				t.Error("hermetic terminal omitted the failed assertion value", output.String())
			}
			if (runErr != nil) != failSecond {
				t.Fatal("real workflow outcome differs from controlled assertion", runErr, output.String())
			}
			want := 3
			outcome := "passed"
			if failSecond {
				want, outcome = 4, "failed"
			}
			body, err := os.ReadFile(witness)
			if err != nil {
				t.Fatal("real test body did not produce execution observations", err, output.String())
			}
			rows, err := decodeObjects[ordinaryRepetitionObservation](body)
			if err != nil || len(rows) != want {
				t.Fatal("workflow did not run each selected fresh execution once", len(rows), want, err)
			}
			pids, fixtures, binaries := map[int]bool{}, map[string]bool{}, map[string]bool{}
			for _, row := range rows {
				if row.PID <= 0 || pids[row.PID] || row.InitialState != 1 || row.Fixture == "" || fixtures[row.Fixture] || !hexString(row.BinarySHA256, 64) || !row.ChildEntered || !row.ParentSuffix {
					t.Error("execution observation lacks independent process/fixture and exact child/suffix", row)
				}
				pids[row.PID], fixtures[row.Fixture], binaries[row.Binary] = true, true, true
				if row.WorkingDirectory != filepath.Join(root, "telemetry/witness") || row.PWD != row.WorkingDirectory || row.Go != realGo {
					t.Error("compiled execution changed package cwd/PWD or toolchain PATH", row)
				}
				if _, err := os.Stat(row.Fixture); !os.IsNotExist(err) {
					t.Error("joined execution retained disposable mutable fixture", row.Fixture, err)
				}
				if row.BinarySHA256 != rows[0].BinarySHA256 {
					t.Error("identical preparation produced a different immutable binary", row)
				}
			}
			if len(binaries) != 1 {
				t.Error("compatible configured steps and repetitions did not share one immutable binary", binaries)
			}
			commandBody, err := os.ReadFile(commands)
			if err != nil {
				t.Fatal(err)
			}
			compiles := 0
			for _, block := range strings.Split(string(commandBody), "BEGIN\n")[1:] {
				lines := strings.Split(strings.TrimSuffix(block, "END\n"), "\n")
				if len(lines) > 2 && lines[1] == "test" && (slices.Contains(lines[2:], "-c") || slices.Contains(lines[2:], "-list=.") && slices.Contains(lines[2:], "-o")) {
					compiles++
					if slices.Contains(lines[2:], "-race") {
						t.Error("actual immutable preparation added race instrumentation to a no-race invocation", lines)
					}
				}
			}
			if compiles != 1 {
				t.Error("compatible configured steps and repetitions did not share one actual compile", compiles)
			}
			if result.Outcome != outcome || len(result.Steps) != planned || result.FinishedAt == nil {
				t.Fatal("current workflow lost its exact admitted execution outcome", result)
			}
			evidenceOwners := map[*ordinaryStepEvidence]bool{}
			var firstPreparation *ordinaryPreparation
			for index, step := range result.Steps[:want] {
				current := result.executions[step.ID].Ordinary
				if step.ID != plan.Steps[index].ID || current == nil || evidenceOwners[current] || step.StartedAt == nil || step.FinishedAt == nil || step.ElapsedSeconds <= 0 {
					t.Fatal("execution did not return separate current results and real wrapper timing", step)
				}
				evidenceOwners[current] = true
				evidence := *current
				if evidence.Race == nil || *evidence.Race || evidence.RaceOptions != acceptedRaceOptions(false) {
					t.Fatal("ordinary repetition changed the accepted no-race policy", step.ID)
				}
				if selected.focus != "test" && (evidence.Profile != "dev" || len(evidence.Packages) != 1 || !slices.Equal(evidence.Packages[0].NotSelected, []string{"TestFullOnlyWitnessMustNotExecute"})) {
					t.Fatal("prepared repetition lost full-only dev omissions", evidence)
				}
				if selected.focus == "" {
					if evidence.Focus != nil || evidence.Preparation != nil || evidence.Execution != nil || !completeOrdinaryEvidence(evidence) {
						t.Fatal("whole configured unit repetition lost its complete ordinary scope", step.ID)
					}
				} else {
					var requested []string
					if selected.focus == "test" {
						requested = []string{"TestRepetitionProcessWitness/leaf[a]+b"}
					}
					if evidence.Focus == nil || !slices.Equal(evidence.Focus.Tests, requested) || evidence.Focus.PackagePath != "telemetry/witness" || evidence.Preparation == nil || len(evidence.Execution) != 1 || evidence.Complete {
						t.Fatal("execution scalar receipt changed package/test focus or complete scope", step.ID)
					}
					if !sameSource(evidence.Preparation.Source, result.Source) || evidence.Preparation.Toolchain == "" || len(evidence.Preparation.Artifacts) != 1 {
						t.Fatal("immutable preparation lost its admitted source/toolchain/artifact identity", evidence.Preparation)
					}
					if evidence.Preparation.Artifacts[0].Owner != "telemetry/witness" || evidence.Execution[0].Artifact != "telemetry/witness" || evidence.Execution[0].Package != modulePrefix+"telemetry/witness" || !slices.Equal(evidence.Execution[0].Tests, []string{"TestRepetitionProcessWitness"}) {
						t.Error("immutable preparation or current execution lost its exact artifact/package/root identity", evidence.Preparation, evidence.Execution)
					}
					if firstPreparation == nil {
						firstPreparation = evidence.Preparation
					} else if evidence.Preparation.Toolchain != firstPreparation.Toolchain || !slices.Equal(evidence.Preparation.Artifacts[0].BuildInputs, firstPreparation.Artifacts[0].BuildInputs) {
						t.Error("identical repeated selection changed its immutable preparation inputs", evidence.Preparation)
					}
				}
				if evidence.EventTimeSource != "post_join_test2json" {
					t.Error("prepared execution mislabeled replay timestamps as runtime event timestamps", evidence.EventTimeSource)
				}
				if evidence.Diagnostics == nil {
					t.Fatal("execution lacks supervised command facts")
				}
				testCommands, conversions := 0, 0
				for _, fact := range evidence.Diagnostics.Commands {
					if !fact.Joined {
						t.Error("real fixture unexpectedly lacked positive process join", fact)
					}
					if fact.Phase == "test" {
						testCommands++
						if !fact.Started || !fact.Joined || fact.WallSeconds == nil || *fact.WallSeconds <= 0 {
							t.Error("test invocation lacks actual start/join and real wall timing", fact)
						}
						if failSecond && index == 1 && (fact.Process != "process_failed" || fact.RequestedNode != "failed" || fact.Events != "valid") {
							t.Error("failed execution two lost its actual joined assertion/event facts", fact)
						}
					}
					if fact.Phase == "conversion" {
						conversions++
						if !fact.Started || !fact.Joined || fact.WallSeconds == nil || *fact.WallSeconds <= 0 {
							t.Error("post-join conversion lacks its separate real timing/join", fact)
						}
					}
				}
				if testCommands != 1 || conversions != 1 {
					t.Error("binary execution and conversion are not separate retained command facts", testCommands, conversions)
				}
				if index != 1 || !failSecond {
					valid := completeOrdinaryEvidence(evidence)
					if selected.focus != "" {
						valid = validOrdinaryFocusedEvidence(evidence)
					}
					if step.Outcome != "passed" || !valid {
						t.Error("fresh successful execution lacks exact selected-node evidence", step.ID)
					}
				} else {
					if step.Outcome != "failed" {
						t.Error("joined execution two assertion lost its failed terminal", step.ID)
					}
					terminals := map[string]string{}
					for _, terminal := range evidence.Tests {
						if terminal.Package != modulePrefix+"telemetry/witness" || terminals[terminal.Name] != "" {
							t.Error("failure receipt has wrong package or duplicate terminals", terminal)
						}
						terminals[terminal.Name] = terminal.Outcome
					}
					if len(terminals) != 2 || terminals["TestRepetitionProcessWitness"] != "fail" || terminals["TestRepetitionProcessWitness/leaf[a]+b"] != "fail" {
						t.Error("execution two did not retain exact child and parent assertion failures", terminals)
					}
				}
			}
			matches := 0
			for _, group := range result.RepetitionGroups {
				if group.ConfiguredStep != "focused" {
					t.Error("unexpected configured repetition group", group)
					continue
				}
				matches++
				ids := make([]string, 0, 3)
				for _, step := range result.Steps[:3] {
					ids = append(ids, step.ID)
				}
				if group.ConfiguredStep != "focused" || group.RequestedExecutions != 3 || group.CompletedExecutions != 3 || group.Outcome != outcome || !slices.Equal(group.StepIDs, ids) {
					t.Error("group changed N/K, outcome or exact ordered attempted scalar references", group, ids)
				}
			}
			if matches != 1 {
				t.Error("workflow lacks one exact configured repetition group", result.RepetitionGroups)
			}
		})
	}
}

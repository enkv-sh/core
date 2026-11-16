package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// full_only: false
func TestPreparedRunnerWorkflowUsesBalancedGroups(t *testing.T) {
	for _, parallel := range []int{1, 2, 4} {
		t.Run(fmt.Sprintf("parallel_%d", parallel), func(t *testing.T) {
			profile := "dev"
			if parallel == 2 {
				profile = "full"
			}
			root := sourceFixtureRoot(t)
			writeLocalGoFixture(t, root, "core/go.mod", "module "+componentPackage+"\n\ngo 1.27.0\n")
			writeLocalGoFixture(t, root, "tests/hermetic/hermetic.mod", "module "+componentPackage+"\n\ngo 1.27.0\n")
			replacements := map[string]string{}
			sources := []struct{ owner, target, pkg, tests string }{
				{"runner", "testmain", "main", preparedRunnerHelperSource},
				{"records", "testrecords", "records", "// full_only: false\nfunc TestPreparedAlpha(t *testing.T) { preparedRunnerWitness(t, \"TestPreparedBeta\") }\n"},
				{"catalog", "testcatalog", "catalog", "// full_only: false\nfunc TestPreparedBeta(t *testing.T) { preparedRunnerWitness(t, \"TestPreparedAlpha\") }\n"},
			}
			for _, fixture := range sources {
				body := "package " + fixture.pkg + "\n" + preparedRunnerWitnessSource + fixture.tests
				file := writeLocalGoFixture(t, root, "tests/shared/"+fixture.owner+"/witness_test.go", body)
				replacements[filepath.Join(root, "core/internal", fixture.target, "witness_test.go")] = file
				file = writeLocalGoFixture(t, root, "tests/shared/"+fixture.owner+"/witness.go", "package "+fixture.pkg+"\n")
				replacements[filepath.Join(root, "core/internal", fixture.target, "witness.go")] = file
			}
			writeLocalGoFixture(t, root, "tests/scripts/bootstrap.go", "package main\nfunc main() {}\n")
			writeLocalGoFixture(t, root, "tests/scripts/bootstrap_test.go", "package main\n"+preparedRunnerWitnessSource+preparedRunnerLauncherSource)
			bootstrap := filepath.Join(t.TempDir(), "overlay.json")
			body, err := json.Marshal(struct{ Replace map[string]string }{replacements})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(bootstrap, body, 0600); err != nil {
				t.Fatal(err)
			}
			initializeWorkflowExecutionFixture(t, root)
			observations := t.TempDir()
			realGo, err := exec.LookPath("go")
			if err != nil {
				t.Fatal(err)
			}
			realGo, err = filepath.EvalSymlinks(realGo)
			if err != nil {
				t.Fatal(err)
			}
			commands := filepath.Join(observations, "go-commands")
			bin := t.TempDir()
			observer := "#!/bin/sh\nprintf 'BEGIN\\n' >> \"$ENKV_PREPARED_RUNNER_COMMANDS\"\nprintf '%s\\n' \"$@\" >> \"$ENKV_PREPARED_RUNNER_COMMANDS\"\nprintf 'END\\n' >> \"$ENKV_PREPARED_RUNNER_COMMANDS\"\nexec '" + strings.ReplaceAll(realGo, "'", "'\"'\"'") + "' \"$@\"\n"
			if err := os.WriteFile(filepath.Join(bin, "go"), []byte(observer), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("ENKV_PREPARED_RUNNER_COMMANDS", commands)
			path := filepath.Join(observations, "workflow.json")
			saveSelection(t, path, map[string]any{
				"schema_version": 1, "name": "prepared-runner", "profile": profile, "execution": map[string]any{"parallel": parallel},
				"steps": []map[string]any{{"id": "runner", "kind": "runner-tests"}},
			})
			ctx, cancel := context.WithTimeout(withExecutionParallel(t.Context(), parallel), 3*time.Minute)
			defer cancel()
			plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path})
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			prepared, err := prepareWorkflow(ctx, root, bootstrap, plan, &output)
			if prepared != nil {
				defer func() {
					tail, release := finalizationContext(ctx)
					defer release()
					if err := prepared.close(tail); err != nil {
						t.Error(err)
					}
				}()
			}
			if err != nil || prepared == nil {
				t.Fatal("prepare runner", err, output.String())
			}
			group := prepared.ordinary["runner"]
			if group == nil || len(group.artifacts) != 4 {
				t.Fatal("prepared artifact count", group)
			}
			hashes := map[string]string{}
			selected := map[string][]string{}
			for _, artifact := range group.artifacts {
				if artifact.binary == "" || !hexString(artifact.binaryHash, 64) {
					t.Fatal("missing prepared binary", artifact)
				}
				hashes[artifact.binary] = artifact.binaryHash
				if artifact.Package != "command-line-arguments" {
					selected[artifact.Package] = slices.Clone(artifact.Tests)
				}
			}
			preparationCommands, err := os.ReadFile(commands)
			if err != nil {
				t.Fatal(err)
			}
			expectedGroups, err := runnerTestGroups(selected, runnerEstimates, parallel)
			if err != nil || len(expectedGroups) != parallel {
				t.Fatal(expectedGroups, err)
			}
			t.Setenv("ENKV_PREPARED_RUNNER_PARALLEL", fmt.Sprint(parallel))
			var repeated ordinaryStepEvidence
			if parallel == 2 {
				// Exercise the divided repetition share before the workflow
				// joins and closes this configured group's owner.
				originalRepetitions := group.step.Repetitions
				group.step.Repetitions = 2
				t.Setenv("ENKV_PREPARED_RUNNER_WITNESS", t.TempDir())
				child := useLocalPreparationPhase(prepared.binding.context(withExecutionParallel(ctx, 2)), prepared.phase)
				err := group.execute(child, root, profile, &repeated, &output)
				prepared.joined = prepared.joined && toolCommandsJoined(err)
				group.step.Repetitions = originalRepetitions
				if err != nil {
					t.Fatal("complete repetition lost its assigned group share", err, output.String())
				}
			}
			t.Setenv("ENKV_PREPARED_RUNNER_WITNESS", observations)
			result, runErr := runPreparedWorkflow(ctx, root, bootstrap, prepared, &output)
			if runErr != nil || result.Outcome != "passed" || len(result.Steps) != 1 {
				t.Fatal("run prepared runner", runErr, result, output.String())
			}
			evidence := result.executions[result.Steps[0].ID].Ordinary
			if evidence == nil || !completeOrdinaryEvidence(*evidence) || len(evidence.Packages) != 4 || len(evidence.Tests) != 11 || len(evidence.RunnerGroups) != parallel {
				t.Fatal("incomplete exact runner result", evidence)
			}
			expected := map[string][]string{
				componentPackage + "/internal/testmain":    {"TestCoordinatorAssertionEvidencePreservesTypedRerun", "TestCoordinatorJoinsWorkersAndKeepsCleanupIndependent", "TestLiveChild", "TestLiveCleanup", "TestLiveRecovery", "TestLiveRun"},
				componentPackage + "/internal/testrecords": {"TestPreparedAlpha"},
				componentPackage + "/internal/testcatalog": {"TestPreparedBeta"},
				"command-line-arguments":                   {"TestPreparedLauncher"},
			}
			seen := map[string]bool{}
			for _, pkg := range evidence.Packages {
				actual := slices.Clone(pkg.Tests)
				slices.Sort(actual)
				want, known := expected[pkg.Name]
				if !known || seen[pkg.Name] || !slices.Equal(actual, want) {
					t.Fatal("selected roots differ", pkg)
				}
				seen[pkg.Name] = true
			}
			for index, fact := range evidence.RunnerGroups {
				if fact.Outcome != "passed" || !reflect.DeepEqual(fact.runnerGroup, expectedGroups[index]) {
					t.Fatal("group membership/order differs", fact)
				}
			}
			terminals := map[string]bool{}
			for _, terminal := range evidence.Tests {
				key := terminal.Package + "\x00" + terminal.Name
				if terminals[key] {
					t.Fatal("duplicate terminal", key)
				}
				terminals[key] = true
			}
			tests, conversions := 0, 0
			launcher := false
			for _, fact := range evidence.Diagnostics.Commands {
				if !fact.Started || !fact.Joined || fact.Process != "passed" {
					t.Fatal("missing positive join", fact)
				}
				if fact.Phase != "test" && fact.Phase != "conversion" {
					continue
				}
				if fact.Scope == "command-line-arguments" {
					launcher = true
				} else if launcher || !strings.HasPrefix(fact.Scope, "balanced-") {
					t.Fatal("launcher preceded group joins", fact)
				}
				if fact.Phase == "test" {
					tests++
				} else {
					conversions++
				}
			}
			expectedProcesses := 4
			if parallel > 1 {
				expectedProcesses = 5
			}
			if tests != expectedProcesses || conversions != expectedProcesses || !launcher {
				t.Fatal("wrong prepared execution count", tests, conversions)
			}
			if parallel == 2 {
				if !completeOrdinaryEvidence(repeated) || len(repeated.Tests) != 11 || len(repeated.RunnerGroups) != parallel {
					t.Fatal("repeated complete execution bypassed balanced groups", repeated)
				}
				for index, fact := range repeated.RunnerGroups {
					if fact.Outcome != "passed" || !reflect.DeepEqual(fact.runnerGroup, expectedGroups[index]) {
						t.Fatal("repetition changed its selected groups", fact)
					}
				}
				for index, terminal := range repeated.Tests {
					original := evidence.Tests[index]
					if terminal.Package != original.Package || terminal.Name != original.Name || terminal.Outcome != original.Outcome {
						t.Fatal("completion order changed deterministic terminal order", original, terminal)
					}
				}
				for _, fact := range repeated.Diagnostics.Commands {
					if !fact.Started || !fact.Joined || fact.Process != "passed" {
						t.Fatal("repeated process did not join", fact)
					}
				}
			}
			body, err = os.ReadFile(commands)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(body, preparationCommands) {
				t.Fatal("preparation command observation changed")
			}
			for _, block := range strings.Split(string(body[len(preparationCommands):]), "BEGIN\n")[1:] {
				if strings.HasPrefix(block, "test\n") {
					t.Fatal("execution rebuilt or rediscovered prepared tests", block)
				}
			}
			for _, artifact := range group.artifacts {
				for _, name := range artifact.Tests {
					if ordinaryRunnerHelperProofs[artifact.Package+"\x00"+name] != "" {
						continue
					}
					identity, err := os.ReadFile(filepath.Join(observations, name+".binary"))
					if err != nil || string(identity) != artifact.binary+"\n"+artifact.binaryHash {
						t.Fatal("execution used a different binary", name, string(identity), err)
					}
				}
			}
			compiles := map[string]int{}
			for _, block := range strings.Split(string(body), "BEGIN\n")[1:] {
				args := strings.Split(strings.TrimSuffix(block, "END\n"), "\n")
				if len(args) == 0 || args[0] != "test" || !slices.Contains(args, "-c") {
					continue
				}
				position := slices.Index(args, "-o")
				if position < 0 || position+1 >= len(args) {
					t.Fatal("compile output absent", args)
				}
				compiles[args[position+1]]++
			}
			if len(compiles) != 4 {
				t.Fatal("unexpected compile set", compiles)
			}
			for binary, hash := range hashes {
				actual, err := assemblyFileSHA256(binary)
				if err != nil || actual != hash || compiles[binary] != 1 {
					t.Fatal("prepared binary rebuilt/changed", binary, compiles[binary], err)
				}
			}
			if _, err := os.Stat(filepath.Join(observations, "launcher")); err != nil {
				t.Fatal("launcher did not execute", err)
			}
			if parallel == 4 {
				tail, release := finalizationContext(ctx)
				closeErr := prepared.close(tail)
				release()
				if closeErr != nil {
					t.Fatal("positive preparation owner did not close", closeErr)
				}
				beforeFailurePreparation, err := os.ReadFile(commands)
				if err != nil {
					t.Fatal(err)
				}
				negative, err := prepareWorkflow(ctx, root, bootstrap, plan, &output)
				if negative != nil {
					defer func() {
						tail, release := finalizationContext(ctx)
						defer release()
						if err := negative.close(tail); err != nil {
							t.Error(err)
						}
					}()
				}
				if err != nil || negative == nil {
					t.Fatal("prepare mutation owner", err, output.String())
				}
				failureGroup := negative.ordinary["runner"]
				if failureGroup == nil || failureGroup.closed || len(failureGroup.artifacts) != 4 {
					t.Fatal("mutation owner is unavailable", failureGroup)
				}
				failureHashes := map[string]string{}
				for _, artifact := range failureGroup.artifacts {
					actual, err := assemblyFileSHA256(artifact.binary)
					if err != nil || actual != artifact.binaryHash {
						t.Fatal("mutation owner binary differs", artifact.Package, err)
					}
					failureHashes[artifact.binary] = artifact.binaryHash
				}
				failurePreparationCommands, err := os.ReadFile(commands)
				if err != nil || !bytes.HasPrefix(failurePreparationCommands, beforeFailurePreparation) {
					t.Fatal("mutation preparation command observation changed", err)
				}
				failureCompiles := map[string]int{}
				for _, block := range strings.Split(string(failurePreparationCommands[len(beforeFailurePreparation):]), "BEGIN\n")[1:] {
					args := strings.Split(strings.TrimSuffix(block, "END\n"), "\n")
					if len(args) == 0 || args[0] != "test" || !slices.Contains(args, "-c") {
						continue
					}
					position := slices.Index(args, "-o")
					if position < 0 || position+1 >= len(args) {
						t.Fatal("mutation compile output absent", args)
					}
					failureCompiles[args[position+1]]++
				}
				if len(failureCompiles) != 4 {
					t.Fatal("mutation owner compile set differs", failureCompiles)
				}
				for binary := range failureHashes {
					if failureCompiles[binary] != 1 {
						t.Fatal("mutation owner did not compile exactly once", binary, failureCompiles[binary])
					}
				}
				failureWitness := t.TempDir()
				t.Setenv("ENKV_PREPARED_RUNNER_WITNESS", failureWitness)
				changed := false
				writer := workflowOutputWriter(func(body []byte) (int, error) {
					if !changed && strings.HasPrefix(string(body), "runner: starting group ") {
						changed = true
						if err := os.WriteFile(failureGroup.artifacts[0].binary, []byte("changed after group verification"), 0600); err != nil {
							return 0, err
						}
					}
					return len(body), nil
				})
				var failed ordinaryStepEvidence
				child := useLocalPreparationPhase(negative.binding.context(ctx), negative.phase)
				err = failureGroup.execute(child, root, profile, &failed, writer)
				negative.joined = negative.joined && toolCommandsJoined(err)
				if err == nil || ctx.Err() != nil || !changed || failed.Complete || failed.Diagnostics == nil || failed.Diagnostics.Preparation != "passed" {
					t.Fatal("failed executable start lost its failure fact", failed, err)
				}
				for _, fact := range failed.Diagnostics.Commands {
					if !fact.Joined {
						t.Fatal("failed adapter retained an unjoined process", fact)
					}
				}
				if _, err := os.Stat(filepath.Join(failureWitness, "launcher")); !os.IsNotExist(err) {
					t.Fatal("launcher executed after group failure", err)
				}
				failureCommands, err := os.ReadFile(commands)
				if err != nil || !bytes.HasPrefix(failureCommands, failurePreparationCommands) {
					t.Fatal("mutation execution command observation changed", err)
				}
				for _, block := range strings.Split(string(failureCommands[len(failurePreparationCommands):]), "BEGIN\n")[1:] {
					if strings.HasPrefix(block, "test\n") {
						t.Fatal("mutation execution rebuilt prepared tests", block)
					}
				}
				for _, artifact := range failureGroup.artifacts {
					for _, name := range artifact.Tests {
						identity, err := os.ReadFile(filepath.Join(failureWitness, name+".binary"))
						if os.IsNotExist(err) {
							continue
						}
						if err != nil || string(identity) != artifact.binary+"\n"+artifact.binaryHash {
							t.Fatal("mutation execution used a different binary", name, string(identity), err)
						}
					}
					if artifact.binary == failureGroup.artifacts[0].binary {
						continue
					}
					actual, err := assemblyFileSHA256(artifact.binary)
					if err != nil || actual != failureHashes[artifact.binary] {
						t.Fatal("unmodified mutation-owner binary changed", artifact.Package, err)
					}
				}
			}
		})
	}
}

const preparedRunnerWitnessSource = `
import (
 "crypto/sha256"
 "flag"
 "fmt"
 "os"
 "path/filepath"
 "strconv"
 "syscall"
 "testing"
 "time"
)
func preparedRunnerIdentity(t *testing.T) {
 t.Helper()
 binary, err := os.Executable()
 if err != nil { t.Fatal(err) }
 body, err := os.ReadFile(binary)
 if err != nil { t.Fatal(err) }
 path := filepath.Join(os.Getenv("ENKV_PREPARED_RUNNER_WITNESS"), t.Name()+".binary")
 if err := os.WriteFile(path, []byte(fmt.Sprintf("%s\n%x", binary, sha256.Sum256(body))), 0600); err != nil { t.Fatal(err) }
}
func preparedRunnerMark(t *testing.T) {
 t.Helper()
 preparedRunnerIdentity(t)
 if flag.Lookup("test.parallel").Value.String() != "1" { t.Fatal("runner group received more than one inner slot") }
 path := filepath.Join(os.Getenv("ENKV_PREPARED_RUNNER_WITNESS"), t.Name())
 if err := os.WriteFile(path+".pid", []byte(strconv.Itoa(os.Getpid())), 0600); err != nil { t.Fatal(err) }
 t.Cleanup(func() { if err := os.WriteFile(path+".done", nil, 0600); err != nil { t.Error(err) } })
}
func preparedRunnerWitness(t *testing.T, peer string) {
 preparedRunnerMark(t)
 directory := os.Getenv("ENKV_PREPARED_RUNNER_WITNESS")
 if os.Getenv("ENKV_PREPARED_RUNNER_PARALLEL") != "4" {
  if _, err := os.Stat(filepath.Join(directory, peer+".pid")); err == nil {
   if _, err := os.Stat(filepath.Join(directory, peer+".done")); err != nil { t.Fatal("parallel one overlapped independent roots") }
  }
  return
 }
 deadline := time.Now().Add(10*time.Second)
 for {
  if _, err := os.Stat(filepath.Join(directory, peer+".pid")); err == nil { return }
  if time.Now().After(deadline) { t.Fatal("distinct balanced roots did not overlap") }
  time.Sleep(time.Millisecond)
 }
}
// Keep all imports used in each of the four fixture packages.
var _ = syscall.ESRCH
`

const preparedRunnerHelperSource = `
// full_only: false
func TestLiveRun(t *testing.T) { t.Skip("controlled child") }
// full_only: false
func TestLiveChild(t *testing.T) { t.Skip("controlled child") }
// full_only: false
func TestLiveCleanup(t *testing.T) { t.Skip("controlled child") }
// full_only: false
func TestLiveRecovery(t *testing.T) { t.Skip("controlled child") }
// full_only: false
func TestCoordinatorJoinsWorkersAndKeepsCleanupIndependent(t *testing.T) { preparedRunnerMark(t); t.Run("passed", func(t *testing.T) {}) }
// full_only: false
func TestCoordinatorAssertionEvidencePreservesTypedRerun(t *testing.T) { preparedRunnerMark(t); t.Run("valid_marker", func(t *testing.T) {}) }
`

const preparedRunnerLauncherSource = `
// full_only: false
func TestPreparedLauncher(t *testing.T) {
 preparedRunnerIdentity(t)
 if flag.Lookup("test.parallel").Value.String() != os.Getenv("ENKV_PREPARED_RUNNER_PARALLEL") { t.Fatal("launcher lost remaining allowance") }
 directory := os.Getenv("ENKV_PREPARED_RUNNER_WITNESS")
 for _, root := range []string{"TestCoordinatorJoinsWorkersAndKeepsCleanupIndependent", "TestCoordinatorAssertionEvidencePreservesTypedRerun", "TestPreparedAlpha", "TestPreparedBeta"} {
  if _, err := os.Stat(filepath.Join(directory, root+".done")); err != nil { t.Fatal("launcher started before root cleanup", root, err) }
  body, err := os.ReadFile(filepath.Join(directory, root+".pid"))
  if err != nil { t.Fatal(err) }
  pid, err := strconv.Atoi(string(body))
  if err != nil { t.Fatal(err) }
  if err := syscall.Kill(pid, 0); err != syscall.ESRCH { t.Fatal("launcher started before runner process exited", pid, err) }
 }
 if err := os.WriteFile(filepath.Join(directory, "launcher"), nil, 0600); err != nil { t.Fatal(err) }
}
`

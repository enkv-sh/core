package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

type componentWorkerObservation struct {
	PID        int       `json:"pid"`
	Binary     string    `json:"binary"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Exclusive  bool      `json:"exclusive"`
	Roots      []string  `json:"roots"`
	Inner      int       `json:"inner"`
}

// full_only: false
func TestComponentNormalWorkersShareBuildAndJoinBeforeExclusive(t *testing.T) {
	root := workflowExecutionFixture(t)
	build := t.TempDir()
	inventory := []string{"TestAlpha", "TestBeta", "TestGamma", "TestDelta", "TestEpsilon", "TestEta", "TestTheta", "TestZeta", "TestOrdinaryOutputMemoryNativeArtifact", "TestExplicitExclusive"}
	classifications := componentFixtureClassifications(inventory)
	classifications[len(classifications)-1].Exclusive = true
	flags := componentMetadataBuildFlags(t, root, classifications)
	var source strings.Builder
	source.WriteString(`package core
import (
 "encoding/json"
 "flag"
 "fmt"
 "os"
 "path/filepath"
 "strconv"
 "strings"
 "testing"
 "time"
)
var workerRoots []string
func workerRoot(t *testing.T) {
 workerRoots = append(workerRoots, t.Name())
 if os.Getenv("ENKV_COMPONENT_PARTITION_FAILURE") == "1" {
  for i := range 81 {
   t.Run(fmt.Sprintf("left%02d", i), func(t *testing.T) {
    t.Run(fmt.Sprintf("right%02d", i), func(t *testing.T) {
     if i == 0 { t.Fatal("controlled first component partition failure") }
    })
   })
  }
  return
 }
 if os.Getenv("ENKV_COMPONENT_WORKER_PANIC") != "1" { return }
 directory := os.Getenv("ENKV_COMPONENT_WORKER_WITNESS")
 wait := func(name string) {
  deadline := time.Now().Add(20*time.Second)
  for {
   if _, err := os.Stat(filepath.Join(directory,name)); err == nil { return } else if !os.IsNotExist(err) { t.Fatal(err) }
   if time.Now().After(deadline) { t.Fatal("peer did not reach "+name) }
   time.Sleep(time.Millisecond)
  }
 }
 switch t.Name() {
 case "TestAlpha":
  t.Run("left",func(t *testing.T) { t.Run("a",func(t *testing.T) {
   wait("beta-entered")
   if err := os.WriteFile(filepath.Join(directory,"panic-entered"),nil,0600); err != nil { t.Fatal(err) }
   panic("controlled worker failure after peer admission")
  }) })
  t.Run("right",func(t *testing.T) { t.Run("b",func(t *testing.T) {
   if err := os.WriteFile(filepath.Join(directory,"replayed"),nil,0600); err != nil { t.Fatal(err) }
  }) })
 case "TestBeta":
  if err := os.WriteFile(filepath.Join(directory,"beta-entered"),nil,0600); err != nil { t.Fatal(err) }
  wait("panic-entered")
 }
}
func TestMain(m *testing.M) {
 for _, arg := range os.Args {
  if arg == "-test.list" || strings.HasPrefix(arg, "-test.list=") { os.Exit(m.Run()) }
 }
 directory := os.Getenv("ENKV_COMPONENT_WORKER_WITNESS")
 if directory == "" { os.Exit(m.Run()) }
 expected, err := strconv.Atoi(os.Getenv("ENKV_COMPONENT_WORKER_EXPECTED")); if err != nil { panic(err) }
 exclusive := false
 for _, arg := range os.Args { if strings.HasPrefix(arg, "-test.run=") { exclusive = strings.Contains(arg, "TestOrdinaryOutputMemoryNativeArtifact") || strings.Contains(arg, "TestExplicitExclusive") } }
 started := time.Now().UTC()
 marker := filepath.Join(directory, fmt.Sprintf("ready-%d", os.Getpid()))
 if !exclusive {
  if err := os.WriteFile(marker, []byte(fmt.Sprintf("%d %s\n",os.Getpid(),started.Format(time.RFC3339Nano))), 0600); err != nil { panic(err) }
  deadline := time.Now().Add(20*time.Second)
  for {
   ready, err := filepath.Glob(filepath.Join(directory,"ready-*")); if err != nil { panic(err) }
   if len(ready) == expected { break }
   if time.Now().After(deadline) { panic("normal workers did not overlap") }
   time.Sleep(time.Millisecond)
  }
 }
 code := m.Run()
 binary, err := os.Executable(); if err != nil { panic(err) }
 inner := flag.Lookup("test.parallel").Value.String()
 n, err := strconv.Atoi(inner); if err != nil { panic(err) }
 row := map[string]any{"pid":os.Getpid(), "binary":binary, "started_at":started, "finished_at":time.Now().UTC(), "exclusive":exclusive, "roots":workerRoots, "inner":n}
 body, err := json.Marshal(row); if err != nil { panic(err) }
 if err := os.WriteFile(filepath.Join(directory,fmt.Sprintf("joined-%d.json",os.Getpid())),body,0600); err != nil { panic(err) }
 os.Exit(code)
}
`)
	for _, row := range classifications {
		fmt.Fprintf(&source, "// full_only: false\n// exclusive: %t\nfunc %s(t *testing.T) { workerRoot(t) }\n", row.Exclusive, row.Name)
	}
	if err := os.WriteFile(filepath.Join(root, "core/classification_test.go"), []byte(source.String()), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(withRacePolicy(workflowTestContext(t, root), false), 2*time.Minute)
	defer cancel()
	binary := filepath.Join(build, "component-workers.test")
	args := append([]string{"test"}, compilerBuildFlags(flags, false)...)
	if _, err := runGo(ctx, root, "core", append(args, "-c", "-o", binary, ".")...); err != nil {
		t.Fatal(err)
	}
	converter := testEventConverterFixture(t, root)
	owner := capturedComponentFixtureOwner(t, ctx, root, binary, converter, flags)
	prepared, _, err := prepareComponentChecks(nil, ctx, root, binary, flags, workerEnvironment(""), "dev", nil, owner)
	if err != nil {
		t.Fatal(err)
	}
	owner.componentSelection = prepared
	binaryHash, err := assemblyFileSHA256(binary)
	if err != nil {
		t.Fatal(err)
	}
	canonicalBinary, err := filepath.EvalSymlinks(binary)
	if err != nil {
		t.Fatal(err)
	}
	for _, parallel := range []int{1, 2, 4} {
		t.Run(fmt.Sprintf("parallel=%d", parallel), func(t *testing.T) {
			directory := t.TempDir()
			env := environment(workerEnvironment(""), map[string]string{"ENKV_COMPONENT_WORKER_WITNESS": directory, "ENKV_COMPONENT_WORKER_EXPECTED": strconv.Itoa(parallel)})
			process, evidence, stdout, stderr := executeProfileComponentChecks(nil, withExecutionParallel(ctx, parallel), root, binary, converter, flags, env, "dev", nil, parallel, io.Discard, owner)
			if process.Status != "passed" || !process.Joined || !evidence.TestsComplete || !componentEvidenceMatchesInventory(inventory, evidence.Tests) {
				t.Fatalf("normal worker execution failed: %+v stdout=%s stderr=%s", process, stdout.Bytes(), stderr.Bytes())
			}
			paths, err := filepath.Glob(filepath.Join(directory, "joined-*.json"))
			if err != nil || len(paths) != parallel+2 {
				t.Fatal("worker process ownership differs", len(paths), err)
			}
			var normal, exclusive []componentWorkerObservation
			seen := map[string]bool{}
			for _, path := range paths {
				body, err := os.ReadFile(path)
				var row componentWorkerObservation
				if err != nil || json.Unmarshal(body, &row) != nil || row.PID <= 0 || row.Binary != canonicalBinary || row.Inner != 1 || row.StartedAt.IsZero() || row.FinishedAt.Before(row.StartedAt) {
					t.Fatal("invalid physical worker observation", string(body), err)
				}
				t.Logf("physical worker observation: %s", body)
				for _, name := range row.Roots {
					if seen[name] || !slices.Contains(inventory, name) {
						t.Fatal("complete root was duplicated or unselected", name)
					}
					seen[name] = true
				}
				if row.Exclusive {
					exclusive = append(exclusive, row)
				} else {
					normal = append(normal, row)
				}
			}
			if len(normal) != parallel || len(exclusive) != 2 || len(seen) != len(inventory) {
				t.Fatal("worker process classes or root coverage differ", normal, exclusive, seen)
			}
			latestStart, earliestFinish := normal[0].StartedAt, normal[0].FinishedAt
			for _, row := range normal {
				if len(row.Roots) < 2 {
					t.Fatal("normal worker lost compatible multi-root sharing", row)
				}
				if row.StartedAt.After(latestStart) {
					latestStart = row.StartedAt
				}
				if row.FinishedAt.Before(earliestFinish) {
					earliestFinish = row.FinishedAt
				}
				for _, isolated := range exclusive {
					if isolated.StartedAt.Before(row.FinishedAt) {
						t.Fatal("exclusive process preceded normal process completion", row, isolated)
					}
				}
			}
			if !latestStart.Before(earliestFinish) {
				t.Fatal("normal process intervals did not overlap", normal)
			}
			a, b := exclusive[0], exclusive[1]
			if a.StartedAt.Before(b.FinishedAt) && b.StartedAt.Before(a.FinishedAt) {
				t.Fatal("dedicated and shared exclusive processes overlapped", exclusive)
			}
			commands, conversions := 0, 0
			for _, command := range evidence.Diagnostics.Commands {
				if !command.Started || !command.Joined || command.Process != "passed" {
					t.Fatal("started worker or converter lacks its positive join", command)
				}
				if command.Phase == "test" {
					commands++
				}
				if command.Phase == "conversion" {
					conversions++
				}
			}
			if commands != len(paths) || conversions != len(paths) {
				t.Fatal("native command facts lost a physical worker or converter", commands, conversions, len(paths))
			}
			currentHash, err := assemblyFileSHA256(binary)
			if err != nil || currentHash != binaryHash {
				t.Fatal("worker execution changed its shared executable", currentHash, err)
			}
			t.Logf("one compiled binary %s served %d overlapping normal PIDs and two later exclusive PIDs", binaryHash, parallel)
			if path := os.Getenv("ENKV_ARTIFACT_MEASUREMENT"); path != "" {
				file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				row := map[string]any{"kind": "component_parallel", "parallel": parallel, "roots": len(inventory), "builds": 1, "binary": canonicalBinary, "binary_sha256": binaryHash, "workers": normal, "exclusive_workers": exclusive, "test_commands": commands, "conversion_commands": conversions, "joined": true, "race": false, "toolchain": runtime.Version(), "native": runtime.GOOS + "/" + runtime.GOARCH}
				if err := errors.Join(json.NewEncoder(file).Encode(row), file.Close()); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	t.Run("partition-failure-collection-remains-flat", func(t *testing.T) {
		var requests []string
		for i := range 81 {
			requests = append(requests, fmt.Sprintf("TestAlpha/left%02d/right%02d", i, i))
		}
		focusedOwner := *owner
		focusedOwner.componentSelection = nil
		env := environment(workerEnvironment(""), map[string]string{"ENKV_COMPONENT_PARTITION_FAILURE": "1"})
		process, evidence, stdout, stderr := executeProfileComponentChecks(nil, withExecutionParallel(ctx, 4), root, binary, converter, flags, env, "dev", requests, 4, io.Discard, &focusedOwner)
		if process.Status == "passed" || process.Cause == nil || !process.Started || !process.Joined || evidence.TestsComplete || len(evidence.Groups) != len(requests) {
			t.Fatalf("partition collection lost its joined failure: %+v stdout=%s stderr=%s", process, stdout.Bytes(), stderr.Bytes())
		}
		leaves := map[string]string{}
		for _, row := range evidence.Tests {
			if slices.Contains(requests, row.Name) {
				if _, seen := leaves[row.Name]; seen {
					t.Fatal("literal leaf executed more than once", row.Name)
				}
				leaves[row.Name] = row.Outcome
			}
		}
		if len(leaves) != len(requests) {
			t.Fatal("partition collection omitted selected leaves", len(leaves))
		}
		for index, request := range requests {
			want := "passed"
			if index == 0 {
				want = "failed"
			}
			if leaves[request] != want {
				t.Fatal("partition collection changed a selected terminal", request, leaves[request], want)
			}
		}
		commands := 0
		for _, fact := range evidence.Diagnostics.Commands {
			if fact.Phase == "test" || fact.Phase == "conversion" {
				commands++
				if !fact.Started || !fact.Joined {
					t.Fatal("partition command lacks its positive join", fact)
				}
			}
		}
		if commands != 2*len(requests) || !containedCheckFailure(ctx, process.Cause) || !toolCommandsJoined(process.Cause) {
			t.Fatal("successful partitions changed the joined failure classification", commands, process.Cause)
		}
		if !bytes.Contains(stdout.Bytes(), []byte("controlled first component partition failure")) {
			t.Fatal("partition collection lost its returned assertion capture", stdout.String())
		}
		var diagnostic bytes.Buffer
		if err := writeAssemblyDiagnosticBody(&diagnostic, process.Cause); err != nil || !strings.Contains(diagnostic.String(), "component phase selected-1") || strings.Contains(diagnostic.String(), "Additional cause branches truncated") {
			t.Fatal("partition collection hid its original diagnostic", err, diagnostic.String())
		}
	})
	t.Run("panic-stops-queued-partitions-and-drains-peer", func(t *testing.T) {
		directory := t.TempDir()
		env := environment(workerEnvironment(""), map[string]string{"ENKV_COMPONENT_WORKER_WITNESS": directory, "ENKV_COMPONENT_WORKER_EXPECTED": "2", "ENKV_COMPONENT_WORKER_PANIC": "1"})
		requests := []string{"TestAlpha/left/a", "TestAlpha/right/b", "TestBeta"}
		focusedOwner := *owner
		focusedOwner.componentSelection = nil
		process, evidence, stdout, stderr := executeProfileComponentChecks(nil, withExecutionParallel(ctx, 2), root, binary, converter, flags, env, "dev", requests, 2, io.Discard, &focusedOwner)
		if process.Status == "passed" || process.Cause == nil || !process.Joined || evidence.TestsComplete || len(evidence.Groups) != 3 {
			t.Fatalf("panic lost its joined failure or queued selection: %+v stdout=%s stderr=%s", process, stdout.Bytes(), stderr.Bytes())
		}
		if evidence.Groups[0].Outcome == "passed" || evidence.Groups[1].Outcome != "not_run" || evidence.Groups[2].Outcome != "passed" {
			t.Fatal("abnormal process restarted selection or discarded its active peer", evidence.Groups)
		}
		outcomes := map[string]string{}
		for _, row := range evidence.Tests {
			outcomes[row.Name] = row.Outcome
		}
		if outcomes["TestBeta"] != "passed" || outcomes["TestAlpha/right/b"] != "not_run" || outcomes["TestAlpha/left/a"] == "passed" {
			t.Fatal("panic changed completed, incomplete or unstarted terminals", evidence.Tests)
		}
		if _, err := os.Stat(filepath.Join(directory, "replayed")); !os.IsNotExist(err) {
			t.Fatal("queued incompatible child partition ran after package termination", err)
		}
		ready, err := filepath.Glob(filepath.Join(directory, "ready-*"))
		if err != nil || len(ready) != 2 {
			t.Fatal("panic fixture did not admit its two actual peer processes", ready, err)
		}
		joined, err := filepath.Glob(filepath.Join(directory, "joined-*.json"))
		if err != nil || len(joined) != 1 {
			t.Fatal("panic did not leave exactly one normally completed peer", joined, err)
		}
		body, err := os.ReadFile(joined[0])
		var peer componentWorkerObservation
		if err != nil || json.Unmarshal(body, &peer) != nil || !slices.Equal(peer.Roots, []string{"TestBeta"}) {
			t.Fatal("the started peer did not finish its own selected root", string(body), err)
		}
		for _, path := range ready {
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("panic peer native admission: %s", body)
		}
		t.Logf("drained peer native completion: %s", body)
		started, failed := 0, 0
		for _, command := range evidence.Diagnostics.Commands {
			if command.Phase == "test" && command.Started {
				started++
				if !command.Joined {
					t.Fatal("started panic or peer process did not join", command)
				}
				if command.Process != "passed" {
					failed++
				}
			}
		}
		if started != 2 || failed != 1 {
			t.Fatal("native facts hid a replay or failed peer settlement", started, failed)
		}
	})
}

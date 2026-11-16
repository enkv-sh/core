package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// full_only: false
func TestCompilerCaptureKeepsClassifiedSelectionAcrossTestEdits(t *testing.T) {
	t.Run("unavailable-status", func(t *testing.T) {
		ordinary := false
		rows := []testClassification{{Name: "TestKnown", FullOnly: &ordinary}, {Name: "TestUnknown", Unavailable: true}}
		names := []string{"TestKnown", "TestUnknown"}
		for _, profile := range []string{"dev", "full"} {
			selected, omitted, err := selectClassifiedTests(names, rows, profile)
			if err != nil || !slices.Equal(selected, []string{"TestKnown"}) || !slices.Equal(omitted, []string{"TestUnknown"}) {
				t.Fatal("unavailable root entered profile", profile, selected, omitted, err)
			}
		}
		if _, err := selectedRootsBig("example.org/fixture", []string{"TestUnknown"}, rows); err == nil {
			t.Fatal("unavailable exact request acquired a resource class")
		}
		for _, bad := range []testClassification{{Name: "TestUnknown"}, {Name: "TestUnknown", Unavailable: true, FullOnly: &ordinary}, {Name: "TestUnknown", Unavailable: true, Exclusive: true}} {
			if _, _, err := selectClassifiedTests(names, []testClassification{rows[0], bad}, "full"); err == nil {
				t.Fatal("missing/inconsistent classification was admitted", bad)
			}
		}
	})
	for _, kind := range []string{"ordinary", "assembly"} {
		for _, change := range []string{"existing-file", "added-file"} {
			t.Run(kind+"/"+change, func(t *testing.T) {
				fixture, root, bootstrap := componentRepetitionAssemblyFixture(t)
				module, packageName, testPath := "telemetry", "witness", "telemetry/witness/stable_test.go"
				if kind == "assembly" {
					module, packageName, testPath = "core", "core", "tests/shared/compiler_capture_fixture_test.go"
					for _, group := range []string{"tests/shared", "tests/hermetic"} {
						entries, err := os.ReadDir(filepath.Join(root, group))
						if err != nil {
							t.Fatal(err)
						}
						for _, entry := range entries {
							if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") {
								if err := os.Remove(filepath.Join(root, group, entry.Name())); err != nil {
									t.Fatal(err)
								}
							}
						}
					}
					writeLocalGoFixture(t, root, "tests/hermetic/capture_profile_test.go", "package core\nimport \"testing\"\n// full_only: true\nfunc TestCaptureProfileOmitted(t *testing.T){t.Fatal(\"profile omitted root ran\")}\n")
				} else {
					writeLocalGoFixture(t, root, "telemetry/go.mod", "module enkv.sh/telemetry\n\ngo 1.27.0\n")
				}
				sourceDirectory := filepath.Dir(testPath)
				if kind == "assembly" {
					sourceDirectory = "core"
				}
				writeLocalGoFixture(t, root, sourceDirectory+"/capture_live.go", "package "+packageName+"\nvar CompilerCaptureValue=1\n")
				writeLocalGoFixture(t, root, testPath, `package `+packageName+`
import("os";"testing")
// full_only: false
func TestCompilerCaptureStable(t *testing.T){
 if CompilerCaptureValue!=2 {t.Fatal("production source edit was not compiled")}
 file,err:=os.OpenFile(os.Getenv("ENKV_COMPILER_CAPTURE_BODY"),os.O_CREATE|os.O_APPEND|os.O_WRONLY,0600);if err!=nil{t.Fatal(err)}
 _,writeErr:=file.WriteString(t.Name()+"\n");closeErr:=file.Close();if writeErr!=nil||closeErr!=nil{t.Fatal(writeErr,closeErr)}
}
`)
				directory := t.TempDir()
				marker := filepath.Join(directory, "bodies")
				changed := filepath.Join(directory, "changed")
				t.Setenv("ENKV_COMPILER_CAPTURE_BODY", marker)
				payload := filepath.Join(directory, "added-source")
				newSource := "\n// full_only: true\n// exclusive: true\nfunc TestCompilerCaptureNew(t *testing.T){t.Fatal(\"new maximum root must not run\")}\n"
				destination := filepath.Join(root, testPath)
				action := "cat " + shellQuote(payload) + " >> " + shellQuote(destination)
				if change == "added-file" {
					newSource = "package " + packageName + "\nimport \"testing\"\n" + newSource
					destination = filepath.Join(root, sourceDirectory, "late_added_test.go")
					action = "cp " + shellQuote(payload) + " " + shellQuote(destination)
				}
				if err := os.WriteFile(payload, []byte(newSource), 0600); err != nil {
					t.Fatal(err)
				}
				realGo, err := exec.LookPath("go")
				if err != nil {
					t.Fatal(err)
				}
				script := "#!/bin/sh\ncompile=false\nfor argument do [ \"$argument\" != -c ] || compile=true; done\nif [ \"$compile\" = true ] && [ \"$PWD\" = " + shellQuote(filepath.Join(root, module)) + " ] && [ ! -e " + shellQuote(changed) + " ]; then\n" + action + "\nprintf '%s\\n' " + shellQuote("package "+packageName) + " 'var CompilerCaptureValue=2' > " + shellQuote(filepath.Join(root, sourceDirectory, "capture_live.go")) + "\nprintf edited > " + shellQuote(changed) + "\nfi\nexec " + shellQuote(realGo) + " \"$@\"\n"
				if err := os.WriteFile(filepath.Join(directory, "go"), []byte(script), 0700); err != nil {
					t.Fatal(err)
				}
				t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
				step := func(id string, requests []string) map[string]any {
					value := map[string]any{"id": id, "kind": "component-tests", "profile": "dev"}
					if kind == "ordinary" {
						value["kind"] = "unit"
						delete(value, "profile")
						value["packages"] = []string{"telemetry/witness"}
						if requests != nil {
							value["package"] = "telemetry/witness"
						}
					}
					if requests != nil {
						value["tests"] = requests
					}
					return value
				}
				steps := []any{step("exact", []string{"TestCompilerCaptureStable"}), step("whole", nil)}
				packageOnly := kind == "ordinary" && change == "added-file"
				if packageOnly {
					scope := step("package", nil)
					scope["package"] = "telemetry/witness"
					steps = append(steps, scope)
				}
				workflow := filepath.Join(directory, "workflow.json")
				saveSelection(t, workflow, map[string]any{"schema_version": 1, "name": "compiler-capture", "profile": "dev", "execution": map[string]any{"parallel": 1}, "steps": steps})
				ctx, cancel := context.WithTimeout(fixture, 2*time.Minute)
				defer cancel()
				plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: workflow})
				if err != nil {
					t.Fatal(err)
				}
				prepared, err := prepareWorkflow(ctx, root, bootstrap, plan, io.Discard)
				if prepared != nil {
					defer func() {
						finish, release := finalizationContext(ctx)
						defer release()
						if err := prepared.close(finish); err != nil {
							t.Error(err)
						}
					}()
				}
				if err != nil {
					t.Fatal(err)
				}
				var terminal bytes.Buffer
				result, runErr := runPreparedWorkflow(ctx, root, bootstrap, prepared, &terminal)
				wantWhole := "passed"
				if change == "added-file" {
					wantWhole = "failed"
				}
				if len(result.Steps) != len(steps) || result.Steps[0].Outcome != "passed" || result.Outcome != wantWhole || (runErr != nil) != (change == "added-file") {
					t.Fatal("captured exact selection or whole-profile outcome differs", runErr, result.Steps, terminal.String())
				}
				if result.Steps[1].Outcome != wantWhole {
					t.Fatal("whole-profile gap outcome differs", result.Steps, terminal.String())
				}
				wantBodies := 2
				if packageOnly {
					wantBodies = 3
					current := result.executions["package"].Ordinary
					if result.Steps[2].Outcome != "failed" || current == nil || current.Focus == nil || len(current.Focus.Tests) != 0 || current.Complete || current.SelectedComplete || len(current.Tests) != 1 || current.Tests[0].Name != "TestCompilerCaptureStable" || current.Tests[0].Outcome != "pass" {
						t.Fatal("package-only scope hid its gap or skipped known work", result.Steps, current, terminal.String())
					}
					if prepared.ordinary["package"].artifacts[0].binary != prepared.ordinary["exact"].artifacts[0].binary {
						t.Fatal("package-only scope rebuilt prepared executable")
					}
					forged := *current
					forged.SelectedComplete = true
					if validOrdinaryFocusedEvidence(forged) {
						t.Fatal("package-only incomplete classification acquired selected-complete credit")
					}
				}
				bodies, err := os.ReadFile(marker)
				if err != nil || strings.Count(string(bodies), "TestCompilerCaptureStable\n") != wantBodies {
					t.Fatal("known exact/profile roots did not both execute", string(bodies), err, terminal.String())
				}
				if _, err := os.Stat(changed); err != nil {
					t.Fatal("compiler edit barrier was not reached", err)
				}
				whole := result.executions["whole"]
				if whole.Ordinary != nil {
					for _, row := range whole.Ordinary.Tests {
						if row.Name == "TestCompilerCaptureNew" {
							t.Fatal("unrun unknown root acquired terminal/timing facts")
						}
					}
				}
				if whole.Component != nil && whole.Component.Checks != nil {
					for _, row := range whole.Component.Checks.Tests {
						if row.Name == "TestCompilerCaptureNew" {
							t.Fatal("unrun unknown root acquired terminal/timing facts")
						}
					}
				}
				exact := result.executions["exact"]
				var names []string
				var rows []testClassification
				var omitted []string
				if kind == "ordinary" {
					if exact.Ordinary == nil || len(exact.Ordinary.Packages) != 1 {
						t.Fatal("ordinary result absent")
					}
					pkg := exact.Ordinary.Packages[0]
					names, rows, omitted = pkg.Inventory, pkg.Classifications, pkg.NotSelected
				} else {
					if exact.Component == nil || exact.Component.Checks == nil {
						t.Fatal("assembly result absent")
					}
					checks := exact.Component.Checks
					names, rows, omitted = checks.Inventory, checks.Classifications, checks.NotSelected
				}
				if kind == "ordinary" {
					var artifacts []ordinaryArtifact
					for _, artifact := range prepared.ordinary["exact"].artifacts {
						artifacts = append(artifacts, artifact.ordinaryArtifact)
					}
					if _, err := resolveOrdinaryFocusSet(artifacts, ordinaryFocus{PackagePath: "telemetry/witness", Tests: []string{"TestCompilerCaptureNew"}}); err == nil {
						t.Fatal("unknown exact ordinary request was admitted")
					}
				} else if _, _, _, _, err := resolveComponentGroups(names, rows, "dev", []string{"TestCompilerCaptureNew"}, 4, componentEstimates); err == nil {
					t.Fatal("unknown exact component request was admitted")
				}
				if change == "added-file" {
					index := slices.Index(names, "TestCompilerCaptureNew")
					if index < 0 || index >= len(rows) || rows[index].FullOnly != nil || !rows[index].Unavailable || !slices.Contains(omitted, "TestCompilerCaptureNew") {
						t.Fatal("actual unknown inventory was lost or admitted", names, rows, omitted)
					}
				} else if slices.Contains(names, "TestCompilerCaptureNew") {
					t.Fatal("metadata and compiled test bytes came from different reads", names)
				}
				if big, err := selectedRootsBig(modulePath(module)+map[bool]string{true: "", false: "/witness"}[kind == "assembly"], []string{"TestCompilerCaptureStable"}, rows); err != nil || big {
					t.Fatal("known root lost normal admission", big, err)
				}
				t.Logf("%s/%s: exact passed, whole %s, unknown refused; actual edit reached", kind, change, wantWhole)
			})
		}
	}
}

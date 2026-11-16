package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// full_only: false
func TestCommandWorkflowBlocksFailedSharedAssemblyWithoutRetry(t *testing.T) {
	for _, boundary := range []string{"assembly-compile", "output-build", "assembly-source-change", "output-descriptor-change"} {
		t.Run(boundary, func(t *testing.T) {
			fixtureCtx, root, bootstrap := componentRepetitionAssemblyFixture(t)
			directory := t.TempDir()
			attempts, witness := filepath.Join(directory, "compiles"), filepath.Join(directory, "body")
			changed := filepath.Join(directory, "changed-input")
			realGo, err := exec.LookPath("go")
			if err != nil {
				t.Fatal(err)
			}
			realGo, err = filepath.EvalSymlinks(realGo)
			if err != nil {
				t.Fatal(err)
			}
			// Refuse only the supervised assembly compiler. Discovery, vet, input
			// identity and independent module commands still use the real Go tool.
			condition := "[ \"$PWD\" = " + shellQuote(filepath.Join(root, "core")) + " ] && [ \"$1\" = test ] && [ \"$compile\" = true ]"
			descriptorChange := ""
			if boundary == "output-build" || boundary == "output-descriptor-change" {
				outputDirectory, err := sourcePath(root, outputTestModule)
				if err != nil {
					t.Fatal(err)
				}
				condition = "[ \"$PWD\" = " + shellQuote(outputDirectory) + " ] && [ \"$1\" = build ]"
				if boundary == "output-descriptor-change" {
					descriptor := filepath.Join(outputDirectory, "cmd", "enkv-output-contract-test", "plugin.json")
					descriptorChange = "if [ \"$PWD\" = " + shellQuote(outputDirectory) + " ] && [ \"$1\" = list ]; then\n case \" $* \" in *\" -m \"*) printf ' ' >> " + shellQuote(descriptor) + " || exit 94; printf 'changed\\n' > " + shellQuote(changed) + " || exit 95 ;; esac\nfi\n"
				}
			}
			change := ""
			originalSource := filepath.Join(root, "tests/shared/repetition_process_fixture_test.go")
			const sourceEdit = "\n// changed after test declaration capture\n"
			if boundary == "assembly-source-change" {
				// The compiler overlay is immutable captured output. Edit its
				// original checkout source after capture instead.
				change = " printf '%s' " + shellQuote(sourceEdit) + " >> " + shellQuote(originalSource) + " || exit 93\n printf 'changed\\n' > " + shellQuote(changed) + " || exit 95\n"
			}
			script := "#!/bin/sh\n" + descriptorChange + "compile=false\nfor argument do\n if [ \"$argument\" = -c ]; then compile=true; fi\ndone\nif " + condition + "; then\n printf 'attempted\\n' >> " + shellQuote(attempts) + " || exit 92\n" + change + " exit 73\nfi\nexec " + shellQuote(realGo) + " \"$@\"\n"
			if err := os.WriteFile(filepath.Join(directory, "go"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("ENKV_PREPARATION_WITNESS", witness)
			writeLocalGoFixture(t, root, "telemetry/sharedassemblywitness/witness_test.go", `package witness
import ("os"; "testing")
// full_only: false
func TestIndependent(t *testing.T) {
 f,err:=os.OpenFile(os.Getenv("ENKV_PREPARATION_WITNESS"),os.O_CREATE|os.O_WRONLY|os.O_APPEND,0600)
 if err!=nil { t.Fatal(err) }
 if _,err:=f.WriteString("executed\n");err!=nil { t.Fatal(err) }
 if err:=f.Close();err!=nil { t.Fatal(err) }
}
`)
			path := filepath.Join(directory, "workflow.json")
			saveSelection(t, path, map[string]any{"schema_version": 1, "name": "shared-assembly-failure", "profile": "dev", "execution": map[string]any{"parallel": 1}, "steps": []any{
				map[string]any{"id": "first", "kind": "component-tests", "profile": "dev", "tests": singleTestRequest("TestFiniteRepetitionProcessWitness")},
				map[string]any{"id": "consumer", "kind": "component-tests", "profile": "full", "tests": singleTestRequest("TestFiniteRepetitionProcessWitness/leaf[a]+b")},
				map[string]any{"id": "independent", "kind": "unit", "packages": []string{"telemetry/sharedassemblywitness"}},
			}})
			ctx, cancel := context.WithTimeout(fixtureCtx, 4*time.Minute)
			defer cancel()
			plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path})
			if err != nil {
				t.Fatal(err)
			}
			prepared, prepareErr := prepareWorkflow(ctx, root, bootstrap, plan, io.Discard)
			if prepared == nil || prepareErr == nil || !toolCommandsJoined(prepareErr) || !sourceCommandsJoined(prepareErr) {
				t.Fatal("shared compiler failure did not retain settled preparation", prepareErr)
			}
			var exit *exec.ExitError
			if !errors.As(prepareErr, &exit) || exit.ExitCode() != 73 {
				t.Fatal("shared build lost the original compiler refusal", prepareErr)
			}
			defer func() {
				if !prepared.closed {
					if err := prepared.close(ctx); err != nil {
						t.Error(err)
					}
				}
			}()
			if boundary == "output-build" {
				outputCtx := useInvocationArtifacts(ctx, prepared.assemblyPreparations)
				_, blockedErr := buildOutputTestArtifactOwned(nil, outputCtx, root, directory, plan.Race)
				var dependency *sharedArtifactFailure
				if !errors.As(blockedErr, &dependency) {
					t.Fatal("shared output failure did not block an independent assembly consumer", blockedErr)
				}
			}
			var terminal bytes.Buffer
			result, commandErr := executeCommandWorkflow(ctx, root, bootstrap, prepared, prepareErr, &terminal)
			if !errors.Is(commandErr, prepareErr) || !prepared.closed || !prepared.phase.released || !prepared.phase.joined || !toolCommandsJoined(commandErr) || !sourceCommandsJoined(commandErr) {
				t.Fatal("outer owner lost the shared failure or positive cleanup", commandErr)
			}
			if boundary == "assembly-source-change" || boundary == "output-descriptor-change" {
				body, err := os.ReadFile(changed)
				if err != nil || string(body) != "changed\n" {
					t.Fatal("fixture did not change its captured build input", string(body), err)
				}
			}
			if boundary == "assembly-source-change" {
				body, err := os.ReadFile(originalSource)
				if err != nil || !bytes.HasSuffix(body, []byte(sourceEdit)) {
					t.Fatal("compiler boundary did not edit the original checkout source", err)
				}
			}
			if !containedCheckFailure(ctx, prepareErr) {
				t.Fatal("settled compiler failure stopped independent work", prepareErr)
			}
			body, err := os.ReadFile(witness)
			if err != nil || string(body) != "executed\n" {
				t.Fatal("independent prepared module did not execute exactly once", string(body), err, terminal.String())
			}
			body, err = os.ReadFile(attempts)
			if err != nil || string(body) != "attempted\n" {
				t.Fatal("shared assembly compiler was retried or omitted", string(body), err)
			}
			if result.Outcome == "passed" || len(result.Steps) != 3 || result.Steps[0].Outcome != "not_run" || result.Steps[1].Outcome != "not_run" || result.Steps[2].Outcome != "passed" {
				t.Fatal("workflow lost blocked consumers or independent success", result.Steps)
			}
			for _, id := range []string{"first", "consumer"} {
				if prepared.preparationFailures[id] == nil || result.executions[id].Component != nil {
					t.Fatal("failed shared assembly acquired a component result", id)
				}
			}
			var dependency *sharedArtifactFailure
			if !errors.As(prepared.preparationFailures["consumer"], &dependency) {
				t.Fatal("later consumer lost its explicit failed prerequisite", prepared.preparationFailures["consumer"])
			}
			for _, id := range []string{"first", "consumer"} {
				failed := 0
				for _, command := range prepared.preparations[id].Commands {
					if command.Process == "process_failed" {
						failed++
						if !command.Started || !command.Joined || command.WallSeconds == nil {
							t.Fatal("shared compiler lost settlement or timing", command)
						}
					}
				}
				want := 0
				if id == "first" {
					want = 1
				}
				if failed != want {
					t.Fatal("blocked consumer invented or repeated compiler facts", id, failed)
				}
			}
		})
	}
}

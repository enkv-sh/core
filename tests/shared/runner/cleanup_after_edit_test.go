package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestStandaloneCleanupKeepsExactOwnershipAfterSourceEdits(t *testing.T) {
	for _, condition := range []string{"supported", "changed_target", "unsupported_record", "unfinished_owner", "unjoined_writer"} {
		t.Run(condition, func(t *testing.T) {
			root, original, _, request, _, inventory := grantedRecoveryFixture(t)
			request.race = false
			state := filepath.Dir(inventory)
			oldRun := filepath.Join(filepath.Dir(filepath.Dir(state)), "run.json")
			if err := os.MkdirAll(filepath.Join(root, "core"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "core", "edited.go"), []byte("package core\n\nconst editedCleanupFixture = true\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(state), "build")); !os.IsNotExist(err) {
				t.Fatal("cleanup fixture unexpectedly has an original executable", err)
			}
			inputPath := filepath.Join(state, "input.json")
			if condition == "changed_target" {
				var input workerInput
				if records.ReadJSON(inputPath, &input) != nil {
					t.Fatal("original cleanup input unavailable")
				}
				input.Settings["bucket"] = "another-owned-looking-bucket"
				if records.WriteJSON(inputPath, input, 0400) != nil {
					t.Fatal("changed target fixture unavailable")
				}
			}
			switch condition {
			case "unsupported_record":
				original.SchemaVersion++
			case "unfinished_owner":
				original.FinishedAt = nil
			case "unjoined_writer":
				original.Scenarios[0].Writer.Joined = false
			}
			if err := records.WriteJSON(oldRun, original, 0600); err != nil {
				t.Fatal(err)
			}
			before := map[string][]byte{}
			for _, path := range []string{oldRun, inputPath, inventory} {
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				before[path] = body
			}
			plan, err := prepareRecovery(root, request)
			var basis *cleanupRecoveryBasis
			if err == nil {
				plan, basis, err = prepareFixtureRecovery(root, request, plan)
			}
			if condition == "supported" {
				if err != nil || basis == nil || basis.Decision != "gcp_exact_generation_grant" || plan.Grant == nil || len(plan.Entries) != 1 || plan.Entries[0].State != state {
					t.Fatal("supported standalone exact cleanup was not admitted", err)
				}
				current := records.Source{Revision: strings.Repeat("f", 40)}
				s, err := newRunState(root, runRequest{Suite: "live", Provider: "gcp", Target: "gcp", Schedule: recoverySchedule(plan)}, current, "current cleanup toolchain")
				if err != nil {
					t.Fatal(err)
				}
				s.failureSources = controlledFailureSources(t, s.private)
				s.record.RecoveryRunID, s.record.CleanupRecoveryBasis = request.RunID, basis
				s.record.Context, s.record.Limits = safeRunContext(plan.Settings), &plan.Limits
				limitsBody, err := json.Marshal(plan.Limits)
				if err != nil {
					t.Fatal(err)
				}
				plan.Grant.GrantRunID, plan.Grant.GrantLimitsSHA256 = s.record.RunID, digestBytes(limitsBody)
				if err := claimFixtureCleanup(plan, s.record); err != nil {
					t.Fatal("exact cleanup claim refused current source", err)
				}
				binary, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				if err := s.executeRecovery(t.Context(), binary, plan); err != nil {
					t.Fatal(err)
				}
				s.finish()
				if s.record.Outcome != "passed" || len(s.record.Scenarios) != 1 || s.record.Correctness.Passed {
					t.Fatal("cleanup claimed Product work or lost its exact result")
				}
				result := s.record.Scenarios[0]
				if result.Writer != nil || result.Rerun != nil || len(result.Children) != 0 || len(result.PostExit) != 0 || result.CleanupWorker == nil || !result.CleanupWorker.Joined || !scenarioCleanupPassed(result) {
					t.Fatal("cleanup replayed Product work or lost settlement")
				}
				name, err := recordedCaseDirectory(result.Entry)
				if err != nil {
					t.Fatal(err)
				}
				inv, err := records.LoadInvocation(filepath.Join(s.private, name, "cleanup", "invocation.json"))
				var input workerInput
				if err != nil || inv.StateDir != state || inv.RunID == request.RunID || records.ReadJSON(inv.Input, &input) != nil || input.RunID != request.RunID || input.Prefix != plan.Entries[0].Input.Prefix || input.Settings["bucket"] != plan.Entries[0].Input.Settings["bucket"] {
					t.Fatal("cleanup changed the original target or ownership", err)
				}
				if err := claimFixtureCleanup(plan, s.record); err == nil {
					t.Fatal("cleanup grant was usable twice")
				}
			} else if err == nil {
				t.Fatal("unsupported or unsettled cleanup reached dispatch")
			}
			_, called := os.Stat(filepath.Join(state, "cleanup-called.json"))
			if (called == nil) != (condition == "supported") {
				t.Fatal("cleanup effect counter differs", called)
			}
			for _, name := range []string{"ready.json", "facts.json"} {
				if _, err := os.Stat(filepath.Join(state, name)); !os.IsNotExist(err) {
					t.Fatal("cleanup entered a Product worker", err)
				}
			}
			for path, body := range before {
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(body, after) {
					t.Fatal("cleanup changed original records", path, err)
				}
			}
		})
	}
}

// full_only: false
func TestWorkflowRestorationOptionsAreRejected(t *testing.T) {
	for _, command := range []string{"plan", "run"} {
		for _, option := range []string{"--resume=0123456789abcdef0123456789abcdef", "--cleanup-limits=limits.json"} {
			if _, err := workflowArguments([]string{command, "--workflow=workflow.json", option}); err == nil {
				t.Fatal("retired workflow restoration option was accepted", command, option)
			}
		}
	}
}

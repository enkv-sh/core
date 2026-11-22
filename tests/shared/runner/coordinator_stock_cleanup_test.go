package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestCoordinatorStockCleanupRequiresJoinedSuccess(t *testing.T) {
	for _, condition := range []string{
		"passed", "failed-writer", "unjoined-writer", "unstarted-writer", "missing-writer-record",
		"failed-reader", "unjoined-reader", "unstarted-reader", "missing-reader", "missing-reader-record",
		"incomplete-product", "other-state", "recovery", "recovery-input", "legacy-failed-writer", "legacy-recovery",
	} {
		t.Run(condition, func(t *testing.T) {
			s, _ := coordinatorFixture(t)
			entry := catalog.Entry{Scenario: records.StockPluginScenario, Repetition: 1}
			name, err := currentCaseDirectory(entry)
			if err != nil {
				t.Fatal(err)
			}
			state := filepath.Join(s.private, name)
			if err := os.MkdirAll(filepath.Join(state, "workers", "cleanup"), 0700); err != nil {
				t.Fatal(err)
			}
			writer := workerEvidence{Worker: name + "-writer", Role: "writer", Started: true, Joined: true, Process: "passed", Outcome: "passed"}
			reader := workerEvidence{Worker: name + "-fresh-0000-after", Role: "fresh_after", Started: true, Joined: true, Process: "passed", Outcome: "passed"}
			result := scenarioResult{Entry: entry, CorrectnessPassed: true, Writer: &writer, PostExit: []workerEvidence{reader}}
			s.workerRecords = map[string]bool{writer.Worker: true, reader.Worker: true}
			fixture := records.StockPluginFixture{Schema: 1, Purpose: records.StockRetirementProofPurpose,
				FixtureID: strings.Repeat("a", 32), Provider: "aws", Region: "us-east-1", Account: "123456789012", Bucket: "enkv-123456789012-pa-" + strings.Repeat("a", 32)}
			input := workerInput{RunID: s.record.RunID, Scenarios: []string{entry.Scenario}, RecoveryMode: "enabled",
				PublicConfiguration: &publicConfigurationInput{Stock: &records.StockPluginAcceptanceInput{Fixture: fixture}}}
			wantStarted := condition == "passed" || strings.HasPrefix(condition, "legacy-")
			switch condition {
			case "failed-writer", "legacy-failed-writer":
				writer.Process, writer.Outcome = "process_failed", "failed"
			case "unjoined-writer":
				writer.Joined = false
			case "unstarted-writer":
				writer.Started = false
			case "missing-writer-record":
				delete(s.workerRecords, writer.Worker)
			case "failed-reader":
				result.PostExit[0].Process, result.PostExit[0].Outcome = "process_failed", "failed"
			case "unjoined-reader":
				result.PostExit[0].Joined = false
			case "unstarted-reader":
				result.PostExit[0].Started = false
			case "missing-reader":
				result.PostExit = nil
			case "missing-reader-record":
				delete(s.workerRecords, reader.Worker)
			case "incomplete-product":
				result.CorrectnessPassed = false
			case "other-state":
				result.Sequence = 1
			case "recovery", "legacy-recovery":
				s.record.RecoveryRunID = strings.Repeat("b", 32)
			case "recovery-input":
				input.StockRecovery = &records.StockPluginRecoveryInput{}
			}
			if strings.HasPrefix(condition, "legacy-") {
				input.PublicConfiguration.Stock.Fixture.Purpose = "stock-plugin-acceptance"
			}
			s.record.Scenarios = []scenarioResult{result}
			inputPath := filepath.Join(state, "cleanup-input.json")
			if records.WriteJSON(inputPath, input, 0400) != nil || records.WriteJSON(filepath.Join(state, "stock-plugin-grant.json"), struct{}{}, 0600) != nil {
				t.Fatal("local cleanup input unavailable")
			}
			binary := prebuiltWorkerArgumentFixture(t)
			inv := records.Invocation{Scenario: entry.Scenario, RunID: s.record.RunID, Worker: writer.Worker + "-cleanup", Role: "cleanup",
				Input: inputPath, StateDir: state, OutputDir: filepath.Join(state, "workers", "cleanup")}
			evidence, cleanup := s.executeCleanup(t.Context(), binary, inv, entry.Scenario, testLimits())
			_, statErr := os.Lstat(binary + ".arguments")
			if wantStarted {
				if statErr != nil || evidence == nil || !evidence.Started || !evidence.Joined {
					t.Fatal("eligible cleanup did not enter and join the controlled native worker", evidence, statErr)
				}
			} else if !os.IsNotExist(statErr) || evidence != nil || cleanup.Outcome != "unresolved" {
				t.Fatal("incomplete stock participants entered cleanup or lost unresolved state", evidence, cleanup, statErr)
			}
		})
	}
}

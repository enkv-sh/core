package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/crypto/testsupport/installedarchive"
)

// full_only: false
func TestLiveConfigurationRecoveryTrustsPreparedArtifactIdentity(t *testing.T) {
	for _, available := range []bool{true, false} {
		name := "available"
		if !available {
			name = "missing"
		}
		t.Run(name, func(t *testing.T) {
			state := t.TempDir()
			binary := filepath.Join(t.TempDir(), "recovery-helper")
			if available {
				body := "#!/bin/sh\nprintf '\\026=== RUN   TestRestrictedAWSReconstructionFromConsoleInputs\\n\\026--- FAIL: TestRestrictedAWSReconstructionFromConsoleInputs (0.01s)\\n\\026FAIL\\n'\nexit 7\n"
				if err := os.WriteFile(binary, []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			captured := strings.Repeat("a", 64)
			race := raceEnabled(testRaceContext(t, t.Context()))
			s := runState{
				recoveryArtifacts: map[string]configurationRecoveryArtifact{"aws": {Path: binary, SHA256: captured}},
				record: runRecord{Provider: "aws", Source: records.Source{Revision: strings.Repeat("b", 40)},
					BuildClosure: &assemblyClosure{Race: race}},
			}
			owner := installedarchive.LiveRecoveryParentInput{Report: filepath.Join(state, "report.json"),
				Input: installedarchive.RecoveryInput{Requests: 10, BodyBytes: 100}}
			result := scenarioResult{BudgetReserved: &records.BudgetReservation{Requests: 1, BodyBytes: 1}}
			joined := true
			err := s.executeLiveConfigurationRecovery(t.Context(), state,
				workerInput{Limits: &limits{Requests: 20, BodyBytes: 200}}, owner,
				time.Now().Add(time.Minute), &result, &joined, true)
			if err == nil || !joined || len(result.Reconstruction) != 1 || len(result.Reconstruction[0].Phases) != 1 {
				t.Fatal("prepared helper did not retain its terminal failure", err, joined, result.Reconstruction)
			}
			phase := result.Reconstruction[0].Phases[0]
			if phase.Started != available || !phase.Joined || phase.Outcome == "passed" || phase.BinarySHA256 != captured {
				t.Fatal("helper execution or captured build observation changed", phase)
			}
			if result.BudgetReserved.Requests != 11 || result.BudgetReserved.BodyBytes != 101 {
				t.Fatal("failed helper lost its reserved allowance", result.BudgetReserved)
			}
		})
	}
}

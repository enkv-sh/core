package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// full_only: false
func TestConfigurationRecoveryPhaseContinuesOnlyWithValidFailedPrefix(t *testing.T) {
	for _, test := range []struct {
		name, body string
		contained  bool
	}{
		{"assertion", "printf '\\026=== RUN   TestControlledFailure\\n\\026--- FAIL: TestControlledFailure (0.01s)\\n\\026FAIL\\n'\nexit 7\n", true},
		{"crash", "kill -KILL $$\n", true},
		{"wrong_root", "printf '\\026=== RUN   TestOther\\n'\nexit 7\n", false},
		{"duplicate_run", "printf '\\026=== RUN   TestControlledFailure\\n\\026=== RUN   TestControlledFailure\\n'\nexit 7\n", false},
		{"save_failure", "printf '\\026=== RUN   TestControlledFailure\\n'\nexit 7\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			binary := filepath.Join(t.TempDir(), "phase")
			if err := os.WriteFile(binary, []byte("#!/bin/sh\n"+test.body), 0700); err != nil {
				t.Fatal(err)
			}
			if test.name == "save_failure" {
				if err := os.Mkdir(filepath.Join(directory, "setup.txt"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			phase, cause := runConfigurationRecoveryPhase(t.Context(), directory, binary, strings.Repeat("a", 64), "setup", "TestControlledFailure", os.Environ())
			projection := configurationRecoveryOutcome(configurationRecoveryProcessEvidence{Provider: "aws", Phases: []configurationRecoveryPhase{phase}})
			if len(projection.Phases) != 1 || projection.Phases[0].Outcome != phase.Process.Status {
				t.Error("failed setup invented a passing restricted child", projection.Phases)
			}
			if cause == nil || !phase.Process.Started || !phase.Process.Joined || containedCheckFailure(t.Context(), cause) != test.contained {
				t.Fatal("recovery phase failure lost containment or concealed invalid evidence", phase.Process, cause)
			}
		})
	}
}

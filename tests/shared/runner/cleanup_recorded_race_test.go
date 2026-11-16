package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// full_only: false
func TestRetiredCleanupGrantRequiresOriginalRaceAgreement(t *testing.T) {
	for _, row := range []struct {
		name                        string
		build, request, current     bool
		missing, null, wantAdmitted bool
	}{
		{"race-original-current-plain", true, true, false, false, false, true},
		{"plain-original-current-race", false, false, true, false, false, true},
		{"race-build-plain-request", true, false, false, false, false, false},
		{"plain-build-race-request", false, true, false, false, false, false},
		{"missing-original-policy", true, false, false, true, false, false},
		{"null-original-policy", true, false, false, false, true, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			root, original, _, request, inventoryPath := awsGrantedRecoveryFixture(t)
			request.race = row.current
			original.BuildClosure.Race = row.build
			original.BuildClosure.RaceOptions, original.BuildClosure.RaceExitSleepMillis = "", 0
			if row.build {
				original.BuildClosure.RaceOptions, original.BuildClosure.RaceExitSleepMillis = "log_path=stderr exitcode=66 halt_on_error=0 atexit_sleep_ms=1000", 1000
			}
			original.Resolved.Race = row.request
			directory := filepath.Dir(filepath.Dir(filepath.Dir(inventoryPath)))
			for _, receipt := range original.CaseReceipts {
				if err := os.Remove(filepath.Join(directory, receipt.Path)); err != nil {
					t.Fatal(err)
				}
			}
			original.CaseReceipts = nil
			state := &runState{directory: directory, record: original}
			identity, err := caseIdentitySHA256(state.record)
			if err != nil || state.writeCaseReceipt(state.record.Scenarios[0], identity) != nil || state.save() != nil {
				t.Fatal("changed policy fixture could not bind its exact receipt", err)
			}
			body, err := json.Marshal(state.record)
			if err != nil {
				t.Fatal(err)
			}
			if row.missing || row.null {
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(body, &fields); err != nil {
					t.Fatal(err)
				}
				var resolved map[string]json.RawMessage
				if err := json.Unmarshal(fields["resolved_request"], &resolved); err != nil {
					t.Fatal(err)
				}
				if row.missing {
					delete(resolved, "scenario_race")
				} else {
					resolved["scenario_race"] = json.RawMessage("null")
				}
				fields["resolved_request"], err = json.Marshal(resolved)
				if err != nil {
					t.Fatal(err)
				}
				body, err = json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
			}
			body = append(body, '\n')
			if err := os.WriteFile(filepath.Join(directory, "run.json"), body, 0600); err != nil {
				t.Fatal(err)
			}
			var recorded runRecord
			if err := json.Unmarshal(body, &recorded); err != nil {
				t.Fatal(err)
			}
			if !row.missing && !row.null {
				var admitted runRecord
				if err := decodeCleanupRecord(body, &admitted); err != nil {
					t.Fatal("complete policy fixture is not a canonical retained record", err)
				}
				if err := validateCaseReceiptSet(directory, admitted); err != nil {
					t.Fatal("complete policy fixture lost its exact receipt custody", err)
				}
			}
			plan, _, _, err := prepareGrantedRecovery(root, recorded, recorded.CaseReceipts[0], request, "")
			if (err == nil) != row.wantAdmitted {
				t.Errorf("original policy admission differs: admitted=%t want=%t error=%v", err == nil, row.wantAdmitted, err)
			}
			if err == nil && plan.OriginalBuild != nil {
				t.Error("current-source cleanup acquired an original-artifact equality requirement")
			}
		})
	}
}

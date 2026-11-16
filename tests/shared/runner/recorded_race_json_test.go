package main

import (
	"encoding/json"
	"testing"
)

func recordedRaceJSONFixture(t *testing.T, enabled bool) runRecord {
	t.Helper()
	_, record := completeRunFixture(t, "gcp")
	options, wait := "", 0
	if enabled {
		options, wait = "log_path=stderr exitcode=66 halt_on_error=0 atexit_sleep_ms=1000", 1000
	}
	record.Resolved.Race = enabled
	record.BuildClosure.Race, record.BuildClosure.RaceOptions, record.BuildClosure.RaceExitSleepMillis = enabled, options, wait
	record.BuildClosure.LocalChecks.Race, record.BuildClosure.LocalChecks.RaceOptions = enabled, options
	for i := range record.BuildClosure.ReconstructionArtifacts {
		record.BuildClosure.ReconstructionArtifacts[i].Race = &enabled
		record.BuildClosure.ReconstructionArtifacts[i].RaceOptions = options
	}
	for i := range record.Scenarios {
		result := &record.Scenarios[i]
		workers := []*workerEvidence{result.Writer, result.Rerun, result.CleanupWorker}
		for j := range result.Children {
			workers = append(workers, &result.Children[j])
		}
		for j := range result.PostExit {
			workers = append(workers, &result.PostExit[j])
		}
		for j := range result.CleanupAttempts {
			workers = append(workers, result.CleanupAttempts[j].Worker)
		}
		for _, worker := range workers {
			if worker != nil {
				worker.Race, worker.RaceOptions = &enabled, options
			}
		}
		for j := range result.Reconstruction {
			result.Reconstruction[j].Race, result.Reconstruction[j].RaceOptions = &enabled, options
		}
	}
	return record
}

// full_only: false
func TestRecordedRaceJSONKeepsFalseAndMissingDistinct(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		name := map[bool]string{false: "plain", true: "race"}[enabled]
		t.Run(name, func(t *testing.T) {
			record := recordedRaceJSONFixture(t, enabled)
			for _, boundary := range []string{"assembly", "checks", "request"} {
				t.Run(boundary, func(t *testing.T) {
					var value any
					field := "race"
					switch boundary {
					case "assembly":
						value = record.BuildClosure
					case "checks":
						value = record.BuildClosure.LocalChecks
					case "request":
						value, field = record.Resolved, "scenario_race"
					}
					body, err := json.Marshal(value)
					if err != nil {
						t.Fatal(err)
					}
					var original map[string]json.RawMessage
					if err := json.Unmarshal(body, &original); err != nil {
						t.Fatal(err)
					}
					want := "false"
					if enabled {
						want = "true"
					}
					if string(original[field]) != want {
						t.Fatalf("known policy was omitted or changed: got %s want %s", original[field], want)
					}
					for _, condition := range []string{"known", "missing", "null", "unknown-field"} {
						t.Run(condition, func(t *testing.T) {
							var fields map[string]json.RawMessage
							if err := json.Unmarshal(body, &fields); err != nil {
								t.Fatal(err)
							}
							switch condition {
							case "missing":
								delete(fields, field)
							case "null":
								fields[field] = json.RawMessage("null")
							case "unknown-field":
								fields["unexpected_race"] = json.RawMessage("true")
							}
							encoded, err := json.Marshal(fields)
							if err != nil {
								t.Fatal(err)
							}
							var got, missing bool
							switch boundary {
							case "assembly":
								var decoded assemblyClosure
								err = json.Unmarshal(encoded, &decoded)
								got, missing = decoded.Race, decoded.raceMissing
							case "checks":
								var decoded checkEvidence
								err = json.Unmarshal(encoded, &decoded)
								got, missing = decoded.Race, decoded.raceMissing
							case "request":
								var decoded resolvedRequest
								err = json.Unmarshal(encoded, &decoded)
								got, missing = decoded.Race, decoded.raceMissing
							}
							if condition == "unknown-field" {
								if err == nil {
									t.Fatal("recorded policy decoder accepted an unknown field")
								}
								return
							}
							if err != nil {
								t.Fatal(err)
							}
							if missing != (condition != "known") || !missing && got != enabled {
								t.Errorf("decoded observation differs: got race=%t missing=%t condition=%s", got, missing, condition)
							}
						})
					}
				})
			}
		})
	}
}

// full_only: false
func TestRecordedRunJSONRequiresConsistentRacePolicy(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		name := map[bool]string{false: "plain", true: "race"}[enabled]
		t.Run(name, func(t *testing.T) {
			fixture := recordedRaceJSONFixture(t, enabled)
			body, err := json.Marshal(fixture)
			if err != nil {
				t.Fatal(err)
			}
			body = append(body, '\n')
			var original runRecord
			if err := decodeCleanupRecord(body, &original); err != nil {
				t.Fatal("valid recorded policy did not round trip", err)
			}
			if observed, known := recordedRunRace(original); !known || observed != enabled || !fullCoverage(original) || !selectedLiveCoverage(original) {
				t.Fatal("known original policy lost its complete selected proof", observed, known)
			}
			for _, current := range []bool{false, true} {
				var candidate runRecord
				if err := json.Unmarshal(body, &candidate); err != nil {
					t.Fatal(err)
				}
				options, wait := "", 0
				if current {
					options, wait = "log_path=stderr exitcode=66 halt_on_error=0 atexit_sleep_ms=1000", 1000
				}
				candidate.BuildClosure.Race, candidate.BuildClosure.RaceOptions, candidate.BuildClosure.RaceExitSleepMillis = current, options, wait
				candidate.BuildClosure.LocalChecks.Race, candidate.BuildClosure.LocalChecks.RaceOptions = current, options
				if got := fullCoverage(candidate); got != (current == enabled) {
					t.Errorf("current/original policy match differs: current=%t original=%t admitted=%t", current, enabled, got)
				}
			}
			for _, boundary := range []string{"assembly", "checks", "request"} {
				for _, condition := range []string{"missing", "null"} {
					t.Run(boundary+"/"+condition, func(t *testing.T) {
						var fields map[string]json.RawMessage
						if err := json.Unmarshal(body, &fields); err != nil {
							t.Fatal(err)
						}
						var build, checks, request map[string]json.RawMessage
						if err := json.Unmarshal(fields["build_closure"], &build); err != nil {
							t.Fatal(err)
						}
						if err := json.Unmarshal(build["local_checks"], &checks); err != nil {
							t.Fatal(err)
						}
						if err := json.Unmarshal(fields["resolved_request"], &request); err != nil {
							t.Fatal(err)
						}
						selected, key := build, "race"
						switch boundary {
						case "checks":
							selected = checks
						case "request":
							selected, key = request, "scenario_race"
						}
						if condition == "missing" {
							delete(selected, key)
						} else {
							selected[key] = json.RawMessage("null")
						}
						build["local_checks"], err = json.Marshal(checks)
						if err != nil {
							t.Fatal(err)
						}
						fields["build_closure"], err = json.Marshal(build)
						if err != nil {
							t.Fatal(err)
						}
						fields["resolved_request"], err = json.Marshal(request)
						if err != nil {
							t.Fatal(err)
						}
						encoded, err := json.Marshal(fields)
						if err != nil {
							t.Fatal(err)
						}
						var damaged runRecord
						if err := json.Unmarshal(encoded, &damaged); err != nil {
							t.Fatal("policy damage changed unrelated JSON fields", err)
						}
						if fullCoverage(damaged) || selectedLiveCoverage(damaged) {
							t.Error("unknown policy observation acquired selected recovery proof")
						}
						if boundary != "checks" {
							if _, known := recordedRunRace(damaged); known {
								t.Error("unknown recorded policy became a known Boolean")
							}
						}
					})
				}
			}
		})
	}
}

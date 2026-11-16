package main

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

// These lookups interpret retained evidence. They do not admit a new run or
// replace the source, artifact and grant checks at continuation boundaries.
func recordedDefinition(name string) (catalog.Definition, bool) {
	if definition, known := catalog.DefinitionFor(name); known {
		return definition, true
	}
	return catalog.HistoricalDefinitionFor(name)
}

func recordedExecution(name, mode string) (catalog.Execution, bool) {
	if execution, known := catalog.ExecutionFor(name, mode); known {
		return execution, true
	}
	return catalog.HistoricalExecutionFor(name, mode)
}

// Current records carry the requested projection; historical evidence keeps
// the original complete execution reader and its positional interpretation.
func recordedExecutionForRecovery(name, mode, recovery string) (catalog.Execution, bool) {
	if _, current := catalog.Name(name); current {
		return catalog.ExecutionForRecovery(name, mode, recovery)
	}
	return recordedExecution(name, mode)
}

func recordedFixture(name string, members int) (catalog.Shape, error) {
	if _, current := catalog.Name(name); current {
		if members != 0 {
			return catalog.Shape{}, errors.New("named case has a numeric fixture override")
		}
		return catalog.FixtureShape(name)
	}
	return catalog.HistoricalFixtureShape(name, members)
}

func recordedHasFixture(name string, capability catalog.FixtureCapability) bool {
	definition, known := recordedDefinition(name)
	if !known || len(definition.Modes) == 0 {
		return false
	}
	execution, known := recordedExecution(name, definition.Modes[0])
	return known && execution.HasFixtureCapability(capability)
}

func recordedPublication(name string) (catalog.LivePublicationCase, bool) {
	if row, known := catalog.LivePublication(name); known {
		return row, true
	}
	return catalog.HistoricalLivePublication(name)
}

func recordedReconstruction(name string) (catalog.ConfigurationRecoveryCase, bool) {
	if row, known := catalog.ConfigurationRecovery(name); known {
		return row, true
	}
	return catalog.HistoricalConfigurationRecovery(name)
}

func recordedReconstructionCells(name, mode string) []catalog.RecoveryProcessCell {
	if _, current := catalog.Name(name); current {
		return catalog.ConfigurationRecoveryCells(name, mode)
	}
	return catalog.HistoricalConfigurationRecoveryCells(name, mode)
}

func reconstructRecordedSchedule(schedule catalog.Schedule) (catalog.Schedule, error) {
	names := append(slices.Clone(schedule.Selected), schedule.NotApplicable...)
	if len(names) == 0 {
		return catalog.Schedule{}, errors.New("recorded case selection is empty")
	}
	if _, current := catalog.Name(names[0]); current {
		if schedule.MemberCounts != nil {
			return catalog.Schedule{}, errors.New("named case schedule has numeric selection")
		}
		expected, err := catalog.Resolve(catalog.Request{Include: names, Repetitions: schedule.Repetitions,
			RecoveryMode: schedule.RecoveryMode, SmokePolicy: schedule.SmokePolicy})
		// Earlier named-case receipts counted their first selected
		// point as smoke 0. Interpret that exact N=1 form without changing the
		// original schedule or admitting it through current execution resolution.
		if err == nil && schedule.Repetitions == 1 && schedule.SmokePolicy == catalog.SmokeFirstSelectedPoint &&
			len(schedule.Entries) != 0 && schedule.Entries[0].Smoke && schedule.Entries[0].Repetition == 0 {
			expected.Entries[0].Repetition = 0
		}
		if err == nil && expected.SmokePolicy == catalog.SmokeSeparatePoint &&
			len(schedule.Entries) == len(expected.Entries)+1 && slices.Contains(expected.Selected, expected.Entries[0].Scenario) {
			historical := expected
			historical.Entries = []catalog.Entry{{Scenario: expected.Entries[0].Scenario, Smoke: true}}
			for repetition := 1; repetition <= expected.Repetitions; repetition++ {
				for _, name := range expected.Selected {
					historical.Entries = append(historical.Entries, catalog.Entry{Scenario: name,
						Sequence: len(historical.Entries), Repetition: repetition})
				}
			}
			if reflect.DeepEqual(schedule, historical) {
				return historical, nil
			}
		}
		return expected, err
	}
	if schedule.SmokePolicy != "" {
		return catalog.Schedule{}, errors.New("historical schedule has current smoke policy")
	}
	return catalog.HistoricalResolve(catalog.HistoricalRequest{Include: names, Members: schedule.MemberCounts,
		Repetitions: schedule.Repetitions, RecoveryMode: schedule.RecoveryMode})
}

func currentCaseDirectory(entry catalog.Entry) (string, error) {
	if entry.Sequence < 0 || entry.Members != 0 {
		return "", errors.New("current case entry refused")
	}
	token, err := catalog.CaseDirectoryToken(entry.Scenario)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%04d-%s", entry.Sequence, token), nil
}

// Historical private state stays at its original dot-to-hyphen path. A name
// migration must not relocate it or change the input's ownership bindings.
func recordedCaseDirectory(entry catalog.Entry) (string, error) {
	if _, current := catalog.Name(entry.Scenario); current {
		return currentCaseDirectory(entry)
	}
	name, known := catalog.HistoricalName(entry.Scenario)
	if !known || entry.Sequence < 0 {
		return "", errors.New("historical case entry refused")
	}
	if _, err := catalog.HistoricalFixtureShape(name, entry.Members); err != nil {
		return "", err
	}
	return fmt.Sprintf("%04d-%s", entry.Sequence, strings.ReplaceAll(name, ".", "-")), nil
}

func recordedSameDomainRecovery(name string) bool {
	return name == sameDomainRecoveryScenario || name == "state.transient-before-send-rerun"
}

// Only retained reading permits earlier complete named history policies.
// Current import calls completeWorkerPhases and never enters this alternative.
func completeRecordedWorkerPhases(role, actor string, phases []records.PhaseResult, scenario, mode string, participants map[string]string, cleanup *records.Cleanup, recovery string, before *catalog.Step) bool {
	if completeWorkerPhases(role, actor, phases, scenario, mode, participants, cleanup, recovery, before) {
		return true
	}
	if role != "writer" || mode != "hermetic" || before != nil {
		return false
	}
	history, namedHistory := catalog.GeneratedHistory(scenario)
	execution, known := catalog.ExecutionForRecovery(scenario, mode, recovery)
	if !namedHistory || !known {
		return false
	}
	// These are the literal original writer policies by original step index.
	// Do not construct the old policy by relaxing each saved mismatching flag.
	var original []bool
	switch execution.Family {
	case catalog.FamilyCombinedHistory:
		original = []bool{true, true, true, true, true, true, true, true, true, true, true, false}
	case catalog.FamilyGeneratedHistory:
		original = []bool{true, true, history.SourceMode == 2, true, true, false, true, false, false}
		if history.Reciprocal {
			original = []bool{true, true, true, true, false, true, true, false, true, true, true, false, true, true, false, true, true, false}
		}
	default:
		return false
	}
	// Before final verification was classified by its actual work, named
	// executions had already moved wholly delegated actions to their children.
	previous := append([]bool(nil), original...)
	switch execution.Family {
	case catalog.FamilyCombinedHistory:
		previous[7] = false
	case catalog.FamilyGeneratedHistory:
		if history.Reciprocal {
			previous[15] = false
		} else {
			previous[3], previous[6] = false, false
		}
	}
	// Validate each whole policy through the same ordered phase, actor,
	// recovery and outcome checks. Never select flags from saved mismatches
	// or rewrite saved phases; mixed policies are not a retained alternative.
	for _, policy := range [][]bool{original, previous} {
		for position, phase := range execution.Writer {
			if phase.StepIndex < 0 || phase.StepIndex >= len(policy) {
				return false
			}
			execution.Writer[position].MeasurementsExpected = policy[phase.StepIndex]
		}
		if completeWorkerPhasesForExecution(execution, role, actor, phases, scenario, mode, participants, cleanup, recovery, before) {
			return true
		}
	}
	return false
}

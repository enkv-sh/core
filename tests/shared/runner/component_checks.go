package main

import (
	"context"
	"errors"
	"io"

	records "enkv.sh/core/internal/testrecords"
)

func checkComponents(initial *checkDiagnostics, parent context.Context, root, directory, binary string, converter preparedTestEventConverter, buildFlags []string, failureSources *records.FailureSourceBinding, profile string, requested []string, parallelism int, output io.Writer, owner *assembly) (checkEvidence, error) {
	env := append(workerEnvironment(""), failureSourcesEnvironment(failureSources)...)
	process, evidence, stdout, stderr := executeProfileComponentChecks(initial, parent, root, binary, converter, buildFlags, env, profile, requested, parallelism, output, owner)
	if err := writeCheckDiagnostics(output, evidence.Diagnostics); err != nil {
		process = componentOutputFailure(process, err)
		evidence.Outcome = process.Status
	}
	if len(requested) == 0 {
		evidence.Selection = profile + " exact inventory in bounded component groups"
	}
	evidence.Race = raceEnabled(parent)
	evidence.RaceOptions = acceptedRaceOptions(evidence.Race)
	complete := completeComponentEvidence(evidence, "hermetic", "memory")
	if len(requested) != 0 {
		complete = completeFocusedComponentEvidence(evidence)
	}
	if process.Status == "passed" && !complete {
		process.Status = "process_failed"
		process.Cause = errors.Join(process.Cause, errors.New("component results lack complete success or helper invocation evidence"))
		evidence.Outcome = process.Status
	}
	if process.Status == "passed" && process.Joined {
		return evidence, nil
	}
	failure := &toolFailure{operation: "component checks", process: process}
	if process.Joined {
		failure.stdout, failure.stderr = stdout.Bytes(), stderr.Bytes()
		failure.overflow = stdout.overflow || stderr.overflow
	}
	phase := "test"
	if evidence.Diagnostics != nil && evidence.Diagnostics.Preparation != "passed" {
		phase = "preparation"
	}
	return evidence, retainCheckFailure(directory, "component-checks.log", phase, failure)
}

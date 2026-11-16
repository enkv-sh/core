package main

import (
	"context"
	"errors"
	"path/filepath"
	"time"
)

type compiledTestInventory struct {
	names           []string
	classifications []testClassification
	sources         map[string]string
	stdout, stderr  *limitedOutput
}

func prepareCompiledInventory(ctx context.Context, root string, value assembly, environment []string, scope string, diagnostics *checkDiagnostics) (compiledTestInventory, error) {
	inventory, _, err := invocationArtifactValue(ctx, root, filepath.Dir(value.Binary), "inventory", value.Binary, func(string) (compiledTestInventory, error) {
		if diagnostics != nil && diagnostics.hasPlan() {
			if err := diagnostics.consumeCommands([]checkCommandFacts{preparationReservationFact(scope, false)}); err != nil {
				return compiledTestInventory{}, err
			}
		}
		started := time.Now()
		process, names, stdout, stderr := executeComponentInventory(ctx, root, value.Binary, environment)
		facts := commandFacts("preparation", scope, process, time.Since(started))
		if process.Joined {
			facts.RaceObservation = observedRace(true, stdout.Bytes(), stderr.Bytes())
		}
		if diagnostics != nil {
			if err := diagnostics.append(facts); err != nil {
				return compiledTestInventory{}, err
			}
		}
		if process.Status != "passed" || !process.Joined {
			failure := &toolFailure{operation: "compiled test inventory", process: process, facts: &facts}
			if process.Joined {
				failure.stdout, failure.stderr, failure.overflow = stdout.Bytes(), stderr.Bytes(), stdout.overflow || stderr.overflow
			}
			return compiledTestInventory{}, failure
		}
		rows, active, err := value.Closure.declarations.classify(map[string][]string{componentPackage: names})
		if err != nil {
			return compiledTestInventory{}, err
		}
		return compiledTestInventory{names: names, classifications: rows[componentPackage], sources: active[componentPackage], stdout: stdout, stderr: stderr}, nil
	})
	return inventory, errors.Join(err, ctx.Err())
}

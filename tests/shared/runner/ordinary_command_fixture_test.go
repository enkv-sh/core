package main

import (
	"context"
	"errors"
	"slices"
	"strings"
)

func executeOrdinaryCommand(ctx context.Context, root, directory, profile string, buildFlags, patterns []string, runPattern string, helperProofs map[string]string, evidence *ordinaryStepEvidence, testFlags ...string) error {
	if evidence.Toolchain == "" {
		version, err := runGo(ctx, root, directory, "version")
		if err != nil {
			return err
		}
		evidence.Toolchain = strings.TrimSpace(string(version))
	}

	evidence.Profile, evidence.RaceOptions = profile, acceptedRaceOptions(raceEnabled(ctx))
	if evidence.Diagnostics == nil {
		evidence.Diagnostics = &checkDiagnostics{Preparation: "pending"}
	}
	want, retained, err := discoverOrdinaryInventory(ctx, root, directory, buildFlags, patterns, runPattern, evidence.Diagnostics, testFlags...)
	if err != nil {
		evidence.Diagnostics.Preparation = "failed"
		return err
	}
	want, retained, err = selectOrdinaryProfile(want, retained, profile)
	if err != nil {
		evidence.Diagnostics.Preparation = "failed"
		return err
	}
	evidence.Diagnostics.Preparation = "passed"
	evidence.Race = raceSetting(raceEnabled(ctx))
	if err := appendOrdinaryInventory(evidence, want, retained); err != nil {
		return err
	}
	if profile != "dev" || !slices.ContainsFunc(retained, func(pkg ordinaryPackage) bool { return len(pkg.NotSelected) != 0 }) {
		return executeOrdinaryInventory(ctx, ctx, root, directory, buildFlags, patterns, runPattern, want, helperProofs, nil, evidence, testFlags...)
	}
	var runErrors []error
	for _, pkg := range retained {
		selection := "^$"
		if len(pkg.Tests) != 0 {
			selection = runnerGroupSelection(pkg.Tests)
		}
		packagePatterns := []string{pkg.Name}
		if pkg.Name == "command-line-arguments" {
			packagePatterns = patterns
		}
		if err := executeOrdinaryInventory(ctx, ctx, root, directory, buildFlags, packagePatterns, selection, map[string][]string{pkg.Name: pkg.Tests}, helperProofs, nil, evidence, testFlags...); err != nil {
			runErrors = append(runErrors, err)
			if !containedCheckFailure(ctx, err) {
				return errors.Join(runErrors...)
			}
		}
	}
	return errors.Join(runErrors...)
}

package main

import (
	"context"
	"debug/buildinfo"
	"errors"
	"strings"
)

type racePolicyContextKey struct{}

func withRacePolicy(ctx context.Context, enabled bool) context.Context {
	return context.WithValue(ctx, racePolicyContextKey{}, enabled)
}

func raceEnabled(ctx context.Context) bool {
	enabled, _ := ctx.Value(racePolicyContextKey{}).(bool)
	return enabled
}

func acceptedRaceOptions(enabled bool) string {
	if enabled {
		return raceOptions
	}
	return ""
}

func validRaceSettings(enabled bool, options string, exitWait int) bool {
	wait := 0
	if enabled {
		wait = 1000
	}
	return options == acceptedRaceOptions(enabled) && exitWait == wait
}

func validRaceOptions(enabled bool, options string) bool {
	return options == acceptedRaceOptions(enabled)
}

func raceSetting(enabled bool) *bool { return &enabled }

func binaryRace(path string) (bool, error) {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return false, errors.New("executable race setting unavailable")
	}
	seen := false
	for _, setting := range info.Settings {
		if setting.Key != "-race" {
			continue
		}
		if seen || setting.Value != "true" {
			return false, errors.New("executable race setting invalid")
		}
		seen = true
	}
	return seen, nil
}

func parseRaceArguments(args []string) ([]string, bool, error) {
	cleaned := make([]string, 0, len(args))
	enabled := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			cleaned = append(cleaned, args[i:]...)
			break
		}
		if arg == "--race" {
			if enabled {
				return nil, false, errors.New("duplicate race option")
			}
			enabled = true
			continue
		}
		if strings.HasPrefix(arg, "--race=") || arg == "--no-race" {
			return nil, false, errors.New("race option only enables detection")
		}
		cleaned = append(cleaned, arg)
		switch arg {
		case "--workflow", "--step", "--test", "--package", "--scenario", "--telemetry-config", "--log-level", "--suite", "--environment", "--recovery-mode", "--limits", "--parallel", "--memory-limit-mib":
			if i+1 < len(args) {
				i++
				cleaned = append(cleaned, args[i])
			}
		}
	}
	return cleaned, enabled, nil
}

func resolveInvocationRace(root string, args []string, enabled bool) (bool, error) {
	if len(args) == 0 {
		return false, errors.New(testCommandUsage)
	}
	return enabled, nil
}

package main

import (
	"strings"
	"testing"
)

// full_only: false
func TestPlanRunArgumentDiagnosticsAreBounded(t *testing.T) {
	for _, command := range []string{"plan", "run"} {
		for _, row := range []struct {
			name string
			args []string
			want string
		}{
			{"unknown flag", []string{"--private-argument-value"}, "unknown plan/run flag"},
			{"missing value", []string{"--workflow"}, "plan/run flag requires a value"},
			{"invalid value", []string{"--parallel=private-argument-value"}, "invalid plan/run flag value"},
			{"empty recovery mode", []string{"--workflow=dev.json", "--recovery-mode="}, "invalid plan/run flag value"},
			{"positional", []string{"--workflow=dev.json", "private-argument-value"}, "unexpected plan/run positional argument"},
			{"repeated step", []string{"--workflow=dev.json", "--step=runner", "--step=runner"}, "plan/run flag may be specified only once"},
			{"incompatible", []string{"--workflow=dev.json", "--suite=private-argument-value"}, "plan/run flags select incompatible input forms"},
			{"empty focus", []string{"--workflow=dev.json", "--step=runner", "--test="}, "--test requires one literal path and one selected step"},
		} {
			t.Run(command+"/"+row.name, func(t *testing.T) {
				_, err := parsePlanRunArguments(append([]string{command}, row.args...))
				if err == nil || err.Error() != row.want || strings.Contains(err.Error(), "private-argument-value") {
					t.Fatalf("argument refusal lacks a bounded reason: %v", err)
				}
			})
		}
	}
}

package main

import (
	"errors"
	"flag"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	records "enkv.sh/core/internal/testrecords"
)

const testCommandUsage = "usage: tests/scripts/test <plan|run|unit|runner-tests|list|cleanup|check|dev|fuzz|fmt|fmt-check|lint>"

type workflowRequest struct {
	Race            bool
	Execution       executionRequest
	Path            string
	SelectedStep    string
	Test            string
	Package         string
	Scenarios       []string
	RecoveryMode    string
	TelemetryConfig string
	LogLevel        string
}

type planRunArguments struct {
	command                            string
	workflowPresent                    bool
	request                            workflowRequest
	suites                             []string
	environment, recoveryMode, limits  string
	stepCount, testCount, packageCount int
	recoveryCount                      int
	present                            map[string]bool
}

func parsePlanRunArguments(args []string) (planRunArguments, error) {
	refused := errors.New("invalid plan/run arguments")
	if len(args) == 0 || args[0] != "plan" && args[0] != "run" {
		return planRunArguments{}, refused
	}
	args, race, err := parseRaceArguments(args)
	if err != nil {
		return planRunArguments{}, err
	}
	parsed := planRunArguments{command: args[0], present: map[string]bool{}}
	parsed.request.Race = race
	request := &parsed.request
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	registerExecutionFlags(flags, &request.Execution)
	flags.StringVar(&request.Path, "workflow", "", "")
	flags.Func("step", "", func(value string) error { parsed.stepCount++; request.SelectedStep = value; return nil })
	flags.Func("test", "", func(value string) error { parsed.testCount++; request.Test = value; return nil })
	flags.Func("package", "", func(value string) error { parsed.packageCount++; request.Package = value; return nil })
	flags.Func("scenario", "", func(value string) error { request.Scenarios = append(request.Scenarios, value); return nil })
	flags.StringVar(&request.TelemetryConfig, "telemetry-config", "", "")
	flags.StringVar(&request.LogLevel, "log-level", "", "")
	flags.Func("suite", "", func(value string) error { parsed.suites = append(parsed.suites, value); return nil })
	flags.StringVar(&parsed.environment, "environment", "", "")
	flags.Func("recovery-mode", "", func(value string) error { parsed.recoveryCount++; parsed.recoveryMode = value; return nil })
	flags.StringVar(&parsed.limits, "limits", "", "")
	if err := flags.Parse(args[1:]); err != nil {
		reason := "invalid plan/run flag value"
		switch {
		case strings.HasPrefix(err.Error(), "flag provided but not defined:"):
			reason = "unknown plan/run flag"
		case strings.HasPrefix(err.Error(), "flag needs an argument:"):
			reason = "plan/run flag requires a value"
		}
		return planRunArguments{}, errors.New(reason)
	}
	if flags.NArg() != 0 {
		return planRunArguments{}, errors.New("unexpected plan/run positional argument")
	}
	flags.Visit(func(value *flag.Flag) { parsed.present[value.Name] = true })
	parsed.workflowPresent = parsed.present["workflow"]
	if parsed.stepCount > 1 || parsed.testCount > 1 || parsed.packageCount > 1 || parsed.recoveryCount > 1 {
		return planRunArguments{}, errors.New("plan/run flag may be specified only once")
	}
	if parsed.recoveryCount != 0 && parsed.recoveryMode == "" {
		return planRunArguments{}, errors.New("invalid plan/run flag value")
	}
	inapplicable := []string{"step", "test", "package", "scenario"}
	if parsed.workflowPresent {
		inapplicable = []string{"suite", "environment", "limits"}
		request.RecoveryMode = parsed.recoveryMode
	}
	for _, name := range inapplicable {
		if parsed.present[name] {
			return planRunArguments{}, errors.New("plan/run flags select incompatible input forms")
		}
	}
	if err := validatePlanRunConfiguration(parsed); err != nil {
		return planRunArguments{}, err
	}
	return parsed, nil
}

type cleanupRequest struct {
	RunID, Limits, Environment string
	race                       bool
	execution                  executionPolicy
}

func parseCleanupRequest(args []string) (cleanupRequest, error) {
	refused := errors.New("cleanup requires a run ID and new limits")
	if len(args) < 2 || args[0] != "cleanup" || !records.ValidRunID(args[1]) {
		return cleanupRequest{}, refused
	}
	args, race, err := parseRaceArguments(args)
	if err != nil {
		return cleanupRequest{}, err
	}
	request := cleanupRequest{RunID: args[1], race: race}
	flags := flag.NewFlagSet("cleanup", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	override := executionRequest{}
	registerExecutionFlags(flags, &override)
	flags.StringVar(&request.Limits, "limits", "", "")
	flags.StringVar(&request.Environment, "environment", "", "")
	if flags.Parse(args[2:]) != nil || flags.NArg() != 0 || request.Limits == "" {
		return cleanupRequest{}, refused
	}
	policy, err := resolveExecution(executionRequest{}, override)
	if err != nil {
		return cleanupRequest{}, err
	}
	request.execution = policy
	emptyEnvironment := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "environment" && request.Environment == "" {
			emptyEnvironment = true
		}
	})
	if emptyEnvironment {
		return cleanupRequest{}, refused
	}
	return request, nil
}

func validOrdinaryFocusName(name string) bool {
	if len(name) > maximumToolOutputBytes || !validOrdinaryName(name) {
		return false
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == "" {
			return false
		}
	}
	return true
}

func validOrdinaryPackagePath(path string) bool {
	if path == "" || filepath.IsAbs(path) || filepath.Clean(path) != path || strings.Contains(path, "..") || strings.ContainsAny(path, "\\\t\r\n :@*?") || strings.HasPrefix(path, "-") || strings.HasPrefix(path, "./") || strings.HasSuffix(path, "/...") {
		return false
	}
	for _, module := range moduleRoots {
		if path == module || strings.HasPrefix(path, module+"/") {
			return true
		}
	}
	return false
}

func validOrdinaryName(name string) bool {
	if len(name) == 0 || strings.ContainsAny(name, "\r\n\t ") {
		return false
	}
	top, _, _ := strings.Cut(name, "/")
	return strings.HasPrefix(top, "Test") && len(top) > 4 ||
		strings.HasPrefix(top, "Example") ||
		strings.HasPrefix(top, "Fuzz") && len(top) > 4
}

var telemetryLabel = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,95}$`)

var componentName = regexp.MustCompile(`^Test[A-Za-z0-9_]+(?:/[A-Za-z0-9_.#+=\[\]-]+)*$`)

func validComponentName(name string) bool {
	return len(name) <= 255 && componentName.MatchString(name)
}

func validAssemblyResponsibility(value string) bool {
	return value == "common" || value == "gcp" || value == "aws"
}

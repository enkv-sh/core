package main

import (
	"errors"
	"math"
	"slices"

	"enkv.sh/compositions/observability"
	catalog "enkv.sh/core/internal/testcatalog"
)

type runRequest struct {
	execution               executionPolicy
	Suite, Provider, Target string
	Profile                 string
	Limits                  string
	Allowance               *limits
	telemetrySettings       *observability.Resolved
	effectiveTelemetry      *effectiveTelemetry
	Schedule                catalog.Schedule
	Resolved                *resolvedRequest
	environment             *environmentFile
	components              *componentRun
	workflowRunID           string
}

type effectiveTelemetry struct {
	ConfigurationSource string                  `json:"configuration_source"`
	LevelOverrideSource string                  `json:"level_override_source"`
	LogLevel            *observability.Severity `json:"log_level"`
	TraceSampleRatio    *float64                `json:"trace_sample_ratio"`
	Logs                []string                `json:"logs"`
	Metrics             []string                `json:"metrics"`
	Traces              []string                `json:"traces"`
}

func summarizeTelemetry(settings observability.Resolved, options observability.Options) *effectiveTelemetry {
	level, ratio := settings.LogLevel, settings.TraceSampleRatio
	value := &effectiveTelemetry{
		ConfigurationSource: "none", LevelOverrideSource: "none",
		LogLevel: &level, TraceSampleRatio: &ratio,
		Logs:    []string{},
		Metrics: telemetryDestinations(settings, settings.MetricExporters, false),
		Traces:  telemetryDestinations(settings, settings.TraceExporters, false),
	}
	if options.LogLevel == "" && options.EnvLogLevel != "" {
		value.LevelOverrideSource = "environment"
	}
	if settings.LogLevel != observability.Off {
		value.Logs = telemetryDestinations(settings, settings.LogExporters, settings.Console)
	}
	return value
}

func telemetryDestinations(settings observability.Resolved, exporters []string, console bool) []string {
	file, http := false, false
	for _, name := range exporters {
		switch settings.ActiveExporters[name].Type {
		case "otlp_file":
			file = true
		case "otlp_http":
			http = true
		}
	}
	destinations := []string{}
	if console {
		destinations = append(destinations, "console")
	}
	if file {
		destinations = append(destinations, "file")
	}
	if http {
		destinations = append(destinations, "http")
	}
	return destinations
}

func (value *effectiveTelemetry) clone() *effectiveTelemetry {
	if value == nil {
		return nil
	}
	copy := *value
	if value.LogLevel != nil {
		level := *value.LogLevel
		copy.LogLevel = &level
	}
	if value.TraceSampleRatio != nil {
		ratio := *value.TraceSampleRatio
		copy.TraceSampleRatio = &ratio
	}
	copy.Logs, copy.Metrics, copy.Traces = slices.Clone(value.Logs), slices.Clone(value.Metrics), slices.Clone(value.Traces)
	return &copy
}

func parseRunRequest(args []string) (runRequest, error) {
	if len(args) == 0 || args[0] != "plan" && args[0] != "run" {
		return runRequest{}, errors.New("expected plan or run with --suite and --environment")
	}
	return parseSavedRequest(args)
}

func validTelemetryDisplay(value *effectiveTelemetry) bool {
	if value == nil || value.LogLevel == nil || value.TraceSampleRatio == nil || !slices.Contains([]string{"none", "workflow", "command"}, value.ConfigurationSource) || !slices.Contains([]string{"none", "environment", "workflow", "command"}, value.LevelOverrideSource) ||
		!slices.Contains([]observability.Severity{observability.Trace, observability.Debug, observability.Info, observability.Warn, observability.Error, observability.Fatal, observability.Off}, *value.LogLevel) || math.IsNaN(*value.TraceSampleRatio) || math.IsInf(*value.TraceSampleRatio, 0) || *value.TraceSampleRatio < 0 || *value.TraceSampleRatio > 1 {
		return false
	}
	return validTelemetryDestinations(value.Logs, true) && validTelemetryDestinations(value.Metrics, false) && validTelemetryDestinations(value.Traces, false) && (*value.LogLevel != observability.Off || len(value.Logs) == 0)
}

func validTelemetryDestinations(destinations []string, console bool) bool {
	maximum := 2
	if console {
		maximum = 3
	}
	if destinations == nil || len(destinations) > maximum {
		return false
	}
	seen := map[string]bool{}
	for _, name := range destinations {
		if seen[name] || name != "file" && name != "http" && !(console && name == "console") {
			return false
		}
		seen[name] = true
	}
	return true
}

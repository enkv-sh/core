package main

type workflowFile struct {
	Execution     executionRequest `json:"execution,omitempty"`
	Profile       string           `json:"profile,omitempty"`
	SchemaVersion int              `json:"schema_version"`
	Name          string           `json:"name"`
	Description   string           `json:"description,omitempty"`
	Steps         []workflowStep   `json:"steps"`
}

type workflowStep struct {
	ParallelGroup       string            `json:"parallel_group,omitempty"`
	Responsibility      string            `json:"responsibility,omitempty"`
	ID                  string            `json:"id"`
	Kind                string            `json:"kind"`
	Tests               []string          `json:"tests,omitempty"`
	Package             string            `json:"package,omitempty"`
	Profile             string            `json:"profile,omitempty"`
	Packages            []string          `json:"packages,omitempty"`
	Targets             []string          `json:"targets,omitempty"`
	Suites              []string          `json:"suites,omitempty"`
	Scenarios           []string          `json:"scenarios,omitempty"`
	Environment         string            `json:"environment,omitempty"`
	AdditionalProviders map[string]string `json:"additional_providers,omitempty"`
	RecoveryMode        string            `json:"recovery_mode,omitempty"`
	Limits              string            `json:"limits,omitempty"`
	SmokePolicy         string            `json:"smoke_policy,omitempty"`
	Repetitions         *int              `json:"repetitions,omitempty"`
	TelemetryConfig     string            `json:"telemetry_config,omitempty"`
	LogLevel            string            `json:"log_level,omitempty"`
}

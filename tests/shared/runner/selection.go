package main

import (
	"errors"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"enkv.sh/compositions/observability"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

type suiteFile struct {
	SchemaVersion int      `json:"schema_version"`
	Name          string   `json:"name"`
	Description   string   `json:"description,omitempty"`
	RequiredRoles []string `json:"required_roles"`
	Scenarios     []string `json:"scenarios"`
}

type accessReference struct {
	SDK               *nativeprocess.StandardContext `json:"sdk_context,omitempty"`
	CredentialsFile   string                         `json:"credentials_file,omitempty"`
	Profile           string                         `json:"profile,omitempty"`
	CredentialExpires string                         `json:"credential_expires,omitempty"`
}

type participantReference struct {
	Access accessReference `json:"access,omitempty"`
}

type environmentResource struct {
	Alias    string       `json:"alias"`
	Settings liveSettings `json:"settings,omitempty"`
}

// Generator inputs are an orthogonal capability. They do not select the
// Store/Trust provider and are retained only in private worker state.
type generatorReference struct {
	Account         string `json:"account"`
	PermissionGroup string `json:"permission_group"`
	CredentialsFile string `json:"credentials_file"`
	Artifact        string `json:"artifact"`
}

// Output targets are separate test fixture coordinates. They do not become
// Store actors or Product authority when a state suite is selected.
type outputActorReference struct {
	Principal       string `json:"principal,omitempty"`
	CredentialsFile string `json:"credentials_file"`
	Profile         string `json:"profile,omitempty"`
	ServiceAccount  string `json:"service_account,omitempty"`
}

type outputTargetReference struct {
	Region           string                          `json:"region,omitempty"`
	Account          string                          `json:"account,omitempty"`
	Project          string                          `json:"project,omitempty"`
	ProjectNumber    string                          `json:"project_number,omitempty"`
	SecretNamePrefix string                          `json:"secret_name_prefix"`
	VersionStage     string                          `json:"version_stage,omitempty"`
	Version          string                          `json:"version,omitempty"`
	Writer           outputActorReference            `json:"writer"`
	Cleaner          outputActorReference            `json:"cleaner"`
	Consumers        map[string]outputActorReference `json:"consumers"`
}

type resolvedGenerator struct {
	Provider           string `json:"provider"`
	AccountContract    string `json:"account_contract"`
	CredentialContract string `json:"credential_contract"`
	ArtifactContract   string `json:"artifact_contract"`
}

type environmentFile struct {
	PluginAcceptance    *records.StockPluginFixture      `json:"plugin_acceptance,omitempty"`
	PublicOutputs       *records.PublicOutputScopes      `json:"public_outputs,omitempty"`
	PublicConfiguration bool                             `json:"public_configuration,omitempty"`
	SchemaVersion       int                              `json:"schema_version"`
	Name                string                           `json:"name"`
	Mode                string                           `json:"mode"`
	Provider            string                           `json:"provider"`
	Resource            environmentResource              `json:"resource"`
	Generator           *generatorReference              `json:"generator,omitempty"`
	OutputTargets       map[string]outputTargetReference `json:"output_targets,omitempty"`
	GitHubOutputTargets *githubOutputReference           `json:"github_output_targets,omitempty"`
	Participants        map[string]participantReference  `json:"participants"`
	RoleBindings        map[string]string                `json:"role_bindings"`
}

// Resolved records keep labels and fixed catalog metadata, never input paths.
type resolvedRequest struct {
	raceMissing  bool
	Profile      string                `json:"profile"`
	Race         bool                  `json:"scenario_race"`
	Suite        string                `json:"suite"`
	Suites       []string              `json:"suites,omitempty"`
	Preparation  []string              `json:"preparation,omitempty"`
	Environment  string                `json:"environment"`
	Mode         string                `json:"mode"`
	Provider     string                `json:"provider"`
	RecoveryMode string                `json:"recovery_mode"`
	Resource     string                `json:"resource"`
	Generator    *resolvedGenerator    `json:"generator,omitempty"`
	Outputs      []resolvedOutputScope `json:"outputs,omitempty"`
	Participants []string              `json:"participants"`
	RoleBindings map[string]string     `json:"role_bindings"`
	Schedule     catalog.Schedule      `json:"schedule"`
	Entries      []resolvedScenario    `json:"entries"`
}

type resolvedScenario struct {
	catalog.Entry
	Title    string         `json:"title"`
	Resource string         `json:"resource"`
	Fixture  catalog.Shape  `json:"fixture"`
	Steps    []catalog.Step `json:"steps"`
}

func parseSavedRequest(args []string) (runRequest, error) {
	parsed, err := parsePlanRunArguments(args)
	if err != nil {
		return runRequest{}, err
	}
	return savedRequestFromArguments(parsed)
}

func savedRequestFromArguments(parsed planRunArguments) (runRequest, error) {
	refused := errors.New("invalid suite, environment or required run input")
	if parsed.workflowPresent || len(parsed.suites) == 0 || parsed.environment == "" {
		return runRequest{}, refused
	}
	policy, err := resolveExecution(executionRequest{}, parsed.request.Execution)
	if err != nil {
		return runRequest{}, err
	}
	request, err := resolveSavedRun(parsed.suites, parsed.environment, "", parsed.limits, parsed.recoveryMode, parsed.request.TelemetryConfig, parsed.request.LogLevel, "", 1, parsed.command == "run")
	if err != nil {
		return request, err
	}
	request.execution = policy
	request.Resolved.Race = parsed.request.Race
	if parsed.request.TelemetryConfig != "" {
		request.effectiveTelemetry.ConfigurationSource = "command"
	}
	if parsed.request.LogLevel != "" {
		request.effectiveTelemetry.LevelOverrideSource = "command"
	}
	return request, nil
}

type scenarioSelection struct {
	Saved []string
	Focus []string
}

func validScenarioSelector(selector string) bool {
	for _, name := range catalog.Names() {
		group, _, _ := strings.Cut(name, "/")
		if selector == name || selector == group {
			return true
		}
	}
	return false
}

// Saved leaves first bound the step. CLI groups expand only inside that bound.
// Both filters preserve suite order, independently of CLI argument order.
func selectScenarioNames(available []string, selection scenarioSelection) ([]string, error) {
	selected := slices.Clone(available)
	if selection.Saved != nil {
		if len(selection.Saved) == 0 {
			return nil, errors.New("saved scenario selection is empty")
		}
		chosen := make(map[string]bool)
		for _, name := range selection.Saved {
			if chosen[name] || !slices.Contains(selected, name) {
				return nil, errors.New("explicit scenario selection differs from selected suites")
			}
			chosen[name] = true
		}
		selected = slices.DeleteFunc(selected, func(name string) bool { return !chosen[name] })
	}
	if selection.Focus != nil {
		chosen := make(map[string]bool)
		for _, selector := range selection.Focus {
			if !validScenarioSelector(selector) {
				return nil, errors.New("scenario selector is not a literal known case or group")
			}
			matched := false
			for _, name := range selected {
				group, _, _ := strings.Cut(name, "/")
				if name != selector && group != selector {
					continue
				}
				if chosen[name] {
					return nil, errors.New("scenario selectors duplicate or overlap")
				}
				chosen[name], matched = true, true
			}
			if !matched {
				return nil, errors.New("scenario selector has no cases in the selected step")
			}
		}
		selected = slices.DeleteFunc(selected, func(name string) bool { return !chosen[name] })
	}
	if len(selected) == 0 {
		return nil, errors.New("scenario selection is empty")
	}
	return selected, nil
}

func resolveSavedRun(suitePaths []string, environmentPath, generatorPath, limitsPath, recoveryMode, configuration, logLevel string, smokePolicy catalog.SmokePolicy, repetitions int, executing bool, focus ...scenarioSelection) (runRequest, error) {
	policy := defaultExecutionPolicy()
	request := runRequest{Limits: limitsPath, execution: policy}
	refused := errors.New("invalid suite, environment or required run input")
	options := observability.EnvironmentOptions(logLevel)
	settings, err := observability.Load(configuration, options)
	if err != nil {
		return request, err
	}
	request.telemetrySettings = &settings
	request.effectiveTelemetry = summarizeTelemetry(settings, options)
	var names, selected []string
	for _, path := range suitePaths {
		var suite suiteFile
		if readSelectionFile(path, &suite) != nil || suite.SchemaVersion != 2 || !telemetryLabel.MatchString(suite.Name) || len(suite.Scenarios) == 0 || slices.Contains(names, suite.Name) {
			return request, refused
		}
		names = append(names, suite.Name)
		for _, name := range suite.Scenarios {
			if _, known := catalog.Name(name); !known {
				return request, errors.New("suite requires individual scenario IDs")
			}
			if slices.Contains(selected, name) {
				return request, errors.New("selected suites contain duplicate scenarios")
			}
			selected = append(selected, name)
		}
		if !slices.Equal(suite.RequiredRoles, catalog.RolesForScenarios(suite.Scenarios, "both")) {
			return request, errors.New("suite required roles differ from its scenarios")
		}
	}
	if len(focus) > 1 {
		return request, refused
	}
	if len(focus) == 1 {
		selected, err = selectScenarioNames(selected, focus[0])
		if err != nil {
			return request, err
		}
	}
	if len(selected) == 0 {
		return request, refused
	}
	var environment environmentFile
	if readSelectionFile(environmentPath, &environment) != nil {
		return request, refused
	}
	if environment.SchemaVersion != 1 {
		return request, refused
	}
	if generatorPath != "" && environment.Mode != "live" {
		return request, errors.New("additional provider requires a live environment")
	}
	directory, err := filepath.Abs(filepath.Dir(environmentPath))
	if err != nil {
		return request, refused
	}
	if generatorPath != "" {
		if environment.Generator != nil {
			return request, errors.New("duplicate Cloudflare generator configuration refused")
		}
		var generator generatorReference
		var err error
		if environment.PluginAcceptance != nil {
			generator, err = loadStockGeneratorConfiguration(generatorPath)
		} else {
			generator, err = loadGeneratorConfiguration(generatorPath, environment.PublicConfiguration)
		}
		if err != nil {
			return request, err
		}
		environment.Generator = &generator
	}
	if err := validateEnvironment(&environment, directory); err != nil {
		return request, err
	}
	if err := selectRecoveryMode(&environment, recoveryMode); err != nil {
		return request, err
	}
	if err := validateEnvironment(&environment, directory); err != nil {
		return request, err
	}
	request.Suite, request.Provider, request.Target = environment.Mode, environment.Provider, environment.Resource.Alias
	request.environment = &environment
	if err := resolveSelection(&request, catalog.Request{RecoveryMode: recoveryMode, Include: selected, SmokePolicy: smokePolicy, Repetitions: repetitions}, names[0], environment); err != nil {
		return runRequest{}, err
	}
	if len(focus) == 1 && focus[0].Focus != nil && len(request.Schedule.NotApplicable) != 0 {
		return runRequest{}, errors.New("explicitly selected scenario does not support the requested recovery mode")
	}
	request.Resolved.Suites = names
	if err := setVerificationProfile(&request, "full"); err != nil {
		return runRequest{}, err
	}
	if request.Suite == "hermetic" && request.Limits != "" {
		return runRequest{}, refused
	}
	if executing && request.Suite == "live" && request.Limits == "" {
		return runRequest{}, refused
	}
	return request, nil
}

// A run selects its domain configuration from the environment's available
// resources. Keep the supplied environment intact so another step can select
// the other mode from the same file.
func selectRecoveryMode(environment *environmentFile, mode string) error {
	if mode == "" {
		return nil // Standalone commands retain their environment default.
	}
	if environment.Mode == "hermetic" {
		if mode != "both" && mode != "disabled" && mode != "enabled" {
			return errors.New("hermetic recovery mode requires both, disabled or enabled")
		}
		return nil
	}
	if mode != "enabled" && mode != "disabled" {
		return errors.New("live runs require recovery_mode enabled or disabled")
	}
	environment.Resource.Settings = maps.Clone(environment.Resource.Settings)
	environment.RoleBindings = maps.Clone(environment.RoleBindings)
	environment.Resource.Settings["recovery_mode"] = mode
	if mode == "disabled" {
		for _, field := range publicResourceFields {
			if field != "recovery_mode" && strings.HasPrefix(field, "recovery_") {
				delete(environment.Resource.Settings, field)
			}
		}
		delete(environment.RoleBindings, "recovery")
		for role, recovery := range replacementRoles {
			if recovery {
				delete(environment.RoleBindings, role)
			}
		}
	}
	return nil
}

func validateEnvironment(environment *environmentFile, directory string) error {
	refused := errors.New("environment resources, participants or execution mode refused")
	if !telemetryLabel.MatchString(environment.Name) || !telemetryLabel.MatchString(environment.Resource.Alias) || environment.Mode != "hermetic" && environment.Mode != "live" {
		return refused
	}
	if environment.Mode == "hermetic" && environment.Provider != "memory" || environment.Mode == "live" && environment.Provider != "gcp" && environment.Provider != "aws" {
		return refused
	}
	if environment.Mode == "hermetic" && len(environment.Resource.Settings) != 0 {
		return refused
	}
	if environment.Mode == "hermetic" && environment.Generator != nil {
		return errors.New("hermetic generator inputs refused")
	}
	if environment.PublicConfiguration {
		if environment.Generator != nil && environment.PluginAcceptance == nil {
			generator, err := validateGeneratorFields(*environment.Generator, directory)
			if err != nil {
				return err
			}
			environment.Generator = &generator
		}
		return validatePublicConfigurationEnvironment(environment)
	}
	if environment.PublicOutputs != nil {
		return errors.New("public output scopes require a public configuration environment")
	}
	if err := validateOutputConfiguration(environment, directory); err != nil {
		return err
	}
	if environment.Mode == "live" {
		if environment.Generator != nil {
			generator, err := validateGeneratorFields(*environment.Generator, directory)
			if err != nil {
				return err
			}
			environment.Generator = &generator
		}
		_, recoveryBound := environment.RoleBindings["recovery"]
		_, recoveryPresent := environment.Participants[environment.RoleBindings["recovery"]]
		switch environment.Resource.Settings["recovery_mode"] {
		case "enabled":
			if !recoveryBound || !recoveryPresent {
				return errors.New("enabled recovery requires its participant")
			}
		case "disabled":
			if recoveryBound {
				return errors.New("disabled recovery must not bind a recovery participant")
			}
		default:
			return errors.New("explicit enabled or disabled recovery mode required")
		}
		bundle := hasReplacementSettings(environment.Resource.Settings)
		for role, recovery := range replacementRoles {
			name, bound := environment.RoleBindings[role]
			if role == "normal-signer-2" && environment.Resource.Settings["normal_successor_2_key_id"] == "" {
				if bound {
					return refused
				}
				continue
			}
			if recovery && environment.Resource.Settings["recovery_mode"] == "disabled" {
				if bound {
					return errors.New("disabled recovery must not bind a replacement recovery participant")
				}
				continue
			}
			if !bundle && !bound {
				continue
			}
			participant, present := environment.Participants[name]
			if !bundle || !bound || !present || participant.Access.CredentialsFile == "" || environment.Provider == "aws" && participant.Access.Profile == "" {
				return errors.New("replacement requires its complete public bundle and participant routes")
			}
		}
	}
	for name, participant := range environment.Participants {
		if !telemetryLabel.MatchString(name) {
			return refused
		}
		access := participant.Access
		if access.CredentialsFile != "" && !filepath.IsAbs(access.CredentialsFile) {
			access.CredentialsFile = filepath.Join(directory, access.CredentialsFile)
		}
		participant.Access = access
		environment.Participants[name] = participant
	}
	for role, name := range environment.RoleBindings {
		if !telemetryLabel.MatchString(role) || !telemetryLabel.MatchString(name) {
			return refused
		}
	}
	return nil
}

func (environment environmentFile) settingsFor(name string) (liveSettings, error) {
	participant, present := environment.Participants[name]
	actor := participant.Access
	if !present {
		return nil, errors.New("required participant missing")
	}
	settings := make(liveSettings, len(environment.Resource.Settings)+4)
	for key, value := range environment.Resource.Settings {
		if key == "provider" || key == "credentials_file" || key == "profile" || key == "credential_expires" {
			return nil, errors.New("resource settings must not contain actor credentials or provider")
		}
		settings[key] = value
	}
	settings["provider"], settings["credentials_file"] = environment.Provider, actor.CredentialsFile
	if actor.Profile != "" {
		settings["profile"] = actor.Profile
	}
	if actor.CredentialExpires != "" {
		settings["credential_expires"] = actor.CredentialExpires
	}
	return settings, nil
}

func resolveSelection(request *runRequest, selection catalog.Request, suite string, environment environmentFile) error {
	if request.Suite == "live" {
		generated := false
		for _, name := range selection.Include {
			execution, known := catalog.ExecutionFor(name, "live")
			generated = generated || name == records.StockPluginScenario || known && execution.HasFixtureCapability(catalog.FixtureGeneratedProcess)
		}
		if generated != (environment.Generator != nil) {
			return errors.New("live generated selection requires its exact Cloudflare inputs")
		}
	}
	if selection.RecoveryMode == "" {
		selection.RecoveryMode = "both"
	}
	if request.Suite == "live" {
		selection.RecoveryMode = environment.Resource.Settings["recovery_mode"]
	}
	schedule, err := catalog.Resolve(selection)
	if err != nil {
		return err
	}
	if scheduleNeedsStockPlugins(schedule) && (len(schedule.Entries) != 1 || schedule.Entries[0].Scenario != records.StockPluginScenario) {
		return errors.New("a single-use stock fixture admits exactly one case")
	}
	if scheduleNeedsStockPlugins(schedule) != (environment.PluginAcceptance != nil) {
		return errors.New("stock acceptance requires its dedicated fixture environment")
	}
	if scheduleNeedsPublicConfiguration(schedule) != environment.PublicConfiguration {
		return errors.New("public configuration requires its isolated standard-context environment")
	}
	resolved := &resolvedRequest{Suite: suite, Environment: environment.Name, Mode: request.Suite, Provider: request.Provider, Resource: environment.Resource.Alias, Schedule: schedule, RoleBindings: map[string]string{}}
	outputs, err := selectPublicationOutputs(schedule, environment)
	if err != nil {
		return err
	}
	for _, output := range outputs {
		resolved.Outputs = append(resolved.Outputs, output.resolvedOutputScope)
	}
	if environment.Generator != nil {
		credentialContract := "environment:CLOUDFLARE_API_TOKEN"
		resolved.Generator = &resolvedGenerator{Provider: "cloudflare", AccountContract: "cloudflare-account-id", CredentialContract: credentialContract, ArtifactContract: "installed-executable"}
	}
	resolved.RecoveryMode = schedule.RecoveryMode
	used := map[string]bool{}
	for _, entry := range schedule.Entries {
		definition, known := catalog.DefinitionFor(entry.Scenario)
		if !known || !slices.Contains(definition.Modes, request.Suite) || !slices.Contains(definition.Providers, request.Provider) {
			return errors.New("scenario execution mode refused")
		}
		roles := definition.RolesForRecovery(resolved.RecoveryMode)
		if len(roles) == 0 {
			return errors.New("scenario recovery mode refused")
		}
		if _, valid := catalog.ExecutionForRecovery(entry.Scenario, request.Suite, resolved.RecoveryMode); !valid {
			return errors.New("scenario has no declared execution for the requested recovery mode")
		}
		row, public := catalog.PublicConfiguration(entry.Scenario)
		usesOperatorSDKContext := public && row.UsesOperatorSDKContext()
		firstFlow := !usesOperatorSDKContext && (slices.Contains(roles, "reader") || slices.Contains(roles, "denied-reader"))
		for _, role := range roles {
			if _, replacement := replacementRoles[role]; replacement {
				firstFlow = true
			}
		}
		scenarioParticipants := map[string]bool{}
		for _, role := range roles {
			name, bound := environment.RoleBindings[role]
			participant, present := environment.Participants[name]
			if !bound || !present {
				return errors.New("required scenario participant missing")
			}
			if usesOperatorSDKContext && (name != environment.RoleBindings["authority"] || participant.Access.SDK == nil || !participant.Access.SDK.OperatorDiscovery(environment.Provider)) {
				return errors.New("operator SDK context requires one selected credential context")
			}
			if (firstFlow || role == "recovery" || definition.DistinctParticipants) && scenarioParticipants[name] {
				return errors.New("scenario requires distinct participants")
			}
			scenarioParticipants[name] = true
			if public && row.Condition == "standard-discovery" &&
				(participant.Access.SDK == nil || !participant.Access.SDK.StandardDiscovery(environment.Provider)) {
				return errors.New("standard discovery requires AWS SSO or direct user ADC")
			}
			if !used[name] {
				if environment.Mode == "hermetic" {
					if participant.Access != (accessReference{}) {
						return errors.New("hermetic participant access refused")
					}
				} else {
					if environment.PublicConfiguration {
						if _, err := environment.publicConfigurationSettings(name); err != nil {
							return err
						}
					} else {
						settings, err := environment.settingsFor(name)
						if err != nil {
							return err
						}
						if _, err := validateSettingsFields(settings, environment.Provider, ""); err != nil {
							return err
						}
					}
				}
			}
			used[name] = true
			resolved.RoleBindings[role] = name
		}
		shape, err := recordedFixture(entry.Scenario, entry.Members)
		if err != nil {
			return err
		}
		steps := append([]catalog.Step(nil), definition.Steps...)
		resolved.Entries = append(resolved.Entries, resolvedScenario{Entry: entry, Title: definition.Title, Resource: environment.Resource.Alias, Fixture: shape, Steps: steps})
	}
	for name := range used {
		resolved.Participants = append(resolved.Participants, name)
	}
	slices.Sort(resolved.Participants)
	request.Schedule, request.Resolved = schedule, resolved
	return nil
}

func (r *resolvedRequest) scenarioParticipants(name string) (map[string]string, error) {
	if r == nil || r.Mode == "hermetic" && r.RecoveryMode != "both" && r.RecoveryMode != "enabled" && r.RecoveryMode != "disabled" || r.Mode == "live" && r.RecoveryMode != "enabled" && r.RecoveryMode != "disabled" || r.Mode != "live" && r.Mode != "hermetic" {
		return nil, errors.New("resolved recovery mode refused")
	}
	definition, known := recordedDefinition(name)
	if !known {
		return nil, errors.New("scenario actor definition unavailable")
	}
	roles := definition.RolesForRecovery(r.RecoveryMode)
	participants := make(map[string]string, len(roles))
	row, public := catalog.PublicConfiguration(name)
	usesOperatorSDKContext := public && row.UsesOperatorSDKContext()
	firstFlow := !usesOperatorSDKContext && (slices.Contains(roles, "reader") || slices.Contains(roles, "denied-reader"))
	for _, role := range roles {
		if _, replacement := replacementRoles[role]; replacement {
			firstFlow = true
		}
	}
	seen := map[string]bool{}
	for _, role := range roles {
		participant := r.RoleBindings[role]
		if !telemetryLabel.MatchString(participant) || usesOperatorSDKContext && participant != r.RoleBindings["authority"] || (firstFlow || role == "recovery" || definition.DistinctParticipants) && seen[participant] {
			return nil, errors.New("resolved scenario participants refused")
		}
		seen[participant] = true
		participants[role] = participant
	}
	return participants, nil
}

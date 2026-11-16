package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
)

type workflowPreview struct {
	Kind       string                `json:"kind"`
	Name       string                `json:"name,omitempty"`
	Profile    string                `json:"profile,omitempty"`
	Race       bool                  `json:"race"`
	Execution  executionPolicy       `json:"execution"`
	Steps      []workflowPreviewStep `json:"steps"`
	Unresolved []string              `json:"unresolved"`
}

type workflowPreviewStep struct {
	workflowStep
	Selected            bool    `json:"selected"`
	LimitsConfiguration *limits `json:"limits_configuration,omitempty"`
}

func previewWorkflow(args []string, output io.Writer) error {
	parsed, err := parsePlanRunArguments(args)
	if err != nil {
		return err
	}
	preview := workflowPreview{Kind: "selection_preview", Race: parsed.request.Race,
		Unresolved: []string{"compiled test and subtest existence", "compiled coverage and resource classification", "required helper execution", "scenario and environment compatibility"}}
	if parsed.workflowPresent {
		file, policy, err := readWorkflowConfiguration(parsed.request)
		if err != nil {
			return err
		}
		preview.Name, preview.Profile, preview.Execution = file.Name, file.Profile, policy
		for _, step := range file.Steps {
			selected := parsed.request.SelectedStep == "" || step.ID == parsed.request.SelectedStep
			if selected {
				step, err = requestedWorkflowStep(step, parsed.request)
				if err != nil {
					return err
				}
			}
			item := workflowPreviewStep{workflowStep: step, Selected: selected}
			if selected && step.Limits != "" {
				path := step.Limits
				if !filepath.IsAbs(path) {
					path = filepath.Join(filepath.Dir(parsed.request.Path), path)
				}
				value, err := loadLimits(path)
				if err != nil {
					return fmt.Errorf("step %s: %w", step.ID, err)
				}
				item.LimitsConfiguration = &value
			}
			preview.Steps = append(preview.Steps, item)
		}
	} else {
		if len(parsed.suites) == 0 || parsed.environment == "" {
			return errors.New("preview requires a workflow or suites and an environment")
		}
		policy, err := resolveExecution(executionRequest{}, parsed.request.Execution)
		if err != nil {
			return err
		}
		preview.Execution, preview.Profile = policy, "full"
		step := workflowStep{ID: "scenarios", Kind: "run", Suites: slices.Clone(parsed.suites), Environment: parsed.environment,
			RecoveryMode: parsed.recoveryMode, Limits: parsed.limits, TelemetryConfig: parsed.request.TelemetryConfig, LogLevel: parsed.request.LogLevel}
		if step.RecoveryMode == "" {
			step.RecoveryMode = "both"
		}
		if err := validateWorkflowStepConfiguration(step); err != nil {
			return err
		}
		item := workflowPreviewStep{workflowStep: step, Selected: true}
		if step.Limits != "" {
			value, err := loadLimits(step.Limits)
			if err != nil {
				return err
			}
			item.LimitsConfiguration = &value
		}
		preview.Steps = []workflowPreviewStep{item}
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(preview)
}

func readWorkflowConfiguration(request workflowRequest) (workflowFile, executionPolicy, error) {
	if request.Path == "" {
		return workflowFile{}, executionPolicy{}, errors.New("workflow path required")
	}
	var file workflowFile
	if err := readSelectionFile(request.Path, &file); err != nil {
		return file, executionPolicy{}, err
	}
	if file.SchemaVersion != 1 || !telemetryLabel.MatchString(file.Name) || len(file.Steps) == 0 {
		return file, executionPolicy{}, errors.New("workflow requires a name and ordered steps")
	}
	policy, err := resolveExecution(file.Execution, request.Execution)
	if err != nil {
		return file, policy, err
	}
	file.Profile, err = resolveVerificationProfile(file.Profile)
	if err != nil {
		return file, policy, err
	}
	if (request.Test != "" || request.Package != "" || len(request.Scenarios) != 0 || request.RecoveryMode != "") && request.SelectedStep == "" {
		return file, policy, errors.New("focus requires one explicit workflow step")
	}
	if err := validateWorkflowParallelGroups(file.Steps, 2, nil); err != nil {
		return file, policy, err
	}
	seen := map[string]bool{}
	for _, step := range file.Steps {
		if !telemetryLabel.MatchString(step.ID) || seen[step.ID] {
			return file, policy, errors.New("workflow step IDs must be valid and unique")
		}
		seen[step.ID] = true
		if err := validateWorkflowStepConfiguration(step); err != nil {
			return file, policy, fmt.Errorf("step %s: %w", step.ID, err)
		}
		if request.SelectedStep == "" || request.SelectedStep == step.ID {
			if _, err := requestedWorkflowStep(step, request); err != nil {
				return file, policy, fmt.Errorf("step %s: %w", step.ID, err)
			}
			if step.Limits != "" {
				path := step.Limits
				if !filepath.IsAbs(path) {
					path = filepath.Join(filepath.Dir(request.Path), path)
				}
				if _, err := loadLimits(path); err != nil {
					return file, policy, fmt.Errorf("step %s: %w", step.ID, err)
				}
			}
		}
	}
	if request.SelectedStep != "" && !seen[request.SelectedStep] {
		return file, policy, errors.New("selected workflow step does not exist")
	}
	return file, policy, nil
}

func validateRequestedTests(tests []string) error {
	for index, name := range tests {
		if !validOrdinaryFocusName(name) {
			return errors.New("tests require literal Go test paths")
		}
		for _, prior := range tests[:index] {
			if prior == name || strings.HasPrefix(name, prior+"/") || strings.HasPrefix(prior, name+"/") {
				return errors.New("test selection has duplicate or overlapping paths")
			}
		}
	}
	return nil
}

func validateWorkflowStepConfiguration(step workflowStep) error {
	if step.Repetitions != nil {
		if step.Kind != "unit" && step.Kind != "runner-tests" && step.Kind != "component-tests" && step.Kind != "run" || *step.Repetitions < 1 || *step.Repetitions > 100 {
			return errors.New("repetitions require an executable test step and a value from 1 through 100")
		}
	}
	if step.Kind != "component-tests" && step.Profile != "" || step.Kind != "assembly-checks" && step.Responsibility != "" ||
		step.Kind != "unit" && step.Packages != nil || step.Kind != "fuzz" && step.Targets != nil ||
		step.Kind != "run" && (step.Scenarios != nil || step.Suites != nil || step.Environment != "" || step.AdditionalProviders != nil || step.RecoveryMode != "" || step.Limits != "" || step.SmokePolicy != "" || step.TelemetryConfig != "" || step.LogLevel != "") {
		return errors.New("workflow fields do not apply to their step kind")
	}
	if err := validateRequestedTests(step.Tests); err != nil {
		return err
	}
	if step.Package != "" && !validOrdinaryPackagePath(step.Package) {
		return errors.New("focus requires literal test and package paths")
	}
	switch step.Kind {
	case "unit":
		if _, err := resolveUnitPackages(step.Packages); err != nil {
			return err
		}
		if len(step.Tests) != 0 && step.Package == "" {
			return errors.New("unit test selection requires an exact package")
		}
	case "runner-tests":
		if step.Package != "" {
			return errors.New("runner tests resolve their artifact; package does not apply")
		}
	case "component-tests":
		if !allComponentRequests(step.Tests, nil) {
			return errors.New("component selection requires literal component test paths")
		}
		if step.Profile == "" || step.Package != "" {
			return errors.New("component tests require an explicit profile and no package override")
		}
		if _, err := resolveVerificationProfile(step.Profile); err != nil {
			return err
		}
	case "assembly-checks":
		if len(step.Tests) > 1 || !allComponentRequests(step.Tests, nil) {
			return errors.New("provider assembly selection requires one literal test path")
		}
		if step.Responsibility != "common" && step.Responsibility != "aws" && step.Responsibility != "gcp" || step.Package != "" || len(step.Tests) != 0 && step.Responsibility == "common" {
			return errors.New("assembly checks require a supported responsibility and no package override")
		}
	case "run":
		if len(step.Suites) == 0 || step.Environment == "" || step.RecoveryMode != "both" && step.RecoveryMode != "enabled" && step.RecoveryMode != "disabled" {
			return errors.New("run steps require suites, an environment and an explicit recovery mode")
		}
		if step.AdditionalProviders != nil && (len(step.AdditionalProviders) != 1 || step.AdditionalProviders["cloudflare"] == "") {
			return errors.New("unsupported additional provider configuration")
		}
		fallthrough
	case "lint", "fuzz":
		if len(step.Tests) != 0 || step.Package != "" {
			return errors.New("test and package focus do not apply to this step kind")
		}
	default:
		return errors.New("unknown workflow step kind")
	}
	return nil
}

func requestedWorkflowStep(step workflowStep, request workflowRequest) (workflowStep, error) {
	if request.Test != "" {
		within := len(step.Tests) == 0
		for _, configured := range step.Tests {
			within = within || request.Test == configured || strings.HasPrefix(request.Test, configured+"/")
		}
		if !within {
			return step, errors.New("requested test replaces or widens configured selection")
		}
		step.Tests = singleTestRequest(request.Test)
	}
	if request.Package != "" {
		if step.Package != "" && step.Package != request.Package {
			return step, errors.New("requested package replaces configured selection")
		}
		step.Package = request.Package
	}
	if len(request.Scenarios) != 0 || request.RecoveryMode != "" {
		if step.Kind != "run" || request.Test != "" || request.Package != "" {
			return step, errors.New("scenario and recovery focus require a run step")
		}
		if request.RecoveryMode != "" {
			if request.RecoveryMode != "both" && request.RecoveryMode != "enabled" && request.RecoveryMode != "disabled" || step.RecoveryMode != "both" && step.RecoveryMode != request.RecoveryMode {
				return step, errors.New("requested recovery mode widens or replaces configured selection")
			}
			step.RecoveryMode = request.RecoveryMode
		}
		step.Scenarios = slices.Clone(request.Scenarios)
	}
	if step.Kind == "run" && request.TelemetryConfig != "" {
		step.TelemetryConfig = request.TelemetryConfig
	}
	if step.Kind == "run" && request.LogLevel != "" {
		step.LogLevel = request.LogLevel
	}
	return step, validateWorkflowStepConfiguration(step)
}

func resolveVerificationProfile(profile string) (string, error) {
	if profile == "" {
		profile = "full"
	}
	if profile != "full" && profile != "dev" {
		return "", errors.New("verification profile must be full or dev")
	}
	return profile, nil
}

func resolveUnitPackages(packages []string) (map[string][]string, error) {
	selection := map[string][]string{}
	if packages == nil {
		for _, module := range moduleRoots {
			selection[module] = []string{"./..."}
		}
		return selection, nil
	}
	if len(packages) == 0 {
		return nil, errors.New("unit package selection must not be empty")
	}
	for _, path := range packages {
		path = strings.TrimPrefix(path, "./")
		base := strings.TrimSuffix(path, "/...")
		if base == "" || filepath.IsAbs(base) || filepath.Clean(base) != base || strings.Contains(base, "..") || strings.ContainsAny(base, "\\\t\r\n :@*") || strings.HasPrefix(base, "-") {
			return nil, errors.New("unit packages must name a registered module or package")
		}
		module := ""
		for _, candidate := range moduleRoots {
			if base == candidate || strings.HasPrefix(base, candidate+"/") {
				module = candidate
				break
			}
		}
		if module == "" {
			return nil, errors.New("unit package module refused")
		}
		pattern := "./..."
		if path != module && path != module+"/..." {
			pattern = "./" + strings.TrimPrefix(path, module+"/")
		}
		if slices.Contains(selection[module], pattern) {
			return nil, errors.New("duplicate unit package")
		}
		selection[module] = append(selection[module], pattern)
	}
	return selection, nil
}

func validateWorkflowParallelGroups(steps []workflowStep, minimum int, ordinaryComponent func(string) bool) error {
	seen := map[string]bool{}
	for i := 0; i < len(steps); {
		label := steps[i].ParallelGroup
		if label == "" {
			i++
			continue
		}
		if !telemetryLabel.MatchString(label) || seen[label] {
			return errors.New("parallel group labels must be valid and contiguous")
		}
		seen[label] = true
		kind, mode := steps[i].Kind, steps[i].RecoveryMode
		responsibilities := map[string]bool{}
		end := i
		for end < len(steps) && steps[end].ParallelGroup == label {
			step := steps[end]
			if step.Kind != kind || step.Repetitions != nil {
				return errors.New("parallel groups require one supported kind without repetitions")
			}
			switch kind {
			case "assembly-checks":
				if !validAssemblyResponsibility(step.Responsibility) || responsibilities[step.Responsibility] {
					return errors.New("assembly groups require distinct supported responsibilities")
				}
				responsibilities[step.Responsibility] = true
			case "component-tests":
				if step.Profile == "" || step.Package != "" ||
					len(step.Tests) == 0 || !allComponentRequests(step.Tests, ordinaryComponent) {
					return errors.New("component groups require an explicit profile and literal ordinary focus")
				}
				if _, err := resolveVerificationProfile(step.Profile); err != nil {
					return err
				}
			case "run":
				if mode != "enabled" && mode != "disabled" || step.RecoveryMode != mode || step.Limits == "" {
					return errors.New("live groups require one explicit recovery mode and finite limits")
				}
			default:
				return errors.New("parallel groups support assembly checks, ordinary focused components or live runs")
			}
			end++
		}
		if end-i < minimum {
			return errors.New("configured parallel groups require at least two members")
		}
		i = end
	}
	return nil
}

func validatePlanRunConfiguration(parsed planRunArguments) error {
	request := parsed.request
	if parsed.workflowPresent {
		if request.Path == "" || parsed.present["step"] && request.SelectedStep == "" {
			return errors.New("workflow and selected step must be nonempty")
		}
		if parsed.testCount != 0 && (parsed.stepCount != 1 || !validOrdinaryFocusName(request.Test)) {
			return errors.New("--test requires one literal path and one selected step")
		}
		if parsed.packageCount != 0 && (parsed.stepCount != 1 || !validOrdinaryPackagePath(request.Package)) {
			return errors.New("--package requires one exact package and one selected step")
		}
		if len(request.Scenarios) != 0 || parsed.recoveryCount != 0 {
			if parsed.stepCount != 1 || request.SelectedStep == "" || parsed.testCount != 0 || parsed.packageCount != 0 {
				return errors.New("scenario and recovery focus require one run step")
			}
		}
	} else {
		if len(parsed.suites) == 0 || parsed.environment == "" {
			return errors.New("suite selection and environment must be nonempty")
		}
		seen := map[string]bool{}
		for _, path := range parsed.suites {
			if path == "" || seen[path] {
				return errors.New("suite paths must be nonempty and unique")
			}
			seen[path] = true
		}
	}
	return nil
}

func singleTestRequest(request string) []string {
	if request == "" {
		return nil
	}
	return []string{request}
}

func allComponentRequests(tests []string, allowed func(string) bool) bool {
	for _, test := range tests {
		if !validComponentName(test) || allowed != nil && !allowed(test) {
			return false
		}
	}
	return true
}

package main

import (
	"errors"
	"path/filepath"
)

// Keep configured and command inputs separate for authenticated delegation.
// Policy resolution does not admit Product selections or authorize effects.
type supervisorExecutionInputs struct {
	Configured executionRequest
	Command    executionRequest
	Policy     executionPolicy
}

func preflightSupervisorExecution(root string, args []string) (supervisorExecutionInputs, error) {
	if len(args) == 0 {
		return supervisorExecutionInputs{}, errors.New(testCommandUsage)
	}
	inputs := supervisorExecutionInputs{}
	workflowPath := ""
	switch args[0] {
	case "plan", "run":
		parsed, err := parsePlanRunArguments(args)
		if err != nil {
			return inputs, err
		}
		inputs.Command = parsed.request.Execution.clone()
		if parsed.workflowPresent {
			if parsed.request.Path == "" {
				return inputs, errors.New("workflow path required")
			}
			workflowPath = parsed.request.Path
			if _, _, err := readWorkflowConfiguration(parsed.request); err != nil {
				return inputs, err
			}
		}
	case "cleanup":
		request, err := parseCleanupRequest(args)
		if err != nil {
			return inputs, err
		}
		inputs.Command = request.execution.Requested.clone()
	case "check", "dev", "unit", "runner-tests", "fuzz", "fmt", "fmt-check", "lint", "list":
		positional, request, err := parseExecutionPositionals(args)
		if err != nil {
			return inputs, err
		}
		inputs.Command = request.clone()
		switch args[0] {
		case "check", "dev":
			if len(positional) != 1 {
				return inputs, errors.New("local workflow takes no positional arguments")
			}
			workflowPath = filepath.Join(root, "tests/workflows", args[0]+".json")
		case "runner-tests", "fmt", "fmt-check", "lint", "list":
			if len(positional) != 1 {
				return inputs, errors.New("test command takes no positional arguments")
			}

		}
	default:
		return inputs, errors.New(testCommandUsage)
	}
	if workflowPath != "" {
		var file workflowFile
		if err := readSelectionFile(workflowPath, &file); err != nil {
			return inputs, err
		}
		if file.SchemaVersion != 1 {
			return inputs, errors.New("workflow schema version refused")
		}
		inputs.Configured = file.Execution.clone()
	}
	policy, err := resolveExecution(inputs.Configured, inputs.Command)
	if err != nil {
		return inputs, err
	}
	inputs.Policy = policy
	return inputs, nil
}

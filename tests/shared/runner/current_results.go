package main

import (
	"encoding/json"
	"errors"
	"io"

	records "enkv.sh/core/internal/testrecords"
)

type currentTestResult struct {
	Type      string                `json:"type"`
	Step      string                `json:"step,omitempty"`
	Activity  string                `json:"activity"`
	Outcome   string                `json:"outcome"`
	Ordinary  *ordinaryStepEvidence `json:"ordinary,omitempty"`
	Component *componentRunRecord   `json:"component,omitempty"`
	Assembly  *offlineEvidence      `json:"assembly,omitempty"`
	Fuzz      []*fuzzEvidence       `json:"fuzz,omitempty"`
	Suite     *runRecord            `json:"suite,omitempty"`
}

func writeCurrentTestResult(output io.Writer, step, activity, outcome string, execution workflowStepExecution) error {
	result := currentTestResult{Type: "test_result", Step: step, Activity: activity, Outcome: outcome,
		Ordinary: execution.Ordinary, Component: execution.Component, Assembly: execution.Assembly, Fuzz: execution.Fuzz, Suite: execution.Suite}
	body, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if len(body)+1 > records.MaximumJSONBytes {
		return errors.New("current test result exceeds its record bound")
	}
	body = append(body, '\n')
	written, err := output.Write(body)
	if err == nil && written != len(body) {
		return io.ErrShortWrite
	}
	return err
}

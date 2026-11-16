package main

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

// full_only: false
func TestPreparedAdmissionUsesAdmittedPolicyWithoutMutation(t *testing.T) {
	for _, kind := range []string{"workflow", "suite"} {
		for _, row := range []struct {
			name                                      string
			parentMemory, requestedMemory, wantMemory int
		}{
			{"big", 24576, 0, 24576}, {"explicit-ceiling", 24576, 12000, 12000}, {"normal", 8192, 0, 8192}, {"parent-cap", 512, 12000, 512},
		} {
			t.Run(kind+"/"+row.name, func(t *testing.T) {
				saved := executionPolicy{Resolved: executionCapacity{Parallel: 4, MemoryLimitMiB: 8192}}
				if row.requestedMemory != 0 {
					saved.Requested.MemoryLimitMiB = &row.requestedMemory
				}
				beforePolicy := saved.clone()
				ctx := withExecutionCapacity(context.Background(), executionPolicy{Resolved: executionCapacity{Parallel: 1, MemoryLimitMiB: row.parentMemory}})
				if _, err := executionWithinContext(ctx, saved); err != nil {
					t.Fatal("invalid admitted policy fixture", err)
				}
				class := rootAdmission{Big: kind != "suite", Execution: saved.clone()}
				expectedClass := class
				expectedClass.Execution = class.Execution.clone()
				check := func(admission rootAdmission) {
					t.Helper()
					admitted, err := admitPreparedExecution(ctx, admission)
					if err != nil || executionCapacityFromContext(admitted) != (executionCapacity{Parallel: 1, MemoryLimitMiB: row.wantMemory}) {
						t.Fatal("prepared owner did not retain the assigned execution allowance", err)
					}
				}
				switch kind {
				case "workflow":
					prepared := &preparedWorkflow{plan: workflowPlan{SchemaVersion: 1, Name: "admitted-plan", Profile: "full", Execution: saved.clone()}, class: class}
					before, err := json.Marshal(prepared.plan)
					if err != nil {
						t.Fatal(err)
					}
					check(prepared.admission())
					after, err := json.Marshal(prepared.plan)
					if err != nil {
						t.Fatal(err)
					}
					if string(before) != string(after) || !reflect.DeepEqual(prepared.plan.Execution, beforePolicy) || !reflect.DeepEqual(prepared.class, expectedClass) {
						t.Fatal("workflow admission changed the saved preparation identity")
					}
				case "suite":
					prepared := &preparedSuite{request: runRequest{Suite: "hermetic", Provider: "memory", Target: "memory", Resolved: &resolvedRequest{Mode: "hermetic", Provider: "memory", Profile: "full", Race: true}, execution: saved.clone()}, class: class}
					identity, err := suiteRequestIdentity(prepared.request)
					if err != nil {
						t.Fatal(err)
					}
					prepared.requestIdentity = identity
					check(prepared.admission())
					after, err := suiteRequestIdentity(prepared.request)
					if err != nil || after != identity || prepared.requestIdentity != identity || !reflect.DeepEqual(prepared.request.execution, beforePolicy) || !reflect.DeepEqual(prepared.class, expectedClass) {
						t.Fatal("suite admission changed the saved preparation identity", err)
					}

				}
			})
		}
	}
}

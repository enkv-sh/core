package main

import (
	"context"
	"reflect"
	"testing"
)

// full_only: false
func TestExecutionGoArgumentsShareAssignedAllowance(t *testing.T) {
	for _, test := range []struct {
		name        string
		share       int
		input, want []string
	}{
		{"test", 4, []string{"test", "-json", "./..."}, []string{"test", "-parallel=4", "-p=1", "-json", "./..."}},
		{"packages", 4, []string{"test", "-p=4", "-parallel=2", "./..."}, []string{"test", "-parallel=2", "-p=2", "./..."}},
		{"child", 1, []string{"test", "-p", "4", "-test.parallel=4", "."}, []string{"test", "-parallel=1", "-p=1", "."}},
		{"compile", 3, []string{"test", "-c", "-o", "binary", "."}, []string{"test", "-p=3", "-c", "-o", "binary", "."}},
		{"compile_false", 2, []string{"test", "-c=false", "."}, []string{"test", "-parallel=2", "-p=1", "-c=false", "."}},
		{"selector", 2, []string{"test", "-run", "-p=4", "-skip", "-c", "."}, []string{"test", "-parallel=2", "-p=1", "-run", "-p=4", "-skip", "-c", "."}},
		{"build", 3, []string{"build", "-o", "-p=4", "."}, []string{"build", "-p=3", "-o", "-p=4", "."}},
		{"run", 2, []string{"run", "-p=4", "main.go", "-p=4"}, []string{"run", "-p=2", "main.go", "-p=4"}},
		{"test_args", 2, []string{"test", ".", "-args", "-parallel=9"}, []string{"test", "-parallel=2", "-p=1", ".", "-args", "-parallel=9"}},
		{"list", 4, []string{"list", "-p=2", "-f", "-p=3", "."}, []string{"list", "-p=2", "-f", "-p=3", "."}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := withExecutionParallel(context.Background(), test.share)
			got, err := executionGoArguments(ctx, test.input)
			if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("arguments = %q, %v; want %q", got, err, test.want)
			}
		})
	}
	for _, input := range [][]string{{"test", "-p"}, {"test", "-parallel=0"}, {"test", "-p=-1"}, {"test", "-parallel=x"}, {"test", "-run"}, {"test", "-args", "-test.parallel=4"}} {
		if _, err := executionGoArguments(context.Background(), input); err == nil {
			t.Fatalf("invalid command accepted: %q", input)
		}
	}
}

// full_only: false
func TestExecutionClassAndNestedAllowance(t *testing.T) {
	policy := defaultExecutionPolicy()
	if policy.Resolved != (executionCapacity{Parallel: 4, MemoryLimitMiB: 8192}) {
		t.Fatal("normal default differs", policy)
	}
	big := executionForClass(policy, true)
	if big.Resolved != (executionCapacity{Parallel: 4, MemoryLimitMiB: 24576}) {
		t.Fatal("big default differs", big)
	}
	explicit := 12000
	policy, err := resolveExecution(executionRequest{MemoryLimitMiB: &explicit}, executionRequest{})
	if err != nil || policy.Resolved.MemoryLimitMiB != 8192 || executionForClass(policy, true).Resolved.MemoryLimitMiB != 12000 {
		t.Fatal("class ceiling differs", policy, err)
	}
	ctx := withExecutionCapacity(context.Background(), executionPolicy{Resolved: executionCapacity{Parallel: 1, MemoryLimitMiB: 512}})
	child, err := executionWithinContext(ctx, big)
	if err != nil || child.Resolved != (executionCapacity{Parallel: 1, MemoryLimitMiB: 512}) {
		t.Fatal("child multiplied assigned allowance", child)
	}
	if _, _, err := parseExecutionPositionals([]string{"unit", "--lanes=2"}); err == nil {
		t.Fatal("removed lanes option accepted")
	}
	for _, row := range []struct {
		name                                                                                                                   string
		parentParallel, parentMemory, savedParallel, savedMemory, requestedParallel, requestedMemory, wantParallel, wantMemory int
		refused                                                                                                                bool
	}{
		{name: "admitted-big-replaces-prepared-normal", parentParallel: 1, parentMemory: 24576, savedParallel: 4, savedMemory: 8192, wantParallel: 1, wantMemory: 24576},
		{name: "explicit-memory-ceiling", parentParallel: 2, parentMemory: 24576, savedParallel: 4, savedMemory: 8192, requestedMemory: 12000, wantParallel: 2, wantMemory: 12000},
		{name: "parent-memory-cap", parentParallel: 3, parentMemory: 512, savedParallel: 4, savedMemory: 8192, requestedMemory: 12000, wantParallel: 3, wantMemory: 512},
		{name: "normal-parent", parentParallel: 1, parentMemory: 8192, savedParallel: 4, savedMemory: 24576, wantParallel: 1, wantMemory: 8192},
		{name: "assigned-parallel-never-expanded", parentParallel: 4, parentMemory: 24576, savedParallel: 1, savedMemory: 8192, wantParallel: 1, wantMemory: 24576},
		{name: "explicit-parallel-ceiling", parentParallel: 4, parentMemory: 24576, savedParallel: 2, savedMemory: 8192, requestedParallel: 2, wantParallel: 2, wantMemory: 24576},
		{name: "invalid-supplied-memory", parentParallel: 1, parentMemory: 24576, savedParallel: 4, savedMemory: 24577, refused: true},
		{name: "invalid-supplied-parallel", parentParallel: 1, parentMemory: 24576, savedParallel: 5, savedMemory: 8192, refused: true},
		{name: "supplied-memory-exceeds-request", parentParallel: 1, parentMemory: 24576, savedParallel: 4, savedMemory: 8192, requestedMemory: 512, refused: true},
		{name: "supplied-parallel-exceeds-request", parentParallel: 1, parentMemory: 24576, savedParallel: 4, savedMemory: 8192, requestedParallel: 1, refused: true},
		{name: "invalid-parent-memory", parentParallel: 1, parentMemory: 0, savedParallel: 4, savedMemory: 8192, refused: true},
		{name: "invalid-parent-parallel", parentParallel: 0, parentMemory: 8192, savedParallel: 4, savedMemory: 8192, refused: true},
	} {
		t.Run(row.name, func(t *testing.T) {
			supplied := executionPolicy{Resolved: executionCapacity{Parallel: row.savedParallel, MemoryLimitMiB: row.savedMemory}}
			if row.requestedParallel != 0 {
				supplied.Requested.Parallel = &row.requestedParallel
			}
			if row.requestedMemory != 0 {
				supplied.Requested.MemoryLimitMiB = &row.requestedMemory
			}
			before := supplied.clone()
			parent := withExecutionCapacity(t.Context(), executionPolicy{Resolved: executionCapacity{Parallel: row.parentParallel, MemoryLimitMiB: row.parentMemory}})
			actual, err := executionWithinContext(parent, supplied)
			if (err != nil) != row.refused {
				t.Fatal("assigned policy admission differs", row.name, actual, err)
			}
			if !row.refused && actual.Resolved != (executionCapacity{Parallel: row.wantParallel, MemoryLimitMiB: row.wantMemory}) {
				t.Fatal("saved preparation replaced final root authority", actual.Resolved, err)
			}
			if !reflect.DeepEqual(supplied, before) {
				t.Fatal("policy resolution changed saved preparation inputs")
			}
		})
	}

}

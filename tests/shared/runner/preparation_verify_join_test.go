package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// full_only: false
func TestPreparedVerificationUsesCapturedOwnersWithoutCompilerReads(t *testing.T) {
	for _, kind := range []string{"workflow", "suite", "fuzz", "live_preflight"} {
		t.Run(kind, func(t *testing.T) {
			ctx := withRacePolicy(t.Context(), true)
			ctx, artifacts := withInvocationArtifacts(ctx)
			t.Cleanup(func() {
				if err := artifacts.close(t.Context(), true); err != nil {
					t.Error(err)
				}
			})
			root, control := t.TempDir(), t.TempDir()
			marker := filepath.Join(control, "compiler-entered")
			if err := os.WriteFile(filepath.Join(control, "go"), []byte("#!/bin/sh\nprintf entered > "+shellQuote(marker)+"\nexit 19\n"), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", control)
			current, err := newCurrentDirectory("enkv-prepared-verification-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if _, err := os.Stat(current.path); err == nil {
					if err := current.remove(true); err != nil {
						t.Error(err)
					}
				} else if !os.IsNotExist(err) {
					t.Error(err)
				}
			})
			sentinel := filepath.Join(current.path, "private-input")
			if err := os.WriteFile(sentinel, []byte("captured private input"), 0600); err != nil {
				t.Fatal(err)
			}
			identity, err := os.Stat(sentinel)
			if err != nil {
				t.Fatal(err)
			}
			binding := preparationBinding{ctx: ctx, race: true, live: kind == "live_preflight"}
			inventory := assembly{Closure: assemblyClosure{Race: true, RaceOptions: acceptedRaceOptions(true), RaceExitSleepMillis: 1000}}
			var verify func(context.Context, string) error
			var closeOwner func(context.Context) error
			var change func() func()
			switch kind {
			case "workflow":
				plan := workflowPlan{SchemaVersion: 1, Name: "captured-owner", Profile: "dev", Race: true}
				body, err := json.Marshal(plan)
				if err != nil {
					t.Fatal(err)
				}
				owner := &preparedWorkflow{assemblyPreparations: ctx, binding: binding, current: current, plan: plan, planIdentity: digestBytes(body), joined: true}
				verify, closeOwner = owner.verify, owner.close
				change = func() func() { owner.plan.Name = "changed"; return func() { owner.plan = plan } }
			case "suite":
				request := runRequest{Suite: "hermetic", Provider: "memory", Resolved: &resolvedRequest{Mode: "hermetic", Provider: "memory", Race: true}}
				identity, err := suiteRequestIdentity(request)
				if err != nil {
					t.Fatal(err)
				}
				owner := &preparedSuite{assemblyPreparations: ctx, binding: binding, current: current, request: request, requestIdentity: identity, inventory: inventory, joined: true}
				verify, closeOwner = owner.verify, owner.close
				change = func() func() { owner.request.Provider = "changed"; return func() { owner.request = request } }
			case "fuzz":
				owner := &preparedFuzz{binding: binding, current: current, names: []string{"format"}, targets: []preparedFuzzTarget{{spec: fuzzSpecifications[0]}}, joined: true}
				verify, closeOwner = owner.verify, owner.close
				change = func() func() { owner.names = []string{"contract"}; return func() { owner.names = []string{"format"} } }
			case "live_preflight":
				owner := &preparedLivePreflight{binding: binding, current: current, inventory: inventory, joined: true}
				verify, closeOwner = owner.verify, owner.close
				change = func() func() { owner.inventory.Closure.Race = false; return func() { owner.inventory = inventory } }
			}
			writeLocalGoFixture(t, root, "edited.go", "package changed\n")
			if err := verify(ctx, root); err != nil {
				t.Fatal("captured owner was invalidated by a checkout edit or compiler path change", err)
			}
			restore := change()
			if err := verify(ctx, root); err == nil {
				t.Fatal("changed prepared selection/build configuration was accepted")
			}
			restore()
			if err := verify(withRacePolicy(ctx, false), root); err == nil {
				t.Fatal("changed invocation race policy was accepted")
			}
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			if err := verify(canceled, root); !errors.Is(err, context.Canceled) {
				t.Fatal("canceled verification did not retain its cause", err)
			}
			body, err := os.ReadFile(sentinel)
			after, statErr := os.Stat(sentinel)
			if err != nil || statErr != nil || string(body) != "captured private input" || !os.SameFile(identity, after) {
				t.Fatal("verification removed or replaced the prepared owner's private input", err, statErr)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("verification invoked a compiler instead of using captured facts", err)
			}
			if err := closeOwner(ctx); err != nil {
				t.Fatal("joined captured owner failed to close", err)
			}
			if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
				t.Fatal("joined owner did not remove its private input", err)
			}
		})
	}
}

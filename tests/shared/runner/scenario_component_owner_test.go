package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestScenarioComponentOwnerPreparationKeepsBorrowedAssembly(t *testing.T) {
	ctx, root, bootstrap := componentRepetitionAssemblyFixture(t)
	compiles := observePreparationCompiles(t)
	build := t.TempDir()
	writeLocalGoFixture(t, root, "core/input.go", "package core\nconst Input = 1\n")
	entered := filepath.Join(t.TempDir(), "worker-entered")
	writeLocalGoFixture(t, root, "tests/hermetic/scenario_component_owner_test.go", fmt.Sprintf(`package core
import (
 "os"
 "testing"
)
func init() {
 if os.Getenv("ENKV_TEST_INVOCATION") != "" {
  if err := os.WriteFile(%[1]q, []byte("entered"), 0600); err != nil { panic(err) }
 }
}
func failScenarioComponentOwnerWorker(t *testing.T) {
 t.Helper()
 if err := os.WriteFile(%[1]q, []byte("entered"), 0600); err != nil { t.Fatal(err) }
 t.Fatal("scenario component owner preparation must not execute a scenario worker")
}
// full_only: false
func TestHermeticRun(t *testing.T) { failScenarioComponentOwnerWorker(t) }
// full_only: false
func TestHermeticChild(t *testing.T) { failScenarioComponentOwnerWorker(t) }
`, entered))
	source, err := sourceRevision(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	version, err := runGo(ctx, root, "core", "version")
	if err != nil {
		t.Fatal(err)
	}
	toolchain := strings.TrimSpace(string(version))
	group := newPreparedComponentGroup(ctx)
	defer group.cancel()
	assembled, err := group.prepare(root, bootstrap, "full", nil, source, toolchain, build)
	if err != nil {
		t.Fatal("prepare real scenario component owner fixture", err)
	}
	// Synthetic complete component evidence is boundary input only. Inventory
	// and assembly identities come from the real compiled fixture.
	_, full := completeRunFixture(t, "memory")
	component := full.Correctness.ComponentRun
	component.Source, component.Toolchain, component.BuildClosure = source, toolchain, &assembled.Closure
	if !component.passedFor(source, toolchain) {
		t.Fatal("complete same-run component fixture was refused")
	}
	suite, environment := filepath.Join(root, "selected-suite.json"), filepath.Join(root, "selected-environment.json")
	saveSelection(t, suite, suiteFixture("scenario-component-owner-preparation", []string{"state.single-value-update-preserves-other-values/members_32"}))
	saveSelection(t, environment, memoryEnvironment())
	request, err := parseRunRequest([]string{"run", "--race", "--suite", suite, "--environment", environment})
	if err != nil {
		t.Fatal(err)
	}
	request.components = &componentRun{record: *component, assembled: assembled}
	beforeReuse, err := os.ReadFile(compiles)
	if err != nil {
		t.Fatal("completed owner compiles unavailable", err)
	}
	t.Run("direct-preparation-borrows-owner", func(t *testing.T) {
		prepared, err := prepareSuite(nil, ctx, root, bootstrap, request, io.Discard)
		if prepared != nil {
			defer func() {
				if err := prepared.close(ctx); err != nil {
					t.Error(err)
				}
			}()
		}
		if err != nil || prepared == nil {
			t.Fatal("valid owner was not prepared", err)
		}
		wantCompiled := []string{"TestFiniteRepetitionProcessWitness", maximumCapacityComponent, "TestHermeticRun", "TestHermeticChild"}
		slices.Sort(wantCompiled)
		compiled, workers := slices.Clone(prepared.compiled), slices.Clone(prepared.workers)
		slices.Sort(compiled)
		slices.Sort(workers)
		if prepared.inventory.Binary != assembled.Binary || !sameAssemblyBuild(prepared.inventory.Closure, assembled.Closure) ||
			!slices.Equal(compiled, wantCompiled) || !slices.Equal(workers, []string{"TestHermeticChild", "TestHermeticRun"}) || prepared.admission().Big {
			t.Fatal("borrowed preparation lost actual inventory or selected worker admission", compiled, workers)
		}
		classifications := map[string]bool{"TestFiniteRepetitionProcessWitness": false, maximumCapacityComponent: true, "TestHermeticRun": false, "TestHermeticChild": false}
		for _, row := range prepared.classifications {
			want, present := classifications[row.Name]
			if !present || row.FullOnly == nil || *row.FullOnly != want {
				t.Fatal("borrowed preparation changed the compiled classification", row)
			}
			delete(classifications, row.Name)
		}
		if len(classifications) != 0 {
			t.Fatal("borrowed preparation omitted compiled classifications", classifications)
		}
		if err := prepared.close(ctx); err != nil {
			t.Fatal(err)
		}
		if err := checkAssemblyRace(ctx, assembled); err != nil {
			t.Fatal("suite close invalidated the borrowed owner", err)
		}
	})
	for _, name := range []string{"source-root", "race"} {
		t.Run("direct-preparation-refuses-"+name, func(t *testing.T) {
			candidate := request
			owner, resolved := *request.components, *request.Resolved
			candidate.components, candidate.Resolved = &owner, &resolved
			if name == "source-root" {
				owner.assembled.root = t.TempDir()
			} else {
				resolved.Race = false
			}
			prepared, err := prepareSuite(nil, withRacePolicy(ctx, resolved.Race), root, bootstrap, candidate, io.Discard)
			if prepared != nil {
				defer func() {
					if err := prepared.close(ctx); err != nil {
						t.Error(err)
					}
				}()
			}
			var refusal *componentReuseFailure
			if err == nil || !errors.As(err, &refusal) || !toolCommandsJoined(err) {
				t.Fatal("direct preparation accepted an incompatible supplied build", err)
			}
		})
	}
	for _, condition := range []string{"source-edit", "failed-result"} {
		t.Run("direct-preparation-borrows-after-"+condition, func(t *testing.T) {
			candidate := request
			owner := *request.components
			candidate.components = &owner
			if condition == "source-edit" {
				writeLocalGoFixture(t, root, "core/input.go", "package core\ninvalid source after the build\n")
				defer writeLocalGoFixture(t, root, "core/input.go", "package core\nconst Input = 1\n")
			} else {
				owner.record.Outcome = "failed"
			}
			prepared, err := prepareSuite(nil, ctx, root, bootstrap, candidate, io.Discard)
			if prepared != nil {
				defer func() {
					if err := prepared.close(ctx); err != nil {
						t.Error(err)
					}
				}()
			}
			if err != nil || prepared == nil || prepared.inventory.Binary != assembled.Binary {
				t.Fatal("completed compatible build was not borrowed", condition, err)
			}
			if condition == "failed-result" && candidate.components.record.Outcome != "failed" {
				t.Fatal("borrowing erased the failed component result")
			}
		})
	}
	if afterReuse, err := os.ReadFile(compiles); err != nil || string(afterReuse) != string(beforeReuse) {
		t.Fatal("supplied-build preparation compiled another assembly", err)
	}
	if _, err := os.Stat(entered); !os.IsNotExist(err) {
		t.Fatal("supplied-build preparation executed a scenario worker", err)
	}
	writer := &ordinaryReviewEnvironmentWriter{before: "Reusing build preparation from the component step\n", change: func() {
		writeLocalGoFixture(t, root, "core/input.go", "package core\ninvalid source before worker entry\n")
	}}
	result, runErr := runSuite(ctx, root, bootstrap, request, writer)
	if !writer.done {
		t.Fatal("component reuse did not reach its announcement", runErr)
	}
	if runErr == nil || !toolCommandsJoined(runErr) || !sourceCommandsJoined(runErr) || result.Record == nil || result.Record.Outcome != "failed" || len(result.Record.Scenarios) != 1 || result.Record.FinishedAt == nil || !records.ValidRunID(result.Record.RunID) {
		t.Fatal("actual controlled worker failure lost its finalized result or positive joins", runErr)
	}
	if _, err := os.Stat(entered); err != nil {
		t.Fatal("source edit stopped the already built scenario worker", err)
	}
	if afterReuse, err := os.ReadFile(compiles); err != nil || string(afterReuse) != string(beforeReuse) {
		t.Fatal("scenario dispatch compiled another assembly", err)
	}
	if _, err := os.Stat(assembled.Binary); err != nil {
		t.Fatal("scenario settlement disposed its borrowed build", err)
	}
}

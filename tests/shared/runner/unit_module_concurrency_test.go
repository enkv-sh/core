package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

func unitModuleTerminal(module string) ordinaryStepEvidence {
	return ordinaryStepEvidence{Packages: []ordinaryPackage{{Name: module, Tests: []string{"TestCase"}}}, Tests: []ordinaryTest{{Package: module, Name: "TestCase", Outcome: "pass"}}}
}

// full_only: false
func TestUnitModuleConcurrencyPreservesEvidenceAndJoins(t *testing.T) {
	modules := []string{"first", "second", "queued"}
	for _, parallel := range []int{1, 2, 3, 4} {
		t.Run(fmt.Sprintf("complete_and_ordered/parallel_%d", parallel), func(t *testing.T) {
			modules := []string{"first", "second", "third", "fourth", "queued"}
			ctx, cancel := context.WithTimeout(withExecutionCapacity(t.Context(), executionPolicy{Resolved: executionCapacity{Parallel: parallel, MemoryLimitMiB: 4096}}), 5*time.Second)
			defer cancel()
			started := make(chan string, len(modules))
			release := make(chan struct{})
			done := make(chan unitModuleOutcome, 1)
			t.Cleanup(func() { cancel(); waitUnitModuleJoin(t, done) })
			var output bytes.Buffer
			var active, peak atomic.Int32
			var wrongAllocation atomic.Bool
			go func() {
				defer close(done)
				runs, err := runUnitPackages(ctx, modules, &output, func(child context.Context, module string) (ordinaryStepEvidence, error) {
					if got := executionCapacityFromContext(child); got != (executionCapacity{Parallel: 1, MemoryLimitMiB: 4096}) {
						wrongAllocation.Store(true)
					}
					live := active.Add(1)
					defer active.Add(-1)
					for old := peak.Load(); live > old; old = peak.Load() {
						if peak.CompareAndSwap(old, live) {
							break
						}
					}
					started <- module
					select {
					case <-release:
					case <-child.Done():
						return ordinaryStepEvidence{}, child.Err()
					}
					return unitModuleTerminal(module), nil
				})
				done <- unitModuleOutcome{runs, err}
			}()
			var firstWave []string
			for range parallel {
				select {
				case module := <-started:
					firstWave = append(firstWave, module)
				case got := <-done:
					t.Fatalf("module invocation ended before admitted wave: %v", got.err)
				case <-ctx.Done():
					t.Fatal("admitted module wave did not start", ctx.Err())
				}
			}
			select {
			case module := <-started:
				t.Errorf("queued module %s began while all %d parallel were occupied", module, parallel)
			case <-time.After(20 * time.Millisecond):
			}
			slices.Sort(firstWave)
			wantWave := slices.Clone(modules[:parallel])
			slices.Sort(wantWave)
			if !reflect.DeepEqual(firstWave, wantWave) {
				t.Errorf("admission changed queue prefix: got %v want %v", firstWave, wantWave)
			}
			close(release)
			got := awaitUnitModuleOutcome(t, done)
			if got.err != nil || len(got.runs) != len(modules) {
				t.Fatal("complete module set failed", got.err)
			}
			if peak.Load() != int32(parallel) || active.Load() != 0 || wrongAllocation.Load() {
				t.Errorf("module capacity: peak=%d want=%d active=%d wrong_child_allocation=%t", peak.Load(), parallel, active.Load(), wrongAllocation.Load())
			}
			for i, module := range modules {
				if !got.runs[i].started || got.runs[i].pkg != module || got.runs[i].err != nil || !reflect.DeepEqual(got.runs[i].evidence, unitModuleTerminal(module)) {
					t.Error("selected/completed module evidence changed", i)
				}
			}
			if bytes.Count(output.Bytes(), []byte("Testing ")) != len(modules) || bytes.Count(output.Bytes(), []byte("Validated 1")) != len(modules) {
				t.Error("module output incomplete")
			}
		})
	}
	t.Run("failure_cancels_and_joins", func(t *testing.T) {
		started := make(chan string, 3)
		release := make(chan struct{})
		joined := make(chan struct{})
		failure := errors.New("controlled module failure")
		var output bytes.Buffer
		done := make(chan unitModuleOutcome, 1)
		ctx, cancel := context.WithTimeout(withExecutionCapacity(t.Context(), executionPolicy{Resolved: executionCapacity{Parallel: 2, MemoryLimitMiB: 4096}}), 5*time.Second)
		defer cancel()
		t.Cleanup(func() { cancel(); waitUnitModuleJoin(t, done) })
		go func() {
			defer close(done)
			runs, err := runUnitPackages(ctx, modules, &output, func(ctx context.Context, module string) (ordinaryStepEvidence, error) {
				started <- module
				if module == "first" {
					select {
					case <-release:
					case <-ctx.Done():
						return ordinaryStepEvidence{}, ctx.Err()
					}
					return ordinaryStepEvidence{}, failure
				}
				if module == "second" {
					<-ctx.Done()
					close(joined)
					return ordinaryStepEvidence{}, ctx.Err()
				}
				return unitModuleTerminal(module), nil
			})
			done <- unitModuleOutcome{runs, err}
		}()
		for range 2 {
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal("two admitted modules did not start", ctx.Err())
			}
		}
		close(release)
		got := awaitUnitModuleOutcome(t, done)
		if !errors.Is(got.err, failure) || got.runs[2].started {
			t.Fatal("queued module ran or failure disappeared", got.err)
		}
		select {
		case <-joined:
		default:
			t.Fatal("second module was not joined")
		}
	})
	for _, parallel := range []int{1, 2, 3, 4} {
		t.Run(fmt.Sprintf("parent_cancellation_joins/parallel_%d", parallel), func(t *testing.T) {
			modules := []string{"first", "second", "third", "fourth", "queued"}
			ctx, cancel := context.WithTimeout(withExecutionCapacity(t.Context(), executionPolicy{Resolved: executionCapacity{Parallel: parallel, MemoryLimitMiB: 4096}}), 5*time.Second)
			defer cancel()
			started := make(chan string, len(modules))
			joined := make(chan string, len(modules))
			var output bytes.Buffer
			done := make(chan unitModuleOutcome, 1)
			t.Cleanup(func() { cancel(); waitUnitModuleJoin(t, done) })
			go func() {
				defer close(done)
				runs, err := runUnitPackages(ctx, modules, &output, func(child context.Context, module string) (ordinaryStepEvidence, error) {
					started <- module
					<-child.Done()
					joined <- module
					return ordinaryStepEvidence{}, child.Err()
				})
				done <- unitModuleOutcome{runs, err}
			}()
			for range parallel {
				select {
				case <-started:
				case <-ctx.Done():
					t.Fatal("admitted cancellation wave did not start", ctx.Err())
				}
			}
			cancel()
			got := awaitUnitModuleOutcome(t, done)
			if !errors.Is(got.err, context.Canceled) || len(got.runs) != len(modules) || len(joined) != parallel {
				t.Fatal("cancelled module set was not joined", got.err, len(joined))
			}
			for index, item := range got.runs {
				if item.started != (index < parallel) {
					t.Error("queued work started or admitted work disappeared", index)
				}
				if item.started && (!errors.Is(item.err, context.Canceled) || item.pkg != modules[index]) {
					t.Error("cancelled module lost its own terminal evidence", index)
				}
			}
		})
	}
	for _, parallel := range []int{1, 2, 3, 4} {
		t.Run(fmt.Sprintf("output_failure_stops_before_commands/parallel_%d", parallel), func(t *testing.T) {
			modules := []string{"first", "second", "third", "fourth", "queued"}
			ctx := withExecutionCapacity(t.Context(), executionPolicy{Resolved: executionCapacity{Parallel: parallel, MemoryLimitMiB: 4096}})
			var calls atomic.Int32
			runs, err := runUnitPackages(ctx, modules, failingUnitOutput{}, func(context.Context, string) (ordinaryStepEvidence, error) {
				calls.Add(1)
				return ordinaryStepEvidence{}, nil
			})
			if err == nil || calls.Load() != 0 {
				t.Fatal("failed output still launched module commands", err)
			}
			for _, queued := range runs[parallel:] {
				if queued.started {
					t.Fatal("failed output still admitted a queued module")
				}
			}
		})
	}
	t.Run("shared_directory_leases_join_before_cleanup", func(t *testing.T) {
		locks := resourceLockFixture(t)
		root := t.TempDir()
		if err := os.Mkdir(filepath.Join(root, "core"), 0700); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(withExecutionCapacity(t.Context(), executionPolicy{Resolved: executionCapacity{Parallel: 2, MemoryLimitMiB: 4096}}), 10*time.Second)
		defer cancel()
		started := make(chan struct{}, 2)
		release := make(chan struct{})
		done := make(chan unitModuleOutcome, 1)
		var output bytes.Buffer
		t.Cleanup(func() { cancel(); waitUnitModuleJoin(t, done) })
		go func() {
			defer close(done)
			runs, err := runUnitPackages(ctx, modules[:2], &output, func(ctx context.Context, module string) (ordinaryStepEvidence, error) {
				cleanup, err := prepareToolDirectories(ctx, locks, root)
				if err != nil {
					return ordinaryStepEvidence{}, err
				}
				releaseLease := func() error {
					tail, cancel := finalizationContext(ctx)
					defer cancel()
					return cleanup.Release(tail, true)
				}
				started <- struct{}{}
				select {
				case <-release:
				case <-ctx.Done():
					return ordinaryStepEvidence{}, errors.Join(ctx.Err(), releaseLease())
				}
				return unitModuleTerminal(module), releaseLease()
			})
			done <- unitModuleOutcome{runs, err}
		}()
		for range 2 {
			select {
			case <-started:
			case got := <-done:
				t.Fatal("parallel lease acquisition failed", got.err)
			case <-ctx.Done():
				t.Fatal("parallel lease acquisition timed out", ctx.Err())
			}
		}
		close(release)
		got := awaitUnitModuleOutcome(t, done)
		if got.err != nil || len(got.runs) != 2 {
			t.Fatal("parallel leased modules failed", got.err)
		}
		if _, err := os.Stat(filepath.Join(root, "core", "internal")); !os.IsNotExist(err) {
			t.Fatal("leased directories remained after joined modules", err)
		}
	})
}

type failingUnitOutput struct{}

func (failingUnitOutput) Write([]byte) (int, error) {
	return 0, errors.New("controlled output failure")
}

// Closed result channels also let cleanup establish the join after a test read.
type unitModuleOutcome struct {
	runs []unitPackageRun
	err  error
}

func waitUnitModuleJoin(t *testing.T, done <-chan unitModuleOutcome) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("module invocation did not join after cancellation")
	}
}

func awaitUnitModuleOutcome(t *testing.T, done <-chan unitModuleOutcome) unitModuleOutcome {
	t.Helper()
	select {
	case got := <-done:
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("module invocation did not return within its join bound")
	}
	return unitModuleOutcome{}
}

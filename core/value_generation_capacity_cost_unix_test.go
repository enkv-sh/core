//go:build darwin || linux

package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

type generatedCapacityCost struct {
	Operation        string `json:"operation"`
	Sample           int    `json:"sample"`
	CreateLineages   int    `json:"create_lineages"`
	Templates        int    `json:"templates"`
	ResultUses       int    `json:"result_uses"`
	WallNanoseconds  int64  `json:"wall_nanoseconds"`
	CPUNanoseconds   int64  `json:"cpu_nanoseconds"`
	AllocatedBytes   uint64 `json:"allocated_bytes"`
	Allocations      uint64 `json:"allocations"`
	CandidateObjects int    `json:"candidate_objects,omitempty"`
	CandidateBytes   uint64 `json:"candidate_body_bytes,omitempty"`
	Completed        bool   `json:"completed"`
}

func generatedCapacityEvidence(t *testing.T) func(string, any) error {
	t.Helper()
	directory := os.Getenv("ENKV_PERFORMANCE_EVIDENCE_DIRECTORY")
	retained := directory != ""
	if !retained {
		directory = t.TempDir()
	}
	info, err := os.Lstat(directory)
	if err != nil || !filepath.IsAbs(directory) || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("performance evidence requires an absolute private directory", err)
	}
	file, err := os.OpenFile(filepath.Join(directory, "generated-continuation-capacity.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("performance evidence file", err)
	}
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("performance evidence file is not private", errors.Join(err, file.Close()))
	}
	written := 0
	appendRecord := func(kind string, value any) error {
		body, err := json.Marshal(struct {
			Kind string `json:"kind"`
			Data any    `json:"data"`
		}{kind, value})
		if err != nil {
			return err
		}
		body = append(body, '\n')
		if len(body) > (1<<20)-written {
			return errors.New("performance evidence exceeds its bound")
		}
		n, writeErr := file.Write(body)
		written += n
		if n != len(body) && writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		return errors.Join(writeErr, file.Sync())
	}
	if err := appendRecord("capture_ready", map[string]any{"schema_version": 1, "test": t.Name(), "retained": retained,
		"goos": runtime.GOOS, "goarch": runtime.GOARCH, "go_version": runtime.Version()}); err != nil {
		t.Fatal("performance evidence header", errors.Join(err, file.Close()))
	}
	t.Cleanup(func() {
		footerErr := appendRecord("capture_complete", map[string]bool{"failed": t.Failed()})
		if err := errors.Join(footerErr, file.Close()); err != nil {
			t.Error("performance evidence completion", err)
		}
	})
	return appendRecord
}

func generatedCapacityProcessCPU(t *testing.T) time.Duration {
	t.Helper()
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		t.Fatal("process CPU measurement", err)
	}
	return time.Duration(usage.Utime.Sec+usage.Stime.Sec)*time.Second +
		time.Duration(int64(usage.Utime.Usec)+int64(usage.Stime.Usec))*time.Microsecond
}

func generatedCapacityCostFixture(t *testing.T, count int) (*StateSession, *generatedSelection) {
	t.Helper()
	names := make([]string, count)
	for i := range names {
		names[i] = fmt.Sprintf("generated-%03d", i)
	}
	before := generatedEmptyPredecessor(t)
	input := generatedReservationInputForGenerations(t, before, generatedVectorID(10), names)
	reservation, err := before.deriveGeneratedReservation(t.Context(), input)
	if err != nil {
		t.Fatal("capacity cost reservation", err)
	}
	selected := mustSelectedGeneratedWork(t, reservation.state)
	creates, templates := 0, 0
	for _, lineage := range selected.bundles[0].Lineages {
		if lineage.Purpose == contract.GeneratorLineageCreate {
			creates++
		}
		templates += int(lineage.TemplateCount)
	}
	if creates != count || templates != count*10 || len(selected.bundles[0].ResultUses) != count*10 || len(selected.attempts) != count {
		t.Fatalf("capacity cost shape differs: creates=%d templates=%d result_uses=%d entered=%d", creates, templates, len(selected.bundles[0].ResultUses), len(selected.attempts))
	}
	return reservation.state, selected
}

// full_only: true
func TestGeneratedSelectedContinuationCapacityCost(t *testing.T) {
	capture := generatedCapacityEvidence(t)
	t.Run("one-lineage-semantic", func(t *testing.T) {
		state, selected := generatedCapacityCostFixture(t, 1)
		read, err := selected.fragmentReader()
		if err != nil {
			t.Fatal(err)
		}
		continuationTestReadOnly(t, state, func() {
			bound, err := continuationCapacityFromSelected(t.Context(), selected.image, selected, read)
			if err != nil || bound.Remaining.Status != capacitySufficient || bound.Remaining.Scope != remainingSelectedContinuations || bound.FirstExit.Scope != firstAdministrativeExit {
				t.Fatal("one-lineage capacity semantics", bound, err)
			}
		})
	})
	t.Run("maximum-shape", func(t *testing.T) {
		state, selected := generatedCapacityCostFixture(t, 128)
		read, err := selected.fragmentReader()
		if err != nil {
			t.Fatal(err)
		}
		var reference selectedContinuationCapacity
		continuationTestReadOnly(t, state, func() {
			for sample := 1; sample <= 3; sample++ {
				runtime.GC()
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				cpu, started := generatedCapacityProcessCPU(t), time.Now()
				bound, callErr := continuationCapacityFromSelected(t.Context(), selected.image, selected, read)
				wall, usedCPU := time.Since(started), generatedCapacityProcessCPU(t)-cpu
				runtime.ReadMemStats(&after)
				measurement := generatedCapacityCost{Operation: "capacity", Sample: sample, CreateLineages: 128, Templates: 1280, ResultUses: 1280,
					WallNanoseconds: wall.Nanoseconds(), CPUNanoseconds: usedCPU.Nanoseconds(), AllocatedBytes: after.TotalAlloc - before.TotalAlloc,
					Allocations: after.Mallocs - before.Mallocs, Completed: callErr == nil}
				encoded, err := json.Marshal(measurement)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("capacity_measurement=%s", encoded)
				if err := capture("capacity_measurement", measurement); err != nil {
					t.Fatal("performance sample capture", err)
				}
				if callErr != nil {
					t.Errorf("capacity sample %d: %v", sample, callErr)
					continue
				}
				if bound.Remaining.Status != capacitySufficient || bound.Remaining.Scope != remainingSelectedContinuations || bound.FirstExit.Scope != firstAdministrativeExit {
					t.Error("maximum capacity semantics", bound)
				}
				if sample == 1 {
					reference = bound
					body, err := json.Marshal(bound)
					if err != nil {
						t.Fatal(err)
					}
					t.Logf("capacity_result=%s", body)
					if err := capture("capacity_result", bound); err != nil {
						t.Fatal("performance capacity result capture", err)
					}
				} else if bound != reference {
					t.Error("same selected image changed its capacity result")
				}
			}
		})
		if t.Failed() {
			return
		}
		cancelled, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := continuationCapacityFromSelected(cancelled, selected.image, selected, read); !errors.Is(err, context.Canceled) {
			t.Fatal("capacity lost original cancellation", err)
		}
		attempt := selected.attempts[selected.phase.FrontierAttemptID]
		result := generatedPublicResultFixture(t, attempt, contract.GeneratorDispositionCompleteCreate)
		admitted := generatedContinuationContext(t, state, 170, 171)
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		cpu, started := generatedCapacityProcessCPU(t), time.Now()
		plan, callErr := state.generatedRecordRequest(t.Context(), attempt.record.AttemptID, result, admitted)
		var recorded *generatedReservation
		if callErr == nil {
			recorded, callErr = state.deriveGeneratedRecord(t.Context(), plan)
		}
		wall, usedCPU := time.Since(started), generatedCapacityProcessCPU(t)-cpu
		runtime.ReadMemStats(&after)
		measurement := generatedCapacityCost{Operation: "record-construction", Sample: 1, CreateLineages: 128, Templates: 1280, ResultUses: 1280,
			WallNanoseconds: wall.Nanoseconds(), CPUNanoseconds: usedCPU.Nanoseconds(), AllocatedBytes: after.TotalAlloc - before.TotalAlloc,
			Allocations: after.Mallocs - before.Mallocs, Completed: callErr == nil}
		if recorded != nil && recorded.candidate != nil {
			measurement.CandidateObjects = len(recorded.candidate.objects)
			for _, object := range recorded.candidate.objects {
				measurement.CandidateBytes += uint64(len(object.body))
			}
		}
		body, err := json.Marshal(measurement)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("capacity_measurement=%s", body)
		if err := capture("capacity_measurement", measurement); err != nil {
			t.Fatal("performance Record capture", err)
		}
		if callErr != nil || recorded == nil || recorded.candidate == nil {
			t.Fatal("maximum Record construction", callErr)
		}
		continuationTestCandidateWithin(t, recorded.state, reference.Remaining)
		digest := fmt.Sprintf("%x", continuationTestSelectedDigest(t, recorded.state))
		t.Logf("record_selected_digest=%s", digest)
		if err := capture("record_selected_digest", digest); err != nil {
			t.Fatal("performance Record digest capture", err)
		}
	})
}

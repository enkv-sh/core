package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
)

type freshChildRetentionStop struct{}
type freshChildRetentionTB struct {
	testing.TB
	fatal      string
	errors     []string
	recordPath string
	saved      records.WorkerResult
	savedErr   error
}

func (t *freshChildRetentionTB) Fatal(args ...any) {
	t.fatal = fmt.Sprint(args...)
	t.savedErr = records.ReadJSON(t.recordPath, &t.saved)
	panic(freshChildRetentionStop{})
}
func (t *freshChildRetentionTB) Error(args ...any) {
	t.errors = append(t.errors, fmt.Sprint(args...))
	t.savedErr = records.ReadJSON(t.recordPath, &t.saved)
}

// full_only: false
func TestLiveFreshCallersRetainProcessBeforeLocalFailure(t *testing.T) {
	for _, route := range []string{"current", "generated-record"} {
		for _, condition := range []string{"canceled-before-start", "refused-input"} {
			t.Run(route+"/"+condition, func(t *testing.T) {
				inv, input := liveProtocolInvocation(t, "writer")
				if route == "generated-record" {
					const scenario = "generated.retirement-acknowledgement-closes/one_current_one_retiring_manual_ack"
					input.Scenarios = []string{scenario}
					input.Generator = &liveGeneratorSettings{}
					inv = liveProtocolBindInvocation(t, inv, scenario)
				}
				if condition == "refused-input" {
					input.Settings.Provider = "refused-provider"
				}
				if records.WriteJSON(inv.Input, input, 0400) != nil {
					t.Fatal("controlled writer input unavailable")
				}
				worker, err := records.NewWorker(inv, liveProvider(), inv.Scenario, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := worker.Finish(context.Background(), false); err != nil {
						t.Error(err)
					}
				}()
				env, _ := genesisEnvironment(t, liveFamily, false)
				selected := newEnvironmentFixture(t, t.Context(), env, nil, false).session
				budget := &runBudget{limits: input.Limits, keys: make(map[string]bool)}
				observed := &freshChildRetentionTB{TB: t, recordPath: filepath.Join(inv.OutputDir, "worker.json")}
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				if condition == "canceled-before-start" {
					cancel()
				}
				stopped := false
				func() {
					defer func() {
						if cause := recover(); cause != nil {
							if _, expected := cause.(freshChildRetentionStop); !expected {
								panic(cause)
							}
							stopped = true
						}
					}()
					if route == "current" {
						facts := freshFacts{Domain: selected.admission.domain, Prefix: input.Prefix, Expected: sessionStateImage(t, selected)}
						runLiveFreshCheck(observed, ctx, inv, input, worker, budget, 0, facts)
					} else {
						attempt := contract.Hash([]byte("fresh-child-retention/local-canceled-attempt"))
						runLiveGeneratedRecordCheck(observed, ctx, inv, input, worker, budget, nil, env, selected, attempt, []byte("unused-local-result"))
					}
				}()
				if route == "current" {
					if stopped || observed.fatal != "" || len(observed.errors) != 1 || observed.errors[0] != "fresh process evidence unavailable" {
						t.Fatalf("current caller stopped at the wrong boundary: fatal=%q errors=%q", observed.fatal, observed.errors)
					}
				} else if !stopped || !strings.HasPrefix(observed.fatal, "fresh generated record child failed") || !strings.Contains(observed.fatal, "fresh process evidence unavailable") || len(observed.errors) != 0 {
					t.Fatalf("generated caller stopped at the wrong boundary: fatal=%q errors=%q", observed.fatal, observed.errors)
				}
				saved := observed.saved
				if observed.savedErr != nil || len(saved.Children) != 1 {
					t.Fatal("caller lost its registered child before reporting failure")
				}
				want := records.FreshChildProcess{Joined: true, Outcome: "not_started"}
				if condition == "refused-input" {
					want = records.FreshChildProcess{Started: true, Joined: true, Outcome: "process_failed"}
				}
				if budget.snapshot() != (budgetReservation{}) {
					t.Fatal("local child refusal reserved remote effects")
				}
				if saved.Children[0].Process == nil || *saved.Children[0].Process != want {
					t.Fatalf("durable process fact before caller failure = %+v, want %+v", saved.Children[0].Process, want)
				}
				owner, _, _, err := records.PrivateOwner(inv.OutputDir)
				if err != nil {
					t.Fatal(err)
				}
				path, err := records.SafePath(owner, saved.Children[0].Invocation)
				if err != nil {
					t.Fatal(err)
				}
				child, err := records.LoadInvocation(path)
				if err != nil || child.Role != "fresh_before" {
					t.Fatal("retained child identity unavailable", err)
				}
				for _, name := range []string{"worker.json", "telemetry.json", "checkpoint.json"} {
					if _, err := os.Lstat(filepath.Join(child.OutputDir, name)); !os.IsNotExist(err) {
						t.Fatal("child entered beyond local input admission", name, err)
					}
				}
				marker := records.InspectAssertions(child, false).Marker
				wantMarker := "no_failure_marker"
				if condition == "refused-input" {
					wantMarker = "valid_failure_marker"
				}
				if marker != wantMarker {
					t.Fatalf("local child assertion marker = %s, want %s", marker, wantMarker)
				}
			})
		}
	}
}

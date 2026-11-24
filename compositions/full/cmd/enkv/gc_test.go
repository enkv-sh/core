package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestGCPlanDeliversOwnedRefusalAfterExecutionDeadline(t *testing.T) {
	for _, structured := range []bool{false, true} {
		t.Run(fmt.Sprintf("json-%t", structured), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
			defer cancel()
			var output, diagnostic bytes.Buffer
			args := []string{"plan", "--source=source.json", "--source-format=json", "--out=plan.bin"}
			if structured {
				args = append(args, "--json")
			}
			calls := 0
			var owned core.PublicQueryResult
			code := runGCWithExecutors(ctx, args, &output, &diagnostic, func(context.Context, compositionfull.GCPlanRequest, string, configuration.Format) compositionfull.GCPlanResult {
				calls++
				result, err := compositionfull.NewGCPlanRefusal(configuration.JSON)
				if err != nil {
					t.Fatal(err)
				}
				owned = result.Operation.PublicQueryResult
				<-ctx.Done()
				if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
					t.Fatal("execution deadline not established", ctx.Err())
				}
				return result
			}, nil)
			if calls != 1 || code != 2 {
				t.Error("GC plan lost its already-owned result or repeated execution", calls, code, diagnostic.String())
			}
			if structured {
				var got struct {
					Schema      string
					Operation   string `json:"operation_kind"`
					State       string `json:"state_result"`
					Reason      string `json:"failure_reason"`
					OperationID string `json:"operation_id"`
					Payload     json.RawMessage
				}
				if json.Unmarshal(output.Bytes(), &got) != nil || got.Schema != "ProductResult/v1" || got.Operation != core.GCPlanOperation || got.State != "refused" || got.Reason != "invalid-input" || got.OperationID != idText(owned.OperationID) || string(got.Payload) != "null" {
					t.Fatal("GC plan JSON lost its complete owned refusal", output.String())
				}
			} else {
				for _, fact := range []string{"GC plan: refused\n", "Reason: invalid-input\n", "Evidence ceiling: unavailable\n", "Operation id: \"" + idText(owned.OperationID) + "\"\n", "Plan file created: false\n", "Plan file synced: false\n", "Plan file read back: false\n", "Plan delivery failed: false\n", "Local source cleanup failed: false\n", "No query data is available.\n", "No remote objects were deleted.\n"} {
					if !strings.Contains(output.String(), fact) {
						t.Fatal("GC plan human refusal lost an owned fact", fact, output.String())
					}
				}
			}
			checkInterruptedCommandDiagnostics(t, diagnostic.String(), "admission_refused", "admission_refused")
		})
	}
}

// full_only: false
func TestAdministrativeGrammarRefusalDeliveryHasSeparateLifetime(t *testing.T) {
	for _, command := range []string{"abandon", "gc-plan", "gc-apply"} {
		t.Run(command, func(t *testing.T) {
			ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
			defer cancel()
			if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Fatal("expired dispatch context not established")
			}
			var output, diagnostic bytes.Buffer
			code := 0
			switch command {
			case "abandon":
				code = runAbandonWithExecutor(ctx, []string{"apply", "--json"}, &output, &diagnostic, nil)
			case "gc-plan":
				code = runGCWithExecutors(ctx, []string{"plan", "--json"}, &output, &diagnostic, nil, nil)
			case "gc-apply":
				code = runGCWithExecutors(ctx, []string{"apply", "--json"}, &output, &diagnostic, nil, nil)
			}
			if code != 2 || !json.Valid(output.Bytes()) || !bytes.Contains(output.Bytes(), []byte(`"state_result": "refused"`)) || diagnostic.Len() != 0 {
				t.Error("execution expiry hid the closed grammar refusal", code, diagnostic.String())
			}
		})
	}
}

// full_only: false
func TestGCDeliversOwnedUnknownResultAfterExecutionCancellation(t *testing.T) {
	for _, structured := range []bool{false, true} {
		for _, interruption := range []string{"cancel", "deadline"} {
			for _, sink := range []string{"complete", "short", "failed"} {
				t.Run(fmt.Sprintf("json-%t/%s/%s", structured, interruption, sink), func(t *testing.T) {
					ctx, cancel := context.WithCancel(t.Context())
					if interruption == "deadline" {
						cancel()
						ctx, cancel = context.WithTimeout(t.Context(), time.Millisecond)
					}
					defer cancel()
					var output, diagnostic bytes.Buffer
					var out io.Writer = &output
					if sink != "complete" {
						out = commandWriterFunc(func(b []byte) (int, error) {
							if sink == "short" {
								return len(b) - 1, nil
							}
							return 0, errors.New("controlled result delivery failure")
						})
					}
					calls := 0
					args := []string{"apply", "--source=source.json", "--source-format=json", "--operation=02" + strings.Repeat("00", 31)}
					if structured {
						args = append(args, "--json")
					}
					code := runGCWithExecutors(ctx, args, out, &diagnostic, nil, func(_ context.Context, request compositionfull.GCApplyRequest, _ string, _ configuration.Format) compositionfull.GCApplyResult {
						calls++
						if interruption == "deadline" {
							<-ctx.Done()
							if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
								t.Fatal("execution deadline did not expire", ctx.Err())
							}
						} else {
							cancel()
						}
						plan := contract.ID{4}
						identity := contract.Hash(append([]byte("ENKV/GC-REQUEST/v1\x00"), plan[:]...))
						object := contract.StoreObjectIdentity{Namespace: contract.StorePageObject, Kind: contract.RootKind, ObjectID: contract.ID{11}}
						target := contract.GCTarget{Object: object, Length: 123, Digest: contract.ID{12}, Token: contract.Token{Family: contract.AWS, Value: `"initial"`}}
						targets, err := contract.GCTargetsDescriptor([]contract.GCTarget{target})
						if err != nil {
							t.Fatal(err)
						}
						r := core.PublicGCResult{Operation: core.GCApplyOperation, RequestID: request.RequestNonce, OperationID: request.OperationID, DomainID: contract.ID{3}, RequestIdentity: identity,
							Result: core.Result{Outcome: core.UnresolvedCommit, Reason: core.WriteUncertain, RequestedRevision: contract.ID{5}, CommitMayHaveOccurred: true},
							Payload: &core.GCCleanupPayload{PlanDigest: plan, RequestIdentity: identity, MarkDigest: contract.ID{6}, EnumerationDigest: contract.ID{7}, TargetsDescriptor: targets, SelectionUncertain: true, RemainingCount: 1,
								Targets:     []core.GCTargetResult{{Object: object, Length: target.Length, Digest: target.Digest, Selected: contract.GCTargetProgress{Disposition: contract.GCTargetPending}}},
								Candidates:  []contract.GCCandidate{{KeyDigest: contract.ID{13}, Classification: contract.GCCandidateEligible}},
								Observation: core.PublicObservation{DomainID: contract.ID{3}, HeadRevisionID: contract.ID{8}, SnapshotID: contract.ID{9}, RootDigest: contract.ID{10}}}}
						if err := core.RefreshGCResult(&r); err != nil {
							t.Fatal("invalid owned unknown result", err)
						}
						return compositionfull.GCApplyResult{Operation: r}
					})
					if calls != 1 {
						t.Fatal("delivery repeated Product work", calls)
					}
					if sink != "complete" {
						if code != 2 || !strings.Contains(diagnostic.String(), "delivery failed") {
							t.Error("output failure was hidden", code)
						}
						return
					}
					var got struct {
						State     string `json:"state_result"`
						Operation string `json:"operation_id"`
						Result    struct {
							Commit    bool   `json:"commit_may_have_occurred"`
							Requested string `json:"requested_revision_id"`
						} `json:"result"`
					}
					if structured {
						if code != 3 || json.Unmarshal(output.Bytes(), &got) != nil || got.State != "commit-outcome-unknown" || got.Operation != "02"+strings.Repeat("00", 31) || !got.Result.Commit || got.Result.Requested != "05"+strings.Repeat("00", 31) {
							t.Error("execution interruption hid the owned possible-CAS result", code, got)
						}
					} else if code != 3 || !strings.HasPrefix(output.String(), "gc-apply: commit-outcome-unknown\n") || !strings.Contains(output.String(), "Operation: 02"+strings.Repeat("00", 31)+".\n") || !strings.Contains(output.String(), "commit may have occurred") || !strings.Contains(output.String(), "Requested revision: 05"+strings.Repeat("00", 31)+".\n") {
						t.Error("human result lost unknown commit and exact observation identity", code, output.String())
					}
					checkInterruptedCommandDiagnostics(t, diagnostic.String(), "unresolved_commit", "uncertain")
				})
			}
		}
	}
}

// full_only: false
func TestGCGrammarRejectsAmbiguousInputsBeforeExecutors(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	for _, form := range []string{"plan", "apply"} {
		base := []string{form, "--source=source.json", "--source-format=json", "--json"}
		suffixes := [][]string{nil, {"extra"}, {"--unknown=private-sentinel"}, {"--out="}, {"--plan="}, {"--operation=" + strings.Repeat("00", 32)}, {"--plan=plan.bin", "--operation=" + strings.Repeat("01", 32)}, {"--out=source.json"}, {"--plan=source.json"}}
		if form == "plan" {
			suffixes = append(suffixes, []string{"--out=plan.bin", "--cursor="}, []string{"--out=plan.bin", "--cursor=" + strings.Repeat("x", core.GCCursorMaxLength+1)}, []string{"--out=a", "--out=b"})
		} else {
			suffixes = append(suffixes, []string{"--operation=" + strings.Repeat("01", 32), "--cursor=page"}, []string{"--plan=a", "--plan=b"})
		}
		for _, suffix := range suffixes {
			calls := 0
			plan := func(context.Context, compositionfull.GCPlanRequest, string, configuration.Format) compositionfull.GCPlanResult {
				calls++
				return compositionfull.GCPlanResult{}
			}
			apply := func(context.Context, compositionfull.GCApplyRequest, string, configuration.Format) compositionfull.GCApplyResult {
				calls++
				return compositionfull.GCApplyResult{}
			}
			var out, diagnostic bytes.Buffer
			code := runGCWithExecutors(ctx, append(append([]string{}, base...), suffix...), &out, &diagnostic, plan, apply)
			if code != 2 || calls != 0 || !json.Valid(out.Bytes()) || bytes.Contains(out.Bytes(), []byte("private-sentinel")) {
				t.Fatal("invalid GC grammar crossed public boundary", form, suffix, code, calls, out.String())
			}
		}
	}
}

// full_only: false
func TestGCCommandsPassExactPlanAndContinuationRequests(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	for _, form := range []string{"plan", "artifact", "operation"} {
		calls := 0
		var out, diagnostic bytes.Buffer
		plan := func(_ context.Context, r compositionfull.GCPlanRequest, path string, format configuration.Format) compositionfull.GCPlanResult {
			calls++
			want, _ := filepath.Abs("plan.bin")
			source, _ := filepath.Abs("source.json")
			if form != "plan" || r.RequestNonce.IsZero() || r.OperationID.IsZero() || r.Cursor != "bounded-wrapper" || r.ArtifactPath != want || path != source || format != configuration.JSON {
				t.Fatal("plan request changed", r, path, format)
			}
			v, err := compositionfull.NewGCPlanRefusal(format)
			if err != nil {
				t.Fatal(err)
			}
			return v
		}
		apply := func(_ context.Context, r compositionfull.GCApplyRequest, path string, format configuration.Format) compositionfull.GCApplyResult {
			calls++
			want, _ := filepath.Abs("plan.bin")
			source, _ := filepath.Abs("source.json")
			if r.RequestNonce.IsZero() || path != source || format != configuration.JSON || form == "artifact" && (r.PlanPath != want || !r.OperationID.IsZero()) || form == "operation" && (r.PlanPath != "" || r.OperationID != (contract.ID{1})) {
				t.Fatal("apply request changed", r, path, format)
			}
			v, err := compositionfull.NewGCApplyRefusal(format)
			if err != nil {
				t.Fatal(err)
			}
			return v
		}
		args := []string{"apply", "--source=source.json", "--source-format=json", "--json"}
		switch form {
		case "plan":
			args[0] = "plan"
			args = append(args, "--out=plan.bin", "--cursor=bounded-wrapper")
		case "artifact":
			args = append(args, "--plan=plan.bin")
		default:
			args = append(args, "--operation=01"+strings.Repeat("00", 31))
		}
		code := runGCWithExecutors(ctx, args, &out, &diagnostic, plan, apply)
		if code != 2 || calls != 1 || !json.Valid(out.Bytes()) {
			t.Fatal("GC exact typed dispatch failed", form, code, calls, out.String(), diagnostic.String())
		}
	}
	for _, args := range [][]string{{"gc"}, {"gc", "plan", "--help"}, {"gc", "apply", "--help"}} {
		var out, diagnostic bytes.Buffer
		if run(args, &out, &diagnostic) != 0 || !bytes.Contains(out.Bytes(), []byte("--operation ID")) {
			t.Fatal("GC dispatch/help missing", args)
		}
	}
}

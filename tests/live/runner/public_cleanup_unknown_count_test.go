package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestPublicOwnedPrefixCleanupRetainsObservedEffectCounts(t *testing.T) {
	for _, condition := range []string{"delete-budget-refused", "delete-reply-lost", "invalid-inventory", "passed"} {
		t.Run(condition, func(t *testing.T) {
			inv, input := liveProtocolInvocation(t, "cleanup")
			const scenario = "public-configuration.empty-initialization/empty_initialization"
			input.Scenarios = []string{scenario}
			inv = liveProtocolBindInvocation(t, inv, scenario)
			worker, err := records.NewWorker(inv, liveProvider(), scenario, nil)
			if err != nil {
				t.Fatal(err)
			}
			unknown := int64(0)
			worker.Result.Actor = "cleanup"
			worker.Result.Cleanup = &records.Cleanup{Outcome: "unresolved", UnknownEffects: &unknown}
			budget := &runBudget{limits: input.Limits, keys: map[string]bool{}}
			if condition == "delete-budget-refused" {
				// LIST, adoption read and conditional-ownership read each reserve two requests.
				budget.limits.Requests = 6
			}
			stopped := &publicGeneratedCleanupTB{TB: t}
			domain := contract.Hash([]byte(input.Prefix))
			family := contract.AWS
			if liveProvider() == "gcp" {
				family = contract.GCP
			}
			store := &memoryStore{desc: contract.Descriptor{Prefix: input.Prefix}, objects: map[string]stored{}}
			store.configure(t, family, domain)
			key, body := input.Prefix+"/HEAD", []byte("owned")
			if condition == "invalid-inventory" {
				body = nil
			}
			if store.Create(t.Context(), key, body).Status != contract.WriteAcknowledged {
				t.Fatal("controlled cleanup object unavailable")
			}
			token := store.objects[key].Token
			lists, deletes, completions := 0, 0, 0
			cleaner := &livePrefixCleaner{Store: store, ValidKey: func(got string) bool { return got == key },
				List: func(_ context.Context, prefix, continuation string) (livePrefixPage, error) {
					lists++
					if prefix != input.Prefix+"/" || continuation != "" {
						t.Fatal("cleanup changed its exact LIST scope")
					}
					if _, exists := store.objects[key]; exists {
						return livePrefixPage{Keys: []string{key}}, nil
					}
					return livePrefixPage{}, nil
				},
				Delete: func(ctx context.Context, got string, gotToken contract.Token) error {
					deletes++
					if got != key || gotToken != token {
						t.Fatal("cleanup changed its exact conditional target")
					}
					if err := testDelete(store)(ctx, got, gotToken); err != nil {
						t.Fatal(err)
					}
					if condition == "delete-reply-lost" {
						return inventoryControlledTransportError{}
					}
					return nil
				}}
			sum := sha256.Sum256([]byte(key))
			func() {
				defer finishLiveWorker(stopped, worker, budget)
				defer func() {
					if recovered := recover(); recovered != nil {
						if _, expected := recovered.(publicGeneratedCleanupStop); !expected {
							panic(recovered)
						}
					}
				}()
				publicCleanupOwnedPrefix(stopped, t.Context(), inv, input, budget, worker, cleaner,
					map[string]bool{hex.EncodeToString(sum[:]): true}, unknown, domain, true, func() error { completions++; return nil })
			}()
			var retained records.WorkerResult
			if records.ReadJSON(filepath.Join(inv.OutputDir, "worker.json"), &retained) != nil || retained.RunID != inv.RunID || retained.Cleanup == nil {
				t.Fatal("cleanup worker result unavailable")
			}
			passed := condition == "passed"
			if (retained.Outcome == "passed") != passed || (retained.Cleanup.Outcome == "passed") != passed || stopped.stopped == passed {
				t.Fatal("unsettled cleanup acquired success")
			}
			if !passed && (retained.Outcome != "failed" || retained.Cleanup.Outcome != "unresolved" || retained.Cleanup.Failure == nil || stopped.message != "public cleanup conditional deletion unresolved") {
				t.Fatal("cleanup failure lost its unresolved terminal result")
			}
			wantDeletes, wantLists, wantCompletions := 1, 1, 0
			if passed {
				wantLists, wantCompletions = 2, 1
			}
			if condition == "delete-budget-refused" {
				wantDeletes = 0
			}
			if condition == "invalid-inventory" {
				wantDeletes = 0
				if retained.Cleanup.UnknownEffects != nil || retained.Cleanup.RemainingOwnedObjects != nil {
					t.Fatal("invalid inventory was reported as a known count")
				}
			} else {
				want := int64(1)
				wantUnknown, wantOwned := want, want
				if passed {
					wantUnknown, wantOwned = 0, 0
				} else if condition == "delete-budget-refused" {
					wantUnknown = 0
				}
				if retained.Cleanup.UnknownEffects == nil || retained.Cleanup.RemainingOwnedObjects == nil {
					t.Fatal("valid cleanup counts are unavailable")
				}
				if *retained.Cleanup.UnknownEffects != wantUnknown {
					t.Fatalf("retained unknown effects = %d, want %d", *retained.Cleanup.UnknownEffects, wantUnknown)
				}
				if *retained.Cleanup.RemainingOwnedObjects != wantOwned {
					t.Fatalf("retained owned objects = %d, want %d", *retained.Cleanup.RemainingOwnedObjects, wantOwned)
				}
			}
			if lists != wantLists || deletes != wantDeletes || completions != wantCompletions || unknown != 0 {
				t.Fatal("cleanup repeated effects, completed early, or changed the caller's count")
			}
		})
	}
}

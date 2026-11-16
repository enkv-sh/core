package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/crypto/testsupport/installedarchive"
	"enkv.sh/telemetry"
)

func testInventory(t *testing.T) (*objectInventory, *memoryStore) {
	t.Helper()
	f := newFixture(t, 1, false, 1)
	i := &objectInventory{path: filepath.Join(liveTestDirectory(t), "inventory.json"), image: inventoryImage{
		Version: 1, RunID: "test", Binding: "binding", Prefix: f.store.desc.Prefix,
		Deleted: make(map[string]int),
	}}
	return i, f.store
}

// full_only: false
func TestInventoryLeaseRequiresExclusiveAccess(t *testing.T) {
	directory := liveTestDirectory(t)
	first, err := lockInventory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := lockInventory(directory); err == nil {
		second.Close()
		t.Fatal("active inventory admitted another writer or cleanup")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := lockInventory(directory)
	if err != nil {
		t.Fatal("released inventory remained unavailable")
	}
	third.Close()
}

type inventoryControlledDeleteError struct{}

func (inventoryControlledDeleteError) Error() string { return "controlled delete failure" }

func (inventoryControlledDeleteError) SafeHarnessFailure() records.HarnessFailure {
	status := uint16(503)
	return records.HarnessFailure{Operation: "object_cleanup", Stage: "conditional_delete", Cause: "provider_refused",
		Effect: "unknown", HTTPStatus: &status, EnvelopeStatus: &status, Attempt: 1}
}

type inventoryControlledTransportError struct{}

func (inventoryControlledTransportError) Error() string { return "controlled transport failure" }

func (inventoryControlledTransportError) SafeHarnessFailure() records.HarnessFailure {
	return records.HarnessFailure{Operation: "object_cleanup", Stage: "conditional_delete", Cause: "transport",
		Effect: "unknown", Attempt: 1}
}

// full_only: false
func TestCleanupRecoveryRequiresTypedTransientGCPCause(t *testing.T) {
	status429, status503, status403 := uint16(429), uint16(503), uint16(403)
	for _, test := range []struct {
		name, stage, cause string
		status, envelope   *uint16
		allowed            bool
	}{
		{"transport", "conditional_delete", "transport", nil, nil, true},
		{"missing_response", "conditional_delete", "missing_response", nil, nil, true},
		{"deadline", "conditional_delete", "deadline", nil, nil, true},
		{"early_eof", "response_intake", "early_eof", &status503, nil, true},
		{"throttled", "conditional_delete", "provider_refused", &status429, &status429, true},
		{"unavailable", "conditional_delete", "provider_refused", &status503, &status503, true},
		{"access_refused", "conditional_delete", "access_refused", &status403, &status403, false},
		{"unmatched_envelope", "conditional_delete", "provider_refused", &status503, &status429, false},
		{"invalid_acknowledgement", "acknowledgement", "invalid_acknowledgement", &status503, nil, false},
		{"wrong_stage", "ownership_read", "transport", nil, nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			failure := records.HarnessFailure{Operation: "object_cleanup", Stage: test.stage, Cause: test.cause,
				Effect: "unknown", HTTPStatus: test.status, EnvelopeStatus: test.envelope, Attempt: 1}
			if got := transientConditionalDelete(&failure); got != test.allowed {
				t.Fatal("private retry gate changed eligibility", got, test.allowed)
			}
		})
	}
}

func failedCleanupInventory(t *testing.T, afterEffect bool) (*objectInventory, *memoryStore, string, []byte) {
	t.Helper()
	ctx := context.Background()
	inventory, store := testInventory(t)
	key, body := inventory.image.Prefix+"/recover", []byte("owned")
	if result := inventory.write(ctx, key, body, "create", func() contract.WriteResult { return store.Create(ctx, key, body) }); result.Status != contract.WriteAcknowledged {
		t.Fatal("controlled object was not owned")
	}
	inventory.stop()
	var sends int
	err := inventory.cleanup(ctx, store, func(ctx context.Context, key string, token contract.Token) error {
		sends++
		if afterEffect {
			if err := testDelete(store)(ctx, key, token); err != nil {
				t.Fatal(err)
			}
			return inventoryControlledTransportError{}
		}
		return inventoryControlledDeleteError{}
	})
	if err == nil || sends != 1 || len(inventory.image.CleanupAttempts) != 1 ||
		inventory.image.CleanupAttempts[0].State != "failed" || inventory.image.CleanupAttempts[0].Ordinal != 1 {
		t.Fatal("controlled original failure was not retained", err, sends)
	}
	return inventory, store, key, body
}

// full_only: false
func TestCleanupRecoveryRetriesOnlyEligibleExactTarget(t *testing.T) {
	for _, afterEffect := range []bool{false, true} {
		name := "fail_before_effect"
		if afterEffect {
			name = "lost_reply_after_effect"
		}
		t.Run(name, func(t *testing.T) {
			inventory, store, key, _ := failedCleanupInventory(t, afterEffect)
			original := *inventory.image.CleanupAttempts[0].Failure
			var sends int
			deleteOnce := testDelete(store)
			err := inventory.recoverCleanup(context.Background(), store, func(ctx context.Context, gotKey string, token contract.Token) error {
				sends++
				if gotKey != key || token != inventory.image.CleanupAttempts[0].Token ||
					len(inventory.image.CleanupAttempts) != 2 || inventory.image.CleanupAttempts[1].State != "pending" ||
					inventory.image.CleanupAttempts[1].Ordinal != 2 ||
					inventory.image.CleanupAttempts[1].Recovery != "gcp_exact_generation" {
					t.Fatal("recovery did not use the durable exact target")
				}
				var saved inventoryImage
				if readPrivateJSON(inventory.path, &saved) != nil || len(saved.CleanupAttempts) != 2 || saved.CleanupAttempts[1].State != "pending" {
					t.Fatal("second attempt was not durable before delete")
				}
				return deleteOnce(ctx, gotKey, token)
			}, 0, 2)
			wantSends, wantAttempts := 1, 2
			if afterEffect {
				wantSends, wantAttempts = 0, 1
			}
			if err != nil || sends != wantSends || len(inventory.image.CleanupAttempts) != wantAttempts ||
				inventory.image.Deleted[key] != len(inventory.image.Intents) ||
				inventory.image.CleanupAttempts[0].Failure == nil || *inventory.image.CleanupAttempts[0].Failure != original {
				t.Fatal("qualified recovery changed the original failure or delete count", err, sends)
			}
			for _, attempt := range inventory.image.CleanupAttempts {
				if attempt.State != "settled" {
					t.Fatal("qualified missing did not settle a prior unknown effect")
				}
			}
			if unknown, err := inventory.image.unknownEffects(); err != nil || unknown != 0 || store.Read(context.Background(), key, 5).Status != contract.ReadMissing {
				t.Fatal("qualified recovery left unresolved residue", unknown, err)
			}
		})
	}
	t.Run("continues_other_owned_items", func(t *testing.T) {
		ctx := context.Background()
		inventory, store := testInventory(t)
		for _, suffix := range []string{"/a", "/z"} {
			key := inventory.image.Prefix + suffix
			body := []byte(suffix)
			if result := inventory.write(ctx, key, body, "create", func() contract.WriteResult { return store.Create(ctx, key, body) }); result.Status != contract.WriteAcknowledged {
				t.Fatal("controlled object was not owned")
			}
		}
		inventory.stop()
		first := inventory.image.Prefix + "/a"
		var sends []string
		if err := inventory.cleanup(ctx, store, func(_ context.Context, key string, _ contract.Token) error {
			sends = append(sends, key)
			return inventoryControlledDeleteError{}
		}); err == nil || len(sends) != 1 || sends[0] != first {
			t.Fatal("initial failure did not stop at the first exact target")
		}
		remove := testDelete(store)
		if err := inventory.recoverCleanup(ctx, store, func(ctx context.Context, key string, token contract.Token) error {
			sends = append(sends, key)
			return remove(ctx, key, token)
		}, 0, 2); err != nil {
			t.Fatal("qualified first target was not recovered", err)
		}
		if err := inventory.cleanup(ctx, store, func(ctx context.Context, key string, token contract.Token) error {
			sends = append(sends, key)
			return remove(ctx, key, token)
		}); err != nil {
			t.Fatal("other owned item was not cleaned", err)
		}
		owned, err := inventory.owned(true)
		unknown, unknownErr := inventory.image.unknownEffects()
		if err != nil || unknownErr != nil || len(owned) != 0 || unknown != 0 || len(sends) != 3 ||
			sends[0] != first || sends[1] != first || sends[2] != inventory.image.Prefix+"/z" ||
			inventory.image.CleanupAttempts[0].Failure == nil {
			t.Fatal("cleanup did not retain failure and settle all owned items", sends, err, unknownErr)
		}
	})
}

// full_only: false
func TestCleanupRecoveryRejectsChangedGenerationAndGenericReplay(t *testing.T) {
	inventory, store, key, body := failedCleanupInventory(t, false)
	store.mu.Lock()
	store.put(key, body)
	store.mu.Unlock()
	var sends int
	remove := func(context.Context, string, contract.Token) error { sends++; return nil }
	if inventory.cleanup(context.Background(), store, remove) == nil ||
		inventory.recoverCleanup(context.Background(), store, remove, 0, 2) == nil || sends != 0 ||
		len(inventory.image.CleanupAttempts) != 1 {
		t.Fatal("new generation or generic cleanup replay sent a delete", sends)
	}
}

// full_only: false
func TestCleanupRecoveryStopsAfterThirdFailedAttempt(t *testing.T) {
	inventory, store, _, _ := failedCleanupInventory(t, false)
	var sends int
	for _, ordinal := range []uint8{2, 3} {
		err := inventory.recoverCleanup(context.Background(), store, func(context.Context, string, contract.Token) error {
			sends++
			return inventoryControlledDeleteError{}
		}, 0, ordinal)
		if err == nil || len(inventory.image.CleanupAttempts) != int(ordinal) ||
			inventory.image.CleanupAttempts[ordinal-1].Ordinal != ordinal ||
			inventory.image.CleanupAttempts[ordinal-1].Failure.Attempt != ordinal {
			t.Fatal("failed recovery attempt or ordinal was not retained", ordinal, err)
		}
	}
	if inventory.recoverCleanup(context.Background(), store, func(context.Context, string, contract.Token) error {
		sends++
		return nil
	}, 0, 4) == nil || sends != 2 {
		t.Fatal("exhausted recovery sent a fourth delete", sends)
	}
	if unknown, err := inventory.image.unknownEffects(); err != nil || unknown != 3 {
		t.Fatal("failed physical attempts were falsely settled", unknown, err)
	}
}

// full_only: false
func TestCleanupRecoveryRejectsCorruptOrUnprovedRecord(t *testing.T) {
	for _, change := range []string{"pending_terminal", "changed_token", "bad_cutoff", "unsettled_writer", "permanent_cause"} {
		t.Run(change, func(t *testing.T) {
			inventory, store, _, _ := failedCleanupInventory(t, false)
			switch change {
			case "pending_terminal":
				inventory.image.CleanupAttempts[0].State = "pending"
			case "changed_token":
				inventory.image.CleanupAttempts[0].Token.Value = "99"
			case "bad_cutoff":
				inventory.image.CleanupAttempts[0].Cutoff = 1
			case "unsettled_writer":
				inventory.image.Intents[0].State = "unknown"
			case "permanent_cause":
				status := uint16(403)
				inventory.image.CleanupAttempts[0].Failure.HTTPStatus = &status
				inventory.image.CleanupAttempts[0].Failure.Cause = "access_refused"
			}
			if err := inventory.save(); err != nil {
				t.Fatal(err)
			}
			var sends int
			if inventory.recoverCleanup(context.Background(), store, func(context.Context, string, contract.Token) error {
				sends++
				return nil
			}, 0, 2) == nil || sends != 0 {
				t.Fatal("corrupt or unproved record authorized delete", change)
			}
		})
	}
}

// full_only: false
func TestSetupCallRetainsClosedFailureDiagnostics(t *testing.T) {
	recorder := telemetry.NewRecorder()
	ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
	finishSetupCall(telemetry.Start(ctx, telemetry.ProviderGCP, telemetry.OpSetupDelete), inventoryControlledDeleteError{})
	entries := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 2))
	if len(entries) != 2 || entries[0].Event != telemetry.DiagnosticStart || entries[1].Event != telemetry.DiagnosticReturn ||
		entries[1].Result != telemetry.ResultFailure || entries[1].Reason != telemetry.DiagnosticReasonUncertain ||
		entries[1].ErrorClass != telemetry.DiagnosticReasonEvidenceUnavailable || entries[1].HTTPStatus != 503 ||
		entries[1].ErrorDetail != "" || entries[1].ErrorDetailStatus != "unavailable" || entries[1].Validate() != nil {
		t.Fatal("setup diagnostic lost the closed cause or admitted private text", entries)
	}
	finishSetupCall(telemetry.Start(context.Background(), telemetry.ProviderGCP, telemetry.OpSetupDelete), inventoryControlledDeleteError{})
}

// full_only: false
func TestInventoryRetainsCleanupFailureStage(t *testing.T) {
	ctx := context.Background()
	inventory, store := testInventory(t)
	key, body := inventory.image.Prefix+"/failed-cleanup", []byte("owned")
	if result := inventory.write(ctx, key, body, "create", func() contract.WriteResult { return store.Create(ctx, key, body) }); result.Status != contract.WriteAcknowledged {
		t.Fatal("controlled object was not owned")
	}
	inventory.stop()
	var sends int
	err := inventory.cleanup(ctx, store, func(_ context.Context, observedKey string, token contract.Token) error {
		var saved inventoryImage
		if readPrivateJSON(inventory.path, &saved) != nil || len(saved.CleanupAttempts) != 1 ||
			saved.CleanupAttempts[0].State != "pending" || saved.CleanupAttempts[0].Key != observedKey ||
			saved.CleanupAttempts[0].Token != token || saved.CleanupAttempts[0].Digest != bodyDigest(body) ||
			saved.CleanupAttempts[0].Failure != nil {
			t.Fatal("exact delete attempt was not durable before the send")
		}
		sends++
		return inventoryControlledDeleteError{}
	})
	var provider inventoryControlledDeleteError
	if !errors.As(err, &provider) || sends != 1 {
		t.Fatal("inventory erased the exact one-send provider cause", err, sends)
	}
	var saved inventoryImage
	if readPrivateJSON(inventory.path, &saved) != nil || len(saved.CleanupAttempts) != 1 ||
		saved.CleanupAttempts[0].State != "failed" || saved.CleanupAttempts[0].Failure == nil ||
		saved.CleanupAttempts[0].Failure.Cause != "provider_refused" || saved.CleanupAttempts[0].Failure.HTTPStatus == nil ||
		*saved.CleanupAttempts[0].Failure.HTTPStatus != 503 || saved.CleanupAttempts[0].Failure.TargetKind != "inventory" ||
		saved.CleanupAttempts[0].Failure.TargetIndex == nil || *saved.CleanupAttempts[0].Failure.TargetIndex != uint32(saved.CleanupAttempts[0].TargetIntent) {
		t.Fatal("exact failure stage was not retained in the private inventory")
	}
	if unknown, err := saved.unknownEffects(); err != nil || unknown != 1 {
		t.Fatal("unknown delete effect was settled", unknown, err)
	}
}

// full_only: false
func TestInventoryCleanupPersistenceFailureKeepsEffectUnresolved(t *testing.T) {
	for _, boundary := range []string{"before_delete", "after_delete"} {
		t.Run(boundary, func(t *testing.T) {
			ctx := context.Background()
			inventory, store := testInventory(t)
			key, body := inventory.image.Prefix+"/persistence-fault", []byte("owned")
			if result := inventory.write(ctx, key, body, "create", func() contract.WriteResult { return store.Create(ctx, key, body) }); result.Status != contract.WriteAcknowledged {
				t.Fatal("controlled object was not owned")
			}
			inventory.stop()
			retained := inventory.path + ".retained"
			breakSave := func() {
				if os.Rename(inventory.path, retained) != nil || os.Mkdir(inventory.path, 0o700) != nil {
					t.Fatal("cleanup persistence fault unavailable")
				}
			}
			if boundary == "before_delete" {
				breakSave()
			}
			var sends int
			err := inventory.cleanup(ctx, store, func(ctx context.Context, key string, token contract.Token) error {
				sends++
				if err := testDelete(store)(ctx, key, token); err != nil {
					return err
				}
				breakSave()
				return nil
			})
			var failure *inventoryCleanupFailure
			if !errors.As(err, &failure) || failure.facts.Stage != "persistence" || failure.facts.Cause != "persistence_failed" {
				t.Fatal("cleanup persistence cause was erased", err)
			}
			wantSends, wantEffect, wantUnknown := 1, "unknown", int64(1)
			if boundary == "before_delete" {
				wantSends, wantEffect, wantUnknown = 0, "no_send", 0
			}
			if sends != wantSends || failure.facts.Effect != wantEffect {
				t.Fatal("persistence failure changed delete effect", sends, failure.facts)
			}
			var saved inventoryImage
			if readPrivateJSON(retained, &saved) != nil {
				t.Fatal("last durable inventory record unavailable")
			}
			if unknown, err := saved.unknownEffects(); err != nil || unknown != wantUnknown {
				t.Fatal("missing terminal record falsely settled delete", unknown, err)
			}
		})
	}
}

// full_only: false
func TestInventoryCleanupBudgetRefusalIsNoSend(t *testing.T) {
	ctx := context.Background()
	inventory, store := testInventory(t)
	key, body := inventory.image.Prefix+"/budget-refusal", []byte("owned")
	if result := inventory.write(ctx, key, body, "create", func() contract.WriteResult { return store.Create(ctx, key, body) }); result.Status != contract.WriteAcknowledged {
		t.Fatal("controlled object was not owned")
	}
	inventory.stop()
	err := inventory.cleanup(ctx, store, func(context.Context, string, contract.Token) error { return errRunLimit })
	var failure *inventoryCleanupFailure
	if !errors.As(err, &failure) || failure.facts.Stage != "admission" || failure.facts.Cause != "budget_exhausted" ||
		failure.facts.Effect != "no_send" || failure.facts.Attempt != 0 {
		t.Fatal("proved budget refusal became an unknown send", err)
	}
	var saved inventoryImage
	if readPrivateJSON(inventory.path, &saved) != nil || len(saved.CleanupAttempts) != 1 || saved.CleanupAttempts[0].State != "failed" {
		t.Fatal("budget refusal lost its durable attempt")
	}
	if unknown, err := saved.unknownEffects(); err != nil || unknown != 0 || store.Read(ctx, key, uint32(len(body))).Status != contract.ReadOK {
		t.Fatal("no-send budget refusal changed object effect", unknown, err)
	}
}

// full_only: false
func TestInventoryKnownBeforeSendFailureDoesNotBlockOwnedCleanup(t *testing.T) {
	ctx := context.Background()
	inventory, store := testInventory(t)
	key := store.desc.Prefix + "/known-not-sent"
	result := inventory.write(ctx, key, []byte("never entered"), "create", func() contract.WriteResult {
		return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport, NotSent: true}
	})
	if result.Status != contract.WriteUnknown || !result.NotSent {
		t.Fatal("before-send evidence lost")
	}
	if unknown, err := inventory.image.unknownEffects(); err != nil || unknown != 0 {
		t.Fatal("known before-send call became an unknown effect", unknown, err)
	}
	owned, err := inventory.owned(false)
	if err != nil || len(owned) != 0 {
		t.Fatal("known before-send call blocked owned cleanup", err)
	}
}

// full_only: false
func TestInventorySettlesOnlyUniqueUnknownImmutableCreateWithExactReadback(t *testing.T) {
	for _, mode := range []string{"acknowledged_retry", "exact_readback", "different_readback", "duplicate_unknown"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			inventory, store := testInventory(t)
			key, body := inventory.image.Prefix+"/unknown", []byte("owned")
			send := func() contract.WriteResult {
				if mode == "exact_readback" || mode == "duplicate_unknown" {
					if result := store.Create(ctx, key, body); result.Status != contract.WriteAcknowledged {
						t.Fatal("controlled create was not accepted")
					}
				}
				return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
			}
			if result := inventory.write(ctx, key, body, "create", send); result.Status != contract.WriteUnknown {
				t.Fatal("unknown create was not retained")
			}
			if mode == "acknowledged_retry" {
				if result := inventory.write(ctx, key, body, "create", func() contract.WriteResult { return store.Create(ctx, key, body) }); result.Status != contract.WriteAcknowledged {
					t.Fatal("exact retry was not acknowledged")
				}
				// Even an exact readback of the acknowledged retry cannot prove
				// the earlier unknown send has stopped.
				budget := &runBudget{limits: liveLimits{Requests: 2, BodyBytes: operationBodyAllowance}, keys: map[string]bool{}}
				if result := (recordedStore{Store: store, inventory: inventory, budget: budget}).Read(ctx, key, 64); result.Status != contract.ReadOK {
					t.Fatal("controlled readback failed")
				}
				retained := &objectInventory{path: inventory.path, stopped: true}
				if readPrivateJSON(retained.path, &retained.image) != nil {
					t.Fatal("retained inventory could not be reopened")
				}
				inventory = retained
			} else {
				if mode == "different_readback" {
					store.put(key, []byte("different"))
				} else if mode == "duplicate_unknown" {
					if result := inventory.write(ctx, key, body, "create", func() contract.WriteResult {
						return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
					}); result.Status != contract.WriteUnknown {
						t.Fatal("second unknown send was lost")
					}
				}
				budget := &runBudget{limits: liveLimits{Requests: 2, BodyBytes: operationBodyAllowance}, keys: map[string]bool{}}
				if result := (recordedStore{Store: store, inventory: inventory, budget: budget}).Read(ctx, key, 64); result.Status != contract.ReadOK {
					t.Fatal("controlled readback failed")
				}
			}
			inventory.stop()
			unknown, err := inventory.image.unknownEffects()
			if err != nil {
				t.Fatal(err)
			}
			if mode != "exact_readback" {
				want := int64(1)
				if mode == "duplicate_unknown" {
					want = 2
				}
				if unknown != want {
					t.Fatal("unproved send was settled", unknown, want)
				}
				if owned, err := inventory.owned(true); err == nil || owned != nil {
					t.Fatal("unproved send authorized cleanup")
				}
				return
			}
			owned, err := inventory.owned(true)
			if unknown != 0 || err != nil || len(owned) != 1 {
				t.Fatal("exact immutable evidence did not settle inventory", unknown, err)
			}
			if err := inventory.cleanup(ctx, store, testDelete(store)); err != nil {
				t.Fatal("settled immutable object was not cleaned", err)
			}
		})
	}
}

// full_only: false
func TestRunBudgetStopsBeforeConcurrentSends(t *testing.T) {
	budget := &runBudget{limits: liveLimits{Requests: 20, BodyBytes: 10 * operationBodyAllowance, Objects: 1, ObjectBytes: 1}, keys: make(map[string]bool)}
	var wg sync.WaitGroup
	for range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			budget.reserve(2, operationBodyAllowance, "", 0)
		}()
	}
	wg.Wait()
	if snapshot := budget.snapshot(); snapshot.Requests != 20 || snapshot.BodyBytes != 10*operationBodyAllowance {
		t.Fatal("concurrent operations exceeded reservation")
	}
}

// full_only: false
func TestFreshReadReservationsRejectOverflow(t *testing.T) {
	maximum := ^uint64(0)
	for _, row := range []struct {
		name             string
		reads, processes uint64
	}{
		{"read_product", maximum, 2},
		{"request_product", maximum/6 + 1, 1},
		{"body_product", maximum/(3*operationBodyAllowance) + 1, 1},
		{"zero_reads", 0, 1},
		{"zero_processes", 1, 0},
	} {
		t.Run(row.name, func(t *testing.T) {
			budget := &runBudget{limits: liveLimits{Requests: maximum, BodyBytes: maximum}}
			if budget.admitFreshReads(row.reads, row.processes) || !budget.exhausted || budget.snapshot() != (budgetReservation{}) {
				t.Fatal("overflowing reservation was admitted or debited")
			}
		})
	}
}

// full_only: false
func TestFreshSelectedReadAllowanceRejectsMalformedFacts(t *testing.T) {
	f := newFixture(t, 1, false, 1)
	image := sessionStateImage(t, f.session)
	if _, ok := freshSelectedReadAllowance(image); !ok {
		t.Fatal("valid saved read shape refused")
	}
	for _, row := range []struct {
		name   string
		change func(*stateImage)
	}{
		{"child_limit", func(s *stateImage) { s.Root.ChildCount = contract.MaxChildPages + 1 }},
		{"missing_configuration", func(s *stateImage) { s.Root.OutputConfiguration.SliceCount = 0 }},
		{"configuration_limit", func(s *stateImage) { s.Root.OutputConfiguration.SliceCount = contract.MaxOutputConfigurationSlices + 1 }},
		{"fragment_limit", func(s *stateImage) {
			s.Root.Generated.Fragments = make([]format.FragmentLocation, contract.GeneratedFragmentLocationLimit+1)
		}},
		{"index_domain", func(s *stateImage) { s.AdministrativeIndex.Domain = contract.ID{} }},
		{"missing_index_page", func(s *stateImage) { s.AdministrativeIndex.Pages = nil }},
		{"wrong_page", func(s *stateImage) { s.AdministrativeIndex.Pages[0].Ref.Object = contract.ID{} }},
		{"unknown_row", func(s *stateImage) { s.AdministrativeIndex.Pages[0].Rows[0].Kind = 255 }},
	} {
		t.Run(row.name, func(t *testing.T) {
			bad := copyStateImage(t, image)
			row.change(&bad)
			if reads, ok := freshSelectedReadAllowance(bad); ok || reads != 0 {
				t.Fatal("malformed saved shape authorized fresh reads", reads)
			}
		})
	}
}

// full_only: false
func TestFreshSelectedReadAllowanceRejectsIncompleteGeneratedIndex(t *testing.T) {
	env, _ := genesisEnvironment(t, liveFamily, false, 3)
	fixture := newEnvironmentFixture(t, t.Context(), env, nil, false)
	fixture.session = configurationRecoveryGenerated(t, t.Context(), env, fixture.session, "generated-active")
	image := sessionStateImage(t, fixture.session)
	for _, name := range []string{"removed_owner_row", "wrong_index_object"} {
		t.Run(name, func(t *testing.T) {
			bad := copyStateImage(t, image)
			if name == "wrong_index_object" {
				bad.AdministrativeIndex.Object = contract.Hash([]byte("wrong saved index object"))
			} else {
				removed := false
				for i := range bad.AdministrativeIndex.Pages {
					page := &bad.AdministrativeIndex.Pages[i]
					for j, row := range page.Rows {
						if row.Kind != contract.GeneratedParentSupportKind || len(page.Rows) < 2 {
							continue
						}
						page.Rows = append(page.Rows[:j], page.Rows[j+1:]...)
						page.Spans = []format.AdministrativeSpan{{Count: uint16(len(page.Rows)), Mandatory: true}}
						removed = true
						break
					}
					if removed {
						break
					}
				}
				if !removed {
					t.Fatal("generated owner row fixture unavailable")
				}
			}
			if _, err := format.EncodeAdministrativeIndex(bad.AdministrativeIndex); err != nil {
				t.Fatal("control must retain an encodable index", err)
			}
			if reads, ok := freshSelectedReadAllowance(bad); ok || reads != 0 {
				t.Fatal("incomplete or unbound index authorized fresh reads", reads)
			}
		})
	}
}

// full_only: false
func TestFreshSelectedReadAllowanceCoversGeneratedBorrows(t *testing.T) {
	env, _ := genesisEnvironment(t, liveFamily, false, 3)
	store := env.Store.(*memoryStore)
	fixture := newEnvironmentFixture(t, t.Context(), env, nil, false)
	selected := configurationRecoveryGenerated(t, t.Context(), env, fixture.session, "generated-active")
	expected := sessionStateImage(t, selected)
	reads, ok := freshSelectedReadAllowance(expected)
	if !ok || len(expected.Root.Generated.Fragments) == 0 || reads <= uint64(expected.Root.ChildCount)+2+uint64(expected.Root.OutputConfiguration.SliceCount) {
		t.Fatal("generated read shape omitted fragment borrows")
	}
	reservation, ok := freshReadReservation(reads, 1)
	if !ok {
		t.Fatal("valid generated reservation overflowed")
	}
	budget := &runBudget{limits: liveLimits{Requests: reservation.Requests, BodyBytes: reservation.BodyBytes}}
	var keys []string
	store.readHook = func(key string, result contract.ReadResult) contract.ReadResult {
		keys = append(keys, key)
		return result
	}
	cold, result := Open(t.Context(), OpenContext{admission: &selected.admission}, recordedStore{Store: store, budget: budget})
	if cold == nil || result.Outcome != ObservedCurrent || budget.exhausted || uint64(len(keys)) > reads {
		t.Fatal("generated cold Open exceeded the saved read allowance", result, len(keys), reads)
	}
	assertFreshSelectedClosureReads(t, store.desc, expected, cold, len(keys), keys)
	assertStateImage(t, cold, expected)
}

// full_only: false
func TestFreshReadsReserveAuthenticationBeforeEveryRead(t *testing.T) {
	f := newFixture(t, 512, false, 1)
	image := sessionStateImage(t, f.session)
	if len(image.Root.Generated.Fragments) != 1 || image.Root.Generated.Slices.Count != 0 {
		t.Fatal("supplied fixture must retain only its receipt-index fragment")
	}
	// After the unique child scan, Open borrows the configuration and reads the
	// receipt fragment for whole-blob verification, generated coverage and the
	// retained receipt windows. Admission uses a larger conservative bound.
	expectedReads := uint64(image.Root.ChildCount) + 2 + uint64(image.Root.OutputConfiguration.SliceCount) + 3
	reads, ok := freshSelectedReadAllowance(image)
	if !ok || reads < expectedReads {
		t.Fatal("fresh read allowance omitted configuration or receipt-index borrows")
	}
	parent := &runBudget{limits: liveLimits{Requests: 12 * reads, BodyBytes: 6 * reads * operationBodyAllowance}}
	if !parent.admitFreshReads(reads, 2) || parent.snapshot() != (budgetReservation{}) {
		t.Fatal("paired fresh readers could not reserve their requests")
	}
	injected := false
	var keys []string
	f.store.readHook = func(key string, result contract.ReadResult) contract.ReadResult {
		if key == f.store.desc.HeadKey && !injected {
			injected = true
			return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
		}
		keys = append(keys, key)
		return result
	}
	var requests uint64
	for index := range 2 {
		keys = nil
		child := &runBudget{limits: liveLimits{Requests: 6 * reads, BodyBytes: 3 * reads * operationBodyAllowance}}
		store := recordedStore{Store: f.store, budget: child}
		session, result := Open(context.Background(), f.admission, store)
		if session == nil || result.Outcome != ObservedCurrent {
			t.Fatal("bounded fresh reader failed")
		}
		if uint64(len(keys)) != expectedReads {
			t.Fatalf("fresh selected read count differs: got=%d want=%d", len(keys), expectedReads)
		}
		assertFreshSelectedClosureReads(t, f.store.desc, image, session, int(expectedReads), keys)
		attempts := expectedReads + uint64(1-index)
		expected := budgetReservation{Requests: 2 * attempts, BodyBytes: attempts * operationBodyAllowance}
		if child.snapshot() != expected || child.transportFailures() != uint64(1-index) {
			t.Fatalf("fresh reader accounting differs: got=%+v want=%+v transport=%d", child.snapshot(), expected, child.transportFailures())
		}
		requests += child.snapshot().Requests
	}
	if !injected || requests > parent.limits.Requests {
		t.Fatal("fresh-reader authentication requests escaped the parent budget")
	}
	short := &runBudget{limits: liveLimits{Requests: 12*reads - 1, BodyBytes: 6 * reads * operationBodyAllowance}}
	if short.admitFreshReads(reads, 2) || !short.exhausted || short.snapshot() != (budgetReservation{}) {
		t.Fatal("fresh-reader worst case exceeded its admission budget")
	}
	shortBody := &runBudget{limits: liveLimits{Requests: 12 * reads, BodyBytes: 6*reads*operationBodyAllowance - 1}}
	if shortBody.admitFreshReads(reads, 2) || !shortBody.exhausted || shortBody.snapshot() != (budgetReservation{}) {
		t.Fatal("fresh-reader worst case exceeded its body budget")
	}
}

// full_only: false
func TestLiveInventoryFreshProcess(t *testing.T) {
	ctx := context.Background()
	env := memoryScenarioEnvironment(t)
	store := env.Store.(*memoryStore)
	inventory := &objectInventory{path: filepath.Join(liveTestDirectory(t), "inventory.json"), image: inventoryImage{
		Version: 1, Prefix: store.desc.Prefix, Deleted: make(map[string]int),
	}}
	limits := liveLimits{Requests: 1000, BodyBytes: 1 << 33, Objects: 100, ObjectBytes: 1 << 20}
	budget := &runBudget{limits: limits, keys: make(map[string]bool)}
	env.Store = recordedStore{Store: store, inventory: inventory, budget: budget}
	env.Trust = budgetTrust{Trust: env.Trust, budget: budget}
	f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	owned, err := inventory.owned(false)
	if err != nil || len(owned) != len(store.objects) {
		t.Fatal("selected fixture escaped its ownership inventory", err)
	}
	for key, object := range store.objects {
		if !owned[key][bodyDigest(object.Body)] {
			t.Fatal("selected object body escaped its ownership inventory", key)
		}
	}
	kinds := make(map[string]bool)
	for _, intent := range inventory.image.Intents {
		kinds[intent.Kind] = true
	}
	if !kinds["create_head"] || !kinds["create"] || !kinds["compare_and_swap"] {
		t.Fatal("inventory fixture did not exercise each selected-state write kind")
	}
	if snapshot := budget.snapshot(); snapshot.Requests == 0 || snapshot.Objects != uint64(len(store.objects)) {
		t.Fatal("selected fixture escaped its run budget", snapshot)
	}

	// FreshOpen runs TestFreshProcessChild and requires its positive completion
	// evidence before it returns. Cleanup starts only after that process exits.
	env.FreshOpen(t, sessionStateImage(t, f.session))
	inventory.stop()
	cleanupBudget := &runBudget{limits: limits, keys: make(map[string]bool)}
	if err := inventory.cleanup(ctx, recordedStore{Store: store, budget: cleanupBudget}, testDelete(store)); err != nil {
		t.Fatal("completed fresh fixture could not be cleaned", err)
	}
	if len(store.objects) != 0 || cleanupBudget.snapshot().Requests == 0 {
		t.Fatal("fresh fixture cleanup left owned objects or bypassed its budget")
	}
}

// full_only: true
// The full catalog representatives complement daily component and isolated scenario coverage.
func TestInventoryRepresentativeScenarios(t *testing.T) {
	// The hermetic scenario stage owns every hermetic catalog scenario and recovery mode.
	// This assembly checks each distinct fixture route through the live budget,
	// inventory, and cleanup wrappers. Keep the delayed CAS schedule as a
	// separate route even though it shares the ordinary state capabilities.
	selected := make(map[string]bool)
	for _, name := range catalog.Names() {
		definition, ok := catalog.DefinitionFor(name)
		if !ok || len(definition.Modes) == 0 || len(definition.RecoveryModes) == 0 {
			t.Fatal("inventory scenario has no declared execution or recovery modes")
		}
		if !slices.Contains(definition.Modes, "hermetic") {
			continue
		}
		execution, ok := catalog.ExecutionFor(name, "hermetic")
		if !ok {
			t.Fatal("inventory scenario has no hermetic execution", name)
		}
		capabilities := slices.Clone(execution.FixtureCapabilities)
		slices.Sort(capabilities)
		route := string(execution.Family) + "/" + fmt.Sprint(capabilities)
		for _, mode := range definition.RecoveryModes {
			key := route + "/" + mode
			if selected[key] && name != "selection.concurrent-writers-select-one-complete-state/members_32_two_writers" {
				continue
			}
			selected[key] = true
			t.Run(name+"/"+mode, func(t *testing.T) {
				env := memoryScenarioEnvironmentMode(t, mode == "enabled")
				if execution.HasFixtureCapability(catalog.FixtureConfigurationRecovery) {
					env, _ = genesisEnvironment(t, liveFamily, mode == "enabled", 3)
				}
				if catalog.HasFixtureCapability(name, catalog.FixtureSyntheticAuthority) {
					freshCurrent := env.FreshCurrent
					env = syntheticAuthorityScenarioEnvironment(t, env)
					execution, _ := catalog.ExecutionFor(name, "hermetic")
					if execution.Family == catalog.FamilyGeneratedRetirement {
						env.FreshCurrent = freshCurrent
					}
				}
				store := env.Store.(*memoryStore)
				inventory := &objectInventory{path: filepath.Join(liveTestDirectory(t), "inventory.json"), image: inventoryImage{Version: 1, Prefix: store.desc.Prefix, Deleted: make(map[string]int)}}
				limits := liveLimits{Requests: 10000, BodyBytes: 1 << 36, Objects: 10000, ObjectBytes: 1 << 30}
				budget := &runBudget{limits: limits, keys: make(map[string]bool)}
				env.Store = recordedStore{Store: store, inventory: inventory, budget: budget}
				env.ControlDelayedCAS = name == "selection.concurrent-writers-select-one-complete-state/members_32_two_writers"
				if actors := env.ReplacementActors; actors != nil {
					env.ReplacementActors = func(t testing.TB, ctx context.Context, before *StateSession, operation, mask, approval uint8) successionActors {
						current := actors(t, ctx, before, operation, mask, approval)
						current.Store = env.Store
						return current
					}
				}
				env.Trust = budgetTrust{Trust: env.Trust, budget: budget}
				env.Put = func(ctx context.Context, key string, body []byte) error {
					result := inventory.write(ctx, key, body, "fixture_create", func() contract.WriteResult { return store.Create(ctx, key, body) })
					if result.Status != contract.WriteAcknowledged {
						return errInventory
					}
					return nil
				}
				env.Delete = func(ctx context.Context, key string) error {
					owned, err := inventory.owned(false)
					if err != nil || len(owned[key]) == 0 {
						return errInventory
					}
					return inventory.remove(ctx, store, testDelete(store), key, owned[key])
				}
				if execution.HasFixtureCapability(catalog.FixtureConfigurationRecovery) {
					inventory.image.Domain = env.Domain
					state, oracle := liveTestDirectory(t), liveTestDirectory(t)
					for _, directory := range []string{state, oracle} {
						if err := os.Chmod(directory, 0700); err != nil {
							t.Fatal(err)
						}
					}
					env.ConfigurationRecovery = func(tb testing.TB, ctx context.Context, env fixtureEnvironment, name string) {
						configuration := fixtureStoreConfiguration(env.Store)
						input := liveRunInput{Scenarios: []string{name}, Prefix: configuration.PrefixBeforeHEAD,
							Settings:              liveSettings{Region: configuration.Region, Bucket: configuration.Bucket, Account: configuration.ExpectedOwner},
							ConfigurationRecovery: &installedarchive.RecoveryWriterInput{Domain: env.Domain, OracleDirectory: oracle}}
						runLiveConfigurationRecoveryWriter(tb, ctx, env, name, state, input, inventory, budget)
						fixture := installedarchive.ReadRecoveryFixture(tb, filepath.Join(state, "recovery-parent.json"))
						owned, err := inventory.owned(false)
						if err != nil || len(owned) == 0 || len(owned) != len(store.objects) || fixture.Archive.ObjectCount != len(owned) ||
							fixture.Secrets != 3 || len(fixture.Oracles) != 5 || len(fixture.Values) != 0 || budget.exhausted {
							tb.Fatal("recovery writer export escaped complete inventory or budget")
						}
						for _, object := range fixture.Archive.Objects {
							if !owned[object.Key][bodyDigest(object.Body)] || object.Token != store.objects[object.Key].Token {
								tb.Fatal("recovery exported object escaped exact inventory")
							}
						}
					}
				}
				runStateScenario(t, context.Background(), env, name)
				inventory.stop()
				cleanupBudget := &runBudget{limits: limits, keys: make(map[string]bool)}
				if inventory.cleanup(context.Background(), recordedStore{Store: store, budget: cleanupBudget}, testDelete(store)) != nil || len(store.objects) != 0 {
					t.Fatal("shared scenario left owned objects")
				}
			})
		}
	}
}

// full_only: false
func TestRecordedStoreAccountsForEveryPhysicalOperation(t *testing.T) {
	ctx := context.Background()
	env := memoryScenarioEnvironment(t)
	store := env.Store.(*memoryStore)
	inventory := &objectInventory{path: filepath.Join(liveTestDirectory(t), "inventory.json"), image: inventoryImage{
		Version: 1, Prefix: store.desc.Prefix, Deleted: make(map[string]int),
	}}
	head, next, object := []byte("head"), []byte("next"), []byte("object")
	budget := &runBudget{limits: liveLimits{Requests: 8, BodyBytes: 4 * operationBodyAllowance,
		Objects: 2, ObjectBytes: uint64(len(head) + len(next) + len(object))}, keys: make(map[string]bool)}
	recorded := recordedStore{Store: store, inventory: inventory, budget: budget}
	request, err := contract.NewHeadCreateRequest(store.desc, head)
	if err != nil || recorded.CreateHead(ctx, request).Status != contract.WriteAcknowledged {
		t.Fatal("recorded HEAD create failed", err)
	}
	read := recorded.Read(ctx, store.desc.HeadKey, uint32(len(head)))
	if read.Status != contract.ReadOK || recorded.CompareAndSwap(ctx, store.desc.HeadKey, read.Token, next).Status != contract.WriteAcknowledged {
		t.Fatal("recorded conditional write failed")
	}
	key := store.desc.Prefix + "/accounted"
	if recorded.Create(ctx, key, object).Status != contract.WriteAcknowledged {
		t.Fatal("recorded immutable create failed")
	}
	want := budgetReservation{Requests: 8, BodyBytes: 4 * operationBodyAllowance,
		Objects: 2, ObjectBytes: uint64(len(head) + len(next) + len(object))}
	if got := budget.snapshot(); got != want || store.reads != 1 || store.creates != 2 || store.cas != 1 {
		t.Fatal("physical operation escaped exact accounting", got, want)
	}
	if result := recorded.Read(ctx, key, uint32(len(object))); result.Status != contract.ReadUnavailable || result.Reason != contract.ReasonLimit || store.reads != 1 {
		t.Fatal("exhausted budget allowed a physical read", result)
	}
	inventory.stop()
	cleanupBudget := &runBudget{limits: liveLimits{Requests: 100, BodyBytes: 100 * operationBodyAllowance}, keys: make(map[string]bool)}
	if err := inventory.cleanup(ctx, recordedStore{Store: store, budget: cleanupBudget}, testDelete(store)); err != nil || len(store.objects) != 0 {
		t.Fatal("accounted objects were not cleaned", err)
	}
}

func testDelete(store *memoryStore) func(context.Context, string, contract.Token) error {
	return func(_ context.Context, key string, token contract.Token) error {
		store.mu.Lock()
		defer store.mu.Unlock()
		if store.objects[key].Token != token {
			return errors.New("condition changed")
		}
		delete(store.objects, key)
		return nil
	}
}

// full_only: false
func TestInventoryPrecedesEveryPossibleWrite(t *testing.T) {
	i, store := testInventory(t)
	key := i.image.Prefix + "/new"
	result := i.write(context.Background(), key, []byte("body"), "create", func() contract.WriteResult {
		body, err := os.ReadFile(i.path)
		if err != nil {
			t.Fatal(err)
		}
		var image inventoryImage
		if json.Unmarshal(body, &image) != nil || len(image.Intents) != 1 || image.Intents[0].State != "pending" || image.Intents[0].Digest != bodyDigest([]byte("body")) {
			t.Fatal("write started without durable intent")
		}
		return store.Create(context.Background(), key, []byte("body"))
	})
	if result.Status != contract.WriteAcknowledged {
		t.Fatal(result)
	}
	info, err := os.Stat(i.path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("inventory permissions")
	}
}

// full_only: false
func TestInventoryUnsettledWritePreventsCleanup(t *testing.T) {
	for _, state := range []string{"pending", "unknown"} {
		t.Run(state, func(t *testing.T) {
			i, store := testInventory(t)
			i.image.Intents = []objectIntent{{Key: i.image.Prefix + "/new", Digest: bodyDigest([]byte("owned")), Bytes: 5, Kind: "create", State: state}}
			i.stop()
			calls := 0
			err := i.cleanup(context.Background(), store, func(context.Context, string, contract.Token) error {
				calls++
				return nil
			})
			if err == nil || calls != 0 {
				t.Fatal("unsettled write allowed cleanup")
			}
		})
	}
}

// full_only: false
func TestInventoryRetainsUnknownAfterLaterSuccessAndRecognizesNotSent(t *testing.T) {
	i, _ := testInventory(t)
	key, body := i.image.Prefix+"/new", []byte("owned")
	for _, result := range []contract.WriteResult{
		{Status: contract.WriteUnknown, Reason: contract.ReasonTransport},
		{Status: contract.WriteAcknowledged},
	} {
		if got := i.write(context.Background(), key, body, "create", func() contract.WriteResult { return result }); got != result {
			t.Fatal("write result changed", got)
		}
	}
	if count, err := i.image.unknownEffects(); err != nil || count != 1 {
		t.Fatal("later success erased an earlier possible entry", count, err)
	}
	if owned, err := i.owned(false); err == nil || owned != nil {
		t.Fatal("unknown create allowed unsafe cleanup")
	}
	other := i.image.Prefix + "/not-sent"
	i.write(context.Background(), other, body, "create", func() contract.WriteResult {
		return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport, NotSent: true}
	})
	if i.image.Intents[2].State != "not_sent" {
		t.Fatal("proved before-send request remained unknown")
	}
	if count, err := i.image.unknownEffects(); err != nil || count != 1 {
		t.Fatal("before-send proof changed earlier uncertainty", count, err)
	}
}

// full_only: false
func TestInventoryPersistsOriginalCASConditionBeforeSend(t *testing.T) {
	i, store := testInventory(t)
	token := contract.Token{Family: store.desc.Family, Value: "17"}
	if token.Family == contract.AWS {
		token.Value = `"17"`
	}
	key, body := store.desc.HeadKey, []byte("frozen")
	got := i.write(context.Background(), key, body, "compare_and_swap", func() contract.WriteResult {
		var saved inventoryImage
		if records.ReadJSON(i.path, &saved) != nil || len(saved.Intents) != 1 || saved.Intents[0].State != "pending" || saved.Intents[0].ConditionToken == nil || *saved.Intents[0].ConditionToken != token || saved.Intents[0].Digest != bodyDigest(body) || saved.Intents[0].Bytes != uint64(len(body)) {
			t.Fatal("conditional write began without its original durable intent")
		}
		return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport, NotSent: true}
	}, token)
	if got.Status != contract.WriteUnknown || !got.NotSent || i.image.Intents[0].State != "not_sent" {
		t.Fatal("before-send condition was not retained", got)
	}
}

// full_only: false
func TestInventoryFailureCannotStartWrite(t *testing.T) {
	i, _ := testInventory(t)
	i.path = filepath.Join(liveTestDirectory(t), "missing", "inventory.json")
	calls := 0
	result := i.write(context.Background(), i.image.Prefix+"/new", []byte("body"), "create", func() contract.WriteResult {
		calls++
		return contract.WriteResult{Status: contract.WriteAcknowledged}
	})
	if calls != 0 || result.Status != contract.WriteRefused {
		t.Fatal("write started after inventory failure")
	}
}

// full_only: false
func TestInventoryPersistenceFailureMakesOwnershipUnknown(t *testing.T) {
	i, store := testInventory(t)
	ctx := context.Background()
	for _, name := range []string{"first", "second"} {
		key := i.image.Prefix + "/" + name
		if result := i.write(ctx, key, []byte("owned"), "create", func() contract.WriteResult { return store.Create(ctx, key, []byte("owned")) }); result.Status != contract.WriteAcknowledged {
			t.Fatal(result)
		}
	}
	i.stop()
	i.path = filepath.Join(liveTestDirectory(t), "missing", "inventory.json")
	var deletes int
	if i.cleanup(ctx, store, func(ctx context.Context, key string, token contract.Token) error {
		deletes++
		return testDelete(store)(ctx, key, token)
	}) == nil {
		t.Fatal("failed cleanup persistence reported success")
	}
	if deletes != 0 || store.Read(ctx, i.image.Prefix+"/first", 5).Status != contract.ReadOK || store.Read(ctx, i.image.Prefix+"/second", 5).Status != contract.ReadOK {
		t.Fatal("cleanup sent a delete without durable pre-effect intent")
	}
	if owned, err := i.owned(true); err == nil || owned != nil {
		t.Fatal("failed journal was treated as a complete ownership inventory")
	}
}

// full_only: false
func TestInventoryCleanupChecksOwnershipAndRetainsFailure(t *testing.T) {
	for _, failure := range []string{"foreign-body", "changed-token", "denied", "none"} {
		t.Run(failure, func(t *testing.T) {
			i, store := testInventory(t)
			key, body := i.image.Prefix+"/new", []byte("owned")
			i.write(context.Background(), key, body, "create", func() contract.WriteResult { return store.Create(context.Background(), key, body) })
			i.stop()
			sends := 0
			remove := func(ctx context.Context, key string, token contract.Token) error {
				sends++
				return testDelete(store)(ctx, key, token)
			}
			switch failure {
			case "foreign-body":
				store.put(key, []byte("other"))
			case "changed-token":
				remove = func(ctx context.Context, key string, token contract.Token) error {
					sends++
					store.put(key, body)
					return testDelete(store)(ctx, key, token)
				}
			case "denied":
				remove = func(context.Context, string, contract.Token) error { sends++; return errors.New("denied") }
			}
			err := i.cleanup(context.Background(), store, remove)
			if (err == nil) != (failure == "none") {
				t.Fatal("cleanup outcome differs")
			}
			if failure != "none" {
				if _, err := os.Stat(i.path); err != nil || i.image.Deleted[key] != 0 {
					t.Fatal("failed cleanup discarded inventory")
				}
			}
			if failure == "foreign-body" {
				var cause *inventoryCleanupFailure
				read := store.Read(context.Background(), key, 64)
				if !errors.As(err, &cause) || cause.facts.Stage != "ownership_check" || cause.facts.Cause != "ownership_mismatch" ||
					cause.facts.Effect != "no_send" || sends != 0 || read.Status != contract.ReadOK || !bytes.Equal(read.Body, []byte("other")) {
					t.Fatal("foreign object was deleted or adopted by cleanup", err, sends)
				}
			}
		})
	}
}

// full_only: false
func TestInventoryRefusedRecreateCannotRestoreOwnership(t *testing.T) {
	i, store := testInventory(t)
	ctx := context.Background()
	key, body := i.image.Prefix+"/new", []byte("owned")
	i.write(ctx, key, body, "create", func() contract.WriteResult { return store.Create(ctx, key, body) })
	if err := i.remove(ctx, store, testDelete(store), key, map[string]bool{bodyDigest(body): true}); err != nil {
		t.Fatal(err)
	}
	store.put(key, body)
	i.write(ctx, key, body, "create", func() contract.WriteResult { return store.Create(ctx, key, body) })
	i.stop()
	if err := i.cleanup(ctx, store, testDelete(store)); err != nil {
		t.Fatal(err)
	}
	if store.Read(ctx, key, 1024).Status != contract.ReadOK {
		t.Fatal("refused recreation adopted a foreign object")
	}
}

// full_only: false
func TestInventoryCleanupRequiresExactRecordedBodySize(t *testing.T) {
	inventory, store := testInventory(t)
	key := inventory.image.Prefix + "/new"
	body := []byte("owned")
	if result := inventory.write(context.Background(), key, body, "create", func() contract.WriteResult { return store.Create(context.Background(), key, body) }); result.Status != contract.WriteAcknowledged {
		t.Fatal("controlled inventory write failed")
	}
	inventory.image.Intents[0].Bytes++
	inventory.stop()
	calls := 0
	if inventory.cleanup(context.Background(), store, func(context.Context, string, contract.Token) error { calls++; return nil }) == nil || calls != 0 {
		t.Fatal("cleanup trusted a digest without its recorded body size")
	}
}

// full_only: false
func TestInventoryCleanupRetriesOnlyTransportReadWithoutRepeatingDelete(t *testing.T) {
	for _, test := range []struct {
		name   string
		reason contract.Reason
	}{{"transport", contract.ReasonTransport}, {"access", contract.ReasonAccess}} {
		t.Run(test.name, func(t *testing.T) {
			inventory, store := testInventory(t)
			ctx := context.Background()
			key, body := inventory.image.Prefix+"/new", []byte("owned")
			if result := inventory.write(ctx, key, body, "create", func() contract.WriteResult { return store.Create(ctx, key, body) }); result.Status != contract.WriteAcknowledged {
				t.Fatal("controlled inventory write failed")
			}
			inventory.stop()
			injected := false
			store.readHook = func(readKey string, result contract.ReadResult) contract.ReadResult {
				if readKey == key && result.Status == contract.ReadMissing && !injected {
					injected = true
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: test.reason}
				}
				return result
			}
			deletes := 0
			deleteOnce := testDelete(store)
			remove := func(ctx context.Context, key string, token contract.Token) error {
				deletes++
				return deleteOnce(ctx, key, token)
			}
			err := inventory.cleanup(ctx, store, remove)
			if !injected || deletes != 1 {
				t.Fatal("cleanup did not exercise one exact delete and failed read")
			}
			owned, ownedErr := inventory.owned(true)
			if test.reason == contract.ReasonTransport {
				if err != nil || ownedErr != nil || len(owned) != 0 {
					t.Fatal("transport read retry did not settle cleanup", err)
				}
			} else if err == nil || ownedErr != nil || len(owned) != 1 {
				t.Fatal("non-transport read failure did not retain inventory", err)
			}
		})
	}
}

// full_only: false
func TestInventoryRejectsSymlinkEvidence(t *testing.T) {
	for _, name := range []string{"inventory.json", "inventory.lock"} {
		t.Run(name, func(t *testing.T) {
			directory := liveTestDirectory(t)
			foreign := filepath.Join(directory, "foreign")
			if os.WriteFile(foreign, []byte("retain"), 0o600) != nil || os.Symlink(foreign, filepath.Join(directory, name)) != nil {
				t.Fatal("test symlink unavailable")
			}
			if name == "inventory.lock" {
				if lock, err := lockInventory(directory); err == nil {
					lock.Close()
					t.Fatal("symlink lock admitted")
				}
			} else if writePrivateJSON(filepath.Join(directory, name), inventoryImage{}) == nil {
				t.Fatal("symlink inventory replaced")
			}
			body, err := os.ReadFile(foreign)
			if err != nil || string(body) != "retain" {
				t.Fatal("foreign evidence changed")
			}
		})
	}
}

// full_only: false
func TestInventoryUnknownEffectsRequireValidEvidence(t *testing.T) {
	inventory, _ := testInventory(t)
	intent := objectIntent{Key: inventory.image.Prefix + "/new", Digest: bodyDigest([]byte("owned")), Bytes: 5, Kind: "create", State: "pending"}
	inventory.image.Intents = []objectIntent{intent}
	for _, state := range []string{"pending", "unknown", "acknowledged", "refused", "invalid"} {
		inventory.image.Intents[0].State = state
		count, err := inventory.image.unknownEffects()
		if state == "invalid" {
			if err == nil {
				t.Fatal("invalid effects were reported as known")
			}
			continue
		}
		want := int64(0)
		if state == "pending" || state == "unknown" {
			want = 1
		}
		if err != nil || count != want {
			t.Fatal("known inventory effects were lost")
		}
	}
	inventory.image.Intents[0].State = "acknowledged"
	status, index := uint16(503), uint32(0)
	fact := records.HarnessFailure{Operation: "object_cleanup", Stage: "conditional_delete", Cause: "provider_refused", Effect: "unknown",
		HTTPStatus: &status, TargetKind: "inventory", TargetIndex: &index, Attempt: 1}
	attempt := cleanupAttempt{TargetIntent: 0, Ordinal: 1, Key: intent.Key, Digest: intent.Digest, Bytes: intent.Bytes,
		Token: contract.Token{Family: contract.GCP, Value: "1"}, State: "failed", Failure: &fact}
	inventory.image.CleanupAttempts = []cleanupAttempt{attempt}
	if count, err := inventory.image.unknownEffects(); err != nil || count != 1 {
		t.Fatal("valid unknown cleanup effect was lost", count, err)
	}
	for _, change := range []string{"target", "digest", "condition", "cutoff", "failure", "state"} {
		t.Run(change, func(t *testing.T) {
			image := inventory.image
			bad := attempt
			switch change {
			case "target":
				bad.Key += "/other"
			case "digest":
				bad.Digest = bodyDigest([]byte("different"))
			case "condition":
				bad.Token = contract.Token{}
			case "cutoff":
				bad.Cutoff = 1
			case "failure":
				bad.Failure = nil
			case "state":
				bad.State = "settled"
			}
			image.CleanupAttempts = []cleanupAttempt{bad}
			if _, err := image.unknownEffects(); err == nil {
				t.Fatal("malformed cleanup attempt was accepted", change)
			}
		})
	}
}

// full_only: false
func TestGenesisHEADUsesBudgetAndInventory(t *testing.T) {
	env := memoryScenarioEnvironment(t)
	store := env.Store.(*memoryStore)
	inventory := &objectInventory{path: filepath.Join(liveTestDirectory(t), "inventory.json"), image: inventoryImage{Version: 1, Prefix: store.desc.Prefix, Deleted: make(map[string]int)}}
	body := []byte("bounded genesis HEAD request")
	request, err := contract.NewHeadCreateRequest(store.desc, body)
	if err != nil {
		t.Fatal(err)
	}
	budget := &runBudget{limits: liveLimits{Requests: 2, BodyBytes: operationBodyAllowance, Objects: 1, ObjectBytes: uint64(len(body))}, keys: make(map[string]bool)}
	recorded := recordedStore{Store: store, inventory: inventory, budget: budget}
	if result := recorded.CreateHead(context.Background(), request); result.Status != contract.WriteAcknowledged {
		t.Fatal(result)
	}
	owned, err := inventory.owned(false)
	if err != nil || len(owned[store.desc.HeadKey]) != 1 || budget.snapshot().Requests != 2 {
		t.Fatal("genesis HEAD escaped inventory or budget", err)
	}
	calls := store.creates
	if result := recorded.CreateHead(context.Background(), request); result.Status != contract.WriteRefused || result.Reason != contract.ReasonLimit || store.creates != calls {
		t.Fatal("genesis HEAD exceeded its request budget", result)
	}
}

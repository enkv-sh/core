package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
)

func controlledCleanupGrant(ordinal uint8) liveCleanupGrant {
	return liveCleanupGrant{
		TargetIndex: 0, Ordinal: ordinal,
		OriginalCaseReceiptSHA256: strings.Repeat("a", 64),
		GrantRunID:                strings.Repeat("b", 32), GrantLimitsSHA256: strings.Repeat("c", 64),
	}
}

// full_only: false
func TestGrantedCleanupAfterAutomaticAttempts(t *testing.T) {
	inventory, store, key, _ := failedCleanupInventory(t, false)
	for _, ordinal := range []uint8{2, 3} {
		if err := inventory.recoverCleanup(context.Background(), store, func(context.Context, string, contract.Token) error {
			return inventoryControlledDeleteError{}
		}, 0, ordinal); err == nil {
			t.Fatal("controlled automatic attempt did not fail")
		}
	}
	grant := controlledCleanupGrant(4)
	var sends int
	remove := testDelete(store)
	err := inventory.recoverGrantedCleanup(context.Background(), store, func(ctx context.Context, gotKey string, token contract.Token) error {
		sends++
		if gotKey != key || token != inventory.image.CleanupAttempts[0].Token {
			t.Fatal("grant changed the exact delete target")
		}
		var durable inventoryImage
		if readPrivateJSON(inventory.path, &durable) != nil || len(durable.CleanupAttempts) != 4 ||
			durable.CleanupAttempts[3].State != "pending" || durable.CleanupAttempts[3].Recovery != "gcp_exact_generation_grant" ||
			durable.CleanupAttempts[3].GrantRunID != grant.GrantRunID || durable.CleanupAttempts[3].CaseSHA256 != grant.OriginalCaseReceiptSHA256 ||
			durable.CleanupAttempts[3].LimitsSHA256 != grant.GrantLimitsSHA256 {
			t.Fatal("explicit grant was not durable before delete")
		}
		return remove(ctx, gotKey, token)
	}, grant)
	if err != nil || sends != 1 || len(inventory.image.CleanupAttempts) != 4 || inventory.image.Deleted[key] != len(inventory.image.Intents) {
		t.Fatal("grant did not settle the exact target", err, sends)
	}
	for _, attempt := range inventory.image.CleanupAttempts {
		if attempt.State != "settled" {
			t.Fatal("attempt history was not settled")
		}
	}
	if count, err := inventory.image.unknownEffects(); err != nil || count != 0 {
		t.Fatal("grant left unknown effects", count, err)
	}
	if inventory.recoverGrantedCleanup(context.Background(), store, func(context.Context, string, contract.Token) error {
		sends++
		return nil
	}, grant) == nil || sends != 1 {
		t.Fatal("grant was reused")
	}
}

// full_only: false
func TestGrantedCleanupSettlesLostReplyWithoutDelete(t *testing.T) {
	inventory, store, key, _ := failedCleanupInventory(t, true)
	grant := controlledCleanupGrant(2)
	var sends int
	if err := inventory.recoverGrantedCleanup(context.Background(), store, func(context.Context, string, contract.Token) error {
		sends++
		return nil
	}, grant); err != nil || sends != 0 || len(inventory.image.CleanupAttempts) != 2 ||
		inventory.image.CleanupAttempts[1].State != "settled" || inventory.image.CleanupAttempts[1].GrantRunID != grant.GrantRunID ||
		inventory.image.Deleted[key] != len(inventory.image.Intents) {
		t.Fatal("qualified absence did not consume and record the grant", err, sends)
	}
	if count, err := inventory.image.unknownEffects(); err != nil || count != 0 {
		t.Fatal("qualified absence left unknown effects", count, err)
	}
}

// full_only: false
func TestGrantedCleanupRefusesChangedOrIncompleteProof(t *testing.T) {
	for _, mode := range []string{"changed_generation", "unknown_create", "wrong_ordinal", "bad_grant", "pending_attempt"} {
		t.Run(mode, func(t *testing.T) {
			inventory, store, key, body := failedCleanupInventory(t, false)
			grant := controlledCleanupGrant(2)
			switch mode {
			case "changed_generation":
				store.mu.Lock()
				store.put(key, body)
				store.mu.Unlock()
			case "unknown_create":
				inventory.image.Intents[0].State = "unknown"
				if err := inventory.save(); err != nil {
					t.Fatal(err)
				}
			case "wrong_ordinal":
				grant.Ordinal = 3
			case "bad_grant":
				grant.GrantLimitsSHA256 = "not-a-digest"
			case "pending_attempt":
				inventory.image.CleanupAttempts[0].State = "pending"
				inventory.image.CleanupAttempts[0].Failure = nil
				if err := inventory.save(); err != nil {
					t.Fatal(err)
				}
			}
			var sends int
			if inventory.recoverGrantedCleanup(context.Background(), store, func(context.Context, string, contract.Token) error {
				sends++
				return nil
			}, grant) == nil || sends != 0 {
				t.Fatal("unproved grant sent delete", mode, sends)
			}
		})
	}
}

func failedAWSCleanupInventory(t *testing.T, afterEffect bool, otherOwned ...bool) (*objectInventory, *memoryStore, string, []byte) {
	t.Helper()
	inventory, store := testInventory(t)
	store.desc.Family = contract.AWS
	key, body := inventory.image.Prefix+"/aws-recover", []byte("owned AWS fixture")
	ctx := context.Background()
	if result := inventory.write(ctx, key, body, "create", func() contract.WriteResult { return store.Create(ctx, key, body) }); result.Status != contract.WriteAcknowledged {
		t.Fatal("AWS fixture unavailable")
	}
	if len(otherOwned) != 0 && otherOwned[0] {
		otherKey := inventory.image.Prefix + "/zzz-not-yet-cleaned"
		otherBody := []byte("other acknowledged fixture")
		if result := inventory.write(ctx, otherKey, otherBody, "create", func() contract.WriteResult { return store.Create(ctx, otherKey, otherBody) }); result.Status != contract.WriteAcknowledged {
			t.Fatal("other fixture unavailable")
		}
	}
	inventory.stop()
	err := inventory.cleanup(ctx, store, func(ctx context.Context, key string, token contract.Token) error {
		if afterEffect {
			if err := testDelete(store)(ctx, key, token); err != nil {
				t.Fatal(err)
			}
		}
		return inventoryControlledTransportError{}
	})
	if err == nil || len(inventory.image.CleanupAttempts) != 1 {
		t.Fatal("AWS original uncertainty unavailable", err)
	}
	return inventory, store, key, body
}

// full_only: false
func TestAWSGrantedCleanupSettlesPresentOrMissingFixture(t *testing.T) {
	for _, afterEffect := range []bool{false, true} {
		t.Run(map[bool]string{false: "present", true: "missing"}[afterEffect], func(t *testing.T) {
			inventory, store, key, _ := failedAWSCleanupInventory(t, afterEffect)
			original := *inventory.image.CleanupAttempts[0].Failure
			grant := controlledCleanupGrant(2)
			body, readErr := os.ReadFile(inventory.path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			grant.InventorySHA256 = bodyDigest(body)
			var sends int
			remove := testDelete(store)
			err := inventory.recoverGrantedCleanup(context.Background(), store, func(ctx context.Context, key string, token contract.Token) error {
				sends++
				var durable inventoryImage
				if readPrivateJSON(inventory.path, &durable) != nil || len(durable.CleanupAttempts) != 2 || durable.CleanupAttempts[1].GrantRunID != grant.GrantRunID || durable.CleanupAttempts[1].State != "pending" {
					t.Fatal("AWS grant not durable before delete")
				}
				return remove(ctx, key, token)
			}, grant)
			expected := 1
			if afterEffect {
				expected = 0
			}
			if err != nil || sends != expected || inventory.image.Deleted[key] != len(inventory.image.Intents) || len(inventory.image.CleanupAttempts) != 2 {
				t.Fatal("AWS grant did not establish current absence", err, sends)
			}
			if !reflect.DeepEqual(original, *inventory.image.CleanupAttempts[0].Failure) || original.Effect != "unknown" {
				t.Fatal("original unknown attribution changed")
			}
			if count, err := inventory.image.unknownEffects(); err != nil || count != 0 {
				t.Fatal("AWS settled inventory unresolved", count, err)
			}
			if inventory.recoverGrantedCleanup(context.Background(), store, remove, grant) == nil {
				t.Fatal("AWS grant reused")
			}
		})
	}
}

func awsInventoryGrant(t *testing.T, inventory *objectInventory) liveCleanupGrant {
	t.Helper()
	grant := controlledCleanupGrant(2)
	digest, err := privateRecordSHA256(inventory.path)
	if err != nil {
		t.Fatal(err)
	}
	grant.InventorySHA256 = digest
	return grant
}

// full_only: false
func TestAWSGrantedCleanupConsumesGrantBeforeReadAndAfterReadFailure(t *testing.T) {
	for _, outcome := range []string{"transport", "budget", "mismatched_body", "mismatched_length", "mismatched_token"} {
		t.Run(outcome, func(t *testing.T) {
			inventory, store, key, _ := failedAWSCleanupInventory(t, false)
			grant := awsInventoryGrant(t, inventory)
			original := *inventory.image.CleanupAttempts[0].Failure
			readChecked := false
			store.readHook = func(_ string, result contract.ReadResult) contract.ReadResult {
				var durable inventoryImage
				if readPrivateJSON(inventory.path, &durable) != nil || len(durable.CleanupAttempts) != 2 || durable.CleanupAttempts[1].State != "pending" || durable.CleanupAttempts[1].GrantRunID != grant.GrantRunID {
					t.Fatal("grant was not durable before first read")
				}
				readChecked = true
				switch outcome {
				case "transport":
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
				case "budget":
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}
				case "mismatched_body":
					result.Body = append([]byte(nil), result.Body...)
					result.Body[0] ^= 1
				case "mismatched_length":
					result.Body = result.Body[:len(result.Body)-1]
				case "mismatched_token":
					result.Token.Value = `"another-current-etag"`
				}
				return result
			}
			sends := 0
			remove := func(context.Context, string, contract.Token) error { sends++; return nil }
			if err := inventory.recoverGrantedCleanup(context.Background(), store, remove, grant); err == nil || sends != 0 || !readChecked {
				t.Fatal("failed read sent delete or did not consume grant", err, sends)
			}
			if len(inventory.image.CleanupAttempts) != 2 || inventory.image.CleanupAttempts[1].State != "failed" || inventory.image.CleanupAttempts[1].Failure.Effect != "no_send" || !reflect.DeepEqual(original, *inventory.image.CleanupAttempts[0].Failure) {
				t.Fatal("read failure lost grant or original uncertainty")
			}
			store.readHook = nil
			next := awsInventoryGrant(t, inventory)
			next.GrantRunID = strings.Repeat("d", 32)
			if inventory.recoverGrantedCleanup(context.Background(), store, remove, next) == nil || sends != 0 {
				t.Fatal("failed recovery received another grant")
			}
			if count, err := inventory.image.unknownEffects(); err != nil || count != 1 {
				t.Fatal("read failure changed unknown effect attribution", count, err)
			}
			if _, ok := store.objects[key]; !ok {
				t.Fatal("failed read removed owned object")
			}
		})
	}
}

// full_only: false
func TestAWSGrantedCleanupRefusesUnqualifiedInventoryWithoutReads(t *testing.T) {
	for _, outcome := range []string{"snapshot", "unknown_create", "pending_create", "unjoined", "pending_delete", "permanent_failure", "changed_target", "changed_digest", "changed_length", "changed_condition", "wrong_prefix", "exhausted_ordinal", "bad_grant"} {
		t.Run(outcome, func(t *testing.T) {
			inventory, store, _, _ := failedAWSCleanupInventory(t, false)
			grant := awsInventoryGrant(t, inventory)
			switch outcome {
			case "snapshot":
				inventory.image.Binding += "-changed"
			case "unknown_create":
				inventory.image.Intents[0].State = "unknown"
			case "pending_create":
				inventory.image.Intents[0].State = "pending"
			case "unjoined":
				inventory.stopped = false
			case "pending_delete":
				inventory.image.CleanupAttempts[0].State = "pending"
				inventory.image.CleanupAttempts[0].Failure = nil
			case "permanent_failure":
				inventory.image.CleanupAttempts[0].Failure.Cause = "access_refused"
			case "changed_target":
				inventory.image.CleanupAttempts[0].Key += "-changed"
			case "changed_digest":
				inventory.image.CleanupAttempts[0].Digest = strings.Repeat("d", 64)
			case "changed_length":
				inventory.image.CleanupAttempts[0].Bytes++
			case "changed_condition":
				inventory.image.CleanupAttempts[0].Token = contract.Token{Family: contract.GCP, Value: "1"}
			case "wrong_prefix":
				store.desc.Prefix += "-changed"
			case "exhausted_ordinal":
				grant.Ordinal = 3
			case "bad_grant":
				grant.GrantLimitsSHA256 = "bad"
			}
			if err := inventory.save(); err != nil {
				t.Fatal(err)
			}
			if outcome != "snapshot" {
				grant.InventorySHA256 = awsInventoryGrant(t, inventory).InventorySHA256
			}
			reads, sends := store.reads, 0
			if err := inventory.recoverGrantedCleanup(context.Background(), store, func(context.Context, string, contract.Token) error { sends++; return nil }, grant); err == nil || sends != 0 || store.reads != reads {
				t.Fatal("unqualified inventory obtained effects", outcome, err, sends)
			}
			if len(inventory.image.CleanupAttempts) != 1 {
				t.Fatal("refused inventory mutated attempt history")
			}
		})
	}
}

// full_only: false
func TestAWSGrantedCleanupFailureNeverAllowsAnotherDelete(t *testing.T) {
	for _, outcome := range []string{"unknown_delete", "post_delete_read", "failed_persistence"} {
		t.Run(outcome, func(t *testing.T) {
			inventory, store, key, _ := failedAWSCleanupInventory(t, false)
			grant := awsInventoryGrant(t, inventory)
			original := *inventory.image.CleanupAttempts[0].Failure
			sends := 0
			remove := testDelete(store)
			if outcome == "failed_persistence" {
				store.readHook = func(_ string, _ contract.ReadResult) contract.ReadResult {
					if os.Rename(inventory.path, inventory.path+".retained") != nil || os.Mkdir(inventory.path, 0700) != nil {
						t.Fatal("controlled persistence failure unavailable")
					}
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}
				}
			}
			err := inventory.recoverGrantedCleanup(context.Background(), store, func(ctx context.Context, key string, token contract.Token) error {
				sends++
				if outcome == "unknown_delete" {
					return inventoryControlledTransportError{}
				}
				if err := remove(ctx, key, token); err != nil {
					return err
				}
				store.readHook = func(string, contract.ReadResult) contract.ReadResult {
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}
				}
				return nil
			}, grant)
			if err == nil || !reflect.DeepEqual(original, *inventory.image.CleanupAttempts[0].Failure) {
				t.Fatal("failed recovery lost uncertainty", err)
			}
			expected := 1
			if outcome == "failed_persistence" {
				expected = 0
			}
			if sends != expected || len(inventory.image.CleanupAttempts) != 2 {
				t.Fatal("recovery issued wrong number of deletes", sends)
			}
			if outcome == "failed_persistence" {
				var durable inventoryImage
				if readPrivateJSON(inventory.path+".retained", &durable) != nil || durable.CleanupAttempts[1].GrantRunID != grant.GrantRunID || durable.CleanupAttempts[1].State != "pending" {
					t.Fatal("persistence failure lost the consumed grant")
				}
			}
			store.readHook = nil
			if inventory.recoverGrantedCleanup(context.Background(), store, func(context.Context, string, contract.Token) error { sends++; return nil }, grant) == nil || sends != expected {
				t.Fatal("failed recovery repeated delete")
			}
			if outcome == "unknown_delete" {
				if _, ok := store.objects[key]; !ok {
					t.Fatal("controlled unknown delete altered object")
				}
			}
		})
	}
}

// full_only: false
func TestLiveProtocolCleanupGrantsBindProviderPolicy(t *testing.T) {
	inv, input := liveProtocolInvocation(t, "cleanup")
	inv = liveProtocolRecoveryOutput(t, inv)
	grant := controlledCleanupGrant(2)
	grant.GrantRunID = inv.RunID
	limits, err := json.Marshal(input.Limits)
	if err != nil {
		t.Fatal(err)
	}
	grant.GrantLimitsSHA256 = bodyDigest(limits)
	if liveFamily == contract.AWS {
		grant.InventorySHA256 = strings.Repeat("d", 64)
	}
	input.CleanupGrant = &grant
	if records.WriteJSON(inv.Input, input, 0400) != nil {
		t.Fatal("input unavailable")
	}
	if _, err := loadLiveInput(inv, "cleanup"); err != nil {
		t.Fatal("provider grant policy refused", err)
	}
	for _, members := range []int{0, 2, 32} {
		t.Run(fmt.Sprintf("historical-members-%d", members), func(t *testing.T) {
			historicalInv, historicalInput := inv, input
			historicalInv.Scenario = "state.single-value-update-preserves-other-values"
			historicalInput.Scenarios = []string{historicalInv.Scenario}
			body, err := json.Marshal(historicalInput)
			if err != nil {
				t.Fatal(err)
			}
			var wire map[string]json.RawMessage
			if err := json.Unmarshal(body, &wire); err != nil {
				t.Fatal(err)
			}
			wire["member_count"] = json.RawMessage(fmt.Sprint(members))
			if err := records.WriteJSON(inv.Input, wire, 0400); err != nil {
				t.Fatal(err)
			}
			if got, err := loadLiveInput(historicalInv, "cleanup"); err != nil || got.MemberCount != members {
				t.Fatal("historical grant changed numeric fixture evidence", got.MemberCount, err)
			}
			delete(wire, "cleanup_grant")
			if err := records.WriteJSON(inv.Input, wire, 0400); err != nil {
				t.Fatal(err)
			}
			if _, err := loadLiveInput(historicalInv, "cleanup"); err == nil {
				t.Fatal("historical input admitted without an explicit grant")
			}
		})
	}
	if liveFamily == contract.GCP {
		grant.Ordinal = 4
		if records.WriteJSON(inv.Input, input, 0400) != nil {
			t.Fatal("input unavailable")
		}
		if _, err := loadLiveInput(inv, "cleanup"); err != nil {
			t.Fatal("existing unknown-delete grant policy refused", err)
		}
		grant.Ordinal = 2
	}
	grant.InventorySHA256 = ""
	if liveFamily == contract.AWS {
		if records.WriteJSON(inv.Input, input, 0400) != nil {
			t.Fatal("input unavailable")
		}
		if _, err := loadLiveInput(inv, "cleanup"); err == nil {
			t.Fatal("AWS grant lacked inventory binding")
		}
	} else {
		grant.InventorySHA256 = strings.Repeat("d", 64)
		grant.Ordinal = 3
		if records.WriteJSON(inv.Input, input, 0400) != nil {
			t.Fatal("input unavailable")
		}
		if _, err := loadLiveInput(inv, "cleanup"); err == nil {
			t.Fatal("GCP bound grant admitted an extra ordinal")
		}
	}
	grant.Ordinal, grant.InventorySHA256 = 2, strings.Repeat("d", 64)
	input.CleanupRetry = &liveCleanupRetry{TargetIndex: 0, Ordinal: 2}
	if records.WriteJSON(inv.Input, input, 0400) != nil {
		t.Fatal("input unavailable")
	}
	if _, err := loadLiveInput(inv, "cleanup"); err == nil {
		t.Fatal("grant mixed with automatic retry")
	}
}

// full_only: false
func TestAWSFixtureCleanupWorkerClaimBindsOldAndCurrentEvidence(t *testing.T) {
	inv, input := liveProtocolInvocation(t, "cleanup")
	input.Settings.Provider = "aws"
	inv = liveProtocolRecoveryOutput(t, inv)
	grant := controlledCleanupGrant(2)
	grant.GrantRunID = inv.RunID
	inventoryPath := filepath.Join(inv.StateDir, "inventory.json")
	if records.WriteJSON(inventoryPath, map[string]string{"fixture": "inventory"}, 0600) != nil {
		t.Fatal("inventory unavailable")
	}
	digest, err := privateRecordSHA256(inventoryPath)
	if err != nil {
		t.Fatal(err)
	}
	grant.InventorySHA256 = digest
	input.CleanupGrant = &grant
	original := filepath.Dir(filepath.Dir(inv.StateDir))
	if records.WriteJSON(filepath.Join(original, "run.json"), map[string]string{"fixture": "original"}, 0600) != nil || os.Mkdir(filepath.Join(original, "cases"), 0700) != nil || records.WriteJSON(filepath.Join(original, "cases", "0000.json"), map[string]string{"fixture": "receipt"}, 0600) != nil {
		t.Fatal("old receipt unavailable")
	}
	originalHash, err := privateRecordSHA256(filepath.Join(original, "run.json"))
	if err != nil {
		t.Fatal(err)
	}
	grant.OriginalCaseReceiptSHA256, err = privateRecordSHA256(filepath.Join(original, "cases", "0000.json"))
	if err != nil {
		t.Fatal(err)
	}
	source := records.Source{Revision: strings.Repeat("b", 40)}
	current := filepath.Dir(filepath.Dir(inv.OutputDir))
	if records.WriteJSON(filepath.Join(current, "run.json"), map[string]any{"source": source}, 0600) != nil {
		t.Fatal("current source unavailable")
	}
	claimPath := filepath.Join(filepath.Dir(inv.StateDir), "aws-cleanup-grant.json")
	claim := map[string]any{"basis": map[string]any{"original_run_id": input.RunID, "original_run_sha256": originalHash, "original_case_receipt_sha256": grant.OriginalCaseReceiptSHA256, "entry": map[string]any{"scenario": inv.Scenario, "members": input.MemberCount, "sequence": 0, "repetition": 1, "smoke": false}, "target_index": grant.TargetIndex, "decision": "aws_retired_fixture_grant"}, "source": source, "grant": grant}
	if records.WriteJSON(claimPath, claim, 0600) != nil {
		t.Fatal("claim unavailable")
	}
	if err := admitFixtureCleanupClaim(inv, input, inventoryPath); err != nil {
		t.Fatal("exact claim refused", err)
	}
	for _, path := range []string{inventoryPath, filepath.Join(original, "run.json"), filepath.Join(original, "cases", "0000.json"), filepath.Join(current, "run.json"), claimPath} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if records.WriteJSON(path, map[string]string{"changed": fmt.Sprintf("%d", len(body))}, 0600) != nil {
			t.Fatal("mutation unavailable")
		}
		if err := admitFixtureCleanupClaim(inv, input, inventoryPath); err == nil {
			t.Fatal("changed claim evidence reached credentials", path)
		}
		if os.WriteFile(path, body, 0600) != nil {
			t.Fatal("restore unavailable")
		}
	}
}

// full_only: false
func TestAWSGrantedCleanupFinishesOtherAcknowledgedObjectsOnce(t *testing.T) {
	inventory, store, key, _ := failedAWSCleanupInventory(t, false, true)
	original := *inventory.image.CleanupAttempts[0].Failure
	grant := awsInventoryGrant(t, inventory)
	deletes := map[string]int{}
	otherKey := inventory.image.Prefix + "/zzz-not-yet-cleaned"
	expected := make(map[string]stored)
	for k, v := range store.objects {
		if k != key && k != otherKey {
			expected[k] = v
		}
	}
	remove := testDelete(store)
	send := func(ctx context.Context, key string, token contract.Token) error {
		deletes[key]++
		return remove(ctx, key, token)
	}
	if err := inventory.recoverGrantedCleanup(context.Background(), store, send, grant); err != nil {
		t.Fatal("eligible target refused other acknowledged objects", err)
	}
	if err := inventory.cleanup(context.Background(), store, send); err != nil {
		t.Fatal("other acknowledged objects unresolved", err)
	}
	if len(deletes) != 2 || deletes[key] != 1 || deletes[otherKey] != 1 || !reflect.DeepEqual(store.objects, expected) || len(inventory.image.CleanupAttempts) != 3 {
		t.Fatal("cleanup repeated a delete or left proved owned objects", deletes)
	}
	attempts := inventory.image.CleanupAttempts
	if attempts[1].Ordinal != 2 || attempts[1].Recovery != "aws_retired_fixture_grant" || attempts[2].Ordinal != 1 || attempts[2].Recovery != "" || !reflect.DeepEqual(original, *attempts[0].Failure) {
		t.Fatal("ordinary cleanup acquired replay authority or changed old uncertainty")
	}
	if count, err := inventory.image.unknownEffects(); err != nil || count != 0 {
		t.Fatal("multi-key cleanup unresolved", count, err)
	}
}

// full_only: false
func TestGrantedCleanupAfterAdmissionNoSend(t *testing.T) {
	for _, family := range []contract.Family{contract.GCP, contract.AWS} {
		for _, outcome := range []string{"present", "absent", "changed-body", "changed-token", "read-refused", "delete-failed"} {
			t.Run(fmt.Sprint(family)+"/"+outcome, func(t *testing.T) {
				inventory, store := testInventory(t)
				store.desc.Family = family
				body := []byte("independently owned configuration fixture")
				key, keyErr := contract.StoreConfigurationKeyForID(family, store.desc.Prefix, store.configuration.DomainID, contract.Hash(body))
				if keyErr != nil {
					t.Fatal(keyErr)
				}
				if inventory.write(t.Context(), key, body, "create", func() contract.WriteResult { return store.Create(t.Context(), key, body) }).Status != contract.WriteAcknowledged {
					t.Fatal("owned fixture unavailable")
				}
				inventory.stop()
				if inventory.cleanup(t.Context(), store, func(context.Context, string, contract.Token) error {
					return inventoryFailure("admission", "invalid_request", "no_send", errInventory, -1, 0)
				}) == nil || len(inventory.image.CleanupAttempts) != 1 {
					t.Fatal("original no-send refusal was not retained")
				}
				original := inventory.image.CleanupAttempts[0]
				if inventory.recoverCleanup(t.Context(), store, func(context.Context, string, contract.Token) error {
					t.Fatal("no-send failure obtained an automatic retry")
					return nil
				}, 0, 2) == nil {
					t.Fatal("no-send failure admitted an automatic retry")
				}
				grant := awsInventoryGrant(t, inventory)
				switch outcome {
				case "absent":
					if testDelete(store)(t.Context(), key, original.Token) != nil {
						t.Fatal("absence control failed")
					}
				case "changed-body":
					store.put(key, []byte("different owned bytes"))
				case "changed-token":
					store.put(key, body)
				}
				readStarted := false
				store.readHook = func(_ string, result contract.ReadResult) contract.ReadResult {
					if !readStarted {
						var saved inventoryImage
						if readPrivateJSON(inventory.path, &saved) != nil || len(saved.CleanupAttempts) != 2 || saved.CleanupAttempts[1].State != "pending" || saved.CleanupAttempts[1].Ordinal != 2 || saved.CleanupAttempts[1].Recovery != "admission_no_send_grant" {
							t.Fatal("one new grant was not durable before ownership read")
						}
						readStarted = true
					}
					if outcome == "read-refused" {
						return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
					}
					return result
				}
				sends := 0
				err := inventory.recoverGrantedCleanup(t.Context(), store, func(ctx context.Context, gotKey string, token contract.Token) error {
					sends++
					if gotKey != key || token != original.Token {
						t.Fatal("grant changed its saved object or condition")
					}
					if outcome == "delete-failed" {
						return inventoryControlledTransportError{}
					}
					return testDelete(store)(ctx, gotKey, token)
				}, grant)
				wantSends := 0
				if outcome == "present" || outcome == "delete-failed" {
					wantSends = 1
				}
				wantPass := outcome == "present" || outcome == "absent"
				if (err == nil) != wantPass || sends != wantSends || !readStarted || len(inventory.image.CleanupAttempts) != 2 || !reflect.DeepEqual(original, inventory.image.CleanupAttempts[0]) {
					t.Fatal("bounded no-send grant or original failure changed", err, sends)
				}
				unknown, countErr := inventory.image.unknownEffects()
				wantUnknown := int64(0)
				if outcome == "delete-failed" {
					wantUnknown = 1
				}
				if countErr != nil || unknown != wantUnknown {
					t.Fatal("new action effect was not retained", unknown, countErr)
				}
				if inventory.recoverGrantedCleanup(t.Context(), store, func(context.Context, string, contract.Token) error { sends++; return nil }, grant) == nil || sends != wantSends {
					t.Fatal("one-action grant was used again")
				}
			})
		}
	}
}

// full_only: false
func TestAdmissionNoSendGrantCannotReplaceUnknownLineage(t *testing.T) {
	inventory, _, _, _ := failedCleanupInventory(t, false)
	prior := inventory.image.CleanupAttempts[0]
	next := prior
	next.Ordinal, next.Recovery, next.State, next.Failure = 2, "admission_no_send_grant", "pending", nil
	next.GrantRunID, next.CaseSHA256, next.LimitsSHA256 = strings.Repeat("a", 32), strings.Repeat("b", 64), strings.Repeat("c", 64)
	inventory.image.CleanupAttempts = append(inventory.image.CleanupAttempts, next)
	if _, err := inventory.image.unknownEffects(); err == nil {
		t.Fatal("unknown DELETE lineage was admitted as a no-send grant")
	}
}

// full_only: false
func TestAdmissionNoSendCleanupWorkerBindsSerializedInputAndClaim(t *testing.T) {
	for _, outcome := range []string{"serialized-input", "claim-boundary", "missing-claim", "changed-run", "changed-receipt", "changed-inventory", "changed-source", "changed-grant", "wrong-decision", "unknown-lineage", "prior-settled", "prior-pending", "duplicate-target"} {
		t.Run(outcome, func(t *testing.T) {
			inv, input := liveProtocolInvocation(t, "cleanup")
			inv = liveProtocolRecoveryOutput(t, inv)
			inventory, store := testInventory(t)
			store.desc.Family, store.desc.Prefix = liveFamily, input.Prefix
			inventory.path = filepath.Join(inv.StateDir, "inventory.json")
			inventory.image.RunID, inventory.image.Prefix = input.RunID, input.Prefix
			inventory.image.Binding, inventory.image.Domain = settingsBinding(input.Settings), store.configuration.DomainID
			body := []byte("owned configuration boundary regression")
			key, err := contract.StoreConfigurationKeyForID(liveFamily, input.Prefix, inventory.image.Domain, contract.Hash(body))
			if err != nil || inventory.write(t.Context(), key, body, "create", func() contract.WriteResult { return store.Create(t.Context(), key, body) }).Status != contract.WriteAcknowledged {
				t.Fatal("owned target unavailable", err)
			}
			priorOwned := strings.HasPrefix(outcome, "prior-")
			if priorOwned {
				for index := 0; index < 3; index++ {
					ownedBody := []byte(fmt.Sprintf("owned administrative index %d", index))
					ownedKey := fmt.Sprintf("%s/%x/admin-index/%d/%x", input.Prefix, inventory.image.Domain, index, contract.Hash(ownedBody))
					if inventory.write(t.Context(), ownedKey, ownedBody, "create", func() contract.WriteResult { return store.Create(t.Context(), ownedKey, ownedBody) }).Status != contract.WriteAcknowledged {
						t.Fatal("prior owned object unavailable")
					}
				}
			}
			inventory.stop()
			if inventory.cleanup(t.Context(), store, func(ctx context.Context, gotKey string, token contract.Token) error {
				if gotKey != key {
					return testDelete(store)(ctx, gotKey, token)
				}
				return inventoryFailure("admission", "invalid_request", "no_send", errInventory, -1, 0)
			}) == nil {
				t.Fatal("original no-send attempt unavailable")
			}
			if outcome == "unknown-lineage" {
				fact := inventoryControlledTransportError{}.SafeHarnessFailure()
				inventory.image.CleanupAttempts[0].Failure = &fact
				if inventory.save() != nil {
					t.Fatal("changed lineage unavailable")
				}
			}
			if priorOwned {
				if len(inventory.image.CleanupAttempts) != 4 || inventory.image.CleanupAttempts[3].TargetIntent != 0 || inventory.image.CleanupAttempts[3].State != "failed" {
					t.Fatal("retained four-attempt target history differs")
				}
				for index := 0; index < 3; index++ {
					if inventory.image.CleanupAttempts[index].State != "settled" {
						t.Fatal("prior owned deletion unsettled")
					}
				}
			}
			if outcome == "prior-pending" {
				inventory.image.CleanupAttempts[0].State = "pending"
			}
			if outcome == "duplicate-target" {
				inventory.image.CleanupAttempts = append(inventory.image.CleanupAttempts, inventory.image.CleanupAttempts[0])
			}
			if inventory.save() != nil {
				t.Fatal("retained history unavailable")
			}
			grant := controlledCleanupGrant(2)
			grant.GrantRunID = inv.RunID
			limits, _ := json.Marshal(input.Limits)
			grant.GrantLimitsSHA256 = bodyDigest(limits)
			grant.InventorySHA256, err = privateRecordSHA256(inventory.path)
			if err != nil {
				t.Fatal(err)
			}
			original := filepath.Dir(filepath.Dir(inv.StateDir))
			casePath := filepath.Join(original, "cases", "0000.json")
			if records.WriteJSON(filepath.Join(original, "run.json"), map[string]string{"fixture": "original"}, 0600) != nil || os.Mkdir(filepath.Dir(casePath), 0700) != nil || records.WriteJSON(casePath, map[string]string{"fixture": "joined receipt"}, 0600) != nil {
				t.Fatal("old evidence unavailable")
			}
			originalHash, err := privateRecordSHA256(filepath.Join(original, "run.json"))
			if err != nil {
				t.Fatal(err)
			}
			grant.OriginalCaseReceiptSHA256, err = privateRecordSHA256(casePath)
			if err != nil {
				t.Fatal(err)
			}
			source := records.Source{Revision: strings.Repeat("b", 40)}
			currentPath := filepath.Join(filepath.Dir(filepath.Dir(inv.OutputDir)), "run.json")
			if records.WriteJSON(currentPath, map[string]any{"source": source}, 0600) != nil {
				t.Fatal("new source unavailable")
			}
			claimPath := filepath.Join(filepath.Dir(inv.StateDir), "admission-cleanup-grant.json")
			decision := "admission_no_send_grant"
			if outcome == "wrong-decision" {
				decision = "aws_retired_fixture_grant"
			}
			claimGrant := grant
			if outcome == "changed-grant" {
				claimGrant.TargetIndex++
			}
			claim := map[string]any{"basis": map[string]any{"original_run_id": input.RunID, "original_run_sha256": originalHash, "original_case_receipt_sha256": grant.OriginalCaseReceiptSHA256, "entry": map[string]any{"scenario": inv.Scenario, "members": input.MemberCount, "sequence": 0, "repetition": 1, "smoke": false}, "target_index": grant.TargetIndex, "decision": decision}, "source": source, "grant": claimGrant}
			if records.WriteJSON(claimPath, claim, 0600) != nil {
				t.Fatal("claim unavailable")
			}
			input.CleanupGrant = &grant
			if records.WriteJSON(inv.Input, input, 0400) != nil {
				t.Fatal("serialized input unavailable")
			}
			loaded, err := loadLiveInput(inv, "cleanup")
			if err != nil {
				t.Fatal("bounded serialized no-send grant refused", err)
			}
			input = loaded
			if outcome == "serialized-input" {
				return
			}
			changed := map[string]string{"changed-run": filepath.Join(original, "run.json"), "changed-receipt": casePath, "changed-inventory": inventory.path, "changed-source": currentPath}
			if path := changed[outcome]; path != "" && records.WriteJSON(path, map[string]string{"changed": "evidence"}, 0600) != nil {
				t.Fatal("changed evidence unavailable")
			}
			if outcome == "missing-claim" && os.Remove(claimPath) != nil {
				t.Fatal("claim removal failed")
			}
			err = admitFixtureCleanupClaim(inv, input, inventory.path)
			if (outcome == "claim-boundary" || outcome == "prior-settled") != (err == nil) {
				t.Fatal("pre-credential claim admission differs from exact retained evidence", err)
			}
		})
	}
}

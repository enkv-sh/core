package core

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/testsupport/nativeprocess"
)

// full_only: false
func TestPublicCapacityGCCaptureKeepsSeparateQueryAndEffectCapabilities(t *testing.T) {
	domain := contract.ID{1}
	target := contract.GCTarget{Object: contract.StoreObjectIdentity{Namespace: contract.StorePageObject, Kind: contract.RecipientKind, ObjectID: contract.ID{6}}, Length: 20, Digest: contract.ID{7}, Token: contract.Token{Family: contract.GCP, Value: "17"}}
	key, err := contract.StoreObjectKey("fixture", domain, target.Object)
	if err != nil {
		t.Fatal(err)
	}
	digest := contract.Hash([]byte(key))
	keyHash := hex.EncodeToString(digest[:])
	base := []nativeprocess.Event{{Kind: "source-kind", SourceKind: "gcp-impersonated-adc", Count: 1, Matched: true}, {Kind: "http-start", Operation: "store-read", Sequence: 1, Sent: true, ObjectKeySHA256: keyHash}, {Kind: "http-return", Operation: "store-read", Sequence: 1, Sent: true, Status: 200, ObjectKeySHA256: keyHash}}
	query := append(append([]nativeprocess.Event(nil), base...), nativeprocess.Event{Kind: "http-start", Operation: "store-list", Sequence: 2, Sent: true}, nativeprocess.Event{Kind: "http-return", Operation: "store-list", Sequence: 2, Sent: true, Status: 200}, nativeprocess.Event{Kind: "footer"})
	plan := contract.GCPlan{DomainID: domain, Targets: []contract.GCTarget{target}}
	mutation := append([]nativeprocess.Event(nil), base...)
	for i := uint64(2); i <= 6; i++ {
		operation, object := "head-write", strings.Repeat("a", 64)
		if i == 6 {
			operation, object = "store-delete", keyHash
		}
		e := nativeprocess.Event{Operation: operation, Sequence: i, Sent: true, ObjectKeySHA256: object, LogicalConditionKind: "match", LogicalConditionValue: []byte("17"), WireConditionKind: "gcp-generation-match", WireConditionValue: []byte("17")}
		e.Kind = "http-start"
		mutation = append(mutation, e)
		mutation = append(mutation, nativeprocess.Event{Kind: "http-return", Operation: operation, Sequence: i, Sent: true, Status: 200, ObjectKeySHA256: object})
		e.Kind, e.WriteStatus = "store-result", uint8(contract.WriteAcknowledged)
		mutation = append(mutation, e)
	}
	mutation = append(mutation, nativeprocess.Event{Kind: "footer"})
	for _, row := range []struct {
		name  string
		query bool
	}{{"query", true}, {"query-no-list", true}, {"query-two-list", true}, {"query-kms", true}, {"mutation", false}, {"mutation-private", false}, {"mutation-recovery", false}, {"mutation-wrong-token", false}, {"mutation-wrong-key", false}, {"mutation-missing-close", false}, {"unjoined", true}} {
		t.Run(row.name, func(t *testing.T) {
			events := append([]nativeprocess.Event(nil), mutation...)
			var original *contract.GCPlan = &plan
			if row.query {
				events, original = append([]nativeprocess.Event(nil), query...), nil
			}
			switch row.name {
			case "query-no-list":
				events = append(append([]nativeprocess.Event(nil), base...), nativeprocess.Event{Kind: "footer"})
			case "query-two-list":
				extra := []nativeprocess.Event{{Kind: "http-start", Operation: "store-list", Sequence: 3, Sent: true}, {Kind: "http-return", Operation: "store-list", Sequence: 3, Sent: true, Status: 200}}
				events = append(append(events[:len(events)-1], extra...), nativeprocess.Event{Kind: "footer"})
			case "query-kms":
				events[1].Operation, events[2].Operation = "kms-public", "kms-public"
			case "mutation-private", "mutation-recovery":
				events[1].Operation, events[2].Operation = "kms-decrypt", "kms-decrypt"
				events[1].Role, events[2].Role = "authority", "authority"
				if row.name == "mutation-recovery" {
					events[1].Operation, events[2].Operation = "kms-sign", "kms-sign"
					events[1].Role, events[2].Role = "recovery-signing", "recovery-signing"
				}
			case "mutation-wrong-token":
				for i := range events {
					if events[i].Operation == "store-delete" {
						events[i].LogicalConditionValue, events[i].WireConditionValue = []byte("18"), []byte("18")
					}
				}
			case "mutation-wrong-key":
				for i := range events {
					if events[i].Operation == "store-delete" {
						events[i].ObjectKeySHA256 = strings.Repeat("b", 64)
					}
				}
			case "mutation-missing-close":
				events = append(events[:12], events[15:]...)
			case "unjoined":
				events = events[:len(events)-1]
			}
			var encoded bytes.Buffer
			for _, event := range events {
				if err := json.NewEncoder(&encoded).Encode(event); err != nil {
					t.Fatal(err)
				}
			}
			capture, err := nativeprocess.InspectCapture(encoded.Bytes())
			got := err == nil && publicCapacityGCCapture(capture, row.query, original, "fixture", domain)
			if got != (row.name == "query" || row.name == "mutation") {
				t.Fatal("capacity/GC capability or join boundary changed")
			}
		})
	}
}

// full_only: false
func TestPublicCapacityGCFreshFactsRequireExactConditionAndRun(t *testing.T) {
	id := strings.Repeat("1", 64)
	valid := publicProcessFacts{RunID: "run", Prefix: "fixture", Domain: id, ExpectReady: true,
		CapacityGC: &publicCapacityGCFacts{RunID: "run", Prefix: "fixture", Domain: id, Operation: id, PlanDigest: id, Revision: id, Snapshot: id, RootDigest: id, ValueBase64: base64.StdEncoding.EncodeToString([]byte("gc-three")), TargetCount: 3, PlanArtifact: "capacity-gc-plan-fixed/plan.bin"}}
	for _, name := range []string{"valid", "missing", "alien-condition", "run", "prefix", "domain", "revision", "value", "target-limit", "not-ready", "inspection", "operator", "replacement", "output"} {
		t.Run(name, func(t *testing.T) {
			facts, gc := valid, *valid.CapacityGC
			facts.CapacityGC = &gc
			condition := "capacity-gc"
			switch name {
			case "missing":
				facts.CapacityGC = nil
			case "alien-condition":
				condition = "inspection-receipts"
			case "run":
				gc.RunID = "other"
			case "prefix":
				gc.Prefix = "other"
			case "domain":
				gc.Domain = strings.Repeat("2", 64)
			case "revision":
				gc.Revision = "bad"
			case "value":
				gc.ValueBase64 = base64.StdEncoding.EncodeToString([]byte("other"))
			case "target-limit":
				gc.TargetCount = 65
			case "not-ready":
				facts.ExpectReady = false
			case "inspection":
				facts.Inspection = &publicInspectionFacts{}
			case "operator":
				facts.Operator = &publicOperatorFacts{}
			case "replacement":
				facts.Replacement = &publicReplacementFacts{}
			case "output":
				facts.Outputs = []publicOutputCoordinate{{}}
			}
			if publicCapacityGCFreshFactsValid(condition, facts, "run", "fixture") != (name == "valid") {
				t.Fatal("capacity/GC fresh fact union admitted foreign or mixed facts")
			}
		})
	}
}

// full_only: false
func TestPublicCapacityGCCompleteResultUsesProductEffectToken(t *testing.T) {
	id := func(first byte) string { v := contract.ID{first}; return hex.EncodeToString(v[:]) }
	target := contract.GCTarget{Object: contract.StoreObjectIdentity{Namespace: contract.StorePageObject, Kind: contract.RecipientKind, ObjectID: contract.ID{6}}, Length: 20, Digest: contract.ID{7}, Token: contract.Token{Family: contract.GCP, Value: "17"}}
	// This is a fixed public consumer fixture, not a production encoder call or
	// an assertion that these structural facts came from a physical history.
	value := map[string]any{
		"schema": "ProductResult/v1", "operation_kind": "gc-apply", "operation_id": id(5), "request_identity": id(9),
		"state_result": "success", "effect_summary": "effect-complete", "output_summary": "not-applicable", "operation_payload": "CleanupPayload/v1",
		"payload": map[string]any{"schema": "CleanupPayload/v1", "plan_digest": id(11), "active": false, "closed": true, "selection_uncertain": false,
			"remaining_count": 0, "progress_ordinal": 3, "sibling_results": map[string]any{"count": 1, "root_digest": id(12)},
			"targets": []any{map[string]any{"namespace": 1, "kind": 2, "index": 0, "object_id": id(6), "length": 20, "digest": id(7),
				"selected": map[string]any{"consumed": 1, "disposition": 3, "evidence_digest": id(8)}, "observed": 3, "observed_evidence": id(8),
				"observation_reason": 0, "permission_owned": true, "delete_attempted": true, "delete_result": map[string]any{"status": 1, "reason": 0, "not_sent": false}}}},
	}
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	publicCapacityGCCheckApplied(t, publicChildResult{Body: body}, contract.GCPlan{Targets: []contract.GCTarget{target}}, contract.ID{11})
}

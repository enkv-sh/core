package compositionfull

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func administrativeGCResultID(n uint32) (id contract.ID) {
	id[0] = 1
	binary.BigEndian.PutUint32(id[28:], n)
	return id
}

func administrativeGCResultHex(n uint32) string {
	id := administrativeGCResultID(n)
	return hex.EncodeToString(id[:])
}

// This is a structural renderer fixture, not an executed permission history
// or a reachable selected-capacity claim.
func administrativeGCListResult(t *testing.T) AbandonmentResult {
	t.Helper()
	r := administrativeListResult(2)
	progress := &contract.GCProgress{
		PlanDigest: administrativeGCResultID(200), RequestIdentity: administrativeGCResultID(201), ObservationDigest: administrativeGCResultID(202),
		TargetsDescriptor: contract.GCDescriptor{Digest: administrativeGCResultID(203), Length: 25621, Count: 256},
		RemainingCount:    213, Ordinal: 17, Targets: make([]contract.GCTargetProgress, 256),
	}
	for i := range progress.Targets {
		row := contract.GCTargetProgress{Disposition: contract.GCTargetPending}
		switch i % 6 {
		case 1:
			row.Consumed, row.Disposition = 1, contract.GCTargetUnknown
		case 2:
			row.Consumed, row.Disposition, row.EvidenceDigest = 3, contract.GCTargetAbsent, administrativeGCResultID(uint32(1000+i))
		case 3:
			row.Disposition = contract.GCTargetChanged
		case 4:
			row.Consumed, row.Disposition = 2, contract.GCTargetTerminalFailure
		case 5:
			row.Consumed, row.Disposition, row.EvidenceDigest = 2, contract.GCTargetRetryableNotSent, administrativeGCResultID(uint32(1000+i))
		}
		progress.Targets[i] = row
	}
	if !progress.Valid() {
		t.Fatal("invalid maximum-length structural progress fixture")
	}
	r.Operation.List.Groups[1] = core.AuthorityGroup{
		GroupID: administrativeGCResultID(101), OwnerID: administrativeGCResultID(101), TargetID: administrativeGCResultID(101),
		OwnerKind: contract.AdministrativeGC, SelectedEvidenceSummary: 55, ChargedPages: 3, ChargedBytes: 12345,
		BlocksChangedMutation: true, Selectable: true, RelatedGroupIndexes: []uint16{0}, GC: progress,
	}
	return r
}

// The complete expected projection uses fixed wire names and test-owned
// values. It does not call the production progress, evidence or ID formatter.
func administrativeGCListExpected(t *testing.T) any {
	t.Helper()
	h := administrativeGCResultHex
	rows := make([]any, 256)
	consumed := []int{0, 1, 3, 0, 2, 2}
	for i := range rows {
		evidence := ""
		if i%6 == 2 || i%6 == 5 {
			evidence = h(uint32(1000 + i))
		}
		rows[i] = map[string]any{"consumed": consumed[i%6], "disposition": i%6 + 1, "evidence_digest": evidence}
	}
	peer := map[string]any{
		"group_id": h(100), "kind": "generated-duty", "owner_id": h(20), "target_id": h(21), "owner_kind": 2, "duty_kind": 1,
		"selected_evidence_summary": 1, "original_evidence_facts": []string{"missing"}, "charged_pages": 0, "charged_bytes": 0,
		"blocks_changed_mutation": false, "selectable": false, "warnings": []string{}, "related_group_ids": []string{},
	}
	gc := map[string]any{
		"group_id": h(101), "kind": "gc", "owner_id": h(101), "target_id": h(101), "owner_kind": 7, "duty_kind": 0,
		"selected_evidence_summary": 55, "original_evidence_facts": []string{"missing", "qualified-unknown", "terminal-failure", "contradiction", "qualified-no-effect-or-scoped-unusability"},
		"charged_pages": 3, "charged_bytes": 12345, "blocks_changed_mutation": true, "selectable": true, "warnings": []string{}, "related_group_ids": []string{h(100)},
		"gc": map[string]any{
			"plan_digest": h(200), "targets_digest": h(203), "targets_length": 25621, "target_count": 256,
			"request_identity": h(201), "observation_digest": h(202), "remaining_count": 213, "progress_ordinal": 17, "targets": rows,
		},
	}
	expected := map[string]any{
		"schema": "ProductResult/v1", "operation_kind": "abandon-list", "state_result": "success", "effect_summary": "not-applicable", "output_summary": "not-applicable",
		"operation_id": h(14), "request_id": h(12), "domain_id": h(4),
		"request_identity": map[string]any{
			"schema": "QueryRequestIdentity/v1", "operation_kind": "abandon-list", "semantic_operation": 15, "expected_domain_id": h(4),
			"store_id": h(5), "coordinate_id": h(6), "non_body_id": h(7), "public_basis_digest": h(9), "store_descriptor_digest": h(8),
			"source":      map[string]any{"file_id": h(1), "format": 1, "editable_digest": h(2), "generated_digest": h(3), "editable_length": 1, "generated_length": 1, "has_generated": true},
			"observation": map[string]any{"domain_id": h(4), "head_revision_id": h(10), "snapshot_id": h(11)}, "request_nonce": h(12), "digest": h(13),
		},
		"result":           map[string]any{"outcome": "observed_current", "reason": "none", "commit_may_have_occurred": false},
		"evidence_ceiling": "canonical", "replay_identity": "none", "commit_may_have_occurred": false, "warning_summary": []string{},
		"delivery": map[string]any{"plan_created": false, "plan_synced": false, "plan_readback": false, "plan_failed": false, "cleanup_failed": false},
		"effects":  []any{}, "outputs": []any{}, "duties": []any{}, "hazards": []any{}, "capsule_policy": "none", "operation_payload": "InspectionPayload/v1",
		"payload": map[string]any{"schema": "InspectionPayload/v1", "view": "administrative-list", "revision": h(10), "snapshot": h(11), "current_warning_summary": []string{}, "targets": []any{peer, gc}, "abandonments": []any{}},
	}
	encoded, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	var normalized any
	if err := json.Unmarshal(encoded, &normalized); err != nil {
		t.Fatal(err)
	}
	return normalized
}

// full_only: false
func TestAdministrativeListRendersCompleteBoundedGCProgress(t *testing.T) {
	r := administrativeGCListResult(t)
	expected := administrativeGCListExpected(t)
	for _, mode := range []struct {
		name  string
		human bool
	}{{"json", false}, {"human", true}} {
		t.Run(mode.name, func(t *testing.T) {
			write := WriteAdministrativeJSON
			if mode.human {
				write = WriteAdministrativeHuman
			}
			var out bytes.Buffer
			if err := write(t.Context(), &out, r); err != nil {
				t.Fatal("valid complete GC progress rejected", err)
			}
			if out.Len() == 0 || out.Len() > 64<<10 {
				t.Fatal("bounded fixture output length changed", out.Len())
			}
			body := out.Bytes()
			if mode.human {
				for _, want := range []string{"abandon-list: success\n", "Target " + administrativeGCResultHex(101) + " (gc)", "GC progress: 213 remaining; ordinal=17; targets=256.\n", "GC target 255: changed; transmissions=0/3.\n", "Evidence: missing, qualified-unknown, terminal-failure, contradiction, qualified-no-effect-or-scoped-unusability.\n"} {
					if !strings.Contains(out.String(), want) {
						t.Error("human output lost GC decision facts", want)
					}
				}
				if strings.Count(out.String(), "GC target ") != 256 || strings.Contains(out.String(), `"schema"`) {
					t.Fatal("human output lost progress rows or dumped structured evidence")
				}
			} else {
				var actual any
				if err := json.Unmarshal(body, &actual); err != nil || !reflect.DeepEqual(actual, expected) {
					t.Fatalf("complete GC administrative projection differs: error=%v actual=%v expected=%v", err, actual, expected)
				}
			}
			var sink administrativeCountingSink
			if err := write(t.Context(), &sink, r); err != nil || sink.bytes != uint64(out.Len()) || sink.largest > 43419 {
				t.Fatal("stream lost bytes or exceeded the independently derived single-row envelope", err, sink.bytes, out.Len(), sink.largest)
			}
			// Copy every mutated owner so the positive and human fixtures retain
			// their original last row. Only the 256th allowance counter is damaged.
			damaged := r
			list := *r.Operation.List
			list.Groups = append([]core.AuthorityGroup(nil), list.Groups...)
			progress := *list.Groups[1].GC
			progress.Targets = append([]contract.GCTargetProgress(nil), progress.Targets...)
			progress.Targets[255].Consumed = 4
			list.Groups[1].GC = &progress
			damaged.Operation.List = &list
			out.Reset()
			if err := write(t.Context(), &out, damaged); !errors.Is(err, ErrAbandonmentResult) || out.Len() != 0 {
				t.Fatal("invalid final GC row escaped whole-result preflight", err, out.Len())
			}
			var rejected administrativeCountingSink
			if err := write(t.Context(), &rejected, damaged); !errors.Is(err, ErrAbandonmentResult) || rejected.bytes != 0 {
				t.Fatal("invalid final GC row reached streaming output", err, rejected.bytes)
			}
			if r.Operation.List.Groups[1].GC.Targets[255].Consumed != 0 {
				t.Fatal("damage test changed the positive fixture")
			}
		})
	}
}

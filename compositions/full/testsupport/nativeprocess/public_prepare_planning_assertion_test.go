package nativeprocess

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	stateformat "enkv.sh/core/format"
	observer "enkv.sh/core/testsupport/nativeprocess"
)

func nativePlanningInstallationRequirementsMatch(body []byte) bool {
	var result struct {
		Requirements json.RawMessage `json:"installation_requirements"`
	}
	if json.Unmarshal(body, &result) != nil {
		return false
	}
	var requirements struct {
		Complete    bool              `json:"complete"`
		Differences []json.RawMessage `json:"differences"`
	}
	decoder := json.NewDecoder(bytes.NewReader(result.Requirements))
	decoder.DisallowUnknownFields()
	return decoder.Decode(&requirements) == nil && requirements.Complete && requirements.Differences != nil && len(requirements.Differences) == 0
}

func nativeMaximumPlanning(t *testing.T, child workflowChild, entries map[string]contract.ValueEntry, head stateformat.Head, root stateformat.Root, private bool) bool {
	t.Helper()
	var result struct {
		Schema  string `json:"schema"`
		Kind    string `json:"operation_kind"`
		State   string `json:"state_result"`
		Effect  string `json:"effect_summary"`
		Output  string `json:"output_summary"`
		Context struct {
			Operation string `json:"operation"`
		} `json:"context"`
		Observation struct {
			Domain   string `json:"domain_id"`
			Revision string `json:"head_revision_id"`
			Snapshot string `json:"snapshot_id"`
		} `json:"observation"`
		Payload struct {
			Schema              string            `json:"schema"`
			Verdict             string            `json:"verdict"`
			EvidenceLimit       string            `json:"evidence_limit"`
			DiagnosticsComplete bool              `json:"diagnostics_complete"`
			Diagnostics         []json.RawMessage `json:"diagnostics"`
			GeneratedEntries    []map[string]any  `json:"generated_entries"`
			PrivateEntries      []json.RawMessage `json:"private_entries"`
			PrivateComplete     bool              `json:"private_complete"`
			DisplayDelivery     string            `json:"display_delivery"`
			SelectedRecords     *uint32           `json:"selected_records"`
			CompletedRecords    *uint32           `json:"completed_records"`
		} `json:"payload"`
	}
	if child.code != 0 || json.Unmarshal(child.out, &result) != nil || !nativePlanningInstallationRequirementsMatch(child.out) || result.Schema != "ProductResult/v1" || result.State != "success" || result.Context.Operation != result.Kind || result.Effect != "not-applicable" || result.Output != "not-applicable" || result.Payload.Verdict != "match" || !result.Payload.DiagnosticsComplete || result.Payload.Diagnostics == nil || len(result.Payload.Diagnostics) != 0 {
		t.Logf("maximum planning common facts differ: exit=%d schema=%t success=%t operation=%t effect=%t output=%t requirements=%t match=%t diagnostics_complete=%t diagnostics_present=%t diagnostics=%d", child.code, result.Schema == "ProductResult/v1", result.State == "success", result.Context.Operation == result.Kind, result.Effect == "not-applicable", result.Output == "not-applicable", nativePlanningInstallationRequirementsMatch(child.out), result.Payload.Verdict == "match", result.Payload.DiagnosticsComplete, result.Payload.Diagnostics != nil, len(result.Payload.Diagnostics))
		return false
	}
	if result.Observation.Domain != hex.EncodeToString(root.Domain[:]) || result.Observation.Revision != hex.EncodeToString(head.Core.Revision[:]) || result.Observation.Snapshot != hex.EncodeToString(root.Snapshot[:]) || len(result.Payload.GeneratedEntries) != len(entries) {
		t.Logf("maximum planning observation differs: domain=%t revision=%t snapshot=%t rows=%d expected_rows=%d", result.Observation.Domain == hex.EncodeToString(root.Domain[:]), result.Observation.Revision == hex.EncodeToString(head.Core.Revision[:]), result.Observation.Snapshot == hex.EncodeToString(root.Snapshot[:]), len(result.Payload.GeneratedEntries), len(entries))
		return false
	}
	if private {
		if result.Kind != "plan-supplied-values" || result.Payload.Schema != "PlanningPayload/v1" || result.Payload.EvidenceLimit != "Fixed authenticated public settings, requested generated intent and supported supplied-secret relations only; future generated content is unavailable and public secret content is unchecked. Excludes apply admission or no-op, performed effects, output actions, remote state, and continued currentness." || !result.Payload.PrivateComplete || result.Payload.PrivateEntries == nil || len(result.Payload.PrivateEntries) != 0 || result.Payload.DisplayDelivery != "not-requested" || result.Payload.SelectedRecords == nil || *result.Payload.SelectedRecords != 0 || result.Payload.CompletedRecords == nil || *result.Payload.CompletedRecords != 0 {
			t.Log("maximum planning private scope, payload schema or evidence limit differs")
			return false
		}
	} else if result.Kind != "compare-public-configuration" || result.Payload.Schema != "ComparisonPayload/v1" || result.Payload.EvidenceLimit != "Fixed authenticated public settings and requested generated intent only; future generated content is unavailable and secret-value equality is unchecked. Excludes apply admission or no-op, performed effects or credential validity, remote output contents or IAM, historical application, and continued currentness." {
		t.Log("maximum planning public scope, payload schema or evidence limit differs")
		return false
	}
	previous := ""
	for index, row := range result.Payload.GeneratedEntries {
		name, ok := row["name"].(string)
		entry, exists := entries[name]
		if !ok || !exists || index > 0 && name <= previous {
			t.Logf("maximum planning row identity or order differs: row=%d name_present=%t expected_entry=%t", index, ok, exists)
			return false
		}
		previous = name
		want := map[string]any{
			"name": name, "requested_action": "unchanged",
			"current_source": "generated", "requested_source": "generated",
			"current_confidentiality": "secret", "requested_confidentiality": "secret",
			"current_incarnation_id": hex.EncodeToString(entry.Incarnation[:]),
			"current_generation_id":  hex.EncodeToString(entry.Generated.GenerationID[:]),
			"current_epoch":          float64(0), "requested_epoch": float64(0),
			"current_lifecycle_mode": "managed", "requested_lifecycle_mode": "managed",
			"current_retirement_policy": "manual", "requested_retirement_policy": "manual",
			"changed_public_fields": []any{}, "retirement_consequence": "none", "observed_blockers": []any{},
			"active_operation_id": nil, "retiring_duty_id": nil, "retiring_incarnation_id": nil,
			"retiring_generation_id": nil, "retiring_epoch": nil, "retiring_resource_id": nil,
			"retiring_original_operation_id": nil, "retiring_original_attempt_id": nil,
			"future_content": "unavailable", "public_secret_content": "unchecked",
		}
		if !reflect.DeepEqual(row, want) {
			for key, expected := range want {
				actual, present := row[key]
				if !present || !reflect.DeepEqual(actual, expected) {
					t.Logf("maximum planning row field differs: row=%d field=%s present=%t", index, key, present)
				}
			}
			t.Logf("maximum planning row shape differs: row=%d fields=%d expected_fields=%d", index, len(row), len(want))
			return false
		}
	}
	requests := 0
	for _, event := range child.capture.Events {
		if event.Kind == "http-start" {
			requests++
			if !event.Sent || event.Operation != "head-read" && event.Operation != "store-read" {
				t.Log("maximum planning includes an unsent or non-read request")
				return false
			}
		}
		if event.Kind == "plaintext" || event.Kind == "recovery-plaintext" {
			t.Log("maximum planning includes plaintext evidence")
			return false
		}
	}
	if requests == 0 {
		t.Log("maximum planning has no authenticated read request")
		return false
	}
	return true
}

// IDs have the indicated first byte and 31 zero bytes; rows are independent
// literals from the public result contract, not production renderer output.
const nativeMaximumPlanningFixture = `{
  "schema": "ProductResult/v1",
  "operation_kind": "plan-supplied-values",
  "state_result": "success",
  "effect_summary": "not-applicable",
  "output_summary": "not-applicable",
  "context": {
    "operation": "plan-supplied-values",
    "request_id": "0800000000000000000000000000000000000000000000000000000000000000",
    "expected_domain_id": "0100000000000000000000000000000000000000000000000000000000000000"
  },
  "observation": {
    "domain_id": "0100000000000000000000000000000000000000000000000000000000000000",
    "head_revision_id": "0200000000000000000000000000000000000000000000000000000000000000",
    "snapshot_id": "0300000000000000000000000000000000000000000000000000000000000000"
  },
  "installation_requirements": {"complete": true, "differences": []},
  "payload": {
    "schema": "PlanningPayload/v1",
    "verdict": "match",
    "diagnostics_complete": true,
    "evidence_limit": "Fixed authenticated public settings, requested generated intent and supported supplied-secret relations only; future generated content is unavailable and public secret content is unchecked. Excludes apply admission or no-op, performed effects, output actions, remote state, and continued currentness.",
    "checked_scope": [
      {
        "family": "generated",
        "status": "complete"
      }
    ],
    "diagnostics": [],
    "generated_entries": [
      {
        "name": "first",
        "requested_action": "unchanged",
        "current_source": "generated",
        "requested_source": "generated",
        "current_confidentiality": "secret",
        "requested_confidentiality": "secret",
        "current_incarnation_id": "0400000000000000000000000000000000000000000000000000000000000000",
        "current_generation_id": "0500000000000000000000000000000000000000000000000000000000000000",
        "current_epoch": 0,
        "requested_epoch": 0,
        "current_lifecycle_mode": "managed",
        "requested_lifecycle_mode": "managed",
        "current_retirement_policy": "manual",
        "requested_retirement_policy": "manual",
        "changed_public_fields": [],
        "retirement_consequence": "none",
        "observed_blockers": [],
        "active_operation_id": null,
        "retiring_duty_id": null,
        "retiring_incarnation_id": null,
        "retiring_generation_id": null,
        "retiring_epoch": null,
        "retiring_resource_id": null,
        "retiring_original_operation_id": null,
        "retiring_original_attempt_id": null,
        "future_content": "unavailable",
        "public_secret_content": "unchecked"
      },
      {
        "name": "second",
        "requested_action": "unchanged",
        "current_source": "generated",
        "requested_source": "generated",
        "current_confidentiality": "secret",
        "requested_confidentiality": "secret",
        "current_incarnation_id": "0600000000000000000000000000000000000000000000000000000000000000",
        "current_generation_id": "0700000000000000000000000000000000000000000000000000000000000000",
        "current_epoch": 0,
        "requested_epoch": 0,
        "current_lifecycle_mode": "managed",
        "requested_lifecycle_mode": "managed",
        "current_retirement_policy": "manual",
        "requested_retirement_policy": "manual",
        "changed_public_fields": [],
        "retirement_consequence": "none",
        "observed_blockers": [],
        "active_operation_id": null,
        "retiring_duty_id": null,
        "retiring_incarnation_id": null,
        "retiring_generation_id": null,
        "retiring_epoch": null,
        "retiring_resource_id": null,
        "retiring_original_operation_id": null,
        "retiring_original_attempt_id": null,
        "future_content": "unavailable",
        "public_secret_content": "unchecked"
      }
    ],
    "private_entries": [],
    "private_complete": true,
    "display_delivery": "not-requested",
    "selected_records": 0,
    "completed_records": 0
  }
}`

func nativeMaximumPlanningInputs() (workflowChild, map[string]contract.ValueEntry, stateformat.Head, stateformat.Root) {
	entries := map[string]contract.ValueEntry{
		"first":  {Name: "first", Incarnation: contract.ID{4}, Generated: contract.GeneratedEntryMetadata{GenerationID: contract.ID{5}, LifecycleMode: contract.GeneratorLifecycleManaged}},
		"second": {Name: "second", Incarnation: contract.ID{6}, Generated: contract.GeneratedEntryMetadata{GenerationID: contract.ID{7}, LifecycleMode: contract.GeneratorLifecycleManaged}},
	}
	var head stateformat.Head
	head.Core.Revision = contract.ID{2}
	root := stateformat.Root{Domain: contract.ID{1}, Snapshot: contract.ID{3}}
	child := workflowChild{out: []byte(nativeMaximumPlanningFixture), capture: observer.Capture{Events: []observer.Event{{Kind: "http-start", Operation: "head-read", Sent: true}}}}
	return child, entries, head, root
}

// full_only: false
func TestMaximumGeneratedPlanningAcceptsCompleteResult(t *testing.T) {
	child, entries, head, root := nativeMaximumPlanningInputs()
	if !nativeMaximumPlanning(t, child, entries, head, root, true) {
		t.Fatal("valid all-generated private plan without plaintext was refused")
	}
	var result map[string]any
	if err := json.Unmarshal(child.out, &result); err != nil {
		t.Fatal(err)
	}
	result["operation_kind"] = "compare-public-configuration"
	payload := result["payload"].(map[string]any)
	payload["schema"] = "ComparisonPayload/v1"
	result["context"].(map[string]any)["operation"] = "compare-public-configuration"
	payload["evidence_limit"] = "Fixed authenticated public settings and requested generated intent only; future generated content is unavailable and secret-value equality is unchecked. Excludes apply admission or no-op, performed effects or credential validity, remote output contents or IAM, historical application, and continued currentness."
	for _, field := range []string{"private_entries", "private_complete", "display_delivery", "selected_records", "completed_records"} {
		delete(payload, field)
	}
	var err error
	child.out, err = json.Marshal(result)
	if err != nil || !nativeMaximumPlanning(t, child, entries, head, root, false) {
		t.Fatal("valid all-generated public plan was refused", err)
	}
	for _, field := range []string{"context-operation", "evidence-limit"} {
		t.Run(field, func(t *testing.T) {
			var damaged map[string]any
			if err := json.Unmarshal(child.out, &damaged); err != nil {
				t.Fatal(err)
			}
			if field == "context-operation" {
				damaged["context"].(map[string]any)["operation"] = "plan-supplied-values"
			} else {
				damaged["payload"].(map[string]any)["evidence_limit"] = "unsupported"
			}
			changed := child
			var err error
			changed.out, err = json.Marshal(damaged)
			if err != nil {
				t.Fatal(err)
			}
			if nativeMaximumPlanning(t, changed, entries, head, root, false) {
				t.Fatal("public planning with changed operation or evidence limit accepted")
			}
		})
	}
}

// full_only: false
func TestMaximumGeneratedPlanningRejectsChangedFacts(t *testing.T) {
	baseline, entries, head, root := nativeMaximumPlanningInputs()
	if !nativeMaximumPlanning(t, baseline, entries, head, root, true) {
		t.Fatal("valid control refused before damage")
	}
	for _, condition := range []string{"exit", "json", "state", "snapshot", "missing-installation-requirements", "incomplete-installation-requirements", "missing-installation-differences", "installation-difference", "extra-installation-field", "incomplete-diagnostics", "diagnostic", "missing-row", "duplicate-row", "reversed-rows", "generation", "requested-epoch", "current-lifecycle", "missing-requested-lifecycle", "missing-row-field", "extra-row-field", "private-incomplete", "private-row", "missing-private-rows", "selected", "missing-selected", "no-read", "unsent", "decrypt", "plaintext", "recovery-plaintext"} {
		t.Run(condition, func(t *testing.T) {
			child, _, _, _ := nativeMaximumPlanningInputs()
			var result map[string]any
			if err := json.Unmarshal(child.out, &result); err != nil {
				t.Fatal(err)
			}
			payload := result["payload"].(map[string]any)
			observation := result["observation"].(map[string]any)
			rows := payload["generated_entries"].([]any)
			first := rows[0].(map[string]any)
			switch condition {
			case "exit":
				child.code = 2
			case "state":
				result["state_result"] = "unavailable"
			case "snapshot":
				observation["snapshot_id"] = "other"
			case "missing-installation-requirements":
				delete(result, "installation_requirements")
			case "incomplete-installation-requirements":
				result["installation_requirements"].(map[string]any)["complete"] = false
			case "missing-installation-differences":
				delete(result["installation_requirements"].(map[string]any), "differences")
			case "installation-difference":
				result["installation_requirements"].(map[string]any)["differences"] = []any{map[string]any{"name": "generic-json", "trusted": map[string]any{}, "candidate": map[string]any{"version": "1.0.0"}}}
			case "extra-installation-field":
				result["installation_requirements"].(map[string]any)["extra"] = true
			case "incomplete-diagnostics":
				payload["diagnostics_complete"] = false
			case "diagnostic":
				payload["diagnostics"] = []any{map[string]any{}}
			case "missing-row":
				payload["generated_entries"] = rows[:1]
			case "duplicate-row":
				rows[1] = rows[0]
			case "reversed-rows":
				rows[0], rows[1] = rows[1], rows[0]
			case "missing-row-field":
				delete(first, "requested_action")
			case "extra-row-field":
				first["unrequested"] = true
			case "generation":
				first["current_generation_id"] = "other"
			case "requested-epoch":
				first["requested_epoch"] = float64(1)
			case "current-lifecycle":
				first["current_lifecycle_mode"] = "none"
			case "missing-requested-lifecycle":
				delete(first, "requested_lifecycle_mode")
			case "private-incomplete":
				payload["private_complete"] = false
			case "private-row":
				payload["private_entries"] = []any{map[string]any{"name": "first"}}
			case "missing-private-rows":
				delete(payload, "private_entries")
			case "selected":
				payload["selected_records"] = float64(1)
			case "missing-selected":
				delete(payload, "selected_records")
			case "no-read":
				child.capture.Events = nil
			case "unsent":
				child.capture.Events[0].Sent = false
			case "decrypt":
				child.capture.Events = append(child.capture.Events, observer.Event{Kind: "http-start", Operation: "kms-decrypt", Role: "authority", Sent: true})
			case "plaintext", "recovery-plaintext":
				child.capture.Events = append(child.capture.Events, observer.Event{Kind: condition, Count: 1, Matched: true})
			}
			var err error
			child.out, err = json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			if condition == "json" {
				child.out = []byte("{")
			}
			if nativeMaximumPlanning(t, child, entries, head, root, true) {
				t.Fatal("damaged generated planning evidence accepted")
			}
		})
	}
}

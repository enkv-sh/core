package compositionfull

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/compositions/configuration"
)

// full_only: false
func TestLocalEditReadableRefusalAndHumanAction(t *testing.T) {
	result, err := NewLocalEditRefusal("domain-rename")
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"schema\": \"LocalEditResult/v1\",\n  \"local_edit\": \"domain-rename\",\n  \"outcome\": \"refused\",\n  \"target\": null,\n  \"local_delivery\": {\n    \"outcome\": \"not-recorded\",\n    \"editable_path\": null,\n    \"generated_path\": null,\n    \"readback\": null,\n    \"recovery_source\": null,\n    \"cleanup_failed\": false\n  },\n  \"warning_summary\": []\n}\n"
	body, err := RenderLocalEditJSON(result, nil)
	if err != nil || string(body) != want {
		t.Fatalf("readable local refusal differs: %v; got %q", err, body)
	}
	result.outcome, result.cleanupFail = "unknown", true
	human, err := RenderLocalEditHuman(result, errors.New("private-provider-error-sentinel"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fact := range []string{"Domain rename: unknown", "Local delivery is uncertain", "Local cleanup did not complete"} {
		if !strings.Contains(string(human), fact) {
			t.Fatalf("human result omits %q: %s", fact, human)
		}
	}
	if bytes.Contains(human, []byte("private-provider-error-sentinel")) || bytes.Contains(human, []byte("LocalEditResult/v1")) || bytes.Contains(human, []byte("readback")) {
		t.Fatal("human result exposed raw errors or routine codec detail", string(human))
	}
}

// full_only: false
func TestLocalEditRefusalClosedResult(t *testing.T) {
	for _, action := range []string{"domain-rename", "recipient-preparation", "recipient-reference-rename", "recovery"} {
		t.Run(action, func(t *testing.T) {
			result, err := NewLocalEditRefusal(action)
			if err != nil {
				t.Fatal(err)
			}
			rawError := errors.New("private-provider-error-body-unique")
			record := localEditWire(t, result, rawError)
			want := map[string]any{"schema": "LocalEditResult/v1", "local_edit": action, "outcome": "refused", "target": nil,
				"local_delivery": map[string]any{"outcome": "not-recorded", "editable_path": nil, "generated_path": nil, "readback": nil, "recovery_source": nil, "cleanup_failed": false}, "warning_summary": []any{}}
			if !reflect.DeepEqual(record, want) || LocalEditExitCode(result, rawError) != 2 {
				t.Fatal("refusal disclosed unadmitted facts")
			}
			body, err := RenderLocalEditJSON(result, rawError)
			if err != nil || bytes.Contains(body, []byte(rawError.Error())) {
				t.Fatal("result exposed raw error", err)
			}
		})
	}
	if result, err := NewLocalEditRefusal("not-an-action"); result != nil || err == nil {
		t.Fatal("unknown action entered closed result")
	}
}

// full_only: false
func TestLocalEditResultRejectsUnconfirmedAndUnboundedFacts(t *testing.T) {
	for _, result := range []*LocalEditResult{
		{action: "domain-rename", outcome: "edited"},
		{action: "domain-rename", outcome: "pending"},
		{action: "domain-rename", outcome: "edited", delivery: &configuration.PairDelivery{}},
		{action: "domain-rename", outcome: "refused", target: map[string]string{"old_name": "prod", "new_name": "next"}},
		{action: "domain-rename", outcome: "refused", paths: [2]string{"relative", ""}},
		{action: "recovery", outcome: "refused", target: recoveryEditTarget{Source: "/" + string(bytes.Repeat([]byte{'p'}, 4096))}},
	} {
		if _, err := RenderLocalEditJSON(result, nil); err == nil || LocalEditExitCode(result, nil) != 2 {
			t.Fatal("unproved or unbounded facts rendered")
		}
	}
}

// These codec fixtures grant no native delivery or cleanup observation.
// full_only: false
func TestLocalEditCleanupFactDoesNotGrantDelivery(t *testing.T) {
	for _, outcome := range []string{"refused", "unknown"} {
		t.Run(outcome, func(t *testing.T) {
			result, err := NewLocalEditRefusal("domain-rename")
			if err != nil {
				t.Fatal(err)
			}
			result.outcome, result.cleanupFail = outcome, true
			deliveryOutcome, exit := "not-recorded", 2
			warnings := []any{"Local cleanup did not complete."}
			if outcome == "unknown" {
				deliveryOutcome, exit = "unknown", 3
				warnings = append([]any{"Local delivery is uncertain; retain the pair and any saved local transaction."}, warnings...)
			}
			renderError := errors.New("private-cleanup-error-sentinel")
			record := localEditWire(t, result, renderError)
			want := map[string]any{"schema": "LocalEditResult/v1", "local_edit": "domain-rename", "outcome": outcome, "target": nil,
				"local_delivery":  map[string]any{"outcome": deliveryOutcome, "editable_path": nil, "generated_path": nil, "readback": nil, "recovery_source": nil, "cleanup_failed": true},
				"warning_summary": warnings}
			if !reflect.DeepEqual(record, want) || LocalEditExitCode(result, renderError) != exit {
				t.Fatal("cleanup fact granted delivery, recovery or an incorrect exit")
			}
		})
	}
}

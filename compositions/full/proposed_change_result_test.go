package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
)

// These expectations are independent JSON contract literals. Base64 AApB and
// AApC encode the fixed input triples {0,10,65} and {0,10,66}; AAoA/w== encodes
// {0,10,0,255}. No production comparison or encoder derives expected values.

// full_only: false
func TestProposedChangeJSONOwnsCompletePlainValues(t *testing.T) {
	for _, fixture := range []struct {
		name, expected string
		after          []byte
	}{
		{"changed", `[{"subject":{"kind":"entry","name":"a/\n雪"},"path":[{"field":"plain_value"}],"action":"changed","before":{"state":"present","type":"bytes","value":{"base64":"AApB","byte_length":3}},"after":{"state":"present","type":"bytes","value":{"base64":"AApC","byte_length":3}}}]`, []byte{0, 10, 66}},
		{"present-empty", `[{"subject":{"kind":"entry","name":"a/\n雪"},"path":[{"field":"plain_value"}],"action":"changed","before":{"state":"present","type":"bytes","value":{"base64":"AApB","byte_length":3}},"after":{"state":"present","type":"bytes","value":{"base64":"","byte_length":0}}}]`, []byte{}},
		{"binary", `[{"subject":{"kind":"entry","name":"a/\n雪"},"path":[{"field":"plain_value"}],"action":"changed","before":{"state":"present","type":"bytes","value":{"base64":"AApB","byte_length":3}},"after":{"state":"present","type":"bytes","value":{"base64":"AAoA/w==","byte_length":4}}}]`, []byte{0, 10, 0, 255}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			result, h, baseline, candidate := proposedChangeComparison(t, func(editable, _ map[string]any) {
				editable["entries"].(map[string]any)["a/\n雪"].(map[string]any)["source"].(map[string]any)["bytes"] = fixture.after
			})
			if result.Verdict != contract.ComparisonMismatch || result.StateResult != contract.ReaderSuccess || result.Observation == nil || ComparisonExitCode(result) != 1 {
				t.Fatalf("fixture did not reach a complete difference: verdict=%s state=%s", result.Verdict, result.StateResult)
			}
			observation := *result.Observation
			baseline.assertUnchanged(t)
			candidate.assertUnchanged(t)
			if err := baseline.pair.Close(); err != nil {
				t.Fatal(err)
			}
			if err := candidate.pair.Close(); err != nil {
				t.Fatal(err)
			}
			// Formatting must use retained comparison facts after both source
			// owners close. A later Store outage cannot change that observation.
			h.reset(true, "", 0)
			body, changes := proposedChangeJSON(t, result)
			assertProposedJSON(t, changes, fixture.expected)
			if len(result.Diagnostics) != 0 || *result.Observation != observation || len(body) != cap(body) {
				t.Fatal("rendering lost owned facts, duplicated a difference or changed its observation")
			}
			h.mu.Lock()
			reads := len(h.reads)
			h.mu.Unlock()
			if reads != 0 {
				t.Fatal("formatting reread Store")
			}
			h.assertNoEffects(t)
		})
	}
}

// full_only: false
func TestProposedChangeJSONIncludesCompleteMembershipDelta(t *testing.T) {
	var authorityID, removedID string
	result, h, baseline, candidate := proposedChangeComparison(t, func(editable, generated map[string]any) {
		entry := editable["entries"].(map[string]any)["a/\n雪"].(map[string]any)
		ref := entry["recipients"].([]string)[0]
		removedID = generated["recipients"].(map[string]any)[ref].(map[string]any)["id"].(string)
		authorityID = generated["domain"].(map[string]any)["authority"].(map[string]any)["id"].(string)
		entry["recipients"] = []string{}
	})
	if result.Verdict != contract.ComparisonMismatch || result.StateResult != contract.ReaderSuccess || ComparisonExitCode(result) != 1 {
		t.Fatalf("membership fixture did not reach complete difference: verdict=%s state=%s", result.Verdict, result.StateResult)
	}
	// IDs are taken from independently captured fixture inputs, never from the
	// comparison result. Authority is an unchanged member of every entry.
	before := []string{`{"id":"` + authorityID + `","change":"unchanged"}`, `{"id":"` + removedID + `","change":"removed"}`}
	sort.Strings(before)
	want := `[{"subject":{"kind":"entry","name":"a/\n雪"},"path":[{"field":"memberships"}],"action":"changed","before":{"state":"present","type":"id-set","value":[` + strings.Join(before, ",") + `]},"after":{"state":"present","type":"id-set","value":[{"id":"` + authorityID + `","change":"unchanged"}]}}]`
	_, changes := proposedChangeJSON(t, result)
	assertProposedJSON(t, changes, want)
	if len(result.Diagnostics) != 0 {
		t.Fatal("membership change was duplicated as a diagnostic")
	}
	baseline.assertUnchanged(t)
	candidate.assertUnchanged(t)
	h.assertNoEffects(t)
}

func proposedChangeComparison(t *testing.T, edit func(map[string]any, map[string]any)) (ConfigurationComparisonResult, *readerHTTPFixture, configurationReaderSource, configurationReaderSource) {
	t.Helper()
	baseline := configurationReaderPair(t, "aws", configuration.JSON, nil)
	candidate := configurationReaderPair(t, "aws", configuration.YAML, edit)
	h := &readerHTTPFixture{archive: baseline.archive, reads: map[string]int{}}
	calls := 0
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	result := compareConfiguration(ctx, contract.Hash([]byte(t.Name())), baseline.pair, candidate.pair, configurationReaderOpener(t, baseline, h, &calls))
	if calls != 1 {
		t.Fatalf("comparison opened %d readers", calls)
	}
	return result, h, baseline, candidate
}

func proposedChangeJSON(t *testing.T, result ConfigurationComparisonResult) ([]byte, json.RawMessage) {
	t.Helper()
	body, err := RenderComparisonJSON(result)
	if err != nil {
		t.Fatal("safe comparison JSON refused", err)
	}
	var decoded struct {
		Payload struct {
			Changes json.RawMessage `json:"changes"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Payload.Changes) == 0 {
		t.Fatal("comparison JSON has no owned proposed changes")
	}
	for _, forbidden := range []string{"raw-error-sentinel", "secret-sentinel", "ciphertext", "commitment", "sealed_input", "private_envelope"} {
		if bytes.Contains(body, []byte(forbidden)) {
			t.Fatalf("ordinary comparison JSON contains forbidden field or bytes %q", forbidden)
		}
	}
	return body, decoded.Payload.Changes
}

func assertProposedJSON(t *testing.T, got json.RawMessage, expected string) {
	t.Helper()
	var actual, want any
	if err := json.Unmarshal(got, &actual); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(expected), &want); err != nil {
		t.Fatal("invalid independent expected JSON", err)
	}
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("complete proposed changes differ:\ngot  %s\nwant %s", got, expected)
	}
}

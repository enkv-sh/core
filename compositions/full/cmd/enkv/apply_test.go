package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestApplyRejectsInvalidSourceSelection(t *testing.T) {
	for _, args := range [][]string{{"--source", ""}, {"--source", "/absent"}, {"--source", "/absent", "--source-format", "automatic"}, {"--config", "/absent", "--source-format", "json"}, {"--source", "/absent", "--source-format", "json", "unexpected"}} {
		var out, diagnostic bytes.Buffer
		if code := runApply(args, &out, &diagnostic); code != 2 || !strings.Contains(out.String(), "refused") || !strings.Contains(diagnostic.String(), "--source") {
			t.Fatal("ambiguous apply source accepted", code, out.String(), diagnostic.String())
		}
	}
}

// full_only: false
func TestApplyMalformedSourceRefusesWithoutChangingOrDisclosingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.json")
	body := []byte(`{"secret-sentinel":"raw-parser-error-sentinel"}`)
	if err := os.WriteFile(path, body, 0444); err != nil {
		t.Fatal(err)
	}
	var out, diagnostic bytes.Buffer
	code := runApply([]string{"--source", path, "--source-format", "json", "--json"}, &out, &diagnostic)
	var result struct {
		Schema      string
		State       string `json:"state_result"`
		Payload     any
		Diagnostics []any
		OperationID string         `json:"operation_id"`
		Identity    map[string]any `json:"request_identity"`
		Replay      string         `json:"replay_identity"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || code != 2 || result.Schema != "ProductResult/v1" || result.State != "refused" || result.Payload != nil || len(result.Diagnostics) != 1 {
		t.Fatal("unsafe apply refusal", code, err, out.String())
	}
	if len(result.OperationID) != 64 || result.Identity["schema"] != "PreAdmissionRequestIdentity/v1" || result.Identity["operation_id"] != result.OperationID || result.Replay != "none" {
		t.Error("malformed apply source lost pre-admission identity")
	}
	for _, forbidden := range []string{"secret-sentinel", "raw-parser-error-sentinel"} {
		if bytes.Contains(out.Bytes(), []byte(forbidden)) || bytes.Contains(diagnostic.Bytes(), []byte(forbidden)) {
			t.Fatal("source escaped safe refusal")
		}
	}
	if bytes.Contains(diagnostic.Bytes(), []byte(path)) {
		t.Fatal("captured source path entered telemetry")
	}
	var source struct {
		Failure *compositionfull.ConfigurationSourceFailure `json:"source_failure"`
	}
	if json.Unmarshal(out.Bytes(), &source) != nil || source.Failure == nil || source.Failure.Path != path {
		t.Fatal("malformed input lost the admitted source path")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatal("apply changed refused source", err)
	}
}

// full_only: false
func TestApplyResultPreservesUnknownCanonicalOutcome(t *testing.T) {
	r := core.PublicApplyResult{RequestID: contract.Hash([]byte("request")), OperationID: contract.Hash([]byte("operation")), RequestIdentity: contract.Hash([]byte("identity")), Result: core.Result{Outcome: core.UnresolvedCommit, CommitMayHaveOccurred: true}}
	for _, structured := range []bool{false, true} {
		var out bytes.Buffer
		if err := writeApplyResult(&out, structured, compositionfull.ConfigurationApplyResult{PublicApplyResult: r}); err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(out.Bytes(), []byte("commit-outcome-unknown")) || structured && !bytes.Contains(out.Bytes(), []byte("effect-no-change")) || !structured && (!strings.Contains(out.String(), "Operation ID: "+idText(r.OperationID)) || !strings.Contains(out.String(), "HEAD change may have occurred")) || bytes.Contains(out.Bytes(), []byte("receipt_hex")) {
			t.Fatal("unknown apply outcome was overstated", out.String())
		}
	}
	var diagnostic bytes.Buffer
	if code := runApply([]string{"--source", filepath.Join(t.TempDir(), "absent"), "--source-format", "json", "--json"}, commandShortWriter{}, &diagnostic); code != 2 || !strings.Contains(diagnostic.String(), "output failed") {
		t.Fatal("partial apply output accepted", code)
	}
}

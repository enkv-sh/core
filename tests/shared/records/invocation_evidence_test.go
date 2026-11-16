package records

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// full_only: false
func TestInvocationEvidenceKeepsRetiredPathsSeparateFromExecution(t *testing.T) {
	inv := testInvocation(t)
	mapPath := filepath.Join(inv.StateDir, "failure-sources.json")
	if os.WriteFile(mapPath, []byte("{}\n"), 0400) != nil {
		t.Fatal("source-map path fixture unavailable")
	}
	inv.FailureSources = &FailureSourceBinding{Path: mapPath, SHA256: strings.Repeat("a", 64)}
	path := filepath.Join(inv.OutputDir, "invocation.json")
	if WriteJSON(path, inv, 0400) != nil || inv.Validate() != nil || inv.ValidateEvidence() != nil {
		t.Fatal("current invocation fixture is not admitted")
	}
	if os.RemoveAll(inv.StateDir) != nil {
		t.Fatal("retired invocation fixture unavailable")
	}
	if inv.ValidateEvidence() != nil || inv.Validate() == nil {
		t.Fatal("retired metadata did not stay distinct from execution admission")
	}
	if _, err := LoadInvocation(path); err == nil {
		t.Fatal("retired evidence admitted execution loading")
	}
	if _, err := LoadRecordedInvocation(path); err == nil {
		t.Fatal("recorded execution loading lost its existing file checks")
	}
	if os.Symlink(canonicalTemp(t), inv.StateDir) != nil {
		t.Fatal("replacement ancestor fixture unavailable")
	}
	if inv.ValidateEvidence() != nil || inv.Validate() == nil {
		t.Fatal("past metadata consulted a replacement logical ancestor")
	}
	for _, condition := range []string{"nonce", "owner", "path", "historical-writer", "fresh-facts", "facts-escape", "facts-nul"} {
		t.Run(condition, func(t *testing.T) {
			value := inv
			switch condition {
			case "nonce":
				value.Nonce = "invalid"
			case "owner":
				value.RunID = oldRunID
			case "path":
				value.Input += "/../input.json"
			case "historical-writer":
				value.Scenario = "state.single-value-update-preserves-other-values"
			case "fresh-facts":
				value.Role = "fresh_after"
			case "facts-escape":
				value.Role, value.Facts = "fresh_after", "../facts.json"
			case "facts-nul":
				value.Role, value.Facts = "fresh_after", "facts\x00.json"
			}
			if value.ValidateEvidence() == nil || value.Validate() == nil {
				t.Fatal("malformed invocation metadata was admitted", condition)
			}
		})
	}
}

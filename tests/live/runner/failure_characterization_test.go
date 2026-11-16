package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestLiveProtocolAssertionMarkerRetainsInputRefusal(t *testing.T) {
	inv, _ := liveProtocolInvocation(t, "writer")
	path := saveLiveProtocolInvocation(t, inv)
	if err := records.WriteJSON(inv.Input, map[string]string{"unknown": "ASSERTION_SECRET_SENTINEL"}, 0o400); err != nil {
		t.Fatal(err)
	}
	if runLiveProtocolEntry(t, "TestLiveRun", path) == nil {
		t.Fatal("invalid input passed")
	}
	body, err := os.ReadFile(filepath.Join(inv.OutputDir, "failure.json"))
	if err != nil {
		t.Fatal("input assertion evidence did not survive Goexit", err)
	}
	var marker struct {
		Code, Source, Phase string
		Line                int
		Sequence            uint64
	}
	if json.Unmarshal(body, &marker) != nil || marker.Code != "fatal" || marker.Source != "tests/live/runner/run_test.go" || marker.Line <= 0 || marker.Phase != "bootstrap" || marker.Sequence != 0 {
		t.Fatal("input refusal lost its immediate assertion or pre-phase location")
	}
}

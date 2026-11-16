package core

import (
	"path/filepath"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestLiveFreshChildStartFailureRetainsProcessFact(t *testing.T) {
	inv, _ := liveProtocolInvocation(t, "fresh_before")
	path := saveLiveProtocolInvocation(t, inv)
	_, process, err := executeFreshChild(t.Context(), filepath.Join(t.TempDir(), "absent-executable"), path)
	want := records.FreshChildProcess{Joined: true, Outcome: "not_started"}
	if err == nil || process == nil || *process != want {
		t.Fatalf("fresh start failure = %+v, %v, want %+v and failure", process, err, want)
	}
}

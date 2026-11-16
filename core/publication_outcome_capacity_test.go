package core

import (
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicationFutureEvidenceCapacityBoundaries(t *testing.T) {
	// These values come from the result grammar: evidence bodies are at most
	// 3122 bytes, target rows at most 80 KiB, and vectors at most 16 MiB.
	for _, tc := range []struct {
		name    string
		maximum int
		actions int
		current int
		want    bool
	}{
		{"target_exact", 81920, 2, 75676, true},
		{"target_one_over", 81920, 2, 75677, false},
		{"vector_exact", 16777216, 2, 16770972, true},
		{"vector_one_over", 16777216, 2, 16770973, false},
		{"retained_blockers", 81920, 2, 81849, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := publicationOutcomeFutureFits(tc.current, tc.actions, tc.maximum); got != tc.want {
				t.Fatalf("current=%d actions=%d maximum=%d fits=%v", tc.current, tc.actions, tc.maximum, got)
			}
		})
	}
	if contract.MaxPublicationEvidenceBytes != 3122 || contract.MaxPublicationOutcomeBytes != 81920 || contract.MaxPublicationOutcomeVectorBytes != 16777216 {
		t.Fatal("publication capacity grammar changed")
	}
}

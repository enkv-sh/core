package format

import (
	"enkv.sh/core/contract"
	"testing"
)

// full_only: false
func TestPublicationIndexPlanningGrowth(t *testing.T) {
	// Group247, marker stamp40, span7/count-index2, summary37,
	// two prerequisite indexes4, incarnation32; coordinate order34+32.
	got, err := PublicationIndexPlanningGrowth(3, 1, 2)
	if err != nil || got != 3*369+359+2*108 {
		t.Fatal(got, err)
	}
	for _, input := range [][3]uint32{{2049, 0, 0}, {0, 1025, 0}, {0, 0, 257}} {
		if _, err := PublicationIndexPlanningGrowth(input[0], input[1], input[2]); err == nil {
			t.Fatal("accepted count overflow", input)
		}
	}
	if got, err := PublicationIndexPlanningGrowth(contract.MaxPublicationMarkers, contract.MaxPublicationCoordinates, contract.MaxChildPages); err != nil || got == 0 {
		t.Fatal(got, err)
	}
}

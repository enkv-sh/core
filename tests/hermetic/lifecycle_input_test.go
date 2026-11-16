package core

import (
	"context"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestCompleteInputAdmitsMembershipChanges(t *testing.T) {
	for _, name := range []string{"addition", "removal", "replacement", "last-removal", "empty-addition"} {
		t.Run(name, func(t *testing.T) {
			count := 2
			if name == "empty-addition" {
				count = 0
			}
			f := newFixture(t, count, false, 1)
			input := f.session.currentEntryInputs()
			addition := ApplyEntryInput{Name: "new", Recipients: []contract.ID{f.session.admission.recipient}, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputBytes: []byte("value"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
			switch name {
			case "addition", "empty-addition":
				input = append(input, addition)
			case "removal":
				input = input[1:]
			case "replacement":
				input = []ApplyEntryInput{addition}
			case "last-removal":
				input = nil
			}
			c, result := f.session.Compare(context.Background(), input, admitSuppliedComparison(t, f.session, nil, input))
			if c == nil || result.Outcome != ObservedCurrent {
				t.Fatalf("valid complete membership intent refused: %+v", result)
			}
			if f.store.creates != 0 || f.store.cas != 0 || f.trust.signs != 0 || f.session.prepared {
				t.Fatal("comparison performed mutation effects")
			}
		})
	}
}

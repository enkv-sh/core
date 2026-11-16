package contract

import (
	"math"
	"testing"
)

// full_only: false
func TestPlanningOptionsKeepPurposesAndExactSelectorsSeparate(t *testing.T) {
	id := Hash([]byte("planning sink"))
	for _, item := range []struct {
		name    string
		options PlanningOptions
		valid   bool
	}{
		{"equality", PlanningOptions{Purpose: PlanningEquality}, true},
		{"explicit-empty", PlanningOptions{Purpose: PlanningDisplay, SinkID: id, SelectedNames: []string{""}}, true},
		{"exact-distinct", PlanningOptions{Purpose: PlanningDisplay, SinkID: id, SelectedNames: []string{"Name", "name", "α/\n"}}, true},
		{"omitted", PlanningOptions{Purpose: PlanningDisplay, SinkID: id}, false},
		{"duplicate-empty", PlanningOptions{Purpose: PlanningDisplay, SinkID: id, SelectedNames: []string{"", ""}}, false},
		{"equality-with-selector", PlanningOptions{Purpose: PlanningEquality, SelectedNames: []string{""}}, false},
		{"equality-with-sink", PlanningOptions{Purpose: PlanningEquality, SinkID: id}, false},
		{"display-without-sink", PlanningOptions{Purpose: PlanningDisplay, SelectedNames: []string{"a"}}, false},
		{"unknown", PlanningOptions{Purpose: 255}, false},
	} {
		t.Run(item.name, func(t *testing.T) {
			if item.options.Valid() != item.valid {
				t.Fatal("wrong closed option admission", item.options)
			}
		})
	}
}

// full_only: false
func TestPlanningSourceIdentityRequiresBothCompleteImages(t *testing.T) {
	p := PlanningSourcePair{FileIdentity: Hash([]byte("file")), EditableDigest: Hash([]byte("editable")), GeneratedDigest: Hash([]byte("generated")), EditableLength: 1, GeneratedLength: 2}
	if !p.Valid() {
		t.Fatal("complete pair refused")
	}
	for _, change := range []func(*PlanningSourcePair){
		func(p *PlanningSourcePair) { p.FileIdentity = ID{} },
		func(p *PlanningSourcePair) { p.EditableDigest = ID{} },
		func(p *PlanningSourcePair) { p.GeneratedDigest = ID{} },
		func(p *PlanningSourcePair) { p.EditableLength = 0 },
		func(p *PlanningSourcePair) { p.GeneratedLength = 0 },
		func(p *PlanningSourcePair) { p.EditableLength = math.MaxUint64 },
	} {
		bad := p
		change(&bad)
		if bad.Valid() {
			t.Fatal("incomplete or overflowing pair admitted", bad)
		}
	}
}

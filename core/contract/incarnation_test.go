package contract

import (
	"math"
	"testing"
)

// full_only: false
func TestIncarnationCounterStep(t *testing.T) {
	old := Hash([]byte("old incarnation"))
	fresh := Hash([]byte("fresh incarnation"))
	for _, tc := range []struct {
		name              string
		before, after     uint64
		beforeID, afterID ID
		want              bool
	}{
		{"ordinary increment", 7, 8, old, old, true},
		{"ordinary incarnation change", 7, 8, old, fresh, false},
		{"skipped count", 7, 9, old, old, false},
		{"zero predecessor count", 0, 1, old, old, false},
		{"zero successor count", 7, 0, old, old, false},
		{"same incarnation overflow", math.MaxUint64, 1, old, old, false},
		{"fresh incarnation rollover", math.MaxUint64, 1, old, fresh, true},
		{"rollover skips first count", math.MaxUint64, 2, old, fresh, false},
		{"zero predecessor incarnation", 7, 8, ID{}, ID{}, false},
		{"zero successor incarnation", math.MaxUint64, 1, old, ID{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IncarnationCounterStep(tc.beforeID, tc.before, tc.afterID, tc.after); got != tc.want {
				t.Fatalf("counter step accepted=%t, want %t", got, tc.want)
			}
		})
	}
}

// full_only: false
func TestAdvanceAccessGenerationRollover(t *testing.T) {
	domain := Hash([]byte("domain"))
	seed := Hash([]byte("selected transition"))
	prior := Hash([]byte("old access incarnation"))
	core := CurrentAccessCore{CurrentControl: CurrentControl{CurrentControlFields: CurrentControlFields{
		DomainID: domain, AccessIncarnationID: prior, AccessGeneration: math.MaxUint64,
	}}}
	if err := AdvanceAccessGeneration(&core, seed); err != nil {
		t.Fatal(err)
	}
	if core.AccessGeneration != 1 || core.AccessIncarnationID.IsZero() || core.AccessIncarnationID == prior ||
		core.AccessIncarnationID != DeriveAccessIncarnationID(domain, seed) {
		t.Fatal("rollover did not select a fresh domain-bound incarnation", core)
	}
	if err := AdvanceAccessGeneration(&core, ID{}); err != nil || core.AccessGeneration != 2 {
		t.Fatal("ordinary increment changed the new incarnation", core, err)
	}
	if DeriveAccessIncarnationID(domain, seed) == DeriveAccessIncarnationID(Hash([]byte("other domain")), seed) ||
		!DeriveAccessIncarnationID(ID{}, seed).IsZero() || !DeriveAccessIncarnationID(domain, ID{}).IsZero() {
		t.Fatal("access incarnation derivation did not bind domain and seed")
	}
	core.AccessGeneration = math.MaxUint64
	if err := AdvanceAccessGeneration(&core, ID{}); err == nil {
		t.Fatal("rollover without a fresh transition identity succeeded")
	}
}

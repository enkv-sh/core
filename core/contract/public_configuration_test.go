package contract

import "testing"

// full_only: false
func TestPublicFieldDistinguishesEmptyMissingAndUnavailable(t *testing.T) {
	empty := PublicField[[]byte]{State: PublicPresent, Value: []byte{}}
	missing := PublicField[[]byte]{}
	unavailable := PublicField[[]byte]{State: PublicUnavailable}
	if empty.State == missing.State || empty.State == unavailable.State || missing.State == unavailable.State {
		t.Fatal("field presence states overlap")
	}
	if empty.Value == nil || len(empty.Value) != 0 {
		t.Fatal("explicit empty application bytes changed")
	}
}

// full_only: false
func TestPublicRoutingEmptyNameIsNotDefault(t *testing.T) {
	name := PublicRoutingKey{EntrySelector: PublicNamedEntry, EntryName: ""}
	defaultRoute := PublicRoutingKey{EntrySelector: PublicDefaultRoute}
	if name == defaultRoute {
		t.Fatal("empty name overlaps default")
	}
}

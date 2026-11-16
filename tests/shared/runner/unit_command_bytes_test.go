package main

import (
	"strings"
	"testing"
)

// full_only: false
func TestUnitCommandReservationMatchesEncodedByteEnvelope(t *testing.T) {
	for _, row := range []struct {
		name, scope string
		accepted    bool
	}{
		{"ascii-last", strings.Repeat("x", 1666), true},
		{"ascii-over", strings.Repeat("x", 1667), false},
		{"html-escaped-last", strings.Repeat("<", 277) + "xxxx", true},
		{"html-escaped-over", strings.Repeat("<", 277) + "xxxxx", false},
		{"quoted-last", strings.Repeat("\"", 833), true},
		{"quoted-over", strings.Repeat("\"", 833) + "x", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			diagnostics := &checkDiagnostics{}
			err := diagnostics.reserveOrdinaryCommands([]ordinaryCommandReservation{{scope: row.scope, processes: 8192, factsPerProcess: 2}})
			if (err == nil) != row.accepted {
				t.Fatal("reservation differs from the independent encoded-byte boundary", err)
			}
			if !row.accepted && (diagnostics.ordinaryCommandLimit != 0 || len(diagnostics.Commands) != 0) {
				t.Fatal("oversized encoded reservation was partly admitted")
			}
		})
	}
}

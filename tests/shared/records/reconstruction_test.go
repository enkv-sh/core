package records

import (
	"strings"
	"testing"
)

// full_only: false
func TestProcessCompletionRequiresJoinedNamedArtifact(t *testing.T) {
	binary := strings.Repeat("a", 64)
	valid := ProcessCompletion{Phase: "restricted-child", Helper: "TestRestricted", BinarySHA256: binary, TerminalsSHA256: strings.Repeat("b", 64), Started: true, Joined: true, Outcome: "passed"}
	if err := valid.Validate("restricted-child", "TestRestricted", binary); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name   string
		change func(*ProcessCompletion)
	}{
		{"phase", func(p *ProcessCompletion) { p.Phase = "writer" }},
		{"helper", func(p *ProcessCompletion) { p.Helper = "TestOther" }},
		{"artifact", func(p *ProcessCompletion) { p.BinarySHA256 = strings.Repeat("c", 64) }},
		{"invalid-artifact", func(p *ProcessCompletion) { p.BinarySHA256 = "invalid" }},
		{"terminal", func(p *ProcessCompletion) { p.TerminalsSHA256 = "" }},
		{"not-started", func(p *ProcessCompletion) { p.Started = false }},
		{"not-joined", func(p *ProcessCompletion) { p.Joined = false }},
		{"failed", func(p *ProcessCompletion) { p.Outcome = "failed" }},
		{"skipped", func(p *ProcessCompletion) { p.Outcome = "skipped" }},
	} {
		t.Run(row.name, func(t *testing.T) {
			p := valid
			row.change(&p)
			if p.Validate("restricted-child", "TestRestricted", binary) == nil {
				t.Fatal("incomplete process accepted")
			}
		})
	}
	if valid.Validate("restricted-child", "TestRestricted", "") == nil {
		t.Fatal("empty expected artifact accepted")
	}
}

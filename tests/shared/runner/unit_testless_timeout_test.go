package main

import (
	"context"
	"testing"
	"time"
)

// full_only: false
func TestPreparedUnitTestlessRejectsUnboundedProcessTimeout(t *testing.T) {
	for _, flag := range []string{"-timeout=0", "-timeout=11m"} {
		t.Run(flag, func(t *testing.T) {
			root, _, _ := overlayFixture(t)
			const directory = "plugins/output-contract-test"
			const command = directory + "/cmd/enkv-output-contract-test"
			writeLocalGoFixture(t, root, directory+"/go.mod", "module "+modulePrefix+directory+"\n\ngo 1.27.0\n")
			writeLocalGoFixture(t, root, command+"/main.go", "package main\nfunc main() {}\n")
			initializeWorkflowExecutionFixture(t, root)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			source, err := sourceRevision(ctx, root)
			if err != nil {
				t.Fatal(err)
			}
			artifact := preparedOrdinaryArtifact{unit: true, ordinaryArtifact: ordinaryArtifact{Directory: directory, Package: modulePrefix + command, Patterns: []string{"./cmd/enkv-output-contract-test"}, TestFlags: []string{flag}}}
			group := preparedOrdinaryGroup{source: source, step: resolvedWorkflowStep{Kind: "unit"}}
			evidence := ordinaryStepEvidence{Diagnostics: &checkDiagnostics{Preparation: "passed"}}
			err = group.executeArtifacts(ctx, root, []preparedOrdinaryArtifact{artifact}, &evidence, nil)
			if err == nil || err.Error() != "ordinary process timeout is outside its bound" {
				t.Fatal("testless unit command did not refuse its invalid physical timeout", err)
			}
			if len(evidence.Diagnostics.Commands) != 0 || len(evidence.Tests) != 0 || evidence.Complete {
				t.Fatal("invalid physical timeout admitted a unit process or terminal result", evidence)
			}
		})
	}
}

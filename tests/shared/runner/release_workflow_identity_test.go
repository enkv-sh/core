package main

import "testing"

// full_only: false
func TestReleaseWorkflowToolsIdentity(t *testing.T) {
	core, _ := distributionRoots(t)
	if ok, detail := releaseRun(t, core, nil, "python3", "-B", "distribution/test_release_workflow.py", "-v"); !ok {
		t.Fatalf("release tools identity: %s", detail)
	}
}

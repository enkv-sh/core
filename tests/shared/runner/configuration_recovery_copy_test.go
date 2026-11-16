package main

import (
	"path/filepath"
	"testing"
)

func sharedConfigurationRecoveryFixture(t *testing.T, root, directory string, setup assembly, provider string) configurationRecoveryArtifact {
	t.Helper()
	ctx, owner := withInvocationArtifacts(withExecutionParallel(testRaceContext(t, t.Context()), 1))
	t.Cleanup(func() {
		if err := owner.close(ctx, true); err != nil {
			t.Error(err)
		}
	})
	source := testSourceRevision(t, root)
	selected := []string{recoveryPhaseHelper(provider, "resource-owner"), recoveryPhaseHelper(provider, "reconstruction-parent")}
	artifact, _, err := prepareConfigurationRecoveryArtifact(ctx, root, filepath.Join(directory, "reconstruction"), provider, source, selected)
	if err != nil {
		t.Fatal("prepare shared reconstruction executable", err)
	}
	return artifact
}

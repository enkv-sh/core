package generatorhost

import "testing"

// full_only: false
func TestIndependentGeneratorInvocationAdmitsExactSDKClosure(t *testing.T) {
	path := buildSDKGenerator(t)
	installed := generatorInstallation(t, path)
	if err := verifyArtifactBuildInfo(t.Context(), path, installed); err != nil {
		t.Fatal("exact SDK closure refused", err)
	}
	installed.artifact.ArtifactSHA256[0] ^= 1
	if verifyArtifactBuildInfo(t.Context(), path, installed) == nil {
		t.Fatal("SDK metadata bypassed artifact authentication")
	}
}

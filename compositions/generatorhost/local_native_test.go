package generatorhost

import (
	"os"
	"path/filepath"
	"testing"

	"enkv.sh/sdk/artifact"
	publicbuild "enkv.sh/sdk/artifact/build"
	wire "enkv.sh/sdk/protocols/generator"
)

// full_only: false
func TestInstalledLocalAuthorRunsWithoutCredentialAcquisition(t *testing.T) {
	t.Setenv("GOFLAGS", "")
	t.Setenv("CLOUDFLARE_API_TOKEN", "invalid management token must not be read")
	root, err := filepath.Abs("../../../enkv-extensions")
	if err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()
	marker, err := publicbuild.Run(t.Context(), publicbuild.Config{Directory: filepath.Join(root, "plugins/generators/local-random-secret"), Descriptor: "cmd/enkv-generator-local-random-secret/plugin.json", Command: "./cmd/enkv-generator-local-random-secret", Output: output, Workspace: filepath.Join(root, "go.work")})
	if err != nil {
		t.Fatal("build public local author", err)
	}
	metadata, err := artifact.VerifyBuild(t.Context(), output)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(output, filepath.FromSlash(marker.Directory))
	t.Cleanup(func() {
		for _, path := range []string{directory, filepath.Join(output, "builds")} {
			if err := os.Chmod(path, 0700); err != nil && !os.IsNotExist(err) {
				t.Error("make owned build removable", err)
			}
		}
	})
	dependency, err := os.ReadFile(filepath.Join(directory, "dependencies.bin"))
	if err != nil {
		t.Fatal(err)
	}
	installed, err := NewInstallation(metadata, dependency)
	if err != nil {
		t.Fatal("admit local author", err)
	}
	row := installed.Artifact()
	route, err := installed.CredentialRoute()
	if err != nil || len(route.Names) != 0 {
		t.Fatal("local route requires environment inputs", err)
	}
	credentials := NewInvocationCredentials(t.Context())
	defer credentials.Close()
	launcher, err := NewNativeForInvocation(t.Context(), Config{Installation: installed, ArtifactPath: filepath.Join(directory, "plugin"), Artifact: row}, credentials)
	if err != nil {
		t.Fatal("launch admission", err)
	}
	command := testCommand(row)
	command.LifecycleMode = wire.LifecycleNone
	command.ResourceContractID = wire.ID{}
	command.Intent, err = wire.EncodeIntent(wire.Intent{Schema: 1, ConfigContractID: wire.ID(row.ConfigContractID), LifecycleMode: wire.LifecycleNone, Settings: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	command.IntentDigest, err = wire.IntentDigest(command.Intent)
	if err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	}()
	run, err := launcher.Start(t.Context(), command, writer)
	if err != nil {
		t.Fatal("native local start", err)
	}
	body, readErr := wire.ReadExpectedFrame(reader, wire.KindResult, wire.ID(run.CommandID()), wire.MaximumResultBody)
	if readErr == nil {
		readErr = wire.RequireEOF(reader)
	}
	status, waitErr := run.Wait(t.Context())
	if readErr != nil || waitErr != nil || status.Category != wire.StatusOK {
		clear(body)
		t.Fatal("native local result/join", readErr, waitErr, status)
	}
	result, err := wire.DecodeResult(body)
	if err != nil || result.SafeFacts.LifecycleMode != wire.LifecycleNone || len(result.SafeFacts.Target) != 0 || len(result.SafeFacts.ResourceData) != 0 || result.SafeFacts.RequestDigest != command.RequestDigest || result.AttemptID != command.AttemptID || result.ExecutorID != command.ExecutorID || len(result.Value) < 1 || len(result.Value) > wire.MaximumSecretLength {
		clear(body)
		t.Fatal("generic no-resource result binding", err)
	}
	clear(body[:cap(body)])
	credentials.mu.Lock()
	captures := len(credentials.captures)
	credentials.mu.Unlock()
	native := run.(*nativeRun)
	if captures > 1 || native.credential != nil || native.credentialRelease != nil {
		t.Fatal("local invocation acquired credential ownership")
	}
}

package nativeprocess

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"enkv.sh/compositions/configuration"
	observer "enkv.sh/core/testsupport/nativeprocess"
)

// full_only: false
func TestPublicNativePrepareYAMLFromSignedGenesisKeepsHEAD(t *testing.T) {
	cli, _ := workflowBuildExecutables(t, false)
	plugins := newNativePluginFixture(t, nativeManifestProductionBuild(t))
	s := newWorkflowServer(t, "gcp", false)
	s.childLimit = 3
	original := filepath.Join(t.TempDir(), "configuration.json")
	if err := os.WriteFile(original, workflowSetup(t, s, false), 0600); err != nil {
		t.Fatal(err)
	}
	workflowResult(t, workflowRun(t, s, cli, "init", observer.Policy{}, nil, "init", "--source", original, "--source-format", "json", "--json"), "success")
	head, selected := workflowHead(t, s)
	if head.Genesis == nil {
		t.Fatal("reconstruction control has no signed genesis")
	}
	if err := os.RemoveAll(filepath.Dir(original)); err != nil {
		t.Fatal("complete local loss failed", err)
	}
	const name = "restored"
	path := filepath.Join(t.TempDir(), "recovered.yaml")
	environment := plugins.Environment(t, path)
	child := workflowRunEnvironment(t, s, cli, "authority", observer.Policy{}, nil, environment,
		"prepare", "--source", path, "--source-format", "yaml", "--name", name, "--provider", "gcp", "--bucket", "fixture-bucket", "--region", "us-central1", "--prefix", s.prefix, "--normal-signing-key", s.selector(1), "--json")
	result := nativePrepareResult(t, child, "reconstruction")
	if result.Recovery.Head != workflowDigest(selected.body) {
		t.Fatal("reconstruction result lost its authenticated HEAD")
	}
	nativePrepareReadOnly(t, child)
	pair, err := configuration.Capture(t.Context(), path, configuration.YAML)
	if err != nil {
		t.Fatal("requested YAML pair was not delivered", err)
	}
	t.Cleanup(func() {
		if err := pair.Close(); err != nil {
			t.Error(err)
		}
	})
	model, err := configuration.Parse(t.Context(), pair)
	if err != nil || model == nil || !model.Resolved || model.DomainID != head.Core.Domain || model.DomainName != name || model.Generated != ".enkv/"+name+".generated.json" || !bytes.Equal(model.Basis.HEAD, selected.body) {
		t.Fatal("delivered YAML pair lost its complete selected meaning", err)
	}
	public := workflowRunEnvironment(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, environment, "plan", "--trusted", path, "--trusted-format", "yaml", "--json")
	if workflowResult(t, public, "success").Payload.Verdict != "match" {
		t.Fatal("fresh Reader did not admit the recovered YAML pair")
	}
	workflowGETOnly(t, public)
	_, final := workflowHead(t, s)
	if !bytes.Equal(selected.body, final.body) || selected.etag != final.etag || s.children != 3 {
		t.Fatal("reconstruction or fresh admission changed the authenticated HEAD")
	}
}

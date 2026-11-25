package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	catalog "enkv.sh/core/internal/testcatalog"
	"enkv.sh/core/testsupport/nativeprocess"
	artifactpkg "enkv.sh/sdk/artifact"
)

// full_only: false
func TestPublicOutputArtifactUsesExactInstalledExpectations(t *testing.T) {
	outer, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	outerRace, err := binaryRace(outer)
	if err != nil {
		t.Fatal(err)
	}
	root, directory := maintainedCloudflareRoot(t), publicPluginBuildOutput(t)
	copied := sourceFixtureRoot(t)
	copyPublicModuleKit(t, root, copied, []string{"sdk/artifact", "protocols/output", "sdk/output", "plugins/aws-output", "plugins/gcp-output", "plugins/github-output"})
	ctx, cancel := context.WithTimeout(cacheOnlyGoContext(withRacePolicy(t.Context(), outerRace)), 5*time.Minute)
	defer cancel()
	bindings := []outputProfileBinding{
		{StoredProfileID: "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v3"},
		{StoredProfileID: "ENKV/OUTPUT/GCP-SECRET-MANAGER/v3"},
		{StoredProfileID: "ENKV/OUTPUT/GITHUB-REPOSITORY/v3"},
		{StoredProfileID: "ENKV/OUTPUT/GITHUB-ORGANIZATION/v3"},
		{StoredProfileID: "ENKV/OUTPUT/GITHUB-ENVIRONMENT/v3"},
	}
	for i := range bindings {
		binding, err := productionOutputBinding(bindings[i].StoredProfileID)
		if err != nil {
			t.Fatal(err)
		}
		bindings[i] = binding
	}
	outputs, err := buildOutputArtifacts(ctx, copied, directory, outerRace, bindings)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := buildPublicConfigurationArtifact(ctx, root, directory, outputs)
	if err != nil {
		t.Fatal(err)
	}
	if !artifact.valid() || artifact.Race == nil || *artifact.Race != outerRace || len(outputs) != 5 {
		t.Fatal("public output artifact/source closure unavailable")
	}
	// Exercise the live CLI constructor with actual trusted local build folders.
	// Existing-pair preparation must verify them without output SDK discovery.
	source := installationSource(t, "aws", true)
	var declaration map[string]any
	body, err := os.ReadFile(source)
	if err != nil || json.Unmarshal(body, &declaration) != nil {
		t.Fatal("public output preparation fixture unavailable")
	}
	declaration["entries"] = map[string]any{}
	body, err = json.Marshal(declaration)
	if err != nil || os.WriteFile(source, body, 0600) != nil {
		t.Fatal("public output preparation declaration unavailable")
	}
	pair := installationPairImage(t, source)
	home, config := installationHome(t)
	application, err := filepath.EvalSymlinks(filepath.Dir(source))
	if err != nil {
		t.Fatal("public output preparation application unavailable")
	}
	var plugins []artifactpkg.LocalPlugin
	artifact.Plugins, artifact.ManifestRenderer, err = preparePublicConfigurationPlugins(ctx, root, directory, catalog.Schedule{}, outputs)
	if err != nil || !artifact.valid() {
		t.Fatal("public output fixture did not retain exact local builds", err)
	}
	for _, local := range artifact.Plugins {
		plugins = append(plugins, artifactpkg.LocalPlugin{Name: local.Metadata.Name, Directory: local.Directory})
	}
	slices.SortFunc(plugins, func(a, b artifactpkg.LocalPlugin) int { return strings.Compare(a.Name, b.Name) })
	settings, err := artifactpkg.EncodeSettings(artifactpkg.Settings{Schema: "enkv/plugin-settings/v1", Applications: []artifactpkg.Application{{Directory: application, Plugins: plugins}}})
	if err != nil || os.MkdirAll(filepath.Join(config, "enkv"), 0700) != nil || os.WriteFile(filepath.Join(config, "enkv", "plugins.json"), settings, 0600) != nil {
		t.Fatal("public output exact trusted settings unavailable")
	}
	var credentialCalls atomic.Int64
	credentials := installationCredentialRefusal(t, &credentialCalls)
	capture := filepath.Join(t.TempDir(), "capture.jsonl")
	policy := filepath.Join(t.TempDir(), "policy.json")
	encodedPolicy, err := json.Marshal(nativeprocess.Policy{Version: 1, RecordPath: capture, MaxRequests: 1, MaxBytes: 1024, NoKMS: true})
	if err != nil || os.WriteFile(capture, nil, 0600) != nil || os.WriteFile(policy, encodedPolicy, 0600) != nil {
		t.Fatal("public output passive capture unavailable")
	}
	var stdout, stderr limitedOutput
	prepared := runProcessOutput(ctx, artifact.CLI, filepath.Dir(source), []string{"prepare", "--source", source, "--source-format", "json", "--json", "--log-level", "off"}, append(installationEnvironment(home, credentials.URL), "ENKV_NATIVE_PROCESS_POLICY="+policy), 30*time.Second, &stdout, &stderr)
	var readiness struct {
		Schema, Branch, Outcome string
		Dependencies            struct {
			Assessment string
			Ready      bool                                          `json:"all_declared_ready"`
			Rows       []struct{ Name, Role, Status, Source string } `json:"installations"`
		}
	}
	if !prepared.Started || !prepared.Joined || prepared.Status != "passed" || stdout.overflow || stderr.overflow || json.Unmarshal([]byte(stdout.String()), &readiness) != nil || readiness.Schema != "enkv/prepare-result/v2" || readiness.Branch != "existing" || readiness.Outcome != "complete" || readiness.Dependencies.Assessment != "complete" || !readiness.Dependencies.Ready || len(readiness.Dependencies.Rows) != 5 {
		t.Fatal("live public CLI did not prepare its exact trusted output installations")
	}
	wantNames := []string{"aws-secrets-manager", "gcp-secret-manager", "github-actions-environment", "github-actions-organization", "github-actions-repository"}
	for i, row := range readiness.Dependencies.Rows {
		if row.Name != wantNames[i] || row.Role != "output" || row.Status != "verified" || row.Source != "local" {
			t.Fatal("public output preparation changed an exact installation fact")
		}
	}
	observed, err := nativeprocess.ReadCapture(capture)
	if err != nil || len(observed.Events) != 1 || observed.Events[0].Kind != "footer" || observed.Events[0].Code != 0 || credentialCalls.Load() != 0 {
		t.Fatal("public output preparation acquired SDK credentials or provider work")
	}
	installationAssertPair(t, source, pair)
	// A valid build selected for another application cannot become this source's
	// trust. Ordinary apply must refuse before credentials or release acquisition.
	wrongScope, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := artifactpkg.EncodeSettings(artifactpkg.Settings{Schema: "enkv/plugin-settings/v1", Applications: []artifactpkg.Application{{Directory: wrongScope, Plugins: plugins}}})
	if err != nil || os.WriteFile(filepath.Join(config, "enkv", "plugins.json"), wrong, 0600) != nil || os.WriteFile(capture, nil, 0600) != nil {
		t.Fatal("wrong-scope control unavailable")
	}
	stdout, stderr = limitedOutput{}, limitedOutput{}
	refused := runProcessOutput(ctx, artifact.CLI, filepath.Dir(source), []string{"apply", "--source", source, "--source-format", "json", "--json", "--log-level", "off"}, append(installationEnvironment(home, credentials.URL), "ENKV_NATIVE_PROCESS_POLICY="+policy), 30*time.Second, &stdout, &stderr)
	var refusal struct {
		State    string                       `json:"state_result"`
		Identity struct{ Stage, Code string } `json:"request_identity"`
	}
	if !refused.Started || !refused.Joined || refused.Status != "process_failed" || stdout.overflow || stderr.overflow || json.Unmarshal([]byte(stdout.String()), &refusal) != nil || refusal.State != "unavailable" || refusal.Identity.Stage != "construction" || refusal.Identity.Code != "evidence-unavailable" {
		t.Fatal("another application supplied output plugin trust")
	}
	observed, err = nativeprocess.ReadCapture(capture)
	if err != nil || len(observed.Events) != 1 || observed.Events[0].Kind != "footer" || observed.Events[0].Code != 3 || credentialCalls.Load() != 0 {
		t.Fatal("wrong-scope refusal entered SDK or provider work")
	}
	installationAssertPair(t, source, pair)
	if err := os.WriteFile(filepath.Join(config, "enkv", "plugins.json"), settings, 0600); err != nil {
		t.Fatal(err)
	}
	// Manifest selection adds a measured renderer but does not change the
	// domain's separately admitted output effect scopes.
	// Live preparation can have no cumulative deadline and shares construction
	// through the invocation artifact owner. Every author command still needs
	// its own finite dispatch allowance.
	manifestCtx, manifestOwner := withInvocationArtifacts(context.WithoutCancel(ctx))
	defer func() {
		if err := manifestOwner.close(context.WithoutCancel(ctx), true); err != nil {
			t.Error(err)
		}
	}()
	if _, bounded := manifestCtx.Deadline(); bounded {
		t.Fatal("manifest caller fixture has a cumulative deadline")
	}
	artifact.Plugins, artifact.ManifestRenderer, err = preparePublicConfigurationPlugins(manifestCtx, root, directory, catalog.Schedule{Selected: []string{"public-configuration.manifest/atomic_public_file"}}, outputs)
	if err != nil || !artifact.valid() || len(artifact.Plugins) != 6 || artifact.ManifestRenderer == nil || artifact.ManifestRenderer.Name != "generic-json" || artifact.ManifestRenderer.Version != "0.1.1" || artifact.ManifestRenderer.Length == 0 {
		t.Fatal("public manifest fixture lost its actual renderer build", err)
	}
	for _, condition := range []string{"directory", "metadata", "renderer"} {
		changed := artifact
		changed.Plugins = slices.Clone(artifact.Plugins)
		switch condition {
		case "directory":
			changed.Plugins[0].Directory = filepath.Dir(changed.Plugins[0].Directory)
		case "metadata":
			changed.Plugins[0].Metadata.Version = "99.0.0"
		case "renderer":
			renderer := *artifact.ManifestRenderer
			changed.ManifestRenderer = &renderer
			changed.ManifestRenderer.Artifact = strings.Repeat("0", 64)
		}
		if changed.valid() {
			t.Fatal("public fixture admitted a changed installation binding", condition)
		}
	}
	marker := filepath.Join(artifact.Plugins[0].Directory, "build.json")
	if err := os.Rename(marker, marker+".held"); err != nil {
		t.Fatal(err)
	}
	missingMarkerAccepted := artifact.valid()
	if err := os.Rename(marker+".held", marker); err != nil {
		t.Fatal(err)
	}
	if missingMarkerAccepted {
		t.Fatal("public fixture admitted a missing local build marker")
	}
	for _, child := range []string{artifact.CLI, artifact.Consumer} {
		observed, err := binaryRace(child)
		if err != nil || observed != outerRace {
			t.Errorf("public configuration child lost the outer race setting: path=%s compiled=%t want=%t error=%v", child, observed, outerRace, err)
		}
	}
	for i, output := range outputs {
		if output.Race {
			t.Fatal("normal output plugin used controlled race construction", i)
		}
		for _, owner := range []string{copied, root} {
			if err := verifyOutputArtifact(ctx, owner, directory, output); err != nil {
				t.Fatal("public output artifact/source closure differs", i, err)
			}
		}
		binding, err := outputBinding(output.Artifact)
		if err != nil || binding != bindings[i] {
			t.Fatal("public output profile binding differs", i, binding, err)
		}
		child := filepath.Join(directory, filepath.Base(output.Artifact.CommandPath))
		observed, err := binaryRace(child)
		if err != nil || observed || output.Race {
			t.Errorf("production output child race construction differs: path=%s compiled=%t recorded=%t error=%v", child, observed, output.Race, err)
		}
		for _, source := range []struct {
			files []artifactSourceFile
			names []string
		}{{output.ProtocolSource, []string{"LICENSE", "go.mod"}}, {output.SDKSource, []string{"LICENSE", "go.mod"}}, {output.PluginSource, []string{"LICENSE", "THIRD_PARTY_NOTICES.md", "go.mod", "go.sum"}}} {
			for _, name := range source.names {
				if !slices.ContainsFunc(source.files, func(file artifactSourceFile) bool { return file.Path == name && file.SHA256 != "" }) {
					t.Fatal("public output source metadata omitted", i, name)
				}
			}
		}
		t.Logf("output_profile=%s artifact_id=%x sha256=%x", binding.StoredProfileID, output.Artifact.ArtifactContractID, output.Artifact.SHA256)
	}
	for _, output := range outputs {
		changed := *output
		metadata := *output.Metadata
		metadata.Command = "example.invalid/other/cmd/output"
		changed.Metadata = &metadata
		if err := validateOutputArtifactClosures([]*outputArtifactClosure{&changed}); err == nil {
			t.Fatal("changed metadata expectation admitted")
		}
		changed = *output
		changed.DependencyManifest = slices.Clone(output.DependencyManifest)
		changed.DependencyManifest[len(changed.DependencyManifest)-1] ^= 1
		if err := validateOutputArtifactClosures([]*outputArtifactClosure{&changed}); err == nil {
			t.Fatal("changed dependency expectation admitted")
		}
	}
	binaryPath := filepath.Join(directory, filepath.Base(outputs[0].Artifact.CommandPath))
	binaryBefore, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binaryPath, []byte("substituted native output"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := verifyOutputArtifact(ctx, root, directory, outputs[0]); err == nil {
		t.Fatal("binary substitution admitted")
	}
	if err := os.WriteFile(binaryPath, binaryBefore, 0700); err != nil {
		t.Fatal(err)
	}
	protocolDirectory := filepath.Join(filepath.Dir(copied), "enkv-extensions", "sdk", "protocols", "output")
	if err := os.Rename(protocolDirectory, protocolDirectory+"-missing"); err != nil {
		t.Fatal(err)
	}
	for _, module := range []string{"plugins/aws-output", "plugins/gcp-output", "plugins/github-output"} {
		if _, _, err := listClosure(runGoEnvironment, ctx, copied, module, []string{"-mod=readonly"}, false); err == nil {
			t.Fatal("output kit resolved missing protocol outside its copy", module)
		}
	}
	if err := validateOutputArtifactClosures([]*outputArtifactClosure{{Race: true, Artifact: outputs[0].Artifact}}); err == nil {
		t.Fatal("installation without exact source closure admitted")
	}
	t.Logf("cli_sha256=%s output_profiles=%d", artifact.CLISHA256, len(outputs))
}

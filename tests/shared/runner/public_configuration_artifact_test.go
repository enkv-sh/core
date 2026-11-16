package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
	artifactpkg "enkv.sh/sdk/artifact"
)

// full_only: false
func TestPublicArtifactRendererPresenceKeepsArchivedIdentity(t *testing.T) {
	const zero = `{"name":"","version":"","protocol_id":"","descriptor_id":"","executor_id":"","artifact_contract_id":"","dependency_manifest_id":"","artifact_id":"","artifact_sha256":"","artifact_length":0}`
	const rendered = `{"name":"generic-json","version":"4.0.0","protocol_id":"protocol","descriptor_id":"descriptor","executor_id":"executor","artifact_contract_id":"contract","dependency_manifest_id":"dependency","artifact_id":"artifact","artifact_sha256":"digest","artifact_length":7}`
	const base = `{"cli_sha256":"cli","consumer_sha256":"consumer","overlay_sha256":"overlay","source_sha256":"source"`
	const artifactBase = `{"cli":"cli-path","cli_sha256":"cli","consumer":"consumer-path","consumer_sha256":"consumer","overlay":{"Path":"overlay-path","Manifest":"manifest-path","SHA256":"overlay","ManifestSHA256":"source"}`
	identities := map[string]bool{}
	s, _ := caseReceiptFixture(t, "live", "gcp", 0)
	for _, test := range []struct{ name, renderer string }{{"absent", ""}, {"explicit-zero", zero}, {"rendered", rendered}} {
		t.Run(test.name, func(t *testing.T) {
			suffix := "}"
			if test.renderer != "" {
				suffix = `,"manifest_renderer":` + test.renderer + "}"
			}
			wire := []byte(base + suffix)
			var closure publicConfigurationClosure
			if err := json.Unmarshal(wire, &closure); err != nil {
				t.Fatal(err)
			}
			roundtrip, err := json.Marshal(closure)
			if err != nil || !bytes.Equal(roundtrip, wire) {
				t.Fatal("archived closure renderer presence changed", err)
			}
			artifactWire := []byte(artifactBase + suffix)
			var artifact publicConfigurationArtifact
			if err := json.Unmarshal(artifactWire, &artifact); err != nil {
				t.Fatal(err)
			}
			roundtrip, err = json.Marshal(artifact)
			if err != nil || !bytes.Equal(roundtrip, artifactWire) || !reflect.DeepEqual(artifact.closure(), &closure) {
				t.Fatal("archived input renderer presence or closure changed", err)
			}
			restored := publicConfigurationArtifactFromClosure("/controlled/build", &closure, false)
			if !reflect.DeepEqual(restored.closure(), &closure) {
				t.Fatal("build restoration changed renderer presence")
			}
			s.record.BuildClosure.PublicConfiguration = &closure
			identity, err := caseIdentitySHA256(s.record)
			if err != nil || identities[identity] {
				t.Fatal("distinct renderer wire forms lost their case identity", err)
			}
			identities[identity] = true
			body, err := json.Marshal(s.record)
			var archived runRecord
			if err != nil || json.Unmarshal(body, &archived) != nil {
				t.Fatal("case archive unavailable", err)
			}
			after, err := caseIdentitySHA256(archived)
			if err != nil || after != identity {
				t.Fatal("renderer wire roundtrip changed case identity", err)
			}
		})
	}
}

// full_only: false
func TestPublicArtifactBindsExecutablesOverlayAndEverySource(t *testing.T) {
	for _, value := range []*bool{nil, raceSetting(false), raceSetting(true)} {
		wire := records.PublicProcessArtifact{Race: value, GeneratorArtifact: "generator", GeneratorSHA256: "generator-digest", GeneratorLength: 7, GeneratorManifest: "generator-manifest", CLI: "cli", CLISHA256: "cli-digest", Consumer: "consumer", ConsumerSHA256: "consumer-digest", Overlay: nativeprocess.Overlay{Path: "overlay", Manifest: "manifest", SHA256: "overlay-digest", ManifestSHA256: "manifest-digest"}}
		producer, err := json.Marshal(publicConfigurationArtifact(wire))
		if err != nil {
			t.Fatal(err)
		}
		shared, err := json.Marshal(wire)
		if err != nil || string(producer) != string(shared) {
			t.Fatal("producer artifact wire differs from the shared owner", err)
		}
	}
	want := []string{"build", "-mod=readonly", "-tags=netgo", "-trimpath", "-buildvcs=false", "-overlay=<overlay>", "-ldflags=" + publicConfigurationPluginTrust, "-o", "<executable>", "-race"}
	if !slices.Equal(publicConfigurationBuildArgs("<executable>", "<overlay>", true), want) {
		t.Fatal("public executable build lost its fixed race or source profile")
	}
	for _, condition := range []string{"complete", "cli", "consumer", "overlay", "manifest", "original", "replacement", "mapping", "duplicate-source"} {
		t.Run(condition, func(t *testing.T) {
			directory := t.TempDir()
			hash := func(body []byte) string {
				sum := sha256.Sum256(body)
				return hex.EncodeToString(sum[:])
			}
			fileHash := func(path string) string {
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				return hash(body)
			}
			artifact := publicConfigurationArtifact{CLI: filepath.Join(directory, "enkv"), Consumer: filepath.Join(directory, "consumer"),
				Overlay: nativeprocess.Overlay{Path: filepath.Join(directory, "overlay.json"), Manifest: filepath.Join(directory, "sources.json")}}
			original, replacement := filepath.Join(directory, "source.go"), filepath.Join(directory, "observed.go")
			for path, body := range map[string]string{artifact.CLI: "actual-cli", artifact.Consumer: "actual-consumer", original: "original-source", replacement: "observed-source"} {
				if err := os.WriteFile(path, []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			sources := []nativeprocess.Source{{Target: original, OriginalSHA256: hash([]byte("original-source")), Replacement: replacement, ReplacementSHA256: hash([]byte("observed-source"))}}
			mapping := struct{ Replace map[string]string }{map[string]string{original: replacement}}
			if err := records.WriteJSON(artifact.Overlay.Path, mapping, 0600); err != nil {
				t.Fatal(err)
			}
			if err := records.WriteJSON(artifact.Overlay.Manifest, sources, 0600); err != nil {
				t.Fatal(err)
			}
			for path, target := range map[string]*string{artifact.CLI: &artifact.CLISHA256, artifact.Consumer: &artifact.ConsumerSHA256, artifact.Overlay.Path: &artifact.Overlay.SHA256, artifact.Overlay.Manifest: &artifact.Overlay.ManifestSHA256} {
				*target = fileHash(path)
			}
			if !artifact.valid() {
				t.Fatal("complete public source closure refused")
			}
			switch condition {
			case "complete":
				return
			case "mapping":
				mapping.Replace[original] = original
				if err := records.WriteJSON(artifact.Overlay.Path, mapping, 0600); err != nil {
					t.Fatal(err)
				}
				artifact.Overlay.SHA256 = fileHash(artifact.Overlay.Path)
			case "duplicate-source":
				if err := records.WriteJSON(artifact.Overlay.Manifest, append(sources, sources...), 0600); err != nil {
					t.Fatal(err)
				}
				artifact.Overlay.ManifestSHA256 = fileHash(artifact.Overlay.Manifest)
			default:
				path := map[string]string{"cli": artifact.CLI, "consumer": artifact.Consumer, "overlay": artifact.Overlay.Path, "manifest": artifact.Overlay.Manifest, "original": original, "replacement": replacement}[condition]
				if err := os.WriteFile(path, []byte("changed-body"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if artifact.valid() {
				t.Fatal("changed public source closure retained its identity", condition)
			}
		})
	}
	original := assemblyClosure{Suite: "live", Provider: "aws", Race: true, BinarySHA256: "worker", OverlaySHA256: "worker-overlay",
		PublicConfiguration: &publicConfigurationClosure{CLISHA256: "cli", ConsumerSHA256: "consumer", OverlaySHA256: "overlay", SourceSHA256: "sources"}}
	if !sameAssemblyBuild(original, original) {
		t.Fatal("identical public executable closure refused continuation")
	}
	for _, condition := range []string{"missing", "cli", "consumer", "overlay", "sources"} {
		changed := original
		closure := *original.PublicConfiguration
		changed.PublicConfiguration = &closure
		switch condition {
		case "missing":
			changed.PublicConfiguration = nil
		case "cli":
			closure.CLISHA256 = "changed"
		case "consumer":
			closure.ConsumerSHA256 = "changed"
		case "overlay":
			closure.OverlaySHA256 = "changed"
		case "sources":
			closure.SourceSHA256 = "changed"
		}
		if sameAssemblyBuild(changed, original) {
			t.Fatal("continuation replaced the public executable source closure", condition)
		}
	}
}

// full_only: false
func TestPublicGeneratedProductionBuildBindingIsExact(t *testing.T) {
	binding := cloudflareAssemblyBinding{ArtifactSHA256: strings.Repeat("a", 64), ArtifactLength: 123, DependencyManifest: strings.Repeat("b", 64)}
	wantFlags := "independent fixture linker facts"
	valid := debug.BuildInfo{GoVersion: "go1.27.3", Path: modulePrefix + "compositions/full/cmd/enkv", Main: debug.Module{Path: modulePrefix + "compositions/full"}, Settings: []debug.BuildSetting{{Key: "-tags", Value: "netgo"}, {Key: "-race", Value: "true"}, {Key: "-trimpath", Value: "true"}}}
	for _, condition := range []string{"exact", "recorded-linker-flags", "empty-linker-flags", "test-main", "test-tag", "duplicate", "missing-race", "missing-trimpath", "wrong-toolchain", "old-toolchain"} {
		t.Run(condition, func(t *testing.T) {
			info := valid
			info.Settings = slices.Clone(valid.Settings)
			switch condition {
			case "recorded-linker-flags":
				info.Settings = append(info.Settings, debug.BuildSetting{Key: "-ldflags", Value: wantFlags})
			case "empty-linker-flags":
				info.Settings = append(info.Settings, debug.BuildSetting{Key: "-ldflags"})
			case "test-main":
				info.Path = cloudflareTestArtifactMain
			case "test-tag":
				info.Settings[0].Value = cloudflareTestArtifactTag
			case "duplicate":
				info.Settings = append(info.Settings, info.Settings[0])
			case "missing-race":
				info.Settings[1].Value = "false"
			case "missing-trimpath":
				info.Settings[2].Value = "false"
			case "wrong-toolchain":
				info.GoVersion = "go0.0.0"
			case "old-toolchain":
				info.GoVersion = "go1.27.0"
			}
			if publicGeneratorBuildSettingsValid(&info, true) != (condition == "exact") {
				t.Fatal("public production build profile differs", condition)
			}
		})
	}
	original := assemblyClosure{Suite: "live", Provider: "aws", Race: true, BinarySHA256: "worker", OverlaySHA256: "overlay", PublicConfiguration: &publicConfigurationClosure{CLISHA256: "cli", ConsumerSHA256: "consumer", OverlaySHA256: "overlay", SourceSHA256: "source", GeneratorSHA256: binding.ArtifactSHA256, GeneratorLength: binding.ArtifactLength, GeneratorManifest: binding.DependencyManifest}}
	for _, field := range []string{"artifact", "length", "manifest"} {
		changed := original
		closure := *original.PublicConfiguration
		changed.PublicConfiguration = &closure
		switch field {
		case "artifact":
			closure.GeneratorSHA256 = strings.Repeat("e", 64)
		case "length":
			closure.GeneratorLength++
		case "manifest":
			closure.GeneratorManifest = strings.Repeat("f", 64)
		}
		if sameAssemblyBuild(changed, original) {
			t.Fatal("continuation replaced production plugin closure", field)
		}
	}
}

// full_only: false
func TestPublicGeneratedArtifactAssemblyOnMaintainedSource(t *testing.T) {
	root, directory := maintainedCloudflareRoot(t), publicPluginBuildOutput(t)
	ctx, cancel := context.WithTimeout(testRaceContext(t, t.Context()), 2*time.Minute)
	defer cancel()
	plugin, err := buildCloudflareArtifacts(ctx, root, directory)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := cloudflareBinding(plugin, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	binding.artifactPath = filepath.Join(directory, "enkv-generator-cloudflare")
	for _, damage := range []string{"missing-installation", "hash", "length", "dependency"} {
		changed := *binding
		switch damage {
		case "missing-installation":
			changed.Installation = nil
		case "hash":
			changed.ArtifactSHA256 = strings.Repeat("0", 64)
		case "length":
			changed.ArtifactLength++
		case "dependency":
			changed.Dependency = append(slices.Clone(changed.Dependency), 0)
		}
		if _, err := publicGeneratorMetadata(&changed); err == nil {
			t.Fatal("changed captured generator binding was admitted", damage)
		}
	}
	artifact, err := buildPublicConfigurationArtifact(ctx, root, directory, nil, binding)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifact.Plugins) != 1 || artifact.Plugins[0].Metadata.Name != "cloudflare-account-token" || artifact.Plugins[0].Metadata.Role != "generator" {
		t.Fatal("public generator fixture lost its exact captured local build")
	}
	source := installationSource(t, "aws", false)
	pair := installationPairImage(t, source)
	home, config := installationHome(t)
	application, err := filepath.EvalSymlinks(filepath.Dir(source))
	if err != nil {
		t.Fatal(err)
	}
	settings, err := artifactpkg.EncodeSettings(artifactpkg.Settings{Schema: "enkv/plugin-settings/v1", Applications: []artifactpkg.Application{{Directory: application, Plugins: []artifactpkg.LocalPlugin{{Name: "cloudflare-account-token", Directory: artifact.Plugins[0].Directory}}}}})
	if err != nil || os.MkdirAll(filepath.Join(config, "enkv"), 0700) != nil || os.WriteFile(filepath.Join(config, "enkv", "plugins.json"), settings, 0600) != nil {
		t.Fatal("captured generator application settings unavailable")
	}
	var credentialCalls atomic.Int64
	credentials := installationCredentialRefusal(t, &credentialCalls)
	capture, policy := filepath.Join(t.TempDir(), "capture.jsonl"), filepath.Join(t.TempDir(), "policy.json")
	encoded, err := json.Marshal(nativeprocess.Policy{Version: 1, RecordPath: capture, MaxRequests: 1, MaxBytes: 1024, NoKMS: true})
	if err != nil || os.WriteFile(capture, nil, 0600) != nil || os.WriteFile(policy, encoded, 0600) != nil {
		t.Fatal("generator passive capture unavailable")
	}
	prepared := installationCLICommand(t, ctx, artifact.CLI, source, append(installationEnvironment(home, credentials.URL), "ENKV_NATIVE_PROCESS_POLICY="+policy), 0, "prepare")
	var readiness struct {
		Schema, Branch, Outcome string
		Dependencies            struct {
			Rows []struct{ Name, Role, Status, Source string } `json:"installations"`
		}
	}
	if json.Unmarshal(prepared, &readiness) != nil || readiness.Schema != "enkv/prepare-result/v2" || readiness.Branch != "existing" || readiness.Outcome != "complete" || len(readiness.Dependencies.Rows) != 1 {
		t.Fatal("captured generator did not prepare its exact local dependency")
	}
	row := readiness.Dependencies.Rows[0]
	if row.Name != "cloudflare-account-token" || row.Role != "generator" || row.Status != "verified" || row.Source != "local" {
		t.Fatal("captured generator preparation changed installation facts")
	}
	observed, err := nativeprocess.ReadCapture(capture)
	if err != nil || len(observed.Events) != 1 || observed.Events[0].Kind != "footer" || observed.Events[0].Code != 0 || credentialCalls.Load() != 0 {
		t.Fatal("generator preparation acquired credentials or provider work")
	}
	installationAssertPair(t, source, pair)
	info, err := buildinfo.ReadFile(artifact.CLI)
	if err != nil {
		t.Fatal(err)
	}
	for _, setting := range info.Settings {
		if setting.Key == "-ldflags" {
			t.Fatal("trimpath unexpectedly recorded linker flags")
		}
	}
	body, err := os.ReadFile(artifact.CLI)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	if hex.EncodeToString(digest[:]) != artifact.CLISHA256 || !artifact.valid() {
		t.Fatal("actual public executable does not match its successful build closure")
	}
	restored := publicConfigurationArtifactFromClosure(directory, artifact.closure(), raceEnabled(ctx))
	if !restored.valid() || !reflect.DeepEqual(restored.closure(), artifact.closure()) {
		t.Fatal("exact public executable closure did not survive restoration")
	}
	for _, condition := range []string{"plugin-hash", "plugin-length", "plugin-dependency", "plugin-role", "cli-hash", "consumer-hash"} {
		t.Run(condition, func(t *testing.T) {
			changed := restored
			switch condition {
			case "plugin-hash":
				changed.GeneratorSHA256 = strings.Repeat("0", 64)
			case "plugin-length":
				changed.GeneratorLength++
			case "plugin-dependency":
				changed.GeneratorManifest = strings.Repeat("0", 64)
			case "plugin-role":
				changed.Plugins = slices.Clone(changed.Plugins)
				changed.Plugins[0].Metadata.Role = "output"
			case "cli-hash":
				changed.CLISHA256 = strings.Repeat("0", 64)
			case "consumer-hash":
				changed.ConsumerSHA256 = strings.Repeat("0", 64)
			}
			if changed.valid() {
				t.Fatal("changed artifact retained the successful build identity")
			}
		})
	}
	t.Logf("go=%s tuple=%s plugin_sha256=%s plugin_length=%d manifest_sha256=%s cli_sha256=%s consumer_sha256=%s overlay_sha256=%s source_sha256=%s",
		plugin.GoVersion, plugin.NativeTuple, artifact.GeneratorSHA256, artifact.GeneratorLength, artifact.GeneratorManifest,
		artifact.CLISHA256, artifact.ConsumerSHA256, artifact.Overlay.SHA256, artifact.Overlay.ManifestSHA256)
}

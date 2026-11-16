package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/sdk/artifact"
)

// full_only: false
func TestStockPluginGeneratorCoordinatesDoNotRequirePrebuiltArtifact(t *testing.T) {
	good := generatorReference{Account: strings.Repeat("a", 32), PermissionGroup: strings.Repeat("b", 32)}
	if _, err := validateStockGenerator(good); err != nil {
		t.Fatal("stock coordinates require an unrelated earlier plugin build", err)
	}
	if _, err := validateGeneratorFields(good, t.TempDir()); err == nil {
		t.Fatal("legacy generator lost its exact installed artifact requirement")
	}
	for _, damage := range []generatorReference{
		{Account: good.Account, PermissionGroup: good.PermissionGroup, Artifact: "/earlier/plugin"},
		{Account: good.Account, PermissionGroup: good.PermissionGroup, CredentialsFile: "/credential-file"},
		{Account: "wrong", PermissionGroup: good.PermissionGroup},
	} {
		if _, err := validateStockGenerator(damage); err == nil {
			t.Fatal("stock coordinates accepted an extra executable, credential route or malformed account")
		}
	}
}

// full_only: false
func TestStockPluginFixtureEnvironmentRefusesOwnerAndCredentialRouteDrift(t *testing.T) {
	root := maintainedCloudflareRoot(t)
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			load := func() environmentFile {
				var environment environmentFile
				if readSelectionFile(filepath.Join(root, "tests", "environments", "stock-plugin-"+provider+".example.json"), &environment) != nil {
					t.Fatal("stock fixture example unavailable")
				}
				environment.Generator = &generatorReference{Account: strings.Repeat("a", 32), PermissionGroup: strings.Repeat("b", 32)}
				return environment
			}
			good := load()
			if err := validateEnvironment(&good, root); err != nil {
				t.Fatal("correct explicit fixture environment refused", err)
			}
			for _, damage := range []struct {
				name   string
				change func(*environmentFile)
			}{
				{"different-bucket", func(v *environmentFile) { v.Resource.Settings["bucket"] = "ordinary-shared-state" }},
				{"different-owner", func(v *environmentFile) { v.PluginAcceptance.Account, v.PluginAcceptance.ProjectNumber = "", "" }},
				{"different-region", func(v *environmentFile) { v.PluginAcceptance.Region = "other-region" }},
				{"different-recovery-mode", func(v *environmentFile) { v.Resource.Settings["recovery_mode"] = "disabled" }},
				{"static-credential-route", func(v *environmentFile) {
					participant := v.Participants[v.RoleBindings["apply"]]
					if provider == "aws" {
						participant.Access.SDK.Mode = "aws-shared-credentials"
					} else {
						participant.Access.SDK.Mode = "gcp-service-account-adc"
						participant.Access.SDK.CredentialsFile = "/static/service-account.json"
					}
				}},
			} {
				t.Run(damage.name, func(t *testing.T) {
					v := load()
					damage.change(&v)
					if validateEnvironment(&v, root) == nil {
						t.Fatal("different fixture or credential route admitted")
					}
				})
			}
		})
	}
}

// full_only: false
func TestStockPluginClosurePreservesBuildOwnerWithoutPublishingAbsolutePaths(t *testing.T) {
	build, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	v := records.StockPluginArtifact{CLI: records.StockPluginFile{Path: filepath.Join(build, "stock", "enkv")}, Archive: records.StockPluginFile{Path: filepath.Join(build, "stock", "archive.tar.gz")}, GeneratorA: records.StockPluginBuild{Directory: filepath.Join(build, "a")}, GeneratorB: records.StockPluginBuild{Directory: filepath.Join(build, "b")}, Renderer: records.StockPluginBuild{Directory: filepath.Join(build, "renderer")}, Outputs: []records.StockPluginBuild{{Directory: filepath.Join(build, "output")}}}
	closure, err := stockPluginClosureFromArtifact(build, v)
	if err != nil {
		t.Fatal(err)
	}
	if closure.Artifact.CLI.Path != "stock/enkv" || closure.Artifact.GeneratorB.Directory != "b" || closure.Artifact.Outputs[0].Directory != "output" {
		t.Fatal("public closure lost exact build-relative paths")
	}
	actual, err := stockPluginArtifactFromClosure(build, closure)
	if err != nil || !reflect.DeepEqual(v, actual) {
		t.Fatal("original build-owner reconstruction differs", err)
	}
	for _, path := range []string{"../other", "/outside", "a/../b"} {
		changed, err := cloneStockPluginArtifact(closure.Artifact)
		if err != nil {
			t.Fatal(err)
		}
		changed.GeneratorB.Directory = path
		if _, err := stockPluginArtifactFromClosure(build, &stockPluginClosure{Artifact: changed}); err == nil {
			t.Fatal("different build owner accepted", path)
		}
	}
}

// full_only: false
func TestStockPluginEvidenceRequiresOriginalWorkerNonceAndActor(t *testing.T) {
	joins := []records.PublicConfigurationWorkerJoin{
		{Worker: "writer", Nonce: strings.Repeat("a", 32), Role: "writer", Actor: "authority", InvocationSHA256: strings.Repeat("1", 64), ResultSHA256: strings.Repeat("2", 64), Started: true, Joined: true, Process: "passed"},
		{Worker: "fresh", Nonce: strings.Repeat("b", 32), Role: "fresh_after", Actor: "reader", InvocationSHA256: strings.Repeat("3", 64), ResultSHA256: strings.Repeat("4", 64), Started: true, Joined: true, Process: "passed"},
		{Worker: "cleanup", Nonce: strings.Repeat("c", 32), Role: "cleanup", Actor: "cleaner", InvocationSHA256: strings.Repeat("5", 64), ResultSHA256: strings.Repeat("6", 64), Started: true, Joined: true, Process: "passed"},
	}
	evidence := records.StockPluginEvidence{Commands: []records.StockPluginCommand{
		{Worker: "writer", Nonce: joins[0].Nonce, Role: "apply", Actor: "publisher"},
		{Worker: "fresh", Nonce: joins[1].Nonce, Role: "reader", Actor: "reader"},
	}}
	actors := map[string]string{"apply": "publisher", "reader": "reader"}
	if validateStockCommandJoins(evidence, joins, actors) != nil {
		t.Fatal("original joined workers refused")
	}
	for _, condition := range []string{"foreign-worker", "foreign-nonce", "foreign-actor", "unjoined", "missing-fresh-command"} {
		t.Run(condition, func(t *testing.T) {
			commands := append([]records.StockPluginCommand(nil), evidence.Commands...)
			workers := append([]records.PublicConfigurationWorkerJoin(nil), joins...)
			switch condition {
			case "foreign-worker":
				commands[0].Worker = "substitute"
			case "foreign-nonce":
				commands[0].Nonce = strings.Repeat("d", 32)
			case "foreign-actor":
				commands[0].Actor = "authority"
			case "unjoined":
				workers[0].Joined = false
			case "missing-fresh-command":
				commands = commands[:1]
			}
			v := records.StockPluginEvidence{Commands: commands}
			if validateStockCommandJoins(v, workers, actors) == nil {
				t.Fatal("substituted or incomplete original worker accepted")
			}
		})
	}
}

// full_only: false
func TestStockPluginEvidenceDoesNotOptionalizeOverlayEvidence(t *testing.T) {
	parent := runRecord{Suite: "live"}
	if publicConfigurationEvidenceRequired(parent, scenarioResult{Entry: catalog.Entry{Scenario: records.StockPluginScenario}}) {
		t.Fatal("stock case was forced to invent native observer captures")
	}
	legacy := scenarioResult{Entry: catalog.Entry{Scenario: "public-configuration.manifest/atomic_public_file"}}
	if !publicConfigurationEvidenceRequired(parent, legacy) || readPublicConfigurationEvidence(t.TempDir(), parent, legacy) == nil {
		t.Fatal("ordinary overlay case lost its required native evidence")
	}
	if readStockPluginEvidence(t.TempDir(), parent, scenarioResult{Entry: catalog.Entry{Scenario: records.StockPluginScenario}}) == nil {
		t.Fatal("stock case passed without its own exact evidence")
	}
}

// full_only: false
func TestStockPluginPrefixEvidenceRequiresOriginalCanonicalGrantAndObservation(t *testing.T) {
	const run = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const prefix = "enkv-test/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/stock-case"
	const limitBody = `{"requests":1,"body_bytes":1,"objects":1,"object_bytes":1,"generator_creates":1,"generator_retires":1,"elapsed_seconds":1,"cleanup_requests":1,"cleanup_bytes":1,"cleanup_seconds":1}`
	const fixtureBody = `{"schema":1,"purpose":"stock-plugin-acceptance","fixture_id":"0123456789abcdef0123456789abcdef","provider":"aws","region":"us-east-1","bucket":"fixture-pa-0123456789abcdef0123456789abcdef","account":"123456789012"}`
	hash := func(body []byte) string {
		id := sha256.Sum256(body)
		return hex.EncodeToString(id[:])
	}
	// These literals independently fix the private wire record's field order,
	// its LF and the exact prefix-observation statement.
	grantBody := `{"schema":1,"fixture":` + fixtureBody + `,"run_id":"` + run + `","scenario":"public-configuration.plugin-contracts/plugin_contracts","prefix":"` + prefix + `","limits_sha256":"` + hash([]byte(limitBody)) + `","preflight_empty":true,"bucket_identity":"fixture-observation"}` + "\n"
	cleanupBody := `{"schema":1,"run_id":"` + run + `","fixture_id":"0123456789abcdef0123456789abcdef","prefix":"` + prefix + `","bucket_identity":"fixture-observation","started":true,"completed":true,"observed_empty":true}` + "\n"
	var allowance limits
	good := stockPluginEvidenceManifest{GrantSHA256: hash([]byte(grantBody)), PrefixCleanupSHA256: hash([]byte(cleanupBody))}
	if json.Unmarshal([]byte(limitBody), &allowance) != nil || json.Unmarshal([]byte(fixtureBody), &good.Fixture) != nil || json.Unmarshal([]byte(grantBody), &good.Grant) != nil || json.Unmarshal([]byte(cleanupBody), &good.PrefixCleanup) != nil {
		t.Fatal("independent prefix proof literals failed to decode")
	}
	if good.validatePrefixCleanup(run, prefix, &allowance) != nil {
		t.Fatal("original canonical prefix proof refused")
	}
	for _, mode := range []os.FileMode{0400, 0600, 0444} {
		t.Run("grant-mode-"+mode.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "stock-plugin-grant.json")
			// writeNewLiveJSON uses this same records writer with immutable mode.
			if err := records.WriteJSON(path, good.Grant, 0400); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			grant, body, err := readStockPluginGrant(path)
			if mode == 0400 {
				if err != nil || !reflect.DeepEqual(grant, good.Grant) || string(body) != grantBody {
					t.Fatal("immutable original grant was not retained exactly", err)
				}
			} else if err == nil {
				t.Fatal("non-immutable grant accepted")
			}
		})
	}
	t.Run("grant-unknown-field", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "stock-plugin-grant.json")
		body := strings.TrimSuffix(grantBody, "}\n") + ",\"unknown\":true}\n"
		if err := os.WriteFile(path, []byte(body), 0400); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readStockPluginGrant(path); err == nil {
			t.Fatal("unknown grant field accepted")
		}
	})
	for _, damage := range []struct {
		name   string
		change func(*stockPluginEvidenceManifest)
	}{
		{"different-run", func(v *stockPluginEvidenceManifest) {
			v.Grant.RunID, v.PrefixCleanup.RunID = strings.Repeat("b", 32), strings.Repeat("b", 32)
		}},
		{"different-prefix", func(v *stockPluginEvidenceManifest) {
			v.Grant.Prefix += "-sibling"
			v.PrefixCleanup.Prefix = v.Grant.Prefix
		}},
		{"different-fixture", func(v *stockPluginEvidenceManifest) { v.Fixture.Bucket = "other-pa-0123456789abcdef0123456789abcdef" }},
		{"different-limits", func(v *stockPluginEvidenceManifest) { v.Grant.LimitsSHA256 = strings.Repeat("e", 64) }},
		{"no-original-preflight", func(v *stockPluginEvidenceManifest) { v.Grant.PreflightEmpty = false }},
		{"different-bucket-observation", func(v *stockPluginEvidenceManifest) { v.PrefixCleanup.BucketIdentity = "other-observation" }},
		{"incomplete", func(v *stockPluginEvidenceManifest) { v.PrefixCleanup.Completed = false }},
		{"no-empty-observation", func(v *stockPluginEvidenceManifest) { v.PrefixCleanup.ObservedEmpty = false }},
	} {
		t.Run(damage.name, func(t *testing.T) {
			v := good
			damage.change(&v)
			// Re-seal damaged records so a checksum mismatch cannot mask the
			// required original-run and observation relations.
			grant, grantErr := json.Marshal(v.Grant)
			cleanup, cleanupErr := json.Marshal(v.PrefixCleanup)
			if grantErr != nil || cleanupErr != nil {
				t.Fatal("controlled proof damage could not be encoded")
			}
			v.GrantSHA256, v.PrefixCleanupSHA256 = hash(append(grant, '\n')), hash(append(cleanup, '\n'))
			if v.validatePrefixCleanup(run, prefix, &allowance) == nil {
				t.Fatal("changed original grant or cleanup observation accepted")
			}
		})
	}
	for _, field := range []string{"grant", "cleanup"} {
		t.Run(field+"-digest", func(t *testing.T) {
			v := good
			if field == "grant" {
				v.GrantSHA256 = strings.Repeat("f", 64)
			} else {
				v.PrefixCleanupSHA256 = strings.Repeat("f", 64)
			}
			if v.validatePrefixCleanup(run, prefix, &allowance) == nil {
				t.Fatal("unverified nested record digest accepted")
			}
		})
	}
}

// full_only: false
func TestStockPluginArtifactPreparesOrdinaryBuildsAfterUnchangedCLI(t *testing.T) {
	// Match the supervisor's parent flags. Stock packaging uses its own
	// sealed compiler environment.
	t.Setenv("GOFLAGS", buildGoFlags+" -p=2")
	ctx, cancel := context.WithTimeout(cacheOnlyGoContext(t.Context()), 15*time.Minute)
	defer cancel()
	root := maintainedCloudflareRoot(t)
	parent := filepath.Join(root, "tests", "live", "runs")
	if err := os.MkdirAll(parent, 0700); err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(parent, "enkv-stock-plugin-construction-")
	if err != nil {
		t.Fatal(err)
	}
	joined := true
	t.Cleanup(func() {
		if !joined {
			t.Error("unjoined construction retained its fixture", directory)
			return
		}
		// Published builds keep their immutable modes until all children have
		// joined and all checks have finished. Only their owned directories
		// need write permission for removal; executable modes stay intact.
		if err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return os.Chmod(path, 0700)
			}
			return nil
		}); err != nil {
			t.Error("construction fixture cleanup preparation failed", err)
			return
		}
		if err := os.RemoveAll(directory); err != nil {
			t.Error("construction fixture cleanup failed", err)
		}
	})
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	directory = canonical
	checkout, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(checkout, directory)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		t.Fatal("construction fixture is not inside the checkout", err)
	}
	binding, err := prepareBinding(runGoEnvironment, ctx, root, true)
	joined = toolCommandsJoined(err)
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]stockCLIKeyInput, 2)
	for i, input := range []struct{ name, body string }{
		{"guard-cli-public.pem", cliArchiveCLIPublicPEM},
		{"guard-plugin-public.pem", cliArchivePluginPublicPEM},
	} {
		path, body := filepath.Join(directory, input.name), []byte(input.body)
		if err := os.WriteFile(path, body, 0400); err != nil {
			t.Fatal(err)
		}
		keys[i] = stockCLIKeyInput{path: path, expected: artifact.DigestLength{SHA256: artifact.Hash(body), Length: uint64(len(body))}}
	}
	refused := filepath.Join(directory, "guard-refused")
	_, guardErr := prepareStockCLI(ctx, root, refused, stockCLIConstruction{version: "0.1.0", cliKey: keys[0], pluginKeys: keys[1:]}, binding)
	joined = joined && toolCommandsJoined(guardErr)
	if guardErr == nil || guardErr.Error() != "stock CLI preparation must be outside source checkouts" {
		t.Fatal("inside-checkout CLI construction did not preserve its guard", guardErr)
	}
	if _, err := os.Lstat(refused); !os.IsNotExist(err) {
		t.Fatal("refused CLI construction created an output", err)
	}
	ctx, artifactOwner := withInvocationArtifacts(ctx)
	defer func() {
		if err := artifactOwner.close(ctx, joined); err != nil {
			t.Error("stock construction owner did not settle", err)
		}
	}()
	var first *records.StockPluginArtifact
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			expectedOutputs := 1
			if provider == "aws" {
				expectedOutputs = 4
			}
			value, err := prepareStockPluginArtifact(ctx, root, filepath.Join(directory, provider), provider, binding)
			joined = joined && toolCommandsJoined(err)
			if err != nil {
				t.Fatal(err)
			}
			if value.Validate(provider) != nil || len(value.Outputs) != expectedOutputs || value.Renderer.Metadata.Name != "workshop-ini" || value.GeneratorA.Metadata.Executable == value.GeneratorB.Metadata.Executable {
				t.Fatal("independently built post-capture families differ")
			}
			if first == nil {
				captured := value
				first = &captured
			} else {
				if value.CLI.SHA256 != first.CLI.SHA256 || value.CLI.Length != first.CLI.Length || value.Archive.SHA256 != first.Archive.SHA256 || value.Archive.Length != first.Archive.Length {
					t.Fatal("provider consumers changed captured CLI bytes")
				}
				for _, builds := range [][2]records.StockPluginBuild{{first.GeneratorA, value.GeneratorA}, {first.GeneratorB, value.GeneratorB}, {first.Renderer, value.Renderer}} {
					originalMarker, originalPath := publicPluginBuildSelection(t, builds[0].Directory)
					borrowedMarker, borrowedPath := publicPluginBuildSelection(t, builds[1].Directory)
					if !reflect.DeepEqual(builds[0].Metadata, builds[1].Metadata) || originalMarker != borrowedMarker {
						t.Fatal("provider consumers changed shared plugin construction")
					}
					original, originalErr := os.Stat(originalPath)
					borrowed, borrowedErr := os.Stat(borrowedPath)
					if originalErr != nil || borrowedErr != nil || !os.SameFile(original, borrowed) {
						t.Fatal("provider consumers did not borrow the same plugin executable", originalPath, borrowedPath, originalErr, borrowedErr)
					}
				}
				for _, files := range [][2]string{{first.CLI.Path, value.CLI.Path}, {first.Archive.Path, value.Archive.Path}} {
					original, originalErr := os.Stat(files[0])
					borrowed, borrowedErr := os.Stat(files[1])
					if originalErr != nil || borrowedErr != nil || !os.SameFile(original, borrowed) {
						t.Fatal("provider consumers did not borrow the same captured CLI bytes", files, originalErr, borrowedErr)
					}
				}
			}
			closure, err := stockPluginClosureFromArtifact(artifactOwner.current.path, value)
			if err != nil {
				t.Fatal("stock artifact escaped the retained build owner", err)
			}
			restored, err := stockPluginArtifactFromClosure(artifactOwner.current.path, closure)
			if err != nil || !reflect.DeepEqual(restored, value) {
				t.Fatal("stock artifact did not survive external owner cleanup and closure reconstruction", err)
			}
			if err := verifyStockPluginArtifact(ctx, restored, provider); err != nil {
				t.Fatal("reconstructed stock artifact verification failed", err)
			}
			assertCompleteStockPluginEvidencePredicates(t, value, provider)
			for _, damage := range []string{"cli", "plugin"} {
				t.Run(damage, func(t *testing.T) {
					path := value.CLI.Path
					if damage == "plugin" {
						_, path = publicPluginBuildSelection(t, value.GeneratorB.Directory)
					}
					body, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					mode, err := os.Stat(path)
					if err != nil {
						t.Fatal(err)
					}
					defer func() {
						if os.WriteFile(path, body, 0600) != nil || os.Chmod(path, mode.Mode().Perm()) != nil {
							t.Error("restore original artifact")
						}
					}()
					if os.Chmod(path, 0600) != nil || os.WriteFile(path, []byte("changed executable"), 0600) != nil {
						t.Fatal("artifact damage failed")
					}
					if verifyStockPluginArtifact(ctx, value, provider) == nil {
						t.Fatal("changed exact executable admitted")
					}
				})
				if err := verifyStockPluginArtifact(ctx, value, provider); err != nil {
					t.Fatal("restored exact artifact refused", err)
				}
			}
		})
		if !joined {
			t.Fatal("construction did not settle; later provider cell refused")
		}
	}
}

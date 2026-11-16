package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/crypto/testsupport/installedarchive"
)

func configurationRecoveryTestAssembly(t *testing.T) (string, string, assembly) {
	return configurationRecoveryTestAssemblyFor(t, "hermetic", "memory")
}
func configurationRecoveryTestAssemblyFor(t *testing.T, suite, provider string) (string, string, assembly) {
	t.Helper()
	ctx := testRaceContext(t, t.Context())
	root := testRepositoryRoot(t)
	directory, pathErr := filepath.EvalSymlinks(t.TempDir())
	if pathErr != nil {
		t.Fatal(pathErr)
	}
	if retained := os.Getenv("ENKV_RECOVERY_EVIDENCE_DIRECTORY"); retained != "" {
		if !filepath.IsAbs(retained) {
			t.Fatal("private evidence directory must be absolute")
		}
		if err := os.MkdirAll(retained, 0700); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(retained)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			t.Fatal("private evidence owner refused")
		}
		directory = filepath.Join(retained, url.PathEscape(t.Name()))
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	bootstrap := filepath.Join(directory, "bootstrap.json")
	replacements := map[string]string{}
	for _, owner := range []string{"catalog", "records"} {
		entries, err := os.ReadDir(filepath.Join(root, "tests/shared", owner))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") {
				replacements[filepath.Join(root, "core/internal/test"+owner, entry.Name())] = filepath.Join(root, "tests/shared", owner, entry.Name())
			}
		}
	}
	if err := records.WriteJSON(bootstrap, struct{ Replace map[string]string }{replacements}, 0600); err != nil {
		t.Fatal(err)
	}
	setup, err := buildAssembly(runGoEnvironment, nil, ctx, root, suite, provider, bootstrap, directory)
	if err != nil {
		t.Fatal(err)
	}
	return root, directory, setup
}

// full_only: false
func TestConfigurationRecoveryJoinedProcesses(t *testing.T) {
	t.Parallel()
	root, directory, setup := configurationRecoveryTestAssembly(t)
	for _, provider := range []string{"aws", "gcp"} {
		driver := sharedConfigurationRecoveryFixture(t, root, directory, setup, provider)
		for _, recovery := range []bool{false, true} {
			mode := "disabled"
			if recovery {
				mode = "enabled"
			}
			t.Run(provider+"-"+mode, func(t *testing.T) {
				ctx := testRaceContext(t, t.Context())
				path := filepath.Join(directory, provider+"-"+mode)
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				evidence, err := runConfigurationRecoveryProcesses(ctx, root, path, setup, driver, recovery, "complete")
				if saveErr := records.WriteJSON(filepath.Join(path, "process-evidence.json"), evidence, 0600); saveErr != nil {
					t.Fatal(saveErr)
				}
				if err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// full_only: false
func TestConfigurationRecoveryPhaseUsesOneTestLane(t *testing.T) {
	for _, parallel := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("parallel-%d", parallel), func(t *testing.T) {
			binary := prebuiltWorkerArgumentFixture(t)
			directory := filepath.Dir(binary)
			body, err := os.ReadFile(binary)
			if err != nil {
				t.Fatal(err)
			}
			var workingDirectory []string
			if parallel == 2 {
				workingDirectory = []string{t.TempDir()}
			}
			name := "TestControlledReconstruction"
			phase, err := runConfigurationRecoveryPhase(withExecutionParallel(t.Context(), parallel), directory, binary, digestBytes(body), "reconstruction", name, goEnvironment(), workingDirectory...)
			if err == nil {
				t.Error("controlled reconstruction refusal became success")
			}
			assertPrebuiltWorkerArguments(t, binary, phase.Process, []string{"-test.v=test2json", "-test.count=1", "-test.timeout=50s", "-test.run=^" + name + "$", "-test.parallel=1"})
			if phase.Phase != "reconstruction" || phase.BinarySHA256 != digestBytes(body) || phase.Terminals != filepath.Join(directory, "reconstruction.txt") {
				t.Errorf("controlled phase lost its execution identity: %+v", phase)
			}
			if _, err := os.Stat(phase.Terminals); err != nil {
				t.Error("joined refusal lost terminal capture", err)
			}
		})
	}
}

// full_only: false
func TestConfigurationRecoveryRunnerKeepsClosedCustodyImports(t *testing.T) {
	t.Parallel()
	if err := checkCustodySources(t.Context(), testRepositoryRoot(t)); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestConfigurationRecoveryCoordinatorDispatch(t *testing.T) {
	t.Parallel()
	ctx := testRaceContext(t, t.Context())
	outer, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	outerRace, err := binaryRace(outer)
	if err != nil {
		t.Fatal(err)
	}
	root, directory, setup := configurationRecoveryTestAssembly(t)
	driver, err := buildConfigurationRecoveryArtifact(ctx, root, directory, "aws", testSourceRevision(t, root))
	if err != nil {
		t.Fatal(err)
	}
	if driver.Closure.Race == nil {
		t.Fatal("recovery artifact omitted its compiled race observation")
	}
	wantOptions := ""
	if outerRace {
		wantOptions = "log_path=stderr exitcode=66 halt_on_error=0 atexit_sleep_ms=1000"
	}
	for _, child := range []struct {
		path, options string
		race          bool
	}{
		{setup.Binary, setup.Closure.RaceOptions, setup.Closure.Race},
		{driver.Path, driver.Closure.RaceOptions, *driver.Closure.Race},
	} {
		observed, err := binaryRace(child.path)
		if err != nil || observed != outerRace || child.race != outerRace || child.options != wantOptions {
			t.Errorf("real recovery child lost the outer race setting: path=%s compiled=%t recorded=%t options=%q want=%t error=%v", child.path, observed, child.race, child.options, outerRace, err)
		}
	}
	source, err := sourceRevision(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	if !sameSource(source, driver.Source) {
		t.Fatal("artifact source changed")
	}
	private := filepath.Join(directory, "coordinator")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	closure := setup.Closure
	closure.ReconstructionArtifacts = []reconstructionArtifactClosure{driver.Closure}
	s := runState{root: root, private: private, recoverySetup: &setup,
		recoveryArtifacts: map[string]configurationRecoveryArtifact{"aws": driver},
		record:            runRecord{Suite: "hermetic", Source: source, BuildClosure: &closure, Resolved: &resolvedRequest{RecoveryMode: "disabled"}},
	}
	result := scenarioResult{Entry: catalog.Entry{Scenario: "reconstruction.zero-secret-genesis/complete_loss_zero_secret_genesis"}, Outcome: "incomplete"}
	if err := s.executeScenario(ctx, setup.Binary, nil, limits{}, &result); err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "passed" || !result.CorrectnessPassed || !reconstructionScenarioComplete(result, s.record) {
		t.Fatal("maintained coordinator completion incomplete", result.Outcome)
	}
	if len(result.Reconstruction) != 1 || result.Reconstruction[0].Checks.Opened != 0 {
		t.Fatal("zero-secret route mismatch")
	}
	t.Run("current-result-without-proof", func(t *testing.T) {
		current := s
		current.record.BuildClosure = nil
		current.record.Source = records.Source{}
		current.record.Schedule.Repetitions = 3
		body, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		var outcome scenarioResult
		if err := json.Unmarshal(body, &outcome); err != nil {
			t.Fatal(err)
		}
		for index := range outcome.Reconstruction {
			recovery := &outcome.Reconstruction[index]
			recovery.Source, recovery.RaceOptions = records.Source{}, ""
			recovery.Checks.ChildTerminalsSHA256 = ""
			for phase := range recovery.Phases {
				recovery.Phases[phase].BinarySHA256, recovery.Phases[phase].TerminalsSHA256 = "", ""
			}
		}
		if !reconstructionScenarioSemantics(outcome, current.record.Resolved.RecoveryMode) || reconstructionScenarioComplete(outcome, current.record) {
			t.Fatal("current semantic disposal and stored proof validation share authority")
		}
	})
	if err := records.WriteJSON(filepath.Join(directory, "coordinator-public-evidence.json"), result, 0600); err != nil {
		t.Fatal(err)
	}
	for _, publication := range []string{"terminals", "process-evidence"} {
		t.Run(publication+"-save-failure", func(t *testing.T) {
			ctx := testRaceContext(t, t.Context())
			binary := filepath.Join(t.TempDir(), "failed-phase")
			const assertion = "controlled recovery phase assertion: got 3, want 5"
			target := "resource-owner.txt"
			if publication == "process-evidence" {
				target = "process-evidence.json"
			}
			body := []byte("#!/bin/sh\nmkdir '" + target + "'\nprintf '%s\n' '" + assertion + "'\nexit 7\n")
			if err := os.WriteFile(binary, body, 0700); err != nil {
				t.Fatal(err)
			}
			controlled := s
			controlled.private = t.TempDir()
			controlled.recoveryArtifacts = map[string]configurationRecoveryArtifact{"aws": {Path: binary, SHA256: digestBytes(body), Provider: "aws", Source: source}}
			failed := scenarioResult{Entry: result.Entry, Outcome: "incomplete"}
			failure := controlled.executeScenario(ctx, setup.Binary, nil, limits{}, &failed)
			var phaseFailure *toolFailure
			var exit *exec.ExitError
			if failure == nil || !errors.As(failure, &phaseFailure) || !errors.As(failure, &exit) || exit.ExitCode() != 7 || !phaseFailure.process.Joined || !bytes.Contains(phaseFailure.stdout, []byte(assertion)) {
				t.Error("later evidence save erased the joined phase assertion", failure)
			}
			if len(failed.Reconstruction) != 1 || len(failed.Reconstruction[0].Phases) == 0 || !failed.Reconstruction[0].Phases[0].Started || !failed.Reconstruction[0].Phases[0].Joined {
				t.Error("later evidence save erased the attempted phase facts")
			}
		})
	}
	t.Run("integrated-suite-fold", func(t *testing.T) {
		ctx := withExecutionParallel(testRaceContext(t, t.Context()), 2)
		selected := []struct {
			entry  catalog.Entry
			cells  []catalog.RecoveryProcessCell
			opened int
		}{
			{entry: catalog.Entry{Scenario: "state.single-value-update-preserves-other-values/members_32", Smoke: true}},
			{catalog.Entry{Scenario: "reconstruction.complete/complete_loss_complete", Sequence: 1, Repetition: 1}, []catalog.RecoveryProcessCell{{Provider: "aws", Recovery: "disabled"}, {Provider: "aws", Recovery: "enabled"}, {Provider: "gcp", Recovery: "disabled"}, {Provider: "gcp", Recovery: "enabled"}}, 5},
			{catalog.Entry{Scenario: "reconstruction.zero-secret-genesis/complete_loss_zero_secret_genesis", Sequence: 2, Repetition: 1}, []catalog.RecoveryProcessCell{{Provider: "aws", Recovery: "disabled"}}, 0},
		}
		suite, environment := filepath.Join(directory, "integrated-suite.json"), filepath.Join(directory, "integrated-environment.json")
		saveSelection(t, suite, suiteFixture("integrated-recovery-fold", []string{selected[1].entry.Scenario, selected[2].entry.Scenario}))
		saveSelection(t, environment, memoryEnvironment())
		request, err := resolveSavedRun([]string{suite}, environment, "", "", "both", "", "", "", 1, false)
		if err != nil {
			t.Fatal(err)
		}
		request.Resolved.Race = outerRace
		request.execution = executionPolicy{Resolved: executionCapacity{Parallel: 2, MemoryLimitMiB: 8192}}
		bootstrap := filepath.Join(directory, "bootstrap.json")
		prepared, err := prepareSuite(nil, ctx, root, bootstrap, request, nil)
		if prepared != nil {
			defer func() {
				tail, cancel := finalizationContext(ctx)
				defer cancel()
				if err := prepared.close(tail); err != nil {
					t.Error(err)
				}
			}()
		}
		if err != nil {
			t.Fatal(err)
		}
		prefix := append([]checkCommandFacts(nil), prepared.preparation.Commands...)
		var output bytes.Buffer
		execution, err := prepared.executeOwned(nil, ctx, root, bootstrap, nil, &output)
		if err != nil {
			t.Fatal("integrated recovery suite failed", err)
		}
		if execution.Record == nil || execution.Record.Outcome != "passed" || len(execution.Record.Scenarios) != len(selected) || execution.Record.Execution.Resolved.Parallel != 2 {
			t.Fatal("integrated recovery suite lost its selected execution", execution.Record)
		}
		diagnostics := execution.preparation
		if diagnostics == nil || diagnostics.Preparation != "passed" || diagnostics.hasPlan() || diagnostics.held != (diagnosticWeights{}) || len(prefix) == 0 || len(diagnostics.Commands) < len(prefix) || !reflect.DeepEqual(diagnostics.Commands[:len(prefix)], prefix) {
			t.Fatal("integrated recovery suite lost its acquired prefix or left reservations open")
		}
		children := make(map[int]*runState)
		owners := make(map[*checkDiagnostics]bool)
		for acquisition := range diagnostics.acquisitions {
			if acquisition.key != "closed-reconstruction" {
				continue
			}
			child, ok := acquisition.owner.(*runState)
			if !ok || len(child.record.Scenarios) != 1 || child.preparation == nil || child.preparation == diagnostics || owners[child.preparation] || !child.preparationFolded || child.preparation.hasPlan() || child.preparation.held != (diagnosticWeights{}) {
				t.Fatal("integrated recovery fold lost independent closed child ownership")
			}
			sequence := child.record.Scenarios[0].Sequence
			if children[sequence] != nil {
				t.Fatal("integrated recovery fold acquired a selected child twice", sequence)
			}
			children[sequence], owners[child.preparation] = child, true
		}
		if len(children) != len(selected) {
			t.Fatal("integrated recovery fold omitted a selected child", len(children))
		}
		var folded []checkCommandFacts
		for index, want := range selected {
			result := execution.Record.Scenarios[index]
			child := children[index]
			if result.Entry != want.entry || result.Outcome != "passed" || !result.CorrectnessPassed || len(result.Reconstruction) != len(want.cells) || child == nil || child.record.Scenarios[0].Entry != want.entry {
				t.Fatal("integrated recovery changed selected entry order or completion", index, result)
			}
			if len(want.cells) != 0 && !reconstructionScenarioComplete(result, *execution.Record) {
				t.Fatal("integrated recovery omitted complete process proofs", index)
			}
			for cellIndex, cell := range want.cells {
				proof := result.Reconstruction[cellIndex]
				if proof.Provider != cell.Provider || proof.RecoveryMode != cell.Recovery || len(proof.Phases) != 5 || !proof.Checks.ChildStarted || !proof.Checks.ChildJoined {
					t.Fatal("integrated recovery changed selected cell order or child joins", index, cellIndex)
				}
				if !proof.LossBarrier || proof.Checks.Refused || proof.Checks.Result != (installedarchive.RecoveryResult{Outcome: 2, Evidence: 1}) || proof.Checks.Opened != want.opened || proof.Checks.Counts.AuthorityDecrypts != uint64(want.opened) {
					t.Fatal("integrated recovery changed the independent recovered-secret expectation", index, cellIndex)
				}
				for _, phase := range proof.Phases {
					if !phase.Started || !phase.Joined || phase.Outcome != "passed" {
						t.Fatal("integrated recovery omitted a positive phase join", phase)
					}
				}
			}
			if len(child.preparation.Commands) != 0 {
				t.Fatal("reconstruction repeated completed output artifact discovery", index, child.preparation.Commands)
			}
			folded = append(folded, child.preparation.Commands...)
		}
		// The last preparation header before the terminal records the actual pre-body prefix.
		prefixCount := -1
		for _, line := range strings.Split(strings.SplitN(output.String(), "Run passed\n", 2)[0], "\n") {
			if strings.HasPrefix(line, "Check preparation=passed; commands=") {
				if _, err := fmt.Sscanf(line, "Check preparation=passed; commands=%d", &prefixCount); err != nil {
					t.Fatal(err)
				}
			}
		}
		if prefixCount < len(prefix) || len(diagnostics.Commands) != prefixCount+len(folded) || !slices.EqualFunc(diagnostics.Commands[prefixCount:], folded, func(actual, want checkCommandFacts) bool {
			return reflect.DeepEqual(actual, want)
		}) {
			t.Fatal("integrated recovery did not retain its actual prefix and each child group once in selected order", prefixCount, len(diagnostics.Commands), len(folded))
		}
	})
}

// full_only: false
func TestConfigurationRecoveryPrivateOracleHandoff(t *testing.T) {
	t.Parallel()
	ctx := testRaceContext(t, t.Context())
	root, directory, setup := configurationRecoveryTestAssembly(t)
	for _, provider := range []string{"aws", "gcp"} {
		driver, err := buildConfigurationRecoveryArtifact(ctx, root, directory, provider, testSourceRevision(t, root))
		if err != nil {
			t.Fatal(err)
		}
		t.Run(provider, func(t *testing.T) {
			ctx := testRaceContext(t, t.Context())
			path := filepath.Join(directory, provider+"-private-handoff")
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			evidence, err := runConfigurationRecoveryProcesses(ctx, root, path, setup, driver, false, "complete", true)
			if saveErr := records.WriteJSON(filepath.Join(path, "process-evidence.json"), evidence, 0600); saveErr != nil {
				t.Fatal(saveErr)
			}
			if err != nil {
				t.Fatal(err)
			}
			if !evidence.LossBarrier || evidence.Report.Opened != 3 || evidence.Report.Counts.AuthorityDecrypts != 3 || evidence.Report.OracleCounts.AuthorityDecrypts != 3 {
				t.Fatal("actual returned-byte/private provider comparison incomplete")
			}
		})
	}
}

// full_only: false
func TestConfigurationRecoveryLiveConstructionControls(t *testing.T) {
	t.Parallel()
	root, directory, live := configurationRecoveryTestAssemblyFor(t, "live", "gcp")
	for _, name := range []string{"TestLiveSecondNormalSuccessorKeepsIndependentResource", "TestLiveProtocolReplacementConfiguration", "TestLiveRecoveryWriterExportKeepsCompletePrivateWitness", "TestLiveRecoveryWriterReusesReplacementActors"} {
		t.Run(name, func(t *testing.T) {
			ctx := testRaceContext(t, t.Context())
			phase, err := runConfigurationRecoveryPhase(ctx, directory, live.Binary, live.Closure.BinarySHA256, name, name, environment(os.Environ(), map[string]string{"ENKV_TEST_FAILURE_SOURCES": live.FailureSources.Path, "ENKV_TEST_FAILURE_SOURCES_SHA256": live.FailureSources.SHA256}), root)
			if err != nil {
				body, _ := os.ReadFile(phase.Terminals)
				t.Fatal(err, string(body))
			}
			if !phase.Process.Joined || phase.Process.Status != "passed" {
				t.Fatal("live construction helper did not complete")
			}
		})
	}
}

// full_only: false
func TestConfigurationRecoveryLiveWriterOrdinaryArtifactHandoff(t *testing.T) {
	t.Parallel()
	runLiveWriterOrdinaryArtifactHandoff(t, false, "complete")
}

// full_only: false
func TestConfigurationRecoveryLiveParentEpochs(t *testing.T) {
	t.Parallel()
	runLiveWriterOrdinaryArtifactHandoff(t, true, "complete")
}

// full_only: false
func TestConfigurationRecoveryLiveParentGeneratedValues(t *testing.T) {
	t.Parallel()
	runLiveWriterOrdinaryArtifactHandoff(t, true, "mixed-generated")
}

// full_only: false
func TestConfigurationRecoveryLiveParentGeneratedPending(t *testing.T) {
	t.Parallel()
	for _, condition := range []string{"generated-active", "generated-retiring", "generated-uncertain"} {
		t.Run(condition, func(t *testing.T) { runLiveWriterOrdinaryArtifactHandoff(t, true, condition) })
	}
}

// full_only: false
func TestConfigurationRecoveryLiveParentLocations(t *testing.T) {
	t.Parallel()
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			for _, condition := range []string{"new-domain-no-pin", "prior-domain-pin", "copied-location"} {
				t.Run(condition, func(t *testing.T) {
					if provider == "gcp" {
						runLiveWriterOrdinaryArtifactHandoff(t, true, condition, provider)
					} else {
						runLiveWriterOrdinaryArtifactHandoff(t, true, condition)
					}
				})
			}
		})
	}
}

// full_only: false
func TestConfigurationRecoveryLiveParentConcurrentChange(t *testing.T) {
	t.Parallel()
	runLiveWriterOrdinaryArtifactHandoff(t, true, "selected-object-disappears")
}

// full_only: false
func TestConfigurationRecoveryLiveParentRepeatedGenerated(t *testing.T) {
	t.Parallel()
	runLiveWriterOrdinaryArtifactHandoff(t, true, "generated-repeated-later")
}

// full_only: false
func TestConfigurationRecoveryLiveParentLaterSecretRefusal(t *testing.T) {
	t.Parallel()
	runLiveWriterOrdinaryArtifactHandoff(t, true, "later-secret-denied")
}

// full_only: false
func TestConfigurationRecoveryGCPLiveParentEpochs(t *testing.T) {
	t.Parallel()
	runLiveWriterOrdinaryArtifactHandoff(t, true, "complete", "gcp")
}

// full_only: false
func TestConfigurationRecoveryLocationControls(t *testing.T) {
	t.Parallel()
	_, directory, live := configurationRecoveryTestAssemblyFor(t, "live", "gcp")
	for _, name := range []string{"TestLiveRecoveryLocationsRefuseBeforeProviderAccess", "TestCleanupRecoveryRetriesOnlyEligibleExactTarget", "TestLiveProtocolCleanupGrantsBindProviderPolicy", "TestLiveCleanupEmptyRecoveryRetainsKnownZeros", "TestLiveProtocolCleanupUnknownsAndWriterResumeRefusal"} {
		t.Run(name, func(t *testing.T) {
			ctx := testRaceContext(t, t.Context())
			phase, err := runConfigurationRecoveryPhase(ctx, directory, live.Binary, live.Closure.BinarySHA256, name, name, environment(os.Environ(), map[string]string{"ENKV_TEST_FAILURE_SOURCES": live.FailureSources.Path, "ENKV_TEST_FAILURE_SOURCES_SHA256": live.FailureSources.SHA256}))
			if err != nil {
				body, _ := os.ReadFile(phase.Terminals)
				t.Fatal(err, string(body))
			}
		})
	}
}

// full_only: false
func TestConfigurationRecoveryLiveCoordinatorBoundary(t *testing.T) {
	t.Parallel()
	runLiveWriterOrdinaryHandoff(t, true, true, "complete")
}

func runLiveWriterOrdinaryArtifactHandoff(t *testing.T, liveParent bool, condition string, explicitProvider ...string) {
	runLiveWriterOrdinaryHandoff(t, liveParent, false, condition, explicitProvider...)
}
func runLiveWriterOrdinaryHandoff(t *testing.T, liveParent, coordinator bool, condition string, explicitProvider ...string) {
	ctx := testRaceContext(t, t.Context())
	provider := "gcp"
	if liveParent {
		provider = "aws"
	}
	if len(explicitProvider) > 1 || len(explicitProvider) == 1 && explicitProvider[0] != "gcp" {
		t.Fatal("local provider selection refused")
	}
	if len(explicitProvider) == 1 {
		provider = explicitProvider[0]
	}
	root, directory, live := configurationRecoveryTestAssemblyFor(t, "live", provider)
	source := testSourceRevision(t, root)
	if coordinator {
		var err error
		source, err = sourceIdentity(ctx, root)
		if err != nil {
			t.Fatal(err)
		}
	}
	driver, err := buildConfigurationRecoveryArtifact(ctx, root, directory, provider, source)
	if err != nil {
		t.Fatal(err)
	}
	local, state, oracle := filepath.Join(directory, "local-configuration"), filepath.Join(directory, "parent-state"), filepath.Join(directory, "parent-oracle")
	for _, path := range []string{local, state, oracle} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	// The private owner removes captured bytes even when a later child refuses.
	t.Cleanup(func() {
		if err := os.RemoveAll(oracle); err != nil {
			t.Error("private oracle cleanup failed")
		}
		if _, err := os.Lstat(oracle); !os.IsNotExist(err) {
			t.Error("private oracle survived cleanup")
		}
	})
	location := contract.StoreLocation{Provider: contract.GCP, Region: "australia-southeast1", Bucket: "fixture-bucket", PrefixBeforeHEAD: "fixture"}
	if provider == "aws" {
		location.Provider, location.Region, location.ExpectedOwner = contract.AWS, "us-east-1", "123456789012"
	}
	resources, descriptor := filepath.Join(directory, "resources-parent.json"), filepath.Join(local, "setup.json")
	resourceInput := filepath.Join(local, "resources-input.json")
	if err := records.WriteJSON(resourceInput, installedarchive.RecoveryResourceInput{Location: location, Resources: resources, Setup: descriptor}, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := runConfigurationRecoveryPhase(ctx, directory, driver.Path, driver.SHA256, "resource-owner", "TestConfigurationRecoveryResourceOwner", environment(os.Environ(), map[string]string{"ENKV_RECOVERY_RESOURCES_INPUT": resourceInput})); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(local, "writer-input.json")
	var writerLimits *limits
	if row, ok := catalog.ConfigurationRecovery(configurationCaseForCondition(t, condition)); ok && row.Generated {
		value, err := loadLimits(filepath.Join(root, "tests/live/limits/cloudflare.json"))
		if err != nil {
			t.Fatal(err)
		}
		writerLimits = &value
	}
	if err := records.WriteJSON(input, struct {
		Setup, Resources, State, Oracle, Condition string
		Limits                                     *limits
	}{descriptor, resources, state, oracle, condition, writerLimits}, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := runConfigurationRecoveryPhase(ctx, directory, live.Binary, live.Closure.BinarySHA256, "live-writer", "TestLiveRecoveryWriterExportKeepsCompletePrivateWitness", environment(os.Environ(), map[string]string{"ENKV_RECOVERY_LIVE_WRITER_CONTROL": input, "ENKV_TEST_FAILURE_SOURCES": live.FailureSources.Path, "ENKV_TEST_FAILURE_SOURCES_SHA256": live.FailureSources.SHA256}), root); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(local); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(local); !os.IsNotExist(err) {
		t.Fatal("writer local state survived loss")
	}
	if liveParent {
		var chosen installedarchive.RecoveryResources
		if err := records.ReadJSON(resources, &chosen); err != nil {
			t.Fatal(err)
		}
		// Independently derive the existing local fixture's resource name before
		// reading any writer-produced binding. Key material was chosen before Domain.
		id := func(label string) contract.ID {
			body := append([]byte("fixture/"), chosen.Domain[:]...)
			body = append(body, '/')
			return contract.Hash(append(body, label...))
		}
		custodyID, recipient := id("custody"), id("recipient")
		binding := append([]byte("ENKV/TEST-CUSTODY/v2/binding\x00"), custodyID[:]...)
		expected := contract.Hash(append(binding, recipient[:]...))
		authorityIndex, normalIndex, nextAuthority := 0, 0, 2
		if history, ok := installedarchive.ReplacementFor(condition); ok {
			for _, step := range history.Steps {
				if step.Mask&1 != 0 {
					normalIndex++
				}
				if step.Mask&2 != 0 {
					authorityIndex = nextAuthority
					nextAuthority++
					body := append([]byte("ENKV/TEST-CUSTODY/v2/successor\x00"), expected[:]...)
					expected = contract.Hash(append(body, recipient[:]...))
				}
			}
		}
		if normalIndex > 0 {
			chosen.Normal = chosen.NormalSuccessors[normalIndex-1]
		}
		selector := hex.EncodeToString(expected[:16])
		authority := fmt.Sprintf("arn:aws:kms:us-east-1:123456789012:key/%s-%s-%s-%s-%s", selector[:8], selector[8:12], selector[12:16], selector[16:20], selector[20:])
		if provider == "gcp" {
			authority = fmt.Sprintf("projects/fixture/locations/us-central1/keyRings/fixture/cryptoKeys/key-%s/cryptoKeyVersions/%d", selector, max(1, authorityIndex))
		}
		locations := installedarchive.RecoveryLocations{}
		if condition == "new-domain-no-pin" || condition == "prior-domain-pin" {
			locations.PriorDomain = chosen.PriorDomain
		}
		if condition == "copied-location" {
			locations.CopiedPrefix = location.PrefixBeforeHEAD + "/copied"
		}
		owner := installedarchive.LiveRecoveryParentInput{Fixture: filepath.Join(state, "recovery-parent.json"), Condition: condition, Report: filepath.Join(directory, "report.json"), ChildTerminals: filepath.Join(directory, "restricted-child.txt"), Resources: chosen, Locations: locations, AuthoritySelector: authority, AuthorityPublicKey: chosen.AuthorityPublicKeys[authorityIndex], Input: installedarchive.RecoveryInput{Provider: "aws", Owner: location.ExpectedOwner, AccessKey: "synthetic-parent-access", SecretKey: "synthetic-parent-secret", ReadRoute: "new-read", SignRoute: "new-sign", PrivateRoute: "new-private", TimeoutMillis: 10000, Requests: 4096, BodyBytes: 1 << 30, ResponseBytes: 1 << 20}}
		if provider == "gcp" {
			owner.Input.Provider, owner.Input.AccessKey, owner.Input.SecretKey, owner.Input.Token = "gcp", "", "", "synthetic-parent-token"
		}
		ownerPath := filepath.Join(directory, "live-parent-input.json")
		if !coordinator {
			if err := records.WriteJSON(ownerPath, owner, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if coordinator {
			var writer struct {
				Budget records.BudgetReservation
				Phases []string
			}
			if err := records.ReadJSON(filepath.Join(state, "writer-reservation.json"), &writer); err != nil || len(writer.Phases) != 2 || writer.Phases[0] != "setup" || writer.Phases[1] != "transition" {
				t.Fatal("actual writer reservation or typed execution absent", err)
			}
			closure := live.Closure
			closure.ReconstructionArtifacts = []reconstructionArtifactClosure{driver.Closure}
			s := runState{root: root, recovery: &liveRecovery{executionSource: &source},
				recoveryArtifacts: map[string]configurationRecoveryArtifact{provider: driver},
				record:            runRecord{Suite: "live", Provider: provider, Source: source, ExecutionSource: &source, BuildClosure: &closure},
			}
			result := scenarioResult{Entry: catalog.Entry{Scenario: configurationCaseForCondition(t, condition)}, BudgetReserved: &writer.Budget}
			allowance := limits{Requests: 4096, BodyBytes: 1 << 30}
			joined := true
			if err := s.executeLiveConfigurationRecovery(ctx, state, workerInput{RecoveryMode: "disabled", Limits: &allowance}, owner, time.Now().Add(time.Minute), &result, &joined, true); err != nil {
				t.Fatal(err)
			}
			if !joined || len(result.Reconstruction) != 1 || !validateLiveConfigurationRecovery(result.Reconstruction[0], "disabled", condition, source, driver.SHA256, owner.Input, *driver.Closure.Race) || result.BudgetReserved.Requests <= writer.Budget.Requests {
				t.Fatal("maintained parent phase or cumulative budget missing")
			}
			if err := records.WriteJSON(filepath.Join(directory, "coordinator-public-evidence.json"), result.Reconstruction, 0600); err != nil {
				t.Fatal(err)
			}
			// This caller's private lifetime also removes a partial capture on any outcome.
			if err := os.RemoveAll(oracle); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(oracle); !os.IsNotExist(err) {
				t.Fatal("private capture survived")
			}
		} else if _, err := runConfigurationRecoveryPhase(ctx, directory, driver.Path, driver.SHA256, "reconstruction-parent", "TestConfigurationRecoveryLiveParentControl", environment(os.Environ(), map[string]string{"ENKV_RECOVERY_LIVE_PARENT_CONTROL": ownerPath})); err != nil {
			t.Fatal(err)
		}
		var report installedarchive.RecoveryReport
		if err := records.ReadJSON(owner.Report, &report); err != nil {
			t.Fatal(err)
		}
		wantOpened := liveRecoverySecretCount(condition)
		wantResult, refused := expectedRecoveryRefusal(condition)
		if refused {
			wantOpened = 0
		}
		wantDecrypts := uint64(wantOpened)
		if condition == "later-secret-denied" {
			wantDecrypts = 4
			if report.Attempted.AuthorityDecrypts != 5 || report.Injected.AuthorityDecrypts != 1 || report.Opened != 0 {
				t.Fatal("fifth-secret refusal or private release evidence differs")
			}
		}
		if condition == "selected-object-disappears" {
			if report.ExternalMutations != 1 || !report.MutationJoined || report.MutationCounts.Delete != 1 || report.Counts.Delete != 0 {
				t.Fatal("separate external conditional deletion incomplete")
			}
		}
		if report.Result != wantResult || report.Refused != refused || !report.ChildStarted || !report.ChildJoined || report.Opened != wantOpened || report.Counts.AuthorityDecrypts != wantDecrypts || report.OracleCounts.AuthorityDecrypts != uint64(wantOpened) || report.SnapshotReadsBefore == 0 || report.SnapshotReadsBefore != report.SnapshotReadsAfter || report.ReservedRequests == 0 || report.ReservedRequests > owner.Input.Requests || report.ReservedBytes > owner.Input.BodyBytes || !report.RemoteEffectsZero || !report.OracleEpochSeparate {
			t.Fatal("four-epoch private comparison incomplete")
		}
		for _, retired := range []string{ownerPath, owner.Fixture} {
			if _, err := os.Lstat(retired); !os.IsNotExist(err) {
				t.Fatal("parent carrier survived")
			}
		}
		return
	}
	name := "TestRestrictedGCPReconstructionFromConsoleInputs"
	if _, err := runConfigurationRecoveryPhase(ctx, directory, driver.Path, driver.SHA256, "reconstruction-parent", name, environment(os.Environ(), map[string]string{"ENKV_RECOVERY_PARENT_FIXTURE": filepath.Join(state, "recovery-parent.json"), "ENKV_RECOVERY_PARENT_RESOURCES": resources, "ENKV_RECOVERY_PARENT_CONDITION": "complete", "ENKV_RECOVERY_PARENT_REPORT": filepath.Join(directory, "report.json"), "ENKV_RECOVERY_CHILD_TERMINALS": filepath.Join(directory, "restricted-child.txt")})); err != nil {
		t.Fatal(err)
	}
	var report installedarchive.RecoveryReport
	if err := records.ReadJSON(filepath.Join(directory, "report.json"), &report); err != nil {
		t.Fatal(err)
	}
	if !report.ChildStarted || !report.ChildJoined || report.Opened != 3 || report.Counts.AuthorityDecrypts != 3 || report.OracleCounts.AuthorityDecrypts != 3 || !report.RemoteEffectsZero || !report.OracleEpochSeparate {
		t.Fatal("live writer/ordinary child actual private comparison incomplete")
	}
}

// full_only: false
func TestConfigurationRecoveryOrdinaryProviderHelpers(t *testing.T) {
	t.Parallel()
	root := testRepositoryRoot(t)
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	overlay, err := buildCryptoOverlay(root, directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ module, restricted string }{
		{"compositions/aws", "TestRestrictedAWSReconstructionFromConsoleInputs"},
		{"providers/gcp", "TestRestrictedGCPReconstructionFromConsoleInputs"},
	} {
		t.Run(row.module, func(t *testing.T) {
			ctx := testRaceContext(t, t.Context())
			selection, err := componentSelection([]string{row.restricted, "TestConfigurationRecoveryResourceOwner", "TestConfigurationRecoveryLiveParentControl", "TestConfigurationRecoveryLiveParentInvokesControl"})
			if err != nil {
				t.Fatal(err)
			}
			var evidence ordinaryStepEvidence
			if err := executeOrdinaryCommand(ctx, root, row.module, "full", moduleTestFlags(root, row.module, overlay), []string{"."}, selection, ordinaryProviderHelperProofs, &evidence); err != nil {
				t.Fatal(err)
			}
			if len(evidence.Packages) != 1 || len(evidence.Tests) != 4 {
				t.Fatal("ordinary provider helper inventory incomplete")
			}
			outcomes := map[string]string{}
			for _, result := range evidence.Tests {
				outcomes[result.Name] = result.Outcome
			}
			if outcomes["TestConfigurationRecoveryLiveParentControl"] != "skip" || outcomes["TestConfigurationRecoveryLiveParentInvokesControl"] != "pass" || outcomes[row.restricted] != "pass" || outcomes["TestConfigurationRecoveryResourceOwner"] != "pass" {
				t.Fatal("ordinary helper outcomes differ")
			}
			if err := records.WriteJSON(filepath.Join(directory, strings.ReplaceAll(row.module, "/", "-")+"-ordinary-evidence.json"), evidence, 0600); err != nil {
				t.Fatal(err)
			}
			t.Logf("ordinary helper package=%s names=%v", evidence.Packages[0].Name, evidence.Tests)
		})
	}
}

// full_only: false
func TestPublicationReconstructionLoss(t *testing.T) {
	t.Parallel()
	root, directory, setup := configurationRecoveryTestAssembly(t)
	drivers := map[string]configurationRecoveryArtifact{}
	for _, history := range []string{"owned_active_then_delete", "owned_retired_unknown_delete", "uncertain_retired_unknown_delete"} {
		t.Run(history, func(t *testing.T) {
			for _, provider := range []string{"aws", "gcp"} {
				for _, enabled := range []bool{false, true} {
					mode := "disabled"
					if enabled {
						mode = "enabled"
					}
					t.Run(provider+"-"+mode, func(t *testing.T) {
						ctx := testRaceContext(t, t.Context())
						driver, ok := drivers[provider]
						if !ok {
							var err error
							driver, err = buildConfigurationRecoveryArtifact(ctx, root, directory, provider, testSourceRevision(t, root))
							if err != nil {
								t.Fatal(err)
							}
							drivers[provider] = driver
						}
						path := filepath.Join(directory, history, provider+"-"+mode)
						if err := os.MkdirAll(path, 0700); err != nil {
							t.Fatal(err)
						}
						evidence, err := runConfigurationRecoveryProcessesWithPublication(ctx, root, path, setup, driver, enabled, "complete", history)
						if saveErr := records.WriteJSON(filepath.Join(path, "process-evidence.json"), evidence, 0600); saveErr != nil {
							t.Fatal(saveErr)
						}
						if err != nil {
							t.Fatal(err)
						}
						if !evidence.LossBarrier || evidence.Report.Refused || !evidence.Report.ChildJoined || evidence.Report.Opened != 5 || evidence.Report.Counts.AuthorityDecrypts != 5 || !evidence.Report.RemoteEffectsZero {
							t.Fatal("complete loss independent every-secret proof absent")
						}
						public, err := publicConfigurationRecovery(evidence, driver.Source, *driver.Closure.Race)
						if err != nil || !validateConfigurationRecovery(public, catalog.RecoveryProcessCell{Provider: provider, Recovery: mode}, "complete", driver.Source, setup.Closure.BinarySHA256, driver.SHA256, *driver.Closure.Race) {
							t.Fatal("existing five-phase recovery evidence incomplete", err)
						}
						if err := records.WriteJSON(filepath.Join(path, "public-recovery-evidence.json"), public, 0600); err != nil {
							t.Fatal(err)
						}
						var returned installedarchive.PublicationLossContinuation
						if err := records.ReadJSON(filepath.Join(path, "verified-publication-continuation.json"), &returned); err != nil {
							t.Fatal(err)
						}
						if returned.Location.Provider != map[string]contract.Family{"aws": contract.AWS, "gcp": contract.GCP}[provider] || returned.Result != (installedarchive.RecoveryResult{Outcome: 2, Evidence: 1}) || returned.Domain.IsZero() {
							t.Fatal("verified continuation selection absent")
						}
						var composition, premise contract.ID
						for _, id := range []*contract.ID{&composition, &premise} {
							if _, err := rand.Read(id[:]); err != nil || id.IsZero() {
								t.Fatal("new normal test grant identity unavailable", err)
							}
						}
						grant := struct {
							Composition                      contract.ID
							Expires                          time.Time
							NamespaceDomain                  contract.ID
							NamespaceProvider, NamespaceSlot string
							NamespacePremise                 contract.ID
						}{Composition: composition, Expires: time.Now().Add(50 * time.Second),
							NamespaceDomain: returned.Domain, NamespaceProvider: "test-output/service/v1",
							NamespaceSlot: "secret-target-publication-loss-" + history, NamespacePremise: premise}
						control := struct {
							Phase, Provider                                                             string
							Recovery                                                                    bool
							PublicationHistory, PublicationExpectation, PublicationContinuation, Output string
							PublicationGrant                                                            any
						}{"publication-continuation", provider, enabled, history, filepath.Join(path, "loss-history-expectation.json"), filepath.Join(path, "verified-publication-continuation.json"), filepath.Join(path, "new-publication-result.json"), grant}
						input := filepath.Join(path, "fresh-normal-grant.json")
						if err := records.WriteJSON(input, control, 0600); err != nil {
							t.Fatal(err)
						}
						if err := checkAssemblyRace(t.Context(), setup); err != nil {
							t.Fatal(err)
						}
						phase, err := runConfigurationRecoveryPhase(ctx, path, setup.Binary, setup.Closure.BinarySHA256, "fresh-normal-publication", "TestConfigurationRecoveryFixtureProcess", environment(os.Environ(), map[string]string{"ENKV_CONFIGURATION_RECOVERY_FIXTURE": input}))
						if saveErr := records.WriteJSON(filepath.Join(path, "fresh-normal-evidence.json"), phase, 0600); saveErr != nil {
							t.Fatal(saveErr)
						}
						if err != nil {
							t.Fatal(err)
						}
						if err := os.Remove(input); err != nil {
							t.Fatal(err)
						}
						var result struct {
							Domain, DeleteAttempt, FreshBirth contract.ID
							WarningBits                       uint8
						}
						if err := records.ReadJSON(control.Output, &result); err != nil {
							t.Fatal(err)
						}
						if result.Domain != returned.Domain || result.DeleteAttempt.IsZero() || result.FreshBirth.IsZero() || result.DeleteAttempt == result.FreshBirth || result.WarningBits == 0 {
							t.Fatal("fresh actions/disposal evidence incomplete")
						}
					})
				}
			}
		})
	}
}

func configurationCaseForCondition(t testing.TB, condition string) string {
	t.Helper()
	for _, name := range catalog.ConfigurationRecoveryNames() {
		row, known := catalog.ConfigurationRecovery(name)
		if known && row.Condition == condition {
			return name
		}
	}
	t.Fatal("controlled reconstruction condition is not declared")
	return ""
}

func testSourceRevision(t *testing.T, root string) records.Source {
	t.Helper()
	source, err := sourceRevision(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	return source
}

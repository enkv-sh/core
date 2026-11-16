package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestHistoricalCleanupLimitsPreserveRecordedIdentity(t *testing.T) {
	const scenario = "state.single-value-update-preserves-other-values/members_32"
	allowance := testLimits()
	original := runRecord{
		SchemaVersion: records.SchemaVersion, RunID: strings.Repeat("a", 32),
		Native:    nativeTuple{GOOS: "darwin", GOARCH: "arm64"},
		StartedAt: time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC),
		Source:    records.Source{Revision: strings.Repeat("b", 40)},
		Suite:     "live", Provider: "aws", Target: "aws", Profile: "full", CoverageScope: "live_scenarios",
		Schedule: catalog.Schedule{RecoveryMode: "disabled", Selected: []string{scenario}, Repetitions: 1,
			Entries: []catalog.Entry{{Scenario: scenario, Repetition: 1, Smoke: true}}},
		Toolchain: "recorded-toolchain", Limits: &allowance,
	}
	body, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	body = bytes.Replace(body, []byte(`"cleanup_seconds":10}`), []byte(`"cleanup_seconds":10,"cost_allowance_usd":5}`), 1)
	body = append(body, '\n')
	var recorded runRecord
	if err := decodeCleanupRecord(body, &recorded); err != nil {
		t.Fatal("supported historical cleanup record was refused", err)
	}
	if recorded.Limits == nil || *recorded.Limits != allowance {
		t.Fatal("historical monetary field changed current operation allowances")
	}
	// This literal follows the historical static-identity field order and values.
	// Its digest uses only the standard library, independent of caseIdentitySHA256.
	const identity = `{"schema_version":2,"run_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","native":{"goos":"darwin","goarch":"arm64"},"started_at":"2026-10-31T00:00:00Z","source":{"revision":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","dirty":false,"dirty_diff_sha256":null},"suite":"live","provider":"aws","target":"aws","profile":"full","coverage_scope":"live_scenarios","schedule":{"recovery_mode":"disabled","selected_scenarios":["state.single-value-update-preserves-other-values/members_32"],"repetitions":1,"entries":[{"scenario":"state.single-value-update-preserves-other-values/members_32","sequence":0,"repetition":1,"smoke":true}],"full_coverage":false},"toolchain":"recorded-toolchain","limits":{"requests":1000,"body_bytes":1073741824,"objects":256,"object_bytes":268435456,"generator_creates":128,"generator_retires":256,"elapsed_seconds":10,"cleanup_requests":1000,"cleanup_bytes":1073741824,"cleanup_seconds":10,"cost_allowance_usd":5}}`
	digest := sha256.Sum256([]byte(identity))
	got, err := caseIdentitySHA256(recorded)
	if err != nil || got != hex.EncodeToString(digest[:]) {
		t.Fatal("historical case identity changed", got, err)
	}
	for _, replacement := range []string{
		`"cost_allowance_usd":null`, `"cost_allowance_usd":"5"`, `"cost_allowance_usd":-1`,
		`"cost_allowance_usd":5,"cost_allowance_usd":5`, `"cost_allowance_usd":5,"extra":1`,
	} {
		damaged := bytes.Replace(body, []byte(`"cost_allowance_usd":5`), []byte(replacement), 1)
		var rejected runRecord
		if err := decodeCleanupRecord(damaged, &rejected); err == nil {
			t.Fatal("malformed or unsupported historical cleanup limits admitted", replacement)
		}
	}
}

// full_only: false
func TestHistoricalCleanupInputKeepsOriginalBytes(t *testing.T) {
	root, request, entries := recoveryFixture(t, 1)
	path := entries[0].InputPath
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body = bytes.Replace(body, []byte(`"cleanup_seconds":10}`), []byte(`"cleanup_seconds":10,"cost_allowance_usd":5}`), 1)
	if !bytes.Contains(body, []byte(`"cost_allowance_usd":5`)) || os.Chmod(path, 0600) != nil || os.WriteFile(path, body, 0400) != nil {
		t.Fatal("historical input fixture unavailable")
	}
	plan, err := prepareRecovery(root, request)
	if err != nil || len(plan.Entries) != 1 || plan.Entries[0].Input.Limits == nil || *plan.Entries[0].Input.Limits != testLimits() {
		t.Fatal("supported historical cleanup input was refused or changed", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, body) {
		t.Fatal("historical cleanup input was rewritten", err)
	}
	var fresh workerInput
	if records.ReadJSON(path, &fresh) == nil {
		t.Fatal("new worker input accepted a retired allowance field")
	}
	limitsPath := filepath.Join(t.TempDir(), "limits.json")
	if os.WriteFile(limitsPath, []byte(`{"requests":1000,"body_bytes":1073741824,"objects":256,"object_bytes":268435456,"generator_creates":128,"generator_retires":256,"elapsed_seconds":10,"cleanup_requests":1000,"cleanup_bytes":1073741824,"cleanup_seconds":10,"cost_allowance_usd":5}`), 0600) != nil {
		t.Fatal("new limit fixture unavailable")
	}
	if _, err := loadLimits(limitsPath); err == nil {
		t.Fatal("new limits accepted a retired allowance field")
	}
}

// full_only: false
func TestFailedStockCleanupRequiresCumulativeAdmissionBeforeDispatch(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", strings.Repeat("x", 40))
	root, original, _, request, _, inventory := grantedRecoveryFixture(t)
	state := filepath.Dir(inventory)
	oldRun := filepath.Join(filepath.Dir(filepath.Dir(state)), "run.json")
	entry := original.Scenarios[0].Entry
	entry.Scenario = records.StockPluginScenario
	name, err := recordedCaseDirectory(entry)
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(filepath.Dir(state), name)
	if err := os.Rename(state, moved); err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(moved, "input.json")
	var input workerInput
	if records.ReadJSON(inputPath, &input) != nil {
		t.Fatal("original failed worker input unavailable")
	}
	input.Scenarios = []string{records.StockPluginScenario}
	input.Prefix = "enkv-test/" + request.RunID + "/" + name
	original.Failure = &records.Failure{Class: "scenario_failed", Stage: "execution"}
	original.Scenarios = original.Scenarios[:1]
	original.Scenarios[0].Entry = entry
	original.Scenarios[0].Outcome = "failed"
	original.Scenarios[0].Writer.Outcome = "failed"
	if records.WriteJSON(oldRun, original, 0600) != nil {
		t.Fatal("failed stock run fixture unavailable")
	}
	ordinary := recoveryPlan{Provider: original.Provider, Settings: input.Settings, Limits: testLimits(),
		Entries: []recoveryEntry{{State: moved, InputPath: inputPath, Input: input}}}
	if _, _, err := prepareFixtureRecovery(root, request, ordinary); err == nil {
		t.Fatal("failed stock recovery reached dispatch without cumulative accounting and exact support")
	}
}

// full_only: false
func TestStockRecoveryRequiresBearerBeforeConsumingClaim(t *testing.T) {
	t.Run("prepare-before-original-support", func(t *testing.T) {
		t.Setenv("CLOUDFLARE_API_TOKEN", "")
		if _, _, err := prepareStockRecovery(t.TempDir(), t.TempDir(), runRecord{}, recoveryPlan{}); err == nil || err.Error() != "stock recovery Cloudflare environment bearer unavailable" {
			t.Fatal("missing bearer was not refused before original support preparation")
		}
	})
	for _, condition := range []string{"available", "maximum-length", "absent", "short", "oversized", "invalid-byte", "trailing-newline"} {
		t.Run(condition, func(t *testing.T) {
			bearer := strings.Repeat("x", 40)
			switch condition {
			case "maximum-length":
				bearer = strings.Repeat("x", 80)
			case "absent":
				bearer = ""
			case "short":
				bearer = strings.Repeat("x", 39)
			case "oversized":
				bearer = strings.Repeat("x", 81)
			case "invalid-byte":
				bearer = strings.Repeat("x", 39) + ":"
			case "trailing-newline":
				bearer += "\n"
			}
			t.Setenv("CLOUDFLARE_API_TOKEN", bearer)
			state, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil || os.Chmod(state, 0700) != nil || os.MkdirAll(filepath.Join(state, "stock-source", ".enkv"), 0700) != nil {
				t.Fatal("stock recovery claim fixture unavailable", err)
			}
			file := func(name, body string) records.StockPluginFile {
				t.Helper()
				path := filepath.Join(state, name)
				if os.WriteFile(path, []byte(body), 0600) != nil {
					t.Fatal("stock recovery original fixture unavailable")
				}
				value, _, err := stockRecoveryFile(path)
				if err != nil {
					t.Fatal("stock recovery original identity unavailable", err)
				}
				return value
			}
			id := func(value string) string { return strings.Repeat(value, 64) }
			old, current := strings.Repeat("a", 32), strings.Repeat("b", 32)
			allowance := testLimits()
			allowance.ElapsedSeconds = 3000
			body, err := json.Marshal(allowance)
			if err != nil {
				t.Fatal(err)
			}
			input := &records.StockPluginRecoveryInput{Schema: 1, OriginalRunID: old, RecoveryRunID: current,
				OriginalRun: file("run.json", "{}\n"), OriginalInput: file("input.json", "{}\n"),
				OriginalEvidence: file("stock-plugin-evidence.json", "{}\n"), OriginalGrant: file("stock-plugin-grant.json", "{}\n"), Accounting: file("stock-recovery-accounting.json", "{}\n"),
				Sources:              []records.StockPluginFile{file("stock-source/.enkv/generated.json", "{}\n"), file("stock-source/configuration.json", "{\"generated\":\".enkv/generated.json\"}\n")},
				Originals:            []records.StockPluginRecoveryOriginal{{OperationID: id("1"), AttemptID: id("2"), OwnerID: id("3"), HazardID: id("4"), ResourceID: id("5"), DescriptorID: id("6"), ExecutorID: id("7"), CredentialRoute: id("8"), ResultContractID: id("9")}},
				OriginalLimitsSHA256: id("c"), CleanupLimitsSHA256: digestBytes(body), ProductRemaining: records.LiveLimits(allowance), OriginalCommands: 2, PriorCommands: 4}
			plan := recoveryPlan{Entries: []recoveryEntry{{State: state}}, Limits: allowance, StockRecovery: input, Grant: &cleanupGrantInput{OriginalCaseReceiptSHA256: id("d")}}
			record := runRecord{RunID: current, RecoveryRunID: old, Limits: &allowance, Source: records.Source{Revision: strings.Repeat("e", 40)},
				CleanupRecoveryBasis: &cleanupRecoveryBasis{Decision: "stock_failed_writer_recovery", OriginalRunSHA256: input.OriginalRun.SHA256, OriginalCaseReceiptSHA256: plan.Grant.OriginalCaseReceiptSHA256}}
			if input.Validate(old, current) != nil || stockRecoverySources(state, input.Sources) != nil {
				t.Fatal("stock recovery fixture is not admissible")
			}
			err = claimStockRecovery(plan, record)
			claim := filepath.Join(state, "stock-recovery-claim.json")
			if condition == "available" || condition == "maximum-length" {
				if err != nil {
					t.Fatal("available selected bearer did not admit claim", err)
				}
				if _, err := os.Stat(claim); err != nil || claimStockRecovery(plan, record) == nil {
					t.Fatal("stock claim is missing or reusable", err)
				}
			} else if err == nil {
				t.Fatal("missing or invalid bearer consumed the stock recovery claim")
			} else if _, err := os.Lstat(claim); !os.IsNotExist(err) {
				t.Fatal("refused bearer still left a consumed stock recovery claim", err)
			}
		})
	}
}

// full_only: false
func TestStockCleanupRejectsPassedWorkerWithoutStockProof(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "")
	root, _, entry := publicCleanupFixture(t, "gcp", "disabled")
	scenario := records.StockPluginScenario
	entry.Input.Scenarios = []string{scenario}
	if records.WriteJSON(entry.InputPath, entry.Input, 0400) != nil || records.WriteJSON(filepath.Join(entry.State, "stock-plugin-grant.json"), struct{}{}, 0600) != nil {
		t.Fatal("controlled stock worker fixture unavailable")
	}
	plan := recoveryPlan{Entries: []recoveryEntry{entry}}
	s, err := newRunState(root, runRequest{Suite: "live", Provider: "gcp", Target: "gcp", Schedule: recoverySchedule(plan)}, records.Source{}, "controlled")
	if err != nil {
		t.Fatal(err)
	}
	inv, err := makeInvocation(records.Invocation{Scenario: scenario, RunID: s.record.RunID, Worker: "stock-cleanup", Role: "cleanup", Input: entry.InputPath, StateDir: entry.State, OutputDir: filepath.Join(s.private, "cleanup"), FailureSources: controlledFailureSources(t, s.private)}, "live")
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	joined, cleanup := s.executeCleanup(context.Background(), binary, inv, scenario, testLimits())
	if joined == nil || !joined.Joined || joined.Process != "passed" || joined.Outcome != "passed" {
		t.Fatal("controlled cleanup worker did not return a joined success", joined)
	}
	if cleanupPassed(cleanup) {
		t.Fatal("zero counts from a passed worker bypassed stock-specific recovery proof")
	}
}

// full_only: false
func TestStockRecoveryDiagnosticAccountingKeepsHistoricalTextAsProvenance(t *testing.T) {
	state, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 64)
	sources := []records.StockPluginFile{{Path: filepath.Join(state, "stock-source", ".enkv", "generated.json"), SHA256: id, Length: 3}, {Path: filepath.Join(state, "stock-source", "configuration.json"), SHA256: id, Length: 3}}
	cli := records.StockPluginFile{Path: filepath.Join(state, "original-cli"), SHA256: id, Length: 100}
	scope := map[string]any{"child_commands": 1, "maximum_logical_requests": 128, "maximum_body_bytes": 16 << 20, "timeout_seconds": 120, "generator_creates": 0, "generator_retires": 0, "mutation_objects": 0, "mutation_object_bytes": 0, "no_cloudflare_or_github_credentials": true, "no_subprocess_derivation": "reviewed reader SDK route; explanatory provenance only", "support_cli_before": map[string]any{"sha256": id, "length": 100}, "original_source_before": map[string]any{"files": map[string]any{".enkv/generated.json": map[string]any{"sha256": id, "length": 3}, "configuration.json": map[string]any{"sha256": id, "length": 3}}}}
	result := map[string]any{"started": true, "joined": true, "exit_code": 0, "copied_source_unchanged": true, "original_source_unchanged": true, "original_registry_unchanged": true, "support_unchanged": true, "timeout": false, "stdout_overflow": false, "stderr_overflow": false, "capture_error": false, "wait_error": false}
	scopePath, resultPath := filepath.Join(state, "scope.json"), filepath.Join(state, "result.json")
	if records.WriteJSON(scopePath, scope, 0600) != nil || records.WriteJSON(resultPath, result, 0600) != nil {
		t.Fatal("historical diagnostic fixture unavailable")
	}
	scopeFile, _, err := stockRecoveryFile(scopePath)
	resultFile, _, resultErr := stockRecoveryFile(resultPath)
	if err != nil || resultErr != nil {
		t.Fatal("historical diagnostic identities unavailable")
	}
	diagnostic := records.StockPluginRecoveryDiagnostic{Scope: scopeFile, Result: resultFile}
	reservation, elapsed, err := stockDiagnosticReservation(diagnostic, sources, state, cli)
	if err != nil || reservation != (records.BudgetReservation{Requests: 128, BodyBytes: 16 << 20}) || elapsed != 120*time.Second {
		t.Fatal("historical explanatory text was treated as a boolean grant", err)
	}
	for _, condition := range []string{"missing-description", "description-is-boolean", "unknown-effect", "missing-join", "mutation", "ambiguous-body"} {
		t.Run(condition, func(t *testing.T) {
			selectedScope, selectedResult := map[string]any{}, map[string]any{}
			for k, v := range scope {
				selectedScope[k] = v
			}
			for k, v := range result {
				selectedResult[k] = v
			}
			switch condition {
			case "missing-description":
				delete(selectedScope, "no_subprocess_derivation")
			case "description-is-boolean":
				selectedScope["no_subprocess_derivation"] = true
			case "unknown-effect":
				selectedResult["timeout"] = true
			case "missing-join":
				delete(selectedResult, "joined")
			case "mutation":
				selectedScope["mutation_objects"] = 1
			case "ambiguous-body":
				selectedScope["planned_body_byte_reservation"] = 1
			}
			if records.WriteJSON(scopePath, selectedScope, 0600) != nil || records.WriteJSON(resultPath, selectedResult, 0600) != nil {
				t.Fatal("damaged diagnostic fixture unavailable")
			}
			scopeFile, _, err := stockRecoveryFile(scopePath)
			resultFile, _, resultErr := stockRecoveryFile(resultPath)
			if err != nil || resultErr != nil {
				t.Fatal("damaged diagnostic identity unavailable")
			}
			if _, _, err := stockDiagnosticReservation(records.StockPluginRecoveryDiagnostic{Scope: scopeFile, Result: resultFile}, sources, state, cli); err == nil {
				t.Fatal("unsupported diagnostic schema or effects entered recovery accounting", condition)
			}
		})
	}
}

type stockReadmissionFixture struct {
	plan                          recoveryPlan
	record                        runRecord
	state, output, predecessorRun string
	first                         records.StockPluginRecoveryInput
	inv                           records.Invocation
	final                         records.StockPluginRecoveryEvidence
	before                        []byte
}

func newStockReadmissionFixture(t *testing.T) stockReadmissionFixture {
	t.Helper()
	return newStockReadmissionFixtureForObjects(t, 256)
}

func newStockReadmissionFixtureForObjects(t *testing.T, objects uint64) stockReadmissionFixture {
	t.Helper()
	t.Setenv("CLOUDFLARE_API_TOKEN", strings.Repeat("x", 40))
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	old, predecessor, successor := strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32)
	entry := catalog.Entry{Scenario: records.StockPluginScenario, Repetition: 1}
	name, err := recordedCaseDirectory(entry)
	if err != nil {
		t.Fatal(err)
	}
	originalRun := filepath.Join(root, "tests", "live", "runs", old)
	predecessorRun := filepath.Join(root, "tests", "live", "runs", predecessor)
	state, output := filepath.Join(originalRun, "private", name), filepath.Join(predecessorRun, "private", name, "cleanup")
	for _, path := range []string{filepath.Join(state, "stock-source", ".enkv"), output} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	file := func(path, body string) records.StockPluginFile {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte(body))
		return records.StockPluginFile{Path: path, SHA256: hex.EncodeToString(digest[:]), Length: uint64(len(body))}
	}
	jsonFile := func(path string, value any) records.StockPluginFile {
		t.Helper()
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return file(path, string(body)+"\n")
	}
	id := func(value string) string { return strings.Repeat(value, 64) }
	allowance := testLimits()
	allowance.ElapsedSeconds, allowance.GeneratorCreates, allowance.Objects = 3000, 6, objects
	allowance.CleanupRequests, allowance.CleanupBytes, allowance.CleanupSeconds = 8192, 16<<30, 900
	allowanceBody, err := json.Marshal(allowance)
	if err != nil {
		t.Fatal(err)
	}
	sources := []records.StockPluginFile{file(filepath.Join(state, "stock-source", ".enkv", "generated.json"), "{}\n"), file(filepath.Join(state, "stock-source", "configuration.json"), "{\"generated\":\".enkv/generated.json\"}\n")}
	fixtureID := strings.Repeat("d", 32)
	fixture := records.StockPluginFixture{Schema: 1, Purpose: "stock-plugin-acceptance", FixtureID: fixtureID, Provider: "aws", Region: "test-region", Bucket: "test-pa-" + fixtureID, Account: "123456789012"}
	stock := &records.StockPluginAcceptanceInput{Fixture: fixture, Artifact: records.StockPluginArtifact{CLI: records.StockPluginFile{Path: filepath.Join(state, "original-cli"), SHA256: "6d8c3f44151bdcacef3587350dd08dfceeb841ff4d4997c0c1e829dfa7fa9f1e", Length: 62903682}, Source: records.Source{Algorithm: "enkv-raw-git-tree-v1", Revision: "4b92ec84a6fd1f2883b373f76b1096d52935db8d", Tree: "9dd848f6a4bcb594af4ba5ad9e5fc1ebb79c2c5b"}}}
	prefix := "enkv-test/" + old + "/" + name
	originalInput := workerInput{RunID: old, Limits: &allowance, Prefix: prefix, Scenarios: []string{records.StockPluginScenario}, Participants: map[string]string{"authority": "operator", "apply": "apply", "reader": "reader"}, PublicConfiguration: &publicConfigurationInput{Stock: stock, Actors: map[string]liveSettings{"apply": {"provider": "aws", "sdk_mode": "aws-assume-role", "sdk_home": filepath.Join(state, "sdk-home"), "sdk_profile": "limited-apply"}}}}
	inputFile := jsonFile(filepath.Join(state, "input.json"), originalInput)
	original := runRecord{RunID: old, Limits: &allowance, Scenarios: []scenarioResult{{Entry: entry, BudgetReserved: &records.BudgetReservation{Requests: 128, BodyBytes: 16 << 20}, WorkloadElapsed: time.Second, Cleanup: records.Cleanup{BudgetReserved: &records.BudgetReservation{}}}}}
	originalFile := jsonFile(filepath.Join(originalRun, "run.json"), original)
	evidenceFile := jsonFile(filepath.Join(state, "stock-plugin-evidence.json"), records.StockPluginEvidence{Schema: 1, RunID: old, Scenario: records.StockPluginScenario, Provider: "aws", Prefix: prefix, FixtureID: fixtureID, CLISHA256: stock.Artifact.CLI.SHA256, Commands: []records.StockPluginCommand{
		{Ordinal: 0, Worker: "stock-writer", Nonce: strings.Repeat("3", 32), Role: "authority", Actor: "operator", Phase: "init", Started: true, Joined: true, ExitCode: 0, ResultSHA256: id("8")},
		{Ordinal: 1, Worker: "stock-writer", Nonce: strings.Repeat("3", 32), Role: "apply", Actor: "apply", Phase: "a0-created", Started: true, Joined: true, ExitCode: 3, ResultSHA256: id("9")}}})
	grant := records.StockPluginGrant{Schema: 1, Fixture: fixture, RunID: old, Scenario: records.StockPluginScenario, Prefix: prefix, LimitsSHA256: digestBytes(allowanceBody), PreflightEmpty: true, BucketIdentity: "original-bucket"}
	grantFile := jsonFile(filepath.Join(state, "stock-plugin-grant.json"), grant)
	accounting := records.StockPluginRecoveryAccounting{Schema: 1, RunID: old, Complete: true, OriginalRunSHA256: originalFile.SHA256, OriginalInputSHA256: inputFile.SHA256, OriginalEvidenceSHA256: evidenceFile.SHA256, OriginalGrantSHA256: grantFile.SHA256, Sources: sources}
	snapshot := map[string]any{"files": map[string]any{".enkv/generated.json": map[string]any{"sha256": sources[0].SHA256, "length": sources[0].Length}, "configuration.json": map[string]any{"sha256": sources[1].SHA256, "length": sources[1].Length}}}
	scope := map[string]any{"child_commands": 1, "maximum_logical_requests": 128, "maximum_body_bytes": 16 << 20, "timeout_seconds": 120, "generator_creates": 0, "generator_retires": 0, "mutation_objects": 0, "mutation_object_bytes": 0, "no_cloudflare_or_github_credentials": true, "no_subprocess_derivation": "retained read-only route", "support_cli_before": map[string]any{"sha256": stock.Artifact.CLI.SHA256, "length": stock.Artifact.CLI.Length}, "original_source_before": snapshot}
	diagnostic := map[string]any{"started": true, "joined": true, "exit_code": 0, "copied_source_unchanged": true, "original_source_unchanged": true, "original_registry_unchanged": true, "support_unchanged": true, "timeout": false, "stdout_overflow": false, "stderr_overflow": false, "capture_error": false, "wait_error": false}
	for _, suffix := range []string{"one", "two"} {
		accounting.Diagnostics = append(accounting.Diagnostics, records.StockPluginRecoveryDiagnostic{Scope: jsonFile(filepath.Join(state, "scope-"+suffix+".json"), scope), Result: jsonFile(filepath.Join(state, "result-"+suffix+".json"), diagnostic)})
	}
	accountingFile := jsonFile(filepath.Join(state, "stock-recovery-accounting.json"), accounting)
	admission := records.StockPluginRecoveryInput{Schema: 1, OriginalRunID: old, RecoveryRunID: predecessor, OriginalRun: originalFile, OriginalInput: inputFile, OriginalEvidence: evidenceFile, OriginalGrant: grantFile, Accounting: accountingFile, Sources: sources,
		Originals:            []records.StockPluginRecoveryOriginal{{OperationID: id("1"), AttemptID: id("2"), OwnerID: id("3"), HazardID: id("4"), ResourceID: id("5"), DescriptorID: id("6"), ExecutorID: id("7"), CredentialRoute: id("8"), ResultContractID: id("9")}},
		OriginalLimitsSHA256: grant.LimitsSHA256, CleanupLimitsSHA256: digestBytes(allowanceBody), OriginalCommands: 2, PriorCommands: 4,
		ProductRemaining: records.LiveLimits{Requests: 616, BodyBytes: 1023410176, Objects: objects, ObjectBytes: 268435456, GeneratorCreates: 6, GeneratorRetires: 256, ElapsedSeconds: 2759, CleanupRequests: 8192, CleanupBytes: 16 << 30, CleanupSeconds: 900}}
	plan := recoveryPlan{Provider: "aws", Entries: []recoveryEntry{{State: state}}, Limits: allowance, StockRecovery: &admission, Grant: &cleanupGrantInput{OriginalCaseReceiptSHA256: id("e")}}
	basis := &cleanupRecoveryBasis{OriginalRunID: old, OriginalRunSHA256: admission.OriginalRun.SHA256, OriginalCaseReceiptSHA256: plan.Grant.OriginalCaseReceiptSHA256, Entry: entry, Decision: "stock_failed_writer_recovery"}
	record := runRecord{RunID: predecessor, RecoveryRunID: old, Limits: &allowance, Source: records.Source{Revision: strings.Repeat("f", 40)}, CleanupRecoveryBasis: basis}
	if err := claimStockRecovery(plan, record); err != nil {
		t.Fatal("first recovery claim refused", err)
	}
	before, err := os.ReadFile(filepath.Join(state, "stock-recovery-claim.json"))
	if err != nil {
		t.Fatal(err)
	}
	input := originalInput
	input.StockRecovery = &admission
	inputPath := filepath.Join(filepath.Dir(output), "input.json")
	jsonFile(inputPath, input)
	inv := records.Invocation{SchemaVersion: records.SchemaVersion, Scenario: records.StockPluginScenario, RunID: predecessor, Worker: "stock-cleanup", Role: "cleanup", Nonce: strings.Repeat("1", 32), Input: inputPath, StateDir: state, OutputDir: output, FailureSources: controlledFailureSources(t, filepath.Dir(output))}
	jsonFile(filepath.Join(output, "invocation.json"), inv)
	marker := records.FailureMarker{FailureIdentity: records.FailureIdentity{SchemaVersion: records.FailureSchemaVersion, RunID: inv.RunID, Worker: inv.Worker, Role: inv.Role, Scenario: inv.Scenario, Nonce: inv.Nonce}, Phase: "cleanup", Sequence: 1, Code: "fatal", Source: "tests/shared/runner/coordinator_test.go", Line: 1, Completed: records.CompletedCheckpoint{Code: "none"}}
	jsonFile(filepath.Join(output, "failure.json"), marker)
	fixtureCleanup := unresolvedCleanup()
	fixtureCleanup.BudgetReserved = &records.BudgetReservation{}
	jsonFile(filepath.Join(output, "worker.json"), records.WorkerResult{Cleanup: &fixtureCleanup, SchemaVersion: records.SchemaVersion, RunID: inv.RunID, Worker: inv.Worker, Role: inv.Role, Scenario: inv.Scenario, Outcome: "failed", Actor: "cleanup", Phases: []records.PhaseResult{{Sequence: 1, Name: "cleanup", Outcome: "incomplete", Actor: "cleanup", Expected: "success", Actual: "incomplete"}}})
	// The private reservation survives even when the public run has zero totals.
	final := records.StockPluginRecoveryEvidence{Schema: 1, OriginalRunID: old, RecoveryRunID: predecessor, Prefix: prefix, FixtureID: fixtureID, CLISHA256: stock.Artifact.CLI.SHA256, OriginalRunSHA256: admission.OriginalRun.SHA256, OriginalEvidenceSHA256: admission.OriginalEvidence.SHA256, AccountingSHA256: admission.Accounting.SHA256, OriginalGrant: grant,
		ProductAllowance: admission.ProductRemaining, OriginalCommands: 2, PriorCommands: 4, Commands: []records.StockPluginCommand{}, ProductReserved: &records.BudgetReservation{Requests: 128, BodyBytes: 16 << 20, Objects: 128, ObjectBytes: 32 << 20, GeneratorRetires: 3}, ProductElapsedSeconds: 1, Reflection: "not-entered", Retirement: "not-entered", ResidualExposure: "unknown", StoreCleanup: "not-entered"}
	jsonFile(filepath.Join(output, "stock-recovery.json"), final)
	finished := time.Now()
	record.SchemaVersion, record.Suite, record.Provider, record.Outcome, record.FinishedAt = records.SchemaVersion, "live", "aws", "failed", &finished
	record.Scenarios = []scenarioResult{{Entry: entry, Outcome: "failed", Cleanup: fixtureCleanup, CleanupWorker: &workerEvidence{Worker: inv.Worker, Role: "cleanup", Actor: "cleanup", Phases: []records.PhaseResult{{Sequence: 1, Name: "cleanup", Outcome: "incomplete", Actor: "cleanup", Expected: "success", Actual: "incomplete"}}, Started: true, Joined: true, Process: "process_failed", Outcome: "failed", Assertions: &records.AssertionEvidence{Marker: "valid_failure_marker", Checkpoint: "no_checkpoint", Completed: records.CompletedCheckpoint{Code: "none"}}}, BudgetReserved: &records.BudgetReservation{}}}
	jsonFile(filepath.Join(predecessorRun, "run.json"), record)
	next := admission
	next.RecoveryRunID = successor
	// Independently calculated from original work, both diagnostics, and private failure reservation.
	next.ProductRemaining = records.LiveLimits{Requests: 488, BodyBytes: 1006632960, Objects: objects - 128, ObjectBytes: 234881024, GeneratorCreates: 6, GeneratorRetires: 253, ElapsedSeconds: 2758, CleanupRequests: 8192, CleanupBytes: 16 << 30, CleanupSeconds: 900}
	plan.StockRecovery = &next
	nextBasis := *basis
	record.RunID, record.CleanupRecoveryBasis = successor, &nextBasis
	return stockReadmissionFixture{plan: plan, record: record, state: state, output: output, predecessorRun: predecessorRun, first: admission, inv: inv, final: final, before: before}
}

// full_only: false
func TestStockRecoveryAdmitsOneSeparateAttemptAfterNoDispatch(t *testing.T) {
	f := newStockReadmissionFixture(t)
	if err := claimStockRecovery(f.plan, f.record); err != nil {
		t.Fatal("separate successor after proved no dispatch was refused", err)
	}
	after, err := os.ReadFile(filepath.Join(f.state, "stock-recovery-claim.json"))
	if err != nil || !bytes.Equal(f.before, after) {
		t.Fatal("successor changed the original claim", err)
	}
	var selected records.StockPluginRecoveryInput
	if records.ReadJSON(filepath.Join(f.state, "stock-recovery-successor-claim.json"), &selected) != nil || selected.RecoveryRunID != f.record.RunID || selected.ProductRemaining != f.plan.StockRecovery.ProductRemaining || selected.Predecessor == nil || selected.Predecessor.RunID != f.first.RecoveryRunID || selected.OriginalCommands != 2 || selected.PriorCommands != 4 || selected.ValidateClaim(f.state) != nil {
		t.Fatal("separate successor relation or private reservation debit is missing")
	}
	if err := claimStockRecovery(f.plan, f.record); err == nil {
		t.Fatal("successor claim was reusable")
	}
	t.Run("prepared-relation-debits-complete-owner-interval", func(t *testing.T) {
		selected := newStockReadmissionFixture(t)
		path := filepath.Join(selected.predecessorRun, "run.json")
		var predecessor runRecord
		if records.ReadJSON(path, &predecessor) != nil {
			t.Fatal("predecessor unavailable")
		}
		predecessor.Scenarios[0].CleanupElapsed = 2500 * time.Millisecond
		if err := records.WriteJSON(path, predecessor, 0600); err != nil {
			t.Fatal(err)
		}
		selected.plan.Limits.CleanupSeconds = 897
		selected.record.Limits = &selected.plan.Limits
		limitsBody, err := json.Marshal(selected.plan.Limits)
		if err != nil {
			t.Fatal(err)
		}
		selected.plan.StockRecovery.CleanupLimitsSHA256 = digestBytes(limitsBody)
		selected.plan.StockRecovery.RecoveryRunID = ""
		selected.plan.StockRecovery.ProductRemaining = selected.first.ProductRemaining
		if err := selectStockRecoveryPredecessor(selected.state, selected.plan.StockRecovery, selected.plan.Limits); err != nil {
			t.Fatal("unassigned successor preparation refused", err)
		}
		if selected.plan.StockRecovery.ProductRemaining.ElapsedSeconds != 2756 {
			t.Fatal("complete joined owner interval was not debited")
		}
		selected.plan.StockRecovery.RecoveryRunID = selected.record.RunID
		if err := claimStockRecovery(selected.plan, selected.record); err != nil {
			t.Fatal("prepared successor relation refused after assigning its new owner", err)
		}
	})

}

// full_only: false
func TestStockRecoveryRefusesUnprovedOrChangedPredecessor(t *testing.T) {
	for _, condition := range []string{"missing-run", "missing-input", "missing-invocation", "missing-result", "missing-worker", "missing-failure-marker", "missing-claim", "changed-original", "changed-source", "changed-diagnostic", "wrong-owner", "changed-nonce", "unjoined-worker", "unknown-join", "intent-before-start", "stale-empty-proof-with-intent", "diagnostic-present", "prefix-cleanup-present", "nonempty-command-directory", "malformed-result", "duplicate-result-field", "missing-commands", "missing-reservation", "underflow", "omitted-private-debit", "changed-after-selection", "failed-checkpoint-write", "successor-name-unavailable", "stale-zero-reservation", "lower-elapsed-than-owner", "symlinked-run", "symlinked-result", "symlinked-output-owner", "symlinked-claim", "inventory-lock-held"} {
		t.Run(condition, func(t *testing.T) {
			f := newStockReadmissionFixture(t)
			write := func(path string, value any) {
				t.Helper()
				if err := records.WriteJSON(path, value, 0600); err != nil {
					t.Fatal(err)
				}
			}
			remove := func(path string) {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			damage := func(path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("changed\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch condition {
			case "missing-run":
				remove(filepath.Join(f.predecessorRun, "run.json"))
			case "missing-input":
				remove(f.inv.Input)
			case "missing-invocation":
				remove(filepath.Join(f.output, "invocation.json"))
			case "missing-result":
				remove(filepath.Join(f.output, "stock-recovery.json"))
			case "missing-worker":
				remove(filepath.Join(f.output, "worker.json"))
			case "missing-failure-marker":
				remove(filepath.Join(f.output, "failure.json"))
			case "missing-claim":
				if err := selectStockRecoveryPredecessor(f.state, f.plan.StockRecovery, f.plan.Limits); err != nil {
					t.Fatal("prepared relation unavailable", err)
				}
				remove(filepath.Join(f.state, "stock-recovery-claim.json"))
			case "changed-original":
				damage(f.first.OriginalEvidence.Path)
			case "changed-source":
				damage(f.first.Sources[1].Path)
			case "changed-diagnostic":
				damage(filepath.Join(f.state, "result-two.json"))
			case "wrong-owner":
				f.inv.StateDir = filepath.Dir(f.state)
				write(filepath.Join(f.output, "invocation.json"), f.inv)
			case "changed-nonce":
				f.inv.Nonce = strings.Repeat("2", 32)
				write(filepath.Join(f.output, "invocation.json"), f.inv)
			case "unjoined-worker", "unknown-join":
				var predecessor runRecord
				path := filepath.Join(f.predecessorRun, "run.json")
				if records.ReadJSON(path, &predecessor) != nil {
					t.Fatal("predecessor unavailable")
				}
				if condition == "unjoined-worker" {
					predecessor.Scenarios[0].CleanupWorker.Joined = false
				} else {
					predecessor.Scenarios[0].CleanupWorker.Process = "join_unknown"
				}
				write(path, predecessor)
			case "intent-before-start", "stale-empty-proof-with-intent":
				command := records.StockPluginCommand{Ordinal: 2, Worker: f.inv.Worker, Nonce: f.inv.Nonce, Role: "apply", Actor: "publisher", Phase: "failed-writer-cleanup", Started: condition == "stale-empty-proof-with-intent"}
				write(filepath.Join(f.output, "stock-plugin-evidence.json"), records.StockPluginEvidence{Commands: []records.StockPluginCommand{command}})
			case "diagnostic-present":
				write(filepath.Join(f.output, "stock-result-02.json"), struct{}{})
			case "prefix-cleanup-present":
				write(filepath.Join(f.output, "stock-prefix-cleanup.json"), struct{}{})
			case "nonempty-command-directory":
				directory := filepath.Join(f.output, "stock-command-123")
				if err := os.Mkdir(directory, 0700); err != nil {
					t.Fatal(err)
				}
				damage(filepath.Join(directory, "diagnostic"))
			case "malformed-result":
				damage(filepath.Join(f.output, "stock-recovery.json"))
			case "duplicate-result-field":
				path := filepath.Join(f.output, "stock-recovery.json")
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				body = bytes.Replace(body, []byte(`"commands":[]`), []byte(`"commands":[],"commands":[]`), 1)
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-commands":
				f.final.Commands = nil
				write(filepath.Join(f.output, "stock-recovery.json"), f.final)
			case "missing-reservation":
				f.final.ProductReserved = nil
				write(filepath.Join(f.output, "stock-recovery.json"), f.final)
			case "underflow":
				f.final.ProductReserved.Requests = 617
				write(filepath.Join(f.output, "stock-recovery.json"), f.final)
			case "omitted-private-debit":
				f.plan.StockRecovery.ProductRemaining.Requests += 128
			case "changed-after-selection":
				if err := selectStockRecoveryPredecessor(f.state, f.plan.StockRecovery, f.plan.Limits); err != nil {
					t.Fatal("prepared relation unavailable", err)
				}
				f.final.ProductElapsedSeconds++
				write(filepath.Join(f.output, "stock-recovery.json"), f.final)
			case "failed-checkpoint-write":
				write(filepath.Join(f.output, "checkpoint.json"), records.FailureCheckpoint{MarkerWriteError: true})
			case "stale-zero-reservation":
				f.final.ProductReserved = &records.BudgetReservation{}
				write(filepath.Join(f.output, "stock-recovery.json"), f.final)
				f.plan.StockRecovery.ProductRemaining = f.first.ProductRemaining
				f.plan.StockRecovery.ProductRemaining.ElapsedSeconds--
			case "lower-elapsed-than-owner":
				path := filepath.Join(f.predecessorRun, "run.json")
				var predecessor runRecord
				if records.ReadJSON(path, &predecessor) != nil {
					t.Fatal("predecessor unavailable")
				}
				predecessor.Scenarios[0].CleanupElapsed = 2500 * time.Millisecond
				write(path, predecessor)
			case "symlinked-run", "symlinked-result", "symlinked-claim", "symlinked-output-owner":
				path := filepath.Join(f.predecessorRun, "run.json")
				switch condition {
				case "symlinked-result":
					path = filepath.Join(f.output, "stock-recovery.json")
				case "symlinked-claim":
					path = filepath.Join(f.state, "stock-recovery-claim.json")
				case "symlinked-output-owner":
					path = f.output
				}
				target := path + "-retained"
				if err := os.Rename(path, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "inventory-lock-held":
				lock, err := os.OpenFile(filepath.Join(f.state, "inventory.lock"), os.O_RDWR, 0600)
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
				if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
					t.Fatal(err)
				}
			case "successor-name-unavailable":
				if err := os.Mkdir(filepath.Join(f.state, "stock-recovery-successor-claim.json"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			before, readErr := os.ReadFile(filepath.Join(f.state, "stock-recovery-claim.json"))
			if err := claimStockRecovery(f.plan, f.record); err == nil {
				t.Fatal("unsupported predecessor consumed another recovery admission", condition)
			}
			after, err := os.ReadFile(filepath.Join(f.state, "stock-recovery-claim.json"))
			if (readErr == nil) != (err == nil) || !bytes.Equal(before, after) {
				t.Fatal("refused admission changed the original claim")
			}
			if condition != "successor-name-unavailable" {
				if _, err := os.Lstat(filepath.Join(f.state, "stock-recovery-successor-claim.json")); !os.IsNotExist(err) {
					t.Fatal("refused predecessor consumed a successor claim", err)
				}
			}
		})
	}
}

// full_only: false
func TestStockRecoverySelectedClaimRequiresOriginalBytes(t *testing.T) {
	f := newStockReadmissionFixture(t)
	if err := claimStockRecovery(f.plan, f.record); err != nil {
		t.Fatal("successor fixture unavailable", err)
	}
	path := filepath.Join(f.state, f.plan.StockRecovery.ClaimName())
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(body, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if f.plan.StockRecovery.ValidateClaim(f.state) == nil {
		t.Fatal("selected claim byte change retained admission authority")
	}
}

// full_only: false
func TestStockRecoverySuccessorGrantUsesCumulativeCleanupAllowance(t *testing.T) {
	for _, condition := range []string{"remaining-grant", "excessive-seconds", "excessive-requests", "excessive-bytes", "exact-native-debit-once", "native-debit-missing", "native-debit-partial", "current-grant-hash", "native-debit-conflict", "native-debit-underflow", "native-fixture-retirement", "predecessor-grant-hash"} {
		t.Run(condition, func(t *testing.T) {
			f := newStockReadmissionFixture(t)
			path := filepath.Join(f.predecessorRun, "run.json")
			var predecessor runRecord
			if records.ReadJSON(path, &predecessor) != nil {
				t.Fatal("predecessor unavailable")
			}
			workerPath := filepath.Join(f.output, "worker.json")
			var raw records.WorkerResult
			if records.ReadJSON(workerPath, &raw) != nil || raw.Cleanup == nil {
				t.Fatal("native cleanup reservation unavailable")
			}
			reservation := &records.BudgetReservation{}
			predecessor.Scenarios[0].CleanupElapsed = 161714542
			f.plan.Limits.CleanupSeconds = 899
			switch condition {
			case "excessive-seconds":
				f.plan.Limits.CleanupSeconds = 900
			case "excessive-requests":
				reservation.Requests = 17
				predecessor.Scenarios[0].CleanupElapsed = 0
				f.plan.Limits.CleanupSeconds = 900
			case "excessive-bytes":
				reservation.BodyBytes = 1024
				predecessor.Scenarios[0].CleanupElapsed = 0
				f.plan.Limits.CleanupSeconds = 900
			case "exact-native-debit-once":
				reservation.Requests, reservation.BodyBytes = 17, 1024
				f.plan.Limits.CleanupRequests -= 17
				f.plan.Limits.CleanupBytes -= 1024
				// The run aggregate and scenario row are two projections of one debit.
				predecessor.Cleanup.BudgetReserved = reservation
			case "native-fixture-retirement":
				reservation.GeneratorRetires = 1
			case "native-debit-underflow":
				reservation.Requests = 8193
			case "predecessor-grant-hash":
				changed := *predecessor.Limits
				changed.CleanupSeconds--
				predecessor.Limits = &changed
				var priorInput workerInput
				if records.ReadJSON(f.inv.Input, &priorInput) != nil {
					t.Fatal("predecessor input unavailable")
				}
				priorInput.Limits = &changed
				if err := records.WriteJSON(f.inv.Input, priorInput, 0600); err != nil {
					t.Fatal(err)
				}
			}
			predecessor.Scenarios[0].Cleanup.BudgetReserved = reservation
			raw.Cleanup.BudgetReserved = reservation
			if condition == "native-debit-missing" {
				raw.Cleanup.BudgetReserved = nil
			}
			if condition == "native-debit-conflict" {
				raw.Cleanup.BudgetReserved = &records.BudgetReservation{Requests: 1}
			}
			if err := records.WriteJSON(workerPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if condition == "native-debit-partial" {
				body, err := os.ReadFile(workerPath)
				if err != nil {
					t.Fatal(err)
				}
				var fields map[string]any
				if json.Unmarshal(body, &fields) != nil {
					t.Fatal("native worker fields unavailable")
				}
				cleanup := fields["cleanup"].(map[string]any)
				delete(cleanup["budget_reserved"].(map[string]any), "requests")
				if err := records.WriteJSON(workerPath, fields, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := records.WriteJSON(path, predecessor, 0600); err != nil {
				t.Fatal(err)
			}
			f.record.Limits = &f.plan.Limits
			body, err := json.Marshal(f.plan.Limits)
			if err != nil {
				t.Fatal(err)
			}
			f.plan.StockRecovery.CleanupLimitsSHA256 = digestBytes(body)
			if condition == "current-grant-hash" {
				f.plan.StockRecovery.CleanupLimitsSHA256 = f.first.CleanupLimitsSHA256
			}
			before := f.plan.StockRecovery.ProductRemaining
			err = claimStockRecovery(f.plan, f.record)
			if condition == "remaining-grant" || condition == "exact-native-debit-once" {
				if err != nil {
					t.Fatal("finite successor cleanup grant was refused", err)
				}
				if f.plan.StockRecovery.ProductRemaining != before {
					t.Fatal("fixture cleanup grant changed original cumulative Product authority")
				}
			} else if err == nil {
				t.Fatal("successor replenished or ignored a native cleanup debit", condition)
			}
		})
	}
}

type stockJoinedReadmissionFixture struct {
	stockReadmissionFixture
	joinedRun, joinedOutput string
	preserved               map[string][]byte
}

func newStockJoinedReadmissionFixture(t *testing.T) stockJoinedReadmissionFixture {
	t.Helper()
	f := newStockReadmissionFixtureForObjects(t, 512)
	write := func(path string, value any) {
		t.Helper()
		if err := records.WriteJSON(path, value, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var firstRun runRecord
	firstRunPath := filepath.Join(f.predecessorRun, "run.json")
	if records.ReadJSON(firstRunPath, &firstRun) != nil {
		t.Fatal("first cleanup run unavailable")
	}
	firstRun.Scenarios[0].CleanupElapsed = time.Millisecond
	write(firstRunPath, firstRun)
	f.plan.Limits.CleanupSeconds = 899
	f.record.Limits = &f.plan.Limits
	body, err := json.Marshal(f.plan.Limits)
	if err != nil {
		t.Fatal(err)
	}
	f.plan.StockRecovery.CleanupLimitsSHA256 = digestBytes(body)
	if err := claimStockRecovery(f.plan, f.record); err != nil {
		t.Fatal("zero-command successor fixture refused", err)
	}
	selected := *f.plan.StockRecovery
	joinedRun := filepath.Join(filepath.Dir(f.predecessorRun), selected.RecoveryRunID)
	joinedOutput := filepath.Join(joinedRun, "private", filepath.Base(f.state), "cleanup")
	if err := os.MkdirAll(joinedOutput, 0700); err != nil {
		t.Fatal(err)
	}
	inv := f.inv
	inv.RunID, inv.Nonce = selected.RecoveryRunID, strings.Repeat("2", 32)
	inv.OutputDir, inv.Input = joinedOutput, filepath.Join(filepath.Dir(joinedOutput), "input.json")
	write(filepath.Join(joinedOutput, "invocation.json"), inv)
	var input workerInput
	if records.ReadJSON(f.inv.Input, &input) != nil {
		t.Fatal("retained worker input unavailable")
	}
	input.StockRecovery, input.Limits = &selected, f.record.Limits
	write(inv.Input, input)
	marker := records.FailureMarker{FailureIdentity: records.FailureIdentity{SchemaVersion: records.FailureSchemaVersion, RunID: inv.RunID, Worker: inv.Worker, Role: inv.Role, Scenario: inv.Scenario, Nonce: inv.Nonce}, Phase: "cleanup", Sequence: 1, Code: "fatal", Source: "tests/shared/runner/coordinator_test.go", Line: 1, Completed: records.CompletedCheckpoint{Code: "none"}}
	write(filepath.Join(joinedOutput, "failure.json"), marker)
	var raw records.WorkerResult
	if records.ReadJSON(filepath.Join(f.output, "worker.json"), &raw) != nil {
		t.Fatal("retained worker result unavailable")
	}
	raw.RunID = inv.RunID
	write(filepath.Join(joinedOutput, "worker.json"), raw)
	const product = `{"schema":"ProductResult/v1","operation_kind":"clean-owned-failure-residue","state_result":"unavailable","operation_id":"1111111111111111111111111111111111111111111111111111111111111111","request_id":"2222222222222222222222222222222222222222222222222222222222222222","domain_id":"3333333333333333333333333333333333333333333333333333333333333333","request_identity":{"schema":"PreAdmissionRequestIdentity/v1","operation_id":"1111111111111111111111111111111111111111111111111111111111111111","operation_kind":"clean-owned-failure-residue","stage":"observation","code":"evidence-unavailable","source_schema":"enkv/configuration/v3","source_profile":"direct-candidate","format":"json","request_nonce":"2222222222222222222222222222222222222222222222222222222222222222"},"replay_identity":"none","payload":null,"effect_summary":"effect-no-change","output_summary":"not-applicable","evidence_ceiling":"unavailable","commit_may_have_occurred":false,"diagnostics":[]}`
	productDigest := sha256.Sum256([]byte(product))
	productSHA256 := hex.EncodeToString(productDigest[:])
	diagnostic := map[string]any{"schema": 1, "run_id": selected.OriginalRunID, "ordinal": selected.OriginalCommands, "worker": inv.Worker, "nonce": inv.Nonce, "phase": "failed-writer-cleanup", "cli_sha256": input.PublicConfiguration.Stock.Artifact.CLI.SHA256,
		"result_sha256": productSHA256, "digest_scope": "complete", "captured_bytes": len(product), "stdout_overflow": false, "stderr_overflow": false, "stderr_captured_bytes": 0, "started": true, "wait_returned": true, "wait_has_process_state": true, "product_joined": true, "timed_out": false, "start_save_failed": false, "cli_changed": false, "status": "observed",
		"uncaptured": []string{"names", "filesystem-paths", "locators", "values", "warning-text", "source-identifiers", "semantic-completeness"}, "result": json.RawMessage(product)}
	diagnosticPath := filepath.Join(joinedOutput, "stock-result-02.json")
	write(diagnosticPath, diagnostic)
	diagnosticBody, err := os.ReadFile(diagnosticPath)
	if err != nil {
		t.Fatal(err)
	}
	diagnosticDigest := sha256.Sum256(diagnosticBody)
	command := records.StockPluginCommand{Ordinal: selected.OriginalCommands, Worker: inv.Worker, Nonce: inv.Nonce, Role: "apply", Actor: "apply", Phase: "failed-writer-cleanup", Started: true, Joined: true, ExitCode: 3,
		ResultSHA256: productSHA256, DiagnosticSHA256: hex.EncodeToString(diagnosticDigest[:]), DiagnosticBytes: uint32(len(diagnosticBody)), DiagnosticStatus: "observed"}
	var index records.StockPluginEvidence
	if records.ReadJSON(selected.OriginalEvidence.Path, &index) != nil {
		t.Fatal("original command prefix unavailable")
	}
	index.Commands = append(index.Commands, command)
	write(filepath.Join(joinedOutput, "stock-plugin-evidence.json"), index)
	proof := f.final
	proof.AdmissionSHA256, proof.RecoveryRunID = selected.ClaimSHA256(), selected.RecoveryRunID
	proof.ProductAllowance = selected.ProductRemaining
	proof.Commands, proof.ProductResultSHA256 = []records.StockPluginCommand{command}, productSHA256
	proof.Reflection, proof.Retirement, proof.ResidualExposure = "incomplete", "incomplete", "possible-live"
	write(filepath.Join(joinedOutput, "stock-recovery.json"), proof)
	settled := f.record
	settled.Scenarios = append([]scenarioResult(nil), firstRun.Scenarios...)
	settled.Scenarios[0].CleanupElapsed = time.Millisecond
	write(filepath.Join(joinedRun, "run.json"), settled)
	preserved := map[string][]byte{}
	for _, path := range []string{selected.OriginalRun.Path, selected.OriginalInput.Path, selected.OriginalEvidence.Path, selected.OriginalGrant.Path, selected.Accounting.Path,
		filepath.Join(f.state, "stock-recovery-claim.json"), filepath.Join(f.state, "stock-recovery-successor-claim.json"), firstRunPath, f.inv.Input, filepath.Join(f.output, "invocation.json"), filepath.Join(f.output, "worker.json"), filepath.Join(f.output, "failure.json"), filepath.Join(f.output, "stock-recovery.json"),
		filepath.Join(joinedRun, "run.json"), inv.Input, filepath.Join(joinedOutput, "invocation.json"), filepath.Join(joinedOutput, "worker.json"), filepath.Join(joinedOutput, "failure.json"), filepath.Join(joinedOutput, "stock-recovery.json"), filepath.Join(joinedOutput, "stock-plugin-evidence.json"), diagnosticPath} {
		preserved[path], err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range selected.Sources {
		preserved[file.Path], err = os.ReadFile(file.Path)
		if err != nil {
			t.Fatal(err)
		}
	}
	third := f.first
	third.RecoveryRunID, third.Predecessor = strings.Repeat("d", 32), nil
	// Original work and two diagnostics consume 384 requests and 48 MiB.
	// Each cleanup admission then consumes 128 requests, 16 MiB, 128 objects,
	// 32 MiB object bytes, three retirements and one rounded second.
	third.ProductRemaining = records.LiveLimits{Requests: 360, BodyBytes: 989855744, Objects: 256, ObjectBytes: 201326592, GeneratorCreates: 6, GeneratorRetires: 250, ElapsedSeconds: 2757, CleanupRequests: 8192, CleanupBytes: 16 << 30, CleanupSeconds: 900}
	third.PriorCommands = 5
	f.plan.Limits.CleanupSeconds = 898
	body, err = json.Marshal(f.plan.Limits)
	if err != nil {
		t.Fatal(err)
	}
	third.CleanupLimitsSHA256 = digestBytes(body)
	f.plan.StockRecovery = &third
	f.record.RunID, f.record.Limits = third.RecoveryRunID, &f.plan.Limits
	result := stockJoinedReadmissionFixture{stockReadmissionFixture: f, joinedRun: joinedRun, joinedOutput: joinedOutput, preserved: preserved}
	addStockReadTransportAccounting(t, &result)
	return result
}

// full_only: false
func TestStockRecoveryRefusesUnreviewedAdditionalDiagnosticProducer(t *testing.T) {
	f := newStockJoinedReadmissionFixture(t)
	if err := selectStockRecoveryPredecessor(f.state, f.plan.StockRecovery, f.plan.Limits); err == nil {
		t.Fatal("compact synthetic diagnostic source entered full historical admission")
	}
	for path, before := range f.preserved {
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("read-only refusal changed retained evidence", path, err)
		}
	}
}

func addStockReadTransportAccounting(t *testing.T, f *stockJoinedReadmissionFixture) {
	t.Helper()
	directory := filepath.Join(filepath.Dir(f.joinedRun), "read-transport-data", "stock-head")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	writeBytes := func(path string, body []byte) records.StockPluginFile {
		t.Helper()
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(body)
		f.preserved[path] = append([]byte(nil), body...)
		return records.StockPluginFile{Path: path, SHA256: hex.EncodeToString(digest[:]), Length: uint64(len(body))}
	}
	write := func(path string, value any) records.StockPluginFile {
		t.Helper()
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return writeBytes(path, append(body, '\n'))
	}
	var input workerInput
	if records.ReadJSON(filepath.Join(filepath.Dir(f.joinedOutput), "input.json"), &input) != nil {
		t.Fatal("joined source input unavailable")
	}
	fixture, prefix := input.PublicConfiguration.Stock.Fixture, input.Prefix
	context := map[string]any{"mode": "aws-assume-role", "home": filepath.Join(f.joinedOutput, "stock-homes", f.inv.Worker, "apply"), "profile": "limited-apply", "credentials_file": "", "quota_project": ""}
	policy := map[string]any{"version": 1, "record_path": "", "bucket": fixture.Bucket, "prefix": prefix, "max_requests": 1, "max_bytes": 65537, "no_kms": true, "expected_source_kind": "aws-assume-role", "require_standard_source": true}
	keyDigest := sha256.Sum256([]byte(prefix + "/HEAD"))
	probe := map[string]any{"name": "stock-head", "provider": "aws", "actor": "apply", "original_run": f.first.OriginalRunID, "failed_successor": filepath.Base(f.joinedRun), "context": context,
		"operation": "aws-candidate-head", "capture_operation": "head-read", "capture_role": "", "key_sha256": hex.EncodeToString(keyDigest[:]), "force_absent_credentials": true, "credential_routes": []string{},
		"args": []string{"--probe-read-transport", "--operation", "aws-candidate-head", "--region", fixture.Region, "--bucket", fixture.Bucket, "--prefix", prefix, "--expected-owner", fixture.Account}, "policy": policy}
	intent := write(filepath.Join(directory, "intent.json"), map[string]any{"Probe": probe, "BinarySHA256": strings.Repeat("7", 64), "ReservedRequests": 1, "ReservedBodyBytes": 65537, "MaximumSeconds": 120})
	capture := writeBytes(filepath.Join(directory, "capture.jsonl"), []byte("{\"kind\":\"footer\"}\n"))
	policyCopy := map[string]any{}
	for key, value := range policy {
		policyCopy[key] = value
	}
	policyCopy["record_path"] = capture.Path
	policyFile := write(filepath.Join(directory, "policy.json"), policyCopy)
	completion := write(filepath.Join(directory, "completion.json"), map[string]any{"Started": true, "Joined": true, "ExitCode": 0, "ElapsedNanos": 104122500, "Deadline": false, "StdoutOverflow": false, "StderrOverflow": false})
	readResult := map[string]any{"schema": "ReadTransportDiagnostic/v1", "operation": "aws-candidate-head", "read_status": 3, "reason": 1}
	stdout := write(filepath.Join(directory, "stdout.json"), readResult)
	stderr := writeBytes(filepath.Join(directory, "stderr.bin"), nil)
	result := write(filepath.Join(directory, "result.json"), map[string]any{"Result": readResult, "Sent": 0, "OriginalEvidenceUnchanged": true})
	refs := []map[string]any{}
	for _, path := range []string{f.first.OriginalRun.Path, f.first.OriginalInput.Path, f.first.Sources[0].Path, f.first.Sources[1].Path, filepath.Join(f.joinedRun, "run.json"), filepath.Join(filepath.Dir(f.joinedOutput), "input.json")} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(body)
		refs = append(refs, map[string]any{"path": path, "sha256": hex.EncodeToString(digest[:]), "bytes": len(body)})
	}
	packet := write(filepath.Join(directory, "packet.json"), map[string]any{"output_directory": filepath.Dir(directory), "references": refs, "probes": []any{probe}})
	// Synthetic archive bytes only exercise exact-reference integrity. They do
	// not stand in for the reviewed helper source or an executed executable.
	source := writeBytes(filepath.Join(directory, "source.go.txt"), []byte("synthetic source reference for pure accounting admission\n"))
	const owner, pkg, parent = "compositions/full/testsupport/nativeprocess", "enkv.sh/compositions/full/testsupport/nativeprocess", "TestRetainedReadTransportDiagnostic"
	artifact := ordinaryArtifact{Owner: owner, Package: pkg, Directory: "compositions/full", Patterns: []string{"./testsupport/nativeprocess"}, Tests: []string{parent}}
	setOrdinaryArtifactFixtureMetadata(&artifact)
	fullOnly, wallSeconds, parentSeconds, childSeconds := true, float64(1), float64(1), float64(0.1041225)
	artifact.Classifications[0].FullOnly = &fullOnly
	began, finished := time.Date(2026, 11, 5, 10, 46, 42, 0, time.UTC), time.Date(2026, 11, 5, 10, 46, 43, 0, time.UTC)
	evidence := ordinaryStepEvidence{Toolchain: "go version go1.27.3 darwin/arm64", Profile: "full", EventTimeSource: "go_test_json", Race: raceSetting(false), RaceOptions: "", SelectedComplete: true,
		Focus:       &ordinaryFocus{PackagePath: owner, Package: pkg, Artifact: owner, Tests: []string{parent}},
		Preparation: &ordinaryPreparation{Source: records.Source{Revision: strings.Repeat("7", 40)}, Toolchain: "go version go1.27.3 darwin/arm64", Artifacts: []ordinaryArtifact{artifact}, AdmittedPackages: []string{owner}},
		Execution:   []ordinaryExecution{{Artifact: owner, Package: pkg, Tests: []string{parent}}},
		Packages:    []ordinaryPackage{{Name: pkg, Tests: []string{parent}, Inventory: artifact.CompiledTests, Classifications: artifact.Classifications}},
		Diagnostics: &checkDiagnostics{Preparation: "passed", Commands: []checkCommandFacts{
			{Phase: "test", Scope: pkg, Process: "passed", Started: true, Joined: true, WallSeconds: &wallSeconds, Events: "valid", ToolCleanup: "not_required", RequestedNode: "passed", RaceObservation: "not_observed"},
			{Phase: "conversion", Scope: pkg, Process: "passed", Started: true, Joined: true, WallSeconds: &wallSeconds, Events: "valid", ToolCleanup: "not_required", RaceObservation: "not_observed"}}},
		Tests: []ordinaryTest{{Package: pkg, Name: parent, Outcome: "pass", StartedAt: &began, FinishedAt: &finished, ElapsedSeconds: &parentSeconds}, {Package: pkg, Name: parent + "/stock-head", Outcome: "pass", StartedAt: &began, FinishedAt: &finished, ElapsedSeconds: &childSeconds}}}
	if !validOrdinaryFocusedEvidence(evidence) {
		t.Fatal("synthetic focused terminal fixture is inconsistent")
	}
	terminal := write(filepath.Join(directory, "terminal.json"), map[string]any{"type": "test_result", "step": "retained-read-diagnostics", "activity": "unit", "outcome": "passed", "ordinary": evidence})
	terminalBody, err := os.ReadFile(terminal.Path)
	if err != nil {
		t.Fatal(err)
	}
	logBody := append([]byte("synthetic native terminal\n"), terminalBody...)
	terminalLog := writeBytes(filepath.Join(directory, "output.log"), logBody)
	terminalProvenance := write(filepath.Join(directory, "terminal-provenance.json"), map[string]any{"source": terminalLog.Path, "source_bytes": terminalLog.Length, "source_sha256": terminalLog.SHA256, "supervisor_exit_code": 0,
		"events": []any{map[string]any{"path": terminal.Path, "line_1_based": 2, "byte_start": len("synthetic native terminal\n"), "byte_end": len(logBody), "bytes": terminal.Length, "sha256": terminal.SHA256, "step": "retained-read-diagnostics", "outcome": "passed"}}})
	timing := write(filepath.Join(directory, "timing.json"), map[string]any{"kind": "live", "started_at": "2026-11-05T10:46:42Z", "finished_at": "2026-11-05T10:46:56Z", "elapsed_seconds": 14, "exit_code": 0})
	before := records.LiveLimits{Requests: 360, BodyBytes: 989855744, Objects: 256, ObjectBytes: 201326592, GeneratorCreates: 6, GeneratorRetires: 250, ElapsedSeconds: 2757, CleanupRequests: 8192, CleanupBytes: 16 << 30, CleanupSeconds: 900}
	after := records.LiveLimits{Requests: 359, BodyBytes: 989790207, Objects: 256, ObjectBytes: 201326592, GeneratorCreates: 6, GeneratorRetires: 250, ElapsedSeconds: 2756, CleanupRequests: 8192, CleanupBytes: 16 << 30, CleanupSeconds: 900}
	var recordedCompletion stockRecoveryReadCompletion
	var recordedResult stockRecoveryReadRecordedResult
	if records.ReadJSON(completion.Path, &recordedCompletion) != nil || records.ReadJSON(result.Path, &recordedResult) != nil {
		t.Fatal("read diagnostic fixture unavailable")
	}
	settlement := write(filepath.Join(directory, "settlement.json"), map[string]any{"owner": "read-transport-live", "kind": "bounded read-only diagnostics", "status": "settled", "packet_sha256": packet.SHA256, "temporary_source_sha256": source.SHA256,
		"stock_original_run": f.first.OriginalRunID, "stock_successor_record": filepath.Base(f.joinedRun), "stock_consumed": map[string]any{"requests": 1, "body_bytes": 65537, "elapsed_seconds": 1},
		"stock_reservation": map[string]any{"requests": 1, "body_bytes": 65537, "elapsed_seconds": 126}, "stock_remaining_before": before, "stock_remaining_after": after,
		"stock_fixture_remaining_unchanged": map[string]any{"cleanup_requests": 8192, "cleanup_bytes": 16 << 30, "cleanup_seconds": 898}, "native_terminal": terminal.Path, "replay_permitted": false,
		"diagnostic_results":         []any{map[string]any{"name": "stock-head", "directory": directory, "result": recordedResult, "completion": recordedCompletion, "consumed": map[string]any{"requests": 1, "body_bytes": 65537, "elapsed_seconds": 1}}},
		"stock_command_slots_before": 5, "stock_command_slots_reserved": 1, "stock_command_slots_after": 6, "stock_verification_slots_before": 0, "stock_verification_slots_reserved": 1, "stock_verification_slots_after": 1})
	sidecar := map[string]any{"schema": 1, "complete": true, "original_run_id": f.first.OriginalRunID, "failed_recovery_run_id": filepath.Base(f.joinedRun), "base_accounting": f.first.Accounting,
		"intent": intent, "completion": completion, "result": result, "capture": capture, "stdout": stdout, "stderr": stderr, "policy": policyFile, "packet": packet, "source_archive": source, "terminal": terminal, "terminal_provenance": terminalProvenance, "terminal_log": terminalLog, "timing": timing, "settlement": settlement}
	path := filepath.Join(f.state, "stock-recovery-additional-accounting.json")
	if err := records.WriteJSONExclusive(path, sidecar, records.MaximumJSONBytes); err != nil {
		t.Fatal("additional diagnostic accounting was not published exclusively", err)
	}
	f.preserved[path], err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f.plan.StockRecovery.ProductRemaining.Requests = 359
	f.plan.StockRecovery.ProductRemaining.BodyBytes = 989790207
	f.plan.StockRecovery.ProductRemaining.ElapsedSeconds = 2756
	f.plan.StockRecovery.PriorCommands, f.plan.StockRecovery.PriorVerifications = 6, 1
}

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

// These local protocol fixtures establish retention and join checks. They do
// not assert that a cloud ran or that a current-state authentication succeeded.
func publicOutputRecoveryRetentionFixture(t *testing.T) (*runState, recoveryPlan) {
	t.Helper()
	return publicOutputRecoveryRetentionFixtureMode(t, "")
}

func publicOutputRecoveryRetentionFixtureMode(t *testing.T, mode string) (*runState, recoveryPlan) {
	t.Helper()
	s, plan, _ := publicCleanupEvidenceFixture(t, "gcp", "disabled")
	entry := plan.Entries[0]
	if mode != "" {
		entry.Input.Settings["test_mode"] = mode
		plan.Settings = entry.Input.Settings
	}
	const scenario = "public-configuration.manifest/atomic_public_file"
	name, err := currentCaseDirectory(catalog.Entry{Scenario: scenario})
	if err != nil {
		t.Fatal(err)
	}
	oldState, oldScenario, oldPrefix := entry.State, entry.Input.Scenarios[0], entry.Input.Prefix
	entry.State = filepath.Join(filepath.Dir(oldState), name)
	entry.InputPath = filepath.Join(entry.State, "input.json")
	entry.Input.Scenarios = []string{scenario}
	entry.Input.Prefix = "enkv-test/" + entry.Input.RunID + "/" + name
	if os.Rename(oldState, entry.State) != nil {
		t.Fatal("local fixture relocation unavailable")
	}
	if err := filepath.WalkDir(entry.State, func(path string, file os.DirEntry, err error) error {
		if err != nil || file.IsDir() || !strings.HasSuffix(path, ".json") {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		info, err := file.Info()
		if err != nil {
			return err
		}
		body = bytes.ReplaceAll(body, []byte(oldState), []byte(entry.State))
		body = bytes.ReplaceAll(body, []byte(oldScenario), []byte(scenario))
		body = bytes.ReplaceAll(body, []byte(oldPrefix), []byte(entry.Input.Prefix))
		if os.Chmod(path, 0600) != nil || os.WriteFile(path, body, 0600) != nil {
			return errPublicConfigurationEvidence
		}
		return os.Chmod(path, info.Mode().Perm())
	}); err != nil {
		t.Fatal(err)
	}
	entry.Input.PublicConfiguration.Actors["apply"] = entry.Input.Settings
	entry.Input.Participants["apply"] = "applicator"
	entry.Input.PublicConfiguration.Outputs = &records.PublicOutputScopes{Repository: records.PublicOutputScope{Owner: "owner", Repository: "repository"}, Organization: records.PublicOutputScope{Owner: "organization", Visibility: "selected", Repositories: []uint64{101}}, Environment: records.PublicOutputScope{Owner: "owner", Repository: "repository", Environment: "prod"}}
	for _, path := range []string{entry.InputPath, filepath.Join(entry.State, "cleanup-input.json")} {
		if records.WriteJSON(path, entry.Input, 0400) != nil {
			t.Fatal("output input fixture unavailable")
		}
	}
	source := filepath.Join(entry.State, "public-source/configuration.json")
	generated := filepath.Join(entry.State, "public-source/.enkv/prod.generated.json")
	if os.MkdirAll(filepath.Dir(generated), 0700) != nil || records.WriteJSON(source, map[string]any{"schema": "enkv/configuration/v3", "generated": ".enkv/prod.generated.json", "outputs": map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}}}, 0600) != nil || records.WriteJSON(generated, map[string]any{"retained_public_basis": "local protocol fixture"}, 0400) != nil {
		t.Fatal("output source fixture unavailable")
	}
	directory := filepath.Dir(filepath.Dir(entry.State))
	var original runRecord
	if records.ReadJSON(filepath.Join(directory, "run.json"), &original) != nil {
		t.Fatal("original fixture unavailable")
	}
	original.Schedule.Entries[0].Scenario = scenario
	original.Schedule.Selected = []string{scenario}
	original.Resolved.RoleBindings = entry.Input.Participants
	original.Context = safeRunContext(entry.Input.Settings)
	original.Scenarios[0].Entry = original.Schedule.Entries[0]
	shape, err := recordedFixture(scenario, 0)
	if err != nil {
		t.Fatal(err)
	}
	original.Scenarios[0].Fixture = shape
	original.CaseReceipts = nil
	if os.Remove(filepath.Join(directory, caseReceiptPath(0))) != nil {
		t.Fatal("local old fixture receipt unavailable")
	}
	old := &runState{directory: directory, record: original}
	identity, err := caseIdentitySHA256(original)
	if err != nil || old.writeCaseReceipt(original.Scenarios[0], identity) != nil || records.WriteJSON(filepath.Join(directory, "run.json"), old.record, 0600) != nil {
		t.Fatal("local output receipt unavailable", err)
	}
	entry.OriginalEntry = original.Schedule.Entries[0]
	plan.Entries = []recoveryEntry{entry}
	s.record.Schedule = recoverySchedule(plan)
	s.record.Context = safeRunContext(plan.Settings)
	return s, plan
}

func retainControlledOutputRecovery(t *testing.T, inv records.Invocation, input workerInput) {
	t.Helper()
	r := input.OutputRecovery
	body, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	proof := records.PublicOutputRecoveryProof{Version: 1, InputSHA256: digestBytes(body), Domain: contract.ID{1}, Revision: contract.ID{2}, Snapshot: contract.ID{3}, HeadSHA256: strings.Repeat("d", 64)}
	for _, name := range []string{"intake", "authenticated-discovery", "prepare-pair", "retire-bindings", "remaining-deletions", "current-disposition", "store-cleanup"} {
		proof.Stages = append(proof.Stages, records.PublicOutputRecoveryStage{Name: name, Outcome: "complete"})
	}
	for _, target := range records.PublicOutputFixtureCoordinates(r.Provider, r.Region, r.Account, r.ProjectNumber, r.Prefix, r.Outputs, []string{"gcp-secret-manager", "github-repository", "github-organization", "github-environment"}) {
		id, err := contract.PublicationCoordinateID(proof.Domain, target.ServiceContractID, target.PhysicalTarget)
		if err != nil {
			t.Fatal(err)
		}
		target.CoordinateID = fmt.Sprintf("%x", id)
		row := records.PublicOutputRecoveryDisposition{Target: target, Disposition: "absent-no-effect"}
		proof.Initial, proof.Final = append(proof.Initial, row), append(proof.Final, row)
	}
	tokens := records.PublicConfigurationTokenSource{Version: 1, RunID: input.RunID, Prefix: input.Prefix, Binding: r.Binding, Domain: proof.Domain}
	tokenBody, _ := json.Marshal(tokens)
	tokenBody = append(tokenBody, '\n')
	proof.Store = &records.PublicConfigurationInventoryEvidence{RunID: input.RunID, Prefix: input.Prefix, Binding: r.Binding, Domain: proof.Domain, TokenSource: &tokens, OriginalTokenSourceSHA256: digestBytes(tokenBody)}
	image := grantInventory{Version: 1, RunID: input.RunID, Prefix: input.Prefix, Binding: r.Binding, Domain: proof.Domain, Deleted: map[string]int{}}
	source := filepath.Join(inv.StateDir, "public-source/configuration.json")
	preparedPair := records.PublicOutputRecoveryPair{Version: 1, Source: source}
	for _, file := range []struct{ path, data string }{
		{".enkv/cleanup.generated.json", "{\"retained_public_basis\":\"controlled current basis\",\"canonical_records\":{\"generators\":{},\"outputs\":{\"cloud\":\"AAIAAAAFY2xvdWQAAAA2AAAAEWZpeHR1cmUvY29uZmlnL3YxAAAAEmZpeHR1cmUvc2VydmljZS92MQAAAAJ7fQAAAAA/AAA=\"}}}\n"},
		{"configuration.json", "{\"schema\":\"enkv/configuration/v3\",\"generated\":\".enkv/cleanup.generated.json\",\"entries\":{\"plain\":{\"source\":\"init.files/plain\"}},\"outputs\":{\"destinations\":{\"cloud\":{\"plugin\":null,\"canonical\":{\"settings\":{}}}},\"routing\":{}}}\n"},
		{"init.files/plain", "controlled retained value"},
	} {
		data := []byte(file.data)
		preparedPair.Files = append(preparedPair.Files, records.PublicOutputRecoveryPairFile{Path: file.path, SHA256: digestBytes(data), Bytes: uint64(len(data)), Mode: 0600, Data: data})
	}
	retiredPair := preparedPair
	retiredPair.Files = append([]records.PublicOutputRecoveryPairFile(nil), preparedPair.Files...)
	var document map[string]any
	if json.Unmarshal(preparedPair.Files[1].Data, &document) != nil {
		t.Fatal("prepared source fixture unavailable")
	}
	document["outputs"] = map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}}
	retiredBody, _ := json.Marshal(document)
	retiredBody = append(retiredBody, '\n')
	retiredPair.Files[1].Data, retiredPair.Files[1].Bytes, retiredPair.Files[1].SHA256 = retiredBody, uint64(len(retiredBody)), digestBytes(retiredBody)
	if preparedPair.Validate(*r) != nil || retiredPair.Validate(*r) != nil || !retiredPair.OutputsRemovedFrom(preparedPair) {
		t.Fatal("controlled exact pair relation unavailable")
	}
	for _, file := range retiredPair.Files {
		path := filepath.Join(filepath.Dir(source), file.Path)
		if os.MkdirAll(filepath.Dir(path), 0700) != nil || os.WriteFile(path, file.Data, 0600) != nil {
			t.Fatal("controlled current pair unavailable")
		}
	}
	prepared := records.PublicOutputRecoveryPreparedPair{Version: 1, InputSHA256: proof.InputSHA256, StageSHA256: records.PublicOutputRecoveryStageBinding(proof.InputSHA256, "prepare-pair"), CommandDirectory: "public-command-1", HeadSHA256: proof.HeadSHA256, Pair: preparedPair}
	prepared.Result = []byte(fmt.Sprintf(`{"schema":"enkv/prepare-result/v2","operation":"prepare","request_id":"1111111111111111111111111111111111111111111111111111111111111111","branch":"reconstruction","recovery":{"status":"complete","domain":"0100000000000000000000000000000000000000000000000000000000000000","head":%q},"local_delivery":{"outcome":"recorded","editable_path":%q,"generated_path":%q,"cleanup_failed":false,"readback":{"editable_digest":%q,"generated_digest":%q}},"dependencies":{"assessment":"complete","minimum_administrative_ready":true,"all_declared_ready":false,"requirements":[{"role":"output","subjects":[0],"plugin":null,"contract":"fixture/config/v1","protocol_version":6,"artifact":null,"status":"missing","reason":"selection-required"}],"installations":[],"settings_failure":null},"missing_inputs":[],"diagnostics":[{"reason":"dependency-missing","subject":"dependencies"}],"outcome":"incomplete"}`, prepared.HeadSHA256, preparedPair.Source, filepath.Join(filepath.Dir(preparedPair.Source), ".enkv/cleanup.generated.json"), preparedPair.Files[1].SHA256, preparedPair.Files[0].SHA256))
	owner := records.PublicOutputRecoveryCaptureOwner{Version: 1, RunID: inv.RunID, OriginalRunID: input.RunID, InputSHA256: proof.InputSHA256}
	for i, stage := range []string{"prepare-pair", "retire-bindings"} {
		role, args := "authority", []string{"prepare", "--source", source, "--source-format", "json", "--name", "cleanup", "--provider", r.Provider, "--bucket", input.Settings["bucket"], "--region", r.Region, "--prefix", r.Prefix, "--normal-signing-key", input.Settings["key_id"], "--json"}
		command := records.PublicOutputRecoveryCommand{Version: 1, InputSHA256: proof.InputSHA256, StageSHA256: records.PublicOutputRecoveryStageBinding(proof.InputSHA256, stage), Stage: stage, Reservation: records.BudgetReservation{Requests: 2, BodyBytes: 3}}
		if i == 1 {
			role, args, command.Pair = "apply", []string{"apply", "--source", source, "--source-format", "json", "--json"}, &retiredPair
		}
		command.Role, command.Args = role, args
		if command.Validate(*r, proof) != nil {
			t.Fatal("controlled command relation unavailable")
		}
		code := 0
		if i == 0 {
			code = 2
		}
		capture := []byte(fmt.Sprintf("{\"kind\":\"footer\",\"code\":%d}\n", code))
		directory := filepath.Join(inv.StateDir, fmt.Sprintf("public-command-%d", i+1))
		path := filepath.Join(directory, "capture.jsonl")
		if os.Mkdir(directory, 0700) != nil || os.WriteFile(path, capture, 0600) != nil || records.WriteJSON(filepath.Join(directory, "command.json"), command, 0400) != nil || records.WriteJSON(filepath.Join(directory, "policy.json"), map[string]any{"version": 1}, 0600) != nil {
			t.Fatal("controlled command capture unavailable")
		}
		owner.Captures = append(owner.Captures, records.PublicConfigurationCaptureRegistration{Ordinal: uint16(i), Path: path, SHA256: digestBytes(capture), Bytes: uint64(len(capture)), Complete: true, ParentWorker: inv.Worker, ParentNonce: inv.Nonce, ParentRole: inv.Role, Actor: input.Participants[role], NativeKind: "cli", ExitCode: code})
	}
	values := map[string]any{filepath.Join(inv.StateDir, "public-output-recovery-captures.json"): owner, filepath.Join(inv.StateDir, "public-output-recovery.json"): proof, filepath.Join(inv.StateDir, "public-output-recovery-prepared-pair.json"): prepared}
	if input.Settings["test_mode"] == "output_recovery_before_store" {
		proof.Stages, proof.Store = proof.Stages[:6], nil
		values[filepath.Join(inv.StateDir, "public-output-recovery.json")] = proof
	} else {
		values[filepath.Join(inv.StateDir, "public-cleanup-inventory.json")], values[filepath.Join(inv.StateDir, "public-cleanup-inventory.json.token-evidence.json")] = image, tokens
	}
	for path, value := range values {
		if records.WriteJSON(path, value, 0600) != nil {
			t.Fatal("controlled output handoff fixture unavailable")
		}
	}
}

// full_only: false
func TestPublicOutputRecoveryCompletedPrepareRequiresRetainedResult(t *testing.T) {
	input := records.PublicOutputRecoveryInput{StateDir: t.TempDir(), Provider: "gcp", Prefix: "fixture", Region: "region"}
	inputBody, _ := json.Marshal(input)
	proof := records.PublicOutputRecoveryProof{InputSHA256: digestBytes(inputBody), Domain: contract.ID{1}, HeadSHA256: strings.Repeat("d", 64), Stages: []records.PublicOutputRecoveryStage{{Name: "prepare-pair", Outcome: "complete"}}}
	pair := records.PublicOutputRecoveryPair{Version: 1, Source: filepath.Join(input.StateDir, "public-source/configuration.json")}
	// Binding/v2: u16 schema, length-prefixed destination and destination facts,
	// then a zero target count. Facts contain config/service/settings,
	// an empty policy and the six action bits. This literal uses no product encoder.
	const source = `{"generated":".enkv/cleanup.generated.json","outputs":{"destinations":{"cloud":{"plugin":null,"canonical":{"settings":{}}}},"routing":{}}}`
	for _, file := range []struct{ path, data string }{{".enkv/cleanup.generated.json", `{"canonical_records":{"generators":{},"outputs":{"cloud":"AAIAAAAFY2xvdWQAAAA2AAAAEWZpeHR1cmUvY29uZmlnL3YxAAAAEmZpeHR1cmUvc2VydmljZS92MQAAAAJ7fQAAAAA/AAA="}}}`}, {"configuration.json", source}} {
		data := []byte(file.data)
		pair.Files = append(pair.Files, records.PublicOutputRecoveryPairFile{Path: file.path, Data: data, SHA256: digestBytes(data), Bytes: uint64(len(data)), Mode: 0600})
	}
	prepared := records.PublicOutputRecoveryPreparedPair{Version: 1, InputSHA256: proof.InputSHA256, StageSHA256: records.PublicOutputRecoveryStageBinding(proof.InputSHA256, "prepare-pair"), CommandDirectory: "public-command-1", HeadSHA256: proof.HeadSHA256, Pair: pair}
	prepared.Result = []byte(fmt.Sprintf(`{"schema":"enkv/prepare-result/v2","operation":"prepare","request_id":"1111111111111111111111111111111111111111111111111111111111111111","branch":"reconstruction","recovery":{"status":"complete","domain":"0100000000000000000000000000000000000000000000000000000000000000","head":%q},"local_delivery":{"outcome":"recorded","editable_path":%q,"generated_path":%q,"cleanup_failed":false,"readback":{"editable_digest":%q,"generated_digest":%q}},"dependencies":{"assessment":"complete","minimum_administrative_ready":true,"all_declared_ready":false,"requirements":[{"role":"output","subjects":[0],"plugin":null,"contract":"fixture/config/v1","protocol_version":6,"artifact":null,"status":"missing","reason":"selection-required"}],"installations":[],"settings_failure":null},"missing_inputs":[],"diagnostics":[{"reason":"dependency-missing","subject":"dependencies"}],"outcome":"incomplete"}`, prepared.HeadSHA256, pair.Source, filepath.Join(filepath.Dir(pair.Source), ".enkv/cleanup.generated.json"), pair.Files[1].SHA256, pair.Files[0].SHA256))
	original := workerInput{Settings: map[string]string{"bucket": "bucket", "key_id": "key"}, Participants: map[string]string{"authority": "authority"}}
	command := records.PublicOutputRecoveryCommand{Version: 1, InputSHA256: proof.InputSHA256, StageSHA256: prepared.StageSHA256, Stage: "prepare-pair", Role: "authority", Args: []string{"prepare", "--source", pair.Source, "--source-format", "json", "--name", "cleanup", "--provider", input.Provider, "--bucket", "bucket", "--region", input.Region, "--prefix", input.Prefix, "--normal-signing-key", "key", "--json"}, Reservation: records.BudgetReservation{Requests: 1, BodyBytes: 1}}
	commandBody, _ := json.Marshal(command)
	commandBody = append(commandBody, '\n')
	var retainedCommand records.PublicOutputRecoveryCommand
	if decodeCleanupRecord(commandBody, &retainedCommand) != nil || retainedCommand.Validate(input, proof) != nil || pair.Validate(input) != nil {
		t.Fatal("retained prepare command fixture is not canonical or complete")
	}
	owner := records.PublicOutputRecoveryCaptureOwner{Captures: []records.PublicConfigurationCaptureRegistration{{Path: filepath.Join(input.StateDir, prepared.CommandDirectory, "capture.jsonl"), Complete: true, NativeKind: "cli", Actor: "authority", ExitCode: 2}}}
	read := func(path string) ([]byte, error) {
		if filepath.Base(path) == "command.json" {
			return commandBody, nil
		}
		return []byte(`{"version":1}`), nil
	}
	if publicOutputRecoveryCommands(input, proof, owner, original, command.Reservation, &prepared, read) != nil {
		t.Fatal("completed prepare lost its exact delivered pair and missing dependency result")
	}
	for _, damage := range []string{"missing-result", "other-code", "other-code-two-failure", "head", "domain", "digest", "requirements", "missing-pair"} {
		t.Run(damage, func(t *testing.T) {
			changed := prepared
			captures := owner
			captures.Captures = append([]records.PublicConfigurationCaptureRegistration(nil), owner.Captures...)
			candidate := &changed
			switch damage {
			case "missing-result":
				changed.Result = nil
			case "other-code":
				captures.Captures[0].ExitCode = 3
			case "other-code-two-failure":
				changed.Result = bytes.Replace(changed.Result, []byte(`"dependency-missing"`), []byte(`"unavailable"`), 1)
			case "head":
				changed.HeadSHA256 = strings.Repeat("e", 64)
			case "domain":
				changed.Result = bytes.Replace(changed.Result, []byte(`"domain":"01`), []byte(`"domain":"02`), 1)
			case "digest":
				changed.Result = bytes.Replace(changed.Result, []byte(pair.Files[1].SHA256), []byte(strings.Repeat("e", 64)), 1)
			case "requirements":
				changed.Result = bytes.Replace(changed.Result, []byte(`"contract":"fixture/config/v1"`), []byte(`"contract":"undeclared/config/v1"`), 1)
			case "missing-pair":
				candidate = nil
			}
			if publicOutputRecoveryCommands(input, proof, captures, original, command.Reservation, candidate, read) == nil {
				t.Fatal("completed prepare accepted an unqualified retained result")
			}
		})
	}
	entered := proof
	entered.Stages = []records.PublicOutputRecoveryStage{{Name: "prepare-pair", Outcome: "entered"}}
	if publicOutputRecoveryCommands(input, entered, owner, original, command.Reservation, nil, read) != nil {
		t.Fatal("entered prepare required a completed pair record")
	}
	t.Run("nonzero-retirement", func(t *testing.T) {
		retired := pair
		retired.Files = append([]records.PublicOutputRecoveryPairFile(nil), pair.Files...)
		retired.Files[1].Data = []byte(`{"generated":".enkv/cleanup.generated.json","outputs":{"destinations":{},"routing":{}}}`)
		retired.Files[1].SHA256, retired.Files[1].Bytes = digestBytes(retired.Files[1].Data), uint64(len(retired.Files[1].Data))
		retirement := records.PublicOutputRecoveryCommand{Version: 1, InputSHA256: proof.InputSHA256, Stage: "retire-bindings", Role: "apply", Args: []string{"apply", "--source", pair.Source, "--source-format", "json", "--json"}, Reservation: command.Reservation, Pair: &retired}
		retirement.StageSHA256 = records.PublicOutputRecoveryStageBinding(proof.InputSHA256, retirement.Stage)
		retirementBody, _ := json.Marshal(retirement)
		retirementBody = append(retirementBody, '\n')
		completed := proof
		completed.Stages = append(append([]records.PublicOutputRecoveryStage(nil), proof.Stages...), records.PublicOutputRecoveryStage{Name: retirement.Stage, Outcome: "complete"})
		captures := owner
		captures.Captures = append(append([]records.PublicConfigurationCaptureRegistration(nil), owner.Captures...), records.PublicConfigurationCaptureRegistration{Ordinal: 1, Path: filepath.Join(input.StateDir, "public-command-2/capture.jsonl"), Complete: true, NativeKind: "cli", Actor: "apply", ExitCode: 2})
		actors := original
		actors.Participants = map[string]string{"authority": "authority", "apply": "apply"}
		readRetirement := func(path string) ([]byte, error) {
			if filepath.Base(filepath.Dir(path)) == "public-command-2" && filepath.Base(path) == "command.json" {
				return retirementBody, nil
			}
			return read(path)
		}
		budget := records.BudgetReservation{Requests: 2, BodyBytes: 2}
		if publicOutputRecoveryCommands(input, completed, captures, actors, budget, &prepared, readRetirement) == nil {
			t.Fatal("prepare dependency result allowed nonzero completed retirement")
		}
		captures.Captures[1].ExitCode = 0
		if publicOutputRecoveryCommands(input, completed, captures, actors, budget, &prepared, readRetirement) != nil {
			t.Fatal("successful retirement lost its exact prepared pair")
		}
	})
}

// full_only: false
func TestPublicOutputRecoveryIntakeRetainsMissingWriterFactsAndExactDebits(t *testing.T) {
	for _, damage := range []string{"none", "capture-parent", "capture-bytes", "missing-generated", "contradictory-debit", "object-underflow"} {
		t.Run(damage, func(t *testing.T) {
			s, plan := publicOutputRecoveryRetentionFixture(t)
			entry := plan.Entries[0]
			s.record.CoverageScope = "cleanup_recovery"
			state := filepath.Join(s.private, "recovery-state")
			if os.Mkdir(state, 0700) != nil {
				t.Fatal("new owner unavailable")
			}
			switch damage {
			case "capture-parent":
				var ledger records.PublicConfigurationOwnership
				p := filepath.Join(entry.State, "public-ownership.json")
				if records.ReadJSON(p, &ledger) != nil {
					t.Fatal("ledger fixture")
				}
				ledger.Captures[0].ParentNonce = strings.Repeat("f", 32)
				if records.WriteJSON(p, ledger, 0600) != nil {
					t.Fatal("damage")
				}
			case "capture-bytes":
				if os.WriteFile(filepath.Join(entry.State, "public-command-1/capture.jsonl"), []byte("{\"kind\":\"footer\"}\n"), 0600) != nil {
					t.Fatal("damage")
				}
			case "missing-generated":
				if os.Remove(filepath.Join(entry.State, "public-source/.enkv/prod.generated.json")) != nil {
					t.Fatal("damage")
				}
			case "contradictory-debit", "object-underflow":
				p := filepath.Join(entry.State, "workers/cleanup/worker.json")
				var raw records.WorkerResult
				if records.ReadJSON(p, &raw) != nil {
					t.Fatal("worker fixture")
				}
				copy := *raw.BudgetReserved
				copy.Objects = 1
				raw.Cleanup.BudgetReserved = &copy
				if damage == "object-underflow" {
					copy.Objects = entry.Input.Limits.Objects + 1
					raw.BudgetReserved = &copy
				}
				if records.WriteJSON(p, raw, 0600) != nil {
					t.Fatal("damage")
				}
			}
			input, err := s.preparePublicOutputRecovery(entry, state, plan.Limits)
			if damage == "none" {
				if err != nil || input.VerifyFiles() != nil || !input.MutationAllowance(entry.Input.Limits.Objects, entry.Input.Limits.ObjectBytes) {
					t.Fatal("supported missing-facts intake refused", err)
				}
				if _, err := os.Lstat(filepath.Join(entry.State, "after.json")); !os.IsNotExist(err) {
					t.Fatal("intake invented writer completion")
				}
				if os.Chmod(input.Generated, 0600) != nil || os.WriteFile(input.Generated, []byte("changed after intake"), 0600) != nil || os.Chmod(input.Generated, 0400) != nil {
					t.Fatal("changed-original control unavailable")
				}
				if input.VerifyFiles() == nil {
					t.Fatal("changed original survived intake pin")
				}
			} else if err == nil {
				t.Fatal("incomplete ownership or accounting reached recovery")
			}
		})
	}
}

// full_only: false
func TestPublicOutputRecoveryEvidenceSurvivesOriginalDisposal(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "")
	s, plan := publicOutputRecoveryRetentionFixture(t)
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.executeRecovery(t.Context(), binary, plan); err != nil {
		publicOutputRecoveryHandoffDiagnostic(t, s)
		t.Fatal("controlled output recovery handoff failed", err)
	}
	s.finish()
	if s.record.Outcome != "passed" || s.record.Correctness.Passed || len(s.record.Scenarios) != 1 || s.record.Scenarios[0].PublicConfigurationEvidence == nil {
		t.Fatal("output cleanup lost its separate result")
	}
	result := s.record.Scenarios[0]
	if err := readPublicOutputRecoveryEvidence(s.directory, s.record, result); err != nil {
		t.Fatal("output proof could not reopen", err)
	}
	checkpoint := "recovery/checkpoint.json"
	checkpointPath := filepath.Join(s.directory, filepath.Dir(result.PublicConfigurationEvidence.Path), checkpoint)
	checkpointBody, err := os.ReadFile(checkpointPath)
	if err != nil {
		t.Fatal("new joined worker checkpoint was not exported", err)
	}
	if os.Remove(checkpointPath) != nil || readPublicOutputRecoveryEvidence(s.directory, s.record, result) == nil {
		t.Fatal("missing new worker checkpoint survived reopen")
	}
	if os.WriteFile(checkpointPath, checkpointBody, 0600) != nil {
		t.Fatal("checkpoint restoration unavailable")
	}
	var changed records.FailureCheckpoint
	if json.Unmarshal(checkpointBody, &changed) != nil {
		t.Fatal("checkpoint fixture unavailable")
	}
	changed.Nonce = strings.Repeat("f", 32)
	changedBody, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	rewriteOutputRecoveryEvidenceFile(t, s.directory, &result, checkpoint, append(changedBody, '\n'))
	if readPublicOutputRecoveryEvidence(s.directory, s.record, result) == nil {
		t.Fatal("changed checkpoint owner survived exact joined assertion validation")
	}
	rewriteOutputRecoveryEvidenceFile(t, s.directory, &result, checkpoint, checkpointBody)
	if readPublicOutputRecoveryEvidence(s.directory, s.record, result) != nil {
		t.Fatal("exact checkpoint proof did not reopen after control restoration")
	}
	if os.Rename(filepath.Dir(plan.Entries[0].State), filepath.Dir(plan.Entries[0].State)+"-unavailable") != nil {
		t.Fatal("local original disposal unavailable")
	}
	if readPublicOutputRecoveryEvidence(s.directory, s.record, result) != nil {
		t.Fatal("output proof depends on original private files")
	}
	proof := filepath.Join(s.directory, filepath.Dir(result.PublicConfigurationEvidence.Path), "recovery/output-recovery.json")
	if os.WriteFile(proof, []byte("{}\n"), 0600) != nil || readPublicOutputRecoveryEvidence(s.directory, s.record, result) == nil {
		t.Fatal("changed current proof survived reopen")
	}
}

// full_only: false
func TestPublicOutputRecoveryExcludesVerifiedCompletedSibling(t *testing.T) {
	const scenario = "public-configuration.output-standalone/output_standalone"
	fixture := publicEvidenceDisposalFixtureForScenario(t, 2, scenario)
	s := fixture.run
	_, _, seed := publicCleanupFixture(t, "gcp", "disabled")
	input := fixture.participants.input
	input.Settings, input.Limits, input.Repetitions = seed.Input.Settings, seed.Input.Limits, 1
	input.PublicConfiguration.Actors = seed.Input.PublicConfiguration.Actors
	input.PublicConfiguration.Actors["apply"] = input.Settings
	input.Participants = map[string]string{"authority": "authority", "apply": "apply", "reader": "reader", "cleanup": "cleanup"}
	input.PublicConfiguration.Outputs = &records.PublicOutputScopes{
		Repository:   records.PublicOutputScope{Owner: "owner", Repository: "repository"},
		Organization: records.PublicOutputScope{Owner: "organization", Visibility: "selected", Repositories: []uint64{101, 202}},
		Environment:  records.PublicOutputScope{Owner: "owner", Repository: "repository", Environment: "production"},
	}
	if !publicCleanupInputValid(input, "gcp") {
		t.Fatal("completed sibling input is not a supported cleanup route")
	}
	fixture.participants.input = input
	if records.WriteJSON(fixture.participants.writer.Input, input, 0400) != nil {
		t.Fatal("completed sibling input unavailable")
	}
	s.record.Context, s.record.Limits = safeRunContext(input.Settings), input.Limits
	s.record.Resolved.RoleBindings = input.Participants
	if err := s.retainPublicConfigurationEvidence(&fixture.result, fixture.participants); err != nil {
		t.Fatal("completed sibling proof could not be retained", err)
	}
	failedEntry := s.record.Schedule.Entries[1]
	name, err := currentCaseDirectory(failedEntry)
	if err != nil {
		t.Fatal(err)
	}
	failedState := filepath.Join(s.private, name)
	if os.Mkdir(failedState, 0700) != nil {
		t.Fatal("failed sibling state unavailable")
	}
	failedInput := input
	failedInput.Prefix = "enkv-test/" + s.record.RunID + "/" + name
	if records.WriteJSON(filepath.Join(failedState, "input.json"), failedInput, 0400) != nil {
		t.Fatal("failed sibling input unavailable")
	}
	shape, err := recordedFixture(scenario, 0)
	if err != nil {
		t.Fatal(err)
	}
	failed := scenarioResult{Entry: failedEntry, Fixture: shape, Outcome: "failed", Cleanup: unresolvedCleanup(),
		Failure: &records.Failure{Class: "writer_failed", Stage: "writer"}}
	s.record.Scenarios = []scenarioResult{fixture.result, failed}
	s.record.Outcome, s.record.Failure = "failed", &records.Failure{Class: "scenario_failed", Stage: "execution"}
	finished := time.Now().UTC()
	s.record.FinishedAt = &finished
	identity, err := caseIdentitySHA256(s.record)
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range s.record.Scenarios {
		if err := s.writeCaseReceipt(result, identity); err != nil {
			t.Fatal("exact sibling receipt unavailable", err)
		}
	}
	if s.save() != nil || readPublicConfigurationEvidence(s.directory, s.record, fixture.result) != nil {
		t.Fatal("completed sibling proof could not reopen")
	}
	limitsPath := filepath.Join(s.root, "cleanup-limits.json")
	if records.WriteJSON(limitsPath, input.Limits, 0600) != nil {
		t.Fatal("cleanup allowance unavailable")
	}
	pins := map[string][]byte{}
	for _, path := range []string{filepath.Join(s.directory, "run.json"), filepath.Join(s.directory, caseReceiptPath(0)),
		filepath.Join(s.directory, caseReceiptPath(1)), fixture.participants.writer.Input, filepath.Join(failedState, "input.json")} {
		pins[path], err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	plan, err := prepareRecovery(s.root, cleanupRequest{RunID: s.record.RunID, Limits: limitsPath})
	if err != nil || len(plan.Entries) != 1 || plan.Entries[0].State != failedState || plan.Entries[0].Input.Prefix != failedInput.Prefix {
		t.Fatalf("cleanup selected a completed sibling or lost the original failed case: entries=%d err=%v", len(plan.Entries), err)
	}
	schedule := recoverySchedule(plan)
	if len(schedule.Entries) != 1 || schedule.Entries[0] != (catalog.Entry{Scenario: scenario, Sequence: 0}) ||
		filepath.Base(plan.Entries[0].State) != name || failedEntry.Sequence != 1 {
		t.Fatal("new cleanup schedule changed the original failed case identity")
	}
	for path, before := range pins {
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("cleanup selection changed original sibling records", err)
		}
	}
}

func publicOutputRecoveryHandoffDiagnostic(t *testing.T, s *runState) {
	t.Helper()
	if len(s.record.Scenarios) != 1 {
		t.Log("recovery diagnostic: scenario count", len(s.record.Scenarios))
		return
	}
	result := s.record.Scenarios[0]
	if result.CleanupWorker == nil {
		t.Log("recovery diagnostic: cleanup did not start")
		return
	}
	name, err := recordedCaseDirectory(result.Entry)
	if err != nil {
		t.Log("recovery diagnostic: case name", err)
		return
	}
	state := filepath.Join(s.private, name, "state")
	var input records.PublicOutputRecoveryInput
	if err := records.ReadJSON(filepath.Join(state, "public-output-recovery-input.json"), &input); err != nil {
		t.Log("recovery diagnostic: intake", err)
		return
	}
	var proof records.PublicOutputRecoveryProof
	proofRead := records.ReadJSON(filepath.Join(state, "public-output-recovery.json"), &proof)
	t.Log("recovery diagnostic: input/proof", input.Validate(), input.VerifyFiles(), proofRead, proof.Validate(input))
	inputBody, _ := json.Marshal(input)
	t.Log("recovery diagnostic: proof shape/hash/store", proof.Complete(input), proof.InputSHA256 == digestBytes(inputBody), len(proof.Initial), len(proof.Final), proof.Store != nil)
	for i, row := range proof.Final {
		t.Log("recovery diagnostic: row", i, row.Validate(proof.Domain, true, input))
	}
	if proof.Store != nil && proof.Store.TokenSource != nil {
		t.Log("recovery diagnostic: Store identity/token", proof.Store.RunID == input.OriginalRunID, proof.Store.Prefix == input.Prefix, proof.Store.Binding == input.Binding, proof.Store.Domain == proof.Domain, proof.Store.TokenSource.Validate())
	}
	manifestPath := filepath.Join(s.directory, "evidence/public-configuration/0000/manifest.json")
	var manifest publicOutputRecoveryEvidenceManifest
	if err := records.ReadJSON(manifestPath, &manifest); err != nil {
		t.Log("recovery diagnostic: retained manifest", err)
		return
	}
	root := filepath.Dir(manifestPath)
	originRead := func(path string) ([]byte, error) {
		relative, err := outputRecoveryOriginPath(manifest.OriginalRuns, path)
		if err != nil {
			return nil, err
		}
		return os.ReadFile(filepath.Join(root, relative))
	}
	_, originErr := verifyPublicOutputRecoveryOrigin(input, manifest.OriginalRuns, root, originRead)
	var original, current workerInput
	oldBody, oldErr := originRead(filepath.Join(input.OriginalState, "input.json"))
	oldDecode := json.Unmarshal(oldBody, &original)
	newErr := records.ReadJSON(filepath.Join(s.private, name, "input.json"), &current)
	expected := original
	expected.Limits, expected.OutputRecovery = current.Limits, &input
	t.Log("recovery diagnostic: retained origin/current relation", originErr, oldErr, oldDecode, newErr, reflect.DeepEqual(expected, current), reflect.DeepEqual(current.OutputRecovery, &input))
	var raw records.WorkerResult
	rawRead := records.ReadJSON(filepath.Join(root, "recovery/worker.json"), &raw)
	t.Log("recovery diagnostic: raw worker", rawRead, raw.Cleanup != nil, result.CleanupElapsed > 0)
	inv := records.Invocation{RunID: s.record.RunID, Scenario: result.Scenario, StateDir: state, OutputDir: filepath.Join(s.private, name, "cleanup"), Input: filepath.Join(s.private, name, "input.json")}
	join, joinErr := publicCleanupJoinedWorker(filepath.Join(root, "recovery"), inv, *result.CleanupWorker, filepath.Join(root, "recovery/failure-sources.json"))
	t.Log("recovery diagnostic: joined worker", joinErr, join == manifest.Worker, join.Actor == original.Participants["cleanup"])
}

// full_only: false
func TestPublicOutputRecoveryRefusesPriorStoreCleanupHistory(t *testing.T) {
	for _, history := range []string{"inventory", "token-evidence", "entered-stage"} {
		t.Run(history, func(t *testing.T) {
			s, plan := publicOutputRecoveryRetentionFixture(t)
			entry := plan.Entries[0]
			path := filepath.Join(entry.State, "public-cleanup-inventory.json")
			var value any = grantInventory{Version: 1, RunID: entry.Input.RunID, Prefix: entry.Input.Prefix, Binding: strings.Repeat("b", 64), Domain: contract.ID{1}, Deleted: map[string]int{}}
			if history == "token-evidence" {
				path += ".token-evidence.json"
				value = records.PublicConfigurationTokenSource{Version: 1, RunID: entry.Input.RunID, Prefix: entry.Input.Prefix, Binding: strings.Repeat("b", 64), Domain: contract.ID{1}}
			} else if history == "entered-stage" {
				path = filepath.Join(entry.State, "public-output-recovery.json")
				value = records.PublicOutputRecoveryProof{Version: 1, Stages: []records.PublicOutputRecoveryStage{{Name: "store-cleanup", Outcome: "entered"}}}
			}
			if records.WriteJSON(path, value, 0600) != nil {
				t.Fatal("prior Store history fixture unavailable")
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			s.record.CoverageScope = "cleanup_recovery"
			state := filepath.Join(s.private, "recovery-state")
			if os.Mkdir(state, 0700) != nil {
				t.Fatal("new recovery owner unavailable")
			}
			if _, err := s.preparePublicOutputRecovery(entry, state, plan.Limits); err == nil {
				t.Error("prior Store cleanup history acquired a fresh inventory and retry allowance")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("intake changed prior Store history", err)
			}
			files, err := os.ReadDir(state)
			if err != nil || len(files) != 0 {
				t.Fatal("Store-history refusal entered a new cleanup stage", err)
			}
		})
	}
}

// full_only: false
func TestPublicOutputRecoveryEvidenceRequiresExactCommandInputs(t *testing.T) {
	for _, damage := range []string{"missing-inputs", "stage-role", "dependency", "non-output", "limits-digest"} {
		t.Run(damage, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "")
			s, plan := publicOutputRecoveryRetentionFixture(t)
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			if err := s.executeRecovery(t.Context(), binary, plan); err != nil {
				publicOutputRecoveryHandoffDiagnostic(t, s)
				t.Fatal("controlled exact command evidence handoff failed", err)
			}
			result := s.record.Scenarios[0]
			ref := result.PublicConfigurationEvidence
			var manifest publicOutputRecoveryEvidenceManifest
			path := filepath.Join(s.directory, ref.Path)
			if records.ReadJSON(path, &manifest) != nil {
				t.Fatal("retained command manifest unavailable")
			}
			if damage == "missing-inputs" {
				var command records.PublicOutputRecoveryCommand
				if records.ReadJSON(filepath.Join(filepath.Dir(path), "recovery/state/public-command-2/command.json"), &command) != nil || command.Pair == nil || len(command.Pair.Files) != 3 {
					t.Fatal("export omitted exact consumed source or dependencies")
				}
				for _, file := range command.Pair.Files {
					if uint64(len(file.Data)) != file.Bytes || digestBytes(file.Data) != file.SHA256 {
						t.Fatal("export omitted or changed consumed bytes")
					}
				}
				// Remove bytes while preserving all declared metadata and archive hashes.
				command.Pair.Files[2].Data = nil
				body, _ := json.Marshal(command)
				rewriteOutputRecoveryEvidenceFile(t, s.directory, &result, "recovery/state/public-command-2/command.json", append(body, '\n'))
				if readPublicOutputRecoveryEvidence(s.directory, s.record, result) == nil {
					t.Fatal("missing exact consumed bytes survived reopen")
				}
				return
			}
			if damage == "limits-digest" {
				var intake records.PublicOutputRecoveryInput
				if records.ReadJSON(filepath.Join(filepath.Dir(path), "recovery/output-recovery-input.json"), &intake) != nil {
					t.Fatal("intake unavailable")
				}
				intake.LimitsSHA256 = strings.Repeat("f", 64)
				body, _ := json.Marshal(intake)
				newHash := digestBytes(body)
				rewriteOutputRecoveryEvidenceFile(t, s.directory, &result, "recovery/output-recovery-input.json", append(body, '\n'))
				var current workerInput
				if records.ReadJSON(filepath.Join(filepath.Dir(path), "recovery/input.json"), &current) != nil {
					t.Fatal("current input unavailable")
				}
				current.OutputRecovery = &intake
				body, _ = json.Marshal(current)
				rewriteOutputRecoveryEvidenceFile(t, s.directory, &result, "recovery/input.json", append(body, '\n'))
				for _, relative := range []string{"recovery/output-recovery.json", "recovery/output-recovery-captures.json", "recovery/prepared-pair.json", "recovery/state/public-command-1/command.json", "recovery/state/public-command-2/command.json"} {
					var record map[string]any
					if records.ReadJSON(filepath.Join(filepath.Dir(path), relative), &record) != nil {
						t.Fatal("context record unavailable")
					}
					record["InputSHA256"] = newHash
					if stage, ok := record["Stage"].(string); ok {
						record["StageSHA256"] = records.PublicOutputRecoveryStageBinding(newHash, stage)
					} else if relative == "recovery/prepared-pair.json" {
						record["StageSHA256"] = records.PublicOutputRecoveryStageBinding(newHash, "prepare-pair")
					}
					body, _ = json.Marshal(record)
					rewriteOutputRecoveryEvidenceFile(t, s.directory, &result, relative, append(body, '\n'))
				}
				if readPublicOutputRecoveryEvidence(s.directory, s.record, result) == nil {
					t.Fatal("different cleanup grant digest survived a self-consistent archive rewrite")
				}
				return
			}
			for i := range manifest.Files {
				file := &manifest.Files[i]
				if !strings.HasSuffix(file.Path, "/public-command-2/command.json") {
					continue
				}
				p := filepath.Join(filepath.Dir(path), file.Path)
				var command map[string]any
				if records.ReadJSON(p, &command) != nil {
					t.Fatal("retained command unavailable")
				}
				if damage == "stage-role" {
					command["Stage"], command["Role"] = "authenticated-discovery", "reader"
				} else {
					var typed records.PublicOutputRecoveryCommand
					if records.ReadJSON(p, &typed) != nil || typed.Pair == nil {
						t.Fatal("consumed pair unavailable")
					}
					index := 2
					data := []byte("different retained value")
					if damage == "non-output" {
						index = 1
						var document map[string]any
						if json.Unmarshal(typed.Pair.Files[index].Data, &document) != nil {
							t.Fatal("source unavailable")
						}
						document["entries"] = map[string]any{}
						data, _ = json.Marshal(document)
					}
					typed.Pair.Files[index].Data, typed.Pair.Files[index].Bytes, typed.Pair.Files[index].SHA256 = data, uint64(len(data)), digestBytes(data)
					encoded, _ := json.Marshal(typed)
					if json.Unmarshal(encoded, &command) != nil {
						t.Fatal("changed pair unavailable")
					}
				}
				if records.WriteJSON(p, command, 0600) != nil {
					t.Fatal("changed command control unavailable")
				}
				body, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				file.SHA256, file.Bytes = digestBytes(body), uint64(len(body))
			}
			if records.WriteJSON(path, manifest, 0600) != nil {
				t.Fatal("changed manifest control unavailable")
			}
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			ref.SHA256, ref.Bytes = digestBytes(body), uint64(len(body))
			if readPublicOutputRecoveryEvidence(s.directory, s.record, result) == nil {
				t.Fatal("reopened proof accepted changed command ownership or non-output input bytes", damage)
			}
		})
	}
}

func rewriteOutputRecoveryEvidenceFile(t *testing.T, directory string, result *scenarioResult, relative string, body []byte) {
	t.Helper()
	path := filepath.Join(directory, result.PublicConfigurationEvidence.Path)
	var manifest publicOutputRecoveryEvidenceManifest
	if records.ReadJSON(path, &manifest) != nil {
		t.Fatal("retained manifest unavailable")
	}
	found := false
	for i := range manifest.Files {
		file := &manifest.Files[i]
		if file.Path != relative {
			continue
		}
		if os.WriteFile(filepath.Join(filepath.Dir(path), relative), body, 0600) != nil {
			t.Fatal("changed retained evidence unavailable")
		}
		file.SHA256, file.Bytes, found = digestBytes(body), uint64(len(body)), true
	}
	if !found || records.WriteJSON(path, manifest, 0600) != nil {
		t.Fatal("exact retained evidence entry unavailable")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	result.PublicConfigurationEvidence.SHA256, result.PublicConfigurationEvidence.Bytes = digestBytes(encoded), uint64(len(encoded))
}

// full_only: false
func TestPublicOutputRecoveryRefusesLaterAttemptStoreHistory(t *testing.T) {
	for _, history := range []string{"entered-stage", "inventory", "token-evidence", "unknown-delete"} {
		t.Run(history, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "")
			prior, plan := publicOutputRecoveryRetentionFixture(t)
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			// Run and join the prior controlled cleanup before changing only its
			// test-owned history for this refusal control.
			if err := prior.executeRecovery(t.Context(), binary, plan); err != nil {
				publicOutputRecoveryHandoffDiagnostic(t, prior)
				t.Fatal("prior controlled cleanup fixture unavailable", err)
			}
			if len(prior.record.Scenarios) != 1 || prior.record.Scenarios[0].CleanupWorker == nil || !prior.record.Scenarios[0].CleanupWorker.Started || !prior.record.Scenarios[0].CleanupWorker.Joined {
				t.Fatal("prior cleanup did not enter and join its actual controlled child")
			}
			name, err := recordedCaseDirectory(prior.record.Scenarios[0].Entry)
			if err != nil {
				t.Fatal(err)
			}
			state := filepath.Join(prior.private, name, "state")
			proofPath := filepath.Join(state, "public-output-recovery.json")
			var priorProof records.PublicOutputRecoveryProof
			if records.ReadJSON(proofPath, &priorProof) != nil {
				t.Fatal("prior joined proof unavailable")
			}
			inventoryPath := filepath.Join(state, "public-cleanup-inventory.json")
			tokenPath := inventoryPath + ".token-evidence.json"
			for _, path := range []string{proofPath, inventoryPath, tokenPath} {
				if os.Remove(path) != nil {
					t.Fatal("prior fixture history unavailable")
				}
			}
			path := proofPath
			priorProof.Store = nil
			priorProof.Stages[len(priorProof.Stages)-1].Outcome = "entered"
			var value any = priorProof
			if history == "inventory" || history == "unknown-delete" {
				path = inventoryPath
				image := grantInventory{Version: 1, RunID: plan.Entries[0].Input.RunID, Prefix: plan.Entries[0].Input.Prefix, Binding: strings.Repeat("b", 64), Domain: contract.ID{1}, Deleted: map[string]int{}}
				if history == "unknown-delete" {
					image.CleanupAttempts = []grantAttempt{{Ordinal: 1, State: "pending"}}
				}
				value = image
			} else if history == "token-evidence" {
				path = tokenPath
				value = records.PublicConfigurationTokenSource{Version: 1, RunID: plan.Entries[0].Input.RunID, Prefix: plan.Entries[0].Input.Prefix, Binding: strings.Repeat("b", 64), Domain: contract.ID{1}}
			}
			if records.WriteJSON(path, value, 0600) != nil {
				t.Fatal("retained prior Store history unavailable")
			}
			mapBody, err := os.ReadFile(prior.failureSources.Path)
			if err != nil || os.MkdirAll(filepath.Join(prior.private, "build"), 0700) != nil || os.WriteFile(filepath.Join(prior.private, "build/failure-sources.json"), mapBody, 0400) != nil {
				t.Fatal("prior retained build source map unavailable", err)
			}
			prior.finish()
			if err := prior.save(); err != nil {
				t.Fatal(err)
			}
			current, err := newRunState(prior.root, runRequest{Suite: "live", Provider: prior.record.Provider, Target: prior.record.Target, Profile: "full", Schedule: recoverySchedule(plan)}, prior.record.Source, "controlled")
			if err != nil {
				t.Fatal(err)
			}
			current.record.RecoveryRunID, current.record.CoverageScope, current.record.Limits = prior.record.RecoveryRunID, "cleanup_recovery", &plan.Limits
			state = filepath.Join(current.private, "recovery-state")
			if os.Mkdir(state, 0700) != nil {
				t.Fatal("new recovery owner unavailable")
			}
			if _, err := current.preparePublicOutputRecovery(plan.Entries[0], state, plan.Limits); err == nil {
				t.Fatal("later joined Store cleanup history acquired a new delete inventory or retry allowance")
			}
		})
	}
}

// full_only: false
func TestPublicOutputRecoverySuccessorRetainsConsumedCommandInputs(t *testing.T) {
	for _, damage := range []string{"none", "missing-command", "missing-policy", "missing-prepared", "changed-dependency"} {
		t.Run(damage, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "")
			prior, plan := publicOutputRecoveryRetentionFixtureMode(t, "output_recovery_before_store")
			entry := &plan.Entries[0]
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			executionErr := prior.executeRecovery(t.Context(), binary, plan)
			if executionErr != nil && !errors.Is(executionErr, errPublicConfigurationEvidence) {
				t.Fatal("controlled prior cleanup failed outside its expected joined refusal", executionErr)
			}
			if executionErr != nil {
				t.Log("retained expected prior cleanup refusal", executionErr)
			}
			if len(prior.record.Scenarios) != 1 || prior.record.Scenarios[0].CleanupWorker == nil || prior.record.Scenarios[0].CleanupWorker.Process != "process_failed" || !prior.record.Scenarios[0].CleanupWorker.Joined {
				if len(prior.record.Scenarios) == 1 && prior.record.Scenarios[0].CleanupWorker != nil {
					worker := prior.record.Scenarios[0].CleanupWorker
					t.Log("prior fixture status", worker.Started, worker.Joined, worker.Process, worker.Assertions)
				}
				t.Fatal("prior before-Store failure did not start and join", executionErr)
			}
			name, err := recordedCaseDirectory(prior.record.Scenarios[0].Entry)
			if err != nil {
				t.Fatal(err)
			}
			priorState := filepath.Join(prior.private, name, "state")
			mapBody, err := os.ReadFile(prior.failureSources.Path)
			if err != nil || os.MkdirAll(filepath.Join(prior.private, "build"), 0700) != nil || os.WriteFile(filepath.Join(prior.private, "build/failure-sources.json"), mapBody, 0400) != nil {
				t.Fatal("retained prior build source map unavailable", err)
			}
			prior.finish()
			if prior.save() != nil {
				t.Fatal("prior joined run unavailable")
			}
			current, err := newRunState(prior.root, runRequest{Suite: "live", Provider: prior.record.Provider, Target: prior.record.Target, Profile: "full", Schedule: recoverySchedule(plan)}, prior.record.Source, "controlled")
			if err != nil {
				t.Fatal(err)
			}
			current.record.RecoveryRunID, current.record.CoverageScope, current.record.Limits = prior.record.RecoveryRunID, "cleanup_recovery", &plan.Limits
			state := filepath.Join(current.private, "recovery-state")
			if os.Mkdir(state, 0700) != nil {
				t.Fatal("successor owner unavailable")
			}
			input, err := current.preparePublicOutputRecovery(*entry, state, plan.Limits)
			if err != nil || input == nil {
				t.Fatal("joined prior cleanup before Store entry did not qualify for exact intake", err)
			}
			pins := map[string]bool{}
			for _, pin := range input.Files {
				pins[pin.Path] = true
			}
			for _, relative := range []string{"public-command-1/command.json", "public-command-1/policy.json", "public-command-2/command.json", "public-command-2/policy.json", "public-output-recovery-prepared-pair.json"} {
				if !pins[filepath.Join(priorState, relative)] {
					t.Error("successor discarded prior consumed-input evidence", relative)
				}
			}
			if damage == "none" {
				_, runs, _, err := records.PrivateOwner(entry.State)
				if err != nil {
					t.Fatal(err)
				}
				archive := t.TempDir()
				pinned := map[string]records.PublicOutputRecoveryFile{}
				for _, pin := range input.Files {
					relative, err := outputRecoveryOriginPath(runs, pin.Path)
					data, _, readErr := publicCleanupRecord(pin.Path)
					path := filepath.Join(archive, relative)
					if err != nil || readErr != nil || digestBytes(data) != pin.SHA256 || os.MkdirAll(filepath.Dir(path), 0700) != nil || os.WriteFile(path, data, 0600) != nil {
						t.Fatal("successor archive image unavailable", err, readErr)
					}
					pinned[pin.Path] = pin
				}
				if os.Rename(filepath.Dir(filepath.Dir(entry.State)), filepath.Dir(filepath.Dir(entry.State))+"-unavailable") != nil || os.Rename(prior.directory, prior.directory+"-unavailable") != nil {
					t.Fatal("controlled original and prior disposal unavailable")
				}
				read := func(path string) ([]byte, error) {
					relative, err := outputRecoveryOriginPath(runs, path)
					if err != nil {
						return nil, err
					}
					data, err := os.ReadFile(filepath.Join(archive, relative))
					if err != nil || digestBytes(data) != pinned[path].SHA256 {
						return nil, errPublicConfigurationEvidence
					}
					return data, nil
				}
				if _, err := verifyPublicOutputRecoveryOrigin(*input, runs, archive, read); err != nil {
					t.Fatal("successor command evidence depends on disposed original or prior private state", err)
				}
				return
			}
			path := filepath.Join(priorState, "public-command-2/command.json")
			switch damage {
			case "missing-command":
				if os.Remove(path) != nil {
					t.Fatal("command damage unavailable")
				}
			case "missing-policy":
				path = filepath.Join(priorState, "public-command-2/policy.json")
				if os.Remove(path) != nil {
					t.Fatal("policy damage unavailable")
				}
			case "missing-prepared":
				path = filepath.Join(priorState, "public-output-recovery-prepared-pair.json")
				if os.Remove(path) != nil {
					t.Fatal("prepared pair damage unavailable")
				}
			case "changed-dependency":
				var command records.PublicOutputRecoveryCommand
				if records.ReadJSON(path, &command) != nil || command.Pair == nil {
					t.Fatal("prior consumed pair unavailable")
				}
				command.Pair.Files[2].Data = []byte("changed prior dependency")
				command.Pair.Files[2].Bytes, command.Pair.Files[2].SHA256 = uint64(len(command.Pair.Files[2].Data)), digestBytes(command.Pair.Files[2].Data)
				if records.WriteJSON(path, command, 0400) != nil {
					t.Fatal("dependency damage unavailable")
				}
			}
			if input.VerifyFiles() == nil {
				t.Error("changed or missing prior command input survived the successor's immutable intake", damage)
			}
		})
	}
}

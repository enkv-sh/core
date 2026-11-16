package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	"enkv.sh/crypto/testsupport/custody"
	"enkv.sh/crypto/testsupport/installedarchive"
)

type freshFacts struct {
	Step            catalog.Step             `json:"step"`
	PhaseLimits     *liveLimits              `json:"phase_limits,omitempty"`
	DomainBasis     []byte                   `json:"domain_basis,omitempty"`
	CurrentBasis    *successionBasisInput    `json:"current_basis,omitempty"`
	Consumer        *successorConsumerInput  `json:"consumer,omitempty"`
	Receipts        []receiptExpectation     `json:"receipts,omitempty"`
	GeneratedRecord *generatedRecordInput    `json:"generated_record,omitempty"`
	GeneratedOutput string                   `json:"generated_output,omitempty"`
	Domain          contract.ID              `json:"domain"`
	Prefix          string                   `json:"prefix"`
	Expected        stateImage               `json:"expected"`
	ExpectedWork    []contract.SupportRecord `json:"expected_work,omitempty"`
	ExpectRefusal   bool                     `json:"expect_refusal"`
}

func readPrivateJSON(path string, value any) error {
	if records.ReadJSON(path, value) != nil {
		return errInventory
	}
	return nil
}

func liveProvider() string {
	return map[contract.Family]string{contract.GCP: "gcp", contract.AWS: "aws"}[liveFamily]
}

func loadLiveInput(inv records.Invocation, roles ...string) (liveRunInput, error) {
	var input liveRunInput
	// Decode the historical field separately so its presence (including null)
	// cannot act as current input. Retained cleanup keeps its original integer.
	wire := struct {
		*liveRunInput
		Members json.RawMessage `json:"member_count,omitempty"`
	}{liveRunInput: &input}
	if inv.Validate() != nil {
		return input, errInventory
	}
	allowed := false
	for _, role := range roles {
		allowed = allowed || inv.Role == role
	}
	if !allowed || readPrivateJSON(inv.Input, &wire) != nil {
		return input, errInventory
	}
	_, _, originalRunID, err := records.PrivateOwner(inv.StateDir)
	ownerMatches := originalRunID == input.RunID
	if input.OutputRecovery != nil {
		ownerMatches = publicOutputRecoveryIdentity(inv, input)
	}
	if err != nil || !ownerMatches || inv.Role != "cleanup" && input.RunID != inv.RunID || input.Settings.Provider != liveProvider() || input.Repetitions != 1 || len(input.Scenarios) != 1 || input.Scenarios[0] != inv.Scenario || !liveRecoveryAdmitted(input) {
		return input, errInventory
	}
	if !strings.HasPrefix(input.Prefix, "enkv-test/"+input.RunID+"/") || filepath.Clean(input.Prefix) != input.Prefix || strings.Contains(input.Prefix, `\`) {
		return input, errInventory
	}
	if _, current := catalog.Name(input.Scenarios[0]); current {
		if len(wire.Members) != 0 {
			return input, errInventory
		}
		if _, err := catalog.FixtureShape(input.Scenarios[0]); err != nil {
			return input, errInventory
		}
	} else {
		if inv.Role != "cleanup" || input.CleanupGrant == nil {
			return input, errInventory
		}
		if len(wire.Members) != 0 && json.Unmarshal(wire.Members, &input.MemberCount) != nil {
			return input, errInventory
		}
		if _, err := catalog.HistoricalFixtureShape(input.Scenarios[0], input.MemberCount); err != nil {
			return input, errInventory
		}
	}
	if input.Participants["authority"] == "" || inv.Role != "cleanup" && !liveActorsAdmitted(input) {
		return input, errInventory
	}
	if input.CleanupRetry != nil && (inv.Role != "cleanup" || input.Settings.Provider != "gcp" || input.Generator != nil ||
		input.CleanupRetry.Ordinal < 2 || input.CleanupRetry.Ordinal > 3 || input.CleanupRetry.TargetIndex > 1000000) {
		return input, errInventory
	}
	if input.StockRecovery != nil {
		body, err := json.Marshal(input.Limits)
		if inv.Role != "cleanup" || !stockPluginCase(input) || input.CleanupGrant != nil || input.CleanupRetry != nil ||
			input.StockRecovery.Validate(input.RunID, inv.RunID) != nil || err != nil || bodyDigest(body) != input.StockRecovery.CleanupLimitsSHA256 {
			return input, errInventory
		}
	}
	if input.CleanupGrant != nil {
		grant := input.CleanupGrant
		body, digestErr := json.Marshal(input.Limits)
		if inv.Role != "cleanup" || input.Settings.Provider != "gcp" && input.Settings.Provider != "aws" || input.Generator != nil || input.CleanupRetry != nil ||
			input.Settings.Provider == "aws" && (grant.Ordinal != 2 || !validInventoryDigest(grant.InventorySHA256)) ||
			grant.InventorySHA256 != "" && (grant.Ordinal != 2 || !validInventoryDigest(grant.InventorySHA256)) ||
			grant.TargetIndex > 1000000 || grant.Ordinal < 2 || grant.Ordinal > 4 ||
			grant.GrantRunID != inv.RunID || !records.ValidRunID(grant.GrantRunID) ||
			!validInventoryDigest(grant.OriginalCaseReceiptSHA256) ||
			!validInventoryDigest(grant.GrantLimitsSHA256) || digestErr != nil || bodyDigest(body) != grant.GrantLimitsSHA256 {
			return input, errInventory
		}
	}
	configurationRecovery := catalog.HasFixtureCapability(input.Scenarios[0], catalog.FixtureConfigurationRecovery)
	if (configurationRecovery && inv.Role == "writer") != (input.ConfigurationRecovery != nil) || input.ConfigurationRecovery != nil && (input.ConfigurationRecovery.Domain.IsZero() || !filepath.IsAbs(input.ConfigurationRecovery.OracleDirectory) || filepath.Clean(input.ConfigurationRecovery.OracleDirectory) != input.ConfigurationRecovery.OracleDirectory) {
		return input, errInventory
	}
	if input.ConfigurationRecovery != nil {
		row, ok := catalog.ConfigurationRecovery(input.Scenarios[0])
		if !ok || !input.ConfigurationRecovery.Locations.Valid(row.Condition, input.Prefix, input.ConfigurationRecovery.Domain) {
			return input, errInventory
		}
	}
	if livePublicationInput(inv, input) != nil {
		return input, errInventory
	}
	l := input.Limits
	if l.Requests == 0 || l.BodyBytes == 0 || l.Objects == 0 || l.ObjectBytes == 0 || l.GeneratorCreates == 0 || l.GeneratorRetires == 0 || l.ElapsedSeconds == 0 || l.ElapsedSeconds > 3600 || l.CleanupRequests == 0 || l.CleanupBytes == 0 || l.CleanupSeconds == 0 || l.CleanupSeconds > 3600 {
		return input, errInventory
	}
	return input, nil
}

func readLiveInvocation(t testing.TB, roles ...string) (testing.TB, records.Invocation, liveRunInput, *records.FailureRecorder) {
	t.Helper()
	path, present := os.LookupEnv("ENKV_TEST_INVOCATION")
	if !present {
		t.Skip("worker entry requires a coordinator invocation")
	}
	inv, err := records.LoadInvocation(path)
	if err != nil {
		t.Fatal("live invocation refused")
	}
	failure, err := records.NewFailureRecorder(inv)
	if err != nil {
		t.Fatal("live failure evidence owner refused")
	}
	t = assertionTB{TB: t, failure: failure}
	if inv.FailureSources == nil {
		t.Fatal("live assembly source mapping unavailable")
	}
	input, err := loadLiveInput(inv, roles...)
	if err != nil {
		t.Fatal("live input or worker role refused")
	}
	return t, inv, input, failure
}

func settingsBinding(settings liveSettings) string {
	settings.CredentialsFile, settings.Profile, settings.CredentialExpires = "", "", time.Time{}
	body, _ := json.Marshal(settings)
	return bodyDigest(body)
}

func liveReservation(b *runBudget) *records.BudgetReservation {
	snapshot := b.snapshot()
	return &records.BudgetReservation{Requests: snapshot.Requests, BodyBytes: snapshot.BodyBytes, Objects: snapshot.Objects, ObjectBytes: snapshot.ObjectBytes,
		GeneratorCreates: snapshot.GeneratorCreates, GeneratorRetires: snapshot.GeneratorRetires}
}

func liveBeginPhase(t testing.TB, worker *records.WorkerRecorder, phase string, expected bool) uint64 {
	t.Helper()
	sequence, err := worker.BeginPhase(phase, expected)
	if err != nil {
		t.Fatal("live phase record unavailable")
	}
	return sequence
}

func liveEndPhase(t testing.TB, worker *records.WorkerRecorder, sequence uint64, passed bool) {
	t.Helper()
	if worker.EndPhase(context.Background(), sequence, passed) != nil {
		t.Fatal("live phase record unavailable")
	}
}

func finishLiveWorker(t testing.TB, worker *records.WorkerRecorder, budget *runBudget) {
	t.Helper()
	worker.Result.BudgetReserved = liveReservation(budget)
	if worker.Result.Cleanup != nil {
		worker.Result.Cleanup.BudgetReserved = liveReservation(budget)
		if t.Failed() {
			worker.Result.Cleanup.Outcome = "unresolved"
			worker.Result.Cleanup.Failure = &records.Failure{Class: "cleanup_unresolved", Stage: "cleanup"}
		}
	}
	if worker.Finish(context.Background(), !t.Failed()) != nil {
		t.Error("live worker record unavailable")
	}
}

func liveHarnessFailure(err error, operation, stage, cause, effect string) records.HarnessFailure {
	fact := records.HarnessFailure{Operation: operation, Stage: stage, Cause: cause, Effect: effect}
	var safe interface{ SafeHarnessFailure() records.HarnessFailure }
	if errors.As(err, &safe) {
		observed := safe.SafeHarnessFailure()
		if observed.Operation == operation && observed.Validate() {
			return observed
		}
	}
	return fact
}

func writeNewLiveJSON(path string, value any) error {
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errInventory
	}
	return records.WriteJSON(path, value, 0o400)
}

// The descriptor is durable before launch. Every reader owns distinct output;
// the writer keeps all descriptors and only replaces the latest after-exit facts.
func prepareFreshChild(inv records.Invocation, worker *records.WorkerRecorder, facts freshFacts) (string, error) {
	index := len(worker.Result.Children)
	execution, known := catalog.ExecutionFor(worker.Result.Scenario, "live")
	if !known {
		return "", errInventory
	}
	children := execution.ExpandedFreshBefore()
	if index >= len(children) || len(inv.FreshBefore) != len(children) {
		return "", errInventory
	}
	facts.Step = children[index].Step
	childInputPath := inv.Input
	var err error
	if execution.HasFixtureCapability(catalog.FixtureGeneratedProcess) || execution.HasFixtureCapability(catalog.FixturePublication) {
		var childInput liveRunInput
		if readPrivateJSON(inv.Input, &childInput) != nil || execution.HasFixtureCapability(catalog.FixtureGeneratedProcess) && childInput.Generator == nil || execution.HasFixtureCapability(catalog.FixturePublication) && childInput.Outputs == nil {
			return "", errInventory
		}
		var isolated map[string]json.RawMessage
		if readPrivateJSON(inv.Input, &isolated) != nil {
			return "", errInventory
		}
		delete(isolated, "generator")
		delete(isolated, "generator_cleanup_ledger")
		delete(isolated, "configuration_recovery")
		delete(isolated, "outputs")
		childInputPath, err = records.SafePath(inv.StateDir, fmt.Sprintf("fresh-input-%d.json", index))
		if err != nil || writeNewLiveJSON(childInputPath, isolated) != nil {
			return "", errInventory
		}
	}
	name := fmt.Sprintf("fresh-%d.json", index)
	path, err := records.SafePath(inv.StateDir, name)
	if err != nil || writeNewLiveJSON(path, facts) != nil {
		return "", errInventory
	}
	output, err := records.SafePath(inv.OutputDir, fmt.Sprintf("fresh-before-%d", index))
	if err != nil || os.Mkdir(output, 0o700) != nil {
		return "", errInventory
	}
	child := records.Invocation{SchemaVersion: records.SchemaVersion, RunID: inv.RunID, Scenario: inv.Scenario, Nonce: inv.FreshBefore[index].Nonce, FailureSources: inv.FailureSources,
		TelemetrySettings: inv.TelemetrySettings,
		Worker:            inv.FreshBefore[index].Worker, Role: "fresh_before",
		Input: childInputPath, StateDir: inv.StateDir, OutputDir: output, Facts: name}
	path, err = records.SafePath(output, "invocation.json")
	if err != nil || child.Validate() != nil || writeNewLiveJSON(path, child) != nil {
		return "", errInventory
	}
	owner, _, ownerID, err := records.PrivateOwner(inv.OutputDir)
	if err != nil || ownerID != inv.RunID {
		return "", errInventory
	}
	relative, err := filepath.Rel(owner, path)
	if err != nil {
		return "", errInventory
	}
	worker.Result.Children = append(worker.Result.Children, records.ChildInvocation{Worker: child.Worker, Invocation: relative})
	worker.Result.FreshChecks = []records.FreshCheck{{Facts: name}}
	if worker.Save() != nil {
		return "", errInventory
	}
	return path, nil
}

func executeFreshChild(ctx context.Context, binary, path string) (records.WorkerResult, *records.FreshChildProcess, error) {
	var result records.WorkerResult
	inv, err := records.LoadInvocation(path)
	if err != nil || inv.Role != "fresh_before" {
		return result, nil, errors.New("fresh process invocation refused")
	}
	resultPath, err := records.SafePath(inv.OutputDir, "worker.json")
	telemetryPath, telemetryErr := records.SafePath(inv.OutputDir, "telemetry.json")
	if err != nil || telemetryErr != nil {
		return result, nil, errors.New("fresh process output refused")
	}
	for _, output := range []string{resultPath, telemetryPath, filepath.Join(inv.OutputDir, "failure.json"), filepath.Join(inv.OutputDir, "checkpoint.json")} {
		if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
			return result, nil, errors.New("fresh process output already exists")
		}
	}
	command := exec.CommandContext(ctx, binary, "-test.run=^TestLiveChild$", "-test.timeout=1h")
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "ENKV_TEST_INVOCATION=") {
			command.Env = append(command.Env, value)
		}
	}
	command.Env = append(command.Env, "ENKV_TEST_INVOCATION="+path)
	// Inherit the writer's process group so the coordinator can join both.
	runErr := command.Run()
	process := records.ObserveFreshChildProcess(command, runErr)
	result, err = readFreshChildResult(inv, runErr)
	return result, &process, err
}

func readFreshChildResult(inv records.Invocation, runErr error) (records.WorkerResult, error) {
	var result records.WorkerResult
	resultPath, pathErr := records.SafePath(inv.OutputDir, "worker.json")
	if pathErr != nil {
		return result, errors.New("fresh process output refused")
	}
	resultErr := readPrivateJSON(resultPath, &result)
	assertions := records.InspectAssertions(inv, runErr == nil || result.Outcome == "passed")
	if resultErr != nil || result.SchemaVersion != records.SchemaVersion || result.RunID != inv.RunID || result.Worker != inv.Worker || result.Role != inv.Role || result.Scenario != inv.Scenario {
		return records.WorkerResult{Assertions: &assertions}, errors.New("fresh process evidence unavailable")
	}
	result.Assertions = &assertions
	if runErr != nil || result.Outcome != "passed" || !assertions.PermitsSuccess() {
		return result, errors.New("fresh process verification failed")
	}
	return result, nil
}

// full_only: false
func TestLiveRun(t *testing.T) {
	handle, inv, input, failure := readLiveInvocation(t, "writer")
	runLiveRun(handle, inv, input, failure)
}

func runLiveRun(t testing.TB, inv records.Invocation, input liveRunInput, failure *records.FailureRecorder) {
	if catalog.HasFixtureCapability(input.Scenarios[0], catalog.FixturePublicConfiguration) {
		if stockPluginCase(input) {
			runStockPluginAcceptance(t, inv, input, failure)
			return
		}
		runPublicConfiguration(t, inv, input, failure)
		return
	}
	worker, err := records.NewWorker(inv, liveProvider(), input.Scenarios[0], failure)
	if err != nil {
		t.Fatal("live worker output refused")
	}
	worker.Result.Actor = input.Participants["authority"]
	budget := &runBudget{limits: input.Limits, keys: make(map[string]bool)}
	defer finishLiveWorker(t, worker, budget)
	lease, err := lockInventory(inv.StateDir)
	if err != nil {
		t.Fatal("object inventory is in use or unavailable")
	}
	defer lease.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(input.Limits.ElapsedSeconds)*time.Second)
	defer cancel()
	ctx = worker.Context(ctx)
	ids, err := allocateGenesisIDs(nil)
	if err != nil {
		t.Fatal("genesis identity allocation failed", err)
	}
	if input.ConfigurationRecovery != nil {
		if input.ConfigurationRecovery.Domain.IsZero() || !catalog.HasFixtureCapability(input.Scenarios[0], catalog.FixtureConfigurationRecovery) {
			t.Fatal("recovery setup Domain refused")
		}
		ids.Domain = input.ConfigurationRecovery.Domain
	}
	if input.Outputs != nil {
		body, err := hex.DecodeString(input.Outputs.Scope.DomainID)
		if err != nil || len(body) != len(ids.Domain) || input.ConfigurationRecovery != nil {
			t.Fatal("publication setup Domain refused")
		}
		copy(ids.Domain[:], body)
	}
	domain := ids.Domain
	inventoryPath, err := records.SafePath(inv.StateDir, "inventory.json")
	if err != nil {
		t.Fatal("inventory path refused")
	}
	if _, err := os.Lstat(inventoryPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("existing inventory cannot resume transitions")
	}
	inventory := &objectInventory{path: inventoryPath, image: inventoryImage{Version: 1, RunID: input.RunID, Binding: settingsBinding(input.Settings), Prefix: input.Prefix, Domain: domain, Deleted: make(map[string]int)}}
	if inventory.save() != nil {
		t.Fatal("initial inventory could not be saved")
	}
	defer inventory.stop()
	sequence := liveBeginPhase(t, worker, "authentication", true)
	backend, err := openLiveBackend(ctx, input.Settings, input.Prefix, domain)
	var keys *custody.Fixture
	var recovery contract.QualifyingTrust
	if err == nil {
		keys, recovery, err = openLiveCustody(t, ctx, input, domain, budget)
	}
	liveEndPhase(t, worker, sequence, err == nil)
	if err != nil {
		t.Fatal("credential or provider construction refused")
	}
	if err := liveCheckRunResources(ctx, worker, backend, budget); err != nil {
		t.Fatal("test resource or operator prefix admission failed")
	}
	if input.ConfigurationRecovery != nil && input.ConfigurationRecovery.Locations != (installedarchive.RecoveryLocations{}) {
		locations := input.ConfigurationRecovery.Locations
		inventory.image.RecoveryLocations = &locations
		if inventory.save() != nil {
			t.Fatal("recovery locations ledger unavailable")
		}
	}
	backend, err = liveRecoveryLocationBackend(input, inventory.image, backend, func(ctx context.Context, prefix string, domain contract.ID) (*liveBackend, error) {
		return openLiveBackend(ctx, input.Settings, prefix, domain)
	})
	if err != nil {
		t.Fatal("recovery recorded location admission refused")
	}
	var storeBackend contract.Store = backend.Store
	var beforeSend *beforeSendRecoveryStore
	if input.Scenarios[0] == beforeSendRecoveryScenario {
		beforeSend = &beforeSendRecoveryStore{Store: backend.Store}
		storeBackend = beforeSend
	}
	store := recordedStore{Store: storeBackend, inventory: inventory, budget: budget}
	execution, known := catalog.ExecutionFor(input.Scenarios[0], "live")
	if !known {
		t.Fatal("live execution facts unavailable")
	}
	steps := execution.WriterSteps()
	stepIndex := 0
	var readerKeys *custody.Fixture
	var env fixtureEnvironment
	env = fixtureEnvironment{
		GenesisIDs: ids,
		Store:      store, Trust: budgetTrust{Trust: backend.Trust, budget: budget}, Domain: domain, PublicKey: backend.PublicKey,
		ControlDelayedCAS: input.Scenarios[0] == "selection.concurrent-writers-select-one-complete-state/members_32_two_writers",
		SigningSelector:   input.Settings.KeyID, Bindings: keys.Bindings(), Crypto: keys.Crypto(), Custody: keys, AdmitInit: keys.AdmitInit, RetireInit: keys.RetireInit, ReserveCustody: budget.reserveCustody, Recovery: recovery, RecoverySelector: input.Settings.RecoveryKeyID,
		ReaderConsume: func(selection contract.ConsumerSelection, choice uint8) custody.ConsumerCheck {
			if readerKeys == nil {
				var err error
				readerKeys, _, err = openLiveReaderCustody(t, ctx, input, domain, budget, "reader")
				if err != nil {
					t.Fatal("independent reader custody construction refused")
				}
			}
			return readerKeys.Consume(ctx, selection, choice)
		},
		Put: func(ctx context.Context, key string, body []byte) error {
			if !budget.reserve(2, operationBodyAllowance, key, uint64(len(body))) {
				return errRunLimit
			}
			result := inventory.write(ctx, key, body, "fixture_create", func() contract.WriteResult { return backend.Put(ctx, key, body) })
			if result.Status != contract.WriteAcknowledged {
				return errInventory
			}
			return nil
		},
		Delete: func(ctx context.Context, key string) error {
			owned, err := inventory.owned(false)
			if err != nil || len(owned[key]) == 0 || !budget.reserve(6, 3*operationBodyAllowance, "", 0) {
				return errInventory
			}
			return inventory.remove(ctx, backend.Store, backend.Delete, key, owned[key])
		},
		Phase: func(name string) {
			if stepIndex >= len(steps) || steps[stepIndex].Name != name {
				t.Fatal("live action differs from the scenario plan")
			}
			step := steps[stepIndex]
			stepIndex++
			var err error
			sequence, err = worker.BeginStep(step, input.Participants[step.Role])
			if err != nil {
				t.Fatal("live scenario phase record unavailable")
			}
		},
		EndPhase: func(string) {
			worker.Result.BudgetReserved = liveReservation(budget)
			liveEndPhase(t, worker, sequence, !t.Failed())
		},
		FreshCurrent: func(t testing.TB, admitted OpenContext, session *StateSession) {
			facts := freshFacts{DomainBasis: bytes.Clone(admitted.admission.descriptor), Domain: domain, Prefix: input.Prefix, Expected: sessionStateImage(t, session), Receipts: freshReceiptExpectations(t, session)}
			if execution.HasFixtureCapability(catalog.FixtureReaderSuccessor) {
				facts.Consumer = &successorConsumerInput{Binding: liveReaderSuccessor(t, input, domain), Name: "secret", Value: custody.StandardValue}
			}
			runLiveFreshCheck(t, ctx, inv, input, worker, budget, sequence, facts)
		},
	}
	if recovery != nil {
		env.RecoveryPublicKey, err = livePublicDER(input.Settings.RecoveryPublicKeyPEM)
		if err != nil {
			t.Fatal("configured recovery public key refused")
		}
	}
	if execution.HasFixtureCapability(catalog.FixtureGeneratedProcess) {
		generatedFailures := newGeneratedFailureTracker(failure)
		env.GeneratedProcess = liveGeneratedProcessFixture(t, input, budget)
		env.GeneratedProcess.ObserveOutcome = generatedFailures.observe
		env.GeneratedProcess.SelectFailure = generatedFailures.selectFailure
		env.FreshCurrent = func(t testing.TB, admitted OpenContext, session *StateSession) {
			facts := liveGeneratedFreshFacts(t, admitted, session, domain, input.Prefix)
			runLiveFreshCheck(t, ctx, inv, input, worker, budget, sequence, facts)
		}
		env.FreshGeneratedRecord = func(t testing.TB, selected *StateSession, attempt contract.ID, packet []byte) *StateSession {
			return runLiveGeneratedRecordCheck(t, ctx, inv, input, worker, budget, inventory, env, selected, attempt, packet)
		}
	}
	if execution.HasFixtureCapability(catalog.FixtureSyntheticAuthority) {
		env.ReplacementActors = func(t testing.TB, ctx context.Context, before *StateSession, _, mask, approval uint8) successionActors {
			keys.CloseRoutes()
			return liveSuccessionActors(t, ctx, input, budget, inventory, before, mask, approval)
		}
		env.CurrentConsume = func(t testing.TB, ctx context.Context, session *StateSession, selection contract.ConsumerSelection, value uint8) custody.ConsumerCheck {
			return liveCurrentConsumer(t, ctx, input, budget, session, selection, value)
		}
		env.PrivateWitness = func(t testing.TB, session *StateSession, choice uint8) {
			liveCurrentPrivateWitness(t, ctx, input, budget, session, choice)
		}
		env.FreshCurrent = func(t testing.TB, admitted OpenContext, session *StateSession) {
			basis := successionBasisTransport(admitted.admission.current)
			facts := freshFacts{CurrentBasis: &basis, Domain: domain, Prefix: input.Prefix, Expected: sessionStateImage(t, session), Receipts: freshReceiptExpectations(t, session)}
			if session.root.SecretCount != 0 {
				facts.Consumer = &successorConsumerInput{Binding: contract.BindingTableRow{SubjectKind: 1, SubjectID: admitted.admission.recipient, Binding: *session.recipientRecord(admitted.admission.recipient).CurrentBinding}, Name: "secret", Value: custody.StandardValue}
			}
			runLiveFreshCheck(t, ctx, inv, input, worker, budget, sequence, facts)
		}
	}
	if execution.HasFixtureCapability(catalog.FixtureReaderSuccessor) {
		successor := liveReaderSuccessor(t, input, domain)
		if err := keys.InstallRecipientSuccessor(successor, liveCredentialRoute(input, "authority"), contract.ID{}); err != nil {
			t.Fatal("reader public successor route refused", err)
		}
		env.ReaderSuccessor = successor.Binding
		env.ReaderSuccessorConsume = func(selection contract.ConsumerSelection, value uint8) custody.ConsumerCheck {
			session, result := Open(ctx, fixtureAdmission(env), env.Store)
			if session == nil {
				t.Fatal("selected reader state unavailable", result)
			}
			return liveCurrentConsumer(t, ctx, input, budget, session, selection, value)
		}
	}
	if execution.HasFixtureCapability(catalog.FixturePublication) {
		env.LivePublication = func(t testing.TB, ctx context.Context, env fixtureEnvironment, name string) {
			runLivePublicationScenario(t, ctx, env, name, input.Outputs, budget)
		}
		env.FreshCurrent = func(t testing.TB, admitted OpenContext, session *StateSession) {
			work, err := session.workSupportRecords(ctx)
			if err != nil || len(work) == 0 {
				t.Fatal("publication fresh support evidence unavailable")
			}
			facts := freshFacts{DomainBasis: bytes.Clone(admitted.admission.descriptor), Domain: domain, Prefix: input.Prefix, Expected: sessionStateImage(t, session), Receipts: freshReceiptExpectations(t, session), ExpectedWork: work}
			runLiveFreshCheck(t, ctx, inv, input, worker, budget, sequence, facts)
		}
	}
	if execution.HasFixtureCapability(catalog.FixtureConfigurationRecovery) {
		env.ConfigurationRecovery = func(t testing.TB, ctx context.Context, env fixtureEnvironment, name string) {
			runLiveConfigurationRecoveryWriter(t, ctx, env, name, inv.StateDir, input, inventory, budget)
		}
	}
	env.Context = ctx
	if beforeSend != nil {
		env.RecoveryHandoff = func(_ *StateSession, desired []ApplyEntryInput) error {
			return saveRecoveryHandoff(inv, input, env, desired)
		}
		env.InjectBeforeSend = func() { beforeSend.active.Store(true) }
		env.ReportTransportFailure = func(result Result) {
			if result.Outcome != EvidenceUnavailable || result.Reason != WriteUncertain || result.StoreReason != contract.ReasonTransport || result.CommitMayHaveOccurred {
				t.Fatal("writer failure is not eligible for recovery")
			}
			worker.Result.Failure = &records.Failure{Class: "store_transport_exhausted", Stage: "transition"}
			worker.Result.StoreFailure = &records.StoreFailure{StoreReason: "transport", Outcome: "evidence-unavailable", Reason: "write-uncertain"}
			if worker.Save() != nil {
				t.Fatal("typed transport evidence unavailable")
			}
		}
	}
	runStateScenario(t, ctx, env, input.Scenarios[0])
	if execution.HasFixtureCapability(catalog.FixtureConfigurationRecovery) {
		worker.Result.FreshChecks = nil
	}
	if budget.exhausted || ctx.Err() != nil {
		t.Fatal("run budget or deadline exhausted")
	}
	if execution.HasFixtureCapability(catalog.FixtureSelectedStateDamage) {
		if !budget.admitFreshReads(maximumFreshRefusalReads, 1) {
			t.Fatal("fresh refusal budget exhausted")
		}
		name := "fresh-refusal.json"
		path, err := records.SafePath(inv.StateDir, name)
		if err != nil || writeNewLiveJSON(path, freshFacts{DomainBasis: bytes.Clone(fixtureAdmission(env).admission.descriptor), Domain: domain, Prefix: input.Prefix, ExpectRefusal: true}) != nil {
			t.Fatal("fresh refusal input could not be saved")
		}
		worker.Result.FreshChecks = []records.FreshCheck{{Facts: name}}
	}
}

// full_only: false
func TestLiveChild(t *testing.T) {
	handle, inv, input, failure := readLiveInvocation(t, "fresh_before", "fresh_after")
	runLiveChild(handle, inv, input, failure)
}

func runLiveChild(t testing.TB, inv records.Invocation, input liveRunInput, failure *records.FailureRecorder) {
	if catalog.HasFixtureCapability(input.Scenarios[0], catalog.FixturePublicConfiguration) {
		if stockPluginCase(input) {
			runStockPluginAcceptanceFresh(t, inv, input, failure)
			return
		}
		runPublicConfigurationFresh(t, inv, input, failure)
		return
	}
	worker, err := records.NewWorker(inv, liveProvider(), input.Scenarios[0], failure)
	if err != nil {
		t.Fatal("fresh process output refused")
	}
	budget := &runBudget{keys: make(map[string]bool)}
	defer finishLiveWorker(t, worker, budget)
	var facts freshFacts
	path, err := records.SafePath(inv.StateDir, inv.Facts)
	execution, known := catalog.ExecutionFor(input.Scenarios[0], "live")
	if !known {
		t.Fatal("fresh live execution facts unavailable")
	}
	if execution.HasFixtureCapability(catalog.FixtureGeneratedProcess) && (input.Generator != nil || input.GeneratorCleanupLedger != "") {
		t.Fatal("fresh generated child retained provider credential route")
	}
	damaged := execution.HasFixtureCapability(catalog.FixtureSelectedStateDamage)
	if err != nil || readPrivateJSON(path, &facts) != nil || facts.Prefix != input.Prefix || facts.Domain.IsZero() || facts.ExpectRefusal != damaged {
		t.Fatal("fresh process facts refused")
	}
	inventoryPath, err := records.SafePath(inv.StateDir, "inventory.json")
	var inventory inventoryImage
	descriptor, descriptorErr := contract.DecodeGenesisDescriptorCore(facts.DomainBasis)
	var current contract.ControlCore
	currentOK := false
	if facts.CurrentBasis != nil {
		current, currentOK = liveCurrentPublicBasis(input, facts.Domain, facts.CurrentBasis)
	}
	basisOK := facts.CurrentBasis == nil && descriptorErr == nil && descriptor.DomainID == facts.Domain && liveDomainPublicBindings(input.Settings, descriptor) || len(facts.DomainBasis) == 0 && currentOK
	if err != nil || readPrivateJSON(inventoryPath, &inventory) != nil || inventory.RunID != input.RunID || inventory.Prefix != input.Prefix || inventory.Domain != facts.Domain || inventory.Binding != settingsBinding(input.Settings) || !basisOK {
		t.Fatal("fresh domain basis differs from retained admission")
	}
	if inv.Role == "fresh_after" || facts.Step.Name == "" {
		after := execution.ExpandedFreshAfter()
		if len(after) == 0 {
			t.Fatal("fresh after-exit purpose is outside the catalog")
		}
		if facts.Step.Name == "" {
			facts.Step = after[0].Step
		}
		if inv.Role == "fresh_after" && facts.Step != after[0].Step {
			t.Fatal("after-exit facts cannot resume a phase")
		}
	}
	if inv.Role == "fresh_before" && !slices.ContainsFunc(execution.ExpandedFreshBefore(), func(child catalog.FreshChild) bool { return child.Step == facts.Step }) {
		t.Fatal("fresh child purpose or role is outside the catalog")
	}
	worker.Result.Actor = input.Participants[facts.Step.Role]
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(input.Limits.ElapsedSeconds)*time.Second)
	defer cancel()
	ctx = worker.Context(ctx)
	sequence := liveBeginPhase(t, worker, "authentication", true)
	settings := liveRoleSettings(input, facts.Step.Role)
	if settings == nil {
		t.Fatal("fresh exact role settings missing")
	}
	backend, err := openLiveBackend(ctx, *settings, facts.Prefix, facts.Domain)
	liveEndPhase(t, worker, sequence, err == nil)
	if err != nil {
		t.Fatal("fresh process authentication or construction refused")
	}
	if facts.GeneratedRecord != nil {
		runLiveGeneratedRecordChild(t, ctx, inv, input, worker, budget, backend, inventoryPath, inventory, facts, execution)
		return
	}
	reads, validReads := freshSelectedReadAllowance(facts.Expected)
	if facts.ExpectRefusal {
		reads, validReads = maximumFreshRefusalReads, true
	}
	extra := uint64(0)
	if execution.HasFixtureCapability(catalog.FixtureSecretState) || facts.Consumer != nil {
		extra = 1
	}
	if len(facts.Receipts) > 2*contract.MutationReceiptWindowLimit || !validReads {
		t.Fatal("fresh process read shape exceeds its bound")
	}
	reads += freshReceiptReadCount(facts.Receipts)
	reservation, validReservation := freshReadReservation(reads+extra, 1)
	if !validReservation || reservation.Requests > input.Limits.Requests || reservation.BodyBytes > input.Limits.BodyBytes {
		t.Fatal("fresh process read budget refused")
	}
	budget.limits = liveLimits{Requests: reservation.Requests, BodyBytes: reservation.BodyBytes}
	env := fixtureEnvironment{GenesisIDs: genesisIDs{Init: descriptor.InitID, Domain: descriptor.DomainID, DescriptorArtifact: descriptor.DescriptorArtifactID, ManifestArtifact: descriptor.ManifestArtifactID}, Store: liveReadOnlyStore{Store: recordedStore{Store: backend.Store, budget: budget}, t: t}, Trust: liveReadOnlyTrust{Trust: backend.Trust, t: t}, Domain: facts.Domain, PublicKey: backend.PublicKey}
	expected := facts.Step.Expected
	sequence, err = worker.BeginStep(facts.Step, worker.Result.Actor)
	if err != nil {
		t.Fatal("fresh process phase record unavailable")
	}
	if facts.CurrentBasis == nil && (descriptor.NormalSigning.KeySelector != input.Settings.KeyID || !bytes.Equal(descriptor.NormalSigning.SPKI, backend.PublicKey)) {
		t.Fatal("fresh public signer differs from domain basis")
	}
	admission := liveFreshAdmission(facts, current, backend)
	session, result := Open(ctx, admission, env.Store)
	actual := readerReadOutcome(result, backend.AccessRefused != nil && backend.AccessRefused())
	if session != nil && facts.Consumer != nil {
		selection := sessionConsumerSelection(t, session, facts.Consumer.Binding.SubjectID, facts.Consumer.Name)
		if !kmsBindingEqual(selection.Binding.Binding, facts.Consumer.Binding.Binding) || livePrivateKeyRole(input.Settings, facts.Consumer.Binding) != facts.Step.Role {
			t.Fatal("fresh consumer differs from exact current role")
		}
		check := liveCurrentConsumer(t, ctx, input, budget, session, selection, facts.Consumer.Value)
		actual = firstFlowConsumerOutcome(check, selection, false)
	} else if session != nil && execution.HasFixtureCapability(catalog.FixtureSecretConsumption) {
		keys, _, err := openLiveReaderCustody(t, ctx, input, facts.Domain, budget, facts.Step.Role)
		if err != nil {
			t.Fatal("fresh private reader construction refused")
		}
		recipient := fixtureID(facts.Domain, "recipient")
		if facts.Step.Role != "authority" {
			recipient = fixtureID(facts.Domain, "reader")
		}
		selection := sessionConsumerSelection(t, session, recipient, "secret")
		if !budget.reserveCustody("consume", 1) {
			t.Fatal("fresh consumer budget exhausted")
		}
		actual = firstFlowConsumerOutcome(keys.Consume(ctx, selection, custody.StandardValue), selection, execution.HasFixtureCapability(catalog.FixtureSecretRefusal))
	}
	if session != nil {
		beforeReceipts := budget.snapshot()
		beforeTransport := budget.transportFailures()
		checkFreshReceipts(t, ctx, session, facts.Receipts)
		afterReceipts := budget.snapshot()
		transportFailures := budget.transportFailures() - beforeTransport
		reads := freshReceiptReadCount(facts.Receipts)
		if afterReceipts.Requests-beforeReceipts.Requests != 2*(reads+transportFailures) || afterReceipts.BodyBytes-beforeReceipts.BodyBytes != (reads+transportFailures)*operationBodyAllowance || afterReceipts.Objects != beforeReceipts.Objects || afterReceipts.ObjectBytes != beforeReceipts.ObjectBytes {
			t.Fatal("fresh receipt queries exceeded their exact current reads")
		}
	}
	if worker.ObservePhase(sequence, actual) != nil {
		t.Fatal("fresh process observation could not be saved")
	}
	liveEndPhase(t, worker, sequence, actual == expected && !budget.exhausted && ctx.Err() == nil)
	sequence = liveBeginPhase(t, worker, "verification", false)
	defer func() { liveEndPhase(t, worker, sequence, !t.Failed()) }()
	if expected == "access-refused" {
		if session != nil || actual != "access-refused" {
			t.Fatal("fresh reader did not produce exact access refusal")
		}
	} else if facts.ExpectRefusal {
		want := EvidenceUnavailable
		if expected == "integrity-failure" {
			want = IntegrityFailure
		}
		if session != nil || result.Outcome != want || (want == EvidenceUnavailable && result.Reason != MissingSelectedObject) {
			t.Fatal("damaged state did not refuse in fresh process")
		}
	} else {
		if session == nil || result.Outcome != ObservedCurrent || result.Evidence != AuthenticatedClosure {
			t.Fatal("fresh state open refused")
		}
		assertStateImage(t, session, facts.Expected)
		if execution.HasFixtureCapability(catalog.FixturePublication) {
			before := budget.snapshot()
			work, err := session.workSupportRecords(ctx)
			if err != nil || facts.ExpectedWork == nil || !reflect.DeepEqual(work, facts.ExpectedWork) || budget.snapshot() != before {
				t.Fatal("fresh publication records changed or caused new provider work")
			}
		}
	}
	if budget.exhausted || ctx.Err() != nil {
		t.Fatal("fresh process budget or deadline exhausted")
	}
}

func liveFreshAdmission(facts freshFacts, current contract.ControlCore, backend *liveBackend) OpenContext {
	if facts.CurrentBasis == nil {
		return processPublicAdmission(facts.Domain, backend.Trust.Identity(), backend.Store.Descriptor(), backend.PublicKey, facts.DomainBasis)
	}
	admission := processPublicAdmission(facts.Domain, current.NormalSigning.Binding.Trust, backend.Store.Descriptor(), current.NormalSigning.SPKI, nil)
	admission.admission.current, admission.admission.epoch = facts.CurrentBasis.owned(), current.NormalSigning.Binding.Epoch
	return admission
}

type liveReadOnlyStore struct {
	contract.Store
	t testing.TB
}

func (s liveReadOnlyStore) StoreConfiguration() contract.StoreConfiguration {
	return fixtureStoreConfiguration(s.Store)
}

func (s liveReadOnlyStore) CreateHead(context.Context, contract.HeadCreateRequest) contract.WriteResult {
	s.t.Error("fresh reader attempted a write")
	return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonProof}
}

func (s liveReadOnlyStore) Create(context.Context, string, []byte) contract.WriteResult {
	s.t.Error("fresh reader attempted a write")
	return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonProof}
}

func (s liveReadOnlyStore) CompareAndSwap(context.Context, string, contract.Token, []byte) contract.WriteResult {
	s.t.Error("fresh reader attempted a write")
	return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonProof}
}

type liveReadOnlyTrust struct {
	contract.Trust
	t testing.TB
}

func (s liveReadOnlyTrust) Sign(context.Context, contract.SignRequest) contract.SignResult {
	s.t.Error("fresh reader attempted signing")
	return contract.SignResult{Reason: contract.ReasonProof}
}

// full_only: false
func TestLiveCleanup(t *testing.T) {
	handle, inv, input, failure := readLiveInvocation(t, "cleanup")
	runLiveCleanup(handle, inv, input, failure)
}

type liveCleanupOutputFacts struct {
	accounted bool
	summary   livePublicationCleanupSummary
	err       error
}

func finishLiveCleanup(t testing.TB, worker *records.WorkerRecorder, budget *runBudget, output liveCleanupOutputFacts) {
	t.Helper()
	// A zero summary before complete admission is unavailable evidence.
	// Qualified output counts add to the final independent Store/generator
	// counts, including early failure and the no-Store-owned path.
	known := output.accounted && (output.err == nil || output.summary.Attempted != 0 || output.summary.Remaining != 0 || output.summary.Unknown != 0 || output.summary.Scheduled != 0)
	if !known {
		worker.Result.Cleanup.RemainingOwnedObjects = nil
		worker.Result.Cleanup.UnknownEffects = nil
	} else {
		if worker.Result.Cleanup.RemainingOwnedObjects != nil {
			*worker.Result.Cleanup.RemainingOwnedObjects += int64(output.summary.Remaining)
		}
		if worker.Result.Cleanup.UnknownEffects != nil {
			*worker.Result.Cleanup.UnknownEffects += int64(output.summary.Unknown)
		}
	}
	if output.err != nil {
		fact := records.HarnessFailure{Operation: "setup_check", Stage: "ownership_check", Cause: "evidence_unavailable", Effect: "no_send"}
		var safe livePublicationCleanupFailure
		if errors.As(output.err, &safe) && safe.fact.Validate() {
			fact = safe.fact
		}
		worker.Result.HarnessFailure, worker.Result.Cleanup.HarnessFailure = &fact, &fact
	}
	finishLiveWorker(t, worker, budget)
}

func runLiveCleanup(t testing.TB, inv records.Invocation, input liveRunInput, failure *records.FailureRecorder) {
	if catalog.HasFixtureCapability(input.Scenarios[0], catalog.FixturePublicConfiguration) {
		if stockPluginCase(input) {
			runStockPluginAcceptanceCleanup(t, inv, input, failure)
			return
		}
		runPublicConfigurationCleanup(t, inv, input, failure)
		return
	}
	worker, err := records.NewWorker(inv, liveProvider(), input.Scenarios[0], failure)
	if err != nil {
		t.Fatal("cleanup output refused")
	}
	worker.Result.Actor = input.Participants["authority"]
	worker.Result.Cleanup = &records.Cleanup{Outcome: "unresolved"}
	limits := input.Limits
	limits.Requests, limits.BodyBytes = limits.CleanupRequests, limits.CleanupBytes
	limits.GeneratorCreates = 0
	budget := &runBudget{limits: limits, keys: make(map[string]bool)}
	outputFacts := liveCleanupOutputFacts{accounted: input.Outputs == nil}
	// Fatal uses Goexit, so final output accounting and worker publication
	// share one outer completion bridge on every exit.
	defer func() { finishLiveCleanup(t, worker, budget, outputFacts) }()
	lease, err := lockInventory(inv.StateDir)
	if err != nil {
		t.Fatal("object inventory is in use or unavailable")
	}
	defer lease.Close()
	path, err := records.SafePath(inv.StateDir, "inventory.json")
	if err != nil {
		t.Fatal("cleanup inventory path refused")
	}
	inventory := &objectInventory{path: path, stopped: true}
	if input.CleanupGrant != nil && (input.Settings.Provider == "aws" || input.CleanupGrant.InventorySHA256 != "") {
		if err := admitFixtureCleanupClaim(inv, input, inventory.path); err != nil {
			fact := liveHarnessFailure(err, "object_cleanup", "ownership_check", "evidence_unavailable", "no_send")
			worker.Result.HarnessFailure, worker.Result.Cleanup.HarnessFailure = &fact, &fact
			t.Fatal("cleanup grant or inventory changed")
		}
	}
	if readPrivateJSON(inventory.path, &inventory.image) != nil || inventory.image.Version != 1 || inventory.image.RunID != input.RunID || inventory.image.Prefix != input.Prefix || inventory.image.Domain.IsZero() || inventory.image.Binding != settingsBinding(input.Settings) {
		t.Fatal("cleanup inventory refused")
	}
	owned, ownedErr := inventory.owned(true)
	unknownEffects, err := inventory.image.unknownEffects()
	if err != nil {
		t.Fatal("cleanup inventory shape refused")
	}
	var generatorOwned, generatorPendingCreates int64
	if input.Generator != nil {
		ledger, ledgerErr := records.ReadGeneratorFixtureLedger(input.GeneratorCleanupLedger, input.RunID, input.Generator.Account)
		if ledgerErr != nil {
			t.Fatal("Cloudflare cleanup ledger unavailable")
		}
		generatorOwned = int64(len(ledger.CleanupTargets()))
		generatorPendingCreates = int64(len(ledger.PendingCreates))
		unknownEffects += generatorPendingCreates
	}
	worker.Result.Cleanup.UnknownEffects = &unknownEffects
	remainingCount := int64(len(owned)) + generatorOwned
	worker.Result.Cleanup.RemainingOwnedObjects = &remainingCount
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(input.Limits.CleanupSeconds)*time.Second)
	defer cancel()
	ctx = worker.Context(ctx)
	var backend *liveBackend
	if len(owned) != 0 && ownedErr == nil {
		sequence := liveBeginPhase(t, worker, "authentication", true)
		backend, err = openLiveBackend(ctx, input.Settings, input.Prefix, inventory.image.Domain)
		liveEndPhase(t, worker, sequence, err == nil)
		if err != nil {
			fact := liveHarnessFailure(err, "setup_check", "authentication", "evidence_unavailable", "unknown")
			worker.Result.HarnessFailure = &fact
			worker.Result.Cleanup.HarnessFailure = &fact
			t.Fatal("cleanup authentication or construction refused")
		}
		backend, err = liveRecoveryLocationBackend(input, inventory.image, backend, func(ctx context.Context, prefix string, domain contract.ID) (*liveBackend, error) {
			return openLiveBackend(ctx, input.Settings, prefix, domain)
		})
		if err != nil {
			t.Fatal("recovery cleanup location ownership refused")
		}
		sequence = liveBeginPhase(t, worker, "resource_check", true)
		var checkErr error
		if !budget.reserve(24, 24*operationBodyAllowance, "", 0) {
			checkErr = errRunLimit
		} else {
			checkErr = backend.Check(ctx)
		}
		admitted := checkErr == nil
		liveEndPhase(t, worker, sequence, admitted)
		if !admitted {
			fact := liveHarnessFailure(checkErr, "setup_check", "configuration_check", "evidence_unavailable", "unknown")
			if errors.Is(checkErr, errRunLimit) {
				fact = records.HarnessFailure{Operation: "setup_check", Stage: "admission", Cause: "budget_exhausted", Effect: "no_send"}
			}
			worker.Result.HarnessFailure = &fact
			worker.Result.Cleanup.HarnessFailure = &fact
			t.Fatal("cleanup resource admission failed")
		}
	}
	var outputSummary livePublicationCleanupSummary
	var outputErr error
	outputExpected := false
	if input.Outputs != nil {
		if livePublicationInput(inv, input) != nil || input.Outputs.Scope.DomainID != hex.EncodeToString(inventory.image.Domain[:]) {
			outputErr = livePublicationCleanupError(nil, "ownership_check", "evidence_unavailable", "no_send")
		} else {
			retained, err := records.ReadOutputFixtureInventory(input.Outputs.InventoryPath, input.Outputs.Scope)
			if err != nil {
				outputErr = livePublicationCleanupError(nil, "ownership_check", "evidence_unavailable", "no_send")
			} else {
				for index := range retained.Rows {
					state, err := retained.CleanupState(uint32(index))
					if err != nil {
						outputErr = livePublicationCleanupError(nil, "ownership_check", "evidence_unavailable", "no_send")
						break
					}
					outputExpected = outputExpected || state.Eligible
				}
			}
		}
	}
	sequence := liveBeginPhase(t, worker, "cleanup", len(owned) != 0 || generatorOwned != 0 || outputExpected)
	defer func() { liveEndPhase(t, worker, sequence, !t.Failed()) }()
	if input.Outputs != nil {
		if outputErr == nil {
			outputSummary, outputErr = cleanupLivePublication(ctx, input.Outputs, budget)
		}
		outputFacts = liveCleanupOutputFacts{accounted: true, summary: outputSummary, err: outputErr}
	}
	var generatorErr error
	var generatorUnknown int64
	if input.Generator != nil {
		generatorErr = cleanupCloudflareFixture(ctx, input, budget)
		if generatorErr != nil {
			fact := liveHarnessFailure(generatorErr, "generator_cleanup", "ledger", "evidence_unavailable", "unknown")
			worker.Result.HarnessFailure = &fact
			worker.Result.Cleanup.HarnessFailure = &fact
			if fact.Effect == "unknown" && fact.TargetKind == "generator_ledger" {
				generatorUnknown = 1
				unknownEffects += generatorUnknown
			}
		}
		ledger, ledgerErr := records.ReadGeneratorFixtureLedger(input.GeneratorCleanupLedger, input.RunID, input.Generator.Account)
		if ledgerErr != nil {
			t.Fatal("Cloudflare cleanup ledger became unavailable")
		}
		generatorOwned = int64(len(ledger.CleanupTargets()))
		remainingCount = int64(len(owned)) + generatorOwned
	}
	if ownedErr != nil {
		worker.Result.Cleanup.RemainingOwnedObjects = nil
		fact := records.HarnessFailure{Operation: "object_cleanup", Stage: "ownership_check", Cause: "evidence_unavailable", Effect: "no_send"}
		if worker.Result.HarnessFailure == nil {
			worker.Result.HarnessFailure = &fact
		}
		worker.Result.Cleanup.HarnessFailure = &fact
		t.Fatal("possible writes are not settled; inventory retained")
	}
	if len(owned) == 0 {
		if generatorErr != nil || generatorOwned != 0 || unknownEffects != 0 || outputErr != nil || outputSummary.Unknown != 0 || outputSummary.Remaining != outputSummary.Scheduled {
			t.Fatal("Cloudflare fixture cleanup unresolved", generatorErr)
		}
		worker.Result.Cleanup.Outcome = "passed"
		return
	}
	store := recordedStore{Store: backend.Store, budget: budget}
	remove := func(ctx context.Context, key string, token contract.Token) error {
		if !budget.reserve(2, operationBodyAllowance, "", 0) {
			return errRunLimit
		}
		return backend.Delete(ctx, key, token)
	}
	var cleanupErr error
	if input.CleanupGrant != nil {
		cleanupErr = inventory.recoverGrantedCleanup(ctx, store, remove, *input.CleanupGrant)
		if cleanupErr == nil {
			cleanupErr = inventory.cleanup(ctx, store, remove)
		}
	} else if input.CleanupRetry != nil {
		cleanupErr = inventory.recoverCleanup(ctx, store, remove, input.CleanupRetry.TargetIndex, input.CleanupRetry.Ordinal)
		if cleanupErr == nil {
			cleanupErr = inventory.cleanup(ctx, store, remove)
		}
	} else {
		cleanupErr = inventory.cleanup(ctx, store, remove)
	}
	if cleanupErr != nil {
		fact := liveHarnessFailure(cleanupErr, "object_cleanup", "ownership_check", "evidence_unavailable", "unknown")
		if worker.Result.HarnessFailure == nil {
			worker.Result.HarnessFailure = &fact
		}
		worker.Result.Cleanup.HarnessFailure = &fact
		if count, countErr := inventory.image.unknownEffects(); countErr == nil {
			unknownEffects = count + generatorPendingCreates + generatorUnknown
		} else {
			worker.Result.Cleanup.UnknownEffects = nil
		}
		remaining, err := inventory.owned(true)
		if err != nil {
			worker.Result.Cleanup.RemainingOwnedObjects = nil
		} else {
			remainingCount = int64(len(remaining)) + generatorOwned
		}
		t.Fatal("cleanup unresolved; inventory retained")
	}
	remaining, remainingErr := inventory.owned(true)
	count, countErr := inventory.image.unknownEffects()
	if remainingErr != nil || countErr != nil {
		worker.Result.Cleanup.RemainingOwnedObjects = nil
		worker.Result.Cleanup.UnknownEffects = nil
		t.Fatal("cleanup inventory outcome unavailable")
	}
	remainingCount = int64(len(remaining)) + generatorOwned
	unknownEffects = count + generatorPendingCreates + generatorUnknown
	if generatorErr != nil || remainingCount != 0 || unknownEffects != 0 || outputErr != nil || outputSummary.Unknown != 0 || outputSummary.Remaining != outputSummary.Scheduled {
		t.Fatal("cleanup residue unresolved", generatorErr)
	}
	worker.Result.Cleanup.Outcome = "passed"
}

func liveCheckRunResources(ctx context.Context, worker *records.WorkerRecorder, backend *liveBackend, budget *runBudget) (err error) {
	sequence, err := worker.BeginPhase("resource_check", true)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, worker.EndPhase(context.Background(), sequence, err == nil)) }()
	if !budget.reserve(24, 24*operationBodyAllowance, "", 0) {
		return errRunLimit
	}
	return backend.Check(ctx)
}

func admitFixtureCleanupClaim(inv records.Invocation, input liveRunInput, inventoryPath string) error {
	if input.CleanupGrant == nil {
		return inventoryFailure("ownership_check", "evidence_unavailable", "no_send", errInventory, -1, 0)
	}
	refuse := func() error {
		return inventoryFailure("ownership_check", "evidence_unavailable", "no_send", errInventory, int(input.CleanupGrant.TargetIndex), 0)
	}
	digest, err := privateRecordSHA256(inventoryPath)
	if err != nil || digest != input.CleanupGrant.InventorySHA256 {
		return refuse()
	}
	filename, decision := "aws-cleanup-grant.json", "aws_retired_fixture_grant"
	var image inventoryImage
	readErr := readPrivateJSON(inventoryPath, &image)
	var target *cleanupAttempt
	targetAttempts := 0
	for index := range image.CleanupAttempts {
		attempt := &image.CleanupAttempts[index]
		if attempt.TargetIntent == int(input.CleanupGrant.TargetIndex) {
			target, targetAttempts = attempt, targetAttempts+1
		}
	}
	noSend := readErr == nil && target != nil && admissionNoSendCleanup(target.Failure)
	if noSend {
		attempt := *target
		unknown, err := image.unknownEffects()
		if err != nil || unknown != 0 || image.Version != 1 || image.RunID != input.RunID || image.Prefix != input.Prefix ||
			image.Binding != settingsBinding(input.Settings) || image.Domain.IsZero() || input.CleanupGrant.Ordinal != 2 || targetAttempts != 1 ||
			attempt.State != "failed" || attempt.Ordinal != 1 || attempt.Recovery != "" ||
			attempt.TargetIntent != int(input.CleanupGrant.TargetIndex) || attempt.Token.Family != liveFamily {
			return refuse()
		}
		for index := range image.CleanupAttempts {
			other := &image.CleanupAttempts[index]
			if other != target && (other.State != "settled" || other.Recovery == "gcp_exact_generation_grant" ||
				other.Recovery == "aws_retired_fixture_grant" || other.Recovery == "admission_no_send_grant") {
				return refuse()
			}
		}
		filename, decision = "admission-cleanup-grant.json", "admission_no_send_grant"
	} else if input.Settings.Provider != "aws" {
		return refuse()
	}
	var claim struct {
		Basis struct {
			OriginalRunID             string        `json:"original_run_id"`
			OriginalRunSHA256         string        `json:"original_run_sha256"`
			OriginalCaseReceiptSHA256 string        `json:"original_case_receipt_sha256"`
			Entry                     catalog.Entry `json:"entry"`
			TargetIndex               uint32        `json:"target_index"`
			Decision                  string        `json:"decision"`
		} `json:"basis"`
		Source records.Source   `json:"source"`
		Grant  liveCleanupGrant `json:"grant"`
	}
	path, err := records.SafePath(filepath.Dir(inv.StateDir), filename)
	if err != nil || readPrivateJSON(path, &claim) != nil || claim.Grant != *input.CleanupGrant ||
		claim.Basis.OriginalRunID != input.RunID || claim.Basis.OriginalCaseReceiptSHA256 != input.CleanupGrant.OriginalCaseReceiptSHA256 ||
		claim.Basis.TargetIndex != input.CleanupGrant.TargetIndex || claim.Basis.Decision != decision ||
		claim.Basis.Entry.Scenario != inv.Scenario || claim.Basis.Entry.Members != input.MemberCount {
		return refuse()
	}
	original := filepath.Dir(filepath.Dir(inv.StateDir))
	digest, err = privateRecordSHA256(filepath.Join(original, "run.json"))
	if err != nil || digest != claim.Basis.OriginalRunSHA256 {
		return refuse()
	}
	digest, err = privateRecordSHA256(filepath.Join(original, "cases", fmt.Sprintf("%04d.json", claim.Basis.Entry.Sequence)))
	if err != nil || digest != claim.Basis.OriginalCaseReceiptSHA256 {
		return refuse()
	}
	_, runs, id, err := records.PrivateOwner(inv.OutputDir)
	if err != nil || id != inv.RunID {
		return refuse()
	}
	current, err := records.ResolveRun(runs, id)
	if err != nil {
		return refuse()
	}
	var record map[string]json.RawMessage
	var source records.Source
	if records.ReadJSON(filepath.Join(current, "run.json"), &record) != nil || json.Unmarshal(record["source"], &source) != nil || !reflect.DeepEqual(source, claim.Source) {
		return refuse()
	}
	return nil
}

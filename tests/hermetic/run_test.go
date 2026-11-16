package core

import (
	"bytes"
	"context"
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
)

type hermeticWorkerInput struct {
	RecoveryMode string   `json:"recovery_mode"`
	Scenarios    []string `json:"scenarios"`
	Repetitions  int      `json:"repetitions"`
	RunID        string   `json:"run_id"`

	Participants map[string]string `json:"participants"`
}

// Only public fixture bindings and persisted objects cross the process boundary.
// The expected image is the shared oracle's independent fixture evidence.
type hermeticFreshFacts struct {
	Step              catalog.Step   `json:"step"`
	RecoveryMode      string         `json:"recovery_mode"`
	RunID             string         `json:"run_id"`
	Scenario          string         `json:"scenario"`
	Refusal           string         `json:"refusal,omitempty"`
	Fixture           processFixture `json:"fixture"`
	ExpectedImageFile string         `json:"expected_image_file,omitempty"`
}

func readHermeticInvocation(t testing.TB, fresh bool) (testing.TB, records.Invocation, hermeticWorkerInput, *records.FailureRecorder) {
	t.Helper()
	inv, err := records.LoadInvocation(os.Getenv("ENKV_TEST_INVOCATION"))
	if err != nil {
		t.Fatal("hermetic worker invocation refused")
	}
	failure, err := records.NewFailureRecorder(inv)
	if err != nil {
		t.Fatal("hermetic failure evidence owner refused")
	}
	t = assertionTB{TB: t, failure: failure}
	if inv.FailureSources == nil {
		t.Fatal("hermetic assembly source mapping unavailable")
	}
	if !fresh && inv.Role != "writer" || fresh && inv.Role != "fresh_before" && inv.Role != "fresh_after" {
		t.Fatal("hermetic worker role refused")
	}
	var input hermeticWorkerInput
	if records.ReadJSON(inv.Input, &input) != nil || len(input.Scenarios) != 1 || input.Scenarios[0] != inv.Scenario || input.Repetitions != 1 || input.RunID != inv.RunID || input.RecoveryMode != "both" && input.RecoveryMode != "disabled" && input.RecoveryMode != "enabled" || inv.Input != filepath.Join(inv.StateDir, "input.json") || filepath.Dir(inv.OutputDir) != filepath.Join(inv.StateDir, "workers") {
		t.Fatal("hermetic worker input refused")
	}
	selected := inv.RecoveryMode
	if selected == "" {
		selected = "both"
	}
	if !fresh && selected != input.RecoveryMode || fresh && input.RecoveryMode != "both" && inv.RecoveryMode != input.RecoveryMode {
		t.Fatal("hermetic worker mode differs from its invocation")
	}
	if _, err := catalog.FixtureShape(input.Scenarios[0]); err != nil {
		t.Fatal("hermetic scenario parameters refused")
	}
	if _, known := catalog.ExecutionForRecovery(input.Scenarios[0], "hermetic", input.RecoveryMode); !known {
		t.Fatal("hermetic recovery selection refused")
	}
	for _, role := range catalog.RolesForScenarios(input.Scenarios, input.RecoveryMode) {
		if input.Participants[role] == "" {
			t.Fatal("required scenario participant missing")
		}
	}
	return t, inv, input, failure
}

func finishHermeticWorker(t testing.TB, worker *records.WorkerRecorder) {
	t.Helper()
	if err := worker.Finish(context.Background(), !t.Failed()); err != nil {
		t.Error("hermetic worker evidence could not be saved")
	}
}

func hermeticWorkerContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	deadline, finite := t.Deadline()
	if !finite {
		t.Fatal("hermetic scenario deadline unavailable")
	}
	return context.WithDeadline(t.Context(), deadline)
}

func hermeticWorkerCommand(t testing.TB, ctx context.Context, invocation, entry string) (*exec.Cmd, time.Duration) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal("hermetic executable unavailable")
	}
	deadline, finite := ctx.Deadline()
	if !finite {
		t.Fatal("hermetic case deadline unavailable")
	}
	remaining := time.Until(deadline)
	command := exec.CommandContext(ctx, binary, "-test.run=^"+entry+"$", "-test.timeout="+remaining.String())
	command.Env = hermeticChildEnvironment(invocation)
	return command, remaining
}

// full_only: false
func TestHermeticRun(test *testing.T) {
	if os.Getenv("ENKV_TEST_INVOCATION") == "" {
		test.Skip("worker entry requires a coordinator invocation")
	}
	t, inv, input, failure := readHermeticInvocation(test, false)
	worker, err := records.NewWorker(inv, "core", input.Scenarios[0], failure)
	if err != nil {
		t.Fatal("hermetic worker could not start")
	}
	worker.Result.Actor = input.Participants["authority"]
	defer finishHermeticWorker(t, worker)
	execution, known := catalog.ExecutionForRecovery(input.Scenarios[0], "hermetic", input.RecoveryMode)
	if !known {
		t.Fatal("hermetic execution facts unavailable")
	}
	steps := execution.WriterSteps()
	stepIndex := 0
	definition, _ := catalog.DefinitionFor(input.Scenarios[0])
	for _, recovery := range definition.RecoveryModes {
		if input.RecoveryMode != "both" && recovery != input.RecoveryMode {
			continue
		}
		if !test.Run(recovery, func(child *testing.T) {
			t := assertionTB{TB: child, failure: failure}
			ctx, cancel := hermeticWorkerContext(child)
			defer cancel()
			ctx = worker.Context(ctx)
			env := memoryScenarioEnvironmentMode(t, recovery == "enabled")
			env.Context = ctx
			if execution.HasFixtureCapability(catalog.FixtureSyntheticAuthority) {
				env = syntheticAuthorityScenarioEnvironment(t, env)
			}
			var phase uint64
			env.Phase = func(name string) {
				if stepIndex >= len(steps) || steps[stepIndex].Name != name || steps[stepIndex].RecoveryMode != recovery {
					t.Fatal("hermetic action differs from the scenario plan")
				}
				var err error
				step := steps[stepIndex]
				stepIndex++
				phase, err = worker.BeginStep(step, input.Participants[step.Role])
				if err != nil {
					t.Fatal("hermetic phase evidence could not be saved")
				}
			}
			env.EndPhase = func(string) {
				if err := worker.EndPhase(context.Background(), phase, !t.Failed()); err != nil {
					t.Fatal("hermetic phase evidence could not be saved")
				}
			}
			env.FreshCurrent = func(t testing.TB, admission OpenContext, selected *StateSession) {
				hermeticFreshCurrentBefore(t, ctx, inv, worker, env, admission, selected)
			}
			env.FreshGeneratedRecord = func(t testing.TB, selected *StateSession, attempt contract.ID, result []byte) *StateSession {
				return hermeticFreshGeneratedSelection(t, ctx, inv, worker, env, selected, &generatedRecordInput{Attempt: attempt, Result: result}, false)
			}
			env.FreshGeneratedFinal = func(t testing.TB, selected *StateSession) *StateSession {
				return hermeticFreshGeneratedSelection(t, ctx, inv, worker, env, selected, nil, true)
			}
			runStateScenario(t, ctx, env, input.Scenarios[0])
			if execution.HasFixtureCapability(catalog.FixtureSelectedStateDamage) {
				env.Phase("reopen")
				defer env.EndPhase("reopen")
				hermeticFreshBeforeInput(t, ctx, inv, worker, env, stateImage{}, input.Scenarios[0], nil)
			}
		}) {
			return
		}
	}
	if stepIndex != len(steps) {
		t.Fatal("hermetic scenario omitted a recovery mode or required step")
	}

}

func hermeticFreshCurrentBefore(t testing.TB, ctx context.Context, inv records.Invocation, worker *records.WorkerRecorder, env fixtureEnvironment, admission OpenContext, selected *StateSession) {
	t.Helper()
	input := selectedProcessFacts(t, admission, selected)
	var err error
	input.ExpectedWork, err = selected.workSupportRecords(t.Context())
	if err != nil {
		t.Fatal("fresh current work evidence unavailable", err)
	}
	if execution, known := catalog.ExecutionFor(worker.Result.Scenario, "hermetic"); known && execution.Family == catalog.FamilyAuthorityReplacement {
		a := admission.admission
		for _, entry := range selected.root.Names {
			if selected.valueEntry(entry.Slot).ConfidentialityClass == contract.Secret {
				input.Consumer = &successorConsumerInput{Binding: contract.BindingTableRow{SubjectKind: 1, SubjectID: a.recipient, Binding: *selected.authority().CurrentBinding}, Name: entry.Name, Value: custody.StandardValue}
			}
		}
	}
	// hermeticFreshBeforeInput writes the oracle to its separately owned file.
	// Do not duplicate it inside the private process fixture.
	input.ExpectedImage = stateImage{}
	hermeticFreshBeforeInput(t, ctx, inv, worker, env, sessionStateImage(t, selected), "", &input)
}

func hermeticFreshGeneratedSelection(t testing.TB, ctx context.Context, inv records.Invocation, worker *records.WorkerRecorder, env fixtureEnvironment, selected *StateSession, record *generatedRecordInput, final bool) *StateSession {
	t.Helper()
	input := selectedGeneratedProcessFacts(t, selected)
	var err error
	input.ExpectedWork, err = selected.workSupportRecords(t.Context())
	if err != nil {
		t.Fatal("fresh generated selection work unavailable", err)
	}
	input.GeneratedRecord, input.GeneratedFinal = record, final
	input.ExpectedImage = stateImage{}
	store := env.Store.(*memoryStore)
	output := hermeticFreshBeforeInput(t, ctx, inv, worker, env, sessionStateImage(t, selected), "", &input)
	return importFreshGeneratedSelection(t, selected, store.generation, output)
}

func hermeticFreshBeforeInput(t testing.TB, ctx context.Context, inv records.Invocation, worker *records.WorkerRecorder, env fixtureEnvironment, expected stateImage, refusal string, current *processFixture) *generatedRecordOutput {
	t.Helper()
	if (current == nil) != (refusal != "") {
		t.Fatal("fresh hermetic input must carry complete selected facts or an explicit refusal")
	}
	index := len(worker.Result.Children)
	execution, known := catalog.ExecutionForRecovery(worker.Result.Scenario, "hermetic", inv.RecoveryMode)
	if !known {
		t.Fatal("fresh child execution facts unavailable")
	}
	children := execution.ExpandedFreshBefore()
	if index >= len(children) {
		t.Fatal("fresh child exceeds catalog plan")
	}
	recovery := "disabled"
	if env.Recovery != nil {
		recovery = "enabled"
	}
	factsName := filepath.Join("facts", fmt.Sprintf("%s-fresh-%04d.json", recovery, index))
	factsPath, err := records.SafePath(inv.StateDir, factsName)
	if err != nil {
		t.Fatal("fresh hermetic facts path refused")
	}
	if index == 0 {
		if err := os.Mkdir(filepath.Dir(factsPath), 0o700); err != nil {
			t.Fatal("fresh hermetic facts directory could not be created")
		}
	}
	// Old and new objects can each fill a complete image. Keep the oracle in
	// its own bounded record so JSON base64 expansion cannot crowd it out.
	expectedName := strings.TrimSuffix(factsName, ".json") + "-expected.json"
	expectedPath, err := records.SafePath(inv.StateDir, expectedName)
	if err != nil || records.WriteJSON(expectedPath, expected, 0o400) != nil {
		t.Fatal("fresh hermetic expected image could not be saved")
	}
	store := env.Store.(*memoryStore)
	store.mu.Lock()
	facts := hermeticFreshFacts{Step: children[index].Step, RecoveryMode: recovery, RunID: inv.RunID, Scenario: worker.Result.Scenario, Refusal: refusal, ExpectedImageFile: expectedName}
	if current == nil {
		facts.Fixture = processFixture{Domain: env.Domain, Trust: env.Trust.Identity(), Objects: store.objects, Descriptor: store.desc, PublicKey: env.PublicKey, DomainBasis: bytes.Clone(fixtureAdmission(env).admission.descriptor)}
	} else {
		facts.Fixture = *current
		facts.Fixture.Objects = store.objects
	}
	facts.Fixture.Generation = store.generation
	err = records.WriteJSON(factsPath, facts, 0o400)
	store.mu.Unlock()
	if err != nil {
		t.Fatal("fresh hermetic facts could not be saved")
	}
	child := inv
	if index >= len(inv.FreshBefore) {
		t.Fatal("fresh child binding unavailable")
	}
	child.Nonce = inv.FreshBefore[index].Nonce
	child.FreshBefore = nil
	child.Worker = fmt.Sprintf("%s-fresh-%04d-before", filepath.Base(inv.StateDir), index)
	if child.Worker != inv.FreshBefore[index].Worker {
		t.Fatal("fresh child binding differs")
	}
	child.Role, child.Facts, child.RecoveryMode = "fresh_before", factsName, recovery
	child.OutputDir = filepath.Join(inv.StateDir, "workers", fmt.Sprintf("fresh-%04d-before", index))
	if err := os.Mkdir(child.OutputDir, 0o700); err != nil {
		t.Fatal("fresh hermetic output directory could not be created")
	}
	invocationPath := filepath.Join(child.OutputDir, "invocation.json")
	if err := records.WriteJSON(invocationPath, child, 0o400); err != nil {
		t.Fatal("fresh hermetic invocation could not be saved")
	}
	owner, _, ownerID, err := records.PrivateOwner(inv.StateDir)
	if err != nil || ownerID != inv.RunID {
		t.Fatal("hermetic invocation owner unavailable")
	}
	relative, err := filepath.Rel(owner, invocationPath)
	if err != nil {
		t.Fatal("fresh hermetic invocation owner refused")
	}
	// Keep every started child's descriptor, even when later history phases
	// replace the latest facts selected for the reader after writer exit.
	worker.Result.Children = append(worker.Result.Children, records.ChildInvocation{Worker: child.Worker, Invocation: relative})
	retained := worker.Result.FreshChecks[:0]
	for _, check := range worker.Result.FreshChecks {
		if !strings.HasPrefix(check.Facts, "facts/"+recovery+"-") {
			retained = append(retained, check)
		}
	}
	worker.Result.FreshChecks = append(retained, records.FreshCheck{Facts: factsName, RecoveryMode: recovery})
	if err := worker.Save(); err != nil {
		t.Fatal("fresh hermetic child registration could not be saved")
	}
	command, remaining := hermeticWorkerCommand(t, ctx, invocationPath, "TestHermeticChild")
	// The child inherits the writer's process group so the coordinator can
	// stop and join the entire run when its deadline expires.
	var output []byte
	var runErr error
	if remaining <= 0 {
		runErr = context.DeadlineExceeded
	} else {
		output, runErr = command.CombinedOutput()
	}
	process := records.ObserveFreshChildProcess(command, runErr)
	worker.Result.Children[index].Process = &process
	if err := worker.Save(); err != nil {
		t.Fatal("fresh hermetic process observation could not be saved")
	}
	var result records.WorkerResult
	if records.ReadJSON(filepath.Join(child.OutputDir, "worker.json"), &result) != nil || result.RunID != child.RunID || result.Worker != child.Worker || result.Role != child.Role || result.Scenario != worker.Result.Scenario {
		t.Fatal("fresh hermetic child evidence unavailable or invalid")
	}
	if len(worker.Result.Phases) != 0 && len(result.Phases) != 0 {
		phase := &worker.Result.Phases[len(worker.Result.Phases)-1]
		if phase.Name == "reopen" {
			if worker.ObservePhase(phase.Sequence, result.Phases[0].Actual) != nil {
				t.Fatal("fresh hermetic observation could not be saved")
			}
		}
	}
	if runErr != nil || result.Outcome != "passed" {
		t.Fatalf("fresh hermetic child failed: %v %s", runErr, output)
	}
	if current == nil || current.GeneratedRecord == nil && !current.GeneratedFinal {
		return nil
	}
	var selected generatedRecordOutput
	if err := records.ReadJSON(filepath.Join(child.OutputDir, "generated-selection.json"), &selected); err != nil {
		t.Fatal("fresh hermetic generated selection output unavailable", err)
	}
	return &selected
}

func hermeticChildEnvironment(invocation string) []string {
	environment := make([]string, 0, len(os.Environ())+1)
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "ENKV_TEST_INVOCATION=") {
			environment = append(environment, value)
		}
	}
	return append(environment, "ENKV_TEST_INVOCATION="+invocation)
}

// full_only: false
func TestHermeticChild(test *testing.T) {
	if os.Getenv("ENKV_TEST_INVOCATION") == "" {
		test.Skip("worker entry requires a coordinator invocation")
	}
	t, inv, input, failure := readHermeticInvocation(test, true)
	worker, err := records.NewWorker(inv, "core", input.Scenarios[0], failure)
	if err != nil {
		t.Fatal("fresh hermetic worker could not start")
	}
	defer finishHermeticWorker(t, worker)
	factsPath, err := records.SafePath(inv.StateDir, inv.Facts)
	var facts hermeticFreshFacts
	if err != nil || records.ReadJSON(factsPath, &facts) != nil || facts.RunID != inv.RunID || facts.Scenario != input.Scenarios[0] || facts.RecoveryMode != inv.RecoveryMode {
		t.Fatal("fresh hermetic facts refused")
	}
	execution, known := catalog.ExecutionForRecovery(input.Scenarios[0], "hermetic", input.RecoveryMode)
	if !known {
		t.Fatal("fresh hermetic execution facts unavailable")
	}
	var after catalog.FreshChild
	for _, child := range execution.ExpandedFreshAfter() {
		if child.Step.RecoveryMode == facts.RecoveryMode {
			after = child
			break
		}
	}
	if after.Role == "" {
		t.Fatal("fresh hermetic recovery facts unavailable")
	}
	if facts.Step.Name == "" {
		facts.Step = after.Step
	}
	if inv.Role == "fresh_after" && facts.Step != after.Step {
		t.Fatal("after-exit child cannot resume work")
	}
	if inv.Role == "fresh_before" && !slices.ContainsFunc(execution.ExpandedFreshBefore(), func(child catalog.FreshChild) bool { return child.Step == facts.Step }) {
		t.Fatal("fresh child purpose or role is outside the catalog")
	}
	worker.Result.Actor = input.Participants[facts.Step.Role]
	ctx, cancel := hermeticWorkerContext(test)
	defer cancel()
	ctx = worker.Context(ctx)
	sequence, err := worker.BeginStep(facts.Step, worker.Result.Actor)
	if err != nil {
		t.Fatal("fresh hermetic phase could not start", err)
	}
	defer func() {
		if err := worker.EndPhase(context.Background(), sequence, !t.Failed()); err != nil {
			t.Error("fresh hermetic phase evidence", err)
		}
	}()
	if facts.ExpectedImageFile != "" {
		// Retained facts without this reference use the original inline oracle.
		// A referenced oracle must have one owner and no competing inline value.
		expectedName := strings.TrimSuffix(inv.Facts, ".json") + "-expected.json"
		expectedPath, err := records.SafePath(inv.StateDir, facts.ExpectedImageFile)
		if err != nil || !strings.HasSuffix(inv.Facts, ".json") || facts.ExpectedImageFile != expectedName || !reflect.DeepEqual(facts.Fixture.ExpectedImage, stateImage{}) || records.ReadJSON(expectedPath, &facts.Fixture.ExpectedImage) != nil {
			t.Fatal("fresh hermetic expected image refused")
		}
	}
	damaged := execution.HasFixtureCapability(catalog.FixtureSelectedStateDamage)
	if damaged && facts.Refusal != facts.Scenario || !damaged && facts.Refusal != "" || facts.Fixture.Domain.IsZero() || facts.Fixture.Trust.IsZero() || len(facts.Fixture.Objects) == 0 || len(facts.Fixture.PublicKey) == 0 {
		t.Fatal("fresh hermetic fixture evidence refused")
	}
	f := facts.Fixture
	admission := processPublicAdmission(f.Domain, f.Trust, f.Descriptor, f.PublicKey, f.DomainBasis)
	if f.CurrentBasis != nil {
		admission.admission.current = f.CurrentBasis.owned()
		admission.admission.epoch = f.Epoch
	}
	control, currentOK := admission.admission.currentControl()
	mode := "disabled"
	if control.Recovery != nil {
		mode = "enabled"
	}
	if !currentOK || facts.RecoveryMode != mode {
		t.Fatal("fresh recovery mode differs from admitted domain")
	}
	worker.Result.Phases[len(worker.Result.Phases)-1].RecoveryMode = facts.RecoveryMode
	if err := worker.Save(); err != nil {
		t.Fatal("fresh mode evidence could not be saved")
	}
	store := &memoryStore{desc: f.Descriptor, configuration: f.Configuration, objects: f.Objects, generation: f.Generation}
	var keys []string
	store.readHook = func(key string, result contract.ReadResult) contract.ReadResult {
		keys = append(keys, key)
		return result
	}
	reader := &hermeticReaderStore{store: store, deny: execution.HasFixtureCapability(catalog.FixtureReadRefusal)}
	phase := &worker.Result.Phases[sequence-1]
	session, result := Open(ctx, admission, reader)
	actual := readerReadOutcome(result, reader.refused)
	if session != nil && f.Consumer != nil {
		checkSuccessorConsumer(t, session, *f.Consumer)
	} else if session != nil && execution.HasFixtureCapability(catalog.FixtureSecretConsumption) {
		authority, recipient := fixtureID(f.Domain, "recipient"), fixtureID(f.Domain, "recipient")
		if after.Role != "authority" {
			recipient = fixtureID(f.Domain, "reader")
		}
		keys := custody.New(t, f.Descriptor.Family, fixtureID(f.Domain, "custody"), control.Recovery != nil, []contract.ID{authority, fixtureID(f.Domain, "reader")})
		selection := sessionConsumerSelection(t, session, recipient, "secret")
		if after.Role == "reader-successor" {
			keys.RestoreRecipientSuccessor(t, selection.Binding)
		}
		denied := execution.HasFixtureCapability(catalog.FixtureSecretRefusal)
		if recipient != authority {
			keys.SetDenied(authority, true)
		}
		if denied {
			keys.SetDenied(recipient, true)
		}
		actual = firstFlowConsumerOutcome(keys.Consume(ctx, selection, custody.StandardValue), selection, denied)
	}
	if worker.ObservePhase(sequence, actual) != nil {
		t.Fatal("fresh hermetic observation could not be saved")
	}
	if reader.writes != 0 || store.creates != 0 || store.cas != 0 {
		t.Fatal("fresh hermetic read resumed writer work")
	}
	if phase.Expected == "access-refused" {
		if session != nil || phase.Actual != "access-refused" || reader.reads != 1 || store.reads != 0 {
			t.Fatal("fresh hermetic reader did not produce exact access refusal")
		}
		return
	}
	if damaged {
		if session != nil || after.Step.Expected == "unavailable" && (result.Outcome != EvidenceUnavailable || result.Reason != MissingSelectedObject) || after.Step.Expected == "integrity-failure" && result.Outcome != IntegrityFailure {
			t.Fatalf("damaged closure accepted by fresh process: %+v", result)
		}
		return
	}
	if session == nil || result.Outcome != ObservedCurrent || result.Evidence != AuthenticatedClosure || result.ObservedRevision != f.ExpectedImage.Revision {
		t.Fatalf("fresh hermetic observation: %+v", result)
	}
	assertStateImage(t, session, f.ExpectedImage)
	store.mu.Lock()
	openReads, openKeys := store.reads, slices.Clone(keys)
	store.mu.Unlock()
	assertFreshSelectedClosureReads(t, f.Descriptor, f.ExpectedImage, session, openReads, openKeys)
	checkFreshReceipts(t, ctx, session, f.Receipts)
	if reader.writes != 0 || store.creates != 0 || store.cas != 0 || uint64(store.reads) != uint64(openReads)+freshReceiptReadCount(f.Receipts) {
		t.Fatal("fresh hermetic receipt queries exceeded their exact current reads")
	}
	store.mu.Lock()
	queryKeys := slices.Clone(keys[openReads:])
	reads := store.reads
	store.mu.Unlock()
	if len(openKeys)+len(queryKeys) != reads {
		t.Fatal("fresh hermetic receipt queries lost a Store read key")
	}
	for _, key := range queryKeys {
		if key != f.Descriptor.HeadKey {
			t.Fatal("fresh hermetic receipt query read an unrelated object", key)
		}
	}
	if publication, known := catalog.Publication(facts.Scenario); known && publication.Condition == "lost-process" {
		checkPublicationFreshPlan(t, ctx, session, publication.Condition)
		if reader.writes != 0 || store.creates != 0 || store.cas != 0 {
			t.Fatal("fresh publication planning resumed writer work")
		}
	}
	if f.GeneratedRecord != nil || f.GeneratedFinal {
		var purpose catalog.FreshPurpose
		for _, child := range execution.FreshBefore {
			if child.Step == facts.Step {
				purpose = child.Purpose
				break
			}
		}
		if inv.Role != "fresh_before" || f.GeneratedRecord != nil && f.GeneratedFinal ||
			f.GeneratedRecord != nil && purpose != catalog.FreshGeneratedRecord ||
			f.GeneratedFinal && purpose != catalog.FreshGeneratedFinal {
			t.Fatal("fresh generated action is outside its catalog transition")
		}
		work, err := session.workSupportRecords(ctx)
		if err != nil || !reflect.DeepEqual(work, f.ExpectedWork) {
			t.Fatal("fresh generated action changed its authenticated input work", err)
		}
		// Read-only reopening is complete. Only this explicitly owned before
		// transition can now obtain the private current-authority write route.
		session.store = store
		var output generatedRecordOutput
		if f.GeneratedRecord != nil {
			output = recordGeneratedInFreshProcess(t, ctx, session, store, *f.GeneratedRecord, f.Receipts)
		} else {
			output = finalGeneratedInFreshProcess(t, ctx, session, store, f.Receipts)
		}
		if err := records.WriteJSON(filepath.Join(inv.OutputDir, "generated-selection.json"), output, 0o600); err != nil {
			t.Fatal("fresh generated action output could not be saved", err)
		}
		if err := worker.ObservePhase(sequence, facts.Step.Expected); err != nil {
			t.Fatal("fresh generated action observation could not be saved", err)
		}
	}
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

// Copy only the registered module owners and the finite assembly source groups.
// Recovery records already under root are current test-owned fixture records.
// No retained result directory in the maintained checkout is read or copied.
func copyPreparationAssemblyFixture(t *testing.T, root string) (context.Context, string, *resourceLocks) {
	t.Helper()
	maintained := testRepositoryRoot(t)
	for _, source := range moduleSources {
		from, err := moduleSourceDirectory(maintained, source)
		if err != nil {
			t.Fatal(err)
		}
		owner := root
		if source.Sibling != "" {
			owner = filepath.Join(filepath.Dir(root), source.Sibling)
		}
		target := filepath.Join(owner, source.Directory)
		if err := os.MkdirAll(target, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.CopyFS(target, os.DirFS(from)); err != nil {
			t.Fatal("copy registered assembly owner", source.Selector, err)
		}
	}
	copyFile := func(relative string) {
		body, err := os.ReadFile(filepath.Join(maintained, relative))
		if err != nil {
			t.Fatal(err)
		}
		writeLocalGoFixture(t, root, relative, string(body))
	}
	for _, group := range []string{"tests/shared", "tests/hermetic", "tests/live/shared", "tests/live/runner", "tests/live/providers/aws", "tests/live/providers/gcp", "tests/shared/runner", "tests/shared/records", "tests/shared/catalog"} {
		entries, err := os.ReadDir(filepath.Join(maintained, group))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") {
				copyFile(filepath.Join(group, entry.Name()))
			}
		}
	}
	copyFile("tests/scripts/bootstrap.go")
	for _, admission := range append(slices.Clone(records.TestAdmissionOverlays()), records.LiveTestSupportOverlays()...) {
		copyFile(admission.Source)
	}
	for _, relative := range []string{"tests/crypto/cloudflare_process_test.go", "tests/hermetic/hermetic.mod", "tests/hermetic/hermetic.sum", "tests/live/providers/aws/live.mod", "tests/live/providers/aws/live.sum", "tests/live/providers/gcp/live.mod", "tests/live/providers/gcp/live.sum"} {
		copyFile(relative)
	}
	initializeWorkflowExecutionFixture(t, root)
	locks := resourceLockFixture(t)
	ctx := withResourceLocks(withRacePolicy(withExecutionParallel(t.Context(), 1), true), locks)
	bootstrap := repetitionTestBootstrap(t, root, t.TempDir())
	return ctx, bootstrap, locks
}

// Record only successful real -c or retained-inventory compilation commands.
// The copied wrapper preserves Go's stdout, stderr and exit status; it supplies
// no inventory or test result.
func observePreparationCompiles(t *testing.T) string {
	t.Helper()
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	realGo, err = filepath.EvalSymlinks(realGo)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	log := filepath.Join(directory, "completed-compiles")
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
	script := "#!/bin/sh\n" + quote(realGo) + " \"$@\"\nstatus=$?\nif [ \"$status\" -eq 0 ]; then\n inventory_list=false\n inventory_output=false\n for argument do\n  case \"$argument\" in\n   -list=.) inventory_list=true ;;\n   -o) inventory_output=true ;;\n  esac\n done\n if [ \"${1-}\" = test ] && [ \"$inventory_list\" = true ] && [ \"$inventory_output\" = true ]; then\n  printf 'compiled\\n' >> " + quote(log) + "\n else\n  for argument do\n   if [ \"$argument\" = -c ]; then printf 'compiled\\n' >> " + quote(log) + "; break; fi\n  done\n fi\nfi\nexit \"$status\"\n"
	if err := os.WriteFile(filepath.Join(directory, "go"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

// These are only the live/workflow records created by this test's own fixture.
func preparationRecoverySnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	result := map[string]string{}
	for _, owner := range []string{"tests/live/runs", "tests/workflows/runs"} {
		directory := filepath.Join(root, owner)
		if _, err := os.Stat(directory); os.IsNotExist(err) {
			continue
		}
		err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			if entry.IsDir() {
				result[relative] = "directory"
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			result[relative] = digestBytes(body)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return result
}

// This fixture uses the same rootAdmitter seam as command composition, with a
// real live EX wait. Native framing and phase transfer have separate controls.
func checkPreparedRecoveryAfterLiveWait(t *testing.T, ctx context.Context, locks *resourceLocks, root string, admission rootAdmission, verify func(context.Context, string) error, path string, replacement []byte, expectRefusal bool) {
	t.Helper()
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	held, err := locks.acquireLive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	wait, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	ready := make(chan struct{})
	joined := make(chan error, 1)
	var acquired *resourceLease
	admissions := 0
	wait = context.WithValue(wait, rootAdmitterContextKey{}, rootAdmitter(func(ctx context.Context, request rootAdmission) (context.Context, error) {
		admissions++
		if !request.Live || request.CleanupSeconds != admission.CleanupSeconds || request.Execution.Resolved.Parallel != 1 {
			return ctx, errors.New("recovery root lost its prepared class or assigned allowance")
		}
		close(ready)
		var err error
		acquired, err = locks.acquireLive(ctx)
		return withExecutionParallel(ctx, 1), err
	}))
	go func() {
		admitted, err := admitPreparedExecution(wait, admission)
		if err == nil {
			err = verify(admitted, root)
		}
		if acquired != nil {
			err = errors.Join(err, acquired.Close())
		}
		joined <- err
	}()
	collected := false
	defer func() {
		cancel()
		held.Close()
		if !collected {
			<-joined
		}
	}()
	select {
	case <-ready:
	case err := <-joined:
		collected = true
		t.Fatal("prepared recovery did not reach root admission", err)
	case <-wait.Done():
		t.Fatal("prepared recovery did not reach its live wait", wait.Err())
	}
	select {
	case err := <-joined:
		collected = true
		t.Fatal("recovery passed a held live EX lock", err)
	default:
	}
	// The selected mutation keeps the provider and resource class intact.
	if replacement == nil {
		replacement = append(slices.Clone(original), ' ')
	}
	if err := os.WriteFile(path, replacement, 0600); err != nil {
		t.Fatal(err)
	}
	mutated := preparationRecoverySnapshot(t, root)
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-joined:
		collected = true
		if admissions != 1 || wait.Err() != nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || !toolCommandsJoined(err) || !sourceCommandsJoined(err) {
			t.Fatal("recovery validation did not finish under live EX admission", err, admissions)
		}
		if expectRefusal && err == nil {
			t.Fatal("ineligible recovery inputs passed after live EX admission")
		}
		if !expectRefusal && err != nil {
			t.Fatal("eligible recovery inputs failed fresh live EX validation", err)
		}
	case <-wait.Done():
		t.Fatal("recovery validation did not join", wait.Err())
	}
	if after := preparationRecoverySnapshot(t, root); !reflect.DeepEqual(mutated, after) {
		t.Fatal("post-wait validation changed a head, grant, checkpoint or retained input")
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verify(ctx, root); err != nil {
		t.Fatal("restored valid recovery inputs remained refused", err)
	}
}

// full_only: false
func TestWorkflowPreviewRequiresNoCompilationOrRootAdmission(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "workflow.json")
	marker := filepath.Join(root, "unexpected-compiler")
	controls := filepath.Join(root, "controls")
	if err := os.Mkdir(controls, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(controls, "go"), []byte("#!/bin/sh\nprintf invoked > "+shellQuote(marker)+"\nexit 97\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", controls+string(os.PathListSeparator)+os.Getenv("PATH"))
	writeLocalGoFixture(t, root, "telemetry/witness/witness_test.go", "broken Go source\n")
	saveSelection(t, path, workflowFile{SchemaVersion: 1, Name: "preview", Profile: "full", Steps: []workflowStep{
		{ID: "first", Kind: "unit", Packages: []string{"telemetry/witness"}, Package: "telemetry/witness", Tests: singleTestRequest("TestNormal")},
		{ID: "later", Kind: "unit", Packages: []string{"telemetry/witness"}, Package: "telemetry/witness", Tests: singleTestRequest("TestBig")},
	}})
	calls := 0
	ctx := context.WithValue(t.Context(), rootAdmitterContextKey{}, rootAdmitter(func(ctx context.Context, admission rootAdmission) (context.Context, error) {
		calls++
		return ctx, errors.New("preview requested resource admission")
	}))
	var output bytes.Buffer
	if err := runCommand(ctx, root, "unavailable-bootstrap", []string{"plan", "--workflow", path}, &output); err != nil {
		t.Fatal(err)
	}
	var preview workflowPreview
	if calls != 0 || json.Unmarshal(output.Bytes(), &preview) != nil || preview.Kind != "selection_preview" || len(preview.Steps) != 2 || len(preview.Unresolved) == 0 {
		t.Fatal("preview claimed compiled facts or requested admission", calls, output.String())
	}
	for _, step := range preview.Steps {
		want := map[string]string{"first": "TestNormal", "later": "TestBig"}[step.ID]
		if !step.Selected || want == "" || step.Tests[0] != want {
			t.Fatal("preview changed its configured test selection", step.ID, step.Tests)
		}
	}
	if err := runCommand(ctx, root, "unavailable-bootstrap", []string{"plan", "--workflow", path, "--memory-limit-mib=0"}, io.Discard); err == nil {
		t.Fatal("preview accepted an invalid configuration limit")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) || calls != 0 {
		t.Fatal("preview started a compiler or requested resources", err, calls)
	}
	for _, directory := range []string{"tests/live/runs", "tests/hermetic/runs", "tests/workflows/runs"} {
		if _, err := os.Stat(filepath.Join(root, directory)); !os.IsNotExist(err) {
			t.Fatal("preview created durable execution state", directory, err)
		}
	}
}

// full_only: false
func TestPreparedFuzzCompilesExactTargetWithoutCampaign(t *testing.T) {
	for _, row := range []struct {
		name   string
		full   bool
		change string
	}{{"normal-source", false, "source"}, {"full-only-seed", true, "seed"}} {
		t.Run(row.name, func(t *testing.T) {
			root, _, _ := overlayFixture(t)
			source := fmt.Sprintf(`package format
import("os";"testing")
// full_only: %t
func FuzzCanonicalRecords(f *testing.F) { if err:=os.WriteFile(os.Getenv("ENKV_PREPARED_FUZZ_BODY"),[]byte("entered"),0600);err!=nil{f.Fatal(err)}; f.Add("seed"); f.Fuzz(func(t *testing.T,s string){}) }
`, row.full)
			writeLocalGoFixture(t, root, "core/format/format.go", "package format\n")
			writeLocalGoFixture(t, root, "core/format/fuzz_test.go", source)
			writeLocalGoFixture(t, root, "tests/hermetic/hermetic.mod", "module "+componentPackage+"\n\ngo 1.27.0\n")
			seed := filepath.Join(root, "core/format/testdata/fuzz/FuzzCanonicalRecords/seed")
			writeLocalGoFixture(t, root, "core/format/testdata/fuzz/FuzzCanonicalRecords/seed", "go test fuzz v1\nstring(\"seed\")\n")
			initializeWorkflowExecutionFixture(t, root)
			marker := filepath.Join(t.TempDir(), "campaign-body")
			t.Setenv("ENKV_PREPARED_FUZZ_BODY", marker)
			locks := resourceLockFixture(t)
			ctx := withResourceLocks(withRacePolicy(withExecutionParallel(t.Context(), 1), true), locks)
			prepared, err := prepareFuzz(nil, ctx, root, []string{"format"}, defaultExecutionPolicy(), io.Discard)
			if prepared != nil {
				defer func() {
					if err := prepared.close(ctx); err != nil {
						t.Error(err)
					}
				}()
			}
			if err != nil {
				t.Fatal(err)
			}
			if prepared.admission().Big || len(prepared.targets) != 1 || !slices.Equal(prepared.targets[0].names, []string{"FuzzCanonicalRecords"}) {
				t.Fatal("compiled fuzz target or classifier differs")
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("fuzz preparation entered a campaign", err)
			}
			path := seed
			if row.change == "source" {
				path = filepath.Join(root, "core/format/fuzz_test.go")
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			held, err := locks.acquireMachine(ctx, true)
			if err != nil {
				t.Fatal(err)
			}
			defer held.Close()
			wait, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			ready, done := make(chan struct{}), make(chan error, 1)
			var acquired *resourceLease
			wait = context.WithValue(wait, rootAdmitterContextKey{}, rootAdmitter(func(ctx context.Context, request rootAdmission) (context.Context, error) {
				if request.Live || request.Big || request.Execution.Resolved.Parallel != 1 {
					return ctx, errors.New("compiled fuzz class changed")
				}
				close(ready)
				var err error
				acquired, err = locks.acquireMachine(ctx, request.Big)
				return withExecutionParallel(ctx, 1), err
			}))
			go func() {
				admitted, err := admitPreparedExecution(wait, prepared.admission())
				if err == nil {
					err = prepared.verify(admitted, root)
				}
				if acquired != nil {
					err = errors.Join(err, acquired.Close())
				}
				done <- err
			}()
			collected := false
			defer func() {
				cancel()
				held.Close()
				if !collected {
					<-done
				}
			}()
			select {
			case <-ready:
			case err := <-done:
				collected = true
				t.Fatal("fuzz did not reach root wait", err)
			case <-wait.Done():
				t.Fatal(wait.Err())
			}
			select {
			case err := <-done:
				collected = true
				t.Fatal("fuzz crossed held machine EX", err)
			default:
			}
			if err := os.WriteFile(path, append(before, ' '), 0600); err != nil {
				t.Fatal(err)
			}
			if err := held.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				collected = true
				if err != nil || wait.Err() != nil {
					t.Fatal("source edit invalidated completed fuzz preparation after admission", err, wait.Err())
				}
			case <-wait.Done():
				t.Fatal(wait.Err())
			}
			if err := os.WriteFile(path, before, 0600); err != nil {
				t.Fatal(err)
			}
			if err := prepared.verify(ctx, root); err != nil {
				t.Fatal("restored compiled fuzz preparation remained refused", err)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("preparation entered a fuzz campaign", err)
			}
		})
	}
}

// full_only: false
func TestPreparedCleanupRevalidatesAfterLiveExclusiveWait(t *testing.T) {
	root, _, _, request, inventory := awsGrantedRecoveryFixture(t)
	ctx, bootstrap, locks := copyPreparationAssemblyFixture(t, root)
	request.execution = executionPolicy{Resolved: executionCapacity{Parallel: 1, MemoryLimitMiB: 8192}}
	before := preparationRecoverySnapshot(t, root)
	prepared, err := prepareCleanup(ctx, root, bootstrap, request, io.Discard)
	if prepared != nil {
		defer func() {
			if err := prepared.close(ctx); err != nil {
				t.Error(err)
			}
		}()
	}
	if err != nil {
		t.Fatal(err)
	}
	if after := preparationRecoverySnapshot(t, root); !reflect.DeepEqual(before, after) {
		t.Fatal("cleanup preparation changed retained state")
	}
	for _, row := range []struct{ name, path string }{{"inventory", inventory}, {"limits", request.Limits}, {"source", filepath.Join(root, "core/go.mod")}} {
		t.Run(row.name, func(t *testing.T) {
			var replacement []byte
			if row.name == "inventory" {
				// Before a claim, live EX validation must refresh an eligible
				// inventory snapshot instead of using its pre-wait byte hash.
				verifyFreshInventory := func(ctx context.Context, root string) error {
					if err := prepared.verify(ctx, root); err != nil {
						return err
					}
					body, err := os.ReadFile(inventory)
					if err != nil {
						return err
					}
					if prepared.plan.Grant == nil || prepared.plan.Grant.InventorySHA256 != digestBytes(body) {
						return errors.New("cleanup grant retained the stale pre-wait inventory hash")
					}
					return nil
				}
				checkPreparedRecoveryAfterLiveWait(t, ctx, locks, root, prepared.admission(), verifyFreshInventory, row.path, nil, false)
				var image grantInventory
				if err := records.ReadJSON(inventory, &image); err != nil || len(image.Intents) == 0 {
					t.Fatal("cleanup inventory fixture unavailable", err)
				}
				if prepared.plan.Grant == nil || int(prepared.plan.Grant.TargetIndex) >= len(image.Intents) {
					t.Fatal("selected cleanup target unavailable")
				}
				image.Intents[prepared.plan.Grant.TargetIndex].State = "unknown"
				var err error
				replacement, err = json.Marshal(image)
				if err != nil {
					t.Fatal(err)
				}
			} else if row.name == "limits" {
				before := prepared.plan.Limits
				checkPreparedRecoveryAfterLiveWait(t, ctx, locks, root, prepared.admission(), prepared.verify, row.path, nil, false)
				if prepared.plan.Limits != before {
					t.Fatal("format-only edit changed the accepted cleanup limits")
				}
				increased := before
				increased.CleanupSeconds = uint64(prepared.class.CleanupSeconds) + 1
				if !increased.valid() {
					t.Fatal("increased cleanup allowance is not a valid limits fixture")
				}
				var err error
				replacement, err = json.Marshal(increased)
				if err != nil {
					t.Fatal(err)
				}
			}
			checkPreparedRecoveryAfterLiveWait(t, ctx, locks, root, prepared.admission(), prepared.verify, row.path, replacement, row.name != "source")
		})
	}
}

// full_only: false

// full_only: false
func TestPreparedLiveInventoryCorrespondsToRunOwnedAssembly(t *testing.T) {
	root := sourceFixtureRoot(t)
	ctx, bootstrap, _ := copyPreparationAssemblyFixture(t, root)
	phaseCtx, phase, err := localPreparationPhase(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := closeLocalPreparationPhase(ctx, phase, true); err != nil {
			t.Error(err)
		}
	}()
	ctx = phaseCtx
	prepared, err := prepareLivePreflight(ctx, root, bootstrap, "gcp", executionPolicy{Resolved: executionCapacity{Parallel: 1, MemoryLimitMiB: 8192}})
	if prepared != nil {
		defer func() {
			if err := prepared.close(ctx); err != nil {
				t.Error(err)
			}
		}()
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "tests/live/runs")); !os.IsNotExist(err) {
		t.Fatal("unbound inventory created a durable live run", err)
	}
	for _, name := range []string{"unchanged", "optional-bindings", "same-class-added-source"} {
		change := name == "same-class-added-source"
		t.Run(name, func(t *testing.T) {
			calls := 0
			admitted := context.WithValue(ctx, rootAdmitterContextKey{}, rootAdmitter(func(ctx context.Context, request rootAdmission) (context.Context, error) {
				calls++
				if !request.Live {
					return ctx, errors.New("live class missing")
				}
				return withExecutionParallel(ctx, 1), nil
			}))
			admitted, err := admitPreparedExecution(admitted, prepared.class)
			if err != nil || calls != 1 {
				t.Fatal("actual assembly began without admission", err, calls)
			}
			if change {
				writeLocalGoFixture(t, root, "tests/live/providers/gcp/prepared_added_test.go", "package core\nimport \"testing\"\n// full_only: false\nfunc TestPreparedAddedProviderRoot(t *testing.T){t.Fatal(\"correspondence executed a body\")}\n")
			}
			source, err := sourceIdentity(admitted, root)
			if err != nil {
				t.Fatal(err)
			}
			state, err := newRunState(root, runRequest{Suite: "live", Provider: "gcp", Target: "gcp", execution: executionPolicy{Resolved: executionCapacity{Parallel: 1, MemoryLimitMiB: 8192}}}, source, prepared.binding.toolchain)
			if err != nil {
				t.Fatal(err)
			}
			protected, err := state.privateOwner.protectedFixtureContext(admitted)
			if err != nil {
				t.Fatal(err)
			}
			directory := filepath.Join(state.private, "build")
			if err := os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			var actual assembly
			if name == "optional-bindings" {
				// These builders only compile local artifacts. No plugin, public
				// consumer, controlled preflight or cloud worker is executed.
				generator, buildErr := buildCloudflareArtifacts(protected, root, directory)
				if buildErr != nil {
					t.Fatal(buildErr)
				}
				binding, bindingErr := cloudflareBinding(generator, strings.Repeat("a", 32))
				if bindingErr != nil {
					t.Fatal(bindingErr)
				}
				environmentPath, input := mixedOutputInput(t, "gcp")
				environment, loadErr := loadOutputEnvironment(t, environmentPath, input)
				if loadErr != nil {
					t.Fatal(loadErr)
				}
				schedule, resolveErr := catalog.Resolve(catalog.Request{Include: []string{"publication.github-repository.plain-secret-lifecycle/plain1_secret1_create_value_inherited_policy_delete"}, Repetitions: 1})
				if resolveErr != nil {
					t.Fatal(resolveErr)
				}
				selected, selectionErr := selectPublicationOutputs(schedule, environment)
				if selectionErr != nil {
					t.Fatal(selectionErr)
				}
				outputs, bindingErr := publicationAssemblyBindings(state.record.RunID, selected)
				if bindingErr != nil || len(outputs) != 1 {
					t.Fatal("optional output fixture did not select one RunID-bound catalog row", bindingErr)
				}
				actual, err = buildBoundAssemblyMode(runGoEnvironment, nil, protected, root, "live", "gcp", bootstrap, directory, raceEnabled(protected), assemblyBindings{Cloudflare: binding, Output: outputs})
				if err != nil {
					t.Fatal(err)
				}
				retained, retainedErr := retainedOutputBindings(actual.Closure.OutputArtifacts)
				if retainedErr != nil || !slices.Equal(retained, outputs) {
					t.Fatal("actual source-verified catalog lost its RunID binding", retainedErr)
				}
				binary, readErr := os.ReadFile(actual.Binary)
				if readErr != nil || !bytes.Contains(binary, []byte(digestBytes(binding.Installation))) || !bytes.Contains(binary, []byte(digestBytes(binding.Dependency))) {
					t.Fatal("actual binary omitted the real generator source/artifact binding", readErr)
				}
			} else {
				actual, err = buildAssembly(runGoEnvironment, nil, protected, root, "live", "gcp", bootstrap, directory)
				if err != nil {
					t.Fatal(err)
				}
			}
			if actual.Binary == prepared.inventory.Binary || !strings.HasPrefix(actual.Binary, state.private+string(filepath.Separator)) {
				t.Fatal("actual assembly lost its RunID-owned private artifact")
			}
			if err := checkAssemblyRace(protected, actual); err != nil {
				t.Fatal("actual artifact identity refused", err)
			}
			correspondenceErr := prepared.bindActual(protected, root, &actual)
			if correspondenceErr != nil {
				t.Fatal("compatible actual assembly was refused", correspondenceErr)
			}
			environment := append(workerEnvironment(""), failureSourcesEnvironment(actual.FailureSources)...)
			inventory, err := prepareCompiledInventory(protected, root, actual, environment, "actual-inventory", nil)
			if err != nil {
				t.Fatal("actual binary inventory did not complete and join", err)
			}
			wantNames := slices.Clone(prepared.compiled)
			wantClasses := slices.Clone(prepared.classifications)
			if change {
				wantNames = append(wantNames, "TestPreparedAddedProviderRoot")
				fullOnly := false
				wantClasses = append(wantClasses, testClassification{Name: "TestPreparedAddedProviderRoot", FullOnly: &fullOnly})
			}
			slices.Sort(wantNames)
			actualNames := slices.Clone(inventory.names)
			slices.Sort(actualNames)
			slices.SortFunc(wantClasses, func(left, right testClassification) int { return strings.Compare(left.Name, right.Name) })
			actualClasses := slices.Clone(inventory.classifications)
			slices.SortFunc(actualClasses, func(left, right testClassification) int { return strings.Compare(left.Name, right.Name) })
			if !slices.Equal(wantNames, actualNames) || !sameTestClassifications(wantClasses, actualClasses) {
				t.Fatal("actual binary lost its complete compiled inventory or classification", actualNames)
			}
			big, err := selectedRootsBig(componentPackage, []string{"TestLiveCleanup"}, actualClasses)
			if err != nil || big != prepared.class.Big {
				t.Fatal("actual cleanup selection did not preserve the admission class", err)
			}
		})
	}
}

// full_only: false
func TestPreparedWorkflowScopesMemoryPolicyToActiveWork(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "")
	for _, row := range []struct {
		name     string
		explicit int
		want     int
	}{{"default", 0, 24576}, {"explicit-ceiling", 12000, 12000}} {
		t.Run(row.name, func(t *testing.T) {
			root := sourceFixtureRoot(t)
			ctx, bootstrap, _ := copyPreparationAssemblyFixture(t, root)
			marker := filepath.Join(t.TempDir(), "tiny-big-body")
			t.Setenv("ENKV_PREPARATION_BIG_POLICY_WITNESS", marker)
			writeLocalGoFixture(t, root, "telemetry/witness/prepared_policy_test.go", `package witness
import("flag";"os";"testing")
// full_only: true
// exclusive: true
func TestBig(t *testing.T){if err:=os.WriteFile(os.Getenv("ENKV_PREPARATION_BIG_POLICY_WITNESS"),[]byte(flag.Lookup("test.parallel").Value.String()),0600);err!=nil{t.Fatal(err)}}
// full_only: false
func TestNormalAfter(t *testing.T) {}
`)
			suite, environment := filepath.Join(root, "selected-suite.json"), filepath.Join(root, "selected-environment.json")
			saveSelection(t, suite, suiteFixture("tiny-normal", []string{"state.single-value-update-preserves-other-values/members_32"}))
			saveSelection(t, environment, memoryEnvironment())
			path := filepath.Join(root, "mixed-workflow.json")
			execution := map[string]int{"parallel": 1}
			if row.explicit != 0 {
				execution["memory_limit_mib"] = row.explicit
			}
			saveSelection(t, path, map[string]any{"schema_version": 1, "name": "mixed-admitted-policy", "profile": "full", "execution": execution, "steps": []any{
				map[string]any{"id": "normal", "kind": "run", "suites": []string{suite}, "environment": environment, "recovery_mode": "both"},
				map[string]any{"id": "big", "kind": "unit", "packages": []string{"telemetry/witness"}, "package": "telemetry/witness", "tests": singleTestRequest("TestBig")},
				map[string]any{"id": "normal-after", "kind": "unit", "packages": []string{"telemetry/witness"}, "package": "telemetry/witness", "tests": singleTestRequest("TestNormalAfter")},
			}})
			plan, err := resolveWorkflow(ctx, root, workflowRequest{Path: path, Race: true})
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := prepareWorkflow(ctx, root, bootstrap, plan, io.Discard)
			if prepared != nil {
				defer func() {
					if err := prepared.close(ctx); err != nil {
						t.Error(err)
					}
				}()
			}
			if err != nil {
				t.Fatal(err)
			}
			normal := prepared.suites[workflowPreparationKey(plan.Steps[0])]
			if normal == nil || normal.class.Big {
				t.Fatal("mixed workflow lacks its actual normal-class suite owner")
			}
			var classes []bool
			ctx = context.WithValue(ctx, rootAdmitterContextKey{}, rootAdmitter(func(ctx context.Context, admission rootAdmission) (context.Context, error) {
				want := normalExecutionMemoryMiB
				if admission.Big {
					want = row.want
				}
				if admission.Execution.Resolved.Parallel != 1 || admission.Execution.Resolved.MemoryLimitMiB != want {
					return ctx, errors.New("active work memory policy differs")
				}
				if len(classes) == 0 || classes[len(classes)-1] != admission.Big {
					classes = append(classes, admission.Big)
				}
				return withExecutionCapacity(ctx, admission.Execution), nil
			}))
			admitted, err := admitPreparedExecution(ctx, prepared.admission())
			if err != nil {
				t.Fatal(err)
			}
			result, err := runPreparedWorkflow(admitted, root, bootstrap, prepared, io.Discard)
			if err != nil {
				t.Fatal("tiny actual mixed workflow failed", err)
			}
			if !slices.Equal(classes, []bool{false, true, false}) || result.Outcome != "passed" || result.Execution.Resolved.Parallel != 1 || result.Execution.Resolved.MemoryLimitMiB != normalExecutionMemoryMiB {
				t.Fatal("prepared workflow lost its scoped memory phases", classes, result.Execution)
			}
			nested := result.executions["normal"].Suite
			if nested == nil || nested.Outcome != "passed" || nested.Execution.Resolved.Parallel != 1 || nested.Execution.Resolved.MemoryLimitMiB != normalExecutionMemoryMiB {
				t.Fatal("normal nested suite inherited later exclusive memory allowance")
			}
			if row.explicit != 0 && (result.Execution.Requested.MemoryLimitMiB == nil || *result.Execution.Requested.MemoryLimitMiB != row.explicit || nested.Execution.Requested.MemoryLimitMiB == nil || *nested.Execution.Requested.MemoryLimitMiB != row.explicit) {
				t.Fatal("mixed workflow lost explicit requested ceiling")
			}
			body, err := os.ReadFile(marker)
			if err != nil || string(body) != "1" {
				t.Fatal("tiny compiled full-only witness did not execute with assigned share1", err, string(body))
			}
		})
	}
}

// full_only: false
func TestPreparedSuiteKeepsAdmittedBigMemoryPolicy(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "")
	root := sourceFixtureRoot(t)
	ctx, bootstrap, _ := copyPreparationAssemblyFixture(t, root)
	// The controlled fixture selects the same tiny maintained hermetic worker
	// body, with an explicit big classification. It allocates no maximum proof.
	path := filepath.Join(root, "tests/hermetic/run_test.go")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	anchor := "// full_only: false\nfunc TestHermeticRun(test *testing.T)"
	if strings.Count(string(body), anchor) != 1 {
		t.Fatal("hermetic worker declaration changed")
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(body), anchor, "// full_only: false\n// exclusive: true\nfunc TestHermeticRun(test *testing.T)", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	suite, environment := filepath.Join(root, "selected-suite.json"), filepath.Join(root, "selected-environment.json")
	saveSelection(t, suite, suiteFixture("tiny-big", []string{"state.single-value-update-preserves-other-values/members_32"}))
	saveSelection(t, environment, memoryEnvironment())
	for _, row := range []struct {
		name     string
		explicit int
		want     int
	}{{"default", 0, 24576}, {"explicit-ceiling", 12000, 12000}} {
		t.Run(row.name, func(t *testing.T) {
			args := []string{"run", "--race", "--suite", suite, "--environment", environment}
			if row.explicit != 0 {
				args = append(args, fmt.Sprintf("--memory-limit-mib=%d", row.explicit))
			}
			request, err := parseRunRequest(args)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := prepareSuite(nil, ctx, root, bootstrap, request, io.Discard)
			if prepared != nil {
				defer func() {
					if err := prepared.close(ctx); err != nil {
						t.Error(err)
					}
				}()
			}
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			control := context.WithValue(ctx, rootAdmitterContextKey{}, rootAdmitter(func(ctx context.Context, admission rootAdmission) (context.Context, error) {
				calls++
				if !admission.Big || admission.Live || admission.Execution.Resolved.Parallel != 1 || admission.Execution.Resolved.MemoryLimitMiB != row.want {
					return ctx, errors.New("suite big root admission policy differs")
				}
				return withExecutionCapacity(ctx, admission.Execution), nil
			}))
			admitted, err := admitPreparedExecution(control, prepared.admission())
			if err != nil {
				t.Fatal(err)
			}
			result, err := runPreparedSuite(admitted, root, bootstrap, prepared, io.Discard)
			if err != nil {
				t.Fatal("tiny actual hermetic suite failed", err)
			}
			if calls != 1 || result.Record == nil || result.Record.Outcome != "passed" || len(result.Record.Scenarios) == 0 || result.Record.Execution.Resolved.Parallel != 1 || result.Record.Execution.Resolved.MemoryLimitMiB != row.want {
				t.Fatal("prepared suite reset the final admitted policy", calls, result.Record)
			}
			if row.explicit != 0 && (result.Record.Execution.Requested.MemoryLimitMiB == nil || *result.Record.Execution.Requested.MemoryLimitMiB != row.explicit) {
				t.Fatal("suite lost explicit requested ceiling")
			}
		})
	}
}

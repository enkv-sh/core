package records

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// full_only: false
func TestGeneratorFixtureLedgerConcurrentUpdatesKeepEveryEnteredAttempt(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "generator-cleanup.json")
	runID, account := strings.Repeat("a", 32), strings.Repeat("b", 32)
	if err := NewGeneratorFixtureLedger(path, runID, account); err != nil {
		t.Fatal(err)
	}
	const count = 16
	start := make(chan struct{})
	errors := make(chan error, count)
	var joined sync.WaitGroup
	for index := range count {
		joined.Add(1)
		go func() {
			defer joined.Done()
			<-start
			errors <- UpdateGeneratorFixtureLedger(path, runID, account, func(ledger *GeneratorFixtureLedger) error {
				// Widen the read/replace overlap. Every successful caller must
				// survive in the one durable ledger image.
				time.Sleep(5 * time.Millisecond)
				return ledger.BeginCreate(fmt.Sprintf("%064x", index+1))
			})
		}()
	}
	close(start)
	joined.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	ledger, err := ReadGeneratorFixtureLedger(path, runID, account)
	if err != nil || len(ledger.PendingCreates) != count {
		t.Fatal("successful concurrent entries lost durable intent", len(ledger.PendingCreates), err)
	}
	assertGeneratorFixtureAttempts(t, ledger.PendingCreates, count)
}

// full_only: false
func TestGeneratorFixtureLedgerPersistsIntentBeforeEffectAndExactRetirement(t *testing.T) {
	runID, account := strings.Repeat("a", 32), strings.Repeat("b", 32)
	create := strings.Repeat("c", 64)
	deleteAttempt := strings.Repeat("d", 64)
	resource := strings.Repeat("e", 32)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "generator-cleanup.json")
	if err := NewGeneratorFixtureLedger(path, runID, account); err != nil {
		t.Fatal(err)
	}
	change := func(fn func(*GeneratorFixtureLedger) error) error {
		return UpdateGeneratorFixtureLedger(path, runID, account, fn)
	}
	if err := change(func(ledger *GeneratorFixtureLedger) error { return ledger.BeginCreate(create) }); err != nil {
		t.Fatal("possible create intent not durable", err)
	}
	ledger, err := ReadGeneratorFixtureLedger(path, runID, account)
	if err != nil || len(ledger.PendingCreates) != 1 || ledger.Clean() || len(ledger.CleanupTargets()) != 0 {
		t.Fatal("unknown create became clean or owned", err)
	}
	if change(func(ledger *GeneratorFixtureLedger) error { return ledger.BeginCreate(create) }) == nil ||
		change(func(ledger *GeneratorFixtureLedger) error { return ledger.RecordCreate(deleteAttempt, resource) }) == nil {
		t.Fatal("duplicate or mismatched create attempt admitted")
	}
	// A qualified known-unusable provider result still yields an exact fixture
	// cleanup target. Product admission makes its own independent decision.
	if err := change(func(ledger *GeneratorFixtureLedger) error { return ledger.RecordCreate(create, resource) }); err != nil {
		t.Fatal("known returned identity lost", err)
	}
	ledger, err = ReadGeneratorFixtureLedger(path, runID, account)
	if err != nil || len(ledger.PendingCreates) != 0 || ledger.Clean() || len(ledger.CleanupTargets()) != 1 || ledger.CleanupTargets()[0] != resource {
		t.Fatal("exact known ID not retained for cleanup", err)
	}
	if change(func(ledger *GeneratorFixtureLedger) error {
		return ledger.BeginDelete(deleteAttempt, strings.Repeat("f", 32))
	}) == nil ||
		change(func(ledger *GeneratorFixtureLedger) error { return ledger.RecordDelete(deleteAttempt, resource) }) == nil {
		t.Fatal("unknown target or absent delete attempt admitted")
	}
	if err := change(func(ledger *GeneratorFixtureLedger) error { return ledger.BeginDelete(deleteAttempt, resource) }); err != nil {
		t.Fatal("exact delete intent not durable", err)
	}
	ledger, err = ReadGeneratorFixtureLedger(path, runID, account)
	if err != nil || ledger.Clean() || len(ledger.Resources[0].DeleteAttempts) != 1 {
		t.Fatal("unknown delete result erased residue", err)
	}
	if change(func(ledger *GeneratorFixtureLedger) error { return ledger.BeginDelete(deleteAttempt, resource) }) == nil ||
		change(func(ledger *GeneratorFixtureLedger) error {
			return ledger.RecordDelete(deleteAttempt, strings.Repeat("f", 32))
		}) == nil {
		t.Fatal("duplicate attempt or mismatched ACK admitted")
	}
	if err := change(func(ledger *GeneratorFixtureLedger) error { return ledger.RecordDelete(deleteAttempt, resource) }); err != nil {
		t.Fatal("exact ACK could not retire fixture", err)
	}
	ledger, err = ReadGeneratorFixtureLedger(path, runID, account)
	if err != nil || !ledger.Clean() || len(ledger.CleanupTargets()) != 0 {
		t.Fatal("exact ACK left fixture owned", err)
	}
}

// full_only: false
func TestGeneratorFixtureCleanupRequiresWriterGroupJoinProof(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "writer-joined.json")
	runID, scenario := strings.Repeat("a", 32), "generated.retirement-acknowledgement-closes/one_current_one_retiring_manual_ack"
	if ReadGeneratorFixtureJoined(path, runID, scenario) == nil {
		t.Fatal("missing group join proof admitted")
	}
	if err := WriteGeneratorFixtureJoined(path, runID, scenario); err != nil ||
		ReadGeneratorFixtureJoined(path, runID, scenario) != nil ||
		ReadGeneratorFixtureJoined(path, runID, "generated.auto-retirement-acknowledgement-closes/one_current_one_retiring_auto_ack") == nil {
		t.Fatal("group join proof lost or escaped exact scenario", err)
	}
}

// full_only: false
func TestGeneratorFixtureLedgerInitializationCannotReplaceEnteredState(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "generator-cleanup.json")
	runID, account := strings.Repeat("a", 32), strings.Repeat("b", 32)
	if NewGeneratorFixtureLedger(path, runID, account) != nil {
		t.Fatal("initial ledger unavailable")
	}
	if err := UpdateGeneratorFixtureLedger(path, runID, account, func(l *GeneratorFixtureLedger) error { return l.BeginCreate(strings.Repeat("c", 64)) }); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if NewGeneratorFixtureLedger(path, runID, account) == nil {
		t.Fatal("initialization replaced an existing ledger")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("refused initialization changed entered state", err)
	}
}

// full_only: false
func TestGeneratorFixtureLedgerCrossProcessRestartAndContention(t *testing.T) {
	const childVariable = "ENKV_GENERATOR_LEDGER_UPDATE_TEST"
	runID, account := strings.Repeat("a", 32), strings.Repeat("b", 32)
	if path := os.Getenv(childVariable); path != "" {
		if err := UpdateGeneratorFixtureLedger(path, runID, account, func(l *GeneratorFixtureLedger) error {
			time.Sleep(10 * time.Millisecond)
			return l.BeginCreate(os.Getenv("ENKV_GENERATOR_LEDGER_ATTEMPT_TEST"))
		}); err != nil {
			t.Fatal("child ledger update refused", err)
		}
		return
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "generator-cleanup.json")
	if NewGeneratorFixtureLedger(path, runID, account) != nil {
		t.Fatal("initial ledger unavailable")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const count = 8
	type ledgerChild struct {
		index   int
		command *exec.Cmd
		joined  bool
	}
	children := make([]ledgerChild, 0, count)
	joinChildren := func() error {
		var result error
		for index := range children {
			child := &children[index]
			if !child.joined {
				child.joined = true
				if err := child.command.Wait(); err != nil {
					result = errors.Join(result, fmt.Errorf("ledger child index=%d stage=wait: %w", child.index, err))
				}
			}
		}
		return result
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer func() {
		cancel()
		if err := joinChildren(); err != nil && !t.Failed() {
			t.Error("ledger child cleanup failed", err)
		}
	}()
	for index := range count {
		child := exec.CommandContext(ctx, executable, "-test.run=^TestGeneratorFixtureLedgerCrossProcessRestartAndContention$", "-test.count=1", "-test.parallel=1")
		child.Env = append(os.Environ(), childVariable+"="+path, "ENKV_GENERATOR_LEDGER_ATTEMPT_TEST="+fmt.Sprintf("%064x", index+1))
		if err := child.Start(); err != nil {
			cancel()
			t.Fatal("ledger child start failed after joining prior children", errors.Join(fmt.Errorf("ledger child index=%d stage=start: %w", index, err), joinChildren()))
		}
		children = append(children, ledgerChild{index: index, command: child})
	}
	if err := joinChildren(); err != nil {
		t.Fatal("independent ledger processes joined with failure", err)
	}
	ledger, err := ReadGeneratorFixtureLedger(path, runID, account)
	if err != nil || len(ledger.PendingCreates) != count {
		t.Fatal("independent successful updates lost intent", err)
	}
	assertGeneratorFixtureAttempts(t, ledger.PendingCreates, count)
	// A separate process can restart after every prior descriptor has closed.
	restarted := exec.CommandContext(ctx, executable, "-test.run=^TestGeneratorFixtureLedgerCrossProcessRestartAndContention$", "-test.count=1", "-test.parallel=1")
	restarted.Env = append(os.Environ(), childVariable+"="+path, "ENKV_GENERATOR_LEDGER_ATTEMPT_TEST="+fmt.Sprintf("%064x", count+1))
	if err := restarted.Run(); err != nil {
		t.Fatal("restarted ledger process failed", err)
	}
	ledger, err = ReadGeneratorFixtureLedger(path, runID, account)
	if err != nil || len(ledger.PendingCreates) != count+1 {
		t.Fatal("restart lost durable entries", err)
	}
	assertGeneratorFixtureAttempts(t, ledger.PendingCreates, count+1)
	// An occupied cross-process lock has a finite refusal, never false success.
	lock, err := os.OpenFile(path+".lock", os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := lock.Close(); err != nil {
			t.Error("ledger test lock close failed", err)
		}
	}()
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		t.Fatal("test lock unavailable")
	}
	started := time.Now()
	err = UpdateGeneratorFixtureLedger(path, runID, account, func(l *GeneratorFixtureLedger) error { return l.BeginCreate(strings.Repeat("f", 64)) })
	elapsed := time.Since(started)
	if err == nil || elapsed > 3*time.Second {
		t.Fatal("occupied ledger lock did not refuse within its bound", elapsed, err)
	}
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) != nil {
		t.Fatal("test lock release failed")
	}
	if err := UpdateGeneratorFixtureLedger(path, runID, account, func(l *GeneratorFixtureLedger) error { return l.BeginCreate(strings.Repeat("f", 64)) }); err != nil {
		t.Fatal("refused caller leaked the update lock", err)
	}
	ledger, err = ReadGeneratorFixtureLedger(path, runID, account)
	expected := make([]string, count+1)
	for index := range expected {
		expected[index] = fmt.Sprintf("%064x", index+1)
	}
	expected = append(expected, strings.Repeat("f", 64))
	slices.Sort(expected)
	actual := slices.Clone(ledger.PendingCreates)
	slices.Sort(actual)
	if err != nil || len(actual) != count+2 || !slices.Equal(actual, expected) {
		t.Fatal("post-contention success changed the exact durable Attempt set", err, actual, expected)
	}

}

func assertGeneratorFixtureAttempts(t testing.TB, actual []string, count int) {
	t.Helper()
	expected := make([]string, count)
	for index := range count {
		expected[index] = fmt.Sprintf("%064x", index+1)
	}
	actual = slices.Clone(actual)
	slices.Sort(actual)
	slices.Sort(expected)
	if !slices.Equal(actual, expected) {
		t.Fatal("durable entered Attempt ID set differs", actual, expected)
	}
}

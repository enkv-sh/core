package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const reconstructionPreparationWitness = "ENKV_RECONSTRUCTION_PREPARATION_WITNESS"

func reconstructionPreparationFixture(t *testing.T) (context.Context, string, string, runRequest, string, *resourceLocks) {
	t.Helper()
	root := sourceFixtureRoot(t)
	ctx, bootstrap, locks := copyPreparationAssemblyFixture(t, root)
	marker := filepath.Join(t.TempDir(), "selected-helper-entered")
	t.Setenv(reconstructionPreparationWitness, marker)
	for _, row := range []struct{ file, name string }{
		{"tests/shared/configuration_recovery_fixture_test.go", "TestConfigurationRecoveryFixtureProcess"},
		{"compositions/aws/reconstruction_process_test.go", "TestConfigurationRecoveryResourceOwner"},
		{"compositions/aws/reconstruction_process_test.go", "TestRestrictedAWSReconstructionFromConsoleInputs"},
		{"providers/gcp/reconstruction_process_external_test.go", "TestConfigurationRecoveryResourceOwner"},
		{"providers/gcp/reconstruction_process_external_test.go", "TestRestrictedGCPReconstructionFromConsoleInputs"},
	} {
		path := filepath.Join(root, row.file)
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		declaration := "func " + row.name + "(t *testing.T) {"
		if strings.Count(string(body), declaration) != 1 {
			t.Fatal("selected helper declaration changed", row.name)
		}
		witness := declaration + "\n if path := os.Getenv(\"" + reconstructionPreparationWitness + "\"); path != \"\" { if err := os.WriteFile(path, []byte(\"entered\"), 0600); err != nil { t.Fatal(err) }; t.Fatal(\"preparation entered a selected reconstruction helper\") }\n"
		if err := os.WriteFile(path, []byte(strings.Replace(string(body), declaration, witness, 1)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	suite, environment := filepath.Join(root, "reconstruction-suite.json"), filepath.Join(root, "reconstruction-environment.json")
	saveSelection(t, suite, suiteFixture("reconstruction-preparation", []string{"reconstruction.complete/complete_loss_complete"}))
	saveSelection(t, environment, memoryEnvironment())
	request, err := resolveSavedRun([]string{suite}, environment, "", "", "both", "", "", "", 1, false)
	if err != nil {
		t.Fatal(err)
	}
	request.Resolved.Race = raceEnabled(ctx)
	request.execution = executionPolicy{Resolved: executionCapacity{Parallel: 1, MemoryLimitMiB: 8192}}
	return ctx, root, bootstrap, request, marker, locks
}

func reconstructionPreparationHasNoBody(t *testing.T, marker string) {
	t.Helper()
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("preparation entered a reconstruction helper", err)
	}
}

// full_only: false
func TestPreparedReconstructionClassifiesOnlyActualHelpers(t *testing.T) {
	for _, row := range []struct {
		name, file, helper string
		big, missing       bool
		fullOnly           bool
	}{
		{name: "normal"},
		{"core-fixture-big", "tests/shared/configuration_recovery_fixture_test.go", "TestConfigurationRecoveryFixtureProcess", true, false, false},
		{"aws-parent-big", "compositions/aws/reconstruction_process_test.go", "TestRestrictedAWSReconstructionFromConsoleInputs", true, false, false},
		{"gcp-resource-big", "providers/gcp/reconstruction_process_external_test.go", "TestConfigurationRecoveryResourceOwner", true, false, false},
		{"unselected-control-big", "compositions/aws/reconstruction_process_test.go", "TestConfigurationRecoveryLiveParentControl", false, false, false},
		{"full-only-normal", "tests/shared/configuration_recovery_fixture_test.go", "TestConfigurationRecoveryFixtureProcess", false, false, true},
		{"missing-core-fixture", "tests/shared/configuration_recovery_fixture_test.go", "TestConfigurationRecoveryFixtureProcess", false, true, false},
		{"missing-aws-parent", "compositions/aws/reconstruction_process_test.go", "TestRestrictedAWSReconstructionFromConsoleInputs", false, true, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			ctx, root, bootstrap, request, marker, _ := reconstructionPreparationFixture(t)
			if row.helper != "" {
				path := filepath.Join(root, row.file)
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				from := "// full_only: false\nfunc " + row.helper + "("
				to := "// full_only: false\n// exclusive: true\nfunc " + row.helper + "("
				if row.fullOnly {
					to = "// full_only: true\nfunc " + row.helper + "("
				}
				if row.missing {
					to = "// full_only: false\nfunc " + row.helper + "Missing("
				}
				if strings.Count(string(body), from) != 1 {
					t.Fatal("selected helper classification changed", row.helper)
				}
				if err := os.WriteFile(path, []byte(strings.Replace(string(body), from, to, 1)), 0600); err != nil {
					t.Fatal(err)
				}
			}
			admissions := 0
			ctx = context.WithValue(ctx, rootAdmitterContextKey{}, rootAdmitter(func(ctx context.Context, admission rootAdmission) (context.Context, error) {
				admissions++
				return ctx, errors.New("preparation called root admission")
			}))
			prepared, err := prepareSuite(nil, ctx, root, bootstrap, request, io.Discard)
			if prepared != nil {
				defer func() {
					if err := prepared.close(ctx); err != nil {
						t.Error(err)
					}
				}()
			}
			reconstructionPreparationHasNoBody(t, marker)
			if admissions != 0 {
				t.Fatal("preparation admitted before returning complete selection")
			}
			if row.missing {
				if err == nil || !strings.Contains(err.Error(), "compiled inventory") || !toolCommandsJoined(err) || !sourceCommandsJoined(err) || ctx.Err() != nil {
					t.Fatal("missing selected reconstruction helper was not refused by compiled inventory", err)
				}
				return
			}
			if err != nil {
				t.Fatal("complete reconstruction preparation failed", err)
			}
			if prepared.admission().Big != row.big {
				t.Fatal("actual reconstruction helper union has the wrong resource class", prepared.admission().Big, row.big)
			}
			if err := prepared.verify(ctx, root); err != nil {
				t.Fatal("unchanged reconstruction preparation failed verification", err)
			}
			reconstructionPreparationHasNoBody(t, marker)
		})
	}
}

// full_only: false
func TestPreparedReconstructionKeepsBuildsAfterMachineWaitEdits(t *testing.T) {
	for _, which := range []string{"provider-bytes", "same-class-provider-root", "crypto-overlay-member"} {
		t.Run(which, func(t *testing.T) {
			ctx, root, bootstrap, request, marker, locks := reconstructionPreparationFixture(t)
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
			if err := prepared.verify(ctx, root); err != nil {
				t.Fatal("unchanged reconstruction preparation failed", err)
			}
			path := filepath.Join(root, "compositions/aws/reconstruction_process_test.go")
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			replacement := append([]byte(nil), original...)
			switch which {
			case "provider-bytes":
				replacement = append(replacement, []byte("\n// selected provider bytes changed\n")...)
			case "same-class-provider-root":
				from := "func TestRestrictedAWSReconstructionFromConsoleInputs("
				if strings.Count(string(original), from) != 1 {
					t.Fatal("selected provider root declaration changed")
				}
				replacement = []byte(strings.Replace(string(original), from, "func TestRestrictedAWSReconstructionFromConsoleInputsChanged(", 1))
			case "crypto-overlay-member":
				path = filepath.Join(root, "tests/crypto/prepared_reconstruction_added_test.go")
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("new Crypto overlay member already exists", err)
				}
				original = nil
				replacement = []byte("package crypto\nimport \"testing\"\n// full_only: false\nfunc TestPreparedReconstructionAddedCryptoMember(t *testing.T) {}\n")
			}
			held, err := locks.acquireMachine(ctx, true)
			if err != nil {
				t.Fatal(err)
			}
			defer held.Close()
			wait, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			ready, joined := make(chan struct{}), make(chan error, 1)
			var acquired *resourceLease
			admissions := 0
			wait = context.WithValue(wait, rootAdmitterContextKey{}, rootAdmitter(func(ctx context.Context, admission rootAdmission) (context.Context, error) {
				admissions++
				if admission.Execution.Resolved.Parallel != 1 || admission.Live || admission.Big {
					return ctx, errors.New("normal hermetic reconstruction lost its assigned admission policy")
				}
				close(ready)
				var err error
				acquired, err = locks.acquireMachine(ctx, admission.Big)
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
				t.Fatal("reconstruction preparation did not reach machine wait", err)
			case <-wait.Done():
				t.Fatal(wait.Err())
			}
			select {
			case err := <-joined:
				collected = true
				t.Fatal("reconstruction passed a held machine EX lock", err)
			default:
			}
			if err := os.WriteFile(path, replacement, 0600); err != nil {
				t.Fatal(err)
			}
			if err := held.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-joined:
				collected = true
				if err != nil || admissions != 1 || wait.Err() != nil || !toolCommandsJoined(err) || !sourceCommandsJoined(err) {
					t.Fatal("source edit invalidated completed reconstruction builds or admission did not join", err, admissions)
				}
			case <-wait.Done():
				t.Fatal("reconstruction verification did not join", wait.Err())
			}
			reconstructionPreparationHasNoBody(t, marker)
			if original == nil {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			if err := prepared.verify(ctx, root); err != nil {
				t.Fatal("completed reconstruction builds unavailable after restoring fixture", err)
			}
			reconstructionPreparationHasNoBody(t, marker)
		})
	}
}

package core

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/installedarchive"
)

// full_only: false
func TestRunBudgetCustodyUsesOperationBounds(t *testing.T) {
	for _, test := range []struct {
		operation string
		maximum   int
	}{
		{"init", contract.CryptoMaxRecipients + 1},
		{"compare", 2 * contract.CryptoMaxValueEntries},
		{"prepare", contract.CryptoMaxValueEntries},
		{"consume", contract.CryptoMaxValueEntries},
	} {
		t.Run(test.operation, func(t *testing.T) {
			calls := test.maximum
			if test.operation == "init" {
				calls = 3*calls + 2
			}
			budget := &runBudget{limits: liveLimits{Requests: uint64(2 * calls), BodyBytes: uint64(calls) * operationBodyAllowance}}
			for _, count := range []int{-1, 0, test.maximum + 1} {
				if budget.reserveCustody(test.operation, count) || budget.snapshot() != (budgetReservation{}) {
					t.Fatal("invalid count reserved custody calls")
				}
			}
			if !budget.reserveCustody(test.operation, test.maximum) {
				t.Fatal("valid maximum custody count was refused")
			}
			if got := budget.snapshot(); got.Requests != uint64(2*calls) || got.BodyBytes != uint64(calls)*operationBodyAllowance {
				t.Fatal("custody reservation differs from bounded provider calls")
			}
			if budget.reserveCustody(test.operation, 1) || !budget.exhausted {
				t.Fatal("custody exceeded the invocation budget")
			}
		})
	}
	budget := &runBudget{limits: liveLimits{Requests: 100, BodyBytes: 100 * operationBodyAllowance}}
	if budget.reserveCustody("unknown", 1) || budget.snapshot() != (budgetReservation{}) {
		t.Fatal("unknown operation reserved custody calls")
	}
}

type recoveryCustodyRefusalTB struct{ testing.TB }
type recoveryCustodyRefusal string

func (tb recoveryCustodyRefusalTB) Fatal(args ...any) {
	panic(recoveryCustodyRefusal(fmt.Sprint(args...)))
}

// full_only: false
func TestLiveRecoveryWriterReservesOnlyActualSecretCaptures(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for _, outcome := range []string{"empty", "secrets", "refused"} {
			t.Run(fmt.Sprintf("recovery=%t/%s", recovery, outcome), func(t *testing.T) {
				env, keys := genesisEnvironment(t, liveFamily, recovery, 3)
				store := env.Store.(*memoryStore)
				configuration := store.StoreConfiguration()
				state, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				oracle := filepath.Join(state, "oracle")
				if os.Mkdir(oracle, 0700) != nil {
					t.Fatal("oracle owner unavailable")
				}
				inventory := &objectInventory{path: filepath.Join(state, "inventory.json"), image: inventoryImage{Version: 1, Prefix: configuration.PrefixBeforeHEAD, Domain: configuration.DomainID, Deleted: make(map[string]int)}}
				budget := &runBudget{limits: liveLimits{Requests: 4096, BodyBytes: 1 << 30, Objects: 4096, ObjectBytes: 32 << 20}, keys: make(map[string]bool)}
				env.Store = recordedStore{Store: store, inventory: inventory, budget: budget}
				consumeReservations, beforePrivate := 0, 0
				env.Phase = func(phase string) {
					if phase == "transition" {
						_, beforePrivate = keys.Calls()
					}
				}
				env.ReserveCustody = func(operation string, count int) bool {
					if operation != "consume" {
						return budget.reserveCustody(operation, count)
					}
					consumeReservations++
					if outcome != "empty" && count != 3 {
						t.Fatal("capture count differs from the three selected secrets")
					}
					_, beforePrivate = keys.Calls()
					before := budget.snapshot()
					if outcome == "refused" {
						budget.limits.Requests = before.Requests
					}
					allowed := budget.reserveCustody(operation, count)
					after := budget.snapshot()
					if outcome == "secrets" && (!allowed || after.Requests-before.Requests != 6 || after.BodyBytes-before.BodyBytes != 3*operationBodyAllowance) {
						t.Fatal("selected consume allowance differs from exact finite calls")
					}
					if outcome == "refused" && (allowed || after != before) {
						t.Fatal("refused capture acquired allowance")
					}
					return allowed
				}
				condition := "complete"
				if outcome == "empty" {
					condition = "zero-secret-genesis"
				}
				input := liveRunInput{Scenarios: []string{configurationCaseForCondition(t, condition)}, Prefix: configuration.PrefixBeforeHEAD, Settings: liveSettings{Region: configuration.Region, Bucket: configuration.Bucket, Account: configuration.ExpectedOwner}, ConfigurationRecovery: &installedarchive.RecoveryWriterInput{Domain: configuration.DomainID, OracleDirectory: oracle}}
				var refusal any
				func() {
					defer func() { refusal = recover() }()
					runLiveConfigurationRecoveryWriter(recoveryCustodyRefusalTB{t}, t.Context(), env, input.Scenarios[0], state, input, inventory, budget)
				}()
				_, afterPrivate := keys.Calls()
				files, err := os.ReadDir(oracle)
				if err != nil {
					t.Fatal(err)
				}
				carrier := filepath.Join(state, "recovery-parent.json")
				if outcome == "refused" {
					if refusal != recoveryCustodyRefusal("recovery capture custody budget refused") || consumeReservations != 1 || afterPrivate != beforePrivate || len(files) != 0 || !budget.exhausted {
						t.Fatal("positive-count refusal did not stop before private capture")
					}
					if _, err := os.Stat(carrier); !os.IsNotExist(err) {
						t.Fatal("refused writer exported a carrier")
					}
					return
				}
				if refusal != nil {
					t.Fatal("actual writer unexpectedly refused")
				}
				fixture := installedarchive.ReadRecoveryFixture(t, carrier)
				if _, err := fixture.Archive.SelectedParts(); err != nil {
					t.Fatal("valid selected archive refused", err)
				}
				if outcome == "empty" {
					if consumeReservations != 0 || afterPrivate != beforePrivate || len(files) != 0 || fixture.Secrets != 0 || len(fixture.Oracles) != 0 {
						t.Fatal("empty selected state reserved or decrypted a secret")
					}
				} else if consumeReservations != 1 || afterPrivate <= beforePrivate || fixture.Secrets != 3 || len(fixture.Oracles) != 5 {
					t.Fatal("selected secrets lost custody reservation or capture")
				}
			})
		}
	}
}

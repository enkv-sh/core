package core

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"

	"enkv.sh/core/contract"
)

type gcGuardFixtureStore struct {
	*installedGuardFixtureStore
	deletes int
}

func (s *gcGuardFixtureStore) DeleteIfToken(context.Context, string, contract.Token) contract.WriteResult {
	s.deletes++
	return s.write
}

// full_only: false
func TestInstalledGCGuardRechecksCancellationAfterSource(t *testing.T) {
	for _, cancelled := range []string{"original", "physical"} {
		for _, operation := range []string{"create", "cas", "sign", "delete"} {
			t.Run(cancelled+"/"+operation, func(t *testing.T) {
				original, stopOriginal := context.WithCancel(t.Context())
				defer stopOriginal()
				physical, stopPhysical := context.WithCancel(original)
				defer stopPhysical()
				backend := &gcGuardFixtureStore{installedGuardFixtureStore: &installedGuardFixtureStore{descriptor: gcCursorTestStore(), write: contract.WriteResult{Status: contract.WriteAcknowledged}}}
				guard, err := newInstalledGCGuard(original, backend, func(context.Context) error {
					if cancelled == "original" {
						stopOriginal()
					} else {
						stopPhysical()
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
				trust := &installedGuardFixtureTrust{}
				switch operation {
				case "create":
					guard.store.Create(physical, "object", []byte{1})
				case "cas":
					guard.store.CompareAndSwap(physical, backend.Descriptor().HeadKey, contract.Token{}, []byte{1})
				case "sign":
					gcGuardTrust{guard: guard, backend: trust}.Sign(physical, contract.SignRequest{})
				case "delete":
					guard.delete(physical, &gcDeletePermission{key: "object", consumed: 1})
				}
				if len(backend.calls) != 0 || backend.deletes != 0 || trust.signs != 0 {
					t.Fatal("source callback cancellation entered backend", backend.calls, backend.deletes, trust.signs)
				}
			})
		}
	}
}

type gcScopeBorrowContext struct {
	context.Context
	onDone func()
	once   sync.Once
}

func (c *gcScopeBorrowContext) Done() <-chan struct{} {
	c.once.Do(c.onDone)
	return c.Context.Done()
}

// full_only: false
func TestInstalledGCPlanScopeValidationHoldsReaderInvocation(t *testing.T) {
	_, _, input, plan, _ := gcExecutionFixture(t)
	plan.PublicBasisDigest[0] ^= 1
	encoded, err := contract.EncodeGCPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	synctest.Test(t, func(t *testing.T) {
		closed := make(chan struct{})
		input.CloseInstalled = func() { close(closed) }
		reader, err := NewInstalledCapacityReader(input)
		if err != nil {
			t.Fatal(err)
		}
		entered := false
		ctx := &gcScopeBorrowContext{Context: gcReadContext(t)}
		ctx.onDone = func() {
			reader.reader.mu.Lock()
			active := reader.reader.activeDone != nil
			reader.reader.mu.Unlock()
			if !active {
				t.Error("scope validation entered without reader ownership")
				return
			}
			entered = true
			go reader.Close()
			synctest.Wait()
			select {
			case <-closed:
				t.Error("Close disposed public basis before scope borrower joined")
			default:
			}
		}
		validated, result := reader.ValidateGCPlan(ctx, encoded)
		reader.Close()
		<-closed
		if !entered || validated != nil || result != refused(AdmissionInvalid) {
			t.Fatal("scope mismatch bypassed guarded public basis validation", entered, result)
		}
	})
}

package crypto

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/core/contract"
)

// The gate locates the cancellation check relative to work registration.
// It does not change the underlying context's cancellation result.
type accessEntryContext struct {
	context.Context
	entered, release chan struct{}
	once             sync.Once
}

func (c *accessEntryContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return c.Context.Done()
}

// full_only: false
func TestAccessStageRetirementBeforeWorkRegistration(t *testing.T) {
	for _, name := range []string{"expired", "session-cancelled", "caller-cancelled", "used"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r, err := New(contract.GCP, nil)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(r.Close)
				deadline := time.Now().Add(time.Minute)
				if name == "expired" {
					deadline = time.Now().Add(-time.Nanosecond)
				}
				a := &accessAdmission{stage: contract.CryptoPrepare, request: contract.CryptoAccessReplaceRequest{BindingTable: []contract.BindingTableRow{{SubjectID: consumerID("retained public binding")}}}}
				clears := 0
				r.mu.Lock()
				a.session = r.installSession(consumerID("access retirement"), deadline, nil, func() {
					clears++
					a.request = contract.CryptoAccessReplaceRequest{}
				})
				r.access = a
				// Represent a successful prior stage after busy was cleared but
				// before its deferred Done. The observer must join this work.
				a.work.Add(1)
				if name == "session-cancelled" {
					a.cancel()
				}
				if name == "used" {
					a.used = true
				}
				r.mu.Unlock()
				synctest.Wait()
				r.mu.Lock()
				retained, draining := clears == 0, a.used
				r.mu.Unlock()
				if !retained || (name == "expired" || name == "session-cancelled") && !draining {
					t.Fatal("observer did not retain the draining prior stage")
				}
				caller, cancel := context.WithCancel(context.Background())
				defer cancel()
				if name == "caller-cancelled" {
					cancel()
				}
				ctx := &accessEntryContext{Context: caller, entered: make(chan struct{}), release: make(chan struct{})}
				result := make(chan contract.CryptoResponse, 1)
				go func() {
					result <- r.Exchange(ctx, contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: contract.CryptoPrepare, RequestID: consumerID("late access stage"), CustodyInstanceID: r.InstanceID()})
				}()
				<-ctx.entered
				// The caller channel is captured before the runtime lock. Keep
				// prior work registered until the late stage has been refused.
				r.mu.Lock()
				busy := a.busy
				r.mu.Unlock()
				if busy {
					t.Error("late access stage registered work before checking retirement")
				}
				close(ctx.release)
				reply := <-result
				want := contract.CryptoCancelled
				switch name {
				case "expired":
					want = contract.CryptoExpired
				case "used":
					want = contract.CryptoAlreadyUsed
				}
				if reply.ResultCode != want || len(reply.Body) != 0 || len(reply.KeyUseRows) != 0 {
					t.Errorf("late stage result=%v want=%v, body=%d key uses=%d", reply.ResultCode, want, len(reply.Body), len(reply.KeyUseRows))
				}
				r.mu.Lock()
				busy, retained = a.busy, clears == 0
				r.mu.Unlock()
				if busy || !retained {
					t.Error("late stage registered work or cleared the draining prior stage")
				}
				a.work.Done()
				r.Close()
				synctest.Wait()
				if clears != 1 || a.clear != nil || a.request.BindingTable != nil || a.busy {
					t.Fatal("retirement did not join and clear the access session exactly once")
				}
			})
		})
	}
}

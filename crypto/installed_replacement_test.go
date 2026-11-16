package crypto

import (
	"context"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

type installedReplacementBlockingPublic struct {
	*exactRecipientPublicQualifier
	entered chan struct{}
}

func (q *installedReplacementBlockingPublic) Qualify(ctx context.Context, binding contract.KMSBinding) KeyResult {
	close(q.entered)
	<-ctx.Done()
	return KeyResult{Status: KeyCancelled}
}

// full_only: false
func TestReplacementCustodyRetiresOnlyItsCapturedAdmission(t *testing.T) {
	f := newAccessCallerContextFixture(t)
	runtime, err := New(contract.GCP, []KeyAccess{f.sourceRoute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	public := &exactRecipientPublicQualifier{binding: f.intent.Successor}
	old, err := NewRecipientReplacementCustody(runtime, f.q, f.intent, f.request, f.control, nil, f.sourceRoute.CredentialRoute(), public, f.deadline)
	if err != nil {
		t.Fatal(err)
	}
	captured := old.admission
	old.Close()
	old.Close()
	nextQ := f.q
	nextQ.Context.AdmissionID = consumerID("next installed replacement admission")
	nextQ.Context.SessionID = consumerID("next installed replacement session")
	nextPublic := &exactRecipientPublicQualifier{binding: f.intent.Successor}
	next, err := NewRecipientReplacementCustody(runtime, nextQ, f.intent, f.request, f.control, nil, f.sourceRoute.CredentialRoute(), nextPublic, f.deadline)
	if err != nil {
		t.Fatal("fresh slot after positive retirement", err)
	}
	defer next.Close()
	body, err := contract.EncodeCryptoAccessReplaceRequest(nextQ)
	if err != nil {
		t.Fatal(err)
	}
	request := contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: contract.CryptoAccessReplace, RequestID: consumerID("captured owner exchange"), CustodyInstanceID: runtime.InstanceID(), Body: body}
	// This is the old-call interleaving after its caller-side check but before
	// the runtime work lock: the expected admission must still be compared there.
	stale := runtime.accessExchangeOwned(t.Context(), request, captured)
	if stale.ResultCode != contract.CryptoInvalidAdmission || nextPublic.calls != 0 {
		t.Fatal("stale captured owner entered newer admission", stale.ResultCode, nextPublic.calls)
	}
	old.Close()
	if reply := next.Exchange(t.Context(), request); reply.ResultCode != contract.CryptoSuccess || nextPublic.calls != 1 {
		t.Fatal("retired owner cancelled a newer session", reply.ResultCode, nextPublic.calls)
	}
	if reply := old.Exchange(t.Context(), request); reply.ResultCode != contract.CryptoInvalidAdmission {
		t.Fatal("closed replacement owner exchanged against newer session", reply.ResultCode)
	}
}

// full_only: false
func TestReplacementCustodyCloseCancelsAndJoinsQualification(t *testing.T) {
	f := newAccessCallerContextFixture(t)
	runtime, err := New(contract.GCP, []KeyAccess{f.sourceRoute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	public := &installedReplacementBlockingPublic{exactRecipientPublicQualifier: &exactRecipientPublicQualifier{binding: f.intent.Successor}, entered: make(chan struct{})}
	owner, err := NewRecipientReplacementCustody(runtime, f.q, f.intent, f.request, f.control, nil, f.sourceRoute.CredentialRoute(), public, f.deadline)
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeCryptoAccessReplaceRequest(f.q)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan contract.CryptoResponse, 1)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	go func() {
		done <- owner.Exchange(ctx, contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: contract.CryptoAccessReplace, RequestID: consumerID("blocked installed qualifier"), CustodyInstanceID: runtime.InstanceID(), Body: body})
	}()
	select {
	case <-public.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("owned qualification did not enter")
	}
	owner.Close()
	select {
	case result := <-done:
		if result.ResultCode == contract.CryptoSuccess {
			t.Fatal("retired qualification returned private success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("custody Close did not positively join exchange")
	}
	runtime.mu.Lock()
	active := runtime.slot != nil || runtime.access != nil
	runtime.mu.Unlock()
	if active {
		t.Fatal("retired replacement left runtime admission occupied")
	}
}

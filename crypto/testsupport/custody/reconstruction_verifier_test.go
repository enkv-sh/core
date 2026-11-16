package custody

import (
	"context"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

type observedErrContext struct {
	context.Context
	once     sync.Once
	observed chan struct{}
}

func (c *observedErrContext) Err() error {
	err := c.Context.Err()
	c.once.Do(func() { close(c.observed) })
	return err
}

// full_only: false
func TestReconstructionVerifierFacadeClosesItsIndependentRuntime(t *testing.T) {
	id := func(name string) contract.ID { return contract.Hash([]byte(name)) }
	authority, domain, snapshot := id("authority"), id("domain"), id("snapshot")
	f := New(t, contract.GCP, id("facade fixture"), false, []contract.ID{authority})
	t.Cleanup(f.Close)
	bindings := f.Bindings()
	if len(bindings) != 1 || bindings[0].SubjectID != authority {
		t.Fatal("test authority binding unavailable")
	}
	pins := contract.ReconstructionVerificationPins{
		DomainID: domain, SnapshotID: snapshot,
		HEADDigest: id("head digest"), HEADRevision: id("revision"), AccessRoot: id("access root"),
		AuthorityRecipientID: authority, AuthorityBinding: bindings[0],
		Root: contract.Ref{Kind: contract.RootKind, Format: contract.CanonicalSchema,
			Domain: domain, Object: snapshot, Digest: id("root digest"), Length: 1},
		HEADToken: contract.Token{Family: contract.GCP, Value: "1"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	verifier, err := f.ReconstructionVerifier(ctx, pins, time.Now().Add(time.Minute))
	if err != nil || verifier == nil {
		t.Fatal("independent verifier construction failed", err)
	}
	fork := verifier.fork
	verifier.Close()
	verifier.Close()
	if _, err := fork.Fork(); err == nil {
		t.Fatal("facade Close kept the private fork open")
	}
	if code := verifier.Verify(ctx, contract.ConsumerSelection{}); code == contract.CryptoSuccess {
		t.Fatal("closed facade accepted a selection")
	}
	if code := (*ReconstructionVerifier)(nil).Verify(ctx, contract.ConsumerSelection{}); code != contract.CryptoInvalidAdmission {
		t.Fatal("nil facade accepted a selection")
	}
	(*ReconstructionVerifier)(nil).Close()
}

// full_only: false
func TestReconstructionVerifierFacadeRefusesCancellationWhileWaitingForFixture(t *testing.T) {
	id := func(name string) contract.ID { return contract.Hash([]byte(name)) }
	authority, domain, snapshot := id("authority"), id("domain"), id("snapshot")
	f := New(t, contract.GCP, id("cancelled facade fixture"), false, []contract.ID{authority})
	t.Cleanup(f.Close)
	pins := contract.ReconstructionVerificationPins{
		DomainID: domain, SnapshotID: snapshot,
		HEADDigest: id("head digest"), HEADRevision: id("revision"), AccessRoot: id("access root"),
		AuthorityRecipientID: authority, AuthorityBinding: f.Bindings()[0],
		Root: contract.Ref{Kind: contract.RootKind, Format: contract.CanonicalSchema,
			Domain: domain, Object: snapshot, Digest: id("root digest"), Length: 1},
		HEADToken: contract.Token{Family: contract.GCP, Value: "1"},
	}
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &observedErrContext{Context: base, observed: make(chan struct{})}
	type construction struct {
		verifier *ReconstructionVerifier
		err      error
	}
	done := make(chan construction, 1)
	f.mu.Lock()
	locked := true
	defer func() {
		if locked {
			f.mu.Unlock()
		}
	}()
	go func() {
		verifier, err := f.ReconstructionVerifier(ctx, pins, time.Now().Add(time.Minute))
		done <- construction{verifier, err}
	}()
	select {
	case <-ctx.observed:
	case <-time.After(30 * time.Second):
		t.Fatal("facade did not read the original context before fixture admission")
	}
	cancel()
	f.mu.Unlock()
	locked = false
	var result construction
	select {
	case result = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("cancelled facade construction did not join")
	}
	if result.verifier != nil {
		result.verifier.Close()
	}
	fork, forkErr := f.runtime.Fork()
	if forkErr != nil {
		t.Fatal("cancelled construction closed the original fixture runtime", forkErr)
	}
	fork.Close()
	if result.verifier != nil || result.err == nil {
		t.Fatal("cancelled construction returned a live private verifier", result.err)
	}
}

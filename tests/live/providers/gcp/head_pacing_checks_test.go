package core

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/providers/gcp"
)

type gcpHeadAttemptStore struct {
	contract.Store
	write func(context.Context, string, contract.Token, []byte) contract.WriteResult
}

func (s gcpHeadAttemptStore) Descriptor() contract.Descriptor {
	return contract.Descriptor{HeadKey: "test-run/HEAD"}
}

func (s gcpHeadAttemptStore) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	return s.write(ctx, key, token, body)
}

type gcpHeadAttemptCredential struct {
	attempts []time.Time
}

func (c *gcpHeadAttemptCredential) Token(context.Context) (string, error) {
	c.attempts = append(c.attempts, time.Now())
	return "", errors.New("controlled credential refusal")
}

// full_only: false
func TestGCPHeadPacingSharesFixtureSelectionAndCleanup(t *testing.T) {
	env := memoryScenarioEnvironment(t)
	settings := liveSettings{Project: "test-project", ProjectNumber: "123", Region: "us-central1", Bucket: "test-bucket", KeyID: "projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1",
		PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: env.PublicKey}))}
	credentials := &gcpHeadAttemptCredential{}
	before := time.Now()
	backend, err := openGCPBackend(context.Background(), settings, "test-run", env.Domain, func(context.Context, string) (gcp.CredentialSource, error) { return credentials, nil })
	if err != nil {
		t.Fatal(err)
	}
	token := contract.Token{Family: contract.GCP, Value: "27"}
	want := contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess}
	if got := backend.Put(context.Background(), "test-run/HEAD", []byte("initial")); got != want {
		t.Fatalf("fixture refusal changed: %+v", got)
	}
	if got := backend.Store.CompareAndSwap(context.Background(), "test-run/HEAD", token, []byte("candidate")); got != want {
		t.Fatalf("selection refusal changed: %+v", got)
	}
	if err := backend.Delete(context.Background(), "test-run/HEAD", token); !errors.Is(err, errGCPDelete) {
		t.Fatalf("cleanup refusal changed: %v", err)
	}
	if len(credentials.attempts) != 3 {
		t.Fatalf("attempt count = %d, want 3", len(credentials.attempts))
	}
	for _, attempt := range credentials.attempts {
		if attempt.Sub(before) < time.Second {
			t.Fatal("backend mutation did not retain the shared HEAD interval")
		}
		before = attempt
	}
}

// full_only: false
func TestGCPHeadPacingPreservesEveryCompareAndSwapResult(t *testing.T) {
	ctx := context.Background()
	token := contract.Token{Family: contract.GCP, Value: "27"}
	body := []byte("original candidate")
	results := []contract.WriteResult{
		{Status: contract.WriteAcknowledged},
		{Status: contract.WritePrecondition, Reason: contract.ReasonCondition},
		{Status: contract.WriteConflict, Reason: contract.ReasonCondition},
		{Status: contract.WriteUnknown, Reason: contract.ReasonTransport},
		{Status: contract.WriteRefused, Reason: contract.ReasonAccess},
		{Status: contract.WriteAcknowledged},
	}
	calls := 0
	before := time.Now()
	store := &gcpActorReadStore{headWrites: newGCPHeadWriteGate(), Store: gcpHeadAttemptStore{write: func(gotCtx context.Context, key string, gotToken contract.Token, gotBody []byte) contract.WriteResult {
		if gotCtx != ctx || key != "test-run/HEAD" || gotToken != token || !bytes.Equal(gotBody, body) {
			t.Fatal("pacing changed the original conditional attempt")
		}
		if time.Since(before) < time.Second {
			t.Fatal("a prior attempt did not reserve the next HEAD interval")
		}
		if calls >= len(results) {
			t.Fatal("conditional attempt was replayed")
		}
		result := results[calls]
		calls++
		before = time.Now()
		return result
	}}}
	for _, want := range results {
		if got := store.CompareAndSwap(ctx, "test-run/HEAD", token, body); got != want {
			t.Fatalf("result changed: %+v, want %+v", got, want)
		}
	}
	if calls != len(results) {
		t.Fatalf("attempt count = %d, want %d", calls, len(results))
	}
}

// full_only: false
func TestGCPHeadPacingCancellationPreventsAllDelegateSends(t *testing.T) {
	for _, waiting := range []string{"cancelled", "interval", "ownership"} {
		t.Run(waiting, func(t *testing.T) {
			credentials := &gcpSetupCredential{}
			setup := newGCPControlledSetup(t, credentials, func(*http.Request) (*http.Response, error) {
				t.Fatal("cancelled setup mutation reached transport")
				return nil, nil
			})
			store := &gcpActorReadStore{headWrites: setup.headWrites, Store: gcpHeadAttemptStore{write: func(context.Context, string, contract.Token, []byte) contract.WriteResult {
				t.Fatal("cancelled selection reached its delegate")
				return contract.WriteResult{}
			}}}
			if waiting == "ownership" {
				setup.headWrites.busy <- struct{}{}
				defer func() { <-setup.headWrites.busy }()
			}
			for _, operation := range []string{"fixture", "selection", "cleanup"} {
				t.Run(operation, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
					defer cancel()
					if waiting == "cancelled" {
						cancel()
					}
					token := contract.Token{Family: contract.GCP, Value: "27"}
					want := contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess}
					switch operation {
					case "fixture":
						if got := setup.put(ctx, setup.head, []byte("initial")); got != want {
							t.Fatalf("cancelled fixture result changed: %+v", got)
						}
					case "selection":
						if got := store.CompareAndSwap(ctx, setup.head, token, []byte("candidate")); got != want {
							t.Fatalf("cancelled selection result changed: %+v", got)
						}
					case "cleanup":
						if err := setup.delete(ctx, setup.head, token); !errors.Is(err, errGCPDelete) {
							t.Fatalf("cancelled cleanup result changed: %v", err)
						}
					}
					if ctx.Err() == nil || credentials.calls != 0 {
						t.Fatal("cancelled wait reached credential resolution")
					}
				})
			}
		})
	}
}

// full_only: false
func TestGCPHeadPacingDoesNotBlockImmutableObjects(t *testing.T) {
	calls := 0
	setup := newGCPControlledSetup(t, &gcpSetupCredential{}, func(*http.Request) (*http.Response, error) {
		calls++
		return gcpSetupReply(http.StatusNoContent, ""), nil
	})
	setup.headWrites.busy <- struct{}{}
	defer func() { <-setup.headWrites.busy }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := setup.delete(ctx, gcpControlledRootKey(setup), contract.Token{Family: contract.GCP, Value: "27"}); err != nil || calls != 1 {
		t.Fatal("HEAD ownership blocked independent immutable cleanup")
	}
}

// full_only: false
func TestGCPGenesisHEADHonorsPacingCancellation(t *testing.T) {
	env := memoryScenarioEnvironment(t)
	store := env.Store.(*memoryStore)
	gate := newGCPHeadWriteGate()
	gate.busy <- struct{}{}
	defer func() { <-gate.busy }()
	wrapped := &gcpActorReadStore{Store: store, headWrites: gate}
	request, err := contract.NewHeadCreateRequest(store.desc, []byte("genesis HEAD"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := wrapped.CreateHead(ctx, request)
	if result.Status != contract.WriteRefused || result.Reason != contract.ReasonAccess || store.creates != 0 {
		t.Fatal("genesis HEAD bypassed the held pacing gate", result)
	}
}

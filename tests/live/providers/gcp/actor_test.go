package core

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/providers/gcp"
)

type gcpActorCredential struct {
	token string
	err   error
	calls int
}

func (c *gcpActorCredential) Token(context.Context) (string, error) {
	c.calls++
	return c.token, c.err
}

type gcpActorCredentialCall func(context.Context) (string, error)

func (f gcpActorCredentialCall) Token(ctx context.Context) (string, error) { return f(ctx) }

// full_only: false
func TestGCPActorRefusalSurvivesProviderContextIsolation(t *testing.T) {
	storeFor := func(t *testing.T, credentials *gcpActorCredentials, requests *atomic.Int32, status int) *gcpActorReadStore {
		t.Helper()
		client, err := gcp.NewLocalResponderClient(gcpInboxTransport(t, func(r *http.Request) (*http.Response, error) {
			requests.Add(1)
			if r.Method != http.MethodGet || r.Host != "storage.us-central1.rep.googleapis.com" || r.Header.Get("Authorization") != "Bearer reader-token" {
				t.Error("read changed the selected operation, host or credential")
			}
			return gcpSetupReply(status, `{"error":{"code":`+fmt.Sprint(status)+`}}`), nil
		}), credentials)
		if err != nil {
			t.Fatal("local reader client unavailable")
		}
		store, err := gcp.NewStore(t.Context(), gcp.StoreConfig{Client: client, Domain: contract.Hash([]byte("actor-refusal-domain")), Region: "us-central1", Endpoint: "https://storage.us-central1.rep.googleapis.com/storage/v1/", Bucket: "fixture-bucket", Prefix: "fixture", CredentialRoute: "test-credential"})
		if err != nil {
			t.Fatal("local reader Store unavailable")
		}
		return &gcpActorReadStore{Store: store, readStore: store, readCredentials: credentials}
	}
	for _, row := range []struct {
		name          string
		status        int
		stale, failed bool
	}{
		{"authenticated-unauthorized", 401, false, false},
		{"authenticated-forbidden", 403, false, false},
		{"credential-failure", 403, false, true},
		{"stale-token-credential-failure", 403, true, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			selected := &gcpActorCredential{token: "reader-token"}
			credentials := &gcpActorCredentials{CredentialSource: selected}
			if row.stale {
				if _, err := credentials.Token(t.Context()); err != nil {
					t.Fatal("prior authentication control failed")
				}
			}
			if row.failed {
				selected.err = errors.New("controlled credential failure")
			}
			var requests atomic.Int32
			store := storeFor(t, credentials, &requests, row.status)
			result := store.Read(t.Context(), store.Descriptor().HeadKey, 1024)
			wantRequests, wantCalls := int32(1), 1
			if row.failed {
				wantRequests = 0
			}
			if row.stale {
				wantCalls++
			}
			if result.Status != contract.ReadUnavailable || result.Reason != contract.ReasonAccess || store.accessRefused.Load() != !row.failed || requests.Load() != wantRequests || selected.calls != wantCalls {
				t.Fatalf("actor read status=%d want=%d reason=%d want=%d authenticated_refusal=%t want=%t requests=%d want=%d tokens=%d want=%d", result.Status, contract.ReadUnavailable, result.Reason, contract.ReasonAccess, store.accessRefused.Load(), !row.failed, requests.Load(), wantRequests, selected.calls, wantCalls)
			}
		})
	}
	t.Run("parallel-unrelated-token-cannot-prove-failed-read", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		entered, release := make(chan struct{}), make(chan struct{})
		var calls, requests atomic.Int32
		selected := gcpActorCredentialCall(func(ctx context.Context) (string, error) {
			if calls.Add(1) == 1 {
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
				}
				return "", errors.New("controlled current-read credential failure")
			}
			return "reader-token", nil
		})
		credentials := &gcpActorCredentials{CredentialSource: selected}
		store := storeFor(t, credentials, &requests, 403)
		done := make(chan contract.ReadResult, 1)
		go func() { done <- store.Read(ctx, store.Descriptor().HeadKey, 1024) }()
		defer func() {
			cancel()
			if done != nil {
				<-done
			}
		}()
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("current read did not enter credential retrieval")
		}
		// Writer and Trust operations use the selected source directly, outside
		// the reader's authentication witness.
		if token, err := selected.Token(ctx); err != nil || token != "reader-token" {
			t.Fatal("unrelated authentication control failed")
		}
		close(release)
		result := <-done
		done = nil
		if result.Status != contract.ReadUnavailable || result.Reason != contract.ReasonAccess || store.accessRefused.Load() || requests.Load() != 0 || calls.Load() != 2 {
			t.Fatalf("parallel actor read status=%d want=%d reason=%d want=%d authenticated_refusal=%t want=false requests=%d want=0 tokens=%d want=2", result.Status, contract.ReadUnavailable, result.Reason, contract.ReasonAccess, store.accessRefused.Load(), requests.Load(), calls.Load())
		}
	})
}

// full_only: false
func TestGCPActorBackendSelectsCredentialFileWithoutFallback(t *testing.T) {
	for _, scenario := range []string{"access.observer-sees-selected-state/members_32_observer", "access.provider-refuses-observer/members_32_denied_observer"} {
		t.Run(scenario, func(t *testing.T) {
			env := memoryScenarioEnvironment(t)
			settings := liveSettings{Provider: "gcp", Project: "test-project", ProjectNumber: "123", Region: "us-central1", Bucket: "test-bucket", KeyID: "projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1",
				PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: env.PublicKey})), CredentialsFile: "/private/writer.json"}
			observerSettings := settings
			observerSettings.CredentialsFile = "/private/reader.json"
			input := liveRunInput{Settings: settings, ObserverSettings: &observerSettings, Scenarios: []string{scenario}}
			if scenario == "access.provider-refuses-observer/members_32_denied_observer" {
				input.ObserverSettings, input.DeniedObserverSettings = nil, &observerSettings
			}
			writer := &gcpActorCredential{err: errors.New("controlled writer token unavailable")}
			reader := &gcpActorCredential{err: errors.New("controlled reader token unavailable")}
			var selected []string
			load := func(_ context.Context, path string) (gcp.CredentialSource, error) {
				selected = append(selected, path)
				switch path {
				case settings.CredentialsFile:
					return writer, nil
				case observerSettings.CredentialsFile:
					return reader, nil
				default:
					t.Fatal("unselected credential file")
					return nil, errors.New("unselected credential file")
				}
			}
			writerBackend, err := openGCPBackend(context.Background(), input.Settings, "test-run", env.Domain, load)
			if err != nil {
				t.Fatal(err)
			}
			readerBackend, err := openGCPBackend(context.Background(), liveFreshSettings(input), "test-run", env.Domain, load)
			if err != nil {
				t.Fatal(err)
			}
			if writerBackend.Store.Descriptor() != readerBackend.Store.Descriptor() || writerBackend.Trust.Identity() != readerBackend.Trust.Identity() || len(selected) != 2 || selected[0] != settings.CredentialsFile || selected[1] != observerSettings.CredentialsFile {
				t.Fatal("actor construction changed binding or selected the wrong credentials")
			}
			for _, backend := range []*liveBackend{writerBackend, readerBackend} {
				admitted := env
				admitted.Store, admitted.Trust, admitted.PublicKey, admitted.SigningSelector = backend.Store, backend.Trust, backend.PublicKey, settings.KeyID
				admission := fixtureAdmission(admitted)
				session, result := Open(context.Background(), admission, backend.Store)
				if session != nil || readerReadOutcome(result, backend.AccessRefused()) != "unavailable" {
					t.Fatal("unavailable credentials were counted as access refusal")
				}
			}
			if writer.calls != 1 || reader.calls != 1 {
				t.Fatal("actor used another credential route or retried")
			}
			loadCalls := 0
			_, err = openGCPBackend(context.Background(), liveFreshSettings(input), "test-run", env.Domain, func(_ context.Context, path string) (gcp.CredentialSource, error) {
				loadCalls++
				if path != observerSettings.CredentialsFile {
					t.Fatal("reader construction fell back to writer credentials")
				}
				return nil, errors.New("controlled reader file unavailable")
			})
			if err == nil || loadCalls != 1 || writer.calls != 1 {
				t.Fatal("reader construction failure did not remain bounded to the selected file")
			}
		})
	}
}

type gcpActorStoreRead func(context.Context, string, uint32) contract.ReadResult

type gcpActorObservedStore struct {
	contract.Store
	read gcpActorStoreRead
}

func (s gcpActorObservedStore) Read(ctx context.Context, key string, maximum uint32) contract.ReadResult {
	return s.read(ctx, key, maximum)
}

// full_only: false
func TestGCPActorRefusalObservationBelongsToTheCurrentRead(t *testing.T) {
	for _, test := range []struct {
		name, token     string
		tokenError      bool
		resolve, cancel bool
		reason          contract.Reason
		want            bool
	}{
		{"authenticated-access-refusal", "reader-token", false, true, false, contract.ReasonAccess, true},
		{"token-unavailable", "reader-token", true, true, false, contract.ReasonAccess, false},
		{"empty-token", "", false, true, false, contract.ReasonAccess, false},
		{"invalid-token", "reader token", false, true, false, contract.ReasonAccess, false},
		{"oversized-token", strings.Repeat("a", 16385), false, true, false, contract.ReasonAccess, false},
		{"stale-authentication", "reader-token", false, false, false, contract.ReasonAccess, false},
		{"cancelled-read", "reader-token", false, true, true, contract.ReasonAccess, false},
		{"transport-unavailable", "reader-token", false, true, false, contract.ReasonTransport, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			selected := &gcpActorCredential{token: test.token}
			if test.tokenError {
				selected.err = errors.New("controlled token unavailable")
			}
			credentials := &gcpActorCredentials{CredentialSource: selected}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			// A credential obtained outside this read must not prove refusal.
			_, _ = credentials.Token(ctx)
			observed := gcpActorObservedStore{read: func(ctx context.Context, _ string, _ uint32) contract.ReadResult {
				if test.resolve {
					_, _ = credentials.Token(ctx)
				}
				if test.cancel {
					cancel()
				}
				return contract.ReadResult{Status: contract.ReadUnavailable, Reason: test.reason}
			}}
			store := &gcpActorReadStore{Store: observed, readStore: observed, readCredentials: credentials}
			store.accessRefused.Store(true)
			result := store.Read(ctx, "fixture/HEAD", 1024)
			if result.Status != contract.ReadUnavailable || store.accessRefused.Load() != test.want {
				t.Fatal("refusal used stale, unavailable, or cancelled credential evidence")
			}
		})
	}
}

// full_only: false
func TestGCPActorBackendPreservesStoreConfiguration(t *testing.T) {
	for _, prefix := range []string{"first-test-run", "second-test-run"} {
		t.Run(prefix, func(t *testing.T) {
			env := memoryScenarioEnvironment(t)
			settings := liveSettings{Provider: "gcp", Project: "test-project", ProjectNumber: "123", Region: "us-central1", Bucket: "test-bucket", KeyID: "projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1", PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: env.PublicKey})), CredentialsFile: "/private/selected.json"}
			credentials := &gcpActorCredential{err: errors.New("metadata must not obtain credentials")}
			loads := 0
			backend, err := openGCPBackend(t.Context(), settings, prefix, env.Domain, func(_ context.Context, path string) (gcp.CredentialSource, error) {
				loads++
				if path != settings.CredentialsFile {
					t.Fatal("configuration construction changed the selected credential route")
				}
				return credentials, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			want := contract.StoreConfiguration{Provider: contract.GCP, ConstructionProfile: contract.StoreConstructionProfile, DomainID: env.Domain, Region: "us-central1", Bucket: "test-bucket", PrefixBeforeHEAD: prefix}
			reader := backend.Store.(*gcpActorReadStore)
			if reader.readStore.Descriptor() != reader.Store.Descriptor() {
				t.Fatal("reader construction changed the Store descriptor")
			}
			for _, got := range []contract.StoreConfiguration{fixtureStoreConfiguration(backend.Store), (recordedStore{Store: backend.Store}).StoreConfiguration(), fixtureStoreConfiguration(reader.readStore)} {
				if got != want {
					t.Errorf("constructed Store configuration changed: %+v", got)
				}
				body, err := contract.EncodeStoreConfiguration(got)
				if err != nil {
					t.Error("constructed Store configuration cannot be encoded", err)
					continue
				}
				decoded, err := contract.DecodeStoreConfiguration(body)
				if err != nil || decoded != want || contract.Hash(body) != backend.Store.Descriptor().Identity {
					t.Error("constructed Store configuration does not round-trip to its descriptor", err)
				}
			}
			if loads != 1 || credentials.calls != 0 {
				t.Fatal("configuration retrieval caused credential or provider work")
			}
		})
	}
}

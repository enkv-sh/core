package compositionfull

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"enkv.sh/core/contract"
)

// consumeReaderManifest constructs every cloud request from decoded artifact
// facts. Independent service fixtures know exact resources and application
// bytes. GitHub has no plaintext secret read API; its scope/visibility checks
// qualify only the consumer metadata, as in the output acknowledgement tests.
func consumeReaderManifest(t *testing.T, artifact []byte) {
	t.Helper()
	const original = "enkv first secret test value"
	const encoded = "ZW5rdiBmaXJzdCBzZWNyZXQgdGVzdCB2YWx1ZQ=="
	var manifest struct {
		Observation struct {
			DomainID string `json:"domain_id"`
		} `json:"observation"`
		Entries []struct {
			Name    string `json:"name"`
			Content struct {
				Kind         string `json:"kind"`
				Destinations []struct {
					Destination string          `json:"destination_id"`
					Provider    string          `json:"service_contract_id"`
					Locator     string          `json:"consumer_locator"`
					Encoding    string          `json:"payload_encoding"`
					Policy      json.RawMessage `json:"consumer_policy"`
				} `json:"destinations"`
			} `json:"content"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(artifact, &manifest); err != nil {
		t.Fatal("consumer artifact decode", err)
	}
	var domain contract.ID
	domainBytes, err := hex.DecodeString(manifest.Observation.DomainID)
	if err != nil || len(domainBytes) != len(domain) {
		t.Fatal("consumer domain identity")
	}
	copy(domain[:], domainBytes)
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test-Credential-Route") != "output-consumer" {
			t.Error("consumer used Reader credential route")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var name, resource string
		if r.URL.Path == "/aws" {
			var request struct {
				SecretID string `json:"SecretId"`
				Stage    string `json:"VersionStage"`
			}
			if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&request) != nil || request.Stage != "AWSCURRENT" {
				t.Error("invalid manifest-derived AWS request")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			resource = request.SecretID
			switch resource {
			case "arn:aws:secretsmanager:us-east-1:123456789012:secret:secret-AbCd12":
				name = "secret"
			case "arn:aws:secretsmanager:us-east-1:123456789012:secret:encoded-XyZ123":
				name = "encoded"
			default:
				t.Error("AWS request did not contain exact current full ARN")
				w.WriteHeader(http.StatusNotFound)
				return
			}
		} else {
			if r.Method != http.MethodGet {
				t.Error("consumer GCP request is not GET")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			switch r.URL.Path {
			case "/v1/projects/123456789/secrets/secret/versions/latest:access":
				name = "secret"
				resource = "projects/123456789/secrets/secret/versions/17"
			case "/v1/projects/123456789/secrets/encoded/versions/latest:access":
				name = "encoded"
				resource = "projects/123456789/secrets/encoded/versions/17"
			default:
				t.Error("GCP request lost the named latest alias")
				w.WriteHeader(http.StatusNotFound)
				return
			}
		}
		calls.Add(1)
		value := original
		if name == "encoded" {
			value = encoded
		}
		wire := base64.StdEncoding.EncodeToString([]byte(value))
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/aws" {
			err := json.NewEncoder(w).Encode(struct {
				ARN    string
				Binary string `json:"SecretBinary"`
			}{resource, wire})
			if err != nil {
				t.Error("consumer response write", err)
			}
		} else {
			err := json.NewEncoder(w).Encode(struct {
				Name    string `json:"name"`
				Payload struct {
					Data string `json:"data"`
				} `json:"payload"`
			}{Name: resource, Payload: struct {
				Data string `json:"data"`
			}{wire}})
			if err != nil {
				t.Error("consumer response write", err)
			}
		}
	}))
	defer server.Close()
	client := server.Client()
	secretRows := 0
	for _, entry := range manifest.Entries {
		if entry.Content.Kind != "secret" {
			continue
		}
		secretRows++
		wantEncoding := "raw"
		if entry.Name == "encoded" {
			wantEncoding = "base64"
		} else if entry.Name != "secret" {
			t.Fatal("unexpected consumer secret entry")
		}
		if len(entry.Content.Destinations) != 5 {
			t.Fatal("consumer lacks complete five-profile route")
		}
		for index, destination := range entry.Content.Destinations {
			oracle := readerFixtureProfiles(entry.Name)[index]
			var policy bytes.Buffer
			if err := json.Compact(&policy, destination.Policy); err != nil {
				t.Fatal("consumer policy is invalid", err)
			}
			if destination.Destination != oracle.destination || destination.Locator != oracle.locator || destination.Provider != oracle.provider || destination.Encoding != wantEncoding || policy.String() != readerFixturePolicyJSON(domain, oracle.policy) {
				t.Fatal("consumer metadata differs from independent resource/encoding oracle")
			}
			if destination.Provider == "github-actions" {
				continue
			}
			var request *http.Request
			var err error
			if destination.Provider == "aws-secrets-manager" {
				secretID, stage, ok := strings.Cut(destination.Locator, "?stage=")
				if !ok {
					t.Fatal("consumer AWS locator lacks stage")
				}
				body, marshalErr := json.Marshal(struct {
					SecretID string `json:"SecretId"`
					Stage    string `json:"VersionStage"`
				}{secretID, stage})
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				request, err = http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/aws", bytes.NewReader(body))
			} else {
				request, err = http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/v1/"+destination.Locator+":access", nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("X-Test-Credential-Route", "output-consumer")
			response, err := client.Do(request)
			if err != nil {
				t.Fatal("manifest consumer request", err)
			}
			body, readErr := io.ReadAll(response.Body)
			closeErr := response.Body.Close()
			if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK {
				t.Fatal("consumer response refused", response.StatusCode, readErr, closeErr)
			}
			var payload struct {
				ARN     string
				Binary  string `json:"SecretBinary"`
				Name    string `json:"name"`
				Payload struct {
					Data string `json:"data"`
				} `json:"payload"`
			}
			if json.Unmarshal(body, &payload) != nil {
				t.Fatal("consumer response decode")
			}
			transport := payload.Binary
			if destination.Provider == "aws-secrets-manager" {
				want := strings.TrimSuffix(oracle.locator, "?stage=AWSCURRENT")
				if payload.ARN != want {
					t.Fatal("AWS returned another resource")
				}
			} else {
				transport = payload.Payload.Data
				want := strings.TrimSuffix(oracle.locator, "latest") + "17"
				if payload.Name != want {
					t.Fatal("GCP returned another resource")
				}
			}
			application, err := base64.StdEncoding.Strict().DecodeString(transport)
			if err != nil {
				t.Fatal("provider transport decode", err)
			}
			want := original
			if destination.Encoding == "base64" {
				want = encoded
			}
			if string(application) != want {
				t.Fatal("provider transport changed chosen payload")
			}
			if destination.Encoding == "base64" {
				application, err = base64.StdEncoding.Strict().DecodeString(string(application))
				if err != nil {
					t.Fatal("application base64 decode", err)
				}
			}
			if string(application) != original {
				t.Fatal("consumer application bytes differ")
			}
		}
	}
	if secretRows != 2 || calls.Load() != 4 {
		t.Fatal("consumer coverage incomplete", secretRows, calls.Load())
	}
}

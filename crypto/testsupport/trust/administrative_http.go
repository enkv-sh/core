package trust

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/fixturekeys"
)

type AdministrativeReadObject struct {
	Key   string
	Token contract.Token
	Body  []byte
}

// AdministrativeReadHTTP is a local GET-only provider responder. Every other
// host or method is counted as forbidden, including KMS, LIST and effects.
type AdministrativeReadHTTP struct {
	mu                  sync.Mutex
	location            contract.StoreLocation
	objects             []AdministrativeReadObject
	failure, failureKey string
	reads, forbidden    int
	principals          map[string]bool
}

func NewAdministrativeReadHTTP(t testing.TB, location contract.StoreLocation, objects []AdministrativeReadObject) (*AdministrativeReadHTTP, *http.Transport) {
	t.Helper()
	h := &AdministrativeReadHTTP{location: location, objects: objects, principals: make(map[string]bool)}
	hosts := []string{"s3." + location.Region + ".amazonaws.com", "storage." + location.Region + ".rep.googleapis.com"}
	transport := PublicHTTPSTransport(t, hosts, http.HandlerFunc(h.serveHTTP))
	return h, transport
}

func (h *AdministrativeReadHTTP) SetObjects(objects []AdministrativeReadObject) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.objects, h.failure, h.failureKey = objects, "", ""
}
func (h *AdministrativeReadHTTP) Fail(kind, key string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.failure, h.failureKey = kind, key
}
func (h *AdministrativeReadHTTP) Counts() (reads, forbidden, principals int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.reads, h.forbidden, len(h.principals)
}
func (h *AdministrativeReadHTTP) serveHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	location := h.location
	prefix, host := "/"+location.Bucket+"/", "s3."+location.Region+".amazonaws.com"
	if location.Provider == contract.GCP {
		prefix, host = "/download/storage/v1/b/"+location.Bucket+"/o/", "storage."+location.Region+".rep.googleapis.com"
	}
	if r.Method != http.MethodGet || r.Host != host || !strings.HasPrefix(r.URL.Path, prefix) || r.Header.Get("Authorization") == "" || location.Provider == contract.GCP && r.URL.Query().Get("alt") != "media" || location.Provider == contract.AWS && r.Header.Get("x-amz-expected-bucket-owner") != location.ExpectedOwner {
		h.forbidden++
		http.Error(w, "forbidden local test request", http.StatusForbidden)
		return
	}
	key := strings.TrimPrefix(r.URL.Path, prefix)
	h.reads++
	principal := r.Header.Get("Authorization")
	if location.Provider == contract.AWS {
		_, credential, ok := strings.Cut(principal, "Credential=")
		if !ok {
			h.forbidden++
			http.Error(w, "missing signed credential", http.StatusForbidden)
			return
		}
		principal, _, _ = strings.Cut(credential, "/")
	}
	h.principals[principal] = true
	if key == h.failureKey && h.failure == "denied" {
		h.failureResponse(w, http.StatusForbidden)
		return
	}
	if key == h.failureKey && h.failure == "missing" {
		h.failureResponse(w, http.StatusNotFound)
		return
	}
	var token contract.Token
	var body []byte
	ok := false
	for _, object := range h.objects {
		if object.Key == key {
			token, body, ok = object.Token, object.Body, true
			break
		}
	}
	if !ok {
		h.failureResponse(w, http.StatusNotFound)
		return
	}
	if location.Provider == contract.AWS {
		w.Header().Set("ETag", token.Value)
	} else {
		w.Header().Set("X-Goog-Generation", token.Value)
	}
	if key == h.failureKey && h.failure == "corrupt" {
		body = bytes.Clone(body)
		body[len(body)-1] ^= 1
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Content-Type", "application/octet-stream")
	if _, err := w.Write(body); err != nil {
		h.forbidden++
	}
}

func (h *AdministrativeReadHTTP) failureResponse(w http.ResponseWriter, status int) {
	var body string
	if h.location.Provider == contract.AWS {
		code := "AccessDenied"
		if status == http.StatusNotFound {
			code = "NoSuchKey"
		}
		w.Header().Set("Content-Type", "application/xml")
		body = "<Error><Code>" + code + "</Code></Error>"
	} else {
		w.Header().Set("Content-Type", "application/json")
		body = `{"error":{"code":` + strconv.Itoa(status) + `,"message":"local fixture refusal"}}`
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	if _, err := w.Write([]byte(body)); err != nil {
		h.forbidden++
	}
}

// AdministrativeNativeCredentials installs ordinary native discovery inputs.
// The token server is local credential refresh, separate from provider effects.
func AdministrativeNativeCredentials(t *testing.T, dir, family, label string) {
	t.Helper()
	write := func(name string, body []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
	t.Setenv("EXPERIMENTAL_GOOGLE_API_USE_S2A", "false")
	if family == "aws" {
		t.Setenv("AWS_ACCESS_KEY_ID", "local-get-"+label)
		t.Setenv("AWS_SECRET_ACCESS_KEY", "local-get-secret")
		t.Setenv("AWS_SESSION_TOKEN", "")
		t.Setenv("AWS_CONFIG_FILE", write("aws-config", []byte{}))
		t.Setenv("AWS_SHARED_CREDENTIALS_FILE", write("aws-credentials", []byte{}))
		t.Setenv("AWS_PROFILE", "")
		t.Setenv("AWS_DEFAULT_PROFILE", "")
		t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
		return
	}
	if family != "gcp" {
		t.Fatal("unknown native credential fixture family")
	}
	tokens := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/token" {
			http.Error(w, "unexpected token request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"access_token":"local-get-` + label + `","expires_in":3600,"token_type":"Bearer"}`)); err != nil {
			t.Errorf("local credential response write: %v", err)
		}
	}))
	t.Cleanup(tokens.Close)
	private, err := base64.StdEncoding.DecodeString(fixturekeys.PrivateKeys[0])
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]string{"type": "service_account", "client_email": "local-test@example.iam.gserviceaccount.com", "private_key_id": "local-test", "private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})), "token_uri": tokens.URL + "/token", "universe_domain": "googleapis.com"})
	clear(private)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", write("adc-"+label+".json", body))
}

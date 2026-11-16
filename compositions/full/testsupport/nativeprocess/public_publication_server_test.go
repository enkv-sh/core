package nativeprocess

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// This server records exact controlled requests, not a live service claim.
// Expected application bytes come from the test before either source is parsed.
type nativePublicationServer struct {
	mu              sync.Mutex
	server          *httptest.Server
	public, private *[32]byte
	account         string
	adcPublic       *rsa.PublicKey
	adcEmail        string
	expected        map[string][]byte
	objects         map[string][]byte
	effects         map[string]int
	requests        int
	violations      []string
}

func newNativePublicationServer(t *testing.T) *nativePublicationServer {
	t.Helper()
	public, private, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("controlled output key unavailable", err)
	}
	s := &nativePublicationServer{public: public, private: private, expected: map[string][]byte{}, objects: map[string][]byte{}, effects: map[string]int{}}
	s.server = httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	s.server.Config.ReadHeaderTimeout = 5 * time.Second
	s.server.Config.ReadTimeout = 10 * time.Second
	s.server.Config.WriteTimeout = 10 * time.Second
	s.server.Start()
	t.Cleanup(func() {
		s.server.Close()
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, body := range s.objects {
			clear(body)
		}
		for _, body := range s.expected {
			clear(body)
		}
		clear(s.private[:])
		if len(s.violations) != 0 {
			t.Errorf("controlled output requests refused: %v", s.violations)
		}
	})
	return s
}

func (s *nativePublicationServer) expect(account string, expected map[string][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.account = account
	for key, body := range expected {
		s.expected[key] = bytes.Clone(body)
	}
}

func (s *nativePublicationServer) effectCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, count := range s.effects {
		n += count
	}
	return n
}

func (s *nativePublicationServer) checkValues(t *testing.T, keys []string, deleted bool) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, key := range keys {
		value, present := s.objects[key]
		if deleted {
			if present {
				t.Fatal("controlled deleted container remains")
			}
			continue
		}
		if !present || !bytes.Equal(value, s.expected[key]) {
			t.Fatal("controlled destination differs from independent application bytes")
		}
	}
}

func (s *nativePublicationServer) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	refuse := func(reason string) {
		s.violations = append(s.violations, reason)
		http.Error(w, "controlled output refused", 400)
	}
	s.requests++
	if s.requests > 1024 || r.ProtoMajor != 1 {
		refuse("request-boundary")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if err != nil || len(body) > 1<<20 {
		refuse("request-size")
		return
	}
	defer clear(body)
	write := func(value any) {
		w.Header().Set("Content-Type", "application/json")
		if json.NewEncoder(w).Encode(value) != nil {
			s.violations = append(s.violations, "response-write")
		}
	}
	if r.URL.Path == "/token/output" {
		form, formErr := url.ParseQuery(string(body))
		parts := strings.Split(form.Get("assertion"), ".")
		if r.Method != "POST" || formErr != nil || form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || len(parts) != 3 || s.adcPublic == nil {
			refuse("output-adc-token")
			return
		}
		header, headerErr := base64.RawURLEncoding.DecodeString(parts[0])
		claims, claimsErr := base64.RawURLEncoding.DecodeString(parts[1])
		signature, signatureErr := base64.RawURLEncoding.DecodeString(parts[2])
		var h struct{ Alg, Typ, Kid string }
		var c struct {
			Issuer   string `json:"iss"`
			Audience string `json:"aud"`
			Scope    string
			Issued   int64 `json:"iat"`
			Expiry   int64 `json:"exp"`
		}
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		now := time.Now().Unix()
		if headerErr != nil || claimsErr != nil || signatureErr != nil || json.Unmarshal(header, &h) != nil || json.Unmarshal(claims, &c) != nil || h.Alg != "RS256" || h.Typ != "JWT" || h.Kid != "native-output" || c.Issuer != s.adcEmail || c.Audience != s.server.URL+"/token/output" || c.Scope != "https://www.googleapis.com/auth/cloud-platform" || c.Issued < now-60 || c.Issued > now+5 || c.Expiry <= now || c.Expiry > now+3605 || c.Expiry-c.Issued != 3600 || rsa.VerifyPKCS1v15(s.adcPublic, crypto.SHA256, digest[:], signature) != nil {
			refuse("output-adc-exact-jwt")
			return
		}
		write(map[string]any{"access_token": "native-output-token", "token_type": "Bearer", "expires_in": 3600})
		return
	}
	if !r.Close {
		refuse("output-request-replay-boundary")
		return
	}
	if r.URL.Path == "/" && r.Header.Get("X-Amz-Target") == "" {
		if r.Method != "POST" || string(body) != "Action=GetCallerIdentity&Version=2011-06-15" || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			refuse("output-sts")
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		_, err := io.WriteString(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:iam::`+s.account+`:user/native-output</Arn><UserId>native-output</UserId><Account>`+s.account+`</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>native-output</RequestId></ResponseMetadata></GetCallerIdentityResponse>`)
		if err != nil {
			s.violations = append(s.violations, "sts-response")
		}
		return
	}
	if strings.HasPrefix(r.Header.Get("X-Amz-Target"), "secretsmanager.") {
		if r.Method != "POST" || r.URL.RequestURI() != "/" || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			refuse("aws-request")
			return
		}
		var q struct {
			Name, SecretID, ClientRequestToken, SecretBinary string
			VersionStages                                    []string
			RecoveryWindowInDays                             int
		}
		if json.Unmarshal(body, &q) != nil {
			refuse("aws-json")
			return
		}
		// encoding/json ignores case but not the AWS SecretId spelling.
		var fields map[string]json.RawMessage
		if json.Unmarshal(body, &fields) != nil {
			refuse("aws-fields")
			return
		}
		if raw := fields["SecretId"]; len(raw) != 0 {
			if json.Unmarshal(raw, &q.SecretID) != nil {
				refuse("aws-secret-id")
				return
			}
		}
		arn := q.SecretID
		if q.Name != "" {
			arn = "arn:aws:secretsmanager:us-east-1:" + s.account + ":secret:" + q.Name + "-AbCd12"
		}
		key := "aws:" + arn
		expected, known := s.expected[key]
		if !known {
			refuse("aws-unselected-target")
			return
		}
		name := strings.TrimSuffix(strings.Split(arn, ":secret:")[1], "-AbCd12")
		switch r.Header.Get("X-Amz-Target") {
		case "secretsmanager.CreateSecret":
			if _, exists := s.objects[key]; exists || len(fields) != 2 || len(q.ClientRequestToken) != 64 {
				refuse("aws-create")
				return
			}
			s.objects[key] = nil
			s.effects["aws-create"]++
			write(map[string]any{"ARN": arn, "Name": name})
		case "secretsmanager.PutSecretValue":
			payload, err := base64.StdEncoding.Strict().DecodeString(q.SecretBinary)
			defer clear(payload)
			if _, exists := s.objects[key]; !exists || err != nil || !bytes.Equal(payload, expected) || len(q.ClientRequestToken) != 64 || !reflect.DeepEqual(q.VersionStages, []string{"AWSCURRENT"}) || len(fields) != 4 {
				refuse("aws-value")
				return
			}
			s.objects[key] = bytes.Clone(payload)
			s.effects["aws-write"]++
			write(map[string]any{"ARN": arn, "Name": name, "VersionId": q.ClientRequestToken, "VersionStages": []string{"AWSCURRENT"}})
		case "secretsmanager.DeleteSecret":
			if _, exists := s.objects[key]; !exists || q.RecoveryWindowInDays != 7 || len(fields) != 2 {
				refuse("aws-delete")
				return
			}
			clear(s.objects[key])
			delete(s.objects, key)
			s.effects["aws-delete"]++
			write(map[string]any{"ARN": arn, "Name": name, "DeletionDate": 1790467200})
		default:
			refuse("aws-operation")
		}
		return
	}
	if strings.HasPrefix(r.URL.Path, "/v1/projects/") {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer native-output-token" && !strings.HasPrefix(auth, "Bearer offline-native-") {
			refuse("gcp-token")
			return
		}
		if r.Header.Get("X-Goog-User-Project") != "fixture-quota" {
			refuse("gcp-quota")
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/v1/")
		if r.Method == "POST" && strings.HasSuffix(path, "/secrets") {
			name := path + "/" + r.URL.Query().Get("secretId")
			key := "gcp:" + name
			if _, known := s.expected[key]; !known || r.URL.Query().Get("secretId") == "" {
				refuse("gcp-create-target")
				return
			}
			if _, exists := s.objects[key]; exists || !bytes.Contains(body, []byte(`"automatic":{}`)) {
				refuse("gcp-create")
				return
			}
			s.objects[key] = nil
			s.effects["gcp-create"]++
			write(map[string]any{"name": name, "replication": map[string]any{"automatic": map[string]any{}}})
			return
		}
		name := strings.TrimSuffix(path, ":addVersion")
		key := "gcp:" + name
		expected, known := s.expected[key]
		if !known {
			refuse("gcp-unselected-target")
			return
		}
		if _, exists := s.objects[key]; !exists {
			refuse("gcp-unowned-target")
			return
		}
		switch {
		case r.Method == "POST" && strings.HasSuffix(path, ":addVersion"):
			var q struct {
				Payload struct {
					Data string
					CRC  string `json:"dataCrc32c"`
				} `json:"payload"`
			}
			if json.Unmarshal(body, &q) != nil {
				refuse("gcp-value-json")
				return
			}
			payload, err := base64.StdEncoding.Strict().DecodeString(q.Payload.Data)
			defer clear(payload)
			wantCRC := strconv.FormatUint(uint64(crc32.Checksum(expected, crc32.MakeTable(crc32.Castagnoli))), 10)
			if err != nil || !bytes.Equal(payload, expected) || q.Payload.CRC != wantCRC {
				refuse("gcp-value")
				return
			}
			s.objects[key] = bytes.Clone(payload)
			s.effects["gcp-write"]++
			write(map[string]any{"name": name + "/versions/42", "clientSpecifiedPayloadChecksum": true})
		case r.Method == "GET":
			write(map[string]any{"name": name, "etag": "native-etag"})
		case r.Method == "DELETE":
			if r.URL.Query().Get("etag") != "native-etag" {
				refuse("gcp-delete-etag")
				return
			}
			clear(s.objects[key])
			delete(s.objects, key)
			s.effects["gcp-delete"]++
			write(map[string]any{})
		default:
			refuse("gcp-operation")
		}
		return
	}
	if strings.HasPrefix(r.URL.Path, "/repos/") || strings.HasPrefix(r.URL.Path, "/orgs/") {
		if r.Header.Get("Authorization") != "Bearer github_pat_NATIVE_OUTPUT" || r.Header.Get("X-GitHub-Api-Version") != "2026-03-10" || r.Header.Get("Accept") != "application/vnd.github+json" || r.URL.RawQuery != "" {
			refuse("github-headers")
			return
		}
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/public-key") {
			write(map[string]string{"key_id": "native-key", "key": base64.StdEncoding.EncodeToString(s.public[:])})
			return
		}
		key := "github:" + strings.TrimPrefix(r.URL.Path, "/")
		expected, known := s.expected[key]
		if !known {
			refuse("github-unselected-target")
			return
		}
		switch r.Method {
		case "PUT":
			var q struct {
				Encrypted    string   `json:"encrypted_value"`
				Key          string   `json:"key_id"`
				Visibility   string   `json:"visibility"`
				Repositories []uint64 `json:"selected_repository_ids"`
			}
			var fields map[string]json.RawMessage
			if json.Unmarshal(body, &q) != nil || json.Unmarshal(body, &fields) != nil || q.Key != "native-key" {
				refuse("github-value-json")
				return
			}
			sealed, err := base64.StdEncoding.Strict().DecodeString(q.Encrypted)
			defer clear(sealed)
			payload, opened := box.OpenAnonymous(nil, sealed, s.public, s.private)
			defer clear(payload)
			if err != nil || !opened || !bytes.Equal(payload, expected) {
				refuse("github-value")
				return
			}
			if strings.HasPrefix(r.URL.Path, "/orgs/") {
				if q.Visibility != "selected" || !reflect.DeepEqual(q.Repositories, []uint64{7, 11}) || len(fields) != 4 {
					refuse("github-organization-policy")
					return
				}
			} else if len(fields) != 2 {
				refuse("github-unexpected-policy")
				return
			}
			_, exists := s.objects[key]
			s.objects[key] = bytes.Clone(payload)
			s.effects["github-value"]++
			if exists {
				w.WriteHeader(204)
			} else {
				w.WriteHeader(201)
			}
		case "DELETE":
			if _, exists := s.objects[key]; !exists || len(body) != 0 {
				refuse("github-delete")
				return
			}
			clear(s.objects[key])
			delete(s.objects, key)
			s.effects["github-delete"]++
			w.WriteHeader(204)
		default:
			refuse("github-operation")
		}
		return
	}
	refuse("unknown-service-request")
}

package core

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"enkv.sh/crypto/testsupport/custody"
)

// This server records exact controlled requests, not a live service claim.
// Expected application bytes come from the test before either source is parsed.
type packagedPublicationServer struct {
	mu            sync.Mutex
	server        *httptest.Server
	box           *custody.OutputBoxFixture
	account       string
	expected      map[string][]byte
	objects       map[string][]byte
	effects       map[string]int
	keyReads      map[string]int
	requests      int
	identityReads int
	violations    []string
}

func newPackagedPublicationServer(t *testing.T) *packagedPublicationServer {
	t.Helper()
	box, err := custody.NewOutputBoxFixture()
	if err != nil {
		t.Fatal("controlled output key unavailable", err)
	}
	s := &packagedPublicationServer{box: box, expected: map[string][]byte{}, objects: map[string][]byte{}, effects: map[string]int{}, keyReads: map[string]int{}}
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
		s.box.Close()
		if len(s.violations) != 0 {
			t.Errorf("controlled output requests refused: %v", s.violations)
		}
	})
	return s
}

func (s *packagedPublicationServer) expect(account string, expected map[string][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.account = account
	for key, body := range expected {
		s.expected[key] = bytes.Clone(body)
	}
}

func (s *packagedPublicationServer) effectCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, count := range s.effects {
		n += count
	}
	return n
}

func (s *packagedPublicationServer) checkValues(t *testing.T, keys []string, deleted bool) {
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

func (s *packagedPublicationServer) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	refuse := func(reason string) {
		s.violations = append(s.violations, reason)
		http.Error(w, "controlled output refused", 400)
	}
	s.requests++
	if s.requests > 25 || r.ProtoMajor != 1 {
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
	if !r.Close {
		refuse("output-request-replay-boundary")
		return
	}
	qualifiedCreates := s.effects["aws-create"]
	if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		if r.Method != "POST" || r.URL.RequestURI() != "/" || r.Header.Get("X-Amz-Target") != "" ||
			!strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") ||
			!strings.Contains(r.Header.Get("Authorization"), "/us-east-1/sts/aws4_request") ||
			string(body) != "Action=GetCallerIdentity&Version=2011-06-15" || s.identityReads != qualifiedCreates {
			refuse("aws-identity-request")
			return
		}
		s.identityReads++
		w.Header().Set("Content-Type", "text/xml")
		if _, err := fmt.Fprintf(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Account>%s</Account><Arn>arn:aws:iam::%s:role/controlled-output</Arn><UserId>controlled-output</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`, s.account, s.account); err != nil {
			s.violations = append(s.violations, "identity-response-write")
		}
		return
	}
	if strings.HasPrefix(r.Header.Get("X-Amz-Target"), "secretsmanager.") {
		// Name-based creation needs a fresh qualification. A retained full ARN
		// identifies the account for subsequent writes and owned deletes.
		wantIdentityReads := qualifiedCreates
		if r.Header.Get("X-Amz-Target") == "secretsmanager.CreateSecret" {
			wantIdentityReads++
		}
		if r.Method != "POST" || r.URL.RequestURI() != "/" || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") || s.identityReads != wantIdentityReads {
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
			s.objects[key] = bytes.Clone(expected)
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
			s.objects[key] = bytes.Clone(expected)
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
			switch r.URL.Path {
			case "/repos/owner/repo/actions/secrets/public-key", "/orgs/owner/actions/secrets/public-key", "/repos/owner/repo/environments/prod/secrets/public-key":
			default:
				refuse("github-public-key-scope")
				return
			}
			s.keyReads[r.URL.Path]++
			if s.keyReads[r.URL.Path] > 2 {
				refuse("github-public-key-count")
				return
			}
			public := s.box.PublicKey()
			write(map[string]string{"key_id": "native-key", "key": base64.StdEncoding.EncodeToString(public[:])})
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
			if err != nil || !s.box.Matches(sealed, expected) {
				refuse("github-value")
				return
			}
			other, err := custody.NewOutputBoxFixture()
			if err != nil {
				refuse("github-custody-fixture")
				return
			}
			wrongKey := other.Matches(sealed, expected)
			other.Close()
			closed := other.Matches(sealed, expected)
			wrongValue := append(bytes.Clone(expected), 0)
			corrupt := bytes.Clone(sealed)
			corrupt[len(corrupt)-1] ^= 1
			invalid := s.box.Matches(sealed, wrongValue) || s.box.Matches(corrupt, expected) || s.box.Matches(nil, expected)
			clear(wrongValue)
			clear(corrupt)
			if wrongKey || closed || invalid {
				refuse("github-custody-negative")
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
			s.objects[key] = bytes.Clone(expected)
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

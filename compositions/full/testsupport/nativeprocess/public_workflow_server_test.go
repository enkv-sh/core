package nativeprocess

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// This responder implements only the exact AWS operations used by this test.
// It is an offline protocol fixture, not an AWS identity or IAM emulator.
type workflowKey struct {
	signing    *ecdsa.PrivateKey
	encryption *rsa.PrivateKey
	decrypt    func([]byte) ([]byte, error)
	der        []byte
	role       string
}
type workflowObject struct {
	body []byte
	etag string
}
type workflowCounts struct {
	reads, headReads, creates, headCreates, headUpdates, conditions int
	lists, deletes                                                  int
	calls                                                           map[string]int
}
type workflowCancelGate struct {
	ready              chan *os.Process
	uses               int
	signaled, canceled bool
}

const workflowChildRequestLimit = 512

type workflowServer struct {
	mu                                  sync.Mutex
	server                              *httptest.Server
	rootPEM, prefix, family             string
	keys                                map[string]workflowKey
	auth                                *httptest.Server
	authKey                             *rsa.PrivateKey
	authRequests                        int
	objects                             map[string]workflowObject
	counts                              map[string]*workflowCounts
	violations                          []string
	requests, bytes, version            int
	requestLimit, childLimit, children  int
	childRequestLimit                   int
	objectLimit                         int
	requestBodyLimit, requestBytesLimit int
	childBytesLimit                     uint64
	childTimeout                        time.Duration
	rejectNextHeadUpdate                bool
	rejectHeadBody                      func([]byte) bool
	cancelGate                          *workflowCancelGate
	gcListPrefix                        string
	gcListKeys                          []string
	gcUnknownDelete                     bool
	materializationGate                 *workflowMaterializationGate
	readerStoreDenied                   bool
	materializationStoreDenied          bool
	materializationDecryptDenied        bool
	materializationRecipientKey         string
}

func workflowSelector(n int) string {
	return fmt.Sprintf("arn:aws:kms:us-east-1:123456789012:key/%08d-1111-1111-1111-111111111111", n)
}
func workflowAccess(phase string) string { return "ENKVLOCAL" + strings.ToUpper(phase) + "00000001" }
func newWorkflowServer(t *testing.T, family string, recovery bool) *workflowServer {
	t.Helper()
	s := &workflowServer{requestLimit: workflowChildRequestLimit, childRequestLimit: workflowChildRequestLimit, objectLimit: 64, family: family, prefix: fmt.Sprintf("workflow-%s-recovery-%t", family, recovery), keys: map[string]workflowKey{}, objects: map[string]workflowObject{}, counts: map[string]*workflowCounts{}}
	s.materializationRecipientKey = s.selector(5)
	t.Cleanup(func() { s.clean(t) })
	for n, role := range map[int]string{1: "normal", 2: "authority", 3: "recovery-signing", 4: "recovery-private", 5: "ordinary", 6: "successor"} {
		if !recovery && (n == 3 || n == 4) {
			continue
		}
		key := workflowKey{role: role}
		var public any
		var err error
		if n == 1 || n == 3 || n == 6 {
			key.signing, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err == nil {
				public = &key.signing.PublicKey
			}
		} else {
			key.encryption, err = rsa.GenerateKey(rand.Reader, 3072)
			if err == nil {
				public = &key.encryption.PublicKey
			}
		}
		if err != nil {
			t.Fatal("local key fixture unavailable", err)
		}
		key.der, err = x509.MarshalPKIXPublicKey(public)
		if err != nil {
			t.Fatal(err)
		}
		s.keys[s.selector(n)] = key
	}
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "offline native workflow"}, DNSNames: []string{"s3.us-east-1.amazonaws.com", "kms.us-east-1.amazonaws.com", "storage.us-central1.rep.googleapis.com", "us-central1-cloudkms.googleapis.com", "oauth2.googleapis.com"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &tlsKey.PublicKey, tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	s.rootPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	pair, err := tls.X509KeyPair([]byte(s.rootPEM), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	if err != nil {
		t.Fatal(err)
	}
	s.server = httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	s.server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	s.server.Config.ReadHeaderTimeout = 5 * time.Second
	s.server.Config.ReadTimeout = 10 * time.Second
	s.server.Config.WriteTimeout = 10 * time.Second
	s.server.Config.MaxHeaderBytes = 32 << 10
	s.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	if family == "gcp" {
		s.startGCPTokenServer(t)
	}
	s.server.StartTLS()
	t.Cleanup(s.server.Close)
	return s
}

// An explicitly counted multi-command case admits one bounded child at a time.
// Counters and violations span the whole sequence; unused allowance does not
// carry into the next child. Other fixtures retain their original total limit.
func (s *workflowServer) admitChild() (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.childRequestLimit <= 0 || s.childRequestLimit > 4096 {
		return 0, false
	}
	if s.childLimit == 0 {
		return s.childRequestLimit, true
	}
	if s.childLimit < 0 || s.children >= s.childLimit || len(s.violations) != 0 {
		return 0, false
	}
	s.children++
	s.requestLimit = s.requests + s.childRequestLimit
	return s.childRequestLimit, true
}

func (s *workflowServer) fail(w http.ResponseWriter, reason string) {
	s.violations = append(s.violations, reason)
	s.awsError(w, 403, "AccessDeniedException")
}

// Response handlers hold s.mu; clean observes write failures after they join.
func (s *workflowServer) writeResponse(w http.ResponseWriter, body []byte) {
	if n, err := w.Write(body); err != nil || n != len(body) {
		s.violations = append(s.violations, "response-write")
	}
}

func (s *workflowServer) awsError(w http.ResponseWriter, status int, code string) {
	if status == 404 || status == 412 {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(status)
		s.writeResponse(w, []byte(fmt.Sprintf("<Error><Code>%s</Code></Error>", code)))
		return
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("X-Amzn-Errortype", code)
	w.WriteHeader(status)
	s.writeResponse(w, []byte(`{"__type":"`+code+`","message":"offline fixture refusal"}`))
}
func (s *workflowServer) serve(w http.ResponseWriter, r *http.Request) {
	if s.family == "gcp" && r.Host == "oauth2.googleapis.com" && r.URL.Path == "/token" {
		s.auth.Config.Handler.ServeHTTP(w, r)
		return
	}
	if !s.waitMaterialization(w, r) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests++
	if s.requests > s.requestLimit {
		s.fail(w, "request-bound")
		return
	}
	authorization := r.Header.Get("Authorization")
	marker := "Credential="
	at := strings.Index(authorization, marker)
	phase := ""
	if s.family == "gcp" {
		phase = strings.TrimPrefix(authorization, "Bearer offline-native-")
		if authorization != "Bearer offline-native-"+phase || !workflowPhase(phase) {
			phase = ""
		}
	}
	if s.family == "aws" && at >= 0 {
		access := strings.SplitN(authorization[at+len(marker):], "/", 2)[0]
		for _, candidate := range []string{"init", "retry", "apply", "change", "noop", "reader", "authority", "recovery", "set", "set-change", "successor", "invalid-private", "materialize"} {
			if access == workflowAccess(candidate) {
				phase = candidate
			}
		}
	}
	if phase == "" {
		s.fail(w, "unknown-synthetic-principal")
		return
	}
	c := s.counts[phase]
	if c == nil {
		c = &workflowCounts{calls: map[string]int{}}
		s.counts[phase] = c
	}
	bodyLimit, bytesLimit := 1<<20, 8<<20
	if s.requestBodyLimit != 0 {
		bodyLimit = s.requestBodyLimit
	}
	if s.requestBytesLimit != 0 {
		bytesLimit = s.requestBytesLimit
	}
	if r.ContentLength < 0 || r.ContentLength > int64(bodyLimit) {
		s.fail(w, "request-length")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(bodyLimit)+1))
	defer clear(body)
	err = errors.Join(err, r.Body.Close())
	s.bytes += len(body)
	if err != nil || len(body) > bodyLimit || s.bytes > bytesLimit || int64(len(body)) != r.ContentLength {
		s.fail(w, "request-bytes")
		return
	}
	if s.family == "gcp" {
		s.gcp(w, r, phase, c, body)
		return
	}
	switch r.Host {
	case "s3.us-east-1.amazonaws.com":
		s.s3(w, r, phase, c, body)
	case "kms.us-east-1.amazonaws.com":
		s.kms(w, r, phase, c, body)
	default:
		s.fail(w, "service-host")
	}
}
func (s *workflowServer) s3(w http.ResponseWriter, r *http.Request, phase string, c *workflowCounts, body []byte) {
	if s.capacityStoreRequest(w, r, phase, c, body) {
		return
	}
	pathPrefix := "/fixture-bucket/" + s.prefix + "/"
	query := r.URL.Query()
	if len(query) > 1 || len(query) == 1 && (query.Get("x-id") != "GetObject" && query.Get("x-id") != "PutObject") {
		s.fail(w, "s3-query")
		return
	}
	if !strings.HasPrefix(r.URL.Path, pathPrefix) || strings.Contains(r.URL.Path, "..") || len(r.URL.Path) > 1100 {
		s.fail(w, "s3-key")
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/fixture-bucket/")
	if !workflowStoreKey(s.prefix, key, phase) {
		s.fail(w, "s3-object-shape")
		return
	}
	expectedQuery := "GetObject"
	if r.Method == http.MethodPut {
		expectedQuery = "PutObject"
	}
	if len(query) != 0 && (len(query["x-id"]) != 1 || query.Get("x-id") != expectedQuery) {
		s.fail(w, "s3-operation-query")
		return
	}
	owner := r.Header.Get("X-Amz-Expected-Bucket-Owner")
	if owner != "" && owner != "123456789012" {
		s.fail(w, "s3-owner")
		return
	}
	object, exists := s.objects[key]
	switch r.Method {
	case http.MethodGet:
		if len(body) != 0 || r.Header.Get("Range") != "" || r.Header.Get("If-Match") != "" || r.Header.Get("If-None-Match") != "" {
			s.fail(w, "s3-get-shape")
			return
		}
		c.reads++
		if key == s.prefix+"/HEAD" {
			c.headReads++
		}
		if phase == "materialize" && s.materializationStoreDenied || phase == "reader" && s.readerStoreDenied {
			s.awsError(w, 403, "AccessDenied")
			return
		}
		if !exists {
			s.awsError(w, 404, "NoSuchKey")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(len(object.body)))
		w.Header().Set("ETag", object.etag)
		w.WriteHeader(200)
		s.writeResponse(w, object.body)
	case http.MethodPut:
		if (phase != "init" && phase != "apply" && phase != "change" && phase != "successor") || owner != "123456789012" || r.Header.Get("Content-Type") != "application/octet-stream" {
			s.fail(w, "s3-write-authority")
			return
		}
		checksum, err := base64.StdEncoding.DecodeString(r.Header.Get("X-Amz-Checksum-Sha256"))
		sum := sha256.Sum256(body)
		if err != nil || !bytes.Equal(checksum, sum[:]) {
			s.fail(w, "s3-checksum")
			return
		}
		match, absent := r.Header.Get("If-Match"), r.Header.Get("If-None-Match")
		head := key == s.prefix+"/HEAD"
		switch {
		case absent == "*" && match == "":
			if exists {
				c.conditions++
				s.awsError(w, 412, "PreconditionFailed")
				return
			}
		case match != "" && absent == "" && head:
			if !exists || object.etag != match {
				c.conditions++
				s.awsError(w, 412, "PreconditionFailed")
				return
			}
		default:
			s.fail(w, "s3-exact-condition")
			return
		}
		if head && exists && (s.rejectNextHeadUpdate || s.rejectHeadBody != nil && s.rejectHeadBody(body)) {
			s.rejectNextHeadUpdate = false
			c.conditions++
			s.awsError(w, 412, "PreconditionFailed")
			return
		}
		if !exists && len(s.objects) >= s.objectLimit {
			s.fail(w, "s3-object-bound")
			return
		}
		s.version++
		etag := fmt.Sprintf(`"workflow-%08d"`, s.version)
		s.objects[key] = workflowObject{body: bytes.Clone(body), etag: etag}
		if head {
			if exists {
				c.headUpdates++
			} else {
				c.headCreates++
			}
		} else {
			c.creates++
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(200)
	default:
		s.fail(w, "s3-method")
	}
}
func (s *workflowServer) kms(w http.ResponseWriter, r *http.Request, phase string, c *workflowCounts, body []byte) {
	if r.Method != http.MethodPost || r.URL.Path != "/" || r.URL.RawQuery != "" || phase == "reader" || phase == "retry" || (phase == "set" || phase == "set-change") {
		s.fail(w, "kms-shape-or-principal")
		return
	}
	var request struct {
		KeyID                         string `json:"KeyId"`
		Message                       []byte
		MessageType, SigningAlgorithm string
		CiphertextBlob                []byte
		EncryptionAlgorithm           string
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
		s.fail(w, "kms-json")
		return
	}
	defer clear(request.Message)
	defer clear(request.CiphertextBlob)
	key, ok := s.keys[request.KeyID]
	if !ok {
		s.fail(w, "kms-exact-key")
		return
	}
	if !strings.HasPrefix(r.Header.Get("X-Amz-Target"), "TrentService.") || r.Header.Get("Content-Type") != "application/x-amz-json-1.1" {
		s.fail(w, "kms-protocol")
		return
	}
	target := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "TrentService.")
	if phase == "materialize" && (target != "Decrypt" || request.KeyID != s.materializationRecipientKey) {
		s.fail(w, "materialization-exact-private-route")
		return
	}
	var response any
	switch target {
	case "GetPublicKey", "DescribeKey":
		if len(request.Message) != 0 || len(request.CiphertextBlob) != 0 || request.MessageType != "" || request.SigningAlgorithm != "" || request.EncryptionAlgorithm != "" {
			s.fail(w, "kms-public-shape")
			return
		}
		public, err := x509.ParsePKIXPublicKey(key.der)
		if err != nil {
			s.fail(w, "kms-public-key-encoding")
			return
		}
		_, signing := public.(*ecdsa.PublicKey)
		if !signing {
			if _, ok := public.(*rsa.PublicKey); !ok {
				s.fail(w, "kms-public-key-type")
				return
			}
		}
		spec, usage := "RSA_3072", "ENCRYPT_DECRYPT"
		if signing {
			spec, usage = "ECC_NIST_P256", "SIGN_VERIFY"
		}
		if target == "GetPublicKey" {
			value := map[string]any{"KeyId": request.KeyID, "KeySpec": spec, "KeyUsage": usage, "PublicKey": key.der}
			if signing {
				value["SigningAlgorithms"] = []string{"ECDSA_SHA_256"}
			} else {
				value["EncryptionAlgorithms"] = []string{"RSAES_OAEP_SHA_256"}
			}
			response = value
		} else {
			value := map[string]any{"Arn": request.KeyID, "KeyId": strings.Split(request.KeyID, "key/")[1], "AWSAccountId": "123456789012", "Enabled": true, "KeyState": "Enabled", "Origin": "AWS_KMS", "KeySpec": spec, "KeyUsage": usage}
			if !signing {
				value["EncryptionAlgorithms"] = []string{"RSAES_OAEP_SHA_256"}
			}
			response = map[string]any{"KeyMetadata": value}
		}
	case "Sign":
		permitted := phase == "init" || ((phase == "apply" || phase == "change") && key.role == "normal") || (phase == "successor" && (key.role == "normal" || key.role == "recovery-signing" || key.role == "successor"))
		if !permitted || key.signing == nil || len(request.Message) != 32 || request.MessageType != "DIGEST" || request.SigningAlgorithm != "ECDSA_SHA_256" || len(request.CiphertextBlob) != 0 || request.EncryptionAlgorithm != "" {
			s.fail(w, "kms-sign-authority-or-shape")
			return
		}
		signature, err := ecdsa.SignASN1(rand.Reader, key.signing, request.Message)
		if err != nil {
			s.fail(w, "local-signing")
			return
		}
		response = map[string]any{"KeyId": request.KeyID, "SigningAlgorithm": "ECDSA_SHA_256", "Signature": signature}
	case "Decrypt":
		permitted := (phase == "init" && (key.role == "authority" || key.role == "recovery-private")) || ((phase == "apply" || phase == "change" || phase == "noop" || phase == "authority" || phase == "successor" || phase == "invalid-private") && key.role == "authority") || (phase == "recovery" && (key.role == "recovery-private" || key.role == "successor-private")) || (phase == "successor" && (key.role == "recovery-private" || key.role == "successor-private")) || (phase == "authority" && key.role == "successor-private")
		permitted = permitted || phase == "materialize" && request.KeyID == s.materializationRecipientKey
		if !permitted || key.encryption == nil && key.decrypt == nil || len(request.CiphertextBlob) != 384 || request.EncryptionAlgorithm != "RSAES_OAEP_SHA_256" || len(request.Message) != 0 || request.MessageType != "" || request.SigningAlgorithm != "" {
			s.fail(w, "kms-private-authority-or-shape")
			return
		}
		if phase == "materialize" && s.materializationDecryptDenied {
			c.calls["Decrypt/"+key.role]++
			s.awsError(w, 403, "AccessDeniedException")
			return
		}
		var packet []byte
		var err error
		if key.decrypt != nil {
			packet, err = key.decrypt(request.CiphertextBlob)
		} else {
			packet, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, key.encryption, request.CiphertextBlob, nil)
		}
		if err != nil {
			s.fail(w, "local-oaep-authentication")
			return
		}
		defer clear(packet)
		if phase == "invalid-private" {
			if len(packet) != 100 {
				s.fail(w, "invalid-private-current-packet-shape")
				return
			}
			packet[0] ^= 1
		}
		response = map[string]any{"KeyId": request.KeyID, "EncryptionAlgorithm": "RSAES_OAEP_SHA_256", "Plaintext": packet}
	default:
		s.fail(w, "kms-target")
		return
	}
	c.calls[target+"/"+key.role]++
	if target == "Decrypt" && key.role == "authority" && s.waitCancellation(w, r) {
		return
	}
	encoded, err := json.Marshal(response)
	defer clear(encoded)
	if err != nil {
		s.fail(w, "kms-response")
		return
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("Content-Length", fmt.Sprint(len(encoded)))
	w.WriteHeader(200)
	s.writeResponse(w, encoded)
}
func (s *workflowServer) snapshot(phase string) workflowCounts {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := workflowCounts{calls: map[string]int{}}
	if c := s.counts[phase]; c != nil {
		result = *c
		result.calls = map[string]int{}
		for key, value := range c.calls {
			result.calls[key] = value
		}
	}
	return result
}
func (s *workflowServer) object(t *testing.T, key string) workflowObject {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	object, ok := s.objects[key]
	if !ok {
		t.Fatal("expected selected object absent")
	}
	return workflowObject{body: bytes.Clone(object.body), etag: object.etag}
}
func (s *workflowServer) clean(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.violations) != 0 {
		t.Fatalf("offline protocol fixture refused %d request(s): %v", len(s.violations), s.violations)
	}
}

func workflowStoreKey(prefix, key, phase string) bool {
	if key == prefix+"/HEAD" {
		return true
	}
	relative, ok := strings.CutPrefix(key, prefix+"/")
	if !ok {
		return false
	}
	parts := strings.Split(relative, "/")
	if len(parts) != 3 && len(parts) != 4 {
		return false
	}
	for _, text := range []string{parts[0], parts[len(parts)-1]} {
		raw, err := hex.DecodeString(text)
		if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != text || bytes.Equal(raw, make([]byte, 32)) {
			return false
		}
	}
	if len(parts) == 3 {
		return parts[1] == "configuration" || parts[1] == "result"
	}
	var limit uint64
	switch parts[1] {
	case "member":
		limit = contract.MaxValueEntryPages
	case "recipient":
		limit = contract.MaxRecipientPages
	case "access", "admin-index", "support":
		limit = contract.MaxChildPages
	case "root":
		limit = 1
	default:
		return false
	}
	index, err := strconv.ParseUint(parts[2], 10, 16)
	return err == nil && index < limit && strconv.FormatUint(index, 10) == parts[2]
}

// full_only: false
func TestPublicWorkflowStoreKeyAcceptsBoundedCanonicalGeneratedSupportPages(t *testing.T) {
	const prefix = "workflow-generated"
	const domain = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const object = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	page := func(index string) string { return prefix + "/" + domain + "/support/" + index + "/" + object }
	// Selected support has at most 256 pages. Keys use canonical decimal indices
	// and two nonzero lowercase 32-byte IDs, independently of the format encoder.
	for _, row := range []struct {
		name, key, phase string
		want             bool
	}{
		{"first", page("0"), "apply", true},
		{"generated-fourth", page("3"), "apply", true},
		{"last", page("255"), "apply", true},
		{"cold-reader", page("255"), "reader", true},
		{"one-over", page("256"), "apply", false},
		{"overflow", page("18446744073709551616"), "apply", false},
		{"negative", page("-1"), "apply", false},
		{"plus", page("+3"), "apply", false},
		{"leading-zero", page("03"), "apply", false},
		{"empty-index", page(""), "apply", false},
		{"missing-prefix", strings.TrimPrefix(page("0"), prefix+"/"), "apply", false},
		{"extra-component", page("0") + "/extra", "apply", false},
		{"uppercase-id", strings.Replace(page("0"), domain, strings.ToUpper(domain), 1), "apply", false},
		{"zero-id", strings.Replace(page("0"), domain, strings.Repeat("0", 64), 1), "apply", false},
		{"short-id", strings.Replace(page("0"), object, object[2:], 1), "apply", false},
		{"unknown-kind", strings.Replace(page("0"), "/support/", "/unknown/", 1), "apply", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := workflowStoreKey(prefix, row.key, row.phase); got != row.want {
				t.Fatalf("offline store key admission=%t want=%t", got, row.want)
			}
		})
	}
}

// full_only: false
func TestPublicWorkflowStoreKeysKeepEveryPageKindBoundAndWriteAuthority(t *testing.T) {
	const prefix = "workflow-pages"
	const domain = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const object = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	// Literal limits follow the stored reference grammar: two 32-page kinds,
	// three 256-page kinds and the one Root; no production encoder supplies them.
	for _, page := range []struct {
		kind  string
		count int
	}{{"member", 32}, {"recipient", 32}, {"access", 256}, {"admin-index", 256}, {"support", 256}, {"root", 1}} {
		for _, index := range []struct {
			name  string
			value int
			want  bool
		}{{"first", 0, true}, {"nonzero", 7, page.count > 7}, {"last", page.count - 1, true}, {"first-excess", page.count, false}} {
			t.Run(page.kind+"/"+index.name, func(t *testing.T) {
				key := prefix + "/" + domain + "/" + page.kind + "/" + strconv.Itoa(index.value) + "/" + object
				if workflowStoreKey(prefix, key, "reader") != index.want {
					t.Fatal("page key did not enforce its exact kind bound")
				}
			})
		}
	}
	key := prefix + "/" + domain + "/member/7/" + object
	for _, phase := range []string{"apply", "reader", "authority"} {
		t.Run("write/"+phase, func(t *testing.T) {
			s := &workflowServer{prefix: prefix, objectLimit: 1, objects: map[string]workflowObject{}}
			body := []byte("public fixture page")
			r := httptest.NewRequest(http.MethodPut, "https://s3.us-east-1.amazonaws.com/fixture-bucket/"+key, bytes.NewReader(body))
			r.Header.Set("X-Amz-Expected-Bucket-Owner", "123456789012")
			r.Header.Set("Content-Type", "application/octet-stream")
			r.Header.Set("If-None-Match", "*")
			sum := sha256.Sum256(body)
			r.Header.Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(sum[:]))
			w := httptest.NewRecorder()
			var counts workflowCounts
			s.s3(w, r, phase, &counts, body)
			if phase == "apply" {
				if w.Code != http.StatusOK || counts.creates != 1 || len(s.violations) != 0 || !bytes.Equal(s.objects[key].body, body) {
					t.Fatal("ordinary setup could not write a bounded nonzero page")
				}
			} else if w.Code != http.StatusForbidden || counts.creates != 0 || len(s.objects) != 0 || len(s.violations) != 1 || s.violations[0] != "s3-write-authority" {
				t.Fatal("page-key admission changed write authority")
			}
		})
	}
}

func (s *workflowServer) objectCount() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.objects) }

func (s *workflowServer) selector(n int) string {
	if s.family == "gcp" {
		return fmt.Sprintf("projects/fixture-project/locations/us-central1/keyRings/fixture/cryptoKeys/key%d/cryptoKeyVersions/1", n)
	}
	return workflowSelector(n)
}
func workflowPhase(phase string) bool {
	switch phase {
	case "init", "retry", "apply", "change", "noop", "reader", "authority", "recovery", "set", "set-change", "successor", "invalid-private", "materialize":
		return true
	}
	return false
}

func (s *workflowServer) summary(phase string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.counts[phase]
	if c == nil {
		c = &workflowCounts{}
	}
	return fmt.Sprintf("provider=%s phase=%s service_requests=%d token_requests=%d phase_reads=%d phase_lists=%d phase_deletes=%d phase_creates=%d phase_head_creates=%d phase_head_updates=%d phase_conditions=%d role_calls=%v", s.family, phase, s.requests, s.authRequests, c.reads, c.lists, c.deletes, c.creates, c.headCreates, c.headUpdates, c.conditions, c.calls)
}

// Called with s.mu held, after actual OAEP authentication and before any private
// response is written. The existing handler defers clear before it releases mu.
func (s *workflowServer) waitCancellation(w http.ResponseWriter, r *http.Request) bool {
	gate := s.cancelGate
	if gate == nil {
		return false
	}
	gate.uses++
	if gate.uses != 1 {
		s.fail(w, "cancellation-private-return-repeated")
		return true
	}
	var child *os.Process
	select {
	case child = <-gate.ready:
	case <-time.After(5 * time.Second):
		s.fail(w, "cancellation-child-not-ready")
		return true
	}
	if child == nil || child.Signal(syscall.SIGUSR1) != nil {
		s.fail(w, "cancellation-signal")
		return true
	}
	gate.signaled = true
	select {
	case <-r.Context().Done():
		gate.canceled = true
	case <-time.After(5 * time.Second):
		s.fail(w, "cancellation-request-not-joined")
	}
	return true
}
func (c workflowChild) cancellationState() (uses int, signaled, canceled bool) {
	if c.cancellation == nil {
		return 0, false, false
	}
	return c.cancellation.uses, c.cancellation.signaled, c.cancellation.canceled
}

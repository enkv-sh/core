package nativeprocess

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"hash/crc32"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func workflowDecode(body []byte, value any) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value) == nil && decoder.Decode(new(any)) == io.EOF
}
func workflowCRC(body []byte) uint32 { return crc32.Checksum(body, crc32.MakeTable(crc32.Castagnoli)) }
func workflowCRCBase64(body []byte) string {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], workflowCRC(body))
	return base64.StdEncoding.EncodeToString(encoded[:])
}
func workflowGCPQuery(values url.Values, allowed map[string]string) bool {
	for name, rows := range values {
		expected, ok := allowed[name]
		if !ok || len(rows) != 1 || rows[0] != expected {
			return false
		}
	}
	return true
}
func (s *workflowServer) writeJSON(w http.ResponseWriter, status int, value any) {
	body, err := json.Marshal(value)
	defer clear(body)
	if err != nil {
		panic("offline response fixture")
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	s.writeResponse(w, body)
}
func (s *workflowServer) gcpError(w http.ResponseWriter, status int, reason string) {
	s.writeJSON(w, status, map[string]any{"error": map[string]any{"code": status, "message": "offline fixture refusal", "errors": []map[string]string{{"reason": reason}}}})
}

// A real DetectDefault service-account source owns the JWT/token exchange.
// This local ADC fixture cannot establish a real user ADC login claim.
func (s *workflowServer) startGCPTokenServer(t *testing.T) {
	t.Helper()
	var err error
	s.authKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s.auth = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.authRequests++
		phase := strings.TrimPrefix(r.URL.Path, "/token/")
		standard := r.Host == "oauth2.googleapis.com" && r.URL.Path == "/token"
		expectedHost, expectedPath := strings.TrimPrefix(s.auth.URL, "http://"), "/token/"+phase
		expectedAudience := s.auth.URL + "/token/" + phase
		if standard {
			phase, expectedHost, expectedPath, expectedAudience = "authority", "oauth2.googleapis.com", "/token", "https://oauth2.googleapis.com/token"
		}
		refuse := func(reason string) { s.violations = append(s.violations, reason); s.gcpError(w, 403, "forbidden") }
		if s.authRequests > 64 || r.Host != expectedHost || r.Method != http.MethodPost || r.URL.RawQuery != "" || r.URL.Path != expectedPath || !workflowPhase(phase) || r.ContentLength < 0 || r.ContentLength > 8192 || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			refuse("adc-token-boundary")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 8193))
		err = errors.Join(err, r.Body.Close())
		defer clear(body)
		if err != nil || len(body) > 8192 || int64(len(body)) != r.ContentLength {
			refuse("adc-token-body")
			return
		}
		form, err := url.ParseQuery(string(body))
		if err != nil || len(form) != 2 || len(form["grant_type"]) != 1 || form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || len(form["assertion"]) != 1 {
			refuse("adc-token-form")
			return
		}
		parts := strings.Split(form.Get("assertion"), ".")
		if len(parts) != 3 {
			refuse("adc-jwt-shape")
			return
		}
		header, err1 := base64.RawURLEncoding.DecodeString(parts[0])
		claims, err2 := base64.RawURLEncoding.DecodeString(parts[1])
		signature, err3 := base64.RawURLEncoding.DecodeString(parts[2])
		defer clear(header)
		defer clear(claims)
		defer clear(signature)
		var h struct{ Alg, Typ, Kid string }
		var c struct {
			Issuer   string `json:"iss"`
			Audience string `json:"aud"`
			Scope    string
			Issued   int64 `json:"iat"`
			Expiry   int64 `json:"exp"`
		}
		sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		now := time.Now().Unix()
		if err1 != nil || err2 != nil || err3 != nil || !workflowDecode(header, &h) || !workflowDecode(claims, &c) || h.Alg != "RS256" || h.Typ != "JWT" || h.Kid != "offline-native" || c.Issuer != phase+"@fixture.iam.gserviceaccount.com" || c.Audience != expectedAudience || c.Scope != "https://www.googleapis.com/auth/cloud-platform" || c.Issued < now-60 || c.Issued > now+5 || c.Expiry <= now || c.Expiry > now+3605 || c.Expiry-c.Issued != 3600 || rsa.VerifyPKCS1v15(&s.authKey.PublicKey, crypto.SHA256, sum[:], signature) != nil {
			refuse("adc-jwt-facts-or-signature")
			return
		}
		count := s.counts[phase]
		if count == nil {
			count = &workflowCounts{calls: map[string]int{}}
			s.counts[phase] = count
		}
		count.calls["Token"]++
		s.writeJSON(w, 200, map[string]any{"access_token": "offline-native-" + phase, "token_type": "Bearer", "expires_in": 3600})
	}))
	s.auth.Config.ReadHeaderTimeout = 5 * time.Second
	s.auth.Config.ReadTimeout = 10 * time.Second
	s.auth.Config.WriteTimeout = 10 * time.Second
	s.auth.Config.MaxHeaderBytes = 16 << 10
	s.auth.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.auth.Start()
	t.Cleanup(s.auth.Close)
}
func (s *workflowServer) environment(t *testing.T, private, phase string) []string {
	t.Helper()
	environment := workflowEnvironment(private, phase)
	if s.family == "aws" {
		return environment
	}
	filtered := []string{}
	for _, entry := range environment {
		name := strings.SplitN(entry, "=", 2)[0]
		if strings.HasPrefix(name, "AWS_") || name == "GCE_METADATA_HOST" {
			continue
		}
		filtered = append(filtered, entry)
	}
	der, err := x509.MarshalPKCS8PrivateKey(s.authKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(der)
	credentials := map[string]any{"type": "service_account", "client_email": phase + "@fixture.iam.gserviceaccount.com", "private_key_id": "offline-native", "private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), "token_uri": s.auth.URL + "/token/" + phase, "universe_domain": "googleapis.com", "quota_project_id": "fixture-quota"}
	encoded, err := json.Marshal(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	path := filepath.Join(private, "local-adc.json")
	if err = os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	return append(filtered, "GOOGLE_APPLICATION_CREDENTIALS="+path, "GCE_METADATA_HOST=127.0.0.1:1")
}
func (s *workflowServer) gcp(w http.ResponseWriter, r *http.Request, phase string, c *workflowCounts, body []byte) {
	if r.Header.Get("X-Goog-User-Project") != "fixture-quota" {
		s.fail(w, "gcp-exact-quota")
		return
	}
	switch r.Host {
	case "storage.us-central1.rep.googleapis.com":
		s.gcs(w, r, phase, c, body)
	case "us-central1-cloudkms.googleapis.com":
		s.gcpKMS(w, r, phase, c, body)
	default:
		s.fail(w, "gcp-service-host")
	}
}
func (s *workflowServer) gcs(w http.ResponseWriter, r *http.Request, phase string, c *workflowCounts, body []byte) {
	if s.capacityStoreRequest(w, r, phase, c, body) {
		return
	}
	getPrefix := "/download/storage/v1/b/fixture-bucket/o/"
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, getPrefix) {
		key := strings.TrimPrefix(r.URL.Path, getPrefix)
		if !workflowStoreKey(s.prefix, key, phase) || len(body) != 0 || r.URL.Query().Get("alt") != "media" || !workflowGCPQuery(r.URL.Query(), map[string]string{"alt": "media", "prettyPrint": "false"}) {
			s.fail(w, "gcs-get-shape")
			return
		}
		c.reads++
		if key == s.prefix+"/HEAD" {
			c.headReads++
		}
		if phase == "materialize" && s.materializationStoreDenied || phase == "reader" && s.readerStoreDenied {
			s.gcpError(w, 403, "forbidden")
			return
		}
		object, ok := s.objects[key]
		if !ok {
			s.gcpError(w, 404, "notFound")
			return
		}
		w.Header().Set("X-Goog-Generation", object.etag)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(object.body)))
		w.WriteHeader(200)
		s.writeResponse(w, object.body)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/upload/storage/v1/b/fixture-bucket/o" || (phase != "init" && phase != "apply" && phase != "change" && phase != "successor") {
		s.fail(w, "gcs-write-route")
		return
	}
	generation := r.URL.Query().Get("ifGenerationMatch")
	number, err := strconv.ParseInt(generation, 10, 64)
	if err != nil || number < 0 || strconv.FormatInt(number, 10) != generation || r.URL.Query().Get("uploadType") != "multipart" || !workflowGCPQuery(r.URL.Query(), map[string]string{"ifGenerationMatch": generation, "uploadType": "multipart", "alt": "json", "prettyPrint": "false"}) {
		s.fail(w, "gcs-exact-generation")
		return
	}
	contentType, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "multipart/related" || len(parameters) != 1 || len(parameters["boundary"]) == 0 || len(parameters["boundary"]) > 128 {
		s.fail(w, "gcs-multipart-header")
		return
	}
	reader := multipart.NewReader(bytes.NewReader(body), parameters["boundary"])
	metadataPart, err := reader.NextPart()
	if err != nil || metadataPart.Header.Get("Content-Type") != "application/json" {
		s.fail(w, "gcs-metadata-part")
		return
	}
	metadataBody, err := io.ReadAll(io.LimitReader(metadataPart, 65537))
	err = errors.Join(err, metadataPart.Close())
	defer clear(metadataBody)
	var metadata struct{ Name, ContentType, CacheControl, Crc32c string }
	if err != nil || len(metadataBody) > 65536 || !workflowDecode(metadataBody, &metadata) || !workflowStoreKey(s.prefix, metadata.Name, phase) || metadata.ContentType != "application/octet-stream" || metadata.CacheControl != "private, no-store, no-transform" {
		s.fail(w, "gcs-metadata-facts")
		return
	}
	media, err := reader.NextPart()
	if err != nil || media.Header.Get("Content-Type") != "application/octet-stream" {
		s.fail(w, "gcs-media-part")
		return
	}
	payload, err := io.ReadAll(io.LimitReader(media, (1<<20)+1))
	err = errors.Join(err, media.Close())
	defer clear(payload)
	_, last := reader.NextPart()
	if err != nil || len(payload) == 0 || len(payload) > 1<<20 || last != io.EOF || metadata.Crc32c != workflowCRCBase64(payload) {
		s.fail(w, "gcs-payload-crc-or-shape")
		return
	}
	object, exists := s.objects[metadata.Name]
	head := metadata.Name == s.prefix+"/HEAD"
	if number == 0 {
		if exists {
			c.conditions++
			s.gcpError(w, 412, "conditionNotMet")
			return
		}
	} else if !head || !exists || object.etag != generation {
		c.conditions++
		s.gcpError(w, 412, "conditionNotMet")
		return
	}
	if head && exists && s.rejectHeadBody != nil && s.rejectHeadBody(payload) {
		c.conditions++
		s.gcpError(w, 412, "conditionNotMet")
		return
	}
	if !exists && len(s.objects) >= s.objectLimit {
		s.fail(w, "gcs-object-bound")
		return
	}
	s.version++
	token := strconv.Itoa(s.version)
	s.objects[metadata.Name] = workflowObject{body: bytes.Clone(payload), etag: token}
	if head {
		if exists {
			c.headUpdates++
		} else {
			c.headCreates++
		}
	} else {
		c.creates++
	}
	s.writeJSON(w, 200, map[string]any{"name": metadata.Name, "bucket": "fixture-bucket", "generation": token, "size": strconv.Itoa(len(payload)), "crc32c": metadata.Crc32c})
}
func (s *workflowServer) gcpKMS(w http.ResponseWriter, r *http.Request, phase string, c *workflowCounts, body []byte) {
	if phase == "reader" || phase == "retry" || phase == "set" || phase == "set-change" || !workflowGCPQuery(r.URL.Query(), map[string]string{"alt": "json", "prettyPrint": "false"}) || !strings.HasPrefix(r.URL.Path, "/v1/") {
		s.fail(w, "gcp-kms-route")
		return
	}
	resource := strings.TrimPrefix(r.URL.Path, "/v1/")
	selector, operation := resource, "version"
	if strings.HasSuffix(resource, "/publicKey") {
		selector, operation = strings.TrimSuffix(resource, "/publicKey"), "public"
	} else if strings.HasSuffix(resource, ":asymmetricSign") {
		selector, operation = strings.TrimSuffix(resource, ":asymmetricSign"), "sign"
	} else if strings.HasSuffix(resource, ":asymmetricDecrypt") {
		selector, operation = strings.TrimSuffix(resource, ":asymmetricDecrypt"), "decrypt"
	}
	key, ok := s.keys[selector]
	if !ok {
		for name, candidate := range s.keys {
			if resource == strings.Split(name, "/cryptoKeyVersions/")[0] && candidate.encryption != nil {
				key, ok, operation = candidate, true, "key"
				break
			}
		}
	}
	if !ok {
		s.fail(w, "gcp-kms-exact-resource")
		return
	}
	if phase == "materialize" && (operation != "decrypt" || selector != s.materializationRecipientKey) {
		s.fail(w, "materialization-exact-private-route")
		return
	}
	algorithm, purpose := "RSA_DECRYPT_OAEP_3072_SHA256", "ASYMMETRIC_DECRYPT"
	if key.signing != nil {
		algorithm, purpose = "EC_SIGN_P256_SHA256", "ASYMMETRIC_SIGN"
	}
	if operation == "key" || operation == "version" || operation == "public" {
		if r.Method != http.MethodGet || len(body) != 0 {
			s.fail(w, "gcp-kms-public-shape")
			return
		}
		switch operation {
		case "key":
			c.calls["CryptoKey/"+key.role]++
			s.writeJSON(w, 200, map[string]any{"name": resource, "purpose": purpose})
		case "version":
			c.calls["Version/"+key.role]++
			s.writeJSON(w, 200, map[string]any{"name": selector, "algorithm": algorithm, "state": "ENABLED", "protectionLevel": "HSM", "generateTime": "2026-01-01T00:00:00Z"})
		case "public":
			text := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: key.der}))
			c.calls["GetPublicKey/"+key.role]++
			s.writeJSON(w, 200, map[string]any{"name": selector, "algorithm": algorithm, "protectionLevel": "HSM", "pem": text, "pemCrc32c": strconv.FormatUint(uint64(workflowCRC([]byte(text))), 10)})
		}
		return
	}
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
		s.fail(w, "gcp-kms-private-method")
		return
	}
	switch operation {
	case "sign":
		var request struct {
			Digest struct {
				SHA256 []byte `json:"sha256"`
			}
			CRC string `json:"digestCrc32c"`
		}
		permitted := phase == "init" || (phase == "apply" || phase == "change") && key.role == "normal" || phase == "successor" && (key.role == "normal" || key.role == "recovery-signing" || key.role == "successor")
		if !workflowDecode(body, &request) || key.signing == nil || len(request.Digest.SHA256) != 32 || request.CRC != strconv.FormatUint(uint64(workflowCRC(request.Digest.SHA256)), 10) || !permitted {
			s.fail(w, "gcp-sign-facts-or-authority")
			return
		}
		signature, err := ecdsa.SignASN1(rand.Reader, key.signing, request.Digest.SHA256)
		if err != nil {
			s.fail(w, "gcp-local-sign")
			return
		}
		c.calls["Sign/"+key.role]++
		s.writeJSON(w, 200, map[string]any{"name": selector, "signature": signature, "signatureCrc32c": strconv.FormatUint(uint64(workflowCRC(signature)), 10), "verifiedDigestCrc32c": true})
	case "decrypt":
		var request struct {
			Ciphertext []byte
			CRC        string `json:"ciphertextCrc32c"`
		}
		permitted := (phase == "init" && (key.role == "authority" || key.role == "recovery-private")) || ((phase == "apply" || phase == "change" || phase == "noop" || phase == "authority" || phase == "successor" || phase == "invalid-private") && key.role == "authority") || (phase == "recovery" && (key.role == "recovery-private" || key.role == "successor-private")) || (phase == "successor" && (key.role == "recovery-private" || key.role == "successor-private")) || (phase == "authority" && key.role == "successor-private")
		permitted = permitted || phase == "materialize" && selector == s.materializationRecipientKey
		if !workflowDecode(body, &request) || key.encryption == nil || !permitted || len(request.Ciphertext) != 384 || request.CRC != strconv.FormatUint(uint64(workflowCRC(request.Ciphertext)), 10) {
			s.fail(w, "gcp-decrypt-facts-or-authority")
			return
		}
		if phase == "materialize" && s.materializationDecryptDenied {
			c.calls["Decrypt/"+key.role]++
			s.gcpError(w, 403, "forbidden")
			return
		}
		packet, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key.encryption, request.Ciphertext, nil)
		if err != nil {
			s.fail(w, "gcp-local-oaep")
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
		c.calls["Decrypt/"+key.role]++
		if key.role == "authority" && s.waitCancellation(w, r) {
			return
		}
		s.writeJSON(w, 200, map[string]any{"plaintext": packet, "plaintextCrc32c": strconv.FormatUint(uint64(workflowCRC(packet)), 10), "verifiedCiphertextCrc32c": true, "protectionLevel": "HSM"})
	default:
		s.fail(w, "gcp-kms-operation")
	}
}

package recovery

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"os"
	"strings"
	"sync"
)

type ReadTransportEvidence struct {
	Attempted, Sent, Refused, Injected RecoveryCounts
	ReservedRequests, ReservedBytes    uint64
	DecryptResources                   []string
	Failures                           uint64
}

type GCPReadTransport struct {
	mu                                           sync.Mutex
	next                                         *http.Transport
	bucket, prefix, region, normal, recovery     string
	maximumRequests, maximumBytes, responseBytes uint64
	evidence                                     ReadTransportEvidence
	removal                                      *ExactRemoval
}

func NewGCPReadTransport(bucket, prefix, region, normal, recovery string, requests, bodyBytes, responseBytes uint64) (*GCPReadTransport, error) {
	next := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DisableKeepAlives: true, DisableCompression: true, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}, MaxResponseHeaderBytes: 64 << 10}
	return newGCPReadTransport(next, bucket, prefix, region, normal, recovery, requests, bodyBytes, responseBytes)
}

// NewGCPResponderReadTransport keeps the same read and authentication bounds
// while dialing only the parent-owned TLS responder. Its upstream evidence is
// owned by that responder; this transport records child attempts and relay sends.
func NewGCPResponderReadTransport(bucket, prefix, region, normal, recovery string, requests, bodyBytes, responseBytes uint64, address string, certificate []byte) (*GCPReadTransport, error) {
	next, err := GCPResponderTransport(address, certificate)
	if err != nil {
		return nil, err
	}
	return newGCPReadTransport(next, bucket, prefix, region, normal, recovery, requests, bodyBytes, responseBytes)
}
func newGCPReadTransport(next *http.Transport, bucket, prefix, region, normal, recovery string, requests, bodyBytes, responseBytes uint64) (*GCPReadTransport, error) {
	if next == nil || next.Proxy != nil || !next.DisableKeepAlives || next.TLSClientConfig == nil || next.TLSClientConfig.InsecureSkipVerify || bucket == "" || prefix == "" || region == "" || normal == "" && recovery == "" || requests == 0 || requests > 4096 || responseBytes == 0 || responseBytes > 8<<20 || bodyBytes < responseBytes {
		return nil, errors.New("read transport admission refused")
	}
	return &GCPReadTransport{next: next, bucket: bucket, prefix: prefix, region: region, normal: normal, recovery: recovery, maximumRequests: requests, maximumBytes: bodyBytes, responseBytes: responseBytes}, nil
}
func (t *GCPReadTransport) CloseIdleConnections() { t.next.CloseIdleConnections() }
func (t *GCPReadTransport) Evidence() ReadTransportEvidence {
	t.mu.Lock()
	defer t.mu.Unlock()
	value := t.evidence
	value.DecryptResources = append([]string(nil), value.DecryptResources...)
	return value
}

type readOperation uint8

const (
	readObject readOperation = iota + 1
	normalPublic
	recoveryPublic
	recoveryMetadata
	authorityDecrypt
	authenticate
	removeObject
)

func countReadOperation(counts *RecoveryCounts, operation readOperation) {
	switch operation {
	case readObject:
		counts.Reads++
	case normalPublic:
		counts.NormalLookups++
		counts.PublicLookups++
	case recoveryPublic:
		counts.RecoveryLookups++
		counts.PublicLookups++
	case recoveryMetadata:
		counts.RecoveryMetadata++
	case authorityDecrypt:
		counts.AuthorityDecrypts++
	case authenticate:
		counts.Authentication++
	case removeObject:
		counts.Delete++
	}
}

func (t *GCPReadTransport) classify(q *http.Request) (readOperation, string) {
	counts := &t.evidence.Attempted
	if q.URL == nil || q.URL.Scheme != "https" || q.URL.User != nil || q.URL.Opaque != "" || q.URL.Fragment != "" || q.Host != "" && q.Host != q.URL.Host {
		counts.Unknown++
		t.evidence.Refused.Unknown++
		return 0, ""
	}
	if q.URL.Host == "oauth2.googleapis.com" && q.URL.Path == "/token" && q.URL.RawQuery == "" && q.Method == http.MethodPost {
		return authenticate, ""
	}
	if q.Header.Get("Authorization") == "" {
		counts.Unknown++
		t.evidence.Refused.Unknown++
		return 0, ""
	}
	if q.URL.Host == "storage."+t.region+".rep.googleapis.com" {
		if q.Method == http.MethodDelete && t.removal != nil && t.evidence.Attempted.Delete == 0 && q.URL.Path == "/storage/v1/b/"+t.bucket+"/o/"+t.removal.Key {
			query := q.URL.Query()
			if len(query) == 3 && query.Get("alt") == "json" && len(query["alt"]) == 1 && query.Get("ifGenerationMatch") == t.removal.Token.Value && len(query["ifGenerationMatch"]) == 1 && query.Get("prettyPrint") == "false" && len(query["prettyPrint"]) == 1 {
				return removeObject, ""
			}
		}
		if q.Method != http.MethodGet {
			switch q.Method {
			case http.MethodDelete:
				counts.Delete++
				t.evidence.Refused.Delete++
			case http.MethodPost, http.MethodPut, http.MethodPatch:
				counts.StoreWrites++
				t.evidence.Refused.StoreWrites++
			default:
				counts.Unknown++
				t.evidence.Refused.Unknown++
			}
			return 0, ""
		}
		query := q.URL.Query()
		if len(query) != 2 || query.Get("alt") != "media" || len(query["alt"]) != 1 || query.Get("prettyPrint") != "false" || len(query["prettyPrint"]) != 1 {
			counts.Discovery++
			t.evidence.Refused.Discovery++
			return 0, ""
		}
		if !strings.HasPrefix(q.URL.Path, "/download/storage/v1/b/"+t.bucket+"/o/"+t.prefix+"/") {
			counts.Unknown++
			t.evidence.Refused.Unknown++
			return 0, ""
		}
		return readObject, ""
	}
	key, action, found := strings.Cut(strings.TrimPrefix(q.URL.Path, "/v1/"), ":")
	if strings.HasSuffix(key, "/publicKey") {
		key = strings.TrimSuffix(key, "/publicKey")
		action = "publicKey"
	}
	parts := strings.Split(key, "/")
	if !strings.HasPrefix(q.URL.Path, "/v1/") || len(parts) != 10 || parts[0] != "projects" || parts[1] == "" || parts[2] != "locations" || parts[3] == "" || parts[4] != "keyRings" || parts[5] == "" || parts[6] != "cryptoKeys" || parts[7] == "" || parts[8] != "cryptoKeyVersions" || parts[9] == "" || q.URL.Host != parts[3]+"-cloudkms.googleapis.com" || !gcpJSONQuery(q) {
		counts.Unknown++
		t.evidence.Refused.Unknown++
		return 0, ""
	}
	switch {
	case q.Method == http.MethodGet && action == "publicKey":
		if key == t.normal {
			return normalPublic, ""
		}
		if key == t.recovery && t.recovery != "" {
			return recoveryPublic, ""
		}
	case q.Method == http.MethodGet && !found && key == t.recovery && t.recovery != "":
		return recoveryMetadata, ""
	case q.Method == http.MethodPost && action == "asymmetricDecrypt":
		return authorityDecrypt, key
	case action == "asymmetricSign":
		counts.Sign++
		t.evidence.Refused.Sign++
		return 0, ""
	case action == "setIamPolicy":
		counts.IAMChanges++
		t.evidence.Refused.IAMChanges++
		return 0, ""
	}
	counts.Unknown++
	t.evidence.Refused.Unknown++
	return 0, ""
}

func (t *GCPReadTransport) RoundTrip(q *http.Request) (reply *http.Response, resultErr error) {
	if q.Body != nil {
		defer func() {
			if q.Body.Close() != nil {
				if reply != nil && reply.Body != nil {
					_ = reply.Body.Close()
				}
				t.mu.Lock()
				t.evidence.Failures++
				t.mu.Unlock()
				reply, resultErr = nil, errors.New("read transport request close refused")
			}
		}()
	}

	t.mu.Lock()
	operation, key := t.classify(q)
	if operation == 0 {
		t.mu.Unlock()
		return nil, errors.New("read transport request refused")
	}
	countReadOperation(&t.evidence.Attempted, operation)
	if operation == authorityDecrypt && len(t.evidence.DecryptResources) >= 512 {
		t.evidence.Attempted.Unknown++
		t.mu.Unlock()
		return nil, errors.New("read transport request refused")
	}

	bodyBytes := q.ContentLength
	if bodyBytes < 0 || bodyBytes > 64<<10 || operation != authenticate && operation != authorityDecrypt && bodyBytes != 0 {
		t.evidence.Attempted.Unknown++
		t.mu.Unlock()
		return nil, errors.New("read transport request refused")
	}
	t.mu.Unlock()
	var requestBody []byte
	if q.Body != nil {
		var readErr error
		requestBody, readErr = io.ReadAll(io.LimitReader(q.Body, (64<<10)+1))
		if readErr != nil || int64(len(requestBody)) != bodyBytes {
			clear(requestBody)
			t.mu.Lock()
			t.evidence.Attempted.Unknown++
			t.mu.Unlock()
			return nil, errors.New("read transport request refused")
		}
	}
	defer clear(requestBody)
	t.mu.Lock()

	allowance := t.responseBytes + uint64(bodyBytes)
	if t.evidence.ReservedRequests >= t.maximumRequests || t.evidence.ReservedBytes > t.maximumBytes || allowance > t.maximumBytes-t.evidence.ReservedBytes {
		t.evidence.Attempted.Unknown++
		t.mu.Unlock()
		return nil, errors.New("read transport budget exhausted")
	}
	t.evidence.ReservedRequests++
	t.evidence.ReservedBytes += allowance
	t.mu.Unlock()
	sends := 0
	trace := &httptrace.ClientTrace{WroteRequest: func(httptrace.WroteRequestInfo) {
		t.mu.Lock()
		defer t.mu.Unlock()
		sends++
		countReadOperation(&t.evidence.Sent, operation)
		if operation == authorityDecrypt {
			digest := sha256.Sum256([]byte(key))
			t.evidence.DecryptResources = append(t.evidence.DecryptResources, hex.EncodeToString(digest[:]))
		}
		if sends > 1 {
			t.evidence.Sent.Unknown++
		}
	}}
	outbound := q.Clone(httptrace.WithClientTrace(q.Context(), trace))
	if q.Body != nil {
		outbound.Body = io.NopCloser(bytes.NewReader(requestBody))
	}
	outbound.GetBody = nil
	response, err := t.next.RoundTrip(outbound)
	if err != nil {
		t.mu.Lock()
		t.evidence.Failures++
		t.mu.Unlock()
		return nil, errors.New("read transport unavailable")
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, int64(t.responseBytes)+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || uint64(len(body)) > t.responseBytes {
		clear(body)
		t.mu.Lock()
		t.evidence.Failures++
		t.mu.Unlock()
		return nil, errors.New("read transport response refused")
	}
	response.Body = &ownedReadResponse{Reader: bytes.NewReader(body), body: body}
	return response, nil
}

type ownedReadResponse struct {
	*bytes.Reader
	body []byte
}

func (body *ownedReadResponse) Close() error { clear(body.body); body.body = nil; return nil }

// CheckGCPPrivateRequests runs only in the parent, against its independently
// retained current binding. No Authority selector enters the restricted input.
func CheckGCPPrivateRequests(evidence ReadTransportEvidence, authority string) error {
	if evidence.Sent.AuthorityDecrypts != uint64(len(evidence.DecryptResources)) || len(evidence.DecryptResources) > 512 {
		return errors.New("private request evidence incomplete")
	}
	expected := sha256.Sum256([]byte(authority))
	digest := hex.EncodeToString(expected[:])
	for _, resource := range evidence.DecryptResources {
		if resource != digest {
			return errors.New("non-authority private request observed")
		}
	}
	return nil
}

func WriteReadTransportEvidence(path string, evidence ReadTransportEvidence) error {
	if evidence.ReservedRequests > 4096 || len(evidence.DecryptResources) > 512 {
		return errors.New("read transport evidence refused")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("read transport evidence unavailable")
	}
	encoded := json.NewEncoder(file).Encode(evidence)
	closed := file.Close()
	if encoded != nil || closed != nil {
		return errors.New("read transport evidence incomplete")
	}
	return nil
}

func gcpJSONQuery(q *http.Request) bool {
	query := q.URL.Query()
	return len(query) == 2 && len(query["alt"]) == 1 && query.Get("alt") == "json" && len(query["prettyPrint"]) == 1 && query.Get("prettyPrint") == "false"
}

package recovery

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/installedarchive"
)

// AWSRelayConfig is private parent state. It is never a recovery-child input.
type AWSRelayConfig struct {
	Bucket, Prefix, Region             string
	Normal, Recovery                   installedarchive.SigningResource
	AuthoritySelector, AuthorityRegion string
	Requests, BodyBytes, ResponseBytes uint64
	Policy                             ResponderPolicy
	AfterPublic                        func(context.Context) error
	Removal                            *ExactRemoval
}

// AWSReadRelay bounds and accounts ordinary SDK calls before forwarding. It has
// no inventory, oracle or cleanup endpoint, and never records request contents.
type AWSReadRelay struct {
	mu                sync.Mutex
	config            AWSRelayConfig
	counts            RecoveryCounts
	evidence          ReadTransportEvidence
	externalMutations uint8
	mutationStarted   bool
	requests, bytes   uint64
	server            *httptest.Server
	certificate       []byte
	transport         *http.Transport
}

func NewAWSReadRelay(t testing.TB, config AWSRelayConfig) (*AWSReadRelay, error) {
	t.Helper()
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DisableKeepAlives: true, DisableCompression: true, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}, MaxResponseHeaderBytes: 64 << 10}
	return newAWSReadRelay(t, config, transport)
}

func newAWSReadRelay(t testing.TB, config AWSRelayConfig, transport *http.Transport) (*AWSReadRelay, error) {
	t.Helper()
	if config.Bucket == "" || config.Prefix == "" || config.Region == "" || config.AuthoritySelector == "" || config.AuthorityRegion == "" || config.Requests == 0 || config.Requests > 4096 || config.ResponseBytes == 0 || config.ResponseBytes > 8<<20 || config.BodyBytes < config.ResponseBytes || transport == nil || transport.Proxy != nil || !transport.DisableKeepAlives || transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify {
		return nil, errors.New("private relay admission refused")
	}
	relay := &AWSReadRelay{config: config, transport: transport}
	if config.Removal != nil && !config.Removal.valid(contract.AWS, config.Prefix) {
		return nil, errors.New("private exact removal refused")
	}
	hosts := []string{"s3." + config.Region + ".amazonaws.com", "kms." + config.AuthorityRegion + ".amazonaws.com"}
	for _, resource := range []installedarchive.SigningResource{config.Normal, config.Recovery} {
		if resource.Selector != "" {
			hosts = append(hosts, "kms."+resource.Region+".amazonaws.com")
		}
	}
	relay.server, relay.certificate = startAWSRecoveryServer(t, hosts, http.HandlerFunc(relay.serve))
	t.Cleanup(transport.CloseIdleConnections)
	return relay, nil
}
func (r *AWSReadRelay) Address() string        { return r.server.Listener.Addr().String() }
func (r *AWSReadRelay) Certificate() []byte    { return bytes.Clone(r.certificate) }
func (r *AWSReadRelay) Counts() RecoveryCounts { r.mu.Lock(); defer r.mu.Unlock(); return r.counts }
func (r *AWSReadRelay) Evidence() ReadTransportEvidence {
	r.mu.Lock()
	defer r.mu.Unlock()
	value := r.evidence
	value.Attempted = r.counts
	value.ReservedRequests, value.ReservedBytes = r.requests, r.bytes
	return value
}
func (r *AWSReadRelay) ExternalMutations() uint8 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.externalMutations
}

func (r *AWSReadRelay) Usage() (uint64, uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.requests, r.bytes
}

func (r *AWSReadRelay) classify(q *http.Request, body []byte) bool {
	c := r.config
	if q.URL.User != nil || q.URL.Opaque != "" || q.URL.Fragment != "" || q.Host == "" || q.Header.Get("Authorization") == "" {
		r.counts.Unknown++
		r.evidence.Refused.Unknown++
		return false
	}
	if q.Host == "s3."+c.Region+".amazonaws.com" {
		if q.Method == http.MethodDelete && c.Removal != nil && r.counts.Delete == 0 && q.URL.Path == "/"+c.Bucket+"/"+c.Removal.Key && q.URL.RawQuery == "x-id=DeleteObject" && q.Header.Get("If-Match") == c.Removal.Token.Value && len(body) == 0 {
			r.counts.Delete++
			return true
		}
		if q.Method != http.MethodGet {
			switch q.Method {
			case http.MethodDelete:
				r.counts.Delete++
				r.evidence.Refused.Delete++
			case http.MethodPut:
				if q.Header.Get("If-Match") != "" {
					r.counts.CAS++
					r.evidence.Refused.CAS++
				} else {
					r.counts.StoreWrites++
					r.evidence.Refused.StoreWrites++
				}
			default:
				r.counts.Unknown++
				r.evidence.Refused.Unknown++
			}
			return false
		}
		query := q.URL.Query()
		if len(query) > 0 && (len(query) != 1 || query.Get("x-id") != "GetObject" || len(query["x-id"]) != 1) {
			r.counts.Discovery++
			r.evidence.Refused.Discovery++
			return false
		}
		if len(body) != 0 || !strings.HasPrefix(q.URL.Path, "/"+c.Bucket+"/"+c.Prefix+"/") {
			r.counts.Unknown++
			r.evidence.Refused.Unknown++
			return false
		}
		r.counts.Reads++
		return true
	}
	if q.Method != http.MethodPost || q.URL.Path != "/" || q.URL.RawQuery != "" {
		r.counts.Unknown++
		r.evidence.Refused.Unknown++
		return false
	}
	var input struct {
		KeyID      string `json:"KeyId"`
		Ciphertext string `json:"CiphertextBlob"`
		Algorithm  string `json:"EncryptionAlgorithm"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var trailing any
	if decoder.Decode(&input) != nil || decoder.Decode(&trailing) != io.EOF {
		r.counts.Unknown++
		r.evidence.Refused.Unknown++
		return false
	}
	switch q.Header.Get("X-Amz-Target") {
	case "TrentService.GetPublicKey", "TrentService.DescribeKey":
		role := 0
		if input.KeyID == c.Normal.Selector && q.Host == "kms."+c.Normal.Region+".amazonaws.com" {
			role = 1
		}
		if input.KeyID == c.Recovery.Selector && q.Host == "kms."+c.Recovery.Region+".amazonaws.com" {
			role = 2
		}
		if role == 0 || input.Ciphertext != "" || input.Algorithm != "" {
			r.counts.Unknown++
			r.evidence.Refused.Unknown++
			return false
		}
		if q.Header.Get("X-Amz-Target") == "TrentService.DescribeKey" {
			if role != 2 {
				r.counts.Unknown++
				r.evidence.Refused.Unknown++
				return false
			}
			r.counts.RecoveryMetadata++
		} else {
			r.counts.PublicLookups++
			if role == 1 {
				r.counts.NormalLookups++
			} else {
				r.counts.RecoveryLookups++
			}
		}
	case "TrentService.Decrypt":
		if input.KeyID != c.AuthoritySelector || q.Host != "kms."+c.AuthorityRegion+".amazonaws.com" {
			r.counts.OtherDecrypts++
			r.evidence.Refused.OtherDecrypts++
			return false
		}
		if input.Algorithm != "RSAES_OAEP_SHA_256" || input.Ciphertext == "" {
			r.counts.Unknown++
			r.evidence.Refused.Unknown++
			return false
		}
		r.counts.AuthorityDecrypts++
	case "TrentService.Sign":
		r.counts.Sign++
		r.evidence.Refused.Sign++
		return false
	case "TrentService.CreateGrant", "TrentService.RevokeGrant", "TrentService.RetireGrant":
		r.counts.GrantChanges++
		r.evidence.Refused.GrantChanges++
		return false
	case "TrentService.CreateKey", "TrentService.DisableKey", "TrentService.ScheduleKeyDeletion":
		r.counts.KeyChanges++
		r.evidence.Refused.KeyChanges++
		return false
	default:
		r.counts.Unknown++
		r.evidence.Refused.Unknown++
		return false
	}
	return true
}

func (r *AWSReadRelay) serve(w http.ResponseWriter, q *http.Request) {
	body, err := io.ReadAll(io.LimitReader(q.Body, (16<<10)+1))
	defer clear(body)
	r.mu.Lock()
	if err != nil || len(body) > 16<<10 {
		r.counts.Unknown++
		r.mu.Unlock()
		http.Error(w, "private relay refused", http.StatusForbidden)
		return
	}
	before := r.counts
	if !r.classify(q, body) {
		r.mu.Unlock()
		http.Error(w, "private relay refused", http.StatusForbidden)
		return
	}
	operation := readObject
	switch {
	case r.counts.Delete > before.Delete:
		operation = removeObject
	case r.counts.NormalLookups > before.NormalLookups:
		operation = normalPublic
	case r.counts.RecoveryLookups > before.RecoveryLookups:
		operation = recoveryPublic
	case r.counts.RecoveryMetadata > before.RecoveryMetadata:
		operation = recoveryMetadata
	case r.counts.AuthorityDecrypts > before.AuthorityDecrypts:
		operation = authorityDecrypt
	}
	policy := r.config.Policy
	if operation == normalPublic && policy.DenyNormal || (operation == recoveryPublic || operation == recoveryMetadata) && policy.DenyRecovery || operation == authorityDecrypt && (policy.DenyAuthority || policy.DenySecretOrdinal == r.counts.AuthorityDecrypts) {
		countReadOperation(&r.evidence.Injected, operation)
		r.mu.Unlock()
		http.Error(w, "parent-controlled denial", http.StatusForbidden)
		return
	}
	allowance := r.config.ResponseBytes + uint64(len(body))
	if r.requests >= r.config.Requests || r.bytes > r.config.BodyBytes || allowance > r.config.BodyBytes-r.bytes {
		r.counts.Unknown++
		r.mu.Unlock()
		http.Error(w, "private relay budget exhausted", http.StatusForbidden)
		return
	}
	r.requests++
	r.bytes += allowance
	r.mu.Unlock()
	sends := 0
	trace := &httptrace.ClientTrace{WroteRequest: func(httptrace.WroteRequestInfo) {
		r.mu.Lock()
		defer r.mu.Unlock()
		sends++
		countReadOperation(&r.evidence.Sent, operation)
		if sends > 1 {
			r.evidence.Sent.Unknown++
		}
	}}
	outbound := q.Clone(httptrace.WithClientTrace(q.Context(), trace))
	outbound.URL.Scheme = "https"
	outbound.URL.Host = q.Host
	outbound.Host = q.Host
	outbound.RequestURI = ""
	outbound.Body = io.NopCloser(bytes.NewReader(body))
	outbound.ContentLength = q.ContentLength
	outbound.GetBody = nil
	response, err := r.transport.RoundTrip(outbound)
	if err != nil {
		r.mu.Lock()
		r.evidence.Failures++
		r.mu.Unlock()
		http.Error(w, "private relay transport unavailable", http.StatusBadGateway)
		return
	}
	reply, readErr := io.ReadAll(io.LimitReader(response.Body, int64(r.config.ResponseBytes)+1))
	closeErr := response.Body.Close()
	defer clear(reply)
	if readErr != nil || closeErr != nil || uint64(len(reply)) > r.config.ResponseBytes {
		r.mu.Lock()
		r.evidence.Failures++
		r.mu.Unlock()
		http.Error(w, "private relay response refused", http.StatusBadGateway)
		return
	}
	if operation == normalPublic || operation == recoveryPublic {
		r.mu.Lock()
		mutate := r.config.AfterPublic != nil && !r.mutationStarted
		if mutate {
			r.mutationStarted = true
		}
		r.mu.Unlock()
		if mutate && r.config.AfterPublic(q.Context()) != nil {
			r.mu.Lock()
			r.evidence.Failures++
			r.mu.Unlock()
			http.Error(w, "parent-controlled mutation refused", http.StatusBadGateway)
			return
		}
		if mutate {
			r.mu.Lock()
			r.externalMutations++
			r.mu.Unlock()
		}
	}
	// RoundTrip performs one send; no redirect client or replay loop exists here.
	for name, values := range response.Header {
		w.Header()[name] = append([]string(nil), values...)
	}
	w.WriteHeader(response.StatusCode)
	if _, err := w.Write(reply); err != nil {
		r.mu.Lock()
		r.counts.Unknown++
		r.mu.Unlock()
	}
}

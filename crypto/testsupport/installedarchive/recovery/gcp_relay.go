package recovery

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/installedarchive"
)

type GCPRelayConfig struct {
	Bucket, Prefix, Region             string
	Normal, Recovery                   installedarchive.SigningResource
	AuthoritySelector                  string
	Requests, BodyBytes, ResponseBytes uint64
	Policy                             ResponderPolicy
	AfterPublic                        func(context.Context) error
	Removal                            *ExactRemoval
}

type GCPReadRelay struct {
	mu                sync.Mutex
	config            GCPRelayConfig
	transport         *GCPReadTransport
	server            *httptest.Server
	certificate       []byte
	mutationStarted   bool
	externalMutations uint8
}

func NewGCPReadRelay(t testing.TB, config GCPRelayConfig) (*GCPReadRelay, error) {
	transport, err := NewGCPReadTransport(config.Bucket, config.Prefix, config.Region, config.Normal.Selector, config.Recovery.Selector, config.Requests, config.BodyBytes, config.ResponseBytes)
	if err != nil {
		return nil, err
	}
	return newGCPReadRelay(t, config, transport)
}
func newGCPReadRelay(t testing.TB, config GCPRelayConfig, transport *GCPReadTransport) (*GCPReadRelay, error) {
	t.Helper()
	parts := strings.Split(config.AuthoritySelector, "/")
	if transport == nil || len(parts) != 10 || parts[0] != "projects" || parts[2] != "locations" || parts[4] != "keyRings" || parts[6] != "cryptoKeys" || parts[8] != "cryptoKeyVersions" {
		return nil, errors.New("GCP parent relay admission refused")
	}
	if config.Removal != nil && !config.Removal.valid(contract.GCP, config.Prefix) {
		return nil, errors.New("private exact removal refused")
	}
	transport.removal = config.Removal
	hosts := []string{"oauth2.googleapis.com", "storage." + config.Region + ".rep.googleapis.com", parts[3] + "-cloudkms.googleapis.com"}
	for _, resource := range []installedarchive.SigningResource{config.Normal, config.Recovery} {
		if resource.Selector != "" {
			hosts = append(hosts, resource.Region+"-cloudkms.googleapis.com")
		}
	}
	relay := &GCPReadRelay{config: config, transport: transport}
	relay.server, relay.certificate = startAWSRecoveryServer(t, hosts, http.HandlerFunc(relay.serve))
	t.Cleanup(transport.CloseIdleConnections)
	return relay, nil
}
func (r *GCPReadRelay) Address() string                 { return r.server.Listener.Addr().String() }
func (r *GCPReadRelay) Certificate() []byte             { return bytes.Clone(r.certificate) }
func (r *GCPReadRelay) Evidence() ReadTransportEvidence { return r.transport.Evidence() }
func (r *GCPReadRelay) ExternalMutations() uint8 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.externalMutations
}
func (r *GCPReadRelay) serve(w http.ResponseWriter, q *http.Request) {
	body, err := io.ReadAll(io.LimitReader(q.Body, (64<<10)+1))
	defer clear(body)
	if err != nil || len(body) > 64<<10 || q.ContentLength != int64(len(body)) {
		http.Error(w, "GCP relay body refused", http.StatusForbidden)
		return
	}
	outbound := q.Clone(q.Context())
	outbound.URL.Scheme, outbound.URL.Host = "https", q.Host
	outbound.Host, outbound.RequestURI = q.Host, ""
	outbound.Body = io.NopCloser(bytes.NewReader(body))
	outbound.GetBody = nil
	r.transport.mu.Lock()
	operation, key := r.transport.classify(outbound)
	if operation == 0 {
		r.transport.mu.Unlock()
		http.Error(w, "GCP relay target refused", http.StatusForbidden)
		return
	}
	if operation == authorityDecrypt && key != r.config.AuthoritySelector {
		r.transport.evidence.Attempted.OtherDecrypts++
		r.transport.evidence.Refused.OtherDecrypts++
		r.transport.mu.Unlock()
		http.Error(w, "GCP relay private target refused", http.StatusForbidden)
		return
	}
	policy := r.config.Policy
	ordinal := r.transport.evidence.Attempted.AuthorityDecrypts + 1
	if operation == normalPublic && policy.DenyNormal || (operation == recoveryPublic || operation == recoveryMetadata) && policy.DenyRecovery || operation == authorityDecrypt && (policy.DenyAuthority || policy.DenySecretOrdinal == ordinal) {
		countReadOperation(&r.transport.evidence.Attempted, operation)
		countReadOperation(&r.transport.evidence.Injected, operation)
		r.transport.mu.Unlock()
		http.Error(w, "parent-controlled denial", http.StatusForbidden)
		return
	}
	r.transport.mu.Unlock()
	response, err := r.transport.RoundTrip(outbound)
	if err != nil {
		http.Error(w, "GCP relay transport refused", http.StatusBadGateway)
		return
	}
	reply, err := io.ReadAll(io.LimitReader(response.Body, int64(r.config.ResponseBytes)+1))
	closeErr := response.Body.Close()
	defer clear(reply)
	if err != nil || closeErr != nil || uint64(len(reply)) > r.config.ResponseBytes {
		r.transport.mu.Lock()
		r.transport.evidence.Failures++
		r.transport.mu.Unlock()
		http.Error(w, "GCP relay response refused", http.StatusBadGateway)
		return
	}
	if operation == normalPublic || operation == recoveryPublic {
		r.mu.Lock()
		mutate := r.config.AfterPublic != nil && !r.mutationStarted
		if mutate {
			r.mutationStarted = true
		}
		r.mu.Unlock()
		if mutate {
			if r.config.AfterPublic(q.Context()) != nil {
				http.Error(w, "parent-controlled mutation refused", http.StatusBadGateway)
				return
			}
			r.mu.Lock()
			r.externalMutations++
			r.mu.Unlock()
		}
	}
	for name, values := range response.Header {
		w.Header()[name] = append([]string(nil), values...)
	}
	w.WriteHeader(response.StatusCode)
	if _, err := w.Write(reply); err != nil {
		r.transport.mu.Lock()
		r.transport.evidence.Failures++
		r.transport.mu.Unlock()
	}
}

// GCPResponderTransport changes only the local TCP route. URL, Host and TLS
// server-name validation still use the exact official request target.
func GCPResponderTransport(address string, certificate []byte) (*http.Transport, error) {
	host, _, err := net.SplitHostPort(address)
	parsed, certErr := x509.ParseCertificate(certificate)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || certErr != nil {
		return nil, errors.New("GCP responder transport refused")
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 64 << 10, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}}, nil
}

package observability

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
	"reflect"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

type bufferedHTTPConnection struct {
	mu                    sync.Mutex
	reads, writes, closes int
	closeError            error
}

func (connection *bufferedHTTPConnection) Read(data []byte) (int, error) {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	connection.reads++
	// TLS can return already decrypted bytes even after its raw socket closes.
	return copy(data, []byte("buffered peer bytes")), nil
}
func (connection *bufferedHTTPConnection) Write(data []byte) (int, error) {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	connection.writes++
	return len(data), nil
}
func (connection *bufferedHTTPConnection) Close() error {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	connection.closes++
	return connection.closeError
}
func (connection *bufferedHTTPConnection) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (connection *bufferedHTTPConnection) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (connection *bufferedHTTPConnection) SetDeadline(time.Time) error      { return nil }
func (connection *bufferedHTTPConnection) SetReadDeadline(time.Time) error  { return nil }
func (connection *bufferedHTTPConnection) SetWriteDeadline(time.Time) error { return nil }
func (connection *bufferedHTTPConnection) counts() (int, int, int) {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	return connection.reads, connection.writes, connection.closes
}

// full_only: false
func TestHTTPStartupReadRequiresWriteAndCloseExcludesBufferedBytes(t *testing.T) {
	for _, action := range []string{"write", "close"} {
		t.Run(action, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				inner := new(bufferedHTTPConnection)
				connection := &httpStartupConnection{Conn: inner, raw: inner, ready: make(chan struct{})}
				defer func() {
					if err := connection.Close(); err != nil {
						t.Error("startup connection cleanup failed", err)
					}
				}()
				type result struct {
					data string
					err  error
				}
				done := make(chan result, 1)
				go func() {
					var data [64]byte
					n, err := connection.Read(data[:])
					done <- result{string(data[:n]), err}
				}()
				synctest.Wait()
				if reads, _, _ := inner.counts(); reads != 0 {
					t.Fatal("read reached decrypted bytes before first write")
				}
				if action == "write" {
					if n, err := connection.Write([]byte("request")); n != 7 || err != nil {
						t.Fatal("first write failed", n, err)
					}
					got := <-done
					if got.err != nil || got.data != "buffered peer bytes" {
						t.Fatal("first write did not release exact response bytes", got)
					}
					return
				}
				if err := connection.Close(); err != nil {
					t.Fatal(err)
				}
				got := <-done
				if got.data != "" || !errors.Is(got.err, net.ErrClosed) {
					t.Fatal("close exposed pending plaintext", got)
				}
				if n, err := connection.Read(make([]byte, 64)); n != 0 || !errors.Is(err, net.ErrClosed) {
					t.Fatal("future read passed closed gate", n, err)
				}
				if n, err := connection.Write([]byte("request")); n != 0 || !errors.Is(err, net.ErrClosed) {
					t.Fatal("future write passed closed gate", n, err)
				}
				if reads, writes, closes := inner.counts(); reads != 0 || writes != 0 || closes != 1 {
					t.Fatal("closed gate touched decrypted data", reads, writes, closes)
				}
			})
		})
	}
}

// full_only: false
func TestHTTPStartupConcurrentWriteCloseAndReadSettle(t *testing.T) {
	for range 32 {
		inner := new(bufferedHTTPConnection)
		connection := &httpStartupConnection{Conn: inner, raw: inner, ready: make(chan struct{})}
		var joined sync.WaitGroup
		joined.Add(3)
		go func() { defer joined.Done(); _, _ = connection.Read(make([]byte, 64)) }()
		go func() { defer joined.Done(); _, _ = connection.Write([]byte("request")) }()
		go func() { defer joined.Done(); _ = connection.Close() }()
		joined.Wait()
		reads, writes, closes := inner.counts()
		if reads > 1 || writes > 1 || closes != 1 || reads > writes {
			t.Fatal("concurrent gate order or close count differs", reads, writes, closes)
		}
	}
}

// full_only: false
func TestHTTPTransportCloseCancelsDialAndClosesLateSocket(t *testing.T) {
	base, owner := newRemoteHTTPTransport()
	late := new(bufferedHTTPConnection)
	entered := make(chan struct{})
	base.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		return late, nil
	}
	finished := make(chan error, 1)
	go func() {
		connection, err := base.DialTLSContext(t.Context(), "tcp", "127.0.0.1:443")
		if connection != nil {
			err = errors.Join(err, errors.New("closed owner returned a late connection"), connection.Close())
		}
		finished <- err
	}()
	<-entered
	if err := owner.close(); err != nil {
		t.Fatal(err)
	}
	if err := <-finished; !errors.Is(err, net.ErrClosed) {
		t.Fatal("late socket did not refuse", err)
	}
	if reads, writes, closes := late.counts(); reads != 0 || writes != 0 || closes != 1 {
		t.Fatal("late socket entered handshake or remained open", reads, writes, closes)
	}
}

// full_only: false
func TestHTTPTransportHandshakeBudgetAndOwnerCancellation(t *testing.T) {
	for _, action := range []string{"deadline", "close"} {
		t.Run(action, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				base, owner := newRemoteHTTPTransport()
				defer func() {
					if err := owner.close(); err != nil {
						t.Error("TLS owner cleanup failed", err)
					}
				}()
				client, peer := net.Pipe()
				defer func() {
					if err := peer.Close(); err != nil {
						t.Error("TLS peer cleanup failed", err)
					}
				}()
				base.DialContext = func(context.Context, string, string) (net.Conn, error) { return client, nil }
				base.TLSClientConfig = &tls.Config{ServerName: "local.invalid", MinVersion: tls.VersionTLS12}
				peerDone := make(chan error, 1)
				started := make(chan struct{})
				go func() {
					var first [1]byte
					_, err := io.ReadFull(peer, first[:])
					close(started)
					if err == nil {
						_, err = io.Copy(io.Discard, peer)
					}
					peerDone <- err
				}()
				finished := make(chan error, 1)
				begin := time.Now()
				go func() {
					connection, err := base.DialTLSContext(t.Context(), "tcp", "local.invalid:443")
					if connection != nil {
						err = errors.Join(err, errors.New("stalled handshake returned connection"), connection.Close())
					}
					finished <- err
				}()
				<-started
				if action == "close" {
					if err := owner.close(); err != nil {
						t.Fatal(err)
					}
				}
				if err := <-finished; err == nil || action == "deadline" && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("stalled handshake result differs", err)
				}
				if elapsed := time.Since(begin); action == "deadline" && elapsed != exportTLSHandshakeTimeout || action == "close" && elapsed != 0 {
					t.Fatal("handshake budget changed", elapsed)
				}
				if err := <-peerDone; err != nil {
					t.Fatal("stalled peer did not join", err)
				}
			})
		})
	}
}

// full_only: false
func TestOwnedHTTPTransportVerifiesTLSAndPreservesSignalHeaders(t *testing.T) {
	t.Setenv("ENKV_OWNED_TLS_TEST_KEY", "synthetic-key")
	var receivedMu sync.Mutex
	var received []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(io.LimitReader(request.Body, maximumOTLPRequestBytes+1))
		if err != nil || !bytes.Equal(body, []byte("request")) || request.Header.Get("x-honeycomb-team") != "synthetic-key" || request.Header.Get("x-honeycomb-dataset") != "synthetic" || request.Header.Get("Content-Type") != "application/x-protobuf" || request.Header.Get("Accept-Encoding") != "identity" || request.Header.Get("x-ambient-leak") != "" {
			t.Error("owned TLS request changed admitted bytes or headers")
		}
		receivedMu.Lock()
		received = append(received, request.URL.Path)
		receivedMu.Unlock()
		w.Header().Set("Content-Type", "application/x-protobuf")
	}))
	defer server.Close()
	settings := Resolved{ActiveExporters: map[string]Exporter{"capture": {Type: "otlp_http", Endpoint: server.URL, APIKeyEnv: "ENKV_OWNED_TLS_TEST_KEY", Dataset: "synthetic"}}, LogExporters: []string{"capture"}, MetricExporters: []string{"capture"}, TraceExporters: []string{"capture"}}
	for _, condition := range []string{"certificate-refused", "hostname-refused", "accepted"} {
		t.Run(condition, func(t *testing.T) {
			transport := newRemoteTransport(settings, nil)
			defer func() {
				if err := transport.close(); err != nil {
					t.Error(err)
				}
			}()
			base := transport.base.(*http.Transport)
			if condition != "certificate-refused" {
				base.TLSClientConfig = &tls.Config{RootCAs: tlsStartupRoots(t, server.Certificate()), MinVersion: tls.VersionTLS12}
				if condition == "hostname-refused" {
					base.TLSClientConfig.ServerName = "wrong.invalid"
				}
			}
			for _, signal := range []string{"logs", "metrics", "traces"} {
				request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/v1/"+signal, io.NopCloser(bytes.NewReader([]byte("request"))))
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("x-ambient-leak", "private-sentinel")
				response, err := transport.RoundTrip(request)
				if condition != "accepted" {
					if !errors.Is(err, errRemoteDelivery) || response != nil {
						t.Fatal("TLS refusal escaped safe delivery error", err)
					}
					continue
				}
				if err != nil || response == nil || response.StatusCode != http.StatusOK || response.TLS == nil || response.TLS.NegotiatedProtocol != "http/1.1" {
					t.Fatal("verified HTTP/1 TLS delivery failed", err)
				}
				if err := response.Body.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	receivedMu.Lock()
	defer receivedMu.Unlock()
	if !reflect.DeepEqual(received, []string{"/v1/logs", "/v1/metrics", "/v1/traces"}) {
		t.Fatal("TLS refusal reached HTTP or successful signals changed", received)
	}
}

// full_only: false
func TestRuntimeCloseReportsOwnedSocketCleanupFailure(t *testing.T) {
	settings, err := Decode(nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := Start(settings, SetupOptions{Console: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	_, owner := newRemoteHTTPTransport()
	closeFailure := errors.New("synthetic socket close failed")
	inner := &bufferedHTTPConnection{closeError: closeFailure}
	connection := &httpStartupConnection{Conn: inner, raw: inner, ready: make(chan struct{}), owner: owner}
	owner.active[connection] = struct{}{}
	runtime.remote = &remoteTransport{connections: owner}
	if err := runtime.Close(t.Context()); !errors.Is(err, closeFailure) {
		t.Fatal("runtime discarded owned socket cleanup failure", err)
	}
	if err := runtime.Close(t.Context()); !errors.Is(err, closeFailure) {
		t.Fatal("repeated close lost cleanup failure", err)
	}
}

func tlsStartupRoots(t testing.TB, certificate *x509.Certificate) *x509.CertPool {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return roots
}

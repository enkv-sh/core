package observability

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const tlsStartupChildEnv = "ENKV_TEST_TLS_STARTUP_CHILD"
const tlsStartupKeyEnv = "ENKV_TEST_TLS_STARTUP_KEY"
const tlsStartupCredential = "SYNTHETIC_COLLECTOR_CREDENTIAL_ECHO"

// full_only: false
func TestTLSStartupDiagnosticSchedule(t *testing.T) {
	if mode := os.Getenv(tlsStartupChildEnv); mode != "" {
		runTLSStartupDiagnosticChild(t, mode)
		return
	}
	for _, mode := range []string{"unsafe-control", "owned-write", "owned-close"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTLSStartupDiagnosticSchedule$", "-test.count=1")
			command.WaitDelay = time.Second
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "OTEL_") && !strings.HasPrefix(entry, tlsStartupChildEnv+"=") && !strings.HasPrefix(entry, tlsStartupKeyEnv+"=") {
					command.Env = append(command.Env, entry)
				}
			}
			command.Env = append(command.Env, tlsStartupChildEnv+"="+mode, tlsStartupKeyEnv+"="+tlsStartupCredential)
			var stdout, stderr bytes.Buffer
			command.Stdout, command.Stderr = &stdout, &stderr
			if err := command.Run(); err != nil {
				t.Fatalf("TLS startup child did not complete: %v; stdout=%s stderr=%s", err, stdout.String(), stderr.String())
			}
			if !bytes.Contains(stdout.Bytes(), []byte("tls_startup_peer_joined first_delivery_accepted=true second_delivery_refused=true")) {
				t.Fatal("TLS startup check did not establish both delivery results and peer join")
			}
			markerLines := 0
			for _, line := range bytes.Split(stderr.Bytes(), []byte{'\n'}) {
				if bytes.Contains(line, []byte(tlsStartupCredential)) {
					markerLines++
					if !bytes.Contains(line, []byte("Unsolicited response received on idle HTTP channel")) {
						t.Fatal("synthetic credential escaped through a different diagnostic path")
					}
				}
			}
			want := 0
			if mode == "unsafe-control" {
				want = 1
			}
			if markerLines != want {
				t.Fatalf("controlled TLS startup standard-log lines=%d, want %d", markerLines, want)
			}
		})
	}
}

func runTLSStartupDiagnosticChild(t *testing.T, mode string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	certificate, roots := tlsStartupCertificate(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	owner := &tlsStartupPeerOwner{listener: listener}
	peerDone := make(chan error, 1)
	earlyWritten := make(chan struct{})
	go func() { peerDone <- serveTLSStartupPeer(ctx, owner, earlyWritten) }()
	defer func() {
		cancel()
		owner.close()
		select {
		case err := <-peerDone:
			if err != nil {
				t.Errorf("TLS peer failed: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("TLS peer did not join")
		}
	}()
	endpoint := "https://" + listener.Addr().String()
	settings := Resolved{
		ActiveExporters: map[string]Exporter{"capture": {Type: "otlp_http", Endpoint: endpoint, APIKeyEnv: tlsStartupKeyEnv}},
		LogExporters:    []string{"capture"},
	}
	var unsafeBase http.RoundTripper
	if mode == "unsafe-control" {
		unsafeBase = &http.Transport{DisableKeepAlives: true, DisableCompression: true,
			TLSHandshakeTimeout: exportTLSHandshakeTimeout, ResponseHeaderTimeout: exportResponseHeaderTimeout}
	}
	transport := newRemoteTransport(settings, unsafeBase)
	defer func() {
		if err := transport.close(); err != nil {
			t.Error("TLS startup transport cleanup failed", err)
		}
	}()
	base := transport.base.(*http.Transport)
	base.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	if !base.DisableKeepAlives {
		t.Fatal("production transport unexpectedly reuses idle connections")
	}
	request := func(requestContext context.Context) *http.Request {
		r, err := http.NewRequestWithContext(requestContext, http.MethodPost, endpoint+"/v1/logs", io.NopCloser(bytes.NewReader([]byte{0})))
		if err != nil {
			t.Fatal(err)
		}
		r.ContentLength = 1
		return r
	}
	response, err := transport.RoundTrip(request(ctx))
	if err != nil || response == nil || response.StatusCode != http.StatusOK {
		t.Fatal("initial local TLS delivery failed")
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	var observedPeerError error
	barrierEntered := false
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		barrierEntered = true
		if mode == "unsafe-control" {
			// The ungated control waits for the stock read loop to consume the
			// early bytes and close before expected-response registration.
			select {
			case observedPeerError = <-peerDone:
				peerDone <- observedPeerError
			case <-ctx.Done():
				observedPeerError = ctx.Err()
			}
			return
		}
		select {
		case <-earlyWritten:
		case <-ctx.Done():
			observedPeerError = ctx.Err()
			return
		}
		if mode == "owned-close" {
			if err := info.Conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				observedPeerError = err
			}
		} else if mode != "owned-write" {
			observedPeerError = errors.New("invalid TLS startup mode")
		}
	}}

	response, err = transport.RoundTrip(request(httptrace.WithClientTrace(ctx, trace)))
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if !barrierEntered || observedPeerError != nil || err == nil {
		t.Fatalf("controlled TLS startup result invalid: barrier=%t peer_failed=%t refused=%t", barrierEntered, observedPeerError != nil, err != nil)
	}
	fmt.Println("tls_startup_peer_joined first_delivery_accepted=true second_delivery_refused=true")
}

type tlsStartupPeerOwner struct {
	mu         sync.Mutex
	listener   net.Listener
	connection net.Conn
	closed     bool
}

func (owner *tlsStartupPeerOwner) accept() (net.Conn, error) {
	connection, err := owner.listener.Accept()
	if err != nil {
		return nil, err
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed {
		_ = connection.(*tls.Conn).NetConn().Close()
		return nil, net.ErrClosed
	}
	owner.connection = connection.(*tls.Conn).NetConn()
	return connection, nil
}

func (owner *tlsStartupPeerOwner) close() {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	owner.closed = true
	_ = owner.listener.Close()
	if owner.connection != nil {
		_ = owner.connection.Close()
	}
}

func serveTLSStartupPeer(ctx context.Context, owner *tlsStartupPeerOwner, earlyWritten chan<- struct{}) error {
	for connectionIndex := 0; connectionIndex < 2; connectionIndex++ {
		connection, err := owner.accept()
		if err != nil {
			return errors.New("local TLS accept failed")
		}
		deadline, _ := ctx.Deadline()
		if err := connection.SetDeadline(deadline); err != nil {
			_ = connection.Close()
			return errors.New("local TLS deadline failed")
		}
		tlsConnection := connection.(*tls.Conn)
		if err := tlsConnection.HandshakeContext(ctx); err != nil {
			_ = connection.Close()
			return errors.New("local TLS handshake failed")
		}
		if tlsConnection.ConnectionState().NegotiatedProtocol != "http/1.1" {
			_ = connection.Close()
			return errors.New("local TLS did not select HTTP/1")
		}
		if connectionIndex == 0 {
			request, err := http.ReadRequest(bufio.NewReader(tlsConnection))
			if err != nil {
				_ = connection.Close()
				return errors.New("initial local HTTP read failed")
			}
			_, bodyErr := io.Copy(io.Discard, request.Body)
			closeErr := request.Body.Close()
			if bodyErr != nil || closeErr != nil || request.Header.Get("x-honeycomb-team") != tlsStartupCredential {
				_ = connection.Close()
				return errors.New("initial local credential or body was not received")
			}
			if _, err := io.WriteString(tlsConnection, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Type: application/x-protobuf\r\nConnection: close\r\n\r\n"); err != nil {
				_ = connection.Close()
				return errors.New("initial local response failed")
			}
		} else {
			// This collector already received the credential on the first
			// TLS connection. Echo it before a request exists on the second.
			if _, err := io.WriteString(tlsConnection, tlsStartupCredential+"\r\n"); err != nil {
				_ = connection.Close()
				return errors.New("local TLS early peer write failed")
			}
			close(earlyWritten)
		}
		// The second client may start its request before rejecting the invalid
		// response. Drain only bounded fixture bytes until its connection closes.
		n, readErr := io.Copy(io.Discard, io.LimitReader(tlsConnection, maximumOTLPRequestBytes+1))
		if n > maximumOTLPRequestBytes || !errors.Is(readErr, io.EOF) && readErr != nil && !errors.Is(readErr, syscall.ECONNRESET) {
			_ = connection.Close()
			return errors.New("local TLS peer did not observe client closure")
		}
		if err := tlsConnection.NetConn().Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			return errors.New("local TLS socket close failed")
		}
	}
	return nil
}

func tlsStartupCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "local TLS collector"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey, Leaf: parsed}, roots
}

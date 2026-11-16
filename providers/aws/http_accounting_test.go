package awsprovider

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

const httpAccountingLimit = 128 << 10
const httpAccountingTimeout = 5 * time.Second

type httpAccountingExchange struct {
	request *http.Request
	raw     []byte
	body    []byte
	sent    int
	failure string
}

type httpAccountingServer struct {
	mu       sync.Mutex
	conn     net.Conn
	done     chan struct{}
	exchange httpAccountingExchange
	dials    atomic.Int32
}

// Observe actual HTTP plaintext on the server side of TLS. One request owns
// one connection; no HTTP reconstruction or network-byte estimate is involved.
func startHTTPAccountingServer(t *testing.T, host string, reply []byte) (*httpAccountingServer, *http.Transport) {
	t.Helper()
	if len(reply) >= httpAccountingLimit {
		t.Fatal("HTTP accounting response exceeds its bound")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	server := &httpAccountingServer{done: make(chan struct{})}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error("HTTP accounting listener close failed")
		}
		server.mu.Lock()
		if server.conn != nil {
			if err := server.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				t.Error("HTTP accounting connection close failed")
			}
		}
		server.mu.Unlock()
		server.join(t)
	})
	go func() {
		result := httpAccountingExchange{}
		defer func() { server.exchange = result; close(server.done) }()
		if listener.SetDeadline(time.Now().Add(httpAccountingTimeout)) != nil {
			result.failure = "accept-deadline"
			return
		}
		conn, err := listener.AcceptTCP()
		if err != nil {
			result.failure = "accept"
			return
		}
		server.mu.Lock()
		server.conn = conn
		server.mu.Unlock()
		defer func() {
			if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				result.failure = "connection-close"
			}
		}()
		if conn.SetDeadline(time.Now().Add(httpAccountingTimeout)) != nil {
			result.failure = "connection-deadline"
			return
		}
		secure := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
		var raw bytes.Buffer
		reader := bufio.NewReader(io.TeeReader(io.LimitReader(secure, httpAccountingLimit), &raw))
		request, err := http.ReadRequest(reader)
		if err != nil || request.ContentLength < 0 || request.ContentLength > 64<<10 || len(request.TransferEncoding) != 0 {
			result.failure = "request-header"
			return
		}
		body, readErr := io.ReadAll(io.LimitReader(request.Body, 64<<10))
		closeErr := request.Body.Close()
		if readErr != nil || closeErr != nil || int64(len(body)) != request.ContentLength || raw.Len() >= httpAccountingLimit || reader.Buffered() != 0 {
			result.failure = "request-body"
			return
		}
		result.request, result.raw, result.body = request, raw.Bytes(), body
		if len(reply) != 0 {
			result.sent, err = secure.Write(reply)
			if err != nil || result.sent != len(reply) {
				result.failure = "response-write"
			}
		}
	}()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, TLSHandshakeTimeout: httpAccountingTimeout, ResponseHeaderTimeout: httpAccountingTimeout, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		server.dials.Add(1)
		if address != net.JoinHostPort(host, "443") {
			return nil, errors.New("HTTP accounting host refused")
		}
		return (&net.Dialer{Timeout: httpAccountingTimeout}).DialContext(ctx, network, listener.Addr().String())
	}}
	return server, transport
}

func (s *httpAccountingServer) join(t *testing.T) httpAccountingExchange {
	t.Helper()
	select {
	case <-s.done:
		if s.exchange.failure != "" {
			t.Fatalf("HTTP accounting fixture failed at %s", s.exchange.failure)
		}
		return s.exchange
	case <-time.After(httpAccountingTimeout):
		t.Fatal("HTTP accounting server did not join")
		return httpAccountingExchange{}
	}
}

type httpAccountingResponse struct {
	raw      string
	body     int
	framing  int
	complete bool
}

func fixedHTTPAccountingResponse(status, contentType, body string, declared int) httpAccountingResponse {
	header := fmt.Sprintf("HTTP/1.1 %s\r\nContent-Length: %d\r\nContent-Type: %s\r\nETag: \"selected\"\r\nConnection: close\r\n\r\n", status, declared, contentType)
	return httpAccountingResponse{raw: header + body, body: len(body), complete: declared == len(body)}
}

func assertHTTPAccounting(t *testing.T, server *httpAccountingServer, exchange httpAccountingExchange, reply httpAccountingResponse, operation telemetry.Operation, name, result string, data metricdata.ResourceMetrics) {
	t.Helper()
	requestHeader := bytes.Index(exchange.raw, []byte("\r\n\r\n")) + 4
	responseHeader := strings.Index(reply.raw, "\r\n\r\n") + 4
	if reply.raw == "" {
		responseHeader = 0
	}
	if server.dials.Load() != 1 || requestHeader < 4 || !bytes.Equal(exchange.raw[requestHeader:], exchange.body) || len(exchange.raw) != requestHeader+len(exchange.body) || exchange.sent != responseHeader+reply.body+reply.framing || exchange.sent != len(reply.raw) {
		t.Fatal("HTTP plaintext header, body, framing or single-send partition differs")
	}
	if telemetrySum(data, telemetry.HTTPAttempts, operation, "", "") != 1 || telemetrySum(data, telemetry.HTTPRequestBodyBytes, operation, "", "complete") != int64(len(exchange.body)) || telemetrySum(data, telemetry.HTTPRequestBodyObservations, operation, "", "complete") != 1 {
		t.Fatal("request body telemetry differs from the complete received request")
	}
	responseStatus := "incomplete"
	if reply.complete {
		responseStatus = "complete"
	}
	if telemetrySum(data, telemetry.HTTPResponseBodyBytes, operation, "", responseStatus) != int64(reply.body) || telemetrySum(data, telemetry.HTTPResponseBodyObservations, operation, "", responseStatus) != 1 {
		t.Fatal("response body telemetry or completeness differs from this controlled reply")
	}
	assertSafeTelemetry(t, data)
	// These are fixture assertions, not fallback production metrics. Sent bytes
	// mean successful server Write counts, not proof of client receipt. Header
	// bytes include the start line and blank line; TLS/TCP/IP are excluded.
	evidence := struct {
		Provider             string `json:"provider"`
		Operation            string `json:"operation"`
		Case                 string `json:"case"`
		RequestHTTPBytes     int    `json:"request_http_bytes"`
		RequestHeaderBytes   int    `json:"request_header_bytes"`
		RequestBodyBytes     int    `json:"request_body_bytes"`
		RequestFramingBytes  int    `json:"request_framing_bytes"`
		ResponseHTTPBytes    int    `json:"response_http_bytes"`
		ResponseHeaderBytes  int    `json:"response_header_bytes"`
		ResponseBodyBytes    int    `json:"response_body_bytes"`
		ResponseFramingBytes int    `json:"response_framing_bytes"`
		ResponseComplete     bool   `json:"response_complete"`
		Result               string `json:"result"`
	}{"aws", string(operation), name, len(exchange.raw), requestHeader, len(exchange.body), 0, exchange.sent, responseHeader, reply.body, reply.framing, reply.complete, result}
	body, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("http accounting: %s", body)
}

// full_only: false
func TestStoreHTTPMessageAccounting(t *testing.T) {
	condition := "<Error><Code>PreconditionFailed</Code></Error>"
	for _, test := range []struct {
		name   string
		read   bool
		reply  httpAccountingResponse
		result string
	}{
		{"cas-content-length", false, fixedHTTPAccountingResponse("200 OK", "application/octet-stream", "", 0), "write_acknowledged"},
		{"read-content-length", true, fixedHTTPAccountingResponse("200 OK", "application/octet-stream", "body", 4), "read_ok"},
		{"read-chunked", true, httpAccountingResponse{raw: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nETag: \"selected\"\r\nConnection: close\r\n\r\n2\r\nbo\r\n2\r\ndy\r\n0\r\n\r\n", body: 4, framing: 15, complete: true}, "read_invalid"},
		{"conditional-error", false, fixedHTTPAccountingResponse("412 Precondition Failed", "application/xml", condition, len(condition)), "write_precondition"},
		{"truncated-reply", false, fixedHTTPAccountingResponse("200 OK", "application/octet-stream", "part", 8), "write_unknown"},
		{"accepted-lost-reply", false, httpAccountingResponse{}, "write_unknown"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "1")
			ctx, snapshot := collectTelemetry(t)
			server, transport := startHTTPAccountingServer(t, "s3.us-east-1.amazonaws.com", []byte(test.reply.raw))
			config := testStoreConfig()
			config.Transport, config.Timeout = transport, httpAccountingTimeout
			store, err := NewStore(config)
			if err != nil {
				t.Fatal(err)
			}
			operation, method := telemetry.OpStoreCompareAndSwap, http.MethodPut
			body := []byte("complete synthetic candidate")
			if test.read {
				operation, method, body = telemetry.OpStoreRead, http.MethodGet, nil
				got := store.Read(ctx, store.Descriptor().HeadKey, 32)
				want := contract.ReadResult{Status: contract.ReadOK, Body: []byte("body"), Token: contract.Token{Family: contract.AWS, Value: "\"selected\""}}
				if test.name == "read-chunked" {
					// The HTTP body is complete, but this Store requires Content-Length.
					want = contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}
				}
				if got.Status != want.Status || got.Reason != want.Reason || got.Token != want.Token || !bytes.Equal(got.Body, want.Body) {
					t.Fatal("Store read result differs from the admitted response contract")
				}
			} else {
				want := contract.WriteResult{Status: contract.WriteAcknowledged}
				switch test.result {
				case "write_precondition":
					want = contract.WriteResult{Status: contract.WritePrecondition, Reason: contract.ReasonCondition}
				case "write_unknown":
					want = contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
				}
				if got := store.CompareAndSwap(ctx, store.Descriptor().HeadKey, contract.Token{Family: contract.AWS, Value: `"old"`}, body); got != want {
					t.Fatal("Store write result differs from its physical response evidence")
				}
			}
			exchange := server.join(t)
			request := exchange.request
			if request.Method != method || request.Proto != "HTTP/1.1" || request.Host != "s3.us-east-1.amazonaws.com" || request.URL.Path != "/fixture-bucket/enkv/domain/HEAD" || request.Header.Get("X-Amz-Expected-Bucket-Owner") != config.ExpectedBucketOwner || !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") || !request.Close || !bytes.Equal(exchange.body, body) {
				t.Fatal("actual SDK request, signed headers or exact body differs")
			}
			if !test.read {
				digest := contract.Hash(body)
				if request.ContentLength != int64(len(body)) || request.Header.Get("If-Match") != `"old"` || request.Header.Get("X-Amz-Checksum-Sha256") != base64.StdEncoding.EncodeToString(digest[:]) || request.Header.Get("Content-Type") != "application/octet-stream" {
					t.Fatal("actual conditional request bindings differ")
				}
			}
			assertHTTPAccounting(t, server, exchange, test.reply, operation, test.name, test.result, snapshot())
		})
	}
}

// full_only: false
func TestTrustHTTPMessageAccounting(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "1")
	ctx, snapshot := collectTelemetry(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	id := contract.Hash([]byte("synthetic accounting subject"))
	request, err := contract.NewBindingRequest(contract.BindingSubject{Domain: id, Coordinate: id, Store: id, Trust: id, PublicKey: id, Interpretation: id, ControlIncarnationID: id, Epoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	digest := request.Digest()
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sc := testStoreConfig()
	config := TrustConfig{Region: sc.Region, KeyARN: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012", PublicKeyDER: public, CredentialRoute: sc.CredentialRoute, Credentials: sc.Credentials, Timeout: httpAccountingTimeout}
	body, err := json.Marshal(map[string]string{"KeyId": config.KeyARN, "SigningAlgorithm": "ECDSA_SHA_256", "Signature": base64.StdEncoding.EncodeToString(signature)})
	if err != nil {
		t.Fatal(err)
	}
	reply := fixedHTTPAccountingResponse("200 OK", "application/x-amz-json-1.1", string(body), len(body))
	server, transport := startHTTPAccountingServer(t, "kms.us-east-1.amazonaws.com", []byte(reply.raw))
	config.Transport = transport
	trust, err := NewTrust(config)
	if err != nil {
		t.Fatal(err)
	}
	got := trust.Sign(ctx, request)
	if got.Reason != contract.ReasonNone || !bytes.Equal(got.Signature, signature) || !ecdsa.VerifyASN1(&key.PublicKey, digest[:], got.Signature) {
		t.Fatal("Trust did not verify the actual returned signature")
	}
	exchange := server.join(t)
	var encoded struct{ KeyId, Message, MessageType, SigningAlgorithm string }
	if json.Unmarshal(exchange.body, &encoded) != nil || encoded.KeyId != config.KeyARN || encoded.Message != base64.StdEncoding.EncodeToString(digest[:]) || encoded.MessageType != "DIGEST" || encoded.SigningAlgorithm != "ECDSA_SHA_256" {
		t.Fatal("actual SDK Trust body differs from the closed signing request")
	}
	httpRequest := exchange.request
	if httpRequest.Method != http.MethodPost || httpRequest.Proto != "HTTP/1.1" || httpRequest.Host != "kms.us-east-1.amazonaws.com" || httpRequest.URL.Path != "/" || httpRequest.Header.Get("X-Amz-Target") != "TrentService.Sign" || httpRequest.Header.Get("Content-Type") != "application/x-amz-json-1.1" || !strings.HasPrefix(httpRequest.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") || !httpRequest.Close {
		t.Fatal("actual signed Trust HTTP request differs")
	}
	data := snapshot()
	if telemetrySum(data, telemetry.OperationInputBytes, telemetry.OpTrustSign, "sign_ok", "") != 32 || telemetrySum(data, telemetry.OperationOutputBytes, telemetry.OpTrustSign, "sign_ok", "") != int64(len(signature)) {
		t.Fatal("logical digest/signature sizes differ from the HTTP body evidence")
	}
	assertHTTPAccounting(t, server, exchange, reply, telemetry.OpTrustSign, "sign-content-length", "sign_ok", data)
}

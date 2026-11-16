package gcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math/big"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

const httpAccountingCaptureLimit = 128 << 10
const httpAccountingBodyLimit = 64 << 10

// Count plaintext returned by TLS, before HTTP parsing. TLS records and lower
// network layers are outside this boundary; no request is reconstructed.
type httpAccountingConn struct {
	*tls.Conn
	request, response []byte
}

func (c *httpAccountingConn) Read(p []byte) (int, error) {
	remaining := httpAccountingCaptureLimit - len(c.request)
	if remaining == 0 {
		return 0, errors.New("HTTP request capture limit reached")
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	n, err := c.Conn.Read(p)
	c.request = append(c.request, p[:n]...)
	return n, err
}

func (c *httpAccountingConn) Write(p []byte) (int, error) {
	if len(p) > httpAccountingCaptureLimit-len(c.response) {
		return 0, errors.New("HTTP response capture limit reached")
	}
	n, err := c.Conn.Write(p)
	c.response = append(c.response, p[:n]...)
	return n, err
}

type httpAccountingExchange struct {
	request                 *http.Request
	body, received, emitted []byte
	err                     error
}

func httpAccountingServer(t *testing.T, reply []byte) (func(*http.Transport), func() httpAccountingExchange) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"storage.us-central1.rep.googleapis.com", "us-central1-cloudkms.googleapis.com", "oauth2.googleapis.com"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	if err := listener.SetDeadline(deadline); err != nil {
		closeErr := listener.Close()
		t.Fatal(errors.Join(err, closeErr))
	}
	var exchange httpAccountingExchange
	var dials atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		raw, err := listener.Accept()
		if err != nil {
			exchange.err = err
			return
		}
		defer func() { exchange.err = errors.Join(exchange.err, raw.Close()) }()
		if err := raw.SetDeadline(deadline); err != nil {
			exchange.err = err
			return
		}
		connection := &httpAccountingConn{Conn: tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})}
		defer func() { exchange.received, exchange.emitted = connection.request, connection.response }()
		reader := bufio.NewReader(connection)
		exchange.request, err = http.ReadRequest(reader)
		if err != nil {
			exchange.err = err
			return
		}
		exchange.body, err = io.ReadAll(io.LimitReader(exchange.request.Body, httpAccountingBodyLimit+1))
		closeErr := exchange.request.Body.Close()
		if err != nil || closeErr != nil || len(exchange.body) > httpAccountingBodyLimit || reader.Buffered() != 0 {
			exchange.err = errors.Join(err, closeErr, errors.New("HTTP request body or request count differs"))
			return
		}
		if len(reply) != 0 {
			n, err := connection.Write(reply)
			if err == nil && n != len(reply) {
				err = io.ErrShortWrite
			}
			exchange.err = err
		}
	}()
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
		// Accept and the accepted connection share the five-second deadline.
		// Join the server before its captured bytes leave this test's lifetime.
		<-done
	})
	route := func(transport *http.Transport) {
		// Only same-package tests can alter the constructor-owned route. Keep
		// certificate verification active against this local certificate.
		transport.TLSClientConfig.RootCAs = roots
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
		}
		t.Cleanup(transport.CloseIdleConnections)
	}
	return route, func() httpAccountingExchange {
		<-done
		if dials.Load() != 1 {
			t.Fatalf("physical HTTP connection attempts: %d, want one", dials.Load())
		}
		if exchange.err != nil {
			t.Fatalf("controlled HTTP server: %v", exchange.err)
		}
		return exchange
	}
}

func httpAccountingReply(status int, body string, extraLength int) []byte {
	return []byte(fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), len(body)+extraLength, body))
}

func assertHTTPAccounting(t *testing.T, exchange httpAccountingExchange, data metricdata.ResourceMetrics, operation telemetry.Operation, name, result string, wantBody []byte, complete bool) {
	t.Helper()
	requestHeaders := bytes.Index(exchange.received, []byte("\r\n\r\n")) + 4
	if requestHeaders < 4 || exchange.request.Proto != "HTTP/1.1" || !exchange.request.Close || exchange.request.ContentLength != int64(len(exchange.body)) || len(exchange.received) != requestHeaders+len(exchange.body) {
		t.Fatal("actual HTTP request does not partition into headers and fixed-length body")
	}
	responseHeaders, framing := 0, 0
	var body []byte
	if len(exchange.emitted) != 0 {
		responseHeaders = bytes.Index(exchange.emitted, []byte("\r\n\r\n")) + 4
		response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(exchange.emitted)), exchange.request)
		if err != nil || responseHeaders < 4 {
			t.Fatal("controlled response headers did not reach the TLS plaintext boundary")
		}
		body, err = io.ReadAll(io.LimitReader(response.Body, httpAccountingBodyLimit+1))
		closeErr := response.Body.Close()
		if closeErr != nil || len(body) > httpAccountingBodyLimit || complete && err != nil || !complete && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("controlled response completeness: %v, close: %v", err, closeErr)
		}
		framing = len(exchange.emitted) - responseHeaders - len(body)
		if framing < 0 || len(response.TransferEncoding) == 0 && framing != 0 || len(response.TransferEncoding) != 0 && framing == 0 {
			t.Fatal("HTTP response framing was not counted separately")
		}
	} else if complete {
		t.Fatal("absent reply marked complete")
	}
	if !bytes.Equal(body, wantBody) {
		t.Fatal("controlled response body differs")
	}
	responseStatus := "incomplete"
	if complete {
		responseStatus = "complete"
	}
	if telemetrySum(data, telemetry.HTTPAttempts, operation, "", "") != 1 || telemetrySum(data, telemetry.HTTPRequestBodyBytes, operation, "", "complete") != int64(len(exchange.body)) || telemetrySum(data, telemetry.HTTPRequestBodyObservations, operation, "", "complete") != 1 || telemetrySum(data, telemetry.HTTPResponseBodyBytes, operation, "", responseStatus) != int64(len(body)) || telemetrySum(data, telemetry.HTTPResponseBodyObservations, operation, "", responseStatus) != 1 {
		t.Fatal("body telemetry differs from this controlled exchange")
	}
	for _, other := range []telemetry.Operation{telemetry.OpStoreRead, telemetry.OpStoreCompareAndSwap, telemetry.OpTrustSign, telemetry.OpAuthentication} {
		if other != operation && telemetrySum(data, telemetry.HTTPAttempts, other, "", "") != 0 {
			t.Fatal("Store, Trust and authentication HTTP accounting overlap")
		}
	}
	// Emitted response completeness is a server fact, not proof of receipt by
	// a client. These full-HTTP counts never replace body telemetry or cloud data.
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
	}{"gcp", string(operation), name, len(exchange.received), requestHeaders, len(exchange.body), 0, len(exchange.emitted), responseHeaders, len(body), framing, complete, result}
	raw, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("http accounting: %s", raw)
}

func assertHTTPAccountingMultipart(t *testing.T, exchange httpAccountingExchange, key string, value []byte, checksum string) {
	t.Helper()
	r := exchange.request
	if r.Method != "POST" || r.Host != "storage.us-central1.rep.googleapis.com" || r.URL.Path != "/upload/storage/v1/b/fixture-bucket/o" || r.URL.Query().Get("ifGenerationMatch") != "42" || r.URL.Query().Get("uploadType") != "multipart" || r.Header.Get("Authorization") != "Bearer fixture-token" {
		t.Fatal("physical conditional request differs")
	}
	kind, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || kind != "multipart/related" {
		t.Fatal("physical multipart content type differs")
	}
	reader := multipart.NewReader(bytes.NewReader(exchange.body), parameters["boundary"])
	metadata, err := reader.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if json.NewDecoder(metadata).Decode(&fields) != nil || fields["name"] != key || fields["crc32c"] != checksum || fields["cacheControl"] != "private, no-store, no-transform" || fields["contentType"] != "application/octet-stream" || fields["contentEncoding"] != nil {
		t.Fatal("physical object metadata differs")
	}
	media, err := reader.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(media)
	if err != nil || !bytes.Equal(body, value) {
		t.Fatal("physical object bytes differ")
	}
	if _, err := reader.NextPart(); err != io.EOF {
		t.Fatal("physical multipart has an extra part")
	}
}

// full_only: false
func TestStoreControlledHTTPAccounting(t *testing.T) {
	// CRC32C("candidate") is 0x722b2c3c, encoded as four big-endian bytes in base64.
	const candidateCRC32C = "cissPA=="
	for _, name := range []string{"content-length-cas", "chunked-read", "conditional-error", "truncated-reply", "accepted-lost-reply"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("ENKV_TELEMETRY", "1")
			ctx, snapshot := collectTelemetry(t)
			value := []byte("candidate")
			body := fmt.Sprintf(`{"bucket":"fixture-bucket","name":"fixture/HEAD","generation":"43","size":"9","crc32c":%q}`, candidateCRC32C)
			reply, complete := httpAccountingReply(200, body, 0), true
			want := contract.WriteResult{Status: contract.WriteAcknowledged}
			operation, result := telemetry.OpStoreCompareAndSwap, "write_acknowledged"
			switch name {
			case "chunked-read":
				body = "body"
				reply = []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Goog-Generation: 43\r\nConnection: close\r\n\r\n3\r\nbod\r\n1\r\ny\r\n0\r\n\r\n")
				operation, result = telemetry.OpStoreRead, "read_ok"
			case "conditional-error":
				body = `{"error":{"code":412,"errors":[{"reason":"conditionNotMet"}]}}`
				reply = httpAccountingReply(412, body, 0)
				want, result = contract.WriteResult{Status: contract.WritePrecondition, Reason: contract.ReasonCondition}, "write_precondition"
			case "truncated-reply":
				body = body[:len(body)/2]
				reply, complete = httpAccountingReply(200, body, 7), false
				want, result = contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}, "write_unknown"
			case "accepted-lost-reply":
				body, reply, complete = "", nil, false
				want, result = contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}, "write_unknown"
			}
			route, finish := httpAccountingServer(t, reply)
			creds := &credentials{}
			client, err := NewClient(&http.Transport{}, creds)
			if err != nil {
				t.Fatal(err)
			}
			route(client.http.Transport.(*singleSend).base.(*http.Transport))
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			store, err := NewStore(ctx, config(client))
			if err != nil {
				t.Fatal(err)
			}
			if name == "chunked-read" {
				got := store.Read(ctx, store.Descriptor().HeadKey, 64)
				if got.Status != contract.ReadOK || got.Reason != contract.ReasonNone || string(got.Body) != body || got.Token != (contract.Token{Family: contract.GCP, Value: "43"}) {
					t.Fatal("chunked read lost complete body or generation")
				}
			} else if got := store.CompareAndSwap(ctx, store.Descriptor().HeadKey, contract.Token{Family: contract.GCP, Value: "42"}, value); got != want {
				t.Fatalf("conditional request result: %+v, want %+v", got, want)
			}
			exchange := finish()
			if creds.calls != 1 {
				t.Fatal("credential or service request repeated")
			}
			if name == "chunked-read" {
				if exchange.request.Method != "GET" || exchange.request.Host != "storage.us-central1.rep.googleapis.com" || exchange.request.URL.Path != "/download/storage/v1/b/fixture-bucket/o/fixture/HEAD" || exchange.request.URL.Query().Get("alt") != "media" || exchange.request.Header.Get("Authorization") != "Bearer fixture-token" || len(exchange.body) != 0 {
					t.Fatal("physical media request differs")
				}
			} else {
				assertHTTPAccountingMultipart(t, exchange, store.Descriptor().HeadKey, value, candidateCRC32C)
			}
			assertHTTPAccounting(t, exchange, snapshot(), operation, name, result, []byte(body), complete)
		})
	}
}

// full_only: false
func TestTrustControlledHTTPAccounting(t *testing.T) {
	checksumTable := crc32.MakeTable(crc32.Castagnoli)
	if got := crc32.Checksum([]byte("123456789"), checksumTable); got != 0xe3069283 {
		t.Fatalf("CRC32C test calculation: %08x, want e3069283", got)
	}
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
	request := signRequest(t)
	digest := request.Digest()
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	configuration := trustConfig(nil, public)
	body := fmt.Sprintf(`{"name":%q,"verifiedDigestCrc32c":true,"signature":%q,"signatureCrc32c":%q}`, configuration.KeyVersion, base64.StdEncoding.EncodeToString(signature), strconv.FormatUint(uint64(crc32.Checksum(signature, checksumTable)), 10))
	route, finish := httpAccountingServer(t, httpAccountingReply(200, body, 0))
	client, err := NewClient(&http.Transport{}, &credentials{})
	if err != nil {
		t.Fatal(err)
	}
	route(client.http.Transport.(*singleSend).base.(*http.Transport))
	configuration.Client = client
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	trust, err := NewTrust(ctx, configuration)
	if err != nil {
		t.Fatal(err)
	}
	got := trust.Sign(ctx, request)
	if got.Reason != contract.ReasonNone || !bytes.Equal(got.Signature, signature) || !ecdsa.VerifyASN1(&key.PublicKey, digest[:], got.Signature) {
		t.Fatal("physical KMS reply failed local proof verification")
	}
	exchange := finish()
	var fields struct {
		Digest struct {
			SHA256 string `json:"sha256"`
		} `json:"digest"`
		CRC string `json:"digestCrc32c"`
	}
	if exchange.request.Method != "POST" || exchange.request.Host != "us-central1-cloudkms.googleapis.com" || exchange.request.URL.Path != "/v1/"+configuration.KeyVersion+":asymmetricSign" || exchange.request.Header.Get("Authorization") != "Bearer fixture-token" || json.Unmarshal(exchange.body, &fields) != nil || fields.Digest.SHA256 != base64.StdEncoding.EncodeToString(digest[:]) || fields.CRC != strconv.FormatUint(uint64(crc32.Checksum(digest[:], checksumTable)), 10) {
		t.Fatal("physical KMS request differs from admitted digest")
	}
	assertHTTPAccounting(t, exchange, snapshot(), telemetry.OpTrustSign, "verified-signature", "sign_ok", []byte(body), true)
}

// full_only: false
func TestAuthenticationControlledHTTPAccounting(t *testing.T) {
	t.Setenv("ENKV_TELEMETRY", "1")
	ctx, snapshot := collectTelemetry(t)
	fields, key := serviceAccountJSON(t)
	body := `{"access_token":"synthetic-accounting-token","token_type":"Bearer","expires_in":3600}`
	route, finish := httpAccountingServer(t, httpAccountingReply(200, body, 0))
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DisableKeepAlives: true, DisableCompression: true, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	route(transport)
	source, err := LoadServiceAccountFileForTest(ctx, serviceAccountPath(t, fields), transport)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if token, err := source.Token(ctx); err != nil || token != "synthetic-accounting-token" {
		t.Fatal("physical service-account authentication failed")
	}
	exchange := finish()
	form, err := url.ParseQuery(string(exchange.body))
	if err != nil || exchange.request.Method != "POST" || exchange.request.Host != "oauth2.googleapis.com" || exchange.request.URL.Path != "/token" || form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		t.Fatal("physical authentication request differs")
	}
	parts := strings.Split(form.Get("assertion"), ".")
	if len(parts) != 3 {
		t.Fatal("authentication assertion missing")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err != nil || rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature) != nil {
		t.Fatal("physical assertion does not verify under the supplied synthetic key")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	if err != nil || json.Unmarshal(payload, &claims) != nil || claims["iss"] != fields["client_email"] || claims["aud"] != tokenURL || claims["scope"] != "https://www.googleapis.com/auth/cloud-platform" || claims["sub"] != nil {
		t.Fatal("physical authentication claims differ")
	}
	assertHTTPAccounting(t, exchange, snapshot(), telemetry.OpAuthentication, "service-account-token", "token_ok", []byte(body), true)
}

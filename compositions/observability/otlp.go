package observability

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	collectlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collecttrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"
)

const (
	exportRequestTimeout                = 2 * time.Second
	exportDialTimeout                   = 2 * time.Second
	exportTLSHandshakeTimeout           = 2 * time.Second
	exportResponseHeaderTimeout         = 2 * time.Second
	exportKeepAliveInterval             = 30 * time.Second
	exportIdleConnectionTimeout         = 30 * time.Second
	maximumExportConnectionsPerHost     = 4
	maximumExportIdleConnectionsPerHost = 2
	maximumAPIKeyHeaderLength           = 512
	maximumDatasetHeaderLength          = 256
)

const maximumRemoteResponseBytes = 16 << 10

var errRemoteDelivery = errors.New("telemetry HTTP delivery failed")

// remoteTransport owns the only network boundary for an explicitly selected
// HTTP destination. It excludes SDK ambient headers and remote response text.
type remoteTransport struct {
	base        http.RoundTripper
	connections *httpTLSOwner
	host        string
	credential  string
	envName     string
	dataset     string
	allowed     map[string]bool
	once        sync.Once
}

func newRemoteTransport(settings Resolved, base http.RoundTripper) *remoteTransport {
	var exporter Exporter
	for _, active := range settings.ActiveExporters {
		if active.Type == "otlp_http" {
			exporter = active
			break
		}
	}
	if exporter.Type == "" {
		return nil
	}
	var connections *httpTLSOwner
	if base == nil {
		base, connections = newRemoteHTTPTransport()
	}
	parsed, _ := url.Parse(exporter.Endpoint) // Resolved.Validate checked this URL.
	allowed := map[string]bool{}
	if len(settings.LogExporters) != 0 {
		for _, name := range settings.LogExporters {
			if settings.ActiveExporters[name].Type == "otlp_http" {
				allowed["/v1/logs"] = true
			}
		}
	}
	for _, name := range settings.MetricExporters {
		if settings.ActiveExporters[name].Type == "otlp_http" {
			allowed["/v1/metrics"] = true
		}
	}
	for _, name := range settings.TraceExporters {
		if settings.ActiveExporters[name].Type == "otlp_http" {
			allowed["/v1/traces"] = true
		}
	}
	return &remoteTransport{base: base, connections: connections, host: parsed.Host, envName: exporter.APIKeyEnv, dataset: exporter.Dataset, allowed: allowed}
}

func (transport *remoteTransport) ready() bool {
	if transport == nil {
		return false
	}
	transport.once.Do(func() {
		value := os.Getenv(transport.envName)
		if validRemoteHeaderValue(value, maximumAPIKeyHeaderLength) && (transport.dataset == "" || validRemoteHeaderValue(transport.dataset, maximumDatasetHeaderLength)) {
			transport.credential = value
		}
	})
	return transport.credential != ""
}

func validRemoteHeaderValue(value string, limit int) bool {
	if value == "" || len(value) > limit || strings.TrimSpace(value) != value {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < ' ' || value[i] > '~' {
			return false
		}
	}
	return true
}

func (transport *remoteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil || request.Body == nil {
		return nil, errRemoteDelivery
	}
	defer func() { _ = request.Body.Close() }()
	if !transport.ready() || request.Method != http.MethodPost ||
		request.URL.Scheme != "https" || request.URL.Host != transport.host || !transport.allowed[request.URL.Path] || request.URL.RawQuery != "" || request.URL.Fragment != "" || request.URL.ForceQuery || request.URL.RawPath != "" || request.URL.User != nil {
		return nil, errRemoteDelivery
	}
	if request.Header.Get("Content-Encoding") != "" {
		return nil, errRemoteDelivery
	}
	wire, err := io.ReadAll(io.LimitReader(request.Body, maximumOTLPRequestBytes+1))
	closeErr := request.Body.Close()
	if err != nil || closeErr != nil || len(wire) > maximumOTLPRequestBytes {
		return nil, errRemoteDelivery
	}
	outbound := request.Clone(request.Context())
	outbound.Body = io.NopCloser(bytes.NewReader(wire))
	outbound.ContentLength = int64(len(wire))
	outbound.Header = make(http.Header)
	outbound.Header.Set("Content-Type", "application/x-protobuf")
	outbound.Header.Set("Accept-Encoding", "identity")
	outbound.Header.Set("x-honeycomb-team", transport.credential)
	if transport.dataset != "" {
		outbound.Header.Set("x-honeycomb-dataset", transport.dataset)
	}
	response, err := transport.base.RoundTrip(outbound)
	if err != nil || response == nil || response.Body == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, errRemoteDelivery
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, maximumRemoteResponseBytes+1))
	closeErr = response.Body.Close()
	if readErr != nil || closeErr != nil || len(data) > maximumRemoteResponseBytes {
		return nil, errRemoteDelivery
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 && !acceptedOTLPResponse(request.URL.Path, data) {
		return nil, errRemoteDelivery
	}
	// The SDK needs the status code, but no server-provided message. Successful
	// responses have already been checked for partial rejection.
	response.Body = io.NopCloser(bytes.NewReader(nil))
	response.ContentLength = 0
	response.Header = make(http.Header)
	response.Header.Set("Content-Type", "application/x-protobuf")
	return response, nil
}

func acceptedOTLPResponse(path string, data []byte) bool {
	if len(data) == 0 {
		return true
	}
	switch path {
	case "/v1/logs":
		response := new(collectlogs.ExportLogsServiceResponse)
		return proto.Unmarshal(data, response) == nil && (response.PartialSuccess == nil || response.PartialSuccess.RejectedLogRecords == 0 && response.PartialSuccess.ErrorMessage == "")
	case "/v1/metrics":
		response := new(collectmetrics.ExportMetricsServiceResponse)
		return proto.Unmarshal(data, response) == nil && (response.PartialSuccess == nil || response.PartialSuccess.RejectedDataPoints == 0 && response.PartialSuccess.ErrorMessage == "")
	case "/v1/traces":
		response := new(collecttrace.ExportTraceServiceResponse)
		return proto.Unmarshal(data, response) == nil && (response.PartialSuccess == nil || response.PartialSuccess.RejectedSpans == 0 && response.PartialSuccess.ErrorMessage == "")
	}
	return false
}

func (transport *remoteTransport) close() error {
	if transport == nil {
		return nil
	}
	var err error
	if transport.connections != nil {
		err = transport.connections.close()
	}
	if closer, ok := transport.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
	return err
}

func remoteEndpoint(exporter Exporter, signal string) string {
	return strings.TrimSuffix(exporter.Endpoint, "/") + "/v1/" + signal
}

func (transport *remoteTransport) client() *http.Client {
	return &http.Client{Transport: transport, Timeout: exportRequestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

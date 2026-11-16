package observability

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	collectlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collecttrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const (
	fileQuotaBytes          = 4 << 20
	maximumOTLPRequestBytes = 256 << 10
)

var errFileDelivery = errors.New("telemetry file delivery failed")

type fileTransport struct {
	base, directory, signal string
	mu                      sync.Mutex
	file                    *os.File
	bytes                   int64
	failed                  bool
}

func newFileTransport(base, directory, signal string) *fileTransport {
	return &fileTransport{base: base, directory: directory, signal: signal}
}

func (sink *fileTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.Body == nil {
		return nil, errFileDelivery
	}
	if request.Method != http.MethodPost || request.Header.Get("Content-Encoding") != "" {
		if request.Body.Close() != nil {
			return nil, errFileDelivery
		}
		return nil, errFileDelivery
	}
	encoded, err := io.ReadAll(io.LimitReader(request.Body, maximumOTLPRequestBytes+1))
	closeErr := request.Body.Close()
	if err != nil || closeErr != nil || len(encoded) > maximumOTLPRequestBytes {
		return nil, errFileDelivery
	}
	line, err := encodeOTLPJSON(sink.signal, encoded)
	if err != nil {
		return nil, errFileDelivery
	}
	if err := sink.writeLine(line); err != nil {
		return nil, errFileDelivery
	}
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(nil)), Header: http.Header{"Content-Type": []string{"application/x-protobuf"}}, Request: request}, nil
}

func encodeOTLPJSON(signal string, wire []byte) ([]byte, error) {
	var message proto.Message
	switch signal {
	case "logs":
		message = new(collectlogs.ExportLogsServiceRequest)
	case "metrics":
		message = new(collectmetrics.ExportMetricsServiceRequest)
	case "traces":
		message = new(collecttrace.ExportTraceServiceRequest)
	default:
		return nil, errFileDelivery
	}
	if proto.Unmarshal(wire, message) != nil {
		return nil, errFileDelivery
	}
	encoded, err := (protojson.MarshalOptions{UseEnumNumbers: true}).Marshal(message)
	if err != nil {
		return nil, errFileDelivery
	}
	var value any
	if json.Unmarshal(encoded, &value) != nil || convertOTLPIDs(value, true) != nil {
		return nil, errFileDelivery
	}
	encoded, err = json.Marshal(value)
	if err != nil || len(encoded) > maximumOTLPRequestBytes {
		return nil, errFileDelivery
	}
	return encoded, nil
}

func convertOTLPIDs(value any, toHex bool) error {
	switch item := value.(type) {
	case []any:
		for _, element := range item {
			if err := convertOTLPIDs(element, toHex); err != nil {
				return err
			}
		}
	case map[string]any:
		for key, element := range item {
			if key == "traceId" || key == "spanId" || key == "parentSpanId" {
				text, ok := element.(string)
				if !ok {
					return errFileDelivery
				}
				if text == "" {
					continue
				}
				var decoded []byte
				var err error
				if toHex {
					decoded, err = base64.StdEncoding.DecodeString(text)
				} else {
					decoded, err = hex.DecodeString(text)
				}
				want := 8
				if key == "traceId" {
					want = 16
				}
				if err != nil || len(decoded) != want {
					return errFileDelivery
				}
				if toHex {
					item[key] = hex.EncodeToString(decoded)
				} else {
					item[key] = base64.StdEncoding.EncodeToString(decoded)
				}
				continue
			}
			if err := convertOTLPIDs(element, toHex); err != nil {
				return err
			}
		}
	}
	return nil
}

func (sink *fileTransport) writeLine(line []byte) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.failed || int64(len(line))+1 > fileQuotaBytes-sink.bytes {
		sink.failed = true
		return errFileDelivery
	}
	if sink.file == nil {
		if err := sink.open(); err != nil {
			sink.failed = true
			return errFileDelivery
		}
	}
	position := sink.bytes
	line = append(line, '\n')
	n, err := sink.file.Write(line)
	if err != nil || n != len(line) {
		_ = sink.file.Truncate(position)
		_, _ = sink.file.Seek(position, io.SeekStart)
		sink.failed = true
		return errFileDelivery
	}
	sink.bytes += int64(n)
	return nil
}

func (sink *fileTransport) open() (result error) {
	if sink.base == "" || !validDirectory(sink.directory) {
		return errFileDelivery
	}
	switch sink.signal {
	case "logs", "metrics", "traces":
	default:
		return errFileDelivery
	}
	root, err := os.OpenRoot(sink.base)
	if err != nil {
		return errFileDelivery
	}
	var file *os.File
	name := filepath.Join(sink.directory, sink.signal+".jsonl")
	defer func() {
		if root.Close() != nil {
			result = errFileDelivery
		}
		if result != nil {
			if file != nil {
				closeErr := file.Close()
				removeErr := os.Remove(filepath.Join(sink.base, name))
				if closeErr != nil || removeErr != nil {
					result = errFileDelivery
				}
			}
			return
		}
		sink.file = file
	}()
	current := ""
	for _, segment := range strings.Split(sink.directory, "/") {
		current = filepath.Join(current, segment)
		if err := root.Mkdir(current, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return errFileDelivery
		}
		info, err := root.Lstat(current)
		if err != nil || !info.IsDir() {
			return errFileDelivery
		}
	}
	file, err = root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return errFileDelivery
	}
	return nil
}

func (sink *fileTransport) Close() error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.file == nil {
		return nil
	}
	err := errors.Join(sink.file.Sync(), sink.file.Close())
	sink.file = nil
	if err != nil {
		sink.failed = true
		return errFileDelivery
	}
	return nil
}

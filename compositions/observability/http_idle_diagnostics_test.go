package observability

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"enkv.sh/telemetry"
)

const idleDiagnosticChildEnv = "ENKV_TEST_HTTP_IDLE_CHILD"
const idleDiagnosticMarker = "SYNTHETIC_UNREVIEWED_COLLECTOR_BYTES"

// full_only: false
func TestOwnedHTTPTransportExcludesUnsolicitedIdleDiagnostics(t *testing.T) {
	if mode := os.Getenv(idleDiagnosticChildEnv); mode != "" {
		runIdleDiagnosticChild(t, mode)
		return
	}
	for _, mode := range []string{"unsafe-control", "owned"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOwnedHTTPTransportExcludesUnsolicitedIdleDiagnostics$", "-test.count=1")
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "OTEL_") && !strings.HasPrefix(entry, idleDiagnosticChildEnv+"=") && !strings.HasPrefix(entry, "ENKV_IDLE_TEST_KEY=") {
					command.Env = append(command.Env, entry)
				}
			}
			command.Env = append(command.Env, idleDiagnosticChildEnv+"="+mode, "ENKV_IDLE_TEST_KEY=synthetic-key")
			var stdout, stderr bytes.Buffer
			command.Stdout = &stdout
			command.Stderr = &stderr
			if err := command.Run(); err != nil {
				t.Fatalf("idle peer child did not join: %v\n%s", err, stderr.String())
			}
			if !strings.Contains(stdout.String(), "idle_peer_joined") {
				t.Fatal("unsolicited peer was not joined")
			}
			found := bytes.Contains(stderr.Bytes(), []byte(idleDiagnosticMarker))
			if found != (mode == "unsafe-control") {
				t.Fatalf("collector marker in stderr=%t for %s", found, mode)
			}
		})
	}
}

func runIdleDiagnosticChild(t *testing.T, mode string) {
	t.Helper()
	sent, joined := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	var connection net.Conn
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(joined)
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
			return
		}
		conn, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		// Cleanup closes the socket without a late TLS close_notify after peer EOF.
		socket := conn.(*tls.Conn).NetConn()
		mu.Lock()
		connection = socket
		mu.Unlock()
		defer func() {
			if err := socket.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				t.Error(err)
			}
		}()
		if _, err := buffer.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Type: application/x-protobuf\r\n\r\n"); err != nil {
			t.Error(err)
			return
		}
		if err := buffer.Flush(); err != nil {
			t.Error(err)
			return
		}
		// The response has completed before these unsolicited bytes arrive.
		time.Sleep(100 * time.Millisecond)
		_, _ = conn.Write([]byte(idleDiagnosticMarker + "\r\n"))
		close(sent)
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		var b [1]byte
		// Unsolicited bytes can race with transport close and cause a TCP reset.
		if n, err := conn.Read(b[:]); n != 0 || (!errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET)) {
			t.Errorf("idle peer did not observe transport close: bytes=%d err=%v", n, err)
		}
	}))
	defer server.Close()
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		if connection != nil {
			if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				t.Error(err)
			}
		}
	}()
	level := "warn"
	routes := []string{"capture"}
	settings, err := Resolve(Config{SchemaVersion: 1, Logs: LogConfig{Level: &level, Exporters: &routes}, Exporters: map[string]Exporter{"capture": {Type: "otlp_http", Endpoint: server.URL, APIKeyEnv: "ENKV_IDLE_TEST_KEY"}}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := Start(settings, SetupOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := runtime.Close(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	if runtime.settings.Console {
		t.Fatal("idle diagnostic check enabled console")
	}
	transport := runtime.remote.base.(*http.Transport)
	transport.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	if mode == "unsafe-control" {
		transport.DisableKeepAlives = false
	} else if mode != "owned" {
		t.Fatal("invalid idle child mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	telemetry.Start(runtime.Context(ctx), telemetry.ProviderCore, telemetry.OpCoreOpen).Finish(telemetry.ResultAdmissionRefused)
	select {
	case <-sent:
	case <-ctx.Done():
		t.Fatal("peer did not send unsolicited bytes")
	}
	// Join the read loop after it has had a scheduling interval to consume the bytes.
	time.Sleep(100 * time.Millisecond)
	if err := runtime.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-joined:
	case <-ctx.Done():
		t.Fatal("idle peer did not join")
	}
	if status := runtime.LogStatus("capture"); status.Written != 1 || status.Failed != 0 || status.Incomplete {
		t.Fatalf("successful response changed log delivery: %+v", status)
	}
	fmt.Println("idle_peer_joined")
}

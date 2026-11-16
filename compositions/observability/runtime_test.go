package observability

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"enkv.sh/telemetry"
	"go.opentelemetry.io/otel"
)

// full_only: false
func TestDefaultConsoleKeepsWarningAndNoSDK(t *testing.T) {
	settings, err := Decode(nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	runtime, err := Start(settings, SetupOptions{Console: &output})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.MeterProvider() != nil || runtime.ManualReader() != nil {
		t.Fatal("default setup constructed a metric SDK")
	}
	ctx := runtime.Context(context.Background())
	telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreOpen).Finish(telemetry.ResultSuccess)
	telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreOpen).Finish(telemetry.ResultAdmissionRefused)
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if strings.Count(text, "WARN (13)") != 1 || strings.Contains(text, "INFO (9)") || strings.Contains(text, "DEBUG (5)") {
		t.Fatalf("default console threshold: %q", text)
	}
}

// full_only: false
func TestUnknownDeliveryStatusIsEmpty(t *testing.T) {
	runtime := &Runtime{metricStatus: map[string]*deliveryCounter{}, traceStatus: map[string]*deliveryCounter{}}
	if got := runtime.MetricStatus("unknown"); got != (DeliveryStatus{}) {
		t.Fatalf("unknown metric destination: %+v", got)
	}
	if got := runtime.TraceStatus("unknown"); got != (DeliveryStatus{}) {
		t.Fatalf("unknown trace destination: %+v", got)
	}
	if got := runtime.LogStatus("unknown"); got != (DeliveryStatus{}) {
		t.Fatalf("unknown log destination: %+v", got)
	}
}

type blockedConsole struct{ entered, release chan struct{} }

func (writer *blockedConsole) Write(data []byte) (int, error) {
	select {
	case writer.entered <- struct{}{}:
	default:
	}
	<-writer.release
	return len(data), nil
}

// full_only: false
func TestBlockedConsoleCannotDelayProductCallOrShutdownDeadline(t *testing.T) {
	settings, err := Decode(nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	writer := &blockedConsole{entered: make(chan struct{}, 1), release: make(chan struct{})}
	runtime, err := Start(settings, SetupOptions{Console: writer})
	if err != nil {
		t.Fatal(err)
	}
	ctx := runtime.Context(context.Background())
	telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreOpen).Finish(telemetry.ResultAdmissionRefused)
	select {
	case <-writer.entered:
	case <-time.After(time.Second):
		t.Fatal("console writer was not reached")
	}
	done := make(chan struct{})
	go func() {
		call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreOpen)
		call.Finish(telemetry.ResultAdmissionRefused)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Product call waited for blocked console")
	}
	deadline, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if runtime.Close(deadline) == nil {
		t.Fatal("blocked console shutdown appeared complete")
	}
	close(writer.release)
	if err := runtime.Close(context.Background()); !errors.Is(err, errDeliveryIncomplete) {
		t.Fatal("released console lost the incomplete wait observation", err)
	}
	select {
	case <-runtime.closeDone:
	default:
		t.Fatal("released console cleanup did not join")
	}
}

type panickingConsole struct{}

func (panickingConsole) Write([]byte) (int, error) { panic("synthetic-secret-panic") }

// full_only: false
func TestConsolePanicIsContainedAndStatusIsSafe(t *testing.T) {
	settings, err := Decode(nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := Start(settings, SetupOptions{Console: panickingConsole{}})
	if err != nil {
		t.Fatal(err)
	}
	telemetry.Start(runtime.Context(context.Background()), telemetry.ProviderCore, telemetry.OpCoreOpen).Finish(telemetry.ResultAdmissionRefused)
	if err := runtime.Close(context.Background()); !errors.Is(err, errDeliveryIncomplete) || strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatal("console failure lacks a safe incomplete-delivery result", err)
	}
	select {
	case <-runtime.closeDone:
	default:
		t.Fatal("failed console worker did not join")
	}
	status := runtime.LogStatus("console")
	if status.Failed != 1 || !status.Incomplete || strings.Contains(fmt.Sprint(status), "synthetic-secret") {
		t.Fatalf("unsafe panic status: %+v", status)
	}
}

// full_only: false
func TestRuntimeCopiesResolvedSettings(t *testing.T) {
	settings, err := Decode([]byte(`{"schema_version":1,"resource":{"attributes":{"service.name":"before"}}}`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := Start(settings, SetupOptions{Console: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}
	settings.Resource["service.name"] = "after"
	settings.Scopes["core"] = Scope{Name: "after"}
	if runtime.settings.Resource["service.name"] != "before" || runtime.settings.Scopes["core"].Name == "after" {
		t.Fatal("active runtime retained mutable settings")
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestMetricBarrierAfterAndDuringCloseReturns(t *testing.T) {
	settings, err := Decode([]byte(`{"schema_version":1,"metrics":{"exporters":["local"]},"exporters":{"local":{"type":"otlp_file","directory":"telemetry"}}}`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := Start(settings, SetupOptions{BaseDirectory: t.TempDir(), ManualMetrics: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.AwaitMetrics(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	settled := make(chan struct{})
	go func() { _ = runtime.Close(ctx); close(settled) }()
loop:
	for range 100 {
		_ = runtime.FlushMetrics(ctx)
		select {
		case <-settled:
			break loop
		default:
		}
	}
	select {
	case <-settled:
	case <-ctx.Done():
		t.Fatal("concurrent close stalled")
	}
	if runtime.FlushMetrics(context.Background()) == nil || runtime.AwaitMetrics(context.Background()) == nil {
		t.Fatal("post-close metric caller stalled or appeared ready")
	}
}

// full_only: false
func TestSDKCallbackOmitsRawErrorText(t *testing.T) {
	settings, err := Decode([]byte(`{"schema_version":1,"metrics":{"exporters":["local"]},"exporters":{"local":{"type":"otlp_file","directory":"telemetry"}}}`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	var console bytes.Buffer
	runtime, err := Start(settings, SetupOptions{BaseDirectory: t.TempDir(), Console: &console})
	if err != nil {
		t.Fatal(err)
	}
	const secret = "SYNTHETIC_SECRET_CREDENTIAL"
	otel.Handle(errors.New(secret))
	if runtime.SDKCallbackCount() == 0 {
		t.Fatal("SDK callback did not reach safe handler")
	}
	_ = runtime.Close(context.Background())
	if strings.Contains(console.String(), secret) {
		t.Fatal("SDK error text reached console")
	}
}

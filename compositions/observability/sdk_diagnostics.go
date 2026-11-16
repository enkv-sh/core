package observability

import (
	"sync"
	"sync/atomic"

	"github.com/go-logr/logr"
	"go.opentelemetry.io/otel"
)

const sdkWarningVerbosity = 1

var sdkHandlerOnce sync.Once
var sdkCallbackCount atomic.Uint64

// Both SDK callbacks can receive arbitrary errors, messages, and attributes.
// Count them without formatting, retaining, or forwarding their content.
// Exporter adapters record their own destination failures separately.
func installSDKErrorHandler() {
	sdkHandlerOnce.Do(func() {
		otel.SetLogger(logr.New(sdkLogSink{}))
		otel.SetErrorHandler(otel.ErrorHandlerFunc(func(error) { sdkCallbackCount.Add(1) }))
	})
}

type sdkLogSink struct{}

func (sdkLogSink) Init(logr.RuntimeInfo) {}

// The pinned SDK uses V(1) for warnings, V(4) for info, and V(8) for debug.
func (sdkLogSink) Enabled(level int) bool { return level <= sdkWarningVerbosity }

func (sdkLogSink) Info(int, string, ...any)    { sdkCallbackCount.Add(1) }
func (sdkLogSink) Error(error, string, ...any) { sdkCallbackCount.Add(1) }

func (sink sdkLogSink) WithValues(...any) logr.LogSink { return sink }
func (sink sdkLogSink) WithName(string) logr.LogSink   { return sink }

func (runtime *Runtime) SDKCallbackCount() uint64 {
	if runtime == nil {
		return 0
	}
	current := sdkCallbackCount.Load()
	if current < runtime.sdkCallbackStart {
		return 0
	}
	return current - runtime.sdkCallbackStart
}

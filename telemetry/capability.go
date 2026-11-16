package telemetry

import (
	"context"
	"sync"
	"sync/atomic"

	"go.opentelemetry.io/otel/trace"
)

// MetricPoint contains only the fixed operation vocabulary and numeric facts.
// Product values, errors, credentials and arbitrary attributes have no entry
// point into this queue.
type MetricPoint struct {
	Name       string
	Provider   Provider
	Operation  Operation
	Result     Result
	Status     string
	IntValue   int64
	FloatValue float64
	Barrier    chan<- struct{}
}

// Capability is owned by one invocation. The channel is bounded and must be
// consumed by setup-owned work after Product calls hand off their measurements.
type Capability struct {
	metrics         chan<- MetricPoint
	recorder        *Recorder
	tracers         map[Provider]trace.Tracer
	closed          atomic.Bool
	metricMu        sync.Mutex
	lostMetrics     atomic.Uint64
	rejectedMetrics atomic.Uint64
	lostTraces      atomic.Uint64
}

func NewCapability(metrics chan<- MetricPoint, recorder *Recorder) *Capability {
	return &Capability{metrics: metrics, recorder: recorder}
}

// NewCapabilityWithTracers takes an invocation-local copy of the configured
// tracers. A missing provider keeps trace capture disabled for that owner.
func NewCapabilityWithTracers(metrics chan<- MetricPoint, recorder *Recorder, tracers map[Provider]trace.Tracer) *Capability {
	capability := NewCapability(metrics, recorder)
	if len(tracers) != 0 {
		capability.tracers = make(map[Provider]trace.Tracer, len(tracers))
		for provider, tracer := range tracers {
			if tracer != nil {
				capability.tracers[provider] = tracer
			}
		}
	}
	return capability
}

func (capability *Capability) tracer(provider Provider) trace.Tracer {
	if capability == nil || capability.closed.Load() {
		return nil
	}
	return capability.tracers[provider]
}

func (capability *Capability) MetricsEnabled() bool {
	return capability != nil && capability.metrics != nil && !capability.closed.Load()
}

func (capability *Capability) Recorder() *Recorder {
	if capability == nil || capability.closed.Load() {
		return nil
	}
	return capability.recorder
}

func (capability *Capability) LostMetrics() uint64 {
	if capability == nil {
		return 0
	}
	return capability.lostMetrics.Load()
}

func (capability *Capability) RejectedMetrics() uint64 {
	if capability == nil {
		return 0
	}
	return capability.rejectedMetrics.Load()
}

func (capability *Capability) LostTraces() uint64 {
	if capability == nil {
		return 0
	}
	return capability.lostTraces.Load()
}

// Deactivate stops admission. The owner never closes metrics: a late Product
// goroutine can still hold this capability after invocation shutdown.
func (capability *Capability) Deactivate() {
	if capability != nil {
		// Close admission under the handoff lock. Every accepted metric has
		// completed its bounded queue handoff before closure is published.
		// emitMetric never waits for this mutex or for queue space.
		capability.metricMu.Lock()
		capability.closed.Store(true)
		capability.metricMu.Unlock()
	}
}

type capabilityContextKey struct{}

func WithCapability(ctx context.Context, capability *Capability) context.Context {
	if capability == nil || ctx == nil {
		return ctx
	}
	return context.WithValue(ctx, capabilityContextKey{}, capability)
}

func capabilityFromContext(ctx context.Context) *Capability {
	if ctx == nil {
		return nil
	}
	capability, _ := ctx.Value(capabilityContextKey{}).(*Capability)
	return capability
}

func (capability *Capability) emitMetric(point MetricPoint) {
	if capability == nil || capability.metrics == nil {
		return
	}
	if !validMetricPoint(point) {
		capability.rejectedMetrics.Add(1)
		return
	}
	if capability.closed.Load() {
		capability.lostMetrics.Add(1)
		return
	}
	if !capability.metricMu.TryLock() {
		capability.lostMetrics.Add(1)
		return
	}
	defer capability.metricMu.Unlock()
	if capability.closed.Load() {
		capability.lostMetrics.Add(1)
		return
	}
	select {
	case capability.metrics <- point:
	default:
		capability.lostMetrics.Add(1)
	}
}

func validMetricPoint(point MetricPoint) bool {
	if !ValidOperationOwner(point.Provider, point.Operation) {
		return false
	}
	switch point.Name {
	case ManifestSelectedEntries, ManifestIncludedEntries, ManifestExcludedEntries:
		if point.Provider != ProviderCore || point.Operation != OpCoreReaderManifest || point.Result != ResultSuccess || point.Status != "" || point.IntValue > 512 {
			return false
		}
	}
	for _, definition := range definitions {
		if definition.Name != point.Name {
			continue
		}
		if point.Result != "" && !AllowedAttribute("result", string(point.Result)) || point.Status != "" && !AllowedAttribute("status", point.Status) {
			return false
		}
		if definition.Unit == "s" {
			return point.FloatValue >= 0 && point.IntValue == 0
		}
		return point.IntValue >= 0 && point.FloatValue == 0
	}
	return false
}

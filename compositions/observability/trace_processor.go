package observability

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

const (
	traceExportTimeout          = 2 * time.Second
	traceFlushTimeout           = 2 * time.Second
	traceCompletionPollInterval = 100 * time.Microsecond
)

const (
	traceQueueSlots = 128
	traceBatchSize  = 16
)

type traceItem struct {
	span    sdktrace.ReadOnlySpan
	barrier chan struct{}
}

type boundedTraceProcessor struct {
	exporter        sdktrace.SpanExporter
	exporterFactory func(context.Context) (sdktrace.SpanExporter, error)
	status          *deliveryCounter
	queue           chan traceItem
	stop            chan struct{}
	done            chan struct{}
	initialized     chan struct{}
	closed          atomic.Bool
	inFlight        atomic.Int64
	shutdownContext context.Context
	runContext      context.Context
	cancelRun       context.CancelFunc
	shutdownErr     error
	once            sync.Once
}

func newBoundedTraceProcessor(exporter sdktrace.SpanExporter, status *deliveryCounter) *boundedTraceProcessor {
	return newDeferredTraceProcessor(func(context.Context) (sdktrace.SpanExporter, error) { return exporter, nil }, status)
}

func newDeferredTraceProcessor(factory func(context.Context) (sdktrace.SpanExporter, error), status *deliveryCounter) *boundedTraceProcessor {
	runContext, cancelRun := context.WithCancel(context.Background())
	processor := &boundedTraceProcessor{exporterFactory: factory, status: status, queue: make(chan traceItem, traceQueueSlots), stop: make(chan struct{}), done: make(chan struct{}), initialized: make(chan struct{}), runContext: runContext, cancelRun: cancelRun}
	go processor.run()
	return processor
}

func (*boundedTraceProcessor) OnStart(context.Context, sdktrace.ReadWriteSpan) {}

func (processor *boundedTraceProcessor) OnEnd(span sdktrace.ReadOnlySpan) {
	processor.inFlight.Add(1)
	defer processor.inFlight.Add(-1)
	if processor.closed.Load() {
		processor.status.dropped.Add(1)
		processor.status.incomplete.Store(true)
		return
	}
	select {
	case processor.queue <- traceItem{span: span}:
		processor.status.accepted.Add(1)
	default:
		processor.status.dropped.Add(1)
		processor.status.incomplete.Store(true)
	}
}

func (processor *boundedTraceProcessor) run() {
	defer close(processor.done)
	defer processor.cancelRun()
	defer processor.shutdownExporter()
	ready := false
	defer func() {
		if !ready {
			close(processor.initialized)
		}
		if recover() != nil {
			processor.status.fail()
			processor.shutdownErr = errFileDelivery
			processor.closed.Store(true)
			processor.dropRemaining()
		}
	}()
	exporter, err := processor.exporterFactory(processor.runContext)
	processor.exporter = exporter
	close(processor.initialized)
	ready = true
	if err != nil || exporter == nil {
		processor.status.fail()
		processor.shutdownErr = errFileDelivery
		processor.closed.Store(true)
		processor.dropRemaining()
		return
	}
	consume := func(parent context.Context, item traceItem) {
		if item.barrier != nil {
			close(item.barrier)
			return
		}
		spans := make([]sdktrace.ReadOnlySpan, 0, traceBatchSize)
		spans = append(spans, item.span)
		var barrier chan struct{}
	collect:
		for len(spans) < traceBatchSize {
			select {
			case next := <-processor.queue:
				if next.barrier != nil {
					barrier = next.barrier
					break collect
				}
				spans = append(spans, next.span)
			default:
				break collect
			}
		}
		if barrier != nil {
			defer close(barrier)
		}
		if parent.Err() != nil {
			processor.status.dropped.Add(uint64(len(spans)))
			processor.status.incomplete.Store(true)
			return
		}
		ctx, cancel := context.WithTimeout(parent, traceExportTimeout)
		func() {
			defer func() {
				if recover() != nil {
					processor.status.failed.Add(uint64(len(spans)))
					processor.status.incomplete.Store(true)
				}
			}()
			if processor.exporter.ExportSpans(ctx, spans) != nil {
				processor.status.failed.Add(uint64(len(spans)))
				processor.status.incomplete.Store(true)
			} else {
				processor.status.written.Add(uint64(len(spans)))
			}
		}()
		cancel()
	}
	for {
		select {
		case item := <-processor.queue:
			if processor.closed.Load() {
				if processor.shutdownContext.Err() != nil {
					processor.dropItem(item)
				} else {
					consume(processor.shutdownContext, item)
				}
			} else {
				consume(processor.runContext, item)
			}
		case <-processor.stop:
			for {
				if processor.shutdownContext.Err() != nil {
					select {
					case item := <-processor.queue:
						processor.dropItem(item)
					default:
						if processor.inFlight.Load() == 0 {
							// A final handoff can enqueue between the first empty selection
							// and observing zero producers. Establish emptiness again.
							select {
							case item := <-processor.queue:
								processor.dropItem(item)
							default:
								return
							}
						}
						time.Sleep(traceCompletionPollInterval)
					}
					continue
				}
				select {
				case item := <-processor.queue:
					consume(processor.shutdownContext, item)
				default:
					if processor.inFlight.Load() == 0 {
						select {
						case item := <-processor.queue:
							consume(processor.shutdownContext, item)
						default:
							return
						}
					}
					runtime.Gosched()
				}
			}
		}
	}
}

func (processor *boundedTraceProcessor) shutdownExporter() {
	if processor.exporter == nil {
		return
	}
	ctx := context.Background()
	var cancel context.CancelFunc
	select {
	case <-processor.stop:
		ctx = processor.shutdownContext
	default:
		ctx, cancel = context.WithTimeout(ctx, traceFlushTimeout)
	}
	if cancel != nil {
		defer cancel()
	}
	defer func() {
		if recover() != nil {
			processor.status.fail()
			processor.shutdownErr = errFileDelivery
		}
	}()
	if processor.exporter.Shutdown(ctx) != nil {
		processor.status.fail()
		processor.shutdownErr = errFileDelivery
	}
}

// A producer that passed the pre-close check can still be handing a span to
// the queue. Account for that handoff before the worker exits.
func (processor *boundedTraceProcessor) dropRemaining() {
	for {
		select {
		case item := <-processor.queue:
			processor.dropItem(item)
		default:
			if processor.inFlight.Load() == 0 {
				select {
				case item := <-processor.queue:
					processor.dropItem(item)
				default:
					return
				}
			}
			time.Sleep(traceCompletionPollInterval)
		}
	}
}

func (processor *boundedTraceProcessor) dropItem(item traceItem) {
	if item.barrier != nil {
		close(item.barrier)
		return
	}
	processor.status.dropped.Add(1)
	processor.status.incomplete.Store(true)
}

func (processor *boundedTraceProcessor) ForceFlush(ctx context.Context) error {
	processor.inFlight.Add(1)
	defer processor.inFlight.Add(-1)
	if processor.closed.Load() {
		return errFileDelivery
	}
	barrier := make(chan struct{})
	select {
	case <-processor.done:
		return errFileDelivery
	default:
	}
	select {
	case processor.queue <- traceItem{barrier: barrier}:
	case <-processor.done:
		return errFileDelivery
	case <-ctx.Done():
		processor.status.incomplete.Store(true)
		return ctx.Err()
	}
	select {
	case <-barrier:
		if processor.closed.Load() {
			return errFileDelivery
		}
		return nil
	case <-processor.done:
		return errFileDelivery
	case <-ctx.Done():
		processor.status.incomplete.Store(true)
		return ctx.Err()
	}
}

func (processor *boundedTraceProcessor) Shutdown(ctx context.Context) error {
	var stopDeadline func() bool
	processor.once.Do(func() {
		processor.shutdownContext = ctx
		if ctx.Done() != nil {
			stopDeadline = context.AfterFunc(ctx, processor.cancelRun)
		}
		processor.closed.Store(true)
		close(processor.stop)
	})
	select {
	case <-processor.done:
		if stopDeadline != nil {
			stopDeadline()
		}
	case <-ctx.Done():
		processor.status.incomplete.Store(true)
		return ctx.Err()
	}
	return processor.shutdownErr
}

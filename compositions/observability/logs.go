package observability

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"enkv.sh/telemetry"
)

const logCapturePollInterval = 10 * time.Millisecond

const logQueueSlots = 8

type logOutput struct {
	name       string
	queue      chan telemetry.DiagnosticRecord
	stop       chan struct{}
	done       chan struct{}
	write      func(context.Context, telemetry.DiagnosticRecord) error
	writeBatch func(context.Context, []telemetry.DiagnosticRecord) error
	finish     func(context.Context) error
	shutdown   context.Context
	accepted   atomic.Uint64
	written    atomic.Uint64
	dropped    atomic.Uint64
	failed     atomic.Uint64
	incomplete atomic.Bool
}

func (runtime *Runtime) startLogs(options SetupOptions) {
	if runtime.settings.LogLevel == Off {
		return
	}
	if runtime.settings.Console {
		writer := options.Console
		if writer == nil {
			writer = os.Stderr
		}
		runtime.addLogOutput("console", func(_ context.Context, record telemetry.DiagnosticRecord) error {
			_, err := fmt.Fprintf(writer, "%s %s (%d) component=%s operation=%s event=%s result=%s reason=%s trace_id=%s span_id=%s trace_sampled=%t invocation_id=%s worker_id=%s member=%s key_id=%s command_id=%s attempt_id=%s path_kind=%s path=%s config_field=%s error_status=%s error=%s\n",
				record.OccurredAt.Format(time.RFC3339Nano), record.SeverityText, record.SeverityNumber,
				strconv.Quote(record.Component), strconv.Quote(string(record.Operation)), strconv.Quote(string(record.Event)), strconv.Quote(string(record.Result)), strconv.Quote(string(record.Reason)),
				strconv.Quote(record.TraceID), strconv.Quote(record.SpanID), record.TraceSampled,
				strconv.Quote(record.InvocationID), strconv.Quote(record.WorkerID),
				strconv.Quote(record.EntryName), strconv.Quote(record.KeyID), strconv.Quote(record.CommandID), strconv.Quote(record.AttemptID), strconv.Quote(record.PathKind), strconv.Quote(record.Path), strconv.Quote(record.ConfigField), strconv.Quote(record.ErrorDetailStatus), strconv.Quote(record.ErrorDetail))
			return err
		})
	}
	for _, name := range runtime.settings.LogExporters {
		exporter := runtime.settings.ActiveExporters[name]
		var writer *otlpLogWriter
		if exporter.Type == "otlp_http" {
			writer = newRemoteLogWriter(runtime.settings, exporter, runtime.remote)
		} else {
			writer = newFileLogWriter(runtime.settings, options.BaseDirectory, exporter.Directory)
		}
		runtime.addLogOutput(name, writer.write)
		output := runtime.logOutputs[len(runtime.logOutputs)-1]
		output.writeBatch = writer.writeBatch
		output.finish = writer.close
	}
	if len(runtime.logOutputs) == 0 {
		return
	}
	runtime.recorder = telemetry.NewRecorderWithMinimumSeverity(int(runtime.settings.LogLevel))
	runtime.logStop = make(chan struct{})
	runtime.logDone = make(chan struct{})
	go runtime.runLogCapture()
}

func (runtime *Runtime) addLogOutput(name string, write func(context.Context, telemetry.DiagnosticRecord) error) {
	output := &logOutput{name: name, queue: make(chan telemetry.DiagnosticRecord, logQueueSlots), stop: make(chan struct{}), done: make(chan struct{}), write: write}
	runtime.logOutputs = append(runtime.logOutputs, output)
	go output.run()
}

func (output *logOutput) run() {
	defer close(output.done)
	defer func() {
		if output.finish != nil && output.safeFinish(output.shutdown) != nil {
			output.failed.Add(1)
			output.incomplete.Store(true)
		}
	}()
	for {
		select {
		case record := <-output.queue:
			output.consume(context.Background(), record)
		case <-output.stop:
			for {
				select {
				case record := <-output.queue:
					output.consume(output.shutdown, record)
				default:
					return
				}
			}
		}
	}
}

func (output *logOutput) consume(ctx context.Context, first telemetry.DiagnosticRecord) {
	if output.writeBatch == nil {
		if output.safeWrite(ctx, first) != nil {
			output.failed.Add(1)
			output.incomplete.Store(true)
		} else {
			output.written.Add(1)
		}
		return
	}
	batch := make([]telemetry.DiagnosticRecord, 1, logQueueSlots)
	batch[0] = first
collect:
	for len(batch) < cap(batch) {
		select {
		case record := <-output.queue:
			batch = append(batch, record)
		default:
			break collect
		}
	}
	if output.safeWriteBatch(ctx, batch) != nil {
		output.failed.Add(uint64(len(batch)))
		output.incomplete.Store(true)
	} else {
		output.written.Add(uint64(len(batch)))
	}
}

func (output *logOutput) safeWriteBatch(ctx context.Context, records []telemetry.DiagnosticRecord) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("telemetry output failed")
		}
	}()
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return output.writeBatch(ctx, records)
}

func (output *logOutput) safeFinish(ctx context.Context) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("telemetry output failed")
		}
	}()
	if ctx == nil {
		ctx = context.Background()
	}
	return output.finish(ctx)
}

func (output *logOutput) safeWrite(ctx context.Context, record telemetry.DiagnosticRecord) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("telemetry output failed")
		}
	}()
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return output.write(ctx, record)
}

func (runtime *Runtime) runLogCapture() {
	defer close(runtime.logDone)
	ticker := time.NewTicker(logCapturePollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			runtime.drainLogs()
		case <-runtime.logStop:
			runtime.recorder.Close()
			runtime.drainLogs()
			return
		}
	}
}

func (runtime *Runtime) drainLogs() {
	batch := make([]telemetry.DiagnosticRecord, 0, 4)
	for {
		batch = runtime.recorder.Drain(batch[:0])
		if len(batch) == 0 {
			return
		}
		for _, record := range batch {
			if record.SeverityNumber < int(runtime.settings.LogLevel) {
				continue
			}
			if record.Validate() != nil {
				for _, output := range runtime.logOutputs {
					output.dropped.Add(1)
					output.incomplete.Store(true)
				}
				continue
			}
			for _, output := range runtime.logOutputs {
				select {
				case output.queue <- record:
					output.accepted.Add(1)
				default:
					output.dropped.Add(1)
					output.incomplete.Store(true)
				}
			}
		}
	}
}

func (runtime *Runtime) closeLogs(ctx context.Context) error {
	if runtime.logStop == nil {
		return nil
	}
	close(runtime.logStop)
	<-runtime.logDone
	for _, output := range runtime.logOutputs {
		output.shutdown = ctx
		close(output.stop)
	}
	for _, output := range runtime.logOutputs {
		<-output.done
	}
	return ctx.Err()
}

func (runtime *Runtime) LogStatus(name string) DeliveryStatus {
	if runtime == nil {
		return DeliveryStatus{}
	}
	for _, output := range runtime.logOutputs {
		if output.name == name {
			status := DeliveryStatus{Accepted: output.accepted.Load(), Written: output.written.Load(), Dropped: output.dropped.Load(), Failed: output.failed.Load(), Incomplete: output.incomplete.Load()}
			capture := runtime.RecorderStatus()
			status.Dropped += capture.DroppedContention + capture.DroppedFull + capture.DroppedClosed + capture.Rejected
			status.Incomplete = status.Incomplete || status.Dropped != 0
			return status
		}
	}
	return DeliveryStatus{}
}

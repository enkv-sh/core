package main

import (
	"context"
	"flag"
	"io"
	"os"
	"path/filepath"
	"sync"

	"enkv.sh/compositions/observability"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

type commandTelemetryOptions struct {
	configuration string
	logLevel      string
	directory     string
	// Plan reports a complete verified difference with exit 1.
	differenceIsSuccess bool
	setupIncomplete     *bool
	terminal            *commandTerminal
}

type commandTerminal struct {
	result telemetry.Result
	reason telemetry.DiagnosticReason
}

func (t *commandTerminal) observe(result core.Result, reasons ...contract.DiagnosticReason) {
	t.reason = ""
	switch result.Outcome {
	case core.ObservedCurrent, core.Unchanged:
		t.result = telemetry.ResultSuccess
	case core.AdmissionRefused:
		t.result = telemetry.ResultAdmissionRefused
	case core.Contention:
		t.result = telemetry.ResultContention
	case core.UnresolvedCommit:
		t.result = telemetry.ResultUnresolvedCommit
	case core.IntegrityFailure:
		t.result = telemetry.ResultIntegrityFailure
	case core.EvidenceUnavailable:
		t.result = telemetry.ResultEvidenceUnavailable
	case core.RootLossUnsupported:
		t.result = telemetry.ResultRootLossUnsupported
	default:
		t.result = telemetry.ResultFailure
	}
	for _, reason := range reasons {
		t.cancellation(reason)
	}
}

func (t *commandTerminal) cancellation(reason contract.DiagnosticReason) {
	if reason != contract.ReasonCancelled && reason != contract.ReasonExpired {
		return
	}
	switch t.result {
	case telemetry.ResultUnknown, telemetry.ResultUnresolvedCommit, telemetry.ResultWriteUnknown:
		return
	}
	t.result, t.reason = telemetry.ResultCancelled, ""
}

func (t *commandTerminal) admission(identity *core.PreAdmissionRequestIdentity) {
	if identity != nil {
		t.cancellation(contract.DiagnosticReason(identity.Code))
	}
}

func (t *commandTerminal) diagnostics(rows []contract.Diagnostic) {
	for _, row := range rows {
		if row.Outcome == contract.DiagnosticUnable {
			t.cancellation(row.Reason)
		}
	}
}

func (t *commandTerminal) deliveryFailed() {
	if t.result == "" || t.result == telemetry.ResultSuccess {
		t.result, t.reason = telemetry.ResultFailure, telemetry.DiagnosticReasonEvidenceUnavailable
	}
}

func (t *commandTerminal) mutation(result core.PublicApplyResult) {
	t.observe(result.Result)
	if result.Result.Outcome == core.UnresolvedCommit {
		return
	}
	if result.Generated != nil {
		switch result.Generated.EffectSummary {
		case contract.ReceiptEffectUnknown:
			t.result = telemetry.ResultUnknown
			return
		case contract.ReceiptEffectPending, contract.ReceiptEffectPartial:
			t.result = telemetry.ResultEvidenceUnavailable
			return
		default:
			switch result.Generated.StateResult {
			case "effect-unknown", "commit-outcome-unknown":
				t.result = telemetry.ResultUnknown
			case "retirement-pending", "effect-pending", "effect-partial", "unavailable":
				t.result = telemetry.ResultEvidenceUnavailable
			case "effect-terminal-failure":
				t.result, t.reason = telemetry.ResultFailure, telemetry.DiagnosticReasonEvidenceUnavailable
			case "positive-defect":
				t.result = telemetry.ResultIntegrityFailure
			case "refused", "snapshot-size-refusal":
				t.result = telemetry.ResultAdmissionRefused
			}
		}
	}
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Outcome == contract.DiagnosticUnable && (result.Generated != nil || result.Result.Outcome != core.AdmissionRefused) && t.result != telemetry.ResultUnknown && t.result != telemetry.ResultUnresolvedCommit {
			t.result, t.reason = telemetry.ResultEvidenceUnavailable, ""
		}
	}
	t.admission(result.PreAdmission)
	t.diagnostics(result.Diagnostics)
}

func (t *commandTerminal) publication(result core.PublicPublicationResult) {
	t.observe(result.Result)
	switch result.Summary {
	case contract.PublicationSummaryUnknown:
		t.result = telemetry.ResultUnknown
	case contract.PublicationSummaryFailed, contract.PublicationSummaryMixedTerminal:
		if t.result == telemetry.ResultSuccess {
			t.result, t.reason = telemetry.ResultFailure, telemetry.DiagnosticReasonEvidenceUnavailable
		}
	}
}

func (o commandTelemetryOptions) successful(code int) bool {
	return code == 0 || o.differenceIsSuccess && code == 1
}

func (o *commandTelemetryOptions) BindFlags(flags *flag.FlagSet) {
	flags.StringVar(&o.configuration, "telemetry-config", "", "")
	flags.StringVar(&o.logLevel, "log-level", "", "")
}

type commandDiagnosticWriter struct {
	mu          sync.Mutex
	writer      io.Writer
	writeFailed bool
}

func (w *commandDiagnosticWriter) Write(body []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.writer.Write(body)
	if err != nil || n != len(body) {
		w.writeFailed = true
	}
	return n, err
}

func (w *commandDiagnosticWriter) failed() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writeFailed
}

// A delivery failure changes only an otherwise successful process exit.
// Existing refusal/unknown exits and already delivered operation facts survive.
func commandDiagnosticExit(out io.Writer, message string, code int) int {
	body := []byte(message + "\n")
	n, err := out.Write(body)
	if (err != nil || n != len(body)) && code == 0 {
		return 2
	}
	return code
}

func withCommandTelemetry(ctx context.Context, options commandTelemetryOptions, diagnostic io.Writer, refuse func() int, run func(context.Context, io.Writer) int) (code int) {
	if ctx == nil || diagnostic == nil || refuse == nil || run == nil {
		return 2
	}
	console := &commandDiagnosticWriter{writer: diagnostic}
	diagnostic = console
	refuseSetup := func(message string) int {
		failureCode := commandDiagnosticExit(diagnostic, message, 2)
		if refusalCode := refuse(); refusalCode != 0 {
			return refusalCode
		}
		return failureCode
	}
	directory := options.directory
	if directory == "" {
		var err error
		directory, err = os.Getwd()
		if err != nil {
			return refuseSetup("application directory is unavailable")
		}
	}
	configuration := options.configuration
	if configuration != "" && !filepath.IsAbs(configuration) {
		configuration = filepath.Join(directory, configuration)
	}
	settings, err := observability.Load(configuration, observability.EnvironmentOptions(options.logLevel))
	if err != nil {
		return refuseSetup("telemetry configuration refused")
	}
	runtime, err := observability.Start(settings, observability.SetupOptions{BaseDirectory: directory, Console: diagnostic})
	if err != nil {
		return refuseSetup("telemetry setup failed")
	}
	// Cleanup runs on panic, but an invocation terminal is emitted only on return.
	defer func() {
		closeErr := runtime.Close(context.Background())
		if closeErr != nil || console.failed() {
			if options.successful(code) {
				code = 2
			}
			code = commandDiagnosticExit(diagnostic, "diagnostic delivery incomplete; retain the result on stdout", code)
		}
	}()
	call := telemetry.Start(runtime.Context(ctx), telemetry.ProviderApplication, telemetry.OpApplicationInvocation)
	code = run(telemetry.CallContext(runtime.Context(ctx), call), diagnostic)
	status := telemetry.ResultFailure
	if options.successful(code) {
		status = telemetry.ResultSuccess
	} else if code == 2 && options.setupIncomplete != nil && *options.setupIncomplete {
		status = telemetry.ResultSetupIncomplete
	}
	if options.terminal != nil && options.terminal.result != "" {
		status = options.terminal.result
		if status == telemetry.ResultSuccess && !options.successful(code) {
			options.terminal.deliveryFailed()
			status = options.terminal.result
		}
		if options.terminal.reason != "" {
			call.FinishReason(status, options.terminal.reason)
			return code
		}
	}
	call.Finish(status)
	return code
}

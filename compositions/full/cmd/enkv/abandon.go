package main

import (
	"context"
	"crypto/rand"
	"flag"
	"io"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

type abandonmentExecutor func(context.Context, contract.ID, string, configuration.Format, compositionfull.AbandonmentRequest) compositionfull.AbandonmentResult

func runAbandon(args []string, out, diagnostic io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return runAbandonWithExecutor(ctx, args, out, diagnostic, compositionfull.AbandonConfigurationFile)
}
func runAbandonWithExecutor(ctx context.Context, args []string, out, diagnostic io.Writer, execute abandonmentExecutor) int {
	if out == nil || diagnostic == nil {
		return 2
	}
	body := "abandon list --source <file>\nabandon plan --source <file> --target <GroupID> --out <plan-file>\nabandon apply --source <file> --plan <plan-file>\nabandon receipt --source <file> --operation <OperationID>\n"
	if len(args) == 0 {
		if n, err := io.WriteString(out, body); err != nil || n != len(body) {
			return 2
		}
		return 0
	}
	if handled, code := publicQueryHelp(args, out, body); handled {
		return code
	}
	operation := core.AdministrativeOperation("abandon-" + args[0])
	switch operation {
	case core.AdministrativeList, core.AdministrativePlan, core.AdministrativeApply, core.AdministrativeReceipt:
	default:
		return writeUnknownDispatch(args[1:], out, diagnostic)
	}
	flags := flag.NewFlagSet("abandon "+args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var source, format, target, artifact, plan, operationID replacementFlag
	flags.Var(&source, "source", "")
	flags.Var(&format, "source-format", "")
	structured := bindCommandJSONFlag(flags)
	flags.Var(&target, "target", "")
	flags.Var(&artifact, "out", "")
	flags.Var(&plan, "plan", "")
	flags.Var(&operationID, "operation", "")
	var telemetryOptions commandTelemetryOptions
	telemetryOptions.BindFlags(flags)
	if handled, code := commandFlagHelp(args[1:], out, flags, "abandon "+args[0]+" [--source PATH] [--source-format yaml|json] [OPTIONS]\n"); handled {
		return code
	}
	refuse := func() int {
		selected, _ := configurationFormat(format.value)
		r, err := compositionfull.NewAbandonmentRefusal(operation, selected)
		if err != nil || writeAbandonment(ctx, out, *structured, r) != nil {
			return commandDiagnosticExit(diagnostic, "abandonment result delivery failed", 2)
		}
		return 2
	}
	invalid := func() int {
		code := refuse()
		if !*structured {
			code = commandDiagnosticExit(diagnostic, "abandon command requires its exact command-specific inputs; default source is enkv.yaml; use --source-format yaml|json for a --source without a recognized suffix", code)
		}
		return code
	}
	if err := flags.Parse(args[1:]); err != nil {
		return invalid()
	}
	if len(flags.Args()) != 0 || execute == nil {
		return invalid()
	}
	paths, captured := captureCommandPaths()
	sourcePath, selected, ok := paths.source(source, format)
	if !captured {
		return commandDiagnosticExit(diagnostic, commandDirectoryUnavailable, refuse())
	}
	if !ok {
		return invalid()
	}
	request := compositionfull.AbandonmentRequest{Operation: operation}
	switch operation {
	case core.AdministrativeList:
		if target.set || artifact.set || plan.set || operationID.set {
			return invalid()
		}
	case core.AdministrativePlan:
		if artifact.value == "" || plan.set || operationID.set {
			return invalid()
		}
		request.TargetGroupID, ok = parseID(target.value)
		if !ok {
			return invalid()
		}
	case core.AdministrativeApply:
		if plan.value == "" || target.set || artifact.set || operationID.set {
			return invalid()
		}
	case core.AdministrativeReceipt:
		if target.set || artifact.set || plan.set {
			return invalid()
		}
		request.OperationID, ok = parseID(operationID.value)
		if !ok {
			return invalid()
		}
	}
	request.ArtifactPath = paths.absolute(artifact.value)
	request.PlanPath = paths.absolute(plan.value)
	if operation == core.AdministrativePlan && !(core.AdministrativePlanRequest{TargetGroupID: request.TargetGroupID, ArtifactPath: request.ArtifactPath}).Valid() {
		return invalid()
	}
	if request.ArtifactPath == sourcePath || request.PlanPath == sourcePath {
		return invalid()
	}
	var terminal commandTerminal
	telemetryOptions.terminal = &terminal
	telemetryOptions.directory = paths.directory
	return withCommandTelemetry(ctx, telemetryOptions, diagnostic, refuse, func(ctx context.Context, diagnostic io.Writer) int {
		var nonce contract.ID
		if _, err := rand.Read(nonce[:]); err != nil || nonce.IsZero() {
			return commandDiagnosticExit(diagnostic, "abandonment request correlation unavailable", 2)
		}
		result := execute(ctx, nonce, sourcePath, selected, request)
		terminal.observe(result.Operation.Result)
		terminal.admission(result.Operation.PreAdmission)
		if err := writeAbandonment(ctx, out, *structured, result); err != nil {
			return commandDiagnosticExit(diagnostic, "abandonment result delivery failed", 2)
		}
		code := compositionfull.AbandonmentExitCode(result)
		if result.Delivery.CleanupFailed {
			code = commandDiagnosticExit(diagnostic, "abandonment local cleanup incomplete", code)
		}
		if result.Delivery.PlanFailed {
			code = commandDiagnosticExit(diagnostic, "abandonment plan delivery incomplete", code)
		}
		return code
	})
}
func writeAbandonment(ctx context.Context, out io.Writer, structured bool, r compositionfull.AbandonmentResult) error {
	delivery, cancel := compositionfull.ResultDeliveryContext(ctx)
	defer cancel()
	if structured {
		return compositionfull.WriteAdministrativeJSON(delivery, out, r)
	}
	return compositionfull.WriteAdministrativeHuman(delivery, out, r)
}

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

type generatedCommandRequest struct {
	kind                            uint16
	operation, duty, attempt, inbox contract.ID
}
type generatedMutationExecutor func(context.Context, contract.ID, string, configuration.Format, generatedCommandRequest) compositionfull.ConfigurationApplyResult
type generatedListExecutor func(context.Context, contract.ID, string, configuration.Format) compositionfull.ConfigurationGeneratedListResult

func runGenerated(args []string, out, diagnostic io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return runGeneratedWithExecutors(ctx, args, out, diagnostic, executeGeneratedMutation, compositionfull.ListConfigurationGeneratedFile)
}

func runGeneratedWithExecutors(ctx context.Context, args []string, out, diagnostic io.Writer, mutate generatedMutationExecutor, list generatedListExecutor) int {
	if out == nil || diagnostic == nil {
		return 2
	}
	if handled, code := publicQueryHelp(args, out, "generated list|retire|accept-retirement-risk|cleanup [OPTIONS]\n"); handled {
		return code
	}
	if len(args) == 0 {
		return writeUnknownDispatch(nil, out, diagnostic)
	}
	var request generatedCommandRequest
	isList := args[0] == "list"
	switch args[0] {
	case "list":
	case "retire":
		request.kind = contract.OperationRetireGeneratedGeneration
	case "accept-retirement-risk":
		request.kind = contract.OperationAcceptGeneratedRetirementResidue
	case "cleanup":
		request.kind = contract.OperationCleanOwnedFailureResidue
	default:
		return writeUnknownDispatch(args[1:], out, diagnostic)
	}
	flags := flag.NewFlagSet("generated "+args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var source, format, operation, duty, attempt, inbox replacementFlag
	flags.Var(&source, "source", "")
	flags.Var(&format, "source-format", "")
	flags.Var(&operation, "operation", "")
	flags.Var(&duty, "duty", "")
	flags.Var(&attempt, "attempt", "")
	flags.Var(&inbox, "inbox", "")
	structured := bindCommandJSONFlag(flags)
	var options commandTelemetryOptions
	options.BindFlags(flags)
	usage := "generated " + args[0] + " [--source PATH] [--source-format yaml|json] [OPTIONS]\n"
	if request.kind == contract.OperationCleanOwnedFailureResidue {
		usage += "Use --operation ID to continue cleanup or --inbox ID to recheck one temporary result. Select one at a time.\n"
	}
	if handled, code := commandFlagHelp(args[1:], out, flags, usage); handled {
		return code
	}
	refuse := func() int {
		selected, _ := configurationFormat(format.value)
		if isList {
			var id contract.ID
			if _, err := rand.Read(id[:]); err != nil || id.IsZero() {
				return 2
			}
			r := compositionfull.ConfigurationGeneratedListResult{PublicGeneratedListResult: core.PublicGeneratedListResult{Context: core.ReaderOperationContext{Operation: core.GeneratedListOperation, RequestID: id}, Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}, StateResult: contract.ReaderRefused, FailureReason: contract.ReasonInvalidInput}}
			if writeGeneratedList(out, *structured, r) != nil {
				return commandDiagnosticExit(diagnostic, "generated result delivery failed", 2)
			}
		} else {
			r, err := compositionfull.NewApplyRefusal(selected)
			if err != nil || writeGeneratedMutation(out, *structured, compositionfull.ConfigurationApplyResult{PublicApplyResult: r}, request.kind) != nil {
				return commandDiagnosticExit(diagnostic, "generated result delivery failed", 2)
			}
		}
		return 2
	}
	invalid := func() int {
		return commandDiagnosticExit(diagnostic, "generated command requires exact command selectors; default source is enkv.yaml; use --source-format yaml|json for a --source without a recognized suffix", refuse())
	}
	if flags.Parse(args[1:]) != nil {
		return invalid()
	}
	paths, captured := captureCommandPaths()
	selectedSource, selected, ok := paths.source(source, format)
	if !captured {
		return commandDiagnosticExit(diagnostic, commandDirectoryUnavailable, refuse())
	}
	if !ok || len(flags.Args()) != 0 || mutate == nil || list == nil {
		return invalid()
	}
	if operation.set {
		request.operation, ok = parseID(operation.value)
		if !ok {
			return invalid()
		}
	}
	if duty.set {
		request.duty, ok = parseID(duty.value)
		if !ok {
			return invalid()
		}
	}
	if attempt.set {
		request.attempt, ok = parseID(attempt.value)
		if !ok {
			return invalid()
		}
	}
	if inbox.set {
		request.inbox, ok = parseID(inbox.value)
		if !ok {
			return invalid()
		}
	}
	switch {
	case isList:
		if operation.set || duty.set || attempt.set || inbox.set {
			return invalid()
		}
	case request.kind == contract.OperationRetireGeneratedGeneration:
		if operation.set == duty.set || attempt.set || inbox.set {
			return invalid()
		}
	case request.kind == contract.OperationAcceptGeneratedRetirementResidue:
		if operation.set || !duty.set || !attempt.set || inbox.set {
			return invalid()
		}
	case request.kind == contract.OperationCleanOwnedFailureResidue:
		if duty.set || attempt.set || operation.set && inbox.set {
			return invalid()
		}
	}
	var terminal commandTerminal
	options.terminal = &terminal
	options.directory = paths.directory
	return withCommandTelemetry(ctx, options, diagnostic, refuse, func(ctx context.Context, diagnostic io.Writer) int {
		var id contract.ID
		if _, err := rand.Read(id[:]); err != nil || id.IsZero() {
			return commandDiagnosticExit(diagnostic, "generated request identity is unavailable", 2)
		}
		if isList {
			r := list(ctx, id, selectedSource, selected)
			terminal.observe(r.Result, r.FailureReason)
			if writeGeneratedList(out, *structured, r) != nil {
				return commandDiagnosticExit(diagnostic, "generated output failed", 2)
			}
			return resultCode(r.Result)
		}
		r := mutate(ctx, id, selectedSource, selected, request)
		terminal.mutation(r.PublicApplyResult)
		if writeGeneratedMutation(out, *structured, r, request.kind) != nil {
			return commandDiagnosticExit(diagnostic, "generated output failed", 2)
		}
		return compositionfull.MutationExitCode(r.PublicApplyResult)
	})
}

func executeGeneratedMutation(ctx context.Context, id contract.ID, source string, format configuration.Format, q generatedCommandRequest) compositionfull.ConfigurationApplyResult {
	switch q.kind {
	case contract.OperationRetireGeneratedGeneration:
		if !q.operation.IsZero() {
			return compositionfull.ContinueConfigurationGeneratedRetirementFile(ctx, id, source, format, core.GeneratedRetirementContinuationRequest{OperationID: q.operation})
		}
		return compositionfull.RetireConfigurationGeneratedFile(ctx, id, source, format, core.GeneratedRetirementRequest{DutyID: q.duty})
	case contract.OperationAcceptGeneratedRetirementResidue:
		return compositionfull.AcceptConfigurationGeneratedRetirementRiskFile(ctx, id, source, format, core.GeneratedRetirementRiskRequest{DutyID: q.duty, AttemptID: q.attempt})
	case contract.OperationCleanOwnedFailureResidue:
		if !q.inbox.IsZero() {
			return compositionfull.ReleaseConfigurationGeneratedInboxFile(ctx, id, source, format, q.inbox)
		}
		if !q.operation.IsZero() {
			return compositionfull.ContinueConfigurationGeneratedCleanupFile(ctx, id, source, format, core.GeneratedCleanupContinuationRequest{OperationID: q.operation})
		}
		return compositionfull.CleanupConfigurationGeneratedFile(ctx, id, source, format)
	}
	return compositionfull.ConfigurationApplyResult{PublicApplyResult: core.PublicApplyResult{Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}}}
}

func writeGeneratedMutation(out io.Writer, structured bool, r compositionfull.ConfigurationApplyResult, operation uint16) error {
	var body []byte
	var err error
	if structured {
		body, err = r.RenderGeneratedJSON(operation)
	} else {
		body, err = r.RenderGeneratedHuman(operation)
	}
	return writeCommandResultBody(out, body, err)
}
func writeGeneratedList(out io.Writer, structured bool, r compositionfull.ConfigurationGeneratedListResult) error {
	var body []byte
	var err error
	if structured {
		body, err = r.RenderJSON()
	} else {
		body, err = r.RenderHuman()
	}
	return writeCommandResultBody(out, body, err)
}
func writeCommandResultBody(out io.Writer, body []byte, err error) error {
	if err != nil {
		return err
	}
	n, err := out.Write(body)
	if err != nil {
		return err
	}
	if n != len(body) {
		return io.ErrShortWrite
	}
	return nil
}

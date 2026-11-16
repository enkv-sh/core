package main

import (
	"context"
	"crypto/rand"
	"flag"
	"io"
	"time"
	"unicode/utf8"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

type accessMutationCommand struct {
	source      string
	output      string
	format      configuration.Format
	name        string
	reference   string
	recipientID contract.ID
}

func runEnvelopeRekey(args []string, out, diagnostic io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return runAccessMutationWithExecutor(ctx, contract.OperationEnvelopeRekey, args, out, diagnostic, executeAccessMutation)
}

func runRecipientRetirement(args []string, out, diagnostic io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return runAccessMutationWithExecutor(ctx, contract.OperationRetireRecipientIdentity, args, out, diagnostic, executeAccessMutation)
}

func executeAccessMutation(ctx context.Context, operation uint16, request contract.ID, command accessMutationCommand) compositionfull.MaintenanceCommandResult {
	switch operation {
	case contract.OperationEnvelopeRekey:
		return compositionfull.RekeyConfigurationEnvelopeFile(ctx, request, command.source, command.format, command.name, command.output)
	case contract.OperationRetireRecipientIdentity:
		return compositionfull.RetireConfigurationSelectedRecipientFile(ctx, request, command.source, command.format, compositionfull.RecipientSelector{Reference: command.reference, ID: command.recipientID}, command.output)
	}
	return compositionfull.MaintenanceCommandResult{PublicApplyResult: core.PublicApplyResult{RequestID: request, Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}}, Delivery: compositionfull.ReplacementCommandDelivery{Status: "not-attempted"}, SourceUsability: "unchecked"}
}

func runAccessMutationWithExecutor(ctx context.Context, operation uint16, args []string, out, diagnostic io.Writer,
	execute func(context.Context, uint16, contract.ID, accessMutationCommand) compositionfull.MaintenanceCommandResult) int {
	if ctx == nil || out == nil || diagnostic == nil || operation != contract.OperationEnvelopeRekey && operation != contract.OperationRetireRecipientIdentity {
		return 2
	}
	flags := flag.NewFlagSet("access mutation", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.String("source", "", "")
	output := flags.String("out", "", "")
	format := flags.String("source-format", "", "")
	var name, reference string
	var recipientID replacementFlag
	if operation == contract.OperationRetireRecipientIdentity {
		flags.StringVar(&reference, "recipient", "", "")
		flags.Var(&recipientID, "recipient-id", "exact existing recipient ID; mutually exclusive with --recipient")
	} else {
		flags.StringVar(&name, "name", "", "")
	}
	structured := bindCommandJSONFlag(flags)
	var options commandTelemetryOptions
	options.BindFlags(flags)
	commandName := "rekey"
	if operation == contract.OperationRetireRecipientIdentity {
		commandName = "recipients retire"
	}
	if handled, code := commandFlagHelp(args, out, flags, commandName+" [--source PATH] [--source-format yaml|json] --out PATH [OPTIONS]\n"); handled {
		return code
	}
	flags.VisitAll(func(f *flag.Flag) { f.Value = &localSingletonFlag{value: f.Value} })
	refuse := func() int {
		selected, _ := configurationFormat(*format)
		var result core.PublicApplyResult
		var err error
		switch operation {
		case contract.OperationEnvelopeRekey:
			result, err = compositionfull.NewEnvelopeRekeyRefusal(selected)
		case contract.OperationRetireRecipientIdentity:
			result, err = compositionfull.NewRecipientRetirementRefusal(selected)
		}
		if err != nil || writeAccessMutationResult(out, *structured, operation, compositionfull.MaintenanceCommandResult{PublicApplyResult: result, Delivery: compositionfull.ReplacementCommandDelivery{Status: "not-attempted"}, SourceUsability: "unchecked"}) != nil {
			return commandDiagnosticExit(diagnostic, "access mutation result delivery failed", 2)
		}
		return 2
	}
	invalid := func() int {
		code := refuse()
		return commandDiagnosticExit(diagnostic, "access mutation requires its exact target and --out; default source is enkv.yaml; use --source-format yaml|json for a --source without a recognized suffix", code)
	}
	parsed := flags.Parse(args)
	if parsed != nil || len(flags.Args()) != 0 || execute == nil {
		return invalid()
	}
	if operation == contract.OperationRetireRecipientIdentity {
		if _, valid := commandRecipientSelection(replacementFlag{value: reference, set: flags.Lookup("recipient").Value.(*localSingletonFlag).set}, recipientID); !valid || reference == "" && !recipientID.set {
			return invalid()
		}
	} else if !flags.Lookup("name").Value.(*localSingletonFlag).set || len(name) > contract.CryptoMaxName || !utf8.ValidString(name) {
		return invalid()
	}
	paths, captured := captureCommandPaths()
	selectedSource, selected, ok := paths.source(commandFlagValue(flags, "source"), commandFlagValue(flags, "source-format"))
	selectedOutput := paths.absolute(*output)
	if !captured {
		return commandDiagnosticExit(diagnostic, commandDirectoryUnavailable, refuse())
	}
	if !ok || !configuration.SuccessorOutputPathValid(selectedOutput) {
		return invalid()
	}
	var request contract.ID
	if _, err := rand.Read(request[:]); err != nil || request.IsZero() {
		return commandDiagnosticExit(diagnostic, "access mutation request correlation unavailable", 2)
	}
	recipientSelection := compositionfull.RecipientSelector{}
	if operation == contract.OperationRetireRecipientIdentity {
		recipientSelection, _ = commandRecipientSelection(replacementFlag{value: reference, set: flags.Lookup("recipient").Value.(*localSingletonFlag).set}, recipientID)
	}
	command := accessMutationCommand{source: selectedSource, output: selectedOutput, format: selected, name: name, reference: recipientSelection.Reference, recipientID: recipientSelection.ID}
	var terminal commandTerminal
	options.terminal = &terminal
	options.directory = paths.directory
	return withCommandTelemetry(ctx, options, diagnostic, refuse, func(ctx context.Context, diagnostic io.Writer) int {
		result := execute(ctx, operation, request, command)
		terminal.mutation(result.PublicApplyResult)
		if err := writeAccessMutationResult(out, *structured, operation, result); err != nil {
			return commandDiagnosticExit(diagnostic, "access mutation result delivery failed", 2)
		}
		code := compositionfull.MutationExitCode(result.PublicApplyResult)
		if result.Delivery.Status == "pending" || code == 3 {
			return 3
		}
		if result.Delivery.Failed || result.Delivery.CleanupFailed {
			return 2
		}
		return code
	})
}

func writeAccessMutationResult(out io.Writer, structured bool, operation uint16, result compositionfull.MaintenanceCommandResult) error {
	var body []byte
	var err error
	if structured {
		body, err = compositionfull.RenderMaintenanceCommandJSON(operation, result)
	} else {
		body, err = compositionfull.RenderMaintenanceCommandHuman(operation, result)
	}
	if err != nil {
		return err
	}
	n, err := out.Write(body)
	if err == nil && n != len(body) {
		err = io.ErrShortWrite
	}
	return err
}

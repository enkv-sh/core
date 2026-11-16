package main

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core/contract"
)

type materializationExecutor func(context.Context, contract.MaterializationRequest, string, configuration.Format, string, compositionfull.RecipientSelector) (compositionfull.ConfigurationMaterializationResult, error)

type materializationNames []string

func (n *materializationNames) String() string { return "" }
func (n *materializationNames) Set(value string) error {
	if len(*n) >= contract.CryptoMaxValueEntries || len(value) > contract.CryptoMaxName || !utf8.ValidString(value) {
		return errors.New("invalid materialization selection")
	}
	for _, name := range *n {
		if name == value {
			return errors.New("duplicate materialization name")
		}
	}
	*n = append(*n, value)
	return nil
}

func runMaterialize(args []string, out, diagnostic io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return runMaterializeWithExecutor(ctx, args, out, diagnostic, compositionfull.MaterializeConfigurationRecipientFile)
}

func runMaterializeWithExecutor(ctx context.Context, args []string, out, diagnostic io.Writer, execute materializationExecutor) int {
	if out == nil || diagnostic == nil {
		return 2
	}
	const usage = "materialize [--source PATH] [--source-format yaml|json] --name NAME [--name NAME ...] [--recipient ALIAS | --recipient-id ID] --out PATH [--json]\n"
	flags, q := bindPublicQueryFlags("materialize", "recipient")
	var names materializationNames
	var destination replacementFlag
	flags.Var(&names, "name", "")
	flags.Var(&destination, "out", "")
	if handled, code := commandFlagHelp(args, out, flags, usage); handled {
		return code
	}
	write := func(result compositionfull.ConfigurationMaterializationResult) error {
		if *q.structured {
			return result.WriteJSON(ctx, out)
		}
		return result.WriteHuman(ctx, out)
	}
	refuse := func() int {
		result, err := compositionfull.NewMaterializationRefusal(0)
		if err != nil || write(compositionfull.ConfigurationMaterializationResult{MaterializationResult: result}) != nil {
			return commandDiagnosticExit(diagnostic, "materialization result delivery failed", 2)
		}
		return 2
	}
	invalid := func() int {
		code := refuse()
		if !*q.structured {
			return commandDiagnosticExit(diagnostic, "materialize requires --name and --out; default source is enkv.yaml; use --source-format yaml|json for a --source without a recognized suffix", code)
		}
		return code
	}
	parseErr := parseUniqueCommandFlags(flags, args, "name")
	if parseErr != nil || len(flags.Args()) != 0 || len(names) == 0 || !destination.set || destination.value == "" || destination.value == "-" || execute == nil {
		return invalid()
	}
	path, format, ok := publicQuerySource(q)
	if !ok {
		return invalid()
	}
	outPath := q.paths.absolute(destination.value)
	if len(path) > contract.MaterializationMaxPath || !utf8.ValidString(path) || strings.ContainsRune(path, 0) ||
		len(outPath) > contract.MaterializationMaxPath || !utf8.ValidString(outPath) || strings.ContainsRune(outPath, 0) || path == outPath {
		return invalid()
	}
	selector, ok := commandRecipientSelection(q.selector, q.recipientID)
	if !ok {
		return invalid()
	}
	var terminal commandTerminal
	q.telemetry.terminal = &terminal
	q.telemetry.directory = q.paths.directory
	return withCommandTelemetry(ctx, q.telemetry, diagnostic, refuse, func(ctx context.Context, diagnostic io.Writer) int {
		var nonce contract.ID
		if _, err := rand.Read(nonce[:]); err != nil || nonce.IsZero() {
			return commandDiagnosticExit(diagnostic, "materialization request correlation unavailable", 2)
		}
		request, err := contract.OwnMaterializationRequest(contract.MaterializationRequest{RequestNonce: nonce, Names: names, RecipientID: selector.ID})
		if err != nil {
			return invalid()
		}
		result, sourceErr := execute(ctx, request, path, format, outPath, selector)
		terminal.observe(result.Result)
		terminal.admission(result.PreAdmission)
		if result.Failure != nil && (result.Failure.Reason == contract.MaterializationCanceled || result.Failure.Reason == contract.MaterializationDeadlineExceeded) {
			terminal.cancellation(contract.ReasonCancelled)
		}
		if err := write(result); err != nil {
			return commandDiagnosticExit(diagnostic, "materialization result delivery failed", 2)
		}
		if sourceErr != nil {
			return commandDiagnosticExit(diagnostic, "materialization source capture or close failed; retain the operation result", 2)
		}
		return compositionfull.MaterializationExitCode(result.MaterializationResult)
	})
}

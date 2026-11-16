package main

import (
	"context"
	"crypto/rand"
	"io"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core/contract"
)

type receiptListExecutor func(context.Context, contract.ID, string, configuration.Format) compositionfull.ConfigurationReceiptListResult
type receiptDetailExecutor func(context.Context, contract.ID, string, configuration.Format, contract.ID) compositionfull.ConfigurationReceiptDetailResult

func runReceipt(args []string, out, diagnostic io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return runReceiptWithExecutors(ctx, args, out, diagnostic, compositionfull.ListConfigurationReceiptsFile, compositionfull.ReadConfigurationReceiptFile)
}
func runReceiptWithExecutors(ctx context.Context, args []string, out, diagnostic io.Writer, list receiptListExecutor, detail receiptDetailExecutor) int {
	if out == nil || diagnostic == nil {
		return 2
	}
	flags, q := bindPublicQueryFlags("receipt", "operation")
	if handled, code := commandFlagHelp(args, out, flags, "receipt [--source PATH] [--source-format yaml|json] [--operation ID] [--json]\nDefault source: enkv.yaml in the current directory; explicit paths infer YAML/YML/JSON syntax unless a format overrides it.\n"); handled {
		return code
	}
	refuse := func() int {
		var err error
		if q.selector.set {
			r, e := compositionfull.NewReceiptDetailRefusal(0)
			err = e
			if err == nil {
				if *q.structured {
					err = compositionfull.WriteReceiptDetailJSON(ctx, out, r)
				} else {
					err = compositionfull.WriteReceiptDetailHuman(ctx, out, r)
				}
			}
		} else {
			r, e := compositionfull.NewReceiptListRefusal(0)
			err = e
			if err == nil {
				if *q.structured {
					err = compositionfull.WriteReceiptListJSON(ctx, out, r)
				} else {
					err = compositionfull.WriteReceiptListHuman(ctx, out, r)
				}
			}
		}
		if err != nil {
			return commandDiagnosticExit(diagnostic, "receipt result delivery failed", 2)
		}
		return 2
	}
	invalid := func() int {
		code := refuse()
		if !*q.structured {
			return commandDiagnosticExit(diagnostic, "Use enkv receipt to list retained receipts, or enkv receipt --operation ID for one exact receipt. Default source is enkv.yaml; use --source-format yaml|json for a source without a recognized suffix.", code)
		}
		return code
	}
	if parseUniqueCommandFlags(flags, args, "") != nil || len(flags.Args()) != 0 {
		return invalid()
	}
	path, format, ok := publicQuerySource(q)
	if !ok {
		return invalid()
	}
	var selected contract.ID
	if q.selector.set {
		selected, ok = parseID(q.selector.value)
		if !ok || detail == nil {
			return invalid()
		}
	} else if list == nil {
		return invalid()
	}
	var terminal commandTerminal
	q.telemetry.terminal = &terminal
	q.telemetry.directory = q.paths.directory
	return withCommandTelemetry(ctx, q.telemetry, diagnostic, refuse, func(ctx context.Context, diagnostic io.Writer) int {
		var nonce contract.ID
		if _, err := rand.Read(nonce[:]); err != nil || nonce.IsZero() {
			return commandDiagnosticExit(diagnostic, "receipt request correlation unavailable", 2)
		}
		if q.selector.set {
			r := detail(ctx, nonce, path, format, selected)
			terminal.observe(r.Result, r.FailureReason)
			var err error
			if *q.structured {
				err = r.WriteJSON(ctx, out)
			} else {
				err = r.WriteHuman(ctx, out)
			}
			if err != nil {
				return commandDiagnosticExit(diagnostic, "receipt result delivery failed", 2)
			}
			return compositionfull.PublicQueryExitCode(r.PublicQueryResult)
		}
		r := list(ctx, nonce, path, format)
		terminal.observe(r.Result, r.FailureReason)
		var err error
		if *q.structured {
			err = r.WriteJSON(ctx, out)
		} else {
			err = r.WriteHuman(ctx, out)
		}
		if err != nil {
			return commandDiagnosticExit(diagnostic, "receipt result delivery failed", 2)
		}
		return compositionfull.PublicQueryExitCode(r.PublicQueryResult)
	})
}

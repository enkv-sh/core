package main

import (
	"context"
	"crypto/rand"
	"io"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

type domainInspectionExecutor func(context.Context, contract.ID, string, configuration.Format) compositionfull.ConfigurationInspectionResult
type recipientInspectionExecutor func(context.Context, contract.ID, string, configuration.Format, compositionfull.RecipientSelector) compositionfull.ConfigurationRecipientInspectionResult
type capacityInspectionExecutor func(context.Context, core.CapacityInspectionRequest, string, configuration.Format) compositionfull.ConfigurationCapacityResult

func runInspect(args []string, out, diagnostic io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return runInspectWithExecutors(ctx, args, out, diagnostic, compositionfull.InspectConfigurationFile, compositionfull.InspectConfigurationSelectedRecipientFile, compositionfull.InspectConfigurationCapacityFile)
}
func runInspectWithExecutors(ctx context.Context, args []string, out, diagnostic io.Writer, domain domainInspectionExecutor, recipient recipientInspectionExecutor, capacity capacityInspectionExecutor) int {
	if out == nil || diagnostic == nil {
		return 2
	}
	flags, q := bindPublicQueryFlags("inspect", "recipient")
	capacityMode := flags.Bool("capacity", false, "")
	var cursor replacementFlag
	flags.Var(&cursor, "cursor", "")
	if handled, code := commandFlagHelp(args, out, flags, "inspect [--source PATH] [--source-format yaml|json] [--recipient ALIAS | --recipient-id ID | --capacity [--cursor TOKEN]] [--json]\nDefault source: enkv.yaml in the current directory; explicit paths infer YAML/YML/JSON syntax unless a format overrides it.\n"); handled {
		return code
	}
	refuse := func() int {
		var err error
		if *capacityMode {
			r, e := compositionfull.NewCapacityInspectionRefusal(0)
			err = e
			if err == nil {
				if *q.structured {
					err = compositionfull.WriteCapacityInspectionJSON(ctx, out, r)
				} else {
					err = compositionfull.WriteCapacityInspectionHuman(ctx, out, r)
				}
			}
		} else if q.selector.set || q.recipientID.set {
			r, e := compositionfull.NewRecipientInspectionRefusal(0)
			err = e
			if err == nil {
				if *q.structured {
					err = compositionfull.WriteRecipientInspectionJSON(ctx, out, r)
				} else {
					err = compositionfull.WriteRecipientInspectionHuman(ctx, out, r)
				}
			}
		} else {
			r, e := compositionfull.NewDomainInspectionRefusal(0)
			err = e
			if err == nil {
				if *q.structured {
					err = compositionfull.WriteInspectionJSON(ctx, out, r)
				} else {
					err = compositionfull.WriteInspectionHuman(ctx, out, r)
				}
			}
		}
		if err != nil {
			return commandDiagnosticExit(diagnostic, "inspection result delivery failed", 2)
		}
		return 2
	}
	invalid := func() int {
		code := refuse()
		if !*q.structured {
			return commandDiagnosticExit(diagnostic, "inspect accepts --recipient ALIAS, --recipient-id ID or --capacity; default source is enkv.yaml; use --source-format yaml|json for a source without a recognized suffix", code)
		}
		return code
	}
	parseErr := parseUniqueCommandFlags(flags, args, "")
	if parseErr != nil || len(flags.Args()) != 0 {
		return invalid()
	}
	path, format, ok := publicQuerySource(q)
	if !ok {
		return invalid()
	}
	if *capacityMode && ((q.selector.set || q.recipientID.set) || capacity == nil) || cursor.set && (!*capacityMode || cursor.value == "" || len(cursor.value) > core.GCCursorMaxLength) {
		return invalid()
	}
	selected, ok := commandRecipientSelection(q.selector, q.recipientID)
	if !ok || (q.selector.set || q.recipientID.set) && recipient == nil {
		return invalid()
	}
	if !q.selector.set && !q.recipientID.set && !*capacityMode && domain == nil {
		return invalid()
	}
	var terminal commandTerminal
	q.telemetry.terminal = &terminal
	q.telemetry.directory = q.paths.directory
	return withCommandTelemetry(ctx, q.telemetry, diagnostic, refuse, func(ctx context.Context, diagnostic io.Writer) int {
		var nonce contract.ID
		if _, err := rand.Read(nonce[:]); err != nil || nonce.IsZero() {
			return commandDiagnosticExit(diagnostic, "inspection request correlation unavailable", 2)
		}
		if *capacityMode {
			r := capacity(ctx, core.CapacityInspectionRequest{RequestNonce: nonce, Cursor: cursor.value}, path, format)
			terminal.observe(r.Result, r.FailureReason)
			var err error
			if *q.structured {
				err = r.WriteJSON(ctx, out)
			} else {
				err = r.WriteHuman(ctx, out)
			}
			if err != nil {
				return commandDiagnosticExit(diagnostic, "capacity result delivery failed", 2)
			}
			return compositionfull.PublicQueryExitCode(r.PublicQueryResult)
		}
		if q.selector.set || q.recipientID.set {
			r := recipient(ctx, nonce, path, format, selected)
			terminal.observe(r.Result, r.FailureReason)
			var err error
			if *q.structured {
				err = r.WriteJSON(ctx, out)
			} else {
				err = r.WriteHuman(ctx, out)
			}
			if err != nil {
				return commandDiagnosticExit(diagnostic, "inspection result delivery failed", 2)
			}
			return compositionfull.PublicQueryExitCode(r.PublicQueryResult)
		}
		r := domain(ctx, nonce, path, format)
		terminal.observe(r.Result, r.FailureReason)
		var err error
		if *q.structured {
			err = r.WriteJSON(ctx, out)
		} else {
			err = r.WriteHuman(ctx, out)
		}
		if err != nil {
			return commandDiagnosticExit(diagnostic, "inspection result delivery failed", 2)
		}
		return compositionfull.PublicQueryExitCode(r.PublicQueryResult)
	})
}

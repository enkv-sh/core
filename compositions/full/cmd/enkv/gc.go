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

type gcPlanExecutor func(context.Context, compositionfull.GCPlanRequest, string, configuration.Format) compositionfull.GCPlanResult
type gcApplyExecutor func(context.Context, compositionfull.GCApplyRequest, string, configuration.Format) compositionfull.GCApplyResult

func runGC(args []string, out, diagnostic io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return runGCWithExecutors(ctx, args, out, diagnostic, compositionfull.PlanConfigurationGCFile, compositionfull.ApplyConfigurationGCFile)
}

func runGCWithExecutors(ctx context.Context, args []string, out, diagnostic io.Writer, plan gcPlanExecutor, apply gcApplyExecutor) int {
	if out == nil || diagnostic == nil {
		return 2
	}
	help := "gc plan [--source PATH] [--source-format yaml|json] --out PATH [--cursor TOKEN] [--json]\ngc apply [--source PATH] [--source-format yaml|json] --plan PATH [--json]\ngc apply [--source PATH] [--source-format yaml|json] --operation ID [--json]\n"
	if len(args) == 0 {
		n, err := io.WriteString(out, help)
		if err != nil || n != len(help) {
			return 2
		}
		return 0
	}
	if handled, code := publicQueryHelp(args, out, help); handled {
		return code
	}
	form := args[0]
	if form != "plan" && form != "apply" {
		return writeUnknownDispatch(args[1:], out, diagnostic)
	}
	flags, q := bindPublicQueryFlags("gc "+form, "operation")
	var artifact, input, cursor replacementFlag
	flags.Var(&artifact, "out", "")
	flags.Var(&input, "plan", "")
	flags.Var(&cursor, "cursor", "")
	if handled, code := commandFlagHelp(args[1:], out, flags, help); handled {
		return code
	}
	refuse := func() int {
		var err error
		if form == "plan" {
			r, e := compositionfull.NewGCPlanRefusal(0)
			err = e
			if err == nil {
				delivery, cancel := compositionfull.ResultDeliveryContext(ctx)
				defer cancel()
				if *q.structured {
					err = compositionfull.WriteGCPlanJSON(delivery, out, r)
				} else {
					err = compositionfull.WriteGCPlanHuman(delivery, out, r)
				}
			}
		} else {
			r, e := compositionfull.NewGCApplyRefusal(0)
			err = e
			if err == nil {
				delivery, cancel := compositionfull.ResultDeliveryContext(ctx)
				defer cancel()
				if *q.structured {
					err = compositionfull.WriteGCApplyJSON(delivery, out, r)
				} else {
					err = compositionfull.WriteGCApplyHuman(delivery, out, r)
				}
			}
		}
		if err != nil {
			return commandDiagnosticExit(diagnostic, "GC result delivery failed", 2)
		}
		return 2
	}
	invalid := func() int {
		code := refuse()
		if !*q.structured {
			return commandDiagnosticExit(diagnostic, "gc requires exactly its command inputs; default source is enkv.yaml; use --source-format yaml|json for a --source without a recognized suffix", code)
		}
		return code
	}
	parseErr := parseUniqueCommandFlags(flags, args[1:], "")
	if parseErr != nil || len(flags.Args()) != 0 {
		return invalid()
	}
	source, format, ok := publicQuerySource(q)
	if !ok {
		return invalid()
	}
	var operation contract.ID
	var outputPath, planPath string
	if form == "plan" {
		if plan == nil || !artifact.set || artifact.value == "" || input.set || q.selector.set || cursor.set && (cursor.value == "" || len(cursor.value) > core.GCCursorMaxLength) {
			return invalid()
		}
		outputPath = q.paths.absolute(artifact.value)
		if outputPath == source {
			return invalid()
		}
	} else {
		if apply == nil || artifact.set || cursor.set || input.set == q.selector.set {
			return invalid()
		}
		if input.set {
			if input.value == "" {
				return invalid()
			}
			planPath = q.paths.absolute(input.value)
			if planPath == source {
				return invalid()
			}
		} else {
			operation, ok = parseID(q.selector.value)
			if !ok {
				return invalid()
			}
		}
	}
	var terminal commandTerminal
	q.telemetry.terminal = &terminal
	q.telemetry.directory = q.paths.directory
	return withCommandTelemetry(ctx, q.telemetry, diagnostic, refuse, func(ctx context.Context, diagnostic io.Writer) int {
		var nonce contract.ID
		if _, err := rand.Read(nonce[:]); err != nil || nonce.IsZero() {
			return commandDiagnosticExit(diagnostic, "GC request correlation unavailable", 2)
		}
		if form == "plan" {
			var proposed contract.ID
			if _, err := rand.Read(proposed[:]); err != nil || proposed.IsZero() {
				return commandDiagnosticExit(diagnostic, "GC operation correlation unavailable", 2)
			}
			r := plan(ctx, compositionfull.GCPlanRequest{RequestNonce: nonce, OperationID: proposed, Cursor: cursor.value, ArtifactPath: outputPath}, source, format)
			terminal.observe(r.Operation.Result, r.Operation.FailureReason)
			delivery, cancel := compositionfull.ResultDeliveryContext(ctx)
			defer cancel()
			var err error
			if *q.structured {
				err = compositionfull.WriteGCPlanJSON(delivery, out, r)
			} else {
				err = compositionfull.WriteGCPlanHuman(delivery, out, r)
			}
			if err != nil {
				return commandDiagnosticExit(diagnostic, "GC preview result delivery failed", 2)
			}
			return compositionfull.GCPlanExitCode(r)
		}
		r := apply(ctx, compositionfull.GCApplyRequest{RequestNonce: nonce, PlanPath: planPath, OperationID: operation}, source, format)
		terminal.observe(r.Operation.Result)
		terminal.admission(r.PreAdmission)
		delivery, cancel := compositionfull.ResultDeliveryContext(ctx)
		defer cancel()
		var err error
		if *q.structured {
			err = compositionfull.WriteGCApplyJSON(delivery, out, r)
		} else {
			err = compositionfull.WriteGCApplyHuman(delivery, out, r)
		}
		if err != nil {
			return commandDiagnosticExit(diagnostic, "GC apply result delivery failed", 2)
		}
		return compositionfull.GCApplyExitCode(r)
	})
}

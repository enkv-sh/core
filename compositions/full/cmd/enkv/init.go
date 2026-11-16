package main

import (
	"context"
	"flag"
	"io"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
)

func runInit(args []string, out, diagnostic io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return runInitWithInitializer(ctx, args, out, diagnostic, compositionfull.InitializeConfiguration)
}

func runInitWithInitializer(ctx context.Context, args []string, out, diagnostic io.Writer,
	initialize func(context.Context, string, configuration.Format) (compositionfull.InitializationResult, error)) int {
	if out == nil || diagnostic == nil || initialize == nil {
		return 2
	}
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.String("source", "", "")
	format := flags.String("source-format", "", "")
	structured := bindCommandJSONFlag(flags)
	var telemetryOptions commandTelemetryOptions
	telemetryOptions.BindFlags(flags)
	if handled, code := commandFlagHelp(args, out, flags, "init [--source PATH] [--source-format yaml|json] [OPTIONS]\n"); handled {
		return code
	}
	refuse := func() int {
		selected, _ := configurationFormat(*format)
		result, err := compositionfull.NewInitializationRefusal(selected)
		if err != nil || writeInitializationResult(out, *structured, result, nil) != nil {
			return commandDiagnosticExit(diagnostic, "init result is unavailable", 2)
		}
		return 2
	}
	badInput := func() int {
		code := refuse()
		return commandDiagnosticExit(diagnostic, "init arguments refused; default source is enkv.yaml; use --source-format yaml|json for a --source without a recognized suffix", code)
	}
	if flags.Parse(args) != nil || len(flags.Args()) != 0 {
		return badInput()
	}
	paths, captured := captureCommandPaths()
	selectedSource, selectedFormat, ok := paths.source(commandFlagValue(flags, "source"), commandFlagValue(flags, "source-format"))
	if !captured {
		return commandDiagnosticExit(diagnostic, commandDirectoryUnavailable, refuse())
	}
	if !ok {
		return badInput()
	}
	var terminal commandTerminal
	telemetryOptions.terminal = &terminal
	telemetryOptions.directory = paths.directory
	return withCommandTelemetry(ctx, telemetryOptions, diagnostic, refuse, func(ctx context.Context, diagnostic io.Writer) int {
		result, deliveryErr := initialize(ctx, selectedSource, selectedFormat)
		terminal.observe(result.Result)
		terminal.admission(result.PreAdmission)
		if err := writeInitializationResult(out, *structured, result, deliveryErr); err != nil {
			return commandDiagnosticExit(diagnostic, "init output failed; retain the pair and any saved local transaction", 2)
		}
		if deliveryErr != nil && result.DeliveryAttempted {
			return commandDiagnosticExit(diagnostic, "init local delivery is incomplete; inspect local_delivery for recovery instructions", compositionfull.InitializationExitCode(result, deliveryErr))
		}
		return compositionfull.InitializationExitCode(result, deliveryErr)
	})
}

func writeInitializationResult(out io.Writer, structured bool, result compositionfull.InitializationResult, deliveryErr error) error {
	var body []byte
	var err error
	if structured {
		body, err = compositionfull.RenderInitializationJSON(result, deliveryErr)
	} else {
		body, err = compositionfull.RenderInitializationHuman(result, deliveryErr)
	}
	if err != nil {
		return err
	}
	if written, err := out.Write(body); err != nil {
		return err
	} else if written != len(body) {
		return io.ErrShortWrite
	}
	return nil
}

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
)

func runSet(args []string, input io.ReadCloser, out, diagnostic io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return runSetContext(ctx, args, input, out, diagnostic)
}
func runSetContext(ctx context.Context, args []string, input io.ReadCloser, out, diagnostic io.Writer) int {
	return runSetWithSetter(ctx, args, input, out, diagnostic, compositionfull.SetConfiguration)
}
func runSetWithSetter(ctx context.Context, args []string, input io.ReadCloser, out, diagnostic io.Writer,
	set func(context.Context, string, configuration.Format, string, io.ReadCloser, compositionfull.SetOptions) (*compositionfull.SetResult, error)) (code int) {
	transferred := false
	defer func() {
		if input != nil && !transferred {
			if err := input.Close(); err != nil {
				code = 2
				if diagnostic != nil {
					code = commandDiagnosticExit(diagnostic, "set input cleanup failed", code)
				}
			}
		}
	}()
	if input == nil || out == nil || diagnostic == nil || set == nil {
		return 2
	}
	flags := flag.NewFlagSet("set", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.String("source", "", "")
	flags.String("source-format", "", "")
	name := flags.String("name", "", "")
	confidential := flags.Bool("confidential", true, "")
	encoded := flags.Bool("base64", false, "")
	structured := bindCommandJSONFlag(flags)
	var options commandTelemetryOptions
	options.BindFlags(flags)
	if handled, code := commandFlagHelp(args, out, flags, "set [--source PATH] [--source-format yaml|json] --name NAME [OPTIONS]\n"); handled {
		return code
	}
	refuse := func() int {
		result, err := compositionfull.NewSetRefusal(*confidential)
		if err != nil || writeSetResponse(out, *structured, result, nil) != nil {
			return commandDiagnosticExit(diagnostic, "set result is unavailable", 2)
		}
		return 2
	}
	badInput := func() int {
		code := refuse()
		return commandDiagnosticExit(diagnostic, "set requires --name; default source is enkv.yaml; use --source-format yaml|json for a --source without a recognized suffix", code)
	}
	if flags.Parse(args) != nil || len(flags.Args()) != 0 {
		return badInput()
	}
	namePresent := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "name" {
			namePresent = true
		}
	})
	paths, captured := captureCommandPaths()
	selectedSource, selectedFormat, ok := paths.source(commandFlagValue(flags, "source"), commandFlagValue(flags, "source-format"))
	if !captured {
		return commandDiagnosticExit(diagnostic, commandDirectoryUnavailable, refuse())
	}
	if !ok || !namePresent {
		return badInput()
	}
	var terminal commandTerminal
	options.terminal = &terminal
	options.directory = paths.directory
	return withCommandTelemetry(ctx, options, diagnostic, refuse, func(ctx context.Context, diagnostic io.Writer) int {
		transferred = true
		result, err := set(ctx, selectedSource, selectedFormat, *name, input, compositionfull.SetOptions{Confidential: *confidential, Base64: *encoded})
		terminal.result = result.TelemetryResult(err)
		if writeSetResponse(out, *structured, result, err) != nil {
			return commandDiagnosticExit(diagnostic, "set output failed; retain the pair and any saved local transaction", 2)
		}
		if err != nil {
			var sourceFailure *configuration.Diagnostic
			message := "set did not complete; inspect the result before further action"
			switch {
			case result != nil && result.EditablePath != "" && result.StateResult == compositionfull.SetSuccess:
				message = "set local cleanup failed; exact pair readback was confirmed"
			case errors.As(err, &sourceFailure) && sourceFailure.Reason == "restore-exact-generated-file" && errors.Is(err, configuration.ErrSourceImageMissing):
				message = "Restore the exact generated JSON file referenced by the configuration. Do not create a new file or search old versions automatically."
			case errors.As(err, &sourceFailure) && configuration.DiagnosticFieldValid(sourceFailure.Field) && configuration.DiagnosticReasonValid(sourceFailure.Reason):
				message = sourceFailure.Error()
			}
			return commandDiagnosticExit(diagnostic, message, compositionfull.SetExitCode(result, err))
		}
		return compositionfull.SetExitCode(result, err)
	})
}
func writeSetResponse(out io.Writer, structured bool, result *compositionfull.SetResult, resultErr error) error {
	var body []byte
	var err error
	if structured {
		body, err = compositionfull.RenderSetJSON(result, resultErr)
	} else {
		body, err = compositionfull.RenderSetHuman(result, resultErr)
	}
	if err != nil {
		return err
	}
	if n, err := out.Write(body); err != nil || n != len(body) {
		return errors.Join(err, io.ErrShortWrite)
	}
	return nil
}

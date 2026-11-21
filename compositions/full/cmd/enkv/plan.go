package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"io"
	"os"
	"time"
	"unicode/utf8"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func runPlan(args []string, out, diagnostic io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return runPlanContext(ctx, args, out, diagnostic)
}

func runPlanContext(ctx context.Context, args []string, out, diagnostic io.Writer) (code int) {
	if out == nil || diagnostic == nil {
		return 2
	}
	flags := flag.NewFlagSet("plan", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.String("trusted", "", "")
	format := flags.String("trusted-format", "", "")
	var candidate, candidateFormat replacementFlag
	flags.Var(&candidate, "candidate", "")
	flags.Var(&candidateFormat, "candidate-format", "")
	structured := bindCommandJSONFlag(flags)
	checkSecrets := flags.Bool("check-secrets", false, "")
	publish := flags.Bool("publish", false, "")
	var selectedNames planSecretNames
	flags.Var(&selectedNames, "show-secret", "")
	var telemetryOptions commandTelemetryOptions
	telemetryOptions.BindFlags(flags)
	if handled, code := commandFlagHelp(args, out, flags, "plan [--trusted PATH] [--trusted-format yaml|json] [OPTIONS]\n"); handled {
		return code
	}
	refuse := func() int {
		selected, _ := configurationFormat(*format)
		result, err := compositionfull.NewComparisonRefusal(selected)
		if *publish {
			result.PublicationRequested = true
			result.Publication = &contract.PublicationPreview{ReasonCode: uint8(core.AdmissionInvalid)}
		}
		if err != nil || writeComparisonResult(out, *structured, result) != nil {
			return commandDiagnosticExit(diagnostic, "plan result is unavailable", 2)
		}
		return 2
	}
	badInput := func() int {
		code := refuse()
		return commandDiagnosticExit(diagnostic, "plan requires valid source selections; trusted source defaults to enkv.yaml; use --trusted-format or --candidate-format yaml|json for an explicit path without a recognized suffix", code)
	}
	parseErr := flags.Parse(args)
	badArguments := parseErr != nil || len(flags.Args()) != 0
	paths, captured := captureCommandPaths()
	selectedTrusted, selectedFormat, trustedOK := paths.source(commandFlagValue(flags, "trusted"), commandFlagValue(flags, "trusted-format"))
	selectedCandidate, selectedCandidateFormat, candidateOK := paths.candidate(candidate, candidateFormat)
	var sources planDisplaySources
	if len(selectedNames) != 0 || parseErr != nil && mayRequestPlanDisplay(args, flags.Args()) {
		stdout, stderr := holdPlanStream(out), holdPlanStream(diagnostic)
		defer func() {
			if err := errors.Join(sources.close(), stderr.close(), stdout.close()); err != nil {
				code = 2
			}
		}()
		complete := false
		if (stdout.regular() || stderr.regular()) && !badArguments && captured && trustedOK && candidateOK {
			complete = sources.capture(ctx, selectedTrusted, selectedFormat, selectedCandidate, selectedCandidateFormat)
		}
		stdoutOK := stdout.allowed(sources.trusted, sources.candidate, complete)
		stderrOK := stderr.allowed(sources.trusted, sources.candidate, complete)
		out, diagnostic = stdout.writer, stderr.writer
		if !stdoutOK || !stderrOK {
			if stdoutOK {
				diagnostic = io.Discard
				return refuse()
			}
			if stderrOK {
				return commandDiagnosticExit(diagnostic, "plan output could not be separated from its configuration files", 2)
			}
			return 2
		}
	}
	if badArguments {
		return badInput()
	}
	if len(selectedNames) != 0 && !*checkSecrets {
		return badInput()
	}
	seen := map[string]bool{}
	for _, name := range selectedNames {
		if seen[name] || len(name) > contract.CryptoMaxName || !utf8.ValidString(name) {
			return badInput()
		}
		seen[name] = true
	}
	if len(selectedNames) > contract.CryptoMaxValueEntries {
		return badInput()
	}
	if !captured {
		return commandDiagnosticExit(diagnostic, commandDirectoryUnavailable, refuse())
	}
	if !trustedOK || !candidateOK {
		return badInput()
	}
	var terminal commandTerminal
	telemetryOptions.terminal = &terminal
	telemetryOptions.directory = paths.directory
	telemetryOptions.differenceIsSuccess = true
	return withCommandTelemetry(ctx, telemetryOptions, diagnostic, refuse, func(ctx context.Context, diagnostic io.Writer) int {
		if *checkSecrets {
			return executePrivatePlan(ctx, selectedTrusted, selectedFormat, selectedCandidate, selectedCandidateFormat, *structured, selectedNames, sources, out, diagnostic, &terminal, *publish)
		}
		return executePlan(ctx, selectedTrusted, selectedFormat, selectedCandidate, selectedCandidateFormat, *structured, out, diagnostic, &terminal, *publish)
	})
}

func executePlan(ctx context.Context, trusted string, format configuration.Format, candidate string,
	candidateFormat configuration.Format, structured bool, out, diagnostic io.Writer, terminal *commandTerminal, publish ...bool) int {
	var requestID contract.ID
	if _, err := rand.Read(requestID[:]); err != nil || requestID.IsZero() {
		return commandDiagnosticExit(diagnostic, "plan request identity is unavailable", 2)
	}
	result := compositionfull.CompareConfigurationFiles(ctx, requestID, trusted, format, candidate, candidateFormat, contract.ComparisonOptions{Publish: len(publish) == 1 && publish[0]})
	terminal.observe(result.Result)
	terminal.admission(result.PreAdmission)
	terminal.diagnostics(result.Diagnostics)
	if err := writeComparisonResult(out, structured, result); err != nil {
		return commandDiagnosticExit(diagnostic, "plan output failed", 2)
	}
	code := compositionfull.ComparisonExitCode(result)
	if result.SourceFailure != nil && result.SourceFailure.Reason == "restore-exact-generated-file" {
		return commandDiagnosticExit(diagnostic, "Restore the exact generated JSON file referenced by the configuration, or run explicit configuration preparation.", code)
	}
	return code
}

func writeComparisonResult(out io.Writer, structured bool, result compositionfull.ConfigurationComparisonResult) error {
	var body []byte
	var err error
	if structured {
		body, err = compositionfull.RenderComparisonJSON(result)
	} else {
		body, err = compositionfull.RenderComparisonHuman(result)
	}
	if err != nil {
		return err
	}
	if written, err := out.Write(body); err != nil {
		return err
	} else if written != len(body) {
		return io.ErrShortWrite
	}
	if structured {
		if written, err := out.Write([]byte{'\n'}); err != nil {
			return err
		} else if written != 1 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func configurationFormat(value string) (configuration.Format, bool) {
	switch value {
	case "yaml":
		return configuration.YAML, true
	case "json":
		return configuration.JSON, true
	}
	return 0, false
}

type planSecretNames []string

func (n *planSecretNames) String() string         { return "" }
func (n *planSecretNames) Set(value string) error { *n = append(*n, value); return nil }

func executePrivatePlan(ctx context.Context, trusted string, format configuration.Format, candidate string, candidateFormat configuration.Format, structured bool, names []string, sources planDisplaySources, out, diagnostic io.Writer, terminal *commandTerminal, publish ...bool) int {
	var requestID contract.ID
	if _, err := rand.Read(requestID[:]); err != nil || requestID.IsZero() {
		return commandDiagnosticExit(diagnostic, "plan request identity is unavailable", 2)
	}
	var result compositionfull.ConfigurationPlanningResult
	if len(names) != 0 {
		native, ok := out.(*os.File)
		if !ok {
			return commandDiagnosticExit(diagnostic, "plan display requires an admitted native output", 2)
		}
		factory, err := compositionfull.NewPlanningDisplayFile(native, structured)
		if err != nil {
			return commandDiagnosticExit(diagnostic, "plan display is unavailable", 2)
		}
		preview := contract.ComparisonOptions{Publish: len(publish) == 1 && publish[0]}
		if sources.trusted != nil {
			result = compositionfull.DisplayConfiguration(ctx, requestID, sources.trusted, sources.candidate, names, factory, preview)
		} else {
			result = compositionfull.DisplayConfigurationFiles(ctx, requestID, trusted, format, candidate, candidateFormat, names, factory, preview)
		}
	} else {
		result = compositionfull.PlanConfigurationFiles(ctx, requestID, trusted, format, candidate, candidateFormat, contract.PlanningOptions{Purpose: contract.PlanningEquality, Publish: len(publish) == 1 && publish[0]})
	}
	terminal.observe(result.Result)
	terminal.admission(result.PreAdmission)
	terminal.diagnostics(result.Diagnostics)
	return writePlanningOutcome(ctx, result, structured, len(names) != 0, out, diagnostic)
}
func writePlanningOutcome(ctx context.Context, result compositionfull.ConfigurationPlanningResult, structured, display bool, out, diagnostic io.Writer) int {
	return writePlanningOutcomeWithOutput(ctx, result, structured, display, func(ctx context.Context, body []byte) error {
		native, ok := out.(*os.File)
		if !ok {
			return io.ErrClosedPipe
		}
		if display {
			return result.WriteDisplayResult(ctx, native, body)
		}
		return compositionfull.WritePlanningResult(ctx, native, body)
	}, diagnostic)
}
func writePlanningOutcomeWithOutput(ctx context.Context, result compositionfull.ConfigurationPlanningResult, structured, display bool, write func(context.Context, []byte) error, diagnostic io.Writer) int {
	code := compositionfull.PlanningExitCode(result)
	if display && result.DisplayDelivery != contract.PlanningDeliveryComplete {
		return commandDiagnosticExit(diagnostic, "plan display incomplete", code)
	}
	var body []byte
	var err error
	if structured {
		body, err = compositionfull.RenderPlanningCommandJSON(result)
	} else {
		body, err = compositionfull.RenderPlanningHuman(result)
	}
	if err != nil {
		return commandDiagnosticExit(diagnostic, "plan result is unavailable", 2)
	}
	if err := write(ctx, body); err != nil {
		return commandDiagnosticExit(diagnostic, "plan output failed", 2)
	}
	return code
}

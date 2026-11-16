package main

import (
	"context"
	"crypto/rand"
	"flag"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/sdk/artifact"
	"enkv.sh/telemetry"
)

func runApply(args []string, out, diagnostic io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return runApplyContext(ctx, args, out, diagnostic)
}

type applyCommandExecutor func(context.Context, contract.ID, string, configuration.Format, contract.ID, compositionfull.ApplyOptions) compositionfull.ConfigurationApplyResult

type applyPublicationCommandExecutor func(context.Context, contract.ID, contract.ID, string, configuration.Format, contract.ID, compositionfull.ApplyPublicationOptions, compositionfull.ApplyOptions) compositionfull.ConfigurationApplyPublicationResult

func runApplyContext(ctx context.Context, args []string, out, diagnostic io.Writer) int {
	return runApplyWithExecutors(ctx, args, out, diagnostic, executeConfigurationApply, executeConfigurationApplyPublication)
}

func runApplyWithExecutor(ctx context.Context, args []string, out, diagnostic io.Writer, execute applyCommandExecutor) int {
	return runApplyWithExecutors(ctx, args, out, diagnostic, execute, executeConfigurationApplyPublication)
}

func runApplyWithExecutors(ctx context.Context, args []string, out, diagnostic io.Writer, execute applyCommandExecutor, executePublication applyPublicationCommandExecutor) int {
	if out == nil || diagnostic == nil {
		return 2
	}
	flags := flag.NewFlagSet("apply", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var source, format, operation replacementFlag
	flags.Var(&source, "source", "")
	flags.Var(&format, "source-format", "")
	flags.Var(&operation, "operation", "")
	structured := bindCommandJSONFlag(flags)
	publish := flags.Bool("publish", false, "")
	var republish, retirement, deletes publicationFlag
	flags.Var(&retirement, "retire-generator", "")
	flags.Var(&republish, "republish-after-unknown", "")
	flags.Var(&deletes, "delete-coordinate", "")
	var options commandTelemetryOptions
	options.BindFlags(flags)
	if handled, code := commandFlagHelp(args, out, flags, "apply [--source PATH] [--source-format yaml|json] [OPTIONS]\n"); handled {
		return code
	}
	refuse := func() int {
		selected, _ := configurationFormat(format.value)
		result, err := compositionfull.NewApplyRefusal(selected)
		if err != nil {
			return commandDiagnosticExit(diagnostic, "apply result is unavailable", 2)
		}
		if *publish {
			err = writeApplyPublicationResult(out, *structured, compositionfull.ConfigurationApplyPublicationResult{PublicApplyPublicationResult: core.PublicApplyPublicationResult{Apply: result, Publication: core.ApplyPublicationStage{Stage: "unstarted", Reason: "apply-incomplete"}}})
		} else {
			err = writeApplyResult(out, *structured, compositionfull.ConfigurationApplyResult{PublicApplyResult: result})
		}
		if err != nil {
			return commandDiagnosticExit(diagnostic, "apply result is unavailable", 2)
		}
		return 2
	}
	invalid := func() int {
		code := refuse()
		return commandDiagnosticExit(diagnostic, "apply arguments refused; default source is enkv.yaml; use --source-format yaml|json for a --source without a recognized suffix", code)
	}
	if flags.Parse(args) != nil {
		for _, arg := range args {
			if arg == "--publish" || arg == "--publish=true" {
				*publish = true
			}
		}
		return invalid()
	}
	if len(flags.Args()) != 0 || *publish && executePublication == nil || !*publish && (execute == nil || len(republish) != 0 || len(deletes) != 0) || len(republish) > contract.MaxPublicationMarkers {
		return invalid()
	}
	paths, captured := captureCommandPaths()
	selectedSource, selected, ok := paths.source(source, format)
	if !captured {
		return commandDiagnosticExit(diagnostic, commandDirectoryUnavailable, refuse())
	}
	if !ok {
		return invalid()
	}
	var operationID contract.ID
	if operation.set {
		operationID, ok = parseID(operation.value)
		if !ok {
			return invalid()
		}
	}
	applyOptions := compositionfull.ApplyOptions{}
	if len(retirement) > contract.GeneratedCurrentEntryLimit || operation.set && len(retirement) != 0 {
		return invalid()
	}
	if len(retirement) != 0 {
		applyOptions.RetirementPlugins = make(map[string]string, len(retirement))
	}
	for _, choice := range retirement {
		split := strings.LastIndexByte(choice, '=')
		if split < 0 {
			return invalid()
		}
		name, plugin := choice[:split], choice[split+1:]
		if !utf8.ValidString(name) || len(name) > contract.CryptoMaxName || !artifact.ValidPluginID(plugin) {
			return invalid()
		}
		if _, exists := applyOptions.RetirementPlugins[name]; exists {
			return invalid()
		}
		applyOptions.RetirementPlugins[name] = plugin
	}
	republishIDs := make([]contract.ID, 0, len(republish))
	seen := make(map[contract.ID]bool, len(republish))
	for _, text := range republish {
		id, valid := parseID(text)
		if !valid || seen[id] {
			return invalid()
		}
		seen[id] = true
		republishIDs = append(republishIDs, id)
	}
	_, deletePlugins, ok := parsePublicationDeletionChoices(deletes)
	if !ok {
		return invalid()
	}
	var terminal commandTerminal
	options.terminal = &terminal
	options.directory = paths.directory
	return withCommandTelemetry(ctx, options, diagnostic, refuse, func(ctx context.Context, diagnostic io.Writer) int {
		if *publish {
			return executeApplyPublicationCommand(ctx, selectedSource, selected, operationID, compositionfull.ApplyPublicationOptions{RepublishAfterUnknown: republishIDs, DeletePlugins: deletePlugins}, applyOptions, *structured, out, diagnostic, executePublication, &terminal)
		}
		return executeApplyCommand(ctx, selectedSource, selected, operationID, applyOptions, *structured, out, diagnostic, execute, &terminal)
	})
}

func executeConfigurationApply(ctx context.Context, request contract.ID, path string, format configuration.Format, operation contract.ID, options compositionfull.ApplyOptions) compositionfull.ConfigurationApplyResult {
	if !operation.IsZero() {
		return compositionfull.ContinueConfigurationApplyFile(ctx, request, path, format, operation)
	}
	return compositionfull.ApplyConfigurationFile(ctx, request, path, format, options)
}

func executeApplyCommand(ctx context.Context, path string, format configuration.Format, operation contract.ID, options compositionfull.ApplyOptions, structured bool, out, diagnostic io.Writer, execute applyCommandExecutor, terminal *commandTerminal) int {
	var request contract.ID
	if _, err := rand.Read(request[:]); err != nil || request.IsZero() {
		return commandDiagnosticExit(diagnostic, "apply request identity is unavailable", 2)
	}
	result := execute(ctx, request, path, format, operation, options)
	terminal.mutation(result.PublicApplyResult)
	if err := writeApplyResult(out, structured, result); err != nil {
		return commandDiagnosticExit(diagnostic, "apply output failed", 2)
	}
	code := compositionfull.MutationExitCode(result.PublicApplyResult)
	if result.SourceFailure != nil && result.SourceFailure.Reason == "restore-exact-generated-file" {
		return commandDiagnosticExit(diagnostic, "Restore the exact generated JSON file referenced by the configuration. Use set to prepare a supplied secret before apply.", code)
	}
	return code
}

func writeApplyResult(out io.Writer, structured bool, r compositionfull.ConfigurationApplyResult) error {
	var body []byte
	var err error
	if structured {
		body, err = r.RenderJSON()
	} else {
		body, err = r.RenderHuman()
	}
	return writeCommandResultBody(out, body, err)
}

func executeConfigurationApplyPublication(ctx context.Context, applyRequest, publicationRequest contract.ID, path string, format configuration.Format, operation contract.ID, publication compositionfull.ApplyPublicationOptions, options compositionfull.ApplyOptions) compositionfull.ConfigurationApplyPublicationResult {
	if !operation.IsZero() {
		return compositionfull.ContinueConfigurationApplyAndPublishFile(ctx, applyRequest, operation, publicationRequest, path, format, publication)
	}
	return compositionfull.ApplyConfigurationAndPublishFile(ctx, applyRequest, publicationRequest, path, format, publication, options)
}

func executeApplyPublicationCommand(ctx context.Context, path string, format configuration.Format, operation contract.ID, publication compositionfull.ApplyPublicationOptions, options compositionfull.ApplyOptions, structured bool, out, diagnostic io.Writer, execute applyPublicationCommandExecutor, terminal *commandTerminal) int {
	var applyRequest, publicationRequest contract.ID
	if _, err := rand.Read(applyRequest[:]); err != nil || applyRequest.IsZero() {
		return commandDiagnosticExit(diagnostic, "apply request identity is unavailable", 2)
	}
	if _, err := rand.Read(publicationRequest[:]); err != nil || publicationRequest.IsZero() || publicationRequest == applyRequest {
		return commandDiagnosticExit(diagnostic, "publication request identity is unavailable", 2)
	}
	result := execute(ctx, applyRequest, publicationRequest, path, format, operation, publication, options)
	terminal.mutation(result.Apply)
	if result.Publication.Result != nil {
		terminal.publication(*result.Publication.Result)
	} else if result.Publication.Stage == "unstarted" && terminal.result == telemetry.ResultSuccess {
		switch result.Publication.Reason {
		case "selection-unavailable":
			terminal.result = telemetry.ResultEvidenceUnavailable
		case "selection-conflict":
			terminal.result = telemetry.ResultContention
		case "deadline-expired":
			terminal.cancellation(contract.ReasonExpired)
		}
	}
	if err := writeApplyPublicationResult(out, structured, result); err != nil {
		return commandDiagnosticExit(diagnostic, "apply publication output failed", 2)
	}
	return applyPublicationResultCode(result.PublicApplyPublicationResult)
}

func writeApplyPublicationResult(out io.Writer, structured bool, result compositionfull.ConfigurationApplyPublicationResult) error {
	if structured {
		return result.WriteJSON(out)
	}
	return result.WriteHuman(out)
}

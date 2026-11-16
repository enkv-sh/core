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
)

type publicationFlag []string

func (f *publicationFlag) String() string         { return "" }
func (f *publicationFlag) Set(value string) error { *f = append(*f, value); return nil }

type publicationCommandExecutor func(context.Context, contract.ID, string, configuration.Format, compositionfull.PublicationOptions) compositionfull.ConfigurationPublicationResult

func runPublish(args []string, out, diagnostic io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return runPublishWithExecutor(ctx, args, out, diagnostic, compositionfull.PublishConfigurationFile)
}

func runPublishWithExecutor(ctx context.Context, args []string, out, diagnostic io.Writer, execute publicationCommandExecutor) int {
	if out == nil || diagnostic == nil {
		return 2
	}
	flags := flag.NewFlagSet("publish", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var source, format replacementFlag
	var names, deletes, republish publicationFlag
	flags.Var(&source, "source", "")
	flags.Var(&format, "source-format", "")
	flags.Var(&names, "name", "")
	flags.Var(&deletes, "delete-coordinate", "")
	flags.Var(&republish, "republish-after-unknown", "")
	structured := bindCommandJSONFlag(flags)
	var options commandTelemetryOptions
	options.BindFlags(flags)
	if handled, code := commandFlagHelp(args, out, flags, "publish [--source PATH] [--source-format yaml|json] [OPTIONS]\n"); handled {
		return code
	}
	refuse := func() int {
		var id contract.ID
		if _, err := rand.Read(id[:]); err != nil || id.IsZero() {
			return commandDiagnosticExit(diagnostic, "publish request identity is unavailable", 2)
		}
		result := core.PublicPublicationResult{RequestID: id, Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.InvalidIntent}}
		if writePublicationResult(out, *structured, compositionfull.ConfigurationPublicationResult{PublicPublicationResult: result}) != nil {
			return commandDiagnosticExit(diagnostic, "publish output failed", 2)
		}
		return 2
	}
	invalid := func() int {
		code := refuse()
		return commandDiagnosticExit(diagnostic, "publish requires explicit --name or --delete-coordinate selectors; default source is enkv.yaml; use --source-format yaml|json for a --source without a recognized suffix", code)
	}
	if flags.Parse(args) != nil {
		return invalid()
	}
	paths, captured := captureCommandPaths()
	selectedSource, selected, ok := paths.source(source, format)
	if !captured {
		return commandDiagnosticExit(diagnostic, commandDirectoryUnavailable, refuse())
	}
	if !ok || len(flags.Args()) != 0 || execute == nil || len(names)+len(deletes) == 0 || len(names) > contract.CryptoMaxValueEntries || len(deletes) > contract.MaxPublicationCoordinates || len(republish) > contract.MaxPublicationMarkers {
		return invalid()
	}
	request := core.PublicationRequest{Names: []string(names)}
	seenNames := make(map[string]bool)
	for _, name := range names {
		if !utf8.ValidString(name) || len(name) > contract.CryptoMaxName || seenNames[name] {
			return invalid()
		}
		seenNames[name] = true
	}
	parse := func(values []string) ([]contract.ID, bool) {
		var ids []contract.ID
		seen := make(map[contract.ID]bool)
		for _, text := range values {
			id, ok := parseID(text)
			if !ok || seen[id] {
				return nil, false
			}
			seen[id] = true
			ids = append(ids, id)
		}
		return ids, true
	}
	coordinates, deletePlugins, ok := parsePublicationDeletionChoices(deletes)
	if !ok {
		return invalid()
	}
	request.DeleteCoordinates = coordinates
	request.RepublishAfterUnknown, ok = parse(republish)
	if !ok {
		return invalid()
	}
	var terminal commandTerminal
	options.terminal = &terminal
	options.directory = paths.directory
	return withCommandTelemetry(ctx, options, diagnostic, refuse, func(ctx context.Context, diagnostic io.Writer) int {
		var id contract.ID
		if _, err := rand.Read(id[:]); err != nil || id.IsZero() {
			return commandDiagnosticExit(diagnostic, "publish request identity is unavailable", 2)
		}
		result := execute(ctx, id, selectedSource, selected, compositionfull.PublicationOptions{Request: request, DeletePlugins: deletePlugins})
		terminal.publication(result.PublicPublicationResult)
		if result.SourceFailure != nil {
			terminal.cancellation(contract.DiagnosticReason(result.SourceFailure.Reason))
		}
		if err := writePublicationResult(out, *structured, result); err != nil {
			return commandDiagnosticExit(diagnostic, "publish output failed", 2)
		}
		return compositionfull.PublicationExitCode(result.PublicPublicationResult)
	})
}

func parsePublicationDeletionChoices(values []string) ([]contract.ID, map[contract.ID]string, bool) {
	if len(values) > contract.MaxPublicationCoordinates {
		return nil, nil, false
	}
	choices := make(map[contract.ID]string, len(values))
	var coordinates []contract.ID
	for _, choice := range values {
		coordinate, plugin, found := strings.Cut(choice, "=")
		id, valid := parseID(coordinate)
		if !found || !valid || !artifact.ValidPluginID(plugin) {
			return nil, nil, false
		}
		if _, exists := choices[id]; exists {
			return nil, nil, false
		}
		choices[id] = plugin
		coordinates = append(coordinates, id)
	}
	return coordinates, choices, true
}

func writePublicationResult(out io.Writer, structured bool, result compositionfull.ConfigurationPublicationResult) error {
	var body []byte
	var err error
	if structured {
		body, err = result.RenderJSON()
	} else {
		body, err = result.RenderHuman()
	}
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
	if len(body) == 0 || body[len(body)-1] != '\n' {
		n, err = io.WriteString(out, "\n")
		if err == nil && n != 1 {
			return io.ErrShortWrite
		}
	}
	return err
}

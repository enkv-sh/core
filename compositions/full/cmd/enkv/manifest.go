package main

import (
	"context"
	"crypto/rand"
	"flag"
	"io"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core/contract"
	"enkv.sh/sdk/artifact"
	manifest "enkv.sh/sdk/manifest-generator"
)

type manifestExecutor func(context.Context, contract.ID, string, configuration.Format, compositionfull.ManifestOptions, string) compositionfull.ManifestFileResult

func runManifest(args []string, out, diagnostic io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return runManifestWithExecutor(ctx, args, out, diagnostic, compositionfull.WriteConfigurationManifestFile)
}
func runManifestWithExecutor(ctx context.Context, args []string, out, diagnostic io.Writer, execute manifestExecutor) int {
	if ctx == nil || out == nil || diagnostic == nil {
		return 2
	}
	const usage = "manifest [--source PATH] [--source-format yaml|json] --out PATH --plugin LOCAL-ID [--settings JSON] [--recipient ALIAS | --recipient-id ID] [--name NAME ... | --empty-selection] [--service SEMANTIC-ID] [--json]\n"
	flags, q := bindPublicQueryFlags("manifest", "recipient")
	var names materializationNames
	var destination, plugin, settings, service replacementFlag
	flags.Var(&names, "name", "")
	flags.Var(&destination, "out", "")
	flags.Var(&plugin, "plugin", "")
	flags.Var(&settings, "settings", "")
	flags.Var(&service, "service", "")
	empty := flags.Bool("empty-selection", false, "")
	if handled, code := commandFlagHelp(args, out, flags, usage); handled {
		return code
	}
	write := func(r compositionfull.ManifestFileResult) error {
		if *q.structured {
			return compositionfull.WriteManifestFileJSON(ctx, out, r)
		}
		return compositionfull.WriteManifestFileHuman(ctx, out, r)
	}
	refuse := func() int {
		issuance, err := compositionfull.NewManifestRefusal(0)
		r := compositionfull.NewManifestFileResult(issuance)
		r.SourceCleanup = compositionfull.ManifestSourceComplete
		if err != nil || write(r) != nil {
			return commandDiagnosticExit(diagnostic, "manifest result delivery failed", 2)
		}
		return 2
	}
	invalid := func() int {
		code := refuse()
		if !*q.structured {
			return commandDiagnosticExit(diagnostic, "manifest requires valid --out and --plugin options; default source is enkv.yaml; use --source-format yaml|json for a --source without a recognized suffix", code)
		}
		return code
	}
	parseErr := parseUniqueCommandFlags(flags, args, "name")
	if parseErr != nil || flags.NArg() != 0 || !destination.set || destination.value == "" || destination.value == "-" || execute == nil || !plugin.set || !artifact.ValidPluginID(plugin.value) {
		return invalid()
	}
	emptyPresent := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "empty-selection" {
			emptyPresent = true
		}
	})
	if emptyPresent && len(names) != 0 || emptyPresent && !*empty {
		return invalid()
	}
	path, format, ok := publicQuerySource(q)
	if !ok {
		return invalid()
	}
	outPath := q.paths.absolute(destination.value)
	if !manifestCLIPathValid(path) || !manifestCLIPathValid(outPath) || path == outPath {
		return invalid()
	}
	request := compositionfull.ManifestOptions{Plugin: plugin.value, Settings: []byte("{}"), TargetMode: manifest.CurrentAuthority, EntryMode: manifest.AllAuthorized}
	if settings.set {
		request.Settings = []byte(settings.value)
	}
	if manifest.ValidateSettings(request.Settings) != "" {
		return invalid()
	}
	selector, ok := commandRecipientSelection(q.selector, q.recipientID)
	if !ok {
		return invalid()
	}
	if q.selector.set || q.recipientID.set {
		request.TargetMode = manifest.ExactRecipient
		request.TargetRecipientID = selector.ID
		request.TargetRecipientReference = selector.Reference
	}
	if len(names) > 0 {
		request.EntryMode = manifest.ExactNames
		request.EntryNames = names
	}
	if *empty {
		request.EntryMode = manifest.ExactNames
		request.EntryNames = []string{}
	}
	slices.Sort(request.EntryNames)
	if service.set {
		if service.value == "" || len(service.value) > manifest.MaxContractBytes || !utf8.ValidString(service.value) {
			return invalid()
		}
		request.ServiceFilter = &service.value
	}
	var terminal commandTerminal
	q.telemetry.terminal = &terminal
	q.telemetry.directory = q.paths.directory
	return withCommandTelemetry(ctx, q.telemetry, diagnostic, refuse, func(ctx context.Context, diagnostic io.Writer) int {
		var requestID contract.ID
		if _, err := rand.Read(requestID[:]); err != nil || requestID.IsZero() {
			return commandDiagnosticExit(diagnostic, "manifest request correlation unavailable", 2)
		}
		r := execute(ctx, requestID, path, format, request, outPath)
		terminal.observe(r.Issuance.Result, r.Issuance.FailureReason)
		r.ResultDelivery = compositionfull.ManifestResultNotObserved
		if err := write(r); err != nil {
			r.ResultDelivery = compositionfull.ManifestResultFailed
			return commandDiagnosticExit(diagnostic, "manifest result delivery failed", compositionfull.ManifestFileExitCode(r))
		}
		r.ResultDelivery = compositionfull.ManifestResultComplete
		return compositionfull.ManifestFileExitCode(r)
	})
}
func manifestCLIPathValid(path string) bool {
	return len(path) > 0 && len(path) <= 4096 && utf8.ValidString(path) && !strings.ContainsRune(path, 0)
}

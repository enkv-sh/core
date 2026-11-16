package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core/contract"
)

func runPrepare(args []string, out, diagnostic io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return runPrepareWithCoordinator(ctx, args, out, diagnostic, compositionfull.PrepareConfiguration)
}

func runPrepareWithCoordinator(ctx context.Context, args []string, out, diagnostic io.Writer,
	execute func(context.Context, compositionfull.PrepareRequest) (*compositionfull.PrepareResult, error)) int {
	if out == nil || diagnostic == nil || execute == nil {
		return 2
	}
	flags := flag.NewFlagSet("prepare", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.String("source", "", "")
	flags.String("source-format", "", "")
	upgrade := flags.Bool("upgrade", false, "")
	structured := bindCommandJSONFlag(flags)
	name, provider := flags.String("name", "", ""), flags.String("provider", "", "")
	bucket, region, prefix := flags.String("bucket", "", ""), flags.String("region", "", ""), flags.String("prefix", "", "")
	normal, recovery := flags.String("normal-signing-key", "", ""), flags.String("recovery-signing-key", "", "")
	domain, owner, kek := flags.String("expected-domain", "", ""), flags.String("expected-owner", "", ""), flags.String("expected-authority-encryption-key", "", "")
	setupIncomplete := false
	options := commandTelemetryOptions{setupIncomplete: &setupIncomplete}
	options.BindFlags(flags)
	if handled, code := commandFlagHelp(args, out, flags, "prepare [--source PATH] [--source-format yaml|json] [OPTIONS]\n"); handled {
		return code
	}
	flags.VisitAll(func(f *flag.Flag) { f.Value = &localSingletonFlag{value: f.Value} })
	refusalMessage := "prepare arguments or setup refused; default source is enkv.yaml; use --source-format yaml|json for a --source without a recognized suffix"
	refuse := func() int {
		result, err := compositionfull.NewPrepareRefusal()
		if err == nil {
			err = writePrepareResponse(out, *structured, result)
		}
		return commandDiagnosticExit(diagnostic, refusalMessage, compositionfull.PrepareExitCode(result, err))
	}
	if flags.Parse(args) != nil || len(flags.Args()) != 0 {
		return refuse()
	}
	paths, captured := captureCommandPaths()
	selectedSource, encoding, ok := paths.source(commandFlagValue(flags, "source"), commandFlagValue(flags, "source-format"))
	if !captured {
		refusalMessage = commandDirectoryUnavailable
		return refuse()
	}
	if !ok {
		return refuse()
	}
	present := func(name string) bool { return flags.Lookup(name).Value.(*localSingletonFlag).set }
	request := compositionfull.PrepareRequest{Source: selectedSource, Format: encoding, Upgrade: *upgrade}
	for _, flag := range []string{"name", "provider", "bucket", "region", "prefix", "normal-signing-key", "recovery-signing-key", "expected-domain", "expected-owner", "expected-authority-encryption-key"} {
		if present(flag) {
			request.Recovery = &compositionfull.PrepareRecoveryRequest{}
			break
		}
	}
	if r := request.Recovery; r != nil {
		if !present("name") || !present("provider") || !present("bucket") || !present("region") || !present("prefix") || *name == "" || *bucket == "" || *region == "" || !present("normal-signing-key") && !present("recovery-signing-key") {
			return refuse()
		}
		if _, err := configuration.GeneratedPath(*name); err != nil {
			return refuse()
		}
		r.Name, r.Bucket, r.Region, r.Prefix = *name, *bucket, *region, prefix
		switch *provider {
		case "aws":
			r.Provider = contract.AWS
		case "gcp":
			r.Provider = contract.GCP
		default:
			return refuse()
		}
		if present("normal-signing-key") {
			r.NormalSigningKey = normal
		}
		if present("recovery-signing-key") {
			r.RecoverySigningKey = recovery
		}
		if present("expected-owner") {
			r.ExpectedOwner = owner
		}
		if present("expected-authority-encryption-key") {
			r.ExpectedAuthorityEncryptionKey = kek
		}
		if present("expected-domain") {
			id, ok := parseID(*domain)
			if !ok {
				return refuse()
			}
			r.ExpectedDomain = &id
		}
		for _, key := range []*string{r.NormalSigningKey, r.RecoverySigningKey} {
			if key != nil && !contract.PublicKeySelectorValid(r.Provider, *key, true) {
				return refuse()
			}
		}
		if r.ExpectedAuthorityEncryptionKey != nil && !contract.PublicKeySelectorValid(r.Provider, *r.ExpectedAuthorityEncryptionKey, false) || r.ExpectedOwner != nil && (*r.ExpectedOwner == "" || r.Provider != contract.AWS) {
			return refuse()
		}
		expectedOwner := ""
		if r.ExpectedOwner != nil {
			expectedOwner = *r.ExpectedOwner
		}
		if !contract.StoreLocationValid(contract.StoreLocation{Provider: r.Provider, Region: r.Region, Bucket: r.Bucket, PrefixBeforeHEAD: *r.Prefix, ExpectedOwner: expectedOwner}) {
			return refuse()
		}
	}
	if ctx == nil {
		return refuse()
	}
	var terminal commandTerminal
	options.terminal = &terminal
	options.directory = paths.directory
	return withCommandTelemetry(ctx, options, diagnostic, refuse, func(ctx context.Context, diagnostic io.Writer) int {
		result, operationErr := execute(ctx, request)
		terminal.result = result.TelemetryResult(operationErr)
		presentationErr := writePrepareResponse(out, *structured, result)
		code := compositionfull.PrepareExitCode(result, presentationErr)
		if presentationErr != nil {
			return commandDiagnosticExit(diagnostic, "prepare result delivery failed; retain the pair and any saved local transaction", code)
		}
		if code == 2 && operationErr == nil && ctx.Err() == nil && result.SetupRequired() {
			setupIncomplete = true
			return commandDiagnosticExit(diagnostic, "WARNING: plugin setup incomplete; complete the unresolved plugin selections or installations listed in the result, then run prepare on the existing pair; source defaults to enkv.yaml", code)
		}
		if code != 0 || operationErr != nil {
			return commandDiagnosticExit(diagnostic, "prepare incomplete; for an existing pair omit recovery inputs; source defaults to enkv.yaml; retain local_delivery and use recover only for the exact saved transaction", code)
		}
		return code
	})
}

func writePrepareResponse(out io.Writer, structured bool, result *compositionfull.PrepareResult) error {
	var body []byte
	var err error
	if structured {
		body, err = compositionfull.RenderPrepareJSON(result)
	} else {
		body, err = compositionfull.RenderPrepareHuman(result)
	}
	if err != nil {
		return err
	}
	if n, err := out.Write(body); err != nil || n != len(body) {
		return errors.Join(err, io.ErrShortWrite)
	}
	return nil
}

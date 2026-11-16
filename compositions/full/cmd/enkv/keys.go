package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

type replacementExecutor func(context.Context, contract.ID, string, configuration.Format, configuration.ReplacementRequest, string, compositionfull.RecipientSelector) compositionfull.ReplacementCommandResult

type replacementFlag struct {
	value string
	set   bool
}

func (f *replacementFlag) String() string { return f.value }
func (f *replacementFlag) Set(value string) error {
	if f.set {
		return fmt.Errorf("duplicate key replacement option")
	}
	f.value = value
	f.set = true
	return nil
}

func runKeys(args []string, out, diagnostic io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return runKeysWithExecutor(ctx, args, out, diagnostic, compositionfull.ReplaceSelectedRecipientKeysConfiguration)
}
func runKeysWithExecutor(ctx context.Context, args []string, out, diagnostic io.Writer, execute replacementExecutor) int {
	if out == nil || diagnostic == nil {
		return 2
	}
	body := "keys replace --source <file> --target authority|recovery --authorizer authority|recovery --signing <key>|--encryption <key> --out <successor-source>\nkeys replace --source <file> --target recipient (--recipient <alias>|--recipient-id <ID>) --encryption <key> --out <successor-source>\n"
	if len(args) == 0 {
		n, err := io.WriteString(out, body)
		if err != nil || n != len(body) {
			return 2
		}
		return 0
	}
	if handled, code := publicQueryHelp(args, out, body); handled {
		return code
	}
	if args[0] != "replace" {
		return writeUnknownDispatch(args[1:], out, diagnostic)
	}
	flags := flag.NewFlagSet("keys replace", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var source, format, output, target, authorizer, signing, encryption, recipient, material, recipientID replacementFlag
	for _, entry := range []struct {
		name  string
		value *replacementFlag
	}{{"source", &source}, {"source-format", &format}, {"out", &output}, {"target", &target}, {"authorizer", &authorizer}, {"signing", &signing}, {"encryption", &encryption}, {"recipient", &recipient}, {"recipient-id", &recipientID}, {"decrypt-with", &material}} {
		flags.Var(entry.value, entry.name, "")
	}
	structured := bindCommandJSONFlag(flags)
	var telemetryOptions commandTelemetryOptions
	telemetryOptions.BindFlags(flags)
	if handled, code := commandFlagHelp(args[1:], out, flags, "keys replace [--source PATH] [--source-format yaml|json] --target authority|recovery|recipient --out PATH [OPTIONS]\n"); handled {
		return code
	}
	selectedTarget, knownTarget := replacementTargetSelection(args[1:], flags)
	parsed := flags.Parse(args[1:])
	if !knownTarget {
		return writeUnknownDispatch(args[1:], out, diagnostic)
	}
	var nonce contract.ID
	if _, err := rand.Read(nonce[:]); err != nil || nonce.IsZero() {
		return commandDiagnosticExit(diagnostic, "replacement request correlation unavailable", 2)
	}
	request := configuration.ReplacementRequest{Target: configuration.ReplacementTarget(selectedTarget), RecipientReference: recipient.value, SigningSelector: signing.value, EncryptionSelector: encryption.value}
	paths, captured := captureCommandPaths()
	sourcePath, selected, formatOK := paths.source(source, format)
	refuse := func() int {
		r, err := compositionfull.NewReplacementCommandRefusal(request.Target, nonce, selected)
		if err != nil || writeKeyReplacement(ctx, out, *structured, r) != nil {
			return commandDiagnosticExit(diagnostic, "replacement result delivery failed", 2)
		}
		return 2
	}
	invalid := func() int {
		code := refuse()
		return commandDiagnosticExit(diagnostic, "keys replace requires an exact target, key selection and new successor output; default source is enkv.yaml; use --source-format yaml|json for a --source without a recognized suffix", code)
	}
	if !captured {
		return commandDiagnosticExit(diagnostic, commandDirectoryUnavailable, refuse())
	}
	if parsed != nil || len(flags.Args()) != 0 || execute == nil || output.value == "" || !formatOK || signing.set && signing.value == "" || encryption.set && encryption.value == "" {
		return invalid()
	}
	switch request.Target {
	case configuration.ReplaceAuthority, configuration.ReplaceRecovery:
		if recipientID.set || recipient.set || signing.value == "" && encryption.value == "" {
			return invalid()
		}
		switch authorizer.value {
		case "authority":
			request.Authorizer = contract.NormalSigningRole
		case "recovery":
			request.Authorizer = contract.RecoverySigningRole
		default:
			return invalid()
		}
		if encryption.value == "" {
			if material.set {
				return invalid()
			}
		} else {
			request.MaterialSource = material.value
			if !material.set {
				request.MaterialSource = authorizer.value
			}
			if request.MaterialSource != "authority" && request.MaterialSource != "recovery" {
				return invalid()
			}
		}
	case configuration.ReplaceRecipient:
		if !recipient.set && !recipientID.set || signing.set || encryption.value == "" || material.set || authorizer.set && authorizer.value != "authority" {
			return invalid()
		}
		request.Authorizer = contract.NormalSigningRole
		request.MaterialSource = "authority"
	}
	if signing.value != "" && !replacementSelector(signing.value, true) || encryption.value != "" && !replacementSelector(encryption.value, false) {
		return invalid()
	}
	selector, selectionOK := commandRecipientSelection(recipient, recipientID)
	if !selectionOK {
		return invalid()
	}
	outputPath := paths.absolute(output.value)
	if sourcePath == outputPath || !configuration.SuccessorOutputPathValid(outputPath) {
		return invalid()
	}
	var terminal commandTerminal
	telemetryOptions.terminal = &terminal
	telemetryOptions.directory = paths.directory
	return withCommandTelemetry(ctx, telemetryOptions, diagnostic, refuse, func(ctx context.Context, diagnostic io.Writer) int {
		result := execute(ctx, nonce, sourcePath, selected, request, outputPath, selector)
		for _, mutation := range []*core.PublicReplacementResult{result.Authority, result.Recovery, result.Recipient} {
			if mutation != nil {
				terminal.observe(mutation.Result)
				terminal.diagnostics(mutation.Diagnostics)
			}
		}
		if result.Observation != nil {
			terminal.observe(result.Observation.Result)
			terminal.admission(result.Observation.PreAdmission)
		}
		terminal.admission(result.PreAdmission)
		if err := writeKeyReplacement(ctx, out, *structured, result); err != nil {
			return commandDiagnosticExit(diagnostic, "replacement result delivery failed", 2)
		}
		code := compositionfull.ReplacementCommandExitCode(result)
		if result.Delivery.CleanupFailed {
			code = commandDiagnosticExit(diagnostic, "replacement local cleanup incomplete", code)
		}
		if result.Delivery.Failed {
			code = commandDiagnosticExit(diagnostic, "replacement local delivery incomplete", code)
		}
		return code
	})
}

// A recognized target survives another invalid option regardless of ordering.
// Known value-taking flags consume their value before target recognition.
func replacementTargetSelection(args []string, flags *flag.FlagSet) (string, bool) {
	selected := ""
	count := 0
	for i := 0; i < len(args); i++ {
		token := args[i]
		if token == "--" {
			break
		}
		if strings.HasPrefix(token, "--") {
			token = token[2:]
		} else if strings.HasPrefix(token, "-") {
			token = token[1:]
		} else {
			continue
		}
		name, value, inline := strings.Cut(token, "=")
		option := flags.Lookup(name)
		if option == nil {
			continue
		}
		boolean, ok := option.Value.(interface{ IsBoolFlag() bool })
		if !inline && (!ok || !boolean.IsBoolFlag()) {
			if i+1 == len(args) {
				if name == "target" {
					return "", false
				}
				continue
			}
			i++
			value = args[i]
		}
		if name != "target" {
			continue
		}
		count++
		if count > 1 && selected != value {
			return "", false
		}
		selected = value
	}
	switch selected {
	case "authority", "recovery", "recipient":
		return selected, true
	}
	return "", false
}

func replacementSelector(value string, signing bool) bool {
	return contract.PublicKeySelectorValid(contract.AWS, value, signing) || contract.PublicKeySelectorValid(contract.GCP, value, signing)
}

func writeKeyReplacement(ctx context.Context, out io.Writer, structured bool, result compositionfull.ReplacementCommandResult) error {
	if structured {
		return compositionfull.WriteReplacementJSON(ctx, out, result)
	}
	return compositionfull.WriteReplacementHuman(ctx, out, result)
}

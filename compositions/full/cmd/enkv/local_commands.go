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

func runRecipients(args []string, out, diagnostic io.Writer) int {
	if handled, code := publicQueryHelp(args, out, "recipients add|rename|retire [OPTIONS]\n"); handled {
		return code
	}
	if len(args) > 0 {
		switch args[0] {
		case "add":
			return runLocalEdit("recipient-preparation", args[1:], out, diagnostic)
		case "rename":
			return runLocalEdit("recipient-reference-rename", args[1:], out, diagnostic)
		case "retire":
			return runRecipientRetirement(args[1:], out, diagnostic)
		}
	}
	return writeUnknownDispatch(args, out, diagnostic)
}

type localEditCommand struct {
	action       string
	source       string
	format       configuration.Format
	name         string
	reference    string
	recipientID  contract.ID
	newReference string
	preparation  compositionfull.RecipientPreparationOptions
}

func runLocalEdit(action string, args []string, out, diagnostic io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return runLocalEditWithExecutor(ctx, action, args, out, diagnostic, executeLocalEdit)
}

func executeLocalEdit(ctx context.Context, command localEditCommand) (*compositionfull.LocalEditResult, error) {
	switch command.action {
	case "domain-rename":
		return compositionfull.RenameConfigurationDomain(ctx, command.source, command.format, command.name)
	case "recipient-preparation":
		return compositionfull.PrepareConfigurationSelectedRecipient(ctx, command.source, command.format, compositionfull.RecipientSelector{Reference: command.reference, ID: command.recipientID}, command.preparation)
	case "recipient-reference-rename":
		return compositionfull.RenameConfigurationSelectedRecipient(ctx, command.source, command.format, compositionfull.RecipientSelector{Reference: command.reference, ID: command.recipientID}, command.newReference)
	case "recovery":
		return compositionfull.RecoverConfigurationEdit(ctx, command.source, command.format)
	}
	return nil, compositionfull.ErrLocalEdit
}

// flag.FlagSet retains only the final value of a repeated flag. Track each Set
// so an explicit false Boolean cannot hide a second occurrence.
type localSingletonFlag struct {
	value flag.Value
	set   bool
}

func (f *localSingletonFlag) String() string {
	if f.value == nil {
		return ""
	}
	return f.value.String()
}
func (f *localSingletonFlag) Set(value string) error {
	if f.set {
		return errors.New("repeated flag")
	}
	f.set = true
	return f.value.Set(value)
}
func (f *localSingletonFlag) IsBoolFlag() bool {
	value, ok := f.value.(interface{ IsBoolFlag() bool })
	return ok && value.IsBoolFlag()
}

func runLocalEditWithExecutor(ctx context.Context, action string, args []string, out, diagnostic io.Writer,
	execute func(context.Context, localEditCommand) (*compositionfull.LocalEditResult, error)) int {
	if ctx == nil || out == nil || diagnostic == nil || execute == nil {
		return 2
	}
	flags := flag.NewFlagSet(action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.String("source", "", "")
	flags.String("source-format", "", "")
	structured := bindCommandJSONFlag(flags)
	var options commandTelemetryOptions
	options.BindFlags(flags)
	var commandName, name, reference, newReference, mode, displayName, encryption string
	var recipientID replacementFlag
	switch action {
	case "domain-rename":
		commandName = "rename"
		flags.StringVar(&name, "name", "", "")
	case "recipient-preparation":
		commandName = "recipients add"
		flags.StringVar(&reference, "recipient", "", "")
		flags.Var(&recipientID, "recipient-id", "exact existing recipient ID; mutually exclusive with --recipient")
		flags.StringVar(&mode, "mode", "", "")
		flags.StringVar(&displayName, "display-name", "", "")
		flags.StringVar(&encryption, "encryption-key", "", "")
	case "recipient-reference-rename":
		commandName = "recipients rename"
		flags.StringVar(&reference, "recipient", "", "")
		flags.Var(&recipientID, "recipient-id", "exact existing recipient ID; mutually exclusive with --recipient")
		flags.StringVar(&newReference, "new-reference", "", "")
	case "recovery":
		commandName = "recover"
	default:
		return 2
	}
	if handled, code := commandFlagHelp(args, out, flags, commandName+" [--source PATH] [--source-format yaml|json] [OPTIONS]\n"); handled {
		return code
	}
	flags.VisitAll(func(f *flag.Flag) { f.Value = &localSingletonFlag{value: f.Value} })
	refuse := func() int {
		result, err := compositionfull.NewLocalEditRefusal(action)
		if err != nil || writeLocalEditResponse(out, *structured, result, nil) != nil {
			return commandDiagnosticExit(diagnostic, "local edit output failed; retain the pair and any saved local transaction", 2)
		}
		return 2
	}
	badInput := func() int {
		code := refuse()
		return commandDiagnosticExit(diagnostic, "local edit arguments refused; use the action's exact flags; default source is enkv.yaml; use --source-format yaml|json for a --source without a recognized suffix", code)
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
	present := func(name string) bool { return flags.Lookup(name).Value.(*localSingletonFlag).set }
	selected := compositionfull.RecipientSelector{}
	if action == "recipient-preparation" || action == "recipient-reference-rename" {
		var selectorOK bool
		selected, selectorOK = commandRecipientSelection(replacementFlag{value: reference, set: present("recipient")}, recipientID)
		if !selectorOK {
			return badInput()
		}
	}
	command := localEditCommand{action: action, source: selectedSource, format: selectedFormat, name: name, reference: selected.Reference, recipientID: selected.ID, newReference: newReference}
	switch action {
	case "domain-rename":
		if !present("name") || name == "" {
			return badInput()
		}
	case "recipient-preparation":
		if reference == "" && selected.ID.IsZero() || mode != string(compositionfull.RecipientPreparationCurrent) && mode != string(compositionfull.RecipientPreparationCreate) || present("display-name") != present("encryption-key") {
			return badInput()
		}
		command.preparation.Mode = compositionfull.RecipientPreparationMode(mode)
		if mode == "create" && (reference == "" || recipientID.set) {
			return badInput()
		}
		if present("display-name") {
			if command.preparation.Mode != compositionfull.RecipientPreparationCreate || encryption == "" {
				return badInput()
			}
			command.preparation.Declaration = &configuration.RecipientDeclaration{DisplayName: displayName, EncryptionSelector: encryption}
		}
	case "recipient-reference-rename":
		if reference == "" && selected.ID.IsZero() || newReference == "" {
			return badInput()
		}

	}
	var terminal commandTerminal
	options.terminal = &terminal
	options.directory = paths.directory
	return withCommandTelemetry(ctx, options, diagnostic, refuse, func(ctx context.Context, diagnostic io.Writer) int {
		result, err := execute(ctx, command)
		terminal.result = result.TelemetryResult(err)
		if writeLocalEditResponse(out, *structured, result, err) != nil {
			return commandDiagnosticExit(diagnostic, "local edit output failed; retain the pair and any saved local transaction", 2)
		}
		if err != nil {
			return commandDiagnosticExit(diagnostic, "local edit did not complete; inspect the result before further action", compositionfull.LocalEditExitCode(result, err))
		}
		return compositionfull.LocalEditExitCode(result, err)
	})
}

func writeLocalEditResponse(out io.Writer, structured bool, result *compositionfull.LocalEditResult, resultErr error) error {
	var body []byte
	var err error
	if structured {
		body, err = compositionfull.RenderLocalEditJSON(result, resultErr)
	} else {
		body, err = compositionfull.RenderLocalEditHuman(result, resultErr)
	}
	if err != nil {
		return err
	}
	if n, err := out.Write(body); err != nil || n != len(body) {
		return errors.Join(err, io.ErrShortWrite)
	}
	return nil
}

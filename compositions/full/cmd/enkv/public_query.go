package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"strconv"
	"strings"

	"enkv.sh/compositions/configuration"
)

type publicQueryFlags struct {
	source, format, selector replacementFlag
	recipientID              replacementFlag
	structured               *bool
	telemetry                commandTelemetryOptions
	paths                    commandPaths
}

func bindPublicQueryFlags(name, selector string) (*flag.FlagSet, *publicQueryFlags) {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	q := &publicQueryFlags{}
	f.Var(&q.source, "source", "")
	f.Var(&q.format, "source-format", "")
	f.Var(&q.selector, selector, "")
	if selector == "recipient" {
		f.Var(&q.recipientID, "recipient-id", "exact recipient ID; mutually exclusive with --recipient")
	}
	q.structured = bindCommandJSONFlag(f)
	q.telemetry.BindFlags(f)
	return f, q
}

// A failed Boolean parse must not overwrite an earlier accepted output mode.
func bindCommandJSONFlag(f *flag.FlagSet) *bool {
	structured := new(bool)
	f.BoolFunc("json", "use JSON output", func(value string) error {
		parsed, err := strconv.ParseBool(value)
		if err == nil {
			*structured = parsed
		}
		return err
	})
	return structured
}

// Reject duplicates at their parser boundary, before they can replace accepted
// values. Each command declares its one repeatable option, if any.
func parseUniqueCommandFlags(f *flag.FlagSet, args []string, repeatable string) error {
	f.VisitAll(func(option *flag.Flag) {
		if option.Name != repeatable {
			option.Value = &localSingletonFlag{value: option.Value}
		}
	})
	if err := f.Parse(args); err != nil {
		return err
	}
	if !commandOptionsUnique(f, args, repeatable) {
		return errors.New("invalid command options")
	}
	return nil
}

// These strict command grammars reject positional arguments and separators,
// including a terminal separator with no following arguments.
func commandOptionsUnique(f *flag.FlagSet, args []string, repeatable string) bool {
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") || arg == "--" {
			return false
		}
		name, _, inline := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		option := f.Lookup(name)
		if option == nil || seen[name] && name != repeatable {
			return false
		}
		seen[name] = true
		boolean, ok := option.Value.(interface{ IsBoolFlag() bool })
		if !inline && (!ok || !boolean.IsBoolFlag()) {
			i++
			if i >= len(args) {
				return false
			}
		}
	}
	return true
}
func publicQuerySource(q *publicQueryFlags) (string, configuration.Format, bool) {
	paths, ok := captureCommandPaths()
	if !ok {
		return "", 0, false
	}
	q.paths = paths
	return paths.source(q.source, q.format)
}
func publicQueryHelp(args []string, out io.Writer, text string) (bool, int) {
	if len(args) != 1 || args[0] != "--help" && args[0] != "-h" {
		return false, 0
	}
	n, err := io.WriteString(out, text)
	if err != nil || n != len(text) {
		return true, 2
	}
	return true, 0
}

func commandFlagHelp(args []string, out io.Writer, flags *flag.FlagSet, usage string) (bool, int) {
	if len(args) != 1 || args[0] != "--help" && args[0] != "-h" {
		return false, 0
	}
	for _, name := range []string{"source", "trusted"} {
		if source := flags.Lookup(name); source != nil {
			source.Usage = "configuration path (default enkv.yaml in the current directory)"
		}
		if format := flags.Lookup(name + "-format"); format != nil {
			format.Usage = "yaml or json; overrides path suffix inference (default YAML for enkv.yaml)"
		}
	}
	if candidate := flags.Lookup("candidate"); candidate != nil {
		candidate.Usage = "optional candidate configuration path"
		flags.Lookup("candidate-format").Usage = "yaml or json; overrides candidate suffix inference"
	}
	if recipient := flags.Lookup("recipient"); recipient != nil {
		recipient.Usage = "local recipient alias; mutually exclusive with --recipient-id"
	}
	if recipient := flags.Lookup("recipient-id"); recipient != nil {
		recipient.Usage = "nonzero 64-character lowercase hexadecimal recipient ID; mutually exclusive with --recipient"
	}
	body := bytes.NewBufferString(usage)
	previous := flags.Output()
	flags.SetOutput(body)
	flags.PrintDefaults()
	flags.SetOutput(previous)
	return publicQueryHelp(args, out, body.String())
}

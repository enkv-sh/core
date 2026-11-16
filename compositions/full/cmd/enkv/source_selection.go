package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"enkv.sh/compositions/configuration"
)

const commandDirectoryUnavailable = "application directory is unavailable; use an accessible current directory"

type commandPaths struct {
	directory string
}

func captureCommandPaths() (commandPaths, bool) {
	directory, err := os.Getwd()
	if err != nil || !filepath.IsAbs(directory) {
		return commandPaths{}, false
	}
	return commandPaths{directory: directory}, true
}

func commandFlagValue(flags *flag.FlagSet, name string) replacementFlag {
	value := replacementFlag{value: flags.Lookup(name).Value.String()}
	flags.Visit(func(f *flag.Flag) {
		if f.Name == name {
			value.set = true
		}
	})
	return value
}

func (p commandPaths) absolute(path string) string {
	if path == "" {
		return ""
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(p.directory, path)
	}
	return filepath.Clean(path)
}

func (p commandPaths) source(path, format replacementFlag) (string, configuration.Format, bool) {
	if path.set && path.value == "" || format.set && format.value == "" {
		return "", 0, false
	}
	selected := configuration.YAML
	if !path.set {
		path.value = "enkv.yaml"
	}
	if format.set {
		var ok bool
		selected, ok = configurationFormat(format.value)
		if !ok {
			return "", 0, false
		}
	} else if path.set {
		switch strings.ToLower(filepath.Ext(path.value)) {
		case ".yaml", ".yml":
			selected = configuration.YAML
		case ".json":
			selected = configuration.JSON
		default:
			return "", 0, false
		}
	}
	resolved := p.absolute(path.value)
	if !validCommandSourcePath(resolved) {
		return "", 0, false
	}
	return resolved, selected, true
}

func (p commandPaths) candidate(path, format replacementFlag) (string, configuration.Format, bool) {
	if !path.set {
		return "", 0, !format.set
	}
	return p.source(path, format)
}

func validCommandSourcePath(source string) bool {
	return len(source) > 0 && len(source) <= 4096 && utf8.ValidString(source) && !strings.ContainsRune(source, 0) && filepath.IsAbs(source) && filepath.Clean(source) == source && source != string(filepath.Separator)
}

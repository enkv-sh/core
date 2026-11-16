package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func localModuleArguments(ctx context.Context, root, workingDirectory string, args []string) (arguments []string, directory string, preparation *modulePreparationFacts, err error) {
	return prepareLocalModuleArguments(nil, ctx, root, workingDirectory, args)
}

func prepareLocalModuleArguments(diagnostics *checkDiagnostics, ctx context.Context, root, workingDirectory string, args []string) (arguments []string, directory string, preparation *modulePreparationFacts, err error) {
	if len(args) == 0 {
		return args, "", nil, nil
	}
	switch args[0] {
	case "build", "test", "list", "vet":
	case "mod":
		if len(args) < 2 || args[1] != "verify" {
			return args, "", nil, nil
		}
	default:
		return args, "", nil, nil
	}
	source := filepath.Join(workingDirectory, "go.mod")
	modIndex := -1
	for i, arg := range args {
		if path, ok := strings.CutPrefix(arg, "-modfile="); ok {
			source = compilerInputPath(workingDirectory, path)
			modIndex = i
		}
	}
	overlay, err := compilerOverlayReplacements(workingDirectory, args)
	if err != nil {
		return nil, "", nil, err
	}
	input := source
	if replacement := overlay[source]; replacement != "" {
		input = replacement
	}
	body, err := os.ReadFile(input)
	if errors.Is(err, os.ErrNotExist) && modIndex < 0 && standaloneFileCommand(root, workingDirectory, args) {
		return args, "", nil, nil
	}
	if err != nil {
		return nil, "", nil, fmt.Errorf("local module input unavailable: %w", err)
	}
	directory, err = os.MkdirTemp("", "enkv-local-modfile-")
	if err != nil {
		return nil, "", nil, err
	}
	defer func() {
		if err != nil && toolCommandsJoined(err) && (preparation == nil || preparation.Joined) {
			cleanupErr := os.RemoveAll(directory)
			err = errors.Join(err, cleanupErr)
			if cleanupErr == nil {
				directory = ""
			}
		}
	}()
	path := filepath.Join(directory, "local.mod")
	if err := os.WriteFile(path, body, 0600); err != nil {
		return nil, directory, nil, err
	}
	scope, err := sourceLabel(root, workingDirectory)
	if err != nil {
		return nil, directory, nil, err
	}
	var parsed []byte
	var facts checkCommandFacts
	var parseErr error
	if diagnostics == nil {
		parsed, facts, parseErr = runGoRecorded(ctx, root, scope, "mod", "edit", "-json", "-modfile="+path)
	} else {
		parsed, facts, parseErr = diagnostics.runGoRecordedEnvironment(ctx, root, scope, nil, "mod", "edit", "-json", "-modfile="+path)
	}
	// A reservation refusal has no acquired command or module process.
	if parseErr != nil && facts.Process == "" {
		return nil, directory, nil, parseErr
	}
	preparation = &modulePreparationFacts{Process: facts.Process, Started: facts.Started, Joined: facts.Joined, WallSeconds: facts.WallSeconds}
	if parseErr != nil {
		return nil, directory, preparation, parseErr
	}
	if !preparation.passed() {
		return nil, directory, preparation, errors.New("module preparation did not complete")
	}
	var definition struct {
		Replace []struct{ Old struct{ Path string } }
	}
	if err := json.Unmarshal(parsed, &definition); err != nil {
		return nil, directory, preparation, errors.New("Go module definition is invalid")
	}
	for _, replacement := range definition.Replace {
		if owner, known := registeredModule(replacement.Old.Path); known && owner.Module == replacement.Old.Path {
			return nil, directory, preparation, errors.New("source module contains a first-party replacement")
		}
	}
	var replacements strings.Builder
	for _, row := range moduleSources {
		owner, err := moduleSourceDirectory(root, row)
		if err != nil {
			return nil, directory, preparation, err
		}
		if owner == workingDirectory {
			continue
		}
		relative, err := filepath.Rel(workingDirectory, owner)
		if err != nil {
			return nil, directory, preparation, err
		}
		relative = filepath.ToSlash(relative)
		if !strings.HasPrefix(relative, ".") {
			relative = "./" + relative
		}
		fmt.Fprintf(&replacements, "replace %s => %s\n", row.Module, relative)
	}
	body = append(append(body, '\n'), replacements.String()...)
	if err := os.WriteFile(path, body, 0600); err != nil {
		return nil, directory, preparation, err
	}
	sumfile := strings.TrimSuffix(source, ".mod") + ".sum"
	if replacement := overlay[sumfile]; replacement != "" {
		sumfile = replacement
	}
	sum, err := os.ReadFile(sumfile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, directory, preparation, err
	}
	if err == nil {
		if err := os.WriteFile(filepath.Join(directory, "local.sum"), sum, 0600); err != nil {
			return nil, directory, preparation, err
		}
	}
	arguments = append([]string(nil), args...)
	if modIndex >= 0 {
		arguments[modIndex] = "-modfile=" + path
	} else {
		index := 1
		if args[0] == "mod" {
			index = 2
		}
		arguments = append(arguments[:index], append([]string{"-modfile=" + path}, arguments[index:]...)...)
	}
	return arguments, directory, preparation, nil
}

func standaloneFileCommand(root, workingDirectory string, args []string) bool {
	for _, row := range moduleSources {
		repository := root
		if row.Sibling != "" {
			repository = filepath.Join(filepath.Dir(root), row.Sibling)
		}
		if filepath.Join(repository, row.Directory) == workingDirectory {
			return false
		}
	}
	for _, arg := range args[1:] {
		if !strings.HasPrefix(arg, "-") && strings.HasSuffix(arg, ".go") {
			return true
		}
	}
	return false
}

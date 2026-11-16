package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	records "enkv.sh/core/internal/testrecords"
)

func captureFailureSources(root, overlay string, closure assemblyClosure) (records.FailureSources, error) {
	var replacements struct{ Replace map[string]string }
	if records.ReadJSON(overlay, &replacements) != nil {
		return records.FailureSources{}, errors.New("assertion source overlay unavailable")
	}
	compiled := make(map[string]bool, len(closure.CompiledImports))
	for _, imported := range closure.CompiledImports {
		name, _, _ := strings.Cut(imported, " [")
		compiled[name] = true
	}
	sources := records.FailureSources{SchemaVersion: records.FailureSchemaVersion, BinarySHA256: closure.BinarySHA256, OverlaySHA256: closure.OverlaySHA256, Paths: make(map[string]string)}
	for _, module := range closure.ResolvedModules {
		registered, local := registeredModule(module.Path)
		if !local {
			if strings.HasPrefix(module.Path, modulePrefix) {
				return records.FailureSources{}, errors.New("assertion module is not registered")
			}
			continue
		}
		if !slices.ContainsFunc(closure.CompiledImports, func(imported string) bool {
			name, _, _ := strings.Cut(imported, " [")
			return withinModule(name, module.Path)
		}) {
			continue
		}
		owner, err := moduleSourceDirectory(root, registered)
		if err != nil {
			return records.FailureSources{}, errors.New("assertion module source refused")
		}
		add := func(target, source string) error {
			targetRelative, err := filepath.Rel(owner, target)
			if err != nil || targetRelative == ".." || strings.HasPrefix(targetRelative, ".."+string(filepath.Separator)) || filepath.IsAbs(targetRelative) {
				return nil
			}
			packagePath := module.Path
			if directory := filepath.Dir(targetRelative); directory != "." {
				packagePath += "/" + filepath.ToSlash(directory)
			}
			if !compiled[packagePath] {
				return nil
			}
			sourceRelative, err := sourceLabel(root, source)
			if err != nil {
				return errors.New("assertion source path unavailable")
			}
			if _, err := sourcePath(root, sourceRelative); err != nil {
				return errors.New("assertion source path refused")
			}
			info, err := os.Lstat(source)
			if err != nil || !info.Mode().IsRegular() {
				return errors.New("assertion source unavailable")
			}
			sourceRelative, targetRelative = filepath.ToSlash(sourceRelative), filepath.ToSlash(targetRelative)
			compilerModule := module.Path
			if module.Version != "local" {
				compilerModule += "@" + module.Version
			}
			sources.Paths[compilerModule+"/"+targetRelative] = sourceRelative
			return nil
		}
		err = filepath.WalkDir(owner, func(source string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				if source != owner {
					relative, err := filepath.Rel(owner, source)
					if err != nil {
						return err
					}
					packagePath := module.Path + "/" + filepath.ToSlash(relative)
					// Traverse only compiled packages and their ancestors. Package
					// names alone cannot distinguish source from local metadata.
					if !slices.ContainsFunc(closure.CompiledImports, func(importPath string) bool {
						importPath, _, _ = strings.Cut(importPath, " [")
						return withinModule(importPath, packagePath)
					}) {
						return filepath.SkipDir
					}
					if _, err := os.Lstat(filepath.Join(source, "go.mod")); err == nil {
						return filepath.SkipDir
					}
				}
				return nil
			}
			if !strings.HasSuffix(entry.Name(), ".go") {
				return nil
			}
			if replacement := replacements.Replace[source]; replacement != "" {
				return add(source, replacement)
			}
			return add(source, source)
		})
		if err != nil {
			return records.FailureSources{}, err
		}
		for target, source := range replacements.Replace {
			if err := add(target, source); err != nil {
				return records.FailureSources{}, err
			}
		}
	}
	return sources, nil
}

func buildFailureSources(root, overlay, directory string, closure assemblyClosure) (*records.FailureSourceBinding, error) {
	sources, err := captureFailureSources(root, overlay, closure)
	if err != nil {
		return nil, err
	}
	return writeFailureSources(directory, sources, closure)
}

func writeFailureSources(directory string, sources records.FailureSources, closure assemblyClosure) (*records.FailureSourceBinding, error) {
	sources.BinarySHA256, sources.OverlaySHA256 = closure.BinarySHA256, closure.OverlaySHA256
	if sources.Validate() != nil {
		return nil, errors.New("assertion source mapping refused")
	}
	path := filepath.Join(directory, "failure-sources.json")
	if records.WriteJSON(path, sources, 0o400) != nil {
		return nil, errors.New("assertion source mapping could not be saved")
	}
	digest, err := assemblyFileSHA256(path)
	if err != nil {
		return nil, err
	}
	binding := &records.FailureSourceBinding{Path: path, SHA256: digest}
	if _, err := records.ReadFailureSources(*binding); err != nil {
		return nil, errors.New("assertion source mapping exceeds its bound")
	}
	return binding, nil
}

func failureSourcesEnvironment(binding *records.FailureSourceBinding) []string {
	if binding == nil {
		return nil
	}
	return []string{"ENKV_TEST_FAILURE_SOURCES=" + binding.Path, "ENKV_TEST_FAILURE_SOURCES_SHA256=" + binding.SHA256}
}

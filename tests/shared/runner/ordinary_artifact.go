package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type ordinaryCompiledPackage struct {
	binary, hash, cwd string
	inventory         ordinaryPackage
}

func prepareOrdinaryPackage(ctx context.Context, root, module string, flags, patterns []string, pkg listedOrdinaryPackage, directory string, diagnostics *checkDiagnostics) (ordinaryCompiledPackage, error) {
	if pkg.ImportPath != "command-line-arguments" {
		patterns = []string{pkg.ImportPath}
	}
	recipe := struct {
		Module, Package string
		Flags, Patterns []string
	}{module, pkg.ImportPath, compilerBuildFlags(flags, raceEnabled(ctx)), patterns}
	value, _, err := invocationArtifactValue(ctx, root, directory, "ordinary", recipe, func(build string) (ordinaryCompiledPackage, error) {
		captured, declarationErr := captureTestDeclarations(root, []listedOrdinaryPackage{pkg}, flags)
		value := ordinaryCompiledPackage{cwd: pkg.Dir, binary: filepath.Join(build, "package.test")}
		actualFlags, err := captured.compilerFlags(recipe.Flags, build)
		if err != nil {
			return value, err
		}
		args := append([]string{"test"}, actualFlags...)
		args = append(args, "-c", "-o", value.binary)
		_, facts, err := runGoRecorded(ctx, root, module, append(args, patterns...)...)
		facts.Phase = "preparation"
		if diagnostics != nil {
			err = errors.Join(err, diagnostics.append(facts))
		}
		if err != nil {
			return value, containProcessFailure(ctx, err)
		}
		if declarationErr != nil {
			return value, declarationErr
		}
		names := []string{}
		if len(pkg.TestGoFiles) == 0 && len(pkg.XTestGoFiles) == 0 {
			value.binary = ""
			if !ordinaryTestlessCommands[pkg.ImportPath] {
				return value, fmt.Errorf("required ordinary package %s has no tests", pkg.ImportPath)
			}
		} else {
			command := exec.Command(value.binary, "-test.list=^(Test|Example|Fuzz)")
			command.Dir, command.Env = pkg.Dir, invocationGoEnvironment(ctx)
			stdout, stderr := &limitedOutput{}, &limitedOutput{}
			command.Stdout, command.Stderr = stdout, stderr
			started := time.Now()
			process := superviseProcess(ctx, command)
			facts := commandFacts("preparation", pkg.ImportPath, process, time.Since(started))
			if process.Joined {
				facts.RaceObservation = observedRace(true, stdout.Bytes(), stderr.Bytes())
			}
			if diagnostics != nil {
				if err := diagnostics.append(facts); err != nil {
					return value, err
				}
			}
			if process.Status != "passed" || !process.Joined || stdout.overflow || stderr.overflow {
				failure := &toolFailure{operation: "ordinary compiled inventory", process: process}
				if process.Joined {
					failure.stdout, failure.stderr, failure.overflow = stdout.Bytes(), stderr.Bytes(), stdout.overflow || stderr.overflow
				}
				return value, failure
			}
			for _, name := range strings.Fields(string(stdout.Bytes())) {
				if !validOrdinaryName(name) || strings.Contains(name, "/") || slices.Contains(names, name) || len(names) >= maximumOrdinaryTests {
					return value, errors.New("ordinary compiled inventory is invalid")
				}
				names = append(names, name)
			}
			if len(names) == 0 {
				return value, errors.New("ordinary compiled inventory has no tests")
			}
			observed, err := binaryRace(value.binary)
			if err != nil || observed != raceEnabled(ctx) {
				return value, errors.Join(err, errors.New("ordinary executable race policy differs"))
			}
			value.hash, err = assemblyFileSHA256(value.binary)
			if err != nil {
				return value, err
			}
		}
		rows, _, err := captured.classify(map[string][]string{pkg.ImportPath: names})
		if err != nil {
			return value, err
		}
		value.inventory = ordinaryPackage{Name: pkg.ImportPath, Inventory: names, Tests: slices.Clone(names), Classifications: rows[pkg.ImportPath]}
		return value, nil
	})
	return value, err
}

func ordinaryInventoryOutput(flags []string) string {
	for index := range flags {
		if flags[index] == "-o" && index+1 < len(flags) {
			return flags[index+1]
		}
		if value, ok := strings.CutPrefix(flags[index], "-o="); ok {
			return value
		}
	}
	return ""
}

func ordinaryPackageDirectory(ctx context.Context, fallback string) (string, func() error, error) {
	if invocationArtifactsFrom(ctx) != nil {
		return fallback, func() error { return nil }, nil
	}
	directory, err := os.MkdirTemp("", "enkv-ordinary-inventory-")
	return directory, func() error {
		if err == nil {
			return os.RemoveAll(directory)
		}
		return nil
	}, err
}

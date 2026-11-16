package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type fuzzArtifact struct {
	executable  ordinaryCompiledPackage
	closure     assemblyClosure
	converter   preparedTestEventConverter
	corpus      string
	seedDigests map[string]string
}

func prepareFuzzArtifact(ctx context.Context, root, directory string, spec fuzzSpecification, diagnostics *checkDiagnostics) (fuzzArtifact, error) {
	recipe := struct{ Module, Package string }{spec.Module, spec.Package}
	artifact, _, err := invocationArtifactValue(ctx, root, directory, "fuzz", recipe, func(build string) (fuzzArtifact, error) {
		overlay, err := buildCryptoOverlay(root, build)
		if err != nil {
			return fuzzArtifact{}, err
		}
		flags := fuzzCompilerFlags(spec, overlay, raceEnabled(ctx))
		command := goEnvironmentCommand(runGoEnvironment)
		if diagnostics != nil {
			command = diagnostics.runGoEnvironment
		}
		modules, packages, err := listClosure(command, ctx, root, spec.Module, flags, true, spec.Package)
		if err != nil {
			return fuzzArtifact{}, err
		}
		var selected listedOrdinaryPackage
		for _, pkg := range packages {
			if pkg.ImportPath == spec.importPath() && pkg.ForTest == "" {
				selected = listedOrdinaryPackage{ImportPath: pkg.ImportPath, Dir: pkg.Dir, GoFiles: pkg.GoFiles, TestGoFiles: pkg.TestGoFiles, XTestGoFiles: pkg.XTestGoFiles}
			}
		}
		if selected.ImportPath == "" {
			return fuzzArtifact{}, errors.New("fuzz compiler package is unavailable")
		}
		corpus := filepath.Join(build, "corpus")
		original := filepath.Join(selected.Dir, "testdata/fuzz")
		if _, err := os.Stat(original); err == nil {
			if err := os.CopyFS(corpus, os.DirFS(original)); err != nil {
				return fuzzArtifact{}, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fuzzArtifact{}, err
		}
		// cmd/go enables instrumentation when -fuzz is set, including with -c.
		executable, err := prepareOrdinaryPackage(ctx, root, spec.Module, append(flags, "-fuzz=."), []string{spec.Package}, selected, build, diagnostics)
		if err != nil {
			return fuzzArtifact{}, err
		}
		converter, facts, err := prepareTestEventConverter(ctx, root, build)
		if diagnostics != nil && facts.Scope != "" {
			err = errors.Join(err, diagnostics.append(facts))
		}
		if err != nil {
			return fuzzArtifact{}, err
		}
		closure := makeClosure("hermetic", "memory", modules, packages)
		closure.BinarySHA256, closure.Race, closure.RaceOptions = executable.hash, raceEnabled(ctx), acceptedRaceOptions(raceEnabled(ctx))
		if closure.Race {
			closure.RaceExitSleepMillis = 1000
		}
		artifact := fuzzArtifact{executable: executable, closure: closure, converter: converter, corpus: corpus, seedDigests: map[string]string{}}
		for _, name := range executable.inventory.Inventory {
			if !strings.HasPrefix(name, "Fuzz") {
				continue
			}
			digest, _, err := fuzzCorpusIdentity(filepath.Join(corpus, name))
			if err != nil {
				return fuzzArtifact{}, err
			}
			artifact.seedDigests[name] = digest
		}
		return artifact, nil
	})
	return artifact, err
}

func fuzzRuntimeArguments(spec fuzzSpecification, cache string, parallel int) []string {
	return []string{"-test.v=test2json", "-test.paniconexit0", "-test.run=^$", "-test.fuzz=^" + spec.Target + "$", "-test.fuzztime=10m", "-test.fuzzminimizetime=1m", "-test.parallel=" + strconv.Itoa(parallel), "-test.timeout=15m", "-test.fuzzcachedir=" + filepath.Join(cache, "fuzz", spec.importPath())}
}

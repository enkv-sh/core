package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"

	records "enkv.sh/core/internal/testrecords"
)

type preparedComponentGroup struct {
	ctx       context.Context
	cancel    context.CancelFunc
	duration  *preparedGroupDuration
	profile   string
	requested []string
	assembled assembly
}

func newPreparedComponentGroup(parent context.Context) *preparedComponentGroup {
	duration := newPreparedGroupDuration(parent, componentGroupAllowance)
	return &preparedComponentGroup{ctx: duration.ctx, cancel: duration.cancel, duration: duration}
}

// Bind the original overlay and its replacement bytes, including files outside
// the checkout. The assembly's merged overlay has separate retained identity.
func componentBootstrapIdentity(root, path string) (string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return componentBootstrapContentsIdentity(root, body)
}

func componentBootstrapContentsIdentity(root string, body []byte) (string, error) {
	var err error
	var overlay struct{ Replace map[string]string }
	if json.Unmarshal(body, &overlay) != nil || overlay.Replace == nil {
		return "", errors.New("component bootstrap unavailable")
	}
	files := map[string]string{"bootstrap": digestBytes(body)}
	for target, source := range overlay.Replace {
		if source == "" {
			files[target] = "removed"
			continue
		}
		if !filepath.IsAbs(source) {
			source = filepath.Join(root, "core", source)
		}
		files[target], err = assemblyFileSHA256(source)
		if err != nil {
			return "", err
		}
	}
	// The bootstrap overlay names a fixed source set. Bind additions/removals
	// in its three source owners as well as replacement bytes already listed.
	for _, directory := range []string{"tests/shared/runner", "tests/shared/records", "tests/shared/catalog"} {
		entries, readErr := os.ReadDir(filepath.Join(root, directory))
		if errors.Is(readErr, os.ErrNotExist) {
			files["source-list:"+directory] = "missing"
			continue
		}
		if readErr != nil {
			return "", readErr
		}
		var names []string
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") {
				names = append(names, entry.Name())
			}
		}
		body, marshalErr := json.Marshal(names)
		if marshalErr != nil {
			return "", marshalErr
		}
		files["source-list:"+directory] = digestBytes(body)
	}
	body, err = json.Marshal(files)
	return digestBytes(body), err
}

func (group *preparedComponentGroup) prepare(root, bootstrap, profile string, requested []string, source records.Source, toolchain, build string) (assembly, error) {
	return group.prepareContext(runGoEnvironment, nil, group.ctx, root, bootstrap, profile, requested, source, toolchain, build)
}

func (group *preparedComponentGroup) prepareContext(command goEnvironmentCommand, diagnostics *checkDiagnostics, ctx context.Context, root, bootstrap, profile string, requested []string, source records.Source, toolchain, build string) (assembly, error) {
	if group.assembled.Binary != "" {
		return group.verifyContextOwned(diagnostics, ctx, root, bootstrap, profile, requested, source, toolchain)
	}
	ctx, cancel := group.duration.preparationContext(ctx)
	defer cancel()
	value, err := buildAssembly(command, diagnostics, ctx, root, "hermetic", "memory", bootstrap, build)
	if err != nil {
		return assembly{}, err
	}
	if diagnostics != nil {
		if err := diagnostics.consumeCommands([]checkCommandFacts{preparationReservationFact("test2json", true)}); err != nil {
			return assembly{}, err
		}
	}
	converter, facts, err := prepareTestEventConverter(ctx, root, build)
	if facts.Process != "" && diagnostics != nil {
		err = errors.Join(err, diagnostics.append(facts))
	}
	if err != nil {
		return assembly{}, err
	}
	value.converter = converter
	value.converterRecorded = facts.Process != ""
	group.profile, group.requested = profile, slices.Clone(requested)
	value.currentPrefix = nil
	group.assembled = value
	return value, nil
}

func (group *preparedComponentGroup) verifyContext(ctx context.Context, root, bootstrap, profile string, requested []string, source records.Source, toolchain string) (assembly, error) {
	return group.verifyContextOwned(nil, ctx, root, bootstrap, profile, requested, source, toolchain)
}

func (group *preparedComponentGroup) verifyContextOwned(diagnostics *checkDiagnostics, ctx context.Context, root, bootstrap, profile string, requested []string, source records.Source, toolchain string) (assembly, error) {
	if err := ctx.Err(); err != nil {
		return assembly{}, err
	}
	if root != group.assembled.root || group.profile != profile || !slices.Equal(group.requested, requested) {
		return assembly{}, errors.New("component prepared selection changed")
	}
	if raceEnabled(ctx) != group.assembled.Closure.Race {
		return assembly{}, errors.New("component prepared race policy changed")
	}
	return group.assembled, nil
}

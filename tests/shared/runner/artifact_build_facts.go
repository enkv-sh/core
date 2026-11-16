package main

import (
	"context"
	"errors"
	"runtime/debug"
	"slices"
	"strings"

	"enkv.sh/sdk/artifact"
)

func artifactSourceModule(m resolvedModule) (*artifact.SourceModule, error) {
	if m.Replace != nil && m.Replace.Replace != nil {
		return nil, errors.New("nested source replacement refused")
	}
	row := &artifact.SourceModule{Path: m.Path, Version: m.Version, Sum: m.Sum, Dir: m.Dir, Main: m.Main}
	if m.Replace != nil {
		row.Replace = &artifact.SourceModule{Path: m.Replace.Path, Version: m.Replace.Version, Sum: m.Replace.Sum, Dir: m.Replace.Dir, Main: m.Replace.Main}
	}
	return row, nil
}

func artifactSourcePackages(modules []resolvedModule, packages []compiledPackage) ([]artifact.SourcePackage, error) {
	if len(modules) == 0 || len(modules) > 256 {
		return nil, errors.New("resolved source owner count refused")
	}
	owners := make([]*artifact.SourceModule, 0, len(modules))
	seen := map[string]bool{}
	for _, m := range modules {
		if m.Path == "" || seen[m.Path] {
			return nil, errors.New("resolved source owners refused")
		}
		seen[m.Path] = true
		row, err := artifactSourceModule(m)
		if err != nil {
			return nil, err
		}
		owners = append(owners, row)
	}
	result := make([]artifact.SourcePackage, 0, len(packages))
	for _, p := range packages {
		if p.Standard {
			continue
		}
		if p.ForTest != "" {
			return nil, errors.New("test package in artifact input")
		}
		var owner *artifact.SourceModule
		for _, m := range owners {
			if (p.ImportPath == m.Path || strings.HasPrefix(p.ImportPath, m.Path+"/")) && (owner == nil || len(m.Path) > len(owner.Path)) {
				owner = m
			}
		}
		if owner == nil {
			return nil, errors.New("selected package source owner missing")
		}
		result = append(result, artifact.SourcePackage{ImportPath: p.ImportPath, Dir: p.Dir, Module: owner, GoFiles: p.GoFiles, CgoFiles: p.CgoFiles, CFiles: p.CFiles, CXXFiles: p.CXXFiles, MFiles: p.MFiles, HFiles: p.HFiles, FFiles: p.FFiles, SFiles: p.SFiles, SwigFiles: p.SwigFiles, SwigCXXFiles: p.SwigCXXFiles, SysoFiles: p.SysoFiles, EmbedFiles: p.EmbedFiles})
	}
	return result, nil
}

func captureArtifactBuildFacts(ctx context.Context, root, role string, modules []resolvedModule, packages []compiledPackage, info *debug.BuildInfo, contracts []artifact.Contract) (artifact.BuildFacts, error) {
	sources, err := captureArtifactSources(ctx, role, modules, packages)
	if err != nil {
		return artifact.BuildFacts{}, err
	}
	options, err := artifact.CaptureBuildOptions(info)
	if err != nil {
		return artifact.BuildFacts{}, err
	}
	compiled, err := artifact.CompiledDependencies(info, sources)
	if err != nil {
		return artifact.BuildFacts{}, err
	}
	digests := map[string]artifact.Digest{}
	for _, s := range sources {
		digests[s.Module] = s.Digest
	}
	resolved := make([]artifact.Dependency, 0, len(modules))
	for _, m := range modules {
		row := artifact.Dependency{Path: m.Path, Version: m.Version, Sum: m.Sum}
		if m.Replace != nil {
			row.Replacement = &artifact.Replacement{Path: m.Replace.Path, Version: m.Replace.Version, Sum: m.Replace.Sum}
			if m.Replace.Version == "" && m.Replace.Sum == "" {
				d, ok := digests[m.Path]
				if !ok {
					return artifact.BuildFacts{}, errors.New("local replacement selected source missing")
				}
				row.Replacement.SourceDigest = d
			}
		}
		resolved = append(resolved, row)
	}
	slices.SortFunc(resolved, func(a, b artifact.Dependency) int { return strings.Compare(a.Path, b.Path) })
	contracts = slices.Clone(contracts)
	slices.SortFunc(contracts, func(a, b artifact.Contract) int {
		if c := strings.Compare(a.Kind, b.Kind); c != 0 {
			return c
		}
		if c := strings.Compare(a.Identity, b.Identity); c != 0 {
			return c
		}
		if a.Version < b.Version {
			return -1
		}
		if a.Version > b.Version {
			return 1
		}
		return 0
	})
	goos, goarch := "", ""
	for _, o := range options {
		switch o.Name {
		case "GOOS":
			goos = o.Value
		case "GOARCH":
			goarch = o.Value
		}
	}
	platform := goos + "/" + goarch
	facts := artifact.BuildFacts{Role: role, MainModule: info.Main.Path, Command: info.Path, Platform: platform, Toolchain: info.GoVersion, BuildOptions: options, Contracts: contracts, Sources: sources, Resolved: resolved, Compiled: compiled}
	if _, err := artifact.EncodeDependency(facts); err != nil {
		return artifact.BuildFacts{}, err
	}
	if err := artifact.VerifyBuildInfo(info, facts); err != nil {
		return artifact.BuildFacts{}, err
	}
	return facts, nil
}

func captureArtifactSources(ctx context.Context, role string, modules []resolvedModule, packages []compiledPackage) ([]artifact.Source, error) {
	selected, err := artifactSourcePackages(modules, packages)
	if err != nil {
		return nil, err
	}
	owners := make([]artifact.SourceModule, 0, len(modules))
	for _, module := range modules {
		owner, err := artifactSourceModule(module)
		if err != nil {
			return nil, err
		}
		owners = append(owners, *owner)
	}
	return artifact.CaptureSourcesForModules(ctx, role, selected, owners)
}

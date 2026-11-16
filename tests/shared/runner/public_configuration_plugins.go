package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/sdk/artifact"
)

func preparePublicConfigurationPlugins(ctx context.Context, root, build string, schedule catalog.Schedule, outputs []*outputArtifactClosure) ([]records.StockPluginBuild, *records.PublicManifestRenderer, error) {
	var renderer *records.PublicManifestRenderer
	manifest := false
	for _, name := range schedule.Selected {
		if row, ok := catalog.PublicConfiguration(name); ok && row.Condition == "manifest" {
			manifest = true
		}
	}
	selected := append([]*outputArtifactClosure(nil), outputs...)
	if manifest {
		var missing []outputProfileBinding
		for _, name := range []string{"ENKV/OUTPUT/GITHUB-REPOSITORY/v3", "ENKV/OUTPUT/GITHUB-ORGANIZATION/v3", "ENKV/OUTPUT/GITHUB-ENVIRONMENT/v3"} {
			binding, err := productionOutputBinding(name)
			if err != nil {
				return nil, renderer, err
			}
			if !slices.ContainsFunc(selected, func(output *outputArtifactClosure) bool { return output.Artifact.DescriptorID == binding.DescriptorID }) {
				missing = append(missing, binding)
			}
		}
		if len(missing) != 0 {
			directory := filepath.Join(build, "public-passive-output")
			if err := os.MkdirAll(directory, 0700); err != nil {
				return nil, renderer, err
			}
			passive, err := buildOutputArtifacts(ctx, root, directory, false, missing)
			if err != nil {
				return nil, renderer, err
			}
			selected = append(selected, passive...)
		}
	}
	var plugins []records.StockPluginBuild
	for _, output := range selected {
		if err := validateOutputArtifactClosures([]*outputArtifactClosure{output}); err != nil {
			return nil, renderer, err
		}
		folder := filepath.Join(build, "public-plugins", output.Metadata.Name)
		directory := output.directory
		if directory == "" {
			directory = build
		}
		if _, err := artifact.PublishBuild(ctx, folder, *output.Metadata, filepath.Join(directory, filepath.Base(output.Artifact.CommandPath)), output.DependencyManifest); err != nil {
			return nil, renderer, err
		}
		plugins = append(plugins, records.StockPluginBuild{Directory: folder, Metadata: *output.Metadata})
	}
	if manifest {
		inputs := filepath.Join(build, "public-plugin-author-inputs")
		if err := os.MkdirAll(inputs, 0700); err != nil {
			return nil, renderer, err
		}
		env, err := stockCLIEnvironment(ctx)
		if err != nil {
			return nil, renderer, err
		}
		env = environment(env, map[string]string{"GOWORK": "off"})
		tool, _, err := invocationArtifactValue(ctx, root, inputs, "plugin-author-tool", "sdk/artifact/cmd/enkv-plugin-build", func(directory string) (string, error) {
			tool := filepath.Join(directory, "enkv-plugin-build")
			_, facts, err := runGoRecordedEnvironment(ctx, root, "sdk/artifact", env, "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", tool, "./cmd/enkv-plugin-build")
			if err != nil || !facts.Started || !facts.Joined || facts.Process != "passed" {
				return "", errors.Join(errors.New("public plugin author tool unavailable"), err)
			}
			return tool, os.Chmod(tool, 0500)
		})
		if err != nil {
			return nil, renderer, err
		}
		var diagnostic limitedOutput
		workspace, err := stockCLIWorkspace(ctx, root, invocationGoBinary(ctx), inputs, env, &diagnostic)
		if err != nil {
			return nil, renderer, err
		}
		owner, err := sourcePath(root, "plugins/manifest-generators/generic-json")
		if err != nil {
			return nil, renderer, err
		}
		local, err := buildStockAuthor(ctx, root, tool, owner, "./cmd/enkv-manifest-generic-json", filepath.Join(build, "public-plugins", "generic-json"), workspace, workspace, env)
		if err != nil {
			return nil, renderer, err
		}
		measured, err := records.PublicManifestRendererFromMetadata(local.Metadata)
		if err != nil {
			return nil, renderer, err
		}
		renderer = &measured
		plugins = append(plugins, local)
	}
	slices.SortFunc(plugins, func(a, b records.StockPluginBuild) int { return strings.Compare(a.Metadata.Name, b.Metadata.Name) })
	return plugins, renderer, nil
}

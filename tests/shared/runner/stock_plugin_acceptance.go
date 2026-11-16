package main

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
)

func scheduleNeedsStockPlugins(schedule catalog.Schedule) bool {
	for _, entry := range schedule.Entries {
		if entry.Scenario == records.StockPluginScenario {
			return true
		}
	}
	return false
}

func validateStockGenerator(v generatorReference) (generatorReference, error) {
	if !cloudflareAccount.MatchString(v.Account) || !cloudflareAccount.MatchString(v.PermissionGroup) || v.CredentialsFile != "" || v.Artifact != "" {
		return generatorReference{}, errors.New("stock Cloudflare coordinates refused")
	}
	return v, nil
}

func validateStockPluginEnvironment(v *environmentFile) error {
	if v == nil || v.PluginAcceptance == nil || v.PluginAcceptance.Validate() != nil || !v.PublicConfiguration || v.Mode != "live" ||
		v.Resource.Settings["recovery_mode"] != "enabled" || v.Generator == nil {
		return errors.New("stock plugin fixture refused")
	}
	f := v.PluginAcceptance
	s := v.Resource.Settings
	if f.Provider != v.Provider || f.Region != s["region"] || f.Bucket != s["bucket"] || f.Account != s["account"] || f.Project != s["project"] || f.ProjectNumber != s["project_number"] {
		return errors.New("stock plugin fixture resource differs")
	}
	for _, role := range []string{"authority", "apply", "reader", "consumer", "cleanup"} {
		actor, ok := v.Participants[v.RoleBindings[role]]
		if !ok || actor.Access.SDK == nil || actor.Access.SDK.Validate(v.Provider) != nil ||
			v.Provider == "aws" && actor.Access.SDK.Mode != "aws-assume-role" ||
			v.Provider == "gcp" && actor.Access.SDK.Mode != "gcp-user-adc" && actor.Access.SDK.Mode != "gcp-impersonated-adc" {
			return errors.New("stock acceptance requires standard SSO-based role or user ADC contexts")
		}
	}
	_, err := validateStockGenerator(*v.Generator)
	return err
}

type stockAuthorSource struct{ directory, workspace string }

// All builds below follow the captured stock CLI. The author tool performs
// ordinary source construction; it never executes the built plugins.
func prepareStockPluginArtifact(ctx context.Context, root, directory, provider string, binding preparationBinding) (records.StockPluginArtifact, error) {
	value, _, err := invocationArtifactValue(ctx, root, filepath.Dir(directory), "stock-plugins", provider, func(build string) (records.StockPluginArtifact, error) {
		return constructStockPluginArtifact(ctx, root, filepath.Join(build, "plugins"), provider, binding)
	})
	if err != nil {
		return value, err
	}
	return cloneStockPluginArtifact(value)
}

func constructStockPluginArtifact(ctx context.Context, root, directory, provider string, binding preparationBinding) (value records.StockPluginArtifact, result error) {
	if len(records.StockPluginOutputNames(provider)) == 0 {
		return value, errors.New("stock plugin provider refused")
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		return value, err
	}
	keys := make([]stockCLIKeyInput, 2)
	for i, input := range []struct{ name, body string }{
		{"cli-public.pem", cliArchiveCLIPublicPEM},
		{"plugin-public.pem", cliArchivePluginPublicPEM},
	} {
		body := []byte(input.body)
		path := filepath.Join(directory, input.name)
		if err := os.WriteFile(path, body, 0400); err != nil {
			return value, err
		}
		keys[i] = stockCLIKeyInput{path: path, expected: artifact.DigestLength{SHA256: artifact.Hash(body), Length: uint64(len(body))}}
	}
	owner, err := newCurrentDirectory("enkv-stock-cli-")
	if err != nil {
		return value, err
	}
	defer func() {
		if err := owner.remove(toolCommandsJoined(result)); err != nil {
			result = errors.Join(result, fmt.Errorf("stock CLI temporary owner %s: %w", owner.path, err))
		}
	}()
	stock, err := prepareStockCLI(ctx, root, filepath.Join(owner.path, "stock-cli"), stockCLIConstruction{version: "0.1.0", cliKey: keys[0], pluginKeys: keys[1:]}, binding)
	if err != nil {
		return value, err
	}
	facts := stock.facts()
	value = records.StockPluginArtifact{Schema: 1, CLI: records.StockPluginFile{Path: facts.executablePath, SHA256: facts.executable.SHA256.String(), Length: facts.executable.Length}, Archive: records.StockPluginFile{Path: facts.archivePath, SHA256: facts.archive.SHA256.String(), Length: facts.archive.Length}, Platform: facts.nativeTuple, Toolchain: facts.compiler, Source: facts.source}
	env := environment(stock.buildEnvironment, map[string]string{"GOWORK": "off"})
	tool, _, err := invocationArtifactValue(ctx, root, directory, "plugin-author-tool", "sdk/artifact/cmd/enkv-plugin-build", func(build string) (string, error) {
		tool := filepath.Join(build, "enkv-plugin-build")
		_, command, err := runGoRecordedEnvironment(ctx, root, "sdk/artifact", env, "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", tool, "./cmd/enkv-plugin-build")
		if err != nil || !command.Started || !command.Joined || command.Process != "passed" {
			return "", errors.Join(errors.New("stock plugin author tool construction refused"), err)
		}
		return tool, os.Chmod(tool, 0500)
	})
	if err != nil {
		return value, err
	}
	// Authoring can extend its own workspace sums. The captured CLI's
	// workspace and sums remain immutable inputs to stock revalidation.
	work, _, err := readPublicConfigurationFileContext(ctx, stock.workspace, artifact.MaxMetadataBytes, 0400)
	if err != nil {
		return value, err
	}
	authorWorkspace := filepath.Join(directory, "author.work")
	if err := os.WriteFile(authorWorkspace, work, 0400); err != nil {
		return value, err
	}

	build := func(selector, command, label, workspace string) (records.StockPluginBuild, error) {
		owner, err := sourcePath(root, selector)
		if err != nil {
			return records.StockPluginBuild{}, err
		}
		return buildStockAuthor(ctx, root, tool, owner, command, filepath.Join(directory, label), workspace, stock.workspace, stock.buildEnvironment)
	}
	value.GeneratorA, err = build("plugins/cloudflare", "./cmd/enkv-generator-cloudflare", "generator-a", authorWorkspace)
	if err != nil {
		return value, err
	}
	bSource, _, err := invocationArtifactValue(ctx, root, directory, "stock-generator-source", stock.workspace, func(build string) (stockAuthorSource, error) {
		author, err := sourcePath(root, "plugins/cloudflare")
		if err != nil {
			return stockAuthorSource{}, err
		}
		bAuthor := filepath.Join(build, "generator-b-source")
		if err := copyStockAuthorSource(author, bAuthor); err != nil {
			return stockAuthorSource{}, err
		}
		profile := filepath.Join(bAuthor, "profile", "artifact.go")
		body, err := os.ReadFile(profile)
		if err != nil || bytes.Count(body, []byte(`"CLOUDFLARE_API_TOKEN"`)) != 1 {
			return stockAuthorSource{}, errors.New("Cloudflare B credential source differs")
		}
		if err := os.WriteFile(profile, bytes.Replace(body, []byte(`"CLOUDFLARE_API_TOKEN"`), []byte(`"CLOUDFLARE_API_TOKEN_B"`), 1), 0600); err != nil {
			return stockAuthorSource{}, err
		}
		descriptorPath := filepath.Join(bAuthor, "cmd", "enkv-generator-cloudflare", "plugin.json")
		descriptor, _, err := artifact.ReadDescriptor(ctx, descriptorPath)
		if err != nil {
			return stockAuthorSource{}, err
		}
		route, err := credentialroute.Decode(descriptor.Generator.CredentialRoute)
		if err != nil {
			return stockAuthorSource{}, err
		}
		route.Names = []string{"CLOUDFLARE_API_TOKEN_B"}
		descriptor.Generator.CredentialRoute, err = credentialroute.Encode(route)
		if err != nil {
			return stockAuthorSource{}, err
		}
		descriptor.Version += "-acceptance-b"
		body, err = artifact.EncodeDescriptor(descriptor)
		if err != nil {
			return stockAuthorSource{}, err
		}
		if err := os.WriteFile(descriptorPath, body, 0600); err != nil {
			return stockAuthorSource{}, err
		}
		quotedAuthor := []byte(strconv.Quote(filepath.ToSlash(author)))
		if !bytes.Contains(work, quotedAuthor) {
			return stockAuthorSource{}, errors.New("stock plugin workspace owner unavailable")
		}
		bWorkspace := filepath.Join(build, "generator-b.work")
		bWork := bytes.ReplaceAll(work, quotedAuthor, []byte(strconv.Quote(filepath.ToSlash(bAuthor))))
		if len(bWork) > artifact.MaxMetadataBytes {
			return stockAuthorSource{}, errors.New("stock plugin workspace exceeds bound")
		}
		if err := os.WriteFile(bWorkspace, bWork, 0400); err != nil {
			return stockAuthorSource{}, err
		}

		return stockAuthorSource{directory: bAuthor, workspace: bWorkspace}, nil
	})
	if err != nil {
		return value, err
	}
	bAuthor, bWorkspace := bSource.directory, bSource.workspace
	value.GeneratorB, err = buildStockAuthor(ctx, root, tool, bAuthor, "./cmd/enkv-generator-cloudflare", filepath.Join(directory, "generator-b"), bWorkspace, bWorkspace, stock.buildEnvironment)
	if err != nil {
		return value, err
	}
	for _, name := range records.StockPluginOutputNames(provider) {
		selector, command := "", ""
		if strings.HasPrefix(name, "github-actions-") {
			selector = "plugins/github-output"
			command = "enkv-output-github-" + strings.TrimPrefix(name, "github-actions-")
		} else if name == "aws-secrets-manager" {
			selector, command = "plugins/aws-output", "enkv-output-aws-secrets-manager"
		} else if name == "gcp-secret-manager" {
			selector, command = "plugins/gcp-output", "enkv-output-gcp-secret-manager"
		}
		plugin, err := build(selector, "./cmd/"+command, name, authorWorkspace)
		if err != nil {
			return value, err
		}
		value.Outputs = append(value.Outputs, plugin)
	}
	value.Renderer, err = build("sdk/examples/ini-reference-manifest", ".", "renderer", authorWorkspace)
	if err != nil {
		return value, err
	}
	for _, workspace := range []string{authorWorkspace, bWorkspace} {
		sum := workspace + ".sum"
		info, err := os.Lstat(sum)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return value, err
		}
		if _, _, err := readPublicConfigurationFileContext(ctx, sum, artifact.MaxMetadataBytes, info.Mode().Perm()); err != nil {
			return value, err
		}
		if err := os.Chmod(sum, 0400); err != nil {
			return value, err
		}

	}
	cli := filepath.Join(directory, "enkv")
	if err := linkInvocationFile(value.CLI.Path, cli); err != nil {
		return value, err
	}
	archive := filepath.Join(directory, "enkv.tar.gz")
	if err := linkInvocationFile(value.Archive.Path, archive); err != nil {
		return value, err
	}
	value.CLI.Path, value.Archive.Path = cli, archive
	return value, verifyStockPluginArtifact(ctx, value, provider)
}

func buildStockAuthor(ctx context.Context, root, tool, owner, command, output, workspace, workspaceOwner string, env []string) (records.StockPluginBuild, error) {
	env = environment(env, map[string]string{"GOWORK": "off"})
	var value records.StockPluginBuild
	descriptor := "plugin.json"
	if command != "." {
		descriptor = filepath.Join(strings.TrimPrefix(command, "./"), descriptor)
	}
	value, _, err := invocationArtifactValue(ctx, root, output, "stock-plugin", struct {
		Owner, Command, Tool, Workspace string
		Environment                     []string
	}{owner, command, tool, workspaceOwner, env}, func(build string) (records.StockPluginBuild, error) {
		if invocationArtifactsFrom(ctx) != nil {
			build = filepath.Join(build, "artifact")
		}
		stdout, stderr, _, err := stockCLIProcess(ctx, tool, owner, env, "-directory", owner, "-descriptor", descriptor, "-command", command, "-workspace", workspace, "-output", build)
		clear(stdout)
		clear(stderr)
		if err != nil {
			return value, err
		}
		metadata, err := artifact.VerifyBuild(ctx, build)
		if err != nil {
			return value, err
		}
		return records.StockPluginBuild{Directory: build, Metadata: metadata}, nil
	})
	if err != nil {
		return value, err
	}
	if err := linkInvocationDirectory(value.Directory, output); err != nil {
		return value, err
	}
	value.Directory = output
	return value, nil
}

func copyStockAuthorSource(source, destination string) error {
	var count, total int
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil || strings.HasPrefix(relative, "..") {
			return errors.New("stock author source path refused")
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.Mkdir(target, 0700)
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 || count >= 512 || total > 8<<20 {
			return errors.New("stock author source bound refused")
		}
		body, _, err := readPublicConfigurationFile(path, 1<<20, info.Mode().Perm())
		if err != nil {
			return err
		}
		if total+len(body) > 8<<20 {
			return errors.New("stock author total source bound refused")
		}
		count++
		total += len(body)
		return os.WriteFile(target, body, 0600)
	})
}

func verifyStockPluginArtifact(ctx context.Context, value records.StockPluginArtifact, provider string) error {
	if value.Validate(provider) != nil || value.Platform != runtime.GOOS+"/"+runtime.GOARCH {
		return errors.New("stock plugin artifact shape refused")
	}
	for _, file := range []records.StockPluginFile{value.CLI, value.Archive} {
		identity, _, err := stockCLIFileIdentity(ctx, file.Path, artifact.MaxArchiveBytes, true)
		if err != nil || identity.SHA256.String() != file.SHA256 || identity.Length != file.Length {
			return errors.New("stock plugin CLI or archive bytes changed")
		}
	}
	info, err := buildinfo.ReadFile(value.CLI.Path)
	if err != nil || info.GoVersion != value.Toolchain || info.Path != "enkv.sh/compositions/full/cmd/enkv" {
		return errors.New("stock plugin CLI native construction differs")
	}
	plugins := append([]records.StockPluginBuild{value.GeneratorA, value.GeneratorB, value.Renderer}, value.Outputs...)
	for _, plugin := range plugins {
		actual, err := artifact.VerifyBuild(ctx, plugin.Directory)
		if err != nil || !reflect.DeepEqual(actual, plugin.Metadata) {
			return errors.New("stock plugin build bytes changed")
		}
	}
	return nil
}

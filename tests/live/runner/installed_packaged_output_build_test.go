package core

import (
	"context"
	"encoding/json"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/outputhost"
	"enkv.sh/crypto/testsupport/custody"
	"enkv.sh/sdk/artifact"
)

type packagedOutputPair struct{ first, second custody.PublicationConfig }

func packagedOutputBuilds(t *testing.T, ctx context.Context, origin string) map[string]packagedOutputPair {
	t.Helper()
	address, err := url.Parse(origin)
	if err != nil || address.Scheme != "http" || address.User != nil || address.Path != "" || address.RawQuery != "" || address.Fragment != "" || !net.ParseIP(address.Hostname()).IsLoopback() || address.Port() == "" {
		t.Fatal("controlled output origin is not loopback")
	}
	_, cloudflare := hermeticCloudflarePluginDirectory(t)
	public := filepath.Clean(filepath.Join(cloudflare, "..", "..", ".."))
	directory := t.TempDir()
	t.Cleanup(func() {
		// Public builds are read-only after verification. Restore only this
		// test's directories before TempDir removes its owned tree.
		err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return os.Chmod(path, 0700)
			}
			return nil
		})
		if err != nil {
			t.Error("restore controlled public build directories", err)
		}
	})
	tool := filepath.Join(directory, "enkv-plugin-build")
	buildTool := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", tool, "./cmd/enkv-plugin-build")
	buildTool.Dir = filepath.Join(public, "sdk", "artifact")
	packagedOutputBuildCommand(t, buildTool)
	selectedModules := []string{livePublicationCloudScope}
	if livePublicationCloudScope == "aws-secrets-manager" {
		selectedModules = append(selectedModules, "github-actions")
	}
	modules := map[string]string{}
	for _, row := range []struct{ name, client, anchor string }{
		{"aws-secrets-manager", "internal/awssm/client.go", "return Implementation{transport:"},
		{"gcp-secret-manager", "internal/gcpsm/client.go", "return Implementation{transport:"},
		{"github-actions", "internal/github/client.go", "endpoint: apiHost"},
	} {
		if !slices.Contains(selectedModules, row.name) {
			continue
		}
		target := filepath.Join(directory, row.name)
		if err := os.CopyFS(target, os.DirFS(filepath.Join(public, "plugins", "outputs", row.name))); err != nil {
			t.Fatal(err)
		}
		source := filepath.Join(target, filepath.FromSlash(row.client))
		body, err := os.ReadFile(source)
		if err != nil || strings.Count(string(body), row.anchor) != 1 {
			t.Fatal("controlled output source anchor differs", row.name, err)
		}
		replacement := "return Implementation{endpoint: " + strconv.Quote(origin) + ", transport:"
		if row.name == "github-actions" {
			replacement = "endpoint: " + strconv.Quote(origin)
		}
		if err := os.WriteFile(source, []byte(strings.Replace(string(body), row.anchor, replacement, 1)), 0600); err != nil {
			t.Fatal(err)
		}
		modules[row.name] = target
	}
	workspace := filepath.Join(directory, "go.work")
	workspaceBody := "go 1.27.0\nuse (\n"
	for _, name := range selectedModules {
		workspaceBody += strconv.Quote(modules[name]) + "\n"
	}
	for _, name := range []string{"sdk/artifact", "sdk/output", "sdk/protocols/output"} {
		workspaceBody += strconv.Quote(filepath.Join(public, filepath.FromSlash(name))) + "\n"
	}
	workspaceBody += ")\n"
	// Full graph loading still requests each required version's go.mod.
	// Pin the three public owners exactly, as the detached public
	// build fixture does; use alone does not satisfy those versioned reads.
	for _, name := range []string{"sdk/artifact", "sdk/output", "sdk/protocols/output"} {
		workspaceBody += "replace enkv.sh/" + name + " v0.1.0 => " + strconv.Quote(filepath.Join(public, filepath.FromSlash(name))) + "\n"
	}
	if err := os.WriteFile(workspace, []byte(workspaceBody), 0600); err != nil {
		t.Fatal(err)
	}
	packagedOutputEnvironment(t)
	t.Setenv("GITHUB_TOKEN", "github_pat_NATIVE_OUTPUT")
	result := map[string]packagedOutputPair{}
	for _, row := range []struct{ name, module, command string }{
		{"aws-secrets-manager", "aws-secrets-manager", "enkv-output-aws-secrets-manager"},
		{"gcp-secret-manager", "gcp-secret-manager", "enkv-output-gcp-secret-manager"},
		{"github-actions-repository", "github-actions", "enkv-output-github-repository"},
		{"github-actions-organization", "github-actions", "enkv-output-github-organization"},
		{"github-actions-environment", "github-actions", "enkv-output-github-environment"},
	} {
		if !slices.Contains(selectedModules, row.module) {
			continue
		}
		var pair packagedOutputPair
		var prior artifact.Metadata
		for i, version := range []string{"0.0.1", "0.0.2"} {
			command := "./cmd/" + row.command
			source := filepath.Join(modules[row.module], "cmd", row.command, "installation_revision.go")
			body := "package main\nimport \"os\"\nfunc init(){if len(os.Args)==0 {panic(" + strconv.Quote(version) + ")}}\n"
			if err := os.WriteFile(source, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(directory, row.name+"-"+version)
			descriptorPath := filepath.Join(modules[row.module], "cmd", row.command, "plugin.json")
			descriptorBody, err := os.ReadFile(descriptorPath)
			if err != nil {
				t.Fatal(err)
			}
			var descriptor map[string]any
			if err := json.Unmarshal(descriptorBody, &descriptor); err != nil {
				t.Fatal(err)
			}
			descriptor["version"] = version
			descriptorBody, err = json.Marshal(descriptor)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(descriptorPath, descriptorBody, 0600); err != nil {
				t.Fatal(err)
			}
			build := exec.CommandContext(ctx, tool, "-directory", modules[row.module], "-descriptor", descriptorPath, "-command", command, "-output", output, "-workspace", workspace)
			build.Dir = directory
			packagedOutputBuildCommand(t, build)
			markerBody, err := os.ReadFile(filepath.Join(output, "build.json"))
			if err != nil {
				t.Fatal(err)
			}
			marker, err := artifact.DecodeBuildMarker(markerBody)
			if err != nil {
				t.Fatal(err)
			}
			metadata, err := artifact.VerifyBuild(ctx, output)
			if err != nil {
				t.Fatal(err)
			}
			folder := filepath.Join(output, filepath.FromSlash(marker.Directory))
			encoded, err := os.ReadFile(filepath.Join(folder, "metadata.json"))
			if err != nil {
				t.Fatal(err)
			}
			dependency, err := os.ReadFile(filepath.Join(folder, "dependencies.bin"))
			if err != nil {
				t.Fatal(err)
			}
			installed, err := outputhost.NewInstallation(metadata, dependency)
			if err != nil {
				t.Fatal(err)
			}
			config := custody.PublicationConfig{ArtifactPath: filepath.Join(folder, "plugin"), Artifact: installed.Artifact(), Metadata: encoded, Dependency: dependency}
			if i == 0 {
				pair.first = config
				prior = metadata
			} else {
				pair.second = config
				if pair.first.Artifact.SHA256 == config.Artifact.SHA256 || pair.first.Artifact.ExecutorID == config.Artifact.ExecutorID || artifact.Hash(pair.first.Metadata) == marker.Artifact || !reflect.DeepEqual(prior.Contracts, metadata.Contracts) {
					t.Fatal("controlled output builds are not independent compatible implementations", row.name)
				}
			}
		}
		result[row.name] = pair
	}
	return result
}

func packagedOutputBuildCommand(t testing.TB, command *exec.Cmd) {
	t.Helper()
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		switch key {
		case "GOWORK", "GOTOOLCHAIN", "GOENV", "GOFLAGS", "GOPROXY", "GOSUMDB":
			continue
		}
		command.Env = append(command.Env, value)
	}
	command.Env = append(command.Env, "GOWORK=off", "GOTOOLCHAIN=local", "GOENV=off", "GOFLAGS=", "GOPROXY=off", "GOSUMDB=off")
	command.WaitDelay = 5 * time.Second
	var output operatorCLIOutput
	command.Stdout, command.Stderr = &output, &output
	err := command.Run()
	body, overflow := output.result()
	defer clear(body)
	defer clear(output.body)
	if err != nil || overflow || command.ProcessState == nil || !command.ProcessState.Exited() {
		t.Fatalf("controlled public build did not complete and join: %v; bounded output: %s", err, body)
	}
}

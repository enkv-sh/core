package nativeprocess

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/sdk/artifact"
)

type nativePluginFixture struct {
	home   string
	builds []artifact.LocalPlugin
}

func newNativePluginFixture(t *testing.T, builds ...artifact.LocalPlugin) nativePluginFixture {
	t.Helper()
	selected := slices.Clone(builds)
	for i := range selected {
		directory, err := filepath.EvalSymlinks(selected[i].Directory)
		if err != nil {
			t.Fatal("native plugin build directory unavailable", err)
		}
		selected[i].Directory = directory
	}
	slices.SortFunc(selected, func(a, b artifact.LocalPlugin) int { return strings.Compare(a.Name, b.Name) })
	return nativePluginFixture{home: nativeGeneratedPrivateDirectory(t), builds: selected}
}

func (f nativePluginFixture) Environment(t *testing.T, source string) []string {
	t.Helper()
	scope, err := filepath.EvalSymlinks(filepath.Dir(source))
	if err != nil {
		t.Fatal("native plugin application directory unavailable", err)
	}
	xdg := filepath.Join(f.home, ".config")
	config := xdg
	if runtime.GOOS == "darwin" {
		config = filepath.Join(f.home, "Library", "Application Support")
	}
	for _, directory := range []string{xdg, filepath.Join(config, "enkv")} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(config, "enkv", "plugins.json")
	settings := artifact.Settings{Schema: "enkv/plugin-settings/v1", Applications: []artifact.Application{{Directory: scope, Plugins: slices.Clone(f.builds)}}}
	body, err := artifact.EncodeSettings(settings)
	if err != nil {
		t.Fatal("native plugin settings refused", err)
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	return []string{"HOME=" + f.home, "XDG_CONFIG_HOME=" + xdg}
}

func nativePluginLinkerFlags() string {
	return "-X=enkv.sh/compositions/full.installedCLIVerificationKey=3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c -X=enkv.sh/compositions/full.installedPluginKeys=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a -X=enkv.sh/compositions/full.installedPluginOrigin=https://127.0.0.1:1/releases/"
}

// nativePluginWorkspace binds exact required versions to their selected local
// owners. A use row alone need not prevent complete graph loading from fetching
// a required workspace owner's versioned module metadata.
func nativePluginWorkspace(t *testing.T, directories []string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	directories = slices.Clone(directories)
	for i, directory := range directories {
		absolute, err := filepath.Abs(directory)
		if err != nil {
			t.Fatal("native plugin workspace owner unavailable", err)
		}
		directories[i], err = filepath.EvalSymlinks(absolute)
		if err != nil {
			t.Fatal("native plugin workspace owner unavailable", err)
		}
	}
	slices.Sort(directories)
	directories = slices.Compact(directories)
	type requirement struct{ Path, Version string }
	owners := make(map[string]string, len(directories))
	var requirements []requirement
	var work strings.Builder
	work.WriteString("go 1.27.0\n\nuse (\n")
	for _, directory := range directories {
		command := exec.CommandContext(ctx, "go", "mod", "edit", "-json", "-modfile="+filepath.Join(directory, "go.mod"))
		command.Dir = directory
		overrides := map[string]string{"GOWORK": "off", "GOENV": "off", "GOTOOLCHAIN": "local", "GOFLAGS": "", "GO111MODULE": "on", "GOPROXY": "off", "GOSUMDB": "off", "GONOPROXY": "none"}
		for _, entry := range os.Environ() {
			key, _, _ := strings.Cut(entry, "=")
			if _, replaced := overrides[key]; !replaced {
				command.Env = append(command.Env, entry)
			}
		}
		for key, value := range overrides {
			command.Env = append(command.Env, key+"="+value)
		}
		body, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("native plugin workspace module parse failed: %v\n%s", err, body)
		}
		var parsed struct {
			Module  struct{ Path string }
			Require []requirement
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			t.Fatal("native plugin workspace module facts unavailable", err)
		}
		if parsed.Module.Path == "" || owners[parsed.Module.Path] != "" {
			t.Fatal("native plugin workspace module identity missing or repeated", parsed.Module.Path)
		}
		owners[parsed.Module.Path] = directory
		requirements = append(requirements, parsed.Require...)
		fmt.Fprintf(&work, "\t%q\n", filepath.ToSlash(directory))
	}
	work.WriteString(")\n")
	seen := make(map[requirement]bool)
	var replacements []requirement
	for _, row := range requirements {
		if owners[row.Path] == "" || seen[row] {
			continue
		}
		if row.Version == "" {
			t.Fatal("native plugin workspace owned requirement has no version", row.Path)
		}
		seen[row] = true
		replacements = append(replacements, row)
	}
	slices.SortFunc(replacements, func(a, b requirement) int {
		if a.Path != b.Path {
			return strings.Compare(a.Path, b.Path)
		}
		return strings.Compare(a.Version, b.Version)
	})
	if len(replacements) != 0 {
		work.WriteString("\nreplace (\n")
		for _, row := range replacements {
			fmt.Fprintf(&work, "\t%s %s => %q\n", row.Path, row.Version, filepath.ToSlash(owners[row.Path]))
		}
		work.WriteString(")\n")
	}
	workspace := filepath.Join(t.TempDir(), "go.work")
	if err := os.WriteFile(workspace, []byte(work.String()), 0600); err != nil {
		t.Fatal(err)
	}
	return workspace
}

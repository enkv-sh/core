package main

import (
	"archive/zip"
	"context"
	"debug/buildinfo"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func runModuleModeCommand(t *testing.T, ctx context.Context, directory string, env map[string]string, args ...string) []byte {
	t.Helper()
	command := exec.Command("go", args...)
	command.Dir = directory
	command.Env = environment(goEnvironment(), env)
	output := new(limitedOutput)
	command.Stdout, command.Stderr = output, output
	result := superviseProcess(ctx, command)
	if result.Status != "passed" || !result.Started || !result.Joined || output.overflow {
		t.Fatalf("module build failed: result=%+v output=%s", result, output.String())
	}
	return append([]byte(nil), output.Bytes()...)
}

// full_only: false
func TestCoordinatedWorkspaceRecordsLocalModuleClosure(t *testing.T) {
	root, docs := distributionRoots(t)
	owner, err := sourcePath(root, "sdk/examples/ini-reference-manifest")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	env := map[string]string{"GOWORK": "off", "GOPROXY": "off", "GOSUMDB": "off", "GONOPROXY": "none"}
	workspaceJSON := runModuleModeCommand(t, ctx, docs, env, "work", "edit", "-json", filepath.Join(docs, "go.work"))
	var workspace struct {
		Go      string
		Use     []struct{ DiskPath string }
		Replace []struct {
			Old, New struct{ Path, Version string }
		}
	}
	if err := json.Unmarshal(workspaceJSON, &workspace); err != nil {
		t.Fatal(err)
	}
	if workspace.Go != "1.27.0" || len(workspace.Use) != len(moduleSources) {
		t.Fatal("generated workspace differs", workspace)
	}
	expected := make(map[string]bool, len(moduleSources))
	ownersByModule := make(map[string]string, len(moduleSources))
	for _, row := range moduleSources {
		owner, err := moduleSourceDirectory(root, row)
		if err != nil {
			t.Fatal(err)
		}
		expected[owner] = true
		ownersByModule[row.Module] = owner
	}
	expectedReplacements := make(map[string]string)
	for _, row := range moduleSources {
		body := runModuleModeCommand(t, ctx, ownersByModule[row.Module], env, "mod", "edit", "-json")
		var parsed struct {
			Module  struct{ Path string }
			Require []struct{ Path, Version string }
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			t.Fatal(err)
		}
		if parsed.Module.Path != row.Module {
			t.Fatal("workspace module source identity differs", row.Module, parsed.Module.Path)
		}
		for _, required := range parsed.Require {
			if owner := ownersByModule[required.Path]; owner != "" {
				expectedReplacements[required.Path+"\x00"+required.Version] = owner
			}
		}
	}
	var privateWorkspace strings.Builder
	privateWorkspace.WriteString("go 1.27.0\n\nuse (\n")
	for _, use := range workspace.Use {
		absolute := use.DiskPath
		if !filepath.IsAbs(absolute) {
			absolute = filepath.Join(docs, absolute)
		}
		absolute = filepath.Clean(absolute)
		if !expected[absolute] {
			t.Fatal("workspace owner differs", use.DiskPath)
		}
		delete(expected, absolute)
		fmt.Fprintf(&privateWorkspace, "\t%q\n", filepath.ToSlash(absolute))
	}
	if len(expected) != 0 {
		t.Fatal("workspace owner missing", expected)
	}
	privateWorkspace.WriteString(")\n")
	if len(workspace.Replace) != len(expectedReplacements) {
		t.Fatal("workspace versioned replacement set differs", len(workspace.Replace), len(expectedReplacements))
	}
	previousReplacement := ""
	if len(workspace.Replace) > 0 {
		privateWorkspace.WriteString("\nreplace (\n")
	}
	for _, replacement := range workspace.Replace {
		key := replacement.Old.Path + "\x00" + replacement.Old.Version
		absolute := replacement.New.Path
		if !filepath.IsAbs(absolute) {
			absolute = filepath.Join(docs, absolute)
		}
		absolute = filepath.Clean(absolute)
		if replacement.Old.Version == "" || replacement.New.Version != "" || expectedReplacements[key] != absolute || key <= previousReplacement {
			t.Fatal("workspace replacement lost exact version or source ownership", replacement)
		}
		previousReplacement = key
		delete(expectedReplacements, key)
		fmt.Fprintf(&privateWorkspace, "\t%s %s => %q\n", replacement.Old.Path, replacement.Old.Version, filepath.ToSlash(absolute))
	}
	if len(workspace.Replace) > 0 {
		privateWorkspace.WriteString(")\n")
	}
	if len(expectedReplacements) != 0 {
		t.Fatal("workspace versioned replacement missing", expectedReplacements)
	}
	privateWorkfile := filepath.Join(t.TempDir(), "go.work")
	if err := os.WriteFile(privateWorkfile, []byte(privateWorkspace.String()), 0600); err != nil {
		t.Fatal(err)
	}
	env["GOWORK"] = privateWorkfile
	// Full graph loading must not request unpublished versions of workspace owners.
	graph := runModuleModeCommand(t, ctx, owner, env, "list", "-mod=readonly", "-m", "-json", "all")
	graphModules, err := decodeObjects[resolvedModule](graph)
	if err != nil {
		t.Fatal(err)
	}
	mainOwners := make(map[string]bool)
	for _, module := range graphModules {
		row, registered := registeredModule(module.Path)
		if !registered {
			continue
		}
		local, err := moduleSourceDirectory(root, row)
		if err != nil {
			t.Fatal(err)
		}
		if mainOwners[module.Path] || !module.Main || module.Version != "" || module.Replace != nil || module.Dir != local {
			t.Fatal("workspace graph lost exact local owner", module)
		}
		mainOwners[module.Path] = true
	}
	if len(mainOwners) != len(moduleSources) {
		t.Fatal("workspace graph omitted local owners", len(mainOwners), len(moduleSources))
	}
	for _, test := range []struct{ selector, module string }{
		{"sdk/examples/ini-reference-manifest", manifestExamplePath},
	} {
		t.Run(test.selector, func(t *testing.T) {
			owner, err := sourcePath(root, test.selector)
			if err != nil {
				t.Fatal(err)
			}
			body := runModuleModeCommand(t, ctx, owner, env, "list", "-m", "-json", "enkv.sh/sdk/artifact", manifestSDKPath, "enkv.sh/sdk/protocols/manifest-generator", test.module)
			modules, err := decodeObjects[resolvedModule](body)
			if err != nil {
				t.Fatal(err)
			}
			if len(modules) != 4 {
				t.Fatal("local module closure differs", modules)
			}
			for _, module := range modules {
				row, ok := registeredModule(module.Path)
				if !ok {
					t.Fatal("unregistered workspace module", module.Path)
				}
				expected, err := moduleSourceDirectory(root, row)
				if err != nil {
					t.Fatal(err)
				}
				if !module.Main || module.Version != "" || module.Replace != nil || module.Dir != expected {
					t.Fatal("workspace did not use local source", module)
				}
			}
			binary := filepath.Join(t.TempDir(), "manifest")
			runModuleModeCommand(t, ctx, owner, env, "build", "-p=1", "-trimpath", "-buildvcs=false", "-o", binary, ".")
			info, err := buildinfo.ReadFile(binary)
			if err != nil {
				t.Fatal(err)
			}
			if len(info.Deps) != 3 {
				t.Fatal("workspace compiled closure differs", info.Deps)
			}
			for _, dep := range info.Deps {
				if dep.Path != "enkv.sh/sdk/artifact" && dep.Path != manifestSDKPath && dep.Path != "enkv.sh/sdk/protocols/manifest-generator" || dep.Version != "(devel)" || dep.Replace != nil {
					t.Fatal("workspace build lost local identity", dep)
				}
			}
		})
	}
}

// full_only: false
func TestPinnedPublicModuleArchivesRecordVersionedClosure(t *testing.T) {
	root, _ := distributionRoots(t)
	const version = "v0.1.7"
	fixtureMod := []byte("module example.invalid/consumer\n\nrequire (\n\tenkv.sh/sdk/artifact v0.1.1\n\tenkv.sh/sdk/protocols/output v0.1.0\n\tenkv.sh/sdk/generator v0.0.0-20240905190251-b4127c9b8d78\n\texample.invalid/external v0.1.0\n\texample.invalid/pseudo v0.0.0-20240905190251-b4127c9b8d78\n)\n")
	expectedMod := "module example.invalid/consumer\n\nrequire (\n\tenkv.sh/sdk/artifact v0.1.7\n\tenkv.sh/sdk/protocols/output v0.1.7\n\tenkv.sh/sdk/generator v0.1.7\n\texample.invalid/external v0.1.0\n\texample.invalid/pseudo v0.0.0-20240905190251-b4127c9b8d78\n)\n"
	if got := string(publicModuleFixtureVersions(fixtureMod, version)); got != expectedMod {
		t.Fatal("synthetic module version rewrite changed external pins", got)
	}
	proxy := t.TempDir()
	for _, selector := range []string{"sdk/artifact", "protocols/manifest-generator", "sdk/manifest-generator"} {
		row, ok := registeredModule(selector)
		if !ok {
			t.Fatal("archive owner missing", selector)
		}
		owner, err := moduleSourceDirectory(root, row)
		if err != nil {
			t.Fatal(err)
		}
		modbody, err := os.ReadFile(filepath.Join(owner, "go.mod"))
		if err != nil {
			t.Fatal(err)
		}
		writePublicModuleArchive(t, proxy, owner, row.Module, version, publicModuleFixtureVersions(modbody, version))
	}
	for _, test := range []struct{ selector, module string }{
		{"sdk/examples/ini-reference-manifest", manifestExamplePath},
	} {
		t.Run(test.selector, func(t *testing.T) {
			owner, err := sourcePath(root, test.selector)
			if err != nil {
				t.Fatal(err)
			}
			main := t.TempDir()
			err = filepath.WalkDir(owner, func(name string, entry fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if entry.IsDir() {
					return nil
				}
				if !entry.Type().IsRegular() {
					return fmt.Errorf("nonregular public source")
				}
				relative, err := filepath.Rel(owner, name)
				if err != nil {
					return err
				}
				body, err := os.ReadFile(name)
				if err != nil {
					return err
				}
				if relative == "go.mod" {
					body = publicModuleFixtureVersions(body, version)
					if strings.Contains(string(body), "replace ") {
						return fmt.Errorf("published module contains replacement")
					}
				}
				target := filepath.Join(main, relative)
				if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
					return err
				}
				return os.WriteFile(target, body, 0600)
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			proxyURL := (&url.URL{Scheme: "file", Path: filepath.ToSlash(proxy)}).String()
			env := map[string]string{"GOWORK": "off", "GOPROXY": proxyURL, "GOSUMDB": "off", "GONOPROXY": "none", "GONOSUMDB": "none", "GOPRIVATE": "", "GOMODCACHE": t.TempDir()}
			env["GOFLAGS"] = buildGoFlags + " -modcacherw"
			runModuleModeCommand(t, ctx, main, env, "mod", "download", "all")
			body := runModuleModeCommand(t, ctx, main, env, "list", "-mod=readonly", "-m", "-json", "all")
			modules, err := decodeObjects[resolvedModule](body)
			if err != nil {
				t.Fatal(err)
			}
			if len(modules) != 4 {
				t.Fatal("pinned resolved closure differs", modules)
			}
			for _, module := range modules {
				if module.Main {
					if module.Path != test.module || module.Replace != nil {
						t.Fatal("pinned main differs", module)
					}
				} else if module.Path != "enkv.sh/sdk/artifact" && module.Path != manifestSDKPath && module.Path != "enkv.sh/sdk/protocols/manifest-generator" || module.Version != version || module.Replace != nil || module.Sum == "" {
					t.Fatal("pinned dependency differs", module)
				}
			}
			binary := filepath.Join(t.TempDir(), "manifest")
			runModuleModeCommand(t, ctx, main, env, "build", "-mod=readonly", "-p=1", "-trimpath", "-buildvcs=false", "-o", binary, ".")
			info, err := buildinfo.ReadFile(binary)
			if err != nil {
				t.Fatal(err)
			}
			if len(info.Deps) != 3 {
				t.Fatal("pinned compiled closure differs", info.Deps)
			}
			for _, dep := range info.Deps {
				if dep.Path != "enkv.sh/sdk/artifact" && dep.Path != manifestSDKPath && dep.Path != "enkv.sh/sdk/protocols/manifest-generator" || dep.Version != version || dep.Replace != nil || dep.Sum == "" {
					t.Fatal("pinned build used local source", dep)
				}
			}
		})
	}
}

func publicModuleFixtureVersions(body []byte, version string) []byte {
	// Only first-party requirements belong to this synthetic proxy. External pins
	// retain their original bytes, including any equal version or pseudo-version.
	pattern := regexp.MustCompile(`(?m)(\benkv\.sh/[^\s]+[ \t]+)v[^\s]+`)
	return pattern.ReplaceAll(body, []byte(`${1}`+version))
}

func writePublicModuleArchive(t *testing.T, proxy, owner, module, version string, modbody []byte) {
	t.Helper()
	destination := filepath.Join(proxy, module, "@v")
	if err := os.MkdirAll(destination, 0700); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(modbody), "replace ") {
		t.Fatal("public module has checkout replacement")
	}
	for name, body := range map[string][]byte{version + ".mod": modbody, version + ".info": []byte(`{"Version":"` + version + `","Time":"2026-01-01T00:00:00Z"}`), "list": []byte(version + "\n")} {
		if err := os.WriteFile(filepath.Join(destination, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	file, err := os.Create(filepath.Join(destination, version+".zip"))
	if err != nil {
		t.Fatal(err)
	}
	archive := zip.NewWriter(file)
	walkErr := filepath.WalkDir(owner, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("nonregular archive input")
		}
		relative, err := filepath.Rel(owner, name)
		if err != nil {
			return err
		}
		body, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		if relative == "go.mod" {
			body = modbody
		}
		output, err := archive.Create(module + "@" + version + "/" + filepath.ToSlash(relative))
		if err != nil {
			return err
		}
		_, err = output.Write(body)
		return err
	})
	archiveErr, closeErr := archive.Close(), file.Close()
	if walkErr != nil || archiveErr != nil || closeErr != nil {
		t.Fatal("archive failed", walkErr, archiveErr, closeErr)
	}
}

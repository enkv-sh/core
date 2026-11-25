package main

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// full_only: false
func TestVersionedPrivateCLIArchiveBuildsOutsideCheckout(t *testing.T) {
	ctx, cancel := context.WithTimeout(cacheOnlyGoContext(t.Context()), 6*time.Minute)
	defer cancel()
	root, docs := distributionRoots(t)
	scratch := t.TempDir()
	resolved, err := filepath.EvalSymlinks(scratch)
	if err != nil {
		t.Fatal(err)
	}
	for _, checkout := range []string{root, docs} {
		checkout, err = filepath.EvalSymlinks(checkout)
		if err != nil {
			t.Fatal(err)
		}
		relative, err := filepath.Rel(checkout, resolved)
		if err != nil || relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			t.Fatal("versioned CLI fixture must be outside source checkouts", err)
		}
	}
	tool := filepath.Join(scratch, "enkv-cli-package")
	if _, err := runGo(ctx, root, "compositions/full", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", tool, "./cmd/enkv-cli-package"); err != nil {
		t.Fatal(err)
	}

	sourceGraph, err := runGo(ctx, root, "compositions/full", "list", "-mod=readonly", "-m", "-json", "all")
	if err != nil {
		t.Fatal(err)
	}
	sourceModules, err := decodeObjects[resolvedModule](sourceGraph)
	if err != nil {
		t.Fatal(err)
	}
	sourceVersions := make(map[string]string, len(sourceModules))
	for _, module := range sourceModules {
		if _, exists := sourceVersions[module.Path]; exists {
			t.Fatal("source closure repeats an owner", module)
		}
		if module.Main {
			if module.Path != "enkv.sh/compositions/full" || module.Version != "" {
				t.Fatal("source main module identity differs", module)
			}
		} else if module.Version == "" || module.Version == "(devel)" {
			t.Fatal("source dependency has no exact version", module)
		}
		if strings.HasPrefix(module.Path, modulePrefix) {
			if _, ok := registeredModule(module.Path); !ok {
				t.Fatal("source closure has an unregistered first-party owner", module)
			}
		}
		sourceVersions[module.Path] = module.Version
	}
	// Archive the current source under its selected versions. These local fixture
	// archives do not establish that the corresponding public tags are available.
	proxy := filepath.Join(scratch, "proxy")
	detached := filepath.Join(scratch, "detached")
	main := filepath.Join(detached, "compositions/full")
	for _, row := range moduleSources {
		owner, err := moduleSourceDirectory(root, row)
		if err != nil {
			t.Fatal(err)
		}
		if row.Module == "enkv.sh/compositions/full" {
			if err := os.CopyFS(main, os.DirFS(owner)); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if version := sourceVersions[row.Module]; version != "" {
			modbody, err := os.ReadFile(filepath.Join(owner, "go.mod"))
			if err != nil {
				t.Fatal(err)
			}
			writePublicModuleArchive(t, proxy, owner, row.Module, version, modbody)
		}
	}
	originalMod, err := os.ReadFile(filepath.Join(main, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	base := publicPluginBuildEnvironment("off")
	base["CGO_ENABLED"] = "1"
	var host struct{ GOMODCACHE, GOROOT string }
	if err := json.Unmarshal(runModuleModeCommand(t, ctx, scratch, base, "env", "-json", "GOMODCACHE", "GOROOT"), &host); err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(host.GOMODCACHE) || !filepath.IsAbs(host.GOROOT) {
		t.Fatal("absolute host module cache and Go toolchain are required", host)
	}
	proxyURL := (&url.URL{Scheme: "file", Path: filepath.ToSlash(proxy)}).String()
	cachedURL := (&url.URL{Scheme: "file", Path: filepath.ToSlash(filepath.Join(host.GOMODCACHE, "cache/download"))}).String()
	// Both fallbacks are local files. Missing third-party pins must fail offline.
	base["GOPROXY"] = proxyURL + "," + cachedURL
	base["GOPRIVATE"], base["GONOSUMDB"] = "", "none"
	base["GOMODCACHE"] = publicPluginBuildOutput(t)
	// Only fixture preparation can add the synthetic archives' missing sums.
	runModuleModeCommand(t, ctx, main, base, "list", "-mod=mod", "-m", "all")
	runModuleModeCommand(t, ctx, main, base, "list", "-mod=mod", "-deps", "./cmd/enkv")
	frozen := map[string][]byte{}
	for _, name := range []string{"go.mod", "go.sum"} {
		body, err := os.ReadFile(filepath.Join(main, name))
		if err != nil {
			t.Fatal(err)
		}
		frozen[name] = body
	}
	if !bytes.Equal(originalMod, frozen["go.mod"]) {
		t.Fatalf("versioned fixture preparation changed declared dependency pins\nbefore:\n%s\nafter:\n%s", originalMod, frozen["go.mod"])
	}
	base["GOMODCACHE"] = publicPluginBuildOutput(t)
	entries, err := os.ReadDir(base["GOMODCACHE"])
	if err != nil || len(entries) != 0 {
		t.Fatal("versioned subject module cache must start empty", err)
	}
	var requests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	for name, body := range map[string]string{"plugin-public.pem": cliArchivePluginPublicPEM, "cli-public.pem": cliArchiveCLIPublicPEM, "catalog.pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))} {
		rawSourceWrite(t, scratch, name, body)
	}
	output := filepath.Join(scratch, "package")
	runCLIArchiveCommand(t, ctx, tool, scratch, environment(goEnvironment(), base), "-directory", main, "-bundle", "full", "-version", "1.2.3", "-versioned", "-environment", "development", "-plugin-public-key", filepath.Join(scratch, "plugin-public.pem"), "-cli-public-key", filepath.Join(scratch, "cli-public.pem"), "-development-origin", server.URL+"/releases/", "-development-tls-root", filepath.Join(scratch, "catalog.pem"), "-output", output)
	for name, before := range frozen {
		after, err := os.ReadFile(filepath.Join(main, name))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("versioned packager changed frozen dependency file", name, err)
		}
	}
	listed := runModuleModeCommand(t, ctx, main, base, "list", "-mod=readonly", "-m", "-json", "all")
	modules, err := decodeObjects[resolvedModule](listed)
	if err != nil {
		t.Fatal(err)
	}
	if len(modules) != len(sourceVersions) {
		t.Fatal("versioned declared closure owner count differs from source", len(modules), len(sourceVersions))
	}
	declared := map[string]resolvedModule{}
	for _, module := range modules {
		if _, exists := declared[module.Path]; exists || module.Replace != nil {
			t.Fatal("versioned declared closure repeats or replaces an owner", module)
		}
		if version, ok := sourceVersions[module.Path]; !ok || module.Version != version {
			t.Fatal("versioned declared closure differs from exact source version", module, version)
		}
		if module.Main {
			if module.Path != "enkv.sh/compositions/full" || module.Dir != main || module.Version != "" {
				t.Fatal("detached main module identity differs", module)
			}
		} else {
			if module.Version == "" || module.Version == "(devel)" {
				t.Fatal("declared dependency has no exact version", module)
			}
		}
		declared[module.Path] = module
	}
	packages, err := decodeObjects[struct {
		Standard bool
		Module   *resolvedModule
	}](runModuleModeCommand(t, ctx, main, base, "list", "-mod=readonly", "-trimpath", "-buildvcs=false", "-deps", "-json=Standard,Module", "./cmd/enkv"))
	if err != nil {
		t.Fatal(err)
	}
	selected := map[string]resolvedModule{}
	for _, pkg := range packages {
		if pkg.Standard {
			continue
		}
		if pkg.Module == nil {
			t.Fatal("selected package has no source owner")
		}
		module := *pkg.Module
		want, ok := declared[module.Path]
		if !ok || module.Replace != nil || module.Version != want.Version || module.Sum != want.Sum {
			t.Fatal("selected owner differs from complete declared closure", module)
		}
		if !module.Main {
			relative, err := filepath.Rel(base["GOMODCACHE"], module.Dir)
			if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) || module.Sum == "" {
				t.Fatal("selected dependency is not a checksummed archive in the fresh cache", module, err)
			}
		}
		selected[module.Path] = module
	}
	filename := "enkv-full-1.2.3-" + runtime.GOOS + "-" + runtime.GOARCH + ".tar.gz"
	archive := filepath.Join(output, filename)
	digest, length, err := cliArchiveIdentity(archive)
	if err != nil || length <= 0 {
		t.Fatal("versioned archive identity differs", err)
	}
	checksums, err := os.ReadFile(filepath.Join(output, "checksums.txt"))
	if err != nil || string(checksums) != fmt.Sprintf("%x  %s\n", digest, filename) {
		t.Fatal("versioned archive checksum differs", err)
	}
	install := filepath.Join(scratch, "installed")
	if err := os.Mkdir(install, 0700); err != nil {
		t.Fatal(err)
	}
	legal := extractCLIArchive(t, archive, install)
	executable := filepath.Join(install, "enkv")
	info, err := buildinfo.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	if info.GoVersion != "go1.27.3" || info.Path != "enkv.sh/compositions/full/cmd/enkv" || info.Main.Path != "enkv.sh/compositions/full" || info.Main.Version != "(devel)" || info.Main.Replace != nil || len(info.Deps)+1 != len(selected) {
		t.Fatal("versioned CLI main or complete compiled owner count differs", info)
	}
	seen := map[string]bool{info.Main.Path: true}
	for _, dep := range info.Deps {
		want, ok := selected[dep.Path]
		if !ok || seen[dep.Path] || dep.Replace != nil || dep.Version != want.Version || dep.Sum != want.Sum || dep.Version == "" || dep.Version == "(devel)" || dep.Sum == "" {
			t.Fatal("compiled dependency differs from exact selected archive", dep, want)
		}
		seen[dep.Path] = true
	}
	checkCLIArchiveSelectedModules(t, "full", info)
	checkCLIArchiveLegalOwners(t, detached, host.GOROOT, legal, info)
	for _, owner := range selected {
		hasLicense := false
		for _, name := range []string{"LICENSE", "LICENSE.txt", "LICENSE.md", "NOTICE", "NOTICE.txt", "THIRD_PARTY_NOTICES.md"} {
			body, err := os.ReadFile(filepath.Join(owner.Dir, name))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			hasLicense = hasLicense || strings.HasPrefix(name, "LICENSE")
			section := []byte(fmt.Sprintf("Module: %s\nVersion: %s\nSource file: %s\n\n", owner.Path, owner.Version, name))
			section = append(section, body...)
			section = append(section, '\n', '\n')
			if bytes.Count(legal["THIRD_PARTY_NOTICES.md"], section) != 1 {
				t.Fatal("selected archive legal bytes were not preserved exactly", owner.Path, name)
			}
		}
		if !hasLicense {
			t.Fatal("selected module owner has no license", owner.Path)
		}
	}
	settings := map[string]string{}
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	for key, want := range map[string]string{"GOOS": runtime.GOOS, "GOARCH": runtime.GOARCH, "CGO_ENABLED": "1", "-trimpath": "true", "-tags": ""} {
		if settings[key] != want {
			t.Fatal("versioned native CLI setting differs", key, settings[key], want)
		}
	}
	emptyPath := filepath.Join(install, "empty-path")
	if err := os.Mkdir(emptyPath, 0700); err != nil {
		t.Fatal(err)
	}
	before, _, err := cloudflareArtifactIdentity(executable)
	if err != nil {
		t.Fatal(err)
	}
	out, diagnostic := runCLIArchiveCommand(t, ctx, executable, install, []string{"PATH=" + emptyPath}, "inspect", "--help")
	if len(diagnostic) != 0 || string(out) != installedInspectHelp {
		t.Fatal("detached versioned CLI help differs", string(out), string(diagnostic))
	}
	after, _, err := cloudflareArtifactIdentity(executable)
	if err != nil || before != after || requests.Load() != 0 {
		t.Fatal("installed versioned CLI changed or accessed the catalog", requests.Load(), err)
	}
	t.Logf("platform=%s archive_sha256=%x cli_sha256=%x declared_modules=%d compiled_modules=%d", runtime.GOOS+"/"+runtime.GOARCH, digest, before, len(declared), len(selected))
}

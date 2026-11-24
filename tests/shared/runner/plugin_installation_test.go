package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/installedarchive"
	"enkv.sh/sdk/artifact"
)

type installationCLI struct {
	bundle, path string
	digest       [32]byte
}

type installationBuild struct {
	directory, author, command, workspace string
	metadata                              artifact.Metadata
	marker                                artifact.BuildMarker
	executable                            []byte
}

type installationCatalog struct {
	mu       sync.Mutex
	files    map[string][]byte
	requests []string
}

type installationFile struct {
	Mode os.FileMode
	Body []byte
}

func (c *installationCatalog) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests = append(c.requests, r.Method+" "+r.URL.Path)
	body, ok := c.files[r.URL.Path]
	if !ok || r.Method != http.MethodGet {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	if _, err := w.Write(body); err != nil {
		// A write failure must remain visible after the client joins.
		c.requests = append(c.requests, "write-failed")
	}
}

func (c *installationCatalog) calls() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.requests)
}

// full_only: false
func TestPluginInstallationProductionCLIWorkflow(t *testing.T) {
	ctx, cancel := context.WithTimeout(cacheOnlyGoContext(t.Context()), 12*time.Minute)
	defer cancel()
	catalog := &installationCatalog{files: map[string][]byte{}}
	server := httptest.NewTLSServer(catalog)
	defer server.Close()
	clis := installationCLIs(t, ctx, server, "full", "aws", "gcp")
	if len(catalog.calls()) != 0 {
		t.Fatal("CLI packaging accessed the development catalog")
	}
	root := maintainedCloudflareRoot(t)
	tool := publicPluginBuildTool(t, ctx, root)
	_, docs := distributionRoots(t)
	signer := releaseSigner(t, docs)
	keyDirectory := t.TempDir()
	releasePEM(t, keyDirectory)
	kit, workspace := installationPublicKit(t, ctx, root)
	first := installationBuildReleaseSet(t, ctx, tool, kit, workspace, "1.0.0", catalog, signer, keyDirectory, nil)
	type application struct {
		cli                  installationCLI
		source, home, config string
	}
	var applications []application
	var credentialCalls atomic.Int64
	credentials := installationCredentialRefusal(t, &credentialCalls)
	for _, cli := range clis {
		family := "aws"
		if cli.bundle == "gcp" {
			family = "gcp"
		}
		source := installationSource(t, family, true)
		home, config := installationHome(t)
		env := installationEnvironment(home, credentials.URL)
		before := installationPairImage(t, source)
		body := installationCLICommand(t, ctx, cli.path, source, env, 0, "prepare")
		installationAssertPrepared(t, body, first)
		installationAssertOfficialSelection(t, config, source, first)
		installationAssertPair(t, source, before)
		applications = append(applications, application{cli, source, home, config})
	}
	second := installationBuildReleaseSet(t, ctx, tool, kit, workspace, "2.0.0", catalog, signer, keyDirectory, first)
	for _, app := range applications {
		t.Run(app.cli.bundle, func(t *testing.T) {
			env := installationEnvironment(app.home, credentials.URL)
			before := installationPairImage(t, app.source)
			calls := len(catalog.calls())
			installationAssertPrepared(t, installationCLICommand(t, ctx, app.cli.path, app.source, env, 0, "prepare"), first)
			if len(catalog.calls()) != calls {
				t.Fatal("repeated prepare accessed the release service")
			}
			installationAssertPair(t, app.source, before)
			installationAssertOfficialSelection(t, app.config, app.source, first)

			installationPin(t, app.source, "2.0.0")
			before = installationPairImage(t, app.source)
			mixed := installationReplaceBuild(first, second["cloudflare-account-token"])
			installationAssertPrepared(t, installationCLICommand(t, ctx, app.cli.path, app.source, env, 0, "prepare"), mixed)
			installationAssertOfficialSelection(t, app.config, app.source, mixed)
			installationAssertPair(t, app.source, before)

			installationPin(t, app.source, "9.0.0")
			before = installationPairImage(t, app.source)
			selectionBefore := installationRead(t, installationSelectionPath(app.config, app.source))
			calls = len(catalog.calls())
			refusal := installationCLICommand(t, ctx, app.cli.path, app.source, env, 2, "prepare")
			var failed struct {
				Outcome      string `json:"outcome"`
				Dependencies struct {
					All           bool                                     `json:"all_declared_ready"`
					Installations []struct{ Name, Version, Status string } `json:"installations"`
				} `json:"dependencies"`
			}
			if err := json.Unmarshal(refusal, &failed); err != nil || failed.Outcome != "incomplete" || failed.Dependencies.All {
				t.Fatal("unavailable exact pin supplied readiness", string(refusal), err)
			}
			found := false
			for _, row := range failed.Dependencies.Installations {
				if row.Name == "cloudflare-account-token" {
					found = row.Version == "9.0.0" && row.Status != "verified"
				}
			}
			if !found {
				t.Fatal("exact pin refusal lost its requested version", string(refusal))
			}
			if len(catalog.calls()) == calls {
				t.Fatal("exact unavailable pin did not request its release")
			}
			for _, call := range catalog.calls()[calls:] {
				if !strings.Contains(call, "/cloudflare-account-token/9.0.0/") {
					t.Fatal("exact pin used an index or another release", call)
				}
			}
			if !bytes.Equal(selectionBefore, installationRead(t, installationSelectionPath(app.config, app.source))) {
				t.Fatal("failed exact pin replaced the prior selection")
			}
			installationAssertPair(t, app.source, before)

			installationPin(t, app.source, "1.0.0")
			before = installationPairImage(t, app.source)
			installationAssertPrepared(t, installationCLICommand(t, ctx, app.cli.path, app.source, env, 0, "prepare"), first)
			installationAssertPair(t, app.source, before)
			mixed = installationReplaceBuild(second, first["cloudflare-account-token"])
			installationAssertPrepared(t, installationCLICommand(t, ctx, app.cli.path, app.source, env, 0, "prepare", "--upgrade"), mixed)
			installationAssertOfficialSelection(t, app.config, app.source, mixed)
			installationAssertPair(t, app.source, before)
			installationPin(t, app.source, "")
			before = installationPairImage(t, app.source)
			installationAssertPrepared(t, installationCLICommand(t, ctx, app.cli.path, app.source, env, 0, "prepare", "--upgrade"), second)
			installationAssertOfficialSelection(t, app.config, app.source, second)
			installationAssertPair(t, app.source, before)
			for _, builds := range []map[string]installationBuild{first, second} {
				for _, build := range builds {
					installationAssertStored(t, app.config, build, true)
				}
			}
		})
	}
	if credentialCalls.Load() != 0 {
		t.Fatal("preparation requested provider credentials", credentialCalls.Load())
	}
	app := applications[0]
	if app.cli.bundle != "full" {
		t.Fatal("ordinary official reuse requires the full CLI fixture")
	}
	before := installationPairImage(t, app.source)
	calls := len(catalog.calls())
	installationAssertApplyUnavailable(t, installationCLICommand(t, ctx, app.cli.path, app.source, installationEnvironment(app.home, credentials.URL), 3, "apply"), "apply")
	if len(catalog.calls()) != calls || credentialCalls.Load() == 0 {
		t.Fatal("ordinary official reuse fetched a release or failed before credential admission")
	}
	installationAssertPair(t, app.source, before)
	for _, call := range catalog.calls() {
		if strings.Contains(call, "/generic-json/") {
			t.Fatal("preparation requested an undeclared manifest generator", call)
		}
		if call == "write-failed" {
			t.Fatal("release server response did not complete")
		}
	}
	installationAssertCLIs(t, clis)
}

// full_only: false
func TestPluginInstallationOrdinaryCaptureBeforeCredentials(t *testing.T) {
	ctx, cancel := context.WithTimeout(cacheOnlyGoContext(t.Context()), 10*time.Minute)
	defer cancel()
	catalog := &installationCatalog{files: map[string][]byte{}}
	server := httptest.NewTLSServer(catalog)
	defer server.Close()
	clis := installationCLIs(t, ctx, server, "full", "aws")
	if len(catalog.calls()) != 0 {
		t.Fatal("CLI packaging accessed the development catalog")
	}
	root := maintainedCloudflareRoot(t)
	tool := publicPluginBuildTool(t, ctx, root)
	kit, workspace := installationPublicKit(t, ctx, root)
	author, err := sourcePath(kit, "plugins/cloudflare")
	if err != nil {
		t.Fatal(err)
	}
	mutable := publicPluginBuildOutput(t)
	stable := publicPluginBuildOutput(t)
	first := installationBuildPlugin(t, ctx, tool, author, "./cmd/enkv-generator-cloudflare", workspace, mutable, "cloudflare-account-token", "1.0.0")
	stableFirst := installationBuildPlugin(t, ctx, tool, author, "./cmd/enkv-generator-cloudflare", workspace, stable, "cloudflare-account-token", "1.0.0")
	if stableFirst.marker.Artifact != first.marker.Artifact {
		t.Fatal("same author build has different local identity")
	}
	type application struct {
		cli                         installationCLI
		source, other, home, config string
		image, otherImage           map[string]installationFile
		settings                    []byte
	}
	var applications []application
	var credentialCalls atomic.Int64
	credentials := installationCredentialRefusal(t, &credentialCalls)
	for _, cli := range clis {
		source, other := installationSource(t, "aws", false), installationSource(t, "aws", false)
		home, config := installationHome(t)
		installationSettings(t, config, map[string]string{filepath.Dir(source): mutable, filepath.Dir(other): stable})
		env := installationEnvironment(home, credentials.URL)
		for _, path := range []string{source, other} {
			calls := credentialCalls.Load()
			result := installationCLICommand(t, ctx, cli.path, path, env, 3, "apply")
			installationAssertStored(t, config, first, false)
			installationAssertApplyUnavailable(t, result, "apply")
			if credentialCalls.Load() <= calls {
				t.Fatal("ordinary apply did not reach credential refusal after capture")
			}
		}
		applications = append(applications, application{cli, source, other, home, config, installationPairImage(t, source), installationPairImage(t, other), installationRead(t, filepath.Join(config, "enkv/plugins.json"))})
	}
	second := installationBuildPlugin(t, ctx, tool, author, "./cmd/enkv-generator-cloudflare", workspace, mutable, "cloudflare-account-token", "2.0.0")
	if first.marker.Artifact == second.marker.Artifact || bytes.Equal(first.executable, second.executable) {
		t.Fatal("local rebuild did not replace exact plugin bytes")
	}
	for _, app := range applications {
		t.Run(app.cli.bundle, func(t *testing.T) {
			env := installationEnvironment(app.home, credentials.URL)
			calls := credentialCalls.Load()
			installationAssertApplyUnavailable(t, installationCLICommand(t, ctx, app.cli.path, app.source, env, 3, "apply"), "apply")
			if credentialCalls.Load() <= calls {
				t.Fatal("rebuilt ordinary apply did not reach later credential refusal")
			}
			installationAssertStored(t, app.config, second, false)
			installationAssertStored(t, app.config, first, false)
			calls = credentialCalls.Load()
			installationAssertApplyUnavailable(t, installationCLICommand(t, ctx, app.cli.path, app.other, env, 3, "apply"), "apply")
			if credentialCalls.Load() <= calls {
				t.Fatal("other application did not retain its valid A capture")
			}
			installationAssertStored(t, app.config, stableFirst, false)
			installationAssertPair(t, app.source, app.image)
			installationAssertPair(t, app.other, app.otherImage)
			if !bytes.Equal(app.settings, installationRead(t, filepath.Join(app.config, "enkv/plugins.json"))) {
				t.Fatal("ordinary capture changed application settings")
			}
		})
	}
	_, executable := publicPluginBuildSelection(t, mutable)
	if err := os.Chmod(executable, 0600); err != nil {
		t.Fatal(err)
	}
	damaged := bytes.Clone(second.executable)
	damaged[len(damaged)-1] ^= 1
	if err := os.WriteFile(executable, damaged, 0500); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(executable, 0500); err != nil {
		t.Fatal(err)
	}
	for _, app := range applications {
		calls := credentialCalls.Load()
		installationAssertApplyUnavailable(t, installationCLICommand(t, ctx, app.cli.path, app.source, installationEnvironment(app.home, credentials.URL), 3, "apply"), "construction")
		if credentialCalls.Load() != calls {
			t.Fatal("damaged local build reached credentials")
		}
		installationAssertApplyUnavailable(t, installationCLICommand(t, ctx, app.cli.path, app.other, installationEnvironment(app.home, credentials.URL), 3, "apply"), "apply")
		if credentialCalls.Load() <= calls {
			t.Fatal("damaging one application build blocked the other application's exact A capture")
		}
		installationAssertStored(t, app.config, first, false)
		installationAssertStored(t, app.config, second, false)
		installationAssertPair(t, app.source, app.image)
		installationAssertPair(t, app.other, app.otherImage)
		if !bytes.Equal(app.settings, installationRead(t, filepath.Join(app.config, "enkv/plugins.json"))) {
			t.Fatal("damaged capture changed settings")
		}
	}
	if len(catalog.calls()) != 0 {
		t.Fatal("ordinary local selection accessed an official release", catalog.calls())
	}
	installationAssertCLIs(t, clis)
}

func installationCLIs(t *testing.T, ctx context.Context, server *httptest.Server, bundles ...string) []installationCLI {
	t.Helper()
	root := maintainedCloudflareRoot(t)
	_, docs := distributionRoots(t)
	scratch := sourceFixtureRoot(t)
	for _, checkout := range []string{root, docs} {
		resolved, err := filepath.EvalSymlinks(checkout)
		if err != nil {
			t.Fatal(err)
		}
		relative, err := filepath.Rel(resolved, scratch)
		if err != nil || relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			t.Fatal("installation fixture is inside a checkout", err)
		}
	}
	var directories []string
	for _, module := range moduleSources {
		directory, err := moduleSourceDirectory(root, module)
		if err != nil {
			t.Fatal(err)
		}
		directories = append(directories, directory)
	}
	workspace := publicPluginBuildWorkspace(t, ctx, directories)
	tool := filepath.Join(scratch, "enkv-cli-package")
	if _, err := runGo(ctx, root, "compositions/full", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", tool, "./cmd/enkv-cli-package"); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"plugin-public.pem": cliArchivePluginPublicPEM, "cli-public.pem": cliArchiveCLIPublicPEM, "catalog.pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))} {
		rawSourceWrite(t, scratch, name, body)
	}
	var result []installationCLI
	for _, bundle := range bundles {
		output := filepath.Join(scratch, "package-"+bundle)
		runCLIArchiveCommand(t, ctx, tool, scratch, environment(goEnvironment(), publicPluginBuildEnvironment("off")), "-directory", filepath.Join(root, "compositions/full"), "-bundle", bundle, "-version", "1.0.0", "-workspace", workspace, "-environment", "development", "-plugin-public-key", filepath.Join(scratch, "plugin-public.pem"), "-cli-public-key", filepath.Join(scratch, "cli-public.pem"), "-development-origin", server.URL+"/releases/", "-development-tls-root", filepath.Join(scratch, "catalog.pem"), "-output", output)
		install := filepath.Join(scratch, "installed-"+bundle)
		if err := os.Mkdir(install, 0700); err != nil {
			t.Fatal(err)
		}
		extractCLIArchive(t, filepath.Join(output, "enkv-"+bundle+"-1.0.0-"+runtime.GOOS+"-"+runtime.GOARCH+".tar.gz"), install)
		path := filepath.Join(install, "enkv")
		info, err := buildinfo.ReadFile(path)
		if err != nil || info.Main.Path != "enkv.sh/compositions/full" || info.Path != "enkv.sh/compositions/full/cmd/enkv" || info.GoVersion != "go1.27.3" {
			t.Fatal("installed CLI production build identity differs", info, err)
		}
		checkCLIArchiveSelectedModules(t, bundle, info)
		if err := os.Chmod(path, 0555); err != nil {
			t.Fatal(err)
		}
		digest, _, err := cloudflareArtifactIdentity(path)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, installationCLI{bundle, path, digest})
	}
	return result
}

func installationAssertCLIs(t *testing.T, clis []installationCLI) {
	t.Helper()
	for _, cli := range clis {
		digest, _, err := cloudflareArtifactIdentity(cli.path)
		if err != nil || digest != cli.digest {
			t.Fatal("frozen CLI bytes changed", cli.bundle, err)
		}
		t.Logf("bundle=%s platform=%s cli_sha256=%x", cli.bundle, runtime.GOOS+"/"+runtime.GOARCH, digest)
	}
}

func installationPublicKit(t *testing.T, ctx context.Context, root string) (string, string) {
	t.Helper()
	kit := sourceFixtureRoot(t)
	var selectors, directories []string
	for _, source := range moduleSources {
		if source.Sibling != "" {
			selectors = append(selectors, source.Selector)
		}
	}
	copyPublicModuleKit(t, root, kit, selectors)
	for _, selector := range selectors {
		directory, err := sourcePath(kit, selector)
		if err != nil {
			t.Fatal(err)
		}
		directories = append(directories, directory)
	}
	return kit, publicPluginBuildWorkspace(t, ctx, directories)
}

func installationBuildReleaseSet(t *testing.T, ctx context.Context, tool, kit, workspace, version string, catalog *installationCatalog, signer, keyDirectory string, previous map[string]installationBuild) map[string]installationBuild {
	t.Helper()
	result := map[string]installationBuild{}
	for _, row := range []struct{ name, selector, command string }{
		{"aws-secrets-manager", "plugins/aws-output", "./cmd/enkv-output-aws-secrets-manager"},
		{"cloudflare-account-token", "plugins/cloudflare", "./cmd/enkv-generator-cloudflare"},
		{"gcp-secret-manager", "plugins/gcp-output", "./cmd/enkv-output-gcp-secret-manager"},
		{"github-actions-environment", "plugins/github-output", "./cmd/enkv-output-github-environment"},
		{"github-actions-organization", "plugins/github-output", "./cmd/enkv-output-github-organization"},
		{"github-actions-repository", "plugins/github-output", "./cmd/enkv-output-github-repository"},
	} {
		author, err := sourcePath(kit, row.selector)
		if err != nil {
			t.Fatal(err)
		}
		build := installationBuildPlugin(t, ctx, tool, author, row.command, workspace, publicPluginBuildOutput(t), row.name, version)
		var releases []artifact.Release
		if prior, ok := previous[row.name]; ok {
			if build.marker.Artifact == prior.marker.Artifact || bytes.Equal(build.executable, prior.executable) {
				t.Fatal("later plugin did not change exact identity and executable bytes", row.name)
			}
			releases = []artifact.Release{{Version: prior.metadata.Version, Platform: prior.metadata.Platform, Artifact: prior.marker.Artifact}}
		}
		// Archive while the source still matches this build, before another author update.
		installationPublish(t, ctx, catalog, tool, signer, keyDirectory, build, releases)
		result[row.name] = build
	}
	return result
}

func installationBuildPlugin(t *testing.T, ctx context.Context, tool, author, command, workspace, directory, name, version string) installationBuild {
	t.Helper()
	main := filepath.Join(author, filepath.FromSlash(command))
	descriptorPath := filepath.Join(main, "plugin.json")
	var descriptor artifact.Descriptor
	if err := json.Unmarshal(installationRead(t, descriptorPath), &descriptor); err != nil || descriptor.Name != name {
		t.Fatal("author descriptor name differs", name, err)
	}
	descriptor.Version = version
	descriptorBody, err := artifact.EncodeDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	rawSourceWrite(t, main, "plugin.json", string(descriptorBody))
	// A public author source change forces distinct executable bytes as well as metadata.
	rawSourceWrite(t, main, "installation_revision.go", "package main\nimport \"os\"\nfunc init(){if len(os.Args)==0 {panic("+fmt.Sprintf("%q", version)+")}}\n")
	runPublicPluginBuildCommand(t, ctx, tool, author, "-directory", author, "-descriptor", descriptorPath, "-command", command, "-workspace", workspace, "-output", directory)
	metadata, err := artifact.VerifyBuild(ctx, directory)
	if err != nil {
		t.Fatal(err)
	}
	marker, executable := publicPluginBuildSelection(t, directory)
	metadataBytes := installationRead(t, filepath.Join(directory, filepath.FromSlash(marker.Directory), "metadata.json"))
	executableBytes := installationRead(t, executable)
	if sha256.Sum256(metadataBytes) != [32]byte(marker.Artifact) || sha256.Sum256(executableBytes) != [32]byte(metadata.Executable.SHA256) || uint64(len(executableBytes)) != metadata.Executable.Length {
		t.Fatal("public build marker and metadata do not bind exact fixture bytes")
	}
	return installationBuild{directory, author, command, workspace, metadata, marker, executableBytes}
}

func installationPublish(t *testing.T, ctx context.Context, catalog *installationCatalog, tool, signer, keyDirectory string, build installationBuild, previous []artifact.Release) {
	t.Helper()
	work := t.TempDir()
	metadata := filepath.Join(build.directory, filepath.FromSlash(build.marker.Directory), "metadata.json")
	sign := func(purpose, input, output string) {
		runCLIArchiveCommand(t, ctx, signer, work, goEnvironment(), "-purpose", purpose, "-input", input, "-key", filepath.Join(keyDirectory, "private.pem"), "-output", output)
	}
	sign("plugin-executable", metadata, filepath.Join(work, "metadata.sig"))
	output := filepath.Join(work, "archive")
	runCLIArchiveCommand(t, ctx, tool, work, environment(goEnvironment(), publicPluginBuildEnvironment("off")), "-directory", build.author, "-command", build.command, "-workspace", build.workspace, "-archive", build.directory, "-metadata-signature", filepath.Join(work, "metadata.sig"), "-output", output)
	recordPath := filepath.Join(output, "archive.json")
	sign("plugin-archive", recordPath, filepath.Join(work, "archive.sig"))
	recordBytes := installationRead(t, recordPath)
	record, err := artifact.DecodeArchiveRecord(recordBytes)
	if err != nil {
		t.Fatal(err)
	}
	if record.Artifact != build.marker.Artifact || record.Name != build.metadata.Name || record.Version != build.metadata.Version {
		t.Fatal("public archive changed the selected author build")
	}
	indexBytes, err := artifact.EncodeReleaseIndex(artifact.ReleaseIndex{Schema: "enkv/plugin-index/v1", Name: build.metadata.Name, Releases: append(slices.Clone(previous), artifact.Release{Version: build.metadata.Version, Platform: build.metadata.Platform, Artifact: build.marker.Artifact})})
	if err != nil {
		t.Fatal(err)
	}
	rawSourceWrite(t, work, "index.json", string(indexBytes))
	sign("plugin-index", filepath.Join(work, "index.json"), filepath.Join(work, "index.sig"))
	archiveBytes := installationRead(t, filepath.Join(output, record.Archive.Filename))
	if sha256.Sum256(archiveBytes) != [32]byte(record.Archive.SHA256) || uint64(len(archiveBytes)) != record.Archive.Length {
		t.Fatal("public archive record does not bind exact compressed bytes")
	}
	catalog.mu.Lock()
	defer catalog.mu.Unlock()
	for _, base := range []string{"/releases/plugins/" + record.Name + "/" + record.Version + "/" + strings.ReplaceAll(record.Platform, "/", "-") + "/", "/releases/artifacts/" + record.Artifact.String() + "/"} {
		catalog.files[base+"archive.json"] = recordBytes
		catalog.files[base+"archive.sig"] = installationRead(t, filepath.Join(work, "archive.sig"))
		catalog.files[base+record.Archive.Filename] = archiveBytes
	}
	catalog.files["/releases/plugins/"+record.Name+"/index.json"] = indexBytes
	catalog.files["/releases/plugins/"+record.Name+"/index.sig"] = installationRead(t, filepath.Join(work, "index.sig"))
}

func installationReplaceBuild(builds map[string]installationBuild, changed installationBuild) map[string]installationBuild {
	result := make(map[string]installationBuild, len(builds))
	for name, build := range builds {
		result[name] = build
	}
	result[changed.metadata.Name] = changed
	return result
}

func installationRead(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func installationHome(t *testing.T) (string, string) {
	t.Helper()
	home := sourceFixtureRoot(t)
	config := filepath.Join(home, ".config")
	if runtime.GOOS == "darwin" {
		config = filepath.Join(home, "Library/Application Support")
	}
	if err := os.MkdirAll(config, 0700); err != nil {
		t.Fatal(err)
	}
	return home, config
}

func installationEnvironment(home, credentials string) []string {
	// Clear all ambient provider and telemetry routes before selecting the local refusal endpoint.
	var env []string
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if name == "HOME" || name == "XDG_CONFIG_HOME" || strings.HasPrefix(name, "AWS_") || strings.HasPrefix(name, "GOOGLE_") || strings.HasPrefix(name, "GCLOUD_") || strings.HasPrefix(name, "CLOUDSDK_") || strings.HasPrefix(name, "EXPERIMENTAL_GOOGLE_") || strings.HasPrefix(name, "ENKV_") || strings.HasPrefix(name, "OTEL_") || name == "CLOUDFLARE_API_TOKEN" || name == "GITHUB_TOKEN" || name == "GH_TOKEN" {
			continue
		}
		env = append(env, entry)
	}
	return append(env, "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, ".config"), "AWS_EC2_METADATA_DISABLED=true", "AWS_CONFIG_FILE="+filepath.Join(home, "absent-config"), "AWS_SHARED_CREDENTIALS_FILE="+filepath.Join(home, "absent-credentials"), "AWS_CONTAINER_CREDENTIALS_FULL_URI="+credentials+"/credentials", "AWS_MAX_ATTEMPTS=1")
}

func installationCredentialRefusal(t *testing.T, calls *atomic.Int64) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/credentials" {
			t.Error("unexpected credential endpoint request")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	server.Config.ReadHeaderTimeout = 2 * time.Second
	server.Config.WriteTimeout = 2 * time.Second
	server.Start()
	t.Cleanup(server.Close)
	return server
}

func installationCLICommand(t *testing.T, ctx context.Context, binary, source string, env []string, code int, command string, extra ...string) []byte {
	t.Helper()
	args := []string{command, "--source", source, "--source-format", "json", "--json", "--log-level", "off"}
	args = append(args, extra...)
	var stdout, stderr limitedOutput
	result := runProcessOutput(ctx, binary, filepath.Dir(source), args, env, 30*time.Second, &stdout, &stderr)
	actual := 0
	if result.Status != "passed" {
		var exit *exec.ExitError
		if !errors.As(result.Cause, &exit) {
			t.Fatalf("CLI did not exit normally: %+v stdout=%s stderr=%s", result, stdout.String(), stderr.String())
		}
		actual = exit.ExitCode()
	}
	if !result.Started || !result.Joined || stdout.overflow || stderr.overflow || actual != code {
		t.Fatalf("CLI result differs: code=%d want=%d result=%+v stdout=%s stderr=%s", actual, code, result, stdout.String(), stderr.String())
	}
	return bytes.Clone(stdout.Bytes())
}

func installationSettings(t *testing.T, config string, applications map[string]string) {
	t.Helper()
	settings := artifact.Settings{Schema: "enkv/plugin-settings/v1", Applications: []artifact.Application{}}
	for directory, build := range applications {
		canonical, err := filepath.EvalSymlinks(directory)
		if err != nil {
			t.Fatal(err)
		}
		build, err = filepath.EvalSymlinks(build)
		if err != nil {
			t.Fatal(err)
		}
		settings.Applications = append(settings.Applications, artifact.Application{Directory: canonical, Plugins: []artifact.LocalPlugin{{Name: "cloudflare-account-token", Directory: build}}})
	}
	slices.SortFunc(settings.Applications, func(a, b artifact.Application) int { return strings.Compare(a.Directory, b.Directory) })
	body, err := artifact.EncodeSettings(settings)
	if err != nil {
		t.Fatal(err)
	}
	rawSourceWrite(t, config, "enkv/plugins.json", string(body))
}

func installationSelectionPath(config, source string) string {
	return filepath.Join(config, "enkv/installation/applications", fmt.Sprintf("%x", sha256.Sum256([]byte(filepath.Dir(source))))+".json")
}

func installationAssertOfficialSelection(t *testing.T, config, source string, builds map[string]installationBuild) {
	t.Helper()
	record, err := artifact.DecodeSelectionRecord(installationRead(t, installationSelectionPath(config, source)))
	if err != nil || record.Directory != filepath.Dir(source) || len(record.Selections) != len(builds) {
		t.Fatal("application selection differs", record, err)
	}
	for _, row := range record.Selections {
		build, ok := builds[row.Name]
		if !ok || row.Version != build.metadata.Version || row.Artifact != build.marker.Artifact || row.Platform != runtime.GOOS+"/"+runtime.GOARCH || row.Proof.IsZero() {
			t.Fatal("exact official selection differs", row)
		}
	}
}

func installationAssertStored(t *testing.T, config string, build installationBuild, official bool) {
	t.Helper()
	base := filepath.Join(config, "enkv/installation/builds", build.marker.Artifact.String())
	if official {
		parent := filepath.Join(config, "enkv/installation/packages", build.marker.Artifact.String())
		entries, err := os.ReadDir(parent)
		if err != nil {
			t.Fatal(err)
		}
		var paths []string
		for _, entry := range entries {
			if entry.IsDir() {
				if _, err := artifact.ParseDigest(entry.Name()); err != nil {
					t.Fatal("invalid official proof directory", entry.Name(), err)
				}
				paths = append(paths, filepath.Join(parent, entry.Name()))
			}
		}
		if len(paths) != 1 {
			t.Fatal("exact official package absent or ambiguous", paths)
		}
		base = paths[0]
	}
	if !bytes.Equal(installationRead(t, filepath.Join(base, "plugin")), build.executable) || !bytes.Equal(installationRead(t, filepath.Join(base, "metadata.json")), installationRead(t, filepath.Join(build.directory, filepath.FromSlash(build.marker.Directory), "metadata.json"))) {
		t.Fatal("immutable installation differs from exact author bytes", build.metadata.Name)
	}
	if build.metadata.Family != nil && !bytes.Equal(installationRead(t, filepath.Join(base, "dependencies.bin")), installationRead(t, filepath.Join(build.directory, filepath.FromSlash(build.marker.Directory), "dependencies.bin"))) {
		t.Fatal("immutable dependency manifest changed")
	}
	if build.metadata.Role == "generator" {
		facts, err := build.metadata.GeneratorFacts()
		if err != nil {
			t.Fatal(err)
		}
		var locator struct{ Executor, Artifact artifact.Digest }
		if err := json.Unmarshal(installationRead(t, filepath.Join(config, "enkv/installation/retained/generator", facts.ExecutorID.String()+".json")), &locator); err != nil || locator.Executor != facts.ExecutorID || locator.Artifact != build.marker.Artifact {
			t.Fatal("retained exact generator identity changed", err)
		}
	}
}

func installationAssertPrepared(t *testing.T, body []byte, builds map[string]installationBuild) {
	t.Helper()
	type requirement struct {
		Role            string
		Plugin          *string
		Contract        string
		ProtocolVersion uint32 `json:"protocol_version"`
		Artifact        *string
		Status, Reason  string
	}
	var got struct {
		Schema, Outcome, Branch string
		Dependencies            struct {
			Assessment    string
			Minimum       bool `json:"minimum_administrative_ready"`
			All           bool `json:"all_declared_ready"`
			Requirements  []requirement
			Installations []struct {
				Name, Role, Version, Platform, Source, Status, Reason string
				Artifact                                              *artifact.Digest
			}
		}
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Schema != "enkv/prepare-result/v2" || got.Outcome != "complete" || got.Branch != "existing" || got.Dependencies.Assessment != "complete" || !got.Dependencies.Minimum || !got.Dependencies.All || len(got.Dependencies.Installations) != len(builds) {
		t.Fatal("public preparation did not provide complete exact readiness", string(body))
	}
	var want []requirement
	for _, declared := range []struct {
		role, plugin, contract string
		protocol               uint32
	}{
		{"generator", "cloudflare-account-token", "7ede2a15bbf86395c097322b651f2752f9adf1bdfa346f09683e20e670ff10c1", 5},
		{"output", "aws-secrets-manager", "ENKV/OUTPUT/AWS-SECRETS-MANAGER/CONFIG/v1", 6},
		{"output", "gcp-secret-manager", "ENKV/OUTPUT/GCP-SECRET-MANAGER/CONFIG/v1", 6},
		{"output", "github-actions-environment", "github-actions/environment-config/v1", 6},
		{"output", "github-actions-organization", "github-actions/organization-config/v1", 6},
		{"output", "github-actions-repository", "github-actions/repository-config/v1", 6},
	} {
		build, ok := builds[declared.plugin]
		if !ok {
			t.Fatal("declared plugin build is absent", declared.plugin)
		}
		id := fmt.Sprintf("%x", sha256.Sum256(build.executable))
		want = append(want, requirement{declared.role, &declared.plugin, declared.contract, declared.protocol, &id, "verified", "none"})
	}
	slices.SortFunc(want, func(a, b requirement) int {
		if a.Role != b.Role {
			return strings.Compare(a.Role, b.Role)
		}
		if a.Contract != b.Contract {
			return strings.Compare(a.Contract, b.Contract)
		}
		return strings.Compare(*a.Plugin, *b.Plugin)
	})
	if len(builds) != len(want) || !reflect.DeepEqual(got.Dependencies.Requirements, want) {
		t.Fatalf("whole semantic requirement set differs: result=%s want=%+v", body, want)
	}
	seen := map[string]bool{}
	for _, row := range got.Dependencies.Installations {
		build, ok := builds[row.Name]
		if !ok || seen[row.Name] || row.Role != build.metadata.Role || row.Version != build.metadata.Version || row.Platform != runtime.GOOS+"/"+runtime.GOARCH || row.Source != "official" || row.Status != "verified" || row.Reason != "none" || row.Artifact == nil || *row.Artifact != build.marker.Artifact {
			t.Fatal("public installation facts differ", row)
		}
		seen[row.Name] = true
	}
}

func installationAssertApplyUnavailable(t *testing.T, body []byte, stage string) {
	t.Helper()
	var got struct {
		State    string                       `json:"state_result"`
		Commit   bool                         `json:"commit_may_have_occurred"`
		Receipt  string                       `json:"receipt_hex"`
		Payload  json.RawMessage              `json:"payload"`
		Identity struct{ Stage, Code string } `json:"request_identity"`
	}
	if err := json.Unmarshal(body, &got); err != nil || got.State != "unavailable" || got.Commit || got.Receipt != "" || string(got.Payload) != "null" || got.Identity.Stage != stage || got.Identity.Code != "evidence-unavailable" {
		t.Fatal("incomplete apply claimed completion or lost its expected failure stage", string(body), err)
	}
}

func installationPin(t *testing.T, source, version string) {
	t.Helper()
	var editable map[string]any
	if err := json.Unmarshal(installationRead(t, source), &editable); err != nil {
		t.Fatal(err)
	}
	if version == "" {
		delete(editable, "plugins")
	} else {
		editable["plugins"] = map[string]any{"cloudflare-account-token": map[string]string{"version": version}}
	}
	body, err := json.Marshal(editable)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, body, 0600); err != nil {
		t.Fatal(err)
	}
}

func installationPairImage(t *testing.T, source string) map[string]installationFile {
	t.Helper()
	root := filepath.Dir(source)
	image := map[string]installationFile{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return errors.New("source pair contains a nonregular file")
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		file := installationFile{Mode: info.Mode()}
		if info.Mode().IsRegular() {
			file.Body, err = os.ReadFile(path)
		}
		image[relative] = file
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return image
}
func installationAssertPair(t *testing.T, source string, want map[string]installationFile) {
	t.Helper()
	if !reflect.DeepEqual(installationPairImage(t, source), want) {
		t.Fatal("command changed source pair bytes, modes or file inventory")
	}
}

func installationSource(t *testing.T, family string, outputs bool) string {
	t.Helper()
	fixture, basisBytes := installedarchive.LoadReader(t, family)
	var basis struct{ Descriptor []byte }
	if err := json.Unmarshal(basisBytes, &basis); err != nil {
		t.Fatal(err)
	}
	d, err := contract.DecodeGenesisDescriptorCore(basis.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	// The signed archive is unchanged. This newly encoded basis uses its public keys only.
	d.InterpretationID, d.TrustInterpretationID = contract.InterpretationID(), contract.TrustInterpretationID()
	d.CompatibilityID, d.CryptoSupportID = contract.CompatibilityID(), contract.CryptoSupportID()
	d.NormalSigning.Binding.Interpretation = d.InterpretationID
	if d.Recovery != nil {
		recovery := *d.Recovery
		recovery.Signing.Binding.Interpretation = d.InterpretationID
		d.Recovery = &recovery
	}
	descriptor, err := contract.EncodeGenesisDescriptorCore(d)
	if err != nil {
		t.Fatal(err)
	}
	id := func(value contract.ID) string { return fmt.Sprintf("%x", value) }
	key := func(binding contract.KMSBinding) map[string]any {
		protection := "software"
		if binding.ProtectionClass == contract.HardwareProtection {
			protection = "hardware"
		}
		return map[string]any{"selector": binding.KeySelector, "public_key": binding.SPKI, "binding": map[string]any{"id": id(binding.BindingID), "incarnation": id(binding.BindingIncarnationID), "serial": binding.BindingSerial, "protection": protection}}
	}
	recipients, generatedRecipients := map[string]any{}, map[string]any{}
	var authority contract.RecipientRecord
	for i, row := range d.Recipients {
		if row.RecipientID == d.AuthorityRecipientID {
			authority = row
			continue
		}
		ref := fmt.Sprintf("recipient%d", i)
		recipients[ref] = map[string]any{"id": id(row.RecipientID), "display_name": row.DisplayName, "encryption_key": row.CurrentBinding.KeySelector}
		generatedRecipients[ref] = map[string]any{"id": id(row.RecipientID), "encryption": key(*row.CurrentBinding)}
	}
	if authority.CurrentBinding == nil || d.Recovery != nil {
		t.Fatal("local integration public key fixture shape differs")
	}
	store := map[string]any{"region": fixture.Archive.Location.Region, "bucket": fixture.Archive.Location.Bucket, "prefix": fixture.Archive.Location.PrefixBeforeHEAD}
	if fixture.Archive.Location.ExpectedOwner != "" {
		store["expected_owner"] = fixture.Archive.Location.ExpectedOwner
	}
	var generator any
	if err := json.Unmarshal([]byte(`{"kind":"generated","plugin":"cloudflare-account-token","epoch":0,"retirement":"manual","settings":{"account":"0123456789abcdef0123456789abcdef","name":"future-token","policies":[{"effect":"allow","permission_groups":["123456789abcdef0123456789abcdef0"],"resources":[{"kind":"account","id":"0123456789abcdef0123456789abcdef"}]}]}}`), &generator); err != nil {
		t.Fatal(err)
	}
	destinations := map[string]any{}
	if outputs {
		for _, row := range []struct {
			name, plugin string
			settings     map[string]any
		}{
			{"aws", "aws-secrets-manager", map[string]any{"account": "123456789012", "region": "us-east-1"}},
			{"gcp", "gcp-secret-manager", map[string]any{"project_number": "123456789"}},
			{"github-environment", "github-actions-environment", map[string]any{"owner": "owner", "repository": "repo", "environment": "prod"}},
			{"github-organization", "github-actions-organization", map[string]any{"owner": "owner", "visibility": "selected", "repositories": []uint64{7, 11}}},
			{"github-repository", "github-actions-repository", map[string]any{"owner": "owner", "repository": "repo"}},
		} {
			destinations[row.name] = map[string]any{"plugin": row.plugin, "settings": row.settings}
		}
	}
	editable := map[string]any{"schema": "enkv/configuration/v3", "generated": ".enkv/prod.generated.json", "domain": map[string]any{"name": "prod", "provider": family, "store": store, "authority": map[string]any{"display_name": authority.DisplayName, "signing_key": d.NormalSigning.KeySelector, "encryption_key": authority.CurrentBinding.KeySelector}, "recovery": map[string]bool{"enabled": false}}, "recipients": recipients, "entries": map[string]any{"future-token": map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": generator}}, "outputs": map[string]any{"destinations": destinations, "routing": map[string]any{}}}
	generated := map[string]any{"schema": "enkv/generated/v2", "file_id": id(contract.Hash([]byte("plugin installation file"))), "domain": map[string]any{"id": id(d.DomainID), "authority": map[string]any{"id": id(d.AuthorityRecipientID), "signing": map[string]any{"selector": d.NormalSigning.KeySelector, "public_key": d.NormalSigning.SPKI}, "encryption": key(*authority.CurrentBinding)}, "recovery": map[string]bool{"enabled": false}}, "recipients": generatedRecipients, "secrets": map[string]any{}, "public_basis": map[string]any{"kind": "genesis", "descriptor": descriptor}}
	directory := sourceFixtureRoot(t)
	for name, value := range map[string]any{"configuration.json": editable, ".enkv/prod.generated.json": generated} {
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		rawSourceWrite(t, directory, name, string(body))
	}
	return filepath.Join(directory, "configuration.json")
}

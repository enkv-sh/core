package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"testing"

	"enkv.sh/sdk/artifact"
)

func packageConfig(t *testing.T) config {
	t.Helper()
	directory := t.TempDir()
	keyFile := func(name, value string) string {
		key, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		body, err := artifact.EncodePublicKeyPEM(ed25519.PublicKey(key))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	return config{directory: directory, bundle: "full", version: "1.2.3", versioned: true, environment: "production", pluginKeys: []string{keyFile("plugin.pem", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")}, cliKey: keyFile("cli.pem", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"), output: filepath.Join(directory, "output")}
}

// full_only: false
func TestPackageConfigurationRejectsInvalidAssembly(t *testing.T) {
	c := packageConfig(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := assemblyFlags(ctx, c); !errors.Is(err, context.Canceled) {
		t.Fatal("assembly public-key read lost cancellation", err)
	}
	link, err := assemblyFlags(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"installedPluginOrigin=https://enkv.sh/releases/", "installedPluginRedirectHosts=github.com,release-assets.githubusercontent.com", "installedCLIVerificationKey=3d4017", "installedPluginKeys=d75a98"} {
		if !strings.Contains(link, want) {
			t.Fatal("fixed production assembly differs", want)
		}
	}
	for _, bundle := range []string{"full", "aws", "gcp"} {
		selected := c
		selected.bundle = bundle
		if _, err := assemblyFlags(t.Context(), selected); err != nil {
			t.Fatal(err)
		}
		args := buildArguments("build", selected)
		want := []string{"build", "-mod=readonly", "-trimpath", "-buildvcs=false"}
		if bundle != "full" {
			want = append(want, "-tags=enkv_"+bundle)
		}
		if !slices.Equal(args, want) {
			t.Fatal("bundle flags differ", args, want)
		}
	}
	for _, row := range []struct {
		name   string
		change func(*config)
	}{
		{"missing-directory", func(c *config) { c.directory = "" }},
		{"missing-output", func(c *config) { c.output = "" }},
		{"invalid-version", func(c *config) { c.version = "v1.0.0" }},
		{"unknown-bundle", func(c *config) { c.bundle = "other" }},
		{"unknown-environment", func(c *config) { c.environment = "other" }},
		{"missing-plugin-root", func(c *config) { c.pluginKeys = nil }},
		{"missing-cli-root", func(c *config) { c.cliKey = "" }},
		{"duplicate-plugin-root", func(c *config) { c.pluginKeys = append(slices.Clone(c.pluginKeys), c.pluginKeys[0]) }},
		{"same-purpose-roots", func(c *config) { c.cliKey = c.pluginKeys[0] }},
		{"retained-cli-root", func(c *config) { c.pluginKeys = append(slices.Clone(c.pluginKeys), c.cliKey) }},
		{"production-origin", func(c *config) { c.origin = "https://127.0.0.1/releases/" }},
		{"production-tls", func(c *config) { c.tlsRoot = c.cliKey }},
		{"development-without-origin", func(c *config) { c.environment = "development" }},
		{"development-without-tls", func(c *config) { c.environment = "development"; c.origin = "https://127.0.0.1/releases/" }},
	} {
		t.Run(row.name, func(t *testing.T) {
			damaged := c
			row.change(&damaged)
			if _, err := assemblyFlags(t.Context(), damaged); err == nil {
				t.Fatal("invalid assembly accepted")
			}
		})
	}
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	c.environment, c.origin, c.tlsRoot = "development", server.URL+"/releases/", filepath.Join(c.directory, "tls.pem")
	if err := os.WriteFile(c.tlsRoot, cert, 0600); err != nil {
		t.Fatal(err)
	}
	link, err = assemblyFlags(t.Context(), c)
	if err != nil || !strings.Contains(link, "installedPluginOrigin="+c.origin) || !strings.Contains(link, "installedPluginRedirectHosts= ") || !strings.Contains(link, "installedPluginTLSRoots=LS0t") {
		t.Fatal("controlled development assembly differs", err)
	}
	for _, origin := range []string{"http://127.0.0.1/releases/", "https://localhost/releases/", "https://192.0.2.1/releases/", "https://name@127.0.0.1/releases/", server.URL + "/releases/?", server.URL + "/releases", server.URL + "/bad path/", "https://127.0.0.1:0/releases/", "https://127.0.0.1:65536/releases/"} {
		damaged := c
		damaged.origin = origin
		if _, err := assemblyFlags(t.Context(), damaged); err == nil {
			t.Fatal("invalid development origin accepted", origin)
		}
	}
	for _, body := range [][]byte{append([]byte("prefix\n"), cert...), append(append([]byte(nil), cert...), []byte("suffix")...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: server.Certificate().Raw}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("bad")})} {
		if err := os.WriteFile(c.tlsRoot, body, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := assemblyFlags(t.Context(), c); err == nil {
			t.Fatal("invalid TLS root accepted")
		}
	}
	if err := os.WriteFile(c.cliKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a public key")}), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := assemblyFlags(t.Context(), c); err == nil {
		t.Fatal("private key input accepted")
	}
}

// full_only: false
func TestPackageBuildEnvironmentIsExplicit(t *testing.T) {
	c := packageConfig(t)
	for _, key := range []string{"GOFLAGS", "GOEXPERIMENT", "GCCGO", "CC", "CXX", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS", "GOTOOLDIR", "GOCACHEPROG", "GOFIPS140", "GODEBUG", "GOOS", "GOARCH"} {
		t.Setenv(key, "")
	}
	environment, err := buildEnvironment(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"GOWORK=off", "GOENV=off", "GOTOOLCHAIN=local", "CGO_ENABLED=1", "GOOS=" + runtime.GOOS, "GOARCH=" + runtime.GOARCH} {
		if !slices.Contains(environment, want) {
			t.Fatal("fixed build input differs", want)
		}
	}
	workspace := filepath.Join(c.directory, "go.work")
	if err := os.WriteFile(workspace, []byte("go 1.27.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildEnvironment(config{workspace: workspace, versioned: true}); err == nil {
		t.Fatal("mixed source modes accepted")
	}
	for _, path := range []string{"", "go.work", c.directory} {
		if _, err := buildEnvironment(config{workspace: path}); err == nil {
			t.Fatal("invalid workspace accepted", path)
		}
	}
	environment, err = buildEnvironment(config{workspace: workspace})
	if err != nil || !slices.Contains(environment, "GOWORK="+workspace) {
		t.Fatal("explicit source workspace refused", err)
	}
	for _, key := range []string{"GOFLAGS", "GOEXPERIMENT", "GCCGO", "CC", "CXX", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS", "GOTOOLDIR", "GOCACHEPROG", "GOFIPS140", "GODEBUG", "GOOS", "GOARCH"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "unsupported")
			if _, err := buildEnvironment(c); err == nil {
				t.Fatal("custom or cross-build input accepted")
			}
		})
	}
}

// full_only: false
func TestCLIArchiveContainsOnlyExecutableAndSelectedLegalFiles(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "enkv")
	if err := os.WriteFile(executable, []byte("native executable fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	legal := map[string][]byte{"LICENSE": []byte("private license"), "NOTICE": []byte("selected notice"), "THIRD_PARTY_NOTICES.md": []byte("selected module licenses and Go license")}
	var first, second bytes.Buffer
	if err := writeArchive(t.Context(), &first, executable, legal); err != nil {
		t.Fatal(err)
	}
	if err := writeArchive(t.Context(), &second, executable, legal); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("archive headers are not deterministic")
	}
	reader := bytes.NewReader(first.Bytes())
	compressed, err := gzip.NewReader(reader)
	if err != nil {
		t.Fatal(err)
	}
	compressed.Multistream(false)
	archive := tar.NewReader(compressed)
	var names []string
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, header.Name)
		want, mode := legal[header.Name], int64(0644)
		if header.Name == "enkv" {
			want, mode = []byte("native executable fixture"), 0755
		}
		body, err := io.ReadAll(archive)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(body, want) || header.Mode != mode || header.Typeflag != tar.TypeReg || header.Format != tar.FormatUSTAR || header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" || header.ModTime.Unix() != 0 {
			t.Fatal("archive member differs", header)
		}
	}
	if !slices.Equal(names, []string{"LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md", "enkv"}) {
		t.Fatal("archive member set differs", names)
	}
	if _, err := io.Copy(io.Discard, compressed); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	if reader.Len() != 0 {
		t.Fatal("trailing archive bytes")
	}
	legal["plugin"] = []byte("unexpected executable")
	if err := writeArchive(t.Context(), io.Discard, executable, legal); err == nil {
		t.Fatal("extra member accepted")
	}
	delete(legal, "plugin")
	delete(legal, "LICENSE")
	if err := writeArchive(t.Context(), io.Discard, executable, legal); err == nil {
		t.Fatal("missing license accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	legal["LICENSE"] = []byte("license")
	if err := writeArchive(ctx, io.Discard, executable, legal); err == nil {
		t.Fatal("cancelled archive succeeded")
	}
}

// full_only: false
func TestChecksumAggregationUsesExactArchiveBytes(t *testing.T) {
	directory := t.TempDir()
	a, b := filepath.Join(directory, "a.tar.gz"), filepath.Join(directory, "b.tar.gz")
	if err := os.WriteFile(a, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(directory, "checksums.txt")
	if err := aggregateChecksums(t.Context(), output, []string{b, a}); err == nil {
		t.Fatal("empty archive accepted")
	}
	if err := os.WriteFile(b, []byte("def"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := aggregateChecksums(t.Context(), output, []string{b, a}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	// SHA-256 literals are the standard digests of the three ASCII bytes abc and def.
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  a.tar.gz\ncb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34  b.tar.gz\n"
	if string(body) != want {
		t.Fatal("checksum bytes differ", string(body))
	}
	if err := aggregateChecksums(t.Context(), output, []string{a}); err == nil {
		t.Fatal("existing checksum file overwritten")
	}
	if err := aggregateChecksums(t.Context(), filepath.Join(directory, "duplicates.txt"), []string{a, a}); err == nil {
		t.Fatal("duplicate basename accepted")
	}
	body, err = os.ReadFile(output)
	if err != nil || string(body) != want {
		t.Fatal("existing checksum bytes changed", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := aggregateChecksums(ctx, filepath.Join(directory, "cancelled.txt"), []string{a}); err == nil {
		t.Fatal("cancelled checksums succeeded")
	}
	if _, err := os.Stat(filepath.Join(directory, "cancelled.txt")); !os.IsNotExist(err) {
		t.Fatal("cancelled checksum published", err)
	}
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), []string{"-checksums", filepath.Join(directory, "mixed.txt"), "-bundle", "full", a}, &stdout, &stderr); code != 2 {
		t.Fatal("mixed checksum/build invocation accepted", code)
	}
	if code := run(t.Context(), []string{"-help"}, &stdout, &stderr); code != 0 {
		t.Fatal("help failed", code)
	}
	silent := &cliDiagnosticWriter{failure: errors.New("unused output stream")}
	quietOutput := filepath.Join(directory, "quiet-checksums.txt")
	if code := run(t.Context(), []string{"-checksums", quietOutput, a, b}, silent, silent); code != 0 || silent.calls != 0 {
		t.Fatal("silent checksum aggregation used an output stream", code, silent.calls)
	}
	body, err = os.ReadFile(quietOutput)
	if err != nil || string(body) != want {
		t.Fatal("silent checksum bytes differ", err)
	}
}

// full_only: false
func TestCompiledCLIClosureMustMatchSelectedModules(t *testing.T) {
	main := artifact.SourceModule{Path: "enkv.sh/compositions/full", Main: true}
	helper := artifact.SourceModule{Path: "example.test/helper", Version: "v1.2.3", Sum: "h1:fixture"}
	packages := []artifact.SourcePackage{{Module: &main}, {Module: &helper}}
	dependency := debug.Module{Path: helper.Path, Version: helper.Version, Sum: helper.Sum}
	if err := checkCompiledModules(packages, main.Path, []*debug.Module{&dependency}); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name string
		deps []*debug.Module
	}{
		{"missing", nil},
		{"extra", []*debug.Module{&dependency, {Path: "example.test/extra"}}},
		{"version", []*debug.Module{{Path: helper.Path, Version: "v1.2.4", Sum: helper.Sum}}},
		{"sum", []*debug.Module{{Path: helper.Path, Version: helper.Version, Sum: "other"}}},
		{"replacement", []*debug.Module{{Path: helper.Path, Version: helper.Version, Sum: helper.Sum, Replace: &debug.Module{Path: "other"}}}},
	} {
		t.Run(row.name, func(t *testing.T) {
			if err := checkCompiledModules(packages, main.Path, row.deps); err == nil {
				t.Fatal("compiled closure mismatch accepted")
			}
		})
	}
	helper.Main, helper.Version, helper.Sum = true, "", ""
	dependency.Version, dependency.Sum = "(devel)", ""
	if err := checkCompiledModules(packages, main.Path, []*debug.Module{&dependency}); err != nil {
		t.Fatal("workspace module identity refused", err)
	}
	helper.Replace = &artifact.SourceModule{Path: "/local/helper"}
	dependency.Replace = &debug.Module{Path: "/local/helper", Version: "(devel)"}
	if err := checkCompiledModules(packages, main.Path, []*debug.Module{&dependency}); err != nil {
		t.Fatal("local replacement identity refused", err)
	}
	dependency.Replace.Path = "/other/helper"
	if err := checkCompiledModules(packages, main.Path, []*debug.Module{&dependency}); err == nil {
		t.Fatal("replacement owner mismatch accepted")
	}
}

type shortArchiveWriter struct{}

func (shortArchiveWriter) Write(body []byte) (int, error) { return len(body) / 2, nil }

// full_only: false
func TestArchiveStreamsEnforceCompleteByteBound(t *testing.T) {
	var output bytes.Buffer
	bounded := &archiveOutput{writer: &output, length: artifact.MaxArchiveBytes - 1}
	if n, err := bounded.Write([]byte("ab")); n != 0 || err == nil || output.Len() != 0 || bounded.length != artifact.MaxArchiveBytes-1 {
		t.Fatal("stream crossed its bound", n, err, bounded.length)
	}
	if n, err := bounded.Write([]byte("a")); n != 1 || err != nil || output.String() != "a" || bounded.length != artifact.MaxArchiveBytes {
		t.Fatal("exact stream bound refused", n, err, bounded.length)
	}
	if n, err := bounded.Write([]byte("b")); n != 0 || err == nil || output.String() != "a" || bounded.length != artifact.MaxArchiveBytes {
		t.Fatal("byte after stream bound accepted", n, err, bounded.length)
	}
	short := &archiveOutput{writer: shortArchiveWriter{}}
	if n, err := short.Write([]byte("ab")); n != 1 || err != io.ErrShortWrite || short.length != 1 {
		t.Fatal("short stream write lost failure or count", n, err, short.length)
	}
}

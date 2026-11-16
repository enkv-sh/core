package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/sdk/artifact"
)

// RFC 8032 section 7.1 second test seed in its RFC 8410 PKCS8 DER form.
// The shared public-only packaging fixtures are in packaged_cli.go.
const cliArchiveCLIPrivatePEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIEzNCJso/5banbbDRuwRTg9bijGfNaumJNqM9u1PuKb7
-----END PRIVATE KEY-----
`

// Expected from the inspect command contract: optional source, suffix inference,
// and the complete public flag set. Keep one literal for all installed builds.
const installedInspectHelp = "inspect [--source PATH] [--source-format yaml|json] [--recipient ALIAS | --recipient-id ID | --capacity [--cursor TOKEN]] [--json]\n" +
	"Default source: enkv.yaml in the current directory; explicit paths infer YAML/YML/JSON syntax unless a format overrides it.\n" +
	"  -capacity\n    \t\n  -cursor value\n    \t\n  -json\n    \tuse JSON output\n" +
	"  -log-level string\n    \t\n  -recipient value\n    \tlocal recipient alias; mutually exclusive with --recipient-id\n" +
	"  -recipient-id value\n    \tnonzero 64-character lowercase hexadecimal recipient ID; mutually exclusive with --recipient\n" +
	"  -source value\n    \tconfiguration path (default enkv.yaml in the current directory)\n" +
	"  -source-format value\n    \tyaml or json; overrides path suffix inference (default YAML for enkv.yaml)\n" +
	"  -telemetry-config string\n    \t\n"

// full_only: false
func TestNativeCLIArchivesInstallOutsideCheckout(t *testing.T) {
	ctx, cancel := context.WithTimeout(cacheOnlyGoContext(t.Context()), 6*time.Minute)
	defer cancel()
	root := maintainedCloudflareRoot(t)
	_, docs := distributionRoots(t)
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
			t.Fatal("installed archive fixture must be outside source checkouts", err)
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
	var requests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	for name, body := range map[string]string{"plugin-public.pem": cliArchivePluginPublicPEM, "cli-public.pem": cliArchiveCLIPublicPEM, "catalog.pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))} {
		rawSourceWrite(t, scratch, name, body)
	}
	env := environment(goEnvironment(), publicPluginBuildEnvironment("off"))
	goRoot := strings.TrimSpace(string(runModuleModeCommand(t, ctx, filepath.Join(root, "compositions/full"), publicPluginBuildEnvironment(workspace), "env", "GOROOT")))
	var archives []string
	var expectedChecksums strings.Builder
	for _, bundle := range []string{"full", "aws", "gcp"} {
		t.Run(bundle, func(t *testing.T) {
			output := filepath.Join(scratch, "package-"+bundle)
			runCLIArchiveCommand(t, ctx, tool, scratch, env, "-directory", filepath.Join(root, "compositions/full"), "-bundle", bundle, "-version", "1.2.3", "-workspace", workspace, "-environment", "development", "-plugin-public-key", filepath.Join(scratch, "plugin-public.pem"), "-cli-public-key", filepath.Join(scratch, "cli-public.pem"), "-development-origin", server.URL+"/releases/", "-development-tls-root", filepath.Join(scratch, "catalog.pem"), "-output", output)
			filename := "enkv-" + bundle + "-1.2.3-" + runtime.GOOS + "-" + runtime.GOARCH + ".tar.gz"
			entries, err := os.ReadDir(output)
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, entry := range entries {
				names = append(names, entry.Name())
			}
			wantNames := []string{"checksums.txt", filename}
			slices.Sort(wantNames)
			if !slices.Equal(names, wantNames) {
				t.Fatal("CLI package output set differs", names)
			}
			archive := filepath.Join(output, filename)
			digest, length, err := cliArchiveIdentity(archive)
			if err != nil || length <= 0 || length > artifact.MaxArchiveBytes {
				t.Fatal("compressed archive identity or bound differs", err)
			}
			checksum := fmt.Sprintf("%x  %s\n", digest, filename)
			actual, err := os.ReadFile(filepath.Join(output, "checksums.txt"))
			if err != nil || string(actual) != checksum {
				t.Fatal("checksum does not bind exact compressed bytes", err)
			}
			archives = append(archives, archive)
			install := filepath.Join(scratch, "installed-"+bundle)
			if err := os.Mkdir(install, 0700); err != nil {
				t.Fatal(err)
			}
			legal := extractCLIArchive(t, archive, install)
			executable := filepath.Join(install, "enkv")
			info, err := buildinfo.ReadFile(executable)
			if err != nil {
				t.Fatal(err)
			}
			if info.GoVersion != "go1.27.3" || info.Main.Path != "enkv.sh/compositions/full" || info.Path != "enkv.sh/compositions/full/cmd/enkv" {
				t.Fatal("archive executable build identity differs", info)
			}
			checkCLIArchiveLegalOwners(t, root, goRoot, legal, info)
			checkCLIArchiveSelectedModules(t, bundle, info)
			settings := map[string]string{}
			for _, setting := range info.Settings {
				settings[setting.Key] = setting.Value
			}
			for key, want := range map[string]string{"GOOS": runtime.GOOS, "GOARCH": runtime.GOARCH, "CGO_ENABLED": "1", "-trimpath": "true"} {
				if settings[key] != want {
					t.Fatal("archive native build setting differs", key, settings[key], want)
				}
			}
			if want := ""; bundle != "full" {
				want = "enkv_" + bundle
				if settings["-tags"] != want {
					t.Fatal("archive bundle tag differs", settings["-tags"], want)
				}
			} else if settings["-tags"] != "" {
				t.Fatal("full archive has selected bundle tag", settings["-tags"])
			}

			if err := os.Chmod(executable, 0555); err != nil {
				t.Fatal(err)
			}
			before, _, err := cloudflareArtifactIdentity(executable)
			if err != nil {
				t.Fatal(err)
			}
			emptyPath := filepath.Join(install, "empty-path")
			if err := os.Mkdir(emptyPath, 0700); err != nil {
				t.Fatal(err)
			}
			out, diagnostic := runCLIArchiveCommand(t, ctx, executable, install, []string{"PATH=" + emptyPath}, "inspect", "--help")
			if len(diagnostic) != 0 || string(out) != installedInspectHelp {
				t.Fatal("installed CLI help differs", string(out), string(diagnostic))
			}
			after, _, err := cloudflareArtifactIdentity(executable)
			if err != nil || before != after {
				t.Fatal("installed CLI changed during execution", err)
			}
			t.Logf("bundle=%s platform=%s archive_sha256=%x cli_sha256=%x compiled_modules=%d", bundle, runtime.GOOS+"/"+runtime.GOARCH, digest, before, len(info.Deps)+1)
		})
	}
	if t.Failed() {
		return
	}
	if requests.Load() != 0 {
		t.Fatal("packaging or installed help accessed the development catalog", requests.Load())
	}
	slices.Sort(archives)
	for _, archive := range archives {
		digest, _, err := cliArchiveIdentity(archive)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&expectedChecksums, "%x  %s\n", digest, filepath.Base(archive))
	}
	aggregate := filepath.Join(scratch, "checksums.txt")
	// Reverse the input order; checksum rows must still use canonical basename order.
	slices.Reverse(archives)
	runCLIArchiveCommand(t, ctx, tool, scratch, env, append([]string{"-checksums", aggregate}, archives...)...)
	actual, err := os.ReadFile(aggregate)
	if err != nil || string(actual) != expectedChecksums.String() {
		t.Fatal("aggregate checksum bytes differ", err)
	}
	rawSourceWrite(t, scratch, "cli-private.pem", cliArchiveCLIPrivatePEM)
	signer := filepath.Join(scratch, "enkv-artifact-sign")
	if _, err := runGo(ctx, root, "sdk/artifact", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", signer, "./cmd/enkv-artifact-sign"); err != nil {
		t.Fatal(err)
	}
	signature := filepath.Join(scratch, "checksums.sig")
	runCLIArchiveCommand(t, ctx, signer, scratch, env, "-purpose", "cli-checksums", "-input", aggregate, "-key", filepath.Join(scratch, "cli-private.pem"), "-output", signature)
	body, err := os.ReadFile(signature)
	if err != nil || len(body) != 64 {
		t.Fatal("actual checksum signature length differs", err)
	}
	runCLIArchiveCommand(t, ctx, signer, scratch, env, "-purpose", "cli-checksums", "-verify", "-input", aggregate, "-key", filepath.Join(scratch, "cli-public.pem"), "-signature", signature)
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Fatal("trusted OpenSSL 3.x is required", err)
	}
	version, _ := runCLIArchiveCommand(t, ctx, openssl, scratch, env, "version")
	if !bytes.HasPrefix(version, []byte("OpenSSL 3.")) {
		t.Fatal("trusted OpenSSL 3.x is required", string(version))
	}
	runCLIArchiveCommand(t, ctx, openssl, scratch, env, "pkeyutl", "-verify", "-pubin", "-inkey", filepath.Join(scratch, "cli-public.pem"), "-rawin", "-in", aggregate, "-sigfile", signature)
	if requests.Load() != 0 {
		t.Fatal("archive verification accessed the development catalog", requests.Load())
	}
}

func cliArchiveIdentity(path string) ([32]byte, int64, error) {
	var digest [32]byte
	info, err := os.Lstat(path)
	if err != nil {
		return digest, 0, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > artifact.MaxArchiveBytes {
		return digest, 0, fmt.Errorf("CLI archive type or size refused")
	}
	file, err := os.Open(path)
	if err != nil {
		return digest, 0, err
	}
	hash := sha256.New()
	length, copyErr := io.Copy(hash, io.LimitReader(file, artifact.MaxArchiveBytes+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || length != info.Size() {
		return digest, 0, fmt.Errorf("CLI archive measurement failed: read=%v close=%v length=%d expected=%d", copyErr, closeErr, length, info.Size())
	}
	copy(digest[:], hash.Sum(nil))
	return digest, length, nil
}

func runCLIArchiveCommand(t *testing.T, ctx context.Context, binary, directory string, env []string, args ...string) ([]byte, []byte) {
	t.Helper()
	var stdout, stderr limitedOutput
	result := runProcessOutput(ctx, binary, directory, args, env, 2*time.Minute, &stdout, &stderr)
	if !result.Started || !result.Joined || result.Status != "passed" || stdout.overflow || stderr.overflow {
		t.Fatalf("archive command failed: result=%+v stdout=%s stderr=%s", result, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Logf("archive command diagnostics: %s", stderr.String())
	}
	return bytes.Clone(stdout.Bytes()), bytes.Clone(stderr.Bytes())
}

func extractCLIArchive(t *testing.T, path, directory string) map[string][]byte {
	t.Helper()
	archive, err := extractStockCLIArchive(t.Context(), path, directory)
	if err != nil {
		t.Fatal(err)
	}
	legal := map[string][]byte{}
	for name, member := range archive.members {
		if name == "enkv" {
			continue
		}
		body, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || uint64(len(body)) != member.Length || artifact.Hash(body) != member.SHA256 {
			t.Fatal("extracted stock legal member changed", name, err)
		}
		legal[name] = body
	}
	return legal
}

func checkCLIArchiveLegalOwners(t *testing.T, root, goRoot string, legal map[string][]byte, info *debug.BuildInfo) {
	t.Helper()
	license, err := os.ReadFile(filepath.Join(root, "compositions/full/LICENSE"))
	if err != nil || !bytes.Equal(legal["LICENSE"], license) || !bytes.HasPrefix(license, []byte("# PolyForm Shield License 1.0.0\n")) {
		t.Fatal("CLI license differs from its actual Shield owner", err)
	}
	goLicense, err := os.ReadFile(filepath.Join(goRoot, "LICENSE"))
	if err != nil {
		t.Fatal(err)
	}
	section := append([]byte("Go toolchain\nSource file: LICENSE\n\n"), goLicense...)
	section = append(section, []byte("\n\n")...)
	if bytes.Count(legal["THIRD_PARTY_NOTICES.md"], section) != 1 {
		t.Fatal("actual Go toolchain license was not preserved exactly")
	}
	expected := map[string]bool{info.Main.Path: true}
	for _, module := range info.Deps {
		if expected[module.Path] {
			t.Fatal("compiled legal owner repeats", module.Path)
		}
		expected[module.Path] = true
	}
	actual := map[string]bool{}
	for _, match := range regexp.MustCompile(`(?m)^Module: ([^\n]+)\nVersion: [^\n]*\n`).FindAllSubmatch(legal["THIRD_PARTY_NOTICES.md"], -1) {
		actual[string(match[1])] = true
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("notice legal owner set differs from actual compiled closure: got=%v want=%v", actual, expected)
	}
	var notice []byte
	for _, name := range []string{"NOTICE", "NOTICE.txt"} {
		body, err := os.ReadFile(filepath.Join(root, "compositions/full", name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		notice = append(notice, body...)
		if !bytes.Contains(legal["NOTICE"], body) {
			t.Fatal("main owner notice bytes were not retained", name)
		}
	}
	if (len(notice) != 0) != (len(legal["NOTICE"]) != 0) {
		t.Fatal("main owner notice presence differs")
	}
}

func checkCLIArchiveSelectedModules(t *testing.T, bundle string, info *debug.BuildInfo) {
	t.Helper()
	modules := map[string]bool{info.Main.Path: true}
	for _, module := range info.Deps {
		modules[module.Path] = true
	}
	required := []string{}
	excluded := []string{}
	switch bundle {
	case "full":
		required = append(required, "enkv.sh/providers/aws", "enkv.sh/providers/gcp", "enkv.sh/compositions/aws", "enkv.sh/compositions/gcp", "github.com/aws/aws-sdk-go-v2/service/s3", "github.com/aws/aws-sdk-go-v2/service/kms", "google.golang.org/api")
	case "aws":
		required = append(required, "enkv.sh/providers/aws", "enkv.sh/compositions/aws", "github.com/aws/aws-sdk-go-v2/service/s3", "github.com/aws/aws-sdk-go-v2/service/kms")
		excluded = append(excluded, "enkv.sh/providers/gcp", "enkv.sh/compositions/gcp", "google.golang.org/api")
	case "gcp":
		required = append(required, "enkv.sh/providers/gcp", "enkv.sh/compositions/gcp", "google.golang.org/api")
		excluded = append(excluded, "enkv.sh/providers/aws", "enkv.sh/compositions/aws", "github.com/aws/aws-sdk-go-v2/service/s3", "github.com/aws/aws-sdk-go-v2/service/kms")
	}
	for _, path := range required {
		if !modules[path] {
			t.Fatal("archive omitted compiled owner", bundle, path)
		}
	}
	for _, path := range excluded {
		if modules[path] {
			t.Fatal("archive compiled an excluded provider or service owner", bundle, path)
		}
	}
}

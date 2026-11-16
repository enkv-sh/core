package plugininstallation

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"enkv.sh/sdk/artifact"
	artifactbuild "enkv.sh/sdk/artifact/build"
)

type fixture struct {
	metadata artifact.Metadata
	identity artifact.Digest
	output   string
	members  map[string][]byte
}

func makeFixture(t *testing.T, name, role, version, message string) fixture {
	t.Helper()
	for _, key := range []string{"GOFLAGS", "GOEXPERIMENT", "GCCGO", "CC", "CXX", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS", "GOTOOLDIR", "GOCACHEPROG", "GOFIPS140", "GODEBUG"} {
		t.Setenv(key, "")
	}
	for key, value := range map[string]string{"GOPROXY": "off", "GOSUMDB": "off", "GONOPROXY": "none"} {
		t.Setenv(key, value)
	}
	source := t.TempDir()
	for name, body := range map[string]string{"LICENSE": "fixture license\n", "go.mod": "module example.test/installation\n\ngo 1.27.0\n", "main.go": "package main\nfunc main(){panic(" + fmtQuote(message) + ")}\n"} {
		if err := os.WriteFile(filepath.Join(source, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	descriptor := fixtureDescriptor(t, name, role, version)
	body, err := artifact.EncodeDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "plugin.json"), body, 0600); err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(t.TempDir(), "go.work")
	if err := os.WriteFile(workspace, []byte("go 1.27.0\n\nuse "+fmtQuote(filepath.ToSlash(source))+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	output := fixtureOutput(t)
	marker, err := artifactbuild.Run(t.Context(), artifactbuild.Config{Directory: source, Descriptor: "plugin.json", Command: ".", Output: output, Workspace: workspace})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(output, filepath.FromSlash(marker.Directory))
	body, err = os.ReadFile(filepath.Join(path, "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := artifact.DecodeMetadata(body)
	if err != nil {
		t.Fatal(err)
	}
	members := map[string][]byte{"metadata.json": body, "LICENSE": []byte("fixture license\n")}
	for _, name := range []string{"plugin", "dependencies.bin"} {
		b, err := os.ReadFile(filepath.Join(path, name))
		if err != nil {
			t.Fatal(err)
		}
		members[name] = b
	}
	return fixture{metadata: metadata, identity: marker.Artifact, output: output, members: members}
}

func fixtureDescriptor(t *testing.T, name, role, version string) artifact.Descriptor {
	t.Helper()
	digest := artifact.Digest{1}
	// Fixed schema-1 environment route with no names or public data.
	route := append([]byte{0, 1}, digest[:]...)
	route = append(route, 1, 0, 0, 0, 0, 0)
	d := artifact.Descriptor{Schema: 1, Name: name, Role: role, Version: version, Wire: artifact.Contract{Kind: "wire", Identity: digest.String(), Version: 1}}
	switch role {
	case "generator":
		d.Generator = &artifact.GeneratorDeclaration{ConfigContractID: digest, CredentialRoute: route}
	case "output":
		d.Output = &artifact.OutputDeclaration{ConfigContractID: "private-output/v1", CredentialRoute: route}
	case "manifest-generator":
		d.Manifest = &artifact.ManifestDeclaration{ConfigContractID: "private-settings/v1", FormatContractID: "private-format/v1"}
	default:
		t.Fatal("invalid fixture role", role)
	}
	return d
}

func fixtureOutput(t *testing.T) string {
	t.Helper()
	output := t.TempDir()
	t.Cleanup(func() {
		if err := filepath.WalkDir(output, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return os.Chmod(path, 0700)
			}
			return nil
		}); err != nil {
			t.Error(err)
		}
	})
	return output
}

func fmtQuote(s string) string { b, _ := json.Marshal(s); return string(b) }
func tempDirectory(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}

type catalog struct {
	mu       sync.Mutex
	files    map[string][]byte
	requests []string
	key      ed25519.PrivateKey
	server   *httptest.Server
	releases []artifact.Release
	before   func(string)
}

func newCatalog(t *testing.T) *catalog {
	t.Helper()
	seed := sha256.Sum256([]byte("installation fixture signing key; never a release root"))
	c := &catalog{files: map[string][]byte{}, key: ed25519.NewKeyFromSeed(seed[:])}
	c.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		c.requests = append(c.requests, r.URL.Path)
		body, ok := c.files[r.URL.Path]
		body = slices.Clone(body)
		before := c.before
		c.mu.Unlock()
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("credentials reached catalog")
		}
		if before != nil {
			before(r.URL.Path)
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(c.server.Close)
	return c
}
func (c *catalog) assembly() Assembly {
	roots := x509.NewCertPool()
	roots.AddCert(c.server.Certificate())
	return Assembly{Origin: c.server.URL + "/releases/", PluginKeys: []ed25519.PublicKey{c.key.Public().(ed25519.PublicKey)}, TLSRoots: roots, Check: func(_ context.Context, m artifact.Metadata, _ []byte) error {
		if m.Version == "3.0.0" {
			return ErrIncompatible
		}
		return nil
	}}
}
func (c *catalog) coordinator(t *testing.T) *Coordinator {
	t.Helper()
	coordinator, err := newCoordinator(tempDirectory(t), c.assembly())
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}
func (c *catalog) count() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.requests) }

func (c *catalog) publish(t *testing.T, f fixture) {
	t.Helper()
	members := map[string][]byte{}
	for name, body := range f.members {
		members[name] = slices.Clone(body)
	}
	members["metadata.sig"] = ed25519.Sign(c.key, members["metadata.json"])
	names := make([]string, 0, len(members))
	for name := range members {
		names = append(names, name)
	}
	slices.Sort(names)
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	tarWriter := tar.NewWriter(gzipWriter)
	record := artifact.ArchiveRecord{Schema: "enkv/plugin-archive/v1", Purpose: "plugin-archive", Artifact: f.identity, Name: f.metadata.Name, Version: f.metadata.Version, Platform: f.metadata.Platform, Members: []artifact.ArchiveMember{}}
	for _, name := range names {
		mode := int64(0400)
		if name == "plugin" {
			mode = 0500
		}
		body := members[name]
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(body)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(body); err != nil {
			t.Fatal(err)
		}
		record.Members = append(record.Members, artifact.ArchiveMember{Name: name, Length: uint64(len(body)), SHA256: sha256.Sum256(body)})
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	record.Archive = artifact.ArchiveFile{Filename: "plugin.tar.gz", SHA256: sha256.Sum256(compressed.Bytes()), Length: uint64(compressed.Len())}
	body, err := artifact.EncodeArchiveRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, base := range []string{"/releases/" + releasePath(artifact.Selection{Name: f.metadata.Name, Version: f.metadata.Version, Platform: f.metadata.Platform}), "/releases/artifacts/" + f.identity.String() + "/"} {
		c.files[base+"archive.json"] = body
		c.files[base+"archive.sig"] = ed25519.Sign(c.key, body)
		c.files[base+"plugin.tar.gz"] = slices.Clone(compressed.Bytes())
	}
	c.releases = append(c.releases, artifact.Release{Version: f.metadata.Version, Platform: f.metadata.Platform, Artifact: f.identity})
	slices.SortFunc(c.releases, func(a, b artifact.Release) int { n, _ := artifact.CompareVersions(a.Version, b.Version); return n })
	index, err := artifact.EncodeReleaseIndex(artifact.ReleaseIndex{Schema: "enkv/plugin-index/v1", Name: f.metadata.Name, Releases: c.releases})
	if err != nil {
		t.Fatal(err)
	}
	c.files["/releases/plugins/"+f.metadata.Name+"/index.json"] = index
	c.files["/releases/plugins/"+f.metadata.Name+"/index.sig"] = ed25519.Sign(c.key, index)
}

func request(scope, name, version string, mode Mode) Request {
	return Request{Directory: scope, Requirements: []Requirement{{name, version}}, Mode: mode, CheckSource: func(context.Context) error { return nil }}
}
func resolve(t *testing.T, c *Coordinator, r Request) (*Installed, Installation) {
	t.Helper()
	session, rows, err := c.Resolve(t.Context(), r)
	if err != nil {
		t.Fatalf("resolve: %v %#v", err, rows)
	}
	if len(rows) != 1 || rows[0].Status != "verified" || rows[0].Reason != "none" {
		t.Fatalf("rows %#v", rows)
	}
	installed, ok := session.Lookup(r.Requirements[0].Name)
	if !ok {
		t.Fatal("installation absent")
	}
	return installed, rows[0]
}

// full_only: false
func TestOfficialSelectionRetainsExactRelease(t *testing.T) {
	catalog := newCatalog(t)
	c := catalog.coordinator(t)
	scope := tempDirectory(t)
	one := makeFixture(t, "private-renderer", "manifest-generator", "1.0.0", "A")
	catalog.publish(t, one)
	first, row := resolve(t, c, request(scope, "private-renderer", "", Prepare))
	if first.Identity() != one.identity || !row.Changed || row.Previous != nil {
		t.Fatalf("first %#v", row)
	}
	two := makeFixture(t, "private-renderer", "manifest-generator", "2.0.0", "B")
	catalog.publish(t, two)
	calls := catalog.count()
	for _, mode := range []Mode{Ordinary, Prepare} {
		got, row := resolve(t, c, request(scope, "private-renderer", "", mode))
		if got.Identity() != one.identity || row.Changed || row.Previous == nil || row.Previous.Artifact != one.identity {
			t.Fatalf("reuse %#v", row)
		}
	}
	if catalog.count() != calls {
		t.Fatal("reuse contacted release service")
	}
	upgraded, row := resolve(t, c, request(scope, "private-renderer", "", Upgrade))
	if upgraded.Identity() != two.identity || !row.Changed || row.Previous == nil || row.Previous.Artifact != one.identity {
		t.Fatalf("upgrade %#v", row)
	}
	pinned, row := resolve(t, c, request(scope, "private-renderer", "1.0.0", Upgrade))
	if pinned.Identity() != one.identity || !row.Changed {
		t.Fatalf("pin %#v", row)
	}
	calls = catalog.count()
	_, row = resolve(t, c, request(scope, "private-renderer", "1.0.0", Upgrade))
	if row.Changed || catalog.count() != calls {
		t.Fatal("pinned upgrade changed or downloaded")
	}
	_, rows, err := c.Resolve(t.Context(), request(scope, "private-renderer", "2.0.0", Ordinary))
	if err == nil || len(rows) != 1 || rows[0].Reason != "version-mismatch" || rows[0].Changed {
		t.Fatalf("ordinary pin mismatch %#v %v", rows, err)
	}
	installed := pinned
	if err := os.Remove(installed.Executable()); err != nil {
		t.Fatal(err)
	}
	_, _, err = c.Resolve(t.Context(), request(scope, "private-renderer", "1.0.0", Ordinary))
	if err == nil || catalog.count() != calls {
		t.Fatal("ordinary missing bytes did not refuse offline")
	}
	restored, row := resolve(t, c, request(scope, "private-renderer", "1.0.0", Prepare))
	if restored.Identity() != one.identity || row.Changed {
		t.Fatalf("restoration %#v", row)
	}
	if first.Identity() != one.identity {
		t.Fatal("invocation identity changed")
	}
}

// full_only: false
func TestFirstSelectionSkipsOnlyCompatibleStableCandidates(t *testing.T) {
	catalog := newCatalog(t)
	c := catalog.coordinator(t)
	for _, version := range []string{"1.0.0", "2.0.0", "3.0.0", "4.0.0-rc.1"} {
		catalog.publish(t, makeFixture(t, "private-renderer", "manifest-generator", version, version))
	}
	got, _ := resolve(t, c, request(tempDirectory(t), "private-renderer", "", Prepare))
	m, _ := got.Metadata()
	if m.Version != "2.0.0" {
		t.Fatal("wrong compatible version", m.Version)
	}
	got, _ = resolve(t, c, request(tempDirectory(t), "private-renderer", "4.0.0-rc.1", Prepare))
	m, _ = got.Metadata()
	if m.Version != "4.0.0-rc.1" {
		t.Fatal("explicit prerelease unavailable")
	}
	base := "/releases/" + releasePath(artifact.Selection{Name: "private-renderer", Version: "3.0.0", Platform: runtime.GOOS + "/" + runtime.GOARCH})
	catalog.mu.Lock()
	catalog.files[base+"archive.sig"] = make([]byte, 64)
	catalog.mu.Unlock()
	_, rows, err := c.Resolve(t.Context(), request(tempDirectory(t), "private-renderer", "", Prepare))
	if err == nil || len(rows) != 1 || rows[0].Reason != "signature-invalid" || rows[0].Changed {
		t.Fatalf("damaged higher release fell back %#v %v", rows, err)
	}
}

func writeSettings(t *testing.T, c *Coordinator, applications []artifact.Application) {
	t.Helper()
	slices.SortFunc(applications, func(a, b artifact.Application) int { return strings.Compare(a.Directory, b.Directory) })
	body, err := artifact.EncodeSettings(artifact.Settings{Schema: "enkv/plugin-settings/v1", Applications: applications})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.configDirectory, "plugins.json"), body, 0600); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestLocalCapturePrecedesPinAndRemainsApplicationScoped(t *testing.T) {
	for _, role := range []string{"generator", "output", "manifest-generator"} {
		t.Run(role, func(t *testing.T) { localCapturePrecedesPin(t, role) })
	}
}

func localCapturePrecedesPin(t *testing.T, role string) {
	catalog := newCatalog(t)
	c := catalog.coordinator(t)
	scope, other := tempDirectory(t), tempDirectory(t)
	official := makeFixture(t, "private-renderer", role, "1.0.0", "official")
	catalog.publish(t, official)
	_, _ = resolve(t, c, request(scope, "private-renderer", "", Prepare))
	local := makeFixture(t, "private-renderer", role, "2.0.0", "local")
	writeSettings(t, c, []artifact.Application{{Directory: scope, Plugins: []artifact.LocalPlugin{{Name: "private-renderer", Directory: local.output}}}})
	calls := catalog.count()
	installed, row := resolve(t, c, request(scope, "private-renderer", "1.0.0", Ordinary))
	if installed.Identity() != local.identity || row.Role != role || row.Source != "local" || row.Changed {
		t.Fatalf("local precedence %#v", row)
	}
	if strings.HasPrefix(installed.Executable(), local.output) {
		t.Fatal("selected mutable output")
	}
	_, rows, err := c.Resolve(t.Context(), request(other, "private-renderer", "", Ordinary))
	if err == nil || rows[0].Reason != "not-installed" || catalog.count() != calls {
		t.Fatalf("scope leak %#v %v", rows, err)
	}
	if err := os.WriteFile(filepath.Join(local.output, "build.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	_, rows, err = c.Resolve(t.Context(), request(scope, "private-renderer", "1.0.0", Ordinary))
	if err == nil || rows[0].Source != "local" || rows[0].Status == "verified" {
		t.Fatal("incomplete replacement fell back")
	}
	writeSettings(t, c, []artifact.Application{})
	resumed, row := resolve(t, c, request(scope, "private-renderer", "1.0.0", Ordinary))
	if resumed.Identity() != official.identity || row.Source != "official" || catalog.count() != calls {
		t.Fatal("official selection not preserved")
	}
	writeSettings(t, c, []artifact.Application{{Directory: scope, Plugins: []artifact.LocalPlugin{{Name: "private-renderer", Directory: official.output}}}})
	assembly := catalog.assembly()
	assembly.Check = func(_ context.Context, metadata artifact.Metadata, _ []byte) error {
		if metadata.Role == role {
			return ErrIncompatible
		}
		return nil
	}
	unsupported, err := newCoordinator(filepath.Dir(c.configDirectory), assembly)
	if err != nil {
		t.Fatal(err)
	}
	session, rows, err := unsupported.Resolve(t.Context(), request(scope, "private-renderer", "", Ordinary))
	if !errors.Is(err, ErrIncompatible) || session != nil || len(rows) != 1 || rows[0].Reason != "unsupported-protocol" || rows[0].Changed {
		t.Fatalf("unsupported family admitted %#v %v", rows, err)
	}
	build := filepath.Join(official.output, "builds", official.identity.String())
	if err := os.Chmod(build, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(build, "dependencies.bin")); err != nil {
		t.Fatal(err)
	}
	session, rows, err = c.Resolve(t.Context(), request(scope, "private-renderer", "", Ordinary))
	if err == nil || session != nil || len(rows) != 1 || rows[0].Status == "verified" || rows[0].Changed || catalog.count() != calls {
		t.Fatalf("missing dependency body admitted or fell back %#v %v", rows, err)
	}
}

// full_only: false
func TestOfficialProofRequiresExactAuthenticatedWholePackage(t *testing.T) {
	catalog := newCatalog(t)
	f := makeFixture(t, "private-renderer", "manifest-generator", "1.0.0", "proof")
	catalog.publish(t, f)
	for _, damage := range []string{"proof hash", "proof signature", "package signature", "extra member", "license", "metadata", "proof missing"} {
		t.Run(damage, func(t *testing.T) {
			c := catalog.coordinator(t)
			scope := tempDirectory(t)
			installed, _ := resolve(t, c, request(scope, "private-renderer", "", Prepare))
			proofPath := c.proofDirectory(artifact.Selection{Artifact: installed.identity, Proof: *installed.proof})
			path := filepath.Dir(installed.Executable())
			switch damage {
			case "proof hash":
				writeTestFile(t, filepath.Join(proofPath, "proof.json"), []byte("{}"))
			case "proof signature":
				writeTestFile(t, filepath.Join(proofPath, "metadata.sig"), make([]byte, 64))
			case "package signature":
				writeTestFile(t, filepath.Join(path, "metadata.sig"), make([]byte, 64))
			case "extra member":
				writeTestFile(t, filepath.Join(path, "extra"), []byte("x"))
			case "license":
				writeTestFile(t, filepath.Join(path, "LICENSE"), []byte("changed"))
			case "metadata":
				writeTestFile(t, filepath.Join(path, "metadata.json"), []byte("{}"))
			case "proof missing":
				if err := os.Remove(filepath.Join(proofPath, "archive.sig")); err != nil {
					t.Fatal(err)
				}
			}
			calls := catalog.count()
			session, rows, err := c.Resolve(t.Context(), request(scope, "private-renderer", "", Ordinary))
			if err == nil || session != nil || rows[0].Changed || rows[0].Status == "verified" || catalog.count() != calls {
				t.Fatalf("bad proof reused %#v %v", rows, err)
			}
		})
	}
}
func writeTestFile(t *testing.T, path string, body []byte) {
	t.Helper()
	if _, err := os.Stat(path); err == nil {
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestSelectionCommitRechecksSourceAndExactPriorUnderLock(t *testing.T) {
	catalog := newCatalog(t)
	c := catalog.coordinator(t)
	f := makeFixture(t, "private-renderer", "manifest-generator", "1.0.0", "source")
	catalog.publish(t, f)
	scope := tempDirectory(t)
	path := filepath.Join(c.store, "applications", artifact.Hash([]byte(scope)).String()+".json")
	if err := ensureDirectory(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	unlock, err := lock(t.Context(), path+".lock")
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	r := request(scope, "private-renderer", "", Prepare)
	var mu sync.Mutex
	changed := false
	r.CheckSource = func(context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		if changed {
			return ErrSourceChanged
		}
		return nil
	}
	catalog.mu.Lock()
	catalog.before = func(path string) {
		if strings.HasSuffix(path, "plugin.tar.gz") {
			close(entered)
			<-release
		}
	}
	catalog.mu.Unlock()
	go func() { _, _, err := c.Resolve(t.Context(), r); done <- err }()
	<-entered
	mu.Lock()
	changed = true
	mu.Unlock()
	close(release)
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrSourceChanged) {
		t.Fatal("changed source committed", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("selection published despite source change", err)
	}
	catalog.mu.Lock()
	catalog.before = nil
	catalog.mu.Unlock()
	otherBody := []byte(`{"schema":"enkv/plugin-selection/v1","directory":` + fmtQuote(scope) + `,"selections":[]}`)
	if err := os.WriteFile(path, otherBody, 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.commitSelection(t.Context(), path, scope, nil, otherBody, func(context.Context) error { return nil }); !errors.Is(err, ErrSourceChanged) {
		t.Fatal("changed prior was overwritten", err)
	}
	if b, err := os.ReadFile(path); err != nil || !bytes.Equal(b, otherBody) {
		t.Fatal("changed prior bytes changed", err)
	}
}

// full_only: false
func TestApplicationScopeAndClosedRecordsRefuseBeforeAcquisition(t *testing.T) {
	catalog := newCatalog(t)
	c := catalog.coordinator(t)
	scope := tempDirectory(t)
	for _, requirements := range [][]Requirement{{{"../unknown", ""}}, {{strings.Repeat("p", 256), ""}}, {{"private-renderer", "*"}}, {{"private-renderer", ""}, {"private-renderer", ""}}} {
		r := request(scope, "private-renderer", "", Prepare)
		r.Requirements = requirements
		if _, _, err := c.Resolve(t.Context(), r); err == nil {
			t.Fatal("bad requirements admitted")
		}
	}
	path := filepath.Join(c.store, "applications", artifact.Hash([]byte(scope)).String()+".json")
	if err := ensureDirectory(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, path, []byte(`{"schema":"enkv/plugin-selection/v1","directory":"/another/application","selections":[]}`))
	if _, rows, err := c.Resolve(t.Context(), request(scope, "private-renderer", "", Prepare)); err == nil || rows[0].Reason != "record-invalid" {
		t.Fatalf("wrong application admitted %#v %v", rows, err)
	}
	if catalog.count() != 0 {
		t.Fatal("invalid records contacted catalog")
	}
	key := sha256.Sum256([]byte(scope))
	if filepath.Base(path) != hex.EncodeToString(key[:])+".json" {
		t.Fatal("scope key differs")
	}
}

// full_only: false
func TestRetainedLocatorHasIndependentCanonicalBytes(t *testing.T) {
	const d = "0100000000000000000000000000000000000000000000000000000000000000"
	const body = `{"schema":"enkv/plugin-retained/v1","executor":"` + d + `","artifact":"` + d + `","proof":null}`
	v, err := decodeLocator([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeLocator(v)
	if err != nil || string(encoded) != body {
		t.Fatalf("canonical locator %s %v", encoded, err)
	}
	for _, bad := range []string{body + "\n", strings.Replace(body, "null", "\""+strings.Repeat("0", 64)+"\"", 1), strings.Replace(body, "\"executor\"", "\"unknown\"", 1), strings.Replace(body, "\"proof\":null", "\"proof\":null,\"proof\":null", 1)} {
		if _, err := decodeLocator([]byte(bad)); err == nil {
			t.Fatal("noncanonical locator admitted", bad)
		}
	}
}

// full_only: false
func TestStageCleanupPreservesForeignEntriesAndDirectoryReplacement(t *testing.T) {
	parent := tempDirectory(t)
	s, err := makeStage(parent)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.writeBytes(t.Context(), "owned", []byte("owned")); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(s.path, "foreign")
	if err := os.WriteFile(foreign, []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.finish(); err == nil {
		t.Fatal("foreign contents were silently removed")
	}
	if body, err := os.ReadFile(foreign); err != nil || string(body) != "foreign" {
		t.Fatal("foreign bytes lost", err)
	}
	s, err = makeStage(parent)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.writeBytes(t.Context(), "owned", []byte("owned")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(s.path, s.path+"-moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(s.path, 0700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(s.path, "owned"), []byte("replacement"))
	if err := s.finish(); err == nil {
		t.Fatal("directory replacement not reported")
	}
	if body, err := os.ReadFile(filepath.Join(s.path, "owned")); err != nil || string(body) != "replacement" {
		t.Fatal("replacement lost", err)
	}
}

// full_only: false
func TestStagePartialAdoptionDisposesEveryExtractedMember(t *testing.T) {
	for _, condition := range []string{"refused_next_member", "replaced_registered_member"} {
		t.Run(condition, func(t *testing.T) {
			parent := tempDirectory(t)
			s, err := makeStage(parent)
			if err != nil {
				t.Fatal(err)
			}
			var creators []*os.File
			for _, name := range []string{"metadata.json", "plugin"} {
				file, err := s.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
				if err != nil {
					t.Fatal(err)
				}
				creators = append(creators, file)
				if _, err := file.WriteString("owned " + name); err != nil {
					t.Fatal(err)
				}
				identity, err := file.Stat()
				if err != nil {
					t.Fatal(err)
				}
				if err := s.adopt(name, identity); err != nil {
					t.Fatal(err)
				}
			}
			identity, err := creators[1].Stat()
			if err != nil {
				t.Fatal(err)
			}
			if err := s.adopt("metadata.sig", identity); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("missing member adoption cause: %v", err)
			}
			if condition == "replaced_registered_member" {
				if err := s.root.Rename("plugin", "original-plugin"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(s.path, "plugin"), []byte("foreign replacement"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := s.root.Remove("original-plugin"); err != nil {
					t.Fatal(err)
				}
			}
			for _, file := range creators {
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			finishErr := s.finish()
			entries, readErr := os.ReadDir(parent)
			if condition == "refused_next_member" {
				if finishErr != nil || readErr != nil || len(entries) != 0 {
					t.Errorf("partial registration left owned entries: %v %v %v", entries, finishErr, readErr)
				}
			} else {
				if finishErr == nil {
					t.Error("foreign replacement cleanup failure not reported")
				}
				got, err := os.ReadFile(filepath.Join(s.path, "plugin"))
				if err != nil || string(got) != "foreign replacement" {
					t.Errorf("foreign replacement changed: %q %v", got, err)
				}
				members, err := os.ReadDir(s.path)
				if err != nil || len(members) != 1 || members[0].Name() != "plugin" {
					t.Errorf("owned member survived partial registration: %v %v", members, err)
				}
			}
			if _, err := s.dir.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Errorf("stage directory handle not settled: %v", err)
			}
		})
	}
}

// full_only: false
func TestRemovedUnrelatedApplicationDoesNotBlockCurrentSelection(t *testing.T) {
	catalog := newCatalog(t)
	f := makeFixture(t, "private-renderer", "manifest-generator", "1.0.0", "current bytes")
	catalog.publish(t, f)
	c := catalog.coordinator(t)
	scope, unrelated := tempDirectory(t), tempDirectory(t)
	installed, _ := resolve(t, c, request(scope, "private-renderer", "1.0.0", Prepare))
	writeSettings(t, c, []artifact.Application{
		{Directory: scope, Plugins: []artifact.LocalPlugin{}},
		{Directory: unrelated, Plugins: []artifact.LocalPlugin{{Name: "unrelated-plugin", Directory: filepath.Join(unrelated, "removed-build")}}},
	})
	if err := os.Remove(unrelated); err != nil {
		t.Fatal(err)
	}
	selectionPath := filepath.Join(c.store, "applications", artifact.Hash([]byte(scope)).String()+".json")
	before, err := os.ReadFile(selectionPath)
	if err != nil {
		t.Fatal(err)
	}
	calls := catalog.count()
	for _, source := range []string{"official", "local"} {
		plugins := []artifact.LocalPlugin{}
		if source == "local" {
			plugins = append(plugins, artifact.LocalPlugin{Name: "private-renderer", Directory: f.output})
		}
		writeSettings(t, c, []artifact.Application{
			{Directory: scope, Plugins: plugins},
			{Directory: unrelated, Plugins: []artifact.LocalPlugin{{Name: "unrelated-plugin", Directory: filepath.Join(unrelated, "removed-build")}}},
		})
		for _, mode := range []Mode{Ordinary, Prepare} {
			session, rows, err := c.Resolve(t.Context(), request(scope, "private-renderer", "1.0.0", mode))
			if err != nil || session == nil || len(rows) != 1 {
				t.Fatalf("unrelated removed application blocked %s mode %d: %#v %v", source, mode, rows, err)
			}
			got, ok := session.Lookup("private-renderer")
			if !ok || got.Identity() != f.identity || got.Source() != source || rows[0].Artifact == nil || *rows[0].Artifact != f.identity || rows[0].Version != "1.0.0" || rows[0].Status != "verified" || rows[0].Changed {
				t.Fatalf("current selection differs: %#v", rows)
			}
			if source == "official" && (got.Executable() != installed.Executable() || rows[0].Previous == nil || rows[0].Previous.Artifact != f.identity) || source == "local" && (got.Executable() == installed.Executable() || rows[0].Previous != nil) {
				t.Fatalf("scope lost exact provenance: %#v", rows)
			}
		}
	}
	after, err := os.ReadFile(selectionPath)
	if err != nil || !bytes.Equal(before, after) || catalog.count() != calls {
		t.Fatal("scope-only reuse changed selection or contacted catalog", err)
	}
}

// full_only: false
func TestSettingsScopeKeepsWholeRecordAndCurrentOverrideValidation(t *testing.T) {
	catalog := newCatalog(t)
	f := makeFixture(t, "private-renderer", "manifest-generator", "1.0.0", "current bytes")
	catalog.publish(t, f)
	for _, condition := range []string{"unknown field", "malformed unrelated path", "missing current scope", "bad current override"} {
		t.Run(condition, func(t *testing.T) {
			c := catalog.coordinator(t)
			scope := tempDirectory(t)
			resolve(t, c, request(scope, "private-renderer", "1.0.0", Prepare))
			selectionPath := filepath.Join(c.store, "applications", artifact.Hash([]byte(scope)).String()+".json")
			prior, err := os.ReadFile(selectionPath)
			if err != nil {
				t.Fatal(err)
			}
			writeSettings(t, c, []artifact.Application{{Directory: scope, Plugins: []artifact.LocalPlugin{}}})
			settingsPath := filepath.Join(c.configDirectory, "plugins.json")
			switch condition {
			case "unknown field":
				writeTestFile(t, settingsPath, []byte(`{"schema":"enkv/plugin-settings/v1","applications":[],"unexpected":true}`))
			case "malformed unrelated path":
				writeTestFile(t, settingsPath, []byte(`{"schema":"enkv/plugin-settings/v1","applications":[{"directory":"relative","plugins":[]}]}`))
			case "missing current scope":
				if err := os.Remove(scope); err != nil {
					t.Fatal(err)
				}
			case "bad current override":
				writeSettings(t, c, []artifact.Application{{Directory: scope, Plugins: []artifact.LocalPlugin{{Name: "private-renderer", Directory: filepath.Join(scope, "missing-build")}}}})
			}
			calls := catalog.count()
			session, rows, err := c.Resolve(t.Context(), request(scope, "private-renderer", "1.0.0", Prepare))
			if err == nil || session != nil || catalog.count() != calls {
				t.Fatalf("invalid current inputs admitted: %#v %v", rows, err)
			}
			if condition == "unknown field" || condition == "malformed unrelated path" {
				if !errors.Is(err, ErrInvalid) || len(rows) != 0 {
					t.Fatalf("whole settings record validation weakened: %#v %v", rows, err)
				}
			}
			after, err := os.ReadFile(selectionPath)
			if err != nil || !bytes.Equal(prior, after) {
				t.Fatal("refused scope changed prior selection", err)
			}
		})
	}
}

// full_only: false
func TestChangedPinPreservesEarlierCommitWhenLaterSourceCheckFails(t *testing.T) {
	catalog := newCatalog(t)
	old := makeFixture(t, "first-renderer", "manifest-generator", "1.0.0", "old first bytes")
	first := makeFixture(t, "first-renderer", "manifest-generator", "2.0.0", "new first bytes")
	second := makeFixture(t, "second-renderer", "manifest-generator", "2.0.0", "second bytes")
	catalog.publish(t, old)
	catalog.publish(t, first)
	catalog.mu.Lock()
	catalog.releases = nil
	catalog.mu.Unlock()
	catalog.publish(t, second)
	c := catalog.coordinator(t)
	scope := tempDirectory(t)
	resolve(t, c, request(scope, "first-renderer", "1.0.0", Prepare))
	var sourceMu sync.Mutex
	changed := false
	catalog.mu.Lock()
	catalog.before = func(path string) {
		if strings.HasPrefix(path, "/releases/plugins/second-renderer/") && strings.HasSuffix(path, "plugin.tar.gz") {
			sourceMu.Lock()
			changed = true
			sourceMu.Unlock()
		}
	}
	catalog.mu.Unlock()
	r := request(scope, "first-renderer", "2.0.0", Prepare)
	r.Requirements = []Requirement{{Name: "first-renderer", Version: "2.0.0"}, {Name: "second-renderer", Version: "2.0.0"}}
	r.CheckSource = func(context.Context) error {
		sourceMu.Lock()
		defer sourceMu.Unlock()
		if changed {
			return ErrSourceChanged
		}
		return nil
	}
	session, rows, err := c.Resolve(t.Context(), r)
	if !errors.Is(err, ErrSourceChanged) || session != nil || len(rows) != 2 {
		t.Fatalf("later source failure lost assessment: %#v %v", rows, err)
	}
	if rows[0].Name != "first-renderer" || rows[0].Status != "verified" || !rows[0].Changed || rows[0].Artifact == nil || *rows[0].Artifact != first.identity || rows[0].Previous == nil || rows[0].Previous.Artifact != old.identity {
		t.Fatalf("earlier exact-pin commit was lost: %#v", rows[0])
	}
	if rows[1].Name != "second-renderer" || rows[1].Status == "verified" || rows[1].Changed || rows[1].Version != "2.0.0" || rows[1].Artifact == nil || *rows[1].Artifact != second.identity || rows[1].Previous != nil {
		t.Fatalf("later failed candidate facts differ: %#v", rows[1])
	}
	path := filepath.Join(c.store, "applications", artifact.Hash([]byte(scope)).String()+".json")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	record, err := artifact.DecodeSelectionRecord(body)
	if err != nil || record.Directory != scope || len(record.Selections) != 1 || record.Selections[0].Name != "first-renderer" || record.Selections[0].Version != "2.0.0" || record.Selections[0].Artifact != first.identity {
		t.Fatal("earlier commit was undone or failed candidate selected", record, err)
	}
}

// full_only: false
func TestSettingsFailureStopsSelectionBeforeAcquisition(t *testing.T) {
	catalog := newCatalog(t)
	for _, tc := range []struct{ name, body, reason string }{
		{"unknown-field", `{"schema":"enkv/plugin-settings/v1","applications":[],"unexpected":true}`, "unknown-field"},
		{"malformed-json", `{`, "invalid-json"},
		{"over-limit", strings.Repeat(" ", artifact.MaxRecordBytes+1), "limit-exceeded"},
		{"unreadable-existing", "", "settings-unavailable"},
		{"dangling-link", "", "settings-unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := catalog.coordinator(t)
			scope := tempDirectory(t)
			path := filepath.Join(c.configDirectory, "plugins.json")
			switch tc.name {
			case "unreadable-existing":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "dangling-link":
				if err := os.Symlink(filepath.Join(c.configDirectory, "absent"), path); err != nil {
					t.Fatal(err)
				}
			default:
				writeTestFile(t, path, []byte(tc.body))
			}
			r := request(scope, "alpha", "", Prepare)
			r.Requirements = []Requirement{{Name: "alpha"}, {Name: "zeta"}}
			calls := catalog.count()
			session, rows, err := c.Resolve(t.Context(), r)
			var failure *SettingsFailure
			if !errors.As(err, &failure) || !failure.Valid() || session != nil || len(rows) != 0 || catalog.count() != calls {
				t.Fatal("settings refusal invented plugin selection", session, rows, err)
			}
			action := "correct-settings"
			if tc.reason == "settings-unavailable" {
				action = "check-settings-access"
			}
			if failure.Stage != "settings" || failure.Object != "plugins.json" || failure.Path == nil || *failure.Path != path || failure.Reason != tc.reason || failure.Action != action {
				t.Fatal("settings stage facts differ", failure)
			}
		})
	}
	c := catalog.coordinator(t)
	settings, err := c.settings(t.Context(), tempDirectory(t))
	if err != nil || len(settings.Applications) != 0 {
		t.Fatal("absent optional settings changed", settings, err)
	}
}

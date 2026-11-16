package plugininstallation

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/sdk/artifact"
)

// full_only: false
func TestAcquisitionDamagePreservesPriorSelection(t *testing.T) {
	catalog := newCatalog(t)
	one := makeFixture(t, "private-renderer", "manifest-generator", "1.0.0", "old")
	two := makeFixture(t, "private-renderer", "manifest-generator", "2.0.0", "new")
	catalog.publish(t, one)
	catalog.publish(t, two)
	base := "/releases/" + releasePath(artifact.Selection{Name: two.metadata.Name, Version: two.metadata.Version, Platform: two.metadata.Platform})
	for _, damage := range []string{"signature", "truncated archive", "wrong record", "cancelled"} {
		t.Run(damage, func(t *testing.T) {
			c := catalog.coordinator(t)
			scope := tempDirectory(t)
			resolve(t, c, request(scope, "private-renderer", "1.0.0", Prepare))
			selectionPath := filepath.Join(c.store, "applications", artifact.Hash([]byte(scope)).String()+".json")
			prior, err := os.ReadFile(selectionPath)
			if err != nil {
				t.Fatal(err)
			}
			catalog.mu.Lock()
			signature := bytes.Clone(catalog.files[base+"archive.sig"])
			archive := bytes.Clone(catalog.files[base+"plugin.tar.gz"])
			record := bytes.Clone(catalog.files[base+"archive.json"])
			catalog.mu.Unlock()
			t.Cleanup(func() {
				catalog.mu.Lock()
				defer catalog.mu.Unlock()
				catalog.files[base+"archive.sig"] = signature
				catalog.files[base+"plugin.tar.gz"] = archive
				catalog.files[base+"archive.json"] = record
			})
			catalog.mu.Lock()
			switch damage {
			case "signature":
				catalog.files[base+"archive.sig"] = make([]byte, 64)
			case "truncated archive":
				catalog.files[base+"plugin.tar.gz"] = archive[:len(archive)/2]
			case "wrong record":
				catalog.files[base+"archive.json"] = []byte("{}")
			case "cancelled":
			}
			catalog.mu.Unlock()
			ctx := t.Context()
			if damage == "cancelled" {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			session, rows, err := c.Resolve(ctx, request(scope, "private-renderer", "2.0.0", Prepare))
			if err == nil || session != nil {
				t.Fatal("damaged acquisition supplied session")
			}
			if damage != "cancelled" && (len(rows) != 1 || rows[0].Changed || rows[0].Previous == nil || rows[0].Previous.Artifact != one.identity || rows[0].Status == "verified") {
				t.Fatalf("failure facts %#v", rows)
			}
			if damage != "cancelled" && rows[0].Version != "2.0.0" {
				t.Fatalf("failed exact pin lost requested version: %#v", rows[0])
			}
			if damage == "truncated archive" {
				if rows[0].Artifact == nil || *rows[0].Artifact != two.identity {
					t.Fatalf("known candidate artifact lost: %#v", rows[0])
				}
			} else if damage != "cancelled" && rows[0].Artifact != nil {
				t.Fatalf("unresolved candidate borrowed prior artifact: %#v", rows[0])
			}
			after, err := os.ReadFile(selectionPath)
			if err != nil || !bytes.Equal(prior, after) {
				t.Fatal("failed acquisition changed prior", err)
			}
		})
	}
}

// full_only: false
func TestHTTPSAcquisitionRejectsUntrustedTLSAndRedirectHosts(t *testing.T) {
	catalog := newCatalog(t)
	assembly := catalog.assembly()
	assembly.TLSRoots = nil
	c, err := newCoordinator(tempDirectory(t), assembly)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.index(t.Context(), "private-renderer"); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
	var reached bool
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true; w.WriteHeader(200) }))
	defer other.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/asset", http.StatusFound)
	}))
	defer redirect.Close()
	assembly = catalog.assembly()
	assembly.Origin = redirect.URL + "/releases/"
	assembly.TLSRoots.AddCert(redirect.Certificate())
	assembly.TLSRoots.AddCert(other.Certificate())
	c, err = newCoordinator(tempDirectory(t), assembly)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.index(t.Context(), "private-renderer"); err == nil || reached {
		t.Fatal("unlisted redirect host reached", err)
	}
	assembly.Origin = strings.Replace(assembly.Origin, "https:", "http:", 1)
	if _, err := newCoordinator(tempDirectory(t), assembly); !errors.Is(err, ErrInvalid) {
		t.Fatal("HTTP origin accepted", err)
	}
}

// full_only: false
func TestOfficialIdentityCannotUseLocalCaptureAsProof(t *testing.T) {
	catalog := newCatalog(t)
	c := catalog.coordinator(t)
	f := makeFixture(t, "private-renderer", "manifest-generator", "1.0.0", "equal local official bytes")
	catalog.publish(t, f)
	scope := tempDirectory(t)
	writeSettings(t, c, []artifact.Application{{Directory: scope, Plugins: []artifact.LocalPlugin{{Name: "private-renderer", Directory: f.output}}}})
	local, _ := resolve(t, c, request(scope, "private-renderer", "", Ordinary))
	if local.Source() != "local" {
		t.Fatal("local incorrectly official")
	}
	writeSettings(t, c, []artifact.Application{})
	if _, _, err := c.Resolve(t.Context(), request(scope, "private-renderer", "", Ordinary)); !errors.Is(err, ErrMissing) {
		t.Fatal("local payload supplied official selection", err)
	}
	official, _ := resolve(t, c, request(scope, "private-renderer", "", Prepare))
	if official.Identity() != local.Identity() || official.Source() != "official" || official.Executable() == local.Executable() {
		t.Fatal("official provenance/payload separation failed")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(local.Executable()), "metadata.sig")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("immutable local capture acquired signature", err)
	}
}

// full_only: false
func TestCandidateCleanupFailureCannotBecomeSemanticFallback(t *testing.T) {
	catalog := newCatalog(t)
	one := makeFixture(t, "private-renderer", "manifest-generator", "1.0.0", "compatible")
	three := makeFixture(t, "private-renderer", "manifest-generator", "3.0.0", "incompatible")
	catalog.publish(t, one)
	catalog.publish(t, three)
	for _, source := range []string{"official", "local"} {
		t.Run(source, func(t *testing.T) {
			assembly := catalog.assembly()
			var c *Coordinator
			assembly.Check = func(_ context.Context, m artifact.Metadata, _ []byte) error {
				if m.Version != "3.0.0" {
					return nil
				}
				identity, err := m.Identity()
				if err != nil {
					return err
				}
				parent := filepath.Join(c.store, "packages", identity.String())
				if source == "local" {
					parent = filepath.Join(c.store, "builds")
				}
				entries, err := os.ReadDir(parent)
				if err != nil {
					return err
				}
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), ".stage-") {
						if err := os.WriteFile(filepath.Join(parent, entry.Name(), "foreign"), []byte("foreign"), 0600); err != nil {
							return err
						}
					}
				}
				return ErrIncompatible
			}
			var err error
			c, err = newCoordinator(tempDirectory(t), assembly)
			if err != nil {
				t.Fatal(err)
			}
			scope := tempDirectory(t)
			if source == "local" {
				writeSettings(t, c, []artifact.Application{{Directory: scope, Plugins: []artifact.LocalPlugin{{Name: three.metadata.Name, Directory: three.output}}}})
			}
			session, rows, err := c.Resolve(t.Context(), request(scope, "private-renderer", "", Prepare))
			if err == nil || session != nil || len(rows) != 1 || rows[0].Status != "unavailable" || rows[0].Reason != "unavailable" {
				t.Fatalf("cleanup failure became protocol refusal or fell back %#v %v", rows, err)
			}
			path := filepath.Join(c.store, "applications", artifact.Hash([]byte(scope)).String()+".json")
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("cleanup failure published selection", err)
			}
		})
	}
}

// full_only: false
func TestTrustedConfigurationRootAliasesUseOneInstallationStore(t *testing.T) {
	catalog := newCatalog(t)
	f := makeFixture(t, "private-renderer", "manifest-generator", "1.0.0", "exact installed bytes")
	catalog.publish(t, f)
	root, scope := tempDirectory(t), tempDirectory(t)
	alias := filepath.Join(tempDirectory(t), "configuration-link")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	var selected artifact.Digest
	var executable string
	for _, spelling := range []string{root, root + "/", alias, alias + "///"} {
		t.Run("root-"+strconv.Itoa(len(spelling)), func(t *testing.T) {
			coordinator, err := newCoordinator(spelling, catalog.assembly())
			if err != nil {
				t.Fatal("trusted configuration root refused", err)
			}
			if coordinator.configDirectory != filepath.Join(root, "enkv") || coordinator.store != filepath.Join(root, "enkv", "installation") {
				t.Fatal("root alias selected another installation store")
			}
			installed, _ := resolve(t, coordinator, request(scope, "private-renderer", "1.0.0", Prepare))
			if selected.IsZero() {
				selected, executable = installed.Identity(), installed.Executable()
			} else if installed.Identity() != selected || installed.Executable() != executable {
				t.Fatal("root alias changed exact installation")
			}
		})
	}
}

// full_only: false
func TestConfigurationDiscoveryResolvesTrustedHomeAncestor(t *testing.T) {
	catalog := newCatalog(t)
	root := tempDirectory(t)
	alias := filepath.Join(tempDirectory(t), "home-link")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	for _, spelling := range []string{alias, alias + "/"} {
		t.Run("suffix-"+strconv.Itoa(len(spelling)-len(alias)), func(t *testing.T) {
			t.Setenv("HOME", spelling)
			t.Setenv("XDG_CONFIG_HOME", spelling)
			coordinator, err := New(catalog.assembly())
			if err != nil {
				t.Fatal("trusted discovered root refused", err)
			}
			config := root
			if runtime.GOOS == "darwin" {
				config = filepath.Join(root, "Library", "Application Support")
			}
			if coordinator.store != filepath.Join(config, "enkv", "installation") {
				t.Fatal("discovery changed canonical installation location")
			}
		})
	}
}

// full_only: false
func TestConfigurationRootRefusesNondirectoryWithoutOwnedStorage(t *testing.T) {
	catalog := newCatalog(t)
	root := tempDirectory(t)
	file := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(file, []byte("preserved"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, spelling := range []string{file, file + "/", filepath.Join(file, "nested")} {
		coordinator, err := newCoordinator(spelling, catalog.assembly())
		if err == nil || coordinator != nil {
			t.Fatal("nondirectory configuration root accepted")
		}
	}
	entries, err := os.ReadDir(root)
	body, readErr := os.ReadFile(file)
	if err != nil || readErr != nil || len(entries) != 1 || entries[0].Name() != "not-a-directory" || string(body) != "preserved" {
		t.Fatal("refused root changed unrelated storage", err, readErr)
	}
}

type archiveResponseCloseFailure struct {
	transport http.RoundTripper
	failure   error
	closed    int
}

func (r *archiveResponseCloseFailure) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := r.transport.RoundTrip(request)
	if err == nil && strings.HasSuffix(request.URL.Path, ".tar.gz") {
		response.Body = &archiveBodyCloseFailure{ReadCloser: response.Body, owner: r}
	}
	return response, err
}

type archiveBodyCloseFailure struct {
	io.ReadCloser
	owner *archiveResponseCloseFailure
}

func (b *archiveBodyCloseFailure) Close() error {
	b.owner.closed++
	return errors.Join(b.ReadCloser.Close(), b.owner.failure)
}

// full_only: false
func TestAcquisitionResponseCloseFailureDisposesExtractedMembers(t *testing.T) {
	catalog := newCatalog(t)
	old := makeFixture(t, "private-renderer", "manifest-generator", "1.0.0", "previous exact bytes")
	next := makeFixture(t, "private-renderer", "manifest-generator", "2.0.0", "new exact bytes")
	catalog.publish(t, old)
	catalog.publish(t, next)
	c := catalog.coordinator(t)
	scope := tempDirectory(t)
	resolve(t, c, request(scope, "private-renderer", "1.0.0", Prepare))
	selectionPath := filepath.Join(c.store, "applications", artifact.Hash([]byte(scope)).String()+".json")
	prior, err := os.ReadFile(selectionPath)
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("archive response close failed")
	transport := &archiveResponseCloseFailure{transport: c.client.Transport, failure: failure}
	c.client.Transport = transport
	selected, rows, err := c.Resolve(t.Context(), request(scope, "private-renderer", "2.0.0", Prepare))
	wantRows := []Installation{{Name: "private-renderer", Version: "2.0.0", Artifact: &next.identity, Platform: next.metadata.Platform, Source: "official", Status: "unavailable", Reason: "unavailable", Previous: &Previous{Version: "1.0.0", Artifact: old.identity, Platform: old.metadata.Platform, Source: "official"}}}
	if !errors.Is(err, failure) || selected != nil || !reflect.DeepEqual(rows, wantRows) {
		t.Errorf("close failure result differs: got=%#v want=%#v error=%v", rows, wantRows, err)
	}
	if transport.closed != 1 {
		t.Errorf("archive response close count = %d", transport.closed)
	}
	after, err := os.ReadFile(selectionPath)
	if err != nil || !bytes.Equal(after, prior) {
		t.Errorf("close failure changed exact prior selection: %v", err)
	}
	parent := filepath.Join(c.store, "packages", next.identity.String())
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Errorf("extracted stage or package survived failed response close: %v %v", entries, err)
	}
	if entries, err := os.ReadDir(filepath.Join(c.store, "proofs", next.identity.String())); !errors.Is(err, os.ErrNotExist) && (err != nil || len(entries) != 0) {
		t.Errorf("close failure published proof: %v %v", entries, err)
	}
}

// full_only: false
func TestSettingsFailureWhenUserConfigPathUnavailable(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	_, err := New(newCatalog(t).assembly())
	var failure *SettingsFailure
	if !errors.As(err, &failure) || !failure.Valid() || failure.Path != nil || failure.Location != nil || failure.Reason != "settings-unavailable" {
		t.Fatal("configuration lookup failure lost settings stage", err, failure)
	}
}

package plugininstallation

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/sdk/artifact"
)

// full_only: false
func TestRetainedLocalLookupKeepsAcceptedAAfterCurrentB(t *testing.T) {
	catalog := newCatalog(t)
	c := catalog.coordinator(t)
	scope := tempDirectory(t)
	name := strings.Repeat("p", 255)
	one := makeFixture(t, name, "generator", "1.0.0", "original A")
	two := makeFixture(t, name, "generator", "2.0.0", "current B")
	writeSettings(t, c, []artifact.Application{{Directory: scope, Plugins: []artifact.LocalPlugin{{Name: name, Directory: one.output}}}})
	first, _ := resolve(t, c, request(scope, name, "", Ordinary))
	family, err := one.metadata.GeneratorFacts()
	if err != nil {
		t.Fatal(err)
	}
	other, err := two.metadata.GeneratorFacts()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := artifact.PublishBuild(t.Context(), one.output, two.metadata, filepath.Join(two.output, "builds", two.identity.String(), "plugin"), two.members["dependencies.bin"]); err != nil {
		t.Fatal(err)
	}
	second, _ := resolve(t, c, request(scope, name, "", Ordinary))
	if second.Identity() != two.identity || first.Identity() != one.identity {
		t.Fatal("current/retained identities changed")
	}
	writeSettings(t, c, []artifact.Application{})
	restarted, err := newCoordinator(filepath.Dir(c.configDirectory), catalog.assembly())
	if err != nil {
		t.Fatal(err)
	}
	check := func(_ context.Context, m artifact.Metadata, dependency []byte) error {
		actual, err := m.GeneratorFacts()
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(m.Family, one.metadata.Family) || !reflect.DeepEqual(actual, family) || !bytes.Equal(dependency, one.members["dependencies.bin"]) {
			return ErrIdentity
		}
		facts, err := artifact.DecodeDependency(dependency)
		if err != nil {
			return err
		}
		identity, err := artifact.DependencyID("generator", dependency)
		if err != nil || identity != actual.DependencyManifestID || facts.MainModule != m.MainModule {
			return ErrIdentity
		}
		return nil
	}
	retained, err := restarted.ResolveRetained(t.Context(), family.ExecutorID, check)
	if err != nil || retained.Identity() != one.identity {
		t.Fatalf("retained A unavailable %v", err)
	}
	if _, err := restarted.ResolveRetained(t.Context(), other.ExecutorID, check); !errors.Is(err, ErrIdentity) {
		t.Fatal("old tuple accepted B", err)
	}
	if err := os.Remove(c.locatorPath(family.ExecutorID)); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.ResolveRetained(t.Context(), family.ExecutorID, check); !errors.Is(err, ErrMissing) {
		t.Fatal("missing pointer scanned store", err)
	}
	if _, err := restarted.RestoreRetainedLocal(t.Context(), filepath.Join(one.output, "builds", one.identity.String()), one.identity, check); err != nil {
		t.Fatal("operator exact restoration", err)
	}
	if _, err := restarted.ResolveRetained(t.Context(), family.ExecutorID, check); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, c.locatorPath(family.ExecutorID), []byte("{}"))
	if _, err := restarted.ResolveRetained(t.Context(), family.ExecutorID, check); !errors.Is(err, ErrInvalid) {
		t.Fatal("corrupt pointer guessed bytes", err)
	}
	// The old locator is unreadable. A new installation must recover A from
	// its independent artifact even when the offered current build is B.
	fresh := catalog.coordinator(t)
	if installed, err := fresh.RestoreRetainedLocal(t.Context(), filepath.Join(two.output, "builds", two.identity.String()), one.identity, check); !errors.Is(err, ErrIdentity) || installed != nil {
		t.Fatal("different local build supplied the retained identity", err)
	}
	if installed, err := fresh.ResolveRetained(t.Context(), family.ExecutorID, check); !errors.Is(err, ErrMissing) || installed != nil {
		t.Fatal("declined build published a retained locator", err)
	}
	exact, err := fresh.RestoreRetainedLocal(t.Context(), filepath.Join(one.output, "builds", one.identity.String()), one.identity, check)
	if err != nil || exact.Identity() != one.identity || exact.Executable() == first.Executable() {
		t.Fatal("fresh installation did not restore the independent original", err)
	}
	executable, err := os.ReadFile(exact.Executable())
	if err != nil || artifact.Hash(executable) != one.metadata.Executable.SHA256 {
		t.Fatal("restored executable differs from the accepted digest", err)
	}
	if catalog.count() != 0 {
		t.Fatal("local retained lookup contacted service")
	}
}

// full_only: false
func TestRetainedOfficialLookupUsesExactProofWithoutLocalFallback(t *testing.T) {
	catalog := newCatalog(t)
	c := catalog.coordinator(t)
	scope := tempDirectory(t)
	one := makeFixture(t, "private-generator", "generator", "1.0.0", "official original")
	catalog.publish(t, one)
	installed, _ := resolve(t, c, request(scope, "private-generator", "", Prepare))
	family, err := one.metadata.GeneratorFacts()
	if err != nil {
		t.Fatal(err)
	}
	check := func(_ context.Context, m artifact.Metadata, body []byte) error {
		got, err := m.GeneratorFacts()
		if err != nil || !reflect.DeepEqual(got, family) || !bytes.Equal(body, one.members["dependencies.bin"]) {
			return ErrIdentity
		}
		return nil
	}
	proof := *installed.proof
	if err := os.Remove(c.locatorPath(family.ExecutorID)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RestoreRetainedOfficial(t.Context(), one.identity, proof, check); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(c.proofDirectory(artifact.Selection{Artifact: one.identity, Proof: proof}), "archive.sig"), make([]byte, 64))
	if _, err := c.ResolveRetained(t.Context(), family.ExecutorID, check); err == nil {
		t.Fatal("damaged official proof fell back")
	}
	if _, err := c.RestoreRetainedOfficial(t.Context(), one.identity, proof, check); err == nil {
		t.Fatal("present damaged proof was overwritten")
	}
}

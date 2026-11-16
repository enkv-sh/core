package plugininstallation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"enkv.sh/sdk/artifact"
)

// full_only: false
func TestLocalCaptureRejectsConcurrentMarkerChangeAndKeepsOldBytes(t *testing.T) {
	catalog := newCatalog(t)
	one := makeFixture(t, "private-renderer", "manifest-generator", "1.0.0", "captured A")
	two := makeFixture(t, "private-renderer", "manifest-generator", "2.0.0", "replacement B")
	assembly := catalog.assembly()
	mutate := false
	assembly.Check = func(ctx context.Context, m artifact.Metadata, _ []byte) error {
		if mutate && m.Version == "1.0.0" {
			mutate = false
			_, err := artifact.PublishBuild(ctx, one.output, two.metadata, filepath.Join(two.output, "builds", two.identity.String(), "plugin"), two.members["dependencies.bin"])
			return err
		}
		return nil
	}
	c, err := newCoordinator(tempDirectory(t), assembly)
	if err != nil {
		t.Fatal(err)
	}
	scope, other := tempDirectory(t), tempDirectory(t)
	writeSettings(t, c, []artifact.Application{{Directory: scope, Plugins: []artifact.LocalPlugin{{Name: "private-renderer", Directory: one.output}}}, {Directory: other, Plugins: []artifact.LocalPlugin{{Name: "private-renderer", Directory: one.output}}}})
	old, _ := resolve(t, c, request(scope, "private-renderer", "", Ordinary))
	mutate = true
	session, rows, err := c.Resolve(t.Context(), request(scope, "private-renderer", "9.0.0", Ordinary))
	if !errors.Is(err, ErrSourceChanged) || session != nil || rows[0].Status == "verified" {
		t.Fatalf("mixed capture admitted %#v %v", rows, err)
	}
	if rows[0].Source != "local" || rows[0].Version != "1.0.0" || rows[0].Artifact == nil || *rows[0].Artifact != one.identity || rows[0].Changed {
		t.Fatalf("captured local candidate facts lost %#v", rows[0])
	}
	for _, directory := range []string{scope, other} {
		current, _ := resolve(t, c, request(directory, "private-renderer", "", Ordinary))
		if current.Identity() != two.identity {
			t.Fatal("complete shared rebuild not captured")
		}
	}
	body, err := os.ReadFile(old.Executable())
	if err != nil || artifact.Hash(body) != one.metadata.Executable.SHA256 {
		t.Fatal("old captured bytes changed", err)
	}
	for _, condition := range []string{"invalid marker", "missing metadata", "mismatched metadata"} {
		t.Run(condition, func(t *testing.T) {
			output := fixtureOutput(t)
			marker := []byte(`{"schema":"enkv/plugin-build/v1","artifact":"` + one.identity.String() + `","directory":"builds/` + one.identity.String() + `"}`)
			var wantArtifact *artifact.Digest
			if condition == "invalid marker" {
				marker = []byte("{}")
			} else {
				wantArtifact = digestPointer(one.identity)
			}
			if err := os.WriteFile(filepath.Join(output, "build.json"), marker, 0600); err != nil {
				t.Fatal(err)
			}
			if condition == "mismatched metadata" {
				path := filepath.Join(output, "builds", one.identity.String())
				if err := os.MkdirAll(path, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, "metadata.json"), two.members["metadata.json"], 0600); err != nil {
					t.Fatal(err)
				}
			}
			writeSettings(t, c, []artifact.Application{{Directory: scope, Plugins: []artifact.LocalPlugin{{Name: "private-renderer", Directory: output}}}})
			session, rows, err := c.Resolve(t.Context(), request(scope, "private-renderer", "9.0.0", Ordinary))
			if err == nil || session != nil || len(rows) != 1 || rows[0].Source != "local" || rows[0].Status == "verified" || rows[0].Version != "" || rows[0].Changed {
				t.Fatalf("early capture facts %#v %v", rows, err)
			}
			if wantArtifact == nil {
				if rows[0].Artifact != nil {
					t.Fatal("invalid marker supplied identity")
				}
			} else if rows[0].Artifact == nil || *rows[0].Artifact != *wantArtifact {
				t.Fatal("valid marker identity lost")
			}
		})
	}
	if catalog.count() != 0 {
		t.Fatal("local capture contacted service")
	}
}

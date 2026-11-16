package plugininstallation

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"enkv.sh/sdk/artifact"
)

func wrapFixture(t *testing.T, base fixture, change func(*artifact.Descriptor)) fixture {
	t.Helper()
	metadata := base.metadata
	facts, err := metadata.GeneratorFacts()
	if err != nil {
		t.Fatal(err)
	}
	if change != nil {
		change(&facts.Descriptor)
	}
	facts, err = artifact.BindGeneratorFacts(facts, metadata.Executable.SHA256, metadata.Executable.Length, facts.DependencyManifestID)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	family := *metadata.Family
	family.Facts = body
	metadata.Family = &family
	output := fixtureOutput(t)
	marker, err := artifact.PublishBuild(t.Context(), output, metadata, filepath.Join(base.output, "builds", base.identity.String(), "plugin"), base.members["dependencies.bin"])
	if err != nil {
		t.Fatal(err)
	}
	body, err = os.ReadFile(filepath.Join(output, "builds", marker.Artifact.String(), "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(body) != marker.Artifact {
		t.Fatal("wrapper identity differs from exact bytes")
	}
	members := map[string][]byte{}
	for name, raw := range base.members {
		members[name] = bytes.Clone(raw)
	}
	members["metadata.json"] = body
	return fixture{metadata: metadata, identity: marker.Artifact, output: output, members: members}
}

// full_only: false
func TestRetainedPointerReplacementVerifiesCompleteProjectionAndBothTargets(t *testing.T) {
	catalog := newCatalog(t)
	original := makeFixture(t, "private-generator", "generator", "1.0.0", "immutable original family")
	catalog.publish(t, original)
	family, err := original.metadata.GeneratorFacts()
	if err != nil {
		t.Fatal(err)
	}
	for _, condition := range []string{"equal official wrapper", "invalid prior target", "invalid candidate target", "different config declaration", "different credential route"} {
		t.Run(condition, func(t *testing.T) {
			c := catalog.coordinator(t)
			scope := tempDirectory(t)
			writeSettings(t, c, []artifact.Application{{Directory: scope, Plugins: []artifact.LocalPlugin{{Name: original.metadata.Name, Directory: original.output}}}})
			old, _ := resolve(t, c, request(scope, original.metadata.Name, "", Ordinary))
			pointerPath := c.locatorPath(family.ExecutorID)
			before, err := os.ReadFile(pointerPath)
			if err != nil {
				t.Fatal(err)
			}
			var candidate *Installed
			var wrapper fixture
			if condition == "different config declaration" || condition == "different credential route" {
				wrapper = wrapFixture(t, original, func(d *artifact.Descriptor) {
					// Detach the borrowed declaration before changing the fixture.
					declaration := *d.Generator
					d.Generator = &declaration
					if condition == "different config declaration" {
						d.Generator.ConfigContractID[0] ^= 0x80
					} else {
						d.Generator.CredentialRoute = bytes.Clone(d.Generator.CredentialRoute)
						d.Generator.CredentialRoute[2] ^= 0x80
					}
				})
				candidate, err = c.local(t.Context(), wrapper.output, artifact.Selection{Name: wrapper.metadata.Name, Platform: wrapper.metadata.Platform})
			} else {
				wrapper = original
				candidate, err = c.acquire(t.Context(), releasePath(artifact.Selection{Name: wrapper.metadata.Name, Version: wrapper.metadata.Version, Platform: wrapper.metadata.Platform}), artifact.Selection{Name: wrapper.metadata.Name, Version: wrapper.metadata.Version, Platform: wrapper.metadata.Platform}, false)
			}
			if err != nil {
				t.Fatal(err)
			}
			newFamily, err := wrapper.metadata.GeneratorFacts()
			if err != nil || newFamily.ExecutorID != family.ExecutorID {
				t.Fatal("test did not preserve same executor", err)
			}
			if condition == "equal official wrapper" {
				if err := c.remember(t.Context(), candidate); err != nil {
					t.Fatal(err)
				}
				proofBytes, err := os.ReadFile(filepath.Join(c.proofDirectory(artifact.Selection{Artifact: wrapper.identity, Proof: *candidate.proof}), "proof.json"))
				if err != nil {
					t.Fatal(err)
				}
				proof := artifact.Digest(sha256.Sum256(proofBytes))
				want := `{"schema":"enkv/plugin-retained/v1","executor":"` + family.ExecutorID.String() + `","artifact":"` + wrapper.identity.String() + `","proof":"` + proof.String() + `"}`
				after, err := os.ReadFile(pointerPath)
				if err != nil || string(after) != want || !reflect.DeepEqual(newFamily, family) {
					t.Fatalf("alternate wrapper/proof locator %s %v", after, err)
				}
			} else {
				if condition == "invalid prior target" {
					writeTestFile(t, old.Executable(), []byte("changed prior bytes"))
				}
				if condition == "invalid candidate target" {
					writeTestFile(t, candidate.Executable(), []byte("changed candidate bytes"))
				}
				if err := c.remember(t.Context(), candidate); err == nil {
					t.Fatal("invalid pointer replacement admitted")
				}
				after, err := os.ReadFile(pointerPath)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("refused pointer replacement changed prior", err)
				}
				if condition == "invalid prior target" {
					writeSettings(t, c, []artifact.Application{})
					session, rows, err := c.Resolve(t.Context(), request(scope, original.metadata.Name, "1.0.0", Prepare))
					if err == nil || session != nil || len(rows) != 1 || rows[0].Status == "verified" || rows[0].Changed || rows[0].Source != "official" || rows[0].Version != "1.0.0" || rows[0].Artifact == nil || *rows[0].Artifact != wrapper.identity {
						t.Fatalf("retained verification failure lost captured candidate facts %#v %v", rows, err)
					}
					after, err := os.ReadFile(pointerPath)
					if err != nil || !bytes.Equal(before, after) {
						t.Fatal("refusal changed retained pointer", err)
					}
				}
			}
			if _, err := os.Stat(old.Executable()); errors.Is(err, os.ErrNotExist) {
				t.Fatal("prior payload removed")
			}
		})
	}
}

package plugininstallation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/sdk/artifact"
)

// full_only: false
func TestUnpinnedFailureRetainsAuthenticatedCandidateFacts(t *testing.T) {
	catalog := newCatalog(t)
	one := makeFixture(t, "private-renderer", "manifest-generator", "1.0.0", "prior")
	two := makeFixture(t, "private-renderer", "manifest-generator", "2.0.0", "candidate")
	catalog.publish(t, one)
	catalog.publish(t, two)
	base := "/releases/" + releasePath(artifact.Selection{Name: two.metadata.Name, Version: two.metadata.Version, Platform: two.metadata.Platform})
	for _, damage := range []string{"archive signature", "truncated bytes"} {
		t.Run(damage, func(t *testing.T) {
			c := catalog.coordinator(t)
			scope := tempDirectory(t)
			resolve(t, c, request(scope, "private-renderer", "1.0.0", Prepare))
			catalog.mu.Lock()
			sig := bytes.Clone(catalog.files[base+"archive.sig"])
			archive := bytes.Clone(catalog.files[base+"plugin.tar.gz"])
			catalog.mu.Unlock()
			t.Cleanup(func() {
				catalog.mu.Lock()
				defer catalog.mu.Unlock()
				catalog.files[base+"archive.sig"] = sig
				catalog.files[base+"plugin.tar.gz"] = archive
			})
			catalog.mu.Lock()
			if damage == "archive signature" {
				catalog.files[base+"archive.sig"] = make([]byte, 64)
			} else {
				catalog.files[base+"plugin.tar.gz"] = archive[:len(archive)/2]
			}
			catalog.mu.Unlock()
			session, rows, err := c.Resolve(t.Context(), request(scope, "private-renderer", "", Upgrade))
			if err == nil || session != nil || len(rows) != 1 {
				t.Fatalf("damage outcome %#v %v", rows, err)
			}
			row := rows[0]
			if row.Version != "2.0.0" || row.Artifact == nil || *row.Artifact != two.identity || row.Previous == nil || row.Previous.Artifact != one.identity || row.Changed || row.Status == "verified" {
				t.Fatalf("resolved candidate facts lost %#v", row)
			}
		})
	}
}

// full_only: false
func TestUpgradeRestoresMissingExactSelectionBeforeConsideringOlderIndex(t *testing.T) {
	catalog := newCatalog(t)
	c := catalog.coordinator(t)
	scope := tempDirectory(t)
	one := makeFixture(t, "private-renderer", "manifest-generator", "1.0.0", "older")
	two := makeFixture(t, "private-renderer", "manifest-generator", "2.0.0", "recorded")
	catalog.publish(t, one)
	catalog.publish(t, two)
	installed, _ := resolve(t, c, request(scope, "private-renderer", "2.0.0", Prepare))
	selectionPath := filepath.Join(c.store, "applications", artifact.Hash([]byte(scope)).String()+".json")
	before, err := os.ReadFile(selectionPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(installed.Executable()); err != nil {
		t.Fatal(err)
	}
	index, err := artifact.EncodeReleaseIndex(artifact.ReleaseIndex{Schema: "enkv/plugin-index/v1", Name: "private-renderer", Releases: []artifact.Release{{Version: "1.0.0", Platform: one.metadata.Platform, Artifact: one.identity}}})
	if err != nil {
		t.Fatal(err)
	}
	catalog.mu.Lock()
	catalog.files["/releases/plugins/private-renderer/index.json"] = index
	catalog.files["/releases/plugins/private-renderer/index.sig"] = ed25519.Sign(catalog.key, index)
	catalog.mu.Unlock()
	session, rows, err := c.Resolve(t.Context(), request(scope, "private-renderer", "", Upgrade))
	if err != nil {
		t.Fatalf("exact restoration failed %#v %v", rows, err)
	}
	got, ok := session.Lookup("private-renderer")
	if !ok || got.Identity() != two.identity || rows[0].Version != "2.0.0" || rows[0].Changed {
		t.Fatalf("missing selection downgraded %#v", rows)
	}
	after, err := os.ReadFile(selectionPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("exact artifact/proof selection changed", err)
	}
	actual, err := os.ReadFile(installed.Executable())
	if err != nil || !bytes.Equal(actual, two.members["plugin"]) {
		t.Fatal("exact selected bytes were not restored", err)
	}
	catalog.mu.Lock()
	requests := append([]string(nil), catalog.requests...)
	catalog.mu.Unlock()
	exact := "/releases/artifacts/" + two.identity.String() + "/archive.json"
	observed := false
	for _, path := range requests {
		if path == exact {
			observed = true
		}
	}
	if !observed {
		t.Fatal("upgrade did not restore exact selected coordinates")
	}
	assembly := catalog.assembly()
	priorCheck := assembly.Check
	assembly.Check = func(ctx context.Context, m artifact.Metadata, body []byte) error {
		if m.Version == "2.0.0" {
			return ErrIncompatible
		}
		return priorCheck(ctx, m, body)
	}
	replaced, err := newCoordinator(filepath.Dir(c.configDirectory), assembly)
	if err != nil {
		t.Fatal(err)
	}
	_, rows, err = replaced.Resolve(t.Context(), request(scope, "private-renderer", "", Upgrade))
	if !errors.Is(err, ErrIncompatible) || len(rows) != 1 || rows[0].Changed || rows[0].Version != "2.0.0" || rows[0].Artifact == nil || *rows[0].Artifact != two.identity {
		t.Fatalf("incompatible prior lost upgrade floor %#v %v", rows, err)
	}
	after, err = os.ReadFile(selectionPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("incompatible recorded selection downgraded", err)
	}
}

// full_only: false
func TestReplacementDoesNotAcquireUnusedOldExecutable(t *testing.T) {
	catalog := newCatalog(t)
	old := makeFixture(t, "private-renderer", "manifest-generator", "1.0.0", "old exact bytes")
	next := makeFixture(t, "private-renderer", "manifest-generator", "2.0.0", "new exact bytes")
	catalog.publish(t, old)
	catalog.publish(t, next)
	for _, operation := range []struct {
		name    string
		mode    Mode
		version string
	}{{"prepare-pin", Prepare, "2.0.0"}, {"upgrade-pin", Upgrade, "2.0.0"}, {"upgrade-unpinned", Upgrade, ""}} {
		states := []string{"present", "missing", "missing-package", "incompatible-present", "incompatible-missing"}
		if operation.version != "" {
			states = append(states, "missing-proof-and-package")
		}
		for _, state := range states {
			t.Run(operation.name+"/"+state, func(t *testing.T) {
				c := catalog.coordinator(t)
				scope := tempDirectory(t)
				installed, _ := resolve(t, c, request(scope, "private-renderer", "1.0.0", Prepare))
				selectionPath := filepath.Join(c.store, "applications", artifact.Hash([]byte(scope)).String()+".json")
				before, err := os.ReadFile(selectionPath)
				if err != nil {
					t.Fatal(err)
				}
				if state == "missing-package" || state == "missing-proof-and-package" {
					if err := os.RemoveAll(filepath.Dir(installed.Executable())); err != nil {
						t.Fatal(err)
					}
				} else if strings.Contains(state, "missing") {
					if err := os.Remove(installed.Executable()); err != nil {
						t.Fatal(err)
					}
				}
				if state == "missing-proof-and-package" {
					proofDirectory := c.proofDirectory(artifact.Selection{Artifact: old.identity, Proof: *installed.proof})
					if err := os.RemoveAll(proofDirectory); err != nil {
						t.Fatal(err)
					}
				}
				if strings.HasPrefix(state, "incompatible") {
					check := c.check
					c.check = func(ctx context.Context, metadata artifact.Metadata, body []byte) error {
						if metadata.Version == "1.0.0" {
							return ErrIncompatible
						}
						return check(ctx, metadata, body)
					}
				}
				catalog.mu.Lock()
				for path := range catalog.files {
					if strings.HasPrefix(path, "/releases/artifacts/"+old.identity.String()+"/") {
						delete(catalog.files, path)
					}
				}
				catalog.requests = nil
				catalog.mu.Unlock()
				session, rows, err := c.Resolve(t.Context(), request(scope, "private-renderer", operation.version, operation.mode))
				if err != nil || session == nil || len(rows) != 1 {
					t.Fatalf("replacement failed: rows=%#v error=%v", rows, err)
				}
				got, ok := session.Lookup("private-renderer")
				wantProof := fixtureOfficialProof(t, catalog, next)
				if !ok || got.Identity() != next.identity || got.Source() != "official" || got.proof == nil || *got.proof != wantProof {
					t.Fatalf("replacement captured identity/proof differs: %#v", rows)
				}
				metadata, err := got.Metadata()
				if err != nil || !reflect.DeepEqual(metadata, next.metadata) {
					t.Fatal("replacement metadata differs", err)
				}
				executable, err := os.ReadFile(got.Executable())
				if err != nil || !bytes.Equal(executable, next.members["plugin"]) {
					t.Fatal("replacement executable bytes differ", err)
				}
				wantRow := Installation{Name: "private-renderer", Role: "manifest-generator", Version: "2.0.0", Artifact: &next.identity, Platform: next.metadata.Platform, Source: "official", Status: "verified", Reason: "none", Changed: true}
				if state == "present" {
					wantRow.Previous = &Previous{Version: "1.0.0", Artifact: old.identity, Platform: old.metadata.Platform, Source: "official"}
				}
				wantRows, err := json.Marshal([]Installation{wantRow})
				if err != nil {
					t.Fatal(err)
				}
				actualRows, err := json.Marshal(rows)
				if err != nil || !bytes.Equal(actualRows, wantRows) {
					t.Fatalf("complete replacement rows differ: got=%s want=%s error=%v", actualRows, wantRows, err)
				}
				after, err := os.ReadFile(selectionPath)
				if err != nil || bytes.Equal(before, after) {
					t.Fatal("replacement did not commit a new selection", err)
				}
				wantRecord, err := artifact.EncodeSelectionRecord(artifact.SelectionRecord{Schema: "enkv/plugin-selection/v1", Directory: scope, Selections: []artifact.Selection{{Name: "private-renderer", Version: "2.0.0", Platform: next.metadata.Platform, Artifact: next.identity, Proof: wantProof}}})
				if err != nil || !bytes.Equal(after, wantRecord) {
					t.Fatalf("complete committed selection differs: got=%s want=%s error=%v", after, wantRecord, err)
				}
				base := "/releases/plugins/private-renderer/2.0.0/" + strings.ReplaceAll(next.metadata.Platform, "/", "-") + "/"
				want := []string{base + "archive.json", base + "archive.sig", base + "plugin.tar.gz"}
				if operation.version == "" {
					want = append([]string{"/releases/plugins/private-renderer/index.json", "/releases/plugins/private-renderer/index.sig"}, want...)
				}
				catalog.mu.Lock()
				requests := append([]string(nil), catalog.requests...)
				catalog.mu.Unlock()
				if !reflect.DeepEqual(requests, want) {
					t.Fatalf("release requests differ: got=%v want=%v", requests, want)
				}
			})
		}
	}
}

// full_only: false
func TestChangedPinDoesNotHidePresentOldDamage(t *testing.T) {
	catalog := newCatalog(t)
	old := makeFixture(t, "private-renderer", "manifest-generator", "1.0.0", "old bytes")
	next := makeFixture(t, "private-renderer", "manifest-generator", "2.0.0", "replacement bytes")
	catalog.publish(t, old)
	catalog.publish(t, next)
	for _, damage := range []string{"proof", "signature", "executable"} {
		t.Run(damage, func(t *testing.T) {
			c := catalog.coordinator(t)
			scope := tempDirectory(t)
			installed, _ := resolve(t, c, request(scope, "private-renderer", "1.0.0", Prepare))
			selectionPath := filepath.Join(c.store, "applications", artifact.Hash([]byte(scope)).String()+".json")
			prior, err := os.ReadFile(selectionPath)
			if err != nil {
				t.Fatal(err)
			}
			proof := c.proofDirectory(artifact.Selection{Artifact: installed.identity, Proof: *installed.proof})
			switch damage {
			case "proof":
				writeTestFile(t, filepath.Join(proof, "proof.json"), []byte("{}"))
			case "signature":
				writeTestFile(t, filepath.Join(proof, "archive.sig"), make([]byte, 64))
			case "executable":
				writeTestFile(t, installed.Executable(), []byte("damage"))
			}
			calls := catalog.count()
			session, rows, err := c.Resolve(t.Context(), request(scope, "private-renderer", "2.0.0", Prepare))
			if err == nil || session != nil || len(rows) != 1 || rows[0].Status != "tampered" || rows[0].Changed || rows[0].Version != "2.0.0" || rows[0].Artifact != nil || catalog.count() != calls {
				t.Fatalf("old damage was hidden by replacement: %#v %v", rows, err)
			}
			after, err := os.ReadFile(selectionPath)
			if err != nil || !bytes.Equal(prior, after) {
				t.Fatal("damaged prior selection changed", err)
			}
		})
	}
}

// full_only: false
func TestUpgradeWithoutNewerCandidateRequiresAvailableExactRepair(t *testing.T) {
	catalog := newCatalog(t)
	old := makeFixture(t, "private-renderer", "manifest-generator", "1.0.0", "exact retained bytes")
	catalog.publish(t, old)
	c := catalog.coordinator(t)
	scope := tempDirectory(t)
	installed, _ := resolve(t, c, request(scope, "private-renderer", "1.0.0", Prepare))
	selectionPath := filepath.Join(c.store, "applications", artifact.Hash([]byte(scope)).String()+".json")
	prior, err := os.ReadFile(selectionPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(installed.Executable()); err != nil {
		t.Fatal(err)
	}
	catalog.mu.Lock()
	for path := range catalog.files {
		if strings.HasPrefix(path, "/releases/artifacts/"+old.identity.String()+"/") {
			delete(catalog.files, path)
		}
	}
	catalog.requests = nil
	catalog.mu.Unlock()
	session, rows, err := c.Resolve(t.Context(), request(scope, "private-renderer", "", Upgrade))
	wantRows := []Installation{{Name: "private-renderer", Version: "1.0.0", Artifact: &old.identity, Platform: old.metadata.Platform, Source: "official", Status: "missing", Reason: "not-installed"}}
	if !errors.Is(err, ErrMissing) || session != nil || !reflect.DeepEqual(rows, wantRows) {
		t.Fatalf("unavailable exact repair supplied or changed selection: rows=%#v error=%v", rows, err)
	}
	after, err := os.ReadFile(selectionPath)
	if err != nil || !bytes.Equal(prior, after) {
		t.Fatal("unavailable repair changed exact old selection", err)
	}
	wantRequests := []string{"/releases/plugins/private-renderer/index.json", "/releases/plugins/private-renderer/index.sig", "/releases/artifacts/" + old.identity.String() + "/archive.json"}
	catalog.mu.Lock()
	requests := append([]string(nil), catalog.requests...)
	catalog.mu.Unlock()
	if !reflect.DeepEqual(requests, wantRequests) {
		t.Fatalf("old repair preceded newer-candidate selection: got=%v want=%v", requests, wantRequests)
	}
}

func fixtureOfficialProof(t *testing.T, catalog *catalog, f fixture) artifact.Digest {
	t.Helper()
	base := "/releases/plugins/" + f.metadata.Name + "/" + f.metadata.Version + "/" + strings.ReplaceAll(f.metadata.Platform, "/", "-") + "/"
	catalog.mu.Lock()
	archive := bytes.Clone(catalog.files[base+"archive.json"])
	archiveSignature := bytes.Clone(catalog.files[base+"archive.sig"])
	catalog.mu.Unlock()
	metadataSignature := ed25519.Sign(catalog.key, f.members["metadata.json"])
	body, err := json.Marshal(artifact.OfficialProof{Schema: "enkv/plugin-official-proof/v1", Artifact: f.identity, ArchiveRecord: artifact.Digest(sha256.Sum256(archive)), MetadataSignature: artifact.Digest(sha256.Sum256(metadataSignature)), ArchiveSignature: artifact.Digest(sha256.Sum256(archiveSignature))})
	if err != nil {
		t.Fatal(err)
	}
	return artifact.Digest(sha256.Sum256(body))
}

// full_only: false
func TestUpgradeMissingPayloadDoesNotUseUnauthenticatedFloor(t *testing.T) {
	catalog := newCatalog(t)
	old := makeFixture(t, "private-renderer", "manifest-generator", "1.0.0", "old exact bytes")
	next := makeFixture(t, "private-renderer", "manifest-generator", "2.0.0", "new candidate bytes")
	catalog.publish(t, old)
	catalog.publish(t, next)
	for _, damage := range []string{"absent proof", "invalid proof", "signed coordinate mismatch"} {
		t.Run(damage, func(t *testing.T) {
			c := catalog.coordinator(t)
			scope := tempDirectory(t)
			installed, _ := resolve(t, c, request(scope, "private-renderer", "1.0.0", Prepare))
			if err := os.Remove(installed.Executable()); err != nil {
				t.Fatal(err)
			}
			selectionPath := filepath.Join(c.store, "applications", artifact.Hash([]byte(scope)).String()+".json")
			proof := c.proofDirectory(artifact.Selection{Artifact: old.identity, Proof: *installed.proof})
			version := "1.0.0"
			switch damage {
			case "absent proof":
				if err := os.RemoveAll(proof); err != nil {
					t.Fatal(err)
				}
			case "invalid proof":
				writeTestFile(t, filepath.Join(proof, "proof.json"), []byte("{}"))
			case "signed coordinate mismatch":
				version = "9.0.0"
				body, err := artifact.EncodeSelectionRecord(artifact.SelectionRecord{Schema: "enkv/plugin-selection/v1", Directory: scope, Selections: []artifact.Selection{{Name: "private-renderer", Version: version, Platform: old.metadata.Platform, Artifact: old.identity, Proof: *installed.proof}}})
				if err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, selectionPath, body)
			}
			prior, err := os.ReadFile(selectionPath)
			if err != nil {
				t.Fatal(err)
			}
			catalog.mu.Lock()
			for path := range catalog.files {
				if strings.HasPrefix(path, "/releases/artifacts/"+old.identity.String()+"/") {
					delete(catalog.files, path)
				}
			}
			catalog.requests = nil
			catalog.mu.Unlock()
			session, rows, err := c.Resolve(t.Context(), request(scope, "private-renderer", "", Upgrade))
			want := Installation{Name: "private-renderer", Version: version, Artifact: &old.identity, Platform: old.metadata.Platform, Source: "official", Status: "tampered", Reason: "record-invalid"}
			wantRequests := []string(nil)
			if damage == "absent proof" {
				want.Status, want.Reason = "missing", "not-installed"
				wantRequests = []string{"/releases/artifacts/" + old.identity.String() + "/archive.json"}
				if !errors.Is(err, ErrMissing) {
					t.Errorf("missing exact proof lost missing error: %v", err)
				}
			} else if damage == "signed coordinate mismatch" {
				want.Reason = "identity-mismatch"
				if !errors.Is(err, ErrIdentity) {
					t.Errorf("signed floor coordinate mismatch lost identity error: %v", err)
				}
			} else if !errors.Is(err, ErrInvalid) {
				t.Errorf("malformed proof lost invalid error: %v", err)
			}
			if err == nil || session != nil || !reflect.DeepEqual(rows, []Installation{want}) {
				t.Errorf("unauthenticated floor was admitted: got=%#v want=%#v error=%v", rows, want, err)
			}
			after, readErr := os.ReadFile(selectionPath)
			if readErr != nil || !bytes.Equal(prior, after) {
				t.Errorf("invalid floor changed prior selection: %v", readErr)
			}
			catalog.mu.Lock()
			requests := append([]string(nil), catalog.requests...)
			catalog.mu.Unlock()
			if !reflect.DeepEqual(requests, wantRequests) {
				t.Errorf("floor used before authentication: got=%v want=%v", requests, wantRequests)
			}
		})
	}
}

// full_only: false
func TestUpgradeAuthenticatesMissingOldProofWithoutOldArchive(t *testing.T) {
	catalog := newCatalog(t)
	old := makeFixture(t, "private-renderer", "manifest-generator", "1.0.0", "old exact bytes")
	next := makeFixture(t, "private-renderer", "manifest-generator", "2.0.0", "new candidate bytes")
	catalog.publish(t, old)
	catalog.publish(t, next)
	for _, condition := range []string{"valid proof", "bad remote signature", "wrong exact proof", "wrong signed tuple", "damaged old package", "damaged partial proof"} {
		t.Run(condition, func(t *testing.T) {
			c := catalog.coordinator(t)
			scope := tempDirectory(t)
			installed, _ := resolve(t, c, request(scope, "private-renderer", "1.0.0", Prepare))
			if condition == "damaged old package" {
				writeTestFile(t, installed.Executable(), []byte("damaged old executable"))
			} else if err := os.RemoveAll(filepath.Dir(installed.Executable())); err != nil {
				t.Fatal(err)
			}
			oldProofPath := c.proofDirectory(artifact.Selection{Artifact: old.identity, Proof: *installed.proof})
			if condition == "damaged partial proof" {
				if err := os.Remove(filepath.Join(oldProofPath, "proof.json")); err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, filepath.Join(oldProofPath, "archive.sig"), make([]byte, 64))
			} else if err := os.RemoveAll(oldProofPath); err != nil {
				t.Fatal(err)
			}
			selectionPath := filepath.Join(c.store, "applications", artifact.Hash([]byte(scope)).String()+".json")
			version, proof := "1.0.0", *installed.proof
			if condition == "wrong exact proof" || condition == "wrong signed tuple" {
				if condition == "wrong exact proof" {
					proof = artifact.Digest{1}
				} else {
					version = "9.0.0"
				}
				body, err := artifact.EncodeSelectionRecord(artifact.SelectionRecord{Schema: "enkv/plugin-selection/v1", Directory: scope, Selections: []artifact.Selection{{Name: "private-renderer", Version: version, Platform: old.metadata.Platform, Artifact: old.identity, Proof: proof}}})
				if err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, selectionPath, body)
			}
			prior, err := os.ReadFile(selectionPath)
			if err != nil {
				t.Fatal(err)
			}
			oldBase := "/releases/artifacts/" + old.identity.String() + "/"
			catalog.mu.Lock()
			archiveSignature := bytes.Clone(catalog.files[oldBase+"archive.sig"])
			delete(catalog.files, oldBase+"plugin.tar.gz")
			if condition == "bad remote signature" {
				catalog.files[oldBase+"archive.sig"] = make([]byte, 64)
			}
			catalog.requests = nil
			catalog.mu.Unlock()
			t.Cleanup(func() {
				catalog.mu.Lock()
				catalog.files[oldBase+"archive.sig"] = archiveSignature
				catalog.mu.Unlock()
			})
			session, rows, err := c.Resolve(t.Context(), request(scope, "private-renderer", "", Upgrade))
			wantRequests := []string{oldBase + "archive.json", oldBase + "archive.sig"}
			if condition != "valid proof" {
				wantErr, reason := ErrIdentity, "identity-mismatch"
				if condition == "bad remote signature" {
					wantErr, reason = ErrSignature, "signature-invalid"
				}
				wantRows := []Installation{{Name: "private-renderer", Version: version, Artifact: &old.identity, Platform: old.metadata.Platform, Source: "official", Status: "tampered", Reason: reason}}
				if !errors.Is(err, wantErr) || session != nil || !reflect.DeepEqual(rows, wantRows) {
					t.Errorf("remote proof refusal differs: got=%#v want=%#v error=%v", rows, wantRows, err)
				}
				after, readErr := os.ReadFile(selectionPath)
				if readErr != nil || !bytes.Equal(after, prior) {
					t.Errorf("remote proof refusal changed prior selection: %v", readErr)
				}
			} else {
				if err != nil || session == nil || len(rows) != 1 {
					t.Fatalf("missing old archive blocked authenticated upgrade: %#v %v", rows, err)
				}
				wantProof := fixtureOfficialProof(t, catalog, next)
				got, ok := session.Lookup("private-renderer")
				if !ok || got.Identity() != next.identity || got.proof == nil || *got.proof != wantProof || got.Source() != "official" {
					t.Fatal("upgrade did not capture exact new authenticated build")
				}
				wantRows, err := json.Marshal([]Installation{{Name: "private-renderer", Role: "manifest-generator", Version: "2.0.0", Artifact: &next.identity, Platform: next.metadata.Platform, Source: "official", Status: "verified", Reason: "none", Changed: true}})
				if err != nil {
					t.Fatal(err)
				}
				actualRows, err := json.Marshal(rows)
				if err != nil || !bytes.Equal(actualRows, wantRows) {
					t.Fatalf("upgrade rows differ: got=%s want=%s error=%v", actualRows, wantRows, err)
				}
				body, err := os.ReadFile(selectionPath)
				if err != nil {
					t.Fatal(err)
				}
				wantRecord, err := artifact.EncodeSelectionRecord(artifact.SelectionRecord{Schema: "enkv/plugin-selection/v1", Directory: scope, Selections: []artifact.Selection{{Name: "private-renderer", Version: "2.0.0", Platform: next.metadata.Platform, Artifact: next.identity, Proof: wantProof}}})
				if err != nil || !bytes.Equal(body, wantRecord) {
					t.Fatalf("upgrade record differs: got=%s want=%s error=%v", body, wantRecord, err)
				}
				newBase := "/releases/plugins/private-renderer/2.0.0/" + strings.ReplaceAll(next.metadata.Platform, "/", "-") + "/"
				wantRequests = append(wantRequests, "/releases/plugins/private-renderer/index.json", "/releases/plugins/private-renderer/index.sig", newBase+"archive.json", newBase+"archive.sig", newBase+"plugin.tar.gz")
			}
			catalog.mu.Lock()
			requests := append([]string(nil), catalog.requests...)
			catalog.mu.Unlock()
			if !reflect.DeepEqual(requests, wantRequests) {
				t.Errorf("remote floor authentication requests differ: got=%v want=%v", requests, wantRequests)
			}
		})
	}
}

// full_only: false
func TestMissingInstallationDoesNotIgnoreJoinedFailures(t *testing.T) {
	missingFile := &os.PathError{Op: "open", Path: "/missing", Err: os.ErrNotExist}
	cleanup := errors.New("owned close failed")
	for _, check := range []struct {
		name string
		err  error
		want bool
	}{
		{"missing", ErrMissing, true},
		{"missing file", errors.Join(ErrMissing, missingFile), true},
		{"identity", errors.Join(ErrMissing, ErrIdentity), false},
		{"cleanup", errors.Join(ErrMissing, missingFile, cleanup), false},
		{"nested cleanup", errors.Join(ErrMissing, errors.Join(missingFile, cleanup)), false},
		{"cancelled", errors.Join(ErrMissing, context.Canceled), false},
		{"no failure", nil, false},
	} {
		t.Run(check.name, func(t *testing.T) {
			if got := onlyMissing(check.err); got != check.want {
				t.Fatalf("missing-only eligibility = %t, want %t", got, check.want)
			}
		})
	}
}

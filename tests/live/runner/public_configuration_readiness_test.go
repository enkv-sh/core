package core

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestPublicPortableSourceRewriteRestoresReadOnlyPair(t *testing.T) {
	for _, condition := range []string{"entries", "generated-reference"} {
		t.Run(condition, func(t *testing.T) {
			directory := t.TempDir()
			source := filepath.Join(directory, "source.json")
			if os.Mkdir(filepath.Join(directory, ".enkv"), 0700) != nil || os.WriteFile(filepath.Join(directory, ".enkv", "old.json"), []byte("{}\n"), 0400) != nil {
				t.Fatal("portable fixture unavailable")
			}
			publicWriteSource(t, source, map[string]any{"generated": ".enkv/old.json", "entries": map[string]any{}})
			original := publicSourceImage(t, source)
			copied := publicPortablePair(t, source, t.TempDir())
			document := publicSourceDocument(t, copied)
			want := "{\n  \"entries\": {\n    \"plain\": \"changed\"\n  },\n  \"generated\": \".enkv/old.json\"\n}\n"
			if condition == "entries" {
				document["entries"] = map[string]any{"plain": "changed"}
			} else {
				document["generated"] = ".enkv/new.json"
				if os.WriteFile(filepath.Join(filepath.Dir(copied), ".enkv", "new.json"), []byte("{\"changed\":true}\n"), 0400) != nil {
					t.Fatal("replacement dependency unavailable")
				}
				want = "{\n  \"entries\": {},\n  \"generated\": \".enkv/new.json\"\n}\n"
			}
			publicRewritePortableSource(t, copied, document)
			body, err := os.ReadFile(copied)
			if err != nil || !bytes.Equal(body, []byte(want)) {
				t.Fatal("portable rewrite bytes differ")
			}
			if err := filepath.WalkDir(filepath.Dir(copied), func(path string, entry os.DirEntry, err error) error {
				if err != nil || entry.IsDir() {
					return err
				}
				info, err := entry.Info()
				if err == nil && info.Mode().Perm() != 0400 {
					t.Errorf("portable file is writable: %s", filepath.Base(path))
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			publicImageUnchanged(t, original)
		})
	}
}

// full_only: false
func TestPublicConfigurationSourceImageIncludesExactDirectoryInventory(t *testing.T) {
	for _, condition := range []string{"unchanged", "sidecar", "generated-artifact", "changed-source", "removed-generated"} {
		t.Run(condition, func(t *testing.T) {
			directory := t.TempDir()
			generated := filepath.Join(directory, ".enkv", "fixture.json")
			source := filepath.Join(directory, "source.json")
			if os.Mkdir(filepath.Dir(generated), 0700) != nil || os.WriteFile(generated, []byte("{}\n"), 0600) != nil || os.WriteFile(source, []byte(`{"generated":".enkv/fixture.json"}`), 0600) != nil {
				t.Fatal("source image fixture unavailable")
			}
			image := publicSourceImage(t, source)
			var err error
			switch condition {
			case "sidecar":
				err = os.WriteFile(filepath.Join(directory, "unrequested.sidecar"), nil, 0600)
			case "generated-artifact":
				err = os.WriteFile(filepath.Join(directory, ".enkv", "unrequested.json"), nil, 0600)
			case "changed-source":
				err = os.WriteFile(source, []byte(`{"generated":".enkv/fixture.json","extra":true}`), 0600)
			case "removed-generated":
				err = os.Remove(generated)
			}
			if err != nil {
				t.Fatal(err)
			}
			if publicImageMatches(image) != (condition == "unchanged") {
				t.Fatal("source image missed changed bytes or a changed artifact inventory")
			}
		})
	}
}

// full_only: false
func TestPublicConfigurationSuccessorReservesMutationAllowance(t *testing.T) {
	for _, row := range []struct {
		name               string
		consumer, mutating bool
		args               []string
	}{
		{"initialize", false, true, []string{"init", "--source", "/source/config.json", "--source-format", "json"}},
		{"apply", false, true, []string{"apply", "--source", "/source/config.json", "--source-format", "json"}},
		{"withdrawn-exclude", false, false, []string{"recipients", "exclude", "--source", "/source/config.json", "--source-format", "json", "--name", "secret", "--recipient", "reader"}},
		{"rekey", false, true, []string{"rekey", "--source", "/source/config.json", "--source-format", "json", "--name", "secret"}},
		{"retire", false, true, []string{"recipients", "retire", "--source", "/source/config.json", "--source-format", "json", "--recipient", "reader"}},
		{"prepare-recipient", false, false, []string{"recipients", "add", "--source", "/source/config.json", "--source-format", "json", "--recipient", "reader", "--mode", "current"}},
		{"rename-recipient", false, false, []string{"recipients", "rename", "--source", "/source/config.json", "--source-format", "json", "--recipient", "reader", "--new-reference", "worker"}},
		{"administrative-apply", false, true, []string{"abandon", "apply", "--source", "/source/config.json", "--plan", "/source/plan.json"}},
		{"keys-replace", false, true, []string{"keys", "replace", "--source", "/source/config.json", "--target", "authority", "--authorizer", "recovery", "--signing", "selected", "--out", "/source/successor.json"}},
		{"administrative-list", false, false, []string{"abandon", "list", "--source", "/source/config.json"}},
		{"administrative-plan", false, false, []string{"abandon", "plan", "--source", "/source/config.json"}},
		{"keys-help", false, false, []string{"keys"}},
		{"keys-invalid-verb", false, false, []string{"keys", "restore"}},
		{"retired-end", false, false, []string{"end-work", "--connection", "/source/connection.json", "--basis", "/source/basis.json"}},
		{"retired-restore", false, false, []string{"restore-signer", "--connection", "/source/connection.json", "--basis", "/source/basis.json"}},
		{"successor", true, true, []string{"--source", "/source/config.json", "--source-format", "json", "--materialize-retained", "--successor-signing-selector", "selected", "--successor-scratch", "/source/scratch"}},
		{"successor-equals", true, true, []string{"--source=/source/config.json", "--materialize-retained", "--successor-signing-selector=selected", "--successor-scratch=/source/scratch"}},
		{"other-command-selector", false, false, []string{"plan", "--successor-signing-selector=selected"}},
		{"materialize-local", true, false, []string{"--source", "/source/config.json", "--source-format", "json", "--materialize-retained"}},
		{"credential-preparation", true, false, []string{"--source", "/source/config.json", "--source-format", "json", "--prepare-output-credential"}},
		{"set-local", false, false, []string{"set", "--source", "/source/config.json", "--source-format", "json", "--name", "secret"}},
		{"reader", false, false, []string{"plan", "--trusted", "/source/config.json", "--trusted-format", "json"}},
		{"inspection", false, false, []string{"inspect", "--source", "/source/config.json", "--source-format", "json"}},
		{"recipient-inspection", false, false, []string{"inspect", "--source", "/source/config.json", "--source-format", "json", "--recipient", "selected"}},
		{"receipt-list", false, false, []string{"receipt", "--source", "/source/config.json", "--source-format", "json"}},
		{"receipt-detail", false, false, []string{"receipt", "--source", "/source/config.json", "--source-format", "json", "--operation", "selected"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			objects, objectBytes := publicCommandMutationAllowance(row.consumer, row.args)
			if row.mutating && (objects != 16 || objectBytes != 8<<20) || !row.mutating && (objects != 0 || objectBytes != 0) {
				t.Fatal("actual public command mutation bypassed or acquired object allowance")
			}
		})
	}
}

// full_only: false
func TestPublicFreshPairSourceAdmitsPortableWriterFacts(t *testing.T) {
	for _, row := range []struct {
		name, basename string
		want           bool
	}{
		{"ordinary", "configuration.json", true},
		{"replacement", "successor.json", true},
		{"administrative", "authority-successor.json", true},
		{"other-basename", "source.json", true},
		{"empty", "configuration.json", false},
		{"relative", "configuration.json", false},
		{"dot-segment", "configuration.json", false},
		{"parent-traversal", "configuration.json", false},
		{"nested", "configuration.json", false},
		{"sibling", "configuration.json", false},
		{"prefix-confusable", "configuration.json", false},
		{"missing", "configuration.json", false},
		{"directory", "configuration.json", false},
		{"leaf-symlink", "configuration.json", false},
		{"pair-symlink", "configuration.json", false},
		{"ancestor-symlink", "configuration.json", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal("canonical temporary owner unavailable")
			}
			originalDir, state := filepath.Join(root, "original"), filepath.Join(root, "state")
			generated := []byte("{\"fixture\":true}\n")
			editable := []byte("{\"generated\":\".enkv/fixture.json\",\"entries\":{}}\n")
			original := filepath.Join(originalDir, row.basename)
			if os.MkdirAll(filepath.Join(originalDir, ".enkv"), 0700) != nil ||
				os.WriteFile(filepath.Join(originalDir, ".enkv", "fixture.json"), generated, 0400) != nil ||
				os.WriteFile(original, editable, 0400) != nil {
				t.Fatal("portable writer fixture unavailable")
			}
			originalImage := publicSourceImage(t, original)
			copied := publicPortablePair(t, original, filepath.Join(state, "fresh-pair"))
			if copied != filepath.Join(state, "fresh-pair", row.basename) {
				t.Fatal("portable copy changed the editable basename")
			}
			for path, want := range map[string][]byte{copied: editable, filepath.Join(state, "fresh-pair", ".enkv", "fixture.json"): generated} {
				body, err := os.ReadFile(path)
				info, statErr := os.Lstat(path)
				if err != nil || statErr != nil || !bytes.Equal(body, want) || !info.Mode().IsRegular() || info.Mode().Perm() != 0400 {
					t.Fatal("portable copy changed exact bytes or read-only file ownership")
				}
			}
			copiedImage := publicSourceImage(t, copied)
			owner, source := state, copied
			switch row.name {
			case "empty":
				source = ""
			case "relative":
				source = filepath.Join("fresh-pair", row.basename)
			case "dot-segment":
				source = filepath.Join(state, "fresh-pair") + "/./" + row.basename
			case "parent-traversal":
				source = filepath.Join(state, "fresh-pair") + "/../fresh-pair/" + row.basename
			case "nested":
				source = publicPortablePair(t, original, filepath.Join(state, "fresh-pair", "nested"))
			case "sibling":
				source = publicPortablePair(t, original, filepath.Join(state, "sibling"))
			case "prefix-confusable":
				source = publicPortablePair(t, original, filepath.Join(state, "fresh-pair-other"))
			case "missing":
				if os.Remove(copied) != nil {
					t.Fatal("missing file damage unavailable")
				}
			case "directory":
				if os.Remove(copied) != nil || os.Mkdir(copied, 0700) != nil {
					t.Fatal("directory leaf damage unavailable")
				}
			case "leaf-symlink":
				if os.Rename(copied, filepath.Join(state, "fresh-pair", "saved.json")) != nil || os.Symlink("saved.json", copied) != nil {
					t.Fatal("leaf symlink damage unavailable")
				}
			case "pair-symlink":
				if os.Rename(filepath.Join(state, "fresh-pair"), filepath.Join(state, "saved-pair")) != nil ||
					os.Symlink("saved-pair", filepath.Join(state, "fresh-pair")) != nil {
					t.Fatal("pair directory symlink damage unavailable")
				}
			case "ancestor-symlink":
				alias := filepath.Join(root, "alias")
				if os.Symlink(root, alias) != nil {
					t.Fatal("ancestor symlink damage unavailable")
				}
				owner = filepath.Join(alias, "state")
				source = filepath.Join(owner, "fresh-pair", row.basename)
			}
			facts := publicProcessFacts{RunID: liveProtocolRun, Prefix: "local-portable-writer", Source: source, ExpectReady: true}
			factsPath := filepath.Join(state, "after.json")
			if writeNewLiveJSON(factsPath, facts) != nil {
				t.Fatal("portable writer facts unavailable")
			}
			path, err := records.SafePath(state, "after.json")
			var stored publicProcessFacts
			if err != nil || records.ReadJSON(path, &stored) != nil || stored.RunID != facts.RunID || stored.Prefix != facts.Prefix || stored.Source != facts.Source {
				t.Fatal("portable writer facts did not round trip exactly")
			}
			got := publicFreshPairSourceValid(owner, stored.Source)
			publicImageUnchanged(t, originalImage)
			if row.want {
				publicImageUnchanged(t, copiedImage)
			}
			if got != row.want {
				t.Fatalf("stored portable source admission differs: admitted=%t expected=%t", got, row.want)
			}
		})
	}
}

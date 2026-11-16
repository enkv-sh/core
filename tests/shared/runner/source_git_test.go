package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestHistoricalSourceRequiresBothVersionedRepositoryProjections(t *testing.T) {
	source := records.Source{Algorithm: rawSourceAlgorithm, Revision: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40), PublicRepository: "enkv-extensions", PublicRevision: strings.Repeat("c", 40), PublicTree: strings.Repeat("d", 40), PublicPaths: []string{"sdk/output"}}
	if !rawSourceValid(source) || !sameRawSource(source, source) {
		t.Fatal("supported historical source record refused")
	}
	for _, damage := range []func(*records.Source){
		func(s *records.Source) { s.Algorithm = "" },
		func(s *records.Source) { s.Algorithm = "enkv-raw-git-tree-v2" },
		func(s *records.Source) { s.Tree = "" },
		func(s *records.Source) { s.Dirty = true },
		func(s *records.Source) { s.Revision = "invalid" },
		func(s *records.Source) { s.PublicRevision = "" },
		func(s *records.Source) { s.PublicTree = "" },
		func(s *records.Source) { s.PublicRepository = "" },
		func(s *records.Source) { s.PublicPaths = nil },
		func(s *records.Source) { s.PublicPaths = []string{"../outside"} },
		func(s *records.Source) { s.PublicPaths = []string{".."} },
		func(s *records.Source) { s.PublicPaths = []string{"sdk/z", "sdk/a"} },
		func(s *records.Source) { s.PublicPaths = []string{"sdk/a", "sdk/a"} },
		func(s *records.Source) { s.PublicSourcesSHA256 = strings.Repeat("a", 64) },
		func(s *records.Source) { v := strings.Repeat("a", 64); s.DirtyDiffSHA256 = &v },
	} {
		damaged := source
		damage(&damaged)
		if rawSourceValid(damaged) || sameRawSource(source, damaged) || sameRawSource(damaged, damaged) {
			t.Fatalf("incomplete or mixed algorithm source admitted: %+v", damaged)
		}
	}
}

func rawSourceFixture(t *testing.T) (string, string) {
	t.Helper()
	parent := t.TempDir()
	root := filepath.Join(parent, "enkv-core")
	public := filepath.Join(parent, "enkv-extensions")
	for _, repository := range []string{root, public} {
		if err := os.MkdirAll(repository, 0700); err != nil {
			t.Fatal(err)
		}
		rawSourceGit(t, repository, "init", "--quiet", "--object-format=sha1")
	}
	for _, source := range moduleSources {
		if source.Sibling != "" {
			rawSourceWrite(t, public, source.Directory+"/fixture.txt", "original\n")
		}
	}
	rawSourceWrite(t, public, moduleInventoryPath, "fixture inventory\n")
	rawSourceWrite(t, public, "go.work", "fixture workspace\n")
	rawSourceCommit(t, root)
	rawSourceCommit(t, public)
	return root, public
}

func rawSourceWrite(t *testing.T, root, name, body string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

func rawSourceGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = root
	body, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("raw source fixture: %v\n%s", err, body)
	}
	return string(body)
}

func rawSourceCommit(t *testing.T, root string) {
	t.Helper()
	rawSourceGit(t, root, "add", "--all")
	rawSourceGit(t, root, "-c", "user.name=Local Test", "-c", "user.email=local@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "--allow-empty", "-m", "Raw source fixture")
}

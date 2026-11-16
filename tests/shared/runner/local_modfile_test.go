package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// full_only: false
func TestLocalModfilesRejectPermanentFirstPartyReplacements(t *testing.T) {
	for _, replacement := range []string{
		"replace enkv.sh/crypto => ../other\n",
		"replace (\n enkv.sh/crypto => ../crypto\n)\n",
		"replace \"enkv.sh/crypto\" v0.0.0 => ../foreign\n",
		"replace ( // mapped module\n enkv.sh/crypto v0.0.0 => ../foreign\n)\n",
	} {
		root := sourceFixtureRoot(t)
		writeLocalGoFixture(t, root, "core/go.mod", "module enkv.sh/core\n\ngo 1.27.0\n\nrequire enkv.sh/crypto v0.0.0\n"+replacement)
		owner, err := sourcePath(root, "core")
		if err != nil {
			t.Fatal(err)
		}
		_, directory, _, err := localModuleArguments(t.Context(), root, owner, []string{"list", "-m", "all"})
		if err == nil || directory != "" || !strings.Contains(err.Error(), "first-party replacement") {
			t.Fatal("source replacement was hidden", err, directory)
		}
	}
}

// full_only: false
func TestLocalModfilesKeepMissingDependenciesAtRegisteredOwners(t *testing.T) {
	root := sourceFixtureRoot(t)
	writeLocalGoFixture(t, root, "core/go.mod", "module enkv.sh/core\n\ngo 1.27.0\n\nrequire enkv.sh/sdk/protocols/output v0.0.0\n")
	owner, err := sourcePath(root, "core")
	if err != nil {
		t.Fatal(err)
	}
	args, directory, preparation, err := localModuleArguments(t.Context(), root, owner, []string{"list", "-m", "all"})
	if err != nil {
		t.Fatal(err)
	}
	if preparation == nil || !preparation.passed() || preparation.WallSeconds == nil {
		t.Fatal("module parser process was not recorded", preparation)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	var filename string
	for _, arg := range args {
		if value, ok := strings.CutPrefix(arg, "-modfile="); ok {
			filename = value
		}
	}
	body, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "replace enkv.sh/sdk/protocols/output => ../../enkv-extensions/sdk/protocols/output\n") {
		t.Fatal("missing dependency can escape its registered owner", string(body))
	}
	ctx, cancel := context.WithTimeout(cacheOnlyGoContext(t.Context()), time.Minute)
	defer cancel()
	if _, err := runGo(ctx, root, "core", "list", "-mod=readonly", "-m", "all"); err == nil || !strings.Contains(err.Error(), "enkv-extensions/sdk/protocols/output/go.mod") {
		t.Fatal("missing local dependency did not refuse at its owner", err)
	}
}

// full_only: false
func TestLocalModfilesAllowStandaloneFilesAndRequireKnownModuleFiles(t *testing.T) {
	root := sourceFixtureRoot(t)
	main := writeLocalGoFixture(t, root, "main.go", "package main\nfunc main() {}\n")
	ctx, cancel := context.WithTimeout(cacheOnlyGoContext(t.Context()), time.Minute)
	defer cancel()
	if _, err := runGo(ctx, root, "", "build", "-o", filepath.Join(t.TempDir(), "standalone"), main); err != nil {
		t.Fatal("standalone Go file requires a root module", err)
	}
	known := writeLocalGoFixture(t, root, "core/main.go", "package main\nfunc main() {}\n")
	if _, err := runGo(ctx, root, "core", "build", "-o", filepath.Join(t.TempDir(), "known"), known); err == nil || !strings.Contains(err.Error(), "local module input unavailable") {
		t.Fatal("missing known module was treated as standalone", err)
	}
}

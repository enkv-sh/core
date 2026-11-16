package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestCompilerInputPathsUseGoWorkingDirectory(t *testing.T) {
	for _, row := range []struct {
		name, directory, module                       string
		relativeMod, relativeOverlay, relativeEntries bool
	}{
		{"relative-modfile", "core", componentPackage, true, false, false},
		{"relative-overlay-file", "core", componentPackage, false, true, false},
		{"relative-overlay-entries", "core", componentPackage, false, false, true},
		{"absolute-controls", "core", componentPackage, false, false, false},
		{"registered-sibling", "sdk/output", outputSDKPath, true, true, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			root, _, _ := overlayFixture(t)
			packageName := "core"
			if row.directory == "sdk/output" {
				packageName = "output"
			}
			moduleBody := "module " + row.module + "\n\ngo 1.27.0\n"
			writeLocalGoFixture(t, root, row.directory+"/go.mod", moduleBody)
			// The original target is deliberately unsuitable for Core custody.
			// Only the selected backing file may supply compiler/type inputs.
			target := writeLocalGoFixture(t, root, row.directory+"/subject.go", "package "+packageName+"\nimport \"crypto\"\nvar Input crypto.PrivateKey\n")
			backing := writeLocalGoFixture(t, root, row.directory+"/testdata/backing.go", "package "+packageName+"\nvar Input = 1\n")
			working, err := sourcePath(root, row.directory)
			if err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(root, "compiler-input-config")
			if err := os.Mkdir(config, 0700); err != nil {
				t.Fatal(err)
			}
			modfile := filepath.Join(config, "selected.mod")
			if err := os.WriteFile(modfile, []byte(moduleBody), 0600); err != nil {
				t.Fatal(err)
			}
			from, to := target, backing
			if row.relativeEntries {
				from, err = filepath.Rel(working, target)
				if err != nil {
					t.Fatal(err)
				}
				to, err = filepath.Rel(working, backing)
				if err != nil {
					t.Fatal(err)
				}
			}
			overlay := filepath.Join(config, "selected.json")
			if err := records.WriteJSON(overlay, struct{ Replace map[string]string }{map[string]string{from: to}}, 0600); err != nil {
				t.Fatal(err)
			}
			modArgument, overlayArgument := modfile, overlay
			if row.relativeMod {
				modArgument, err = filepath.Rel(working, modfile)
				if err != nil {
					t.Fatal(err)
				}
			}
			if row.relativeOverlay {
				overlayArgument, err = filepath.Rel(working, overlay)
				if err != nil {
					t.Fatal(err)
				}
			}
			flags := []string{"-mod=readonly", "-modfile=" + modArgument, "-overlay=" + overlayArgument}
			ctx := withResourceLocks(withExecutionParallel(t.Context(), 1), resourceLockFixture(t))
			for range 2 {
				t.Chdir(t.TempDir())
				modules, packages, err := listClosure(runGoEnvironment, ctx, root, row.directory, flags, true, ".")
				if err != nil {
					t.Fatal("actual Go inputs were resolved outside the command working directory", err)
				}
				if err := checkModuleSource(root, modules, row.directory); err != nil {
					t.Fatal("compiler input left its registered module owner", err)
				}
				found := false
				for _, pkg := range packages {
					if pkg.ImportPath != row.module {
						continue
					}
					found = true
					selected := false
					for _, names := range compilerSourceFiles(pkg) {
						for _, name := range names {
							if !filepath.IsAbs(name) {
								name = filepath.Join(pkg.Dir, name)
							}
							if name == target {
								t.Fatal("compiler source names the replaced physical target")
							}
							selected = selected || name == backing
						}
					}
					if !selected {
						t.Fatal("compiler source omitted the selected overlay backing")
					}
				}
				if !found {
					t.Fatal("selected module package is absent")
				}
				if row.directory == "core" {
					if err := checkCompiledCustody(packages); err != nil {
						t.Fatal("custody read the physical target instead of the selected overlay backing", err)
					}
				}
			}
			if row.directory == "core" {
				if err := os.WriteFile(target, []byte("package core\nvar Input = 1\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(backing, []byte("package core\nimport \"crypto\"\nvar Input crypto.PrivateKey\n"), 0600); err != nil {
					t.Fatal(err)
				}
				_, packages, err := listClosure(runGoEnvironment, ctx, root, row.directory, flags, true, ".")
				if err != nil {
					t.Fatal("forbidden overlay source did not produce actual compiler metadata", err)
				}
				err = checkCompiledCustody(packages)
				if err == nil || !strings.Contains(err.Error(), "Core private-key custody refused at ") || !strings.Contains(err.Error(), "crypto.PrivateKey") || !toolCommandsJoined(err) || !sourceCommandsJoined(err) {
					t.Fatal("custody did not refuse the forbidden selected overlay source", err)
				}
			}
		})
	}
}

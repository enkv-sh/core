package main

import (
	"context"
	"os"
	"testing"
	"time"
)

// full_only: false
func TestModuleChecksAcceptPluginFreeHosts(t *testing.T) {
	root := maintainedCloudflareRoot(t)
	for _, owner := range []string{"compositions/generatorhost", "compositions/configuration", "compositions/manifesthost", "compositions/internal/nativeprocess"} {
		t.Run(owner, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			checked, err := checkModule(ctx, root, owner)
			if err != nil {
				t.Fatal("plugin-free host module refused", err)
			}
			if checked.closure.Provider != owner || len(checked.closure.CompiledImports) == 0 {
				t.Fatal("checked host closure absent")
			}
			for _, imported := range checked.closure.CompiledImports {
				if withinModule(imported, "enkv.sh/plugins") {
					t.Fatal("generic host compiled a concrete plugin", imported)
				}
			}
		})
	}
}

// full_only: false
func TestLintAssemblyBindsNestedModuleScope(t *testing.T) {
	root, _ := lintFixture(t, t.TempDir())
	writeLocalGoFixture(t, root, "telemetry/subdir/fixture.go", "package subdir\n")
	copyRoot, sources, err := buildLintAssembly(t.Context(), root, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeLocalGoFixture(t, root, "telemetry/subdir/go.mod", "module example.invalid/nested\n\ngo 1.27.0\n")
	if err := verifyLintAssembly(t.Context(), root, copyRoot, sources); err == nil {
		t.Fatal("nested module removed a checked package without changing its Go bytes")
	}
}

// full_only: false
func TestLintAssemblyBindsCompilerSelectedGoSource(t *testing.T) {
	root, _ := lintFixture(t, t.TempDir())
	const name = "telemetry/node_modules/fixture/fixture.go"
	const original = "package fixture\n\nconst Value = 1\n"
	path := writeLocalGoFixture(t, root, name, original)
	copyRoot, sources, err := buildLintAssembly(t.Context(), root, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	copied, err := lintSourceBytes(copyRoot, name)
	if err != nil || string(copied) != original {
		t.Errorf("compiler-selected Go source was not copied: %v", err)
	}
	if err := os.WriteFile(path, []byte(original+"\n// changed compiler input\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyLintAssembly(t.Context(), root, copyRoot, sources); err == nil {
		t.Error("changed compiler-selected Go bytes were not checked")
	}
}

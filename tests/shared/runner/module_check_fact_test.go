package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func moduleFactFixture(t *testing.T, root string) *moduleCheckFacts {
	t.Helper()
	_, sources, err := buildLintAssembly(t.Context(), root, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	environment, err := moduleCheckEnvironment(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	return &moduleCheckFacts{root: root, race: raceEnabled(t.Context()), sources: sources, environment: environment, modules: map[string]assemblyClosure{}}
}

// full_only: false
func TestModuleCheckFactRequiresCompatibleOwnerAndEnvironment(t *testing.T) {
	root, _ := lintFixture(t, t.TempDir())
	facts := moduleFactFixture(t, root)
	check := func(t *testing.T, ctx context.Context, fact *moduleCheckFacts, want bool) {
		t.Helper()
		got, err := fact.current(ctx, root)
		if err != nil || got != want {
			t.Fatalf("compatible owner and environment=%t, error=%v; want %t", got, err, want)
		}
	}
	check(t, t.Context(), nil, false)
	check(t, t.Context(), facts, true)
	check(t, withRacePolicy(t.Context(), !facts.race), facts, false)
	t.Run("different-checkout-owner", func(t *testing.T) {
		other := *facts
		other.root = t.TempDir()
		check(t, t.Context(), &other, false)
	})
	t.Run("effective-flags", func(t *testing.T) {
		t.Setenv("GOFLAGS", "-must-not-reach-go")
		check(t, t.Context(), facts, true)
	})
	t.Run("module-policy", func(t *testing.T) {
		t.Setenv("GONOSUMDB", "example.invalid/changed-policy")
		check(t, t.Context(), facts, false)
	})
	t.Run("working-source", func(t *testing.T) {
		path, err := sourcePath(root, "protocols/generator/fixture.go")
		if err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(body, []byte("\n// changed\n")...), 0600); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Error(err)
			}
		}()
		check(t, t.Context(), facts, true)
	})
	t.Run("new-source-member", func(t *testing.T) {
		path := writeLocalGoFixture(t, root, "telemetry/extra.go", "package fixture\n")
		defer func() {
			if err := os.Remove(path); err != nil {
				t.Error(err)
			}
		}()
		check(t, t.Context(), facts, true)
	})
	check(t, t.Context(), facts, true)
}

// full_only: false
func TestModuleCheckEnvironmentBindsSelectedGoExecutable(t *testing.T) {
	root := testRepositoryRoot(t)
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	path := filepath.Join(bin, "go")
	body := "#!/bin/sh\nexec '" + strings.ReplaceAll(realGo, "'", "'\"'\"'") + "' \"$@\"\n"
	if err := os.WriteFile(path, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	before, err := moduleCheckEnvironment(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body+"# changed executable bytes\n"), 0700); err != nil {
		t.Fatal(err)
	}
	after, err := moduleCheckEnvironment(t.Context(), root)
	if err != nil || before == after {
		t.Fatalf("changed selected executable did not change identity: %v", err)
	}
}

// full_only: false
func TestBorrowedModuleCheckKeepsCacheVerificationAcrossSourceEdits(t *testing.T) {
	for _, condition := range []string{"cache-refusal", "source-change"} {
		t.Run(condition, func(t *testing.T) {
			root, _ := lintFixture(t, t.TempDir())
			initializeWorkflowExecutionFixture(t, root)
			ctx := withResourceLocks(t.Context(), resourceLockFixture(t))
			checked, err := checkModule(ctx, root, moduleRoots[0])
			if err != nil || !checked.borrowable {
				t.Fatal("controlled registered module was not checked", err)
			}
			realGo, err := exec.LookPath("go")
			if err != nil {
				t.Fatal(err)
			}
			bin := t.TempDir()
			source, err := sourcePath(root, "telemetry/fixture.go")
			if err != nil {
				t.Fatal(err)
			}
			script := `#!/bin/sh
if [ "$1" = mod ] && [ "$2" = verify ]; then
 if [ "$ENKV_FACT_VERIFY" = cache-refusal ]; then
  printf '%s\n' 'controlled cache integrity refusal' >&2
  exit 7
 fi
 if [ ! -f "$ENKV_FACT_MARKER" ]; then
  printf '\n// changed during mod verify\n' >> "$ENKV_FACT_SOURCE"
  : > "$ENKV_FACT_MARKER"
 fi
fi
exec '` + strings.ReplaceAll(realGo, "'", "'\"'\"'") + `' "$@"
`
			if err := os.WriteFile(filepath.Join(bin, "go"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("ENKV_FACT_VERIFY", condition)
			t.Setenv("ENKV_FACT_SOURCE", source)
			t.Setenv("ENKV_FACT_MARKER", filepath.Join(bin, "mutated"))
			facts := moduleFactFixture(t, root)
			facts.modules[moduleRoots[0]] = copyModuleCheckClosure(checked.closure)
			observedSources := lintSourcesDigest(facts.sources)
			var output stopCommonArtifactOutput
			record, err := runOfflineResponsibilityPrepared(nil, ctx, root, "", "dev", "common", "", &output, nil, facts)
			if err == nil || !toolCommandsJoined(err) || record == nil || record.Outcome != "failed" {
				t.Fatalf("borrowed module check lost failed current outcome or process joins: record=%v error=%v", record, err)
			}
			if condition == "source-change" {
				body, readErr := os.ReadFile(source)
				if readErr != nil || !strings.Contains(string(body), "// changed during mod verify") {
					t.Fatal("fixture did not change source during cache verification", readErr)
				}
				if !output.reached || !errors.Is(err, commonArtifactStop) || len(record.Modules) != len(moduleRoots) || !reflect.DeepEqual(record.Modules[moduleRoots[0]], facts.modules[moduleRoots[0]]) || lintSourcesDigest(facts.sources) != observedSources {
					t.Fatalf("source edit invalidated or rewrote completed module facts: record=%v reached artifact=%t error=%v\n%s", record, output.reached, err, output.String())
				}
				return
			}
			if !strings.Contains(err.Error(), "controlled cache integrity refusal") || output.reached {
				t.Fatalf("borrowed check lost %s refusal: outcome=%v, reached artifact=%t, error=%v\n%s", condition, record, output.reached, err, output.String())
			}
		})
	}
}

// full_only: false
func TestModuleCheckDoesNotLendExternalLocalReplacement(t *testing.T) {
	root, _ := lintFixture(t, t.TempDir())
	external, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeLocalGoFixture(t, external, "go.mod", "module example.invalid/module-input\n\ngo 1.27.0\n")
	writeLocalGoFixture(t, external, "input.go", "package input\n")
	writeLocalGoFixture(t, root, "providers/aws/local_input.go", "package fixture\n\nimport _ \"example.invalid/module-input\"\n")
	for _, name := range []string{"providers/aws/go.mod", "providers/aws/telemetry_test.mod"} {
		path, err := sourcePath(root, name)
		if err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		body = append(body, []byte(fmt.Sprintf("\nrequire example.invalid/module-input v0.0.0\nreplace example.invalid/module-input => %q\n", external))...)
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx := withResourceLocks(t.Context(), resourceLockFixture(t))
	checked, err := checkModule(ctx, root, "providers/aws")
	if err != nil {
		t.Fatal("standalone local replacement should remain supported", err)
	}
	if checked.borrowable {
		t.Fatal("unrepresented external local replacement became a reusable fact")
	}
}

// full_only: false
func TestModuleCheckInputErrorsRemainFailures(t *testing.T) {
	root, _ := lintFixture(t, t.TempDir())
	facts := moduleFactFixture(t, root)
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, condition := range []string{"environment-query", "missing-executable", "missing-toolchain-observation"} {
		t.Run(condition, func(t *testing.T) {
			bin := t.TempDir()
			if condition == "environment-query" {
				script := "#!/bin/sh\nif [ \"$1\" = env ]; then printf '%s\n' 'controlled environment query refusal' >&2; exit 7; fi\nexec '" + strings.ReplaceAll(realGo, "'", "'\"'\"'") + "' \"$@\"\n"
				if err := os.WriteFile(filepath.Join(bin, "go"), []byte(script), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if condition == "missing-toolchain-observation" {
				script := "#!/bin/sh\nif [ \"$1\" = env ]; then printf '%s\n' '{\"GOROOT\":\"/controlled\",\"GOOS\":\"darwin\",\"GOARCH\":\"arm64\"}'; exit 0; fi\nexec '" + strings.ReplaceAll(realGo, "'", "'\"'\"'") + "' \"$@\"\n"
				if err := os.WriteFile(filepath.Join(bin, "go"), []byte(script), 0700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", bin)
			current, err := facts.current(t.Context(), root)
			if err == nil || current {
				t.Fatalf("%s became a silent mismatch/pass: current=%t, err=%v", condition, current, err)
			}
			if condition == "environment-query" && (!strings.Contains(err.Error(), "controlled environment query refusal") || !toolCommandsJoined(err)) {
				t.Fatal("environment-query cause/join lost", err)
			}
			if condition == "missing-toolchain-observation" && !strings.Contains(err.Error(), "module check toolchain identity unavailable") {
				t.Fatal("missing command observation acquired an identity", err)
			}
		})
	}
}

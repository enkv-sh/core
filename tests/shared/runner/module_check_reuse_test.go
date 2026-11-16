package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type stopCommonArtifactOutput struct {
	bytes.Buffer
	reached bool
}

var commonArtifactStop = errors.New("controlled stop before common artifact build")

func (out *stopCommonArtifactOutput) Write(body []byte) (int, error) {
	if strings.Contains(string(body), "Checking offline Cloudflare plugin artifact") {
		out.reached = true
		return 0, commonArtifactStop
	}
	return out.Buffer.Write(body)
}

// full_only: false
func TestLintCommonUsesOneEquivalentModuleCheck(t *testing.T) {
	root, bootstrap := lintFixture(t, t.TempDir())
	initializeWorkflowExecutionFixture(t, root)
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	realGo, err = filepath.EvalSymlinks(realGo)
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	commands := filepath.Join(bin, "go-commands")
	observer := "#!/bin/sh\nprintf '%s|%s|%s\n' \"$PWD\" \"$1\" \"$2\" >> \"$ENKV_MODULE_COMMANDS\"\nexec '" + strings.ReplaceAll(realGo, "'", "'\"'\"'") + "' \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "go"), []byte(observer), 0700); err != nil {
		t.Fatal(err)
	}
	lint := "#!/bin/sh\ncase \"$1\" in\nversion) printf '%s\n' '{\"version\":\"2.14.0\"}' ;;\nrun) exit 0 ;;\n*) exit 9 ;;\nesac\n"
	if err := os.WriteFile(filepath.Join(bin, "golangci-lint"), []byte(lint), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ENKV_MODULE_COMMANDS", commands)
	workflow := writeLocalGoFixture(t, root, "module-check-workflow.json", `{"schema_version":1,"execution":{"parallel":1},"name":"module-check","profile":"dev","steps":[{"id":"lint","kind":"lint"},{"id":"common","kind":"assembly-checks","responsibility":"common"}]}`)
	var output stopCommonArtifactOutput
	err = runCommand(t.Context(), root, bootstrap, []string{"run", "--workflow=" + workflow, "--parallel=1"}, &output)
	if !output.reached || err == nil || !strings.Contains(output.String(), commonArtifactStop.Error()) {
		t.Fatalf("did not finish lint and common module checks: %v\n%s", err, output.String())
	}
	body, err := os.ReadFile(commands)
	if err != nil {
		t.Fatal(err)
	}
	telemetry, err := sourcePath(root, "telemetry")
	if err != nil {
		t.Fatal(err)
	}
	vets, verifies := 0, 0
	for _, line := range strings.Split(string(body), "\n") {
		directory, operation, _ := strings.Cut(line, "|")
		if directory != telemetry {
			continue
		}
		command, subcommand, _ := strings.Cut(operation, "|")
		if command == "vet" {
			vets++
		}
		if command == "mod" && subcommand == "verify" {
			verifies++
		}
	}
	if vets != 1 || verifies != 2 {
		t.Fatalf("equivalent telemetry module work: vet=%d, mod verify=%d; want 1 and 2", vets, verifies)
	}
}

// full_only: false
func TestLintAssemblyBindsModuleCheckDirectAndNativeInputs(t *testing.T) {
	root, _ := lintFixture(t, t.TempDir())
	writeLocalGoFixture(t, root, "telemetry/native.s", "// Native compiler input.\n")
	writeLocalGoFixture(t, root, "plugins/cloudflare/internal/cloudflare/tagged.s", "//go:build enkv_cloudflare_testartifact\n\n// Tagged compiler input.\n")
	copyRoot, sources, err := buildLintAssembly(t.Context(), root, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"telemetry/native.s", "plugins/cloudflare/internal/cloudflare/tagged.s", "plugins/cloudflare/LICENSE", "protocols/generator/LICENSE", "sdk/generator/LICENSE"} {
		t.Run(name, func(t *testing.T) {
			body, err := lintSourceBytes(root, name)
			if err != nil {
				t.Fatal(err)
			}
			copied, err := lintSourceBytes(copyRoot, name)
			if err != nil || !bytes.Equal(copied, body) {
				t.Errorf("module-check input was not copied: %v", err)
			}
			path, err := sourcePath(root, name)
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
			if err := verifyLintAssembly(t.Context(), root, copyRoot, sources); err == nil {
				t.Error("changed module-check input accepted")
			}
		})
	}
}

// full_only: false
func TestModuleCheckEnvironmentBindsModuleResolution(t *testing.T) {
	root := testRepositoryRoot(t)
	for _, row := range []struct{ key, first, second string }{
		{"GOPROXY", "https://first.invalid", "https://second.invalid"},
		{"GOSUMDB", "off", "sum.golang.org"},
		{"GONOSUMDB", "first.invalid/private", "second.invalid/private"},
		{"GOPRIVATE", "first.invalid/private", "second.invalid/private"},
		{"GONOPROXY", "first.invalid/private", "second.invalid/private"},
		{"GOMODCACHE", filepath.Join(t.TempDir(), "first-cache"), filepath.Join(t.TempDir(), "second-cache")},
	} {
		t.Run(row.key, func(t *testing.T) {
			t.Setenv(row.key, row.first)
			before, err := moduleCheckEnvironment(t.Context(), root)
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv(row.key, row.second)
			after, err := moduleCheckEnvironment(t.Context(), root)
			if err != nil {
				t.Fatal(err)
			}
			if before == after {
				t.Errorf("changed effective %s did not change module-check identity", row.key)
			}
		})
	}
}

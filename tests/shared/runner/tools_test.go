package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestEveryOverlayGoCommandOwnsRequiredDirectories(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	core := filepath.Join(root, "core")
	if os.Mkdir(core, 0700) != nil {
		t.Fatal("Core fixture")
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(core, "go.mod"), "module example.test/core\n\ngo 1.23.0\n")
	write(filepath.Join(core, "core.go"), "package core\nimport _ \"example.test/core/internal/testcatalog\"\n")
	source := filepath.Join(root, "catalog.go")
	write(source, "package testcatalog\n")
	overlay := filepath.Join(root, "overlay.json")
	body, err := json.Marshal(struct{ Replace map[string]string }{map[string]string{filepath.Join(core, "internal/testcatalog/catalog.go"): source}})
	if err != nil {
		t.Fatal(err)
	}
	write(overlay, string(body))
	for _, form := range []string{"equals", "separate"} {
		t.Run(form, func(t *testing.T) {
			flags := []string{"-overlay=" + overlay}
			if form == "separate" {
				flags = []string{"-overlay", overlay}
			}
			write(source, "package testcatalog\n")
			for _, command := range []string{"vet", "test"} {
				args := append([]string{command, "-mod=readonly"}, flags...)
				if _, err := runGo(context.Background(), root, "core", append(args, "./...")...); err != nil {
					t.Fatalf("%s: %v", command, err)
				}
				if _, err := os.Lstat(filepath.Join(core, "internal")); !os.IsNotExist(err) {
					t.Fatal("successful overlay command retained temporary directories")
				}
			}
			write(source, "package testcatalog\nimport \"fmt\"\nfunc bad(){fmt.Printf(\"%d\",\"wrong\")}\n")
			args := append([]string{"vet", "-mod=readonly"}, flags...)
			if _, err := runGo(context.Background(), root, "core", append(args, "./...")...); err == nil {
				t.Fatal("real vet failure was swallowed")
			}
			if _, err := os.Lstat(filepath.Join(core, "internal")); !os.IsNotExist(err) {
				t.Fatal("failed overlay command retained temporary directories")
			}
		})
	}
}

// full_only: false
func TestGenericOverlayCommandsDoNotRequireToolDirectories(t *testing.T) {
	for _, form := range []string{"equals", "separate"} {
		t.Run(form, func(t *testing.T) {
			root := sourceFixtureRoot(t)
			writeLocalGoFixture(t, root, "go.mod", "module example.test/standalone\n\ngo 1.27.0\n")
			writeLocalGoFixture(t, root, "package/value.go", "package sample\nconst Value = 1\n")
			writeLocalGoFixture(t, root, "testdata/value.go", "package sample\nconst Value = 7\n")
			writeLocalGoFixture(t, root, "package/value_test.go", "package sample\nimport \"testing\"\n// full_only: false\nfunc TestValue(t *testing.T){if Value != 7 {t.Fatal(\"overlay source was not compiled\")}}\n")
			if err := records.WriteJSON(filepath.Join(root, "overlay.json"), struct{ Replace map[string]string }{map[string]string{"package/value.go": "testdata/value.go"}}, 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"test", "-mod=readonly", "-overlay=overlay.json"}
			if form == "separate" {
				args = []string{"test", "-mod=readonly", "-overlay", "overlay.json"}
			}
			args = append(args, "-count=1", "-v", "-run=^TestValue$", "./package")
			body, facts, err := runGoRecorded(withExecutionParallel(t.Context(), 1), root, ".", args...)
			if err != nil || facts.Process != "passed" || !facts.Started || !facts.Joined || !strings.Contains(string(body), "--- PASS: TestValue") {
				t.Fatal("standalone overlay lost its actual selected execution", err, facts, string(body))
			}
			if _, err := os.Lstat(filepath.Join(root, "core")); !os.IsNotExist(err) {
				t.Fatal("generic overlay created ENKV tool directories", err)
			}
		})
	}
}

// full_only: false
func TestOverlayCommandsRejectUnavailableDefinitions(t *testing.T) {
	root := sourceFixtureRoot(t)
	writeLocalGoFixture(t, root, "go.mod", "module example.test/standalone\n\ngo 1.27.0\n")
	writeLocalGoFixture(t, root, "subject.go", "package sample\n")
	if err := os.WriteFile(filepath.Join(root, "invalid.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, form := range []string{"equals", "separate"} {
		for _, path := range []string{"invalid.json", "missing.json"} {
			t.Run(form+"/"+path, func(t *testing.T) {
				args := []string{"test", "-overlay=" + path}
				if form == "separate" {
					args = []string{"test", "-overlay", path}
				}
				_, facts, err := runGoRecorded(t.Context(), root, ".", append(args, ".")...)
				if err == nil || !strings.Contains(err.Error(), "compiled custody overlay unavailable") || facts.Started || facts.ModulePreparation != nil {
					t.Fatal("unavailable overlay reached a Go process", err, facts)
				}
			})
		}
	}
	t.Run("missing-argument", func(t *testing.T) {
		_, facts, err := runGoRecorded(t.Context(), root, ".", "test", "-overlay")
		if err == nil || !strings.Contains(err.Error(), "compiled custody overlay unavailable") || facts.Started || facts.ModulePreparation != nil {
			t.Fatal("missing overlay argument reached a Go process", err, facts)
		}
	})
	if _, err := os.Lstat(filepath.Join(root, "core")); !os.IsNotExist(err) {
		t.Fatal("refused overlay created ENKV tool directories", err)
	}
}

// full_only: false
func TestGoEnvironmentPreservesExplicitTelemetry(t *testing.T) {
	for _, value := range []string{"", "1", "true"} {
		t.Setenv("ENKV_TELEMETRY", value)
		t.Setenv("GOWORK", "synthetic-workspace")
		t.Setenv("GOFLAGS", "-tags=synthetic")
		t.Setenv("GORACE", "halt_on_error=1 exitcode=0 log_path=/tmp/hidden atexit_sleep_ms=0 halt_on_error=1")
		values := make(map[string][]string)
		for _, item := range goEnvironment() {
			key, value, _ := strings.Cut(item, "=")
			values[key] = append(values[key], value)
		}
		for key, want := range map[string]string{"GOWORK": "off", "GOTOOLCHAIN": "local", "GOFLAGS": "-trimpath", "GORACE": "", "ENKV_TELEMETRY": value} {
			if len(values[key]) != 1 || values[key][0] != want {
				t.Errorf("environment %s differs", key)
			}
		}
	}
}

// full_only: false
func TestFocusedGoPreparationDisablesFetch(t *testing.T) {
	root := sourceFixtureRoot(t)
	if err := os.WriteFile(filepath.Join(root, "go"), []byte("#!/bin/sh\nprintf '%s\\n' \"$GOPROXY\" \"$GOSUMDB\" \"$GONOPROXY\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GOPROXY", "https://example.invalid")
	t.Setenv("GOSUMDB", "sum.golang.org")
	t.Setenv("GONOPROXY", "*")
	body, err := runGo(cacheOnlyGoContext(t.Context()), root, ".", "version")
	if err != nil || string(body) != "off\noff\nnone\n" {
		t.Fatal("focused preparation could fetch missing prerequisites", string(body), err)
	}
}

// full_only: false
func TestFocusedLauncherDisablesFetchForAcceptedSpellings(t *testing.T) {
	maintained := filepath.Join(filepath.Dir(savedWorkflowPath(t, "check")), "../scripts/test")
	launcherBody, err := os.ReadFile(maintained)
	if err != nil {
		t.Fatal(err)
	}
	root := sourceFixtureRoot(t)
	launcher := filepath.Join(root, "tests/scripts/test")
	supervisor := filepath.Join(root, "tests/.supervisor/supervisor")
	for _, path := range []string{launcher, supervisor} {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(launcher, launcherBody, 0700); err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(root, "supervisor-environment")
	arguments := filepath.Join(root, "supervisor-arguments")
	goCalled := filepath.Join(root, "go-called")
	workflow := filepath.Join(root, "workflow.json")
	saveSelection(t, workflow, workflowFile{SchemaVersion: 1, Name: "offline", Steps: []workflowStep{
		{ID: "components", Kind: "component-tests", Profile: "dev"},
		{ID: "unit", Kind: "unit", Packages: []string{"core/contract"}},
	}})
	// Observe the launcher at its supervisor boundary. Plan uses a pure
	// preview; neither selector form requires a Go bootstrap in this shell.
	script := "#!/bin/sh\nprintf '%s\\n' \"$GOPROXY\" \"$GOSUMDB\" \"$GONOPROXY\" > \"$ENKV_LAUNCHER_PROBE\" || exit 91\nprintf '%s\\n' \"$@\" > \"$ENKV_LAUNCHER_ARGUMENTS\" || exit 92\nexit 7\n"
	if err := os.WriteFile(supervisor, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go"), []byte("#!/bin/sh\nprintf 'called\\n' > "+shellQuote(goCalled)+"\nexit 9\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GOPROXY", "https://example.invalid")
	t.Setenv("GOSUMDB", "sum.golang.org")
	t.Setenv("GONOPROXY", "*")
	t.Setenv("ENKV_LAUNCHER_PROBE", probe)
	t.Setenv("ENKV_LAUNCHER_ARGUMENTS", arguments)
	for _, command := range []string{"plan", "run"} {
		for _, spelling := range [][]string{{"--test", "TestParent"}, {"--test=TestParent"}, {"-test", "TestParent"}, {"-test=TestParent"}, {"--package", "core/contract"}, {"--package=core/contract"}, {"-package", "core/contract"}, {"-package=core/contract"}} {
			t.Run(command+"/"+spelling[0], func(t *testing.T) {
				step := "components"
				if strings.Contains(spelling[0], "package") {
					step = "unit"
				}
				args := append([]string{command, "--workflow=" + workflow, "--step=" + step}, spelling...)
				request, err := workflowArguments(args)
				if err != nil {
					t.Fatal("control does not use an accepted selector spelling", err)
				}
				if _, _, err := readWorkflowConfiguration(request); err != nil {
					t.Fatal("control does not use an accepted step selection", err)
				}
				for _, path := range []string{probe, arguments} {
					if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
						t.Fatal(err)
					}
				}
				child := exec.CommandContext(t.Context(), launcher, args...)
				if body, err := child.CombinedOutput(); err == nil || child.ProcessState == nil || child.ProcessState.ExitCode() != 7 {
					t.Fatal("controlled supervisor exit was lost", err, string(body))
				}
				body, err := os.ReadFile(probe)
				if err != nil || string(body) != "off\noff\nnone\n" {
					t.Fatal("focused launcher could fetch prerequisites", string(body), err)
				}
				body, err = os.ReadFile(arguments)
				wantArgs := append([]string{"invoke", "--root", root, "--"}, args...)
				if err != nil || string(body) != strings.Join(wantArgs, "\n")+"\n" {
					t.Fatal("launcher changed its root or literal selection arguments", string(body), err)
				}
				if _, err := os.Stat(goCalled); !os.IsNotExist(err) {
					t.Fatal("launcher unexpectedly invoked a Go bootstrap", err)
				}
			})
		}
	}
}

// full_only: false
func TestRaceEnvironmentRemovesAllInheritedDuplicates(t *testing.T) {
	for _, test := range []struct {
		name    string
		enabled bool
		want    string
	}{
		{"race_off", false, ""},
		{"race_on", true, "log_path=stderr exitcode=66 halt_on_error=0 atexit_sleep_ms=1000"},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := append(goEnvironment(), "GORACE=exitcode=0", "KEPT=value", "GORACE=halt_on_error=1", "GORACE=log_path=/tmp/hidden")
			values := raceEnvironment(base, test.enabled)
			traces := 0
			kept := false
			for _, item := range values {
				if item == "KEPT=value" {
					kept = true
				}
				if value, ok := strings.CutPrefix(item, "GORACE="); ok {
					traces++
					if value != test.want {
						t.Fatalf("race environment setting differs for enabled=%t", test.enabled)
					}
				}
			}
			if traces != 1 || !kept {
				t.Fatalf("race environment lost unique policy or unrelated input: traces=%d kept=%t", traces, kept)
			}
		})
	}
}

// full_only: false
func TestGoMetadataStreamRejectsPartialOutput(t *testing.T) {
	for _, body := range []string{`{"Path":"core"} trailing`, `{"Path":`, `{"Path":false}`} {
		if _, err := decodeObjects[resolvedModule]([]byte(body)); err == nil {
			t.Fatal("malformed metadata admitted")
		}
	}
	values, err := decodeObjects[resolvedModule]([]byte("{\"Path\":\"first\"}\n{\"Path\":\"second\"}\n"))
	if err != nil || len(values) != 2 || values[1].Path != "second" {
		t.Fatal("metadata stream changed")
	}
}

// full_only: false
func TestSharedSourceCannotBeReplacedByAnotherDirectory(t *testing.T) {
	for _, name := range []string{"core", "crypto", "telemetry", "compositions/outputhost", "protocols/output", "compositions/configuration", "compositions/manifesthost"} {
		root := sourceFixtureRoot(t)
		path, err := sourcePath(root, name)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		modules := []resolvedModule{{Path: modulePath(name), Dir: path, GoVersion: "1.27.0"}}
		if err := checkModuleSource(root, modules, name); err != nil {
			t.Fatal(err)
		}
		modules[0].GoVersion = "1.26.0"
		if checkModuleSource(root, modules, name) == nil {
			t.Fatal("downgraded module language admitted")
		}
		modules[0].GoVersion = "1.27.0"
		modules[0].Dir = t.TempDir()
		if checkModuleSource(root, modules, name) == nil {
			t.Fatal("external shared source admitted")
		}
		if checkModuleSource(root, nil, name) == nil {
			t.Fatal("missing shared source admitted")
		}
	}
}

// full_only: false
func TestCompiledCoreCustodyRejectsMethodValues(t *testing.T) {
	for _, name := range []string{"fixture.go", "fixture_test.go"} {
		root := sourceFixtureRoot(t)
		writeLocalGoFixture(t, root, "core/go.mod", "module "+modulePrefix+"core\n\ngo 1.27.0\n")
		writeLocalGoFixture(t, root, "core/core.go", "package core\n")
		writeLocalGoFixture(t, root, "core/"+name, "package core\n\nimport \"crypto/ecdh\"\n\nvar privateMethod = ecdh.P256().GenerateKey\n")
		_, packages, err := listClosure(runGoEnvironment, t.Context(), root, "core", []string{"-mod=readonly"}, name == "fixture_test.go")
		if err != nil {
			t.Fatal("private-method compiler metadata unavailable", err)
		}
		if err := checkCompiledCustody(packages); err == nil || !strings.Contains(err.Error(), "crypto/ecdh.GenerateKey") {
			t.Fatalf("compiled private method admitted for %s: %v", name, err)
		}
	}
}

// full_only: false
func TestCompiledCoreCustodyResolvesProviderMethods(t *testing.T) {
	root := sourceFixtureRoot(t)
	writeLocalGoFixture(t, root, "kms/go.mod", "module github.com/aws/aws-sdk-go-v2/service/kms\n\ngo 1.27.0\n")
	writeLocalGoFixture(t, root, "kms/kms.go", "package kms\ntype Client struct{}\nfunc (*Client) Decrypt() {}\n")
	writeLocalGoFixture(t, root, "core/go.mod", "module "+modulePrefix+"core\n\ngo 1.27.0\n\nrequire github.com/aws/aws-sdk-go-v2/service/kms v1.45.2\nreplace github.com/aws/aws-sdk-go-v2/service/kms => ../kms\n")
	writeLocalGoFixture(t, root, "core/core.go", "package core\n")
	writeLocalGoFixture(t, root, "core/private_test.go", "package core\nimport client \"github.com/aws/aws-sdk-go-v2/service/kms\"\nvar decrypt = new(client.Client).Decrypt\n")
	_, packages, err := listClosure(runGoEnvironment, t.Context(), root, "core", []string{"-mod=readonly"}, true)
	if err != nil {
		t.Fatal("provider-method compiler metadata unavailable", err)
	}
	if err := checkCompiledCustody(packages); err == nil || !strings.Contains(err.Error(), "kms.Decrypt") {
		t.Fatalf("provider private method admitted: %v", err)
	}
}

// full_only: false
func TestCompiledCoreCustodyAllowsOnlySafeFacadeSurface(t *testing.T) {
	for _, unsafe := range []bool{false, true} {
		root := sourceFixtureRoot(t)
		writeLocalGoFixture(t, root, "core/go.mod", "module "+modulePrefix+"core\n\ngo 1.27.0\n\nrequire "+modulePrefix+"crypto v0.0.0\n")
		writeLocalGoFixture(t, root, "crypto/go.mod", "module "+modulePrefix+"crypto\n\ngo 1.27.0\n")
		facade := "package trust\nimport \"crypto/rsa\"\ntype Fixture struct { key *rsa.PrivateKey }\nfunc New() *Fixture { return new(Fixture) }\n"
		if unsafe {
			facade += "func (f *Fixture) Key() *rsa.PrivateKey { return f.key }\n"
		}
		writeLocalGoFixture(t, root, "crypto/testsupport/trust/fixture.go", facade)
		writeLocalGoFixture(t, root, "core/core.go", "package core\n")
		writeLocalGoFixture(t, root, "core/fixture_test.go", "package core\nimport \""+modulePrefix+"crypto/testsupport/trust\"\nvar fixture = trust.New()\n")
		_, packages, err := listClosure(runGoEnvironment, t.Context(), root, "core", []string{"-mod=readonly"}, true)
		if err != nil {
			t.Fatal("facade compiler metadata unavailable", err)
		}
		err = checkCompiledCustody(packages)
		if unsafe && (err == nil || !strings.Contains(err.Error(), "facade exposes private type")) || !unsafe && err != nil {
			t.Fatalf("facade private surface (unsafe=%t): %v", unsafe, err)
		}
	}
}

// full_only: false
func TestProductionCryptoRootsKeepReachableFixtureImportsVisible(t *testing.T) {
	root, _ := lintFixture(t, t.TempDir())
	writeLocalGoFixture(t, root, "crypto/testsupport/trust/fixture.go", "package trust\n")
	modules, packages, err := listClosure(runGoEnvironment, context.Background(), root, "crypto", []string{"-mod=readonly"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkBoundary("crypto", modules, packages); err != nil {
		t.Fatal(err)
	}
	for _, p := range packages {
		if withinModule(p.ImportPath, modulePrefix+"crypto/testsupport") {
			t.Fatal("unused test facade became a production root")
		}
	}
	writeLocalGoFixture(t, root, "crypto/forbidden.go", "package crypto\nimport _ \""+modulePrefix+"crypto/testsupport/trust\"\n")
	modules, packages, err = listClosure(runGoEnvironment, context.Background(), root, "crypto", []string{"-mod=readonly"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkBoundary("crypto", modules, packages); err == nil {
		t.Fatal("reachable production fixture import was filtered from the graph")
	}
}

// full_only: false
func TestProductionCoreRootsKeepReachableNativeObserverImportsVisible(t *testing.T) {
	root := sourceFixtureRoot(t)
	helper := modulePrefix + "core/testsupport/nativeprocess"
	writeLocalGoFixture(t, root, "core/go.mod", "module "+modulePrefix+"core\n\ngo 1.27.0\n")
	writeLocalGoFixture(t, root, "core/core.go", "package core\n")
	writeLocalGoFixture(t, root, "core/testsupport/nativeprocess/fixture.go", "package nativeprocess\nimport _ \"strings\"\n")
	_, packages, err := listClosure(runGoEnvironment, t.Context(), root, "core", []string{"-mod=readonly"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkCustodyImports(packages, false, ""); err != nil {
		t.Fatal("unused standard-only observer became a production root", err)
	}
	for _, p := range packages {
		if p.ImportPath == helper {
			t.Fatal("unused native observer entered the production closure")
		}
	}
	writeLocalGoFixture(t, root, "core/forbidden.go", "package core\nimport _ \""+helper+"\"\n")
	_, packages, err = listClosure(runGoEnvironment, t.Context(), root, "core", []string{"-mod=readonly"}, false)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range packages {
		found = found || p.ImportPath == helper
	}
	if !found || checkCustodyImports(packages, false, "") == nil {
		t.Fatal("reachable production observer import was filtered from the graph")
	}
	writeLocalGoFixture(t, root, "core/testsupport/nativeprocess/nested/fixture.go", "package nested\n")
	writeLocalGoFixture(t, root, "core/testsupport/sibling/fixture.go", "package sibling\n")
	roots, err := productionPackages(runGoEnvironment, t.Context(), root, "core")
	if err != nil || len(roots) != 3 {
		t.Fatal("production root nomination omitted or added a test-support package", roots, err)
	}
	for _, want := range []string{modulePrefix + "core", helper + "/nested", modulePrefix + "core/testsupport/sibling"} {
		found := false
		for _, name := range roots {
			found = found || name == want
		}
		if !found {
			t.Fatal("production root nomination hid a non-helper package", want)
		}
	}
}

// full_only: false
func TestCompiledFacadeRejectsNamedMutableSink(t *testing.T) {
	root := sourceFixtureRoot(t)
	writeLocalGoFixture(t, root, "core/go.mod", "module "+modulePrefix+"core\n\ngo 1.27.0\n\nrequire "+modulePrefix+"crypto v0.0.0\n")
	writeLocalGoFixture(t, root, "crypto/go.mod", "module "+modulePrefix+"crypto\n\ngo 1.27.0\n")
	writeLocalGoFixture(t, root, "crypto/testsupport/trust/fixture.go", "package trust\nimport \"bytes\"\nfunc Sink() *bytes.Buffer { return new(bytes.Buffer) }\n")
	writeLocalGoFixture(t, root, "core/core.go", "package core\n")
	writeLocalGoFixture(t, root, "core/fixture_test.go", "package core\nimport \""+modulePrefix+"crypto/testsupport/trust\"\nvar sink = trust.Sink()\n")
	_, packages, err := listClosure(runGoEnvironment, t.Context(), root, "core", []string{"-mod=readonly"}, true)
	if err != nil {
		t.Fatal("mutable-sink compiler metadata unavailable", err)
	}
	if err := checkCompiledCustody(packages); err == nil {
		t.Fatal("facade exported an unrestricted mutable sink")
	}
}

// full_only: false
func TestActualCryptoFacadesKeepPrivateTypesOutsideCore(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	overlay, err := buildCryptoOverlay(root, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	modules, packages, err := listClosure(runGoEnvironment, context.Background(), root, "crypto", moduleTestFlags(root, "crypto", overlay), true, "./testsupport/trust", "./testsupport/custody")
	if err != nil {
		t.Fatal(err)
	}
	for _, owner := range []string{"core", "crypto", "telemetry", "compositions/outputhost", "protocols/output"} {
		if err := checkModuleSource(root, modules, owner); err != nil {
			t.Fatal(err)
		}
	}
	if err := checkCustodyImports(packages, true, ""); err != nil {
		t.Fatal(err)
	}
	modules, packages, err = listClosure(runGoEnvironment, t.Context(), root, "crypto", []string{"-mod=readonly"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkBoundary("crypto", modules, packages); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestCompiledCoreCustodyUsesCgoCompilerSources(t *testing.T) {
	t.Setenv("CGO_ENABLED", "1")
	for _, row := range []struct {
		name                           string
		overlay, forbidden, nestedTest bool
	}{{"safe", false, false, false}, {"forbidden", false, true, false}, {"overlay-safe", true, false, false}, {"overlay-forbidden", true, true, false}, {"safe-test-main", false, false, true}} {
		t.Run(row.name, func(t *testing.T) {
			root := sourceFixtureRoot(t)
			writeLocalGoFixture(t, root, "core/go.mod", "module "+modulePrefix+"core\n\ngo 1.27.0\n")
			packageDirectory, pattern := "core", "."
			if row.nestedTest {
				packageDirectory, pattern = "core/contract", "./contract"
				writeLocalGoFixture(t, root, "core/contract/core_test.go", "package core\nimport \"testing\"\n// full_only: false\nfunc TestNativeValue(t *testing.T) { if nativeValue() != 7 { t.Fatal(\"native value changed\") } }\n")
			}
			caller := "package core\nvar nativeResult = nativeValue()\n"
			native := "package core\nimport \"C\"\nfunc nativeValue() int { return int(C.int(7)) }\n"
			forbidden := "import \"crypto/ecdh\"\nvar privateMethod = ecdh.P256().GenerateKey\n"
			selected := native
			if row.forbidden {
				selected = strings.Replace(native, "func nativeValue", forbidden+"func nativeValue", 1)
			}
			flags := []string{"-mod=readonly"}
			if row.overlay {
				// Physical ordinary source is forbidden; only its overlay is safe.
				// Physical cgo source is safe; its overlay selects either outcome.
				writeLocalGoFixture(t, root, filepath.Join(packageDirectory, "core.go"), strings.Replace(caller, "var nativeResult", forbidden+"var nativeResult", 1))
				writeLocalGoFixture(t, root, filepath.Join(packageDirectory, "native.go"), native)
				writeLocalGoFixture(t, root, "caller-overlay.go", caller)
				writeLocalGoFixture(t, root, "native-overlay.go", selected)
				path := filepath.Join(root, "overlay.json")
				body, err := json.Marshal(struct{ Replace map[string]string }{map[string]string{
					filepath.Join(root, packageDirectory, "core.go"):   filepath.Join(root, "caller-overlay.go"),
					filepath.Join(root, packageDirectory, "native.go"): filepath.Join(root, "native-overlay.go"),
				}})
				if err != nil || os.WriteFile(path, body, 0600) != nil {
					t.Fatal("cgo custody overlay unavailable", err)
				}
				flags = append(flags, "-overlay="+path)
			} else {
				writeLocalGoFixture(t, root, filepath.Join(packageDirectory, "core.go"), caller)
				writeLocalGoFixture(t, root, filepath.Join(packageDirectory, "native.go"), selected)
			}
			_, packages, err := listClosure(runGoEnvironment, t.Context(), root, "core", flags, row.nestedTest, pattern)
			if err != nil {
				t.Fatal("cgo compiler metadata unavailable", err)
			}
			err = checkCompiledCustody(packages)
			if row.forbidden {
				if err == nil || !strings.Contains(err.Error(), "Core private-key custody refused") || !strings.Contains(err.Error(), "crypto/ecdh.GenerateKey") {
					t.Error("compiled cgo custody method was not refused by exact policy", err)
				}
			} else if err != nil {
				t.Error("valid Go caller of a cgo-defined function lost compiled sources", err)
			}
			if row.nestedTest && err == nil {
				found := false
				for _, pkg := range packages {
					if pkg.ImportPath == modulePrefix+"core/contract.test" {
						found = true
						if len(pkg.GoFiles) == 0 || len(pkg.CgoFiles)+len(pkg.SwigFiles)+len(pkg.SwigCXXFiles) != 0 {
							t.Error("actual nested test-main source metadata unavailable", pkg.ImportPath)
						}
					}
				}
				if !found {
					t.Error("safe nested graph did not include its actual generated test main")
				}
			}
			if row.name == "safe" && err == nil {
				// The same actual transformed fixture must not fall back to an
				// incomplete ordinary source set if compiled metadata is lost.
				found := false
				for _, pkg := range packages {
					if pkg.ImportPath == modulePrefix+"core" && len(pkg.CgoFiles) != 0 {
						found = true
						pkg.CompiledGoFiles = nil
						if err := checkCompiledCustody([]compiledPackage{pkg}); err == nil || !strings.Contains(err.Error(), "custody compiled sources unavailable") {
							t.Error("missing transformed sources admitted ordinary fallback", err)
						}
					}
				}
				if !found {
					t.Error("safe fixture lost its selected cgo source class")
				}
			}
		})
	}
}

// full_only: false
func TestSharedGeneratorSourcesUseRegisteredSiblingOwners(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "enkv-core")
	for _, test := range []struct{ selector, physical, module string }{
		{"protocols/generator", "sdk/protocols/generator", "enkv.sh/sdk/protocols/generator"},
		{"plugins/cloudflare", "plugins/generators/cloudflare-account-token", cloudflareModulePath},
		{"protocols/output", "sdk/protocols/output", "enkv.sh/sdk/protocols/output"},
		{"plugins/aws-output", "plugins/outputs/aws-secrets-manager", "enkv.sh/plugins/outputs/aws-secrets-manager"},
		{"plugins/gcp-output", "plugins/outputs/gcp-secret-manager", "enkv.sh/plugins/outputs/gcp-secret-manager"},
		{"plugins/github-output", "plugins/outputs/github-actions", "enkv.sh/plugins/outputs/github-actions"},
		{"sdk/generator", "sdk/generator", generatorSDKPath},
		{"sdk/examples/local-token-generator", "sdk/examples/local-token-generator", generatorExamplePath},
	} {
		owner := filepath.Join(parent, "enkv-extensions", test.physical)
		if err := os.MkdirAll(owner, 0700); err != nil {
			t.Fatal(err)
		}
		modules := []resolvedModule{{Path: test.module, Dir: owner, GoVersion: "1.27.0"}}
		if err := checkModuleSource(root, modules, test.selector); err != nil {
			t.Fatalf("registered sibling source refused: %v", err)
		}
		modules[0].Dir = t.TempDir()
		if checkModuleSource(root, modules, test.selector) == nil {
			t.Fatal("unregistered source admitted")
		}
	}
}

// full_only: false
func TestRegisteredSourceLabelsRejectUnmappedAndSymlinkOwners(t *testing.T) {
	root := sourceFixtureRoot(t)
	label := "plugins/cloudflare/profile/semantics.go"
	physical := writeLocalGoFixture(t, root, label, "package profile\n")
	got, err := sourceLabel(root, physical)
	if err != nil || got != label {
		t.Fatal("registered source label changed", got, err)
	}
	if _, err := sourceLabel(root, filepath.Join(t.TempDir(), "unmapped.go")); err == nil {
		t.Fatal("unmapped sibling source admitted")
	}
	if _, err := sourcePath(root, "../other/source.go"); err == nil {
		t.Fatal("generic parent source path admitted")
	}
	stale := filepath.Join(root, "plugins/cloudflare/profile/semantics.go")
	if err := os.MkdirAll(filepath.Dir(stale), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("package profile\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := sourceLabel(root, stale); err == nil {
		t.Fatal("retired physical owner received a registered logical label")
	}
	registered, ok := registeredModule("enkv.sh/plugins/generators/cloudflare-account-token")
	if !ok || registered.Selector != "plugins/cloudflare" || registered.Module != cloudflareModulePath {
		t.Fatal("registered module or command identity changed")
	}
	owner, err := moduleSourceDirectory(root, registered)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(owner); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), owner); err != nil {
		t.Fatal(err)
	}
	if _, err := sourcePath(root, label); err == nil {
		t.Fatal("symlink public source owner admitted")
	}
}

// full_only: false
func TestCompilerSourcesIncludeVirtualFilesAndEmbeddedInputs(t *testing.T) {
	root, _, _ := overlayFixture(t)
	keep := writeLocalGoFixture(t, root, "core/keep.go", "package core\n")
	backing := filepath.Join(t.TempDir(), "backing.go")
	if err := os.WriteFile(backing, []byte("package core\nimport _ \"embed\"\n//go:embed input.txt\nvar Input string\n"), 0600); err != nil {
		t.Fatal(err)
	}
	embedded := writeLocalGoFixture(t, root, "core/input.txt", "embedded bytes\n")
	writeLocalGoFixture(t, root, "core/unselected.txt", "unrelated bytes\n")
	virtual := filepath.Join(root, "core", "virtual.go")
	overlay := filepath.Join(t.TempDir(), "overlay.json")
	if err := records.WriteJSON(overlay, struct{ Replace map[string]string }{map[string]string{virtual: backing}}, 0600); err != nil {
		t.Fatal(err)
	}
	flags, patterns := []string{"-mod=readonly", "-overlay=" + overlay}, []string{"keep.go", "virtual.go"}
	_, packages, err := listClosure(runGoEnvironment, t.Context(), root, "core", flags, true, patterns...)
	if err != nil {
		t.Fatal("virtual file-list compiler metadata unavailable", err)
	}
	if _, err := os.Stat(virtual); !os.IsNotExist(err) {
		t.Fatal("fixture did not retain a genuinely virtual source", err)
	}
	found := false
	for _, pkg := range packages {
		if pkg.ImportPath != "command-line-arguments" {
			continue
		}
		found = true
		if len(pkg.GoFiles) != 2 || len(pkg.EmbedFiles) != 1 {
			t.Fatal("compiler source or embedded-input set differs", pkg.GoFiles, pkg.EmbedFiles)
		}
		sources := map[string]bool{}
		for _, name := range pkg.GoFiles {
			if !filepath.IsAbs(name) {
				name = filepath.Join(pkg.Dir, name)
			}
			sources[name] = true
		}
		input := pkg.EmbedFiles[0]
		if !filepath.IsAbs(input) {
			input = filepath.Join(pkg.Dir, input)
		}
		if !sources[keep] || !sources[backing] || input != embedded {
			t.Fatal("compiler omitted an effective source or selected an unrelated embedded input", sources, input)
		}
	}
	if !found {
		t.Fatal("virtual file-list package is absent")
	}
}

// full_only: false
func TestCompilerSourcesFollowRaceBuildTags(t *testing.T) {
	for _, race := range []bool{false, true} {
		t.Run(fmt.Sprintf("race=%t", race), func(t *testing.T) {
			root, _, _ := overlayFixture(t)
			writeLocalGoFixture(t, root, "core/race.go", "//go:build race\n\npackage core\nconst Selected = 1\n")
			writeLocalGoFixture(t, root, "core/nonrace.go", "//go:build !race\n\npackage core\nconst Selected = 1\n")
			flags := compilerBuildFlags([]string{"-mod=readonly"}, race)
			_, packages, err := listClosure(runGoEnvironment, t.Context(), root, "core", flags, true, ".")
			if err != nil {
				t.Fatal("race-selected compiler metadata unavailable", err)
			}
			active := "nonrace.go"
			if race {
				active = "race.go"
			}
			found := false
			for _, pkg := range packages {
				if pkg.ImportPath != componentPackage {
					continue
				}
				found = true
				if len(pkg.GoFiles) != 1 || filepath.Base(pkg.GoFiles[0]) != active {
					t.Fatal("compiler source set differs from the accepted race setting", pkg.GoFiles, active)
				}
			}
			if !found {
				t.Fatal("race-selected package is absent")
			}
		})
	}
}

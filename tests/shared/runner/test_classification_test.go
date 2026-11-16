package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestTestClassificationRequiresExplicitActiveDeclarations(t *testing.T) {
	t.Run("compiled-ordinary-kinds", func(t *testing.T) {
		root, _, _ := overlayFixture(t)
		const pkg = "enkv.sh/telemetry/inventory"
		writeLocalGoFixture(t, root, "telemetry/go.mod", "module enkv.sh/telemetry\n\ngo 1.27.0\n")
		writeLocalGoFixture(t, root, "telemetry/inventory/kinds_test.go", `package inventory
import ("fmt"; "testing")
// full_only: false
func TestOrdinary(t *testing.T) {}
// full_only: false
func FuzzSeed(f *testing.F) { f.Add("seed"); f.Fuzz(func(t *testing.T, value string) {}) }
// full_only: false
func Example() { fmt.Println("example")
// Output: example
}
func BenchmarkNotSelected(b *testing.B) { b.Fatal("benchmark must not execute") }
`)
		ctx := withExecutionParallel(withRacePolicy(t.Context(), false), 1)
		listed, err := listOrdinaryPackages(ctx, root, "telemetry", nil, []string{"./inventory"}, nil)
		if err != nil || len(listed) != 1 {
			t.Fatal("ordinary inventory fixture discovery failed", listed, err)
		}
		compiled, err := prepareOrdinaryPackage(ctx, root, "telemetry", nil, []string{"./inventory"}, listed[0], t.TempDir(), nil)
		if err != nil {
			t.Fatal(err)
		}
		names := []string{"TestOrdinary", "FuzzSeed", "Example"}
		if !slices.Equal(compiled.inventory.Inventory, names) || len(compiled.inventory.Classifications) != len(names) {
			t.Fatal("ordinary inventory omitted a runnable root or included a benchmark", compiled.inventory)
		}
		goroot, err := runGo(ctx, root, "telemetry", "env", "GOROOT")
		if err != nil {
			t.Fatal(err)
		}
		artifact := preparedOrdinaryArtifact{ordinaryArtifact: ordinaryArtifact{Directory: "telemetry", Package: pkg, Tests: names, Classifications: compiled.inventory.Classifications}, binary: compiled.binary, cwd: compiled.cwd, converter: testEventConverterFixture(t, root), unit: true}
		evidence := ordinaryStepEvidence{Diagnostics: &checkDiagnostics{Preparation: "passed"}}
		if err := executePreparedOrdinary(ctx, root, artifact, strings.TrimSpace(string(goroot)), map[string][]string{pkg: names}, &evidence); err != nil {
			t.Fatal("ordinary roots failed after inventory", err)
		}
		if len(evidence.Tests) != 4 {
			t.Fatal("ordinary roots or seed terminal missing", evidence.Tests)
		}
		for _, test := range evidence.Tests {
			if test.Outcome != "pass" || !slices.Contains(names, strings.SplitN(test.Name, "/", 2)[0]) {
				t.Fatal("ordinary execution changed selection or ran a benchmark", evidence.Tests)
			}
		}
	})
	for _, test := range []struct {
		name, marker string
		valid        bool
		fullOnly     bool
		exclusive    bool
	}{
		{"daily", "// full_only: false\n", true, false, false},
		{"full", "// full_only: true\n", true, true, false},
		{"exclusive-daily", "// full_only: false\n// exclusive: true\n", true, false, true},
		{"exclusive-full", "// full_only: true\n// exclusive: true\n", true, true, true},
		{"explicit-normal", "// full_only: true\n// exclusive: false\n", true, true, false},
		{"missing", "", false, false, false},
		{"invalid", "// full_only: yes\n", false, false, false},
		{"repeated", "// full_only: false\n// full_only: true\n", false, false, false},
		{"block", "/* full_only: true */\n", false, false, false},
		{"exclusive-invalid", "// full_only: false\n// exclusive: yes\n", false, false, false},
		{"exclusive-repeated", "// full_only: false\n// exclusive: false\n// exclusive: true\n", false, false, false},
		{"exclusive-block", "// full_only: false\n/* exclusive: true */\n", false, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := sourceFixtureRoot(t)
			body := "package sample\n" + test.marker + "func TestRoot() {}\nfunc helper() {}\nfunc ExampleWithoutOutput() {}\n"
			if err := os.WriteFile(filepath.Join(root, "active_test.go"), []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "inactive_test.go"), []byte("package sample\nfunc TestInactive() {}\n"), 0600); err != nil {
				t.Fatal(err)
			}
			classified, _, err := classifyTestPackages(root, []listedOrdinaryPackage{{ImportPath: "example.org/sample", Dir: root, TestGoFiles: []string{"active_test.go"}}}, nil, map[string][]string{"example.org/sample": {"TestRoot"}})
			if (err == nil) != test.valid {
				t.Fatal("explicit classification admission differs", err)
			}
			if test.valid && (len(classified["example.org/sample"]) != 1 || classified["example.org/sample"][0].FullOnly == nil || *classified["example.org/sample"][0].FullOnly != test.fullOnly || classified["example.org/sample"][0].Exclusive != test.exclusive) {
				t.Fatal("classification changed its declared value")
			}
			if test.valid {
				rows := classified["example.org/sample"]
				selected, omitted, err := selectClassifiedTests([]string{"TestRoot"}, rows, "dev")
				if err != nil || test.fullOnly && (len(selected) != 0 || len(omitted) != 1) || !test.fullOnly && (len(selected) != 1 || len(omitted) != 0) {
					t.Fatal("resource class changed coverage selection", selected, omitted, err)
				}
				changed := slices.Clone(rows)
				changed[0].Exclusive = !changed[0].Exclusive
				if sameTestClassifications(rows, changed) {
					t.Fatal("classification comparison omitted resource class")
				}
			}
		})
	}
	t.Run("overlaid-seeds-and-example", func(t *testing.T) {
		root := sourceFixtureRoot(t)
		original, replacement := filepath.Join(root, "active_test.go"), filepath.Join(root, "overlay_test.go")
		if err := os.WriteFile(original, []byte("package sample\nfunc FuzzDecode() {}\nfunc ExampleRead() {}\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(replacement, []byte("package sample\n// full_only: false\nfunc FuzzDecode() {}\n// full_only: true\nfunc ExampleRead() {}\n"), 0600); err != nil {
			t.Fatal(err)
		}
		overlay := filepath.Join(root, "overlay.json")
		if err := records.WriteJSON(overlay, struct{ Replace map[string]string }{map[string]string{original: replacement}}, 0600); err != nil {
			t.Fatal(err)
		}
		names := []string{"FuzzDecode", "ExampleRead"}
		classified, sources, err := classifyTestPackages(root, []listedOrdinaryPackage{{ImportPath: "example.org/sample", Dir: root, XTestGoFiles: []string{"active_test.go"}}}, []string{"-overlay=" + overlay}, map[string][]string{"example.org/sample": names})
		if err != nil {
			t.Fatal(err)
		}
		selected, omitted, err := selectClassifiedTests(names, classified["example.org/sample"], "dev")
		if err != nil || !slices.Equal(selected, []string{"FuzzDecode"}) || !slices.Equal(omitted, []string{"ExampleRead"}) || sources["example.org/sample"]["FuzzDecode"] != "overlay_test.go" {
			t.Fatal("active overlay metadata or seed/example selection changed", selected, omitted, err)
		}
	})
}

// full_only: false
func TestClassifiedFocusAndRetainedEvidenceRefuseMissingOrExcludedMetadata(t *testing.T) {
	value := true
	artifact := ordinaryArtifact{Owner: "core/contract", Package: "example.org/contract", Profile: "dev", Tests: []string{"TestSmall"}, CompiledTests: []string{"TestSmall", "TestMaximum"}, Classifications: componentFixtureClassifications([]string{"TestSmall", "TestMaximum"})}
	artifact.Classifications[1].FullOnly = &value
	if _, _, err := resolveOneOrdinaryFocusFixture([]ordinaryArtifact{artifact}, ordinaryFocus{PackagePath: artifact.Owner, Tests: singleTestRequest("TestSmall")}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveOneOrdinaryFocusFixture([]ordinaryArtifact{artifact}, ordinaryFocus{PackagePath: artifact.Owner, Tests: singleTestRequest("TestMaximum")}); err == nil {
		t.Fatal("dev focus admitted an excluded maximum root")
	}
	pkg := ordinaryPackage{Name: artifact.Package, Tests: artifact.Tests, Inventory: artifact.CompiledTests, Classifications: artifact.Classifications, NotSelected: []string{"TestMaximum"}}
	if !validOrdinaryPackageSelection(pkg, "dev") {
		t.Fatal("retained explicit classification was refused")
	}
	for _, changed := range []func(*ordinaryPackage){
		func(p *ordinaryPackage) { p.Classifications = nil },
		func(p *ordinaryPackage) { p.Classifications[1].FullOnly = nil },
		func(p *ordinaryPackage) { p.NotSelected = nil },
		func(p *ordinaryPackage) { p.Tests = append(p.Tests, "TestMaximum") },
	} {
		broken := pkg
		broken.Classifications = slices.Clone(pkg.Classifications)
		changed(&broken)
		if validOrdinaryPackageSelection(broken, "dev") {
			t.Fatal("inconsistent retained profile facts acquired completion")
		}
	}
	only := ordinaryPackage{Name: "example.org/only", Inventory: []string{"TestMaximum"}, NotSelected: []string{"TestMaximum"}, Classifications: []testClassification{{Name: "TestMaximum", FullOnly: &value}}}
	empty := ordinaryStepEvidence{Profile: "dev", Packages: []ordinaryPackage{only}}
	for _, test := range []struct {
		name   string
		events []ordinaryEvent
		valid  bool
	}{
		{"pass", []ordinaryEvent{{Action: "start", Package: only.Name}, {Action: "pass", Package: only.Name}}, true},
		{"skip", []ordinaryEvent{{Action: "start", Package: only.Name}, {Action: "skip", Package: only.Name}}, false},
		{"excluded-body", []ordinaryEvent{{Action: "start", Package: only.Name}, {Action: "run", Package: only.Name, Test: "TestMaximum"}, {Action: "pass", Package: only.Name, Test: "TestMaximum"}, {Action: "pass", Package: only.Name}}, false},
	} {
		t.Run("empty-"+test.name, func(t *testing.T) {
			_, _, err := parseOrdinarySelectedEvents(ordinaryEvents(test.events...), map[string][]string{only.Name: nil}, nil, &empty, nil)
			if (err == nil) != test.valid {
				t.Fatal("empty selected scope changed package terminal requirements", err)
			}
		})
	}
	if err := appendOrdinaryInventory(&ordinaryStepEvidence{}, map[string][]string{only.Name: nil}, nil); err == nil {
		t.Fatal("missing metadata silently dropped an empty selected package")
	}
}

// full_only: false
func TestTestClassificationMatchesBoundRaceFiles(t *testing.T) {
	root := sourceFixtureRoot(t)
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.org/raceclassification\n\ngo 1.27.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, file := range []struct{ name, source string }{
		{"plain_test.go", "//go:build !race\n\npackage sample\nimport \"testing\"\n// full_only: false\nfunc TestMode(t *testing.T) {}\n"},
		{"race_test.go", "//go:build race\n\npackage sample\nimport \"testing\"\n// full_only: true\nfunc TestMode(t *testing.T) {}\n"},
	} {
		if err := os.WriteFile(filepath.Join(root, file.name), []byte(file.source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, race := range []bool{false, true} {
		classified, sources, err := discoverTestClassifications(t.Context(), root, ".", []string{"-mod=readonly"}, []string{"."}, race, map[string][]string{"example.org/raceclassification": {"TestMode"}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		want := "plain_test.go"
		if race {
			want = "race_test.go"
		}
		if len(classified["example.org/raceclassification"]) != 1 || *classified["example.org/raceclassification"][0].FullOnly != race || sources["example.org/raceclassification"]["TestMode"] != want {
			t.Fatal("classification did not use the bound artifact's active race files", race, sources)
		}
	}
}

// full_only: false
func TestOrdinaryDailyClassificationKeepsPackageIdentityAndEmptyBuildProof(t *testing.T) {
	root := sourceFixtureRoot(t)
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.org/classification\n\ngo 1.27.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ pkg, source string }{
		{"first", "// full_only: true\nfunc TestSame(t *testing.T) { t.Fatal(\"full-only first executed\") }\n// full_only: false\nfunc TestSmall(t *testing.T) {}\n"},
		{"second", "// full_only: false\nfunc TestSame(t *testing.T) {}\n// full_only: false\nfunc TestSmall(t *testing.T) {}\n"},
		{"only", "// full_only: true\nfunc TestSame(t *testing.T) { t.Fatal(\"all-full-only package executed\") }\n"},
	} {
		directory := filepath.Join(root, test.pkg)
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "profile_test.go"), []byte("package sample\nimport \"testing\"\n"+test.source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var evidence ordinaryStepEvidence
	if err := executeOrdinaryCommand(t.Context(), root, ".", "dev", []string{"-mod=readonly"}, []string{"./first", "./second", "./only"}, "", nil, &evidence); err != nil {
		t.Fatal(err)
	}
	if len(evidence.Tests) != 3 || len(evidence.Packages) != 3 {
		t.Fatal("daily classification lost package/terminal scope", evidence)
	}
	for _, pkg := range evidence.Packages {
		if !validOrdinaryPackageSelection(pkg, "dev") {
			t.Fatal("ordinary execution lost explicit retained metadata", pkg)
		}
		if strings.HasSuffix(pkg.Name, "/only") && (len(pkg.Tests) != 0 || !slices.Equal(pkg.NotSelected, []string{"TestSame"})) {
			t.Fatal("all-full-only package lost its exact omissions")
		}
	}
	commands := 0
	for _, command := range evidence.Diagnostics.Commands {
		if command.Phase == "test" {
			commands++
			if command.Process != "passed" || !command.Started || !command.Joined || command.Events != "valid" {
				t.Fatal("daily package did not retain real successful build/execution proof", command)
			}
		}
	}
	if commands != 3 {
		t.Fatal("package-specific selection did not execute each real package", commands)
	}
	evidence.Complete = true
	if !completeOrdinaryEvidence(evidence) {
		t.Fatal("complete daily selection was refused")
	}
	file := filepath.Join(root, "first", "profile_test.go")
	var launcher ordinaryStepEvidence
	if err := executeOrdinaryCommand(t.Context(), root, ".", "dev", []string{"-mod=readonly"}, []string{file}, "", nil, &launcher); err != nil || len(launcher.Tests) != 1 || launcher.Tests[0].Name != "TestSmall" || launcher.Packages[0].Name != "command-line-arguments" {
		t.Fatal("file-list launcher classification differs", launcher, err)
	}
}

// full_only: false
func TestOrdinaryPackageFocusPreservesProfileSelection(t *testing.T) {
	root := sourceFixtureRoot(t)
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.org/focusprofile\n\ngo 1.27.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct{ name, body string }{
		{"mixed", "// full_only: false\nfunc TestSmall(t *testing.T) {}\n// full_only: true\nfunc TestMaximum(t *testing.T) {}\n"},
		{"only", "// full_only: true\nfunc TestMaximum(t *testing.T) {}\n"},
	} {
		directory := filepath.Join(root, fixture.name)
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "profile_test.go"), []byte("package sample\nimport \"testing\"\n"+fixture.body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct {
		name, profile string
		want          []string
	}{
		{"mixed", "dev", []string{"TestSmall"}},
		{"only", "dev", nil},
		{"mixed", "full", []string{"TestSmall", "TestMaximum"}},
	} {
		t.Run(test.name+"-"+test.profile, func(t *testing.T) {
			flags, patterns := []string{"-mod=readonly"}, []string{"./" + test.name}
			inventory, retained, err := discoverOrdinaryInventory(t.Context(), root, ".", flags, patterns, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			selected, retained, err := selectOrdinaryProfile(inventory, retained, test.profile)
			if err != nil || len(retained) != 1 {
				t.Fatal("profile inventory unavailable", err)
			}
			pkg := retained[0]
			if !slices.Equal(pkg.Tests, test.want) {
				t.Fatal("profile selected wrong roots", pkg.Tests)
			}
			artifact := ordinaryArtifact{Owner: "core/" + test.name, Package: pkg.Name, Profile: test.profile, Tests: pkg.Tests, CompiledTests: pkg.Inventory, Classifications: pkg.Classifications}
			focus, _, err := resolveOneOrdinaryFocusFixture([]ordinaryArtifact{artifact}, ordinaryFocus{PackagePath: artifact.Owner})
			if err != nil {
				t.Fatal(err)
			}
			evidence := ordinaryStepEvidence{Profile: test.profile, RaceOptions: raceOptions}
			if err := appendOrdinaryInventory(&evidence, selected, retained); err != nil {
				t.Fatal(err)
			}
			if err := executeOrdinaryInventory(t.Context(), t.Context(), root, ".", flags, patterns, runnerGroupSelection(ordinaryFocusedRoots(artifact, focus)), selected, nil, &focus, &evidence); err != nil {
				t.Fatal("package focus executed outside its selected profile", err)
			}
			if len(evidence.Tests) != len(test.want) || !validOrdinaryProfileEvidence(evidence) {
				t.Fatal("package focus lost exact terminal or omission evidence", evidence)
			}
		})
	}
}

// full_only: false
func TestMovedPublicTestsKeepLogicalClassificationAndFocus(t *testing.T) {
	root := sourceFixtureRoot(t)
	physical := writeLocalGoFixture(t, root, "protocols/generator/wire_test.go", "package generator\n// full_only: false\nfunc TestWire() {}\n")
	pkg := "enkv.sh/sdk/protocols/generator"
	classified, sources, err := classifyTestPackages(root, []listedOrdinaryPackage{{ImportPath: pkg, Dir: filepath.Dir(physical), TestGoFiles: []string{"wire_test.go"}}}, nil, map[string][]string{pkg: {"TestWire"}})
	if err != nil || len(classified[pkg]) != 1 || sources[pkg]["TestWire"] != "protocols/generator/wire_test.go" {
		t.Fatal("moved test classification lost its logical owner", sources, err)
	}
	writeLocalGoFixture(t, root, "plugins/cloudflare/go.mod", "module "+cloudflareModulePath+"\n\ngo 1.27.0\n")
	writeLocalGoFixture(t, root, "plugins/cloudflare/profile/profile.go", "package profile\n")
	focus, err := resolveOrdinaryUnitPackage(t.Context(), root, map[string][]string{"plugins/cloudflare": {"./..."}}, "plugins/cloudflare/profile")
	if err != nil || len(focus.Artifacts) != 1 || focus.Artifacts[0].Package != cloudflareModulePath+"/profile" || focus.Artifacts[0].Directory != "plugins/cloudflare" || !slices.Equal(focus.Artifacts[0].Patterns, []string{"./profile"}) {
		t.Fatal("moved package focus changed its configured identity", focus, err)
	}
}

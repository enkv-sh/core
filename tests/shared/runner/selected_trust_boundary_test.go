package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// full_only: false
func TestCLIAssembliesBuildAndExposeSelectedManifest(t *testing.T) {
	root := maintainedCloudflareRoot(t)
	ctx, cancel := context.WithTimeout(cacheOnlyGoContext(t.Context()), 6*time.Minute)
	defer cancel()
	directory := t.TempDir()
	probe := filepath.Join(directory, "manifest.go")
	if err := os.WriteFile(probe, []byte(selectedManifestProbe), 0600); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name, tag string
		families  []int
	}{
		{"full", "", []int{1, 2}},
		{"aws", "enkv_aws", []int{1}},
		{"gcp", "enkv_gcp", []int{2}},
	} {
		t.Run(row.name, func(t *testing.T) {
			binary := filepath.Join(directory, "enkv-"+row.name)
			flags := []string{"build", "-mod=readonly", "-trimpath", "-buildvcs=false"}
			if row.tag != "" {
				flags = append(flags, "-tags="+row.tag)
			}
			if _, err := runGo(ctx, root, "compositions/full", append(append([]string{}, flags...), "-o", binary, "./cmd/enkv")...); err != nil {
				t.Fatal(err)
			}
			var out, diagnostic limitedOutput
			result := runProcessOutput(ctx, binary, directory, []string{"inspect", "--help"}, []string{}, 10*time.Second, &out, &diagnostic)
			if !result.Started || !result.Joined || result.Status != "passed" || out.overflow || diagnostic.overflow || diagnostic.String() != "" || out.String() != installedInspectHelp {
				t.Fatalf("installed CLI help: result=%+v stdout=%q stderr=%q", result, out.String(), diagnostic.String())
			}
			manifestBinary := filepath.Join(directory, "manifest-"+row.name)
			if _, err := runGo(ctx, root, "compositions/full", append(append([]string{}, flags...), "-o", manifestBinary, probe)...); err != nil {
				t.Fatal(err)
			}
			out, diagnostic = limitedOutput{}, limitedOutput{}
			result = runProcessOutput(ctx, manifestBinary, directory, nil, []string{}, 10*time.Second, &out, &diagnostic)
			if !result.Started || !result.Joined || result.Status != "passed" || out.overflow || diagnostic.overflow || diagnostic.String() != "" {
				t.Fatalf("manifest API probe: result=%+v stderr=%q", result, diagnostic.String())
			}
			var got selectedManifestFacts
			if err := json.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			identity := sha256.Sum256([]byte("enkv/composition/" + row.name + "/v1"))
			want := selectedManifestFacts{Identity: hex.EncodeToString(identity[:]), Versions: []string{"v0.0.0", "state-session/v9", "canonical-state/v16", "store-trust-crypto/v9", "supplied-secret/v4", "rsa3072-oaep-sha256-aes256gcm-hmacsha256/v2"}, Fresh: true}
			for _, family := range row.families {
				provider, store, trust, verifier := "aws", "aws-s3-regional-v2", "aws-kms-p256-v1", "aws-kms-p256-spki-v1"
				if family == 2 {
					provider, store, trust, verifier = "gcp", "gcp-gcs-json-v2", "gcp-cloudkms-p256-v1", "gcp-p256-spki-v1"
				}
				want.Components = append(want.Components, selectedComponentFact{family, 1, store, "enkv.sh/providers/" + provider, "v0.0.0"}, selectedComponentFact{family, 2, trust, "enkv.sh/providers/" + provider, "v0.0.0"})
				want.Constructions = append(want.Constructions, selectedConstructionFact{family, 1, store}, selectedConstructionFact{family, 2, trust})
				want.Verifiers = append(want.Verifiers, selectedVerifierFact{family, verifier, true, true})
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("selected manifest differs\ngot: %+v\nwant: %+v", got, want)
			}
		})
	}
	t.Run("conflicting-selection", func(t *testing.T) {
		binary := filepath.Join(directory, "conflicting-enkv")
		_, err := runGo(ctx, root, "compositions/full", "build", "-mod=readonly", "-tags=enkv_aws,enkv_gcp", "-o", binary, "./cmd/enkv")
		if err == nil || !strings.Contains(err.Error(), "enkv_aws_and_enkv_gcp_are_mutually_exclusive") {
			t.Fatalf("both selection tags did not produce the deliberate compiler refusal: %v", err)
		}
		if _, err := os.Stat(binary); !os.IsNotExist(err) {
			t.Fatal("conflicting selections left an executable", err)
		}
	})
}

type selectedComponentFact struct {
	Family, Kind           int
	Class, Module, Version string
}

type selectedConstructionFact struct {
	Family, Kind int
	Class        string
}

type selectedVerifierFact struct {
	Family              int
	Class               string
	Present, NilRefused bool
}

type selectedManifestFacts struct {
	Identity      string
	Versions      []string
	Components    []selectedComponentFact
	Constructions []selectedConstructionFact
	Verifiers     []selectedVerifierFact
	Generators    int
	Fresh         bool
}

// The probe calls the public library with the same build flags as the CLI.
// Production command closure is checked separately without this probe.
const selectedManifestProbe = `package main
import (
 "encoding/hex"
 "encoding/json"
 "os"
 "reflect"
 full "enkv.sh/compositions/full"
 "enkv.sh/core/contract"
)
type verifier struct { Family contract.Family; Class string; Present, NilRefused bool }
func facts(m contract.CompatibilityManifest) map[string]any {
 v := make([]verifier, 0, len(m.Verifiers))
 for _, p := range m.Verifiers {
  refused := false
  if p.Parse != nil { _, err := p.Parse(nil); refused = err != nil }
  v = append(v, verifier{p.Family,p.Class,p.Parse != nil,refused})
 }
 return map[string]any{"Identity":hex.EncodeToString(m.Identity[:]),"Versions":[]string{m.Core,m.Engine,m.Format,m.ComponentContract,m.Crypto,m.CryptoProfile},"Components":m.Components,"Constructions":m.Constructions,"Verifiers":v,"Generators":len(m.Generators)}
}
func main() {
 m := full.CompatibilityManifest()
 before := facts(m)
 encoded, err := json.Marshal(before); if err != nil { panic(err) }
 for i := range m.Components { m.Components[i] = contract.ComponentImplementation{} }
 for i := range m.Constructions { m.Constructions[i] = contract.ConstructionClass{} }
 for i := range m.Verifiers { m.Verifiers[i] = contract.VerifierParser{} }
 after := facts(full.CompatibilityManifest())
 encodedAfter, err := json.Marshal(after); if err != nil { panic(err) }
 after["Fresh"] = reflect.DeepEqual(encoded, encodedAfter)
 if err := json.NewEncoder(os.Stdout).Encode(after); err != nil { panic(err) }
}
`

// full_only: false
func TestSelectedTrustCompositionsCompileOnlyTheirProvider(t *testing.T) {
	root := maintainedCloudflareRoot(t)
	for _, row := range []struct {
		module, ownProvider, siblingProvider, siblingComposition string
	}{
		{"compositions/aws", "enkv.sh/providers/aws", "enkv.sh/providers/gcp", "enkv.sh/compositions/gcp"},
		{"compositions/gcp", "enkv.sh/providers/gcp", "enkv.sh/providers/aws", "enkv.sh/compositions/aws"},
	} {
		t.Run(row.module, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			checked, err := checkModule(ctx, root, row.module)
			if err != nil {
				t.Fatal(err)
			}
			closure := checked.closure
			if closure.Suite != "unit" || closure.Provider != row.module || !slices.Contains(closure.CompiledImports, "enkv.sh/"+row.module) || !slices.Contains(closure.CompiledImports, row.ownProvider) {
				t.Fatal("maintained selected trust composition or its provider is absent")
			}
			for _, imported := range closure.CompiledImports {
				for _, excluded := range []string{row.siblingProvider, row.siblingComposition, "enkv.sh/compositions/full"} {
					if imported == excluded || strings.HasPrefix(imported, excluded+"/") {
						t.Fatal("another trust composition reached the selected production closure", imported)
					}
				}
			}
			t.Logf("module=%s selected_provider=%s compiled_imports=%d", row.module, row.ownProvider, len(closure.CompiledImports))
		})
	}
}

// full_only: false
func TestSelectedCLIAssembliesKeepExactProductionFamilies(t *testing.T) {
	root := maintainedCloudflareRoot(t)
	for _, row := range []struct {
		name, tag, provider, excludedProvider string
		excludedServices                      []string
	}{
		{"full", "", "", "", nil},
		{"aws", "enkv_aws", "aws", "gcp", []string{"google.golang.org/api/storage/v1", "google.golang.org/api/cloudkms/v1"}},
		{"gcp", "enkv_gcp", "gcp", "aws", []string{"github.com/aws/aws-sdk-go-v2/service/s3", "github.com/aws/aws-sdk-go-v2/service/kms"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(cacheOnlyGoContext(t.Context()), 2*time.Minute)
			defer cancel()
			flags := []string{"-mod=readonly"}
			if row.tag != "" {
				flags = append(flags, "-tags="+row.tag)
			}
			_, packages, err := listClosure(runGoEnvironment, ctx, root, "compositions/full", flags, false, "./cmd/enkv")
			if err != nil {
				t.Fatal(err)
			}
			imports := make(map[string]bool, len(packages))
			for _, pkg := range packages {
				if pkg.ForTest != "" {
					t.Fatal("test package entered the production CLI closure", pkg.ImportPath)
				}
				imports[pkg.ImportPath] = true
				for _, sources := range [][]string{pkg.GoFiles, pkg.CompiledGoFiles} {
					for _, source := range sources {
						name := filepath.Base(source)
						if strings.HasSuffix(name, "_test.go") || strings.HasPrefix(name, "zz_test_") || strings.HasPrefix(name, "nativeprocess_") {
							t.Fatal("test admission or observer source entered production CLI", pkg.ImportPath, name)
						}
					}
				}
				if pkg.ImportPath == "enkv.sh/compositions/full" {
					checkCLIAssemblySources(t, pkg, row.name)
				}
			}
			required := []string{"enkv.sh/compositions/full/cmd/enkv"}
			providers := []string{row.provider}
			if row.name == "full" {
				providers = []string{"aws", "gcp"}
			}
			for _, provider := range providers {
				required = append(required, "enkv.sh/compositions/"+provider, "enkv.sh/providers/"+provider, "enkv.sh/providers/"+provider+"/credentials")
				if provider == "gcp" {
					required = append(required, "enkv.sh/providers/gcp/internal/httptransport")
				}
			}
			for _, required := range required {
				if !imports[required] {
					t.Fatal("required production owner is absent", required)
				}
			}
			if row.name == "full" {
				return
			}
			for path := range imports {
				if strings.HasPrefix(path, "enkv.sh/providers/"+row.excludedProvider+"/") {
					t.Fatal("unreviewed sibling provider owner entered selected CLI", path)
				}
				if path == "enkv.sh/providers/"+row.excludedProvider || path == "enkv.sh/compositions/"+row.excludedProvider || strings.HasPrefix(path, "enkv.sh/compositions/"+row.excludedProvider+"/") {
					t.Fatal("sibling State provider entered selected CLI", path)
				}
				for _, service := range row.excludedServices {
					if path == service || strings.HasPrefix(path, service+"/") {
						t.Fatal("sibling Store/KMS service entered selected CLI", path)
					}
				}
			}
		})
	}
}

func checkCLIAssemblySources(t *testing.T, pkg compiledPackage, selection string) {
	t.Helper()
	want := []string{"assembly_full.go"}
	providers := []string{"aws", "gcp"}
	if selection != "full" {
		want = []string{"assembly_selected_" + selection + ".go"}
		providers = []string{selection}
	}
	for _, provider := range providers {
		for _, prefix := range []string{"configuration_provider_", "configuration_keys_", "configuration_keys_initialization_", "configuration_administration_"} {
			want = append(want, prefix+provider+".go")
		}
	}
	slices.Sort(want)
	compiled := pkg.CompiledGoFiles
	if len(compiled) == 0 && len(pkg.CgoFiles) == 0 && len(pkg.SwigFiles) == 0 && len(pkg.SwigCXXFiles) == 0 {
		compiled = pkg.GoFiles
	}
	for _, sources := range [][]string{pkg.GoFiles, compiled} {
		var selected []string
		for _, source := range sources {
			name := filepath.Base(source)
			if strings.HasPrefix(name, "assembly_") || strings.HasPrefix(name, "configuration_provider_") || strings.HasPrefix(name, "configuration_keys_initialization_") || name == "configuration_keys_aws.go" || name == "configuration_keys_gcp.go" || strings.HasPrefix(name, "configuration_administration_") {
				selected = append(selected, name)
			}
		}
		slices.Sort(selected)
		if !slices.Equal(selected, want) {
			t.Fatalf("selected assembly source set differs: got %v, want %v", selected, want)
		}
	}
}

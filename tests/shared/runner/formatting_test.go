package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

func writeLocalGoFixture(t *testing.T, root, name, body string) string {
	t.Helper()
	publicSourceFixtureOwners(t, root)
	path, err := sourcePath(root, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// full_only: false
func TestWholeSourceCustodyRejectsForbiddenEdgesInCoreAndOverlays(t *testing.T) {
	for _, fixture := range []struct {
		name, path string
		imports    []string
		allowed    bool
	}{
		{"shared native profiles", "tests/live/runner/publication_manifest_test.go", []string{"enkv.sh/plugins/outputs/github-actions/profile", "enkv.sh/plugins/generators/cloudflare-account-token/profile"}, true},
		{"AWS own profiles", "tests/live/providers/aws/publication_manifest_test.go", []string{"enkv.sh/plugins/outputs/aws-secrets-manager/profile", "enkv.sh/plugins/outputs/github-actions/profile"}, true},
		{"GCP own profiles", "tests/live/providers/gcp/publication_manifest_test.go", []string{"enkv.sh/plugins/outputs/gcp-secret-manager/profile", "enkv.sh/plugins/outputs/github-actions/profile"}, true},
		{"production", "core/publication_manifest.go", []string{"enkv.sh/plugins/outputs/github-actions/profile"}, false},
		{"hermetic", "tests/hermetic/publication_manifest_test.go", []string{"enkv.sh/plugins/outputs/github-actions/profile"}, false},
		{"different common source", "tests/live/runner/future_profile_test.go", []string{"enkv.sh/plugins/outputs/github-actions/profile"}, true},
		{"shared native source", "tests/live/shared/consumer_profile_test.go", []string{"enkv.sh/plugins/outputs/github-actions/profile"}, true},
		{"non-test native source", "tests/live/runner/profile.go", []string{"enkv.sh/plugins/outputs/github-actions/profile"}, false},
		{"ordinary runner source", "tests/shared/runner/profile_test.go", []string{"enkv.sh/plugins/outputs/github-actions/profile"}, false},
		{"Core unit source", "core/profile_test.go", []string{"enkv.sh/plugins/outputs/github-actions/profile"}, false},
		{"common AWS profile", "tests/live/runner/publication_manifest_test.go", []string{"enkv.sh/plugins/outputs/aws-secrets-manager/profile"}, false},
		{"common GCP profile", "tests/live/runner/publication_manifest_test.go", []string{"enkv.sh/plugins/outputs/gcp-secret-manager/profile"}, false},
		{"common GitHub effect", "tests/live/runner/publication_manifest_test.go", []string{"enkv.sh/plugins/outputs/github-actions"}, false},
		{"common Cloudflare effect", "tests/live/runner/publication_manifest_test.go", []string{"enkv.sh/plugins/generators/cloudflare-account-token"}, false},
		{"common nested profile", "tests/live/runner/publication_manifest_test.go", []string{"enkv.sh/plugins/outputs/github-actions/profile/child"}, false},
		{"common AWS provider", "tests/live/runner/publication_manifest_test.go", []string{"enkv.sh/providers/aws"}, false},
		{"common GCP provider", "tests/live/runner/publication_manifest_test.go", []string{"enkv.sh/providers/gcp"}, false},
		{"AWS sibling profile", "tests/live/providers/aws/publication_manifest_test.go", []string{"enkv.sh/plugins/outputs/gcp-secret-manager/profile"}, false},
		{"GCP sibling profile", "tests/live/providers/gcp/publication_manifest_test.go", []string{"enkv.sh/plugins/outputs/aws-secrets-manager/profile"}, false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			root := sourceFixtureRoot(t)
			body := "package core\n"
			for _, imported := range fixture.imports {
				body += "import _ \"" + imported + "\"\n"
			}
			writeLocalGoFixture(t, root, fixture.path, body)
			if err := checkCustodySources(t.Context(), root); (err == nil) != fixture.allowed {
				t.Fatalf("source custody admission differs for %s: %v", fixture.path, err)
			}
		})
	}
	for _, dependency := range []string{"github.com/aws/aws-sdk-go-v2/service/secretsmanager", "google.golang.org/api/secretmanager/v1"} {
		t.Run(dependency, func(t *testing.T) {
			root := sourceFixtureRoot(t)
			writeLocalGoFixture(t, root, "tests/live/runner/publication_manifest_test.go", "package core\nimport _ \""+dependency+"\"\n")
			if err := checkCustodySources(t.Context(), root); err == nil {
				t.Fatal("shared native fixture admitted a cloud-specific SDK")
			}
		})
	}
	for _, name := range []string{
		"core/rogue.go", "core/contract/rogue_test.go", "core/format/rogue_test.go",
		"tests/hermetic/rogue_test.go", "tests/shared/runner/rogue.go",
		"tests/workflows/rogue.go", "tests/workflows/runs-extra/rogue.go", "core/workflows/runs/rogue.go",
		"tests/work-evidences-extra/rogue.go", "core/work-evidences/rogue.go",
	} {
		root := sourceFixtureRoot(t)
		writeLocalGoFixture(t, root, "tests/workflows/runs/previous/snapshot/crypto/copied.go", "package crypto\nimport _ \""+modulePrefix+"crypto/internal/custody\"\n")
		writeLocalGoFixture(t, root, "tests/work-evidences/076/attempt/before.go", "package crypto\nimport _ \""+modulePrefix+"crypto/testsupport/custody\"\n")
		if err := checkCustodySources(t.Context(), root); err != nil {
			t.Fatalf("custody check inspected excluded workflow run data: %v", err)
		}
		writeLocalGoFixture(t, root, name, "package core\nimport _ \""+modulePrefix+"crypto/internal/custody\"\n")
		if err := checkCustodySources(t.Context(), root); err == nil {
			t.Fatalf("uncompiled custody edge admitted in %s", name)
		}
	}
}

// full_only: false
func TestWholeSourceCustodyKeepsNativeObserverHelperStandardOnly(t *testing.T) {
	for _, fixture := range []struct {
		name, path string
		imports    []string
		allowed    bool
	}{
		{"standard helper", "core/testsupport/nativeprocess/context.go", []string{"errors", "path/filepath", "strings", "encoding/json", "crypto/sha256", "os/exec", "net/http"}, true},
		{"helper Core dependency", "core/testsupport/nativeprocess/context.go", []string{modulePrefix + "core/contract"}, false},
		{"helper external dependency", "core/testsupport/nativeprocess/context.go", []string{"example.com/observer"}, false},
		{"helper dotless dependency", "core/testsupport/nativeprocess/context.go", []string{"localobserver/helper"}, false},
		{"helper dotless root dependency", "core/testsupport/nativeprocess/context.go", []string{"localobserver"}, false},
		{"production observer import", "core/observer.go", []string{modulePrefix + "core/testsupport/nativeprocess"}, false},
		{"nested helper is not exempt", "core/testsupport/nativeprocess/nested/context.go", []string{"errors"}, false},
		{"helper test dependencies", "core/testsupport/nativeprocess/context_test.go", []string{modulePrefix + "core/contract", modulePrefix + "crypto/testsupport/custody"}, true},
		{"Core test observer import", "core/observer_test.go", []string{modulePrefix + "core/testsupport/nativeprocess"}, true},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			root := sourceFixtureRoot(t)
			body := "package observer\n"
			for _, imported := range fixture.imports {
				body += "import _ \"" + imported + "\"\n"
			}
			writeLocalGoFixture(t, root, fixture.path, body)
			if err := checkCustodySources(t.Context(), root); (err == nil) != fixture.allowed {
				t.Fatalf("native observer source custody differs for %s: %v", fixture.path, err)
			}
		})
	}
	for _, owner := range []struct {
		name, path string
		allowed    bool
	}{
		{"composition protocol fixture", "compositions/full/testsupport/nativeprocess/server_test.go", true},
		{"Core test private key remains refused", "core/server_test.go", false},
	} {
		t.Run(owner.name, func(t *testing.T) {
			root := sourceFixtureRoot(t)
			writeLocalGoFixture(t, root, owner.path, "package fixture\nimport \"crypto/rsa\"\nvar _ = rsa.GenerateKey\n")
			if err := checkCustodySources(t.Context(), root); (err == nil) != owner.allowed {
				t.Fatalf("private fixture owner differs for %s: %v", owner.path, err)
			}
		})
	}
}

// full_only: false
func TestWholeSourceCustodyUsesExactAssemblySourceOwners(t *testing.T) {
	t.Run("compiled_runner_metadata_context", func(t *testing.T) {
		for _, imported := range []string{"enkv.sh/sdk/artifact", "enkv.sh/plugins/generators/cloudflare-account-token/profile"} {
			tool := compiledPackage{ImportPath: modulePrefix + "core/internal/testmain", Imports: []string{imported}}
			if err := checkCustodyImports([]compiledPackage{tool}, true, ""); err != nil {
				t.Fatal("ordinary runner metadata import refused", imported, err)
			}
			if checkCustodyImports([]compiledPackage{tool}, false, "") == nil {
				t.Fatal("production testmain acquired metadata import", imported)
			}
		}
		for _, fixture := range []struct {
			owner, forTest string
			allowed        bool
		}{
			{"core", modulePrefix + "core", true},
			{"core", "", false},
			{"core", modulePrefix + "core/contract", false},
			{"core/contract", "", true},
			{"core/internal/testrecords", "", true},
			{"core/internal/testrecords", modulePrefix + "core/internal/testrecords", true},
			{"core/internal/testrecords/nested", modulePrefix + "core/internal/testrecords/nested", false},
			{"core/internal/testmain/nested", modulePrefix + "core/internal/testmain/nested", false},
			{"core/internal/testcatalog", modulePrefix + "core/internal/testcatalog", false},
		} {
			other := compiledPackage{ImportPath: modulePrefix + fixture.owner, ForTest: fixture.forTest, Imports: []string{"enkv.sh/sdk/artifact"}}
			if err := checkCustodyImports([]compiledPackage{other}, true, ""); (err == nil) != fixture.allowed {
				t.Fatal("compiled artifact metadata owner differs", fixture.owner, fixture.forTest, err)
			}
		}
		for _, imported := range []string{"enkv.sh/sdk/artifact/build", "enkv.sh/plugins/generators/cloudflare-account-token", "enkv.sh/plugins/generators/cloudflare-account-token/internal/cloudflare", "enkv.sh/plugins/generators/cloudflare-account-token/cmd/enkv-generator-cloudflare", "enkv.sh/plugins/generators/cloudflare-account-token/profile/private"} {
			tool := compiledPackage{ImportPath: modulePrefix + "core/internal/testmain", Imports: []string{imported}}
			if checkCustodyImports([]compiledPackage{tool}, true, "") == nil {
				t.Fatal("runner metadata import expanded to an author tool or effect package", imported)
			}
		}
	})
	fullImports := []string{modulePrefix + "compositions/configuration", modulePrefix + "crypto/testsupport/installedarchive", modulePrefix + "providers/gcp"}
	publicImports := []string{modulePrefix + "compositions/aws", modulePrefix + "compositions/configuration", modulePrefix + "compositions/full", modulePrefix + "compositions/gcp", modulePrefix + "core", modulePrefix + "core/contract", modulePrefix + "core/testsupport/nativeprocess", modulePrefix + "crypto", modulePrefix + "providers/aws", modulePrefix + "providers/gcp", "enkv.sh/plugins/outputs/aws-secrets-manager/credential", "enkv.sh/plugins/outputs/gcp-secret-manager/credential", "enkv.sh/sdk/protocols/output"}
	for _, fixture := range []struct {
		name, path, pkg, body string
		imports               []string
		allowed               bool
	}{
		{"live sealed-box custody", "tests/live/custody/output_box.go", "custody", "var _ = box.GenerateKey\n", []string{"golang.org/x/crypto/nacl/box"}, true},
		{"unregistered custody sibling", "tests/live/custody/foreign.go", "custody", "var _ = box.GenerateKey\n", []string{"golang.org/x/crypto/nacl/box"}, false},
		{"live Core private box", "tests/live/runner/box_test.go", "core", "var _ = box.OpenAnonymous\n", []string{"golang.org/x/crypto/nacl/box"}, false},
		{"live Core metadata", "tests/live/runner/artifact_test.go", "core", "", []string{"enkv.sh/sdk/artifact"}, true},
		{"live Core author tool", "tests/live/runner/build_test.go", "core", "", []string{"enkv.sh/sdk/artifact/build"}, false},
		{"runner artifact metadata", "tests/shared/runner/artifact_build_facts.go", "main", "", []string{"enkv.sh/sdk/artifact"}, true},
		{"runner artifact metadata test", "tests/shared/runner/artifact_build_facts_test.go", "main", "", []string{"enkv.sh/sdk/artifact"}, true},
		{"runner generator semantics", "tests/shared/runner/cloudflare.go", "main", "", []string{"enkv.sh/plugins/generators/cloudflare-account-token/profile"}, true},
		{"Core production artifact metadata", "core/artifact.go", "core", "", []string{"enkv.sh/sdk/artifact"}, false},
		{"Core unit artifact metadata", "core/artifact_test.go", "core", "", []string{"enkv.sh/sdk/artifact"}, true},
		{"shared Core artifact metadata", "tests/shared/artifact_test.go", "core", "", []string{"enkv.sh/sdk/artifact"}, true},
		{"hermetic Core artifact metadata", "tests/hermetic/artifact_test.go", "core", "", []string{"enkv.sh/sdk/artifact"}, true},
		{"nested runner metadata", "tests/shared/runner/nested/artifact.go", "main", "", []string{"enkv.sh/sdk/artifact"}, false},
		{"runner-like sibling metadata", "tests/shared/runner-extra/artifact.go", "main", "", []string{"enkv.sh/sdk/artifact"}, false},
		{"records artifact metadata", "tests/shared/records/artifact.go", "records", "", []string{"enkv.sh/sdk/artifact"}, true},
		{"catalog artifact metadata", "tests/shared/catalog/artifact.go", "catalog", "", []string{"enkv.sh/sdk/artifact"}, false},
		{"Core contract artifact metadata", "core/contract/artifact.go", "contract", "", []string{"enkv.sh/sdk/artifact"}, true},
		{"records test artifact metadata", "tests/shared/records/artifact_test.go", "records", "", []string{"enkv.sh/sdk/artifact"}, true},
		{"catalog test artifact metadata", "tests/shared/catalog/artifact_test.go", "catalog", "", []string{"enkv.sh/sdk/artifact"}, false},
		{"catalog ordinary source has no test variant", "tests/shared/catalog/custody.go", "catalog", "", []string{modulePrefix + "crypto/testsupport/custody"}, false},
		{"nested runner test metadata", "tests/shared/runner/nested/artifact_test.go", "main", "", []string{"enkv.sh/sdk/artifact"}, false},
		{"runner-like sibling test metadata", "tests/shared/runner-extra/artifact_test.go", "main", "", []string{"enkv.sh/sdk/artifact"}, false},
		{"nested records metadata", "tests/shared/records/nested/artifact.go", "records", "", []string{"enkv.sh/sdk/artifact"}, false},
		{"nested records test metadata", "tests/shared/records/nested/artifact_test.go", "records", "", []string{"enkv.sh/sdk/artifact"}, false},
		{"shared non-test metadata", "tests/shared/artifact.go", "core", "", []string{"enkv.sh/sdk/artifact"}, false},
		{"unregistered shared metadata", "tests/shared/extra/artifact.go", "core", "", []string{"enkv.sh/sdk/artifact"}, false},
		{"unregistered shared test metadata", "tests/shared/extra/artifact_test.go", "core", "", []string{"enkv.sh/sdk/artifact"}, false},
		{"telemetry example command", "tests/examples/telemetry/main.go", "main", "", []string{modulePrefix + "core", modulePrefix + "compositions/observability", modulePrefix + "telemetry"}, true},
		{"telemetry example sibling is not the command", "tests/examples/telemetry/extra.go", "main", "", []string{modulePrefix + "compositions/observability"}, false},
		{"telemetry example private primitive", "tests/examples/telemetry/main.go", "main", "var _ = rsa.GenerateKey\n", []string{"crypto/rsa"}, false},
		{"production testmain metadata", "core/internal/testmain/artifact.go", "main", "", []string{"enkv.sh/sdk/artifact"}, false},
		{"runner artifact author tooling", "tests/shared/runner/artifact_tool.go", "main", "", []string{"enkv.sh/sdk/artifact/build"}, false},
		{"runner provider effect", "tests/shared/runner/provider.go", "main", "", []string{modulePrefix + "providers/aws"}, false},
		{"Core generator semantics", "core/generator_metadata.go", "core", "", []string{"enkv.sh/plugins/generators/cloudflare-account-token/profile"}, false},
		{"runner nested generator semantics", "tests/shared/runner/profile.go", "main", "", []string{"enkv.sh/plugins/generators/cloudflare-account-token/profile/private"}, false},
		{"runner private primitive", "tests/shared/runner/private_key.go", "main", "var _ = rsa.GenerateKey\n", []string{"crypto/rsa"}, false},
		{"Crypto admission", "tests/crypto/admission.go", "crypto", "var _ = rsa.GenerateKey\n", []string{"crypto/rsa", modulePrefix + "core/contract", modulePrefix + "crypto/internal/custody"}, true},
		{"GCP admission", "tests/gcp/admission.go", "gcp", "", []string{"cloud.google.com/go/auth"}, true},
		{"GCP credential admission", "tests/gcpcredentials/admission.go", "credentials", "", []string{"cloud.google.com/go/auth"}, true},
		{"unowned GCP credential sibling", "tests/gcpcredentials/foreign.go", "credentials", "", []string{modulePrefix + "providers/gcp/credentials"}, false},
		{"Full admission", "tests/full/admission.go", "compositionfull", "", fullImports, true},
		{"public process", "tests/live/publicprocess/main.go", "main", "", publicImports, true},
		{"public source parser", "tests/live/publicprocess/source_pair.go", "main", "", []string{modulePrefix + "compositions/configuration", modulePrefix + "core/testsupport/nativeprocess"}, true},
		{"public denied decrypt probe", "tests/live/publicprocess/recipient_denial.go", "main", "var _ = rsa.EncryptOAEP\n", append([]string{"crypto/rsa"}, publicImports...), true},
		{"live retained decoder", "tests/live/runner/retained_test.go", "core", "", []string{"enkv.sh/sdk/protocols/generator/retained"}, true},
		{"shared live retained decoder", "tests/live/shared/retained_test.go", "core", "", []string{"enkv.sh/sdk/protocols/generator/retained"}, true},
		{"production retained decoder", "core/retained.go", "core", "", []string{"enkv.sh/sdk/protocols/generator/retained"}, false},
		{"Core unit retained decoder", "core/retained_test.go", "core", "", []string{"enkv.sh/sdk/protocols/generator/retained"}, false},
		{"shared hermetic retained decoder", "tests/shared/retained_test.go", "core", "", []string{"enkv.sh/sdk/protocols/generator/retained"}, false},
		{"live non-test retained decoder", "tests/live/runner/retained.go", "core", "", []string{"enkv.sh/sdk/protocols/generator/retained"}, false},
		{"live nested retained decoder", "tests/live/runner/retained_test.go", "core", "", []string{"enkv.sh/sdk/protocols/generator/retained/private"}, false},
		{"live retired serving package", "tests/live/runner/retained_test.go", "core", "", []string{"enkv.sh/sdk/generator/retained"}, false},
		{"runner input owners", "tests/shared/runner/inputs.go", "main", "", []string{modulePrefix + "compositions/configuration", modulePrefix + "compositions/manifesthost", "enkv.sh/sdk/artifact", cloudflareModulePath + "/profile"}, true},
		{"runner test input owners", "tests/shared/runner/inputs_test.go", "main", "", []string{modulePrefix + "compositions/configuration", modulePrefix + "compositions/manifesthost", "enkv.sh/sdk/artifact", cloudflareModulePath + "/profile"}, true},
		{"runner nested owners", "tests/shared/runner/nested/inputs.go", "main", "", []string{modulePrefix + "compositions/configuration"}, false},
		{"runner records remain passive", "tests/shared/records/inputs.go", "records", "", []string{modulePrefix + "compositions/configuration"}, false},
		{"runner catalog remains passive", "tests/shared/catalog/inputs.go", "catalog", "", []string{modulePrefix + "compositions/manifesthost"}, false},
		{"runner host descendant", "tests/shared/runner/inputs.go", "main", "", []string{modulePrefix + "compositions/manifesthost/internal"}, false},
		{"runner artifact descendant", "tests/shared/runner/inputs.go", "main", "", []string{"enkv.sh/sdk/artifact/build"}, false},
		{"runner effect composition", "tests/shared/runner/inputs.go", "main", "", []string{modulePrefix + "compositions/full"}, false},
		{"Core unit runner profile", "core/runner_profile_test.go", "core", "", []string{cloudflareModulePath + "/profile"}, false},
		{"records runner profile", "tests/shared/records/profile.go", "records", "", []string{cloudflareModulePath + "/profile"}, false},
		{"catalog runner profile", "tests/shared/catalog/profile.go", "catalog", "", []string{cloudflareModulePath + "/profile"}, false},
		{"nested runner profile", "tests/shared/runner/nested/profile.go", "main", "", []string{cloudflareModulePath + "/profile"}, false},
		{"runner profile descendant", "tests/shared/runner/profile.go", "main", "", []string{cloudflareModulePath + "/profile/internal"}, false},
		{"runner private key custody", "tests/shared/runner/inputs.go", "main", "var _ = rsa.GenerateKey\n", []string{"crypto/rsa"}, false},
		{"Core test foreign imports", "core/foreign_test.go", "core", "", fullImports, false},
		{"Core overlay foreign imports", "tests/shared/foreign_test.go", "core", "", fullImports, false},
		{"unowned Full sibling", "tests/full/foreign.go", "compositionfull", "", fullImports, false},
		{"unowned nested admission", "tests/full/nested/admission.go", "compositionfull", "", fullImports, false},
		{"unowned GCP sibling", "tests/gcp/foreign.go", "gcp", "", []string{modulePrefix + "providers/gcp"}, false},
		{"unowned Crypto sibling", "tests/crypto/foreign.go", "crypto", "", []string{modulePrefix + "crypto/internal/custody"}, false},
		{"public helper fixture dependency", "tests/live/publicprocess/fixture.go", "main", "", []string{modulePrefix + "crypto/testsupport/installedarchive"}, false},
		{"public helper fixture root", "tests/live/publicprocess/fixture.go", "main", "", []string{modulePrefix + "crypto/testsupport"}, false},
		{"public helper internal root", "tests/live/publicprocess/fixture.go", "main", "", []string{modulePrefix + "core/internal"}, false},
		{"public helper private primitive", "tests/live/publicprocess/private.go", "main", "var _ = rsa.GenerateKey\n", []string{"crypto/rsa"}, false},
		{"Core test private primitive", "core/private_test.go", "core", "var _ = rsa.GenerateKey\n", []string{"crypto/rsa"}, false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			root := sourceFixtureRoot(t)
			body := "package " + fixture.pkg + "\n"
			for _, imported := range fixture.imports {
				name := "_"
				if imported == "crypto/rsa" && fixture.body != "" {
					name = "rsa"
				}
				body += "import " + name + " \"" + imported + "\"\n"
			}
			writeLocalGoFixture(t, root, fixture.path, body+fixture.body)
			if err := checkCustodySources(t.Context(), root); (err == nil) != fixture.allowed {
				t.Fatalf("source owner differs for %s: %v", fixture.path, err)
			}
		})
	}
}

// full_only: false
func TestFormattingCommandsDiscoverTheSameMaintainedFiles(t *testing.T) {
	for _, owner := range []struct{ name, directory string }{
		{"checkout-dependencies", "tests/fixtures/consumer"},
		{"sibling-dependencies", "protocols/generator"},
	} {
		t.Run(owner.name, func(t *testing.T) {
			root := sourceFixtureRoot(t)
			maintained := owner.directory + "/node_modules-extra/new.go"
			before := "package sample\nfunc f( ){println(\"ready\")}\n"
			path := writeLocalGoFixture(t, root, maintained, before)
			dependency := writeLocalGoFixture(t, root, owner.directory+"/node_modules/installed/invalid.go", "this is not Go source\n")
			outside := filepath.Join(t.TempDir(), "outside.go")
			if err := os.WriteFile(outside, []byte(before), 0600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(filepath.Dir(filepath.Dir(dependency)), ".bin", "dotenv")
			if err := os.MkdirAll(filepath.Dir(link), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, link); err != nil {
				t.Fatal(err)
			}
			files, err := maintainedGoFiles(root)
			if err != nil || !slices.Equal(files, []string{maintained}) {
				t.Fatalf("installed dependencies changed maintained source: got %v, error: %v", files, err)
			}
			var checked bytes.Buffer
			if err := runCommand(t.Context(), root, "", []string{"fmt-check"}, &checked); err == nil || checked.String() != path+"\n" {
				t.Fatalf("fmt-check did not select adjacent maintained source: %q, %v", checked.String(), err)
			}
			if err := runCommand(t.Context(), root, "", []string{"fmt"}, io.Discard); err != nil {
				t.Fatal(err)
			}
			if body, err := os.ReadFile(path); err != nil || string(body) != "package sample\n\nfunc f() { println(\"ready\") }\n" {
				t.Fatal("fmt did not format adjacent maintained source", err)
			}
			if err := runCommand(t.Context(), root, "", []string{"fmt-check"}, io.Discard); err != nil {
				t.Fatal(err)
			}
			if body, err := os.ReadFile(dependency); err != nil || string(body) != "this is not Go source\n" {
				t.Fatal("formatting changed installed dependency bytes", err)
			}
			if body, err := os.ReadFile(outside); err != nil || string(body) != before {
				t.Fatal("formatting changed the dependency link target", err)
			}
			if target, err := os.Readlink(link); err != nil || target != outside {
				t.Fatal("formatting changed the dependency link", err)
			}
		})
	}
	root := sourceFixtureRoot(t)
	// No Git index exists. New files, tests, and ordinary directories with names
	// that also occur in generated trees are all maintained source.
	maintained := []string{
		"new.go", "-name.go", "core/core.go", "core/core_test.go", "telemetry/new.go", "telemetry/new_test.go", "providers/aws/new.go",
		"providers/gcp/new_test.go", "compositions/full/new.go",
		"tests/shared/fixture_test.go", "tests/shared/runner/new.go",
		"tests/shared/records/new_test.go", "tests/shared/catalog/new.go",
		"protocols/generator/new_test.go", "plugins/cloudflare/profile/new.go",
		"sdk/output/run.go", "sdk/manifest-generator/view.go", "plugins/manifest-generators/generic-json/encode.go", "sdk/examples/local-value-output/main.go", "sdk/examples/ini-reference-manifest/main.go",
		"sdk/manifest-generator/jsonwriter/writer.go", "plugins/manifest-generators/opentofu-tfvars-json/encode.go", "sdk/examples/ini-reference-manifest/consumer/read.go",
		"sdk/examples/testservice/service.go", "sdk/generator/run.go", "sdk/examples/local-token-generator/main.go", "protocols/output/new.go",
		"plugins/aws-output/new.go", "plugins/gcp-output/new.go", "plugins/github-output/new.go", "plugins/output-contract-test/new.go",
		"tests/hermetic/new_test.go", "tests/live/shared/new_test.go",
		"tests/live/runner/new_test.go", "tests/live/providers/aws/new_test.go",
		"tests/live/providers/gcp/new_test.go", "tests/scripts/bootstrap.go",
		"tests/examples/telemetry/main.go", "core/reports/new.go",
		"core/runs/new.go", "core/private/new.go", "core/build/new.go",
		"tests/workflows/new.go", "tests/workflows/runs-extra/new.go", "core/workflows/runs/new.go",
		"tests/work-evidences-extra/new.go", "core/work-evidences/new.go",
		"directory with spaces/new source.go",
	}
	excluded := []string{
		"tests/.supervisor/setup.fixture/core/internal/supervisor/copied.go",
		"tests/hermetic/runs/run/private/input.go", "tests/hermetic/reports/run/report.go",
		"tests/live/runs/run/private/input.go", "tests/live/reports/run/report.go",
		"tests/workflows/runs/run/snapshot/crypto/copied.go",
		"tests/qualification/2000-01-01/old/source.go",
		"tests/work-evidences/076/attempt/before.go", "tests/work-evidences/078/attempt/after.go",
		"tests/work-evidences/future/snapshot/source.go",
		"vendor/external.go", "core/vendor/external.go", ".git/objects/source.go",
		"build/generated.go", "dist/generated.go",
	}
	before := "package sample\nfunc f( ){println(\"ready\")}\n"
	after := "package sample\n\nfunc f() { println(\"ready\") }\n"
	for _, name := range maintained {
		writeLocalGoFixture(t, root, name, before)
	}
	for _, name := range excluded {
		writeLocalGoFixture(t, root, name, "this is not Go source\n")
	}
	slices.Sort(maintained)
	discovered, err := maintainedGoFiles(root)
	slices.Sort(discovered)
	if err != nil || !slices.Equal(discovered, maintained) {
		t.Fatalf("maintained source differs: got %v, want %v; error: %v", discovered, maintained, err)
	}
	var checked bytes.Buffer
	if runCommand(context.Background(), root, "", []string{"fmt-check"}, &checked) == nil {
		t.Fatal("unformatted maintained files passed fmt-check")
	}
	physicalPaths := make(map[string]string, len(maintained))
	expectedOutput := make([]string, 0, len(maintained))
	for _, name := range maintained {
		physical := filepath.Join(root, name)
		for _, public := range []struct{ selector, directory string }{
			{"protocols/generator", "sdk/protocols/generator"},
			{"plugins/cloudflare", "plugins/generators/cloudflare-account-token"},
			{"protocols/output", "sdk/protocols/output"},
			{"sdk/output", "sdk/output"},
			{"sdk/manifest-generator", "sdk/manifest-generator"},
			{"plugins/manifest-generators/generic-json", "plugins/manifest-generators/generic-json"},
			{"plugins/manifest-generators/opentofu-tfvars-json", "plugins/manifest-generators/opentofu-tfvars-json"},
			{"sdk/examples/local-value-output", "sdk/examples/local-value-output"},
			{"sdk/examples/ini-reference-manifest", "sdk/examples/ini-reference-manifest"},
			{"sdk/examples/testservice", "sdk/examples/testservice"},
			{"sdk/generator", "sdk/generator"},
			{"sdk/examples/local-token-generator", "sdk/examples/local-token-generator"},
			{"plugins/aws-output", "plugins/outputs/aws-secrets-manager"},
			{"plugins/gcp-output", "plugins/outputs/gcp-secret-manager"},
			{"plugins/github-output", "plugins/outputs/github-actions"},
		} {
			if relative, found := strings.CutPrefix(name, public.selector+"/"); found {
				physical = filepath.Join(filepath.Dir(root), "enkv-extensions", public.directory, relative)
			}
		}
		if relative, found := strings.CutPrefix(name, "plugins/output-contract-test/"); found {
			physical = filepath.Join(root, "tests/fixtures/output-contract-test", relative)
		}
		physicalPaths[name] = physical
		expectedOutput = append(expectedOutput, physical)
		body, err := os.ReadFile(physical)
		if err != nil || string(body) != before {
			t.Fatalf("fmt-check rewrote %s", name)
		}
	}
	actualOutput := strings.Split(strings.TrimSuffix(checked.String(), "\n"), "\n")
	slices.Sort(actualOutput)
	slices.Sort(expectedOutput)
	if !slices.Equal(actualOutput, expectedOutput) {
		t.Fatalf("fmt-check physical source output differs: got %v, want %v", actualOutput, expectedOutput)
	}
	var rewritten bytes.Buffer
	if err := runCommand(context.Background(), root, "", []string{"fmt"}, &rewritten); err != nil {
		t.Fatal(err)
	}
	if checked.String() != rewritten.String() {
		t.Fatal("fmt and fmt-check discovered different changed files")
	}
	for _, name := range maintained {
		path := physicalPaths[name]
		body, err := os.ReadFile(path)
		info, statErr := os.Stat(path)
		if err != nil || string(body) != after || statErr != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("fmt did not format %s or changed its permissions", name)
		}
	}
	for _, name := range excluded {
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || string(body) != "this is not Go source\n" {
			t.Fatalf("fmt changed excluded file %s", name)
		}
	}
	var clean bytes.Buffer
	if err := runCommand(context.Background(), root, "", []string{"fmt-check"}, &clean); err != nil || clean.Len() != 0 {
		t.Fatalf("formatted files did not pass silently: %v", err)
	}
}

// full_only: false
func TestFormattingCommandsPropagateSyntaxAndFilesystemErrors(t *testing.T) {
	for _, command := range []string{"fmt-check", "fmt"} {
		t.Run(command, func(t *testing.T) {
			for _, kind := range []string{"malformed", "missing_root", "file_root", "outside_file", "outside_directory", "dangling_link", "checkout_dependency_link", "sibling_dependency_link"} {
				t.Run(kind, func(t *testing.T) {
					root := sourceFixtureRoot(t)
					outside := writeLocalGoFixture(t, t.TempDir(), "outside.go", "package external\nfunc f( ){}\n")
					before, err := os.ReadFile(outside)
					if err != nil {
						t.Fatal(err)
					}
					switch kind {
					case "malformed":
						writeLocalGoFixture(t, root, "invalid.go", "package sample\nfunc broken(\n")
					case "missing_root":
						root = filepath.Join(root, "missing")
					case "file_root":
						root = writeLocalGoFixture(t, root, "file.go", "package sample\n")
					case "outside_file", "outside_directory", "dangling_link":
						target := outside
						if kind == "outside_directory" {
							target = filepath.Dir(outside)
						} else if kind == "dangling_link" {
							target += ".missing"
						}
						if err := os.Symlink(target, filepath.Join(root, "linked.go")); err != nil {
							t.Fatal(err)
						}
					case "checkout_dependency_link", "sibling_dependency_link":
						publicSourceFixtureOwners(t, root)
						link := filepath.Join(root, "node_modules")
						if kind == "sibling_dependency_link" {
							link, err = sourcePath(root, "protocols/generator/node_modules")
							if err != nil {
								t.Fatal(err)
							}
						}
						if err := os.Symlink(filepath.Dir(outside), link); err != nil {
							t.Fatal(err)
						}
					}
					if runCommand(context.Background(), root, "", []string{command}, io.Discard) == nil {
						t.Fatal("formatting command concealed a source error")
					}
					after, err := os.ReadFile(outside)
					if err != nil || !bytes.Equal(before, after) {
						t.Fatal("formatting command changed an outside file")
					}
				})
			}
		})
	}
}

// full_only: false
func TestLintPreservesFormattingFailureWithoutRewriting(t *testing.T) {
	root := sourceFixtureRoot(t)
	body := "package sample\nfunc f( ){}\n"
	path := writeLocalGoFixture(t, root, "untracked.go", body)
	var output bytes.Buffer
	err := runCommand(context.Background(), root, "missing-overlay", []string{"lint"}, &output)
	if err == nil || !strings.Contains(output.String(), "untracked.go") || !strings.Contains(err.Error(), "Go formatting differs") {
		t.Fatalf("lint lost its format check failure: %v", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || string(got) != body {
		t.Fatal("lint rewrote source")
	}
}

// full_only: false
func TestFormattingCancellationStopsDescendantsBeforeReturning(t *testing.T) {
	root := sourceFixtureRoot(t)
	writeLocalGoFixture(t, root, "source.go", "package sample\n")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	race, err := binaryRace(executable)
	if err != nil {
		t.Fatal("executing test binary race policy unavailable", err)
	}
	directory := t.TempDir()
	launcher := "#!/bin/sh\nexec " + shellQuote(executable) + " -test.run=^TestProcessHelper$ -test.parallel=1 -test.timeout=30s\n"
	if err := os.WriteFile(filepath.Join(directory, "gofmt"), []byte(launcher), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ENKV_PROCESS_HELPER", "captured_interrupted")
	t.Setenv("ENKV_PROCESS_FIXTURE", directory)
	ctx, cancel := context.WithCancel(withRacePolicy(t.Context(), race))
	done := make(chan error, 1)
	var writer, child processIdentity
	finished, settled := false, false
	t.Cleanup(func() {
		cancel()
		if settled {
			return
		}
		for _, identity := range []processIdentity{child, writer} {
			if identity.start == 0 {
				continue
			}
			actual, err := nativeProcessIdentity(identity.pid)
			if errors.Is(err, syscall.ESRCH) || err == nil && actual.identity != identity {
				continue
			}
			if err != nil {
				t.Error("formatting fixture cleanup identity unavailable", identity, err)
				continue
			}
			if err := syscall.Kill(identity.pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
				t.Error("formatting fixture cleanup failed", identity, err)
			}
		}
		if !finished {
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Error("formatting did not return after fixture cleanup")
			}
		}
	})
	go func() { done <- runFormatting(ctx, root, false, io.Discard) }()
	ready, stop := context.WithTimeout(t.Context(), 10*time.Second)
	defer stop()
	writerPID := waitProcessMarker(t, ready, filepath.Join(directory, "writer.pid"))
	writerInfo, err := nativeProcessIdentity(writerPID)
	if err != nil || writerInfo.identity.start == 0 {
		t.Fatal("formatting writer identity unavailable", writerInfo, err)
	}
	writer = writerInfo.identity
	childPID := waitProcessMarker(t, ready, filepath.Join(directory, "child.pid"))
	childInfo, err := nativeProcessIdentity(childPID)
	if err != nil || childInfo.identity.start == 0 {
		t.Fatal("formatting descendant identity unavailable", childInfo, err)
	}
	child = childInfo.identity
	if childInfo.parent != writer.pid || childInfo.group != writerInfo.group {
		t.Fatal("formatting descendant is outside its writer ownership", childInfo, writerInfo)
	}
	select {
	case err := <-done:
		finished = true
		t.Fatal("formatting returned before cancellation", err)
	default:
	}
	cancel()
	select {
	case err = <-done:
		finished = true
	case <-time.After(8 * time.Second):
		t.Fatal("formatting did not cancel and join within its settlement allowance")
	}
	var failure *toolFailure
	if !errors.As(err, &failure) || failure.operation != "gofmt" || !errors.Is(err, context.Canceled) ||
		failure.process.Status != "interrupted" || !failure.process.Started || !failure.process.Joined {
		t.Fatal("formatting lost its canceled physical result", err)
	}
	settled = true
	for _, identity := range []processIdentity{writer, child} {
		actual, err := nativeProcessIdentity(identity.pid)
		if err == nil && actual.identity != identity {
			continue
		}
		if !errors.Is(err, syscall.ESRCH) {
			settled = false
			t.Error("formatting returned before descendant settlement", identity, err)
		}
	}
}

func publicSourceFixtureOwners(t *testing.T, root string) {
	t.Helper()
	for _, source := range moduleSources {
		if source.Sibling == "" {
			continue
		}
		owner, err := moduleSourceDirectory(root, source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(owner, 0700); err != nil {
			t.Fatal(err)
		}
	}
}

// full_only: false
func TestMaintainedSourcesRequireRegisteredPublicOwners(t *testing.T) {
	root := sourceFixtureRoot(t)
	writeLocalGoFixture(t, root, "protocols/generator/wire.go", "package generator\n")
	if _, err := maintainedGoFiles(root); err != nil {
		t.Fatal(err)
	}
	protocol, err := sourcePath(root, "protocols/generator")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(protocol, protocol+"-missing"); err != nil {
		t.Fatal(err)
	}
	if _, err := maintainedGoFiles(root); err == nil {
		t.Fatal("missing public source owner omitted from maintained inventory")
	}
	if err := os.Rename(protocol+"-missing", protocol); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(root, "protocols/generator/wire.go")
	if err := os.MkdirAll(filepath.Dir(stale), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("package stale\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := maintainedGoFiles(root); err == nil {
		t.Fatal("retired same-name physical source omitted from maintained inventory")
	}
}

func sourceFixtureRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "implementation")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

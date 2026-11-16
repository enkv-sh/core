package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

const nativeProcessPath = modulePrefix + "compositions/internal/nativeprocess"

var neutralModules = map[string]string{
	"go.opentelemetry.io/otel":            "v1.36.0",
	"go.opentelemetry.io/otel/metric":     "v1.36.0",
	"go.opentelemetry.io/otel/trace":      "v1.36.0",
	"go.opentelemetry.io/otel/sdk":        "v1.36.0",
	"go.opentelemetry.io/otel/sdk/metric": "v1.36.0",
	"go.opentelemetry.io/auto/sdk":        "v1.1.0",
	"github.com/go-logr/logr":             "v1.4.2",
	"github.com/go-logr/stdr":             "v1.2.2",
	"github.com/google/uuid":              "v1.6.0",
	"github.com/google/go-cmp":            "v0.7.0",
	"github.com/kr/text":                  "v0.2.0",
	"github.com/kr/pretty":                "v0.3.1",
	"github.com/rogpeppe/go-internal":     "v1.13.1",
	"gopkg.in/check.v1":                   "v1.0.0-20201130134442-10cb98267c6c",
	"github.com/stretchr/testify":         "v1.10.0",
	"go.uber.org/goleak":                  "v1.3.0",
	"github.com/davecgh/go-spew":          "v1.1.1",
	"github.com/pmezard/go-difflib":       "v1.0.0",
	"golang.org/x/sys":                    "v0.33.0",
	"gopkg.in/yaml.v3":                    "v3.0.1",
}

// Only the setup composition may admit this exact exporter and generated-wire
// closure. These modules are not added to neutral production components.
var observabilityModules = map[string]string{
	"cel.dev/expr":                         "v0.23.0",
	"cloud.google.com/go/compute/metadata": "v0.6.0",
	"github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp": "v1.27.0",
	"github.com/antihax/optional":                                       "v1.0.0",
	"github.com/cenkalti/backoff/v5":                                    "v5.0.2",
	"github.com/cespare/xxhash/v2":                                      "v2.3.0",
	"github.com/cncf/xds/go":                                            "v0.0.0-20250326154945-ae57f3c0d45f",
	"github.com/envoyproxy/go-control-plane":                            "v0.13.4",
	"github.com/envoyproxy/go-control-plane/envoy":                      "v1.32.4",
	"github.com/envoyproxy/go-control-plane/ratelimit":                  "v0.1.0",
	"github.com/envoyproxy/protoc-gen-validate":                         "v1.2.1",
	"github.com/go-jose/go-jose/v4":                                     "v4.0.5",
	"github.com/golang/glog":                                            "v1.2.4",
	"github.com/golang/protobuf":                                        "v1.5.4",
	"github.com/grpc-ecosystem/grpc-gateway/v2":                         "v2.27.1",
	"github.com/planetscale/vtprotobuf":                                 "v0.6.1-0.20240319094008-0393e58bdf10",
	"github.com/rogpeppe/fastuuid":                                      "v1.2.0",
	"github.com/spiffe/go-spiffe/v2":                                    "v2.5.0",
	"github.com/zeebo/errs":                                             "v1.4.0",
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp":       "v0.12.1",
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp": "v1.36.0",
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace":                 "v1.36.0",
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp":   "v1.36.0",
	"go.opentelemetry.io/otel/log":                                      "v0.12.1",
	"go.opentelemetry.io/otel/sdk/log":                                  "v0.12.1",
	"go.opentelemetry.io/otel/sdk/log/logtest":                          "v0.0.0-20250521073539-a85ae98dcedc",
	"go.opentelemetry.io/contrib/detectors/gcp":                         "v1.35.0",
	"go.opentelemetry.io/proto/otlp":                                    "v1.6.0",
	"golang.org/x/net":                                                  "v0.40.0",
	"golang.org/x/crypto":                                               "v0.38.0",
	"golang.org/x/mod":                                                  "v0.25.0",
	"golang.org/x/oauth2":                                               "v0.30.0",
	"golang.org/x/sync":                                                 "v0.15.0",
	"golang.org/x/term":                                                 "v0.32.0",
	"golang.org/x/text":                                                 "v0.26.0",
	"golang.org/x/tools":                                                "v0.33.0",
	"golang.org/x/xerrors":                                              "v0.0.0-20191204190536-9bdfabe68543",
	"google.golang.org/genproto/googleapis/api":                         "v0.0.0-20250603155806-513f23925822",
	"google.golang.org/genproto/googleapis/rpc":                         "v0.0.0-20250603155806-513f23925822",
	"google.golang.org/grpc":                                            "v1.73.0",
	"google.golang.org/protobuf":                                        "v1.36.6",
}

type resolvedModule struct {
	Main      bool
	Path      string
	Version   string
	Sum       string
	GoVersion string
	Dir       string
	Replace   *resolvedModule
}

type compiledPackage struct {
	ImportPath      string
	Dir             string
	Export          string
	ImportMap       map[string]string
	Standard        bool
	ForTest         string
	GoFiles         []string
	TestGoFiles     []string
	XTestGoFiles    []string
	CompiledGoFiles []string
	CgoFiles        []string
	CFiles          []string
	CXXFiles        []string
	MFiles          []string
	HFiles          []string
	FFiles          []string
	SFiles          []string
	SwigFiles       []string
	SwigCXXFiles    []string
	SysoFiles       []string
	EmbedFiles      []string
	Imports         []string
}

func checkBoundary(directory string, modules []resolvedModule, packages []compiledPackage) error {
	if err := checkSDKBoundaries(directory, modules, packages); err != nil {
		return err
	}
	if err := checkGeneratorServingBoundary(directory, modules, packages); err != nil {
		return err
	}
	source, known := registeredModule(directory)
	if !known || directory != source.Selector {
		return errors.New("unknown module root")
	}
	if main, _, _ := authorModuleDependencies(directory); main != "" {
		return checkAuthorModule(directory, modules, packages)
	}
	for _, module := range modules {
		if strings.HasPrefix(module.Path, modulePrefix) {
			owner, known := registeredModule(module.Path)
			if !known || owner.Module != module.Path {
				return errors.New("first-party module is not registered")
			}
		}
	}
	for _, pkg := range packages {
		if strings.HasPrefix(pkg.ImportPath, modulePrefix) && !slices.ContainsFunc(moduleSources, func(owner moduleSource) bool { return withinModule(pkg.ImportPath, owner.Module) }) {
			return errors.New("first-party package is not registered")
		}
	}
	if err := checkNeutralPins(modules); err != nil {
		return err
	}
	if directory == "compositions/observability" {
		return checkObservabilityBoundary(modules, packages)
	}
	if err := checkTelemetryImports(packages); err != nil {
		return err
	}
	if err := checkCustodyImports(packages, false, ""); err != nil {
		return err
	}
	for _, p := range packages {
		if !withinModule(p.ImportPath, modulePrefix+"core") || p.Dir == "" {
			continue
		}
		for _, name := range p.GoFiles {
			if err := checkCoreCustodyFile(filepath.Join(p.Dir, name)); err != nil {
				return err
			}
		}
	}
	owned := 0
	for _, module := range modules {
		if module.Path == source.Module {
			owned++
		}
		cryptoProcessModule := directory == "crypto" && (module.Path == modulePrefix+"core" || module.Path == modulePrefix+"compositions/generatorhost" || module.Path == "enkv.sh/sdk/protocols/generator" || module.Path == modulePrefix+"compositions/outputhost" || module.Path == nativeProcessPath || module.Path == "enkv.sh/sdk/protocols/output" || module.Path == "enkv.sh/plugins/generators/cloudflare-account-token" || module.Path == "enkv.sh/plugins/generators/local-random-secret" || module.Path == generatorSDKPath)
		publicSourceModule := (directory == "core" || directory == "crypto") && (module.Path == manifestSDKPath || module.Path == "enkv.sh/sdk/protocols/manifest-generator" || module.Path == genericJSONPath || module.Path == openTofuJSONPath || module.Path == "enkv.sh/sdk/artifact" || module.Path == "enkv.sh/sdk/protocols/generator" || module.Path == "enkv.sh/sdk/protocols/output")
		if (directory == "core" || directory == "telemetry" || directory == "crypto") && module.Path != source.Module && module.Path != modulePrefix+"telemetry" && !publicSourceModule && !(directory == "crypto" && module.Path == outputSDKPath) && !cryptoProcessModule && neutralModules[module.Path] == "" {
			return errors.New("neutral component has an unreviewed dependency")
		}
		if wrongProvider(directory, module.Path) {
			return errors.New("sibling provider reached resolved modules")
		}
	}
	if owned != 1 {
		return errors.New("resolved module root differs")
	}
	for _, p := range packages {
		if (directory == "core" || directory == "telemetry" || directory == "crypto" || strings.HasPrefix(directory, "providers/")) && withinModule(p.ImportPath, "go.opentelemetry.io/otel/sdk") {
			return errors.New("SDK reached production component")
		}
		if directory == "telemetry" && !p.Standard && !withinModule(p.ImportPath, modulePrefix+"telemetry") && !telemetryAPIClosure(p.ImportPath) {
			return errors.New("telemetry imports an unreviewed package")
		}
		if directory == "core" && !p.Standard && !withinModule(p.ImportPath, modulePrefix+"core") && !withinModule(p.ImportPath, modulePrefix+"telemetry") && p.ImportPath != manifestSDKPath && p.ImportPath != "enkv.sh/sdk/artifact" && p.ImportPath != "enkv.sh/sdk/artifact/credentialroute" && p.ImportPath != "enkv.sh/sdk/protocols/generator" && p.ImportPath != "enkv.sh/sdk/protocols/output" && !neutral(p.ImportPath) {
			return errors.New("Core imports an unreviewed package")
		}
		if directory == "crypto" && !p.Standard && !withinModule(p.ImportPath, modulePrefix+"crypto") && !cryptoPublicDependency(p.ImportPath) {
			return errors.New("Crypto imports an unreviewed package")
		}
		if wrongProvider(directory, p.ImportPath) {
			return errors.New("sibling provider reached compiled imports")
		}
	}
	if strings.HasPrefix(directory, "compositions/") {
		if directory == "compositions/internal/nativeprocess" {
			return checkNativeProcessLeaf(modules, packages)
		}
		if directory == "compositions/generatorhost" {
			return checkGeneratorHost(packages)
		}
		if directory == "compositions/outputhost" {
			return checkOutputHost(modules, packages)
		}
		if directory == "compositions/manifesthost" {
			return checkManifestHost(modules, packages)
		}
		if directory == "compositions/configuration" {
			return checkConfiguration(packages)
		}
		return checkComposition(directory, modules, packages)
	}
	if directory == "plugins/cloudflare" {
		return checkCloudflarePlugin(modules, packages)
	}
	if directory == "plugins/output-contract-test" {
		return checkOutputContractTestPlugin(modules, packages)
	}
	if directory == "plugins/github-output" {
		return checkGitHubOutputPlugin(modules, packages)
	}
	if directory == "plugins/aws-output" {
		return checkOutputPluginModules("plugins/aws-output", modules, packages, awsOutputPins,
			"github.com/aws/aws-sdk-go-v2/aws", "github.com/aws/aws-sdk-go-v2/aws/signer/v4", "github.com/aws/aws-sdk-go-v2/config", "github.com/aws/aws-sdk-go-v2/credentials/endpointcreds", "github.com/aws/aws-sdk-go-v2/aws/retry", "github.com/aws/aws-sdk-go-v2/aws/transport/http", "github.com/aws/smithy-go/logging", "github.com/aws/smithy-go/middleware", "github.com/aws/smithy-go/transport/http")
	}
	if directory == "plugins/gcp-output" {
		return checkOutputPluginModules("plugins/gcp-output", modules, packages, gcpOutputPins,
			"google.golang.org/api/secretmanager/v1", "google.golang.org/api/option", "google.golang.org/api/googleapi", "cloud.google.com/go/auth", "cloud.google.com/go/auth/credentials")
	}
	return nil
}

func cryptoPublicDependency(path string) bool {
	return path == modulePrefix+"core/contract" || path == modulePrefix+"core/format" || path == manifestSDKPath || path == "enkv.sh/sdk/artifact" || path == "enkv.sh/sdk/artifact/credentialroute" || path == modulePrefix+"compositions/generatorhost" ||
		path == "enkv.sh/sdk/protocols/generator" || path == "enkv.sh/sdk/protocols/generator/retained" || path == modulePrefix+"compositions/outputhost" || path == nativeProcessPath || path == "enkv.sh/sdk/protocols/output" || withinModule(path, modulePrefix+"telemetry") || neutral(path)
}

func cryptoFacade(path string) bool {
	return path == modulePrefix+"crypto/testsupport/trust" || path == modulePrefix+"crypto/testsupport/custody" || path == modulePrefix+"crypto/testsupport/installedarchive"
}

func privateKeyAPI(path, name string) bool {
	switch path {
	case "crypto":
		return name == "PrivateKey" || name == "Signer" || name == "Decrypter"
	case "crypto/rsa", "crypto/ecdsa", "crypto/ed25519", "crypto/dsa", "crypto/ecdh":
		return strings.Contains(name, "PrivateKey") || strings.HasPrefix(name, "Generate") || strings.HasPrefix(name, "Sign") || strings.HasPrefix(name, "Decrypt") || name == "NewKeyFromSeed" || name == "PrecomputedValues" || name == "CRTValue"
	case "golang.org/x/crypto/nacl/box":
		return name == "GenerateKey" || name == "Precompute" || name == "Seal" || name == "SealAfterPrecomputation" || name == "Open" || name == "OpenAfterPrecomputation" || name == "OpenAnonymous"
	case "crypto/x509":
		return strings.Contains(name, "PrivateKey") || name == "DecryptPEMBlock" || name == "EncryptPEMBlock" || name == "CreateCertificate" || name == "CreateCertificateRequest" || name == "CreateRevocationList"
	}
	if withinModule(path, "github.com/aws/aws-sdk-go-v2/service/kms") {
		return slices.Contains([]string{"Sign", "SignInput", "SignOutput", "Decrypt", "DecryptInput", "DecryptOutput", "GenerateDataKey", "GenerateDataKeyInput", "GenerateDataKeyOutput", "GenerateDataKeyPair", "GenerateDataKeyPairInput", "GenerateDataKeyPairOutput"}, name)
	}
	if withinModule(path, "google.golang.org/api/cloudkms") || withinModule(path, "cloud.google.com/go/kms") {
		return strings.Contains(name, "AsymmetricSign") || strings.Contains(name, "AsymmetricDecrypt") || strings.Contains(name, "RawDecrypt") || name == "Decrypt" || name == "DecryptRequest" || name == "DecryptResponse"
	}
	return false
}

// Export data comes from the same Go invocation and module flags as the graph.
// Type resolution catches method values and calls such as Curve.GenerateKey or
// a KMS client's Decrypt, even when no private-key type is spelled in the file.
func checkCompiledCustody(packages []compiledPackage) error {
	exports := make(map[string]string, len(packages))
	for _, p := range packages {
		exports[p.ImportPath] = p.Export
	}
	for _, p := range packages {
		owner, _, _ := strings.Cut(p.ImportPath, " [")
		if !withinModule(owner, modulePrefix+"core") && !cryptoFacade(owner) || p.Dir == "" {
			continue
		}
		sources := p.CompiledGoFiles
		// Go's cached generated test-main filename can lack a .go suffix,
		// leaving CompiledGoFiles empty. Without cgo/SWIG transformation,
		// the selected GoFiles are already the exact compiler source set.
		if len(sources) == 0 && len(p.CgoFiles) == 0 && len(p.SwigFiles) == 0 && len(p.SwigCXXFiles) == 0 {
			sources = p.GoFiles
		}
		if len(sources) == 0 {
			return fmt.Errorf("custody compiled sources unavailable for %s", owner)
		}
		fset := token.NewFileSet()
		var files []*ast.File
		for _, path := range sources {
			if !filepath.IsAbs(path) {
				path = filepath.Join(p.Dir, path)
			}
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return fmt.Errorf("custody type source unavailable: %w", err)
			}
			files = append(files, file)
		}
		config := types.Config{Importer: importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
			if mapped := p.ImportMap[path]; mapped != "" {
				path = mapped
			}
			return os.Open(exports[path])
		})}
		info := types.Info{Uses: make(map[*ast.Ident]types.Object)}
		checked, err := config.Check(owner, fset, files, &info)
		if err != nil {
			return fmt.Errorf("custody type resolution failed for %s: %w", owner, err)
		}
		if cryptoFacade(owner) {
			if err := checkFacadeSurface(checked); err != nil {
				return err
			}
			continue
		}
		for identifier, object := range info.Uses {
			if object.Pkg() != nil && privateKeyAPI(object.Pkg().Path(), object.Name()) {
				return fmt.Errorf("Core private-key custody refused at %s: %s.%s", fset.Position(identifier.Pos()), object.Pkg().Path(), object.Name())
			}
		}
	}
	return nil
}

func checkFacadeSurface(p *types.Package) error {
	type inspection struct {
		value    types.Type
		metadata bool
	}
	seen := make(map[inspection]bool)
	var inspect func(types.Type, bool) error
	inspect = func(value types.Type, metadata bool) error {
		key := inspection{value, metadata}
		if seen[key] {
			return nil
		}
		seen[key] = true
		switch value := value.(type) {
		case *types.Alias:
			return inspect(types.Unalias(value), metadata)
		case *types.Named:
			object := value.Obj()
			if object.Pkg() == nil && object.Name() == "error" {
				if metadata {
					return errors.New("test custody facade exposes a metadata interface")
				}
				return nil
			}
			if object.Pkg() != nil {
				path := object.Pkg().Path()
				if privateKeyAPI(path, object.Name()) || path == "io" || path == "os" || withinModule(path, modulePrefix+"crypto") && !cryptoFacade(path) {
					return fmt.Errorf("test custody facade exposes private type %s", object)
				}
				outputMetadata := facadeOutputMetadata(path, object.Name())
				if metadata && !outputMetadata {
					return fmt.Errorf("test custody facade exposes unreviewed metadata type %s", object)
				}
				if outputMetadata {
					for i := 0; i < value.NumMethods(); i++ {
						method := value.Method(i)
						if !method.Exported() {
							continue
						}
						signature := method.Type().(*types.Signature)
						for _, tuple := range []*types.Tuple{signature.Params(), signature.Results()} {
							for j := 0; j < tuple.Len(); j++ {
								if err := inspect(tuple.At(j).Type(), true); err != nil {
									return err
								}
							}
						}
					}
					return inspect(value.Underlying(), true)
				}
				if path != p.Path() {
					public := path == modulePrefix+"core/contract" || path == modulePrefix+"core/format" || cryptoFacade(path)
					standard := path == "context" && object.Name() == "Context" || path == "testing" && (object.Name() == "T" || object.Name() == "TB") || path == "time" && (object.Name() == "Time" || object.Name() == "Duration")
					publicKey := (path == "crypto/rsa" || path == "crypto/ecdsa" || path == "crypto/ed25519" || path == "crypto/ecdh") && object.Name() == "PublicKey"
					// The trust fixture owns its TLS server key. Its public HTTP
					// handler and client transport do not carry private KMS data.
					publicHTTP := p.Path() == modulePrefix+"crypto/testsupport/trust" && path == "net/http" && (object.Name() == "Handler" || object.Name() == "Transport")
					if !public && !standard && !publicKey && !publicHTTP {
						return fmt.Errorf("test custody facade exposes unreviewed type %s", object)
					}
					return nil
				}
			}
			for i := 0; i < value.NumMethods(); i++ {
				if value.Method(i).Exported() {
					if err := inspect(value.Method(i).Type(), metadata); err != nil {
						return err
					}
				}
			}
			return inspect(value.Underlying(), metadata)
		case *types.Pointer:
			if metadata {
				return errors.New("test custody facade exposes a metadata pointer")
			}
			return inspect(value.Elem(), metadata)
		case *types.Slice:
			if metadata {
				return errors.New("test custody facade exposes a metadata slice")
			}
			return inspect(value.Elem(), metadata)
		case *types.Array:
			return inspect(value.Elem(), metadata)
		case *types.Map:
			return errors.New("test custody facade exposes a map")
		case *types.Chan:
			return errors.New("test custody facade exposes a channel")
		case *types.Signature:
			if metadata {
				return errors.New("test custody facade exposes a metadata callback")
			}
			for _, tuple := range []*types.Tuple{value.Params(), value.Results()} {
				for i := 0; i < tuple.Len(); i++ {
					if _, callback := tuple.At(i).Type().Underlying().(*types.Signature); callback {
						return errors.New("test custody facade exposes a callback")
					}
					if err := inspect(tuple.At(i).Type(), metadata); err != nil {
						return err
					}
				}
			}
		case *types.Struct:
			for i := 0; i < value.NumFields(); i++ {
				if value.Field(i).Exported() {
					if err := inspect(value.Field(i).Type(), metadata); err != nil {
						return err
					}
				}
			}
		case *types.Basic:
			if metadata && value.Info()&(types.IsBoolean|types.IsInteger|types.IsString) == 0 {
				return errors.New("test custody facade exposes unreviewed metadata")
			}
		case *types.Interface:
			return errors.New("test custody facade exposes an unreviewed interface")
		}
		return nil
	}
	for _, name := range p.Scope().Names() {
		object := p.Scope().Lookup(name)
		if object.Exported() {
			if err := inspect(object.Type(), false); err != nil {
				return err
			}
		}
	}
	return nil
}

func facadeOutputMetadata(path, name string) bool {
	switch path {
	case modulePrefix + "compositions/outputhost":
		return name == "Artifact"
	case "enkv.sh/sdk/protocols/output":
		return name == "ActionCheckResult" || name == "PayloadBounds" || name == "ID"
	}
	return false
}

// Resolve package selectors through each file's imports, including renamed and
// dot imports. Local names with the same spelling are not imported symbols.
func checkCoreCustodyFile(path string) error {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return fmt.Errorf("Core custody source unavailable: %w", err)
	}
	imports := map[string]string{}
	var dotImports []string
	for _, spec := range file.Imports {
		imported, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return err
		}
		name := filepath.Base(imported)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name == "." {
			dotImports = append(dotImports, imported)
		} else {
			imports[name] = imported
		}
	}
	var refused string
	ast.Inspect(file, func(node ast.Node) bool {
		if refused != "" {
			return false
		}
		switch node := node.(type) {
		case *ast.SelectorExpr:
			if qualifier, ok := node.X.(*ast.Ident); ok && qualifier.Obj == nil && privateKeyAPI(imports[qualifier.Name], node.Sel.Name) {
				refused = imports[qualifier.Name] + "." + node.Sel.Name
			}
		case *ast.Ident:
			if node.Obj == nil {
				for _, imported := range dotImports {
					if privateKeyAPI(imported, node.Name) {
						refused = imported + "." + node.Name
					}
				}
			}
		}
		return true
	})
	if refused != "" {
		return fmt.Errorf("Core private-key custody refused in %s: %s", path, refused)
	}
	return nil
}

// Inspect direct edges owned by each package. A reviewed test facade may use
// private Crypto dependencies without making those dependencies Core-owned.
func checkCustodyImports(packages []compiledPackage, tests bool, provider string) error {
	if tests && (provider == "aws" || provider == "gcp") {
		if err := checkLiveManifestConsumerImports(packages); err != nil {
			return err
		}
	}
	standard := resolvedStandardPackages(packages)
	for _, p := range packages {
		owner, _, _ := strings.Cut(p.ImportPath, " [")
		nativeObserver := modulePrefix + "core/testsupport/nativeprocess"
		testTool := owner == modulePrefix+"core/internal/testrecords" || owner == modulePrefix+"core/internal/testmain"
		testOwner := tests && (p.ForTest != "" || strings.HasSuffix(owner, "_test") || testTool || owner == nativeObserver+".test")
		if withinModule(owner, nativeObserver) && !tests {
			return errors.New("native process observer reached production compilation")
		}
		if !tests && withinModule(owner, modulePrefix+"crypto/testsupport") {
			return errors.New("test custody facade reached production compilation")
		}
		for _, imported := range p.Imports {
			imported, _, _ = strings.Cut(imported, " [")
			if withinModule(owner, nativeObserver) && !testOwner && !standard[imported] {
				return errors.New("native process observer imports a nonstandard dependency")
			}
			if withinModule(imported, nativeObserver) && !testOwner {
				return errors.New("production package imports native process observer")
			}
			if !tests && withinModule(imported, modulePrefix+"crypto/testsupport") {
				return errors.New("production package imports a test custody facade")
			}
			if withinModule(owner, modulePrefix+"core") {
				generatorHost := testOwner && imported == modulePrefix+"compositions/generatorhost"
				outputHost := testOwner && imported == modulePrefix+"compositions/outputhost"
				observability := testOwner && imported == modulePrefix+"compositions/observability"
				runnerInput := tests && owner == modulePrefix+"core/internal/testmain" && (imported == modulePrefix+"compositions/configuration" || imported == modulePrefix+"compositions/manifesthost" || imported == "enkv.sh/sdk/artifact" || imported == cloudflareModulePath+"/profile")
				artifactMetadata := imported == "enkv.sh/sdk/artifact" && (owner == modulePrefix+"core/contract" || tests && owner == modulePrefix+"core" && p.ForTest == modulePrefix+"core" || tests && owner == modulePrefix+"core/internal/testrecords")
				telemetryWire := testOwner && telemetryWireDecoder(imported)
				generatorWire := (testOwner || owner == modulePrefix+"core" || owner == modulePrefix+"core/contract") && imported == "enkv.sh/sdk/protocols/generator"
				retainedGenerator := testOwner && (provider == "aws" || provider == "gcp") && imported == "enkv.sh/sdk/protocols/generator/retained"
				outputWire := (testOwner || owner == modulePrefix+"core" || owner == modulePrefix+"core/contract") && imported == "enkv.sh/sdk/protocols/output"
				passiveProfile := testOwner && livePassiveProfile(provider, imported)
				outputCredential := testOwner && liveOutputCredential(provider, imported)
				manifestConsumer := tests && owner == modulePrefix+"core" && p.ForTest == modulePrefix+"core" && (provider == "aws" || provider == "gcp") && imported == liveManifestConsumerPath
				if withinModule(imported, modulePrefix+"crypto") && !(testOwner && cryptoFacade(imported)) {
					return errors.New("Core imports Crypto outside the reviewed test facades")
				}
				if withinModule(imported, modulePrefix+"providers") && !(testOwner && provider != "" && imported == modulePrefix+"providers/"+provider) ||
					withinModule(imported, modulePrefix+"compositions") && !generatorHost && !outputHost && !observability && !runnerInput {
					return errors.New("Core imports a provider or composition outside the selected live fixture")
				}
				if owner == modulePrefix+"core/contract" && withinModule(imported, modulePrefix+"core/format") {
					return errors.New("contract imports format")
				}
				local := imported == manifestSDKPath || imported == "enkv.sh/sdk/artifact/credentialroute" || testOwner && (imported == genericJSONPath || imported == openTofuJSONPath) || withinModule(imported, modulePrefix+"core") || withinModule(imported, modulePrefix+"telemetry") || testOwner && cryptoFacade(imported) || generatorHost || outputHost || observability || generatorWire || retainedGenerator || outputWire || passiveProfile || outputCredential || runnerInput || artifactMetadata || manifestConsumer
				selectedFixture := testOwner && (provider == "aws" && aws(imported) || provider == "gcp" && google(imported))
				if strings.Contains(imported, ".") && !local && !neutral(imported) && !selectedFixture && !telemetryWire {
					return errors.New("Core directly imports an unreviewed dependency")
				}
			}
			cryptoTestSetup := tests && p.ForTest != "" && imported == modulePrefix+"compositions/observability"
			if withinModule(owner, modulePrefix+"crypto") && !withinModule(owner, modulePrefix+"crypto/testsupport") && strings.HasPrefix(imported, modulePrefix) && !withinModule(imported, modulePrefix+"crypto") && !cryptoPublicDependency(imported) && !cryptoTestSetup {
				return errors.New("Crypto imports a private component")
			}
			if withinModule(owner, modulePrefix+"crypto") && (aws(imported) || google(imported)) {
				return errors.New("Crypto imports a provider dependency")
			}
		}
	}
	return nil
}

// Privacy tests decode actual exporter payloads. This permits only the wire
// messages and decoders, not exporter construction or a provider SDK.
func telemetryWireDecoder(path string) bool {
	switch path {
	case "go.opentelemetry.io/proto/otlp/collector/logs/v1",
		"go.opentelemetry.io/proto/otlp/collector/metrics/v1",
		"go.opentelemetry.io/proto/otlp/collector/trace/v1",
		"google.golang.org/protobuf/encoding/protojson",
		"google.golang.org/protobuf/proto":
		return true
	default:
		return false
	}
}

func telemetryAPIClosure(path string) bool {
	for _, collection := range []string{"go.opentelemetry.io/otel/sdk", "go.opentelemetry.io/otel/exporters", "go.opentelemetry.io/otel/log"} {
		if withinModule(path, collection) {
			return false
		}
	}
	for _, module := range []string{"go.opentelemetry.io/otel", "go.opentelemetry.io/auto/sdk", "github.com/go-logr/logr", "github.com/go-logr/stdr"} {
		if withinModule(path, module) {
			return true
		}
	}
	return false
}

func checkTelemetryImports(packages []compiledPackage) error {
	standard := make(map[string]bool)
	for _, p := range packages {
		standard[p.ImportPath] = p.Standard
	}
	for _, p := range packages {
		if !withinModule(p.ImportPath, modulePrefix+"telemetry") || p.ForTest != "" {
			continue
		}
		for _, imported := range p.Imports {
			if !standard[imported] && !withinModule(imported, modulePrefix+"telemetry") && imported != "go.opentelemetry.io/otel" && imported != "go.opentelemetry.io/otel/attribute" && imported != "go.opentelemetry.io/otel/metric" && imported != "go.opentelemetry.io/otel/trace" {
				return errors.New("telemetry directly imports a non-API dependency")
			}
		}
	}
	return nil
}

func livePassiveProfile(provider, path string) bool {
	return (provider == "aws" || provider == "gcp") && (path == modulePath("plugins/"+provider+"-output")+"/profile" ||
		path == "enkv.sh/plugins/outputs/github-actions/profile" || path == "enkv.sh/plugins/generators/cloudflare-account-token/profile" || path == "enkv.sh/plugins/generators/local-random-secret/profile")
}

func resolvedStandardPackages(packages []compiledPackage) map[string]bool {
	standard := make(map[string]bool, len(packages))
	for _, p := range packages {
		if p.Standard {
			standard[p.ImportPath] = true
		}
	}
	return standard
}

func checkLiveBoundary(provider string, modules []resolvedModule, packages []compiledPackage) error {
	if err := checkSDKBoundaries("live", modules, packages); err != nil {
		return err
	}
	if err := checkGeneratorServingBoundary("live", modules, packages); err != nil {
		return err
	}
	standard := resolvedStandardPackages(packages)
	if provider != "aws" && provider != "gcp" {
		return errors.New("unknown live provider")
	}
	if err := checkNeutralPins(modules); err != nil {
		return err
	}
	if err := checkObservabilityPins(modules); err != nil {
		return err
	}
	if err := checkCustodyImports(packages, true, provider); err != nil {
		return err
	}
	passiveModules := []string{modulePath("plugins/" + provider + "-output"), "enkv.sh/plugins/outputs/github-actions", "enkv.sh/plugins/generators/cloudflare-account-token", "enkv.sh/plugins/generators/local-random-secret"}
	for _, module := range modules {
		if withinModule(module.Path, nativeProcessPath) && module.Path != nativeProcessPath {
			return errors.New("unreviewed native process module reached live assembly")
		}
		if withinModule(module.Path, modulePrefix+"plugins") && module.Path != genericJSONPath && module.Path != openTofuJSONPath && (!slices.Contains(passiveModules, module.Path) || module.Version != "v0.1.0") {
			return errors.New("passive profile module identity differs from live provider")
		}
		if (withinModule(module.Path, modulePrefix+"compositions/outputhost") && module.Path != modulePrefix+"compositions/outputhost") ||
			(withinModule(module.Path, "enkv.sh/sdk/protocols/output") && module.Path != "enkv.sh/sdk/protocols/output") {
			return errors.New("unreviewed output module reached live assembly")
		}
		if wrongProvider("providers/"+provider, module.Path) && !observabilityModule(module.Path) {
			return errors.New("sibling provider reached live resolved modules")
		}
	}
	present := false
	for _, p := range packages {
		if err := checkOutputCredentialImports(p, standard); err != nil {
			return err
		}
		if withinModule(p.ImportPath, modulePrefix+"plugins") && p.ImportPath != genericJSONPath && p.ImportPath != openTofuJSONPath && p.ImportPath != "enkv.sh/plugins/generators/cloudflare-account-token/artifact" && !livePassiveProfile(provider, p.ImportPath) && !liveOutputCredential(provider, p.ImportPath) {
			return errors.New("unreviewed plugin package reached live assembly")
		}
		if withinModule(p.ImportPath, "enkv.sh/sdk/protocols/output") && p.ImportPath != "enkv.sh/sdk/protocols/output" {
			return errors.New("unreviewed output wire package reached live assembly")
		}
		if withinModule(p.ImportPath, "enkv.sh/sdk/protocols/manifest-generator") && p.ImportPath != "enkv.sh/sdk/protocols/manifest-generator" {
			return errors.New("unreviewed manifest wire package reached live assembly")
		}
		if p.ImportPath == modulePrefix+"providers/"+provider {
			present = true
		}
		if wrongProvider("providers/"+provider, p.ImportPath) && !observabilityDependency(p.ImportPath) {
			return errors.New("sibling provider reached live compiled imports")
		}
		if strings.Contains(p.ImportPath, "/compositions/") && p.ImportPath != modulePrefix+"compositions/generatorhost" && p.ImportPath != modulePrefix+"compositions/outputhost" && p.ImportPath != nativeProcessPath && p.ImportPath != modulePrefix+"compositions/observability" {
			return errors.New("composition reached private Core test assembly")
		}
	}
	if !present {
		return errors.New("selected provider missing from live test assembly")
	}
	return nil
}

func checkNeutralPins(modules []resolvedModule) error {
	for _, module := range modules {
		version, known := neutralModules[module.Path]
		if observabilityDependency(module.Path) && !observabilityModule(module.Path) && !known {
			return errors.New("unreviewed observability dependency module")
		}
		if neutral(module.Path) && !known && !observabilityModule(module.Path) {
			return errors.New("unreviewed module borrowed neutral package prefix")
		}
		if known && (module.Version != version || module.Replace != nil) {
			return errors.New("neutral dependency pin or replacement differs")
		}
	}
	return nil
}

func observabilityModule(path string) bool {
	_, known := observabilityModules[path]
	return known
}

func observabilityDependency(path string) bool {
	for module := range observabilityModules {
		if withinModule(path, module) {
			return true
		}
	}
	return false
}

func checkObservabilityPins(modules []resolvedModule) error {
	for _, module := range modules {
		if version, known := observabilityModules[module.Path]; known && (module.Version != version || module.Replace != nil) {
			return errors.New("observability dependency pin or replacement differs")
		}
	}
	return nil
}

func checkObservabilityBoundary(modules []resolvedModule, packages []compiledPackage) error {
	if err := checkObservabilityPins(modules); err != nil {
		return err
	}
	owned := 0
	for _, module := range modules {
		if module.Path == modulePrefix+"compositions/observability" {
			owned++
			continue
		}
		if module.Path != modulePrefix+"telemetry" && neutralModules[module.Path] == "" && !observabilityModule(module.Path) {
			return errors.New("observability setup has an unreviewed module")
		}
	}
	if owned != 1 {
		return errors.New("observability setup identity differs")
	}
	for _, p := range packages {
		if !p.Standard && !withinModule(p.ImportPath, modulePrefix+"compositions/observability") && !withinModule(p.ImportPath, modulePrefix+"telemetry") && !neutral(p.ImportPath) && !observabilityDependency(p.ImportPath) {
			return errors.New("observability setup has an unreviewed import")
		}
	}
	return nil
}

func withinModule(path, module string) bool {
	return path == module || strings.HasPrefix(path, module+"/")
}

func neutral(path string) bool {
	if observabilityDependency(path) {
		return false
	}
	for module := range neutralModules {
		if withinModule(path, module) {
			return true
		}
	}
	return false
}

func google(path string) bool {
	if neutral(path) {
		return false
	}
	for _, prefix := range []string{"google.golang.org/", "cloud.google.com/", "github.com/google/", "github.com/googleapis/", "golang.org/x/oauth2", "go.opentelemetry.io/"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return strings.Contains(path, "/providers/gcp") || strings.Contains(path, "/compositions/gcp")
}

func aws(path string) bool {
	return strings.HasPrefix(path, "github.com/aws/") || strings.Contains(path, "/providers/aws") || strings.Contains(path, "/compositions/aws")
}

func wrongProvider(directory, path string) bool {
	return strings.HasSuffix(directory, "/aws") && google(path) || strings.HasSuffix(directory, "/gcp") && aws(path)
}

func checkNativeProcessLeaf(modules []resolvedModule, packages []compiledPackage) error {
	seen := make(map[string]bool, len(modules))
	for _, module := range modules {
		if seen[module.Path] {
			return errors.New("native process module duplicated")
		}
		seen[module.Path] = true
		switch module.Path {
		case nativeProcessPath:
			if module.Version != "" || module.Replace != nil {
				return errors.New("native process main identity differs")
			}
		case "golang.org/x/sys":
			if module.Version != "v0.33.0" || module.Replace != nil {
				return errors.New("native process system dependency differs")
			}
		default:
			return errors.New("native process has an unreviewed module dependency")
		}
	}
	if !seen[nativeProcessPath] || !seen["golang.org/x/sys"] {
		return errors.New("native process required module missing")
	}
	for _, pkg := range packages {
		if !pkg.Standard && pkg.ImportPath != nativeProcessPath && pkg.ImportPath != "golang.org/x/sys/unix" {
			return errors.New("native process imports an unreviewed package")
		}
	}
	return nil
}

func checkComposition(directory string, modules []resolvedModule, packages []compiledPackage) error {
	for _, name := range []string{"core", "crypto", "telemetry"} {
		count := 0
		for _, module := range modules {
			if module.Path == modulePrefix+name {
				if module.Version != "v0.1.0" {
					return errors.New("neutral component version differs")
				}
				count++
			}
		}
		if count != 1 {
			return errors.New("neutral component identity differs")
		}
	}
	for _, name := range []string{"core", "core/contract", "core/format", "crypto", "telemetry"} {
		if !slices.ContainsFunc(packages, func(p compiledPackage) bool { return p.ImportPath == modulePrefix+name }) {
			return errors.New("neutral component missing")
		}
	}
	for _, p := range packages {
		if withinModule(p.ImportPath, "enkv.sh/plugins") {
			return errors.New("concrete plugin reached trust composition imports")
		}
		if p.ForTest != "" || slices.ContainsFunc(p.GoFiles, func(name string) bool { return strings.HasSuffix(name, "_test.go") }) {
			return errors.New("test fixture reached production compilation")
		}
	}
	return nil
}

func checkOutputContractTestPlugin(modules []resolvedModule, packages []compiledPackage) error {
	protocols, sdk, artifacts := 0, 0, 0
	for _, module := range modules {
		switch module.Path {
		case "enkv.sh/tests/fixtures/output-contract-test":
		case "enkv.sh/sdk/artifact":
			if module.Version != "v0.1.0" || module.Replace == nil || module.Replace.Path != "../../../../enkv-extensions/sdk/artifact" || module.Replace.Version != "" || module.Replace.Replace != nil {
				return errors.New("output test plugin artifact identity differs")
			}
			artifacts++
		case outputSDKPath:
			if module.Version != "v0.1.0" || module.Replace == nil || module.Replace.Path != "../../../../enkv-extensions/sdk/output" || module.Replace.Version != "" || module.Replace.Replace != nil {
				return errors.New("output test plugin SDK identity differs")
			}
			sdk++
		case "enkv.sh/sdk/protocols/output":
			if module.Version != "v0.1.0" || module.Replace == nil || module.Replace.Path != "../../../../enkv-extensions/sdk/protocols/output" || module.Replace.Version != "" {
				return errors.New("output test plugin protocol identity differs")
			}
			protocols++
		default:
			return errors.New("output test plugin has an unreviewed module dependency")
		}
	}
	if protocols != 1 || sdk != 1 || artifacts != 1 {
		return errors.New("output test plugin protocol or SDK dependency missing")
	}
	for _, p := range packages {
		if p.Standard || withinModule(p.ImportPath, "enkv.sh/tests/fixtures/output-contract-test") || p.ImportPath == outputSDKPath || p.ImportPath == "enkv.sh/sdk/artifact" || p.ImportPath == "enkv.sh/sdk/artifact/credentialroute" || withinModule(p.ImportPath, "enkv.sh/sdk/protocols/output") {
			continue
		}
		return errors.New("output test plugin imports an unreviewed package")
	}
	return nil
}

func checkGitHubOutputPlugin(modules []resolvedModule, packages []compiledPackage) error {
	return checkOutputPluginModules("plugins/github-output", modules, packages, githubOutputPins, "golang.org/x/crypto/nacl/box")
}

func checkOutputHost(modules []resolvedModule, packages []compiledPackage) error {
	for _, module := range modules {
		switch module.Path {
		case modulePrefix + "compositions/outputhost":
		case nativeProcessPath:
			if module.Version != "v0.1.0" || module.Replace == nil || module.Replace.Path != "../internal/nativeprocess" || module.Replace.Version != "" || module.Replace.Replace != nil {
				return errors.New("output host native process identity differs")
			}
		case "enkv.sh/sdk/artifact":
			if module.Version != "v0.1.0" || module.Replace == nil || module.Replace.Path != "../../../enkv-extensions/sdk/artifact" || module.Replace.Version != "" || module.Replace.Replace != nil {
				return errors.New("output host artifact identity differs")
			}
		case "enkv.sh/sdk/protocols/output":
			if module.Version != "v0.1.0" || module.Replace == nil || module.Replace.Path != "../../../enkv-extensions/sdk/protocols/output" || module.Replace.Version != "" {
				return errors.New("output host protocol identity differs")
			}
		case modulePrefix + "telemetry":
			if module.Version != "v0.1.0" || module.Replace == nil || module.Replace.Path != "../../telemetry" || module.Replace.Version != "" {
				return errors.New("output host telemetry identity differs")
			}
		case "golang.org/x/sys":
			if module.Version != "v0.33.0" {
				return errors.New("output host system dependency differs")
			}
		default:
			if neutralModules[module.Path] == "" {
				return errors.New("output host has an unreviewed module dependency")
			}
		}
	}
	for _, p := range packages {
		if withinModule(p.ImportPath, "go.opentelemetry.io/otel/sdk") || withinModule(p.ImportPath, "go.opentelemetry.io/auto/sdk") {
			return errors.New("telemetry SDK reached output host")
		}
		if p.Standard || withinModule(p.ImportPath, modulePrefix+"compositions/outputhost") || p.ImportPath == nativeProcessPath || p.ImportPath == "enkv.sh/sdk/protocols/output" || p.ImportPath == "enkv.sh/sdk/artifact" || p.ImportPath == "enkv.sh/sdk/artifact/credentialroute" ||
			withinModule(p.ImportPath, modulePrefix+"telemetry") || telemetryAPIClosure(p.ImportPath) || p.ImportPath == "golang.org/x/sys/unix" {
			continue
		}
		return errors.New("output host imports an unreviewed package")
	}
	return nil
}

func checkCloudflarePlugin(modules []resolvedModule, packages []compiledPackage) error {
	protocols, helpers, artifacts := 0, 0, 0
	for _, module := range modules {
		switch module.Path {
		case "enkv.sh/plugins/generators/cloudflare-account-token":
		case "enkv.sh/sdk/artifact":
			if module.Version != "v0.1.0" || module.Replace == nil || module.Replace.Path != "../../../sdk/artifact" || module.Replace.Version != "" {
				return errors.New("Cloudflare artifact dependency identity differs")
			}
			artifacts++
		case generatorSDKPath:
			if module.Version != "v0.1.0" || module.Replace == nil || module.Replace.Path != "../../../sdk/generator" || module.Replace.Version != "" {
				return errors.New("Cloudflare SDK dependency identity differs")
			}
			helpers++
		case "enkv.sh/sdk/protocols/generator":
			if module.Version != "v0.1.0" || module.Replace == nil || module.Replace.Path != "../../../sdk/protocols/generator" || module.Replace.Version != "" {
				return errors.New("Cloudflare protocol dependency identity differs")
			}
			protocols++
		default:
			return errors.New("Cloudflare plugin has an unreviewed module dependency")
		}
	}
	if protocols != 1 || helpers != 1 || artifacts != 1 {
		return errors.New("Cloudflare protocol dependency identity differs")
	}
	for _, p := range packages {
		if p.Standard || withinModule(p.ImportPath, "enkv.sh/plugins/generators/cloudflare-account-token") || withinModule(p.ImportPath, "enkv.sh/sdk/protocols/generator") || withinModule(p.ImportPath, generatorSDKPath) || p.ImportPath == "enkv.sh/sdk/artifact" || p.ImportPath == "enkv.sh/sdk/artifact/credentialroute" {
			continue
		}
		return errors.New("Cloudflare plugin imports an unreviewed package")
	}
	return nil
}

func checkGeneratorHost(packages []compiledPackage) error {
	for _, p := range packages {
		if p.Standard || withinModule(p.ImportPath, modulePrefix+"compositions/generatorhost") || p.ImportPath == modulePrefix+"core/contract" || p.ImportPath == manifestSDKPath || p.ImportPath == modulePrefix+"telemetry" ||
			p.ImportPath == "enkv.sh/sdk/protocols/generator" || p.ImportPath == "enkv.sh/sdk/protocols/output" || p.ImportPath == "enkv.sh/sdk/protocols/generator/retained" || p.ImportPath == "enkv.sh/sdk/artifact" || p.ImportPath == "enkv.sh/sdk/artifact/credentialroute" || p.ImportPath == modulePrefix+"core/format" || p.ImportPath == "golang.org/x/sys/unix" || hostTraceAPIClosure(p.ImportPath) {
			continue
		}
		return errors.New("generator host imports an unreviewed package")
	}
	return nil
}

// Neutral trace context adds only these pinned API packages to the host graph.
func hostTraceAPIClosure(path string) bool {
	switch path {
	case "go.opentelemetry.io/otel/attribute/internal", "go.opentelemetry.io/otel/attribute", "go.opentelemetry.io/otel/codes",
		"go.opentelemetry.io/otel/semconv/v1.26.0", "go.opentelemetry.io/otel/trace/embedded",
		"go.opentelemetry.io/otel/trace/internal/telemetry", "go.opentelemetry.io/otel/trace":
		return true
	}
	return false
}

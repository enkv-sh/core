package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/version"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	records "enkv.sh/core/internal/testrecords"
)

const golangciLintVersion = "2.14.0"

func runLint(ctx context.Context, root, bootstrap string, output io.Writer) (facts *moduleCheckFacts, err error) {
	var collectionErr error
	var directory string
	defer func() {
		err = errors.Join(collectionErr, err)
		if directory != "" {
			err = finishLintAssembly(directory, err)
		}
		if err != nil && !containedCheckFailure(ctx, err) {
			facts = nil
		}
	}()
	if !version.IsValid(runtime.Version()) || version.Compare(runtime.Version(), "go1.27.0") < 0 {
		return nil, fmt.Errorf("Go 1.27.0 or later required; installed %s", runtime.Version())
	}
	if err := runFormatting(ctx, root, false, output); err != nil {
		if !containedCheckFailure(ctx, err) {
			return nil, err
		}
		collectionErr = errors.Join(collectionErr, err)
	}
	version, err := runGolangciLint(ctx, root, "", "version", "--json")
	if err != nil {
		return nil, fmt.Errorf("golangci-lint v%s required; see README.md for installation: %w", golangciLintVersion, err)
	}
	var installed struct{ Version string }
	if json.Unmarshal(version, &installed) != nil || installed.Version != golangciLintVersion {
		return nil, fmt.Errorf("golangci-lint v%s required; see README.md for installation", golangciLintVersion)
	}
	directory, err = os.MkdirTemp("", "enkv-lint-")
	if err != nil {
		return nil, err
	}
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return nil, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	environment, err := moduleCheckEnvironment(ctx, root)
	if err != nil {
		return nil, err
	}
	unavailable := make(map[string]error)
	lintRoot, sources, err := buildLintAssemblyWithFailures(ctx, root, canonical, unavailable)
	for _, module := range moduleRoots {
		if cause := unavailable[module]; cause != nil {
			collectionErr = errors.Join(collectionErr, fmt.Errorf("module %s source inventory unavailable: %w", module, cause))
		}
	}
	if err != nil {
		return nil, err
	}
	failed := maps.Clone(unavailable)
	if _, err := fmt.Fprintf(output, "Lint source SHA-256: %s; assembly: %s\n", lintSourcesDigest(sources), lintRoot); err != nil {
		return nil, err
	}
	closures := make(map[string]assemblyClosure, len(moduleRoots))
	for _, module := range moduleRoots {
		if unavailable[module] != nil {
			if _, err := fmt.Fprintln(output, "Not running module checks", module, "(source inventory unavailable)"); err != nil {
				return nil, err
			}
			continue
		}
		if _, err := fmt.Fprintln(output, "Checking dependencies and vet", module); err != nil {
			return nil, err
		}
		checked, err := checkModule(ctx, root, module)
		if err != nil {
			if !containedCheckFailure(ctx, err) {
				return nil, fmt.Errorf("module %s: %w", module, err)
			}
			failed[module] = err
			collectionErr = errors.Join(collectionErr, fmt.Errorf("module %s: %w", module, err))
			continue
		}
		if checked.borrowable {
			closures[module] = copyModuleCheckClosure(checked.closure)
		}
		if _, err := fmt.Fprintln(output, "Checking golangci-lint", module, "(including unit tests)"); err != nil {
			return nil, err
		}
		flags := lintModuleFlags(lintRoot, module)
		modules, _, err := listClosure(localDiscoveryCommand(runGoEnvironment), ctx, lintRoot, module, compilerBuildFlags(flags, raceEnabled(ctx)), true, "./...")
		if err != nil {
			if !containedCheckFailure(ctx, err) {
				return nil, err
			}
			delete(closures, module)
			failed[module] = err
			collectionErr = errors.Join(collectionErr, fmt.Errorf("lint module %s discovery: %w", module, err))
			continue
		}
		for _, resolved := range modules {
			if strings.HasPrefix(resolved.Path, modulePrefix) {
				if err := checkModuleSource(lintRoot, modules, resolved.Path); err != nil {
					return nil, fmt.Errorf("lint module %s resolved source %s: %w", module, resolved.Path, err)
				}
			}
		}
		args := []string{"run", "--concurrency=" + strconv.Itoa(executionCapacityFromContext(ctx).Parallel), "--config=" + filepath.Join(lintRoot, ".golangci.yml"), "./..."}
		if _, err := fmt.Fprintf(output, "golangci-lint module=%s flags=%q args=%q\n", module, flags, args); err != nil {
			return nil, err
		}
		body, err := runGolangciLintWithFlags(ctx, lintRoot, module, flags, args...)
		if err != nil {
			if !containedCheckFailure(ctx, err) {
				return nil, err
			}
			collectionErr = errors.Join(collectionErr, err)
			continue
		}
		if _, err := output.Write(body); err != nil {
			return nil, err
		}
	}
	if _, err := fmt.Fprintln(output, "Checking vet for test tools and local examples"); err != nil {
		return nil, err
	}
	if err := vetLintTools(ctx, root, lintRoot, bootstrap); err != nil {
		if !containedCheckFailure(ctx, err) {
			return nil, err
		}
		collectionErr = errors.Join(collectionErr, err)
	}
	files, err := maintainedGoFiles(root)
	if err != nil {
		return nil, err
	}
	standalone := make(map[string][]string)
	var groups []string
	for _, source := range files {
		if !strings.HasPrefix(source, "tests/scripts/") && !strings.HasPrefix(source, "tests/examples/") {
			continue
		}
		group := filepath.Dir(source)
		if _, known := standalone[group]; !known {
			groups = append(groups, group)
		}
		standalone[group] = append(standalone[group], "../"+source)
	}
	slices.Sort(groups)
	for _, group := range groups {
		args := append([]string{"vet", "-mod=readonly", "-modfile=" + assemblyModfile(root, "hermetic", "memory")}, standalone[group]...)
		if _, err := runGo(ctx, root, "core", args...); err != nil {
			failure := containProcessFailure(ctx, err)
			if !containedCheckFailure(ctx, failure) {
				return nil, err
			}
			collectionErr = errors.Join(collectionErr, failure)
		}
	}
	for _, spec := range []struct{ suite, provider string }{{"hermetic", "memory"}, {"live", "gcp"}, {"live", "aws"}} {
		blocked := false
		for _, module := range requiredAssemblyModules(spec.suite, spec.provider) {
			blocked = blocked || failed[module] != nil
		}
		if blocked {
			if _, err := fmt.Fprintln(output, "Not running vet for", spec.suite, spec.provider, "assembly (module prerequisite failed)"); err != nil {
				return nil, err
			}
			continue
		}
		if _, err := fmt.Fprintln(output, "Checking vet for", spec.suite, spec.provider, "assembly"); err != nil {
			return nil, err
		}
		assemblyDirectory, err := os.MkdirTemp(canonical, "vet-"+spec.suite+"-"+spec.provider+"-")
		if err != nil {
			return nil, err
		}
		if _, _, err := vetAssembly(runGoEnvironment, ctx, root, spec.suite, spec.provider, bootstrap, assemblyDirectory); err != nil {
			if !containedCheckFailure(ctx, err) {
				return nil, err
			}
			collectionErr = errors.Join(collectionErr, err)
			continue
		}
		if _, err := runGo(ctx, root, "core", "mod", "verify", "-modfile="+assemblyModfile(root, spec.suite, spec.provider)); err != nil {
			return nil, err
		}
	}
	afterEnvironment, err := moduleCheckEnvironment(ctx, root)
	if err != nil {
		return nil, err
	}
	if afterEnvironment != environment {
		return nil, errors.New("module check environment changed during lint")
	}
	return &moduleCheckFacts{root: root, race: raceEnabled(ctx), sources: slices.Clone(sources), environment: environment, modules: closures, failed: failed, unavailableSources: unavailable}, nil
}

type moduleCheckFacts struct {
	root               string
	race               bool
	sources            []lintSource
	environment        string
	modules            map[string]assemblyClosure
	failed             map[string]error
	unavailableSources map[string]error
}

func moduleCheckEnvironment(ctx context.Context, root string) (string, error) {
	values, err := testBuildEnvironment(runGoEnvironment, ctx, root)
	if err != nil {
		return "", err
	}
	body, err := runGo(ctx, root, "core", "env", "-json", "GOVERSION", "GOTOOLDIR", "GOTOOLCHAIN", "GOWORK", "GOENV", "GOPATH", "GOMODCACHE",
		"GOPROXY", "GOSUMDB", "GOPRIVATE", "GONOSUMDB", "GONOPROXY", "GOINSECURE", "GOVCS", "GO111MODULE", "GOFIPS140")
	if err != nil {
		return "", err
	}
	var policy map[string]string
	if json.Unmarshal(body, &policy) != nil {
		return "", errors.New("module check environment unavailable")
	}
	for key, value := range policy {
		values[key] = value
	}
	if values["GOVERSION"] == "" || values["GOTOOLDIR"] == "" {
		return "", errors.New("module check toolchain identity unavailable")
	}
	goPath, err := exec.LookPath("go")
	if err != nil {
		return "", err
	}
	goPath, err = filepath.EvalSymlinks(goPath)
	if err != nil {
		return "", err
	}
	values["go_executable"] = goPath
	values["go_executable_sha256"], err = assemblyFileSHA256(goPath)
	if err != nil {
		return "", err
	}
	values["vet_GOFLAGS"] = analysisGoFlags
	body, err = json.Marshal(values)
	return digestBytes(body), err
}

func (facts *moduleCheckFacts) current(ctx context.Context, root string) (bool, error) {
	if facts == nil || facts.race != raceEnabled(ctx) {
		return false, nil
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false, err
	}
	if canonical != facts.root {
		return false, nil
	}
	environment, err := moduleCheckEnvironment(ctx, canonical)
	return environment == facts.environment, err
}

func finishLintAssembly(directory string, err error) error {
	if !toolCommandsJoined(err) {
		return fmt.Errorf("private lint assembly retained at %s after unsettled tool process: %w", directory, err)
	}
	return errors.Join(err, os.RemoveAll(directory))
}

func runGolangciLint(ctx context.Context, root, module string, args ...string) ([]byte, error) {
	return runGolangciLintWithFlags(ctx, root, module, nil, args...)
}

func runGolangciLintWithFlags(ctx context.Context, root, module string, flags []string, args ...string) (body []byte, err error) {
	command := exec.Command("golangci-lint", args...)
	if root != "" || module != "" {
		directory, err := sourcePath(root, module)
		if err != nil {
			return nil, err
		}
		command.Dir = directory
	}
	localDirectory := ""
	joined := true
	defer func() {
		if localDirectory != "" && joined {
			err = errors.Join(err, os.RemoveAll(localDirectory))
		}
	}()
	if command.Dir != "" && len(args) != 0 && args[0] == "run" {
		localArgs, directory, preparation, prepareErr := localModuleArguments(ctx, root, command.Dir, append([]string{"list"}, flags...))
		localDirectory, joined = directory, toolCommandsJoined(prepareErr) && (preparation == nil || preparation.Joined)
		if prepareErr != nil {
			return nil, prepareErr
		}
		flags = localArgs[1:]
	}
	// CGo analyzers reopen raw files named by generated //line directives.
	// Keep this disposable physical source path in the analysis cache identity.
	capacity := executionCapacityFromContext(ctx)
	if err := validateExecutionCapacity(capacity); err != nil {
		return nil, err
	}
	goFlags := analysisGoFlags
	for _, flag := range flags {
		goFlags += " " + strconv.Quote(flag)
	}
	goFlags += " -p=" + strconv.Itoa(capacity.Parallel)
	command.Env = environment(goEnvironment(), map[string]string{"GOPROXY": "off", "GOSUMDB": "off", "GONOPROXY": "none", "GOFLAGS": goFlags})
	var stdout, stderr limitedOutput
	command.Stdout, command.Stderr = &stdout, &stderr
	parent := ctx
	ctx, cancel := preparationCommandContext(ctx)
	defer cancel()
	process := superviseProcess(ctx, command)
	joined = process.Joined
	body, err = golangciLintResult(module, process, &stdout, &stderr)
	if len(args) != 0 && args[0] == "run" {
		err = containProcessFailure(parent, err)
	}
	return body, err
}

func golangciLintResult(module string, process processResult, stdout, stderr *limitedOutput) ([]byte, error) {
	if !process.Joined {
		return nil, &toolFailure{operation: "golangci-lint " + module, process: process}
	}
	if process.Status != "passed" {
		return nil, &toolFailure{operation: "golangci-lint " + module, process: process, stdout: slices.Clone(stdout.Bytes()), stderr: slices.Clone(stderr.Bytes()), overflow: stdout.overflow || stderr.overflow}
	}
	if stdout.overflow || stderr.overflow {
		return nil, errors.New("golangci-lint output exceeds its bound")
	}
	return stdout.Bytes(), nil
}

// Lint reads physical files, so materialize the same single Crypto admission
// overlay in a private source copy. The real checkout never receives that file.
type lintSource struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func lintModuleFlags(root, module string) []string {
	flags := []string{"-mod=readonly"}
	if module == "core" {
		flags = append(flags, "-modfile="+assemblyModfile(root, "hermetic", "memory"))
	} else if module == "crypto" || module == "providers/aws" || module == "providers/gcp" {
		flags = append(flags, "-modfile="+filepath.Join(root, module, "telemetry_test.mod"))
	}
	return flags
}

func lintSourcePathsForModules(ctx context.Context, root string, unavailable, failures map[string]error) ([]string, error) {
	files, err := maintainedGoFiles(root)
	if err != nil {
		return nil, err
	}
	// Keep each maintained package's testdata assets with its Go sources.
	// Embedded inputs and native test fixtures belong to the same hashed
	// source copy; discovery does not interpret individual embed patterns.
	owners := make(map[string]bool)
	for _, name := range files {
		owners[filepath.Dir(name)] = true
	}
	controls := make(map[string]bool)
	for owner := range owners {
		// A nested manifest changes ./... membership without changing Go bytes.
		for directory := owner; !controls[directory]; directory = filepath.ToSlash(filepath.Dir(directory)) {
			controls[directory] = true
			for _, name := range []string{"go.mod", "go.sum"} {
				label := filepath.ToSlash(filepath.Join(directory, name))
				path, err := sourcePath(root, label)
				if err != nil {
					return nil, err
				}
				if _, err := os.Lstat(path); err == nil {
					files = append(files, label)
				} else if !os.IsNotExist(err) {
					return nil, err
				}
			}
			source, registered := registeredModule(directory)
			if directory == "." || registered && source.Selector == directory {
				break
			}
		}
		data, err := sourcePath(root, filepath.ToSlash(filepath.Join(owner, "testdata")))
		if err != nil {
			return nil, err
		}
		info, err := os.Lstat(data)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			return nil, errors.New("lint testdata source is not a directory")
		}
		if err := filepath.WalkDir(data, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return errors.New("lint testdata source is not regular")
			}
			relative, err := sourceLabel(root, path)
			if err != nil {
				return err
			}
			files = append(files, filepath.ToSlash(relative))
			return nil
		}); err != nil {
			return nil, err
		}
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	for _, module := range moduleRoots {
		if unavailable[module] != nil {
			continue
		}
		// Test embed and native source lists are resolved while Go loads test variants.
		// Without -export or -compiled, list does not compile or run them.
		var moduleFiles []string
		configurations := [][]string{lintModuleFlags(canonicalRoot, module)}
		if module == cloudflareModule {
			configurations = append(configurations, append(lintModuleFlags(canonicalRoot, module), "-tags="+cloudflareTestArtifactTag))
		}
		for _, flags := range configurations {
			args := append([]string{"list"}, compilerBuildFlags(flags, raceEnabled(ctx))...)
			args = append(args, "-test", "-json=Name,ImportPath,ForTest,Dir,GoFiles,CgoFiles,TestGoFiles,XTestGoFiles,CFiles,CXXFiles,MFiles,HFiles,FFiles,SFiles,SwigFiles,SwigCXXFiles,SysoFiles,EmbedFiles,TestEmbedFiles,XTestEmbedFiles", "./...")
			body, err := runGo(cacheOnlyGoContext(ctx), canonicalRoot, module, args...)
			if err != nil {
				failure := containProcessFailure(ctx, err)
				if failures == nil || !containedCheckFailure(ctx, failure) {
					return nil, err
				}
				failures[module] = failure
				break
			}
			packages, err := decodeObjects[struct {
				compiledPackage
				Name                            string
				TestGoFiles, XTestGoFiles       []string
				TestEmbedFiles, XTestEmbedFiles []string
			}](body)
			if err != nil {
				return nil, err
			}
			if len(packages) == 0 {
				return nil, errors.New("lint compiler source package inventory is empty")
			}
			for _, pkg := range packages {
				if pkg.Name == "main" && pkg.ForTest == "" && strings.HasSuffix(pkg.ImportPath, ".test") {
					// Go puts the synthetic test main in its cache. It has no
					// checkout source lifetime; ordinary GoFiles are relative.
					pkg.GoFiles = slices.DeleteFunc(pkg.GoFiles, filepath.IsAbs)
				}
				assets := append(slices.Clone(pkg.TestEmbedFiles), pkg.XTestEmbedFiles...)
				assets = append(assets, pkg.TestGoFiles...)
				assets = append(assets, pkg.XTestGoFiles...)
				for _, names := range compilerSourceFiles(pkg.compiledPackage) {
					assets = append(assets, names...)
				}
				if len(assets) == 0 {
					continue
				}
				if pkg.Dir == "" {
					return nil, errors.New("lint compiler source package directory unavailable")
				}
				directory, err := filepath.EvalSymlinks(pkg.Dir)
				if err != nil {
					return nil, err
				}
				for _, asset := range assets {
					if filepath.IsAbs(asset) || filepath.Clean(asset) != asset || asset == ".." || strings.HasPrefix(asset, ".."+string(filepath.Separator)) {
						return nil, errors.New("lint compiler source path refused")
					}
					path := filepath.Join(directory, asset)
					relative, err := sourceLabel(canonicalRoot, path)
					if err != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
						return nil, errors.New("lint compiler source escaped checkout")
					}
					info, err := os.Lstat(path)
					resolved, resolveErr := filepath.EvalSymlinks(path)
					if err != nil || !info.Mode().IsRegular() || resolveErr != nil || resolved != path {
						return nil, errors.New("lint compiler source is unavailable or not regular")
					}
					moduleFiles = append(moduleFiles, filepath.ToSlash(relative))
				}
			}
		}
		if failures[module] == nil {
			files = append(files, moduleFiles...)
		}
	}
	files = append(files, cloudflareModule+"/LICENSE", cloudflareProtocolModule+"/LICENSE", cloudflareSDKModule+"/LICENSE", ".golangci.yml", "tests/hermetic/hermetic.mod", "crypto/telemetry_test.mod", "providers/aws/telemetry_test.mod", "providers/gcp/telemetry_test.mod")
	for _, module := range moduleRoots {
		files = append(files, module+"/go.mod")
	}
	sums := []string{"tests/hermetic/hermetic.sum", "crypto/telemetry_test.sum", "providers/aws/telemetry_test.sum", "providers/gcp/telemetry_test.sum"}
	for _, module := range moduleRoots {
		sums = append(sums, module+"/go.sum")
	}
	for _, name := range sums {
		physical, err := sourcePath(root, name)
		if err != nil {
			return nil, err
		}
		if _, err := os.Lstat(physical); err == nil {
			files = append(files, name)
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	slices.Sort(files)
	return slices.Compact(files), nil
}

func lintSourceBytes(root, name string) ([]byte, error) {
	path, err := sourcePath(root, name)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("lint source is unavailable or not regular")
	}
	return os.ReadFile(path)
}

// Analyze the same Core callers as the hermetic execution assembly. Only the
// catalog and records dependencies belong here; testmain is vetted separately.
func lintReplacements(root string) (map[string]string, error) {
	replacements := map[string]string{}
	if err := addTestAdmissions(root, replacements); err != nil {
		return nil, err
	}
	if err := addCryptoTests(root, replacements); err != nil {
		return nil, err
	}
	if err := addCoreTestGroups(root, []string{"tests/shared", "tests/hermetic"}, replacements); err != nil {
		return nil, err
	}
	for _, item := range []struct{ source, target string }{
		{"records", "testrecords"}, {"catalog", "testcatalog"},
	} {
		directory, err := records.SafePath(root, "tests/shared/"+item.source)
		if err != nil {
			return nil, errors.New("lint dependency source path refused")
		}
		entries, err := os.ReadDir(directory)
		if err != nil {
			return nil, err
		}
		count := 0
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
				continue
			}
			source, err := records.SafePath(root, filepath.Join("tests/shared", item.source, entry.Name()))
			if err != nil {
				return nil, errors.New("lint dependency source path refused")
			}
			target := filepath.Join(root, "core/internal", item.target, entry.Name())
			if _, err := os.Lstat(target); !os.IsNotExist(err) || replacements[target] != "" {
				return nil, errors.New("lint dependency would replace Core source")
			}
			replacements[target] = source
			count++
		}
		if count == 0 {
			return nil, errors.New("lint dependency source group is empty")
		}
	}
	return replacements, nil
}

func buildLintAssembly(ctx context.Context, root, directory string) (string, []lintSource, error) {
	return buildLintAssemblyWithFailures(ctx, root, directory, nil)
}

func buildLintAssemblyWithFailures(ctx context.Context, root, directory string, unavailable map[string]error) (string, []lintSource, error) {
	relative, err := filepath.Rel(root, directory)
	if err != nil || !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", nil, errors.New("lint assembly must be outside checkout")
	}
	replacements, err := lintReplacements(root)
	if err != nil {
		return "", nil, err
	}
	files, err := lintSourcePathsForModules(ctx, root, unavailable, unavailable)
	if err != nil {
		return "", nil, err
	}
	assemblyRoot := filepath.Join(directory, "source")
	if err := os.Mkdir(assemblyRoot, 0700); err != nil {
		return "", nil, err
	}
	sources := make([]lintSource, 0, len(files))
	for _, name := range files {
		body, err := lintSourceBytes(root, name)
		if err != nil {
			return "", nil, err
		}
		target, err := sourcePath(assemblyRoot, name)
		if err != nil {
			return "", nil, err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return "", nil, err
		}
		if err := os.WriteFile(target, body, 0600); err != nil {
			return "", nil, err
		}
		sum := sha256.Sum256(body)
		sources = append(sources, lintSource{Path: name, SHA256: hex.EncodeToString(sum[:])})
	}
	for target, source := range replacements {
		relative, err := filepath.Rel(root, target)
		if err != nil {
			return "", nil, err
		}
		body, err := os.ReadFile(source)
		if err != nil {
			return "", nil, err
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(assemblyRoot, relative)), 0700); err != nil {
			return "", nil, err
		}
		if err := os.WriteFile(filepath.Join(assemblyRoot, relative), body, 0600); err != nil {
			return "", nil, err
		}
	}
	return assemblyRoot, sources, nil
}

func lintSourcesDigest(sources []lintSource) string {
	body, _ := json.Marshal(sources)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

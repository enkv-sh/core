package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/version"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	records "enkv.sh/core/internal/testrecords"
)

type cacheOnlyGoKey struct{}

func cacheOnlyGoContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, cacheOnlyGoKey{}, true)
}

type toolFailure struct {
	operation  string
	process    processResult
	cleanup    error
	stdout     []byte
	stderr     []byte
	overflow   bool
	facts      *checkCommandFacts
	factsOwner *checkDiagnostics
}

type goEnvironmentCommand func(context.Context, string, string, []string, ...string) ([]byte, error)

func localDiscoveryCommand(command goEnvironmentCommand) goEnvironmentCommand {
	return func(ctx context.Context, root, directory string, env []string, args ...string) ([]byte, error) {
		body, err := command(ctx, root, directory, env, args...)
		if len(args) != 0 && args[0] == "list" {
			err = containProcessFailure(ctx, err)
		}
		return body, err
	}
}

func (failure *toolFailure) Error() string {
	if failure == nil {
		return "tool failed"
	}
	var causes []error
	if !failure.process.Joined {
		causes = append(causes, fmt.Errorf("process group did not settle: %w", failure.process.Cause))
	} else if failure.process.Status != "passed" {
		causes = append(causes, failure.process.Cause)
	} else if !failure.process.Started {
		causes = append(causes, errors.New("tool process did not start"))
	}
	if failure.overflow {
		causes = append(causes, errors.New("Go command output exceeds its bound"))
	}
	if failure.cleanup != nil {
		causes = append(causes, fmt.Errorf("tool directory cleanup failed: %w", failure.cleanup))
	}
	message := fmt.Sprintf("%s: %v", failure.operation, errors.Join(causes...))
	if failure.process.Joined && (len(failure.stdout) != 0 || len(failure.stderr) != 0) {
		message += "\n" + string(failure.stdout) + string(failure.stderr)
	}
	return message
}

func (failure *toolFailure) Unwrap() error {
	if failure == nil {
		return nil
	}
	return errors.Join(failure.process.Cause, failure.cleanup)
}

func runGo(ctx context.Context, root, directory string, args ...string) ([]byte, error) {
	body, _, err := runGoRecorded(ctx, root, directory, args...)
	return body, err
}

func runGoEnvironment(ctx context.Context, root, directory string, env []string, args ...string) ([]byte, error) {
	body, _, err := runGoRecordedEnvironment(ctx, root, directory, env, args...)
	return body, err
}

func runGoRecorded(ctx context.Context, root, directory string, args ...string) ([]byte, checkCommandFacts, error) {
	return runGoRecordedEnvironment(ctx, root, directory, nil, args...)
}

func runGoRecordedEnvironment(ctx context.Context, root, directory string, env []string, args ...string) (body []byte, facts checkCommandFacts, err error) {
	started := time.Now()
	facts = checkCommandFacts{Scope: directory, Process: "unavailable", Events: "not_run", ToolCleanup: "not_required", RaceObservation: "unavailable"}
	defer func() {
		seconds := time.Since(started).Seconds()
		facts.WallSeconds = &seconds
	}()
	workingDirectory, err := sourcePath(root, directory)
	if err != nil {
		return nil, facts, err
	}
	args, localDirectory, preparation, err := localModuleArguments(ctx, root, workingDirectory, args)
	facts.ModulePreparation = preparation
	localJoined := toolCommandsJoined(err) && (preparation == nil || preparation.Joined)
	defer func() {
		if localDirectory != "" && localJoined {
			err = errors.Join(err, os.RemoveAll(localDirectory))
		}
	}()
	if err != nil {
		return nil, facts, err
	}
	var lease *toolDirectoryLease
	var reportJoin func(bool)
	needsDirectories, err := compilerOverlayNeedsToolDirectories(root, workingDirectory, args)
	if err != nil {
		return nil, facts, err
	}
	if needsDirectories {
		var borrowed bool
		reportJoin, borrowed, err = borrowToolDirectoryPhase(ctx, root)
		if err != nil {
			return nil, facts, err
		}
		if !borrowed {
			locks, lockErr := resourceLocksFromContext(ctx)
			if lockErr != nil {
				return nil, facts, lockErr
			}
			lease, err = prepareToolDirectories(ctx, locks, root)
			if err != nil {
				return nil, facts, err
			}
		}
	}
	args, err = executionGoArguments(ctx, args)
	if err != nil {
		if reportJoin != nil {
			reportJoin(true)
		}
		if lease != nil {
			finish, release := finalizationContext(ctx)
			defer release()
			err = errors.Join(err, lease.Release(finish, true))
		}
		return nil, facts, err
	}
	command := exec.Command(invocationGoBinary(ctx), args...)
	command.Dir = workingDirectory
	command.Env = invocationGoEnvironment(ctx)
	if env != nil {
		command.Env = slices.Clone(env)
	}
	commandRace := raceEnabled(ctx)
	for _, argument := range args {
		commandRace = commandRace || argument == "-race"
	}
	ctx = withRacePolicy(ctx, commandRace)
	if len(args) != 0 && args[0] == "vet" {
		command.Env = environment(command.Env, map[string]string{"GOFLAGS": analysisGoFlags})
	}
	if ctx.Value(cacheOnlyGoKey{}) == true {
		command.Env = environment(command.Env, map[string]string{"GOPROXY": "off", "GOSUMDB": "off", "GONOPROXY": "none"})
	}
	var stdout, stderr limitedOutput
	command.Stdout, command.Stderr = &stdout, &stderr
	if !goCommandRunsTests(args) {
		var cancel context.CancelFunc
		ctx, cancel = preparationCommandContext(ctx)
		defer cancel()
	}
	process := superviseProcess(ctx, command)
	localJoined = process.Joined
	facts.Process, facts.Started, facts.Joined = process.Status, process.Started, process.Joined
	operation := "go"
	if len(args) != 0 {
		operation += " " + args[0]
	}
	var cleanupErr error
	if reportJoin != nil {
		reportJoin(process.Joined)
		facts.ToolCleanup = "not_owner"
	}
	if lease != nil {
		finish, release := finalizationContext(ctx)
		cleanupErr = lease.Release(finish, process.Joined)
		release()
		facts.ToolCleanup = "passed"
		if !process.Joined {
			facts.ToolCleanup = "retained_unjoined"
		} else if cleanupErr != nil {
			facts.ToolCleanup = "failed"
		}
	}
	failure := &toolFailure{operation: operation, process: process, cleanup: cleanupErr, facts: &facts}
	if process.Joined {
		failure.stdout = append([]byte(nil), stdout.Bytes()...)
		failure.stderr = append([]byte(nil), stderr.Bytes()...)
		failure.overflow = stdout.overflow || stderr.overflow
		facts.RaceObservation = observedRace(true, failure.stdout, failure.stderr)
	}
	if process.Status != "passed" || !process.Started || !process.Joined || cleanupErr != nil || failure.overflow {
		return nil, facts, failure
	}
	return stdout.Bytes(), facts, nil
}

// Compilation and compiled inventory are preparation even when Go calls them test.
func goCommandRunsTests(args []string) bool {
	if len(args) == 0 || args[0] != "test" {
		return false
	}
	for index, arg := range args[1:] {
		if arg == "-c" || arg == "-c=true" || strings.HasPrefix(arg, "-list=") && arg != "-list=" || arg == "-list" && index+2 < len(args) && args[index+2] != "" {
			return false
		}
	}
	return true
}

func decodeObjects[T any](body []byte) ([]T, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	var values []T
	for {
		var value T
		if err := decoder.Decode(&value); err != nil {
			if errors.Is(err, io.EOF) {
				return values, nil
			}
			return nil, errors.New("invalid Go metadata")
		}
		values = append(values, value)
	}
}

// Go resolves file flags and overlay entries from its command working directory.
func compilerInputPath(workingDirectory, path string) string {
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(workingDirectory, path)
}

func compilerOverlayNeedsToolDirectories(root, workingDirectory string, args []string) (bool, error) {
	replacements, err := compilerOverlayReplacements(workingDirectory, args)
	if err != nil {
		return false, err
	}
	if len(replacements) == 0 {
		return false, nil
	}
	roots := []string{filepath.Clean(root)}
	canonical, err := canonicalToolRoot(root)
	if err != nil {
		return false, err
	}
	if canonical != roots[0] {
		roots = append(roots, canonical)
	}
	for target := range replacements {
		for _, owner := range roots {
			for _, relative := range toolPackageDirectories() {
				directory := filepath.Join(owner, filepath.FromSlash(relative))
				if target == directory || strings.HasPrefix(target, directory+string(filepath.Separator)) {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func compilerOverlayReplacements(workingDirectory string, flags []string) (map[string]string, error) {
	replacements := make(map[string]string)
	for index := 0; index < len(flags); index++ {
		flag := flags[index]
		path, ok := strings.CutPrefix(flag, "-overlay=")
		if flag == "-overlay" {
			index++
			if index >= len(flags) {
				return nil, errors.New("compiled custody overlay unavailable")
			}
			path, ok = flags[index], true
		}
		if !ok {
			continue
		}
		var overlay struct{ Replace map[string]string }
		body, err := os.ReadFile(compilerInputPath(workingDirectory, path))
		if err != nil || json.Unmarshal(body, &overlay) != nil {
			return nil, errors.New("compiled custody overlay unavailable")
		}
		for target, source := range overlay.Replace {
			replacements[compilerInputPath(workingDirectory, target)] = compilerInputPath(workingDirectory, source)
		}
	}
	return replacements, nil
}

func listClosure(command goEnvironmentCommand, ctx context.Context, root, directory string, flags []string, tests bool, patterns ...string) ([]resolvedModule, []compiledPackage, error) {
	return listClosureEnvironment(command, ctx, root, directory, nil, flags, tests, patterns...)
}

func listClosureEnvironment(command goEnvironmentCommand, ctx context.Context, root, directory string, env []string, flags []string, tests bool, patterns ...string) ([]resolvedModule, []compiledPackage, error) {
	workingDirectory, err := sourcePath(root, directory)
	if err != nil {
		return nil, nil, err
	}
	args := append([]string{"list"}, flags...)
	moduleBytes, err := command(ctx, root, directory, env, append(args, "-m", "-json", "all")...)
	if err != nil {
		return nil, nil, err
	}
	modules, err := decodeObjects[resolvedModule](moduleBytes)
	if err != nil {
		return nil, nil, err
	}
	args = append([]string{"list"}, flags...)
	args = append(args, "-deps", "-export", "-compiled", "-json=ImportPath,Dir,Export,ImportMap,Standard,ForTest,GoFiles,TestGoFiles,XTestGoFiles,CompiledGoFiles,CgoFiles,CFiles,CXXFiles,MFiles,HFiles,FFiles,SFiles,SwigFiles,SwigCXXFiles,SysoFiles,EmbedFiles,Imports")
	if tests {
		args = append(args, "-test")
		if len(patterns) == 0 {
			patterns = []string{"."}
		}
		args = append(args, patterns...)
	} else {
		if len(patterns) == 0 {
			var err error
			patterns, err = productionPackages(command, ctx, root, directory)
			if err != nil {
				return nil, nil, err
			}
		}
		args = append(args, patterns...)
	}
	packageBytes, err := command(ctx, root, directory, env, args...)
	if err != nil {
		return nil, nil, err
	}
	packages, err := decodeObjects[compiledPackage](packageBytes)
	if err != nil {
		return nil, nil, err
	}
	replacements, err := compilerOverlayReplacements(workingDirectory, flags)
	if err != nil {
		return nil, nil, err
	}
	for i := range packages {
		// Ordinary compiled paths can still name overlay targets. Generated
		// cgo paths are cached compiler inputs and need no replacement.
		for _, sources := range compilerSourceFiles(packages[i]) {
			for j, name := range sources {
				if !filepath.IsAbs(name) {
					name = filepath.Join(packages[i].Dir, name)
				}
				if source := replacements[name]; source != "" {
					sources[j] = source
				}
			}
		}
	}
	return modules, packages, nil
}

func productionPackages(command goEnvironmentCommand, ctx context.Context, root, directory string) ([]string, error) {
	if directory != "crypto" && directory != "core" {
		return []string{"./..."}, nil
	}
	body, err := command(ctx, root, directory, nil, append(compilerBuildFlags([]string{"list", "-mod=readonly", "-find", "-json=ImportPath"}, raceEnabled(ctx)), "./...")...)
	if err != nil {
		return nil, err
	}
	packages, err := decodeObjects[compiledPackage](body)
	if err != nil {
		return nil, err
	}
	var roots []string
	for _, p := range packages {
		testRoot := directory == "crypto" && withinModule(p.ImportPath, modulePrefix+"crypto/testsupport") ||
			directory == "core" && p.ImportPath == modulePrefix+"core/testsupport/nativeprocess"
		if !testRoot {
			roots = append(roots, p.ImportPath)
		}
	}
	if len(roots) == 0 {
		if directory == "core" {
			return nil, errors.New("Core runtime package roots missing")
		}
		return nil, errors.New("Crypto runtime package roots missing")
	}
	return roots, nil
}

func checkModuleSource(root string, modules []resolvedModule, name string) error {
	source, known := registeredModule(name)
	if !known {
		return fmt.Errorf("%s source is not registered", name)
	}
	want, err := moduleSourceDirectory(root, source)
	if err != nil {
		return fmt.Errorf("%s source unavailable", name)
	}
	for _, module := range modules {
		if module.Path != source.Module {
			continue
		}
		if !version.IsValid("go"+module.GoVersion) || version.Compare("go"+module.GoVersion, "go1.27.0") < 0 {
			return fmt.Errorf("%s module requires a Go 1.27.0 minimum", name)
		}
		actual, err := filepath.EvalSymlinks(module.Dir)
		if err != nil || actual != want {
			return fmt.Errorf("resolved %s source differs", name)
		}
		return nil
	}
	return fmt.Errorf("resolved %s source missing", name)
}

func testBuildEnvironment(command goEnvironmentCommand, ctx context.Context, root string) (map[string]string, error) {
	body, err := command(ctx, root, "core", nil, "env", "-json", "GOROOT", "GOOS", "GOARCH", "CGO_ENABLED", "GOEXPERIMENT", "GOFLAGS",
		"GOARM64", "GOAMD64", "CC", "CXX", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS", "PKG_CONFIG",
		"GOVERSION", "GOTOOLDIR", "GOTOOLCHAIN", "GOWORK", "GOENV", "GOPATH", "GOMODCACHE", "GOPROXY", "GOSUMDB", "GOPRIVATE", "GONOSUMDB", "GONOPROXY", "GOINSECURE", "GOVCS", "GO111MODULE", "GOFIPS140")
	if err != nil {
		return nil, err
	}
	var values map[string]string
	if json.Unmarshal(body, &values) != nil || values["GOROOT"] == "" || values["GOOS"] == "" || values["GOARCH"] == "" {
		return nil, errors.New("test toolchain/native environment unavailable")
	}
	// Relative compiler and pkg-config commands resolve through this PATH.
	values["PATH"] = os.Getenv("PATH")
	return values, nil
}

func compilerSourceFiles(pkg compiledPackage) [][]string {
	return [][]string{pkg.GoFiles, pkg.TestGoFiles, pkg.XTestGoFiles, pkg.CompiledGoFiles, pkg.CgoFiles, pkg.CFiles, pkg.CXXFiles, pkg.MFiles, pkg.HFiles, pkg.FFiles, pkg.SFiles, pkg.SwigFiles, pkg.SwigCXXFiles, pkg.SysoFiles, pkg.EmbedFiles}
}

func compilerBuildFlags(flags []string, race bool) []string {
	actual := slices.DeleteFunc(slices.Clone(flags), func(flag string) bool { return flag == "-race" })
	if race {
		actual = append(actual, "-race")
	}
	return actual
}

func registeredModule(name string) (moduleSource, bool) {
	for _, source := range moduleSources {
		if name == source.Selector || name == source.Module {
			return source, true
		}
	}
	return moduleSource{}, false
}

func moduleSourceDirectory(root string, source moduleSource) (string, error) {
	owner := root
	if source.Sibling != "" {
		owner = filepath.Join(filepath.Dir(root), source.Sibling)
	}
	return records.SafePath(owner, filepath.FromSlash(source.Directory))
}

// Logical source labels remain stable when a registered module moves.
func sourcePath(root, logical string) (string, error) {
	if logical == "" {
		return records.SafePath(root, ".")
	}
	for _, source := range moduleSources {
		if logical == source.Selector || strings.HasPrefix(logical, source.Selector+"/") {
			owner, err := moduleSourceDirectory(root, source)
			if err != nil {
				return "", err
			}
			if logical == source.Selector {
				return owner, nil
			}
			return records.SafePath(owner, filepath.FromSlash(strings.TrimPrefix(logical, source.Selector+"/")))
		}
	}
	return records.SafePath(root, filepath.FromSlash(logical))
}

func sourceLabel(root, physical string) (string, error) {
	for _, source := range moduleSources {
		owner, err := moduleSourceDirectory(root, source)
		if err != nil {
			return "", err
		}
		relative, err := filepath.Rel(owner, physical)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
			continue
		}
		if _, err := records.SafePath(owner, relative); err != nil {
			return "", err
		}
		if relative == "." {
			return source.Selector, nil
		}
		return source.Selector + "/" + filepath.ToSlash(relative), nil
	}
	relative, err := filepath.Rel(root, physical)
	if err != nil {
		return "", err
	}
	if _, err := records.SafePath(root, relative); err != nil {
		return "", err
	}
	resolved, err := sourcePath(root, filepath.ToSlash(relative))
	if err != nil || resolved != physical {
		return "", errors.New("source does not use its registered owner")
	}
	return filepath.ToSlash(relative), nil
}

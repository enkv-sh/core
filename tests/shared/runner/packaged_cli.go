package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"syscall"

	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/sdk/artifact"
)

// RFC 8032 section 7.1 public keys in RFC 8410 SPKI PEM form. These
// public-only test inputs serve the normal production packaging constructor;
// local plugin acceptance needs no private signing key or official publication.
const cliArchivePluginPublicPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=
-----END PUBLIC KEY-----
`
const cliArchiveCLIPublicPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAPUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=
-----END PUBLIC KEY-----
`

// stockCLIArchive is the closed stock CLI layout, shared by preparation and
// archive tests. The caller owns a private empty extraction directory.
type stockCLIArchive struct {
	archive artifact.DigestLength
	members map[string]artifact.DigestLength
}

type stockCLIReader struct {
	ctx    context.Context
	reader io.Reader
	length int64
}

func (r *stockCLIReader) Read(body []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.reader.Read(body)
	r.length += int64(n)
	if r.length > artifact.MaxArchiveBytes {
		return n, errors.New("stock CLI archive exceeds bound")
	}
	return n, err
}

func extractStockCLIArchive(ctx context.Context, path, directory string) (value stockCLIArchive, result error) {
	if ctx == nil || ctx.Err() != nil {
		return value, errors.New("stock CLI archive context refused")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return value, err
	}
	if !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > artifact.MaxArchiveBytes {
		return value, errors.New("stock CLI archive type or length refused")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return value, err
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	opened, err := file.Stat()
	if err != nil || !sameStockCLIFile(before, opened) {
		return value, errors.Join(errors.New("stock CLI archive changed"), err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		return value, errors.Join(errors.New("stock CLI extraction directory is not empty"), err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return value, err
	}
	defer func() { result = errors.Join(result, root.Close()) }()
	digest := sha256.New()
	counted := &stockCLIReader{ctx: ctx, reader: io.TeeReader(io.LimitReader(file, artifact.MaxArchiveBytes+1), digest)}
	input := bufio.NewReader(counted)
	compressed, err := gzip.NewReader(input)
	if err != nil {
		return value, err
	}
	closed := false
	defer func() {
		if !closed {
			result = errors.Join(result, compressed.Close())
		}
	}()
	compressed.Multistream(false)
	expanded := &stockCLIReader{ctx: ctx, reader: io.LimitReader(compressed, artifact.MaxArchiveBytes+1)}
	archive := tar.NewReader(expanded)
	value.members = make(map[string]artifact.DigestLength)
	names := []string{}
	expectedTarBytes := int64(1024)
	var window [64 << 10]byte
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return value, err
		}
		mode := int64(0644)
		switch header.Name {
		case "enkv":
			mode = 0755
		case "LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md":
		default:
			return value, errors.New("stock CLI archive member refused")
		}
		if _, exists := value.members[header.Name]; exists || len(names) >= 4 || header.Typeflag != tar.TypeReg || header.Format != tar.FormatUSTAR || header.Mode != mode || header.Size < 0 || header.Size > artifact.MaxArchiveBytes || header.Linkname != "" || header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" || header.ModTime.Unix() != 0 {
			return value, errors.New("stock CLI archive attributes refused")
		}
		expectedTarBytes += 512 + (header.Size+511)/512*512
		if expectedTarBytes > artifact.MaxArchiveBytes {
			return value, errors.New("stock CLI expanded archive exceeds bound")
		}
		if header.Name == "enkv" && (header.Size == 0 || header.Size > artifact.MaxExecutableBytes) {
			return value, errors.New("stock CLI executable length refused")
		}
		output, err := root.OpenFile(header.Name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(mode))
		if err != nil {
			return value, err
		}
		memberHash := sha256.New()
		n, copyErr := io.CopyBuffer(io.MultiWriter(output, memberHash), archive, window[:])
		closeErr := output.Close()
		if copyErr != nil || closeErr != nil || n != header.Size {
			return value, errors.Join(errors.New("stock CLI member incomplete"), copyErr, closeErr)
		}
		value.members[header.Name] = artifact.DigestLength{SHA256: artifact.Digest(memberHash.Sum(nil)), Length: uint64(n)}
		names = append(names, header.Name)
	}
	expected := []string{"LICENSE", "THIRD_PARTY_NOTICES.md", "enkv"}
	if _, ok := value.members["NOTICE"]; ok {
		expected = append(expected, "NOTICE")
		slices.Sort(expected)
	}
	if !slices.Equal(names, expected) || expanded.length != expectedTarBytes {
		return value, errors.New("stock CLI archive member set or tar length refused")
	}
	var extra [1]byte
	if n, err := expanded.Read(extra[:]); n != 0 || err != io.EOF {
		return value, errors.Join(errors.New("stock CLI expanded trailing bytes"), err)
	}
	closed = true
	if err := compressed.Close(); err != nil {
		return value, err
	}
	if _, err := input.ReadByte(); err != io.EOF {
		return value, errors.Join(errors.New("stock CLI compressed trailing bytes"), err)
	}
	if counted.length != before.Size() {
		return value, errors.New("stock CLI compressed length changed")
	}
	after, err := os.Lstat(path)
	final, statErr := file.Stat()
	if err != nil || statErr != nil || !os.SameFile(before, after) || !os.SameFile(before, final) || before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		return value, errors.Join(errors.New("stock CLI archive changed"), err, statErr)
	}
	value.archive = artifact.DigestLength{SHA256: artifact.Digest(digest.Sum(nil)), Length: uint64(counted.length)}
	return value, ctx.Err()
}

func checkStockCLIBuild(info *debug.BuildInfo, packages []artifact.SourcePackage) error {
	if info == nil || info.GoVersion != "go1.27.3" || info.Path != "enkv.sh/compositions/full/cmd/enkv" || info.Main.Path != "enkv.sh/compositions/full" {
		return errors.New("stock CLI build identity refused")
	}
	options, err := artifact.CaptureBuildOptions(info)
	if err != nil {
		return err
	}
	settings := map[string]string{}
	for _, option := range options {
		switch option.Name {
		case "-buildmode", "-compiler", "-trimpath", "CGO_ENABLED", "GOOS", "GOARCH", "DefaultGODEBUG":
		case "GOAMD64":
			if option.Value != "v1" {
				return errors.New("stock CLI architecture setting refused")
			}
		case "GOARM64":
			if option.Value != "v8.0" {
				return errors.New("stock CLI architecture setting refused")
			}
		default:
			return errors.New("stock CLI build setting refused")
		}
		settings[option.Name] = option.Value
	}
	for key, want := range map[string]string{"-buildmode": "exe", "-compiler": "gc", "-trimpath": "true", "CGO_ENABLED": "1", "GOOS": runtime.GOOS, "GOARCH": runtime.GOARCH} {
		if settings[key] != want {
			return errors.New("stock CLI native setting refused")
		}
	}
	if settings["-tags"] != "" || settings["-race"] != "" || settings["-ldflags"] != "" {
		return errors.New("stock CLI build override refused")
	}
	if runtime.GOOS+"/"+runtime.GOARCH != "darwin/arm64" && runtime.GOOS+"/"+runtime.GOARCH != "linux/amd64" {
		return errors.New("stock CLI native tuple refused")
	}
	selected := map[string]*artifact.SourceModule{}
	for _, pkg := range packages {
		if !pkg.Standard {
			if pkg.Module == nil {
				return errors.New("stock CLI selected module missing")
			}
			if previous := selected[pkg.Module.Path]; previous != nil && !reflect.DeepEqual(previous, pkg.Module) {
				return errors.New("stock CLI selected module conflict")
			}
			selected[pkg.Module.Path] = pkg.Module
		}
	}
	main := selected[info.Main.Path]
	if main == nil || !main.Main || info.Main.Version != "(devel)" || info.Main.Sum != "" || info.Main.Replace != nil {
		return errors.New("stock CLI main source identity differs")
	}
	delete(selected, info.Main.Path)
	if len(selected) != len(info.Deps) {
		return errors.New("stock CLI compiled closure differs")
	}
	for _, dependency := range info.Deps {
		source := selected[dependency.Path]
		if source == nil {
			return errors.New("stock CLI compiled module unselected")
		}
		version := source.Version
		if source.Main && version == "" {
			version = "(devel)"
		}
		if dependency.Version != version || dependency.Sum != source.Sum || (dependency.Replace == nil) != (source.Replace == nil) {
			return errors.New("stock CLI compiled identity differs")
		}
		if source.Replace != nil {
			a, b := source.Replace, dependency.Replace
			replacementVersion := a.Version
			if replacementVersion == "" {
				replacementVersion = "(devel)"
			}
			if a.Path != b.Path || replacementVersion != b.Version || a.Sum != b.Sum {
				return errors.New("stock CLI compiled replacement differs")
			}
		}
		delete(selected, dependency.Path)
	}
	if len(selected) != 0 {
		return errors.New("stock CLI selected owner uncompiled")
	}
	for _, required := range []string{"enkv.sh/providers/aws", "enkv.sh/providers/gcp", "enkv.sh/compositions/aws", "enkv.sh/compositions/gcp", "github.com/aws/aws-sdk-go-v2/service/s3", "github.com/aws/aws-sdk-go-v2/service/kms", "google.golang.org/api"} {
		found := false
		for _, dependency := range info.Deps {
			found = found || dependency.Path == required
		}
		if !found {
			return errors.New("stock CLI full provider closure missing")
		}
	}
	return nil
}

func stockCLIFileIdentity(ctx context.Context, path string, maximum int64, immutable bool) (value artifact.DigestLength, identity os.FileInfo, result error) {
	if ctx == nil {
		return value, nil, errors.New("stock CLI context refused")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return value, nil, err
	}
	if !filepath.IsAbs(path) || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maximum || immutable && before.Mode().Perm()&0222 != 0 {
		return value, nil, errors.New("stock CLI file type mode or size refused")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != filepath.Clean(path) {
		return value, nil, errors.Join(errors.New("stock CLI path is not canonical"), err)
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return value, nil, err
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	opened, err := file.Stat()
	if err != nil || !sameStockCLIFile(before, opened) {
		return value, nil, errors.Join(errors.New("stock CLI opened file changed"), err)
	}
	h := sha256.New()
	r := &stockCLIReader{ctx: ctx, reader: io.LimitReader(file, maximum+1)}
	if _, err := io.Copy(h, r); err != nil {
		return value, nil, err
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || before.Size() != r.length || before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		return value, nil, errors.Join(errors.New("stock CLI file changed"), err)
	}
	return artifact.DigestLength{SHA256: artifact.Digest(h.Sum(nil)), Length: uint64(r.length)}, before, ctx.Err()
}

func stockCLILegalMembers(legal map[string][]byte, executable artifact.DigestLength) map[string]artifact.DigestLength {
	result := map[string]artifact.DigestLength{"enkv": executable}
	for name, body := range legal {
		result[name] = artifact.DigestLength{SHA256: artifact.Hash(body), Length: uint64(len(body))}
	}
	return result
}

// These private construction inputs expose no bundle, endpoint, trust-mode,
// alternate command, tag or linker override. Persisted packet admission remains
// a separate owner; decoding JSON cannot create this accepted value.
type stockCLIKeyInput struct {
	path     string
	expected artifact.DigestLength
}

type stockCLIConstruction struct {
	version    string
	cliKey     stockCLIKeyInput
	pluginKeys []stockCLIKeyInput
}

type stockCLIOriginalKey struct {
	path     string
	identity artifact.DigestLength
	file     os.FileInfo
}

type preparedStockCLI struct {
	root, archive, executable, goBinary string
	workspace, goLicense                string
	originalKeys                        []stockCLIOriginalKey
	goIdentity, goLicenseIdentity       artifact.DigestLength
	goFile, goLicenseFile               os.FileInfo
	binding                             preparationBinding
	archiveIdentity, executableIdentity artifact.DigestLength
	archiveFile, executableFile         os.FileInfo
	packagerIdentity                    artifact.DigestLength
	buildEnvironment                    []string
	build                               checkCommandFacts
	packaging                           processResult
	diagnostics                         limitedOutput
	selected                            []artifact.SourcePackage
	members                             map[string]artifact.DigestLength
}

func stockCLIEnvironment(ctx context.Context) ([]string, error) {
	capacity := executionCapacityFromContext(ctx)
	if err := validateExecutionCapacity(capacity); err != nil {
		return nil, err
	}
	for _, key := range []string{"GOEXPERIMENT", "GCCGO", "CC", "CXX", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS", "GOTOOLDIR", "GOCACHEPROG", "GOFIPS140", "GODEBUG"} {
		if os.Getenv(key) != "" {
			return nil, errors.New("stock CLI custom compiler input refused")
		}
	}
	for key, want := range map[string]string{"GOOS": runtime.GOOS, "GOARCH": runtime.GOARCH} {
		if v := os.Getenv(key); v != "" && v != want {
			return nil, errors.New("stock CLI cross-build refused")
		}
	}
	var base []string
	for _, key := range []string{"PATH", "HOME", "TMPDIR", "TMP", "TEMP", "GOPATH", "GOCACHE", "GOMODCACHE", "GOTMPDIR", "SDKROOT", "MACOSX_DEPLOYMENT_TARGET", "SYSTEMROOT", "WINDIR"} {
		if value, ok := os.LookupEnv(key); ok {
			base = append(base, key+"="+value)
		}
	}
	return environment(base, map[string]string{"GOENV": "off", "GO111MODULE": "on", "GOTOOLCHAIN": "local", "GOFLAGS": "", "GOEXPERIMENT": "", "CGO_ENABLED": "1", "GOOS": runtime.GOOS, "GOARCH": runtime.GOARCH, "GOAMD64": "v1", "GOARM64": "v8.0", "GOPROXY": "off", "GOSUMDB": "off", "GONOPROXY": "none", "GOMAXPROCS": strconv.Itoa(capacity.Parallel)}), nil
}

func stockCLIProcess(ctx context.Context, binary, directory string, env []string, args ...string) ([]byte, []byte, processResult, error) {
	var stdout, stderr limitedOutput
	process := runProcessOutput(ctx, binary, directory, args, env, preparationCommandTimeout, &stdout, &stderr)
	if process.Status != "passed" || !process.Started || !process.Joined || stdout.overflow || stderr.overflow {
		failure := &toolFailure{operation: "stock CLI preparation", process: process}
		if process.Joined {
			failure.stdout = slices.Clone(stdout.Bytes())
			failure.stderr = slices.Clone(stderr.Bytes())
			failure.overflow = stdout.overflow || stderr.overflow
		}
		return nil, nil, process, failure
	}
	return slices.Clone(stdout.Bytes()), slices.Clone(stderr.Bytes()), process, nil
}

func stockCLISelected(ctx context.Context, root, goBinary, directory, command string, env []string, diagnostics *limitedOutput) ([]artifact.SourcePackage, error) {
	if command != "./cmd/enkv" && command != "./cmd/enkv-cli-package" {
		return nil, errors.New("stock CLI source command refused")
	}
	expectedMain := "enkv.sh/compositions/full/" + strings.TrimPrefix(command, "./")
	body, diagnostic, _, err := stockCLIProcess(ctx, goBinary, directory, env, "list", "-mod=readonly", "-trimpath", "-buildvcs=false", "-deps", "-json", command)
	if err != nil {
		return nil, err
	}
	if _, err := diagnostics.Write(diagnostic); err != nil {
		return nil, err
	}
	if diagnostics.overflow {
		return nil, errors.New("stock CLI preparation diagnostics exceed bound")
	}
	packages, err := decodeObjects[artifact.SourcePackage](body)
	if err != nil {
		return nil, err
	}
	main := 0
	for _, pkg := range packages {
		if pkg.Standard {
			continue
		}
		if pkg.Module == nil {
			return nil, errors.New("stock CLI source owner missing")
		}
		module := pkg.Module
		actual := module
		if module.Replace != nil {
			actual = module.Replace
			if actual.Replace != nil {
				return nil, errors.New("stock CLI nested source replacement refused")
			}
		}
		local := module.Main || actual.Version == "" || actual.Version == "(devel)"
		if local {
			row, ok := registeredModule(module.Path)
			if !ok {
				return nil, errors.New("stock CLI foreign local source refused")
			}
			want, err := moduleSourceDirectory(root, row)
			if err != nil {
				return nil, err
			}
			got, err := filepath.EvalSymlinks(actual.Dir)
			if err != nil || got != want {
				return nil, errors.Join(errors.New("stock CLI local source differs"), err)
			}
		} else if module.Version == "" || module.Sum == "" || module.Replace != nil && (actual.Version == "" || actual.Sum == "") {
			return nil, errors.New("stock CLI versioned source identity missing")
		}
		if pkg.Name == "main" {
			if pkg.ImportPath != expectedMain || module.Path != "enkv.sh/compositions/full" {
				return nil, errors.New("stock CLI main source differs")
			}
			main++
		}
	}
	if main != 1 {
		return nil, errors.New("stock CLI main source missing")
	}
	return packages, nil
}

func prepareStockCLI(ctx context.Context, root, directory string, construction stockCLIConstruction, original preparationBinding) (preparedStockCLI, error) {
	keys := []artifact.DigestLength{construction.cliKey.expected}
	for _, key := range construction.pluginKeys {
		keys = append(keys, key.expected)
	}
	value, _, err := invocationArtifactValue(ctx, root, filepath.Dir(directory), "stock-cli", struct {
		Version string
		Keys    []artifact.DigestLength
	}{construction.version, keys}, func(build string) (preparedStockCLI, error) {
		return constructStockCLI(ctx, root, filepath.Join(build, "cli"), construction, original)
	})
	return value, err
}

func constructStockCLI(ctx context.Context, root, directory string, construction stockCLIConstruction, original preparationBinding) (value preparedStockCLI, result error) {
	construction.pluginKeys = slices.Clone(construction.pluginKeys)
	if ctx == nil || !original.live || !artifact.ValidVersion(construction.version) || len(construction.pluginKeys) == 0 || len(construction.pluginKeys) > 63 {
		return value, errors.New("stock CLI construction inputs refused")
	}
	if _, ok := ctx.Deadline(); !ok {
		return value, errors.New("stock CLI finite preparation deadline required")
	}
	if original.toolchain != "go version go1.27.3 "+runtime.GOOS+"/"+runtime.GOARCH {
		return value, errors.New("stock CLI compiler refused")
	}
	if err := original.checkRace(ctx); err != nil {
		return value, err
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return value, errors.New("stock CLI preparation directory refused")
	}
	for _, checkout := range []string{root, filepath.Join(filepath.Dir(root), original.source.PublicRepository)} {
		relative, err := filepath.Rel(checkout, directory)
		if err != nil || relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return value, errors.New("stock CLI preparation must be outside source checkouts")
		}
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		return value, err
	}
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil || canonical != directory {
		return value, errors.Join(errors.New("stock CLI preparation directory is not canonical"), err)
	}
	env, err := stockCLIEnvironment(ctx)
	if err != nil {
		return value, err
	}
	slices.Sort(env)
	value.buildEnvironment = slices.Clone(env)
	goBinary, err := exec.LookPath("go")
	if err != nil {
		return value, err
	}
	goBinary, err = filepath.EvalSymlinks(goBinary)
	if err != nil {
		return value, err
	}
	goRoot := original.environment["GOROOT"]
	if goBinary != filepath.Join(goRoot, "bin/go") {
		return value, errors.New("stock CLI executing compiler differs from admitted toolchain")
	}
	value.root, value.goBinary = root, goBinary
	value.goLicense = filepath.Join(goRoot, "LICENSE")
	value.goIdentity, value.goFile, err = stockCLIFileIdentity(ctx, goBinary, artifact.MaxExecutableBytes, false)
	if err != nil {
		return value, err
	}
	value.goLicenseIdentity, value.goLicenseFile, err = stockCLIFileIdentity(ctx, value.goLicense, artifact.MaxArchiveBytes, false)
	if err != nil {
		return value, err
	}
	inputs := filepath.Join(directory, "inputs")
	if err := os.Mkdir(inputs, 0700); err != nil {
		return value, err
	}
	cliKey := filepath.Join(inputs, "cli-public.pem")
	originalKey, err := snapshotStockCLIKey(ctx, construction.cliKey, cliKey)
	if err != nil {
		return value, err
	}
	value.originalKeys = append(value.originalKeys, originalKey)
	var pluginKeys []string
	for i, key := range construction.pluginKeys {
		owned := filepath.Join(inputs, fmt.Sprintf("plugin-public-%02d.pem", i))
		originalKey, err := snapshotStockCLIKey(ctx, key, owned)
		if err != nil {
			return value, err
		}
		value.originalKeys = append(value.originalKeys, originalKey)
		pluginKeys = append(pluginKeys, owned)
	}
	value.workspace, err = stockCLIWorkspace(ctx, root, goBinary, inputs, env, &value.diagnostics)
	if err != nil {
		return value, err
	}

	value.binding = original

	full, err := sourcePath(root, "compositions/full")
	if err != nil {
		return value, err
	}
	env = environment(env, map[string]string{"GOWORK": value.workspace})
	before, err := stockCLISelected(ctx, root, goBinary, full, "./cmd/enkv", env, &value.diagnostics)
	if err != nil {
		return value, err
	}
	legal, err := artifact.CollectLegalFiles(ctx, before, "enkv.sh/compositions/full", goRoot)
	if err != nil {
		return value, err
	}
	tool := filepath.Join(directory, "enkv-cli-package")
	toolEnv := environment(env, map[string]string{"GOWORK": "off"})
	_, value.build, err = runGoRecordedEnvironment(ctx, root, "compositions/full", toolEnv, "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", tool, "./cmd/enkv-cli-package")
	if err != nil || value.build.Process != "passed" || !value.build.Started || !value.build.Joined {
		return value, errors.Join(errors.New("stock CLI packager build refused"), err)
	}
	if err := os.Chmod(tool, 0555); err != nil {
		return value, err
	}

	value.packagerIdentity, _, err = stockCLIFileIdentity(ctx, tool, artifact.MaxExecutableBytes, true)
	if err != nil {
		return value, err
	}
	if err := value.binding.checkRace(ctx); err != nil {
		return value, err
	}
	output := filepath.Join(directory, "package")
	args := []string{"-directory", full, "-bundle", "full", "-version", construction.version, "-workspace", value.workspace, "-environment", "production", "-cli-public-key", cliKey, "-output", output}
	for _, key := range pluginKeys {
		args = append(args, "-plugin-public-key", key)
	}
	var diagnostic []byte
	_, diagnostic, value.packaging, err = stockCLIProcess(ctx, tool, directory, environment(env, map[string]string{"GOWORK": "off"}), args...)
	if err != nil {
		return value, err
	}
	if _, err := value.diagnostics.Write(diagnostic); err != nil {
		return value, err
	}
	if value.diagnostics.overflow {
		return value, errors.New("stock CLI preparation diagnostics exceed bound")
	}
	filename := "enkv-full-" + strings.ReplaceAll(construction.version, "+", "_") + "-" + runtime.GOOS + "-" + runtime.GOARCH + ".tar.gz"
	entries, err := os.ReadDir(output)
	if err != nil {
		return value, err
	}
	if len(entries) != 2 || entries[0].Name() != "checksums.txt" || entries[1].Name() != filename {
		return value, errors.New("stock CLI package output differs")
	}
	value.archive = filepath.Join(output, filename)
	checksums, err := stockCLIChecksums(ctx, filepath.Join(output, "checksums.txt"))
	if err != nil || len(checksums) > artifact.MaxRecordBytes {
		return value, errors.Join(errors.New("stock CLI checksum output refused"), err)
	}
	rows, err := artifact.DecodeChecksums(checksums)
	if err != nil || len(rows) != 1 || rows[0].Name != filename {
		return value, errors.Join(errors.New("stock CLI checksum member differs"), err)
	}
	installed := filepath.Join(directory, "installed")
	if err := os.Mkdir(installed, 0700); err != nil {
		return value, err
	}
	archive, err := extractStockCLIArchive(ctx, value.archive, installed)
	if err != nil {
		return value, err
	}
	if archive.archive.SHA256 != rows[0].Digest {
		return value, errors.New("stock CLI checksum differs from actual archive")
	}
	value.executable = filepath.Join(installed, "enkv")
	identity, openedIdentity, err := stockCLIFileIdentity(ctx, value.executable, artifact.MaxExecutableBytes, false)
	if err != nil {
		return value, err
	}
	info, err := stockCLIExecutableInfo(ctx, value.executable, openedIdentity)
	if err != nil {
		return value, err
	}
	if err := checkStockCLIBuild(info, before); err != nil {
		return value, err
	}
	if !reflect.DeepEqual(archive.members, stockCLILegalMembers(legal, identity)) {
		return value, errors.New("stock CLI archive members differ from exact source owners")
	}
	if err := os.Chmod(value.archive, 0444); err != nil {
		return value, err
	}
	if err := os.Chmod(value.executable, 0555); err != nil {
		return value, err
	}
	value.archiveIdentity, value.archiveFile, err = stockCLIFileIdentity(ctx, value.archive, artifact.MaxArchiveBytes, true)
	if err != nil || value.archiveIdentity != archive.archive {
		return value, errors.Join(errors.New("stock CLI archive changed during construction"), err)
	}
	value.executableIdentity, value.executableFile, err = stockCLIFileIdentity(ctx, value.executable, artifact.MaxExecutableBytes, true)
	if err != nil || value.executableIdentity != identity {
		return value, errors.Join(errors.New("stock CLI executable changed during construction"), err)
	}
	sumPath := value.workspace + ".sum"
	sumInfo, sumErr := os.Lstat(sumPath)
	if !errors.Is(sumErr, os.ErrNotExist) {
		if sumErr != nil {
			return value, sumErr
		}
		if _, _, err := readPublicConfigurationFile(sumPath, artifact.MaxMetadataBytes, sumInfo.Mode().Perm()); err != nil {
			return value, err
		}
		if err := os.Chmod(sumPath, 0400); err != nil {
			return value, err
		}

	}
	value.selected, value.members = before, archive.members
	return value, nil
}

func (value preparedStockCLI) verify(ctx context.Context) error {
	if value.root == "" || value.archiveFile == nil || value.executableFile == nil || value.build.Process != "passed" || !value.build.Started || !value.build.Joined || value.packaging.Status != "passed" || !value.packaging.Started || !value.packaging.Joined {
		return errors.New("stock CLI production construction missing")
	}
	if err := value.binding.checkRace(ctx); err != nil {
		return err
	}
	for _, key := range value.originalKeys {
		if err := key.verify(ctx); err != nil {
			return err
		}
	}
	for _, subject := range []struct {
		path     string
		maximum  int64
		identity artifact.DigestLength
		file     os.FileInfo
	}{{value.goBinary, artifact.MaxExecutableBytes, value.goIdentity, value.goFile}, {value.goLicense, artifact.MaxArchiveBytes, value.goLicenseIdentity, value.goLicenseFile}} {
		identity, file, err := stockCLIFileIdentity(ctx, subject.path, subject.maximum, false)
		if err != nil || identity != subject.identity || !sameStockCLIFile(subject.file, file) {
			return errors.Join(errors.New("stock CLI compiler source changed"), err)
		}
	}
	env, err := stockCLIEnvironment(ctx)
	if err != nil {
		return err
	}
	slices.Sort(env)
	if !slices.Equal(env, value.buildEnvironment) {
		return errors.New("stock CLI construction environment changed")
	}
	archive, archiveFile, err := stockCLIFileIdentity(ctx, value.archive, artifact.MaxArchiveBytes, true)
	if err != nil || archive != value.archiveIdentity || !sameStockCLIFile(value.archiveFile, archiveFile) {
		return errors.Join(errors.New("stock CLI admitted archive changed"), err)
	}
	executable, executableFile, err := stockCLIFileIdentity(ctx, value.executable, artifact.MaxExecutableBytes, true)
	if err != nil || executable != value.executableIdentity || !sameStockCLIFile(value.executableFile, executableFile) {
		return errors.Join(errors.New("stock CLI admitted executable changed"), err)
	}
	return nil
}

func stockCLIChecksums(ctx context.Context, path string) (body []byte, result error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > artifact.MaxRecordBytes {
		return nil, errors.New("stock CLI checksum file type or bound refused")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	opened, err := file.Stat()
	if err != nil || !sameStockCLIFile(before, opened) {
		return nil, errors.Join(errors.New("stock CLI checksum file changed"), err)
	}
	body, err = io.ReadAll(io.LimitReader(&stockCLIReader{ctx: ctx, reader: file}, artifact.MaxRecordBytes+1))
	if err != nil || int64(len(body)) != before.Size() {
		return nil, errors.Join(errors.New("stock CLI checksum file incomplete"), err)
	}
	after, err := os.Lstat(path)
	if err != nil || !sameStockCLIFile(before, after) {
		return nil, errors.Join(errors.New("stock CLI checksum file changed"), err)
	}
	return body, ctx.Err()
}

func stockCLIExecutableInfo(ctx context.Context, path string, want os.FileInfo) (info *debug.BuildInfo, result error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	opened, err := file.Stat()
	if err != nil || !sameStockCLIFile(want, opened) {
		return nil, errors.Join(errors.New("stock CLI BuildInfo subject changed"), err)
	}
	info, err = buildinfo.Read(file)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !sameStockCLIFile(want, after) || !sameStockCLIFile(want, pathInfo) {
		return nil, errors.Join(errors.New("stock CLI BuildInfo subject changed"), err, pathErr)
	}
	return info, ctx.Err()
}

func sameStockCLIFile(first, second os.FileInfo) bool {
	return records.SameLocalFile(first, second) && first.Mode() == second.Mode() && first.Size() == second.Size() && first.ModTime().Equal(second.ModTime())
}

func snapshotStockCLIKey(ctx context.Context, input stockCLIKeyInput, owned string) (value stockCLIOriginalKey, result error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(input.path) || input.expected.Length == 0 || input.expected.Length > 4096 {
		return value, errors.New("stock CLI public key reference refused")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(input.path))
	if err != nil {
		return value, err
	}
	path := filepath.Join(parent, filepath.Base(input.path))
	before, err := os.Lstat(path)
	if err != nil {
		return value, err
	}
	body, identity, err := readPublicConfigurationFile(path, 4096, before.Mode().Perm())
	if err != nil {
		return value, err
	}
	defer clear(body[:cap(body)])
	observed := artifact.DigestLength{SHA256: artifact.Hash(body), Length: uint64(len(body))}
	if observed != input.expected {
		return value, errors.New("stock CLI public key identity differs")
	}
	if _, err := artifact.ParsePublicKeyPEM(body); err != nil {
		return value, errors.New("stock CLI public key refused")
	}
	output, err := os.OpenFile(owned, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0400)
	if err != nil {
		return value, err
	}
	n, writeErr := output.Write(body)
	if err := errors.Join(writeErr, output.Close()); err != nil {
		return value, err
	}
	if n != len(body) {
		return value, io.ErrShortWrite
	}
	return stockCLIOriginalKey{path: input.path, identity: observed, file: identity}, ctx.Err()
}

func (value stockCLIOriginalKey) verify(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || value.file == nil {
		return errors.New("stock CLI public key input unavailable")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(value.path))
	if err != nil {
		return err
	}
	path := filepath.Join(parent, filepath.Base(value.path))
	body, identity, err := readPublicConfigurationFile(path, 4096, value.file.Mode().Perm())
	if err != nil {
		return err
	}
	defer clear(body[:cap(body)])
	if !sameStockCLIFile(value.file, identity) || value.identity != (artifact.DigestLength{SHA256: artifact.Hash(body), Length: uint64(len(body))}) {
		return errors.New("stock CLI original public key changed")
	}
	return ctx.Err()
}

// This is the fixed registered-owner recipe from publicPluginBuildWorkspace,
// without its testing dependency or support for arbitrary caller module roots.
// Go's own mod-edit JSON supplies parsed requirements; no Go file parser is added.
func stockCLIWorkspace(ctx context.Context, root, goBinary, inputs string, env []string, diagnostics *limitedOutput) (string, error) {
	const maximumWorkspaceBytes = artifact.MaxMetadataBytes
	type requirement struct{ Path, Version string }
	owners := make(map[string]string, len(moduleSources))
	for _, row := range moduleSources {
		directory, err := moduleSourceDirectory(root, row)
		if err != nil {
			return "", err
		}
		if owners[row.Module] != "" {
			return "", errors.New("stock CLI registered owner repeats")
		}
		owners[row.Module] = directory
	}
	var work strings.Builder
	work.WriteString("go 1.27.0\n\nuse (\n")
	seen := map[requirement]bool{}
	var replacements []requirement
	account := 0
	for _, row := range moduleSources {
		directory := owners[row.Module]
		body, diagnostic, _, err := stockCLIProcess(ctx, goBinary, directory, environment(env, map[string]string{"GOWORK": "off"}), "mod", "edit", "-json", filepath.Join(directory, "go.mod"))
		if err != nil {
			return "", err
		}
		if _, err := diagnostics.Write(diagnostic); err != nil {
			return "", err
		}
		if diagnostics.overflow {
			return "", errors.New("stock CLI preparation diagnostics exceed bound")
		}
		var parsed struct {
			Module  struct{ Path string }
			Require []requirement
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return "", err
		}
		if parsed.Module.Path != row.Module {
			return "", errors.New("stock CLI registered module identity differs")
		}
		fmt.Fprintf(&work, "\t%q\n", filepath.ToSlash(directory))
		for _, required := range parsed.Require {
			if owners[required.Path] == "" || seen[required] {
				continue
			}
			account += len(required.Path) + len(required.Version) + len(owners[required.Path]) + 32
			if account > maximumWorkspaceBytes {
				return "", errors.New("stock CLI workspace requirements exceed bound")
			}
			seen[required] = true
			replacements = append(replacements, required)
		}
		if work.Len()+account > maximumWorkspaceBytes {
			return "", errors.New("stock CLI workspace exceeds bound")
		}
	}
	work.WriteString(")\n")
	slices.SortFunc(replacements, func(a, b requirement) int {
		if n := strings.Compare(a.Path, b.Path); n != 0 {
			return n
		}
		return strings.Compare(a.Version, b.Version)
	})
	if len(replacements) != 0 {
		work.WriteString("\nreplace (\n")
		for _, required := range replacements {
			fmt.Fprintf(&work, "\t%s %s => %q\n", required.Path, required.Version, filepath.ToSlash(owners[required.Path]))
		}
		work.WriteString(")\n")
	}
	if work.Len() > maximumWorkspaceBytes {
		return "", errors.New("stock CLI workspace exceeds bound")
	}
	path := filepath.Join(inputs, "go.work")
	if err := os.WriteFile(path, []byte(work.String()), 0400); err != nil {
		return "", err
	}
	return path, nil
}

type stockCLIFacts struct {
	archivePath, executablePath string
	archive, executable         artifact.DigestLength
	nativeTuple, compiler       string
	source                      records.Source
}

func (value preparedStockCLI) facts() stockCLIFacts {
	source := value.binding.source
	source.PublicPaths = slices.Clone(source.PublicPaths)
	if source.DirtyDiffSHA256 != nil {
		copy := *source.DirtyDiffSHA256
		source.DirtyDiffSHA256 = &copy
	}
	return stockCLIFacts{archivePath: value.archive, executablePath: value.executable, archive: value.archiveIdentity, executable: value.executableIdentity, nativeTuple: runtime.GOOS + "/" + runtime.GOARCH, compiler: "go1.27.3", source: source}
}

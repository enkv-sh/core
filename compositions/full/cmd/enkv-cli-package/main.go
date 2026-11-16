package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"enkv.sh/sdk/artifact"
)

type config struct {
	directory, bundle, version, workspace, environment, cliKey, origin, tlsRoot, output string
	pluginKeys                                                                          []string
	versioned                                                                           bool
	diagnostic                                                                          io.Writer
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	c := config{diagnostic: stderr}
	var checksums string
	flags := flag.NewFlagSet("enkv-cli-package", flag.ContinueOnError)
	var flagOutput bytes.Buffer
	flags.SetOutput(&flagOutput)
	flags.StringVar(&c.directory, "directory", "", "full composition module directory")
	flags.StringVar(&c.bundle, "bundle", "", "full, aws or gcp")
	flags.StringVar(&c.version, "version", "", "semantic version without v")
	flags.StringVar(&c.workspace, "workspace", "", "absolute coordinated go.work file")
	flags.BoolVar(&c.versioned, "versioned", false, "disable workspace and require versioned dependencies")
	flags.StringVar(&c.environment, "environment", "", "development or production")
	flags.Func("plugin-public-key", "SPKI PEM plugin public key; repeat for retained roots", func(value string) error { c.pluginKeys = append(c.pluginKeys, value); return nil })
	flags.StringVar(&c.cliKey, "cli-public-key", "", "distinct SPKI PEM CLI public key")
	flags.StringVar(&c.origin, "development-origin", "", "controlled loopback HTTPS catalog with trailing slash")
	flags.StringVar(&c.tlsRoot, "development-tls-root", "", "controlled catalog TLS certificate PEM")
	flags.StringVar(&c.output, "output", "", "new output directory")
	flags.StringVar(&checksums, "checksums", "", "write a new checksum file for positional archive paths")
	parseErr := flags.Parse(args)
	if err := writeText(stderr, flagOutput.String()); err != nil {
		return 1
	}
	if parseErr != nil {
		if errors.Is(parseErr, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	var err error
	if checksums != "" {
		count := 0
		flags.Visit(func(*flag.Flag) { count++ })
		if count != 1 || flags.NArg() == 0 {
			return diagnosticExit(stderr, "checksums requires only archive paths", 2)
		}
		err = aggregateChecksums(ctx, checksums, flags.Args())
	} else {
		if flags.NArg() != 0 {
			return diagnosticExit(stderr, "unexpected positional arguments", 2)
		}
		err = packageCLI(ctx, c, stdout)
	}
	if err != nil {
		return diagnosticExit(stderr, err.Error(), 1)
	}
	return 0
}

func diagnosticExit(output io.Writer, message string, code int) int {
	if err := writeText(output, message+"\n"); err != nil {
		return 1
	}
	return code
}

func writeText(output io.Writer, text string) error {
	if text == "" {
		return nil
	}
	n, err := io.WriteString(output, text)
	if err != nil {
		return err
	}
	if n != len(text) {
		return io.ErrShortWrite
	}
	return nil
}

func assemblyFlags(ctx context.Context, c config) (string, error) {
	if c.directory == "" || c.output == "" || !artifact.ValidVersion(c.version) {
		return "", errors.New("directory, output and semantic version are required")
	}
	if c.bundle != "full" && c.bundle != "aws" && c.bundle != "gcp" {
		return "", errors.New("bundle must be full, aws or gcp")
	}
	cli, err := publicKey(ctx, c.cliKey)
	if err != nil {
		return "", fmt.Errorf("CLI public key: %w", err)
	}
	if len(c.pluginKeys) == 0 {
		return "", errors.New("plugin public key is required")
	}
	var keys []string
	for _, path := range c.pluginKeys {
		key, err := publicKey(ctx, path)
		if err != nil {
			return "", fmt.Errorf("plugin public key: %w", err)
		}
		if key == cli || slices.Contains(keys, key) {
			return "", errors.New("plugin roots must be unique and differ from CLI root")
		}
		keys = append(keys, key)
	}
	slices.Sort(keys)
	if len(strings.Join(keys, ",")) > 4096 {
		return "", errors.New("plugin roots exceed assembly limit")
	}
	origin, redirects, roots := "https://enkv.sh/releases/", "github.com,release-assets.githubusercontent.com", ""
	switch c.environment {
	case "production":
		if c.origin != "" || c.tlsRoot != "" {
			return "", errors.New("production uses fixed origin and system TLS roots")
		}
	case "development":
		parsed, err := url.Parse(c.origin)
		if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawPath != "" || !strings.HasSuffix(parsed.Path, "/") || len(c.origin) > 4096 || strings.ContainsAny(c.origin, " \t\r\n\"'\\") {
			return "", errors.New("development requires a loopback HTTPS catalog with trailing slash")
		}
		ip := net.ParseIP(parsed.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return "", errors.New("development catalog must use a loopback IP")
		}
		if port := parsed.Port(); port != "" {
			value, err := strconv.ParseUint(port, 10, 16)
			if err != nil || value == 0 || strconv.FormatUint(value, 10) != port {
				return "", errors.New("invalid development catalog port")
			}
		} else if strings.HasSuffix(parsed.Host, ":") {
			return "", errors.New("invalid development catalog port")
		}
		body, err := readRegular(ctx, c.tlsRoot, 96*1024)
		if err != nil {
			return "", err
		}
		if len(body) == 0 {
			return "", errors.New("development TLS root is required")
		}
		remaining := body
		for len(remaining) != 0 {
			if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----\n")) {
				return "", errors.New("invalid TLS certificate PEM")
			}
			block, rest := pem.Decode(remaining)
			if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				return "", errors.New("invalid TLS certificate PEM")
			}
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return "", err
			}
			remaining = rest
		}
		origin, redirects, roots = c.origin, "", base64.StdEncoding.EncodeToString(body)
	default:
		return "", errors.New("environment must be development or production")
	}
	values := []struct{ name, value string }{{"installedPluginOrigin", origin}, {"installedPluginKeys", strings.Join(keys, ",")}, {"installedCLIVerificationKey", cli}, {"installedPluginRedirectHosts", redirects}, {"installedPluginTLSRoots", roots}}
	var flags []string
	for _, row := range values {
		flags = append(flags, "-X=enkv.sh/compositions/full."+row.name+"="+row.value)
	}
	return strings.Join(flags, " "), nil
}

func publicKey(ctx context.Context, path string) (string, error) {
	body, err := readRegular(ctx, path, 4096)
	if err != nil {
		return "", err
	}
	key, err := artifact.ParsePublicKeyPEM(body)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

func buildEnvironment(c config) ([]string, error) {
	tuple := runtime.GOOS + "/" + runtime.GOARCH
	if tuple != "darwin/arm64" && tuple != "linux/amd64" {
		return nil, errors.New("unsupported native platform")
	}
	for _, row := range []struct{ key, want string }{{"GOOS", runtime.GOOS}, {"GOARCH", runtime.GOARCH}} {
		if value := os.Getenv(row.key); value != "" && value != row.want {
			return nil, errors.New("cross-builds are unsupported")
		}
	}
	for _, key := range []string{"GOFLAGS", "GOEXPERIMENT", "GCCGO", "CC", "CXX", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS", "GOTOOLDIR", "GOCACHEPROG", "GOFIPS140", "GODEBUG"} {
		if os.Getenv(key) != "" {
			return nil, fmt.Errorf("custom compiler input %s is unsupported", key)
		}
	}
	workspace := "off"
	if c.versioned {
		if c.workspace != "" {
			return nil, errors.New("versioned mode cannot select a workspace")
		}
	} else {
		if !filepath.IsAbs(c.workspace) {
			return nil, errors.New("source mode requires an absolute workspace file")
		}
		info, err := os.Lstat(c.workspace)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, errors.New("workspace must be a regular file")
		}
		workspace = c.workspace
	}
	fixed := map[string]string{"GOENV": "off", "GO111MODULE": "on", "GOTOOLCHAIN": "local", "GOWORK": workspace, "GOFLAGS": "", "GOEXPERIMENT": "", "CGO_ENABLED": "1", "GOOS": runtime.GOOS, "GOARCH": runtime.GOARCH, "GOAMD64": "v1", "GOARM64": "v8.0"}
	var result []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, ok := fixed[key]; !ok {
			result = append(result, entry)
		}
	}
	for key, value := range fixed {
		result = append(result, key+"="+value)
	}
	slices.Sort(result)
	return result, nil
}

type commandBuffer struct{ buffer bytes.Buffer }

func (b *commandBuffer) Write(body []byte) (int, error) {
	if b.buffer.Len()+len(body) > 64<<20 {
		return 0, errors.New("go command output exceeds limit")
	}
	return b.buffer.Write(body)
}

var errGoCommandUnsettled = errors.New("go command work did not settle")

func goCommand(ctx context.Context, c config, environment []string, args ...string) ([]byte, error) {
	cmd := exec.Command("go", args...)
	cmd.Dir, cmd.Env = c.directory, environment
	var output, diagnostic commandBuffer
	cmd.Stdout, cmd.Stderr = &output, &diagnostic
	settled, err := runGoCommand(ctx, cmd)
	if !settled {
		return nil, fmt.Errorf("go %s: %w", args[0], errors.Join(errGoCommandUnsettled, err))
	}
	if err != nil {
		return nil, fmt.Errorf("go %s: %w: %s", args[0], err, strings.TrimSpace(diagnostic.buffer.String()))
	}
	if diagnostic.buffer.Len() != 0 {
		if _, err := io.Copy(c.diagnostic, &diagnostic.buffer); err != nil {
			return nil, fmt.Errorf("write Go command diagnostics: %w", err)
		}
	}
	return output.buffer.Bytes(), nil
}
func buildArguments(verb string, c config) []string {
	args := []string{verb, "-mod=readonly", "-trimpath", "-buildvcs=false"}
	if c.bundle != "full" {
		args = append(args, "-tags=enkv_"+c.bundle)
	}
	return args
}
func selectedPackages(ctx context.Context, c config, environment []string) ([]artifact.SourcePackage, error) {
	args := append(buildArguments("list", c), "-deps", "-json", "./cmd/enkv")
	body, err := goCommand(ctx, c, environment, args...)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	var result []artifact.SourcePackage
	main := 0
	for {
		var pkg artifact.SourcePackage
		err := decoder.Decode(&pkg)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if !pkg.Standard {
			if pkg.Module == nil {
				return nil, errors.New("selected package has no source module")
			}
			if c.versioned && (!pkg.Module.Main && pkg.Module.Version == "" || pkg.Module.Replace != nil && pkg.Module.Replace.Version == "") {
				return nil, errors.New("versioned dependencies require real versions")
			}
		}
		if pkg.Name == "main" {
			if pkg.ImportPath != "enkv.sh/compositions/full/cmd/enkv" || pkg.Module == nil || pkg.Module.Path != "enkv.sh/compositions/full" {
				return nil, errors.New("directory must contain the full composition CLI")
			}
			main++
		}
		result = append(result, pkg)
	}
	if main != 1 {
		return nil, errors.New("full composition CLI main is missing")
	}
	if c.versioned {
		body, err := goCommand(ctx, c, environment, "list", "-mod=readonly", "-m", "-json", "all")
		if err != nil {
			return nil, err
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		for {
			var module artifact.SourceModule
			err := decoder.Decode(&module)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, err
			}
			if !module.Main && (module.Version == "" || module.Version == "(devel)") || module.Replace != nil && (module.Replace.Version == "" || module.Replace.Version == "(devel)") {
				return nil, errors.New("versioned dependencies require real versions")
			}
		}
	}
	return result, nil
}

func packageCLI(ctx context.Context, c config, stdout io.Writer) (result error) {
	link, err := assemblyFlags(ctx, c)
	if err != nil {
		return err
	}
	environment, err := buildEnvironment(c)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(c.output); !errors.Is(err, os.ErrNotExist) {
		return errors.Join(errors.New("output directory must not exist"), err)
	}
	version, err := goCommand(ctx, c, environment, "env", "GOVERSION")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(version)) != "go1.27.3" {
		return errors.New("go1.27.3 is required")
	}
	goRoot, err := goCommand(ctx, c, environment, "env", "GOROOT")
	if err != nil {
		return err
	}
	before, err := selectedPackages(ctx, c, environment)
	if err != nil {
		return err
	}
	legal, err := artifact.CollectLegalFiles(ctx, before, "enkv.sh/compositions/full", strings.TrimSpace(string(goRoot)))
	if err != nil {
		return err
	}
	temporary, err := os.MkdirTemp("", "enkv-cli-package-")
	if err != nil {
		return err
	}
	defer func() {
		if errors.Is(result, errGoCommandUnsettled) {
			result = fmt.Errorf("CLI package scratch retained at %s: %w", temporary, result)
			return
		}
		result = errors.Join(result, os.RemoveAll(temporary))
	}()
	executable := filepath.Join(temporary, "enkv")
	args := append(buildArguments("build", c), "-ldflags="+link, "-o", executable, "./cmd/enkv")
	if _, err := goCommand(ctx, c, environment, args...); err != nil {
		return err
	}
	info, err := buildinfo.ReadFile(executable)
	if err != nil {
		return err
	}
	if info.Path != "enkv.sh/compositions/full/cmd/enkv" || info.Main.Path != "enkv.sh/compositions/full" || info.GoVersion != "go1.27.3" {
		return errors.New("compiled executable identity differs")
	}
	if err := checkCompiledModules(before, info.Main.Path, info.Deps); err != nil {
		return err
	}
	after, err := selectedPackages(ctx, c, environment)
	if err != nil {
		return err
	}
	afterLegal, err := artifact.CollectLegalFiles(ctx, after, info.Main.Path, strings.TrimSpace(string(goRoot)))
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(legal, afterLegal) {
		return errors.New("selected closure or legal files changed during build")
	}
	filename := "enkv-" + c.bundle + "-" + strings.ReplaceAll(c.version, "+", "_") + "-" + runtime.GOOS + "-" + runtime.GOARCH + ".tar.gz"
	if err := os.Mkdir(c.output, 0755); err != nil {
		return err
	}
	root, err := os.OpenRoot(c.output)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, root.Close()) }()
	output, err := root.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	hash := sha256.New()
	err = writeArchive(ctx, io.MultiWriter(output, hash), executable, legal)
	if err := errors.Join(err, output.Close()); err != nil {
		return err
	}
	checksum, err := artifact.EncodeChecksums([]artifact.Checksum{{Name: filename, Digest: artifact.Digest(hash.Sum(nil))}})
	if err != nil {
		return err
	}
	if err := writeNew(root, "checksums.txt", checksum); err != nil {
		return err
	}
	mode := "workspace"
	if c.versioned {
		mode = "versioned"
	}
	summary := fmt.Sprintf("bundle=%s platform=%s environment=%s source_mode=%s toolchain=%s modules=%d\n%s", c.bundle, runtime.GOOS+"/"+runtime.GOARCH, c.environment, mode, info.GoVersion, len(info.Deps)+1, checksum)
	return writeText(stdout, summary)
}

func checkCompiledModules(packages []artifact.SourcePackage, main string, dependencies []*debug.Module) error {
	selected := map[string]*artifact.SourceModule{}
	for _, pkg := range packages {
		if !pkg.Standard {
			selected[pkg.Module.Path] = pkg.Module
		}
	}
	delete(selected, main)
	if len(selected) != len(dependencies) {
		return errors.New("compiled module set differs from selected closure")
	}
	for _, dependency := range dependencies {
		source, ok := selected[dependency.Path]
		if !ok {
			return errors.New("compiled module is absent from selected closure")
		}
		version := source.Version
		if source.Main && version == "" {
			version = "(devel)"
		}
		if dependency.Version != version || dependency.Sum != source.Sum || (dependency.Replace == nil) != (source.Replace == nil) {
			return errors.New("compiled module identity differs from selected closure")
		}
		if source.Replace != nil {
			a, b := source.Replace, dependency.Replace
			replacementVersion := a.Version
			if replacementVersion == "" {
				replacementVersion = "(devel)"
			}
			if a.Path != b.Path || replacementVersion != b.Version || a.Sum != b.Sum {
				return errors.New("compiled replacement differs from selected closure")
			}
		}
		delete(selected, dependency.Path)
	}
	if len(selected) != 0 {
		return errors.New("selected module is absent from executable")
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(body []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(body)
}

func readRegular(ctx context.Context, path string, limit int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > limit {
		return nil, errors.New("input file type or size refused")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(before, opened) {
		return nil, errors.Join(errors.New("input changed"), statErr, file.Close())
	}
	body, readErr := io.ReadAll(io.LimitReader(contextReader{ctx, file}, before.Size()+1))
	err = errors.Join(readErr, file.Close())
	if int64(len(body)) != before.Size() {
		err = errors.Join(err, errors.New("input length changed"))
	}
	return body, err
}

type archiveOutput struct {
	writer io.Writer
	length uint64
}

func (w *archiveOutput) Write(body []byte) (int, error) {
	if uint64(len(body)) > artifact.MaxArchiveBytes-w.length {
		return 0, errors.New("archive stream exceeds size limit")
	}
	n, err := w.writer.Write(body)
	w.length += uint64(n)
	if err == nil && n != len(body) {
		err = io.ErrShortWrite
	}
	return n, err
}

func writeArchive(ctx context.Context, output io.Writer, executable string, legal map[string][]byte) error {
	for name := range legal {
		if name != "LICENSE" && name != "NOTICE" && name != "THIRD_PARTY_NOTICES.md" {
			return errors.New("unsupported legal filename")
		}
	}
	if len(legal["LICENSE"]) == 0 || len(legal["THIRD_PARTY_NOTICES.md"]) == 0 {
		return errors.New("license and third-party notices are required")
	}
	input, err := os.Open(executable)
	if err != nil {
		return err
	}
	info, err := input.Stat()
	if err != nil {
		return errors.Join(err, input.Close())
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > artifact.MaxExecutableBytes {
		return errors.Join(errors.New("executable type or size refused"), input.Close())
	}
	total := info.Size()
	names := []string{"enkv"}
	for name, body := range legal {
		total += int64(len(body))
		names = append(names, name)
	}
	if total > artifact.MaxArchiveBytes {
		return errors.Join(errors.New("archive exceeds size limit"), input.Close())
	}
	slices.Sort(names)
	compressed := gzip.NewWriter(&archiveOutput{writer: output})
	compressed.OS = 255
	archive := tar.NewWriter(&archiveOutput{writer: compressed})
	for _, name := range names {
		size, mode := int64(len(legal[name])), int64(0644)
		if name == "enkv" {
			size, mode = info.Size(), 0755
		}
		if err = archive.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: size, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
			break
		}
		var reader io.Reader = bytes.NewReader(legal[name])
		if name == "enkv" {
			reader = input
		}
		var n int64
		n, err = io.Copy(archive, contextReader{ctx, reader})
		if err != nil {
			break
		}
		if n != size {
			err = errors.New("archive member changed length")
			break
		}
	}
	return errors.Join(err, archive.Close(), compressed.Close(), input.Close(), ctx.Err())
}

func writeNew(root *os.Root, name string, body []byte) error {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	_, err = io.Copy(file, bytes.NewReader(body))
	return errors.Join(err, file.Close())
}

func aggregateChecksums(ctx context.Context, output string, paths []string) (result error) {
	if len(paths) == 0 || len(paths) > 256 {
		return errors.New("one to 256 archives are required")
	}
	rows := make([]artifact.Checksum, 0, len(paths))
	for _, path := range paths {
		before, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > artifact.MaxArchiveBytes {
			return errors.New("archive type or size refused")
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		opened, statErr := file.Stat()
		if statErr != nil || !os.SameFile(before, opened) {
			return errors.Join(errors.New("archive changed"), statErr, file.Close())
		}
		hash := sha256.New()
		n, copyErr := io.Copy(hash, io.LimitReader(contextReader{ctx, file}, before.Size()+1))
		if err := errors.Join(copyErr, file.Close()); err != nil {
			return err
		}
		if n != before.Size() {
			return errors.New("archive length changed")
		}
		rows = append(rows, artifact.Checksum{Name: filepath.Base(path), Digest: artifact.Digest(hash.Sum(nil))})
	}
	slices.SortFunc(rows, func(a, b artifact.Checksum) int { return strings.Compare(a.Name, b.Name) })
	body, err := artifact.EncodeChecksums(rows)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(filepath.Dir(output))
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, root.Close()) }()
	return writeNew(root, filepath.Base(output), body)
}

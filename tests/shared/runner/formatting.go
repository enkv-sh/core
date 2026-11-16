package main

import (
	"context"
	records "enkv.sh/core/internal/testrecords"
	"errors"
	"fmt"
	"go/build"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

func maintainedGoFiles(root string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("formatting source root unavailable: %w", err)
	}
	if !info.IsDir() {
		return nil, errors.New("formatting source root is not a directory")
	}
	var files []string
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("formatting source discovery failed: %w", walkErr)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		excluded := entry.Name() == ".git" || entry.Name() == "vendor" || entry.IsDir() && entry.Name() == "node_modules"
		switch relative {
		case "build", "dist", "tests/.supervisor", "tests/hermetic/runs", "tests/hermetic/reports", "tests/live/runs", "tests/live/reports", "tests/workflows/runs", "tests/qualification", "tests/work-evidences":
			excluded = true
		}
		if excluded {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("formatting source symlink refused: %s", relative)
		}
		if !entry.IsDir() && strings.HasSuffix(relative, ".go") {
			info, err := entry.Info()
			if err != nil {
				return fmt.Errorf("formatting source unavailable: %w", err)
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("formatting source is not a regular file: %s", relative)
			}
			label, err := sourceLabel(root, path)
			if err != nil {
				return err
			}
			files = append(files, label)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	for _, source := range moduleSources {
		if source.Sibling == "" {
			continue
		}
		owner, err := moduleSourceDirectory(root, source)
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(owner); err != nil {
			return nil, err
		}
		err = filepath.WalkDir(owner, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return errors.New("formatting source symlink refused")
			}
			if entry.IsDir() {
				if entry.Name() == ".git" || entry.Name() == "vendor" || entry.Name() == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() {
				return errors.New("formatting source is not regular")
			}
			label, err := sourceLabel(root, path)
			if err != nil {
				return err
			}
			files = append(files, label)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	slices.Sort(files)
	return files, nil
}

func checkCustodySources(ctx context.Context, root string) error {
	files, err := maintainedGoFiles(root)
	if err != nil {
		return err
	}
	standardImports := make(map[string]bool)
	var toolchain *build.Context
	for _, name := range files {
		if strings.HasPrefix(name, "core/") || strings.HasPrefix(name, "tests/") {
			directory := filepath.ToSlash(filepath.Dir(name))
			owner := ""
			for _, overlay := range append(slices.Clone(records.TestAdmissionOverlays()), records.LiveTestSupportOverlays()...) {
				if name == overlay.Source {
					owner = filepath.ToSlash(filepath.Dir(overlay.Target))
					break
				}
			}
			if directory == "tests/crypto" && strings.HasSuffix(name, "_test.go") {
				owner = "crypto"
			}
			publicHelper := directory == publicProcessSourceDirectory && !strings.HasSuffix(name, "_test.go")
			if publicHelper {
				owner = publicProcessBuildDirectory
			}
			// Only declared foreign sources leave Core custody ownership. The
			// public process also keeps the private-key primitive refusal.
			if owner == "" || publicHelper {
				if err := checkCoreCustodyFile(filepath.Join(root, name)); err != nil {
					return err
				}
			}
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, name), nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			p := compiledPackage{ImportPath: modulePrefix + directory}
			nativeHelper := directory == "core/testsupport/nativeprocess"
			testFile := strings.HasSuffix(name, "_test.go")
			tests := testFile
			if strings.HasPrefix(name, "tests/") {
				p.ImportPath = modulePrefix + "core"
				tests = false
				switch directory {
				case "tests/shared/runner":
					p.ImportPath, tests = modulePrefix+"core/internal/testmain", true
				case "tests/shared/records":
					p.ImportPath, tests = modulePrefix+"core/internal/testrecords", true
				case "tests/shared/catalog":
					p.ImportPath, tests = modulePrefix+"core/internal/testcatalog", true
				case "tests/shared", "tests/hermetic", "tests/live/shared", "tests/live/runner", "tests/live/providers/aws", "tests/live/providers/gcp":
					tests = testFile
				}
				if name == "tests/examples/telemetry/main.go" {
					p.ImportPath = "command-line-arguments"
				}
			}
			if owner != "" {
				p.ImportPath, tests = modulePrefix+owner, true
			}
			if tests && (testFile || publicHelper) {
				p.ForTest = p.ImportPath
			}
			provider := ""
			for _, selected := range []string{"aws", "gcp"} {
				if strings.HasPrefix(name, "tests/live/providers/"+selected+"/") {
					provider = selected
				}
			}
			for _, spec := range file.Imports {
				imported, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					return err
				}
				if publicHelper && (strings.Contains(imported+"/", "/internal/") || strings.Contains(imported+"/", "/testsupport/") && imported != modulePrefix+"core/testsupport/nativeprocess") {
					return fmt.Errorf("public process imports private fixture dependency in %s", name)
				}
				p.Imports = append(p.Imports, imported)
			}
			packages := []compiledPackage{p}
			if nativeHelper && !tests {
				if toolchain == nil {
					body, err := runGo(ctx, root, "", "env", "GOROOT")
					if err != nil {
						return err
					}
					goroot := strings.TrimSpace(string(body))
					info, err := os.Stat(filepath.Join(goroot, "src"))
					if !filepath.IsAbs(goroot) || err != nil || !info.IsDir() {
						return errors.New("source custody toolchain root unavailable")
					}
					installed := build.Default
					installed.GOROOT = goroot
					toolchain = &installed
				}
				// The helper is compiled only for tests, but its ordinary files
				// retain no ForTest exemption from the standard-only import law.
				for _, imported := range p.Imports {
					standard, resolved := standardImports[imported]
					if !resolved {
						dependency, err := toolchain.Import(imported, "", build.FindOnly)
						standard = err == nil && dependency.Goroot
						standardImports[imported] = standard
					}
					if standard {
						packages = append(packages, compiledPackage{ImportPath: imported, Standard: true})
					}
				}
			}
			providers := []string{provider}
			if liveCommonTestSource(name) {
				// Common native test fixtures must be valid in both assemblies.
				// Their intersection admits no cloud-specific dependency here.
				providers = []string{"aws", "gcp"}
			}
			for _, selected := range providers {
				if err := checkCustodyImports(packages, tests || nativeHelper, selected); err != nil {
					return fmt.Errorf("custody import refused in %s: %w", name, err)
				}
			}
		}
	}
	return nil
}

func runFormatting(ctx context.Context, root string, rewrite bool, output io.Writer) error {
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("formatting source root unavailable: %w", err)
	}
	files, err := maintainedGoFiles(root)
	if err != nil || len(files) == 0 {
		return err
	}
	args := []string{"-l"}
	if rewrite {
		args = append(args, "-w")
	}
	// Keep source names separate from flags, including new files named -name.go.
	args = append(args, "--")
	for _, name := range files {
		physical, err := sourcePath(root, name)
		if err != nil {
			return err
		}
		args = append(args, physical)
	}
	parent := ctx
	ctx, cancel := preparationCommandContext(ctx)
	defer cancel()
	command := exec.Command("gofmt", args...)
	command.Dir, command.Env = root, goEnvironment()
	var stdout, stderr limitedOutput
	command.Stdout, command.Stderr = &stdout, &stderr
	process := superviseProcess(ctx, command)
	if !process.Joined {
		return &toolFailure{operation: "gofmt", process: process}
	}
	if process.Status != "passed" {
		err = &toolFailure{operation: "gofmt", process: process}
	}
	if stdout.overflow || stderr.overflow {
		err = errors.Join(err, errors.New("gofmt output exceeds its bound"))
	}
	err = containProcessFailure(parent, err)
	if err == nil && !rewrite && stdout.Len() != 0 {
		err = &localCheckFailure{cause: errors.New("Go formatting differs; run make fmt")}
	}
	if _, writeErr := output.Write(stdout.Bytes()); writeErr != nil {
		return errors.Join(err, writeErr)
	}
	if err != nil {
		return fmt.Errorf("gofmt: %w\n%s", err, stderr.String())
	}
	return nil
}

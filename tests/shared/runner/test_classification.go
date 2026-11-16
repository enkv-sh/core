package main

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	records "enkv.sh/core/internal/testrecords"
)

// A pointer preserves the distinction between an explicit false and missing
// classification when a retained receipt is decoded.
type testClassification struct {
	Name        string `json:"name"`
	FullOnly    *bool  `json:"full_only"`
	Exclusive   bool   `json:"exclusive,omitempty"`
	Unavailable bool   `json:"classification_unavailable,omitempty"`
}

type listedOrdinaryPackage struct {
	ImportPath   string
	Dir          string
	GoFiles      []string
	TestGoFiles  []string
	XTestGoFiles []string
}

func sameTestClassifications(left, right []testClassification) bool {
	if len(left) != len(right) {
		return false
	}
	for index, item := range left {
		other := right[index]
		if item.Name != other.Name || item.Unavailable != other.Unavailable || item.Exclusive != other.Exclusive {
			return false
		}
		if item.FullOnly == nil || other.FullOnly == nil {
			if !item.Unavailable || item.FullOnly != nil || other.FullOnly != nil || item.Exclusive {
				return false
			}
		} else if item.Unavailable || *item.FullOnly != *other.FullOnly {
			return false
		}
	}
	return true
}

func sameOrdinaryOmissions(left, right []ordinaryPackage) bool {
	if len(left) != len(right) {
		return false
	}
	for index, item := range left {
		if item.Name != right[index].Name || !slices.Equal(item.Tests, right[index].Tests) {
			return false
		}
	}
	return true
}

func selectClassifiedTests(names []string, classifications []testClassification, profile string) (selected, omitted []string, err error) {
	if profile != "full" && profile != "dev" {
		return nil, nil, errors.New("unknown test profile")
	}
	if len(names) != len(classifications) {
		return nil, nil, errors.New("test classification does not match compiled inventory")
	}
	seen := map[string]bool{}
	for index, name := range names {
		classification := classifications[index]
		if !validOrdinaryName(name) || strings.Contains(name, "/") || seen[name] || classification.Name != name || classification.FullOnly == nil && !classification.Unavailable || classification.Unavailable && (classification.FullOnly != nil || classification.Exclusive) {
			return nil, nil, errors.New("test classification is missing, repeated or inconsistent")
		}
		seen[name] = true
		if classification.Unavailable || profile == "dev" && *classification.FullOnly {
			omitted = append(omitted, name)
		} else {
			selected = append(selected, name)
		}
	}
	return selected, omitted, nil
}

func selectOrdinaryProfile(inventory map[string][]string, packages []ordinaryPackage, profile string) (map[string][]string, []ordinaryPackage, error) {
	if len(inventory) != len(packages) {
		return nil, nil, errors.New("ordinary classification package set differs from compiled inventory")
	}
	selected := make(map[string][]string, len(inventory))
	retained := make([]ordinaryPackage, 0, len(packages))
	for _, pkg := range packages {
		requested, found := inventory[pkg.Name]
		if !found || pkg.Name == "" {
			return nil, nil, errors.New("ordinary classification package identity differs from compiled inventory")
		}
		if _, repeated := selected[pkg.Name]; repeated {
			return nil, nil, errors.New("ordinary classification repeats a compiled package")
		}
		seen := map[string]bool{}
		for _, name := range requested {
			if !slices.Contains(pkg.Inventory, name) || seen[name] {
				return nil, nil, errors.New("ordinary requested inventory differs from classified roots")
			}
			seen[name] = true
		}
		eligible, _, err := selectClassifiedTests(pkg.Inventory, pkg.Classifications, profile)
		if err != nil {
			return nil, nil, err
		}
		pkg.Tests = slices.DeleteFunc(slices.Clone(inventory[pkg.Name]), func(name string) bool { return !slices.Contains(eligible, name) })
		pkg.NotSelected = slices.DeleteFunc(slices.Clone(pkg.Inventory), func(name string) bool { return slices.Contains(pkg.Tests, name) })
		selected[pkg.Name] = slices.Clone(pkg.Tests)
		retained = append(retained, pkg)
	}
	return selected, retained, nil
}

func validOrdinaryPackageSelection(pkg ordinaryPackage, profile string) bool {
	selected, omitted, err := selectClassifiedTests(pkg.Inventory, pkg.Classifications, profile)
	if err != nil || len(pkg.Inventory) == 0 && !ordinaryTestlessCommands[pkg.Name] {
		return false
	}
	return slices.Equal(selected, pkg.Tests) && slices.Equal(omitted, pkg.NotSelected)
}

func validOrdinaryArtifactProfile(artifact ordinaryArtifact) bool {
	return validOrdinaryPackageSelection(ordinaryPackage{Name: artifact.Package, Tests: artifact.Tests, Inventory: artifact.CompiledTests, Classifications: artifact.Classifications,
		NotSelected: slices.DeleteFunc(slices.Clone(artifact.CompiledTests), func(name string) bool { return slices.Contains(artifact.Tests, name) })}, artifact.Profile)
}

func ordinaryArtifactEmptyPackages(artifact ordinaryArtifact) map[string]bool {
	if len(artifact.CompiledTests) != 0 && len(artifact.Tests) == 0 && validOrdinaryArtifactProfile(artifact) {
		return map[string]bool{artifact.Package: true}
	}
	return ordinaryTestlessCommands
}

func validOrdinaryProfileEvidence(evidence ordinaryStepEvidence) bool {
	if len(evidence.Packages) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, pkg := range evidence.Packages {
		if pkg.Name == "" || seen[pkg.Name] || !validOrdinaryPackageSelection(pkg, evidence.Profile) {
			return false
		}
		seen[pkg.Name] = true
	}
	outcomes := map[string]string{}
	for _, test := range evidence.Tests {
		index := slices.IndexFunc(evidence.Packages, func(pkg ordinaryPackage) bool { return pkg.Name == test.Package })
		top, _, _ := strings.Cut(test.Name, "/")
		key := test.Package + "\x00" + test.Name
		if index < 0 || !slices.Contains(evidence.Packages[index].Tests, top) || outcomes[key] != "" {
			return false
		}
		outcomes[key] = test.Outcome
	}
	for key, outcome := range outcomes {
		if outcome == "pass" {
			continue
		}
		proof := ordinaryRunnerHelperProofs[key]
		if proof == "" {
			proof = ordinaryProviderHelperProofs[key]
		}
		pkg, _, _ := strings.Cut(key, "\x00")
		if outcome != "skip" || proof == "" || outcomes[pkg+"\x00"+proof] != "pass" {
			return false
		}
	}
	for _, pkg := range evidence.Packages {
		for _, name := range pkg.Tests {
			if outcome := outcomes[pkg.Name+"\x00"+name]; outcome != "pass" && outcome != "skip" {
				return false
			}
		}
	}
	return true
}

func declarationClassification(function *ast.FuncDecl) (fullOnly *bool, exclusive bool, err error) {
	var declaredExclusive bool
	if function.Doc != nil {
		for _, comment := range function.Doc.List {
			text := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(comment.Text, "//"), "/*"), "*/"))
			switch {
			case strings.HasPrefix(text, "full_only"):
				if fullOnly != nil || !strings.HasPrefix(comment.Text, "//") {
					return nil, false, errors.New("test has repeated or invalid full_only declaration")
				}
				var value bool
				switch text {
				case "full_only: false":
				case "full_only: true":
					value = true
				default:
					return nil, false, errors.New("test full_only must be explicitly true or false")
				}
				fullOnly = &value
			case strings.HasPrefix(text, "exclusive"):
				if declaredExclusive || !strings.HasPrefix(comment.Text, "//") {
					return nil, false, errors.New("test has repeated or invalid exclusive declaration")
				}
				switch text {
				case "exclusive: false":
				case "exclusive: true":
					exclusive = true
				default:
					return nil, false, errors.New("test exclusive must be explicitly true or false")
				}
				declaredExclusive = true
			}
		}
	}
	if fullOnly == nil {
		return nil, false, errors.New("test lacks an explicit full_only declaration")
	}
	return fullOnly, exclusive, nil
}

type capturedTestDeclaration struct {
	fullOnly  *bool
	exclusive bool
	source    string
	failure   error
}
type capturedTestDeclarations struct {
	packages     map[string]map[string]capturedTestDeclaration
	files        map[string][]byte
	replacements map[string]string
}

func hasUnavailableClassifications(rows []testClassification) bool {
	return slices.ContainsFunc(rows, func(row testClassification) bool { return row.Unavailable })
}

func (captured *capturedTestDeclarations) compilerFlags(flags []string, directory string) ([]string, error) {
	if len(captured.files) == 0 {
		return slices.Clone(flags), nil
	}
	private, err := os.MkdirTemp(directory, "test-inputs-")
	if err != nil {
		return nil, err
	}
	replacements := maps.Clone(captured.replacements)
	if replacements == nil {
		replacements = map[string]string{}
	}
	targets := slices.Sorted(maps.Keys(captured.files))
	for index, target := range targets {
		path := filepath.Join(private, fmt.Sprintf("%06d_test.go", index))
		if err := os.WriteFile(path, captured.files[target], 0400); err != nil {
			return nil, err
		}
		replacements[target] = path
	}
	overlay := filepath.Join(private, "overlay.json")
	if err := records.WriteJSON(overlay, struct{ Replace map[string]string }{replacements}, 0400); err != nil {
		return nil, err
	}
	actual := slices.DeleteFunc(slices.Clone(flags), func(flag string) bool { return strings.HasPrefix(flag, "-overlay=") })
	captured.files, captured.replacements = nil, nil
	return append(actual, "-overlay="+overlay), nil
}

func captureTestDeclarations(root string, packages []listedOrdinaryPackage, flags []string) (capturedTestDeclarations, error) {
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return capturedTestDeclarations{}, errors.New("test classification checkout is unavailable")
	}
	replacements := map[string]string{}
	for _, flag := range flags {
		if path, found := strings.CutPrefix(flag, "-overlay="); found {
			var overlay struct{ Replace map[string]string }
			if err := records.ReadJSON(path, &overlay); err != nil || overlay.Replace == nil {
				return capturedTestDeclarations{}, errors.New("test classification overlay is unavailable")
			}
			replacements = overlay.Replace
		}
	}
	result := capturedTestDeclarations{packages: make(map[string]map[string]capturedTestDeclaration, len(packages)), files: map[string][]byte{}, replacements: replacements}
	for _, pkg := range packages {
		if result.packages[pkg.ImportPath] != nil || !filepath.IsAbs(pkg.Dir) {
			return capturedTestDeclarations{}, errors.New("test classification package identity is unavailable or repeated")
		}
		classified := map[string]capturedTestDeclaration{}
		result.packages[pkg.ImportPath] = classified
		files := append(slices.Clone(pkg.TestGoFiles), pkg.XTestGoFiles...)
		for _, file := range pkg.GoFiles {
			if strings.HasSuffix(file, "_test.go") {
				files = append(files, file)
			}
		}
		slices.Sort(files)
		files = slices.Compact(files)
		for _, file := range files {
			path := filepath.Join(pkg.Dir, file)
			if filepath.IsAbs(file) {
				path = file
			}
			target := path
			if replacement, overlaid := replacements[path]; overlaid {
				if replacement == "" {
					return capturedTestDeclarations{}, errors.New("active test classification source was removed by its overlay")
				}
				path = replacement
			}
			effectivePath := path
			path, err := filepath.EvalSymlinks(path)
			if err != nil {
				return capturedTestDeclarations{}, errors.New("active test classification source is unavailable")
			}
			relative, err := sourceLabel(canonicalRoot, path)
			if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
				return capturedTestDeclarations{}, errors.New("test classification source is outside its checkout")
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return result, errors.New("active test classification source is unavailable")
			}
			remapped := false
			for virtual, source := range replacements {
				if (source == path || source == effectivePath) && filepath.Dir(virtual) == pkg.Dir {
					result.files[virtual] = body
					remapped = true
				}
			}
			if !remapped {
				result.files[target] = body
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), path, body, parser.ParseComments)
			if err != nil {
				return result, errors.New("active test classification source cannot be parsed")
			}
			for _, declaration := range parsed.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Recv != nil || !validOrdinaryName(function.Name.Name) {
					continue
				}
				name := function.Name.Name
				if _, found := classified[name]; found {
					return capturedTestDeclarations{}, fmt.Errorf("compiled test %s has repeated declarations", name)
				}
				fullOnly, exclusive, err := declarationClassification(function)
				classified[name] = capturedTestDeclaration{fullOnly: fullOnly, exclusive: exclusive, source: filepath.ToSlash(relative), failure: err}
			}
		}
	}
	return result, nil
}

func (captured capturedTestDeclarations) classify(inventory map[string][]string) (map[string][]testClassification, map[string]map[string]string, error) {
	result := make(map[string][]testClassification, len(inventory))
	sources := make(map[string]map[string]string, len(inventory))
	for pkg, names := range inventory {
		declarations, found := captured.packages[pkg]
		if !found {
			return nil, nil, errors.New("test classification omitted a compiled package")
		}
		sources[pkg] = map[string]string{}
		for _, name := range names {
			declaration, found := declarations[name]
			if !found {
				result[pkg] = append(result[pkg], testClassification{Name: name, Unavailable: true})
				continue
			}
			if declaration.failure != nil {
				return nil, nil, fmt.Errorf("compiled test %s: %w", name, declaration.failure)
			}
			result[pkg] = append(result[pkg], testClassification{Name: name, FullOnly: declaration.fullOnly, Exclusive: declaration.exclusive})
			if declaration.source != "" {
				sources[pkg][name] = declaration.source
			}
		}
		if _, _, err := selectClassifiedTests(names, result[pkg], "full"); err != nil {
			return nil, nil, fmt.Errorf("compiled package %s: %w", pkg, err)
		}
	}
	return result, sources, nil
}

func classifyTestPackages(root string, packages []listedOrdinaryPackage, flags []string, inventory map[string][]string) (map[string][]testClassification, map[string]map[string]string, error) {
	captured, err := captureTestDeclarations(root, packages, flags)
	if err != nil {
		return nil, nil, err
	}
	rows, sources, err := captured.classify(inventory)
	if err != nil {
		return nil, nil, err
	}
	for _, classified := range rows {
		if hasUnavailableClassifications(classified) {
			return nil, nil, errors.New("compiled test declaration is unavailable")
		}
	}
	return rows, sources, nil
}

func captureCompiledTestDeclarations(root string, packages []compiledPackage, flags []string, imported string) (capturedTestDeclarations, error) {
	for _, pkg := range packages {
		if pkg.ImportPath == imported && pkg.ForTest == "" {
			return captureTestDeclarations(root, []listedOrdinaryPackage{{ImportPath: imported, Dir: pkg.Dir, GoFiles: pkg.GoFiles, TestGoFiles: pkg.TestGoFiles, XTestGoFiles: pkg.XTestGoFiles}}, flags)
		}
	}
	return capturedTestDeclarations{}, errors.New("active test package discovery is incomplete")
}

func discoverTestClassifications(ctx context.Context, root, directory string, flags, patterns []string, race bool, inventory map[string][]string, diagnostics *checkDiagnostics) (map[string][]testClassification, map[string]map[string]string, error) {
	args := append([]string{"list"}, flags...)
	if race {
		args = append(args, "-race")
	}
	args = append(args, "-json=ImportPath,Dir,GoFiles,TestGoFiles,XTestGoFiles")
	body, facts, err := runGoRecorded(ctx, root, directory, append(args, patterns...)...)
	if diagnostics != nil {
		facts.Phase = "preparation"
		err = errors.Join(err, diagnostics.append(facts))
	}
	if err != nil {
		return nil, nil, err
	}
	packages, err := decodeObjects[listedOrdinaryPackage](body)
	if err != nil || len(packages) == 0 {
		return nil, nil, errors.New("active test package discovery is incomplete")
	}
	return classifyTestPackages(root, packages, flags, inventory)
}

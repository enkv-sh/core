package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/version"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

func main() {
	var err error
	if len(os.Args) > 1 && os.Args[1] == "modfile" {
		if len(os.Args) != 7 {
			err = fmt.Errorf("modfile requires repository, directory, input, overlay and output")
		} else {
			err = prepareLocalModfile(os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6])
		}
	} else {
		err = bootstrap()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func bootstrap() error {
	if !version.IsValid(runtime.Version()) || version.Compare(runtime.Version(), "go1.27.0") < 0 {
		return fmt.Errorf("Go 1.27.0 or later required; installed %s", runtime.Version())
	}
	if len(os.Args) != 2 {
		return fmt.Errorf("repository path required")
	}
	root, err := filepath.EvalSymlinks(os.Args[1])
	if err != nil || !filepath.IsAbs(root) {
		return fmt.Errorf("repository path unavailable")
	}
	directory, err := os.MkdirTemp("", "enkv-test-")
	if err != nil {
		return err
	}
	success := false
	defer func() {
		if !success {
			os.RemoveAll(directory)
		}
	}()
	replacements := make(map[string]string)
	for _, item := range []struct{ source, target string }{
		{"tests/shared/runner", "testmain"},
		{"tests/shared/records", "testrecords"},
		{"tests/shared/catalog", "testcatalog"},
	} {
		files, err := os.ReadDir(filepath.Join(root, item.source))
		if err != nil {
			return err
		}
		for _, file := range files {
			if file.IsDir() || !strings.HasSuffix(file.Name(), ".go") {
				continue
			}
			target := filepath.Join(root, "core/internal", item.target, file.Name())
			if _, err := os.Lstat(target); !os.IsNotExist(err) {
				return fmt.Errorf("test tool overlay cannot replace a Core file")
			}
			replacements[target] = filepath.Join(root, item.source, file.Name())
		}
	}
	body, err := json.Marshal(struct{ Replace map[string]string }{replacements})
	if err != nil {
		return err
	}
	overlay := filepath.Join(directory, "overlay.json")
	if err := os.WriteFile(overlay, body, 0600); err != nil {
		return err
	}
	localModfile := filepath.Join(directory, "runner.mod")
	if err := prepareLocalModfile(root, filepath.Join(root, "core"), filepath.Join(root, "tests/hermetic/hermetic.mod"), overlay, localModfile); err != nil {
		return err
	}
	binary := filepath.Join(directory, "runner")
	command := exec.Command("go", "build", "-mod=readonly", "-modfile="+localModfile, "-overlay="+overlay, "-o", binary, "./internal/testmain")
	command.Dir = filepath.Join(root, "core")
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(os.Stdout, binary); err != nil {
		return err
	}
	success = true
	return nil
}

func prepareLocalModfile(root, directory, input, overlay, output string) error {
	var err error
	root, err = filepath.Abs(root)
	if err != nil {
		return err
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		return err
	}
	if err := regularPath(root, true); err != nil {
		return err
	}
	if err := regularPath(directory, true); err != nil {
		return err
	}
	inventoryName := filepath.Join(filepath.Dir(root), "enkv-extensions/distribution/modules.json")
	if err := regularPath(inventoryName, false); err != nil {
		return err
	}
	data, err := os.ReadFile(inventoryName)
	if err != nil {
		return err
	}
	if err := rejectDuplicateFields(data); err != nil {
		return err
	}
	var inv inventory
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&inv); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("trailing module inventory")
	}
	if err := validate(inv); err != nil {
		return err
	}
	expected := ""
	for _, row := range inv.Modules {
		if row.Selector == "" {
			continue
		}
		owner := filepath.Join(root, row.Directory)
		if row.Repository == "enkv-extensions" {
			owner = filepath.Join(filepath.Dir(root), row.Repository, row.Directory)
		}
		if owner == directory {
			expected = row.Module
		}
	}
	if expected == "" {
		return fmt.Errorf("module directory is not registered")
	}
	if input == "" {
		input = filepath.Join(directory, "go.mod")
	} else if !filepath.IsAbs(input) {
		input = filepath.Join(directory, input)
	}
	sumInput := strings.TrimSuffix(input, ".mod") + ".sum"
	var mapping struct{ Replace map[string]string }
	if overlay != "" {
		if !filepath.IsAbs(overlay) {
			overlay = filepath.Join(directory, overlay)
		}
		body, err := os.ReadFile(overlay)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(body, &mapping); err != nil {
			return err
		}
		originalInput, originalSum := input, sumInput
		for from, to := range mapping.Replace {
			if !filepath.IsAbs(from) {
				from = filepath.Join(directory, from)
			}
			if !filepath.IsAbs(to) {
				to = filepath.Join(directory, to)
			}
			if from == originalInput {
				input = to
			}
			if from == originalSum {
				sumInput = to
			}
		}
	}
	if err := regularPath(input, false); err != nil {
		return err
	}
	body, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	for _, name := range []string{output, strings.TrimSuffix(output, ".mod") + ".sum"} {
		if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("local modfile output already exists")
		}
	}
	captured, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := captured.Write(body)
	closeErr := captured.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	inspect := exec.Command("go", "mod", "edit", "-json", "-modfile="+output)
	inspect.Dir, inspect.Stderr = directory, os.Stderr
	inspect.Env = bootstrapGoEnvironment()
	definitionBody, err := inspect.Output()
	if err != nil {
		return err
	}
	var definition struct {
		Module  struct{ Path string }
		Replace []struct{ Old struct{ Path string } }
	}
	if err := json.Unmarshal(definitionBody, &definition); err != nil {
		return err
	}
	if definition.Module.Path != expected {
		return fmt.Errorf("main module identity differs")
	}
	for _, replacement := range definition.Replace {
		for _, row := range inv.Modules {
			if replacement.Old.Path == row.Module {
				return fmt.Errorf("source module contains a first-party replacement")
			}
		}
	}
	for _, row := range inv.Modules {
		if row.Selector == "" {
			continue
		}
		owner := filepath.Join(root, row.Directory)
		if row.Repository == "enkv-extensions" {
			owner = filepath.Join(filepath.Dir(root), row.Repository, row.Directory)
		}
		if owner == directory {
			continue
		}
		if err := safeOwner(owner); err != nil {
			return err
		}
		relative, err := filepath.Rel(directory, owner)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if !strings.HasPrefix(relative, ".") {
			relative = "./" + relative
		}
		body = append(body, []byte("\nreplace "+row.Module+" => "+relative+"\n")...)
	}
	if err := os.WriteFile(output, body, 0600); err != nil {
		return err
	}
	if err := regularPath(sumInput, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	sum, err := os.ReadFile(sumInput)
	if err != nil {
		return err
	}
	return os.WriteFile(strings.TrimSuffix(output, ".mod")+".sum", sum, 0600)
}

func bootstrapGoEnvironment() []string {
	var env []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key != "GOWORK" && key != "GOTOOLCHAIN" {
			env = append(env, entry)
		}
	}
	return append(env, "GOWORK=off", "GOTOOLCHAIN=local")
}

func safeOwner(filename string) error {
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(filename, current), string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("module source path refused")
		}
	}
	return nil
}

func regularPath(filename string, directory bool) error {
	if !filepath.IsAbs(filename) || filepath.Clean(filename) != filename {
		return fmt.Errorf("module input path refused")
	}
	if err := safeOwner(filepath.Dir(filename)); err != nil {
		return err
	}
	info, err := os.Lstat(filename)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
		return fmt.Errorf("module input type refused")
	}
	return nil
}

type moduleLocation struct {
	Selector      string `json:"selector"`
	Module        string `json:"module"`
	Repository    string `json:"repository"`
	RepositoryURL string `json:"repository_url"`
	Directory     string `json:"directory"`
	TagPrefix     string `json:"tag_prefix"`
}

type inventory struct {
	SchemaVersion int              `json:"schema_version"`
	Go            string           `json:"go"`
	Modules       []moduleLocation `json:"modules"`
}

func validate(inv inventory) error {
	if inv.SchemaVersion != 1 || inv.Go != "1.27.0" || len(inv.Modules) == 0 {
		return errors.New("unsupported module inventory")
	}
	selectors := make(map[string]bool)
	for i, row := range inv.Modules {
		if row.Repository != "enkv-core" && row.Repository != "enkv-extensions" {
			return errors.New("unknown module repository")
		}
		expectedURL := "https://github.com/enkv-sh/" + strings.TrimPrefix(row.Repository, "enkv-")
		if row.RepositoryURL != expectedURL || !relative(row.Directory) || row.TagPrefix != row.Directory+"/" || !strings.HasPrefix(row.Module, "enkv.sh/") || !relative(strings.TrimPrefix(row.Module, "enkv.sh/")) {
			return errors.New("module ownership differs")
		}
		public := strings.HasPrefix(row.Module, "enkv.sh/sdk/") || strings.HasPrefix(row.Module, "enkv.sh/plugins/")
		if public != (row.Repository == "enkv-extensions") {
			return errors.New("module repository ownership differs")
		}
		if row.Selector != "" {
			if !relative(row.Selector) || selectors[row.Selector] {
				return errors.New("module selector differs")
			}
			selectors[row.Selector] = true
		}
		for _, prior := range inv.Modules[:i] {
			if overlaps(prior.Module, row.Module) || prior.Repository == row.Repository && overlaps(prior.Directory, row.Directory) || prior.Selector != "" && row.Selector != "" && overlaps(prior.Selector, row.Selector) {
				return errors.New("overlapping module ownership")
			}
		}
	}
	return nil
}
func relative(value string) bool {
	return value != "" && value != "." && value != ".." && !strings.HasPrefix(value, "../") && !path.IsAbs(value) && path.Clean(value) == value && !strings.ContainsAny(value, "\\ \t\r\n\x00")
}
func overlaps(first, second string) bool {
	return first == second || strings.HasPrefix(first, second+"/") || strings.HasPrefix(second, first+"/")
}

func rejectDuplicateFields(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	var value func() error
	value = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]bool)
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("duplicate inventory field")
				}
				seen[name] = true
				if err := value(); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := value(); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid inventory delimiter")
		}
		_, err = decoder.Token()
		return err
	}
	return value()
}

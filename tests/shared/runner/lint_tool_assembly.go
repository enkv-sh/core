package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	records "enkv.sh/core/internal/testrecords"
)

type lintToolFile struct {
	source string
	target string
}

// Standalone vet reads a cgo file at its package path even when an overlay
// supplies its contents. Give vet the same exact tool sources in the private
// lint assembly, where no checkout file has to be installed.
func vetLintTools(ctx context.Context, root, lintRoot, bootstrap string) (err error) {
	files, err := lintToolFiles(root, bootstrap)
	if err != nil {
		return err
	}
	replacements, err := lintReplacements(root)
	if err != nil {
		return err
	}
	type createdFile struct {
		path string
		info os.FileInfo
		sum  [sha256.Size]byte
	}
	var created, borrowed []createdFile
	var directories []string
	defer func() {
		if !toolCommandsJoined(err) {
			return
		}
		var cleanup []error
		for _, file := range borrowed {
			current, statErr := os.Lstat(file.path)
			body, readErr := os.ReadFile(file.path)
			if statErr != nil || readErr != nil || !current.Mode().IsRegular() || !records.SameLocalFile(file.info, current) || sha256.Sum256(body) != file.sum {
				cleanup = append(cleanup, errors.New("borrowed lint dependency changed during vet"))
			}
		}
		for i := len(created) - 1; i >= 0; i-- {
			file := created[i]
			current, statErr := os.Lstat(file.path)
			body, readErr := os.ReadFile(file.path)
			if statErr != nil || readErr != nil || !current.Mode().IsRegular() || !records.SameLocalFile(file.info, current) || sha256.Sum256(body) != file.sum {
				cleanup = append(cleanup, errors.New("private lint tool source changed before cleanup"))
				continue
			}
			if removeErr := os.Remove(file.path); removeErr != nil {
				cleanup = append(cleanup, removeErr)
			}
		}
		for i := len(directories) - 1; i >= 0; i-- {
			if removeErr := os.Remove(directories[i]); removeErr != nil {
				cleanup = append(cleanup, removeErr)
			}
		}
		err = errors.Join(err, errors.Join(cleanup...))
	}()
	for _, relative := range []string{"core/internal", "core/internal/testmain", "core/internal/testrecords", "core/internal/testcatalog"} {
		path := filepath.Join(lintRoot, relative)
		info, statErr := os.Lstat(path)
		if os.IsNotExist(statErr) {
			if err := os.Mkdir(path, 0700); err != nil {
				return err
			}
			directories = append(directories, path)
		} else if statErr != nil {
			return statErr
		} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("private lint tool directory refused")
		}
	}
	for _, file := range files {
		original, err := lintSourceBytes(root, file.source)
		if err != nil {
			return err
		}
		body, err := lintSourceBytes(lintRoot, file.source)
		if err != nil || !bytes.Equal(original, body) {
			return errors.New("lint tool source changed before vet")
		}
		target := filepath.Join(lintRoot, file.target)
		if source := replacements[filepath.Join(root, file.target)]; source != "" {
			if source != filepath.Join(root, file.source) {
				return errors.New("lint tool dependency differs from assembly")
			}
			dependency, readErr := lintSourceBytes(lintRoot, file.target)
			info, statErr := os.Lstat(target)
			if readErr != nil || statErr != nil || !bytes.Equal(dependency, original) {
				return errors.New("lint tool dependency changed before vet")
			}
			borrowed = append(borrowed, createdFile{path: target, info: info, sum: sha256.Sum256(dependency)})
			continue
		}
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			return errors.New("private lint tool target already exists")
		}
		if err := os.WriteFile(target, body, 0600); err != nil {
			return err
		}
		info, err := os.Lstat(target)
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("private lint tool source unavailable")
		}
		created = append(created, createdFile{path: target, info: info, sum: sha256.Sum256(body)})
	}
	_, err = runGo(ctx, lintRoot, "core", "vet", "-mod=readonly", "-modfile="+assemblyModfile(lintRoot, "hermetic", "memory"),
		"./internal/testmain", "./internal/testrecords", "./internal/testcatalog")
	return containProcessFailure(ctx, err)
}

func lintToolFiles(root, bootstrap string) ([]lintToolFile, error) {
	body, err := os.ReadFile(bootstrap)
	if err != nil {
		return nil, err
	}
	var overlay struct{ Replace map[string]string }
	if err := json.Unmarshal(body, &overlay); err != nil || overlay.Replace == nil {
		return nil, errors.New("test tool overlay unavailable")
	}
	var files []lintToolFile
	for _, item := range []struct{ source, target string }{
		{"runner", "testmain"}, {"records", "testrecords"}, {"catalog", "testcatalog"},
	} {
		sourceDir := filepath.Join(root, "tests/shared", item.source)
		entries, err := os.ReadDir(sourceDir)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
				continue
			}
			source := filepath.Join(sourceDir, entry.Name())
			target := filepath.Join(root, "core/internal", item.target, entry.Name())
			if overlay.Replace[target] != source {
				return nil, fmt.Errorf("test tool overlay differs from %s", item.source)
			}
			files = append(files, lintToolFile{
				source: filepath.ToSlash(filepath.Join("tests/shared", item.source, entry.Name())),
				target: filepath.ToSlash(filepath.Join("core/internal", item.target, entry.Name())),
			})
		}
	}
	if len(files) == 0 || len(files) != len(overlay.Replace) {
		return nil, errors.New("test tool overlay source set differs")
	}
	return files, nil
}

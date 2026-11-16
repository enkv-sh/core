package main

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"

	records "enkv.sh/core/internal/testrecords"
)

// Public closure paths are relative to the original assembly build owner.
// Absolute local paths occur only in the private worker input.
type stockPluginClosure struct {
	Artifact records.StockPluginArtifact `json:"artifact"`
}

func stockPluginPaths(value *records.StockPluginArtifact, change func(string) (string, error)) error {
	paths := []*string{&value.CLI.Path, &value.Archive.Path, &value.GeneratorA.Directory, &value.GeneratorB.Directory, &value.Renderer.Directory}
	for i := range value.Outputs {
		paths = append(paths, &value.Outputs[i].Directory)
	}
	for _, path := range paths {
		changed, err := change(*path)
		if err != nil {
			return err
		}
		*path = changed
	}
	return nil
}

func cloneStockPluginArtifact(value records.StockPluginArtifact) (records.StockPluginArtifact, error) {
	body, err := json.Marshal(value)
	var copy records.StockPluginArtifact
	if err != nil || json.Unmarshal(body, &copy) != nil {
		return copy, errors.New("stock plugin closure unavailable")
	}
	return copy, nil
}

func stockPluginClosureFromArtifact(build string, value records.StockPluginArtifact) (*stockPluginClosure, error) {
	copy, err := cloneStockPluginArtifact(value)
	if err != nil {
		return nil, err
	}
	err = stockPluginPaths(&copy, func(path string) (string, error) {
		relative, err := filepath.Rel(build, path)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return "", errors.New("stock plugin path outside build owner")
		}
		return filepath.ToSlash(relative), nil
	})
	if err != nil {
		return nil, err
	}
	return &stockPluginClosure{Artifact: copy}, nil
}

func stockPluginArtifactFromClosure(build string, closure *stockPluginClosure) (records.StockPluginArtifact, error) {
	if closure == nil || !filepath.IsAbs(build) {
		return records.StockPluginArtifact{}, errors.New("stock plugin closure owner unavailable")
	}
	copy, err := cloneStockPluginArtifact(closure.Artifact)
	if err != nil {
		return copy, err
	}
	err = stockPluginPaths(&copy, func(path string) (string, error) {
		if filepath.IsAbs(path) || filepath.ToSlash(filepath.Clean(path)) != path || path == "." {
			return "", errors.New("stock plugin relative path refused")
		}
		return records.SafePath(build, filepath.FromSlash(path))
	})
	return copy, err
}

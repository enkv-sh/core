package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	records "enkv.sh/core/internal/testrecords"
)

const moduleInventoryPath = "distribution/modules.json"

func moduleInventoryBytes(root string) ([]byte, error) {
	filename, err := records.SafePath(filepath.Join(filepath.Dir(root), "enkv-extensions"), moduleInventoryPath)
	if err != nil {
		return nil, errors.New("module inventory path refused")
	}
	body, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("module inventory unavailable: %w", err)
	}
	return body, nil
}

func verifyModuleInventory(root string) error {
	body, err := moduleInventoryBytes(root)
	if err != nil {
		return err
	}
	if fmt.Sprintf("%x", sha256.Sum256(body)) != moduleInventorySHA256 {
		return errors.New("module inventory changed; run distribution/generate.go and tests/scripts/setup-supervisor")
	}
	return nil
}

const outputSDKPath = "enkv.sh/sdk/output"
const outputExamplePath = "enkv.sh/sdk/examples/local-value-output"
const manifestSDKPath = "enkv.sh/sdk/manifest-generator"
const genericJSONPath = "enkv.sh/plugins/manifest-generators/generic-json"
const manifestExamplePath = "enkv.sh/sdk/examples/ini-reference-manifest"
const openTofuJSONPath = "enkv.sh/plugins/manifest-generators/opentofu-tfvars-json"
const testServicePath = "enkv.sh/sdk/examples/testservice"

const modulePrefix = "enkv.sh/"

const generatorSDKPath = "enkv.sh/sdk/generator"
const generatorExamplePath = "enkv.sh/sdk/examples/local-token-generator"

type moduleSource struct {
	Selector  string
	Module    string
	Sibling   string
	Directory string
}

var moduleRoots = func() []string {
	roots := make([]string, len(moduleSources))
	for i, source := range moduleSources {
		roots[i] = source.Selector
	}
	return roots
}()

func modulePath(selector string) string {
	for _, source := range moduleSources {
		if source.Selector == selector {
			return source.Module
		}
	}
	return ""
}

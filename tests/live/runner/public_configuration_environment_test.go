package core

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// The live worker is one isolated process. Only source selection runs with this
// temporary discovery environment; the returned provider captures its own source.
// Product children receive their separately built environment from publicCLI.
func publicSDKEnvironment(input liveRunInput, role, directory string) (func(), error) {
	actor, ok := input.PublicConfiguration.Actors[role]
	if !ok {
		return nil, errors.New("public SDK role unavailable")
	}
	absent := filepath.Join(directory, "absent-shared-credentials")
	if _, err := os.Lstat(absent); !os.IsNotExist(err) {
		return nil, errors.New("public SDK static fallback refused")
	}
	original := os.Environ()
	selected, err := publicContext(actor).Environment(input.Settings.Provider, original, absent)
	if err != nil {
		return nil, err
	}
	if stockPluginCase(input) && input.Settings.Provider == "aws" {
		// The acceptance profiles derive from SSO. The independent fixture
		// readers and cleanup must exclude the old static-credential seed too.
		selected = stockReplaceEnvironment(selected, "AWS_SHARED_CREDENTIALS_FILE", absent)
	}
	affected := func(key string) bool {
		return key == "HOME" || key == "XDG_CONFIG_HOME" || strings.HasPrefix(key, "AWS_") || strings.HasPrefix(key, "GCE_") || strings.HasPrefix(key, "GOOGLE_") || strings.HasPrefix(key, "GCLOUD_") || strings.HasPrefix(key, "CLOUDSDK_") || strings.HasPrefix(key, "EXPERIMENTAL_GOOGLE_")
	}
	before, after := map[string]string{}, map[string]string{}
	for _, value := range original {
		key, value, _ := strings.Cut(value, "=")
		if affected(key) {
			before[key] = value
		}
	}
	for _, value := range selected {
		key, value, _ := strings.Cut(value, "=")
		if affected(key) {
			after[key] = value
		}
	}
	restore := func() {
		for key := range after {
			if _, ok := before[key]; !ok {
				os.Unsetenv(key)
			}
		}
		for key, value := range before {
			os.Setenv(key, value)
		}
	}
	for key := range before {
		if err := os.Unsetenv(key); err != nil {
			restore()
			return nil, err
		}
	}
	for key, value := range after {
		if err := os.Setenv(key, value); err != nil {
			restore()
			return nil, err
		}
	}
	return restore, nil
}

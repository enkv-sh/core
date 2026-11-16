package main

import (
	"errors"
	"os"
	"strings"
	"testing"

	"enkv.sh/sdk/artifact"
)

// full_only: false
func TestPackageRefusesValidPrivateKeyBeforeBuild(t *testing.T) {
	const privateKey = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIEzNCJso/5banbbDRuwRTg9bijGfNaumJNqM9u1PuKb7\n-----END PRIVATE KEY-----\n"
	for _, purpose := range []string{"CLI", "plugin"} {
		t.Run(purpose, func(t *testing.T) {
			c := packageConfig(t)
			if _, err := assemblyFlags(t.Context(), c); err != nil {
				t.Fatal(err)
			}
			path := c.cliKey
			if purpose == "plugin" {
				path = c.pluginKeys[0]
			}
			if err := os.WriteFile(path, []byte(privateKey), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := assemblyFlags(t.Context(), c)
			if !errors.Is(err, artifact.ErrSignature) || !strings.HasPrefix(err.Error(), purpose+" public key:") {
				t.Fatal("valid private key was not refused at the public-key boundary", err)
			}
		})
	}
}

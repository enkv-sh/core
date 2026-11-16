package records

import (
	"strings"
	"testing"
)

// full_only: false
func TestFailureSourcesAcceptOnlyOwningPassiveCredentialCodecPaths(t *testing.T) {
	for _, row := range []struct {
		source   string
		admitted bool
	}{
		{"plugins/aws-output/credential/credential.go", true},
		{"plugins/gcp-output/credential/credential.go", true},
		{"plugins/aws-output/profile/profile.go", true},
		{"plugins/gcp-output/profile/profile.go", true},
		{"plugins/github-output/profile/profile.go", true},
		{"plugins/cloudflare/profile/profile.go", true},
		{"plugins/github-output/credential/credential.go", false},
		{"plugins/cloudflare/credential/credential.go", false},
		{"plugins/unreviewed-output/credential/credential.go", false},
		{"plugins/aws-output/credential/nested/credential.go", false},
		{"plugins/gcp-output/internal/credential.go", false},
		{"plugins/aws-output/credential/../effect.go", false},
	} {
		t.Run(row.source, func(t *testing.T) {
			sources := FailureSources{SchemaVersion: FailureSchemaVersion, BinarySHA256: strings.Repeat("a", 64), OverlaySHA256: strings.Repeat("b", 64), Paths: map[string]string{passiveFailureCaller(row.source): row.source}}
			if err := sources.Validate(); (err == nil) != row.admitted {
				t.Fatal("passive source mapping classification differs", err)
			}
		})
	}
}

func passiveFailureCaller(source string) string {
	for selector, module := range map[string]string{
		"plugins/local-random-secret/": "enkv.sh/plugins/generators/local-random-secret/",
		"plugins/cloudflare/":          "enkv.sh/plugins/generators/cloudflare-account-token/",
		"plugins/aws-output/":          "enkv.sh/plugins/outputs/aws-secrets-manager/",
		"plugins/gcp-output/":          "enkv.sh/plugins/outputs/gcp-secret-manager/",
		"plugins/github-output/":       "enkv.sh/plugins/outputs/github-actions/",
	} {
		if rest, ok := strings.CutPrefix(source, selector); ok {
			return module + rest
		}
	}
	return "enkv.sh/" + source
}

// full_only: false
func TestFailureSourcesRejectSwappedNamespaceOwners(t *testing.T) {
	for _, row := range []struct{ caller, source string }{
		{"enkv.sh/crypto@v0.0.0/contract.go", "core/contract.go"},
		{"enkv.sh/sdk/unknown@v0.0.0/wire.go", "protocols/generator/wire.go"},
		{"enkv.sh/sdk/protocols/output@v0.0.0/wire.go", "protocols/generator/wire.go"},
		{"enkv.sh/plugins/outputs/gcp-secret-manager@v0.0.0/profile/profile.go", "plugins/aws-output/profile/profile.go"},
		{"enkv.sh/plugins/aws-output@v0.0.0/profile/profile.go", "plugins/aws-output/profile/profile.go"},
	} {
		sources := FailureSources{SchemaVersion: FailureSchemaVersion, BinarySHA256: strings.Repeat("a", 64), OverlaySHA256: strings.Repeat("b", 64), Paths: map[string]string{row.caller: row.source}}
		if err := sources.Validate(); err == nil {
			t.Fatal("unregistered or swapped module owner accepted", row)
		}
	}
}

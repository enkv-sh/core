package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

func configurationFixture(t *testing.T, provider string) (string, liveSettings) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	settings := liveSettings{
		"provider": provider, "region": "example-region", "bucket": "example-bucket", "key_id": "example-key",
		"public_key_pem": "-----BEGIN PUBLIC KEY-----\nsynthetic\n-----END PUBLIC KEY-----", "credentials_file": "identity.json",
		"recovery_mode": "disabled", "authority_kek_id": "example-authority", "reader_kek_id": "example-reader",
		"authority_kek_public_key_pem": "-----BEGIN PUBLIC KEY-----\nsynthetic-authority\n-----END PUBLIC KEY-----",
		"reader_kek_public_key_pem":    "-----BEGIN PUBLIC KEY-----\nsynthetic-reader\n-----END PUBLIC KEY-----",
	}
	if provider == "gcp" {
		settings["project"], settings["project_number"] = "example-project", "123456789012"
	} else {
		settings["account"], settings["profile"] = "123456789012", "example-profile"
	}
	if err := os.WriteFile(filepath.Join(root, "identity.json"), []byte("synthetic credentials"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "config.json")
	if records.WriteJSON(path, environmentFor(settings), 0600) != nil {
		t.Fatal("configuration fixture write failed")
	}
	return path, settings
}

// full_only: false
func TestCredentialsResolveBesideConfiguration(t *testing.T) {
	for _, provider := range []string{"gcp", "aws"} {
		path, settings := configurationFixture(t, provider)
		loaded, err := validateSettings(settings, provider, filepath.Dir(path))
		if err != nil || loaded["credentials_file"] != filepath.Join(filepath.Dir(path), "identity.json") {
			t.Fatal("credential path resolution changed")
		}
	}
}

// full_only: false
func TestConfigurationRejectsAmbiguousOrMissingInputs(t *testing.T) {
	for _, mutation := range []struct{ field, value string }{
		{"provider", "aws"}, {"extra", "synthetic-secret"}, {"project_number", "not-an-owner"},
		{"bucket", "contains space"}, {"key_id", "key\u00a0identity"}, {"public_key_pem", "invalid public basis"},
		{"credential_expires", "2000-01-01T00:00:00Z"}, {"credential_expires", "2099-01-01T00:00:00"},
		{"credentials_file", "synthetic-secret-unavailable"}, {"region", ""},
	} {
		path, settings := configurationFixture(t, "gcp")
		settings[mutation.field] = mutation.value
		if records.WriteJSON(path, environmentFor(settings), 0600) != nil {
			t.Fatal("configuration fixture write failed")
		}
		_, err := validateSettings(settings, "gcp", filepath.Dir(path))
		if err == nil || strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatal("invalid configuration admitted or exposed")
		}
	}
}

func testLimits() limits {
	return limits{Requests: 1000, BodyBytes: 1 << 30, Objects: 256, ObjectBytes: 1 << 28, GeneratorCreates: 128, GeneratorRetires: 256, ElapsedSeconds: 10, CleanupRequests: 1000, CleanupBytes: 1 << 30, CleanupSeconds: 10}
}

// full_only: false
func TestLimitsRequireFiniteExplicitRunAndCleanupAllowance(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "limits.json")
	original := testLimits()
	const literal = `{"requests":1000,"body_bytes":1073741824,"objects":256,"object_bytes":268435456,"generator_creates":128,"generator_retires":256,"elapsed_seconds":10,"cleanup_requests":1000,"cleanup_bytes":1073741824,"cleanup_seconds":10}`
	base := []byte(literal)
	if err := os.WriteFile(path, base, 0600); err != nil {
		t.Fatal("limit fixture write failed", err)
	}
	loaded, err := loadLimits(path)
	if err != nil || loaded != original {
		t.Fatal("ten explicit run and cleanup limits refused or changed", err)
	}
	for _, replacement := range []struct{ before, after string }{
		{`"requests":1000`, `"requests":0`},
		{`"requests":1000`, `"requests":1000001`},
		{`"requests":1000`, `"REQUESTS":1000`},
		{`"requests":1000`, `"requests":1000,"requests":null`},
		{`"requests":1000`, `"requests":1.0`},
		{`"elapsed_seconds":10`, `"elapsed_seconds":true`},
		{`"body_bytes":1073741824`, `"body_bytes":-1`},
		{`"generator_creates":128`, `"generator_creates":0`},
		{`"generator_retires":256`, `"generator_retires":100001`},
		{`"cleanup_seconds":10`, `"cleanup_seconds":10,"cost_allowance_usd":1`},
		{`"cleanup_seconds":10`, `"cleanup_seconds":3601`},
		{`"cleanup_requests":1000`, `"cleanup_requests":"1000"`},
		{`"objects":256,`, ``},
	} {
		body := strings.Replace(string(base), replacement.before, replacement.after, 1)
		if body == string(base) {
			t.Fatal("test did not mutate its input")
		}
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadLimits(path); err == nil {
			t.Fatal("unbounded or ambiguous allowance admitted")
		}
	}
}

// full_only: false
func TestCleanupAllowsCredentialReplacementButKeepsResourceIdentity(t *testing.T) {
	_, original := configurationFixture(t, "aws")
	for _, field := range []string{"credentials_file", "profile", "credential_expires", "bucket", "region", "key_id", "public_key_pem", "account", "provider", "recovery_mode", "authority_kek_id", "authority_kek_public_key_pem", "reader_kek_id", "reader_kek_public_key_pem", "recovery_key_id", "recovery_public_key_pem", "recovery_kek_id", "recovery_kek_public_key_pem"} {
		changed := make(liveSettings)
		for name, value := range original {
			changed[name] = value
		}
		changed[field] = "replacement"
		credentialField := field == "credentials_file" || field == "profile" || field == "credential_expires"
		if sameResources(original, changed) != credentialField {
			t.Errorf("resource binding for %s differs", field)
		}
	}
}

func firstFlowConfigurationFixture(t *testing.T, provider, mode string) liveSettings {
	t.Helper()
	_, settings := configurationFixture(t, provider)
	settings["recovery_mode"] = mode
	keys := []struct{ id, pem, label string }{
		{"key_id", "public_key_pem", "normal"},
		{"authority_kek_id", "authority_kek_public_key_pem", "authority"},
		{"reader_kek_id", "reader_kek_public_key_pem", "reader"},
	}
	if mode == "enabled" {
		keys = append(keys, struct{ id, pem, label string }{"recovery_key_id", "recovery_public_key_pem", "recovery-sign"}, struct{ id, pem, label string }{"recovery_kek_id", "recovery_kek_public_key_pem", "recovery"})
	}
	for _, key := range keys {
		settings[key.id] = "arn:aws:kms:us-east-1:123456789012:key/" + key.label
		if provider == "gcp" {
			settings[key.id] = "projects/example-project/locations/us-east1/keyRings/enkv/cryptoKeys/" + key.label + "/cryptoKeyVersions/1"
		}
		settings[key.pem] = "-----BEGIN PUBLIC KEY-----\nsynthetic-" + key.label + "\n-----END PUBLIC KEY-----"
	}
	return settings
}

// full_only: false
func TestFirstFlowConfigurationAcceptsBothProviderOutputShapes(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		for _, mode := range []string{"disabled", "enabled"} {
			t.Run(provider+"/"+mode, func(t *testing.T) {
				settings := firstFlowConfigurationFixture(t, provider, mode)
				if _, err := validateSettingsFields(settings, provider, "/unused"); err != nil {
					t.Fatalf("prepared Tofu output shape refused: %v", err)
				}
				for key := range settings {
					if key == "credential_expires" {
						continue
					}
					copy := make(liveSettings)
					for name, value := range settings {
						copy[name] = value
					}
					delete(copy, key)
					if _, err := validateSettingsFields(copy, provider, ""); err == nil {
						t.Errorf("missing %s accepted", key)
					}
				}
			})
		}
	}
}

// full_only: false
func TestFirstFlowConfigurationRefusesMixedRecoveryAndPrivateInputs(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		for _, mode := range []string{"disabled", "enabled"} {
			for _, mutation := range []struct{ key, value string }{
				{"recovery_mode", ""}, {"recovery_mode", "automatic"},
				{"authority_kek_id", "contains space"}, {"reader_kek_id", "key\u00a0identity"},
				{"authority_kek_public_key_pem", "-----BEGIN PRIVATE KEY-----\nsecret"},
				{"reader_kek_public_key_pem", strings.Repeat("x", 4097)},
				{"authority_private_key", "secret"}, {"recovery_mode", map[string]string{"disabled": "enabled", "enabled": "disabled"}[mode]},
			} {
				settings := firstFlowConfigurationFixture(t, provider, mode)
				settings[mutation.key] = mutation.value
				if _, err := validateSettingsFields(settings, provider, ""); err == nil {
					t.Errorf("%s/%s accepted %s mutation", provider, mode, mutation.key)
				}
			}
		}
	}
}

// full_only: false
func TestFirstFlowPublicResourcesBindCleanupAndReports(t *testing.T) {
	settings := firstFlowConfigurationFixture(t, "aws", "enabled")
	original := safeRunContext(settings)
	for _, field := range publicResourceFields {
		changed := make(liveSettings)
		for key, value := range settings {
			changed[key] = value
		}
		changed[field] += "-changed"
		if sameResources(settings, changed) {
			t.Errorf("cleanup ignored %s", field)
		}
		context := safeRunContext(changed)
		if context.ConfigurationSHA256 == original.ConfigurationSHA256 || context.ResourceHashes[field] == original.ResourceHashes[field] {
			t.Errorf("report identity ignored %s", field)
		}
	}
	disabled := safeRunContext(firstFlowConfigurationFixture(t, "gcp", "disabled"))
	if _, present := disabled.ResourceHashes["recovery_key_id"]; present {
		t.Fatal("disabled recovery invented public identity")
	}
}

package records

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// These fixed fixture facts describe two different providers and owners; they
// are independent input literals, not output from an infrastructure renderer.
func stockFixtureLiteral(provider string) StockPluginFixture {
	v := StockPluginFixture{Schema: 1, Purpose: "stock-plugin-acceptance", FixtureID: "0123456789abcdef0123456789abcdef", Provider: provider, Region: "us-east-1", Bucket: "fixture-pa-0123456789abcdef0123456789abcdef", Account: "123456789012"}
	if provider == "gcp" {
		v.Region, v.Account, v.Project, v.ProjectNumber = "us-central1", "", "fixture-project", "123456789012"
	}
	return v
}

// full_only: false
func TestStockPluginFixtureRequiresExactReusableScope(t *testing.T) {
	t.Run("retained-version-proof", func(t *testing.T) {
		f := stockFixtureLiteral("aws")
		f.Purpose = "stock-plugin-retirement-proof"
		f.Bucket = "enkv-123456789012-pa-0123456789abcdef0123456789abcdef"
		if f.Validate() != nil {
			t.Fatal("dedicated AWS retirement fixture refused")
		}
		for _, other := range []StockPluginFixture{stockFixtureLiteral("gcp"), stockFixtureLiteral("aws")} {
			other.Purpose = f.Purpose
			if other.Validate() == nil {
				t.Fatal("version proof accepted outside its dedicated AWS bucket")
			}
		}
		f.Account = "210987654321"
		if f.Validate() == nil {
			t.Fatal("another account acquired the version proof fixture")
		}
	})
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			good := stockFixtureLiteral(provider)
			if err := good.Validate(); err != nil {
				t.Fatal("independent reusable fixture refused", err)
			}
			for _, damage := range []struct {
				name   string
				change func(*StockPluginFixture)
			}{
				{"missing-schema", func(v *StockPluginFixture) { v.Schema = 0 }},
				{"shared-bucket", func(v *StockPluginFixture) { v.Bucket = "ordinary-shared-state" }},
				{"foreign-fixture", func(v *StockPluginFixture) { v.FixtureID = strings.Repeat("b", 32) }},
				{"ambiguous-purpose", func(v *StockPluginFixture) { v.Purpose = "general-cleanup" }},
				{"foreign-provider", func(v *StockPluginFixture) { v.Provider = "other" }},
				{"uppercase-identifier", func(v *StockPluginFixture) { v.FixtureID = strings.ToUpper(v.FixtureID) }},
				{"missing-region", func(v *StockPluginFixture) { v.Region = "" }},
				{"missing-owner", func(v *StockPluginFixture) { v.Account, v.ProjectNumber = "", "" }},
				{"mixed-owner-kinds", func(v *StockPluginFixture) {
					v.Account, v.Project, v.ProjectNumber = "123456789012", "fixture-project", "123456789012"
				}},
			} {
				t.Run(damage.name, func(t *testing.T) {
					v := good
					damage.change(&v)
					if v.Validate() == nil {
						t.Fatal("invalid fixture identity accepted")
					}
				})
			}
		})
	}
}

// full_only: false
func TestStockPluginGrantBindsOriginalRunAndActualPreflight(t *testing.T) {
	good := StockPluginGrant{Schema: 1, Fixture: stockFixtureLiteral("aws"), RunID: strings.Repeat("a", 32), Scenario: StockPluginScenario, Prefix: "enkv-test/" + strings.Repeat("a", 32) + "/stock-case", LimitsSHA256: strings.Repeat("b", 64), PreflightEmpty: true, BucketIdentity: "2026-10-31T00:00:00Z"}
	if good.Validate() != nil {
		t.Fatal("exact original run grant refused")
	}
	for _, damage := range []struct {
		name   string
		change func(*StockPluginGrant)
	}{
		{"foreign-run", func(v *StockPluginGrant) { v.RunID = strings.Repeat("c", 32) }},
		{"foreign-scenario", func(v *StockPluginGrant) { v.Scenario = "public-configuration.manifest/atomic_public_file" }},
		{"no-preflight", func(v *StockPluginGrant) { v.PreflightEmpty = false }},
		{"no-original-identity", func(v *StockPluginGrant) { v.BucketIdentity = "" }},
		{"no-finite-limits-binding", func(v *StockPluginGrant) { v.LimitsSHA256 = "" }},
		{"parent-prefix", func(v *StockPluginGrant) { v.Prefix += "/../other" }},
	} {
		t.Run(damage.name, func(t *testing.T) {
			v := good
			damage.change(&v)
			if v.Validate() == nil {
				t.Fatal("different run, resource or preflight acquired deletion authority")
			}
		})
	}
}

// full_only: false
func TestStockPluginPrefixCleanupBindsOriginalGrantAndObservation(t *testing.T) {
	grant := StockPluginGrant{Schema: 1, Fixture: stockFixtureLiteral("aws"), RunID: strings.Repeat("a", 32), Scenario: StockPluginScenario, Prefix: "enkv-test/" + strings.Repeat("a", 32) + "/stock-case", LimitsSHA256: strings.Repeat("b", 64), PreflightEmpty: true, BucketIdentity: "2026-10-31T00:00:00Z"}
	good := StockPluginPrefixCleanup{Schema: 1, RunID: grant.RunID, FixtureID: grant.Fixture.FixtureID, Prefix: grant.Prefix, BucketIdentity: grant.BucketIdentity, Started: true, Completed: true, ObservedEmpty: true}
	if err := good.Validate(grant); err != nil {
		t.Fatal("exact prefix observation refused", err)
	}
	for _, damage := range []struct {
		name   string
		change func(*StockPluginPrefixCleanup)
	}{
		{"missing-schema", func(v *StockPluginPrefixCleanup) { v.Schema = 0 }},
		{"different-run", func(v *StockPluginPrefixCleanup) { v.RunID = strings.Repeat("c", 32) }},
		{"different-fixture", func(v *StockPluginPrefixCleanup) { v.FixtureID = strings.Repeat("d", 32) }},
		{"different-prefix", func(v *StockPluginPrefixCleanup) { v.Prefix += "-sibling" }},
		{"different-bucket-observation", func(v *StockPluginPrefixCleanup) { v.BucketIdentity = "other" }},
		{"unstarted", func(v *StockPluginPrefixCleanup) { v.Started = false }},
		{"incomplete", func(v *StockPluginPrefixCleanup) { v.Completed = false }},
		{"not-observed-empty", func(v *StockPluginPrefixCleanup) { v.ObservedEmpty = false }},
	} {
		t.Run(damage.name, func(t *testing.T) {
			v := good
			damage.change(&v)
			if v.Validate(grant) == nil {
				t.Fatal("different or incomplete prefix observation accepted")
			}
		})
	}
	grant.PreflightEmpty = false
	if good.Validate(grant) == nil {
		t.Fatal("final observation invented original empty-prefix authority")
	}
}

// full_only: false
func TestStockPluginEvidenceReadRefusesUnknownAndOversizedFields(t *testing.T) {
	directory := t.TempDir()
	path := directory + "/evidence.json"
	if WriteJSON(path, map[string]any{"schema": 1, "secret": "not permitted"}, 0600) != nil {
		t.Fatal("fixture write failed")
	}
	if _, err := ReadStockPluginEvidence(path); err == nil {
		t.Fatal("unknown evidence field accepted")
	}
	id := strings.Repeat("a", 64)
	for _, test := range []struct {
		name, fields string
		accepted     bool
	}{
		{"historical-absence", ``, true},
		{"observed", `,"diagnostic_sha256":"` + id + `","diagnostic_bytes":12,"diagnostic_status":"observed"`, true},
		{"partial-readable", `,"diagnostic_sha256":"` + id + `","diagnostic_bytes":12,"diagnostic_status":"partial"`, true},
		{"unavailable-readable", `,"diagnostic_sha256":"` + id + `","diagnostic_bytes":12,"diagnostic_status":"unavailable"`, true},
		{"write-failed-readable", `,"diagnostic_status":"write-failed"`, true},
		{"null-status", `,"diagnostic_status":null`, false},
		{"empty-status", `,"diagnostic_status":""`, false},
		{"uppercase-alias", `,"DIAGNOSTIC_STATUS":null`, false},
		{"mixed-case-after-canonical", `,"diagnostic_sha256":"` + id + `","diagnostic_bytes":12,"diagnostic_status":"observed","Diagnostic_Status":null`, false},
		{"null-digest", `,"diagnostic_sha256":null,"diagnostic_bytes":12,"diagnostic_status":"observed"`, false},
		{"empty-digest", `,"diagnostic_sha256":"","diagnostic_bytes":12,"diagnostic_status":"observed"`, false},
		{"null-bytes", `,"diagnostic_sha256":"` + id + `","diagnostic_bytes":null,"diagnostic_status":"observed"`, false},
		{"zero-bytes", `,"diagnostic_sha256":"` + id + `","diagnostic_bytes":0,"diagnostic_status":"observed"`, false},
		{"missing-status", `,"diagnostic_sha256":"` + id + `","diagnostic_bytes":12`, false},
		{"missing-bytes", `,"diagnostic_sha256":"` + id + `","diagnostic_status":"observed"`, false},
		{"missing-digest", `,"diagnostic_bytes":12,"diagnostic_status":"observed"`, false},
		{"unknown-status", `,"diagnostic_sha256":"` + id + `","diagnostic_bytes":12,"diagnostic_status":"unknown"`, false},
		{"failed-with-reference", `,"diagnostic_sha256":"` + id + `","diagnostic_status":"write-failed"`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := json.RawMessage(`{"schema":1,"commands":[{"ordinal":0` + test.fields + `}]}`)
			if WriteJSON(path, body, 0600) != nil {
				t.Fatal("wire fixture write failed")
			}
			_, err := ReadStockPluginEvidence(path)
			if (err == nil) != test.accepted {
				t.Fatal("diagnostic field presence was not preserved", err)
			}
		})
	}
	var value StockPluginEvidence
	if json.Unmarshal([]byte(`{"schema":1,"provider":"aws"}`), &value) != nil {
		t.Fatal("fixture decode failed")
	}
	value.Assertions = []string{strings.Repeat("x", MaximumStockPluginEvidenceBytes)}
	if WriteStockPluginEvidence(path, value) == nil {
		t.Fatal("oversized live evidence accepted")
	}
}

// full_only: false
func TestStockPluginCleanupRequiresProviderFactsBeforePrefixObservation(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			// This is the complete independent pre-cleanup obligation set. The
			// prefix observation must be produced only after prefix cleanup.
			before := []string{"a0-created", "a1-pending-a", "b-same-epoch-reused", "missing-a-refused", "exact-a-retired", "b2-created", "b-retired-a1", "outputs-published", "cloud-output-values-equal", "manifest-complete", "reconstruction-canonical", "final-generation-retired", "post-exit-reader"}
			if provider == "aws" {
				before = append(before, "github-metadata-checked")
			}
			slices.Sort(before)
			if !slices.Equal(stockPluginBeforeCleanupAssertions(provider), before) || validateStockPluginAssertions(before, stockPluginBeforeCleanupAssertions(provider)) != nil {
				t.Fatal("pre-cleanup lost a known provider obligation")
			}
			if validateStockPluginAssertions(before, StockPluginAssertions(provider)) == nil {
				t.Fatal("provider completion invented a final prefix observation")
			}
			complete := append(slices.Clone(before), "store-prefix-observed-empty")
			if validateStockPluginAssertions(complete, StockPluginAssertions(provider)) != nil || validateStockPluginAssertions(complete, stockPluginBeforeCleanupAssertions(provider)) == nil {
				t.Fatal("prefix observation did not preserve the one-time cleanup boundary")
			}
			for index := range before {
				missing := append(slices.Clone(before[:index]), before[index+1:]...)
				if validateStockPluginAssertions(missing, stockPluginBeforeCleanupAssertions(provider)) == nil {
					t.Fatal("missing provider obligation acquired cleanup authority", before[index])
				}
			}
		})
	}
}

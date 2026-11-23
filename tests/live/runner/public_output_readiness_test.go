package core

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

// full_only: false
func TestPublicOutputCleanupDeclarationComparisonPreservesCompleteMeaning(t *testing.T) {
	input := liveRunInput{Prefix: "enkv-test/declaration/fixture", Scenarios: []string{"public-configuration.output-standalone/output_standalone"},
		Settings: liveSettings{Provider: "aws", Region: "us-east-1", Account: "123456789012"},
		PublicConfiguration: &publicConfigurationInput{Outputs: &records.PublicOutputScopes{
			Repository:   records.PublicOutputScope{Owner: "owner", Repository: "repository"},
			Organization: records.PublicOutputScope{Owner: "organization", Visibility: "selected", Repositories: []uint64{9007199254740993, 18446744073709551615}},
			Environment:  records.PublicOutputScope{Owner: "owner", Repository: "repository", Environment: "prod"},
		}}}
	names := publicOutputNames(input.Prefix)
	for _, tc := range []struct {
		plain, secret map[string]any
		ok            bool
	}{
		{map[string]any{}, map[string]any{"output_encoding": "base64"}, true},
		{map[string]any{"output_encoding": "raw"}, map[string]any{"output_encoding": "base64"}, true},
		{map[string]any{"output_encoding": "base64"}, map[string]any{"output_encoding": "base64"}, false},
		{map[string]any{}, map[string]any{"output_encoding": "raw"}, false},
		{map[string]any{}, map[string]any{}, false},
	} {
		doc := map[string]any{"entries": map[string]any{names[0]: tc.plain, names[1]: tc.secret}}
		if publicOutputEncodingsMatch(doc, names) != tc.ok {
			t.Fatal("cleanup accepted different entry output encodings")
		}
	}
	want, err := json.Marshal(publicOutputDeclaration(input))
	if err != nil {
		t.Fatal(err)
	}
	for _, condition := range []string{"exact", "owner", "repository", "environment", "visibility", "large-repository", "maximum-repository", "repository-order", "missing-destination", "extra-destination", "routing", "encoding"} {
		t.Run(condition, func(t *testing.T) {
			var decoded map[string]any
			decoder := json.NewDecoder(bytes.NewReader(want))
			decoder.UseNumber()
			if decoder.Decode(&decoded) != nil {
				t.Fatal("complete declaration fixture unavailable")
			}
			destinations := decoded["destinations"].(map[string]any)
			settings := func(name string) map[string]any {
				return destinations[name].(map[string]any)["settings"].(map[string]any)
			}
			switch condition {
			case "owner":
				settings("github-repository")["owner"] = "other"
			case "repository":
				settings("github-repository")["repository"] = "other"
			case "environment":
				settings("github-environment")["environment"] = "other"
			case "visibility":
				settings("github-organization")["visibility"] = "all"
			case "large-repository":
				settings("github-organization")["repositories"].([]any)[0] = json.Number("9007199254740992")
			case "maximum-repository":
				settings("github-organization")["repositories"].([]any)[1] = json.Number("18446744073709551614")
			case "repository-order":
				repositories := settings("github-organization")["repositories"].([]any)
				repositories[0], repositories[1] = repositories[1], repositories[0]
			case "missing-destination":
				delete(destinations, "github-environment")
			case "extra-destination":
				destinations["foreign"] = destinations["github-environment"]
			case "routing":
				decoded["routing"].(map[string]any)["default"] = []string{"aws-secrets-manager"}
			case "encoding":
				destinations["aws-secrets-manager"].(map[string]any)["encodings"] = map[string]any{"obsolete": "raw"}
			}
			actual, err := json.Marshal(decoded)
			if err != nil || publicOutputDeclarationMatches(actual, want) != (condition == "exact") {
				t.Fatal("cleanup declaration comparison changed scope, numeric identity or complete structure")
			}
		})
	}
}

// full_only: false
func TestPublicOutputScenariosKeepDistinctNames(t *testing.T) {
	input := liveRunInput{
		RunID:     "0123456789abcdef0123456789abcdef",
		Scenarios: []string{"public-configuration.output-standalone/output_standalone"},
		Settings:  liveSettings{Provider: liveProvider(), Region: "us-east-1", Account: "123456789012", ProjectNumber: "123456789"},
		PublicConfiguration: &publicConfigurationInput{Outputs: &records.PublicOutputScopes{
			Repository:   records.PublicOutputScope{Owner: "owner", Repository: "repository"},
			Organization: records.PublicOutputScope{Owner: "organization", Visibility: "selected", Repositories: []uint64{101, 202}},
			Environment:  records.PublicOutputScope{Owner: "owner", Repository: "repository", Environment: "environment"},
		}},
	}
	seen := make(map[string]string)
	for _, row := range []struct{ run, directory string }{
		{input.RunID, "0000-output-standalone"},
		{input.RunID, "0001-output-combined"},
		{input.RunID, "0002-output-standalone"},
		{"fedcba9876543210fedcba9876543210", "0000-output-standalone"},
	} {
		input.RunID, input.Prefix = row.run, "enkv-test/"+row.run+"/"+row.directory
		names := publicOutputDeclaration(input)["groups"].([][]string)[0]
		if len(names) != 2 || names[0] == names[1] {
			t.Fatal("plain and secret output names are not distinct")
		}
		for _, name := range names {
			if len(name) > 100 || !strings.HasPrefix(name, "ENKV_") || strings.Trim(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != "" {
				t.Fatal("output name exceeds the common provider grammar")
			}
			if previous, exists := seen[name]; exists {
				t.Fatalf("output name reused across case prefixes: %s and %s", previous, input.Prefix)
			}
			seen[name] = input.Prefix
		}
		coordinates := publicExpectedOutputCoordinates(input)
		if len(coordinates) != 8 {
			t.Fatal("output scope does not contain both values in all four destinations")
		}
		for _, name := range names {
			count := 0
			for _, coordinate := range coordinates {
				if strings.HasSuffix(coordinate.PhysicalTarget, "/"+name) || strings.HasSuffix(coordinate.PhysicalTarget, ":secret:"+name) {
					count++
				}
			}
			if count != 4 {
				t.Fatal("publication and cleanup targets do not use the declared names")
			}
		}
		if again := publicOutputDeclaration(input)["groups"].([][]string)[0]; !slices.Equal(names, again) {
			t.Fatal("reopening a case changed its output names")
		}
	}
}

// full_only: false
func TestPublicPublicationCommandsReserveMarkerMutationAllowance(t *testing.T) {
	input := liveRunInput{Scenarios: []string{"public-configuration.manifest/atomic_public_file"}}
	for _, row := range []struct {
		name        string
		args        []string
		publication bool
		mutating    bool
	}{
		{"standalone-name", []string{"publish", "--name", "entry"}, true, true},
		{"standalone-deletion", []string{"publish", "--delete-coordinate", "coordinate"}, true, true},
		{"combined", []string{"apply", "--publish"}, true, true},
		{"ordinary-apply", []string{"apply"}, false, true},
		{"passive-publication-plan", []string{"plan", "--publish"}, false, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			want := budgetReservation{Requests: 128, BodyBytes: 16 << 20}
			if row.publication {
				// The larger controlled native fixture publishes both clouds and
				// all three GitHub scopes under this same child policy.
				want.Requests, want.BodyBytes = 2048, 64<<20
			}
			if row.mutating {
				want.Objects, want.ObjectBytes = want.Requests, want.BodyBytes
			}
			got := publicCommandReservation(input, false, nativeprocess.Policy{}, row.args)
			if got != want {
				t.Fatal("public command reservation differs from its native publication scope", got, want)
			}
			limits := liveLimits{Requests: got.Requests, BodyBytes: got.BodyBytes, Objects: got.Objects, ObjectBytes: got.ObjectBytes}
			budget := &runBudget{limits: limits}
			if !budget.absorbChild(got) || budget.snapshot() != got {
				t.Fatal("exact command reservation refused")
			}
			for _, field := range []string{"requests", "body", "objects", "object-bytes"} {
				short := limits
				switch field {
				case "requests":
					short.Requests--
				case "body":
					short.BodyBytes--
				case "objects":
					if short.Objects == 0 {
						continue
					}
					short.Objects--
				case "object-bytes":
					if short.ObjectBytes == 0 {
						continue
					}
					short.ObjectBytes--
				}
				budget := &runBudget{limits: short}
				if budget.absorbChild(got) || !budget.exhausted || budget.snapshot() != (budgetReservation{}) {
					t.Fatal("short command reservation was not refused atomically", field)
				}
			}
			limited := publicCommandReservation(input, false, nativeprocess.Policy{MaxRequests: 1, MaxBytes: 1}, row.args)
			if limited.Requests != 1 || limited.BodyBytes != 1 || row.mutating && (limited.Objects != 1 || limited.ObjectBytes != 1) {
				t.Fatal("explicit negative policy was widened")
			}
			consumer := publicCommandReservation(input, true, nativeprocess.Policy{}, row.args)
			if consumer != (budgetReservation{Requests: 128, BodyBytes: 16 << 20}) {
				t.Fatal("consumer acquired publication work")
			}
		})
	}
}

// full_only: false
func TestPublicOutputCleanupRequiresCompleteTerminalCoordinateSet(t *testing.T) {
	flag, reason := false, uint8(0)
	id, binding := strings.Repeat("a", 64), strings.Repeat("b", 64)
	expected := []publicOutputCoordinate{{ServiceContractID: "github-actions/service/v1", PhysicalTarget: "repos/owner/repo/actions/secrets/ENKV_RUN_SECRET", TargetContractID: "github-actions/target/v1", CoordinateID: id, BindingID: binding}}
	complete := true
	row := publicOutputPreviewRow{ServiceContractID: expected[0].ServiceContractID, PhysicalTarget: expected[0].PhysicalTarget, TargetContractID: expected[0].TargetContractID, Coordinate: &id, Binding: &binding, Origin: "observed", Basis: "warning", Actions: []string{}, Blockers: []string{}, Conditional: &flag, Reason: &reason, Remote: &complete, Late: &flag}
	baseline := publicOutputPreview{Schema: "PublicationPreview/v2", Complete: &complete, Reason: &reason, Warning: &flag, Entries: []publicOutputPreviewRow{row}}
	for _, condition := range []string{"exact", "incomplete", "missing-completion", "reason", "warning", "missing-warning", "missing-coordinate", "foreign-coordinate", "foreign-binding", "foreign-target", "foreign-service", "foreign-target-contract", "active", "unacknowledged", "pending-delete", "blocker", "conditional", "remote-absence-claim", "late-warning", "missing-actions", "missing-blockers", "missing-row", "extra-row"} {
		t.Run(condition, func(t *testing.T) {
			body, err := json.Marshal(baseline)
			var changed publicOutputPreview
			if err != nil || json.Unmarshal(body, &changed) != nil {
				t.Fatal("preview fixture unavailable")
			}
			switch condition {
			case "incomplete":
				*changed.Complete = false
			case "missing-completion":
				changed.Complete = nil
			case "reason":
				*changed.Reason = 1
			case "warning":
				*changed.Warning = true
			case "missing-warning":
				changed.Warning = nil
			case "missing-coordinate":
				changed.Entries[0].Coordinate = nil
			case "foreign-coordinate":
				*changed.Entries[0].Coordinate = strings.Repeat("c", 64)
			case "foreign-binding":
				*changed.Entries[0].Binding = strings.Repeat("d", 64)
			case "foreign-target":
				changed.Entries[0].PhysicalTarget += "_OTHER"
			case "foreign-service":
				changed.Entries[0].ServiceContractID = "different/service/v1"
			case "foreign-target-contract":
				changed.Entries[0].TargetContractID = "different/target/v1"
			case "active":
				changed.Entries[0].Origin = "both"
			case "unacknowledged":
				changed.Entries[0].Basis = "retained-deletion"
			case "pending-delete":
				changed.Entries[0].Actions = []string{"delete-owned"}
			case "blocker":
				changed.Entries[0].Blockers = []string{binding}
			case "conditional":
				*changed.Entries[0].Conditional = true
			case "remote-absence-claim":
				*changed.Entries[0].Remote = false
			case "late-warning":
				*changed.Entries[0].Late = true
			case "missing-actions":
				changed.Entries[0].Actions = nil
			case "missing-blockers":
				changed.Entries[0].Blockers = nil
			case "missing-row":
				changed.Entries = nil
			case "extra-row":
				changed.Entries = append(changed.Entries, changed.Entries[0])
			}
			if publicOutputPreviewMatches(changed, expected, true) != (condition == "exact") {
				t.Fatal("unsettled output evidence acquired State cleanup authority")
			}
		})
	}
	for _, effects := range []bool{false, true} {
		t.Setenv("GITHUB_TOKEN", "selected-token")
		env := publicOutputEnvironment([]string{"KEEP=yes", "GITHUB_TOKEN=other", "GH_TOKEN=fallback"}, effects, []string{"aws-secrets-manager", "github-repository", "github-organization", "github-environment"})
		if slices.Contains(env, "GH_TOKEN=fallback") || slices.Contains(env, "GITHUB_TOKEN=other") || slices.Contains(env, "GITHUB_TOKEN=selected-token") != effects || !slices.Contains(env, "KEEP=yes") {
			t.Fatal("output bearer escaped its selected effect child")
		}
	}
}

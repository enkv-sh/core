package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestApplyCLIRetirementSelectionsReachNewApplyOnly(t *testing.T) {
	for _, publish := range []bool{false, true} {
		for _, count := range []int{3, 128} {
			t.Run(fmt.Sprintf("publish=%t/count=%d", publish, count), func(t *testing.T) {
				args := []string{"--source=/source", "--source-format=json", "--json", "--log-level=off"}
				if publish {
					args = append(args, "--publish")
				}
				want := map[string]string{"": "private-generator", "a=b": "other-generator", strings.Repeat("n", 256): strings.Repeat("p", 255)}
				for i := 3; i < count; i++ {
					want[fmt.Sprintf("entry-%03d", i)] = "private-generator"
				}
				for name, plugin := range want {
					args = append(args, "--retire-generator", name+"="+plugin)
				}
				plain, combined := 0, 0
				check := func(operation contract.ID, options compositionfull.ApplyOptions) {
					if !operation.IsZero() || !reflect.DeepEqual(options.RetirementPlugins, want) {
						t.Fatal("retirement selections changed", options)
					}
				}
				var out, diagnostic bytes.Buffer
				code := runApplyWithExecutors(t.Context(), args, &out, &diagnostic,
					func(_ context.Context, _ contract.ID, _ string, _ configuration.Format, operation contract.ID, options compositionfull.ApplyOptions) compositionfull.ConfigurationApplyResult {
						plain++
						check(operation, options)
						return generatedCLIRefusal()
					}, func(_ context.Context, applyRequest, publicationRequest contract.ID, _ string, _ configuration.Format, operation contract.ID, _ compositionfull.ApplyPublicationOptions, options compositionfull.ApplyOptions) compositionfull.ConfigurationApplyPublicationResult {
						combined++
						check(operation, options)
						return compositionfull.ConfigurationApplyPublicationResult{PublicApplyPublicationResult: applyPublicationCLIResult(applyRequest, publicationRequest, false)}
					})
				wantCode, wantPlain, wantCombined := 2, 1, 0
				if publish {
					wantCode, wantPlain, wantCombined = 0, 0, 1
				}
				if code != wantCode || plain != wantPlain || combined != wantCombined || !json.Valid(out.Bytes()) {
					t.Fatal("retirement dispatch differs", code, plain, combined, diagnostic.String())
				}
			})
		}
	}
}

// full_only: false
func TestApplyCLIRetirementSelectionRejectsInvalidMappings(t *testing.T) {
	cases := [][]string{
		{"--retire-generator=entry"}, {"--retire-generator=entry="}, {"--retire-generator=="},
		{"--retire-generator=entry=../plugin"}, {"--retire-generator=entry=private plugin"},
		{"--retire-generator=" + strings.Repeat("n", 257) + "=plugin"},
		{"--retire-generator=entry=" + strings.Repeat("p", 256)},
		{"--retire-generator=" + string([]byte{0xff}) + "=plugin"},
		{"--retire-generator=entry=plugin", "--retire-generator=entry=plugin"},
		{"--retire-generator=entry=plugin", "--retire-generator=entry=other-plugin"},
		{"--retire-generator==plugin", "--retire-generator==other-plugin"},
		{"--operation=" + strings.Repeat("01", 32), "--retire-generator==plugin"},
	}
	var tooMany []string
	for i := 0; i < 129; i++ {
		tooMany = append(tooMany, fmt.Sprintf("--retire-generator=entry-%03d=plugin", i))
	}
	cases = append(cases, tooMany)
	for _, publish := range []bool{false, true} {
		for i, selectors := range cases {
			t.Run(fmt.Sprintf("publish=%t/case=%d", publish, i), func(t *testing.T) {
				args := []string{"--source=/source", "--source-format=json", "--json", "--log-level=off"}
				if publish {
					args = append(args, "--publish")
				}
				args = append(args, selectors...)
				calls := 0
				var out, diagnostic bytes.Buffer
				code := runApplyWithExecutors(t.Context(), args, &out, &diagnostic,
					func(context.Context, contract.ID, string, configuration.Format, contract.ID, compositionfull.ApplyOptions) compositionfull.ConfigurationApplyResult {
						calls++
						return compositionfull.ConfigurationApplyResult{}
					},
					func(context.Context, contract.ID, contract.ID, string, configuration.Format, contract.ID, compositionfull.ApplyPublicationOptions, compositionfull.ApplyOptions) compositionfull.ConfigurationApplyPublicationResult {
						calls++
						return compositionfull.ConfigurationApplyPublicationResult{}
					})
				if code != 2 || calls != 0 || !json.Valid(out.Bytes()) || !bytes.Contains(out.Bytes(), []byte("refused")) {
					t.Fatal("invalid selection reached execution", code, calls, out.String())
				}
			})
		}
	}
}

// full_only: false
func TestPublishCLIDeletionSelectionBounds(t *testing.T) {
	for _, count := range []int{1024, 1025} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			args := []string{"--source=/source", "--source-format=json", "--json", "--log-level=off"}
			want := make(map[contract.ID]string, count)
			for i := 1; i <= count; i++ {
				coordinate := fmt.Sprintf("%064x", i)
				plugin := "private-output"
				if i == 1 {
					plugin = strings.Repeat("p", 255)
				}
				args = append(args, "--delete-coordinate="+coordinate+"="+plugin)
				var id contract.ID
				id[30], id[31] = byte(i>>8), byte(i)
				want[id] = plugin
			}
			calls := 0
			var out, diagnostic bytes.Buffer
			code := runPublishWithExecutor(t.Context(), args, &out, &diagnostic, func(_ context.Context, id contract.ID, _ string, _ configuration.Format, options compositionfull.PublicationOptions) compositionfull.ConfigurationPublicationResult {
				calls++
				if len(options.Request.DeleteCoordinates) != count || !reflect.DeepEqual(options.DeletePlugins, want) {
					t.Fatal("exact deletion choices changed")
				}
				for i, coordinate := range options.Request.DeleteCoordinates {
					var expected contract.ID
					expected[30], expected[31] = byte((i+1)>>8), byte(i+1)
					if coordinate != expected {
						t.Fatal("coordinate order changed")
					}
				}
				return compositionfull.ConfigurationPublicationResult{PublicPublicationResult: core.PublicPublicationResult{RequestID: id, Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.InvalidIntent}}}
			})
			wantCalls := 1
			if count > 1024 {
				wantCalls = 0
			}
			if code != 2 || calls != wantCalls || !json.Valid(out.Bytes()) {
				t.Fatal("deletion bound differs", code, calls)
			}
		})
	}
}

// full_only: false
func TestManifestCLIPluginSettingsAndServiceBounds(t *testing.T) {
	plugin := strings.Repeat("p", 255)
	service := strings.Repeat("s", 256)
	settings := `"` + strings.Repeat("x", 16382) + `"`
	args := []string{"--source=source.json", "--source-format=json", "--out=manifest.bytes", "--plugin=" + plugin, "--service=" + service, "--settings=" + settings, "--json", "--log-level=off"}
	calls := 0
	var out, diagnostic bytes.Buffer
	code := runManifestWithExecutor(t.Context(), args, &out, &diagnostic, func(_ context.Context, _ contract.ID, _ string, _ configuration.Format, options compositionfull.ManifestOptions, _ string) compositionfull.ManifestFileResult {
		calls++
		if options.Plugin != plugin || options.ServiceFilter == nil || *options.ServiceFilter != service || string(options.Settings) != settings {
			t.Fatal("bounded renderer inputs changed")
		}
		return manifestCLIUnavailable()
	})
	if code != 3 || calls != 1 || !json.Valid(out.Bytes()) {
		t.Fatal("manifest boundary refused", code, calls, diagnostic.String())
	}
}

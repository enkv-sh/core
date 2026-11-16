package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicQueryGrammarRejectsInvalidSelectorsBeforeExecutors(t *testing.T) {
	for _, command := range []string{"inspect", "receipt"} {
		selector := "recipient-id"
		if command == "receipt" {
			selector = "operation"
		}
		base := []string{"--source=source.json", "--source-format=json", "--json"}
		type queryCase struct {
			args       []string
			structured bool
		}
		cases := []queryCase{
			{[]string{"--source=source.json", "--source-format="}, false},
			{[]string{"root-health", "--source=source.json", "--source-format=json", "--json"}, false},
			{append(append([]string{}, base...), "extra"), true},
			{append(append([]string{}, base...), "--descriptor=ref"), true},
			{append(append([]string{}, base...), "--root-pin=ref"), true},
			{append(append([]string{}, base...), "--unknown=private-sentinel"), true},
		}
		for _, id := range []string{"", strings.Repeat("00", 32), strings.Repeat("AA", 32), strings.Repeat("01", 31), strings.Repeat("z", 64)} {
			cases = append(cases, queryCase{append(append([]string{}, base...), "--"+selector+"="+id), true})
		}
		for _, flag := range []struct{ name, value string }{{"source", "source.json"}, {"source-format", "json"}, {selector, strings.Repeat("01", 32)}, {"json", "true"}, {"log-level", "warn"}, {"telemetry-config", "config.json"}} {
			values := append([]string{}, base...)
			if flag.name != "source" && flag.name != "source-format" && flag.name != "json" {
				values = append(values, "--"+flag.name+"="+flag.value)
			}
			values = append(values, "--"+flag.name+"="+flag.value)
			cases = append(cases, queryCase{values, true})
		}
		for n, row := range cases {
			t.Run(command+"/"+string(rune('a'+n)), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				calls := 0
				domain := func(context.Context, contract.ID, string, configuration.Format) compositionfull.ConfigurationInspectionResult {
					calls++
					return compositionfull.ConfigurationInspectionResult{PublicDomainInspectionResult: core.PublicDomainInspectionResult{}}
				}
				recipient := func(context.Context, contract.ID, string, configuration.Format, compositionfull.RecipientSelector) compositionfull.ConfigurationRecipientInspectionResult {
					calls++
					return compositionfull.ConfigurationRecipientInspectionResult{PublicRecipientInspectionResult: core.PublicRecipientInspectionResult{}}
				}
				list := func(context.Context, contract.ID, string, configuration.Format) compositionfull.ConfigurationReceiptListResult {
					calls++
					return compositionfull.ConfigurationReceiptListResult{PublicReceiptListResult: core.PublicReceiptListResult{}}
				}
				detail := func(context.Context, contract.ID, string, configuration.Format, contract.ID) compositionfull.ConfigurationReceiptDetailResult {
					calls++
					return compositionfull.ConfigurationReceiptDetailResult{PublicReceiptDetailResult: core.PublicReceiptDetailResult{}}
				}
				var out, diagnostic bytes.Buffer
				var code int
				if command == "inspect" {
					code = runInspectWithExecutors(ctx, row.args, &out, &diagnostic, domain, recipient, nil)
				} else {
					code = runReceiptWithExecutors(ctx, row.args, &out, &diagnostic, list, detail)
				}
				if code != 2 || calls != 0 || json.Valid(out.Bytes()) != row.structured || bytes.Contains(out.Bytes(), []byte("private-sentinel")) {
					t.Fatal("invalid query escaped input boundary", code, calls, out.String())
				}
				if row.structured {
					var value map[string]json.RawMessage
					if json.Unmarshal(out.Bytes(), &value) != nil || string(value["state_result"]) != `"refused"` || string(value["payload"]) != "null" {
						t.Fatal("invalid input lost closed JSON refusal", out.String())
					}
				}
			})
		}
	}
}

// full_only: false
func TestPublicQueryCLIFormsCaptureExactSourceFormatAndSelector(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	for _, form := range []string{"domain", "recipient", "list", "detail"} {
		for _, format := range []string{"json", "yaml"} {
			t.Run(form+"/"+format, func(t *testing.T) {
				args := []string{"--source", "relative-source", "--source-format", format, "--json"}
				selected := contract.ID{1}
				if form == "recipient" {
					args = append(args, "--recipient-id", strings.Repeat("01", 1)+strings.Repeat("00", 31))
				}
				if form == "detail" {
					args = append(args, "--operation", strings.Repeat("01", 1)+strings.Repeat("00", 31))
				}
				calls := 0
				check := func(nonce contract.ID, path string, got configuration.Format) {
					calls++
					want, _ := filepath.Abs("relative-source")
					wantFormat := configuration.JSON
					if format == "yaml" {
						wantFormat = configuration.YAML
					}
					if nonce.IsZero() || path != want || got != wantFormat {
						t.Fatal("source inputs changed", path, got)
					}
				}
				domain := func(_ context.Context, nonce contract.ID, path string, f configuration.Format) compositionfull.ConfigurationInspectionResult {
					check(nonce, path, f)
					r, _ := compositionfull.NewDomainInspectionRefusal(f)
					return compositionfull.ConfigurationInspectionResult{PublicDomainInspectionResult: r}
				}
				recipient := func(_ context.Context, nonce contract.ID, path string, f configuration.Format, selection compositionfull.RecipientSelector) compositionfull.ConfigurationRecipientInspectionResult {
					id := selection.ID
					check(nonce, path, f)
					if id != selected {
						t.Fatal("recipient selector changed")
					}
					r, _ := compositionfull.NewRecipientInspectionRefusal(f)
					return compositionfull.ConfigurationRecipientInspectionResult{PublicRecipientInspectionResult: r}
				}
				list := func(_ context.Context, nonce contract.ID, path string, f configuration.Format) compositionfull.ConfigurationReceiptListResult {
					check(nonce, path, f)
					r, _ := compositionfull.NewReceiptListRefusal(f)
					return compositionfull.ConfigurationReceiptListResult{PublicReceiptListResult: r}
				}
				detail := func(_ context.Context, nonce contract.ID, path string, f configuration.Format, id contract.ID) compositionfull.ConfigurationReceiptDetailResult {
					check(nonce, path, f)
					if id != selected {
						t.Fatal("operation selector changed")
					}
					r, _ := compositionfull.NewReceiptDetailRefusal(f)
					return compositionfull.ConfigurationReceiptDetailResult{PublicReceiptDetailResult: r}
				}
				var out, diagnostic bytes.Buffer
				var code int
				if form == "domain" || form == "recipient" {
					code = runInspectWithExecutors(ctx, args, &out, &diagnostic, domain, recipient, nil)
				} else {
					code = runReceiptWithExecutors(ctx, args, &out, &diagnostic, list, detail)
				}
				if code != 2 || calls != 1 || !json.Valid(out.Bytes()) {
					t.Fatal("valid grammar did not invoke its exact query", code, calls, out.String(), diagnostic.String())
				}
			})
		}
	}
}

// full_only: false
func TestPublicQueryDispatchHelpAndIncompleteOutputKeepClosedExit(t *testing.T) {
	for _, command := range []string{"inspect", "receipt"} {
		var out, diagnostic bytes.Buffer
		if code := run([]string{command, "--help"}, &out, &diagnostic); code != 0 || !strings.Contains(out.String(), "--source-format yaml|json") {
			t.Fatal("query help missing", command, code, out.String())
		}
		out.Reset()
		if code := run([]string{command, "--json"}, &out, &diagnostic); code != 2 || !json.Valid(out.Bytes()) {
			t.Fatal("query dispatch fell through", command, code, out.String())
		}
		if code := run([]string{command, "--json"}, shortPublicQueryOutput{}, io.Discard); code == 0 {
			t.Fatal("short output returned success")
		}
	}
}

type shortPublicQueryOutput struct{}

func (shortPublicQueryOutput) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	return len(b) - 1, nil
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
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
func TestInspectCapacityRejectsMixedAndUnboundedInputsBeforeExecutors(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	base := []string{"--source=source.json", "--source-format=json", "--json"}
	cases := [][]string{{"--capacity", "--recipient-id=" + strings.Repeat("01", 32)}, {"--cursor=page"}, {"--capacity", "--cursor="}, {"--capacity", "--cursor=" + strings.Repeat("x", core.GCCursorMaxLength+1)}, {"--capacity", "--capacity"}, {"--capacity", "--cursor=one", "--cursor=two"}, {"--capacity", "extra"}}
	for _, suffix := range cases {
		calls := 0
		domain := func(context.Context, contract.ID, string, configuration.Format) compositionfull.ConfigurationInspectionResult {
			calls++
			return compositionfull.ConfigurationInspectionResult{PublicDomainInspectionResult: core.PublicDomainInspectionResult{}}
		}
		recipient := func(context.Context, contract.ID, string, configuration.Format, compositionfull.RecipientSelector) compositionfull.ConfigurationRecipientInspectionResult {
			calls++
			return compositionfull.ConfigurationRecipientInspectionResult{PublicRecipientInspectionResult: core.PublicRecipientInspectionResult{}}
		}
		capacity := func(context.Context, core.CapacityInspectionRequest, string, configuration.Format) compositionfull.ConfigurationCapacityResult {
			calls++
			return compositionfull.ConfigurationCapacityResult{PublicCapacityInspectionResult: core.PublicCapacityInspectionResult{}}
		}
		var out, diagnostic bytes.Buffer
		code := runInspectWithExecutors(ctx, append(append([]string{}, base...), suffix...), &out, &diagnostic, domain, recipient, capacity)
		if code != 2 || calls != 0 || !json.Valid(out.Bytes()) {
			t.Fatal("invalid capacity grammar reached executor", code, calls, out.String())
		}
	}
}

// full_only: false
func TestInspectCapacityPassesOnlyExactTypedRequest(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	for _, syntax := range []string{"json", "yaml"} {
		calls := 0
		capacity := func(_ context.Context, request core.CapacityInspectionRequest, path string, format configuration.Format) compositionfull.ConfigurationCapacityResult {
			calls++
			want, _ := filepath.Abs("source." + syntax)
			if request.RequestNonce.IsZero() || request.Cursor != "bounded-wrapper" || path != want || syntax == "json" && format != configuration.JSON || syntax == "yaml" && format != configuration.YAML {
				t.Fatal("capacity request changed", request, path, format)
			}
			r, err := compositionfull.NewCapacityInspectionRefusal(format)
			if err != nil {
				t.Fatal(err)
			}
			return compositionfull.ConfigurationCapacityResult{PublicCapacityInspectionResult: r}
		}
		var out, diagnostic bytes.Buffer
		code := runInspectWithExecutors(ctx, []string{"--source=source." + syntax, "--source-format=" + syntax, "--capacity", "--cursor=bounded-wrapper", "--json"}, &out, &diagnostic, nil, nil, capacity)
		if code != 2 || calls != 1 || !json.Valid(out.Bytes()) || !bytes.Contains(out.Bytes(), []byte(`"operation_kind":"inspect-capacity"`)) {
			t.Fatal("capacity grammar failed typed dispatch", code, calls, out.String(), diagnostic.String())
		}
	}
}

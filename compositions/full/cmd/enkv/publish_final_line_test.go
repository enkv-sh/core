package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestPublishFinalLineFailurePreservesCompletedInvocation(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		name := "no-change"
		if unknown {
			name = "unknown"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			var out applyPublicationFinalLFShortWriter
			var diagnostic bytes.Buffer
			var retained core.PublicPublicationResult
			calls := 0
			code := runPublishWithExecutor(ctx, []string{"--source", "/source", "--source-format", "json", "--name", "entry", "--json", "--log-level", "off"}, &out, &diagnostic,
				func(_ context.Context, request contract.ID, _ string, _ configuration.Format, _ compositionfull.PublicationOptions) compositionfull.ConfigurationPublicationResult {
					calls++
					retained = *applyPublicationCLIResult(contract.ID{1}, request, unknown).Publication.Result
					return compositionfull.ConfigurationPublicationResult{PublicPublicationResult: retained}
				})
			wantSummary := uint8(contract.PublicationSummaryNoChange)
			wantDisposition := uint8(contract.PublicationNoOp)
			if unknown {
				wantSummary, wantDisposition = contract.PublicationSummaryUnknown, contract.PublicationOutcomeUnknown
			}
			var body map[string]json.RawMessage
			if code != 2 || calls != 1 || !strings.Contains(diagnostic.String(), "output failed") || json.Unmarshal(out.body.Bytes(), &body) != nil || string(body["schema"]) != `"ProductResult/v1"` || string(body["operation_kind"]) != `"publish"` {
				t.Fatal("final line failure did not follow one complete publication body", code, calls)
			}
			if retained.Summary != wantSummary || retained.Output == nil || len(retained.Output.Entries) != 1 || retained.Output.Entries[0].Actions[0].Disposition != wantDisposition {
				t.Fatal("delivery failure changed retained publication facts")
			}
		})
	}
}

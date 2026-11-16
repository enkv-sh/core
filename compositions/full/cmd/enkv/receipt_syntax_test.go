package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core/contract"
)

// full_only: false
func TestReceiptInvalidListSyntaxGivesSupportedCommand(t *testing.T) {
	for _, token := range []string{"list", "private-sentinel"} {
		t.Run(token, func(t *testing.T) {
			calls := 0
			list := func(context.Context, contract.ID, string, configuration.Format) compositionfull.ConfigurationReceiptListResult {
				calls++
				return compositionfull.ConfigurationReceiptListResult{}
			}
			var out, diagnostic bytes.Buffer
			code := runReceiptWithExecutors(t.Context(), []string{token}, &out, &diagnostic, list, nil)
			if code != 2 || calls != 0 || !strings.Contains(diagnostic.String(), "Use enkv receipt to list retained receipts") || strings.Contains(diagnostic.String(), "private-sentinel") {
				t.Fatalf("unsupported syntax lost safe correction: exit=%d calls=%d diagnostic=%q", code, calls, diagnostic.String())
			}
		})
	}
}

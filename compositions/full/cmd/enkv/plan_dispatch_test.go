package main

import (
	"bytes"
	"strings"
	"testing"
)

// full_only: false
func TestPlanDispatchAndRemovedCommands(t *testing.T) {
	t.Run("plan uses public Reader", func(t *testing.T) {
		var out, diagnostic bytes.Buffer
		code := run([]string{"plan", "--trusted", "/absent", "--trusted-format", "json", "--json"}, &out, &diagnostic)
		if code != 2 || !strings.Contains(out.String(), "compare-public-configuration") || strings.Contains(diagnostic.String(), "unsupported command") {
			t.Fatal("plan did not use the public comparison route", code, out.String(), diagnostic.String())
		}
	})
	for _, args := range [][]string{{"compare", "--json"}, {"rotate", "--json"}, {"recipients", "exclude", "--json"}} {
		t.Run(strings.Join(args[:len(args)-1], " "), func(t *testing.T) {
			var out, diagnostic bytes.Buffer
			code := run(args, &out, &diagnostic)
			if code != 2 || !strings.Contains(diagnostic.String(), "unsupported command") || !strings.Contains(out.String(), `"operation_payload":"none"`) {
				t.Fatal("withdrawn command remains recognized", code, out.String(), diagnostic.String())
			}
		})
	}
}

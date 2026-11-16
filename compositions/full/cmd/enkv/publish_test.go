package main

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestPublishRequiresExplicitExactSelectorsBeforeExecution(t *testing.T) {
	id := strings.Repeat("01", 32)
	for _, args := range [][]string{
		nil,
		{"--source", "/source", "--source-format", "json"},
		{"--source", "/source", "--name", "entry"},
		{"--source", "/source", "--source-format", "automatic", "--name", "entry"},
		{"--source", "/source", "--source-format", "json", "entry"},
		{"--source", "/source", "--source-format", "json", "--name", "entry", "--name", "entry"},
		{"--source", "/source", "--source-format", "json", "--delete-coordinate", id + "=private-output", "--delete-coordinate", id + "=private-output"},
		{"--source", "/source", "--source-format", "json", "--delete-coordinate", id + "=private-output", "--delete-coordinate", id + "=other-output"},
		{"--source", "/source", "--source-format", "json", "--delete-coordinate", id},
		{"--source", "/source", "--source-format", "json", "--delete-coordinate", id + "="},
		{"--source", "/source", "--source-format", "json", "--delete-coordinate", id + "=../output"},
		{"--source", "/source", "--source-format", "json", "--delete-coordinate", id + "=output=other"},
		{"--source", "/source", "--source-format", "json", "--delete-coordinate", id + "=" + strings.Repeat("p", 256)},
		{"--source", "/source", "--source-format", "json", "--delete-coordinate", strings.Repeat("00", 32) + "=private-output"},
		{"--source", "/source", "--source-format", "json", "--delete-coordinate", strings.Repeat("AB", 32) + "=private-output"},
		{"--source", "/source", "--source-format", "json", "--delete-coordinate", "provider/address"},
		{"--source", "/source", "--source-format", "json", "--name", "entry", "--republish-after-unknown"},
		{"--source", "/source", "--source-format", "json", "--name", "entry", "--republish-after-unknown", id, "--republish-after-unknown", id},
		{"--source", "/source", "--source-format", "json", "--republish-after-unknown", id},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			calls := 0
			var out, diagnostic bytes.Buffer
			code := runPublishWithExecutor(ctx, args, &out, &diagnostic, func(context.Context, contract.ID, string, configuration.Format, compositionfull.PublicationOptions) compositionfull.ConfigurationPublicationResult {
				calls++
				return compositionfull.ConfigurationPublicationResult{PublicPublicationResult: core.PublicPublicationResult{}}
			})
			if code != 2 || calls != 0 || !strings.HasPrefix(out.String(), "Publication: refused\n") {
				t.Fatal("ambiguous publication reached execution", code, calls, out.String())
			}
		})
	}
}

// full_only: false
func TestPublishPreservesEmptyNameAndExactDeletionAndUnknownIDs(t *testing.T) {
	coordinateText, blockerText := strings.Repeat("01", 32), strings.Repeat("02", 32)
	coordinate, _ := parseID(coordinateText)
	blocker, _ := parseID(blockerText)
	for _, test := range []struct {
		name      string
		selectors []string
		want      compositionfull.PublicationOptions
	}{
		{"empty-name", []string{"--name", ""}, compositionfull.PublicationOptions{Request: core.PublicationRequest{Names: []string{""}}, DeletePlugins: map[contract.ID]string{}}},
		{"deletion-only", []string{"--delete-coordinate", coordinateText + "=private-output"}, compositionfull.PublicationOptions{Request: core.PublicationRequest{DeleteCoordinates: []contract.ID{coordinate}}, DeletePlugins: map[contract.ID]string{coordinate: "private-output"}}},
		{"disjoint-mixed", []string{"--name", "entry", "--delete-coordinate", coordinateText + "=private-output", "--republish-after-unknown", blockerText}, compositionfull.PublicationOptions{Request: core.PublicationRequest{Names: []string{"entry"}, DeleteCoordinates: []contract.ID{coordinate}, RepublishAfterUnknown: []contract.ID{blocker}}, DeletePlugins: map[contract.ID]string{coordinate: "private-output"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			calls := 0
			args := append([]string{"--source", "/source", "--source-format", "json", "--json"}, test.selectors...)
			var out, diagnostic bytes.Buffer
			code := runPublishWithExecutor(ctx, args, &out, &diagnostic, func(got context.Context, request contract.ID, path string, format configuration.Format, input compositionfull.PublicationOptions) compositionfull.ConfigurationPublicationResult {
				calls++
				deadline, finite := got.Deadline()
				wantDeadline, _ := ctx.Deadline()
				if !finite || deadline != wantDeadline || request.IsZero() || path != "/source" || format != configuration.JSON || !reflect.DeepEqual(input, test.want) {
					t.Fatal("CLI changed the exact public request or deadline", input)
				}
				return compositionfull.ConfigurationPublicationResult{PublicPublicationResult: core.PublicPublicationResult{RequestID: request, Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.InvalidIntent}}}
			})
			var record map[string]json.RawMessage
			if json.Unmarshal(out.Bytes(), &record) != nil || code != 2 || calls != 1 || string(record["operation_kind"]) != `"publish"` || string(record["payload"]) != "null" {
				t.Fatal("exact selector was not passed once", code, calls, out.String())
			}
		})
	}
}

// full_only: false
func TestPublishResultDeliveryFailureDoesNotRepeatExecution(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	calls := 0
	var diagnostic bytes.Buffer
	code := runPublishWithExecutor(ctx, []string{"--source", "/source", "--source-format", "json", "--name", "entry", "--json"}, commandShortWriter{}, &diagnostic,
		func(_ context.Context, request contract.ID, _ string, _ configuration.Format, _ compositionfull.PublicationOptions) compositionfull.ConfigurationPublicationResult {
			calls++
			return compositionfull.ConfigurationPublicationResult{PublicPublicationResult: core.PublicPublicationResult{RequestID: request, Result: core.Result{Outcome: core.EvidenceUnavailable, Reason: core.ReadUnavailable}}}
		})
	if code != 2 || calls != 1 || !strings.Contains(diagnostic.String(), "output failed") {
		t.Fatal("short output was accepted or execution repeated", code, calls, diagnostic.String())
	}
}

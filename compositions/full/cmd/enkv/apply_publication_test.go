package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func applyPublicationCLIResult(applyRequest, publicationRequest contract.ID, unknown bool) core.PublicApplyPublicationResult {
	apply := core.PublicApplyResult{RequestID: applyRequest, OperationID: contract.ID{2}, RequestIdentity: contract.ID{3}, DomainID: contract.ID{4}, Result: core.Result{Outcome: core.Unchanged, Evidence: core.AuthenticatedClosure, ObservedRevision: contract.ID{5}}}
	action := contract.PublicationOutcome{Disposition: contract.PublicationNoOp}
	summary := uint8(contract.PublicationSummaryNoChange)
	if unknown {
		action = contract.PublicationOutcome{Action: contract.PublicationWriteValue, ProjectionCommitment: contract.ID{11}, AttemptID: contract.ID{12}, Disposition: contract.PublicationOutcomeUnknown,
			Evidence: contract.PublicationEvidence{Schema: 3, Entry: contract.PublicationMayHaveEnteredEntry, Class: contract.PublicationUnproved, ResponseContractDigest: contract.ID{13}}}
		summary = contract.PublicationSummaryUnknown
	}
	name, destination := "entry", "destination"
	coordinate, _ := contract.PublicationCoordinateID(contract.ID{4}, "service", "account/entry")
	description := core.PublicationTargetDescription{CoordinateID: coordinate, Origin: core.PublicationTargetCurrent, EntryName: &name, DestinationID: &destination, ServiceContractID: "service", CanonicalTarget: "account/entry"}
	publication := core.PublicPublicationResult{Descriptions: []core.PublicationTargetDescription{description}, RequestID: publicationRequest, DomainID: contract.ID{4}, OperationID: contract.ID{6}, RequestIdentity: contract.ID{7}, Result: core.Result{Outcome: core.ObservedCurrent, Evidence: core.AuthenticatedClosure}, Summary: summary,
		Output: &contract.PublicationOutcomeVector{Schema: 2, DomainID: contract.ID{4}, OperationID: contract.ID{6}, SnapshotID: contract.ID{8}, SelectionDigest: contract.ID{9}, Entries: []contract.PublicationTargetOutcome{{CoordinateID: coordinate, Actions: []contract.PublicationOutcome{action}}}}}
	return core.PublicApplyPublicationResult{Apply: apply, Publication: core.ApplyPublicationStage{Stage: "evaluated", Result: &publication}}
}

// full_only: false
func TestApplyPublicationCLIAdmitsRetainedExecutorChoices(t *testing.T) {
	for _, continuation := range []bool{false, true} {
		name := "fresh"
		if continuation {
			name = "accepted-operation"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			deadline, _ := ctx.Deadline()
			coordinateText, blockerText := strings.Repeat("01", 32), strings.Repeat("02", 32)
			coordinate, _ := parseID(coordinateText)
			blocker, _ := parseID(blockerText)
			args := []string{"--source", "/source", "--source-format", "json", "--publish", "--delete-coordinate", coordinateText + "=private-output", "--republish-after-unknown", blockerText, "--json", "--log-level", "off"}
			var operation contract.ID
			if continuation {
				text := strings.Repeat("03", 32)
				operation, _ = parseID(text)
				args = append(args, "--operation", text)
			}
			plainCalls, combinedCalls := 0, 0
			var output, diagnostic bytes.Buffer
			code := runApplyWithExecutors(ctx, args, &output, &diagnostic,
				func(context.Context, contract.ID, string, configuration.Format, contract.ID, compositionfull.ApplyOptions) compositionfull.ConfigurationApplyResult {
					plainCalls++
					return generatedCLIRefusal()
				},
				func(callctx context.Context, applyRequest, publicationRequest contract.ID, path string, format configuration.Format, gotOperation contract.ID, publication compositionfull.ApplyPublicationOptions, _ compositionfull.ApplyOptions) compositionfull.ConfigurationApplyPublicationResult {
					combinedCalls++
					gotDeadline, finite := callctx.Deadline()
					want := compositionfull.ApplyPublicationOptions{RepublishAfterUnknown: []contract.ID{blocker}, DeletePlugins: map[contract.ID]string{coordinate: "private-output"}}
					if !finite || gotDeadline != deadline || path != "/source" || format != configuration.JSON || gotOperation != operation || !reflect.DeepEqual(publication, want) {
						t.Fatal("retained-executor request changed combined admission")
					}
					return compositionfull.ConfigurationApplyPublicationResult{PublicApplyPublicationResult: applyPublicationCLIResult(applyRequest, publicationRequest, false)}
				})
			if code != 0 || plainCalls != 0 || combinedCalls != 1 || !json.Valid(output.Bytes()) || diagnostic.Len() != 0 {
				t.Fatal("valid retained-executor selection did not reach one combined invocation", code, plainCalls, combinedCalls, diagnostic.String())
			}
		})
	}
}

// full_only: false
func TestApplyPublicationCLIUsesOneCombinedInvocationAndOriginalDeadline(t *testing.T) {
	for _, continuation := range []bool{false, true} {
		name := "fresh"
		if continuation {
			name = "accepted-operation"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			deadline, _ := ctx.Deadline()
			blockerText := strings.Repeat("02", 32)
			blocker, _ := parseID(blockerText)
			operationText := strings.Repeat("03", 32)
			var wantOperation contract.ID
			args := []string{"--source", "/source", "--source-format", "json", "--publish", "--republish-after-unknown", blockerText, "--json", "--log-level", "off"}
			if continuation {
				wantOperation, _ = parseID(operationText)
				args = append(args, "--operation", operationText)
			}
			plainCalls, combinedCalls := 0, 0
			var output, diagnostic bytes.Buffer
			code := runApplyWithExecutors(ctx, args, &output, &diagnostic,
				func(context.Context, contract.ID, string, configuration.Format, contract.ID, compositionfull.ApplyOptions) compositionfull.ConfigurationApplyResult {
					plainCalls++
					return generatedCLIRefusal()
				},
				func(callctx context.Context, applyRequest, publicationRequest contract.ID, path string, format configuration.Format, operation contract.ID, publication compositionfull.ApplyPublicationOptions, _ compositionfull.ApplyOptions) compositionfull.ConfigurationApplyPublicationResult {
					combinedCalls++
					got, finite := callctx.Deadline()
					if !finite || got != deadline || applyRequest.IsZero() || publicationRequest.IsZero() || publicationRequest == applyRequest || path != "/source" || format != configuration.JSON || operation != wantOperation || !reflect.DeepEqual(publication.RepublishAfterUnknown, []contract.ID{blocker}) || len(publication.DeletePlugins) != 0 {
						t.Fatal("CLI changed a request selector, stage identity or original deadline")
					}
					return compositionfull.ConfigurationApplyPublicationResult{PublicApplyPublicationResult: applyPublicationCLIResult(applyRequest, publicationRequest, false)}
				})
			var envelope struct {
				Schema      string
				Apply       json.RawMessage
				Publication struct {
					Stage  string
					Reason json.RawMessage
					Result json.RawMessage
				}
			}
			if code != 0 || plainCalls != 0 || combinedCalls != 1 || json.Unmarshal(output.Bytes(), &envelope) != nil || envelope.Schema != "ApplyPublicationResult/v1" || envelope.Publication.Stage != "evaluated" || string(envelope.Publication.Reason) != "null" || len(envelope.Apply) == 0 || len(envelope.Publication.Result) == 0 || output.Len() < 2 || output.Bytes()[output.Len()-1] != '\n' || output.Bytes()[output.Len()-2] == '\n' {
				t.Fatal("CLI lost a complete stage or invoked apply twice", code, plainCalls, combinedCalls, output.String())
			}
		})
	}
}

// full_only: false
func TestApplyPublicationCLIRejectsAmbiguousSelectorsBeforeExecution(t *testing.T) {
	id := strings.Repeat("01", 32)
	for _, selectors := range [][]string{
		{"--republish-after-unknown", id},
		{"--publish", "--republish-after-unknown", id, "--republish-after-unknown", id},
		{"--publish", "--republish-after-unknown", strings.Repeat("00", 32)},
		{"--publish", "--republish-after-unknown", strings.Repeat("AB", 32)},
		{"--publish", "--republish-after-unknown", "provider/address"},
		{"--publish", "--republish-after-unknown"},
		{"--publish", "--name", "entry"},
		{"--publish", "--delete-coordinate", id},
		{"--delete-coordinate", id + "=private-output"},
		{"--publish", "--delete-coordinate", id + "="},
		{"--publish", "--delete-coordinate", id + "=../output"},
		{"--publish", "--delete-coordinate", id + "=output=other"},
		{"--publish", "--delete-coordinate", strings.Repeat("00", 32) + "=private-output"},
		{"--publish", "--delete-coordinate", strings.Repeat("AB", 32) + "=private-output"},
		{"--publish", "--delete-coordinate", id + "=private-output", "--delete-coordinate", id + "=private-output"},
		{"--publish", "--delete-coordinate", id + "=private-output", "--delete-coordinate", id + "=other-output"},
		{"--publish", "entry"},
		{"--publish", "--operation", strings.Repeat("00", 32)},
	} {
		t.Run(strings.Join(selectors, " "), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			calls := 0
			args := append([]string{"--source", "/source", "--source-format", "json", "--json", "--log-level", "off"}, selectors...)
			var output, diagnostic bytes.Buffer
			code := runApplyWithExecutors(ctx, args, &output, &diagnostic,
				func(context.Context, contract.ID, string, configuration.Format, contract.ID, compositionfull.ApplyOptions) compositionfull.ConfigurationApplyResult {
					calls++
					return generatedCLIRefusal()
				},
				func(context.Context, contract.ID, contract.ID, string, configuration.Format, contract.ID, compositionfull.ApplyPublicationOptions, compositionfull.ApplyOptions) compositionfull.ConfigurationApplyPublicationResult {
					calls++
					return compositionfull.ConfigurationApplyPublicationResult{}
				})
			if code != 2 || calls != 0 || !bytes.Contains(output.Bytes(), []byte("refused")) {
				t.Fatal("ambiguous combined request reached execution", code, calls, output.String())
			}
		})
	}
}

type applyPublicationFinalLFShortWriter struct{ body bytes.Buffer }

func (w *applyPublicationFinalLFShortWriter) Write(body []byte) (int, error) {
	if len(body) != 0 && body[len(body)-1] == '\n' {
		n, err := w.body.Write(body[:len(body)-1])
		if err != nil || json.Valid(w.body.Bytes()) {
			return n, err
		}
		last, err := w.body.Write(body[len(body)-1:])
		return n + last, err
	}
	return w.body.Write(body)
}

// full_only: false
func TestApplyPublicationCLIOutputFailureDoesNotRepeatCompletedInvocation(t *testing.T) {
	for _, cut := range []string{"first-chunk", "final-lf", "complete-unknown-output"} {
		t.Run(cut, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			calls := 0
			var complete bytes.Buffer
			var final applyPublicationFinalLFShortWriter
			var output io.Writer = commandShortWriter{}
			switch cut {
			case "final-lf":
				output = &final
			case "complete-unknown-output":
				output = &complete
			}
			var diagnostic bytes.Buffer
			var retained core.PublicApplyPublicationResult
			code := runApplyWithExecutors(ctx, []string{"--source", "/source", "--source-format", "json", "--publish", "--json", "--log-level", "off"}, output, &diagnostic, nil,
				func(_ context.Context, applyRequest, publicationRequest contract.ID, _ string, _ configuration.Format, _ contract.ID, _ compositionfull.ApplyPublicationOptions, _ compositionfull.ApplyOptions) compositionfull.ConfigurationApplyPublicationResult {
					calls++
					retained = applyPublicationCLIResult(applyRequest, publicationRequest, true)
					return compositionfull.ConfigurationApplyPublicationResult{PublicApplyPublicationResult: retained}
				})
			wantCode := 2
			if cut == "complete-unknown-output" {
				wantCode = 3
			}
			if code != wantCode || calls != 1 || retained.Publication.Result == nil || retained.Publication.Result.Summary != contract.PublicationSummaryUnknown || retained.Publication.Result.Output.Entries[0].Actions[0].Disposition != contract.PublicationOutcomeUnknown || retained.Apply.Result.Outcome != core.Unchanged {
				t.Fatal("output delivery rewrote uncertainty, changed apply or repeated execution", code, calls)
			}
			if cut != "complete-unknown-output" && !strings.Contains(diagnostic.String(), "output failed") {
				t.Fatal("short output did not report its delivery failure")
			}
			if cut == "final-lf" {
				var result map[string]json.RawMessage
				if err := json.Unmarshal(final.body.Bytes(), &result); err != nil || string(result["schema"]) != `"ApplyPublicationResult/v1"` {
					t.Fatal("final-LF cut did not follow both complete stage bodies", err)
				}
			}
		})
	}
}

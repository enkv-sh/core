package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/installedarchive"
)

func materializationCLIResult(t *testing.T) compositionfull.ConfigurationMaterializationResult {
	t.Helper()
	_, body := installedarchive.LoadReader(t, "aws")
	var image struct{ Descriptor []byte }
	if json.Unmarshal(body, &image) != nil {
		t.Fatal("fixture basis unavailable")
	}
	descriptor, err := contract.DecodeGenesisDescriptorCore(image.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := descriptor.BindingTable()
	if err != nil {
		t.Fatal(err)
	}
	identity := contract.ID{1}
	p := &contract.MaterializationPayload{Schema: contract.MaterializationPayloadSchema, RequestIdentity: identity, DomainID: descriptor.DomainID, HEADRevision: contract.ID{2}, SnapshotID: contract.ID{3}, Recipient: bindings[0], Target: contract.MaterializationTarget{Path: "/private/application.env", SurfaceID: contract.ID{4}, Format: contract.MaterializationDotenvFormat, NativeProfile: contract.MaterializationNativeFileProfile}, Entries: []contract.MaterializationEntryIdentity{{Name: "VALUE", EntryIncarnationID: contract.ID{5}, ValueStateID: contract.ID{6}, ValueSource: 1, ConfidentialityClass: 1}}, Facts: contract.MaterializationFacts{Replacement: contract.MaterializationReplaced, CandidateVerification: contract.MaterializationVerified, InstalledVerification: contract.MaterializationVerified, NativeCompletion: contract.MaterializationComplete, Disclosure: contract.MaterializationDisclosureOccurred, Cleanup: contract.MaterializationCandidateRenamed}}
	return compositionfull.ConfigurationMaterializationResult{MaterializationResult: core.MaterializationResult{Operation: contract.MaterializationOperation, OperationID: contract.Hash(append([]byte("ENKV/materialization-operation/v1\x00"), identity[:]...)), RequestID: contract.ID{9}, RequestIdentity: identity, DomainID: descriptor.DomainID, StateResult: contract.MaterializationSuccess, Payload: p, Result: core.Result{Outcome: core.ObservedCurrent, Evidence: core.AuthenticatedClosure, ObservedRevision: p.HEADRevision, ObservedSnapshotID: p.SnapshotID}}}
}

// full_only: false
func TestMaterializeCapturesExactRequestOnce(t *testing.T) {
	for _, format := range []string{"json", "yaml"} {
		for _, explicit := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", format, explicit), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				deadline, _ := ctx.Deadline()
				args := []string{"--source=relative-source", "--source-format=" + format, "--name=ZETA", "--name", "ALPHA", "--out=application.env", "--json", "--log-level=off"}
				wantRecipient := contract.ID{}
				if explicit {
					wantRecipient = contract.ID{7}
					args = append(args, "--recipient-id="+idText(wantRecipient))
				}
				calls := 0
				var out, diagnostic bytes.Buffer
				code := runMaterializeWithExecutor(ctx, args, &out, &diagnostic, func(callCtx context.Context, r contract.MaterializationRequest, path string, f configuration.Format, destination string, _ compositionfull.RecipientSelector) (compositionfull.ConfigurationMaterializationResult, error) {
					calls++
					wantPath, _ := filepath.Abs("relative-source")
					wantOut, _ := filepath.Abs("application.env")
					actualDeadline, _ := callCtx.Deadline()
					if r.RequestNonce.IsZero() || r.RecipientID != wantRecipient || !reflect.DeepEqual(r.Names, []string{"ALPHA", "ZETA"}) || path != wantPath || destination != wantOut || configurationSourceName(f) != format || !actualDeadline.Equal(deadline) {
						t.Fatal("CLI changed captured request")
					}
					return materializationCLIResult(t), nil
				})
				if code != 0 || calls != 1 || !json.Valid(out.Bytes()) {
					t.Fatal("valid CLI did not execute once", code, calls, diagnostic.String())
				}
			})
		}
	}
}

func configurationSourceName(format configuration.Format) string {
	if format == configuration.JSON {
		return "json"
	}
	return "yaml"
}

// full_only: false
func TestMaterializeRefusesInvalidArgumentsBeforeExecution(t *testing.T) {
	base := []string{"--source=source.json", "--source-format=json", "--name=VALUE", "--out=application.env", "--json"}
	type argumentCase struct {
		args       []string
		structured bool
	}
	cases := []argumentCase{
		{nil, false},
		{[]string{"--source=source.json", "--source-format=json", "--out=application.env", "--json"}, true},
		{[]string{"--source=source.json", "--source-format=json", "--name=VALUE", "--json"}, true},
		{append(append([]string{}, base...), "extra"), true},
		{append(append([]string{}, base...), "--"), true},
		{append(append([]string{}, base...), "--unknown=private-argument-sentinel"), true},
		{[]string{"--source=source.json", "--source-format=json", "--name=VALUE", "--out=-", "--json"}, true},
	}
	for _, row := range []struct {
		fields     [4]string
		structured bool
	}{
		{[4]string{"", "json", "VALUE", "application.env"}, true},
		{[4]string{"source.json", "toml", "VALUE", "application.env"}, true},
		{[4]string{"source.json", "json", "VALUE", ""}, true},
		{[4]string{"source.json", "json", "VALUE", "source.json"}, true},
		{[4]string{"source.json", "json", strings.Repeat("x", contract.CryptoMaxName+1), "application.env"}, false},
		{[4]string{"source.json", "json", "VALUE", "invalid\x00.env"}, true},
	} {
		fields := row.fields
		cases = append(cases, argumentCase{[]string{"--source=" + fields[0], "--source-format=" + fields[1], "--name=" + fields[2], "--out=" + fields[3], "--json"}, row.structured})
	}
	overCount := append([]string{}, base...)
	for at := 0; at < contract.CryptoMaxValueEntries; at++ {
		overCount = append(overCount, fmt.Sprintf("--name=VALUE%d", at))
	}
	cases = append(cases, argumentCase{overCount, true})
	for _, name := range []string{"source", "source-format", "recipient", "out", "json", "log-level", "telemetry-config", "name"} {
		value := map[string]string{"source": "source.json", "source-format": "json", "recipient": idText(contract.ID{7}), "out": "application.env", "json": "true", "log-level": "off", "telemetry-config": "private-argument-sentinel", "name": "VALUE"}[name]
		args := append([]string{}, base...)
		if name == "recipient" || name == "log-level" || name == "telemetry-config" {
			args = append(args, "--"+name+"="+value)
		}
		cases = append(cases, argumentCase{append(args, "--"+name+"="+value), true})
	}
	for _, id := range []string{"", strings.Repeat("00", 32), strings.Repeat("AA", 32), strings.Repeat("1", 63)} {
		cases = append(cases, argumentCase{append(append([]string{}, base...), "--recipient-id="+id), true})
	}
	for at, row := range cases {
		t.Run(fmt.Sprint(at), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			calls := 0
			var out, diagnostic bytes.Buffer
			code := runMaterializeWithExecutor(ctx, row.args, &out, &diagnostic, func(context.Context, contract.MaterializationRequest, string, configuration.Format, string, compositionfull.RecipientSelector) (compositionfull.ConfigurationMaterializationResult, error) {
				calls++
				return compositionfull.ConfigurationMaterializationResult{}, nil
			})
			if code != 2 || calls != 0 || bytes.Contains(out.Bytes(), []byte("private-argument-sentinel")) || bytes.Contains(diagnostic.Bytes(), []byte("private-argument-sentinel")) {
				t.Fatal("invalid arguments reached executor", code, calls)
			}
			if json.Valid(out.Bytes()) != row.structured {
				t.Fatal("refusal lost closed result")
			}
		})
	}
}

type materializationCLIWriter struct{ short bool }

func (w materializationCLIWriter) Write(p []byte) (int, error) {
	if w.short {
		return len(p) - 1, nil
	}
	return 0, errors.New("private-write-error-sentinel")
}

// full_only: false
func TestMaterializePreservesOperationOnResultDeliveryFailure(t *testing.T) {
	for _, human := range []bool{false, true} {
		for _, failure := range []string{"short", "error", "source-close"} {
			t.Run(fmt.Sprintf("%t/%s", human, failure), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				args := []string{"--source=source.json", "--source-format=json", "--name=VALUE", "--out=application.env", "--log-level=off"}
				if !human {
					args = append(args, "--json")
				}
				operation := materializationCLIResult(t)
				calls := 0
				var output, diagnostic bytes.Buffer
				var writer io.Writer = &output
				if failure != "source-close" {
					writer = materializationCLIWriter{short: failure == "short"}
				}
				code := runMaterializeWithExecutor(ctx, args, writer, &diagnostic, func(context.Context, contract.MaterializationRequest, string, configuration.Format, string, compositionfull.RecipientSelector) (compositionfull.ConfigurationMaterializationResult, error) {
					calls++
					if failure == "source-close" {
						return operation, compositionfull.ErrMaterializationSourceClose
					}
					return operation, nil
				})
				if code != 2 || calls != 1 || operation.StateResult != contract.MaterializationSuccess || operation.Payload.Facts.Replacement != contract.MaterializationReplaced || bytes.Contains(diagnostic.Bytes(), []byte("private-write-error-sentinel")) {
					t.Fatal("delivery failure replayed or changed operation", code, calls)
				}
				if failure == "source-close" {
					if human {
						if !strings.HasPrefix(output.String(), "Materialize file: \"/private/application.env\"\n") || !strings.Contains(output.String(), "materialize: success\n") || !strings.Contains(output.String(), "Replacement: replaced; installed verification=verified; completion=complete.\n") {
							t.Fatal("source close erased completed human delivery facts", output.String())
						}
					} else {
						var got struct {
							State   string `json:"state_result"`
							Payload struct{ Facts struct{ Replacement string } }
						}
						if json.Unmarshal(output.Bytes(), &got) != nil || got.State != "success" || got.Payload.Facts.Replacement != "replaced" {
							t.Fatal("source close erased completed JSON delivery facts")
						}
					}
				}
			})
		}
	}
}

// full_only: false
func TestMaterializeDispatchAndHelp(t *testing.T) {
	var out, diagnostic bytes.Buffer
	if code := run([]string{"materialize", "--help"}, &out, &diagnostic); code != 0 || !strings.HasPrefix(out.String(), "materialize [--source") {
		t.Fatal("materialize help not dispatched", code)
	}
	if code := run([]string{"materialize", "--json"}, &bytes.Buffer{}, &diagnostic); code != 2 {
		t.Fatal("materialize refusal not dispatched", code)
	}
}

// full_only: false
func TestMaterializeReportsResultDeliveryFailureAfterInvocationCancellation(t *testing.T) {
	for _, human := range []bool{false, true} {
		for _, expiry := range []string{"canceled", "deadline"} {
			t.Run(fmt.Sprintf("%t/%s", human, expiry), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
					defer cancel()
					args := []string{"--source=source.json", "--source-format=json", "--name=VALUE", "--out=application.env", "--log-level=off"}
					if !human {
						args = append(args, "--json")
					}
					calls := 0
					operation := materializationCLIResult(t)
					var out, diagnostic bytes.Buffer
					code := runMaterializeWithExecutor(ctx, args, &out, &diagnostic, func(context.Context, contract.MaterializationRequest, string, configuration.Format, string, compositionfull.RecipientSelector) (compositionfull.ConfigurationMaterializationResult, error) {
						calls++
						reason := contract.MaterializationCanceled
						if expiry == "deadline" {
							time.Sleep(time.Minute)
							// The sleep and deadline timer become runnable at the same fake
							// instant. Observe cancellation before testing canceled delivery.
							<-ctx.Done()
							if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
								t.Fatal("deadline did not cancel the invocation")
							}
							reason = contract.MaterializationDeadlineExceeded
						} else {
							cancel()
						}
						operation.StateResult = contract.MaterializationUnavailable
						operation.Result.Outcome, operation.Result.Reason = core.EvidenceUnavailable, core.CustodyUnavailable
						operation.Failure = &contract.MaterializationFailure{Stage: contract.MaterializationInstalledClose, Reason: reason}
						operation.Payload.Facts.Failure, operation.Payload.Facts.NativeCompletion = operation.Failure, contract.MaterializationIncomplete
						return operation, nil
					})
					if code != 2 || calls != 1 || out.Len() != 0 || !bytes.Contains(diagnostic.Bytes(), []byte("materialization result delivery failed")) || operation.Validate() != nil || operation.Payload.Facts.Replacement != contract.MaterializationReplaced || operation.Payload.Facts.InstalledVerification != contract.MaterializationVerified || operation.Payload.Facts.Disclosure != contract.MaterializationDisclosureOccurred {
						t.Fatal("canceled result delivery replayed or erased settled native facts", code, calls, out.Len())
					}
				})
			})
		}
	}
}

package core

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"enkv.sh/telemetry"
)

// full_only: false
func TestStockIndependentVerificationTelemetryPreservesClosedResults(t *testing.T) {
	const account = "0123456789abcdef0123456789abcdef"
	const token = "PRIVATE_VERIFICATION_BEARER_SENTINEL"
	const target = "repos/private-owner/private-repository/actions/secrets/ENKV_PRIVATE_SECRET"
	const transportFailure = "PRIVATE_VERIFICATION_TRANSPORT_FAILURE"
	t.Setenv("GITHUB_TOKEN", token)
	for _, enabled := range []bool{false, true} {
		for _, owner := range []string{"cloudflare", "github"} {
			for _, condition := range []string{"success", "refusal", "transport-failure"} {
				name := "disabled/"
				if enabled {
					name = "enabled/"
				}
				t.Run(name+owner+"/"+condition, func(t *testing.T) {
					recorder := telemetry.NewRecorder()
					metrics := make(chan telemetry.MetricPoint, 16)
					ctx := context.Background()
					if enabled {
						ctx = telemetry.WithCapability(ctx, telemetry.NewCapability(metrics, recorder))
					}
					requests := 0
					client := &http.Client{Transport: stockVerificationTransport(func(request *http.Request) (*http.Response, error) {
						requests++
						// A normal local child call observes the actual request context.
						// Its diagnostic parent proves CallContext reached this boundary.
						child := telemetry.Start(request.Context(), telemetry.ProviderWorker, telemetry.OpWorkerInvocation)
						if condition == "transport-failure" {
							child.Finish(telemetry.ResultFailure)
							return nil, errors.New(transportFailure)
						}
						child.Finish(telemetry.ResultSuccess)
						body := `{"success":true,"errors":[],"result":{"id":"abcdef0123456789abcdef0123456789","status":"active"}}`
						if owner == "github" {
							body = `{"name":"ENKV_PRIVATE_SECRET"}`
						}
						return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					operation := telemetry.OpSetupVerifyCloudflare
					var err error
					if owner == "cloudflare" {
						selectedAccount := account
						if condition == "refusal" {
							selectedAccount = "invalid"
						}
						_, err = stockVerifyCloudflare(ctx, client, selectedAccount, []byte(token))
					} else {
						operation = telemetry.OpSetupGitHubMetadata
						selectedTarget := target
						if condition == "refusal" {
							selectedTarget = "invalid"
						}
						err = stockGitHubMetadata(ctx, client, selectedTarget, true)
					}
					wantRequests := 1
					if condition == "refusal" {
						wantRequests = 0
					}
					if (err == nil) != (condition == "success") || requests != wantRequests {
						t.Fatal("telemetry changed the independent read result or dispatch count")
					}
					entries := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 8))
					var points []telemetry.MetricPoint
					for len(metrics) != 0 {
						points = append(points, <-metrics)
					}
					if !enabled {
						if len(entries) != 0 || len(points) != 0 {
							t.Fatal("disabled independent read emitted telemetry")
						}
						return
					}
					result, reason, severity := telemetry.ResultSuccess, telemetry.DiagnosticReasonNone, telemetry.SeverityInfo
					if condition == "refusal" {
						result, reason, severity = telemetry.ResultAdmissionRefused, telemetry.DiagnosticReasonAdmissionInvalid, telemetry.SeverityWarn
					} else if condition == "transport-failure" {
						result, reason, severity = telemetry.ResultFailure, telemetry.DiagnosticReasonReadUnavailable, telemetry.SeverityError
					}
					var operationRecords []telemetry.DiagnosticRecord
					var nestedParent uint64
					for _, entry := range entries {
						if entry.Validate() != nil {
							t.Fatal("independent read emitted an invalid diagnostic")
						}
						if entry.Operation == operation {
							operationRecords = append(operationRecords, entry)
						} else if entry.Operation == telemetry.OpWorkerInvocation {
							nestedParent = entry.ParentCall
						}
					}
					if len(operationRecords) != 2 || operationRecords[0].Provider != telemetry.ProviderWorker || operationRecords[0].Event != telemetry.DiagnosticStart || operationRecords[1].Event != telemetry.DiagnosticReturn || operationRecords[1].Call != operationRecords[0].Call || operationRecords[1].Result != result || operationRecords[1].Reason != reason || operationRecords[1].SeverityNumber != severity || operationRecords[1].ElapsedNanos <= 0 {
						t.Fatal("independent read lost its exact normal-return result or duration")
					}
					if wantRequests == 1 && nestedParent != operationRecords[0].Call {
						t.Fatal("independent request did not retain its operation parent")
					}
					calls, results, durations := 0, 0, 0
					for _, point := range points {
						if point.Operation != operation {
							continue
						}
						if point.Provider != telemetry.ProviderWorker {
							t.Fatal("independent read used another telemetry owner")
						}
						switch point.Name {
						case telemetry.OperationCalls:
							calls += int(point.IntValue)
						case telemetry.OperationResults:
							if point.Result != result {
								t.Fatal("independent read metric result differs")
							}
							results += int(point.IntValue)
						case telemetry.OperationDuration:
							if point.FloatValue <= 0 {
								t.Fatal("independent read duration was omitted")
							}
							durations++
						default:
							t.Fatal("independent read emitted an unrelated measurement")
						}
					}
					if calls != 1 || results != 1 || durations != 1 {
						t.Fatal("independent read operation signals are incomplete")
					}
					encoded, encodeErr := json.Marshal(entries)
					if encodeErr != nil {
						t.Fatal("controlled telemetry records could not be inspected")
					}
					for _, forbidden := range []string{account, token, target, transportFailure, "ENKV_PRIVATE_SECRET", "abcdef0123456789abcdef0123456789"} {
						if strings.Contains(string(encoded), forbidden) {
							t.Fatal("independent read telemetry retained private input or raw provider data")
						}
					}
				})
			}
		}
	}
}

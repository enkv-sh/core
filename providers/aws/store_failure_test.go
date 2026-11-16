package awsprovider

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
	"github.com/aws/aws-sdk-go-v2/aws"
)

// full_only: false
func TestStoreWriteReasonsKeepReplyAndTransportFactsSeparate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		code   string
		want   contract.WriteStatus
		reason contract.Reason
	}{
		{"invalid-request", 400, "InvalidRequest", contract.WriteUnknown, contract.ReasonConstruction},
		{"other-conflict", 409, "OtherConflict", contract.WriteUnknown, contract.ReasonMalformed},
		{"other-precondition", 412, "OtherPolicy", contract.WriteUnknown, contract.ReasonMalformed},
		{"internal-error", 500, "InternalError", contract.WriteUnknown, contract.ReasonTransport},
		{"slow-down", 503, "SlowDown", contract.WriteUnknown, contract.ReasonTransport},
		{"other-unavailable", 503, "OtherFailure", contract.WriteUnknown, contract.ReasonMalformed},
		{"slow-down-wrong-status", 400, "SlowDown", contract.WriteUnknown, contract.ReasonMalformed},
		{"access", 403, "AccessDenied", contract.WriteUnknown, contract.ReasonAccess},
		{"conditional-conflict", 409, "ConditionalRequestConflict", contract.WriteConflict, contract.ReasonCondition},
		{"precondition", 412, "PreconditionFailed", contract.WritePrecondition, contract.ReasonCondition},
		{"malformed-success", 200, "", contract.WriteUnknown, contract.ReasonMalformed},
		{"oversized-success", 200, "", contract.WriteUnknown, contract.ReasonMalformed},
		{"lost-reply", 0, "", contract.WriteUnknown, contract.ReasonTransport},
	} {
		for _, operation := range []string{"create", "compare-and-swap", "conditional-delete"} {
			t.Run(tc.name+"/"+operation, func(t *testing.T) {
				calls := 0
				token := contract.Token{Family: contract.AWS, Value: `"unchanged-etag"`}
				s, err := newStore(testStoreConfig(), roundTripFunc(func(r *http.Request) (*http.Response, error) {
					calls++
					method := http.MethodPut
					if operation == "conditional-delete" {
						method = http.MethodDelete
					}
					match, absent := token.Value, ""
					if operation == "create" {
						match, absent = "", "*"
					}
					if r.Method != method || r.Header.Get("If-Match") != match || r.Header.Get("If-None-Match") != absent || r.Header.Get("X-Amz-Expected-Bucket-Owner") != "123456789012" {
						t.Fatalf("conditional request changed: %s %s %v", r.Method, r.URL, r.Header)
					}
					if operation != "conditional-delete" {
						body, readErr := io.ReadAll(r.Body)
						if readErr != nil || string(body) != "candidate" {
							t.Fatal("candidate bytes changed", readErr)
						}
					}
					switch tc.name {
					case "lost-reply":
						return nil, errors.New("controlled reply loss")
					case "malformed-success":
						return response(tc.status, "unexpected", nil), nil
					case "oversized-success":
						return response(tc.status, strings.Repeat("x", maximumPublicResponseBytes+1), nil), nil
					default:
						return response(tc.status, "<Error><Code>"+tc.code+"</Code></Error>", nil), nil
					}
				}))
				if err != nil {
					t.Fatal(err)
				}
				var got contract.WriteResult
				switch operation {
				case "conditional-delete":
					got = s.DeleteIfToken(context.Background(), testResultKey(), token)
				case "create":
					got = s.Create(context.Background(), testResultKey(), []byte("candidate"))
				default:
					got = s.CompareAndSwap(context.Background(), s.Descriptor().HeadKey, token, []byte("candidate"))
				}
				if got.Status != tc.want || got.Reason != tc.reason || got.NotSent || calls != 1 {
					t.Fatalf("result=%+v want status=%v reason=%v physical sends=%d", got, tc.want, tc.reason, calls)
				}
			})
		}
	}
}

// full_only: false
func TestStoreCredentialRefusalRetainsPositiveNoSend(t *testing.T) {
	for _, operation := range []string{"create", "compare-and-swap", "conditional-delete"} {
		t.Run(operation, func(t *testing.T) {
			calls, credentials := 0, 0
			config := testStoreConfig()
			config.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
				credentials++
				return aws.Credentials{}, errors.New("controlled credential refusal")
			})
			s, err := newStore(config, roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return nil, errors.New("unexpected provider entry")
			}))
			if err != nil {
				t.Fatal(err)
			}
			var got contract.WriteResult
			switch operation {
			case "create":
				got = s.Create(context.Background(), testResultKey(), []byte("candidate"))
			case "compare-and-swap":
				got = s.CompareAndSwap(context.Background(), s.Descriptor().HeadKey, contract.Token{Family: contract.AWS, Value: `"current"`}, []byte("candidate"))
			case "conditional-delete":
				got = s.DeleteIfToken(context.Background(), testResultKey(), contract.Token{Family: contract.AWS, Value: `"current"`})
			}
			if got.Status != contract.WriteRefused || got.Reason != contract.ReasonAccess || !got.NotSent || calls != 0 || credentials != 1 {
				t.Fatalf("result=%+v sends=%d credential resolutions=%d", got, calls, credentials)
			}
		})
	}
}

// full_only: false
func TestStoreCreatePreconditionIsPendingWithoutChangingHEADOrCAS(t *testing.T) {
	for _, operation := range []string{"immutable", "head", "cas"} {
		t.Run(operation, func(t *testing.T) {
			s, err := newStore(testStoreConfig(), roundTripFunc(func(*http.Request) (*http.Response, error) {
				return response(412, "<Error><Code>PreconditionFailed</Code></Error>", nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			recorder := telemetry.NewRecorder()
			ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
			var got contract.WriteResult
			switch operation {
			case "immutable":
				got = s.Create(ctx, testResultKey(), []byte("candidate"))
			case "head":
				request, err := contract.NewHeadCreateRequest(s.Descriptor(), []byte("candidate"))
				if err != nil {
					t.Fatal(err)
				}
				got = s.CreateHead(ctx, request)
			case "cas":
				got = s.CompareAndSwap(ctx, s.Descriptor().HeadKey, contract.Token{Family: contract.AWS, Value: `"current"`}, []byte("candidate"))
			}
			if got.Status != contract.WritePrecondition || got.Reason != contract.ReasonCondition {
				t.Fatal("provider changed known rejection", got)
			}
			returns := 0
			for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32)) {
				if record.Event != telemetry.DiagnosticReturn || record.Operation != telemetry.OpStoreCreate && record.Operation != telemetry.OpStoreCompareAndSwap {
					continue
				}
				returns++
				want, severity := "write_precondition", "WARN"
				if operation == "immutable" {
					want, severity = "verification_pending", "INFO"
				}
				if string(record.Result) != want || record.SeverityText != severity || record.Validate() != nil {
					t.Fatal("precondition meaning changed", record)
				}
			}
			if returns != 1 || recorder.Status().Rejected != 0 {
				t.Fatal("provider return fact missing", returns)
			}
		})
	}
}

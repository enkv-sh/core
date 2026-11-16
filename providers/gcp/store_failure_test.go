package gcp

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// full_only: false
func TestStoreReadQualifiesMissingObjectAndBucketResponses(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		want       contract.ReadStatus
		reason     contract.Reason
	}{
		{"json-object", `{"error":{"code":404,"errors":[{"reason":"notFound"}]}}`, 404, contract.ReadMissing, contract.ReasonNone},
		{"json-bucket", `{"error":{"code":404,"message":"The specified bucket does not exist.","errors":[{"reason":"notFound"}]}}`, 404, contract.ReadMissing, contract.ReasonNone},
		{"xml-object", `<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>`, 404, contract.ReadMissing, contract.ReasonNone},
		{"xml-bucket", `<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist.</Message></Error>`, 404, contract.ReadMissing, contract.ReasonNone},
		{"empty", "", 404, contract.ReadInvalid, contract.ReasonMalformed},
		{"html", `<html>resource not found</html>`, 404, contract.ReadInvalid, contract.ReasonMalformed},
		{"json-wrong-code", `{"error":{"code":503,"errors":[{"reason":"notFound"}]}}`, 404, contract.ReadInvalid, contract.ReasonMalformed},
		{"json-wrong-reason", `{"error":{"code":404,"errors":[{"reason":"conditionNotMet"}]}}`, 404, contract.ReadInvalid, contract.ReasonMalformed},
		{"json-duplicate-errors", `{"error":{"code":404,"errors":[{"reason":"conditionNotMet"}],"errors":[{"reason":"notFound"}]}}`, 404, contract.ReadInvalid, contract.ReasonMalformed},
		{"json-duplicate-reason", `{"error":{"code":404,"errors":[{"reason":"conditionNotMet","reason":"notFound"}]}}`, 404, contract.ReadInvalid, contract.ReasonMalformed},
		{"json-case-alias", `{"error":{"code":404,"Errors":[{"reason":"notFound"}]}}`, 404, contract.ReadInvalid, contract.ReasonMalformed},
		{"xml-wrong-code", `<Error><Code>InvalidUri</Code></Error>`, 404, contract.ReadInvalid, contract.ReasonMalformed},
		{"xml-trailing", `<Error><Code>NoSuchKey</Code></Error>extra`, 404, contract.ReadInvalid, contract.ReasonMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s, credentials := newStore(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodGet || r.URL.Path != "/download/storage/v1/b/fixture-bucket/o/fixture/HEAD" || r.URL.Query().Get("alt") != "media" {
					t.Fatalf("object observation changed request: %s %s", r.Method, r.URL)
				}
				return response(tc.status, tc.body), nil
			})
			got := s.Read(context.Background(), s.Descriptor().HeadKey, 64)
			if got.Status != tc.want || got.Reason != tc.reason || len(got.Body) != 0 || got.Token != (contract.Token{}) || calls != 1 || credentials.calls != 1 {
				t.Fatalf("result=%+v sends=%d credential resolutions=%d", got, calls, credentials.calls)
			}
		})
	}
}

// full_only: false
func TestStoreCredentialRefusalRetainsPositiveNoSend(t *testing.T) {
	for _, operation := range []string{"create", "compare-and-swap", "conditional-delete"} {
		t.Run(operation, func(t *testing.T) {
			calls := 0
			s, credentials := newStore(t, func(*http.Request) (*http.Response, error) {
				calls++
				return nil, errors.New("unexpected provider entry")
			})
			credentials.err = errors.New("controlled credential refusal")
			var got contract.WriteResult
			switch operation {
			case "create":
				got = s.Create(context.Background(), childKey(s), []byte("candidate"))
			case "compare-and-swap":
				got = s.CompareAndSwap(context.Background(), s.Descriptor().HeadKey, contract.Token{Family: contract.GCP, Value: "24"}, []byte("candidate"))
			case "conditional-delete":
				got = s.DeleteIfToken(context.Background(), childKey(s), contract.Token{Family: contract.GCP, Value: "24"})
			}
			if got.Status != contract.WriteRefused || got.Reason != contract.ReasonAccess || !got.NotSent || calls != 0 || credentials.calls != 1 {
				t.Fatalf("result=%+v sends=%d credential resolutions=%d", got, calls, credentials.calls)
			}
		})
	}
}

// full_only: false
func TestStoreCreatePreconditionIsPendingWithoutChangingHEADOrCAS(t *testing.T) {
	for _, operation := range []string{"immutable", "head", "cas"} {
		t.Run(operation, func(t *testing.T) {
			s, _ := newStore(t, func(*http.Request) (*http.Response, error) {
				return response(412, `{"error":{"code":412,"errors":[{"reason":"conditionNotMet"}]}}`), nil
			})
			recorder := telemetry.NewRecorder()
			ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
			var got contract.WriteResult
			switch operation {
			case "immutable":
				got = s.Create(ctx, childKey(s), []byte("candidate"))
			case "head":
				request, err := contract.NewHeadCreateRequest(s.Descriptor(), []byte("candidate"))
				if err != nil {
					t.Fatal(err)
				}
				got = s.CreateHead(ctx, request)
			case "cas":
				got = s.CompareAndSwap(ctx, s.Descriptor().HeadKey, contract.Token{Family: contract.GCP, Value: "24"}, []byte("candidate"))
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

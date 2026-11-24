package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

type queryIdentitySample struct {
	base  core.PublicQueryResult
	write func(context.Context, io.Writer, bool) error
}

// These six typed writers share one public envelope. This adapter only lets
// the table inspect their actual returned bytes without new Product fields.
func queryIdentitySampleOf(t *testing.T, value any) queryIdentitySample {
	t.Helper()
	switch r := value.(type) {
	case ConfigurationInspectionResult:
		return queryIdentityCompositionSample(r.PublicQueryResult, r.WriteJSON, r.WriteHuman)
	case ConfigurationRecipientInspectionResult:
		return queryIdentityCompositionSample(r.PublicQueryResult, r.WriteJSON, r.WriteHuman)
	case ConfigurationReceiptListResult:
		return queryIdentityCompositionSample(r.PublicQueryResult, r.WriteJSON, r.WriteHuman)
	case ConfigurationReceiptDetailResult:
		return queryIdentityCompositionSample(r.PublicQueryResult, r.WriteJSON, r.WriteHuman)
	case ConfigurationCapacityResult:
		return queryIdentityCompositionSample(r.PublicQueryResult, r.WriteJSON, r.WriteHuman)
	case core.PublicDomainInspectionResult:
		return queryIdentitySample{r.PublicQueryResult, func(ctx context.Context, w io.Writer, h bool) error {
			if h {
				return WriteInspectionHuman(ctx, w, r)
			}
			return WriteInspectionJSON(ctx, w, r)
		}}
	case core.PublicRecipientInspectionResult:
		return queryIdentitySample{r.PublicQueryResult, func(ctx context.Context, w io.Writer, h bool) error {
			if h {
				return WriteRecipientInspectionHuman(ctx, w, r)
			}
			return WriteRecipientInspectionJSON(ctx, w, r)
		}}
	case core.PublicReceiptListResult:
		return queryIdentitySample{r.PublicQueryResult, func(ctx context.Context, w io.Writer, h bool) error {
			if h {
				return WriteReceiptListHuman(ctx, w, r)
			}
			return WriteReceiptListJSON(ctx, w, r)
		}}
	case core.PublicReceiptDetailResult:
		return queryIdentitySample{r.PublicQueryResult, func(ctx context.Context, w io.Writer, h bool) error {
			if h {
				return WriteReceiptDetailHuman(ctx, w, r)
			}
			return WriteReceiptDetailJSON(ctx, w, r)
		}}
	case core.PublicCapacityInspectionResult:
		return queryIdentitySample{r.PublicQueryResult, func(ctx context.Context, w io.Writer, h bool) error {
			if h {
				return WriteCapacityInspectionHuman(ctx, w, r)
			}
			return WriteCapacityInspectionJSON(ctx, w, r)
		}}
	case GCPlanResult:
		return queryIdentitySample{r.Operation.PublicQueryResult, func(ctx context.Context, w io.Writer, h bool) error {
			if h {
				return WriteGCPlanHuman(ctx, w, r)
			}
			return WriteGCPlanJSON(ctx, w, r)
		}}
	}
	t.Fatal("unsupported query identity test form")
	return queryIdentitySample{}
}

func queryIdentityCompositionSample(base core.PublicQueryResult, json, human func(context.Context, io.Writer) error) queryIdentitySample {
	return queryIdentitySample{base, func(ctx context.Context, w io.Writer, h bool) error {
		if h {
			return human(ctx, w)
		}
		return json(ctx, w)
	}}
}

func newQueryIdentityRefusal(t *testing.T, operation string, format configuration.Format) queryIdentitySample {
	t.Helper()
	switch operation {
	case core.InspectOperation:
		r, e := NewDomainInspectionRefusal(format)
		if e != nil {
			t.Fatal(e)
		}
		return queryIdentitySampleOf(t, r)
	case core.InspectRecipientOperation:
		r, e := NewRecipientInspectionRefusal(format)
		if e != nil {
			t.Fatal(e)
		}
		return queryIdentitySampleOf(t, r)
	case core.ReceiptListOperation:
		r, e := NewReceiptListRefusal(format)
		if e != nil {
			t.Fatal(e)
		}
		return queryIdentitySampleOf(t, r)
	case core.ReceiptDetailOperation:
		r, e := NewReceiptDetailRefusal(format)
		if e != nil {
			t.Fatal(e)
		}
		return queryIdentitySampleOf(t, r)
	case core.InspectCapacityOperation:
		r, e := NewCapacityInspectionRefusal(format)
		if e != nil {
			t.Fatal(e)
		}
		return queryIdentitySampleOf(t, r)
	case core.GCPlanOperation:
		r, e := NewGCPlanRefusal(format)
		if e != nil {
			t.Fatal(e)
		}
		return queryIdentitySampleOf(t, r)
	}
	t.Fatal("unknown recognized query")
	return queryIdentitySample{}
}

// full_only: false
func TestConfigurationPublicQueriesRetainRecognizedPreAdmissionIdentity(t *testing.T) {
	type identityCase struct {
		name, operation, stage, code string
		format                       configuration.Format
		nonce                        contract.ID
		bound                        bool
		run                          func(*testing.T, context.Context, contract.ID) queryIdentitySample
	}
	cases := []identityCase{{name: "bound-unavailable-control", operation: core.InspectOperation, format: configuration.JSON, bound: true, nonce: contract.ID{91}, run: func(t *testing.T, ctx context.Context, nonce contract.ID) queryIdentitySample {
		source := configurationReaderPair(t, "aws", configuration.JSON, nil)
		server := &readerHTTPFixture{archive: source.archive, reads: make(map[string]int), unavailable: true}
		transport, stop := readerHTTPTransport(t, server, []string{"s3.us-east-1.amazonaws.com"})
		t.Cleanup(stop)
		open := func(ctx context.Context, c InspectionReaderConfig) (*core.InstalledInspectionReader, error) {
			c.AWS.Candidate.Credentials = readerFixtureCredentials{}
			c.AWS.Candidate.Transport = transport
			return NewInspectionReader(ctx, c)
		}
		c, pins, err := configurationPublicQueryInput(ctx, nonce, source.pair)
		if err != nil {
			t.Fatal(err)
		}
		directReader, err := open(ctx, InspectionReaderConfig{ReaderConfig: c, SourcePins: pins, CheckSource: source.pair.CheckUnchanged})
		if err != nil {
			t.Fatal(err)
		}
		direct := directReader.Inspect(ctx, core.DomainInspectionRequest{RequestNonce: nonce})
		directReader.Close()
		wrapped := inspectConfiguration(ctx, nonce, source.pair, open)
		if direct.Query == nil || direct.Query.Validate() != nil || direct.StateResult != core.PublicQueryUnavailable || direct.View != nil || direct.RequestIdentity.IsZero() || direct.RequestIdentity != direct.Query.Digest || !reflect.DeepEqual(wrapped.Query, direct.Query) || !reflect.DeepEqual(wrapped.PublicQueryResult, direct.PublicQueryResult) || wrapped.View != nil {
			t.Fatal("authentic bound unavailable control lost original Core correlation")
		}
		server.assertNoEffects(t)
		source.assertUnchanged(t)
		return queryIdentitySampleOf(t, wrapped)
	}}}
	for i, operation := range []string{core.InspectOperation, core.InspectRecipientOperation, core.ReceiptListOperation, core.ReceiptDetailOperation, core.InspectCapacityOperation, core.GCPlanOperation} {
		format := configuration.JSON
		if i%2 != 0 {
			format = configuration.YAML
		}
		cases = append(cases, identityCase{name: "recognition/" + operation, operation: operation, stage: "dispatch", code: string(contract.ReasonInvalidInput), format: format, run: func(t *testing.T, _ context.Context, _ contract.ID) queryIdentitySample {
			return newQueryIdentityRefusal(t, operation, format)
		}})
	}
	cases = append(cases,
		identityCase{name: "file-capture", operation: core.InspectOperation, stage: "capture", code: string(contract.ReasonInvalidInput), format: configuration.YAML, nonce: contract.ID{92}, run: func(t *testing.T, ctx context.Context, nonce contract.ID) queryIdentitySample {
			path := filepath.Join(protectedConfigurationTestDirectory(t), "private-query-envelope-sentinel.yaml")
			return queryIdentitySampleOf(t, InspectConfigurationFile(ctx, nonce, path, configuration.YAML))
		}},
		identityCase{name: "pair-parse", operation: core.ReceiptListOperation, stage: "parse", code: string(contract.ReasonInvalidInput), format: 0, nonce: contract.ID{93}, run: func(t *testing.T, ctx context.Context, nonce contract.ID) queryIdentitySample {
			opened := 0
			r := listConfigurationReceipts(ctx, nonce, nil, func(context.Context, ReceiptReaderConfig) (*core.InstalledReceiptReader, error) {
				opened++
				return nil, errors.New("private-query-envelope-sentinel")
			})
			if opened != 0 {
				t.Fatal("nil captured pair reached credentials")
			}
			return queryIdentitySampleOf(t, r)
		}},
		identityCase{name: "capacity-cancelled-context", operation: core.InspectCapacityOperation, stage: "context", code: string(contract.ReasonCancelled), format: configuration.JSON, nonce: contract.ID{99}, run: func(t *testing.T, ctx context.Context, nonce contract.ID) queryIdentitySample {
			source := configurationReaderPair(t, "aws", configuration.JSON, nil)
			operationContext, cancel := context.WithCancel(ctx)
			cancel()
			opened := 0
			r := inspectConfigurationCapacity(operationContext, core.CapacityInspectionRequest{RequestNonce: nonce}, source.pair, func(context.Context, CapacityReaderConfig) (*core.InstalledCapacityReader, error) {
				opened++
				return nil, errors.New("private-query-envelope-sentinel")
			})
			if opened != 0 {
				t.Fatal("cancelled operation reached credentials")
			}
			source.assertUnchanged(t)
			// The table renders with its still-live outer context.
			return queryIdentitySampleOf(t, r)
		}},
		identityCase{name: "capacity-cursor", operation: core.InspectCapacityOperation, stage: "declaration", code: string(contract.ReasonInvalidInput), format: configuration.JSON, nonce: contract.ID{94}, run: func(t *testing.T, ctx context.Context, nonce contract.ID) queryIdentitySample {
			source := configurationReaderPair(t, "aws", configuration.JSON, nil)
			opened := 0
			r := inspectConfigurationCapacity(ctx, core.CapacityInspectionRequest{RequestNonce: nonce, Cursor: "not-wrapped"}, source.pair, func(context.Context, CapacityReaderConfig) (*core.InstalledCapacityReader, error) {
				opened++
				return nil, errors.New("private-query-envelope-sentinel")
			})
			if opened != 0 {
				t.Fatal("invalid capacity cursor reached credentials")
			}
			source.assertUnchanged(t)
			return queryIdentitySampleOf(t, r)
		}},
		identityCase{name: "gc-plan-cursor", operation: core.GCPlanOperation, stage: "declaration", code: string(contract.ReasonInvalidInput), format: configuration.JSON, nonce: contract.ID{95}, run: func(t *testing.T, ctx context.Context, nonce contract.ID) queryIdentitySample {
			source := configurationReaderPair(t, "aws", configuration.JSON, nil)
			opened := 0
			r := planConfigurationGC(ctx, GCPlanRequest{RequestNonce: nonce, OperationID: contract.ID{98}, Cursor: "not-wrapped", ArtifactPath: filepath.Join(protectedConfigurationTestDirectory(t), "unused.bin")}, source.pair, func(context.Context, CapacityReaderConfig) (*core.InstalledCapacityReader, error) {
				opened++
				return nil, errors.New("private-query-envelope-sentinel")
			}, nativeAbandonPlanIO())
			if opened != 0 {
				t.Fatal("invalid plan cursor reached credentials")
			}
			source.assertUnchanged(t)
			return queryIdentitySampleOf(t, r)
		}},
		identityCase{name: "recipient-construction", operation: core.InspectRecipientOperation, stage: "construction", code: string(contract.ReasonEvidenceUnavailable), format: configuration.YAML, nonce: contract.ID{96}, run: func(t *testing.T, ctx context.Context, nonce contract.ID) queryIdentitySample {
			source := configurationReaderPair(t, "aws", configuration.YAML, nil)
			opened := 0
			r := inspectConfigurationRecipient(ctx, nonce, source.pair, contract.ID{97}, func(context.Context, InspectionReaderConfig) (*core.InstalledInspectionReader, error) {
				opened++
				return nil, errors.New("private-query-envelope-sentinel")
			})
			if opened != 1 || r.StateResult != core.PublicQueryUnavailable {
				t.Fatal("construction refusal control did not reach only its opener")
			}
			source.assertUnchanged(t)
			return queryIdentitySampleOf(t, r)
		}},
	)
	seen := make(map[contract.ID]bool)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			sample := tc.run(t, ctx, tc.nonce)
			if sample.base.OperationID.IsZero() || seen[sample.base.OperationID] {
				t.Error("recognized query lacks fresh operation correlation")
			}
			seen[sample.base.OperationID] = true
			if sample.base.RequestID != tc.nonce || sample.base.Operation != tc.operation {
				t.Fatal("query seam changed operation or nonce")
			}
			for _, human := range []bool{false, true} {
				var output bytes.Buffer
				if err := sample.write(ctx, &output, human); err != nil {
					t.Errorf("recognized query did not render: %v", err)
					continue
				}
				body := output.Bytes()
				if human {
					assertQueryHumanHasNoEnvelope(t, string(body))
					b := sample.base
					if !bytes.Contains(body, []byte(publicQueryHumanHeading(tc.operation)+": "+string(b.StateResult)+"\n")) ||
						!bytes.Contains(body, []byte("Operation id: \""+readerID(b.OperationID)+"\"\n")) ||
						(!b.RequestID.IsZero() && !bytes.Contains(body, []byte("Request id: \""+readerID(tc.nonce)+"\"\n"))) ||
						!bytes.Contains(body, []byte("Evidence ceiling: unavailable\n")) ||
						!bytes.Contains(body, []byte("No query data is available.\n")) {
						t.Error("human query refusal lost correlation or evidence")
					}
					continue
				}
				var record map[string]json.RawMessage
				if json.Unmarshal(body, &record) != nil {
					t.Fatal("query envelope is not complete JSON")
				}
				var schema, operation, local, replay, payloadKind string
				if json.Unmarshal(record["schema"], &schema) != nil || json.Unmarshal(record["operation_kind"], &operation) != nil || json.Unmarshal(record["operation_id"], &local) != nil || json.Unmarshal(record["replay_identity"], &replay) != nil || json.Unmarshal(record["operation_payload"], &payloadKind) != nil || schema != "ProductResult/v1" || operation != tc.operation || local != readerID(sample.base.OperationID) || replay != "none" || payloadKind != "none" || !bytes.Equal(record["payload"], []byte("null")) || bytes.Contains(body, []byte("private-query-envelope-sentinel")) || bytes.Contains(body, []byte("raw-error-sentinel")) {
					t.Error("query envelope lost exact local/Core correlation or disclosed private input")
				}
				if tc.bound {
					var identity string
					if json.Unmarshal(record["request_identity"], &identity) != nil || identity != readerID(sample.base.RequestIdentity) {
						t.Error("bound unavailable Query identity was overlaid by local metadata")
					}
					continue
				}
				if !sample.base.RequestIdentity.IsZero() || sample.base.Result.CommitMayHaveOccurred {
					t.Fatal("pre-admission query gained authority or selection")
				}
				var fields map[string]json.RawMessage
				if json.Unmarshal(record["request_identity"], &fields) != nil || fields == nil {
					t.Error("recognized query lacks PreAdmissionRequestIdentity/v1 object")
					continue
				}
				var q preAdmissionIdentityRecord
				if json.Unmarshal(record["request_identity"], &q) != nil || q.Schema != "PreAdmissionRequestIdentity/v1" || q.OperationID != local || q.OperationKind != tc.operation || q.SourceSchema != "enkv/configuration/v3" || q.SourceProfile != "direct-candidate" || q.Format != configurationSourceFormat(tc.format) || q.Stage != tc.stage || q.Code != tc.code || q.RequestNonce != readerID(tc.nonce) {
					t.Error("recognized query lost exact schema/profile/format/stage/code/nonce")
				}
				for _, name := range []string{"predecessor", "predecessor_digest", "predecessor_revision_id", "selection", "authority_subject", "retry_right"} {
					if _, exists := fields[name]; exists {
						t.Errorf("pre-admission query grants unavailable %s", name)
					}
				}
			}
		})
	}
}

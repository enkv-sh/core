package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	gcpprovider "enkv.sh/providers/gcp"
)

// full_only: false
func TestConfigurationQueryUnsupportedSourceSchemaRefusesAtEveryFileEntry(t *testing.T) {
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		body := []byte(`{"schema":"enkv/configuration/unsupported"}`)
		if format == configuration.YAML {
			body = []byte("schema: enkv/configuration/unsupported\n")
		}
		path := filepath.Join(t.TempDir(), "configuration")
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		for _, operation := range []string{core.ReceiptListOperation, core.ReceiptDetailOperation, core.InspectOperation, core.InspectRecipientOperation, core.InspectCapacityOperation, core.GCPlanOperation} {
			t.Run(fmt.Sprintf("%s/%d", operation, format), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				var out core.PublicQueryResult
				switch operation {
				case core.ReceiptListOperation:
					out = ListConfigurationReceiptsFile(ctx, contract.ID{1}, path, format).PublicQueryResult
				case core.ReceiptDetailOperation:
					out = ReadConfigurationReceiptFile(ctx, contract.ID{1}, path, format, contract.ID{2}).PublicQueryResult
				case core.InspectOperation:
					out = InspectConfigurationFile(ctx, contract.ID{1}, path, format).PublicQueryResult
				case core.InspectRecipientOperation:
					out = InspectConfigurationRecipientFile(ctx, contract.ID{1}, path, format, contract.ID{2}).PublicQueryResult
				case core.InspectCapacityOperation:
					out = InspectConfigurationCapacityFile(ctx, core.CapacityInspectionRequest{RequestNonce: contract.ID{1}}, path, format).PublicQueryResult
				case core.GCPlanOperation:
					out = PlanConfigurationGCFile(ctx, GCPlanRequest{RequestNonce: contract.ID{1}, OperationID: contract.ID{2}, ArtifactPath: filepath.Join(t.TempDir(), "plan")}, path, format).Operation.PublicQueryResult
				}
				if out.StateResult != core.PublicQueryProfileBlocked || out.Result != (core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}) || out.FailureReason != contract.ReasonUnsupportedSchema || out.PreAdmission == nil || out.PreAdmission.Stage != "capture" || out.PreAdmission.Code != string(contract.ReasonUnsupportedSchema) || !out.DomainID.IsZero() || !out.RequestIdentity.IsZero() {
					t.Error("unsupported source schema lost its closed capture refusal", out)
				}
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, body) {
					t.Fatal("unsupported-source query changed source bytes", err)
				}
			})
		}
	}
}

// full_only: false
func TestConfigurationQueryUnsupportedSchemaProducesRenderableClosedFailure(t *testing.T) {
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		for _, operation := range []string{core.ReceiptListOperation, core.ReceiptDetailOperation, core.InspectOperation, core.InspectRecipientOperation, core.InspectCapacityOperation, core.GCPlanOperation} {
			t.Run(fmt.Sprintf("%s/%d", operation, format), func(t *testing.T) {
				out, err := newConfigurationQueryRefusal(operation, contract.ID{1}, format)
				if err != nil {
					t.Fatal(err)
				}
				configurationQueryFailure(t.Context(), &out, nil, "capture", &configuration.Diagnostic{Field: "schema", Reason: "unsupported-schema"}, false)
				if out.StateResult != core.PublicQueryProfileBlocked || out.FailureReason != contract.ReasonUnsupportedSchema || out.Result != (core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}) || !out.RequestIdentity.IsZero() || !out.DomainID.IsZero() || out.PreAdmission == nil || out.PreAdmission.Stage != "capture" || out.PreAdmission.Code != string(contract.ReasonUnsupportedSchema) || PublicQueryExitCode(out) != 2 {
					t.Error("capture failure lost closed unsupported-schema meaning", out)
				}
				var writers []func(context.Context, io.Writer) error
				switch operation {
				case core.ReceiptListOperation:
					r := core.PublicReceiptListResult{PublicQueryResult: out}
					writers = []func(context.Context, io.Writer) error{func(ctx context.Context, w io.Writer) error { return WriteReceiptListJSON(ctx, w, r) }, func(ctx context.Context, w io.Writer) error { return WriteReceiptListHuman(ctx, w, r) }}
				case core.ReceiptDetailOperation:
					r := core.PublicReceiptDetailResult{PublicQueryResult: out}
					writers = []func(context.Context, io.Writer) error{func(ctx context.Context, w io.Writer) error { return WriteReceiptDetailJSON(ctx, w, r) }, func(ctx context.Context, w io.Writer) error { return WriteReceiptDetailHuman(ctx, w, r) }}
				case core.InspectOperation:
					r := core.PublicDomainInspectionResult{PublicQueryResult: out}
					writers = []func(context.Context, io.Writer) error{func(ctx context.Context, w io.Writer) error { return WriteInspectionJSON(ctx, w, r) }, func(ctx context.Context, w io.Writer) error { return WriteInspectionHuman(ctx, w, r) }}
				case core.InspectRecipientOperation:
					r := core.PublicRecipientInspectionResult{PublicQueryResult: out}
					writers = []func(context.Context, io.Writer) error{func(ctx context.Context, w io.Writer) error { return WriteRecipientInspectionJSON(ctx, w, r) }, func(ctx context.Context, w io.Writer) error { return WriteRecipientInspectionHuman(ctx, w, r) }}
				case core.InspectCapacityOperation:
					r := core.PublicCapacityInspectionResult{PublicQueryResult: out}
					writers = []func(context.Context, io.Writer) error{func(ctx context.Context, w io.Writer) error { return WriteCapacityInspectionJSON(ctx, w, r) }, func(ctx context.Context, w io.Writer) error { return WriteCapacityInspectionHuman(ctx, w, r) }}
				case core.GCPlanOperation:
					r := GCPlanResult{Operation: core.PublicGCPreviewResult{PublicQueryResult: out}}
					writers = []func(context.Context, io.Writer) error{func(ctx context.Context, w io.Writer) error { return WriteGCPlanJSON(ctx, w, r) }, func(ctx context.Context, w io.Writer) error { return WriteGCPlanHuman(ctx, w, r) }}
				}
				for i, write := range writers {
					var body bytes.Buffer
					if err := write(t.Context(), &body); err != nil {
						t.Error("unsupported-schema failure did not render", i, err)
						continue
					}
					if i == 0 {
						var doc struct {
							State   string          `json:"state_result"`
							Kind    string          `json:"operation_payload"`
							Payload json.RawMessage `json:"payload"`
						}
						if err := json.Unmarshal(body.Bytes(), &doc); err != nil || doc.State != "profile-blocked" || doc.Kind != "none" || string(doc.Payload) != "null" {
							t.Error("rendered unsupported-schema failure changed meaning", body.String(), err)
						}
					}
				}
			})
		}
	}
}

// full_only: false
func TestConfigurationPublicQueriesUseInstalledGETAndPreserveBothSourceFormats(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
			t.Run(fmt.Sprintf("%s/%d", family, format), func(t *testing.T) {
				t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
				t.Setenv("EXPERIMENTAL_GOOGLE_API_USE_S2A", "false")
				source := configurationReaderPair(t, family, format, nil)
				defer source.assertUnchanged(t)
				server := &readerHTTPFixture{archive: source.archive, reads: make(map[string]int)}
				transport, stop := readerHTTPTransport(t, server, []string{"s3.us-east-1.amazonaws.com", "storage.australia-southeast1.rep.googleapis.com"})
				defer stop()
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				configure := func(c ReaderConfig) ReaderConfig {
					if c.AWS != nil {
						c.AWS.Candidate.Credentials = readerFixtureCredentials{}
						c.AWS.Candidate.Transport = transport
					} else {
						client, err := gcpprovider.NewLocalResponderClient(transport, readerFixtureCredentials{})
						if err != nil {
							t.Fatal(err)
						}
						c.GCP.Candidate.Client = client
					}
					return c
				}
				receiptOpen := func(ctx context.Context, c ReceiptReaderConfig) (*core.InstalledReceiptReader, error) {
					c.ReaderConfig = configure(c.ReaderConfig)
					return NewReceiptReader(ctx, c)
				}
				inspectOpen := func(ctx context.Context, c InspectionReaderConfig) (*core.InstalledInspectionReader, error) {
					c.ReaderConfig = configure(c.ReaderConfig)
					return NewInspectionReader(ctx, c)
				}
				inspected := inspectConfiguration(ctx, contract.ID{1}, source.pair, inspectOpen)
				if inspected.StateResult != core.PublicQuerySuccess || validateInspection(inspected.PublicDomainInspectionResult) != nil {
					t.Fatal("installed complete inspection", inspected.PublicQueryResult)
				}
				wantNames := []string{"", "a/\n雪", "encoded", "secret"}
				if len(inspected.View.Entries) != len(wantNames) {
					t.Fatal("incomplete entry set")
				}
				for i, row := range inspected.View.Entries {
					if row.Name != wantNames[i] {
						t.Fatal("selected metadata changed", row.Name)
					}
				}
				selector := RecipientSelector{ID: readerFixtureTarget(source.archive.Domain)}
				if format == configuration.YAML {
					model, err := configuration.Parse(ctx, source.pair)
					if err != nil {
						t.Fatal(err)
					}
					for _, row := range model.Recipients {
						if row.ID == selector.ID {
							selector = RecipientSelector{Reference: row.Reference}
							break
						}
					}
					if selector.Reference == "" {
						t.Fatal("target has no local alias")
					}
				}
				initial, err := newConfigurationQueryRefusal(core.InspectRecipientOperation, contract.ID{2}, format)
				if err != nil {
					t.Fatal(err)
				}
				recipient := inspectConfigurationRecipientWithIdentity(ctx, contract.ID{2}, source.pair, selector, inspectOpen, initial)
				if recipient.StateResult != core.PublicQuerySuccess || recipient.Validate() != nil || len(recipient.View.Entries) != 4 {
					t.Fatal("installed recipient view", recipient.PublicQueryResult)
				}
				list := listConfigurationReceipts(ctx, contract.ID{3}, source.pair, receiptOpen)
				if list.StateResult != core.PublicQuerySuccess || list.Validate() != nil || list.Payload.Receipts == nil {
					t.Fatal("installed complete retention", list.PublicQueryResult)
				}
				exact := contract.ID{99}
				if len(list.Payload.Receipts) > 0 {
					exact = list.Payload.Receipts[0].OperationID
				}
				detail := readConfigurationReceipt(ctx, contract.ID{4}, source.pair, exact, receiptOpen)
				if detail.Validate() != nil || len(list.Payload.Receipts) > 0 && detail.StateResult != core.PublicQuerySuccess || len(list.Payload.Receipts) == 0 && detail.StateResult != core.PublicQueryUnavailable {
					t.Fatal("installed exact detail", detail.PublicQueryResult)
				}
				if detail.Payload != nil && len(detail.Payload.EncodedReceipt) != 471 {
					t.Fatal("retained receipt bytes lost")
				}
				source.assertUnchanged(t)
				server.assertNoEffects(t)
				server.reset(true, "", 0)
				unavailable := inspectConfiguration(ctx, contract.ID{5}, source.pair, inspectOpen)
				if unavailable.StateResult != core.PublicQueryUnavailable || unavailable.View != nil || unavailable.ValidateMetadataWorkOutput() != nil {
					t.Fatal("unavailable evidence changed category", unavailable.PublicQueryResult)
				}
				canceled, stopQuery := context.WithCancel(ctx)
				stopQuery()
				closed := InspectConfigurationFile(canceled, contract.ID{6}, source.path, format)
				if closed.StateResult == core.PublicQuerySuccess || closed.View != nil {
					t.Fatal("canceled capture returned a view")
				}
				source.assertUnchanged(t)
			})
		}
	}
}

// full_only: false
func TestConfigurationQuerySelectorsAndContextRefuseBeforeOpeningCredentials(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	opened := 0
	receiptOpen := func(context.Context, ReceiptReaderConfig) (*core.InstalledReceiptReader, error) {
		opened++
		return nil, nil
	}
	inspectOpen := func(context.Context, InspectionReaderConfig) (*core.InstalledInspectionReader, error) {
		opened++
		return nil, nil
	}
	detail := readConfigurationReceipt(ctx, contract.ID{1}, nil, contract.ID{}, receiptOpen)
	recipient := inspectConfigurationRecipient(ctx, contract.ID{2}, nil, contract.ID{}, inspectOpen)
	domain := inspectConfiguration(context.Background(), contract.ID{3}, nil, inspectOpen)
	if opened != 0 || detail.Validate() != nil || recipient.Validate() != nil || domain.ValidateMetadataWorkOutput() != nil {
		t.Fatal("invalid inputs reached provider construction")
	}
	if detail.Operation != core.ReceiptDetailOperation || recipient.Operation != core.InspectRecipientOperation || domain.StateResult != core.PublicQueryRefused {
		t.Fatal("recognized forms lost closed refusal")
	}
}

// full_only: false
func TestQueryRefusalRenderersKeepClosedFailureAndExitCategories(t *testing.T) {
	for _, state := range []core.PublicQueryStateResult{core.PublicQuerySuccess, core.PublicQueryUnavailable, core.PublicQueryContention, core.PublicQueryRefused, core.PublicQueryPositiveDefect, core.PublicQueryRootLoss} {
		want := 2
		switch state {
		case core.PublicQuerySuccess:
			want = 0
		case core.PublicQueryUnavailable, core.PublicQueryContention:
			want = 3
		}
		if PublicQueryExitCode(core.PublicQueryResult{StateResult: state}) != want {
			t.Fatal("query exit convention", state)
		}
	}
	r, err := NewReceiptListRefusal(configuration.JSON)
	if err != nil {
		t.Fatal(err)
	}
	if r.Validate() != nil {
		t.Fatal("local refusal invalid")
	}
	var body bytes.Buffer
	if err := WriteReceiptListJSON(t.Context(), &body, r); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Operation string `json:"operation_kind"`
		State     string `json:"state_result"`
		Payload   json.RawMessage
		Kind      string `json:"operation_payload"`
	}
	if err := json.Unmarshal(body.Bytes(), &doc); err != nil || doc.Operation != "receipt-list" || doc.State != "refused" || string(doc.Payload) != "null" || doc.Kind != "none" {
		t.Fatal("local refusal changed closed result", doc, err)
	}
}

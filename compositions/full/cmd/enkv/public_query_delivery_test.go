package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicQuerySuccessfulDeliveryControlsExitForEveryForm(t *testing.T) {
	for _, key := range []string{"ENKV_LOG_LEVEL", "OTEL_SERVICE_NAME", "OTEL_RESOURCE_ATTRIBUTES"} {
		t.Setenv(key, "")
	}
	for _, form := range []string{"domain", "recipient", "list", "detail"} {
		for _, output := range []string{"human", "json"} {
			for _, delivery := range []string{"complete", "short", "error", "cancel-final-newline", "deadline-final-newline"} {
				t.Run(form+"/"+output+"/"+delivery, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
						defer cancel()
						args := []string{"--source=delivery-source.json", "--source-format=json", "--log-level=off"}
						selector := "0b" + strings.Repeat("00", 31)
						if form == "recipient" {
							args = append(args, "--recipient-id="+selector)
						}
						if form == "detail" {
							args = append(args, "--operation="+selector)
						}
						if output == "json" {
							args = append(args, "--json")
						}
						calls := 0
						check := func(nonce contract.ID, path string, format configuration.Format) {
							t.Helper()
							calls++
							wantPath, err := filepath.Abs("delivery-source.json")
							if err != nil || nonce.IsZero() || path != wantPath || format != configuration.JSON {
								t.Fatal("successful query received different source inputs", err, path, format)
							}
						}
						operation := map[string]string{"domain": "inspect", "recipient": "inspect-recipient", "list": "receipt-list", "detail": "receipt-detail"}[form]
						r, q, digest := publicQueryDeliveryBasis(t, operation)
						domain := func(_ context.Context, nonce contract.ID, path string, format configuration.Format) compositionfull.ConfigurationInspectionResult {
							check(nonce, path, format)
							config := contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: contract.ID{1}}
							image, err := contract.EncodeOutputConfiguration(config)
							if err != nil {
								t.Fatal(err)
							}
							descriptor, _, err := contract.SplitOutputConfiguration(config.DomainID, image)
							if err != nil {
								t.Fatal(err)
							}
							return compositionfull.ConfigurationInspectionResult{PublicDomainInspectionResult: core.PublicDomainInspectionResult{PublicQueryResult: r, Query: &core.DomainInspectionQueryIdentity{PublicQueryBasis: q, Digest: digest}, View: &core.DomainInspection{Observation: *q.Observation, Output: core.InspectionOutput{Configuration: config, ConfigurationDescriptor: descriptor}}}}
						}
						recipient := func(_ context.Context, nonce contract.ID, path string, format configuration.Format, selection compositionfull.RecipientSelector) compositionfull.ConfigurationRecipientInspectionResult {
							id := selection.ID
							check(nonce, path, format)
							if id != (contract.ID{11}) {
								t.Fatal("Recipient selector changed")
							}
							return compositionfull.ConfigurationRecipientInspectionResult{PublicRecipientInspectionResult: core.PublicRecipientInspectionResult{PublicQueryResult: r, Query: &core.RecipientInspectionQueryIdentity{PublicQueryBasis: q, RecipientID: id, Digest: digest}, View: &core.RecipientInspection{Observation: *q.Observation, RecipientID: id}}}
						}
						list := func(_ context.Context, nonce contract.ID, path string, format configuration.Format) compositionfull.ConfigurationReceiptListResult {
							check(nonce, path, format)
							return compositionfull.ConfigurationReceiptListResult{PublicReceiptListResult: core.PublicReceiptListResult{PublicQueryResult: r, Query: &core.ReceiptListQueryIdentity{PublicQueryBasis: q, Digest: digest}, Payload: &core.ReceiptListPayload{Observation: *q.Observation, Receipts: []core.ReceiptSummary{}}}}
						}
						detail := func(_ context.Context, nonce contract.ID, path string, format configuration.Format, id contract.ID) compositionfull.ConfigurationReceiptDetailResult {
							check(nonce, path, format)
							if id != (contract.ID{11}) {
								t.Fatal("operation selector changed")
							}
							row, body := publicQueryDeliveryReceipt()
							return compositionfull.ConfigurationReceiptDetailResult{PublicReceiptDetailResult: core.PublicReceiptDetailResult{PublicQueryResult: r, Query: &core.ReceiptDetailQueryIdentity{PublicQueryBasis: q, RequestedOperationID: id, Digest: digest}, Payload: &core.ReceiptDetailPayload{Observation: *q.Observation, Receipt: row, EncodedReceipt: body, Authenticity: "authenticated-retained", Retention: "retained"}}}
						}
						out := &publicQueryFinalDeliveryWriter{ctx: ctx, cancel: cancel, delivery: delivery, human: output == "human"}
						var diagnostic bytes.Buffer
						var code int
						wantDiagnostic := "inspection result delivery failed\n"
						if form == "domain" || form == "recipient" {
							code = runInspectWithExecutors(ctx, args, out, &diagnostic, domain, recipient, nil)
						} else {
							code = runReceiptWithExecutors(ctx, args, out, &diagnostic, list, detail)
							wantDiagnostic = "receipt result delivery failed\n"
						}
						wantCode := 2
						if delivery == "complete" {
							wantCode, wantDiagnostic = 0, ""
						}
						if code != wantCode || calls != 1 || diagnostic.String() != wantDiagnostic {
							t.Errorf("successful read delivery exit, executor count or safe diagnostic changed: code=%d calls=%d diagnostic=%q", code, calls, diagnostic.String())
						}
						if out.newlines != 1 || out.beforeFinal != nil {
							t.Fatal("delivery did not reach the final newline with a live context", out.newlines, out.beforeFinal)
						}
						var wantContext error
						if delivery == "cancel-final-newline" {
							wantContext = context.Canceled
						}
						if delivery == "deadline-final-newline" {
							wantContext = context.DeadlineExceeded
						}
						if !errors.Is(ctx.Err(), wantContext) {
							t.Fatal("final-write context condition was not established", ctx.Err(), wantContext)
						}
						body := out.body.Bytes()
						var doc struct {
							Operation string `json:"operation_kind"`
							State     string `json:"state_result"`
							Payload   struct{ Form string }
						}
						if output == "json" {
							if err := json.Unmarshal(body, &doc); err != nil || doc.Operation != operation || doc.State != "success" || doc.Payload.Form != form {
								t.Fatal("delivery did not render the complete successful typed result", err, doc)
							}
						} else {
							heading := map[string]string{"domain": "Domain inspection", "recipient": "Recipient inspection", "list": "Receipt list", "detail": "Receipt detail"}[form]
							fact := map[string]string{"domain": "Entries: 0 rows", "recipient": "Recipient id: \"" + selector + "\"", "list": "Receipts: 0 rows", "detail": "Authenticity: \"authenticated-retained\""}[form]
							if !bytes.HasPrefix(body, []byte(heading+": success\n")) || !bytes.Contains(body, []byte(fact)) || !bytes.Contains(body, []byte("Query only; no domain changes were made.")) || bytes.Contains(body, []byte("ProductResult/v1")) {
								t.Fatal("human delivery lost command outcome or query facts", string(body))
							}
						}
						wantNewline := delivery != "short" && delivery != "error"
						if bytes.HasSuffix(body, []byte("\n")) != wantNewline {
							t.Fatal("writer did not establish the selected final-newline outcome")
						}
					})
				})
			}
		}
	}
}

type publicQueryFinalDeliveryWriter struct {
	ctx         context.Context
	cancel      context.CancelFunc
	delivery    string
	body        bytes.Buffer
	newlines    int
	beforeFinal error
	human       bool
}

func (w *publicQueryFinalDeliveryWriter) Write(b []byte) (int, error) {
	body := w.body.Bytes()
	finalBody := json.Valid(body)
	if w.human {
		finalBody = bytes.HasSuffix(body, []byte("Query only; no domain changes were made."))
	}
	if string(b) == "\n" && finalBody {
		w.newlines++
		w.beforeFinal = w.ctx.Err()
		switch w.delivery {
		case "short":
			return 0, nil
		case "error":
			return 0, errors.New("private-writer-error-sentinel")
		case "cancel-final-newline":
			w.cancel()
		case "deadline-final-newline":
			// The fake clock advances only when this finite wait blocks.
			<-w.ctx.Done()
		}
	}
	return w.body.Write(b)
}

func publicQueryDeliveryBasis(t *testing.T, operation string) (core.PublicQueryResult, core.PublicQueryBasis, contract.ID) {
	t.Helper()
	// Reuse the renderer fixtures' independently calculated SHA-256 vectors:
	// LE u16/u64 query traversal; basis IDs 1..6, pins 12/13/14, format 1,
	// lengths 1/2, nonce 7, selector 11 or zero, observation 1/8/9/10.
	// These are valid executor results; this test checks delivery, not nonce binding.
	vectors := map[string][2]string{
		core.InspectOperation:          {"6fa4a9861165863efc7d44a934a7f4cd0f9af0d40ec75470c344db741b010a41", "d48fcb07fec22946659a24aa0f88132e832775b366663c699150e828010fa3df"},
		core.InspectRecipientOperation: {"2440ed07e6620e07a884ff428d5525e68f60ba7efc8f06c59ff75e13f2ab61c1", "30181585db73db13a6dca51106b4b3f9260a41b9943cd5da3ff8c8512d87e66a"},
		core.ReceiptListOperation:      {"b6b17d94a4eaf0b609b6d162cb60dd7286d4cb50f1a0c7e3237c625b05c218ee", "a962afe31dc5d3fb85d6c5f0b5cd6e0b867ab28862ed7fc54839fb9b5d3678c2"},
		core.ReceiptDetailOperation:    {"2315ce07ecdf49ea45542bc0cbe12ccfb41065d9f6138dfdc46a3be2abb67015", "2665b81debcb0d83b7c9617d8779fc304a27e2e13e23df00ab7ad049ad80f084"},
	}
	parse := func(value string) (id contract.ID) {
		body, err := hex.DecodeString(value)
		if err != nil || len(body) != len(id) {
			t.Fatal("invalid independent query vector")
		}
		copy(id[:], body)
		return id
	}
	vector := vectors[operation]
	digest, operationID := parse(vector[0]), parse(vector[1])
	semantic := uint16(15)
	if strings.HasPrefix(operation, "receipt") {
		semantic = 16
	}
	observation := core.PublicObservation{DomainID: contract.ID{1}, HeadRevisionID: contract.ID{8}, SnapshotID: contract.ID{9}, RootDigest: contract.ID{10}}
	q := core.PublicQueryBasis{Schema: "QueryRequestIdentity/v1", Operation: operation, SemanticOperation: semantic, ExpectedDomain: contract.ID{1}, StoreID: contract.ID{2}, CoordinateID: contract.ID{3}, NonBodyID: contract.ID{4}, StoreDescriptorDigest: contract.ID{5}, PublicBasisDigest: contract.ID{6}, SourcePins: core.AdministrativeSourcePins{FileID: contract.ID{12}, Format: 1, EditableDigest: contract.ID{13}, EditableLength: 1, GeneratedDigest: contract.ID{14}, GeneratedLength: 2, HasGenerated: true}, RequestNonce: contract.ID{7}, Observation: &observation}
	r := core.PublicQueryResult{Operation: operation, RequestID: contract.ID{7}, OperationID: operationID, RequestIdentity: digest, DomainID: contract.ID{1}, Result: core.Result{Outcome: core.ObservedCurrent, Evidence: core.AuthenticatedClosure, ObservedRevision: contract.ID{8}, ObservedSnapshotID: contract.ID{9}}, StateResult: core.PublicQuerySuccess}
	return r, q, digest
}

func publicQueryDeliveryReceipt() (contract.CompactMutationReceipt, []byte) {
	row := contract.CompactMutationReceipt{Schema: 3, OperationKind: 2, StateResult: 1, EffectSummary: 1, EvidenceCeiling: 1, DomainID: contract.ID{1}, OperationID: contract.ID{11}, RequestIdentityDigest: contract.ID{21}, PredecessorRevisionID: contract.ID{22}, RequestedRevisionID: contract.ID{23}, ObservedRevisionID: contract.ID{23}, CanonicalOutcome: 1, ChangedSubjects: contract.GeneratorDescriptor{Count: 0, Length: 4, Digest: contract.ID{24}}, CompleteResult: contract.GeneratorDescriptor{Count: 1, Length: 655, Digest: contract.ID{25}}}
	// Same independent receipt fixture as the renderer: BE six u16 scalars,
	// six IDs, one u8 outcome, two ID/u64/u32 descriptors, then 178 zero bytes.
	body := []byte{}
	for _, value := range []uint16{3, 2, 1, 1, 0, 1} {
		body = binary.BigEndian.AppendUint16(body, value)
	}
	for _, id := range []contract.ID{{1}, {11}, {21}, {22}, {23}, {23}} {
		body = append(body, id[:]...)
	}
	body = append(body, 1)
	for _, descriptor := range []contract.GeneratorDescriptor{row.ChangedSubjects, row.CompleteResult} {
		body = append(body, descriptor.Digest[:]...)
		body = binary.BigEndian.AppendUint64(body, descriptor.Length)
		body = binary.BigEndian.AppendUint32(body, descriptor.Count)
	}
	return row, append(body, make([]byte, 178)...)
}

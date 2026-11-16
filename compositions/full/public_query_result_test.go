package compositionfull

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func publicQueryRendererBasis(t *testing.T, operation string) (core.PublicQueryResult, core.PublicQueryBasis, contract.ID) {
	t.Helper()
	// Independently calculated SHA-256 vectors use the specified LE u16/u64
	// query traversal. IDs are their first byte followed by 31 zeros. The basis
	// IDs are 1..6, pins 12/13/14, format 1, lengths 1/2, nonce 7,
	// selector 11 (or zero), and observation 1/8/9/10. Operation IDs hash the
	// fixed ENKV/public-query-operation/v1 NUL prefix and that query digest.
	vectors := map[string][2]string{
		core.InspectOperation:          {"6fa4a9861165863efc7d44a934a7f4cd0f9af0d40ec75470c344db741b010a41", "d48fcb07fec22946659a24aa0f88132e832775b366663c699150e828010fa3df"},
		core.InspectRecipientOperation: {"2440ed07e6620e07a884ff428d5525e68f60ba7efc8f06c59ff75e13f2ab61c1", "30181585db73db13a6dca51106b4b3f9260a41b9943cd5da3ff8c8512d87e66a"},
		core.ReceiptListOperation:      {"b6b17d94a4eaf0b609b6d162cb60dd7286d4cb50f1a0c7e3237c625b05c218ee", "a962afe31dc5d3fb85d6c5f0b5cd6e0b867ab28862ed7fc54839fb9b5d3678c2"},
		core.ReceiptDetailOperation:    {"2315ce07ecdf49ea45542bc0cbe12ccfb41065d9f6138dfdc46a3be2abb67015", "2665b81debcb0d83b7c9617d8779fc304a27e2e13e23df00ab7ad049ad80f084"},
	}
	parse := func(s string) (id contract.ID) {
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 32 {
			t.Fatal("bad independent vector")
		}
		copy(id[:], b)
		return id
	}
	vector := vectors[operation]
	digest, opID := parse(vector[0]), parse(vector[1])
	semantic := uint16(15)
	if strings.HasPrefix(operation, "receipt") {
		semantic = 16
	}
	observation := core.PublicObservation{DomainID: contract.ID{1}, HeadRevisionID: contract.ID{8}, SnapshotID: contract.ID{9}, RootDigest: contract.ID{10}}
	q := core.PublicQueryBasis{Schema: "QueryRequestIdentity/v1", Operation: operation, SemanticOperation: semantic, ExpectedDomain: contract.ID{1}, StoreID: contract.ID{2}, CoordinateID: contract.ID{3}, NonBodyID: contract.ID{4}, StoreDescriptorDigest: contract.ID{5}, PublicBasisDigest: contract.ID{6}, SourcePins: core.AdministrativeSourcePins{FileID: contract.ID{12}, Format: 1, EditableDigest: contract.ID{13}, EditableLength: 1, GeneratedDigest: contract.ID{14}, GeneratedLength: 2, HasGenerated: true}, RequestNonce: contract.ID{7}, Observation: &observation}
	r := core.PublicQueryResult{Operation: operation, RequestID: contract.ID{7}, OperationID: opID, RequestIdentity: digest, DomainID: contract.ID{1}, Result: core.Result{Outcome: core.ObservedCurrent, Evidence: core.AuthenticatedClosure, ObservedRevision: contract.ID{8}, ObservedSnapshotID: contract.ID{9}}, StateResult: core.PublicQuerySuccess}
	return r, q, digest
}
func publicQueryRendererDomain(t *testing.T) core.PublicDomainInspectionResult {
	t.Helper()
	r, q, digest := publicQueryRendererBasis(t, core.InspectOperation)
	config := contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: contract.ID{1}}
	image, err := contract.EncodeOutputConfiguration(config)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, _, err := contract.SplitOutputConfiguration(config.DomainID, image)
	if err != nil {
		t.Fatal(err)
	}
	view := &core.DomainInspection{Observation: *q.Observation, Output: core.InspectionOutput{Configuration: config, ConfigurationDescriptor: descriptor}}
	return core.PublicDomainInspectionResult{PublicQueryResult: r, Query: &core.DomainInspectionQueryIdentity{PublicQueryBasis: q, Digest: digest}, View: view}
}
func publicQueryRendererList(t *testing.T) core.PublicReceiptListResult {
	t.Helper()
	r, q, digest := publicQueryRendererBasis(t, core.ReceiptListOperation)
	rows := []core.ReceiptSummary{{OperationID: contract.ID{3}, OperationKind: 2, CanonicalOutcome: 1, StateResult: 1, ObservedRevisionID: contract.ID{20}, RequestedRevisionID: contract.ID{20}, WarningBits: 0, EvidenceCeiling: 1}, {OperationID: contract.ID{2}, OperationKind: 2, CanonicalOutcome: 2, StateResult: 11, ObservedRevisionID: contract.ID{18}, RequestedRevisionID: contract.ID{19}, WarningBits: 0, EvidenceCeiling: 2}, {OperationID: contract.ID{1}, OperationKind: 2, CanonicalOutcome: 1, StateResult: 1, ObservedRevisionID: contract.ID{17}, RequestedRevisionID: contract.ID{17}, WarningBits: 0, EvidenceCeiling: 1}}
	return core.PublicReceiptListResult{PublicQueryResult: r, Query: &core.ReceiptListQueryIdentity{PublicQueryBasis: q, Digest: digest}, Payload: &core.ReceiptListPayload{Observation: *q.Observation, CurrentDomainWarningBits: 4, CurrentWarnings: core.PublicDomainWarnings{PublicationOrderValue: true}, Receipts: rows}}
}
func publicQueryRendererDetail(t *testing.T) core.PublicReceiptDetailResult {
	t.Helper()
	r, q, digest := publicQueryRendererBasis(t, core.ReceiptDetailOperation)
	row := contract.CompactMutationReceipt{Schema: 3, OperationKind: 2, StateResult: 1, EffectSummary: 1, EvidenceCeiling: 1, DomainID: contract.ID{1}, OperationID: contract.ID{11}, RequestIdentityDigest: contract.ID{21}, PredecessorRevisionID: contract.ID{22}, RequestedRevisionID: contract.ID{23}, ObservedRevisionID: contract.ID{23}, CanonicalOutcome: 1, ChangedSubjects: contract.GeneratorDescriptor{Count: 0, Length: 4, Digest: contract.ID{24}}, CompleteResult: contract.GeneratorDescriptor{Count: 1, Length: 655, Digest: contract.ID{25}}}
	// Independent receipt scalar traversal: BE six u16s, six IDs, u8,
	// two (ID,u64 length,u32 count) descriptors, zero u64 warning bits,
	// twelve zero u32 counts, three zero u32 outcomes, then the 110-byte
	// absent administrative suffix. No receipt encoder supplies these bytes.
	body := []byte{}
	for _, n := range []uint16{3, 2, 1, 1, 0, 1} {
		body = binary.BigEndian.AppendUint16(body, n)
	}
	for _, id := range []contract.ID{{1}, {11}, {21}, {22}, {23}, {23}} {
		body = append(body, id[:]...)
	}
	body = append(body, 1)
	for _, d := range []contract.GeneratorDescriptor{row.ChangedSubjects, row.CompleteResult} {
		body = append(body, d.Digest[:]...)
		body = binary.BigEndian.AppendUint64(body, d.Length)
		body = binary.BigEndian.AppendUint32(body, d.Count)
	}
	body = append(body, make([]byte, 178)...)
	if len(body) != 471 {
		t.Fatal("independent receipt framing", len(body))
	}
	return core.PublicReceiptDetailResult{PublicQueryResult: r, Query: &core.ReceiptDetailQueryIdentity{PublicQueryBasis: q, RequestedOperationID: contract.ID{11}, Digest: digest}, Payload: &core.ReceiptDetailPayload{Observation: *q.Observation, Receipt: row, EncodedReceipt: body, Authenticity: "authenticated-retained", Retention: "retained"}}
}

// full_only: false
func TestPublicReceiptRenderingPreservesCompleteOrderAndExactHistoricalBytes(t *testing.T) {
	list := publicQueryRendererList(t)
	var machine, human bytes.Buffer
	if err := WriteReceiptListJSON(t.Context(), &machine, list); err != nil {
		t.Fatal(err)
	}
	if err := WriteReceiptListHuman(t.Context(), &human, list); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Payload struct {
			Form     string
			Receipts []struct {
				OperationID string `json:"operation_id"`
				State       uint16 `json:"state_result"`
				Warnings    uint64 `json:"warning_bits"`
			}
			Bits uint8 `json:"current_domain_warning_bits"`
		}
	}
	if err := json.Unmarshal(machine.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	want := []string{strings.Repeat("03", 1) + strings.Repeat("00", 31), strings.Repeat("02", 1) + strings.Repeat("00", 31), strings.Repeat("01", 1) + strings.Repeat("00", 31)}
	var got []string
	for _, row := range doc.Payload.Receipts {
		got = append(got, row.OperationID)
		if row.Warnings != 0 {
			t.Fatal("current warnings rewrote historical flags")
		}
	}
	if doc.Payload.Form != "list" || doc.Payload.Bits != 4 || !reflect.DeepEqual(got, want) || doc.Payload.Receipts[1].State != 11 {
		t.Fatal("ordered whole receipt set changed", doc)
	}
	if !strings.HasPrefix(human.String(), "Receipt list: success\n") || strings.Contains(human.String(), "ProductResult/v1") || strings.Contains(human.String(), "\nresult: ") {
		t.Fatal("human result did not use a command-specific view", human.String())
	}
	_, receiptRows, _ := strings.Cut(human.String(), "Receipts: 3 rows\n")
	last := -1
	for _, id := range want {
		at := strings.Index(receiptRows, id)
		if at <= last {
			t.Fatal("human result lost receipt order or identity", id)
		}
		last = at
	}
	for _, fact := range []string{"Receipts: 3 rows", "State result: effect-terminal-failure", "Evidence ceiling: provider-facts", "Current domain warning bits: 4"} {
		if !strings.Contains(human.String(), fact) {
			t.Fatal("human result lost a receipt fact", fact, human.String())
		}
	}
	detail := publicQueryRendererDetail(t)
	machine.Reset()
	if err := WriteReceiptDetailJSON(t.Context(), &machine, detail); err != nil {
		t.Fatal(err)
	}
	var exact struct {
		Payload struct {
			Encoded                 []byte `json:"encoded_receipt"`
			Receipt                 map[string]json.RawMessage
			Authenticity, Retention string
		}
	}
	if err := json.Unmarshal(machine.Bytes(), &exact); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(exact.Payload.Encoded, detail.Payload.EncodedReceipt) || len(exact.Payload.Encoded) != 471 || len(exact.Payload.Receipt) != 28 || exact.Payload.Authenticity != "authenticated-retained" || exact.Payload.Retention != "retained" {
		t.Fatal("exact receipt lost bytes or closed fields", len(exact.Payload.Receipt))
	}
}

// full_only: false
func TestPublicQueryPreflightRejectsClosedTupleAndLatePayloadDamageBeforeOutput(t *testing.T) {
	for _, damage := range []string{"outcome", "identity", "receipt-bytes", "receipt-state", "observation", "duplicate-row", "generated-last-row"} {
		t.Run(damage, func(t *testing.T) {
			var out bytes.Buffer
			var err error
			switch damage {
			case "receipt-bytes", "receipt-state":
				r := publicQueryRendererDetail(t)
				if damage == "receipt-bytes" {
					r.Payload.EncodedReceipt[470] ^= 1
				} else {
					r.Payload.Receipt.StateResult = 4
				}
				err = WriteReceiptDetailJSON(t.Context(), &out, r)
			case "generated-last-row":
				r := publicQueryRendererDomain(t)
				r.View.Generated.NextActions = []core.GeneratedNextAction{{Command: "unsafe"}}
				err = WriteInspectionJSON(t.Context(), &out, r)
			default:
				r := publicQueryRendererList(t)
				switch damage {
				case "outcome":
					r.Result.Outcome = core.EvidenceUnavailable
				case "identity":
					r.OperationID[0] ^= 1
				case "observation":
					r.Payload.Observation.RootDigest[0] ^= 1
				case "duplicate-row":
					r.Payload.Receipts[2] = r.Payload.Receipts[0]
				}
				err = WriteReceiptListJSON(t.Context(), &out, r)
			}
			if err == nil || out.Len() != 0 {
				t.Fatal("invalid result crossed output boundary", err, out.Len())
			}
		})
	}
}

// full_only: false
func TestPublicQueryPreAdmissionEnvelopeValidation(t *testing.T) {
	t.Run("direct-core-capacity-refusal", func(t *testing.T) {
		var reader *core.InstalledCapacityReader
		r := reader.InspectCapacity(t.Context(), core.CapacityInspectionRequest{RequestNonce: contract.ID{1}})
		if r.Validate() != nil || r.PreAdmission != nil || !r.OperationID.IsZero() || !r.RequestIdentity.IsZero() || r.Query != nil || r.View != nil {
			t.Fatal("actual direct Core refusal fixture changed")
		}
		for _, human := range []bool{false, true} {
			var out bytes.Buffer
			var err error
			if human {
				err = WriteCapacityInspectionHuman(t.Context(), &out, r)
			} else {
				err = WriteCapacityInspectionJSON(t.Context(), &out, r)
			}
			if err != nil {
				t.Errorf("valid direct Core refusal lost existing none fallback: human=%t error=%v", human, err)
				continue
			}
			body := out.Bytes()
			if human {
				if !bytes.HasPrefix(body, []byte("Capacity inspection: refused\n")) || !bytes.Contains(body, []byte("No query data is available.")) || bytes.Contains(body, []byte("Operation id:")) || bytes.Contains(body, []byte("Request identity:")) {
					t.Error("direct Core human refusal invented parser identity or payload", string(body))
				}
				continue
			}
			var record map[string]json.RawMessage
			if json.Unmarshal(body, &record) != nil || !bytes.Equal(record["request_identity"], []byte("null")) || !bytes.Equal(record["operation_id"], []byte("null")) || !bytes.Equal(record["payload"], []byte("null")) {
				t.Error("direct Core fallback invented parser identity or payload")
			}
		}
	})
	for _, damage := range []string{"stripped-local-metadata", "missing-local-id", "nonce", "source-schema", "source-profile", "format", "stage", "code", "code-mismatch", "local-and-bound-identity", "bound-query-overlay"} {
		t.Run(damage, func(t *testing.T) {
			r, err := NewDomainInspectionRefusal(configuration.JSON)
			if err != nil {
				t.Fatal(err)
			}
			if r.PreAdmission == nil || r.OperationID.IsZero() {
				t.Fatal("Full local identity fixture absent")
			}
			q := *r.PreAdmission
			r.PreAdmission = &q
			switch damage {
			case "stripped-local-metadata":
				r.PreAdmission = nil
			case "missing-local-id":
				r.OperationID = contract.ID{}
			case "nonce":
				q.RequestNonce = contract.ID{4}
			case "source-schema":
				q.SourceSchema = "unsupported"
			case "source-profile":
				q.SourceProfile = "unsupported"
			case "format":
				q.Format = "xml"
			case "stage":
				q.Stage = "unreviewed-stage"
			case "code":
				q.Code = "unreviewed-code"
			case "code-mismatch":
				q.Code = string(contract.ReasonEvidenceUnavailable)
			case "local-and-bound-identity":
				r.RequestIdentity = contract.ID{5}
			case "bound-query-overlay":
				r = publicQueryRendererDomain(t)
				q.RequestNonce = r.RequestID
				r.PreAdmission = &q
			}
			var out bytes.Buffer
			if WriteInspectionJSON(t.Context(), &out, r) == nil || out.Len() != 0 {
				t.Fatal("malformed local/bound metadata crossed shared preflight", damage)
			}
		})
	}
}

type publicQueryDeliveryWriter struct {
	cancel context.CancelFunc
	n      int
	short  bool
	fail   error
}

func (w *publicQueryDeliveryWriter) Write(b []byte) (int, error) {
	w.n += len(b)
	if w.cancel != nil && w.n > 100 {
		w.cancel()
	}
	if w.fail != nil && w.n > 100 {
		return 0, w.fail
	}
	if w.short && len(b) > 1 {
		return len(b) - 1, nil
	}
	return len(b), nil
}

// full_only: false
func TestPublicQueryStreamingPropagatesCancellationShortWriteAndWriterFailure(t *testing.T) {
	r := publicQueryRendererList(t)
	for _, kind := range []string{"cancel-before", "cancel-during", "short", "error"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			w := &publicQueryDeliveryWriter{}
			want := io.ErrShortWrite
			switch kind {
			case "cancel-before":
				cancel()
				want = context.Canceled
			case "cancel-during":
				w.cancel = cancel
				want = context.Canceled
			case "short":
				w.short = true
			case "error":
				want = errors.New("writer unavailable")
				w.fail = want
			}
			if err := WriteReceiptListJSON(ctx, w, r); !errors.Is(err, want) {
				t.Fatal("delivery failure lost", err, want)
			}
			if kind == "cancel-before" && w.n != 0 {
				t.Fatal("canceled preflight wrote bytes")
			}
		})
	}
}

// full_only: true
// Proves all 65,535 administrative group positions and compact u16 relations.
func TestPublicInspectionStreamsMaximumCompactGroupTable(t *testing.T) {
	r := publicQueryRendererDomain(t)
	const count = 65535
	r.View.Work.Groups = make([]format.AdministrativeGroup, count)
	r.View.Work.GroupSelections = make([]core.InspectionGroupSelection, count)
	for i := range count {
		id := contract.ID{1}
		binary.BigEndian.PutUint32(id[28:], uint32(i+1))
		g := format.AdministrativeGroup{GroupID: id, OwnerID: contract.ID{2}, TargetID: contract.ID{3}, OwnerKind: contract.AdministrativeGeneratedDuty, DutyKind: contract.GeneratedDutyCreate, SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing}
		if i > 0 {
			g.RelatedGroupIndexes = []uint16{uint16(i - 1)}
		}
		g.Affected = contract.GeneratorDescriptor{Digest: contract.ID{2}, Length: 4}
		g.Dependencies = g.Affected
		g.Disposable = g.Affected
		r.View.Work.Groups[i] = g
		r.View.Work.GroupSelections[i].Selectable = true
	}
	r.View.Work.Groups[count-1].RelatedGroupIndexes = make([]uint16, count-1)
	for i := range r.View.Work.Groups[count-1].RelatedGroupIndexes {
		r.View.Work.Groups[count-1].RelatedGroupIndexes[i] = uint16(i)
	}
	var sink administrativeCountingSink
	var captured bytes.Buffer
	if err := WriteInspectionJSON(t.Context(), io.MultiWriter(&sink, &captured), r); err != nil {
		t.Fatal(err)
	}
	if sink.bytes != uint64(captured.Len()) || sink.bytes > 67*publicQueryCompactOutputLimit || sink.largest > 8192 {
		t.Fatal("maximum compact table changed its streamed writes or output account", sink, captured.Len())
	}
	var doc struct {
		Schema    string
		Operation string `json:"operation_kind"`
		State     string `json:"state_result"`
		Payload   struct {
			Schema, Form string
			Work         struct {
				Groups           []json.RawMessage
				Pages            []json.RawMessage
				PublicationOrder []json.RawMessage `json:"publication_order"`
			}
		}
	}
	if err := json.Unmarshal(captured.Bytes(), &doc); err != nil {
		t.Fatal("complete maximum-group JSON", err)
	}
	if doc.Schema != "ProductResult/v1" || doc.Operation != "inspect" || doc.State != "success" || doc.Payload.Schema != "InspectionPayload/v1" || doc.Payload.Form != "domain" || len(doc.Payload.Work.Groups) != count || len(doc.Payload.Work.Pages) != 0 || len(doc.Payload.Work.PublicationOrder) != 0 {
		t.Fatal("maximum group table or owning result changed", doc.Schema, doc.Operation, doc.State, doc.Payload.Form, len(doc.Payload.Work.Groups))
	}
	type descriptor struct {
		Count  *uint32
		Length uint64
		Digest string
	}
	type group struct {
		GroupID                            string `json:"group_id"`
		OwnerID                            string `json:"owner_id"`
		TargetID                           string `json:"target_id"`
		OwnerKind                          uint8  `json:"owner_kind"`
		DutyKind                           uint8  `json:"duty_kind"`
		EffectEntryCeiling                 *uint8 `json:"effect_entry_ceiling"`
		SelectedEvidenceSummary            uint16 `json:"selected_evidence_summary"`
		DestructiveEffect                  *bool  `json:"destructive_effect"`
		UncertainCreateProof               *bool  `json:"uncertain_create_proof"`
		Affected, Dependencies, Disposable descriptor
		ChargedPages                       *uint16  `json:"charged_pages"`
		ChargedBytes                       *uint64  `json:"charged_bytes"`
		RelatedGroupIndexes                []uint16 `json:"related_group_indexes"`
		PublicationIncarnationID           string   `json:"publication_incarnation_id"`
		AdmissionOrdinal                   *uint64  `json:"admission_ordinal"`
		Selectable                         bool
		RequiredParentIndex                *uint16 `json:"required_parent_index"`
	}
	ownerID := "02" + strings.Repeat("00", 31)
	targetID := "03" + strings.Repeat("00", 31)
	validDescriptor := func(d descriptor) bool {
		return d.Count != nil && *d.Count == 0 && d.Length == 4 && d.Digest == ownerID
	}
	var relationships int
	for i, encoded := range doc.Payload.Work.Groups {
		var row group
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&row); err != nil {
			t.Fatal("closed maximum group row", i, err)
		}
		wantID := fmt.Sprintf("01%s%08x", strings.Repeat("00", 27), i+1)
		if row.GroupID != wantID || row.OwnerID != ownerID || row.TargetID != targetID || row.OwnerKind != 2 || row.DutyKind != 1 || row.SelectedEvidenceSummary != 1 || row.PublicationIncarnationID != strings.Repeat("00", 32) || !row.Selectable || row.RequiredParentIndex != nil {
			t.Fatal("group identity, order, owner or selector changed", i)
		}
		if row.EffectEntryCeiling == nil || row.DestructiveEffect == nil || row.UncertainCreateProof == nil || row.ChargedPages == nil || row.ChargedBytes == nil || row.AdmissionOrdinal == nil {
			t.Fatal("required zero-valued group fact omitted", i)
		}
		if *row.EffectEntryCeiling != 0 || *row.DestructiveEffect || *row.UncertainCreateProof || *row.ChargedPages != 0 || *row.ChargedBytes != 0 || *row.AdmissionOrdinal != 0 || !validDescriptor(row.Affected) || !validDescriptor(row.Dependencies) || !validDescriptor(row.Disposable) {
			t.Fatal("group scalar or descriptor changed", i)
		}
		wantCount := 0
		if i > 0 {
			wantCount = 1
		}
		if i == count-1 {
			wantCount = count - 1
		}
		if row.RelatedGroupIndexes == nil || len(row.RelatedGroupIndexes) != wantCount {
			t.Fatal("compact relation vector omitted or truncated", i, len(row.RelatedGroupIndexes), wantCount)
		}
		for j, index := range row.RelatedGroupIndexes {
			want := uint16(i - 1)
			if i == count-1 {
				want = uint16(j)
			}
			if index != want {
				t.Fatal("compact relation index changed", i, j, index, want)
			}
		}
		relationships += len(row.RelatedGroupIndexes)
	}
	if relationships != 2*count-3 {
		t.Fatal("whole compact relation set changed", relationships)
	}
}

// full_only: false
func TestPublicReceiptHumanWarningsUseEachOriginalOperationEncoding(t *testing.T) {
	for _, cell := range []struct {
		name                       string
		operation, state, evidence uint16
		bits                       uint64
		want, absent               []string
	}{
		{name: "ordinary-domain-garbage", operation: contract.OperationApplyDeclaration, state: contract.ReceiptStateSuccess, evidence: 1, bits: 64, want: []string{"Immutable store garbage can remain."}, absent: []string{"invalidation is not confirmed", "old effect can still be live"}},
		{name: "administrative-domain-destructive", operation: contract.OperationEndSelectedWork, state: contract.ReceiptStateWorkEnded, evidence: 1, bits: 2, want: []string{"An old destructive request can act"}, absent: []string{"invalidation is not confirmed"}},
		{name: "ordinary-effect-acknowledgement", operation: contract.OperationApplyDeclaration, state: contract.ReceiptStateSuccess, evidence: 3, bits: 2, want: []string{"Deletion was acknowledged; invalidation is not confirmed."}, absent: []string{"An old destructive request can act"}},
		{name: "ordinary-all-domain-flags", operation: contract.OperationApplyDeclaration, state: contract.ReceiptStateSuccess, evidence: 1, bits: 124, want: []string{"The old effect can still be live.", "An old destructive request can act", "Publication acknowledgement does not prove current remote order or value.", "Discarded exact evidence cannot be recovered", "Immutable store garbage can remain."}, absent: []string{"Deletion was acknowledged; invalidation is not confirmed."}},
		{name: "initialization-zero", operation: contract.OperationInitializeDomain, state: contract.ReceiptStateSuccess, evidence: 1, bits: 0, absent: []string{"Warning:"}},
	} {
		t.Run(cell.name, func(t *testing.T) {
			r := publicQueryRendererList(t)
			r.Payload.CurrentDomainWarningBits = 0
			r.Payload.CurrentWarnings = core.PublicDomainWarnings{}
			row := r.Payload.Receipts[0]
			row.OperationKind, row.StateResult, row.EvidenceCeiling, row.WarningBits = cell.operation, cell.state, cell.evidence, cell.bits
			r.Payload.Receipts = []core.ReceiptSummary{row}
			var out bytes.Buffer
			if err := WriteReceiptListHuman(t.Context(), &out, r); err != nil {
				t.Fatal(err)
			}
			for _, want := range cell.want {
				if !strings.Contains(out.String(), want) {
					t.Fatal("historical warning meaning omitted", want, out.String())
				}
			}
			for _, absent := range cell.absent {
				if strings.Contains(out.String(), absent) {
					t.Fatal("historical warning acquired another operation meaning", absent)
				}
			}
		})
	}
}

// full_only: false
func TestStreamedResultLimitErrorsKeepOwningResultContract(t *testing.T) {
	for _, cell := range []struct {
		name             string
		limitError, want error
	}{{"administrative", nil, ErrAbandonmentResult}, {"public-query", ErrPublicQueryResult, ErrPublicQueryResult}} {
		t.Run(cell.name, func(t *testing.T) {
			var out bytes.Buffer
			w := &resultStreamWriter{ctx: t.Context(), out: &out, limit: 1, limitError: cell.limitError}
			w.text("xx")
			if !errors.Is(w.err, cell.want) || out.Len() != 0 {
				t.Fatal("owned overflow error or before-write boundary changed", w.err, out.Len())
			}
		})
	}
	failure := &publicQueryDeliveryWriter{fail: ErrAbandonmentResult, n: 101}
	w := &resultStreamWriter{ctx: t.Context(), out: failure, limit: 100, limitError: ErrPublicQueryResult}
	w.text("x")
	if w.err != ErrAbandonmentResult {
		t.Fatal("caller writer error was relabeled", w.err)
	}
}

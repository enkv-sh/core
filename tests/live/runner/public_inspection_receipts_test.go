package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

// These are public expected facts, not prior query output. The final observer
// receives them only after the writer and all its executable children exit.
type publicInspectionFacts struct {
	Domain, Recipient, Revision, Snapshot, RootDigest string
	DomainPayload, RecipientPayload, ListPayload      json.RawMessage
	Details                                           []publicInspectionDetail
}

type publicInspectionDetail struct {
	Operation string
	Payload   json.RawMessage
}

func runPublicInspectionReceipts(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string, initialized publicProductResult) *publicInspectionFacts {
	t.Helper()
	if input.Participants["reader"] == input.Participants["authority"] || input.Participants["reader"] == input.Participants["apply"] || input.Participants["reader"] == input.Participants["cleanup"] {
		t.Fatal("inspection requires its independently selected Reader")
	}
	// Reuse the supplied fixture recipe: one shared secret and one Authority-only
	// plain value. The latter establishes actual exclusion in the scoped form.
	secret := []byte{'l', 'i', 'v', 'e', '-', 'i', 'n', 's', 'p', 'e', 'c', 't', 0, 255, 128}
	defer clear(secret)
	plain := []byte{'p', 'l', 'a', 'i', 'n', 0, 255}
	document := publicSourceDocument(t, source)
	document["entries"] = map[string]any{
		"local-plain": map[string]any{"confidentiality": "plain", "recipients": []string{}, "source": map[string]any{"kind": "supplied", "bytes": base64.StdEncoding.EncodeToString(plain)}},
		"secret":      map[string]any{"confidentiality": "secret", "recipients": []string{"consumer"}, "source": map[string]any{"kind": "supplied"}},
	}
	publicWriteSource(t, source, document)
	set := publicCLI(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{NoKMS: true}, secret,
		"set", "--source", source, "--source-format", "json", "--name", "secret", "--json")
	publicAssertSet(t, set, source, "secret")
	clear(set.Body)
	image := publicSourceImage(t, source)
	applied := publicCLI(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{}, nil, "apply", "--source", source, "--source-format", "json", "--json")
	defer clear(applied.Body)
	product := publicProduct(t, applied, "apply-declaration")
	if !publicApplyMatches(applied, product, "success") {
		t.Fatal("inspection fixture public apply did not select its two supplied entries")
	}
	publicImageUnchanged(t, image)
	publicAssertNoRecovery(t, applied.Capture)
	// This is a separate public GET path. It supplies raw selected facts for the
	// oracle; no inspection projection or query renderer prepares expectations.
	basis, descriptor := publicOperatorGenesis(t, source)
	store, err := openPublicReaderStore(ctx, input, descriptor.DomainID, inv.StateDir)
	if err != nil {
		t.Fatal("inspection independent public Store unavailable")
	}
	selected := publicOperatorOpen(t, ctx, descriptor.DomainID, basis, recordedStore{Store: store, budget: budget})
	facts := publicInspectionExpected(t, selected, descriptor, initialized, product, secret, plain)
	publicPlanningSafe(t, applied, applied.Body, secret)
	return facts
}

func publicInspectionJSON(t testing.TB, value any) json.RawMessage {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal("inspection expected public facts cannot be encoded")
	}
	return body
}

func publicInspectionExpected(t testing.TB, selected *StateSession, descriptor contract.GenesisDescriptorCore, initialized, applied publicProductResult, secret, plain []byte) *publicInspectionFacts {
	t.Helper()
	id := func(v contract.ID) string { return hex.EncodeToString(v[:]) }
	empty := []any{}
	observation := map[string]any{"domain_id": id(selected.root.Domain), "head_revision_id": id(selected.head.Core.Revision), "snapshot_id": id(selected.root.Snapshot), "root_digest": id(selected.head.Core.Root.Digest)}
	domainWarnings := map[string]any{"orphan_generated_effect": false, "late_destructive_effect": false, "publication_order_value": false, "discarded_exact_evidence": false, "possible_store_garbage": false}
	outputWarnings := map[string]any{"domain_wide_warning": false, "unresolved_publication": false, "late_write_risk": false}
	var recipient contract.ID
	recipients := make([]any, 0, len(descriptor.Recipients))
	for _, row := range descriptor.Recipients {
		if row.RecipientID != descriptor.AuthorityRecipientID {
			recipient = row.RecipientID
		}
		if row.CurrentBinding == nil || row.Status != contract.CurrentRecipient {
			t.Fatal("inspection fixture did not enroll two current public bindings")
		}
		b := row.CurrentBinding
		recipients = append(recipients, map[string]any{"recipient_id": id(row.RecipientID), "status": row.Status, "display_name": row.DisplayName, "binding_id": id(b.BindingID), "binding_serial": b.BindingSerial, "binding_fingerprint": id(b.Fingerprint)})
	}
	slices.SortFunc(recipients, func(a, b any) int {
		return bytes.Compare([]byte(a.(map[string]any)["recipient_id"].(string)), []byte(b.(map[string]any)["recipient_id"].(string)))
	})
	if recipient.IsZero() || len(recipients) != 2 || selected.root.Domain != descriptor.DomainID || selected.root.ValueEntryCount != 2 || selected.root.SecretCount != 1 || selected.root.RecipientCount != 2 || selected.root.WarningBits != 0 || len(selected.adminIndex.Groups) != 0 || len(selected.adminIndex.PublicationOrder) != 0 || len(selected.root.Names) != 2 {
		t.Fatal("inspection fixture exceeds its bounded two-entry selection")
	}
	entries, scoped := make([]any, 0, 2), make([]any, 0, 1)
	for i, named := range selected.root.Names {
		entry := selected.valueEntry(named.Slot)
		name, raw, confidential := "local-plain", uint32(len(plain)), false
		members := []contract.ID{descriptor.AuthorityRecipientID}
		if i == 1 {
			name, raw, confidential = "secret", uint32(len(secret)), true
			members = append(members, recipient)
			slices.SortFunc(members, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		}
		if entry == nil || named.Name != name || entry.Name != name || entry.ValueSource != contract.Supplied || entry.InputEncoding != contract.InputEncodingRaw || entry.OutputEncoding != contract.OutputEncodingRaw || entry.ContentLength != raw || entry.RetainedLength != raw || (entry.ConfidentialityClass == contract.Secret) != confidential || !slices.Equal(entry.Recipients, members) || !confidential && !bytes.Equal(entry.ValueBytes, plain) {
			t.Fatal("inspection fixture differs from its literal supplied declaration")
		}
		if confidential {
			payload, err := contract.InspectCanonicalPayload(entry.ValueBytes)
			if err != nil || payload.InputEncoding != contract.InputEncodingRaw || payload.ContentLength != raw || payload.RetainedLength != raw {
				t.Fatal("inspection secret metadata differs from literal supplied bytes")
			}
		}
		row := map[string]any{"name": name, "incarnation_id": id(entry.Incarnation), "value_state_id": id(entry.ValueState), "value_source": uint8(contract.Supplied), "confidential": confidential, "raw_length": raw}
		if confidential {
			scoped = append(scoped, row)
		}
		domainRow := make(map[string]any, len(row)+2)
		for key, value := range row {
			domainRow[key] = value
		}
		ids := make([]string, len(members))
		for i, member := range members {
			ids[i] = id(member)
		}
		domainRow["slot"], domainRow["recipient_ids"] = named.Slot, ids
		entries = append(entries, domainRow)
	}
	// Pages are authenticated index facts, including all receipt row summaries.
	// This fixture creates no administrative groups or publication order.
	pages := make([]any, 0, len(selected.adminIndex.Pages))
	for _, page := range selected.adminIndex.Pages {
		spans, rows := make([]any, 0, len(page.Spans)), make([]any, 0, len(page.Rows))
		for _, span := range page.Spans {
			indexes := make([]uint16, len(span.GroupIndexes))
			copy(indexes, span.GroupIndexes)
			spans = append(spans, map[string]any{"first": span.First, "count": span.Count, "mandatory": span.Mandatory, "group_indexes": indexes})
		}
		for _, row := range page.Rows {
			fact := map[string]any{"kind": row.Kind, "record_id": id(row.RecordID), "body_length": row.BodyLength}
			if !row.MaterialID.IsZero() {
				fact["material_id"] = id(row.MaterialID)
			}
			rows = append(rows, fact)
		}
		r := page.Ref
		pages = append(pages, map[string]any{"ref": map[string]any{"kind": r.Kind, "domain_id": id(r.Domain), "object_id": id(r.Object), "digest": id(r.Digest), "format": r.Format, "length": r.Length, "index": r.Index}, "read_required": page.ReadRequired, "spans": spans, "rows": rows})
	}
	d := selected.root.OutputConfiguration
	domain := map[string]any{
		"schema": "InspectionPayload/v1", "form": "domain", "observation": observation, "entries": entries, "recipients": recipients, "active_operation": nil,
		"generated":           map[string]any{"current_generations": empty, "effects": empty, "duties": empty, "hazards": empty, "pending_releases": empty, "next_actions": empty},
		"work":                map[string]any{"groups": empty, "pages": pages, "publication_order": empty},
		"output":              map[string]any{"configuration_descriptor": map[string]any{"schema": d.Schema, "configuration_digest": id(d.ConfigurationDigest), "total_length": d.TotalLength, "slice_count": d.SliceCount, "binding_count": d.BindingCount, "routing_length": d.RoutingLength}, "configuration": map[string]any{"schema": uint16(contract.OutputConfigurationSchema), "domain_id": id(selected.root.Domain), "bindings": empty, "default_destinations": empty, "routes": empty, "groups": empty}, "current_targets": empty, "coordinates": empty, "markers": empty, "current_blockers": empty, "warnings": outputWarnings},
		"domain_warning_bits": uint8(0), "warnings": map[string]any{"domain": domainWarnings, "generated": map[string]any{"possible_live_residue": false, "late_effect": false, "invalidation_not_confirmed": false}, "output": outputWarnings, "possible_store_garbage": false},
	}
	facts := &publicInspectionFacts{Domain: id(selected.root.Domain), Recipient: id(recipient), Revision: id(selected.head.Core.Revision), Snapshot: id(selected.root.Snapshot), RootDigest: id(selected.head.Core.Root.Digest), DomainPayload: publicInspectionJSON(t, domain), RecipientPayload: publicInspectionJSON(t, map[string]any{"schema": "InspectionPayload/v1", "form": "recipient", "observation": observation, "recipient_id": id(recipient), "entries": scoped})}
	list := make([]any, 0, 2)
	// The independently known selection sequence is init, then one changed apply.
	// Original bytes come from those terminal replies, never from query detail.
	for i, product := range []publicProductResult{applied, initialized} {
		body, err := hex.DecodeString(product.Receipt)
		receipt, decodeErr := contract.InspectCompactMutationReceipt(body)
		kind := uint16(contract.OperationApplyDeclaration)
		if i == 1 {
			kind = contract.OperationInitializeDomain
		}
		if err != nil || decodeErr != nil || len(body) != 471 || receipt.OperationKind != kind || receipt.DomainID != selected.root.Domain || receipt.StateResult != contract.ReceiptStateSuccess || receipt.CanonicalOutcome != contract.ReceiptCanonicalSelected || receipt.WarningBits != 0 || i == 0 && receipt.ObservedRevisionID != selected.head.Core.Revision || i == 1 && receipt.ObservedRevisionID == selected.head.Core.Revision {
			t.Fatal("inspection fixture original terminal receipt facts differ")
		}
		_, stored, found, err := selected.retainedMutationReceipt(receipt.OperationID)
		if err != nil || !found || !bytes.Equal(stored, body) {
			t.Fatal("selected receipt differs from its original terminal result")
		}
		list = append(list, map[string]any{"operation_id": id(receipt.OperationID), "operation_kind": receipt.OperationKind, "canonical_outcome": receipt.CanonicalOutcome, "state_result": receipt.StateResult, "observed_revision_id": id(receipt.ObservedRevisionID), "requested_revision_id": id(receipt.RequestedRevisionID), "warning_bits": receipt.WarningBits, "evidence_ceiling": receipt.EvidenceCeiling})
		detail := map[string]any{"schema": "ReceiptPayload/v1", "form": "detail", "observation": observation, "current_domain_warning_bits": uint8(0), "current_warnings": domainWarnings, "receipt": publicInspectionReceiptFields(receipt), "encoded_receipt": body, "authenticity": "authenticated-retained", "retention": "retained"}
		facts.Details = append(facts.Details, publicInspectionDetail{Operation: id(receipt.OperationID), Payload: publicInspectionJSON(t, detail)})
	}
	facts.ListPayload = publicInspectionJSON(t, map[string]any{"schema": "ReceiptPayload/v1", "form": "list", "observation": observation, "current_domain_warning_bits": uint8(0), "current_warnings": domainWarnings, "receipts": list})
	return facts
}

func publicInspectionReceiptFields(r contract.CompactMutationReceipt) map[string]any {
	id := func(v contract.ID) string { return hex.EncodeToString(v[:]) }
	descriptor := func(d contract.GeneratorDescriptor) any {
		return map[string]any{"count": d.Count, "length": d.Length, "digest": id(d.Digest)}
	}
	return map[string]any{"schema": r.Schema, "operation_kind": r.OperationKind, "state_result": r.StateResult, "effect_summary": r.EffectSummary, "output_summary": r.OutputSummary, "evidence_ceiling": r.EvidenceCeiling, "domain_id": id(r.DomainID), "operation_id": id(r.OperationID), "request_identity_digest": id(r.RequestIdentityDigest), "predecessor_revision_id": id(r.PredecessorRevisionID), "requested_revision_id": id(r.RequestedRevisionID), "observed_revision_id": id(r.ObservedRevisionID), "canonical_outcome": r.CanonicalOutcome, "changed_subjects": descriptor(r.ChangedSubjects), "complete_result": descriptor(r.CompleteResult), "warning_bits": r.WarningBits, "summary_counts": r.SummaryCounts, "acknowledged_count": r.AcknowledgedCount, "confirmed_count": r.ConfirmedCount, "unknown_count": r.UnknownCount, "administrative_target_kind": r.AdministrativeTargetKind, "administrative_warning_changes": r.AdministrativeWarningChanges, "administrative_target_id": id(r.AdministrativeTargetID), "administrative_disposition": id(r.AdministrativeDisposition), "administrative_original_evidence": r.AdministrativeOriginalEvidence, "administrative_page_delta": r.AdministrativePageDelta, "administrative_byte_delta": r.AdministrativeByteDelta, "administrative_group_id": id(r.AdministrativeGroupID)}
}

func publicInspectionReceiptsFresh(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string, facts publicInspectionFacts) {
	t.Helper()
	head := publicIndependentHEAD(t, ctx, input, budget, source, inv.StateDir)
	if facts.Domain != hex.EncodeToString(head.Core.Domain[:]) || facts.Revision != hex.EncodeToString(head.Core.Revision[:]) || facts.Snapshot != hex.EncodeToString(head.Core.Root.Object[:]) || facts.RootDigest != hex.EncodeToString(head.Core.Root.Digest[:]) || len(facts.Details) != 2 {
		t.Fatal("inspection Reader independent current selection differs")
	}
	run := func(command, operation, schema string, expected json.RawMessage, extra ...string) {
		child := publicLifecycleReadOnly(t, source, func() publicChildResult {
			args := []string{command, "--source", source, "--source-format", "json", "--json"}
			return publicCLI(t, ctx, inv, input, budget, "reader", false, nativeprocess.Policy{NoKMS: true}, nil, append(args, extra...)...)
		})
		defer clear(child.Body)
		failure := publicInspectionFailure(child, operation, schema, facts.Domain, facts.Revision, expected)
		// The failure owner retains source and line, not assertion text. Separate
		// fixed call sites retain the closed class without retaining child output.
		switch failure {
		case "":
		case "capture":
			t.Fatal("inspection GET-only capture failed")
		case "exit":
			t.Fatal("inspection child exit or diagnostic failed")
		case "envelope":
			t.Fatal("inspection result envelope failed")
		case "schema":
			t.Fatal("inspection result schema failed")
		case "payload":
			t.Fatal("inspection result payload failed")
		default:
			t.Fatal("inspection failure class unavailable")
		}
	}
	run("inspect", InspectOperation, "InspectionPayload/v1", facts.DomainPayload)
	run("inspect", InspectRecipientOperation, "InspectionPayload/v1", facts.RecipientPayload, "--recipient-id", facts.Recipient)
	run("receipt", ReceiptListOperation, "ReceiptPayload/v1", facts.ListPayload)
	for _, detail := range facts.Details {
		run("receipt", ReceiptDetailOperation, "ReceiptPayload/v1", detail.Payload, "--operation", detail.Operation)
	}
	after := publicIndependentHEAD(t, ctx, input, budget, source, inv.StateDir)
	if !reflect.DeepEqual(head, after) {
		t.Fatal("public inspection changed the independently selected HEAD")
	}
}

func publicInspectionReadCapture(capture nativeprocess.Capture) bool {
	reads, footer := 0, false
	for _, event := range capture.Events {
		if footer {
			return false
		}
		switch event.Kind {
		case "source-kind":
			if !event.Matched || event.Count != 1 {
				return false
			}
		case "http-start", "http-return":
			if event.Operation != "head-read" && event.Operation != "store-read" {
				return false
			}
			if event.Kind == "http-return" && event.Sent && event.Status >= 200 && event.Status < 300 {
				reads++
			}
		case "footer":
			footer = event.Code == 0
		default:
			return false
		}
	}
	// publicCLI's existing capture parser requires paired requests and a normal
	// joined child footer. This assertion adds the precise capability ceiling.
	return reads > 0 && footer
}

func publicInspectionFailure(child publicChildResult, operation, schema, domain, revision string, expected json.RawMessage) string {
	if !publicInspectionReadCapture(child.Capture) {
		return "capture"
	}
	return publicInspectionPayloadFailure(child, operation, schema, domain, revision, expected)
}

func publicInspectionPayloadMatches(child publicChildResult, operation, schema, domain, revision string, expected json.RawMessage) bool {
	return publicInspectionPayloadFailure(child, operation, schema, domain, revision, expected) == ""
}

// publicInspectionPayloadFailure returns only a closed failure class. It never
// retains the command output or changes the complete expected-facts check.
func publicInspectionPayloadFailure(child publicChildResult, operation, schema, domain, revision string, expected json.RawMessage) string {
	if child.Code != 0 || child.DiagnosticBytes != 0 {
		return "exit"
	}
	decode := func(body []byte, out any) bool {
		d := json.NewDecoder(bytes.NewReader(body))
		d.UseNumber()
		return d.Decode(out) == nil && d.Decode(new(any)) == io.EOF
	}
	var actual, want map[string]any
	var payload any
	if !decode(child.Body, &actual) || !decode(expected, &payload) {
		return "envelope"
	}
	// Nonces and query digests vary by command. Validate their complete syntax;
	// all semantic fields and the exact payload come from independent facts.
	for _, key := range []string{"request_id", "operation_id", "request_identity"} {
		value, ok := actual[key].(string)
		body, err := hex.DecodeString(value)
		if !ok || err != nil || len(body) != 32 || value != hex.EncodeToString(body) || bytes.Equal(body, make([]byte, 32)) {
			return "envelope"
		}
	}
	wantBody, err := json.Marshal(map[string]any{"schema": "ProductResult/v1", "operation_kind": operation, "state_result": "success", "effect_summary": "not-applicable", "output_summary": "not-applicable", "request_id": actual["request_id"], "operation_id": actual["operation_id"], "request_identity": actual["request_identity"], "replay_identity": "none", "domain_id": domain, "failure_reason": "", "result": map[string]any{"outcome": "observed_current", "reason": "none", "observed_revision": revision, "commit_may_have_occurred": false}, "evidence_ceiling": "canonical", "effects": []any{}, "outputs": []any{}, "duties": []any{}, "hazards": []any{}, "capsule_policy": "none", "operation_payload": schema, "payload": payload})
	if err != nil || !decode(wantBody, &want) {
		return "envelope"
	}
	actualPayload, present := actual["payload"]
	if actual["operation_payload"] != schema {
		return "schema"
	}
	if actualObject, ok := actualPayload.(map[string]any); ok {
		if expectedObject, ok := payload.(map[string]any); ok && !reflect.DeepEqual(actualObject["schema"], expectedObject["schema"]) {
			return "schema"
		}
	}
	delete(actual, "payload")
	delete(want, "payload")
	if !reflect.DeepEqual(actual, want) {
		return "envelope"
	}
	if !present || !reflect.DeepEqual(actualPayload, payload) {
		return "payload"
	}
	return ""
}

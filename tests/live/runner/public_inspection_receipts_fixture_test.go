package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestPublicInspectionReceiptExpectedFactsMatchInstalledQueries(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, keys := genesisEnvironment(t, contract.GCP, true)
	installation, _ := publicInitializationInstallation(t, env, keys)
	initializer, err := NewInstalledInitializer(initializationAllocationForDescriptor(t, installation.Descriptor), installation)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(initializer.Close)
	ready := initializer.Initialize(ctx)
	if ready.StateResult != contract.InitializationSuccess || ready.PublicBasis == nil || len(ready.Receipt) != 471 {
		t.Fatal("authentic initialization receipt unavailable", ready.Result)
	}
	admitted, result := admitPublicNormal(ctx, env.Domain, env.Store.Descriptor(), *ready.PublicBasis, env.Store, installation.CompositionID, nil)
	if result.Outcome != ObservedCurrent {
		t.Fatal(result)
	}
	selected, result := Open(ctx, admitted, env.Store)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal(result)
	}
	f := installedApplyTestFixture{env: env, keys: keys, basis: *ready.PublicBasis, composition: installation.CompositionID, admitted: admitted, selected: selected}
	authority, recipient := selected.admission.recipient, fixtureID(env.Domain, "reader")
	plain := []byte{'p', 'l', 'a', 'i', 'n', 0, 255}
	// This literal is the existing custody.StandardValue recipe, not a value
	// recovered from inspection or from the selected ciphertext.
	secret := []byte("enkv first secret test value")
	input := []ApplyEntryInput{
		{Name: "local-plain", Recipients: []contract.ID{authority}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: plain},
		suppliedSecret(t, env, "secret", "inspection builder secret source", custody.StandardValue, authority, recipient),
	}
	engine := f.engine(t, selected, input, nil)
	applied := engine.Apply(ctx, fixtureID(env.Domain, "inspection builder apply"), input)
	engine.Close()
	if applied.Result.Outcome != ObservedCurrent || len(applied.Receipt) != 471 {
		t.Fatal("authentic apply receipt unavailable", applied.Result)
	}
	f.selected = f.open(t, ctx)
	descriptor, err := contract.DecodeGenesisDescriptorCore(f.basis.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	facts := publicInspectionExpected(t, f.selected, descriptor,
		publicProductResult{Receipt: hex.EncodeToString(ready.Receipt)}, publicProductResult{Receipt: hex.EncodeToString(applied.Receipt)}, secret, plain)
	id := func(v contract.ID) string { return hex.EncodeToString(v[:]) }
	decode := func(body []byte) map[string]json.RawMessage {
		t.Helper()
		var fields map[string]json.RawMessage
		if json.Unmarshal(body, &fields) != nil {
			t.Fatal("builder returned malformed public facts")
		}
		return fields
	}
	assertJSON := func(expected json.RawMessage, actual any) {
		t.Helper()
		var a, b any
		d := json.NewDecoder(bytes.NewReader(expected))
		d.UseNumber()
		if d.Decode(&a) != nil {
			t.Fatal("builder expected field unavailable")
		}
		d = json.NewDecoder(bytes.NewReader(publicInspectionJSON(t, actual)))
		d.UseNumber()
		if d.Decode(&b) != nil || !reflect.DeepEqual(a, b) {
			t.Fatal("builder public facts differ from authentic installed query")
		}
	}
	observation := PublicObservation{env.Domain, f.selected.head.Core.Revision, f.selected.root.Snapshot, f.selected.head.Core.Root.Digest}
	observationFields := map[string]any{"domain_id": id(observation.DomainID), "head_revision_id": id(observation.HeadRevisionID), "snapshot_id": id(observation.SnapshotID), "root_digest": id(observation.RootDigest)}
	if facts.Domain != id(env.Domain) || facts.Recipient != id(recipient) || facts.Revision != id(observation.HeadRevisionID) || facts.Snapshot != id(observation.SnapshotID) || facts.RootDigest != id(observation.RootDigest) {
		t.Fatal("builder current observation differs")
	}
	memory, ok := underlyingAdmittedMemoryStore(env.Store)
	if !ok {
		t.Fatal("fixture Store counters unavailable")
	}
	trust, ok := underlyingAdmittedFixtureTrust(env.Trust)
	if !ok {
		t.Fatal("fixture signer counters unavailable")
	}
	public, private := keys.Calls()
	creates, cas, signs := memory.creates, memory.cas, trust.signs
	inspection, source := installedInspectionFixture(t, f)
	domain := inspection.Inspect(ctx, DomainInspectionRequest{fixtureID(env.Domain, "builder domain query")})
	if domain.StateResult != PublicQuerySuccess || domain.View == nil || domain.ValidateMetadataWorkOutput() != nil || domain.View.Observation != observation {
		t.Fatal("authentic domain inspection unavailable", domain.Result)
	}
	domainFields := decode(facts.DomainPayload)
	if len(domainFields) != 11 {
		t.Fatal("builder domain form is incomplete")
	}
	assertJSON(domainFields["schema"], "InspectionPayload/v1")
	assertJSON(domainFields["form"], "domain")
	assertJSON(domainFields["observation"], observationFields)
	entries := make([]any, 0, len(domain.View.Entries))
	for _, entry := range domain.View.Entries {
		members := make([]string, len(entry.RecipientIDs))
		for i, member := range entry.RecipientIDs {
			members[i] = id(member)
		}
		entries = append(entries, map[string]any{"slot": entry.Slot, "name": entry.Name, "incarnation_id": id(entry.IncarnationID), "value_state_id": id(entry.ValueStateID), "value_source": entry.ValueSource, "confidential": entry.Confidential, "raw_length": entry.RawLength, "recipient_ids": members})
	}
	assertJSON(domainFields["entries"], entries)
	registry := make([]any, 0, len(domain.View.Recipients))
	for _, row := range domain.View.Recipients {
		registry = append(registry, map[string]any{"recipient_id": id(row.RecipientID), "status": row.Status, "display_name": row.DisplayName, "binding_id": id(row.BindingID), "binding_serial": row.BindingSerial, "binding_fingerprint": id(row.BindingFingerprint)})
	}
	assertJSON(domainFields["recipients"], registry)
	if domain.View.ActiveOperation != nil || domain.View.DomainWarningBits != 0 || len(domain.View.Generated.CurrentGenerations)+len(domain.View.Generated.Effects)+len(domain.View.Generated.Duties)+len(domain.View.Generated.Hazards)+len(domain.View.Generated.PendingReleases)+len(domain.View.Generated.NextActions) != 0 || len(domain.View.Work.Groups)+len(domain.View.Work.PublicationOrder) != 0 || !reflect.DeepEqual(domain.View.Work.Pages, f.selected.adminIndex.Pages) || len(domain.View.Output.Configuration.Bindings)+len(domain.View.Output.Configuration.Routes)+len(domain.View.Output.Configuration.Groups)+len(domain.View.Output.Coordinates)+len(domain.View.Output.Markers)+len(domain.View.Output.CurrentTargets)+len(domain.View.Output.CurrentBlockers) != 0 || domain.View.Output.ConfigurationDescriptor != f.selected.root.OutputConfiguration {
		t.Fatal("authentic fixture has unexpected generated, work or output facts")
	}
	empty := []any{}
	assertJSON(domainFields["active_operation"], nil)
	assertJSON(domainFields["generated"], map[string]any{"current_generations": empty, "effects": empty, "duties": empty, "hazards": empty, "pending_releases": empty, "next_actions": empty})
	pages := make([]any, 0, len(domain.View.Work.Pages))
	for _, page := range domain.View.Work.Pages {
		spans, rows := make([]any, 0, len(page.Spans)), make([]any, 0, len(page.Rows))
		for _, span := range page.Spans {
			indexes := append([]uint16{}, span.GroupIndexes...)
			spans = append(spans, map[string]any{"first": span.First, "count": span.Count, "mandatory": span.Mandatory, "group_indexes": indexes})
		}
		for _, row := range page.Rows {
			fields := map[string]any{"kind": row.Kind, "record_id": id(row.RecordID), "body_length": row.BodyLength}
			if !row.MaterialID.IsZero() {
				fields["material_id"] = id(row.MaterialID)
			}
			rows = append(rows, fields)
		}
		r := page.Ref
		pages = append(pages, map[string]any{"ref": map[string]any{"kind": r.Kind, "domain_id": id(r.Domain), "object_id": id(r.Object), "digest": id(r.Digest), "format": r.Format, "length": r.Length, "index": r.Index}, "read_required": page.ReadRequired, "spans": spans, "rows": rows})
	}
	assertJSON(domainFields["work"], map[string]any{"groups": empty, "pages": pages, "publication_order": empty})
	d := domain.View.Output.ConfigurationDescriptor
	outputWarnings := map[string]any{"domain_wide_warning": false, "unresolved_publication": false, "late_write_risk": false}
	domainWarnings := map[string]any{"orphan_generated_effect": false, "late_destructive_effect": false, "publication_order_value": false, "discarded_exact_evidence": false, "possible_store_garbage": false}
	if domain.View.Warnings != (InspectionWarnings{}) || domain.View.Output.Warnings != (InspectionOutputWarnings{}) || domain.View.Output.Configuration.DomainID != env.Domain || domain.View.Output.Configuration.Schema != contract.OutputConfigurationSchema {
		t.Fatal("authentic empty output or warning interpretation differs")
	}
	assertJSON(domainFields["output"], map[string]any{"configuration_descriptor": map[string]any{"schema": d.Schema, "configuration_digest": id(d.ConfigurationDigest), "total_length": d.TotalLength, "slice_count": d.SliceCount, "binding_count": d.BindingCount, "routing_length": d.RoutingLength}, "configuration": map[string]any{"schema": domain.View.Output.Configuration.Schema, "domain_id": id(domain.View.Output.Configuration.DomainID), "bindings": empty, "routes": empty, "groups": empty}, "current_targets": empty, "coordinates": empty, "markers": empty, "current_blockers": empty, "warnings": outputWarnings})
	assertJSON(domainFields["domain_warning_bits"], uint8(0))
	assertJSON(domainFields["warnings"], map[string]any{"domain": domainWarnings, "generated": map[string]any{"possible_live_residue": false, "late_effect": false, "invalidation_not_confirmed": false}, "output": outputWarnings, "possible_store_garbage": false})
	scoped := inspection.InspectRecipient(ctx, RecipientInspectionRequest{fixtureID(env.Domain, "builder recipient query"), recipient})
	if scoped.StateResult != PublicQuerySuccess || scoped.View == nil || scoped.Validate() != nil || scoped.View.Observation != observation || scoped.View.RecipientID != recipient || len(scoped.View.Entries) != 1 || source.reads == 0 {
		t.Fatal("authentic Recipient inspection unavailable", scoped.Result)
	}
	scopedFields := decode(facts.RecipientPayload)
	if len(scopedFields) != 5 {
		t.Fatal("builder Recipient form disclosed domain fields")
	}
	assertJSON(scopedFields["schema"], "InspectionPayload/v1")
	assertJSON(scopedFields["form"], "recipient")
	assertJSON(scopedFields["observation"], observationFields)
	assertJSON(scopedFields["recipient_id"], id(recipient))
	entry := scoped.View.Entries[0]
	assertJSON(scopedFields["entries"], []any{map[string]any{"name": entry.Name, "incarnation_id": id(entry.IncarnationID), "value_state_id": id(entry.ValueStateID), "value_source": entry.ValueSource, "confidential": entry.Confidential, "raw_length": entry.RawLength}})
	receipts, receiptSource := installedReceiptFixture(t, f)
	listed := receipts.List(ctx, ReceiptListRequest{fixtureID(env.Domain, "builder receipt list")})
	if listed.StateResult != PublicQuerySuccess || listed.Payload == nil || listed.Validate() != nil || listed.Payload.Observation != observation || len(listed.Payload.Receipts) != 2 || len(facts.Details) != 2 {
		t.Fatal("authentic retained receipt list unavailable", listed.Result)
	}
	listFields := decode(facts.ListPayload)
	if len(listFields) != 6 {
		t.Fatal("builder retained receipt list is incomplete")
	}
	assertJSON(listFields["schema"], "ReceiptPayload/v1")
	assertJSON(listFields["form"], "list")
	if listed.Payload.CurrentDomainWarningBits != 0 || listed.Payload.CurrentWarnings != (PublicDomainWarnings{}) {
		t.Fatal("authentic receipt list current warnings differ")
	}
	assertJSON(listFields["current_domain_warning_bits"], uint8(0))
	assertJSON(listFields["current_warnings"], domainWarnings)
	assertJSON(listFields["observation"], observationFields)
	list := make([]any, 0, 2)
	for i, original := range [][]byte{applied.Receipt, ready.Receipt} {
		row, err := contract.InspectCompactMutationReceipt(original)
		if err != nil {
			t.Fatal(err)
		}
		want := ReceiptSummary{row.OperationID, row.OperationKind, row.CanonicalOutcome, row.StateResult, row.ObservedRevisionID, row.RequestedRevisionID, row.WarningBits, row.EvidenceCeiling}
		if listed.Payload.Receipts[i] != want || facts.Details[i].Operation != id(row.OperationID) {
			t.Fatal("builder or query changed known terminal selection order")
		}
		list = append(list, map[string]any{"operation_id": id(row.OperationID), "operation_kind": row.OperationKind, "canonical_outcome": row.CanonicalOutcome, "state_result": row.StateResult, "observed_revision_id": id(row.ObservedRevisionID), "requested_revision_id": id(row.RequestedRevisionID), "warning_bits": row.WarningBits, "evidence_ceiling": row.EvidenceCeiling})
		detail := receipts.Detail(ctx, ReceiptDetailRequest{fixtureID(env.Domain, "builder receipt detail "+facts.Details[i].Operation), row.OperationID})
		if detail.StateResult != PublicQuerySuccess || detail.Payload == nil || detail.Validate() != nil || detail.Payload.Observation != observation || detail.Payload.Receipt != row || !bytes.Equal(detail.Payload.EncodedReceipt, original) || i == 1 && row.ObservedRevisionID == observation.HeadRevisionID {
			t.Fatal("authentic detail changed original receipt or historical observation", detail.Result)
		}
		fields := decode(facts.Details[i].Payload)
		if len(fields) != 9 {
			t.Fatal("builder receipt detail is incomplete")
		}
		assertJSON(fields["schema"], "ReceiptPayload/v1")
		assertJSON(fields["form"], "detail")
		if detail.Payload.CurrentDomainWarningBits != 0 || detail.Payload.CurrentWarnings != (PublicDomainWarnings{}) {
			t.Fatal("authentic receipt detail current warnings differ")
		}
		assertJSON(fields["current_domain_warning_bits"], uint8(0))
		assertJSON(fields["current_warnings"], domainWarnings)
		assertJSON(fields["observation"], observationFields)
		assertJSON(fields["receipt"], publicInspectionReceiptFields(detail.Payload.Receipt))
		assertJSON(fields["encoded_receipt"], detail.Payload.EncodedReceipt)
		assertJSON(fields["authenticity"], detail.Payload.Authenticity)
		assertJSON(fields["retention"], detail.Payload.Retention)
	}
	assertJSON(listFields["receipts"], list)
	if p, q := keys.Calls(); p != public || q != private || memory.creates != creates || memory.cas != cas || trust.signs != signs || receiptSource.reads == 0 {
		t.Fatal("authentic public queries used private authority or Store mutation, or did not read")
	}
}

package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestRecipientReplacementRetainsExactReceipt(t *testing.T) {
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	before := f.session
	windows, err := before.receiptWindows(ctx)
	if err != nil || len(windows.Successes) == 0 || len(windows.Successes) >= contract.MutationReceiptWindowLimit || before.root.WarningBits != 0 {
		t.Fatal("bounded authenticated predecessor receipt fixture", err)
	}
	prior := make(map[contract.ID][]byte)
	for _, row := range append(slices.Clone(windows.Successes), windows.Failures...) {
		body, result := before.MutationReceipt(ctx, row.OperationID)
		if result.Outcome != ObservedCurrent {
			t.Fatal("predecessor receipt unavailable", result)
		}
		prior[row.OperationID] = bytes.Clone(body)
	}
	entries := make(map[uint16][]byte)
	for _, name := range before.root.Names {
		body, err := contract.EncodeValueEntry(*before.valueEntry(name.Slot))
		if err != nil {
			t.Fatal(err)
		}
		entries[name.Slot] = body
	}
	reader := fixtureID(env.Domain, "reader")
	record := before.recipientRecord(reader)
	if record == nil || record.Status != contract.CurrentRecipient || record.CurrentBinding == nil || reader == before.admission.recipient {
		t.Fatal("fixture has no distinct current Recipient")
	}
	successor := keys.RecipientSuccessor(t, reader)
	if successor.BindingID == record.CurrentBinding.BindingID || !contract.IncarnationCounterStep(record.CurrentBinding.BindingIncarnationID, record.CurrentBinding.BindingSerial, successor.BindingIncarnationID, successor.BindingSerial) {
		t.Fatal("fixture successor has no fresh binding progression")
	}
	permit := admitReaderReplacement(t, before, keys, reader, successor)
	defer keys.RetireAccess()
	_, request, rows, err := before.replacementRequest(ctx, permit.intent, permit.plan, permit.context)
	if err != nil || len(rows) != 0 {
		t.Fatal("fixture must replace an unused Recipient", err)
	}
	requestBody, err := contract.EncodeRequestCore(request)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := sha256.Sum256(requestBody)
	publicBefore, privateBefore := keys.Calls()
	candidate, result := before.PrepareRecipientReplacement(ctx, permit, env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("replacement preparation did not succeed", result)
	}
	if result = before.Select(ctx, candidate); result.Outcome != ObservedCurrent || result.RequestedRevision != permit.plan.revision || result.ObservedRevision != permit.plan.revision {
		t.Fatal("replacement did not select its exact candidate", result)
	}
	keys.RetireAccess()
	if err := keys.ActivateRecipientSuccessor(reader); err != nil {
		t.Fatal(err)
	}
	selected, result := Open(ctx, f.admission, env.Store)
	if selected == nil || result.Outcome != ObservedCurrent || selected.head.Core.Revision != permit.plan.revision || selected.root.Snapshot != permit.plan.snapshot {
		t.Fatal("replacement did not authenticate in a cold open", result)
	}
	publicAfter, privateAfter := keys.Calls()
	if publicAfter != publicBefore+1 || privateAfter != privateBefore {
		t.Fatal("unused Recipient replacement did not use exactly public qualification")
	}
	if selected.root.CurrentAccess.Core.AccessGeneration != before.root.CurrentAccess.Core.AccessGeneration+1 || selected.root.CurrentAccess.Core.AccessIncarnationID != before.root.CurrentAccess.Core.AccessIncarnationID {
		t.Fatal("replacement changed access progression")
	}
	if selected.head.Subject.Operation != permit.plan.operation || selected.head.Subject.Request != requestDigest {
		t.Fatal("selected lifecycle does not bind the admitted operation and request")
	}
	for _, old := range before.registry() {
		want := old
		if old.RecipientID == reader {
			want.CurrentBinding = &successor
		}
		got := selected.recipientRecord(old.RecipientID)
		wantBody, err := contract.EncodeRecipientRecord(want)
		if err != nil || got == nil {
			t.Fatal("replacement lost a current Recipient", err)
		}
		gotBody, err := contract.EncodeRecipientRecord(*got)
		if err != nil || !bytes.Equal(gotBody, wantBody) {
			t.Fatal("replacement changed an unrelated Recipient or the nominated binding", err)
		}
	}
	if len(selected.registry()) != len(before.registry()) || !reflect.DeepEqual(selected.root.Names, before.root.Names) {
		t.Fatal("replacement changed the complete registry or value-name set")
	}
	for slot, want := range entries {
		got, err := contract.EncodeValueEntry(*selected.valueEntry(slot))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("replacement changed immutable entry bytes or memberships", err)
		}
	}
	for index, ref := range before.root.ValueEntryPages {
		if !reflect.DeepEqual(selected.root.ValueEntryPages[index], ref) {
			t.Fatal("replacement rewrote an unchanged value-entry page")
		}
	}

	body, result := selected.MutationReceipt(ctx, permit.plan.operation)
	if result.Outcome != ObservedCurrent || len(body) != contract.CompactMutationReceiptLength {
		t.Fatal("selected Recipient replacement has no exact retained receipt", result)
	}
	row, err := contract.InspectCompactMutationReceipt(body)
	if err != nil || row.RequestIdentityDigest.IsZero() {
		t.Fatal("selected Recipient receipt has no valid request identity", err)
	}

	// These fixed preimages use the specified raw IDs, scalar order and frames;
	// neither the replacement writer nor a production receipt encoder is used.
	generator := func(label string, value []byte) contract.GeneratorDescriptor {
		preimage := []byte("ENKV/GENERATOR/v1/" + label + "\x00")
		preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(value)))
		return contract.GeneratorDescriptor{Digest: sha256.Sum256(append(preimage, value...)), Length: uint64(len(value))}
	}
	subject := append([]byte("ENKV/CRYPTO/v2/changed-subject-identity-v1\x00"), env.Domain[:]...)
	subject = append(subject, byte(contract.ChangedSubjectRecipient))
	subject = append(subject, reader[:]...)
	subject = append(subject, make([]byte, 32)...)
	identity := sha256.Sum256(subject)
	subjects := binary.BigEndian.AppendUint32(nil, 1)
	subjects = binary.BigEndian.AppendUint32(subjects, 34)
	subjects = append(subjects, byte(contract.ChangedSubjectRecipient), byte(contract.ChangedSubjectUpdated))
	subjects = append(subjects, identity[:]...)
	changed := generator("changed-subjects", subjects)
	changed.Count = 1
	appendDescriptor := func(out []byte, descriptor contract.GeneratorDescriptor) []byte {
		out = append(out, descriptor.Digest[:]...)
		out = binary.BigEndian.AppendUint64(out, descriptor.Length)
		return binary.BigEndian.AppendUint32(out, descriptor.Count)
	}
	var empty [5]contract.GeneratorDescriptor
	for index, label := range []string{"changed-access", "effect-results", "output-results", "result-duties", "result-hazards"} {
		empty[index] = generator(label, make([]byte, 4))
	}
	projection := binary.BigEndian.AppendUint16(nil, 3)       // compact receipt schema
	projection = binary.BigEndian.AppendUint16(projection, 9) // Recipient key replacement
	for _, id := range []contract.ID{env.Domain, permit.plan.operation, requestDigest, before.head.Core.Revision, permit.plan.revision, permit.plan.revision} {
		projection = append(projection, id[:]...)
	}
	for _, scalar := range []uint16{1, 1, 0, 1} {
		projection = binary.BigEndian.AppendUint16(projection, scalar)
	}
	projection = append(projection, 1)
	projection = appendDescriptor(projection, changed)
	projection = append(projection, make([]byte, 8+12*4+3*4+78)...)
	for _, descriptor := range empty {
		projection = appendDescriptor(projection, descriptor)
	}
	projection = append(projection, make([]byte, 32)...)
	if len(projection) != 647 {
		t.Fatal("independent complete-result projection length", len(projection))
	}
	framed := binary.BigEndian.AppendUint32(nil, 1)
	framed = binary.BigEndian.AppendUint32(framed, uint32(len(projection)))
	complete := generator("complete-result", append(framed, projection...))
	complete.Count = 1
	want := contract.CompactMutationReceipt{Schema: 3, OperationKind: 9, DomainID: env.Domain, OperationID: permit.plan.operation,
		RequestIdentityDigest: row.RequestIdentityDigest, PredecessorRevisionID: before.head.Core.Revision,
		RequestedRevisionID: permit.plan.revision, ObservedRevisionID: permit.plan.revision,
		StateResult: 1, EffectSummary: 1, OutputSummary: 0, EvidenceCeiling: 1, CanonicalOutcome: 1,
		ChangedSubjects: changed, CompleteResult: complete}
	if row != want {
		t.Fatal("receipt does not bind the exact Recipient result and admitted request")
	}
	var wire []byte
	for _, scalar := range []uint16{3, 9, 1, 1, 0, 1} {
		wire = binary.BigEndian.AppendUint16(wire, scalar)
	}
	for _, id := range []contract.ID{env.Domain, permit.plan.operation, row.RequestIdentityDigest, before.head.Core.Revision, permit.plan.revision, permit.plan.revision} {
		wire = append(wire, id[:]...)
	}
	wire = append(wire, 1)
	wire = appendDescriptor(wire, changed)
	wire = appendDescriptor(wire, complete)
	wire = append(wire, make([]byte, 8+12*4+3*4+78+32)...)
	if len(wire) != 471 || !bytes.Equal(body, wire) {
		t.Fatal("retained receipt differs from independent exact bytes")
	}
	after, err := selected.receiptWindows(ctx)
	wantSuccesses := append(slices.Clone(windows.Successes), want)
	if err != nil || after.DomainID != windows.DomainID || !reflect.DeepEqual(after.Successes, wantSuccesses) || !reflect.DeepEqual(after.Failures, windows.Failures) {
		t.Fatal("replacement changed history beyond its one exact success append", err)
	}
	assertSuccessReceiptOrder(t, windows, after, want.OperationID)
	found := 0
	for _, page := range selected.support {
		for _, record := range page.Records {
			if record.Kind == contract.MutationReceiptSupportKind && record.RecordID == permit.plan.operation {
				found++
				if !bytes.Equal(record.Body, wire) {
					t.Fatal("selected support does not own the exact indexed receipt bytes")
				}
			}
		}
	}
	if found != 1 {
		t.Fatal("selected receipt is not exactly one retained support row", found)
	}
	for operation, want := range prior {
		got, read := selected.MutationReceipt(ctx, operation)
		if read.Outcome != ObservedCurrent || !bytes.Equal(got, want) {
			t.Fatal("replacement changed a prior retained receipt", read)
		}
	}
	again, result := Open(ctx, f.admission, env.Store)
	if again == nil || result.Outcome != ObservedCurrent {
		t.Fatal("repeat cold open failed", result)
	}
	if got, read := again.MutationReceipt(ctx, permit.plan.operation); read.Outcome != ObservedCurrent || !bytes.Equal(got, wire) {
		t.Fatal("exact replacement receipt did not survive cold retrieval", read)
	}
}

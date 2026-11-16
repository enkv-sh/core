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
func TestRecipientReplacementReceiptCommitsAllChangedMaterialOwners(t *testing.T) {
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, false)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	generatedSourcePlanInput(t, run, f, 2)
	readers := []contract.ID{f.session.admission.recipient, fixtureID(env.Domain, "reader")}
	slices.SortFunc(readers, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	sources, canonical := generatedCurrentDeclaration(t, f.session)
	input := generatedPlanInputForGenerationsMembershipIntent(t, f.session, generatedVectorID(10), []string{"generated"}, readers,
		[]byte(`{"name":"generated"}`), defaultGeneratedFixtureProfile(), sources...)
	reservation, _ := preparePrivateGeneratedReservation(t, env, f.session, input, canonical)
	producer, expected := preparePrivateGeneratedProducer(t, env, f.session, reservation, nil)
	var output []byte
	if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		var code contract.CryptoResultCode
		output, _, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		return code
	}) {
		t.Fatal("generated producer handoff")
	}
	entered, result := f.session.selectCandidate(ctx, producer.reservation.candidate)
	if entered == nil || result.Outcome != ObservedCurrent || len(output) == 0 {
		t.Fatal("generated producer selection", result)
	}
	keys.RetireGenerated()
	recorded := selectFreshGeneratedRecord(t, env.Store.(*memoryStore), entered, expected.Template.AttemptID, output)
	finalContext := generatedPlanInputFixture(t, recorded).context
	finalContext.AdmissionID, finalContext.SessionID = testID("material receipt final admission"), testID("material receipt final session")
	finalPlan, err := recorded.generatedFinalRequest(ctx, finalContext)
	if err != nil {
		t.Fatal(err)
	}
	recorded, final := preparePrivateGeneratedFinal(t, env, recorded, finalPlan)
	before, result := recorded.selectCandidate(ctx, final.reservation.candidate)
	if before == nil || result.Outcome != ObservedCurrent || before.root.ValueEntryCount != 2 || before.root.Generated.GeneratedCurrent != 1 {
		t.Fatal("selected generated and supplied material fixture", result)
	}
	keys.RetireGenerated()
	reader := fixtureID(env.Domain, "reader")
	var subjects [][]byte
	add := func(kind byte, id contract.ID) {
		preimage := append([]byte("ENKV/CRYPTO/v2/changed-subject-identity-v1\x00"), env.Domain[:]...)
		preimage = append(preimage, kind)
		preimage = append(preimage, id[:]...)
		preimage = append(preimage, make([]byte, 32)...)
		digest := sha256.Sum256(preimage)
		subjects = append(subjects, append([]byte{kind, 3}, digest[:]...))
	}
	add(2, reader)
	entries := make(map[uint16][]byte)
	priorAccess := make(map[contract.ID]contract.AccessRecord)
	for _, name := range before.root.Names {
		entry := before.valueEntry(name.Slot)
		core, _, access, ok := before.selectedValue(name.Slot)
		if entry == nil || !ok || entry.ConfidentialityClass != contract.Secret || !slices.Contains(entry.Recipients, reader) {
			t.Fatal("fixture material owner missing")
		}
		add(1, entry.Incarnation)
		if entry.ValueSource == contract.Generated {
			add(4, entry.Generated.GenerationID)
		}
		entries[name.Slot], err = contract.EncodeValueEntry(*entry)
		if err != nil {
			t.Fatal(err)
		}
		priorAccess[core.ValueStateID] = access
	}
	if len(subjects) != 4 || len(priorAccess) != 2 {
		t.Fatal("fixture must cover Recipient, supplied entry, generated entry and selected generation")
	}
	slices.SortFunc(subjects, bytes.Compare)
	framed := binary.BigEndian.AppendUint32(nil, 4)
	for _, row := range subjects {
		framed = binary.BigEndian.AppendUint32(framed, 34)
		framed = append(framed, row...)
	}
	preimage := []byte("ENKV/GENERATOR/v1/changed-subjects\x00")
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(framed)))
	want := contract.GeneratorDescriptor{Digest: sha256.Sum256(append(preimage, framed...)), Length: 156, Count: 4}
	successor := keys.RecipientSuccessor(t, reader)
	permit := admitReaderReplacement(t, before, keys, reader, successor)
	defer keys.RetireAccess()
	_, _, rows, err := before.replacementRequest(ctx, permit.intent, permit.plan, permit.context)
	if err != nil || len(rows) != 2 {
		t.Fatal("replacement must cover both selected material rows", err, len(rows))
	}
	candidate, result := before.PrepareRecipientReplacement(ctx, permit, env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("replacement preparation", result)
	}
	if result = before.Select(ctx, candidate); result.Outcome != ObservedCurrent {
		t.Fatal("replacement selection", result)
	}
	keys.RetireAccess()
	if err := keys.ActivateRecipientSuccessor(reader); err != nil {
		t.Fatal(err)
	}
	selected, result := Open(ctx, f.admission, env.Store)
	if selected == nil || result.Outcome != ObservedCurrent || selected.head.Core.Revision != permit.plan.revision {
		t.Fatal("replacement cold open", result)
	}
	for slot, want := range entries {
		got, err := contract.EncodeValueEntry(*selected.valueEntry(slot))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("wrap replacement changed immutable value entry", err)
		}
	}
	for material, prior := range priorAccess {
		after, ok := selected.materialAccess(contract.ValueMaterialKind, material)
		if !ok || after.MaterialContextDigest != prior.MaterialContextDigest || after.PackageCheck != prior.PackageCheck || len(after.Wraps) != len(prior.Wraps) {
			t.Fatal("material correspondence changed")
		}
		changed := 0
		for i, wrap := range prior.Wraps {
			got := after.Wraps[i]
			if wrap.SubjectKind == contract.OrdinaryWrapSubject && wrap.SubjectID == reader {
				if got.BindingID != successor.BindingID || got.BindingSerial != successor.BindingSerial || bytes.Equal(got.RSACiphertext, wrap.RSACiphertext) {
					t.Fatal("nominated material wrap did not change")
				}
				changed++
			} else {
				if !reflect.DeepEqual(wrap, got) {
					t.Fatal("unrelated wrap changed")
				}
			}
		}
		if changed != 1 {
			t.Fatal("each selected material must change one nominated wrap", changed)
		}
	}
	body, result := selected.MutationReceipt(ctx, permit.plan.operation)
	if result.Outcome != ObservedCurrent || len(body) != contract.CompactMutationReceiptLength {
		t.Fatal("selected material replacement has no exact retained receipt", result)
	}
	receipt, err := contract.InspectCompactMutationReceipt(body)
	if err != nil || receipt.OperationKind != 9 || receipt.ChangedSubjects != want || receipt.SummaryCounts[contract.ReceiptChangedAccessCount] != 2 || receipt.RequestIdentityDigest.IsZero() {
		t.Fatal("replacement receipt omitted or added changed material owners", err, receipt.ChangedSubjects)
	}
	again, result := Open(ctx, f.admission, env.Store)
	if again == nil || result.Outcome != ObservedCurrent {
		t.Fatal("repeat cold open", result)
	}
	if got, result := again.MutationReceipt(ctx, permit.plan.operation); result.Outcome != ObservedCurrent || !bytes.Equal(got, body) {
		t.Fatal("exact owner commitment did not survive cold lookup", result)
	}
}

package core

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestInstalledRecipientReplacementWaitsForActiveGeneratedWork(t *testing.T) {
	for _, sameKey := range []bool{false, true} {
		t.Run(map[bool]string{false: "changed-key", true: "same-key"}[sameKey], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			h := newInstalledReplacementFixture(t, contract.GCP, ReplacementTargetRecipient, 0, 1, ReplacementMaterialAuthority, sameKey)
			source := h.fixture.session
			declaration, canonical := generatedCurrentDeclaration(t, source)
			input := generatedPlanInputForGenerations(t, source, testID("parent before key replacement"), []string{"generated"}, defaultGeneratedFixtureProfile(), declaration...)
			prior, _ := preparePrivateGeneratedReservation(t, h.env, source, input, canonical)
			recorded, _, _, _ := selectActualGeneratedPacketRecord(t, h.env, source, prior, custody.StandardValue, true, nil)
			active := retainedReaderColdOpen(t, recorded, h.env.Store)
			owner := input.graph.Header.OperationID
			if active.root.Generated.ActiveOwner != owner || active.root.Generated.ActivePhase.IsZero() {
				t.Fatal("expected a recorded result in an active generated operation")
			}
			before := active.recipientRecord(h.recipient).CurrentBinding
			current := checkOccupiedRecipientReplacement(t, ctx, h, active)
			deadline, _ := ctx.Deadline()
			finalContext, err := installedGeneratedContext(current, deadline)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := current.generatedFinalRequest(ctx, finalContext)
			if err != nil {
				t.Fatal(err)
			}
			current, final := preparePrivateGeneratedFinal(t, h.env, current, plan)
			closed, observed := current.selectCandidate(ctx, final.reservation.candidate)
			h.keys.RetireGenerated()
			if closed == nil || observed.Outcome != ObservedCurrent || !closed.root.Generated.ActiveOwner.IsZero() {
				t.Fatal("original work failed to reach Final", observed)
			}
			e := h.engine(t)
			replaced := e.Replace(ctx, testID("fresh replacement after Final"))
			e.Close()
			if replaced.Result.Outcome != ObservedCurrent || len(replaced.Receipt) == 0 || h.delivered != 1 {
				t.Fatal("fresh replacement after the slot closed", replaced.Result)
			}
			after := retainedReaderColdOpen(t, closed, h.env.Store).recipientRecord(h.recipient).CurrentBinding
			if after.BindingID == before.BindingID || len(h.output.Recipients) == 0 || h.output.Recipients[0].RecipientID != h.recipient ||
				!kmsBindingEqual(*after, h.output.Recipients[0].Encryption) {
				t.Fatal("replacement did not deliver the selected fresh binding")
			}
		})
	}
}

func checkOccupiedRecipientReplacement(t *testing.T, ctx context.Context, h *installedReplacementFixture, active *StateSession) *StateSession {
	t.Helper()
	store := requireAdmittedMemoryStore(t, h.env.Store)
	signs, creates, cas := h.env.Trust.(*fixtureTrust).signs, store.creates, store.cas
	publicCalls, privateCalls := h.keys.Calls()
	resolve := h.installation.ResolvePublicGoal
	reachedResolver := false
	h.installation.ResolvePublicGoal = func(context.Context, ReplacementPublicRequest) (ReplacementPublicGoal, error) {
		reachedResolver = true
		return ReplacementPublicGoal{}, contract.ErrRecord
	}
	e := h.engine(t)
	refusal := e.Replace(ctx, testID("ordinary replacement with active parent"))
	e.Close()
	h.installation.ResolvePublicGoal = resolve
	current := retainedReaderColdOpen(t, active, h.env.Store)
	publicAfter, privateAfter := h.keys.Calls()
	if reachedResolver || refusal.Result != refused(InvalidRelation) ||
		len(refusal.Receipt) != 0 || h.delivered != 0 || h.signerFactories != 0 || h.custodyFactories != 0 ||
		store.creates != creates || store.cas != cas || h.env.Trust.(*fixtureTrust).signs != signs || publicCalls != publicAfter || privateCalls != privateAfter ||
		!bytes.Equal(active.body, current.body) || active.token != current.token || current.root.Generated.ActiveOwner != active.root.Generated.ActiveOwner ||
		!reflect.DeepEqual(active.recipientRecord(h.recipient).CurrentBinding, current.recipientRecord(h.recipient).CurrentBinding) {
		t.Fatal("occupied recipient replacement reached its resolver or changed selected work", refusal.Result)
	}
	return current
}

// full_only: false
func TestInstalledReplacementPreservesCompleteOccupiedGeneratedWork(t *testing.T) {
	h := newInstalledReplacementFixture(t, contract.GCP, ReplacementTargetRecipient, 0, 1, ReplacementMaterialAuthority)
	sources, canonical := generatedCurrentDeclaration(t, h.fixture.session)
	input := generatedPlanInputForGenerations(t, h.fixture.session, testID("installed occupied accepted operation"), []string{"accepted-good", "accepted-bad"}, defaultGeneratedFixtureProfile(), sources...)
	before, _ := selectPrivateOwnedUnusableAggregateFromInput(t, h.env, h.fixture.session, []string{"accepted-good", "accepted-bad"}, input, canonical)
	if before.root.Generated.Duties != 1 || before.root.Generated.Hazards != 1 || !before.root.Generated.ActiveOwner.IsZero() {
		t.Fatal("fixture requires two occupied accepted owners")
	}
	work := mustSelectedGeneratedWork(t, before)
	var duties, hazards []contract.ID
	for key := range work.records {
		switch key.kind {
		case contract.GeneratedDutySupportKind:
			duties = append(duties, key.id)
		case contract.GeneratedHazardSupportKind:
			hazards = append(hazards, key.id)
		}
	}
	if len(duties) != 1 || len(hazards) != 1 {
		t.Fatal("fixture owner identity sets")
	}
	preserved, err := before.preservedWorkSupportRecords(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	h.fixture.session = before
	h.installation.ExpectedControl = currentControlOf(before)
	engine := h.engine(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	out := engine.Replace(ctx, testID("installed occupied reader replacement"))
	if out.Result.Outcome != ObservedCurrent || out.Payload == nil || !slices.Equal(out.Payload.LiveDutyIDs, duties) || !slices.Equal(out.Payload.LiveHazardIDs, hazards) {
		t.Fatal("replacement refused or lost complete live owner vector", out.Result, out.Payload)
	}
	admitted, result := admitPublicNormal(ctx, h.env.Domain, h.env.Store.Descriptor(), h.output.Basis, h.env.Store, h.installation.CompositionID, nil)
	if result.Outcome != ObservedCurrent {
		t.Fatal(result)
	}
	after, result := Open(ctx, admitted, h.env.Store)
	if after == nil || result.Outcome != ObservedCurrent {
		t.Fatal("occupied replacement cold open", result)
	}
	retained, err := after.preservedWorkSupportRecords(ctx)
	if err != nil || !reflect.DeepEqual(preserved, retained) || after.root.Generated.Duties != 1 || after.root.Generated.Hazards != 1 {
		t.Fatal("replacement changed accepted work bytes or owner counts", err)
	}
	receipt, err := contract.InspectCompactMutationReceipt(out.Receipt)
	if err != nil || receipt.ChangedSubjects.Count != 2 || receipt.SummaryCounts[contract.ReceiptChangedAccessCount] != 1 {
		t.Fatal("current and retained aliases duplicated changed owner projection", err, receipt.ChangedSubjects)
	}
}

// full_only: false
func TestInstalledRecoveryAuthorizedSignerReplacementPreservesMissingOptionalWork(t *testing.T) {
	h := newInstalledReplacementFixture(t, contract.GCP, ReplacementTargetAuthority, 1, 2, 0)
	sources, canonical := generatedCurrentDeclaration(t, h.fixture.session)
	input := generatedPlanInputForGenerations(t, h.fixture.session, testID("installed missing optional accepted operation"), []string{"accepted-good", "accepted-bad"}, defaultGeneratedFixtureProfile(), sources...)
	before, _ := selectPrivateOwnedUnusableAggregateFromInput(t, h.env, h.fixture.session, []string{"accepted-good", "accepted-bad"}, input, canonical)
	if before.root.Generated.Duties != 1 || before.root.Generated.Hazards != 1 {
		t.Fatal("fixture requires occupied mandatory owner summaries")
	}
	var missing *contract.Ref
	for _, page := range before.adminIndex.Pages {
		mandatory, detail := page.ReadRequired, false
		for _, span := range page.Spans {
			mandatory = mandatory || span.Mandatory
		}
		for _, row := range page.Rows {
			detail = detail || row.Kind == contract.GeneratedFragmentSupportKind
		}
		if !mandatory && detail {
			ref := page.Ref
			missing = &ref
			break
		}
	}
	if missing == nil {
		t.Fatal("occupied image has no optional detail page")
	}
	key, err := format.Key(before.admission.store.Prefix, *missing)
	if err != nil {
		t.Fatal(err)
	}
	store := h.env.Store.(*memoryStore)
	delete(store.objects, key)
	h.fixture.session = before
	h.installation.ExpectedControl = currentControlOf(before)
	normal := h.env.Trust.(*fixtureTrust).Signer
	normal.SetUnavailable(true)
	oldCalls := normal.Calls()
	engine := h.engine(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	if selected, result := Open(ctx, h.fixture.admission, store); selected != nil || result.Outcome == ObservedCurrent {
		t.Fatal("ordinary open accepted missing selected optional work", result)
	}
	out := engine.Replace(ctx, testID("installed signer recovery with optional loss"))
	if out.Result.Outcome != ObservedCurrent || len(out.Receipt) != 0 || h.custodyFactories != 0 || normal.Calls() != oldCalls || out.Payload == nil || len(out.Payload.LiveDutyIDs) != 1 || len(out.Payload.LiveHazardIDs) != 1 {
		t.Fatal("Recovery signer replacement required lost signer, KEK or optional bytes", out.Result)
	}
	admitted, result := admitPublicNormal(ctx, h.env.Domain, store.Descriptor(), h.output.Basis, store, h.installation.CompositionID, nil)
	if result.Outcome != ObservedCurrent {
		t.Fatal(result)
	}
	after, result := openAdministrative(ctx, admitted, store)
	if after == nil || result.Outcome != ObservedCurrent || !reflect.DeepEqual(before.root.Generated, after.root.Generated) || !slices.Equal(before.root.RequiredSupport, after.root.RequiredSupport) || before.root.AdministrativeIndex != after.root.AdministrativeIndex || !slices.Equal(before.root.AdministrativeIndexShards, after.root.AdministrativeIndexShards) {
		t.Fatal("signer recovery changed missing accepted-work commitments", result)
	}
	for index, ref := range before.root.ValueEntryPages {
		if ref != nil {
			other := after.root.ValueEntryPages[index]
			if other == nil || *ref != *other {
				t.Fatal("signer recovery changed application page reference")
			}
		}
	}
	for _, name := range before.root.Names {
		old, _ := contract.EncodeValueEntry(*before.valueEntry(name.Slot))
		current, _ := contract.EncodeValueEntry(*after.valueEntry(name.Slot))
		if !bytes.Equal(old, current) {
			t.Fatal("signer recovery changed application entry bytes")
		}
	}
	if selected, result := Open(ctx, admitted, store); selected != nil || result.Outcome == ObservedCurrent {
		t.Fatal("ordinary open treated preserved optional loss as repaired", result)
	}
}

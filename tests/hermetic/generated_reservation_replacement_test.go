package core

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestAuthorityKeyRecoveryKeepsReservationAndPublication(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	env := memoryScenarioEnvironmentMode(t, true)
	env.Context = ctx
	f := newEnvironmentFixture(t, ctx, env, []int{12}, false)
	entries := installedApplyCurrentInput(f.session)
	name := entries[0].Name
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "publication", targets: []outputApplyTarget{outputConfigurationTarget(name, "slot-000")}}}}
	source := selectAdmittedOutputConfiguration(t, ctx, f.session, env, env.Custody, entries, output)
	publication, err := selectedPublicationRelation(source.selectedImage())
	if err != nil || len(publication.coordinates) != 1 {
		t.Fatal("expected one selected publication coordinate", err)
	}
	declaration, canonical := generatedCurrentDeclaration(t, source)
	operation := fixtureID(env.Domain, "accepted generated operation")
	input := generatedPlanInputForGenerations(t, source, operation, []string{"generated"}, defaultGeneratedFixtureProfile(), declaration...)
	proposal, _ := preparePrivateGeneratedReservation(t, env, source, input, canonical)
	selected, _, expected, packet := selectActualGeneratedPacketRecord(t, env, source, proposal, custody.StandardValue, false, nil)
	env.Custody.RetireGenerated()
	selected = retainedReaderColdOpen(t, selected, env.Store)
	work := mustSelectedGeneratedWork(t, selected)
	selectedPublication, err := selectedPublicationRelation(selected.selectedImage())
	if err != nil || !reflect.DeepEqual(publication, selectedPublication) ||
		work.parent == nil || work.phase == nil || work.parent.OperationID != operation ||
		work.phase.Phase != 1 || work.phase.FrontierAttemptID != expected.Template.AttemptID || len(packet) == 0 {
		t.Fatal("cold reservation lost the accepted operation, original attempt or publication")
	}

	f.session = selected
	h := installedReplacementForCurrent(t, env, f, ReplacementTargetAuthority, contract.SuccessionChangeAuthorityKEK,
		contract.RecoverySigningRole, ReplacementMaterialRecovery)
	old := currentControlOf(selected).AuthorityKMSBinding
	env.Custody.LoseRecipientPredecessor(selected.admission.recipient)
	if probe := env.Custody.PrivateWitness(ctx, old.BindingID, old, old); probe.Outcome == contract.CryptoSuccess || probe.Completed != 0 {
		t.Fatal("original Authority key was still usable")
	}
	engine := h.engine(t)
	replaced := engine.Replace(ctx, fixtureID(env.Domain, "restore authority encryption"))
	engine.Close()
	if replaced.Result.Outcome != ObservedCurrent || h.delivered != 1 || h.custodyFactories != 1 {
		t.Fatal("covered key replacement did not deliver the successor", replaced.Result)
	}
	if err := env.Custody.ActivateSuccessor(selected.admission.recipient); err != nil {
		t.Fatal(err)
	}
	admitted, result := admitPublicNormal(ctx, env.Domain, env.Store.Descriptor(), h.output.Basis, env.Store,
		h.installation.CompositionID, selected.admission.outputInterpreter)
	if result.Outcome != ObservedCurrent {
		t.Fatal("successor basis", result)
	}
	after, result := Open(ctx, admitted, env.Store)
	if after == nil || result.Outcome != ObservedCurrent || currentControlOf(after).AuthorityKMSBinding.BindingID == old.BindingID {
		t.Fatal("cold recovery did not use the successor key", result)
	}
	surviving, err := selectedPublicationRelation(after.selectedImage())
	continued := mustSelectedGeneratedWork(t, after)
	if err != nil || !reflect.DeepEqual(surviving, publication) || !reflect.DeepEqual(work.parent, continued.parent) ||
		!reflect.DeepEqual(work.phase, continued.phase) || !reflect.DeepEqual(selected.root.Generated, after.root.Generated) {
		t.Fatal("replacement changed the accepted reservation or the selected publication")
	}
	saved, present, read := after.ReadGeneratedResult(ctx, expected.Template.AttemptID)
	if !present || read.Outcome != 0 || !bytes.Equal(saved, packet) {
		t.Fatal("cold recovery lost the original inbox", read)
	}
	deadline, _ := ctx.Deadline()
	recordContext, err := installedGeneratedContext(after, deadline)
	if err != nil {
		t.Fatal(err)
	}
	record, err := after.generatedRecordRequest(ctx, expected.Template.AttemptID, saved, recordContext)
	if err != nil {
		t.Fatal("cold continuation of the original result", err)
	}
	fresh := currentGeneratedEnvironment(t, env.Store, after)
	fresh.Context = ctx
	prepared := preparePrivateGeneratedRecord(t, fresh, after, record)
	recorded, result := after.selectCandidate(ctx, prepared.reservation.candidate)
	fresh.Custody.RetireGenerated()
	if recorded == nil || result.Outcome != ObservedCurrent {
		t.Fatal("original result was not selected", result)
	}
	finalContext, err := installedGeneratedContext(recorded, deadline)
	if err != nil {
		t.Fatal(err)
	}
	final, err := recorded.generatedFinalRequest(ctx, finalContext)
	if err != nil {
		t.Fatal(err)
	}
	current, prepared := preparePrivateGeneratedFinal(t, fresh, recorded, final)
	closed, result := current.selectCandidate(ctx, prepared.reservation.candidate)
	fresh.Custody.RetireGenerated()
	if closed == nil || result.Outcome != ObservedCurrent {
		t.Fatal("original operation did not finish", result)
	}
	closed = retainedReaderColdOpen(t, closed, env.Store)
	if !closed.root.Generated.ActiveOwner.IsZero() || closed.valueEntry(entrySlot(t, closed, "generated")) == nil {
		t.Fatal("completed operation lost its value or retained the slot")
	}
}

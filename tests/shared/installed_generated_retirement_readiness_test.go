package core

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
	protocol "enkv.sh/sdk/protocols/generator"
)

// full_only: false
func TestInstalledRemovalRefusesRejectedRetirementBeforeDuty(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	process, effects := installedGeneratedRetirementProcess(t, "acknowledged")
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, true)
	f.env.GeneratedProcess = process
	input := installedGeneratedRetirementEntries(process, f.selected.admission.recipient, 0, "healthy sibling")
	engine := installedGeneratedTestEngine(t, ctx, f, f.selected, input, currentApplyRecipients(f.selected.registry()), installedGeneratedRetirementCallbacks(t, f, process))
	created := engine.Apply(ctx, testID("initial retirement readiness resource"), input)
	engine.Close()
	if created.Result.Outcome != ObservedCurrent {
		t.Fatal("initial resource was not selected", created.Result)
	}
	selected := f.open(t, ctx)
	if selected.root.Generated.Duties != 0 || selected.root.Generated.Retiring != 0 {
		t.Fatal("initial resource already has retirement work")
	}
	_, beforeCurrent := observeCurrentValueEntry(t, selected, "generated")
	_, beforeHealthy := observeCurrentValueEntry(t, selected, "healthy")
	remove := []ApplyEntryInput{input[1]}
	callbacks := installedGeneratedRetirementCallbacks(t, f, process)
	compatible := callbacks.CheckRetirementCompatibility
	checks, reservations := 0, 0
	callbacks.CheckRetirementCompatibility = func(ctx context.Context, row contract.GeneratorImplementation, intent []byte, facts contract.GeneratorSafeFacts, completion uint8) ([]byte, []byte, error) {
		checks++
		if !reflect.DeepEqual(row, process.Implementation) || facts.ResourceContractID != beforeCurrent.Generated.ResourceContractID || generatedFactsResourceDigest(facts) != beforeCurrent.Generated.ResourceDigest {
			t.Fatal("compatibility checked another generated resource")
		}
		request, response, err := compatible(ctx, row, intent, facts, completion)
		if err != nil {
			return nil, nil, err
		}
		validation, err := protocol.DecodeValidationResponse(response)
		if err != nil {
			return nil, nil, err
		}
		validation.Accepted = false
		response, err = protocol.EncodeValidationResponse(validation)
		return request, response, err
	}
	callbacks.AdmitReservation = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedReservationInput, time.Time) (*InstalledGeneratedCustody, error) {
		reservations++
		return nil, contract.ErrRecord
	}
	store := requireAdmittedMemoryStore(t, f.env.Store)
	beforeHEAD := bytes.Clone(selected.body)
	beforeWrites, beforeCAS := store.creates, store.cas
	retirer := installedGeneratedTestEngine(t, ctx, f, selected, remove, currentApplyRecipients(selected.registry()), callbacks)
	refused := retirer.Apply(ctx, testID("refused retirement handoff"), remove)
	retirer.Close()
	if refused.Result.Outcome != AdmissionRefused || checks != 1 || reservations != 0 || store.creates != beforeWrites || store.cas != beforeCAS || len(refused.Receipt) != 0 || refused.Result.CommitMayHaveOccurred {
		t.Fatal("rejected compatibility acquired retirement work", refused.Result, checks, reservations)
	}
	cold := f.open(t, ctx)
	_, afterCurrent := observeCurrentValueEntry(t, cold, "generated")
	_, afterHealthy := observeCurrentValueEntry(t, cold, "healthy")
	creates, deletes := effects()
	if !bytes.Equal(cold.body, beforeHEAD) || !reflect.DeepEqual(beforeCurrent, afterCurrent) || !reflect.DeepEqual(beforeHealthy, afterHealthy) || cold.root.Generated.Duties != 0 || cold.root.Generated.Retiring != 0 || creates != 1 || len(deletes) != 0 {
		t.Fatal("incompatible removal changed selected state or sent a provider request", creates, deletes)
	}
}

// full_only: false
func TestInstalledUnavailableRetirementKeepsIdentityUntilAuthorizedEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f, selected, current, effects := installedGeneratedRetirementFixture(t, ctx, "acknowledged")
	work := mustSelectedGeneratedWork(t, selected)
	duty, err := contract.InspectGeneratedDutyRecord(work.records[generatedRecordKey{contract.GeneratedDutySupportKind, current.Generated.RetiringDutyID}].Body)
	if err != nil {
		t.Fatal(err)
	}
	beforeHEAD := bytes.Clone(selected.body)
	_, beforeCurrent := observeCurrentValueEntry(t, selected, "generated")
	_, beforeHealthy := observeCurrentValueEntry(t, selected, "healthy")
	for round := 0; round < 2; round++ {
		cold := f.open(t, ctx)
		reader, _ := installedGeneratedReaderFixture(t, f)
		listed := reader.List(ctx, testID("discover unavailable exact retirement"))
		reader.Close()
		if listed.StateResult != contract.ReaderSuccess || listed.View == nil || len(listed.View.Duties) != 1 || !reflect.DeepEqual(listed.View.Duties[0].Record, duty) {
			t.Fatal("cold inspection replaced retained retirement identity", listed.StateResult)
		}
		engine := installedGeneratedRetirementEngine(t, ctx, f, cold, nil)
		refused := engine.RetireGenerated(ctx, testID("unavailable exact retirement"), GeneratedRetirementRequest{DutyID: duty.DutyID})
		engine.Close()
		if refused.Result.Outcome != AdmissionRefused || refused.Payload != nil || len(refused.Receipt) != 0 || refused.Result.CommitMayHaveOccurred {
			t.Fatal("missing executor acquired another retirement right", refused.Result)
		}
	}
	cold := f.open(t, ctx)
	if !bytes.Equal(cold.body, beforeHEAD) {
		t.Fatal("unavailable retirement changed selected state")
	}
	_, privateBefore := f.keys.Calls()
	candidate, result := prepareTestEndSelectedWork(t, cold, ctx, duty.DutyID, f.env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("authorized exact end unavailable", result)
	}
	ended, result := cold.selectCandidate(ctx, candidate)
	if ended == nil || result.Outcome != ObservedCurrent {
		t.Fatal("authorized exact end was not selected", result)
	}
	ended = f.open(t, ctx)
	_, afterCurrent := observeCurrentValueEntry(t, ended, "generated")
	_, afterHealthy := observeCurrentValueEntry(t, ended, "healthy")
	beforeCurrent.Generated.RetiringDutyPresent, beforeCurrent.Generated.RetiringDutyID = 0, contract.ID{}
	_, privateAfter := f.keys.Calls()
	creates, deletes := effects()
	if !reflect.DeepEqual(beforeCurrent, afterCurrent) || !reflect.DeepEqual(beforeHealthy, afterHealthy) || ended.root.Generated.Retiring != 0 || ended.root.Generated.Duties != 0 || ended.root.WarningBits&(WarningOrphanGeneratedEffect|WarningDiscardedExactEvidence) != (WarningOrphanGeneratedEffect|WarningDiscardedExactEvidence) || privateAfter != privateBefore || creates != 2 || len(deletes) != 0 {
		t.Fatal("ending changed current values or lost resource uncertainty", ended.root.WarningBits, creates, deletes)
	}
}

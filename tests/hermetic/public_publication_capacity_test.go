package core

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

func publicPublicationJointOutput(entries []ApplyEntryInput, bindings int) *outputApplyInput {
	out := &outputApplyInput{}
	for binding := 0; binding < bindings; binding++ {
		destination := fmt.Sprintf("joint-%02d", binding)
		row := outputApplyBinding{destinationID: destination}
		for i, entry := range entries {
			if i/16 != binding/8 {
				continue
			}
			slot := fmt.Sprintf("joint-%02d-%s", binding, entry.Name)
			row.targets = append(row.targets, outputApplyTarget{entryName: entry.Name, target: hermeticNativeOutputTarget(slot, slot, contract.OutputEncodingRaw, hermeticNumberPolicy("test-policy", []uint64{1, 9}))})
		}
		out.bindings = append(out.bindings, row)
	}
	return out
}

func publicPublicationJointFixture(t *testing.T, bindings int) (*fixture, fixtureEnvironment, []ApplyEntryInput, *outputApplyInput) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	env := memoryScenarioEnvironment(t)
	initial := newEnvironmentFixture(t, ctx, env, nil, false)
	f := &fixture{store: env.Store.(*memoryStore), trust: env.Trust.(*fixtureTrust), admission: initial.admission, session: initial.session}
	// Keep the complete immutable publication history without retaining every
	// old selected body in the worker's heap.
	if err := f.store.useFileBodies(filepath.Join(t.TempDir(), "bodies")); err != nil {
		t.Fatal("joint publication file-backed Store", err)
	}
	entries := make([]ApplyEntryInput, ((bindings+7)/8)*16)
	for i := range entries {
		entries[i] = ApplyEntryInput{Name: fmt.Sprintf("entry-%03d", i), ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{f.session.admission.recipient}, InputBytes: []byte("joint initial value"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
	}
	output := publicPublicationJointOutput(entries, bindings)
	f.session = selectAdmittedOutputConfiguration(t, ctx, f.session, env, env.Custody, entries, output)
	f.admission = OpenContext{admission: &f.session.admission}
	selected, err := selectedPublicationRelation(f.session.selectedImage())
	if err != nil || len(selected.coordinates) != bindings*16 || len(selected.markers) != 0 {
		t.Fatal("joint fixture did not start with exactly its requested coordinate union", len(selected.coordinates), len(selected.markers), err)
	}
	return f, env, entries, output
}

func publicPublicationJointPublish(t *testing.T, f *fixture, private publicationPrivate, label string, request PublicationRequest) PublicPublicationResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Minute)
	defer cancel()
	engine := installedPublicationEngine(t, f, private)
	defer engine.Close()
	started := time.Now()
	result := engine.Publish(ctx, fixtureID(f.session.root.Domain, label), request)
	t.Logf("publication call: label=%q elapsed=%s expired=%t outcome=%d reason=%d summary=%d", label, time.Since(started), ctx.Err() == context.DeadlineExceeded, result.Result.Outcome, result.Result.Reason, result.Summary)
	return result
}

func publicPublicationJointReopen(t *testing.T, f *fixture) selectedPublication {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	a := f.session.admission
	admitted, result := admitPublicNormal(ctx, a.domain, f.store.Descriptor(), a.publicBasis(), f.store, a.composition, a.outputInterpreter)
	if result.Outcome != ObservedCurrent {
		t.Fatal("joint observation admission", result)
	}
	session, result := Open(ctx, admitted, f.store)
	if session == nil || result.Outcome != ObservedCurrent {
		t.Fatal("joint cold observation", result)
	}
	f.session, f.admission = session, admitted
	selected, err := selectedPublicationRelation(session.selectedImage())
	if err != nil {
		t.Fatal("joint cold relation", err)
	}
	return selected
}

func publicPublicationNames(entries []ApplyEntryInput) []string {
	names := make([]string, len(entries))
	for i := range entries {
		names[i] = entries[i].Name
	}
	return names
}

func publicPublicationJointRemoveHalf(t *testing.T, f *fixture, env fixtureEnvironment, entries []ApplyEntryInput, output *outputApplyInput, change bool) []ApplyEntryInput {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	remaining := make([]ApplyEntryInput, 0, len(entries)/2)
	keep := make(map[string]bool)
	for i, entry := range entries {
		if i%16 < 8 {
			continue
		}
		if change {
			entry.InputBytes = []byte("joint changed value")
		}
		remaining = append(remaining, entry)
		keep[entry.Name] = true
	}
	desired := &outputApplyInput{}
	for _, binding := range output.bindings {
		next := binding
		next.targets = nil
		for _, target := range binding.targets {
			if keep[target.entryName] {
				next.targets = append(next.targets, target)
			}
		}
		desired.bindings = append(desired.bindings, next)
	}
	// The proposal carries complete named routes for the retained entries.
	for _, entry := range remaining {
		var destinations []string
		for _, binding := range desired.bindings {
			if slices.ContainsFunc(binding.targets, func(target outputApplyTarget) bool { return target.entryName == entry.Name }) {
				destinations = append(destinations, binding.destinationID)
			}
		}
		desired.routes = append(desired.routes, outputApplyRoute{entryName: entry.Name, destinations: destinations})
	}
	a := publicPublicationApplyFixture(env, f)
	engine := a.engineWithValidator(t, f.session, remaining, currentApplyRecipients(f.session.registry()), installedOutputValidator(t, f.session), nil)
	publicOutputApplyProposal(&engine.installation.PublicConfiguration, desired)
	result := engine.Apply(ctx, fixtureID(env.Domain, "public joint remove half"), remaining)
	if result.Result.Outcome != ObservedCurrent {
		t.Fatal("public joint removal", result.Result)
	}
	publicPublicationJointReopen(t, f)
	configuration := installedOutputConfiguration(t, ctx, f.session)
	selected, err := selectedPublicationRelation(f.session.selectedImage())
	active, retired := 0, 0
	for _, coordinate := range selected.coordinates {
		if coordinate.BindingState == contract.PublicationBindingActive {
			active++
		} else {
			retired++
		}
	}
	if err != nil || len(configuration.Bindings) != len(output.bindings) || len(selected.coordinates) != len(output.bindings)*16 || active != len(output.bindings)*8 || retired != len(output.bindings)*8 {
		t.Fatal("joint active/retired workload differs", len(configuration.Bindings), active, retired, err)
	}
	return remaining
}

func publicPublicationRetiredIDs(t *testing.T, f *fixture) []contract.ID {
	t.Helper()
	selected, err := selectedPublicationRelation(f.session.selectedImage())
	if err != nil {
		t.Fatal(err)
	}
	var ids []contract.ID
	for id, row := range selected.coordinates {
		if row.BindingState == contract.PublicationBindingRetired {
			ids = append(ids, id)
		}
	}
	slices.SortFunc(ids, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	return ids
}

// full_only: true
func TestInstalledPublicPublicationJointCapacityBoundary(t *testing.T) {
	f, env, entries, output := publicPublicationJointFixture(t, 64)
	controlled := newPublicationControlledPrivate()
	// One exact target requires create-empty then write-value. The remaining
	// 1,023 targets require one action, so only the invocation-send limit is
	// exceeded: 1,025 actions still fit the 2,048-marker count allowance.
	oneOver := controlled.callbacks()
	firstSlot := output.bindings[0].targets[0].target.CanonicalTarget
	hermeticPublicationTargetFacts(t, f, func(target *contract.OutputTarget) {
		if target.CanonicalTarget == firstSlot {
			target.Capabilities &^= contract.OutputCapabilityCreateWithValue
			target.CreateValueBounds = contract.OutputPayloadBounds{}
		}
	})

	creates, cas, signs := f.store.creates, f.store.cas, f.trust.signs
	excess := publicPublicationJointPublish(t, f, oneOver, "joint 1025 actions", PublicationRequest{Names: publicPublicationNames(entries)})
	if excess.Output != nil || excess.Result.Outcome != AdmissionRefused || excess.Result.Reason != CapacityExceeded || len(controlled.owners) != 0 || f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs {
		t.Fatal("one-over invocation action allowance reached private work", excess.Result)
	}
	hermeticPublicationTargetFacts(t, f, func(target *contract.OutputTarget) {
		target.Capabilities = contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot | contract.OutputCapabilityCreateSetsPolicy | contract.OutputCapabilityWriteSetsPolicy
		target.CreateValueBounds = contract.OutputPayloadBounds{Maximum: 65536}
	})
	publicPublicationWriteAndDelete(t, f, env, entries, output, 1024)
}

// full_only: false
func TestInstalledPublicPublicationSmallWriteAndDeletion(t *testing.T) {
	f, env, entries, output := publicPublicationJointFixture(t, 1)
	publicPublicationWriteAndDelete(t, f, env, entries, output, 16)
}

func publicPublicationWriteAndDelete(t *testing.T, f *fixture, env fixtureEnvironment, entries []ApplyEntryInput, output *outputApplyInput, coordinates int) {
	t.Helper()
	started := time.Now()
	initial := publicPublicationJointReopen(t, f)
	if len(initial.coordinates) != coordinates || len(initial.markers) != 0 {
		t.Fatal("initial publication set differs")
	}
	controlled := newPublicationControlledPrivate()
	birthStarted := time.Now()
	firstOwnerElapsed := time.Duration(-1)
	controlled.configureOwner = func(*publicationControlledOwner) {
		if firstOwnerElapsed < 0 {
			firstOwnerElapsed = time.Since(birthStarted)
		}
	}
	beforeBirthChecks, beforeBirthCreates, beforeBirthCAS, beforeBirthSigns := controlled.checks, f.store.creates, f.store.cas, f.trust.signs
	birth := publicPublicationJointPublish(t, f, controlled.callbacks(), "joint births", PublicationRequest{Names: publicPublicationNames(entries)})
	prepared, armed, sent, retired := 0, 0, 0, 0
	for _, owner := range controlled.owners {
		prepared += owner.prepared
		armed += owner.armed
		sent += owner.sent
		retired += owner.retired
	}
	var dispositions [6]int
	targets, actionRows, admissionReasons, otherReasons := 0, 0, 0, 0
	if birth.Output != nil {
		targets = len(birth.Output.Entries)
		for _, target := range birth.Output.Entries {
			for _, action := range target.Actions {
				actionRows++
				if int(action.Disposition) < len(dispositions) {
					dispositions[action.Disposition]++
				}
				if action.CoreReason == uint16(AdmissionInvalid) {
					admissionReasons++
				} else if action.CoreReason != 0 {
					otherReasons++
				}
			}
		}
	}
	t.Logf("joint birth progress: total_elapsed=%s birth_elapsed=%s first_owner_elapsed=%s outcome=%d reason=%d summary=%d targets=%d actions=%d owners=%d checks=%d prepared=%d armed=%d sent=%d retired=%d noop=%d not_sent=%d acknowledged=%d qualified_no_effect=%d unknown=%d admission_reasons=%d other_reasons=%d creates=%d cas=%d signs=%d", time.Since(started), time.Since(birthStarted), firstOwnerElapsed, birth.Result.Outcome, birth.Result.Reason, birth.Summary, targets, actionRows, len(controlled.owners), controlled.checks-beforeBirthChecks, prepared, armed, sent, retired, dispositions[contract.PublicationNoOp], dispositions[contract.PublicationNotSent], dispositions[contract.PublicationOutcomeAcknowledged], dispositions[contract.PublicationOutcomeQualifiedNoEffect], dispositions[contract.PublicationOutcomeUnknown], admissionReasons, otherReasons, f.store.creates-beforeBirthCreates, f.store.cas-beforeBirthCAS, f.trust.signs-beforeBirthSigns)
	before := publicPublicationJointReopen(t, f)
	t.Logf("joint birth observation: coordinates=%d markers=%d active_owner=%t", len(before.coordinates), len(before.markers), !f.session.root.Generated.ActiveOwner.IsZero())
	assertInstalledPublicationVector(t, birth, contract.PublicationSummaryComplete, coordinates)
	if len(before.coordinates) != coordinates || len(before.markers) != coordinates || len(controlled.owners) != coordinates {
		t.Fatal("joint old coordinate or marker count")
	}
	seen := make(map[contract.ID]bool)
	for _, target := range birth.Output.Entries {
		_, present := initial.coordinates[target.CoordinateID]
		if !present || len(target.Actions) != 1 || seen[target.CoordinateID] {
			t.Fatal("birth changed the exact coordinate set")
		}
		seen[target.CoordinateID] = true
		row := target.Actions[0]
		marker := before.markers[row.AttemptID]
		if row.Action != contract.PublicationCreateWithValue || row.Disposition != contract.PublicationOutcomeAcknowledged || before.coordinates[target.CoordinateID].OwnedBirthAttemptID != row.AttemptID || marker.State != contract.PublicationAcknowledged || marker.CoordinateID != target.CoordinateID || marker.OperationID != birth.OperationID || marker.Projection.Action != row.Action {
			t.Fatal("birth action or retained acknowledgement differs")
		}
	}
	publicPublicationJointOwners(t, controlled.owners, coordinates)
	remaining := publicPublicationJointRemoveHalf(t, f, env, entries, output, true)
	deletes := publicPublicationRetiredIDs(t, f)
	selected := publicPublicationJointReopen(t, f)
	beforeEffects := len(controlled.owners)
	result := publicPublicationJointPublish(t, f, controlled.callbacks(), "joint new actions", PublicationRequest{Names: publicPublicationNames(remaining), DeleteCoordinates: deletes})
	if result.Summary != contract.PublicationSummaryComplete {
		t.Logf("joint writes and deletes: expected=%d entered=%d", coordinates, len(controlled.owners)-beforeEffects)
	}
	assertInstalledPublicationVector(t, result, contract.PublicationSummaryComplete, coordinates)
	after := publicPublicationJointReopen(t, f)
	writes, removals := 0, 0
	clear(seen)
	for _, target := range result.Output.Entries {
		coordinate, present := selected.coordinates[target.CoordinateID]
		if !present || seen[target.CoordinateID] || len(target.Actions) != 1 || target.Actions[0].Disposition != contract.PublicationOutcomeAcknowledged {
			t.Fatal("joint action vector is incomplete")
		}
		seen[target.CoordinateID] = true
		row := target.Actions[0]
		marker := after.markers[row.AttemptID]
		if _, old := before.markers[row.AttemptID]; old || marker.State != contract.PublicationAcknowledged || marker.CoordinateID != target.CoordinateID || marker.OperationID != result.OperationID || marker.Projection.Action != row.Action || after.coordinates[target.CoordinateID].OwnedBirthAttemptID != before.coordinates[target.CoordinateID].OwnedBirthAttemptID {
			t.Fatal("new action reused an Attempt or changed its birth")
		}
		switch target.Actions[0].Action {
		case contract.PublicationWriteValue:
			if coordinate.BindingState != contract.PublicationBindingActive || after.coordinates[target.CoordinateID].LastValueAckAttemptID != row.AttemptID {
				t.Fatal("write targeted a retired coordinate")
			}
			writes++
		case contract.PublicationDeleteOwned:
			if coordinate.BindingState != contract.PublicationBindingRetired || after.coordinates[target.CoordinateID].LastDeleteAckAttemptID != row.AttemptID {
				t.Fatal("delete lost its exact target or acknowledgement")
			}
			removals++
		default:
			t.Fatal("unexpected joint action", target.Actions[0].Action)
		}
	}
	if writes != coordinates/2 || removals != coordinates/2 || len(after.coordinates) != coordinates || len(after.markers) != coordinates*2 {
		t.Fatal("joint marker/action count differs", writes, removals, len(after.markers))
	}
	publicPublicationJointOwners(t, controlled.owners[beforeEffects:], coordinates)
	for id, marker := range before.markers {
		if after.markers[id] != marker {
			t.Fatal("joint transition replaced retained birth evidence")
		}
	}
}

func publicPublicationJointOwners(t *testing.T, owners []*publicationControlledOwner, count int) {
	t.Helper()
	if len(owners) != count {
		t.Fatal("private owner count differs", len(owners), count)
	}
	for _, owner := range owners {
		if owner.prepared != 1 || owner.armed != 1 || owner.sent != 1 || owner.retired != 1 {
			t.Fatal("private action was not sent and retired exactly once", owner.prepared, owner.armed, owner.sent, owner.retired)
		}
	}
}

func publicPublicationUnknownRounds(t *testing.T, f *fixture, entries []ApplyEntryInput, coordinates int) (*publicationControlledPrivate, []contract.ID) {
	t.Helper()
	controlled := newPublicationControlledPrivate()
	controlled.evidence = contract.PublicationUnproved
	previous := publicPublicationJointReopen(t, f)
	if len(previous.coordinates) != coordinates || len(previous.markers) != 0 {
		t.Fatal("initial unknown publication set differs")
	}
	var blockers []contract.ID
	for round := 0; round < 2; round++ {
		roundStarted, firstOwner := time.Now(), len(controlled.owners)
		result := publicPublicationJointPublish(t, f, controlled.callbacks(), fmt.Sprintf("joint unknown round %d", round), PublicationRequest{Names: publicPublicationNames(entries), RepublishAfterUnknown: blockers})
		var dispositions [6]int
		targets, actions := 0, 0
		if result.Output != nil {
			targets = len(result.Output.Entries)
			for _, target := range result.Output.Entries {
				for _, action := range target.Actions {
					actions++
					if int(action.Disposition) < len(dispositions) {
						dispositions[action.Disposition]++
					}
				}
			}
		}
		prepared, armed, sent, retired := 0, 0, 0, 0
		for _, owner := range controlled.owners[firstOwner:] {
			prepared += owner.prepared
			armed += owner.armed
			sent += owner.sent
			retired += owner.retired
		}
		t.Logf("joint uncertainty progress: round=%d elapsed=%s outcome=%d reason=%d summary=%d targets=%d actions=%d prepared=%d armed=%d sent=%d retired=%d noop=%d not_sent=%d acknowledged=%d qualified_no_effect=%d unknown=%d", round, time.Since(roundStarted), result.Result.Outcome, result.Result.Reason, result.Summary, targets, actions, prepared, armed, sent, retired, dispositions[contract.PublicationNoOp], dispositions[contract.PublicationNotSent], dispositions[contract.PublicationOutcomeAcknowledged], dispositions[contract.PublicationOutcomeQualifiedNoEffect], dispositions[contract.PublicationOutcomeUnknown])
		assertInstalledPublicationVector(t, result, contract.PublicationSummaryUnknown, coordinates)
		selected := publicPublicationJointReopen(t, f)
		blockers = nil
		for id, marker := range selected.markers {
			if marker.State == contract.PublicationUnknown || marker.State == contract.PublicationMayHaveEntered {
				blockers = append(blockers, id)
			}
		}
		t.Logf("joint saturation observation: round=%d coordinates=%d markers=%d blockers=%d active_owner=%t", round, len(selected.coordinates), len(selected.markers), len(blockers), !f.session.root.Generated.ActiveOwner.IsZero())
		if len(selected.coordinates) != coordinates || len(selected.markers) != (round+1)*coordinates || len(blockers) != (round+1)*coordinates {
			t.Fatal("joint unresolved prefix has wrong complete marker count", len(blockers))
		}
		seen, attempts := make(map[contract.ID]bool), make(map[contract.ID]bool)
		for _, target := range result.Output.Entries {
			_, present := previous.coordinates[target.CoordinateID]
			if !present || seen[target.CoordinateID] || len(target.Actions) != 1 {
				t.Fatal("unknown publication changed the exact coordinate set")
			}
			seen[target.CoordinateID] = true
			row := target.Actions[0]
			marker, found := selected.markers[row.AttemptID]
			_, old := previous.markers[row.AttemptID]
			if row.Action != contract.PublicationCreateWithValue || row.Disposition != contract.PublicationOutcomeUnknown || !found || old || attempts[row.AttemptID] || marker.State != contract.PublicationUnknown || marker.CoordinateID != target.CoordinateID || marker.OperationID != result.OperationID || marker.Projection.Action != row.Action {
				t.Fatal("unknown action did not retain one fresh exact Attempt")
			}
			attempts[row.AttemptID] = true
			if len(publicationBlockers(selected, target.CoordinateID)) != round+1 || round == 1 && (selected.coordinates[target.CoordinateID].LateEffectRisk == 0 || row.LateWriteRisk == 0) {
				t.Fatal("unknown action lost its blockers or late-effect warning")
			}
		}
		for id, marker := range previous.markers {
			if selected.markers[id] != marker {
				t.Fatal("new unknown attempt changed prior evidence")
			}
		}
		publicPublicationJointOwners(t, controlled.owners[firstOwner:], coordinates)
		previous = selected
		slices.SortFunc(blockers, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	}
	request := PublicationRequest{Names: publicPublicationNames(entries)}
	owners, creates, cas, signs := len(controlled.owners), f.store.creates, f.store.cas, f.trust.signs
	blocked := publicPublicationJointPublish(t, f, controlled.callbacks(), "joint complete blockers", request)
	assertInstalledPublicationVector(t, blocked, contract.PublicationSummaryUnknown, coordinates)
	all := make(map[contract.ID]bool)
	for _, target := range blocked.Output.Entries {
		for _, row := range target.Actions {
			if row.Disposition != contract.PublicationOutcomeUnknown || row.LateWriteRisk == 0 || len(row.BlockerIDs) != 2 {
				t.Fatal("blocked result lost its exact blockers or warning")
			}
			for _, id := range row.BlockerIDs {
				if all[id] || previous.markers[id].CoordinateID != target.CoordinateID {
					t.Fatal("blocker escaped its owning coordinate")
				}
				all[id] = true
			}
		}
	}
	if len(all) != coordinates*2 {
		t.Fatal("public saturation truncated blocker union", len(all))
	}
	if len(controlled.owners) != owners || f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs {
		t.Fatal("default blocked publication acquired effects")
	}
	return controlled, blockers
}

// full_only: false
func TestInstalledPublicPublicationSmallUnknownHistory(t *testing.T) {
	f, _, entries, _ := publicPublicationJointFixture(t, 1)
	controlled, blockers := publicPublicationUnknownRounds(t, f, entries, 16)
	before := bytes.Clone(f.session.body)
	owners, creates, cas, signs := len(controlled.owners), f.store.creates, f.store.cas, f.trust.signs
	for _, ids := range [][]contract.ID{{blockers[0]}, {blockers[0], blockers[0]}, {fixtureID(f.session.root.Domain, "foreign blocker")}} {
		result := publicPublicationJointPublish(t, f, controlled.callbacks(), "joint incomplete blocker authorization", PublicationRequest{Names: publicPublicationNames(entries), RepublishAfterUnknown: ids})
		if result.Result.Outcome != AdmissionRefused || result.Output != nil || len(controlled.owners) != owners || f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs {
			t.Fatal("inexact blocker authorization acquired effects", result.Result)
		}
	}
	publicPublicationJointReopen(t, f)
	if !bytes.Equal(before, f.session.body) {
		t.Fatal("blocked requests changed selected state")
	}
}

// full_only: true
func TestInstalledPublicPublicationSaturatedBlockersRefuseNewActions(t *testing.T) {
	f, env, entries, output := publicPublicationJointFixture(t, 64)
	controlled, blockers := publicPublicationUnknownRounds(t, f, entries, 1024)
	remaining := publicPublicationJointRemoveHalf(t, f, env, entries, output, false)
	selected, err := selectedPublicationRelation(f.session.selectedImage())
	if err != nil || len(selected.markers) != 2048 {
		t.Fatal("removal discarded saturated unresolved history", err)
	}
	for _, id := range blockers {
		if _, ok := selected.markers[id]; !ok {
			t.Fatal("retirement discarded an exact blocker")
		}
	}
	request := PublicationRequest{Names: publicPublicationNames(remaining), DeleteCoordinates: publicPublicationRetiredIDs(t, f)}
	owners, creates, cas, signs := len(controlled.owners), f.store.creates, f.store.cas, f.trust.signs
	before := bytes.Clone(f.session.body)
	request.RepublishAfterUnknown = blockers
	refused := publicPublicationJointPublish(t, f, controlled.callbacks(), "joint saturated refuses new marker", request)
	if refused.Output != nil || refused.Result.Outcome != AdmissionRefused || refused.Result.Reason != CapacityExceeded || len(controlled.owners) != owners || f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs {
		t.Fatal("saturated republish crossed private preparation or persistence", refused.Result)
	}
	publicPublicationJointReopen(t, f)
	if !bytes.Equal(before, f.session.body) {
		t.Fatal("capacity refusal changed selected state")
	}
	coordinate := request.DeleteCoordinates[0]
	var exactBlockers []contract.ID
	for _, id := range blockers {
		if selected.markers[id].CoordinateID == coordinate {
			exactBlockers = append(exactBlockers, id)
		}
	}
	oneOver := publicPublicationJointPublish(t, f, controlled.callbacks(), "joint exactly 2049 markers", PublicationRequest{DeleteCoordinates: []contract.ID{coordinate}, RepublishAfterUnknown: exactBlockers})
	if len(exactBlockers) != 2 || oneOver.Output != nil || oneOver.Result.Outcome != AdmissionRefused || oneOver.Result.Reason != CapacityExceeded || len(controlled.owners) != owners || f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs {
		t.Fatal("exactly one marker over capacity acquired private work", oneOver.Result)
	}
}

// full_only: false
func TestInstalledPublicPublicationRawAndBase64ExactGroupBoundary(t *testing.T) {
	for _, encoding := range []string{"raw", "base64"} {
		t.Run(encoding, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f, env, _, _, _ := nativePublicationFixture(t, false)
			controlled := newPublicationControlledPrivate()
			private := controlled.callbacks()
			rawLength := 65536
			if encoding == "base64" {
				rawLength = 49152
			}
			entries := []ApplyEntryInput{
				{Name: "alpha", ValueSource: contract.Supplied, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{f.session.admission.recipient}, InputBytes: bytes.Repeat([]byte{0xa5}, rawLength)},
				{Name: "omega", ValueSource: contract.Supplied, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{f.session.admission.recipient}, InputBytes: bytes.Repeat([]byte{0x5a}, rawLength)},
			}
			output := nativePublicationOutput(entries, []uint64{1, 9})
			for i := range output.bindings[0].targets {
				output.bindings[0].targets[i].target.PayloadEncoding = hermeticOutputEncoding(encoding)
			}
			output.groups = [][]string{{"alpha", "omega"}}
			f.session = selectAdmittedOutputConfiguration(t, ctx, f.session, env, env.Custody, entries, output)
			f.admission = OpenContext{admission: &f.session.admission}
			var checked []uint32
			check := private.Check
			private.Check = func(ctx context.Context, input publicationActionCheckInput) (publicationActionCheckFacts, error) {
				checked = append(checked, input.PayloadLength)
				return check(ctx, input)
			}
			result := installedPublicationEngine(t, f, private).Publish(ctx, fixtureID(env.Domain, "public exact "+encoding+" group"), PublicationRequest{Names: []string{"alpha", "omega"}})
			assertInstalledPublicationVector(t, result, contract.PublicationSummaryComplete, 2)
			// Padded Base64 of 49,152 raw bytes is exactly 65,536 bytes.
			// Encoding either exact-limit request twice cannot fit this profile.
			if len(checked) < 2 {
				t.Fatal("complete group did not check both targets")
			}
			for _, length := range checked {
				if length != 65536 {
					t.Fatal("exact complete-group payload length differs", length)
				}
			}
			for _, target := range result.Output.Entries {
				if len(target.Actions) != 1 || target.Actions[0].Disposition != contract.PublicationOutcomeAcknowledged {
					t.Fatal("exact complete-group boundary refused a member")
				}
			}
		})
	}
	for _, encoding := range []string{"raw", "base64"} {
		t.Run("native-literals/"+encoding, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f, env, input, private, _ := nativePublicationFixture(t, true, "plain-encoding-target", "secret-encoding-target")
			entries := installedApplyCurrentInput(f.session)
			output := nativePublicationOutput(entries, []uint64{1, 9})
			for i := range output.bindings[0].targets {
				slot := "plain-encoding-target"
				if entries[i].ConfidentialityClass == contract.Secret {
					slot = "secret-encoding-target"
				}
				hermeticRetargetOutput(&output.bindings[0].targets[i].target, slot, slot)
				output.bindings[0].targets[i].target.PayloadEncoding = hermeticOutputEncoding(encoding)
			}
			output.groups = [][]string{input.names}
			f.session = selectAdmittedOutputConfiguration(t, ctx, f.session, env, env.Custody, entries, output)
			f.admission = OpenContext{admission: &f.session.admission}
			result := installedPublicationEngine(t, f, private).Publish(ctx, fixtureID(env.Domain, "public complete native literals "+encoding), PublicationRequest{Names: input.names})
			assertInstalledPublicationVector(t, result, contract.PublicationSummaryComplete, 2)
			// The existing child compares the whole raw or encoded payload with
			// cHJpdmF0ZSBkYXRh and ZW5rdiBmaXJzdCBzZWNyZXQgdGVzdCB2YWx1ZQ==.
			// Those fixed literals do not call the production encoder.
			for _, target := range result.Output.Entries {
				if len(target.Actions) != 1 || target.Actions[0].Disposition != contract.PublicationOutcomeAcknowledged {
					t.Fatal("complete native group changed an independently specified payload")
				}
			}
		})
	}
}

package core

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

func selectOutputConfiguration(t *testing.T, f *fixture, entries []ApplyEntryInput, output *outputApplyInput) contract.OutputConfiguration {
	t.Helper()
	installOutputFixtureSource(t, f.session, output)
	parent := admitSuppliedOutputComparison(t, f.session, nil, entries, output)
	c, result := f.session.compareWithOutput(t.Context(), entries, output, parent)
	if c == nil || result.Outcome != ObservedCurrent {
		t.Fatal("output comparison", result)
	}
	candidate := prepareOutputComparison(t, f.session, c, parent, f.trust)
	if result := f.session.Select(t.Context(), candidate); result.Outcome != ObservedCurrent {
		t.Fatal("output selection", result)
	}
	// Keep the passive interpreter across this cold selection and later
	// fixture reopens. It is an independent composition fact.
	admission := OpenContext{admission: &f.session.admission}
	opened, result := Open(t.Context(), admission, f.store)
	if opened == nil {
		t.Fatal("cold selected output", result)
	}
	f.session = opened
	f.admission = OpenContext{admission: &opened.admission}
	configuration, result := opened.currentOutputConfigurationForApply(t.Context())
	if result.Outcome != 0 || opened.publicationProof == nil || !opened.publicationProof.validFor(opened.selectedImage()) {
		t.Fatal("complete selected output relation", result)
	}
	return configuration
}

func selectAdmittedOutputConfiguration(t testing.TB, operationCtx context.Context, s *StateSession, env fixtureEnvironment, keys *custody.Fixture,
	entries []ApplyEntryInput, output *outputApplyInput, registry ...contract.GeneratorImplementation) *StateSession {
	t.Helper()
	for i := range entries {
		var encoding uint8
		for _, binding := range output.bindings {
			for _, target := range binding.targets {
				if target.entryName != entries[i].Name {
					continue
				}
				if encoding != 0 && encoding != target.target.PayloadEncoding {
					t.Fatal("positive output fixture has conflicting entry encodings", entries[i].Name)
				}
				encoding = target.target.PayloadEncoding
			}
		}
		if encoding != 0 {
			entries[i].OutputEncoding = encoding
		}
	}
	installOutputFixtureSource(t, s, output)
	parent := admitSuppliedOutputComparison(t, s, keys, entries, output, registry...)
	c, result := s.compareWithOutput(t.Context(), entries, output, parent)
	if c == nil || result.Outcome != ObservedCurrent {
		t.Fatal("private output comparison", result)
	}
	candidate := prepareOutputComparison(t, s, c, parent, env.Trust)
	selected, result := s.selectCandidate(t.Context(), candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("private output selection", result)
	}
	keys.RetireApply()
	return generatedLifecycleReopen(t, operationCtx, selected, env.Store)
}

// Transition fixtures supply an independent public target table. This passive
// adapter tests state relations; installed provider tests own address derivation.
func outputFixtureDestination(name, service string, capabilities contract.OutputActionCapabilities, policy contract.OutputPolicy) contract.OutputDestination {
	settings, err := json.Marshal(struct {
		Destination string `json:"destination"`
	}{name})
	if err != nil {
		panic(err)
	}
	config := "fixture/" + name + "/config/v1"
	if service == "test-output/service/v1" {
		config = publicationTestConfigContract
	}
	return contract.OutputDestination{ConfigContractID: config, ServiceContractID: service, CanonicalSettings: settings, Capabilities: capabilities, Policy: policy}
}

func outputFixtureTarget(service, physical, locator string, encoding uint8, capabilities contract.OutputActionCapabilities, policy contract.OutputPolicy) contract.OutputTarget {
	return contract.OutputTarget{ServiceContractID: service, TargetContractID: "fixture/target/v1", CanonicalTarget: physical, ConsumerLocator: locator, TargetData: []byte("target:" + physical), PayloadEncoding: encoding, Capabilities: capabilities, CreateValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, Policy: policy}
}

func installOutputFixtureSource(t testing.TB, s *StateSession, input *outputApplyInput) {
	t.Helper()
	if input == nil || s == nil {
		return
	}
	type sourceRow struct {
		destination contract.OutputDestination
		targets     map[string]contract.OutputTarget
	}
	rows := make(map[string]sourceRow)
	routes := make(map[string][]string)
	for i := range input.bindings {
		binding := &input.bindings[i]
		if binding.destination.ServiceContractID == "" && len(binding.targets) != 0 {
			target := binding.targets[0].target
			binding.destination = outputFixtureDestination(binding.destinationID, target.ServiceContractID, target.Capabilities, target.Policy)
			if target.ServiceContractID == "test-output/service/v1" {
				binding.destination.ConfigContractID = publicationTestConfigContract
			}
		}
		row := sourceRow{destination: ownOutputDestination(binding.destination), targets: make(map[string]contract.OutputTarget)}
		for _, named := range binding.targets {
			target := ownOutputTarget(named.target)
			row.targets[named.entryName] = target
			routes[named.entryName] = append(routes[named.entryName], binding.destinationID)
		}
		rows[binding.destinationID] = row
	}
	if len(input.routes) == 0 {
		names := make([]string, 0, len(routes))
		for name := range routes {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			slices.Sort(routes[name])
			input.routes = append(input.routes, outputApplyRoute{entryName: name, destinations: routes[name]})
		}
	}
	before := s.admission.outputInterpreter
	s.admission.outputInterpreter = func(ctx context.Context, id string, destination contract.OutputDestination, name string, encoding uint8) (contract.OutputTarget, error) {
		if err := ctx.Err(); err != nil {
			return contract.OutputTarget{}, err
		}
		if row, exists := rows[id]; exists {
			if !reflect.DeepEqual(destination, row.destination) {
				return contract.OutputTarget{}, contract.ErrRecord
			}
			target, ok := row.targets[name]
			if !ok {
				return contract.OutputTarget{}, contract.ErrRecord
			}
			target.EntryIncarnationID = contract.ID{}
			target.PayloadEncoding = encoding
			return ownOutputTarget(target), nil
		}
		if before != nil {
			return before(ctx, id, destination, name, encoding)
		}
		return contract.OutputTarget{}, contract.ErrRecord
	}
}

// Keep the admitted parent and Comparison alive across terminal preparation.
func checkConsumedOutputComparison(t testing.TB, s *StateSession, c *Comparison, permit *AdmittedParentTransition,
	parent *AdmittedParentComparison, witness *contract.NormalOutputTransition, descriptor contract.OutputConfigurationDescriptor, records []contract.SupportRecord) {
	t.Helper()
	if !s.prepared || !permit.used {
		t.Error("terminal output preparation did not consume session and permit")
	}
	if c.outputIntent != nil || c.outputAfter != nil && c.outputAfter.transition != nil {
		t.Error("consumed output comparison retained input or planned witness")
	}
	if c.support != parent.support || c.support.Output != parent.support.Output || !reflect.DeepEqual(parent.support.Output, witness) {
		t.Error("terminal output preparation changed the admitted parent witness")
	}
	if c.outputAfter != nil && (c.outputAfter.descriptor != descriptor || !reflect.DeepEqual(c.outputAfter.records, records)) {
		t.Error("terminal output preparation changed descriptor or records")
	}
}

func prepareOutputComparison(t testing.TB, s *StateSession, c *Comparison, parent *AdmittedParentComparison, trust contract.Trust) *Candidate {
	t.Helper()
	permit := admit(t, s, c)
	if parent == nil || parent.support == nil || parent.support.Output == nil || c.outputIntent == nil {
		t.Fatal("output fixture has no independently admitted witness and owned input")
	}
	witness, err := parent.support.Output.Own()
	if err != nil {
		t.Fatal("output parent witness snapshot", err)
	}
	var descriptor contract.OutputConfigurationDescriptor
	var records []contract.SupportRecord
	if c.outputAfter != nil {
		descriptor, records = c.outputAfter.descriptor, slices.Clone(c.outputAfter.records)
		for i := range records {
			records[i].Body = bytes.Clone(records[i].Body)
		}
	}
	input, projection := c.outputIntent, c.outputAfter
	var transition *contract.NormalOutputTransition
	if projection != nil {
		transition = projection.transition
	}
	store := requireAdmittedMemoryStore(t, s.store)
	signer, ok := underlyingAdmittedFixtureTrust(trust)
	if !ok {
		t.Fatal("output fixture has no signing counters")
	}
	creates, cas, signs := store.creates, store.cas, signer.signs
	bad := *permit
	bad.predecessorDigest[0] ^= 1
	for _, refusal := range []struct {
		permit *AdmittedParentTransition
		trust  contract.Trust
		want   Result
	}{
		{&bad, trust, refused(AdmissionInvalid)}, {permit, nil, refused(ConstructionMismatch)},
	} {
		if candidate, result := s.Prepare(t.Context(), c, refusal.permit, refusal.trust); candidate != nil || result != refusal.want {
			t.Fatal("early output preparation refusal", result)
		}
		if s.prepared || permit.used || c.outputIntent != input || c.outputAfter != projection || projection != nil && projection.transition != transition || !reflect.DeepEqual(parent.support.Output, witness) || store.creates != creates || store.cas != cas || signer.signs != signs {
			t.Fatal("early output refusal consumed ownership or caused effects")
		}
	}
	var counter *changedCryptoReply
	if c.operation != nil {
		counter = &changedCryptoReply{inner: c.operation.adapter}
		c.operation.adapter = counter
	}
	candidate, result := s.Prepare(t.Context(), c, permit, trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("valid output preparation after early refusal", result)
	}
	checkConsumedOutputComparison(t, s, c, permit, parent, witness, descriptor, records)
	creates, cas, signs = store.creates, store.cas, signer.signs
	exchanges := 0
	if counter != nil {
		exchanges = counter.exchanges
	}
	if repeated, result := s.Prepare(t.Context(), c, permit, trust); repeated != nil || result != refused(AdmissionInvalid) {
		t.Fatal("repeated output preparation was accepted", result)
	}
	if store.creates != creates || store.cas != cas || signer.signs != signs || counter != nil && counter.exchanges != exchanges {
		t.Fatal("repeated output preparation caused effects")
	}
	if c.outputChanged {
		if _, err := planTransition(t.Context(), c); err == nil {
			t.Error("consumed changed-output comparison replanned without required input")
		}
	}
	return candidate
}

// full_only: false
func TestOrdinaryOutputPreparationKeepsLateConfigurationReadResult(t *testing.T) {
	for _, tc := range []struct {
		name string
		read contract.ReadResult
		want Result
	}{
		{"missing", contract.ReadResult{Status: contract.ReadMissing}, Result{Outcome: EvidenceUnavailable, Reason: MissingSelectedObject}},
		{"unavailable", contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}, Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonTransport}},
		{"invalid", contract.ReadResult{Status: contract.ReadInvalid}, Result{Outcome: IntegrityFailure, Reason: InvalidFormat}},
		{"invalid-body", contract.ReadResult{Status: contract.ReadOK, Body: []byte{1}}, Result{Outcome: IntegrityFailure, Reason: InvalidReference}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			f := newFixture(t, 1, false, 1)
			entries := f.session.currentEntryInputs()
			output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{outputConfigurationTarget(entries[0].Name, "app")}}}}
			installOutputFixtureSource(t, f.session, output)
			parent := admitSuppliedOutputComparison(t, f.session, nil, entries, output)
			comparison, result := f.session.compareWithOutput(ctx, entries, output, parent)
			if comparison == nil || result.Outcome != ObservedCurrent || !comparison.outputChanged || comparison.operation != nil {
				t.Fatal("healthy plain output comparison", result)
			}
			permit := admit(t, f.session, comparison)
			id, err := contract.OutputConfigurationSliceID(f.session.root.Domain, f.session.root.OutputConfiguration.ConfigurationDigest, 0)
			if err != nil {
				t.Fatal(err)
			}
			var ref format.Ref
			for _, page := range f.session.supportFacts {
				for _, fact := range page.rows {
					if fact.Kind() == contract.OutputConfigurationSliceSupportKind && fact.RecordID() == id {
						ref = page.ref
					}
				}
			}
			if ref.Kind != contract.RequiredSupportKind {
				t.Fatal("selected configuration has no exact physical reference")
			}
			key, err := format.Key(f.session.admission.store.Prefix, ref)
			if err != nil {
				t.Fatal(err)
			}
			reads := 0
			f.store.readHook = func(actual string, read contract.ReadResult) contract.ReadResult {
				if actual == key {
					reads++
				}
				return read
			}
			t.Cleanup(func() { f.store.readHook = nil })
			if _, err := f.session.closureIDsMode(ctx, false); err != nil || reads != 0 {
				t.Fatal("healthy closure consumed the late configuration read", err, reads)
			}
			if _, result := f.session.currentOutputConfigurationForApply(ctx); result.Outcome != 0 || reads == 0 {
				t.Fatal("healthy configuration did not reach its exact read", result, reads)
			}
			reads = 0
			creates, cas, signs := f.store.creates, f.store.cas, f.trust.signs
			before, selectedRoot := contract.Hash(f.session.body), f.session.head.Core.Root
			prepared, used := f.session.prepared, permit.used
			intent, projection := comparison.outputIntent, comparison.outputAfter
			f.store.readHook = func(actual string, read contract.ReadResult) contract.ReadResult {
				if actual == key {
					reads++
					return tc.read
				}
				return read
			}
			candidate, result := f.session.Prepare(ctx, comparison, permit, f.trust)
			if candidate != nil || result != tc.want || reads == 0 {
				t.Fatal("late configuration read lost its exact result", result, reads)
			}
			if f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs ||
				f.session.prepared != prepared || permit.used != used || contract.Hash(f.session.body) != before || f.session.head.Core.Root != selectedRoot ||
				comparison.outputIntent != intent || comparison.outputAfter != projection {
				t.Fatal("late configuration refusal changed ownership or caused effects")
			}
			reads = 0
			_, err = planTransition(ctx, comparison)
			failure, present := selectedReadResult(err)
			if !present || failure != tc.want || reads == 0 || comparison.outputAfter != nil || comparison.outputIntent != intent ||
				f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs ||
				f.session.prepared != prepared || permit.used != used || contract.Hash(f.session.body) != before || f.session.head.Core.Root != selectedRoot {
				t.Fatal("failed output planner lost the read result or retained a projection", failure, reads)
			}
		})
	}
}

// full_only: false
func TestOutputConfigurationGeneratedPreservation(t *testing.T) {
	env, keys, selected, row, effects, author := normalHandoffGeneratedFixture(t, false, true)
	old := *selected.valueEntry(0)
	beforeAccess := selected.root.CurrentAccess
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{outputConfigurationTarget(old.Name, "app")}}}}
	selected = selectAdmittedOutputConfiguration(t, t.Context(), selected, env, keys, selected.currentEntryInputs(), output)
	configuration, result := selected.currentOutputConfigurationForApply(t.Context())
	if result.Outcome != 0 || !reflect.DeepEqual(*selected.valueEntry(0), old) || !reflect.DeepEqual(selected.root.CurrentAccess, beforeAccess) || effects.Load() != 1 {
		t.Fatal("generated binding-only changed canonical value/access or repeated generation", result)
	}
	coordinate := selectedOutputCoordinate(t, selected, "app")
	beforeDescriptor := selected.root.OutputConfiguration
	intent, requestBody := hermeticCloudflareIntent()
	profile := nativeGeneratedFixtureProfile(t, row)
	input := generatedPlanInputWithCurrentGenerated(t, selected, fixtureID(env.Domain, "output preserved generated final"), []string{"second"}, profile, intent)
	input.requestBindings[0].Digest = hermeticCloudflareHTTPRequestDigest(requestBody)
	selected = author.create(selected, input)
	keys.RetireGenerated()
	selected = generatedLifecycleReopen(t, t.Context(), selected, env.Store)
	after, result := selected.currentOutputConfigurationForApply(t.Context())
	if result.Outcome != 0 || selected.root.OutputConfiguration != beforeDescriptor || !reflect.DeepEqual(configuration, after) ||
		!reflect.DeepEqual(selectedOutputCoordinate(t, selected, "app"), coordinate) || effects.Load() != 2 {
		t.Fatal("generated declaration/reservation/final lost selected output", result)
	}
	proposed := selected.currentEntryInputs()
	for i := range proposed {
		if proposed[i].Name == old.Name {
			proposed[i] = suppliedSecret(t, env, old.Name, "generated output source conversion", custody.HermeticCloudflareValue)
		}
	}
	installOutputFixtureSource(t, selected, output)
	parent := admitSuppliedOutputComparison(t, selected, keys, proposed, output, row)
	wantSupport := normalHandoffExpectedSupport(t, parent, old, row)
	comparison, result := selected.compareWithOutput(t.Context(), proposed, output, parent)
	if comparison == nil || result.Outcome != ObservedCurrent {
		t.Fatal("private output comparison", result)
	}
	candidate := prepareOutputComparison(t, selected, comparison, parent, env.Trust)
	selected, result = selected.selectCandidate(t.Context(), candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("private output selection", result)
	}
	keys.RetireApply()
	selected = generatedLifecycleReopen(t, t.Context(), selected, env.Store)
	after, result = selected.currentOutputConfigurationForApply(t.Context())
	fresh := selected.valueEntry(0)
	want := coordinate
	want.ActiveBindingIncarnationID = after.Bindings[0].IncarnationID
	if result.Outcome != 0 || fresh.ValueSource != contract.Supplied || fresh.Incarnation == old.Incarnation ||
		after.Bindings[0].IncarnationID != configuration.Bindings[0].IncarnationID || after.Bindings[0].Targets[0].EntryIncarnationID != fresh.Incarnation ||
		!reflect.DeepEqual(selectedOutputCoordinate(t, selected, "app"), want) || effects.Load() != 2 {
		t.Fatal("equal-payload source conversion lost the new entry or retained destination and coordinate", result)
	}
	suppliedIncarnation, suppliedBinding := fresh.Incarnation, after.Bindings[0].IncarnationID
	input = generatedPlanInputWithCurrentGenerated(t, selected, fixtureID(env.Domain, "output supplied to generated"), []string{old.Name}, profile, intent)
	initial := generatedReservationInputForStateIntent(t, selected, input.graph.Request.OperationID, []string{old.Name}, intent, profile, 0, nil, nil,
		generatedWriterCurrentDeclarations(t, selected, []string{old.Name})...)
	input.graph, input.declaration, input.registry, input.recoveryPolicy, input.requestBindings = initial.graph, initial.declaration,
		initial.graph.Request.Registry, initial.graph.Request.RecoveryPolicyID, slices.Clone(initial.requestBindings)
	input.requestBindings[0].Digest = hermeticCloudflareHTTPRequestDigest(requestBody)
	selected = author.create(selected, input)
	keys.RetireGenerated()
	selected = generatedLifecycleReopen(t, t.Context(), selected, env.Store)
	after, result = selected.currentOutputConfigurationForApply(t.Context())
	fresh = selected.valueEntry(0)
	want.ActiveBindingIncarnationID = after.Bindings[0].IncarnationID
	if result.Outcome != 0 || fresh.ValueSource != contract.Generated || fresh.Incarnation == suppliedIncarnation || fresh.Generated.Epoch != 0 ||
		after.Bindings[0].IncarnationID != suppliedBinding || after.Bindings[0].Targets[0].EntryIncarnationID != fresh.Incarnation ||
		!reflect.DeepEqual(selectedOutputCoordinate(t, selected, "app"), want) || effects.Load() != 3 {
		t.Fatal("supplied to generated lost the new entry or retained destination and coordinate", result)
	}
	if check := keys.Consume(t.Context(), sessionConsumerSelection(t, selected, selected.admission.recipient, old.Name), custody.HermeticCloudflareValue); check.Code != contract.CryptoSuccess || !check.ValueMatched || check.Delivery != 1 {
		t.Fatal("source conversion changed generated semantic value", check)
	}
	dutyID, err := contract.GeneratorDutyID(env.Domain, old.Generated.OriginOperationID, old.Generated.OriginAttemptID, 2)
	if err != nil {
		t.Fatal(err)
	}
	work := mustSelectedGeneratedWork(t, selected)
	duty, err := contract.InspectGeneratedDutyRecord(work.records[generatedRecordKey{10, dutyID}].Body)
	if err != nil {
		t.Fatal("source change lost original retirement", err)
	}
	target, err := work.retirementTarget(t.Context(), duty)
	if err != nil || selected.root.Generated.Retiring != 1 || fresh.Generated.RetiringDutyID != dutyID ||
		duty.Support != wantSupport || duty.CompletionClass != old.Generated.CompletionClass || duty.Step != 1 || duty.Status != 1 ||
		target.ResourceID != old.Generated.ResourceIncarnationID || target.ResourceDigest != old.Generated.ResourceDigest || target.Name != old.Name || target.IncarnationID != old.Incarnation {
		t.Fatal("source change redirected or completed the old exact retirement", err)
	}
}

// full_only: false
func TestOutputConfigurationPendingRevocation(t *testing.T) {
	env, f, coordinate, marker := signedPublicationSelectionFixture(t, format.OutputReserveAuth, false)
	entries := f.session.currentEntryInputs()
	target := outputConfigurationTarget(entries[0].Name, coordinate.CanonicalTarget)
	target.target.ServiceContractID = coordinate.ServiceContractID
	target.target.ConsumerLocator, target.target.TargetContractID = coordinate.DeletionConsumerLocator, coordinate.DeletionTargetContractID
	target.target.TargetData = slices.Clone(coordinate.DeletionTargetData)
	target.target.LocatorRequiresCreation = coordinate.LocatorRequiresCreation
	if target.target.LocatorRequiresCreation {
		target.target.ConsumerLocator = ""
	}
	// Newly selected output uses current single/raw; retained deletion facts stay opaque and unchanged.
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{target}}}}
	selected := selectAdmittedOutputConfiguration(t, t.Context(), f.session, env, env.Custody, entries, output)
	configuration, result := selected.currentOutputConfigurationForApply(t.Context())
	if result.Outcome != 0 {
		t.Fatal(result)
	}
	active := coordinate
	active.BindingState, active.ActiveBindingIncarnationID = contract.PublicationBindingActive, configuration.Bindings[0].IncarnationID
	coordinateID := coordinate.CoordinateID
	check := func(s *StateSession, want contract.PublicationCoordinate) {
		t.Helper()
		var foundCoordinate, foundMarker bool
		for _, row := range s.supportRecords() {
			if row.Kind == contract.PublicationCoordinateSupportKind && row.RecordID == coordinateID {
				got, err := contract.InspectPublicationCoordinate(row.Body)
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Fatal("selection lost retained revocation/deletion inputs", err)
				}
				foundCoordinate = true
			}
			if row.Kind == contract.PublicationMarkerSupportKind && row.RecordID == marker.AttemptID {
				got, err := contract.InspectPublicationMarker(row.Body)
				if err != nil || !reflect.DeepEqual(got, marker) {
					t.Fatal("selection changed unresolved action or warning", err)
				}
				foundMarker = true
			}
		}
		if !foundCoordinate || !foundMarker {
			t.Fatal("retained output evidence omitted")
		}
	}
	check(selected, active)
	selected = selectAdmittedOutputConfiguration(t, t.Context(), selected, env, env.Custody, entries, &outputApplyInput{})
	check(selected, coordinate)
	if coordinate.OwnerState == contract.PublicationOwnerNone || coordinate.DeletionTargetRowDigest.IsZero() || coordinate.LatestUnresolvedAttemptID.IsZero() {
		t.Fatal("test did not retain actual uncertain ownership and minimal deletion inputs")
	}
}

// full_only: false
func TestOutputConfigurationReplacementPreservation(t *testing.T) {
	env, keys := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, t.Context(), env)
	f := newEnvironmentFixture(t, t.Context(), run.env, []int{1}, false)
	shared := []contract.ID{f.session.admission.recipient, fixtureID(env.Domain, "reader")}
	slices.SortFunc(shared, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	entries := append(f.session.currentEntryInputs(), sharingSecret(t, env, "selected output replacement", shared))
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{outputConfigurationTarget("secret", "app")}}}}
	f.session = selectAdmittedOutputConfiguration(t, t.Context(), f.session, run.env, keys, entries, output)
	wantDescriptor := f.session.root.OutputConfiguration
	want, result := f.session.currentOutputConfigurationForApply(t.Context())
	if result.Outcome != 0 {
		t.Fatal(result)
	}
	coordinate := selectedOutputCoordinate(t, f.session, "app")
	before, after := replaceReaderInSelectedForName(t, t.Context(), run, f, "secret")
	if !keys.MaterialPreserved(before, after) {
		t.Fatal("reader replacement changed private value material")
	}
	check := func(s *StateSession) {
		t.Helper()
		got, result := s.currentOutputConfigurationForApply(t.Context())
		if result.Outcome != 0 || s.root.OutputConfiguration != wantDescriptor || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(selectedOutputCoordinate(t, s, "app"), coordinate) {
			t.Fatal("replacement lost exact selected output", result)
		}
	}
	check(f.session)
	control := currentControlOf(f.session)
	successor, binding := env.Trust.(*fixtureTrust).Successor(t, control.NormalSigning)
	control.NormalSigning, control.AccessGeneration = binding, control.AccessGeneration+1
	permit := admitAuthorityReplacement(t, f.session, keys, control, contract.SuccessionReplaceAuthority, contract.NormalSigningRole, contract.SuccessionChangeNormalSigner, contract.BindingTableRow{})
	candidate, result := f.session.PrepareSuccession(t.Context(), permit, SuccessionSigners{Authorizer: env.Trust, NormalSuccessor: successor})
	if candidate == nil {
		t.Fatal("output signer succession preparation", result)
	}
	admission := deliverSuccessionBasis(t, candidate)
	if result := f.session.Select(t.Context(), candidate); result.Outcome != ObservedCurrent {
		t.Fatal("output signer succession selection", result)
	}
	selected, result := Open(t.Context(), admission, env.Store)
	if selected == nil {
		t.Fatal("cold output signer succession", result)
	}
	check(selected)
}

func outputConfigurationTarget(name, slot string) outputApplyTarget {
	return outputApplyTarget{entryName: name, target: contract.OutputTarget{ServiceContractID: "aws", TargetContractID: "fixture/target/v1", CanonicalTarget: slot, ConsumerLocator: slot + "?stage=AWSCURRENT", TargetData: []byte("target:" + slot), PayloadEncoding: contract.OutputEncodingRaw, Capabilities: contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot, CreateValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536}}}
}

// full_only: false
func TestOutputConfigurationEmptyEntryRouting(t *testing.T) {
	t.Run("preview_and_selection", func(t *testing.T) {
		f := newFixture(t, 1, false, 1)
		entries := f.session.currentEntryInputs()
		entries[0].Name = ""
		output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{outputConfigurationTarget("", "app")}}},
			routes: []outputApplyRoute{{entryName: "", destinations: []string{"app"}}}}
		incarnation := fixtureID(f.session.root.Domain, "empty entry preview incarnation")
		installOutputFixtureSource(t, f.session, output)
		preview, _, err := outputApplyConfiguration(f.session.root.Domain, output, map[string]contract.ID{"": incarnation}, map[string]contract.ID{"app": fixtureID(f.session.root.Domain, "empty entry preview binding")})
		want := []contract.OutputRoute{{EntryIncarnationID: incarnation, Destinations: []string{"app"}}}
		if err != nil || !reflect.DeepEqual(preview.Routes, want) {
			t.Fatal("preview changed exact empty entry to default", preview.Routes, err)
		}
		configuration := selectOutputConfiguration(t, f, entries, output)
		want[0].EntryIncarnationID = f.session.valueEntry(entrySlot(t, f.session, "")).Incarnation
		if !reflect.DeepEqual(configuration.Routes, want) {
			t.Fatal("cold selected empty entry route changed", configuration.Routes)
		}
	})
	t.Run("named_empty_and_default_keep_complete_sets", func(t *testing.T) {
		f := newFixture(t, 2, false, 1)
		entries := f.session.currentEntryInputs()
		entries[0].Name = ""
		output := &outputApplyInput{bindings: []outputApplyBinding{
			{destinationID: "app", targets: []outputApplyTarget{outputConfigurationTarget("", "app-empty")}},
			{destinationID: "backup", targets: []outputApplyTarget{outputConfigurationTarget(entries[1].Name, "backup-other")}},
		}, routes: []outputApplyRoute{
			{entryName: "", destinations: []string{"app"}},
			{defaultRoute: true, destinations: []string{"backup"}},
		}}
		installOutputFixtureSource(t, f.session, output)
		if !checkOutputApplyInput(f.session.root.Domain, entries, output) {
			t.Fatal("named empty and default share one key")
		}
		owned := ownOutputApplyInput(output)
		output.routes[0].entryName = "caller-changed"
		output.routes[0].destinations[0] = "caller-changed"
		if owned.routes[0].defaultRoute || owned.routes[0].entryName != "" || !slices.Equal(owned.routes[0].destinations, []string{"app"}) {
			t.Fatal("private input ownership retained caller route metadata")
		}
		configuration := selectOutputConfiguration(t, f, entries, owned)
		emptyID := f.session.valueEntry(entrySlot(t, f.session, "")).Incarnation
		want := []contract.OutputRoute{{EntryIncarnationID: emptyID, Destinations: []string{"app"}}}
		if !reflect.DeepEqual(configuration.Routes, want) || !slices.Equal(configuration.DefaultDestinations, []string{"backup"}) {
			t.Fatal("named empty and default changed their complete route sets", configuration.Routes)
		}
	})
	t.Run("entry_replaces_default_complete_list", func(t *testing.T) {
		routes := map[outputApplyRouteKey]*outputApplyRoute{
			{defaultRoute: true}: {defaultRoute: true, destinations: []string{"default"}},
			{entry: ""}:          {destinations: []string{"named"}},
		}
		if got := outputApplyRouteFor(routes, ""); got == nil || !slices.Equal(got.destinations, []string{"named"}) {
			t.Fatal("exact empty entry did not replace the default", got)
		}
		if got := outputApplyRouteFor(routes, "other"); got == nil || !slices.Equal(got.destinations, []string{"default"}) {
			t.Fatal("empty entry override leaked to another entry", got)
		}
		routes[outputApplyRouteKey{entry: ""}].destinations = []string{}
		if got := outputApplyRouteFor(routes, ""); got == nil || len(got.destinations) != 0 {
			t.Fatal("empty replacement inherited the default", got)
		}
		delete(routes, outputApplyRouteKey{entry: ""})
		if got := outputApplyRouteFor(routes, ""); got == nil || !slices.Equal(got.destinations, []string{"default"}) {
			t.Fatal("absent replacement did not inherit", got)
		}
	})
	for _, fault := range []string{"nonempty_default_name", "absent_named_entry", "duplicate_exact_key", "missing_target"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t, 2, false, 1)
			entries := f.session.currentEntryInputs()
			entries[0].Name = ""
			output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{outputConfigurationTarget("", "app")}}},
				routes: []outputApplyRoute{{entryName: "", destinations: []string{"app"}}}}
			switch fault {
			case "nonempty_default_name":
				output.routes[0].defaultRoute, output.routes[0].entryName = true, entries[1].Name
			case "absent_named_entry":
				output.routes[0].entryName = "absent"
			case "duplicate_exact_key":
				output.routes = append(output.routes, output.routes[0])
			case "missing_target":
				output.bindings[0].targets[0].entryName = entries[1].Name
			}
			creates, cas, signs := f.store.creates, f.store.cas, f.trust.signs
			installOutputFixtureSource(t, f.session, output)
			if c, result := f.session.compareWithOutput(t.Context(), entries, output, nil); c != nil || result != refused(InvalidIntent) {
				t.Fatal("invalid empty entry route admitted", result)
			}
			if f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs {
				t.Fatal("invalid empty entry route reached effects")
			}
		})
	}
}

func selectedOutputCoordinate(t *testing.T, s *StateSession, slot string) contract.PublicationCoordinate {
	t.Helper()
	id, err := contract.PublicationCoordinateID(s.root.Domain, "aws", slot)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range s.supportRecords() {
		if row.Kind == contract.PublicationCoordinateSupportKind && row.RecordID == id {
			coordinate, err := contract.InspectPublicationCoordinate(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			return coordinate
		}
	}
	t.Fatal("selected coordinate missing", slot)
	return contract.PublicationCoordinate{}
}

// full_only: false
func TestOutputConfigurationSelection(t *testing.T) {
	t.Run("policy_only_preserves_secret_value_and_access", func(t *testing.T) {
		env, keys := genesisEnvironment(t, contract.GCP, true)
		f := newEnvironmentFixture(t, t.Context(), env, []int{1}, false)
		entries := firstSecretInput(t, env, f.session)
		output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{outputConfigurationTarget("secret", "app")}}}}
		output.bindings[0].targets[0].target.Policy = contract.OutputPolicy{ContractID: "test-policy", Data: []byte{2}}
		selected := selectAdmittedOutputConfiguration(t, t.Context(), f.session, env, keys, entries, output)
		before, result := selected.currentOutputConfigurationForApply(t.Context())
		if result.Outcome != 0 {
			t.Fatal(result)
		}
		pages, access := selected.pages, selected.root.CurrentAccess
		output.bindings[0].targets[0].target.Policy.Data = []byte{1}
		output.bindings[0].destination.Policy = output.bindings[0].targets[0].target.Policy
		selected = selectAdmittedOutputConfiguration(t, t.Context(), selected, env, keys, entries, output)
		after, result := selected.currentOutputConfigurationForApply(t.Context())
		want := before
		want.Bindings = slices.Clone(before.Bindings)
		want.Bindings[0].Targets = slices.Clone(before.Bindings[0].Targets)
		want.Bindings[0].Targets[0].Policy.Data = []byte{1}
		want.Bindings[0].Destination.Policy.Data = []byte{1}
		if result.Outcome != 0 || !reflect.DeepEqual(after, want) || !reflect.DeepEqual(selected.pages, pages) || !reflect.DeepEqual(selected.root.CurrentAccess, access) {
			t.Fatal("policy-only selection changed exact configuration, values or access", result)
		}
	})
	t.Run("routing_only_preserves_values_and_coordinates", func(t *testing.T) {
		f := newFixture(t, 1, false, 1)
		entries := f.session.currentEntryInputs()
		output := &outputApplyInput{bindings: []outputApplyBinding{
			{destinationID: "app", targets: []outputApplyTarget{outputConfigurationTarget(entries[0].Name, "app")}},
			{destinationID: "backup", targets: []outputApplyTarget{outputConfigurationTarget(entries[0].Name, "backup")}},
		}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"app", "backup"}}}}
		before := selectOutputConfiguration(t, f, entries, output)
		pages, access := f.session.pages, f.session.root.CurrentAccess
		app, backup := selectedOutputCoordinate(t, f.session, "app"), selectedOutputCoordinate(t, f.session, "backup")
		output.routes[0].destinations = []string{"backup"}
		output.bindings[0].targets = nil
		after := selectOutputConfiguration(t, f, entries, output)
		want := before
		want.Bindings = slices.Clone(before.Bindings)
		want.Bindings[0].Targets = []contract.OutputTarget{}
		want.DefaultDestinations = []string{"backup"}
		app.BindingState, app.ActiveBindingIncarnationID = contract.PublicationBindingRetired, contract.ID{}
		if !reflect.DeepEqual(want, after) ||
			!reflect.DeepEqual(f.session.pages, pages) || !reflect.DeepEqual(f.session.root.CurrentAccess, access) ||
			!reflect.DeepEqual(selectedOutputCoordinate(t, f.session, "app"), app) || !reflect.DeepEqual(selectedOutputCoordinate(t, f.session, "backup"), backup) {
			t.Fatal("routing-only selection changed values, binding identities or coordinates")
		}
		installOutputFixtureSource(t, f.session, output)
		if c, result := f.session.compareWithOutput(t.Context(), entries, output, admitSuppliedOutputComparison(t, f.session, nil, entries, output)); c != nil || result.Outcome != Unchanged {
			t.Fatal("identical selected routing obtained transition authority", result)
		}
		t.Run("malformed_destinations_refuse", func(t *testing.T) {
			output.routes[0].destinations = []string{"backup", "app"}
			creates, cas := f.store.creates, f.store.cas
			installOutputFixtureSource(t, f.session, output)
			if c, result := f.session.compareWithOutput(t.Context(), entries, output, nil); c != nil || result.Outcome != AdmissionRefused || result.Reason != InvalidIntent {
				t.Fatal("noncanonical destination order admitted", result)
			}
			if f.store.creates != creates || f.store.cas != cas {
				t.Fatal("malformed routing reached writes")
			}
		})
	})
	t.Run("removal_and_readd_preserve_clean_coordinate", func(t *testing.T) {
		f := newFixture(t, 1, false, 1)
		entries := f.session.currentEntryInputs()
		output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{outputConfigurationTarget(entries[0].Name, "app")}}}}
		before := selectOutputConfiguration(t, f, entries, output)
		coordinate := selectedOutputCoordinate(t, f.session, "app")
		removed := selectOutputConfiguration(t, f, entries, &outputApplyInput{})
		retired := selectedOutputCoordinate(t, f.session, "app")
		want := coordinate
		want.BindingState, want.ActiveBindingIncarnationID = contract.PublicationBindingRetired, contract.ID{}
		if len(removed.Bindings) != 0 || !reflect.DeepEqual(retired, want) {
			t.Fatal("removal lost or changed clean coordinate ownership")
		}
		after := selectOutputConfiguration(t, f, entries, output)
		active := selectedOutputCoordinate(t, f.session, "app")
		want.BindingState, want.ActiveBindingIncarnationID = contract.PublicationBindingActive, after.Bindings[0].IncarnationID
		if after.Bindings[0].IncarnationID == before.Bindings[0].IncarnationID || !reflect.DeepEqual(active, want) {
			t.Fatal("re-add reused old binding or lost retained physical coordinate")
		}
	})
	t.Run("independent_route_removal_preserves_other_coordinate", func(t *testing.T) {
		f := newFixture(t, 2, false, 1)
		entries := f.session.currentEntryInputs()
		output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{
			outputConfigurationTarget(entries[0].Name, "first"), outputConfigurationTarget(entries[1].Name, "second"),
		}}}}
		before := selectOutputConfiguration(t, f, entries, output)
		first, second := selectedOutputCoordinate(t, f.session, "first"), selectedOutputCoordinate(t, f.session, "second")
		output.bindings[0].targets = output.bindings[0].targets[:1]
		output.routes = slices.DeleteFunc(output.routes, func(route outputApplyRoute) bool { return route.entryName == entries[1].Name })
		after := selectOutputConfiguration(t, f, entries, output)
		if after.Bindings[0].IncarnationID != before.Bindings[0].IncarnationID || len(after.Bindings[0].Targets) != 1 ||
			after.Bindings[0].Targets[0].EntryIncarnationID != first.LastEntryIncarnationID {
			t.Fatal("independent route removal changed the retained binding or entry")
		}
		wantFirst := first
		wantFirst.ActiveBindingIncarnationID = after.Bindings[0].IncarnationID
		wantSecond := second
		wantSecond.BindingState, wantSecond.ActiveBindingIncarnationID = contract.PublicationBindingRetired, contract.ID{}
		if !reflect.DeepEqual(selectedOutputCoordinate(t, f.session, "first"), wantFirst) || !reflect.DeepEqual(selectedOutputCoordinate(t, f.session, "second"), wantSecond) {
			t.Fatal("independent route removal lost retained coordinate meaning")
		}
	})
}

// full_only: false
func TestOutputConfigurationApply(t *testing.T) {
	t.Run("binding_only_preserves_values", func(t *testing.T) {
		f := newFixture(t, 1, false, 1)
		before := fixtureStateImage(t, f)
		entries := before.entryInputs()
		intent := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{{
			entryName: entries[0].Name,
			target:    contract.OutputTarget{ServiceContractID: "aws", TargetContractID: "fixture/target/v1", CanonicalTarget: "app-secret", ConsumerLocator: "app-secret?stage=AWSCURRENT", TargetData: []byte("target:" + "app-secret"), PayloadEncoding: contract.OutputEncodingRaw, Capabilities: contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot, CreateValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, Policy: contract.OutputPolicy{}},
		}}}}}
		installOutputFixtureSource(t, f.session, intent)
		if !checkOutputApplyInput(f.session.root.Domain, entries, intent) {
			t.Fatal("test fixture has an invalid output declaration")
		}
		if _, result := f.session.currentOutputConfigurationForApply(context.Background()); result.Outcome != 0 {
			t.Fatal("test fixture has no selected output configuration", result)
		}
		parent := admitSuppliedOutputComparison(t, f.session, nil, entries, intent)
		comparison, result := f.session.compareWithOutput(context.Background(), entries, intent, parent)
		if comparison == nil || result.Outcome != ObservedCurrent {
			t.Fatalf("binding-only comparison: %+v", result)
		}
		if len(comparison.changed) != 0 || len(comparison.added) != 0 || len(comparison.removed) != 0 ||
			!reflect.DeepEqual(comparison.desiredEntries, entries) || comparison.outputIntent == nil || !comparison.outputChanged {
			t.Fatal("binding-only comparison changed value identity or lost output intent")
		}
		intent.bindings[0].targets[0].target.CanonicalTarget = "caller-mutated"
		if comparison.outputIntent.bindings[0].targets[0].target.CanonicalTarget != "app-secret" {
			t.Fatal("comparison retained mutable caller output input")
		}
		selectedEntry := before.Pages[before.Root.Names[0].Slot/format.PageSlots].Slots[before.Root.Names[0].Slot%format.PageSlots]
		plan, err := planTransition(context.Background(), comparison)
		if err != nil || len(plan.outputBindings) != 1 || plan.outputBindings["app"].IsZero() || comparison.outputAfter == nil {
			t.Fatal("binding-only plan did not resolve a fresh binding and complete output projection")
		}
		if plan.outputBindings["app"] == selectedEntry.Incarnation {
			t.Fatal("fresh binding reused the selected entry incarnation")
		}
		projection := comparison.outputAfter
		if projection.descriptor.BindingCount != 1 || len(projection.records) != int(projection.descriptor.SliceCount) {
			t.Fatal("plan has an incomplete output descriptor")
		}
		parts := make([]contract.OutputConfigurationSlice, len(projection.records))
		for _, record := range projection.records {
			if record.Kind != contract.OutputConfigurationSliceSupportKind {
				t.Fatal("plan contains a non-configuration record")
			}
			part, err := contract.InspectOutputConfigurationSlice(record.Body)
			if err != nil {
				t.Fatal("plan contains an invalid configuration slice", err)
			}
			id, err := contract.OutputConfigurationSliceID(f.session.root.Domain, projection.descriptor.ConfigurationDigest, part.SliceIndex)
			if err != nil || record.RecordID != id {
				t.Fatal("configuration slice has wrong record identity", err)
			}
			parts[part.SliceIndex] = part
		}
		image, err := contract.JoinOutputConfiguration(f.session.root.Domain, projection.descriptor, parts)
		if err != nil {
			t.Fatal("plan's complete configuration does not match its descriptor", err)
		}
		selected, _, err := contract.InspectOutputConfiguration(f.session.root.Domain, image)
		if err != nil || len(selected.Bindings) != 1 || selected.Bindings[0].IncarnationID != plan.outputBindings["app"] ||
			selected.Bindings[0].Targets[0].EntryIncarnationID != selectedEntry.Incarnation ||
			!slices.Equal(selected.Bindings[0].Targets[0].Policy.Data, intent.bindings[0].targets[0].target.Policy.Data) {
			t.Fatal("plan lost the resolved binding or target", err)
		}
		changedPlan := plan
		changedPlan.operation[0] ^= 1
		if f.session.validPlan(t.Context(), comparison, changedPlan) == nil {
			t.Fatal("changed operation retained output plan authority")
		}
		descriptorBefore := projection.descriptor
		projection.descriptor.ConfigurationDigest[0] ^= 1
		if f.session.validPlan(t.Context(), comparison, plan) == nil {
			t.Fatal("altered output descriptor accepted")
		}
		projection.descriptor = descriptorBefore
		bodyBefore := projection.records[0].Body
		projection.records[0].Body = bytes.Clone(bodyBefore)
		projection.records[0].Body[len(bodyBefore)-1] ^= 1
		if f.session.validPlan(t.Context(), comparison, plan) == nil {
			t.Fatal("altered output support accepted")
		}
		projection.records[0].Body = bodyBefore
		next, err := f.session.deriveSuccessor(t.Context(), comparison, plan)
		if err != nil || next == nil || next.root.OutputConfiguration != projection.descriptor {
			t.Fatal("output selection did not derive exact configuration")
		}
		authority, err := f.session.lifecycleAuthority(t.Context(), comparison, plan)
		if err != nil {
			t.Fatal("output authority")
		}
		permit := &AdmittedParentTransition{session: f.session, comparison: comparison, predecessorDigest: contract.Hash(f.session.body), predecessorRevision: f.session.head.Core.Revision, predecessorToken: f.session.token, plan: plan, authority: authority}
		candidate, result := f.session.Prepare(t.Context(), comparison, permit, f.trust)
		if candidate == nil {
			t.Fatal("output preparation", result)
		}
		result = f.session.Select(t.Context(), candidate)
		if result.Outcome != ObservedCurrent {
			t.Fatal("output selection", result)
		}
		opened, result := Open(t.Context(), f.admission, f.store)
		if opened == nil {
			t.Fatal("cold output selection", result)
		}
		if !reflect.DeepEqual(opened.pages, before.Pages) || !reflect.DeepEqual(opened.root.CurrentAccess, before.Root.CurrentAccess) {
			t.Fatal("binding-only selection changed canonical values or access")
		}
		configuration, result := opened.currentOutputConfigurationForApply(t.Context())
		if result.Outcome != 0 || !reflect.DeepEqual(configuration, selected) || (opened.publicationProof == nil || !opened.publicationProof.validFor(opened.selectedImage())) {
			t.Fatal("selected exact output declaration unavailable", result)
		}

	})
	t.Run("new_entry_and_binding_use_plan_identities", func(t *testing.T) {
		f := newFixture(t, 1, false, 1)
		entries := fixtureStateImage(t, f).entryInputs()
		entries = append(entries, ApplyEntryInput{Name: "new-entry", Recipients: slices.Clone(entries[0].Recipients),
			ValueSource: entries[0].ValueSource, ConfidentialityClass: entries[0].ConfidentialityClass, InputBytes: []byte("new value"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
		target := func(name, slot string) outputApplyTarget {
			return outputApplyTarget{entryName: name, target: contract.OutputTarget{ServiceContractID: "aws", TargetContractID: "fixture/target/v1", CanonicalTarget: slot, ConsumerLocator: slot + "?stage=AWSCURRENT", TargetData: []byte("target:" + slot), PayloadEncoding: contract.OutputEncodingRaw, Capabilities: contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot, CreateValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, Policy: contract.OutputPolicy{}}}
		}
		intent := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app",
			targets: []outputApplyTarget{target(entries[0].Name, "old-slot"), target("new-entry", "new-slot")}}}}
		installOutputFixtureSource(t, f.session, intent)
		parent := admitSuppliedOutputComparison(t, f.session, nil, entries, intent)
		comparison, result := f.session.compareWithOutput(t.Context(), entries, intent, parent)
		if comparison == nil || result.Outcome != ObservedCurrent || len(comparison.added) != 1 {
			t.Fatal("new entry was not admitted for comparison", result)
		}
		plan, err := planTransition(t.Context(), comparison)
		if err != nil || comparison.outputAfter == nil || len(plan.outputBindings) != 1 {
			t.Fatal("plan did not resolve new entry and binding")
		}
		newID := plan.incarnations[comparison.added[0]]
		if newID.IsZero() || newID == plan.outputBindings["app"] {
			t.Fatal("new entry and binding identities overlap")
		}
		parts := make([]contract.OutputConfigurationSlice, comparison.outputAfter.descriptor.SliceCount)
		for _, record := range comparison.outputAfter.records {
			part, err := contract.InspectOutputConfigurationSlice(record.Body)
			if err != nil {
				t.Fatal(err)
			}
			parts[part.SliceIndex] = part
		}
		image, err := contract.JoinOutputConfiguration(f.session.root.Domain, comparison.outputAfter.descriptor, parts)
		if err != nil {
			t.Fatal(err)
		}
		selected, _, err := contract.InspectOutputConfiguration(f.session.root.Domain, image)
		if err != nil || len(selected.Bindings) != 1 || len(selected.Bindings[0].Targets) != 2 ||
			!slices.ContainsFunc(selected.Bindings[0].Targets, func(row contract.OutputTarget) bool {
				return row.EntryIncarnationID == newID && row.CanonicalTarget == "new-slot"
			}) {
			t.Fatal("new target did not bind its planned entry incarnation", err)
		}
	})
	t.Run("unrelated_new_entry_keeps_empty_output", func(t *testing.T) {
		f := newFixture(t, 1, false, 1)
		entries := fixtureStateImage(t, f).entryInputs()
		entries = append(entries, ApplyEntryInput{Name: "new-entry", Recipients: slices.Clone(entries[0].Recipients),
			ValueSource: entries[0].ValueSource, ConfidentialityClass: entries[0].ConfidentialityClass, InputBytes: []byte("new value"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
		output := &outputApplyInput{}
		parent := admitSuppliedOutputComparison(t, f.session, nil, entries, output)
		comparison, result := f.session.compareWithOutput(t.Context(), entries, output, parent)
		if comparison == nil || result.Outcome != ObservedCurrent || comparison.outputChanged {
			t.Fatal("unrelated entry creation changed the selected empty output configuration", result)
		}
		plan, err := planTransition(t.Context(), comparison)
		if err != nil || comparison.outputAfter != nil || len(plan.outputBindings) != 0 {
			t.Fatal("unchanged output declaration was planned for rewrite")
		}
		beforeDescriptor := f.session.root.OutputConfiguration
		permit := admit(t, f.session, comparison)
		next, err := f.session.deriveSuccessor(t.Context(), comparison, permit.plan)
		if err != nil || next == nil || next.root.OutputConfiguration != beforeDescriptor {
			t.Fatal("ordinary entry addition did not preserve the selected output descriptor")
		}
		candidate, result := f.session.Prepare(t.Context(), comparison, permit, f.trust)
		if candidate == nil || result.Outcome != ObservedCurrent || !f.session.prepared || !permit.used || comparison.outputIntent != nil || comparison.outputAfter != nil {
			t.Fatal("unchanged output input survived consumed preparation", result)
		}
		reads, creates, cas, signs := f.store.reads, f.store.creates, f.store.cas, f.trust.signs
		if repeated, result := f.session.Prepare(t.Context(), comparison, permit, f.trust); repeated != nil || result != refused(AdmissionInvalid) || f.store.reads != reads || f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs {
			t.Fatal("unchanged output preparation repeated effects", result)
		}
		if result := f.session.Select(t.Context(), candidate); result.Outcome != ObservedCurrent {
			t.Fatal("unchanged output selection", result)
		}
		opened, result := Open(t.Context(), f.admission, f.store)
		if opened == nil || result.Outcome != ObservedCurrent {
			t.Fatal("cold unchanged output selection", result)
		}
		configuration, result := opened.currentOutputConfigurationForApply(t.Context())
		if result.Outcome != 0 || len(configuration.Bindings) != 0 || len(configuration.Routes) != 0 || opened.root.OutputConfiguration != beforeDescriptor || !reflect.DeepEqual(opened.currentEntryInputs(), entries) {
			t.Fatal("unchanged output selection lost exact empty configuration or values", result)
		}
	})
	t.Run("explicit_empty_matches_selected_empty", func(t *testing.T) {
		f := newFixture(t, 1, false, 1)
		entries := fixtureStateImage(t, f).entryInputs()
		output := &outputApplyInput{}
		parent := admitSuppliedOutputComparison(t, f.session, nil, entries, output)
		if c, result := f.session.compareWithOutput(context.Background(), entries, output, parent); c != nil || result.Outcome != Unchanged {
			t.Fatalf("canonical empty declaration changed selection: %+v", result)
		}
	})
	t.Run("incomplete_target_refuses_before_private_work", func(t *testing.T) {
		f := newFixture(t, 1, false, 1)
		entries := fixtureStateImage(t, f).entryInputs()
		intent := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{{
			entryName: "absent", target: contract.OutputTarget{ServiceContractID: "aws", TargetContractID: "fixture/target/v1", CanonicalTarget: "app-secret", ConsumerLocator: "app-secret?stage=AWSCURRENT", TargetData: []byte("target:" + "app-secret"), PayloadEncoding: contract.OutputEncodingRaw, Capabilities: contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot, CreateValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, Policy: contract.OutputPolicy{}},
		}}}}}
		beforeCreate, beforeCAS := f.store.creates, f.store.cas
		installOutputFixtureSource(t, f.session, intent)
		if c, result := f.session.compareWithOutput(context.Background(), entries, intent, nil); c != nil || result.Outcome != AdmissionRefused || result.Reason != InvalidIntent {
			t.Fatalf("missing target was admitted: %+v", result)
		}
		if f.store.creates != beforeCreate || f.store.cas != beforeCAS {
			t.Fatal("incomplete output target caused a store write")
		}
	})
	t.Run("default_route_requires_each_resolved_entry_target", func(t *testing.T) {
		f := newFixture(t, 2, false, 1)
		entries := fixtureStateImage(t, f).entryInputs()
		target := func(name, slot string) outputApplyTarget {
			return outputApplyTarget{entryName: name, target: contract.OutputTarget{ServiceContractID: "aws", TargetContractID: "fixture/target/v1", CanonicalTarget: slot, ConsumerLocator: slot + "?stage=AWSCURRENT", TargetData: []byte("target:" + slot), PayloadEncoding: contract.OutputEncodingRaw, Capabilities: contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot, CreateValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, Policy: contract.OutputPolicy{}}}
		}
		input := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{target(entries[0].Name, "first")}}},
			routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"app"}}}}
		beforeCreate, beforeCAS := f.store.creates, f.store.cas
		installOutputFixtureSource(t, f.session, input)
		if c, result := f.session.compareWithOutput(t.Context(), entries, input, nil); c != nil || result.Outcome != AdmissionRefused || result.Reason != InvalidIntent {
			t.Fatalf("default routed an entry absent from the logical binding: %+v", result)
		}
		if f.store.creates != beforeCreate || f.store.cas != beforeCAS {
			t.Fatal("incomplete default route caused a store write")
		}
		input.bindings = append(input.bindings, outputApplyBinding{destinationID: "second", targets: []outputApplyTarget{target(entries[1].Name, "second")}})
		input.routes = append(input.routes, outputApplyRoute{entryName: entries[1].Name, destinations: []string{"second"}})
		installOutputFixtureSource(t, f.session, input)
		parent := admitSuppliedOutputComparison(t, f.session, nil, entries, input)
		if c, result := f.session.compareWithOutput(t.Context(), entries, input, parent); c == nil || result.Outcome != ObservedCurrent {
			t.Fatalf("specific entry route did not override default: %+v", result)
		}
	})
	t.Run("shared_route_does_not_change_membership", func(t *testing.T) {
		f := newFixture(t, 1, false, 1)
		entries := fixtureStateImage(t, f).entryInputs()
		members := slices.Clone(entries[0].Recipients)
		input := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{outputConfigurationTarget(entries[0].Name, "first")}}}, routes: []outputApplyRoute{{entryName: entries[0].Name, destinations: []string{"app"}}}}
		selectOutputConfiguration(t, f, entries, input)
		if !slices.Equal(f.session.valueEntry(entrySlot(t, f.session, entries[0].Name)).Recipients, members) {
			t.Fatal("shared routing changed selected membership")
		}
	})
	t.Run("empty_destination_list_is_an_explicit_replacement", func(t *testing.T) {
		f := newFixture(t, 1, false, 1)
		entries := fixtureStateImage(t, f).entryInputs()
		input := &outputApplyInput{routes: []outputApplyRoute{{entryName: entries[0].Name, destinations: []string{}}}}
		if !checkOutputApplyInput(f.session.root.Domain, entries, input) {
			t.Fatal("empty replacement was refused")
		}
	})
	t.Run("departed_target_is_a_declaration_difference_not_birth_proof", func(t *testing.T) {
		domain := testID("output target differences")
		bindingID := fixtureID(domain, "binding")
		entryID := fixtureID(domain, "entry")
		old := contract.OutputTarget{EntryIncarnationID: entryID, ServiceContractID: "aws", TargetContractID: "fixture/target/v1", CanonicalTarget: "old-slot", ConsumerLocator: "old-slot?stage=AWSCURRENT", TargetData: []byte("target:" + "old-slot"), PayloadEncoding: contract.OutputEncodingRaw, Capabilities: contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot, CreateValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, Policy: contract.OutputPolicy{}}
		before := contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: domain,
			Bindings: []contract.OutputBinding{{DestinationID: "app", IncarnationID: bindingID,
				Destination: outputFixtureDestination("app", "aws", 63, contract.OutputPolicy{}), Targets: []contract.OutputTarget{old}}},
			Routes: []contract.OutputRoute{{EntryIncarnationID: entryID, Destinations: []string{"app"}}}}
		copyBefore := func() contract.OutputConfiguration {
			after := before
			after.Bindings = slices.Clone(before.Bindings)
			after.Bindings[0].Targets = slices.Clone(before.Bindings[0].Targets)
			return after
		}
		originalBefore := copyBefore()
		// Fixed SHA-256 vectors use the v3 coordinate and target-row prefixes,
		// big-endian length-prefixed strings and an absent policy frame. The
		// target-row literal was derived independently with Python hashlib/struct.
		want := outputTargetDifference{
			coordinateID:         contract.ID{0x0f, 0x10, 0x18, 0x3f, 0x4f, 0x2a, 0x72, 0x6b, 0x26, 0xb4, 0xdf, 0x7c, 0x2b, 0x88, 0x10, 0x4c, 0x19, 0xa0, 0x74, 0x4b, 0xa3, 0x0e, 0xe3, 0x26, 0x0b, 0xdd, 0x8a, 0x40, 0x3b, 0x2e, 0xcf, 0x67},
			bindingIncarnationID: bindingID,
			entryIncarnationID:   entryID,
			targetRowDigest:      contract.ID{0xfd, 0x81, 0x9b, 0xb1, 0xb8, 0xd6, 0xb1, 0x6d, 0xba, 0x87, 0x05, 0x4f, 0x59, 0x99, 0xa5, 0x11, 0x1a, 0xe2, 0xb2, 0x40, 0xd4, 0x79, 0x6c, 0x8b, 0xf0, 0x60, 0xbb, 0x69, 0x0c, 0xd6, 0x14, 0xcf},
			destinationID:        "app", target: old,
		}
		cases := []struct {
			name     string
			change   func(*contract.OutputConfiguration)
			departed bool
		}{
			{"same", func(*contract.OutputConfiguration) {}, false},
			{"policy_and_profile_change_same_container", func(after *contract.OutputConfiguration) {
				after.Bindings[0].Targets[0].Policy = contract.OutputPolicy{ContractID: "test-policy", Data: []byte{1}}
				after.Bindings[0].Targets[0].TargetContractID = "alternate-profile"
				after.Bindings[0].Targets[0].ConsumerLocator = "new-locator"
				after.Bindings[0].Targets[0].PayloadEncoding = contract.OutputEncodingBase64
				after.Bindings[0].Destination.Policy = after.Bindings[0].Targets[0].Policy
				after.Bindings[0].Destination.ConfigContractID = "alternate-config"
			}, false},
			{"physical_slot_replaced", func(after *contract.OutputConfiguration) { after.Bindings[0].Targets[0].CanonicalTarget = "new-slot" }, true},
			{"provider_replaced", func(after *contract.OutputConfiguration) { after.Bindings[0].Targets[0].ServiceContractID = "gcp" }, true},
			{"binding_removed", func(after *contract.OutputConfiguration) { after.Bindings = nil }, true},
			{"binding_readded", func(after *contract.OutputConfiguration) {
				after.Bindings[0].IncarnationID = fixtureID(domain, "new binding")
			}, true},
			{"entry_readded", func(after *contract.OutputConfiguration) {
				after.Bindings[0].Targets[0].EntryIncarnationID = fixtureID(domain, "new entry")
			}, true},
		}
		for _, tt := range cases {
			t.Run(tt.name, func(t *testing.T) {
				after := copyBefore()
				tt.change(&after)
				departed, err := outputApplyTargetDifferences(domain, before, after)
				if err != nil {
					t.Fatal(err)
				}
				if tt.departed && !reflect.DeepEqual(departed, []outputTargetDifference{want}) || !tt.departed && len(departed) != 0 {
					t.Fatalf("wrong old target difference: %+v", departed)
				}
				if !reflect.DeepEqual(before, originalBefore) {
					t.Fatal("target difference changed the complete predecessor declaration")
				}
			})
		}
	})
	t.Run("cold_nonempty_selection_uses_authenticated_slices", func(t *testing.T) {
		ctx := t.Context()
		env, _ := genesisEnvironment(t, contract.GCP, false)
		f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
		entry := f.session.valueEntry(f.session.root.Names[0].Slot)
		configuration := contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: env.Domain,
			Bindings: []contract.OutputBinding{{IncarnationID: fixtureID(env.Domain, "output apply binding"), DestinationID: "app",
				Destination: outputFixtureDestination("app", "gcp", 63, contract.OutputPolicy{}),
				Targets: []contract.OutputTarget{{EntryIncarnationID: entry.Incarnation, ServiceContractID: "gcp", CanonicalTarget: "app-secret",
					ConsumerLocator: "app-secret/versions/latest", TargetContractID: "fixture/target/v1", TargetData: []byte("target:app-secret"), PayloadEncoding: contract.OutputEncodingRaw, Capabilities: contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot, CreateValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, Policy: contract.OutputPolicy{}}}}},
			DefaultDestinations: []string{"app"}}
		seedTarget := configuration.Bindings[0].Targets[0]
		seedTarget.EntryIncarnationID = contract.ID{}
		installOutputFixtureSource(t, f.session, &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", destination: configuration.Bindings[0].Destination, targets: []outputApplyTarget{{entryName: entry.Name, target: seedTarget}}}}})
		image, err := contract.EncodeOutputConfiguration(configuration)
		if err != nil {
			t.Fatal("test configuration", err)
		}
		descriptor, parts, err := contract.SplitOutputConfiguration(env.Domain, image)
		if err != nil || len(parts) != 1 {
			t.Fatal("output fixture slices", err)
		}
		beforeReceipts, err := f.session.receiptWindows(ctx)
		if err != nil {
			t.Fatal("output fixture receipt windows", err)
		}
		beforeRefs := slices.Clone(f.session.root.RequiredSupport)
		wantSupport := make(map[generatedRecordKey]contract.SupportRecordDigest)
		for _, page := range f.session.supportFacts {
			for _, fact := range page.rows {
				if fact.Kind() != contract.OutputConfigurationSliceSupportKind {
					wantSupport[generatedRecordKey{fact.Kind(), fact.RecordID()}] = fact
				}
			}
		}
		generatedMaterializeFixtureSupport(t, f.session)
		outputPage, outputRow := -1, -1
		for i, page := range f.session.support {
			for j, row := range page.Records {
				if row.Kind == contract.OutputConfigurationSliceSupportKind {
					if outputPage >= 0 {
						t.Fatal("output fixture has multiple initial slices")
					}
					outputPage, outputRow = i, j
				}
			}
		}
		if outputPage < 0 {
			t.Fatal("output fixture has no initial slice")
		}
		outputBody, err := contract.EncodeOutputConfigurationSlice(parts[0])
		if err != nil {
			t.Fatal(err)
		}
		outputID, err := contract.OutputConfigurationSliceID(env.Domain, descriptor.ConfigurationDigest, 0)
		if err != nil {
			t.Fatal(err)
		}
		page := format.RequiredSupportPage{Domain: env.Domain, Object: fixtureID(env.Domain, "output apply page"),
			Index: f.session.root.RequiredSupport[outputPage].Index, Records: make([]contract.SupportRecord, len(f.session.support[outputPage].Records))}
		for i, row := range f.session.support[outputPage].Records {
			page.Records[i] = contract.SupportRecord(row)
		}
		page.Records[outputRow] = contract.SupportRecord{Kind: contract.OutputConfigurationSliceSupportKind, RecordID: outputID, Body: outputBody}
		outputFact, err := contract.InspectSupportRecordDigest(env.Domain, page.Records[outputRow])
		if err != nil {
			t.Fatal(err)
		}
		wantSupport[generatedRecordKey{outputFact.Kind(), outputFact.RecordID()}] = outputFact
		pageBody, err := format.EncodeRequiredSupportPage(page)
		if err != nil {
			t.Fatal(err)
		}
		pageRef, err := format.Reference(contract.RequiredSupportKind, env.Domain, page.Object, page.Index, pageBody)
		if err != nil {
			t.Fatal(err)
		}
		pageView, err := format.InspectRequiredSupportPage(pageBody)
		if err != nil {
			t.Fatal(err)
		}
		key, err := format.Key(env.Store.Descriptor().Prefix, pageRef)
		if err != nil {
			t.Fatal(err)
		}
		if err := env.Put(ctx, key, pageBody); err != nil {
			t.Fatal(err)
		}
		f.session.root.OutputConfiguration = descriptor
		f.session.root.RequiredSupport[outputPage], f.session.support[outputPage] = pageRef, pageView
		seedSignedOutputConfiguration(t, env, f, configuration)
		coordinateID, err := contract.PublicationCoordinateID(env.Domain, seedTarget.ServiceContractID, seedTarget.CanonicalTarget)
		if err != nil {
			t.Fatal(err)
		}
		wantCoordinate := contract.PublicationCoordinate{Schema: 5, DomainID: env.Domain, CoordinateID: coordinateID,
			CurrentPublicationIncarnationID: fixtureID(env.Domain, "output publication incarnation"), ServiceContractID: seedTarget.ServiceContractID, CanonicalTarget: seedTarget.CanonicalTarget,
			BindingState: contract.PublicationBindingActive, ActiveBindingIncarnationID: configuration.Bindings[0].IncarnationID,
			LastBindingIncarnationID: configuration.Bindings[0].IncarnationID, LastEntryIncarnationID: entry.Incarnation}
		coordinateBody, err := contract.EncodePublicationCoordinate(wantCoordinate)
		if err != nil {
			t.Fatal(err)
		}
		coordinateFact, err := contract.InspectSupportRecordDigest(env.Domain, contract.SupportRecord{Kind: contract.PublicationCoordinateSupportKind, RecordID: coordinateID, Body: coordinateBody})
		if err != nil {
			t.Fatal(err)
		}
		wantSupport[generatedRecordKey{coordinateFact.Kind(), coordinateFact.RecordID()}] = coordinateFact
		gotSupport := make(map[generatedRecordKey]contract.SupportRecordDigest)
		for _, page := range f.session.supportFacts {
			for _, fact := range page.rows {
				key := generatedRecordKey{fact.Kind(), fact.RecordID()}
				if _, duplicate := gotSupport[key]; duplicate {
					t.Fatal("output fixture duplicated a support row")
				}
				gotSupport[key] = fact
			}
		}
		afterReceipts, err := f.session.receiptWindows(ctx)
		if err != nil || !reflect.DeepEqual(afterReceipts, beforeReceipts) || !reflect.DeepEqual(gotSupport, wantSupport) {
			t.Fatal("output fixture changed receipt windows or complete support inventory", err)
		}
		for i, ref := range beforeRefs {
			if i != outputPage && !slices.Contains(f.session.root.RequiredSupport, ref) {
				t.Fatal("output fixture changed an unrelated support page")
			}
		}
		if f.session.root.OutputConfiguration != descriptor || !f.session.selectedOutputComplete() ||
			f.session.validateSelectedOutputConfiguration(ctx).Outcome != 0 {
			t.Fatal("test fixture lacks authenticated nonempty output")
		}
		selected, result := f.session.currentOutputConfigurationForApply(ctx)
		if result.Outcome != 0 {
			t.Fatal("cold output declaration is not available to comparison", result)
		}
		selectedImage, err := contract.EncodeOutputConfiguration(selected)
		if err != nil || !bytes.Equal(selectedImage, image) {
			t.Fatal("cold output declaration differs from authenticated selected bytes", err)
		}
		if !slices.Equal(selected.DefaultDestinations, []string{"app"}) || len(selected.Routes) != 0 {
			t.Fatal("cold selected entry did not inherit the domain default")
		}
		var selectedSliceID contract.ID
		var selectedSliceRef format.Ref
		for i, page := range f.session.supportFacts {
			for _, fact := range page.rows {
				if fact.Kind() == contract.OutputConfigurationSliceSupportKind {
					selectedSliceID = fact.RecordID()
					selectedSliceRef = page.ref
					if slices.ContainsFunc(f.session.support[i].Records, func(row contract.SupportRecordView) bool { return row.RecordID == selectedSliceID && row.Body != nil }) {
						t.Fatal("selected configuration slice was not bodyless")
					}
				}
			}
		}
		if selectedSliceID.IsZero() {
			t.Fatal("cold selection has no configuration fact")
		}
		used, err := f.session.closureIDsMode(ctx, false)
		if err != nil || !used[selectedSliceID] {
			t.Fatal("fresh-ID closure omitted an authenticated bodyless configuration record")
		}
		newTarget := selected.Bindings[0].Targets[0]
		newTarget.EntryIncarnationID = contract.ID{}
		newTarget.CanonicalTarget = "second-secret"
		newTarget.ConsumerLocator = "second-secret/versions/latest"
		oldTarget := selected.Bindings[0].Targets[0]
		oldTarget.EntryIncarnationID = contract.ID{}
		newBindingIntent := &outputApplyInput{bindings: []outputApplyBinding{
			{destinationID: "app", targets: []outputApplyTarget{{entryName: entry.Name, target: oldTarget}}},
			{destinationID: "second", targets: []outputApplyTarget{{entryName: entry.Name, target: newTarget}}},
		}}
		newBindingComparison, result := f.session.compareWithOutput(ctx, f.session.currentEntryInputs(), newBindingIntent, admitSuppliedOutputComparison(t, f.session, nil, f.session.currentEntryInputs(), newBindingIntent))
		if newBindingComparison == nil || result.Outcome != ObservedCurrent {
			t.Fatal("cold binding addition comparison", result)
		}
		entropyForSupport := func(pageID contract.ID) *bytes.Reader {
			var stream []byte
			for _, label := range []string{"output operation", "output transition", "output snapshot", "output revision"} {
				id := fixtureID(env.Domain, label)
				stream = append(stream, id[:]...)
			}
			stream = append(stream, pageID[:]...)
			for i := 0; i < 32; i++ {
				id := fixtureID(env.Domain, "output extra "+string(rune('a'+i)))
				stream = append(stream, id[:]...)
			}
			return bytes.NewReader(stream)
		}
		f.session.admission.entropy = entropyForSupport(fixtureID(env.Domain, "fresh output support page"))
		if plan, err := planTransition(ctx, newBindingComparison); err != nil || plan.outputBindings["second"].IsZero() {
			t.Fatal("valid cold binding addition could not be planned")
		}
		f.session.admission.entropy = entropyForSupport(selectedSliceID)
		if plan, err := planTransition(ctx, newBindingComparison); err == nil || !plan.outputBindings["second"].IsZero() {
			t.Fatal("selected bodyless configuration ID was reused as a fresh support page")
		}
		f.session.admission.entropy = nil
		retained := selected.Bindings[0].Targets[0]
		retained.EntryIncarnationID = contract.ID{}
		intent := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{{entryName: entry.Name, target: retained}}}},
			routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"app"}}, {entryName: entry.Name, destinations: []string{"app"}}}}
		comparison, result := f.session.compareWithOutput(ctx, f.session.currentEntryInputs(), intent, admitSuppliedOutputComparison(t, f.session, nil, f.session.currentEntryInputs(), intent))
		if comparison == nil || result.Outcome != ObservedCurrent {
			t.Fatal("cold routing comparison", result)
		}
		projection, err := f.session.outputProjectionForPlan(ctx, comparison, transitionPlan{operation: fixtureID(env.Domain, "projection operation"), outputBindings: map[string]contract.ID{}}, selected)
		if err != nil || projection.descriptor == descriptor || len(projection.records) != int(projection.descriptor.SliceCount) {
			t.Fatal("routing-only projection did not change exact selected declaration", err)
		}
		parts = make([]contract.OutputConfigurationSlice, projection.descriptor.SliceCount)
		for _, record := range projection.records {
			part, err := contract.InspectOutputConfigurationSlice(record.Body)
			if err != nil {
				t.Fatal(err)
			}
			parts[part.SliceIndex] = part
		}
		afterImage, err := contract.JoinOutputConfiguration(env.Domain, projection.descriptor, parts)
		if err != nil {
			t.Fatal(err)
		}
		after, _, err := contract.InspectOutputConfiguration(env.Domain, afterImage)
		if err != nil || !slices.Equal(after.DefaultDestinations, []string{"app"}) || len(after.Routes) != 1 ||
			after.Routes[0].EntryIncarnationID != entry.Incarnation || !slices.Equal(after.Routes[0].Destinations, []string{"app"}) ||
			after.Bindings[0].IncarnationID != selected.Bindings[0].IncarnationID ||
			after.Bindings[0].Targets[0].EntryIncarnationID != entry.Incarnation {
			t.Fatal("routing-only projection lost the retained binding or entry", err)
		}
		if len(projection.departedTargets) != 0 {
			t.Fatal("routing-only edit invented a retired physical target")
		}
		replaced := oldTarget
		replaced.CanonicalTarget = "replacement-secret"
		replaced.ConsumerLocator = "replacement-secret/versions/latest"
		replacementIntent := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{{entryName: entry.Name, target: replaced}}}}}
		replacement, result := f.session.compareWithOutput(ctx, f.session.currentEntryInputs(), replacementIntent, admitSuppliedOutputComparison(t, f.session, nil, f.session.currentEntryInputs(), replacementIntent))
		if replacement == nil || result.Outcome != ObservedCurrent {
			t.Fatal("cold physical replacement comparison", result)
		}
		replacedProjection, err := f.session.outputProjectionForPlan(ctx, replacement, transitionPlan{operation: fixtureID(env.Domain, "projection operation"), outputBindings: map[string]contract.ID{}}, selected)
		if err != nil || len(replacedProjection.departedTargets) != 1 ||
			replacedProjection.departedTargets[0].coordinateID.IsZero() ||
			replacedProjection.departedTargets[0].targetRowDigest.IsZero() ||
			replacedProjection.departedTargets[0].destinationID != "app" ||
			!reflect.DeepEqual(replacedProjection.departedTargets[0].target, selected.Bindings[0].Targets[0]) ||
			replacedProjection.departedTargets[0].bindingIncarnationID != selected.Bindings[0].IncarnationID ||
			replacedProjection.departedTargets[0].entryIncarnationID != entry.Incarnation {
			t.Fatal("physical replacement lost the selected old target difference", err)
		}
		stillSelected, err := contract.EncodeOutputConfiguration(selected)
		if err != nil || !bytes.Equal(stillSelected, image) {
			t.Fatal("projection changed the complete predecessor declaration", err)
		}
		ref := selectedSliceRef
		key, err = format.Key(f.session.admission.store.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		delete(f.session.cache, ref)
		store := env.Store.(*memoryStore)
		store.mu.Lock()
		beforeCreate, beforeCAS := store.creates, store.cas
		store.readHook = func(readKey string, reply contract.ReadResult) contract.ReadResult {
			if readKey == key {
				return contract.ReadResult{Status: contract.ReadMissing}
			}
			return reply
		}
		store.mu.Unlock()
		_, result = f.session.currentOutputConfigurationForApply(ctx)
		store.mu.Lock()
		store.readHook = nil
		unchanged := store.creates == beforeCreate && store.cas == beforeCAS
		store.mu.Unlock()
		if result.Outcome != EvidenceUnavailable || result.Reason != MissingSelectedObject || !unchanged {
			t.Fatal("missing selected output slice lost its typed read failure or wrote state", result)
		}
	})
}

// This adapter uses the current signed publication fixture constructors for a nonempty selection.
func seedSignedOutputConfiguration(t *testing.T, env fixtureEnvironment, f *environmentFixture, configuration contract.OutputConfiguration) {
	t.Helper()
	current := *f.session
	current.support = slices.Clone(current.support)
	binding := configuration.Bindings[0]
	target := binding.Targets[0]
	coordinateID, err := contract.PublicationCoordinateID(env.Domain, target.ServiceContractID, target.CanonicalTarget)
	if err != nil {
		t.Fatal(err)
	}
	coordinate := contract.PublicationCoordinate{Schema: 5, DomainID: env.Domain, CoordinateID: coordinateID,
		CurrentPublicationIncarnationID: fixtureID(env.Domain, "output publication incarnation"), ServiceContractID: target.ServiceContractID, CanonicalTarget: target.CanonicalTarget,
		BindingState: contract.PublicationBindingActive, ActiveBindingIncarnationID: binding.IncarnationID,
		LastBindingIncarnationID: binding.IncarnationID, LastEntryIncarnationID: target.EntryIncarnationID}
	coordinateBody, err := contract.EncodePublicationCoordinate(coordinate)
	if err != nil {
		t.Fatal(err)
	}
	physical := generatedFixtureFreeSupportIndex(t, &current)
	pageBody, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: env.Domain, Object: fixtureID(env.Domain, "output coordinate page"), Index: physical,
		Records: []contract.SupportRecord{{Kind: contract.PublicationCoordinateSupportKind, RecordID: coordinateID, Body: coordinateBody}}})
	if err != nil {
		t.Fatal(err)
	}
	coordinatePage, err := format.InspectRequiredSupportPage(pageBody)
	if err != nil {
		t.Fatal(err)
	}
	current.support = append(current.support, coordinatePage)
	current.root.Snapshot, current.root.Transition = fixtureID(env.Domain, "output fixture snapshot"), fixtureID(env.Domain, "output fixture transition")
	seedSignedOutputState(t, env, f, &current)
}

func seedSignedOutputState(t *testing.T, env fixtureEnvironment, f *environmentFixture, current *StateSession) {
	t.Helper()
	generatedRefreshSupport(t, current)
	indexPages, err := format.EncodeAdministrativeIndexPages(current.adminIndex)
	if err != nil {
		t.Fatal(err)
	}
	current.root.AdministrativeIndex = indexPages[0].Ref
	current.root.AdministrativeIndexShards = nil
	var indexObjects []objectImage
	for i, page := range indexPages {
		if i > 0 {
			current.root.AdministrativeIndexShards = append(current.root.AdministrativeIndexShards, page.Ref)
		}
		indexObjects = append(indexObjects, objectImage{ref: page.Ref, body: page.Body})
	}
	current.recountChildren()

	for _, page := range current.support {
		rows := make([]contract.SupportRecord, len(page.Records))
		for i, row := range page.Records {
			rows[i] = contract.SupportRecord(row)
		}
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: rows})
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal(err)
		}
		indexObjects = append(indexObjects, objectImage{ref: ref, body: body})
	}
	for _, object := range indexObjects {
		key, err := format.Key(env.Store.Descriptor().Prefix, object.ref)
		if err != nil {
			t.Fatal("signed output fixture object key", err)
		}
		if err := env.Put(context.Background(), key, object.body); err != nil {
			t.Fatal("signed output fixture object create", err)
		}
	}
	body, err := format.EncodeRoot(current.root)
	if err != nil {
		t.Fatal("signed output fixture root encoding", err)
	}
	ref, err := format.Reference(format.RootKind, env.Domain, current.root.Snapshot, 0, body)
	if err != nil {
		t.Fatal("signed output fixture root reference", err)
	}
	key, err := format.Key(env.Store.Descriptor().Prefix, ref)
	if err != nil {
		t.Fatal("signed output fixture root key", err)
	}
	if err := env.Put(context.Background(), key, body); err != nil {
		t.Fatal("signed output fixture root create", err)
	}
	h := current.head
	h.Core.Root, h.Core.Revision = ref, fixtureID(env.Domain, "output fixture revision")
	h.Core.PreviousRevision, h.Core.PreviousDigest, h.Core.PreviousToken = f.session.head.Core.Revision, contract.Hash(f.session.body), f.session.token
	h.Subject.Operation = fixtureID(env.Domain, "output fixture operation")
	h.Subject.Normal.PublicState = current.publicState()
	h.Subject.Request = requestCommitment(h.Core, h.Subject)
	core, err := format.EncodeHeadCore(h.Core)
	if err != nil {
		t.Fatal("signed output fixture HEAD core", err)
	}
	conditionalBody, err := format.EncodeConditionalPlan(conditional(h.Core, core))
	if err != nil {
		t.Fatal("signed output fixture conditional plan", err)
	}
	h.Subject.HeadCore, h.Subject.HeadCoreLength, h.Subject.ConditionalPlan = contract.Hash(core), uint32(len(core)), contract.Hash(conditionalBody)
	request, err := contract.NewLifecycleRequest(h.Subject)
	if err != nil {
		t.Fatal("signed output fixture lifecycle request", err)
	}
	h.AuthorizationSignature = currentBasisSign(t, env.Trust, request, err)
	storeSignedPublicationHead(t, env, h)
	opened, result := Open(context.Background(), f.admission, env.Store)
	if opened == nil {
		t.Fatal("trusted output predecessor did not authenticate", result)
	}
	f.session = opened
}

// full_only: false
func TestOutputConfigurationGeneratedRoutingAdmission(t *testing.T) {
	env, keys, selected, row, effects, _ := normalHandoffGeneratedFixture(t, false)
	old := *selected.valueEntry(0)
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{outputConfigurationTarget(old.Name, "app")}}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"app"}}}}
	selected = selectAdmittedOutputConfiguration(t, t.Context(), selected, env, keys, selected.currentEntryInputs(), output)
	intent, requestBody := hermeticCloudflareIntent()
	profile := nativeGeneratedFixtureProfile(t, row)
	input := generatedPlanInputWithCurrentGenerated(t, selected, fixtureID(env.Domain, "output uncovered new entry"), []string{"second"}, profile, intent)
	input.requestBindings[0].Digest = hermeticCloudflareHTTPRequestDigest(requestBody)
	beforePublic, beforePrivate := keys.Calls()
	store := env.Store.(*memoryStore)
	beforeCAS, beforeObjects := store.cas, len(store.objects)
	if plan, err := selected.generatedPlanRequest(t.Context(), input); plan != nil || err == nil {
		t.Error("uncovered generated successor admitted", err)
	}
	afterPublic, afterPrivate := keys.Calls()
	if afterPublic != beforePublic || afterPrivate != beforePrivate || effects.Load() != 1 || store.cas != beforeCAS || len(store.objects) != beforeObjects {
		t.Fatal("routing refusal reached key/provider/store work")
	}
	output.routes = nil
	selected = selectAdmittedOutputConfiguration(t, t.Context(), selected, env, keys, selected.currentEntryInputs(), output)
	input = generatedPlanInputWithCurrentGenerated(t, selected, fixtureID(env.Domain, "output valid new entry"), []string{"second"}, profile, intent)
	input.requestBindings[0].Digest = hermeticCloudflareHTTPRequestDigest(requestBody)
	if plan, err := selected.generatedPlanRequest(t.Context(), input); plan == nil || err != nil {
		t.Fatal("valid sibling generated successor refused", err)
	}
}

// full_only: false
func TestOutputConfigurationGeneratedSharedRoutingPreservesMembershipAdmission(t *testing.T) {
	env, keys, selected, row, effects, author := normalHandoffGeneratedFixture(t, false)
	intent, requestBody := hermeticCloudflareIntent()
	profile := nativeGeneratedFixtureProfile(t, row)
	input := generatedPlanInputWithCurrentGenerated(t, selected, fixtureID(env.Domain, "output recipient before second"), []string{"second"}, profile, intent)
	input.requestBindings[0].Digest = hermeticCloudflareHTTPRequestDigest(requestBody)
	selected = author.create(selected, input)
	keys.RetireGenerated()
	old := *selected.valueEntry(0)
	reader := fixtureID(env.Domain, "reader")
	proposed := selected.currentEntryInputs()
	for i := range proposed {
		if proposed[i].Name == old.Name {
			proposed[i].Recipients = append(proposed[i].Recipients, reader)
			slices.SortFunc(proposed[i].Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		}
	}
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{outputConfigurationTarget(old.Name, "app")}}}, routes: []outputApplyRoute{{entryName: old.Name, destinations: []string{"app"}}}}
	selected = selectAdmittedOutputConfiguration(t, t.Context(), selected, env, keys, proposed, output)
	input = generatedPlanInputWithCurrentGenerated(t, selected, fixtureID(env.Domain, "output recipient successor"), []string{"third"}, profile, intent)
	input.requestBindings[0].Digest = hermeticCloudflareHTTPRequestDigest(requestBody)
	if plan, err := selected.generatedPlanRequest(t.Context(), input); plan == nil || err != nil {
		t.Fatal("unchanged membership sibling refused", err)
	}
	view, err := contract.InspectGeneratorDeclaration(input.declaration)
	if err != nil {
		t.Fatal(err)
	}
	declaration, err := view.Own()
	if err != nil {
		t.Fatal(err)
	}
	for i := range declaration.Entries {
		if declaration.Entries[i].Name == "second" {
			declaration.Entries[i].Recipients = append(declaration.Entries[i].Recipients, reader)
			slices.SortFunc(declaration.Entries[i].Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			input.graph.ValueEntryPlans[i].IntendedMembership, err = contract.GeneratorIntendedMembershipDescriptor(declaration.Entries[i].Recipients)
			if err != nil {
				t.Fatal(err)
			}
			input.graph.ValueEntryPlans[i].ChangeMask |= contract.GeneratorValueChangeMembership
		}
	}
	oldJoin, err := contract.GeneratorCompleteJoinID(input.graph.Header.RequestCoreDigest)
	if err != nil {
		t.Fatal(err)
	}
	input.declaration, err = contract.EncodeGeneratorDeclaration(declaration)
	if err != nil {
		t.Fatal(err)
	}
	input.graph.Request.Declaration, err = contract.GeneratorDeclarationDescriptor(declaration)
	if err != nil {
		t.Fatal(err)
	}
	input.graph.Header.RequestCoreDigest, err = contract.GeneratorRequestCoreDigest(input.graph.Request)
	if err != nil {
		t.Fatal(err)
	}
	newJoin, err := contract.GeneratorCompleteJoinID(input.graph.Header.RequestCoreDigest)
	if err != nil {
		t.Fatal(err)
	}
	for i := range input.graph.Edges {
		if input.graph.Edges[i].DestinationTemplateID == oldJoin {
			input.graph.Edges[i].DestinationTemplateID = newJoin
		}
	}
	input.graph.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(input.graph.Header, input.graph.ValueEntryPlans, input.graph.Lineages, input.graph.Edges)
	if err != nil {
		t.Fatal(err)
	}
	view, err = contract.InspectGeneratorDeclaration(input.declaration)
	if err != nil || contract.ValidateGeneratorDeclarationGraph(view, input.graph) != nil || contract.ValidateGeneratorEffectGraph(input.graph) != nil {
		t.Fatal("membership successor graph invalid", err)
	}
	beforePublic, beforePrivate := keys.Calls()
	store := env.Store.(*memoryStore)
	beforeCAS, beforeObjects := store.cas, len(store.objects)
	if plan, err := selected.generatedPlanRequest(t.Context(), input); plan == nil || err != nil {
		t.Fatal("membership-only successor changed shared target admission", err)
	}
	afterPublic, afterPrivate := keys.Calls()
	if beforePublic != afterPublic || beforePrivate != afterPrivate || effects.Load() != 2 || store.cas != beforeCAS || len(store.objects) != beforeObjects {
		t.Fatal("shared routing planning reached key/provider/store work")
	}
}

// full_only: false
func TestOutputConfigurationGeneratedWholeRemoval(t *testing.T) {
	env, keys, selected, row, effects, author := normalHandoffGeneratedFixture(t, false, true)
	// Select a supplied entry while retaining the earlier generated retirement.
	plain := ApplyEntryInput{Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{selected.admission.recipient}, InputBytes: []byte("original"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{outputConfigurationTarget(plain.Name, "app")}}}, routes: []outputApplyRoute{{entryName: plain.Name, destinations: []string{"app"}}}, groups: [][]string{{plain.Name}}}
	selected = selectAdmittedOutputConfiguration(t, t.Context(), selected, env, keys, []ApplyEntryInput{plain}, output, row)
	beforeConfiguration, result := selected.currentOutputConfigurationForApply(t.Context())
	if result.Outcome != 0 || len(beforeConfiguration.Bindings) != 1 || len(beforeConfiguration.Groups) != 1 {
		t.Fatal("whole-removal fixture lacks the explicit selected group", result)
	}
	coordinate := selectedOutputCoordinate(t, selected, "app")
	beforeMarkers := make(map[contract.ID][]byte)
	for _, record := range selected.supportRecords() {
		if record.Kind == contract.PublicationMarkerSupportKind {
			beforeMarkers[record.RecordID] = bytes.Clone(record.Body)
		}
	}
	intent, requestBody := hermeticCloudflareIntent()
	profile := nativeGeneratedFixtureProfile(t, row)
	input := generatedPlanInputForGenerationsIntent(t, selected, fixtureID(env.Domain, "output whole removal"), []string{"replacement"}, intent, profile)
	input.requestBindings[0].Digest = hermeticCloudflareHTTPRequestDigest(requestBody)
	selected = author.create(selected, input)
	keys.RetireGenerated()
	selected = generatedLifecycleReopen(t, t.Context(), selected, env.Store)
	configuration, result := selected.currentOutputConfigurationForApply(t.Context())
	wantBinding := beforeConfiguration.Bindings[0]
	wantBinding.Targets = []contract.OutputTarget{}
	if result.Outcome != 0 || !reflect.DeepEqual(configuration.Bindings, []contract.OutputBinding{wantBinding}) || len(configuration.Routes) != 0 || len(configuration.Groups) != 0 || len(selected.root.Names) != 1 || selected.root.Names[0].Name != "replacement" || effects.Load() != 2 {
		t.Fatal("whole removal lost the dormant destination or retained an old target, route or group", result)
	}
	coordinate.BindingState, coordinate.ActiveBindingIncarnationID = contract.PublicationBindingRetired, contract.ID{}
	if !reflect.DeepEqual(selectedOutputCoordinate(t, selected, "app"), coordinate) {
		t.Fatal("whole removal changed retained physical coordinate")
	}
	count := 0
	for _, record := range selected.supportRecords() {
		if record.Kind == contract.PublicationMarkerSupportKind {
			count++
			if !bytes.Equal(record.Body, beforeMarkers[record.RecordID]) {
				t.Fatal("whole removal changed marker")
			}
		}
	}
	if count != len(beforeMarkers) {
		t.Fatal("whole removal lost marker")
	}
}

// full_only: false
func TestOutputComparisonTerminalPreparationReleasesWorkspace(t *testing.T) {
	for _, terminal := range []string{"freeze_facts", "claim_framing", "cancel_after_freeze", "persist_conflict", "sign_corrupt"} {
		t.Run(terminal, func(t *testing.T) {
			env, keys := genesisEnvironment(t, contract.GCP, true)
			defer keys.RetireApply()
			f := newEnvironmentFixture(t, t.Context(), env, []int{1}, false)
			entries := firstSecretInput(t, env, f.session)
			output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{outputConfigurationTarget("secret", "app")}}}}
			parent := admitSuppliedOutputComparison(t, f.session, keys, entries, output)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			changed := &changedCryptoReply{inner: parent.crypto}
			switch terminal {
			case "freeze_facts":
				changed.kind = contract.CryptoFreeze
				changed.change = func(r contract.CryptoResponse) contract.CryptoResponse { r.Body[0] ^= 1; return r }
			case "claim_framing":
				changed.kind = contract.CryptoClaim
				changed.change = func(r contract.CryptoResponse) contract.CryptoResponse { r.Body = []byte{1}; return r }
			case "cancel_after_freeze":
				changed.kind = contract.CryptoFreeze
				changed.change = func(r contract.CryptoResponse) contract.CryptoResponse { cancel(); return r }
			}
			parent.crypto = changed
			installOutputFixtureSource(t, f.session, output)
			c, result := f.session.compareWithOutput(ctx, entries, output, parent)
			if c == nil || result.Outcome != ObservedCurrent {
				t.Fatal("terminal output comparison", result)
			}
			permit := admit(t, f.session, c)
			if c.outputIntent == nil || c.outputAfter == nil || c.outputAfter.transition == nil || parent.support == nil || parent.support.Output == nil {
				t.Fatal("terminal fixture did not own all output workspaces")
			}
			witness, err := parent.support.Output.Own()
			if err != nil {
				t.Fatal(err)
			}
			descriptor, records := c.outputAfter.descriptor, slices.Clone(c.outputAfter.records)
			for i := range records {
				records[i].Body = bytes.Clone(records[i].Body)
			}
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			before := contract.Hash(f.session.body)
			creates, cas, signs := store.creates, store.cas, trust.signs
			want := refused(AdmissionInvalid)
			switch terminal {
			case "persist_conflict":
				store.createMode = "conflict"
				want = failure(IntegrityFailure, ImmutableConflict)
			case "sign_corrupt":
				trust.corrupt = true
				want = failure(IntegrityFailure, InvalidProof)
			}
			candidate, result := f.session.Prepare(ctx, c, permit, env.Trust)
			if candidate != nil || result != want {
				t.Fatal("terminal output preparation", result)
			}
			checkConsumedOutputComparison(t, f.session, c, permit, parent, witness, descriptor, records)
			if !c.operation.terminal || store.cas != cas || terminal != "sign_corrupt" && trust.signs != signs || terminal != "persist_conflict" && terminal != "sign_corrupt" && store.creates != creates {
				t.Fatal("terminal output preparation crossed its effect boundary")
			}
			if changed.kind != 0 && changed.calls != 1 {
				t.Fatal("terminal fault did not reach its exact stage", changed.calls)
			}
			creates, cas, signs, exchanges := store.creates, store.cas, trust.signs, changed.exchanges
			if repeated, result := f.session.Prepare(t.Context(), c, permit, env.Trust); repeated != nil || result != refused(AdmissionInvalid) {
				t.Fatal("terminal preparation repeated", result)
			}
			if store.creates != creates || store.cas != cas || trust.signs != signs || changed.exchanges != exchanges {
				t.Fatal("repeated terminal preparation caused effects")
			}
			opened, result := Open(t.Context(), f.admission, env.Store)
			if opened == nil || result.Outcome != ObservedCurrent || contract.Hash(opened.body) != before {
				t.Fatal("terminal preparation changed selected state", result)
			}
		})
	}
}

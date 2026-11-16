package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

func previewTestInterpreter(ctx context.Context, _ string, destination contract.OutputDestination, name string, encoding uint8) (contract.OutputTarget, error) {
	if err := ctx.Err(); err != nil {
		return contract.OutputTarget{}, err
	}
	var settings struct {
		Prefix string `json:"prefix"`
	}
	if destination.ServiceContractID != "preview-provider" || destination.ConfigContractID != "preview-output/config/v1" || json.Unmarshal(destination.CanonicalSettings, &settings) != nil || settings.Prefix == "" {
		return contract.OutputTarget{}, contract.ErrRecord
	}
	physical := settings.Prefix + "/" + name
	return outputFixtureTarget(destination.ServiceContractID, physical, physical+"/latest", encoding, destination.Capabilities, destination.Policy), nil
}

func previewTestOutput(t *testing.T, ctx context.Context, names []string, prefixes ...string) (*outputApplyInput, []contract.PublicOutputBinding) {
	t.Helper()
	output := &outputApplyInput{}
	var public []contract.PublicOutputBinding
	for i, prefix := range prefixes {
		destination := fmt.Sprintf("destination-%d", i)
		settings := contract.OutputDestination{ConfigContractID: "preview-output/config/v1", ServiceContractID: "preview-provider", CanonicalSettings: hermeticDestinationSettings([][2]string{{"prefix", prefix}}), Policy: contract.OutputPolicy{}, Capabilities: (contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot) | contract.OutputCapabilityCreateSetsPolicy | contract.OutputCapabilityWriteSetsPolicy}
		binding := outputApplyBinding{destinationID: destination, destination: settings}
		row := contract.PublicOutputBinding{DestinationID: destination, Destination: publicPresent(settings), Targets: publicPresent([]contract.PublicOutputTarget(nil))}
		for _, name := range names {
			target, err := previewTestInterpreter(ctx, destination, settings, name, contract.OutputEncodingRaw)
			if err != nil {
				t.Fatal(err)
			}
			binding.targets = append(binding.targets, outputApplyTarget{entryName: name, target: target})
			row.Targets.Value = append(row.Targets.Value, hermeticPublicOutputTarget(name, target))
		}
		output.bindings = append(output.bindings, binding)
		public = append(public, row)
	}
	destinations := make([]string, len(public))
	for i, row := range public {
		destinations[i] = row.DestinationID
	}
	output.routes = []outputApplyRoute{{defaultRoute: true, destinations: destinations}}
	return output, public
}

func previewTestPublicOutput(public *contract.PublicConfiguration, bindings []contract.PublicOutputBinding) {
	public.OutputBindings = publicPresent(bindings)
	destinations := make([]string, len(bindings))
	for i, row := range bindings {
		destinations[i] = row.DestinationID
	}
	public.Routing = publicPresent([]contract.PublicRoutingRule{{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicDefaultRoute}, Destinations: publicPresent(destinations)}})
}

func previewTestSuppliedFixture(t *testing.T, choices ...uint8) (context.Context, context.CancelFunc, fixtureEnvironment, *StateSession, contract.PublicConfiguration, *PublicConfigurationValidator, ApplyEntryInput) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	env, _ := genesisEnvironment(t, contract.GCP, false)
	initial := newEnvironmentFixture(t, ctx, env, nil, false)
	choice := custody.StandardValue
	if len(choices) != 0 {
		choice = choices[0]
	}
	sealed := suppliedSecret(t, env, "secret", "publication preview supplied", choice)
	output, bindings := previewTestOutput(t, ctx, []string{"secret"}, "managed")
	selected := selectAdmittedOutputConfiguration(t, ctx, initial.session, env, env.Custody, []ApplyEntryInput{sealed}, output)
	public := comparisonCurrentInput(t, env, selected)
	previewTestPublicOutput(&public, bindings)
	validator := NewPublicConfigurationValidator(previewTestInterpreter)
	return ctx, cancel, env, selected, public, validator, sealed
}

// full_only: false
func TestPublicationPreviewPrivateEqualityResolvesOnlyCheckedOutput(t *testing.T) {
	for _, mode := range []string{"equal", "changed", "display"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel, env, selected, public, validator, sealed := previewTestSuppliedFixture(t)
			defer cancel()
			f := &fixture{store: env.Store.(*memoryStore), trust: env.Trust.(*fixtureTrust), session: selected}
			selected.admission.publicationNamespaces = []publicationNamespace{{domain: env.Domain, service: "preview-provider", physical: "managed/secret", premise: contract.Hash([]byte("independent namespace"))}}
			f.admission = OpenContext{admission: &selected.admission}
			controlled := newPublicationControlledPrivate()
			request := publicationInput{names: []string{"secret"}, acting: selected.admission.recipient, deadline: time.Now().Add(30 * time.Second)}
			published := publicationEnginePlan(t, f, request, controlled).execute(ctx, controlled.callbacks(), publicationEngineCurrent(f))
			if len(published.output.Entries) != 1 || len(published.output.Entries[0].Actions) != 1 {
				t.Fatalf("initial publication incomplete: outcome=%d reason=%d summary=%d entries=%d owners=%d", published.state.Outcome, published.state.Reason, published.summary, len(published.output.Entries), len(controlled.owners))
			}
			created := published.output.Entries[0].Actions[0]
			if published.state.Outcome != ObservedCurrent || published.state.Reason != NoReason || published.summary != contract.PublicationSummaryComplete || created.Action != contract.PublicationCreateWithValue || created.Disposition != contract.PublicationOutcomeAcknowledged || created.CoreReason != 0 || created.AttemptID.IsZero() || len(controlled.owners) != 1 {
				t.Fatalf("initial create not acknowledged: outcome=%d state_reason=%d summary=%d action=%d disposition=%d action_reason=%d attempt_missing=%t owners=%d", published.state.Outcome, published.state.Reason, published.summary, created.Action, created.Disposition, created.CoreReason, created.AttemptID.IsZero(), len(controlled.owners))
			}
			owner := controlled.owners[0]
			if owner.prepared != 1 || owner.armed != 1 || owner.sent != 1 || owner.retired != 1 {
				t.Fatalf("initial create owner incomplete: prepared=%d armed=%d sent=%d retired=%d", owner.prepared, owner.armed, owner.sent, owner.retired)
			}
			facts := publicationEngineReopen(t, f)
			coordinate := facts.coordinates[published.output.Entries[0].CoordinateID]
			marker := facts.markers[created.AttemptID]
			if coordinate.OwnerState != contract.PublicationOwnerQualified || coordinate.OwnedBirthAttemptID != created.AttemptID || coordinate.LastValueAckAttemptID != created.AttemptID || !coordinate.LastPolicyAckAttemptID.IsZero() || !coordinate.LastPolicyDigest.IsZero() || marker.State != contract.PublicationAcknowledged || coordinate.LateEffectRisk != 0 || len(publicationBlockers(facts, coordinate.CoordinateID)) != 0 {
				t.Fatalf("initial acknowledged create not selected: owner=%d birth_matches=%t value_ack_matches=%t marker_state=%d late_risk=%d", coordinate.OwnerState, coordinate.OwnedBirthAttemptID == created.AttemptID, coordinate.LastValueAckAttemptID == created.AttemptID, marker.State, coordinate.LateEffectRisk)
			}
			selected = f.session
			if mode == "changed" {
				sealed = suppliedSecret(t, env, "secret", "publication preview replacement", custody.AlternateStandardValue)
			}
			inputs := []contract.PlanningInput{{Name: "secret", Form: contract.PlanningSealed, SealedInput: bytes.Clone(sealed.InputBytes)}}
			original := bytes.Clone(inputs[0].SealedInput)
			reader, _, _ := readerEngineFixture(t, env, selected)
			reader.validator = validator
			publicCalls, privateCalls := env.Custody.Calls()
			creates, cas, signs, owners := f.store.creates, f.store.cas, f.trust.signs, len(controlled.owners)
			unchecked := reader.Compare(ctx, fixtureID(env.Domain, "unchecked publication"), public, contract.ComparisonOptions{Publish: true})
			if unchecked.StateResult != contract.ReaderSuccess || unchecked.Publication == nil {
				t.Fatalf("public preview unavailable: state=%s reason=%d projection_missing=%t", unchecked.StateResult, unchecked.Result.Reason, unchecked.Publication == nil)
			}
			if !unchecked.Publication.Complete || len(unchecked.Publication.Entries) != 1 {
				t.Fatalf("public preview incomplete: complete=%t reason=%d entries=%d", unchecked.Publication.Complete, unchecked.Publication.ReasonCode, len(unchecked.Publication.Entries))
			}
			uncheckedRow := unchecked.Publication.Entries[0]
			if uncheckedRow.Basis != "secret-unchecked" || !uncheckedRow.Conditional || uncheckedRow.ReasonCode != 0 || !reflect.DeepEqual(uncheckedRow.Actions, []uint8{contract.PublicationWriteValue}) {
				t.Fatalf("public preview differs from unchecked acknowledged secret: basis=%s conditional=%t reason=%d actions=%v blockers=%d late_risk=%t domain_warning=%t", uncheckedRow.Basis, uncheckedRow.Conditional, uncheckedRow.ReasonCode, uncheckedRow.Actions, len(uncheckedRow.BlockerIDs), uncheckedRow.LateWriteRisk, unchecked.Publication.DomainWideWarning)
			}
			if p, k := env.Custody.Calls(); p != publicCalls || k != privateCalls {
				t.Fatal("public output preview used KMS")
			}
			display := custody.NewPlanningDisplay(custody.StandardValue)
			options := contract.PlanningOptions{Purpose: contract.PlanningEquality, Publish: true}
			if mode == "display" {
				options = contract.PlanningOptions{Purpose: contract.PlanningDisplay, Publish: true, SelectedNames: []string{"secret"}, SinkID: display.Identity()}
			}
			factories := 0
			planner, _, source := installedPlanningFixture(t, env, selected, public, inputs, func(c context.Context, q contract.PlanningAdmission) (PlanningCustody, error) {
				factories++
				if q.SnapshotID != selected.root.Snapshot || len(q.Targets) != 1 {
					t.Fatal("output preview changed private admission selection")
				}
				if mode == "display" {
					return env.Custody.NewPlanningDisplayCustody(c, q, display)
				}
				return env.Custody.NewPlanningCustody(c, q)
			})
			planner.reader.validator = validator
			got := planner.Plan(ctx, fixtureID(env.Domain, "checked publication"), public, inputs, options)
			planner.Close()
			if got.StateResult != contract.ReaderSuccess || !got.PrivateComplete || got.Observation == nil || got.Observation.SnapshotID != selected.root.Snapshot || got.Publication == nil || !got.Publication.Complete || len(got.Publication.Entries) != 1 || factories != 1 || source.closes != 1 {
				t.Fatal("private publication planning incomplete", got.StateResult, got.PrivateComplete, factories)
			}
			row := got.Publication.Entries[0]
			wantBasis, wantRelation, wantActions := "acknowledged-equal", contract.PlanningEqual, []uint8(nil)
			if mode == "changed" {
				wantBasis, wantRelation, wantActions = "value-changed", contract.PlanningChanged, []uint8{contract.PublicationWriteValue}
			}
			if row.Basis != wantBasis || row.Conditional || !reflect.DeepEqual(row.Actions, wantActions) || len(got.PrivateEntries) != 1 || got.PrivateEntries[0].Relation != wantRelation || row.CoordinateID != unchecked.Publication.Entries[0].CoordinateID || row.BindingID != unchecked.Publication.Entries[0].BindingID || row.RemoteValueMayRemain != unchecked.Publication.Entries[0].RemoteValueMayRemain {
				t.Fatal("checked equality changed unrelated publication facts", row)
			}
			if mode == "display" && (got.DisplayDelivery != contract.PlanningDeliveryComplete || display.Acquisitions != 1 || display.Records != 1 || display.Closes != 1 || !display.Cleared()) {
				t.Fatal("output preview changed explicit display custody")
			}
			if mode != "display" && display.Acquisitions != 0 {
				t.Fatal("equality preview acquired display sink")
			}
			if p, k := env.Custody.Calls(); p != publicCalls || k <= privateCalls || f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs || len(controlled.owners) != owners || !bytes.Equal(original, inputs[0].SealedInput) {
				t.Fatal("private output preview changed source or acquired effect authority")
			}
		})
	}
}

// full_only: false
func TestPublicationPreviewFutureGeneratedOutputIsConditional(t *testing.T) {
	ctx, cancel, env, selected, baseline := comparisonGeneratedFixture(t)
	defer cancel()
	validator := NewPublicConfigurationValidator(previewTestInterpreter)
	for _, condition := range []string{"unchanged", "equivalent-semantic-intent", "policy-only", "future-epoch"} {
		t.Run(condition, func(t *testing.T) {
			public := ownPublicConfiguration(baseline)
			_, bindings := previewTestOutput(t, ctx, []string{"generated"}, "future")
			previewTestPublicOutput(&public, bindings)
			public.Routing = publicPresent([]contract.PublicRoutingRule{{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: "generated"}, Destinations: publicPresent([]string{bindings[0].DestinationID})}})
			expectedAction := contract.GeneratedPlanningUnchanged
			expectedBasis, expectedConditional := "unpublished", false
			for i := range public.Entries.Value {
				if public.Entries.Value[i].Name != "generated" {
					continue
				}
				switch condition {
				case "equivalent-semantic-intent":
					public.Entries.Value[i].Generated.ContentIntent.Value = bytes.Clone(public.Entries.Value[i].Generated.ContentIntent.Value)
				case "policy-only":
					public.Entries.Value[i].Generated.Retirement.Value = contract.GeneratedRetirementAuto
					expectedAction = contract.GeneratedPlanningPolicyChange
				case "future-epoch":
					public.Entries.Value[i].Generated.Epoch.Value = 2
					expectedAction = contract.GeneratedPlanningRotate
					expectedBasis, expectedConditional = "generated-unavailable", true
				}
			}
			reader, _, _ := readerEngineFixture(t, env, selected)
			reader.validator = validator
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			creates, cas, signs := store.creates, store.cas, trust.signs
			publicCalls, privateCalls := env.Custody.Calls()
			got := reader.Compare(ctx, fixtureID(env.Domain, "future generated output preview/"+condition), public, contract.ComparisonOptions{Publish: true})
			if got.StateResult != contract.ReaderSuccess || got.Publication == nil || !got.Publication.Complete || len(got.Publication.Entries) != 1 {
				t.Fatal("generated target omitted", got.StateResult)
			}
			row := got.Publication.Entries[0]
			if row.Origin != "proposed" || !row.CoordinateID.IsZero() || !row.BindingID.IsZero() || row.ConsumerLocator != nil || row.Basis != expectedBasis || row.Conditional != expectedConditional || !reflect.DeepEqual(row.Actions, []uint8{contract.PublicationCreateWithValue}) || len(got.GeneratedEntries) != 1 || got.GeneratedEntries[0].Action != expectedAction {
				t.Fatal("generated value availability differs from intent classification", row)
			}
			if p, k := env.Custody.Calls(); p != publicCalls || k != privateCalls || store.creates != creates || store.cas != cas || trust.signs != signs {
				t.Fatal("generated output preview reached generator/private/effect routes")
			}
			reader.Close()
		})
	}
}

// full_only: false
func TestPublicationPreviewLateSelectedReadStopsBeforeDisplay(t *testing.T) {
	for _, damage := range []string{"missing", "corrupt"} {
		t.Run(damage, func(t *testing.T) {
			ctx, cancel, env, selected, public, validator, sealed := previewTestSuppliedFixture(t)
			defer cancel()
			var key string
			for i, page := range selected.support {
				if slices.ContainsFunc(page.Records, func(row contract.SupportRecordView) bool {
					return row.Kind == contract.PublicationCoordinateSupportKind
				}) {
					key = readerFixtureKey(t, selected.admission.store.Prefix, selected.root.RequiredSupport[i])
					break
				}
			}
			if key == "" {
				t.Fatal("selected coordinate page missing")
			}
			reader, _, source := readerEngineFixture(t, env, selected)
			reader.validator = validator
			baseline := &comparisonReadGate{PublicSelectedReader: source, key: key}
			reader.construct = func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
				return baseline, Result{}
			}
			observed := reader.Compare(ctx, fixtureID(env.Domain, "late preview baseline"), public, contract.ComparisonOptions{Publish: true})
			if observed.Publication == nil || !observed.Publication.Complete || baseline.reads < 2 {
				t.Fatal("baseline did not reread exact selected support")
			}
			reader.Close()
			inputs := []contract.PlanningInput{{Name: "secret", Form: contract.PlanningSealed, SealedInput: sealed.InputBytes}}
			display := custody.NewPlanningDisplay(custody.StandardValue)
			factories := 0
			planner, _, opened := installedPlanningFixture(t, env, selected, public, inputs, func(c context.Context, q contract.PlanningAdmission) (PlanningCustody, error) {
				factories++
				return env.Custody.NewPlanningDisplayCustody(c, q, display)
			})
			planner.reader.validator = validator
			gate := &comparisonReadGate{PublicSelectedReader: opened, key: key, failAt: baseline.reads, kind: damage}
			planner.reader.construct = func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
				return gate, Result{}
			}
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			creates, cas, signs := store.creates, store.cas, trust.signs
			publicCalls, privateCalls := env.Custody.Calls()
			got := planner.Plan(ctx, fixtureID(env.Domain, "late preview damage"), public, inputs, contract.PlanningOptions{Purpose: contract.PlanningDisplay, Publish: true, SelectedNames: []string{"secret"}, SinkID: display.Identity()})
			planner.Close()
			if got.StateResult == contract.ReaderSuccess || got.Verdict != contract.ComparisonUnable || got.PrivateComplete || got.Publication == nil || got.Publication.Complete || factories != 0 || display.Acquisitions != 0 || display.Records != 0 || display.Closes != 0 || got.CompletedRecords != 0 || gate.reads != baseline.reads || opened.closes != 1 {
				t.Fatal("late publication evidence damage crossed display barrier", got.StateResult, factories, gate.reads, baseline.reads)
			}
			if p, k := env.Custody.Calls(); p != publicCalls || k != privateCalls || store.creates != creates || store.cas != cas || trust.signs != signs {
				t.Fatal("failed preview acquired private or mutation authority")
			}
		})
	}
}

// full_only: false
func TestPublicationPreviewDoesNotUseOldSecretLengthForUncheckedReplacement(t *testing.T) {
	for _, mode := range []string{"public-unchecked", "private-changed", "private-equal"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel, env, selected, public, validator, selectedInput := previewTestSuppliedFixture(t, custody.EmptyValue)
			defer cancel()
			validator.interpret = func(ctx context.Context, id string, destination contract.OutputDestination, name string, encoding uint8) (contract.OutputTarget, error) {
				target, err := previewTestInterpreter(ctx, id, destination, name, encoding)
				target.CreateValueBounds.Minimum, target.WriteValueBounds.Minimum = 1, 1
				return target, err
			}
			// The selected bounds and proposed bounds describe the same public target.
			for i := range public.OutputBindings.Value {
				for j := range public.OutputBindings.Value[i].Targets.Value {
					target := &public.OutputBindings.Value[i].Targets.Value[j]
					target.CreateValueBounds.Value.Minimum, target.WriteValueBounds.Value.Minimum = 1, 1
				}
			}
			selected = selectAdmittedOutputConfiguration(t, ctx, selected, env, env.Custody, []ApplyEntryInput{selectedInput}, publicOutputApplyInput(public))

			replacement := selectedInput
			if mode != "private-equal" {
				replacement = suppliedSecret(t, env, "secret", "pending nonempty secret", custody.StandardValue)
			}
			// The selected length applies only after the proposed content compares equal.
			inputs := []contract.PlanningInput{{Name: "secret", Form: contract.PlanningSealed, SealedInput: replacement.InputBytes}}
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			creates, cas, signs := store.creates, store.cas, trust.signs
			publicCalls, privateCalls := env.Custody.Calls()
			var preview *contract.PublicationPreview
			if mode == "public-unchecked" {
				reader, _, _ := readerEngineFixture(t, env, selected)
				reader.validator = validator
				got := reader.Compare(ctx, fixtureID(env.Domain, "unchecked replacement length"), public, contract.ComparisonOptions{Publish: true})
				reader.Close()
				preview = got.Publication
				if p, k := env.Custody.Calls(); p != publicCalls || k != privateCalls {
					t.Fatal("public capacity preview opened a secret")
				}
			} else {
				planner, _, _ := installedPlanningFixture(t, env, selected, public, inputs, func(c context.Context, q contract.PlanningAdmission) (PlanningCustody, error) {
					return env.Custody.NewPlanningCustody(c, q)
				})
				planner.reader.validator = validator
				got := planner.Plan(ctx, fixtureID(env.Domain, "checked replacement length"), public, inputs, contract.PlanningOptions{Purpose: contract.PlanningEquality, Publish: true})
				planner.Close()
				preview = got.Publication
				wantRelation := contract.PlanningChanged
				if mode == "private-equal" {
					wantRelation = contract.PlanningEqual
				}
				if got.StateResult != contract.ReaderSuccess || !got.PrivateComplete || len(got.PrivateEntries) != 1 || got.PrivateEntries[0].Relation != wantRelation {
					t.Fatal("proposed secret did not compare", got.StateResult, got.PrivateEntries)
				}
			}
			wantReason := uint8(0)
			if mode == "private-equal" {
				wantReason = uint8(CapacityExceeded)
			}
			if preview == nil || !preview.Complete || len(preview.Entries) != 1 || preview.Entries[0].ReasonCode != wantReason || !reflect.DeepEqual(preview.Entries[0].Actions, []uint8{contract.PublicationCreateWithValue}) {
				t.Fatal("candidate inherited unrelated old secret capacity refusal", preview)
			}
			row := preview.Entries[0]
			if mode == "public-unchecked" && (row.Basis != "secret-unchecked" || !row.Conditional) || mode == "private-changed" && (row.Basis != "value-changed" || row.Conditional) || mode == "private-equal" && (row.Basis != "capacity" || row.Conditional) {
				t.Fatal("replacement relation became old-value capacity proof", row)
			}
			if p, _ := env.Custody.Calls(); p != publicCalls || store.creates != creates || store.cas != cas || trust.signs != signs {
				t.Fatal("capacity preview acquired mutation authority")
			}
		})
	}
}

// full_only: false
func TestPublicationPreviewCompleteUnionReportsCapacityWithoutInventingIDs(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	sizes := make([]int, 512)
	names := make([]string, 512)
	for i := range names {
		sizes[i] = 1
		names[i] = fmt.Sprintf("entry-%03d", i)
	}
	f := newNamedEnvironmentFixture(t, ctx, env, sizes, false, names)
	output, bindings := previewTestOutput(t, ctx, names, "old-a", "old-b")
	selected := selectAdmittedOutputConfiguration(t, ctx, f.session, env, env.Custody, f.session.currentEntryInputs(), output)
	public := comparisonCurrentInput(t, env, selected)
	previewTestPublicOutput(&public, bindings)
	validator := NewPublicConfigurationValidator(previewTestInterpreter)
	_, proposed := previewTestOutput(t, ctx, names, "new-a", "new-b")
	previewTestPublicOutput(&public, proposed)
	reader, _, _ := readerEngineFixture(t, env, selected)
	reader.validator = validator
	store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
	creates, cas, signs := store.creates, store.cas, trust.signs
	publicCalls, privateCalls := env.Custody.Calls()
	got := reader.Compare(ctx, fixtureID(env.Domain, "complete observed proposed union"), public, contract.ComparisonOptions{Publish: true})
	if got.StateResult != contract.ReaderSuccess || got.Publication == nil || !got.Publication.Complete || got.Publication.ReasonCode != uint8(CapacityExceeded) || len(got.Publication.Entries) != 2048 {
		t.Fatal("complete union was truncated or treated as executable", got.StateResult)
	}
	observed, proposedCount := 0, 0
	for _, row := range got.Publication.Entries {
		switch row.Origin {
		case "observed":
			observed++
			if !strings.HasPrefix(row.PhysicalTarget, "old-") || row.CoordinateID.IsZero() || row.BindingID.IsZero() || len(row.Actions) != 0 {
				t.Fatal("selected old coordinate changed", row)
			}
		case "proposed":
			proposedCount++
			if !strings.HasPrefix(row.PhysicalTarget, "new-") || !row.CoordinateID.IsZero() || !row.BindingID.IsZero() || row.ConsumerLocator != nil || !reflect.DeepEqual(row.Actions, []uint8{contract.PublicationCreateWithValue}) {
				t.Fatal("prospective target gained authenticated IDs", row)
			}
		default:
			t.Fatal("disjoint union merged", row.Origin)
		}
	}
	if observed != 1024 || proposedCount != 1024 {
		t.Fatal("union lost an independently bounded set", observed, proposedCount)
	}
	if p, k := env.Custody.Calls(); p != publicCalls || k != privateCalls || store.creates != creates || store.cas != cas || trust.signs != signs {
		t.Fatal("ineligible union acquired effect/private authority")
	}
}

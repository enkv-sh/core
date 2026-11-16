package core

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	"enkv.sh/crypto/testsupport/custody"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

type successionActors struct {
	After    contract.ControlCore
	Source   contract.BindingTableRow
	Keys     *custody.Fixture
	Signers  SuccessionSigners
	Store    contract.Store
	Activate func(testing.TB, *StateSession)
}

// The same action and assertions run with synthetic or provider actor routes.
// Each parent supplies admission, current consumption and fresh process routes.
func runAuthorityScenario(t testing.TB, ctx context.Context, env fixtureEnvironment, scenario catalog.AuthorityReplacementCase) {
	t.Helper()
	if env.ReplacementActors == nil || env.CurrentConsume == nil || env.FreshCurrent == nil || scenario.PrivateWitnesses() && env.PrivateWitness == nil {
		t.Fatal("authority scenario requires exact parent actor and current reader routes")
	}
	run := newScenarioRun(t, ctx, env)
	var f *environmentFixture
	run.phase("setup", func() { f = newEnvironmentFixture(t, ctx, run.env, []int{1}, false) })
	if scenario.Material {
		run.phase("transition", func() {
			run.suppliedSelection(f, append(f.session.currentEntryInputs(), sharingSecret(t, env, "authority scenario current", []contract.ID{f.session.admission.recipient})))
		})
	}
	receipts := make(map[contract.ID][]byte)
	for _, stage := range scenario.Stages() {
		before := f.session
		beforeImage := sessionStateImage(t, before)
		var permit *AdmittedSuccession
		var actors successionActors
		run.phase("transition", func() {
			actors = env.ReplacementActors(t, ctx, before, stage.Operation, stage.Mask, stage.Approval)
			if actors.Keys == nil && stage.Mask&(2|8) != 0 || actors.Store == nil || actors.Activate == nil || !before.admission.valid(actors.Store) {
				t.Fatal("succession actors differ from admitted Store or private routes")
			}
			if stage.Mask&(2|8) != 0 {
				control := currentControlOf(before)
				wanted := contract.BindingTableRow{SubjectKind: 1, SubjectID: control.AuthorityRecipientID, Binding: control.AuthorityKMSBinding}
				if stage.Mask&2 != 0 && control.Recovery != nil {
					wanted = contract.BindingTableRow{SubjectKind: 2, SubjectID: control.Recovery.RoleID, Binding: control.Recovery.KMS}
				}
				if !sameBindingRow(actors.Source, wanted) {
					t.Fatal("authority scenario source is not the exact surviving KEK")
				}
			}
			// The owner switches only the exact Store route. The selected token,
			// current public state and independent admission are unchanged.
			admitted := *before
			admitted.store = scenarioStore{Store: actors.Store, spy: run.spy}
			before = &admitted
			permit = admitAuthorityReplacement(t, before, actors.Keys, actors.After, stage.Operation, stage.Approval, stage.Mask, actors.Source)
			public, private := 0, 0
			if actors.Keys != nil {
				public, private = actors.Keys.Calls()
			}
			candidate, result := before.PrepareSuccession(ctx, permit, actors.Signers)
			if candidate == nil {
				t.Fatal("authority scenario preparation", result)
			}
			wantPublic, wantPrivate := 0, 0
			if stage.Mask&(2|8) != 0 {
				wantPublic, wantPrivate = 1, int(before.root.SecretCount)+1
			}
			if actors.Keys != nil {
				if p, k := actors.Keys.Calls(); p-public != wantPublic || k-private != wantPrivate {
					t.Fatal("authority scenario used an unrequested private operation", p-public, k-private)
				}
			}
			admission := deliverSuccessionBasis(t, candidate)
			if result = before.Select(ctx, candidate); result.Outcome != ObservedCurrent {
				t.Fatal("authority scenario selection", result)
			}
			selected, result := Open(ctx, admission, admitted.store)
			if selected == nil {
				t.Fatal("authority scenario current reopen", result)
			}
			if actors.Keys != nil {
				actors.Keys.RetireAccess()
			}
			actors.Activate(t, selected)
			f.admission, f.session = admission, selected
		})
		run.phase("verification", func() {
			selected := f.session
			if !controlEqual(currentControlOf(selected), actors.After) || !reflect.DeepEqual(beforeImage.Pages, selected.pages) || !reflect.DeepEqual(beforeImage.Root.ValueEntryPages, selected.root.ValueEntryPages) || !reflect.DeepEqual(beforeImage.Root.Names, selected.root.Names) || beforeImage.Root.ValueEntryCount != selected.root.ValueEntryCount || beforeImage.Root.RawBytes != selected.root.RawBytes {
				t.Fatal("authority scenario changed immutable state or omitted exact successor control")
			}
			for _, entry := range before.root.Names {
				if before.valueEntry(entry.Slot).ConfidentialityClass != contract.Secret {
					continue
				}
				_, oldPayload, oldAccess, ok := before.selectedValue(entry.Slot)
				if !ok {
					t.Fatal("before current secret missing")
				}
				_, payload, access, ok := selected.selectedValue(entry.Slot)
				oldBytes, oldErr := contract.EncodeCanonicalPayload(oldPayload)
				payloadBytes, payloadErr := contract.EncodeCanonicalPayload(payload)
				if !ok || oldErr != nil || payloadErr != nil || !bytes.Equal(oldBytes, payloadBytes) || oldAccess.PackageCheck != access.PackageCheck {
					t.Fatal("authority scenario changed payload or private material commitment")
				}
				if target, _, changed := successionTarget(permit.request); changed {
					if !preservesReplacementWraps(oldAccess, access, target) {
						t.Fatal("authority scenario changed an unselected wrap")
					}
				} else {
					a, err := contract.EncodeAccessRecord(oldAccess)
					if err != nil {
						t.Fatal(err)
					}
					b, err := contract.EncodeAccessRecord(access)
					if err != nil || !bytes.Equal(a, b) {
						t.Fatal("signer-only scenario changed access bytes", err)
					}
				}
			}
			if stage.Operation != 1 {
				receipts[permit.request.OperationID] = checkSuccessionReceipt(t, ctx, selected, permit)
			}
			for id, expected := range receipts {
				actual, result := selected.MutationReceipt(ctx, id)
				if result.Outcome != ObservedCurrent || !bytes.Equal(actual, expected) {
					t.Fatal("later succession changed an existing receipt", result)
				}
			}
			if stage.Material {
				selection := sessionConsumerSelection(t, selected, selected.admission.recipient, "secret")
				check := env.CurrentConsume(t, ctx, selected, selection, custody.StandardValue)
				if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
					t.Fatal("exact current authority did not consume", check)
				}
			}
		})
		if scenario.PrivateWitnesses() {
			for witness := uint8(1); witness <= 3; witness++ {
				run.phase("verification", func() { env.PrivateWitness(t, f.session, witness) })
			}
		}
	}
	run.phase("reopen", func() { env.FreshCurrent(t, f.admission, f.session) })
}

// This private memory parent uses the existing synthetic key facades. It is
// installed explicitly; the generic scenario never selects a provider fallback.
func syntheticAuthorityScenarioEnvironment(t testing.TB, env fixtureEnvironment) fixtureEnvironment {
	t.Helper()
	return syntheticAuthorityScenarioEnvironmentWithReplacement(t, env, nil)
}

// Actual generated loss cuts keep their producer runtime frozen. Replacement
// owns an independently admitted current source, not the producer's live slot.
func syntheticFreshAuthorityReplacementEnvironment(t testing.TB, env fixtureEnvironment) fixtureEnvironment {
	t.Helper()
	return syntheticAuthorityScenarioEnvironmentWithReplacement(t, env, func(t testing.TB, ctx context.Context, before *StateSession, source contract.BindingTableRow) *custody.Fixture {
		t.Helper()
		if got := env.Custody.PrivateWitness(ctx, source.Binding.BindingID, source.Binding, source.Binding); got != (custody.RouteWitness{Outcome: contract.CryptoSuccess, Completed: 1}) {
			t.Fatal("current replacement source is not surviving", got)
		}
		current, err := before.currentBindings()
		if err != nil {
			t.Fatal(err)
		}
		keys, err := custody.NewCurrentReplacement(t, fixtureID(contract.Hash(before.body), "fresh current replacement"), currentControlOf(before), current, source)
		if err != nil {
			t.Fatal(err)
		}
		return keys
	})
}

func syntheticAuthorityScenarioEnvironmentWithReplacement(t testing.TB, env fixtureEnvironment, replacementKeys func(testing.TB, context.Context, *StateSession, contract.BindingTableRow) *custody.Fixture) fixtureEnvironment {
	t.Helper()
	trust, ok := underlyingAdmittedFixtureTrust(env.Trust)
	if !ok {
		t.Fatal("synthetic authority requires the admitted fixture trust")
	}
	normal := trust.Signer
	var recovery *testtrust.Signer
	if env.Recovery != nil {
		recovery = env.Recovery.(*testtrust.Signer)
	}
	keys := env.Custody
	env.ReplacementActors = func(t testing.TB, ctx context.Context, before *StateSession, operation, mask, approval uint8) successionActors {
		t.Helper()
		body, err := contract.EncodeControlCore(currentControlOf(before))
		if err != nil {
			t.Fatal(err)
		}
		after, err := contract.DecodeControlCore(body)
		if err != nil {
			t.Fatal(err)
		}
		after.AccessGeneration++
		a := successionActors{After: after, Keys: keys, Store: env.Store, Signers: SuccessionSigners{Authorizer: normal}}
		if approval == 2 {
			if recovery == nil {
				t.Fatal("recovery authorizer is disabled")
			}
			a.Signers.Authorizer = recovery
		}
		var retired, successor *testtrust.Signer
		if mask&1 != 0 {
			successor, a.After.NormalSigning = normal.Successor(t, after.NormalSigning)
			retired, a.Signers.NormalSuccessor = normal, successor
		}
		if mask&4 != 0 {
			if recovery == nil {
				t.Fatal("recovery successor is disabled")
			}
			successor, a.After.Recovery.Signing = recovery.Successor(t, after.Recovery.Signing)
			retired, a.Signers.RecoverySuccessor = recovery, successor
		}
		if retired != nil && retired.Identity() != a.Signers.Authorizer.Identity() {
			retired.SetUnavailable(true)
		}
		var target contract.ID
		var lostBinding contract.BindingTableRow
		originalRetired := false
		retireOriginal := func() {
			witness := keys.PrivateWitness(ctx, lostBinding.Binding.BindingID, lostBinding.Binding, lostBinding.Binding)
			switch witness.Outcome {
			case contract.CryptoSuccess:
				if witness.Completed != 1 {
					t.Fatal("original replacement target has incomplete private access", witness)
				}
				if err := keys.RetireCurrentPrivateRoute(lostBinding); err != nil {
					t.Fatal(err)
				}
			case contract.CryptoInvalidAdmission, contract.CryptoPrivateRouteUnavailable:
				if witness.Completed != 0 {
					t.Fatal("absent replacement target completed private access", witness)
				}
			default:
				t.Fatal("original replacement target access is uncertain", witness)
			}
			originalRetired = true
		}
		if mask&(2|8) != 0 {
			a.Source = contract.BindingTableRow{SubjectKind: 1, SubjectID: after.AuthorityRecipientID, Binding: after.AuthorityKMSBinding}
			if mask&2 != 0 && after.Recovery != nil {
				a.Source = contract.BindingTableRow{SubjectKind: 2, SubjectID: after.Recovery.RoleID, Binding: after.Recovery.KMS}
			}
			if replacementKeys != nil {
				a.Keys = replacementKeys(t, ctx, before, a.Source)
			}
			if mask&2 != 0 {
				target = after.AuthorityRecipientID
				lostBinding = contract.BindingTableRow{SubjectKind: 1, SubjectID: target, Binding: after.AuthorityKMSBinding}
				a.After.AuthorityKMSBinding = a.Keys.KEKSuccessor(t, contract.SuccessorAuthorityKEK)
			} else {
				target = after.Recovery.RoleID
				lostBinding = contract.BindingTableRow{SubjectKind: 2, SubjectID: target, Binding: after.Recovery.KMS}
				a.After.Recovery.KMS = a.Keys.KEKSuccessor(t, contract.SuccessorRecoveryKEK)
			}
			if a.Source.SubjectID != target {
				a.Keys.LoseRecipientPredecessor(target)
				if a.Keys != keys {
					retireOriginal()
				}
			}
		}
		a.Activate = func(t testing.TB, _ *StateSession) {
			if !target.IsZero() {
				if err := a.Keys.ActivateSuccessor(target); err != nil {
					t.Fatal(err)
				}
				if a.Keys != keys && !originalRetired {
					retireOriginal()
				}
			}
			if retired != nil {
				retired.SetUnavailable(true)
				if mask&1 != 0 {
					normal = successor
				} else {
					recovery = successor
				}
			}
		}
		return a
	}
	env.CurrentConsume = func(t testing.TB, ctx context.Context, _ *StateSession, selection contract.ConsumerSelection, choice uint8) custody.ConsumerCheck {
		return keys.Consume(ctx, selection, choice)
	}
	env.PrivateWitness = func(t testing.TB, selected *StateSession, witness uint8) {
		t.Helper()
		control := currentControlOf(selected)
		if control.Recovery == nil {
			t.Fatal("private route witness requires independent recovery")
		}
		route, wrapped := control.AuthorityKMSBinding.BindingID, control.AuthorityKMSBinding
		want := custody.RouteWitness{Outcome: contract.CryptoSuccess, Completed: 1}
		switch witness {
		case 1:
		case 2:
			wrapped = control.Recovery.KMS
			want = custody.RouteWitness{Outcome: contract.CryptoPrivateRouteUnavailable, Failed: 1}
		case 3:
			route = control.Recovery.KMS.BindingID
			want = custody.RouteWitness{Outcome: contract.CryptoPrivateRouteUnavailable, Denied: 1}
		default:
			t.Fatal("unknown private witness")
		}
		if got := keys.PrivateWitness(context.Background(), route, control.AuthorityKMSBinding, wrapped); got != want {
			t.Fatal("private witness differs from exact provider result", witness, got)
		}
	}
	env.FreshCurrent = func(t testing.TB, admission OpenContext, selected *StateSession) {
		a := admission.admission
		input := selectedProcessFacts(t, admission, selected)
		var err error
		input.ExpectedWork, err = selected.workSupportRecords(t.Context())
		if err != nil {
			t.Fatal("fresh current work unavailable", err)
		}
		store := env.Store.(*memoryStore)
		input.Objects, input.Generation = store.objects, store.generation
		for _, entry := range selected.root.Names {
			if selected.valueEntry(entry.Slot).ConfidentialityClass == contract.Secret {
				input.Consumer = &successorConsumerInput{Binding: contract.BindingTableRow{SubjectKind: 1, SubjectID: a.recipient, Binding: *selected.authority().CurrentBinding}, Name: entry.Name, Value: custody.StandardValue}
			}
		}
		checkFreshProcessInput(t, input)
	}
	return env
}

// full_only: false
func TestAuthorityScenarioUsesCatalogStepsForEveryApplicableCase(t *testing.T) {
	for _, name := range catalog.CurrentKeyReplacementNames("both") {
		_, ok := catalog.AuthorityReplacement(name)
		if !ok {
			continue
		}
		definition, _ := catalog.DefinitionFor(name)
		for _, mode := range definition.RecoveryModes {
			t.Run(name+"/"+mode, func(t *testing.T) {
				env, _ := genesisEnvironment(t, contract.GCP, mode == "enabled")
				env = syntheticAuthorityScenarioEnvironment(t, env)
				step := 0
				env.Phase = func(name string) {
					if step >= len(definition.Steps) || definition.Steps[step].Name != name {
						t.Fatal("shared authority action differs from catalog plan", step, name)
					}
					step++
				}
				runStateScenario(t, context.Background(), env, name)
				if step != len(definition.Steps) {
					t.Fatal("shared authority action omitted catalog steps")
				}
			})
		}
	}
}

// full_only: false
func TestReciprocalAuthorityUsesCurrentPackages(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, material := range []bool{false, true} {
			env, _ := genesisEnvironment(t, family, true)
			env = syntheticAuthorityScenarioEnvironment(t, env)
			actors, consume, fresh := env.ReplacementActors, env.CurrentConsume, env.FreshCurrent
			stages, consumed, restarted := 0, 0, 0
			var initialWindow contract.MutationReceiptWindows
			var firstRecoveryOperation, firstRecoveryRequest, firstRecoveryRevision contract.ID
			env.ReplacementActors = func(t testing.TB, ctx context.Context, before *StateSession, operation, mask, approval uint8) successionActors {
				want := [][5]uint64{{1, 3, 2, 1, 1}, {3, 12, 1, 2, 1}, {1, 2, 2, 2, 2}, {3, 8, 1, 3, 2}}
				control := currentControlOf(before)
				if stages >= len(want) || [5]uint64{uint64(operation), uint64(mask), uint64(approval), control.AuthorityKMSBinding.BindingSerial, control.Recovery.KMS.BindingSerial} != want[stages] {
					t.Fatal("reciprocal replacement did not use its exact current generation", stages)
				}
				if stages == 0 {
					var err error
					initialWindow, err = before.receiptWindows(ctx)
					if err != nil || len(initialWindow.Successes)+2 > contract.MutationReceiptWindowLimit {
						t.Fatalf("reciprocal predecessor receipt history unavailable or needs eviction: read_error=%t successes=%d", err != nil, len(initialWindow.Successes))
					}
					initialWindow.Successes = slices.Clone(initialWindow.Successes)
					initialWindow.Failures = slices.Clone(initialWindow.Failures)
				}
				if stages == 2 {
					if before.head.Succession == nil || before.head.Succession.Subject.OperationKind != contract.SuccessionReplaceRecoveryBasis {
						t.Fatal("reciprocal intermediate HEAD is not the first Recovery replacement")
					}
					firstRecoveryOperation = before.head.Succession.Subject.OperationID
					firstRecoveryRequest = before.head.Succession.Subject.RequestIdentityDigest
					firstRecoveryRevision = before.head.Core.Revision
				}
				stages++
				return actors(t, ctx, before, operation, mask, approval)
			}
			env.CurrentConsume = func(t testing.TB, ctx context.Context, selected *StateSession, selection contract.ConsumerSelection, value uint8) custody.ConsumerCheck {
				consumed++
				return consume(t, ctx, selected, selection, value)
			}
			env.FreshCurrent = func(t testing.TB, admission OpenContext, selected *StateSession) {
				control := currentControlOf(selected)
				window, err := selected.receiptWindows(t.Context())
				if stages != 4 || control.AuthorityKMSBinding.BindingSerial != 3 || control.Recovery.KMS.BindingSerial != 3 || control.NormalSigning.Binding.Epoch != 2 || control.Recovery.Signing.Binding.Epoch != 2 || err != nil || len(window.Successes) != len(initialWindow.Successes)+2 {
					t.Fatalf("reciprocal restart has wrong current generation or receipt additions: stages=%d authority_serial=%d recovery_serial=%d normal_epoch=%d recovery_epoch=%d read_error=%t initial_successes=%d final_successes=%d", stages, control.AuthorityKMSBinding.BindingSerial, control.Recovery.KMS.BindingSerial, control.NormalSigning.Binding.Epoch, control.Recovery.Signing.Binding.Epoch, err != nil, len(initialWindow.Successes), len(window.Successes))
				}
				if window.DomainID != initialWindow.DomainID || !slices.Equal(window.Successes[:len(initialWindow.Successes)], initialWindow.Successes) || !slices.Equal(window.Failures, initialWindow.Failures) {
					t.Fatal("reciprocal replacement changed prior receipt history or domain")
				}
				if selected.head.Succession == nil || selected.head.Succession.Subject.OperationKind != contract.SuccessionReplaceRecoveryBasis {
					t.Fatal("reciprocal final HEAD is not the second Recovery replacement")
				}
				wantOperations := [2]contract.ID{firstRecoveryOperation, selected.head.Succession.Subject.OperationID}
				wantRequests := [2]contract.ID{firstRecoveryRequest, selected.head.Succession.Subject.RequestIdentityDigest}
				wantRevisions := [2]contract.ID{firstRecoveryRevision, selected.head.Core.Revision}
				if wantOperations[0] == wantOperations[1] {
					t.Fatal("reciprocal Recovery replacements reused an operation identity")
				}
				for i, row := range window.Successes[len(initialWindow.Successes):] {
					if row.DomainID != initialWindow.DomainID || row.OperationKind != contract.OperationReplaceRecoveryKeysAndRoot || row.StateResult != contract.ReceiptStateSuccess || row.EffectSummary != contract.ReceiptEffectNotApplicable || row.OperationID != wantOperations[i] || row.RequestIdentityDigest != wantRequests[i] || row.RequestedRevisionID != wantRevisions[i] || row.ObservedRevisionID != wantRevisions[i] {
						t.Fatal("reciprocal receipt addition differs from its actual Recovery replacement", i)
					}
				}
				restarted++
				fresh(t, admission, selected)
			}
			runAuthorityScenario(t, context.Background(), env, catalog.AuthorityReplacementCase{Material: material, Reciprocal: true})
			if stages != 4 || restarted != 1 || material && consumed != 4 || !material && consumed != 0 {
				t.Fatal("reciprocal scenario omitted current material checks or final restart", stages, consumed, restarted)
			}
		}
	}
}

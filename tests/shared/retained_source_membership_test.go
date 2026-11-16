package core

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

func selectRetainedMembership(t *testing.T, env fixtureEnvironment, selected *StateSession, readers []contract.ID, label string) *StateSession {
	t.Helper()
	sources, canonical := generatedCurrentDeclaration(t, selected)
	for i := range sources {
		if sources[i].Name == "shared" {
			sources[i].Recipients = slices.Clone(readers)
		}
	}
	input := generatedPlanInputForGenerations(t, selected, testID(t.Name()+label), []string{label}, defaultGeneratedFixtureProfile(), sources...)
	for i := range input.graph.ValueEntryPlans {
		if input.graph.ValueEntryPlans[i].Name == "shared" {
			input.graph.ValueEntryPlans[i].ChangeMask &^= contract.GeneratorValueChangeContent
			input.graph.ValueEntryPlans[i].ChangeMask |= contract.GeneratorValueChangeMembership
		}
	}
	var err error
	input.graph.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(input.graph.Header, input.graph.ValueEntryPlans, input.graph.Lineages, input.graph.Edges)
	if err != nil {
		t.Fatal(err)
	}
	prior, _ := preparePrivateGeneratedReservation(t, env, selected, input, canonical)
	recorded, _, _, _ := selectActualGeneratedPacketRecord(t, env, selected, prior, custody.StandardValue, true, nil)
	admitted := generatedPlanInputFixture(t, recorded).context
	admitted.AdmissionID, admitted.SessionID = testID(t.Name()+label+" final admission"), testID(t.Name()+label+" final session")
	plan, err := recorded.generatedFinalRequest(t.Context(), admitted)
	if err != nil || plan == nil || !plan.selecting {
		t.Fatal("membership Final request", err)
	}
	recorded, final := preparePrivateGeneratedFinal(t, env, recorded, plan)
	selected, result := recorded.selectCandidate(t.Context(), final.reservation.candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("membership Final selection", result)
	}
	env.Custody.RetireGenerated()
	return retainedReaderColdOpen(t, selected, env.Store)
}

// full_only: true
func TestGeneratedRetainedSourcesCoverRegisteredReaders(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprintf("reverse=%t", reverse), func(t *testing.T) {
			env, _ := genesisEnvironment(t, contract.GCP, true, 256)
			authority := fixtureID(env.Domain, "recipient")
			others := []contract.ID{fixtureID(env.Domain, "reader")}
			for i := 2; i < 256; i++ {
				others = append(others, fixtureID(env.Domain, fmt.Sprintf("reader-%03d", i)))
			}
			var cohorts [][]contract.ID
			for start := 0; start < len(others); start += 63 {
				readers := append([]contract.ID{authority}, others[start:min(start+63, len(others))]...)
				slices.SortFunc(readers, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
				cohorts = append(cohorts, readers)
			}
			run := newScenarioRun(t, t.Context(), env)
			f := newEnvironmentFixture(t, t.Context(), run.env, nil, false)
			run.suppliedSelection(f, []ApplyEntryInput{sharingSecretNamed(t, env, "shared", "full registry retained source", cohorts[0])})
			selected := f.session
			var values []contract.ValueEntry
			var owners []contract.ID
			var accesses []contract.AccessRecord
			for i, readers := range cohorts {
				if i > 0 {
					selected = selectRetainedMembership(t, env, selected, readers, fmt.Sprintf("membership-%d", i))
				}
				_, current := lifecycleEntry(t, selected, "shared")
				if i > 0 {
					assertPublicExclusionProtection(t, values[i-1], *current)
				}
				values = append(values, ownScenarioValueEntry(*current))
				sources, canonical := generatedCurrentDeclaration(t, selected)
				names := []string{fmt.Sprintf("failed-%d", i)}
				input := generatedPlanInputForGenerations(t, selected, testID(t.Name()+names[0]), names, defaultGeneratedFixtureProfile(), sources...)
				var attempt generatedAttempt
				selected, attempt = selectPrivateOwnedUnusableAggregateFromInput(t, env, selected, names, input, canonical)
				selected = retainedReaderColdOpen(t, selected, env.Store)
				owners = append(owners, attempt.expected.Template.HazardID)
				access, ok := selected.materialAccess(contract.ValueMaterialKind, current.ValueState)
				if !ok || len(access.Wraps) != len(readers)+1 {
					t.Fatal("exact cohort access")
				}
				accesses = append(accesses, access)
			}
			if len(mustSelectedGeneratedWork(t, selected).canonical) != 5 {
				t.Fatal("five exact sources are required")
			}
			total := 0
			for i, value := range values {
				access, ok := selected.materialAccess(contract.ValueMaterialKind, value.ValueState)
				body, err := contract.EncodeAccessRecord(access)
				if !ok || err != nil || !reflect.DeepEqual(access, accesses[i]) {
					t.Fatal("old cohort protection changed", i, err)
				}
				total += len(body)
				reader := others[i*63]
				source, result := selected.generatedConsumerSelection(t.Context(), contract.GeneratedHazardSupportKind, owners[i], value.ValueState, reader)
				if result.Outcome != ObservedCurrent || !reflect.DeepEqual(source.Record.Entry, value) {
					t.Fatal("exact cohort source", result)
				}
				bindings, err := selected.currentBindings()
				if err != nil {
					t.Fatal(err)
				}
				keys := custody.NewCurrentConsumer(t, testID(t.Name()+fmt.Sprint(i)), authority, selected.root.CurrentAccess.Core.Recovery.RoleID, bindings, source.Selection.Binding)
				if check := keys.ConsumeGenerated(t.Context(), source, custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
					t.Fatal("cohort consumption", check)
				}
				wrong := others[((i+1)%len(cohorts))*63]
				if _, result := selected.generatedConsumerSelection(t.Context(), contract.GeneratedHazardSupportKind, owners[i], value.ValueState, wrong); result.Outcome == ObservedCurrent {
					t.Fatal("another source granted cohort access")
				}
			}
			// Four 64-reader materials and one four-reader current material duplicate
			// Authority five times: 260 ordinary wraps plus five Recovery wraps.
			if total != 130095 {
				t.Fatal("five-material access ledger", total)
			}
			order := []int{0, 1, 2, 3, 4}
			if reverse {
				slices.Reverse(order)
			}
			remaining := map[int]bool{0: true, 1: true, 2: true, 3: true, 4: true}
			for _, ended := range order {
				selected = retainedReaderEndWork(t, selected, owners[ended], env.Trust)
				selected = retainedReaderColdOpen(t, selected, env.Store)
				delete(remaining, ended)
				for i, value := range values {
					access, present := selected.materialAccess(contract.ValueMaterialKind, value.ValueState)
					required := remaining[i] || i == 4
					if present != required || present && !reflect.DeepEqual(access, accesses[i]) {
						t.Fatal("owner disposition changed another material", ended, i)
					}
				}
				_, current := lifecycleEntry(t, selected, "shared")
				if !reflect.DeepEqual(*current, values[4]) {
					t.Fatal("old-owner exit changed current cohort")
				}
				if check := env.Custody.Consume(t.Context(), sessionConsumerSelection(t, selected, authority, "shared"), custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
					t.Fatal("current cohort consumption after owner exit", check)
				}
				for i := range remaining {
					source, result := selected.generatedConsumerSelection(t.Context(), contract.GeneratedHazardSupportKind, owners[i], values[i].ValueState, others[i*63])
					if result.Outcome != ObservedCurrent {
						t.Fatal("surviving cohort source", result)
					}
					if check := env.Custody.ConsumeGenerated(t.Context(), source, custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
						t.Fatal("surviving cohort consumption", check)
					}
				}
			}
		})
	}
}

// full_only: false
func TestGeneratedGrantOnlySourcesReachSameMaterialReaderLimit(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("recovery=%t", recovery), func(t *testing.T) {
			env, _ := genesisEnvironment(t, contract.GCP, recovery, 65)
			authority := fixtureID(env.Domain, "recipient")
			ids := []contract.ID{authority, fixtureID(env.Domain, "reader")}
			for i := 2; i < 65; i++ {
				ids = append(ids, fixtureID(env.Domain, fmt.Sprintf("reader-%03d", i)))
			}
			readers := func(n int) []contract.ID {
				out := slices.Clone(ids[:n])
				slices.SortFunc(out, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
				return out
			}
			run := newScenarioRun(t, t.Context(), env)
			f := newEnvironmentFixture(t, t.Context(), run.env, nil, false)
			run.suppliedSelection(f, []ApplyEntryInput{sharingSecretNamed(t, env, "shared", "grant-only same material", readers(1))})
			selected := f.session
			_, entry := lifecycleEntry(t, selected, "shared")
			original := ownScenarioValueEntry(*entry)
			var owners []contract.ID
			for _, count := range []int{1, 2, 32, 64} {
				if count > 1 {
					selected = selectRetainedMembership(t, env, selected, readers(count), fmt.Sprintf("grant-%d", count))
				}
				_, entry = lifecycleEntry(t, selected, "shared")
				if !sameRetainedEntryValue(*entry, original) || !slices.Equal(entry.Recipients, readers(count)) {
					t.Fatal("grant changed protected material")
				}
				sources, canonical := generatedCurrentDeclaration(t, selected)
				name := fmt.Sprintf("owner-%d", count)
				input := generatedPlanInputForGenerations(t, selected, testID(t.Name()+name), []string{name}, defaultGeneratedFixtureProfile(), sources...)
				var attempt generatedAttempt
				selected, attempt = selectPrivateOwnedUnusableAggregateFromInput(t, env, selected, []string{name}, input, canonical)
				selected = retainedReaderColdOpen(t, selected, env.Store)
				owners = append(owners, attempt.expected.Template.HazardID)
			}
			work := mustSelectedGeneratedWork(t, selected)
			access, present := selected.materialAccess(contract.ValueMaterialKind, original.ValueState)
			body, err := contract.EncodeAccessRecord(access)
			if !present || err != nil || len(work.canonical) != 4 || len(access.Wraps) != 64+boolInt(recovery) || len(body) != 31398+489*boolInt(recovery) {
				t.Fatal("reachable same-material maximum", len(body), err)
			}
			for i, count := range []int{1, 2, 32, 64} {
				source, result := selected.generatedConsumerSelection(t.Context(), contract.GeneratedHazardSupportKind, owners[i], original.ValueState, ids[count-1])
				if result.Outcome != ObservedCurrent || !slices.Equal(source.Record.Entry.Recipients, readers(count)) {
					t.Fatal("exact grant source admission", result)
				}
				if check := env.Custody.ConsumeGenerated(t.Context(), source, custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
					t.Fatal("grant source consumption", check)
				}
				if count < 64 {
					if _, result := selected.generatedConsumerSelection(t.Context(), contract.GeneratedHazardSupportKind, owners[i], original.ValueState, ids[count]); result.Outcome == ObservedCurrent {
						t.Fatal("later grant authorized earlier source")
					}
				}
			}
			sources, _ := generatedCurrentDeclaration(t, selected)
			declaration := contract.GeneratorDeclaration{Schema: 1, DomainID: env.Domain, OperationID: testID(t.Name() + " over"), Entries: sources}
			if _, err := contract.EncodeGeneratorDeclaration(declaration); err != nil {
				t.Fatal("64-reader declaration control", err)
			}
			for i := range sources {
				if sources[i].Name == "shared" {
					sources[i].Recipients = readers(65)
				}
			}
			if _, err := contract.EncodeGeneratorDeclaration(declaration); err == nil {
				t.Fatal("65 current memberships admitted")
			}
			// After exclusion current material is separate. Ending the largest source
			// first must shrink the old-material union to the largest surviving source.
			selected = selectRetainedMembership(t, env, selected, readers(1), "exclude-after-grants")
			_, current := lifecycleEntry(t, selected, "shared")
			fresh := ownScenarioValueEntry(*current)
			assertPublicExclusionProtection(t, original, fresh)
			for i := len(owners) - 1; i >= 0; i-- {
				selected = retainedReaderEndWork(t, selected, owners[i], env.Trust)
				selected = retainedReaderColdOpen(t, selected, env.Store)
				old, ok := selected.materialAccess(contract.ValueMaterialKind, original.ValueState)
				if i == 0 {
					if ok {
						t.Fatal("last source left old material")
					}
				} else {
					want := readers([]int{1, 2, 32, 64}[i-1])
					if !ok || len(old.Wraps) != len(want)+boolInt(recovery) {
						t.Fatal("largest surviving source union")
					}
					for j, id := range want {
						at := slices.IndexFunc(access.Wraps, func(w contract.WrapRow) bool {
							return w.SubjectKind == contract.OrdinaryWrapSubject && w.SubjectID == id
						})
						if at < 0 || !reflect.DeepEqual(old.Wraps[j], access.Wraps[at]) {
							t.Fatal("surviving grant wrap changed")
						}
					}
					if recovery && !reflect.DeepEqual(old.Wraps[len(want)], access.Wraps[64]) {
						t.Fatal("old Recovery wrap changed")
					}
				}
				_, current = lifecycleEntry(t, selected, "shared")
				if !reflect.DeepEqual(*current, fresh) {
					t.Fatal("old source exit changed new current")
				}
				if check := env.Custody.Consume(t.Context(), sessionConsumerSelection(t, selected, authority, "shared"), custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
					t.Fatal("fresh current consumption after grant-source exit", check)
				}
			}
		})
	}
}

// full_only: false
func TestGeneratedReservationRetainsCurrentSourceAfterReaderRemoval(t *testing.T) {
	f := newRetainedReaderFixture(t, false, 2)
	_, current := lifecycleEntry(t, f.selected, "shared")
	authority := fixtureID(f.env.Domain, "recipient")
	if !slices.Equal(current.Recipients, []contract.ID{authority}) || len(f.value.Recipients) != 2 || len(f.owners) != 2 {
		t.Fatal("fixture must retain old readers under real owners after current membership changes")
	}
	sources, canonical := generatedCurrentDeclaration(t, f.selected)
	for _, source := range sources {
		if source.Name != "shared" {
			continue
		}
		retained, err := contract.DecodeRetainedCanonicalRecord(source.Payload)
		if err != nil || !slices.Equal(retained.Entry.Recipients, []contract.ID{authority}) {
			t.Fatal("next operation must use the exact current source", err)
		}
	}
	input := generatedPlanInputForGenerations(t, f.selected, testID(t.Name()+" next operation"),
		[]string{"next-generated"}, defaultGeneratedFixtureProfile(), sources...)
	// A later operation must remain possible while the older owners retain
	// their own source reader list. Changing the declaration is not a repair.
	preparePrivateGeneratedReservation(t, f.env, f.selected, input, canonical)
}

// full_only: false
func TestGeneratedReservationRetainsCurrentSourceAfterLastOlderOwnerEnds(t *testing.T) {
	f := newRetainedReaderFixture(t, false, 2)
	selected := f.selected
	for _, owner := range retainedReaderOwnerIDs(f) {
		selected = retainedReaderEndWork(t, selected, owner, f.env.Trust)
		selected = retainedReaderColdOpen(t, selected, f.env.Store)
	}
	checkRetainedReaderAccess(t, selected, f, false)
	sources, canonical := generatedCurrentDeclaration(t, selected)
	input := generatedPlanInputForGenerations(t, selected, testID(t.Name()+" next operation"),
		[]string{"next-generated"}, defaultGeneratedFixtureProfile(), sources...)
	preparePrivateGeneratedReservation(t, f.env, selected, input, canonical)
}

// full_only: false
func TestGeneratedDistinctRetainedSourcesKeepOwnerReaders(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for _, newestFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("recovery=%t/newest_first=%t", recovery, newestFirst), func(t *testing.T) {
				f := newRetainedReaderFixture(t, recovery, 2)
				sources, canonical := generatedCurrentDeclaration(t, f.selected)
				names := []string{"newer-failed"}
				input := generatedPlanInputForGenerations(t, f.selected, testID(t.Name()+" new operation"), names, defaultGeneratedFixtureProfile(), sources...)
				selected, attempt := selectPrivateOwnedUnusableAggregateFromInput(t, f.env, f.selected, names, input, canonical)
				selected = retainedReaderColdOpen(t, selected, f.env.Store)
				newest := attempt.expected.Template.HazardID
				authority, reader := fixtureID(f.env.Domain, "recipient"), fixtureID(f.env.Domain, "reader")
				work := mustSelectedGeneratedWork(t, selected)
				if len(work.canonical) != 2 {
					t.Fatal("different saved reader lists did not survive as two exact sources")
				}
				checkOwner := func(owner, material, acting contract.ID, allowed bool) {
					t.Helper()
					source, result := selected.generatedConsumerSelection(t.Context(), contract.GeneratedHazardSupportKind, owner, material, acting)
					if !allowed {
						if result.Outcome == ObservedCurrent {
							t.Fatal("wrap union granted a reader to a different saved source")
						}
						return
					}
					if result.Outcome != ObservedCurrent {
						t.Fatal("owner lost its source", result)
					}
					bindings, err := selected.currentBindings()
					if err != nil {
						t.Fatal(err)
					}
					var recoveryID contract.ID
					if selected.root.CurrentAccess.Core.Recovery != nil {
						recoveryID = selected.root.CurrentAccess.Core.Recovery.RoleID
					}
					keys := custody.NewCurrentConsumer(t, testID(t.Name()+" consume"), authority, recoveryID, bindings, source.Selection.Binding)
					if check := keys.ConsumeGenerated(t.Context(), source, custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || check.SinkCalls != 1 || !check.ValueMatched {
						t.Fatal("exact owner consumption", check)
					}
				}
				checkOwner(newest, f.current.ValueState, authority, true)
				checkOwner(newest, f.current.ValueState, reader, false)
				older := retainedReaderOwnerIDs(f)
				for _, owner := range older {
					checkOwner(owner, f.value.ValueState, reader, true)
				}
				order := append(slices.Clone(older), newest)
				if newestFirst {
					order = append([]contract.ID{newest}, older...)
				}
				remaining := map[contract.ID]bool{older[0]: true, older[1]: true, newest: true}
				for _, ended := range order {
					selected = retainedReaderEndWork(t, selected, ended, f.env.Trust)
					selected = retainedReaderColdOpen(t, selected, f.env.Store)
					delete(remaining, ended)
					oldSurvives := remaining[older[0]] || remaining[older[1]]
					checkRetainedReaderAccess(t, selected, f, oldSurvives)
					for owner := range remaining {
						if owner == newest {
							checkOwner(owner, f.current.ValueState, authority, true)
							checkOwner(owner, f.current.ValueState, reader, false)
						} else {
							checkOwner(owner, f.value.ValueState, reader, true)
						}
					}
					material := f.value.ValueState
					if ended == newest {
						material = f.current.ValueState
					}
					checkOwner(ended, material, authority, false)
				}
			})
		}
	}
}

// full_only: false
func TestRetainedOnlyReaderSurvivesNormalMutationAndKeyReplacement(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			f := newRetainedReaderFixture(t, recovery, 2)
			env, selected := f.env, f.selected
			keys := env.Custody
			sources, canonical := generatedCurrentDeclaration(t, selected)
			names := []string{"newer-failed"}
			input := generatedPlanInputForGenerations(t, selected, testID(t.Name()+" newer"), names, defaultGeneratedFixtureProfile(), sources...)
			selected, attempt := selectPrivateOwnedUnusableAggregateFromInput(t, env, selected, names, input, canonical)
			selected = retainedReaderColdOpen(t, selected, env.Store)
			authority, reader := fixtureID(env.Domain, "recipient"), fixtureID(env.Domain, "reader")
			older := retainedReaderOwnerIDs(f)
			before := mustSelectedGeneratedWork(t, selected)
			if len(before.canonical) != 2 {
				t.Fatal("expected two exact saved sources")
			}
			access, _ := selected.materialAccess(contract.ValueMaterialKind, f.value.ValueState)
			beforeAccess, err := contract.EncodeAccessRecord(access)
			if err != nil {
				t.Fatal(err)
			}
			apply := selected.currentEntryInputs()
			for i := range apply {
				if apply[i].Name == "shared" {
					apply[i] = sharingSecretNamed(t, env, "shared", "normal unchanged shared input", []contract.ID{authority})
				}
			}

			apply = append(apply, ApplyEntryInput{Name: "plain-marker", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{authority}, InputBytes: []byte("normal mutation with retained-only reader"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
			parent := admitSuppliedComparison(t, selected, keys, apply)
			comparison, result := selected.Compare(t.Context(), apply, parent)
			if comparison == nil {
				t.Fatal("normal comparison", result)
			}
			candidate, result := selected.Prepare(t.Context(), comparison, admit(t, selected, comparison), env.Trust)
			if candidate == nil || result.Outcome != ObservedCurrent {
				t.Fatal("normal preparation", result)
			}
			selected, result = selected.selectCandidate(t.Context(), candidate)
			if selected == nil || result.Outcome != ObservedCurrent {
				t.Fatal("normal selection", result)
			}
			keys.RetireApply()
			selected = retainedReaderColdOpen(t, selected, env.Store)
			access, _ = selected.materialAccess(contract.ValueMaterialKind, f.value.ValueState)
			body, err := contract.EncodeAccessRecord(access)
			if err != nil || !bytes.Equal(body, beforeAccess) {
				t.Fatal("normal mutation changed retained access", err)
			}

			successor := keys.RecipientSuccessor(t, reader)
			keys.LoseRecipientPredecessor(reader)
			permit := admitReaderReplacement(t, selected, keys, reader, successor)
			candidate, result = selected.PrepareRecipientReplacement(t.Context(), permit, env.Trust)
			if candidate == nil || result.Outcome != ObservedCurrent {
				t.Fatal("retained-only recipient replacement", result)
			}
			selected, result = selected.selectCandidate(t.Context(), candidate)
			if selected == nil || result.Outcome != ObservedCurrent {
				t.Fatal("recipient replacement selection", result)
			}
			keys.RetireAccess()
			if err := keys.ActivateRecipientSuccessor(reader); err != nil {
				t.Fatal(err)
			}
			selected = retainedReaderColdOpen(t, selected, env.Store)
			afterAccess, _ := selected.materialAccess(contract.ValueMaterialKind, f.value.ValueState)
			if len(afterAccess.Wraps) != len(access.Wraps) {
				t.Fatal("replacement changed reader count")
			}
			for i, old := range access.Wraps {
				if old.SubjectKind == contract.OrdinaryWrapSubject && old.SubjectID == reader {
					if afterAccess.Wraps[i].BindingID != successor.BindingID || bytes.Equal(afterAccess.Wraps[i].RSACiphertext, old.RSACiphertext) {
						t.Fatal("retained-only wrap did not move to successor")
					}
				} else if !reflect.DeepEqual(afterAccess.Wraps[i], old) {
					t.Fatal("replacement changed unrelated wrap")
				}
			}
			if recovery {
				replacement := syntheticFreshAuthorityReplacementEnvironment(t, env)
				actors := replacement.ReplacementActors(t, t.Context(), selected, contract.SuccessionReplaceRecoveryBasis, contract.SuccessionChangeRecoveryKEK, contract.NormalSigningRole)
				permit := admitAuthorityReplacement(t, selected, actors.Keys, actors.After, contract.SuccessionReplaceRecoveryBasis, contract.NormalSigningRole, contract.SuccessionChangeRecoveryKEK, actors.Source)
				candidate, result = selected.PrepareSuccession(t.Context(), permit, actors.Signers)
				if candidate == nil || result.Outcome != ObservedCurrent {
					t.Fatal("retained Recovery replacement", result)
				}
				admission := deliverSuccessionBasis(t, candidate)
				if result := selected.Select(t.Context(), candidate); result.Outcome != ObservedCurrent {
					t.Fatal("Recovery selection", result)
				}
				actors.Keys.RetireAccess()
				selected, result = Open(t.Context(), admission, env.Store)
				if selected == nil || result.Outcome != ObservedCurrent {
					t.Fatal("Recovery cold Open", result)
				}
				actors.Activate(t, selected)
				got, _ := selected.materialAccess(contract.ValueMaterialKind, f.value.ValueState)
				if len(got.Wraps) != len(afterAccess.Wraps) {
					t.Fatal("Recovery changed reader count")
				}
				for i, old := range afterAccess.Wraps {
					if old.SubjectKind == contract.RecoveryWrapSubject {
						if got.Wraps[i].BindingID != actors.After.Recovery.KMS.BindingID || bytes.Equal(got.Wraps[i].RSACiphertext, old.RSACiphertext) {
							t.Fatal("Recovery did not move retained material")
						}
					} else if !reflect.DeepEqual(got.Wraps[i], old) {
						t.Fatal("Recovery changed ordinary wrap")
					}
				}
			}
			after := mustSelectedGeneratedWork(t, selected)
			if len(before.canonical) != len(after.canonical) {
				t.Fatal("mutation or replacement changed exact saved sources")
			}
			for id, old := range before.canonical {
				got, ok := after.canonical[id]
				if !ok || !reflect.DeepEqual(old.record, got.record) || !reflect.DeepEqual(old.core, got.core) || !reflect.DeepEqual(old.payload, got.payload) {
					t.Fatal("mutation or replacement changed exact saved source", id)
				}
			}
			_, current := lifecycleEntry(t, selected, "shared")
			if !sameRetainedEntryValue(*current, f.current) || !slices.Equal(current.Recipients, []contract.ID{authority}) {
				t.Fatal("mutation or replacement changed current value")
			}
			for _, owner := range older {
				selection, result := selected.generatedConsumerSelection(t.Context(), contract.GeneratedHazardSupportKind, owner, f.value.ValueState, reader)
				if result.Outcome != ObservedCurrent || selection.Selection.Binding.Binding.BindingID != successor.BindingID {
					t.Fatal("older source did not resolve successor", result)
				}
				check := keys.ConsumeGenerated(t.Context(), selection, custody.StandardValue)
				if check.Code != contract.CryptoSuccess || check.Delivery != 1 || check.SinkCalls != 1 || !check.ValueMatched || len(check.KeyUses) != 1 || check.KeyUses[0].BindingID != successor.BindingID {
					t.Fatal("successor retained consumption", check)
				}
			}
			if _, result := selected.generatedConsumerSelection(t.Context(), contract.GeneratedHazardSupportKind, attempt.expected.Template.HazardID, f.current.ValueState, reader); result.Outcome == ObservedCurrent {
				t.Fatal("shared wrap granted reader to newer A-only source")
			}

			retainedAccess, present := selected.materialAccess(contract.ValueMaterialKind, f.value.ValueState)
			wantAccess, err := contract.EncodeAccessRecord(retainedAccess)
			if !present || err != nil {
				t.Fatal("post-replacement retained access", err)
			}
			wantValueEntries := selected.root.ValueEntryCount + 1
			wantGenerated := selected.root.Generated.GeneratedCurrent + 1
			continuation := currentGeneratedEnvironment(t, env.Store, selected)
			sources, canonical = generatedCurrentDeclaration(t, selected)
			input = generatedPlanInputForGenerations(t, selected, testID(t.Name()+" checkpoint continuation"),
				[]string{"after-replacement"}, defaultGeneratedFixtureProfile(), sources...)
			prior, _ := preparePrivateGeneratedReservation(t, continuation, selected, input, canonical)
			recorded, _, _, _ := selectActualGeneratedPacketRecord(t, continuation, selected, prior, custody.StandardValue, true, nil)
			prepared := prepareCheckpointFinal(t, continuation, recorded, t.Name()+" retained-only checkpoint")
			if prepared.reservation.candidate.head.Generator == nil || prepared.reservation.candidate.head.Generator.Purpose != contract.GeneratorAuthorityFinalPreparation {
				t.Fatal("retained-only continuation omitted its preparation checkpoint")
			}
			if candidate, result := recorded.ClaimGeneratedPreparation(t.Context(), prepared.reservation.candidate, continuation.Trust); candidate == nil || result.Outcome != ObservedCurrent {
				t.Fatal("retained-only checkpoint claim", result)
			}
			checkpoint, result := recorded.selectCandidate(t.Context(), prepared.reservation.candidate)
			if checkpoint == nil || result.Outcome != ObservedCurrent ||
				!reflect.DeepEqual(checkpoint.currentEntryInputs(), recorded.currentEntryInputs()) ||
				!reflect.DeepEqual(checkpoint.accessRecords(), recorded.accessRecords()) {
				t.Fatal("retained-only checkpoint changed the selected current set or access", result)
			}
			checkpointAccess, present := checkpoint.materialAccess(contract.ValueMaterialKind, f.value.ValueState)
			checkpointBody, err := contract.EncodeAccessRecord(checkpointAccess)
			if !present || err != nil || !bytes.Equal(checkpointBody, wantAccess) {
				t.Fatal("checkpoint changed post-replacement retained access", err)
			}
			continuation.Custody.RetireGenerated()
			work := mustSelectedGeneratedWork(t, checkpoint)
			if work.preparation == nil || work.phase.FinalPreparationID != work.preparation.Image.ContentID {
				t.Fatal("retained-only checkpoint lost its selected image association")
			}
			expected := generatedFinalCheckpointExpectation{Mode: "reuse", ImageID: work.preparation.Image.ContentID,
				MaterializationPhaseID: mustGeneratedPhaseID(work.preparation.MaterializationPhase)}
			image, err := work.readSelectedSlice(t.Context(), contract.GeneratorContentFinalPreparation, expected.ImageID, contract.GeneratedFinalPreparationMaxLength)
			if err != nil || contract.Hash(image) != expected.ImageID {
				t.Fatal("retained-only checkpoint image", err)
			}
			image = bytes.Clone(image)
			artifacts := checkpointArtifactBodies(t, recorded, prepared.reservation.candidate)
			store := requireAdmittedMemoryStore(t, env.Store)
			process := selectedGeneratedProcessFacts(t, checkpoint)
			process.Objects, process.Generation, process.GeneratedFinal = store.objects, store.generation, true
			process.GeneratedFinalCheckpoint = &expected
			output := checkFreshProcessInput(t, process)
			if output == nil || output.CheckpointHead != nil || len(output.CheckpointObjects) != 0 {
				t.Fatal("cold actual Final did not reuse the exact post-replacement checkpoint")
			}
			selected = importFreshGeneratedSelection(t, checkpoint, process.Generation, output)
			selected = retainedReaderColdOpen(t, selected, env.Store)
			gotAccess, present := selected.materialAccess(contract.ValueMaterialKind, f.value.ValueState)
			gotBody, err := contract.EncodeAccessRecord(gotAccess)
			if !present || err != nil || !bytes.Equal(gotBody, wantAccess) || !selected.root.Generated.ActiveOwner.IsZero() ||
				selected.root.ValueEntryCount != wantValueEntries || selected.root.Generated.GeneratedCurrent != wantGenerated {
				t.Fatal("cold actual Final changed post-replacement retained access or omitted its generated value", err)
			}
			for _, wrap := range gotAccess.Wraps {
				if wrap.SubjectKind == contract.OrdinaryWrapSubject && wrap.SubjectID == reader && wrap.BindingID != successor.BindingID {
					t.Fatal("cold actual Final restored a retained predecessor wrap")
				}
			}
			_, current = lifecycleEntry(t, selected, "shared")
			if !sameRetainedEntryValue(*current, f.current) || !slices.Equal(current.Recipients, []contract.ID{authority}) {
				t.Fatal("cold actual Final changed current value protection")
			}
			for key, body := range artifacts {
				if object, ok := store.objects[key]; !ok || !bytes.Equal(object.Body, body) {
					t.Fatal("cold actual Final changed immutable checkpoint bytes", key)
				}
			}
			gotImage, err := work.readSelectedSlice(t.Context(), contract.GeneratorContentFinalPreparation, expected.ImageID, contract.GeneratedFinalPreparationMaxLength)
			if err != nil || !bytes.Equal(gotImage, image) {
				t.Fatal("cold actual Final changed the saved preparation image", err)
			}
			for _, owner := range older {
				selection, result := selected.generatedConsumerSelection(t.Context(), contract.GeneratedHazardSupportKind, owner, f.value.ValueState, reader)
				if result.Outcome != ObservedCurrent || selection.Selection.Binding.Binding.BindingID != successor.BindingID {
					t.Fatal("cold actual Final lost the retained successor reader", result)
				}
				check := keys.ConsumeGenerated(t.Context(), selection, custody.StandardValue)
				if check.Code != contract.CryptoSuccess || check.Delivery != 1 || check.SinkCalls != 1 || !check.ValueMatched ||
					len(check.KeyUses) != 1 || check.KeyUses[0].SubjectID != reader || check.KeyUses[0].BindingID != successor.BindingID {
					t.Fatal("cold actual Final successor retained consumption", check)
				}
			}
		})
	}
}

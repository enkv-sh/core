package core

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestGeneratedSuppliedContentClearRequiresUnchangedMeaning(t *testing.T) {
	for _, name := range []string{"new plain", "new sealed", "changed plain", "unchanged plain", "plain membership", "changed sealed", "unchanged sealed", "sealed membership addition", "sealed membership removal", "sealed content removal", "changed sealed content removal", "retained membership"} {
		t.Run(name, func(t *testing.T) {
			changedContentRemoval := name == "sealed content removal" || name == "changed sealed content removal"
			env, keys := genesisEnvironment(t, contract.GCP, true)
			run := newScenarioRun(t, t.Context(), env)
			var sizes []int
			var names []string
			if name == "changed plain" || name == "unchanged plain" || name == "plain membership" {
				sizes, names = []int{1}, []string{"supplied"}
			}
			fixture := newNamedEnvironmentFixture(t, t.Context(), env, sizes, false, names)
			var before *contract.ValueEntry
			if name != "new plain" && name != "new sealed" {
				if name == "changed sealed" || name == "unchanged sealed" || name == "retained membership" || name == "sealed membership addition" || name == "sealed membership removal" || changedContentRemoval {
					input := suppliedSecret(t, env, "supplied", "selected supplied seal", custody.StandardValue)
					if name == "sealed membership removal" || changedContentRemoval {
						readers := []contract.ID{fixture.session.admission.recipient, fixtureID(env.Domain, "reader")}
						slices.SortFunc(readers, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
						input = sharingSecretNamed(t, env, "supplied", "selected shared supplied seal", readers)
					}
					candidate := run.suppliedPreparation(fixture, []ApplyEntryInput{input})
					selected, result := fixture.session.selectCandidate(t.Context(), candidate)
					if selected == nil || result.Outcome != ObservedCurrent {
						t.Fatal("selected supplied secret", result)
					}
					fixture.session = generatedLifecycleReopen(t, t.Context(), selected, env.Store)
				}
				entry := *fixture.session.valueEntry(0)
				before = &entry
			}
			s := fixture.session
			source := contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationPlain, Name: "supplied", Recipients: []contract.ID{s.admission.recipient}, Payload: []byte{0}}
			switch name {
			case "new sealed", "changed sealed", "unchanged sealed", "sealed membership addition", "sealed membership removal", "sealed content removal", "changed sealed content removal":
				choice := uint8(custody.StandardValue)
				if name == "changed sealed" || name == "changed sealed content removal" {
					choice = custody.EmptyValue
				}
				sealed := suppliedSecret(t, env, source.Name, "proposed supplied seal", choice)
				if name == "sealed membership addition" {
					source.Recipients = []contract.ID{s.admission.recipient, fixtureID(env.Domain, "reader")}
					slices.SortFunc(source.Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
					sealed = sharingSecretNamed(t, env, source.Name, "proposed shared supplied seal", source.Recipients)
				}
				source.Kind, source.Payload = contract.GeneratorDeclarationSealed, sealed.InputBytes
			case "changed plain":
				source.Payload = []byte{1}
			case "plain membership":
				source.Recipients = []contract.ID{s.admission.recipient, fixtureID(env.Domain, "reader")}
			case "retained membership":
				source.Kind = contract.GeneratorDeclarationRetained
				var err error
				source.Payload, err = contract.EncodeRetainedCanonicalRecord(contract.RetainedCanonicalRecord{OriginalSlot: 0, Entry: *before})
				if err != nil {
					t.Fatal("selected retained source", err)
				}
				source.Recipients = []contract.ID{s.admission.recipient, fixtureID(env.Domain, "reader")}
			}
			slices.SortFunc(source.Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			input := generatedPlanInputForGenerations(t, s, generatedVectorID(10), []string{"generated"}, defaultGeneratedFixtureProfile(), source)
			for i := range input.graph.ValueEntryPlans {
				if input.graph.ValueEntryPlans[i].ValueSource == contract.Supplied {
					if !changedContentRemoval {
						input.graph.ValueEntryPlans[i].ChangeMask &^= contract.GeneratorValueChangeContent
					}
					if name == "plain membership" || name == "retained membership" || name == "sealed membership addition" || name == "sealed membership removal" || changedContentRemoval {
						input.graph.ValueEntryPlans[i].ChangeMask |= contract.GeneratorValueChangeMembership
					}
				}
			}
			var err error
			input.graph.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(input.graph.Header, input.graph.ValueEntryPlans, input.graph.Lineages, input.graph.Edges)
			if err != nil || contract.ValidateGeneratorEffectGraph(input.graph) != nil {
				t.Fatal("content-clear graph fixture", err)
			}
			var canonical []custody.GeneratedCanonicalSelection
			if name == "retained membership" {
				selection := sessionConsumerSelection(t, s, s.admission.recipient, before.Name)
				canonical = []custody.GeneratedCanonicalSelection{{Record: contract.RetainedCanonicalRecord{OriginalSlot: 0, Entry: *before}, Selection: selection}}
			}
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			creates, cas, signs := store.creates, store.cas, trust.signs
			permit, admissionErr := admitUnclaimedGeneratedReservation(t, env, s, input, canonical)
			var preparation *generatedPreparation
			if admissionErr == nil {
				var result Result
				preparation, result = s.PrepareGeneratedPlan(t.Context(), permit)
				if preparation == nil && result.Outcome == ObservedCurrent {
					t.Fatal("refused plan reported admitted preparation")
				}
			}
			if store.creates != creates || store.cas != cas || trust.signs != signs {
				t.Fatal("supplied meaning admission reached persistence or signing")
			}
			refuse := name == "new plain" || name == "new sealed" || name == "changed plain" || name == "changed sealed"
			if refuse {
				if admissionErr == nil && preparation != nil {
					t.Fatal("new or changed supplied content admitted without content preparation")
				}
				return
			}
			if admissionErr != nil || preparation == nil {
				t.Fatal("legitimate unchanged supplied meaning refused", admissionErr)
			}
			if code := keys.BindGeneratedCandidate(t.Context(), preparation.operation.context.AdmissionID, generatedPrivateCandidate(t, preparation)); code != contract.CryptoSuccess {
				t.Fatal("unchanged supplied reservation binding", code)
			}
			if candidate, result := s.ClaimGeneratedPreparation(t.Context(), preparation.reservation.candidate, env.Trust); candidate == nil || result.Outcome != ObservedCurrent {
				t.Fatal("unchanged supplied reservation Claim", result)
			}
			recorded, _, _, _ := selectActualGeneratedPacketRecord(t, env, s, preparation, custody.StandardValue, true, nil)
			finalContext := generatedPlanInputFixture(t, recorded).context
			finalContext.AdmissionID, finalContext.SessionID = testID("supplied meaning Final admission"), testID("supplied meaning Final session")
			plan, err := recorded.generatedFinalRequest(t.Context(), finalContext)
			if err != nil {
				t.Fatal("unchanged supplied Final plan", err)
			}
			membership := name == "sealed membership addition" || name == "sealed membership removal" || changedContentRemoval
			beforeAccess, _ := s.materialAccess(contract.ValueMaterialKind, before.ValueState)
			capture := &suppliedMeaningMembershipCrypto{inner: env.Crypto, keys: keys, t: t, addition: name == "sealed membership addition", content: changedContentRemoval}
			var final *generatedPreparation
			if membership {
				recorded, final = preparePrivateGeneratedFinal(t, env, recorded, plan, capture)
				wantArtifacts := checkpointArtifactBodies(t, recorded, final.reservation.candidate)
				wantHead, err := format.DecodeHead(bytes.Clone(final.reservation.candidate.body))
				if err != nil {
					t.Fatal("original unchanged supplied Final HEAD", err)
				}
				wantHead.AuthorizationSignature = nil
				// Reconstruct the selected preparation in a fresh Core session and a
				// fresh private admission before selecting the exact same Final.
				cold := generatedLifecycleReopen(t, t.Context(), recorded, env.Store)
				keys.RetireGenerated()
				admitted := generatedPlanInputFixture(t, cold).context
				admitted.AdmissionID, admitted.SessionID = testID(t.Name()+" replay admission"), testID(t.Name()+" replay session")
				replayPlan, err := cold.generatedFinalRequest(t.Context(), admitted)
				if err != nil {
					t.Fatal("cold unchanged supplied Final request", err)
				}
				var replay *generatedPreparation
				cold, replay = preparePrivateGeneratedFinal(t, env, cold, replayPlan, capture)
				if changedContentRemoval {
					opens := uint32(0)
					for _, use := range replay.keyUses {
						if use.Purpose == contract.KeyUseMaterialOpen {
							if use.Outcome != contract.KeyUseCompleted {
								t.Fatal("changed sealed replay source open did not complete")
							}
							opens += use.Count
						}
					}
					if opens != 4 {
						t.Fatal("changed sealed exclusion replay must open seed, both saved values and old current packet", opens)
					}
				}
				replayHead := replay.reservation.candidate.head
				replayHead.AuthorizationSignature = nil
				if !reflect.DeepEqual(checkpointArtifactBodies(t, cold, replay.reservation.candidate), wantArtifacts) ||
					!reflect.DeepEqual(replayHead, wantHead) || capture.batches != 1 {
					t.Fatal("cold Final changed immutable artifacts, signed HEAD meaning or membership preparation count", capture.batches)
				}
				recorded, final = cold, replay
			} else {
				recorded, final = preparePrivateGeneratedFinal(t, env, recorded, plan)
			}
			selected, result := recorded.selectCandidate(t.Context(), final.reservation.candidate)
			if selected == nil || result.Outcome != ObservedCurrent {
				t.Fatal("unchanged supplied Final selection", result)
			}
			selected = generatedLifecycleReopen(t, t.Context(), selected, env.Store)
			entry := selected.valueEntry(0)
			exclusion := name == "sealed membership removal" || changedContentRemoval
			if entry == nil || !slices.Equal(entry.Recipients, source.Recipients) || entry.Incarnation != before.Incarnation {
				t.Fatal("content-clear supplied Final changed the entry or omitted intended membership")
			}
			if exclusion {
				if entry.ValueState == before.ValueState || bytes.Equal(entry.ValueBytes, before.ValueBytes) {
					t.Fatal("content-clear removal reused old protection")
				}
				if _, present := selected.materialAccess(contract.ValueMaterialKind, before.ValueState); present {
					t.Fatal("content-clear removal retained unused old material")
				}
				choice := uint8(custody.StandardValue)
				if name == "changed sealed content removal" {
					choice = custody.EmptyValue
				}
				if check := keys.Consume(t.Context(), sessionConsumerSelection(t, selected, s.admission.recipient, entry.Name), choice); check.Code != contract.CryptoSuccess || !check.ValueMatched || check.Delivery != 1 {
					t.Fatal("content-clear removal changed the intended semantic value", check)
				}
			} else if !sameRetainedEntryValue(*entry, *before) || !bytes.Equal(entry.ValueBytes, before.ValueBytes) {
				t.Fatal("content-clear grant changed protected material")
			}
			if membership {
				access, ok := selected.materialAccess(contract.ValueMaterialKind, entry.ValueState)
				if !ok || len(access.Wraps) != len(source.Recipients)+1 || !exclusion && (access.PackageCheck != beforeAccess.PackageCheck || access.MaterialContextDigest != beforeAccess.MaterialContextDigest) {
					t.Fatal("sealed membership Final changed material or wrap count")
				}
				for _, wrap := range access.Wraps {
					if wrap.SubjectKind == contract.OrdinaryWrapSubject && !slices.Contains(source.Recipients, wrap.SubjectID) || wrap.SubjectKind == contract.RecoveryWrapSubject && wrap.SubjectID != currentControlOf(selected).Recovery.RoleID {
						t.Fatal("sealed membership Final has an unintended wrap")
					}
					old := slices.IndexFunc(beforeAccess.Wraps, func(row contract.WrapRow) bool {
						return row.SubjectKind == wrap.SubjectKind && row.SubjectID == wrap.SubjectID
					})
					if !exclusion && old >= 0 && !reflect.DeepEqual(wrap, beforeAccess.Wraps[old]) {
						t.Fatal("sealed membership Final replaced an existing required wrap")
					}
				}
			}
		})
	}
}

// This observer checks actual fresh preparation before Core accepts its key-use
// evidence. Checkpoint replay must not repeat the supplied batch.
type suppliedMeaningMembershipCrypto struct {
	inner    contract.Crypto
	keys     *custody.Fixture
	t        testing.TB
	addition bool
	content  bool
	batches  int
}

func (c *suppliedMeaningMembershipCrypto) InstanceID() contract.ID { return c.inner.InstanceID() }

func (c *suppliedMeaningMembershipCrypto) Exchange(ctx context.Context, request contract.CryptoRequest) contract.CryptoResponse {
	public, private := c.keys.Calls()
	reply := c.inner.Exchange(ctx, request)
	if request.Kind != contract.CryptoPrepare {
		return reply
	}
	if _, err := contract.InspectCryptoGeneratedSuppliedRequest(request.Body); err != nil {
		return reply
	}
	c.batches++
	afterPublic, afterPrivate := c.keys.Calls()
	wantOpens := uint32(1)
	if c.content {
		wantOpens = 0 // The source was already authenticated and transferred.
	}
	if reply.ResultCode != contract.CryptoSuccess || afterPublic != public || afterPrivate-private != int(wantOpens) {
		c.t.Fatal("sealed preparation private work differs", reply.ResultCode, afterPublic-public, afterPrivate-private, wantOpens)
	}
	opens, wraps := uint32(0), uint32(0)
	for _, row := range reply.KeyUseRows {
		if row.Outcome != contract.KeyUseCompleted {
			c.t.Fatal("sealed membership key use did not complete")
		}
		switch row.Purpose {
		case contract.KeyUseMaterialOpen:
			opens += row.Count
		case contract.KeyUseMaterialWrap:
			wraps += row.Count
		default:
			c.t.Fatal("sealed membership used an unexpected private purpose")
		}
	}
	wantWraps := uint32(2) // fresh Authority and Recovery protection
	if c.addition {
		wantWraps = 1
	}
	if opens != wantOpens || wraps != wantWraps {
		c.t.Fatal("sealed membership key-use counts differ", opens, wraps, wantWraps)
	}
	return reply
}

// full_only: false
func TestGeneratedSuppliedCurrentUsesTotalEntryBound(t *testing.T) {
	for _, count := range []int{128, 129} {
		t.Run(fmt.Sprintf("supplied%d-plus-one-generated", count), func(t *testing.T) {
			env, keys := genesisEnvironment(t, contract.GCP, false)
			run := newScenarioRun(t, t.Context(), env)
			fixture := newEnvironmentFixture(t, t.Context(), run.env, nil, false)
			var initial []ApplyEntryInput
			for i := range count {
				name := fmt.Sprintf("supplied-%03d", i)
				initial = append(initial, suppliedSecret(t, env, name, name+" selected source", custody.StandardValue))
			}
			run.suppliedSelection(fixture, initial)
			s := generatedLifecycleReopen(t, t.Context(), fixture.session, env.Store)
			var sources []contract.GeneratorDeclarationEntry
			var before []contract.ValueEntry
			var access []contract.AccessRecord
			for i := range count {
				name := fmt.Sprintf("supplied-%03d", i)
				_, entry := lifecycleEntry(t, s, name)
				before = append(before, ownScenarioValueEntry(*entry))
				row, ok := s.materialAccess(contract.ValueMaterialKind, entry.ValueState)
				if !ok {
					t.Fatal("current supplied access absent")
				}
				access = append(access, row)
				proposed := suppliedSecret(t, env, name, name+" proposed source", custody.StandardValue)
				sources = append(sources, contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationSealed, Name: name,
					Recipients: proposed.Recipients, Payload: proposed.InputBytes})
			}
			input := generatedPlanInputForGenerations(t, s, generatedVectorID(10), []string{"generated"}, defaultGeneratedFixtureProfile(), sources...)
			for i := range input.graph.ValueEntryPlans {
				if input.graph.ValueEntryPlans[i].ValueSource == contract.Supplied {
					input.graph.ValueEntryPlans[i].ChangeMask &^= contract.GeneratorValueChangeContent
				}
			}
			var err error
			input.graph.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(input.graph.Header, input.graph.ValueEntryPlans, input.graph.Lineages, input.graph.Edges)
			if err != nil || contract.ValidateGeneratorEffectGraph(input.graph) != nil {
				t.Fatal("mixed total-bound graph", err)
			}
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			creates, cas, signs := store.creates, store.cas, trust.signs
			permit, err := admitUnclaimedGeneratedReservation(t, env, s, input, nil)
			if err != nil {
				t.Fatal("valid mixed supplied current collection refused before effects", err)
			}
			prior, result := s.PrepareGeneratedPlan(t.Context(), permit)
			if prior == nil || result.Outcome != ObservedCurrent {
				t.Fatal("mixed total-bound reservation preparation", result)
			}
			if store.creates != creates || store.cas != cas || trust.signs != signs {
				t.Fatal("reservation preparation reached persistence or signing")
			}
			if code := keys.BindGeneratedCandidate(t.Context(), prior.operation.context.AdmissionID, generatedPrivateCandidate(t, prior)); code != contract.CryptoSuccess {
				t.Fatal("mixed total-bound reservation binding", code)
			}
			if candidate, result := s.ClaimGeneratedPreparation(t.Context(), prior.reservation.candidate, env.Trust); candidate == nil || result.Outcome != ObservedCurrent {
				t.Fatal("mixed total-bound reservation Claim", result)
			}
			// The existing helper enters the actual producer exactly once and
			// selects its original result before Final admission.
			recorded, _, _, _ := selectActualGeneratedPacketRecord(t, env, s, prior, custody.StandardValue, true, nil)
			admitted := generatedPlanInputFixture(t, recorded).context
			admitted.AdmissionID, admitted.SessionID = testID(t.Name()+" Final admission"), testID(t.Name()+" Final session")
			plan, err := recorded.generatedFinalRequest(t.Context(), admitted)
			if err != nil {
				t.Fatal("mixed total-bound Final request", err)
			}
			recorded, final := preparePrivateGeneratedFinal(t, env, recorded, plan)
			selected, result := recorded.selectCandidate(t.Context(), final.reservation.candidate)
			if selected == nil || result.Outcome != ObservedCurrent {
				t.Fatal("mixed total-bound Final selection", result)
			}
			selected = generatedLifecycleReopen(t, t.Context(), selected, env.Store)
			if len(selected.currentEntryInputs()) != count+1 {
				t.Fatal("mixed Final entry count differs", len(selected.currentEntryInputs()), count+1)
			}
			for i, want := range before {
				_, entry := lifecycleEntry(t, selected, want.Name)
				gotAccess, ok := selected.materialAccess(contract.ValueMaterialKind, want.ValueState)
				if !reflect.DeepEqual(*entry, want) || !ok || !reflect.DeepEqual(gotAccess, access[i]) {
					t.Fatal("mixed Final changed supplied bytes, membership or wraps", want.Name)
				}
			}
		})
	}
}

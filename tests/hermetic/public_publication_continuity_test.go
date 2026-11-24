package core

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"testing"
	"time"
	"unsafe"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

func publicPublicationApplyFixture(env fixtureEnvironment, f *fixture) installedApplyTestFixture {
	return installedApplyTestFixture{env: env, keys: env.Custody, basis: f.session.admission.publicBasis(), composition: f.session.admission.composition,
		admitted: OpenContext{admission: &f.session.admission}, selected: f.session}
}

type publicationBetweenActionsOwner struct {
	publicationPrivateOwner
	prepare     func(*contract.ConsumerSelection)
	afterRetire func()
}

func (o *publicationBetweenActionsOwner) Prepare(ctx context.Context, id contract.ID, selection *contract.ConsumerSelection) ([]contract.KeyUseRow, contract.CryptoResultCode) {
	if o.prepare != nil {
		o.prepare(selection)
	}
	return o.publicationPrivateOwner.Prepare(ctx, id, selection)
}

func (o *publicationBetweenActionsOwner) Retire(ctx context.Context) error {
	if err := o.publicationPrivateOwner.Retire(ctx); err != nil {
		return err
	}
	if o.afterRetire != nil {
		o.afterRetire()
	}
	return nil
}

// full_only: false
func TestInstalledPublicPublicationRefusesStaleBasisAfterAuthorityKEKReplacement(t *testing.T) {
	for _, combined := range []bool{false, true} {
		for _, loseOldRoute := range []bool{false, true} {
			name := "standalone"
			if combined {
				name = "combined"
			}
			if loseOldRoute {
				name += "/old-route-unavailable"
			} else {
				name += "/old-route-usable"
			}
			t.Run(name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
				defer cancel()
				f, env, _, private, _ := nativePublicationFixture(t, true)
				entries := []ApplyEntryInput{suppliedSecret(t, env, "alpha", "captured alpha", custody.StandardValue, f.session.admission.recipient), suppliedSecret(t, env, "beta", "captured beta", custody.StandardValue, f.session.admission.recipient)}
				output := nativePublicationOutput(entries, []uint64{1, 9})
				for i := range output.bindings[0].targets {
					hermeticRetargetOutput(&output.bindings[0].targets[i].target, "secret-target-"+entries[i].Name, "secret-target-"+entries[i].Name)
				}
				f.session = selectAdmittedOutputConfiguration(t, ctx, f.session, env, env.Custody, entries, output)
				f.admission = OpenContext{admission: &f.session.admission}
				old := *f.session.authority().CurrentBinding
				capturedAccess := make(map[string]contract.AccessRecord)
				for _, entry := range entries {
					capturedAccess[entry.Name] = sessionConsumerSelection(t, f.session, f.session.admission.recipient, entry.Name).Access
				}
				var successor contract.KMSBinding
				prepared, retired, replaced := 0, 0, false
				original := private.NewOwner
				private.NewOwner = func(ctx context.Context, input publicationOwnerInput) (publicationPrivateOwner, error) {
					owner, err := original(ctx, input)
					if err != nil {
						return nil, err
					}
					return &publicationBetweenActionsOwner{publicationPrivateOwner: owner, prepare: func(selection *contract.ConsumerSelection) {
						prepared++
						if selection == nil || selection.Binding.Binding.BindingID != old.BindingID || !bytes.Equal(selection.Binding.Binding.SPKI, old.SPKI) {
							t.Fatal("first preparation substituted the captured encryption binding")
						}
						if !reflect.DeepEqual(selection.Access, capturedAccess[selection.Entry.Name]) {
							t.Fatal("first preparation substituted a new captured wrap")
						}
					}, afterRetire: func() {
						retired++
						if retired != 1 {
							return
						}
						current, state := Open(ctx, f.admission, f.store)
						if current == nil {
							t.Fatal("current before key replacement", state)
						}
						after := currentControlOf(current)
						source := contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: after.AuthorityRecipientID, Binding: after.AuthorityKMSBinding}
						successor = env.Custody.KEKSuccessor(t, contract.SuccessorAuthorityKEK)
						after.AuthorityKMSBinding, after.AccessGeneration = successor, after.AccessGeneration+1
						permit := admitAuthorityReplacement(t, current, env.Custody, after, contract.SuccessionReplaceAuthority, contract.NormalSigningRole, contract.SuccessionChangeAuthorityKEK, source)
						candidate, state := current.PrepareSuccession(ctx, permit, SuccessionSigners{Authorizer: env.Trust})
						if candidate == nil {
							t.Fatal("key replacement preparation", state)
						}
						admission := deliverSuccessionBasis(t, candidate)
						selected, state := current.selectCandidate(ctx, candidate)
						if selected == nil {
							t.Fatal("key replacement selection", state)
						}
						if selected.authority().CurrentBinding == nil || !reflect.DeepEqual(*selected.authority().CurrentBinding, successor) {
							t.Fatal("key replacement did not select the successor binding")
						}
						env.Custody.RetireAccess()
						f.session, f.admission = selected, admission
						if loseOldRoute {
							if err := env.Custody.RetireCurrentPrivateRoute(source); err != nil {
								t.Fatal("old route retirement", err)
							}
						}
						replaced = true
					}}, nil
				}
				publication := installedPublicationEngine(t, f, private)
				var result PublicPublicationResult
				if combined {
					a := publicPublicationApplyFixture(env, f)
					input := installedApplyCurrentInput(f.session)
					apply := a.engineWithValidator(t, f.session, input, currentApplyRecipients(f.session.registry()), installedOutputValidator(t, f.session), nil)
					joined := apply.ApplyAndPublish(ctx, fixtureID(env.Domain, "captured apply"), fixtureID(env.Domain, "captured publication"), input, publication, nil)
					if !applyPublicationComplete(joined.Apply) || joined.Publication.Stage != "evaluated" || joined.Publication.Result == nil {
						t.Fatal("combined publication did not preserve completed apply", joined.Apply.Result, joined.Publication)
					}
					result = *joined.Publication.Result
				} else {
					result = publication.Publish(ctx, fixtureID(env.Domain, "captured standalone"), PublicationRequest{Names: []string{"alpha", "beta"}})
				}
				if !replaced || successor.BindingID == old.BindingID || prepared != 1 || retired != 1 {
					t.Fatal("stale installed basis admitted another private action", prepared, retired, result.Result)
				}
				// Installation owns its independent public basis; the fixture's new
				// admission does not qualify that installed basis after succession.
				if result.Result != (Result{Outcome: EvidenceUnavailable, Reason: SigningUnavailable}) {
					t.Fatal("stale installed basis did not preserve unavailable current authority", result.Result)
				}
				assertInstalledPublicationVector(t, result, contract.PublicationSummaryMixedTerminal, 2)
				for i, target := range result.Output.Entries {
					if len(target.Actions) != 1 {
						t.Fatal("key replacement lost the complete action vector", target)
					}
					action := target.Actions[0]
					if action.Action != contract.PublicationCreateWithValue || action.ProjectionCommitment.IsZero() || len(action.BlockerIDs) != 0 || action.LateWriteRisk != 0 {
						t.Fatal("key replacement changed the admitted creation action", action)
					}
					if i == 0 {
						if action.Disposition != contract.PublicationOutcomeAcknowledged || action.AttemptID.IsZero() || action.CoreReason != 0 || action.RemoteValueMayRemain != 1 || action.Evidence.Class != contract.PublicationRequestAcknowledged || action.Evidence.Entry != contract.PublicationMayHaveEnteredEntry {
							t.Fatal("key replacement erased the first acknowledgement", action)
						}
					} else if action.Disposition != contract.PublicationNotSent || !action.AttemptID.IsZero() || action.CoreReason != uint16(SigningUnavailable) || action.RemoteValueMayRemain != 0 || action.Evidence != (contract.PublicationEvidence{}) {
						t.Fatal("stale installed basis invented a later effect", action)
					}
				}
			})
		}
	}
}

// full_only: false
func TestInstalledPublicPublicationRechecksCurrentSigningAuthorityBetweenActions(t *testing.T) {
	for _, combined := range []bool{false, true} {
		name := "standalone"
		if combined {
			name = "combined"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			f, env, _, private, _ := nativePublicationFixture(t, true)
			entries := []ApplyEntryInput{suppliedSecret(t, env, "alpha", "fresh signing alpha", custody.StandardValue, f.session.admission.recipient), suppliedSecret(t, env, "beta", "fresh signing beta", custody.StandardValue, f.session.admission.recipient)}
			output := nativePublicationOutput(entries, []uint64{1, 9})
			for i := range output.bindings[0].targets {
				slot := "secret-target-" + entries[i].Name
				hermeticRetargetOutput(&output.bindings[0].targets[i].target, slot, slot)
			}
			f.session = selectAdmittedOutputConfiguration(t, ctx, f.session, env, env.Custody, entries, output)
			f.admission = OpenContext{admission: &f.session.admission}
			env = syntheticAuthorityScenarioEnvironment(t, env)
			prepared, retired, replaced := 0, 0, false
			original := private.NewOwner
			private.NewOwner = func(ctx context.Context, input publicationOwnerInput) (publicationPrivateOwner, error) {
				owner, err := original(ctx, input)
				if err != nil {
					return nil, err
				}
				return &publicationBetweenActionsOwner{publicationPrivateOwner: owner, prepare: func(*contract.ConsumerSelection) { prepared++ }, afterRetire: func() {
					retired++
					if retired != 1 {
						t.Fatal("stale signer admitted another private owner")
					}
					current, state := Open(ctx, f.admission, f.store)
					if current == nil {
						t.Fatal("current before signer replacement", state)
					}
					actors := env.ReplacementActors(t, ctx, current, contract.SuccessionReplaceAuthority, contract.SuccessionChangeNormalSigner, contract.NormalSigningRole)
					permit := admitAuthorityReplacement(t, current, actors.Keys, actors.After, contract.SuccessionReplaceAuthority, contract.NormalSigningRole, contract.SuccessionChangeNormalSigner, actors.Source)
					candidate, state := current.PrepareSuccession(ctx, permit, actors.Signers)
					if candidate == nil {
						t.Fatal("signer replacement preparation", state)
					}
					admission := deliverSuccessionBasis(t, candidate)
					selected, state := current.selectCandidate(ctx, candidate)
					if selected == nil {
						t.Fatal("signer replacement selection", state)
					}
					actors.Activate(t, selected)
					f.session, f.admission, replaced = selected, admission, true
				}}, nil
			}
			publication := installedPublicationEngine(t, f, private)
			var result PublicPublicationResult
			if combined {
				a := publicPublicationApplyFixture(env, f)
				input := installedApplyCurrentInput(f.session)
				apply := a.engineWithValidator(t, f.session, input, currentApplyRecipients(f.session.registry()), installedOutputValidator(t, f.session), nil)
				joined := apply.ApplyAndPublish(ctx, fixtureID(env.Domain, "fresh signing apply"), fixtureID(env.Domain, "fresh signing publication"), input, publication, nil)
				if !applyPublicationComplete(joined.Apply) || joined.Publication.Stage != "evaluated" || joined.Publication.Result == nil {
					t.Fatal("combined current-authority result lost its completed apply", joined.Apply.Result, joined.Publication)
				}
				result = *joined.Publication.Result
			} else {
				result = publication.Publish(ctx, fixtureID(env.Domain, "fresh signing standalone"), PublicationRequest{Names: []string{"alpha", "beta"}})
			}
			if !replaced || prepared != 1 || retired != 1 || result.Output == nil || len(result.Output.Entries) != 2 {
				t.Fatal("fresh current authority did not stop the later private action", prepared, retired, result.Result)
			}
			ack, unsent := 0, 0
			for _, target := range result.Output.Entries {
				for _, action := range target.Actions {
					if action.Disposition == contract.PublicationOutcomeAcknowledged {
						ack++
					} else if action.Disposition == contract.PublicationNotSent && action.AttemptID.IsZero() {
						unsent++
					} else {
						t.Fatal("stale-authority result invented a later effect", action)
					}
				}
			}
			if ack != 1 || unsent != 1 {
				t.Fatal("signer replacement erased an earlier result or granted a later right", ack, unsent)
			}
		})
	}
}

// full_only: false
func TestInstalledPublicPublicationEndingKeepsPermanentWarning(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f, env, input, _, _ := nativePublicationFixture(t, false)
	controlled := newPublicationControlledPrivate()
	controlled.evidence = contract.PublicationUnproved
	first := installedPublicationEngine(t, f, controlled.callbacks()).Publish(ctx, fixtureID(env.Domain, "public ending unknown"), PublicationRequest{Names: input.names})
	assertInstalledPublicationVector(t, first, contract.PublicationSummaryUnknown, 1)
	marker := first.Output.Entries[0].Actions[0].AttemptID
	publicationEngineReopen(t, f)
	admin, state := openAdministrative(ctx, f.admission, f.store)
	if admin == nil {
		t.Fatal("exact marker administrative open", state)
	}
	candidate, state := prepareTestEndSelectedWork(t, admin, ctx, marker, f.trust)
	if candidate == nil {
		t.Fatal("exact marker ending preparation", state)
	}
	if selected, state := admin.selectCandidate(ctx, candidate); selected == nil {
		t.Fatal("exact marker ending selection", state)
	}
	relation := publicationEngineReopen(t, f)
	if _, exists := relation.markers[marker]; exists || f.session.root.WarningBits&(WarningPublicationOrderValue|WarningDiscardedExactEvidence) != WarningPublicationOrderValue|WarningDiscardedExactEvidence {
		t.Fatal("ending restored exact detail or lost its permanent warning")
	}
	controlled.evidence = contract.PublicationRequestAcknowledged
	for _, slot := range []string{"plain-target", "new-warning-target"} {
		if slot == "new-warning-target" {
			configuration := installedOutputConfiguration(t, ctx, f.session)
			target := configuration.Bindings[0].Targets[0]
			target.EntryIncarnationID = contract.ID{}
			hermeticRetargetOutput(&target, slot, slot)
			output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "native", destination: configuration.Bindings[0].Destination, targets: []outputApplyTarget{{entryName: input.names[0], target: target}}}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"native"}}}}
			f.session = selectAdmittedOutputConfiguration(t, ctx, f.session, env, env.Custody, f.session.currentEntryInputs(), output)
			f.admission = OpenContext{admission: &f.session.admission}
		}
		before := len(controlled.owners)
		result := installedPublicationEngine(t, f, controlled.callbacks()).Publish(ctx, fixtureID(env.Domain, "permanent warning "+slot), PublicationRequest{Names: input.names})
		assertInstalledPublicationVector(t, result, contract.PublicationSummaryComplete, 1)
		if result.Output.DomainWideWarning != 1 || result.Output.Entries[0].Actions[0].Disposition == contract.PublicationNoOp || len(controlled.owners) <= before {
			t.Fatal("discarded history supported no-op or cleared a warning")
		}
		publicationEngineReopen(t, f)
	}
}

// full_only: false
func TestApplyPublicationCaptureOwnsAndChargesDistinctBacking(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f, _, _, _, _ := nativePublicationFixture(t, true)
	h, err := captureApplyPublicationSelection(ctx, f.session)
	if err != nil {
		t.Fatal("capture actual selected publication", err)
	}
	defer h.close()
	if len(h.entries) != 2 || len(h.targets) != 2 || h.backingBytes == 0 {
		t.Fatal("capture omitted selected entries or targets")
	}
	// Count distinct backing from the owned representation. Shared binding,
	// token, name and ciphertext storage is counted once.
	want := uint64(unsafe.Sizeof(*h)) + uint64(len(h.entries))*uint64(unsafe.Sizeof(applyPublicationEntry{})) + uint64(len(h.targets))*uint64(unsafe.Sizeof(applyPublicationTarget{})) + uint64(len(h.policies))*uint64(unsafe.Sizeof(applyPublicationPolicy{})) + uint64(len(h.groups))*uint64(unsafe.Sizeof([]contract.ID{}))
	shared := h.entries[0].selection
	want += uint64(len(shared.Binding.Binding.KeySelector) + len(shared.Binding.Binding.SPKI) + len(shared.HEADToken.Value))
	for _, entry := range h.entries {
		selection := entry.selection
		want += uint64(len(selection.Entry.Name)+len(selection.Entry.ValueBytes)) + 32*uint64(len(selection.Entry.Recipients)) + uint64(len(selection.Access.Wraps))*(uint64(unsafe.Sizeof(contract.WrapRow{}))+384)
		original := f.session.valueEntry(selection.Slot)
		if original == nil || !reflect.DeepEqual(selection.Entry, *original) || len(selection.Entry.ValueBytes) > 0 && &selection.Entry.ValueBytes[0] == &original.ValueBytes[0] || cap(selection.Entry.ValueBytes) != len(selection.Entry.ValueBytes) {
			t.Fatal("capture borrowed or overallocated selected value backing")
		}
		if selection.Entry.ConfidentialityClass != contract.Secret {
			continue
		}
		view, err := contract.InspectCanonicalPayload(selection.Entry.ValueBytes)
		if err != nil || len(view.Ciphertext) == 0 || &view.Ciphertext[0] != &selection.Payload.Ciphertext[0] {
			t.Fatal("capture duplicated ciphertext backing", err)
		}
		if cap(selection.Access.Wraps) != len(selection.Access.Wraps) {
			t.Fatal("capture retained wrap growth capacity")
		}
		for _, wrap := range selection.Access.Wraps {
			if len(wrap.RSACiphertext) != 384 || cap(wrap.RSACiphertext) != 384 {
				t.Fatal("capture wrap arena has wrong exact span")
			}
		}
		if !slices.Equal(selection.Entry.Recipients, original.Recipients) {
			t.Fatal("capture changed exact membership")
		}
	}
	for _, policy := range h.policies {
		want += uint64(len(policy.destination) + len(policy.policy.ContractID) + len(policy.policy.Data))
	}
	for _, target := range h.targets {
		p := target.target
		want += uint64(len(p.ServiceContractID) + len(p.CanonicalTarget) + len(p.ConsumerLocator) + len(p.TargetContractID) + len(p.TargetData))
	}

	for _, group := range h.groups {
		want += 32 * uint64(len(group))
	}
	if len(h.deletions) != 0 || h.backingBytes != want {
		t.Fatal("capture did not charge distinct owned backing exactly", h.backingBytes, want)
	}
	// Independent specified widths: 512 entries, 11,186,176 retained bytes, 4,096 current
	// memberships, and 131,584 retained/Recovery wraps, not 4,096 wraps.
	maximum := uint64(11186176 + 215*512 + 256*512 + 32*4096 + 1024 + 422 + 256 + 4*32<<20)
	maximum += 131584*(uint64(unsafe.Sizeof(contract.WrapRow{}))+384) + 1024*(8192+8192) + 2048*32
	if applyPublicationDynamicLimit() != maximum {
		t.Fatal("capture maximum omitted retained wraps or an output account", applyPublicationDynamicLimit(), maximum)
	}
	var n = ^uint64(0) - 7
	if !addApplyPublicationBytes(&n, 1, 7) || n != ^uint64(0) || addApplyPublicationBytes(&n, 1, 1) || n != ^uint64(0) {
		t.Fatal("capture unsigned charge did not reject exactly one over")
	}
	h.close()
	if selection, _, ok := h.consumer(0); ok || selection != nil || h.entries != nil || h.targets != nil {
		t.Fatal("closed capture retained borrowing rights")
	}
}

// full_only: true
func TestInstalledPublicPublicationPreservesGeneratedWorkAndFullReceiptWindows(t *testing.T) {
	for _, combined := range []bool{false, true} {
		name := "standalone"
		if combined {
			name = "combined"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			env, seed, _ := configuredSuccessionMemoryFixture(t, false)
			historyNames := []string{"publication-history-alpha", "publication-history-omega"}
			sources, canonical := generatedCurrentDeclaration(t, seed.session)
			history := generatedPlanInputForGenerations(t, seed.session, fixtureID(env.Domain, "public publication retained cleanup"), historyNames, defaultGeneratedFixtureProfile(), sources...)
			selected, failed := selectPrivateOwnedUnusableAggregateFromInput(t, env, seed.session, historyNames, history, canonical)
			selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
			work := mustSelectedGeneratedWork(t, selected)
			if work.parent != nil || !selected.root.Generated.ActiveOwner.IsZero() || selected.root.Generated.Duties == 0 || selected.root.Generated.Hazards == 0 || !work.hasRecord(generatedRecordKey{kind: contract.GeneratedHazardSupportKind, id: failed.expected.Template.HazardID}) {
				t.Fatal("retained-work fixture did not leave exact independent cleanup")
			}
			input := installedApplyCurrentInput(selected)
			for i := range input {
				if input[i].ValueSource == contract.Generated {
					input[i].InputBytes = selected.valueEntry(entrySlot(t, selected, input[i].Name)).ValueBytes
				}
			}
			selected = selectAdmittedOutputConfiguration(t, ctx, selected, env, env.Custody, input, nativePublicationOutput(input, []uint64{1, 9}))
			f := &fixture{store: env.Store.(*memoryStore), trust: env.Trust.(*fixtureTrust), admission: OpenContext{admission: &selected.admission}, session: selected}
			retainedWork := func(session *StateSession) []contract.SupportRecordDigest {
				return slices.DeleteFunc(installedApplyStableWork(t, ctx, session), func(fact contract.SupportRecordDigest) bool {
					return fact.Kind() == contract.PublicationCoordinateSupportKind || fact.Kind() == contract.PublicationMarkerSupportKind
				})
			}
			beforeWork := retainedWork(selected)
			beforeWindows, err := selected.receiptWindows(ctx)
			if err != nil || len(beforeWindows.Successes) != 256 || len(beforeWindows.Failures) != 256 {
				t.Fatal("retained work lacks both complete encoded receipt windows", err)
			}
			beforeWindows.Successes, beforeWindows.Failures = slices.Clone(beforeWindows.Successes), slices.Clone(beforeWindows.Failures)
			currentRecords := func(session *StateSession) (map[uint16][]byte, [][]byte) {
				entries := make(map[uint16][]byte, len(session.root.Names))
				for _, named := range session.root.Names {
					body, err := contract.EncodeValueEntry(*session.valueEntry(named.Slot))
					if err != nil {
						t.Fatal("current value entry encoding", err)
					}
					entries[named.Slot] = body
				}
				var access [][]byte
				for _, record := range session.accessRecords() {
					body, err := contract.EncodeAccessRecord(record)
					if err != nil {
						t.Fatal("current access record encoding", err)
					}
					access = append(access, body)
				}
				return entries, access
			}
			beforeEntries, beforeAccess := currentRecords(selected)
			beforeAccessRoot, beforeGenerated := selected.root.CurrentAccess.AccessRoot, selected.root.Generated
			beforeGenerated.Fragments = slices.Clone(beforeGenerated.Fragments)
			controlled := newPublicationControlledPrivate()
			publication := installedPublicationEngine(t, f, controlled.callbacks())
			var result PublicPublicationResult
			if combined {
				a := publicPublicationApplyFixture(env, f)
				input = installedApplyCurrentInput(selected)
				apply := a.engineWithValidator(t, selected, input, currentApplyRecipients(selected.registry()), installedOutputValidator(t, selected), nil)
				joined := apply.ApplyAndPublish(ctx, fixtureID(env.Domain, "full windows completed apply"), fixtureID(env.Domain, "full windows publication"), input, publication, nil)
				if !applyPublicationComplete(joined.Apply) || joined.Publication.Stage != "evaluated" || joined.Publication.Result == nil {
					t.Fatal("independent old cleanup blocked completed combined publication", joined.Apply.Result, joined.Publication)
				}
				result = *joined.Publication.Result
			} else {
				result = publication.Publish(ctx, fixtureID(env.Domain, "full windows standalone"), PublicationRequest{Names: publicPublicationNames(input)})
			}
			assertInstalledPublicationVector(t, result, contract.PublicationSummaryComplete, len(input))
			publicationEngineReopen(t, f)
			afterWindows, err := f.session.receiptWindows(ctx)
			afterEntries, afterAccess := currentRecords(f.session)
			if err != nil || !reflect.DeepEqual(beforeWindows, afterWindows) || !reflect.DeepEqual(beforeWork, retainedWork(f.session)) || !reflect.DeepEqual(beforeEntries, afterEntries) || !reflect.DeepEqual(beforeAccess, afterAccess) || beforeAccessRoot != f.session.root.CurrentAccess.AccessRoot || !reflect.DeepEqual(beforeGenerated, f.session.root.Generated) {
				t.Fatal("public publication changed retained generated work, receipts, canonical values or access", err)
			}
		})
	}
}

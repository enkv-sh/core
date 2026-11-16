package core

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGeneratedSignedColdCleanupRequiresCompleteOwnedSets(t *testing.T) {
	for _, ownerKind := range []uint8{contract.GeneratedDutySupportKind, contract.GeneratedHazardSupportKind} {
		t.Run(fmt.Sprintf("owner-kind=%d", ownerKind), func(t *testing.T) {
			ctx := t.Context()
			env, _ := genesisEnvironment(t, contract.GCP, false)
			before := newEnvironmentFixture(t, ctx, env, nil, false).session
			names := []string{"alpha", "omega"}
			input := generatedPlanInputForGenerations(t, before, testID(t.Name()+" create operation"), names, defaultGeneratedFixtureProfile())
			selected, failed := selectPrivateOwnedUnusableAggregateFromInput(t, env, before, names, input, nil)
			selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
			work := mustSelectedGeneratedWork(t, selected)
			selection, present, err := work.selectGeneratedCleanup(ctx, nil)
			if err != nil || !present || selection.kind != generatedCleanupDuty {
				t.Fatal("actual cleanup owner baseline", err)
			}
			ownerID := selection.duty.DutyID
			if ownerKind == contract.GeneratedHazardSupportKind {
				// Core selects ordinary cleanup Duties before Hazards. Complete
				// that real predecessor obligation before reserving the Hazard.
				deleteStore := &generatedCleanupDeleteStore{memoryStore: env.Store.(*memoryStore)}
				selected = closeAndReleaseActualCleanup(t, env, selected, deleteStore, selection.attempt, contract.GeneratedDutySupportKind, ownerID, 40)
				selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
				ownerID = failed.expected.Template.HazardID
			}
			work = mustSelectedGeneratedWork(t, selected)
			initial, err := contract.InspectGeneratedDeleteSource(work.records[generatedRecordKey{ownerKind, ownerID}])
			if err != nil {
				t.Fatal("initial actual cleanup source", err)
			}
			prefix, err := work.vectors.resolve(ownerKind, ownerID, contract.GeneratorVectorHistory, initial.History)
			if err != nil {
				t.Fatal("initial actual cleanup history prefix", err)
			}
			var enteredResults []contract.ID
			var enteredAttempts []contract.ID
			effects := 0
			for invocation := range 2 {
				work = mustSelectedGeneratedWork(t, selected)
				source, err := contract.InspectGeneratedDeleteSource(work.records[generatedRecordKey{ownerKind, ownerID}])
				target, targetErr := work.generatedCleanupTarget(ownerKind, ownerID, source.Target)
				if err != nil || targetErr != nil {
					t.Fatal("actual parked cleanup source", err, targetErr)
				}
				label := fmt.Sprintf("%s delete %d", t.Name(), invocation)
				deleteInput, canonical := generatedDeletePlanInputForSource(t, selected, testID(label+" operation"), source.Record, target)
				prior, _ := preparePrivateGeneratedReservation(t, env, selected, deleteInput, canonical)
				producer, expected := preparePrivateGeneratedProducer(t, env, selected, prior, nil)
				var packet []byte
				if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
					effects++
					var code contract.CryptoResultCode
					packet, _, code = env.Custody.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
					return code
				}) {
					t.Fatal("actual parked Delete handoff")
				}
				entered, result := selected.selectCandidate(ctx, producer.reservation.candidate)
				if entered == nil || result.Outcome != ObservedCurrent || effects != invocation+1 || len(packet) == 0 {
					t.Fatal("actual parked Delete entry", result)
				}
				env.Custody.RetireGenerated()
				facts, err := contract.EncodeGeneratorSafeFacts(generatedUnknownFixtureFacts(expected, generatedTargetEvidence(t, entered, target)))
				if err != nil {
					t.Fatal("lost Delete observation framing", err)
				}
				admitted := generatedPlanInputFixture(t, entered).context
				admitted.AdmissionID, admitted.SessionID = testID(label+" parking admission"), testID(label+" parking session")
				permit, err := entered.admitGeneratedOrdinaryCleanupUnknown(ctx, expected.Template.AttemptID, facts, admitted)
				if err != nil {
					t.Fatal("actual Delete parking admission", err)
				}
				candidate, result := entered.PrepareGeneratedLifecycle(ctx, permit, env.Trust)
				if candidate == nil || result.Outcome != ObservedCurrent {
					t.Fatal("actual Delete parking preparation", result)
				}
				selected, result = entered.selectCandidate(ctx, candidate)
				if selected == nil || result.Outcome != ObservedCurrent {
					t.Fatal("actual Delete parking selection", result)
				}
				selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
				enteredResults = append(enteredResults, expected.Template.ResultID)
				enteredAttempts = append(enteredAttempts, expected.Template.AttemptID)
			}
			work = mustSelectedGeneratedWork(t, selected)
			source, err := contract.InspectGeneratedDeleteSource(work.records[generatedRecordKey{ownerKind, ownerID}])
			if err != nil || source.History.Count != initial.History.Count+2 || source.Consumers.Count != initial.Consumers.Count+2 ||
				len(enteredResults) != 2 || len(enteredAttempts) != 2 || enteredAttempts[0] == enteredAttempts[1] || effects != 2 {
				t.Fatal("fixture did not establish two independent parked Deletes", err)
			}
			history, err := work.vectors.resolve(ownerKind, ownerID, contract.GeneratorVectorHistory, source.History)
			if err != nil || len(history) != len(prefix)+2 {
				t.Fatal("actual parked Delete history count", err)
			}
			for i, body := range history {
				row, err := contract.InspectGeneratorHistory(body)
				if err != nil {
					t.Fatal("actual parked Delete history framing", err)
				}
				if i < len(prefix) {
					original, err := contract.InspectGeneratorHistory(prefix[i])
					if err != nil || row.PredecessorAttemptID != original.PredecessorAttemptID {
						t.Fatal("actual parked Delete changed its original history prefix", err)
					}
				} else if row.PredecessorAttemptID != enteredAttempts[i-len(prefix)] || row.Outcome != contract.GeneratedEffectUnknown {
					t.Fatal("actual parked Delete history omitted a transmitted invocation")
				}
			}
			// Preserve the valid receipt exclusion set before changing the selected
			// root. Re-reading receipt windows against a half-rebuilt HEAD would
			// test stale framing instead of complete owned invocation semantics.
			validWork, err := selected.workSupportRecords(ctx)
			if err != nil {
				t.Fatal("valid selected work before signed omission", err)
			}
			workKeys := make(map[generatedRecordKey]bool, len(validWork))
			for _, row := range validWork {
				workKeys[generatedRecordKey{row.Kind, row.RecordID}] = true
			}
			excluded := make(map[generatedRecordKey]bool)
			for _, row := range selected.supportRecords() {
				key := generatedRecordKey{row.Kind, row.RecordID}
				if !workKeys[key] {
					excluded[key] = true
				}
			}
			for _, damage := range []string{"complete", "missing consumer", "missing history"} {
				t.Run(damage, func(t *testing.T) {
					bad := *selected
					ownSelectedSupportForMutationFixture(t, ctx, &bad)
					var replacements []contract.SupportRecord
					var vectorKind contract.GeneratorVectorKind
					if damage != "complete" {
						vectorKind = contract.GeneratorVectorConsumers
						descriptor := source.Consumers
						if damage == "missing history" {
							vectorKind, descriptor = contract.GeneratorVectorHistory, source.History
						}
						bodies, err := work.vectors.resolve(ownerKind, ownerID, vectorKind, descriptor)
						minimum := 3
						if vectorKind == contract.GeneratorVectorHistory {
							minimum = 2
						}
						if err != nil || len(bodies) < minimum {
							t.Fatal("complete actual owner vector", err)
						}
						bodies = slices.Clone(bodies)
						if damage == "missing consumer" {
							index := -1
							for i, body := range bodies {
								consumer, err := contract.InspectGeneratorConsumer(body)
								if err != nil {
									t.Fatal("actual Delete consumer", err)
								}
								if consumer.SubjectID == enteredResults[0] {
									index = i
								}
							}
							if index < 0 {
								t.Fatal("missing actual parked Delete adoption consumer in positive fixture")
							}
							bodies = slices.Delete(bodies, index, index+1)
						} else {
							bodies = bodies[:len(bodies)-1]
							last, err := contract.InspectGeneratorHistory(bodies[len(bodies)-1])
							if err != nil {
								t.Fatal("actual Delete history predecessor", err)
							}
							last.Edge, last.NextAttemptID = 0, contract.ID{}
							bodies[len(bodies)-1], err = contract.EncodeGeneratorHistory(last)
							if err != nil {
								t.Fatal("coherent shortened history", err)
							}
						}
						replacement, carriers, err := generatedCarrierRows(bad.root.Domain, ownerKind, ownerID, vectorKind, bodies)
						if err != nil {
							t.Fatal("coherent omitted vector framing", err)
						}
						replacements = carriers
						if ownerKind == contract.GeneratedDutySupportKind {
							owner := source.Duty
							if vectorKind == contract.GeneratorVectorConsumers {
								owner.Consumers = replacement
							} else {
								owner.History = replacement
							}
							body, err := contract.EncodeGeneratedDutyRecord(owner)
							if err != nil {
								t.Fatal("shortened Duty framing", err)
							}
							replacements = append(replacements, contract.SupportRecord{Kind: ownerKind, RecordID: ownerID, Body: body})
						} else {
							owner := source.Hazard
							if vectorKind == contract.GeneratorVectorConsumers {
								owner.Consumers = replacement
							} else {
								owner.History = replacement
							}
							body, err := contract.EncodeGeneratedHazardRecord(owner)
							if err != nil {
								t.Fatal("shortened Hazard framing", err)
							}
							replacements = append(replacements, contract.SupportRecord{Kind: ownerKind, RecordID: ownerID, Body: body})
						}
					}
					store := signCleanupQualificationImage(t, env, &bad, ownerKind, ownerID, vectorKind, replacements, excluded)
					public, private := env.Custody.Calls()
					creates, cas := store.creates, store.cas
					opened, result := Open(ctx, OpenContext{admission: &selected.admission}, store)
					if damage == "complete" {
						if opened == nil || result.Outcome != ObservedCurrent {
							t.Fatal("complete re-signed actual parked closure did not cold-open", result)
						}
						if _, err := opened.validateRelationsMode(ctx, false); err != nil {
							t.Fatal("complete re-signed actual closure relations", err)
						}
					} else if opened != nil || result.Outcome != IntegrityFailure || result.Reason != InvalidRelation {
						t.Fatal("signed cold cleanup admitted an omitted actual owned invocation", result.Outcome, result.Reason)
					}
					if p, k := env.Custody.Calls(); p != public || k != private || effects != 2 ||
						store.creates != creates || store.cas != cas || store.deletes != 0 {
						t.Fatal("cold cleanup qualification reached private/provider effects or persistence")
					}
				})
			}
		})
	}
}

// This fixture writer preserves actual selected ownership spans while changing
// only the named vector. It deliberately uses raw codecs because the production
// ownership writer must refuse the semantic omission before it can be signed.
func signCleanupQualificationImage(t *testing.T, env fixtureEnvironment, bad *StateSession, ownerKind uint8, ownerID contract.ID,
	vectorKind contract.GeneratorVectorKind, replacements []contract.SupportRecord, excluded map[generatedRecordKey]bool) *generatedCleanupDeleteStore {
	t.Helper()
	bad.root.RequiredSupport = slices.Clone(bad.root.RequiredSupport)
	bad.adminIndex.Pages = slices.Clone(bad.adminIndex.Pages)
	bad.adminIndex.Groups = slices.Clone(bad.adminIndex.Groups)
	bad.root.RequiredSupportRecordCount = 0
	changedOwner, oldCarriers := 0, 0
	for i, page := range bad.support {
		rows := make([]contract.SupportRecordView, 0, len(page.Records))
		var spans []format.AdministrativeSpan
		position := 0
		for _, span := range bad.adminIndex.Pages[i].Spans {
			updated := span
			updated.First, updated.Count = uint16(len(rows)), 0
			for _, row := range page.Records[position : position+int(span.Count)] {
				keep := true
				if vectorKind != 0 && row.Kind == ownerKind && row.RecordID == ownerID {
					row = contract.SupportRecordView(replacements[len(replacements)-1])
					changedOwner++
				} else if vectorKind != 0 && row.Kind == contract.GeneratorVectorSupportKind {
					carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
					if err != nil {
						t.Fatal("physical owner-vector inspection", err)
					}
					if carrier.OwnerKind == ownerKind && carrier.OwnerID == ownerID && carrier.VectorKind == vectorKind {
						oldCarriers++
						if int(carrier.Ordinal) < len(replacements)-1 {
							row = contract.SupportRecordView(replacements[carrier.Ordinal])
						} else {
							keep = false
						}
					}
				}
				if keep {
					rows = append(rows, row)
					updated.Count++
				}
			}
			position += int(span.Count)
			if updated.Count != 0 {
				spans = append(spans, updated)
			}
		}
		if position != len(page.Records) || len(rows) == 0 {
			t.Fatal("raw omitted-vector fixture lost selected page ownership")
		}
		bad.support[i].Records = rows
		bad.adminIndex.Pages[i].Spans = spans
		physical := make([]contract.SupportRecord, len(rows))
		for j, row := range rows {
			physical[j] = contract.SupportRecord(row)
		}
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: physical})
		if err != nil {
			t.Fatal("raw omitted-vector physical framing", err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal("raw omitted-vector reference", err)
		}
		bad.root.RequiredSupport[i], bad.adminIndex.Pages[i].Ref = ref, ref
		bad.root.RequiredSupportRecordCount += uint32(len(rows))
		if !bad.adminIndex.Pages[i].ReadRequired {
			bad.adminIndex.Pages[i].Rows = make([]format.AdministrativeRowSummary, len(rows))
			for j, row := range rows {
				bad.adminIndex.Pages[i].Rows[j] = format.AdministrativeRowSummary{Kind: row.Kind, RecordID: row.RecordID, BodyLength: uint32(len(row.Body))}
			}
		}
	}
	if vectorKind != 0 && (changedOwner != 1 || oldCarriers != len(replacements)) {
		t.Fatal("raw omission did not replace one exact owner and omit one vector row", changedOwner, oldCarriers)
	}
	for group := range bad.adminIndex.Groups {
		var count uint32
		var chargedPages uint16
		var chargedBytes uint64
		for i, page := range bad.adminIndex.Pages {
			position, ownsPage := 0, false
			for _, span := range page.Spans {
				if slices.Contains(span.GroupIndexes, uint16(group)) {
					ownsPage = true
					count += uint32(span.Count)
					for _, row := range bad.support[i].Records[position : position+int(span.Count)] {
						chargedBytes += uint64(contract.SupportRecordOverhead + len(row.Body))
					}
				}
				position += int(span.Count)
			}
			if ownsPage {
				chargedPages++
			}
		}
		digest := selectedDisposableDigest(count)
		for i, page := range bad.adminIndex.Pages {
			position := 0
			for _, span := range page.Spans {
				if slices.Contains(span.GroupIndexes, uint16(group)) {
					for _, row := range bad.support[i].Records[position : position+int(span.Count)] {
						writeSelectedDisposableRow(digest, row.Kind, row.RecordID, uint32(len(row.Body)))
					}
				}
				position += int(span.Count)
			}
		}
		bad.adminIndex.Groups[group].Disposable = selectedDisposableDescriptor(digest, count)
		bad.adminIndex.Groups[group].ChargedPages, bad.adminIndex.Groups[group].ChargedBytes = chargedPages, chargedBytes
	}
	original := env.Store.(*memoryStore)
	memory := &memoryStore{desc: original.desc, configuration: original.configuration, objects: make(map[string]stored)}
	for key, value := range original.objects {
		memory.objects[key] = value
	}
	for i, page := range bad.support {
		rows := make([]contract.SupportRecord, len(page.Records))
		for j, row := range page.Records {
			rows[j] = contract.SupportRecord(row)
		}
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: rows})
		if err != nil {
			t.Fatal("signed omission support encoding", err)
		}
		memory.put(mustKey(t, memory.desc.Prefix, bad.root.RequiredSupport[i]), body)
	}
	shards, err := format.EncodeAdministrativeIndexPages(bad.adminIndex)
	if err != nil || len(shards) == 0 {
		t.Fatal("signed omission mandatory index framing", err)
	}
	bad.root.AdministrativeIndex, bad.root.AdministrativeIndexShards = shards[0].Ref, nil
	for i, shard := range shards {
		memory.put(mustKey(t, memory.desc.Prefix, shard.Ref), shard.Body)
		if i != 0 {
			bad.root.AdministrativeIndexShards = append(bad.root.AdministrativeIndexShards, shard.Ref)
		}
	}
	bad.recountChildren()
	rootBody, err := format.EncodeRoot(bad.root)
	if err != nil {
		t.Fatal("signed omission root framing", err)
	}
	rootRef, err := format.Reference(format.RootKind, bad.root.Domain, bad.root.Snapshot, 0, rootBody)
	if err != nil || bad.head.Generator == nil {
		t.Fatal("signed omission generated HEAD basis", err)
	}
	memory.put(mustKey(t, memory.desc.Prefix, rootRef), rootBody)
	head := bad.head
	subject := *head.Generator
	head.Generator, head.Core.Root = &subject, rootRef
	subject.AfterRootDigest, subject.AfterAccessDigest = rootRef.Digest, bad.root.CurrentAccess.AccessRoot
	identity := contract.IdentityPlan{Operation: subject.OperationID, Snapshot: bad.root.Snapshot, Transition: bad.root.Transition, Revision: head.Core.Revision}
	for _, ref := range bad.root.RequiredSupport {
		identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: ref.Kind, Index: ref.Index, Object: ref.Object})
	}
	subject.IdentityPlan, err = contract.GeneratorAuthorityIdentityDescriptor(identity)
	if err != nil {
		t.Fatal("signed omission identity commitment", err)
	}
	rows := slices.DeleteFunc(bad.supportRecords(), func(row contract.SupportRecord) bool {
		return excluded[generatedRecordKey{row.Kind, row.RecordID}]
	})
	subject.AfterWork, err = contract.GeneratorAuthorityWorkDescriptor(bad.root.Domain, rows)
	if err != nil {
		t.Fatal("signed omission exact live-work commitment", err)
	}
	coreBody, err := format.EncodeHeadCore(head.Core)
	if err != nil {
		t.Fatal("signed omission HEAD core", err)
	}
	condition, err := format.EncodeConditionalPlan(conditional(head.Core, coreBody))
	if err != nil {
		t.Fatal("signed omission conditional plan", err)
	}
	subject.HeadCoreDigest, subject.HeadCoreLength = contract.Hash(coreBody), uint32(len(coreBody))
	subject.ConditionalPlanDigest, subject.ConditionalLength = contract.Hash(condition), uint32(len(condition))
	request, err := contract.NewGeneratorRequest(subject)
	if err != nil {
		t.Fatal("signed omission authority request", err)
	}
	proof := env.Trust.Sign(t.Context(), request)
	if proof.Reason != contract.ReasonNone || len(proof.Signature) == 0 {
		t.Fatal("signed omission authority signature", proof.Reason)
	}
	head.AuthorizationSignature = proof.Signature
	if !bad.verifyHeadProofs(head, currentControlOf(bad)) {
		t.Fatal("signed omission failed independent authority verification")
	}
	headBody, err := format.EncodeHead(head)
	if err != nil {
		t.Fatal("signed omission HEAD framing", err)
	}
	memory.put(memory.desc.HeadKey, headBody)
	return &generatedCleanupDeleteStore{memoryStore: memory}
}

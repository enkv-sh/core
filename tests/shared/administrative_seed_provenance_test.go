package core

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestAdministrativeEndWorkDropsSeedKeptOnlyForInboxProvenance(t *testing.T) {
	checkAdministrativeSeedProvenance(t, false)
}

// full_only: false
func TestAdministrativeEndWorkRepairsHistoricalInboxProvenance(t *testing.T) {
	checkAdministrativeSeedProvenance(t, true)
}

func pendingInboxProvenanceFixture(t *testing.T, recovery bool) (fixtureEnvironment, *StateSession, generatedAttempt, generatedAttempt) {
	t.Helper()
	env, _ := genesisEnvironment(t, contract.GCP, recovery)
	f := newEnvironmentFixture(t, t.Context(), env, nil, false)
	sources, canonical := generatedCurrentDeclaration(t, f.session)
	input := generatedPlanInputForGenerations(t, f.session, testID(t.Name()+" original"), []string{"alpha", "omega"}, defaultGeneratedFixtureProfile(), sources...)
	closed, failed := selectPrivateOwnedUnusableAggregateFromInput(t, env, f.session, []string{"alpha", "omega"}, input, canonical)
	closed = retainedReaderColdOpen(t, closed, env.Store)
	work := mustSelectedGeneratedWork(t, closed)
	cleanup, ok, err := work.selectGeneratedCleanup(t.Context(), nil)
	if err != nil || !ok || cleanup.kind != generatedCleanupDuty {
		t.Fatal("actual succeeded sibling has no cleanup Duty", err)
	}
	original := work.attempts[cleanup.duty.OriginalAttemptID]
	source, err := contract.InspectGeneratedDeleteSource(work.records[generatedRecordKey{contract.GeneratedDutySupportKind, cleanup.duty.DutyID}])
	target, targetErr := work.generatedCleanupTarget(source.Record.Kind, source.OwnerID, source.Target)
	if err != nil || targetErr != nil {
		t.Fatal("actual cleanup target", err, targetErr)
	}
	input, canonical = generatedDeletePlanInputForSource(t, closed, testID(t.Name()+" cleanup"), source.Record, target)
	prior, _ := preparePrivateGeneratedReservation(t, env, closed, input, canonical)
	recorded, _, expected, _ := selectActualGeneratedPacketRecord(t, env, closed, prior, custody.StandardValue, true, nil)
	env.Custody.RetireGenerated()
	closed = selectOrdinaryGeneratedCleanupClose(t, t.Context(), env, recorded, expected.Template.AttemptID)
	store := &generatedCleanupDeleteStore{memoryStore: env.Store.(*memoryStore)}
	closed = selectActualGeneratedInboxRelease(t, t.Context(), env, closed, store, expected.Template.AttemptID, false)
	closed = retainedReaderColdOpen(t, closed, store)
	return env, closed, failed, original
}

func checkAdministrativeSeedProvenance(t *testing.T, historical bool) {
	t.Helper()
	for _, recovery := range []bool{false, true} {
		for _, partial := range []bool{false, true} {
			t.Run(fmt.Sprintf("recovery=%t/partial=%t", recovery, partial), func(t *testing.T) {
				env, closed, failed, original := pendingInboxProvenanceFixture(t, recovery)
				store := closed.store.(*generatedCleanupDeleteStore)
				work := mustSelectedGeneratedWork(t, closed)
				release := work.releases[original.record.AttemptID]
				material := failed.material.Core.OperationMaterialID
				if release.release.State != contract.GeneratedReleasePending || release.release.OriginalResultID != original.record.ResultID ||
					release.release.SelectedHandoffDigest != contract.Hash(original.result) || release.release.ObjectLength != uint32(len(original.result)) ||
					!work.materials[materialIdentity{contract.OperationSeedMaterialKind, material}] || len(work.attempts) != 1 {
					t.Fatal("setup lost exact pending release or last real seed consumer")
				}
				provenance := make(map[generatedRecordKey][]byte)
				for _, key := range []generatedRecordKey{{contract.GeneratedAttemptSupportKind, original.record.AttemptID}, {contract.PendingInboxReleaseSupportKind, release.release.InboxID}} {
					provenance[key] = bytes.Clone(work.records[key].Body)
					if len(provenance[key]) == 0 {
						t.Fatal("setup lacks exact release provenance", key)
					}
				}
				graph, err := work.retainedGraph(original.record.OperationID)
				if err != nil {
					t.Fatal("original graph", err)
				}
				if historical {
					changed := historicalInboxProvenanceIndex(t, env, closed, release.release.InboxID, material, failed.expected.Template.IntentDigest)
					env.Store = changed
					store = &generatedCleanupDeleteStore{memoryStore: changed}
					closed = retainedReaderColdOpen(t, closed, store)
				}
				wantEntries := make(map[uint16][]byte)
				wantAccess := make(map[contract.ID][]byte)
				for _, named := range closed.root.Names {
					entry := closed.valueEntry(named.Slot)
					wantEntries[named.Slot], err = contract.EncodeValueEntry(*entry)
					if err != nil {
						t.Fatal(err)
					}
					if entry.ConfidentialityClass == contract.Secret {
						access, present := closed.materialAccess(contract.ValueMaterialKind, entry.ValueState)
						wantAccess[entry.ValueState], err = contract.EncodeAccessRecord(access)
						if !present || err != nil {
							t.Fatal("current access", err)
						}
					}
				}
				entry := closed
				if partial {
					var result Result
					entry, result = openAdministrative(t.Context(), OpenContext{admission: &closed.admission}, store)
					if entry == nil || result.Outcome != ObservedCurrent {
						t.Fatal("partial entry", result)
					}
					skipped := false
					for i, page := range entry.support {
						skipped = skipped || len(page.Records) == 0 && !entry.adminIndex.Pages[i].ReadRequired
					}
					if !skipped {
						t.Fatal("partial entry read every detail page")
					}
				}
				next := retainedReaderEndWork(t, entry, failed.expected.Template.HazardID, env.Trust)
				if _, present := next.materialAccess(contract.OperationSeedMaterialKind, material); present {
					t.Fatal("EndWork retained seed access after its last real consumer")
				}
				next = retainedReaderColdOpen(t, next, store)
				after := mustSelectedGeneratedWork(t, next)
				if _, present := next.materialAccess(contract.OperationSeedMaterialKind, material); present || after.materials[materialIdentity{contract.OperationSeedMaterialKind, material}] {
					t.Fatal("inbox provenance kept an unused operation seed")
				}
				if len(after.records[generatedRecordKey{contract.OperationMaterialSupportKind, material}].Body) != 0 || len(after.attempts) != 0 || len(after.releases) != 1 {
					t.Fatal("EndWork lost exact material and live-owner closure")
				}
				if _, present := after.content.locations[generatedContentKey{kind: contract.GeneratorContentIntent, id: failed.expected.Template.IntentDigest}]; present {
					t.Fatal("inbox provenance kept an unused Intent")
				}
				for key, body := range provenance {
					if !bytes.Equal(after.records[key].Body, body) {
						t.Fatal("EndWork changed exact inbox provenance", key)
					}
				}
				afterGraph, err := after.retainedGraph(original.record.OperationID)
				if err != nil || !reflect.DeepEqual(graph, afterGraph) || !reflect.DeepEqual(closed.root.Names, next.root.Names) {
					t.Fatal("EndWork changed original graph or current names", err)
				}
				for slot, body := range wantEntries {
					got, err := contract.EncodeValueEntry(*next.valueEntry(slot))
					if err != nil || !bytes.Equal(got, body) {
						t.Fatal("EndWork changed current entry", slot, err)
					}
				}
				for id, body := range wantAccess {
					access, present := next.materialAccess(contract.ValueMaterialKind, id)
					got, err := contract.EncodeAccessRecord(access)
					if !present || err != nil || !bytes.Equal(got, body) {
						t.Fatal("EndWork changed current value access", err)
					}
				}
			})
		}
	}
}

// The archived writer assigned every operation owner to its seed and every
// attempt owner to its Intent. Blob ownership was the union of Slice owners.
// Preserve all support bytes and add only those three historical index edges.
func historicalInboxProvenanceIndex(t *testing.T, env fixtureEnvironment, selected *StateSession, release, material, intent contract.ID) *memoryStore {
	t.Helper()
	original := env.Store.(*memoryStore)
	store := &memoryStore{desc: original.desc, configuration: original.configuration, generation: original.generation, objects: make(map[string]stored)}
	for key, value := range original.objects {
		value.Body = bytes.Clone(value.Body)
		store.objects[key] = value
	}
	bad := *selected
	bad.adminIndex.Pages = slices.Clone(selected.adminIndex.Pages)
	bad.adminIndex.Groups = slices.Clone(selected.adminIndex.Groups)
	group := slices.IndexFunc(bad.adminIndex.Groups, func(g format.AdministrativeGroup) bool {
		return g.GroupID == release && g.OwnerKind == format.AdministrativeInboxRelease
	})
	if group < 0 {
		t.Fatal("historical release group absent")
	}
	added := map[generatedRecordKey]bool{{contract.OperationMaterialSupportKind, material}: true}
	var blob contract.ID
	views := make(map[format.Ref]format.RequiredSupportPageView)
	for _, page := range bad.adminIndex.Pages {
		if !page.ReadRequired {
			continue
		}
		view, err := selected.administrativeSelectedSupportPage(page)
		if err != nil {
			t.Fatal(err)
		}
		views[page.Ref] = view
		for _, row := range view.Records {
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
			if err != nil {
				t.Fatal(err)
			}
			if location.ContentKind == contract.GeneratorContentIntent && location.ContentID == intent {
				added[generatedRecordKey{row.Kind, row.RecordID}] = true
				blob = location.BlobID
			}
		}
	}
	if blob.IsZero() {
		t.Fatal("historical shared Intent absent")
	}
	for _, location := range selected.root.Generated.Fragments {
		if location.BlobID == blob {
			id, err := contract.GeneratorFragmentID(blob, location.FragmentIndex)
			if err != nil {
				t.Fatal(err)
			}
			added[generatedRecordKey{contract.GeneratedFragmentSupportKind, id}] = true
		}
	}
	matched := make(map[generatedRecordKey]bool)
	for i, page := range bad.adminIndex.Pages {
		bad.adminIndex.Pages[i].Spans = nil
		logical := 0
		for _, span := range page.Spans {
			for n := uint16(0); n < span.Count; n++ {
				one := span
				one.First, one.Count = span.First+n, 1
				one.GroupIndexes = slices.Clone(span.GroupIndexes)
				var key generatedRecordKey
				if page.ReadRequired {
					row := views[page.Ref].Records[logical]
					key = generatedRecordKey{row.Kind, row.RecordID}
				} else {
					row := page.Rows[logical]
					key = generatedRecordKey{row.Kind, row.RecordID}
				}
				if added[key] {
					matched[key] = true
					if !slices.Contains(one.GroupIndexes, uint16(group)) {
						one.GroupIndexes = append(one.GroupIndexes, uint16(group))
						slices.Sort(one.GroupIndexes)
					}
				}
				bad.adminIndex.Pages[i].Spans = append(bad.adminIndex.Pages[i].Spans, one)
				logical++
			}
		}
	}
	if len(matched) != len(added) {
		t.Fatal("historical row ownership injection incomplete", len(matched), len(added))
	}
	if err := rechargeEndWorkGroups(&bad.adminIndex, views); err != nil {
		t.Fatal(err)
	}
	shards, err := format.EncodeAdministrativeIndexPages(bad.adminIndex)
	if err != nil {
		t.Fatal(err)
	}
	bad.root.AdministrativeIndex, bad.root.AdministrativeIndexShards = shards[0].Ref, nil
	for i, shard := range shards {
		store.put(mustKey(t, store.desc.Prefix, shard.Ref), shard.Body)
		if i != 0 {
			bad.root.AdministrativeIndexShards = append(bad.root.AdministrativeIndexShards, shard.Ref)
		}
	}
	return retainedReaderSignedState(t, retainedReaderFixture{env: env, selected: selected}, &bad, store)
}

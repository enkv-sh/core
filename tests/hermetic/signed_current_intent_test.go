package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

type selectedBudgetObservationStore struct {
	*memoryStore
	observedLimit, observedReads, observedStages int
	observedDeadline                             time.Time
	deadlineChanged                              bool
}

func (s *selectedBudgetObservationStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	result := s.memoryStore.Read(ctx, key, limit)
	if episode, ok := ctx.Value(storeEpisodeKey{}).(*storeEpisode); ok && episode != nil && episode.stages != 0 {
		s.observedLimit = episode.readLimit
		s.observedReads = episode.stageReads
		s.observedStages = episode.stages
		if !s.observedDeadline.IsZero() && s.observedDeadline != episode.deadline {
			s.deadlineChanged = true
		}
		s.observedDeadline = episode.deadline
	}
	return result
}

func capacityFixtureAdmission(t *testing.T, basis OpenContext) OpenContext {
	t.Helper()
	deadline, ok := t.Deadline()
	if !ok || !time.Now().Before(deadline) || basis.admission == nil {
		t.Fatal("capacity fixture requires an active finite test deadline and admission")
	}
	admitted := *basis.admission
	admitted.expires = deadline
	return OpenContext{admission: &admitted}
}

func assertConfiguredReplacementSeed(t *testing.T, before, after *StateSession, name string) {
	t.Helper()
	_, original := lifecycleEntry(t, before, name)
	_, current := lifecycleEntry(t, after, name)
	if original.ValueSource != contract.Supplied || original.ConfidentialityClass != contract.Plain ||
		!reflect.DeepEqual(before.root.Names, after.root.Names) || current.Name != original.Name ||
		current.Incarnation != original.Incarnation || current.ValueSource != original.ValueSource ||
		current.ConfidentialityClass != original.ConfidentialityClass ||
		!slices.Equal(current.Recipients, original.Recipients) || !bytes.Equal(current.ValueBytes, original.ValueBytes) {
		t.Fatal("configured replacement changed the retained supplied seed or selected names", name)
	}
}

// signedCurrentIntentFixture joins unchanged generated values from real,
// separate selected Final operations. Each source produced and wrapped its own
// value for its exact intent. Only the selected physical image is assembled
// here; the current writer does not produce this multi-origin combination.
func signedCurrentIntentFixture(t *testing.T, env fixtureEnvironment, lifecycle *StateSession,
	label string, sources ...*StateSession) (*memoryStore, *StateSession) {
	t.Helper()
	return signedCurrentIntentFixtureWithRelease(t, env, lifecycle, label, contract.ID{}, sources...)
}

// The release variant retains one real original-create release and its exact
// graph from the first source. It gives EndWork an independent local owner
// while the unchanged multi-origin current values remain selected.
func signedCurrentIntentFixtureWithRelease(t *testing.T, env fixtureEnvironment, lifecycle *StateSession,
	label string, releaseAttempt contract.ID, sources ...*StateSession) (*memoryStore, *StateSession) {
	t.Helper()
	ctx := t.Context()
	if len(sources) < 2 {
		t.Fatal("independent generated sources required")
	}
	selected := sources[0]
	store := selectedMemoryStoreCopy(env.Store.(*memoryStore))
	domain := selected.root.Domain
	current := *selected
	current.store = store
	current.clearSelectedSupportFacts()
	current.root = selected.root
	current.root.Snapshot = fixtureID(domain, label+" snapshot")
	current.root.Transition = fixtureID(domain, label+" transition")
	current.root.Generated = format.EmptyGeneratedClosure()
	current.root.Generated.SuccessWindow = lifecycle.root.Generated.SuccessWindow
	current.root.Generated.FailureWindow = lifecycle.root.Generated.FailureWindow
	current.root.Generated.ReceiptOrder = lifecycle.root.Generated.ReceiptOrder
	current.root.RequiredSupport = nil
	current.root.RequiredSupportRecordCount = 0
	current.root.WarningBits = lifecycle.root.WarningBits
	current.support = nil
	current.adminIndex = format.AdministrativeIndex{}
	current.root.AdministrativeIndexShards = nil
	current.pages = [contract.MaxValueEntryPages]*format.ValueEntryPage{}
	current.root.ValueEntryPages = [contract.MaxValueEntryPages]*format.Ref{}
	current.root.Names = nil
	current.root.ValueEntryCount, current.root.SecretCount, current.root.RawBytes = 0, 0, 0
	current.root.MembershipCount, current.root.SecretOrdinaryWrapCount = 0, 0
	current.root.Generated.GeneratedCurrent = 0
	put := func(ref format.Ref, body []byte) {
		t.Helper()
		if err := format.CheckReference(ref, body); err != nil {
			t.Fatal("signed intent object reference", err)
		}
		key, err := format.Key(store.desc.Prefix, ref)
		if err != nil {
			t.Fatal("signed intent object key", err)
		}
		value := stored{Token: selected.token}
		if store.fileBodies == nil || key == store.desc.HeadKey {
			value.Body = bytes.Clone(body)
		} else {
			fileValue, err := store.fileBodies.write(body)
			if err != nil {
				t.Fatal("signed intent object file", err)
			}
			value = fileValue
			value.Token = selected.token
		}
		store.objects[key] = value
	}
	blobID := fixtureID(domain, label+" compact blob")
	var blob []byte
	var locations []contract.GeneratorSliceLocation
	var rows []contract.SupportRecord
	var accessRows []contract.AccessRecord
	receiptIndex, err := lifecycle.receiptIndexID()
	if err != nil {
		t.Fatal("signed intent retained receipt index", err)
	}
	receiptFragments := make(map[contract.ID]bool)
	for _, location := range lifecycle.root.Generated.Fragments {
		if location.BlobID != receiptIndex {
			continue
		}
		id, err := contract.GeneratorFragmentID(location.BlobID, location.FragmentIndex)
		if err != nil {
			t.Fatal("signed intent retained receipt fragment", err)
		}
		receiptFragments[id] = true
	}
	retainedRow := func(row contract.SupportRecordView) bool {
		return row.Kind == contract.OutputConfigurationSliceSupportKind || row.Kind == contract.MutationReceiptSupportKind ||
			row.Kind == contract.GeneratedFragmentSupportKind && receiptFragments[row.RecordID]
	}
	for _, ref := range lifecycle.root.RequiredSupport {
		position := slices.IndexFunc(lifecycle.support, func(page format.RequiredSupportPageView) bool {
			return page.Domain == ref.Domain && page.Object == ref.Object && page.Index == ref.Index
		})
		if position < 0 {
			t.Fatal("signed intent retained support identity")
		}
		if !slices.ContainsFunc(lifecycle.support[position].Records, retainedRow) {
			continue
		}
		body, result := lifecycle.readObjectBorrowedUncached(ctx, ref)
		if result.Outcome != 0 {
			t.Fatal("signed intent retained configuration read", result)
		}
		page, err := format.InspectRequiredSupportPage(body)
		if err != nil {
			t.Fatal("signed intent retained configuration page", err)
		}
		for _, selectedRow := range lifecycle.support[position].Records {
			if !retainedRow(selectedRow) {
				continue
			}
			physical := slices.IndexFunc(page.Records, func(row contract.SupportRecordView) bool {
				return row.Kind == selectedRow.Kind && row.RecordID == selectedRow.RecordID
			})
			if physical < 0 {
				t.Fatal("signed intent retained configuration row identity")
			}
			row := page.Records[physical]
			rows = append(rows, contract.SupportRecord{Kind: row.Kind, RecordID: row.RecordID, Body: bytes.Clone(row.Body)})
		}
	}
	current.root.OutputConfiguration = lifecycle.root.OutputConfiguration
	used := make(map[uint16]bool)
	intents := make(map[contract.ID]bool)
	operations := make(map[contract.ID]bool)
	for _, source := range sources {
		if source == nil || source.root.Domain != domain || source.root.CurrentAccess.Core.CompatibilityID != current.root.CurrentAccess.Core.CompatibilityID {
			t.Fatal("independent source control differs")
		}
		work, err := source.selectedGeneratedWork(ctx)
		if err != nil {
			t.Fatal("independent source closure", err)
		}
		var sourceOperation contract.ID
		for _, named := range source.root.Names {
			entry := source.valueEntry(named.Slot)
			if entry == nil || entry.ValueSource != contract.Generated {
				continue
			}
			if used[named.Slot] {
				t.Fatal("generated source slot repeats", named.Name)
			}
			if sourceOperation.IsZero() {
				sourceOperation = entry.Generated.OriginOperationID
				if operations[sourceOperation] {
					t.Fatal("generated source operation repeats", named.Name)
				}
				operations[sourceOperation] = true
			} else if sourceOperation != entry.Generated.OriginOperationID {
				t.Fatal("one source includes several generated origins")
			}
			used[named.Slot] = true
			intent, err := work.readSelectedSlice(ctx, contract.GeneratorContentIntent, entry.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
			if err != nil {
				t.Fatal("selected source intent", named.Name, err)
			}
			if !intents[entry.Generated.IntentDigest] {
				location := contract.GeneratorSliceLocation{Schema: 1, ContentKind: contract.GeneratorContentIntent,
					ContentID: entry.Generated.IntentDigest, BlobID: blobID, Offset: uint64(len(blob)), Length: uint32(len(intent)), Digest: contract.Hash(intent)}
				if _, err := contract.EncodeGeneratorSliceLocation(location); err != nil {
					t.Fatal("signed intent location", named.Name, err)
				}
				locations = append(locations, location)
				blob = append(blob, intent...)
				intents[entry.Generated.IntentDigest] = true
			}
			key := generatedRecordKey{kind: contract.GeneratedCreateEvidenceSupportKind, id: entry.Generated.CreateResultID}
			evidenceRow, ok := work.records[key]
			if !ok {
				t.Fatal("selected source evidence missing", named.Name)
			}
			evidence, err := contract.DecodeGeneratedCreateEvidence(evidenceRow.Body)
			if err != nil || contract.ValidateGeneratedValueEntryEvidence(domain, *entry, evidence, intent) != nil {
				t.Fatal("selected source evidence does not bind its exact entry", named.Name, err)
			}
			rows = append(rows, contract.SupportRecord(evidenceRow))
			access, ok := source.materialAccess(contract.ValueMaterialKind, entry.ValueState)
			if !ok {
				t.Fatal("selected source access missing", named.Name)
			}
			accessRows = append(accessRows, access)
			pageIndex := named.Slot / format.PageSlots
			if current.pages[pageIndex] == nil {
				current.pages[pageIndex] = &format.ValueEntryPage{Domain: domain,
					Object: fixtureID(domain, fmt.Sprintf("%s value page %d", label, pageIndex)), Index: pageIndex}
			}
			copy := *entry
			copy.ValueBytes = bytes.Clone(entry.ValueBytes)
			copy.Recipients = slices.Clone(entry.Recipients)
			current.pages[pageIndex].Slots[named.Slot%format.PageSlots] = &copy
			current.root.Names = append(current.root.Names, format.NameEntry{Name: entry.Name, Slot: named.Slot})
			current.root.ValueEntryCount++
			current.root.SecretCount++
			current.root.Generated.GeneratedCurrent++
			current.root.MembershipCount += uint32(len(entry.Recipients))
			current.root.SecretOrdinaryWrapCount += uint32(len(entry.Recipients))
			payload, err := contract.DecodeCanonicalPayload(entry.ValueBytes)
			if err != nil {
				t.Fatal("selected source payload", named.Name, err)
			}
			current.root.RawBytes += uint64(payload.ContentLength)
		}
	}
	for _, named := range lifecycle.root.Names {
		entry := lifecycle.valueEntry(named.Slot)
		if entry == nil || used[named.Slot] || entry.ValueSource != contract.Supplied {
			t.Fatal("baseline supplied entry overlaps generated source")
		}
		pageIndex := named.Slot / format.PageSlots
		if current.pages[pageIndex] == nil {
			current.pages[pageIndex] = &format.ValueEntryPage{Domain: domain,
				Object: fixtureID(domain, fmt.Sprintf("%s value page %d", label, pageIndex)), Index: pageIndex}
		}
		copy := *entry
		copy.ValueBytes = bytes.Clone(entry.ValueBytes)
		copy.Recipients = slices.Clone(entry.Recipients)
		current.pages[pageIndex].Slots[named.Slot%format.PageSlots] = &copy
		current.root.Names = append(current.root.Names, format.NameEntry{Name: entry.Name, Slot: named.Slot})
		current.root.ValueEntryCount++
		current.root.MembershipCount += uint32(len(entry.Recipients))
		if entry.ConfidentialityClass == contract.Secret {
			access, found := lifecycle.materialAccess(contract.ValueMaterialKind, entry.ValueState)
			if !found {
				t.Fatal("baseline supplied secret access")
			}
			accessRows = append(accessRows, access)
			payload, err := contract.InspectCanonicalPayload(entry.ValueBytes)
			if err != nil {
				t.Fatal("baseline supplied secret payload", err)
			}
			current.root.SecretCount++
			current.root.SecretOrdinaryWrapCount += uint32(len(entry.Recipients))
			current.root.RawBytes += uint64(payload.ContentLength)
		} else {
			current.root.RawBytes += uint64(len(entry.ValueBytes))
		}
	}
	slices.SortFunc(current.root.Names, func(a, b format.NameEntry) int {
		return bytes.Compare([]byte(a.Name), []byte(b.Name))
	})
	slices.SortFunc(accessRows, func(a, b contract.AccessRecord) int {
		return bytes.Compare(a.MaterialID[:], b.MaterialID[:])
	})
	current.access = [contract.MaxChildPages]*format.AccessPage{}
	current.root.CurrentAccess.Core.AccessPageRefs = nil
	for first := 0; first < len(accessRows); first += 16 {
		index := uint16(first / 16)
		page := format.AccessPage{Domain: domain, Object: fixtureID(domain, fmt.Sprintf("%s access page %d", label, index)), Index: index, Records: slices.Clone(accessRows[first:min(first+16, len(accessRows))])}
		body, err := format.EncodeAccessPage(page)
		if err != nil {
			t.Fatal("signed independent access page", err)
		}
		ref, err := format.Reference(format.AccessKind, domain, page.Object, index, body)
		if err != nil {
			t.Fatal("signed independent access reference", err)
		}
		put(ref, body)
		current.access[index] = &page
		current.root.CurrentAccess.Core.AccessPageRefs = append(current.root.CurrentAccess.Core.AccessPageRefs, ref)
	}
	current.root.CurrentAccess.Core.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(domain, accessRows)
	if err != nil {
		t.Fatal("signed independent access descriptor", err)
	}
	current.root.AccessRecordCount = uint32(len(accessRows))
	if err := contract.AdvanceAccessGeneration(&current.root.CurrentAccess.Core, current.root.Transition); err != nil {
		t.Fatal("signed independent access generation", err)
	}
	current.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(current.root.CurrentAccess.Core)
	if err != nil {
		t.Fatal("signed independent access root", err)
	}
	var bundles []contract.GeneratorPlanBundle
	if !releaseAttempt.IsZero() {
		work, err := selected.selectedGeneratedWork(ctx)
		if err != nil {
			t.Fatal("release source selected work", err)
		}
		released, ok := work.releases[releaseAttempt]
		a := released.attempt
		if !ok || released.template.Action != contract.GeneratorActionCreate ||
			released.release.State != contract.GeneratedReleasePending || a.State != contract.GeneratedEffectFailedTerminal ||
			a.Facts != contract.EmptyGeneratorVector(contract.GeneratorVectorFacts) ||
			a.History != contract.EmptyGeneratorVector(contract.GeneratorVectorHistory) ||
			a.Progress != contract.EmptyGeneratorVector(contract.GeneratorVectorProgress) {
			t.Fatalf("release source is not the simple real failed create: found=%t action=%d release_state=%d attempt_state=%d facts_empty=%t history_empty=%t progress_empty=%t support_count=%d",
				ok, released.template.Action, released.release.State, a.State,
				a.Facts == contract.EmptyGeneratorVector(contract.GeneratorVectorFacts),
				a.History == contract.EmptyGeneratorVector(contract.GeneratorVectorHistory),
				a.Progress == contract.EmptyGeneratorVector(contract.GeneratorVectorProgress), a.Support.Count)
		}
		for _, key := range []generatedRecordKey{{contract.GeneratedAttemptSupportKind, releaseAttempt},
			{contract.PendingInboxReleaseSupportKind, a.InboxID}} {
			row, ok := work.records[key]
			if !ok || len(row.Body) == 0 {
				t.Fatal("release source lost an exact selected row", key)
			}
			rows = append(rows, contract.SupportRecord{Kind: row.Kind, RecordID: row.RecordID, Body: bytes.Clone(row.Body)})
		}
		if _, err := work.vectors.resolve(contract.GeneratedParentSupportKind, a.OperationID,
			contract.GeneratorVectorSupport, a.Support); err != nil {
			t.Fatal("release source exact support vector", err)
		}
		var copied uint32
		for _, row := range work.records {
			if row.Kind != contract.GeneratorVectorSupportKind {
				continue
			}
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				t.Fatal("release source support carrier", err)
			}
			if carrier.OwnerKind == contract.GeneratedParentSupportKind && carrier.OwnerID == a.OperationID &&
				carrier.VectorKind == contract.GeneratorVectorSupport && carrier.Vector == a.Support {
				rows = append(rows, contract.SupportRecord{Kind: row.Kind, RecordID: row.RecordID, Body: bytes.Clone(row.Body)})
				copied++
			}
		}
		if copied != a.Support.Count {
			t.Fatal("release source support carriers are incomplete", copied, a.Support.Count)
		}
		bundle, err := work.retainedGraph(a.OperationID)
		if err != nil {
			t.Fatal("release source retained graph", err)
		}
		graph, err := work.readSelectedSlice(ctx, contract.GeneratorContentGraph,
			bundle.UsePlan.PlanGraphID, contract.GeneratorGraphMaxLength-8)
		if err != nil {
			t.Fatal("release source authenticated graph slice", err)
		}
		graphBlob := fixtureID(domain, label+" release graph blob")
		graphRows, err := generatedFragmentRows(graphBlob, graph)
		if err != nil {
			t.Fatal("release graph fragments", err)
		}
		rows = append(rows, graphRows...)
		locations = append(locations, contract.GeneratorSliceLocation{Schema: 1,
			ContentKind: contract.GeneratorContentGraph, ContentID: bundle.UsePlan.PlanGraphID,
			BlobID: graphBlob, Length: uint32(len(graph)), Digest: contract.Hash(graph)})
		bundles = append(bundles, bundle)
		current.root.Generated.Graphs, err = contract.GeneratorIndexDescriptor(contract.GeneratorGraphSet,
			[]contract.ID{bundle.UsePlan.PlanGraphID})
		if err != nil {
			t.Fatal("release graph set", err)
		}
	}
	fragmentRows, err := generatedFragmentRows(blobID, blob)
	if err != nil {
		t.Fatal("signed compact intent fragments", err)
	}
	rows = append(rows, fragmentRows...)
	slices.SortFunc(locations, func(a, b contract.GeneratorSliceLocation) int {
		if a.ContentKind != b.ContentKind {
			return int(a.ContentKind) - int(b.ContentKind)
		}
		return bytes.Compare(a.ContentID[:], b.ContentID[:])
	})
	var locationBodies [][]byte
	for _, location := range locations {
		body, err := contract.EncodeGeneratorSliceLocation(location)
		if err != nil {
			t.Fatal("signed Slice carrier", err)
		}
		locationBodies = append(locationBodies, body)
	}
	current.root.Generated.Slices, fragmentRows = generatedVectorRowsForDomain(t, domain,
		contract.GeneratorSnapshotOwner, current.root.Snapshot, contract.GeneratorVectorSlices, locationBodies)
	rows = append(rows, fragmentRows...)
	generatedRefreshClosureCounts(&current.root.Generated, rows)
	groups, err := generatedReservationGroupsForState(&current, rows, locations, bundles)
	if err != nil {
		t.Fatal("signed intent storage groups", err)
	}
	packed, err := format.PackRequiredSupportRows(domain, groups, 0)
	if err != nil {
		t.Fatal("signed intent physical packing", err)
	}
	current.root.RequiredSupport = nil
	current.support = nil
	pages := make([]format.RequiredSupportPage, 0, len(packed))
	for i, records := range packed {
		page := format.RequiredSupportPage{Domain: domain, Object: fixtureID(domain, fmt.Sprintf("%s support %d", label, i)),
			Index: uint16(i), Records: records}
		body, err := format.EncodeRequiredSupportPage(page)
		if err != nil {
			t.Fatal("signed intent support page", err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal("signed intent support reference", err)
		}
		put(ref, body)
		view, err := format.InspectRequiredSupportPage(body)
		if err != nil {
			t.Fatal("signed intent support view", err)
		}
		current.root.RequiredSupport = append(current.root.RequiredSupport, ref)
		current.root.RequiredSupportRecordCount += uint32(len(records))
		current.support = append(current.support, view)
		pages = append(pages, page)
	}
	current.root.Generated.Fragments, err = generatedFragmentDirectory(pages)
	if err != nil {
		t.Fatal("signed intent fragment directory", err)
	}
	for i, page := range current.pages {
		if page == nil || page == selected.pages[i] {
			continue
		}
		body, err := format.EncodeValueEntryPage(*page)
		if err != nil {
			t.Fatal("signed intent value page", err)
		}
		ref, err := format.Reference(contract.ValueEntryPageKind, domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal("signed intent value reference", err)
		}
		put(ref, body)
		current.root.ValueEntryPages[i] = &ref
	}
	index := format.AdministrativeIndex{Domain: domain, Object: administrativeIndexObject(domain, current.root.Snapshot),
		SliceSnapshot: current.root.Snapshot}
	if !releaseAttempt.IsZero() {
		index, err = selected.buildAdministrativeIndex(ctx, current.root, pages, nil, nil, &current, bundles...)
		if err != nil {
			t.Fatal("signed independent release administrative index", err)
		}
	} else {
		for i, page := range current.support {
			readRequired := true
			for _, row := range page.Records {
				if row.Kind != contract.GeneratorVectorSupportKind {
					readRequired = false
					break
				}
				carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil || carrier.VectorKind != contract.GeneratorVectorSlices {
					readRequired = false
					break
				}
			}
			indexed := format.AdministrativePage{Ref: current.root.RequiredSupport[i], ReadRequired: readRequired,
				Spans: []format.AdministrativeSpan{{First: 0, Count: uint16(len(page.Records)), Mandatory: true}}}
			if !readRequired {
				for _, row := range page.Records {
					indexed.Rows = append(indexed.Rows, format.AdministrativeRowSummary{Kind: row.Kind,
						RecordID: row.RecordID, BodyLength: uint32(len(row.Body))})
				}
			}
			index.Pages = append(index.Pages, indexed)
		}
	}
	indexPages, err := format.EncodeAdministrativeIndexPages(index)
	if err != nil || len(indexPages) == 0 {
		t.Fatal("signed independent administrative index", err)
	}
	current.adminIndex = index
	current.root.AdministrativeIndex = indexPages[0].Ref
	current.root.AdministrativeIndexShards = nil
	for i, page := range indexPages {
		put(page.Ref, page.Body)
		if i != 0 {
			current.root.AdministrativeIndexShards = append(current.root.AdministrativeIndexShards, page.Ref)
		}
	}
	current.recountChildren()
	if _, err := current.selectedGeneratedWork(ctx); err != nil {
		t.Fatal("assembled selected generated image", err)
	}
	if _, err := current.validateRelationsMode(t.Context(), false); err != nil {
		t.Fatal("assembled selected relations", err)
	}
	return writeSignedCurrentIntentImage(t, env, lifecycle, selected, &current, store, label, put)
}

func writeSignedCurrentIntentImage(t *testing.T, env fixtureEnvironment, lifecycle, selected, current *StateSession,
	store *memoryStore, label string, put func(format.Ref, []byte)) (*memoryStore, *StateSession) {
	t.Helper()
	ctx := t.Context()
	domain := current.root.Domain
	rootBody, err := format.EncodeRoot(current.root)
	if err != nil {
		t.Fatal("signed intent root", err)
	}
	rootRef, err := format.Reference(contract.RootKind, domain, current.root.Snapshot, 0, rootBody)
	if err != nil {
		t.Fatal("signed intent root reference", err)
	}
	put(rootRef, rootBody)
	h := lifecycle.head
	h.Core = selected.head.Core
	h.Core.Root = rootRef
	h.Core.Revision = fixtureID(domain, label+" revision")
	h.Core.PreviousRevision, h.Core.PreviousDigest, h.Core.PreviousToken = selected.head.Core.Revision, contract.Hash(selected.body), selected.token
	h.Subject.Operation = fixtureID(domain, label+" operation")
	h.Subject.BeforeValueEntryCount, h.Subject.AfterValueEntryCount = current.root.ValueEntryCount, current.root.ValueEntryCount
	h.Subject.BeforeSecretCount, h.Subject.AfterSecretCount = uint16(current.root.SecretCount), uint16(current.root.SecretCount)
	h.Subject.BeforeRawBytes, h.Subject.AfterRawBytes = current.root.RawBytes, current.root.RawBytes
	h.Subject.BeforeMembershipCount, h.Subject.AfterMembershipCount = current.root.MembershipCount, current.root.MembershipCount
	h.Subject.BeforeAccessRoot, h.Subject.AfterAccessRoot = current.root.CurrentAccess.AccessRoot, current.root.CurrentAccess.AccessRoot
	h.Subject.Normal.PublicState = current.publicState()
	h.Subject.Normal.Changed = 1
	h.Subject.Normal.Union.Count = current.root.ValueEntryCount
	h.Subject.Grant.Grants = grantCommitment(domain, nil)
	h.Subject.Exclusion.Exclusions = exclusionCommitment(domain, nil)
	h.Subject.Exclusion.Retirements = retirementCommitment(domain)
	h.Subject.Normal.Union.Length = uint64(len("ENKV/CRYPTO/v2/lifecycle-union-v6\x00")+32+4) +
		142*uint64(current.root.ValueEntryCount) + 64*uint64(current.root.MembershipCount)
	h.Subject.Normal.Intent.Length = fixtureValueIntentLength(&current.root) + fixtureCompleteIntentOverhead(t, current)
	for _, named := range current.root.Names {
		h.Subject.Normal.Union.Length += uint64(len(named.Name))
	}
	h.Subject.Request = requestCommitment(h.Core, h.Subject)
	coreBody, err := format.EncodeHeadCore(h.Core)
	if err != nil {
		t.Fatal("signed intent HEAD core", err)
	}
	conditionalBody, err := format.EncodeConditionalPlan(conditional(h.Core, coreBody))
	if err != nil {
		t.Fatal("signed intent conditional plan", err)
	}
	h.Subject.HeadCore, h.Subject.HeadCoreLength, h.Subject.ConditionalPlan = contract.Hash(coreBody), uint32(len(coreBody)), contract.Hash(conditionalBody)
	request, err := contract.NewLifecycleRequest(h.Subject)
	if err != nil {
		t.Fatal("signed intent lifecycle request", err)
	}
	proof := env.Trust.Sign(ctx, request)
	if proof.Reason != contract.ReasonNone {
		t.Fatal("signed intent proof", proof.Reason)
	}
	h.AuthorizationSignature = proof.Signature
	headBody, err := format.EncodeHead(h)
	if err != nil {
		t.Fatal("signed intent HEAD", err)
	}
	if _, err := format.DecodeHead(headBody); err != nil {
		t.Fatal("signed intent HEAD round trip", err)
	}
	store.put(store.desc.HeadKey, headBody)
	if store.fileBodies != nil {
		for key, object := range store.objects {
			if key != store.desc.HeadKey && (object.bodyPath == "" || object.Body != nil) {
				t.Fatal("signed image held an immutable body before cold Open", key)
			}
		}
	}
	var readKeys []string
	store.readHook = func(key string, result contract.ReadResult) contract.ReadResult {
		readKeys = append(readKeys, key)
		return result
	}
	opened, outcome := Open(ctx, OpenContext{admission: &selected.admission}, store)
	store.readHook = nil
	if opened == nil || outcome.Outcome != ObservedCurrent {
		t.Fatal("signed independent current intent did not cold-open", outcome, readKeys)
	}
	return store, opened
}

// This predecessor is selected by the ordinary failed-create and cleanup
// lifecycle. Neither result inbox is released remotely by this helper.
func signedCurrentIntentReleasePredecessor(t *testing.T, operationCtx context.Context, env fixtureEnvironment,
	before *StateSession, label string) (*StateSession, generatedAttempt) {
	t.Helper()
	ctx := t.Context()
	closed, original := selectPrivateOwnedUnusableAggregateForProfile(t, env, before,
		[]string{"unusable-before-current"}, defaultGeneratedFixtureProfile(), fixtureID(env.Domain, label+" failed create"))
	closed = generatedLifecycleReopen(t, operationCtx, closed, env.Store)
	work, err := closed.selectedGeneratedWork(ctx)
	if err != nil {
		t.Fatal("current-intent release predecessor", err)
	}
	row, ok := work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, original.expected.Template.HazardID}]
	if !ok {
		t.Fatal("current-intent release predecessor lost its actual Hazard")
	}
	hazard, err := contract.InspectGeneratedHazardRecord(row.Body)
	target, targetErr := work.generatedCleanupTarget(contract.GeneratedHazardSupportKind, hazard.HazardID, hazard.Target)
	if err != nil || targetErr != nil || target.OriginalAttemptID != original.record.AttemptID ||
		target.ResourceID != original.record.ResourceID || hazard.OriginalOperationID != original.record.OperationID {
		t.Fatal("current-intent release predecessor changed its actual target", err, targetErr)
	}
	input, inputCanonical := generatedDeletePlanInputForSource(t, closed, fixtureID(env.Domain, label+" cleanup"),
		contract.SupportRecord(row), target)
	prior, _ := preparePrivateGeneratedReservation(t, env, closed, input, inputCanonical)
	recorded, _, cleanup, _ := selectActualGeneratedPacketRecord(t, env, closed, prior, custody.StandardValue, true, nil)
	completed := selectOrdinaryGeneratedCleanupClose(t, ctx, env, recorded, cleanup.Template.AttemptID)
	completed = generatedLifecycleReopen(t, operationCtx, completed, env.Store)
	selected, err := completed.selectedGeneratedWork(ctx)
	if err != nil {
		t.Fatal("ordinary cleanup selected release closure", err)
	}
	release, retained := selected.releases[original.record.AttemptID]
	if !retained || release.template.Action != contract.GeneratorActionCreate ||
		release.release.State != contract.GeneratedReleasePending || release.release.InboxID != original.record.InboxID ||
		release.release.OriginalResultID != original.record.ResultID ||
		release.release.SelectedHandoffDigest != contract.Hash(original.result) ||
		release.release.ObjectLength != uint32(len(original.result)) ||
		completed.root.ValueEntryCount != before.root.ValueEntryCount || completed.root.Generated.Hazards != 0 ||
		completed.root.Generated.Duties != 0 || !completed.root.Generated.ActiveOwner.IsZero() {
		t.Fatal("ordinary cleanup did not retain the exact original-create release", err)
	}
	return completed, original
}

func assertEndWorkReceiptWindow(t testing.TB, before contract.MutationReceiptWindows, after *StateSession) contract.CompactMutationReceipt {
	t.Helper()
	if len(before.Successes) >= contract.MutationReceiptWindowLimit {
		t.Fatal("EndWork receipt fixture must leave room in its success window")
	}
	windows, err := after.receiptWindows(t.Context())
	if err != nil || windows.DomainID != before.DomainID || len(windows.Successes) != len(before.Successes)+1 || !slices.Equal(windows.Failures, before.Failures) {
		t.Fatal("EndWork changed the receipt domain, failures or exact success count", err)
	}
	receipt := windows.Successes[len(before.Successes)]
	if after.head.EndWork == nil || receipt.OperationKind != contract.OperationEndSelectedWork || receipt.OperationID != after.head.EndWork.OperationID {
		t.Fatal("EndWork did not append its own successful receipt")
	}
	want := append(slices.Clone(before.Successes), receipt)
	if !slices.Equal(windows.Successes, want) {
		t.Fatal("EndWork changed or reordered an existing successful receipt")
	}
	assertSuccessReceiptOrder(t, before, windows, receipt.OperationID)
	return receipt
}

func assertSignedCurrentIntentReleaseExit(t *testing.T, env fixtureEnvironment, store *memoryStore,
	before, releaseSource *StateSession, original generatedAttempt, expectedGenerated int, wantSeed []byte) {
	t.Helper()
	ctx := t.Context()
	beforeWindows, err := before.receiptWindows(ctx)
	if err != nil {
		t.Fatal("before-replacement receipt window", err)
	}
	work, err := before.selectedGeneratedWork(ctx)
	if err != nil {
		t.Fatal("before-replacement selected work", err)
	}
	released, ok := work.releases[original.record.AttemptID]
	if !ok || len(work.releases) != 1 || len(before.adminIndex.Groups) != 1+len(before.adminIndex.PublicationOrder) ||
		before.root.Generated.GeneratedCurrent != uint32(expectedGenerated) ||
		before.root.Generated.Attempts != 1 || before.root.Generated.PendingReleases != 1 ||
		before.root.Generated.Graphs.Count != 1 || before.root.Generated.LiveOwners.Count != 1 ||
		before.root.Generated.Duties != 0 || before.root.Generated.Hazards != 0 ||
		before.root.Generated.Results != 0 || before.root.Generated.Materials != 0 ||
		before.root.Generated.Slices.Count != uint32(expectedGenerated+1) ||
		before.root.SecretCount != uint32(expectedGenerated) || before.root.ValueEntryCount != uint32(expectedGenerated+1) ||
		before.root.WarningBits != 0 {
		t.Fatal("before-replacement release fixture changed its exact shape")
	}
	sourceWork, err := releaseSource.selectedGeneratedWork(ctx)
	if err != nil || !reflect.DeepEqual(released, sourceWork.releases[original.record.AttemptID]) || len(work.attempts) != 0 {
		t.Fatal("before-replacement fixture changed or made adoptable the actual released create", err)
	}
	for _, key := range []generatedRecordKey{{contract.GeneratedAttemptSupportKind, original.record.AttemptID},
		{contract.PendingInboxReleaseSupportKind, original.record.InboxID}} {
		if !bytes.Equal(work.records[key].Body, sourceWork.records[key].Body) {
			t.Fatal("before-replacement fixture changed an exact original release row", key)
		}
	}
	var supportCount uint32
	for key, row := range sourceWork.records {
		if row.Kind != contract.GeneratorVectorSupportKind {
			continue
		}
		carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			t.Fatal("before-replacement source support carrier", err)
		}
		if carrier.OwnerKind == contract.GeneratedParentSupportKind && carrier.OwnerID == released.attempt.OperationID &&
			carrier.VectorKind == contract.GeneratorVectorSupport && carrier.Vector == released.attempt.Support {
			if !bytes.Equal(work.records[key].Body, row.Body) {
				t.Fatal("before-replacement fixture changed an exact original Support carrier", key)
			}
			supportCount++
		}
	}
	if supportCount != released.attempt.Support.Count {
		t.Fatal("before-replacement fixture lost an original Support carrier")
	}
	graph, err := work.retainedGraph(released.attempt.OperationID)
	if err != nil {
		t.Fatal("before-replacement original graph", err)
	}
	graphBody, err := work.readSelectedSlice(ctx, contract.GeneratorContentGraph,
		graph.UsePlan.PlanGraphID, contract.GeneratorGraphMaxLength-8)
	if err != nil {
		t.Fatal("before-replacement original graph bytes", err)
	}
	sourceGraph, err := sourceWork.readSelectedSlice(ctx, contract.GeneratorContentGraph,
		graph.UsePlan.PlanGraphID, contract.GeneratorGraphMaxLength-8)
	if err != nil || !bytes.Equal(graphBody, sourceGraph) {
		t.Fatal("before-replacement fixture changed the authenticated original graph", err)
	}
	// Each current intent contains its distinct name in JSON settings within
	// complete 384 KiB canonical framing. The graph lives in a separate blob
	// and is charged as well as those current bytes.
	intentFragments := (expectedGenerated*(384<<10) + contract.GeneratedFragmentMaxPayload - 1) / contract.GeneratedFragmentMaxPayload
	graphFragments := (len(graphBody) + contract.GeneratedFragmentMaxPayload - 1) / contract.GeneratedFragmentMaxPayload
	receiptFragments := int(receiptIndexFragmentCount(t, before.root))
	receiptRows := int(before.root.Generated.SuccessWindow.Count + before.root.Generated.FailureWindow.Count)
	wantFragments := intentFragments + graphFragments + receiptFragments
	wantRows := 2*expectedGenerated + wantFragments + 3 + int(released.attempt.Support.Count) + int(before.root.OutputConfiguration.SliceCount) + len(before.adminIndex.PublicationOrder) + receiptRows
	if len(before.root.Generated.Fragments) != wantFragments || before.root.RequiredSupportRecordCount != uint32(wantRows) {
		t.Fatalf("before-replacement support charges: rows=%d wanted=%d fragments=%d wanted=%d receipts=%d receipt-fragments=%d", before.root.RequiredSupportRecordCount, wantRows, len(before.root.Generated.Fragments), wantFragments, receiptRows, receiptFragments)
	}
	var intentBytes uint64
	assertCurrent := func(after *StateSession) {
		t.Helper()
		if after.root.ValueEntryCount != before.root.ValueEntryCount || after.root.SecretCount != before.root.SecretCount ||
			after.root.Generated.GeneratedCurrent != before.root.Generated.GeneratedCurrent ||
			after.root.RawBytes != before.root.RawBytes || after.root.MembershipCount != before.root.MembershipCount ||
			after.root.SecretOrdinaryWrapCount != before.root.SecretOrdinaryWrapCount ||
			!reflect.DeepEqual(after.root.Names, before.root.Names) ||
			!reflect.DeepEqual(after.root.ValueEntryPages, before.root.ValueEntryPages) ||
			!reflect.DeepEqual(after.root.CurrentAccess, before.root.CurrentAccess) {
			t.Fatal("before-replacement exit changed current counts, pages, membership or access")
		}
		assertCapacityConfigurationPreserved(t, before, after)
		afterWork, err := after.selectedGeneratedWork(ctx)
		if err != nil {
			t.Fatal("before-replacement current selected work", err)
		}
		intentBytes = 0
		for _, named := range before.root.Names {
			entry, actual := before.valueEntry(named.Slot), after.valueEntry(named.Slot)
			if !reflect.DeepEqual(actual, entry) {
				t.Fatal("before-replacement exit changed an exact entry", named.Name)
			}
			if entry.ValueSource != contract.Generated {
				if entry.Name != "a-seed" || entry.ConfidentialityClass != contract.Plain || !bytes.Equal(entry.ValueBytes, wantSeed) {
					t.Fatal("before-replacement exit changed the plain seed")
				}
				continue
			}
			want := capacityIntentBytes(t, named.Name)
			intent, err := afterWork.readSelectedSlice(ctx, contract.GeneratorContentIntent,
				entry.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
			if err != nil || !bytes.Equal(intent, want) {
				t.Fatal("before-replacement exit changed an exact original Intent", named.Name, err)
			}
			intentBytes += uint64(len(intent))
			key := generatedRecordKey{contract.GeneratedCreateEvidenceSupportKind, entry.Generated.CreateResultID}
			if !bytes.Equal(afterWork.records[key].Body, work.records[key].Body) {
				t.Fatal("before-replacement exit changed exact current evidence", named.Name)
			}
			priorAccess, priorOK := before.materialAccess(contract.ValueMaterialKind, entry.ValueState)
			actualAccess, actualOK := after.materialAccess(contract.ValueMaterialKind, entry.ValueState)
			if !priorOK || !actualOK || !reflect.DeepEqual(actualAccess, priorAccess) {
				t.Fatal("before-replacement exit changed exact current access", named.Name)
			}
			consumed := env.Custody.Consume(ctx, sessionConsumerSelection(t, after, after.admission.recipient, named.Name), custody.StandardValue)
			if consumed.Code != contract.CryptoSuccess || consumed.Delivery != 1 || !consumed.ValueMatched {
				t.Fatal("before-replacement original current value is not privately readable", named.Name, consumed)
			}
		}
		if intentBytes != uint64(expectedGenerated)*(384<<10) {
			t.Fatal("before-replacement exit changed the independent current Intent byte total", intentBytes)
		}
	}
	assertCurrent(before)
	inboxKey, err := format.GeneratedResultKey(store.desc.Prefix, before.root.Domain, original.record.InboxID)
	if err != nil {
		t.Fatal("before-replacement original inbox key", err)
	}
	inbox := store.Read(ctx, inboxKey, uint32(len(original.result)))
	if inbox.Status != contract.ReadOK || !bytes.Equal(inbox.Body, original.result) {
		t.Fatal("before-replacement exact original inbox bytes")
	}
	admin, result := openAdministrative(ctx, OpenContext{admission: &before.admission}, store)
	if admin == nil || result.Outcome != ObservedCurrent || !reflect.DeepEqual(admin.adminIndex.Groups, before.adminIndex.Groups) {
		t.Fatal("before-replacement release did not administrative-open", result)
	}
	targetIndex := slices.IndexFunc(admin.adminIndex.Groups, func(group format.AdministrativeGroup) bool {
		return group.GroupID == released.release.InboxID && group.OwnerKind == format.AdministrativeInboxRelease
	})
	if targetIndex < 0 {
		t.Fatal("before-replacement exact release group")
	}
	target := admin.adminIndex.Groups[targetIndex]
	// The unchanged terminal failed Attempt and Pending release each contribute
	// their selected local fact to this one group's authenticated summary.
	const originalEvidence = contract.AdministrativeEvidenceTerminalFailure | contract.AdministrativeEvidenceReleasePending
	if target.OwnerKind != format.AdministrativeInboxRelease || target.GroupID != released.release.InboxID ||
		target.OwnerID != released.release.InboxID || target.TargetID != released.release.OriginalResultID ||
		target.SelectedEvidenceSummary != originalEvidence || len(target.RelatedGroupIndexes) != 0 {
		t.Fatalf("before-replacement release is not an independent exact administrative group: kind=%d group_matches=%t owner_matches=%t target_matches=%t evidence=%x related=%d",
			target.OwnerKind, target.GroupID == released.release.InboxID, target.OwnerID == released.release.InboxID,
			target.TargetID == released.release.OriginalResultID, target.SelectedEvidenceSummary, len(target.RelatedGroupIndexes))
	}
	public, private := env.Custody.Calls()
	candidate, prepared := prepareTestEndSelectedWork(t, admin, ctx, target.GroupID, env.Trust)
	if candidate == nil || prepared.Outcome != ObservedCurrent {
		t.Fatal("before-replacement release EndWork preparation", prepared)
	}
	if selected, result := admin.selectCandidate(ctx, candidate); selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("before-replacement release EndWork selection", result)
	}
	cold, result := Open(ctx, OpenContext{admission: &admin.admission}, store)
	if cold == nil || result.Outcome != ObservedCurrent || len(cold.adminIndex.Groups) != len(before.adminIndex.PublicationOrder) ||
		cold.root.Generated.PendingReleases != 0 || cold.root.Generated.Attempts != 0 ||
		cold.root.Generated.Graphs.Count != 0 || cold.root.Generated.LiveOwners.Count != 0 ||
		cold.root.Generated.Slices.Count != uint32(expectedGenerated) ||
		len(cold.root.Generated.Fragments) != intentFragments+1 || cold.root.WarningBits != 0x19 {
		// 0x19 is discarded exact evidence, orphan effect and possible Store
		// garbage. The extra mandatory fragment is the new receipt index.
		t.Fatal("before-replacement release exit did not cold-open with exact local loss", result)
	}
	for _, group := range before.adminIndex.Groups {
		if group.GroupID == target.GroupID {
			continue
		}
		if !slices.ContainsFunc(cold.adminIndex.Groups, func(after format.AdministrativeGroup) bool { return reflect.DeepEqual(group, after) }) {
			t.Fatal("release exit changed an unrelated publication group")
		}
	}
	if p, k := env.Custody.Calls(); p != public || k != private {
		t.Fatal("before-replacement exit used a public or private key route", p-public, k-private)
	}
	q := cold.head.EndWork
	if cold.head.AuthKind != format.AdministrativeAuth || q == nil || q.TargetGroupID != target.GroupID ||
		q.TargetOwnerID != target.OwnerID || q.TargetID != target.TargetID || q.TargetKind != target.OwnerKind ||
		q.SelectedEvidenceSummary != originalEvidence || q.DependentGroups.Count != 1 ||
		q.PredecessorRevisionID != before.head.Core.Revision || q.PredecessorFullHEADDigest != contract.Hash(before.body) ||
		q.PredecessorToken != before.token || q.BeforeAccessRoot != before.root.CurrentAccess.AccessRoot ||
		q.AfterAccessRoot != before.root.CurrentAccess.AccessRoot || q.BeforeWarningBits != 0 || q.AfterWarningBits != 0x19 ||
		q.BeforeChildCount != uint16(before.root.ChildCount) || q.AfterChildCount != uint16(cold.root.ChildCount) ||
		q.BeforeChildBytes != before.root.ChildEncodedBytes || q.AfterChildBytes != cold.root.ChildEncodedBytes {
		t.Fatal("before-replacement EndWork envelope lost its exact predecessor, target or preserved access")
	}
	afterWork, err := cold.selectedGeneratedWork(ctx)
	if err != nil || len(afterWork.releases) != 0 || len(afterWork.bundles) != 0 {
		t.Fatal("before-replacement EndWork retained the discarded release graph", err)
	}
	for key := range afterWork.records {
		if key.kind == contract.GeneratedAttemptSupportKind || key.kind == contract.PendingInboxReleaseSupportKind {
			t.Fatal("before-replacement EndWork retained discarded Attempt or release", key)
		}
	}
	receipt := assertEndWorkReceiptWindow(t, beforeWindows, cold)
	if receipt.OperationKind != contract.OperationEndSelectedWork || receipt.OperationID != q.OperationID ||
		receipt.StateResult != contract.ReceiptStateWorkEnded || receipt.EffectSummary != contract.ReceiptEffectNotApplicable ||
		receipt.CanonicalOutcome != contract.ReceiptCanonicalSelected || receipt.AdministrativeTargetKind != target.OwnerKind ||
		receipt.AdministrativeTargetID != target.TargetID || receipt.AdministrativeOriginalEvidence != originalEvidence ||
		receipt.WarningBits != 0x19 || receipt.AdministrativeWarningChanges != 0x19 ||
		receipt.PredecessorRevisionID != before.head.Core.Revision || receipt.ObservedRevisionID != cold.head.Core.Revision {
		t.Fatal("before-replacement EndWork receipt changed its local disposition")
	}
	assertCurrent(cold)
	afterInbox := store.Read(ctx, inboxKey, uint32(len(original.result)))
	if afterInbox.Status != contract.ReadOK || !bytes.Equal(afterInbox.Body, inbox.Body) || afterInbox.Token != inbox.Token {
		t.Fatal("local release EndWork changed the original remote-result inbox")
	}
	t.Logf("before replacement EndWork retained entries=%d intent_bytes=%d original_graph_bytes=%d before_fragments=%d after_fragments=%d before_children=%d after_children=%d",
		expectedGenerated, intentBytes, len(graphBody), intentFragments+graphFragments,
		len(cold.root.Generated.Fragments), before.root.ChildCount, cold.root.ChildCount)
}

// full_only: false
func TestSignedIndependentCurrentIntentsBeforeReplacementEndWork(t *testing.T) {
	ctx := t.Context()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	fixture := newNamedEnvironmentFixture(t, ctx, env, []int{1}, false, []string{"a-seed"})
	lifecycle := fixture.session
	storeB := selectedMemoryStoreCopy(env.Store.(*memoryStore))
	envB := env
	envB.Store = storeB
	envB.Custody = env.Custody.ForkGenerated(t)
	envB.Crypto = envB.Custody.Crypto()
	sourceB, result := Open(ctx, OpenContext{admission: &lifecycle.admission}, storeB)
	if sourceB == nil || result.Outcome != ObservedCurrent {
		t.Fatal("small release source B base", result)
	}
	filler := []ApplyEntryInput{
		{Name: "a-seed", Recipients: []contract.ID{sourceB.admission.recipient}, ValueSource: format.Supplied,
			ConfidentialityClass: format.Plain, InputBytes: []byte{0}},
		{Name: "b-filler", Recipients: []contract.ID{sourceB.admission.recipient}, ValueSource: format.Supplied,
			ConfidentialityClass: format.Plain, InputBytes: []byte{1}},
	}
	comparison, result := sourceB.Compare(ctx, filler, admitSuppliedComparison(t, sourceB, nil, filler))
	if comparison == nil || result.Outcome != ObservedCurrent {
		t.Fatal("small release source B filler comparison", result)
	}
	candidate, result := sourceB.Prepare(ctx, comparison, admit(t, sourceB, comparison), envB.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("small release source B filler preparation", result)
	}
	if result = sourceB.Select(ctx, candidate); result.Outcome != ObservedCurrent {
		t.Fatal("small release source B filler selection", result)
	}
	sourceB = generatedLifecycleReopen(t, ctx, sourceB, storeB)
	predecessor, original := signedCurrentIntentReleasePredecessor(t, ctx, env, lifecycle, "small before replacement")
	aSources, _ := generatedCurrentDeclaration(t, predecessor)
	selectedA := signedFullIntentSource(t, ctx, env, predecessor, fixtureID(env.Domain, "small release source A"),
		[]string{"alpha"}, aSources, []contract.ID{predecessor.admission.recipient}, custody.StandardValue, contract.OutputEncodingRaw, "small release source A", nil)
	bSources, _ := generatedCurrentDeclaration(t, sourceB)
	selectedB := signedFullIntentSource(t, ctx, envB, sourceB, fixtureID(env.Domain, "small release source B"),
		[]string{"omega"}, bSources, []contract.ID{sourceB.admission.recipient}, custody.StandardValue, contract.OutputEncodingRaw, "small release source B", nil)
	store, opened := signedCurrentIntentFixtureWithRelease(t, env, lifecycle, "small before replacement",
		original.record.AttemptID, selectedA, selectedB)
	configuredEnv := env
	configuredEnv.Store = store
	store, opened = signedCapacityConfiguration(t, configuredEnv, lifecycle, opened, "small release configured", false)
	assertSignedCurrentIntentReleaseExit(t, env, store, opened, selectedA, original, 2, []byte{0})
}

// full_only: false
func TestSignedIndependentCurrentIntentsColdOpen(t *testing.T) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	fixture := newNamedEnvironmentFixture(t, ctx, env, []int{1}, false, []string{"a-seed"})
	lifecycle := fixture.session
	// The combined image still reads this baseline after source history is pruned.
	baseline := *lifecycle
	baseline.store = selectedMemoryStoreCopy(env.Store.(*memoryStore))
	observationStore := &selectedBudgetObservationStore{memoryStore: selectedMemoryStoreCopy(env.Store.(*memoryStore))}
	observer, result := Open(ctx, OpenContext{admission: &lifecycle.admission}, observationStore)
	if observer == nil || result.Outcome != ObservedCurrent {
		t.Fatal("independent plain candidate predecessor", result)
	}
	plainChange := []ApplyEntryInput{{Name: "a-seed", Recipients: []contract.ID{observer.admission.recipient},
		ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputBytes: []byte("competing plain candidate")}}
	plainComparison, result := observer.Compare(ctx, plainChange, admitSuppliedComparison(t, observer, nil, plainChange))
	if plainComparison == nil || result.Outcome != ObservedCurrent {
		t.Fatal("independent plain candidate comparison", result)
	}
	plainCandidate, result := observer.Prepare(ctx, plainComparison, admit(t, observer, plainComparison), env.Trust)
	if plainCandidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("independent plain candidate preparation", result)
	}
	storeB := selectedMemoryStoreCopy(env.Store.(*memoryStore))
	envB := env
	envB.Store = storeB
	envB.Custody = env.Custody.ForkGenerated(t)
	envB.Crypto = envB.Custody.Crypto()
	sourceB, result := Open(ctx, OpenContext{admission: &lifecycle.admission}, storeB)
	if sourceB == nil || result.Outcome != ObservedCurrent {
		t.Fatal("independent source B base", result)
	}
	desired := []ApplyEntryInput{
		{Name: "a-seed", Recipients: []contract.ID{sourceB.admission.recipient}, ValueSource: format.Supplied,
			ConfidentialityClass: format.Plain, InputBytes: []byte{0}},
		{Name: "b-filler", Recipients: []contract.ID{sourceB.admission.recipient}, ValueSource: format.Supplied,
			ConfidentialityClass: format.Plain, InputBytes: []byte{1}},
	}
	comparison, result := sourceB.Compare(ctx, desired, admitSuppliedComparison(t, sourceB, nil, desired))
	if comparison == nil || result.Outcome != ObservedCurrent {
		t.Fatal("independent source B filler comparison", result)
	}
	candidate, result := sourceB.Prepare(ctx, comparison, admit(t, sourceB, comparison), envB.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("independent source B filler preparation", result)
	}
	if result = sourceB.Select(ctx, candidate); result.Outcome != ObservedCurrent {
		t.Fatal("independent source B filler selection", result)
	}
	sourceB, result = Open(ctx, OpenContext{admission: &sourceB.admission}, storeB)
	if sourceB == nil || result.Outcome != ObservedCurrent {
		t.Fatal("independent source B filler reopen", result)
	}
	env.FreshGeneratedRecord = func(t testing.TB, s *StateSession, attempt contract.ID, body []byte) *StateSession {
		return selectFreshGeneratedRecord(t, env.Store.(*memoryStore), s, attempt, body)
	}
	envB.FreshGeneratedRecord = func(t testing.TB, s *StateSession, attempt contract.ID, body []byte) *StateSession {
		return selectFreshGeneratedRecord(t, storeB, s, attempt, body)
	}
	aSources, _ := generatedCurrentDeclaration(t, lifecycle)
	aInput := generatedPlanInputForGenerationsIntent(t, lifecycle, generatedVectorID(238),
		[]string{"alpha"}, []byte(`{"name":"alpha independent intent"}`), defaultGeneratedFixtureProfile(), aSources...)
	selectedA := selectPrivateGeneratedOperation(t, env, lifecycle, aInput, "independent source alpha")
	selectedA = pruneCompletedIntentSourceStore(t, env, selectedA, generatedVectorID(238), []string{"alpha"})
	bSources, _ := generatedCurrentDeclaration(t, sourceB)
	bInput := generatedPlanInputForGenerationsIntent(t, sourceB, generatedVectorID(239),
		[]string{"omega"}, []byte(`{"name":"omega independent intent"}`), defaultGeneratedFixtureProfile(), bSources...)
	selectedB := selectPrivateGeneratedOperation(t, envB, sourceB, bInput, "independent source omega")
	selectedB = pruneCompletedIntentSourceStore(t, envB, selectedB, generatedVectorID(239), []string{"omega"})
	store, opened := signedCurrentIntentFixture(t, env, &baseline, "small multi-origin", selectedA, selectedB)
	currentBlob := fixtureID(env.Domain, "small multi-origin compact blob")
	currentFragments := slices.DeleteFunc(slices.Clone(opened.root.Generated.Fragments), func(location format.FragmentLocation) bool {
		return location.BlobID != currentBlob
	})
	if len(currentFragments) != 1 || len(opened.root.Generated.Fragments) != len(currentFragments)+int(receiptIndexFragmentCount(t, opened.root)) {
		t.Fatal("signed current image lost current or receipt-index fragments")
	}
	t.Run("file_backed_signed_image_cold_open", func(t *testing.T) {
		fileStore := selectedMemoryStoreCopy(env.Store.(*memoryStore))
		if err := fileStore.useFileBodies(filepath.Join(t.TempDir(), "bodies")); err != nil {
			t.Fatal("file-backed signed image", err)
		}
		fileEnv := env
		fileEnv.Store = fileStore
		fileImage, fileOpened := signedCurrentIntentFixture(t, fileEnv, &baseline,
			"small multi-origin file bodies", selectedA, selectedB)
		if fileOpened.root.Generated.GeneratedCurrent != opened.root.Generated.GeneratedCurrent ||
			fileImage.objects[fileImage.desc.HeadKey].Token != store.objects[store.desc.HeadKey].Token {
			t.Fatal("file-backed signed image changed selected semantics or HEAD token")
		}
	})
	t.Run("competing_observed_root_sets_its_own_read_allowance", func(t *testing.T) {
		var candidateRoot format.Root
		for _, object := range plainCandidate.objects {
			if object.ref == plainCandidate.head.Core.Root {
				var err error
				candidateRoot, err = format.DecodeRoot(object.body)
				if err != nil {
					t.Fatal("plain candidate Root", err)
				}
			}
		}
		if candidateRoot.Generated.Slices.Count != 0 || len(candidateRoot.Generated.Fragments) != int(receiptIndexFragmentCount(t, candidateRoot)) {
			t.Fatal("plain candidate carries fragments beyond its receipt index")
		}
		for key, value := range store.objects {
			if key != observationStore.desc.HeadKey {
				observationStore.objects[key] = stored{Body: bytes.Clone(value.Body), Token: value.Token}
			}
		}
		winner := store.objects[store.desc.HeadKey]
		beforeReads := observationStore.reads
		injected := false
		observationStore.casMode = "lost-after"
		observationStore.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
			if key != observationStore.desc.HeadKey || injected {
				return read
			}
			injected = true
			observationStore.put(key, winner.Body)
			value := observationStore.objects[key]
			return contract.ReadResult{Status: contract.ReadOK, Body: bytes.Clone(value.Body), Token: value.Token}
		}
		observed := observer.Select(ctx, plainCandidate)
		observationStore.readHook = nil
		reads, err := opened.selectedObservationExtraReads()
		if err != nil || !injected || observed.Outcome != UnresolvedCommit ||
			observed.ObservedRevision != opened.head.Core.Revision ||
			observationStore.observedLimit != headObservationLimit()+3*int(reads) ||
			observationStore.observedStages != 1 || observationStore.observedDeadline.IsZero() ||
			observationStore.deadlineChanged || observationStore.observedReads != observationStore.reads-beforeReads {
			t.Fatal("competing selected Root did not set the finite read allowance", observed, reads, err, observationStore.observedLimit)
		}
	})
	if opened.root.Generated.GeneratedCurrent != 2 || len(currentFragments) != 1 ||
		opened.root.Generated.Duties != 0 || len(opened.adminIndex.Groups) != 0 {
		t.Fatal("signed current intent image changed its closed shape")
	}
	t.Run("observed_image_has_finite_selected_read_allowance", func(t *testing.T) {
		if opened.root.ValueEntryCount != 3 || opened.root.Generated.Slices.Count != 2 {
			t.Fatal("small signed allowance fixture changed")
		}
		wantReads := uint64(1+receiptIndexFragmentCount(t, opened.root))*(2+3+2+5) + 1
		reads, err := opened.selectedObservationExtraReads()
		if err != nil || reads != wantReads {
			t.Fatal("signed selected image read allowance", reads, wantReads, err)
		}
		episode := &storeEpisode{}
		if !episode.beginStage(headObservationLimit()) {
			t.Fatal("observation stage did not start")
		}
		observedCtx := context.WithValue(ctx, storeEpisodeKey{}, episode)
		before := store.reads
		fresh, result := Open(observedCtx, OpenContext{admission: &opened.admission}, store)
		if fresh == nil || result.Outcome != ObservedCurrent || episode.stages != 1 ||
			episode.readLimit != headObservationLimit()+3*int(reads) || episode.stageReads != store.reads-before {
			t.Fatal("signed observation lost its finite stage", result, episode, store.reads-before)
		}
	})
	t.Run("orphan_slice_count_cannot_expand_the_read_allowance", func(t *testing.T) {
		malformed := *opened
		malformed.root = opened.root
		receiptOwners := opened.root.Generated.SuccessWindow.Count + opened.root.Generated.FailureWindow.Count
		malformed.root.Generated.Slices.Count = 2 + 3*(2+receiptOwners) + 1
		before := store.reads
		if _, err := malformed.selectedObservationExtraReads(); err == nil || store.reads != before {
			t.Fatal("orphan Slice count acquired a selected read allowance", err, store.reads-before)
		}
	})
	t.Run("exact_ref_fragment_read", func(t *testing.T) {
		location := currentFragments[0]
		fact, ok := opened.fragmentFacts[location]
		var matchingPage bool
		for _, page := range opened.supportFacts {
			if page.ref == fact.ref && int(location.RowSlot) < len(page.ordinals) &&
				page.ordinals[location.RowSlot] == fact.physical {
				matchingPage = true
			}
		}
		if !ok || !matchingPage {
			t.Fatal("selected fragment lost its authenticated physical row")
		}
		before := store.reads
		var payload []byte
		result, err := opened.withSelectedFragment(ctx, location, func(part []byte) error {
			payload = bytes.Clone(part)
			return nil
		})
		if err != nil || result.Outcome != 0 || store.reads != before+1 ||
			!bytes.Contains(payload, []byte("alpha independent intent")) ||
			!bytes.Contains(payload, []byte("omega independent intent")) {
			t.Fatal("exact selected fragment read", result, err)
		}
		content, err := newGeneratedContent(opened)
		if err != nil {
			t.Fatal("selected content source", err)
		}
		alpha := hermeticGeneratorIntent([]byte(`{"name":"alpha independent intent"}`))
		intentID, err := contract.GeneratorIntentDigest(hermeticGeneratorIntent(alpha))
		if err != nil {
			t.Fatal("alpha logical intent digest", err)
		}
		owned, err := content.readSelectedSlice(ctx, contract.GeneratorContentIntent, intentID, contract.GeneratorIntentMaxLength, opened.withSelectedFragment)
		if err != nil || !bytes.Equal(owned, alpha) {
			t.Fatal("selected logical intent read", err)
		}
		before = store.reads
		if result := opened.verifySelectedGeneratedSlices(ctx); result.Outcome != 0 || store.reads != before ||
			opened.generatedSlicesRoot.IsZero() || !slices.ContainsFunc(opened.generatedSliceLocations,
			func(row contract.GeneratorSliceLocation) bool {
				return row.ContentKind == contract.GeneratorContentIntent && row.ContentID == intentID
			}) {
			t.Fatal("streamed generated directory and slices", result)
		}
		key, err := format.Key(store.desc.Prefix, fact.ref)
		if err != nil {
			t.Fatal(err)
		}
		original := store.objects[key]
		changed := bytes.Clone(original.Body)
		changed[len(changed)-1] ^= 1
		store.put(key, changed)
		called := false
		result, err = opened.withSelectedFragment(ctx, location, func([]byte) error { called = true; return nil })
		store.objects[key] = original
		if err != nil || called || result.Outcome != IntegrityFailure || result.Reason != InvalidReference {
			t.Fatal("changed selected fragment bytes reached consumer", result, err)
		}
		store.readHook = func(readKey string, read contract.ReadResult) contract.ReadResult {
			if readKey == key {
				return contract.ReadResult{Status: contract.ReadMissing}
			}
			return read
		}
		result, err = opened.withSelectedFragment(ctx, location, func([]byte) error { called = true; return nil })
		store.readHook = nil
		if err != nil || called || result.Outcome != EvidenceUnavailable || result.Reason != MissingSelectedObject {
			t.Fatal("missing selected fragment was relabeled", result, err)
		}
		store.readHook = func(readKey string, read contract.ReadResult) contract.ReadResult {
			if readKey == key {
				return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
			}
			return read
		}
		result, err = opened.withSelectedFragment(ctx, location, func([]byte) error { called = true; return nil })
		store.readHook = nil
		if err != nil || called || result.Outcome != EvidenceUnavailable || result.Reason != ReadUnavailable ||
			result.StoreReason != contract.ReasonTransport {
			t.Fatal("uncertain selected fragment read was relabeled", result, err)
		}
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		before = store.reads
		result, err = opened.withSelectedFragment(cancelled, location, func([]byte) error { called = true; return nil })
		if err != nil || called || result.Outcome != EvidenceUnavailable || result.Reason != ReadUnavailable || store.reads != before {
			t.Fatal("cancelled selected fragment read entered Store", result, err)
		}
	})
	t.Run("releases_fragment_backing", func(t *testing.T) {
		var fragments, retained int
		for i, page := range opened.support {
			for _, row := range page.Records {
				if row.Kind != contract.GeneratedFragmentSupportKind {
					continue
				}
				fragments++
				retained += cap(row.Body)
				retained += cap(opened.cache[opened.root.RequiredSupport[i]])
			}
		}
		if fragments == 0 || retained != 0 {
			t.Fatalf("cold-open fragment ownership: fragments=%d retained backing=%d bytes", fragments, retained)
		}
	})
	t.Run("receipt_order_bound_to_exact_root", func(t *testing.T) {
		before := store.reads
		windows, found, err := opened.retainedSelectedReceiptWindows()
		if err != nil || !found || windows.DomainID != opened.root.Domain || store.reads != before {
			t.Fatal("complete Open did not retain its authenticated receipt order", err, found)
		}
		changed := *opened
		changed.root.Snapshot = fixtureID(opened.root.Domain, "other selected receipt root")
		if _, found, err := changed.retainedSelectedReceiptWindows(); found || err != nil || store.reads != before {
			t.Fatal("changed root reused predecessor receipt order", found, err)
		}
	})
	t.Run("late_selected_read_result", func(t *testing.T) {
		fact := opened.fragmentFacts[currentFragments[0]]
		key, err := format.Key(store.desc.Prefix, fact.ref)
		if err != nil {
			t.Fatal(err)
		}
		var cleanReads int
		store.readHook = func(readKey string, read contract.ReadResult) contract.ReadResult {
			if readKey == key {
				cleanReads++
			}
			return read
		}
		defer func() { store.readHook = nil }()
		// Measure the complete selected-image boundary independently of Open's
		// later generated relation reads, so the fault stays in that later stage.
		image, selectedResult := readCompleteSelectedImage(ctx, selectedObjectReader{
			domain: opened.root.Domain, descriptor: store.desc, source: store,
		}, opened.root, false)
		if selectedResult != (Result{}) || cleanReads == 0 ||
			!slices.Equal(image.generatedSliceLocations, opened.generatedSliceLocations) {
			t.Fatal("complete selected-image read did not establish the relation boundary", selectedResult, cleanReads)
		}
		selectedReads := cleanReads
		cleanReads = 0
		fresh, result := Open(ctx, OpenContext{admission: &opened.admission}, store)
		if fresh == nil || result.Outcome != ObservedCurrent ||
			cleanReads <= selectedReads {
			t.Fatal("clean Open did not reach generated relation reads", result, cleanReads, selectedReads)
		}
		for _, tc := range []struct {
			name, failure string
			want          Reason
			storeReason   contract.Reason
		}{
			{"missing", "missing", MissingSelectedObject, contract.ReasonNone},
			{"unavailable", "unavailable", ReadUnavailable, contract.ReasonTransport},
			{"cancelled", "cancelled", ReadUnavailable, contract.ReasonNone},
		} {
			t.Run(tc.name, func(t *testing.T) {
				callCtx, cancel := context.WithCancel(ctx)
				defer cancel()
				var reads int
				store.readHook = func(readKey string, read contract.ReadResult) contract.ReadResult {
					if readKey == key {
						reads++
						if reads == cleanReads || tc.failure == "unavailable" && reads > cleanReads {
							switch tc.failure {
							case "missing":
								return contract.ReadResult{Status: contract.ReadMissing}
							case "unavailable":
								return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
							case "cancelled":
								cancel()
							}
						}
					}
					return read
				}
				missing, result := Open(callCtx, OpenContext{admission: &opened.admission}, store)
				if missing != nil || result.Outcome != EvidenceUnavailable || result.Reason != tc.want ||
					result.StoreReason != tc.storeReason || reads < cleanReads || tc.failure != "unavailable" && reads != cleanReads {
					t.Fatal("late selected read lost its Store result", result, reads, cleanReads)
				}
			})
		}
	})
	seen := make(map[contract.ID]bool)
	work, err := opened.selectedGeneratedWork(ctx)
	if err != nil {
		t.Fatal("signed current intent selected work", err)
	}
	for _, named := range opened.root.Names {
		entry := opened.valueEntry(named.Slot)
		if entry.ValueSource != contract.Generated {
			continue
		}
		if seen[entry.Generated.OriginOperationID] {
			t.Fatal("signed current intent origins were not independent", named.Name)
		}
		seen[entry.Generated.OriginOperationID] = true
		intent, err := work.readSelectedSlice(ctx, contract.GeneratorContentIntent, entry.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
		if err != nil || !bytes.Contains(intent, []byte(named.Name)) {
			t.Fatal("signed current intent bytes", named.Name, err)
		}
		selection := sessionConsumerSelection(t, opened, opened.admission.recipient, named.Name)
		check := env.Custody.Consume(ctx, selection, custody.StandardValue)
		if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
			t.Fatal("independent source value did not survive private consumption", named.Name, check)
		}
	}
	if fresh, result := Open(ctx, OpenContext{admission: &opened.admission}, store); fresh == nil || result.Outcome != ObservedCurrent {
		t.Fatal("second fresh complete Open", result)
	}
	t.Run("whole_set_replacement_admission", func(t *testing.T) {
		names := []string{"alpha", "omega"}
		retiring := make(map[string]contract.ValueEntry, len(names))
		incarnations := make(map[string]contract.ID, len(names))
		for _, named := range opened.root.Names {
			if !slices.Contains(names, named.Name) {
				continue
			}
			entry := opened.valueEntry(named.Slot)
			if entry == nil || entry.ValueSource != contract.Generated {
				t.Fatal("replacement predecessor lacks generated value", named.Name)
			}
			retiring[named.Name], incarnations[named.Name] = *entry, entry.Incarnation
		}
		if len(retiring) != len(names) {
			t.Fatal("replacement predecessor omitted a current generated value")
		}
		operation := fixtureID(opened.root.Domain, "two-origin whole-set replacement")
		profile := defaultGeneratedFixtureProfile()
		input := generatedStatePlanInput(t, opened, operation, names, profile, 2, incarnations, retiring)
		bound := generatedReservationInputForMembershipStateIntents(t, opened, operation,
			[]contract.ID{opened.admission.recipient}, names,
			func(name string) []byte {
				return hermeticGeneratorIntent([]byte(`{"name":"replacement-` + name + `"}`))
			},
			profile, 2, incarnations, retiring)
		input.graph, input.declaration = bound.graph, bound.declaration
		input.registry, input.recoveryPolicy = bound.graph.Request.Registry, bound.graph.Request.RecoveryPolicyID
		input.requestBindings = slices.Clone(bound.requestBindings)
		plan, err := opened.generatedPlanRequest(ctx, input)
		if err != nil || plan == nil || opened.prepared {
			t.Fatal("valid two-origin replacement did not pass public admission", err)
		}
		if plan.capacity.Groups[contract.GeneratorCapacityIntents].MaxCount == 0 {
			t.Fatal("replacement did not charge selected old and new intent fragments")
		}
		successorEnv := env
		successorEnv.Store = store
		replaced := selectTwoNameCurrentGeneration(t, ctx, successorEnv, opened, input, "two-origin whole-set replacement")
		t.Run("signed_family_refusal_does_not_publish_relation_facts", func(t *testing.T) {
			badStore := selectedMemoryStoreCopy(store)
			badHead := replaced.head
			subject := *badHead.Generator
			subject.IdentityPlan.Digest[0] ^= 1
			badHead.Generator = &subject
			request, err := contract.NewGeneratorRequest(subject)
			if err != nil {
				t.Fatal("changed signed subject is malformed", err)
			}
			proof := env.Trust.Sign(ctx, request)
			if proof.Reason != contract.ReasonNone {
				t.Fatal("changed subject could not be signed", proof.Reason)
			}
			badHead.AuthorizationSignature = proof.Signature
			badBody, err := format.EncodeHead(badHead)
			if err != nil {
				t.Fatal("changed signed HEAD", err)
			}
			badStore.put(badStore.desc.HeadKey, badBody)
			beforeCreates, beforeCAS := badStore.creates, badStore.cas
			bad, observed := Open(ctx, OpenContext{admission: &replaced.admission}, badStore)
			if bad != nil || observed.Outcome != IntegrityFailure || observed.Reason != InvalidProof ||
				badStore.creates != beforeCreates || badStore.cas != beforeCAS {
				t.Fatal("signed family mismatch escaped complete proof refusal", observed)
			}
			probe := *replaced
			probe.store, probe.head, probe.body = badStore, badHead, badBody
			probe.generatedWork, probe.generatedGraphs = nil, nil
			relation, err := probe.validateRelationsMode(ctx, false)
			if err != nil || relation == nil {
				t.Fatal("family mismatch did not reach complete relation facts", err)
			}
			if probe.generatedWork != nil || probe.generatedGraphs != nil {
				t.Fatal("relation facts published before independent signed proof")
			}
			if err := probe.validateGeneratedSelection(ctx, relation); !errors.Is(err, contract.ErrRecord) ||
				probe.generatedWork != nil || probe.generatedGraphs != nil {
				t.Fatal("failed signed family proof published relation facts", err)
			}
		})
		if replaced.root.Generated.GeneratedCurrent != 2 || replaced.root.Generated.Duties < 2 {
			t.Fatal("whole-set replacement lost current values or retirement duties")
		}
		admin, observed := openAdministrative(ctx, OpenContext{admission: &replaced.admission}, store)
		if admin == nil || observed.Outcome != ObservedCurrent {
			t.Fatal("whole-set replacement did not reopen for administrative exit", observed)
		}
		oldResources := make(map[contract.ID]bool, len(retiring))
		for _, entry := range retiring {
			oldResources[entry.Generated.ResourceIncarnationID] = true
		}
		oldGroups := make(map[contract.ID]bool, len(retiring))
		for _, group := range admin.adminIndex.Groups {
			if group.OwnerKind == format.AdministrativeGeneratedDuty && group.DutyKind == contract.GeneratedDutyRetirement &&
				oldResources[group.TargetID] {
				oldGroups[group.GroupID] = true
			}
		}
		if len(oldGroups) != len(retiring) {
			t.Fatal("whole-set replacement lacks exact old retirement owners", len(oldGroups))
		}
		assertCurrent := func(s *StateSession) {
			t.Helper()
			if s.root.Generated.GeneratedCurrent != 2 || len(s.root.Names) != 2 {
				t.Fatal("administrative exit changed the new current set")
			}
			for _, name := range names {
				var entry *format.ValueEntry
				for _, named := range s.root.Names {
					if named.Name == name {
						entry = s.valueEntry(named.Slot)
					}
				}
				wantIntent, err := contract.GeneratorIntentDigest(hermeticGeneratorIntent([]byte(`{"name":"replacement-` + name + `"}`)))
				if err != nil || entry == nil || entry.ValueSource != contract.Generated ||
					entry.Generated.Epoch != 2 || entry.Generated.IntentDigest != wantIntent {
					t.Fatal("administrative exit changed a replacement value", name, err)
				}
				check := env.Custody.Consume(ctx, sessionConsumerSelection(t, s, s.admission.recipient, name), custody.StandardValue)
				if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
					t.Fatal("replacement value was not privately readable after exit", name, check)
				}
			}
		}
		var target contract.ID
		for _, group := range admin.adminIndex.Groups {
			if !oldGroups[group.GroupID] {
				continue
			}
			remaining, scope, err := admin.administrativeWorkClosure(group.GroupID)
			if err == nil && len(scope) == 1 && len(remaining.Groups) != 0 {
				target = group.GroupID
				break
			}
		}
		if target.IsZero() {
			t.Fatal("whole-set replacement has no independent old retirement exit")
		}
		beforeWindows, err := admin.receiptWindowsFromAdministrativeSupport()
		if err != nil {
			t.Fatal("first old retirement receipt window", err)
		}
		candidate, prepared := prepareTestEndSelectedWork(t, admin, ctx, target, env.Trust)
		if candidate == nil || prepared.Outcome != ObservedCurrent {
			t.Fatal("whole-set replacement could not prepare its first old retirement exit", prepared)
		}
		if next, selected := admin.selectCandidate(ctx, candidate); next == nil || selected.Outcome != ObservedCurrent {
			t.Fatal("whole-set replacement could not select its first old retirement exit", selected)
		}
		cold, result := Open(ctx, OpenContext{admission: &admin.admission}, store)
		if cold == nil || result.Outcome != ObservedCurrent || cold.root.Generated.GeneratedCurrent != 2 ||
			len(cold.adminIndex.Groups) != len(admin.adminIndex.Groups)-1 {
			t.Fatal("old retirement exit did not preserve the two new current values and other owner", result)
		}
		if cold.root.WarningBits&admin.root.WarningBits != admin.root.WarningBits {
			t.Fatal("first exit cleared a permanent warning")
		}
		for _, group := range admin.adminIndex.Groups {
			if (group.GroupID == target) == slices.ContainsFunc(cold.adminIndex.Groups,
				func(remaining format.AdministrativeGroup) bool { return remaining.GroupID == group.GroupID }) {
				t.Fatal("first exit changed an unrelated owner", group.GroupID)
			}
		}
		assertCurrent(cold)
		assertEndWorkReceiptWindow(t, beforeWindows, cold)
		firstOperation := cold.head.EndWork.OperationID
		firstReceipt, result := cold.MutationReceipt(ctx, firstOperation)
		if result.Outcome != ObservedCurrent || len(firstReceipt) == 0 {
			t.Fatal("first exit receipt was not selected", result)
		}
		remaining, result := openAdministrative(ctx, OpenContext{admission: &cold.admission}, store)
		if remaining == nil || result.Outcome != ObservedCurrent {
			t.Fatal("remaining old retirement did not reopen", result)
		}
		var second contract.ID
		for _, group := range remaining.adminIndex.Groups {
			if oldGroups[group.GroupID] {
				second = group.GroupID
			}
		}
		if second.IsZero() || second == target {
			t.Fatal("first exit removed the independent second old retirement")
		}
		secondBeforeWindows, err := remaining.receiptWindowsFromAdministrativeSupport()
		if err != nil {
			t.Fatal("second old retirement receipt window", err)
		}
		secondCandidate, prepared := prepareTestEndSelectedWork(t, remaining, ctx, second, env.Trust)
		if secondCandidate == nil || prepared.Outcome != ObservedCurrent {
			t.Fatal("second old retirement exit could not prepare", prepared)
		}
		if next, selected := remaining.selectCandidate(ctx, secondCandidate); next == nil || selected.Outcome != ObservedCurrent {
			t.Fatal("second old retirement exit could not select", selected)
		}
		final, result := Open(ctx, OpenContext{admission: &remaining.admission}, store)
		if final == nil || result.Outcome != ObservedCurrent ||
			len(final.adminIndex.Groups) != len(remaining.adminIndex.Groups)-1 ||
			final.root.WarningBits&cold.root.WarningBits != cold.root.WarningBits {
			t.Fatal("second exit changed unrelated owners or cleared warnings", result)
		}
		for _, group := range final.adminIndex.Groups {
			if oldGroups[group.GroupID] {
				t.Fatal("an ended old retirement owner returned", group.GroupID)
			}
		}
		assertCurrent(final)
		assertEndWorkReceiptWindow(t, secondBeforeWindows, final)
		retainedReceipt, result := final.MutationReceipt(ctx, firstOperation)
		if result.Outcome != ObservedCurrent || !bytes.Equal(retainedReceipt, firstReceipt) {
			t.Fatal("second exit changed the first signed receipt", result)
		}
	})
}

// The small two-value fixture keeps its old current intents in one fragment.
// This fixture crosses a fragment page boundary while two independent source
// operations and a complete replacement still fit in a short focused test.
// full_only: false
func TestSignedSharedFragmentCurrentIntentsFirstExitColdOpen(t *testing.T) {
	ctx := t.Context()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	fixture := newNamedEnvironmentFixture(t, ctx, env, []int{1}, false, []string{"a-seed"})
	before := fixture.session
	storeB := selectedMemoryStoreCopy(env.Store.(*memoryStore))
	envB := env
	envB.Store = storeB
	envB.Custody = env.Custody.ForkGenerated(t)
	envB.Crypto = envB.Custody.Crypto()
	sourceB, result := Open(ctx, OpenContext{admission: &before.admission}, storeB)
	if sourceB == nil || result.Outcome != ObservedCurrent {
		t.Fatal("second source base", result)
	}
	const perOrigin = 4
	filler := []ApplyEntryInput{{Name: "a-seed", Recipients: []contract.ID{sourceB.admission.recipient},
		ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputBytes: []byte{0},
		InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}}
	var alpha, omega []string
	for i := 0; i < perOrigin; i++ {
		filler = append(filler, ApplyEntryInput{Name: fmt.Sprintf("b-filler-%d", i),
			Recipients: []contract.ID{sourceB.admission.recipient}, ValueSource: format.Supplied,
			ConfidentialityClass: format.Plain, InputBytes: []byte{byte(i)}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
		alpha = append(alpha, fmt.Sprintf("alpha-%d", i))
		omega = append(omega, fmt.Sprintf("omega-%d", i))
	}
	comparison, result := sourceB.Compare(ctx, filler, admitSuppliedComparison(t, sourceB, nil, filler))
	if comparison == nil || result.Outcome != ObservedCurrent {
		t.Fatal("second source filler comparison", result)
	}
	candidate, result := sourceB.Prepare(ctx, comparison, admit(t, sourceB, comparison), envB.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("second source filler preparation", result)
	}
	if result = sourceB.Select(ctx, candidate); result.Outcome != ObservedCurrent {
		t.Fatal("second source filler selection", result)
	}
	sourceB, result = Open(ctx, OpenContext{admission: &sourceB.admission}, storeB)
	if sourceB == nil || result.Outcome != ObservedCurrent {
		t.Fatal("second source filler reopen", result)
	}
	aSources, _ := generatedCurrentDeclaration(t, before)
	operationA := fixtureID(env.Domain, "shared-page source A")
	selectedA := signedFullIntentSource(t, ctx, env, before, operationA, alpha, aSources, []contract.ID{before.admission.recipient}, custody.StandardValue, contract.OutputEncodingRaw, "shared-page source A", nil)
	bSources, _ := generatedCurrentDeclaration(t, sourceB)
	operationB := fixtureID(env.Domain, "shared-page source B")
	selectedB := signedFullIntentSource(t, ctx, envB, sourceB, operationB, omega, bSources, []contract.ID{sourceB.admission.recipient}, custody.StandardValue, contract.OutputEncodingRaw, "shared-page source B", nil)
	store, opened := signedCurrentIntentFixture(t, env, before, "shared-page current intents", selectedA, selectedB)
	currentBlob := fixtureID(env.Domain, "shared-page current intents compact blob")
	fragments := slices.DeleteFunc(slices.Clone(opened.root.Generated.Fragments), func(location format.FragmentLocation) bool {
		return location.BlobID != currentBlob
	})
	if len(opened.root.Generated.Fragments) != len(fragments)+int(receiptIndexFragmentCount(t, opened.root)) {
		t.Fatal("shared current image lost current or receipt-index fragments")
	}
	pageSlots := make(map[uint16]uint8)
	for i, fragment := range fragments {
		if i > 0 && fragment.BlobID != fragments[0].BlobID || fragment.FragmentIndex != uint16(i) || fragment.RowSlot > 1 {
			t.Fatal("old current intent fragment identity or order", i, fragment)
		}
		pageSlots[fragment.SupportPageIndex] |= 1 << fragment.RowSlot
	}
	if opened.root.Generated.GeneratedCurrent != 2*perOrigin || len(fragments) != 4 ||
		len(pageSlots) != 2 {
		t.Fatal("old current intents did not span two packed fragment pages",
			opened.root.Generated.GeneratedCurrent, len(fragments), pageSlots)
	}
	for page, slots := range pageSlots {
		if slots != 3 {
			t.Fatal("old current intent page did not hold two physical fragment rows", page, slots)
		}
	}
	names := append(slices.Clone(alpha), omega...)
	retiring := make(map[string]contract.ValueEntry, len(names))
	incarnations := make(map[string]contract.ID, len(names))
	for _, named := range opened.root.Names {
		entry := opened.valueEntry(named.Slot)
		if entry != nil && entry.ValueSource == contract.Generated {
			retiring[named.Name], incarnations[named.Name] = *entry, entry.Incarnation
		}
	}
	if len(retiring) != len(names) {
		t.Fatal("replacement predecessor lost a current generated value")
	}
	t.Run("reconstruct shared intents", func(t *testing.T) {
		projection := reconstructProjectionFixture(t, env, opened, store)
		for _, name := range names {
			intent, err := projection.CopyGeneratedIntent(t.Context(), retiring[name].Generated.IntentDigest)
			if err != nil || !bytes.Equal(intent, hermeticSizedGeneratorIntent(name, 0x5a, 384<<10)) {
				t.Fatal("reconstruction lost a current intent from the shared blob", name, err)
			}
		}
	})
	operation := fixtureID(env.Domain, "shared-page whole-set replacement")
	profile := defaultGeneratedFixtureProfile()
	replacementIntent := func(name string) []byte {
		intent := hermeticSizedGeneratorIntent("replacement-"+name, 0x4c, 384<<10)
		return intent
	}
	input := generatedStatePlanInput(t, opened, operation, names, profile, 2, incarnations, retiring)
	bound := generatedReservationInputForMembershipStateIntents(t, opened, operation,
		[]contract.ID{opened.admission.recipient}, names, replacementIntent,
		profile, 2, incarnations, retiring)
	input.graph, input.declaration = bound.graph, bound.declaration
	input.registry, input.recoveryPolicy = bound.graph.Request.Registry, bound.graph.Request.RecoveryPolicyID
	input.requestBindings = slices.Clone(bound.requestBindings)
	successorEnv := env
	successorEnv.Store = store
	reservation, _ := preparePrivateGeneratedReservation(t, successorEnv, opened, input, nil)
	current, originals := sendParallelOriginals(t, ctx, successorEnv, opened, reservation, custody.StandardValue)
	if len(originals) != len(names) {
		t.Fatal("replacement omitted an original", len(originals))
	}
	for i, original := range originals {
		recordContext := generatedPlanInputFixture(t, current).context
		recordContext.AdmissionID = fixtureID(env.Domain, fmt.Sprintf("shared-page record admission %d", i))
		recordContext.SessionID = fixtureID(env.Domain, fmt.Sprintf("shared-page record session %d", i))
		recordContext.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
		record, err := current.generatedRecordRequest(context.Background(), original.expected.Template.AttemptID, original.result, recordContext)
		if err != nil {
			t.Fatal("replacement Record request", i, err)
		}
		prepared := preparePrivateGeneratedRecord(t, successorEnv, current, record)
		current, result = current.selectCandidate(ctx, prepared.reservation.candidate)
		if current == nil || result.Outcome != ObservedCurrent {
			t.Fatal("replacement Record selection", i, result)
		}
		env.Custody.RetireGenerated()
	}
	finalContext := generatedPlanInputFixture(t, current).context
	finalContext.AdmissionID = fixtureID(env.Domain, "shared-page final admission")
	finalContext.SessionID = fixtureID(env.Domain, "shared-page final session")
	finalContext.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
	finalPlan, err := current.generatedFinalRequest(ctx, finalContext)
	if err != nil || finalPlan == nil || len(finalPlan.entryPlans) != len(names) {
		t.Fatal("replacement Final request", err)
	}
	current, final := preparePrivateGeneratedFinal(t, successorEnv, current, finalPlan)
	replaced, result := current.selectCandidate(ctx, final.reservation.candidate)
	if replaced == nil || result.Outcome != ObservedCurrent {
		t.Fatal("replacement Final selection", result)
	}
	env.Custody.RetireGenerated()
	replaced = generatedLifecycleReopen(t, ctx, replaced, store)
	t.Run("cold_current_intent_plan", func(t *testing.T) {
		plan, err := replaced.planAdministrativeCurrentIntents(ctx, replaced.adminIndex)
		if err != nil || len(plan.intents) != len(names) || len(plan.before) == 0 {
			t.Fatal("cold current-intent plan refused authenticated selected facts", err)
		}
	})
	t.Run("cold_current_intents_use_authenticated_facts", func(t *testing.T) {
		if len(replaced.fragmentFacts) == 0 {
			t.Fatal("cold replacement has no selected fragment facts")
		}
		for _, page := range replaced.support {
			for _, row := range page.Records {
				if row.Kind == contract.GeneratedFragmentSupportKind && row.Body != nil {
					t.Fatal("cold replacement retained a fragment body")
				}
			}
		}
		selected, err := replaced.administrativeCurrentIntentSelection(ctx)
		if err != nil || selected == nil || selected.content == nil || len(selected.content.fragments) != 0 {
			t.Fatal("cold current-intent selection", err)
		}
		checked := 0
		for _, named := range replaced.root.Names {
			entry := replaced.valueEntry(named.Slot)
			if entry == nil || entry.ValueSource != contract.Generated || !slices.Contains(names, named.Name) {
				continue
			}
			actual, readErr := selected.readSelectedSlice(ctx, contract.GeneratorContentIntent,
				entry.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
			if readErr != nil || !bytes.Equal(actual, replacementIntent(named.Name)) {
				t.Fatal("cold selected intent changed", named.Name, readErr)
			}
			checked++
		}
		if checked != len(names) {
			t.Fatal("cold selected current-intent count", checked, len(names))
		}
		var location format.FragmentLocation
		for _, refs := range selected.content.fragmentLocations {
			if len(refs) != 0 {
				location = refs[0]
				break
			}
		}
		fact, found := replaced.fragmentFacts[location]
		position, positioned := replaced.selectedSupportPosition(fact.ref)
		if !found || !positioned {
			t.Fatal("cold current intent lacks an exact selected Ref")
		}
		beforeReads := store.reads
		rows, err := replaced.administrativeSelectedRows(replaced.adminIndex.Pages[position])
		if err != nil || store.reads != beforeReads {
			t.Fatal("fact summary read a fragment body", err)
		}
		fragmentID, err := contract.GeneratorFragmentID(location.BlobID, location.FragmentIndex)
		if err != nil {
			t.Fatal(err)
		}
		matched := 0
		for _, row := range rows {
			if row.summary.Kind == contract.GeneratedFragmentSupportKind && row.summary.RecordID == fragmentID {
				if row.blob != location.BlobID || row.physical != fact.physical ||
					row.summary.BodyLength != fact.row.BodyLength() {
					t.Fatal("fact summary lost physical fragment identity")
				}
				matched++
			}
		}
		if matched != 1 {
			t.Fatal("fragment fact was not unique", matched)
		}
		key, err := format.Key(store.desc.Prefix, fact.ref)
		if err != nil {
			t.Fatal(err)
		}
		beforeCreates, beforeCAS := store.creates, store.cas
		readAttempts := 0
		store.readHook = func(readKey string, read contract.ReadResult) contract.ReadResult {
			if readKey == key {
				readAttempts++
				return contract.ReadResult{Status: contract.ReadMissing}
			}
			return read
		}
		_, err = replaced.administrativeCurrentIntentSelection(ctx)
		store.readHook = nil
		result, typed := selectedReadResult(err)
		if !typed || result.Outcome != EvidenceUnavailable || result.Reason != MissingSelectedObject ||
			readAttempts == 0 || store.creates != beforeCreates || store.cas != beforeCAS {
			t.Fatal("missing exact fragment lost typed refusal", result, typed, readAttempts, err)
		}
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		beforeReads = store.reads
		_, err = replaced.administrativeCurrentIntentSelection(cancelled)
		result, typed = selectedReadResult(err)
		if !typed || result.Outcome != EvidenceUnavailable || result.Reason != ReadUnavailable ||
			store.reads != beforeReads || store.creates != beforeCreates || store.cas != beforeCAS {
			t.Fatal("cancelled selection lost typed refusal", result, typed, err)
		}
	})
	admin, result := openAdministrative(ctx, OpenContext{admission: &replaced.admission}, store)
	if admin == nil || result.Outcome != ObservedCurrent {
		t.Fatal("replacement administrative reopen", result)
	}
	oldResources := make(map[contract.ID]bool, len(retiring))
	oldIntents := make(map[contract.ID]contract.ID, len(retiring))
	for _, entry := range retiring {
		oldResources[entry.Generated.ResourceIncarnationID] = true
		oldIntents[entry.Generated.ResourceIncarnationID] = entry.Generated.IntentDigest
	}
	var target contract.ID
	var targetIntent contract.ID
	for _, group := range admin.adminIndex.Groups {
		if group.OwnerKind != format.AdministrativeGeneratedDuty || group.DutyKind != contract.GeneratedDutyRetirement ||
			!oldResources[group.TargetID] {
			continue
		}
		remaining, scope, err := admin.administrativeWorkClosure(group.GroupID)
		if err == nil && len(scope) == 1 && len(remaining.Groups) == len(admin.adminIndex.Groups)-1 {
			target = group.GroupID
			targetIntent = oldIntents[group.TargetID]
			break
		}
	}
	if target.IsZero() || targetIntent.IsZero() {
		t.Fatal("replacement has no independent old retirement exit")
	}
	t.Run("ended_old_intent_has_only_duty_ownership", func(t *testing.T) {
		currentIntents := make(map[contract.ID]bool, len(admin.root.Names))
		for _, named := range admin.root.Names {
			entry := admin.valueEntry(named.Slot)
			if entry == nil || entry.ValueSource != contract.Generated {
				t.Fatal("replacement current entry is not generated", named.Name)
			}
			currentIntents[entry.Generated.IntentDigest] = true
		}
		oldOwners := make(map[contract.ID]contract.ID, len(retiring))
		for _, group := range admin.adminIndex.Groups {
			if group.OwnerKind == format.AdministrativeGeneratedDuty && group.DutyKind == contract.GeneratedDutyRetirement &&
				oldResources[group.TargetID] {
				oldOwners[oldIntents[group.TargetID]] = group.GroupID
			}
		}
		if len(currentIntents) != len(names) || len(oldOwners) != len(retiring) || currentIntents[targetIntent] {
			t.Fatal("replacement does not have distinct old and current Intent owners")
		}
		type oldSlice struct {
			location  contract.GeneratorSliceLocation
			mandatory bool
		}
		var oldSlices []oldSlice
		currentCount, receiptCount := 0, 0
		for pageIndex, page := range admin.adminIndex.Pages {
			if !page.ReadRequired {
				logical := 0
				for _, span := range page.Spans {
					for offset := uint16(0); offset < span.Count; offset++ {
						if logical >= len(page.Rows) {
							t.Fatal("selected receipt span exceeds its page")
						}
						if page.Rows[logical].Kind == contract.MutationReceiptSupportKind {
							receiptCount++
							if !span.Mandatory {
								t.Fatal("selected receipt lost mandatory ownership")
							}
						}
						logical++
					}
				}
				continue
			}
			logical := 0
			for _, span := range page.Spans {
				for offset := uint16(0); offset < span.Count; offset++ {
					if logical >= len(admin.support[pageIndex].Records) {
						t.Fatal("selected Slice carrier span exceeds its page")
					}
					row := admin.support[pageIndex].Records[logical]
					logical++
					carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
					if row.Kind != contract.GeneratorVectorSupportKind || err != nil || carrier.VectorKind != contract.GeneratorVectorSlices {
						t.Fatal("read-required page did not contain a Slice carrier", err)
					}
					location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
					if err != nil {
						t.Fatal("selected Slice carrier", err)
					}
					if location.ContentKind != contract.GeneratorContentIntent {
						continue
					}
					if currentIntents[location.ContentID] {
						currentCount++
						if !span.Mandatory {
							t.Fatal("current replacement Intent Slice lost mandatory ownership")
						}
						continue
					}
					owner, old := oldOwners[location.ContentID]
					if !old || len(span.GroupIndexes) != 1 || admin.adminIndex.Groups[span.GroupIndexes[0]].GroupID != owner {
						t.Fatal("old Intent Slice lost its exact retirement owner")
					}
					oldSlices = append(oldSlices, oldSlice{location: location, mandatory: span.Mandatory})
				}
			}
			if logical != len(admin.support[pageIndex].Records) {
				t.Fatal("selected Slice carrier span did not cover its page")
			}
		}
		wantReceiptRows := int(admin.root.Generated.SuccessWindow.Count + admin.root.Generated.FailureWindow.Count)
		if currentCount != len(names) || receiptCount != wantReceiptRows || len(oldSlices) != len(retiring) {
			t.Fatal("selected index lost current intents, receipts, or old Duty Intents",
				currentCount, receiptCount, len(oldSlices))
		}
		var targetSlice *oldSlice
		for i := range oldSlices {
			if oldSlices[i].location.ContentID == targetIntent {
				targetSlice = &oldSlices[i]
			}
		}
		if targetSlice == nil {
			t.Fatal("ended Duty Intent Slice was not selected")
		}
		sharedSurvivors := 0
		for _, old := range oldSlices {
			if old.location.ContentID != targetIntent && old.location.BlobID == targetSlice.location.BlobID {
				sharedSurvivors++
			}
		}
		if sharedSurvivors == 0 {
			t.Fatal("ended Duty Intent blob has no surviving Duty consumer")
		}
		if targetSlice.mandatory {
			t.Fatal("ended Duty Intent Slice remained mandatory after whole-set replacement")
		}
		for _, old := range oldSlices {
			if old.location.ContentID != targetIntent && old.location.BlobID == targetSlice.location.BlobID && old.mandatory {
				t.Fatal("surviving Duty Intent Slice remained mandatory after whole-set replacement")
			}
		}
	})
	work, _, err := admin.administrativeWorkClosure(target)
	if err != nil {
		t.Fatal("first exit selected work", err)
	}
	work, err = admin.administrativeWorkWithoutOldReceipts(work)
	if err != nil {
		t.Fatal("first exit prior receipts", err)
	}
	intentPlan, err := admin.planAdministrativeCurrentIntents(ctx, work)
	if err != nil || !intentPlan.changed || !intentPlan.emit || intentPlan.fragments != 4 {
		t.Fatal("first exit did not compact the new current intents across two pages", err,
			intentPlan.changed, intentPlan.emit, intentPlan.fragments)
	}
	t.Logf("first exit old fragments=%d compact fragments=%d index shards=%d drop blobs=%d",
		len(admin.root.Generated.Fragments), intentPlan.fragments, len(admin.root.AdministrativeIndexShards)+1,
		len(intentPlan.dropBlobs))
	beforeWindows, err := admin.receiptWindowsFromAdministrativeSupport()
	if err != nil {
		t.Fatal("shared current first exit receipt window", err)
	}
	exit, result := prepareTestEndSelectedWork(t, admin, ctx, target, env.Trust)
	if exit == nil || result.Outcome != ObservedCurrent {
		t.Fatal("first old retirement exit preparation", result)
	}
	if next, observed := admin.selectCandidate(ctx, exit); next == nil || observed.Outcome != ObservedCurrent {
		t.Fatal("first old retirement exit selection", observed)
	}
	cold, result := Open(ctx, OpenContext{admission: &admin.admission}, store)
	if cold == nil || result.Outcome != ObservedCurrent || cold.root.Generated.GeneratedCurrent != 2*perOrigin ||
		len(cold.adminIndex.Groups) != len(admin.adminIndex.Groups)-1 {
		t.Fatal("first old retirement exit did not cold-open with shared fragment pages", result)
	}
	if cold.root.WarningBits&admin.root.WarningBits != admin.root.WarningBits {
		t.Fatal("first old retirement exit cleared a permanent warning")
	}
	assertEndWorkReceiptWindow(t, beforeWindows, cold)
	selected, err := cold.selectedGeneratedWork(ctx)
	if err != nil {
		t.Fatal("first old retirement exit lost selected generated work", err)
	}
	for _, name := range names {
		var entry *format.ValueEntry
		for _, named := range cold.root.Names {
			if named.Name == name {
				entry = cold.valueEntry(named.Slot)
				break
			}
		}
		if entry == nil || entry.ValueSource != contract.Generated || entry.Generated.Epoch != 2 {
			t.Fatal("first old retirement exit changed a new current entry", name)
		}
		actual, err := selected.readSelectedSlice(ctx, contract.GeneratorContentIntent,
			entry.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
		if err != nil || !bytes.Equal(actual, replacementIntent(name)) {
			t.Fatal("first old retirement exit changed a new current intent", name, err)
		}
		check := env.Custody.Consume(ctx, sessionConsumerSelection(t, cold, cold.admission.recipient, name), custody.StandardValue)
		if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
			t.Fatal("new current value was not privately readable after exit", name, check)
		}
	}
	receipt, result := cold.MutationReceipt(ctx, cold.head.EndWork.OperationID)
	if result.Outcome != ObservedCurrent || len(receipt) == 0 {
		t.Fatal("first old retirement exit lost its signed receipt", result)
	}
}

func signedFullIntentSource(t *testing.T, operationCtx context.Context, env fixtureEnvironment, before *StateSession,
	operation contract.ID, names []string, sources []contract.GeneratorDeclarationEntry, recipients []contract.ID, valueChoice, outputEncoding uint8, label string,
	progress func(string, int, int)) *StateSession {
	t.Helper()
	ctx := context.Background()
	profile := defaultGeneratedFixtureProfile()
	intentForName := func(name string) []byte {
		intent := hermeticSizedGeneratorIntent(name, 0x5a, 384<<10)
		return intent
	}
	bound := generatedReservationInputForMembershipStateIntents(t, before, operation,
		recipients, names, intentForName, profile, 0, nil, nil, sources...)
	input := generatedPlanInputForGenerations(t, before, operation, names, profile, sources...)
	input.graph, input.declaration, input.registry, input.recoveryPolicy, input.requestBindings =
		bound.graph, bound.declaration, bound.graph.Request.Registry, bound.graph.Request.RecoveryPolicyID, slices.Clone(bound.requestBindings)
	declarationView, err := contract.InspectGeneratorDeclaration(input.declaration)
	if err != nil {
		t.Fatal("source declaration", err)
	}
	declaration, err := declarationView.Own()
	if err != nil {
		t.Fatal("source declaration ownership", err)
	}
	authoredDeclarations, authoredPlans := 0, 0
	for i := range declaration.Entries {
		entry := &declaration.Entries[i]
		if !slices.Contains(names, entry.Name) {
			continue
		}
		if entry.Kind != contract.GeneratorDeclarationGenerated {
			t.Fatal("source name is not a new generated declaration", entry.Name)
		}
		entry.OutputEncoding = outputEncoding
		authoredDeclarations++
	}
	for i := range input.graph.ValueEntryPlans {
		plan := &input.graph.ValueEntryPlans[i]
		if !slices.Contains(names, plan.Name) {
			continue
		}
		if plan.ValueSource != contract.Generated || plan.ChangeMask&contract.GeneratorValueChangeContent == 0 {
			t.Fatal("source name is not a new generated plan", plan.Name)
		}
		plan.OutputEncoding = outputEncoding
		authoredPlans++
	}
	if authoredDeclarations != len(names) || authoredPlans != len(names) {
		t.Fatal("source output authoring omitted a generated name", authoredDeclarations, authoredPlans, len(names))
	}
	oldJoin, err := contract.GeneratorCompleteJoinID(input.graph.Header.RequestCoreDigest)
	if err != nil {
		t.Fatal("source original completion join", err)
	}
	input.declaration, err = contract.EncodeGeneratorDeclaration(declaration)
	if err != nil {
		t.Fatal("source encoded declaration", err)
	}
	input.graph.Request.Declaration, err = contract.GeneratorDeclarationDescriptor(declaration)
	if err != nil {
		t.Fatal("source declaration descriptor", err)
	}
	input.graph.Header.RequestCoreDigest, err = contract.GeneratorRequestCoreDigest(input.graph.Request)
	if err != nil {
		t.Fatal("source request digest", err)
	}
	newJoin, err := contract.GeneratorCompleteJoinID(input.graph.Header.RequestCoreDigest)
	if err != nil {
		t.Fatal("source completion join", err)
	}
	for i := range input.graph.Edges {
		if input.graph.Edges[i].DestinationTemplateID == oldJoin {
			input.graph.Edges[i].DestinationTemplateID = newJoin
		}
	}
	input.graph.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(input.graph.Header, input.graph.ValueEntryPlans, input.graph.Lineages, input.graph.Edges)
	if err != nil {
		t.Fatal("source graph identity", err)
	}
	declarationView, err = contract.InspectGeneratorDeclaration(input.declaration)
	if err != nil {
		t.Fatal("source rebound declaration", err)
	}
	if err := contract.ValidateGeneratorDeclarationGraph(declarationView, input.graph); err != nil {
		t.Fatal("source declaration graph", err)
	}
	if err := contract.ValidateGeneratorEffectGraph(input.graph); err != nil {
		t.Fatal("source effect graph", err)
	}
	input.context.AdmissionID = fixtureID(env.Domain, label+" plan admission")
	input.context.SessionID = fixtureID(env.Domain, label+" plan session")
	input.context.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
	if uint64(len(input.declaration)) > contract.GeneratorDeclarationMaxLength {
		t.Fatal("one source exceeded the 32 MiB declaration ceiling", len(input.declaration))
	}
	_, canonical := generatedCurrentDeclaration(t, before)
	reservation, _ := preparePrivateGeneratedReservation(t, env, before, input, canonical)
	current, originals := sendParallelOriginals(t, ctx, env, before, reservation, valueChoice)
	if len(originals) != len(names) {
		t.Fatal("independent source original count", len(originals))
	}
	for i, original := range originals {
		recordContext := generatedPlanInputFixture(t, current).context
		recordContext.AdmissionID = fixtureID(env.Domain, fmt.Sprintf("%s record admission %d", label, i))
		recordContext.SessionID = fixtureID(env.Domain, fmt.Sprintf("%s record session %d", label, i))
		recordContext.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
		record, err := current.generatedRecordRequest(context.Background(), original.expected.Template.AttemptID, original.result, recordContext)
		if err != nil {
			t.Fatal("independent source Record request", label, i, err)
		}
		prepared := preparePrivateGeneratedRecord(t, env, current, record)
		var result Result
		current, result = current.selectCandidate(ctx, prepared.reservation.candidate)
		if current == nil || result.Outcome != ObservedCurrent {
			t.Fatal("independent source Record selection", label, i, result)
		}
		env.Custody.RetireGenerated()
		if (i+1)%8 == 0 {
			if progress == nil {
				t.Logf("%s recorded %d/%d real results", label, i+1, len(originals))
			} else {
				progress(label+"-record", i+1, len(originals))
			}
		}
	}
	finalContext := generatedPlanInputFixture(t, current).context
	finalContext.AdmissionID = fixtureID(env.Domain, label+" final admission")
	finalContext.SessionID = fixtureID(env.Domain, label+" final session")
	finalContext.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
	finalPlan, err := current.generatedFinalRequest(t.Context(), finalContext)
	if err != nil || finalPlan == nil || len(finalPlan.entryPlans) != len(names) {
		t.Fatal("independent source Final request", label, err)
	}
	current, final := preparePrivateGeneratedFinal(t, env, current, finalPlan)
	closed, result := current.selectCandidate(ctx, final.reservation.candidate)
	if closed == nil || result.Outcome != ObservedCurrent ||
		closed.root.Generated.GeneratedCurrent != uint32(len(names)) {
		t.Fatal("independent source Final selection", label, result)
	}
	for _, name := range names {
		entry := closed.valueEntry(entrySlot(t, closed, name))
		if entry.OutputEncoding != outputEncoding {
			t.Fatal("source Final lost the authored entry output encoding", name, entry.OutputEncoding, outputEncoding)
		}
	}
	env.Custody.RetireGenerated()
	return generatedLifecycleReopen(t, operationCtx, closed, env.Store)
}

// The two independent origins are only inputs to the signed combined image.
// Keep their complete selected images and create-only result inboxes, without
// retaining every obsolete phase page in the in-memory fixture Store.
func pruneCompletedIntentSourceStore(t *testing.T, env fixtureEnvironment, selected *StateSession,
	operation contract.ID, names []string) *StateSession {
	t.Helper()
	ctx := t.Context()
	store := env.Store.(*memoryStore)
	beforeReceipt, beforeResult := selected.MutationReceipt(ctx, operation)
	if beforeResult.Outcome != ObservedCurrent {
		t.Fatal("source Final receipt before Store pruning", beforeResult)
	}
	beforeWork, err := selected.selectedGeneratedWork(ctx)
	if err != nil {
		t.Fatal("source selected work before Store pruning", err)
	}
	intentDigests := make(map[string]contract.DigestLength, len(names))
	for _, name := range names {
		selection := sessionConsumerSelection(t, selected, selected.admission.recipient, name)
		entry := selected.valueEntry(selection.Slot)
		if entry == nil || entry.ValueSource != contract.Generated {
			t.Fatal("completed source has no generated entry", name)
		}
		intent, err := beforeWork.readSelectedSlice(ctx, contract.GeneratorContentIntent,
			entry.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
		if err != nil {
			t.Fatal("completed source intent before Store pruning", name, err)
		}
		intentDigests[name] = contract.DigestLength{Digest: contract.Hash(intent), Length: uint64(len(intent))}
	}
	type inboxObservation struct {
		body    []byte
		present bool
		result  Result
	}
	inboxes := make(map[contract.ID]inboxObservation, len(beforeWork.attempts))
	for attempt := range beforeWork.attempts {
		body, present, result := selected.ReadGeneratedResult(ctx, attempt)
		inboxes[attempt] = inboxObservation{body: body, present: present, result: result}
	}
	store.mu.Lock()
	beforeCreates, beforeCAS := store.creates, store.cas
	kept := make(map[string]stored)
	keepKey := func(key string) {
		object, ok := store.objects[key]
		if !ok {
			store.mu.Unlock()
			t.Fatal("selected source object absent before pruning", key)
		}
		kept[key] = object
	}
	keepRef := func(ref format.Ref) {
		key, err := format.Key(store.desc.Prefix, ref)
		if err != nil {
			store.mu.Unlock()
			t.Fatal("selected source Ref key", err)
		}
		keepKey(key)
	}
	keepKey(store.desc.HeadKey)
	keepRef(selected.head.Core.Root)
	for _, ref := range selected.root.ValueEntryPages {
		if ref != nil {
			keepRef(*ref)
		}
	}
	for _, ref := range selected.root.Recipients {
		if ref != nil {
			keepRef(*ref)
		}
	}
	for _, ref := range selected.root.CurrentAccess.Core.AccessPageRefs {
		keepRef(ref)
	}
	keepRef(selected.root.AdministrativeIndex)
	for _, ref := range selected.root.AdministrativeIndexShards {
		keepRef(ref)
	}
	for _, ref := range selected.root.RequiredSupport {
		keepRef(ref)
	}
	for key, object := range store.objects {
		if strings.Contains(key, "/result/") {
			kept[key] = object
		}
	}
	store.objects = kept
	store.mu.Unlock()
	reopened, result := Open(ctx, OpenContext{admission: &selected.admission}, store)
	if reopened == nil || result.Outcome != ObservedCurrent || reopened.head.Core != selected.head.Core ||
		reopened.root.Generated.GeneratedCurrent != uint32(len(names)) {
		t.Fatal("completed source did not cold-open after Store pruning", result)
	}
	afterReceipt, afterResult := reopened.MutationReceipt(ctx, operation)
	if afterResult.Outcome != ObservedCurrent || !bytes.Equal(beforeReceipt, afterReceipt) {
		t.Fatal("completed source lost its signed Final receipt", afterResult)
	}
	afterWork, err := reopened.selectedGeneratedWork(ctx)
	if err != nil {
		t.Fatal("completed source lost selected generated work", err)
	}
	for attempt, before := range inboxes {
		body, present, result := reopened.ReadGeneratedResult(ctx, attempt)
		if present != before.present || result.Outcome != before.result.Outcome || result.Reason != before.result.Reason ||
			result.StoreReason != before.result.StoreReason || !bytes.Equal(body, before.body) {
			t.Fatal("completed source changed a selected result inbox", attempt, result)
		}
	}
	for _, name := range names {
		selection := sessionConsumerSelection(t, reopened, reopened.admission.recipient, name)
		check := env.Custody.Consume(ctx, selection, custody.StandardValue)
		if check.Code != contract.CryptoSuccess || !check.ValueMatched {
			t.Fatal("completed source lost current private value", name, check)
		}
		entry := reopened.valueEntry(selection.Slot)
		if entry == nil || entry.ValueSource != contract.Generated {
			t.Fatal("completed source lost generated entry", name)
		}
		intent, err := afterWork.readSelectedSlice(ctx, contract.GeneratorContentIntent,
			entry.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
		if err != nil || uint64(len(intent)) != intentDigests[name].Length ||
			contract.Hash(intent) != intentDigests[name].Digest {
			t.Fatal("completed source lost exact intent", name, err)
		}
	}
	if store.creates != beforeCreates || store.cas != beforeCAS {
		t.Fatal("test-only Store pruning wrote an object or HEAD")
	}
	return reopened
}

// full_only: false
func TestCompletedIntentSourceStorePrune(t *testing.T) {
	for _, count := range []int{8, 16} {
		t.Run(fmt.Sprintf("results_%d", count), func(t *testing.T) {
			env, _ := genesisEnvironment(t, contract.GCP, false)
			fixture := newNamedEnvironmentFixture(t, t.Context(), env, []int{1}, false, []string{"a-seed"})
			sources, _ := generatedCurrentDeclaration(t, fixture.session)
			names := make([]string, count)
			for i := range names {
				names[i] = fmt.Sprintf("prune-%03d", i)
			}
			operation := fixtureID(env.Domain, fmt.Sprintf("prune operation %d", count))
			selected := signedFullIntentSource(t, t.Context(), env, fixture.session, operation, names, sources,
				[]contract.ID{fixture.session.admission.recipient}, custody.StandardValue, contract.OutputEncodingRaw, fmt.Sprintf("prune source %d", count), nil)
			store := env.Store.(*memoryStore)
			beforeObjects := len(store.objects)
			selected = pruneCompletedIntentSourceStore(t, env, selected, operation, names)
			if selected == nil || len(store.objects) >= beforeObjects {
				t.Fatal("completed source history was not pruned", beforeObjects, len(store.objects))
			}
		})
	}
}

// full_only: false
func TestConfiguredGeneratedReplacementPreparation(t *testing.T) {
	env, _ := genesisEnvironment(t, contract.GCP, false)
	// Slice IDs sort by hash, so fixed genesis identities keep this partition stable.
	env.GenesisIDs = genesisIDs{Init: testID("configured replacement init"), Domain: testID("configured replacement domain"),
		DescriptorArtifact: testID("configured replacement descriptor"), ManifestArtifact: testID("configured replacement manifest")}
	env.Domain = env.GenesisIDs.Domain
	env.Store.(*memoryStore).configure(t, contract.GCP, env.Domain)
	keys := custody.New(t, contract.GCP, fixtureID(env.Domain, "custody"), false,
		[]contract.ID{fixtureID(env.Domain, "recipient"), fixtureID(env.Domain, "reader")})
	env.Custody, env.Bindings, env.Crypto = keys, keys.Bindings(), keys.Crypto()
	env.AdmitInit, env.RetireInit = keys.AdmitInit, keys.RetireInit

	ctx := t.Context()
	f := newNamedEnvironmentFixture(t, ctx, env, []int{1}, false, []string{"configuration-seed"})
	sources, _ := generatedCurrentDeclaration(t, f.session)
	recipients := capacityRecipients(t, f.session, 2)
	names := []string{"configured-generated-a", "configured-generated-b", "configured-generated-c", "configured-generated-d"}
	selected := signedFullIntentSource(t, ctx, env, f.session, fixtureID(env.Domain, "configured replacement origin"),
		names, sources, recipients, custody.StandardValue, contract.OutputEncodingRaw, "configured replacement origin", nil)
	configuration := capacityOutputConfiguration(t, selected, false)
	first := configuration.Bindings[0]
	targets := first.Targets
	configuration.Bindings = nil
	for b := 0; b < 8; b++ {
		binding := contract.OutputBinding{DestinationID: fmt.Sprintf("destination-%02d", b),
			IncarnationID: fixtureID(env.Domain, fmt.Sprintf("replacement packing fixture 2/%d", b)), Destination: first.Destination}
		binding.Destination.CanonicalSettings = hermeticDestinationSettings([][2]string{{"destination", fmt.Sprintf("fixture-value-%02d", b)}})
		for e, original := range targets {
			target := original
			target.CanonicalTarget = fmt.Sprintf("projects/123456789012/secrets/enkv-b%02d-e%03d", b, e)
			target.ConsumerLocator = target.CanonicalTarget + "/versions/latest"
			var subjects []string
			for member := 0; member < 1500; member++ {
				subjects = append(subjects, fmt.Sprintf("serviceAccount:capacity-account-member-%04d@capacity-fixture.iam.gserviceaccount.com", member))
			}
			target.Policy = hermeticTextPolicy(target.Policy.ContractID, subjects)
			target.TargetData = []byte("target:" + target.CanonicalTarget)
			binding.Targets = append(binding.Targets, target)
		}
		binding.Destination.Policy = binding.Targets[0].Policy
		configuration.Bindings = append(configuration.Bindings, binding)
	}
	for i := range configuration.Routes {
		configuration.Routes[i].Destinations = nil
		for _, binding := range configuration.Bindings {
			configuration.Routes[i].Destinations = append(configuration.Routes[i].Destinations, binding.DestinationID)
		}
	}
	store, opened := signedCapacityConfigurationImage(t, env, f.session, selected, "configured replacement predecessor", false, configuration)
	// Eight bindings and their four targets each retain all 1500 subjects.
	// Independent schema4 framing gives declaration5230734, routing1678 and
	// image5232416: four 1048423-byte payloads and one 1038724-byte payload.
	if opened.root.OutputConfiguration.TotalLength != 5232416 || opened.root.OutputConfiguration.RoutingLength != 1678 ||
		opened.root.OutputConfiguration.SliceCount != 5 || opened.root.OutputConfiguration.BindingCount != 8 {
		t.Fatal("bounded replacement configuration dimensions", opened.root.OutputConfiguration)
	}
	successorEnv := env
	successorEnv.Store = store
	incarnations := make(map[string]contract.ID)
	retiring := make(map[string]contract.ValueEntry)
	for _, named := range opened.root.Names {
		entry := opened.valueEntry(named.Slot)
		if entry.ValueSource == contract.Generated {
			incarnations[named.Name], retiring[named.Name] = entry.Incarnation, *entry
		}
	}
	operation := fixtureID(env.Domain, "configured replacement operation")
	profile := defaultGeneratedFixtureProfile()
	bound := generatedReservationInputForMembershipStateIntents(t, opened, operation, recipients, names,
		func(name string) []byte { return hermeticGeneratorIntent([]byte("replacement intent " + name)) }, profile, 2, incarnations, retiring, sources...)
	input := generatedPlanInputForGenerations(t, opened, operation, names, profile, sources...)
	input.graph, input.declaration = bound.graph, bound.declaration
	input.registry, input.recoveryPolicy = bound.graph.Request.Registry, bound.graph.Request.RecoveryPolicyID
	input.requestBindings = slices.Clone(bound.requestBindings)
	reservation, _ := preparePrivateGeneratedReservation(t, successorEnv, opened, input, nil)
	retained, rewritten := 0, 0
	for _, ref := range capacityConfigurationSupportRefs(t, opened) {
		if slices.Contains(reservation.reservation.state.root.RequiredSupport, ref) {
			retained++
		} else {
			rewritten++
		}
	}
	if retained != 1 || rewritten != 2 {
		t.Fatal("replacement did not exercise mixed retained and repacked configuration pages", retained, rewritten)
	}
	beforeFacts, err := opened.selectedOutputFactsByRecord()
	if err != nil {
		t.Fatal("replacement predecessor configuration facts", err)
	}
	afterFacts, err := reservation.reservation.state.selectedOutputFactsByRecord()
	if err != nil || len(afterFacts) != len(beforeFacts) || reservation.reservation.state.root.OutputConfiguration != opened.root.OutputConfiguration {
		t.Fatal("replacement changed the configuration descriptor or slice count", err)
	}
	for id, before := range beforeFacts {
		if after, present := afterFacts[id]; !present || after.row != before.row {
			t.Fatal("replacement changed an authenticated configuration slice", id)
		}
	}
	current, originals := sendParallelOriginals(t, ctx, successorEnv, opened, reservation, custody.StandardValue)
	if len(originals) != len(names) {
		t.Fatal("configured replacement original count", len(originals))
	}
	current = generatedLifecycleReopen(t, ctx, current, store)
	previous := input.context
	for _, cut := range []string{"pre_canceled", "selected_read"} {
		if !t.Run("record_"+cut, func(t *testing.T) {
			admitted := freshGeneratedSequenceContext(t, current, "configured replacement record "+cut, &previous)
			original := originals[0]
			record, err := current.generatedRecordRequest(context.Background(), original.expected.Template.AttemptID, original.result, admitted)
			if err != nil {
				t.Fatal("configured replacement canceled Record request", err)
			}
			permit := admitPrivateGeneratedRecord(ctx, t, keys, current, record)
			predecessor := current
			current = assertMaximumGeneratedCanceled(t, ctx, successorEnv, predecessor, func(ctx context.Context) (bool, Result) {
				p, result := predecessor.PrepareGeneratedRecord(ctx, permit)
				return p != nil, result
			}, &permit.used, cut)
			assertCapacityConfigurationPreserved(t, opened, current)
		}) {
			return
		}
	}
	for i, original := range originals {
		recordContext := freshGeneratedSequenceContext(t, current, fmt.Sprintf("configured replacement record %d", i), &previous)
		record, err := current.generatedRecordRequest(context.Background(), original.expected.Template.AttemptID, original.result, recordContext)
		if err != nil {
			t.Fatal("configured replacement Record request", i, err)
		}
		prepared := preparePrivateGeneratedRecord(t, successorEnv, current, record)
		var outcome Result
		current, outcome = current.selectCandidate(ctx, prepared.reservation.candidate)
		if current == nil || outcome.Outcome != ObservedCurrent {
			t.Fatal("configured replacement Record selection", i, outcome)
		}
		env.Custody.RetireGenerated()
		current = generatedLifecycleReopen(t, ctx, current, store)
	}
	for _, cut := range []string{"pre_canceled", "selected_read"} {
		if !t.Run("final_"+cut, func(t *testing.T) {
			admitted := freshGeneratedSequenceContext(t, current, "configured replacement final "+cut, &previous)
			plan, err := current.generatedFinalRequest(ctx, admitted)
			if err != nil || plan == nil || !plan.selecting || len(plan.entryPlans) != len(names) {
				t.Fatal("configured replacement canceled Final request", err)
			}
			permit := admitPrivateGeneratedFinal(t, successorEnv, current, plan)
			predecessor := current
			current = assertMaximumGeneratedCanceled(t, ctx, successorEnv, predecessor, func(ctx context.Context) (bool, Result) {
				p, result := predecessor.PrepareGeneratedFinal(ctx, permit)
				return p != nil, result
			}, &permit.used, cut)
			assertCapacityConfigurationPreserved(t, opened, current)
		}) {
			return
		}
	}
	finalContext := freshGeneratedSequenceContext(t, current, "configured replacement final complete", &previous)
	finalPlan, err := current.generatedFinalRequest(ctx, finalContext)
	if err != nil || finalPlan == nil || len(finalPlan.entryPlans) != len(names) {
		t.Fatal("configured replacement Final request", err)
	}
	current, final := preparePrivateGeneratedFinal(t, successorEnv, current, finalPlan)
	replaced, outcome := current.selectCandidate(ctx, final.reservation.candidate)
	if replaced == nil || outcome.Outcome != ObservedCurrent {
		t.Fatal("configured replacement Final selection", outcome)
	}
	env.Custody.RetireGenerated()
	replaced = generatedLifecycleReopen(t, ctx, replaced, store)
	finalFacts, err := replaced.selectedOutputFactsByRecord()
	if err != nil {
		t.Fatal("configured replacement cold configuration facts", err)
	}
	changedRows, changedLocations := 0, 0
	for id, before := range beforeFacts {
		after, present := finalFacts[id]
		if !present || after.row != before.row {
			changedRows++
		}
		if after.ref != before.ref || after.physical != before.physical {
			changedLocations++
		}
	}
	t.Logf("replacement cold preservation: descriptor-equal=%t rows-before=%d rows-after=%d changed-rows=%d changed-locations=%d refs-equal=%t",
		opened.root.OutputConfiguration == replaced.root.OutputConfiguration, len(beforeFacts), len(finalFacts), changedRows, changedLocations,
		slices.Equal(capacityConfigurationSupportRefs(t, opened), capacityConfigurationSupportRefs(t, replaced)))
	assertCapacityConfigurationPreserved(t, opened, replaced)
	assertConfiguredReplacementSeed(t, opened, replaced, "configuration-seed")
	admin, result := openAdministrative(ctx, OpenContext{admission: &replaced.admission}, store)
	if admin == nil || result.Outcome != ObservedCurrent {
		t.Fatal("bounded replacement administrative reopen", result)
	}
	var exitTargets []contract.ID
	for _, group := range admin.adminIndex.Groups {
		if group.OwnerKind != format.AdministrativeGeneratedDuty || group.DutyKind != contract.GeneratedDutyRetirement {
			continue
		}
		remaining, scope, err := admin.administrativeWorkClosure(group.GroupID)
		if err == nil && len(scope) == 1 && len(remaining.Groups) == len(admin.adminIndex.Groups)-1 {
			exitTargets = append(exitTargets, group.GroupID)
			if len(exitTargets) == 2 {
				break
			}
		}
	}
	if len(exitTargets) != 2 {
		t.Fatal("bounded replacement lacks two independent retirement exits", len(exitTargets))
	}
	for i, target := range exitTargets {
		candidate, prepared := prepareTestEndSelectedWork(t, admin, ctx, target, env.Trust)
		if candidate == nil || prepared.Outcome != ObservedCurrent {
			t.Fatal("bounded replacement EndWork preparation", i, prepared)
		}
		if next, selected := admin.selectCandidate(ctx, candidate); next == nil || selected.Outcome != ObservedCurrent {
			t.Fatal("bounded replacement EndWork selection", i, selected)
		}
		ordinary := generatedLifecycleReopen(t, ctx, admin, store)
		assertCapacityConfigurationPreserved(t, opened, ordinary)
		assertConfiguredReplacementSeed(t, opened, ordinary, "configuration-seed")
		expired := ordinary.admission
		expired.expires = time.Now().Add(-time.Second)
		reader := *ordinary
		reader.admission = expired
		if selection, refused := reader.admitConsumerSelection(ctx, names, reader.admission.recipient); selection != nil ||
			refused.Outcome != AdmissionRefused || refused.Reason != AdmissionInvalid {
			t.Fatal("expired replacement read admission did not refuse", i, refused)
		}
		if current, refused := Open(ctx, OpenContext{admission: &expired}, store); current != nil ||
			refused.Outcome != AdmissionRefused || refused.Reason != AdmissionInvalid {
			t.Fatal("expired replacement cold admission did not refuse", i, refused)
		}
		interpret := expired.outputInterpreter
		if interpret == nil {
			t.Fatal("replacement fixture lacks its output interpreter", i)
		}
		interpretCalls := 0
		expired.outputInterpreter = func(ctx context.Context, destinationID string, destination contract.OutputDestination, name string, encoding uint8) (contract.OutputTarget, error) {
			interpretCalls++
			return interpret(ctx, destinationID, destination, name, encoding)
		}
		wantAdmission := expired
		deadline, _ := t.Deadline()
		bounded := capacityFixtureAdmission(t, OpenContext{admission: &expired})
		if bounded.admission == nil || bounded.admission == &expired || bounded.admission.outputInterpreter == nil ||
			expired.outputInterpreter == nil || interpretCalls != 0 {
			t.Fatal("bounded fixture did not copy its passive interpreter", i)
		}
		gotAdmission, predecessorAdmission, originalAdmission := *bounded.admission, expired, wantAdmission
		gotAdmission.outputInterpreter, wantAdmission.outputInterpreter = nil, nil
		predecessorAdmission.outputInterpreter, originalAdmission.outputInterpreter = nil, nil
		wantAdmission.expires = deadline
		if !reflect.DeepEqual(gotAdmission, wantAdmission) || !reflect.DeepEqual(predecessorAdmission, originalAdmission) ||
			reader.admission.expires != expired.expires || expired.expires != originalAdmission.expires {
			t.Fatal("bounded fixture changed admission pins or its expired predecessor", i)
		}
		binding := configuration.Bindings[0]
		wantTarget := binding.Targets[0]
		var targetName string
		for name, incarnation := range incarnations {
			if incarnation == wantTarget.EntryIncarnationID {
				targetName = name
			}
		}
		if targetName == "" {
			t.Fatal("replacement target lacks its original name", i)
		}
		wantTarget.EntryIncarnationID, wantTarget.PayloadEncoding = contract.ID{}, contract.OutputEncodingRaw
		actualTarget, err := bounded.admission.outputInterpreter(ctx, binding.DestinationID, binding.Destination, targetName, contract.OutputEncodingRaw)
		if err != nil || interpretCalls != 1 || !reflect.DeepEqual(actualTarget, wantTarget) {
			t.Fatal("bounded fixture changed its exact output interpreter", i, err)
		}
		actualTarget, err = expired.outputInterpreter(ctx, binding.DestinationID, binding.Destination, targetName, contract.OutputEncodingRaw)
		if err != nil || interpretCalls != 2 || !reflect.DeepEqual(actualTarget, wantTarget) {
			t.Fatal("bounded fixture changed its predecessor interpreter", i, err)
		}
		if _, err := bounded.admission.outputInterpreter(ctx, binding.DestinationID, binding.Destination, "configured-generated-missing", contract.OutputEncodingRaw); err == nil || interpretCalls != 3 {
			t.Fatal("bounded fixture lost its unknown-name refusal", i, err)
		}
		fresh, result := Open(ctx, bounded, store)
		if fresh == nil || result.Outcome != ObservedCurrent {
			t.Fatal("finite replacement read admission did not cold-open", i, result)
		}
		for _, name := range names {
			check := keys.Consume(ctx, sessionConsumerSelection(t, fresh, fresh.admission.recipient, name), custody.StandardValue)
			if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
				t.Fatal("bounded replacement current private consume", i, name, check)
			}
		}
		admin, result = openAdministrative(ctx, OpenContext{admission: &fresh.admission}, store)
		if admin == nil || result.Outcome != ObservedCurrent {
			t.Fatal("bounded replacement next administrative predecessor", i, result)
		}
	}
}

// full_only: true
// Maximum-capacity or accumulated-history proof; smaller behavior checks remain in dev.
func TestSignedIndependentCurrentIntentsFortyEightMiB(t *testing.T) {
	ctx := t.Context()
	env, _ := genesisEnvironment(t, contract.GCP, false, 16)
	// All 128 new creates declare 64 KiB, filling the 8 MiB raw-value account.
	// Retain the configured supplied seed with an empty value.
	fixture := newNamedEnvironmentFixture(t, ctx, env, []int{0}, false, []string{"a-seed"})
	fixture.admission = capacityFixtureAdmission(t, fixture.admission)
	fixture.session.admission = *fixture.admission.admission
	lifecycle := fixture.session
	bodyDirectory := filepath.Join(t.TempDir(), "bodies")
	fmt.Fprintln(os.Stderr, "full fixture body directory", bodyDirectory)
	if err := env.Store.(*memoryStore).useFileBodies(bodyDirectory); err != nil {
		t.Fatal("full fixture body files", err)
	}
	bodyFiles := env.Store.(*memoryStore).fileBodies
	progress := func(phase string, completed, total int) {
		bodyFiles.mu.Lock()
		used := bodyFiles.used
		bodyFiles.mu.Unlock()
		fmt.Fprintf(os.Stderr, "full fixture phase=%s completed=%d total=%d body_file_bytes=%d\n",
			phase, completed, total, used)
	}
	progress("file-mode-enabled", 0, 0)
	storeB := selectedMemoryStoreCopy(env.Store.(*memoryStore))
	envB := env
	envB.Store = storeB
	envB.Custody = env.Custody.ForkGenerated(t)
	envB.Crypto = envB.Custody.Crypto()
	sourceB, result := Open(ctx, OpenContext{admission: &lifecycle.admission}, storeB)
	if sourceB == nil || result.Outcome != ObservedCurrent {
		t.Fatal("full source B base", result)
	}
	const perOrigin = 64
	filler := make([]ApplyEntryInput, 0, perOrigin+1)
	filler = append(filler, ApplyEntryInput{Name: "a-seed", Recipients: []contract.ID{sourceB.admission.recipient},
		ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
	var alpha, omega []string
	for i := 0; i < perOrigin; i++ {
		filler = append(filler, ApplyEntryInput{Name: fmt.Sprintf("b-filler-%03d", i),
			Recipients: []contract.ID{sourceB.admission.recipient}, ValueSource: format.Supplied, ConfidentialityClass: format.Plain,
			InputBytes: []byte{byte(i)}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
		alpha = append(alpha, fmt.Sprintf("alpha-%03d", i))
		omega = append(omega, fmt.Sprintf("omega-%03d", i))
	}
	comparison, result := sourceB.Compare(ctx, filler, admitSuppliedComparison(t, sourceB, nil, filler))
	if comparison == nil || result.Outcome != ObservedCurrent {
		t.Fatal("full source B filler comparison", result)
	}
	candidate, result := sourceB.Prepare(ctx, comparison, admit(t, sourceB, comparison), envB.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("full source B filler preparation", result)
	}
	if result = sourceB.Select(ctx, candidate); result.Outcome != ObservedCurrent {
		t.Fatal("full source B filler selection", result)
	}
	sourceB, result = Open(ctx, OpenContext{admission: &sourceB.admission}, storeB)
	if sourceB == nil || result.Outcome != ObservedCurrent {
		t.Fatal("full source B filler reopen", result)
	}
	predecessor, originalRelease := signedCurrentIntentReleasePredecessor(t, ctx, env, lifecycle, "full before replacement")
	aSources, _ := generatedCurrentDeclaration(t, predecessor)
	operationA := fixtureID(env.Domain, "full source A operation")
	progress("source-a-start", 0, perOrigin)
	selectedA := signedFullIntentSource(t, ctx, env, predecessor, operationA,
		alpha, aSources, capacityRecipients(t, predecessor, 16), custody.StandardValue, contract.OutputEncodingRaw, "full source A", progress)
	progress("source-a-final", perOrigin, perOrigin)
	bSources, _ := generatedCurrentDeclaration(t, sourceB)
	operationB := fixtureID(env.Domain, "full source B operation")
	progress("source-b-start", 0, perOrigin)
	selectedB := signedFullIntentSource(t, ctx, envB, sourceB, operationB,
		omega, bSources, capacityRecipients(t, sourceB, 16), custody.StandardValue, contract.OutputEncodingRaw, "full source B", progress)
	progress("source-b-final", perOrigin, perOrigin)
	store, opened := signedCurrentIntentFixture(t, env, lifecycle, "full forty-eight MiB", selectedA, selectedB)
	configuredEnv := env
	configuredEnv.Store = store
	store, opened = signedCapacityConfiguration(t, configuredEnv, lifecycle, opened, "full forty-eight MiB configured", true)
	capacityConfigurationSupportRefs(t, opened)
	if opened.root.MembershipCount != 2049 || opened.root.SecretOrdinaryWrapCount != 2048 {
		t.Fatal("full actual generated memberships", opened.root.MembershipCount, opened.root.SecretOrdinaryWrapCount)
	}
	progress("signed-selected", perOrigin*2, perOrigin*2)
	for _, source := range []struct {
		name  string
		store *memoryStore
	}{{"source A", env.Store.(*memoryStore)}, {"source B", storeB}, {"signed successor", store}} {
		source.store.mu.Lock()
		for key, object := range source.store.objects {
			if key != source.store.desc.HeadKey && (object.bodyPath == "" || object.Body != nil) {
				source.store.mu.Unlock()
				t.Fatal("full fixture retained an immutable body in RAM", source.name, key)
			}
		}
		source.store.mu.Unlock()
	}
	// 128 distinct 384 KiB Intents need 49 fragments with 1 MiB-256-byte
	// payloads. The retained initialization receipt adds one separate fragment:
	// its schema-2 index is 2+3*8+36*(1+0+1) = 98 bytes.
	if opened.root.Generated.GeneratedCurrent != 128 || opened.root.SecretCount != 128 ||
		opened.root.ValueEntryCount != 129 || len(opened.root.Generated.Fragments) != 49+1 {
		t.Fatal("signed 48 MiB current selected dimensions", opened.root.Generated.GeneratedCurrent,
			opened.root.SecretCount, opened.root.ValueEntryCount, len(opened.root.Generated.Fragments))
	}
	var logical uint64
	origins := make(map[contract.ID]int)
	work, err := opened.selectedGeneratedWork(ctx)
	if err != nil {
		t.Fatal("full signed generated selection", err)
	}
	for _, named := range opened.root.Names {
		entry := opened.valueEntry(named.Slot)
		if entry.ValueSource != contract.Generated {
			continue
		}
		origins[entry.Generated.OriginOperationID]++
		intent, err := work.readSelectedSlice(ctx, contract.GeneratorContentIntent, entry.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
		if err != nil {
			t.Fatal("full signed exact generated intent", named.Name, err)
		}
		assertCapacityIntentBytes(t, named.Name, intent)
		logical += uint64(len(intent))
		selection := sessionConsumerSelection(t, opened, opened.admission.recipient, named.Name)
		check := env.Custody.Consume(ctx, selection, custody.StandardValue)
		if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
			t.Fatal("full signed private generated consume", named.Name, check)
		}
	}
	if logical != 48<<20 || len(origins) != 2 {
		t.Fatal("full signed independent original dimensions", logical, origins)
	}
	for _, count := range origins {
		if count != perOrigin {
			t.Fatal("one original did not produce 64 exact current entries", origins)
		}
	}
	if fresh, result := Open(ctx, OpenContext{admission: &opened.admission}, store); fresh == nil || result.Outcome != ObservedCurrent {
		t.Fatal("full signed state did not cold-open again", result)
	}
	t.Run("complete_reconstruction", func(t *testing.T) {
		assertReconstructionJointMaximum(t, env, opened, store)
	})
	t.Run("still_current_intents_release_end_work", func(t *testing.T) {
		// Reuse the same 128 actual successful source results. This selected
		// Store is independent of the unchanged zero-owner replacement fixture.
		progress("still-current-release-start", 0, perOrigin*2)
		releaseStore, releaseOpened := signedCurrentIntentFixtureWithRelease(t, env, lifecycle,
			"full forty-eight MiB before replacement", originalRelease.record.AttemptID, selectedA, selectedB)
		releaseEnv := env
		releaseEnv.Store = releaseStore
		releaseStore, releaseOpened = signedCapacityConfiguration(t, releaseEnv, lifecycle, releaseOpened, "full release configured", true)
		assertSignedCurrentIntentReleaseExit(t, env, releaseStore, releaseOpened, selectedA, originalRelease, perOrigin*2, nil)
		progress("still-current-release-exit", perOrigin*2, perOrigin*2)
	})
	t.Run("full_new_declaration_admission", func(t *testing.T) {
		const baseIntentLength = 255 << 10
		names := make([]string, 0, perOrigin*2)
		retiring := make(map[string]contract.ValueEntry, perOrigin*2)
		incarnations := make(map[string]contract.ID, perOrigin*2)
		intents := make(map[string][]byte, perOrigin*2)
		for _, named := range opened.root.Names {
			entry := opened.valueEntry(named.Slot)
			if entry == nil || entry.ValueSource != contract.Generated {
				continue
			}
			names = append(names, named.Name)
			retiring[named.Name], incarnations[named.Name] = *entry, entry.Incarnation
			intent := hermeticSizedGeneratorIntent(named.Name, 0x4c, baseIntentLength)
			intents[named.Name] = intent
		}
		if len(names) != contract.GeneratedCurrentEntryLimit {
			t.Fatal("replacement does not cover every old generated entry", len(names))
		}
		operation := fixtureID(opened.root.Domain, "full old-new intent replacement")
		profile := defaultGeneratedFixtureProfile()
		sources, _ := generatedCurrentDeclaration(t, lifecycle)
		if len(sources) != 1 || sources[0].Name != "a-seed" || sources[0].Kind != contract.GeneratorDeclarationPlain {
			t.Fatal("full replacement lacks its supplied seed declaration")
		}
		makeBound := func() generatedReservationInput {
			return generatedReservationInputForMembershipStateIntents(t, opened, operation,
				capacityRecipients(t, opened, 16), names,
				func(name string) []byte { return intents[name] }, profile, 2, incarnations, retiring, sources...)
		}
		bound := makeBound()
		remaining := contract.GeneratorDeclarationMaxLength - len(bound.declaration)
		if remaining <= 0 || remaining > contract.GeneratorIntentMaxLength-baseIntentLength {
			t.Fatal("new declaration cannot reach its full legal byte bound", remaining)
		}
		intents[names[0]] = hermeticSizedGeneratorIntent(names[0], 0x4c, len(intents[names[0]])+remaining)
		bound = makeBound()
		if len(bound.declaration) != contract.GeneratorDeclarationMaxLength {
			t.Fatal("new declaration did not reach its full legal byte bound", len(bound.declaration))
		}
		input := generatedPlanInputForGenerations(t, opened, operation, names, profile, sources...)
		input.graph, input.declaration = bound.graph, bound.declaration
		input.registry, input.recoveryPolicy = bound.graph.Request.Registry, bound.graph.Request.RecoveryPolicyID
		input.requestBindings = slices.Clone(bound.requestBindings)
		input.context.AdmissionID = fixtureID(opened.root.Domain, "full old-new plan admission")
		input.context.SessionID = fixtureID(opened.root.Domain, "full old-new plan session")
		input.context.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
		beforeCreates, beforeCAS := store.creates, store.cas
		beforePublic, beforePrivate := env.Custody.Calls()
		plan, err := opened.generatedPlanRequest(ctx, input)
		if err != nil || plan == nil || opened.prepared || store.creates != beforeCreates || store.cas != beforeCAS {
			t.Fatal("full old48/new32 whole-set replacement was not admitted before private work", err)
		}
		if afterPublic, afterPrivate := env.Custody.Calls(); afterPublic != beforePublic || afterPrivate != beforePrivate {
			t.Fatal("public old48/new32 admission entered custody", afterPublic-beforePublic, afterPrivate-beforePrivate)
		}
		progress("replacement-admitted", 0, len(names))
		// The declaration descriptor includes the eight-byte envelope framing;
		// the selected physical classes remain 49 old mandatory and 33 new
		// optional fragments, packed as 25 + 17 pages.
		intentCharge := plan.capacity.Groups[contract.GeneratorCapacityIntents]
		if plan.capacity.Declaration.Length != uint64(len(bound.declaration)+8) ||
			plan.capacity.Declaration.Length != contract.GeneratorDeclarationMaxFramedLength ||
			intentCharge.MaxCount != 49+33 || intentCharge.MaxPages != 25+17 ||
			intentCharge.MaxFramedBytes != (48<<20)+uint64(len(bound.declaration))+(49+33)*generatedFragmentCharge {
			t.Fatal("full old and new intent physical fragments were not charged", plan.capacity)
		}
		declaration, err := contract.InspectGeneratorDeclaration(input.declaration)
		if err != nil {
			t.Fatal("full new declaration", err)
		}
		shape, err := opened.generatedAdmissionShape(ctx, input.graph, declaration, work)
		if err != nil {
			t.Fatal("full old/new capacity shape", err)
		}
		shape.DeclarationBytes = uint64(len(input.declaration))
		if plan.intents.changed && plan.intents.emit {
			shape.ProjectedCurrentIntentFragments = uint64(plan.intents.fragments)
		}
		indexShards, err := opened.generatedAdministrativeShardReserve(shape)
		if err != nil {
			t.Fatal("old/new index reserve", err)
		}
		exitShards, err := opened.generatedAdministrativeFirstExitShardReserve(shape)
		if err != nil {
			t.Fatal("old/new first-exit index reserve", err)
		}
		var physicalPages uint32
		for _, group := range plan.capacity.Groups {
			physicalPages += group.MaxPages
		}
		t.Logf("signed old48/new32 public reservation: physical=%d index=%d first-exit-index=%d predecessor=%d",
			physicalPages, indexShards, exitShards, opened.root.ChildCount)
		if physicalPages+indexShards > ordinaryChildPageLimit ||
			physicalPages+2+exitShards > contract.MaxChildPages {
			t.Fatal("public old/new admission did not preserve ordinary and first-exit space")
		}
		successorEnv := env
		successorEnv.Store = store
		reservation, _ := preparePrivateGeneratedReservation(t, successorEnv, opened, input, nil)
		progress("replacement-reserved", 0, len(names))
		current, originals := sendParallelOriginals(t, ctx, successorEnv, opened, reservation, custody.StandardValue)
		if len(originals) != len(names) {
			t.Fatal("full replacement did not start every original", len(originals))
		}
		progress("replacement-originals-complete", len(originals), len(names))
		for i, original := range originals {
			recordContext := generatedPlanInputFixture(t, current).context
			recordContext.AdmissionID = fixtureID(env.Domain, fmt.Sprintf("full replacement record admission %d", i))
			recordContext.SessionID = fixtureID(env.Domain, fmt.Sprintf("full replacement record session %d", i))
			recordContext.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
			record, err := current.generatedRecordRequest(context.Background(), original.expected.Template.AttemptID, original.result, recordContext)
			if err != nil {
				t.Fatal("full replacement Record request", i, err)
			}
			prepared := preparePrivateGeneratedRecord(t, successorEnv, current, record)
			var outcome Result
			current, outcome = current.selectCandidate(ctx, prepared.reservation.candidate)
			if current == nil || outcome.Outcome != ObservedCurrent {
				t.Fatal("full replacement Record selection", i, outcome)
			}
			env.Custody.RetireGenerated()
			if (i+1)%16 == 0 {
				progress("replacement-record", i+1, len(originals))
			}
		}
		finalContext := generatedPlanInputFixture(t, current).context
		finalContext.AdmissionID = fixtureID(env.Domain, "full replacement Final admission")
		finalContext.SessionID = fixtureID(env.Domain, "full replacement Final session")
		finalContext.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
		finalPlan, err := current.generatedFinalRequest(ctx, finalContext)
		if err != nil || finalPlan == nil || len(finalPlan.entryPlans) != len(names) {
			t.Fatal("full replacement Final request", err)
		}
		current, final := preparePrivateGeneratedFinal(t, successorEnv, current, finalPlan)
		replaced, outcome := current.selectCandidate(ctx, final.reservation.candidate)
		if replaced == nil || outcome.Outcome != ObservedCurrent {
			t.Fatal("full replacement Final selection", outcome)
		}
		env.Custody.RetireGenerated()
		replaced = generatedLifecycleReopen(t, ctx, replaced, store)
		progress("replacement-final", len(names), len(names))
		if replaced.root.Generated.GeneratedCurrent != contract.GeneratedCurrentEntryLimit {
			t.Fatal("full replacement changed the required current count", replaced.root.Generated.GeneratedCurrent)
		}
		oldResources := make(map[contract.ID]bool, len(retiring))
		for _, entry := range retiring {
			oldResources[entry.Generated.ResourceIncarnationID] = true
		}
		admin, result := openAdministrative(ctx, OpenContext{admission: &replaced.admission}, store)
		if admin == nil || result.Outcome != ObservedCurrent {
			t.Fatal("full replacement did not reopen administratively", result)
		}
		oldGroups := make(map[contract.ID]bool, len(retiring))
		for _, group := range admin.adminIndex.Groups {
			if group.OwnerKind == format.AdministrativeGeneratedDuty && group.DutyKind == contract.GeneratedDutyRetirement &&
				oldResources[group.TargetID] {
				oldGroups[group.GroupID] = true
			}
		}
		if len(oldGroups) != len(retiring) {
			t.Fatal("full replacement lost old retirement owners", len(oldGroups))
		}
		assertCurrent := func(s *StateSession) {
			t.Helper()
			assertConfiguredReplacementSeed(t, opened, s, "a-seed")
			if s.root.Generated.GeneratedCurrent != contract.GeneratedCurrentEntryLimit ||
				len(s.root.Names) != contract.GeneratedCurrentEntryLimit+len(sources) {
				t.Fatal("full replacement exit changed current membership")
			}
			for _, named := range s.root.Names {
				entry := s.valueEntry(named.Slot)
				if named.Name == "a-seed" {
					continue
				}
				want, err := contract.GeneratorIntentDigest(hermeticGeneratorIntent(intents[named.Name]))
				if err != nil || entry == nil || entry.ValueSource != contract.Generated || entry.Generated.Epoch != 2 ||
					entry.Generated.IntentDigest != want {
					t.Fatal("full replacement exit changed current intent", named.Name, err)
				}
				check := env.Custody.Consume(ctx, sessionConsumerSelection(t, s, s.admission.recipient, named.Name), custody.StandardValue)
				if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
					t.Fatal("full replacement current value was not privately readable", named.Name, check)
				}
			}
		}
		assertCapacityConfigurationPreserved(t, opened, replaced)
		assertCurrent(replaced)
		var selectedTargets []contract.ID
		for _, group := range admin.adminIndex.Groups {
			if !oldGroups[group.GroupID] {
				continue
			}
			remaining, scope, err := admin.administrativeWorkClosure(group.GroupID)
			if err == nil && len(scope) == 1 && len(remaining.Groups) == len(admin.adminIndex.Groups)-1 {
				selectedTargets = append(selectedTargets, group.GroupID)
				if len(selectedTargets) == 2 {
					break
				}
			}
		}
		if len(selectedTargets) != 2 {
			t.Fatal("full replacement lacks two independent old retirement exits", len(selectedTargets))
		}
		previous := admin
		var firstReceipt []byte
		var firstOperation contract.ID
		for i, target := range selectedTargets {
			beforeCount, beforeWarnings := len(previous.adminIndex.Groups), previous.root.WarningBits
			candidate, prepared := prepareTestEndSelectedWork(t, previous, ctx, target, env.Trust)
			if candidate == nil || prepared.Outcome != ObservedCurrent {
				t.Fatal("full replacement EndWork preparation", i, prepared)
			}
			if next, result := previous.selectCandidate(ctx, candidate); next == nil || result.Outcome != ObservedCurrent {
				t.Fatal("full replacement EndWork selection", i, result)
			}
			ordinary, result := Open(ctx, OpenContext{admission: &previous.admission}, store)
			if ordinary == nil || result.Outcome != ObservedCurrent || len(ordinary.adminIndex.Groups) != beforeCount-1 ||
				ordinary.root.WarningBits&beforeWarnings != beforeWarnings || ordinary.root.ChildCount > contract.MaxChildPages {
				t.Fatal("full replacement EndWork did not cold-open within reserved space", i, result)
			}
			for _, group := range previous.adminIndex.Groups {
				if (group.GroupID == target) == slices.ContainsFunc(ordinary.adminIndex.Groups,
					func(remaining format.AdministrativeGroup) bool { return remaining.GroupID == group.GroupID }) {
					t.Fatal("full replacement EndWork changed an unrelated owner", i, group.GroupID)
				}
			}
			assertCapacityConfigurationPreserved(t, opened, ordinary)
			assertCurrent(ordinary)
			if i == 0 {
				firstOperation = ordinary.head.EndWork.OperationID
				firstReceipt, result = ordinary.MutationReceipt(ctx, firstOperation)
				if result.Outcome != ObservedCurrent || len(firstReceipt) == 0 {
					t.Fatal("full replacement first exit receipt", result)
				}
			} else {
				body, receiptResult := ordinary.MutationReceipt(ctx, firstOperation)
				if receiptResult.Outcome != ObservedCurrent || !bytes.Equal(body, firstReceipt) {
					t.Fatal("full replacement second exit changed first receipt", receiptResult)
				}
			}
			progress("replacement-exit", i+1, len(selectedTargets))
			fmt.Fprintf(os.Stderr, "full fixture exit=%d children=%d shards=%d groups=%d warnings=%02x\n",
				i+1, ordinary.root.ChildCount, 1+len(ordinary.root.AdministrativeIndexShards),
				len(ordinary.adminIndex.Groups), ordinary.root.WarningBits)
			previous, result = openAdministrative(ctx, OpenContext{admission: &ordinary.admission}, store)
			if previous == nil || result.Outcome != ObservedCurrent {
				t.Fatal("full replacement next administrative predecessor", i, result)
			}
		}
	})
}

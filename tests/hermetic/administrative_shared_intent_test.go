package core

import (
	"bytes"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

const sharedIntentHistoricalFixturePath = "tests/shared/testdata/shared-intent-release/retirement.json"

type sharedIntentHistoricalCapture struct {
	Checkpoint                    processFixture
	Current                       []contract.ValueEntry
	A, B                          contract.ValueEntry
	DutyA, DutyB, Release, Marker contract.ID
	LocationA, LocationB          contract.GeneratorSliceLocation
	Evidence                      sharedIntentReleaseEvidence
	BeforeA                       []contract.ID
}

type sharedIntentRetirementFixture struct {
	env                           fixtureEnvironment
	selected                      *StateSession
	current                       []contract.ValueEntry
	a, b                          contract.ValueEntry
	dutyA, dutyB, release, marker contract.ID
	locationA, locationB          contract.GeneratorSliceLocation
	output                        []contract.NormalOutputBinding
	evidence                      sharedIntentReleaseEvidence
	groups                        []contract.ID
}

func actualSharedIntentRetirementPredecessor(t *testing.T) sharedIntentRetirementFixture {
	t.Helper()
	ctx := t.Context()
	prefix := actualSharedIntentReleasePrefix(t)
	env, before := prefix.env, prefix.selected
	names := []string{"later-a", "later-b"}
	input := generatedWriterPlanInput(t, before, fixtureID(env.Domain, "shared carrier later operation"), names,
		func(name string) []byte { return []byte("later real producer Intent " + name) }, 0, nil)
	before = selectGeneratedWriterBatch(t, env, before, input, "shared carrier later", custody.StandardValue)
	before = generatedLifecycleReopen(t, ctx, before, env.Store)
	assertSharedIntentReleaseEvidence(t, before, prefix.evidence)
	a, b := prefix.entries[0], *before.valueEntry(entrySlot(t, before, names[0]))
	work := mustSelectedGeneratedWork(t, before)
	locationA := work.content.locations[generatedContentKey{contract.GeneratorContentIntent, a.Generated.IntentDigest}]
	locationB := work.content.locations[generatedContentKey{contract.GeneratorContentIntent, b.Generated.IntentDigest}]
	release := work.releases[prefix.original].release.InboxID
	if locationA != prefix.location || locationB.BlobID != contract.Hash(input.declaration) || locationA.BlobID == locationB.BlobID || release.IsZero() {
		t.Fatal("later actual generation did not preserve the two physical Intent blobs")
	}
	var kept []contract.ValueEntry
	for _, named := range before.root.Names {
		if named.Name != a.Name && named.Name != b.Name {
			kept = append(kept, *before.valueEntry(named.Slot))
		}
	}
	proposed := slices.DeleteFunc(before.currentEntryInputs(), func(row ApplyEntryInput) bool { return row.Name == a.Name || row.Name == b.Name })
	target := publicationEngineTarget("a-seed", "shared-carrier-publication")
	target.target.PayloadEncoding = contract.OutputEncodingRaw
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "publication", targets: []outputApplyTarget{target}}},
		routes: []outputApplyRoute{{entryName: "a-seed", destinations: []string{"publication"}}}}
	before = selectAdmittedOutputConfiguration(t, ctx, before, env, env.Custody, proposed, output,
		staticGeneratedHandoffImplementation(t, env.Domain, defaultGeneratedFixtureProfile()))
	assertSharedIntentReleaseEvidence(t, before, prefix.evidence)
	configuration, result := before.currentOutputConfigurationForApply(ctx)
	if result.Outcome != 0 || len(configuration.Bindings) != 1 || configuration.Bindings[0].DestinationID != "publication" || len(configuration.Bindings[0].Targets) != 1 || configuration.Bindings[0].Targets[0].EntryIncarnationID != before.valueEntry(entrySlot(t, before, "a-seed")).Incarnation || !reflect.DeepEqual(configuration.Routes, []contract.OutputRoute{{EntryIncarnationID: before.valueEntry(entrySlot(t, before, "a-seed")).Incarnation, Destinations: []string{"publication"}}}) {
		t.Fatal("selected output is not the exact a-seed-only named route", result)
	}
	dutyA, err := contract.GeneratorDutyID(env.Domain, a.Generated.OriginOperationID, a.Generated.OriginAttemptID, contract.GeneratedDutyRetirement)
	if err != nil {
		t.Fatal(err)
	}
	dutyB, err := contract.GeneratorDutyID(env.Domain, b.Generated.OriginOperationID, b.Generated.OriginAttemptID, contract.GeneratedDutyRetirement)
	if err != nil {
		t.Fatal(err)
	}
	if before.root.Generated.GeneratedCurrent != 2 || before.root.Generated.Retiring != 2 {
		t.Fatal("ordinary removal lost either real retirement")
	}
	f := &fixture{store: requireAdmittedMemoryStore(t, env.Store), trust: env.Trust.(*fixtureTrust), admission: OpenContext{admission: &before.admission}, session: before}
	f.admission.admission.publicationNamespaces = []publicationNamespace{{domain: env.Domain, service: "controlled-provider", physical: "shared-carrier-publication", premise: contract.Hash([]byte("qualified shared carrier fixture namespace"))}}
	p := newPublicationControlledPrivate()
	p.evidence = contract.PublicationUnproved
	publication := publicationInput{names: []string{"a-seed"}, acting: before.admission.recipient, deadline: time.Now().Add(30 * time.Second)}
	published := publicationEnginePlan(t, f, publication, p).execute(ctx, p.callbacks(), publicationEngineCurrent(f))
	if published.state.Outcome != ObservedCurrent || published.summary != contract.PublicationSummaryUnknown || len(published.output.Entries) != 1 || len(published.output.Entries[0].Actions) != 1 {
		t.Fatal("actual publication did not leave one unknown marker", published.state)
	}
	marker := published.output.Entries[0].Actions[0].AttemptID
	publicationEngineReopen(t, f)
	before = f.session
	assertSharedIntentReleaseEvidence(t, before, prefix.evidence)
	for _, entry := range []contract.ValueEntry{a, b} {
		location, mandatory, owners, found := sharedIntentCarrier(t, before, entry.Generated.IntentDigest)
		want := dutyA
		if entry.Name == b.Name {
			want = dutyB
		}
		if !found || mandatory || !slices.Contains(owners, want) || location.Logical().ContentID != entry.Generated.IntentDigest {
			t.Fatal("ordinary handoff lacks exact noncurrent retirement Intent", entry.Name)
		}
	}
	if _, _, err := before.administrativeWorkClosure(marker); err != nil {
		t.Fatal("actual marker is not independently endable", err)
	}
	if len(before.root.Names) != len(kept) || len(kept) != 3 {
		t.Fatal("ordinary handoff changed the complete retained entry set")
	}
	for _, entry := range kept {
		if got := before.valueEntry(entrySlot(t, before, entry.Name)); got == nil || !reflect.DeepEqual(*got, entry) {
			t.Fatal("ordinary handoff changed an independent current entry", entry.Name)
		}
	}
	outputWitness, err := before.generatedOutputTransition(ctx)
	if err != nil {
		t.Fatal("selected passive output source bindings", err)
	}
	return sharedIntentRetirementFixture{env, before, kept, a, b, dutyA, dutyB, release, marker, locationA, locationB, outputWitness.Bindings, prefix.evidence, sharedIntentGroupIDs(t, before)}
}

func sharedIntentCarrier(t *testing.T, s *StateSession, intent contract.ID) (contract.GeneratorSliceLocation, bool, []contract.ID, bool) {
	t.Helper()
	return sharedIntentContentCarrier(t, s, contract.GeneratorContentIntent, intent)
}

func sharedIntentContentCarrier(t *testing.T, s *StateSession, kind uint8, content contract.ID) (contract.GeneratorSliceLocation, bool, []contract.ID, bool) {
	t.Helper()
	var result contract.GeneratorSliceLocation
	var mandatory, found bool
	var owners []contract.ID
	for _, page := range s.adminIndex.Pages {
		if !page.ReadRequired {
			continue
		}
		view, err := s.administrativeSelectedSupportPage(page)
		if err != nil {
			t.Fatal(err)
		}
		logical := 0
		for _, span := range page.Spans {
			for range span.Count {
				row := contract.SupportRecord(view.Records[logical])
				logical++
				carrier, match, err := snapshotSliceRecord(row, s.root.Domain, s.adminIndex.SliceSnapshot)
				if err != nil {
					t.Fatal("selected Slice carrier", err)
				}
				if !match {
					continue
				}
				location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
				if err != nil {
					t.Fatal(err)
				}
				if location.ContentKind != kind || location.ContentID != content {
					continue
				}
				if found {
					t.Fatal("duplicate selected logical content carrier")
				}
				result, mandatory, found = location, span.Mandatory, true
				for _, owner := range span.GroupIndexes {
					owners = append(owners, s.adminIndex.Groups[owner].GroupID)
				}
			}
		}
	}
	return result, mandatory, owners, found
}

func endSharedIntentWork(t *testing.T, s *StateSession, id contract.ID, trust contract.Trust) *StateSession {
	t.Helper()
	beforeGroups := sharedIntentGroupIDs(t, s)
	beforeReceipts, err := s.receiptWindowsFromAdministrativeSupport()
	if err != nil || len(beforeReceipts.Successes) >= contract.MutationReceiptWindowLimit {
		t.Fatal("small exit receipt predecessor", err)
	}
	candidate, result := prepareTestEndSelectedWork(t, s, t.Context(), id, trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("actual shared Intent exit preparation", id, result)
	}
	next, result := s.selectCandidate(t.Context(), candidate)
	if next == nil || result.Outcome != ObservedCurrent {
		t.Fatal("actual shared Intent exit selection", id, result)
	}
	next, result = openAdministrative(t.Context(), OpenContext{admission: &next.admission}, s.store)
	if next == nil || result.Outcome != ObservedCurrent {
		t.Fatal("actual exit administrative cold Open", result)
	}
	afterReceipts, err := next.receiptWindowsFromAdministrativeSupport()
	if err != nil || len(afterReceipts.Successes) != len(beforeReceipts.Successes)+1 || !reflect.DeepEqual(afterReceipts.Failures, beforeReceipts.Failures) {
		t.Fatal("small exit receipt window delta", err)
	}
	for _, old := range beforeReceipts.Successes {
		if !slices.ContainsFunc(afterReceipts.Successes, func(row contract.CompactMutationReceipt) bool { return reflect.DeepEqual(row, old) }) {
			t.Fatal("small exit changed prior success receipt")
		}
	}
	if next.head.EndWork == nil {
		t.Fatal("actual exit lost signed subject")
	}
	q := next.head.EndWork
	if !slices.ContainsFunc(afterReceipts.Successes, func(row contract.CompactMutationReceipt) bool {
		return row.OperationID == q.OperationID && row.OperationKind == contract.OperationEndSelectedWork && row.AdministrativeTargetID == q.TargetID && row.AdministrativeDisposition == q.RequestCoreDigest && row.WarningBits == uint64(next.root.WarningBits) && row.AdministrativeWarningChanges == next.root.WarningBits&^s.root.WarningBits
	}) {
		t.Fatal("actual exit receipt lost exact disposition or warnings")
	}
	assertSharedIntentGroupIDs(t, next, beforeGroups, id)
	return next
}

func assertSharedIntentRetirement(t *testing.T, fixture sharedIntentRetirementFixture, selected *StateSession, legacy bool) {
	t.Helper()
	assertSharedIntentGroupIDs(t, selected, fixture.groups, fixture.dutyA)
	assertSharedIntentReleaseEvidence(t, selected, fixture.evidence)
	location, mandatory, owners, found := sharedIntentCarrier(t, selected, fixture.a.Generated.IntentDigest)
	if legacy {
		if !found || location != fixture.locationA || mandatory || !slices.Equal(owners, []contract.ID{fixture.release}) {
			t.Fatal("historical exit lacks exact release-only A Intent")
		}
	} else if found {
		t.Fatal("modern exit retained obsolete release-only A Intent")
	}
	location, mandatory, owners, found = sharedIntentCarrier(t, selected, fixture.b.Generated.IntentDigest)
	if !found || location != fixture.locationB || mandatory || !slices.Equal(owners, []contract.ID{fixture.dutyB}) {
		t.Fatal("exit changed exact noncurrent B retirement Intent")
	}
	for _, entry := range fixture.current {
		if got := selected.valueEntry(entrySlot(t, selected, entry.Name)); got == nil || !reflect.DeepEqual(*got, entry) {
			t.Fatal("exit changed exact current entry", entry.Name)
		}
	}
	for _, id := range []contract.ID{fixture.release, fixture.dutyB, fixture.marker} {
		if !slices.ContainsFunc(selected.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == id }) {
			t.Fatal("exit lost independent group", id)
		}
	}
	if slices.ContainsFunc(selected.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == fixture.dutyA }) {
		t.Fatal("A retirement survived its actual exit")
	}
}

// full_only: false
func TestAdministrativeExitPrunesObsoleteSharedReleaseIntent(t *testing.T) {
	f := actualSharedIntentRetirementPredecessor(t)
	selected := endSharedIntentWork(t, f.selected, f.dutyA, f.env.Trust)
	assertSharedIntentRetirement(t, f, selected, false)
	_, ownershipChanged, err := selected.administrativeDispositionPages()
	if err != nil || ownershipChanged {
		t.Fatal("modern publication closure changed ownership", err)
	}
	proved, err := selected.publicationExitNeedsNoIntentCompaction(t.Context())
	if err != nil || !proved {
		t.Fatal("modern publication closure lost its unchanged-ownership shortcut", err)
	}
	selected = endSharedIntentWork(t, selected, f.marker, f.env.Trust)
	assertSharedIntentGroupIDs(t, selected, f.groups, f.dutyA, f.marker)
	assertSharedIntentReleaseEvidence(t, selected, f.evidence)
	for _, id := range []contract.ID{f.release, f.dutyB} {
		if !slices.ContainsFunc(selected.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == id }) {
			t.Fatal("publication exit lost independent group", id)
		}
	}
	for _, entry := range f.current {
		if got := selected.valueEntry(entrySlot(t, selected, entry.Name)); got == nil || !reflect.DeepEqual(*got, entry) {
			t.Fatal("publication exit changed exact current entry", entry.Name)
		}
	}
	if _, _, _, found := sharedIntentCarrier(t, selected, f.a.Generated.IntentDigest); found {
		t.Fatal("publication exit restored obsolete A Intent")
	}
}

type sharedIntentReleaseEvidence struct {
	Original      contract.ID
	Release       []byte
	Attempt       []byte
	GraphLocation contract.GeneratorSliceLocation
	Graph         []byte
}

func sharedIntentPrefixEvidence(t *testing.T, selected *StateSession, original contract.ID) sharedIntentReleaseEvidence {
	t.Helper()
	work := mustSelectedGeneratedWork(t, selected)
	mapping, ok := work.releases[original]
	if !ok {
		t.Fatal("selected prefix lost original release")
	}
	bundle, err := work.retainedGraph(mapping.attempt.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	graphID, err := contract.GeneratorGraphID(bundle.Header, bundle.ValueEntryPlans, bundle.Lineages, bundle.Edges)
	if err != nil {
		t.Fatal(err)
	}
	location := work.content.locations[generatedContentKey{contract.GeneratorContentGraph, graphID}]
	graph, err := work.readSelectedSlice(t.Context(), contract.GeneratorContentGraph, graphID, contract.GeneratorGraphMaxLength)
	if err != nil {
		t.Fatal(err)
	}
	attempt := work.records[generatedRecordKey{contract.GeneratedAttemptSupportKind, original}]
	release := work.records[generatedRecordKey{contract.PendingInboxReleaseSupportKind, mapping.release.InboxID}]
	if len(attempt.Body) == 0 || len(release.Body) == 0 {
		t.Fatal("selected prefix omitted immutable release provenance")
	}
	return sharedIntentReleaseEvidence{original, bytes.Clone(release.Body), bytes.Clone(attempt.Body), location, bytes.Clone(graph)}
}

func assertSharedIntentReleaseEvidence(t *testing.T, selected *StateSession, want sharedIntentReleaseEvidence) {
	t.Helper()
	release, err := contract.InspectPendingInboxReleaseRecord(want.Release)
	if err != nil {
		t.Fatal(err)
	}
	var rows []contract.SupportRecord
	for _, page := range selected.adminIndex.Pages {
		body, result := selected.readObject(t.Context(), page.Ref)
		if result.Outcome != 0 {
			t.Fatal("selected provenance page", result)
		}
		physical, err := format.InspectRequiredSupportPage(body)
		if err != nil || physical.Domain != page.Ref.Domain || physical.Object != page.Ref.Object || physical.Index != page.Ref.Index {
			t.Fatal("selected provenance page identity", err)
		}
		for _, span := range page.Spans {
			end := uint32(span.First) + uint32(span.Count)
			if end > uint32(len(physical.Records)) {
				t.Fatal("selected provenance span exceeds physical page")
			}
			for _, row := range physical.Records[uint32(span.First):end] {
				rows = append(rows, contract.SupportRecord(row))
			}
		}
	}
	for _, expected := range []contract.SupportRecord{
		{Kind: contract.GeneratedAttemptSupportKind, RecordID: want.Original, Body: want.Attempt},
		{Kind: contract.PendingInboxReleaseSupportKind, RecordID: release.InboxID, Body: want.Release},
	} {
		count := 0
		for _, actual := range rows {
			if actual.Kind == expected.Kind && actual.RecordID == expected.RecordID {
				count++
				if !bytes.Equal(actual.Body, expected.Body) {
					t.Fatal("independent original release provenance changed", expected.Kind)
				}
			}
		}
		if count != 1 {
			t.Fatal("independent original release provenance is not uniquely selected", expected.Kind, count)
		}
	}
	location, _, _, found := sharedIntentContentCarrier(t, selected, contract.GeneratorContentGraph, want.GraphLocation.ContentID)
	if !found || location.Logical() != want.GraphLocation.Logical() {
		t.Fatal("independent original graph lost its exact logical carrier")
	}
	graph, err := contract.InspectGeneratedImmutableSlice(selected.root.Domain, selected.adminIndex.SliceSnapshot, rows, location, contract.GeneratorGraphMaxLength)
	if err != nil || !bytes.Equal(graph, want.Graph) {
		t.Fatal("independent original operation graph changed", err)
	}
}

func sharedIntentGroupIDs(t *testing.T, selected *StateSession) []contract.ID {
	t.Helper()
	ids := make([]contract.ID, len(selected.adminIndex.Groups))
	for i, group := range selected.adminIndex.Groups {
		ids[i] = group.GroupID
	}
	slices.SortFunc(ids, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	for i, id := range ids {
		if id.IsZero() || i != 0 && ids[i-1] == id {
			t.Fatal("selected group IDs are not unique and nonzero")
		}
	}
	return ids
}

func assertSharedIntentGroupIDs(t *testing.T, selected *StateSession, want []contract.ID, ended ...contract.ID) {
	t.Helper()
	want = slices.Clone(want)
	for _, id := range ended {
		position := slices.Index(want, id)
		if position < 0 {
			t.Fatal("expected exit target absent from predecessor group set", id)
		}
		want = slices.Delete(want, position, position+1)
	}
	if !slices.Equal(sharedIntentGroupIDs(t, selected), want) {
		t.Fatal("exit changed the complete independent group set")
	}
}

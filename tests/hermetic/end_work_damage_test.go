package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

type damagedWorkFixtureRefs struct {
	configuration format.Ref
	owners        [2]format.Ref
}

func damagedWorkFixture(t *testing.T, ctx context.Context) (fixtureEnvironment, *StateSession, format.AdministrativeIndex, format.Root, damagedWorkFixtureRefs) {
	t.Helper()
	env := memoryScenarioEnvironmentMode(t, true)
	env.Context = ctx
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	s := run.suppliedSelection(f, []ApplyEntryInput{suppliedSecret(t, env, "kept", "damaged current supplied source", custody.StandardValue)})
	if s.root.SecretCount != 1 || s.root.AccessRecordCount == 0 || len(s.accessRecords()) == 0 ||
		len(s.root.CurrentAccess.Core.AccessPageRefs) == 0 || s.valueEntry(0) == nil || s.valueEntry(0).ConfidentialityClass != format.Secret {
		t.Fatal("damaged fixture lacks a real Secret current value and nonempty current access")
	}
	// Initialize retains one receipt and its index fragment. The first real
	// supplied transition separates that history from the exact output slice.
	// All three mandatory rows survive into the damaged-work fixture.
	windows, err := s.receiptWindows(ctx)
	if err != nil || len(windows.Successes) != 1 || len(windows.Failures) != 0 ||
		windows.Successes[0].OperationKind != contract.OperationInitializeDomain ||
		len(s.root.RequiredSupport) != 3 || len(s.adminIndex.Pages) != 3 ||
		s.root.RequiredSupportRecordCount != 3 || len(s.adminIndex.Groups) != 0 ||
		s.root.OutputConfiguration.SliceCount != 1 || len(s.root.Generated.Fragments) != 1 {
		t.Fatal("damaged fixture lacks its exact configuration/initialization-history base", err)
	}
	receiptIndex, err := s.receiptIndexID()
	if err != nil {
		t.Fatal("damaged fixture initialization receipt index", err)
	}
	fragment, err := contract.GeneratorFragmentID(receiptIndex, 0)
	if err != nil {
		t.Fatal("damaged fixture initialization receipt fragment", err)
	}
	configuration, err := contract.OutputConfigurationSliceID(s.root.Domain, s.root.OutputConfiguration.ConfigurationDigest, 0)
	if err != nil {
		t.Fatal("damaged fixture exact configuration identity", err)
	}
	var refs damagedWorkFixtureRefs
	expectedRows := map[uint8]contract.ID{
		contract.OutputConfigurationSliceSupportKind: configuration,
		contract.MutationReceiptSupportKind:          windows.Successes[0].OperationID,
		contract.GeneratedFragmentSupportKind:        fragment,
	}
	used := make(map[uint16]bool)
	for i, page := range s.adminIndex.Pages {
		if page.Ref != s.root.RequiredSupport[i] || page.ReadRequired || len(page.Rows) != 1 ||
			len(page.Spans) != 1 || page.Spans[0].First != 0 || page.Spans[0].Count != 1 ||
			!page.Spans[0].Mandatory || len(page.Spans[0].GroupIndexes) != 0 {
			t.Fatal("damaged fixture mandatory base page differs")
		}
		row := page.Rows[0]
		expected, present := expectedRows[row.Kind]
		if !present || row.RecordID != expected {
			t.Fatal("damaged fixture mandatory row identity differs or repeats")
		}
		delete(expectedRows, row.Kind)
		if row.Kind == contract.OutputConfigurationSliceSupportKind {
			refs.configuration = page.Ref
		}
		if row.Kind == contract.GeneratedFragmentSupportKind {
			location := s.root.Generated.Fragments[0]
			if location.BlobID != receiptIndex || location.FragmentIndex != 0 || location.SupportPageIndex != page.Ref.Index {
				t.Fatal("damaged fixture initialization receipt carrier differs")
			}
		}
		used[page.Ref.Index] = true
	}
	if len(expectedRows) != 0 {
		t.Fatal("damaged fixture lacks one exact row of each mandatory base kind")
	}
	index := s.adminIndex
	index.Object = testID("damaged work index")
	index.Pages = slices.Clone(s.adminIndex.Pages)
	index.Groups = nil
	for i, kind := range []uint8{contract.GeneratedDutySupportKind, contract.GeneratedHazardSupportKind} {
		id := contract.ID{byte(i + 1)}
		row := format.AdministrativeRowSummary{Kind: kind, RecordID: id, BodyLength: 87}
		item := append([]byte{kind}, id[:]...)
		item = binary.BigEndian.AppendUint32(item, row.BodyLength)
		group := format.AdministrativeGroup{GroupID: id, OwnerID: id, TargetID: id,
			OwnerKind:    format.AdministrativeGeneratedDuty + uint8(i),
			Affected:     contract.GeneratorDescriptor{Digest: testID("damaged affected selection"), Length: 4},
			Dependencies: contract.GeneratorDescriptor{Digest: testID("damaged retained dependencies"), Length: 4},
			Disposable:   administrativeDescriptor("selected-disposable", item), ChargedPages: 1, ChargedBytes: 124,
			SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing}
		if i == 0 {
			group.DutyKind = contract.GeneratedDutyCreate
		} else {
			group.SelectedEvidenceSummary = contract.AdministrativeEvidencePossibleLive
		}
		var physical uint16
		for used[physical] {
			physical++
		}
		used[physical] = true
		ref := format.Ref{Kind: contract.RequiredSupportKind, Format: format.Version, Domain: s.root.Domain,
			Object: testID(string([]byte{'d', byte(i)})), Index: physical,
			Digest: testID(string([]byte{'h', byte(i)})), Length: 199}
		refs.owners[i] = ref
		index.Groups = append(index.Groups, group)
		index.Pages = append(index.Pages, format.AdministrativePage{Ref: ref,
			Spans: []format.AdministrativeSpan{{First: 0, Count: 1, GroupIndexes: []uint16{uint16(i)}}},
			Rows:  []format.AdministrativeRowSummary{row}})
	}
	slices.SortFunc(index.Pages, func(a, b format.AdministrativePage) int { return int(a.Ref.Index) - int(b.Ref.Index) })
	root := s.root
	root.Snapshot, root.Transition = testID("damaged work snapshot"), testID("damaged work transition")
	root.RequiredSupport = nil
	for _, page := range index.Pages {
		root.RequiredSupport = append(root.RequiredSupport, page.Ref)
	}
	root.RequiredSupportRecordCount = s.root.RequiredSupportRecordCount + uint32(len(refs.owners))
	root.Generated.Duties, root.Generated.Hazards = 1, 1
	root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, []contract.ID{{1}, {2}})
	if err != nil {
		t.Fatal("damaged fixture live owners", err)
	}
	return env, s, index, root, refs
}

// The test signs a complete index/Root/HEAD image. Optional work objects are
// deliberately absent; their authenticated row summaries remain selected.
func putSignedDamagedWork(t *testing.T, ctx context.Context, env fixtureEnvironment, before *StateSession,
	root format.Root, shards []format.AdministrativeIndexPage) {
	t.Helper()
	if len(shards) == 0 {
		t.Fatal("signed damaged fixture has no index")
	}
	root.AdministrativeIndex, root.AdministrativeIndexShards = shards[0].Ref, nil
	for _, shard := range shards[1:] {
		root.AdministrativeIndexShards = append(root.AdministrativeIndexShards, shard.Ref)
	}
	counted := StateSession{root: root}
	counted.recountChildren()
	root = counted.root
	rootBody, err := format.EncodeRoot(root)
	if err != nil {
		t.Fatal("signed damaged root", err)
	}
	rootRef, err := format.Reference(format.RootKind, root.Domain, root.Snapshot, 0, rootBody)
	if err != nil {
		t.Fatal(err)
	}
	head := before.head
	head.Core.PreviousRevision, head.Core.PreviousDigest, head.Core.PreviousToken = before.head.Core.Revision, contract.Hash(before.body), before.token
	head.Core.Revision, head.Core.Root = testID("damaged work revision"), rootRef
	coreBody, err := format.EncodeHeadCore(head.Core)
	if err != nil {
		t.Fatal(err)
	}
	head.Subject.HeadCore, head.Subject.HeadCoreLength = contract.Hash(coreBody), uint32(len(coreBody))
	condition, err := contract.MatchHeadCondition(head.Core.PreviousToken)
	if err != nil {
		t.Fatal(err)
	}
	planBody, err := format.EncodeConditionalPlan(format.ConditionalPlan{Family: head.Core.PreviousToken.Family,
		Store: head.Core.Store, Coordinate: head.Core.Coordinate, NonBody: head.Core.NonBody,
		Condition: condition, HeadCore: head.Subject.HeadCore, HeadCoreLength: head.Subject.HeadCoreLength})
	if err != nil {
		t.Fatal(err)
	}
	head.Subject.ConditionalPlan = contract.Hash(planBody)
	head.Subject.Request = requestCommitment(head.Core, head.Subject)
	request, err := contract.NewLifecycleRequest(head.Subject)
	if err != nil {
		t.Fatal(err)
	}
	signed := env.Trust.Sign(ctx, request)
	if signed.Reason != contract.ReasonNone {
		t.Fatal("signed damaged lifecycle proof", signed.Reason)
	}
	head.AuthorizationSignature = signed.Signature
	body, err := format.EncodeHead(head)
	if err != nil {
		t.Fatal(err)
	}
	put := func(ref format.Ref, body []byte) {
		t.Helper()
		if err := format.CheckReference(ref, body); err != nil {
			t.Fatal("signed damaged complete reference", err)
		}
		key, err := format.Key(before.admission.store.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		if err := env.Put(ctx, key, body); err != nil {
			t.Fatal(err)
		}
	}
	for _, shard := range shards {
		put(shard.Ref, shard.Body)
	}
	put(rootRef, rootBody)
	if err := env.Put(ctx, before.admission.store.HeadKey, body); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestEndWorkSelectsTwoDamagedDisposableGroupsWithoutRepair(t *testing.T) {
	ctx := t.Context()
	env, current, index, root, refs := damagedWorkFixture(t, ctx)
	shards, err := format.EncodeAdministrativeIndexPages(index)
	if err != nil {
		t.Fatal("two damaged index pages", err)
	}
	putSignedDamagedWork(t, ctx, env, current, root, shards)
	store := env.Store.(*memoryStore)
	admission := OpenContext{admission: &current.admission}
	admin, result := openAdministrative(ctx, admission, store)
	if admin == nil || result.Outcome != ObservedCurrent || !reflect.DeepEqual(admin.adminIndex.Groups, index.Groups) ||
		!reflect.DeepEqual(admin.adminIndex.Pages, index.Pages) {
		t.Fatal("signed independent damaged groups did not cold-open", result)
	}
	if ordinary, result := Open(ctx, admission, store); ordinary != nil || result.Outcome != EvidenceUnavailable {
		t.Fatal("ordinary reader accepted two absent selected pages", result)
	}
	public, private := env.Custody.Calls()
	for step, target := range index.Groups {
		before := admin
		// Each fixture group owns exactly its own row and has no dependency.
		for _, group := range before.adminIndex.Groups {
			if len(group.RelatedGroupIndexes) != 0 {
				t.Fatal("damaged fixture has an incoming or outgoing dependency")
			}
		}
		_, scope, err := before.administrativeWorkClosure(target.GroupID)
		if err != nil || len(scope) != 1 || !reflect.DeepEqual(scope[0], target) {
			t.Fatal("damaged group closure differs from the known one-row scope", err)
		}
		windows, err := before.receiptWindowsFromAdministrativeSupport()
		if err != nil {
			t.Fatal(err)
		}
		candidate, result := prepareTestEndSelectedWork(t, before, ctx, target.GroupID, env.Trust)
		if candidate == nil || result.Outcome != ObservedCurrent || candidate.firstSend != nil {
			t.Fatal("damaged group preparation required absent work detail", result)
		}
		if selected, result := before.selectCandidate(ctx, candidate); selected == nil || result.Outcome != ObservedCurrent {
			t.Fatal("damaged group selection", result)
		}
		admin, result = openAdministrative(ctx, admission, store)
		if admin == nil || result.Outcome != ObservedCurrent {
			t.Fatal("damaged successor administrative cold Open", result)
		}
		if !reflect.DeepEqual(admin.currentEntryInputs(), current.currentEntryInputs()) ||
			!reflect.DeepEqual(admin.accessRecords(), current.accessRecords()) ||
			!reflect.DeepEqual(admin.root.CurrentAccess, current.root.CurrentAccess) ||
			!reflect.DeepEqual(admin.root.ValueEntryPages, current.root.ValueEntryPages) ||
			!reflect.DeepEqual(admin.root.Recipients, current.root.Recipients) ||
			admin.root.ValueEntryCount != current.root.ValueEntryCount || admin.root.AccessRecordCount != current.root.AccessRecordCount ||
			admin.root.SecretCount != current.root.SecretCount || admin.root.RawBytes != current.root.RawBytes || admin.root.MembershipCount != current.root.MembershipCount {
			t.Fatal("damaged exit changed exact current values, membership or access")
		}
		warning := before.root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
		q := admin.head.EndWork
		// One ended ID: u32 count, u32 length=32, ID, under the fixed
		// ENKV/admin-descriptor/v1/ended-groups NUL-prefixed framing.
		body := binary.BigEndian.AppendUint32(nil, 1)
		body = binary.BigEndian.AppendUint32(body, 32)
		body = append(body, target.GroupID[:]...)
		digest := sha256.Sum256(append([]byte("ENKV/admin-descriptor/v1/ended-groups\x00"), body...))
		dependent := contract.GeneratorDescriptor{Digest: contract.ID(digest), Length: 40, Count: 1}
		if q == nil || q.TargetGroupID != target.GroupID || q.TargetOwnerID != target.OwnerID || q.TargetKind != target.OwnerKind ||
			q.TargetID != target.TargetID || q.SelectedEvidenceSummary != target.SelectedEvidenceSummary || q.DependentGroups != dependent ||
			q.PredecessorRevisionID != before.head.Core.Revision || q.PredecessorFullHEADDigest != contract.Hash(before.body) || q.PredecessorToken != before.token ||
			q.BeforeWarningBits != before.root.WarningBits || q.AfterWarningBits != warning || admin.root.WarningBits != warning ||
			q.BeforeChildCount != uint16(before.root.ChildCount) || q.AfterChildCount != uint16(admin.root.ChildCount) ||
			q.BeforeChildBytes != before.root.ChildEncodedBytes || q.AfterChildBytes != admin.root.ChildEncodedBytes {
			t.Fatal("damaged exit lost exact signed target, scope, warnings or charge")
		}
		got, err := admin.receiptWindowsFromAdministrativeSupport()
		if err != nil || len(got.Successes) != len(windows.Successes)+1 ||
			!slices.Equal(got.Successes[:len(windows.Successes)], windows.Successes) || !slices.Equal(got.Failures, windows.Failures) {
			t.Fatal("damaged exit changed prior receipt windows", err)
		}
		receipt := got.Successes[len(got.Successes)-1]
		if receipt.OperationKind != contract.OperationEndSelectedWork || receipt.OperationID != q.OperationID || receipt.StateResult != contract.ReceiptStateWorkEnded ||
			receipt.EffectSummary != contract.ReceiptEffectNotApplicable || receipt.CanonicalOutcome != contract.ReceiptCanonicalSelected ||
			receipt.AdministrativeTargetKind != target.OwnerKind || receipt.AdministrativeTargetID != target.TargetID ||
			receipt.AdministrativeOriginalEvidence != target.SelectedEvidenceSummary || receipt.WarningBits != uint64(warning) ||
			receipt.AdministrativeWarningChanges != warning&^before.root.WarningBits || receipt.PredecessorRevisionID != before.head.Core.Revision ||
			receipt.ObservedRevisionID != admin.head.Core.Revision {
			t.Fatal("damaged exit receipt lost the exact disposition")
		}
		for _, ref := range refs.owners {
			key, err := format.Key(current.admission.store.Prefix, ref)
			if err != nil {
				t.Fatal(err)
			}
			if _, present := store.objects[key]; present {
				t.Fatal("administrative exit restored an absent work object")
			}
		}
		if !slices.Contains(admin.root.RequiredSupport, refs.configuration) || admin.root.OutputConfiguration != current.root.OutputConfiguration {
			t.Fatal("damaged exit changed the mandatory configuration page or declaration")
		}
		if slices.Contains(admin.root.RequiredSupport, refs.owners[step]) {
			t.Fatal("ended group retained its exclusive absent page")
		}
		if step == 0 {
			position := slices.IndexFunc(index.Pages, func(page format.AdministrativePage) bool { return page.Ref == refs.owners[1] })
			if position < 0 {
				t.Fatal("remaining damaged owner page absent")
			}
			remainingPage := index.Pages[position]
			remainingPage.Spans = []format.AdministrativeSpan{{First: 0, Count: 1, GroupIndexes: []uint16{0}}}
			if len(admin.adminIndex.Groups) != 1 || !reflect.DeepEqual(admin.adminIndex.Groups[0], index.Groups[1]) ||
				!slices.ContainsFunc(admin.adminIndex.Pages, func(page format.AdministrativePage) bool { return reflect.DeepEqual(page, remainingPage) }) {
				t.Fatal("first exit changed the other damaged group, descriptor or physical span")
			}
			if ordinary, result := Open(ctx, admission, store); ordinary != nil || result.Outcome != EvidenceUnavailable {
				t.Fatal("ordinary Open accepted remaining absent work", result)
			}
		} else if len(admin.adminIndex.Groups) != 0 || slices.Contains(admin.root.RequiredSupport, refs.owners[0]) ||
			admin.root.Generated.Duties != 0 || admin.root.Generated.Hazards != 0 {
			t.Fatal("second exit retained an ended damaged owner")
		}
	}
	ordinary, result := Open(ctx, admission, store)
	if ordinary == nil || result.Outcome != ObservedCurrent || !bytes.Equal(ordinary.body, admin.body) || ordinary.token != admin.token {
		t.Fatal("ordinary cold Open did not accept the complete final successor", result)
	}
	if p, k := env.Custody.Calls(); p != public || k != private {
		t.Fatal("damaged administrative exits invoked a custody key route")
	}
	selection := fixtureConsumerSelection(t, ctx, env, current.admission.recipient, "kept")
	check := env.Custody.Consume(ctx, selection, custody.StandardValue)
	if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched || check.SinkCalls != 1 ||
		len(check.KeyUses) != 1 || check.KeyUses[0].SubjectID != current.admission.recipient {
		t.Fatal("retained Secret current value lost its actual private consumption route", check)
	}
}

// full_only: false
func TestAdministrativeReaderRefusesSignedMalformedWork(t *testing.T) {
	for _, damage := range []string{"valid_control", "duplicate_opaque_row", "wrong_owner_row", "wrong_disposable_commitment", "invalid_dependency"} {
		t.Run(damage, func(t *testing.T) {
			ctx := t.Context()
			env, before, index, root, refs := damagedWorkFixture(t, ctx)
			ownerPages := [2]int{}
			for i, ref := range refs.owners {
				ownerPages[i] = slices.IndexFunc(index.Pages, func(page format.AdministrativePage) bool { return page.Ref == ref })
				if ownerPages[i] < 0 {
					t.Fatal("damaged owner page absent before semantic damage")
				}
			}
			// Keep each real owner summary and add one independently named opaque
			// Attempt summary per page. A duplicate then leaves both owners intact.
			refreshDisposable := func(i int) {
				var items [][]byte
				for _, row := range index.Pages[ownerPages[i]].Rows {
					item := append([]byte{row.Kind}, row.RecordID[:]...)
					items = append(items, binary.BigEndian.AppendUint32(item, row.BodyLength))
				}
				index.Groups[i].Disposable = administrativeDescriptor("selected-disposable", items...)
			}
			for i := range index.Groups {
				page := &index.Pages[ownerPages[i]]
				page.Ref.Length = 323 // 75-byte header + two (37+87)-byte rows.
				page.Spans[0].Count = 2
				page.Rows = append(page.Rows, format.AdministrativeRowSummary{
					Kind: contract.GeneratedAttemptSupportKind, RecordID: contract.ID{byte(3 + i)}, BodyLength: 87})
				index.Groups[i].ChargedBytes = 248
				refreshDisposable(i)
			}
			root.RequiredSupport = nil
			for _, page := range index.Pages {
				root.RequiredSupport = append(root.RequiredSupport, page.Ref)
			}
			root.RequiredSupportRecordCount += uint32(len(refs.owners))
			root.Generated.Attempts = 2
			if damage == "invalid_dependency" {
				index.Groups[1].RelatedGroupIndexes = []uint16{0}
			}
			shards, err := format.EncodeAdministrativeIndexPages(index)
			if err != nil {
				t.Fatal("signed malformed-work control encoding", err)
			}
			putSignedDamagedWork(t, ctx, env, before, root, shards)
			store := env.Store.(*memoryStore)
			admission := OpenContext{admission: &before.admission}
			if valid, result := openAdministrative(ctx, admission, store); valid == nil || result.Outcome != ObservedCurrent {
				t.Fatal("signed valid work control did not cold-open", result)
			}
			if damage != "valid_control" {
				if damage == "invalid_dependency" {
					logical, err := format.EncodeAdministrativeIndex(index)
					if err != nil || len(shards) != 1 {
						t.Fatal("dependency control framing", err)
					}
					// Logical header: tag/version7, IDs96, two escape words4,
					// schema2, group/page counts4: 113 bytes, then two fixed
					// 247-byte groups. The second group's first u16 edge
					// is at607. Replace its valid edge to0 with a self-edge1.
					const edge = 7 + 3*32 + 2 + 2 + 2 + 2 + 2 + 2*247
					const payload = 7 + 1 + 2*32 + 2 + 2 + 4 + 32 + 4
					if binary.BigEndian.Uint16(logical[edge:]) != 0 || len(shards[0].Body) != payload+len(logical) ||
						!bytes.Equal(shards[0].Body[payload:], logical) {
						t.Fatal("dependency edge or shard framing differs from its independent offsets")
					}
					logical = bytes.Clone(logical)
					binary.BigEndian.PutUint16(logical[edge:], 1)
					if _, err := format.DecodeAdministrativeIndex(logical); err == nil {
						t.Fatal("intended self-dependency damage was not established")
					}
					body := bytes.Clone(shards[0].Body)
					copy(body[payload:], logical)
					digest := sha256.Sum256(logical)
					copy(body[80:112], digest[:]) // Complete logical hash in the shard header.
					ref, err := format.Reference(contract.AdministrativeIndexKind, root.Domain, index.Object, 0, body)
					if err != nil {
						t.Fatal("damaged dependency shard reference", err)
					}
					shards[0] = format.AdministrativeIndexPage{Ref: ref, Body: body}
				} else {
					switch damage {
					case "duplicate_opaque_row":
						index.Pages[ownerPages[1]].Rows[1] = index.Pages[ownerPages[0]].Rows[1]
						refreshDisposable(1)
					case "wrong_owner_row":
						index.Pages[ownerPages[1]].Rows[0].RecordID = contract.ID{9}
						refreshDisposable(1)
					case "wrong_disposable_commitment":
						index.Groups[1].Disposable.Digest[0] ^= 1
					}
					shards, err = format.EncodeAdministrativeIndexPages(index)
					if err != nil {
						t.Fatal("semantic damage did not form a signed codec-valid index", err)
					}
				}
				putSignedDamagedWork(t, ctx, env, before, root, shards)
			}
			trust := env.Trust.(*fixtureTrust)
			creates, cas, signs := store.creates, store.cas, trust.signs
			public, private := env.Custody.Calls()
			selected := store.objects[before.admission.store.HeadKey]
			image, result := openAdministrative(ctx, admission, store)
			if damage == "valid_control" {
				if image == nil || result.Outcome != ObservedCurrent {
					t.Fatal("signed valid control refused", result)
				}
			} else {
				wantReason := InvalidRelation
				if damage == "invalid_dependency" {
					wantReason = InvalidReference
				}
				if image != nil || result.Outcome != IntegrityFailure || result.Reason != wantReason {
					t.Fatal("cold administrative reader accepted signed malformed work", result)
				}
			}
			if p, k := env.Custody.Calls(); p != public || k != private || store.creates != creates || store.cas != cas || trust.signs != signs ||
				!reflect.DeepEqual(store.objects[before.admission.store.HeadKey], selected) {
				t.Fatal("signed administrative observation reached a private, signing or write effect")
			}
		})
	}
}

// full_only: false
func TestAdministrativeReaderRefusesMissingAccessPage(t *testing.T) {
	ctx := t.Context()
	env, selected, _, _ := generatedAuthenticatedDeleteHazardFixture(t, true, 0)
	env.Custody.RetireGenerated()
	store := env.Store.(*memoryStore)
	if len(selected.root.CurrentAccess.Core.AccessPageRefs) == 0 {
		t.Fatal("actual selected generated state has no current access page")
	}
	ref := selected.root.CurrentAccess.Core.AccessPageRefs[0]
	key, err := format.Key(selected.admission.store.Prefix, ref)
	if err != nil {
		t.Fatal(err)
	}
	missing, found := store.objects[key]
	if !found || format.CheckReference(ref, missing.Body) != nil {
		t.Fatal("current access-page damage lacks exact authenticated bytes")
	}
	delete(store.objects, key)
	trust := env.Trust.(*fixtureTrust)
	creates, cas, signs := store.creates, store.cas, trust.signs
	public, private := env.Custody.Calls()
	head := store.objects[selected.admission.store.HeadKey]
	admission := OpenContext{admission: &selected.admission}
	if image, result := openAdministrative(ctx, admission, store); image != nil || result.Outcome != EvidenceUnavailable || result.Reason != MissingSelectedObject {
		t.Fatal("administrative reader accepted missing mandatory current access", result)
	}
	if image, result := Open(ctx, admission, store); image != nil || result.Outcome != EvidenceUnavailable || result.Reason != MissingSelectedObject {
		t.Fatal("ordinary reader accepted missing current access", result)
	}
	if p, k := env.Custody.Calls(); p != public || k != private || store.creates != creates || store.cas != cas || trust.signs != signs ||
		!reflect.DeepEqual(store.objects[selected.admission.store.HeadKey], head) {
		t.Fatal("mandatory access refusal reached a private, signing or write effect")
	}
	store.objects[key] = missing
	if image, result := openAdministrative(ctx, admission, store); image == nil || result.Outcome != ObservedCurrent {
		t.Fatal("exact current access-page repair did not reopen", result)
	}
}

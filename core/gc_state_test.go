package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"strconv"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

func gcTestID(label string) contract.ID { return sha256.Sum256([]byte("gc-state-test/" + label)) }
func gcTestPlan(t testing.TB, s *StateSession, label string) contract.GCPlan {
	t.Helper()
	targetPage := *s.recipients[0]
	targetPage.Object = gcTestID(label + "/obsolete-page")
	body, e := format.EncodeRecipientPage(targetPage)
	if e != nil {
		t.Fatal(e)
	}
	target := contract.GCTarget{Object: contract.StoreObjectIdentity{Namespace: contract.StorePageObject, Kind: format.RecipientKind, ObjectID: targetPage.Object}, Length: uint32(len(body)), Digest: contract.Hash(body), Token: s.token}
	key, e := contract.StoreObjectKey(s.admission.store.Prefix, s.root.Domain, target.Object)
	if e != nil {
		t.Fatal(e)
	}
	targets, e := contract.GCTargetsDescriptor([]contract.GCTarget{target})
	if e != nil {
		t.Fatal(e)
	}
	return contract.GCPlan{DomainID: s.root.Domain, OperationID: gcTestID(label + "/operation"), RequestNonce: gcTestID(label + "/nonce"), StoreDescriptorDigest: administrativeStoreDescriptorDigest(s.admission.store), PublicBasisDigest: gcTestID("public-basis"), SourcePinsDigest: gcTestID("source-pins"), HeadRevisionID: s.head.Core.Revision, FullHEADDigest: contract.Hash(s.body), SnapshotID: s.root.Snapshot, RootDigest: s.head.Core.Root.Digest, MarkDigest: gcTestID(label + "/mark"), EnumerationDigest: gcTestID(label + "/enumeration"), TargetsDigest: targets.Digest, PredecessorToken: s.token, Targets: []contract.GCTarget{target}, Candidates: []contract.GCCandidate{{KeyDigest: contract.Hash([]byte(key)), Classification: contract.GCCandidateEligible}}}
}
func gcTestProgress(t testing.TB, plan contract.GCPlan) contract.GCProgress {
	t.Helper()
	digest, e := contract.GCPlanDigest(plan)
	if e != nil {
		t.Fatal(e)
	}
	targets, e := contract.GCTargetsDescriptor(plan.Targets)
	if e != nil {
		t.Fatal(e)
	}
	observation, e := contract.GCPlanObservationDigest(plan)
	if e != nil {
		t.Fatal(e)
	}
	// Derive the request commitment here without the production identity helper.
	// The exact canonical preview commits every original source and predecessor.
	body, e := contract.EncodeGCPlan(plan)
	if e != nil {
		t.Fatal(e)
	}
	planHash := sha256.Sum256(body)
	requestBytes := append([]byte("ENKV/GC-REQUEST/v1\x00"), planHash[:]...)
	if len(requestBytes) != 51 {
		t.Fatal("request commitment framing changed")
	}
	request := sha256.Sum256(requestBytes)
	return contract.GCProgress{PlanDigest: digest, TargetsDescriptor: targets, RequestIdentity: request, ObservationDigest: observation, RemainingCount: uint16(len(plan.Targets)), Ordinal: 1, Targets: []contract.GCTargetProgress{{Disposition: contract.GCTargetPending}}}
}
func gcTestSelectState(t testing.TB, s *StateSession, plan contract.GCPlan, progress contract.GCProgress, phase contract.GCPhase, active bool, packPlans ...bool) *StateSession {
	t.Helper()
	operation := plan.OperationID
	next := *s
	next.root = s.root
	next.support = slices.Clone(s.support)
	next.root.RequiredSupport = slices.Clone(s.root.RequiredSupport)
	candidate := &Candidate{session: s}
	if phase == contract.GCSelect {
		body, e := contract.EncodeGCPlan(plan)
		if e != nil {
			t.Fatal(e)
		}
		index := uint16(0)
		for _, ref := range next.root.RequiredSupport {
			if ref.Index >= index {
				index = ref.Index + 1
			}
		}
		page := format.RequiredSupportPage{Domain: s.root.Domain, Object: gcTestID(string(operation[:]) + "/plan-page"), Index: index, Records: []contract.SupportRecord{{Kind: contract.GCPlanSupportKind, RecordID: operation, Body: body}}}
		encoded, e := format.EncodeRequiredSupportPage(page)
		if e != nil {
			t.Fatal(e)
		}
		ref, e := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, index, encoded)
		if e != nil {
			t.Fatal(e)
		}
		view, e := format.InspectRequiredSupportPage(encoded)
		if e != nil {
			t.Fatal(e)
		}
		next.root.RequiredSupport = append(next.root.RequiredSupport, ref)
		next.support = append(next.support, view)
		next.root.RequiredSupportRecordCount++
		candidate.objects = append(candidate.objects, objectImage{ref: ref, body: encoded})
	}
	if len(packPlans) != 0 && packPlans[0] {
		gcTestPackPlanPages(t, &next, candidate, operation)
	}
	marker := string(operation[:]) + "/" + string([]byte{byte(phase)}) + "/" + strconv.FormatUint(uint64(progress.Ordinal), 10)
	next.root.Snapshot, next.root.Transition = gcTestID(marker+"/snapshot"), gcTestID(marker+"/transition")
	if active {
		next.root.ActiveGC = operation
	} else {
		next.root.ActiveGC = contract.ID{}
	}
	if e := s.installGCAdministrativeIndex(t.Context(), &next, candidate, operation, &progress); e != nil {
		t.Fatal("install GC ownership", e)
	}
	if len(packPlans) > 1 && packPlans[1] {
		gcTestSplitRetainedOwnerSpan(t, &next, candidate)
	}
	before, e := s.gcPreservedCurrent(t.Context(), operation)
	if e != nil {
		t.Fatal("GC before preservation", e)
	}
	after, e := next.gcPreservedCurrent(t.Context(), operation)
	if e != nil || before != after {
		t.Fatal("GC changed preserved state", before, after, e)
	}
	rootBody, e := format.EncodeRoot(next.root)
	if e != nil {
		t.Fatal(e)
	}
	root, e := format.Reference(format.RootKind, next.root.Domain, next.root.Snapshot, 0, rootBody)
	if e != nil {
		t.Fatal(e)
	}
	candidate.objects = append(candidate.objects, objectImage{ref: root, body: rootBody})
	head := s.successorCore(transitionPlan{revision: gcTestID(marker + "/revision")})
	head.Root = root
	headBody, e := format.EncodeHeadCore(head)
	if e != nil {
		t.Fatal(e)
	}
	condition, e := format.EncodeConditionalPlan(conditional(head, headBody))
	if e != nil {
		t.Fatal(e)
	}
	afterProgress, e := contract.GCProgressDigest(progress)
	if e != nil {
		t.Fatal(e)
	}
	var beforeProgress contract.ID
	if phase != contract.GCSelect {
		_, old, e := s.selectedGCPlan(operation)
		if e != nil {
			t.Fatal(e)
		}
		beforeProgress, e = contract.GCProgressDigest(old)
		if e != nil {
			t.Fatal(e)
		}
	}
	q := contract.GCSubject{DomainID: s.root.Domain, OperationID: operation, AdmissionID: gcTestID(marker + "/admission"), RequestIdentity: progress.RequestIdentity, Phase: phase, PredecessorRevisionID: s.head.Core.Revision, PredecessorFullHEADDigest: contract.Hash(s.body), PredecessorToken: s.token, BeforeOwners: s.root.GCPlans, AfterOwners: next.root.GCPlans, PlanDigest: progress.PlanDigest, BeforeProgressDigest: beforeProgress, AfterProgressDigest: afterProgress, PreservedCurrentDigest: after.Digest, PreservedCurrentLength: after.Length, HeadCoreDigest: contract.Hash(headBody), HeadCoreLength: uint32(len(headBody)), ConditionalPlanDigest: contract.Hash(condition)}
	candidate.head = format.Head{Core: head, AuthKind: format.GCAuth, GC: &q, K1: bytes.Clone(s.head.K1), K3: bytes.Clone(s.head.K3)}
	next.head = candidate.head
	if !selectedGCSelection(next.head, next.selectedImage()) {
		t.Fatal("constructed GC relation refused")
	}
	signer := testtrust.New(t, s.admission.store.Family, s.admission.trust)
	candidate, result := s.persistCandidate(t.Context(), candidate, signer)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("persist GC fixture", result)
	}
	selected, result := s.selectCandidate(t.Context(), candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("select GC fixture", result)
	}
	return selected
}

func gcTestPackPlanPages(t testing.TB, next *StateSession, candidate *Candidate, operation contract.ID) {
	t.Helper()
	var records []contract.SupportRecord
	var index uint16
	var first bool
	gcPages := make([]bool, len(next.support))
	for i, page := range next.support {
		if len(page.Records) == 0 || !slices.ContainsFunc(page.Records, func(row contract.SupportRecordView) bool { return row.Kind == contract.GCPlanSupportKind }) {
			continue
		}
		if slices.ContainsFunc(page.Records, func(row contract.SupportRecordView) bool { return row.Kind != contract.GCPlanSupportKind }) {
			t.Fatal("GC packing fixture has a mixed source page")
		}
		if !first {
			index, first = page.Index, true
		}
		gcPages[i] = true
		for _, row := range page.Records {
			records = append(records, contract.SupportRecord(row))
		}
	}
	if len(records) < 2 {
		t.Fatal("shared GC fixture needs two exact plans")
	}
	page := format.RequiredSupportPage{Domain: next.root.Domain, Object: gcTestID(string(operation[:]) + "/shared-plan-page"), Index: index, Records: records}
	body, err := format.EncodeRequiredSupportPage(page)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
	if err != nil {
		t.Fatal(err)
	}
	view, err := format.InspectRequiredSupportPage(body)
	if err != nil {
		t.Fatal(err)
	}
	var refs []format.Ref
	var support []format.RequiredSupportPageView
	inserted := false
	for i := range next.support {
		if gcPages[i] {
			if !inserted {
				refs, support = append(refs, ref), append(support, view)
				inserted = true
			}
			continue
		}
		refs, support = append(refs, next.root.RequiredSupport[i]), append(support, next.support[i])
	}
	next.root.RequiredSupport, next.support = refs, support
	// The newly appended individual plan page is replaced by this selected page.
	candidate.objects = []objectImage{{ref: ref, body: body}}
}
func gcStateFixture(t testing.TB, pending bool) (*StateSession, contract.GCPlan) {
	t.Helper()
	s, _, _ := observationSelectedPredecessor(t)
	plan := gcTestPlan(t, s, "first")
	progress := gcTestProgress(t, plan)
	s = gcTestSelectState(t, s, plan, progress, contract.GCSelect, true)
	if pending {
		s = gcTestSelectState(t, s, plan, progress, contract.GCClose, false)
	}
	return s, plan
}

// full_only: false
func TestGCSelectedOwnershipPreservesExactPlanAndProgress(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(map[bool]string{false: "active", true: "pending"}[pending], func(t *testing.T) {
			s, plan := gcStateFixture(t, pending)
			got, progress, e := s.selectedGCPlan(plan.OperationID)
			if e != nil {
				t.Fatal(e)
			}
			a, _ := contract.EncodeGCPlan(plan)
			b, _ := contract.EncodeGCPlan(got)
			if !bytes.Equal(a, b) || progress.Targets[0].Consumed != 0 || progress.RemainingCount != 1 || s.root.ActiveGC.IsZero() != pending {
				t.Fatal("selected GC changed exact meaning")
			}
			progress.Targets[0].Consumed = 3
			_, fresh, e := s.selectedGCPlan(plan.OperationID)
			if e != nil || fresh.Targets[0].Consumed != 0 {
				t.Fatal("returned progress aliases selected ownership")
			}
			if _, e := s.selectedGeneratedWork(t.Context()); e != nil {
				t.Fatal("GC invalidated unrelated generated validation", e)
			}
		})
	}
}

// full_only: false
func TestGCAdministrativeEndingSurvivesUnreadablePlan(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(map[bool]string{false: "active", true: "pending"}[pending], func(t *testing.T) {
			s, plan := gcStateFixture(t, pending)
			store := s.store.(*observationSelectionStore)
			for _, page := range s.adminIndex.Pages {
				for _, row := range page.Rows {
					if row.Kind == contract.GCPlanSupportKind {
						key, err := format.Key(s.admission.store.Prefix, page.Ref)
						if err != nil {
							t.Fatal(err)
						}
						delete(store.objects, key)
					}
				}
			}
			opened, result := openAdministrative(t.Context(), OpenContext{admission: &s.admission}, store)
			if opened == nil || result.Outcome != ObservedCurrent {
				t.Fatal("cold administrative read needed optional GC body", result)
			}
			s = opened
			if _, e := selectedGCState(s.selectedImage(), true); e == nil {
				t.Fatal("complete read accepted missing target payload")
			}
			if _, e := selectedGCState(s.selectedImage(), false); e != nil {
				t.Fatal("mandatory reader needed disposable payload", e)
			}
			s.admission.endWorkInvocation = gcTestID("end-invocation")
			ids := endWorkIDs{operation: gcTestID("end-op"), transition: gcTestID("end-transition"), snapshot: gcTestID("end-snapshot"), revision: gcTestID("end-revision"), receipts: gcTestID("end-receipts"), receiptIndex: gcTestID("end-receipt-index")}
			candidate, next, e := s.deriveEndWorkCandidate(t.Context(), plan.OperationID, ids)
			if e != nil {
				t.Fatal("end GC without payload", e)
			}
			if candidate == nil || !next.root.ActiveGC.IsZero() || next.root.GCPlans != contract.EmptyGCOwnersDescriptor() || next.root.WarningBits&(WarningDiscardedExactEvidence|WarningPossibleStoreGarbage) != (WarningDiscardedExactEvidence|WarningPossibleStoreGarbage) {
				t.Fatal("GC ending retained rights or lost warnings")
			}
			if next.root.CurrentAccess.AccessRoot != s.root.CurrentAccess.AccessRoot || next.root.ValueEntryCount != s.root.ValueEntryCount {
				t.Fatal("GC ending changed current values/access")
			}
			if !selectedEndWorkSelection(candidate.head, next.selectedImage(), s.admission.recipient) {
				t.Fatal("GC ending is not selected administrative contract")
			}
		})
	}
}

// full_only: false
func TestGCProgressAndMandatoryOwnershipDamageRefuses(t *testing.T) {
	s, plan := gcStateFixture(t, false)
	for _, damage := range []string{"owner digest", "owner identity", "progress", "active overlap"} {
		t.Run(damage, func(t *testing.T) {
			broken := *s
			broken.adminIndex = clonePublicationWork(s.adminIndex)
			switch damage {
			case "owner digest":
				broken.root.GCPlans.Digest = gcTestID("wrong")
			case "owner identity":
				broken.root.ActiveGC = gcTestID("wrong")
			case "progress":
				broken.adminIndex.Groups[len(broken.adminIndex.Groups)-1].GC.Targets[0].Consumed = 4
			case "active overlap":
				broken.root.Generated.ActiveOwner = gcTestID("canonical")
			}
			if _, e := selectedGCState(broken.selectedImage(), false); e == nil {
				t.Fatal("mandatory GC damage admitted", plan.OperationID)
			}
		})
	}
}

// full_only: false
func TestGCSelectedPlanJoinsOriginalOwnership(t *testing.T) {
	s, plan := gcStateFixture(t, false)
	for _, damage := range []string{"affected", "dependencies", "request identity"} {
		t.Run(damage, func(t *testing.T) {
			broken := *s
			broken.adminIndex = clonePublicationWork(s.adminIndex)
			position := slices.IndexFunc(broken.adminIndex.Groups, func(g format.AdministrativeGroup) bool { return g.GroupID == plan.OperationID })
			if position < 0 {
				t.Fatal("selected GC group missing")
			}
			group := &broken.adminIndex.Groups[position]
			switch damage {
			case "affected":
				group.Affected.Digest = gcTestID("unrelated-targets")
			case "dependencies":
				group.Dependencies.Digest = gcTestID("unrelated-mark-enumeration")
			case "request identity":
				group.GC.RequestIdentity = gcTestID("unrelated-original-request")
				var e error
				broken.root.GCPlans, e = format.GCPlansDescriptor(broken.adminIndex)
				if e != nil {
					t.Fatal(e)
				}
			}
			if _, e := selectedGCState(broken.selectedImage(), true); e == nil {
				t.Fatal("selected GC admitted unrelated original ownership", damage)
			}
		})
	}
}

// full_only: false
func TestGCSelectedPlanJoinsActualStore(t *testing.T) {
	s, plan := gcStateFixture(t, false)
	if plan.StoreDescriptorDigest != administrativeStoreDescriptorDigest(s.admission.store) {
		t.Fatal("fixture does not bind its actual Store")
	}
	if _, _, e := s.selectedGCPlan(plan.OperationID); e != nil {
		t.Fatal("genuine selected Store refused", e)
	}
	changed := *s
	changed.admission.store.Prefix += "/different"
	changed.admission.store.HeadKey = changed.admission.store.Prefix + "/HEAD"
	if !changed.admission.store.Valid() {
		t.Fatal("changed Store descriptor is not valid")
	}
	if _, _, e := changed.selectedGCPlan(plan.OperationID); e == nil {
		t.Fatal("selected GC plan admitted under a different Store")
	}
}

// full_only: false
func TestGCPhaseRelationsPreserveConsumedRights(t *testing.T) {
	s := generatedEmptyPredecessor(t)
	plan := gcTestPlan(t, s, "phase")
	before := gcTestProgress(t, plan)
	reserved := before.Own()
	reserved.Ordinal++
	reserved.Targets[0].Consumed = 1
	if e := validateGCProgressTransition(&before, &reserved, contract.GCReserve); e != nil {
		t.Fatal(e)
	}
	unknown := reserved.Own()
	unknown.Ordinal++
	unknown.Targets[0].Disposition = contract.GCTargetUnknown
	if e := validateGCProgressTransition(&reserved, &unknown, contract.GCRecordProgress); e != nil {
		t.Fatal(e)
	}
	reset := unknown.Own()
	reset.Ordinal++
	reset.Targets[0].Consumed = 0
	if e := validateGCProgressTransition(&unknown, &reset, contract.GCReserve); e == nil {
		t.Fatal("resume restored consumed permission")
	}
	retry := unknown.Own()
	retry.Ordinal++
	retry.Targets[0].Consumed++
	if e := validateGCProgressTransition(&unknown, &retry, contract.GCReserve); e == nil {
		t.Fatal("unknown call acquired replacement allowance")
	}
}

// full_only: false
func TestGCPreservationBindsMandatoryCounters(t *testing.T) {
	s, plan := gcStateFixture(t, false)
	before, e := s.preservedState(context.Background(), contract.SuccessionChangeNormalSigner, false)
	if e != nil {
		t.Fatal(e)
	}
	_, progress, e := s.selectedGCPlan(plan.OperationID)
	if e != nil {
		t.Fatal(e)
	}
	progress.Ordinal++
	progress.Targets[0].Consumed = 1
	changed := gcTestSelectState(t, s, plan, progress, contract.GCReserve, true)
	after, e := changed.preservedState(context.Background(), contract.SuccessionChangeNormalSigner, false)
	if e != nil || before == after {
		t.Fatal("mandatory GC counters escaped preservation", e)
	}
	rootBytes, _ := format.EncodeRoot(s.root)
	if len(rootBytes) < 76 || !bytes.Equal(rootBytes[len(rootBytes)-44:len(rootBytes)-12], s.root.GCPlans.Digest[:]) {
		t.Fatal("root omitted exact GC descriptor")
	}
	if binary.BigEndian.Uint32(rootBytes[len(rootBytes)-4:]) != 1 {
		t.Fatal("GC count encoding")
	}
}

func gcTestSplitRetainedOwnerSpan(t testing.TB, next *StateSession, candidate *Candidate) {
	t.Helper()
	next.adminIndex = clonePublicationWork(next.adminIndex)
	split := false
	for i, page := range next.adminIndex.Pages {
		for j, span := range page.Spans {
			if span.Count < 2 {
				continue
			}
			first, rest := span, span
			first.Count = 1
			rest.First, rest.Count = span.First+1, span.Count-1
			spans := slices.Clone(page.Spans[:j])
			spans = append(spans, first, rest)
			next.adminIndex.Pages[i].Spans = append(spans, page.Spans[j+1:]...)
			split = true
			break
		}
		if split {
			break
		}
	}
	if !split {
		for i, page := range next.adminIndex.Pages {
			t.Logf("retained page %d: read-required=%t spans=%v rows=%d", i, page.ReadRequired, page.Spans, len(page.Rows))
			for _, row := range page.Rows {
				t.Logf("row kind=%d bytes=%d", row.Kind, row.BodyLength)
			}
		}
		t.Fatal("fixture lacks a multirow retained owner span")
	}
	shards, err := format.EncodeAdministrativeIndexPages(next.adminIndex)
	if err != nil || len(shards) == 0 {
		t.Fatal("encode valid nonmaximal index", err)
	}
	objects := candidate.objects[:0]
	for _, object := range candidate.objects {
		if object.ref.Kind != contract.AdministrativeIndexKind {
			objects = append(objects, object)
		}
	}
	candidate.objects = objects
	next.root.AdministrativeIndex = shards[0].Ref
	next.root.AdministrativeIndexShards = nil
	for i, shard := range shards {
		if i != 0 {
			next.root.AdministrativeIndexShards = append(next.root.AdministrativeIndexShards, shard.Ref)
		}
		candidate.objects = append(candidate.objects, objectImage{ref: shard.Ref, body: shard.Body})
	}
	next.recountChildren()
}

// full_only: false
func TestGCAlreadySelectedNonmaximalIndexSurvivesColdReopenAndProgress(t *testing.T) {
	gcTestRetainedOwnerPartitionProgress(t, false)
}

// full_only: false
func TestGCEndWorkRetainedIndexSurvivesColdReopenAndProgress(t *testing.T) {
	gcTestRetainedOwnerPartitionProgress(t, true)
}

func gcTestRetainedOwnerPartitionProgress(t *testing.T, endWork bool) {
	t.Helper()
	s, initial := gcStateFixture(t, false)
	var result Result
	for round := 0; round < 2; round++ {
		label := "partition-fixture/" + strconv.Itoa(round)
		s.admission.endWorkInvocation = gcTestID(label + "/invocation")
		initialIDs := endWorkIDs{operation: gcTestID(label + "/operation"), transition: gcTestID(label + "/transition"), snapshot: gcTestID(label + "/snapshot"), revision: gcTestID(label + "/revision"), receipts: gcTestID(label + "/receipts"), receiptIndex: gcTestID(label + "/index")}
		candidate, _, err := s.deriveEndWorkCandidate(t.Context(), initial.OperationID, initialIDs)
		if err != nil {
			t.Fatal("construct independent retained receipt page", err)
		}
		candidate, result = s.persistCandidate(t.Context(), candidate, testtrust.New(t, s.admission.store.Family, s.admission.trust))
		if candidate == nil || result.Outcome != ObservedCurrent {
			t.Fatal("persist retained receipt page", result)
		}
		s, result = s.selectCandidate(t.Context(), candidate)
		if s == nil || result.Outcome != ObservedCurrent {
			t.Fatal("select retained receipt page", result)
		}
		s, result = Open(t.Context(), OpenContext{admission: &s.admission}, s.store)
		if s == nil || result.Outcome != ObservedCurrent {
			t.Fatal("cold read of retained receipt page", result)
		}
		if round == 0 {
			initial = gcTestPlan(t, s, "second-retained-receipt-source")
			s = gcTestSelectState(t, s, initial, gcTestProgress(t, initial), contract.GCSelect, true)
		}
	}
	current, err := format.EncodeValueEntryPage(*s.pages[0])
	if err != nil {
		t.Fatal(err)
	}
	first := gcTestPlan(t, s, "nonmaximal-retained-source")
	progress := gcTestProgress(t, first)
	s = gcTestSelectState(t, s, first, progress, contract.GCSelect, true)
	// Publish a valid current-format nonmaximal index, without EndWork.
	s = gcTestSelectState(t, s, first, progress, contract.GCClose, false, false, true)
	s, result = Open(t.Context(), OpenContext{admission: &s.admission}, s.store)
	if s == nil || result.Outcome != ObservedCurrent {
		t.Fatal("cold read of selected nonmaximal index", result)
	}
	nonmaximal := false
	for _, page := range s.adminIndex.Pages {
		for i, span := range page.Spans {
			if i != 0 {
				last := page.Spans[i-1]
				nonmaximal = nonmaximal || last.Mandatory == span.Mandatory && slices.Equal(last.GroupIndexes, span.GroupIndexes) && uint32(last.First)+uint32(last.Count) == uint32(span.First)
			}
		}
	}
	if !nonmaximal {
		t.Fatal("cold reader removed the selected nonmaximal fixture")
	}
	if endWork {
		s.admission.endWorkInvocation = gcTestID("partition-ending-invocation")
		ids := endWorkIDs{operation: gcTestID("partition-ending-operation"), transition: gcTestID("partition-ending-transition"), snapshot: gcTestID("partition-ending-snapshot"), revision: gcTestID("partition-ending-revision"), receipts: gcTestID("partition-ending-receipts"), receiptIndex: gcTestID("partition-ending-index")}
		candidate, _, err := s.deriveEndWorkCandidate(t.Context(), first.OperationID, ids)
		if err != nil {
			t.Fatal("derive exact retained owner ending", err)
		}
		candidate, result = s.persistCandidate(t.Context(), candidate, testtrust.New(t, s.admission.store.Family, s.admission.trust))
		if candidate == nil || result.Outcome != ObservedCurrent {
			t.Fatal("persist exact retained owner ending", result)
		}
		s, result = s.selectCandidate(t.Context(), candidate)
		if s == nil || result.Outcome != ObservedCurrent {
			t.Fatal("select exact retained owner ending", result)
		}
		s, result = Open(t.Context(), OpenContext{admission: &s.admission}, s.store)
		if s == nil || result.Outcome != ObservedCurrent {
			t.Fatal("cold read after exact owner ending", result)
		}
		for _, page := range s.adminIndex.Pages {
			for i, span := range page.Spans {
				if i != 0 {
					last := page.Spans[i-1]
					if last.Mandatory == span.Mandatory && slices.Equal(last.GroupIndexes, span.GroupIndexes) && uint32(last.First)+uint32(last.Count) == uint32(span.First) {
						t.Fatal("ending retained a nonmaximal owner partition")
					}
				}
			}
		}
	}
	second := gcTestPlan(t, s, "nonmaximal-next-gc")
	nextProgress := gcTestProgress(t, second)
	selectPhase := func(phase contract.GCPhase, after *contract.GCProgress) {
		t.Helper()
		var entropy []byte
		for i := 0; i < 300; i++ {
			id := gcTestID("nonmaximal-phase/" + strconv.Itoa(int(phase)) + "/" + strconv.Itoa(i))
			entropy = append(entropy, id[:]...)
		}
		s.admission.entropy = bytes.NewReader(entropy)
		candidate, prepared := s.prepareGCPhase(t.Context(), second, gcTestID("nonmaximal-phase-admission"), phase, after)
		if candidate == nil || prepared != (Result{}) {
			t.Fatal("prepare GC from selected owner partition", phase, prepared)
		}
		candidate, result = s.persistCandidate(t.Context(), candidate, testtrust.New(t, s.admission.store.Family, s.admission.trust))
		if candidate == nil || result.Outcome != ObservedCurrent {
			t.Fatal("persist GC phase", phase, result)
		}
		s, result = s.selectCandidate(t.Context(), candidate)
		if s == nil || result.Outcome != ObservedCurrent {
			t.Fatal("select GC phase", phase, result)
		}
	}
	selectPhase(contract.GCSelect, &nextProgress)
	nextProgress.Ordinal++
	nextProgress.Targets[0].Consumed = 1
	selectPhase(contract.GCReserve, &nextProgress)
	nextProgress.Ordinal++
	nextProgress.Targets[0].Disposition = contract.GCTargetAbsent
	nextProgress.Targets[0].EvidenceDigest = gcTestID("nonmaximal-exact-absence")
	nextProgress.RemainingCount = 0
	selectPhase(contract.GCRecordProgress, &nextProgress)
	s, result = Open(t.Context(), OpenContext{admission: &s.admission}, s.store)
	if s == nil || result.Outcome != ObservedCurrent {
		t.Fatal("cold read after GC progress", result)
	}
	after, err := format.EncodeValueEntryPage(*s.pages[0])
	if err != nil || !bytes.Equal(current, after) {
		t.Fatal("GC changed exact current value bytes", err)
	}
	_, got, err := s.selectedGCPlan(second.OperationID)
	if err != nil || !contract.GCProgressEqual(got, nextProgress) {
		t.Fatal("cold progress lost exact selected facts", err)
	}
	selectPhase(contract.GCClose, nil)
	if !s.root.ActiveGC.IsZero() || slices.ContainsFunc(s.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == second.OperationID }) {
		t.Fatal("completed GC retained local work")
	}
}

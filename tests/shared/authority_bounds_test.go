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
	testtrust "enkv.sh/crypto/testsupport/trust"
)

// This observer delegates every request to actual admitted Crypto. It records
// public batch facts and checks ordering before immutable Store effects.
type successionBatchWitness struct {
	contract.Crypto
	t                    *testing.T
	store                *memoryStore
	creates, cas         int
	maxInput             int
	batches, materials   uint32
	last                 contract.ID
	final, frozen, claim bool
}

func (w *successionBatchWitness) Exchange(ctx context.Context, q contract.CryptoRequest) contract.CryptoResponse {
	w.t.Helper()
	if w.store.creates != w.creates || w.store.cas != w.cas {
		w.t.Fatal("succession wrote before the complete Crypto claim")
	}
	switch q.Kind {
	case contract.CryptoPrepare:
		v, err := contract.DecodeCryptoAccessPrepareRequest(q.Body)
		if err != nil || w.final || v.BatchIndex != w.batches || len(v.Rows) == 0 {
			w.t.Fatal("invalid observed succession batch", err)
		}
		length, err := contract.AccessInputBatchLength(v.Rows)
		if err != nil || length > 2<<20 {
			w.t.Fatal("succession input exceeded the 2 MiB region", err)
		}
		w.maxInput = max(w.maxInput, length)
		for _, row := range v.Rows {
			if !w.last.IsZero() && bytes.Compare(w.last[:], row.Coverage.MaterialID[:]) >= 0 {
				w.t.Fatal("material order restarted at a batch boundary")
			}
			w.last = row.Coverage.MaterialID
			w.materials++
		}
		w.batches++
		w.final = v.Final == 1
	case contract.CryptoFreeze:
		if !w.final || w.materials != 512 || w.batches < 2 || w.frozen {
			w.t.Fatal("Freeze preceded complete multibatch coverage")
		}
		v, err := contract.DecodeCryptoAccessFreezeRequest(q.Body)
		if err != nil || v.ExpectedCoverageDescriptor.Count != 512 || v.AfterAccessRowsDescriptor.Count != 512 || v.UnchangedMaterialDescriptor.Count != 512 {
			w.t.Fatal("Freeze omitted material from its complete projections", err)
		}
		w.frozen = true
	case contract.CryptoClaim:
		if !w.frozen || w.claim {
			w.t.Fatal("Claim did not follow one Freeze")
		}
		w.claim = true
	}
	return w.Crypto.Exchange(ctx, q)
}

// full_only: true
func TestSuccessionBoundsMaximumMaterialsUseMultipleBatches(t *testing.T) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	enrolled := []contract.ID{fixtureID(env.Domain, "recipient")}
	for i := 1; i < 8; i++ {
		enrolled = append(enrolled, fixtureID(env.Domain, fmt.Sprintf("bounds-reader-%d", i)))
	}
	keys := custody.New(t, contract.GCP, fixtureID(env.Domain, "bounds-custody"), true, enrolled)
	env.Bindings, env.Crypto, env.Custody = keys.Bindings(), keys.Crypto(), keys
	env.AdmitInit, env.RetireInit = keys.AdmitInit, keys.RetireInit
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	recipients := slices.Clone(enrolled)
	slices.SortFunc(recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	names := maximumLifecycleNames("succession-bounds")
	input := make([]ApplyEntryInput, 512)
	for i, name := range names {
		input[i] = sharingSecretNamed(t, env, name, fmt.Sprintf("bounds-source-%d", i), recipients)
	}
	before := run.suppliedSelection(f, input)
	// Each record has eight ordinary wraps and one recovery wrap. Byte packing
	// requires two page envelopes: 2*75 + 512*(102 + 9*489).
	var accessBytes uint64
	for _, ref := range before.root.CurrentAccess.Core.AccessPageRefs {
		accessBytes += uint64(ref.Length)
	}
	if before.root.SecretCount != 512 || before.root.MembershipCount != 4096 || before.root.SecretOrdinaryWrapCount != 4096 || len(before.root.CurrentAccess.Core.AccessPageRefs) != 2 || accessBytes != 2305686 {
		t.Fatal("fixture did not reach the material and ordinary-wrap limits")
	}
	// This unselected source is outside the complete required material set.
	stale := sharingSecretNamed(t, env, "unselected", "lost-authority-source", recipients)
	after := currentControlOf(before)
	source := contract.BindingTableRow{SubjectKind: 2, SubjectID: after.Recovery.RoleID, Binding: after.Recovery.KMS}
	after.AuthorityKMSBinding = keys.KEKSuccessor(t, contract.SuccessorAuthorityKEK)
	after.AccessGeneration++
	keys.LoseRecipientPredecessor(after.AuthorityRecipientID)
	permit := admitAuthorityReplacement(t, before, keys, after, 1, 1, 2, source)
	defer keys.RetireAccess()
	store := env.Store.(*memoryStore)
	witness := &successionBatchWitness{Crypto: permit.crypto, t: t, store: store, creates: store.creates, cas: store.cas}
	permit.crypto = witness
	public, private := keys.Calls()
	candidate, result := before.PrepareSuccession(ctx, permit, SuccessionSigners{Authorizer: env.Trust})
	if candidate == nil || !witness.claim || witness.materials != 512 || witness.batches < 2 {
		t.Fatal("maximum succession did not prepare and claim complete coverage", result)
	}
	t.Logf("materials=%d ordinary_wraps=%d batches=%d maximum_input_region=%d input_region_limit=%d", witness.materials, before.root.SecretOrdinaryWrapCount, witness.batches, witness.maxInput, contract.AccessBatchLimit)
	if p, k := keys.Calls(); p-public != 1 || k-private != 513 {
		t.Fatal("maximum succession did not use one successor probe and exactly 512 material opens", p-public, k-private)
	}
	admission := deliverSuccessionBasis(t, candidate)
	if result = before.Select(ctx, candidate); result.Outcome != ObservedCurrent || store.cas != witness.cas+1 {
		t.Fatal("maximum succession did not select exactly once", result)
	}
	keys.RetireAccess()
	if err := keys.ActivateSuccessor(after.AuthorityRecipientID); err != nil {
		t.Fatal(err)
	}
	keys.SetUnavailable(true)
	selected, result := Open(ctx, admission, env.Store)
	keys.SetUnavailable(false)
	if selected == nil || result.Outcome != ObservedCurrent || !sameControl(currentControlOf(selected), after) || selected.root.ChildCount != before.root.ChildCount || selected.root.ChildCount > 97 || selected.root.ChildEncodedBytes > 512<<20 {
		t.Fatal("maximum succession cold state or child headroom differs", result)
	}
	for _, entry := range before.root.Names {
		if !reflect.DeepEqual(before.valueEntry(entry.Slot), selected.valueEntry(entry.Slot)) || *before.root.ValueEntryPages[entry.Slot/format.PageSlots] != *selected.root.ValueEntryPages[entry.Slot/format.PageSlots] {
			t.Fatal("multibatch succession rewrote immutable material")
		}
		_, _, oldAccess, oldOK := before.selectedValue(entry.Slot)
		_, _, newAccess, newOK := selected.selectedValue(entry.Slot)
		if !oldOK || !newOK || !preservesReplacementWraps(oldAccess, newAccess, contract.BindingTableRow{SubjectKind: 1, SubjectID: after.AuthorityRecipientID, Binding: after.AuthorityKMSBinding}) {
			t.Fatal("multibatch succession changed an unaffected wrap")
		}
	}
	for _, name := range []string{names[0], names[len(names)-1]} {
		a := sessionConsumerSelection(t, before, before.admission.recipient, name)
		a.Binding = source
		b := sessionConsumerSelection(t, selected, selected.admission.recipient, name)
		if !keys.MaterialPreserved(a, b) {
			t.Fatal("boundary material changed private D/C")
		}
	}
	if comparison, result := selected.compareEntryInputs([]ApplyEntryInput{stale}); comparison != nil || result.Outcome != AdmissionRefused {
		t.Fatal("unselected source under retired authority became usable", result)
	}
	basis := successionBasisTransport(admission.admission.current)
	process := selectedProcessFacts(t, admission, selected)
	process.CurrentBasis, process.Objects = &basis, store.objects
	checkFreshProcessInput(t, process)
}

func prepareSelectionSigner(t *testing.T, s *StateSession, env fixtureEnvironment, keys *custody.Fixture) *Candidate {
	t.Helper()
	after := currentControlOf(s)
	successor, binding := env.Trust.(*fixtureTrust).Successor(t, after.NormalSigning)
	after.NormalSigning, after.AccessGeneration = binding, after.AccessGeneration+1
	permit := admitAuthorityReplacement(t, s, keys, after, 1, 1, 1, contract.BindingTableRow{})
	candidate, result := s.PrepareSuccession(context.Background(), permit, SuccessionSigners{Authorizer: env.Trust, NormalSuccessor: successor})
	if candidate == nil {
		t.Fatal("selection fixture preparation", result)
	}
	return candidate
}

// full_only: false
func TestSuccessionSelectionAbandonedCandidateDoesNotBlockReplacement(t *testing.T) {
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	store := env.Store.(*memoryStore)
	abandoned := prepareSelectionSigner(t, f.session, env, keys)
	// Simulate loss of every unselected immutable object. Current state remains
	// complete, and fresh admission must not discover or adopt this proposal.
	for _, object := range abandoned.objects {
		key, err := format.Key(store.desc.Prefix, object.ref)
		if err != nil {
			t.Fatal(err)
		}
		delete(store.objects, key)
	}
	fresh, result := Open(ctx, f.admission, env.Store)
	if fresh == nil || !bytes.Equal(fresh.body, f.session.body) {
		t.Fatal("abandoned object loss blocked current open", result)
	}
	candidate := prepareSelectionSigner(t, fresh, env, keys)
	admission := deliverSuccessionBasis(t, candidate)
	if result = fresh.Select(ctx, candidate); result.Outcome != ObservedCurrent {
		t.Fatal("abandoned candidate blocked fresh replacement", result)
	}
	beforeCAS := store.cas
	deliverSuccessionBasis(t, abandoned)
	if result = f.session.Select(ctx, abandoned); result.Outcome != Contention || result.Reason != StalePrecondition || store.cas != beforeCAS+1 {
		t.Fatal("abandoned candidate rebased onto new current state", result)
	}
	if selected, result := Open(ctx, admission, env.Store); selected == nil || !bytes.Equal(selected.body, candidate.body) {
		t.Fatal("stale abandoned proposal changed the selected replacement", result)
	}
}

// full_only: false
func TestSuccessionSelectionLostRepliesKeepOriginalCondition(t *testing.T) {
	for _, mode := range []string{"lost-after", "lost-before", "delayed"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			env, keys := genesisEnvironment(t, contract.GCP, false)
			f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
			store := env.Store.(*memoryStore)
			candidate := prepareSelectionSigner(t, f.session, env, keys)
			admission := deliverSuccessionBasis(t, candidate)
			store.casMode = mode
			cas := store.cas
			result := f.session.Select(ctx, candidate)
			wantCalls := 3
			if mode == "lost-after" {
				wantCalls = 1
			}
			if store.cas != cas+wantCalls || !candidate.used {
				t.Fatal("uncertain succession exceeded or missed its conditional send bound")
			}
			for i := cas; i < store.cas; i++ {
				if store.casConditions[i] != f.session.token || !bytes.Equal(store.casBodies[i], candidate.body) {
					t.Fatal("retry changed the original condition or frozen HEAD")
				}
			}
			if mode == "lost-after" {
				if result.Outcome != ObservedCurrent || result.RequestedRevision != candidate.head.Core.Revision || result.ObservedRevision != candidate.head.Core.Revision || result.CommitMayHaveOccurred {
					t.Fatal("exact observation failed to establish the lost-reply selection", result)
				}
				if selected, result := Open(ctx, admission, env.Store); selected == nil || !bytes.Equal(selected.body, candidate.body) {
					t.Fatal("lost-reply successor did not reopen", result)
				}
			} else {
				wantOutcome, wantPossible := UnresolvedCommit, true
				if mode == "lost-before" {
					wantOutcome, wantPossible = EvidenceUnavailable, false
				}
				if result.Outcome != wantOutcome || result.CommitMayHaveOccurred != wantPossible || !bytes.Equal(store.objects[store.desc.HeadKey].Body, f.session.body) {
					t.Fatal("unestablished selection lost its ambiguity", result)
				}
				late := store.late
				store.casMode = ""
				fresh, result := Open(ctx, f.admission, env.Store)
				if fresh == nil {
					t.Fatal("uncertain prior request blocked independent current admission", result)
				}
				other := prepareSelectionSigner(t, fresh, env, keys)
				otherAdmission := deliverSuccessionBasis(t, other)
				if result = fresh.Select(ctx, other); result.Outcome != ObservedCurrent {
					t.Fatal("fresh replacement after ambiguity failed", result)
				}
				if late != nil {
					if err := late(); err != nil {
						t.Fatal("delayed Store write", err)
					}
				}
				if selected, result := Open(ctx, otherAdmission, env.Store); selected == nil || !bytes.Equal(selected.body, other.body) {
					t.Fatal("delayed request escaped its original condition", result)
				}
			}
			cas = store.cas
			if result = f.session.Select(ctx, candidate); result.Outcome != AdmissionRefused || store.cas != cas {
				t.Fatal("used uncertain candidate issued another CAS", result)
			}
		})
	}
}

// full_only: false
func TestSuccessionLostReplyThenPreconditionUsesEarlierCommitEvidence(t *testing.T) {
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, false)
	defer keys.RetireGenerated()
	f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	store := env.Store.(*memoryStore)
	candidate := prepareSelectionSigner(t, f.session, env, keys)
	deliverSuccessionBasis(t, candidate)
	old := contract.ReadResult{Status: contract.ReadOK, Body: bytes.Clone(f.session.body), Token: f.session.token}
	store.casMode = "lost-after"
	staleReads := 0
	store.readHook = func(key string, result contract.ReadResult) contract.ReadResult {
		if key == store.desc.HeadKey && staleReads < 2 {
			staleReads++
			return old
		}
		return result
	}
	before := store.cas
	result := f.session.Select(ctx, candidate)
	if result.Outcome != ObservedCurrent || result.CommitMayHaveOccurred || store.cas != before+2 || staleReads != 2 {
		t.Fatal("later precondition hid an earlier committed HEAD", result)
	}
	for i := before; i < store.cas; i++ {
		if store.casConditions[i] != old.Token || !bytes.Equal(store.casBodies[i], candidate.body) {
			t.Fatal("retry changed original condition or HEAD")
		}
	}
}

// This fixture supplies an independently trusted, signed current state with a
// full public receipt window. It does not claim to execute 256 prior recoveries.
// The test below performs the next real Prepare/Freeze/Select transition.
func seedFullSuccessionReceiptWindow(t *testing.T, env fixtureEnvironment, f *environmentFixture) []contract.CompactMutationReceipt {
	t.Helper()
	rows := fullSuccessReceiptRows(env.Domain, f.session.admission)
	windows := contract.MutationReceiptWindows{DomainID: env.Domain, Successes: rows}
	for _, row := range rows {
		windows.Order = append(windows.Order, row.OperationID)
	}
	storage := mutationReceiptFixtureStorage(t, windows)
	if len(storage.objects) != 2 || len(storage.objects[0].body) != 75+256*508 || len(storage.objects[1].body) != 75+37+86+26+256*72 {
		t.Fatal("full receipt fixture differs from fixed record/index bounds")
	}
	seedSignedReceiptWindows(t, env, f, storage)
	return rows
}

func fullSuccessReceiptRows(domain contract.ID, admission openAdmission) []contract.CompactMutationReceipt {
	rows := make([]contract.CompactMutationReceipt, 256)
	for i := range rows {
		prior := fixtureID(domain, fmt.Sprintf("retained-recovery-revision-%03d", i))
		selected := fixtureID(domain, fmt.Sprintf("retained-recovery-revision-%03d", i+1))
		rows[i] = contract.CompactMutationReceipt{Schema: contract.MutationReceiptSchema, OperationKind: 36,
			DomainID: domain, OperationID: fixtureID(domain, fmt.Sprintf("retained-recovery-%03d", i)),
			RequestIdentityDigest: fixtureID(domain, fmt.Sprintf("retained-recovery-identity-%03d", i)), PredecessorRevisionID: prior, RequestedRevisionID: selected, ObservedRevisionID: selected,
			StateResult: 1, EvidenceCeiling: 1, CanonicalOutcome: 1,
			ChangedSubjects: contract.GeneratorDescriptor{Digest: testID("prior changed subjects"), Length: 80, Count: 2},
			CompleteResult:  contract.GeneratorDescriptor{Digest: fixtureID(domain, fmt.Sprintf("retained-recovery-result-%03d", i)), Length: 655, Count: 1}}
	}
	return rows
}

// A legal ApplyDeclaration unknown is a failure-window row. A signer-only
// succession cannot claim that effect result, so this trusted history is
// installed before generated work starts.
func fullUnknownReceiptRows(domain contract.ID, admission openAdmission) []contract.CompactMutationReceipt {
	rows := make([]contract.CompactMutationReceipt, contract.MutationReceiptWindowLimit)
	for i := range rows {
		prior := fixtureID(domain, fmt.Sprintf("retained-unknown-prior-%03d", i))
		requested := fixtureID(domain, fmt.Sprintf("retained-unknown-requested-%03d", i))
		rows[i] = contract.CompactMutationReceipt{Schema: contract.MutationReceiptSchema,
			OperationKind: contract.OperationApplyDeclaration, StateResult: contract.ReceiptStateEffectUnknown,
			EffectSummary: contract.ReceiptEffectUnknown, EvidenceCeiling: contract.ReceiptEvidenceProviderFacts,
			CanonicalOutcome: contract.ReceiptCanonicalNotSelected, WarningBits: contract.ReceiptWarningPossibleLive,
			DomainID: domain, OperationID: fixtureID(domain, fmt.Sprintf("retained-unknown-operation-%03d", i)),

			RequestIdentityDigest: fixtureID(domain, fmt.Sprintf("retained-unknown-identity-%03d", i)),
			PredecessorRevisionID: prior, RequestedRevisionID: requested, ObservedRevisionID: prior,
			UnknownCount: 1, ChangedSubjects: contract.GeneratorDescriptor{Digest: testID("prior changed subjects"), Length: 80, Count: 2},
			CompleteResult: contract.GeneratorDescriptor{Digest: fixtureID(domain, fmt.Sprintf("retained-unknown-result-%03d", i)), Length: 655, Count: 1}}
		rows[i].SummaryCounts[contract.ReceiptEffectCount] = 1
		rows[i].SummaryCounts[contract.ReceiptSummaryUnknownCount] = 1
	}
	return rows
}

func seedBothFullReceiptWindows(t *testing.T, env fixtureEnvironment, f *environmentFixture) contract.MutationReceiptWindows {
	t.Helper()
	windows := contract.MutationReceiptWindows{DomainID: env.Domain,
		Successes: fullSuccessReceiptRows(env.Domain, f.session.admission),
		Failures:  fullUnknownReceiptRows(env.Domain, f.session.admission)}
	// This synthetic history selects all successes, then all failures.
	for _, rows := range [][]contract.CompactMutationReceipt{windows.Successes, windows.Failures} {
		for _, row := range rows {
			windows.Order = append(windows.Order, row.OperationID)
		}
	}
	for i, row := range windows.Failures {
		if !contract.CompactMutationReceiptValid(row) {
			t.Fatalf("invalid retained unknown receipt %d", i)
		}
	}
	storage := mutationReceiptFixtureStorage(t, windows)
	if len(storage.objects) != 2 || len(storage.pages[0].Records) != 2*contract.MutationReceiptWindowLimit ||
		len(storage.pages[1].Records) != 1 {
		t.Fatal("both full receipt windows did not encode one exact selected image")
	}
	seedSignedReceiptWindows(t, env, f, storage)
	return windows
}

// The fixture signs terminal receipt history before the next real mutation.
// It does not claim that the history's 512 operations ran in this test.
func seedSignedReceiptWindows(t *testing.T, env fixtureEnvironment, f *environmentFixture, storage mutationReceiptStorage) {
	t.Helper()
	current := *f.session
	var retainedRefs []format.Ref
	var retainedPages []format.RequiredSupportPageView
	var retainedCount uint32
	used := make(map[uint16]bool)
	for i, page := range f.session.support {
		if !slices.ContainsFunc(page.Records, func(row contract.SupportRecordView) bool {
			return row.Kind == contract.OutputConfigurationSliceSupportKind
		}) {
			continue
		}
		ref := f.session.root.RequiredSupport[i]
		key, err := format.Key(env.Store.Descriptor().Prefix, ref)
		if err != nil {
			t.Fatal("configuration fixture key", err)
		}
		read := env.Store.Read(t.Context(), key, ref.Length)
		if read.Status != contract.ReadOK || uint32(len(read.Body)) != ref.Length || contract.Hash(read.Body) != ref.Digest {
			t.Fatal("configuration fixture readback differs")
		}
		view, err := format.InspectRequiredSupportPage(read.Body)
		if err != nil {
			t.Fatal("configuration fixture page", err)
		}
		for _, row := range view.Records {
			if row.Kind != contract.OutputConfigurationSliceSupportKind {
				t.Fatal("configuration fixture page includes replaced history")
			}
		}
		retainedRefs = append(retainedRefs, ref)
		retainedPages = append(retainedPages, view)
		retainedCount += uint32(len(view.Records))
		used[ref.Index] = true
	}
	if retainedCount != uint32(current.root.OutputConfiguration.SliceCount) {
		t.Fatal("receipt fixture omitted mandatory configuration")
	}
	relocated := make(map[uint16]uint16)
	for i, page := range storage.pages {
		physical := uint16(0)
		for used[physical] {
			physical++
		}
		used[physical], relocated[page.Index] = true, physical
		rows := make([]contract.SupportRecord, len(page.Records))
		for j, row := range page.Records {
			rows[j] = contract.SupportRecord(row)
		}
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: physical, Records: rows})
		if err != nil {
			t.Fatal("relocated receipt fixture page", err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, physical, body)
		if err != nil {
			t.Fatal("relocated receipt fixture reference", err)
		}
		view, err := format.InspectRequiredSupportPage(body)
		if err != nil {
			t.Fatal("relocated receipt fixture view", err)
		}
		storage.refs[i], storage.pages[i], storage.objects[i] = ref, view, objectImage{ref: ref, body: body}
	}
	storage.generated.Fragments = slices.Clone(storage.generated.Fragments)
	for i := range storage.generated.Fragments {
		storage.generated.Fragments[i].SupportPageIndex = relocated[storage.generated.Fragments[i].SupportPageIndex]
	}
	storage.refs = append(storage.refs, retainedRefs...)
	storage.pages = append(storage.pages, retainedPages...)
	storage.count += retainedCount
	slices.SortFunc(storage.refs, func(a, b contract.Ref) int { return int(a.Index) - int(b.Index) })
	slices.SortFunc(storage.pages, func(a, b format.RequiredSupportPageView) int { return int(a.Index) - int(b.Index) })
	storage.install(&current)
	current.root.Snapshot, current.root.Transition = fixtureID(env.Domain, "full receipt snapshot"), fixtureID(env.Domain, "full receipt transition")
	indexObjects := installReceiptFixtureAdministrativeIndex(t, &current)
	for _, object := range append(storage.objects, indexObjects...) {
		key, err := format.Key(env.Store.Descriptor().Prefix, object.ref)
		if err != nil {
			t.Fatal("signed receipt fixture object key", err)
		}
		if err := env.Put(context.Background(), key, object.body); err != nil {
			t.Fatal("signed receipt fixture object create", err)
		}
	}
	body, err := format.EncodeRoot(current.root)
	if err != nil {
		t.Fatal("signed receipt fixture root encoding", err)
	}
	ref, err := format.Reference(format.RootKind, env.Domain, current.root.Snapshot, 0, body)
	if err != nil {
		t.Fatal("signed receipt fixture root reference", err)
	}
	key, err := format.Key(env.Store.Descriptor().Prefix, ref)
	if err != nil {
		t.Fatal("signed receipt fixture root key", err)
	}
	if err := env.Put(context.Background(), key, body); err != nil {
		t.Fatal("signed receipt fixture root create", err)
	}
	h := current.head
	h.Core.Root, h.Core.Revision = ref, fixtureID(env.Domain, "full receipt revision")
	h.Core.PreviousRevision, h.Core.PreviousDigest, h.Core.PreviousToken = f.session.head.Core.Revision, contract.Hash(f.session.body), f.session.token
	h.Subject.Operation = fixtureID(env.Domain, "full receipt operation")
	h.Subject.Normal.PublicState = current.publicState()
	h.Subject.Request = requestCommitment(h.Core, h.Subject)
	core, err := format.EncodeHeadCore(h.Core)
	if err != nil {
		t.Fatal("signed receipt fixture HEAD core", err)
	}
	conditionalBody, err := format.EncodeConditionalPlan(conditional(h.Core, core))
	if err != nil {
		t.Fatal("signed receipt fixture conditional plan", err)
	}
	h.Subject.HeadCore, h.Subject.HeadCoreLength, h.Subject.ConditionalPlan = contract.Hash(core), uint32(len(core)), contract.Hash(conditionalBody)
	request, err := contract.NewLifecycleRequest(h.Subject)
	if err != nil {
		t.Fatal("signed receipt fixture lifecycle request", err)
	}
	proof := env.Trust.Sign(context.Background(), request)
	if proof.Reason != contract.ReasonNone {
		t.Fatal("trusted receipt fixture signing failed", proof.Reason)
	}
	h.AuthorizationSignature = proof.Signature
	body, err = format.EncodeHead(h)
	if err != nil {
		t.Fatal("signed receipt fixture HEAD encoding", err)
	}
	if err := env.Put(context.Background(), env.Store.Descriptor().HeadKey, body); err != nil {
		t.Fatal("signed receipt fixture HEAD create", err)
	}
	opened, result := Open(context.Background(), f.admission, env.Store)
	if opened == nil {
		t.Fatal("trusted full receipt predecessor did not authenticate", result)
	}
	f.session = opened
}

// full_only: false
func TestSignedBothFullReceiptWindowsColdOpen(t *testing.T) {
	env, _ := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, context.Background(), env, []int{1}, false)
	want := seedBothFullReceiptWindows(t, env, f)
	opened, result := Open(context.Background(), f.admission, env.Store)
	if opened == nil || result.Outcome != ObservedCurrent {
		t.Fatal("both-window predecessor did not cold-open", result)
	}
	got, err := opened.receiptWindows(t.Context())
	if err != nil || len(got.Successes) != contract.MutationReceiptWindowLimit ||
		len(got.Failures) != contract.MutationReceiptWindowLimit ||
		!reflect.DeepEqual(got.Successes, want.Successes) || !reflect.DeepEqual(got.Failures, want.Failures) || !reflect.DeepEqual(got.Order, want.Order) {
		t.Fatal("both full receipt windows changed in selected storage", err)
	}
	if len(opened.adminIndex.Groups) != 0 || opened.root.RequiredSupportRecordCount != 2*contract.MutationReceiptWindowLimit+2 {
		t.Fatal("both-window signed predecessor has unexpected selected work or row count")
	}
}

// full_only: false
func TestSuccessionBoundsFullReceiptWindowRetainsExactColdResults(t *testing.T) {
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, true)
	f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	previous := seedFullSuccessionReceiptWindow(t, env, f)
	before := f.session
	control, err := contract.EncodeControlCore(currentControlOf(before))
	if err != nil {
		t.Fatal(err)
	}
	after, err := contract.DecodeControlCore(control)
	if err != nil {
		t.Fatal(err)
	}
	successor, binding := env.Recovery.(*testtrust.Signer).Successor(t, after.Recovery.Signing)
	after.Recovery.Signing, after.AccessGeneration = binding, after.AccessGeneration+1
	permit := admitAuthorityReplacement(t, before, keys, after, 3, 1, 4, contract.BindingTableRow{})
	public, private := keys.Calls()
	candidate, result := before.PrepareSuccession(ctx, permit, SuccessionSigners{Authorizer: env.Trust, RecoverySuccessor: successor})
	if candidate == nil {
		t.Fatal("full window blocked required recovery succession", result)
	}
	admission := deliverSuccessionBasis(t, candidate)
	if result = before.Select(ctx, candidate); result.Outcome != ObservedCurrent {
		t.Fatal("full receipt window replacement did not select", result)
	}
	keys.SetUnavailable(true)
	selected, result := Open(ctx, admission, env.Store)
	if selected == nil {
		t.Fatalf("full receipt window cold open refused: outcome=%d reason=%d", result.Outcome, result.Reason)
	}
	if selected.root.ChildCount != before.root.ChildCount || selected.root.RequiredSupportRecordCount != 258 || len(selected.root.RequiredSupport) != 3 {
		t.Fatalf("full receipt window changed selected counts: before_children=%d selected_children=%d support_records=%d support_refs=%d", before.root.ChildCount, selected.root.ChildCount, selected.root.RequiredSupportRecordCount, len(selected.root.RequiredSupport))
	}
	receiptPages := 0
	for _, page := range selected.support {
		receiptRows := 0
		for _, row := range page.Records {
			if row.Kind == contract.MutationReceiptSupportKind {
				receiptRows++
			}
		}
		if receiptRows == 0 {
			continue
		}
		receiptPages++
		if receiptRows != 256 || len(page.Records) != 256 {
			t.Fatalf("full receipt page changed row set: index=%d receipt_rows=%d page_rows=%d", page.Index, receiptRows, len(page.Records))
		}
		for _, row := range page.Records {
			if len(row.Body) != 471 {
				t.Fatalf("full receipt page changed encoded row length: index=%d length=%d", page.Index, len(row.Body))
			}
		}
		matchedRefs := 0
		for _, ref := range selected.root.RequiredSupport {
			if ref.Index != page.Index {
				continue
			}
			matchedRefs++
			if ref.Kind != contract.RequiredSupportKind || ref.Domain != page.Domain || ref.Object != page.Object || ref.Length != 75+256*508 {
				t.Fatalf("full receipt page changed reference or encoded headroom: index=%d kind=%d length=%d", ref.Index, ref.Kind, ref.Length)
			}
		}
		if matchedRefs != 1 {
			t.Fatalf("full receipt page lacks one selected reference: index=%d refs=%d", page.Index, matchedRefs)
		}
	}
	if receiptPages != 1 {
		t.Fatalf("full receipt window changed receipt page count: pages=%d", receiptPages)
	}
	window, err := selected.receiptWindows(t.Context())
	if err != nil || len(window.Successes) != 256 {
		t.Fatal("full receipt window did not retain exactly 256 rows", err)
	}
	for i := 0; i < 255; i++ {
		if window.Successes[i] != previous[i+1] {
			t.Fatal("receipt append changed retained order or fields", i)
		}
	}
	if window.Successes[255].OperationID != permit.request.OperationID {
		t.Fatal("new recovery receipt is not last")
	}
	for _, row := range []contract.CompactMutationReceipt{previous[1], previous[255]} {
		want, err := contract.EncodeCompactMutationReceipt(row)
		if err != nil {
			t.Fatal(err)
		}
		got, result := selected.MutationReceipt(ctx, row.OperationID)
		if result.Outcome != ObservedCurrent || !bytes.Equal(got, want) {
			t.Fatal("cold retrieval changed the retained receipt bytes", result)
		}
	}
	if got, result := selected.MutationReceipt(ctx, previous[0].OperationID); got != nil || result.Outcome != AdmissionRefused {
		t.Fatal("evicted oldest receipt remained retrievable", result)
	}
	checkSuccessionReceipt(t, context.Background(), selected, permit)
	if p, k := keys.Calls(); p != public || k != private {
		t.Fatal("signer-only full-window replacement or cold retrieval used Crypto")
	}
	basis := successionBasisTransport(admission.admission.current)
	process := selectedProcessFacts(t, admission, selected)
	process.CurrentBasis, process.Objects = &basis, env.Store.(*memoryStore).objects
	checkFreshProcessInput(t, process)
}

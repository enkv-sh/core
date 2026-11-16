package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestRecoveryReceiptProjectionPreservesWrappedEndWorkCapacityCause(t *testing.T) {
	for _, count := range []int{21, 22} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			source, store, trust, keys := successorCapacityColdSelection(t, successorWrappedCapacityState(t, count))
			// This exercises the Recovery receipt projection owner before Crypto. The
			// full role declaration/admission is separately checked by succession tests.
			intent := contract.RecipientReplacementIntent{RecipientReplacementIntentFields: contract.RecipientReplacementIntentFields{Schema: contract.CanonicalSchema, Profile: 2, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), DomainID: source.root.Domain, BeforeAccessRoot: source.root.CurrentAccess.AccessRoot, RecipientID: generatedVectorID(26)}, Before: *source.recipientRecord(generatedVectorID(26)).CurrentBinding, Successor: keys.RecipientSuccessor(t, generatedVectorID(26))}
			plan, ok := source.planRecipientReplacement(t.Context(), intent)
			if !ok {
				t.Fatal("public support identity allocation")
			}
			request := contract.SuccessionRequestCore{OperationKind: contract.SuccessionReplaceRecoveryBasis, DomainID: source.root.Domain, OperationID: plan.operation, PredecessorHeadRevisionID: source.head.Core.Revision}
			subjects := contract.GeneratorDescriptor{Digest: contract.Hash([]byte("independent Recovery projection changed-subject vector")), Length: 80, Count: 2}
			before := generatedSuccessorPredecessorSnapshot(t, source)
			public, private := keys.Calls()
			creates, cas, signs := store.creates, store.cas, trust.signs
			projected, err := source.projectedSuccessionRoot(t.Context(), request, plan, subjects)
			bytes := uint64(count)*393216 + 12
			fragments := (bytes + 1048320 - 1) / 1048320
			pages := (fragments + 1) / 2
			children := uint64(252+2-2) + pages
			if source.root.ChildCount != 250 || count == 21 && (bytes != 8257548 || fragments != 8 || pages != 4 || children != 256 || err != nil || projected.ChildCount != 252 || projected.Generated.SuccessWindow.Count != 1) || count == 22 && (bytes != 8650764 || fragments != 9 || pages != 5 || children != 257 || !errors.Is(err, contract.ErrRecordCapacity) || err == contract.ErrRecordCapacity) {
				t.Fatal("Recovery receipt lost exact252 ordinary /256 first-EndWork adjacent boundary", projected.ChildCount, children, err)
			}
			p, k := keys.Calls()
			if p != public || k != private || store.creates != creates || store.cas != cas || trust.signs != signs || string(before) != string(generatedSuccessorPredecessorSnapshot(t, source)) {
				t.Fatal("Recovery capacity projection used private/write authority or changed predecessor")
			}
		})
	}
}

// full_only: false
func TestSuppliedApplyReceiptReservationKeepsExistingFastPath(t *testing.T) {
	for _, materialized := range []bool{false, true} {
		t.Run(fmt.Sprintf("materialized=%t", materialized), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			fixture := newInstalledApplyTestFixture(t, ctx, contract.AWS, true)
			source := fixture.selected
			if len(source.adminIndex.Groups) != 0 || source.root.Generated.GeneratedCurrent != 0 {
				t.Fatal("Apply admission requires no generated work")
			}
			// Genesis puts its receipt and single output slice on physical page0.
			// Replacing that receipt rewrites the page. A cold reader must fetch
			// the exact retained slice; a body-backed reader needs no such GET.
			if len(source.support) != 2 || len(source.root.RequiredSupport) != 2 || source.support[0].Index != 0 || source.root.RequiredSupport[0].Index != 0 {
				t.Fatal("genesis support fixture shape changed")
			}
			ref := source.root.RequiredSupport[0]
			key, err := format.Key(source.admission.store.Prefix, ref)
			if err != nil {
				t.Fatal("original mixed support page key", err)
			}
			outputs, receipts := 0, 0
			for _, row := range source.support[0].Records {
				switch row.Kind {
				case contract.OutputConfigurationSliceSupportKind:
					outputs++
					if row.Body != nil {
						t.Fatal("cold fixture retained an output body")
					}
				case contract.MutationReceiptSupportKind:
					receipts++
				}
			}
			if outputs != 1 || receipts != 1 || len(source.support[0].Records) != 2 {
				t.Fatal("genesis must share exactly one receipt and output slice")
			}
			if materialized {
				generatedMaterializeFixtureSupport(t, source)
				for _, row := range source.support[0].Records {
					if row.Kind == contract.OutputConfigurationSliceSupportKind && row.Body == nil {
						t.Fatal("body-backed fixture did not retain its authenticated slice")
					}
				}
			}
			comparison, result := source.compareEntryInputs([]ApplyEntryInput{{Name: "capacity-fast-plain", Recipients: []contract.ID{source.admission.recipient}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("public supplied value")}})
			if comparison == nil || result.Outcome != ObservedCurrent {
				t.Fatal("public Apply comparison", result)
			}
			before, err := source.receiptWindows(ctx)
			if err != nil {
				t.Fatal(err)
			}
			comparison.applyReceipt = &installedApplyReceipt{before: before}
			plan, err := planTransition(ctx, comparison)
			if err != nil {
				t.Fatal(err)
			}
			comparison.applyReceipt.subjects, err = installedApplyChangedSubjects(comparison, plan)
			if err != nil {
				t.Fatal(err)
			}
			store := fixture.env.Store.(*memoryStore)
			if store.readHook != nil {
				t.Fatal("reservation fixture already has a read hook")
			}
			var readKeys []string
			joined := 0
			store.readHook = func(readKey string, read contract.ReadResult) contract.ReadResult {
				readKeys = append(readKeys, readKey)
				if readKey == key && read.Status == contract.ReadOK && read.Token.Valid() && format.CheckReference(ref, read.Body) == nil {
					joined++
				}
				return read
			}
			defer func() { store.readHook = nil }()
			reads, creates, cas := store.reads, store.creates, store.cas
			public, private := fixture.keys.Calls()
			signs := fixture.env.Trust.(*fixtureTrust).Calls()
			original := generatedSuccessorPredecessorSnapshot(t, source)
			if err := source.reserveInstalledApplyReceipt(ctx, comparison, plan); err != nil {
				t.Fatal("actual supplied Apply reservation", err)
			}
			var wanted []string
			if !materialized {
				wanted = []string{key}
			}
			if !slices.Equal(readKeys, wanted) || store.reads-reads != len(wanted) || joined != len(wanted) {
				t.Fatalf("Apply reservation changed the exact retained-output GET set: calls=%d observed=%d joined=%d expected=%d", store.reads-reads, len(readKeys), joined, len(wanted))
			}
			p, k := fixture.keys.Calls()
			if store.creates != creates || store.cas != cas || p != public || k != private || fixture.env.Trust.(*fixtureTrust).Calls() != signs {
				t.Fatalf("Apply reservation used private/write authority: creates=%d cas=%d public=%d private=%d signs=%d", store.creates-creates, store.cas-cas, p-public, k-private, fixture.env.Trust.(*fixtureTrust).Calls()-signs)
			}
			if string(original) != string(generatedSuccessorPredecessorSnapshot(t, source)) {
				t.Fatal("Apply reservation changed authenticated predecessor state or backing")
			}
			for _, page := range source.supportFacts {
				if page.plannedReceipt != nil {
					t.Fatal("Apply source acquired a reservation token")
				}
			}
		})
	}
}

// Reseal only the pressure fixture, using its original admission and signers.
func receiptCapacityPressureColdState(t *testing.T, ctx context.Context, f installedApplyTestFixture, s *StateSession) *StateSession {
	t.Helper()
	store, ok := underlyingAdmittedMemoryStore(f.env.Store)
	if !ok {
		t.Fatal("pressure fixture has no original memory Store")
	}
	trust, ok := underlyingAdmittedFixtureTrust(f.env.Trust)
	if !ok || s.head.AuthKind != format.LifecycleAuth {
		t.Fatal("pressure fixture has no original lifecycle Trust")
	}
	before := make(map[string]contract.GeneratedEntryMetadata)
	values := make(map[string][]byte)
	for _, named := range s.root.Names {
		entry := s.valueEntry(named.Slot)
		if entry == nil {
			t.Fatal("pressure fixture current entry missing")
		}
		before[named.Name], values[named.Name] = entry.Generated, bytes.Clone(entry.ValueBytes)
	}
	configuration := 0
	for _, page := range s.support {
		if len(page.Records) == 1 && page.Records[0].Kind == contract.OutputConfigurationSliceSupportKind {
			configuration++
		}
	}
	if configuration != 1 {
		t.Fatal("pressure fixture requires one isolated actual configuration page", configuration)
	}
	generatedMaterializeFixtureSupport(t, s)
	successorCapacityPublicationRows(t, s)
	generatedSealSelectedFixture(t, s)
	if s.root.ChildCount != 250 {
		t.Fatal("pressure fixture is not the actual 250-child image", s.root.ChildCount)
	}
	put := func(ref contract.Ref, body []byte, err error) {
		t.Helper()
		if err != nil || format.CheckReference(ref, body) != nil {
			t.Fatal("pressure object encoding", err)
		}
		store.put(mustKey(t, store.desc.Prefix, ref), body)
	}
	for i, page := range s.pages {
		if page != nil {
			body, err := format.EncodeValueEntryPage(*page)
			put(*s.root.ValueEntryPages[i], body, err)
		}
	}
	for i, page := range s.recipients {
		if page != nil {
			body, err := format.EncodeRecipientPage(*page)
			put(*s.root.Recipients[i], body, err)
		}
	}
	for _, ref := range s.root.CurrentAccess.Core.AccessPageRefs {
		body, err := format.EncodeAccessPage(*s.access[ref.Index])
		put(ref, body, err)
	}
	for i, page := range s.support {
		rows := make([]contract.SupportRecord, len(page.Records))
		for j, row := range page.Records {
			rows[j] = contract.SupportRecord(row)
		}
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: rows})
		put(s.root.RequiredSupport[i], body, err)
	}
	shards, err := format.EncodeAdministrativeIndexPages(s.adminIndex)
	if err != nil {
		t.Fatal(err)
	}
	for _, shard := range shards {
		put(shard.Ref, shard.Body, nil)
	}
	body, err := format.EncodeRoot(s.root)
	put(s.head.Core.Root, body, err)
	receiptCapacityStorePressureLifecycleHead(t, f, s, store, trust)
	cold := f.open(t, ctx)
	if cold.root.Domain != s.root.Domain || cold.root.ChildCount != 250 || len(cold.adminIndex.Groups) == 0 || len(cold.root.Names) != len(before) {
		t.Fatal("pressure cold selection changed original domain/current image")
	}
	for _, named := range cold.root.Names {
		entry := cold.valueEntry(named.Slot)
		if entry == nil || entry.Generated != before[named.Name] || !bytes.Equal(entry.ValueBytes, values[named.Name]) {
			t.Fatal("pressure setup changed original canonical value or generated evidence", named.Name)
		}
	}
	return cold
}

func checkProspectiveReceiptCapacity(t *testing.T, ctx context.Context, f installedApplyTestFixture, source *StateSession, input []ApplyEntryInput, wantGenerated int, registry ...contract.GeneratorImplementation) {
	t.Helper()
	parent := admitSuppliedComparison(t, source, f.keys, input, registry...)
	defer f.keys.RetireApply()
	c, result := source.Compare(ctx, input, parent)
	if c == nil || result.Outcome != ObservedCurrent {
		t.Fatal("prospective receipt comparison", result)
	}
	before, err := source.receiptWindows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c.applyReceipt = &installedApplyReceipt{before: before}
	p, err := planTransition(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	c.applyReceipt.subjects, err = installedApplyChangedSubjects(c, p)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := prospectiveNormalGeneratedEntryMetadata(c)
	if err != nil || len(entries) != wantGenerated || wantGenerated == 0 && entries == nil {
		t.Fatal("exact prospective metadata, including explicit empty set", len(entries), err)
	}
	if wantGenerated != 0 {
		// Build only the actual receipt/support projection needed to count its
		// physical refs. This is no alternate row encoder or capacity oracle.
		empty := contract.EmptyMutationResultDescriptors()
		request := requestCommitment(source.successorCore(p), contract.LifecycleSubject{IdentityPlan: identityCommitment(c, p), Normal: contract.NormalSection{Intent: contract.DigestLength{Digest: c.desired, Length: c.desiredLength}}})
		delta, err := source.installedApplyReceiptPlan(c, p, empty[0], request)
		if err != nil {
			t.Fatal(err)
		}
		storage, err := source.encodeLifecycleReceiptSupport(ctx, c, p, delta, contract.ID{})
		if err != nil {
			t.Fatal(err)
		}
		projection := *source
		projection.root.Snapshot, projection.root.Transition = p.snapshot, p.transition
		if err := projection.installApplyRecipientPages(c, p); err != nil {
			t.Fatal(err)
		}
		storage.install(&projection)
		projection.root.ValueEntryPages = [contract.MaxValueEntryPages]*contract.Ref{}
		projection.root.CurrentAccess.Core.AccessPageRefs = nil
		projection.recountChildren()
		withoutIndex := int64(projection.root.ChildCount) - int64(1+len(projection.root.AdministrativeIndexShards))
		// ceil(128*393216/1048320)=49 fragments; ceil(49/2)=25 pages.
		// The scalar's publication-page delta is nonnegative and its final
		// index has at least one shard. Thus the actual scalar is at least:
		lowerBound := withoutIndex + 2 + 25 + 1
		if lowerBound <= 256 {
			t.Fatal("fixture cannot prove scalar slow-path entry", lowerBound)
		}
		t.Logf("prospective receipt scalar >= %d > 256; first-EndWork slow path required", lowerBound)
	}
	store, ok := underlyingAdmittedMemoryStore(f.env.Store)
	if !ok {
		t.Fatal("original Store unavailable")
	}
	trust, ok := underlyingAdmittedFixtureTrust(f.env.Trust)
	if !ok {
		t.Fatal("original Trust unavailable")
	}
	public, private := f.keys.Calls()
	creates, cas, signs, signCalls, qualifications := store.creates, store.cas, trust.signs, trust.Calls(), trust.QualificationCalls()
	original := generatedSuccessorPredecessorSnapshot(t, source)
	err = source.reserveInstalledApplyReceipt(ctx, c, p)
	if err != nil {
		t.Error("prospective receipt capacity refused", err)
	}
	afterPublic, afterPrivate := f.keys.Calls()
	if public != afterPublic || private != afterPrivate || creates != store.creates || cas != store.cas || signs != trust.signs || signCalls != trust.Calls() || qualifications != trust.QualificationCalls() || !bytes.Equal(original, generatedSuccessorPredecessorSnapshot(t, source)) {
		t.Fatal("capacity used key/Trust/write authority or changed its authenticated predecessor")
	}
}

// This is a real ordinary Apply before fixture pressure is added. It retains
// both selected generated values and the real CF release, and adds one plain
// value so that Unchanged cannot stand in for a selected LifecycleAuth HEAD.
func receiptCapacityLifecycleCheckpoint(t *testing.T, ctx context.Context, f installedApplyTestFixture, s *StateSession, declarations []ApplyEntryInput, author installedLocalAuthor, admissions *int, effects func() (int, []string)) *StateSession {
	t.Helper()
	work := mustSelectedGeneratedWork(t, s)
	if work.parent != nil || len(work.releases) != 1 || s.root.Generated.GeneratedCurrent != 2 {
		t.Fatal("capacity checkpoint lost the real mixed starting state")
	}
	input := s.currentEntryInputs()
	for at := range input {
		entry := &input[at]
		defer clear(entry.InputBytes[:cap(entry.InputBytes)])
		if entry.Name == "zz-receipt-capacity" {
			t.Fatal("capacity plain name already exists")
		}
		declared := slices.IndexFunc(declarations, func(row ApplyEntryInput) bool { return row.Name == entry.Name })
		if declared < 0 || declarations[declared].Generated == nil {
			t.Fatal("capacity checkpoint original declaration missing", entry.Name)
		}
		generation := *declarations[declared].Generated
		generation.Intent = bytes.Clone(generation.Intent)
		defer clear(generation.Intent[:cap(generation.Intent)])
		entry.Generated = &generation
	}
	before := make(map[string]contract.GeneratedEntryMetadata)
	for _, named := range s.root.Names {
		entry := s.valueEntry(named.Slot)
		if entry == nil || entry.ValueSource != contract.Generated {
			t.Fatal("mixed checkpoint current entry missing")
		}
		before[entry.Name] = entry.Generated
	}
	beforeAdmissions := *admissions
	beforeCreates, beforeDeletes := effects()
	beforeRevision := s.head.Core.Revision
	input = append(input, ApplyEntryInput{Name: "zz-receipt-capacity", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain,
		Recipients: []contract.ID{s.admission.recipient}, InputBytes: []byte("ordinary checkpoint before capacity pressure"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
	engine := installedLocalEngine(t, ctx, f, s, input, author, admissions)
	result := engine.Apply(ctx, fixtureID(f.env.Domain, "receipt capacity ordinary lifecycle checkpoint"), input)
	engine.Close()
	if result.Result.Outcome != ObservedCurrent {
		t.Fatal("ordinary capacity checkpoint did not select", result.Result)
	}
	current := f.open(t, ctx)
	afterCreates, afterDeletes := effects()
	if current.head.AuthKind != format.LifecycleAuth || current.head.Core.Revision == beforeRevision || *admissions != beforeAdmissions ||
		afterCreates != beforeCreates || !slices.Equal(afterDeletes, beforeDeletes) {
		t.Fatal("ordinary capacity checkpoint did not select without a generated callback")
	}
	if len(current.root.Names) != len(before)+1 || current.root.Generated.GeneratedCurrent != 2 || !current.root.Generated.ActiveOwner.IsZero() {
		t.Fatal("ordinary checkpoint changed the original generated set")
	}
	selected := mustSelectedGeneratedWork(t, current)
	if selected.parent != nil || len(selected.releases) != len(work.releases) {
		t.Fatal("ordinary checkpoint changed the real release set")
	}
	for _, old := range input[:len(input)-1] {
		index := slices.IndexFunc(current.root.Names, func(name format.NameEntry) bool { return name.Name == old.Name })
		if index < 0 {
			t.Fatal("ordinary checkpoint removed original entry", old.Name)
		}
		entry := current.valueEntry(current.root.Names[index].Slot)
		if entry == nil || entry.Generated != before[old.Name] || !bytes.Equal(entry.ValueBytes, old.InputBytes) {
			t.Fatal("ordinary checkpoint changed original generated metadata/value", old.Name)
		}
		for _, key := range []generatedRecordKey{{contract.GeneratedCreateEvidenceSupportKind, entry.Generated.CreateResultID}} {
			if !bytes.Equal(selected.records[key].Body, work.records[key].Body) {
				t.Fatal("ordinary checkpoint changed original create evidence")
			}
		}
	}
	for id, original := range work.releases {
		retained, ok := selected.releases[id]
		if !ok || retained.attempt != original.attempt || retained.release != original.release || retained.template != original.template {
			t.Fatal("ordinary checkpoint changed original release mapping")
		}
	}
	return current
}

// Replace the old pressure helper's bare storeHead call with this existing
// lifecycle-subject construction route. The fixture has already encoded its
// pressure children/index/root into the ORIGINAL Store. This does not change
// original admission, binding, canonical values, wraps, K1 or K3.
func receiptCapacityStorePressureLifecycleHead(t *testing.T, f installedApplyTestFixture, s *StateSession, store *memoryStore, trust *fixtureTrust) {
	t.Helper()
	if s.head.AuthKind != format.LifecycleAuth {
		t.Fatal("pressure needs the selected ordinary checkpoint")
	}
	input := s.currentEntryInputs()
	for _, entry := range input {
		defer clear(entry.InputBytes[:cap(entry.InputBytes)])
	}
	rows, _, err := buildEntryIntent(s.root.Domain, input)
	if err != nil {
		t.Fatal("pressure exact current intent", err)
	}
	desired, err := contract.CompleteApplyIntentDescriptor(s.root.Domain, rows, currentApplyRecipients(s.registry()))
	if err != nil {
		t.Fatal("pressure exact current intent recipients", err)
	}
	p := transitionPlan{operation: fixtureID(f.env.Domain, "receipt pressure selected operation"), revision: fixtureID(f.env.Domain, "receipt pressure selected revision"), snapshot: s.root.Snapshot, transition: s.root.Transition}
	for i, ref := range s.root.ValueEntryPages {
		if ref != nil {
			p.pages[i] = ref.Object
		}
	}
	for i, ref := range s.root.Recipients {
		if ref != nil {
			p.recipientPages[i] = ref.Object
		}
	}
	for _, ref := range s.root.CurrentAccess.Core.AccessPageRefs {
		p.accessPages[ref.Index] = ref.Object
	}
	for _, ref := range s.root.RequiredSupport {
		p.supportPages[ref.Index] = ref.Object
	}
	c := &Comparison{session: s, desired: desired.Digest, desiredLength: desired.Length}
	authority, err := s.authorityFrom(s, c, p)
	if err != nil {
		t.Fatal("pressure original-key lifecycle authority", err)
	}
	originalK1, originalK3 := s.head.K1, s.head.K3
	root := s.head.Core.Root
	s.head = format.Head{Core: s.successorCore(p), AuthKind: format.LifecycleAuth, Subject: authority.subject(), K1: originalK1, K3: originalK3}
	s.head.Core.Root = root
	storeHead(t, &fixture{store: store, trust: trust}, s.head, true)
}

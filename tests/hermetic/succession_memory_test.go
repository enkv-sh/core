package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/crypto/testsupport/custody"
	testtrust "enkv.sh/crypto/testsupport/trust"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestCurrentReadStopsAtDeclaredAccessLimit(t *testing.T) {
	ctx := context.Background()
	env := memoryScenarioEnvironmentMode(t, true)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	recipients := []contract.ID{f.session.admission.recipient, fixtureID(env.Domain, "reader")}
	slices.SortFunc(recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	input := make([]ApplyEntryInput, 48)
	for i := range input {
		name := fmt.Sprintf("access-limit-%02d", i)
		input[i] = sharingSecretNamed(t, env, name, name, recipients)
	}
	run.suppliedSelection(f, input)
	root := f.session.root
	// Mandatory configuration uses the byte-packed normal transition path:
	// 48 records with two ordinary wraps and one recovery wrap fit one page.
	const accessBytes = 75 + 48*102 + (96+48)*489
	if root.ValueEntryCount != 48 || root.SecretCount != 48 || root.MembershipCount != 96 ||
		root.SecretOrdinaryWrapCount != 96 || root.AccessRecordCount != 48 ||
		len(root.CurrentAccess.Core.AccessPageRefs) != 1 || root.CurrentAccess.Core.AccessPageRefs[0].Length != accessBytes {
		t.Fatal("access limit fixture dimensions", root.ValueEntryCount, root.SecretCount, root.MembershipCount,
			root.SecretOrdinaryWrapCount, root.AccessRecordCount, root.CurrentAccess.Core.AccessPageRefs)
	}
	// The signed root admits 48 ordinary wraps, but references bytes for 96.
	// Refuse the impossible aggregate before allocating any child body.
	root.SecretOrdinaryWrapCount = 48
	root.Snapshot = fixtureID(env.Domain, "access limit root")
	body, err := format.EncodeRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(contract.RootKind, env.Domain, root.Snapshot, 0, body)
	if err != nil {
		t.Fatal(err)
	}
	store := env.Store.(*memoryStore)
	store.put(mustKey(t, store.desc.Prefix, ref), body)
	head := f.session.head
	head.Core.Root = ref
	storeHead(t, &fixture{store: store, trust: env.Trust.(*fixtureTrust)}, head, true)
	readChild := false
	store.readHook = func(key string, result contract.ReadResult) contract.ReadResult {
		readChild = readChild || key != store.desc.HeadKey && key != mustKey(t, store.desc.Prefix, ref)
		return result
	}
	current, result := Open(ctx, f.admission, store)
	if current != nil || result.Outcome != IntegrityFailure || result.Reason != InvalidRelation || readChild {
		t.Fatal("access byte overflow reached a child read", result, readChild)
	}
}

// full_only: false
func TestRetainedByteCapacitySuccessionOwners(t *testing.T) {
	t.Run("replacement-source-account", assertReplacementMemorySourceAccount)
	t.Run("replacement-delivery-owners", assertReplacementDeliveryOwners)
	// Separate allocations have independent expected capacities. Repeated aliases
	// below must not add capacity; each new succession owner must add its bytes.
	sizes := []int{11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59}
	owned := make([][]byte, len(sizes))
	var want uint64
	for i, size := range sizes {
		owned[i] = make([]byte, size)
		want += uint64(size)
	}
	state := &StateSession{
		admission: openAdmission{current: &qualifiedCurrentBasis{control: owned[0], selection: owned[1]}},
		support:   []format.RequiredSupportPageView{{Records: []contract.SupportRecordView{{Body: owned[2]}}}},
		head: format.Head{Succession: &format.SuccessionProof{
			Authorizer: contract.PublicSigningBinding{SPKI: owned[3]},
			Evidence:   []contract.SuccessorEvidenceRow{{Trust: contract.SuccessorTrustEvidence{Signature: owned[4]}}},
		}},
	}
	next := &StateSession{body: owned[5]}
	next.root.CurrentAccess.Core.NormalSigning.SPKI = owned[6]
	candidate := &Candidate{head: state.head, succession: &successionPreparation{
		basis: &qualifiedCurrentBasis{control: owned[7], selection: owned[8]},
		selectionAdmission: &openAdmission{
			current:   &qualifiedCurrentBasis{control: owned[9], selection: owned[10]},
			publicKey: owned[11], descriptor: owned[12],
		},
	}}
	next.support = state.support
	if got := retainedByteCapacity(state, nil, candidate, next); got != want {
		t.Fatalf("succession backing union = %d, want %d", got, want)
	}
	runtime.KeepAlive(owned)
}

// full_only: false
func TestRetainedByteCapacitySuccessionRequestOwners(t *testing.T) {
	owned := make([][]byte, 8)
	var want uint64
	for i := range owned {
		owned[i] = make([]byte, i+11)
		want += uint64(cap(owned[i]))
	}
	q := contract.SuccessionRequestCore{}
	q.BeforeControl.AuthorityKMSBinding.SPKI = owned[0]
	q.ProposedAfterControl.AuthorityKMSBinding.SPKI = owned[1]
	q.BeforeControl.NormalSigning.SPKI = owned[2]
	q.ProposedAfterControl.NormalSigning.SPKI = owned[3]
	q.ReplacementPlan.Rows = []contract.SuccessionReplacementRow{{
		BeforeKMS: contract.KMSBinding{SPKI: owned[4]}, AfterKMS: contract.KMSBinding{SPKI: owned[5]},
		BeforeSigning: contract.PublicSigningBinding{SPKI: owned[6]}, AfterSigning: contract.PublicSigningBinding{SPKI: owned[7]},
	}}
	var buffers byteBuffers
	buffers.addSuccessionRequest(q)
	buffers.addControlCore(q.BeforeControl) // An aliased owner adds no second copy.
	if got := buffers.capacity(); got != want {
		t.Fatalf("request backing union = %d, want %d", got, want)
	}
	runtime.KeepAlive(owned)
}

func assertReplacementDeliveryOwners(t *testing.T) {
	t.Helper()
	var owned [][]byte
	var want uint64
	allocate := func() []byte {
		body := make([]byte, 11+len(owned))
		owned = append(owned, body)
		want += uint64(cap(body))
		return body
	}
	control := func() contract.ControlCore {
		var value contract.ControlCore
		value.NormalSigning.SPKI = allocate()
		value.Recovery = &contract.RecoveryBindings{Signing: contract.PublicSigningBinding{SPKI: allocate()}, KMS: contract.KMSBinding{SPKI: allocate()}}
		value.AuthorityKMSBinding.SPKI = allocate()
		return value
	}
	basis := func() PublicBasis {
		return PublicBasis{Descriptor: allocate(), Control: allocate(), Selection: allocate(), SigningAnchor: allocate(),
			StoreConfiguration: allocate(), HEAD: allocate(), Root: allocate(), RecipientPages: [][]byte{allocate(), allocate()}}
	}
	recipients := func() []ReplacementRecipientFact {
		return []ReplacementRecipientFact{{Encryption: contract.KMSBinding{SPKI: allocate()}}, {Encryption: contract.KMSBinding{SPKI: allocate()}}}
	}
	source := &ReplacementInstallation{ExpectedControl: control(), PublicBasis: basis(), CapturedRecipients: recipients()}
	offered := &ReplacementSuccessor{Control: control(), Basis: basis(), Recipients: recipients(), Correlation: ReplacementCorrelation{SignedCandidate: allocate()}}
	readback := &ReplacementReadback{Control: control(), Basis: basis(), Recipients: recipients(), Correlation: ReplacementCorrelation{SignedCandidate: allocate()}}
	var buffers byteBuffers
	buffers.addReplacementSource(source)
	buffers.addReplacementSuccessor(offered)
	buffers.addReplacementReadback(readback)
	// Repeated owners and a delivered alias must contribute no second copy.
	buffers.addReplacementSource(source)
	buffers.addReplacementSuccessor(offered)
	buffers.addReplacementReadback(readback)
	delivered := *offered
	buffers.addReplacementSuccessor(&delivered)
	if got := buffers.capacity(); got != want {
		t.Fatalf("replacement delivery backing union = %d, want %d", got, want)
	}
	runtime.KeepAlive(owned)
}

func sampleInstalledReplacementMemory(m *memoryAccounting, phase string, offered *ReplacementSuccessor, readback *ReplacementReadback) {
	var buffers byteBuffers
	buffers.addReplacementSource(m.replacementSource)
	buffers.addReplacementSuccessor(offered)
	buffers.addReplacementReadback(readback)
	capacity := buffers.capacity()
	m.sample(phase, nil, nil, nil, nil)
	m.samples[len(m.samples)-1].ByteCapacity = capacity
	runtime.KeepAlive(m.replacementSource)
	runtime.KeepAlive(offered)
	runtime.KeepAlive(readback)
}

func sampleSuccessionMemory(m *memoryAccounting, phase string, permit *AdmittedSuccession, candidate *Candidate, observed *StateSession, publicBodies ...[]byte) {
	buffers := retainedByteBuffers(permit.session, nil, candidate, observed)
	buffers.addSuccessionRequest(permit.request)
	buffers.add(permit.source.Binding.SPKI)
	buffers.addReplacementSource(m.replacementSource)
	for _, body := range publicBodies {
		buffers.add(body)
	}
	capacity := buffers.capacity()
	m.sample(phase, permit.session, nil, candidate, observed)
	m.samples[len(m.samples)-1].ByteCapacity = capacity
	runtime.KeepAlive(permit)
	runtime.KeepAlive(candidate)
	runtime.KeepAlive(observed)
	runtime.KeepAlive(publicBodies)
}

// Observe the real transport's byte slices. It never copies a private packet or
// returns a private pointer. Crypto-local decoded batch/output allocations are
// not reachable here; the separately reported Go heap bound includes them.
type successionMemoryCrypto struct {
	contract.Crypto
	t                       *testing.T
	memory                  *memoryAccounting
	permit                  *AdmittedSuccession
	keys                    *custody.Fixture
	cancel                  context.CancelFunc
	fault                   string
	batches                 uint32
	maxRequest, maxResponse int
}

func (w *successionMemoryCrypto) Exchange(ctx context.Context, q contract.CryptoRequest) contract.CryptoResponse {
	if q.Kind == contract.CryptoPrepare {
		w.batches++
		if w.batches == 2 {
			if w.fault == "cancel-second-batch" {
				w.cancel()
			}
			if w.fault == "denied-second-batch" {
				w.keys.SetDenied(w.permit.source.SubjectID, true)
			}
		}
		w.maxRequest = max(w.maxRequest, cap(q.Body))
	}
	sampleSuccessionMemory(w.memory, fmt.Sprintf("exchange-%d-input", q.Kind), w.permit, nil, nil, q.Body)
	if q.Kind == contract.CryptoPrepare {
		var wire byteBuffers
		wire.add(q.Body)
		w.memory.samples[len(w.memory.samples)-1].ResultUnobservedReserve = 8<<20 - min(uint64(8<<20), wire.capacity())
	}
	reply := w.Crypto.Exchange(ctx, q)
	if q.Kind == contract.CryptoPrepare {
		w.maxResponse = max(w.maxResponse, cap(reply.Body))
		if w.batches == 2 && w.fault == "cancel-second-batch" && reply.ResultCode != contract.CryptoCancelled {
			w.t.Fatal("second batch did not reach actual cancellation", reply.ResultCode)
		}
		if w.batches == 2 && w.fault == "denied-second-batch" && reply.ResultCode != contract.CryptoPrivateRouteUnavailable {
			w.t.Fatal("second batch did not reach actual private denial", reply.ResultCode)
		}
	}
	sampleSuccessionMemory(w.memory, fmt.Sprintf("exchange-%d-return", q.Kind), w.permit, nil, nil, q.Body, reply.Body)
	if q.Kind == contract.CryptoPrepare {
		var wire byteBuffers
		wire.add(q.Body)
		wire.add(reply.Body)
		w.memory.samples[len(w.memory.samples)-1].ResultUnobservedReserve = 8<<20 - min(uint64(8<<20), wire.capacity())
	}
	return reply
}

// full_only: false
func TestSuccessionReceiptFixtureKeepsConfiguration(t *testing.T) {
	for _, both := range []bool{false, true} {
		t.Run(fmt.Sprintf("both-windows=%t", both), func(t *testing.T) {
			ctx := t.Context()
			env, _ := genesisEnvironment(t, contract.GCP, true)
			f := newNamedEnvironmentFixture(t, ctx, env, []int{1}, false, []string{"receipt-seed"})
			configurationRefs := capacityConfigurationSelectedRefs(t, f.session)
			if len(configurationRefs) != 1 || f.session.root.OutputConfiguration.SliceCount != 1 {
				t.Fatal("receipt fixture initial configuration")
			}
			configurationRef, configuration := configurationRefs[0], f.session.root.OutputConfiguration
			if both {
				seedBothFullReceiptWindows(t, env, f)
			} else {
				seedFullSuccessionReceiptWindow(t, env, f)
			}
			count := contract.MutationReceiptWindowLimit
			if both {
				count *= 2
			}
			if len(f.session.root.RequiredSupport) != 3 || f.session.root.OutputConfiguration != configuration ||
				!slices.Contains(f.session.root.RequiredSupport, configurationRef) {
				t.Fatal("receipt support dimensions", len(f.session.root.RequiredSupport))
			}
			successionReceiptSupportRef(t, f.session, count)
		})
	}
}

// Receipt pages are located by their authenticated row kind, not their position
// beside the unchanged mandatory configuration page.
func successionReceiptSupportRef(t *testing.T, selected *StateSession, receiptCount int) format.Ref {
	t.Helper()
	indexID, err := selected.receiptIndexID()
	if err != nil || indexID.IsZero() {
		t.Fatal("receipt index identity", err)
	}
	indexRows := make(map[contract.ID]bool)
	for _, location := range selected.root.Generated.Fragments {
		if location.BlobID == indexID {
			id, err := contract.GeneratorFragmentID(indexID, location.FragmentIndex)
			if err != nil {
				t.Fatal(err)
			}
			indexRows[id] = true
		}
	}
	var receiptRef format.Ref
	receipts, indexes, configurationRows, fragments, total := 0, 0, 0, 0, 0
	for _, ref := range selected.root.RequiredSupport {
		position := slices.IndexFunc(selected.supportFacts, func(facts selectedSupportPageFacts) bool { return facts.ref == ref })
		if position < 0 || position >= len(selected.support) {
			t.Fatal("receipt support facts identity")
		}
		view, facts := selected.support[position], selected.supportFacts[position]
		if view.Domain != ref.Domain || view.Object != ref.Object || view.Index != ref.Index || len(view.Records) != len(facts.rows) {
			t.Fatal("receipt support view identity")
		}
		pageReceipts := 0
		for i, row := range view.Records {
			fact := facts.rows[i]
			if row.Kind != fact.Kind() || row.RecordID != fact.RecordID() {
				t.Fatal("receipt support row identity")
			}
			total++
			switch row.Kind {
			case contract.MutationReceiptSupportKind:
				receipts++
				pageReceipts++
				if 37+fact.BodyLength() != 508 {
					t.Fatal("exact receipt row bound", fact.BodyLength())
				}
			case contract.GeneratedFragmentSupportKind:
				fragments++
				if indexRows[row.RecordID] {
					indexes++
					if fact.BodyLength() != uint32(86+26+receiptCount*72) {
						t.Fatal("exact receipt index row bound", fact.BodyLength())
					}
				}
			case contract.OutputConfigurationSliceSupportKind:
				configurationRows++
			case contract.PublicationCoordinateSupportKind, contract.PublicationMarkerSupportKind:
				publication, err := selected.publicationRecord(contract.SupportRecord(row))
				if err != nil || publication.digest != fact {
					t.Fatal("receipt fixture publication row differs from authenticated selection", row.Kind, err)
				}
			case contract.GeneratedCreateEvidenceSupportKind, contract.GeneratorVectorSupportKind,
				contract.GeneratedParentSupportKind, contract.PendingInboxReleaseSupportKind:
			default:
				t.Fatal("unexpected selected receipt fixture row kind", row.Kind)
			}
		}
		if pageReceipts != 0 {
			if receiptRef != (format.Ref{}) {
				t.Fatal("receipt rows cross fixture pages")
			}
			receiptRef = ref
			if pageReceipts == len(view.Records) && ref.Length != uint32(75+receiptCount*508) {
				t.Fatal("exact pure receipt page bound", ref.Length)
			}
		}
		if len(view.Records) == 1 && indexRows[view.Records[0].RecordID] && ref.Length != uint32(75+37+86+26+receiptCount*72) {
			t.Fatal("exact pure receipt index page bound", ref.Length)
		}
	}
	if receipts != receiptCount || indexes != 1 || len(indexRows) != 1 || fragments != len(selected.root.Generated.Fragments) ||
		configurationRows != int(selected.root.OutputConfiguration.SliceCount) || total != int(selected.root.RequiredSupportRecordCount) || !selected.selectedOutputComplete() {
		t.Fatal("selected receipt/configuration dimensions", receipts, indexes, fragments, configurationRows, total)
	}
	return receiptRef
}

func successionMemoryRegistryFixture(t *testing.T, full bool) (fixtureEnvironment, *scenarioRun, *environmentFixture, *custody.Fixture, []contract.ID) {
	t.Helper()
	ctx := t.Context()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	if err := env.Store.(*memoryStore).useFileBodies(filepath.Join(t.TempDir(), "bodies")); err != nil {
		t.Fatal("maximum fixture body storage", err)
	}
	enrolled := []contract.ID{fixtureID(env.Domain, "recipient")}
	registryCount := 4
	if full {
		registryCount = 256
	}
	for i := 1; i < registryCount; i++ {
		enrolled = append(enrolled, fixtureID(env.Domain, fmt.Sprintf("memory-reader-%d", i)))
	}
	keys := custody.New(t, contract.GCP, fixtureID(env.Domain, "memory-custody"), true, enrolled)
	if full {
		keys.UseMaximumSelectors(t)
	}
	env.Bindings, env.Crypto, env.Custody = keys.Bindings(), keys.Crypto(), keys
	env.AdmitInit, env.RetireInit = keys.AdmitInit, keys.RetireInit
	run := newScenarioRun(t, ctx, env)
	admitted := fixtureAdmission(run.env)
	d, ok := admitted.admission.domainBasis()
	if !ok {
		t.Fatal("maximum registry descriptor")
	}
	for i := range d.Recipients {
		d.Recipients[i].DisplayName = strings.Repeat("r", 256)
	}
	var err error
	admitted.admission.descriptor, err = contract.EncodeGenesisDescriptorCore(d)
	if err != nil {
		t.Fatal(err)
	}
	init, _ := fixtureInitAdmission(t, run.env, admitted)
	session, result := Initialize(ctx, init, run.env.Store, run.env.Trust.(contract.QualifyingTrust), run.env.Recovery, run.env.Crypto)
	if session == nil || result.Outcome != ObservedCurrent {
		t.Fatal("maximum registry init", result)
	}
	keys.RetireInit()
	admitted = capacityFixtureAdmission(t, admitted)
	session.admission = *admitted.admission
	f := &environmentFixture{admission: admitted, session: session}
	return env, run, f, keys, enrolled
}

func maximumSuccessionMemoryFixture(t *testing.T) (fixtureEnvironment, *environmentFixture, *custody.Fixture) {
	return maximumSuccessionMemoryFixtureReceiptMode(t, false)
}

func maximumSuccessionMemoryFixtureReceiptMode(t *testing.T, bothWindows bool) (fixtureEnvironment, *environmentFixture, *custody.Fixture) {
	t.Helper()
	env, run, f, keys, enrolled := successionMemoryRegistryFixture(t, true)
	input := make([]ApplyEntryInput, 512)
	for i, name := range maximumLifecycleNames("succession-memory") {
		recipients := []contract.ID{enrolled[0]}
		readerCount := 8
		if i == 0 {
			readerCount = 64
		} else if i <= 8 {
			readerCount = 1
		}
		for j := 0; j < readerCount-1; j++ {
			recipients = append(recipients, enrolled[1+(i*7+j)%255])
		}
		slices.SortFunc(recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		seal := fmt.Sprintf("memory-source-%d", i)
		core := contract.SealedInputCore{SealedInputCoreFields: contract.SealedInputCoreFields{Schema: contract.SealedInputSchema, Profile: 2, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), DomainID: env.Domain, FileIdentity: fixtureID(env.Domain, "source-file"), SourceID: fixtureID(env.Domain, seal), DataKeyID: fixtureID(env.Domain, seal+" key"), DataKeyEpoch: 1, InputEncoding: contract.InputEncodingRaw, RetainedLength: 0}, Name: name}
		choice := uint8(custody.EmptyValue)
		if i < 128 {
			choice = custody.MaximumValue
		}
		sealed, code := keys.SealInput(context.Background(), core, recipients, choice)
		if code != contract.CryptoSuccess {
			t.Fatal("memory source sealing", code)
		}
		input[i] = ApplyEntryInput{Name: name, Recipients: recipients, ValueSource: format.Supplied, ConfidentialityClass: format.Secret,
			InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, InputBytes: sealed}
	}
	run.suppliedSelection(f, input)
	if bothWindows {
		seedBothFullReceiptWindows(t, env, f)
	} else {
		seedFullSuccessionReceiptWindow(t, env, f)
	}
	root := f.session.root
	receiptCount := contract.MutationReceiptWindowLimit
	if bothWindows {
		receiptCount *= 2
	}
	// This supplied-only ordinary transition packs access records by bytes.
	// 512 records and 4096 ordinary + 512 recovery wraps require two pages;
	// the separate configured/generated fixture deliberately selects 32 pages.
	const accessBytes = 2*75 + 512*102 + (4096+512)*489
	var selectedAccessBytes uint64
	for _, ref := range root.CurrentAccess.Core.AccessPageRefs {
		selectedAccessBytes += uint64(ref.Length)
	}
	if root.ValueEntryCount != 512 || root.SecretCount != 512 || root.RawBytes != 8<<20 ||
		root.MembershipCount != 4096 || root.SecretOrdinaryWrapCount != 4096 || root.RecipientCount != 256 ||
		root.AccessRecordCount != 512 || len(root.CurrentAccess.Core.AccessPageRefs) != 2 || selectedAccessBytes != accessBytes ||
		len(root.RequiredSupport) != 3 || root.RequiredSupportRecordCount != uint32(receiptCount+2) ||
		root.OutputConfiguration.SliceCount != 1 || root.Generated.GeneratedCurrent != 0 {
		t.Fatal("joint memory fixture does not reach its specified dimensions", root.ValueEntryCount, root.SecretCount,
			root.RawBytes, root.MembershipCount, root.SecretOrdinaryWrapCount, root.RecipientCount,
			root.AccessRecordCount, len(root.CurrentAccess.Core.AccessPageRefs), selectedAccessBytes,
			len(root.RequiredSupport), root.RequiredSupportRecordCount, root.OutputConfiguration.SliceCount, root.Generated.GeneratedCurrent)
	}
	successionReceiptSupportRef(t, f.session, receiptCount)
	sizes := map[uint32]int{}
	names := 0
	for _, entry := range root.Names {
		names += len(entry.Name)
		value := f.session.valueEntry(entry.Slot)
		if value.ValueSource != contract.Supplied || value.ConfidentialityClass != contract.Secret {
			t.Fatal("joint supplied-only fixture contains another value source or class", entry.Name)
		}
		payload, err := contract.InspectCanonicalPayload(value.ValueBytes)
		if err != nil {
			t.Fatal(err)
		}
		sizes[payload.ContentLength]++
	}
	if names != 512*256 || sizes[65536] != 128 || sizes[0] != 384 {
		t.Fatal("joint raw/name dimensions differ", names, sizes)
	}
	return env, f, keys
}

// Both dimensions use real sealed inputs, two independent generated sources,
// signed receipt history and the same configuration construction.
func configuredSuccessionMemoryFixture(t *testing.T, full bool) (fixtureEnvironment, *environmentFixture, *custody.Fixture) {
	t.Helper()
	env, run, f, keys, enrolled := successionMemoryRegistryFixture(t, full)
	return configuredSuccessionMemoryFixtureFrom(t, full, env, run, f, keys, enrolled,
		func(t *testing.T, env fixtureEnvironment, f *environmentFixture) {
			seedBothFullReceiptWindows(t, env, f)
		})
}

// The actual-history GC caller supplies its already selected receipt prefix.
// Both callers use this same current-value and configuration construction.
func configuredSuccessionMemoryFixtureFrom(t *testing.T, full bool, env fixtureEnvironment, run *scenarioRun,
	f *environmentFixture, keys *custody.Fixture, enrolled []contract.ID,
	selectReceiptHistory func(*testing.T, fixtureEnvironment, *environmentFixture)) (fixtureEnvironment, *environmentFixture, *custody.Fixture) {
	t.Helper()
	baselineCount, perOrigin, memberCount := 4, 1, 2
	outputEncoding := uint8(contract.OutputEncodingRaw)
	if full {
		baselineCount, perOrigin, memberCount = 384, 64, 16
		outputEncoding = contract.OutputEncodingBase64
	}
	// Source histories reserve baseline slots with Plain values. The real
	// supplied secrets enter only the final image, so unrelated private wraps
	// do not get rebuilt by each generated Record and Final.
	sourceEnvironments := [2]fixtureEnvironment{env, env}
	for i := range sourceEnvironments {
		sourceEnvironments[i].Store = selectedMemoryStoreCopy(env.Store.(*memoryStore))
		sourceEnvironments[i].Custody = keys.ForkGenerated(t)
		sourceEnvironments[i].Crypto = sourceEnvironments[i].Custody.Crypto()
	}
	names := maximumLifecycleNames("configured-succession-memory")
	input := make([]ApplyEntryInput, baselineCount)
	for i := range input {
		count := 2
		if full {
			count = 5
			if i == 0 {
				count = 64
			} else if i <= 8 {
				count = 1
			} else if i <= 109 {
				count = 6
			}
		}
		recipients := []contract.ID{enrolled[0]}
		for j := 0; j < count-1; j++ {
			recipients = append(recipients, enrolled[1+(i*7+j)%(len(enrolled)-1)])
		}
		slices.SortFunc(recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		seal := fmt.Sprintf("configured-memory-source-%d", i)
		core := contract.SealedInputCore{SealedInputCoreFields: contract.SealedInputCoreFields{Schema: contract.SealedInputSchema, Profile: 2, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), DomainID: env.Domain, FileIdentity: fixtureID(env.Domain, "source-file"), SourceID: fixtureID(env.Domain, seal), DataKeyID: fixtureID(env.Domain, seal+" key"), DataKeyEpoch: 1, InputEncoding: contract.InputEncodingRaw, RetainedLength: 0}, Name: names[i]}
		sealed, code := keys.SealInput(t.Context(), core, recipients, custody.EmptyValue)
		if code != contract.CryptoSuccess {
			t.Fatal("configured source sealing", code)
		}
		input[i] = ApplyEntryInput{Name: names[i], Recipients: recipients, ValueSource: format.Supplied, ConfidentialityClass: format.Secret,
			InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, InputBytes: sealed}
	}
	run.suppliedSelection(f, input)
	selectReceiptHistory(t, env, f)
	lifecycle := f.session
	var selectedSources [2]*StateSession
	for i, sourceEnv := range sourceEnvironments {
		sourceRun := newScenarioRun(t, t.Context(), sourceEnv)
		source, result := Open(t.Context(), f.admission, sourceRun.env.Store)
		if source == nil || result.Outcome != ObservedCurrent {
			t.Fatal("configured source genesis open", i, result)
		}
		placeholders := make([]ApplyEntryInput, baselineCount+i*perOrigin)
		for slot := range placeholders {
			placeholders[slot] = ApplyEntryInput{Name: names[slot], Recipients: []contract.ID{lifecycle.admission.recipient},
				ValueSource: format.Supplied, ConfidentialityClass: format.Plain,
				InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, InputBytes: []byte{byte(slot)}}
		}
		sourceFixture := &environmentFixture{session: source, admission: OpenContext{admission: &source.admission}}
		sourceRun.suppliedSelection(sourceFixture, placeholders)
		source = sourceFixture.session
		declarations, _ := generatedCurrentDeclaration(t, source)
		label := fmt.Sprintf("configured source %c", 'A'+i)
		first := baselineCount + i*perOrigin
		selectedSources[i] = signedFullIntentSource(t, t.Context(), sourceEnv, source, fixtureID(env.Domain, label+" operation"),
			names[first:first+perOrigin], declarations, capacityRecipients(t, source, memberCount), custody.MaximumValue, outputEncoding, label, nil)
	}
	store, combined := signedCurrentIntentFixture(t, env, lifecycle, "configured combined origins", selectedSources[:]...)
	env.Store = store
	store, opened := signedCapacityConfiguration(t, env, lifecycle, combined, "configured succession capacity", full)
	env.Store = store
	env.Put = func(_ context.Context, key string, body []byte) error {
		store.mu.Lock()
		defer store.mu.Unlock()
		return store.putSelected(key, body)
	}
	env.Delete = func(_ context.Context, key string) error {
		store.mu.Lock()
		defer store.mu.Unlock()
		delete(store.objects, key)
		return nil
	}
	f.session, f.admission = opened, OpenContext{admission: &opened.admission}
	assertConfiguredSuccessionMemoryFixture(t, opened, keys, full)
	return env, f, keys
}

func assertConfiguredSuccessionMemoryFixture(t *testing.T, opened *StateSession, keys *custody.Fixture, full bool) {
	t.Helper()
	wantEntries, wantMembers, wantRaw, wantRegistry, wantAccess := 6, uint32(12), uint64(128<<10), uint16(4), 1
	if full {
		wantEntries, wantMembers, wantRaw, wantRegistry, wantAccess = 512, 4096, 8<<20, 256, 32
	}
	perOrigin := 1
	if full {
		perOrigin = 64
	}
	root := opened.root
	if int(root.ValueEntryCount) != wantEntries || int(root.SecretCount) != wantEntries || root.RawBytes != wantRaw || root.MembershipCount != wantMembers || root.SecretOrdinaryWrapCount != wantMembers || root.RecipientCount != wantRegistry || len(root.CurrentAccess.Core.AccessPageRefs) != wantAccess || int(root.Generated.GeneratedCurrent) != 2*perOrigin || root.Generated.SuccessWindow.Count != 256 || root.Generated.FailureWindow.Count != 256 {
		t.Fatal("configured joint dimensions", root.ValueEntryCount, root.RawBytes, root.MembershipCount, root.SecretOrdinaryWrapCount, root.RecipientCount, len(root.CurrentAccess.Core.AccessPageRefs))
	}
	successionReceiptSupportRef(t, opened, 512)
	capacityConfigurationSupportRefs(t, opened)
	assertCapacityCurrentIntents(t, opened, 2*perOrigin)
	if full {
		for _, page := range opened.recipients {
			if page == nil {
				continue
			}
			for _, recipient := range page.Slots {
				if recipient != nil && (len(recipient.DisplayName) != 256 || recipient.CurrentBinding == nil || len(recipient.CurrentBinding.KeySelector) != contract.MaxKeySelector) {
					t.Fatal("configured maximum registry row")
				}
			}
		}
	}
	t.Logf("configured selected preflight: full=%t entries=%d generated=%d raw=%d memberships=%d wraps=%d registry=%d access-pages=%d children=%d child-bytes=%d support-pages=%d index-shards=%d receipt-rows=512", full, root.ValueEntryCount, root.Generated.GeneratedCurrent, root.RawBytes, root.MembershipCount, root.SecretOrdinaryWrapCount, root.RecipientCount, len(root.CurrentAccess.Core.AccessPageRefs), root.ChildCount, root.ChildEncodedBytes, len(root.RequiredSupport), 1+len(root.AdministrativeIndexShards))
	for _, named := range root.Names {
		entry := opened.valueEntry(named.Slot)
		choice := uint8(custody.EmptyValue)
		if entry.ValueSource == contract.Generated {
			choice = custody.MaximumValue
		}
		selection := sessionConsumerSelection(t, opened, opened.admission.recipient, named.Name)
		if result := keys.Consume(t.Context(), selection, choice); result.Code != contract.CryptoSuccess || !result.ValueMatched {
			t.Fatal("configured private consume", result)
		}
		if len(named.Name) != 256 {
			t.Fatal("configured exact name width")
		}
	}
}

// Only immutable Store bodies and independently admitted public inputs survive
// setup. Every case opens its own Core session and constructs private owners.
type configuredSuccessionMemorySeed struct {
	store               *memoryStore
	domain              contract.ID
	admission           OpenContext
	control             contract.ControlCore
	bindings            []byte
	head                []byte
	token               contract.Token
	root                []byte
	full                bool
	replacement         bool
	capturedRecipients  int
	observedSupportRows int
}

func newConfiguredSuccessionMemorySeed(t *testing.T, full bool) configuredSuccessionMemorySeed {
	t.Helper()
	timing := startCapacityTimer(t)
	defer timing.finish()
	env, f, keys := configuredSuccessionMemoryFixture(t, full)
	return freezeConfiguredSuccessionMemorySeed(t, full, env, f, keys)
}

func freezeConfiguredSuccessionMemorySeed(t *testing.T, full bool, env fixtureEnvironment, f *environmentFixture, keys *custody.Fixture) configuredSuccessionMemorySeed {
	t.Helper()
	controlBody, err := contract.EncodeControlCore(currentControlOf(f.session))
	if err != nil {
		t.Fatal(err)
	}
	control, err := contract.DecodeControlCore(controlBody)
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := contract.EncodeBindingTable(keys.Bindings())
	if err != nil {
		t.Fatal(err)
	}
	root, err := format.EncodeRoot(f.session.root)
	if err != nil {
		t.Fatal(err)
	}
	admission := *f.admission.admission
	admission.publicKey = bytes.Clone(admission.publicKey)
	admission.descriptor = bytes.Clone(admission.descriptor)
	admission.current = admission.current.clone()
	return configuredSuccessionMemorySeed{store: env.Store.(*memoryStore), domain: env.Domain,
		admission: OpenContext{admission: &admission}, control: control, bindings: bindings,
		head: bytes.Clone(f.session.body), token: f.session.token, root: root, full: full}
}

// The installed replacement admission has no output interpreter. Give memory
// cases that same independent admission before their first selected read.
func privateReplacementMemorySeed(seed configuredSuccessionMemorySeed) configuredSuccessionMemorySeed {
	admission := *seed.admission.admission
	admission.outputInterpreter = nil
	seed.admission, seed.replacement = OpenContext{admission: &admission}, true
	return seed
}

func (seed configuredSuccessionMemorySeed) openCase(t *testing.T) (fixtureEnvironment, *environmentFixture, *custody.Fixture) {
	t.Helper()
	store := selectedMemoryStoreCopy(seed.store)
	enrolled := []contract.ID{fixtureID(seed.domain, "recipient")}
	registryCount := 4
	if seed.full {
		registryCount = 256
	}
	for i := 1; i < registryCount; i++ {
		enrolled = append(enrolled, fixtureID(seed.domain, fmt.Sprintf("memory-reader-%d", i)))
	}
	keys := custody.New(t, contract.GCP, fixtureID(seed.domain, "memory-custody"), true, enrolled)
	if seed.full {
		keys.UseMaximumSelectors(t)
	}
	bindings, err := contract.EncodeBindingTable(keys.Bindings())
	if err != nil || !bytes.Equal(bindings, seed.bindings) {
		t.Fatal("case private owner changed frozen bindings", err)
	}
	normal := testtrust.NewCurrent(t, seed.control.NormalSigning)
	recovery := testtrust.NewCurrent(t, seed.control.Recovery.Signing)
	env := fixtureEnvironment{Domain: seed.domain, Store: store, Custody: keys, Crypto: keys.Crypto(),
		Bindings: keys.Bindings(), AdmitInit: keys.AdmitInit, RetireInit: keys.RetireInit,
		Trust: &fixtureTrust{Signer: normal}, Recovery: recovery,
		PublicKey: normal.PublicKey(), SigningSelector: normal.KeySelector(),
		RecoveryPublicKey: recovery.PublicKey(), RecoverySelector: recovery.KeySelector(),
		Put: func(_ context.Context, key string, body []byte) error {
			store.mu.Lock()
			defer store.mu.Unlock()
			return store.putSelected(key, body)
		},
		Delete: func(_ context.Context, key string) error {
			store.mu.Lock()
			defer store.mu.Unlock()
			delete(store.objects, key)
			return nil
		}}
	var opened *StateSession
	var result Result
	if seed.replacement {
		if seed.admission.admission.outputInterpreter != nil {
			t.Fatal("replacement admission retained a fixture output interpreter")
		}
		opened, result = openReplacementSession(t.Context(), seed.admission, store, false)
	} else {
		opened, result = Open(t.Context(), seed.admission, store)
	}
	if opened == nil || result.Outcome != ObservedCurrent || store.reads == 0 ||
		!bytes.Equal(opened.body, seed.head) || opened.token != seed.token {
		t.Fatal("case did not cold-open exact frozen HEAD", result)
	}
	root, err := format.EncodeRoot(opened.root)
	if err != nil || !bytes.Equal(root, seed.root) {
		t.Fatal("case changed frozen root", err)
	}
	assertConfiguredSuccessionMemoryFixture(t, opened, keys, seed.full)
	return env, &environmentFixture{session: opened, admission: OpenContext{admission: &opened.admission}}, keys
}

// full_only: false
func TestSuccessionConfiguredFixtureColdOpen(t *testing.T) {
	env, f, _ := configuredSuccessionMemoryFixture(t, false)
	admin, result := openAdministrative(t.Context(), f.admission, env.Store)
	if admin == nil || result.Outcome != ObservedCurrent || !admin.selectedOutputComplete() || len(admin.adminIndex.PublicationOrder) != 4 {
		t.Fatal("small combined administrative open", result)
	}
	kept, err := admin.administrativeWorkWithoutOldReceipts(admin.adminIndex)
	if err != nil || len(kept.PublicationOrder) != 4 {
		t.Fatal("small combined receipt filtering", err)
	}
	t.Run("publication-markers", func(t *testing.T) {
		rows, order, _ := publicationJointConfiguredMarkers(t, f.session, false)
		_, selected := publicationJointSelectedImage(t, env, f.session, f.session, rows, order, 0, 0, "small receipt publication markers")
		if ref := successionReceiptSupportRef(t, selected, 512); ref.Object.IsZero() {
			t.Fatal("publication peers hid the selected receipt page")
		}
		publication, err := selectedPublicationRelation(selected.selectedImage())
		if err != nil || len(publication.coordinates) != 4 || len(publication.markers) != 8 {
			t.Fatal("small selected publication population changed", err)
		}
		peers, err := publicationSelectedRowProofs(selected.selectedImage())
		if err != nil || len(peers) != len(rows) {
			t.Fatal("receipt lookup changed the complete selected publication row set", err)
		}
		for _, expected := range rows {
			actual, found := peers[generatedRecordKey{expected.Kind, expected.RecordID}]
			if !found || actual.bodyDigest != contract.Hash(expected.Body) || actual.length != uint32(len(expected.Body)) {
				t.Fatal("receipt lookup changed exact authenticated publication peer", expected.Kind, found)
			}
		}
	})
}

// full_only: false
func TestSuccessionConfiguredFixtureOwnerIsolation(t *testing.T) {
	seed := newConfiguredSuccessionMemorySeed(t, false)
	originalStore := selectedMemoryStoreCopy(seed.store)
	originalAdmission := *seed.admission.admission
	originalAdmission.publicKey = bytes.Clone(originalAdmission.publicKey)
	originalAdmission.descriptor = bytes.Clone(originalAdmission.descriptor)
	originalAdmission.current = originalAdmission.current.clone()
	envB, fB, keysB := seed.openCase(t)
	var closedKeys *custody.Fixture
	t.Run("faulted-owner", func(t *testing.T) {
		envA, fA, keysA := seed.openCase(t)
		closedKeys = keysA
		storeA, storeB := envA.Store.(*memoryStore), envB.Store.(*memoryStore)
		if storeA == storeB || storeA == seed.store || fA.session == fB.session || keysA == keysB ||
			envA.Crypto.InstanceID() == envB.Crypto.InstanceID() || envA.Trust == envB.Trust || envA.Recovery == envB.Recovery ||
			!reflect.DeepEqual(storeA.objects, originalStore.objects) || !reflect.DeepEqual(storeB.objects, originalStore.objects) {
			t.Fatal("case owners or initial frozen objects differ")
		}
		cacheRef := format.Ref{Kind: contract.RootKind, Object: fixtureID(seed.domain, "isolation cache")}
		fA.session.cache[cacheRef] = []byte{1}
		if _, shared := fB.session.cache[cacheRef]; shared {
			t.Fatal("case caches share mutation")
		}
		delete(fA.session.cache, cacheRef)
		_, privateB := keysB.Calls()
		_, privateA := keysA.Calls()
		name := fA.session.root.Names[0].Name
		selectionA := sessionConsumerSelection(t, fA.session, fA.session.admission.recipient, name)
		keysA.SetDenied(seed.control.AuthorityRecipientID, true)
		denied := keysA.Consume(t.Context(), selectionA, custody.EmptyValue)
		uses := uint32(0)
		for _, use := range denied.KeyUses {
			if use.Outcome == contract.KeyUseDenied && use.SubjectID == seed.control.AuthorityRecipientID {
				uses += use.Count
			}
		}
		_, afterA := keysA.Calls()
		_, afterB := keysB.Calls()
		if denied.Code != contract.CryptoPrivateRouteUnavailable || denied.SinkCalls != 0 || uses == 0 ||
			afterA != privateA+1 || afterB != privateB {
			t.Fatal("authority denial did not stay in its real private owner", denied, privateA, afterA, privateB, afterB)
		}
		keysA.SetDenied(seed.control.AuthorityRecipientID, false)
		if result := keysA.Consume(t.Context(), selectionA, custody.EmptyValue); result.Code != contract.CryptoSuccess || !result.ValueMatched {
			t.Fatal("authority denial reset", result)
		}
		assertConfiguredSuccessionMemoryFixture(t, fB.session, keysB, false)
		_, _, keysC := seed.openCase(t)
		recovery := seed.control.Recovery.KMS
		keysA.LoseRecipientPredecessor(seed.control.Recovery.RoleID)
		witnessA := keysA.PrivateWitness(t.Context(), recovery.BindingID, recovery, recovery)
		if witnessA.Outcome != contract.CryptoPrivateRouteUnavailable || witnessA.Denied != 1 || witnessA.Completed != 0 {
			t.Fatal("lost predecessor did not reach its real private owner", witnessA)
		}
		successor := keysA.KEKSuccessor(t, contract.SuccessorRecoveryKEK)
		witnessA = keysA.PrivateWitness(t.Context(), successor.BindingID, successor, successor)
		if witnessA.Outcome != contract.CryptoSuccess || witnessA.Completed != 1 || witnessA.Denied != 0 {
			t.Fatal("successor did not use its real private owner", witnessA)
		}
		for _, keys := range []*custody.Fixture{keysB, keysC} {
			bindings, err := contract.EncodeBindingTable(keys.Bindings())
			witness := keys.PrivateWitness(t.Context(), recovery.BindingID, recovery, recovery)
			if err != nil || !bytes.Equal(bindings, seed.bindings) || witness.Outcome != contract.CryptoSuccess || witness.Completed != 1 || witness.Denied != 0 {
				t.Fatal("loss or successor changed another owner", err, witness)
			}
		}
		supportKey := mustKey(t, storeA.desc.Prefix, successionReceiptSupportRef(t, fA.session, 512))
		support := storeA.Read(t.Context(), supportKey, ^uint32(0))
		if support.Status != contract.ReadOK {
			t.Fatal("isolation support read", support)
		}
		if err := envA.Delete(t.Context(), supportKey); err != nil {
			t.Fatal(err)
		}
		if current, result := Open(t.Context(), seed.admission, storeA); current != nil || result.Outcome != EvidenceUnavailable || result.Reason != MissingSelectedObject {
			t.Fatal("isolated missing support", result)
		}
		support.Body[len(support.Body)-1] ^= 1
		if err := envA.Put(t.Context(), supportKey, support.Body); err != nil {
			t.Fatal(err)
		}
		if current, result := Open(t.Context(), seed.admission, storeA); current != nil || result.Outcome != IntegrityFailure || result.Reason != InvalidReference {
			t.Fatal("isolated damaged support", result)
		}
		if err := envA.Put(t.Context(), storeA.desc.HeadKey, []byte{0}); err != nil {
			t.Fatal(err)
		}
		if current, result := Open(t.Context(), seed.admission, storeA); current != nil || result.Outcome != IntegrityFailure {
			t.Fatal("isolated damaged HEAD", result)
		}
		keysA.CloseRoutes()
		if result := keysA.Consume(t.Context(), selectionA, custody.EmptyValue); result.Code != contract.CryptoInvalidAdmission {
			t.Fatal("closed private owner remained usable", result)
		}
	})
	currentAdmission, originalFacts := *seed.admission.admission, originalAdmission
	currentAdmission.outputInterpreter, originalFacts.outputInterpreter = nil, nil
	if closedKeys == nil || len(closedKeys.Bindings()) != 0 || !reflect.DeepEqual(seed.store.objects, originalStore.objects) ||
		!reflect.DeepEqual(currentAdmission, originalFacts) {
		t.Fatal("child cleanup or faults changed frozen setup")
	}
	interpret := seed.admission.admission.outputInterpreter
	if interpret == nil {
		t.Fatal("frozen output interpreter is absent")
	}
	configuration := capacityOutputConfiguration(t, fB.session, false)
	names := make(map[contract.ID]string)
	for _, named := range fB.session.root.Names {
		names[fB.session.valueEntry(named.Slot).Incarnation] = named.Name
	}
	interpreted := 0
	for _, binding := range configuration.Bindings {
		for _, target := range binding.Targets {
			name, exists := names[target.EntryIncarnationID]
			if !exists {
				t.Fatal("authored output target lacks its selected name")
			}
			for _, encoding := range []uint8{contract.OutputEncodingRaw, contract.OutputEncodingBase64} {
				want := target
				want.EntryIncarnationID, want.PayloadEncoding = contract.ID{}, encoding
				got, err := interpret(t.Context(), binding.DestinationID, binding.Destination, name, encoding)
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Fatal("child cleanup changed frozen output interpretation", binding.DestinationID, name, encoding, got, want, err)
				}
			}
			interpreted++
		}
	}
	if interpreted != 4 {
		t.Fatal("small fixture output target count", interpreted)
	}
	binding := configuration.Bindings[0]
	if _, err := interpret(t.Context(), binding.DestinationID, binding.Destination, "unknown fixture entry", contract.OutputEncodingRaw); err == nil {
		t.Fatal("frozen output interpreter accepted an unknown entry")
	}
	changedDestination := binding.Destination
	changedDestination.ConfigContractID += "/changed"
	name := names[binding.Targets[0].EntryIncarnationID]
	if _, err := interpret(t.Context(), binding.DestinationID, changedDestination, name, contract.OutputEncodingRaw); err == nil {
		t.Fatal("frozen output interpreter accepted a changed destination")
	}
	for _, store := range []*memoryStore{seed.store, envB.Store.(*memoryStore)} {
		current, result := Open(t.Context(), seed.admission, store)
		if current == nil || result.Outcome != ObservedCurrent || !bytes.Equal(current.body, seed.head) || current.token != seed.token ||
			!reflect.DeepEqual(store.objects, originalStore.objects) {
			t.Fatal("unaffected Store did not cold-open exact frozen bytes", result)
		}
	}
	envC, fC, keysC := seed.openCase(t)
	for _, owner := range []struct {
		env  fixtureEnvironment
		f    *environmentFixture
		keys *custody.Fixture
	}{{envB, fB, keysB}, {envC, fC, keysC}} {
		assertConfiguredSuccessionMemoryFixture(t, owner.f.session, owner.keys, false)
		encoded, err := contract.EncodeControlCore(currentControlOf(owner.f.session))
		if err != nil {
			t.Fatal(err)
		}
		after, err := contract.DecodeControlCore(encoded)
		if err != nil {
			t.Fatal(err)
		}
		signer, binding := owner.env.Recovery.(*testtrust.Signer).Successor(t, after.Recovery.Signing)
		after.Recovery.Signing = binding
		after.Recovery.KMS = owner.keys.KEKSuccessor(t, contract.SuccessorRecoveryKEK)
		after.AccessGeneration++
		owner.keys.LoseRecipientPredecessor(after.Recovery.RoleID)
		source := contract.BindingTableRow{SubjectKind: 1, SubjectID: after.AuthorityRecipientID, Binding: after.AuthorityKMSBinding}
		permit := admitAuthorityReplacement(t, owner.f.session, owner.keys, after, 3, 1, 12, source)
		candidate, result := owner.f.session.PrepareSuccession(t.Context(), permit, SuccessionSigners{Authorizer: owner.env.Trust, RecoverySuccessor: signer})
		owner.keys.RetireAccess()
		if candidate == nil || result.Outcome != ObservedCurrent {
			t.Fatal("child cleanup damaged another owner's succession", result)
		}
	}
}

// full_only: false
func TestSuccessionConfiguredMemory(t *testing.T) {
	env, fixture, keys := configuredSuccessionMemoryFixture(t, false)
	store, current, _ := signedCurrentRequiredSupport(t, env, fixture.session, 2)
	env.Store = store
	fixture.session, fixture.admission = current, OpenContext{admission: &current.admission}
	seed := privateReplacementMemorySeed(freezeConfiguredSuccessionMemorySeed(t, false, env, fixture, keys))
	for _, fault := range []string{"success", "different-current", "missing-observed-support", "invalid-observed-support"} {
		t.Run(fault, func(t *testing.T) { runSuccessionJointMaximumMemory(t, fault, seed) })
	}
	t.Run("native-captured-recipients", func(t *testing.T) {
		native := seed
		native.capturedRecipients = 1 << 16
		runSuccessionJointMaximumMemory(t, "success", native)
	})
	for _, damage := range []bool{false, true} {
		t.Run(fmt.Sprintf("installed-delivery/invalid-final-row=%t", damage), func(t *testing.T) {
			runInstalledCapturedRecipientMemory(t, damage)
		})
	}
	for _, fault := range []string{"different-current", "missing-observed-support", "invalid-observed-support"} {
		t.Run("larger-observation/"+fault, func(t *testing.T) {
			larger := seed
			larger.observedSupportRows = 8192
			runSuccessionJointMaximumMemory(t, fault, larger)
		})
	}
}

func runInstalledCapturedRecipientMemory(t *testing.T, invalidFinalRow bool) {
	t.Helper()
	h := newInstalledReplacementFixture(t, contract.GCP, ReplacementTargetAuthority, contract.SuccessionChangeNormalSigner, contract.NormalSigningRole, 0)
	pattern := slices.Clone(h.installation.CapturedRecipients)
	const count = 1 << 16
	rows := make([]ReplacementRecipientFact, count)
	for i := range rows {
		rows[i] = pattern[i%len(pattern)]
	}
	h.installation.CapturedRecipients = rows
	store := h.env.Store.(*memoryStore)
	creates, cas := store.creates, store.cas
	var delivered ReplacementSuccessor
	var memory *memoryAccounting
	h.installation.PublishSuccessor = func(_ context.Context, output ReplacementSuccessor) (ReplacementReadback, error) {
		delivered = output
		if len(output.Recipients) != count {
			t.Fatal("installed delivery changed captured row count", len(output.Recipients))
		}
		for i, row := range output.Recipients {
			if !reflect.DeepEqual(row, pattern[i%len(pattern)]) {
				t.Fatal("installed delivery changed captured order, multiplicity or binding", i)
			}
		}
		readback, err := ownReplacementRecipients(output.Recipients)
		if err != nil {
			t.Fatal("installed independent readback", err)
		}
		control, err := output.Basis.ControlCore(h.env.Domain, store.Descriptor())
		if err != nil {
			t.Fatal(err)
		}
		observed := ReplacementReadback{FileIdentity: h.installation.FileIdentity, Control: control, Basis: output.Basis,
			Recipients: readback, Correlation: output.Correlation}
		sampleInstalledReplacementMemory(memory, "installed-delivery-callback", &output, &observed)
		sample := &memory.samples[len(memory.samples)-1]
		// The callback exposes offered and independently reconstructed rows.
		// Core's expected rows and its subsequent owned readback overlap them.
		sample.ResultUnobservedReserve = 2 * count * contract.KMSPublicKeyLength
		if invalidFinalRow {
			readback[len(readback)-1].Encryption.SPKI[0] ^= 1
		}
		return observed, nil
	}
	owner, err := NewInstalledAuthorityReplacement(AuthorityReplacementInstallation{ReplacementInstallation: h.installation, Goal: h.goal})
	if err != nil {
		t.Fatal("installed maximum captured source", err)
	}
	defer owner.Close()
	// The constructor owns its independent source. The fixture needs only
	// the three-row expected pattern after that handoff.
	h.installation.CapturedRecipients = nil
	memory = startMemoryAccounting()
	memory.replacementSource = &owner.owner.installation
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	output := owner.Replace(ctx, fixtureID(h.env.Domain, "maximum installed captured recipients"))
	sampleInstalledReplacementMemory(memory, "installed-delivery-return", &delivered, nil)
	runtime.KeepAlive(delivered)
	const minimumReturnedRecipients = 2 * count * contract.KMSPublicKeyLength
	if sample := memory.samples[len(memory.samples)-1]; sample.ByteCapacity < minimumReturnedRecipients {
		t.Errorf("installed return omitted retained source or delivered recipients: owned=%d minimum=%d", sample.ByteCapacity, minimumReturnedRecipients)
	}
	if delivered.DomainID != h.env.Domain || len(memory.samples) != 2 {
		t.Fatal("installed maximum source did not reach actual delivery", output.Result)
	}
	if invalidFinalRow {
		if output.Result.Outcome != AdmissionRefused || store.cas != cas {
			t.Fatal("invalid final delivered binding changed selected HEAD", output.Result, store.cas-cas)
		}
		head := store.Read(ctx, store.desc.HeadKey, contract.MaxHeadLength)
		if head.Status != contract.ReadOK || head.Token != h.fixture.session.token || !bytes.Equal(head.Body, h.fixture.session.body) {
			t.Fatal("invalid final readback changed exact selected HEAD", head.Status, head.Token)
		}
		selected, result := Open(ctx, h.fixture.admission, store)
		if selected == nil || result.Outcome != ObservedCurrent || !reflect.DeepEqual(selected.root, h.fixture.session.root) {
			t.Fatal("invalid final readback changed cold-open selected state", result)
		}
		for _, named := range selected.root.Names {
			if !reflect.DeepEqual(selected.valueEntry(named.Slot), h.fixture.session.valueEntry(named.Slot)) {
				t.Fatal("invalid final readback changed stored current value", named.Name)
			}
		}
		t.Logf("invalid final readback preserved selected HEAD: candidate-creates=%d cas=%d", store.creates-creates, store.cas-cas)
	} else {
		if output.Result.Outcome != ObservedCurrent || output.Result.Evidence != AuthenticatedClosure || store.cas != cas+1 {
			t.Fatal("installed maximum captured source selection", output.Result, store.cas-cas)
		}
		admission, result := admitPublicNormal(ctx, h.env.Domain, store.Descriptor(), delivered.Basis, store, h.installation.CompositionID, nil)
		if result.Outcome != ObservedCurrent {
			t.Fatal("installed maximum delivered admission", result)
		}
		selected, result := Open(ctx, admission, store)
		if selected == nil || result.Outcome != ObservedCurrent || !slices.Equal(selected.root.Names, h.fixture.session.root.Names) {
			t.Fatal("installed maximum delivered cold selection", result)
		}
		for _, named := range selected.root.Names {
			if !reflect.DeepEqual(selected.valueEntry(named.Slot), h.fixture.session.valueEntry(named.Slot)) {
				t.Fatal("installed maximum source changed stored current value", named.Name)
			}
		}
	}
	recipientFixedUpper := replacementRecipientFixedMemoryUpper(count)
	t.Logf("recipient/basis/fixed-owner allowance=%d replacement-adapter-design-reserve=%d native-layout-qualification=pending", recipientFixedUpper, replacementNativeAdapterDesignUpper())
	for _, sample := range memory.samples {
		envelope := sample.ByteCapacity + sample.ResultUnobservedReserve
		t.Logf("%s: captured-rows=%d visible-owned=%d hidden-recipient-reserve=%d recipient-byte-envelope=%d heap-upper=%d", sample.Phase, count, sample.ByteCapacity, sample.ResultUnobservedReserve, envelope, sample.GoHeapUpperBound)
		if envelope > recipientFixedUpper {
			t.Errorf("installed delivery recipient byte envelope %d exceeds recipient/basis/fixed-owner allowance %d", envelope, recipientFixedUpper)
		}
	}
}

// full_only: false
func TestPrivateReplacementOpensCurrentGeneratedRequiredSupport(t *testing.T) {
	env, fixture, _ := configuredSuccessionMemoryFixture(t, false)
	store, source, slot := signedCurrentRequiredSupport(t, env, fixture.session, 1)
	for _, private := range []bool{false, true} {
		for _, administrative := range []bool{false, true} {
			t.Run(fmt.Sprintf("private=%t/administrative=%t", private, administrative), func(t *testing.T) {
				admission := OpenContext{admission: &source.admission}
				var opened *StateSession
				var result Result
				if private {
					opened, result = openReplacementSession(t.Context(), admission, store, administrative)
				} else if administrative {
					opened, result = openAdministrative(t.Context(), admission, store)
				} else {
					opened, result = Open(t.Context(), admission, store)
				}
				if opened == nil || result.Outcome != ObservedCurrent || opened.valueEntry(slot).Generated.RequiredSupport != source.valueEntry(slot).Generated.RequiredSupport {
					t.Fatal("current generated required support lost authenticated ownership", result)
				}
			})
		}
	}
}

func signedCurrentRequiredSupport(t *testing.T, env fixtureEnvironment, original *StateSession, count int) (*memoryStore, *StateSession, uint16) {
	t.Helper()
	if count < 1 {
		t.Fatal("current support fixture needs nonempty support")
	}
	label := fmt.Sprintf("current required support %d", count)
	next := *original
	next.root.Snapshot = fixtureID(env.Domain, label+" snapshot")
	next.root.Transition = fixtureID(env.Domain, label+" transition")
	next.root.RequiredSupport = slices.Clone(original.root.RequiredSupport)
	next.support = slices.Clone(original.support)
	next.supportFacts = slices.Clone(original.supportFacts)
	next.adminIndex = clonePublicationWork(original.adminIndex)
	next.adminIndex.Object = administrativeIndexObject(env.Domain, next.root.Snapshot)
	var slot uint16
	found := false
	for _, named := range next.root.Names {
		if original.valueEntry(named.Slot).ValueSource == contract.Generated {
			slot, found = named.Slot, true
			break
		}
	}
	if !found {
		t.Fatal("current generated source missing")
	}
	pageIndex, entryIndex := int(slot)/format.PageSlots, int(slot)%format.PageSlots
	valuePage := *original.pages[pageIndex]
	entry := *valuePage.Slots[entryIndex]
	oldSupport := entry.Generated.RequiredSupport
	bodies := make([][]byte, count)
	for i := range bodies {
		var err error
		bodies[i], err = contract.EncodeGeneratorSupportBinding(contract.GeneratorSupportBinding{Schema: contract.GeneratorSupportBindingSchema, Role: 3,
			ContractID: fixtureID(env.Domain, fmt.Sprintf("current support contract %d", i)), ImplementationID: fixtureID(env.Domain, "current support implementation"), PublicBindingDigest: fixtureID(env.Domain, "current support binding")})
		if err != nil {
			t.Fatal(err)
		}
	}
	slices.SortFunc(bodies, bytes.Compare)
	var carriers []contract.SupportRecord
	var err error
	entry.Generated.RequiredSupport, carriers, err = generatedCarrierRows(env.Domain, contract.GeneratedParentSupportKind, entry.Generated.OriginOperationID, contract.GeneratorVectorSupport, bodies)
	if err != nil || len(carriers) != count {
		t.Fatal("current original-operation support carrier", err, len(carriers), count)
	}
	valuePage.Slots[entryIndex] = &entry
	next.pages[pageIndex] = &valuePage
	if oldSupport.Count != 0 {
		removed := uint32(0)
		for i := len(next.support) - 1; i >= 0; i-- {
			page := next.support[i]
			matches := 0
			for _, row := range page.Records {
				if row.Kind != contract.GeneratorVectorSupportKind {
					continue
				}
				carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					t.Fatal("current support predecessor carrier", err)
				}
				if carrier.OwnerKind == contract.GeneratedParentSupportKind && carrier.OwnerID == entry.Generated.OriginOperationID && carrier.VectorKind == contract.GeneratorVectorSupport && carrier.Vector == oldSupport {
					matches++
				}
			}
			if matches == 0 {
				continue
			}
			if matches != len(page.Records) {
				t.Fatal("current support fixture replacement needs its dedicated predecessor pages")
			}
			removed += uint32(matches)
			next.root.RequiredSupport = slices.Delete(next.root.RequiredSupport, i, i+1)
			next.support = slices.Delete(next.support, i, i+1)
			next.supportFacts = slices.Delete(next.supportFacts, i, i+1)
			next.adminIndex.Pages = slices.Delete(next.adminIndex.Pages, i, i+1)
		}
		if removed != oldSupport.Count {
			t.Fatal("current support fixture did not replace its complete prior vector", removed, oldSupport.Count)
		}
		next.root.RequiredSupportRecordCount -= removed
	}
	store := selectedMemoryStoreCopy(env.Store.(*memoryStore))
	put := func(ref format.Ref, body []byte) {
		t.Helper()
		if err := format.CheckReference(ref, body); err != nil {
			t.Fatal(err)
		}
		if err := store.putSelected(mustKey(t, store.desc.Prefix, ref), body); err != nil {
			t.Fatal(err)
		}
	}
	valuePage.Object = fixtureID(env.Domain, label+" value page")
	valueBody, err := format.EncodeValueEntryPage(valuePage)
	if err != nil {
		t.Fatal(err)
	}
	valueRef, err := format.Reference(contract.ValueEntryPageKind, env.Domain, valuePage.Object, valuePage.Index, valueBody)
	if err != nil {
		t.Fatal(err)
	}
	put(valueRef, valueBody)
	next.root.ValueEntryPages[pageIndex] = &valueRef
	core, err := contract.ValueCoreForEntry(env.Domain, next.root.CurrentAccess.Core.CompatibilityID, entry)
	if err != nil {
		t.Fatal(err)
	}
	material, err := contract.ValueMaterialContextDigest(core)
	if err != nil {
		t.Fatal(err)
	}
	next.root.CurrentAccess.Core.AccessPageRefs = slices.Clone(original.root.CurrentAccess.Core.AccessPageRefs)
	for i, source := range next.access {
		if source == nil {
			continue
		}
		position := slices.IndexFunc(source.Records, func(row contract.AccessRecord) bool {
			return row.MaterialKind == contract.ValueMaterialKind && row.MaterialID == entry.ValueState
		})
		if position < 0 {
			continue
		}
		page := *source
		page.Records = slices.Clone(source.Records)
		page.Records[position].MaterialContextDigest = material
		page.Object = fixtureID(env.Domain, label+" access page")
		next.access[i] = &page
		body, err := format.EncodeAccessPage(page)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(contract.AccessKind, env.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal(err)
		}
		put(ref, body)
		for j, old := range next.root.CurrentAccess.Core.AccessPageRefs {
			if old.Index == page.Index {
				next.root.CurrentAccess.Core.AccessPageRefs[j] = ref
			}
		}
	}
	next.root.CurrentAccess.Core.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(env.Domain, next.accessRecords())
	if err != nil {
		t.Fatal(err)
	}
	next.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(next.root.CurrentAccess.Core)
	if err != nil {
		t.Fatal(err)
	}
	// Each minimum binding has 103 inner bytes, 120 carrier bytes and 37
	// page-row bytes. Keep complete rows within the actual physical limit.
	const rowsPerPage = (contract.MaxRequiredSupportPageLength - contract.RequiredSupportPageHeaderLength) / (103 + 120 + 37)
	for first := 0; first < len(carriers); first += rowsPerPage {
		rows := carriers[first:min(first+rowsPerPage, len(carriers))]
		index := generatedFixtureFreeSupportIndex(t, &next)
		object := fixtureID(env.Domain, fmt.Sprintf("%s physical page %d", label, index))
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: env.Domain, Object: object, Index: index, Records: rows})
		if err != nil {
			t.Fatal("current support page", err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, env.Domain, object, index, body)
		if err != nil {
			t.Fatal(err)
		}
		put(ref, body)
		view, err := format.InspectRequiredSupportPage(body)
		if err != nil {
			t.Fatal(err)
		}
		facts := selectedSupportPageFacts{ref: ref}
		page := format.AdministrativePage{Ref: ref, Spans: []format.AdministrativeSpan{{Count: uint16(len(rows)), Mandatory: true}}}
		for i, row := range view.Records {
			fact, err := contract.InspectSupportRecordDigest(env.Domain, contract.SupportRecord(row))
			if err != nil {
				t.Fatal(err)
			}
			facts.rows = append(facts.rows, fact)
			facts.ordinals = append(facts.ordinals, uint16(i))
			page.Rows = append(page.Rows, format.AdministrativeRowSummary{Kind: row.Kind, RecordID: row.RecordID, BodyLength: uint32(len(row.Body))})
		}
		next.root.RequiredSupport = append(next.root.RequiredSupport, ref)
		next.support = append(next.support, view)
		next.supportFacts = append(next.supportFacts, facts)
		next.adminIndex.Pages = append(next.adminIndex.Pages, page)
		for i := len(next.root.RequiredSupport) - 1; i > 0 && next.root.RequiredSupport[i].Index < next.root.RequiredSupport[i-1].Index; i-- {
			next.root.RequiredSupport[i-1], next.root.RequiredSupport[i] = next.root.RequiredSupport[i], next.root.RequiredSupport[i-1]
			next.support[i-1], next.support[i] = next.support[i], next.support[i-1]
			next.supportFacts[i-1], next.supportFacts[i] = next.supportFacts[i], next.supportFacts[i-1]
			next.adminIndex.Pages[i-1], next.adminIndex.Pages[i] = next.adminIndex.Pages[i], next.adminIndex.Pages[i-1]
		}
	}
	next.root.RequiredSupportRecordCount += uint32(len(carriers))
	shards, err := format.EncodeAdministrativeIndexPages(next.adminIndex)
	if err != nil {
		t.Fatal(err)
	}
	next.root.AdministrativeIndex, next.root.AdministrativeIndexShards = shards[0].Ref, nil
	for i, shard := range shards {
		put(shard.Ref, shard.Body)
		if i != 0 {
			next.root.AdministrativeIndexShards = append(next.root.AdministrativeIndexShards, shard.Ref)
		}
	}
	next.recountChildren()
	if next.root.ChildCount > contract.MaxChildPages {
		t.Fatal("current support fixture exceeds accepted child count", next.root.ChildCount)
	}
	if err := original.bindReceiptSuccessorSlices(&next); err != nil {
		t.Fatal("current required support unchanged intent facts", err)
	}
	if _, err := next.publicStateProjection(); err != nil {
		t.Fatal("current required support public projection", err)
	}
	store, source := writeSignedCurrentIntentImage(t, env, original, original, &next, store, label, put)
	if source.valueEntry(slot).Generated.RequiredSupport != entry.Generated.RequiredSupport || entry.Generated.RequiredSupport.Count != uint32(count) || entry.Generated.RequiredSupport.Length != uint64(4+count*107) {
		t.Fatal("signed current support descriptor changed")
	}
	indexBytes, err := format.AdministrativeIndexEncodedLength(source.adminIndex)
	if err != nil {
		t.Fatal("signed current support index", err)
	}
	t.Logf("signed current support: rows=%d carrier-body-bytes=%d physical-pages=%d children=%d child-bytes=%d index-shards=%d logical-index-bytes=%d", count, count*(103+120), (count+rowsPerPage-1)/rowsPerPage, source.root.ChildCount, source.root.ChildEncodedBytes, 1+len(source.root.AdministrativeIndexShards), indexBytes)
	return store, source, slot
}

// full_only: false
func TestAuthorityReplacementPreservesSharedSlicePublicationOwner(t *testing.T) {
	env, fixture, _ := configuredSuccessionMemoryFixture(t, false)
	original := fixture.session
	next := *original
	next.root.Snapshot = fixtureID(env.Domain, "shared Slice owner snapshot")
	next.root.Transition = fixtureID(env.Domain, "shared Slice owner transition")
	next.adminIndex = clonePublicationWork(original.adminIndex)
	next.adminIndex.Object = administrativeIndexObject(env.Domain, next.root.Snapshot)
	owner := slices.IndexFunc(next.adminIndex.Groups, func(group format.AdministrativeGroup) bool {
		return group.OwnerKind == format.AdministrativePublicationCoordinate
	})
	page := slices.IndexFunc(next.adminIndex.Pages, func(page format.AdministrativePage) bool { return page.ReadRequired })
	if owner < 0 || page < 0 || len(next.adminIndex.Pages[page].Spans) == 0 {
		t.Fatal("shared Slice/publication owner fixture missing")
	}
	next.adminIndex.Pages[page].Spans[0].GroupIndexes = []uint16{uint16(owner)}
	var count uint32
	for _, page := range next.adminIndex.Pages {
		for _, span := range page.Spans {
			if slices.Contains(span.GroupIndexes, uint16(owner)) {
				count += uint32(span.Count)
			}
		}
	}
	digest := selectedDisposableDigest(count)
	group := &next.adminIndex.Groups[owner]
	group.ChargedPages, group.ChargedBytes = 0, 0
	for i, page := range next.adminIndex.Pages {
		logical, charged := 0, false
		for _, span := range page.Spans {
			if slices.Contains(span.GroupIndexes, uint16(owner)) {
				charged = true
				for j := logical; j < logical+int(span.Count); j++ {
					row := original.support[i].Records[j]
					length := uint32(len(row.Body))
					if row.Body == nil {
						length = original.supportFacts[i].rows[j].BodyLength()
					}
					writeSelectedDisposableRow(digest, row.Kind, row.RecordID, length)
					group.ChargedBytes += uint64(contract.SupportRecordOverhead) + uint64(length)
				}
			}
			logical += int(span.Count)
		}
		if charged {
			group.ChargedPages++
		}
	}
	group.Disposable = selectedDisposableDescriptor(digest, count)
	shards, err := format.EncodeAdministrativeIndexPages(next.adminIndex)
	if err != nil {
		t.Fatal("shared Slice index", err)
	}
	store := selectedMemoryStoreCopy(env.Store.(*memoryStore))
	put := func(ref format.Ref, body []byte) {
		t.Helper()
		if err := format.CheckReference(ref, body); err != nil {
			t.Fatal(err)
		}
		if err := store.putSelected(mustKey(t, store.desc.Prefix, ref), body); err != nil {
			t.Fatal(err)
		}
	}
	next.root.AdministrativeIndex, next.root.AdministrativeIndexShards = shards[0].Ref, nil
	for i, shard := range shards {
		put(shard.Ref, shard.Body)
		if i != 0 {
			next.root.AdministrativeIndexShards = append(next.root.AdministrativeIndexShards, shard.Ref)
		}
	}
	next.recountChildren()
	store, source := writeSignedCurrentIntentImage(t, env, original, original, &next, store, "shared Slice owner", put)
	env.Store = store
	for _, private := range []bool{false, true} {
		t.Run(map[bool]string{false: "reusable", true: "private"}[private], func(t *testing.T) {
			caseStore := selectedMemoryStoreCopy(store)
			caseEnv := env
			caseEnv.Store = caseStore
			admission := OpenContext{admission: &source.admission}
			var before *StateSession
			var result Result
			if private {
				before, result = openReplacementSession(t.Context(), admission, caseStore, false)
			} else {
				before, result = Open(t.Context(), admission, caseStore)
			}
			if before == nil || result.Outcome != ObservedCurrent {
				t.Fatal("shared Slice source did not authenticate", result)
			}
			caseEnv = syntheticAuthorityScenarioEnvironment(t, caseEnv)
			actors := caseEnv.ReplacementActors(t, t.Context(), before, contract.SuccessionReplaceAuthority, contract.SuccessionChangeAuthorityKEK, contract.NormalSigningRole)
			defer actors.Keys.RetireAccess()
			permit := admitAuthorityReplacement(t, before, actors.Keys, actors.After, contract.SuccessionReplaceAuthority, contract.NormalSigningRole, contract.SuccessionChangeAuthorityKEK, actors.Source)
			if err := before.successionRequestValid(t.Context(), permit.request, permit.plan); err != nil {
				t.Fatal("shared Slice admitted request relation", err)
			}
			subjects, err := contract.SuccessionChangedSubjectDescriptor(permit.request)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := before.projectedSuccessionRoot(t.Context(), permit.request, permit.plan, subjects); err != nil {
				projected := *before
				projected.root.Snapshot, projected.root.Transition = permit.plan.snapshot, permit.plan.transition
				if _, rebindErr := before.rebindGeneratedSnapshot(t.Context(), &projected, permit.plan); rebindErr != nil {
					t.Fatal("shared Slice projected carrier rebinding", rebindErr)
				}
				var bodyCharge, factCharge uint64
				for i, page := range before.adminIndex.Pages {
					logical := 0
					for _, span := range page.Spans {
						if slices.Contains(span.GroupIndexes, uint16(owner)) {
							for j := logical; j < logical+int(span.Count); j++ {
								row := projected.support[i].Records[j]
								fact := projected.supportFacts[i].rows[j]
								if fact.Kind() != row.Kind || fact.RecordID() != row.RecordID || projected.supportFacts[i].ref != projected.root.RequiredSupport[i] {
									t.Fatal("shared Slice projected fact binding")
								}
								bodyCharge += uint64(contract.SupportRecordOverhead + len(row.Body))
								factCharge += uint64(contract.SupportRecordOverhead) + uint64(fact.BodyLength())
							}
						}
						logical += int(span.Count)
					}
				}
				indexErr := before.installSuccessionSnapshotIndex(t.Context(), &projected, &Candidate{session: before})
				installed := projected.adminIndex.Object == administrativeIndexObject(before.root.Domain, permit.plan.snapshot)
				if installed {
					outputErr := before.bindPreservedOutputConfiguration(&projected)
					publicationErr := before.bindPreservedPublication(t.Context(), &projected)
					reserveErr := projected.reserveOrdinaryPublicationRewrite(t.Context())
					exitErr := projected.reserveFirstEndWork(t.Context())
					t.Fatalf("shared Slice projected support/index: %v; body-charge=%d authenticated-charge=%d expected-charge=%d output=%v publication=%v rewrite=%v exit=%v", err, bodyCharge, factCharge, group.ChargedBytes, outputErr, publicationErr, reserveErr, exitErr)
				}
				t.Fatalf("shared Slice projected support/index: %v; body-charge=%d authenticated-charge=%d expected-charge=%d index-installed=%t index-error=%v", err, bodyCharge, factCharge, group.ChargedBytes, installed, indexErr)
			}
			candidate, result := before.PrepareSuccession(t.Context(), permit, actors.Signers)
			if candidate == nil || result.Outcome != ObservedCurrent {
				t.Fatal("shared Slice ownership refused actual authority replacement", result)
			}
			deliverSuccessionBasis(t, candidate)
			after, result := before.selectCandidate(t.Context(), candidate)
			if after == nil || result.Outcome != ObservedCurrent {
				t.Fatal("shared Slice authority observation", result)
			}
			if !slices.Equal(after.adminIndex.Pages[page].Spans[0].GroupIndexes, []uint16{uint16(owner)}) ||
				after.adminIndex.Groups[owner].ChargedPages != group.ChargedPages || after.adminIndex.Groups[owner].ChargedBytes != group.ChargedBytes {
				t.Fatal("authority replacement changed shared selected ownership or exact charge")
			}
		})
	}
}

// full_only: true
// Maximum-capacity or accumulated-history proof; smaller behavior checks remain in dev.
// exclusive: true
func TestSuccessionJointMaximumMemory(t *testing.T) {
	env, fixture, keys := configuredSuccessionMemoryFixture(t, true)
	seed := privateReplacementMemorySeed(freezeConfiguredSuccessionMemorySeed(t, true, env, fixture, keys))
	for _, fault := range []string{"success", "different-current", "missing-observed-support", "invalid-observed-support", "cancel-second-batch", "denied-second-batch"} {
		t.Run(fault, func(t *testing.T) { runSuccessionJointMaximumMemory(t, fault, seed) })
	}
	t.Run("large-current-support", func(t *testing.T) {
		store, current, _ := signedCurrentRequiredSupport(t, env, fixture.session, 200000)
		caseEnv := env
		caseEnv.Store = store
		caseFixture := &environmentFixture{session: current, admission: OpenContext{admission: &current.admission}}
		large := privateReplacementMemorySeed(freezeConfiguredSuccessionMemorySeed(t, true, caseEnv, caseFixture, keys))
		runSuccessionJointMaximumMemory(t, "success", large)
	})
}

// full_only: true
// exclusive: true
func TestSuccessionPublicationMaximumMemory(t *testing.T) {
	env, f, keys := configuredSuccessionMemoryFixture(t, true)
	rows, order := successionTerminalPublicationRows(t, f.session)
	env, f.session = publicationJointSelectedImage(t, env, f.session, f.session, rows, order, 0, 0, "terminal publication memory")
	f.admission = OpenContext{admission: &f.session.admission}
	seed := privateReplacementMemorySeed(freezeConfiguredSuccessionMemorySeed(t, true, env, f, keys))
	for _, fault := range []string{"success", "different-current", "missing-observed-support", "invalid-observed-support", "cancel-second-batch", "denied-second-batch"} {
		t.Run(fault, func(t *testing.T) { runSuccessionJointMaximumMemory(t, fault, seed) })
	}
}

// The current output route is separate from each qualified historical birth.
// A later binding can keep the same physical coordinate and its frozen target.
func successionTerminalPublicationRows(t *testing.T, before *StateSession) ([]contract.SupportRecord, []format.PublicationCoordinateOrder) {
	t.Helper()
	rows, order, _ := publicationJointConfiguredMarkers(t, before, true)
	selected, err := inspectPublicationRows(before.root.Domain, rows)
	if err != nil {
		t.Fatal(err)
	}
	targets := make(map[contract.ID]contract.OutputTarget)
	for _, binding := range capacityOutputConfiguration(t, before, true).Bindings {
		for _, target := range binding.Targets {
			id, err := contract.PublicationCoordinateID(before.root.Domain, target.ServiceContractID, target.CanonicalTarget)
			if err != nil {
				t.Fatal(err)
			}
			targets[id] = target
		}
	}
	byCoordinate := make(map[contract.ID][]contract.PublicationMarker)
	for _, marker := range selected.markers {
		byCoordinate[marker.CoordinateID] = append(byCoordinate[marker.CoordinateID], marker)
	}
	var out []contract.SupportRecord
	var markerBytes uint64
	for id, coordinate := range selected.coordinates {
		markers := byCoordinate[id]
		slices.SortFunc(markers, func(a, b contract.PublicationMarker) int {
			if a.AdmissionOrdinal < b.AdmissionOrdinal {
				return -1
			}
			if a.AdmissionOrdinal > b.AdmissionOrdinal {
				return 1
			}
			return 0
		})
		if len(markers) != 2 {
			t.Fatal("terminal publication coordinate history", len(markers))
		}
		birth, write := markers[0], markers[1]
		coordinate.OwnerState, coordinate.LatestUnresolvedAttemptID = contract.PublicationOwnerQualified, contract.ID{}
		coordinate.LastBindingIncarnationID = fixtureID(before.root.Domain, fmt.Sprintf("historical memory binding %x", id))
		coordinate.DeletionDestinationID = strings.Repeat("d", 256)
		coordinate.DeletionTargetContractID = strings.Repeat("t", 256)
		coordinate.DeletionConfigContractID = strings.Repeat("c", 256)
		coordinate.DeletionCredentialRouteContractID = strings.Repeat("r", 256)
		coordinate.DeletionConsumerLocator = strings.Repeat("l", 1024)
		coordinate.DeletionTargetData = bytes.Repeat([]byte{'x'}, contract.MaxOutputTargetDataBytes)
		historical := targets[id]
		historical.TargetContractID, historical.TargetData, historical.ConsumerLocator = coordinate.DeletionTargetContractID, coordinate.DeletionTargetData, coordinate.DeletionConsumerLocator
		coordinate.DeletionTargetRowDigest, err = contract.PublicationTargetRowDigest(before.root.Domain, coordinate.DeletionDestinationID, coordinate.LastBindingIncarnationID, historical)
		if err != nil {
			t.Fatal(err)
		}
		for i, marker := range []contract.PublicationMarker{birth, write} {
			marker.State, marker.Evidence.Class, marker.Evidence.NormalizedStatus = contract.PublicationAcknowledged, contract.PublicationRequestAcknowledged, 200
			marker.ExecutorID, marker.CredentialRouteID = strings.Repeat("e", 256), strings.Repeat("r", 256)
			marker.Evidence.SafeRequestID, marker.Evidence.SafeResourceID = strings.Repeat("q", 1024), strings.Repeat("s", 1024)
			marker.Projection.BindingIncarnationID = coordinate.LastBindingIncarnationID
			marker.Projection.TargetRowDigest = coordinate.DeletionTargetRowDigest
			if i == 0 {
				marker.Evidence.ConsumerLocator = coordinate.DeletionConsumerLocator
				marker.BirthServiceContractID, marker.BirthTargetContractID = coordinate.ServiceContractID, coordinate.DeletionTargetContractID
			} else {
				marker.Projection.Action, marker.Projection.OwnedBirthAttemptID = contract.PublicationWriteValue, birth.AttemptID
				marker.Projection.ValueBasisDigest = fixtureID(before.root.Domain, fmt.Sprintf("historical memory value %x", id))
				marker.BirthServiceContractID, marker.BirthTargetContractID, marker.Evidence.ConsumerLocator = "", "", ""
			}
			marker.ProjectionCommitment, err = contract.PublicationProjectionCommitment(marker.Projection)
			if err != nil {
				t.Fatal(err)
			}
			body, err := contract.EncodePublicationMarker(marker)
			// Marker/v5: 763 fixed bytes, executor/route 512 bytes, two
			// safe IDs 2048 bytes; birth adds locator 1024 and contract IDs.
			want := 3323
			if i == 0 {
				want += 1024 + len(coordinate.ServiceContractID) + 256
			}
			if err != nil || len(body) != want {
				t.Fatal("terminal marker byte account", len(body), want, err)
			}
			markerBytes += uint64(len(body))
			out = append(out, contract.SupportRecord{Kind: contract.PublicationMarkerSupportKind, RecordID: marker.AttemptID, Body: body})
			if i == 0 {
				birth = marker
			} else {
				write = marker
			}
		}
		coordinate.OwnedBirthAttemptID = birth.AttemptID
		coordinate.OwnedInstanceDigest, err = contract.PublicationOwnedInstanceDigest(before.root.Domain, id, birth.Projection.BindingIncarnationID, birth.Projection.EntryIncarnationID, birth.Projection.TargetRowDigest, birth.AttemptID, birth.Evidence.SafeResourceID)
		if err != nil {
			t.Fatal(err)
		}
		coordinate.LastValueAckAttemptID, coordinate.LastValueAckIncarnationID, coordinate.LastValueAckOrdinal = write.AttemptID, write.PublicationIncarnationID, write.AdmissionOrdinal
		coordinate.LastPolicyAckAttemptID, coordinate.LastPolicyAckIncarnationID, coordinate.LastPolicyAckOrdinal, coordinate.LastPolicyDigest = write.AttemptID, write.PublicationIncarnationID, write.AdmissionOrdinal, write.Projection.PolicyDigest
		coordinate.LastValueDigest, err = contract.PublicationSelectedValueDigest(before.root.Domain, write.Projection.ValueBasisDigest, birth.AttemptID, coordinate.OwnedInstanceDigest)
		if err != nil {
			t.Fatal(err)
		}
		body, err := contract.EncodePublicationCoordinate(coordinate)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, contract.SupportRecord{Kind: contract.PublicationCoordinateSupportKind, RecordID: id, Body: body})
	}
	if len(selected.coordinates) != 1024 || len(out) != 3072 {
		t.Fatal("terminal publication population", len(selected.coordinates), len(out))
	}
	if _, err := publicationRowsRelation(before.root.Domain, out, order); err != nil {
		t.Fatal("terminal publication relation", err)
	}
	t.Logf("terminal publication memory population: coordinates=1024 markers=2048 marker-body-bytes=%d coordinate-target-data-bytes=%d", markerBytes, 1024*contract.MaxOutputTargetDataBytes)
	return out, order
}

func successionMemorySource(t *testing.T, state *StateSession) replacementImageMemorySource {
	t.Helper()
	if state == nil {
		t.Fatal("replacement memory source image missing")
	}
	locations, err := state.resolveSelectedGeneratedSlices()
	if err != nil {
		t.Fatal("replacement memory logical source dimensions", err)
	}
	source := replacementImageMemoryDimensions(state.root, locations)
	if source.ChildBytes != state.root.ChildEncodedBytes || source.ChildBytes > replacementPhysicalChildUpper {
		t.Fatal("replacement memory child Ref dimensions differ from selected root", source.ChildBytes, state.root.ChildEncodedBytes)
	}
	return source
}

func runSuccessionJointMaximumMemory(t *testing.T, fault string, seed configuredSuccessionMemorySeed) {
	t.Helper()
	timing := startCapacityTimer(t)
	defer timing.finish()
	env, f, keys := seed.openCase(t)
	full := seed.full
	timing.next("operation")
	before := f.session
	predecessorSource := successionMemorySource(t, before)
	if !before.replacementRead || before.admission.outputInterpreter != nil {
		t.Fatal("memory case did not open the private replacement lifetime")
	}
	encoded, err := contract.EncodeControlCore(currentControlOf(before))
	if err != nil {
		t.Fatal(err)
	}
	after, err := contract.DecodeControlCore(encoded)
	if err != nil {
		t.Fatal(err)
	}
	source := contract.BindingTableRow{SubjectKind: 1, SubjectID: after.AuthorityRecipientID, Binding: after.AuthorityKMSBinding}
	signer, binding := env.Recovery.(*testtrust.Signer).Successor(t, after.Recovery.Signing)
	after.Recovery.Signing = binding
	after.Recovery.KMS = keys.KEKSuccessor(t, contract.SuccessorRecoveryKEK)
	after.AccessGeneration++
	keys.LoseRecipientPredecessor(after.Recovery.RoleID)
	permit := admitAuthorityReplacement(t, before, keys, after, 3, 1, 12, source)
	defer keys.RetireAccess()
	// These are the same independently owned fields kept by the installed
	// constructor. Its immutable basis is shared with the private admission.
	// The constructor/admission isolation roots cover that source handoff.
	sourceControl, err := replacementCallbackControl(currentControlOf(before))
	if err != nil {
		t.Fatal(err)
	}
	sourceOwner := ReplacementInstallation{ExpectedControl: sourceControl, PublicBasis: before.admission.publicBasis()}
	for _, row := range before.registry() {
		if row.RecipientID != sourceControl.AuthorityRecipientID && row.CurrentBinding != nil {
			sourceOwner.CapturedRecipients = append(sourceOwner.CapturedRecipients, ReplacementRecipientFact{RecipientID: row.RecipientID, Encryption: *row.CurrentBinding})
		}
	}
	selectedRecipients := len(sourceOwner.CapturedRecipients)
	for len(sourceOwner.CapturedRecipients) < seed.capturedRecipients {
		sourceOwner.CapturedRecipients = append(sourceOwner.CapturedRecipients, sourceOwner.CapturedRecipients[len(sourceOwner.CapturedRecipients)%selectedRecipients])
	}
	sourceOwner.CapturedRecipients, err = ownReplacementRecipients(sourceOwner.CapturedRecipients)
	if err != nil {
		t.Fatal(err)
	}
	var capturedBytes byteBuffers
	for _, row := range sourceOwner.CapturedRecipients {
		capturedBytes.add(row.Encryption.SPKI)
	}
	t.Logf("replacement source recipients=%d distinct-spki-capacity=%d", len(sourceOwner.CapturedRecipients), capturedBytes.capacity())
	memory := startMemoryAccounting()
	memory.replacementSource = &sourceOwner
	defer func() {
		for _, sample := range memory.samples {
			t.Logf("phase %s: owned=%d heap-upper=%d", sample.Phase, sample.ByteCapacity, sample.GoHeapUpperBound)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	witness := &successionMemoryCrypto{Crypto: permit.crypto, t: t, memory: memory, permit: permit, keys: keys, cancel: cancel, fault: fault}
	permit.crypto = witness
	sampleSuccessionMemory(memory, "admitted", permit, nil, nil)
	selectedBytes := uint64(len(before.body)) + uint64(before.head.Core.Root.Length) + before.root.ChildEncodedBytes
	var accessWraps uint64
	for _, page := range before.access {
		if page != nil {
			for _, row := range page.Records {
				accessWraps += uint64(len(row.Wraps))
			}
		}
	}
	wantWraps := uint64(12 + 6)
	if full {
		wantWraps = 4096 + 512
	}
	if accessWraps != wantWraps {
		t.Fatal("joint maximum access wrap count differs", accessWraps, wantWraps)
	}
	var registryBytes uint64
	for _, ref := range before.root.Recipients {
		if ref != nil {
			registryBytes += uint64(ref.Length)
		}
	}
	store := env.Store.(*memoryStore)
	creates, cas := store.creates, store.cas
	candidate, result := before.PrepareSuccession(ctx, permit, SuccessionSigners{Authorizer: env.Trust, RecoverySuccessor: signer})
	sampleSuccessionMemory(memory, "prepare-return", permit, candidate, nil)
	candidateSource, observationSource := replacementUnknownImageMemorySource(), replacementUnknownImageMemorySource()
	var candidateRefs []format.Ref
	if candidate != nil {
		candidateSource = successionMemorySource(t, candidate.replacementState)
		candidateRefs = make([]format.Ref, 0, len(candidate.objects))
		for _, object := range candidate.objects {
			candidateRefs = append(candidateRefs, object.ref)
		}
	}
	var observedForVerification *StateSession
	var expectedSupport contract.GeneratorDescriptor
	var expectedSupportSlot uint16
	var newAccessBytes uint64
	var selectionReadBase, selectionReadBody uint64
	observationDecodedCapacity := decodedMemoryObservationCapacity(before)
	if fault != "cancel-second-batch" && fault != "denied-second-batch" {
		if candidate == nil || result.Outcome != ObservedCurrent || full && witness.batches < 2 || !full && witness.batches != 1 {
			t.Fatal("joint replacement preparation", result, witness.batches)
		}
		for _, object := range candidate.objects {
			if object.ref.Kind == contract.AccessKind {
				newAccessBytes += uint64(len(object.body))
			}
		}
		admission := deliverSuccessionBasis(t, candidate)
		sampleSuccessionMemory(memory, "owner-basis-delivered", permit, candidate, nil)
		fixtureWork := false
		if fault != "success" {
			before.store = boundaryStore{Store: before.store, after: func(method, _ string) {
				if method != "CAS" {
					return
				}
				fixtureWork = true
				defer func() { fixtureWork = false }()
				// The Store fixture installs a later signed closure after the
				// writer's CAS and before its ordinary current observation.
				// Fixture construction is not part of Core's owned workspace.
				reader := *before
				reader.store = env.Store
				reader.admission = *admission.admission
				reader.key, _ = publicKey(reader.admission.publicKey)
				selected, res := reader.readCurrentImage(ctx, false)
				if selected == nil {
					t.Fatal("different selection fixture", res)
				}
				seedDifferentSuccessionMemoryHead(t, env, before, candidate, selected)
				reader.cache = make(map[format.Ref][]byte)
				competing, competingResult := reader.readCurrentImage(ctx, false)
				if competing == nil || competingResult.Outcome != ObservedCurrent ||
					competing.root.Snapshot != fixtureID(env.Domain, "other memory snapshot") ||
					competing.head.Core.Root.Object != competing.root.Snapshot {
					t.Fatal("signed competing memory closure did not cold-open", competingResult)
				}
				if seed.observedSupportRows != 0 {
					largeStore, large, slot := signedCurrentRequiredSupport(t, env, competing, seed.observedSupportRows)
					store.objects, store.generation = largeStore.objects, largeStore.generation
					expectedSupport, expectedSupportSlot = large.valueEntry(slot).Generated.RequiredSupport, slot
					competing, competingResult = reader.readCurrentImage(ctx, false)
					if competing == nil || competingResult.Outcome != ObservedCurrent || competing.valueEntry(slot).Generated.RequiredSupport != expectedSupport {
						t.Fatal("larger signed observation did not cold-open", competingResult)
					}
					observationDecodedCapacity = decodedMemoryObservationCapacity(competing)
					if observationDecodedCapacity <= decodedMemoryObservationCapacity(before) {
						t.Fatal("larger observation did not add independent byte owners", observationDecodedCapacity)
					}
					t.Logf("independent observation fixture: support-rows=%d predecessor-decoded-bytes=%d observation-decoded-bytes=%d child-bytes=%d children=%d", seed.observedSupportRows, decodedMemoryObservationCapacity(before), observationDecodedCapacity, competing.root.ChildEncodedBytes, competing.root.ChildCount)
				}
				observationSource = successionMemorySource(t, competing)
				if fault == "missing-observed-support" || fault == "invalid-observed-support" {
					readBody := func(key string) []byte {
						value, ok := store.objects[key]
						if !ok {
							t.Fatal("joint replacement fault source is missing", key)
						}
						read := readFixtureStoredBody(value, ^uint32(0))
						if read.Status != contract.ReadOK {
							t.Fatal("joint replacement fault source is unreadable", key, read.Status, read.Reason)
						}
						return read.Body
					}
					head, err := format.DecodeHead(readBody(store.desc.HeadKey))
					if err != nil {
						t.Fatal(err)
					}
					root, err := format.DecodeRoot(readBody(mustKey(t, store.desc.Prefix, head.Core.Root)))
					if err != nil {
						t.Fatal(err)
					}
					if !slices.Equal(root.RequiredSupport, competing.root.RequiredSupport) {
						t.Fatal("joint replacement fault selected support identity")
					}
					faultRef := successionReceiptSupportRef(t, competing, 2*contract.MutationReceiptWindowLimit)
					if seed.observedSupportRows != 0 {
						faultRef = competing.root.RequiredSupport[len(competing.root.RequiredSupport)-1]
					}
					key := mustKey(t, store.desc.Prefix, faultRef)
					if fault == "missing-observed-support" {
						delete(store.objects, key)
					} else {
						body := readBody(key)
						body[len(body)-1] ^= 1
						if err := store.putSelected(key, body); err != nil {
							t.Fatal("joint replacement fault body", err)
						}
					}
				}
			}}
		}
		// Observe provider capacities during the independent read. Fixture setup
		// records this competing image's decoded shape before a last-page fault;
		// that characterization also covers a discarded tentative observation.
		priorRead := store.readHook
		store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
			if priorRead != nil {
				read = priorRead(key, read)
			}
			if !fixtureWork {
				if selectionReadBase == 0 {
					buffers := retainedByteBuffers(before, nil, candidate, nil)
					buffers.addSuccessionRequest(permit.request)
					buffers.add(permit.source.Binding.SPKI)
					buffers.addReplacementSource(memory.replacementSource)
					selectionReadBase = buffers.capacity()
				}
				selectionReadBody = max(selectionReadBody, uint64(cap(read.Body)))
			}
			return read
		}
		observed, result := before.selectCandidate(ctx, candidate)
		store.readHook = priorRead
		want := ObservedCurrent
		if fault != "success" {
			want = UnresolvedCommit
		}
		if result.Outcome != want || result.RequestedRevision != candidate.head.Core.Revision {
			t.Fatal("joint replacement selection", result)
		}
		if fault == "missing-observed-support" || fault == "invalid-observed-support" {
			reason := MissingSelectedObject
			if fault == "invalid-observed-support" {
				reason = InvalidReference
			}
			if observed != nil || result.Reason != reason || !result.CommitMayHaveOccurred || result.Evidence == AuthenticatedClosure {
				t.Fatal("late observation failure lost uncertainty", result)
			}
		} else if observed == nil || result.Evidence != AuthenticatedClosure {
			t.Fatal("selection did not authenticate its actual observation", result)
		} else if fault == "different-current" {
			if result.Reason != DifferentSelection || !result.CommitMayHaveOccurred || result.ObservedRevision == candidate.head.Core.Revision {
				t.Fatal("different closure lost selection uncertainty", result)
			}
		} else if result.ObservedRevision != candidate.head.Core.Revision {
			t.Fatal("exact selection revision", result)
		}
		if observed != nil {
			if !observed.replacementRead {
				t.Fatal("replacement observation lost its private lifetime")
			}
			observedForVerification = observed
			observationSource = successionMemorySource(t, observed)
			assertCapacityPublicationPreserved(t, before, observed)
			wantGenerated := 2
			if full {
				wantGenerated = 128
			}
			assertCapacityCurrentIntents(t, observed, wantGenerated)
			if fault == "success" {
				assertCapacityConfigurationPreserved(t, before, observed)
			} else if observed.root.OutputConfiguration != before.root.OutputConfiguration || !observed.selectedOutputComplete() || len(observed.adminIndex.PublicationOrder) != len(before.adminIndex.PublicationOrder) {
				t.Fatal("different closure lost configuration")
			}
		}
		// The private selection implementation returns the actual
		// decoded observation. The public wrapper discards it and
		// returns only Result; the owner counter keeps it through this
		// sample together with the predecessor and candidate.
		sampleSuccessionMemory(memory, "select-"+fault+"-overlap", permit, candidate, observed)

	} else {
		if candidate != nil || result.Outcome != AdmissionRefused || witness.batches != 2 || store.creates != creates || store.cas != cas {
			t.Fatal("partial replacement changed selected storage", result, witness.batches)
		}
		// No candidate access image survives a refused preparation.
		sampleSuccessionMemory(memory, "failed-preparation-retained", permit, nil, nil)
	}
	sourceAccount := replacementCoreMemoryAccount(predecessorSource, candidateSource, observationSource, candidateRefs, uint64(len(sourceOwner.CapturedRecipients)))
	unknownObservation := replacementCoreMemoryAccount(predecessorSource, candidateSource, replacementUnknownImageMemorySource(), candidateRefs, uint64(len(sourceOwner.CapturedRecipients)))
	coreAllowance := sourceAccount.CoreUpper
	// Crypto's complete batch component includes both visible wire bodies.
	// Add its remaining owner allowance to those samples, all earlier Core
	// outputs, one serial provider response and the public remainder. The
	// candidate assembly phase instead owns object bodies and verified cache;
	// it follows the private batches and needs one persistence workspace.
	var preparationEnvelope, selectionEnvelope uint64
	// Custody retains its independently decoded public binding table until
	// RetireAccess. The Crypto batch component already includes it; later
	// phases need its separate complete-table upper bound as well.
	const cryptoBindingUpper = uint64(258 * contract.KMSPublicKeyLength)
	for _, sample := range memory.samples {
		if sample.Phase == "prepare-return" {
			preparationEnvelope = max(preparationEnvelope, sample.ByteCapacity+4<<20+cryptoBindingUpper)
		}
		if strings.HasPrefix(sample.Phase, fmt.Sprintf("exchange-%d-", contract.CryptoPrepare)) {
			preparationEnvelope = max(preparationEnvelope, sample.ByteCapacity+sample.ResultUnobservedReserve+accessWraps*384+1<<20+128<<10)
		}
		if sample.Phase == "owner-basis-delivered" {
			// Source SPKIs are already sampled. Offered, expected, callback
			// readback and owned readback populations can overlap at delivery.
			// Public-basis copies end before the CAS read.
			preparationEnvelope = max(preparationEnvelope, sample.ByteCapacity+4<<20+3*786432+4*capturedBytes.capacity()+cryptoBindingUpper)
		}
		if strings.HasPrefix(sample.Phase, "select-") {
			// Provider +settings +rounded policy bounds the read visitor.
			// Intent+unquote after provider release is a smaller alternative.
			// Root digest encoding follows the streamed validators.
			selectionEnvelope = max(sample.ByteCapacity+2<<20+598016+cryptoBindingUpper,
				selectionReadBase+observationDecodedCapacity+selectionReadBody+598016+cryptoBindingUpper)
		}
	}
	if selectionReadBase != 0 {
		memory.sample("independent-read-prefix-envelope", before, nil, candidate, nil)
		sample := &memory.samples[len(memory.samples)-1]
		sample.ByteCapacity = selectionReadBase + observationDecodedCapacity + selectionReadBody + 598016 + cryptoBindingUpper
		sample.ResultStoreCapacity = selectionReadBody
		sample.ResultUnobservedReserve = observationDecodedCapacity + 598016 + cryptoBindingUpper
	}
	if preparationEnvelope > coreAllowance || selectionEnvelope > coreAllowance {
		t.Errorf("composed phase envelopes exceed source-derived Core allowance: prepare=%d select=%d limit=%d", preparationEnvelope, selectionEnvelope, coreAllowance)
	}
	evidence, err := json.Marshal(struct {
		GoVersion               string `json:"go_version"`
		AccessRecords           uint32 `json:"access_records"`
		AccessWraps             uint64 `json:"access_wraps"`
		SelectedBytes           uint64 `json:"selected_encoded_bytes"`
		NewAccessBytes          uint64 `json:"new_access_encoded_bytes"`
		RegistryBytes           uint64 `json:"registry_encoded_bytes"`
		CoreAllowance           uint64 `json:"core_byte_allowance"`
		PreparationEnvelope     uint64 `json:"preparation_byte_envelope"`
		SelectionEnvelope       uint64 `json:"selection_byte_envelope"`
		Batches                 uint32 `json:"batches"`
		CryptoBindingUpper      uint64 `json:"crypto_retained_binding_upper_bytes"`
		MaxRequest, MaxResponse int
		Samples                 []memorySample                 `json:"samples"`
		SourceAccount           replacementMemorySourceAccount `json:"replacement_source_account"`
		UnknownObservationUpper uint64                         `json:"unknown_observation_core_upper_bytes"`
	}{runtime.Version(), before.root.AccessRecordCount, accessWraps, selectedBytes, newAccessBytes, registryBytes, coreAllowance, preparationEnvelope, selectionEnvelope, witness.batches, cryptoBindingUpper, witness.maxRequest, witness.maxResponse, memory.samples, sourceAccount, unknownObservation.CoreUpper})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(evidence))
	for _, sample := range memory.samples {
		if sample.ByteCapacity > sourceAccount.CoreUpper {
			t.Errorf("%s byte backing union %d exceeds source-derived Core allowance %d", sample.Phase, sample.ByteCapacity, sourceAccount.CoreUpper)
		}
		if sample.GoHeapUpperBound < sample.ByteCapacity {
			t.Errorf("%s heap bound is below its byte backing union", sample.Phase)
		}
	}
	if observedForVerification != nil {
		expected := before
		if expectedSupport.Count != 0 {
			copy := *before
			pageIndex, entryIndex := int(expectedSupportSlot)/format.PageSlots, int(expectedSupportSlot)%format.PageSlots
			page := *before.pages[pageIndex]
			entry := *page.Slots[entryIndex]
			entry.Generated.RequiredSupport = expectedSupport
			page.Slots[entryIndex], copy.pages[pageIndex] = &entry, &page
			expected = &copy
		}
		assertSuccessionCurrentValues(t, expected, observedForVerification, keys)
	}

}

// Private verification follows the complete replacement sample interval. Page
// references may change, while the complete named entries remain exact.
func assertSuccessionCurrentValues(t *testing.T, before, after *StateSession, keys *custody.Fixture) {
	t.Helper()
	if !slices.Equal(before.root.Names, after.root.Names) || before.root.ValueEntryCount != after.root.ValueEntryCount || before.root.SecretCount != after.root.SecretCount || before.root.RawBytes != after.root.RawBytes || before.root.MembershipCount != after.root.MembershipCount || before.root.SecretOrdinaryWrapCount != after.root.SecretOrdinaryWrapCount {
		t.Fatal("succession changed complete current dimensions")
	}
	for _, named := range before.root.Names {
		entry, actual := before.valueEntry(named.Slot), after.valueEntry(named.Slot)
		if entry == nil || !reflect.DeepEqual(entry, actual) {
			t.Fatal("succession changed exact current entry")
		}
		choice := uint8(custody.EmptyValue)
		if actual.ValueSource == contract.Generated {
			choice = custody.MaximumValue
		}
		selection := sessionConsumerSelection(t, after, after.admission.recipient, named.Name)
		if result := keys.Consume(t.Context(), selection, choice); result.Code != contract.CryptoSuccess || !result.ValueMatched {
			t.Fatal("succession observed private value", result)
		}
	}
}

// The trusted fixture re-encodes every child under a fresh object identity. It
// tests a complete uncached public closure, not another private operation.
func seedDifferentSuccessionMemoryHead(t *testing.T, env fixtureEnvironment, predecessor *StateSession, candidate *Candidate, selected *StateSession) {
	t.Helper()
	current := *selected
	current.root.Snapshot = fixtureID(env.Domain, "other memory snapshot")
	current.root.Transition = fixtureID(env.Domain, "other memory transition")
	plan := transitionPlan{operation: fixtureID(env.Domain, "other memory operation"), snapshot: current.root.Snapshot, transition: current.root.Transition, revision: fixtureID(env.Domain, "other memory revision")}
	put := func(kind contract.Kind, object contract.ID, index uint16, body []byte, err error) contract.Ref {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(kind, env.Domain, object, index, body)
		if err != nil {
			t.Fatal(err)
		}
		if _, cached := predecessor.cache[ref]; cached {
			t.Fatal("different closure used cached child")
		}
		key, err := format.Key(env.Store.Descriptor().Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		if err := env.Put(context.Background(), key, body); err != nil {
			t.Fatal(err)
		}
		return ref
	}
	for i, page := range selected.pages {
		if page == nil {
			continue
		}
		p := *page
		p.Object = fixtureID(env.Domain, fmt.Sprintf("other member page %d", i))
		b, err := format.EncodeValueEntryPage(p)
		ref := put(contract.ValueEntryPageKind, p.Object, p.Index, b, err)
		current.root.ValueEntryPages[i], current.pages[i], plan.pages[i] = &ref, &p, p.Object
	}
	var recipients []contract.Ref
	for i, page := range selected.recipients {
		if page == nil {
			continue
		}
		p := *page
		p.Object = fixtureID(env.Domain, fmt.Sprintf("other recipient page %d", i))
		b, err := format.EncodeRecipientPage(p)
		ref := put(contract.RecipientKind, p.Object, p.Index, b, err)
		current.root.Recipients[i], current.recipients[i], plan.recipientPages[i] = &ref, &p, p.Object
		recipients = append(recipients, ref)
	}
	var err error
	current.root.CurrentAccess.Core.RecipientRefsDescriptor, err = contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: env.Domain, Refs: recipients})
	if err != nil {
		t.Fatal(err)
	}
	current.root.CurrentAccess.Core.AccessPageRefs = nil
	for i, page := range selected.access {
		if page == nil {
			continue
		}
		p := *page
		p.Object = fixtureID(env.Domain, fmt.Sprintf("other access page %d", i))
		b, err := format.EncodeAccessPage(p)
		ref := put(contract.AccessKind, p.Object, p.Index, b, err)
		current.root.CurrentAccess.Core.AccessPageRefs = append(current.root.CurrentAccess.Core.AccessPageRefs, ref)
		current.access[i], plan.accessPages[i] = &p, p.Object
	}
	current.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(current.root.CurrentAccess.Core)
	if err != nil {
		t.Fatal(err)
	}
	current.root.RequiredSupport, current.support = nil, nil
	current.supportFacts, current.fragmentFacts = nil, nil
	current.adminIndex = selected.adminIndex
	current.adminIndex.Pages = slices.Clone(selected.adminIndex.Pages)
	if len(current.adminIndex.Pages) != len(selected.root.RequiredSupport) ||
		len(selected.support) != len(selected.root.RequiredSupport) || len(selected.supportFacts) != len(selected.root.RequiredSupport) {
		t.Fatal("different closure support index shape")
	}
	for i, prior := range selected.root.RequiredSupport {
		body, result := selected.readObjectUncached(t.Context(), prior)
		if result.Outcome != 0 {
			t.Fatal("different closure support read", result)
		}
		page, err := format.InspectRequiredSupportPage(body)
		if err != nil || page.Domain != env.Domain || page.Object != prior.Object || page.Index != prior.Index ||
			current.adminIndex.Pages[i].Ref != prior {
			t.Fatal("different closure physical support page", err)
		}
		plan.supportPages[prior.Index] = fixtureID(env.Domain, fmt.Sprintf("other support page %d", prior.Index))
		rows := make([]contract.SupportRecord, len(page.Records))
		for j, row := range page.Records {
			rows[j] = contract.SupportRecord(row)
		}
		support, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: env.Domain, Object: plan.supportPages[prior.Index], Index: prior.Index, Records: rows})
		ref := put(contract.RequiredSupportKind, plan.supportPages[prior.Index], prior.Index, support, err)
		current.root.RequiredSupport = append(current.root.RequiredSupport, ref)
		current.adminIndex.Pages[i].Ref = ref
		view, err := format.InspectRequiredSupportPage(support)
		if err != nil {
			t.Fatal(err)
		}
		selectedPage := format.RequiredSupportPageView{Domain: view.Domain, Object: view.Object, Index: view.Index}
		facts := selected.supportFacts[i]
		if facts.ref != prior || len(facts.ordinals) != len(selected.support[i].Records) {
			t.Fatal("different closure selected support rows")
		}
		for j, ordinal := range facts.ordinals {
			if int(ordinal) >= len(view.Records) || view.Records[ordinal].Kind != selected.support[i].Records[j].Kind ||
				view.Records[ordinal].RecordID != selected.support[i].Records[j].RecordID {
				t.Fatal("different closure selected row changed")
			}
			selectedPage.Records = append(selectedPage.Records, view.Records[ordinal])
		}
		current.support = append(current.support, selectedPage)
	}
	current.adminIndex.Object = fixtureID(env.Domain, "other administrative index")
	indexPages, err := format.EncodeAdministrativeIndexPages(current.adminIndex)
	if err != nil || len(indexPages) == 0 {
		t.Fatal("different closure administrative index", err)
	}
	current.root.AdministrativeIndexShards = nil
	for i, page := range indexPages {
		ref := put(contract.AdministrativeIndexKind, page.Ref.Object, page.Ref.Index, page.Body, nil)
		if ref != page.Ref {
			t.Fatal("different closure administrative index reference")
		}
		if i == 0 {
			current.root.AdministrativeIndex = ref
		} else {
			current.root.AdministrativeIndexShards = append(current.root.AdministrativeIndexShards, ref)
		}
	}
	current.recountChildren()
	root, err := format.EncodeRoot(current.root)
	rootRef := put(contract.RootKind, current.root.Snapshot, 0, root, err)
	intentLength := fixtureValueIntentLength(&current.root) + fixtureCompleteIntentOverhead(t, &current)
	comparison := &Comparison{session: selected, desired: fixtureID(env.Domain, "other memory intent"), desiredLength: intentLength}
	authority, err := selected.authorityFrom(&current, comparison, plan)
	if err != nil {
		t.Fatal("current memory authority", err)
	}
	h := candidate.head
	h.AuthKind, h.Succession, h.Subject = format.LifecycleAuth, nil, authority.subject()
	h.Core = selected.successorCore(plan)
	h.Core.Root = rootRef
	core, err := format.EncodeHeadCore(h.Core)
	if err != nil {
		t.Fatal(err)
	}
	conditionalBody, err := format.EncodeConditionalPlan(conditional(h.Core, core))
	if err != nil {
		t.Fatal(err)
	}
	h.Subject.HeadCore, h.Subject.HeadCoreLength, h.Subject.ConditionalPlan = contract.Hash(core), uint32(len(core)), contract.Hash(conditionalBody)
	request, err := contract.NewLifecycleRequest(h.Subject)
	if err != nil {
		t.Fatal(err)
	}
	proof := env.Trust.Sign(context.Background(), request)
	if proof.Reason != contract.ReasonNone {
		t.Fatal("different current memory fixture signing", proof.Reason)
	}
	h.AuthorizationSignature = proof.Signature
	body, err := format.EncodeHead(h)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Put(context.Background(), env.Store.Descriptor().HeadKey, body); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestInstalledSignerReplacementKeepsStreamedCurrentIntents(t *testing.T) {
	env, fixture, _ := configuredSuccessionMemoryFixture(t, false)
	before := fixture.session
	control := currentControlOf(before)
	successor, binding := env.Trust.(*fixtureTrust).Successor(t, control.NormalSigning)
	intentBlobs := make(map[contract.ID]bool)
	locations, err := before.resolveSelectedGeneratedSlices()
	if err != nil {
		t.Fatal(err)
	}
	for _, location := range locations {
		if location.ContentKind == contract.GeneratorContentIntent {
			intentBlobs[location.BlobID] = true
		}
	}
	intentKeys := make(map[string]int)
	for location, fact := range before.fragmentFacts {
		if intentBlobs[location.BlobID] {
			intentKeys[mustKey(t, env.Store.Descriptor().Prefix, fact.ref)] = 0
		}
	}
	if len(intentKeys) == 0 {
		t.Fatal("current intent fragment fixture missing")
	}
	input := ReplacementInstallation{ExpectedDomain: env.Domain, ExpectedStore: env.Store.Descriptor(), ExpectedControl: control,
		PublicBasis: fixture.admission.admission.publicBasis(), Store: env.Store, CompositionID: before.admission.composition,
		FileIdentity: fixtureID(env.Domain, "streamed signer source"), SourceUnchanged: func(context.Context) error { return nil }, CloseInstalled: func() {}}
	for _, row := range before.registry() {
		if row.CurrentBinding != nil {
			input.CapturedRecipients = append(input.CapturedRecipients, ReplacementRecipientFact{RecipientID: row.RecipientID, Encryption: *row.CurrentBinding})
		}
	}
	input.ResolvePublicGoal = func(context.Context, ReplacementPublicRequest) (ReplacementPublicGoal, error) {
		return ReplacementPublicGoal{Provider: env.Store.Descriptor().Family, Signing: &ReplacementSigningKey{Selector: binding.KeySelector, SPKI: binding.SPKI,
			Fingerprint: binding.Fingerprint, Trust: binding.Binding.Trust, Profile: binding.SigningProfile}}, nil
	}
	input.ConstructSigners = func(_ context.Context, authorizer contract.PublicSigningBinding, selected *contract.PublicSigningBinding) (SuccessionSigners, func(), error) {
		if !signingBindingEqual(authorizer, control.Recovery.Signing) || selected == nil || selected.KeySelector != binding.KeySelector || !bytes.Equal(selected.SPKI, binding.SPKI) || selected.Fingerprint != binding.Fingerprint || selected.SigningProfile != binding.SigningProfile || selected.Binding.Trust != binding.Binding.Trust {
			t.Fatal("signer replacement changed its fixed routes")
		}
		return SuccessionSigners{Authorizer: env.Recovery, NormalSuccessor: successor}, func() {}, nil
	}
	var delivered ReplacementSuccessor
	input.PublishSuccessor = func(_ context.Context, output ReplacementSuccessor) (ReplacementReadback, error) {
		delivered = output
		current, err := output.Basis.ControlCore(env.Domain, env.Store.Descriptor())
		return ReplacementReadback{FileIdentity: input.FileIdentity, Control: current, Basis: output.Basis, Recipients: output.Recipients, Correlation: output.Correlation}, err
	}
	owner, err := NewInstalledAuthorityReplacement(AuthorityReplacementInstallation{ReplacementInstallation: input,
		Goal: RoleReplacementGoal{ApprovalRole: contract.RecoverySigningRole, SigningSelector: binding.KeySelector}})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	store := env.Store.(*memoryStore)
	prior := store.readHook
	store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
		if prior != nil {
			read = prior(key, read)
		}
		if _, current := intentKeys[key]; current {
			intentKeys[key]++
		}
		return read
	}
	defer func() { store.readHook = prior }()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	output := owner.Replace(ctx, fixtureID(env.Domain, "streamed signer request"))
	store.readHook = prior
	if output.Result.Outcome != ObservedCurrent || output.Result.Evidence != AuthenticatedClosure {
		t.Fatal("installed signer replacement", output.Result)
	}
	for key, reads := range intentKeys {
		if reads != 2 {
			t.Fatalf("current intent page acquired extra replacement reads: key=%s reads=%d want2", key, reads)
		}
	}
	admission, result := admitPublicNormal(ctx, env.Domain, env.Store.Descriptor(), delivered.Basis, env.Store, input.CompositionID, nil)
	if result.Outcome != ObservedCurrent {
		t.Fatal("delivered successor admission", result)
	}
	selected, result := Open(ctx, admission, env.Store)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("cold successor", result)
	}
	assertCapacityCurrentIntents(t, selected, 2)
	beforeWindows, err := before.receiptWindows(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	afterWindows, err := selected.receiptWindows(t.Context())
	if err != nil || !reflect.DeepEqual(beforeWindows, afterWindows) {
		t.Fatal("signer-only replacement changed receipt windows", err)
	}
}

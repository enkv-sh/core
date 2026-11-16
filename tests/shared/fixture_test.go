package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

func memoryScenarioEnvironment(t testing.TB) fixtureEnvironment {
	return memoryScenarioEnvironmentMode(t, false)
}

func memoryScenarioEnvironmentMode(t testing.TB, recovery bool) fixtureEnvironment {
	t.Helper()
	ids, err := allocateGenesisIDs(nil)
	if err != nil {
		t.Fatal(err)
	}
	domain := ids.Domain
	desc := contract.Descriptor{Family: contract.GCP, Coordinate: testID("coordinate"), NonBody: testID("nonbody"), Prefix: "fixture", HeadKey: "fixture/HEAD"}
	store := &memoryStore{desc: desc, objects: make(map[string]stored)}
	store.configure(t, contract.GCP, domain)
	trust := &fixtureTrust{Signer: testtrust.New(t, contract.GCP, testID("trust"))}
	crypto := custody.New(t, desc.Family, fixtureID(domain, "custody"), recovery, []contract.ID{fixtureID(domain, "recipient"), fixtureID(domain, "reader")})
	env := fixtureEnvironment{Store: store, Trust: trust, GenesisIDs: ids, Domain: domain, PublicKey: trust.PublicKey(), SigningSelector: trust.KeySelector(), Bindings: crypto.Bindings(), Crypto: crypto.Crypto(), AdmitInit: crypto.AdmitInit, RetireInit: crypto.RetireInit, Custody: crypto}
	if recovery {
		signer := testtrust.NewRecovery(t, desc.Family, testID("recovery-trust"))
		env.Recovery, env.RecoveryPublicKey, env.RecoverySelector = signer, signer.PublicKey(), signer.KeySelector()
	}
	env.Put = func(_ context.Context, name string, body []byte) error {
		store.mu.Lock()
		defer store.mu.Unlock()
		return store.putSelected(name, body)
	}
	env.Delete = func(_ context.Context, name string) error {
		store.mu.Lock()
		defer store.mu.Unlock()
		delete(store.objects, name)
		return nil
	}
	env.FreshOpen = func(t testing.TB, want stateImage) {
		checkFreshProcess(t, &fixture{store: store, trust: trust, admission: fixtureAdmission(env)}, want)
	}
	env.FreshCurrent = func(t testing.TB, admission OpenContext, selected *StateSession) {
		input := selectedProcessFacts(t, admission, selected)
		var err error
		input.ExpectedWork, err = selected.workSupportRecords(t.Context())
		if err != nil {
			t.Fatal("fresh current work unavailable", err)
		}
		input.Objects, input.Generation = store.objects, store.generation
		checkFreshProcessInput(t, input)
	}
	env.FreshGeneratedRecord = func(t testing.TB, selected *StateSession, attempt contract.ID, result []byte) *StateSession {
		return selectFreshGeneratedRecord(t, store, selected, attempt, result)
	}
	env.FreshGeneratedFinal = func(t testing.TB, selected *StateSession) *StateSession {
		return selectFreshGeneratedFinal(t, store, selected)
	}
	return env
}

type stored struct {
	Body       []byte
	Token      contract.Token
	bodyPath   string
	bodyLength uint64
	bodyDigest [32]byte
}

type memoryStore struct {
	mu                  sync.Mutex
	desc                contract.Descriptor
	configuration       contract.StoreConfiguration
	objects             map[string]stored
	reads, creates, cas int
	casConditions       []contract.Token
	casBodies           [][]byte
	generation          int
	createMode, casMode string
	readHook            func(string, contract.ReadResult) contract.ReadResult
	late                func() error
	fileBodies          *fixtureBodyFiles
	writerWrites        *[]generatedWriterWrite
}

type admittedMemoryStoreProvider interface {
	admittedMemoryStore() *memoryStore
}

func (m *memoryStore) admittedMemoryStore() *memoryStore { return m }

func underlyingAdmittedMemoryStore(store contract.Store) (*memoryStore, bool) {
	provider, ok := store.(admittedMemoryStoreProvider)
	if !ok {
		return nil, false
	}
	memory := provider.admittedMemoryStore()
	return memory, memory != nil
}

func requireAdmittedMemoryStore(t testing.TB, store contract.Store) *memoryStore {
	t.Helper()
	memory, ok := underlyingAdmittedMemoryStore(store)
	if !ok {
		t.Fatal("test requires the admitted memory store")
	}
	return memory
}

func (m *memoryStore) configure(t testing.TB, family contract.Family, domain contract.ID) {
	t.Helper()
	configuration := contract.StoreConfiguration{Provider: family, ConstructionProfile: contract.StoreConstructionProfile,
		DomainID: domain, Bucket: "fixture-bucket", PrefixBeforeHEAD: m.desc.Prefix}
	switch family {
	case contract.AWS:
		configuration.Region, configuration.ExpectedOwner = "us-east-1", "123456789012"
	case contract.GCP:
		configuration.Region = "australia-southeast1"
	}
	identity, err := contract.StoreConfigurationID(configuration)
	if err != nil {
		t.Fatal("invalid fixture Store configuration", err)
	}
	m.configuration = configuration
	m.desc.Family, m.desc.Identity = family, identity
}

func fixtureStoreConfiguration(store contract.Store) contract.StoreConfiguration {
	if source, ok := store.(contract.StoreConfigurationSource); ok {
		return source.StoreConfiguration()
	}
	return contract.StoreConfiguration{}
}

func (m *memoryStore) StoreConfiguration() contract.StoreConfiguration { return m.configuration }

func (m *memoryStore) Descriptor() contract.Descriptor { return m.desc }

func (m *memoryStore) Read(_ context.Context, key string, max uint32) contract.ReadResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reads++
	v, ok := m.objects[key]
	r := contract.ReadResult{Status: contract.ReadMissing}
	if ok {
		r = readFixtureStoredBody(v, max)
	}
	if m.readHook != nil {
		r = m.readHook(key, r)
	}
	return r
}

func (m *memoryStore) put(key string, body []byte) {
	m.putValue(key, stored{Body: bytes.Clone(body)})
}

func (m *memoryStore) putValue(key string, value stored) {
	before := m.objects[key].Token
	m.generation++
	tokenValue := strconv.Itoa(m.generation)
	if m.desc.Family == contract.AWS {
		tokenValue = `"` + tokenValue + `"`
	}
	value.Token = contract.Token{Family: m.desc.Family, Value: tokenValue}
	m.objects[key] = value
	if m.writerWrites != nil {
		*m.writerWrites = append(*m.writerWrites, generatedWriterWrite{Key: key, Condition: before, Object: generatedWriterObjectFacts(value)})
	}
}

func (m *memoryStore) Create(_ context.Context, key string, body []byte) contract.WriteResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.creates++
	if _, ok := m.objects[key]; ok {
		return contract.WriteResult{Status: contract.WritePrecondition}
	}
	switch m.createMode {
	case "lost-before":
		return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport, NotSent: true}
	case "delayed":
		frozen := bytes.Clone(body)
		m.late = func() error {
			m.mu.Lock()
			defer m.mu.Unlock()
			if _, exists := m.objects[key]; !exists {
				return m.putSelected(key, frozen)
			}
			return nil
		}
		return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
	case "conflict":
		if err := m.putSelected(key, []byte("different bytes")); err != nil {
			return fixtureBodyWriteFailure()
		}
		return contract.WriteResult{Status: contract.WritePrecondition}
	case "lost-after":
		if err := m.putSelected(key, body); err != nil {
			return fixtureBodyWriteFailure()
		}
		return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
	}
	if err := m.putSelected(key, body); err != nil {
		return fixtureBodyWriteFailure()
	}
	return contract.WriteResult{Status: contract.WriteAcknowledged}
}

func (m *memoryStore) CreateHead(ctx context.Context, q contract.HeadCreateRequest) contract.WriteResult {
	if !q.Valid() || q.Descriptor() != m.desc {
		return contract.WriteResult{Status: contract.WriteRefused}
	}
	return m.Create(ctx, m.desc.HeadKey, q.Body())
}

func (m *memoryStore) CompareAndSwap(_ context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cas++
	m.casConditions = append(m.casConditions, token)
	m.casBodies = append(m.casBodies, bytes.Clone(body))
	if m.objects[key].Token != token {
		return contract.WriteResult{Status: contract.WritePrecondition}
	}
	switch m.casMode {
	case "lost-before":
		return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport, NotSent: true}
	case "delayed":
		frozen := bytes.Clone(body)
		m.late = func() error {
			m.mu.Lock()
			defer m.mu.Unlock()
			if m.objects[key].Token == token {
				return m.putSelected(key, frozen)
			}
			return nil
		}
		return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
	case "lost-after":
		if err := m.putSelected(key, body); err != nil {
			return fixtureBodyWriteFailure()
		}
		return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
	case "ack-before":
		return contract.WriteResult{Status: contract.WriteAcknowledged}
	case "conflict":
		return contract.WriteResult{Status: contract.WriteConflict}
	case "refused":
		return contract.WriteResult{Status: contract.WriteRefused}
	}
	if err := m.putSelected(key, body); err != nil {
		return fixtureBodyWriteFailure()
	}
	return contract.WriteResult{Status: contract.WriteAcknowledged}
}

type fixtureTrust struct {
	*testtrust.Signer
	signs   int
	corrupt bool
}

type admittedFixtureTrustProvider interface {
	admittedFixtureTrust() *fixtureTrust
}

func (t *fixtureTrust) admittedFixtureTrust() *fixtureTrust { return t }

func underlyingAdmittedFixtureTrust(trust contract.Trust) (*fixtureTrust, bool) {
	provider, ok := trust.(admittedFixtureTrustProvider)
	if !ok {
		return nil, false
	}
	fixture := provider.admittedFixtureTrust()
	return fixture, fixture != nil
}

func (t *fixtureTrust) Sign(ctx context.Context, r contract.SignRequest) contract.SignResult {
	t.signs++
	t.SetCorrupt(t.corrupt)
	return t.Signer.Sign(ctx, r)
}

func testID(s string) contract.ID { return contract.Hash([]byte("fixture/" + s)) }

type fixture struct {
	store     *memoryStore
	trust     *fixtureTrust
	admission OpenContext
	session   *StateSession
}

func newFixture(t *testing.T, count int, fragmented bool, valueSize int) *fixture {
	sizes := make([]int, count)
	for i := range sizes {
		sizes[i] = valueSize
	}
	return newSizedFixture(t, sizes, fragmented)
}

func newSizedFixture(t *testing.T, sizes []int, fragmented bool) *fixture {
	t.Helper()
	env := memoryScenarioEnvironment(t)
	store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
	f := newEnvironmentFixture(t, context.Background(), env, sizes, fragmented)
	trust.signs = 0
	store.reads, store.creates, store.cas = 0, 0, 0
	var result Result
	f.session, result = Open(context.Background(), f.admission, store)
	if f.session == nil || result.Outcome != ObservedCurrent {
		t.Fatal("fixture cold authentication", result)
	}
	return &fixture{store: store, trust: trust, admission: f.admission, session: f.session}
}

type fixtureEnvironment struct {
	Context                context.Context
	ReplacementActors      func(testing.TB, context.Context, *StateSession, uint8, uint8, uint8) successionActors
	CurrentConsume         func(testing.TB, context.Context, *StateSession, contract.ConsumerSelection, uint8) custody.ConsumerCheck
	PrivateWitness         func(testing.TB, *StateSession, uint8)
	FreshCurrent           func(testing.TB, OpenContext, *StateSession)
	FreshGeneratedRecord   func(testing.TB, *StateSession, contract.ID, []byte) *StateSession
	FreshGeneratedFinal    func(testing.TB, *StateSession) *StateSession
	GeneratedProcess       *generatedProcessFixture
	AuthorityOperator      func(testing.TB, context.Context, fixtureEnvironment, string)
	ConfigurationRecovery  func(testing.TB, context.Context, fixtureEnvironment, string)
	LivePublication        func(testing.TB, context.Context, fixtureEnvironment, string)
	GenesisIDs             genesisIDs
	Store                  contract.Store
	Trust                  contract.Trust
	Domain                 contract.ID
	Composition            contract.ID
	PublicKey              []byte
	SigningSelector        string
	Bindings               []contract.BindingTableRow
	Crypto                 contract.Crypto
	AdmitInit              func(contract.CryptoQualifyInitKeysRequest, contract.ID, time.Time) error
	RetireInit             func()
	Custody                *custody.Fixture
	ReaderConsume          func(contract.ConsumerSelection, uint8) custody.ConsumerCheck
	ReaderSuccessor        contract.KMSBinding
	ReaderSuccessorConsume func(contract.ConsumerSelection, uint8) custody.ConsumerCheck
	ReserveCustody         func(string, int) bool
	Recovery               contract.QualifyingTrust
	RecoveryPublicKey      []byte
	RecoverySelector       string
	Put                    func(context.Context, string, []byte) error
	Delete                 func(context.Context, string) error
	FreshOpen              func(testing.TB, stateImage)
	RecoveryHandoff        func(*StateSession, []ApplyEntryInput) error
	InjectBeforeSend       func()
	ReportTransportFailure func(Result)
	ControlDelayedCAS      bool
	Phase                  func(string)
	EndPhase               func(string)
}

// generatedProcessFixture supplies one explicit process and private fixture
// accounting to shared generated scenarios. The hooks cannot supply Product
// evidence: scenarios still inspect the selected state and returned SafeFacts.
type generatedProcessFixture struct {
	Artifact       string
	Implementation contract.GeneratorImplementation
	Intent         []byte
	RequestDigest  contract.ID
	Configure      func(testing.TB, string, contract.GeneratorResultExpectation) custody.GeneratedProcessConfig
	BeforeCreate   func(contract.ID) error
	AfterCreate    func(contract.ID, contract.GeneratorSafeFacts) error
	BeforeDelete   func(contract.ID, contract.ID) error
	AfterDelete    func(contract.ID, contract.ID, contract.GeneratorSafeFacts) error
	ObserveOutcome func(custody.GeneratedProducerOutcome)
	// SelectFailure binds the exact private return, or a proved pre-invocation
	// boundary, to the next failing assertion. It supplies no Product evidence.
	SelectFailure func(string, contract.ID, contract.ID, contract.ID, contract.CryptoResultCode, bool)
}

func (env fixtureEnvironment) operationContext() context.Context {
	if env.Context != nil {
		return env.Context
	}
	return context.Background()
}

func (env fixtureEnvironment) readerConsume(selection contract.ConsumerSelection, choice uint8) custody.ConsumerCheck {
	if env.ReaderConsume != nil {
		return env.ReaderConsume(selection, choice)
	}
	return env.Custody.Consume(env.operationContext(), selection, choice)
}

func (env fixtureEnvironment) readerSuccessorConsume(selection contract.ConsumerSelection, choice uint8) custody.ConsumerCheck {
	if env.ReaderSuccessorConsume != nil {
		return env.ReaderSuccessorConsume(selection, choice)
	}
	return env.Custody.Consume(env.operationContext(), selection, choice)
}

type environmentFixture struct {
	admission OpenContext
	session   *StateSession
}

func fixtureID(domain contract.ID, label string) contract.ID {
	name := append([]byte("fixture/"), domain[:]...)
	name = append(name, '/')
	return contract.Hash(append(name, label...))
}

func fixtureControlIncarnation(domain, trust contract.ID) contract.ID {
	b := append([]byte("fixture/control-incarnation/"), domain[:]...)
	return contract.Hash(append(b, trust[:]...))
}

func fixtureDescriptor(env fixtureEnvironment) (contract.GenesisDescriptorCore, error) {
	if env.Domain != env.GenesisIDs.Domain {
		return contract.GenesisDescriptorCore{}, contract.ErrSubject
	}
	store := env.Store.Descriptor()
	a := openAdmission{domain: env.Domain, trust: env.Trust.Identity(), controlIncarnation: fixtureControlIncarnation(env.Domain, env.Trust.Identity()), interpretation: contract.InterpretationID(), store: store, epoch: 1, publicKey: env.PublicKey}
	d := contract.GenesisDescriptorCore{InitID: env.GenesisIDs.Init, DomainID: env.Domain, DescriptorArtifactID: env.GenesisIDs.DescriptorArtifact, ManifestArtifactID: env.GenesisIDs.ManifestArtifact, Provider: store.Family, StoreID: store.Identity, CoordinateID: store.Coordinate, NonBodyID: store.NonBody, TrustID: env.Trust.Identity(), InterpretationID: contract.InterpretationID(), TrustInterpretationID: contract.TrustInterpretationID(), CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), AuthorityRecipientID: fixtureID(env.Domain, "recipient"), NormalSigning: contract.PublicSigningBinding{Schema: contract.CanonicalSchema, Role: 1, Provider: store.Family, SigningProfile: 1, BindingID: fixtureID(env.Domain, "normal-signing-binding"), KeySelector: env.SigningSelector, SPKI: bytes.Clone(env.PublicKey), Fingerprint: contract.Hash(env.PublicKey), Binding: binding(a)}}
	for _, r := range env.Bindings {
		b := r.Binding
		b.SPKI = bytes.Clone(b.SPKI)
		if r.SubjectKind == 1 {
			d.Recipients = append(d.Recipients, contract.RecipientRecord{RecipientID: r.SubjectID, Status: contract.CurrentRecipient, CurrentBinding: &b})
		} else {
			if env.Recovery == nil {
				return d, contract.ErrSubject
			}
			ra := a
			ra.trust = env.Recovery.Identity()
			ra.controlIncarnation = fixtureControlIncarnation(env.Domain, ra.trust)
			ra.publicKey = env.RecoveryPublicKey
			d.Recovery = &contract.RecoveryBindings{RoleID: r.SubjectID, KMS: b, Signing: contract.PublicSigningBinding{Schema: contract.CanonicalSchema, Role: 2, Provider: store.Family, SigningProfile: 1, BindingID: fixtureID(env.Domain, "recovery-signing-binding"), KeySelector: env.RecoverySelector, SPKI: bytes.Clone(env.RecoveryPublicKey), Fingerprint: contract.Hash(env.RecoveryPublicKey), Binding: binding(ra)}}
		}
	}
	_, err := contract.GenesisDescriptorCoreLength(d)
	return d, err
}

// Private test callers issue a fresh EndWork identity for each invocation.
// Production admission supplies its own identity and never falls back here.
func issueTestEndWorkInvocation(t testing.TB, s *StateSession) {
	t.Helper()
	if s == nil {
		t.Fatal("missing private EndWork session")
	}
	used := s.signerOnlyClosureIDs()
	if used == nil {
		t.Fatal("private EndWork selected IDs unavailable")
	}
	for attempt := 0; attempt < 8; attempt++ {
		if _, err := rand.Read(s.admission.endWorkInvocation[:]); err != nil {
			t.Fatal("could not issue private EndWork invocation", err)
		}
		if !s.admission.endWorkInvocation.IsZero() &&
			!used[s.admission.endWorkInvocation] {
			return
		}
	}
	t.Fatal("could not issue distinct private EndWork invocation")
}

func prepareTestEndSelectedWork(t testing.TB, s *StateSession, ctx context.Context,
	groupID contract.ID, trust contract.Trust) (*Candidate, Result) {
	t.Helper()
	issueTestEndWorkInvocation(t, s)
	return s.prepareEndSelectedWork(ctx, groupID, trust)
}

func fixtureAdmission(env fixtureEnvironment) OpenContext {
	d, err := fixtureDescriptor(env)
	if err != nil {
		return OpenContext{}
	}
	body, err := contract.EncodeGenesisDescriptorCore(d)
	if err != nil {
		return OpenContext{}
	}
	composition := env.Composition
	if composition.IsZero() {
		composition = fixtureID(env.Domain, "composition")
	}
	return OpenContext{admission: &openAdmission{domain: env.Domain, trust: env.Trust.Identity(), controlIncarnation: fixtureControlIncarnation(env.Domain, env.Trust.Identity()), interpretation: contract.InterpretationID(), recipient: fixtureID(env.Domain, "recipient"), composition: composition, store: env.Store.Descriptor(), epoch: 1, publicKey: bytes.Clone(env.PublicKey), descriptor: body, expires: time.Now().Add(time.Hour)}}
}
func persistGenesisArtifact(t testing.TB, dir string, kind uint8, id contract.ID, body []byte) artifactReceipt {
	t.Helper()
	path := filepath.Join(dir, fmt.Sprintf("%x", id))
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	n, err := f.Write(body)
	if err != nil || n != len(body) {
		t.Fatal("artifact write did not complete", err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := directory.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := directory.Close(); err != nil {
		t.Fatal(err)
	}
	f, err = os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	read, err := io.ReadAll(io.LimitReader(f, int64(len(body))+1))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(read, body) {
		t.Fatal("durable artifact readback differs")
	}
	return artifactReceipt{fact: contract.GenesisArtifactFact{Kind: kind, ArtifactID: id, BodyDigest: contract.Hash(read), BodyLength: uint64(len(read)), DurabilityProfile: 1, Outcome: 1}}
}
func fixtureInitAdmission(t testing.TB, env fixtureEnvironment, admitted OpenContext) (InitContext, *genesisPreparation) {
	t.Helper()
	a := admitted.admission
	if a == nil || !a.valid(env.Store) || env.Crypto == nil || env.AdmitInit == nil {
		t.Fatal("incomplete internal genesis environment")
	}
	d, ok := a.domainBasis()
	if !ok {
		t.Fatal("invalid admitted domain basis")
	}
	dir := t.TempDir()
	descriptor := persistGenesisArtifact(t, dir, 1, d.DescriptorArtifactID, a.descriptor)
	deadline := time.Now().Add(30 * time.Minute)
	p, err := planGenesisScope(*a, contract.Hash(a.descriptor), uint64(deadline.UnixNano()))
	if err != nil {
		t.Fatalf("plan genesis: %v", err)
	}
	manifest := persistGenesisArtifact(t, dir, 2, d.ManifestArtifactID, p.manifestBytes)
	// The private parent fixes its context from admitted fixture facts and exact
	// durable artifacts. It does not accept an envelope supplied by Core callers.
	bindings, err := d.BindingTable()
	if err != nil {
		t.Fatalf("genesis binding table: %v", err)
	}
	q := contract.CryptoQualifyInitKeysRequest{Context: contract.InitKeyContext{Schema: contract.CryptoSchema, GenesisProfile: 1, AdmissionID: fixtureID(env.Domain, "init-admission"), SessionID: fixtureID(env.Domain, "init-session"), DomainID: env.Domain, CompatibilityID: contract.CompatibilityID(), Expiry: uint64(deadline.UnixNano()), InitID: d.InitID, DescriptorDigest: descriptor.fact.BodyDigest, GenesisPlanDigest: contract.Hash(p.planBytes), RequestDescriptor: contract.DescriptorVector{Digest: contract.Hash(p.requestBytes), Length: uint64(len(p.requestBytes)), Count: 1}}, Bindings: bindings, Probes: append([]contract.InitProbePlanRow(nil), p.plan.Probes...)}
	if err := env.AdmitInit(q, contract.CryptoSupportID(), deadline); err != nil {
		t.Fatalf("admit genesis keys: %v", err)
	}
	return InitContext{admission: &initAdmission{open: admitted, prepared: p, descriptor: descriptor, manifest: manifest, qualification: q, requestID: fixtureID(env.Domain, "init-request"), custodyID: env.Crypto.InstanceID(), custody: env.Crypto, deadline: deadline}}, p
}

func newEnvironmentFixture(t testing.TB, ctx context.Context, env fixtureEnvironment, sizes []int, fragmented bool) *environmentFixture {
	t.Helper()
	return newNamedEnvironmentFixture(t, ctx, env, sizes, fragmented, nil)
}

func newNamedEnvironmentFixture(t testing.TB, ctx context.Context, env fixtureEnvironment, sizes []int, fragmented bool, names []string) *environmentFixture {
	t.Helper()
	if names != nil && len(names) != len(sizes) {
		t.Fatal("fixture name and value counts differ")
	}
	admitted := fixtureAdmission(env)
	init, _ := fixtureInitAdmission(t, env, admitted)
	normal, ok := env.Trust.(contract.QualifyingTrust)
	if !ok {
		t.Fatal("fixture lacks typed signing qualification")
	}
	if env.ReserveCustody != nil && !env.ReserveCustody("init", len(env.Bindings)) {
		t.Fatal("init custody budget exhausted")
	}
	session, res := Initialize(ctx, init, env.Store, normal, env.Recovery, env.Crypto)
	if session == nil || res.Outcome != ObservedCurrent {
		t.Fatalf("fixture genesis: %+v", res)
	}
	if env.RetireInit == nil {
		t.Fatal("fixture has no private init retirement handoff")
	}
	env.RetireInit()
	apply := func(desiredEntries []ApplyEntryInput) {
		t.Helper()
		parent := admitSuppliedComparison(t, session, env.Custody, desiredEntries)
		comparison, res := session.Compare(context.Background(), desiredEntries, parent)
		if comparison == nil {
			if res.Outcome == Unchanged {
				return
			}
			t.Fatalf("fixture compare: %+v", res)
		}
		permit := admit(t, session, comparison)
		candidate, res := session.Prepare(ctx, comparison, permit, env.Trust)
		if candidate == nil {
			t.Fatalf("fixture prepare: %+v", res)
		}
		res = session.Select(ctx, candidate)
		if res.Outcome != ObservedCurrent {
			t.Fatalf("fixture select: %+v", res)
		}
		session, res = Open(ctx, admitted, env.Store)
		if session == nil || res.Outcome != ObservedCurrent {
			t.Fatalf("fixture reopen: %+v", res)
		}
	}
	if len(sizes) > 0 {
		desiredEntries := make([]ApplyEntryInput, len(sizes))
		for i, size := range sizes {
			name := fmt.Sprintf("member-%03d", i)
			if names != nil {
				name = names[i]
			}
			desiredEntries[i] = ApplyEntryInput{Name: name, Recipients: []contract.ID{admitted.admission.recipient}, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputBytes: bytes.Repeat([]byte{byte(i)}, size), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
		}
		if !fragmented {
			apply(desiredEntries)
		} else {
			// Four ordinary transitions retain exactly the spread occupied slot set.
			// Every placement follows Core's unchanged lowest-free-slot allocation.
			target := map[uint16]bool{}
			highest := 0
			for i := range sizes {
				slot := (i%32)*16 + i/32
				target[uint16(slot)] = true
				highest = max(highest, slot)
			}
			placeholders := make([]ApplyEntryInput, highest+1)
			for i := range placeholders {
				placeholders[i] = ApplyEntryInput{Name: fmt.Sprintf("fixture-placeholder-%03d", i), Recipients: []contract.ID{admitted.admission.recipient}, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
			}
			apply(placeholders)
			retained := make([]ApplyEntryInput, 0, len(placeholders)-len(desiredEntries))
			for i, v := range placeholders {
				if !target[uint16(i)] {
					retained = append(retained, v)
				}
			}
			apply(retained)
			combined := append(append([]ApplyEntryInput(nil), retained...), desiredEntries...)
			apply(combined)
			apply(desiredEntries)
		}
	}
	return &environmentFixture{admission: admitted, session: session}
}

// Fixture admission is compiled only into Core tests. Production has no such constructor.
func admit(t testing.TB, s *StateSession, c *Comparison) *AdmittedParentTransition {
	t.Helper()
	permit, _ := admitTransition(t, s, c)
	return permit
}

func changed(t testing.TB, s *StateSession, indices ...int) *Comparison {
	t.Helper()
	values := s.currentEntryInputs()
	for _, i := range indices {
		values[i].InputBytes = append(bytes.Clone(values[i].InputBytes), byte(99))
	}
	c, res := s.Compare(context.Background(), values, admitSuppliedComparison(t, s, nil, values))
	if c == nil {
		t.Fatalf("compare: %+v", res)
	}
	return c
}

func prepare(t testing.TB, f *fixture, c *Comparison) *Candidate {
	t.Helper()
	candidate, res := f.session.Prepare(context.Background(), c, admit(t, f.session, c), f.trust)
	if candidate == nil {
		t.Fatalf("prepare: %+v", res)
	}
	return candidate
}

func (s *StateSession) currentEntryInputs() []ApplyEntryInput {
	desiredEntries := make([]ApplyEntryInput, 0, len(s.root.Names))
	for _, entry := range s.root.Names {
		m := s.valueEntry(entry.Slot)
		desiredEntries = append(desiredEntries, ApplyEntryInput{Name: m.Name, Recipients: slices.Clone(m.Recipients), ValueSource: m.ValueSource, ConfidentialityClass: m.ConfidentialityClass, InputBytes: bytes.Clone(m.ValueBytes), InputEncoding: m.InputEncoding, OutputEncoding: m.OutputEncoding})
	}
	return desiredEntries
}

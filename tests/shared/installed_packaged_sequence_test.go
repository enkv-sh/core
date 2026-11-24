package core

import (
	"bytes"
	"context"

	"debug/buildinfo"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"enkv.sh/compositions/generatorhost"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
	pluginartifact "enkv.sh/sdk/artifact"
)

type packagedSequenceWrite struct {
	Identity contract.StoreObjectIdentity
	Key      string
	Length   uint64
	Digest   contract.ID
	Status   contract.WriteStatus
}

type packagedSequenceEpisode struct {
	Sign                                                         packagedSequenceSign
	ImmutableObjects, ImmutableBytes, ResultObjects, ResultBytes uint64
	ResultSends, ResultWriteBytes                                uint64
}

type packagedSequenceSign struct {
	Purpose contract.Purpose
	Digest  contract.ID
	Writes  int
}

type packagedSequenceCommand struct {
	Label                                    string
	WriteStart, WriteEnd, SignStart, SignEnd int
	Reads                                    uint64
	QualificationCalls, DecryptCalls         int
}

type packagedSequenceHead struct {
	body  []byte
	token contract.Token
}

type packagedSequenceShape struct {
	Revision                                                                                                        contract.ID
	SignDigest                                                                                                      contract.ID
	ChildCount, ChildBytes, Values, GeneratedValues, OutputSlices, Fragments, Slices                                uint64
	Parents, Attempts, Duties, Hazards, Vectors, HistoryCarriers, GraphRows, CreateLineages, SourceUses, ValuePlans uint64
}

func (s packagedSequenceShape) selectedReadBound() uint64 {
	return s.ChildCount + 2 + s.OutputSlices + 5*s.Fragments + 2*s.Slices + s.Values + s.Parents*(3+s.CreateLineages+s.ValuePlans) + 2*s.Attempts + 2*s.Duties + 2*s.Hazards + 4*s.Vectors
}

type packagedSequenceObservation struct {
	genesis packagedSequenceHead
	mu      sync.Mutex
	domain  contract.ID
	t       testing.TB
	writes  []packagedSequenceWrite
	signs   []packagedSequenceSign
	reads   uint64
	heads   []packagedSequenceHead
}

type packagedSequenceStore struct {
	contract.Store
	observation *packagedSequenceObservation
}

func (s packagedSequenceStore) StoreConfiguration() contract.StoreConfiguration {
	return fixtureStoreConfiguration(s.Store)
}
func (s packagedSequenceStore) admittedMemoryStore() *memoryStore {
	store, _ := underlyingAdmittedMemoryStore(s.Store)
	return store
}
func (s packagedSequenceStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	s.observation.mu.Lock()
	s.observation.reads++
	s.observation.mu.Unlock()
	return s.Store.Read(ctx, key, limit)
}
func (s packagedSequenceStore) Create(ctx context.Context, key string, body []byte) contract.WriteResult {
	identity, err := contract.ParseStoreObjectKey(s.Store.Descriptor().Prefix, s.observation.domain, key)
	if err != nil || len(body) > int(contract.StoreObjectLimit(identity)) {
		s.observation.t.Fatal("controlled write is outside the exact typed Store domain", err)
	}
	result := s.Store.Create(ctx, key, body)
	s.observation.mu.Lock()
	if len(s.observation.writes) == cap(s.observation.writes) {
		s.observation.mu.Unlock()
		s.observation.t.Fatal("controlled Store observation exceeded its fixed capacity")
	}
	s.observation.writes = append(s.observation.writes, packagedSequenceWrite{Identity: identity, Key: key, Length: uint64(len(body)), Digest: contract.Hash(body), Status: result.Status})
	s.observation.mu.Unlock()
	return result
}

func (s packagedSequenceStore) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	result := s.Store.CompareAndSwap(ctx, key, token, body)
	store := s.admittedMemoryStore()
	store.mu.Lock()
	selected := store.objects[key]
	matches := bytes.Equal(selected.Body, body)
	selectedToken := selected.Token
	store.mu.Unlock()
	if matches {
		s.observation.mu.Lock()
		if len(s.observation.heads) == cap(s.observation.heads) || len(body) > contract.MaxHeadLength {
			s.observation.mu.Unlock()
			s.observation.t.Fatal("controlled selected HEAD observation exceeded its fixed capacity")
		}
		s.observation.heads = append(s.observation.heads, packagedSequenceHead{body: bytes.Clone(body), token: selectedToken})
		s.observation.mu.Unlock()
	}
	return result
}

type packagedSequenceHeadStore struct {
	contract.Store
	head packagedSequenceHead
}

func (s packagedSequenceHeadStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	if key != s.Store.Descriptor().HeadKey {
		return s.Store.Read(ctx, key, limit)
	}
	if len(s.head.body) > int(limit) {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonLimit}
	}
	return contract.ReadResult{Status: contract.ReadOK, Body: bytes.Clone(s.head.body), Token: s.head.token}
}
func (s packagedSequenceHeadStore) StoreConfiguration() contract.StoreConfiguration {
	return fixtureStoreConfiguration(s.Store)
}

type packagedSequenceTrust struct {
	contract.QualifyingTrust
	observation *packagedSequenceObservation
}

func (s packagedSequenceTrust) admittedFixtureTrust() *fixtureTrust {
	trust, _ := underlyingAdmittedFixtureTrust(s.QualifyingTrust)
	return trust
}
func (s packagedSequenceTrust) Sign(ctx context.Context, request contract.SignRequest) contract.SignResult {
	s.observation.mu.Lock()
	if len(s.observation.signs) == cap(s.observation.signs) {
		s.observation.mu.Unlock()
		s.observation.t.Fatal("controlled Trust observation exceeded its fixed capacity")
	}
	s.observation.signs = append(s.observation.signs, packagedSequenceSign{Purpose: request.Purpose(), Digest: request.Digest(), Writes: len(s.observation.writes)})
	s.observation.mu.Unlock()
	return s.QualifyingTrust.Sign(ctx, request)
}

func packagedSequenceProcess(t testing.TB, origin, label string) *generatedProcessFixture {
	t.Helper()
	artifact := filepath.Join(t.TempDir(), "generator-"+label)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-tags=enkv_cloudflare_testartifact",
		"-ldflags=-X=enkv.sh/plugins/generators/cloudflare-account-token/internal/cloudflare.unqualifiedTestArtifactOrigin="+origin+" -buildid=enkv-packaged-sequence-"+label,
		"-o", artifact, "./cmd/enkv-generator-cloudflare-test")
	root, directory := hermeticCloudflarePluginDirectory(t)
	command.Dir = directory
	command.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local", "GOFLAGS=-trimpath")
	prepareNativeModule(t, root, command, artifact+".mod")
	before := captureHermeticGeneratorBuildInputs(t, command)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("controlled packaged generator build: %v\n%s", err, output)
	}
	if err := os.Chmod(artifact, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(filepath.Dir(artifact), ".enkv-generator-staging"), 0700); err != nil {
		t.Fatal(err)
	}
	info, err := buildinfo.ReadFile(artifact)
	if err != nil || info.GoVersion != "go1.27.3" {
		t.Fatal("packaged generator compiler", err)
	}
	descriptorBytes, err := os.ReadFile(filepath.Join(directory, "cmd/enkv-generator-cloudflare-test/plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := pluginartifact.DecodeDescriptor(descriptorBytes)
	if err != nil {
		t.Fatal(err)
	}
	metadata, dependency := hermeticGeneratorMetadata(t, command, artifact, descriptor, before)
	installed, err := generatorhost.NewInstallation(metadata, dependency)
	if err != nil {
		t.Fatal(err)
	}
	row := installed.Artifact()
	encoded, err := pluginartifact.EncodeMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	for suffix, body := range map[string][]byte{".metadata.json": encoded, ".dependencies.bin": dependency} {
		if err := os.WriteFile(artifact+suffix, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	intent, request := hermeticCloudflareIntent()
	return &generatedProcessFixture{Artifact: artifact, Implementation: row, Intent: intent, RequestDigest: hermeticCloudflareHTTPRequestDigest(request),
		Configure: func(tb testing.TB, executable string, expected contract.GeneratorResultExpectation) custody.GeneratedProcessConfig {
			return hermeticCloudflareConfig(tb, executable, origin, row, expected)
		}}
}

func packagedSequenceCallbacks(t testing.TB, f installedApplyTestFixture, current, first, second *generatedProcessFixture, entered *[]contract.ID) *GeneratedApplyInstallation {
	t.Helper()
	callbacks := installedGeneratedRetirementCallbacks(t, f, current)
	selectProcess := func(row contract.GeneratorImplementation) (*generatedProcessFixture, error) {
		for _, process := range []*generatedProcessFixture{first, second} {
			if reflect.DeepEqual(row, process.Implementation) {
				return process, nil
			}
		}
		return nil, contract.ErrRecord
	}
	callbacks.ResolveImplementation = func(request GeneratedImplementationRequest) (contract.GeneratorImplementation, error) {
		row := current.Implementation
		if request.Retained != nil {
			found := false
			for _, process := range []*generatedProcessFixture{first, second} {
				candidate := process.Implementation
				retained := request.Retained
				result, err := contract.GeneratedResultContractID(candidate, retained.Action, retained.CompletionClass, retained.MaxSecret, retained.MaxFacts, retained.InputEncoding)
				if err == nil && candidate.ExecutorID == retained.ExecutorID && candidate.CredentialRouteID == retained.CredentialRouteID && candidate.DescriptorID == retained.DescriptorID && result == retained.ResultContractID {
					if found {
						return row, contract.ErrRecord
					}
					row, found = candidate, true
				}
			}
			if !found {
				return row, contract.ErrRecord
			}
		}
		if request.ConfigContractID != row.ConfigContractID || request.ResourceContractID != hermeticCloudflareResourceContractID() || request.LifecycleMode != contract.GeneratorLifecycleManaged {
			return row, contract.ErrRecord
		}
		return row, nil
	}
	callbacks.CheckRetirementCompatibility = func(ctx context.Context, row contract.GeneratorImplementation, intent []byte, facts contract.GeneratorSafeFacts, completion uint8) ([]byte, []byte, error) {
		process, err := selectProcess(row)
		if err != nil {
			return nil, nil, err
		}
		return hermeticCloudflareRetirementExchange(ctx, process.Artifact, row, intent, facts, completion)
	}
	callbacks.RequestDigest = func(ctx context.Context, row contract.GeneratorImplementation, action uint8, intent []byte, target *contract.GeneratorTarget) (contract.ID, error) {
		process, err := selectProcess(row)
		if err != nil {
			return contract.ID{}, err
		}
		return installedGeneratedRetirementCallbacks(t, f, process).RequestDigest(ctx, row, action, intent, target)
	}
	callbacks.AdmitProducer = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedProducerInput, row contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
		process, err := selectProcess(row)
		if err != nil {
			return nil, err
		}
		owner, err := installedGeneratedRetirementCallbacks(t, f, process).AdmitProducer(ctx, q, control, input, row, deadline)
		if err != nil {
			return nil, err
		}
		invoke := owner.InvokeProducer
		owner.InvokeProducer = func(ctx context.Context, transmission, result contract.ID) contract.GeneratedProducerResult {
			*entered = append(*entered, row.ExecutorID)
			return invoke(ctx, transmission, result)
		}
		return owner, nil
	}
	return callbacks
}

// full_only: false
func TestInstalledPackagedSequenceCandidateCharges(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	f, observation, commands := packagedGeneratedSequence(t, ctx)
	packagedSequenceEvidence(t, ctx, f, observation, commands, 6)
}

func packagedGeneratedSequence(t *testing.T, ctx context.Context) (installedApplyTestFixture, *packagedSequenceObservation, []packagedSequenceCommand) {
	return packagedGeneratedSequenceWithRecovery(t, ctx, nil)
}

// full_only: false
func TestInstalledRetirementReleasesInboxAfterLastSupportOwner(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	history := make(map[string]contract.ReadResult)
	f, _, _ := packagedGeneratedSequenceWithHandoff(t, ctx, false, nil, history)
	if len(history) != 3 || f.selected.root.Generated.PendingReleases != 0 {
		t.Fatal("retirements left a temporary result after the final handoff")
	}
	for key, original := range history {
		if f.env.Store.Read(ctx, key, uint32(len(original.Body))).Status != contract.ReadMissing {
			t.Fatal("released result remains in the Store")
		}
	}
}

func packagedGeneratedSequenceWithRecovery(t *testing.T, ctx context.Context, fault *packagedRecoveryCase) (installedApplyTestFixture, *packagedSequenceObservation, []packagedSequenceCommand) {
	return packagedGeneratedSequenceWithHandoff(t, ctx, false, fault, nil)
}

func packagedGeneratedSequenceWithHandoff(t *testing.T, ctx context.Context, recovery bool, fault *packagedRecoveryCase, history map[string]contract.ReadResult) (installedApplyTestFixture, *packagedSequenceObservation, []packagedSequenceCommand) {
	var lock sync.Mutex
	creates := 0
	var deletes []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lock.Lock()
		defer lock.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPost:
			creates++
			if fault.reply(t, w, r.Method, creates) {
				return
			}
			if _, err := fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":{"id":"%032x","value":"%s","status":"active","name":"generated","policies":[{"effect":"allow","permission_groups":[{"id":"%s"}],"resources":{"com.cloudflare.api.account.%s":"*"}}]}}`, creates, hermeticCloudflareSecret, hermeticCloudflarePermission, hermeticCloudflareAccount); err != nil {
				t.Error(err)
			}
		case http.MethodDelete:
			token := path.Base(r.URL.Path)
			deletes = append(deletes, token)
			if fault.reply(t, w, r.Method, 0) {
				return
			}
			if _, err := fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":{"id":"%s"}}`, token); err != nil {
				t.Error(err)
			}
		default:
			t.Error("unexpected packaged generator method")
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	first := packagedSequenceProcess(t, server.URL+"/client/v4", "A")
	second := packagedSequenceProcess(t, server.URL+"/client/v4", "B")
	if first.Implementation.ExecutorID == second.Implementation.ExecutorID || first.Implementation.ConfigContractID != second.Implementation.ConfigContractID || first.Implementation.ProtocolID != second.Implementation.ProtocolID {
		t.Fatal("independent compatible process pair differs")
	}
	f := newInstalledApplyTestFixture(t, ctx, contract.AWS, recovery)
	if len(f.selected.registry()) != 2 {
		t.Fatal("fixed sequence requires two initialized recipients")
	}
	observation := &packagedSequenceObservation{t: t, domain: f.env.Domain, writes: make([]packagedSequenceWrite, 0, 4096), signs: make([]packagedSequenceSign, 0, 128), heads: make([]packagedSequenceHead, 0, 128)}
	observation.genesis = packagedSequenceHead{bytes.Clone(f.selected.body), f.selected.token}
	f.env.Store = packagedSequenceStore{Store: f.env.Store, observation: observation}
	f.env.Trust = packagedSequenceTrust{QualifyingTrust: f.env.Trust.(contract.QualifyingTrust), observation: observation}
	var commands []packagedSequenceCommand
	observe := func(label string) func() {
		public, private := f.keys.Calls()
		startWrite, startSign, startRead := len(observation.writes), len(observation.signs), observation.reads
		return func() {
			afterPublic, afterPrivate := f.keys.Calls()
			commands = append(commands, packagedSequenceCommand{Label: label, WriteStart: startWrite, WriteEnd: len(observation.writes), SignStart: startSign, SignEnd: len(observation.signs), Reads: observation.reads - startRead, QualificationCalls: afterPublic - public, DecryptCalls: afterPrivate - private})
		}
	}
	current := first
	var entered []contract.ID
	readers := []contract.ID{f.selected.registry()[0].RecipientID, f.selected.registry()[1].RecipientID}
	slices.SortFunc(readers, compareGeneratedIDs)
	meta := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged,
		RetirementMode: contract.GeneratedRetirementManual, ConfigContractID: first.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(),
		CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(first.Intent)}
	input := []ApplyEntryInput{{Name: "generated", InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: readers, Generated: &meta}}
	apply := func(label string, wantPurposes []contract.GeneratorAuthorityPurpose, wantSigns int) *StateSession {
		t.Helper()
		store := requireAdmittedMemoryStore(t, f.env.Store)
		startCAS, startSigns := len(store.casBodies), len(observation.signs)
		f.env.GeneratedProcess = current
		selected := f.open(t, ctx)
		firstHead, startEntered := len(observation.heads), len(entered)
		recovery := fault != nil && fault.phase == label
		lock.Lock()
		startCreates, startDeletes := creates, len(deletes)
		if recovery {
			fault.active = true
		}
		lock.Unlock()
		finishObservation := observe(label)
		engine := installedGeneratedTestEngine(t, ctx, f, selected, input, currentApplyRecipients(selected.registry()), packagedSequenceCallbacks(t, f, current, first, second, &entered))
		result := engine.Apply(ctx, testID("packaged "+label), input)
		engine.Close()
		finishObservation()
		if recovery {
			lock.Lock()
			fault.active = false
			actualCreates, actualDeletes, served := creates-startCreates, len(deletes)-startDeletes, fault.served
			lock.Unlock()
			if served != 1 || actualCreates != served || actualDeletes != 0 || len(entered)-startEntered != served {
				t.Fatal("native recovery create call set differs", served, actualCreates, actualDeletes)
			}
			for _, executor := range entered[startEntered:] {
				if executor != current.Implementation.ExecutorID {
					t.Fatal("native recovery changed its installed executor")
				}
			}
			closed := f.open(t, ctx)
			fault.checkWindow(t, ctx, f, observation, commands[len(commands)-1], firstHead, result)
			fault.checkCreate(t, ctx, f, observation.heads[firstHead:], selected, closed, result, current.Implementation)
			f.selected = closed
			return closed
		}
		wantOutcome := ObservedCurrent
		if len(wantPurposes) == 0 {
			wantOutcome = Unchanged
		}
		if result.Result.Outcome != wantOutcome {
			t.Fatal("packaged sequence apply", label, result.Result)
		}
		var actual []contract.GeneratorAuthorityPurpose
		for _, body := range store.casBodies[startCAS:] {
			head, err := format.DecodeHead(body)
			if err != nil || head.Generator == nil {
				t.Fatal("packaged generated selection", label, err)
			}
			actual = append(actual, head.Generator.Purpose)
		}
		if !slices.Equal(actual, wantPurposes) || len(observation.signs)-startSigns != wantSigns {
			t.Fatal("packaged generated candidate/sign count", label, actual, len(observation.signs)-startSigns)
		}
		return f.open(t, ctx)
	}
	wantCreate := []contract.GeneratorAuthorityPurpose{contract.GeneratorAuthorityReservation, contract.GeneratorAuthorityRecord, contract.GeneratorAuthorityFinalPreparation, contract.GeneratorAuthorityFinal}
	apply("A0", wantCreate, 5)
	if fault != nil && fault.done {
		return f, observation, commands
	}
	meta.Epoch = 1
	selected := apply("A1", wantCreate, 5)
	if fault != nil && fault.done {
		return f, observation, commands
	}
	_, before := observeCurrentValueEntry(t, selected, "generated")
	current = second
	selected = apply("B unchanged A1", nil, 0)
	_, after := observeCurrentValueEntry(t, selected, "generated")
	if !reflect.DeepEqual(before, after) || !slices.Equal(entered, []contract.ID{first.Implementation.ExecutorID, first.Implementation.ExecutorID}) {
		t.Fatal("B selection changed original A1 or executed a producer")
	}
	retire := func(label string, duty contract.ID, wantExecutor contract.ID, wantCurrent *contract.ValueEntry) *StateSession {
		t.Helper()
		store := requireAdmittedMemoryStore(t, f.env.Store)
		startCAS, startSigns, startEntered := len(store.casBodies), len(observation.signs), len(entered)
		f.env.GeneratedProcess = current
		selected := f.open(t, ctx)
		firstHead := len(observation.heads)
		recovery := fault != nil && fault.phase == label
		lock.Lock()
		startCreates, startDeletes := creates, len(deletes)
		if recovery {
			fault.active = true
		}
		lock.Unlock()
		finishObservation := observe(label)
		callbacks := packagedSequenceCallbacks(t, f, current, first, second, &entered)
		engine := installedGeneratedRetirementEngine(t, ctx, f, selected, callbacks)
		result := engine.RetireGenerated(ctx, testID("packaged "+label), GeneratedRetirementRequest{DutyID: duty})
		engine.Close()
		finishObservation()
		if recovery {
			lock.Lock()
			fault.active = false
			actualCreates, actualDeletes, served := creates-startCreates, len(deletes)-startDeletes, fault.served
			lock.Unlock()
			if served != 1 || actualCreates != 0 || actualDeletes != 1 || len(entered)-startEntered != 1 || entered[startEntered] != wantExecutor {
				t.Fatal("native recovery retirement call set differs", served, actualCreates, actualDeletes)
			}
			closed := f.open(t, ctx)
			fault.checkWindow(t, ctx, f, observation, commands[len(commands)-1], firstHead, result)
			fault.checkRetirement(t, ctx, selected, closed, result, duty, wantExecutor)
			f.selected = closed
			return closed
		}
		if result.Result.Outcome != ObservedCurrent || result.Generated == nil || result.Generated.EvidenceCeiling != contract.ReceiptEvidenceAcknowledged || len(result.Generated.Effects) != 1 {
			t.Fatal("packaged sequence retirement", label, result.Result)
		}
		if len(entered)-startEntered != 1 || entered[startEntered] != wantExecutor || len(observation.signs)-startSigns != 4 {
			t.Fatal("retirement did not use the exact retained implementation/signing count", label)
		}
		var actual []contract.GeneratorAuthorityPurpose
		for _, body := range store.casBodies[startCAS:] {
			head, err := format.DecodeHead(body)
			if err != nil || head.Generator == nil {
				t.Fatal("packaged retirement selection", label, err)
			}
			actual = append(actual, head.Generator.Purpose)
		}
		want := []contract.GeneratorAuthorityPurpose{contract.GeneratorAuthorityRetireReserve, contract.GeneratorAuthorityRecord, contract.GeneratorAuthorityRetireClose}
		if !slices.Equal(actual, want) {
			t.Fatal("packaged retirement candidate order", label, actual)
		}
		closed := f.open(t, ctx)
		if closed.head.Generator == nil || closed.head.Generator.Purpose != contract.GeneratorAuthorityRetireClose || closed.root.Generated.Retiring != 0 || !closed.root.Generated.ActiveOwner.IsZero() {
			t.Fatal("retirement immediate authenticated close", label)
		}
		receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
		if err != nil || receipt.OperationKind != contract.OperationRetireGeneratedGeneration || receipt.OperationID != result.OperationID || receipt.EvidenceCeiling != contract.ReceiptEvidenceAcknowledged {
			t.Fatal("retirement exact receipt", label, err)
		}
		packagedSequenceRetirementEvidence(t, ctx, selected, closed, result.OperationID, duty, wantExecutor, receipt, closed.store.Read)
		packagedRetirementSuccessor(t, closed, wantCurrent, receipt)
		if wantCurrent == nil && len(closed.root.Names) != 0 {
			t.Fatal("detached retirement restored entries", label)
		}
		if history != nil {
			store := &generatedCleanupDeleteStore{memoryStore: requireAdmittedMemoryStore(t, f.env.Store), Store: f.env.Store}
			original := mustSelectedGeneratedWork(t, closed).releases[closed.head.Generator.AttemptID]
			key, err := format.GeneratedResultKey(store.desc.Prefix, f.env.Domain, original.release.InboxID)
			if err != nil {
				t.Fatal(err)
			}
			read := store.Read(ctx, key, original.release.ObjectLength)
			if read.Status != contract.ReadOK || contract.Hash(read.Body) != original.release.SelectedHandoffDigest {
				t.Fatal("original retirement result unavailable", label)
			}
			history[key] = read
			closed = generatedLifecycleReopen(t, ctx, closed, store)
			releaseInstalledGeneratedInboxes(ctx, closed, result.OperationID, f.env.Trust, time.Now().Add(time.Minute))
			closed = f.open(t, ctx)
			if store.deletes != 1 || store.deleteKey != key || store.deleteToken != read.Token || closed.head.Generator == nil || closed.head.Generator.Purpose != contract.GeneratorAuthorityInboxRelease {
				t.Fatal("installed handoff did not release the exact retirement inbox", label)
			}
		}
		return closed
	}
	if before.Generated.RetiringDutyPresent != 1 {
		t.Fatal("A1 lacks exact A0 retirement")
	}
	retire("retire A0 under B selection", before.Generated.RetiringDutyID, first.Implementation.ExecutorID, &before)
	if fault != nil && fault.done {
		return f, observation, commands
	}
	meta.Epoch = 2
	selected = apply("B2", wantCreate, 5)
	if fault != nil && fault.done {
		return f, observation, commands
	}
	_, secondCurrent := observeCurrentValueEntry(t, selected, "generated")
	if secondCurrent.Generated.RetiringDutyPresent != 1 || secondCurrent.Generated.Epoch != 2 {
		t.Fatal("B2 did not retain A1 retirement")
	}
	retire("retire A1 with B", secondCurrent.Generated.RetiringDutyID, second.Implementation.ExecutorID, &secondCurrent)
	if fault != nil && fault.done {
		return f, observation, commands
	}
	store := requireAdmittedMemoryStore(t, f.env.Store)
	startCAS, startSigns, startEntered := len(store.casBodies), len(observation.signs), len(entered)
	input = nil
	selected = f.open(t, ctx)
	finishRemoval := observe("remove B2")
	engine := installedGeneratedTestEngine(t, ctx, f, selected, input, currentApplyRecipients(selected.registry()), packagedSequenceCallbacks(t, f, current, first, second, &entered))
	removed := engine.Apply(ctx, testID("packaged remove B2"), input)
	engine.Close()
	finishRemoval()
	if removed.Result.Outcome != ObservedCurrent || len(store.casBodies)-startCAS != 1 || len(observation.signs)-startSigns != 1 || len(entered) != startEntered {
		t.Fatal("B2 removal did not select one ordinary candidate without provider calls", removed.Result)
	}
	selected = f.open(t, ctx)
	if len(selected.root.Names) != 0 || selected.root.Generated.GeneratedCurrent != 0 || selected.root.Generated.Retiring != 1 {
		t.Fatal("B2 removal lost detached retirement")
	}
	work := mustSelectedGeneratedWork(t, selected)
	var detached contract.ID
	for _, row := range work.records {
		if row.Kind != contract.GeneratedDutySupportKind {
			continue
		}
		duty, err := contract.InspectGeneratedDutyRecord(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		if duty.Kind == contract.GeneratedDutyRetirement {
			if !detached.IsZero() || duty.ExecutorID != second.Implementation.ExecutorID || duty.ResourceID != secondCurrent.Generated.ResourceIncarnationID {
				t.Fatal("detached B2 retirement identity differs")
			}
			detached = duty.DutyID
		}
	}
	if detached.IsZero() {
		t.Fatal("B2 detached Duty missing")
	}
	selected = retire("retire detached B2", detached, second.Implementation.ExecutorID, nil)
	if fault != nil && fault.done {
		return f, observation, commands
	}
	if !slices.Equal(entered, []contract.ID{first.Implementation.ExecutorID, first.Implementation.ExecutorID, first.Implementation.ExecutorID, second.Implementation.ExecutorID, second.Implementation.ExecutorID, second.Implementation.ExecutorID}) {
		t.Fatal("complete A/B generated invocation sequence differs")
	}
	lock.Lock()
	actualCreates, actualDeletes := creates, slices.Clone(deletes)
	lock.Unlock()
	if actualCreates != 3 || !slices.Equal(actualDeletes, []string{"00000000000000000000000000000001", "00000000000000000000000000000002", "00000000000000000000000000000003"}) {
		t.Fatal("generated sequence physical effects differ", actualCreates, actualDeletes)
	}
	// Each fresh create opens its seed in Producer, Record and both Final
	// owners, then opens one prepared value. Retirement opens Producer and
	// Record seeds; unchanged and removal each compare one current value.
	wantCommands := []struct {
		label           string
		signs, decrypts int
	}{
		{"A0", 5, 5},
		{"A1", 5, 5},
		{"B unchanged A1", 0, 1},
		{"retire A0 under B selection", 4, 2},
		{"B2", 5, 5},
		{"retire A1 with B", 4, 2},
		{"remove B2", 1, 1},
		{"retire detached B2", 4, 2},
	}
	if len(commands) != len(wantCommands) {
		t.Fatal("generated sequence command set differs")
	}
	for at, want := range wantCommands {
		got := commands[at]
		if got.Label != want.label || got.SignEnd-got.SignStart != want.signs || got.DecryptCalls != want.decrypts || got.QualificationCalls != 0 {
			t.Fatal("generated sequence independent key-call counts differ", want.label, got)
		}
	}
	f.selected = selected
	return f, observation, commands
}

func packagedSequenceCandidateShapes(t *testing.T, ctx context.Context, f installedApplyTestFixture, heads []packagedSequenceHead) []packagedSequenceShape {
	t.Helper()
	store := requireAdmittedMemoryStore(t, f.env.Store)
	var shapes []packagedSequenceShape
	for _, head := range heads {
		// Authenticate each captured intermediate HEAD against its unchanged
		// immutable objects after the command windows have positively joined.
		image, result := Open(ctx, f.admitted, packagedSequenceHeadStore{Store: store, head: head})
		if image == nil || result.Outcome != ObservedCurrent {
			t.Fatal("captured candidate authentication", result)
		}
		shape := packagedSequenceShape{Revision: image.head.Core.Revision, ChildCount: uint64(image.root.ChildCount), ChildBytes: image.root.ChildEncodedBytes,
			Values: uint64(image.root.ValueEntryCount), GeneratedValues: uint64(image.root.Generated.GeneratedCurrent), OutputSlices: uint64(image.root.OutputConfiguration.SliceCount), Fragments: uint64(len(image.root.Generated.Fragments)), Slices: uint64(image.root.Generated.Slices.Count)}
		// Every fixed fixture blob fits one fragment. Relation reads select that
		// BlobID; they cannot reread unrelated directory members.
		blobs := make(map[contract.ID]bool, len(image.root.Generated.Fragments))
		for _, location := range image.root.Generated.Fragments {
			if location.FragmentIndex != 0 || blobs[location.BlobID] {
				t.Fatal("fixed selected blob spans multiple fragments")
			}
			blobs[location.BlobID] = true
		}
		var request contract.SignRequest
		var err error
		if image.head.Generator != nil {
			request, err = contract.NewGeneratorRequest(*image.head.Generator)
		} else if image.head.OutputReserve != nil {
			request, err = contract.NewOutputReserveRequest(*image.head.OutputReserve)
		} else if image.head.OutputClose != nil {
			request, err = contract.NewOutputCloseRequest(*image.head.OutputClose)
		} else {
			request, err = contract.NewLifecycleRequest(image.head.Subject)
		}
		if err != nil {
			t.Fatal("captured candidate signing identity", err)
		}
		shape.SignDigest = request.Digest()
		work := mustSelectedGeneratedWork(t, image)
		if work.parent != nil {
			shape.ValuePlans = uint64(work.parent.ValueEntryPlanCount)
		}
		for _, row := range work.records {
			switch row.Kind {
			case contract.GeneratedParentSupportKind:
				shape.Parents++
			case contract.GeneratedAttemptSupportKind:
				shape.Attempts++
			case contract.GeneratedDutySupportKind:
				shape.Duties++
			case contract.GeneratedHazardSupportKind:
				shape.Hazards++
			case contract.GeneratorVectorSupportKind:
				shape.Vectors++
				carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				if carrier.VectorKind == contract.GeneratorVectorHistory {
					shape.HistoryCarriers++
				}
			}
		}
		for _, graph := range work.bundles {
			shape.GraphRows += uint64(len(graph.Lineages))
			if work.parent != nil && graph.Header.OperationID == work.parent.OperationID {
				shape.CreateLineages += uint64(graph.Header.LineageCount)
				shape.SourceUses += uint64(len(graph.SourceUses))
			}
		}
		shapes = append(shapes, shape)
	}
	return shapes
}

func packagedSequenceEvidence(t *testing.T, ctx context.Context, f installedApplyTestFixture, observation *packagedSequenceObservation, commands []packagedSequenceCommand, wantResults uint64) {
	shapes := packagedSequenceCandidateShapes(t, ctx, f, observation.heads)
	if len(shapes) != len(observation.signs)-int(wantResults) {
		t.Fatal("healthy sequence selected candidate count differs", len(shapes), len(observation.signs))
	}
	type generatedBound struct{ slices, vectors, fragments, objects, bytes, reads uint64 }
	var generatedBounds []generatedBound
	if wantResults == 6 {
		// Source-derived packing includes ReadRequired carriers and released
		// DELETE mappings. Every relation uses its single-fragment blob; five
		// global passes still charge the whole directory. Byte bounds use the
		// larger one-page-per-row derivation, never a measured encoded length.
		// Selecting Final rebinds output into a body-backed row. Its opaque
		// predecessor page cannot be retained, even for unchanged empty output.
		// Removal retains one route carrier; detached retirement copies it for
		// its Parent, then close keeps that copy for the released Attempt.Support.
		// The route is 40+1+20=61 bytes; its framed carrier is 37+120+103+61=321.
		// One page adds 321+75+105+108+7+37+2=655 bytes for one group owner;
		// the copied carrier has two owners before close, adding 657 bytes.
		// Each carrier also adds one object and five reads (one child plus four
		// vector reads), so the last four candidates add 1, 2, 2, 1 carriers.
		generatedBounds = []generatedBound{
			{5, 7, 5, 14, 52106, 89}, {5, 9, 5, 13, 56216, 98}, {6, 10, 6, 14, 62313, 110}, {1, 1, 2, 10, 20577, 30},
			{5, 7, 6, 16, 58391, 99}, {5, 9, 6, 16, 61421, 108}, {6, 10, 7, 17, 67550, 120}, {1, 2, 2, 12, 26772, 38},
			{4, 8, 5, 17, 48007, 96}, {4, 9, 5, 16, 49445, 100}, {2, 2, 3, 12, 31156, 46},
			{6, 8, 7, 17, 69247, 113}, {6, 10, 7, 17, 72277, 122}, {7, 11, 8, 18, 78406, 134}, {2, 3, 3, 15, 37628, 54},
			{5, 9, 6, 17, 58863, 109}, {5, 10, 6, 16, 60301, 113}, {3, 3, 4, 12, 42012, 59}, {3, 5, 4, 11, 45163, 68},
			{6, 12, 7, 17, 67715, 127}, {6, 13, 7, 16, 70233, 131}, {3, 4, 4, 9, 47272, 61},
		}
		if len(shapes) < len(generatedBounds) {
			t.Fatal("generated candidate shape set incomplete")
		}
		for at, expected := range generatedBounds {
			got := shapes[at]
			if got.Slices != expected.slices || got.Vectors != expected.vectors || got.Fragments != expected.fragments || got.OutputSlices != 1 || got.Parents > 1 || got.SourceUses != 0 {
				t.Fatal("generated independent slice/vector/fragment shape differs", at, expected, got)
			}
			reads := got.selectedReadBound()
			if reads > expected.reads {
				t.Fatal("generated selected read shape exceeds independent bound", at, reads, expected.reads, got)
			}
		}
	}
	for _, sign := range observation.signs {
		if !slices.ContainsFunc(shapes, func(shape packagedSequenceShape) bool { return shape.SignDigest == sign.Digest }) {
			t.Fatal("healthy signing call has no authenticated selected candidate")
		}
	}
	var episodes []packagedSequenceEpisode
	start := 0
	var resultObjects, resultSends uint64
	for _, sign := range observation.signs {
		episode := packagedSequenceEpisode{Sign: sign}
		seen := map[string]packagedSequenceWrite{}
		for _, write := range observation.writes[start:sign.Writes] {
			previous, repeated := seen[write.Key]
			if write.Identity.Namespace == contract.StoreResultObject {
				episode.ResultSends++
				episode.ResultWriteBytes += write.Length
				if repeated {
					if write.Identity != previous.Identity || write.Digest != previous.Digest || write.Length != previous.Length || previous.Status != contract.WriteAcknowledged || write.Status != contract.WritePrecondition {
						t.Fatal("repeated result inbox send changed its exact body or acknowledgement")
					}
				} else {
					if write.Status != contract.WriteAcknowledged {
						t.Fatal("first healthy result inbox send was not acknowledged")
					}
					episode.ResultObjects++
					episode.ResultBytes += write.Length
				}
			} else {
				if repeated {
					t.Fatal("healthy persistence episode repeated a candidate immutable send")
				}
				episode.ImmutableObjects++
				episode.ImmutableBytes += write.Length
			}
			seen[write.Key] = write
		}
		if episode.ResultSends != 2*episode.ResultObjects || episode.ResultWriteBytes != 2*episode.ResultBytes {
			t.Fatal("healthy result inbox did not charge producer and adoption persistence")
		}
		shapeAt := slices.IndexFunc(shapes, func(shape packagedSequenceShape) bool { return shape.SignDigest == sign.Digest })
		if shapeAt >= 0 && shapeAt < len(generatedBounds) {
			bound := generatedBounds[shapeAt]
			if episode.ImmutableObjects > bound.objects || episode.ImmutableBytes > bound.bytes {
				t.Fatal("generated persistence episode exceeds independent object/byte bound", shapeAt, episode, bound)
			}
		}
		resultObjects += episode.ResultObjects
		resultSends += episode.ResultSends
		episodes = append(episodes, episode)
		start = sign.Writes
	}
	// The retained AWS route adds one child, four vector reads and 655 bytes.
	// Current public rows add at most 9457 bytes: configuration <=3529 and
	// four framed coordinates <=1548+1486+1439+1455. Count all new rows on
	// Apply, including their unchanged fields, rather than subtract old framing.
	// Publication keeps the unchanged 8192-byte framed-row maximum.
	type outputBound struct{ objects, bytes, children, reads uint64 }
	outputBounds := map[string]outputBound{
		"outputs-A-apply":   {9, 27025 + 655 + 9457, 13, 68},
		"outputs-A-publish": {4, 89329 + 655, 14, 69},
		"outputs-B-apply":   {7, 22980 + 655 + 9457, 14, 69},
		"outputs-B-publish": {4, 125162 + 655, 14, 69},
		"outputs-retire":    {7, 27175 + 655 + 9457, 14, 69},
		"outputs-cleanup":   {4, 161139 + 655, 14, 69},
	}
	if f.env.Trust.Family() == contract.GCP {
		// Current GCP configuration and framed coordinate add <=883+1468 bytes.
		outputBounds = map[string]outputBound{
			"outputs-A-apply":   {8, 8832 + 2351, 8, 17},
			"outputs-A-publish": {4, 29914, 9, 18},
			"outputs-B-apply":   {6, 8541 + 2351, 9, 18},
			"outputs-B-publish": {4, 38949, 9, 18},
			"outputs-retire":    {6, 10127 + 2351, 9, 18},
			"outputs-cleanup":   {4, 47996, 9, 18},
		}
	}
	for _, command := range commands {
		bound, ok := outputBounds[command.Label]
		if !ok {
			continue
		}
		for at := command.SignStart; at < command.SignEnd; at++ {
			episode := episodes[at]
			shapeAt := slices.IndexFunc(shapes, func(shape packagedSequenceShape) bool { return shape.SignDigest == episode.Sign.Digest })
			if shapeAt < 0 {
				t.Fatal("publication candidate has no authenticated shape", command.Label, at)
			}
			shape := shapes[shapeAt]
			if episode.ImmutableObjects > bound.objects || episode.ImmutableBytes > bound.bytes || shape.ChildCount > bound.children || shape.selectedReadBound() > bound.reads {
				t.Fatal("publication candidate exceeds independent bound", command.Label, at, episode, shape, bound)
			}
		}
	}
	if resultObjects != wantResults || resultSends != 2*wantResults {
		t.Fatal("generated sequence result inbox object/send count differs", resultObjects, resultSends)
	}
	if start != len(observation.writes) {
		t.Fatal("healthy sequence left writes outside a signed persistence episode")
	}
}

func packagedSequenceRetirementEvidence(t testing.TB, ctx context.Context, before, closed *StateSession, operation, dutyID, executor contract.ID, receipt contract.CompactMutationReceipt, readOriginal func(context.Context, string, uint32) contract.ReadResult) {
	t.Helper()
	original := mustSelectedGeneratedWork(t, before)
	row, present := original.records[generatedRecordKey{contract.GeneratedDutySupportKind, dutyID}]
	if !present {
		t.Fatal("retirement frozen Duty is absent")
	}
	duty, err := contract.InspectGeneratedDutyRecord(row.Body)
	if err != nil || duty.Kind != contract.GeneratedDutyRetirement || duty.ExecutorID != executor {
		t.Fatal("retirement frozen Duty differs", err)
	}
	target, err := original.retirementTarget(ctx, duty)
	if err != nil {
		t.Fatal("retirement frozen target unavailable", err)
	}
	facts, err := original.createTargetEvidence(ctx, target)
	if err != nil || !bytes.Equal(facts.Target, generatedTargetEvidence(t, before, target).Target) || generatedFactsResourceDigest(facts.GeneratorSafeFacts) != target.ResourceDigest {
		t.Fatal("retirement frozen original evidence differs", err)
	}
	subject := closed.head.Generator
	if subject == nil || subject.Purpose != contract.GeneratorAuthorityRetireClose || subject.OwnerID != dutyID || subject.OperationID.IsZero() || subject.OperationID == operation {
		t.Fatal("immediate retirement signed subject differs")
	}
	work := mustSelectedGeneratedWork(t, closed)
	if _, present := work.records[generatedRecordKey{contract.GeneratedDutySupportKind, dutyID}]; present {
		t.Fatal("acknowledged retirement retains its Duty")
	}
	mapping, present := work.releases[subject.AttemptID]
	if !present || mapping.release.State != contract.GeneratedReleasePending || mapping.attempt.OperationID != operation || mapping.attempt.OwnerID != dutyID || mapping.template.DutyID != dutyID ||
		mapping.attempt.ResourceID != duty.ResourceID || mapping.attempt.ConfigContractID != duty.ConfigContractID || mapping.attempt.ResourceContractID != duty.ResourceContractID ||
		mapping.attempt.ExecutorID != executor || mapping.attempt.CredentialRouteID != duty.CredentialRouteID || mapping.attempt.DescriptorID != duty.DescriptorID ||
		mapping.attempt.ResultContractID != duty.ResultContractID || mapping.template.Action != contract.GeneratorActionDelete {
		t.Fatal("retirement retained canonical mapping differs")
	}
	graphAt := slices.IndexFunc(work.bundles, func(graph contract.GeneratorPlanBundle) bool { return graph.UsePlan.PlanGraphID == subject.PlanGraphID })
	if graphAt < 0 {
		t.Fatal("retirement retained graph missing")
	}
	graph := work.bundles[graphAt]
	condition, err := contract.MatchHeadCondition(before.token)
	if err != nil {
		t.Fatal(err)
	}
	conditionDigest, err := contract.CryptoConditionDigest(condition)
	if err != nil {
		t.Fatal(err)
	}
	if graph.Header.OperationID != operation || graph.Request.OperationID != operation || graph.Request.OperationKind != contract.OperationRetireGeneratedGeneration || graph.Request.PredecessorRevisionID != before.head.Core.Revision || graph.Request.PredecessorHEADDigest != contract.Hash(before.body) || graph.Request.ConditionDigest != conditionDigest ||
		len(graph.Lineages) != 1 || graph.Lineages[0].Purpose != contract.GeneratorLineageRetirement || graph.Lineages[0].TemplateCount != 1 || graph.Header.TemplateCount != 1 {
		t.Fatal("retirement graph does not bind its frozen predecessor")
	}
	reservation, valid, err := before.generatedDeleteReservationSelection(ctx, graph, original)
	if err != nil || !valid || reservation.duty != duty || reservation.target != target || reservation.template != mapping.template {
		t.Fatal("retirement original reservation correspondence differs", err)
	}
	key, err := format.GeneratedResultKey(closed.store.Descriptor().Prefix, closed.root.Domain, mapping.release.InboxID)
	if err != nil {
		t.Fatal(err)
	}
	read := readOriginal(ctx, key, mapping.release.ObjectLength)
	defer clear(read.Body)
	if read.Status != contract.ReadOK || uint32(len(read.Body)) != mapping.release.ObjectLength || contract.Hash(read.Body) != mapping.release.SelectedHandoffDigest ||
		mapping.release.SelectedHandoffDigest != subject.ResultDigest || mapping.release.HandoffRevisionID != closed.head.Core.Revision || mapping.release.OriginalResultID != subject.ResultID || mapping.release.InboxID != mapping.attempt.InboxID {
		t.Fatal("retirement original inbox identity differs")
	}
	result, err := contract.InspectGeneratedResultRecord(read.Body)
	if err != nil {
		t.Fatal("retirement original result unavailable", err)
	}
	core := result.Core
	if core.DomainID != closed.root.Domain || core.OperationID != operation || core.AttemptID != mapping.attempt.AttemptID || core.TransmissionID != mapping.attempt.TransmissionID || core.ResultID != mapping.attempt.ResultID ||
		core.ExecutorID != executor || core.ConfigContractID != duty.ConfigContractID || core.DescriptorID != duty.DescriptorID || core.ResultContractID != duty.ResultContractID || core.PlanGraphID != subject.PlanGraphID ||
		core.RequestDigest != mapping.attempt.RequestDigest || result.SafeFacts.RequestDigest != core.RequestDigest || !bytes.Equal(result.SafeFacts.Target, facts.Target) || len(result.SafeFacts.ResourceData) == 0 || generatedFactsResourceDigest(result.SafeFacts.GeneratorSafeFacts) != target.ResourceDigest || result.SafeFacts.Disposition != contract.GeneratorDispositionRetirementAcknowledged {
		t.Fatal("retirement original result does not acknowledge the frozen target")
	}
	if receipt.DomainID != closed.root.Domain || receipt.PredecessorRevisionID != before.head.Core.Revision || receipt.RequestedRevisionID != closed.head.Core.Revision || receipt.ObservedRevisionID != closed.head.Core.Revision ||
		receipt.StateResult != contract.ReceiptStateSuccess || receipt.CanonicalOutcome != contract.ReceiptCanonicalSelected || receipt.EffectSummary != contract.ReceiptEffectComplete ||
		receipt.SummaryCounts[contract.ReceiptEffectCount] != 1 || receipt.SummaryCounts[contract.ReceiptSummarySuccessCount] != 1 || receipt.SummaryCounts[contract.ReceiptDutyCount] != 0 || receipt.SummaryCounts[contract.ReceiptHazardCount] != 0 ||
		receipt.AcknowledgedCount != 1 || receipt.ConfirmedCount != 0 || receipt.UnknownCount != 0 || receipt.WarningBits != contract.ReceiptWarningInvalidationNotConfirmed {
		t.Fatal("retirement receipt does not bind the immediate acknowledged close")
	}
}

func packagedRetirementSuccessor(t testing.TB, closed *StateSession, wantCurrent *contract.ValueEntry, receipt contract.CompactMutationReceipt) {
	t.Helper()
	var changed []contract.ChangedSubjectIdentity
	if wantCurrent != nil {
		for _, subject := range []struct {
			kind uint8
			id   contract.ID
		}{{contract.ChangedSubjectValueEntry, wantCurrent.Incarnation}, {contract.ChangedSubjectGeneratedValue, wantCurrent.Generated.GenerationID}} {
			identity, err := contract.ChangedSubjectIdentityID(closed.root.Domain, subject.kind, subject.id, contract.ID{})
			if err != nil {
				t.Fatal(err)
			}
			changed = append(changed, contract.ChangedSubjectIdentity{Kind: subject.kind, Change: contract.ChangedSubjectUpdated, Identity: identity})
		}
		_, actualCurrent := observeCurrentValueEntry(t, closed, "generated")
		expected := *wantCurrent
		expected.Generated.RetiringDutyPresent, expected.Generated.RetiringDutyID = 0, contract.ID{}
		if !reflect.DeepEqual(actualCurrent, expected) || receipt.ChangedSubjects.Count != 2 || receipt.ChangedSubjects.Length != 80 {
			t.Fatal("retirement changed current successor or its exact vector")
		}
	} else if closed.root.Generated.GeneratedCurrent != 0 || receipt.ChangedSubjects.Count != 0 || receipt.ChangedSubjects.Length != 4 {
		t.Fatal("detached retirement restored a current value")
	}
	wantedSubjects, err := contract.ChangedSubjectDescriptor(changed)
	if err != nil || receipt.ChangedSubjects != wantedSubjects {
		t.Fatal("retirement changed-subject identities differ", err)
	}
}

// Historical reads have no mutation capability. The expected digest comes from a signed HEAD.
type stockOriginalReader func(context.Context, string, contract.ID, uint32) (contract.ReadResult, error)

func stockHistoricalRetirement(t testing.TB, ctx context.Context, before, after *StateSession, operation, revision, dutyID, executor contract.ID, reader stockOriginalReader) (contract.ID, contract.ID, uint32) {
	t.Helper()
	domain := before.root.Domain
	if after.root.Domain != domain || before.store.Descriptor() != after.store.Descriptor() {
		t.Fatal("stock retirement observation domain or Store changed")
	}
	current := after
	released := make(map[contract.ID]contract.ID)
	for current.head.Generator != nil && current.head.Generator.Purpose == contract.GeneratorAuthorityInboxRelease {
		s := current.head.Generator
		if _, seen := released[s.OwnerID]; seen || uint64(len(released)) >= generatedResultReleaseLimit {
			t.Fatal("stock retirement release chain repeats or exceeds its limit")
		}
		released[s.OwnerID] = s.ResultDigest
		predecessor, err := stockReleasePredecessor(ctx, before, current, reader)
		if err != nil {
			t.Fatal("historical release predecessor does not authenticate", err)
		}
		current = predecessor
	}
	closed := current
	receipt, ok := closed.mutationReceipts[operation]
	if closed.head.Generator == nil || closed.head.Generator.Purpose != contract.GeneratorAuthorityRetireClose || !ok || after.mutationReceipts[operation] != receipt || receipt.OperationID != operation || receipt.OperationKind != contract.OperationRetireGeneratedGeneration || receipt.EvidenceCeiling != contract.ReceiptEvidenceAcknowledged || closed.head.Core.Revision != revision {
		t.Fatal("stock retirement close or retained receipt differs")
	}
	closeSubject := closed.head.Generator
	mapping, ok := mustSelectedGeneratedWork(t, closed).releases[closeSubject.AttemptID]
	if !ok || released[mapping.release.InboxID] != closeSubject.ResultDigest {
		t.Fatal("stock release does not reference the retired result")
	}
	if _, stillPresent := mustSelectedGeneratedWork(t, after).releases[closeSubject.AttemptID]; stillPresent {
		t.Fatal("stock retirement release remains selected")
	}
	key, err := format.GeneratedResultKey(after.store.Descriptor().Prefix, domain, mapping.release.InboxID)
	if err != nil || after.store.Read(ctx, key, mapping.release.ObjectLength).Status != contract.ReadMissing {
		t.Fatal("stock retirement result remains current or its absence is unknown")
	}
	packagedSequenceRetirementEvidence(t, ctx, before, closed, operation, dutyID, executor, receipt, func(ctx context.Context, k string, n uint32) contract.ReadResult {
		read, err := reader(ctx, k, closeSubject.ResultDigest, n)
		if err != nil {
			t.Fatal("stock original retirement result unavailable")
		}
		return read
	})
	var successor *contract.ValueEntry
	if before.root.Generated.GeneratedCurrent != 0 {
		_, entry := observeCurrentValueEntry(t, before, "generated")
		successor = &entry
	}
	packagedRetirementSuccessor(t, closed, successor, receipt)

	return contract.Hash(closed.body), closeSubject.ResultDigest, mapping.release.ObjectLength
}

// The current image was independently opened. Reopen the exact preceding HEAD
// with the original admission, then compare its signed revision and root.
func stockReleasePredecessor(ctx context.Context, before, current *StateSession, reader stockOriginalReader) (*StateSession, error) {
	head, s := current.head.Core, current.head.Generator
	if s == nil || s.Purpose != contract.GeneratorAuthorityInboxRelease || s.PreviousHEADDigest != head.PreviousDigest || s.PreviousRevisionID != head.PreviousRevision || s.AfterRootDigest != head.Root.Digest {
		return nil, contract.ErrRecord
	}
	read, err := reader(ctx, current.store.Descriptor().HeadKey, head.PreviousDigest, 0)
	defer clear(read.Body)
	if err != nil {
		return nil, err
	}
	if read.Status != contract.ReadOK || read.Token != head.PreviousToken || contract.Hash(read.Body) != head.PreviousDigest {
		return nil, contract.ErrRecord
	}
	store := packagedSequenceHeadStore{Store: current.store, head: packagedSequenceHead{body: bytes.Clone(read.Body), token: read.Token}}
	predecessor, opened := Open(ctx, OpenContext{admission: &before.admission}, store)
	if predecessor == nil || opened.Outcome != ObservedCurrent || predecessor.head.Core.Revision != head.PreviousRevision || predecessor.head.Core.Root.Digest != s.BeforeRootDigest {
		return nil, contract.ErrRecord
	}
	return predecessor, nil
}

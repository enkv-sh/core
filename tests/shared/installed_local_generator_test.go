package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

type installedLocalAuthor struct {
	config           custody.GeneratedProcessConfig
	refuseResultPipe *custody.GeneratedPipeFault
}

func installedLocalPublicRoot(t testing.TB) string {
	t.Helper()
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(root, "core", "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(root)
		if parent == root {
			t.Fatal("implementation source root unavailable")
		}
		root = parent
	}
	public := filepath.Join(filepath.Dir(root), "enkv-extensions")
	return public
}

func buildInstalledLocalAuthor(t testing.TB, rebuilt bool) installedLocalAuthor {
	t.Helper()
	return installedLocalAuthor{config: custody.BuildInstalledLocalAuthor(t, installedLocalPublicRoot(t), rebuilt)}
}

type localAuthorObservedCrypto struct {
	contract.Crypto
	t     testing.TB
	stage string
}

func (c localAuthorObservedCrypto) Exchange(ctx context.Context, q contract.CryptoRequest) contract.CryptoResponse {
	out := c.Crypto.Exchange(ctx, q)
	if out.ResultCode != contract.CryptoSuccess {
		c.t.Log("local exchange refused", c.stage, q.Kind, out.ResultCode)
	}
	return out
}

func installedLocalEngine(t testing.TB, ctx context.Context, f installedApplyTestFixture, selected *StateSession, input []ApplyEntryInput, author installedLocalAuthor, entries *int, observeCompletion ...func(bool)) *InstalledApply {
	t.Helper()
	return installedLocalEngineWithRecipients(t, ctx, f, selected, input, currentApplyRecipients(selected.registry()), author, entries, observeCompletion...)
}

func installedLocalEngineWithRecipients(t testing.TB, ctx context.Context, f installedApplyTestFixture, selected *StateSession, input []ApplyEntryInput, desired []contract.ApplyRecipientInput, author installedLocalAuthor, entries *int, observeCompletion ...func(bool)) *InstalledApply {
	t.Helper()
	row := author.config.Artifact
	implementations := []contract.GeneratorImplementation{row}
	var remote *GeneratedApplyInstallation
	if process := f.env.GeneratedProcess; process != nil {
		implementations = append(implementations, process.Implementation)
		remote = installedGeneratedRetirementCallbacks(t, f, process)
	}
	validator := NewPublicConfigurationValidator(selected.admission.outputInterpreter)
	configuration := installedApplyTestConfiguration(t, ctx, selected, input, desired, validator)
	for at := range configuration.Entries.Value {
		public := &configuration.Entries.Value[at]
		for _, entry := range input {
			if public.Name == entry.Name && entry.Generated != nil {
				g := entry.Generated
				public.Generated = installedGeneratedPublicSettings(g)

			}
		}
	}
	wrap := func(stage string, owner *custody.InstalledGeneratedOwner, err error) (*InstalledGeneratedCustody, error) {
		if err != nil {
			t.Log("local custody refusal", stage, err)
			return nil, err
		}
		return &InstalledGeneratedCustody{Crypto: localAuthorObservedCrypto{Crypto: owner, t: t, stage: stage}, BindCandidate: func(ctx context.Context, input contract.GeneratedCandidateInput) contract.CryptoResultCode {
			code := owner.BindCandidate(ctx, input)
			if code != contract.CryptoSuccess {
				t.Log("local candidate refused", stage, code)
			}
			return code
		}, Close: owner.Close}, nil
	}
	callbacks := &GeneratedApplyInstallation{
		NewRetirementReturnProof: f.keys.NewRetirementReturnProof,
		ResolveImplementation: func(q GeneratedImplementationRequest) (contract.GeneratorImplementation, error) {
			if remote != nil && q.ConfigContractID != row.ConfigContractID {
				return remote.ResolveImplementation(q)
			}
			if q.ConfigContractID != row.ConfigContractID || !q.ResourceContractID.IsZero() || q.LifecycleMode != contract.GeneratorLifecycleNone {
				return row, contract.ErrRecord
			}
			return row, nil
		},
		CheckCreateReadiness: func(ctx context.Context, name string, implementation contract.GeneratorImplementation, intent []byte) error {
			if remote != nil && reflect.DeepEqual(implementation, f.env.GeneratedProcess.Implementation) {
				return remote.CheckCreateReadiness(ctx, name, implementation, intent)
			}
			if !reflect.DeepEqual(implementation, row) || !bytes.Equal(intent, installedLocalCanonicalIntent()) {
				return contract.ErrRecord
			}
			return installedGeneratorCreateReadiness(ctx, author.config, intent)
		},
		RequestDigest: func(ctx context.Context, implementation contract.GeneratorImplementation, action uint8, b []byte, target *contract.GeneratorTarget) (contract.ID, error) {
			if remote != nil && reflect.DeepEqual(implementation, f.env.GeneratedProcess.Implementation) {
				return remote.RequestDigest(ctx, implementation, action, b, target)
			}
			if ctx.Err() != nil || !reflect.DeepEqual(implementation, row) || action != contract.GeneratorActionCreate || target != nil || !bytes.Equal(b, installedLocalCanonicalIntent()) {
				return contract.ID{}, contract.ErrRecord
			}
			// Fixed request binding vector, separate from canonical semantic intent.
			bytes, err := hex.DecodeString("ffc883f26ef97ff2caaa3df3acf8ec0d2dc87492741ade34fe3e1e109f7158cb")
			if err != nil {
				return contract.ID{}, err
			}
			var digest contract.ID
			copy(digest[:], bytes)
			return digest, nil
		},
		AdmitReservation: func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedReservationInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
			owner, err := f.keys.NewInstalledGeneratedReservation(q, control, input, fixtureID(f.env.Domain, "source-file"), deadline)
			return wrap("reservation", owner, err)
		},
		AdmitProducer: func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedProducerInput, implementation contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
			*entries++
			if remote != nil && reflect.DeepEqual(implementation, f.env.GeneratedProcess.Implementation) {
				return remote.AdmitProducer(ctx, q, control, input, implementation, deadline)
			}
			owner, err := f.keys.NewInstalledGeneratedProducer(ctx, q, control, input, author.config, deadline, observeCompletion...)
			base, err := wrap("producer", owner, err)
			if err != nil {
				return nil, err
			}
			if author.refuseResultPipe != nil {
				owner.RefuseResultPipe(author.refuseResultPipe)
			}
			failure := f.keys.InstalledGeneratedLocalFailure(owner)
			producer := &InstalledGeneratedProducerCustody{InstalledGeneratedCustody: *base, InvokeProducer: owner.InvokeProducer}
			if failure != nil {
				producer.LocalFailureReason = failure.Reason
				producer.AdmitLocalFailure = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedLocalFailureInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
					continued, err := failure.Admit(ctx, q, control, input, deadline)
					return wrap("local-failure", continued, err)
				}
			}
			return producer, nil
		},
		AdmitAdoption: func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedAdoptionInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
			owner, err := f.keys.NewInstalledGeneratedAdoption(q, control, input, deadline)
			return wrap("adoption", owner, err)
		},
		AdmitFinal: func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedFinalInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
			owner, err := f.keys.NewInstalledGeneratedFinal(q, control, input, deadline)
			return wrap("final", owner, err)
		},
	}
	if remote != nil {
		callbacks.CheckRetirementCompatibility = remote.CheckRetirementCompatibility
	}
	engine, err := NewInstalledApply(ApplyInstallation{ExpectedDomain: f.env.Domain, ExpectedStore: f.env.Store.Descriptor(), PublicBasis: f.basis, ExpectedControl: currentControlOf(selected), DesiredRecipients: desired, GeneratorImplementations: implementations, Generated: callbacks, PublicConfiguration: configuration, ConfigurationValidator: validator, Store: f.env.Store, Trust: f.env.Trust, CompositionID: f.composition, FileIdentity: fixtureID(f.env.Domain, "source-file"), CloseInstalled: func() {}, AdmitCustody: func(ctx context.Context, q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, plain []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, revision contract.ID, before contract.MutationReceiptWindows, warningBits uint8, deadline time.Time) (*InstalledApplyCustody, error) {
		owner, err := f.keys.NewApplyCustody(q, control, current, fixtureID(f.env.Domain, "source-file"), plain, support, witness, revision, before, warningBits, deadline)
		if err != nil {
			return nil, err
		}
		return &InstalledApplyCustody{Crypto: localAuthorObservedCrypto{Crypto: owner, t: t, stage: "ordinary"}, BindReceipt: owner.BindReceipt, Close: owner.Close}, nil
	}})
	if err != nil {
		t.Fatal("local installed engine", err)
	}
	t.Cleanup(engine.Close)
	return engine
}

// full_only: false
func TestInstalledLocalGeneratorPublicAuthorSelectsUsefulSecret(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	t.Setenv("CLOUDFLARE_API_TOKEN", "invalid must not be captured")
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	author := buildInstalledLocalAuthor(t, false)
	row := author.config.Artifact
	declaration := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleNone, ConfigContractID: row.ConfigContractID, ResourceContractID: contract.ID{}, Intent: installedLocalCanonicalIntent()}
	input := []ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "local", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{f.selected.admission.recipient}, Generated: &declaration}}
	admissions := 0
	engine := installedLocalEngine(t, ctx, f, f.selected, input, author, &admissions)
	result := engine.Apply(ctx, fixtureID(f.env.Domain, "installed local author create"), input)
	if result.Result.Outcome != ObservedCurrent {
		t.Fatal("local author create did not select", result.Result, "producer admissions", admissions)
	}
	cold := f.open(t, ctx)
	if admissions != 1 || cold.root.Generated.GeneratedCurrent != 1 || !cold.root.Generated.ActiveOwner.IsZero() || cold.root.Generated.Retiring != 0 || cold.root.Generated.Hazards != 0 {
		t.Fatalf("local Final incomplete: admissions=%d current=%d active=%t retiring=%d hazards=%d", admissions, cold.root.Generated.GeneratedCurrent, !cold.root.Generated.ActiveOwner.IsZero(), cold.root.Generated.Retiring, cold.root.Generated.Hazards)
	}
	for _, record := range cold.supportRecords() {
		if record.Kind != contract.GeneratedDutySupportKind {
			continue
		}
		duty, err := contract.InspectGeneratedDutyRecord(record.Body)
		if err != nil || duty.LifecycleMode != contract.GeneratorLifecycleNone || duty.Kind != contract.GeneratedDutyCreate {
			t.Fatal("local selection has a remote Duty", err)
		}
	}
	entry := cold.valueEntry(cold.root.Names[0].Slot)
	if entry.Generated.SemanticLifecycleMode() != contract.GeneratorLifecycleNone || !entry.Generated.ResourceContractID.IsZero() || !entry.Generated.ResourceDigest.IsZero() || entry.Generated.CompletionClass != 0 || entry.Generated.RetirementMode != 0 || entry.Generated.OriginOperationID != result.OperationID || entry.Generated.CreateResultID.IsZero() {
		t.Fatal("local selected identity differs")
	}
	if result.Generated == nil || len(result.Generated.Effects) != 1 || result.Generated.Effects[0].GenerationID != entry.Generated.GenerationID || result.Generated.Effects[0].Target != nil {
		t.Error("selected local invocation lost the exact generation or invented a remote target")
	}
	assertInstalledLocalPublicReaders(t, ctx, f, cold, &admissions)
	evidenceFound := false
	for _, record := range cold.supportRecords() {
		if record.Kind != contract.GeneratedCreateEvidenceSupportKind || record.RecordID != entry.Generated.CreateResultID {
			continue
		}
		evidence, err := contract.DecodeGeneratedCreateEvidence(record.Body)
		if err != nil || evidence.Schema != contract.GeneratedCreateEvidenceSchema || evidence.LifecycleMode != contract.GeneratorLifecycleNone || evidence.CredentialRouteID != row.CredentialRouteID || len(record.Body) != 687 {
			t.Fatal("local Final stored the wrong create evidence", err)
		}
		descriptor, err := contract.GeneratedCreateEvidenceDescriptor(evidence)
		if err != nil || descriptor != entry.Generated.CreateEvidence {
			t.Fatal("stored local evidence differs from selected metadata", err)
		}
		evidenceFound = true
	}
	if !evidenceFound {
		t.Fatal("selected local create evidence is missing")
	}
	image := cold.selectedImage()
	materials := selectedMaterialFacts{accessLocations: cold.accessLocations, valueReaders: cold.valueReaders}
	if _, ok := selectedValueRelations(cold.head, image, cold.admission.recipient, materials); !ok || image.root.RawBytes != 43 {
		t.Fatal("selected local image does not qualify its actual children")
	}
	image.root.RawBytes--
	if !validAggregate(image.root) {
		t.Fatal("forged raw total must remain inside the coarse metadata interval")
	}
	if _, ok := selectedValueRelations(cold.head, image, cold.admission.recipient, materials); ok {
		t.Fatal("complete child validation accepted an in-range forged raw total")
	}
	captureInstalledLocalValue(t, ctx, f, cold, "local")
}

// full_only: false
func TestInstalledLocalGeneratorKeepsResultAfterExecutableRemovalFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	root := generatorRemovalFixtureRoot(t)
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	author := installedLocalAuthor{config: custody.BuildInstalledCleanupRefusedLocalAuthor(t, installedLocalPublicRoot(t))}
	row := author.config.Artifact
	declaration := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema,
		LifecycleMode: contract.GeneratorLifecycleNone, ConfigContractID: row.ConfigContractID, Intent: installedLocalCanonicalIntent()}
	input := []ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "local", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret,
		Recipients: []contract.ID{f.selected.admission.recipient}, Generated: &declaration}}
	admissions := 0
	engine := installedLocalEngine(t, ctx, f, f.selected, input, author, &admissions)
	admit := engine.installation.Generated.AdmitProducer
	var observed contract.GeneratedProducerResult
	engine.installation.Generated.AdmitProducer = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedProducerInput, implementation contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
		owner, err := admit(ctx, q, control, in, implementation, deadline)
		if err != nil || owner == nil {
			return owner, err
		}
		invoke := owner.InvokeProducer
		owner.InvokeProducer = func(ctx context.Context, locator, authority contract.ID) contract.GeneratedProducerResult {
			returned := invoke(ctx, locator, authority)
			observed = returned
			// A second invocation uses no retained cleanup state from the first.
			refused := invoke(ctx, locator, authority)
			if refused.Code == contract.CryptoSuccess || refused.ExecutableCleanupFailed || len(refused.Record) != 0 || refused.Facts.Schema != 0 {
				t.Error("refused invocation inherited a prior completion result")
			}
			if !returned.ExecutableCleanupFailed || len(returned.Record) == 0 || returned.Code != contract.CryptoSuccess {
				t.Error("real host completion lost its per-call cleanup evidence")
			}
			return returned
		}
		return owner, nil
	}
	result := engine.Apply(ctx, fixtureID(f.env.Domain, "local result despite executable removal"), input)
	engine.Close()
	assertGeneratorRemovalFixture(t, root)
	if !observed.ExecutableCleanupFailed {
		t.Fatal("real installed return carried no cleanup evidence")
	}
	if result.Result.Outcome != ObservedCurrent || result.Generated == nil || result.Generated.StateResult != "success" || admissions != 1 {
		t.Fatalf("sole executable removal discarded the useful local result: outcome=%d reason=%d generated=%t admissions=%d", result.Result.Outcome, result.Result.Reason, result.Generated != nil, admissions)
	}
	if len(result.Diagnostics) != 1 || !generatorCleanupDiagnostic(result.Diagnostics[0]) {
		t.Fatal("completed local result did not retain one separate safe cleanup diagnostic")
	}
	cold := f.open(t, ctx)
	if cold.root.Generated.GeneratedCurrent != 1 || !cold.root.Generated.ActiveOwner.IsZero() || cold.root.Generated.Retiring != 0 || cold.root.Generated.Hazards != 0 || len(cold.root.Names) != 1 {
		t.Fatal("cold local result is incomplete or invented managed work")
	}
	// The copied callback fills entropy with bytes 00..1f before ordinary encoding.
	want := sha256.Sum256([]byte("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"))
	if got := captureInstalledLocalValue(t, ctx, f, cold, "local"); got != want {
		t.Fatal("cold local Reader changed the independently fixed returned value")
	}
}

func captureInstalledLocalValue(t testing.TB, ctx context.Context, f installedApplyTestFixture, cold *StateSession, name string) [32]byte {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "value.private")
	selection := sessionConsumerSelection(t, cold, cold.admission.recipient, name)
	captured := f.keys.CaptureSelected(ctx, selection, path)
	if captured.Code != contract.CryptoSuccess || captured.Delivery != 1 || captured.SinkCalls != 1 || !captured.ValueMatched {
		t.Fatal("cold local Reader could not deliver the selected value", captured.Code, captured.Delivery, captured.SinkCalls)
	}
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(value[:cap(value)])
	if len(value) != 43 {
		t.Fatal("cold local Reader returned the wrong value length")
	}
	memory, ok := underlyingAdmittedMemoryStore(f.env.Store)
	if !ok {
		t.Fatal("local fixture has no persisted object owner")
	}
	memory.mu.Lock()
	for _, object := range memory.objects {
		body := object.Body
		if object.bodyPath != "" {
			body, err = os.ReadFile(object.bodyPath)
			if err != nil {
				memory.mu.Unlock()
				t.Fatal(err)
			}
		}
		leaked := bytes.Contains(body, value)
		if object.bodyPath != "" {
			clear(body[:cap(body)])
		}
		if leaked {
			memory.mu.Unlock()
			t.Fatal("persisted object exposed the plaintext local secret")
		}
	}
	memory.mu.Unlock()
	var entropy [32]byte
	defer clear(entropy[:])
	count, err := base64.RawURLEncoding.Strict().Decode(entropy[:], value)
	var encoded [43]byte
	defer clear(encoded[:])
	base64.RawURLEncoding.Encode(encoded[:], entropy[:])
	if err != nil || count != 32 || !bytes.Equal(encoded[:], value) {
		t.Fatal("cold local Reader returned noncanonical entropy bytes")
	}
	return sha256.Sum256(value)
}

// full_only: false
func TestInstalledLocalGeneratorRebuildReuseRotateAndRemove(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	a, b := buildInstalledLocalAuthor(t, false), buildInstalledLocalAuthor(t, true)
	if a.config.Artifact.ExecutorID == b.config.Artifact.ExecutorID || a.config.Artifact.ConfigContractID != b.config.Artifact.ConfigContractID {
		t.Fatal("author rebuild did not retain semantics and change exact executor identity")
	}
	declaration := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleNone, ConfigContractID: a.config.Artifact.ConfigContractID, ResourceContractID: contract.ID{}, Intent: installedLocalCanonicalIntent()}
	input := []ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "local", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{f.selected.admission.recipient}, Generated: &declaration}}
	admissions := 0
	engine := installedLocalEngine(t, ctx, f, f.selected, input, a, &admissions)
	created := engine.Apply(ctx, fixtureID(f.env.Domain, "local rebuild original"), input)
	if created.Result.Outcome != ObservedCurrent || admissions != 1 {
		t.Fatal("original local generation did not select", created.Result, admissions)
	}
	selected := f.open(t, ctx)
	original := selected.valueEntry(selected.root.Names[0].Slot).Generated
	assertInstalledLocalExecutor(t, selected, a.config.Artifact.ExecutorID)
	captureInstalledLocalValue(t, ctx, f, selected, "local")
	input = append(input, ApplyEntryInput{Name: "ordinary", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{selected.admission.recipient}, InputBytes: []byte("unrelated supplied value"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
	engine = installedLocalEngine(t, ctx, f, selected, input, a, &admissions)
	unrelated := engine.Apply(ctx, fixtureID(f.env.Domain, "unrelated supplied change beside local"), input)
	if unrelated.Result.Outcome != ObservedCurrent || admissions != 1 {
		t.Fatal("unrelated supplied update lost the unchanged local value", unrelated.Result, admissions)
	}
	selected = f.open(t, ctx)
	if current := selected.valueEntry(selected.root.Names[0].Slot).Generated; current != original {
		t.Fatal("unrelated supplied update changed the local generation identity")
	}
	captureInstalledLocalValue(t, ctx, f, selected, "local")
	engine = installedLocalEngine(t, ctx, f, selected, input, b, &admissions)
	reused := engine.Apply(ctx, fixtureID(f.env.Domain, "local rebuilt same epoch"), input)
	if reused.Result.Outcome != Unchanged || admissions != 1 {
		t.Fatal("same epoch rebuild did not reuse without producer entry", reused.Result, admissions)
	}
	selected = f.open(t, ctx)
	if current := selected.valueEntry(selected.root.Names[0].Slot).Generated; current != original {
		t.Fatal("same epoch rebuild changed original identity")
	}
	assertInstalledLocalExecutor(t, selected, a.config.Artifact.ExecutorID)
	captureInstalledLocalValue(t, ctx, f, selected, "local")
	declaration.Epoch++
	engine = installedLocalEngine(t, ctx, f, selected, input, b, &admissions)
	rotated := engine.Apply(ctx, fixtureID(f.env.Domain, "local rebuilt next epoch"), input)
	if rotated.Result.Outcome != ObservedCurrent || admissions != 2 {
		t.Fatal("local epoch advance did not select rebuilt producer", rotated.Result, admissions)
	}
	selected = f.open(t, ctx)
	current := selected.valueEntry(selected.root.Names[0].Slot).Generated
	if current.Epoch != 1 || current.GenerationID == original.GenerationID || current.CreateResultID == original.CreateResultID || selected.root.Generated.Retiring != 0 || selected.root.Generated.Hazards != 0 || !selected.root.Generated.ActiveOwner.IsZero() {
		t.Fatalf("local rotation incomplete: epoch=%d sameGeneration=%t sameResult=%t retiring=%d hazards=%d active=%t", current.Epoch, current.GenerationID == original.GenerationID, current.CreateResultID == original.CreateResultID, selected.root.Generated.Retiring, selected.root.Generated.Hazards, !selected.root.Generated.ActiveOwner.IsZero())
	}
	assertInstalledLocalExecutor(t, selected, b.config.Artifact.ExecutorID)
	captureInstalledLocalValue(t, ctx, f, selected, "local")
	engine = installedLocalEngine(t, ctx, f, selected, nil, b, &admissions)
	removed := engine.Apply(ctx, fixtureID(f.env.Domain, "local removal"), nil)
	if removed.Result.Outcome != ObservedCurrent || admissions != 2 {
		t.Fatal("local removal entered a producer or failed selection", removed.Result, admissions)
	}
	selected = f.open(t, ctx)
	if selected.root.ValueEntryCount != 0 || selected.root.Generated.GeneratedCurrent != 0 || selected.root.Generated.Retiring != 0 || selected.root.Generated.Hazards != 0 || !selected.root.Generated.ActiveOwner.IsZero() {
		t.Fatal("local removal retained a value or remote work")
	}
}

func assertInstalledLocalExecutor(t testing.TB, selected *StateSession, executor contract.ID) {
	t.Helper()
	entry := selected.valueEntry(selected.root.Names[0].Slot)
	for _, row := range selected.supportRecords() {
		if row.Kind != contract.GeneratedCreateEvidenceSupportKind || row.RecordID != entry.Generated.CreateResultID {
			continue
		}
		evidence, err := contract.DecodeGeneratedCreateEvidence(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		core, err := contract.InspectGeneratedResultCore(evidence.ResultCore)
		if err != nil || core.ExecutorID != executor || core.AttemptID != entry.Generated.OriginAttemptID || core.OperationID != entry.Generated.OriginOperationID || core.ResultID != entry.Generated.CreateResultID {
			t.Fatal("selected local create evidence lost exact original identity", err)
		}
		return
	}
	t.Fatal("selected local evidence is absent")
}

func assertInstalledLocalPublicReaders(t testing.TB, ctx context.Context, f installedApplyTestFixture, selected *StateSession, admissions *int) {
	t.Helper()
	memory, ok := underlyingAdmittedMemoryStore(f.env.Store)
	if !ok {
		t.Fatal("local reader fixture has no Store counters")
	}
	trust, ok := underlyingAdmittedFixtureTrust(f.env.Trust)
	if !ok {
		t.Fatal("local reader fixture has no signer counters")
	}
	public, private := f.keys.Calls()
	creates, cas, signs, entries := memory.creates, memory.cas, trust.signs, *admissions
	entry := selected.valueEntry(selected.root.Names[0].Slot)
	reader, source := installedGeneratedReaderFixture(t, f)
	listed := reader.List(ctx, fixtureID(f.env.Domain, "local public list"))
	if listed.StateResult != contract.ReaderSuccess || listed.View == nil || len(listed.View.CurrentGenerations) != 1 || source.closes != 1 {
		t.Error("cold local list did not return one current generation")
	} else {
		current := listed.View.CurrentGenerations[0]
		if current.LifecycleMode != contract.GeneratorLifecycleNone || current.Name != entry.Name || current.EntryIncarnationID != entry.Incarnation || current.GenerationID != entry.Generated.GenerationID || current.OriginOperationID != entry.Generated.OriginOperationID || current.OriginAttemptID != entry.Generated.OriginAttemptID || current.ResourceID != entry.Generated.ResourceIncarnationID || !current.ResourceContractID.IsZero() || !current.ResourceDigest.IsZero() || current.CompletionClass != 0 || current.RetirementMode != 0 {
			t.Error("cold local list changed identity or invented remote facts")
		}
	}
	inspector, inspectSource := installedInspectionFixture(t, f)
	inspected := inspector.Inspect(ctx, DomainInspectionRequest{fixtureID(f.env.Domain, "local public inspection")})
	if inspected.StateResult != PublicQuerySuccess || inspected.View == nil || inspected.ValidateMetadataWorkOutput() != nil || inspectSource.closes != 1 {
		t.Error("cold local inspection did not validate its actual selected metadata and work")
	}
	if p, q := f.keys.Calls(); p != public || q != private || memory.creates != creates || memory.cas != cas || trust.signs != signs || *admissions != entries {
		t.Error("GET-only local readers used private custody, signing, producer entry or Store mutation")
	}
}

// full_only: false
func TestInstalledLocalGeneratorSharedIntentAndSuppliedReplacement(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	author := buildInstalledLocalAuthor(t, false)
	row := author.config.Artifact
	declaration := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleNone, ConfigContractID: row.ConfigContractID, ResourceContractID: contract.ID{}, Intent: installedLocalCanonicalIntent()}
	authority, reader := f.selected.admission.recipient, fixtureID(f.env.Domain, "reader")
	input := []ApplyEntryInput{}
	for _, name := range []string{"alpha", "omega"} {
		input = append(input, ApplyEntryInput{Name: name, ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{authority}, Generated: &declaration, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
	}
	admissions := 0
	apply := func(label string, selected *StateSession, rows []ApplyEntryInput) *StateSession {
		t.Helper()
		engine := installedLocalEngine(t, ctx, f, selected, rows, author, &admissions)
		result := engine.Apply(ctx, fixtureID(f.env.Domain, label), rows)
		if result.Result.Outcome != ObservedCurrent {
			t.Fatal("local shared-intent transition refused", label, result.Result)
		}
		return f.open(t, ctx)
	}
	selected := apply("two local original producers", f.selected, input)
	if admissions != 2 || selected.root.Generated.GeneratedCurrent != 2 {
		t.Fatal("two local producers did not select exactly once each", admissions)
	}
	original := selected.valueEntry(selected.root.Names[0].Slot).Generated
	valueDigest := captureInstalledLocalValue(t, ctx, f, selected, "alpha")
	captureInstalledLocalValue(t, ctx, f, selected, "omega")
	if selected.recipientRecord(reader) == nil {
		t.Fatal("local membership fixture has no selected reader")
	}
	input[0].Recipients = []contract.ID{authority, reader}
	slices.SortFunc(input[0].Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	selected = apply("local grant preserves original", selected, input)
	if selected.valueEntry(selected.root.Names[0].Slot).Generated != original || captureInstalledLocalValue(t, ctx, f, selected, "alpha") != valueDigest || admissions != 2 {
		t.Fatal("grant changed original local generation or value")
	}
	input[0].Recipients = []contract.ID{authority}
	selected = apply("local exclusion preserves original", selected, input)
	excludedEntry := selected.valueEntry(selected.root.Names[0].Slot)
	excluded := excludedEntry.Generated
	// Exclusion rotates ordinary canonical material and its GenerationID,
	// while the original generated result and value remain the source.
	newGeneration := excluded.GenerationID
	excluded.GenerationID = original.GenerationID
	if excluded != original || newGeneration == original.GenerationID || newGeneration != excludedEntry.ValueState || captureInstalledLocalValue(t, ctx, f, selected, "alpha") != valueDigest || admissions != 2 {
		t.Fatal("exclusion lost the original local result or value, or retained stale canonical material")
	}
	original = excludedEntry.Generated
	input = input[:1]
	selected = apply("remove one shared local intent user", selected, input)
	if admissions != 2 || selected.root.Generated.GeneratedCurrent != 1 {
		t.Fatal("one local removal changed producer entry or current count")
	}
	work, err := selected.selectedGeneratedWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := work.content.locations[generatedContentKey{contract.GeneratorContentIntent, original.IntentDigest}]; !exists {
		t.Fatal("removing one local value discarded the shared intent")
	}
	for _, support := range selected.supportRecords() {
		if support.Kind == contract.GeneratedCreateEvidenceSupportKind && support.RecordID != original.CreateResultID {
			t.Fatal("removed local value retained detached evidence")
		}
	}
	input = []ApplyEntryInput{suppliedSecret(t, f.env, "alpha", "local to supplied replacement", custody.StandardValue, authority)}
	selected = apply("replace last local with supplied secret", selected, input)
	if admissions != 2 || selected.root.Generated.GeneratedCurrent != 0 || selected.root.Generated.Duties != 0 || selected.root.Generated.Hazards != 0 {
		t.Fatal("local to supplied replacement entered a producer or created remote work")
	}
	work, err = selected.selectedGeneratedWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := work.content.locations[generatedContentKey{contract.GeneratorContentIntent, original.IntentDigest}]; exists {
		t.Fatal("last local consumer left an unowned intent")
	}
	for _, support := range selected.supportRecords() {
		if support.Kind == contract.GeneratedCreateEvidenceSupportKind {
			t.Fatal("last local consumer left detached local evidence")
		}
	}
	selection := sessionConsumerSelection(t, selected, authority, "alpha")
	consumed := f.keys.Consume(ctx, selection, custody.StandardValue)
	if consumed.Code != contract.CryptoSuccess || consumed.Delivery != 1 || consumed.SinkCalls != 1 || !consumed.ValueMatched {
		t.Fatal("supplied replacement did not deliver the selected supplied value")
	}
}

// full_only: false
func TestInstalledLocalGeneratorSharedDeleteReleaseRetainsOnlyActualIntents(t *testing.T) {
	for _, successor := range []string{"ordinary", "generated CF", "ordinary capacity"} {
		t.Run(successor, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			process, effects := installedGeneratedRetirementProcess(t, "acknowledged")
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
			f.env.GeneratedProcess = process
			remote := &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged,
				RetirementMode: contract.GeneratedRetirementManual, ConfigContractID: process.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(),
				CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent)}
			input := []ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "remote", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{f.selected.admission.recipient}, Generated: remote}}
			first := installedGeneratedTestEngine(t, ctx, f, f.selected, input, currentApplyRecipients(f.selected.registry()), installedGeneratedRetirementCallbacks(t, f, process))
			initial := first.Apply(ctx, fixtureID(f.env.Domain, "shared release original CF"), input)
			first.Close()
			if initial.Result.Outcome != ObservedCurrent {
				t.Fatal("original CF did not select", initial.Result)
			}
			before := f.open(t, ctx)
			author := buildInstalledLocalAuthor(t, false)
			row := author.config.Artifact
			local := &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleNone, ConfigContractID: row.ConfigContractID, ResourceContractID: contract.ID{}, Intent: installedLocalCanonicalIntent()}
			remote.Epoch, remote.RetirementMode = 1, contract.GeneratedRetirementAuto
			input = append([]ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "local", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{before.admission.recipient}, Generated: local}}, input...)
			admissions := 0
			mixed := installedLocalEngine(t, ctx, f, before, input, author, &admissions)
			selected := mixed.Apply(ctx, fixtureID(f.env.Domain, "shared release mixed local and CF"), input)
			mixed.Close()
			current := f.open(t, ctx)
			work := mustSelectedGeneratedWork(t, current)
			if selected.Result.Outcome != ObservedCurrent || work.parent != nil || admissions != 3 || current.root.Generated.GeneratedCurrent != 2 || len(work.releases) != 1 {
				t.Fatal("mixed local and automatic CF did not complete with one real DELETE release", selected.Result, admissions, len(work.releases))
			}
			if creates, deletes := effects(); creates != 2 || len(deletes) != 1 {
				t.Fatal("mixed originals did not execute exactly one CF retirement", creates, len(deletes))
			}
			localEntry := current.valueEntry(current.root.Names[0].Slot)
			if localEntry.Name != "local" || localEntry.Generated.OriginOperationID != selected.OperationID {
				t.Fatal("local current did not originate in the shared graph")
			}
			captureInstalledLocalValue(t, ctx, f, current, "local")
			var release generatedReleasedAttempt
			for _, value := range work.releases {
				release = value
			}
			if release.template.Action != contract.GeneratorActionDelete || release.attempt.SemanticLifecycleMode() != contract.GeneratorLifecycleManaged || release.attempt.OperationID != selected.OperationID {
				t.Fatal("release is not the actual CF DELETE from the local origin graph")
			}
			for _, attempt := range work.attempts {
				if attempt.record.SemanticLifecycleMode() == contract.GeneratorLifecycleNone {
					t.Fatal("terminal automatic close retained a local CREATE consumer")
				}
			}
			evidence := work.records[generatedRecordKey{contract.GeneratedCreateEvidenceSupportKind, localEntry.Generated.CreateResultID}]
			decoded, err := contract.DecodeGeneratedCreateEvidence(evidence.Body)
			if err != nil {
				t.Fatal(err)
			}
			core, err := contract.InspectGeneratedResultCore(decoded.ResultCore)
			if err != nil {
				t.Fatal(err)
			}
			graphKey := generatedContentKey{contract.GeneratorContentGraph, core.PlanGraphID}
			graph, exists := work.content.locations[graphKey]
			if !exists {
				t.Fatal("release lost its exact shared original graph")
			}
			attemptRow := work.records[generatedRecordKey{contract.GeneratedAttemptSupportKind, release.attempt.AttemptID}]
			releaseRow := work.records[generatedRecordKey{contract.PendingInboxReleaseSupportKind, release.release.InboxID}]
			if successor == "ordinary capacity" {
				current = receiptCapacityLifecycleCheckpoint(t, ctx, f, current, input, author, &admissions, effects)
				current = receiptCapacityPressureColdState(t, ctx, f, current)
				capacityInput := current.currentEntryInputs()
				capacityInput = slices.DeleteFunc(capacityInput, func(entry ApplyEntryInput) bool { return entry.Name == "local" })
				checkProspectiveReceiptCapacity(t, ctx, f, current, capacityInput, 1, process.Implementation)
				checkProspectiveReceiptCapacity(t, ctx, f, current, nil, 0, process.Implementation)
			}
			input = input[1:]
			if successor == "generated CF" {
				remote.Epoch, remote.RetirementMode = 2, contract.GeneratedRetirementManual
			}
			last := installedLocalEngine(t, ctx, f, current, input, author, &admissions)
			result := last.Apply(ctx, fixtureID(f.env.Domain, "remove local after shared CF DELETE release "+successor), input)
			last.Close()
			if result.Result.Outcome != ObservedCurrent {
				t.Fatal("removing the last local current consumer refused beside release-only graph", result.Result)
			}
			after := f.open(t, ctx)
			if !after.root.Generated.ActiveOwner.IsZero() || after.root.Generated.GeneratedCurrent != 1 || len(after.root.Names) != 1 || after.root.Names[0].Name != "remote" {
				t.Fatal("removing local beside a shared release did not complete the successor selection")
			}
			remaining := mustSelectedGeneratedWork(t, after)
			if _, present := remaining.records[generatedRecordKey{contract.GeneratedCreateEvidenceSupportKind, localEntry.Generated.CreateResultID}]; present {
				t.Fatal("removed local current retained detached evidence")
			}
			if _, present := remaining.content.locations[generatedContentKey{contract.GeneratorContentIntent, localEntry.Generated.IntentDigest}]; present {
				t.Fatal("release-only graph retained the dead local intent")
			}
			if remaining.content.locations[graphKey] != graph || !bytes.Equal(remaining.records[generatedRecordKey{attemptRow.Kind, attemptRow.RecordID}].Body, attemptRow.Body) || !bytes.Equal(remaining.records[generatedRecordKey{releaseRow.Kind, releaseRow.RecordID}].Body, releaseRow.Body) {
				t.Fatal("local removal changed independent CF release graph, Attempt or release")
			}
			want := 3
			if successor == "generated CF" {
				want++
			}
			if admissions != want || after.root.Generated.GeneratedCurrent != 1 || after.root.Generated.Hazards != 0 {
				t.Fatal("local removal entered another local producer or created remote residue", admissions)
			}
		})
	}
}

func installedLocalCanonicalIntent() []byte {
	config := sha256.Sum256([]byte("ENKV/local-random-secret/config/v1"))
	body := []byte{0, 1}
	body = append(body, config[:]...)
	body = append(body, byte(contract.GeneratorLifecycleNone))
	body = append(body, make([]byte, 32)...)
	body = append(body, 0, 0, 0, 2)
	return append(body, []byte(`{}`)...)
}

// full_only: false
func TestInstalledLocalGeneratorRejectsTrailingResultWithRealCompletionProof(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	root := generatorRemovalFixtureRoot(t)
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	author := installedLocalAuthor{config: custody.BuildInstalledTrailingCleanupRefusedLocalAuthor(t, installedLocalPublicRoot(t))}
	declaration := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema,
		LifecycleMode: contract.GeneratorLifecycleNone, ConfigContractID: author.config.Artifact.ConfigContractID, Intent: installedLocalCanonicalIntent()}
	input := []ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "local", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret,
		Recipients: []contract.ID{f.selected.admission.recipient}, Generated: &declaration}}
	admissions, proofs := 0, 0
	engine := installedLocalEngine(t, ctx, f, f.selected, input, author, &admissions, func(qualified bool) {
		if !qualified {
			t.Error("real trailing-result fixture did not retain host completion proof")
		}
		proofs++
	})
	admit := engine.installation.Generated.AdmitProducer
	invocations := 0
	engine.installation.Generated.AdmitProducer = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedProducerInput, implementation contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
		owner, err := admit(ctx, q, control, in, implementation, deadline)
		if err != nil || owner == nil {
			return owner, err
		}
		invoke := owner.InvokeProducer
		owner.InvokeProducer = func(ctx context.Context, locator, authority contract.ID) contract.GeneratedProducerResult {
			returned := invoke(ctx, locator, authority)
			invocations++
			if returned.Code != contract.CryptoCustodyUnavailable || len(returned.Record) != 0 || !reflect.DeepEqual(returned.Facts, contract.GeneratorSafeFacts{}) || returned.ExecutableCleanupFailed {
				t.Error("host completion proof bypassed complete secret-result framing")
			}
			return returned
		}
		return owner, nil
	}
	result := engine.Apply(ctx, fixtureID(f.env.Domain, "reject trailing secret despite real host proof"), input)
	engine.Close()
	assertGeneratorRemovalFixture(t, root)
	if proofs != 1 || invocations != 1 || admissions != 1 {
		t.Fatal("real host and Crypto observations did not belong to one joined invocation", proofs, invocations, admissions)
	}
	for _, diagnostic := range result.Diagnostics {
		if generatorCleanupDiagnostic(diagnostic) {
			t.Error("unqualified secret result exported a completion cleanup fact")
		}
	}
	cold := f.open(t, ctx)
	if cold.root.Generated.GeneratedCurrent != 0 || len(cold.root.Names) != 0 {
		t.Fatal("trailing secret result became a selected local value")
	}
}

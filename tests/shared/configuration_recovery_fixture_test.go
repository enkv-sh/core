package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
	"enkv.sh/crypto/testsupport/installedarchive"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

type configurationRecoveryFixtureInput struct {
	Phase                                      string
	Provider                                   string
	Recovery                                   bool
	Configuration                              string
	Output                                     string
	Setup, Resources, Condition                string
	AuthoritySelector                          string
	Plain                                      bool
	OracleDirectory                            string
	PublicationHistory, PublicationExpectation string
	PublicationContinuation                    string
	PublicationGrant                           publicationLossGrant
}

// full_only: false
func TestConfigurationRecoveryFixtureProcess(t *testing.T) {
	if path := os.Getenv("ENKV_CONFIGURATION_RECOVERY_FIXTURE"); path != "" {
		var input configurationRecoveryFixtureInput
		readConfigurationRecoveryJSONBound(t, path, &input, 64<<10)
		configurationRecoveryFixturePhase(t, input)
		return
	}
	directory := t.TempDir()
	input := configurationRecoveryFixtureInput{Phase: "setup", Provider: "gcp", Configuration: filepath.Join(directory, "configuration.json"), Output: filepath.Join(directory, "remote.json")}
	configurationRecoveryFixturePhase(t, input)
	input.Phase = "writer"
	configurationRecoveryFixturePhase(t, input)
	var carrier installedarchive.RecoveryFixture
	readConfigurationRecoveryJSON(t, input.Output, &carrier)
	var fileBytes uint64
	objects := filepath.Join(directory, "objects")
	if err := os.Mkdir(objects, 0700); err != nil {
		t.Fatal(err)
	}
	for index, object := range carrier.Archive.Objects {
		token, n, err := contract.ParseToken(object.TokenWire)
		if err != nil || n != len(object.TokenWire) {
			t.Fatal("exported token refused")
		}
		path := filepath.Join(objects, fmt.Sprintf("%04d", index))
		if _, err := writeFreshProcessObject(path, object.Key, stored{Token: token, Body: object.Body}); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		fileBytes += uint64(info.Size())
	}
	if fileBytes == 0 || carrier.Archive.ObjectFileBytes != fileBytes {
		t.Fatal("dynamic export differs from actual encoded object-file bytes", carrier.Archive.ObjectFileBytes, fileBytes)
	}
	fixture := installedarchive.ReadRecoveryFixture(t, input.Output)
	if fixture.Archive.ObjectCount <= 10 || len(fixture.Values) != 7 {
		t.Fatal("populated fixture is incomplete")
	}
}

func configurationRecoveryFixturePhase(t *testing.T, input configurationRecoveryFixtureInput) {
	t.Helper()
	family := contract.GCP
	if input.Provider == "aws" {
		family = contract.AWS
	} else if input.Provider != "gcp" {
		t.Fatal("fixture provider refused")
	}
	if input.Condition == "installed-single" && (input.Setup == "" || input.Resources == "" || input.AuthoritySelector == "") {
		t.Fatal("installed single archive requires independently fixed setup and resources")
	}
	deadline := time.Now().Add(time.Minute)
	if input.Condition == "maximum-current-intents" || input.Condition == "near-limit-output" {
		var ok bool
		deadline, ok = t.Deadline()
		if !ok {
			t.Fatal("maximum fixture requires finite component deadline")
		}
	}
	ctx, cancel := context.WithDeadline(t.Context(), deadline)
	defer cancel()
	if input.Phase == "publication-continuation" {
		configurationRecoveryPublicationContinuation(t, ctx, input)
		return
	}
	if input.Phase == "setup" {
		var previous *processFixture
		if input.Condition == "new-domain-no-pin" || input.Condition == "prior-domain-pin" {
			var setup installedarchive.RecoverySetup
			readConfigurationRecoveryJSON(t, input.Setup, &setup)
			if setup.PriorConfiguration.DomainID.IsZero() || setup.PriorConfiguration.DomainID == setup.Domain {
				t.Fatal("separately valid prior DomainID missing")
			}
			prior := input
			prior.Condition, prior.Setup, prior.Configuration = "", input.Setup+"-prior", input.Configuration+"-prior"
			writeConfigurationRecoveryJSON(t, prior.Setup, installedarchive.RecoverySetup{Domain: setup.PriorConfiguration.DomainID, Descriptor: setup.PriorDescriptor, Configuration: setup.PriorConfiguration})
			configurationRecoveryFixturePhase(t, prior)
			previous = new(processFixture)
			readConfigurationRecoveryJSON(t, prior.Configuration, previous)
			if previous.Domain != setup.PriorConfiguration.DomainID {
				t.Fatal("prior Genesis lost independent DomainID")
			}
		}

		// Choose this resource before random domain creation. These test routes
		// reproduce independent provider keys across setup and writer processes.
		normal := testtrust.New(t, family, testID("trust"))
		env, _ := genesisEnvironment(t, family, input.Recovery, 3)
		if (input.Condition == "full-receipt-windows" || input.Condition == "maximum-current-intents") && input.Setup == "" {
			// Keep the fixed test key, with the real provider construction identity
			// required by a fresh public signing anchor before its KMS lookup.
			normal = testtrust.NewWithIdentity(t, family, testID("trust"), publicationLossTrustID(family, contract.NormalSigningRole), contract.NormalSigningRole)
			env.Trust = &fixtureTrust{Signer: normal}
			env.PublicKey, env.SigningSelector = normal.PublicKey(), normal.KeySelector()
		}
		if input.Setup != "" {
			var setup installedarchive.RecoverySetup
			var resources installedarchive.RecoveryResources
			readConfigurationRecoveryJSON(t, input.Setup, &setup)
			readConfigurationRecoveryJSON(t, input.Resources, &resources)
			env = configurationRecoverySetupEnvironment(t, env, setup, resources, input.Recovery)
			normal = testtrust.NewWithIdentity(t, family, resources.Normal.Material, resources.Normal.TrustID, contract.NormalSigningRole)
		}
		if input.AuthoritySelector != "" {
			env.Custody.UseAuthoritySelector(t, input.AuthoritySelector)
			env.Bindings = env.Custody.Bindings()
		}
		if input.Condition == "reader-mixed" || input.Condition == "installed-single" || input.Condition == "administrative-reads" || input.Condition == "full-receipt-windows" || input.Condition == "maximum-current-intents" || input.Condition == "near-limit-output" {
			store := env.Store.(*memoryStore)
			descriptor, err := configurationRecoveryStoreDescriptor(store.configuration)
			if err != nil {
				t.Fatal("Reader fixture provider construction refused", err)
			}
			store.desc = descriptor
		}
		if input.PublicationHistory != "" {
			if input.Condition != "complete" || input.Plain {
				t.Fatal("publication loss requires the complete seven-value fixture")
			}
			env.GenesisIDs = publicationLossAuthorityData(env.Domain)
			wantStore, err := publicationLossDescriptor(env.Store.(*memoryStore).configuration)
			if err != nil || wantStore != env.Store.Descriptor() || env.Trust.Identity() != publicationLossTrustID(family, contract.NormalSigningRole) || input.Recovery && env.Recovery.Identity() != publicationLossTrustID(family, contract.RecoverySigningRole) {
				t.Fatal("initial independent publication authority recipe differs from actual constructor", err)
			}
		}
		if env.SigningSelector != normal.KeySelector() || !bytes.Equal(env.PublicKey, normal.PublicKey()) {
			t.Fatal("setup changed independent signing resource")
		}
		if previous != nil {
			store := env.Store.(*memoryStore)
			store.objects, store.generation = previous.Objects, previous.Generation
			// The external owner reuses this location after removing the old HEAD.
			// Both Genesis selections authenticate before the recovery epoch starts.
			delete(store.objects, store.configuration.PrefixBeforeHEAD+"/HEAD")
		}
		genesis := newEnvironmentFixture(t, ctx, env, nil, false)
		if previous != nil && (genesis.session.root.Domain == previous.Domain) {
			t.Fatal("new Genesis did not change DomainID")
		}
		fixture := selectedProcessFacts(t, genesis.admission, genesis.session)
		store := env.Store.(*memoryStore)
		fixture.Objects, fixture.Generation = store.objects, store.generation
		writeConfigurationRecoveryJSON(t, input.Configuration, fixture)
		if input.Condition == "reader-mixed" || input.Condition == "installed-single" || input.Condition == "administrative-reads" || input.Condition == "full-receipt-windows" || input.Condition == "maximum-current-intents" || input.Condition == "near-limit-output" {
			writeConfigurationRecoveryJSON(t, input.Output+".basis.json", struct {
				Schema     int    `json:"schema"`
				Kind       string `json:"kind"`
				Descriptor []byte `json:"descriptor"`
			}{2, "genesis", fixture.DomainBasis})
		}
		return
	}
	if input.Phase != "writer" {
		t.Fatal("fixture phase refused")
	}
	var saved processFixture
	readConfigurationRecoveryJSON(t, input.Configuration, &saved)
	store := &memoryStore{desc: saved.Descriptor, configuration: saved.Configuration, objects: saved.Objects, generation: saved.Generation}
	admission := processPublicAdmission(saved.Domain, saved.Trust, saved.Descriptor, saved.PublicKey, saved.DomainBasis)
	admission.admission.expires = deadline
	selected, result := Open(ctx, admission, store)
	if selected == nil || result.Outcome != ObservedCurrent || selected.head.AuthKind != format.GenesisAuth {
		t.Fatal("ordinary writer did not admit joined setup Genesis", result)
	}
	recipients := []contract.ID{fixtureID(saved.Domain, "recipient"), fixtureID(saved.Domain, "reader"), fixtureID(saved.Domain, "reader-002")}
	keys := custody.New(t, family, fixtureID(saved.Domain, "custody"), input.Recovery, recipients)
	if input.AuthoritySelector != "" {
		keys.UseAuthoritySelector(t, input.AuthoritySelector)
	}
	var resources installedarchive.RecoveryResources
	normal := testtrust.New(t, family, saved.Trust)
	if input.Condition == "full-receipt-windows" || input.Condition == "maximum-current-intents" {
		normal = testtrust.NewWithIdentity(t, family, testID("trust"), saved.Trust, contract.NormalSigningRole)
	}
	if input.Resources != "" {
		readConfigurationRecoveryJSON(t, input.Resources, &resources)
		normal = testtrust.NewWithIdentity(t, family, resources.Normal.Material, saved.Trust, contract.NormalSigningRole)
		if saved.Trust != resources.Normal.TrustID || normal.KeySelector() != resources.Normal.Selector || !bytes.Equal(normal.PublicKey(), resources.Normal.PublicKey) {
			t.Fatal("writer changed independent normal resource")
		}
	}
	trust := &fixtureTrust{Signer: normal}
	env := fixtureEnvironment{Store: store, Trust: trust, Domain: saved.Domain, PublicKey: trust.PublicKey(), SigningSelector: trust.KeySelector(), Bindings: keys.Bindings(), Crypto: keys.Crypto(), Custody: keys, Context: ctx}
	env.Put = func(_ context.Context, key string, body []byte) error {
		store.mu.Lock()
		defer store.mu.Unlock()
		return store.putSelected(key, body)
	}
	if input.Recovery {
		recovery := testtrust.NewRecovery(t, family, testID("recovery-trust"))
		if input.Resources != "" {
			recovery = testtrust.NewWithIdentity(t, family, resources.Recovery.Material, resources.Recovery.TrustID, contract.RecoverySigningRole)
		}
		env.Recovery, env.RecoveryPublicKey, env.RecoverySelector = recovery, recovery.PublicKey(), recovery.KeySelector()
	}
	run := newScenarioRun(t, ctx, env)
	fixture := &environmentFixture{admission: admission, session: run.open(admission)}
	if input.Condition == "near-limit-output" {
		configurationRecoveryOutputBoundsFixture(t, ctx, input, env, fixture.session, keys)
		return
	}
	if input.Condition == "reader-mixed" {
		configurationRecoveryReaderFixture(t, ctx, input, env, fixture.session, keys)
		return
	}
	if input.Condition == "installed-single" {
		selected := run.suppliedSelection(fixture, []ApplyEntryInput{suppliedSecret(t, env, "installed-positive-secret", "installed single archive", custody.StandardValue, fixture.session.admission.recipient)})
		archive := configurationRecoveryArchive(t, env, selected, store)
		writeConfigurationRecoveryJSON(t, input.Output, installedarchive.RecoveryFixture{Archive: archive, Secrets: 1, Values: []installedarchive.ExpectedValue{{Name: "installed-positive-secret", Bytes: []byte("enkv first secret test value")}}})
		return
	}
	if input.Condition == "administrative-reads" {
		configurationRecoveryAdministrativeFixture(t, ctx, input, env, fixture.session)
		return
	}
	if input.Condition == "maximum-current-intents" {
		configurationRecoveryMaximumCurrentIntents(t, env, fixture, input.Output)
		return
	}
	if input.Condition == "full-receipt-windows" {
		// An ordinary selected Plain row precedes the signed capacity fixture.
		// The terminal history is synthetic; this does not execute its 512 operations.
		run.suppliedSelection(fixture, []ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "seed", Recipients: []contract.ID{fixture.session.admission.recipient}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte{0}}})
		windows := seedBothFullReceiptWindows(t, env, fixture)
		indexes := contract.MutationReceiptIndexes{Order: slices.Clone(windows.Order)}
		for _, row := range windows.Successes {
			indexes.Successes = append(indexes.Successes, row.OperationID)
		}
		for _, row := range windows.Failures {
			indexes.Failures = append(indexes.Failures, row.OperationID)
		}
		if len(indexes.Successes) != 256 || len(indexes.Failures) != 256 || len(indexes.Order) != 512 {
			t.Fatal("signed full receipt window fixture dimensions differ")
		}
		binding, eligible := candidateSelectionSignature(fixture.session.head, fixture.session.root, contract.NormalSigningRole)
		canonicalTrust := binding.Binding.Trust == publicationLossTrustID(family, contract.NormalSigningRole)
		independentResource := binding.KeySelector == normal.KeySelector() && bytes.Equal(binding.SPKI, normal.PublicKey())
		if !eligible || !canonicalTrust || !independentResource {
			t.Fatalf("full-window public candidate invalid: proof=%t canonical_trust=%t independent_resource=%t", eligible, canonicalTrust, independentResource)
		}
		archive := configurationRecoveryArchive(t, env, fixture.session, store)
		writeConfigurationRecoveryJSON(t, input.Output, installedarchive.RecoveryFixture{Archive: archive, Values: []installedarchive.ExpectedValue{{Name: "seed", Bytes: []byte{0}}}})
		writeConfigurationRecoveryJSON(t, input.Output+".index.json", indexes)
		return
	}

	if input.Condition == "zero-secret-genesis" {
		archive := configurationRecoveryArchive(t, env, fixture.session, store)
		writeConfigurationRecoveryJSON(t, input.Output, installedarchive.RecoveryFixture{Archive: archive})
		return
	}
	if input.Condition == "generated-retiring" || input.Condition == "generated-uncertain" {
		selected := configurationRecoveryRetiring(t, ctx, env, fixture.session, input.Condition == "generated-uncertain")
		archive := configurationRecoveryArchive(t, env, selected, store)
		writeConfigurationRecoveryJSON(t, input.Output, installedarchive.RecoveryFixture{Archive: archive, Values: []installedarchive.ExpectedValue{{Name: "generated-alpha", Bytes: []byte("enkv first secret test value")}}, Secrets: 1})
		return
	}
	plain := []byte{0, 255, 1, 128}

	selected = configurationRecoveryPopulate(t, ctx, run, fixture, input.Condition, !input.Plain)

	values := map[string][]byte{"": plain, "plain-Ю": []byte("value-Ю"), "supplied-shared": []byte("enkv first secret test value"), "supplied-empty": {}, "generated-alpha": []byte("enkv first secret test value"), "generated-omega": []byte("enkv first secret test value")}
	binary := make([]byte, contract.CryptoMaxRawValue)
	for i := range binary {
		binary[i] = byte(i % 251)
	}
	values["supplied-binary"] = binary
	secrets := 5
	if input.Plain {
		delete(values, "generated-alpha")
		delete(values, "generated-omega")
		secrets = 3
	}
	if input.Condition == "generated-active" {
		delete(values, "generated-alpha")
		delete(values, "generated-omega")
		secrets = 3
	}
	var expected []installedarchive.ExpectedValue
	for name, value := range values {
		expected = append(expected, installedarchive.ExpectedValue{Name: name, Bytes: value})
	}
	slices.SortFunc(expected, func(a, b installedarchive.ExpectedValue) int { return strings.Compare(a.Name, b.Name) })
	fixture.session = selected
	if input.Condition == "reader-replacement" {
		replaceReaderInSelectedForName(t, ctx, run, fixture, "supplied-shared")
		selected = fixture.session
	}
	if history, ok := installedarchive.ReplacementFor(input.Condition); ok {
		var resources installedarchive.RecoveryResources
		readConfigurationRecoveryJSON(t, input.Resources, &resources)
		configurationRecoveryReplace(t, ctx, &env, fixture, history, resources)
		selected = fixture.session
		if history.LaterHEAD {
			selected = configurationRecoveryLaterHEAD(t, ctx, env, fixture)
			for i := range expected {
				if expected[i].Name == "plain-Ю" {
					expected[i].Bytes = []byte("later-value-Ю")
				}
			}
		}
	}
	if input.PublicationHistory != "" {
		selected = configurationRecoveryPublicationHistory(t, ctx, env, fixture.admission, selected, input.PublicationHistory, input.PublicationExpectation)
	}
	archive := configurationRecoveryArchive(t, env, selected, store)
	carrier := installedarchive.RecoveryFixture{Archive: archive, Values: expected, Secrets: secrets}
	if input.OracleDirectory != "" {
		carrier.Values = nil
		carrier.Oracles = configurationRecoveryCapture(t, ctx, selected, env.Custody, input.OracleDirectory)
	}
	writeConfigurationRecoveryJSON(t, input.Output, carrier)
}

func configurationRecoveryGenerated(t testing.TB, ctx context.Context, env fixtureEnvironment, selected *StateSession, condition string, profiles ...generatedFixtureProfile) *StateSession {
	t.Helper()
	profile := defaultGeneratedFixtureProfile()
	if len(profiles) > 1 {
		t.Fatal("generated recovery fixture requires one profile")
	}
	if len(profiles) == 1 {
		profile = profiles[0]
	}
	sources, canonical := generatedCurrentDeclaration(t, selected)
	input := generatedPlanInputForGenerations(t, selected, generatedVectorID(10), []string{"generated-alpha", "generated-omega"}, profile, sources...)
	if live := env.GeneratedProcess; live != nil {
		liveProfile := liveGeneratedProfile(t, live.Implementation, contract.GeneratedRetirementManual)
		liveProfile.InputEncoding = profile.InputEncoding
		input = generatedPlanInputForGenerationsIntent(t, selected, generatedVectorID(10), []string{"generated-alpha", "generated-omega"}, live.Intent, liveProfile, sources...)
		for i := range input.requestBindings {
			input.requestBindings[i].Digest = live.RequestDigest
		}
	}
	reservation, _ := preparePrivateGeneratedReservation(t, env, selected, input, canonical)
	if condition == "generated-active" {
		var producer *generatedPreparation
		var expected contract.GeneratorResultExpectation
		if live := env.GeneratedProcess; live != nil {
			producer, expected = preparePrivateGeneratedProcessProducerWithConfig(t, env, selected, reservation, live.Artifact, live.Configure)
			if live.BeforeCreate != nil {
				if err := live.BeforeCreate(expected.Template.AttemptID); err != nil {
					t.Fatal("generated create ledger refused", err)
				}
			}
		} else {
			producer, expected = preparePrivateGeneratedProducer(t, env, selected, reservation, nil)
		}
		sends := 0
		if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
			sends++
			packet, facts, outcome := env.Custody.InvokeGeneratedProducerOutcome(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
			code := outcome.Code
			if live := env.GeneratedProcess; live != nil {
				if live.ObserveOutcome != nil {
					live.ObserveOutcome(outcome)
				}
				if len(facts.ResourceData) > 0 && live.AfterCreate != nil {
					if err := live.AfterCreate(expected.Template.AttemptID, facts); err != nil {
						t.Fatal("generated create ledger refused", err)
					}
				}
			}
			clear(packet)
			return code
		}) {
			t.Fatal("pending generated handoff refused")
		}
		current, result := selected.selectCandidate(ctx, producer.reservation.candidate)
		env.Custody.RetireGenerated()
		if current == nil || result.Outcome != ObservedCurrent || current.root.Generated.ActiveOwner.IsZero() || sends != 1 {
			t.Fatal("pending generated selected state missing", result)
		}
		return current
	}
	ids := [2]contract.ID{input.requestBindings[0].AttemptID, input.requestBindings[1].AttemptID}
	current, first, second, firstBody, secondBody := runParallelGeneratedCreates(t, ctx, env, selected, reservation, ids, custody.StandardValue)
	for i, returned := range []struct {
		expectation contract.GeneratorResultExpectation
		body        []byte
	}{{first, firstBody}, {second, secondBody}} {
		env.Custody.RetireGenerated()
		operation := generatedPlanInputFixture(t, current).context
		operation.AdmissionID, operation.SessionID = testID(fmt.Sprintf("recovery record admission-%d", i)), testID(fmt.Sprintf("recovery record session-%d", i))
		plan, err := current.generatedRecordRequest(context.Background(), returned.expectation.Template.AttemptID, returned.body, operation)
		if err != nil {
			t.Fatal(err)
		}
		prepared := preparePrivateGeneratedRecord(t, env, current, plan)
		var result Result
		current, result = current.selectCandidate(ctx, prepared.reservation.candidate)
		if current == nil || result.Outcome != ObservedCurrent {
			t.Fatal("recovery generated record", result)
		}
	}
	env.Custody.RetireGenerated()
	operation := generatedPlanInputFixture(t, current).context
	operation.AdmissionID, operation.SessionID = testID("recovery final admission"), testID("recovery final session")
	plan, err := current.generatedFinalRequest(ctx, operation)
	if err != nil {
		t.Fatal(err)
	}
	current, prepared := preparePrivateGeneratedFinal(t, env, current, plan)
	current, result := current.selectCandidate(ctx, prepared.reservation.candidate)
	if current == nil || result.Outcome != ObservedCurrent || current.root.Generated.GeneratedCurrent != 2 {
		t.Fatal("recovery generated final", result)
	}
	env.Custody.RetireGenerated()
	return current
}

func configurationRecoveryArchive(t testing.TB, env fixtureEnvironment, selected *StateSession, store *memoryStore) installedarchive.Archive {
	t.Helper()
	configuration := store.configuration
	location := contract.StoreLocation{Provider: configuration.Provider, Region: configuration.Region, Bucket: configuration.Bucket, PrefixBeforeHEAD: configuration.PrefixBeforeHEAD, ExpectedOwner: configuration.ExpectedOwner}
	archive := configurationRecoveryArchiveMetadata(t, env, selected, location)
	var keys []string
	for key := range store.objects {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := store.objects[key]
		token, err := contract.AppendToken(nil, value.Token)
		if err != nil {
			t.Fatal(err)
		}
		archive.Objects = append(archive.Objects, installedarchive.Object{Key: key, TokenWire: token, Body: bytes.Clone(value.Body), BodySHA256: fmt.Sprintf("%x", sha256.Sum256(value.Body))})
	}
	return configurationRecoveryArchiveWithObjects(archive, archive.Objects)
}

func configurationRecoveryArchiveWithObjects(archive installedarchive.Archive, objects []installedarchive.Object) installedarchive.Archive {
	archive.Objects, archive.ObjectCount, archive.ObjectFileBytes = objects, len(objects), 0
	for _, object := range objects {
		archive.ObjectFileBytes += uint64(28) + uint64(len(object.Key)) + uint64(len(object.TokenWire)) + uint64(len(object.Body))
	}
	return archive
}

func writeConfigurationRecoveryJSON(t testing.TB, path string, value any) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
}

func readConfigurationRecoveryJSON(t testing.TB, path string, value any) {
	t.Helper()
	readConfigurationRecoveryJSONBound(t, path, value, 64<<20)
}

func readConfigurationRecoveryJSONBound(t testing.TB, path string, value any, maximum int64) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("fixture input unavailable")
	}
	body, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(body)) > maximum {
		t.Fatal("fixture input bound refused")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		t.Fatal(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatal("fixture trailing input")
	}
}

func configurationRecoveryPopulate(t testing.TB, ctx context.Context, run *scenarioRun, fixture *environmentFixture, condition string, generated bool) *StateSession {
	t.Helper()
	env := run.env
	authority, reader := fixture.session.admission.recipient, fixtureID(env.Domain, "reader")
	shared := []contract.ID{authority, reader}
	slices.SortFunc(shared, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	inputs := []ApplyEntryInput{
		{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "", Recipients: []contract.ID{authority}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte{0, 255, 1, 128}},
		{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "plain-Ю", Recipients: []contract.ID{authority}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("value-Ю")},
		suppliedSecret(t, env, "supplied-shared", "recovery shared", custody.StandardValue, shared...),
		suppliedSecret(t, env, "supplied-empty", "recovery empty", custody.EmptyValue),
		suppliedSecret(t, env, "supplied-binary", "recovery binary", custody.MaximumValue),
	}
	if condition == "later-secret-denied" && !generated {
		inputs = append(inputs, suppliedSecret(t, env, "supplied-later-a", "recovery later a", custody.StandardValue), suppliedSecret(t, env, "supplied-later-b", "recovery later b", custody.EmptyValue))
	}
	run.suppliedSelection(fixture, inputs)
	selected := fixture.session
	if generated {
		selected = configurationRecoveryGenerated(t, ctx, env, selected, condition)
	}
	fixture.session = selected
	return selected
}

func configurationRecoveryArchiveMetadata(t testing.TB, env fixtureEnvironment, selected *StateSession, location contract.StoreLocation) installedarchive.Archive {
	t.Helper()
	control, ok := selected.selectedControl()
	if !ok {
		t.Fatal("fixture control missing")
	}
	return installedarchive.Archive{ArchiveVersion: 1, Family: location.Provider, Domain: env.Domain, Location: location,
		SignerID: env.Trust.Identity(), SignerSelector: control.NormalSigning.KeySelector, SignerPublicKey: control.NormalSigning.SPKI,
		CustodyID: fixtureID(env.Domain, "custody"), AuthorityID: control.AuthorityRecipientID, AuthorityBinding: control.AuthorityKMSBinding,
		HeadDigest: contract.Hash(selected.body), Revision: selected.head.Core.Revision}
}

func configurationRecoveryCapture(t testing.TB, ctx context.Context, selected *StateSession, keys *custody.Fixture, directory string) []installedarchive.PrivateValue {
	t.Helper()
	var oracles []installedarchive.PrivateValue
	for index, named := range selected.root.Names {
		entry := selected.valueEntry(named.Slot)
		path := filepath.Join(directory, fmt.Sprintf("value-%04d.private", index))
		length := uint32(len(entry.ValueBytes))
		if entry.ConfidentialityClass == contract.Plain {
			if err := custody.CapturePublicValue(path, entry.ValueBytes); err != nil {
				t.Fatal("public oracle capture failed", err)
			}
		} else {
			selection := sessionConsumerSelection(t, selected, selected.admission.recipient, entry.Name)
			check := keys.CaptureSelected(ctx, selection, path)
			if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched || check.SinkCalls != 1 {
				t.Fatal("private selected oracle capture failed", check)
			}
			length = selection.Core.ContentLength
		}
		oracles = append(oracles, installedarchive.PrivateValue{Name: entry.Name, Path: path, Length: length})
	}
	return oracles
}

func configurationRecoverySetupEnvironment(t testing.TB, env fixtureEnvironment, setup installedarchive.RecoverySetup, resources installedarchive.RecoveryResources, enabled bool) fixtureEnvironment {
	t.Helper()
	if setup.Domain.IsZero() || setup.Domain != setup.Configuration.DomainID || setup.Descriptor.Family != setup.Configuration.Provider || resources.Location.Provider != setup.Configuration.Provider {
		t.Fatal("recovery setup constructor facts differ")
	}
	env.Domain, env.GenesisIDs.Domain = setup.Domain, setup.Domain
	store := env.Store.(*memoryStore)
	store.desc, store.configuration = setup.Descriptor, setup.Configuration
	recipients := []contract.ID{fixtureID(env.Domain, "recipient"), fixtureID(env.Domain, "reader"), fixtureID(env.Domain, "reader-002")}
	keys := custody.New(t, setup.Configuration.Provider, fixtureID(env.Domain, "custody"), enabled, recipients)
	env.Custody, env.Bindings, env.Crypto, env.AdmitInit, env.RetireInit = keys, keys.Bindings(), keys.Crypto(), keys.AdmitInit, keys.RetireInit
	trust := testtrust.NewWithIdentity(t, setup.Configuration.Provider, resources.Normal.Material, resources.Normal.TrustID, contract.NormalSigningRole)
	if trust.KeySelector() != resources.Normal.Selector || !bytes.Equal(trust.PublicKey(), resources.Normal.PublicKey) {
		t.Fatal("independent normal resource changed")
	}
	env.Trust = &fixtureTrust{Signer: trust}
	env.PublicKey, env.SigningSelector = trust.PublicKey(), trust.KeySelector()
	if enabled {
		recovery := testtrust.NewWithIdentity(t, setup.Configuration.Provider, resources.Recovery.Material, resources.Recovery.TrustID, contract.RecoverySigningRole)
		if recovery.KeySelector() != resources.Recovery.Selector || !bytes.Equal(recovery.PublicKey(), resources.Recovery.PublicKey) {
			t.Fatal("independent recovery resource changed")
		}
		env.Recovery, env.RecoveryPublicKey, env.RecoverySelector = recovery, recovery.PublicKey(), recovery.KeySelector()
	}
	return env
}

func configurationRecoveryLaterHEAD(t testing.TB, ctx context.Context, env fixtureEnvironment, fixture *environmentFixture) *StateSession {
	t.Helper()
	before := fixture.session
	run := newScenarioRun(t, ctx, env)
	fixture.session = run.open(fixture.admission)
	shared := []contract.ID{fixture.session.admission.recipient, fixtureID(env.Domain, "reader")}
	slices.SortFunc(shared, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	inputs := before.currentEntryInputs()
	for i := range inputs {
		switch inputs[i].Name {
		case "plain-Ю":
			inputs[i].InputBytes = []byte("later-value-Ю")
		case "supplied-shared":
			inputs[i] = suppliedSecret(t, env, "supplied-shared", "later shared", custody.StandardValue, shared...)
		case "supplied-empty":
			inputs[i] = suppliedSecret(t, env, "supplied-empty", "later empty", custody.EmptyValue)
		case "supplied-binary":
			inputs[i] = suppliedSecret(t, env, "supplied-binary", "later binary", custody.MaximumValue)
		}
	}
	run.suppliedSelection(fixture, inputs)
	selected := fixture.session
	for _, named := range before.root.Names {
		entry := before.valueEntry(named.Slot)
		if entry.ValueSource != contract.Generated {
			continue
		}
		current := selected.valueEntry(named.Slot)
		if current == nil || entry.Generated != current.Generated || !bytes.Equal(entry.ValueBytes, current.ValueBytes) || entry.ValueState != current.ValueState || !slices.Equal(entry.Recipients, current.Recipients) {
			t.Fatal("later ordinary HEAD changed current generated value/settings")
		}
	}
	return selected
}

// This external test authority recipe exists before Genesis. It can be issued
// again after loss; neither returned enrollment nor an old local basis issues it.
func publicationLossAuthorityData(domain contract.ID) genesisIDs {
	return genesisIDs{Domain: domain, Init: fixtureID(domain, "publication loss init"),
		DescriptorArtifact: fixtureID(domain, "publication loss descriptor artifact"),
		ManifestArtifact:   fixtureID(domain, "publication loss manifest artifact")}
}

func configurationRecoveryConstruction(purpose string, fields ...string) contract.ID {
	b := []byte(purpose)
	for _, field := range fields {
		b = binary.BigEndian.AppendUint32(b, uint32(len(field)))
		b = append(b, field...)
	}
	return sha256.Sum256(b)
}

func publicationLossTrustID(family contract.Family, role uint8) contract.ID {
	if family == contract.AWS {
		return configurationRecoveryConstruction("", "aws-kms-p256-v1", "kms.us-east-1.amazonaws.com", "ECC_NIST_P256", "SIGN_VERIFY", "ECDSA_SHA_256", "DIGEST", fmt.Sprint(role))
	}
	return configurationRecoveryConstruction("ENKV/GCP-CONSTRUCTION/v1\x00", "gcp-cloudkms-p256-v1", "us-central1", "https://us-central1-cloudkms.googleapis.com/", "EC_SIGN_P256_SHA256", "ASYMMETRIC_SIGN", fmt.Sprint(role))
}

func publicationLossLocation(family contract.Family) contract.StoreLocation {
	l := contract.StoreLocation{Provider: family, Region: "us-east-1", Bucket: "fixture-bucket", PrefixBeforeHEAD: "fixture", ExpectedOwner: "123456789012"}
	if family == contract.GCP {
		l.Region, l.ExpectedOwner = "australia-southeast1", ""
	}
	return l
}

func publicationLossDescriptor(configuration contract.StoreConfiguration) (contract.Descriptor, error) {
	l := publicationLossLocation(configuration.Provider)
	if configuration.Region != l.Region || configuration.Bucket != l.Bucket || configuration.PrefixBeforeHEAD != l.PrefixBeforeHEAD || configuration.ExpectedOwner != l.ExpectedOwner {
		return contract.Descriptor{}, contract.ErrSubject
	}
	return configurationRecoveryStoreDescriptor(configuration)
}

// Native fixture archives use the existing provider construction framing. The
// publication-loss caller retains its separate fixed-location policy above.
func configurationRecoveryStoreDescriptor(configuration contract.StoreConfiguration) (contract.Descriptor, error) {
	id, err := contract.StoreConfigurationID(configuration)
	if err != nil {
		return contract.Descriptor{}, err
	}
	d := contract.Descriptor{Family: configuration.Provider, Identity: id, Prefix: configuration.PrefixBeforeHEAD, HeadKey: configuration.PrefixBeforeHEAD + "/HEAD"}
	if configuration.Provider == contract.AWS {
		d.Coordinate = configurationRecoveryConstruction("", "aws-s3-regional-v2", "s3."+configuration.Region+".amazonaws.com", configuration.Bucket, d.HeadKey, fmt.Sprintf("%x", configuration.DomainID))
		d.NonBody = configurationRecoveryConstruction("", "aws-s3-regional-v2", "PUT", "application/octet-stream", configuration.ExpectedOwner, "sha256", "fixed-content-length", "path-style", "single-attempt", "no-cache-transform")
	} else {
		endpoint := "https://storage." + configuration.Region + ".rep.googleapis.com/storage/v1/"
		d.Coordinate = configurationRecoveryConstruction("ENKV/GCP-CONSTRUCTION/v2\x00", "gcp-gcs-json-v2", "HEAD", endpoint, configuration.Bucket, d.HeadKey, fmt.Sprintf("%x", configuration.DomainID))
		d.NonBody = configurationRecoveryConstruction("ENKV/GCP-CONSTRUCTION/v2\x00", "gcp-gcs-json-v2", "JSON-MULTIPART-INSERT/v1", endpoint, configuration.Bucket, "ifGenerationMatch", "application/octet-stream", "private, no-store, no-transform", "crc32c", "one-send")
	}
	return d, nil
}

func publicationLossTarget(history string) outputApplyTarget {
	slot := "secret-target-publication-loss-" + history
	return outputApplyTarget{entryName: "supplied-shared", target: contract.OutputTarget{ServiceContractID: "test-output/service/v1", TargetContractID: "test-output/target/v1", CanonicalTarget: slot, ConsumerLocator: slot, TargetData: []byte("target:" + slot), PayloadEncoding: contract.OutputEncodingRaw, Capabilities: contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot | contract.OutputCapabilityCreateSetsPolicy | contract.OutputCapabilityWriteSetsPolicy, CreateValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, Policy: contract.OutputPolicy{ContractID: "test-policy", Data: []byte("1,9")}}}
}

func publicationLossNamespace(domain contract.ID, history string) publicationNamespace {
	target := publicationLossTarget(history).target
	return publicationNamespace{domain: domain, service: target.ServiceContractID, physical: target.CanonicalTarget, premise: fixtureID(domain, "fresh independent publication namespace "+history)}
}

type publicationLossExpectation struct {
	History       string
	Configuration contract.OutputConfiguration
	Coordinate    contract.PublicationCoordinate
	Markers       []contract.PublicationMarker
	Order         []format.PublicationCoordinateOrder
	WarningBits   uint8
}

// A successful native action can lose its result before Core sees it. This
// wrapper preserves the real one-send call and suppresses only its reply proof.
type publicationLossOwner struct {
	publicationPrivateOwner
	input                          publicationOwnerInput
	loseReply                      bool
	prepared, armed, sent, retired int
}

func (o *publicationLossOwner) Prepare(ctx context.Context, id contract.ID, selection *contract.ConsumerSelection) ([]contract.KeyUseRow, contract.CryptoResultCode) {
	o.prepared++
	return o.publicationPrivateOwner.Prepare(ctx, id, selection)
}
func (o *publicationLossOwner) Arm(ctx context.Context, id contract.ID, d contract.PublicationDispatch) error {
	o.armed++
	return o.publicationPrivateOwner.Arm(ctx, id, d)
}
func (o *publicationLossOwner) Send(ctx context.Context, id contract.ID) (contract.PublicationResult, contract.CryptoResultCode) {
	o.sent++
	r, code := o.publicationPrivateOwner.Send(ctx, id)
	if o.loseReply && code == contract.CryptoSuccess {
		r.Evidence.Class = contract.PublicationUnproved
		r.Evidence.NormalizedStatus, r.Evidence.SafeResourceID, r.Evidence.SafeRequestID = 0, "", ""
		r.Evidence.ConsumerLocator = ""
	}
	return r, code
}
func (o *publicationLossOwner) Retire(ctx context.Context) error {
	o.retired++
	return o.publicationPrivateOwner.Retire(ctx)
}

func publicationLossPrivate(base publicationPrivate, loseReply bool, owners *[]*publicationLossOwner) publicationPrivate {
	p := base
	p.NewOwner = func(ctx context.Context, input publicationOwnerInput) (publicationPrivateOwner, error) {
		o, err := base.NewOwner(ctx, input)
		if err != nil {
			return nil, err
		}
		wrapped := &publicationLossOwner{publicationPrivateOwner: o, input: input, loseReply: loseReply}
		*owners = append(*owners, wrapped)
		return wrapped, nil
	}
	return p
}

func publicationLossExecute(t *testing.T, ctx context.Context, env fixtureEnvironment, admitted OpenContext, selected *StateSession, input publicationInput, history string, loseReply bool) (*StateSession, contract.PublicationTargetOutcome, *publicationLossOwner) {
	t.Helper()
	generated := publicationLossGeneratedFacts(t, selected)
	var owners []*publicationLossOwner
	private := publicationLossPrivate(publicationCustodyPrivate(env.Custody), loseReply, &owners)
	plan, r := selected.planPublication(ctx, input, private)
	if plan == nil {
		t.Fatalf("publication loss plan outcome=%d reason=%d", r.Outcome, r.Reason)
	}
	var expectedMarker contract.PublicationMarker
	var expectedCreate *contract.PublicationCoordinate
	if len(input.deletes) != 0 {
		expectedMarker = publicationLossExpectedDelete(t, selected, plan, input, loseReply)
	} else {
		var coordinate contract.PublicationCoordinate
		expectedMarker, coordinate = publicationLossExpectedCreate(t, selected, plan, input, history, loseReply)
		expectedCreate = &coordinate
	}
	got := plan.execute(ctx, private, func(ctx context.Context) (*StateSession, contract.Trust, Result) {
		s, r := Open(ctx, admitted, env.Store)
		return s, env.Trust, r
	})
	if len(got.output.Entries) != 1 || len(got.output.Entries[0].Actions) != 1 || len(owners) != 1 {
		t.Fatalf("publication loss action set entries=%d owners=%d state=%+v", len(got.output.Entries), len(owners), got.state)
	}
	want := uint8(contract.PublicationOutcomeAcknowledged)
	if loseReply {
		want = contract.PublicationOutcomeUnknown
	}
	row, o := got.output.Entries[0], owners[0]
	wantSummary := uint8(contract.PublicationSummaryComplete)
	if loseReply {
		wantSummary = contract.PublicationSummaryUnknown
	}
	if got.state.Outcome != ObservedCurrent || got.summary != wantSummary || row.Actions[0].Disposition != want || row.Actions[0].AttemptID.IsZero() || o.prepared != 1 || o.armed != 1 || o.sent != 1 || o.retired != 1 {
		t.Fatalf("publication loss result disposition=%d want=%d prepare=%d arm=%d send=%d retire=%d", row.Actions[0].Disposition, want, o.prepared, o.armed, o.sent, o.retired)
	}
	s, r := Open(ctx, admitted, env.Store)
	if s == nil || r.Outcome != ObservedCurrent {
		t.Fatal("publication loss reopen", r)
	}
	publicationLossAssertGeneratedFacts(t, s, generated)
	relation, err := selectedPublicationRelation(s.selectedImage())
	if err != nil {
		t.Fatal("publication loss selected action relation", err)
	}
	publicationLossAssertMarker(t, relation.markers[expectedMarker.AttemptID], expectedMarker)
	if row.CoordinateID != expectedMarker.CoordinateID || row.Actions[0].Action != expectedMarker.Projection.Action || row.Actions[0].AttemptID != expectedMarker.AttemptID || !slices.Equal(row.Actions[0].BlockerIDs, input.republish[expectedMarker.CoordinateID]) {
		t.Fatal("publication loss returned action/Attempt/blockers differ from fixed reservation")
	}
	if expectedCreate != nil {
		actual := relation.coordinates[expectedMarker.CoordinateID]
		if !reflect.DeepEqual(actual, *expectedCreate) {
			av, ev := reflect.ValueOf(actual), reflect.ValueOf(*expectedCreate)
			for i := 0; i < av.NumField(); i++ {
				if !reflect.DeepEqual(av.Field(i).Interface(), ev.Field(i).Interface()) {
					t.Logf("publication loss create coordinate field=%s equal=false", av.Type().Field(i).Name)
				}
			}
			t.Fatalf("publication loss full independent create coordinate differs ordinal=%d owner=%d risk=%d", expectedCreate.LastAdmissionOrdinal, expectedCreate.OwnerState, expectedCreate.LateEffectRisk)
		}
	}
	return s, row, o
}

// Formats field orders and purpose labels, evaluated from fixed caller input and selected
// predecessor before reservation or Send. No successor or production hash helper
// supplies a semantic expectation.
func publicationLossExpectedDelete(t *testing.T, before *StateSession, plan *publicationPlan, input publicationInput, loseReply bool) contract.PublicationMarker {
	t.Helper()
	if len(input.deletes) != 1 || len(plan.targets) != 1 || len(plan.targets[0].actions) != 1 || len(plan.targets[0].attempts) != 1 {
		t.Fatal("publication loss delete is not one selected target/action")
	}
	relation, err := selectedPublicationRelation(before.selectedImage())
	if err != nil {
		t.Fatal("publication loss delete predecessor", err)
	}
	c, present := relation.coordinates[input.deletes[0]]
	if !present || c.LastAdmissionOrdinal == ^uint64(0) {
		t.Fatal("publication loss delete predecessor coordinate/stamp")
	}
	p := plan.targets[0]
	blockers := slices.Clone(input.republish[c.CoordinateID])
	for i, id := range blockers {
		if id.IsZero() || i > 0 && bytes.Compare(blockers[i-1][:], id[:]) >= 0 {
			t.Fatal("publication loss caller blockers are not a complete sorted set")
		}
	}
	if !slices.Equal(p.blockers, blockers) {
		t.Fatal("publication loss planner changed explicit blockers")
	}
	action := uint8(contract.PublicationDeleteOwned)
	if c.OwnerState == contract.PublicationOwnerUncertainCreate {
		action = contract.PublicationDeleteReservedSlot
	} else if c.OwnerState != contract.PublicationOwnerQualified {
		t.Fatal("publication loss delete has no independent owner")
	}
	if p.actions[0] != action || p.coordinate != c.CoordinateID || p.binding != c.LastBindingIncarnationID || p.target.EntryIncarnationID != c.LastEntryIncarnationID || p.target.ServiceContractID != c.ServiceContractID || p.target.CanonicalTarget != c.CanonicalTarget || p.target.ConsumerLocator != c.DeletionConsumerLocator || p.target.TargetContractID != c.DeletionTargetContractID || p.configContractID != c.DeletionConfigContractID || !bytes.Equal(p.target.TargetData, c.DeletionTargetData) || p.target.PayloadEncoding != c.DeletionPayloadEncoding || !reflect.DeepEqual(p.target.Policy, contract.OutputPolicy{}) {
		t.Fatal("publication loss planned delete differs from exact frozen predecessor")
	}
	projection := contract.PublicationProjection{Schema: 4, DomainID: before.root.Domain, ConfigurationDigest: before.root.OutputConfiguration.ConfigurationDigest, CoordinateID: c.CoordinateID, BindingIncarnationID: c.LastBindingIncarnationID, EntryIncarnationID: c.LastEntryIncarnationID, TargetRowDigest: c.DeletionTargetRowDigest, Action: action, ActingRecipientID: input.acting}
	var birthRow contract.ID
	resource := c.CanonicalTarget
	if action == contract.PublicationDeleteOwned {
		projection.OwnedBirthAttemptID = c.OwnedBirthAttemptID
		birth, ok := relation.markers[c.OwnedBirthAttemptID]
		if !ok || birth.State != contract.PublicationAcknowledged || birth.Projection.Action != contract.PublicationCreateWithValue {
			t.Fatal("publication loss delete lacks checked original birth")
		}
		birthRow = birth.Projection.TargetRowDigest
		resource = "test-instance/" + c.CanonicalTarget + "/" + fmt.Sprintf("%x", c.OwnedBirthAttemptID)
	} else {
		var uncertain contract.ID
		for _, marker := range relation.markers {
			if marker.CoordinateID == c.CoordinateID && marker.Projection.Action == contract.PublicationCreateWithValue && marker.State == contract.PublicationUnknown {
				if !uncertain.IsZero() {
					t.Fatal("publication loss ambiguous uncertain birth")
				}
				uncertain = marker.AttemptID
			}
		}
		if uncertain.IsZero() {
			t.Fatal("publication loss reserved delete lacks checked uncertain birth")
		}
		projection.UncertainCreateAttemptID = uncertain
		for _, pin := range before.admission.publicationNamespaces {
			if pin.domain == before.root.Domain && pin.service == c.ServiceContractID && pin.physical == c.CanonicalTarget {
				projection.ExclusiveNamespaceDigest = pin.premise
			}
		}
		if projection.ExclusiveNamespaceDigest.IsZero() {
			t.Fatal("publication loss reserved delete lacks new explicit namespace")
		}
	}
	protocol := sha256.Sum256([]byte("ENKV/OUTPUT-WIRE/v6\x00"))
	config := publicationExpectedHash("ENKV/OUTPUT/CONFIG-CONTRACT/v1", publicationExpectedBlob(nil, []byte(c.DeletionConfigContractID)))
	b := append(append([]byte(nil), protocol[:]...), config[:]...)
	b = publicationExpectedBlob(b, []byte(c.ServiceContractID))
	b = publicationExpectedBlob(b, []byte(c.DeletionTargetContractID))
	projection.RequestContractDigest = publicationExpectedHash("ENKV/OUTPUT/REQUEST-CONTRACT/v2", append(b, action))
	b = binary.BigEndian.AppendUint16(nil, 4)
	for _, id := range []contract.ID{projection.DomainID, projection.ConfigurationDigest, projection.CoordinateID, projection.BindingIncarnationID, projection.EntryIncarnationID, projection.TargetRowDigest} {
		b = append(b, id[:]...)
	}
	b = append(b, action)
	for _, id := range []contract.ID{projection.OwnedBirthAttemptID, projection.UncertainCreateAttemptID, projection.ExclusiveNamespaceDigest, projection.ValueBasisDigest, projection.PolicyDigest, projection.RequestContractDigest, projection.ActingRecipientID} {
		b = append(b, id[:]...)
	}
	commitment := publicationExpectedHash("ENKV/PUBLICATION/PROJECTION/v4", b)
	b = append(append([]byte(nil), projection.RequestContractDigest[:]...), p.facts.ArtifactContractID[:]...)
	for _, n := range []uint16{6, 1, 3} {
		b = binary.BigEndian.AppendUint16(b, n)
	}
	m := contract.PublicationMarker{Schema: 5, DomainID: before.root.Domain, OperationID: plan.operation, AttemptID: p.attempts[0], CoordinateID: c.CoordinateID, PublicationIncarnationID: c.CurrentPublicationIncarnationID, AdmissionOrdinal: c.LastAdmissionOrdinal + 1, Projection: projection, ProjectionCommitment: commitment, ExecutorID: fmt.Sprintf("%x", p.facts.ExecutorID), CredentialRouteID: fmt.Sprintf("%x", p.facts.CredentialRouteID), BlockerCount: uint16(len(blockers)), State: contract.PublicationAcknowledged, LateEffectRisk: c.LateEffectRisk, Evidence: contract.PublicationEvidence{Schema: 3, Entry: contract.PublicationMayHaveEnteredEntry, Class: contract.PublicationRequestAcknowledged, ResponseContractDigest: publicationExpectedHash("ENKV/OUTPUT/RESPONSE-CONTRACT/v2", b), NormalizedStatus: 204, SafeResourceID: resource}}
	if len(blockers) > 0 {
		b = binary.BigEndian.AppendUint16(nil, uint16(len(blockers)))
		for _, id := range blockers {
			b = append(b, id[:]...)
		}
		m.BlockerDigest = publicationExpectedHash("ENKV/PUBLICATION/BLOCKERS/v2", b)
	}
	if len(blockers) > 0 || before.root.WarningBits&(WarningPublicationOrderValue|WarningDiscardedExactEvidence) != 0 {
		m.LateEffectRisk = 1
	}
	if loseReply {
		m.State = contract.PublicationUnknown
		m.LateEffectRisk = 1
		m.Evidence.Class = contract.PublicationUnproved
		m.Evidence.NormalizedStatus = 0
		m.Evidence.SafeResourceID = ""
		m.Evidence.ConsumerLocator = ""
	}
	m.AuthoritySubjectDigest = publicationLossExpectedAuthority(before, m, birthRow)
	return m
}

// The operation and predecessor selection are fixed before Reserve. The
// result's status/resource and the later signed HEAD are not admission inputs.
func publicationLossExpectedAuthority(before *StateSession, m contract.PublicationMarker, birthRow contract.ID) contract.ID {
	projection := m.Projection
	b := binary.BigEndian.AppendUint16(nil, 5)
	b = append(b, m.Projection.Action)
	for _, id := range []contract.ID{m.DomainID, m.OperationID, m.AttemptID, before.head.Core.Revision, sha256.Sum256(before.body)} {
		b = append(b, id[:]...)
	}
	b = append(b, byte(before.token.Family))
	b = publicationExpectedBlob(b, []byte(before.token.Value))
	for _, id := range []contract.ID{before.root.CurrentAccess.AccessRoot, projection.ConfigurationDigest, m.CoordinateID, m.PublicationIncarnationID} {
		b = append(b, id[:]...)
	}
	b = binary.BigEndian.AppendUint64(b, m.AdmissionOrdinal)
	for _, id := range []contract.ID{projection.BindingIncarnationID, projection.EntryIncarnationID, projection.TargetRowDigest, birthRow, projection.OwnedBirthAttemptID, projection.UncertainCreateAttemptID, projection.ExclusiveNamespaceDigest, projection.ValueBasisDigest, projection.PolicyDigest, projection.RequestContractDigest} {
		b = append(b, id[:]...)
	}
	b = binary.BigEndian.AppendUint16(b, m.BlockerCount)
	b = append(b, m.BlockerDigest[:]...)
	b = append(b, m.ProjectionCommitment[:]...)
	b = publicationExpectedBlob(b, []byte(m.ExecutorID))
	b = publicationExpectedBlob(b, []byte(m.CredentialRouteID))
	b = append(b, m.Evidence.ResponseContractDigest[:]...)
	b = publicationExpectedBlob(b, []byte(m.BirthServiceContractID))
	b = publicationExpectedBlob(b, []byte(m.BirthTargetContractID))
	return publicationExpectedHash("ENKV/K2-OUTPUT-RESERVE-ADMISSION/v5", b)
}

func publicationLossExpectedCreate(t *testing.T, before *StateSession, plan *publicationPlan, input publicationInput, history string, loseReply bool) (contract.PublicationMarker, contract.PublicationCoordinate) {
	t.Helper()
	fixed := publicationLossTarget(history)
	if !slices.Equal(input.names, []string{fixed.entryName}) || len(input.deletes) != 0 || len(plan.targets) != 1 || len(plan.targets[0].actions) != 1 || len(plan.targets[0].attempts) != 1 {
		t.Fatal("publication loss create is not the independently fixed one-entry action")
	}
	p := plan.targets[0]
	if p.actions[0] != contract.PublicationCreateWithValue || p.destination != "publication-loss" || !p.target.Capabilities.CreateSetsPolicy() || len(p.blockers) != 0 || len(input.republish) != 0 || plan.operation.IsZero() || p.attempts[0].IsZero() {
		t.Fatal("publication loss create differs from the TEST create/policy/empty-blocker contract")
	}
	for _, named := range before.root.Names {
		if named.Name == fixed.entryName {
			fixed.target.EntryIncarnationID = before.valueEntry(named.Slot).Incarnation
		}
	}
	if fixed.target.EntryIncarnationID.IsZero() {
		t.Fatal("publication loss create lacks the independently named selected entry")
	}
	relation, err := selectedPublicationRelation(before.selectedImage())
	if err != nil {
		t.Fatal("publication loss create predecessor relation", err)
	}
	id := publicationExpectedCoordinate(before.root.Domain, fixed.target.ServiceContractID, fixed.target.CanonicalTarget)
	c, present := relation.coordinates[id]
	config, r := before.currentOutputConfigurationForApply(t.Context())
	if !present || r.Outcome != 0 || len(config.Bindings) != 1 || config.Bindings[0].DestinationID != "publication-loss" || len(config.Bindings[0].Targets) != 1 || !reflect.DeepEqual(config.Bindings[0].Targets[0], fixed.target) {
		t.Fatal("publication loss create predecessor lacks the exact new binding/target")
	}
	binding := config.Bindings[0].IncarnationID
	pristine := contract.PublicationCoordinate{Schema: 5, DomainID: before.root.Domain, CoordinateID: id, ServiceContractID: fixed.target.ServiceContractID, CanonicalTarget: fixed.target.CanonicalTarget, BindingState: contract.PublicationBindingActive, OwnerState: contract.PublicationOwnerNone, ActiveBindingIncarnationID: binding, LastBindingIncarnationID: binding, LastEntryIncarnationID: fixed.target.EntryIncarnationID, CurrentPublicationIncarnationID: c.CurrentPublicationIncarnationID}
	if !reflect.DeepEqual(c, pristine) || binding.IsZero() || c.CurrentPublicationIncarnationID.IsZero() || p.binding != binding {
		t.Fatal("publication loss create inherited an old owner, stamp or frozen deletion obligation")
	}
	projection, commitment, response := publicationExpectedProjection(t, plan, p, contract.PublicationCreateWithValue, fixed.target, contract.ID{}, contract.ID{})
	m := contract.PublicationMarker{Schema: 5, DomainID: before.root.Domain, OperationID: plan.operation, AttemptID: p.attempts[0], CoordinateID: id, PublicationIncarnationID: c.CurrentPublicationIncarnationID, AdmissionOrdinal: 1, Projection: projection, ProjectionCommitment: commitment, ExecutorID: fmt.Sprintf("%x", p.facts.ExecutorID), CredentialRouteID: fmt.Sprintf("%x", p.facts.CredentialRouteID), State: contract.PublicationAcknowledged, Evidence: contract.PublicationEvidence{Schema: 3, Entry: contract.PublicationMayHaveEnteredEntry, Class: contract.PublicationRequestAcknowledged, ResponseContractDigest: response, NormalizedStatus: 201, SafeResourceID: "test-instance/" + fixed.target.CanonicalTarget + "/" + fmt.Sprintf("%x", p.attempts[0]), ConsumerLocator: fixed.target.ConsumerLocator}, BirthServiceContractID: fixed.target.ServiceContractID, BirthTargetContractID: fixed.target.TargetContractID}
	if before.root.WarningBits&(WarningPublicationOrderValue|WarningDiscardedExactEvidence) != 0 {
		m.LateEffectRisk = 1
	}
	if loseReply {
		m.State, m.LateEffectRisk = contract.PublicationUnknown, 1
		m.Evidence.Class, m.Evidence.NormalizedStatus, m.Evidence.SafeResourceID = contract.PublicationUnproved, 0, ""
		m.Evidence.ConsumerLocator = ""
	}
	m.AuthoritySubjectDigest = publicationLossExpectedAuthority(before, m, contract.ID{})
	c.LastAdmissionOrdinal, c.PossibleRemoteObject, c.LateEffectRisk = 1, 1, m.LateEffectRisk
	c.DeletionDestinationID, c.DeletionConsumerLocator = "publication-loss", fixed.target.ConsumerLocator
	c.DeletionTargetContractID, c.DeletionConfigContractID = fixed.target.TargetContractID, publicationTestConfigContract
	c.DeletionCredentialRouteContractID = p.facts.CredentialRouteContractID
	c.DeletionTargetData, c.DeletionPayloadEncoding, c.DeletionTargetRowDigest = fixed.target.TargetData, fixed.target.PayloadEncoding, projection.TargetRowDigest
	if loseReply {
		c.OwnerState, c.LatestUnresolvedAttemptID = contract.PublicationOwnerUncertainCreate, m.AttemptID
	} else {
		c.OwnerState, c.OwnedBirthAttemptID = contract.PublicationOwnerQualified, m.AttemptID
		var b []byte
		for _, id := range []contract.ID{before.root.Domain, c.CoordinateID, binding, fixed.target.EntryIncarnationID, projection.TargetRowDigest, m.AttemptID} {
			b = append(b, id[:]...)
		}
		c.OwnedInstanceDigest = publicationExpectedHash("ENKV/PUBLICATION/OWNED-INSTANCE/v2", publicationExpectedBlob(b, []byte(m.Evidence.SafeResourceID)))
		b = nil
		for _, id := range []contract.ID{before.root.Domain, projection.ValueBasisDigest, m.AttemptID, c.OwnedInstanceDigest} {
			b = append(b, id[:]...)
		}
		c.LastValueDigest = publicationExpectedHash("ENKV/PUBLICATION/SELECTED-VALUE/v2", b)
		c.LastValueAckAttemptID, c.LastValueAckIncarnationID, c.LastValueAckOrdinal = m.AttemptID, m.PublicationIncarnationID, 1
		c.LastPolicyDigest = projection.PolicyDigest
		c.LastPolicyAckAttemptID, c.LastPolicyAckIncarnationID, c.LastPolicyAckOrdinal = m.AttemptID, m.PublicationIncarnationID, 1
	}
	return m, c
}

func publicationLossAssertMarker(t *testing.T, actual, expected contract.PublicationMarker) {
	t.Helper()
	if actual == expected {
		return
	}
	av, ev := reflect.ValueOf(actual), reflect.ValueOf(expected)
	for i := 0; i < av.NumField(); i++ {
		if !reflect.DeepEqual(av.Field(i).Interface(), ev.Field(i).Interface()) {
			name := av.Type().Field(i).Name
			t.Logf("publication loss marker field=%s equal=false", name)
			if av.Field(i).Kind() == reflect.Struct {
				a, e := av.Field(i), ev.Field(i)
				for j := 0; j < a.NumField(); j++ {
					if !reflect.DeepEqual(a.Field(j).Interface(), e.Field(j).Interface()) {
						t.Logf("publication loss marker field=%s.%s equal=false", name, a.Type().Field(j).Name)
					}
				}
			}
		}
	}
	t.Fatalf("publication loss full independent marker differs action=%d ordinal=%d blockers=%d state=%d", expected.Projection.Action, expected.AdmissionOrdinal, expected.BlockerCount, expected.State)
}

// Supplied comparison requires a new sealed source, whereas generated current
// entries use their canonical payload. The fixed complete-fixture recipe supplies
// these three values independently; no recovered plaintext or old source is used.
func publicationLossSelectConfiguration(t *testing.T, operationCtx context.Context, before *StateSession, env fixtureEnvironment, output *outputApplyInput) (*StateSession, publicationLossGeneratedPreservation) {
	t.Helper()
	inputs := before.currentEntryInputs()
	sealed := 0
	for i, entry := range inputs {
		if entry.ValueSource != contract.Supplied || entry.ConfidentialityClass != contract.Secret {
			continue
		}
		var choice uint8
		switch entry.Name {
		case "supplied-shared":
			choice = custody.StandardValue
		case "supplied-empty":
			choice = custody.EmptyValue
		case "supplied-binary":
			choice = custody.MaximumValue
		default:
			t.Fatal("publication loss configuration has a supplied secret outside the fixed recipe")
		}
		inputs[i] = suppliedSecret(t, env, entry.Name, fmt.Sprintf("publication loss config source %x %s", before.root.Snapshot, entry.Name), choice, entry.Recipients...)
		sealed++
	}
	if len(inputs) != 7 || sealed != 3 || before.root.SecretCount != 5 {
		t.Fatal("publication loss configuration input cardinality differs from complete recipe")
	}
	windows, err := before.receiptWindows(t.Context())
	if err != nil {
		t.Fatal("publication loss normal predecessor receipt windows", err)
	}
	installOutputFixtureSource(t, before, output)
	parent := admitSuppliedOutputComparison(t, before, env.Custody, inputs, output)
	comparison, result := before.compareWithOutput(t.Context(), inputs, output, parent)
	if comparison == nil || result.Outcome != ObservedCurrent || len(comparison.changed) != 0 || parent == nil || parent.support == nil || len(parent.support.Handoffs) != 0 {
		t.Fatal("publication loss configuration cannot change or retire current values", result)
	}
	candidate := prepareOutputComparison(t, before, comparison, parent, env.Trust)
	generated := publicationLossExpectedNormalGenerated(t, before, candidate)
	after, result := before.selectCandidate(t.Context(), candidate)
	if after == nil || result.Outcome != ObservedCurrent {
		t.Fatal("publication loss configuration selection", result)
	}
	env.Custody.RetireApply()
	after = generatedLifecycleReopen(t, operationCtx, after, env.Store)
	publicationLossAssertGeneratedFacts(t, after, generated)
	gotWindows, err := after.receiptWindows(t.Context())
	if err != nil || !slices.Equal(gotWindows.Successes, windows.Successes) || !slices.Equal(gotWindows.Failures, windows.Failures) || !slices.Equal(gotWindows.Order, windows.Order) || after.root.Generated.SuccessWindow != before.root.Generated.SuccessWindow || after.root.Generated.FailureWindow != before.root.Generated.FailureWindow || after.root.Generated.ReceiptOrder != before.root.Generated.ReceiptOrder {
		t.Fatal("publication loss normal configuration changed unrelated receipt windows", err)
	}
	if !reflect.DeepEqual(after.pages, before.pages) || !reflect.DeepEqual(after.recipients, before.recipients) || !reflect.DeepEqual(after.root.CurrentAccess, before.root.CurrentAccess) || !reflect.DeepEqual(after.root.ValueEntryPages, before.root.ValueEntryPages) || !reflect.DeepEqual(after.root.Names, before.root.Names) || !reflect.DeepEqual(after.root.Recipients, before.root.Recipients) || after.root.ValueEntryCount != 7 || after.root.SecretCount != 5 || after.root.RawBytes != before.root.RawBytes || after.root.MembershipCount != before.root.MembershipCount || after.root.SecretOrdinaryWrapCount != before.root.SecretOrdinaryWrapCount {
		t.Fatalf("publication loss configuration changed exact current material pages_equal=%t registry_equal=%t access_equal=%t value_refs_equal=%t names_equal=%t values=%d secrets=%d", reflect.DeepEqual(after.pages, before.pages), reflect.DeepEqual(after.recipients, before.recipients), reflect.DeepEqual(after.root.CurrentAccess, before.root.CurrentAccess), reflect.DeepEqual(after.root.ValueEntryPages, before.root.ValueEntryPages), reflect.DeepEqual(after.root.Names, before.root.Names), after.root.ValueEntryCount, after.root.SecretCount)
	}
	return after, generated
}

func configurationRecoveryPublicationHistory(t *testing.T, ctx context.Context, env fixtureEnvironment, admitted OpenContext, selected *StateSession, history, expectationPath string) *StateSession {
	t.Helper()
	if history != "owned_active_then_delete" && history != "owned_retired_unknown_delete" && history != "uncertain_retired_unknown_delete" {
		t.Fatal("publication loss history refused")
	}
	target := publicationLossTarget(history)
	admitted.admission.publicationNamespaces = []publicationNamespace{publicationLossNamespace(env.Domain, history)}
	selected.admission.publicationNamespaces = admitted.admission.publicationNamespaces
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "publication-loss", targets: []outputApplyTarget{target}}}, routes: []outputApplyRoute{{entryName: target.entryName, destinations: []string{"publication-loss"}}}}
	selected, _ = publicationLossSelectConfiguration(t, ctx, selected, env, output)
	if err := env.Custody.InstallPublication(ctx, installedPublicationTestConfig(t), "publication-loss", publicationTestConfigContract); err != nil {
		t.Fatal("publication loss native installation", err)
	}
	input := publicationInput{names: []string{target.entryName}, acting: selected.admission.recipient, deadline: time.Now().Add(30 * time.Second)}
	initialPlan, r := selected.planPublication(ctx, input, publicationCustodyPrivate(env.Custody))
	if initialPlan == nil || len(initialPlan.targets) != 1 {
		t.Fatal("publication loss independent original plan", r)
	}
	fixedTarget := target.target
	for _, named := range selected.root.Names {
		if named.Name == target.entryName {
			fixedTarget.EntryIncarnationID = selected.valueEntry(named.Slot).Incarnation
		}
	}
	projection, commitment, response := publicationExpectedProjection(t, initialPlan, initialPlan.targets[0], contract.PublicationCreateWithValue, fixedTarget, contract.ID{}, contract.ID{})
	selected, birth, _ := publicationLossExecute(t, ctx, env, admitted, selected, input, history, history == "uncertain_retired_unknown_delete")
	if birth.Actions[0].Action != contract.PublicationCreateWithValue {
		t.Fatal("publication loss actual birth action")
	}
	if history == "owned_active_then_delete" {
		output.bindings[0].targets[0].target.Policy.Data = []byte("1")
		output.bindings[0].destination.Policy.Data = []byte("1")
		selected, _ = publicationLossSelectConfiguration(t, ctx, selected, env, output)
	} else {
		selected, _ = publicationLossSelectConfiguration(t, ctx, selected, env, &outputApplyInput{})
		input.names, input.deletes = nil, []contract.ID{birth.CoordinateID}
		if history == "uncertain_retired_unknown_delete" {
			input.republish = map[contract.ID][]contract.ID{birth.CoordinateID: {birth.Actions[0].AttemptID}}
		}
		selected, _, _ = publicationLossExecute(t, ctx, env, admitted, selected, input, history, true)
	}
	relation, err := selectedPublicationRelation(selected.selectedImage())
	if err != nil || len(relation.coordinates) != 1 {
		t.Fatal("publication loss selected relation", err)
	}
	coordinate := relation.coordinates[birth.CoordinateID]
	wantTarget := target.target
	wantTarget.EntryIncarnationID = coordinate.LastEntryIncarnationID
	if coordinate.Schema != 5 || coordinate.DomainID != env.Domain || coordinate.CoordinateID != publicationExpectedCoordinate(env.Domain, wantTarget.ServiceContractID, wantTarget.CanonicalTarget) || coordinate.ServiceContractID != wantTarget.ServiceContractID || coordinate.CanonicalTarget != wantTarget.CanonicalTarget || coordinate.DeletionDestinationID != "publication-loss" || coordinate.DeletionConsumerLocator != wantTarget.ConsumerLocator || coordinate.DeletionTargetContractID != wantTarget.TargetContractID || coordinate.DeletionConfigContractID != publicationTestConfigContract || !bytes.Equal(coordinate.DeletionTargetData, wantTarget.TargetData) || coordinate.DeletionPayloadEncoding != wantTarget.PayloadEncoding || coordinate.DeletionTargetRowDigest != projection.TargetRowDigest || coordinate.PossibleRemoteObject != 1 {
		t.Fatal("publication loss independent frozen deletion facts differ")
	}
	wantOwner, wantBinding := uint8(contract.PublicationOwnerQualified), uint8(contract.PublicationBindingRetired)
	if history == "uncertain_retired_unknown_delete" {
		wantOwner = contract.PublicationOwnerUncertainCreate
	}
	if history == "owned_active_then_delete" {
		wantBinding = contract.PublicationBindingActive
	}
	if coordinate.OwnerState != wantOwner || coordinate.BindingState != wantBinding || selected.root.WarningBits != 0 {
		t.Fatal("publication loss independent ownership/warnings")
	}
	if wantOwner == contract.PublicationOwnerQualified && coordinate.OwnedBirthAttemptID != birth.Actions[0].AttemptID || wantOwner == contract.PublicationOwnerUncertainCreate && (!coordinate.OwnedBirthAttemptID.IsZero() || !coordinate.OwnedInstanceDigest.IsZero()) {
		t.Fatal("publication loss birth qualification differs")
	}
	birthMarker := relation.markers[birth.Actions[0].AttemptID]
	wantBirthState := uint8(contract.PublicationAcknowledged)
	if history == "uncertain_retired_unknown_delete" {
		wantBirthState = contract.PublicationUnknown
	}
	if birthMarker.State != wantBirthState || birthMarker.Projection != projection || birthMarker.ProjectionCommitment != commitment || birthMarker.Evidence.ResponseContractDigest != response || birthMarker.BirthServiceContractID != fixedTarget.ServiceContractID || birthMarker.BirthTargetContractID != fixedTarget.TargetContractID || birthMarker.AdmissionOrdinal != 1 || birthMarker.Projection.BindingIncarnationID != coordinate.LastBindingIncarnationID || birthMarker.Projection.EntryIncarnationID != coordinate.LastEntryIncarnationID {
		t.Fatal("publication loss original birth independent projection/stamp differs")
	}
	if wantOwner == contract.PublicationOwnerQualified {
		b := append([]byte(nil), env.Domain[:]...)
		for _, id := range []contract.ID{coordinate.CoordinateID, coordinate.LastBindingIncarnationID, coordinate.LastEntryIncarnationID, projection.TargetRowDigest, birthMarker.AttemptID} {
			b = append(b, id[:]...)
		}
		b = publicationExpectedBlob(b, []byte("test-instance/"+fixedTarget.CanonicalTarget+"/"+fmt.Sprintf("%x", birthMarker.AttemptID)))
		valueBytes := append([]byte(nil), env.Domain[:]...)
		for _, id := range []contract.ID{projection.ValueBasisDigest, birthMarker.AttemptID, coordinate.OwnedInstanceDigest} {
			valueBytes = append(valueBytes, id[:]...)
		}
		if coordinate.OwnedInstanceDigest != publicationExpectedHash("ENKV/PUBLICATION/OWNED-INSTANCE/v2", b) || coordinate.LastValueAckAttemptID != birthMarker.AttemptID || coordinate.LastPolicyAckAttemptID != birthMarker.AttemptID || coordinate.LastValueDigest != publicationExpectedHash("ENKV/PUBLICATION/SELECTED-VALUE/v2", valueBytes) || coordinate.LastPolicyDigest != projection.PolicyDigest || coordinate.LastValueAckOrdinal != 1 || coordinate.LastPolicyAckOrdinal != 1 {
			t.Fatal("publication loss original owned instance/value/policy ACK facts differ")
		}
	}
	wantMarkers, wantOrdinal := 1, uint64(1)
	if history != "owned_active_then_delete" {
		wantMarkers, wantOrdinal = 2, 2
	}
	if len(relation.markers) != wantMarkers || coordinate.LastAdmissionOrdinal != wantOrdinal {
		t.Fatal("publication loss exact marker/stamp cardinality")
	}
	for _, marker := range relation.markers {
		if marker.AttemptID == birthMarker.AttemptID {
			continue
		}
		wantAction := uint8(contract.PublicationDeleteOwned)
		if history == "uncertain_retired_unknown_delete" {
			wantAction = contract.PublicationDeleteReservedSlot
		}
		if marker.State != contract.PublicationUnknown || marker.Projection.Action != wantAction || marker.AdmissionOrdinal != 2 || marker.Projection.TargetRowDigest != projection.TargetRowDigest || !marker.Projection.ValueBasisDigest.IsZero() || !marker.Projection.PolicyDigest.IsZero() || marker.AttemptID != coordinate.LatestUnresolvedAttemptID || marker.Evidence.Class != contract.PublicationUnproved {
			t.Fatal("publication loss unknown deletion independent facts differ")
		}
	}
	configuration, r := selected.currentOutputConfigurationForApply(ctx)
	if r.Outcome != 0 || configuration.Schema != contract.OutputConfigurationSchema {
		t.Fatal("publication loss schema", r)
	}
	if history == "owned_active_then_delete" {
		fixedTarget.Policy.Data = []byte("1")
		wantConfiguration := contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: env.Domain, Bindings: []contract.OutputBinding{{DestinationID: "publication-loss", IncarnationID: initialPlan.targets[0].binding, Destination: outputFixtureDestination("publication-loss", "test-output/service/v1", 255, contract.OutputPolicy{ContractID: "test-policy", Data: []byte("1")}), Targets: []contract.OutputTarget{fixedTarget}}}, Routes: []contract.OutputRoute{{EntryIncarnationID: fixedTarget.EntryIncarnationID, Destinations: []string{"publication-loss"}}}}
		if !reflect.DeepEqual(configuration, wantConfiguration) {
			t.Fatal("publication loss current policy")
		}
	} else if len(configuration.Bindings) != 0 || len(configuration.Routes) != 0 {
		t.Fatal("publication loss retired configuration not empty")
	}
	expected := publicationLossExpectation{History: history, Configuration: configuration, Coordinate: coordinate, Order: clonePublicationWork(selected.adminIndex).PublicationOrder, WarningBits: selected.root.WarningBits}
	for _, marker := range relation.markers {
		expected.Markers = append(expected.Markers, marker)
	}
	slices.SortFunc(expected.Markers, func(a, b contract.PublicationMarker) int { return bytes.Compare(a.AttemptID[:], b.AttemptID[:]) })
	writeConfigurationRecoveryJSON(t, expectationPath, expected)
	return selected
}

type publicationLossGrant struct {
	Composition                      contract.ID
	Expires                          time.Time
	NamespaceDomain                  contract.ID
	NamespaceProvider, NamespaceSlot string
	NamespacePremise                 contract.ID
}

func publicationLossOpen(t testing.TB, ctx context.Context, returned installedarchive.PublicationLossContinuation, grant publicationLossGrant, history string, family contract.Family, enabled, wrongAuthority bool, selectedAccessGeneration ...uint64) (fixtureEnvironment, OpenContext, *StateSession, error) {
	t.Helper()
	var configuration contract.StoreConfiguration
	var head format.Head
	var root format.Root
	var headBody []byte
	for _, part := range returned.Parts {
		var err error
		switch part.Kind {
		case "configuration":
			configuration, err = contract.DecodeStoreConfiguration(part.Body)
		case "HEAD":
			head, err = format.DecodeHead(part.Body)
			headBody = part.Body
		case "root":
			root, err = format.DecodeRoot(part.Body)
		}
		if err != nil {
			return fixtureEnvironment{}, OpenContext{}, nil, errors.New("returned public fact refused")
		}
	}
	domain := returned.Domain
	if returned.Result != (installedarchive.RecoveryResult{Outcome: 2, Evidence: 1}) || domain.IsZero() || configuration.DomainID != domain || configuration.Provider != family || (root.CurrentAccess.Core.Recovery != nil) != enabled || head.Core.Domain != domain || head.Core.Revision != returned.Revision || head.Core.Root.Object != returned.Snapshot || root.Snapshot != returned.Snapshot || contract.Hash(headBody) != returned.HEADDigest || returned.Location != publicationLossLocation(configuration.Provider) {
		return fixtureEnvironment{}, OpenContext{}, nil, errors.New("verified reconstruction selection absent")
	}
	desc, err := publicationLossDescriptor(configuration)
	if err != nil || desc.Coordinate != head.Core.Coordinate || desc.NonBody != head.Core.NonBody || desc.Identity != head.Core.Store {
		return fixtureEnvironment{}, OpenContext{}, nil, errors.New("independent store location differs")
	}
	store := &memoryStore{desc: desc, configuration: configuration, objects: make(map[string]stored)}
	for _, object := range returned.Objects {
		token, n, err := contract.ParseToken(object.TokenWire)
		generationText := strings.Trim(token.Value, "\"")
		generation, generationErr := strconv.Atoi(generationText)
		_, duplicate := store.objects[object.Key]
		if err != nil || n != len(object.TokenWire) || token.Family != desc.Family || generationErr != nil || generation <= 0 || duplicate || fmt.Sprintf("%x", sha256.Sum256(object.Body)) != object.BodySHA256 {
			return fixtureEnvironment{}, OpenContext{}, nil, errors.New("actual remote object backing refused")
		}
		store.objects[object.Key] = stored{Body: bytes.Clone(object.Body), Token: token}
		store.generation = max(store.generation, generation)
	}
	actual, ok := store.objects[desc.HeadKey]
	if !ok || actual.Token != returned.HEADToken || !bytes.Equal(actual.Body, headBody) {
		return fixtureEnvironment{Store: store}, OpenContext{}, nil, errors.New("actual remote HEAD changed after reconstruction")
	}
	archive := installedarchive.Archive{Family: desc.Family, Domain: domain, Location: returned.Location, HeadDigest: returned.HEADDigest, Revision: returned.Revision, Objects: returned.Objects}
	parts, err := archive.SelectedParts()
	if err != nil || !reflect.DeepEqual(parts, returned.Parts) {
		return fixtureEnvironment{Store: store}, OpenContext{}, nil, errors.New("returned complete selected parts differ")
	}
	if grant.Composition.IsZero() || !time.Now().Before(grant.Expires) || time.Until(grant.Expires) > time.Minute || grant.NamespaceDomain != domain || grant.NamespaceProvider != "test-output/service/v1" || grant.NamespaceSlot != publicationLossTarget(history).target.CanonicalTarget || grant.NamespacePremise.IsZero() {
		return fixtureEnvironment{Store: store}, OpenContext{}, nil, errors.New("fresh private construction facts absent")
	}
	trustID := publicationLossTrustID(desc.Family, contract.NormalSigningRole)
	material := testID("trust")
	if wrongAuthority {
		material = testID("wrong independent publication loss authority")
	}
	trust := &fixtureTrust{Signer: testtrust.NewWithIdentity(t, desc.Family, material, trustID, contract.NormalSigningRole)}
	recipients := []contract.ID{fixtureID(domain, "recipient"), fixtureID(domain, "reader"), fixtureID(domain, "reader-002")}
	keys := custody.New(t, desc.Family, fixtureID(domain, "custody"), enabled, recipients)
	env := fixtureEnvironment{Store: store, Trust: trust, Domain: domain, GenesisIDs: publicationLossAuthorityData(domain), PublicKey: trust.PublicKey(), SigningSelector: trust.KeySelector(), Custody: keys, Crypto: keys.Crypto(), Bindings: keys.Bindings(), Context: ctx}
	if enabled {
		recovery := testtrust.NewWithIdentity(t, desc.Family, testID("recovery-trust"), publicationLossTrustID(desc.Family, contract.RecoverySigningRole), contract.RecoverySigningRole)
		env.Recovery, env.RecoveryPublicKey, env.RecoverySelector = recovery, recovery.PublicKey(), recovery.KeySelector()
	}
	descriptor, err := fixtureDescriptor(env)
	if err != nil {
		return env, OpenContext{}, nil, errors.New("independent authority descriptor refused")
	}
	body, err := contract.EncodeGenesisDescriptorCore(descriptor)
	if err != nil {
		return env, OpenContext{}, nil, errors.New("independent authority encoding refused")
	}
	admitted := OpenContext{admission: &openAdmission{domain: domain, trust: trustID, interpretation: contract.InterpretationID(), recipient: descriptor.AuthorityRecipientID, composition: grant.Composition, controlIncarnation: fixtureControlIncarnation(domain, trustID), store: desc, epoch: 1, publicKey: trust.PublicKey(), descriptor: body, expires: grant.Expires, entropy: rand.Reader,
		publicationNamespaces: []publicationNamespace{{domain: grant.NamespaceDomain, service: grant.NamespaceProvider, physical: grant.NamespaceSlot, premise: grant.NamespacePremise}}}}
	selected, result := Open(ctx, admitted, store)
	if selected == nil || result.Outcome != ObservedCurrent {
		return env, admitted, nil, errors.New("new independent normal admission refused selected state")
	}
	// The default caller observes Genesis only. The complete seven-value caller
	// supplies 4: Genesis 1 + supplied protection + seed reservation + Final.
	// This changes an expectation copy, never the independently admitted basis.
	wantGeneration := uint64(1)
	if len(selectedAccessGeneration) > 1 {
		return env, admitted, nil, errors.New("independent selected access recipe is ambiguous")
	}
	if len(selectedAccessGeneration) == 1 {
		wantGeneration = selectedAccessGeneration[0]
	}
	basis, ok := admitted.admission.currentControl()
	control, current := selected.selectedControl()
	wantControl := basis
	wantControl.AccessGeneration = wantGeneration
	registryEqual := reflect.DeepEqual(selected.registry(), descriptor.Recipients)
	if !ok || !current || basis.AccessGeneration != 1 || !controlEqual(wantControl, control) || !registryEqual {
		t.Logf("publication loss independent control available=%t selected=%t Genesis_generation=%d expected_generation=%d actual_generation=%d registry_equal=%t registry_count=%d expected_registry_count=%d", ok, current, basis.AccessGeneration, wantGeneration, control.AccessGeneration, registryEqual, len(selected.registry()), len(descriptor.Recipients))
		av, ev := reflect.ValueOf(control.CurrentControlFields), reflect.ValueOf(wantControl.CurrentControlFields)
		for i := 0; i < av.NumField(); i++ {
			t.Logf("publication loss independent control field=%s equal=%t", av.Type().Field(i).Name, reflect.DeepEqual(av.Field(i).Interface(), ev.Field(i).Interface()))
		}
		t.Logf("publication loss independent control NormalSigning_equal=%t Recovery_equal=%t AuthorityKMSBinding_equal=%t", reflect.DeepEqual(control.NormalSigning, wantControl.NormalSigning), reflect.DeepEqual(control.Recovery, wantControl.Recovery), reflect.DeepEqual(control.AuthorityKMSBinding, wantControl.AuthorityKMSBinding))
		registry := selected.registry()
		if len(registry) == len(descriptor.Recipients) {
			for i, actual := range registry {
				a, e := reflect.ValueOf(actual), reflect.ValueOf(descriptor.Recipients[i])
				for j := 0; j < a.NumField(); j++ {
					t.Logf("publication loss independent registry index=%d field=%s equal=%t", i, a.Type().Field(j).Name, reflect.DeepEqual(a.Field(j).Interface(), e.Field(j).Interface()))
				}
			}
		}
		return env, admitted, nil, errors.New("current control or complete registry differs from independent authority recipe")
	}
	return env, admitted, selected, nil
}

func publicationLossChangedRemoteHEAD(t testing.TB, returned installedarchive.PublicationLossContinuation) installedarchive.PublicationLossContinuation {
	t.Helper()
	returned.Objects = slices.Clone(returned.Objects)
	for i, object := range returned.Objects {
		if object.Key != returned.Location.PrefixBeforeHEAD+"/HEAD" {
			continue
		}
		token := returned.HEADToken
		token.Value = "999999"
		if token.Family == contract.AWS {
			token.Value = "\"999999\""
		}
		wire, err := contract.AppendToken(nil, token)
		if err != nil {
			t.Fatal("changed actual remote HEAD token refused", err)
		}
		returned.Objects[i].TokenWire = wire
		return returned
	}
	t.Fatal("actual remote HEAD backing unavailable")
	return returned
}

func configurationRecoveryPublicationContinuation(t *testing.T, ctx context.Context, input configurationRecoveryFixtureInput) {
	t.Helper()
	var returned installedarchive.PublicationLossContinuation
	readConfigurationRecoveryJSON(t, input.PublicationContinuation, &returned)
	family := contract.AWS
	if input.Provider == "gcp" {
		family = contract.GCP
	}
	var expected publicationLossExpectation
	readConfigurationRecoveryJSON(t, input.PublicationExpectation, &expected)
	if expected.History != input.PublicationHistory || expected.Coordinate.DomainID != returned.Domain {
		t.Fatal("loss continuation history binding")
	}
	for _, damage := range []string{"missing_grant", "refused_recovery", "stale_HEAD", "wrong_authority", "wrong_namespace"} {
		t.Run(damage, func(t *testing.T) {
			candidate, grant := returned, input.PublicationGrant
			switch damage {
			case "missing_grant":
				grant = publicationLossGrant{}
			case "refused_recovery":
				candidate.Result = installedarchive.RecoveryResult{Outcome: 5}
			case "stale_HEAD":
				candidate = publicationLossChangedRemoteHEAD(t, returned)
			case "wrong_namespace":
				grant.NamespaceSlot = "different namespace"
			}
			env, _, selected, err := publicationLossOpen(t, ctx, candidate, grant, expected.History, family, input.Recovery, damage == "wrong_authority", 4)
			if err == nil || selected != nil {
				t.Fatal("loss continuation negative admission succeeded")
			}
			if env.Store != nil {
				store := env.Store.(*memoryStore)
				if store.creates != 0 || store.cas != 0 {
					t.Fatal("negative admission mutated store", store.creates, store.cas)
				}
			}
			if env.Trust != nil && env.Trust.(*fixtureTrust).Calls() != 0 {
				t.Fatal("negative admission signed")
			}
		})
	}
	env, admitted, selected, err := publicationLossOpen(t, ctx, returned, input.PublicationGrant, expected.History, family, input.Recovery, false, 4)
	if err != nil {
		t.Fatal("fresh publication loss admission", err)
	}
	if input.PublicationGrant.NamespaceSlot != publicationLossTarget(input.PublicationHistory).target.CanonicalTarget {
		t.Fatal("fresh independently named namespace differs")
	}
	relation, err := selectedPublicationRelation(selected.selectedImage())
	if err != nil || !reflect.DeepEqual(relation.coordinates[expected.Coordinate.CoordinateID], expected.Coordinate) || len(relation.coordinates) != 1 || len(relation.markers) != len(expected.Markers) || !reflect.DeepEqual(selected.adminIndex.PublicationOrder, expected.Order) || selected.root.WarningBits != expected.WarningBits {
		t.Fatal("recovered complete coordinate/marker/index/warning relation differs", err)
	}
	for _, marker := range expected.Markers {
		if !reflect.DeepEqual(relation.markers[marker.AttemptID], marker) {
			t.Fatal("recovered marker differs", marker.AttemptID)
		}
	}
	configuration, r := selected.currentOutputConfigurationForApply(ctx)
	if r.Outcome != 0 || !reflect.DeepEqual(configuration, expected.Configuration) {
		t.Fatal("recovered schema 2 configuration/current policy differs", r)
	}
	store := env.Store.(*memoryStore)
	if store.creates != 0 || store.cas != 0 || env.Trust.(*fixtureTrust).Calls() != 0 {
		t.Fatal("normal observation restored mutation rights")
	}
	if _, err := env.Custody.PublicationArtifact(ctx, "publication-loss", publicationTestConfigContract); err == nil {
		t.Fatal("new custody inherited an old installed output route")
	}
	beforeValues, beforeRegistry, beforeAccess := selected.pages, selected.recipients, selected.root.CurrentAccess
	beforeGenerated := publicationLossGeneratedFacts(t, selected)
	if err := env.Custody.InstallPublication(ctx, installedPublicationTestConfig(t), "publication-loss", publicationTestConfigContract); err != nil {
		t.Fatal("fresh installed output lifetime", err)
	}
	if input.PublicationHistory == "owned_active_then_delete" {
		selected, beforeGenerated = publicationLossSelectConfiguration(t, ctx, selected, env, &outputApplyInput{})
	}
	id := expected.Coordinate.CoordinateID
	var blockers []contract.ID
	for _, marker := range expected.Markers {
		if marker.State == contract.PublicationUnknown || marker.State == contract.PublicationMayHaveEntered {
			blockers = append(blockers, marker.AttemptID)
		}
	}
	slices.SortFunc(blockers, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	operation := publicationInput{deletes: []contract.ID{id}, acting: selected.admission.recipient, deadline: time.Now().Add(30 * time.Second)}
	if len(blockers) > 0 {
		operation.republish = map[contract.ID][]contract.ID{id: blockers}
	}
	selected, row, owner := publicationLossExecute(t, ctx, env, admitted, selected, operation, input.PublicationHistory, false)
	projection := owner.input.Projection
	action := uint8(contract.PublicationDeleteOwned)
	if expected.Coordinate.OwnerState == contract.PublicationOwnerUncertainCreate {
		action = contract.PublicationDeleteReservedSlot
	}
	if projection.Action != action || !reflect.DeepEqual(owner.input.Target.Policy, contract.OutputPolicy{}) || !projection.ValueBasisDigest.IsZero() || !projection.PolicyDigest.IsZero() || projection.TargetRowDigest != expected.Coordinate.DeletionTargetRowDigest || owner.input.Target.CanonicalTarget != expected.Coordinate.CanonicalTarget || owner.input.Target.ConsumerLocator != expected.Coordinate.DeletionConsumerLocator || owner.input.Target.TargetContractID != expected.Coordinate.DeletionTargetContractID || owner.input.ConfigContractID != expected.Coordinate.DeletionConfigContractID || !bytes.Equal(owner.input.Target.TargetData, expected.Coordinate.DeletionTargetData) || owner.input.Target.PayloadEncoding != expected.Coordinate.DeletionPayloadEncoding {
		t.Fatal("new delete did not use exact frozen minimal inputs")
	}
	for _, marker := range expected.Markers {
		if row.Actions[0].AttemptID == marker.AttemptID {
			t.Fatal("new delete reused old Attempt")
		}
	}
	after, err := selectedPublicationRelation(selected.selectedImage())
	coordinate := after.coordinates[id]
	if err != nil || coordinate.LastDeleteAckAttemptID != row.Actions[0].AttemptID || coordinate.PossibleRemoteObject != 1 || coordinate.DeletionTargetRowDigest != expected.Coordinate.DeletionTargetRowDigest || coordinate.BindingState != contract.PublicationBindingRetired {
		t.Fatal("delete ACK lost retained facts or claimed absence", err)
	}
	for _, marker := range expected.Markers {
		if !reflect.DeepEqual(after.markers[marker.AttemptID], marker) {
			t.Fatal("new delete altered old marker")
		}
	}
	if action == contract.PublicationDeleteOwned && (owner.input.Birth == nil || owner.input.Birth.AttemptID != expected.Coordinate.OwnedBirthAttemptID || owner.input.Coordinate.OwnedInstanceDigest != expected.Coordinate.OwnedInstanceDigest) {
		t.Fatal("new owned delete lacked original exact birth/instance")
	}
	if action == contract.PublicationDeleteReservedSlot && (owner.input.UncertainCreate == nil || owner.input.Birth != nil || projection.ExclusiveNamespaceDigest.IsZero()) {
		t.Fatal("new reserved delete lacked independent namespace/uncertain birth")
	}
	if len(blockers) > 0 {
		_, _, beforeGenerated = publicationLossDispose(t, ctx, env, admitted, blockers[0], beforeGenerated)
	}
	var expectedReceiptIndex publicationLossReceiptIndex
	selected, expectedReceiptIndex, _ = publicationLossDispose(t, ctx, env, admitted, id, beforeGenerated)
	warnings := selected.root.WarningBits
	if warnings&expected.WarningBits != expected.WarningBits || warnings&(WarningPublicationOrderValue|WarningDiscardedExactEvidence) == 0 {
		t.Fatal("loss disposal warning monotonicity")
	}
	target := publicationLossTarget(input.PublicationHistory)
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "publication-loss", targets: []outputApplyTarget{target}}}, routes: []outputApplyRoute{{entryName: target.entryName, destinations: []string{"publication-loss"}}}}
	selected, beforeGenerated = publicationLossSelectConfiguration(t, ctx, selected, env, output)
	config, r := selected.currentOutputConfigurationForApply(ctx)
	if r.Outcome != 0 || config.Bindings[0].IncarnationID == expected.Coordinate.LastBindingIncarnationID {
		t.Fatal("fresh binding inherited old incarnation", r)
	}
	freshInput := publicationInput{names: []string{target.entryName}, acting: selected.admission.recipient, deadline: time.Now().Add(30 * time.Second)}
	selected, fresh, _ := publicationLossExecute(t, ctx, env, admitted, selected, freshInput, input.PublicationHistory, false)
	if fresh.Actions[0].Action != contract.PublicationCreateWithValue || fresh.Actions[0].AttemptID == row.Actions[0].AttemptID || selected.root.WarningBits != warnings {
		t.Fatal("fresh birth inherited equality/right or cleared warning")
	}
	publicationLossAssertGeneratedFacts(t, selected, beforeGenerated)
	publicationLossAssertReceiptIndex(t, selected, expectedReceiptIndex)
	if !reflect.DeepEqual(selected.pages, beforeValues) || !reflect.DeepEqual(selected.recipients, beforeRegistry) || !reflect.DeepEqual(selected.root.CurrentAccess, beforeAccess) || selected.root.ValueEntryCount != 7 || selected.root.SecretCount != 5 {
		t.Fatal("fresh actions/disposals changed the seven current values, registry/access or generated state")
	}
	writeConfigurationRecoveryJSON(t, input.Output, struct {
		Domain, DeleteAttempt, FreshBirth contract.ID
		WarningBits                       uint8
	}{returned.Domain, row.Actions[0].AttemptID, fresh.Actions[0].AttemptID, warnings})
}

// These facts retain exact generated rows and payload backing. Normal Apply
// derives the one permitted Slice-owner rebind before CAS. Publication-only
// EndWork retains the owner only when the complete physical location vector is
// unchanged. Receipt changes use independent window/index expectations.
type publicationLossSupportFact struct {
	Kind                 uint8
	RecordID, BodySHA256 contract.ID
	BodyLength           uint32
}
type publicationLossFragmentFact struct {
	Row                    publicationLossSupportFact
	Ref                    format.Ref
	Physical, Index, Count uint16
	Blob, Whole            contract.ID
	Total                  uint64
	Offset, PayloadLength  uint32
}
type publicationLossGeneratedPreservation struct {
	Closure       format.GeneratedClosure
	SliceSnapshot contract.ID
	SlicePage     format.Ref
	Location      contract.GeneratorSliceLocation
	Intent        []byte
	Entries       map[string]contract.GeneratedEntryMetadata
	Rows          map[generatedRecordKey]publicationLossSupportFact
	Fragments     map[contract.ID]publicationLossFragmentFact
}

func publicationLossGeneratorHash(label string, body []byte) contract.ID {
	return publicationExpectedHash("ENKV/GENERATOR/v1/"+label, publicationExpectedBlob(nil, body))
}
func publicationLossReceiptBlob(domain contract.ID, success, failure, order contract.GeneratorDescriptor) contract.ID {
	b := append([]byte(nil), domain[:]...)
	for _, d := range []contract.GeneratorDescriptor{success, failure, order} {
		b = append(b, d.Digest[:]...)
		b = binary.BigEndian.AppendUint64(b, d.Length)
		b = binary.BigEndian.AppendUint32(b, d.Count)
	}
	return publicationLossGeneratorHash("receipt-index", b)
}
func publicationLossExpectedIntent() []byte {
	// This public fixture uses schema1, two fixed semantic IDs, managed lifecycle
	// and the same 20-byte settings in its complete 91-byte typed Intent.
	literal := []byte{0, 1}
	literal = append(literal, bytes.Repeat([]byte{41}, 32)...)
	literal = append(literal, 2)
	literal = append(literal, bytes.Repeat([]byte{42}, 32)...)
	return publicationExpectedBlob(literal, []byte(`{"name":"generated"}`))
}
func publicationLossGeneratedFacts(t *testing.T, s *StateSession) publicationLossGeneratedPreservation {
	t.Helper()
	indexBlob := publicationLossReceiptBlob(s.root.Domain, s.root.Generated.SuccessWindow, s.root.Generated.FailureWindow, s.root.Generated.ReceiptOrder)
	indexID := publicationLossGeneratorHash("fragment", binary.BigEndian.AppendUint16(append([]byte(nil), indexBlob[:]...), 0))
	out := publicationLossGeneratedPreservation{Closure: s.root.Generated, SliceSnapshot: s.adminIndex.SliceSnapshot, Rows: make(map[generatedRecordKey]publicationLossSupportFact), Fragments: make(map[contract.ID]publicationLossFragmentFact), Entries: make(map[string]contract.GeneratedEntryMetadata)}
	out.Closure.SuccessWindow, out.Closure.FailureWindow, out.Closure.ReceiptOrder = contract.GeneratorDescriptor{}, contract.GeneratorDescriptor{}, contract.GeneratorDescriptor{}
	out.Closure.Fragments = nil
	for _, page := range s.supportFacts {
		for _, row := range page.rows {
			if row.Kind() <= contract.GeneratorVectorSupportKind && row.Kind() != contract.MutationReceiptSupportKind && row.RecordID() != indexID {
				key := generatedRecordKey{row.Kind(), row.RecordID()}
				if _, duplicate := out.Rows[key]; duplicate {
					t.Fatal("publication loss duplicate preserved generated support")
				}
				out.Rows[key] = publicationLossSupportFact{row.Kind(), row.RecordID(), row.BodyDigest(), row.BodyLength()}
			}
		}
	}
	for location, fact := range s.fragmentFacts {
		if location.BlobID == indexBlob {
			continue
		}
		if location.SupportPageIndex != fact.ref.Index || location.RowSlot != fact.logical || location.FragmentIndex != fact.index || location.BlobID != fact.blob {
			t.Fatal("publication loss preserved fragment location differs from authenticated backing")
		}
		row := publicationLossSupportFact{fact.row.Kind(), fact.row.RecordID(), fact.row.BodyDigest(), fact.row.BodyLength()}
		out.Fragments[row.RecordID] = publicationLossFragmentFact{row, fact.ref, fact.physical, fact.index, fact.count, fact.blob, fact.whole, fact.total, fact.offset, fact.payloadLength}
	}
	literal := publicationLossExpectedIntent()
	intentID := publicationLossGeneratorHash("intent-v3", literal)
	logical := contract.GeneratorLogicalSlice{Schema: 1, ContentKind: contract.GeneratorContentIntent, ContentID: intentID, Length: 91, Digest: sha256.Sum256(literal)}
	for _, named := range s.root.Names {
		entry := s.valueEntry(named.Slot)
		if entry.ValueSource != contract.Generated {
			continue
		}
		if entry.ConfidentialityClass != contract.Secret || named.Name != "generated-alpha" && named.Name != "generated-omega" || entry.Generated.IntentDigest != intentID {
			t.Fatal("publication loss current generated entries differ from fixed two-entry/shared-Intent recipe")
		}
		out.Entries[named.Name] = entry.Generated
	}
	if len(out.Entries) != 2 || len(s.generatedSliceLocations) != 1 || len(out.Fragments) != 1 || s.generatedSliceLocations[0].Logical() != logical {
		t.Fatal("publication loss requires exactly two generated entries/one logical Intent/one fragment")
	}
	out.Location = s.generatedSliceLocations[0]
	work, err := s.selectedGeneratedWork(t.Context())
	if err != nil {
		t.Fatal("publication loss complete current Intent selection", err)
	}
	out.Intent, err = work.readSelectedSlice(t.Context(), contract.GeneratorContentIntent, intentID, contract.GeneratorIntentMaxLength)
	if err != nil || !bytes.Equal(out.Intent, literal) {
		t.Fatal("publication loss current logical Intent differs from fixed bytes", err)
	}
	if out.Closure.Slices != publicationLossSliceDescriptor(out.Location) {
		t.Fatal("publication loss complete Slice descriptor differs from its exact location")
	}
	body, id := publicationLossSliceCarrier(s.root.Domain, out.SliceSnapshot, out.Closure.Slices, publicationLossSliceRow(out.Location))
	for _, page := range s.supportFacts {
		for _, row := range page.rows {
			if row.RecordID() == id {
				if !out.SlicePage.Object.IsZero() || len(page.rows) != 1 || row.Kind() != contract.GeneratorVectorSupportKind || row.BodyDigest() != sha256.Sum256(body) || row.BodyLength() != uint32(len(body)) {
					t.Fatal("publication loss exact single Slice carrier differs")
				}
				out.SlicePage = page.ref
			}
		}
	}
	if out.SlicePage.Object.IsZero() {
		t.Fatal("publication loss exact Slice backing absent")
	}
	return out
}

func publicationLossSliceRow(v contract.GeneratorSliceLocation) []byte {
	b := binary.BigEndian.AppendUint16(nil, 1)
	b = append(b, v.ContentKind)
	b = append(b, v.ContentID[:]...)
	b = append(b, v.BlobID[:]...)
	b = binary.BigEndian.AppendUint64(b, v.Offset)
	b = binary.BigEndian.AppendUint32(b, v.Length)
	return append(b, v.Digest[:]...)
}
func publicationLossSliceDescriptor(v contract.GeneratorSliceLocation) contract.GeneratorDescriptor {
	b := publicationExpectedBlob(binary.BigEndian.AppendUint32(nil, 1), publicationLossSliceRow(v))
	return contract.GeneratorDescriptor{Digest: publicationLossGeneratorHash("slice-index", b), Length: uint64(len(b)), Count: 1}
}
func publicationLossSliceCarrier(domain, owner contract.ID, vector contract.GeneratorDescriptor, row []byte) ([]byte, contract.ID) {
	b := binary.BigEndian.AppendUint16(nil, 1)
	b = append(b, domain[:]...)
	b = append(b, 128)
	b = append(b, owner[:]...)
	b = append(b, 7)
	b = binary.BigEndian.AppendUint32(b, 0)
	b = append(b, vector.Digest[:]...)
	b = binary.BigEndian.AppendUint64(b, vector.Length)
	b = binary.BigEndian.AppendUint32(b, vector.Count)
	body := publicationExpectedBlob(b, row)
	b = append([]byte(nil), domain[:]...)
	b = append(b, 128)
	b = append(b, owner[:]...)
	b = append(b, 7)
	b = append(b, vector.Digest[:]...)
	b = binary.BigEndian.AppendUint64(b, vector.Length)
	b = binary.BigEndian.AppendUint32(b, vector.Count)
	return body, publicationLossGeneratorHash("support-vector-row", binary.BigEndian.AppendUint32(b, 0))
}
func publicationLossSingleSupportPage(domain, object contract.ID, index uint16, kind uint8, id contract.ID, row []byte) ([]byte, format.Ref) {
	// The canonical page and Ref use schema11; the nested generator row keeps
	// its own schema1 and slice vector kind7. Spell the expected header directly.
	b := []byte{'E', 'N', 'K', 'V', 8, 0, 11}
	b = append(b, domain[:]...)
	b = append(b, object[:]...)
	b = binary.BigEndian.AppendUint16(b, index)
	b = binary.BigEndian.AppendUint16(b, 1)
	b = append(b, kind)
	b = append(b, id[:]...)
	b = publicationExpectedBlob(b, row)
	return b, format.Ref{Kind: contract.RequiredSupportKind, Format: contract.CanonicalSchema, Domain: domain, Object: object, Index: index, Length: uint32(len(b)), Digest: sha256.Sum256(b)}
}
func publicationLossPreparedPage(t *testing.T, candidate *Candidate, domain, object contract.ID, index uint16, kind uint8, id contract.ID, row []byte) format.Ref {
	t.Helper()
	body, ref := publicationLossSingleSupportPage(domain, object, index, kind, id, row)
	if index >= contract.MaxChildPages {
		t.Fatal("publication loss prepared support index out of bounds")
	}
	matches := 0
	for _, actual := range candidate.objects {
		if actual.ref.Object == object {
			if actual.ref != ref || !bytes.Equal(actual.body, body) {
				t.Fatal("publication loss independent complete prepared page/header/Ref differs")
			}
			matches++
		}
	}
	if matches != 1 {
		t.Fatal("publication loss independent prepared page not unique", matches)
	}
	return ref
}

// Normal Apply rebinds the one fixture Slice carrier, preserving its complete
// location and logical bytes. The snapshot is allocated before CAS.
func publicationLossExpectedNormalGenerated(t *testing.T, before *StateSession, candidate *Candidate) publicationLossGeneratedPreservation {
	t.Helper()
	want := publicationLossGeneratedFacts(t, before)
	snapshot := candidate.head.Core.Root.Object
	if snapshot.IsZero() || snapshot == before.root.Snapshot {
		t.Fatal("publication loss normal candidate has no new fixed snapshot")
	}
	oldBody, oldID := publicationLossSliceCarrier(before.root.Domain, want.SliceSnapshot, want.Closure.Slices, publicationLossSliceRow(want.Location))
	oldKey := generatedRecordKey{contract.GeneratorVectorSupportKind, oldID}
	if want.Rows[oldKey] != (publicationLossSupportFact{contract.GeneratorVectorSupportKind, oldID, sha256.Sum256(oldBody), uint32(len(oldBody))}) {
		t.Fatal("publication loss complete predecessor Slice bytes/ID/fact differ")
	}
	body, id := publicationLossSliceCarrier(before.root.Domain, snapshot, want.Closure.Slices, publicationLossSliceRow(want.Location))
	matches := 0
	for _, object := range candidate.objects {
		if object.ref.Kind != contract.RequiredSupportKind {
			continue
		}
		page, err := format.InspectRequiredSupportPage(object.body)
		if err != nil {
			t.Fatal("publication loss prepared normal support", err)
		}
		for _, row := range page.Records {
			if row.RecordID == id {
				want.SlicePage = publicationLossPreparedPage(t, candidate, before.root.Domain, object.ref.Object, object.ref.Index, contract.GeneratorVectorSupportKind, id, body)
				matches++
			}
		}
	}
	if matches != 1 {
		t.Fatal("publication loss prepared Slice carrier cardinality", matches)
	}
	delete(want.Rows, oldKey)
	want.Rows[generatedRecordKey{contract.GeneratorVectorSupportKind, id}] = publicationLossSupportFact{contract.GeneratorVectorSupportKind, id, sha256.Sum256(body), uint32(len(body))}
	want.SliceSnapshot = snapshot
	return want
}

// Only this complete fixture's shared 91-byte Intent may move. General packing,
// reachability and multi-fragment behavior remain covered by their owning tests.
func publicationLossExpectedEndGenerated(t *testing.T, before *StateSession, candidate *Candidate, prior publicationLossGeneratedPreservation) publicationLossGeneratedPreservation {
	t.Helper()
	want := prior
	want.Rows, want.Fragments, want.Entries = maps.Clone(prior.Rows), maps.Clone(prior.Fragments), maps.Clone(prior.Entries)
	want.Intent = bytes.Clone(prior.Intent)
	literal := publicationLossExpectedIntent()
	blob := sha256.Sum256(literal)
	location := prior.Location
	location.BlobID, location.Offset = blob, 0
	if !bytes.Equal(prior.Intent, literal) || len(prior.Entries) != 2 || len(prior.Fragments) != 1 || before.root.Generated.Slices != prior.Closure.Slices || before.adminIndex.SliceSnapshot != prior.SliceSnapshot {
		t.Fatal("publication loss EndWork predecessor differs from complete fixed expectation")
	}
	fragment := binary.BigEndian.AppendUint16(nil, 1)
	fragment = append(fragment, blob[:]...)
	fragment = binary.BigEndian.AppendUint16(fragment, 0)
	fragment = binary.BigEndian.AppendUint16(fragment, 1)
	fragment = binary.BigEndian.AppendUint64(fragment, uint64(len(literal)))
	fragment = append(fragment, blob[:]...)
	fragment = binary.BigEndian.AppendUint32(fragment, 0)
	fragment = publicationExpectedBlob(fragment, literal)
	fragmentID := publicationLossGeneratorHash("fragment", binary.BigEndian.AppendUint16(append([]byte(nil), blob[:]...), 0))
	fragmentRow := publicationLossSupportFact{contract.GeneratedFragmentSupportKind, fragmentID, sha256.Sum256(fragment), uint32(len(fragment))}
	if prior.Location == location {
		fact, present := prior.Fragments[fragmentID]
		body, ref := publicationLossSingleSupportPage(before.root.Domain, fact.Ref.Object, fact.Ref.Index, contract.GeneratedFragmentSupportKind, fragmentID, fragment)
		if !present || fact.Row != fragmentRow || fact.Physical != 0 || fact.Index != 0 || fact.Count != 1 || fact.Blob != blob || fact.Whole != blob || fact.Total != uint64(len(literal)) || fact.Offset != 0 || fact.PayloadLength != uint32(len(literal)) || fact.Ref != ref {
			t.Fatal("publication loss already-packed Intent lacks complete fragment/backing proof")
		}
		actual, result := before.selectedObjectReader().readOwned(t.Context(), ref)
		if result.Outcome != 0 || !bytes.Equal(actual, body) {
			t.Fatal("publication loss already-packed Intent bytes differ", result)
		}
		return want
	}
	if candidate.head.EndWork == nil || candidate.head.EndWork.OperationID.IsZero() {
		t.Fatal("publication loss EndWork allocation absent")
	}
	operation, snapshot := candidate.head.EndWork.OperationID, candidate.head.Core.Root.Object
	intentObject := publicationExpectedHash("ENKV/end-work-intent-page/v1", binary.BigEndian.AppendUint16(append(append(append([]byte(nil), before.root.Domain[:]...), operation[:]...), blob[:]...), 0))
	var fragmentRef format.Ref
	for _, object := range candidate.objects {
		if object.ref.Object == intentObject {
			fragmentRef = publicationLossPreparedPage(t, candidate, before.root.Domain, intentObject, object.ref.Index, contract.GeneratedFragmentSupportKind, fragmentID, fragment)
		}
	}
	if fragmentRef.Object.IsZero() {
		t.Fatal("publication loss exact prepared compact Intent page absent")
	}
	for oldID := range prior.Fragments {
		delete(want.Fragments, oldID)
		delete(want.Rows, generatedRecordKey{contract.GeneratedFragmentSupportKind, oldID})
	}
	want.Rows[generatedRecordKey{contract.GeneratedFragmentSupportKind, fragmentID}] = fragmentRow
	want.Fragments[fragmentID] = publicationLossFragmentFact{fragmentRow, fragmentRef, 0, 0, 1, blob, blob, uint64(len(literal)), 0, uint32(len(literal))}
	oldBody, oldID := publicationLossSliceCarrier(before.root.Domain, prior.SliceSnapshot, prior.Closure.Slices, publicationLossSliceRow(prior.Location))
	if prior.Rows[generatedRecordKey{contract.GeneratorVectorSupportKind, oldID}] != (publicationLossSupportFact{contract.GeneratorVectorSupportKind, oldID, sha256.Sum256(oldBody), uint32(len(oldBody))}) {
		t.Fatal("publication loss EndWork old Slice carrier differs")
	}
	want.Location, want.Closure.Slices, want.SliceSnapshot = location, publicationLossSliceDescriptor(location), snapshot
	body, id := publicationLossSliceCarrier(before.root.Domain, snapshot, want.Closure.Slices, publicationLossSliceRow(location))
	sliceObject := publicationExpectedHash("ENKV/end-work-slice-page/v1", binary.BigEndian.AppendUint16(append(append([]byte(nil), operation[:]...), prior.SlicePage.Digest[:]...), prior.SlicePage.Index))
	want.SlicePage = publicationLossPreparedPage(t, candidate, before.root.Domain, sliceObject, prior.SlicePage.Index, contract.GeneratorVectorSupportKind, id, body)
	delete(want.Rows, generatedRecordKey{contract.GeneratorVectorSupportKind, oldID})
	want.Rows[generatedRecordKey{contract.GeneratorVectorSupportKind, id}] = publicationLossSupportFact{contract.GeneratorVectorSupportKind, id, sha256.Sum256(body), uint32(len(body))}
	var root format.Root
	for _, object := range candidate.objects {
		if object.ref == candidate.head.Core.Root {
			var err error
			root, err = format.DecodeRoot(object.body)
			if err != nil {
				t.Fatal("publication loss prepared root placement", err)
			}
		}
	}
	if !slices.Contains(root.RequiredSupport, fragmentRef) || !slices.Contains(root.RequiredSupport, want.SlicePage) {
		t.Fatal("publication loss expected physical pages not selected beforeCAS")
	}
	for _, ref := range root.RequiredSupport {
		oldFragment := false
		for _, fact := range prior.Fragments {
			oldFragment = oldFragment || ref == fact.Ref
		}
		if ref.Index == fragmentRef.Index && ref != fragmentRef || ref == prior.SlicePage || oldFragment {
			t.Fatal("publication loss compact placement collides or keeps old Slice page")
		}
	}
	return want
}

func publicationLossAssertGeneratedFacts(t *testing.T, selected *StateSession, expected publicationLossGeneratedPreservation) {
	t.Helper()
	actual := publicationLossGeneratedFacts(t, selected)
	if reflect.DeepEqual(actual, expected) {
		return
	}
	if actual.SliceSnapshot != expected.SliceSnapshot {
		t.Log("publication loss generated SliceSnapshot equal=false")
	}
	for _, fact := range []struct {
		name  string
		equal bool
	}{
		{"SlicePage", actual.SlicePage == expected.SlicePage},
		{"Location", actual.Location == expected.Location},
		{"Intent", bytes.Equal(actual.Intent, expected.Intent)},
		{"Entries", reflect.DeepEqual(actual.Entries, expected.Entries)},
	} {
		if !fact.equal {
			t.Logf("publication loss generated field=%s equal=false", fact.name)
		}
	}
	av, ev := reflect.ValueOf(actual.Closure), reflect.ValueOf(expected.Closure)
	for i := 0; i < av.NumField(); i++ {
		if !reflect.DeepEqual(av.Field(i).Interface(), ev.Field(i).Interface()) {
			t.Logf("publication loss generated closure field=%s equal=false", av.Type().Field(i).Name)
		}
	}
	for key, row := range expected.Rows {
		if got, present := actual.Rows[key]; !present || got != row {
			t.Logf("publication loss generated support kind=%d id=%x present=%t body_equal=%t", key.kind, key.id, present, got == row)
		}
	}
	for id, fact := range expected.Fragments {
		if got, present := actual.Fragments[id]; !present || got != fact {
			t.Logf("publication loss generated fragment id=%x present=%t backing_equal=%t", id, present, got == fact)
		}
	}
	t.Fatalf("publication loss exact generated source/intent/support changed rows=%d/%d fragments=%d/%d", len(actual.Rows), len(expected.Rows), len(actual.Fragments), len(expected.Fragments))
}

type publicationLossReceiptIndex struct {
	Success, Failure, Order contract.GeneratorDescriptor
	Body, Fragment          []byte
	Blob, RecordID          contract.ID
	Ref                     format.Ref
	Location                format.FragmentLocation
}

func publicationLossExpectedReceiptIndex(t *testing.T, before *StateSession, windows contract.MutationReceiptWindows, candidate *Candidate) publicationLossReceiptIndex {
	t.Helper()
	if candidate.head.EndWork == nil {
		t.Fatal("publication loss missing prepared disposition identity")
	}
	var out publicationLossReceiptIndex
	out.Body = binary.BigEndian.AppendUint16(nil, 2)
	for i, rows := range [][]contract.CompactMutationReceipt{windows.Successes, windows.Failures} {
		ids := make([]contract.ID, 0, len(rows)+1)
		for _, row := range rows {
			ids = append(ids, row.OperationID)
		}
		if i == 0 {
			ids = append(ids, candidate.head.EndWork.OperationID)
			if len(ids) > 256 {
				ids = ids[len(ids)-256:]
			}
		}
		vector := binary.BigEndian.AppendUint32(nil, uint32(len(ids)))
		for _, id := range ids {
			vector = publicationExpectedBlob(vector, id[:])
		}
		label := "success-window"
		if i == 1 {
			label = "failure-window"
		}
		d := contract.GeneratorDescriptor{Digest: publicationLossGeneratorHash(label, vector), Length: uint64(len(vector)), Count: uint32(len(ids))}
		if i == 0 {
			out.Success = d
		} else {
			out.Failure = d
		}
		out.Body = publicationExpectedBlob(out.Body, vector)
	}
	order := make([]contract.ID, 0, len(windows.Order)+1)
	for _, id := range windows.Order {
		if len(windows.Successes) == 256 && id == windows.Successes[0].OperationID {
			continue
		}
		order = append(order, id)
	}
	order = append(order, candidate.head.EndWork.OperationID)
	vector := binary.BigEndian.AppendUint32(nil, uint32(len(order)))
	for _, id := range order {
		vector = publicationExpectedBlob(vector, id[:])
	}
	out.Order = contract.GeneratorDescriptor{Digest: publicationLossGeneratorHash("receipt-order", vector), Length: uint64(len(vector)), Count: uint32(len(order))}
	out.Body = publicationExpectedBlob(out.Body, vector)
	out.Blob = publicationLossReceiptBlob(before.root.Domain, out.Success, out.Failure, out.Order)
	out.RecordID = publicationLossGeneratorHash("fragment", binary.BigEndian.AppendUint16(append([]byte(nil), out.Blob[:]...), 0))
	out.Fragment = binary.BigEndian.AppendUint16(nil, 1)
	out.Fragment = append(out.Fragment, out.Blob[:]...)
	out.Fragment = binary.BigEndian.AppendUint16(out.Fragment, 0)
	out.Fragment = binary.BigEndian.AppendUint16(out.Fragment, 1)
	out.Fragment = binary.BigEndian.AppendUint64(out.Fragment, uint64(len(out.Body)))
	whole := sha256.Sum256(out.Body)
	out.Fragment = append(out.Fragment, whole[:]...)
	out.Fragment = binary.BigEndian.AppendUint32(out.Fragment, 0)
	out.Fragment = publicationExpectedBlob(out.Fragment, out.Body)
	matched := 0
	for _, object := range candidate.objects {
		if object.ref.Kind != contract.RequiredSupportKind {
			continue
		}
		page, err := format.InspectRequiredSupportPage(object.body)
		if err != nil {
			t.Fatal("publication loss prepared support page", err)
		}
		for _, row := range page.Records {
			if row.RecordID != out.RecordID {
				continue
			}
			if len(page.Records) != 1 || row.Kind != contract.GeneratedFragmentSupportKind || !bytes.Equal(row.Body, out.Fragment) || page.Domain != before.root.Domain || page.Object != object.ref.Object || page.Index != object.ref.Index || object.ref.Length != uint32(contract.RequiredSupportPageHeaderLength+contract.SupportRecordOverhead+len(out.Fragment)) || object.ref.Digest != sha256.Sum256(object.body) {
				t.Fatal("publication loss prepared receipt-index bytes/location differ")
			}
			out.Ref = object.ref
			out.Location = format.FragmentLocation{BlobID: out.Blob, SupportPageIndex: object.ref.Index}
			matched++
		}
	}
	if matched != 1 {
		t.Fatal("publication loss has no unique independently derived prepared receipt index", matched)
	}
	return out
}
func publicationLossAssertReceiptIndex(t *testing.T, after *StateSession, expected publicationLossReceiptIndex) {
	t.Helper()
	if after.root.Generated.SuccessWindow != expected.Success || after.root.Generated.FailureWindow != expected.Failure || after.root.Generated.ReceiptOrder != expected.Order {
		t.Fatal("publication loss receipt-window descriptors differ from predecessor plus prepared operation")
	}
	matched := 0
	for _, location := range after.root.Generated.Fragments {
		if location.BlobID != expected.Blob {
			continue
		}
		fact, present := after.fragmentFacts[location]
		if location != expected.Location || !present || fact.ref != expected.Ref || fact.row.RecordID() != expected.RecordID || fact.row.Kind() != contract.GeneratedFragmentSupportKind || fact.row.BodyDigest() != sha256.Sum256(expected.Fragment) || fact.row.BodyLength() != uint32(len(expected.Fragment)) || fact.physical != 0 || fact.logical != 0 || fact.index != 0 || fact.count != 1 || fact.total != uint64(len(expected.Body)) || fact.whole != sha256.Sum256(expected.Body) || fact.offset != 0 || fact.payloadLength != uint32(len(expected.Body)) {
			t.Fatal("publication loss exact selected receipt-index fragment/backing differs")
		}
		called := false
		r, err := after.withSelectedFragment(t.Context(), location, func(body []byte) error {
			called = true
			if !bytes.Equal(body, expected.Body) {
				return contract.ErrRecord
			}
			return nil
		})
		if !called || err != nil || r.Outcome != 0 {
			t.Fatal("publication loss exact selected receipt-index payload differs", r, err)
		}
		matched++
	}
	if matched != 1 {
		t.Fatal("publication loss selected receipt-index cardinality", matched)
	}
}

func publicationLossDispose(t *testing.T, ctx context.Context, env fixtureEnvironment, admitted OpenContext, target contract.ID, expectedGenerated publicationLossGeneratedPreservation) (*StateSession, publicationLossReceiptIndex, publicationLossGeneratedPreservation) {
	t.Helper()
	store := env.Store.(*memoryStore)
	before, r := openAdministrative(ctx, admitted, store)
	if before == nil {
		t.Fatal("publication loss administrative Open", r)
	}
	var group format.AdministrativeGroup
	for _, row := range before.adminIndex.Groups {
		if row.GroupID == target {
			group = row
		}
	}
	if group.GroupID.IsZero() {
		t.Fatal("publication loss exact disposition target absent")
	}
	windows, err := before.receiptWindowsFromAdministrativeSupport()
	if err != nil {
		t.Fatal("publication loss predecessor administrative receipt windows", err)
	}
	_, beforeBodies, err := before.retainedMutationReceiptBodies()
	if err != nil {
		t.Fatal("publication loss predecessor original receipt bytes", err)
	}
	originalBodies := make(map[contract.ID][]byte, len(beforeBodies))
	for id, body := range beforeBodies {
		originalBodies[id] = bytes.Clone(body)
	}
	cas := store.cas
	public, private := env.Custody.Calls()
	wantWarnings := before.root.WarningBits | WarningPublicationOrderValue | WarningDiscardedExactEvidence | WarningPossibleStoreGarbage
	candidate, r := prepareTestEndSelectedWork(t, before, ctx, target, env.Trust)
	if candidate == nil {
		t.Fatal("publication loss actual disposition preparation", r)
	}
	expectedIndex := publicationLossExpectedReceiptIndex(t, before, windows, candidate)
	expectedGenerated = publicationLossExpectedEndGenerated(t, before, candidate, expectedGenerated)
	after, r := before.selectCandidate(ctx, candidate)
	if after == nil || r.Outcome != ObservedCurrent || store.cas != cas+1 {
		t.Fatal("publication loss disposition CAS", r, store.cas-cas)
	}
	after, r = Open(ctx, admitted, store)
	if after == nil || r.Outcome != ObservedCurrent {
		t.Fatal("publication loss disposition cold reopen", r)
	}
	publicationLossAssertReceiptIndex(t, after, expectedIndex)
	publicationLossAssertGeneratedFacts(t, after, expectedGenerated)
	q := after.head.EndWork
	if q == nil || q.TargetGroupID != target || q.TargetOwnerID != group.OwnerID || q.TargetID != group.TargetID || q.TargetKind != group.OwnerKind || q.SelectedEvidenceSummary != group.SelectedEvidenceSummary || q.PredecessorRevisionID != before.head.Core.Revision || q.PredecessorFullHEADDigest != contract.Hash(before.body) || q.PredecessorToken != before.token || q.BeforeWarningBits != before.root.WarningBits || q.AfterWarningBits != wantWarnings || after.root.WarningBits != wantWarnings {
		t.Fatal("publication loss exact disposition/warning facts differ")
	}
	got, err := after.receiptWindows(ctx)
	if err != nil || len(got.Successes) != len(windows.Successes)+1 || !slices.Equal(got.Successes[:len(windows.Successes)], windows.Successes) || !slices.Equal(got.Failures, windows.Failures) {
		t.Fatal("publication loss exact disposition receipt windows", err)
	}
	_, afterBodies, err := after.retainedMutationReceiptBodies()
	if err != nil || len(afterBodies) != len(originalBodies)+1 {
		t.Fatal("publication loss appended receipt body set", err)
	}
	for id, body := range originalBodies {
		if !bytes.Equal(afterBodies[id], body) {
			t.Fatal("publication loss append changed an original retained receipt body")
		}
	}
	last := got.Successes[len(got.Successes)-1]
	if last.OperationKind != contract.OperationEndSelectedWork || last.OperationID != q.OperationID || last.StateResult != contract.ReceiptStateWorkEnded || last.EffectSummary != contract.ReceiptEffectNotApplicable || last.OutputSummary != contract.ReceiptOutputNotApplicable || last.EvidenceCeiling != contract.ReceiptEvidenceCanonical || last.CanonicalOutcome != contract.ReceiptCanonicalSelected || last.PredecessorRevisionID != before.head.Core.Revision || last.RequestedRevisionID != after.head.Core.Revision || last.ObservedRevisionID != after.head.Core.Revision || last.AdministrativeTargetKind != group.OwnerKind || last.AdministrativeTargetID != group.TargetID || last.AdministrativeOriginalEvidence != group.SelectedEvidenceSummary || last.WarningBits != uint64(wantWarnings) || last.AdministrativeWarningChanges != wantWarnings&^before.root.WarningBits || last.AdministrativePageDelta != int16(after.root.ChildCount)-int16(before.root.ChildCount) || last.AdministrativeByteDelta != int64(after.root.ChildEncodedBytes)-int64(before.root.ChildEncodedBytes) || last.AdministrativeDisposition != q.RequestCoreDigest {
		t.Fatal("publication loss exact local disposition receipt differs")
	}
	if p, k := env.Custody.Calls(); p != public || k != private {
		t.Fatal("publication loss disposition used a custody key route")
	}
	for _, row := range after.adminIndex.Groups {
		if row.GroupID == target {
			t.Fatal("publication loss disposed group remained selected")
		}
	}
	return after, expectedIndex, expectedGenerated
}

// This one-time fixture uses the normal apply/sign/select owner and the existing
// archive exporter. The setup phase supplies its public trust asset separately.
func configurationRecoveryReaderFixture(t *testing.T, ctx context.Context, input configurationRecoveryFixtureInput, env fixtureEnvironment, selected *StateSession, keys *custody.Fixture) {
	authority, recipient := selected.admission.recipient, fixtureID(env.Domain, "reader")
	members := []contract.ID{authority, recipient}
	slices.SortFunc(members, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	entries := []ApplyEntryInput{
		{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "", Recipients: members, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte{}},
		{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "a/\n雪", Recipients: members, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte{0, 10, 65}},
		suppliedSecret(t, env, "secret", "Reader raw fixture", custody.StandardValue, members...),
		suppliedSecret(t, env, "encoded", "Reader encoded fixture", custody.StandardValue, members...),
	}
	rows := []struct {
		name                    string
		destination             contract.OutputDestination
		secretSlot, encodedSlot string
	}{
		{"aws", outputFixtureDestination("aws", "aws-secrets-manager", 63, contract.OutputPolicy{}), "arn:aws:secretsmanager:us-east-1:123456789012:secret:secret", "arn:aws:secretsmanager:us-east-1:123456789012:secret:encoded"},
		{"gcp", outputFixtureDestination("gcp", "gcp-secret-manager", 63, contract.OutputPolicy{}), "projects/123456789/secrets/secret", "projects/123456789/secrets/encoded"},
		{"github-environment", outputFixtureDestination("github-environment", "github-actions", 63, contract.OutputPolicy{}), "repos/owner/repo/environments/prod/secrets/SECRET", "repos/owner/repo/environments/prod/secrets/ENCODED"},
		{"github-organization", outputFixtureDestination("github-organization", "github-actions", 255, contract.OutputPolicy{ContractID: "fixture/organization-policy/v1", Data: []byte{1, 7, 11}}), "orgs/owner/actions/secrets/SECRET", "orgs/owner/actions/secrets/ENCODED"},
		{"github-repository", outputFixtureDestination("github-repository", "github-actions", 63, contract.OutputPolicy{}), "repos/owner/repo/actions/secrets/SECRET", "repos/owner/repo/actions/secrets/ENCODED"},
	}
	output := &outputApplyInput{}
	var destinations []string
	for _, row := range rows {
		binding := outputApplyBinding{destinationID: row.name, destination: row.destination}
		for _, value := range []struct {
			name, slot string
			encoding   uint8
		}{{"secret", row.secretSlot, contract.OutputEncodingRaw}, {"encoded", row.encodedSlot, contract.OutputEncodingBase64}} {
			locator := value.slot
			switch row.destination.ServiceContractID {
			case "aws-secrets-manager":
				locator = ""
			case "gcp-secret-manager":
				locator += "/versions/latest"
			}
			target := outputFixtureTarget(row.destination.ServiceContractID, value.slot, locator, value.encoding, row.destination.Capabilities, row.destination.Policy)
			target.LocatorRequiresCreation = row.destination.ServiceContractID == "aws-secrets-manager"
			binding.targets = append(binding.targets, outputApplyTarget{entryName: value.name, target: target})
		}
		output.bindings = append(output.bindings, binding)
		destinations = append(destinations, row.name)
	}
	output.routes = []outputApplyRoute{
		{defaultRoute: true, destinations: []string{"aws"}},
		{entryName: "", destinations: []string{}},
		{entryName: "a/\n雪", destinations: []string{}},
		{entryName: "encoded", destinations: []string{"aws"}},
	}
	finalOutput := ownOutputApplyInput(output)
	finalOutput.routes[0].destinations = slices.Clone(destinations)
	finalOutput.routes[3].destinations = slices.Clone(destinations)
	for i := range output.bindings {
		if output.bindings[i].destinationID != "aws" {
			output.bindings[i].targets = nil
		}
	}

	selected = selectAdmittedOutputConfiguration(t, ctx, selected, env, keys, entries, output)
	configuration := selected.root.OutputConfiguration
	private := newPublicationControlledPrivate()
	private.configureOwner = func(owner *publicationControlledOwner) {
		switch owner.input.Target.CanonicalTarget {
		case "arn:aws:secretsmanager:us-east-1:123456789012:secret:secret":
			owner.resource = "arn:aws:secretsmanager:us-east-1:123456789012:secret:secret-AbCd12"
		case "arn:aws:secretsmanager:us-east-1:123456789012:secret:encoded":
			owner.resource = "arn:aws:secretsmanager:us-east-1:123456789012:secret:encoded-XyZ123"
		default:
			t.Fatal("Reader archive publication reached an unselected destination")
		}
		owner.consumerLocator = owner.resource + "?stage=AWSCURRENT"
	}
	for _, slot := range []string{rows[0].secretSlot, rows[0].encodedSlot} {
		selected.admission.publicationNamespaces = append(selected.admission.publicationNamespaces, publicationNamespace{
			domain: env.Domain, service: "aws-secrets-manager", physical: slot,
			premise: fixtureID(env.Domain, "Reader archive independent AWS namespace "+slot),
		})
	}
	admitted := OpenContext{admission: &selected.admission}
	names := []string{"encoded", "secret"}
	deadline := time.Now().Add(30 * time.Second)
	if !publicationNormalAdmission(ctx, selected, deadline) {
		t.Fatal("Reader archive current Normal publication admission")
	}
	consumer, result := selected.admitConsumerSelection(ctx, names, authority)
	if consumer == nil || result.Outcome != ObservedCurrent || len(consumer.slots) != 2 {
		t.Fatal("Reader archive current Authority consumer selection", result)
	}
	plan, result := selected.planPublication(ctx, publicationInput{names: names, acting: authority, deadline: deadline}, private.callbacks())
	if plan == nil || result.Outcome != ObservedCurrent || len(plan.targets) != 2 {
		t.Fatal("Reader archive AWS creation planning", result)
	}
	for _, target := range plan.targets {
		if target.target.ServiceContractID != "aws-secrets-manager" || target.destination != "aws" {
			t.Fatal("Reader archive creation selected a non-AWS target")
		}
	}
	executed := plan.execute(ctx, private.callbacks(), func(ctx context.Context) (*StateSession, contract.Trust, Result) {
		current, result := Open(ctx, admitted, env.Store)
		return current, env.Trust, result
	})
	if executed.state.Outcome != ObservedCurrent || executed.summary != contract.PublicationSummaryComplete || len(executed.output.Entries) != 2 || len(private.owners) != 2 {
		t.Fatal("Reader archive selected AWS creation", executed)
	}
	for _, row := range executed.output.Entries {
		if len(row.Actions) != 1 || row.Actions[0].Action != contract.PublicationCreateWithValue || row.Actions[0].Disposition != contract.PublicationOutcomeAcknowledged {
			t.Fatal("Reader archive AWS creation did not select its complete lifecycle")
		}
	}
	selected, result = Open(ctx, admitted, env.Store)
	if selected == nil || result.Outcome != ObservedCurrent || selected.root.OutputConfiguration != configuration {
		t.Fatal("Reader archive creation changed desired output configuration", result)
	}
	selected = selectAdmittedOutputConfiguration(t, ctx, selected, env, keys, installedApplyCurrentInput(selected), finalOutput)
	archive := configurationRecoveryArchive(t, env, selected, env.Store.(*memoryStore))
	writeConfigurationRecoveryJSON(t, input.Output, installedarchive.RecoveryFixture{Archive: archive, Secrets: 2, Values: []installedarchive.ExpectedValue{{Name: "", Bytes: []byte{}}, {Name: "a/\n雪", Bytes: []byte{0, 10, 65}}, {Name: "encoded", Bytes: []byte("enkv first secret test value")}, {Name: "secret", Bytes: []byte("enkv first secret test value")}}})
}

// configurationRecoveryAdministrativeFixture uses the existing native export
// route to retain both sides of a real EndWork selection, with no private keys.
func configurationRecoveryAdministrativeFixture(t *testing.T, ctx context.Context, input configurationRecoveryFixtureInput, env fixtureEnvironment, selected *StateSession) {
	selected = configurationRecoveryRetiring(t, ctx, env, selected, false)
	store := env.Store.(*memoryStore)
	values := []installedarchive.ExpectedValue{{Name: "generated-alpha", Bytes: []byte("enkv first secret test value")}}
	before := installedarchive.RecoveryFixture{Archive: configurationRecoveryArchive(t, env, selected, store), Secrets: 1, Values: values}
	preview, result := openAdministrativeEngineFixture(ctx, selected, store, nil, LocalAuthorityPreview)
	if preview == nil || result.Outcome != ObservedCurrent || len(preview.state.adminIndex.Groups) != 1 {
		t.Fatal("administrative export requires exactly one real selected duty", result)
	}
	group := preview.state.adminIndex.Groups[0].GroupID
	decision, result := preview.Preview(ctx, group)
	if result.Outcome != ObservedCurrent {
		t.Fatal("administrative export preview", result)
	}
	ender, result := openAdministrativeEngineFixture(ctx, selected, store, env.Trust, LocalAuthorityEnd)
	if ender == nil || result.Outcome != ObservedCurrent {
		t.Fatal("administrative export fresh End admission", result)
	}
	outcome := ender.End(ctx, decision)
	if outcome.Result.Outcome != ObservedCurrent || len(outcome.Receipt) != contract.CompactMutationReceiptLength {
		t.Fatal("administrative export real End selection", outcome)
	}
	after, result := openAdministrativeEngineFixture(ctx, selected, store, nil, LocalAuthorityRecheck)
	if after == nil || result.Outcome != ObservedCurrent {
		t.Fatal("administrative export selected receipt open", result)
	}
	receipt, result := after.Recheck(ctx, outcome.OperationID)
	encoded, err := contract.EncodeCompactMutationReceipt(receipt)
	if err != nil || result.Outcome != ObservedCurrent || !bytes.Equal(encoded, outcome.Receipt) {
		t.Fatal("administrative export exact selected receipt", result, err)
	}
	basis, err := os.ReadFile(input.Output + ".basis.json")
	if err != nil {
		t.Fatal("administrative export independent setup basis", err)
	}
	writeConfigurationRecoveryJSON(t, input.Output, installedarchive.AdministrativeFixture{
		Before: before, After: installedarchive.RecoveryFixture{Archive: configurationRecoveryArchive(t, env, after.state, store), Secrets: 1, Values: values},
		Basis: basis, GroupID: group, OperationID: outcome.OperationID, PreviewIdentity: decision.Identity, Receipt: bytes.Clone(encoded),
	})
}

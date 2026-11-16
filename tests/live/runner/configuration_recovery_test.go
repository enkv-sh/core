package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	"enkv.sh/crypto/testsupport/custody"
	"enkv.sh/crypto/testsupport/installedarchive"
)

type localRecoveryWriterSetup struct {
	Facts     installedarchive.RecoverySetup
	Resources installedarchive.RecoveryResources
}

func configurationCaseForCondition(t testing.TB, condition string) string {
	t.Helper()
	for _, name := range catalog.ConfigurationRecoveryNames() {
		row, known := catalog.ConfigurationRecovery(name)
		if known && row.Condition == condition {
			return name
		}
	}
	t.Fatal("controlled reconstruction condition is not declared")
	return ""
}

func runLiveConfigurationRecoveryWriter(t testing.TB, ctx context.Context, env fixtureEnvironment, name, state string, input liveRunInput, inventory *objectInventory, budget *runBudget, localSetup ...*localRecoveryWriterSetup) {
	t.Helper()
	row, known := catalog.ConfigurationRecovery(name)
	if !known || inventory == nil {
		t.Fatal("recovery writer owner unavailable")
	}
	// The coordinator owns this directory beyond writer exit and removes it on
	// every outcome. It is not part of the deleted local configuration.
	directory := os.Getenv("ENKV_RECOVERY_PRIVATE_ORACLE")
	if input.ConfigurationRecovery != nil {
		directory = input.ConfigurationRecovery.OracleDirectory
	}
	info, err := os.Lstat(directory)
	if err != nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("recovery private oracle owner refused")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatal("recovery private oracle is not empty")
	}
	if len(localSetup) > 1 {
		t.Fatal("local setup owner is ambiguous")
	}
	var setup *localRecoveryWriterSetup
	if len(localSetup) == 1 && localSetup[0] != nil {
		setup = localSetup[0]
	}
	run := newScenarioRun(t, ctx, env)
	var fixture *environmentFixture
	run.phase("setup", func() {
		if input.ConfigurationRecovery != nil && !input.ConfigurationRecovery.Locations.PriorDomain.IsZero() {
			liveConfigurationRecoveryPriorGenesis(t, ctx, run.env, input, inventory, budget, setup)
		}
		fixture = newEnvironmentFixture(t, ctx, run.env, nil, false)
	})
	run.phase("transition", func() {
		if row.Condition == "generated-retiring" || row.Condition == "generated-uncertain" {
			fixture.session = configurationRecoveryRetiring(t, ctx, run.env, fixture.session, row.Condition == "generated-uncertain")
		} else if row.Condition != "zero-secret-genesis" {
			configurationRecoveryPopulate(t, ctx, run, fixture, row.Condition, row.Generated)
		}
		if row.Condition == "reader-replacement" {
			replaceReaderInSelectedForName(t, ctx, run, fixture, "supplied-shared")
		}
		if history, ok := installedarchive.ReplacementFor(row.Condition); ok {
			if setup != nil {
				configurationRecoveryReplace(t, ctx, &env, fixture, history, localSetup[0].Resources)
			} else {
				liveConfigurationRecoveryReplace(t, ctx, env, fixture, history)
			}
			if history.LaterHEAD {
				current := env
				if setup == nil {
					current = liveConfigurationRecoveryCurrentEnvironment(t, ctx, env, input, budget, fixture.session)
					defer current.Custody.Close()
				}
				configurationRecoveryLaterHEAD(t, ctx, current, fixture)
			}
		}
		selected := fixture.session
		configuration := input.Settings
		location := contract.StoreLocation{Provider: liveFamily, Region: configuration.Region, Bucket: configuration.Bucket, PrefixBeforeHEAD: input.Prefix, ExpectedOwner: configuration.Account}
		if liveFamily == contract.GCP {
			location.ExpectedOwner = ""
		}
		if input.ConfigurationRecovery != nil && input.ConfigurationRecovery.Locations.CopiedPrefix != "" {
			prefix := input.ConfigurationRecovery.Locations.CopiedPrefix
			if prefix != input.Prefix+"/copied" || env.Put == nil {
				t.Fatal("copied location setup owner refused")
			}
			for _, object := range liveConfigurationRecoveryObjects(t, ctx, env.Store, inventory) {
				key := prefix + object.Key[len(input.Prefix):]
				if err := env.Put(ctx, key, bytes.Clone(object.Body)); err != nil {
					t.Fatal("owned copied object was not acknowledged")
				}
			}
		}
		archive := configurationRecoveryArchiveMetadata(t, env, selected, location)
		archive = configurationRecoveryArchiveWithObjects(archive, liveConfigurationRecoveryObjects(t, ctx, env.Store, inventory))
		if _, err := archive.SelectedParts(); err != nil {
			t.Fatal("recovery writer selected archive refused", err)
		}
		keys := env.Custody
		if _, history := installedarchive.ReplacementFor(row.Condition); history && setup == nil {
			control := currentControlOf(selected)
			keys = liveSelectedPrivateCustody(t, ctx, input, budget, selected, contract.BindingTableRow{SubjectKind: 1, SubjectID: control.AuthorityRecipientID, Binding: control.AuthorityKMSBinding})
			defer keys.Close()
		}
		if selected.root.SecretCount > 0 && env.ReserveCustody != nil && !env.ReserveCustody("consume", int(selected.root.SecretCount)) {
			t.Fatal("recovery capture custody budget refused")
		}
		oracles := configurationRecoveryCapture(t, ctx, selected, keys, directory)
		fixture := installedarchive.RecoveryFixture{Archive: archive, Secrets: int(selected.root.SecretCount), Oracles: oracles}
		writeConfigurationRecoveryJSON(t, filepath.Join(state, "recovery-parent.json"), fixture)
	})
}

func liveConfigurationRecoveryObjects(t testing.TB, ctx context.Context, store contract.Store, inventory *objectInventory) []installedarchive.Object {
	t.Helper()
	owned, err := inventory.owned(false)
	if err != nil || len(owned) == 0 || len(owned) > 4096 {
		t.Fatal("recovery complete object ownership refused")
	}
	keys := make([]string, 0, len(owned))
	for key := range owned {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var objects []installedarchive.Object
	var total uint64
	for _, key := range keys {
		inventory.mu.Lock()
		var length uint64
		for _, intent := range inventory.image.Intents {
			if intent.Key == key && owned[key][intent.Digest] && intent.Bytes > length {
				length = intent.Bytes
			}
		}
		inventory.mu.Unlock()
		if length == 0 || length > 32<<20 {
			t.Fatal("recovery recorded object length refused")
		}
		result := store.Read(ctx, key, uint32(length))
		if result.Status != contract.ReadOK || !result.Token.Valid() || !owned[key][bodyDigest(result.Body)] {
			t.Fatal("recovery object snapshot differs from owner")
		}
		total += uint64(len(result.Body))
		if total > 32<<20 {
			t.Fatal("recovery object snapshot exceeds its bound")
		}
		token, err := contract.AppendToken(nil, result.Token)
		if err != nil {
			t.Fatal("recovery object token refused")
		}
		objects = append(objects, installedarchive.Object{Key: key, TokenWire: token, Token: result.Token, Body: bytes.Clone(result.Body), BodySHA256: fmt.Sprintf("%x", sha256.Sum256(result.Body))})
	}
	return objects
}

type liveRecoveryWriterControl struct {
	Setup, Resources, State, Oracle, Condition string
	Limits                                     *liveLimits
}

// full_only: false
func TestLiveRecoveryWriterExportKeepsCompletePrivateWitness(t *testing.T) {
	ctx := t.Context()
	env, _ := genesisEnvironment(t, liveFamily, false, 3)
	var control liveRecoveryWriterControl
	var controlledSetup *localRecoveryWriterSetup
	var chosen installedarchive.RecoveryResources
	if path := os.Getenv("ENKV_RECOVERY_LIVE_WRITER_CONTROL"); path != "" {
		readConfigurationRecoveryJSON(t, path, &control)
		var setup installedarchive.RecoverySetup
		var resources installedarchive.RecoveryResources
		readConfigurationRecoveryJSON(t, control.Setup, &setup)
		readConfigurationRecoveryJSON(t, control.Resources, &resources)
		controlledSetup = &localRecoveryWriterSetup{Facts: setup, Resources: resources}
		chosen = resources
		env = configurationRecoverySetupEnvironment(t, env, setup, resources, false)
		store := env.Store.(*memoryStore)
		env.FreshGeneratedRecord = func(tb testing.TB, selected *StateSession, attempt contract.ID, packet []byte) *StateSession {
			material := resources.Normal.Material
			binding := currentControlOf(selected).NormalSigning
			for _, resource := range resources.NormalSuccessors {
				if resource.Selector == binding.KeySelector && bytes.Equal(resource.PublicKey, binding.SPKI) {
					material = resource.Material
				}
			}
			return selectFreshGeneratedRecord(tb, store, selected, attempt, packet, material)
		}

	}
	condition := control.Condition
	if condition == "" {
		condition = "complete"
	}
	row, known := catalog.ConfigurationRecovery(configurationCaseForCondition(t, condition))
	if !known {
		t.Fatal("local writer control condition refused")
	}
	var generatedCounts func() (int32, int32)
	if row.Generated {
		env.GeneratedProcess, generatedCounts = configurationRecoveryLocalGeneratedProcess(t)
	}
	store := env.Store.(*memoryStore)
	configuration := store.StoreConfiguration()
	state, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if control.State != "" {
		state = control.State
	}
	oracle := filepath.Join(state, "oracle")
	if control.Oracle != "" {
		oracle = control.Oracle
	}
	if control.Oracle == "" {
		if err := os.Mkdir(oracle, 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("ENKV_RECOVERY_PRIVATE_ORACLE", oracle)
	inventory := &objectInventory{path: filepath.Join(state, "inventory.json"), image: inventoryImage{Version: 1, Prefix: configuration.PrefixBeforeHEAD, Domain: configuration.DomainID, Deleted: make(map[string]int)}}
	budget := &runBudget{limits: liveLimits{Requests: 4096, BodyBytes: 1 << 30, Objects: 4096, ObjectBytes: 32 << 20}, keys: make(map[string]bool)}
	if row.Generated {
		if control.Limits == nil || control.Limits.Requests == 0 || control.Limits.BodyBytes == 0 {
			t.Fatal("finite generated writer allowance unavailable")
		}
		budget.limits = *control.Limits
		env.GeneratedProcess.BeforeCreate = func(contract.ID) error {
			if !budget.reserveGenerator(true) {
				return fmt.Errorf("local create budget refused")
			}
			return nil
		}
		env.GeneratedProcess.BeforeDelete = func(contract.ID, contract.ID) error {
			if !budget.reserveGenerator(false) {
				return fmt.Errorf("local retire budget refused")
			}
			return nil
		}
	}
	t.Cleanup(func() {
		t.Logf("local writer budget reservation=%+v limits=%+v exhausted=%t", budget.snapshot(), budget.limits, budget.exhausted)
	})
	env.Store = recordedStore{Store: store, inventory: inventory, budget: budget}
	// An owned but unselected object must remain in the complete snapshot.
	unused := fmt.Sprintf("%s/%x/support/0/%s", configuration.PrefixBeforeHEAD, configuration.DomainID, bodyDigest([]byte("unused")))
	if result := env.Store.Create(ctx, unused, []byte("unused")); result.Status != contract.WriteAcknowledged {
		t.Fatal("unselected fixture object refused", result)
	}
	locations := installedarchive.RecoveryLocations{}
	if condition == "new-domain-no-pin" || condition == "prior-domain-pin" {
		locations.PriorDomain = chosen.PriorDomain
	}
	if condition == "copied-location" {
		locations.CopiedPrefix = configuration.PrefixBeforeHEAD + "/copied"
	}
	if locations != (installedarchive.RecoveryLocations{}) {
		inventory.image.RecoveryLocations = &locations
	}
	env.Put = func(ctx context.Context, key string, body []byte) error {
		if result := env.Store.Create(ctx, key, body); result.Status != contract.WriteAcknowledged {
			return errInventory
		}
		return nil
	}
	env.Delete = func(ctx context.Context, key string) error {
		owned, err := inventory.owned(false)
		if err != nil || len(owned[key]) == 0 {
			return errInventory
		}
		return inventory.remove(ctx, env.Store, testDelete(store), key, owned[key])
	}
	var phases []string
	env.Phase = func(name string) { phases = append(phases, name) }
	input := liveRunInput{Scenarios: []string{configurationCaseForCondition(t, condition)}, Prefix: configuration.PrefixBeforeHEAD, Settings: liveSettings{Region: configuration.Region, Bucket: configuration.Bucket, Account: configuration.ExpectedOwner}, ConfigurationRecovery: &installedarchive.RecoveryWriterInput{Domain: configuration.DomainID, OracleDirectory: oracle, Locations: locations}}
	runLiveConfigurationRecoveryWriter(t, ctx, env, configurationCaseForCondition(t, condition), state, input, inventory, budget, controlledSetup)
	fixture := installedarchive.ReadRecoveryFixture(t, filepath.Join(state, "recovery-parent.json"))
	secrets, names := 3, 5
	if condition == "later-secret-denied" {
		secrets, names = 5, 7
	}
	if row.Generated {
		secrets, names = 5, 7
		wantCreates, wantDeletes := int32(2), int32(0)
		switch condition {
		case "generated-active":
			secrets, names, wantCreates = 3, 5, 1
		case "generated-retiring":
			secrets, names = 1, 1
		case "generated-uncertain":
			secrets, names, wantDeletes = 1, 1, 1
		}
		creates, deletes := generatedCounts()
		if creates != wantCreates || deletes != wantDeletes {
			t.Fatal("local real generated operation inventory differs")
		}
	}
	if fixture.Secrets != secrets || len(fixture.Oracles) != names || len(phases) != 2 || phases[0] != "setup" || phases[1] != "transition" || fixture.Archive.ObjectCount != len(store.objects) {
		t.Fatal("writer witness incomplete")
	}
	if object, ok := fixture.Archive.Object(unused); !ok || string(object.Body) != "unused" {
		t.Fatal("unselected object omitted")
	}
	if len(fixture.Values) != 0 || budget.exhausted {
		t.Fatal("private values leaked or snapshot exceeded budget")
	}
	for _, captured := range fixture.Oracles {
		info, err := os.Lstat(captured.Path)
		if err != nil || info.Mode().Perm() != 0600 || info.Size() != int64(captured.Length) {
			t.Fatal("captured private file incomplete")
		}
	}
	if control.State != "" {
		writeConfigurationRecoveryJSON(t, filepath.Join(state, "recovery-parent.json"), fixture)
		writeConfigurationRecoveryJSON(t, filepath.Join(state, "writer-reservation.json"), struct {
			Budget budgetReservation
			Phases []string
		}{budget.snapshot(), phases})
	}
}

func liveConfigurationRecoveryReplace(t testing.TB, ctx context.Context, env fixtureEnvironment, fixture *environmentFixture, history installedarchive.RecoveryReplacement) {
	t.Helper()
	if env.ReplacementActors == nil {
		t.Fatal("recovery replacement actors unavailable")
	}
	for _, step := range history.Steps {
		before := fixture.session
		actors := env.ReplacementActors(t, ctx, before, step.Operation, step.Mask, step.Approval)
		if actors.Store == nil || actors.Activate == nil || !before.admission.valid(actors.Store) || step.Mask&(2|8) != 0 && actors.Keys == nil {
			t.Fatal("recovery replacement ownership differs")
		}
		admitted := *before
		admitted.store = actors.Store
		permit := admitAuthorityReplacement(t, &admitted, actors.Keys, actors.After, step.Operation, step.Approval, step.Mask, actors.Source)
		candidate, result := admitted.PrepareSuccession(ctx, permit, actors.Signers)
		if candidate == nil || result.Outcome != ObservedCurrent {
			t.Fatal("recovery history preparation refused", result)
		}
		admission := deliverSuccessionBasis(t, candidate)
		if result = admitted.Select(ctx, candidate); result.Outcome != ObservedCurrent {
			t.Fatal("recovery history selection refused", result)
		}
		selected, result := Open(ctx, admission, env.Store)
		if selected == nil || result.Outcome != ObservedCurrent || !controlEqual(currentControlOf(selected), actors.After) {
			t.Fatal("recovery history current binding differs", result)
		}
		if actors.Keys != nil {
			actors.Keys.RetireAccess()
		}
		actors.Activate(t, selected)
		for _, named := range before.root.Names {
			old, current := before.valueEntry(named.Slot), selected.valueEntry(named.Slot)
			if current == nil || old.Name != current.Name || old.Incarnation != current.Incarnation || old.Generated != current.Generated || !bytes.Equal(old.ValueBytes, current.ValueBytes) {
				t.Fatal("recovery history changed selected value or generated settings")
			}
		}
		fixture.admission, fixture.session = admission, selected
	}
}

func liveConfigurationRecoveryCurrentEnvironment(t testing.TB, ctx context.Context, env fixtureEnvironment, input liveRunInput, budget *runBudget, selected *StateSession) fixtureEnvironment {
	t.Helper()
	control := currentControlOf(selected)
	bindings, err := selected.currentBindings()
	if err != nil {
		t.Fatal("recovery current bindings refused")
	}
	role := livePrivateKeyRole(input.Settings, contract.BindingTableRow{SubjectKind: 1, SubjectID: control.AuthorityRecipientID, Binding: control.AuthorityKMSBinding})
	routes := liveReplacementConstructionRoutes(input, env.Domain, bindings, role)
	keys, err := openLiveReplacementCustody(t, ctx, input, env.Domain, budget, bindings, routes, []string{role})
	if err != nil {
		t.Fatal("recovery later HEAD custody refused")
	}
	env.Custody, env.Crypto, env.Bindings = keys, keys.Crypto(), bindings
	env.Trust, err = openLiveReplacementSigner(ctx, input, budget, liveSigningRole(input.Settings, control.NormalSigning), control.NormalSigning)
	if err != nil {
		keys.Close()
		t.Fatal("recovery later HEAD signer refused")
	}
	return env
}

// full_only: false
func TestLiveRecoveryWriterReusesReplacementActors(t *testing.T) {
	for _, condition := range []string{"normal-signer-replaced", "normal-combined-replaced", "recovery-signer-replaced"} {
		t.Run(condition, func(t *testing.T) {
			env, _ := genesisEnvironment(t, liveFamily, true, 3)
			env = syntheticAuthorityScenarioEnvironment(t, env)
			run := newScenarioRun(t, t.Context(), env)
			fixture := newEnvironmentFixture(t, t.Context(), run.env, nil, false)
			configurationRecoveryPopulate(t, t.Context(), run, fixture, condition, false)
			before := currentControlOf(fixture.session)
			calls := 0
			actors := env.ReplacementActors
			env.ReplacementActors = func(tb testing.TB, ctx context.Context, selected *StateSession, operation, mask, approval uint8) successionActors {
				calls++
				return actors(tb, ctx, selected, operation, mask, approval)
			}
			history, ok := installedarchive.ReplacementFor(condition)
			if !ok {
				t.Fatal("required history unavailable")
			}
			liveConfigurationRecoveryReplace(t, t.Context(), env, fixture, history)
			after := currentControlOf(fixture.session)
			if calls != len(history.Steps) || after.AccessGeneration != before.AccessGeneration+1 || fixture.session.root.SecretCount != 3 {
				t.Fatal("exact replacement owner or current set differs")
			}
		})
	}
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("generated-repeated-later/recovery=%t/variable-width-selectors", recovery), func(t *testing.T) {
			ctx := t.Context()
			env, _ := genesisEnvironment(t, liveFamily, recovery, 3)
			env.Custody.UseMaximumSelectors(t)
			env.Bindings = env.Custody.Bindings()
			store := env.Store.(*memoryStore)
			configuration := store.StoreConfiguration()
			inventory := &objectInventory{path: filepath.Join(liveTestDirectory(t), "inventory.json"), image: inventoryImage{Version: 1, Prefix: configuration.PrefixBeforeHEAD, Domain: env.Domain, Deleted: make(map[string]int)}}
			budget := &runBudget{limits: liveLimits{Requests: 10000, BodyBytes: 1 << 36, Objects: 10000, ObjectBytes: 1 << 30}, keys: make(map[string]bool)}
			env.Store = recordedStore{Store: store, inventory: inventory, budget: budget}
			var generatedCounts func() (int32, int32)
			env.GeneratedProcess, generatedCounts = configurationRecoveryLocalGeneratedProcess(t)
			run := newScenarioRun(t, ctx, env)
			fixture := newEnvironmentFixture(t, ctx, run.env, nil, false)
			configurationRecoveryPopulate(t, ctx, run, fixture, "generated-repeated-later", true)
			opened := fixture.session
			before := currentControlOf(opened)
			env = syntheticAuthorityScenarioEnvironmentWithReplacement(t, env, func(tb testing.TB, _ context.Context, before *StateSession, source contract.BindingTableRow) *custody.Fixture {
				tb.Helper()
				bindings, err := before.currentBindings()
				if err != nil {
					tb.Fatal(err)
				}
				keys, err := custody.NewCurrentReplacement(tb, fixtureID(contract.Hash(before.body), "fresh current replacement"), currentControlOf(before), bindings, source)
				if err != nil {
					tb.Fatal(err)
				}
				return keys
			})
			actors, calls := env.ReplacementActors, 0
			env.ReplacementActors = func(tb testing.TB, ctx context.Context, selected *StateSession, operation, mask, approval uint8) successionActors {
				current := actors(tb, ctx, selected, operation, mask, approval)
				current.Store = recordedStore{Store: &scenarioStore{Store: store, spy: &scenarioSpy{}}, inventory: inventory, budget: budget}
				calls++
				control := currentControlOf(selected)
				if calls == 1 && len(control.AuthorityKMSBinding.KeySelector) == len(current.After.AuthorityKMSBinding.KeySelector) {
					t.Fatal("replacement did not change the encoded selector width")
				}
				wanted := contract.BindingTableRow{SubjectKind: 1, SubjectID: control.AuthorityRecipientID, Binding: control.AuthorityKMSBinding}
				if recovery {
					wanted = contract.BindingTableRow{SubjectKind: 2, SubjectID: control.Recovery.RoleID, Binding: control.Recovery.KMS}
				}
				if current.Keys == env.Custody || !sameBindingRow(current.Source, wanted) || current.Store == env.Store || current.Store.Descriptor() != env.Store.Descriptor() || fixtureStoreConfiguration(current.Store) != configuration || current.Store.(admittedMemoryStoreProvider).admittedMemoryStore() != store {
					t.Fatal("generated replacement did not use the exact independent current live routes")
				}
				return current
			}
			history, ok := installedarchive.ReplacementFor("generated-repeated-later")
			if !ok || len(history.Steps) != 2 || !history.LaterHEAD {
				t.Fatal("generated repeated history declaration differs")
			}
			liveConfigurationRecoveryReplace(t, ctx, env, fixture, history)
			after := currentControlOf(fixture.session)
			if calls != 2 || after.AccessGeneration != before.AccessGeneration+2 || fixture.session.root.SecretCount != 5 || !reflect.DeepEqual(fixture.session.root.Generated, opened.root.Generated) {
				t.Fatal("generated replacement omitted a step or changed selected work")
			}
			current := env
			current.Custody = memoryCurrentAuthorityKeys(t, fixture.session)
			current.Crypto, current.Bindings = current.Custody.Crypto(), current.Custody.Bindings()
			current.Trust = memoryCurrentAuthoritySigner(t, fixture.session)
			configurationRecoveryLaterHEAD(t, ctx, current, fixture)
			creates, deletes := generatedCounts()
			if creates != 2 || deletes != 0 || budget.exhausted {
				t.Fatal("replacement or later HEAD replayed generated work or exceeded the finite budget")
			}
		})
	}
}

func liveConfigurationRecoveryPriorGenesis(t testing.TB, ctx context.Context, env fixtureEnvironment, input liveRunInput, inventory *objectInventory, budget *runBudget, setup *localRecoveryWriterSetup) {
	t.Helper()
	facts := input.ConfigurationRecovery
	row, known := catalog.ConfigurationRecovery(input.Scenarios[0])
	if !known || facts == nil || !facts.Locations.Valid(row.Condition, input.Prefix, facts.Domain) || facts.Locations.PriorDomain.IsZero() {
		t.Fatal("prior Genesis ownership refused")
	}
	prior := env
	ids, err := allocateGenesisIDs(nil)
	if err != nil {
		t.Fatal("prior Genesis identities unavailable")
	}
	ids.Domain = facts.Locations.PriorDomain
	prior.GenesisIDs, prior.Domain = ids, ids.Domain
	if setup != nil {
		provider, ok := env.Store.(admittedMemoryStoreProvider)
		if !ok || provider.admittedMemoryStore() == nil {
			t.Fatal("local prior Store owner unavailable")
		}
		store := provider.admittedMemoryStore()
		descriptor, configuration := store.desc, store.configuration
		defer func() { store.desc, store.configuration = descriptor, configuration }()
		prior.Store = store
		prior = configurationRecoverySetupEnvironment(t, prior, installedarchive.RecoverySetup{Domain: ids.Domain, Descriptor: setup.Facts.PriorDescriptor, Configuration: setup.Facts.PriorConfiguration}, setup.Resources, false)
		prior.GenesisIDs = ids
		prior.Store = recordedStore{Store: store, inventory: inventory, budget: budget}
	} else {
		backend, err := openLiveBackend(ctx, input.Settings, input.Prefix, ids.Domain)
		if err != nil {
			t.Fatal("prior Genesis provider constructor refused")
		}
		keys, recovery, err := openLiveCustody(t, ctx, input, ids.Domain, budget)
		if err != nil {
			t.Fatal("prior Genesis private custody refused")
		}
		prior.Store = recordedStore{Store: backend.Store, inventory: inventory, budget: budget}
		prior.Trust = budgetTrust{Trust: backend.Trust, budget: budget}
		prior.PublicKey = backend.PublicKey
		prior.Custody, prior.Crypto, prior.Bindings, prior.AdmitInit, prior.RetireInit = keys, keys.Crypto(), keys.Bindings(), keys.AdmitInit, keys.RetireInit
		prior.Recovery = recovery
	}
	defer prior.Custody.Close()
	old := newEnvironmentFixture(t, ctx, prior, nil, false)
	if old.session == nil || old.session.admission.domain != ids.Domain {
		t.Fatal("earlier valid Domain was not selected")
	}
	if env.Delete == nil || env.Delete(ctx, old.session.store.Descriptor().HeadKey) != nil {
		t.Fatal("old HEAD conditional deletion was not acknowledged")
	}
}

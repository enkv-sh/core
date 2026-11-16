package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
	"enkv.sh/crypto/testsupport/custody"
)

type publicOperatorClient struct {
	Store  contract.Store
	Trust  contract.Trust
	Crypto contract.Crypto
	Route  contract.ID
}

type publicOperatorFacts struct {
	Basis      PublicBasis
	Descriptor contract.Descriptor
	Genesis    []byte
	Consumer   contract.ID
	Expected   stateImage
}

func publicAuthorityOperator(input liveRunInput) bool {
	if len(input.Scenarios) != 1 {
		return false
	}
	execution, ok := catalog.ExecutionFor(input.Scenarios[0], "live")
	return ok && execution.Family == catalog.FamilyAuthorityOperator && execution.HasFixtureCapability(catalog.FixturePublicConfiguration)
}

func publicOperatorGenesis(t testing.TB, source string) (PublicBasis, contract.GenesisDescriptorCore) {
	t.Helper()
	document := publicSourceDocument(t, source)
	ref, ok := document["generated"].(string)
	if !ok {
		t.Fatal("administrative generated dependency unavailable")
	}
	body, err := os.ReadFile(filepath.Join(filepath.Dir(source), filepath.FromSlash(ref)))
	var generated struct {
		Basis struct{ Descriptor []byte } `json:"public_basis"`
	}
	if err != nil || len(body) > 8<<20 || json.Unmarshal(body, &generated) != nil {
		t.Fatal("administrative descriptor unavailable")
	}
	descriptor, err := contract.DecodeGenesisDescriptorCore(generated.Basis.Descriptor)
	if err != nil {
		t.Fatal("administrative descriptor refused")
	}
	return PublicBasis{Descriptor: generated.Basis.Descriptor}, descriptor
}

func publicOperatorBindings(d contract.GenesisDescriptorCore) ([]contract.BindingTableRow, contract.ID) {
	bindings := make([]contract.BindingTableRow, 0, len(d.Recipients)+1)
	var recovery contract.ID
	for _, recipient := range d.Recipients {
		if recipient.Status == contract.CurrentRecipient && recipient.CurrentBinding != nil {
			bindings = append(bindings, contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: recipient.RecipientID, Binding: *recipient.CurrentBinding})
		}
	}
	if d.Recovery != nil {
		recovery = d.Recovery.RoleID
		bindings = append(bindings, contract.BindingTableRow{SubjectKind: contract.RecoveryWrapSubject, SubjectID: recovery, Binding: d.Recovery.KMS})
	}
	return bindings, recovery
}

func publicOperatorCustody(t testing.TB, client publicOperatorClient, d contract.GenesisDescriptorCore, privateRecipient contract.ID) *custody.Fixture {
	t.Helper()
	bindings, recovery := publicOperatorBindings(d)
	routes := make([]custody.Route, len(bindings))
	for i, row := range bindings {
		routes[i] = custody.Route{BindingID: row.Binding.BindingID, PublicRoute: client.Route}
		if row.SubjectKind == contract.OrdinaryWrapSubject && row.SubjectID == privateRecipient {
			routes[i].PrivateRoute = client.Route
		}
	}
	return custody.NewLive(t, client.Crypto, d.AuthorityRecipientID, recovery, bindings, routes)
}

func publicOperatorOpen(t testing.TB, ctx context.Context, domain contract.ID, basis PublicBasis, store contract.Store) *StateSession {
	t.Helper()
	admission, result := admitPublicNormal(ctx, domain, store.Descriptor(), basis, store, contract.Hash([]byte("enkv/composition/full/v1")), nil)
	if result.Outcome != ObservedCurrent {
		t.Fatal("administrative actual public basis refused", result)
	}
	selected, result := Open(ctx, admission, store)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("administrative complete selected state refused", result)
	}
	return selected
}

func publicOperatorSelectedWork(t testing.TB, env fixtureEnvironment, initial *StateSession, consumer contract.ID) *StateSession {
	t.Helper()
	members := []contract.ID{initial.admission.recipient, consumer}
	slices.SortFunc(members, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	profile := defaultGeneratedFixtureProfile()
	first := generatedPlanInputForGenerationsMembershipIntent(t, initial, generatedVectorID(230), []string{"generated"}, members, []byte(`{"name":"generated"}`), profile)
	selected := selectPrivateGeneratedOperationInProcess(t, env, initial, first, "administrative initial value")
	old := selected.valueEntry(0)
	if old == nil || old.Generated.ResourceDigest.IsZero() {
		t.Fatal("controlled initial generation unavailable")
	}
	operation := generatedVectorID(231)
	input := generatedStatePlanInput(t, selected, operation, []string{old.Name}, profile, old.Generated.Epoch+1,
		map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: *old})
	reservation := generatedReservationInputForMembershipStateIntent(t, selected, operation, members, []string{old.Name}, []byte(`{"name":"generated"}`), profile, old.Generated.Epoch+1,
		map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: *old})
	input.graph, input.declaration, input.registry, input.recoveryPolicy, input.requestBindings = reservation.graph, reservation.declaration,
		reservation.graph.Request.Registry, reservation.graph.Request.RecoveryPolicyID, slices.Clone(reservation.requestBindings)
	selected = selectPrivateGeneratedOperationInProcess(t, env, selected, input, "administrative controlled rotation")
	current := selected.valueEntry(0)
	if current == nil || current.Generated.ResourceDigest == old.Generated.ResourceDigest || !slices.Equal(current.Recipients, members) || len(selected.adminIndex.Groups) != 1 || selected.root.Generated.Retiring != 1 || selected.root.ChildCount > 32 {
		t.Fatal("controlled rotation did not preserve exact shared current material and one retirement duty")
	}
	return selected
}

func publicOperatorPlainSet(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string) {
	t.Helper()
	original := publicSourceImage(t, source)
	head := publicIndependentHEAD(t, ctx, input, budget, source, inv.StateDir)
	copy := publicPortablePair(t, source, filepath.Join(inv.StateDir, "plain-set-pair"))
	if os.Chmod(copy, 0600) != nil {
		t.Fatal("plain-set editable copy unavailable")
	}
	before := publicSourceImage(t, copy)
	value := []byte{'p', 'l', 'a', 'i', 'n', 0, 255}
	result := publicCLI(t, ctx, inv, input, budget, "reader", false, nativeprocess.Policy{NoKMS: true}, value, "set", "--source", copy, "--source-format", "json", "--name", "local-plain", "--confidential=false", "--json")
	defer clear(result.Body)
	var product struct {
		LocalEdit string `json:"local_edit"`
		Outcome   string `json:"outcome"`
	}
	if result.Code != 0 || json.Unmarshal(result.Body, &product) != nil || product.LocalEdit != "plain" || product.Outcome != "edited" || len(result.Capture.Events) != 1 || result.Capture.Events[0].Kind != "footer" {
		t.Fatal("plain set entered discovery or HTTP or did not return local success")
	}
	document := publicSourceDocument(t, copy)
	entry, _ := document["entries"].(map[string]any)["local-plain"].(map[string]any)
	plain, _ := entry["source"].(map[string]any)
	if entry["confidentiality"] != "plain" || !reflect.DeepEqual(plain, map[string]any{"kind": "supplied", "bytes": base64.StdEncoding.EncodeToString(value)}) {
		t.Fatal("plain set changed exact supplied bytes")
	}
	for path, body := range before.Files {
		if path != copy {
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, body) {
				t.Fatal("plain set changed its generated dependency")
			}
		}
	}
	publicImageUnchanged(t, original)
	if after := publicIndependentHEAD(t, ctx, input, budget, source, inv.StateDir); !reflect.DeepEqual(after, head) {
		t.Fatal("local plain set changed remote HEAD")
	}
}

func publicOperatorSetup(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string) (fixtureEnvironment, *StateSession, contract.ID, []byte) {
	t.Helper()
	basis, descriptor := publicOperatorGenesis(t, source)
	var consumer contract.ID
	for _, recipient := range descriptor.Recipients {
		if recipient.CurrentBinding != nil && recipient.CurrentBinding.KeySelector == input.Settings.ReaderKEKID {
			consumer = recipient.RecipientID
		}
	}
	if consumer.IsZero() || consumer == descriptor.AuthorityRecipientID {
		t.Fatal("administrative independent recipient was not initialized")
	}
	client, err := openPublicOperatorClient(t, ctx, input, "authority", inv.StateDir, descriptor.DomainID, &descriptor.NormalSigning)
	if err != nil {
		t.Fatal("administrative SDK fixture unavailable")
	}
	location := client.Store.Descriptor()
	if location.Identity != descriptor.StoreID || location.Coordinate != descriptor.CoordinateID || location.NonBody != descriptor.NonBodyID {
		t.Fatal("SDK fixture differs from initialized Store")
	}
	inventory := &objectInventory{path: filepath.Join(inv.StateDir, "public-controlled-inventory.json"), image: inventoryImage{Version: 1, RunID: input.RunID, Prefix: input.Prefix, Binding: settingsBinding(input.Settings), Domain: descriptor.DomainID, Deleted: map[string]int{}}}
	if inventory.save() != nil {
		t.Fatal("controlled administrative ownership unavailable")
	}
	var ledger publicOwnership
	if records.ReadJSON(publicLedgerPath(inv), &ledger) != nil || ledger.ControlledInventory != "" {
		t.Fatal("controlled administrative ledger unavailable")
	}
	ledger.ControlledInventory = inventory.path
	if records.WriteJSON(publicLedgerPath(inv), ledger, 0600) != nil {
		t.Fatal("controlled inventory could not be linked before mutation")
	}
	// The two controlled generations use at most three public KEK bindings and bounded private checks.
	if !budget.reserve(64, 64*operationBodyAllowance, "", 0) {
		t.Fatal("controlled administrative key-call allowance unavailable")
	}
	keys := publicOperatorCustody(t, client, descriptor, descriptor.AuthorityRecipientID)
	env := fixtureEnvironment{Context: ctx, Domain: descriptor.DomainID, Composition: contract.Hash([]byte("enkv/composition/full/v1")),
		Store: recordedStore{Store: client.Store, inventory: inventory, budget: budget}, Trust: budgetTrust{Trust: client.Trust, budget: budget},
		PublicKey: descriptor.NormalSigning.SPKI, SigningSelector: descriptor.NormalSigning.KeySelector, Bindings: keys.Bindings(), Crypto: keys.Crypto(), Custody: keys, ReserveCustody: budget.reserveCustody}
	initial := publicOperatorOpen(t, ctx, descriptor.DomainID, basis, env.Store)
	selected := publicOperatorSelectedWork(t, env, initial, consumer)
	return env, selected, consumer, basis.Descriptor
}

func publicOperatorFresh(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, facts publicOperatorFacts) {
	t.Helper()
	descriptor, err := contract.DecodeGenesisDescriptorCore(facts.Genesis)
	if err != nil || descriptor.DomainID.IsZero() || descriptor.DomainID != facts.Expected.Root.Domain || facts.Consumer.IsZero() {
		t.Fatal("fresh administrative facts refused")
	}
	client, err := openPublicOperatorClient(t, ctx, input, "recipient-consumer", inv.StateDir, descriptor.DomainID, nil)
	if err != nil || client.Store.Descriptor() != facts.Descriptor {
		t.Fatal("fresh administrative SDK recipient unavailable")
	}
	store := liveReadOnlyStore{Store: recordedStore{Store: client.Store, budget: budget}, t: t}
	selected := publicOperatorOpen(t, ctx, descriptor.DomainID, facts.Basis, store)
	assertStateImage(t, selected, facts.Expected)
	entry := selected.valueEntry(0)
	if entry == nil || entry.Name != "generated" || !slices.Contains(entry.Recipients, facts.Consumer) || !budget.reserveCustody("consume", 1) {
		t.Fatal("fresh administrative current generated selection unavailable")
	}
	keys := publicOperatorCustody(t, client, descriptor, facts.Consumer)
	check := keys.Consume(ctx, sessionConsumerSelection(t, selected, facts.Consumer, entry.Name), custody.StandardValue)
	if check.Code != contract.CryptoSuccess || check.Delivery != 1 || check.SinkCalls != 1 || !check.ValueMatched || len(check.KeyUses) != 1 || check.KeyUses[0].SubjectID != facts.Consumer || check.KeyUses[0].Purpose != contract.KeyUseMaterialOpen || check.KeyUses[0].Outcome != contract.KeyUseCompleted {
		t.Fatal("fresh independent recipient did not preserve exact current bytes")
	}
}

// full_only: false
func TestPublicOperatorUsesInitializedIDsAndSharedCurrentValue(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[recovery], func(t *testing.T) {
			env, _ := genesisEnvironment(t, liveFamily, recovery)
			admission := fixtureAdmission(env)
			descriptor, err := contract.DecodeGenesisDescriptorCore(admission.admission.descriptor)
			if err != nil {
				t.Fatal(err)
			}
			authority, consumer := testID("allocated administrative authority"), testID("allocated independent administrative recipient")
			if recovery {
				authority, consumer = consumer, authority
			}
			if (bytes.Compare(authority[:], consumer[:]) > 0) != recovery {
				t.Fatal("allocated-ID regression did not cover both role orderings")
			}
			if authority == fixtureID(env.Domain, "recipient") || consumer == fixtureID(env.Domain, "reader") {
				t.Fatal("allocated-ID regression did not change fixture assumptions")
			}
			keys := custody.New(t, liveFamily, testID("administrative actual custody"), recovery, []contract.ID{authority, consumer})
			descriptor.AuthorityRecipientID = authority
			descriptor.Recipients = nil
			for _, row := range keys.Bindings() {
				binding := row.Binding
				if row.SubjectKind == contract.OrdinaryWrapSubject {
					descriptor.Recipients = append(descriptor.Recipients, contract.RecipientRecord{RecipientID: row.SubjectID, Status: contract.CurrentRecipient, CurrentBinding: &binding})
				} else {
					descriptor.Recovery.RoleID, descriptor.Recovery.KMS = row.SubjectID, binding
				}
			}
			slices.SortFunc(descriptor.Recipients, func(a, b contract.RecipientRecord) int { return bytes.Compare(a.RecipientID[:], b.RecipientID[:]) })
			encoded, err := contract.EncodeGenesisDescriptorCore(descriptor)
			if err != nil {
				t.Fatal(err)
			}
			admission.admission.descriptor, admission.admission.recipient = encoded, authority
			admission.admission.composition = contract.Hash([]byte("enkv/composition/full/v1"))
			env.Composition, env.Bindings, env.Crypto, env.Custody, env.AdmitInit, env.RetireInit = admission.admission.composition, keys.Bindings(), keys.Crypto(), keys, keys.AdmitInit, keys.RetireInit
			init, _ := fixtureInitAdmission(t, env, admission)
			signer, ok := env.Trust.(contract.QualifyingTrust)
			if !ok {
				t.Fatal("initialization signer unavailable")
			}
			selected, result := Initialize(t.Context(), init, env.Store, signer, env.Recovery, env.Crypto)
			if selected == nil || result.Outcome != ObservedCurrent {
				t.Fatal("allocated-ID initialization refused", result)
			}
			keys.RetireInit()
			directory := t.TempDir()
			source := filepath.Join(directory, "configuration.json")
			if os.Mkdir(filepath.Join(directory, ".enkv"), 0700) != nil {
				t.Fatal("generated fixture directory unavailable")
			}
			publicWriteSource(t, source, map[string]any{"generated": ".enkv/initialized.json"})
			body, err := json.Marshal(map[string]any{"domain": map[string]any{"id": operatorIDText(descriptor.DomainID)}, "public_basis": map[string]any{"descriptor": encoded}})
			if err != nil || os.WriteFile(filepath.Join(directory, ".enkv", "initialized.json"), body, 0600) != nil {
				t.Fatal("initialized descriptor delivery unavailable")
			}
			basis, decoded := publicOperatorGenesis(t, source)
			bindings, recoveryID := publicOperatorBindings(decoded)
			if !bytes.Equal(basis.Descriptor, encoded) || !reflect.DeepEqual(bindings, keys.Bindings()) || recovery != !recoveryID.IsZero() {
				t.Fatal("administrative adapter replaced initialized recipient or Recovery bindings")
			}
			// Each dispatcher command is charged once as a bounded child. The
			// controlled setup and ordinary continuation use the live wrappers.
			limits := liveLimits{Requests: 8192, BodyBytes: 8192 * operationBodyAllowance, Objects: 256, ObjectBytes: 512 << 20, CleanupRequests: 6144, CleanupBytes: 13 << 30}
			budget := &runBudget{limits: limits, keys: map[string]bool{}}
			if !budget.absorbChild(budgetReservation{Requests: 2 * 128, BodyBytes: 2 * (16 << 20), Objects: 16, ObjectBytes: 8 << 20}) ||
				!budget.reserve(16, 16*operationBodyAllowance, "", 0) || // resource preflight
				!budget.reserve(2, operationBodyAllowance, "", 0) || // empty prefix LIST
				!budget.reserve(24, 12*operationBodyAllowance, "", 0) || // independent HEAD checks
				!budget.reserve(64, 64*operationBodyAllowance, "", 0) { // controlled KEK routes
				t.Fatal("administrative fixed reservations exceeded the case budget")
			}
			baseStore, baseTrust := env.Store, env.Trust
			inventory := &objectInventory{path: filepath.Join(directory, "controlled-inventory.json"), image: inventoryImage{Version: 1,
				RunID: liveProtocolRun, Prefix: baseStore.Descriptor().Prefix, Domain: decoded.DomainID, Deleted: map[string]int{}}}
			if inventory.save() != nil {
				t.Fatal("administrative budget inventory unavailable")
			}
			env.Store = recordedStore{Store: baseStore, inventory: inventory, budget: budget}
			env.Trust = budgetTrust{Trust: baseTrust, budget: budget}
			env.ReserveCustody = budget.reserveCustody
			opened := publicOperatorOpen(t, t.Context(), decoded.DomainID, basis, env.Store)
			if opened.admission.recipient != authority || opened.head.Core != selected.head.Core {
				t.Fatal("administrative adapter derived a synthetic authority or another selection")
			}
			current := publicOperatorSelectedWork(t, env, opened, consumer)
			publicOperatorFreeze(t, t.Context(), current)
			shape := *current
			shape.root.ChildCount, shape.root.ChildEncodedBytes = 32, 32<<20
			commands := []string{"list", "plan", "stale-apply", "plan", "apply", "list", "receipt"}
			if recovery {
				commands = append([]string{"keys-replace"}, commands...)
				if !budget.reserve(8, 8*operationBodyAllowance, "", 0) {
					t.Fatal("successor lookup reservation exceeded the case budget")
				}
				// The independent post-replacement reader performs the same full
				// read and frozen-support scan; signer semantics have separate proof.
				current = publicOperatorOpen(t, t.Context(), decoded.DomainID, basis, env.Store)
				publicOperatorFreeze(t, t.Context(), current)
			}
			for _, command := range commands {
				count, size := uint16(0), uint64(0)
				if command == "apply" || command == "keys-replace" {
					count, size = 32, 32<<20
				}
				reservation, ok := operatorCLIReservation(&shape, command, count, size)
				if !ok || !budget.absorbChild(reservation) {
					t.Fatal("complete administrative command reservations exceeded the case budget", command, budget.snapshot())
				}
			}
			current = operatorAdvanceCurrent(newScenarioRun(t, t.Context(), env), current, env.Trust, "ordinary-between-plan-and-apply")
			before := publicOperatorFreeze(t, t.Context(), current)
			group := current.adminIndex.Groups[0]
			operatorEndFixture(t, t.Context(), current, baseStore, baseTrust)
			after := operatorAuthenticatedRead(t, t.Context(), current, env.Store)
			publicOperatorCheckEnd(t, t.Context(), before, after, group)
			freshCalls := 0
			env.FreshCurrent = func(tb testing.TB, admission OpenContext, selected *StateSession) {
				freshCalls++
				cold, result := Open(t.Context(), admission, env.Store)
				if cold == nil || result.Outcome != ObservedCurrent {
					tb.Fatal("budgeted complete fresh reader", result)
				}
				assertStateImage(tb, cold, observeSelectedState(tb, selected))
				if !budget.reserveCustody("consume", 1) {
					tb.Fatal("independent consumption reservation exceeded the case budget")
				}
				check := keys.Consume(t.Context(), sessionConsumerSelection(tb, cold, consumer, "generated"), custody.StandardValue)
				if check.Code != contract.CryptoSuccess || check.Delivery != 1 || check.SinkCalls != 1 || !check.ValueMatched {
					tb.Fatal("controlled administrative value lost independent Recipient access")
				}
			}
			operatorReopenCurrent(newScenarioRun(t, t.Context(), env), after, env.Trust, false)
			used := budget.snapshot()
			// Each owned object can need three adoption reads, three pre-delete
			// reads, one conditional delete, and three absence reads. Include
			// the two scans' full 256-page bounds in the separate cleanup budget.
			if 20*used.Objects+1024 > limits.CleanupRequests || (50*used.Objects+512)*(1<<20) > limits.CleanupBytes {
				t.Fatal("complete administrative ownership exceeds cleanup retry allowance", used.Objects)
			}
			old := &runBudget{limits: liveLimits{Requests: limits.Requests, BodyBytes: 1 << 30, Objects: limits.Objects, ObjectBytes: limits.ObjectBytes}, keys: map[string]bool{}}
			if freshCalls != 1 || budget.exhausted || old.absorbChild(used) || !old.exhausted {
				t.Fatal("complete administrative budget did not preserve its finite bound or old-limit refusal", used)
			}
			t.Logf("administrative whole-case reservation requests=%d body_bytes=%d objects=%d object_bytes=%d", used.Requests, used.BodyBytes, used.Objects, used.ObjectBytes)
		})
	}
}

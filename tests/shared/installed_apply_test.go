package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

// full_only: false
func TestInstalledSuppliedApplyPreservesInitializationReceiptSupport(t *testing.T) {
	env, keys := genesisEnvironment(t, contract.AWS, false)
	installation, _ := publicInitializationInstallation(t, env, keys)
	initializer, err := NewInstalledInitializer(initializationAllocationForDescriptor(t, installation.Descriptor), installation)
	if err != nil {
		t.Fatal(err)
	}
	defer initializer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ready := initializer.Initialize(ctx)
	if ready.StateResult != contract.InitializationSuccess || ready.PublicBasis == nil {
		t.Fatal("initialization failed", ready.Result)
	}
	control, err := ready.PublicBasis.ControlCore(env.Domain, env.Store.Descriptor())
	if err != nil {
		t.Fatal(err)
	}
	admitted, result := admitPublicNormal(ctx, env.Domain, env.Store.Descriptor(), *ready.PublicBasis, env.Store, installation.CompositionID, nil)
	if result.Outcome != ObservedCurrent {
		t.Fatal("production normal admission failed", result)
	}
	selected, result := Open(ctx, admitted, env.Store)
	if selected == nil {
		t.Fatal("production selected read failed", result)
	}
	before, err := selected.receiptWindows(ctx)
	if err != nil || len(before.Successes) != 1 {
		t.Fatal("initial receipt support missing", err)
	}
	input := []ApplyEntryInput{{Name: "alpha", Recipients: []contract.ID{control.AuthorityRecipientID}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("plain")}}
	validator := NewPublicConfigurationValidator(nil)
	configuration := installedApplyTestConfiguration(t, ctx, selected, input, currentApplyRecipients(selected.registry()), validator)
	var privateCalls int
	apply, err := NewInstalledApply(ApplyInstallation{ExpectedDomain: env.Domain, ExpectedStore: env.Store.Descriptor(), PublicBasis: *ready.PublicBasis,
		ExpectedControl: control, DesiredRecipients: currentApplyRecipients(selected.registry()), PublicConfiguration: configuration, ConfigurationValidator: validator, Store: env.Store, Trust: env.Trust, CompositionID: installation.CompositionID, FileIdentity: fixtureID(env.Domain, "apply-file"),
		AdmitCustody: func(context.Context, contract.CryptoCompareRequest, contract.ControlCore, []contract.RecipientRecord, []contract.MembershipRow, contract.DescriptorVector, *contract.GeneratedSupportTransition, contract.ID, contract.MutationReceiptWindows, uint8, time.Time) (*InstalledApplyCustody, error) {
			privateCalls++
			return nil, contract.ErrRecord
		}, CloseInstalled: func() {}})
	if err != nil {
		t.Fatal(err)
	}
	defer apply.Close()
	got := apply.Apply(ctx, fixtureID(env.Domain, "apply-request"), input)
	if got.Result.Outcome != ObservedCurrent {
		t.Fatal("first supplied apply refused authenticated receipt support", got.Result)
	}
	if privateCalls != 0 {
		t.Fatal("plain supplied apply reached private custody")
	}
	fresh, result := Open(ctx, admitted, env.Store)
	if fresh == nil {
		t.Fatal("fresh applied selection failed", result)
	}
	after, err := fresh.receiptWindows(ctx)
	if err != nil || len(after.Successes) != 2 || after.Successes[0] != before.Successes[0] {
		t.Fatal("apply did not preserve initialization receipt and append one success", err)
	}
	if got.RequestIdentity.IsZero() || len(got.Receipt) == 0 {
		t.Fatal("public supplied apply omitted frozen receipt identity")
	}
}

type installedApplyTestFixture struct {
	env         fixtureEnvironment
	keys        *custody.Fixture
	basis       PublicBasis
	composition contract.ID
	admitted    OpenContext
	selected    *StateSession
}

func newInstalledApplyTestFixture(t testing.TB, ctx context.Context, family contract.Family, recovery bool) installedApplyTestFixture {
	t.Helper()
	env, keys := genesisEnvironment(t, family, recovery)
	i, _ := publicInitializationInstallation(t, env, keys)
	initializer, err := NewInstalledInitializer(initializationAllocationForDescriptor(t, i.Descriptor), i)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(initializer.Close)
	ready := initializer.Initialize(ctx)
	if ready.StateResult != contract.InitializationSuccess || ready.PublicBasis == nil {
		t.Fatal("installed fixture initialization", ready.Result)
	}
	admitted, result := admitPublicNormal(ctx, env.Domain, env.Store.Descriptor(), *ready.PublicBasis, env.Store, i.CompositionID, nil)
	if result.Outcome != ObservedCurrent {
		t.Fatal("installed fixture normal admission", result)
	}
	selected, result := Open(ctx, admitted, env.Store)
	if selected == nil {
		t.Fatal("installed fixture selected read", result)
	}
	return installedApplyTestFixture{env: env, keys: keys, basis: *ready.PublicBasis, composition: i.CompositionID, admitted: admitted, selected: selected}
}

type installedApplyObservedCrypto struct {
	contract.Crypto
	observe func(contract.CryptoKind)
}

func (c installedApplyObservedCrypto) Exchange(ctx context.Context, q contract.CryptoRequest) contract.CryptoResponse {
	if c.observe != nil {
		c.observe(q.Kind)
	}
	return c.Crypto.Exchange(ctx, q)
}

func (f installedApplyTestFixture) engine(t testing.TB, selected *StateSession, input []ApplyEntryInput, observe func(contract.CryptoKind)) *InstalledApply {
	return f.engineWithRecipients(t, selected, input, currentApplyRecipients(selected.registry()), observe)
}

func (f installedApplyTestFixture) engineWithRecipients(t testing.TB, selected *StateSession, input []ApplyEntryInput, desired []contract.ApplyRecipientInput, observe func(contract.CryptoKind)) *InstalledApply {
	t.Helper()
	validator := NewPublicConfigurationValidator(nil)
	return f.engineWithValidator(t, selected, input, desired, validator, observe)
}

func (f installedApplyTestFixture) engineWithValidator(t testing.TB, selected *StateSession, input []ApplyEntryInput, desired []contract.ApplyRecipientInput, validator *PublicConfigurationValidator, observe func(contract.CryptoKind), generated ...*GeneratedApplyInstallation) *InstalledApply {
	t.Helper()
	configuration := installedApplyTestConfiguration(t, t.Context(), selected, input, desired, validator)
	for at := range input {
		if input[at].ValueSource != contract.Generated || input[at].Generated != nil {
			continue
		}
		public := slices.IndexFunc(configuration.Entries.Value, func(row contract.PublicEntry) bool { return row.Name == input[at].Name })
		if public < 0 || configuration.Entries.Value[public].Generated == nil {
			t.Fatal("installed fixture generated declaration absent")
		}
		g := configuration.Entries.Value[public].Generated
		input[at].Generated = &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: g.LifecycleMode.Value, Epoch: g.Epoch.Value, RetirementMode: g.Retirement.Value, ConfigContractID: g.ConfigContractID.Value, ResourceContractID: g.ResourceContractID.Value, CompletionClass: g.Completion.Value, Intent: g.ContentIntent.Value}
	}
	var generators *GeneratedApplyInstallation
	if len(generated) != 0 {
		generators = generated[0]
	}
	engine, err := NewInstalledApply(ApplyInstallation{ExpectedDomain: f.env.Domain, ExpectedStore: f.env.Store.Descriptor(), PublicBasis: f.basis, ExpectedControl: currentControlOf(selected), DesiredRecipients: desired, Generated: generators, PublicConfiguration: configuration, ConfigurationValidator: validator, Store: f.env.Store, Trust: f.env.Trust, CompositionID: f.composition, FileIdentity: fixtureID(f.env.Domain, "source-file"), CloseInstalled: func() {},
		AdmitCustody: func(ctx context.Context, q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, plain []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, revision contract.ID, before contract.MutationReceiptWindows, warningBits uint8, deadline time.Time) (*InstalledApplyCustody, error) {
			owner, err := f.keys.NewApplyCustody(q, control, current, fixtureID(f.env.Domain, "source-file"), plain, support, witness, revision, before, warningBits, deadline)
			if err != nil {
				return nil, err
			}
			return &InstalledApplyCustody{Crypto: installedApplyObservedCrypto{Crypto: owner, observe: observe}, BindReceipt: owner.BindReceipt, Close: owner.Close}, nil
		}})
	if err != nil {
		t.Fatal("installed fixture apply construction", err)
	}
	t.Cleanup(engine.Close)
	return engine
}

func (f installedApplyTestFixture) open(t testing.TB, ctx context.Context) *StateSession {
	t.Helper()
	selected, result := Open(ctx, f.admitted, f.env.Store)
	if selected == nil {
		t.Fatal("installed fixture cold reopen", result)
	}
	return selected
}

// full_only: false
func TestInstalledSuppliedSecretApplyUsesAuthorityAndPreservesRecovery(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/recovery=%t", family, recovery), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				f := newInstalledApplyTestFixture(t, ctx, family, recovery)
				authority, reader := f.selected.admission.recipient, fixtureID(f.env.Domain, "reader")
				var recoverySigner *testtrust.Signer
				var recoveryCalls int
				if recovery {
					f.keys.SetDenied(f.keys.RecoveryID(), true)
					recoverySigner = f.env.Recovery.(*testtrust.Signer)
					recoveryCalls = recoverySigner.Calls()
					recoverySigner.SetUnavailable(true)
				}
				plain := ApplyEntryInput{Name: "beta", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{authority}, InputBytes: []byte("whole desired set"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
				input := []ApplyEntryInput{suppliedSecret(t, f.env, "alpha", "installed first source", custody.StandardValue, authority), plain}
				var stages []contract.CryptoKind
				run := func(label string, selected *StateSession, input []ApplyEntryInput) PublicApplyResult {
					t.Helper()
					stages = nil
					engine := f.engine(t, selected, input, func(kind contract.CryptoKind) { stages = append(stages, kind) })
					result := engine.Apply(ctx, fixtureID(f.env.Domain, label), input)
					engine.Close()
					return result
				}
				assertSelected := func(result PublicApplyResult, count uint32) {
					t.Helper()
					if result.Result.Outcome != ObservedCurrent || result.Payload == nil || result.Payload.ChangedSubjects.Count != count || result.RequestIdentity.IsZero() {
						t.Fatal("installed supplied mutation result", result.Result, count)
					}
					receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
					if err != nil || receipt.RequestIdentityDigest != result.RequestIdentity || receipt.ChangedSubjects.Count != count || receipt.ChangedSubjects.Digest != result.Payload.ChangedSubjects.IdentityRootDigest || receipt.EffectSummary != contract.ReceiptEffectNoChange {
						t.Fatal("installed mutation receipt differs", err)
					}
				}
				assertSelected(run("installed first request", f.selected, input), 4)
				selected := f.open(t, ctx)
				first := sessionConsumerSelection(t, selected, authority, "alpha")
				check := f.keys.Consume(ctx, first, custody.StandardValue)
				if check.Code != contract.CryptoSuccess || !check.ValueMatched {
					t.Fatal("first exact private value", check)
				}
				input[0] = suppliedSecret(t, f.env, "alpha", "installed changed source", custody.AlternateStandardValue, authority)
				_, privateBefore := f.keys.Calls()
				assertSelected(run("installed changed request", selected, input), 1)
				_, privateAfter := f.keys.Calls()
				if privateAfter-privateBefore != 3 {
					t.Fatal("changed supplied apply private capabilities differ", privateAfter-privateBefore)
				}
				selected = f.open(t, ctx)
				changed := sessionConsumerSelection(t, selected, authority, "alpha")
				if bytes.Equal(first.Entry.ValueBytes, changed.Entry.ValueBytes) || first.Entry.ValueState == changed.Entry.ValueState {
					t.Fatal("actual supplied replacement did not change secret state")
				}
				check = f.keys.Consume(ctx, changed, custody.AlternateStandardValue)
				if check.Code != contract.CryptoSuccess || !check.ValueMatched {
					t.Fatal("changed exact private value", check)
				}
				verifyRecovery := func(selection contract.ConsumerSelection) {
					t.Helper()
					if recovery {
						other := selection
						other.Binding = contract.BindingTableRow{SubjectKind: contract.RecoveryWrapSubject, SubjectID: currentControlOf(selected).Recovery.RoleID, Binding: currentControlOf(selected).Recovery.KMS}
						if !f.keys.MaterialPreserved(selection, other) {
							t.Fatal("independent Recovery packet did not preserve the exact checked value material")
						}
					}
				}
				verifyRecovery(changed)
				pin := &contract.RetainedSecretInput{Incarnation: changed.Entry.Incarnation, Material: changed.Entry.ValueState}
				retained := ApplyEntryInput{Name: "alpha", ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{authority}, Retained: pin, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
				store := f.env.Store.(*memoryStore)
				creates, cas, signs := store.creates, store.cas, f.env.Trust.(*fixtureTrust).signs
				windows, err := selected.receiptWindows(ctx)
				if err != nil {
					t.Fatal(err)
				}
				noop := run("installed no-op request", selected, []ApplyEntryInput{retained, plain})
				if noop.Result.Outcome != Unchanged || noop.Payload != nil || noop.OperationID.IsZero() || noop.RequestIdentity.IsZero() || len(noop.Receipt) != 0 || store.creates != creates || store.cas != cas || f.env.Trust.(*fixtureTrust).signs != signs || !slices.Equal(stages, []contract.CryptoKind{contract.CryptoCompare, contract.CryptoDiscard}) {
					t.Fatal("retained no-op allocated mutation or skipped private comparison", noop.Result, stages)
				}
				afterNoop := f.open(t, ctx)
				gotWindows, err := afterNoop.receiptWindows(ctx)
				if err != nil || !slices.Equal(gotWindows.Successes, windows.Successes) || !slices.Equal(gotWindows.Failures, windows.Failures) || !slices.Equal(gotWindows.Order, windows.Order) {
					t.Fatal("no-op changed terminal windows", err)
				}
				retained.Recipients = []contract.ID{authority, reader}
				slices.SortFunc(retained.Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
				grant := run("installed retained grant", selected, []ApplyEntryInput{retained, plain})
				assertSelected(grant, 2)
				selected = f.open(t, ctx)
				granted := sessionConsumerSelection(t, selected, reader, "alpha")
				if granted.Entry.ValueState != changed.Entry.ValueState || !bytes.Equal(granted.Entry.ValueBytes, changed.Entry.ValueBytes) || !f.keys.MaterialPreserved(changed, granted) {
					t.Fatal("retained grant changed or lost current material")
				}
				check = f.keys.Consume(ctx, granted, custody.AlternateStandardValue)
				if check.Code != contract.CryptoSuccess || !check.ValueMatched {
					t.Fatal("new grant exact private value", check)
				}
				verifyRecovery(sessionConsumerSelection(t, selected, authority, "alpha"))
				retained.Recipients = []contract.ID{authority}
				assertSelected(run("installed retained exclusion", selected, []ApplyEntryInput{retained}), 4)
				selected = f.open(t, ctx)
				excluded := sessionConsumerSelection(t, selected, authority, "alpha")
				if excluded.Entry.ValueState == granted.Entry.ValueState || bytes.Equal(excluded.Entry.ValueBytes, granted.Entry.ValueBytes) || len(selected.root.Names) != 1 || selected.root.Names[0].Name != "alpha" {
					t.Fatal("exclusion did not refresh secret protection and honor the complete desired set")
				}
				for _, wrap := range excluded.Access.Wraps {
					if wrap.SubjectKind == contract.OrdinaryWrapSubject && wrap.SubjectID == reader {
						t.Fatal("excluded recipient retained current access")
					}
				}
				check = f.keys.Consume(ctx, excluded, custody.AlternateStandardValue)
				if check.Code != contract.CryptoSuccess || !check.ValueMatched {
					t.Fatal("exclusion exact private value", check)
				}
				verifyRecovery(excluded)
				if recovery && recoverySigner.Calls() != recoveryCalls {
					t.Fatal("ordinary apply reached private Recovery signing")
				}
				stale := run("installed stale retained request", selected, []ApplyEntryInput{retained})
				if stale.Result.Outcome != AdmissionRefused || len(stages) != 0 {
					t.Fatal("stale retained material reached private admission", stale.Result, stages)
				}
			})
		}
	}
}

// full_only: false
func TestInstalledApplyRefusesUnusedEnrolledRecipientOmissionBeforePrivateOrWrite(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.AWS, false)
	control := currentControlOf(f.selected)
	registry := f.selected.registry()
	unused := fixtureID(f.env.Domain, "reader")
	omitted := slices.DeleteFunc(slices.Clone(registry), func(row contract.RecipientRecord) bool { return row.RecipientID == unused })
	if len(omitted) != len(registry)-1 || len(f.selected.root.Names) != 0 {
		t.Fatal("unused selected enrollment precondition")
	}
	input := []ApplyEntryInput{suppliedSecret(t, f.env, "alpha", "omitted unused registry source", custody.StandardValue, control.AuthorityRecipientID)}
	source := slices.Clone(input[0].InputBytes)
	store := f.env.Store.(*memoryStore)
	creates, cas, signs := store.creates, store.cas, f.env.Trust.(*fixtureTrust).signs
	_, privateBefore := f.keys.Calls()
	var custodyCalls int
	validator := NewPublicConfigurationValidator(nil)
	configuration := installedApplyTestConfiguration(t, ctx, f.selected, input, currentApplyRecipients(omitted), validator)
	engine, err := NewInstalledApply(ApplyInstallation{ExpectedDomain: f.env.Domain, ExpectedStore: f.env.Store.Descriptor(), PublicBasis: f.basis, ExpectedControl: control, DesiredRecipients: currentApplyRecipients(omitted), PublicConfiguration: configuration, ConfigurationValidator: validator,
		Store: f.env.Store, Trust: f.env.Trust, CompositionID: f.composition, FileIdentity: fixtureID(f.env.Domain, "source-file"), CloseInstalled: func() {},
		AdmitCustody: func(context.Context, contract.CryptoCompareRequest, contract.ControlCore, []contract.RecipientRecord, []contract.MembershipRow, contract.DescriptorVector, *contract.GeneratedSupportTransition, contract.ID, contract.MutationReceiptWindows, uint8, time.Time) (*InstalledApplyCustody, error) {
			custodyCalls++
			return nil, contract.ErrRecord
		}})
	if err != nil {
		t.Fatal("omitted source registry should reach authenticated selection check", err)
	}
	defer engine.Close()
	got := engine.Apply(ctx, fixtureID(f.env.Domain, "omitted unused registry request"), input)
	_, privateAfter := f.keys.Calls()
	if got.Result != refused(AdmissionInvalid) || got.Payload != nil || !got.OperationID.IsZero() || !got.RequestIdentity.IsZero() || len(got.Receipt) != 0 || custodyCalls != 0 || privateAfter != privateBefore || store.creates != creates || store.cas != cas || f.env.Trust.(*fixtureTrust).signs != signs || !bytes.Equal(input[0].InputBytes, source) {
		t.Fatal("source omission reached mutation capability or changed source", got.Result, custodyCalls, privateAfter-privateBefore)
	}
}

// full_only: false
func TestInstalledApplyNoopReturnsFreshAuthenticatedObservationIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.AWS, false)
	input := []ApplyEntryInput{{Name: "plain", Recipients: []contract.ID{f.selected.admission.recipient}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("complete unchanged requested set")}}
	first := f.engine(t, f.selected, input, nil)
	changed := first.Apply(ctx, fixtureID(f.env.Domain, "no-work baseline"), input)
	first.Close()
	if changed.Result.Outcome != ObservedCurrent {
		t.Fatal("real selected no-work baseline", changed.Result)
	}
	selected := f.open(t, ctx)
	before, err := selected.receiptWindows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	store := f.env.Store.(*memoryStore)
	creates, cas, signs := store.creates, store.cas, f.env.Trust.(*fixtureTrust).signs
	_, privateBefore := f.keys.Calls()
	source := slices.Clone(input[0].InputBytes)
	requestID := fixtureID(f.env.Domain, "repeated no-work caller request")
	var results []PublicApplyResult
	var stages []contract.CryptoKind
	for range 2 {
		engine := f.engine(t, selected, input, func(kind contract.CryptoKind) { stages = append(stages, kind) })
		result := engine.Apply(ctx, requestID, input)
		engine.Close()
		results = append(results, result)
		if result.Result.Outcome != Unchanged || result.Result.Evidence != AuthenticatedClosure || result.Result.ObservedRevision != selected.head.Core.Revision || result.Payload != nil || len(result.Receipt) != 0 {
			t.Fatal("no-op changed the authenticated result branch", result.Result)
		}
	}
	_, privateAfter := f.keys.Calls()
	after := f.open(t, ctx)
	windows, err := after.receiptWindows(ctx)
	if err != nil || !slices.Equal(before.Successes, windows.Successes) || !slices.Equal(before.Failures, windows.Failures) || !slices.Equal(before.Order, windows.Order) || store.creates != creates || store.cas != cas || f.env.Trust.(*fixtureTrust).signs != signs || privateAfter != privateBefore || len(stages) != 0 || !bytes.Equal(source, input[0].InputBytes) {
		t.Fatal("no-work observation acquired mutation or private effects", err, stages)
	}
	for _, result := range results {
		if result.OperationID.IsZero() || result.RequestIdentity.IsZero() || result.DomainID != f.env.Domain || result.RequestID != requestID {
			t.Fatal("authenticated no-op omitted its fresh observation identity")
		}
	}
	if results[0].OperationID == results[1].OperationID || results[0].RequestIdentity == results[1].RequestIdentity {
		t.Fatal("repeated no-op reused a historical observation identity")
	}
}

// This fixture signs a prior selection with already inherited warnings. It does
// not claim to execute the historical work that caused those warnings.
func seedInstalledApplyDomainWarnings(t *testing.T, f installedApplyTestFixture, selected *StateSession, warnings uint8) *StateSession {
	t.Helper()
	windows, err := selected.receiptWindows(t.Context())
	if err != nil || warnings&^uint8(31) != 0 {
		t.Fatal("signed warning fixture precondition", err)
	}
	prior := *selected
	prior.root.WarningBits = warnings
	history := &environmentFixture{admission: f.admitted, session: &prior}
	seedSignedReceiptWindows(t, f.env, history, mutationReceiptFixtureStorage(t, windows))
	if history.session.root.WarningBits != warnings {
		t.Fatal("inherited warnings did not authenticate")
	}
	return history.session
}

// full_only: false
func TestInstalledApplyReceiptPreservesInheritedDomainWarnings(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.AWS, false)
	authority := f.selected.admission.recipient
	plain := ApplyEntryInput{Name: "plain", Recipients: []contract.ID{authority}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("warning baseline"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
	baseline := f.engine(t, f.selected, []ApplyEntryInput{plain}, nil)
	result := baseline.Apply(ctx, fixtureID(f.env.Domain, "warning baseline apply"), []ApplyEntryInput{plain})
	baseline.Close()
	if result.Result.Outcome != ObservedCurrent {
		t.Fatal("warning baseline did not select", result.Result)
	}
	selected := seedInstalledApplyDomainWarnings(t, f, f.open(t, ctx), 31)
	before, err := selected.receiptWindows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	input := []ApplyEntryInput{suppliedSecret(t, f.env, "alpha", "warning supplied source", custody.StandardValue, authority), plain}
	engine := f.engine(t, selected, input, nil)
	result = engine.Apply(ctx, fixtureID(f.env.Domain, "inherited warning apply"), input)
	engine.Close()
	if result.Result.Outcome != ObservedCurrent || result.WarningBits != 31 {
		t.Fatal("ordinary supplied apply did not preserve selected domain warnings", result.Result, result.WarningBits)
	}
	fresh := f.open(t, ctx)
	after, err := fresh.receiptWindows(ctx)
	if err != nil || fresh.root.WarningBits != 31 || len(after.Successes) != len(before.Successes)+1 || !slices.Equal(after.Successes[:len(before.Successes)], before.Successes) || !slices.Equal(after.Failures, before.Failures) {
		t.Fatal("warning apply changed prior history or selected warnings", err)
	}
	receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
	if err != nil || receipt.WarningBits != 124 {
		t.Fatal("Apply receipt omitted inherited domain summary: expected domain31 shifted past two effect bits", err, receipt.WarningBits)
	}
}

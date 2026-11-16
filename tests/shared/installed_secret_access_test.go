package core

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

type installedSecretAccessTrace struct {
	contract.Crypto
	t          testing.TB
	comparison []contract.CryptoComparisonRow
	identities []contract.IdentityRow
}

func (c *installedSecretAccessTrace) Exchange(ctx context.Context, q contract.CryptoRequest) contract.CryptoResponse {
	if q.Kind == contract.CryptoPrepare {
		request, err := contract.DecodeCryptoPrepareRequest(q.Body)
		if err != nil {
			c.t.Fatal(err)
		}
		plan, err := contract.DecodeIdentityPlan(request.IdentityPlan)
		if err != nil {
			c.t.Fatal(err)
		}
		c.identities = slices.Clone(plan.Rows)
	}
	result := c.Crypto.Exchange(ctx, q)
	if q.Kind == contract.CryptoCompare && result.ResultCode == contract.CryptoSuccess {
		comparison, err := contract.DecodeCryptoCompareResult(result.Body)
		if err != nil {
			c.t.Fatal(err)
		}
		c.comparison = slices.Clone(comparison.Rows)
	}
	return result
}

type installedSecretAccessTestSetup struct {
	AccessMutationInstallation
	AdmitCustody installedAccessCustodyAdmitter
}

func installedSecretAccessTestInstallation(t testing.TB, f installedApplyTestFixture, selected *StateSession, validator *PublicConfigurationValidator, trace **installedSecretAccessTrace, admitted *int) installedSecretAccessTestSetup {
	t.Helper()
	return installedSecretAccessTestSetup{AccessMutationInstallation: AccessMutationInstallation{ExpectedDomain: f.env.Domain, ExpectedStore: f.env.Store.Descriptor(), PublicBasis: f.basis, ExpectedControl: currentControlOf(selected), Store: f.env.Store, Trust: f.env.Trust, CompositionID: f.composition, ConfigurationValidator: validator, Maintenance: installedMaintenanceTestInstallation(t, f, selected, validator), CloseInstalled: func() {}},
		AdmitCustody: func(ctx context.Context, q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, plain []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, revision contract.ID, before contract.MutationReceiptWindows, warningBits uint8, deadline time.Time) (*InstalledApplyCustody, error) {
			if admitted != nil {
				(*admitted)++
			}
			owner, err := f.keys.NewEnvelopeRekeyCustody(q, control, current, plain, support, witness, revision, before, warningBits, deadline)
			if err != nil {
				return nil, err
			}
			observed := &installedSecretAccessTrace{Crypto: owner, t: t}
			if trace != nil {
				*trace = observed
			}
			return &InstalledApplyCustody{Crypto: observed, BindReceipt: owner.BindReceipt, Close: owner.Close}, nil
		}}
}

func installedSecretAccessTestRef(t testing.TB, selected *StateSession, id contract.ID) contract.RecipientBindingReference {
	t.Helper()
	recipient := selected.recipientRecord(id)
	if recipient == nil || recipient.CurrentBinding == nil {
		t.Fatal("selected reader binding absent")
	}
	digest, err := contract.PublicBindingDigest(*recipient.CurrentBinding)
	if err != nil {
		t.Fatal(err)
	}
	return contract.RecipientBindingReference{RecipientID: id, PublicBindingDigest: digest}
}

// full_only: false
func TestInstalledSecretAccessSelectsOnlyExactCurrentTarget(t *testing.T) {
	for _, cell := range []struct {
		family   contract.Family
		recovery bool
	}{{contract.AWS, false}, {contract.GCP, true}} {
		for _, kind := range []uint16{contract.OperationApplyDeclaration, contract.OperationEnvelopeRekey} {
			t.Run(fmt.Sprintf("%d/recovery=%t/kind=%d", cell.family, cell.recovery, kind), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				f := newInstalledApplyTestFixture(t, ctx, cell.family, cell.recovery)
				authority, reader := f.selected.admission.recipient, fixtureID(f.env.Domain, "reader")
				members := []contract.ID{authority, reader}
				slices.SortFunc(members, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
				input := []ApplyEntryInput{sharingSecretNamed(t, f.env, "target", "installed secret access target", members), sharingSecretNamed(t, f.env, "unrelated", "installed unrelated secret", members), {Name: "plain", Recipients: []contract.ID{authority}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("unchanged public content"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}}
				setup := f.engine(t, f.selected, input, nil)
				if result := setup.Apply(ctx, fixtureID(f.env.Domain, "secret access setup"), input); result.Result.Outcome != ObservedCurrent {
					t.Fatal("setup did not select", result.Result)
				}
				setup.Close()
				selected := f.open(t, ctx)
				beforeReceipts, err := selected.receiptWindows(ctx)
				if err != nil {
					t.Fatal("secret access predecessor receipt order", err)
				}
				_, old := lifecycleEntry(t, selected, "target")
				_, unrelated := lifecycleEntry(t, selected, "unrelated")
				oldValue, unrelatedValue := ownScenarioValueEntry(*old), ownScenarioValueEntry(*unrelated)
				_, plain := lifecycleEntry(t, selected, "plain")
				plainValue := ownScenarioValueEntry(*plain)
				unrelatedAccess, present := selected.materialAccess(contract.ValueMaterialKind, unrelated.ValueState)
				if !present {
					t.Fatal("unrelated access absent")
				}
				if cell.recovery {
					f.keys.SetDenied(f.keys.RecoveryID(), true)
					f.env.Recovery.(*testtrust.Signer).SetUnavailable(true)
				}
				validator := installedApplyGeneratedValidator(t, selected)
				var trace *installedSecretAccessTrace
				installation := installedSecretAccessTestInstallation(t, f, selected, validator, &trace, nil)
				store := f.env.Store.(*memoryStore)
				cas := store.cas
				_, private := f.keys.Calls()
				var result PublicApplyResult
				if kind == contract.OperationApplyDeclaration {
					proposal := installedApplyCurrentInput(selected)
					for at := range proposal {
						if proposal[at].Name == "target" {
							proposal[at].Recipients = []contract.ID{authority}
						}
					}
					engine := f.engineWithValidator(t, selected, proposal, currentApplyRecipients(selected.registry()), validator, nil)
					admit := engine.installation.AdmitCustody
					engine.installation.AdmitCustody = func(ctx context.Context, q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, plain []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, revision contract.ID, windows contract.MutationReceiptWindows, warnings uint8, deadline time.Time) (*InstalledApplyCustody, error) {
						owner, err := admit(ctx, q, control, current, plain, support, witness, revision, windows, warnings, deadline)
						if err == nil {
							trace = &installedSecretAccessTrace{Crypto: owner.Crypto, t: t}
							owner.Crypto = trace
						}
						return owner, err
					}
					result = engine.Apply(ctx, fixtureID(f.env.Domain, "installed apply exclusion"), proposal)
					engine.Close()
				} else {
					engine, err := NewInstalledEnvelopeRekey(EnvelopeRekeyInstallation{AccessMutationInstallation: installation.AccessMutationInstallation, AdmitCustody: installation.AdmitCustody, Name: "target"})
					if err != nil {
						t.Fatal(err)
					}
					result = engine.Rekey(ctx, fixtureID(f.env.Domain, "installed rekey"))
					engine.Close()
				}
				_, privateAfter := f.keys.Calls()
				count := uint32(1)
				comparisons, privateCalls := 1, 2
				effect := uint16(contract.ReceiptEffectNotApplicable)
				if kind == contract.OperationApplyDeclaration {
					count++
					comparisons, privateCalls = 2, 3
					effect = contract.ReceiptEffectNoChange
				}
				if result.Result.Outcome != ObservedCurrent || result.Payload == nil || result.Payload.ChangedSubjects.Count != count || store.cas != cas+1 || privateAfter-private != privateCalls {
					t.Fatal("secret mutation did not select with the required comparison/preparation scope", result.Result, store.cas-cas, privateAfter-private)
				}
				assertPositiveApplyPreparation(t, result)
				if trace == nil || len(trace.comparison) != comparisons || trace.comparison[0].Name != "target" || trace.comparison[0].Relation != contract.CryptoEqual || len(trace.identities) != 1 || trace.identities[0].Name != "target" {
					t.Fatal("private target subset or truthful equality differs")
				}
				if comparisons == 2 && (trace.comparison[1].Name != "unrelated" || trace.comparison[1].Relation != contract.CryptoEqual) {
					t.Fatal("apply omitted private authentication of an unrelated retained input")
				}
				fresh := f.open(t, ctx)
				afterReceipts, err := fresh.receiptWindows(ctx)
				if err != nil {
					t.Fatal("secret access selected receipt order", err)
				}
				assertSuccessReceiptOrder(t, beforeReceipts, afterReceipts, result.OperationID)
				_, current := lifecycleEntry(t, fresh, "target")
				_, other := lifecycleEntry(t, fresh, "unrelated")
				_, freshPlain := lifecycleEntry(t, fresh, "plain")
				access, ok := fresh.materialAccess(contract.ValueMaterialKind, unrelated.ValueState)
				if !reflect.DeepEqual(*freshPlain, plainValue) || !reflect.DeepEqual(*other, unrelatedValue) || !ok || !reflect.DeepEqual(access, unrelatedAccess) || !reflect.DeepEqual(fresh.registry(), selected.registry()) || current.Incarnation != oldValue.Incarnation || current.ValueState == oldValue.ValueState || bytes.Equal(current.ValueBytes, oldValue.ValueBytes) {
					t.Fatal("target protection was not refreshed independently of unrelated state")
				}
				wantMembers := members
				if kind == contract.OperationApplyDeclaration {
					wantMembers = []contract.ID{authority}
				}
				if !slices.Equal(current.Recipients, wantMembers) {
					t.Fatal("target membership result differs")
				}
				targetAccess, ok := fresh.materialAccess(contract.ValueMaterialKind, current.ValueState)
				if !ok || len(targetAccess.Wraps) != len(wantMembers)+boolInt(cell.recovery) {
					t.Fatal("fresh target wrap set differs")
				}
				for _, wrap := range targetAccess.Wraps {
					if wrap.SubjectKind == contract.OrdinaryWrapSubject {
						if !slices.Contains(wantMembers, wrap.SubjectID) {
							t.Fatal("fresh target retained removed reader")
						}
						ref := installedSecretAccessTestRef(t, fresh, wrap.SubjectID)
						if wrap.PublicBindingDigest != ref.PublicBindingDigest {
							t.Fatal("fresh wrap differs from selected recipient binding")
						}
					} else if !cell.recovery || wrap.SubjectID != fresh.root.CurrentAccess.Core.Recovery.RoleID {
						t.Fatal("fresh target implicit Recovery wrap differs")
					}
				}
				if check := f.keys.Consume(ctx, sessionConsumerSelection(t, fresh, authority, "target"), custody.StandardValue); check.Code != contract.CryptoSuccess || !check.ValueMatched || check.Delivery != 1 {
					t.Fatal("fresh protected target changed plaintext", check)
				}
				receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
				if err != nil || receipt.OperationKind != kind || receipt.StateResult != contract.ReceiptStateSuccess || receipt.EffectSummary != effect || receipt.ChangedSubjects.Count != count || receipt.ChangedSubjects.Digest != result.Payload.ChangedSubjects.IdentityRootDigest {
					t.Fatal("standalone receipt differs from actual selection", err)
				}
				// A fresh installation resolves the new selected image again.
				repeatInstallation := installedSecretAccessTestInstallation(t, f, fresh, validator, nil, nil)
				cas = store.cas
				_, private = f.keys.Calls()
				if kind == contract.OperationApplyDeclaration {
					proposal := installedApplyCurrentInput(fresh)
					engine := f.engineWithValidator(t, fresh, proposal, currentApplyRecipients(fresh.registry()), validator, nil)
					repeated := engine.Apply(ctx, fixtureID(f.env.Domain, "repeat installed apply exclusion"), proposal)
					engine.Close()
					_, after := f.keys.Calls()
					if repeated.Result.Outcome != Unchanged || store.cas != cas || after-private != 2 || len(repeated.Receipt) != 0 {
						t.Fatal("repeat apply did not authenticate its exact retained inputs without selecting", repeated.Result)
					}
				} else {
					engine, err := NewInstalledEnvelopeRekey(EnvelopeRekeyInstallation{AccessMutationInstallation: repeatInstallation.AccessMutationInstallation, AdmitCustody: repeatInstallation.AdmitCustody, Name: "target"})
					if err != nil {
						t.Fatal(err)
					}
					repeated := engine.Rekey(ctx, fixtureID(f.env.Domain, "repeat installed rekey"))
					engine.Close()
					if repeated.Result.Outcome != ObservedCurrent || store.cas != cas+1 {
						t.Fatal("fresh rekey became an equality no-op", repeated.Result)
					}
					_, second := lifecycleEntry(t, f.open(t, ctx), "target")
					if second.ValueState == current.ValueState || second.Incarnation != current.Incarnation || !slices.Equal(second.Recipients, current.Recipients) {
						t.Fatal("repeat rekey did not refresh only protected material")
					}
				}
			})
		}
	}
}

// full_only: false
func TestInstalledSecretAccessRefusesWrongTargetAndBindingBeforeCustody(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.AWS, false)
	authority, reader := f.selected.admission.recipient, fixtureID(f.env.Domain, "reader")
	members := []contract.ID{authority, reader}
	slices.SortFunc(members, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	input := []ApplyEntryInput{sharingSecretNamed(t, f.env, "secret", "refusal target source", members), {Name: "plain", Recipients: []contract.ID{authority}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("plain")}}
	setup := f.engine(t, f.selected, input, nil)
	if result := setup.Apply(ctx, fixtureID(f.env.Domain, "refusal setup"), input); result.Result.Outcome != ObservedCurrent {
		t.Fatal(result.Result)
	}
	setup.Close()
	selected := f.open(t, ctx)
	ref := installedSecretAccessTestRef(t, selected, reader)
	wrong := ref
	wrong.PublicBindingDigest = fixtureID(f.env.Domain, "wrong selected binding")
	for _, cell := range []struct {
		name string
		ref  contract.RecipientBindingReference
	}{{"absent", ref}, {"plain", ref}, {"secret", wrong}, {"secret", installedSecretAccessTestRef(t, selected, authority)}} {
		admitted := 0
		cas := f.env.Store.(*memoryStore).cas
		_, private := f.keys.Calls()
		var result PublicApplyResult
		if cell.name != "secret" {
			installation := installedSecretAccessTestInstallation(t, f, selected, installedApplyGeneratedValidator(t, selected), nil, &admitted)
			engine, err := NewInstalledEnvelopeRekey(EnvelopeRekeyInstallation{AccessMutationInstallation: installation.AccessMutationInstallation, AdmitCustody: installation.AdmitCustody, Name: cell.name})
			if err != nil {
				t.Fatal(err)
			}
			result = engine.Rekey(ctx, fixtureID(f.env.Domain, "refused exact target"))
			engine.Close()
		} else {
			result = installedRetirementTestRun(t, ctx, f, selected, cell.ref, "refused exact binding", func(contract.CryptoCompareRequest, uint16) { admitted++ })
		}
		_, privateAfter := f.keys.Calls()
		if result.Result.Outcome != AdmissionRefused || admitted != 0 || privateAfter != private || f.env.Store.(*memoryStore).cas != cas {
			t.Fatal("invalid target crossed custody or selection", cell.name, result.Result, admitted)
		}
	}
}

// full_only: false
func TestInstalledGeneratedSecretRekeyPreservesParkedRetainedWork(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	retained := newRetainedReaderFixture(t, true, 2)
	selected := retained.selected
	f := installedApplyTestFixture{env: retained.env, keys: retained.keys, basis: selected.admission.publicBasis(), composition: selected.admission.composition, admitted: OpenContext{admission: &selected.admission}, selected: selected}
	_, old := lifecycleEntry(t, selected, "generated")
	before := ownScenarioValueEntry(*old)
	stable := installedApplyStableWork(t, ctx, selected)
	beforeReceipts, err := selected.receiptWindows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	access := selected.accessRecords()
	f.keys.SetDenied(f.keys.RecoveryID(), true)
	f.env.Recovery.(*testtrust.Signer).SetUnavailable(true)
	var trace *installedSecretAccessTrace
	installation := installedSecretAccessTestInstallation(t, f, selected, installedApplyGeneratedValidator(t, selected), &trace, nil)
	engine, err := NewInstalledEnvelopeRekey(EnvelopeRekeyInstallation{AccessMutationInstallation: installation.AccessMutationInstallation, AdmitCustody: installation.AdmitCustody, Name: "generated"})
	if err != nil {
		t.Fatal(err)
	}
	result := engine.Rekey(ctx, fixtureID(f.env.Domain, "generated standalone rekey"))
	engine.Close()
	if result.Result.Outcome != ObservedCurrent || result.Payload == nil || result.Payload.ChangedSubjects.Count != 3 || len(result.Payload.LiveHazardIDs) != 2 || len(result.Payload.LiveDutyIDs) != 0 {
		t.Fatal("generated rekey failed exact generated/retained result", result.Result)
	}
	fresh := f.open(t, ctx)
	_, current := lifecycleEntry(t, fresh, "generated")
	wantGenerated := before.Generated
	wantGenerated.GenerationID = current.ValueState
	afterReceipts, err := fresh.receiptWindows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assertSuccessReceiptOrder(t, beforeReceipts, afterReceipts, result.OperationID)
	beforeClosure, afterClosure := selected.root.Generated, fresh.root.Generated
	beforeClosure.Fragments, afterClosure.Fragments = nil, nil
	beforeClosure.SuccessWindow, afterClosure.SuccessWindow = contract.GeneratorDescriptor{}, contract.GeneratorDescriptor{}
	beforeClosure.ReceiptOrder, afterClosure.ReceiptOrder = contract.GeneratorDescriptor{}, contract.GeneratorDescriptor{}
	if current.Incarnation != before.Incarnation || current.ValueState == before.ValueState || current.Generated != wantGenerated || !slices.Equal(current.Recipients, before.Recipients) || !reflect.DeepEqual(stable, installedApplyStableWork(t, ctx, fresh)) || !reflect.DeepEqual(beforeClosure, afterClosure) || !slices.Equal(fresh.generatedSliceLocations, selected.generatedSliceLocations) || fresh.root.OutputConfiguration != selected.root.OutputConfiguration {
		t.Fatal("generated rekey changed resource identity, Attempt, target, seed, duty, hazard or output markers")
	}
	newReceipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	wantSuccesses := append(slices.Clone(beforeReceipts.Successes), newReceipt)
	if len(wantSuccesses) > contract.MutationReceiptWindowLimit {
		wantSuccesses = wantSuccesses[len(wantSuccesses)-contract.MutationReceiptWindowLimit:]
	}
	if afterReceipts.DomainID != beforeReceipts.DomainID || !slices.Equal(afterReceipts.Successes, wantSuccesses) || !slices.Equal(afterReceipts.Failures, beforeReceipts.Failures) {
		t.Fatal("generated rekey did not preserve receipt history and append exactly its receipt")
	}
	for _, oldAccess := range access {
		if oldAccess.MaterialKind == contract.ValueMaterialKind && oldAccess.MaterialID == before.ValueState {
			continue
		}
		after, ok := fresh.materialAccess(oldAccess.MaterialKind, oldAccess.MaterialID)
		if !ok || !reflect.DeepEqual(after, oldAccess) {
			t.Fatal("generated rekey changed unrelated retained access or wraps")
		}
	}
	if trace == nil || len(trace.comparison) != 1 || trace.comparison[0].Relation != contract.CryptoEqual || len(trace.identities) != 1 {
		t.Fatal("generated target private equality or fresh plan differs")
	}
	if check := f.keys.Consume(ctx, sessionConsumerSelection(t, fresh, fresh.admission.recipient, "generated"), custody.StandardValue); check.Code != contract.CryptoSuccess || !check.ValueMatched || check.Delivery != 1 {
		t.Fatal("generated rekey changed current plaintext", check)
	}
}

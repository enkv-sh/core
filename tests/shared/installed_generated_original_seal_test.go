package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestInstalledGeneratedApplyChecksOriginalSealedSecretBeforeCreate(t *testing.T) {
	process, effects := configurationRecoveryLocalGeneratedProcess(t)
	for _, recovery := range []bool{false, true} {
		for _, unequal := range []bool{false, true} {
			t.Run(fmt.Sprintf("recovery=%t/unequal=%t", recovery, unequal), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
				defer cancel()
				f := newInstalledApplyTestFixture(t, ctx, contract.GCP, recovery)
				f.env.GeneratedProcess = process
				authority, reader := f.selected.admission.recipient, fixtureID(f.env.Domain, "reader")
				members := []contract.ID{authority, reader}
				slices.SortFunc(members, compareGeneratedIDs)
				original := suppliedSecret(t, f.env, "secret", "installed mixed original seal", custody.StandardValue, members...)
				initial := f.engine(t, f.selected, []ApplyEntryInput{original}, nil)
				got := initial.Apply(ctx, testID("installed mixed original predecessor"), []ApplyEntryInput{original})
				initial.Close()
				if got.Result.Outcome != ObservedCurrent {
					t.Fatal("shared current StandardValue was not selected", got.Result)
				}
				before := f.open(t, ctx)
				_, old := observeCurrentValueEntry(t, before, "secret")
				oldAccess, ok := observeMaterialAccess(before, contract.ValueMaterialKind, old.ValueState)
				if !ok || !slices.Equal(old.Recipients, members) || !slices.Equal(scenarioAccessRecipients(oldAccess), members) || len(oldAccess.Wraps) != 2+boolInt(recovery) {
					t.Fatal("predecessor lacks exact shared current access")
				}
				oldReader := sessionConsumerSelection(t, before, reader, "secret")
				if check := f.keys.Consume(ctx, oldReader, custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
					t.Fatal("original Reader could not consume StandardValue", check)
				}
				proposed := original
				if unequal {
					proposed = suppliedSecret(t, f.env, "secret", "installed mixed unequal original seal", custody.AlternateStandardValue, members...)
				}
				originalSeal, err := contract.InspectSealedInputEnvelope(original.InputBytes)
				if err != nil {
					t.Fatal("original shared seal could not be inspected")
				}
				proposedSeal, err := contract.InspectSealedInputEnvelope(proposed.InputBytes)
				if err != nil || proposedSeal.Core.IntendedRecipientBindingSetDigest.IsZero() || proposedSeal.Core.IntendedRecipientBindingSetDigest != originalSeal.Core.IntendedRecipientBindingSetDigest {
					t.Fatal("real proposed seal lost the original shared recipient-binding set")
				}
				sealedBefore := bytes.Clone(proposed.InputBytes)
				proposed.Recipients = []contract.ID{authority}
				generation := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Epoch: 0, RetirementMode: contract.GeneratedRetirementManual,
					ConfigContractID: process.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(),
					CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent)}
				input := []ApplyEntryInput{{Name: "generated", Recipients: []contract.ID{authority}, ValueSource: contract.Generated,
					ConfidentialityClass: contract.Secret, Generated: &generation}, proposed}
				callbacks := installedGeneratedTestCallbacks(t, f, process)
				reservationCalls := 0
				reserve := callbacks.AdmitReservation
				callbacks.AdmitReservation = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedReservationInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
					reservationCalls++
					graph, err := contract.DecodeGeneratorPlanBundle(in.Session.Graph)
					if err != nil {
						return nil, err
					}
					at := slices.IndexFunc(graph.ValueEntryPlans, func(row contract.GeneratorValueEntryPlan) bool { return row.Name == "secret" })
					if at < 0 || graph.ValueEntryPlans[at].ChangeMask&contract.GeneratorValueChangeContent != 0 || graph.ValueEntryPlans[at].ChangeMask&contract.GeneratorValueChangeMembership == 0 ||
						len(in.Plan.CurrentValues) != 1 || !reflect.DeepEqual(in.Plan.CurrentValues[0].Entry, old) || !reflect.DeepEqual(in.Plan.CurrentValues[0].Access, oldAccess) {
						t.Error("installed derivation/loading omitted exact equal-only exclusion facts")
						return nil, contract.ErrRecord
					}
					declaration, err := contract.InspectGeneratorDeclaration(in.Plan.Declaration)
					if err != nil {
						return nil, err
					}
					entry, _, err := declaration.Entry(at)
					if err != nil || entry.Kind != contract.GeneratorDeclarationSealed || !bytes.Equal(entry.Payload, sealedBefore) {
						t.Error("installed declaration replaced or damaged the original seal")
						return nil, contract.ErrRecord
					}
					registry, err := contract.DecodeGeneratedRecipientRegistryImage(in.Plan.RegistryImage)
					if err != nil {
						return nil, err
					}
					authorityAt := slices.IndexFunc(registry.Recipients, func(row contract.ApplyRecipientInput) bool { return row.Recipient.RecipientID == authority })
					current := in.Plan.CurrentValues[0]
					wrapAt := slices.IndexFunc(current.Access.Wraps, func(row contract.WrapRow) bool {
						return row.SubjectKind == contract.OrdinaryWrapSubject && row.SubjectID == authority
					})
					if authorityAt < 0 || wrapAt < 0 || !bytes.Equal(entry.RecipientIDs, authority[:]) || current.Binding.SubjectID != authority ||
						registry.Recipients[authorityAt].Recipient.CurrentBinding == nil || !reflect.DeepEqual(*registry.Recipients[authorityAt].Recipient.CurrentBinding, current.Binding.Binding) {
						t.Error("admitted proposed secret does not use the exact current Authority-only binding")
						return nil, contract.ErrRecord
					}
					// Independent one-row preimage; do not call production binding-set encoders.
					const prefix = "ENKV/CRYPTO/v2/source-recipient-bindings\x00"
					var preimage [len(prefix) + 32 + 2 + 32 + 32]byte
					offset := copy(preimage[:], prefix)
					offset += copy(preimage[offset:], control.DomainID[:])
					preimage[offset], preimage[offset+1] = 0, 1
					offset += 2
					offset += copy(preimage[offset:], authority[:])
					copy(preimage[offset:], current.Access.Wraps[wrapAt].PublicBindingDigest[:])
					intended := contract.ID(sha256.Sum256(preimage[:]))
					actualSeal, err := contract.InspectSealedInputEnvelope(entry.Payload)
					if err != nil || actualSeal.Core.IntendedRecipientBindingSetDigest != proposedSeal.Core.IntendedRecipientBindingSetDigest || actualSeal.Core.IntendedRecipientBindingSetDigest == intended {
						t.Error("actual original seal does not exercise the admitted Authority-only binding mismatch")
						return nil, contract.ErrRecord
					}
					return reserve(ctx, q, control, in, deadline)
				}
				var producerCalls, reservedReads atomic.Int32
				// This independent observation must not reuse the producer selection's Store episode.
				observationCtx := ctx
				admit := callbacks.AdmitProducer
				callbacks.AdmitProducer = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedProducerInput, implementation contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
					producerCalls.Add(1)
					owner, err := admit(ctx, q, control, in, implementation, deadline)
					if err != nil || owner == nil {
						return owner, err
					}
					invoke := owner.InvokeProducer
					owner.InvokeProducer = func(ctx context.Context, locator, transmission contract.ID) contract.GeneratedProducerResult {
						selected, result := Open(observationCtx, f.admitted, f.env.Store)
						if selected == nil {
							t.Error("provider predecessor read refused", result.Outcome, result.Reason, result.StoreReason)
							return contract.GeneratedProducerResult{Code: contract.CryptoInvalidAdmission}
						}
						if result.Outcome != ObservedCurrent || selected.root.Generated.ActiveOwner.IsZero() || selected.root.ValueEntryCount != 1 || selected.root.Generated.GeneratedCurrent != 0 {
							t.Error("provider entry lacks an unchanged selected predecessor and active reservation", result.Outcome, selected.root.Generated.ActiveOwner.IsZero(), selected.root.ValueEntryCount, selected.root.Generated.GeneratedCurrent)
							return contract.GeneratedProducerResult{Code: contract.CryptoInvalidAdmission}
						}
						at := slices.IndexFunc(selected.root.Names, func(row format.NameEntry) bool { return row.Name == "secret" })
						access, present := selected.materialAccess(contract.ValueMaterialKind, old.ValueState)
						if at < 0 || !reflect.DeepEqual(*selected.valueEntry(selected.root.Names[at].Slot), old) || !present || !reflect.DeepEqual(access, oldAccess) {
							t.Error("selected reservation lost old shared value/access before complete Final")
							return contract.GeneratedProducerResult{Code: contract.CryptoInvalidAdmission}
						}
						reservedReads.Add(1)
						return invoke(ctx, locator, transmission)
					}
					return owner, nil
				}
				engine := installedGeneratedTestEngine(t, ctx, f, before, input, currentApplyRecipients(before.registry()), callbacks)
				store := requireAdmittedMemoryStore(t, f.env.Store)
				trust, ok := underlyingAdmittedFixtureTrust(f.env.Trust)
				if !ok {
					t.Fatal("fixture does not expose its actual Trust signer")
				}
				signs := trust.Calls()
				writes, cas := store.creates, store.cas
				createsBefore, deletesBefore := effects()
				result := engine.Apply(ctx, testID("installed mixed original-seal request"), input)
				engine.Close()
				createsAfter, deletesAfter := effects()
				if reservationCalls != 1 || !bytes.Equal(proposed.InputBytes, sealedBefore) || !slices.Equal(proposed.Recipients, []contract.ID{authority}) || !bytes.Equal(generation.Intent, process.Intent) {
					t.Fatal("mixed original-seal admission was bypassed or source input changed")
				}
				cold := f.open(t, ctx)
				if unequal {
					if result.Result != refused(AdmissionInvalid) || producerCalls.Load() != 0 || reservedReads.Load() != 0 || createsAfter != createsBefore || deletesAfter != deletesBefore || store.creates != writes || store.cas != cas || trust.Calls() != signs ||
						result.Payload != nil || len(result.Receipt) != 0 || !bytes.Equal(cold.body, before.body) || !reflect.DeepEqual(cold.root, before.root) || !reflect.DeepEqual(cold.registry(), before.registry()) || !reflect.DeepEqual(cold.accessRecords(), before.accessRecords()) {
						t.Fatal("real unequal original seal reached mutation/effects or changed current state", result.Result)
					}
					_, current := observeCurrentValueEntry(t, cold, "secret")
					if !reflect.DeepEqual(current, old) {
						t.Fatal("unequal proposal changed the original shared secret")
					}
					return
				}
				if result.Result.Outcome != ObservedCurrent || result.Payload == nil || result.Generated == nil || !result.Generated.EffectsAvailable || len(result.Generated.Effects) != 1 ||
					result.Generated.Effects[0].Name != "generated" || result.Generated.Effects[0].Action != contract.GeneratorActionCreate || result.Generated.EffectSummary != contract.ReceiptEffectComplete ||
					producerCalls.Load() != 1 || reservedReads.Load() != 1 || createsAfter-createsBefore != 1 || deletesAfter != deletesBefore {
					t.Fatal("equal original seal did not join one exact generated create with complete selection", result.Result)
				}
				if cold.root.ValueEntryCount != 2 || cold.root.SecretCount != 2 || cold.root.MembershipCount != 2 || cold.root.Generated.GeneratedCurrent != 1 || !cold.root.Generated.ActiveOwner.IsZero() ||
					!reflect.DeepEqual(cold.registry(), before.registry()) || !reflect.DeepEqual(cold.root.CurrentAccess.Core.Recovery, before.root.CurrentAccess.Core.Recovery) {
					t.Fatal("complete selected set, registry or Recovery differs")
				}
				_, current := observeCurrentValueEntry(t, cold, "secret")
				assertFreshSecretValue(t, &old, &current, true)
				currentAccess, ok := observeMaterialAccess(cold, contract.ValueMaterialKind, current.ValueState)
				if !ok || !slices.Equal(current.Recipients, []contract.ID{authority}) || !slices.Equal(scenarioAccessRecipients(currentAccess), []contract.ID{authority}) || len(currentAccess.Wraps) != 1+boolInt(recovery) {
					t.Fatal("current exclusion did not remove exactly Reader while retaining Recovery")
				}
				for _, wrap := range currentAccess.Wraps {
					if wrap.SubjectKind != contract.OrdinaryWrapSubject && (!recovery || wrap.SubjectKind != contract.RecoveryWrapSubject || wrap.SubjectID != cold.root.CurrentAccess.Core.Recovery.RoleID) {
						t.Fatal("current exclusion has an unexpected Recovery wrap")
					}
				}
				if oldAccess, present := cold.materialAccess(contract.ValueMaterialKind, old.ValueState); present {
					t.Fatal("completed apply retained unowned old current access", oldAccess.MaterialID)
				}
				if selected, refused := cold.admitConsumerSelection(ctx, []string{"secret"}, reader); selected != nil || refused.Outcome != AdmissionRefused {
					t.Fatal("removed Reader retained current selection", refused)
				}
				if check := f.keys.Consume(ctx, sessionConsumerSelection(t, cold, authority, "secret"), custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
					t.Fatal("current exclusion changed supplied plaintext", check)
				}
				if check := f.keys.Consume(ctx, oldReader, custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
					t.Fatal("current exclusion incorrectly revoked an already held historical selection", check)
				}
				_, generated := observeCurrentValueEntry(t, cold, "generated")
				if generated.ValueSource != contract.Generated || generated.ConfidentialityClass != contract.Secret || generated.Generated.Epoch != 0 || generated.Generated.OriginOperationID != result.OperationID ||
					generated.Generated.ResourceContractID != hermeticCloudflareResourceContractID() || !slices.Equal(generated.Recipients, []contract.ID{authority}) {
					t.Fatal("selected generated sibling lost exact epoch, origin or membership")
				}
				receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
				if err != nil || receipt.StateResult != contract.ReceiptStateSuccess || receipt.OperationKind != contract.OperationApplyDeclaration || receipt.OperationID != result.OperationID ||
					receipt.RequestIdentityDigest != result.RequestIdentity || receipt.EffectSummary != contract.ReceiptEffectComplete || receipt.SummaryCounts[contract.ReceiptEffectCount] != 1 || receipt.SummaryCounts[contract.ReceiptSummarySuccessCount] != 1 {
					t.Fatal("mixed selection receipt lost its exact complete one-create result", err)
				}
			})
		}
	}
}

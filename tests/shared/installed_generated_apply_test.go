package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestInstalledGeneratedApplySelectsCompleteGeneratedAndSuppliedSet(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	process, effects := configurationRecoveryLocalGeneratedProcess(t)
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	f.env.GeneratedProcess = process
	selected := f.selected
	authority := selected.admission.recipient
	implementation := process.Implementation
	intent := bytes.Clone(process.Intent)
	declaration := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Epoch: 0, RetirementMode: contract.GeneratedRetirementManual,
		ConfigContractID: implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(), CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: intent}
	input := []ApplyEntryInput{
		{Name: "generated", Recipients: []contract.ID{authority}, ValueSource: contract.Generated,
			ConfidentialityClass: contract.Secret, Generated: &declaration},
		{Name: "plain", Recipients: []contract.ID{authority}, ValueSource: contract.Supplied,
			ConfidentialityClass: contract.Plain, InputBytes: []byte("complete supplied sibling")},
	}
	validator := NewPublicConfigurationValidator(nil)
	desired := currentApplyRecipients(selected.registry())
	configuration := installedApplyTestConfiguration(t, ctx, selected, input, desired, validator)
	configuration.Entries.Value[0].Generated = installedGeneratedPublicSettings(&declaration)
	configurationBefore := ownPublicConfiguration(configuration)
	intentBefore, plainBefore := bytes.Clone(intent), bytes.Clone(input[1].InputBytes)
	engine, err := NewInstalledApply(ApplyInstallation{ExpectedDomain: f.env.Domain, ExpectedStore: f.env.Store.Descriptor(),
		PublicBasis: f.basis, ExpectedControl: currentControlOf(selected), DesiredRecipients: desired,
		GeneratorImplementations: []contract.GeneratorImplementation{implementation}, Generated: installedGeneratedTestCallbacks(t, f, process), PublicConfiguration: configuration,
		ConfigurationValidator: validator, Store: f.env.Store, Trust: f.env.Trust, CompositionID: f.composition,
		FileIdentity: fixtureID(f.env.Domain, "source-file"), CloseInstalled: func() {},
		AdmitCustody: func(ctx context.Context, q contract.CryptoCompareRequest, control contract.ControlCore,
			current []contract.RecipientRecord, plain []contract.MembershipRow, support contract.DescriptorVector,
			witness *contract.GeneratedSupportTransition, revision contract.ID, before contract.MutationReceiptWindows,
			warningBits uint8, deadline time.Time) (*InstalledApplyCustody, error) {
			owner, err := f.keys.NewApplyCustody(q, control, current, fixtureID(f.env.Domain, "source-file"),
				plain, support, witness, revision, before, warningBits, deadline)
			if err != nil {
				return nil, err
			}
			return &InstalledApplyCustody{Crypto: owner, BindReceipt: owner.BindReceipt, Close: owner.Close}, nil
		}})
	if err != nil {
		t.Fatal("installed generated apply construction", err)
	}
	defer engine.Close()
	result := engine.Apply(ctx, fixtureID(f.env.Domain, "installed generated whole-set request"), input)
	if !reflect.DeepEqual(configuration, configurationBefore) || !bytes.Equal(intent, intentBefore) ||
		!bytes.Equal(input[1].InputBytes, plainBefore) || input[0].InputBytes != nil || declaration.Epoch != 0 ||
		!slices.Equal(input[0].Recipients, []contract.ID{authority}) || !slices.Equal(input[1].Recipients, []contract.ID{authority}) {
		t.Error("installed apply changed its complete source inputs")
	}
	creates, deletes := effects()
	if result.Result.Outcome != ObservedCurrent || result.Payload == nil || result.RequestIdentity.IsZero() ||
		creates != 1 || deletes != 0 {
		t.Fatal("installed apply did not select the complete generated and supplied set with one create", result.Result, creates, deletes)
	}
	receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
	if err != nil || receipt.OperationKind != contract.OperationApplyDeclaration || receipt.OperationID != result.OperationID ||
		receipt.RequestIdentityDigest != result.RequestIdentity || receipt.StateResult != contract.ReceiptStateSuccess ||
		receipt.EffectSummary != contract.ReceiptEffectComplete || receipt.SummaryCounts[contract.ReceiptEffectCount] != 1 ||
		receipt.SummaryCounts[contract.ReceiptSummarySuccessCount] != 1 || receipt.ChangedSubjects.Count != 5 {
		t.Fatal("installed generated receipt differs from the complete selection", err, receipt)
	}
	cold := f.open(t, ctx)
	if cold.root.ValueEntryCount != 2 || cold.root.SecretCount != 1 || cold.root.MembershipCount != 2 ||
		cold.root.Generated.GeneratedCurrent != 1 || !cold.root.Generated.ActiveOwner.IsZero() ||
		!reflect.DeepEqual(cold.registry(), selected.registry()) {
		t.Fatal("cold selection lost the complete value set or changed the registry")
	}
	generatedAt := slices.IndexFunc(cold.root.Names, func(row format.NameEntry) bool { return row.Name == "generated" })
	plainAt := slices.IndexFunc(cold.root.Names, func(row format.NameEntry) bool { return row.Name == "plain" })
	if generatedAt < 0 || plainAt < 0 {
		t.Fatal("cold selection omitted a requested sibling")
	}
	generated, supplied := cold.valueEntry(cold.root.Names[generatedAt].Slot), cold.valueEntry(cold.root.Names[plainAt].Slot)
	if generated.ValueSource != contract.Generated || generated.ConfidentialityClass != contract.Secret ||
		generated.Generated.Epoch != 0 || generated.Generated.LifecycleMode != contract.GeneratorLifecycleManaged ||
		generated.Generated.ConfigContractID != implementation.ConfigContractID || generated.Generated.ResourceContractID != hermeticCloudflareResourceContractID() ||
		generated.Generated.OriginOperationID != result.OperationID ||
		generated.Generated.ResourceDigest != hermeticCloudflareResourceDigest("00000000000000000000000000000001") ||
		!slices.Equal(generated.Recipients, []contract.ID{authority}) ||
		supplied.ValueSource != contract.Supplied || supplied.ConfidentialityClass != contract.Plain ||
		!bytes.Equal(supplied.ValueBytes, plainBefore) || !slices.Equal(supplied.Recipients, []contract.ID{authority}) {
		t.Fatal("cold generated origin or supplied sibling differs from the exact request")
	}
	beforeNoOp := bytes.Clone(cold.body)
	noFresh := installedGeneratedTestCallbacks(t, f, process)
	noFresh.CheckCreateReadiness = func(context.Context, string, contract.GeneratorImplementation, []byte) error {
		t.Fatal("same-epoch current value requested fresh CREATE readiness")
		return contract.ErrRecord
	}
	unchanged := installedGeneratedTestEngine(t, ctx, f, cold, input, currentApplyRecipients(cold.registry()), noFresh)
	noOp := unchanged.Apply(ctx, fixtureID(f.env.Domain, "unchanged generated value"), input)
	unchanged.Close()
	afterNoOp := f.open(t, ctx)
	creates, deletes = effects()
	if noOp.Result.Outcome != Unchanged || !bytes.Equal(afterNoOp.body, beforeNoOp) || creates != 1 || deletes != 0 {
		t.Fatal("same-epoch current value changed state or entered a new effect", noOp.Result, creates, deletes)
	}
}

func installedGeneratedTestCallbacks(t testing.TB, f installedApplyTestFixture, process *generatedProcessFixture) *GeneratedApplyInstallation {
	t.Helper()
	wrap := func(owner *custody.InstalledGeneratedOwner, err error) (*InstalledGeneratedCustody, error) {
		if err != nil {
			return nil, err
		}
		return &InstalledGeneratedCustody{Crypto: owner, BindCandidate: owner.BindCandidate, Close: owner.Close}, nil
	}
	return &GeneratedApplyInstallation{
		CheckCreateReadiness: func(ctx context.Context, _ string, row contract.GeneratorImplementation, intent []byte) error {
			if !reflect.DeepEqual(row, process.Implementation) || !bytes.Equal(intent, process.Intent) {
				return contract.ErrRecord
			}
			metadata, err := os.ReadFile(process.Artifact + ".metadata.json")
			if err != nil {
				return err
			}
			dependency, err := os.ReadFile(process.Artifact + ".dependencies.bin")
			if err != nil {
				return err
			}
			return installedGeneratorCreateReadiness(ctx, custody.GeneratedProcessConfig{ArtifactPath: process.Artifact, Artifact: row, Metadata: metadata, Dependency: dependency}, intent)
		},
		CheckRetirementCompatibility: func(ctx context.Context, row contract.GeneratorImplementation, intent []byte, facts contract.GeneratorSafeFacts, completion uint8) ([]byte, []byte, error) {
			return hermeticCloudflareRetirementExchange(ctx, process.Artifact, row, intent, facts, completion)
		},
		ResolveImplementation: func(request GeneratedImplementationRequest) (contract.GeneratorImplementation, error) {
			row := process.Implementation
			if request.ConfigContractID != row.ConfigContractID || request.LifecycleMode != contract.GeneratorLifecycleManaged || request.ResourceContractID != hermeticCloudflareResourceContractID() {
				return row, contract.ErrRecord
			}
			return row, nil
		},
		RequestDigest: func(ctx context.Context, row contract.GeneratorImplementation, action uint8, intent []byte, target *contract.GeneratorTarget) (contract.ID, error) {
			if ctx.Err() != nil || !reflect.DeepEqual(row, process.Implementation) || action != contract.GeneratorActionCreate || target != nil || !bytes.Equal(intent, process.Intent) {
				return contract.ID{}, contract.ErrRecord
			}
			return process.RequestDigest, nil
		},
		AdmitReservation: func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedReservationInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
			owner, err := f.keys.NewInstalledGeneratedReservation(q, control, input, fixtureID(f.env.Domain, "source-file"), deadline)
			return wrap(owner, err)
		},
		AdmitProducer: func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedProducerInput, row contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
			config := process.Configure(t, process.Artifact, input.Expected)
			owner, err := f.keys.NewInstalledGeneratedProducer(ctx, q, control, input, config, deadline)
			base, err := wrap(owner, err)
			if err != nil {
				return nil, err
			}
			return &InstalledGeneratedProducerCustody{InstalledGeneratedCustody: *base, InvokeProducer: owner.InvokeProducer}, nil
		},
		AdmitAdoption: func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedAdoptionInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
			owner, err := f.keys.NewInstalledGeneratedAdoption(q, control, input, deadline)
			return wrap(owner, err)
		},
		AdmitFinal: func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedFinalInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
			owner, err := f.keys.NewInstalledGeneratedFinal(q, control, input, deadline)
			return wrap(owner, err)
		},
	}
}

func installedGeneratedPublicSettings(g *contract.GeneratorDeclaredGeneration) *contract.PublicGeneratedSettings {
	public := &contract.PublicGeneratedSettings{Epoch: observedPublicField(g.Epoch), ConfigContractID: observedPublicField(g.ConfigContractID), ResourceContractID: observedPublicField(g.ResourceContractID), LifecycleMode: observedPublicField(g.LifecycleMode), ContentIntent: observedPublicField(bytes.Clone(g.Intent))}
	if g.LifecycleMode == contract.GeneratorLifecycleManaged {
		public.Retirement = observedPublicField(g.RetirementMode)
		public.Completion = observedPublicField(g.CompletionClass)
	}
	return public
}

func installedGeneratedTestEngine(t testing.TB, ctx context.Context, f installedApplyTestFixture, selected *StateSession, input []ApplyEntryInput, desired []contract.ApplyRecipientInput, callbacks *GeneratedApplyInstallation) *InstalledApply {
	t.Helper()
	implementation := f.env.GeneratedProcess.Implementation
	validator := NewPublicConfigurationValidator(selected.admission.outputInterpreter)
	configuration := installedApplyTestConfiguration(t, ctx, selected, input, desired, validator)
	for at := range configuration.Entries.Value {
		row := &configuration.Entries.Value[at]
		source := slices.IndexFunc(input, func(entry ApplyEntryInput) bool { return entry.Name == row.Name })
		if source < 0 || input[source].Generated == nil {
			continue
		}
		g := input[source].Generated
		row.Generated = installedGeneratedPublicSettings(g)
	}
	engine, err := NewInstalledApply(ApplyInstallation{ExpectedDomain: f.env.Domain, ExpectedStore: f.env.Store.Descriptor(), PublicBasis: f.basis, ExpectedControl: currentControlOf(selected), DesiredRecipients: desired, GeneratorImplementations: []contract.GeneratorImplementation{implementation}, Generated: callbacks, PublicConfiguration: configuration, ConfigurationValidator: validator, Store: f.env.Store, Trust: f.env.Trust, CompositionID: f.composition, FileIdentity: fixtureID(f.env.Domain, "source-file"), CloseInstalled: func() {}, AdmitCustody: func(ctx context.Context, q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, plain []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, revision contract.ID, before contract.MutationReceiptWindows, warningBits uint8, deadline time.Time) (*InstalledApplyCustody, error) {
		owner, err := f.keys.NewApplyCustody(q, control, current, fixtureID(f.env.Domain, "source-file"), plain, support, witness, revision, before, warningBits, deadline)
		if err != nil {
			return nil, err
		}
		return &InstalledApplyCustody{Crypto: owner, BindReceipt: owner.BindReceipt, Close: owner.Close}, nil
	}})
	if err != nil {
		t.Fatal("installed generated engine", err)
	}
	t.Cleanup(engine.Close)
	return engine
}

// full_only: false
func TestInstalledGeneratedContinueInstallsAcceptedRegistryAfterRestart(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("recovery=%t", recovery), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			process, effects := configurationRecoveryLocalGeneratedProcess(t)
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, recovery)
			f.env.GeneratedProcess = process
			desired := installedApplyPreparedRecipient(t, f.selected, "generated registry creation nonce")
			created := slices.IndexFunc(desired, func(row contract.ApplyRecipientInput) bool { return row.Creation != nil })
			pending := desired[created].Recipient.RecipientID
			for at := range desired {
				if desired[at].Recipient.RecipientID == f.selected.admission.recipient {
					desired[at].Recipient.DisplayName = "accepted authority display"
				}
			}
			readers := []contract.ID{f.selected.admission.recipient, pending}
			slices.SortFunc(readers, compareGeneratedIDs)
			meta := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Epoch: 0, RetirementMode: contract.GeneratedRetirementManual, ConfigContractID: process.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(), CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent)}
			input := []ApplyEntryInput{{Name: "generated", Recipients: readers, ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Generated: &meta}, {Name: "plain", Recipients: []contract.ID{f.selected.admission.recipient}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("accepted complete sibling")}}
			callbacks := installedGeneratedTestCallbacks(t, f, process)
			traceOwner := func(stage string, owner *InstalledGeneratedCustody, err error) {
				t.Log("registry restart admission", stage, "owner present", owner != nil, "error", err)
				if owner != nil && owner.BindCandidate != nil {
					bind := owner.BindCandidate
					owner.BindCandidate = func(ctx context.Context, candidate contract.GeneratedCandidateInput) contract.CryptoResultCode {
						code := bind(ctx, candidate)
						t.Log("registry restart binding", stage, "code", code)
						return code
					}
				}
			}
			admitReservation := callbacks.AdmitReservation
			callbacks.AdmitReservation = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedReservationInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
				owner, err := admitReservation(ctx, q, control, in, deadline)
				traceOwner("reservation", owner, err)
				return owner, err
			}
			admitProducer := callbacks.AdmitProducer
			callbacks.AdmitProducer = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedProducerInput, implementation contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
				owner, err := admitProducer(ctx, q, control, in, implementation, deadline)
				if owner == nil {
					traceOwner("producer", nil, err)
				} else {
					traceOwner("producer", &owner.InstalledGeneratedCustody, err)
				}
				return owner, err
			}
			callbacks.AdmitFinal = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedFinalInput, time.Time) (*InstalledGeneratedCustody, error) {
				traceOwner("intentional Final stop", nil, contract.ErrRecord)
				return nil, contract.ErrRecord
			}
			engine := installedGeneratedTestEngine(t, ctx, f, f.selected, input, desired, callbacks)
			initialInstallation := engine.installation
			stopped := engine.Apply(ctx, fixtureID(f.env.Domain, "generated stop before final"), input)
			engine.Close()
			creates, deletes := effects()
			cold := f.open(t, ctx)
			if stopped.OperationID.IsZero() || cold.root.Generated.ActiveOwner != stopped.OperationID || creates != 1 || deletes != 0 || !reflect.DeepEqual(cold.registry(), f.selected.registry()) {
				t.Log("registry restart selected state", "operation present", !stopped.OperationID.IsZero(), "active owner present", !cold.root.Generated.ActiveOwner.IsZero(), "active phase present", !cold.root.Generated.ActivePhase.IsZero())
				if stopped.OperationID.IsZero() {
					deadline, _ := ctx.Deadline()
					plan, err := f.selected.installedGeneratedPlan(ctx, initialInstallation, input, nil, deadline)
					t.Log("registry restart side-effect-free plan validation", "plan present", plan != nil, "error", err)
				}
				t.Fatal("pre-Final stop changed registry or lost exact active operation", stopped.Result, creates, deletes)
			}
			if stopped.Generated == nil || stopped.Payload != nil || len(stopped.Receipt) != 0 {
				t.Fatal("nonterminal apply exposed an unproved terminal payload", stopped.Generated, stopped.Payload)
			}
			selected, err := cold.selectedGeneratedWork(ctx)
			if err != nil || selected.registry == nil || !slices.Equal(selected.registry.InitiallyAbsent, []contract.ID{pending}) {
				t.Fatal("cold accepted recipient image missing", err)
			}
			for _, row := range desired {
				if row.Recipient.RecipientID == pending && cold.recipientRecord(pending) != nil {
					t.Fatal("pending recipient became current before Final")
				}
			}
			// A fresh installed invocation has an edited local complete proposal. Exact
			// continuation must use the retained proposal, including its original proof.
			input[1].InputBytes[0] = 'X'
			meta.Intent[0] = 'X'
			edited := []ApplyEntryInput{{Name: "edited", Recipients: []contract.ID{cold.admission.recipient}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("unrelated local proposal")}}
			resumed := installedGeneratedTestEngine(t, ctx, f, cold, edited, currentApplyRecipients(cold.registry()), installedGeneratedTestCallbacks(t, f, process))
			got := resumed.Continue(ctx, fixtureID(f.env.Domain, "generated exact restart"), stopped.OperationID)
			resumed.Close()
			creates, deletes = effects()
			after := f.open(t, ctx)
			expectedRegistry := make([]contract.RecipientRecord, len(desired))
			for at, row := range desired {
				expectedRegistry[at] = row.Recipient
			}
			if got.Result.Outcome != ObservedCurrent || got.Generated == nil || got.Generated.ReceiptObservation || got.RequestIdentity != stopped.RequestIdentity || creates != 1 || deletes != 0 || !after.root.Generated.ActiveOwner.IsZero() || !reflect.DeepEqual(after.registry(), expectedRegistry) {
				t.Fatal("exact restart did not atomically install accepted registry", got.Result, creates, deletes)
			}
			plainAt := slices.IndexFunc(after.root.Names, func(row format.NameEntry) bool { return row.Name == "plain" })
			if plainAt < 0 || !bytes.Equal(after.valueEntry(after.root.Names[plainAt].Slot).ValueBytes, []byte("accepted complete sibling")) {
				t.Fatal("restart reread the edited supplied source")
			}
			generatorAt := slices.IndexFunc(after.root.Names, func(row format.NameEntry) bool { return row.Name == "generated" })
			generated := after.valueEntry(after.root.Names[generatorAt].Slot)
			if !slices.Equal(generated.Recipients, readers) {
				t.Fatal("Final omitted accepted pending recipient membership")
			}
			selection := sessionConsumerSelection(t, after, after.admission.recipient, "generated")
			if len(selection.Access.Wraps) != len(readers)+boolInt(recovery) {
				t.Fatal("Final has inexact pending/Recovery wrap coverage")
			}
			receiptOnlyCallbacks := installedGeneratedTestCallbacks(t, f, process)
			receiptOnlyCallbacks.ResolveImplementation = func(GeneratedImplementationRequest) (contract.GeneratorImplementation, error) {
				t.Error("terminal receipt lookup resolved an old producer")
				return contract.GeneratorImplementation{}, contract.ErrRecord
			}
			receiptOnlyCallbacks.AdmitFinal = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedFinalInput, time.Time) (*InstalledGeneratedCustody, error) {
				t.Error("terminal receipt lookup entered private custody")
				return nil, contract.ErrRecord
			}
			observer := installedGeneratedTestEngine(t, ctx, f, after, edited, currentApplyRecipients(after.registry()), receiptOnlyCallbacks)
			observed := observer.Continue(ctx, fixtureID(f.env.Domain, "generated terminal observation"), stopped.OperationID)
			observer.Close()
			if observed.Result.Outcome != ObservedCurrent || observed.Generated == nil || !observed.Generated.ReceiptObservation || observed.Generated.EffectsAvailable || observed.Generated.RelatedWorkAvailable || observed.Generated.StateResult != got.Generated.StateResult || !bytes.Equal(observed.Receipt, got.Receipt) {
				t.Fatal("terminal receipt observation fabricated complete effect history or changed historical token")
			}
		})
	}
}

// full_only: false
func TestInstalledGeneratedPlanRequiresFreshReadinessBeforeRequestBinding(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	process, effects := configurationRecoveryLocalGeneratedProcess(t)
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	meta := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema,
		LifecycleMode: contract.GeneratorLifecycleManaged, RetirementMode: contract.GeneratedRetirementManual,
		ConfigContractID: process.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(),
		CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent)}
	input := []ApplyEntryInput{{Name: "generated", Recipients: []contract.ID{f.selected.admission.recipient},
		ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Generated: &meta}}
	requestCalls := 0
	installation := ApplyInstallation{DesiredRecipients: currentApplyRecipients(f.selected.registry()), Generated: &GeneratedApplyInstallation{
		ResolveImplementation: func(GeneratedImplementationRequest) (contract.GeneratorImplementation, error) {
			return process.Implementation, nil
		},
		RequestDigest: func(context.Context, contract.GeneratorImplementation, uint8, []byte, *contract.GeneratorTarget) (contract.ID, error) {
			requestCalls++
			return process.RequestDigest, nil
		},
	}}
	deadline, _ := ctx.Deadline()
	plan, err := f.selected.installedGeneratedPlan(ctx, installation, input, nil, deadline)
	creates, deletes := effects()
	if err == nil || plan != nil || requestCalls != 0 || creates != 0 || deletes != 0 {
		t.Fatal("fresh CREATE without readiness reached request binding", "plan", plan != nil, "error", err,
			"request calls", requestCalls, "creates", creates, "deletes", deletes)
	}
	refused := errors.New("selected generator cannot create")
	installation.Generated.CheckCreateReadiness = func(context.Context, string, contract.GeneratorImplementation, []byte) error { return refused }
	if plan, err := f.selected.installedGeneratedPlan(ctx, installation, input, nil, deadline); !errors.Is(err, refused) || plan != nil || requestCalls != 0 {
		t.Fatal("fresh readiness refusal reached request binding or lost its cause", plan != nil, err, requestCalls)
	}
	readyCalls := 0
	installation.Generated.CheckCreateReadiness = func(ctx context.Context, name string, row contract.GeneratorImplementation, intent []byte) error {
		readyCalls++
		if ctx.Err() != nil || name != "generated" || !reflect.DeepEqual(row, process.Implementation) || !bytes.Equal(intent, process.Intent) {
			t.Fatal("fresh readiness did not receive the exact resolved current input")
		}
		return nil
	}
	if plan, err := f.selected.installedGeneratedPlan(ctx, installation, input, nil, deadline); err != nil || plan == nil || requestCalls != 1 || readyCalls != 1 {
		t.Fatal("accepted fresh readiness did not precede request binding", plan != nil, err, requestCalls, readyCalls)
	}
	creates, deletes = effects()
	if creates != 0 || deletes != 0 {
		t.Fatal("fresh planning entered provider effects", creates, deletes)
	}
}

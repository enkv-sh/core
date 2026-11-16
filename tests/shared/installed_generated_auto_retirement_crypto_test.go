package core

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

func damageInstalledAutomaticCryptoCandidate(t *testing.T, input contract.GeneratedCandidateInput, damage string) contract.GeneratedCandidateInput {
	t.Helper()
	if damage == "healthy" {
		return input
	}
	if damage == "anchor" || damage == "cleared_anchor" || damage == "changed_subjects" || damage == "changed_access" {
		input.SupportRecords = slices.Clone(input.SupportRecords)
		found := false
		for i, row := range input.SupportRecords {
			if row.Kind != contract.GeneratedPhaseSupportKind || row.RecordID != input.ActiveOwner {
				continue
			}
			phase, err := contract.InspectGeneratedPhaseRecord(row.Body)
			if err != nil || phase.SelectionPhaseID.IsZero() {
				t.Fatal("candidate has no authenticated selection anchor", err)
			}
			switch damage {
			case "anchor":
				phase.SelectionPhaseID = testID("different automatic selection anchor")
			case "cleared_anchor":
				phase.SelectionPhaseID = contract.ID{}
				phase.ChangedSubjects, phase.ChangedAccess = contract.GeneratorDescriptor{}, contract.GeneratorDescriptor{}
			case "changed_subjects":
				phase.ChangedSubjects = contract.GeneratorDescriptor{Digest: testID("different frozen subjects"), Length: 42, Count: 1}
			case "changed_access":
				phase.ChangedAccess = contract.GeneratorDescriptor{Digest: testID("different frozen access"), Length: 106, Count: 1}
			}
			input.SupportRecords[i].Body, err = contract.EncodeGeneratedPhaseRecord(phase)
			if err != nil {
				t.Fatal("damaged anchor is not structurally valid", err)
			}
			found = true
		}
		if !found {
			t.Fatal("candidate omitted the selected Phase")
		}
		var err error
		input.PublicState.RequiredSupport, err = contract.RequiredSupportDescriptor(input.PublicState.Domain, input.SupportRecords)
		if err != nil {
			t.Fatal("damaged support projection", err)
		}
		return input
	}
	input.AccessRecords = slices.Clone(input.AccessRecords)
	at := slices.IndexFunc(input.AccessRecords, func(row contract.AccessRecord) bool { return row.MaterialKind == contract.ValueMaterialKind })
	if at < 0 {
		t.Fatal("candidate has no surviving current value access")
	}
	body, err := contract.EncodeAccessRecord(input.AccessRecords[at])
	if err != nil {
		t.Fatal(err)
	}
	row, err := contract.DecodeAccessRecord(body)
	if err != nil {
		t.Fatal(err)
	}
	switch damage {
	case "ordinary_ciphertext", "recovery_ciphertext":
		kind := contract.OrdinaryWrapSubject
		if damage == "recovery_ciphertext" {
			kind = contract.RecoveryWrapSubject
		}
		wrap := slices.IndexFunc(row.Wraps, func(w contract.WrapRow) bool { return w.SubjectKind == kind })
		if wrap < 0 {
			t.Fatal("candidate lacks requested wrap subject", damage)
		}
		row.Wraps[wrap].RSACiphertext[0] ^= 1
	case "package_check":
		row.PackageCheck = testID("different automatic package check")
	case "material_context":
		row.MaterialContextDigest = testID("different automatic material context")
	case "added_identity":
		row.MaterialID = testID("unadmitted automatic access identity")
		input.AccessRecords = append(input.AccessRecords, row)
		input.CurrentAccess.AccessPageRefs = slices.Clone(input.CurrentAccess.AccessPageRefs)
		page := slices.IndexFunc(input.CurrentAccess.AccessPageRefs, func(ref contract.Ref) bool {
			return uint64(ref.Length)+uint64(len(body)) <= contract.MaxAccessPageLength
		})
		if page < 0 {
			t.Fatal("small fixture has no room for one access record")
		}
		input.CurrentAccess.AccessPageRefs[page].Length += uint32(len(body))
	default:
		t.Fatal("unknown candidate damage", damage)
	}
	if damage != "added_identity" {
		input.AccessRecords[at] = row
	}
	slices.SortFunc(input.AccessRecords, func(a, b contract.AccessRecord) int {
		if a.MaterialKind != b.MaterialKind {
			return int(a.MaterialKind) - int(b.MaterialKind)
		}
		return bytes.Compare(a.MaterialID[:], b.MaterialID[:])
	})
	input.CurrentAccess.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(input.PublicState.Domain, input.AccessRecords)
	if err != nil {
		t.Fatal("damaged access projection", err)
	}
	input.CurrentAccess.AccessGeneration++
	input.PublicState.AccessRoot, err = contract.AccessRoot(input.CurrentAccess)
	if err != nil {
		t.Fatal("damaged access root", err)
	}
	input.Subject.AfterAccessDigest = input.PublicState.AccessRoot
	return input
}

// full_only: false
func TestInstalledGeneratedAutomaticCryptoRejectsPostSelectionDrift(t *testing.T) {
	for _, stage := range []string{"producer", "adoption"} {
		for _, damage := range []string{"healthy", "ordinary_ciphertext", "recovery_ciphertext", "package_check", "material_context", "added_identity", "anchor", "changed_subjects", "changed_access"} {
			t.Run(stage+"/"+damage, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
				defer cancel()
				process, effects := installedGeneratedRetirementProcess(t, "acknowledged")
				f := newInstalledApplyTestFixture(t, ctx, contract.GCP, true)
				f.env.GeneratedProcess = process
				generation := &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged, RetirementMode: contract.GeneratedRetirementManual,
					ConfigContractID: process.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(),
					CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent)}
				input := []ApplyEntryInput{{Name: "generated", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret,
					Recipients: []contract.ID{f.selected.admission.recipient}, Generated: generation}}
				initialEngine := installedGeneratedTestEngine(t, ctx, f, f.selected, input, currentApplyRecipients(f.selected.registry()), installedGeneratedRetirementCallbacks(t, f, process))
				initial := initialEngine.Apply(ctx, testID("automatic crypto initial "+stage+damage), input)
				initialEngine.Close()
				if initial.Result.Outcome != ObservedCurrent || len(initial.Receipt) == 0 {
					t.Fatal("initial generation did not complete", initial.Result)
				}
				before := f.open(t, ctx)
				generation.Epoch, generation.RetirementMode = 1, contract.GeneratedRetirementAuto
				callbacks := installedGeneratedRetirementCallbacks(t, f, process)
				store, ok := underlyingAdmittedMemoryStore(f.env.Store)
				if !ok {
					t.Fatal("fixture Store counters unavailable")
				}
				trust, ok := underlyingAdmittedFixtureTrust(f.env.Trust)
				if !ok {
					t.Fatal("fixture signing counters unavailable")
				}
				bound := 0
				var code contract.CryptoResultCode
				var selectedRevision contract.ID
				var createsAtBind, casAtBind, signsAtBind, providerCreatesAtBind, deletesAtBind int
				wrap := func(owner *InstalledGeneratedCustody, phase *contract.GeneratedPhaseRecord) {
					if phase == nil || phase.SelectionPhaseID.IsZero() {
						t.Fatal("production custody admitted no selected anchor")
					}
					bind := owner.BindCandidate
					owner.BindCandidate = func(callctx context.Context, candidate contract.GeneratedCandidateInput) contract.CryptoResultCode {
						bound++
						if bound != 1 {
							t.Fatal("fixture bound more than one automatic candidate")
						}
						selected := f.open(t, callctx)
						work := mustSelectedGeneratedWork(t, selected)
						if !generatedSelectionAnchored(work) || work.phase.SelectionPhaseID != phase.SelectionPhaseID || work.phase.ChangedSubjects != phase.ChangedSubjects || work.phase.ChangedAccess != phase.ChangedAccess {
							t.Fatal("custody anchor differs from actual selected state")
						}
						selectedRevision = selected.head.Core.Revision
						createsAtBind, casAtBind, signsAtBind = store.creates, store.cas, trust.signs
						var deletes []string
						providerCreatesAtBind, deletes = effects()
						deletesAtBind = len(deletes)
						code = bind(callctx, damageInstalledAutomaticCryptoCandidate(t, candidate, damage))
						return code
					}
				}
				producer := callbacks.AdmitProducer
				callbacks.AdmitProducer = func(callctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedProducerInput, implementation contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
					owner, err := producer(callctx, q, control, in, implementation, deadline)
					if err == nil && stage == "producer" && in.Expected.Template.Action == contract.GeneratorActionDelete {
						wrap(&owner.InstalledGeneratedCustody, in.Session.SelectionPhase)
					}
					return owner, err
				}
				adoption := callbacks.AdmitAdoption
				callbacks.AdmitAdoption = func(callctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedAdoptionInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
					owner, err := adoption(callctx, q, control, in, deadline)
					if err == nil && stage == "adoption" && in.Result.Expected.Template.Action == contract.GeneratorActionDelete {
						wrap(owner, in.Session.SelectionPhase)
					}
					return owner, err
				}
				engine := installedGeneratedTestEngine(t, ctx, f, before, input, currentApplyRecipients(before.registry()), callbacks)
				got := engine.Apply(ctx, testID("automatic crypto rotation "+stage+damage), input)
				engine.Close()
				if bound != 1 || selectedRevision.IsZero() {
					t.Fatal("rotation did not reach actual post-selection Crypto binding", got.Result, bound)
				}
				creates, deletes := effects()
				if damage == "healthy" {
					if code != contract.CryptoSuccess || got.Result.Outcome != ObservedCurrent || len(got.Receipt) == 0 || creates != 2 || len(deletes) != 1 {
						t.Fatal("unchanged post-selection candidate did not complete", code, got.Result, creates, deletes)
					}
					return
				}
				if code != contract.CryptoInvalidAdmission || store.creates != createsAtBind || store.cas != casAtBind || trust.signs != signsAtBind || creates != providerCreatesAtBind || len(deletes) != deletesAtBind {
					t.Fatal("damaged post-selection candidate escaped Crypto or entered effects", code, got.Result,
						store.creates-createsAtBind, store.cas-casAtBind, trust.signs-signsAtBind, creates-providerCreatesAtBind, len(deletes)-deletesAtBind)
				}
				cold := f.open(t, ctx)
				if cold.head.Core.Revision != selectedRevision || len(got.Receipt) != 0 {
					t.Fatal("rejected candidate changed exact selected predecessor", got.Result)
				}
			})
		}
	}
}

// full_only: false
func TestInstalledGeneratedAutomaticCryptoRejectsOmittedSelectionWitness(t *testing.T) {
	for _, stage := range []string{"producer", "adoption"} {
		for _, damage := range []string{"healthy", "anchor", "cleared_anchor"} {
			t.Run(stage+"/"+damage, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
				defer cancel()
				process, effects := installedGeneratedRetirementProcess(t, "acknowledged")
				f := newInstalledApplyTestFixture(t, ctx, contract.GCP, true)
				f.env.GeneratedProcess = process
				generation := &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged, RetirementMode: contract.GeneratedRetirementManual,
					ConfigContractID: process.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(),
					CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent)}
				input := []ApplyEntryInput{{Name: "generated", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret,
					Recipients: []contract.ID{f.selected.admission.recipient}, Generated: generation}}
				initialEngine := installedGeneratedTestEngine(t, ctx, f, f.selected, input, currentApplyRecipients(f.selected.registry()), installedGeneratedRetirementCallbacks(t, f, process))
				initial := initialEngine.Apply(ctx, testID("automatic witness initial "+stage+damage), input)
				initialEngine.Close()
				if initial.Result.Outcome != ObservedCurrent || len(initial.Receipt) == 0 {
					t.Fatal("initial generation did not complete", initial.Result)
				}
				before := f.open(t, ctx)
				generation.Epoch, generation.RetirementMode = 1, contract.GeneratedRetirementAuto
				callbacks := installedGeneratedRetirementCallbacks(t, f, process)
				store, ok := underlyingAdmittedMemoryStore(f.env.Store)
				if !ok {
					t.Fatal("fixture Store counters unavailable")
				}
				trust, ok := underlyingAdmittedFixtureTrust(f.env.Trust)
				if !ok {
					t.Fatal("fixture signing counters unavailable")
				}
				admitted, bound := 0, 0
				var admissionErr error
				var code contract.CryptoResultCode
				var selectedRevision contract.ID
				var createsBefore, casBefore, signsBefore, providerCreatesBefore, deletesBefore int
				prepare := func(callctx context.Context, session *contract.GeneratedSessionInput, plan contract.GeneratedPlanInput) {
					admitted++
					if admitted != 1 {
						t.Fatal("fixture reached more than one automatic admission")
					}
					graph, err := contract.DecodeGeneratorPlanBundle(session.Graph)
					if err != nil || len(graph.SourceUses) != 0 || len(plan.LiveSourceUses) != 0 {
						t.Fatal("fixture is not a generated-only automatic plan", err)
					}
					registry, err := contract.DecodeGeneratedRecipientRegistryImage(plan.RegistryImage)
					if err != nil || len(registry.InitiallyAbsent) != 0 || len(session.CurrentRecipients) == 0 {
						t.Fatal("fixture does not use an existing recipient registry", err)
					}
					selected := f.open(t, callctx)
					work := mustSelectedGeneratedWork(t, selected)
					if !generatedSelectionAnchored(work) || session.SelectionPhase == nil || *session.SelectionPhase != *work.phase ||
						session.BeforeAccess == nil || session.Output == nil || session.Output.Inspect(session.BeforePublic) != nil {
						t.Fatal("fixture has no exact authenticated automatic predecessor")
					}
					selectedRevision = selected.head.Core.Revision
					createsBefore, casBefore, signsBefore = store.creates, store.cas, trust.signs
					var deletes []string
					providerCreatesBefore, deletes = effects()
					deletesBefore = len(deletes)
					if damage != "healthy" {
						session.SelectionPhase = nil
					}
				}
				wrap := func(owner *InstalledGeneratedCustody) {
					bind := owner.BindCandidate
					owner.BindCandidate = func(callctx context.Context, candidate contract.GeneratedCandidateInput) contract.CryptoResultCode {
						bound++
						if bound != 1 || candidate.Registry == nil || len(candidate.LiveSourceUses) != 0 {
							t.Fatal("fixture did not bind one generated-only registry candidate")
						}
						code = bind(callctx, damageInstalledAutomaticCryptoCandidate(t, candidate, damage))
						if damage != "healthy" {
							// Retain the real result, but stop the coordinator before effects if admission is broken.
							return contract.CryptoInvalidAdmission
						}
						return code
					}
				}
				producer := callbacks.AdmitProducer
				callbacks.AdmitProducer = func(callctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedProducerInput, implementation contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
					target := stage == "producer" && in.Expected.Template.Action == contract.GeneratorActionDelete
					if target {
						prepare(callctx, &in.Session, in.Plan)
					}
					owner, err := producer(callctx, q, control, in, implementation, deadline)
					if target {
						admissionErr = err
						if err == nil {
							wrap(&owner.InstalledGeneratedCustody)
						}
					}
					return owner, err
				}
				adoption := callbacks.AdmitAdoption
				callbacks.AdmitAdoption = func(callctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedAdoptionInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
					target := stage == "adoption" && in.Result.Expected.Template.Action == contract.GeneratorActionDelete
					if target {
						prepare(callctx, &in.Session, in.Plan)
					}
					owner, err := adoption(callctx, q, control, in, deadline)
					if target {
						admissionErr = err
						if err == nil {
							wrap(owner)
						}
					}
					return owner, err
				}
				engine := installedGeneratedTestEngine(t, ctx, f, before, input, currentApplyRecipients(before.registry()), callbacks)
				got := engine.Apply(ctx, testID("automatic witness rotation "+stage+damage), input)
				engine.Close()
				if admitted != 1 || selectedRevision.IsZero() {
					t.Fatal("rotation did not reach actual post-selection Crypto admission", got.Result, admitted)
				}
				creates, deletes := effects()
				if damage == "healthy" {
					if admissionErr != nil || bound != 1 || code != contract.CryptoSuccess || got.Result.Outcome != ObservedCurrent || len(got.Receipt) == 0 || creates != 2 || len(deletes) != 1 {
						t.Fatal("unchanged post-selection candidate did not complete", admissionErr, bound, code, got.Result, creates, deletes)
					}
					return
				}
				if admissionErr == nil && (bound != 1 || code != contract.CryptoInvalidAdmission) {
					t.Error("changed anchor with omitted witness escaped Crypto", bound, code, got.Result)
				}
				if store.creates != createsBefore || store.cas != casBefore || trust.signs != signsBefore || creates != providerCreatesBefore || len(deletes) != deletesBefore {
					t.Fatal("damaged automatic admission entered effects", store.creates-createsBefore, store.cas-casBefore,
						trust.signs-signsBefore, creates-providerCreatesBefore, len(deletes)-deletesBefore)
				}
				cold := f.open(t, ctx)
				if cold.head.Core.Revision != selectedRevision || len(got.Receipt) != 0 {
					t.Fatal("damaged automatic admission changed exact selected predecessor", got.Result)
				}
			})
		}
	}
}

// full_only: false
func TestInstalledGeneratedAutomaticRetirementAfterOriginalSealReduction(t *testing.T) {
	for _, stop := range []string{"before-delete", "after-delete"} {
		t.Run(stop, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			process, effects := installedGeneratedRetirementProcess(t, "acknowledged")
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, true)
			f.env.GeneratedProcess = process
			authority, reader := f.selected.admission.recipient, fixtureID(f.env.Domain, "reader")
			members := []contract.ID{authority, reader}
			slices.SortFunc(members, compareGeneratedIDs)
			original := suppliedSecret(t, f.env, "secret", "automatic original shared seal", custody.StandardValue, members...)
			generation := &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged, RetirementMode: contract.GeneratedRetirementManual,
				ConfigContractID: process.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(), CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent)}
			input := []ApplyEntryInput{{Name: "generated", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{authority}, Generated: generation}, original}
			initial := installedGeneratedTestEngine(t, ctx, f, f.selected, input, currentApplyRecipients(f.selected.registry()), installedGeneratedRetirementCallbacks(t, f, process))
			first := initial.Apply(ctx, testID("shared original seal initial "+stop), input)
			initial.Close()
			if first.Result.Outcome != ObservedCurrent || len(first.Receipt) == 0 {
				t.Fatal("shared predecessor did not complete", first.Result)
			}
			before := f.open(t, ctx)
			oldSecret := sessionConsumerSelection(t, before, authority, "secret")
			_, oldGenerated := observeCurrentValueEntry(t, before, "generated")
			oldToken := generatedEntryProviderToken(t, before, oldGenerated)
			generation.Epoch, generation.RetirementMode = 1, contract.GeneratedRetirementAuto
			input[1].Recipients = []contract.ID{authority}
			callbacks := installedGeneratedRetirementCallbacks(t, f, process)
			producer := callbacks.AdmitProducer
			callbacks.AdmitProducer = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedProducerInput, implementation contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
				if stop == "before-delete" && in.Expected.Template.Action == contract.GeneratorActionDelete {
					return nil, contract.ErrRecord
				}
				return producer(ctx, q, control, in, implementation, deadline)
			}
			adoption := callbacks.AdmitAdoption
			callbacks.AdmitAdoption = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedAdoptionInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
				if stop == "after-delete" && in.Result.Expected.Template.Action == contract.GeneratorActionDelete {
					return nil, contract.ErrRecord
				}
				return adoption(ctx, q, control, in, deadline)
			}
			engine := installedGeneratedTestEngine(t, ctx, f, before, input, currentApplyRecipients(before.registry()), callbacks)
			stopped := engine.Apply(ctx, testID("original seal automatic rotation "+stop), input)
			engine.Close()
			selected := f.open(t, ctx)
			work := mustSelectedGeneratedWork(t, selected)
			if !generatedSelectionAnchored(work) || stopped.OperationID.IsZero() || selected.root.Generated.ActiveOwner != stopped.OperationID || len(stopped.Receipt) != 0 {
				t.Fatal("automatic stop lost the selected successor or parent", stopped.Result)
			}
			_, successor := observeCurrentValueEntry(t, selected, "generated")
			secret := sessionConsumerSelection(t, selected, authority, "secret")
			if successor.Generated.Epoch != 1 || successor.Generated.GenerationID == oldGenerated.Generated.GenerationID || successor.Generated.OriginOperationID != stopped.OperationID ||
				!slices.Equal(secret.Entry.Recipients, []contract.ID{authority}) || !slices.Equal(scenarioAccessRecipients(secret.Access), []contract.ID{authority}) || len(secret.Access.Wraps) != 2 {
				t.Fatal("canonical selection did not complete rotation and exact exclusion")
			}
			assertFreshSecretValue(t, &oldSecret.Entry, &secret.Entry, true)
			creates, deletes := effects()
			wantDeletes := 0
			if stop == "after-delete" {
				wantDeletes = 1
			}
			if creates != 2 || len(deletes) != wantDeletes || len(deletes) == 1 && deletes[0] != oldToken {
				t.Fatal("automatic stop did not retain exact send progress", creates, deletes)
			}
			callbacks = installedGeneratedRetirementCallbacks(t, f, process)
			producer = callbacks.AdmitProducer
			injected := 0
			callbacks.AdmitProducer = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedProducerInput, implementation contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
				if in.Expected.Template.Action == contract.GeneratorActionDelete {
					if in.Session.SelectionPhase == nil || in.Session.SelectionPhase.SelectionPhaseID.IsZero() || len(in.Plan.CurrentValues) != 0 {
						t.Fatal("automatic admission reopened original current-value sources")
					}
					graph, err := contract.DecodeGeneratorPlanBundle(in.Session.Graph)
					if err != nil || len(graph.SourceUses) == 0 {
						t.Fatal("original sealed fixture has no original source use", err)
					}
					for _, source := range []string{"current-value", "canonical", "live-source"} {
						bad := in
						switch source {
						case "current-value":
							bad.Plan.CurrentValues = []contract.ConsumerSelection{oldSecret}
						case "canonical":
							bad.Plan.Canonical = []contract.GeneratedCanonicalSelection{{Selection: oldSecret}}
						case "live-source":
							bad.Plan.LiveSourceUses = graph.SourceUses[:1]
						}
						owner, err := producer(ctx, q, control, bad, implementation, deadline)
						if owner != nil {
							owner.Close()
						}
						if err == nil {
							t.Fatal("automatic admission accepted an injected original source", source)
						}
						injected++
					}
				}
				return producer(ctx, q, control, in, implementation, deadline)
			}
			continued := installedGeneratedTestEngine(t, ctx, f, selected, input, currentApplyRecipients(selected.registry()), callbacks)
			got := continued.Continue(ctx, testID("cold original seal retirement "+stop), stopped.OperationID)
			continued.Close()
			creates, deletes = effects()
			if got.Result.Outcome != ObservedCurrent || got.Generated == nil || got.Generated.StateResult != "success" || len(got.Receipt) == 0 || creates != 2 || !slices.Equal(deletes, []string{oldToken}) || stop == "before-delete" && injected != 3 {
				t.Fatal("cold automatic retirement failed or repeated a consumed send", got.Result, creates, deletes, injected)
			}
			closed := f.open(t, ctx)
			_, current := observeCurrentValueEntry(t, closed, "generated")
			want := successor
			want.Generated.RetiringDutyPresent, want.Generated.RetiringDutyID = 0, contract.ID{}
			if !reflect.DeepEqual(current, want) || !reflect.DeepEqual(sessionConsumerSelection(t, closed, authority, "secret").Entry, secret.Entry) ||
				!reflect.DeepEqual(sessionConsumerSelection(t, closed, authority, "secret").Access, secret.Access) || !closed.root.Generated.ActiveOwner.IsZero() || closed.root.Generated.Duties != 0 {
				t.Fatal("terminal automatic retirement changed current values/access or kept its slot")
			}
			if selection, result := closed.admitConsumerSelection(ctx, []string{"secret"}, reader); selection != nil || result.Outcome != AdmissionRefused {
				t.Fatal("excluded reader retained current access")
			}
			for _, name := range []string{"secret", "generated"} {
				choice := uint8(custody.StandardValue)
				if name == "generated" {
					choice = custody.HermeticCloudflareValue
				}
				if check := f.keys.Consume(ctx, sessionConsumerSelection(t, closed, authority, name), choice); check.Code != contract.CryptoSuccess || !check.ValueMatched {
					t.Fatal("retirement changed selected secret bytes", name, check)
				}
			}
			receipt, err := contract.InspectCompactMutationReceipt(got.Receipt)
			if err != nil || receipt.OperationID != stopped.OperationID || receipt.RequestIdentityDigest != stopped.RequestIdentity || receipt.OperationKind != contract.OperationApplyDeclaration ||
				receipt.CanonicalOutcome != contract.ReceiptCanonicalSelected || receipt.StateResult != contract.ReceiptStateSuccess || receipt.SummaryCounts[contract.ReceiptEffectCount] != 2 || receipt.SummaryCounts[contract.ReceiptSummarySuccessCount] != 2 || receipt.SummaryCounts[contract.ReceiptDutyCount] != 0 || receipt.SummaryCounts[contract.ReceiptHazardCount] != 0 {
				t.Fatal("automatic retirement receipt differs from exact entered create/delete facts", err)
			}
			nextInput := installedApplyCurrentInput(closed)
			for i := range nextInput {
				if nextInput[i].Name == "generated" {
					nextInput[i].Generated = generation
				}
			}
			nextInput = append(nextInput, ApplyEntryInput{Name: "next", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{authority}, InputBytes: []byte("after automatic retirement"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
			next := installedGeneratedTestEngine(t, ctx, f, closed, nextInput, currentApplyRecipients(closed.registry()), installedGeneratedRetirementCallbacks(t, f, process))
			progress := next.Apply(ctx, testID("mutation after original seal retirement "+stop), nextInput)
			next.Close()
			creates, deletes = effects()
			if progress.Result.Outcome != ObservedCurrent || len(progress.Receipt) == 0 || creates != 2 || !slices.Equal(deletes, []string{oldToken}) {
				t.Fatal("automatic retirement blocked the next permitted mutation or repeated effects", progress.Result)
			}
			_, afterProgress := observeCurrentValueEntry(t, f.open(t, ctx), "generated")
			if !reflect.DeepEqual(afterProgress, current) {
				t.Fatal("next permitted mutation changed the selected generated entry")
			}
		})
	}
}

package compositionfull

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestMaintenancePlanningCallbackKeepsQualifiedControlAfterSourceRelease(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			source := configurationMaintenancePair(t, family, configuration.JSON, nil)
			model, installed, _, ok := configurationAccessMutationSource(ctx, contract.ID{77}, source.pair)
			if !ok {
				t.Fatal("source did not reach maintenance qualification")
			}
			request := configuration.MaintenanceRequest{OperationKind: contract.OperationEnvelopeRekey, Name: "first"}
			output := maintenanceAdapterTestOutput(t, ctx, source.pair, request)
			defer func() {
				if err := output.Close(); err != nil {
					t.Error(err)
				}
			}()
			if err := configureMaintenanceOutput(ctx, source.pair, model, &installed, output, request); err != nil {
				t.Fatal(err)
			}
			admission := contract.PlanningAdmission{DomainID: model.DomainID, Control: installed.ExpectedControl,
				CredentialRoute: installed.Maintenance.CredentialRoute, Options: contract.PlanningOptions{Purpose: contract.PlanningEquality}}
			releaseConfigurationBasis(model)
			installed.PublicBasis = core.PublicBasis{}
			for name, change := range map[string]func(*contract.PlanningAdmission){
				"domain":             func(a *contract.PlanningAdmission) { a.DomainID[0] ^= 1 },
				"purpose":            func(a *contract.PlanningAdmission) { a.Options.Purpose = contract.PlanningDisplay },
				"credential route":   func(a *contract.PlanningAdmission) { a.CredentialRoute[0] ^= 1 },
				"store":              func(a *contract.PlanningAdmission) { a.Control.StoreID[0] ^= 1 },
				"signing resource":   func(a *contract.PlanningAdmission) { a.Control.NormalSigning.KeySelector += "/foreign" },
				"authority binding":  func(a *contract.PlanningAdmission) { a.Control.AuthorityKMSBinding.BindingSerial++ },
				"regressed progress": func(a *contract.PlanningAdmission) { a.Control.AccessGeneration = 0 },
			} {
				t.Run(name, func(t *testing.T) {
					changed := admission
					change(&changed)
					owner, err := installed.Maintenance.AdmitFeasibility(ctx, changed)
					if owner != nil || !errors.Is(err, contract.ErrRecord) {
						t.Fatal("changed callback premises reached credential or private construction", err)
					}
				})
			}
		})
	}
}

func maintenanceAdapterTestOutput(t *testing.T, ctx context.Context, pair *configuration.Pair, request configuration.MaintenanceRequest) *configuration.MaintenanceOutput {
	t.Helper()
	model, err := configuration.Parse(ctx, pair)
	if err != nil {
		t.Fatal(err)
	}
	if request.OperationKind == contract.OperationRetireRecipientIdentity {
		reference := request.RecipientReference
		recipient, err := configurationRecipientReference(model, reference)
		if err != nil {
			reference = model.Recipients[0].Reference
			recipient, err = configurationRecipientReference(model, reference)
		}
		if err != nil {
			t.Fatal(err)
		}
		request.RecipientReference, request.RecipientID, request.BindingDigest = reference, recipient.RecipientID, recipient.PublicBindingDigest
	}
	capture, err := configuration.CaptureMaintenanceOutput(ctx, filepath.Join(t.TempDir(), "successor.json"), pair.Format)
	if err != nil {
		t.Fatal(err)
	}
	output, err := configuration.PrepareMaintenanceOutputFromCapture(ctx, pair, capture, request)
	if err != nil {
		if closeErr := capture.Close(); closeErr != nil {
			t.Error("maintenance output capture cleanup failed", closeErr)
		}
		t.Fatal(err)
	}
	return output
}

func rekeyConfigurationEnvelopeForTest(t *testing.T, tctx context.Context, request contract.ID, pair *configuration.Pair, name string, open func(context.Context, *configuration.Model, core.EnvelopeRekeyInstallation) (configurationRekeyEngine, error)) core.PublicApplyResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	output := maintenanceAdapterTestOutput(t, ctx, pair, configuration.MaintenanceRequest{OperationKind: contract.OperationEnvelopeRekey, Name: name})
	defer func() {
		if err := output.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	return rekeyConfigurationEnvelope(tctx, request, pair, name, output, open)
}

func retireConfigurationRecipientForTest(t *testing.T, tctx context.Context, request contract.ID, pair *configuration.Pair, reference string, open func(context.Context, *configuration.Model, core.RecipientRetirementInstallation) (configurationRetirementEngine, error)) core.PublicApplyResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	output := maintenanceAdapterTestOutput(t, ctx, pair, configuration.MaintenanceRequest{OperationKind: contract.OperationRetireRecipientIdentity, RecipientReference: reference})
	defer func() {
		if err := output.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	return retireConfigurationRecipient(tctx, request, pair, reference, output, open)
}

// full_only: false
func TestMaintenanceAdaptersRequireOutputBeforePrivateConstruction(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	source := configurationApplyPair(t, "aws", configuration.JSON, nil)
	model, err := configuration.Parse(ctx, source.pair)
	if err != nil {
		t.Fatal(err)
	}
	rekey := rekeyConfigurationEnvelope(ctx, contract.ID{77}, source.pair, "secret", nil, func(context.Context, *configuration.Model, core.EnvelopeRekeyInstallation) (configurationRekeyEngine, error) {
		t.Fatal("missing output reached rekey constructor")
		return nil, ErrCell
	})
	retire := retireConfigurationRecipient(ctx, contract.ID{77}, source.pair, model.Recipients[0].Reference, nil, func(context.Context, *configuration.Model, core.RecipientRetirementInstallation) (configurationRetirementEngine, error) {
		t.Fatal("missing output reached retirement constructor")
		return nil, ErrCell
	})
	for index, result := range []core.PublicApplyResult{rekey, retire} {
		if result.Result.Outcome != core.AdmissionRefused || result.PreAdmission == nil || result.PreAdmission.Stage != "output" {
			t.Fatal("missing output lost safe refusal")
		}
		kind := uint16(contract.OperationEnvelopeRekey)
		if index == 1 {
			kind = contract.OperationRetireRecipientIdentity
		}
		for _, render := range []func(uint16, MaintenanceCommandResult) ([]byte, error){RenderMaintenanceCommandJSON, RenderMaintenanceCommandHuman} {
			if _, err := render(kind, MaintenanceCommandResult{PublicApplyResult: result, Delivery: ReplacementCommandDelivery{Status: "not-attempted"}, SourceUsability: "unchecked"}); err != nil {
				t.Fatal("mandatory output refusal cannot be delivered safely", err)
			}
		}
	}

	for _, result := range []MaintenanceCommandResult{
		RekeyConfigurationEnvelopeFile(ctx, contract.ID{77}, "/missing/source.json", configuration.JSON, "secret", ""),
		RetireConfigurationRecipientFile(ctx, contract.ID{77}, "/missing/source.json", configuration.JSON, "recipient", "")} {
		if result.Result.Outcome != core.AdmissionRefused || result.PreAdmission == nil || result.PreAdmission.Stage != "dispatch" || result.Delivery.Status != "not-attempted" || result.SourceUsability != "unchecked" {
			t.Fatal("file adapter captured source without output admission")
		}
	}
}

func maintenanceTestSourceImage(t *testing.T, ctx context.Context, pair *configuration.Pair) map[string]configurationApplyFileImage {
	t.Helper()
	// Pair publication uses persistent native coordination files. Prepare them
	// before the exact source-inventory assertion begins.
	output := maintenanceAdapterTestOutput(t, ctx, pair, configuration.MaintenanceRequest{OperationKind: contract.OperationEnvelopeRekey})
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	return configurationApplySourceImage(t, filepath.Dir(pair.Editable.OriginalPath()))
}

// full_only: false
func TestMaintenanceAdaptersRefuseOutputTransplantsBeforePrivateConstruction(t *testing.T) {
	for _, condition := range []string{"target", "source", "operation"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			source := configurationMaintenancePair(t, "aws", configuration.JSON, nil)
			output := maintenanceAdapterTestOutput(t, ctx, source.pair, configuration.MaintenanceRequest{OperationKind: contract.OperationEnvelopeRekey, Name: "first"})
			defer func() {
				if err := output.Close(); err != nil {
					t.Fatal(err)
				}
			}()
			pair, name := source.pair, "first"
			if condition == "source" {
				other := configurationMaintenancePair(t, "aws", configuration.JSON, func(editable, generated map[string]any) {
					editable["domain"].(map[string]any)["authority"].(map[string]any)["display_name"] = "different source bytes"
				})
				pair = other.pair
			}
			if condition == "target" {
				name = "second"
			}
			called := false
			var result core.PublicApplyResult
			if condition == "operation" {
				model, err := configuration.Parse(ctx, pair)
				if err != nil {
					t.Fatal(err)
				}
				result = retireConfigurationRecipient(ctx, contract.ID{77}, pair, model.Recipients[0].Reference, output, func(context.Context, *configuration.Model, core.RecipientRetirementInstallation) (configurationRetirementEngine, error) {
					called = true
					return nil, ErrCell
				})
			} else {
				result = rekeyConfigurationEnvelope(ctx, contract.ID{77}, pair, name, output, func(context.Context, *configuration.Model, core.EnvelopeRekeyInstallation) (configurationRekeyEngine, error) {
					called = true
					return nil, ErrCell
				})
			}
			if called || result.Result.Outcome != core.AdmissionRefused || result.PreAdmission == nil || result.PreAdmission.Stage != "output" {
				t.Fatalf("transplanted %s reached private construction=%t", condition, called)
			}
			kind := uint16(contract.OperationEnvelopeRekey)
			if condition == "operation" {
				kind = contract.OperationRetireRecipientIdentity
			}
			for _, render := range []func(uint16, MaintenanceCommandResult) ([]byte, error){RenderMaintenanceCommandJSON, RenderMaintenanceCommandHuman} {
				if _, err := render(kind, MaintenanceCommandResult{PublicApplyResult: result, Delivery: ReplacementCommandDelivery{Status: "not-attempted"}, SourceUsability: "unchecked"}); err != nil {
					t.Fatal("output boundary refusal cannot be delivered safely", err)
				}
			}
		})
	}
}

func configurationMaintenancePair(t *testing.T, family string, encoding configuration.Format, edit func(map[string]any, map[string]any)) configurationReaderSource {
	t.Helper()
	source := configurationApplyPair(t, family, encoding, edit)
	if err := source.pair.Close(); err != nil {
		t.Fatal(err)
	}
	// Native coordination files are installed before recapture. The source
	// files and their directories then remain read-only for the invocation.
	configurationSetWritable(t, source)
	for _, path := range []string{source.path, source.generated} {
		for _, name := range []string{".enkv-locks", ".enkv-pending"} {
			if err := os.Mkdir(filepath.Join(filepath.Dir(path), name), 0700); err != nil {
				t.Fatal(err)
			}
		}
		lock := filepath.Join(filepath.Dir(path), ".enkv-locks", filepath.Base(path))
		if err := os.WriteFile(lock, nil, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0444); err != nil {
			t.Fatal(err)
		}
	}
	for _, directory := range []string{filepath.Dir(source.path), filepath.Dir(source.generated)} {
		if err := os.Chmod(directory, 0555); err != nil {
			t.Fatal(err)
		}
	}
	pair, err := configuration.Capture(t.Context(), source.path, encoding)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pair.Close(); err != nil {
			t.Error(err)
		}
	})
	source.pair = pair
	return source
}

// full_only: false
func TestMaintenanceReadbackSeparatesSourceMetadataFromReopenedOutputPins(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	source := configurationMaintenancePair(t, "aws", configuration.JSON, nil)
	model, err := configuration.Parse(ctx, source.pair)
	if err != nil {
		t.Fatal(err)
	}
	parts, err := source.archive.SelectedParts()
	if err != nil {
		t.Fatal(err)
	}
	var head format.Head
	for _, part := range parts {
		if part.Kind == "HEAD" {
			head, err = format.DecodeHead(part.Body)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	recipient := model.Recipients[0]
	binding, err := configurationApplyBinding(model.Provider, recipient.Encryption)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := contract.PublicBindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	retired, err := contract.NewRecipientRetirementRow(1, contract.RecipientRecord{RecipientID: recipient.ID, Status: contract.CurrentRecipient, DisplayName: recipient.DisplayName, CurrentBinding: &binding})
	if err != nil {
		t.Fatal(err)
	}
	retirements, err := contract.RetirementDescriptor(model.DomainID, []contract.RecipientRetirementRow{retired})
	if err != nil {
		t.Fatal(err)
	}
	authority, err := configurationApplyBinding(model.Provider, model.Authority.Encryption)
	if err != nil {
		t.Fatal(err)
	}
	coreBytes, err := format.EncodeHeadCore(head.Core)
	if err != nil {
		t.Fatal(err)
	}
	condition, err := contract.MatchHeadCondition(head.Core.PreviousToken)
	if err != nil {
		t.Fatal(err)
	}
	conditional, err := format.EncodeConditionalPlan(format.ConditionalPlan{Family: head.Core.PreviousToken.Family, Store: head.Core.Store, Coordinate: head.Core.Coordinate, NonBody: head.Core.NonBody, Condition: condition, HeadCore: contract.Hash(coreBytes), HeadCoreLength: uint32(len(coreBytes))})
	if err != nil {
		t.Fatal(err)
	}
	id := func(n byte) contract.ID { return contract.ID{n} }
	// A structural candidate is sufficient for this mapping test. Core's tests
	// separately authenticate the signed candidate and callback correlations.
	subject := contract.LifecycleSubject{OperationKind: contract.OperationRetireRecipientIdentity, Operation: id(25), Request: id(26), Recipient: model.Authority.ID, KeyBinding: authority.BindingID, Fingerprint: authority.Fingerprint, BindingVersion: 1, IdentityPlan: contract.DigestLength{Digest: id(27), Length: 197}, HeadCore: contract.Hash(coreBytes), HeadCoreLength: uint32(len(coreBytes)), ConditionalPlan: contract.Hash(conditional), BeforeValueEntryCount: 1, AfterValueEntryCount: 1, BeforeRawBytes: 5, AfterRawBytes: 5, BeforeAccessRoot: id(28), AfterAccessRoot: id(29), BeforeMembershipCount: 1, AfterMembershipCount: 1, Normal: contract.NormalSection{Intent: contract.DigestLength{Digest: id(30), Length: 1002}, PublicState: contract.DigestLength{Digest: id(31), Length: 187}, Union: contract.DescriptorVector{Digest: id(32), Length: 282, Count: 1}}, Grant: contract.GrantSection{Grants: contract.DescriptorVector{Digest: id(33), Length: 61}}, Exclusion: contract.ExclusionSection{Exclusions: contract.DescriptorVector{Digest: id(34), Length: 65}, Retirements: retirements}}
	signature := []byte{0x30, 6, 2, 1, 1, 2, 1, 1}
	candidate, err := format.EncodeHead(format.Head{Core: head.Core, AuthKind: format.LifecycleAuth, Subject: subject, K1: signature, AuthorizationSignature: signature})
	if err != nil {
		t.Fatal(err)
	}
	sourcePins, err := replacementObservationPins(source.pair, model)
	if err != nil {
		t.Fatal(err)
	}
	metadataSource := configuration.SourcePairIdentity{Format: configuration.JSON, Editable: contract.DigestLength{Digest: id(90), Length: 83}, Generated: contract.DigestLength{Digest: id(91), Length: 84}}
	model.Maintenance = &configuration.MaintenanceMetadata{Request: configuration.MaintenanceRequest{OperationKind: contract.OperationRetireRecipientIdentity, RecipientReference: recipient.Reference, RecipientID: recipient.ID, BindingDigest: digest}, Source: metadataSource, FileID: model.FileID, OutputPath: source.path, RequestIdentity: id(37), RequestCoreDigest: subject.Request, OperationID: subject.Operation, SignedCandidate: candidate, Retirement: &retired}
	mapped, err := maintenanceReadback(ctx, source.pair, &configuration.SuccessorReadback{Pair: source.pair, Model: model}, source.path, nil, source.pair.CheckUnchanged)
	if err != nil {
		t.Fatal(err)
	}
	if mapped.SourcePins == sourcePins || mapped.SourcePins.EditableDigest != metadataSource.Editable.Digest || mapped.SourcePins.GeneratedDigest != metadataSource.Generated.Digest || mapped.SourcePins.EditableLength != 83 || mapped.SourcePins.GeneratedLength != 84 {
		t.Fatal("readback replaced metadata source with captured factory source pins")
	}
	editableHash, generatedHash := sha256.Sum256(source.editableBytes), sha256.Sum256(source.generatedBytes)
	if mapped.OutputPins.EditableDigest != contract.ID(editableHash) || mapped.OutputPins.GeneratedDigest != contract.ID(generatedHash) || mapped.OutputPins.EditableLength != uint64(len(source.editableBytes)) || mapped.OutputPins.GeneratedLength != uint64(len(source.generatedBytes)) || mapped.OutputPins.EditableDigest == metadataSource.Editable.Digest {
		t.Fatal("output pins were not independently derived from the exact reopened pair")
	}
}

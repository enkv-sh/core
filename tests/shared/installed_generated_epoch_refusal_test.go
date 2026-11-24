package core

import (
	"bytes"
	"context"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// full_only: false
func TestInstalledGeneratedEpochConflictsRefuseBeforeAnyProducer(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f, selected, current, effects := installedGeneratedRetirementFixture(t, ctx, "acknowledged")
	process := f.env.GeneratedProcess
	implementation := process.Implementation
	changedIntent, _ := cloudflareIntent(hermeticCloudflareAccount, hermeticCloudflarePermission, "changed")
	validator := NewPublicConfigurationValidator(nil)
	for _, condition := range []struct {
		name       string
		epoch      uint64
		intent     []byte
		retirement uint8
		reason     Reason
	}{
		{name: "lower-epoch", epoch: 0, intent: process.Intent, retirement: contract.GeneratedRetirementManual, reason: StaleGeneratedEpoch},
		{name: "same-epoch-changed-intent", epoch: 1, intent: changedIntent, retirement: contract.GeneratedRetirementManual, reason: GeneratedIntentConflict},
		{name: "same-epoch-changed-retirement-policy", epoch: 1, intent: process.Intent, retirement: contract.GeneratedRetirementAuto, reason: GeneratedIntentConflict},
	} {
		for _, mixed := range []bool{false, true} {
			name := condition.name
			if mixed {
				name += "/later-mixed-entry"
			}
			t.Run(name, func(t *testing.T) {
				meta := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Epoch: condition.epoch, RetirementMode: condition.retirement,
					ConfigContractID: implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(), CompletionClass: current.Generated.CompletionClass, Intent: bytes.Clone(condition.intent)}
				input := selected.currentEntryInputs()
				at := slices.IndexFunc(input, func(entry ApplyEntryInput) bool { return entry.Name == "generated" })
				if at < 0 || current.Generated.Epoch != 1 {
					t.Fatal("fixture must have an authenticated generated entry at epoch one")
				}
				input[at].InputBytes, input[at].Generated = nil, &meta
				if mixed {
					fresh := meta
					fresh.Epoch, fresh.Intent = 0, bytes.Clone(process.Intent)
					fresh.RetirementMode = contract.GeneratedRetirementManual
					input = append([]ApplyEntryInput{{Name: "aaa-new-generated", Recipients: slices.Clone(current.Recipients),
						ValueSource: contract.Generated, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ConfidentialityClass: contract.Secret, Generated: &fresh}}, input...)
				}
				desired := currentApplyRecipients(selected.registry())
				configuration := installedApplyTestConfiguration(t, ctx, selected, input, desired, validator)
				for at := range configuration.Entries.Value {
					row := &configuration.Entries.Value[at]
					entry := input[at]
					if entry.Generated == nil {
						continue
					}
					g := entry.Generated
					row.Generated = installedGeneratedPublicSettings(g)
				}
				var privateCalls, generatorCalls int
				callbacks := installedGeneratedTestCallbacks(t, f, process)
				callbacks.RequestDigest = func(context.Context, contract.GeneratorImplementation, uint8, []byte, *contract.GeneratorTarget) (contract.ID, error) {
					generatorCalls++
					return contract.ID{}, contract.ErrRecord
				}
				engine, err := NewInstalledApply(ApplyInstallation{ExpectedDomain: f.env.Domain, ExpectedStore: f.env.Store.Descriptor(),
					PublicBasis: f.basis, ExpectedControl: currentControlOf(selected), DesiredRecipients: desired,
					GeneratorImplementations: []contract.GeneratorImplementation{implementation}, Generated: callbacks,
					PublicConfiguration: configuration, ConfigurationValidator: validator, Store: f.env.Store, Trust: f.env.Trust,
					CompositionID: f.composition, FileIdentity: fixtureID(f.env.Domain, "source-file"), CloseInstalled: func() {},
					AdmitCustody: func(context.Context, contract.CryptoCompareRequest, contract.ControlCore, []contract.RecipientRecord,
						[]contract.MembershipRow, contract.DescriptorVector, *contract.GeneratedSupportTransition, contract.ID,
						contract.MutationReceiptWindows, uint8, time.Time) (*InstalledApplyCustody, error) {
						privateCalls++
						return nil, contract.ErrRecord
					}})
				if err != nil {
					t.Fatal(err)
				}
				defer engine.Close()
				creates, deletes := effects()
				store := requireAdmittedMemoryStore(t, f.env.Store)
				writes, cas := store.creates, store.cas
				recorder := telemetry.NewRecorder()
				observed := telemetry.WithCapability(ctx, telemetry.NewCapability(nil, recorder))
				result := engine.Apply(observed, testID("generated epoch conflict "+name), input)
				if result.Result != refused(condition.reason) {
					t.Errorf("epoch conflict returned %v; want exact refusal %v", result.Result, refused(condition.reason))
				}
				if result.Generated != nil || result.Payload != nil || len(result.Receipt) != 0 {
					t.Error("epoch refusal returned accepted generated work or transition evidence")
				}
				returns := 0
				var batch [32]telemetry.DiagnosticRecord
				for records := recorder.Drain(batch[:0]); len(records) != 0; records = recorder.Drain(batch[:0]) {
					for _, record := range records {
						if record.Operation == telemetry.OpCoreApply && record.Event == telemetry.DiagnosticReturn {
							returns++
							if record.Result != telemetry.ResultAdmissionRefused || record.Reason != telemetry.DiagnosticReasonInvalidIntent || record.Validate() != nil {
								t.Error("epoch refusal lost its known invalid-intent diagnostic category", record)
							}
						}
					}
				}
				if returns != 1 {
					t.Error("epoch refusal must emit exactly one apply return diagnostic", returns)
				}
				laterCreates, laterDeletes := effects()
				if laterCreates != creates || !slices.Equal(laterDeletes, deletes) || privateCalls != 0 || generatorCalls != 0 || store.creates != writes || store.cas != cas {
					t.Error("epoch refusal reached private admission, generator planning or provider mutation", privateCalls, generatorCalls, laterCreates, laterDeletes)
				}
				if after := f.open(t, ctx); !bytes.Equal(after.body, selected.body) {
					t.Error("epoch refusal changed the authenticated selection")
				}
			})
		}
	}
}

package core

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// The installed fixture owns immutable synthetic pair bytes. Native file
// delivery and reread are exercised by the configuration and process tests.
func installedMaintenanceTestInstallation(t testing.TB, f installedApplyTestFixture, selected *StateSession, validator *PublicConfigurationValidator, sourceInputs ...contract.PlanningInput) *MaintenanceInstallation {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	public := installedApplyPassiveConfiguration(t, ctx, selected, validator)
	// Raw source declares destinations, encodings and routing. Selected-state
	// projection also materializes derived targets, which are not source offers.
	for i := range public.OutputBindings.Value {
		public.OutputBindings.Value[i].Targets = contract.PublicField[[]contract.PublicOutputTarget]{State: contract.PublicUnavailable}
	}
	recipients := installedApplyPassiveRecipients(selected)
	var inputs []contract.PlanningInput
	for _, entry := range installedApplyCurrentInput(selected) {
		if entry.ValueSource != contract.Supplied || entry.ConfidentialityClass != contract.Secret {
			continue
		}
		if entry.Retained == nil {
			t.Fatal("maintenance fixture lost exact retained input")
		}
		inputs = append(inputs, contract.PlanningInput{Name: entry.Name, Form: contract.PlanningRetained, Retained: *entry.Retained})
	}
	if sourceInputs != nil {
		inputs = sourceInputs
	}
	digest, err := PlanningInputDigest(public, inputs)
	if err != nil {
		t.Fatal(err)
	}
	editable := []byte("installed maintenance captured editable")
	generated := []byte("installed maintenance captured generated")
	pins := AdministrativeSourcePins{FileID: fixtureID(f.env.Domain, "maintenance file"), Format: 2, EditableDigest: contract.Hash(editable), EditableLength: uint64(len(editable)), GeneratedDigest: contract.Hash(generated), GeneratedLength: uint64(len(generated)), HasGenerated: true}
	for _, input := range inputs {
		if input.Form == contract.PlanningSealed {
			view, err := contract.InspectSealedInputEnvelope(input.SealedInput)
			if err != nil {
				t.Fatal(err)
			}
			pins.FileID = view.Core.FileIdentity
			break
		}
	}
	installation := &MaintenanceInstallation{SourcePins: pins, OutputPath: filepath.Join(t.TempDir(), "maintenance.json"), InputDigest: digest, Configuration: public, Inputs: inputs, Recipients: recipients,
		CredentialRoute: f.keys.PlanningCredentialRoute(), SourceUnchanged: func(ctx context.Context) error { return ctx.Err() },
		AdmitFeasibility: func(context.Context, contract.PlanningAdmission) (PlanningCustody, error) {
			return nil, contract.ErrRecord
		}}
	installation.PublishSuccessor = func(ctx context.Context, successor MaintenanceSuccessor) (MaintenanceReadback, error) {
		if err := ctx.Err(); err != nil {
			return MaintenanceReadback{}, err
		}
		configuration := ownPublicConfiguration(public)
		outputInputs := slices.Clone(inputs)
		outputRecipients := slices.Clone(recipients)
		if successor.OperationKind == contract.OperationRetireRecipientIdentity {
			retired := successor.Recipient.RecipientID
			configuration.Recipients.Value = slices.DeleteFunc(configuration.Recipients.Value, func(row contract.PublicRecipient) bool { return row.RecipientID == retired })
			for i := range configuration.Entries.Value {
				row := &configuration.Entries.Value[i]
				row.Memberships.Value = slices.DeleteFunc(row.Memberships.Value, func(id contract.ID) bool { return id == retired })
			}

			outputRecipients = slices.DeleteFunc(outputRecipients, func(row contract.ApplyRecipientInput) bool { return row.Recipient.RecipientID == retired })
		}
		for _, delta := range successor.PinDeltas {
			found := false
			for i := range outputInputs {
				if outputInputs[i].Name == delta.Name {
					if outputInputs[i].Form == contract.PlanningRetained && outputInputs[i].Retained != delta.Before {
						return MaintenanceReadback{}, contract.ErrRecord
					}
					if outputInputs[i].Form == contract.PlanningRetained {
						outputInputs[i].Retained = delta.After
					}
					found = true
				}
			}
			if !found {
				return MaintenanceReadback{}, contract.ErrRecord
			}
		}
		body, err := json.Marshal(struct {
			Public    contract.PublicConfiguration
			Inputs    []contract.PlanningInput
			Candidate MaintenanceSuccessor
		}{configuration, outputInputs, successor})
		if err != nil {
			return MaintenanceReadback{}, err
		}
		outputPins := pins
		outputPins.EditableDigest = contract.Hash(body)
		outputPins.EditableLength = uint64(len(body))
		candidateBody, err := json.Marshal(successor)
		if err != nil {
			return MaintenanceReadback{}, err
		}
		outputPins.GeneratedDigest = contract.Hash(candidateBody)
		outputPins.GeneratedLength = uint64(len(candidateBody))
		return MaintenanceReadback{SourcePins: pins, OutputPins: outputPins, OutputPath: installation.OutputPath, Basis: f.basis, Configuration: configuration, Inputs: outputInputs, Recipients: outputRecipients, Correlation: successor}, nil
	}
	return installation
}

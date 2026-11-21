package compositionfull

import (
	"context"
	"encoding/binary"
	"errors"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func observeMaintenanceConfiguration(ctx context.Context, nonce contract.ID, source *configuration.Pair, output *configuration.MaintenanceOutput,
	open func(context.Context, *configuration.Model) (core.PublicSelectedReader, func() error, error)) (result core.PublicMaintenanceObservationResult, resultErr error) {
	if output == nil || output.Existing() == nil || output.Existing().Maintenance == nil || open == nil {
		return result, configuration.ErrEdit
	}
	result = maintenanceObservationRefusal(ctx, nonce, output.Existing().Maintenance.Request.OperationKind, output.Existing().Maintenance.Source.Format, "source", nil)
	baseline, err := configuration.Parse(ctx, source)
	if err != nil {
		return result, err
	}
	sourcePins, err := replacementObservationPins(source, baseline)
	if err != nil {
		return result, err
	}
	existing := output.Existing()
	identity, err := output.OutputIdentity()
	if err != nil {
		return result, err
	}
	pins := core.AdministrativeSourcePins{FileID: existing.FileID, Format: uint8(identity.Format), EditableDigest: identity.Editable.Digest, EditableLength: identity.Editable.Length, GeneratedDigest: identity.Generated.Digest, GeneratedLength: identity.Generated.Length, HasGenerated: true}
	basis, store, err := configurationPublicBasis(baseline)
	if err != nil {
		return result, err
	}
	apply, _, err := configurationApplyAccess(existing)
	if err != nil {
		return result, err
	}
	correlation, err := maintenanceCorrelation(existing)
	if err != nil {
		return result, err
	}
	result.Correlation = correlation
	if err := output.CheckUnchanged(ctx); err != nil {
		return result, err
	}
	result.PreAdmission.Stage = "construction"
	reader, close, err := open(ctx, baseline)
	if close != nil {
		defer func() { resultErr = errors.Join(resultErr, close()) }()
	}
	if err != nil || reader == nil {
		if reader != nil {
			reader.Close()
		}
		result.Result = core.Result{Outcome: core.EvidenceUnavailable, Reason: core.CustodyUnavailable}
		result.StateResult = contract.ReaderUnavailable
		result.PreAdmission.Code = string(contract.ReasonEvidenceUnavailable)
		return result, errors.Join(err, configuration.ErrEdit)
	}
	observer, err := core.NewInstalledMaintenanceObserver(core.MaintenanceObservationInstallation{ExpectedDomain: baseline.DomainID, ExpectedStore: store, PublicBasis: basis,
		SourcePins: sourcePins, OutputPins: pins, OutputPath: output.Path(), CompositionID: CompatibilityManifest().Identity, Correlation: correlation,
		Configuration: existing.Public, Inputs: configurationPlanningInputs(existing), Recipients: apply.DesiredRecipients, Source: reader, CheckSourceOutput: output.CheckUnchanged})
	if err != nil {
		reader.Close()
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, observer.Close()) }()
	observed := observer.Observe(ctx, nonce)
	if observed.OperationID.IsZero() {
		if observed.Result.Outcome != core.AdmissionRefused || observed.Query != nil || len(observed.Receipt) != 0 || observed.SourceUsabilityChecked || observed.CandidateCurrent {
			return result, configuration.ErrEdit
		}
		result.PreAdmission.Stage = "observation"
		result.PreAdmission.Code = configurationFailureCode(ctx, ctx.Err())
		return result, ctx.Err()
	}
	return observed, nil
}

func maintenanceObservationRefusal(ctx context.Context, nonce contract.ID, kind uint16, encoding configuration.Format, stage string, cause error) core.PublicMaintenanceObservationResult {
	body := append([]byte("ENKV/maintenance-read-pre-admission/v1\x00"), nonce[:]...)
	body = binary.BigEndian.AppendUint16(body, kind)
	return core.PublicMaintenanceObservationResult{RequestID: nonce, OperationID: contract.Hash(body), Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}, StateResult: contract.ReaderRefused, Correlation: core.MaintenanceSuccessor{OperationKind: kind}, PreAdmission: &core.PreAdmissionRequestIdentity{Stage: stage, Code: configurationFailureCode(ctx, cause), RequestNonce: nonce, SourceSchema: "enkv/configuration/v3", SourceProfile: "installed-public-maintenance", Format: configurationSourceFormat(encoding)}}
}

package compositionfull

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func replacementObservationTarget(target configuration.ReplacementTarget) (core.ReplacementTarget, bool) {
	return replacementCommandTarget(target)
}

// NewReplacementObservationRefusal retains a recognized protected target even
// when source capture or exact output admission cannot produce a query image.
func NewReplacementObservationRefusal(target core.ReplacementTarget, nonce contract.ID, encoding configuration.Format) (core.PublicReplacementObservationResult, error) {
	out := core.PublicReplacementObservationResult{Target: target, RequestID: nonce, Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.AdmissionInvalid}, StateResult: contract.ReaderRefused, PreAdmission: &core.PreAdmissionRequestIdentity{Stage: "capture", Code: string(contract.ReasonInvalidInput), SourceSchema: "enkv/configuration/v3", SourceProfile: "installed-public-replacement", Format: configurationSourceFormat(encoding), RequestNonce: nonce}}
	switch target {
	case core.ReplacementTargetAuthority:
		out.Operation = core.ReplacementObserve
		out.UnderlyingOperation = contract.OperationReplaceAuthorityKeys
	case core.ReplacementTargetRecovery:
		out.Operation = core.ReplacementReceipt
		out.UnderlyingOperation = contract.OperationReplaceRecoveryKeysAndRoot
	case core.ReplacementTargetRecipient:
		out.Operation = core.ReplacementReceipt
		out.UnderlyingOperation = contract.OperationRotateRecipientKeyBinding
	default:
		return out, errConfigurationReplacement
	}
	if nonce.IsZero() || encoding != configuration.JSON && encoding != configuration.YAML {
		return out, errConfigurationReplacement
	}
	body := append([]byte("ENKV/replacement-read-pre-admission/v1\x00"), nonce[:]...)
	body = append(body, byte(target))
	out.OperationID = contract.Hash(body)
	return out, nil
}

func replacementObservationPins(pair *configuration.Pair, m *configuration.Model) (core.AdministrativeSourcePins, error) {
	if pair == nil || pair.Editable == nil || pair.Generated == nil || m == nil || !m.Resolved {
		return core.AdministrativeSourcePins{}, errConfigurationReplacement
	}
	pins := core.AdministrativeSourcePins{FileID: m.FileID, Format: uint8(pair.Format), EditableDigest: contract.ID(pair.Editable.Digest()), GeneratedDigest: contract.ID(pair.Generated.Digest()), EditableLength: uint64(pair.Editable.Size()), GeneratedLength: uint64(pair.Generated.Size()), HasGenerated: true}
	if !pins.Valid() {
		return core.AdministrativeSourcePins{}, errConfigurationReplacement
	}
	return pins, nil
}

// ObserveReplacementConfiguration enters only the existing-output branch. It
// never resolves nominated keys or calls a fresh replacement constructor.
func ObserveReplacementConfiguration(ctx context.Context, nonce contract.ID, source *configuration.Pair, output *configuration.SuccessorOutput) (core.PublicReplacementObservationResult, error) {
	return observeReplacementConfiguration(ctx, nonce, source, output, defaultReplacementObservationSource)
}
func defaultReplacementObservationSource(ctx context.Context, m *configuration.Model) (core.PublicSelectedReader, func() error, error) {
	transport := &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	close := func() error { transport.CloseIdleConnections(); return nil }
	reader, err := openConfigurationPublicSource(ctx, m, transport)
	if err != nil {
		return nil, close, err
	}
	return reader, close, nil
}
func observeReplacementConfiguration(ctx context.Context, nonce contract.ID, source *configuration.Pair, output *configuration.SuccessorOutput, open func(context.Context, *configuration.Model) (core.PublicSelectedReader, func() error, error)) (core.PublicReplacementObservationResult, error) {
	result, _, err := observeReplacementConfigurationOwned(ctx, nonce, source, output, open)
	return result, err
}

func observeReplacementConfigurationOwned(ctx context.Context, nonce contract.ID, source *configuration.Pair, output *configuration.SuccessorOutput, open func(context.Context, *configuration.Model) (core.PublicSelectedReader, func() error, error)) (result core.PublicReplacementObservationResult, cleanupErr, resultErr error) {
	defer func() {
		if cleanupErr != nil {
			resultErr = errors.Join(resultErr, cleanupErr)
		}
	}()
	if output == nil || output.Existing() == nil || output.Existing().Replacement == nil {
		return result, nil, errConfigurationReplacement
	}
	existing := output.Existing()
	metadata := existing.Replacement
	target, known := replacementObservationTarget(metadata.Request.Target)
	if !known {
		return result, nil, errConfigurationReplacement
	}
	result, err := NewReplacementObservationRefusal(target, nonce, metadata.Source.Format)
	if err != nil {
		return result, nil, err
	}
	result.Correlation = core.ReplacementCorrelation{Target: target, RecipientID: metadata.RecipientID, RequestIdentity: metadata.RequestIdentity, SignedCandidate: bytes.Clone(metadata.SignedCandidate)}
	if ctx == nil || ctx.Err() != nil || open == nil {
		return result, nil, errConfigurationReplacement
	}
	if deadline, finite := ctx.Deadline(); !finite || !time.Now().Before(deadline) {
		return result, nil, errConfigurationReplacement
	}
	result.PreAdmission.Stage = "source"
	baseline, err := configuration.Parse(ctx, source)
	if err != nil {
		return result, nil, err
	}
	sourcePins, err := replacementObservationPins(source, baseline)
	if err != nil {
		return result, nil, err
	}
	if metadata.Source.Format != source.Format || metadata.Source.Editable != (contract.DigestLength{Digest: sourcePins.EditableDigest, Length: sourcePins.EditableLength}) || metadata.Source.Generated != (contract.DigestLength{Digest: sourcePins.GeneratedDigest, Length: sourcePins.GeneratedLength}) {
		return result, nil, errConfigurationReplacement
	}
	identity, err := output.OutputIdentity()
	if err != nil {
		return result, nil, err
	}
	outputPins := core.AdministrativeSourcePins{FileID: existing.FileID, Format: uint8(identity.Format), EditableDigest: identity.Editable.Digest, GeneratedDigest: identity.Generated.Digest, EditableLength: identity.Editable.Length, GeneratedLength: identity.Generated.Length, HasGenerated: true}
	sourceBasis, store, err := configurationPublicBasis(baseline)
	if err != nil {
		return result, nil, err
	}
	successorBasis, successorStore, err := configurationPublicBasis(existing)
	if err != nil || successorStore != store {
		return result, nil, errors.Join(err, errConfigurationReplacement)
	}
	before, err := sourceBasis.ControlCore(baseline.DomainID, store)
	if err != nil || !configurationReplacementRoleFacts(baseline, before) {
		return result, nil, errors.Join(err, errConfigurationReplacement)
	}
	after, err := successorBasis.ControlCore(existing.DomainID, store)
	if err != nil || !configurationReplacementRoleFacts(existing, after) {
		return result, nil, errors.Join(err, errConfigurationReplacement)
	}
	installation := core.ReplacementObservationInstallation{ExpectedDomain: baseline.DomainID, ExpectedStore: store, SourceBasis: sourceBasis, SuccessorBasis: successorBasis, SourcePins: sourcePins, OutputPins: outputPins, CompositionID: CompatibilityManifest().Identity, Correlation: result.Correlation, Goal: core.RoleReplacementGoal{ApprovalRole: metadata.Request.Authorizer, SigningSelector: metadata.Request.SigningSelector, EncryptionSelector: metadata.Request.EncryptionSelector}, CheckSourceOutput: output.CheckUnchanged}
	switch metadata.Request.MaterialSource {
	case "authority":
		installation.Goal.MaterialSource = core.ReplacementMaterialAuthority
	case "recovery":
		installation.Goal.MaterialSource = core.ReplacementMaterialRecovery
	case "":
	default:
		return result, nil, errConfigurationReplacement
	}
	if target == core.ReplacementTargetRecipient {
		row := -1
		for i, recipient := range baseline.GeneratedRecipients {
			if recipient.Reference == metadata.Request.RecipientReference && recipient.ID == metadata.RecipientID {
				row = i
				break
			}
		}
		if row < 0 || row >= len(existing.GeneratedRecipients) || existing.GeneratedRecipients[row].Reference != metadata.Request.RecipientReference || existing.GeneratedRecipients[row].ID != metadata.RecipientID {
			return result, nil, errConfigurationReplacement
		}
		installation.RecipientBefore, err = configurationApplyBinding(baseline.Provider, baseline.GeneratedRecipients[row].Encryption)
		if err != nil {
			return result, nil, err
		}
		installation.RecipientAfter, err = configurationApplyBinding(existing.Provider, existing.GeneratedRecipients[row].Encryption)
		if err != nil {
			return result, nil, err
		}
	}
	if err := output.CheckUnchanged(ctx); err != nil {
		return result, nil, err
	}
	result.PreAdmission.Stage = "construction"
	reader, close, err := open(ctx, baseline)
	if close != nil {
		defer func() { cleanupErr = errors.Join(cleanupErr, close()) }()
	}
	if err != nil || reader == nil {
		if reader != nil {
			reader.Close()
		}
		unavailable := configurationComparisonUnavailable(ctx, nonce, baseline.DomainID, "source")
		result.Result, result.StateResult = unavailable.Result, unavailable.StateResult
		result.PreAdmission.Code = string(unavailable.Diagnostics[0].Reason)
		return result, nil, errors.Join(err, errConfigurationReplacement, ctx.Err())
	}
	installation.Source = reader
	observer, err := core.NewInstalledReplacementObserver(installation)
	if err != nil {
		reader.Close()
		return result, nil, err
	}
	defer func() { cleanupErr = errors.Join(cleanupErr, observer.Close()) }()
	result = observer.Observe(ctx, nonce)
	return result, nil, nil
}

package compositionfull

import (
	"bytes"
	"context"
	"slices"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
)

type ApplyOptions struct {
	RetirementPlugins map[string]string
}

type configurationApplyOpener func(context.Context, *configuration.Model, core.ApplyInstallation, *configurationInstalledPlugins) (*core.InstalledApply, error)

// ApplyConfiguration consumes a complete explicitly trusted pair. Its generated
// public basis fixes verification; declaration edits grant no key replacement,
// Recovery mode change or output operation.
// The caller keeps both captured images open and unchanged until return.
func ApplyConfiguration(ctx context.Context, requestID contract.ID, pair *configuration.Pair, options ApplyOptions) (out ConfigurationApplyResult) {
	out.PublicApplyResult = applyConfiguration(ctx, requestID, pair, configurationCurrentApplyOpener(pair, options), configurationMutationResultFacts{&out.SourceFailure, &out.storeLocation})
	return out
}

func applyConfiguration(ctx context.Context, requestID contract.ID, pair *configuration.Pair,
	open configurationApplyOpener, resultFacts ...configurationMutationResultFacts) core.PublicApplyResult {
	var format configuration.Format
	if pair != nil {
		format = pair.Format
	}
	out, err := newConfigurationApplyResult(requestID, format)
	if err != nil {
		return out
	}
	return applyConfigurationWithIdentity(ctx, requestID, pair, open, out, resultFacts...)
}

func newConfigurationApplyResult(requestID contract.ID, format configuration.Format) (core.PublicApplyResult, error) {
	out, err := NewApplyRefusal(format)
	out.RequestID = requestID
	if out.PreAdmission != nil {
		out.PreAdmission.RequestNonce = requestID
	}
	return out, err
}

func applyConfigurationWithIdentity(ctx context.Context, requestID contract.ID, pair *configuration.Pair,
	open configurationApplyOpener, out core.PublicApplyResult, resultFacts ...configurationMutationResultFacts) core.PublicApplyResult {
	refuse := func(stage string, err error) core.PublicApplyResult {
		return configurationApplyFailure(ctx, out, stage, err, mutationSourceFailureTarget(resultFacts))
	}

	m, err := configuration.Parse(ctx, pair)
	if err != nil {
		return refuse("parse", err)
	}
	plugins, interpret, err := configurationNormalizePlugins(ctx, pair, pair, m)
	if err != nil {
		return refuse("declaration", err)
	}
	i, input, err := configurationApplyInput(m)
	if err != nil {
		return refuse("declaration", err)
	}
	if !m.Resolved {
		return refuse("declaration", &configuration.Diagnostic{Reason: "unsupported-apply-change"})
	}
	if ctx == nil || ctx.Err() != nil || requestID.IsZero() || open == nil {
		return refuse("context", nil)
	}
	deadline, finite := ctx.Deadline()
	if !finite || !time.Now().Before(deadline) {
		return refuse("context", &configuration.Diagnostic{Reason: "expired"})
	}
	i.ConfigurationValidator = core.NewPublicConfigurationValidator(interpret)
	engine, err := open(ctx, m, i, plugins)
	if err != nil || engine == nil {
		out := refuse("construction", nil)
		out.Result = core.Result{Outcome: core.EvidenceUnavailable, Reason: core.CustodyUnavailable}
		out.Diagnostics[0].Reason = contract.ReasonEvidenceUnavailable
		out.PreAdmission.Code = string(contract.ReasonEvidenceUnavailable)
		return out
	}
	releaseConfigurationBasis(m)
	defer engine.Close()
	result := engine.Apply(ctx, requestID, input)
	if result.RequestIdentity.IsZero() {
		if result.OperationID.IsZero() {
			result.OperationID = out.OperationID
		}
		out.PreAdmission.Stage = "apply"
		out.PreAdmission.Code = string(configurationMutationObservationReason(ctx, result.Result))
		result.PreAdmission = out.PreAdmission
	}
	retainMutationStoreLocation(resultFacts, m, result)
	return result
}

func configurationMutationObservationReason(ctx context.Context, result core.Result) contract.DiagnosticReason {
	switch result.Outcome {
	case core.AdmissionRefused:
		if result.Reason == core.CapacityExceeded {
			return contract.ReasonLimitExceeded
		}
		if result.Reason != core.AdmissionInvalid {
			return contract.ReasonInvalidInput
		}
	case core.IntegrityFailure:
		switch result.Reason {
		case core.InvalidProof:
			return contract.ReasonProofInvalid
		case core.InvalidFormat, core.InvalidReference:
			return contract.ReasonSelectedObjectInvalid
		case core.InvalidRelation:
			return contract.ReasonSelectedRelationInvalid
		}
		return contract.ReasonEvidenceUnavailable
	case core.RootLossUnsupported:
		return contract.ReasonSelectedObjectUnavailable
	case core.Contention:
		return contract.ReasonReadContention
	}
	if ctx != nil {
		switch ctx.Err() {
		case context.Canceled:
			return contract.ReasonCancelled
		case context.DeadlineExceeded:
			return contract.ReasonExpired
		}
	}
	if result.Outcome == core.AdmissionRefused {
		return contract.ReasonInvalidInput
	}
	return contract.ReasonEvidenceUnavailable
}

// ApplyConfigurationFile has read-only source reach. Capture's temporary image
// owner is closed after the invocation; no source repair or preparation exists.
func ApplyConfigurationFile(ctx context.Context, requestID contract.ID, path string, format configuration.Format, options ApplyOptions) (out ConfigurationApplyResult) {
	raw, err := newConfigurationApplyResult(requestID, format)
	out.PublicApplyResult = raw
	if err != nil {
		return out
	}
	pair, err := configuration.Capture(ctx, path, format)
	if err != nil {
		out.PublicApplyResult = configurationApplyFailure(ctx, raw, "capture", err, &out.SourceFailure)
		return out
	}
	defer func() {
		if err := pair.Close(); err != nil {
			out.AddCleanupDiagnostic()
		}
	}()
	out.PublicApplyResult = applyConfigurationWithIdentity(ctx, requestID, pair, configurationCurrentApplyOpener(pair, options), raw, configurationMutationResultFacts{&out.SourceFailure, &out.storeLocation})
	return out
}

func configurationApplyFailure(ctx context.Context, out core.PublicApplyResult, stage string, err error, sourceFailure ...**ConfigurationSourceFailure) core.PublicApplyResult {
	comparison := configurationComparisonFailure(ctx, out.RequestID, contract.ID{}, "source", err)
	out.Result, out.Diagnostics = comparison.Result, comparison.Diagnostics
	if comparison.Result.Outcome == core.EvidenceUnavailable {
		out.Result.Reason = core.CustodyUnavailable
		if comparison.SourceFailure == nil {
			stage = "construction"
		}
	}
	out.PreAdmission.Stage, out.PreAdmission.Code = stage, configurationFailureReasonCode(err, comparison.Diagnostics[0].Reason)
	if len(sourceFailure) != 0 && sourceFailure[0] != nil && validConfigurationAdmissionSourceFailure(comparison.SourceFailure, out.PreAdmission, out.RequestIdentity, out.Result) {
		*sourceFailure[0] = comparison.SourceFailure
	}
	return out
}

func configurationApplyInput(m *configuration.Model) (core.ApplyInstallation, []core.ApplyEntryInput, error) {
	refuse := func() (core.ApplyInstallation, []core.ApplyEntryInput, error) {
		return core.ApplyInstallation{}, nil, &configuration.Diagnostic{Reason: "unsupported-apply-change"}
	}
	if m == nil || !m.Resolved {
		return core.ApplyInstallation{}, nil, &configuration.Diagnostic{Field: "generated", Reason: "restore-exact-generated-file"}
	}
	basis, store, err := configurationPublicBasis(m)
	if err != nil {
		return core.ApplyInstallation{}, nil, err
	}
	control, err := basis.ControlCore(m.DomainID, store)
	if err != nil {
		return core.ApplyInstallation{}, nil, err
	}
	if m.Authority.ID != control.AuthorityRecipientID || m.Authority.SigningSelector != control.NormalSigning.KeySelector || !bytes.Equal(m.Authority.Signing.PublicKey, control.NormalSigning.SPKI) ||
		(m.RecoveryEnabled != (control.Recovery != nil)) {
		return refuse()
	}
	authority, err := configurationApplyBinding(m.Provider, m.Authority.Encryption)
	if err != nil {
		return refuse()
	}
	actual, err := contract.EncodeKMSBinding(authority)
	if err != nil {
		return refuse()
	}
	expected, err := contract.EncodeKMSBinding(control.AuthorityKMSBinding)
	if err != nil || !bytes.Equal(actual, expected) {
		return refuse()
	}
	if control.Recovery != nil {
		if m.Recovery.SigningSelector != control.Recovery.Signing.KeySelector || !bytes.Equal(m.Recovery.Signing.PublicKey, control.Recovery.Signing.SPKI) {
			return refuse()
		}
		recovery, err := configurationApplyBinding(m.Provider, m.Recovery.Encryption)
		if err != nil {
			return refuse()
		}
		actual, err := contract.EncodeKMSBinding(recovery)
		if err != nil {
			return refuse()
		}
		expected, err := contract.EncodeKMSBinding(control.Recovery.KMS)
		if err != nil || !bytes.Equal(actual, expected) {
			return refuse()
		}
	}
	registry := []contract.ApplyRecipientInput{{Recipient: contract.RecipientRecord{RecipientID: m.Authority.ID, Status: contract.CurrentRecipient, DisplayName: m.Authority.DisplayName, CurrentBinding: &authority}}}
	references := make(map[string]contract.ID, len(m.Recipients))
	for _, row := range m.Recipients {
		binding, err := configurationApplyBinding(m.Provider, row.Encryption)
		if err != nil {
			return refuse()
		}
		proposed := contract.ApplyRecipientInput{Recipient: contract.RecipientRecord{RecipientID: row.ID, Status: contract.CurrentRecipient, DisplayName: row.DisplayName, CurrentBinding: &binding}}
		if row.Creation != nil {
			proposed.Creation = &contract.RecipientCreationProof{Snapshot: row.Creation.Snapshot, Nonce: row.Creation.Nonce}
		}
		registry = append(registry, proposed)
		references[row.Reference] = row.ID
	}
	input := make([]core.ApplyEntryInput, 0, len(m.Entries))
	for _, row := range m.Entries {
		members := []contract.ID{m.Authority.ID}
		for _, reference := range row.Recipients {
			id, ok := references[reference]
			if !ok {
				return refuse()
			}
			members = append(members, id)
		}
		slices.SortFunc(members, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		entry := core.ApplyEntryInput{Name: row.Name, InputEncoding: row.InputEncoding, OutputEncoding: row.OutputEncoding, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: members, InputBytes: row.Plain}
		if row.Secret {
			entry.ConfidentialityClass = contract.Secret
			if row.Generated != nil {
				entry.ValueSource = contract.Generated
				entry.InputBytes = nil
				generated := row.Generated
				intent, err := contract.InspectGeneratorIntent(generated.Intent)
				if err != nil {
					return refuse()
				}
				retirement := contract.GeneratedRetirementManual
				if generated.Retirement == "auto" {
					retirement = contract.GeneratedRetirementAuto
				}
				entry.Generated = &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: intent.LifecycleMode, Epoch: generated.Epoch, RetirementMode: retirement,
					ConfigContractID: intent.ConfigContractID, ResourceContractID: intent.ResourceContractID,
					CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: generated.Intent}
				if intent.LifecycleMode == contract.GeneratorLifecycleNone {
					entry.Generated.RetirementMode, entry.Generated.CompletionClass = 0, 0
				}
			} else if row.Retained != nil {
				entry.Retained = &contract.RetainedSecretInput{Incarnation: row.Retained.Incarnation, Material: row.Retained.Material}
				entry.InputBytes = nil
			} else {
				if len(row.Sealed) == 0 {
					return refuse()
				}
				entry.InputBytes = row.Sealed
			}
		}
		input = append(input, entry)
	}
	return core.ApplyInstallation{ExpectedDomain: m.DomainID, ExpectedStore: store, PublicBasis: basis, ExpectedControl: control, DesiredRecipients: registry, PublicConfiguration: m.Public,
		FileIdentity: m.FileID, CompositionID: CompatibilityManifest().Identity}, input, nil
}

func configurationApplyBinding(family contract.Family, key configuration.Key) (contract.KMSBinding, error) {
	v := contract.KMSBinding{BindingID: key.Binding.ID, BindingIncarnationID: key.Binding.Incarnation, BindingSerial: key.Binding.Serial, Provider: family,
		WrapProfile: contract.RSAOAEPWrapProfile, ProtectionClass: key.Binding.Protection, KeySelector: key.Selector, SPKI: key.PublicKey, Fingerprint: contract.Hash(key.PublicKey)}
	_, err := contract.KMSBindingLength(v)
	return v, err
}

func configurationCurrentApplyOpener(pair *configuration.Pair, options ApplyOptions) configurationApplyOpener {
	return func(ctx context.Context, m *configuration.Model, i core.ApplyInstallation, captured *configurationInstalledPlugins) (*core.InstalledApply, error) {
		plugins, err := configurationAttachGeneratedPlugins(ctx, pair, m, captured, options.RetirementPlugins)
		if err != nil {
			return nil, err
		}
		return openConfigurationApplyWithPlugins(ctx, m, i, plugins)
	}
}

func openConfigurationApply(ctx context.Context, m *configuration.Model, i core.ApplyInstallation) (*core.InstalledApply, error) {
	return openConfigurationApplyWithPlugins(ctx, m, i, nil)
}

func openConfigurationApplyWithPlugins(ctx context.Context, m *configuration.Model, i core.ApplyInstallation, plugins *configurationInstalledPlugins) (*core.InstalledApply, error) {
	config, route, err := configurationApplyConfig(m, i.ExpectedControl)
	if err != nil {
		return nil, err
	}
	config, err = LoadDefaultConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	cell, err := New(ctx, config)
	if err != nil {
		return nil, err
	}
	runtime, ok := cell.Crypto.(*enkvcrypto.Runtime)
	if !ok {
		return nil, ErrCell
	}
	if i.ConfigurationValidator == nil {
		i.ConfigurationValidator = core.NewPublicConfigurationValidator(nil)
	}
	i.Store, i.Trust = cell.Store, cell.Trust
	fileIdentity := i.FileIdentity
	i.AdmitCustody = func(ctx context.Context, q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, plain []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, revision contract.ID, before contract.MutationReceiptWindows, warningBits uint8, deadline time.Time) (*core.InstalledApplyCustody, error) {
		public, err := configurationApplyPublicKeys(ctx, config, current, q.Recipients)
		if err != nil {
			return nil, err
		}
		owner, err := enkvcrypto.NewApplyCustody(runtime, q, control, current, public, route, fileIdentity, plain, support, witness, revision, before, warningBits, deadline)
		if err != nil {
			return nil, err
		}
		return &core.InstalledApplyCustody{Crypto: owner, BindReceipt: owner.BindReceipt, Close: owner.Close}, nil
	}
	var closeGenerated func()
	i.Generated, closeGenerated, err = configurationGeneratedInstallation(ctx, config, runtime, route, fileIdentity, plugins)
	if err != nil {
		runtime.Close()
		return nil, err
	}
	i.CloseInstalled = func() { closeGenerated(); runtime.Close() }
	engine, err := core.NewInstalledApply(i)
	if err != nil {
		i.CloseInstalled()
		return nil, err
	}
	return engine, nil
}

func configurationApplyPublicKeys(ctx context.Context, config Config, current []contract.RecipientRecord, proposed []contract.ApplyRecipientInput) (map[contract.ID]enkvcrypto.PublicKeyQualifier, error) {
	present := make(map[contract.ID]bool, len(current))
	for _, row := range current {
		present[row.RecipientID] = true
	}
	public := make(map[contract.ID]enkvcrypto.PublicKeyQualifier)
	for _, input := range proposed {
		row := input.Recipient
		if present[row.RecipientID] {
			continue
		}
		if row.CurrentBinding == nil || row.CurrentBinding.Provider != config.Family {
			return nil, ErrCell
		}
		binding := *row.CurrentBinding
		route := contract.Hash(append([]byte("enkv/apply/recipient-public-credential-route/v1\x00"), row.RecipientID[:]...))
		qualifier, err := selectConfigurationApplyQualifier(ctx, config, binding, route)
		if err != nil {
			return nil, err
		}
		public[row.RecipientID] = qualifier
	}
	return public, nil
}

func configurationApplyConfig(m *configuration.Model, control contract.ControlCore) (Config, contract.ID, error) {
	if m == nil {
		return Config{}, contract.ID{}, ErrCell
	}
	route := contract.Hash(append([]byte("enkv/apply/authority-credential-route/v1\x00"), m.DomainID[:]...))
	config, err := selectConfigurationApplyConfig(m, control, route)
	if err != nil {
		return Config{}, contract.ID{}, err
	}
	return config, route, nil
}

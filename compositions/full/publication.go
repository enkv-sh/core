package compositionfull

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"enkv.sh/compositions/configuration"
	"enkv.sh/compositions/full/plugininstallation"
	"enkv.sh/compositions/outputhost"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	"enkv.sh/sdk/artifact"
)

type PublicationOptions struct {
	Request       core.PublicationRequest
	DeletePlugins map[contract.ID]string
}

func ownPublicationOptions(options PublicationOptions) (PublicationOptions, error) {
	request := options.Request
	if len(request.Names) > contract.CryptoMaxValueEntries || len(request.DeleteCoordinates) > contract.MaxPublicationCoordinates || len(request.RepublishAfterUnknown) > contract.MaxPublicationMarkers || len(options.DeletePlugins) != len(request.DeleteCoordinates) {
		return PublicationOptions{}, contract.ErrRecord
	}
	seenNames := make(map[string]bool, len(request.Names))
	for _, name := range request.Names {
		if len(name) > contract.CryptoMaxName || !utf8.ValidString(name) || seenNames[name] {
			return PublicationOptions{}, contract.ErrRecord
		}
		seenNames[name] = true
	}
	for _, rows := range [][]contract.ID{request.DeleteCoordinates, request.RepublishAfterUnknown} {
		seen := make(map[contract.ID]bool, len(rows))
		for _, id := range rows {
			if id.IsZero() || seen[id] {
				return PublicationOptions{}, contract.ErrRecord
			}
			seen[id] = true
		}
	}
	choices, err := ownDeletionPluginChoices(options.DeletePlugins)
	if err != nil {
		return PublicationOptions{}, err
	}
	for _, id := range request.DeleteCoordinates {
		if choices[id] == "" {
			return PublicationOptions{}, contract.ErrRecord
		}
	}
	owned := PublicationOptions{Request: core.PublicationRequest{Names: slices.Clone(request.Names), DeleteCoordinates: slices.Clone(request.DeleteCoordinates), RepublishAfterUnknown: slices.Clone(request.RepublishAfterUnknown)}, DeletePlugins: choices}
	for i := range owned.Request.Names {
		owned.Request.Names[i] = strings.Clone(owned.Request.Names[i])
	}
	return owned, nil
}
func ownDeletionPluginChoices(input map[contract.ID]string) (map[contract.ID]string, error) {
	if len(input) > contract.MaxPublicationCoordinates {
		return nil, contract.ErrRecordCapacity
	}
	if input == nil {
		return nil, nil
	}
	owned := make(map[contract.ID]string, len(input))
	for id, name := range input {
		if id.IsZero() || !artifact.ValidPluginID(name) {
			return nil, contract.ErrRecord
		}
		owned[id] = strings.Clone(name)
	}
	return owned, nil
}

// PublishConfiguration uses the pair only for independently trusted construction.
// Selected state, rather than the pair's pending declaration, supplies content.
func PublishConfiguration(ctx context.Context, requestID contract.ID, pair *configuration.Pair, options PublicationOptions) ConfigurationPublicationResult {
	out := ConfigurationPublicationResult{PublicPublicationResult: core.PublicPublicationResult{RequestID: requestID, Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.InvalidIntent}}}
	owned, err := ownPublicationOptions(options)
	if err != nil {
		return out
	}
	m, err := configuration.Parse(ctx, pair)
	if err != nil || m == nil || !m.Resolved {
		out.SourceFailure, out.sourceStage = configurationSourceFailure("source", err), "parse"
		return out
	}
	basis, store, err := configurationPublicBasis(m)
	if err != nil {
		out.SourceFailure, out.sourceStage = configurationSourceFailure("source", err), "public-basis"
		return out
	}
	control, err := basis.ControlCore(m.DomainID, store)
	if err != nil {
		return out
	}
	out.DomainID = m.DomainID
	if ctx == nil || ctx.Err() != nil || requestID.IsZero() {
		return out
	}
	if deadline, finite := ctx.Deadline(); !finite || !time.Now().Before(deadline) {
		return out
	}
	engine, err := openConfigurationPublication(ctx, pair, m, core.PublicationInstallation{ExpectedDomain: m.DomainID, ExpectedStore: store, PublicBasis: basis, ExpectedControl: control, CompositionID: CompatibilityManifest().Identity}, owned.DeletePlugins, nil)
	if err != nil || engine == nil {
		out.Result = core.Result{Outcome: core.EvidenceUnavailable, Reason: core.CustodyUnavailable}
		return out
	}
	defer engine.Close()
	out.PublicPublicationResult = engine.Publish(ctx, requestID, owned.Request)
	return out
}

func PublishConfigurationFile(ctx context.Context, requestID contract.ID, path string, format configuration.Format, options PublicationOptions) (out ConfigurationPublicationResult) {
	out = ConfigurationPublicationResult{PublicPublicationResult: core.PublicPublicationResult{RequestID: requestID, Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.InvalidIntent}}}
	owned, err := ownPublicationOptions(options)
	if err != nil {
		return out
	}
	pair, err := configuration.Capture(ctx, path, format)
	if err != nil {
		out.SourceFailure, out.sourceStage = configurationSourceFailure("source", err), "capture"
		return out
	}
	defer func() {
		if err := pair.Close(); err != nil {
			out.CleanupFailed = true
		}
	}()
	return PublishConfiguration(ctx, requestID, pair, owned)
}

func openConfigurationPublication(ctx context.Context, pair *configuration.Pair, m *configuration.Model, i core.PublicationInstallation, deletePlugins map[contract.ID]string, normalized *configurationInstalledPlugins) (*core.InstalledPublication, error) {
	deleteChoices, err := ownDeletionPluginChoices(deletePlugins)
	if err != nil {
		return nil, err
	}
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
	i.Store, i.Trust = cell.Store, cell.Trust
	i.Namespace = configurationOutputPremise
	type capturedOutput struct {
		path      string
		installed *outputhost.Installation
		err       error
	}
	var captureMu sync.Mutex
	outputs := map[string]capturedOutput{}
	requirements := make(map[string]plugininstallation.Requirement, len(m.Plugins))
	for _, requirement := range m.Plugins {
		owned := configurationPluginRequirement(m, requirement.Name)
		requirements[owned.Name] = owned
	}
	active := make(map[string]string, len(m.Outputs))
	for _, binding := range m.Outputs {
		active[binding.DestinationID] = strings.Clone(binding.Plugin)
	}
	capture := func(ctx context.Context, input core.PublicationExecutionInput) (capturedOutput, error) {
		name := active[input.DestinationID]
		if !input.DeleteCoordinate.IsZero() {
			coordinate, err := contract.PublicationCoordinateID(i.ExpectedDomain, input.Target.ServiceContractID, input.Target.CanonicalTarget)
			if err != nil || coordinate != input.DeleteCoordinate {
				return capturedOutput{}, outputhost.ErrAdmission
			}
			name = deleteChoices[input.DeleteCoordinate]
		}
		if !artifact.ValidPluginID(name) {
			return capturedOutput{}, outputhost.ErrArtifactMissing
		}
		captureMu.Lock()
		defer captureMu.Unlock()
		if row, ok := outputs[name]; ok {
			return row, row.err
		}
		requirement := requirements[name]
		requirement.Name = name
		plugins := normalized
		var err error
		if _, ok := plugins.lookup(name); !ok {
			plugins, _, err = configurationCapturePlugins(ctx, pair, []plugininstallation.Requirement{requirement}, plugininstallation.Ordinary)
		}
		if err != nil {
			row := capturedOutput{err: err}
			outputs[name] = row
			return row, err
		}
		path, installed, err := configurationOutputArtifact(plugins, name)
		row := capturedOutput{path: path, installed: installed, err: err}
		outputs[name] = row
		return row, err
	}
	executionInput := func(destination, config string, target contract.OutputTarget, action uint8, coordinate contract.ID) core.PublicationExecutionInput {
		input := core.PublicationExecutionInput{DestinationID: destination, ConfigContractID: config, Target: target}
		if action >= contract.PublicationDeleteOwned {
			input.DeleteCoordinate = coordinate
		}
		return input
	}
	i.Actions = func(ctx context.Context, input core.PublicationExecutionInput) (core.PublicationActionFacts, error) {
		if ctx == nil || ctx.Err() != nil {
			return core.PublicationActionFacts{}, outputhost.ErrAdmission
		}
		captured, err := capture(ctx, input)
		if err != nil {
			return core.PublicationActionFacts{}, err
		}
		config, err := contract.OutputConfigContractDigest(input.ConfigContractID)
		if err != nil {
			return core.PublicationActionFacts{}, err
		}
		a := captured.installed.Artifact()
		return core.PublicationActionFacts{ProtocolID: contract.ID(a.ProtocolID), DescriptorID: contract.ID(a.DescriptorID), ConfigContractDigest: config,
			ArtifactContractID: contract.ID(a.ArtifactContractID), ExecutorID: contract.ID(a.ExecutorID), CredentialRouteID: contract.ID(a.CredentialRouteID), CredentialRouteContractID: a.CredentialRouteContractID}, nil
	}
	i.SelectPolicyAction = func(ctx context.Context, in core.PublicationPolicyActionInput) (uint8, error) {
		captured, err := capture(ctx, core.PublicationExecutionInput{DestinationID: in.DestinationID, ConfigContractID: in.ConfigContractID, Target: in.Target})
		if err != nil {
			return 0, err
		}
		action, err := enkvcrypto.SelectPublicationPolicyAction(ctx, captured.path, captured.installed, enkvcrypto.PublicationPolicyActionInput{
			DomainID: in.DomainID, Target: in.Target, HasPreviousPolicyDigest: in.HasPreviousPolicyDigest, PreviousPolicyDigest: in.PreviousPolicyDigest, Deadline: in.Deadline})
		return uint8(action), err
	}
	i.Check = func(ctx context.Context, in core.PublicationActionCheckInput) (core.PublicationActionCheckFacts, error) {
		captured, err := capture(ctx, executionInput(in.DestinationID, in.ConfigContractID, in.Target, in.Action, in.Coordinate.CoordinateID))
		if err != nil {
			return core.PublicationActionCheckFacts{}, err
		}
		facts, err := enkvcrypto.CheckPublicationAction(ctx, captured.path, captured.installed, enkvcrypto.PublicationActionCheckInput{DestinationID: in.DestinationID, ConfigContractID: in.ConfigContractID,
			DomainID: in.DomainID, Action: in.Action, Target: in.Target, Coordinate: in.Coordinate, Birth: in.Birth, UncertainCreate: in.UncertainCreate, ExclusiveNamespaceDigest: in.ExclusiveNamespaceDigest, PayloadLength: in.PayloadLength, Deadline: in.Deadline})
		if err != nil {
			return core.PublicationActionCheckFacts{}, err
		}
		config, err := contract.OutputConfigContractDigest(in.ConfigContractID)
		if err != nil {
			return core.PublicationActionCheckFacts{}, err
		}
		a := captured.installed.Artifact()
		return core.PublicationActionCheckFacts{MinimumPayload: facts.PayloadBounds.Minimum, MaximumPayload: facts.PayloadBounds.Maximum,
			ProtocolID: contract.ID(a.ProtocolID), DescriptorID: contract.ID(a.DescriptorID), ConfigContractDigest: config, ArtifactContractID: contract.ID(a.ArtifactContractID),
			ExecutorID: contract.ID(a.ExecutorID), CredentialRouteID: contract.ID(a.CredentialRouteID), CredentialRouteContractID: a.CredentialRouteContractID}, nil
	}
	i.NewOwner = func(ctx context.Context, in core.PublicationOwnerInput) (core.PublicationPrivateOwner, error) {
		captured, err := capture(ctx, executionInput(in.DestinationID, in.ConfigContractID, in.Target, in.Projection.Action, in.Coordinate.CoordinateID))
		if err != nil {
			return nil, err
		}
		native, artifact, err := configurationOutputCapturedNative(ctx, captured.path, captured.installed)
		if err != nil {
			return nil, err
		}
		p := in.ActionCheck
		if p.ProtocolID != contract.ID(artifact.ProtocolID) || p.DescriptorID != contract.ID(artifact.DescriptorID) || p.ArtifactContractID != contract.ID(artifact.ArtifactContractID) || p.ExecutorID != contract.ID(artifact.ExecutorID) || p.CredentialRouteID != contract.ID(artifact.CredentialRouteID) {
			return nil, outputhost.ErrAdmission
		}
		owner, err := enkvcrypto.NewPublicationCustody(ctx, runtime, enkvcrypto.PublicationCustodyInput{Projection: in.Projection, DestinationID: in.DestinationID, ConfigContractID: in.ConfigContractID, Target: in.Target, Coordinate: in.Coordinate, Birth: in.Birth, UncertainCreate: in.UncertainCreate, Native: native, Minimum: p.MinimumPayload, Maximum: p.MaximumPayload, Deadline: in.Deadline})
		if err != nil {
			return nil, err
		}
		return &configurationPublicationOwner{PublicationCustody: owner, route: route}, nil
	}
	i.CloseInstalled = runtime.Close
	engine, err := core.NewInstalledPublication(i)
	if err != nil {
		runtime.Close()
		return nil, err
	}
	return engine, nil
}

type configurationPublicationOwner struct {
	*enkvcrypto.PublicationCustody
	route contract.ID
}

func (o *configurationPublicationOwner) Prepare(ctx context.Context, id contract.ID, selected *contract.ConsumerSelection) ([]contract.KeyUseRow, contract.CryptoResultCode) {
	var route contract.ID
	if selected != nil && selected.Entry.ConfidentialityClass == contract.Secret {
		route = o.route
	}
	return o.PublicationCustody.Prepare(ctx, id, selected, route)
}

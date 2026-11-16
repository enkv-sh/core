package core

import (
	"context"
	"enkv.sh/compositions/outputhost"
	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	"enkv.sh/sdk/artifact"
	protocol "enkv.sh/sdk/protocols/output"
	"time"
)

func packagedOutputInterpreter(destinations map[string]custody.PublicationConfig) PublicOutputInterpreter {
	return func(ctx context.Context, destinationID string, d contract.OutputDestination, name string, encoding uint8) (contract.OutputTarget, error) {
		config, ok := destinations[destinationID]
		if !ok {
			return contract.OutputTarget{}, contract.ErrRecord
		}
		metadata, err := artifact.DecodeMetadata(config.Metadata)
		if err != nil {
			return contract.OutputTarget{}, err
		}
		installation, err := outputhost.NewInstallation(metadata, config.Dependency)
		if err != nil {
			return contract.OutputTarget{}, err
		}
		validator, err := outputhost.NewPublicValidator(ctx, config.ArtifactPath, installation)
		if err != nil {
			return contract.OutputTarget{}, err
		}
		deadline := uint64(time.Now().Add(time.Minute).UnixMilli())
		destination := protocol.Destination{ConfigContractID: d.ConfigContractID, ServiceContractID: d.ServiceContractID, CanonicalSettings: d.CanonicalSettings, Policy: protocol.Policy{ContractID: d.Policy.ContractID, Data: d.Policy.Data}, Capabilities: protocol.ActionCapabilities(d.Capabilities)}
		result, err := validator.InterpretTarget(ctx, protocol.InterpretRequest{Schema: 1, DeadlineUnixMillis: deadline, Destination: destination, EntryName: name, PayloadEncoding: encoding})
		if err != nil {
			return contract.OutputTarget{}, err
		}
		target := result.Target
		return contract.OutputTarget{ServiceContractID: target.ServiceContractID, TargetContractID: target.TargetContractID, CanonicalTarget: target.CanonicalTarget, ConsumerLocator: target.ConsumerLocator, TargetData: target.TargetData, PayloadEncoding: target.PayloadEncoding, LocatorRequiresCreation: target.LocatorRequiresCreation, Capabilities: contract.OutputActionCapabilities(target.Capabilities), CreateValueBounds: contract.OutputPayloadBounds(target.CreateValueBounds), WriteValueBounds: contract.OutputPayloadBounds(target.WriteValueBounds), Policy: d.Policy}, nil
	}
}

func livePublicOutputTarget(name string, target contract.OutputTarget) contract.PublicOutputTarget {
	return contract.PublicOutputTarget{EntryName: name, ServiceContractID: observedPublicField(target.ServiceContractID), TargetContractID: observedPublicField(target.TargetContractID), CanonicalTarget: observedPublicField(target.CanonicalTarget), ConsumerLocator: observedPublicField(target.ConsumerLocator), TargetData: observedPublicField(target.TargetData), PayloadEncoding: observedPublicField(target.PayloadEncoding), LocatorRequiresCreation: observedPublicField(target.LocatorRequiresCreation), Capabilities: observedPublicField(target.Capabilities), CreateValueBounds: observedPublicField(target.CreateValueBounds), WriteValueBounds: observedPublicField(target.WriteValueBounds), ConsumerPolicy: observedPublicField(target.Policy)}
}

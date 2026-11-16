package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"os"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
	awsoutput "enkv.sh/plugins/outputs/aws-secrets-manager/execution"
	gcpoutput "enkv.sh/plugins/outputs/gcp-secret-manager/execution"
	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
)

type publicOutputPreparationResult struct {
	Provider         string
	Prepared, Closed bool
}

func preparePublicOutput(ctx context.Context, model *configuration.Model, project string) publicOutputPreparationResult {
	var result publicOutputPreparationResult
	var settingsFields map[string]string
	var plugin string
	var constructor func([]byte) (output.Implementation, error)
	switch model.Provider {
	case contract.AWS:
		if project != "" {
			return result
		}
		result.Provider, constructor = "aws", awsoutput.NewImplementation
		plugin, settingsFields = "aws-secrets-manager", map[string]string{"account": model.Store.ExpectedOwner, "region": model.Store.Region}
	case contract.GCP:
		result.Provider, constructor = "gcp", gcpoutput.NewImplementation
		plugin, settingsFields = "gcp-secret-manager", map[string]string{"project_number": project}
	default:
		return result
	}
	settings, err := json.Marshal(settingsFields)
	if err != nil {
		return result
	}
	descriptorBytes := nativeProcessOutputDescriptor(result.Provider)
	descriptor, err := artifact.DecodeDescriptor(descriptorBytes)
	if err != nil || descriptor.Output == nil || descriptor.Name != plugin {
		return result
	}
	implementation, err := constructor(descriptorBytes)
	if err != nil {
		return result
	}
	identity, err := descriptor.Identity()
	wire, wireErr := artifact.ParseDigest(descriptor.Wire.Identity)
	route := implementation.CredentialRoute()
	routeID, routeErr := credentialroute.Identity(route)
	expectedRoute, decodeErr := credentialroute.Decode(descriptor.Output.CredentialRoute)
	expectedRouteID, expectedErr := credentialroute.Identity(expectedRoute)
	if err != nil || wireErr != nil || routeErr != nil || decodeErr != nil || expectedErr != nil || routeID != expectedRouteID || route.Mode != credentialroute.ModeSDK ||
		implementation.Identity().DescriptorID != protocol.ID(identity) || implementation.Identity().ProtocolID != protocol.ID(wire) {
		return result
	}
	destination, err := implementation.NormalizeDestination(ctx, settings)
	if err != nil {
		return result
	}
	target, err := implementation.InterpretTarget(ctx, output.TargetRequest{Destination: destination, EntryName: "ENKV_CREDENTIAL_PREPARATION", PayloadEncoding: protocol.EncodingRaw})
	if err != nil {
		return result
	}
	var attempt protocol.ID
	if _, err := rand.Read(attempt[:]); err != nil {
		return result
	}
	preparation := output.Preparation{Action: protocol.ActionCreateEmpty, Target: target, AttemptID: attempt, PayloadLengthMode: protocol.LengthAbsent}
	policy := protocol.Policy{}
	if _, err := implementation.CheckAction(ctx, output.ActionCheck{Action: preparation.Action, Target: target, PayloadLengthMode: preparation.PayloadLengthMode}, policy); err != nil {
		return result
	}
	inputs := make([]credentialroute.Input, len(route.Names))
	defer func() {
		for _, input := range inputs {
			clear(input.Value)
		}
	}()
	length := 3
	for index, name := range route.Names {
		value, present := os.LookupEnv(name)
		length += 6 + len(name) + len(value)
		if length > credentialroute.MaxInputsBytes {
			return result
		}
		inputs[index] = credentialroute.Input{Name: name, Present: present, Value: []byte(value)}
	}
	encoded, err := credentialroute.EncodeInputs(route, inputs)
	clear(encoded)
	if err != nil {
		return result
	}
	prepared, prepareErr := implementation.Prepare(ctx, preparation, policy, inputs)
	if prepared == nil {
		return result
	}
	result.Prepared = prepareErr == nil
	result.Closed = prepared.Close() == nil
	return result
}

package compositionfull

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"reflect"
	"time"

	"enkv.sh/compositions/full/plugininstallation"
	"enkv.sh/compositions/generatorhost"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	"enkv.sh/sdk/artifact"
	protocol "enkv.sh/sdk/protocols/generator"
)

func resolveConfigurationGeneratedImplementation(request core.GeneratedImplementationRequest, row contract.GeneratorImplementation) (contract.GeneratorImplementation, error) {
	if generatorhost.ValidateRuntimeImplementation(row) != nil || request.ConfigContractID.IsZero() ||
		request.LifecycleMode != contract.GeneratorLifecycleNone && request.LifecycleMode != contract.GeneratorLifecycleManaged ||
		(request.LifecycleMode == contract.GeneratorLifecycleNone) != request.ResourceContractID.IsZero() {
		return contract.GeneratorImplementation{}, ErrCell
	}
	if identity := request.Retained; identity != nil {
		result, err := contract.GeneratedResultContractID(row, identity.Action, identity.CompletionClass, identity.MaxSecret, identity.MaxFacts, identity.InputEncoding)
		if err != nil || row.DescriptorID != identity.DescriptorID || row.ExecutorID != identity.ExecutorID ||
			row.CredentialRouteID != identity.CredentialRouteID || result != identity.ResultContractID {
			return contract.GeneratorImplementation{}, ErrCell
		}
	}
	row.CredentialRoute = bytes.Clone(row.CredentialRoute)
	return row, nil
}

// Fresh work uses the captured current selection. Accepted work resolves its
// original executor and then rechecks the full retained tuple; a current local
// plugin with the same name is not a fallback.
func configurationGeneratedInstalled(ctx context.Context, plugins *configurationInstalledPlugins, request core.GeneratedImplementationRequest) (contract.GeneratorImplementation, *generatorhost.Installation, string, error) {
	if ctx == nil {
		return contract.GeneratorImplementation{}, nil, "", ErrCell
	}
	if err := ctx.Err(); err != nil {
		return contract.GeneratorImplementation{}, nil, "", err
	}
	var exact *generatorhost.Installation
	var captured *plugininstallation.Installed
	var err error
	if request.Retained == nil {
		name, err := plugins.generatorPlugin(request.EntryName)
		if err != nil {
			return contract.GeneratorImplementation{}, nil, "", err
		}
		if plugins.currentGenerator != nil {
			plugins, err = plugins.currentGenerator(name)
			if err != nil {
				return contract.GeneratorImplementation{}, nil, "", err
			}
		}
		var ok bool
		captured, ok = plugins.lookup(name)
		if !ok {
			return contract.GeneratorImplementation{}, nil, "", ErrCell
		}
		metadata, err := captured.Metadata()
		if err != nil {
			return contract.GeneratorImplementation{}, nil, "", err
		}
		exact, err = generatorhost.NewInstallation(metadata, captured.DependencyBytes())
		if err != nil {
			return contract.GeneratorImplementation{}, nil, "", err
		}
	} else {
		if plugins == nil || plugins.coordinator == nil {
			plugins, err = configurationRetainedPlugins()
			if err != nil {
				return contract.GeneratorImplementation{}, nil, "", err
			}
		}
		captured, err = plugins.coordinator.ResolveRetained(ctx, artifact.Digest(request.Retained.ExecutorID), func(_ context.Context, metadata artifact.Metadata, dependency []byte) error {
			candidate, err := generatorhost.NewRetainedInstallation(metadata, dependency)
			if err != nil {
				return err
			}
			if _, err := resolveConfigurationGeneratedImplementation(request, candidate.Artifact()); err != nil {
				return err
			}
			exact = candidate
			return nil
		})
	}
	if err != nil || captured == nil || exact == nil {
		return contract.GeneratorImplementation{}, nil, "", errors.Join(ErrCell, err)
	}
	selected, err := resolveConfigurationGeneratedImplementation(request, exact.Artifact())
	if err != nil {
		return selected, nil, "", err
	}
	return selected, exact, captured.Executable(), nil
}

func configurationGeneratedResolver(ctx context.Context, plugins *configurationInstalledPlugins) func(core.GeneratedImplementationRequest) (contract.GeneratorImplementation, error) {
	return func(request core.GeneratedImplementationRequest) (contract.GeneratorImplementation, error) {
		row, _, _, err := configurationGeneratedInstalled(ctx, plugins, request)
		return row, err
	}
}

func configurationGeneratedCreateReadiness(plugins *configurationInstalledPlugins) func(context.Context, string, contract.GeneratorImplementation, []byte) error {
	return func(ctx context.Context, name string, expected contract.GeneratorImplementation, intent []byte) error {
		deadline, err := configurationPassiveDeadline(ctx)
		if err != nil {
			return err
		}
		canonical, err := contract.InspectGeneratorIntent(intent)
		if err != nil {
			return err
		}
		selected, installed, path, err := configurationGeneratedInstalled(ctx, plugins, core.GeneratedImplementationRequest{
			EntryName: name, ConfigContractID: canonical.ConfigContractID, ResourceContractID: canonical.ResourceContractID, LifecycleMode: canonical.LifecycleMode,
		})
		if err != nil || !reflect.DeepEqual(selected, expected) {
			return errors.Join(ErrCell, err)
		}
		validator, err := generatorhost.NewPublicValidator(ctx, path, installed)
		if err != nil {
			return err
		}
		request := protocol.CanonicalRequest{Schema: protocol.Schema, DeadlineUnixMillis: deadline, Purpose: protocol.CanonicalFreshCreate, Intent: intent}
		request.InputDigest, err = protocol.CanonicalInputDigest(request)
		if err != nil {
			return err
		}
		_, err = validator.ValidateCanonical(ctx, request)
		if errors.Is(err, generatorhost.ErrPassiveRefused) {
			return errors.Join(contract.ErrRecord, err)
		}
		return err
	}
}

func configurationGeneratedRetirementCompatibility(plugins *configurationInstalledPlugins) func(context.Context, contract.GeneratorImplementation, []byte, contract.GeneratorSafeFacts, uint8) ([]byte, []byte, error) {
	return func(ctx context.Context, row contract.GeneratorImplementation, intent []byte, facts contract.GeneratorSafeFacts, completion uint8) ([]byte, []byte, error) {
		deadline, err := configurationPassiveDeadline(ctx)
		if err != nil {
			return nil, nil, err
		}
		canonical, err := contract.InspectGeneratorIntent(intent)
		if err != nil {
			return nil, nil, err
		}
		original, err := contract.EncodeNativeGeneratorSafeFacts(facts)
		if err != nil {
			return nil, nil, err
		}
		request := protocol.RetirementCompatibilityRequest{Schema: protocol.Schema, DeadlineUnixMillis: deadline, Intent: intent, OriginalFacts: original, CompletionClass: completion}
		request.InputDigest, err = protocol.RetirementCompatibilityInputDigest(request)
		if err != nil {
			return nil, nil, err
		}
		body, err := protocol.EncodeRetirementCompatibilityRequest(request)
		if err != nil {
			return nil, nil, err
		}
		result, err := contract.GeneratedResultContractID(row, contract.GeneratorActionDelete, completion, 0, contract.GeneratorSafeFactsEnvelopeLength, contract.InputEncodingRaw)
		if err != nil {
			return nil, nil, err
		}
		_, installed, path, err := configurationGeneratedInstalled(ctx, plugins, core.GeneratedImplementationRequest{
			ConfigContractID: canonical.ConfigContractID, ResourceContractID: canonical.ResourceContractID, LifecycleMode: canonical.LifecycleMode,
			Retained: &core.GeneratedImplementationIdentity{DescriptorID: row.DescriptorID, ExecutorID: row.ExecutorID, CredentialRouteID: row.CredentialRouteID, ResultContractID: result,
				Action: contract.GeneratorActionDelete, InputEncoding: contract.InputEncodingRaw, CompletionClass: completion, MaxFacts: contract.GeneratorSafeFactsEnvelopeLength},
		})
		if err != nil {
			return nil, nil, err
		}
		validator, err := generatorhost.NewPublicValidator(ctx, path, installed)
		if err != nil {
			return nil, nil, err
		}
		response, err := validator.CheckRetirementCompatibility(ctx, request)
		if err != nil {
			return nil, nil, err
		}
		reply, err := protocol.EncodeValidationResponse(response)
		if err != nil {
			return nil, nil, err
		}
		return body, reply, nil
	}
}

func configurationGeneratedRequestDigest(ctx context.Context, row contract.GeneratorImplementation, action uint8, intent []byte, target *contract.GeneratorTarget) (contract.ID, error) {
	if ctx == nil || generatorhost.ValidateRuntimeImplementation(row) != nil {
		return contract.ID{}, ErrCell
	}
	if err := ctx.Err(); err != nil {
		return contract.ID{}, errors.Join(ErrCell, err)
	}
	canonical, err := contract.InspectGeneratorIntent(intent)
	if err != nil {
		return contract.ID{}, errors.Join(ErrCell, err)
	}
	var targetBody []byte
	switch action {
	case contract.GeneratorActionCreate:
		if target != nil {
			return contract.ID{}, ErrCell
		}
	case contract.GeneratorActionDelete:
		if target == nil || canonical.LifecycleMode != contract.GeneratorLifecycleManaged || target.LifecycleMode != canonical.LifecycleMode ||
			target.ConfigContractID != canonical.ConfigContractID || target.ResourceContractID != canonical.ResourceContractID {
			return contract.ID{}, ErrCell
		}
		targetBody, err = contract.EncodeGeneratorTarget(*target)
		if err != nil {
			return contract.ID{}, errors.Join(ErrCell, err)
		}
	default:
		return contract.ID{}, ErrCell
	}
	hash := sha256.New()
	hash.Write([]byte("ENKV/GENERATOR-REQUEST/v1\x00"))
	hash.Write([]byte{action})
	hash.Write(binary.BigEndian.AppendUint32(nil, uint32(len(intent))))
	hash.Write(intent)
	hash.Write(binary.BigEndian.AppendUint32(nil, uint32(len(targetBody))))
	hash.Write(targetBody)
	if err := ctx.Err(); err != nil {
		return contract.ID{}, errors.Join(ErrCell, err)
	}
	var digest contract.ID
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

func configurationGeneratedConstruction(ctx context.Context, config Config, route, fileIdentity contract.ID, session contract.GeneratedSessionInput, plan contract.GeneratedPlanInput, purpose contract.CryptoGeneratedPurpose, selectsEntries bool) (enkvcrypto.GeneratedCustodyConstruction, error) {
	out := enkvcrypto.GeneratedCustodyConstruction{RouteID: route, FileIdentity: fileIdentity}
	if ctx == nil {
		return out, ErrCell
	}
	if err := ctx.Err(); err != nil {
		return out, errors.Join(ErrCell, err)
	}
	if !purpose.QualifiesPendingRecipients(selectsEntries) || len(plan.RegistryImage) == 0 {
		return out, nil
	}
	image, err := contract.DecodeGeneratedRecipientRegistryImage(plan.RegistryImage)
	if err != nil {
		return out, err
	}
	out.Public, err = configurationApplyPublicKeys(ctx, config, session.CurrentRecipients, image.Recipients)
	return out, err
}

func configurationGeneratedCustody(owner *enkvcrypto.GeneratedCustody) *core.InstalledGeneratedCustody {
	return &core.InstalledGeneratedCustody{Crypto: owner, BindCandidate: owner.BindCandidate, Close: owner.Close}
}

func configurationGeneratedProducerCustody(owner *enkvcrypto.GeneratedCustody, fork *enkvcrypto.Runtime) *core.InstalledGeneratedProducerCustody {
	return &core.InstalledGeneratedProducerCustody{InstalledGeneratedCustody: core.InstalledGeneratedCustody{Crypto: owner, BindCandidate: owner.BindCandidate, Close: func() { owner.Close(); fork.Close() }}, InvokeProducer: owner.InvokeProducer}
}

func configurationGeneratedInstallation(ctx context.Context, config Config, runtime *enkvcrypto.Runtime, route, fileIdentity contract.ID, plugins *configurationInstalledPlugins) (*core.GeneratedApplyInstallation, func(), error) {
	if ctx == nil || ctx.Err() != nil || runtime == nil || runtime.InstanceID().IsZero() || route.IsZero() || fileIdentity.IsZero() || !config.Family.Valid() {
		return nil, nil, ErrCell
	}
	credentials := generatorhost.NewInvocationCredentials(ctx)
	i := &core.GeneratedApplyInstallation{ResolveImplementation: configurationGeneratedResolver(ctx, plugins), CheckCreateReadiness: configurationGeneratedCreateReadiness(plugins), CheckRetirementCompatibility: configurationGeneratedRetirementCompatibility(plugins), RequestDigest: configurationGeneratedRequestDigest}
	i.AdmitVerification = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedVerificationInput, deadline time.Time) (*core.InstalledGeneratedCustody, error) {
		owner, err := enkvcrypto.NewGeneratedVerificationCustody(runtime, q, control,
			enkvcrypto.GeneratedCustodyConstruction{RouteID: route, FileIdentity: fileIdentity}, input, deadline)
		if err != nil {
			return nil, err
		}
		return configurationGeneratedCustody(owner), nil
	}
	i.AdmitReservation = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedReservationInput, deadline time.Time) (*core.InstalledGeneratedCustody, error) {
		construction, err := configurationGeneratedConstruction(ctx, config, route, fileIdentity, input.Session, input.Plan, q.Purpose, false)
		if err != nil {
			return nil, err
		}
		owner, err := enkvcrypto.NewGeneratedReservationCustody(runtime, q, control, construction, input, deadline)
		if err != nil {
			return nil, err
		}
		return configurationGeneratedCustody(owner), nil
	}
	i.AdmitAdoption = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedAdoptionInput, deadline time.Time) (*core.InstalledGeneratedCustody, error) {
		construction, err := configurationGeneratedConstruction(ctx, config, route, fileIdentity, input.Session, input.Plan, q.Purpose, false)
		if err != nil {
			return nil, err
		}
		owner, err := enkvcrypto.NewGeneratedAdoptionCustody(runtime, q, control, construction, input, deadline)
		if err != nil {
			return nil, err
		}
		return configurationGeneratedCustody(owner), nil
	}
	i.AdmitFinal = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedFinalInput, deadline time.Time) (*core.InstalledGeneratedCustody, error) {
		construction, err := configurationGeneratedConstruction(ctx, config, route, fileIdentity, input.Session, input.Plan, q.Purpose, len(input.EntryAdmissions) != 0)
		if err != nil {
			return nil, err
		}
		owner, err := enkvcrypto.NewGeneratedFinalCustody(runtime, q, control, construction, input, deadline)
		if err != nil {
			return nil, err
		}
		return configurationGeneratedCustody(owner), nil
	}
	i.AdmitProducer = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedProducerInput, row contract.GeneratorImplementation, deadline time.Time) (*core.InstalledGeneratedProducerCustody, error) {
		x, use := input.Expected.Template, input.Expected.Use
		request := core.GeneratedImplementationRequest{ConfigContractID: x.ConfigContractID, ResourceContractID: x.ResourceContractID, LifecycleMode: x.LifecycleMode, Retained: &core.GeneratedImplementationIdentity{DescriptorID: x.DescriptorID, ExecutorID: x.ExecutorID, CredentialRouteID: x.CredentialRouteID, ResultContractID: x.ResultContractID, Action: x.Action, InputEncoding: input.Expected.InputEncoding, CompletionClass: x.CompletionClass, MaxSecret: use.MaxSecret, MaxFacts: use.MaxFacts}}
		_, installed, path, err := configurationGeneratedInstalled(ctx, plugins, request)
		if err != nil {
			return nil, err
		}
		construction, err := configurationGeneratedConstruction(ctx, config, route, fileIdentity, input.Session, input.Plan, q.Purpose, false)
		if err != nil {
			return nil, err
		}
		launcher, err := generatorhost.NewNativeForInvocation(ctx, generatorhost.Config{ArtifactPath: path, Artifact: row, Installation: installed}, credentials)
		if err != nil {
			return nil, err
		}
		fork, err := runtime.Fork()
		if err != nil {
			return nil, err
		}
		owner, err := enkvcrypto.NewGeneratedProducerCustody(fork, q, control, construction, input, launcher, deadline)
		if err != nil {
			fork.Close()
			return nil, err
		}
		producer := configurationGeneratedProducerCustody(owner, fork)
		reason, admit := owner.LocalFailureAdmission()
		producer.LocalFailureReason = reason
		if admit != nil {
			producer.AdmitLocalFailure = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedLocalFailureInput, deadline time.Time) (*core.InstalledGeneratedCustody, error) {
				construction, err := configurationGeneratedConstruction(ctx, config, route, fileIdentity, input.Session, input.Plan, q.Purpose, false)
				if err != nil {
					return nil, err
				}
				continued, err := admit(ctx, runtime, q, control, construction, input, deadline)
				if err != nil {
					return nil, err
				}
				return configurationGeneratedCustody(continued), nil
			}
		}
		return producer, nil
	}
	// Core must close its producer owners before releasing this capture owner;
	// Close also waits for the host leases that keep private copies in use.
	return i, credentials.Close, nil
}

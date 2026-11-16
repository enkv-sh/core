package generatorhost

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	protocol "enkv.sh/sdk/protocols/generator"
	"enkv.sh/telemetry"
)

// ErrPassiveRefused marks a complete, correlated passive semantic refusal.
// The returned error also matches ErrAdmission for existing admission callers.
var ErrPassiveRefused = errors.New("generator passive input refused")

// PublicValidator performs passive interpretation with one exact captured build.
// It has no credential capture and supplies no effect command.
type PublicValidator struct{ config Config }

// NewPublicValidator verifies an absolute executable path against installed
// facts without credentials or child execution. Each check rechecks its launch copy.
// The required context controls construction; checks use their own caller context.
func NewPublicValidator(ctx context.Context, path string, installed *Installation) (*PublicValidator, error) {
	if !filepath.IsAbs(path) || installed == nil || installed.artifact.Validate() != nil {
		return nil, ErrAdmission
	}
	if err := VerifyInstalledArtifact(ctx, path, installed); err != nil {
		return nil, err
	}
	return &PublicValidator{config: Config{Installation: installed, ArtifactPath: path, Artifact: installed.Artifact()}}, nil
}

// Normalize returns accepted canonical intent from the captured build after
// digest, framing and process checks. A semantic refusal matches both
// ErrPassiveRefused and ErrAdmission. The request is borrowed only until return.
func (v *PublicValidator) Normalize(ctx context.Context, request protocol.NormalizeRequest) (protocol.NormalizeResponse, error) {
	call := telemetry.Start(ctx, telemetry.ProviderGeneratorHost, telemetry.OpGeneratorHostStart)
	ctx = telemetry.CallContext(ctx, call)
	response, err := func() (protocol.NormalizeResponse, error) {
		if v == nil || request.ConfigContractID != protocol.ID(v.config.Artifact.ConfigContractID) {
			return protocol.NormalizeResponse{}, ErrAdmission
		}
		body, err := protocol.EncodeNormalizeRequest(request)
		if err != nil {
			return protocol.NormalizeResponse{}, err
		}
		resultBody, err := v.exchange(ctx, protocol.KindNormalize, protocol.KindNormalized, request.DeadlineUnixMillis, body)
		if err != nil {
			return protocol.NormalizeResponse{}, err
		}
		result, err := protocol.DecodeNormalizeResponse(resultBody)
		if err != nil {
			return protocol.NormalizeResponse{}, errors.Join(ErrProcess, err)
		}
		if result.InputDigest != request.InputDigest {
			return protocol.NormalizeResponse{}, errors.Join(ErrProcess, protocol.ErrProtocol)
		}
		if !result.Accepted {
			return protocol.NormalizeResponse{}, errors.Join(ErrAdmission, ErrPassiveRefused)
		}
		intent, err := protocol.DecodeIntent(result.Intent)
		if err != nil || intent.ConfigContractID != request.ConfigContractID {
			return protocol.NormalizeResponse{}, errors.Join(ErrProcess, protocol.ErrProtocol, err)
		}
		return result, nil
	}()
	finishHostCall(call, err)
	return response, err
}

// ValidateCanonical checks the exact intent through the captured build.
// Acceptance is a plugin claim, not effect permission. A semantic refusal
// matches both ErrPassiveRefused and ErrAdmission.
func (v *PublicValidator) ValidateCanonical(ctx context.Context, request protocol.CanonicalRequest) (protocol.ValidationResponse, error) {
	call := telemetry.Start(ctx, telemetry.ProviderGeneratorHost, telemetry.OpGeneratorHostStart)
	ctx = telemetry.CallContext(ctx, call)
	response, err := func() (protocol.ValidationResponse, error) {
		body, err := protocol.EncodeCanonicalRequest(request)
		if err != nil {
			return protocol.ValidationResponse{}, err
		}
		return v.validate(ctx, protocol.KindValidateCanonical, protocol.KindCanonicalValidation, request.DeadlineUnixMillis, request.InputDigest, body)
	}()
	finishHostCall(call, err)
	return response, err
}

// CheckRetirementCompatibility asks the captured build about the exact
// original intent and facts. Acceptance binds only that input digest and does
// not authorize retirement or substitute for retained execution support.
func (v *PublicValidator) CheckRetirementCompatibility(ctx context.Context, request protocol.RetirementCompatibilityRequest) (protocol.ValidationResponse, error) {
	call := telemetry.Start(ctx, telemetry.ProviderGeneratorHost, telemetry.OpGeneratorHostStart)
	ctx = telemetry.CallContext(ctx, call)
	response, err := func() (protocol.ValidationResponse, error) {
		body, err := protocol.EncodeRetirementCompatibilityRequest(request)
		if err != nil {
			return protocol.ValidationResponse{}, err
		}
		return v.validate(ctx, protocol.KindRetirementCompatibility, protocol.KindRetirementCompatibilityResult, request.DeadlineUnixMillis, request.InputDigest, body)
	}()
	finishHostCall(call, err)
	return response, err
}
func (v *PublicValidator) validate(ctx context.Context, kind, resultKind uint8, deadline uint64, digest protocol.ID, body []byte) (protocol.ValidationResponse, error) {
	resultBody, err := v.exchange(ctx, kind, resultKind, deadline, body)
	if err != nil {
		return protocol.ValidationResponse{}, err
	}
	result, err := protocol.DecodeValidationResponse(resultBody)
	if err != nil {
		return protocol.ValidationResponse{}, errors.Join(ErrProcess, err)
	}
	if result.InputDigest != digest {
		return protocol.ValidationResponse{}, errors.Join(ErrProcess, protocol.ErrProtocol)
	}
	if !result.Accepted {
		return protocol.ValidationResponse{}, errors.Join(ErrAdmission, ErrPassiveRefused)
	}
	return result, nil
}
func (v *PublicValidator) exchange(ctx context.Context, kind, resultKind uint8, deadline uint64, body []byte) (result []byte, resultErr error) {
	if v == nil || ctx == nil {
		return nil, ErrAdmission
	}
	ctx, cancel := context.WithDeadline(ctx, boundedCommandDeadline(time.Now(), deadline))
	defer cancel()
	defer func() {
		if lifetimeErr := ctx.Err(); lifetimeErr != nil {
			result = nil
			resultErr = errors.Join(resultErr, lifetimeErr)
		}
	}()
	launcher, err := newNative(v.config, true)
	if err != nil {
		return nil, err
	}
	ownedReader, ownedWriter, err := acquirePipe(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := ownedReader.release(); closeErr != nil {
			result = nil
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	run, err := launcher.startExchange(ctx, kind, deadline, body, ownedWriter, false)
	if err != nil {
		return nil, err
	}
	joined := false
	defer func() {
		if !joined {
			resultErr = errors.Join(resultErr, run.Cancel())
			result = nil
		}
	}()
	result, err = protocol.ReadExpectedFrame(ownedReader, resultKind, run.CommandID(), protocol.MaximumPublicBody)
	if err == nil {
		err = protocol.RequireEOF(ownedReader)
	}
	if err != nil {
		return nil, errors.Join(ErrProcess, err)
	}
	status, err := run.Wait(ctx)
	joined = true
	if err != nil || status.Stage != protocol.StatusStageReturn || status.Category != protocol.StatusOK {
		return nil, errors.Join(ErrProcess, err)
	}
	return result, nil
}

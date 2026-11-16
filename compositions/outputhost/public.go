package outputhost

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"time"

	protocol "enkv.sh/sdk/protocols/output"
	"enkv.sh/telemetry"
)

// PublicValidator owns only passive public exchanges with one captured build.
// Calls borrow request backing until return. Successful results contain owned
// decoded data; they supply no credential or effect permission. A valid refusal
// matches ErrPassiveRefused through errors.Is; malformed replies and failed
// process completion match ErrProcess instead.
type PublicValidator struct {
	config   Config
	retained *publicExecutable
}

// NewPublicValidator verifies an absolute executable path and retains the
// immutable installation expectation. Each call rechecks its own launch copy.
// The required context controls construction; calls use their own caller context.
func NewPublicValidator(ctx context.Context, path string, installation *Installation) (*PublicValidator, error) {
	if !filepath.IsAbs(path) || !installation.valid() {
		return nil, ErrAdmission
	}
	if err := VerifyInstalledArtifact(ctx, path, installation); err != nil {
		return nil, err
	}
	return &PublicValidator{config: Config{ArtifactPath: path, Installation: installation}}, nil
}

// Normalize obtains canonical destination settings from the captured build.
// Its accepted configuration identity must match the installed declaration.
func (v *PublicValidator) Normalize(ctx context.Context, request protocol.NormalizeRequest) (response protocol.NormalizeResult, resultErr error) {
	call := telemetry.Start(ctx, telemetry.ProviderOutputHost, telemetry.OpOutputHostPublicCheck)
	defer func() { finishOutputCall(call, resultErr, nil) }()
	ctx = telemetry.CallContext(ctx, call)
	body, err := protocol.EncodeNormalizeRequest(request)
	if err != nil {
		return protocol.NormalizeResult{}, err
	}
	id, resultBody, err := v.exchange(ctx, request.DeadlineUnixMillis, protocol.KindNormalizeRequest, protocol.KindNormalizeResult, body, nil, protocol.MaximumPublicResultBytes)
	if err != nil {
		return protocol.NormalizeResult{}, err
	}
	// Validate the whole response before classifying refusal. Otherwise malformed
	// accepted facts or correlation could masquerade as a semantic decision.
	result, err := protocol.DecodeNormalizeResult(resultBody)
	if err == nil {
		err = protocol.ValidateNormalizeResult(id, request, result)
	}
	if err != nil {
		return protocol.NormalizeResult{}, errors.Join(ErrProcess, err)
	}
	if !result.Accepted {
		return protocol.NormalizeResult{}, ErrPassiveRefused
	}
	if result.Destination.ConfigContractID != v.config.Installation.artifact.ConfigContractID {
		return protocol.NormalizeResult{}, errors.Join(ErrProcess, protocol.ErrProtocol)
	}
	return result, nil
}

// ValidateCanonical checks the exact destination through the captured build.
// The plugin owns its semantic interpretation; the host checks reply binding.
func (v *PublicValidator) ValidateCanonical(ctx context.Context, request protocol.CanonicalRequest) (response protocol.CanonicalResult, resultErr error) {
	call := telemetry.Start(ctx, telemetry.ProviderOutputHost, telemetry.OpOutputHostPublicCheck)
	defer func() { finishOutputCall(call, resultErr, nil) }()
	ctx = telemetry.CallContext(ctx, call)
	body, err := protocol.EncodeCanonicalRequest(request)
	if err != nil {
		return protocol.CanonicalResult{}, err
	}
	id, resultBody, err := v.exchange(ctx, request.DeadlineUnixMillis, protocol.KindCanonicalRequest, protocol.KindCanonicalResult, body, nil, protocol.MaximumPublicResultBytes)
	if err != nil {
		return protocol.CanonicalResult{}, err
	}
	result, err := protocol.DecodeCanonicalResult(resultBody)
	if err == nil {
		err = protocol.ValidateCanonicalResult(id, request, result)
	}
	if err != nil {
		return protocol.CanonicalResult{}, errors.Join(ErrProcess, err)
	}
	if !result.Accepted {
		return protocol.CanonicalResult{}, ErrPassiveRefused
	}
	return result, nil
}

// InterpretTarget obtains one bounded target for the exact destination,
// entry and encoding. Acceptance does not authenticate a service resource.
func (v *PublicValidator) InterpretTarget(ctx context.Context, request protocol.InterpretRequest) (response protocol.InterpretResult, resultErr error) {
	call := telemetry.Start(ctx, telemetry.ProviderOutputHost, telemetry.OpOutputHostPublicCheck)
	defer func() { finishOutputCall(call, resultErr, nil) }()
	ctx = telemetry.CallContext(ctx, call)
	body, err := protocol.EncodeInterpretRequest(request)
	if err != nil {
		return protocol.InterpretResult{}, err
	}
	id, resultBody, err := v.exchange(ctx, request.DeadlineUnixMillis, protocol.KindInterpretRequest, protocol.KindInterpretResult, body, nil, protocol.MaximumPublicResultBytes)
	if err != nil {
		return protocol.InterpretResult{}, err
	}
	result, err := protocol.DecodeInterpretResult(resultBody)
	if err == nil {
		err = protocol.ValidateInterpretResponse(id, request, result)
	}
	if err != nil {
		return protocol.InterpretResult{}, errors.Join(ErrProcess, err)
	}
	if !result.Accepted {
		return protocol.InterpretResult{}, ErrPassiveRefused
	}
	return result, nil
}

// CheckAction checks public target, policy and ownership facts for one action
// without opening a credential or payload channel. It grants no send permission.
func (v *PublicValidator) CheckAction(ctx context.Context, request protocol.ActionCheckRequest, policy protocol.Policy) (response protocol.ActionCheckResult, resultErr error) {
	call := telemetry.Start(ctx, telemetry.ProviderOutputHost, telemetry.OpOutputHostPublicCheck)
	defer func() { finishOutputCall(call, resultErr, nil) }()
	ctx = telemetry.CallContext(ctx, call)
	body, err := protocol.EncodeActionCheckRequest(request)
	if err != nil {
		return protocol.ActionCheckResult{}, err
	}
	if err := protocol.ValidateActionCheckPolicy(request, policy); err != nil {
		return protocol.ActionCheckResult{}, err
	}
	if v == nil || request.DescriptorID != v.config.Installation.artifact.DescriptorID {
		return protocol.ActionCheckResult{}, ErrAdmission
	}
	id, resultBody, err := v.exchange(ctx, request.DeadlineUnixMillis, protocol.KindActionCheckRequest, protocol.KindActionCheckResult, body, policy.Data, protocol.MaximumActionCheckResultBytes)
	if err != nil {
		return protocol.ActionCheckResult{}, err
	}
	result, err := protocol.DecodeActionCheckResult(resultBody)
	if err == nil {
		err = protocol.ValidateActionCheckResponse(id, request, policy, result)
	}
	if err != nil {
		return protocol.ActionCheckResult{}, errors.Join(ErrProcess, err)
	}
	if !result.Accepted {
		return protocol.ActionCheckResult{}, ErrPassiveRefused
	}
	return result, nil
}

// SelectPolicyAction asks the captured plugin which existing action carries the
// desired policy. It opens no credential or value channel.
func (v *PublicValidator) SelectPolicyAction(ctx context.Context, request protocol.PolicyActionRequest, policy protocol.Policy) (response protocol.PolicyActionResult, resultErr error) {
	call := telemetry.Start(ctx, telemetry.ProviderOutputHost, telemetry.OpOutputHostPublicCheck)
	defer func() { finishOutputCall(call, resultErr, nil) }()
	ctx = telemetry.CallContext(ctx, call)
	body, err := protocol.EncodePolicyActionRequest(request)
	if err != nil {
		return protocol.PolicyActionResult{}, err
	}
	if err := protocol.ValidatePolicyActionPolicy(request, policy); err != nil {
		return protocol.PolicyActionResult{}, err
	}
	if v == nil || request.DescriptorID != v.config.Installation.artifact.DescriptorID {
		return protocol.PolicyActionResult{}, ErrAdmission
	}
	id, resultBody, err := v.exchange(ctx, request.DeadlineUnixMillis, protocol.KindPolicyActionRequest, protocol.KindPolicyActionResult, body, policy.Data, protocol.MaximumPolicyActionResultBytes)
	if err != nil {
		return protocol.PolicyActionResult{}, err
	}
	result, err := protocol.DecodePolicyActionResult(resultBody)
	if err == nil {
		err = protocol.ValidatePolicyActionResponse(id, request, policy, result)
	}
	if err != nil {
		return protocol.PolicyActionResult{}, errors.Join(ErrProcess, err)
	}
	if !result.Accepted {
		return protocol.PolicyActionResult{}, ErrPassiveRefused
	}
	return result, nil
}

func (v *PublicValidator) exchange(ctx context.Context, deadlineMillis uint64, kind, resultKind uint8, body, policy []byte, maximum uint32) (id protocol.ID, result []byte, err error) {
	if v == nil || ctx == nil {
		return id, nil, ErrAdmission
	}
	deadline := time.UnixMilli(int64(deadlineMillis))
	if !time.Now().Before(deadline) {
		return id, nil, context.DeadlineExceeded
	}
	callCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if err := callCtx.Err(); err != nil {
		return id, nil, err
	}
	if _, err := rand.Read(id[:]); err != nil {
		return id, nil, errors.Join(ErrAdmission, err)
	}
	result, err = v.runPublic(callCtx, id, kind, resultKind, body, policy, maximum)
	if err != nil {
		err = errors.Join(ErrProcess, err)
	}
	if callErr := callCtx.Err(); callErr != nil {
		return id, nil, errors.Join(callErr, err)
	}
	return id, result, err
}

func (v *PublicValidator) runPublic(ctx context.Context, checkID protocol.ID, kind, resultKind uint8, requestBody, policyBody []byte, maximum uint32) (result []byte, err error) {
	stage, executable, err := v.preparePublicInvocation(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cleanupErr := stage.close(); cleanupErr != nil {
			result = nil
			err = errors.Join(err, cleanupErr)
		}
	}()
	controlR, controlW, err := acquirePipe(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := releaseEndpoints(controlR, controlW); closeErr != nil {
			result = nil
			err = errors.Join(err, closeErr)
		}
	}()
	resultR, resultW, err := acquirePipe(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := releaseEndpoints(resultR, resultW); closeErr != nil {
			result = nil
			err = errors.Join(err, closeErr)
		}
	}()
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := null.Close(); closeErr != nil {
			result = nil
			err = errors.Join(err, closeErr)
		}
	}()
	cmd, err := startNativeChild(ctx, executable, stage.path, "output-public-v3", []*os.File{null, null, null, controlR.File, resultW.File})
	if err != nil {
		return nil, errors.Join(ErrProcess, err)
	}

	cmd.WatchCancellation(ctx)
	joined := false
	defer func() {
		if !joined {
			cancelCall := telemetry.Start(ctx, telemetry.ProviderOutputHost, telemetry.OpOutputHostCancel)
			killErr := cmd.Process.Kill()
			killed := killErr == nil
			if errors.Is(killErr, os.ErrProcessDone) {
				cancelCall.Finish(telemetry.ResultUnchanged)
				killErr = nil
			} else {
				finishOutputCall(cancelCall, killErr, nil)
			}
			joinCall := telemetry.Start(ctx, telemetry.ProviderOutputHost, telemetry.OpOutputHostJoin)
			waitErr := cmd.Wait()
			finishOutputJoin(joinCall, waitErr, ctx.Err(), killed)
			err = errors.Join(err, killErr, waitErr)
		}
	}()
	if err := releaseEndpoints(controlR, resultW); err != nil {
		return nil, err
	}
	handshakeCall := telemetry.Start(ctx, telemetry.ProviderOutputHost, telemetry.OpOutputHostHandshake)
	hello := protocol.Hello{ProtocolID: v.config.Installation.artifact.ProtocolID,
		DescriptorID: v.config.Installation.artifact.DescriptorID, ArtifactContractID: v.config.Installation.artifact.ArtifactContractID}
	helloBody, err := protocol.EncodeHello(hello)
	if err != nil {
		finishOutputCall(handshakeCall, err, nil)
		return nil, err
	}
	if err := protocol.WriteFrame(controlW, protocol.Frame{Kind: protocol.KindHello, CorrelationID: checkID, Body: helloBody}); err != nil {
		finishOutputCall(handshakeCall, err, nil)
		return nil, err
	}
	ackBody, err := protocol.ReadExpectedFrame(resultR, protocol.KindHelloAck, checkID, protocol.HelloBytes)
	if err != nil {
		finishOutputCall(handshakeCall, err, nil)
		return nil, err
	}
	ack, err := protocol.DecodeHello(ackBody)
	if err != nil || ack != hello {
		finishOutputCall(handshakeCall, ErrAdmission, nil)
		return nil, ErrAdmission
	}
	finishOutputCall(handshakeCall, nil, nil)
	commandCall := telemetry.Start(ctx, telemetry.ProviderOutputHost, telemetry.OpOutputHostCommandSend)
	if err := protocol.WriteFrame(controlW, protocol.Frame{Kind: kind, CorrelationID: checkID, Body: requestBody}); err != nil {
		finishOutputCall(commandCall, err, nil)
		return nil, err
	}
	if kind == protocol.KindActionCheckRequest || kind == protocol.KindPolicyActionRequest {
		if err := protocol.WriteFrame(controlW, protocol.Frame{Kind: protocol.KindPolicy, CorrelationID: checkID, Body: policyBody}); err != nil {
			finishOutputCall(commandCall, err, nil)
			return nil, err
		}
	}
	if err := controlW.release(); err != nil {
		finishOutputCall(commandCall, err, nil)
		return nil, err
	}
	finishOutputCall(commandCall, nil, nil)
	readCall := telemetry.Start(ctx, telemetry.ProviderOutputHost, telemetry.OpOutputHostResultRead)
	result, err = protocol.ReadExpectedFrame(resultR, resultKind, checkID, maximum)
	if err != nil {
		finishOutputCall(readCall, err, nil)
		return nil, err
	}
	if err == nil {
		err = protocol.RequireEOF(resultR)
	}
	if err != nil {
		finishOutputCall(readCall, err, nil)
		return nil, err
	}
	finishOutputCall(readCall, nil, nil)
	joinCall := telemetry.Start(ctx, telemetry.ProviderOutputHost, telemetry.OpOutputHostJoin)
	if waitErr := cmd.Wait(); waitErr != nil {
		joined = true
		finishOutputJoin(joinCall, waitErr, ctx.Err(), false)
		return nil, errors.Join(ErrProcess, waitErr)
	}
	joined = true
	finishOutputJoin(joinCall, nil, nil, false)
	return result, nil
}

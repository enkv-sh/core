package outputhost

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/output"
	"enkv.sh/telemetry"
)

// These sentinels support errors.Is. ErrPassiveRefused means a valid passive
// refusal after response validation and process join. ErrProcess is incomplete
// execution evidence; neither a process error nor ErrCredential grants a resend.
var (
	ErrCredential     = errors.New("output credential refused")
	ErrPassiveRefused = errors.New("output passive request refused")
	ErrProcess        = errors.New("output process failed")
	errStagingCleanup = errors.New("output staging cleanup failed")
)

type dispatchProof uint8

const (
	dispatchUnqualified dispatchProof = iota
	dispatchNotStarted
	dispatchPreparationRefused
	dispatchComplete
)

type checkedDispatchFailure struct {
	result protocol.Result
	cause  error
}

func (e *checkedDispatchFailure) Error() string { return e.cause.Error() }
func (e *checkedDispatchFailure) Unwrap() error { return e.cause }

// PreservesResult recognizes only this host's complete qualification of the
// exact returned result. Wrapping or joining another failure invalidates it.
func PreservesResult(result protocol.Result, err error) bool {
	failure, ok := err.(*checkedDispatchFailure)
	return ok && failure != nil && failure.result == result
}

func notEnteredResult(command protocol.Command) protocol.Result {
	result := command.NewResult()
	result.Entry, result.Class = protocol.EntryNotEntered, protocol.ClassQualifiedNoEffect
	return result
}

// Config selects an absolute executable path and its authenticated installation
// expectation. The host rechecks the executable at construction and dispatch.
type Config struct {
	ArtifactPath string
	Installation *Installation
}

// Native owns one action's process and private input lifetime.
type Native struct {
	config Config
	mu     sync.Mutex
	used   bool
}

// Installation returns the shared immutable installation expectation.
// A nil Native returns nil.
func (n *Native) Installation() *Installation {
	if n == nil {
		return nil
	}
	return n.config.Installation
}

// NewNative verifies installed bytes and build facts without credentials or
// child execution. The returned owner permits one Dispatch attempt; its zero
// value is not usable.
// The required context controls construction at the file-operation boundaries.
func NewNative(ctx context.Context, config Config) (*Native, error) {
	if !config.Installation.valid() || !filepath.IsAbs(config.ArtifactPath) {
		return nil, ErrAdmission
	}
	if err := VerifyInstalledArtifact(ctx, config.ArtifactPath, config.Installation); err != nil {
		return nil, err
	}
	return &Native{config: config}, nil
}

// Dispatch borrows policy and payload until return; callers must not mutate
// their backing during the call. Command admission consumes the attempt. It
// authenticates the launch copy before capturing credentials and joins every
// started child before return. Failure after possible entry preserves uncertainty.
func (n *Native) Dispatch(ctx context.Context, command protocol.Command, policy protocol.Policy, payload []byte) (protocol.Result, error) {
	call := telemetry.Start(ctx, telemetry.ProviderOutputHost, telemetry.OpOutputHostDispatch)
	result, err := n.dispatch(telemetry.CallContext(ctx, call), command, policy, payload)
	finishOutputCall(call, err, &result)
	return result, err
}

func (n *Native) dispatch(ctx context.Context, command protocol.Command, policy protocol.Policy, payload []byte) (result protocol.Result, err error) {
	if n == nil || ctx == nil {
		return protocol.Result{}, ErrAdmission
	}
	n.mu.Lock()
	if n.used {
		n.mu.Unlock()
		return protocol.Result{}, ErrAdmission
	}
	n.used = true
	n.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return protocol.Result{}, err
	}
	if command.DescriptorID != n.config.Installation.artifact.DescriptorID ||
		command.CredentialRouteID != n.config.Installation.artifact.CredentialRouteID ||
		int(command.PayloadLength) != len(payload) || len(payload) > protocol.MaximumPayloadBytes ||
		protocol.ValidatePolicy(command, policy) != nil {
		return protocol.Result{}, ErrAdmission
	}
	commandBody, err := protocol.EncodeCommand(command)
	if err != nil {
		return protocol.Result{}, err
	}
	policyBody, err := protocol.EncodePolicy(policy)
	if err != nil {
		return protocol.Result{}, err
	}
	deadline := time.UnixMilli(int64(command.DeadlineUnixMillis))
	if !time.Now().Before(deadline) {
		return protocol.Result{}, context.DeadlineExceeded
	}
	callCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	callDeadline, _ := callCtx.Deadline()
	var stage *artifactStage
	var cleanupErr error
	proof := dispatchNotStarted
	defer func() {
		removalErr, resourceErr := stage.closeOutcome()
		err = errors.Join(err, removalErr, resourceErr)
		if callErr := callCtx.Err(); callErr != nil {
			err = errors.Join(err, callErr)
			proof = dispatchUnqualified
		} else if !time.Now().Before(callDeadline) {
			err = errors.Join(err, context.DeadlineExceeded)
			proof = dispatchUnqualified
		}
		qualified := cleanupErr == nil && resourceErr == nil
		switch proof {
		case dispatchNotStarted, dispatchPreparationRefused:
			qualified = qualified && removalErr == nil
			if qualified {
				result = notEnteredResult(command)
			}
		case dispatchComplete:
		default:
			qualified = false
		}
		if !qualified {
			result = protocol.Result{}
		} else if err != nil {
			err = &checkedDispatchFailure{result: result, cause: err}
		}
	}()
	stage, cleanupErr, err = stageInstallation(callCtx, n.config.ArtifactPath, n.config.Installation)
	if err != nil {
		return protocol.Result{}, err
	}
	route, err := n.config.Installation.CredentialRoute()
	if err != nil {
		return protocol.Result{}, err
	}
	credentialBody, err := captureEnvironment(callCtx, route)
	if err != nil {
		return protocol.Result{}, errors.Join(ErrCredential, err, callCtx.Err())
	}
	defer clear(credentialBody)
	result, proof, err = n.run(callCtx, stage, command, commandBody, policyBody, credentialBody, payload)
	return result, err
}

func (n *Native) run(ctx context.Context, stage *artifactStage, command protocol.Command, commandBody, policyBody, credentialBody, payload []byte) (result protocol.Result, proof dispatchProof, err error) {
	proof = dispatchNotStarted
	var controlR, controlW, credentialR, credentialW, payloadR, payloadW, resultR, resultW *ownedEndpoint
	var null *os.File
	defer func() {
		if closeErr := errors.Join(releaseEndpoints(controlR, controlW, credentialR, credentialW, payloadR, payloadW, resultR, resultW), closeOwnedFiles(&null)); closeErr != nil {
			result, proof = protocol.Result{}, dispatchUnqualified
			err = errors.Join(err, closeErr)
		}
	}()
	controlR, controlW, err = acquirePipe(ctx)
	if err != nil {
		return protocol.Result{}, proof, err
	}
	credentialR, credentialW, err = acquirePipe(ctx)
	if err != nil {
		return protocol.Result{}, proof, err
	}
	payloadR, payloadW, err = acquirePipe(ctx)
	if err != nil {
		return protocol.Result{}, proof, err
	}
	resultR, resultW, err = acquirePipe(ctx)
	if err != nil {
		return protocol.Result{}, proof, err
	}
	null, err = os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return protocol.Result{}, proof, err
	}
	proof = dispatchUnqualified
	cmd, err := startNativeChild(ctx, stage.target, stage.path, "output-wire-v6", []*os.File{null, null, null, controlR.File, credentialR.File, payloadR.File, resultW.File})
	if err != nil {
		return protocol.Result{}, proof, fmt.Errorf("%w: start: %w", ErrProcess, err)
	}

	cmd.WatchCancellation(ctx)
	// The parent must not retain child pipe ends. Deferred Wait always joins a
	// started child before any borrowed payload is released to the caller.
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
	if err := releaseEndpoints(controlR, credentialR, payloadR, resultW); err != nil {
		return protocol.Result{}, proof, err
	}
	handshakeCall := telemetry.Start(ctx, telemetry.ProviderOutputHost, telemetry.OpOutputHostHandshake)
	hello := protocol.Hello{ProtocolID: n.config.Installation.artifact.ProtocolID, DescriptorID: n.config.Installation.artifact.DescriptorID,
		ArtifactContractID: n.config.Installation.artifact.ArtifactContractID}
	helloBody, err := protocol.EncodeHello(hello)
	if err != nil {
		finishOutputCall(handshakeCall, err, nil)
		return protocol.Result{}, proof, err
	}
	if err := protocol.WriteFrame(controlW, protocol.Frame{Kind: protocol.KindHello, CorrelationID: command.AttemptID, Body: helloBody}); err != nil {
		finishOutputCall(handshakeCall, err, nil)
		return protocol.Result{}, proof, err
	}
	ackBody, err := protocol.ReadExpectedFrame(resultR, protocol.KindHelloAck, command.AttemptID, protocol.HelloBytes)
	if err != nil {
		finishOutputCall(handshakeCall, err, nil)
		return protocol.Result{}, proof, err
	}
	ack, err := protocol.DecodeHello(ackBody)
	if err != nil || ack != hello {
		finishOutputCall(handshakeCall, ErrAdmission, nil)
		return protocol.Result{}, proof, ErrAdmission
	}
	finishOutputCall(handshakeCall, nil, nil)
	commandCall := telemetry.Start(ctx, telemetry.ProviderOutputHost, telemetry.OpOutputHostCommandSend)
	if err := protocol.WriteFrame(controlW, protocol.Frame{Kind: protocol.KindCommand, CorrelationID: command.AttemptID, Body: commandBody}); err != nil {
		finishOutputCall(commandCall, err, nil)
		return protocol.Result{}, proof, err
	}
	if err := protocol.WriteFrame(controlW, protocol.Frame{Kind: protocol.KindPolicy, CorrelationID: command.AttemptID, Body: policyBody}); err != nil {
		finishOutputCall(commandCall, err, nil)
		return protocol.Result{}, proof, err
	}
	if err := controlW.release(); err != nil {
		finishOutputCall(commandCall, err, nil)
		return protocol.Result{}, proof, err
	}
	finishOutputCall(commandCall, nil, nil)
	credentialCall := telemetry.Start(ctx, telemetry.ProviderOutputHost, telemetry.OpOutputHostCredentialGate)
	if err := protocol.WriteFrame(credentialW, protocol.Frame{Kind: protocol.KindCredential, CorrelationID: command.AttemptID, Body: credentialBody}); err != nil {
		finishOutputCall(credentialCall, err, nil)
		return protocol.Result{}, proof, err
	}
	if err := credentialW.release(); err != nil {
		finishOutputCall(credentialCall, err, nil)
		return protocol.Result{}, proof, err
	}
	gate, err := protocol.ReadFrame(resultR, 0)
	if err != nil {
		finishOutputCall(credentialCall, ErrProcess, nil)
		return protocol.Result{}, proof, errors.Join(ErrProcess, err)
	}
	if gate.CorrelationID != command.AttemptID {
		finishOutputCall(credentialCall, protocol.ErrProtocol, nil)
		return protocol.Result{}, proof, protocol.ErrProtocol
	}
	if gate.Kind == protocol.KindPreparationRefused {
		if err := protocol.RequireEOF(resultR); err != nil {
			finishOutputCall(credentialCall, protocol.ErrProtocol, nil)
			return protocol.Result{}, proof, protocol.ErrProtocol
		}
		joinCall := telemetry.Start(ctx, telemetry.ProviderOutputHost, telemetry.OpOutputHostJoin)
		if waitErr := cmd.Wait(); waitErr != nil {
			joined = true
			finishOutputJoin(joinCall, waitErr, ctx.Err(), false)
			finishOutputCall(credentialCall, ErrProcess, nil)
			return protocol.Result{}, proof, errors.Join(ErrProcess, waitErr)
		}
		joined = true
		finishOutputJoin(joinCall, nil, nil, false)
		finishOutputCall(credentialCall, ErrCredential, nil)
		return notEnteredResult(command), dispatchPreparationRefused, ErrCredential
	}
	if gate.Kind != protocol.KindReadyForPayload {
		finishOutputCall(credentialCall, protocol.ErrProtocol, nil)
		return protocol.Result{}, proof, protocol.ErrProtocol
	}
	finishOutputCall(credentialCall, nil, nil)
	if err := ctx.Err(); err != nil {
		return protocol.Result{}, proof, err
	}
	kind := protocol.KindArm
	if command.PayloadLengthMode == protocol.LengthExact {
		kind = protocol.KindPayload
	}
	if err := protocol.WriteFrame(payloadW, protocol.Frame{Kind: kind, CorrelationID: command.AttemptID, Body: payload}); err != nil {
		return protocol.Result{}, proof, err
	}
	if err := payloadW.release(); err != nil {
		return protocol.Result{}, proof, err
	}
	readCall := telemetry.Start(ctx, telemetry.ProviderOutputHost, telemetry.OpOutputHostResultRead)
	resultBody, err := protocol.ReadExpectedFrame(resultR, protocol.KindResult, command.AttemptID, protocol.MaximumResultBytes)
	if err != nil {
		finishOutputCall(readCall, err, nil)
		return protocol.Result{}, proof, err
	}
	result, err = protocol.DecodeResult(resultBody)
	if err == nil {
		err = protocol.ValidateResult(command, result)
	}
	if err == nil {
		err = protocol.RequireEOF(resultR)
	}
	if err != nil {
		finishOutputCall(readCall, err, nil)
		return protocol.Result{}, proof, err
	}
	finishOutputCall(readCall, nil, &result)
	joinCall := telemetry.Start(ctx, telemetry.ProviderOutputHost, telemetry.OpOutputHostJoin)
	if waitErr := cmd.Wait(); waitErr != nil {
		joined = true
		finishOutputJoin(joinCall, waitErr, ctx.Err(), false)
		return protocol.Result{}, proof, fmt.Errorf("%w: join: %w", ErrProcess, waitErr)
	}
	joined = true
	finishOutputJoin(joinCall, nil, nil, false)
	return result, dispatchComplete, nil
}

func captureEnvironment(ctx context.Context, route credentialroute.Route) ([]byte, error) {
	inputs := make([]credentialroute.Input, len(route.Names))
	defer func() {
		for _, input := range inputs {
			clear(input.Value)
		}
	}()
	n := 3
	for i, name := range route.Names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		value, present := os.LookupEnv(name)
		n += 6 + len(name) + len(value)
		if n > credentialroute.MaxInputsBytes {
			return nil, ErrCredential
		}
		inputs[i] = credentialroute.Input{Name: name, Present: present, Value: []byte(value)}
	}
	body, err := credentialroute.EncodeInputs(route, inputs)
	if err != nil {
		return nil, errors.Join(ErrCredential, err)
	}
	if err := ctx.Err(); err != nil {
		clear(body)
		return nil, err
	}
	return body, nil
}

func closeOwnedFiles(files ...**os.File) error {
	var result error
	for _, file := range files {
		owned := *file
		*file = nil
		if owned != nil {
			result = errors.Join(result, owned.Close())
		}
	}
	return result
}

type ownedEndpoint struct {
	*os.File
	closeOnce   sync.Once
	releaseOnce sync.Once
	closeErr    error
	stop        func() bool
	done        chan struct{}
}

func ownEndpoint(ctx context.Context, file *os.File) *ownedEndpoint {
	if file == nil {
		return nil
	}
	endpoint := &ownedEndpoint{File: file, done: make(chan struct{})}
	if ctx != nil {
		endpoint.stop = context.AfterFunc(ctx, func() {
			defer close(endpoint.done)
			_ = endpoint.close() // release returns the stored close error after joining this callback.
		})
	}
	return endpoint
}

func acquirePipe(ctx context.Context) (*ownedEndpoint, *ownedEndpoint, error) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	return ownEndpoint(ctx, reader), ownEndpoint(ctx, writer), nil
}

func (endpoint *ownedEndpoint) close() error {
	if endpoint == nil {
		return nil
	}
	endpoint.closeOnce.Do(func() { endpoint.closeErr = endpoint.Close() })
	return endpoint.closeErr
}

func (endpoint *ownedEndpoint) release() error {
	if endpoint == nil {
		return nil
	}
	endpoint.releaseOnce.Do(func() {
		if endpoint.stop != nil && !endpoint.stop() {
			<-endpoint.done
		}
		_ = endpoint.close() // closeErr is returned after the once-only release completes.
	})
	return endpoint.closeErr
}

func releaseEndpoints(endpoints ...*ownedEndpoint) error {
	var result error
	for _, endpoint := range endpoints {
		result = errors.Join(result, endpoint.release())
	}
	return result
}

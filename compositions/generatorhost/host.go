package generatorhost

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/generator"
	"enkv.sh/telemetry"
	"golang.org/x/sys/unix"
)

const (
	parentWorkspaceBytes = 4 << 20
	childWorkspaceBytes  = 8 << 20
	nativePipeFrameCount = 4
)

// These sentinels classify host failures for errors.Is. A process or credential
// error does not establish whether a managed effect occurred.
var (
	ErrAdmission  = errors.New("generator host admission refused")
	ErrProcess    = errors.New("generator process failed")
	ErrCredential = errors.New("generator credential refused")

	errStagingCleanup = errors.New("generator staging cleanup failed")
)

type checkedHostFailure struct {
	commandBinding [32]byte
	command        protocol.ID
	status         protocol.Status
	notStarted     bool
	cause          error
}

func (e *checkedHostFailure) Error() string { return e.cause.Error() }
func (e *checkedHostFailure) Unwrap() error { return e.cause }

// ProvesNotStarted accepts only this host's clean no-child proof for command.
// Wrapping or joining another failure invalidates the qualification.
func ProvesNotStarted(command protocol.Command, err error) bool {
	failure, ok := err.(*checkedHostFailure)
	if !ok || failure == nil || !failure.notStarted {
		return false
	}
	body, encodeErr := protocol.EncodeCommand(command)
	if encodeErr != nil {
		return false
	}
	defer clear(body[:cap(body)])
	return failure.commandBinding == sha256.Sum256(body)
}

// PreservesCompletion accepts only this host's sole-removal qualification for
// the exact command and Return/OK status. Crypto still validates result bytes.
func PreservesCompletion(original protocol.Command, command protocol.ID, status protocol.Status, err error) bool {
	failure, ok := err.(*checkedHostFailure)
	if !ok || failure == nil || failure.notStarted || command.IsZero() || failure.command != command || failure.status != status ||
		status != (protocol.Status{Stage: protocol.StatusStageReturn, Category: protocol.StatusOK}) {
		return false
	}
	body, encodeErr := protocol.EncodeCommand(original)
	if encodeErr != nil {
		return false
	}
	defer clear(body[:cap(body)])
	return failure.commandBinding == sha256.Sum256(body)
}

// ParentFixedOwnedBytes and ChildFixedOwnedBytes bound the fixed controlled
// backing allowance for one exchange. They are not heap or RSS limits.
const (
	ParentFixedOwnedBytes = 2*protocol.MaximumCommandBody + 2*protocol.MaximumEnvironmentBody +
		protocol.MaximumResultBody + nativePipeFrameCount*protocol.HeaderLength + parentWorkspaceBytes
	ChildFixedOwnedBytes = protocol.MaximumCommandBody + protocol.MaximumEnvironmentBody + protocol.MaximumResultBody +
		protocol.HelloBodyLength + protocol.StatusBodyLength + nativePipeFrameCount*protocol.HeaderLength + childWorkspaceBytes
)

// Config binds an absolute executable path to one admitted installation.
// Artifact must match Installation exactly; neither field grants effect authority.
type Config struct {
	Installation *Installation
	ArtifactPath string
	Artifact     contract.GeneratorImplementation
}

// Run owns a started child until Wait or Cancel completes. The caller must
// drain or close its result reader and then settle the run on every path.
type Run interface {
	CommandID() protocol.ID
	// Wait returns a status only after its complete stream and native disposal
	// settle. A joined nonzero child exit remains an error alongside that status.
	Wait(context.Context) (protocol.Status, error)
	// Cancel stops and joins the child and completes private disposal.
	Cancel() error
}

// Launcher starts an admitted generator command and transfers result-pipe
// ownership to its run. Each native launcher permits only one start attempt.
type Launcher interface {
	Implementation() contract.GeneratorImplementation
	// Start consumes the result writer on every return. The caller owns the read end.
	Start(context.Context, protocol.Command, *os.File) (Run, error)
}

// NativeLauncher holds one exact build and one start opportunity. Construct
// it with NewNative or NewNativeForInvocation; its zero value is not usable.
type NativeLauncher struct {
	config      Config
	invocation  *InvocationCredentials
	commandSent chan struct{}
	commandOnce sync.Once
	startMu     sync.Mutex
	started     bool

	// Hooks are used only by same-package failure tests. They are not
	// reachable through Config or the production constructor.
	beforeSourceCopy func(context.Context)
	afterSourceCopy  func()
	afterSourceCheck func()
	removeLaunchDir  func(string) error
}

// NewNative checks the installation, native tuple and executable build facts
// without reading credentials or starting a child. It copies the credential route.
// The required context controls construction at the file-operation boundaries.
func NewNative(ctx context.Context, config Config) (*NativeLauncher, error) {
	if ctx == nil {
		return nil, ErrAdmission
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	launcher, err := newNative(config, true)
	if err != nil {
		return nil, err
	}
	if err := verifyArtifactBuildInfo(ctx, config.ArtifactPath, config.Installation); err != nil {
		return nil, errors.Join(ErrAdmission, err)
	}
	return launcher, nil
}

func newHermeticNative(config Config) (*NativeLauncher, error) {
	if !validBoundImplementation(config.Artifact) {
		return nil, ErrAdmission
	}
	return newNative(config, false)
}

func newNative(config Config, requireInstalled bool) (*NativeLauncher, error) {
	if requireInstalled && (config.Installation == nil || !config.Installation.validRuntime(config.Artifact)) {
		return nil, ErrAdmission
	}
	if config.Artifact.Validate() != nil || config.Artifact.NativeTuple != runtime.GOOS+"/"+runtime.GOARCH || !filepath.IsAbs(config.ArtifactPath) {
		return nil, ErrAdmission
	}
	config.Artifact.CredentialRoute = append([]byte(nil), config.Artifact.CredentialRoute...)
	return &NativeLauncher{config: config, commandSent: make(chan struct{})}, nil
}

func verifyArtifactBuildInfo(ctx context.Context, path string, installed *Installation) (resultErr error) {
	if installed == nil {
		return ErrAdmission
	}
	setup := &nativeSetup{context: ctx}
	defer func() {
		if err := setup.cleanup(); err != nil {
			resultErr = errors.Join(resultErr, ErrArtifactUnavailable, err)
		}
		if ctx != nil {
			resultErr = errors.Join(resultErr, ctx.Err())
		}
	}()
	if _, err := setup.sealedArtifactCopy(path, installed.artifact, nil, nil, nil); err != nil {
		return err
	}
	info, err := buildinfo.Read(io.NewSectionReader(artifactFileReader{ctx, setup.stage.executable}, 0, int64(installed.artifact.ArtifactLength)))
	if err != nil {
		return errors.Join(ErrAdmission, ErrArtifactIncompatible, err)
	}
	if err := installed.verifyBuildInfo(info); err != nil {
		return errors.Join(ErrAdmission, ErrArtifactIncompatible, err)
	}
	return nil
}

// Implementation returns the captured build with an independent credential
// route. A nil launcher returns a zero implementation.
func (l *NativeLauncher) Implementation() contract.GeneratorImplementation {
	if l == nil {
		return contract.GeneratorImplementation{}
	}
	row := l.config.Artifact
	row.CredentialRoute = append([]byte(nil), row.CredentialRoute...)
	return row
}

func hostResult(err error) telemetry.Result {
	switch {
	case err == nil:
		return telemetry.ResultSuccess
	case errors.Is(err, errStagingCleanup):
		return telemetry.ResultEvidenceUnavailable
	case errors.Is(err, context.Canceled):
		return telemetry.ResultCancelled
	case errors.Is(err, context.DeadlineExceeded):
		return telemetry.ResultExpired
	case errors.Is(err, ErrAdmission):
		return telemetry.ResultAdmissionRefused
	case errors.Is(err, ErrCredential):
		return telemetry.ResultDenied
	case errors.Is(err, ErrProcess):
		return telemetry.ResultFailure
	default:
		return telemetry.ResultEvidenceUnavailable
	}
}

func finishHostCall(call *telemetry.Call, err error) {
	if err != nil {
		details := telemetry.DiagnosticDetails{}
		switch {
		case errors.Is(err, errStagingCleanup):
			details = details.WithErrorFacts(telemetry.DiagnosticReasonEvidenceUnavailable, 0).WithReviewedErrorText(errStagingCleanup.Error())
		case errors.Is(err, ErrAdmission):
			details = details.WithErrorFacts(telemetry.DiagnosticReasonAdmissionRefused, 0).WithReviewedErrorText(ErrAdmission.Error())
		case errors.Is(err, ErrCredential):
			details = details.WithErrorFacts(telemetry.DiagnosticReasonDenied, 0).WithReviewedErrorText(ErrCredential.Error())
		case errors.Is(err, ErrProcess):
			details = details.WithErrorFacts(telemetry.DiagnosticReasonEvidenceUnavailable, 0).WithReviewedErrorText(ErrProcess.Error())
		case errors.Is(err, context.Canceled):
			details = details.WithErrorFacts(telemetry.DiagnosticReasonCancelled, 0).WithReviewedErrorText(context.Canceled.Error())
		case errors.Is(err, context.DeadlineExceeded):
			details = details.WithErrorFacts(telemetry.DiagnosticReasonCancelled, 0).WithReviewedErrorText(context.DeadlineExceeded.Error())
		case errors.Is(err, protocol.ErrProtocol):
			details = details.WithErrorFacts(telemetry.DiagnosticReasonInvalidFormat, 0).WithReviewedErrorText(protocol.ErrProtocol.Error())
		case errors.Is(err, protocol.ErrCapacity):
			details = details.WithErrorFacts(telemetry.DiagnosticReasonCapacityExceeded, 0).WithReviewedErrorText(protocol.ErrCapacity.Error())
		default:
			details = details.WithErrorFacts(telemetry.DiagnosticReasonEvidenceUnavailable, 0)
		}
		call.ReturnDetails(details)
	}
	call.Finish(hostResult(err))
}

// nativeSetup owns resources until they are closed or transferred to nativeRun.
type nativeSetup struct {
	// Opaque acquisition failures can contain helper-local disposal failures.
	// They cannot establish complete settlement through cleanup alone.
	settlementUnproven bool
	credentialRelease  func()
	removeLaunchDir    func(string) error
	stopContext        context.CancelFunc
	context            context.Context
	launchDir          string
	resultWriter       *ownedEndpoint
	stage              *artifactStage
	controlRead        *ownedEndpoint
	controlWrite       *ownedEndpoint
	credentialRead     *ownedEndpoint
	credentialWrite    *ownedEndpoint
	statusRead         *ownedEndpoint
	statusWrite        *ownedEndpoint
	null               *os.File
}

func (s *nativeSetup) cleanup() error {
	if s.credentialRelease != nil {
		defer s.credentialRelease()
	}
	closeErr := releaseEndpoints(s.resultWriter, s.controlRead, s.controlWrite, s.credentialRead, s.credentialWrite, s.statusRead, s.statusWrite)
	if s.null != nil {
		closeErr = errors.Join(closeErr, s.null.Close())
		s.null = nil
	}
	if s.stopContext != nil {
		s.stopContext()
	}
	if s.stage != nil && s.stage.settlementUnproven {
		s.settlementUnproven = true
	}
	err := s.stage.close()
	s.stage = nil
	return errors.Join(closeErr, err)
}

func (s *nativeSetup) childStarted() error {
	err := releaseEndpoints(s.controlRead, s.credentialRead, s.resultWriter, s.statusWrite)
	if s.null != nil {
		err = errors.Join(err, s.null.Close())
	}
	s.controlRead, s.credentialRead, s.resultWriter, s.statusWrite, s.null = nil, nil, nil, nil, nil
	return err
}

func (s *nativeSetup) abort(run *nativeRun) error {
	err := run.abort(s.controlWrite, s.credentialWrite)
	s.controlWrite, s.credentialWrite = nil, nil
	return err
}

// Start consumes secretWriter even on failure. It admits the command and
// launch copy before credential capture. On success the caller must consume the
// result stream and call Wait or Cancel; failure after entry grants no resend.
func (l *NativeLauncher) Start(ctx context.Context, command protocol.Command, secretWriter *os.File) (Run, error) {
	call := telemetry.StartWithDetails(ctx, telemetry.ProviderGeneratorHost, telemetry.OpGeneratorHostStart, telemetry.DiagnosticDetails{})
	run, err := l.start(telemetry.CallContext(ctx, call), command, secretWriter)
	finishHostCall(call, err)
	return run, err
}

func (l *NativeLauncher) start(ctx context.Context, command protocol.Command, secretWriter *os.File) (result Run, resultErr error) {
	ownedWriter := ownEndpoint(ctx, secretWriter)
	transferred := false
	defer func() {
		if !transferred {
			resultErr = errors.Join(resultErr, ownedWriter.release())
		}
	}()
	if l == nil || ctx == nil || secretWriter == nil {
		return nil, ErrAdmission
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if command.DescriptorID != protocol.ID(l.config.Artifact.DescriptorID) || command.ExecutorID != protocol.ID(l.config.Artifact.ExecutorID) || command.CredentialRouteID != protocol.ID(l.config.Artifact.CredentialRouteID) {
		return nil, ErrAdmission
	}
	commandBody, err := protocol.EncodeCommand(command)
	if err != nil {
		return nil, ErrAdmission
	}
	defer func() { clear(commandBody[:cap(commandBody)]) }()
	transferred = true
	return l.startExchange(ctx, protocol.KindCommand, command.DeadlineUnixMillis, commandBody, ownedWriter, true)
}

func (l *NativeLauncher) startExchange(ctx context.Context, kind uint8, deadlineMillis uint64, commandBody []byte, secretWriter *ownedEndpoint, effect bool) (result Run, resultErr error) {
	setup := &nativeSetup{resultWriter: secretWriter}
	consumed, notStarted := false, true
	if l != nil {
		setup.removeLaunchDir = l.removeLaunchDir
	}
	defer func() {
		if resultErr != nil && ctx != nil {
			resultErr = errors.Join(resultErr, ctx.Err())
			if setup.context != nil {
				resultErr = errors.Join(resultErr, setup.context.Err())
			}
		}
		cleanupErr := setup.cleanup()
		if cleanupErr != nil {
			resultErr = errors.Join(resultErr, cleanupErr)
		}
		if resultErr != nil && effect && consumed && notStarted && cleanupErr == nil && !setup.settlementUnproven {
			resultErr = &checkedHostFailure{commandBinding: sha256.Sum256(commandBody), notStarted: true, cause: resultErr}
		}
	}()
	if l == nil || ctx == nil || secretWriter == nil {
		return nil, ErrAdmission
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := time.Now()
	commandDeadline := boundedCommandDeadline(now, deadlineMillis)
	if !now.Before(commandDeadline) {
		return nil, context.DeadlineExceeded
	}
	launchContext, stopContext := context.WithDeadline(ctx, commandDeadline)
	setup.stopContext = stopContext
	setup.context = launchContext
	l.startMu.Lock()
	if l.started {
		l.startMu.Unlock()
		return nil, ErrAdmission
	}
	l.started = true
	consumed = true
	l.startMu.Unlock()
	if effect && l.invocation != nil {
		release, err := l.invocation.begin()
		if err != nil {
			return nil, err
		}
		setup.credentialRelease = release
	}
	if err := writeOnlyPipe(secretWriter.File); err != nil {
		return nil, err
	}
	launchPath, err := l.sealedLaunchCopy(setup)
	if err != nil {
		return nil, err
	}
	if l.config.Installation != nil {
		info, err := buildinfo.Read(io.NewSectionReader(artifactFileReader{launchContext, setup.stage.executable}, 0, int64(l.config.Artifact.ArtifactLength)))
		if err != nil {
			return nil, errors.Join(ErrAdmission, ErrArtifactIncompatible, err)
		}
		if err := l.config.Installation.verifyBuildInfo(info); err != nil {
			return nil, errors.Join(ErrAdmission, ErrArtifactIncompatible, err)
		}
	}
	commandID, err := randomProtocolID()
	if err != nil {
		return nil, err
	}
	setup.controlRead, setup.controlWrite, err = acquirePipe(launchContext)
	if err != nil {
		setup.settlementUnproven = true
		return nil, err
	}
	setup.credentialRead, setup.credentialWrite, err = acquirePipe(launchContext)
	if err != nil {
		setup.settlementUnproven = true
		return nil, err
	}
	setup.statusRead, setup.statusWrite, err = acquirePipe(launchContext)
	if err != nil {
		setup.settlementUnproven = true
		return nil, err
	}
	setup.null, err = os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		setup.settlementUnproven = true
		return nil, err
	}
	entrypoint := "generator-wire-v5"
	cmd, err := startNativeChild(launchContext, launchPath, filepath.Dir(l.config.ArtifactPath), entrypoint, []*os.File{setup.null, setup.null, setup.null, setup.controlRead.File, setup.credentialRead.File, setup.resultWriter.File, setup.statusWrite.File})
	_, notStarted = err.(*nativeStartFailure)
	if err != nil {
		return nil, errors.Join(ErrProcess, err, launchContext.Err())
	}
	commandDetails := telemetry.DiagnosticDetails{}.WithCommandID(hex.EncodeToString(commandID[:]))
	run := &nativeRun{command: commandID, cmd: cmd, status: setup.statusRead, launchDir: setup.launchDir, done: make(chan struct{}), cancelDone: make(chan struct{}), stopContext: setup.stopContext,
		telemetryContext: telemetry.PrivateContext(context.Background(), ctx), telemetryDetails: commandDetails, stage: setup.stage, credentialRelease: setup.credentialRelease, context: launchContext}
	if effect {
		run.commandBinding = sha256.Sum256(commandBody)
	}
	setup.credentialRelease = nil
	setup.statusRead, setup.launchDir, setup.stopContext, setup.stage = nil, "", nil, nil
	run.cancel = context.AfterFunc(launchContext, func() {
		defer close(run.cancelDone)
		_ = run.kill() // finish joins the stored kill error before publishing the result.
	})
	abort := func(refusal error) error {
		// Observe the launch context before Cancel stops it during cleanup.
		failure := errors.Join(refusal, launchContext.Err())
		return errors.Join(failure, setup.abort(run))
	}
	if err := setup.childStarted(); err != nil {
		return nil, abort(err)
	}
	handshake := telemetry.StartWithDetails(launchContext, telemetry.ProviderGeneratorHost, telemetry.OpGeneratorHostHandshake, commandDetails)
	hello := protocol.Hello{ProtocolID: protocolID(l.config.Artifact.ProtocolID), DescriptorID: protocolID(l.config.Artifact.DescriptorID), ArtifactContractID: protocolID(l.config.Artifact.ArtifactContractID)}
	helloBody, err := protocol.EncodeHello(hello)
	if err != nil {
		finishHostCall(handshake, err)
		return nil, abort(err)
	}
	if err := protocol.WriteFrame(setup.controlWrite, protocol.Frame{Kind: protocol.KindHello, CommandID: commandID, Body: helloBody}); err != nil {
		finishHostCall(handshake, err)
		return nil, abort(err)
	}
	reply, err := protocol.ReadExpectedFrame(run.status, protocol.KindHelloAck, commandID, protocol.HelloBodyLength)
	if err != nil {
		finishHostCall(handshake, err)
		return nil, abort(err)
	}
	ack, err := protocol.DecodeHello(reply)
	if err != nil || ack != hello {
		refusal := errors.Join(ErrAdmission, err)
		finishHostCall(handshake, refusal)
		return nil, abort(refusal)
	}
	if err := launchContext.Err(); err != nil {
		finishHostCall(handshake, err)
		return nil, abort(err)
	}
	finishHostCall(handshake, nil)
	send := telemetry.StartWithDetails(launchContext, telemetry.ProviderGeneratorHost, telemetry.OpGeneratorHostCommandSend, commandDetails)
	if err := protocol.WriteFrame(setup.controlWrite, protocol.Frame{Kind: kind, CommandID: commandID, Body: commandBody}); err != nil {
		refusal := errors.Join(ErrProcess, err)
		finishHostCall(send, refusal)
		return nil, abort(refusal)
	}
	if err := setup.controlWrite.release(); err != nil {
		finishHostCall(send, err)
		return nil, abort(err)
	}
	setup.controlWrite = nil
	if effect {
		var inputs []byte
		if l.invocation != nil {
			inputs, err = l.invocation.capture(launchContext, l.config.Artifact, l.config.Installation)
		} else {
			route, routeErr := credentialroute.Decode(l.config.Artifact.CredentialRoute)
			err = routeErr
			if err == nil {
				inputs, err = readEnvironmentInputs(launchContext, route)
			}
		}
		run.credential = inputs
		if err == nil {
			err = protocol.WriteFrame(setup.credentialWrite, protocol.Frame{Kind: protocol.KindEnvironment, CommandID: commandID, Body: inputs})
		}
		if err != nil {
			refusal := errors.Join(ErrCredential, err)
			finishHostCall(send, refusal)
			return nil, abort(refusal)
		}
	}
	if err := launchContext.Err(); err != nil {
		finishHostCall(send, err)
		return nil, abort(err)
	}
	l.commandOnce.Do(func() { close(l.commandSent) })
	finishHostCall(send, nil)
	if err := releaseEndpoints(setup.controlWrite, setup.credentialWrite); err != nil {
		return nil, abort(err)
	}
	setup.controlWrite, setup.credentialWrite = nil, nil
	return run, nil
}

// WaitCommand reports when the admitted command has crossed the native
// boundary. It exposes no command or credential bytes.
func (l *NativeLauncher) WaitCommand(ctx context.Context) bool {
	if l == nil || ctx == nil {
		return false
	}
	select {
	case <-l.commandSent:
		return true
	case <-ctx.Done():
		return false
	}
}

type nativeRun struct {
	credentialRelease func()
	credential        []byte
	stage             *artifactStage
	command           protocol.ID
	commandBinding    [32]byte
	cmd               *nativeChild
	status            *ownedEndpoint
	launchDir         string
	cancel            func() bool
	cancelDone        chan struct{}
	stopContext       context.CancelFunc
	done              chan struct{}
	context           context.Context
	killErr           error
	killMu            sync.Mutex
	settled           bool
	killOnce          sync.Once
	waitOnce          sync.Once
	result            protocol.Status
	err               error
	telemetryContext  context.Context
	telemetryDetails  telemetry.DiagnosticDetails
}

func (r *nativeRun) CommandID() protocol.ID { return r.command }

func (r *nativeRun) finish() {
	r.waitOnce.Do(func() {
		statusCall := telemetry.StartWithDetails(r.telemetryContext, telemetry.ProviderGeneratorHost, telemetry.OpGeneratorHostStatusRead, r.telemetryDetails)
		body, readErr := protocol.ReadExpectedFrame(r.status, protocol.KindStatus, r.command, protocol.StatusBodyLength)
		var result protocol.Status
		if readErr == nil {
			result, readErr = protocol.DecodeStatus(body)
		}
		if readErr == nil {
			readErr = protocol.RequireEOF(r.status)
		}
		finishHostCall(statusCall, readErr)
		closeErr := r.status.release()
		joinCall := telemetry.StartWithDetails(r.telemetryContext, telemetry.ProviderGeneratorHost, telemetry.OpGeneratorHostJoin, r.telemetryDetails)
		waitErr := r.cmd.Wait()
		if r.cancel != nil && !r.cancel() {
			<-r.cancelDone
		}
		r.killMu.Lock()
		killErr := r.killErr
		r.settled = true
		r.killMu.Unlock()
		// The child and cancellation callback can no longer use private backing.
		clear(r.credential[:cap(r.credential)])
		r.credential = nil
		removalErr, cleanupErr := r.stage.dispose()
		if r.credentialRelease != nil {
			r.credentialRelease()
			r.credentialRelease = nil
		}
		lifetimeErr := r.context.Err()
		if deadline, ok := r.context.Deadline(); ok && !time.Now().Before(deadline) {
			lifetimeErr = errors.Join(lifetimeErr, context.DeadlineExceeded)
		}
		if r.stopContext != nil {
			r.stopContext()
		}
		if readErr == nil && closeErr == nil && lifetimeErr == nil && r.cmd.ProcessState != nil && cleanupErr == nil && removalErr == nil {
			r.result = result
		}
		if waitErr != nil {
			waitErr = errors.Join(ErrProcess, waitErr)
		}
		r.err = errors.Join(readErr, closeErr, waitErr, killErr, removalErr, cleanupErr, lifetimeErr)
		if removalErr != nil && readErr == nil && closeErr == nil && waitErr == nil && killErr == nil && cleanupErr == nil && lifetimeErr == nil &&
			r.cmd.ProcessState != nil && r.cmd.ProcessState.Success() && r.commandBinding != ([32]byte{}) && result == (protocol.Status{Stage: protocol.StatusStageReturn, Category: protocol.StatusOK}) {
			r.result = result
			r.err = &checkedHostFailure{commandBinding: r.commandBinding, command: r.command, status: result, cause: r.err}
		}
		finishHostCall(joinCall, r.err)
		close(r.done)
	})
}

func (r *nativeRun) kill() error {
	r.killMu.Lock()
	defer r.killMu.Unlock()
	if r.settled {
		return nil
	}
	r.killOnce.Do(func() {
		call := telemetry.StartWithDetails(r.telemetryContext, telemetry.ProviderGeneratorHost, telemetry.OpGeneratorHostCancel, r.telemetryDetails)
		var err error
		if r.cmd.Process != nil {
			err = r.cmd.Process.Kill()
		}
		if errors.Is(err, os.ErrProcessDone) {
			err = nil
		}
		r.killErr = errors.Join(err, r.status.release())
		finishHostCall(call, r.killErr)
	})
	return r.killErr
}

func (r *nativeRun) Wait(ctx context.Context) (protocol.Status, error) {
	if r == nil || ctx == nil {
		return protocol.Status{}, ErrProcess
	}
	select {
	case <-r.done:
		return r.result, r.err
	default:
	}
	go r.finish()
	select {
	case <-ctx.Done():
		_ = r.kill() // finish includes the stored kill error in r.err.
		<-r.done
		return protocol.Status{}, errors.Join(ctx.Err(), r.err)
	case <-r.done:
		return r.result, r.err
	}
}

func (r *nativeRun) Cancel() error {
	if r == nil {
		return ErrProcess
	}
	_ = r.kill() // finish includes the stored kill error in r.err.
	r.finish()
	<-r.done
	return r.err
}

func (r *nativeRun) abort(files ...*ownedEndpoint) error {
	closeErr := releaseEndpoints(files...)
	return errors.Join(closeErr, r.Cancel())
}

func (l *NativeLauncher) sealedLaunchCopy(setup *nativeSetup) (string, error) {
	return setup.sealedArtifactCopy(l.config.ArtifactPath, l.config.Artifact, l.beforeSourceCopy, l.afterSourceCopy, l.afterSourceCheck)
}

func (setup *nativeSetup) sealedArtifactCopy(path string, implementation contract.GeneratorImplementation, beforeSourceCopy func(context.Context), afterSourceCopy, afterSourceCheck func()) (target string, resultErr error) {
	length := implementation.ArtifactLength
	if length == 0 || length > artifact.MaxExecutableBytes {
		return "", ErrAdmission
	}
	source, err := acquireRegularFile(setup.context, path)
	if err != nil {
		setup.settlementUnproven = !acquisitionSettled(err)
		if errors.Is(err, os.ErrNotExist) {
			err = errors.Join(ErrArtifactMissing, err)
		}
		return "", errors.Join(ErrAdmission, err)
	}
	defer func() {
		if err := source.close(); err != nil {
			setup.settlementUnproven = true
			resultErr = errors.Join(resultErr, ErrArtifactUnavailable, err)
		}
	}()
	if source.info.Mode().Perm()&0022 != 0 || uint64(source.info.Size()) != length {
		return "", errors.Join(ErrAdmission, ErrArtifactIdentity)
	}
	nameID, err := randomProtocolID()
	if err != nil {
		return "", err
	}
	stage, err := newTemporaryArtifactStage(setup.context, fmt.Sprintf(".launch-%x", nameID[:16]), "generator")
	if err != nil {
		setup.settlementUnproven = !acquisitionSettled(err)
		return "", err
	}
	setup.stage = stage
	stage.remove = setup.removeLaunchDir
	setup.launchDir = stage.path
	copyFile, err := openNativeAt(setup.context, stage.directory, "generator", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
	if err != nil {
		setup.settlementUnproven = !acquisitionSettled(err)
		return "", errors.Join(ErrAdmission, err)
	}
	defer func() {
		if copyFile != nil {
			closeErr := copyFile.Close()
			setup.settlementUnproven = setup.settlementUnproven || closeErr != nil
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	if beforeSourceCopy != nil {
		beforeSourceCopy(setup.context)
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(copyFile, hash), io.LimitReader(artifactFileReader{setup.context, source.file}, int64(length)+1))
	if setup.context != nil && setup.context.Err() != nil {
		return "", errors.Join(copyErr, setup.context.Err())
	}
	modeErr := copyFile.Chmod(0500)
	if setup.context != nil && setup.context.Err() != nil {
		return "", errors.Join(copyErr, modeErr, setup.context.Err())
	}
	syncErr := copyFile.Sync()
	closeErr := copyFile.Close()
	setup.settlementUnproven = setup.settlementUnproven || closeErr != nil
	copyFile = nil
	if setup.context != nil && setup.context.Err() != nil {
		return "", errors.Join(copyErr, modeErr, syncErr, closeErr, setup.context.Err())
	}
	if copyErr != nil || modeErr != nil || syncErr != nil || closeErr != nil || uint64(written) != length {
		return "", errors.Join(ErrAdmission, copyErr, modeErr, syncErr, closeErr)
	}
	var digest contract.ID
	copy(digest[:], hash.Sum(nil))
	if digest != implementation.ArtifactSHA256 {
		return "", errors.Join(ErrAdmission, ErrArtifactIdentity)
	}
	if afterSourceCopy != nil {
		afterSourceCopy()
	}
	if err := source.unchanged(setup.context); err != nil {
		return "", err
	}
	if err := stage.authenticate(setup.context, implementation.ArtifactSHA256, length); err != nil {
		return "", err
	}
	if setup.context != nil && setup.context.Err() != nil {
		return "", setup.context.Err()
	}
	if err := stage.directory.Sync(); err != nil {
		return "", err
	}
	if setup.context != nil && setup.context.Err() != nil {
		return "", setup.context.Err()
	}
	if err := stage.rootFile.Sync(); err != nil {
		return "", err
	}
	if setup.context != nil && setup.context.Err() != nil {
		return "", setup.context.Err()
	}
	if afterSourceCheck != nil {
		afterSourceCheck()
	}
	return stage.target, nil
}

func writeOnlyPipe(file *os.File) error {
	connection, err := file.SyscallConn()
	if err != nil {
		return errors.Join(ErrAdmission, err)
	}
	var info unix.Stat_t
	var flags int
	var inspectErr error
	controlErr := connection.Control(func(fd uintptr) {
		inspectErr = unix.Fstat(int(fd), &info)
		if inspectErr == nil {
			flags, inspectErr = unix.FcntlInt(fd, unix.F_GETFL, 0)
		}
	})
	if controlErr != nil || inspectErr != nil || info.Mode&unix.S_IFMT != unix.S_IFIFO || flags&unix.O_ACCMODE != unix.O_WRONLY {
		return errors.Join(ErrAdmission, controlErr, inspectErr)
	}
	return nil
}

func randomProtocolID() (protocol.ID, error) {
	var id protocol.ID
	if _, err := rand.Read(id[:]); err != nil || id.IsZero() {
		return protocol.ID{}, ErrProcess
	}
	return id, nil
}

func protocolID(id contract.ID) protocol.ID { return protocol.ID(id) }

func closeFile(file *os.File) {
	if file != nil {
		_ = file.Close()
	}
}

func closeFiles(files ...*os.File) {
	for _, file := range files {
		closeFile(file)
	}
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

func boundedCommandDeadline(now time.Time, millis uint64) time.Time {
	deadline := time.UnixMilli(int64(millis))
	if maximum := now.Add(time.Duration(contract.GeneratorMaximumChildCommandDurationMillis) * time.Millisecond); deadline.After(maximum) {
		return maximum
	}
	return deadline
}

package manifesthost

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	manifest "enkv.sh/sdk/manifest-generator"
	protocol "enkv.sh/sdk/protocols/manifest-generator"
	"enkv.sh/telemetry"
)

// Render borrows view until child and transport have positively joined. Keep
// its projection immutable until return and use a context with a finite deadline.
// Success transfers one exact-capacity artifact to the caller for disposal;
// native settlement proves exact transport bytes, not format correspondence.
// On exchange failure provisional artifact backing is cleared before return.
func (n *Native) Render(ctx context.Context, view manifest.View) (result manifest.Result) {
	call := telemetry.Start(ctx, telemetry.ProviderManifestHost, telemetry.OpManifestHostRender)
	callCtx := telemetry.CallContext(ctx, call)
	result, err := n.render(callCtx, view)
	if ctx != nil {
		err = errors.Join(err, invocationError(ctx))
	}
	if err != nil {
		clear(result.Artifact[:cap(result.Artifact)])
		result = manifest.Result{Failure: manifest.InvalidResult}
		switch {
		case errors.Is(err, context.Canceled):
			result.Failure = manifest.Cancelled
		case errors.Is(err, context.DeadlineExceeded):
			result.Failure = manifest.Expired
		}
	}
	finishRender(call, err, result.Failure)
	return result
}

func (n *Native) render(ctx context.Context, view manifest.View) (manifest.Result, error) {
	if n == nil || ctx == nil {
		return manifest.Result{}, ErrAdmission
	}
	if f := view.Validate(ctx); f != "" {
		return manifest.Result{Failure: f}, nil
	}
	header := view.Header()
	if header.FormatContractID != n.format || header.ConfigContractID != n.config {
		return manifest.Result{}, ErrAdmission
	}
	correlation, err := manifestCorrelation()
	if err != nil {
		return manifest.Result{}, err
	}
	return n.exchange(ctx, correlation, manifest.MaxArtifactBytes, func(w io.Writer) error { return protocol.WriteRenderRequest(ctx, w, correlation, n.descriptor, view) })
}

// ValidateSettings borrows input only for the call and requires a finite
// context deadline. It completes a separate child invocation before a dependent
// render and transfers canonical settings backing to the caller for disposal.
// The selected plugin owns settings semantics; transport success cannot prove them.
func (n *Native) ValidateSettings(ctx context.Context, input manifest.SettingsRequest) (result manifest.SettingsResult) {
	call := telemetry.Start(ctx, telemetry.ProviderManifestHost, telemetry.OpManifestHostRender)
	var resultErr error
	defer func() {
		if ctx != nil {
			if err := invocationError(ctx); err != nil {
				resultErr = errors.Join(resultErr, err)
				clear(result.Settings[:cap(result.Settings)])
				result = manifest.SettingsResult{Failure: exchangeFailure(ctx)}
			}
		}
		finishRender(call, resultErr, result.Failure)
	}()
	ctx = telemetry.CallContext(ctx, call)
	if n == nil || ctx == nil || input.FormatContractID != n.format || input.ConfigContractID != n.config {
		return manifest.SettingsResult{Failure: manifest.InvalidInput}
	}
	if f := manifest.ValidateSettingsRequest(input); f != "" {
		return manifest.SettingsResult{Failure: f}
	}
	correlation, err := manifestCorrelation()
	if err != nil {
		resultErr = err
		return manifest.SettingsResult{Failure: manifest.InvalidResult}
	}
	request := protocol.Request{Operation: protocol.OperationValidateSettings, Correlation: correlation, DescriptorID: n.descriptor, Settings: input}
	digest, err := protocol.SettingsRequestDigest(ctx, request)
	if err != nil {
		resultErr = err
		return manifest.SettingsResult{Failure: manifest.InvalidInput}
	}
	reply, err := n.exchange(ctx, correlation, protocol.MaximumSettingsResponseBytes, func(w io.Writer) error { return protocol.WriteRequest(ctx, w, request) })
	defer clear(reply.Artifact[:cap(reply.Artifact)])
	if err != nil {
		resultErr = err
		return manifest.SettingsResult{Failure: exchangeFailure(ctx)}
	}
	if reply.Failure != "" {
		return manifest.SettingsResult{Failure: reply.Failure}
	}
	var canonical []byte
	if input.Canonical {
		canonical = input.Settings
	}
	response, failure, err := protocol.ReadSettingsResponse(ctx, bytes.NewReader(reply.Artifact), digest, canonical)
	if err != nil {
		resultErr = err
		failure = manifest.InvalidResult
	}
	return manifest.SettingsResult{Settings: response.Settings, Failure: failure}
}
func manifestCorrelation() (manifest.ID, error) {
	var id manifest.ID
	_, err := rand.Read(id[:])
	if err != nil || id.IsZero() {
		return manifest.ID{}, errors.Join(ErrProcess, err)
	}
	return id, nil
}
func exchangeFailure(ctx context.Context) manifest.Failure {
	if ctx != nil {
		err := invocationError(ctx)
		if errors.Is(err, context.Canceled) {
			return manifest.Cancelled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return manifest.Expired
		}
	}
	return manifest.InvalidResult
}

func (n *Native) exchange(ctx context.Context, correlation manifest.ID, maximum uint64, writeRequest func(io.Writer) error) (result manifest.Result, resultErr error) {
	if n == nil || ctx == nil || correlation.IsZero() || writeRequest == nil {
		return result, ErrAdmission
	}
	deadline, finite := ctx.Deadline()
	if !finite {
		return result, ErrAdmission
	}
	stage, err := stageExecutable(ctx, n.path, n.identity)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, stage.close()) }()
	requestR, requestW, err := os.Pipe()
	if err != nil {
		return result, err
	}
	var owned []*os.File
	owned = append(owned, requestR, requestW)
	defer func() {
		for _, f := range owned {
			if f != nil {
				if err := f.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
					resultErr = errors.Join(resultErr, err)
				}
			}
		}
	}()
	artifactR, artifactW, err := os.Pipe()
	if err != nil {
		return result, err
	}
	owned = append(owned, artifactR, artifactW)
	statusR, statusW, err := os.Pipe()
	if err != nil {
		return result, err
	}
	owned = append(owned, statusR, statusW)
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return result, err
	}
	owned = append(owned, null)
	if err := stage.authenticate(ctx); err != nil {
		return result, err
	}
	if err := errors.Join(requestW.SetWriteDeadline(deadline), artifactR.SetReadDeadline(deadline), statusR.SetReadDeadline(deadline)); err != nil {
		return result, err
	}
	child, err := startNativeChild(ctx, stage.target, stage.path, protocol.Mode, []*os.File{null, null, null, requestR, artifactW, statusW})
	if err != nil {
		return result, errors.Join(ErrProcess, err)
	}
	child.WatchCancellation(ctx)
	requestStream := &nativeStream{file: requestW}
	artifactStream := &nativeStream{file: artifactR}
	statusStream := &nativeStream{file: statusR}
	finishTransport := watchTransport(ctx, requestStream, artifactStream, statusStream)
	joined := false
	var requestDone chan error
	defer func() {
		if !joined {
			cancelCall := telemetry.Start(ctx, telemetry.ProviderManifestHost, telemetry.OpManifestHostCancel)
			killErr := child.Process.Kill()
			if errors.Is(killErr, os.ErrProcessDone) {
				killErr = nil
			}
			finishCall(cancelCall, killErr)
			resultErr = errors.Join(resultErr, killErr)
			joinCall := telemetry.Start(ctx, telemetry.ProviderManifestHost, telemetry.OpManifestHostJoin)
			waitErr := child.Wait()
			finishCall(joinCall, errors.Join(waitErr, ctx.Err()))
			resultErr = errors.Join(resultErr, waitErr)
		}
		// Parent endpoint closure also unblocks borrowers when another process
		// retains a pipe end. Collect closes and join the cancellation callback.
		resultErr = errors.Join(resultErr, finishTransport())
		if requestDone != nil {
			resultErr = errors.Join(resultErr, <-requestDone)
		}
	}()
	for _, f := range []*os.File{requestR, artifactW, statusW} {
		if err := f.Close(); err != nil {
			return result, err
		}
	}
	requestDone = make(chan error, 1)
	go func() {
		err := writeRequest(requestStream)
		requestDone <- errors.Join(err, requestStream.Close())
	}()
	result, resultErr = readReply(ctx, correlation, maximum, artifactStream, statusStream)
	if resultErr != nil {
		return result, resultErr
	}
	joinCall := telemetry.Start(ctx, telemetry.ProviderManifestHost, telemetry.OpManifestHostJoin)
	waitErr := child.Wait()
	joined = true
	finishCall(joinCall, errors.Join(waitErr, ctx.Err()))
	if waitErr != nil {
		return result, errors.Join(ErrProcess, waitErr)
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	return result, nil
}

func readReply(ctx context.Context, correlation manifest.ID, maximum uint64, artifact, status io.Reader) (result manifest.Result, err error) {
	if ctx == nil || correlation.IsZero() || maximum == 0 || maximum > manifest.MaxArtifactBytes {
		return result, ErrAdmission
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	s, err := protocol.ReadStatus(status)
	if err != nil {
		return result, errors.Join(protocol.ErrWire, err)
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if s.Correlation != correlation || s.Length > maximum {
		return result, protocol.ErrWire
	}
	if s.Length > 0 {
		result.Artifact = make([]byte, int(s.Length))
		if _, err := io.ReadFull(artifact, result.Artifact); err != nil {
			return result, err
		}
	}
	if err := protocol.RequireEOF(artifact); err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	result.Failure = s.Failure
	return result, nil
}

// nativeStream records its one owned close so cancellation and completion cannot
// race descriptor reuse or discard the original close result.
type nativeStream struct {
	file *os.File
	once sync.Once
	err  error
}

func (s *nativeStream) Read(b []byte) (int, error)  { return s.file.Read(b) }
func (s *nativeStream) Write(b []byte) (int, error) { return s.file.Write(b) }
func (s *nativeStream) close()                      { s.once.Do(func() { s.err = s.file.Close() }) }
func (s *nativeStream) Close() error                { s.close(); return s.err }

func watchTransport(ctx context.Context, request, artifact, status *nativeStream) func() error {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { request.close(); artifact.close(); status.close(); close(done) })
	return func() error {
		request.close()
		artifact.close()
		status.close()
		if !stop() {
			<-done
		}
		return errors.Join(request.err, artifact.err, status.err)
	}
}
func invocationError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, finite := ctx.Deadline(); finite && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

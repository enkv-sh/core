package crypto

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"enkv.sh/compositions/generatorhost"
	"enkv.sh/core/contract"
	wire "enkv.sh/sdk/protocols/generator"
	"enkv.sh/telemetry"
)

func invokeGeneratedProcessOwned(ctx context.Context, launcher generatorhost.Launcher, command contract.GeneratedProducerCommand, intent []byte) (out generatedProducerReturn, code contract.CryptoResultCode) {
	out.effect = generatedEffectNoSend
	if ctx == nil || launcher == nil {
		out.stage, out.category = generatedFailureEntry, generatedFailureInvalid
		return out, contract.CryptoInvalidAdmission
	}
	var nativeFacts []byte
	if len(command.OriginalFacts) != 0 {
		original, err := contract.InspectGeneratorSafeFacts(command.OriginalFacts)
		if err != nil {
			out.stage, out.category = generatedFailureEntry, generatedFailureInvalid
			return out, contract.CryptoInvalidAdmission
		}
		nativeFacts, err = wire.EncodeSafeFacts(wire.SafeFacts{Schema: wire.Schema, Action: original.Action, LifecycleMode: uint8(original.LifecycleMode), Disposition: original.Disposition, Reason: original.Reason,
			RequestDigest: wire.ID(original.RequestDigest), IntentDigest: wire.ID(original.IntentDigest), ResourceContractID: wire.ID(original.ResourceContractID), Target: original.Target, ResourceData: original.ResourceData, ProviderFacts: original.ProviderFacts})
		if err != nil {
			out.stage, out.category = generatedFailureEntry, generatedFailureInvalid
			return out, contract.CryptoInvalidAdmission
		}
	}
	defer clear(nativeFacts[:cap(nativeFacts)])
	processCommand := wire.Command{Schema: wire.Schema,
		DomainID: wire.ID(command.DomainID), OperationID: wire.ID(command.OperationID), RequestIdentityDigest: wire.ID(command.RequestIdentityDigest),
		PlanGraphID: wire.ID(command.PlanGraphID), LineageID: wire.ID(command.LineageID), AttemptID: wire.ID(command.AttemptID),
		TransmissionID: wire.ID(command.TransmissionID), ResultID: wire.ID(command.ResultID), ResultContractID: wire.ID(command.ResultContractID),
		DescriptorID: wire.ID(command.DescriptorID), ExecutorID: wire.ID(command.ExecutorID), CredentialRouteID: wire.ID(command.CredentialRouteID),
		Action: command.Action, DeadlineUnixMillis: command.DeadlineUnixMillis, RequestDigest: wire.ID(command.RequestDigest), IntentDigest: wire.ID(command.IntentDigest),
		ResourceContractID: wire.ID(command.ResourceContractID), LifecycleMode: uint8(command.LifecycleMode), Intent: bytes.Clone(intent), OriginalFacts: nativeFacts}
	defer clear(processCommand.Intent[:cap(processCommand.Intent)])
	deadline := time.UnixMilli(int64(command.DeadlineUnixMillis))
	processContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if processContext.Err() != nil {
		code := processResultCode(ctx, deadline)
		out.stage, out.category = generatedFailureDeadline, generatedCategoryForCode(code)
		return out, code
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		out.stage, out.category = generatedFailurePipe, generatedFailureUnavailable
		return out, contract.CryptoCustodyUnavailable
	}
	var readerCloseErr error
	closeReader := sync.OnceFunc(func() { readerCloseErr = reader.Close() })
	readerCallbackDone := make(chan struct{})
	stopReader := context.AfterFunc(processContext, func() {
		defer close(readerCallbackDone)
		closeReader()
	})
	releaseReader := sync.OnceFunc(func() {
		if !stopReader() {
			<-readerCallbackDone
		}
		closeReader()
	})
	defer releaseReader()
	run, err := launcher.Start(processContext, processCommand, writer)
	if err != nil {
		out.effect = generatedEffectUnknown
		releaseReader()
		cleanupErr := readerCloseErr
		if run != nil {
			cleanupErr = errors.Join(cleanupErr, run.Cancel())
		}
		if cleanupErr == nil && run == nil && generatorhost.ProvesNotStarted(processCommand, err) {
			out.effect = generatedEffectNoSend
			out.settled = processContext.Err() == nil && time.Now().Before(deadline)
		}
		code := processResultCode(ctx, deadline)
		out.stage, out.category = generatedFailureLaunch, generatedCategoryForCode(code)
		return out, code
	}
	out.effect = generatedEffectUnknown
	commandID := run.CommandID()
	intake := telemetry.StartWithDetails(processContext, telemetry.ProviderCrypto, telemetry.OpCryptoGeneratedResultIntake,
		generatedAttemptDetails(command.AttemptID).WithCommandID(hex.EncodeToString(commandID[:])))
	processContext = telemetry.CallContext(processContext, intake)
	defer func() {
		if code == contract.CryptoSuccess && (processContext.Err() != nil || !time.Now().Before(deadline)) {
			clear(out.Secret[:cap(out.Secret)])
			clear(out.Facts.Target[:cap(out.Facts.Target)])
			clear(out.Facts.ResourceData[:cap(out.Facts.ResourceData)])
			clear(out.Facts.ProviderFacts[:cap(out.Facts.ProviderFacts)])
			out.Secret, out.Facts = nil, contract.GeneratorSafeFacts{}
			out.effect, out.settled, out.executableCleanupFailed = generatedEffectUnknown, false, false
			code = processResultCode(ctx, deadline)
			out.stage, out.category = generatedFailureReturn, generatedCategoryForCode(code)
			if code == contract.CryptoExpired {
				out.stage = generatedFailureDeadline
			}
		}
		finishCryptoCall(intake, code)
	}()
	body, readErr := wire.ReadExpectedFrame(reader, wire.KindResult, wire.ID(commandID), wire.MaximumResultBody)
	if readErr == nil {
		readErr = wire.RequireEOF(reader)
	}
	releaseReader()
	if readerCloseErr != nil {
		readErr = errors.Join(readErr, readerCloseErr)
	}
	// Even an unreadable result must settle the child before its command
	// backing is cleared or a local failure status is used.
	status, waitErr := run.Wait(processContext)
	completeWithCleanupFailure := waitErr != nil && generatorhost.PreservesCompletion(processCommand, commandID, status, waitErr)
	local := command.LifecycleMode == contract.GeneratorLifecycleNone
	if local {
		out.settled = processContext.Err() == nil && time.Now().Before(deadline) && (generatedLocalFailureStatus(status) || status == (wire.Status{Stage: wire.StatusStageReturn, Category: wire.StatusOK}))
	}
	if readErr != nil || waitErr != nil && !completeWithCleanupFailure || status != (wire.Status{Stage: wire.StatusStageReturn, Category: wire.StatusOK}) {
		clear(body)
		code := processResultCode(ctx, deadline)
		if local {
			switch {
			case code == contract.CryptoExpired:
				out.stage, out.category = generatedFailureDeadline, generatedFailureExpired
			case code == contract.CryptoCancelled:
				out.stage, out.category = generatedFailureReturn, generatedFailureCancelled
			case readErr == io.EOF && generatedLocalFailureStatus(status):
				out.stage, out.category = generatedFailureStatus, generatedCategoryForStatus(status)
			case readErr != nil && readErr != io.EOF:
				out.stage, out.category = generatedFailureResultRead, generatedFailureProtocol
			case readErr == nil && generatedLocalFailureStatus(status):
				out.stage, out.category = generatedFailureResultRead, generatedFailureProtocol
			case waitErr != nil:
				out.stage, out.category = generatedFailureWait, generatedFailureUnavailable
			default:
				out.stage, out.category = generatedFailureResultRead, generatedFailureProtocol
			}
		} else {
			switch {
			case readErr != nil:
				out.stage, out.category = generatedFailureResultRead, generatedCategoryForCode(code)
			case waitErr != nil:
				out.stage, out.category = generatedFailureWait, generatedCategoryForCode(code)
			default:
				out.stage, out.category = generatedFailureStatus, generatedCategoryForStatus(status)
			}
		}
		return out, code
	}
	result, err := wire.DecodeResult(body)
	if err != nil {
		clear(body)
		out.stage, out.category = generatedFailureDecode, generatedFailureInvalid
		if local {
			out.category = generatedFailureProtocol
		}
		return out, contract.CryptoCustodyUnavailable
	}
	f := result.SafeFacts
	if result.AttemptID != processCommand.AttemptID || result.ResultID != processCommand.ResultID || result.ResultContractID != processCommand.ResultContractID || result.ExecutorID != processCommand.ExecutorID ||
		f.Action != processCommand.Action || f.LifecycleMode != processCommand.LifecycleMode || f.ResourceContractID != processCommand.ResourceContractID ||
		f.RequestDigest != processCommand.RequestDigest || f.IntentDigest != processCommand.IntentDigest {
		clear(body)
		out.stage, out.category = generatedFailureBinding, generatedFailureInvalid
		if local {
			out.category = generatedFailureProtocol
		}
		return out, contract.CryptoCustodyUnavailable
	}
	out.Facts = contract.GeneratorSafeFacts{Schema: contract.GeneratorSafeFactsSchema, Action: f.Action, LifecycleMode: contract.GeneratorLifecycleMode(f.LifecycleMode),
		Disposition: f.Disposition, Reason: f.Reason, RequestDigest: contract.ID(f.RequestDigest), IntentDigest: contract.ID(f.IntentDigest), ResourceContractID: contract.ID(f.ResourceContractID),
		Target: bytes.Clone(f.Target), ResourceData: bytes.Clone(f.ResourceData), ProviderFacts: bytes.Clone(f.ProviderFacts)}
	out.Secret = bytes.Clone(result.Value)
	out.effect = generatedEffectFromDisposition(out.Facts.Disposition)
	out.executableCleanupFailed = completeWithCleanupFailure
	clear(body)
	return out, contract.CryptoSuccess
}

func generatedLocalFailureStatus(status wire.Status) bool {
	return status.Stage == wire.StatusStageCommand &&
		(status.Category == wire.StatusInvalid || status.Category == wire.StatusUnavailable || status.Category == wire.StatusCancelled) ||
		status.Stage == wire.StatusStageResponse && status.Category == wire.StatusProtocol
}

func generatedCategoryForCode(code contract.CryptoResultCode) generatedFailureCategory {
	switch code {
	case contract.CryptoExpired:
		return generatedFailureExpired
	case contract.CryptoCancelled:
		return generatedFailureCancelled
	default:
		return generatedFailureUnavailable
	}
}

func generatedCategoryForStatus(status wire.Status) generatedFailureCategory {
	switch status.Category {
	case wire.StatusInvalid:
		return generatedFailureInvalid
	case wire.StatusUnavailable:
		return generatedFailureUnavailable
	case wire.StatusCancelled:
		return generatedFailureCancelled
	default:
		return generatedFailureProtocol
	}
}

func processResultCode(ctx context.Context, deadline time.Time) contract.CryptoResultCode {
	if !time.Now().Before(deadline) {
		return contract.CryptoExpired
	}
	if ctx.Err() != nil {
		return contract.CryptoCancelled
	}
	return contract.CryptoCustodyUnavailable
}

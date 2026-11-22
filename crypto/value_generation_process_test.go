package crypto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"

	"enkv.sh/compositions/generatorhost"
	"enkv.sh/core/contract"
	protocol "enkv.sh/sdk/protocols/generator"
	"enkv.sh/telemetry"
)

func generatedProcessFixtureCommand(t testing.TB, mode contract.GeneratorLifecycleMode, action uint8) contract.GeneratedProducerCommand {
	t.Helper()
	id := consumerID
	resource := contract.ID{}
	if mode == contract.GeneratorLifecycleManaged {
		resource = id("process resource contract")
	}
	intent := generatedFixtureIntent(id("process config contract"), resource, mode, `{"private":"Private_intent_sentinel"}`)
	digest, err := contract.GeneratorIntentDigest(intent)
	if err != nil {
		t.Fatal(err)
	}
	c := contract.GeneratedProducerCommand{GeneratedProducerPreparation: contract.GeneratedProducerPreparation{
		Schema: contract.GeneratedProducerPreparationSchema, Action: action, LifecycleMode: mode,
		DomainID: id("process domain"), OperationID: id("process operation"), RequestIdentityDigest: id("process request identity"),
		PlanGraphID: id("process graph"), LineageID: id("process lineage"), AttemptID: id("process attempt"), TransmissionID: id("process transmission"),
		ResultID: id("process result"), ResultContractID: id("process result contract"), DescriptorID: id("process descriptor"), ExecutorID: id("process executor"),
		RequestDigest: id("process request"), IntentDigest: digest, ResourceContractID: resource, CredentialRouteID: id("process credential route")},
		DeadlineUnixMillis: uint64(time.Now().Add(time.Minute).UnixMilli()), Intent: intent}
	if action == contract.GeneratorActionDelete {
		original := generatedProcessFixtureFacts(c, protocol.DispositionCompleteCreate, protocol.ReasonNone)
		original.Action = protocol.ActionCreate
		core := contract.GeneratorSafeFacts{Schema: contract.GeneratorSafeFactsSchema, Action: original.Action, LifecycleMode: mode,
			Disposition: original.Disposition, Reason: original.Reason, RequestDigest: contract.ID(original.RequestDigest), IntentDigest: digest,
			ResourceContractID: resource, Target: original.Target, ResourceData: original.ResourceData, ProviderFacts: original.ProviderFacts}
		c.OriginalFacts, err = contract.EncodeGeneratorSafeFacts(core)
		if err != nil {
			t.Fatal(err)
		}
		c.ResourceDigest = generatedFixtureResourceDigest(t, core)
	}
	return c
}

func generatedProcessFixtureFacts(command contract.GeneratedProducerCommand, disposition, reason uint8) protocol.SafeFacts {
	f := protocol.SafeFacts{Schema: protocol.Schema, Action: command.Action, LifecycleMode: uint8(command.LifecycleMode), Disposition: disposition, Reason: reason,
		RequestDigest: protocol.ID(command.RequestDigest), IntentDigest: protocol.ID(command.IntentDigest), ResourceContractID: protocol.ID(command.ResourceContractID)}
	if command.LifecycleMode == contract.GeneratorLifecycleManaged && (disposition == protocol.DispositionCompleteCreate || disposition == protocol.DispositionOwnedUnusableCreate || disposition == protocol.DispositionRetirementAcknowledged) {
		resource := consumerID("process resource")
		f.Target = []byte("private-service/target")
		f.ResourceData = bytes.Clone(resource[:])
	}
	return f
}

type telemetryProcessLauncher struct {
	implementation contract.GeneratorImplementation
	rawResult      []byte
	startFailure   error
	startRun       generatorhost.Run
	commandID      protocol.ID
	resultBody     []byte
	omitResult     bool
	status         protocol.Status
	noStatus       bool
	waitErr        error
	waits          *int
}

func (launcher telemetryProcessLauncher) Implementation() contract.GeneratorImplementation {
	if launcher.implementation.Schema == 0 {
		return contract.GeneratorImplementation{Schema: 1}
	}
	return launcher.implementation
}

func (launcher telemetryProcessLauncher) Start(_ context.Context, _ protocol.Command, writer *os.File) (run generatorhost.Run, err error) {
	defer func() { err = errors.Join(err, writer.Close()) }()
	if launcher.startFailure != nil {
		return launcher.startRun, launcher.startFailure
	}
	if launcher.omitResult {
		return telemetryProcessRun{commandID: launcher.commandID, status: launcher.status, noStatus: launcher.noStatus, waitErr: launcher.waitErr, waits: launcher.waits}, nil
	}
	if launcher.rawResult != nil {
		_, err := writer.Write(launcher.rawResult)
		return telemetryProcessRun{commandID: launcher.commandID, status: launcher.status, noStatus: launcher.noStatus, waitErr: launcher.waitErr, waits: launcher.waits}, err
	}
	body := launcher.resultBody
	if body == nil {
		body = []byte("private-result-sentinel")
	}
	if err := protocol.WriteFrame(writer, protocol.Frame{Kind: protocol.KindResult, CommandID: launcher.commandID, Body: body}); err != nil {
		return nil, err
	}
	return telemetryProcessRun{commandID: launcher.commandID, status: launcher.status, noStatus: launcher.noStatus, waitErr: launcher.waitErr, waits: launcher.waits}, nil
}

// full_only: false
func TestLocalEnvironmentRefusalRequiresEmptyResultAndLiveAuthority(t *testing.T) {
	for _, tc := range []struct {
		name     string
		readErr  error
		code     contract.CryptoResultCode
		category generatedFailureCategory
		settled  bool
	}{
		{"empty", io.EOF, contract.CryptoCustodyUnavailable, generatedFailureInvalid, true},
		{"complete result", nil, contract.CryptoCustodyUnavailable, generatedFailureProtocol, false},
		{"partial result", io.ErrUnexpectedEOF, contract.CryptoCustodyUnavailable, generatedFailureProtocol, false},
		{"reader close failed", errors.Join(io.EOF, os.ErrClosed), contract.CryptoCustodyUnavailable, generatedFailureProtocol, false},
		{"cancelled", io.EOF, contract.CryptoCancelled, generatedFailureCancelled, false},
		{"expired", io.EOF, contract.CryptoExpired, generatedFailureExpired, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := localEnvironmentRefusal(protocol.Status{Stage: protocol.StatusStageCommand, Category: protocol.StatusInvalid}, tc.readErr, tc.code)
			if out.settled != tc.settled || out.category != tc.category || out.effect != generatedEffectUnknown ||
				len(out.Secret) != 0 || !reflect.DeepEqual(out.Facts, contract.GeneratorSafeFacts{}) {
				t.Fatal("unexpected local handoff outcome", tc.code, out.category, out.settled)
			}
		})
	}
}

// full_only: false
func TestGeneratedLocalProcessFailureDistinguishesEmptyAndTruncatedResult(t *testing.T) {
	command := generatedProcessFixtureCommand(t, contract.GeneratorLifecycleNone, contract.GeneratorActionCreate)
	commandID := protocol.ID(consumerID("local process command"))
	var frame bytes.Buffer
	if err := protocol.WriteFrame(&frame, protocol.Frame{Kind: protocol.KindResult, CommandID: protocol.ID(commandID), Body: []byte{7}}); err != nil {
		t.Fatal(err)
	}
	zeroBody := bytes.Clone(frame.Bytes()[:protocol.HeaderLength])
	clear(zeroBody[39:43])
	wrongCorrelation := bytes.Clone(frame.Bytes())
	wrongCorrelation[7] ^= 1
	wrongKind := bytes.Clone(frame.Bytes())
	wrongKind[6] = protocol.KindCommand
	for _, tc := range []struct {
		name     string
		status   protocol.Status
		raw      []byte
		waitErr  error
		stage    generatedFailureStage
		category generatedFailureCategory
	}{
		{"invalid", protocol.Status{Stage: 3, Category: 1}, nil, errors.New("joined execution exit"), generatedFailureStatus, generatedFailureInvalid},
		{"unavailable", protocol.Status{Stage: 3, Category: 2}, nil, errors.New("joined execution exit"), generatedFailureStatus, generatedFailureUnavailable},
		{"cancelled", protocol.Status{Stage: 3, Category: 3}, nil, errors.New("joined execution exit"), generatedFailureStatus, generatedFailureCancelled},
		{"protocol", protocol.Status{Stage: 4, Category: 4}, nil, errors.New("joined encoding exit"), generatedFailureStatus, generatedFailureProtocol},
		{"truncated header", protocol.Status{Stage: 3, Category: 2}, []byte{1}, nil, generatedFailureResultRead, generatedFailureProtocol},
		{"truncated body", protocol.Status{Stage: 3, Category: 2}, bytes.Clone(frame.Bytes()[:protocol.HeaderLength]), nil, generatedFailureResultRead, generatedFailureProtocol},
		{"truncated settled OK", protocol.Status{Stage: 5, Category: 0}, []byte{1}, nil, generatedFailureResultRead, generatedFailureProtocol},
		{"trailing result", protocol.Status{Stage: 5, Category: 0}, append(bytes.Clone(frame.Bytes()), 0), nil, generatedFailureResultRead, generatedFailureProtocol},
		{"zero length frame", protocol.Status{Stage: 5, Category: 0}, zeroBody, nil, generatedFailureDecode, generatedFailureProtocol},
		{"wrong correlation", protocol.Status{Stage: 5, Category: 0}, wrongCorrelation, nil, generatedFailureResultRead, generatedFailureProtocol},
		{"wrong kind", protocol.Status{Stage: 5, Category: 0}, wrongKind, nil, generatedFailureResultRead, generatedFailureProtocol},
		{"malformed body", protocol.Status{Stage: 5, Category: 0}, bytes.Clone(frame.Bytes()), nil, generatedFailureDecode, generatedFailureProtocol},
		{"failure leaked result", protocol.Status{Stage: 3, Category: 2}, bytes.Clone(frame.Bytes()), errors.New("joined execution exit"), generatedFailureResultRead, generatedFailureProtocol},
		{"unsettled host", protocol.Status{}, nil, errors.New("unsettled cleanup"), generatedFailureWait, generatedFailureUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			waits := 0
			launcher := telemetryProcessLauncher{implementation: contract.GeneratorImplementation{Schema: 2}, commandID: commandID,
				omitResult: tc.raw == nil, rawResult: tc.raw, status: tc.status, noStatus: tc.status == (protocol.Status{}), waitErr: tc.waitErr, waits: &waits}
			out, code := invokeGeneratedProcess(os.Pipe, context.Background(), launcher, command, []byte{0, 1})
			if code != contract.CryptoCustodyUnavailable || out.stage != tc.stage || out.category != tc.category || waits != 1 || len(out.Secret) != 0 || !reflect.DeepEqual(out.Facts, contract.GeneratorSafeFacts{}) {
				t.Fatal("local intake lost its exact joined failure", code, out.stage, out.category, waits)
			}
			if out.settled != (tc.status != (protocol.Status{})) {
				t.Fatal("qualified native disposal was confused with result validity")
			}
		})
	}
}

// full_only: false
func TestGeneratedProcessTelemetryRetainsObservedProviderOutcome(t *testing.T) {
	secret := []byte("Private_generated_result_0123456789_ABCDEFG")
	for _, test := range []struct {
		name                string
		disposition, reason uint8
		status              uint16
		class               telemetry.DiagnosticReason
		detail              string
	}{
		{"complete-create", 1, 0, 200, telemetry.DiagnosticReasonNone, ""},
		{"delete-acknowledgement", 4, 0, 200, telemetry.DiagnosticReasonNone, ""},
		{"missing-value", 2, 1, 200, telemetry.DiagnosticReasonInvalid, "generator result: owned unusable create; reason: missing value"},
		{"invalid-value", 2, 2, 200, telemetry.DiagnosticReasonInvalid, "generator result: owned unusable create; reason: invalid value"},
		{"controls", 2, 3, 200, telemetry.DiagnosticReasonInvalid, "generator result: owned unusable create; reason: controls"},
		{"inactive", 2, 4, 200, telemetry.DiagnosticReasonInvalid, "generator result: owned unusable create; reason: inactive"},
		{"malformed", 5, 5, 200, telemetry.DiagnosticReasonUncertain, "generator result: unknown; reason: malformed"},
		{"overflow", 5, 6, 200, telemetry.DiagnosticReasonUncertain, "generator result: unknown; reason: overflow"},
		{"rejected", 5, 7, 503, telemetry.DiagnosticReasonUncertain, "generator result: unknown; reason: rejected"},
		{"transport", 5, 8, 0, telemetry.DiagnosticReasonUncertain, "generator result: unknown; reason: transport"},
		{"deadline", 5, 9, 0, telemetry.DiagnosticReasonUncertain, "generator result: unknown; reason: deadline"},
		{"identity-conflict", 5, 10, 200, telemetry.DiagnosticReasonUncertain, "generator result: unknown; reason: identity conflict"},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := generatedProcessFixtureCommand(t, contract.GeneratorLifecycleManaged, contract.GeneratorActionCreate)
			command.Action = contract.GeneratorActionCreate
			if test.name == "delete-acknowledgement" {
				command.Action = contract.GeneratorActionDelete
			}
			if command.Action == contract.GeneratorActionDelete {
				command = generatedProcessFixtureCommand(t, contract.GeneratorLifecycleManaged, contract.GeneratorActionDelete)
			}
			facts := generatedProcessFixtureFacts(command, test.disposition, test.reason)
			facts.ProviderFacts = []byte{byte(test.status >> 8), byte(test.status)}
			result := protocol.Result{Schema: protocol.Schema, AttemptID: protocol.ID(command.AttemptID), ResultID: protocol.ID(command.ResultID), ResultContractID: protocol.ID(command.ResultContractID), ExecutorID: protocol.ID(command.ExecutorID), SafeFacts: facts}
			if test.disposition == protocol.DispositionCompleteCreate {
				result.Value = bytes.Clone(secret)
			}
			body, err := protocol.EncodeResult(result)
			if err != nil {
				t.Fatal(err)
			}
			launcher := telemetryProcessLauncher{commandID: sha256.Sum256([]byte("command")), resultBody: body}
			for _, enabled := range []bool{false, true} {
				recorder := telemetry.NewRecorder()
				ctx := context.Background()
				if enabled {
					ctx = telemetry.WithCapability(ctx, telemetry.NewCapability(nil, recorder))
				}
				out, code := invokeGeneratedProcess(os.Pipe, ctx, launcher, command, []byte("Private_intent_sentinel"))
				if code != contract.CryptoSuccess || out.Facts.Disposition != test.disposition || out.Facts.Reason != test.reason ||
					!bytes.Equal(out.Facts.ProviderFacts, facts.ProviderFacts) || !bytes.Equal(out.Secret, result.Value) {
					t.Fatal("telemetry changed the returned provider observation")
				}
				if test.name == "delete-acknowledgement" && out.effect != generatedEffectDeleteAck {
					t.Fatal("delete acknowledgement was reported as create no-effect")
				}
				clear(out.Secret)
				records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 16))
				returns := 0
				for _, record := range records {
					if err := record.Validate(); err != nil {
						t.Fatal(err)
					}
					if record.Operation != telemetry.OpCryptoGeneratedProcess || record.Event != telemetry.DiagnosticReturn {
						continue
					}
					returns++
					wantStatus := 0
					if record.Result != telemetry.ResultSuccess || record.Reason != test.class || record.ErrorClass != test.class ||
						record.HTTPStatus != wantStatus || record.ErrorDetail != test.detail {
						t.Fatalf("provider outcome details missing: reason=%q class=%q status=%d detail=%q", record.Reason, record.ErrorClass, record.HTTPStatus, record.ErrorDetail)
					}
					if test.class != telemetry.DiagnosticReasonNone && record.SeverityText != "WARN" {
						t.Fatal("non-success provider observation lost warning severity")
					}
				}
				if enabled && returns != 1 || !enabled && len(records) != 0 {
					t.Fatal("process telemetry return count changed")
				}
				encoded, err := json.Marshal(records)
				if err != nil {
					t.Fatal(err)
				}
				for _, value := range [][]byte{secret, []byte("Private_intent_sentinel")} {
					for _, representation := range [][]byte{value, []byte(hex.EncodeToString(value)), []byte(base64.StdEncoding.EncodeToString(value))} {
						if bytes.Contains(encoded, representation) {
							t.Fatal("private process input or output reached telemetry")
						}
					}
				}
			}
			result.AttemptID = sha256.Sum256([]byte("different attempt"))
			launcher.resultBody, err = protocol.EncodeResult(result)
			if err != nil {
				t.Fatal(err)
			}
			recorder := telemetry.NewRecorder()
			ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
			out, code := invokeGeneratedProcess(os.Pipe, ctx, launcher, command, nil)
			if code != contract.CryptoCustodyUnavailable || out.Facts.Disposition != 0 || len(out.Secret) != 0 {
				t.Fatal("unbound process response was accepted")
			}
			for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 16)) {
				if record.Event == telemetry.DiagnosticReturn && (record.Result != telemetry.ResultEvidenceUnavailable ||
					record.ErrorClass != telemetry.DiagnosticReasonCustodyUnavailable || record.HTTPStatus != 0 || record.ErrorDetail != "") {
					t.Fatal("unbound process response gained a provider classification")
				}
			}
		})
	}
}

type telemetryProcessRun struct {
	commandID protocol.ID
	status    protocol.Status
	noStatus  bool
	waitErr   error
	waits     *int
	cancels   *int
}

func (run telemetryProcessRun) CommandID() protocol.ID { return run.commandID }
func (run telemetryProcessRun) Wait(context.Context) (protocol.Status, error) {
	if run.waits != nil {
		(*run.waits)++
	}
	if run.status == (protocol.Status{}) && !run.noStatus {
		run.status = protocol.Status{Stage: protocol.StatusStageReturn, Category: protocol.StatusOK}
	}
	return run.status, run.waitErr
}
func (run telemetryProcessRun) Cancel() error {
	if run.cancels != nil {
		(*run.cancels)++
	}
	return nil
}

// full_only: false
func TestGeneratedProcessTelemetryCoversRefusalAndResultIntake(t *testing.T) {
	for _, failStart := range []bool{false, true} {
		t.Run(map[bool]string{false: "malformed-result", true: "start-refusal"}[failStart], func(t *testing.T) {
			recorder := telemetry.NewRecorder()
			ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
			launcher := telemetryProcessLauncher{commandID: sha256.Sum256([]byte("local command identity"))}
			if failStart {
				launcher.startFailure = errors.New("private-error-sentinel")
			}
			command := generatedProcessFixtureCommand(t, contract.GeneratorLifecycleManaged, contract.GeneratorActionCreate)
			out, code := invokeGeneratedProcess(os.Pipe, ctx, launcher, command, []byte("private-intent-sentinel"))
			if code != contract.CryptoCustodyUnavailable {
				t.Fatalf("process refusal changed: %v", code)
			}
			wantStage, wantCategory := generatedFailureDecode, generatedFailureInvalid
			if failStart {
				wantStage, wantCategory = generatedFailureLaunch, generatedFailureUnavailable
			}
			if out.stage != wantStage || out.category != wantCategory || !reflect.DeepEqual(out.Facts, contract.GeneratorSafeFacts{}) || len(out.Secret) != 0 {
				t.Fatalf("private intake gate lost its closed failure and empty result: stage=%q category=%q", out.stage, out.category)
			}
			records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 16))
			starts := map[telemetry.Operation]int{}
			returns := map[telemetry.Operation]int{}
			var processCall uint64
			for _, record := range records {
				if err := record.Validate(); err != nil {
					t.Fatal(err)
				}
				switch record.Event {
				case telemetry.DiagnosticStart:
					starts[record.Operation]++
					if record.Operation == telemetry.OpCryptoGeneratedProcess {
						processCall = record.Call
						if record.AttemptID != hex.EncodeToString(command.AttemptID[:]) {
							t.Fatal("process lost attempt identity")
						}
					}
					if record.Operation == telemetry.OpCryptoGeneratedResultIntake {
						if record.ParentCall != processCall || record.CommandID != hex.EncodeToString(launcher.commandID[:]) || record.AttemptID != hex.EncodeToString(command.AttemptID[:]) {
							t.Fatal("result intake lost process parent or command identity")
						}
					}
				case telemetry.DiagnosticReturn:
					returns[record.Operation]++
					if record.Result != telemetry.ResultEvidenceUnavailable {
						t.Fatal("unsafe process result class", record.Result)
					}
				}
			}
			if starts[telemetry.OpCryptoGeneratedProcess] != 1 || returns[telemetry.OpCryptoGeneratedProcess] != 1 {
				t.Fatal("process boundary did not return once")
			}
			intake := 1
			if failStart {
				intake = 0
			}
			if starts[telemetry.OpCryptoGeneratedResultIntake] != intake || returns[telemetry.OpCryptoGeneratedResultIntake] != intake {
				t.Fatal("result intake boundary did not match process entry")
			}
			encoded, err := json.Marshal(records)
			if err != nil || bytes.Contains(encoded, []byte("private-result-sentinel")) || bytes.Contains(encoded, []byte("private-intent-sentinel")) || bytes.Contains(encoded, []byte("private-error-sentinel")) {
				t.Fatal("private process input or output reached telemetry")
			}
		})
	}
}

// full_only: false
func TestGeneratedProcessFailureGateAndEffect(t *testing.T) {
	command := generatedProcessFixtureCommand(t, contract.GeneratorLifecycleManaged, contract.GeneratorActionCreate)
	result := protocol.Result{Schema: protocol.Schema, AttemptID: protocol.ID(command.AttemptID), ResultID: protocol.ID(command.ResultID), ResultContractID: protocol.ID(command.ResultContractID), ExecutorID: protocol.ID(command.ExecutorID), SafeFacts: generatedProcessFixtureFacts(command, protocol.DispositionUnknown, protocol.ReasonTransport)}
	body, err := protocol.EncodeResult(result)
	if err != nil {
		t.Fatal(err)
	}
	result.AttemptID = sha256.Sum256([]byte("different attempt"))
	unbound, err := protocol.EncodeResult(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		launcher telemetryProcessLauncher
		stage    generatedFailureStage
		category generatedFailureCategory
	}{
		{"read", telemetryProcessLauncher{omitResult: true}, generatedFailureResultRead, generatedFailureUnavailable},
		{"wait", telemetryProcessLauncher{resultBody: body, waitErr: errors.New("private wait sentinel")}, generatedFailureWait, generatedFailureUnavailable},
		{"status", telemetryProcessLauncher{resultBody: body, status: protocol.Status{Stage: protocol.StatusStageResponse, Category: protocol.StatusProtocol}}, generatedFailureStatus, generatedFailureProtocol},
		{"binding", telemetryProcessLauncher{resultBody: unbound}, generatedFailureBinding, generatedFailureInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			waits := 0
			launcher := tc.launcher
			launcher.commandID = sha256.Sum256([]byte("command"))
			launcher.waits = &waits
			out, code := invokeGeneratedProcess(os.Pipe, context.Background(), launcher, command, nil)
			if code != contract.CryptoCustodyUnavailable || out.stage != tc.stage || out.category != tc.category ||
				out.effect != generatedEffectUnknown || !reflect.DeepEqual(out.Facts, contract.GeneratorSafeFacts{}) || len(out.Secret) != 0 || waits != 1 {
				t.Fatalf("failure gate or join changed: code=%v stage=%q category=%q effect=%q waits=%d", code, out.stage, out.category, out.effect, waits)
			}
		})
	}
	t.Run("complete-create-wait-refusal", func(t *testing.T) {
		secret := []byte("Private_complete_create_0123456789_ABCDEFG")
		complete := protocol.Result{Schema: protocol.Schema, AttemptID: protocol.ID(command.AttemptID), ResultID: protocol.ID(command.ResultID), ResultContractID: protocol.ID(command.ResultContractID), ExecutorID: protocol.ID(command.ExecutorID), SafeFacts: generatedProcessFixtureFacts(command, protocol.DispositionCompleteCreate, protocol.ReasonNone), Value: secret}
		body, err := protocol.EncodeResult(complete)
		if err != nil {
			t.Fatal("invalid complete-create fixture")
		}
		defer clear(body)
		defer clear(secret)
		for _, enabled := range []bool{false, true} {
			t.Run(map[bool]string{false: "telemetry-disabled", true: "telemetry-enabled"}[enabled], func(t *testing.T) {
				recorder := telemetry.NewRecorder()
				ctx := context.Background()
				if enabled {
					ctx = telemetry.WithCapability(ctx, telemetry.NewCapability(nil, recorder))
				}
				waits := 0
				launcher := telemetryProcessLauncher{commandID: sha256.Sum256([]byte("complete create command")), resultBody: body,
					waitErr: &os.PathError{Op: "remove", Path: "private-generated-cleanup-path", Err: errors.New("private-generated-cleanup-error")}, waits: &waits}
				out, code := invokeGeneratedProcess(os.Pipe, ctx, launcher, command, []byte("private complete-create intent"))
				records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 16))
				t.Logf("complete_create=true status_success=true waits=%d code=%v stage=%q category=%q effect=%q secret_returned=%t", waits, code, out.stage, out.category, out.effect, len(out.Secret) != 0)
				if code != contract.CryptoCustodyUnavailable || out.stage != generatedFailureWait || out.category != generatedFailureUnavailable ||
					out.effect != generatedEffectUnknown || out.executableCleanupFailed || waits != 1 || len(out.Secret) != 0 || !reflect.DeepEqual(out.Facts, contract.GeneratorSafeFacts{}) {
					t.Fatal("valid generated result hid a failed host Wait or released private plaintext")
				}
				returns := 0
				for _, record := range records {
					if err := record.Validate(); err != nil {
						t.Fatal("invalid failure telemetry")
					}
					if record.Event != telemetry.DiagnosticReturn {
						continue
					}
					returns++
					if record.Result != telemetry.ResultEvidenceUnavailable || record.ErrorClass != telemetry.DiagnosticReasonCustodyUnavailable || record.HTTPStatus != 0 || record.ErrorDetail != "" {
						t.Fatal("failed Wait gained a provider success classification")
					}
				}
				if enabled && returns != 2 || !enabled && len(records) != 0 {
					t.Fatal("failure boundaries did not return once")
				}
				encoded, err := json.Marshal(records)
				if err != nil {
					t.Fatal(err)
				}
				for _, private := range [][]byte{secret, []byte("private complete-create intent"), []byte("private-generated-cleanup-path"), []byte("private-generated-cleanup-error")} {
					for _, representation := range [][]byte{private, []byte(hex.EncodeToString(private)), []byte(base64.StdEncoding.EncodeToString(private))} {
						if bytes.Contains(encoded, representation) {
							t.Fatal("private result or Wait error reached telemetry")
						}
					}
				}
			})
		}
	})
	command.DeadlineUnixMillis = uint64(time.Now().Add(-time.Second).UnixMilli())
	out, code := invokeGeneratedProcess(os.Pipe, context.Background(), telemetryProcessLauncher{}, command, nil)
	if code != contract.CryptoExpired || out.stage != generatedFailureDeadline || out.category != generatedFailureExpired || out.effect != generatedEffectNoSend {
		t.Fatal("pre-start deadline did not retain proved no-send")
	}
}

// full_only: false
func TestGeneratedResultIntakeCancellationOwnsReader(t *testing.T) {
	for _, condition := range []string{"no frame", "short frame", "complete frame without EOF"} {
		t.Run(condition, func(t *testing.T) {
			command := generatedProcessFixtureCommand(t, contract.GeneratorLifecycleManaged, contract.GeneratorActionCreate)
			commandID := protocol.ID(consumerID("retained writer command"))
			var raw bytes.Buffer
			if condition == "short frame" {
				raw.WriteByte(1)
			}
			if condition == "complete frame without EOF" {
				body, err := protocol.EncodeResult(protocol.Result{Schema: 1, AttemptID: protocol.ID(command.AttemptID), ResultID: protocol.ID(command.ResultID), ResultContractID: protocol.ID(command.ResultContractID), ExecutorID: protocol.ID(command.ExecutorID), SafeFacts: generatedProcessFixtureFacts(command, protocol.DispositionCompleteCreate, protocol.ReasonNone), Value: []byte("private held result")})
				if err != nil {
					t.Fatal(err)
				}
				defer clear(body)
				if err := protocol.WriteFrame(&raw, protocol.Frame{Kind: protocol.KindResult, CommandID: commandID, Body: body}); err != nil {
					t.Fatal(err)
				}
			}
			joined := false
			t.Cleanup(func() {
				if joined {
					clear(raw.Bytes())
				}
			})
			launcher := &retainedResultWriterLauncher{commandID: commandID, raw: raw.Bytes(), acquired: make(chan struct{}), started: make(chan struct{})}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			type result struct {
				out  generatedProducerReturn
				code contract.CryptoResultCode
			}
			done := make(chan result, 1)
			t.Cleanup(func() {
				cancel()
				limit := time.NewTimer(5 * time.Second)
				defer limit.Stop()
				if !joined {
					select {
					case <-launcher.acquired:
					case <-done:
						joined = true
					case <-limit.C:
						t.Error("intake setup did not settle after cancellation")
						return
					}
				}
				select {
				case <-launcher.acquired:
					if err := launcher.writer.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
						t.Error(err)
					}
				default:
					// A consumed terminal proves Start cannot later acquire a writer.
				}
				if !joined {
					select {
					case <-done:
						joined = true
					case <-limit.C:
						t.Error("intake call did not settle after cancellation and writer release")
					}
				}
			})
			go func() {
				out, code := invokeGeneratedProcessOwned(os.Pipe, ctx, launcher, command, command.Intent)
				done <- result{out, code}
			}()
			select {
			case <-launcher.started:
			case result := <-done:
				joined = true
				t.Fatal("controlled launcher setup failed", result.code)
			case <-time.After(10 * time.Second):
				t.Fatal("controlled direct child did not join")
			}
			cancel()
			var got result
			select {
			case got = <-done:
				joined = true
			case <-time.After(time.Second):
				// Release the intentionally retained writer, then join the failed call.
				if err := launcher.writer.Close(); err != nil {
					t.Error(err)
				}
				t.Error("intake needed the opposite writer to close after cancellation")
				select {
				case got = <-done:
					joined = true
				case <-time.After(5 * time.Second):
					t.Fatal("intake did not join after the test writer was released")
				}
			}
			if err := launcher.writer.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				t.Error(err)
			}
			if got.code != contract.CryptoCancelled || got.out.effect != generatedEffectUnknown || len(got.out.Secret) != 0 || !reflect.DeepEqual(got.out.Facts, contract.GeneratorSafeFacts{}) || launcher.waits != 1 {
				t.Fatal("canceled native intake lost uncertainty, empty result, or positive run join", got.code, got.out.effect, launcher.waits)
			}
		})
	}
}

type retainedResultWriterLauncher struct {
	commandID protocol.ID
	raw       []byte
	writer    *os.File
	acquired  chan struct{}
	started   chan struct{}
	waits     int
}

func (*retainedResultWriterLauncher) Implementation() contract.GeneratorImplementation {
	return contract.GeneratorImplementation{Schema: 1}
}
func (l *retainedResultWriterLauncher) Start(ctx context.Context, _ protocol.Command, writer *os.File) (generatorhost.Run, error) {
	l.writer = writer
	close(l.acquired)
	if _, err := writer.Write(l.raw); err != nil {
		return nil, err
	}
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGeneratedResultPipeHelper$", "--", "exit")
	child.ExtraFiles = []*os.File{writer}
	child.Env = []string{}
	if err := child.Run(); err != nil {
		return nil, err
	}
	close(l.started)
	return telemetryProcessRun{commandID: l.commandID, status: protocol.Status{Stage: protocol.StatusStageReturn, Category: protocol.StatusOK}, waits: &l.waits}, nil
}

// full_only: false
func TestGeneratedResultPipeHelper(t *testing.T) {
	if len(os.Args) >= 3 && os.Args[len(os.Args)-2] == "--" && os.Args[len(os.Args)-1] == "exit" {
		os.Exit(0)
	}
}

// full_only: false
func TestGeneratedPipeRefusalSettlesOnlyLiveLocalWork(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    contract.GeneratorLifecycleMode
		cancel  bool
		code    contract.CryptoResultCode
		settled bool
	}{
		{"local", contract.GeneratorLifecycleNone, false, contract.CryptoCustodyUnavailable, true},
		{"managed", contract.GeneratorLifecycleManaged, false, contract.CryptoCustodyUnavailable, false},
		{"cancelled local", contract.GeneratorLifecycleNone, true, contract.CryptoCancelled, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			command := generatedProcessFixtureCommand(t, tc.mode, contract.GeneratorActionCreate)
			open := func() (*os.File, *os.File, error) {
				if tc.cancel {
					cancel()
				}
				return nil, nil, os.ErrPermission
			}
			// The embedded nil launcher panics if Start is ever called.
			launcher := struct{ generatorhost.Launcher }{}
			out, code := invokeGeneratedProcess(open, ctx, launcher, command, nil)
			if code != tc.code || out.category != generatedCategoryForCode(tc.code) || out.stage != generatedFailurePipe ||
				out.effect != generatedEffectNoSend || out.settled != tc.settled || len(out.Secret) != 0 {
				t.Fatal("unexpected result-pipe refusal", code, out.stage, out.category, out.effect, out.settled)
			}
		})
	}
}

// full_only: false
func TestGeneratedStartFailureWithReturnedRunAlwaysJoinsWithoutQualification(t *testing.T) {
	command := generatedProcessFixtureCommand(t, contract.GeneratorLifecycleManaged, contract.GeneratorActionCreate)
	cancels := 0
	launcher := telemetryProcessLauncher{startFailure: &os.PathError{Op: "start", Path: "private", Err: os.ErrNotExist}, startRun: telemetryProcessRun{cancels: &cancels}}
	out, code := invokeGeneratedProcess(os.Pipe, t.Context(), launcher, command, nil)
	if code != contract.CryptoCustodyUnavailable || cancels != 1 || out.effect != generatedEffectUnknown || out.executableCleanupFailed || out.settled || len(out.Secret) != 0 || !reflect.DeepEqual(out.Facts, contract.GeneratorSafeFacts{}) {
		t.Fatal("failed Start did not join its returned owner or fabricated host proof")
	}
}

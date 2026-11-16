package generatorhost

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	protocol "enkv.sh/sdk/protocols/generator"
	"enkv.sh/telemetry"
)

type panickingPublicContext struct {
	context.Context
	cause error
}

func (ctx panickingPublicContext) Deadline() (time.Time, bool) { panic(ctx.cause) }

func normalizationRequest(t *testing.T, installed *Installation) protocol.NormalizeRequest {
	t.Helper()
	request := protocol.NormalizeRequest{Schema: 1, DeadlineUnixMillis: uint64(time.Now().Add(time.Minute).UnixMilli()), ConfigContractID: protocol.ID(installed.Artifact().ConfigContractID), Settings: []byte(`{"private-author-setting":1.00}`)}
	var err error
	request.InputDigest, err = protocol.NormalizeInputDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

// full_only: false
func TestPublicGeneratorNormalizationAndCompatibilityUseExactCapturedBuild(t *testing.T) {
	path := buildSDKGenerator(t)
	installed := generatorInstallation(t, path)
	validator, err := NewPublicValidator(t.Context(), path, installed)
	if err != nil {
		t.Fatal(err)
	}
	// A passive exchange must ignore even an oversized declared environment value.
	t.Setenv("ENKV_GENERATOR_TEST_TOKEN", strings.Repeat("x", protocol.MaximumEnvironmentBody))
	recorder := telemetry.NewRecorder()
	ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
	request := normalizationRequest(t, installed)
	response, err := validator.Normalize(ctx, request)
	if err != nil || response.InputDigest != request.InputDigest || !response.Accepted {
		t.Fatal("generic author normalization failed", err)
	}
	intent, err := protocol.DecodeIntent(response.Intent)
	if err != nil || !bytes.Equal(intent.Settings, request.Settings) {
		t.Fatal("author canonical bytes changed", err)
	}
	canonical := protocol.CanonicalRequest{Schema: 1, Purpose: protocol.CanonicalHistorical, DeadlineUnixMillis: request.DeadlineUnixMillis, Intent: response.Intent}
	canonical.InputDigest, err = protocol.CanonicalInputDigest(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := validator.ValidateCanonical(ctx, canonical); err != nil || result.InputDigest != canonical.InputDigest || !result.Accepted {
		t.Fatal("exact canonical validation failed", err)
	}
	fresh := canonical
	fresh.Purpose = protocol.CanonicalFreshCreate
	fresh.InputDigest, err = protocol.CanonicalInputDigest(fresh)
	if err != nil || fresh.InputDigest == canonical.InputDigest {
		t.Fatal("fresh readiness did not bind its distinct purpose", err)
	}
	if result, err := validator.ValidateCanonical(ctx, fresh); err != nil || result.InputDigest != fresh.InputDigest || !result.Accepted {
		t.Fatal("fresh readiness through the exact captured build failed", err)
	}
	command := testCommand(installed.Artifact())
	command.Intent = response.Intent
	command.IntentDigest, err = protocol.IntentDigest(response.Intent)
	if err != nil {
		t.Fatal(err)
	}
	facts := command.NewFacts(protocol.DispositionCompleteCreate, protocol.ReasonNone)
	facts.Target = []byte("original-account")
	facts.ResourceData = []byte("original-resource")
	body, err := protocol.EncodeSafeFacts(facts)
	if err != nil {
		t.Fatal(err)
	}
	compatibility := protocol.RetirementCompatibilityRequest{Schema: 1, DeadlineUnixMillis: request.DeadlineUnixMillis, CompletionClass: protocol.CompletionAcknowledged, Intent: response.Intent, OriginalFacts: body}
	compatibility.InputDigest, err = protocol.RetirementCompatibilityInputDigest(compatibility)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := validator.CheckRetirementCompatibility(ctx, compatibility); err != nil || result.InputDigest != compatibility.InputDigest || !result.Accepted {
		t.Fatal("exact original facts compatibility failed", err)
	}
	starts, returns, drained := 0, 0, 0
	batch := make([]telemetry.DiagnosticRecord, 0, 32)
	for {
		batch = recorder.Drain(batch[:0])
		if len(batch) == 0 {
			break
		}
		drained += len(batch)
		for _, record := range batch {
			if record.Operation != telemetry.OpGeneratorHostStart {
				continue
			}
			if record.Event == telemetry.DiagnosticStart {
				starts++
			}
			if record.Event == telemetry.DiagnosticReturn {
				returns++
				if record.Result != telemetry.ResultSuccess {
					t.Error("normal passive return lost its success", record.Result)
				}
			}
		}
	}
	capture := recorder.Status()
	if capture.Accepted != uint64(drained) || capture.DroppedContention != 0 || capture.DroppedFull != 0 || capture.DroppedClosed != 0 || capture.Rejected != 0 {
		t.Fatal("passive telemetry capture is incomplete", capture, drained)
	}
	if starts != 4 || returns != 4 {
		t.Fatal("normal passive calls lack one return each", starts, returns)
	}
	for _, operation := range []string{"normalize", "canonical", "retirement"} {
		t.Run("panic/"+operation, func(t *testing.T) {
			recorder := telemetry.NewRecorder()
			base := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
			sentinel := errors.New("private-public-check-panic-sentinel")
			ctx := panickingPublicContext{Context: base, cause: sentinel}
			func() {
				defer func() {
					if recovered := recover(); recovered != sentinel {
						t.Errorf("public check changed its panic: %v", recovered)
					}
				}()
				switch operation {
				case "normalize":
					_, _ = validator.Normalize(ctx, request)
				case "canonical":
					_, _ = validator.ValidateCanonical(ctx, canonical)
				case "retirement":
					_, _ = validator.CheckRetirementCompatibility(ctx, compatibility)
				}
				t.Error("public check swallowed its panic")
			}()
			starts, returns := 0, 0
			for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 8)) {
				if err := record.Validate(); err != nil {
					t.Fatal(err)
				}
				if record.Operation != telemetry.OpGeneratorHostStart {
					continue
				}
				if record.Event == telemetry.DiagnosticStart {
					starts++
				}
				if record.Event == telemetry.DiagnosticReturn {
					returns++
				}
			}
			if starts != 1 || returns != 0 {
				t.Errorf("panic emitted a normal terminal: starts=%d returns=%d", starts, returns)
			}
		})
	}
	compatibility.OriginalFacts = bytes.Clone(body)
	compatibility.OriginalFacts[len(body)-2] ^= 1
	if _, err := validator.CheckRetirementCompatibility(t.Context(), compatibility); err == nil || errors.Is(err, ErrPassiveRefused) {
		t.Fatal("changed original facts reused old input digest")
	}

	t.Run("maximum-intent-and-facts", func(t *testing.T) {
		maximum := normalizationRequest(t, installed)
		maximum.Settings = append([]byte{'"'}, bytes.Repeat([]byte{'s'}, 393143)...)
		maximum.Settings = append(maximum.Settings, '"')
		maximum.InputDigest, err = protocol.NormalizeInputDigest(maximum)
		if err != nil {
			t.Fatal(err)
		}
		normalized, err := validator.Normalize(t.Context(), maximum)
		if err != nil || len(normalized.Intent) != 393216 || normalized.InputDigest != maximum.InputDigest {
			t.Fatal("maximum passive intent or exact request failed", err)
		}
		decoded, err := protocol.DecodeIntent(normalized.Intent)
		if err != nil || !bytes.Equal(decoded.Settings, maximum.Settings) {
			t.Fatal("maximum canonical settings changed", err)
		}
		current := testCommand(installed.Artifact())
		current.Intent = normalized.Intent
		current.IntentDigest, err = protocol.IntentDigest(normalized.Intent)
		if err != nil {
			t.Fatal(err)
		}
		original := current.NewFacts(protocol.DispositionCompleteCreate, protocol.ReasonNone)
		original.Target = []byte{'t'}
		original.ResourceData = []byte{'r'}
		original.ProviderFacts = bytes.Repeat([]byte{'p'}, 3979)
		factsBody, err := protocol.EncodeSafeFacts(original)
		if err != nil || len(factsBody) != 4096 {
			t.Fatal("complete facts maximum changed", err)
		}
		request := protocol.RetirementCompatibilityRequest{Schema: 1, DeadlineUnixMillis: maximum.DeadlineUnixMillis, CompletionClass: protocol.CompletionAcknowledged, Intent: normalized.Intent, OriginalFacts: factsBody}
		request.InputDigest, err = protocol.RetirementCompatibilityInputDigest(request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := protocol.EncodeRetirementCompatibilityRequest(request)
		if err != nil || len(body) != 397363 {
			t.Fatal("complete passive request maximum changed", len(body), err)
		}
		result, err := validator.CheckRetirementCompatibility(t.Context(), request)
		if err != nil || !result.Accepted || result.InputDigest != request.InputDigest {
			t.Fatal("maximum exact compatibility failed", err)
		}
	})
	assertNoLaunchDescriptors(t, path)
}

// full_only: false
func TestPublicGeneratorRefusesChangedDigestAndTrailingReplyAfterJoin(t *testing.T) {
	for _, mode := range []string{"public-wrong-digest", "public-trailing"} {
		t.Run(mode, func(t *testing.T) {
			path := buildTestGenerator(t, mode)
			installed := generatorInstallation(t, path)
			validator, err := NewPublicValidator(t.Context(), path, installed)
			if err != nil {
				t.Fatal(err)
			}
			recorder := telemetry.NewRecorder()
			ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
			if _, err := validator.Normalize(ctx, normalizationRequest(t, installed)); !errors.Is(err, ErrProcess) || errors.Is(err, ErrPassiveRefused) {
				t.Fatal("uncorrelated or trailing public reply admitted")
			}
			assertNoLaunchDescriptors(t, path)
			if mode == "public-wrong-digest" {
				terminals := 0
				for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32)) {
					if err := record.Validate(); err != nil {
						t.Fatal("invalid public-host diagnostic", err)
					}
					if record.Operation == telemetry.OpGeneratorHostStart && record.Event == telemetry.DiagnosticReturn {
						terminals++
						if record.Result != telemetry.ResultFailure || record.ErrorClass != telemetry.DiagnosticReasonEvidenceUnavailable {
							t.Error("wrong public digest lost its process-failure meaning", record.Result, record.ErrorClass)
						}
					}
				}
				if terminals != 1 {
					t.Fatal("public admission lacks one terminal", terminals)
				}
			}
		})
	}
	var missing *PublicValidator
	if _, err := missing.Normalize(t.Context(), protocol.NormalizeRequest{}); !errors.Is(err, ErrAdmission) || errors.Is(err, ErrPassiveRefused) {
		t.Fatal("missing passive owner admitted input", err)
	}
}

// full_only: false
func TestPublicGeneratorPassiveRefusalStaysDistinctFromUnboundReply(t *testing.T) {
	for _, operation := range []string{"normalize", "canonical", "fresh-canonical", "retirement"} {
		t.Run(operation, func(t *testing.T) {
			for _, mode := range []string{"public-refused", "public-wrong-digest"} {
				t.Run(mode, func(t *testing.T) {
					path := buildTestGenerator(t, mode)
					installed := generatorInstallation(t, path)
					validator, err := NewPublicValidator(t.Context(), path, installed)
					if err != nil {
						t.Fatal(err)
					}
					request := normalizationRequest(t, installed)
					if operation == "normalize" {
						_, err = validator.Normalize(t.Context(), request)
					} else {
						intent, encodeErr := protocol.EncodeIntent(protocol.Intent{Schema: 1, ConfigContractID: request.ConfigContractID, LifecycleMode: protocol.LifecycleManaged, ResourceContractID: testID(22), Settings: bytes.Clone(request.Settings)})
						if encodeErr != nil {
							t.Fatal(encodeErr)
						}
						if operation == "canonical" || operation == "fresh-canonical" {
							canonical := protocol.CanonicalRequest{Schema: 1, Purpose: protocol.CanonicalHistorical, DeadlineUnixMillis: request.DeadlineUnixMillis, Intent: intent}
							if operation == "fresh-canonical" {
								canonical.Purpose = protocol.CanonicalFreshCreate
							}
							canonical.InputDigest, err = protocol.CanonicalInputDigest(canonical)
							if err != nil {
								t.Fatal(err)
							}
							_, err = validator.ValidateCanonical(t.Context(), canonical)
						} else {
							command := testCommand(installed.Artifact())
							command.Intent = intent
							command.IntentDigest, err = protocol.IntentDigest(intent)
							if err != nil {
								t.Fatal(err)
							}
							facts := command.NewFacts(protocol.DispositionCompleteCreate, protocol.ReasonNone)
							facts.Target, facts.ResourceData = []byte("original-account"), []byte("original-resource")
							original, encodeErr := protocol.EncodeSafeFacts(facts)
							if encodeErr != nil {
								t.Fatal(encodeErr)
							}
							compatibility := protocol.RetirementCompatibilityRequest{Schema: 1, DeadlineUnixMillis: request.DeadlineUnixMillis, CompletionClass: protocol.CompletionAcknowledged, Intent: intent, OriginalFacts: original}
							compatibility.InputDigest, err = protocol.RetirementCompatibilityInputDigest(compatibility)
							if err != nil {
								t.Fatal(err)
							}
							_, err = validator.CheckRetirementCompatibility(t.Context(), compatibility)
						}
					}
					if mode == "public-refused" {
						if !errors.Is(err, ErrPassiveRefused) || !errors.Is(err, ErrAdmission) || errors.Is(err, ErrProcess) {
							t.Fatal("valid passive refusal lost its known semantic outcome", err)
						}
					} else if !errors.Is(err, ErrProcess) || errors.Is(err, ErrPassiveRefused) {
						t.Fatal("unbound public reply looked like a known semantic refusal", err)
					}
					assertNoLaunchDescriptors(t, path)
				})
			}
		})
	}
}

// full_only: false
func TestPublicGeneratorCancellationOwnsResultReader(t *testing.T) {
	for _, mode := range []string{"hold-public-result", "hold-public-result-short", "hold-public-result-eof"} {
		t.Run(mode, func(t *testing.T) {
			path := buildTestGenerator(t, mode)
			installed := generatorInstallation(t, path)
			validator, err := NewPublicValidator(t.Context(), path, installed)
			if err != nil {
				t.Fatal(err)
			}
			listener := endpointHolderListener(t, filepath.Dir(path))
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := validator.Normalize(ctx, normalizationRequest(t, installed))
				done <- err
			}()
			holder := receiveHeldEndpoint(t, listener)
			assertEndpointCancellation(t, cancel, done, holder)
			assertNoLaunchDescriptors(t, path)
		})
	}
}

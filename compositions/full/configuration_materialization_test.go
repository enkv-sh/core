package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	gcpprovider "enkv.sh/providers/gcp"
)

// full_only: false
func TestConfigurationMaterializationCapturesCurrentStateAndPreservesBothFormats(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
			t.Run(fmt.Sprintf("%s/%d", family, format), func(t *testing.T) {
				t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
				t.Setenv("EXPERIMENTAL_GOOGLE_API_USE_S2A", "false")
				source := configurationReaderPair(t, family, format, func(editable, generated map[string]any) {
					// Pending values and membership do not supply current selected facts.
					entries := editable["entries"].(map[string]any)
					entries[""].(map[string]any)["recipients"] = []string{}
					entries[""].(map[string]any)["source"] = map[string]any{"kind": "supplied", "bytes": []byte("pending source sentinel")}
				})
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				server := &readerHTTPFixture{archive: source.archive, reads: map[string]int{}}
				transport, stop := readerHTTPTransport(t, server, []string{"s3.us-east-1.amazonaws.com", "storage.australia-southeast1.rep.googleapis.com"})
				defer stop()
				calls := 0
				open := func(ctx context.Context, c MaterializationConfig) (*core.InstalledMaterialization, error) {
					calls++
					if c.CheckSource(ctx) != nil || !c.SourcePins.Valid() || c.Target == nil {
						t.Fatal("lost captured source lifetime")
					}
					var one [1]byte
					if n, e := source.pair.Editable.ReadAt(one[:], 0); n != 1 || e != nil {
						t.Fatal("source closed before operation")
					}
					if c.AWS != nil {
						c.AWS.Candidate.Credentials = readerFixtureCredentials{}
						c.AWS.Candidate.Transport = transport
					} else {
						client, e := gcpprovider.NewLocalResponderClient(transport, readerFixtureCredentials{})
						if e != nil {
							t.Fatal(e)
						}
						c.GCP.Candidate.Client = client
					}
					return NewMaterialization(ctx, c)
				}
				outPath := filepath.Join(protectedConfigurationTestDirectory(t), "application.env")
				selector := RecipientSelector{ID: readerFixtureTarget(source.archive.Domain)}
				if format == configuration.YAML {
					model, err := configuration.Parse(ctx, source.pair)
					if err != nil {
						t.Fatal(err)
					}
					for _, row := range model.Recipients {
						if row.ID == selector.ID {
							selector = RecipientSelector{Reference: row.Reference}
							break
						}
					}
					if selector.Reference == "" {
						t.Fatal("target has no local reference")
					}
				}
				result, sourceErr := materializeConfigurationSelectedFile(ctx, contract.MaterializationRequest{RequestNonce: contract.ID{1}, Names: []string{""}}, source.path, format, outPath, open, (*configuration.Pair).Close, selector)
				if sourceErr != nil {
					t.Fatal(sourceErr)
				}
				if calls != 1 || result.Validate() != nil || result.StateResult != contract.MaterializationRefused || result.Failure == nil || result.Failure.Stage != contract.MaterializationEncoding || result.Failure.Reason != contract.MaterializationUnrepresentableValue || result.Payload == nil || len(result.Payload.Entries) != 1 || result.Payload.Entries[0].Name != "" {
					t.Fatal("current plain selection did not reach private encoding", calls, result.StateResult, result.Failure)
				}
				if _, e := os.Lstat(outPath); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("refusal created a plaintext destination")
				}
				if source.pair.CheckUnchanged(ctx) != nil {
					t.Fatal("borrowed source closed before caller release")
				}
				source.assertUnchanged(t)
				server.assertNoEffects(t)
				if err := source.pair.Close(); err != nil {
					t.Fatal(err)
				}
				var one [1]byte
				if _, e := source.pair.Editable.ReadAt(one[:], 0); e == nil {
					t.Fatal("caller close retained source descriptor")
				}
			})
		}
	}
}

// full_only: false
func TestConfigurationMaterializationRejectsInvalidRequestsBeforeConstruction(t *testing.T) {
	source := configurationReaderPair(t, "aws", configuration.JSON, nil)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	valid := contract.MaterializationRequest{RequestNonce: contract.ID{1}, Names: []string{"secret"}}
	for _, condition := range []string{"missing-names", "duplicate-names", "nonce", "relative-output", "stdout", "source-alias", "missing-parent", "nil-pair", "canceled"} {
		t.Run(condition, func(t *testing.T) {
			request := valid
			pair := source.pair
			path := filepath.Join(protectedConfigurationTestDirectory(t), "application.env")
			operationCtx := ctx
			switch condition {
			case "missing-names":
				request.Names = nil
			case "duplicate-names":
				request.Names = []string{"secret", "secret"}
			case "nonce":
				request.RequestNonce = contract.ID{}
			case "relative-output":
				path = "relative.env"
			case "stdout":
				path = "-"
			case "source-alias":
				path = source.path
			case "missing-parent":
				path = filepath.Join(path, "missing", "application.env")
			case "nil-pair":
				pair = nil
			case "canceled":
				var stop context.CancelFunc
				operationCtx, stop = context.WithCancel(ctx)
				stop()
			}
			calls := 0
			result := materializeConfiguration(operationCtx, request, pair, path, func(context.Context, MaterializationConfig) (*core.InstalledMaterialization, error) {
				calls++
				return nil, errors.New("private-construction-sentinel")
			})
			if calls != 0 || result.Validate() != nil || result.Payload != nil || result.PreAdmission == nil {
				t.Fatal("invalid request reached construction or lost identity", condition, calls, result)
			}
			var out bytes.Buffer
			if result.WriteJSON(ctx, &out) != nil || bytes.Contains(out.Bytes(), []byte("private-construction-sentinel")) {
				t.Fatal("refusal did not render safely")
			}
		})
	}
	source.assertUnchanged(t)
}

// full_only: false
func TestConfigurationMaterializationFileOwnsCapturedPairAndSeparatesSourceFailure(t *testing.T) {
	source := configurationReaderPair(t, "aws", configuration.JSON, nil)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	for _, condition := range []string{"nil", "unbounded", "canceled", "expired"} {
		t.Run("context-before-capture/"+condition, func(t *testing.T) {
			var operationCtx context.Context
			wantReason := contract.MaterializationInvalidRequest
			wantState := contract.MaterializationRefused
			switch condition {
			case "unbounded":
				operationCtx = context.Background()
			case "canceled":
				var stop context.CancelFunc
				operationCtx, stop = context.WithCancel(ctx)
				stop()
				wantReason, wantState = contract.MaterializationCanceled, contract.MaterializationUnavailable
			case "expired":
				var stop context.CancelFunc
				operationCtx, stop = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer stop()
				wantReason = contract.MaterializationDeadlineExceeded
			}
			missing := filepath.Join(protectedConfigurationTestDirectory(t), "must-not-capture.yaml")
			request := contract.MaterializationRequest{RequestNonce: contract.ID{41}, Names: []string{"secret"}}
			result, err := MaterializeConfigurationFile(operationCtx, request, missing, configuration.YAML, filepath.Join(filepath.Dir(missing), "application.env"))
			if err != nil || result.Validate() != nil || result.Payload != nil || result.PreAdmission == nil || result.PreAdmission.Stage != "context" || result.PreAdmission.RequestNonce != request.RequestNonce || result.OperationID.IsZero() || !result.RequestIdentity.IsZero() || result.Failure == nil || result.Failure.Stage != contract.MaterializationAdmissionStage || result.Failure.Reason != wantReason || result.StateResult != wantState {
				t.Fatal("invalid invocation reached source capture or lost correlated context refusal", err, result.PreAdmission, result.Failure)
			}
			var output bytes.Buffer
			if result.WriteJSON(ctx, &output) != nil {
				t.Fatal("context refusal lost safe result")
			}
		})
	}
	var check func(context.Context) error
	result, err := materializeConfigurationFile(ctx, contract.MaterializationRequest{RequestNonce: contract.ID{1}, Names: []string{"secret"}}, source.path, configuration.JSON, filepath.Join(protectedConfigurationTestDirectory(t), "application.env"), func(ctx context.Context, c MaterializationConfig) (*core.InstalledMaterialization, error) {
		check = c.CheckSource
		if check(ctx) != nil {
			t.Fatal("owned pair was not live during operation")
		}
		return nil, errors.New("private-construction-sentinel")
	}, (*configuration.Pair).Close)
	if err != nil || check == nil || check(ctx) == nil || result.Validate() != nil || result.StateResult != contract.MaterializationUnavailable || result.Failure.Reason != contract.MaterializationRequiredReadUnavailable {
		t.Fatal("file wrapper lost pair ownership or constructor failure", err, result.Failure)
	}
	source.assertUnchanged(t)
	server := &readerHTTPFixture{archive: source.archive, reads: map[string]int{}}
	transport, stop := readerHTTPTransport(t, server, []string{"s3.us-east-1.amazonaws.com"})
	defer stop()
	closed := 0
	admitted, closeErr := materializeConfigurationFile(ctx, contract.MaterializationRequest{RequestNonce: contract.ID{3}, RecipientID: readerFixtureTarget(source.archive.Domain), Names: []string{""}}, source.path, configuration.JSON, filepath.Join(protectedConfigurationTestDirectory(t), "application.env"), func(ctx context.Context, c MaterializationConfig) (*core.InstalledMaterialization, error) {
		check = c.CheckSource
		c.AWS.Candidate.Credentials = readerFixtureCredentials{}
		c.AWS.Candidate.Transport = transport
		return NewMaterialization(ctx, c)
	}, func(pair *configuration.Pair) error {
		closed++
		if err := pair.Close(); err != nil {
			t.Fatal(err)
		}
		return errors.New("private-close-error-sentinel")
	})
	if !errors.Is(closeErr, ErrMaterializationSourceClose) || closed != 1 || check(ctx) == nil || admitted.Validate() != nil || admitted.Payload == nil || admitted.Failure.Stage != contract.MaterializationEncoding || admitted.Failure.Reason != contract.MaterializationUnrepresentableValue || admitted.Payload.Facts.Replacement != contract.MaterializationNotReplaced {
		t.Fatal("source close failure erased admitted operation or leaked ownership", closeErr, admitted.Failure)
	}
	var safe bytes.Buffer
	if admitted.WriteJSON(ctx, &safe) != nil || bytes.Contains(safe.Bytes(), []byte("private-close-error-sentinel")) {
		t.Fatal("source close escaped closed operation result")
	}
	server.assertNoEffects(t)
	missing := filepath.Join(protectedConfigurationTestDirectory(t), "missing.yaml")
	failed, err := MaterializeConfigurationFile(ctx, contract.MaterializationRequest{RequestNonce: contract.ID{2}, Names: []string{"secret"}}, missing, configuration.YAML, filepath.Join(filepath.Dir(missing), "application.env"))
	if !errors.Is(err, ErrMaterializationSource) || failed.Validate() != nil || failed.Payload != nil || failed.PreAdmission.Stage != "capture" {
		t.Fatal("capture failure not separate and safe", err)
	}
	if configuration.MaxPairBytes != 256<<20 || configuration.WindowBytes != 64<<10 {
		t.Fatal("source owner bound changed")
	}
}

// full_only: false
func TestConfigurationMaterializationPreAdmissionRefusalsKeepLocalIdentity(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
			t.Setenv("EXPERIMENTAL_GOOGLE_API_USE_S2A", "false")
			source := configurationReaderPair(t, family, configuration.JSON, nil)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			for _, condition := range []string{"missing-selection", "unauthorized-selection", "required-read-unavailable"} {
				t.Run(condition, func(t *testing.T) {
					server := &readerHTTPFixture{archive: source.archive, reads: map[string]int{}, unavailable: condition == "required-read-unavailable"}
					transport, stop := readerHTTPTransport(t, server, []string{"s3.us-east-1.amazonaws.com", "storage.australia-southeast1.rep.googleapis.com"})
					defer stop()
					request := contract.MaterializationRequest{RequestNonce: contract.ID{37}, Names: []string{""}, RecipientID: readerFixtureTarget(source.archive.Domain)}
					wantStage, wantReason := contract.MaterializationAdmissionStage, contract.MaterializationMissingSelection
					wantState, wantCode := contract.MaterializationRefused, string(contract.ReasonInvalidInput)
					switch condition {
					case "missing-selection":
						request.Names = []string{"ABSENT"}
					case "unauthorized-selection":
						request.RecipientID = contract.Hash([]byte("absent test recipient"))
						wantReason = contract.MaterializationUnauthorizedSelection
					case "required-read-unavailable":
						wantStage = contract.MaterializationLoad
						wantReason, wantState, wantCode = contract.MaterializationRequiredReadUnavailable, contract.MaterializationUnavailable, string(contract.ReasonEvidenceUnavailable)
					}
					var previous contract.ID
					for attempt := 0; attempt < 2; attempt++ {
						calls := 0
						result := materializeConfiguration(ctx, request, source.pair, filepath.Join(protectedConfigurationTestDirectory(t), "application.env"), func(ctx context.Context, c MaterializationConfig) (*core.InstalledMaterialization, error) {
							calls++
							if c.AWS != nil {
								c.AWS.Candidate.Credentials, c.AWS.Candidate.Transport = readerFixtureCredentials{}, transport
							} else {
								client, err := gcpprovider.NewLocalResponderClient(transport, readerFixtureCredentials{})
								if err != nil {
									t.Fatal(err)
								}
								c.GCP.Candidate.Client = client
							}
							return NewMaterialization(ctx, c)
						})
						if calls != 1 || result.Validate() != nil || !result.RequestIdentity.IsZero() || result.OperationID.IsZero() || result.OperationID == previous || result.Payload != nil || result.PreAdmission == nil || result.StateResult != wantState || result.Failure == nil || result.Failure.Stage != wantStage || result.Failure.Reason != wantReason {
							t.Fatal("before-selection refusal published a projection identity or lost exact local failure", calls, result.RequestIdentity, result.PreAdmission, result.Failure)
						}
						previous = result.OperationID
						for _, human := range []bool{false, true} {
							var output bytes.Buffer
							var err error
							if human {
								err = result.WriteHuman(ctx, &output)
							} else {
								err = result.WriteJSON(ctx, &output)
							}
							if err != nil {
								t.Fatal("tagged local refusal did not render", err)
							}
							body := output.Bytes()
							if human {
								if !bytes.Contains(body, []byte("materialize: "+string(wantState)+"\n")) ||
									!bytes.Contains(body, []byte("Operation: "+readerID(result.OperationID)+".\n")) ||
									!bytes.Contains(body, []byte("Admission: observation / "+wantCode+".\n")) ||
									!bytes.Contains(body, []byte("Failure: "+string(wantStage)+" / "+string(wantReason)+".\n")) ||
									bytes.Contains(body, []byte("raw-error-sentinel")) || bytes.Contains(body, []byte("secret-sentinel")) {
									t.Fatal("human refusal lost the observed failure or disclosed private input")
								}
								continue
							}
							var record struct {
								OperationID string                     `json:"operation_id"`
								Payload     json.RawMessage            `json:"payload"`
								Kind        string                     `json:"operation_payload"`
								Replay      string                     `json:"replay_identity"`
								Identity    preAdmissionIdentityRecord `json:"request_identity"`
							}
							if json.Unmarshal(body, &record) != nil || record.OperationID != readerID(result.OperationID) || record.Kind != "none" || string(record.Payload) != "null" || record.Replay != "none" || record.Identity.Schema != "PreAdmissionRequestIdentity/v1" || record.Identity.OperationID != record.OperationID || record.Identity.OperationKind != "materialize" || record.Identity.RequestNonce != readerID(request.RequestNonce) || record.Identity.SourceSchema != "enkv/configuration/v3" || record.Identity.SourceProfile != "direct-candidate" || record.Identity.Format != "json" || record.Identity.Stage != "observation" || record.Identity.Code != wantCode {
								t.Fatal("local refusal lost closed source identity or gained a fabricated projection")
							}
							if bytes.Contains(body, []byte("raw-error-sentinel")) || bytes.Contains(body, []byte("secret-sentinel")) {
								t.Fatal("provider failure escaped safe refusal")
							}
						}
					}
					server.assertNoEffects(t)
				})
			}
			source.assertUnchanged(t)
		})
	}
}

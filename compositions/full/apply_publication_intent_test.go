package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

func applyPublicationIntentSource(t *testing.T) configurationReaderSource {
	t.Helper()
	return configurationAcceptedWorkPair(t, "aws", configuration.JSON, configuration.Entry{
		Name: "future", Secret: true, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw,
		Generated: &configuration.Generator{Plugin: "intent-fixture-uninstalled-generator", Retirement: "manual", Settings: []byte("{}")},
	})
}

// full_only: false
func TestApplyPublicationContinuationRequiresOperationBeforeSourceAccess(t *testing.T) {
	for _, file := range []bool{false, true} {
		name := "pair"
		if file {
			name = "file"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			source := applyPublicationIntentSource(t)
			defer func() {
				if err := source.pair.Close(); err != nil {
					t.Error(err)
				}
			}()
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			model, err := configuration.Parse(ctx, source.pair)
			if err != nil || !model.Resolved {
				t.Fatal("continuation fixture is not a complete source", err)
			}
			before := configurationApplySourceImage(t, filepath.Dir(source.path))
			recorder := telemetry.NewRecorder()
			ctx = telemetry.WithCapability(ctx, telemetry.NewCapability(nil, recorder))
			request, publication := contract.ID{31}, contract.ID{32}
			var result core.PublicApplyPublicationResult
			if file {
				result = ContinueConfigurationApplyAndPublishFile(ctx, request, contract.ID{}, publication, source.path, configuration.JSON, ApplyPublicationOptions{}).PublicApplyPublicationResult
			} else {
				result = ContinueConfigurationApplyAndPublish(ctx, request, contract.ID{}, publication, source.pair, ApplyPublicationOptions{}).PublicApplyPublicationResult
			}
			apply := result.Apply
			if apply.RequestID != request || apply.OperationID.IsZero() || !apply.RequestIdentity.IsZero() || apply.Result.Outcome != core.AdmissionRefused || apply.Result.Reason != core.AdmissionInvalid || apply.Result.CommitMayHaveOccurred || apply.Payload != nil || apply.Generated != nil || len(apply.Receipt) != 0 || apply.PreAdmission == nil || apply.PreAdmission.Stage != "dispatch" || apply.PreAdmission.Code != "invalid-input" || apply.PreAdmission.RequestNonce != request {
				t.Error("zero operation did not retain the recognized input refusal", apply.Result, apply.PreAdmission)
			}
			if result.Publication.Stage != "unstarted" || result.Publication.Reason != "apply-incomplete" || result.Publication.Result != nil {
				t.Error("invalid continuation entered publication", result.Publication)
			}
			for _, record := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32)) {
				if err := record.Validate(); err != nil {
					t.Fatal(err)
				}
				if record.Event == telemetry.DiagnosticStart {
					t.Error("invalid continuation entered a source, plugin or operation owner", record.Operation)
				}
			}
			status := recorder.Status()
			if status.DroppedContention != 0 || status.DroppedFull != 0 || status.DroppedClosed != 0 || status.Rejected != 0 {
				t.Fatal("continuation boundary observation lost diagnostics", status)
			}
			var body bytes.Buffer
			if err := WriteApplyPublicationJSON(&body, result); err != nil {
				t.Fatal("input refusal cannot be rendered", err)
			}
			var wire struct {
				Apply       json.RawMessage
				Publication struct{ Stage, Reason string }
			}
			if json.Unmarshal(body.Bytes(), &wire) != nil || wire.Publication.Stage != "unstarted" || wire.Publication.Reason != "apply-incomplete" {
				t.Fatal("combined refusal lost its publication stage", body.String())
			}
			assertConfigurationPreAdmission(t, wire.Apply, "apply-declaration")
			configurationApplyAssertUnchanged(t, filepath.Dir(source.path), before)
		})
	}
}

// full_only: false
func TestApplyPublicationFreshAndContinuationKeepDistinctConstruction(t *testing.T) {
	for _, continuation := range []bool{false, true} {
		name := "fresh"
		if continuation {
			name = "continuation"
		}
		t.Run(name, func(t *testing.T) {
			var source configurationReaderSource
			if continuation {
				source = applyPublicationIntentSource(t)
			} else {
				source = configurationAcceptedWorkPair(t, "aws", configuration.JSON, configuration.Entry{
					Name: "plain", InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Plain: []byte("fresh input"),
				})
			}
			defer func() {
				if err := source.pair.Close(); err != nil {
					t.Error(err)
				}
			}()
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			operation := contract.ID{}
			if continuation {
				operation = contract.ID{33}
			}
			opened, publishers := 0, 0
			result := configurationApplyPublication(ctx, contract.ID{31}, contract.ID{32}, source.pair, operation, ApplyPublicationOptions{},
				func(_ context.Context, model *configuration.Model, installed core.ApplyInstallation, plugins *configurationInstalledPlugins) (*core.InstalledApply, error) {
					opened++
					if plugins != nil || continuation && (len(installed.PublicConfiguration.Entries.Value) != 0 || len(installed.GeneratorImplementations) != 0) || !continuation && len(installed.PublicConfiguration.Entries.Value) == 0 || len(model.Entries) == 0 {
						t.Error("fresh proposal and accepted construction were interchanged")
					}
					return nil, errors.New("controlled construction refusal")
				}, func(context.Context, *configuration.Model, core.PublicationInstallation, map[contract.ID]string, *configurationInstalledPlugins) (*core.InstalledPublication, error) {
					publishers++
					return nil, errors.New("unexpected publisher construction")
				})
			if opened != 1 || publishers != 0 || result.Apply.Result.Outcome != core.EvidenceUnavailable || result.Apply.Payload != nil || len(result.Apply.Receipt) != 0 || result.Apply.Result.CommitMayHaveOccurred || result.Publication.Stage != "unstarted" || result.Publication.Reason != "apply-incomplete" {
				t.Fatal("construction control changed operation or effect reach", opened, publishers, result.Apply.Result, result.Publication)
			}
		})
	}
}

package crypto

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	protocol "enkv.sh/sdk/protocols/generator"
)

// full_only: false
func TestGeneratedNativeFactsBindCompleteAdmittedCommand(t *testing.T) {
	for _, name := range []string{"exact", "action", "lifecycle", "resource contract", "request", "intent"} {
		t.Run(name, func(t *testing.T) {
			command := generatedProcessFixtureCommand(t, contract.GeneratorLifecycleManaged, contract.GeneratorActionCreate)
			facts := generatedProcessFixtureFacts(command, protocol.DispositionCompleteCreate, protocol.ReasonNone)
			value := []byte("private-value")
			switch name {
			case "action":
				facts.Action, facts.Disposition = protocol.ActionRetire, protocol.DispositionRetirementAcknowledged
				value = nil
			case "lifecycle":
				facts.LifecycleMode = protocol.LifecycleNone
				facts.ResourceContractID = protocol.ID{}
				facts.Target, facts.ResourceData = nil, nil
			case "resource contract":
				facts.ResourceContractID[0] ^= 1
			case "request":
				facts.RequestDigest[0] ^= 1
			case "intent":
				facts.IntentDigest[0] ^= 1
			}
			body, err := protocol.EncodeResult(protocol.Result{Schema: protocol.Schema, AttemptID: protocol.ID(command.AttemptID), ResultID: protocol.ID(command.ResultID), ResultContractID: protocol.ID(command.ResultContractID), ExecutorID: protocol.ID(command.ExecutorID), SafeFacts: facts, Value: value})
			if err != nil {
				t.Fatal("invalid binding fixture", err)
			}
			defer clear(body)
			waits := 0
			launcher := telemetryProcessLauncher{commandID: protocol.ID(consumerID("binding command")), resultBody: body, status: protocol.Status{Stage: protocol.StatusStageReturn, Category: protocol.StatusOK}, waits: &waits}
			out, code := invokeGeneratedProcess(os.Pipe, context.Background(), launcher, command, command.Intent)
			defer clear(out.Secret)
			if name == "exact" {
				if code != contract.CryptoSuccess || len(out.Secret) != len(value) || waits != 1 {
					t.Fatal("exact native result refused", code, out.stage, waits)
				}
				return
			}
			if code != contract.CryptoCustodyUnavailable || len(out.rejectedRetirement) != 0 || out.stage != generatedFailureBinding || len(out.Secret) != 0 || !reflect.DeepEqual(out.Facts, contract.GeneratorSafeFacts{}) || waits != 1 {
				t.Fatal("unbound native facts admitted", code, out.stage, waits)
			}
		})
	}
}

// full_only: false
func TestGeneratedNativeRetirementReturnsOnlyOriginalResourceFacts(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		disposition, reason          uint8
		changeTarget, changeResource bool
		missing                      string
	}{
		{"exact Unknown", protocol.DispositionUnknown, protocol.ReasonTransport, false, false, ""},
		{"exact provider conflict", protocol.DispositionUnknown, protocol.ReasonIdentityConflict, false, false, ""},
		{"different target", protocol.DispositionUnknown, protocol.ReasonTransport, true, false, ""},
		{"different resource", protocol.DispositionUnknown, protocol.ReasonTransport, false, true, ""},
		{"missing target", protocol.DispositionUnknown, protocol.ReasonTransport, false, false, "target"},
		{"missing resource", protocol.DispositionUnknown, protocol.ReasonTransport, false, false, "resource"},
		{"exact acknowledgement", protocol.DispositionRetirementAcknowledged, protocol.ReasonNone, false, false, ""},
		{"different acknowledged target", protocol.DispositionRetirementAcknowledged, protocol.ReasonNone, true, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := generatedProcessFixtureCommand(t, contract.GeneratorLifecycleManaged, contract.GeneratorActionDelete)
			original, err := contract.DecodeGeneratorSafeFacts(command.OriginalFacts)
			if err != nil {
				t.Fatal(err)
			}
			facts := generatedProcessFixtureFacts(command, tc.disposition, tc.reason)
			facts.Target, facts.ResourceData = bytes.Clone(original.Target), bytes.Clone(original.ResourceData)
			if tc.changeTarget {
				facts.Target[0] ^= 1
			}
			if tc.changeResource {
				facts.ResourceData[0] ^= 1
			}
			switch tc.missing {
			case "target":
				facts.Target = nil
			case "resource":
				facts.ResourceData = nil
			}
			packet := protocol.Result{Schema: protocol.Schema, AttemptID: protocol.ID(command.AttemptID), ResultID: protocol.ID(command.ResultID), ResultContractID: protocol.ID(command.ResultContractID), ExecutorID: protocol.ID(command.ExecutorID), SafeFacts: facts}
			body, err := protocol.EncodeResult(packet)
			if tc.missing != "" {
				if !errors.Is(err, protocol.ErrProtocol) || len(body) != 0 {
					t.Fatal("protocol accepted incomplete retirement identity", err)
				}
				// Encode the missing public field under a legal create/Unknown
				// frame, then change only the action in the nested facts header.
				packet.SafeFacts.Action = protocol.ActionCreate
				body, err = protocol.EncodeResult(packet)
				if err != nil {
					t.Fatal(err)
				}
				const actionOffset = 2 + 4*32 + 4 + 2
				body[actionOffset] = protocol.ActionRetire
			}
			if err != nil {
				t.Fatal(err)
			}
			waits := 0
			launcher := telemetryProcessLauncher{commandID: protocol.ID(consumerID("retirement binding")), resultBody: body, status: protocol.Status{Stage: protocol.StatusStageReturn, Category: protocol.StatusOK}, waits: &waits}
			out, code := invokeGeneratedProcess(os.Pipe, t.Context(), launcher, command, command.Intent)
			if waits != 1 || len(out.Secret) != 0 {
				t.Fatal("return custody", waits, len(out.Secret))
			}
			if tc.missing != "" {
				if code != contract.CryptoCustodyUnavailable || out.stage != generatedFailureDecode || out.effect != generatedEffectUnknown || len(out.rejectedRetirement) != 0 || out.Facts.Disposition != 0 {
					t.Fatal("incomplete identity supplied rejection evidence", code, out.stage)
				}
				return
			}
			if tc.changeTarget || tc.changeResource {
				if code != contract.CryptoCustodyUnavailable || out.stage != generatedFailureBinding || out.category != generatedFailureInvalid || out.effect != generatedEffectUnknown || !reflect.DeepEqual(out.Facts, contract.GeneratorSafeFacts{}) {
					t.Fatal("retirement accepted a response with an unbound resource", code, out.stage, out.category, out.effect)
				}
				rejected, err := contract.InspectGeneratorAttemptFacts(out.rejectedRetirement)
				if err != nil || !rejected.RetirementRejected || rejected.Disposition != tc.disposition || rejected.Reason != tc.reason ||
					!bytes.Equal(rejected.Target, facts.Target) || !bytes.Equal(rejected.ResourceData, facts.ResourceData) || len(rejected.ProviderFacts) != 0 {
					t.Fatal("missing exact public rejection from original return", err)
				}
				if _, err := contract.InspectGeneratorSafeFacts(out.rejectedRetirement); err == nil {
					t.Fatal("host rejection qualified as provider facts")
				}
				return
			}
			if len(out.rejectedRetirement) != 0 || code != contract.CryptoSuccess || out.Facts.Reason != tc.reason || out.Facts.Disposition != tc.disposition ||
				!bytes.Equal(out.Facts.Target, original.Target) || !bytes.Equal(out.Facts.ResourceData, original.ResourceData) {
				t.Fatal("exact original retirement facts lost", code, out.stage)
			}
		})
	}
}

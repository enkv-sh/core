package crypto

import (
	"context"
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
			out, code := invokeGeneratedProcess(context.Background(), launcher, command, command.Intent)
			defer clear(out.Secret)
			if name == "exact" {
				if code != contract.CryptoSuccess || len(out.Secret) != len(value) || waits != 1 {
					t.Fatal("exact native result refused", code, out.stage, waits)
				}
				return
			}
			if code != contract.CryptoCustodyUnavailable || out.stage != generatedFailureBinding || len(out.Secret) != 0 || !reflect.DeepEqual(out.Facts, contract.GeneratorSafeFacts{}) || waits != 1 {
				t.Fatal("unbound native facts admitted", code, out.stage, waits)
			}
		})
	}
}

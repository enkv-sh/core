package main

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestMaintenanceCommandsRequireSuccessorOutputBeforeExecutor(t *testing.T) {
	for _, row := range []struct {
		name   string
		kind   uint16
		target []string
	}{
		{"rekey", contract.OperationEnvelopeRekey, []string{"--name", "secret"}},
		{"retire", contract.OperationRetireRecipientIdentity, []string{"--recipient", "recipient"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			args := []string{"--source", filepath.Join(t.TempDir(), "source.json"), "--source-format", "json", "--json", "--log-level", "off"}
			args = append(args, row.target...)
			var out, diagnostic bytes.Buffer
			called := false
			code := runAccessMutationWithExecutor(t.Context(), row.kind, args, &out, &diagnostic, func(context.Context, uint16, contract.ID, accessMutationCommand) compositionfull.MaintenanceCommandResult {
				called = true
				return maintenanceCLIResult(core.PublicApplyResult{Result: core.Result{Outcome: core.Contention}})
			})
			if code != 2 || called {
				t.Fatalf("missing successor output: exit=%d executor_called=%v", code, called)
			}
		})
	}
}

func maintenanceCLIResult(result core.PublicApplyResult) compositionfull.MaintenanceCommandResult {
	return compositionfull.MaintenanceCommandResult{PublicApplyResult: result, Delivery: compositionfull.ReplacementCommandDelivery{Status: "not-attempted"}, SourceUsability: "unchecked"}
}

// full_only: false
func TestMaintenanceCommandsRejectInvalidSuccessorOutputBeforeExecutor(t *testing.T) {
	for _, operation := range []uint16{contract.OperationEnvelopeRekey, contract.OperationRetireRecipientIdentity} {
		for _, output := range []string{"", "/", "/private\x00successor", "/" + string([]byte{255})} {
			args := []string{"--source", "/absolute/source.json", "--source-format", "json", "--out", output, "--json", "--log-level", "off"}
			if operation == contract.OperationEnvelopeRekey {
				args = append(args, "--name", "secret")
			} else {
				args = append(args, "--recipient", "recipient")
			}
			assertSecretAccessGrammarRefusal(t, operation, args)
		}
		args := []string{"--source", "/absolute/source.json", "--source-format", "json", "--out", "/first/successor.json", "--out", "/second/successor.json", "--json", "--log-level", "off"}
		if operation == contract.OperationEnvelopeRekey {
			args = append(args, "--name", "secret")
		} else {
			args = append(args, "--recipient", "recipient")
		}
		assertSecretAccessGrammarRefusal(t, operation, args)
	}
}

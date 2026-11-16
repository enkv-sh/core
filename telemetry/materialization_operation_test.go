package telemetry

import "testing"

// full_only: false
func TestMaterializationOperationsKeepNativeStagesPrivate(t *testing.T) {
	coreOperation := Operation("core.materialize")
	cryptoOperation := Operation("crypto.materialize")
	localStages := []DiagnosticStage{"local_staging", "local_replacement", "local_completion"}
	for _, item := range []struct {
		provider  Provider
		operation Operation
	}{{ProviderCore, coreOperation}, {ProviderCrypto, cryptoOperation}} {
		if !AllowedAttribute("operation", string(item.operation)) || !ValidOperationOwner(item.provider, item.operation) {
			t.Errorf("materialization operation is not registered: %s", item.operation)
		}
		for _, provider := range []Provider{ProviderCore, ProviderCrypto, ProviderAWS, ProviderGCP, ProviderApplication, ProviderWorker, ProviderGeneratorHost, ProviderOutputHost, ProviderManifestHost} {
			if ValidOperationOwner(provider, item.operation) != (provider == item.provider) {
				t.Errorf("unexpected operation owner: %s/%s", provider, item.operation)
			}
		}
		for _, stage := range []DiagnosticStage{DiagnosticProviderCall, DiagnosticCandidatePersistence, DiagnosticCommitObservation} {
			if validDiagnosticStageFor(item.provider, item.operation, stage) {
				t.Errorf("materialization admits an unrelated stage: %s", stage)
			}
		}
	}
	for _, stage := range []DiagnosticStage{DiagnosticAdmission, DiagnosticStateLoading, DiagnosticAuthentication, DiagnosticPrivateCustody} {
		if !validDiagnosticStageFor(ProviderCore, coreOperation, stage) {
			t.Errorf("Core materialization refuses a read stage: %s", stage)
		}
	}
	for _, stage := range append(localStages, DiagnosticPrivateCustody) {
		if !validDiagnosticStageFor(ProviderCrypto, cryptoOperation, stage) {
			t.Errorf("Crypto materialization refuses a private stage: %s", stage)
		}
	}
	for _, stage := range localStages {
		for _, item := range []struct {
			provider  Provider
			operation Operation
		}{{ProviderCore, coreOperation}, {ProviderCrypto, OpCryptoConsume}, {ProviderCrypto, OpCryptoPlanning}, {ProviderAWS, OpKeyDecrypt}, {ProviderGCP, OpKeyDecrypt}} {
			if validDiagnosticStageFor(item.provider, item.operation, stage) {
				t.Errorf("local plaintext stage escaped its owner: %s/%s/%s", item.provider, item.operation, stage)
			}
		}
	}
}

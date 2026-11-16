package crypto_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	"enkv.sh/telemetry"
)

// full_only: false
func TestSecretPublicEvidenceRejectsDictionaryDisclosure(t *testing.T) {
	observer := custody.NewDictionaryObserver()
	domain := contract.Hash([]byte("public evidence domain"))
	recipient := contract.Hash([]byte("public evidence recipient"))
	keys := custody.New(t, contract.GCP, contract.Hash([]byte("public evidence custody")), false, []contract.ID{recipient})
	recorder := telemetry.NewRecorder()
	ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
	core := contract.SealedInputCore{SealedInputCoreFields: contract.SealedInputCoreFields{
		Schema: 4, Profile: 2, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(),
		DomainID: domain, FileIdentity: contract.Hash([]byte("public evidence file")), SourceID: contract.Hash([]byte("public evidence source")),

		DataKeyID: contract.Hash([]byte("public evidence data key")), DataKeyEpoch: 1,
		InputEncoding: contract.InputEncodingRaw, RetainedLength: 0}, Name: "secret"}
	sealed, code := keys.SealInput(ctx, core, []contract.ID{recipient}, custody.StandardValue)
	if code != contract.CryptoSuccess || len(sealed) == 0 {
		t.Fatal("real private source seal failed")
	}
	records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 3))
	status := recorder.Status()
	if status.Accepted != 3 || status.DroppedContention != 0 || status.DroppedFull != 0 || status.DroppedClosed != 0 || status.Rejected != 0 {
		t.Fatalf("successful seal recorder incomplete: %+v", status)
	}
	if len(records) != 3 || records[0].Event != telemetry.DiagnosticStart || records[1].Event != telemetry.DiagnosticCheckpoint || records[2].Event != telemetry.DiagnosticReturn || records[2].Result != telemetry.ResultSuccess {
		t.Fatal("real successful seal diagnostics missing")
	}
	for _, record := range records {
		if err := record.Validate(); err != nil {
			t.Fatal("invalid successful seal diagnostic", err)
		}
	}
	publicRecords, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	if err := observer.Check([]custody.PublicSurface{{Name: "sealed_source", Body: sealed}, {Name: "successful_seal_recorder", Body: publicRecords}}); err != nil {
		t.Fatal(err)
	}

	// The dictionary is fixed before the seal. These controls check each named
	// accidental disclosure form; the real call above checks its public path.
	guess := []byte("enkv first secret test value")
	digest := sha256.Sum256(guess)
	for _, material := range [][]byte{guess, digest[:]} {
		for _, encoded := range [][]byte{material, []byte(hex.EncodeToString(material)), []byte(base64.StdEncoding.EncodeToString(material))} {
			if err := observer.Check([]custody.PublicSurface{{Name: "synthetic_disclosure", Body: encoded}}); err == nil {
				t.Fatal("named dictionary disclosure was accepted")
			}
		}
	}
}

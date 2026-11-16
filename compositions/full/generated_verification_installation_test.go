package compositionfull

import (
	"context"
	"errors"
	"testing"
	"time"

	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
)

// full_only: false
func TestGeneratedOriginalVerificationInstallationUsesPureCryptoAdmission(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", "invalid-input-must-not-be-read-here")
	runtime, err := enkvcrypto.New(contract.GCP, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	id := contract.Hash([]byte("fixed verification construction"))
	installation, closeInvocation, err := configurationGeneratedInstallation(t.Context(), Config{Family: contract.GCP}, runtime, id, id, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeInvocation)
	if installation.AdmitVerification == nil {
		t.Fatal("installed original verification has no pure custody constructor")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	deadline, _ := ctx.Deadline()
	owner, err := installation.AdmitVerification(ctx, contract.CryptoGeneratedCompareRequest{}, contract.ControlCore{}, contract.GeneratedVerificationInput{}, deadline)
	if owner != nil || !errors.Is(err, enkvcrypto.ErrAdmission) {
		t.Fatal("malformed original verification bypassed Crypto admission", err)
	}
	// A rejected verification must not end the shared runtime or capture a
	// producer credential. The producer is absent from this constructor.
	fork, err := runtime.Fork()
	if err != nil {
		t.Fatal("verification admission ended the shared runtime", err)
	}
	fork.Close()
}

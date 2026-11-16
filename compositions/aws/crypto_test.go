package compositionaws

import (
	"context"
	"testing"

	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	awsprovider "enkv.sh/providers/aws"
)

// full_only: false
func TestNewInstallsUnadmittedCrypto(t *testing.T) {
	c := localConfig(t)
	first, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, cell := range []contract.Cell{first, second} {
		runtime, ok := cell.Crypto.(*enkvcrypto.Runtime)
		if !ok || runtime.InstanceID().IsZero() {
			t.Fatalf("Crypto type = %T", cell.Crypto)
		}
		t.Cleanup(runtime.Close)
		q := contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: contract.CryptoCompare, RequestID: contract.Hash([]byte("request")), CustodyInstanceID: runtime.InstanceID()}
		if result := runtime.Exchange(context.Background(), q); result.ResultCode != contract.CryptoInvalidAdmission {
			t.Fatalf("construction granted private admission: %v", result.ResultCode)
		}
	}
	if first.Identity != second.Identity || first.Crypto.InstanceID() == second.Crypto.InstanceID() {
		t.Fatal("cell identity or fresh custody instance differs")
	}
}

// full_only: false
func TestNewRefusesMissingOrInvalidCryptoRoutes(t *testing.T) {
	for _, name := range []string{"missing", "duplicate", "zero", "invalid-later", "too-many"} {
		t.Run(name, func(t *testing.T) {
			c := localConfig(t)
			switch name {
			case "missing":
				c.KeyAccess = nil
			case "duplicate":
				c.KeyAccess = append(c.KeyAccess, c.KeyAccess[0])
			case "zero":
				c.KeyAccess[0].CredentialRoute = contract.ID{}
			case "invalid-later":
				c.KeyAccess = append(c.KeyAccess, awsprovider.KeyAccessConfig{})
			case "too-many":
				c.KeyAccess = make([]awsprovider.KeyAccessConfig, contract.CryptoMaxRecipients+2)
			}
			if cell, err := New(c); err == nil || cell != (contract.Cell{}) {
				t.Fatalf("invalid routes returned cell=%+v error=%v", cell, err)
			}
		})
	}
}

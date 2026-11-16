package contract

import (
	"encoding/hex"
	"testing"
)

// full_only: false
func TestGeneratorRecoveryPolicyIdentityVector(t *testing.T) {
	// Independently derived with Python hashlib.sha256 over the UTF-8 label
	// ENKV/GENERATOR/v1/recovery-policy followed by NUL, u32be(10), and
	// bytes.fromhex("00010102030401010103"). No product encoder is used.
	const want = "5a4c1ad190823e2872fd10b746a337388d99e9fe4834c4e7398515b9d68767c5"
	got := GeneratorRecoveryPolicyID()
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("recovery policy identity: %x", got)
	}
}

// full_only: false
func TestPublicGeneratedRequestRequiresFixedRecoveryPolicy(t *testing.T) {
	request := generatorGraphRequestFixture()
	request.Schema = GeneratorPublicRequestCoreSchema
	request.RecoveryPolicyID = GeneratorRecoveryPolicyID()
	if _, err := EncodeGeneratorRequestCore(request); err != nil {
		t.Fatal(err)
	}
	request.RecoveryPolicyID[0] ^= 1
	if _, err := EncodeGeneratorRequestCore(request); err == nil {
		t.Fatal("public generated request accepted a different recovery policy")
	}
	request.Schema = GeneratorRequestCoreSchema
	if _, err := EncodeGeneratorRequestCore(request); err != nil {
		t.Fatal("retained schema lost its exact accepted policy", err)
	}
}

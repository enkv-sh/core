package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"testing"

	"enkv.sh/core/contract"
)

type damagedSuccessorProbeRoute struct {
	*testKeyAccess
	damage string
	cancel context.CancelFunc
}

func (r *damagedSuccessorProbeRoute) Decrypt(ctx context.Context, binding contract.KMSBinding, ciphertext []byte, length uint16) PrivateResult {
	if r.damage == "public-only" {
		return PrivateResult{Status: KeyOK, Uses: KeyUses{Completed: 1}}
	}
	result := r.testKeyAccess.Decrypt(ctx, binding, ciphertext, length)
	if result.Status != KeyOK {
		return result
	}
	switch r.damage {
	case "denied":
		result.Status, result.Uses = KeyDenied, KeyUses{Denied: 1}
	case "cancelled":
		r.cancel()
	case "packet-kind":
		result.Packet[3] = 2
	case "context":
		result.Packet[4] ^= 1
	case "challenge":
		result.Packet[len(result.Packet)-1] ^= 1
	case "length":
		result.Packet = result.Packet[:len(result.Packet)-1]
	case "missing-use":
		result.Uses = KeyUses{}
	case "extra-use":
		result.Uses.Completed++
	case "overflow-use":
		result.Uses = KeyUses{Completed: 1, Denied: ^uint32(0), Failed: 1}
	case "unknown-use":
		result.Uses = KeyUses{Unknown: 1}
	}
	return result
}

// full_only: false
func TestSuccessorPrivateProbeChecksPacketAndClearsCapacity(t *testing.T) {
	id := func(name string) contract.ID { return contract.Hash([]byte(name)) }
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	binding := contract.KMSBinding{BindingID: id("successor binding"), BindingIncarnationID: id("successor binding incarnation"), BindingSerial: 2, Provider: contract.GCP, WrapProfile: 2, ProtectionClass: 2, KeySelector: "projects/test-project/locations/us-central1/keyRings/test/cryptoKeys/successor/cryptoKeyVersions/2", SPKI: spki, Fingerprint: contract.Hash(spki)}
	digest, err := contract.PublicBindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	c := contract.ApplyContext{OperationClass: contract.CryptoAccessReplacementClass, AdmissionID: id("admission"), SessionID: id("session"), DomainID: id("domain"), CompatibilityID: contract.CompatibilityID(), Expiry: 1, PredecessorHEADDigest: id("head"), OriginalConditionDigest: id("condition"), IntentDescriptor: contract.DescriptorVector{Digest: id("request"), Length: 430, Count: 1}, CurrentAccessRoot: id("access root")}
	root, err := contract.AppendRef(nil, contract.Ref{Kind: contract.RootKind, Format: contract.CanonicalSchema, Domain: c.DomainID, Object: id("snapshot"), Digest: id("root digest"), Length: 100}, contract.CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	copy(c.PredecessorRootRef[:], root)
	for _, genesis := range []bool{false, true} {
		for _, kind := range []uint8{1, 2} {
			for _, damage := range []string{"none", "public-only", "packet-kind", "context", "challenge", "length", "missing-use", "extra-use", "unknown-use", "overflow-use", "denied", "cancelled"} {
				t.Run(fmt.Sprintf("genesis-%t/%d/%s", genesis, kind, damage), func(t *testing.T) {
					base := &testKeyAccess{key: key, binding: binding}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					route := &damagedSuccessorProbeRoute{testKeyAccess: base, damage: damage, cancel: cancel}
					row := contract.BindingTableRow{SubjectKind: kind, SubjectID: id("target"), Binding: binding}
					probe := contract.SuccessorKEKProbeCore{Schema: contract.CanonicalSchema, Profile: 2, ProbeID: id("probe"), Context: c, SubjectKind: kind, SubjectID: row.SubjectID, SuccessorBindingDigest: digest}
					var code contract.CryptoResultCode
					var uses KeyUses
					if genesis {
						init := contract.InitKeyContext{Schema: contract.CryptoSchema, GenesisProfile: 1, AdmissionID: c.AdmissionID, SessionID: c.SessionID, DomainID: c.DomainID, CompatibilityID: c.CompatibilityID, Expiry: 1, InitID: id("init"), DescriptorDigest: id("descriptor"), GenesisPlanDigest: id("plan"), RequestDescriptor: contract.DescriptorVector{Digest: id("request"), Length: contract.GenesisRequestCoreLength, Count: 1}}
						plan := contract.InitProbePlanRow{ProbeID: probe.ProbeID, SubjectKind: kind, SubjectID: row.SubjectID, BindingID: binding.BindingID, PublicBindingDigest: digest}
						code, uses = probeInit(ctx, init, contract.CryptoSupportID(), plan, row, route)
					} else {
						code, uses = probeSuccessorKEK(ctx, probe, row, route)
					}
					if (code == contract.CryptoSuccess) != (damage == "none") {
						t.Fatal("private probe result", code, uses)
					}
					if damage != "public-only" && base.privateCalls != 1 {
						t.Fatal("probe did not use its exact route once")
					}
					if !bytes.Equal(base.returned, make([]byte, len(base.returned))) {
						t.Fatal("probe retained bytes in provider packet capacity")
					}
				})
			}
		}
	}
}

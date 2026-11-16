package contract

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"testing"
)

func successionTestSigning(t testing.TB, role uint8, key byte) PublicSigningBinding {
	t.Helper()
	// Public multiples 1..4 of the P-256 base point, in DER SPKI. The literal
	// points use the standard affine curve equation; no private route is present.
	public := [...]string{
		"3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
		"3059301306072a8648ce3d020106082a8648ce3d030107034200047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1",
		"3059301306072a8648ce3d020106082a8648ce3d030107034200045ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032",
		"3059301306072a8648ce3d020106082a8648ce3d03010703420004e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852e0f1575a4c633cc719dfee5fda862d764efc96c3f30ee0055c42c23f184ed8c6",
	}
	if key < 1 || int(key) > len(public) {
		t.Fatal("signing fixture key outside literal set")
	}
	spki, err := hex.DecodeString(public[key-1])
	if err != nil {
		t.Fatal(err)
	}
	id := func(s string) ID { return Hash([]byte(s)) }
	return PublicSigningBinding{Schema: CanonicalSchema, Role: role, Provider: GCP, SigningProfile: 1, BindingID: id(fmt.Sprintf("signing-%d", key)),
		KeySelector: fmt.Sprintf("projects/fixture/locations/us-central1/keyRings/ring/cryptoKeys/signing-%d/cryptoKeyVersions/1", key), SPKI: spki, Fingerprint: Hash(spki),
		Binding: BindingSubject{Domain: id("domain"), Coordinate: id("coordinate"), Store: id("store"), Trust: id(fmt.Sprintf("trust-%d", role)), PublicKey: Hash(spki), Interpretation: InterpretationID(), ControlIncarnationID: id(fmt.Sprintf("signing-incarnation-%d", role)), Epoch: 1}}
}
func successionTestKMS(t testing.TB, key byte) KMSBinding {
	t.Helper()
	// This odd 3072-bit public modulus is structural test material, with no private route.
	n := new(big.Int).Lsh(big.NewInt(1), 3071)
	n.Add(n, big.NewInt(12345+int64(key)*2))
	spki, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	return KMSBinding{BindingID: Hash([]byte(fmt.Sprintf("kek-%d", key))), BindingIncarnationID: Hash([]byte(fmt.Sprintf("kek-incarnation-%d", key))), BindingSerial: 1, Provider: GCP, WrapProfile: 2, ProtectionClass: 2,
		KeySelector: fmt.Sprintf("projects/fixture/locations/us-central1/keyRings/ring/cryptoKeys/encryption-%d/cryptoKeyVersions/1", key), SPKI: spki, Fingerprint: Hash(spki)}
}
func successionTestRequest(t testing.TB, operation, mask, approval uint8, recovery bool) SuccessionRequestCore {
	t.Helper()
	id := func(s string) ID { return Hash([]byte(s)) }
	b := ControlCore{CurrentControl: CurrentControl{CurrentControlFields: CurrentControlFields{Schema: CanonicalSchema, Profile: 2, DomainID: id("domain"), Provider: GCP, StoreID: id("store"), CoordinateID: id("coordinate"), NonBodyID: id("nonbody"), TrustInterpretationID: TrustInterpretationID(), CompatibilityID: CompatibilityID(), CryptoSupportID: CryptoSupportID(), AuthorityRecipientID: id("authority"), AccessIncarnationID: id("access-incarnation"), AccessGeneration: 1}, NormalSigning: successionTestSigning(t, 1, 1)}, AuthorityKMSBinding: successionTestKMS(t, 1)}
	if recovery {
		b.Recovery = &RecoveryBindings{RoleID: id("recovery"), Signing: successionTestSigning(t, 2, 2), KMS: successionTestKMS(t, 2)}
	}
	a := b
	a.AccessGeneration = 2
	if b.Recovery != nil {
		copied := *b.Recovery
		a.Recovery = &copied
	}
	if mask&1 != 0 {
		a.NormalSigning = successionTestSigning(t, 1, 3)
		a.NormalSigning.Binding.Epoch = 2
	}
	if mask&2 != 0 {
		a.AuthorityKMSBinding = successionTestKMS(t, 3)
		a.AuthorityKMSBinding.BindingIncarnationID = b.AuthorityKMSBinding.BindingIncarnationID
		a.AuthorityKMSBinding.BindingSerial = 2
	}
	if mask&4 != 0 {
		a.Recovery.Signing = successionTestSigning(t, 2, 4)
		a.Recovery.Signing.Binding.Epoch = 2
	}
	if mask&8 != 0 {
		a.Recovery.KMS = successionTestKMS(t, 4)
		a.Recovery.KMS.BindingIncarnationID = b.Recovery.KMS.BindingIncarnationID
		a.Recovery.KMS.BindingSerial = 2
	}
	v := SuccessionRequestCore{SuccessionRequestFields: SuccessionRequestFields{Schema: CanonicalSchema, OperationKind: operation, ApprovalRole: approval, ChangeMask: mask,
		DomainID: b.DomainID, StoreID: b.StoreID, CoordinateID: b.CoordinateID, NonBodyID: b.NonBodyID, TrustInterpretationID: b.TrustInterpretationID, CompatibilityID: b.CompatibilityID, CryptoSupportID: b.CryptoSupportID,
		AdmissionID: id("admission"), OperationID: id("operation"), PredecessorHeadRevisionID: id("previous-revision"), PredecessorFullHEADDigest: id("previous-head"), BeforeAccessRoot: id("before-access")}, Token: Token{Family: GCP, Value: "42"}, BeforeControl: b, ProposedAfterControl: a,
		IdentityPlan: IdentityPlan{Operation: id("operation"), Transition: id("transition"), Snapshot: id("snapshot"), Revision: id("revision")}}
	if mask&(SuccessionChangeAuthorityKEK|SuccessionChangeRecoveryKEK) != 0 {
		v.MaterialSourceRole = SuccessionMaterialAuthority
	}
	successionTestSetRows(&v)
	return v
}
func successionTestSetRows(v *SuccessionRequestCore) {
	v.ReplacementPlan = SuccessionReplacementPlanCore{SuccessionReplacementPlanFields: SuccessionReplacementPlanFields{Schema: v.Schema, DomainID: v.DomainID, OperationKind: v.OperationKind, ChangeMask: v.ChangeMask}}
	roles, count, err := successionRoles(v.OperationKind, v.ChangeMask)
	if err != nil {
		return
	}
	for _, role := range roles[:count] {
		r := SuccessionReplacementRow{TargetRole: role}
		switch role {
		case 1:
			r.BeforeSigning, r.AfterSigning = v.BeforeControl.NormalSigning, v.ProposedAfterControl.NormalSigning
		case 2:
			r.BeforeKMS, r.AfterKMS = v.BeforeControl.AuthorityKMSBinding, v.ProposedAfterControl.AuthorityKMSBinding
		case 3:
			if v.BeforeControl.Recovery != nil && v.ProposedAfterControl.Recovery != nil {
				r.BeforeSigning, r.AfterSigning = v.BeforeControl.Recovery.Signing, v.ProposedAfterControl.Recovery.Signing
			}
		case 4:
			if v.BeforeControl.Recovery != nil && v.ProposedAfterControl.Recovery != nil {
				r.BeforeKMS, r.AfterKMS = v.BeforeControl.Recovery.KMS, v.ProposedAfterControl.Recovery.KMS
			}
		}
		v.ReplacementPlan.Rows = append(v.ReplacementPlan.Rows, r)
	}
}

// full_only: false
func TestSuccessionRequestAllowedChangesAndAuthorizers(t *testing.T) {
	for _, selection := range [][2]uint8{{1, 1}, {1, 2}, {1, 3}, {3, 4}, {3, 8}, {3, 12}} {
		for _, role := range []uint8{1, 2} {
			t.Run(fmt.Sprintf("operation%d-mask%d-role%d", selection[0], selection[1], role), func(t *testing.T) {
				v := successionTestRequest(t, selection[0], selection[1], role, true)
				wire, err := EncodeSuccessionRequestCore(v)
				if err != nil {
					t.Fatal(err)
				}
				d, err := SuccessionRequestDescriptor(v)
				if err != nil || d.Digest != Hash(wire) || d.Length != uint64(len(wire)) || d.Count != uint32(len(v.ReplacementPlan.Rows)) {
					t.Fatal("request descriptor differs", err)
				}
			})
		}
	}
	for _, mask := range []uint8{1, 2, 3} {
		v := successionTestRequest(t, 1, mask, 1, false)
		if _, err := EncodeSuccessionRequestCore(v); err != nil {
			t.Fatal(err)
		}
		v.ApprovalRole = 2
		if _, err := EncodeSuccessionRequestCore(v); err == nil {
			t.Fatal("disabled K3 authorizer admitted")
		}
	}
}

// full_only: false
func TestSuccessionRequestAllowsFreshCounterIncarnationAtLimit(t *testing.T) {
	for _, name := range []string{"access", "signing", "authority binding", "recovery binding"} {
		t.Run(name, func(t *testing.T) {
			operation, mask := uint8(1), uint8(1)
			switch name {
			case "authority binding":
				mask = 2
			case "recovery binding":
				operation, mask = 3, 8
			}
			v := successionTestRequest(t, operation, mask, 1, true)
			fresh := Hash([]byte("fresh " + name + " incarnation"))
			switch name {
			case "access":
				v.BeforeControl.AccessGeneration = math.MaxUint64
				v.ProposedAfterControl.AccessGeneration = 1
				v.ProposedAfterControl.AccessIncarnationID = fresh
			case "signing":
				v.BeforeControl.NormalSigning.Binding.Epoch = math.MaxUint64
				v.ProposedAfterControl.NormalSigning.Binding.Epoch = 1
				v.ProposedAfterControl.NormalSigning.Binding.ControlIncarnationID = fresh
			case "authority binding":
				v.BeforeControl.AuthorityKMSBinding.BindingSerial = math.MaxUint64
				v.ProposedAfterControl.AuthorityKMSBinding.BindingSerial = 1
				v.ProposedAfterControl.AuthorityKMSBinding.BindingIncarnationID = fresh
			case "recovery binding":
				v.BeforeControl.Recovery.KMS.BindingSerial = math.MaxUint64
				v.ProposedAfterControl.Recovery.KMS.BindingSerial = 1
				v.ProposedAfterControl.Recovery.KMS.BindingIncarnationID = fresh
			}
			successionTestSetRows(&v)
			if _, err := EncodeSuccessionRequestCore(v); err != nil {
				t.Fatal("fresh exact succession refused at exhausted local counter", err)
			}
		})
	}
}

// full_only: false
func TestSuccessionRequestRefusesControlAndCounterChanges(t *testing.T) {
	for name, change := range map[string]func(*SuccessionRequestCore){
		"access unchanged": func(v *SuccessionRequestCore) { v.ProposedAfterControl.AccessGeneration = 1 },
		"access skipped":   func(v *SuccessionRequestCore) { v.ProposedAfterControl.AccessGeneration = 3 },
		"access overflow": func(v *SuccessionRequestCore) {
			v.BeforeControl.AccessGeneration = math.MaxUint64
			v.ProposedAfterControl.AccessGeneration = 1
		},
		"signing unchanged epoch": func(v *SuccessionRequestCore) { v.ProposedAfterControl.NormalSigning.Binding.Epoch = 1 },
		"signing skipped epoch":   func(v *SuccessionRequestCore) { v.ProposedAfterControl.NormalSigning.Binding.Epoch = 3 },
		"signing trust changed": func(v *SuccessionRequestCore) {
			v.ProposedAfterControl.NormalSigning.Binding.Trust = Hash([]byte("other trust construction"))
		},
		"signing overflow": func(v *SuccessionRequestCore) {
			v.BeforeControl.NormalSigning.Binding.Epoch = math.MaxUint64
			v.ProposedAfterControl.NormalSigning.Binding.Epoch = 1
		},
		"reused binding": func(v *SuccessionRequestCore) {
			v.ProposedAfterControl.NormalSigning.BindingID = v.BeforeControl.NormalSigning.BindingID
		},
		"other former binding": func(v *SuccessionRequestCore) {
			v.ProposedAfterControl.NormalSigning.BindingID = v.BeforeControl.Recovery.KMS.BindingID
		},
		"unrequested recovery":  func(v *SuccessionRequestCore) { v.ProposedAfterControl.Recovery.KMS.BindingSerial++ },
		"mode removed":          func(v *SuccessionRequestCore) { v.ProposedAfterControl.Recovery = nil },
		"role changed":          func(v *SuccessionRequestCore) { v.ProposedAfterControl.Recovery.RoleID = Hash([]byte("changed role")) },
		"store rebound":         func(v *SuccessionRequestCore) { v.ProposedAfterControl.StoreID = Hash([]byte("changed store")) },
		"request coordinate":    func(v *SuccessionRequestCore) { v.CoordinateID = Hash([]byte("changed coordinate")) },
		"request provider":      func(v *SuccessionRequestCore) { v.Token = Token{Family: AWS, Value: `"etag"`} },
		"identity operation":    func(v *SuccessionRequestCore) { v.IdentityPlan.Operation = Hash([]byte("other operation")) },
		"identity values":       func(v *SuccessionRequestCore) { v.IdentityPlan.Rows = append(v.IdentityPlan.Rows, IdentityRow{}) },
		"excess identity pages": func(v *SuccessionRequestCore) { v.IdentityPlan.Pages = make([]IdentityPage, MaxChildPages+1) },
	} {
		t.Run(name, func(t *testing.T) {
			v := successionTestRequest(t, 1, 1, 2, true)
			change(&v)
			successionTestSetRows(&v)
			if _, err := SuccessionRequestDescriptor(v); err == nil {
				t.Fatal("invalid request admitted")
			}
		})
	}
	for _, role := range []uint8{2, 4} {
		for _, serial := range []uint64{1, 3, math.MaxUint64} {
			op, mask := uint8(1), uint8(2)
			if role == 4 {
				op, mask = 3, 8
			}
			v := successionTestRequest(t, op, mask, 1, true)
			if role == 2 {
				v.ProposedAfterControl.AuthorityKMSBinding.BindingSerial = serial
			} else {
				v.ProposedAfterControl.Recovery.KMS.BindingSerial = serial
			}
			successionTestSetRows(&v)
			if _, err := EncodeSuccessionRequestCore(v); err == nil {
				t.Fatal("invalid KEK serial admitted")
			}
		}
	}
}

// full_only: false
func TestSuccessionRequestRefusesUnrequestedKEKIncarnation(t *testing.T) {
	for _, role := range []string{"authority", "recovery"} {
		t.Run(role, func(t *testing.T) {
			v := successionTestRequest(t, SuccessionReplaceAuthority, SuccessionChangeNormalSigner, RecoverySigningRole, true)
			if _, err := SuccessionRequestDescriptor(v); err != nil {
				t.Fatal("valid signer-only change refused", err)
			}
			if role == "authority" {
				v.ProposedAfterControl.AuthorityKMSBinding.BindingIncarnationID = Hash([]byte("different authority KEK incarnation"))
			} else {
				v.ProposedAfterControl.Recovery.KMS.BindingIncarnationID = Hash([]byte("different recovery KEK incarnation"))
			}
			if _, err := SuccessionRequestDescriptor(v); err == nil {
				t.Fatal("unrequested KEK incarnation change admitted")
			}
		})
	}
}

// full_only: false
func TestSuccessionReplacementRefusesUnusedKEKIncarnation(t *testing.T) {
	for _, role := range []uint8{SuccessorNormalSigner, SuccessorRecoverySigner} {
		for _, field := range []string{"before", "after"} {
			t.Run(fmt.Sprintf("role%d-%s", role, field), func(t *testing.T) {
				operation, mask := uint8(SuccessionReplaceAuthority), uint8(SuccessionChangeNormalSigner)
				if role == SuccessorRecoverySigner {
					operation, mask = SuccessionReplaceRecoveryBasis, SuccessionChangeRecoverySigner
				}
				v := successionTestRequest(t, operation, mask, NormalSigningRole, true).ReplacementPlan
				if _, err := EncodeSuccessionReplacementPlanCore(v); err != nil {
					t.Fatal("empty unused KEK refused", err)
				}
				unused := &v.Rows[0].BeforeKMS
				if field == "after" {
					unused = &v.Rows[0].AfterKMS
				}
				unused.BindingIncarnationID = Hash([]byte("nonempty unused KEK incarnation"))
				if _, err := EncodeSuccessionReplacementPlanCore(v); err == nil {
					t.Fatal("unused KEK incarnation was ignored")
				}
			})
		}
	}
}

// full_only: false
func TestSuccessionRequestRejectsAmbiguousGCPRecoveryParent(t *testing.T) {
	v := successionTestRequest(t, 1, 1, 2, true)
	v.BeforeControl.AuthorityKMSBinding.KeySelector = gcpKMSSelector("fixture-project", "us-central1", "ring", "shared", "1")
	v.BeforeControl.Recovery.KMS.KeySelector = gcpKMSSelector("123456789", "us-central1", "ring", "shared", "2")
	v.ProposedAfterControl = v.BeforeControl
	v.ProposedAfterControl.AccessGeneration++
	v.ProposedAfterControl.NormalSigning = successionTestSigning(t, NormalSigningRole, 3)
	v.ProposedAfterControl.NormalSigning.Binding.Epoch = 2
	successionTestSetRows(&v)
	if _, err := EncodeSuccessionRequestCore(v); err == nil {
		t.Fatal("ambiguous project ID/number recovery parent was admitted for succession")
	}
}

// full_only: false
func TestSuccessionKeyChangeRequiresNewMaterialAndExactSelector(t *testing.T) {
	for _, target := range []struct {
		name      string
		operation uint8
		mask      uint8
		signing   func(*SuccessionRequestCore) (*PublicSigningBinding, *PublicSigningBinding)
	}{
		{"normal", 1, 1, func(v *SuccessionRequestCore) (*PublicSigningBinding, *PublicSigningBinding) {
			return &v.BeforeControl.NormalSigning, &v.ProposedAfterControl.NormalSigning
		}},
		{"normal-combined", 1, 3, func(v *SuccessionRequestCore) (*PublicSigningBinding, *PublicSigningBinding) {
			return &v.BeforeControl.NormalSigning, &v.ProposedAfterControl.NormalSigning
		}},
		{"recovery", 3, 4, func(v *SuccessionRequestCore) (*PublicSigningBinding, *PublicSigningBinding) {
			return &v.BeforeControl.Recovery.Signing, &v.ProposedAfterControl.Recovery.Signing
		}},
		{"recovery-combined", 3, 12, func(v *SuccessionRequestCore) (*PublicSigningBinding, *PublicSigningBinding) {
			return &v.BeforeControl.Recovery.Signing, &v.ProposedAfterControl.Recovery.Signing
		}},
	} {
		for _, approval := range []uint8{1, 2} {
			for name, change := range map[string]func(before, after *PublicSigningBinding){
				"same material, new selector and ID": func(before, after *PublicSigningBinding) {
					after.SPKI = append([]byte(nil), before.SPKI...)
					after.Fingerprint = before.Fingerprint
					after.Binding.PublicKey = before.Binding.PublicKey
				},
				"same selector, new material and ID": func(before, after *PublicSigningBinding) {
					after.KeySelector = before.KeySelector
				},
				"same fingerprint, new material and selector": func(before, after *PublicSigningBinding) {
					after.Fingerprint = before.Fingerprint
					after.Binding.PublicKey = before.Binding.PublicKey
				},
			} {
				t.Run(fmt.Sprintf("%s/approval%d/%s", target.name, approval, name), func(t *testing.T) {
					v := successionTestRequest(t, target.operation, target.mask, approval, true)
					before, after := target.signing(&v)
					change(before, after)
					successionTestSetRows(&v)
					if _, err := EncodeSuccessionRequestCore(v); err == nil {
						t.Fatal("key-changing operation admitted reused material or selector")
					}
				})
			}
		}
	}
}

// full_only: false
func TestSuccessionKEKChangeRequiresNewMaterialAndExactSelector(t *testing.T) {
	for _, target := range []struct {
		name      string
		operation uint8
		mask      uint8
		binding   func(*SuccessionRequestCore) (*KMSBinding, *KMSBinding)
	}{
		{"authority", 1, 2, func(v *SuccessionRequestCore) (*KMSBinding, *KMSBinding) {
			return &v.BeforeControl.AuthorityKMSBinding, &v.ProposedAfterControl.AuthorityKMSBinding
		}},
		{"authority-combined", 1, 3, func(v *SuccessionRequestCore) (*KMSBinding, *KMSBinding) {
			return &v.BeforeControl.AuthorityKMSBinding, &v.ProposedAfterControl.AuthorityKMSBinding
		}},
		{"recovery", 3, 8, func(v *SuccessionRequestCore) (*KMSBinding, *KMSBinding) {
			return &v.BeforeControl.Recovery.KMS, &v.ProposedAfterControl.Recovery.KMS
		}},
		{"recovery-combined", 3, 12, func(v *SuccessionRequestCore) (*KMSBinding, *KMSBinding) {
			return &v.BeforeControl.Recovery.KMS, &v.ProposedAfterControl.Recovery.KMS
		}},
	} {
		for _, approval := range []uint8{1, 2} {
			for name, change := range map[string]func(before, after *KMSBinding){
				"same material, new selector and ID": func(before, after *KMSBinding) {
					after.SPKI = append([]byte(nil), before.SPKI...)
					after.Fingerprint = before.Fingerprint
				},
				"same selector, new material and ID": func(before, after *KMSBinding) {
					after.KeySelector = before.KeySelector
				},
				"same fingerprint, new material and selector": func(before, after *KMSBinding) {
					after.Fingerprint = before.Fingerprint
				},
			} {
				t.Run(fmt.Sprintf("%s/approval%d/%s", target.name, approval, name), func(t *testing.T) {
					v := successionTestRequest(t, target.operation, target.mask, approval, true)
					before, after := target.binding(&v)
					change(before, after)
					successionTestSetRows(&v)
					if _, err := EncodeSuccessionRequestCore(v); err == nil {
						t.Fatal("key-changing operation admitted reused material or selector")
					}
				})
			}
		}
	}
}

// full_only: false
func TestSuccessionRequestRefusesPlanOmissionAndSubstitution(t *testing.T) {
	for name, change := range map[string]func(*SuccessionRequestCore){
		"omitted":   func(v *SuccessionRequestCore) { v.ReplacementPlan.Rows = v.ReplacementPlan.Rows[:1] },
		"duplicate": func(v *SuccessionRequestCore) { v.ReplacementPlan.Rows[1] = v.ReplacementPlan.Rows[0] },
		"reordered": func(v *SuccessionRequestCore) {
			v.ReplacementPlan.Rows[0], v.ReplacementPlan.Rows[1] = v.ReplacementPlan.Rows[1], v.ReplacementPlan.Rows[0]
		},
		"substituted before": func(v *SuccessionRequestCore) {
			v.ReplacementPlan.Rows[0].BeforeSigning.BindingID = Hash([]byte("other before"))
		},
		"substituted after": func(v *SuccessionRequestCore) {
			v.ReplacementPlan.Rows[1].AfterKMS.BindingID = Hash([]byte("other after"))
		},
		"hidden opposite fields": func(v *SuccessionRequestCore) {
			v.ReplacementPlan.Rows[0].BeforeKMS = v.BeforeControl.AuthorityKMSBinding
		},
		"extra mask": func(v *SuccessionRequestCore) { v.ChangeMask |= 4 },
	} {
		t.Run(name, func(t *testing.T) {
			v := successionTestRequest(t, 1, 3, 1, true)
			change(&v)
			if _, err := EncodeSuccessionRequestCore(v); err == nil {
				t.Fatal("invalid replacement vector admitted")
			}
		})
	}
}

// The expected bytes below use only fixed field order and standard big-endian
// append operations. They do not invoke production schema/hash writers.
func successionExpectedBlob(dst, body []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(body)))
	return append(dst, body...)
}
func successionExpectedIDs(dst []byte, ids ...ID) []byte {
	for _, id := range ids {
		dst = append(dst, id[:]...)
	}
	return dst
}
func successionExpectedSigning(v PublicSigningBinding) []byte {
	b := binary.BigEndian.AppendUint16(nil, v.Schema)
	b = append(b, v.Role, byte(v.Provider))
	b = binary.BigEndian.AppendUint16(b, v.SigningProfile)
	b = successionExpectedIDs(b, v.BindingID)
	b = successionExpectedBlob(b, []byte(v.KeySelector))
	b = successionExpectedBlob(b, v.SPKI)
	b = successionExpectedIDs(b, v.Fingerprint)
	p := []byte("ENKV/K1-BINDING/v2\x00")
	p = successionExpectedIDs(p, v.Binding.Domain, v.Binding.Coordinate, v.Binding.Store, v.Binding.Trust, v.Binding.PublicKey, v.Binding.Interpretation, v.Binding.ControlIncarnationID)
	p = binary.BigEndian.AppendUint64(p, v.Binding.Epoch)
	return successionExpectedBlob(b, p)
}
func successionExpectedKMS(v KMSBinding) []byte {
	b := successionExpectedIDs(nil, v.BindingID, v.BindingIncarnationID)
	b = binary.BigEndian.AppendUint64(b, v.BindingSerial)
	b = append(b, byte(v.Provider))
	b = binary.BigEndian.AppendUint16(b, v.WrapProfile)
	b = append(b, byte(v.ProtectionClass))
	b = successionExpectedBlob(b, []byte(v.KeySelector))
	b = append(b, v.SPKI...)
	return successionExpectedIDs(b, v.Fingerprint)
}
func successionExpectedControl(v ControlCore) []byte {
	b := []byte("ENKV/CRYPTO/v2/succession-control-v2\x00")
	b = binary.BigEndian.AppendUint16(b, 11)
	b = binary.BigEndian.AppendUint16(b, 2)
	b = successionExpectedIDs(b, v.DomainID)
	b = append(b, byte(v.Provider))
	b = successionExpectedIDs(b, v.StoreID, v.CoordinateID, v.NonBodyID, v.TrustInterpretationID, v.CompatibilityID, v.CryptoSupportID, v.AuthorityRecipientID)
	b = successionExpectedIDs(b, v.AccessIncarnationID)
	b = binary.BigEndian.AppendUint64(b, v.AccessGeneration)
	b = successionExpectedBlob(b, successionExpectedSigning(v.NormalSigning))
	b = successionExpectedBlob(b, successionExpectedKMS(v.AuthorityKMSBinding))
	if v.Recovery == nil {
		return append(b, 0)
	}
	b = append(b, 1)
	b = successionExpectedIDs(b, v.Recovery.RoleID)
	b = successionExpectedBlob(b, successionExpectedSigning(v.Recovery.Signing))
	return successionExpectedBlob(b, successionExpectedKMS(v.Recovery.KMS))
}

// full_only: false
func TestSuccessionRequestIndependentBytes(t *testing.T) {
	v := successionTestRequest(t, 1, 3, 2, true)
	want := []byte("ENKV/CRYPTO/v2/succession-request-core-v2\x00")
	want = append(want, 0, 11, 1, 2, 3, 1)
	want = successionExpectedIDs(want, v.DomainID, v.StoreID, v.CoordinateID, v.NonBodyID, v.TrustInterpretationID, v.CompatibilityID, v.CryptoSupportID, v.AdmissionID, v.OperationID, v.PredecessorHeadRevisionID, v.PredecessorFullHEADDigest, v.BeforeAccessRoot)
	want = append(want, byte(GCP))
	want = successionExpectedBlob(want, []byte("42"))
	want = successionExpectedBlob(want, successionExpectedControl(v.BeforeControl))
	want = successionExpectedBlob(want, successionExpectedControl(v.ProposedAfterControl))
	plan := []byte("ENKV/CRYPTO/v2/succession-replacement-plan-v1\x00")
	plan = append(plan, 0, 11)
	plan = successionExpectedIDs(plan, v.DomainID)
	plan = append(plan, 1, 3, 0, 2, 1)
	plan = successionExpectedBlob(plan, successionExpectedSigning(v.BeforeControl.NormalSigning))
	plan = successionExpectedBlob(plan, successionExpectedSigning(v.ProposedAfterControl.NormalSigning))
	plan = append(plan, 2)
	plan = successionExpectedBlob(plan, successionExpectedKMS(v.BeforeControl.AuthorityKMSBinding))
	plan = successionExpectedBlob(plan, successionExpectedKMS(v.ProposedAfterControl.AuthorityKMSBinding))
	want = successionExpectedBlob(want, plan)
	identity := []byte("ENKV/LIFECYCLE-ID-PLAN/v7\x00")
	identity = successionExpectedIDs(identity, v.OperationID, v.IdentityPlan.Transition, v.IdentityPlan.Snapshot, v.IdentityPlan.Revision)
	identity = append(identity, make([]byte, 8)...)
	want = successionExpectedBlob(want, identity)
	got, err := EncodeSuccessionRequestCore(v)
	if err != nil || !bytes.Equal(got, want) {
		for i := 0; i < min(len(got), len(want)); i++ {
			if got[i] != want[i] {
				t.Fatalf("request differs at byte %d: got=%02x want=%02x", i, got[i], want[i])
			}
		}
		t.Fatalf("request differs from independent bytes: got=%d want=%d error=%v", len(got), len(want), err)
	}
	d, err := SuccessionRequestDescriptor(v)
	if err != nil || d.Digest != Hash(want) {
		t.Fatal("request hash differs from independent bytes")
	}
	if SuccessionRequestCoreMaxLength != 29669 || SuccessionReplacementPlanCoreMaxLength != 6444 {
		t.Fatal("schema bound differs")
	}
}

// full_only: false
func TestSuccessionRequestRefusesRetiredKind(t *testing.T) {
	for _, approval := range []uint8{1, 2} {
		t.Run(fmt.Sprintf("approval%d", approval), func(t *testing.T) {
			v := successionTestRequest(t, 3, 4, approval, true)
			if _, err := EncodeSuccessionRequestCore(v); err != nil {
				t.Fatal("supported recovery signer replacement refused", err)
			}
			v.ProposedAfterControl.Recovery.Signing = v.BeforeControl.Recovery.Signing
			v.ProposedAfterControl.Recovery.Signing.BindingID = Hash([]byte("fresh recovery signing binding"))
			successionTestSetRows(&v)
			if _, err := EncodeSuccessionRequestCore(v); err == nil {
				t.Fatal("recovery replacement admitted unchanged signing key")
			}
			v.OperationKind, v.ReplacementPlan.OperationKind = 2, 2
			if _, err := EncodeSuccessionReplacementPlanCore(v.ReplacementPlan); err == nil {
				t.Error("retired succession replacement kind admitted")
			}
			if _, err := EncodeSuccessionRequestCore(v); err == nil {
				t.Error("retired succession request kind admitted")
			}
		})
	}
}

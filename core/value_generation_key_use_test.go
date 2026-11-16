package core

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"math"
	"math/big"
	"testing"

	"enkv.sh/core/contract"
)

func generatedPublicBinding(t testing.TB, n byte) contract.KMSBinding {
	t.Helper()
	public := &rsa.PublicKey{N: new(big.Int).SetBytes(bytes.Repeat([]byte{255}, 384)), E: 65537}
	spki, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return contract.KMSBinding{BindingID: generatedVectorID(n), BindingIncarnationID: contract.Hash([]byte{n}), BindingSerial: 1, Provider: contract.GCP,
		WrapProfile: contract.RSAOAEPWrapProfile, ProtectionClass: contract.SoftwareProtection,
		KeySelector: "projects/fixture-project/locations/global/keyRings/fixture/cryptoKeys/fixture/cryptoKeyVersions/1",
		SPKI:        spki, Fingerprint: contract.Hash(spki)}
}

// full_only: false
func TestGeneratedKeyUsesAccumulateExactCheckedRows(t *testing.T) {
	row := contract.KeyUseRow{BindingID: generatedVectorID(1), PublicBindingDigest: generatedVectorID(2), SubjectKind: 1,
		SubjectID: generatedVectorID(3), Provider: contract.GCP, Purpose: contract.KeyUseMaterialOpen, Outcome: contract.KeyUseCompleted, Count: 2}
	wrap := row
	wrap.Purpose, wrap.Count = contract.KeyUseMaterialWrap, 1
	var p generatedPreparation
	if !p.accumulateKeyUses([]contract.KeyUseRow{row}) || !p.accumulateKeyUses([]contract.KeyUseRow{wrap, row}) ||
		len(p.keyUses) != 2 || p.keyUses[0] != wrap || p.keyUses[1].Count != 4 {
		t.Fatal("key-use facts lost counts or canonical order")
	}
	if _, err := contract.CryptoGeneratedKeyUseDescriptor(p.keyUses); err != nil {
		t.Fatal(err)
	}
	row.Count = math.MaxUint32
	if p.accumulateKeyUses([]contract.KeyUseRow{row}) {
		t.Fatal("aggregate key-use count overflow accepted")
	}
}

// full_only: false
func TestGeneratedKeyUseCountsMatchEachExchange(t *testing.T) {
	id := generatedVectorID
	bindings := []contract.BindingTableRow{
		{SubjectKind: 1, SubjectID: id(1), Binding: generatedPublicBinding(t, 11)},
		{SubjectKind: 1, SubjectID: id(2), Binding: generatedPublicBinding(t, 12)},
		{SubjectKind: 2, SubjectID: id(3), Binding: generatedPublicBinding(t, 13)},
	}
	use := func(index int, purpose uint8, count uint32) contract.KeyUseRow {
		b := bindings[index]
		digest, err := contract.PublicBindingDigest(b.Binding)
		if err != nil {
			t.Fatal(err)
		}
		return contract.KeyUseRow{BindingID: b.Binding.BindingID, PublicBindingDigest: digest, SubjectKind: b.SubjectKind,
			SubjectID: b.SubjectID, Provider: b.Binding.Provider, Purpose: purpose, Outcome: contract.KeyUseCompleted, Count: count}
	}
	for _, tc := range []struct {
		name  string
		kind  contract.CryptoKind
		opens uint32
		wraps map[contract.ID]uint32
		uses  []contract.KeyUseRow
	}{
		{"initial comparison", contract.CryptoCompare, 0, nil, nil},
		{"continuation comparison", contract.CryptoCompare, 1, nil, []contract.KeyUseRow{use(0, contract.KeyUseMaterialOpen, 1)}},
		{"declaration part", contract.CryptoPrepare, 2, nil, []contract.KeyUseRow{use(0, contract.KeyUseMaterialOpen, 2)}},
		{"graph part", contract.CryptoPrepare, 0, nil, nil},
		{"seed finish", contract.CryptoPrepare, 0, map[contract.ID]uint32{id(11): 1, id(13): 1}, []contract.KeyUseRow{use(0, contract.KeyUseMaterialWrap, 1), use(2, contract.KeyUseMaterialWrap, 1)}},
		{"member batch", contract.CryptoPrepare, 0, map[contract.ID]uint32{id(11): 2, id(12): 1, id(13): 2}, []contract.KeyUseRow{use(0, contract.KeyUseMaterialWrap, 2), use(1, contract.KeyUseMaterialWrap, 1), use(2, contract.KeyUseMaterialWrap, 2)}},
		{"adopt", contract.CryptoPrepare, 0, nil, nil},
		{"producer", contract.CryptoPrepare, 0, nil, nil},
		{"freeze", contract.CryptoFreeze, 0, nil, nil},
		{"claim", contract.CryptoClaim, 0, nil, nil},
		{"discard", contract.CryptoDiscard, 0, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op := &cryptoOperation{context: contract.ApplyContext{OperationClass: contract.CryptoGeneratedClass}, authority: id(1),
				bindings: bindings, sourceCount: tc.opens, wrapCounts: tc.wraps}
			if !op.keyUsesValid(tc.kind, contract.CryptoSuccess, tc.uses) {
				t.Fatal("exact successful key uses refused")
			}
			if len(tc.uses) != 0 && op.keyUsesValid(tc.kind, contract.CryptoSuccess, tc.uses[:len(tc.uses)-1]) {
				t.Fatal("missing successful key use accepted")
			}
			extra := append(append([]contract.KeyUseRow(nil), tc.uses...), use(0, contract.KeyUseMaterialOpen, 1))
			if op.keyUsesValid(tc.kind, contract.CryptoSuccess, extra) {
				t.Fatal("unadmitted key open accepted")
			}
			for _, outcome := range []uint8{contract.KeyUseDenied, contract.KeyUseFailed, contract.KeyUseUnknown} {
				if len(tc.uses) == 0 {
					continue
				}
				partial := []contract.KeyUseRow{tc.uses[0]}
				partial[0].Outcome = outcome
				if !op.keyUsesValid(tc.kind, contract.CryptoCustodyUnavailable, partial) || op.keyUsesValid(tc.kind, contract.CryptoSuccess, partial) {
					t.Fatal("failed attempt accounting changed successful evidence")
				}
			}
		})
	}
}

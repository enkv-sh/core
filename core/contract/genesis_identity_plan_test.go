package contract

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

// full_only: false
func TestGenesisRequestIdentityBindsOriginalCaptureAndFiniteExpiry(t *testing.T) {
	id := func(s string) ID { return Hash([]byte(s)) }
	v := GenesisRequestCore{InitID: id("init"), DomainID: id("domain"), DescriptorDigest: id("descriptor"),
		GenesisIdentityPlanDigest: id("identity plan"), SetupDigest: id("original captured setup"), Expiry: 1,
		InitOwnerDecision: 1, RecoveryLossAcknowledgement: 1}
	// This field-order oracle does not call a production serializer. A historical
	// expiry remains valid public data; execution admission owns the time check.
	want := []byte("ENKV/CRYPTO/v2/genesis-request-v2\x00")
	want = binary.BigEndian.AppendUint16(want, 11)
	want = binary.BigEndian.AppendUint16(want, 1)
	for _, field := range []ID{v.InitID, v.DomainID, v.DescriptorDigest, v.GenesisIdentityPlanDigest, v.SetupDigest} {
		want = append(want, field[:]...)
	}
	want = binary.BigEndian.AppendUint64(want, 1)
	want = append(want, 0, 1, 1)
	body, err := EncodeGenesisRequestCore(v)
	if err != nil || len(body) != 209 || !bytes.Equal(body, want) {
		t.Fatal("normalized request differs from independent 209-byte field order", err)
	}
	decoded, err := DecodeGenesisRequestCore(want)
	if err != nil || decoded != v {
		t.Fatal("historical normalized request did not decode", err)
	}
	for name, change := range map[string]func(*GenesisRequestCore){
		"setup":  func(q *GenesisRequestCore) { q.SetupDigest = id("different captured setup") },
		"expiry": func(q *GenesisRequestCore) { q.Expiry++ },
		"plan":   func(q *GenesisRequestCore) { q.GenesisIdentityPlanDigest = id("different identity plan") },
	} {
		t.Run(name, func(t *testing.T) {
			q := v
			change(&q)
			changed, err := EncodeGenesisRequestCore(q)
			if err != nil || Hash(changed) == Hash(body) {
				t.Fatal("authority-bearing capture change did not change request identity", err)
			}
		})
	}
	for _, invalid := range []GenesisRequestCore{func() GenesisRequestCore { q := v; q.Expiry = 0; return q }(), func() GenesisRequestCore { q := v; q.Expiry = 1 << 63; return q }()} {
		if _, err := EncodeGenesisRequestCore(invalid); err == nil {
			t.Fatal("invalid original finite expiry accepted")
		}
	}
	old := bytes.Replace(want, []byte("genesis-request-v2"), []byte("genesis-request-v1"), 1)
	if _, err := DecodeGenesisRequestCore(old); err == nil {
		t.Fatal("legacy request interpretation accepted")
	}
}

// full_only: false
func TestGenesisIdentityPlanAllowsOnlyNamedReceiptHoles(t *testing.T) {
	id := func(s string) ID { return Hash([]byte(s)) }
	probe := initKeysFixture(t).Probes[0]
	v := GenesisIdentityPlanCore{DomainID: id("domain"), DescriptorDigest: id("descriptor"),
		IdentityPlan: IdentityPlan{Operation: id("init"), Transition: id("transition"), Snapshot: id("snapshot"), Revision: id("revision"), Rows: []IdentityRow{},
			Pages: []IdentityPage{{Kind: RecipientKind, Object: id("recipients")}, {Kind: RequiredSupportKind, Object: id("receipt and output")}, {Kind: RequiredSupportKind, Index: 1, Object: id("receipt index")}, {Kind: AdministrativeIndexKind, Object: id("admin")}}}, Probes: []InitProbePlanRow{probe}}
	body, err := EncodeGenesisIdentityPlanCore(v)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeGenesisIdentityPlanCore(body)
	if err != nil || !reflect.DeepEqual(decoded, v) {
		t.Fatal("typed identity plan differs", err)
	}
	for _, tag := range [][]byte{[]byte("HEAD-ABSENT"), []byte("InitPayload/v1"), []byte("receipt-request-identity-hole"), []byte("receipt-complete-result-digest-hole")} {
		changed := bytes.Clone(body)
		at := bytes.Index(changed, tag)
		if at < 0 {
			t.Fatal("identity plan omitted fixed interpretation", string(tag))
		}
		changed[at] ^= 1
		if _, err := DecodeGenesisIdentityPlanCore(changed); err == nil {
			t.Fatal("identity decoder admitted altered fixed construction", string(tag))
		}
	}
	receipt, err := GenesisReceiptFields(v.DomainID, v.IdentityPlan.Operation, v.IdentityPlan.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EncodeCompactMutationReceipt(receipt); err == nil {
		t.Fatal("an identity-plan receipt template became a usable retained receipt")
	}
}

package custody

import (
	"bytes"
	"context"
	"testing"
	"time"

	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
)

// full_only: false
func TestInitRoutesReopenWithoutPrivateProcessFacts(t *testing.T) {
	id := func(s string) contract.ID { return contract.Hash([]byte(s)) }
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		f := New(t, family, id("fixture"), true, []contract.ID{id("authority"), id("reader")})
		g := New(t, family, id("fixture"), true, []contract.ID{id("authority"), id("reader")})
		rows := f.Bindings()
		other := g.Bindings()
		if len(rows) != 3 || len(other) != 3 {
			t.Fatal("missing enrolled binding")
		}
		for i := range rows {
			x, err := contract.PublicBindingDigest(rows[i].Binding)
			if err != nil {
				t.Fatal(err)
			}
			y, err := contract.PublicBindingDigest(other[i].Binding)
			if err != nil || x != y {
				t.Fatal("public route changed on reopen")
			}
			clear(other[i].Binding.SPKI)
		}
		for i, row := range f.Bindings() {
			if !bytes.Equal(row.Binding.SPKI, rows[i].Binding.SPKI) {
				t.Fatal("public result aliases key owner")
			}
		}
		deadline := time.Now().Add(time.Minute)
		q := contract.CryptoQualifyInitKeysRequest{Context: contract.InitKeyContext{Schema: 3, GenesisProfile: 1, AdmissionID: id("admission"), SessionID: id("session"), DomainID: id("domain"), CompatibilityID: contract.CompatibilityID(), Expiry: uint64(deadline.UnixNano()), InitID: id("init"), DescriptorDigest: id("descriptor"), GenesisPlanDigest: id("plan"), RequestDescriptor: contract.DescriptorVector{Digest: id("request"), Length: contract.GenesisRequestCoreLength, Count: 1}}, Bindings: rows}
		for _, subject := range []contract.ID{id("authority"), f.RecoveryID()} {
			for _, row := range rows {
				if row.SubjectID != subject {
					continue
				}
				digest, err := contract.PublicBindingDigest(row.Binding)
				if err != nil {
					t.Fatal(err)
				}
				q.Probes = append(q.Probes, contract.InitProbePlanRow{ProbeID: id("probe" + string(subject[:])), SubjectKind: row.SubjectKind, SubjectID: subject, BindingID: row.Binding.BindingID, PublicBindingDigest: digest})
			}
		}
		if err := f.AdmitInit(q, contract.CryptoSupportID(), deadline); err != nil {
			t.Fatal(err)
		}
		body, err := contract.EncodeCryptoQualifyInitKeysRequest(q)
		if err != nil {
			t.Fatal(err)
		}
		r := f.Crypto().Exchange(context.Background(), contract.CryptoRequest{Schema: 3, Kind: contract.CryptoQualifyInitKeys, RequestID: id("message"), CustodyInstanceID: f.Crypto().InstanceID(), Body: body})
		if r.ResultCode != contract.CryptoSuccess {
			t.Fatalf("qualification refused: %v", r.ResultCode)
		}
		if public, private := f.Calls(); public != 3 || private != 2 {
			t.Fatalf("qualification calls: %d/%d", public, private)
		}
	}
}

// full_only: false
func TestMaximumGCPSelectorsRemainValidAndIndependent(t *testing.T) {
	id := func(s string) contract.ID { return contract.Hash([]byte(s)) }
	f := New(t, contract.GCP, id("maximum selectors"), true, []contract.ID{id("authority"), id("reader")})
	f.UseMaximumSelectors(t)
	rows := f.Bindings()
	if len(rows) != 3 {
		t.Fatal("missing maximum-selector bindings")
	}
	var authority, recovery contract.KMSBinding
	for _, row := range rows {
		if len(row.Binding.KeySelector) != contract.MaxKeySelector {
			t.Fatal("selector did not reach contract capacity")
		}
		if !contract.PublicKeySelectorValid(row.Binding.Provider, row.Binding.KeySelector, false) {
			t.Fatal("maximum selector does not preserve public grammar")
		}
		if row.SubjectID == f.authority {
			authority = row.Binding
		}
		if row.SubjectID == f.recovery {
			recovery = row.Binding
		}
	}
	if !contract.IndependentKMSBindings(authority, recovery) {
		t.Fatal("maximum GCP selectors do not prove separate parents")
	}
}

// full_only: false
func TestKeyRoutesCountRefusedInvocations(t *testing.T) {
	id := func(s string) contract.ID { return contract.Hash([]byte(s)) }
	f := New(t, contract.GCP, id("refused route calls"), false, []contract.ID{id("authority")})
	binding := f.Bindings()[0].Binding
	route := &keyRoute{owner: f, subject: f.authority, id: f.routes[binding.BindingID]}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name       string
		ctx        context.Context
		binding    contract.KMSBinding
		ciphertext []byte
		length     uint16
		public     privatecrypto.KeyStatus
		private    privatecrypto.KeyStatus
	}{
		{"canceled", canceled, binding, make([]byte, 384), 68, privatecrypto.KeyCancelled, privatecrypto.KeyCancelled},
		{"invalid-binding", context.Background(), contract.KMSBinding{}, make([]byte, 384), 68, privatecrypto.KeyInvalid, privatecrypto.KeyInvalid},
		{"invalid-ciphertext", context.Background(), binding, nil, 68, privatecrypto.KeyOK, privatecrypto.KeyInvalid},
		{"invalid-length", context.Background(), binding, make([]byte, 384), 67, privatecrypto.KeyOK, privatecrypto.KeyInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			public, private := f.Calls()
			if got := route.Qualify(tc.ctx, tc.binding); got.Status != tc.public {
				t.Fatalf("qualification status: got %v, want %v", got.Status, tc.public)
			}
			if got := route.Decrypt(tc.ctx, tc.binding, tc.ciphertext, tc.length); got.Status != tc.private || len(got.Packet) != 0 {
				t.Fatalf("private refusal: got status %v and %d packet bytes", got.Status, len(got.Packet))
			}
			if gotPublic, gotPrivate := f.Calls(); gotPublic != public+1 || gotPrivate != private+1 {
				t.Fatalf("refused route calls: got %d/%d, want %d/%d", gotPublic-public, gotPrivate-private, 1, 1)
			}
		})
	}
}

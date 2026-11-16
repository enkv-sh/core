package format

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

func fid(n byte) ID { var id ID; id[0] = n; return id }

func configurationAdministrativeRef(t testing.TB, domain, snapshot ID, support Ref, row contract.SupportRecord) Ref {
	t.Helper()
	index := AdministrativeIndex{Domain: domain, Object: fid(210), SliceSnapshot: snapshot,
		Pages: []AdministrativePage{{Ref: support, Spans: []AdministrativeSpan{{First: 0, Count: 1, Mandatory: true}},
			Rows: []AdministrativeRowSummary{{Kind: row.Kind, RecordID: row.RecordID, BodyLength: uint32(len(row.Body))}}}}}
	pages, err := EncodeAdministrativeIndexPages(index)
	if err != nil || len(pages) != 1 {
		t.Fatal(err)
	}
	return pages[0].Ref
}

func valueEntryPageFixture() ValueEntryPage {
	return ValueEntryPage{Domain: fid(1), Object: fid(2), Index: 3, Slots: [PageSlots]*ValueEntry{0: {
		Name: "sample", Incarnation: fid(3), ValueState: fid(4), OriginSnapshot: fid(5),
		OriginTransition: fid(6), Recipients: []ID{fid(7)}, ValueSource: Supplied, ConfidentialityClass: Plain, ValueBytes: []byte("value"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 5, RetainedLength: 5,
	}}}
}

func recipientFixture(t testing.TB) RecipientPage {
	t.Helper()
	n := new(big.Int).Lsh(big.NewInt(1), 3071)
	n.Add(n, big.NewInt(12345))
	spki, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	return RecipientPage{Domain: fid(1), Object: fid(8), Index: 4, Slots: [RecipientSlots]*Recipient{2: {RecipientID: fid(7), Status: Current, CurrentBinding: &contract.KMSBinding{BindingID: fid(9), BindingIncarnationID: fid(79), BindingSerial: 1, Provider: contract.AWS, WrapProfile: 2, ProtectionClass: 2, KeySelector: "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000001", SPKI: spki, Fingerprint: contract.Hash(spki)}}}}
}
func currentControlFixture(t testing.TB) contract.CurrentControl {
	t.Helper()
	// Fixed public P-256 generator SPKI preserves the independent codec vectors.
	spki, err := hex.DecodeString("3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
	if err != nil {
		t.Fatal(err)
	}
	signing := contract.PublicSigningBinding{Schema: contract.CanonicalSchema, Role: 1, Provider: contract.AWS, SigningProfile: 1, BindingID: fid(70), KeySelector: "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000002", SPKI: spki, Fingerprint: contract.Hash(spki), Binding: contract.BindingSubject{Domain: fid(1), Coordinate: fid(72), Store: fid(71), Trust: fid(75), PublicKey: contract.Hash(spki), Interpretation: fid(76), ControlIncarnationID: fid(80), Epoch: 1}}
	return contract.CurrentControl{CurrentControlFields: contract.CurrentControlFields{Schema: contract.CanonicalSchema, Profile: 2, DomainID: fid(1), Provider: contract.AWS, StoreID: fid(71), CoordinateID: fid(72), NonBodyID: fid(73), TrustInterpretationID: fid(74), CompatibilityID: fid(77), CryptoSupportID: fid(78), AuthorityRecipientID: fid(7), AccessIncarnationID: fid(81), AccessGeneration: 1}, NormalSigning: signing}
}
func conditionFixture(t contract.Token) contract.HeadCondition {
	c, err := contract.MatchHeadCondition(t)
	if err != nil {
		panic(err)
	}
	return c
}
func rootFixture(t testing.TB) Root {
	t.Helper()
	m := valueEntryPageFixture()
	mb, err := EncodeValueEntryPage(m)
	if err != nil {
		t.Fatal(err)
	}
	mr, err := Reference(ValueEntryPageKind, m.Domain, m.Object, m.Index, mb)
	if err != nil {
		t.Fatal(err)
	}
	r := recipientFixture(t)
	rb, err := EncodeRecipientPage(r)
	if err != nil {
		t.Fatal(err)
	}
	rr, err := Reference(RecipientKind, r.Domain, r.Object, r.Index, rb)
	if err != nil {
		t.Fatal(err)
	}
	recipients, err := contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: fid(1), Refs: []Ref{rr}})
	if err != nil {
		t.Fatal(err)
	}
	records, err := contract.AccessRecordsDescriptor(fid(1), nil)
	if err != nil {
		t.Fatal(err)
	}
	access := contract.CurrentAccessCore{CurrentControl: currentControlFixture(t), RecipientRefsDescriptor: recipients, AccessRecordsDescriptor: records}
	digest, err := contract.AccessRoot(access)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := contract.EncodeOutputConfiguration(contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: fid(1)})
	if err != nil {
		t.Fatal(err)
	}
	configurationDescriptor, slices, err := contract.SplitOutputConfiguration(fid(1), configuration)
	if err != nil || len(slices) != 1 {
		t.Fatal(err)
	}
	sliceBody, err := contract.EncodeOutputConfigurationSlice(slices[0])
	if err != nil {
		t.Fatal(err)
	}
	sliceID, err := contract.OutputConfigurationSliceID(fid(1), configurationDescriptor.ConfigurationDigest, 0)
	if err != nil {
		t.Fatal(err)
	}
	row := contract.SupportRecord{Kind: contract.OutputConfigurationSliceSupportKind, RecordID: sliceID, Body: sliceBody}
	supportBody, err := EncodeRequiredSupportPage(RequiredSupportPage{Domain: fid(1), Object: fid(211), Index: 0, Records: []contract.SupportRecord{row}})
	if err != nil {
		t.Fatal(err)
	}
	supportRef, err := Reference(contract.RequiredSupportKind, fid(1), fid(211), 0, supportBody)
	if err != nil {
		t.Fatal(err)
	}
	admin := configurationAdministrativeRef(t, fid(1), fid(10), supportRef, row)
	return Root{Domain: fid(1), Snapshot: fid(10), Transition: fid(11), ValueEntryPages: [contract.MaxValueEntryPages]*Ref{3: &mr}, Recipients: [contract.MaxRecipientPages]*Ref{4: &rr}, CurrentAccess: contract.CurrentAccessSection{Core: access, AccessRoot: digest}, AdministrativeIndex: admin, RequiredSupport: []Ref{supportRef}, OutputConfiguration: configurationDescriptor, Names: []NameEntry{{Name: "sample", Slot: 48}}, ValueEntryCount: 1, RawBytes: 5, MembershipCount: 1, RecipientCount: 1, RequiredSupportRecordCount: 1, ChildCount: 4, ChildEncodedBytes: uint64(len(mb)+len(rb)+len(supportBody)) + uint64(admin.Length), Generated: EmptyGeneratedClosure(), GCPlans: contract.EmptyGCOwnersDescriptor()}
}

func projectionFixture(t testing.TB) (HeadCore, ConditionalPlan, contract.LifecycleSubject) {
	t.Helper()
	core := HeadCore{Form: SuccessorHead, Domain: fid(1), Revision: fid(2), PreviousRevision: fid(3), PreviousDigest: fid(4), PreviousToken: contract.Token{Family: contract.AWS, Value: `"etag-1"`},
		Root:  Ref{Kind: RootKind, Format: Version, Domain: fid(1), Object: fid(5), Digest: fid(6), Length: 123},
		Store: fid(7), Trust: fid(8), Coordinate: fid(9), NonBody: fid(10), Interpretation: fid(11), Epoch: 12}
	cb, err := EncodeHeadCore(core)
	if err != nil {
		t.Fatal(err)
	}
	plan := ConditionalPlan{Family: contract.AWS, Store: fid(7), Coordinate: fid(9), NonBody: fid(10), Condition: conditionFixture(core.PreviousToken), HeadCore: contract.Hash(cb), HeadCoreLength: uint32(len(cb))}
	pb, err := EncodeConditionalPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	subject := contract.LifecycleSubject{OperationKind: contract.OperationApplyDeclaration, Operation: fid(20), Request: fid(23),
		Recipient: fid(26), KeyBinding: fid(27), Fingerprint: fid(28), BindingVersion: 1,
		IdentityPlan: contract.DigestLength{Digest: fid(29), Length: 337}, HeadCore: contract.Hash(cb), HeadCoreLength: uint32(len(cb)), ConditionalPlan: contract.Hash(pb),
		BeforeValueEntryCount: 1, AfterValueEntryCount: 1, BeforeRawBytes: 5, AfterRawBytes: 5, BeforeAccessRoot: fid(34), AfterAccessRoot: fid(35), BeforeMembershipCount: 1, AfterMembershipCount: 1,
		Normal: contract.NormalSection{Intent: contract.DigestLength{Digest: fid(24), Length: 888}, PublicState: contract.DigestLength{Digest: fid(30), Length: 187},
			Union: contract.DescriptorVector{Digest: fid(25), Length: 282, Count: 1}, Changed: 1},
		Grant:     contract.GrantSection{Grants: contract.DescriptorVector{Digest: fid(31), Length: 61}},
		Exclusion: contract.ExclusionSection{Exclusions: contract.DescriptorVector{Digest: fid(32), Length: 65}, Retirements: contract.DescriptorVector{Digest: fid(33), Length: 66}},
	}
	return core, plan, subject
}

func headFixture(t testing.TB) Head {
	t.Helper()
	core, _, subject := projectionFixture(t)
	// This minimal DER is structurally valid, but it is not an authority proof.
	// Cryptographic acceptance is tested by Core; Format owns canonical parsing.
	sig := []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}
	return Head{Core: core, AuthKind: LifecycleAuth, Subject: subject, K1: bytes.Clone(sig), AuthorizationSignature: bytes.Clone(sig)}
}

// full_only: false
func TestAllRecordCanonicalAndTruncation(t *testing.T) {
	m, err := EncodeValueEntryPage(valueEntryPageFixture())
	if err != nil {
		t.Fatal(err)
	}
	r, err := EncodeRecipientPage(recipientFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	root, err := EncodeRoot(rootFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	h := headFixture(t)
	core, err := EncodeHeadCore(h.Core)
	if err != nil {
		t.Fatal(err)
	}
	head, err := EncodeHead(h)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := contract.LifecycleBytes(h.Subject)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		body      []byte
		roundtrip func([]byte) ([]byte, error)
	}{
		{"member", m, func(b []byte) ([]byte, error) {
			p, e := DecodeValueEntryPage(b)
			if e != nil {
				return nil, e
			}
			return EncodeValueEntryPage(p)
		}},
		{"recipient", r, func(b []byte) ([]byte, error) {
			p, e := DecodeRecipientPage(b)
			if e != nil {
				return nil, e
			}
			return EncodeRecipientPage(p)
		}},
		{"root", root, func(b []byte) ([]byte, error) {
			p, e := DecodeRoot(b)
			if e != nil {
				return nil, e
			}
			return EncodeRoot(p)
		}},
		{"core", core, func(b []byte) ([]byte, error) {
			p, e := DecodeHeadCore(b)
			if e != nil {
				return nil, e
			}
			return EncodeHeadCore(p)
		}},
		{"head", head, func(b []byte) ([]byte, error) {
			p, e := DecodeHead(b)
			if e != nil {
				return nil, e
			}
			return EncodeHead(p)
		}},
		{"lifecycle", lifecycle, func(b []byte) ([]byte, error) {
			p, e := DecodeLifecycleSubject(b)
			if e != nil {
				return nil, e
			}
			return contract.LifecycleBytes(p)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.roundtrip(tc.body)
			if err != nil || !bytes.Equal(got, tc.body) {
				t.Fatal("canonical round trip", err)
			}
			for i := range tc.body {
				if _, err := tc.roundtrip(tc.body[:i]); err == nil {
					t.Fatalf("truncation %d accepted", i)
				}
			}
			if _, err := tc.roundtrip(append(bytes.Clone(tc.body), 0)); err == nil {
				t.Fatal("trailing byte accepted")
			}
			for _, at := range []int{0, 4, 5, 6} {
				broken := bytes.Clone(tc.body)
				broken[at] = 255
				if _, err := tc.roundtrip(broken); err == nil {
					t.Fatalf("unknown schema at %d accepted", at)
				}
			}
		})
	}
}

// full_only: false
func TestMemberRejectsInvalidFields(t *testing.T) {
	tests := []struct {
		name   string
		change func(*ValueEntryPage)
	}{
		{"empty page", func(p *ValueEntryPage) { p.Slots = [PageSlots]*ValueEntry{} }},
		{"page index", func(p *ValueEntryPage) { p.Index = contract.MaxValueEntryPages }},
		{"domain", func(p *ValueEntryPage) { p.Domain = ID{} }},
		{"name bytes", func(p *ValueEntryPage) { p.Slots[0].Name = string([]byte{255}) }},
		{"name length", func(p *ValueEntryPage) { p.Slots[0].Name = strings.Repeat("n", contract.CryptoMaxName+1) }},
		{"source", func(p *ValueEntryPage) { p.Slots[0].ValueSource = 2 }},
		{"encoding", func(p *ValueEntryPage) { p.Slots[0].ConfidentialityClass = 2 }},
		{"incarnation", func(p *ValueEntryPage) { p.Slots[0].Incarnation = ID{} }},
		{"recipient", func(p *ValueEntryPage) { p.Slots[0].Recipients[0] = ID{} }},
		{"duplicate name", func(p *ValueEntryPage) {
			c := *p.Slots[0]
			c.Incarnation = fid(30)
			c.ValueState = fid(31)
			p.Slots[1] = &c
		}},
		{"duplicate incarnation", func(p *ValueEntryPage) { c := *p.Slots[0]; c.Name = "other"; c.ValueState = fid(31); p.Slots[1] = &c }},
		{"duplicate value identity", func(p *ValueEntryPage) { c := *p.Slots[0]; c.Name = "other"; c.Incarnation = fid(30); p.Slots[1] = &c }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := valueEntryPageFixture()
			tc.change(&p)
			if _, err := EncodeValueEntryPage(p); err == nil {
				t.Fatal("invalid member page accepted")
			}
		})
	}
	b, err := EncodeValueEntryPage(valueEntryPageFixture())
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(b[75:79], ^uint32(0))
	if _, err := DecodeValueEntryPage(b); err == nil {
		t.Fatal("overflow length accepted")
	}
}

// full_only: false
func TestPageBoundsAndOwnedBytes(t *testing.T) {
	p := valueEntryPageFixture()
	p.Slots[0].Name = strings.Repeat("n", contract.CryptoMaxName)
	p.Slots[0].ValueBytes = nil
	p.Slots[0].ContentLength, p.Slots[0].RetainedLength = 0, 0
	b, err := EncodeValueEntryPage(p)
	if err != nil {
		t.Fatal("empty value and max name", err)
	}
	decoded, err := DecodeValueEntryPage(b)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 1
	if decoded.Slots[0].Name != p.Slots[0].Name || len(decoded.Slots[0].ValueBytes) != 0 {
		t.Fatal("decoder retained caller storage")
	}
	for i := range p.Slots {
		c := *p.Slots[0]
		c.Name = fmt.Sprintf("member-%02d", i)
		c.Incarnation = fid(byte(i + 40))
		c.ValueState = fid(byte(i + 80))
		c.ValueBytes = make([]byte, contract.CryptoMaxRawValue)
		c.ContentLength, c.RetainedLength = contract.CryptoMaxRawValue, contract.CryptoMaxRawValue
		p.Slots[i] = &c
	}
	b, err = EncodeValueEntryPage(p)
	if err != nil || len(b) > MaxValueEntryPage {
		t.Fatal("16 maximum values", err)
	}
	d, err := DecodeValueEntryPage(b)
	if err != nil {
		t.Fatal(err)
	}
	expected := d.Slots[15].ValueBytes[contract.CryptoMaxRawValue-1]
	b[len(b)-1] ^= 1
	if d.Slots[15].ValueBytes[contract.CryptoMaxRawValue-1] != expected {
		t.Fatal("value aliases caller storage")
	}
	if _, err := DecodeValueEntryPage(make([]byte, MaxValueEntryPage+1)); err == nil {
		t.Fatal("oversized encoded page accepted")
	}
}

// full_only: false
func TestRecipientRejectsInvalidKeyAndBinding(t *testing.T) {
	// The format4 page has one occupied-slot mask byte. Each bit maps only to
	// its eight fixed recipient slots; an absent or excess row must refuse.
	p := recipientFixture(t)
	p.Slots[7] = p.Slots[2]
	p.Slots[2] = nil
	body, err := EncodeRecipientPage(p)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRecipientPage(body)
	if err != nil || decoded.Slots[7] == nil {
		t.Fatal("last recipient slot refused")
	}
	for _, mask := range []byte{0, 1, 255} {
		broken := bytes.Clone(body)
		broken[73] = mask
		if mask == 1 {
			if page, err := DecodeRecipientPage(broken); err != nil || page.Slots[0] == nil {
				t.Fatal("first mask bit refused")
			}
		} else if _, err := DecodeRecipientPage(broken); err == nil {
			t.Fatal("mask and row count mismatch accepted")
		}
	}
	for _, tc := range []struct {
		name   string
		change func(*Recipient)
	}{
		{"version", func(r *Recipient) { r.CurrentBinding.BindingSerial = 0 }},
		{"status", func(r *Recipient) { r.Status = 3 }},
		{"algorithm", func(r *Recipient) { r.CurrentBinding.WrapProfile = 1 }},
		{"fingerprint", func(r *Recipient) { r.CurrentBinding.Fingerprint = fid(50) }},
		{"malformed key", func(r *Recipient) {
			r.CurrentBinding.SPKI = []byte{0}
			r.CurrentBinding.Fingerprint = contract.Hash(r.CurrentBinding.SPKI)
		}},
		{"overlong key", func(r *Recipient) {
			r.CurrentBinding.SPKI = make([]byte, contract.KMSPublicKeyLength+1)
			r.CurrentBinding.Fingerprint = contract.Hash(r.CurrentBinding.SPKI)
		}},
		{"other key family", func(r *Recipient) {
			b := currentControlFixture(t).NormalSigning.SPKI
			r.CurrentBinding.SPKI = b
			r.CurrentBinding.Fingerprint = contract.Hash(b)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := recipientFixture(t)
			tc.change(p.Slots[2])
			if _, err := EncodeRecipientPage(p); err == nil {
				t.Fatal("invalid recipient accepted")
			}
		})
	}
	p = recipientFixture(t)
	p.Index = contract.MaxRecipientPages
	if _, err := EncodeRecipientPage(p); err == nil {
		t.Fatal("out-of-range recipient page accepted")
	}
}

// full_only: false
func TestRootRejectsInvalidIndexAndReferences(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Root)
	}{
		{"unsupported", func(p *Root) { p.Unsupported = 1 }},
		{"member count", func(p *Root) { p.ValueEntryCount++ }},
		{"child count", func(p *Root) { p.ChildCount++ }},
		{"raw count", func(p *Root) { p.RawBytes = contract.CryptoMaxRawSet + 1 }},
		{"index wrong slot", func(p *Root) { p.Names[0].Slot = 0 }},
		{"index duplicate slot", func(p *Root) { p.Names = append(p.Names, NameEntry{"second", 48}); p.ValueEntryCount++ }},
		{"index duplicate name", func(p *Root) { p.Names = append(p.Names, NameEntry{"sample", 49}); p.ValueEntryCount++ }},
		{"index not sorted", func(p *Root) { p.Names = append(p.Names, NameEntry{"earlier", 49}); p.ValueEntryCount++ }},
		{"index no member", func(p *Root) { p.ValueEntryPages[3] = nil; p.ChildCount-- }},
		{"unindexed page", func(p *Root) {
			c := *p.ValueEntryPages[3]
			c.Object = fid(60)
			c.Index = 5
			p.ValueEntryPages[5] = &c
			p.ChildCount++
		}},
		{"missing recipient", func(p *Root) { p.Recipients[4] = nil; p.ChildCount-- }},
		{"extra recipient", func(p *Root) {
			c := *p.Recipients[4]
			c.Object = fid(60)
			c.Index = 5
			p.Recipients[5] = &c
			p.ChildCount++
		}},
		{"reference domain", func(p *Root) { p.ValueEntryPages[3].Domain = fid(60) }},
		{"reference index", func(p *Root) { p.ValueEntryPages[3].Index++ }},
		{"reference type", func(p *Root) { p.ValueEntryPages[3].Kind = RecipientKind }},
		{"reference format", func(p *Root) { p.ValueEntryPages[3].Format++ }},
		{"reference length", func(p *Root) { p.ValueEntryPages[3].Length = MaxValueEntryPage + 1 }},
		{"reference duplicate identity", func(p *Root) { p.Recipients[4].Object = p.ValueEntryPages[3].Object }},
		{"missing administrative index", func(p *Root) { p.AdministrativeIndex = Ref{} }},
		{"unknown warning bit", func(p *Root) { p.WarningBits = 0x20 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := rootFixture(t)
			tc.change(&p)
			if _, err := EncodeRoot(p); err == nil {
				t.Fatal("invalid root accepted")
			}
		})
	}
	root := rootFixture(t)
	root.ValueEntryPages = [contract.MaxValueEntryPages]*Ref{}
	root.Names = nil
	root.ValueEntryCount = 0
	root.MembershipCount = 0
	root.RawBytes = 0
	root.ChildCount = 3
	root.ChildEncodedBytes = uint64(root.Recipients[4].Length) + uint64(root.AdministrativeIndex.Length) + uint64(root.RequiredSupport[0].Length)
	if _, err := EncodeRoot(root); err != nil {
		t.Fatal("empty domain refused", err)
	}
}

// full_only: false
func TestSharedCountBoundaryAndRootCapacity(t *testing.T) {
	// These synthetic count inputs are not complete supported state closures.
	if err := CheckChildCount(256); err != nil {
		t.Fatal(err)
	}
	for _, n := range []uint32{257, ^uint32(0)} {
		if CheckChildCount(n) == nil {
			t.Fatalf("count %d accepted", n)
		}
	}
	p := rootFixture(t)
	p.ValueEntryPages = [contract.MaxValueEntryPages]*Ref{}
	p.Names = nil
	for i := 0; i < contract.MaxValueEntryPages; i++ {
		p.ValueEntryPages[i] = &Ref{Kind: ValueEntryPageKind, Domain: p.Domain, Object: fid(byte(i + 80)), Digest: fid(190), Format: Version, Length: 100, Index: uint16(i)}
	}
	for i := 0; i < contract.CryptoMaxValueEntries; i++ {
		p.Names = append(p.Names, NameEntry{fmt.Sprintf("member-%03d", i), uint16(i)})
	}
	p.ValueEntryCount, p.RawBytes, p.ChildCount = contract.CryptoMaxValueEntries, contract.CryptoMaxRawSet, contract.MaxValueEntryPages+3
	p.MembershipCount = contract.CryptoMaxValueEntries
	p.ChildEncodedBytes = uint64(contract.MaxValueEntryPages*100) + uint64(p.Recipients[4].Length) + uint64(p.AdministrativeIndex.Length) + uint64(p.RequiredSupport[0].Length)
	b, err := EncodeRoot(p)
	if err != nil || len(b) > MaxRoot {
		t.Fatal("bounded 512-member root", err)
	}
	p.ValueEntryCount++
	p.Names = append(p.Names, NameEntry{"member-512", 512})
	if _, err := EncodeRoot(p); err == nil {
		t.Fatal("513-member root accepted")
	}
}

// full_only: false
func TestReferencesBindCompleteObjectAndCoordinate(t *testing.T) {
	p := valueEntryPageFixture()
	b, err := EncodeValueEntryPage(p)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := Reference(ValueEntryPageKind, p.Domain, p.Object, p.Index, b)
	if err != nil {
		t.Fatal(err)
	}
	key, err := Key("fixture", ref)
	if err != nil {
		t.Fatal(err)
	}
	want := "fixture/" + hex.EncodeToString(p.Domain[:]) + "/member/3/" + hex.EncodeToString(p.Object[:])
	if key != want {
		t.Fatalf("key %q, want %q", key, want)
	}
	for _, prefix := range []string{"", "/fixture", "fixture/", "fixture//x", "fixture/../x", "fixture/./x", "fixture?x", "fixture#x", "fixture\\x", "fixture\x00"} {
		if _, err := Key(prefix, ref); err == nil {
			t.Fatalf("invalid prefix %q", prefix)
		}
	}
	for _, change := range []func(*Ref){func(r *Ref) { r.Domain = fid(90) }, func(r *Ref) { r.Object = fid(90) }, func(r *Ref) { r.Digest = fid(90) }, func(r *Ref) { r.Index++ }, func(r *Ref) { r.Kind = RecipientKind }, func(r *Ref) { r.Length++ }, func(r *Ref) { r.Format++ }} {
		c := ref
		change(&c)
		if CheckReference(c, b) == nil {
			t.Fatal("mismatched reference accepted")
		}
	}
	broken := bytes.Clone(b)
	broken[len(broken)-1] ^= 1
	if CheckReference(ref, broken) == nil {
		t.Fatal("corrupt body accepted")
	}
	if _, err := Reference(HeadKind, p.Domain, p.Object, 0, b); err == nil {
		t.Fatal("mutable HEAD reference accepted")
	}
}

// full_only: false
func TestGeneratedResultKeysUseSeparateDomainLocalCoordinates(t *testing.T) {
	var domain, coordinate ID
	domain[0], coordinate[0] = 1, 2
	key, err := GeneratedResultKey("fixture/nested", domain, coordinate)
	want := "fixture/nested/0100000000000000000000000000000000000000000000000000000000000000/result/0200000000000000000000000000000000000000000000000000000000000000"
	if err != nil || key != want {
		t.Fatal("fixed result key differs from independent literal", key, err)
	}
	if _, err := GeneratedResultKey(strings.Repeat("x", 512), domain, coordinate); err != nil {
		t.Fatal("maximum admitted result prefix refused", err)
	}
	for _, prefix := range []string{"", "/fixture", "fixture/", "fixture//x", "fixture/../x", "fixture/./x", "fixture?x", "fixture#x", "fixture\\x", "fixture\x00", "fixture\xff", strings.Repeat("x", 513)} {
		if _, err := GeneratedResultKey(prefix, domain, coordinate); err == nil {
			t.Fatalf("invalid result prefix %q", prefix)
		}
	}
	for _, ids := range [][2]ID{{{}, coordinate}, {domain, {}}} {
		if _, err := GeneratedResultKey("fixture", ids[0], ids[1]); err == nil {
			t.Fatal("zero result coordinate admitted")
		}
	}
}

// full_only: false
func TestHeadRejectsInvalidProofStructureAndProjection(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Head)
	}{
		{"ready sections", func(h *Head) { h.Core.Unsupported = 1 }},
		{"zero epoch", func(h *Head) { h.Core.Epoch = 0 }},
		{"bad token", func(h *Head) { h.Core.PreviousToken.Value = "" }},
		{"wrong root domain", func(h *Head) { h.Core.Root.Domain = fid(90) }},
		{"core digest", func(h *Head) { h.Subject.HeadCore = fid(90) }},
		{"core length", func(h *Head) { h.Subject.HeadCoreLength++ }},
		{"plan digest", func(h *Head) { h.Subject.ConditionalPlan = fid(90) }},
		{"empty signature", func(h *Head) { h.K1 = nil }},
		{"overlong signature", func(h *Head) { h.AuthorizationSignature = make([]byte, 73) }},
		{"negative signature", func(h *Head) { h.AuthorizationSignature = []byte{0x30, 6, 2, 1, 255, 2, 1, 1} }},
		{"zero signature", func(h *Head) { h.AuthorizationSignature = []byte{0x30, 6, 2, 1, 0, 2, 1, 1} }},
		{"noncanonical signature", func(h *Head) { h.AuthorizationSignature = []byte{0x30, 7, 2, 2, 0, 1, 2, 1, 1} }},
		{"trailing signature", func(h *Head) { h.AuthorizationSignature = append(h.AuthorizationSignature, 0) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := headFixture(t)
			tc.change(&h)
			if _, err := EncodeHead(h); err == nil {
				t.Fatal("invalid HEAD accepted")
			}
		})
	}
	_, p, _ := projectionFixture(t)
	p.Family = contract.GCP
	if _, err := EncodeConditionalPlan(p); err == nil {
		t.Fatal("mismatched token family accepted")
	}
	if _, err := contract.MatchHeadCondition(contract.Token{Family: contract.GCP, Value: "01"}); err == nil {
		t.Fatal("noncanonical generation accepted")
	}
	p.Condition = conditionFixture(contract.Token{Family: contract.GCP, Value: "1"})
	if b, err := EncodeConditionalPlan(p); err != nil || !bytes.Contains(b, []byte("POST")) {
		t.Fatal("GCP method", err)
	}
}

// full_only: false
func TestEveryBoundProjectionFieldChangesItsCommitment(t *testing.T) {
	core, plan, subject := projectionFixture(t)
	coreBytes, err := EncodeHeadCore(core)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*HeadCore){
		func(c *HeadCore) { c.Domain = fid(99); c.Root.Domain = c.Domain },
		func(c *HeadCore) { c.Revision = fid(99) },
		func(c *HeadCore) { c.PreviousRevision = fid(99) },
		func(c *HeadCore) { c.PreviousDigest = fid(99) },
		func(c *HeadCore) { c.PreviousToken.Value = `"other"` },
		func(c *HeadCore) { c.Root.Object = fid(99) },
		func(c *HeadCore) { c.Root.Digest = fid(99) },
		func(c *HeadCore) { c.Root.Length++ },
		func(c *HeadCore) { c.Store = fid(99) },
		func(c *HeadCore) { c.Trust = fid(99) },
		func(c *HeadCore) { c.Coordinate = fid(99) },
		func(c *HeadCore) { c.NonBody = fid(99) },
		func(c *HeadCore) { c.Interpretation = fid(99) },
		func(c *HeadCore) { c.Epoch++ },
	} {
		changed := core
		change(&changed)
		b, err := EncodeHeadCore(changed)
		if err != nil || contract.Hash(b) == contract.Hash(coreBytes) {
			t.Fatal("core field omitted from projection", err)
		}
	}
	planBytes, err := EncodeConditionalPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*ConditionalPlan){
		func(p *ConditionalPlan) {
			p.Family = contract.GCP
			p.Condition = conditionFixture(contract.Token{Family: contract.GCP, Value: "1"})
		},
		func(p *ConditionalPlan) { p.Store = fid(99) },
		func(p *ConditionalPlan) { p.Coordinate = fid(99) },
		func(p *ConditionalPlan) { p.NonBody = fid(99) },
		func(p *ConditionalPlan) {
			p.Condition = conditionFixture(contract.Token{Family: contract.AWS, Value: `"other"`})
		},
		func(p *ConditionalPlan) { p.HeadCore = fid(99) },
		func(p *ConditionalPlan) { p.HeadCoreLength++ },
	} {
		changed := plan
		change(&changed)
		b, err := EncodeConditionalPlan(changed)
		if err != nil || contract.Hash(b) == contract.Hash(planBytes) {
			t.Fatal("conditional field omitted from projection", err)
		}
	}
	subjectBytes, err := contract.LifecycleBytes(subject)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*contract.LifecycleSubject){
		func(s *contract.LifecycleSubject) { s.Operation = fid(99) },
		func(s *contract.LifecycleSubject) { s.Request = fid(99) },
		func(s *contract.LifecycleSubject) { s.Normal.Intent.Digest = fid(99) },
		func(s *contract.LifecycleSubject) {
			s.Normal.Intent.Length++
			s.Normal.PublicState.Length++
			s.Normal.Union.Length++
		},
		func(s *contract.LifecycleSubject) { s.Normal.Union.Digest = fid(99) },
		func(s *contract.LifecycleSubject) { s.BindingVersion++ },
		func(s *contract.LifecycleSubject) { s.HeadCore = fid(99) },
		func(s *contract.LifecycleSubject) { s.HeadCoreLength++ },
		func(s *contract.LifecycleSubject) { s.ConditionalPlan = fid(99) },
	} {
		changed := subject
		change(&changed)
		b, err := contract.LifecycleBytes(changed)
		if err != nil || contract.Hash(b) == contract.Hash(subjectBytes) {
			t.Fatal("authority field omitted from subject", err)
		}
	}
}

// full_only: false
func TestRandomProofsDoNotFeedBackIntoSubjects(t *testing.T) {
	signer := testtrust.New(t, contract.AWS, fid(8))
	h := headFixture(t)
	beforeCore, err := EncodeHeadCore(h.Core)
	if err != nil {
		t.Fatal(err)
	}
	_, plan, _ := projectionFixture(t)
	beforePlan, err := EncodeConditionalPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	beforeSubject, err := contract.LifecycleBytes(h.Subject)
	if err != nil {
		t.Fatal(err)
	}
	spki := signer.PublicKey()
	binding, err := contract.NewBindingRequest(contract.BindingSubject{Domain: h.Core.Domain, Coordinate: h.Core.Coordinate, Store: h.Core.Store, Trust: h.Core.Trust, PublicKey: contract.Hash(spki), Interpretation: h.Core.Interpretation, ControlIncarnationID: fid(80), Epoch: h.Core.Epoch})
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := contract.NewLifecycleRequest(h.Subject)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(q contract.SignRequest) []byte {
		result := signer.Sign(context.Background(), q)
		if result.Reason != contract.ReasonNone || len(result.Signature) == 0 {
			t.Fatal("fixture signature refused")
		}
		return result.Signature
	}
	h.K1, h.AuthorizationSignature = sign(binding), sign(lifecycle)
	first, err := EncodeHead(h)
	if err != nil {
		t.Fatal(err)
	}
	h.K1, h.AuthorizationSignature = sign(binding), sign(lifecycle)
	second, err := EncodeHead(h)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("random signatures did not change full HEAD")
	}
	afterCore, _ := EncodeHeadCore(h.Core)
	afterPlan, _ := EncodeConditionalPlan(plan)
	afterSubject, _ := contract.LifecycleBytes(h.Subject)
	if !bytes.Equal(beforeCore, afterCore) || !bytes.Equal(beforePlan, afterPlan) || !bytes.Equal(beforeSubject, afterSubject) {
		t.Fatal("proof bytes changed a signable projection")
	}
	// The largest desired image is represented by bounded commitments.
	setMaximumLifecycle(&h.Subject)
	if b, err := EncodeHead(h); err != nil || len(b) > contract.MaxHeadLength {
		t.Fatal("maximum image commitment exceeded HEAD bound", err)
	}
}

// full_only: false
func TestMemberCanonicalAndBounded(t *testing.T) {
	p := valueEntryPageFixture()
	b, err := EncodeValueEntryPage(p)
	if err != nil {
		t.Fatal(err)
	}
	q, err := DecodeValueEntryPage(b)
	if err != nil {
		t.Fatal(err)
	}
	again, err := EncodeValueEntryPage(q)
	if err != nil || !bytes.Equal(b, again) {
		t.Fatal("noncanonical round trip")
	}
	if _, err := DecodeValueEntryPage(append(b, 0)); err == nil {
		t.Fatal("trailing byte accepted")
	}
	for i := range b {
		if _, err := DecodeValueEntryPage(b[:i]); err == nil {
			t.Fatalf("truncation %d accepted", i)
		}
	}
	p.Slots[0].ValueBytes = make([]byte, contract.CryptoMaxRawValue+1)
	p.Slots[0].ContentLength, p.Slots[0].RetainedLength = contract.CryptoMaxRawValue+1, contract.CryptoMaxRawValue+1
	if _, err := EncodeValueEntryPage(p); err == nil {
		t.Fatal("overlong value accepted")
	}
}

// Independent field framing and SHA-256 reproduce the earlier schema-10
// literals before deriving schema 11 and its dependent hashes. The lifecycle
// purpose label stays v8. Its complete intent minimum of 888 includes six name
// bytes; the complete lifecycle literal remains 715 bytes.
// full_only: false
func TestLiteralProjectionVectors(t *testing.T) {
	core, plan, subject := projectionFixture(t)
	coreBytes, err := EncodeHeadCore(core)
	if err != nil {
		t.Fatal(err)
	}
	planBytes, err := EncodeConditionalPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	subjectBytes, err := contract.LifecycleBytes(subject)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct {
		name        string
		body        []byte
		length      int
		hex, digest string
	}{
		{"HeadCore", coreBytes, 426, "454e4b5605000b010100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000010000000822657461672d312203000b0100000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000000007b00000700000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000009000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000b00000000000000000000000000000000000000000000000000000000000000000000000000000c00000000", "35e3382845dfcc842e8ba8263bf93e0683111524122da6c22b0a77f1738c0128"},
		{"ConditionalPlan", planBytes, 160, "454e4b5606000b0100000003505554070000000000000000000000000000000000000000000000000000000000000009000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000010000000822657461672d312235e3382845dfcc842e8ba8263bf93e0683111524122da6c22b0a77f1738c0128000001aa", "4a3fdada2bd9e7a62283eeac2a88fc5126aaeec83859b8e53066f148075b0043"},
		{"LifecycleSubject", subjectBytes, 715, "454e4b562f4b322d4c4946454359434c452f7638000002140000000000000000000000000000000000000000000000000000000000000017000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000001b000000000000000000000000000000000000000000000000000000000000001c0000000000000000000000000000000000000000000000000000000000000000000000000000011d00000000000000000000000000000000000000000000000000000000000000000000000000015135e3382845dfcc842e8ba8263bf93e0683111524122da6c22b0a77f1738c0128000001aa4a3fdada2bd9e7a62283eeac2a88fc5126aaeec83859b8e53066f148075b004300000001000000000001000000000000000000050000000000000005220000000000000000000000000000000000000000000000000000000000000023000000000000000000000000000000000000000000000000000000000000000000000100000001454e4b562f4b322d4e4f524d414c2f763800180000000000000000000000000000000000000000000000000000000000000000000000000003781e0000000000000000000000000000000000000000000000000000000000000000000000000000bb1900000000000000000000000000000000000000000000000000000000000000000000000000011a0000000100000001454e4b562f4b322d4752414e542f7638001f00000000000000000000000000000000000000000000000000000000000000000000000000003d00000000454e4b562f4b322d4558434c5553494f4e2f76380020000000000000000000000000000000000000000000000000000000000000000000000000000041000000002100000000000000000000000000000000000000000000000000000000000000000000000000004200000000", "baa0598ea4dc63c8f19ec4bf803af9861ecdd32fa48fd405bc2e54f12f198339"},
	} {
		t.Run(v.name, func(t *testing.T) {
			want, err := hex.DecodeString(v.hex)
			if err != nil || len(want) != v.length {
				t.Fatal("invalid independent vector")
			}
			if !bytes.Equal(v.body, want) {
				t.Fatalf("golden encoding differs: %x", v.body)
			}
			digest := contract.Hash(v.body)
			if hex.EncodeToString(digest[:]) != v.digest {
				t.Fatal("golden digest differs")
			}
		})
	}
}

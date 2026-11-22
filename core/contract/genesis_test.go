package contract

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"math/big"
	"reflect"
	"slices"
	"testing"
)

// full_only: false
func TestHeadCreateRequestFreezesExactAdmission(t *testing.T) {
	id := Hash([]byte("genesis-create"))
	d := Descriptor{Family: GCP, Identity: id, Coordinate: id, NonBody: id, Prefix: "fixture", HeadKey: "fixture/HEAD"}
	body := []byte("bounded proof-bearing HEAD")
	want := bytes.Clone(body)
	q, err := NewHeadCreateRequest(d, body)
	if err != nil {
		t.Fatal(err)
	}
	body[0] ^= 1
	if q.Descriptor() != d || q.Digest() != Hash(want) || q.Length() != uint32(len(want)) || !q.Condition().IsAbsent() || !bytes.Equal(q.Body(), want) {
		t.Fatal("create request did not retain exact admission and body")
	}
	copy := q.Body()
	copy[0] ^= 1
	if !bytes.Equal(q.Body(), want) {
		t.Fatal("body accessor released mutable request ownership")
	}
	for _, invalid := range [][]byte{nil, make([]byte, (64<<10)+1)} {
		if _, err := NewHeadCreateRequest(d, invalid); err == nil {
			t.Fatal("accepted empty or oversized HEAD")
		}
	}
	if (HeadCreateRequest{}).Valid() {
		t.Fatal("zero create request was admitted")
	}
	if _, err := NewHeadCreateRequest(Descriptor{}, want); err == nil {
		t.Fatal("accepted missing descriptor")
	}
}

func initKeysFixture(t testing.TB) CryptoQualifyInitKeysRequest {
	t.Helper()
	id := func(s string) ID { return Hash([]byte(s)) }
	// Public-only structural fixture. This modulus has no fixture private route.
	n := new(big.Int).Lsh(big.NewInt(1), 3071)
	n.Add(n, big.NewInt(12345))
	spki, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	binding := KMSBinding{BindingID: id("binding"), BindingIncarnationID: id("binding incarnation"), BindingSerial: 1, Provider: GCP, WrapProfile: 2, ProtectionClass: 2, KeySelector: "projects/fixture/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1", SPKI: spki, Fingerprint: Hash(spki)}
	digest, err := PublicBindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	return CryptoQualifyInitKeysRequest{Context: InitKeyContext{Schema: 4, GenesisProfile: 1, AdmissionID: id("admission"), SessionID: id("session"), DomainID: id("domain"), CompatibilityID: id("compatibility"), Expiry: 1, InitID: id("init"), DescriptorDigest: id("descriptor"), GenesisPlanDigest: id("plan"), RequestDescriptor: DescriptorVector{Digest: id("request"), Length: GenesisRequestCoreLength, Count: 1}}, Bindings: []BindingTableRow{{SubjectKind: 1, SubjectID: id("authority"), Binding: binding}}, Probes: []InitProbePlanRow{{ProbeID: id("probe"), SubjectKind: 1, SubjectID: id("authority"), BindingID: binding.BindingID, PublicBindingDigest: digest}}}
}

// full_only: false
func TestInitKeyContextIndependentBytes(t *testing.T) {
	q := initKeysFixture(t)
	v := q.Context
	want := []byte{0, 4, 0, 1}
	for _, id := range []ID{v.AdmissionID, v.SessionID, v.DomainID, v.CompatibilityID} {
		want = append(want, id[:]...)
	}
	want = binary.BigEndian.AppendUint64(want, 1)
	for _, id := range []ID{v.InitID, v.DescriptorDigest, v.GenesisPlanDigest, v.RequestDescriptor.Digest} {
		want = append(want, id[:]...)
	}
	want = binary.BigEndian.AppendUint64(want, 209)
	want = binary.BigEndian.AppendUint32(want, 1)
	got, err := EncodeInitKeyContext(v)
	if err != nil || len(got) != 280 || !bytes.Equal(got, want) {
		t.Fatal("initial context differs from independent field-order fixture")
	}
	decoded, err := DecodeInitKeyContext(want)
	if err != nil || decoded != v {
		t.Fatal("initial context decode differs")
	}
	for _, bad := range [][]byte{want[:len(want)-1], append(bytes.Clone(want), 0)} {
		if _, err := DecodeInitKeyContext(bad); err == nil {
			t.Fatal("accepted incomplete or trailing context")
		}
	}
}

// full_only: false
func TestInitQualificationRequestOwnershipAndCorrelation(t *testing.T) {
	q := initKeysFixture(t)
	wire, err := EncodeCryptoQualifyInitKeysRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := DecodeCryptoQualifyInitKeysRequest(wire)
	if err != nil || !reflect.DeepEqual(owned, q) {
		t.Fatal("initial request round trip differs")
	}
	for i := range wire {
		wire[i] = 0
	}
	if !reflect.DeepEqual(owned, q) {
		t.Fatal("owned initial request retained input")
	}
	probe := q.Probes[0]
	field := QualifiedBindingFields{SubjectKind: 1, SubjectID: probe.SubjectID, BindingID: probe.BindingID, PublicBindingDigest: probe.PublicBindingDigest, Provider: GCP, Qualified: 1}
	result := GenesisQualifiedKeysCore{InitID: q.Context.InitID, DescriptorDigest: q.Context.DescriptorDigest, RequestCoreDigest: q.Context.RequestDescriptor.Digest, GenesisPlanDigest: q.Context.GenesisPlanDigest, Public: []QualifiedBindingFields{field}, Private: []QualifiedSuccessorRow{{ProbeID: probe.ProbeID, QualifiedBindingFields: field}}}
	if err := ValidateGenesisQualifiedKeys(q, result); err != nil {
		t.Fatal(err)
	}
	result.Private[0].ProbeID = Hash([]byte("other probe"))
	if err := ValidateGenesisQualifiedKeys(q, result); err == nil {
		t.Fatal("accepted qualification for different private probe")
	}
	q.Probes[0].SubjectID = Hash([]byte("reader"))
	if _, err := EncodeCryptoQualifyInitKeysRequest(q); err == nil {
		t.Fatal("accepted probe outside binding table")
	}
}

func initQualificationSuccessFixture(t testing.TB) (CryptoQualifyInitKeysRequest, GenesisQualifiedKeysCore, []KeyUseRow) {
	t.Helper()
	q := initKeysFixture(t)
	probe := q.Probes[0]
	field := QualifiedBindingFields{SubjectKind: 1, SubjectID: probe.SubjectID, BindingID: probe.BindingID, PublicBindingDigest: probe.PublicBindingDigest, Provider: GCP, Qualified: 1}
	result := GenesisQualifiedKeysCore{InitID: q.Context.InitID, DescriptorDigest: q.Context.DescriptorDigest, RequestCoreDigest: q.Context.RequestDescriptor.Digest, GenesisPlanDigest: q.Context.GenesisPlanDigest, Public: []QualifiedBindingFields{field}, Private: []QualifiedSuccessorRow{{ProbeID: probe.ProbeID, QualifiedBindingFields: field}}}
	rows := []KeyUseRow{
		{BindingID: field.BindingID, PublicBindingDigest: field.PublicBindingDigest, SubjectKind: field.SubjectKind, SubjectID: field.SubjectID, Provider: field.Provider, Purpose: KeyUsePublicKeyRead, Outcome: KeyUseCompleted, Count: 3},
		{BindingID: field.BindingID, PublicBindingDigest: field.PublicBindingDigest, SubjectKind: field.SubjectKind, SubjectID: field.SubjectID, Provider: field.Provider, Purpose: KeyUsePrivateRoleProbe, Outcome: KeyUseCompleted, Count: 1},
	}
	return q, result, rows
}

// full_only: false
func TestInitQualificationCorrelatedSuccessRequiresExactKeyUses(t *testing.T) {
	q, result, valid := initQualificationSuccessFixture(t)
	requestBody, err := EncodeCryptoQualifyInitKeysRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	resultBody, err := EncodeCryptoQualifyInitKeysResult(result)
	if err != nil {
		t.Fatal(err)
	}
	request := CryptoRequest{Schema: CryptoSchema, Kind: CryptoQualifyInitKeys, RequestID: Hash([]byte("request")), CustodyInstanceID: Hash([]byte("custody")), Body: requestBody}
	response := CryptoResponse{Schema: CryptoSchema, Kind: CryptoQualifyInitKeys, RequestID: request.RequestID, CustodyInstanceID: request.CustodyInstanceID, ResultCode: CryptoSuccess, Body: resultBody}
	if response.KeyUseRows = slices.Clone(valid); ValidateCryptoExchange(request, response) != nil {
		t.Fatal("exact successful key-use facts were refused")
	}
	cases := map[string]func([]KeyUseRow) []KeyUseRow{
		"empty":           func([]KeyUseRow) []KeyUseRow { return nil },
		"missing-public":  func(rows []KeyUseRow) []KeyUseRow { return rows[1:] },
		"missing-private": func(rows []KeyUseRow) []KeyUseRow { return rows[:1] },
		"wrong-provider": func(rows []KeyUseRow) []KeyUseRow {
			rows[0].Provider = AWS
			return rows
		},
		"wrong-subject": func(rows []KeyUseRow) []KeyUseRow {
			rows[0].SubjectID = Hash([]byte("other subject"))
			return rows
		},
		"wrong-binding": func(rows []KeyUseRow) []KeyUseRow {
			rows[0].BindingID = Hash([]byte("other binding"))
			return rows
		},
		"wrong-digest": func(rows []KeyUseRow) []KeyUseRow {
			rows[0].PublicBindingDigest = Hash([]byte("other digest"))
			return rows
		},
		"wrong-purpose": func(rows []KeyUseRow) []KeyUseRow {
			rows[0].Purpose = KeyUseMaterialWrap
			return rows
		},
		"non-completed": func(rows []KeyUseRow) []KeyUseRow {
			rows[0].Outcome = KeyUseUnknown
			return rows
		},
		"public-undercount": func(rows []KeyUseRow) []KeyUseRow {
			rows[0].Count = 2
			return rows
		},
		"public-excess": func(rows []KeyUseRow) []KeyUseRow {
			rows[0].Count = 4
			return rows
		},
		"private-excess": func(rows []KeyUseRow) []KeyUseRow {
			rows[1].Count = 2
			return rows
		},
		"extra-outcome": func(rows []KeyUseRow) []KeyUseRow {
			extra := rows[0]
			extra.Outcome = KeyUseDenied
			rows = append(rows, extra)
			slices.SortFunc(rows, compareKeyUseRows)
			return rows
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			response.KeyUseRows = change(slices.Clone(valid))
			if err := ValidateCryptoExchange(request, response); err == nil {
				t.Fatal("incomplete or inexact successful key-use facts were accepted")
			}
		})
	}
}

// full_only: false
func TestInitQualificationFailureRetainsValidPartialKeyUses(t *testing.T) {
	q, _, valid := initQualificationSuccessFixture(t)
	requestBody, err := EncodeCryptoQualifyInitKeysRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	rows := []KeyUseRow{valid[0]}
	for _, outcome := range []uint8{KeyUseDenied, KeyUseFailed, KeyUseUnknown} {
		row := valid[0]
		row.Outcome = outcome
		row.Count = 1
		rows = append(rows, row)
	}
	slices.SortFunc(rows, compareKeyUseRows)
	request := CryptoRequest{Schema: CryptoSchema, Kind: CryptoQualifyInitKeys, RequestID: Hash([]byte("request")), CustodyInstanceID: Hash([]byte("custody")), Body: requestBody}
	response := CryptoResponse{Schema: CryptoSchema, Kind: CryptoQualifyInitKeys, RequestID: request.RequestID, CustodyInstanceID: request.CustodyInstanceID, ResultCode: CryptoPrivateRouteUnavailable, KeyUseRows: rows}
	if err := ValidateCryptoExchange(request, response); err != nil {
		t.Fatal("valid failure response facts were refused", err)
	}
	if err := ValidateInitKeyUseRows(q, rows); err != nil {
		t.Fatal("valid partial key-use facts were refused", err)
	}
}

func genesisDescriptorFixture(t testing.TB, recovery bool) GenesisDescriptorCore {
	t.Helper()
	id := func(s string) ID { return Hash([]byte(s)) }
	control := successionTestRequest(t, 1, 1, 1, recovery).BeforeControl
	reader := successionTestKMS(t, 3)
	recipients := []RecipientRecord{
		{RecipientID: control.AuthorityRecipientID, Status: CurrentRecipient, CurrentBinding: &control.AuthorityKMSBinding},
		{RecipientID: id("reader"), Status: CurrentRecipient, CurrentBinding: &reader},
	}
	slices.SortFunc(recipients, func(a, b RecipientRecord) int { return bytes.Compare(a.RecipientID[:], b.RecipientID[:]) })
	return GenesisDescriptorCore{
		InitID: id("init"), DomainID: control.DomainID, DescriptorArtifactID: id("descriptor artifact"), ManifestArtifactID: id("manifest artifact"),
		Provider: control.Provider, StoreID: control.StoreID, CoordinateID: control.CoordinateID, NonBodyID: control.NonBodyID,
		TrustID: control.NormalSigning.Binding.Trust, InterpretationID: control.NormalSigning.Binding.Interpretation,
		TrustInterpretationID: control.TrustInterpretationID, CompatibilityID: control.CompatibilityID, CryptoSupportID: control.CryptoSupportID,
		AuthorityRecipientID: control.AuthorityRecipientID, NormalSigning: control.NormalSigning, Recovery: control.Recovery, Recipients: recipients,
	}
}

func damageUniqueID(t testing.TB, wire []byte, from, to ID) []byte {
	t.Helper()
	if bytes.Count(wire, from[:]) != 1 {
		t.Fatal("fixture identity is not unique in serialized input")
	}
	damaged := slices.Clone(wire)
	offset := bytes.Index(damaged, from[:])
	copy(damaged[offset:offset+len(to)], to[:])
	return damaged
}

// full_only: false
func TestGenesisRecipientsRejectRecipientBindingIdentityCollisions(t *testing.T) {
	d := genesisDescriptorFixture(t, false)
	rows := d.Recipients
	if _, err := EncodeGenesisRecipientsCore(d.DomainID, rows); err != nil {
		t.Fatal("valid recipients refused", err)
	}
	shared := genesisDescriptorFixture(t, false).Recipients
	shared[1].CurrentBinding.SPKI = slices.Clone(shared[0].CurrentBinding.SPKI)
	shared[1].CurrentBinding.Fingerprint = shared[0].CurrentBinding.Fingerprint
	if _, err := EncodeGenesisRecipientsCore(d.DomainID, shared); err != nil {
		t.Fatal("distinct recipients sharing one physical reader key were refused", err)
	}
	cases := map[string]func([]RecipientRecord){
		"own-collision": func(rows []RecipientRecord) {
			rows[0].CurrentBinding.BindingID = rows[0].RecipientID
		},
		"prior-recipient-current-binding": func(rows []RecipientRecord) {
			rows[1].CurrentBinding.BindingID = rows[0].RecipientID
		},
		"later-recipient-current-binding": func(rows []RecipientRecord) {
			rows[0].CurrentBinding.BindingID = rows[1].RecipientID
		},
		"duplicate-binding": func(rows []RecipientRecord) {
			rows[1].CurrentBinding.BindingID = rows[0].CurrentBinding.BindingID
		},
	}
	validWire, err := EncodeGenesisRecipientsCore(d.DomainID, rows)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			changed := genesisDescriptorFixture(t, false).Recipients
			var from, to ID
			switch name {
			case "own-collision":
				from = changed[0].CurrentBinding.BindingID
				to = changed[0].RecipientID
			case "prior-recipient-current-binding":
				from = changed[1].CurrentBinding.BindingID
				to = changed[0].RecipientID
			case "later-recipient-current-binding":
				from = changed[0].CurrentBinding.BindingID
				to = changed[1].RecipientID
			case "duplicate-binding":
				from = changed[1].CurrentBinding.BindingID
				to = changed[0].CurrentBinding.BindingID
			}
			change(changed)
			if _, err := EncodeGenesisRecipientsCore(d.DomainID, changed); err == nil {
				t.Fatal("recipient/binding identity collision was accepted on encode")
			}
			damaged := damageUniqueID(t, validWire, from, to)
			if _, _, err := DecodeGenesisRecipientsCore(damaged); err == nil {
				t.Fatal("recipient/binding identity collision was accepted on decode")
			}
		})
	}
}

func genesisControlBindingID(d GenesisDescriptorCore, index int) ID {
	switch index {
	case 0:
		return d.NormalSigning.BindingID
	case 1:
		for _, row := range d.Recipients {
			if row.RecipientID == d.AuthorityRecipientID {
				return row.CurrentBinding.BindingID
			}
		}
	case 2:
		return d.Recovery.Signing.BindingID
	case 3:
		return d.Recovery.KMS.BindingID
	}
	return ID{}
}

func setGenesisControlBindingID(d *GenesisDescriptorCore, index int, id ID) {
	switch index {
	case 0:
		d.NormalSigning.BindingID = id
	case 1:
		for i := range d.Recipients {
			if d.Recipients[i].RecipientID == d.AuthorityRecipientID {
				d.Recipients[i].CurrentBinding.BindingID = id
			}
		}
	case 2:
		d.Recovery.Signing.BindingID = id
	case 3:
		d.Recovery.KMS.BindingID = id
	}
}

// full_only: false
func TestGenesisDescriptorRejectsEveryControlBindingPairCollision(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[recovery], func(t *testing.T) {
			valid := genesisDescriptorFixture(t, recovery)
			wire, err := EncodeGenesisDescriptorCore(valid)
			if err != nil {
				t.Fatal("valid authority control reference refused", err)
			}
			count := 2
			if recovery {
				count = 4
			}
			for left := 0; left < count; left++ {
				for right := left + 1; right < count; right++ {
					name := string(rune('0'+left)) + "-" + string(rune('0'+right))
					t.Run(name, func(t *testing.T) {
						changed := genesisDescriptorFixture(t, recovery)
						from := genesisControlBindingID(changed, right)
						to := genesisControlBindingID(changed, left)
						setGenesisControlBindingID(&changed, right, to)
						if _, err := EncodeGenesisDescriptorCore(changed); err == nil {
							t.Fatal("control BindingID pair collision was accepted on encode")
						}
						damaged := damageUniqueID(t, wire, from, to)
						if _, err := DecodeGenesisDescriptorCore(damaged); err == nil {
							t.Fatal("control BindingID pair collision was accepted on decode")
						}
					})
				}
			}
		})
	}
}

// full_only: false
func TestGenesisKeepsRecoveryRoleSeparateFromOrdinaryRecipients(t *testing.T) {
	d := genesisDescriptorFixture(t, true)
	if _, err := EncodeGenesisDescriptorCore(d); err != nil {
		t.Fatal("independent Recovery role", err)
	}
	for _, recipient := range d.Recipients {
		d.Recovery.RoleID = recipient.RecipientID
		if _, err := EncodeGenesisDescriptorCore(d); err == nil {
			t.Fatal("genesis accepted a recipient ID for the Recovery role")
		}
	}
}

// full_only: false
func TestGenesisDescriptorRejectsAmbiguousGCPRecoveryParent(t *testing.T) {
	d := genesisDescriptorFixture(t, true)
	for i := range d.Recipients {
		if d.Recipients[i].RecipientID == d.AuthorityRecipientID {
			d.Recipients[i].CurrentBinding.KeySelector = gcpKMSSelector("fixture-project", "us-central1", "ring", "shared", "1")
		}
	}
	d.Recovery.KMS.KeySelector = gcpKMSSelector("123456789", "us-central1", "ring", "shared", "2")
	if _, err := EncodeGenesisDescriptorCore(d); err == nil {
		t.Fatal("ambiguous project ID/number recovery parent was admitted at genesis")
	}
}

// full_only: false
func TestGenesisStoreConfigurationReadbackFactHasOwnBound(t *testing.T) {
	id := Hash([]byte("selected StoreConfiguration"))
	fact := GenesisArtifactFact{Kind: 3, ArtifactID: id, BodyDigest: id,
		BodyLength: 121, DurabilityProfile: 1, Outcome: 1}
	if _, err := EncodeGenesisArtifactFact(fact); err != nil {
		t.Fatal(err)
	}
	fact.BodyLength = MaxStoreConfigurationLength + 1
	if _, err := EncodeGenesisArtifactFact(fact); err == nil {
		t.Fatal("oversized helper readback accepted")
	}
}

package contract

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// full_only: false
func TestGeneratedNumericDomainMappings(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  uint64
		want uint64
	}{
		{"request reservation", uint64(CryptoGeneratedReservationPurpose), 1},
		{"request adoption", uint64(CryptoGeneratedAdoptionPurpose), 2},
		{"request final preparation", uint64(CryptoGeneratedFinalPreparationPurpose), 3},
		{"request producer preparation", uint64(CryptoGeneratedProducerPreparationPurpose), 4},
		{"request original verification", uint64(CryptoGeneratedOriginalVerificationPurpose), 5},
		{"lineage create", uint64(GeneratorLineageCreate), 1},
		{"lineage retirement", uint64(GeneratorLineageRetirement), 2},
		{"lineage cleanup", uint64(GeneratorLineageCleanup), 3},
		{"prepare plan part", uint64(CryptoGeneratedPreparePlanPart), 1},
		{"prepare finish plan", uint64(CryptoGeneratedPrepareFinishPlan), 2},
		{"prepare producer", uint64(CryptoGeneratedPrepareProducer), 8},
		{"prepare adopt", uint64(CryptoGeneratedPrepareAdopt), 4},
		{"prepare members", uint64(CryptoGeneratedPrepareValueEntries), 5},
		{"prepare supplied", uint64(CryptoGeneratedPrepareSupplied), 6},
		{"prepare verify original", uint64(CryptoGeneratedPrepareVerifyOriginal), 7},
		{"support operation material", uint64(OperationMaterialSupportKind), 1},
		{"support generated parent", uint64(GeneratedParentSupportKind), 2},
		{"support generated fragment", uint64(GeneratedFragmentSupportKind), 3},
		{"support generated result", uint64(GeneratedResultSupportKind), 4},
		{"support generated phase", uint64(GeneratedPhaseSupportKind), 5},
		{"support retained canonical", uint64(RetainedCanonicalSupportKind), 6},
		{"support mutation receipt", uint64(MutationReceiptSupportKind), 7},
		{"support generated lineage", uint64(GeneratedLineageSupportKind), 8},
		{"support generated attempt", uint64(GeneratedAttemptSupportKind), 9},
		{"support generated duty", uint64(GeneratedDutySupportKind), 10},
		{"support generated hazard", uint64(GeneratedHazardSupportKind), 11},
		{"support pending inbox release", uint64(PendingInboxReleaseSupportKind), 12},
		{"support generated create evidence", uint64(GeneratedCreateEvidenceSupportKind), 13},
		{"support generator vector", uint64(GeneratorVectorSupportKind), 14},
		{"support publication coordinate", uint64(PublicationCoordinateSupportKind), 15},
		{"support publication marker", uint64(PublicationMarkerSupportKind), 16},
		{"support output configuration slice", uint64(OutputConfigurationSliceSupportKind), 17},
		{"crypto kind CryptoCompare", uint64(CryptoCompare), 1},
		{"crypto kind CryptoPrepare", uint64(CryptoPrepare), 2},
		{"crypto kind CryptoFreeze", uint64(CryptoFreeze), 3},
		{"crypto kind CryptoClaim", uint64(CryptoClaim), 4},
		{"crypto kind CryptoDiscard", uint64(CryptoDiscard), 5},
		{"crypto kind CryptoAccessReplace", uint64(CryptoAccessReplace), 6},
		{"crypto kind CryptoQualifyInitKeys", uint64(CryptoQualifyInitKeys), 7},
		{"crypto result CryptoSuccess", uint64(CryptoSuccess), 1},
		{"crypto result CryptoInvalidInput", uint64(CryptoInvalidInput), 2},
		{"crypto result CryptoInvalidAdmission", uint64(CryptoInvalidAdmission), 3},
		{"crypto result CryptoExpired", uint64(CryptoExpired), 4},
		{"crypto result CryptoCancelled", uint64(CryptoCancelled), 5},
		{"crypto result CryptoAlreadyUsed", uint64(CryptoAlreadyUsed), 6},
		{"crypto result CryptoSourceAuthenticationFailed", uint64(CryptoSourceAuthenticationFailed), 7},
		{"crypto result CryptoPrivateRouteUnavailable", uint64(CryptoPrivateRouteUnavailable), 8},
		{"crypto result CryptoCustodyUnavailable", uint64(CryptoCustodyUnavailable), 9},
		{"crypto result CryptoResponseUnknown", uint64(CryptoResponseUnknown), 10},
		{"crypto result CryptoCapacityExceeded", uint64(CryptoCapacityExceeded), 11},
		{"crypto result CryptoStoredAuthenticationFailed", uint64(CryptoStoredAuthenticationFailed), 12},
		{"key use purpose KeyUsePublicKeyRead", uint64(KeyUsePublicKeyRead), 1},
		{"key use purpose KeyUseMaterialWrap", uint64(KeyUseMaterialWrap), 2},
		{"key use purpose KeyUseMaterialOpen", uint64(KeyUseMaterialOpen), 3},
		{"key use purpose KeyUsePrivateRoleProbe", uint64(KeyUsePrivateRoleProbe), 4},
		{"key use outcome KeyUseCompleted", uint64(KeyUseCompleted), 1},
		{"key use outcome KeyUseDenied", uint64(KeyUseDenied), 2},
		{"key use outcome KeyUseFailed", uint64(KeyUseFailed), 3},
		{"key use outcome KeyUseUnknown", uint64(KeyUseUnknown), 4},
		{"publication action PublicationCreateEmpty", uint64(PublicationCreateEmpty), 1},
		{"publication action PublicationCreateWithValue", uint64(PublicationCreateWithValue), 2},
		{"publication action PublicationWriteValue", uint64(PublicationWriteValue), 3},
		{"publication action PublicationUpdatePolicy", uint64(PublicationUpdatePolicy), 4},
		{"publication action PublicationDeleteOwned", uint64(PublicationDeleteOwned), 5},
		{"publication action PublicationDeleteReservedSlot", uint64(PublicationDeleteReservedSlot), 6},
		{"capacity position GeneratorCapacityCurrentValueEntries", uint64(GeneratorCapacityCurrentValueEntries), 0},
		{"capacity position GeneratorCapacityCurrentRecipients", uint64(GeneratorCapacityCurrentRecipients), 1},
		{"capacity position GeneratorCapacityCurrentAccess", uint64(GeneratorCapacityCurrentAccess), 2},
		{"capacity position GeneratorCapacityOldValues", uint64(GeneratorCapacityOldValues), 3},
		{"capacity position GeneratorCapacityOldAccess", uint64(GeneratorCapacityOldAccess), 4},
		{"capacity position GeneratorCapacityCandidateValues", uint64(GeneratorCapacityCandidateValues), 5},
		{"capacity position GeneratorCapacityCandidateAccess", uint64(GeneratorCapacityCandidateAccess), 6},
		{"capacity position GeneratorCapacityCreateResults", uint64(GeneratorCapacityCreateResults), 7},
		{"capacity position GeneratorCapacitySeedAccess", uint64(GeneratorCapacitySeedAccess), 8},
		{"capacity position GeneratorCapacityMaterial", uint64(GeneratorCapacityMaterial), 9},
		{"capacity position GeneratorCapacityCreates", uint64(GeneratorCapacityCreates), 10},
		{"capacity position GeneratorCapacityDeletes", uint64(GeneratorCapacityDeletes), 11},
		{"capacity position GeneratorCapacityOwners", uint64(GeneratorCapacityOwners), 12},
		{"capacity position GeneratorCapacityReceipts", uint64(GeneratorCapacityReceipts), 13},
		{"capacity position GeneratorCapacityIntents", uint64(GeneratorCapacityIntents), 14},
		{"capacity position GeneratorCapacityGraph", uint64(GeneratorCapacityGraph), 15},
		{"capacity position GeneratorCapacityAuxiliary", uint64(GeneratorCapacityAuxiliary), 16},
		{"capacity position GeneratorCapacityGroupCount", uint64(GeneratorCapacityGroupCount), 17},
		{"material value", uint64(ValueMaterialKind), 1},
		{"material source", uint64(SourceMaterialKind), 2},
		{"material operation seed", uint64(OperationSeedMaterialKind), 3},
		{"material proof", uint64(ProofMaterialKind), 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("encoded assignment %d, want independent literal %d", tc.got, tc.want)
			}
		})
	}

	for k := uint16(0); k <= 255; k++ {
		if CryptoKind(k).Valid() != (k >= 1 && k <= 7) {
			t.Fatalf("Crypto kind closed set changed at %d", k)
		}
	}
	for _, code := range []uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 65535} {
		if CryptoResultCode(code).Valid() != (code >= 1 && code <= 12) {
			t.Fatalf("Crypto result closed set changed at %d", code)
		}
	}

	// The shared literal is intentional. Distinct types prevent a cleanup
	// lineage value from selecting final-preparation request behavior.
	requestPurpose := CryptoGeneratedFinalPreparationPurpose
	lineagePurpose := GeneratorLineageCleanup
	if uint8(requestPurpose) != 3 || uint8(lineagePurpose) != 3 {
		t.Fatal("shared literal mapping changed")
	}
}

// full_only: false
func TestCryptoGeneratedPrepareClassifierValidatesEnvelope(t *testing.T) {
	context := generatedCryptoCompareFixture(t, 1).Context
	body, err := EncodeCryptoGeneratedPlanPartRequest(CryptoGeneratedPlanPartRequest{OperationRef: generatedRecordID(27), Context: context,
		BlobKind: 2, Count: 1, Total: 4, WholeDigest: Hash([]byte("body")), Payload: []byte("body")})
	if err != nil {
		t.Fatal(err)
	}
	valid := CryptoRequest{Schema: CryptoSchema, Kind: CryptoPrepare, RequestID: generatedRecordID(50), CustodyInstanceID: generatedRecordID(51), Body: body}
	if classified, err := InspectCryptoGeneratedPrepareRequest(valid); err != nil || classified.Variant != CryptoGeneratedPreparePlanPart {
		t.Fatal("valid envelope refused", classified.Variant, err)
	}
	for name, mutate := range map[string]func(*CryptoRequest){
		"wrong kind":     func(q *CryptoRequest) { q.Kind = CryptoFreeze },
		"wrong schema":   func(q *CryptoRequest) { q.Schema = CryptoSchema + 1 },
		"zero request":   func(q *CryptoRequest) { q.RequestID = ID{} },
		"zero custody":   func(q *CryptoRequest) { q.CustodyInstanceID = ID{} },
		"oversized body": func(q *CryptoRequest) { q.Body = make([]byte, CryptoRequestLimit-cryptoRequestHeader+1) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := valid
			mutate(&bad)
			if _, err := InspectCryptoGeneratedPrepareRequest(bad); err == nil {
				t.Fatal("invalid Prepare envelope accepted")
			}
		})
	}
}

func generatedCryptoHexID(t testing.TB, s string) ID {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatal("invalid independent hash", err)
	}
	return ID(b)
}

func generatedCryptoCompareFixture(t testing.TB, purpose uint8) CryptoGeneratedCompareRequest {
	t.Helper()
	id := generatedRecordID
	desc := func(n byte, length uint64, count uint32) GeneratorDescriptor {
		return GeneratorDescriptor{Digest: id(n), Length: length, Count: count}
	}
	parent := GeneratedParentRecord{Schema: 2, DomainID: id(1), OperationID: id(2), RequestIdentityDigest: id(3), RequestCoreDigest: id(4),
		PlanGraphID: id(5), UsePlanDigest: id(6), MaterialID: id(7), RecoveryPolicyID: id(10),
		ValueEntryPlanCount: 1, LineageCount: 1, TemplateCount: 5, Declaration: desc(11, 20, 1), Registry: desc(12, 20, 1), Graph: desc(13, 300, 1),
		SourceUses: desc(14, 4, 0), IntendedEntryPlans: desc(15, 64, 1), Capacity: desc(16, 100, 1), InitialPredecessorDigest: id(17), ConditionDigest: id(18)}
	admission := []string{
		"14a51a29f8b2536a1cb03e924ed25a413cab9f2a80e0aef7dd339721eb0b3ce4",
		"fbbfa54eecd7a82c2edabc7bb053c6c8aac8cdfaa9bec5a7524a3b9d36b7f96e",
		"55256c7a962a5b1da9ecc893ff1cf8d00f5816ac7bcf8b862dcf73f720b6653f",
		"a4f4b83728ea5495651c435e1a41197ceb8debe0875c4e2e48ce57945af67a9f",
	}
	ref, err := AppendRef(nil, Ref{Kind: RootKind, Format: CanonicalSchema, Domain: id(1), Object: id(24), Digest: id(25), Length: 200}, CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	v := CryptoGeneratedCompareRequest{Purpose: CryptoGeneratedPurpose(purpose), Context: ApplyContext{OperationClass: 4, AdmissionID: id(21), SessionID: id(22),
		DomainID: id(1), CompatibilityID: id(23), Expiry: 1000000000, PredecessorHEADDigest: id(17),
		OriginalConditionDigest: id(18), IntentDescriptor: DescriptorVector{Digest: generatedCryptoHexID(t, admission[purpose-1]), Length: 830, Count: 1}, CurrentAccessRoot: id(26)},
		PlanGraph: parent.Graph, UsePlanDigest: parent.UsePlanDigest, MaterialID: parent.MaterialID, AcceptedSources: parent.SourceUses, IntendedEntryPlans: parent.IntendedEntryPlans}
	copy(v.Context.PredecessorRootRef[:], ref)
	if purpose == 1 {
		parent.RequestIdentityDigest = ID{}
		v.ParentPlan = GeneratedParentPlan(parent)
	} else {
		v.Parent = parent
	}
	return v
}

// full_only: false
func TestCryptoGeneratedCompareIndependentHashes(t *testing.T) {
	// Python SHA-256 independently encoded big-endian fields: repeated-byte parent
	// IDs 1..7,10, descriptors (11,20,1),(12,20,1),(13,300,1),(14,4,0),
	// (15,64,1),(16,100,1), predecessor17/condition18. Context uses class4,
	// IDs21,22,1,23, expiry1e9, predecessor17, RootRef(3,10,1,24,25,200,0),
	// condition18, admission(length830,count1), access26. Only purpose1 has the
	// named request-identity hole. Admission is D("crypto-admission", tail).
	wants := []string{"e3bd5f9d5afb5fde32a67f1a79df7327f338101ea0d37d830be34504ee984e80", "0f02b981831cc52fcf7a3bffceae8c534e5862c45ae5ceecb55bffc6d4aa8a1e", "209224416a9b051c8b80c23c220794a19536675534fe20ebf3d36942375f8ed2", "dc95e2a56bb7f66dbaadf6853b872a766e44ef3f830a8008af095d9908396fef"}
	for p := uint8(1); p <= 4; p++ {
		v := generatedCryptoCompareFixture(t, p)
		b, err := EncodeCryptoGeneratedCompareRequest(v)
		if err != nil || len(b) != 1216 || Hash(b) != generatedCryptoHexID(t, wants[p-1]) {
			t.Fatal("compare vector differs", p, len(b), err)
		}
		got, err := InspectCryptoGeneratedCompareRequest(b)
		if err != nil || got != v {
			t.Fatal("compare decode differs", p, err)
		}
		d, err := CryptoGeneratedAdmissionDescriptor(v)
		if err != nil || d != v.Context.IntentDescriptor {
			t.Fatal("admission descriptor differs", p, err)
		}
		for n := 0; n < len(b); n++ {
			if _, err := InspectCryptoGeneratedCompareRequest(b[:n]); err == nil {
				t.Fatal("compare truncation accepted", p, n)
			}
		}
		for _, class := range []byte{1, 2, 3, 5} {
			bad := bytes.Clone(b)
			bad[4] = class
			if _, err := InspectCryptoGeneratedCompareRequest(bad); err == nil {
				t.Fatal("non-generated class accepted", class)
			}
		}
	}
	v := generatedCryptoCompareFixture(t, 1)
	b, err := EncodeCryptoGeneratedCompareRequest(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, purpose := range []byte{0, 6} {
		bad := bytes.Clone(b)
		bad[cryptoContextBlobLength] = purpose
		if _, err := InspectCryptoGeneratedCompareRequest(bad); err == nil {
			t.Fatal("unknown request purpose accepted", purpose)
		}
	}
}

// full_only: false
func TestCryptoGeneratedContinuationUsesFreshAdmissionWithoutChangingParent(t *testing.T) {
	for purpose := uint8(1); purpose <= 4; purpose++ {
		v := generatedCryptoCompareFixture(t, purpose)
		parent, plan := v.Parent, v.ParentPlan
		v.Context.AdmissionID, v.Context.SessionID = generatedRecordID(91), generatedRecordID(92)
		body, err := EncodeCryptoGeneratedCompareRequest(v)
		if err != nil {
			t.Fatalf("purpose %d refused a fresh private admission: %v", purpose, err)
		}
		got, err := InspectCryptoGeneratedCompareRequest(body)
		if err != nil || got.Parent != parent || got.ParentPlan != plan || got.Context != v.Context {
			t.Fatalf("purpose %d changed parent or fresh context: %v", purpose, err)
		}
		for _, mutate := range []func(*CryptoGeneratedCompareRequest){
			func(q *CryptoGeneratedCompareRequest) {
				if purpose == 1 {
					q.ParentPlan.RequestCoreDigest = generatedRecordID(93)
				} else {
					q.Parent.RequestCoreDigest = generatedRecordID(93)
				}
			},
			func(q *CryptoGeneratedCompareRequest) {
				if purpose == 1 {
					q.ParentPlan.ConditionDigest = generatedRecordID(94)
				} else {
					q.Parent.ConditionDigest = generatedRecordID(94)
				}
			},
			func(q *CryptoGeneratedCompareRequest) { q.Context.DomainID = generatedRecordID(95) },
		} {
			bad := v
			mutate(&bad)
			if _, err := EncodeCryptoGeneratedCompareRequest(bad); err == nil {
				t.Fatal("unpinned public parent or domain accepted")
			}
		}
	}
}

// full_only: false
func TestCryptoGeneratedPlanAndDiscardIndependentHashes(t *testing.T) {
	c := generatedCryptoCompareFixture(t, 1).Context
	part := CryptoGeneratedPlanPartRequest{OperationRef: generatedRecordID(27), Context: c, BlobKind: 2, Count: 1, Total: 4, WholeDigest: Hash([]byte("abcd")), Payload: []byte("abcd")}
	b, err := EncodeCryptoGeneratedPlanPartRequest(part)
	if err != nil || len(b) != 476 || Hash(b) != generatedCryptoHexID(t, "aa3752443ee427afefb0c43cea8e27cfe4724f8e92653cb1bc485d5d1e5a87f8") {
		t.Fatal("part vector differs", len(b), err)
	}
	view, err := InspectCryptoGeneratedPlanPartRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := view.Own()
	if err != nil {
		t.Fatal(err)
	}
	clear(b)
	if string(owned.Payload) != "abcd" {
		t.Fatal("part retains borrowed bytes")
	}
	cmp := generatedCryptoCompareFixture(t, 1)
	finish := CryptoGeneratedFinishPlanRequest{OperationRef: part.OperationRef, Context: c, Declaration: cmp.ParentPlan.Declaration, Graph: cmp.PlanGraph, SourceUses: cmp.AcceptedSources}
	b, err = EncodeCryptoGeneratedFinishPlanRequest(finish)
	if err != nil || len(b) != 551 || Hash(b) != generatedCryptoHexID(t, "ce0eb197d7a8730d15c6f90db1f2baadeefb5173369b19b5e2b27add3b7227f4") {
		t.Fatal("finish vector differs", len(b), err)
	}
	got, err := InspectCryptoGeneratedFinishPlanRequest(b)
	if err != nil || got != finish {
		t.Fatal("finish round trip differs", err)
	}
	discard := CryptoGeneratedDiscardRequest{OperationRef: part.OperationRef, Context: c}
	b, err = EncodeCryptoGeneratedDiscardRequest(discard)
	if err != nil || len(b) != 418 || Hash(b) != generatedCryptoHexID(t, "de5be3fb48d4a874daf96ecebc751303faa2427bb20f7d153ca0150347e6be7b") {
		t.Fatal("discard vector differs", len(b), err)
	}
	decoded, err := InspectCryptoGeneratedDiscardRequest(b)
	if err != nil || decoded != discard {
		t.Fatal("discard round trip differs", err)
	}
}

// full_only: false
func TestCryptoGeneratedCommandIndependentHash(t *testing.T) {
	id := generatedRecordID
	intent := generatorIntentFixture(t, id(17), id(14), GeneratorLifecycleManaged, []byte("{}"))
	intentDigest, err := GeneratorIntentDigest(intent)
	if err != nil {
		t.Fatal(err)
	}
	facts := generatedSafeFactsFixture(GeneratorDispositionCompleteCreate)
	facts.RequestDigest, facts.IntentDigest, facts.ResourceContractID = id(13), intentDigest, id(14)
	original, err := EncodeGeneratorSafeFacts(facts)
	if err != nil {
		t.Fatal(err)
	}
	resource := generatorResourceFixtureDigest(t, facts)
	preparation := GeneratedProducerPreparation{Schema: GeneratedProducerPreparationSchema, LifecycleMode: GeneratorLifecycleManaged,
		DomainID: id(1), OperationID: id(2), RequestIdentityDigest: id(3), PlanGraphID: id(4), LineageID: id(5), AttemptID: id(6), TransmissionID: id(7), ResultID: id(8), ResultContractID: id(9), DescriptorID: id(10), ExecutorID: id(11), CredentialRouteID: id(12), Action: 1, RequestDigest: id(13), IntentDigest: intentDigest, ResourceContractID: id(14)}
	// Python struct/hashlib independently concatenated schema3/action, the
	// fifteen IDs in the documented order, lifecycle2 and resource digest.
	// Commands replace the digest with the admitted intent/original-facts
	// blobs and insert uint64be(1000) immediately after the action.
	for _, tc := range []struct {
		action            uint8
		wire, preparation string
		commandLength     int
		command           string
	}{
		{1, "0003010101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020203030303030303030303030303030303030303030303030303030303030303030404040404040404040404040404040404040404040404040404040404040404050505050505050505050505050505050505050505050505050505050505050506060606060606060606060606060606060606060606060606060606060606060707070707070707070707070707070707070707070707070707070707070707080808080808080808080808080808080808080808080808080808080808080809090909090909090909090909090909090909090909090909090909090909090a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d7a326b6a29c0dd6eea369a8ee7cb447c0cfd9796aad746f53a66f48dccd593430e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c020000000000000000000000000000000000000000000000000000000000000000", "a77ab651c4c708df1e036d3b5d60aa4156feab7f3b204c395b59e1e7ca01885f", 573, "8d7da511a33ecaee73520e52fcac38edc33c112b1918c85f07767c11a92d5c1d"},
		{2, "0003020101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020203030303030303030303030303030303030303030303030303030303030303030404040404040404040404040404040404040404040404040404040404040404050505050505050505050505050505050505050505050505050505050505050506060606060606060606060606060606060606060606060606060606060606060707070707070707070707070707070707070707070707070707070707070707080808080808080808080808080808080808080808080808080808080808080809090909090909090909090909090909090909090909090909090909090909090a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d7a326b6a29c0dd6eea369a8ee7cb447c0cfd9796aad746f53a66f48dccd593430e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c02cb23c76d2b4f5297464f5b388e75132bec6d22ff3f711487945f0c8984a7147d", "1be6776d9eb926b1a974d2c5a51427c4b922fbfed8b73a2afe27e0eb5bdc7cf7", 705, "abd3ff16a53f3954ed06c58535e42852cf0789c2048589e4a47b56e0db84a828"},
	} {
		preparation.Action = tc.action
		if tc.action == GeneratorActionDelete {
			preparation.ResourceDigest = resource
		}
		want, err := hex.DecodeString(tc.wire)
		if err != nil {
			t.Fatal(err)
		}
		b, err := EncodeGeneratedProducerPreparation(preparation)
		if err != nil || len(b) != 516 || !bytes.Equal(b, want) || Hash(b) != generatedCryptoHexID(t, tc.preparation) {
			t.Fatal("preparation vector differs", tc.action, len(b), err)
		}
		got, err := InspectGeneratedProducerPreparation(b)
		if err != nil || got != preparation {
			t.Fatal("preparation round trip differs", err)
		}
		for n := range len(b) {
			if _, err := InspectGeneratedProducerPreparation(b[:n]); err == nil {
				t.Fatal("preparation truncation accepted", n)
			}
		}
		if _, err := InspectGeneratedProducerPreparation(append(bytes.Clone(b), 0)); err == nil {
			t.Fatal("preparation suffix accepted")
		}
		command := GeneratedProducerCommand{GeneratedProducerPreparation: preparation, DeadlineUnixMillis: 1000, Intent: intent}
		if tc.action == GeneratorActionDelete {
			command.OriginalFacts = original
		}
		b, err = EncodeGeneratedProducerCommand(command)
		if err != nil || len(b) != tc.commandLength || Hash(b) != generatedCryptoHexID(t, tc.command) {
			t.Fatal("command vector differs", tc.action, len(b), err)
		}
		decoded, err := InspectGeneratedProducerCommand(b)
		if err != nil || decoded.GeneratedProducerPreparation != command.GeneratedProducerPreparation || decoded.DeadlineUnixMillis != command.DeadlineUnixMillis || !bytes.Equal(decoded.Intent, command.Intent) || !bytes.Equal(decoded.OriginalFacts, command.OriginalFacts) {
			t.Fatal("command round trip differs", err)
		}
		if _, err := InspectGeneratedProducerPreparation(b); err == nil {
			t.Fatal("command accepted as preparation", tc.action)
		}
		if _, err := InspectGeneratedProducerCommand(want); err == nil {
			t.Fatal("preparation accepted as command", tc.action)
		}
		for n := range len(b) {
			if _, err := InspectGeneratedProducerCommand(b[:n]); err == nil {
				t.Fatal("command truncation accepted", n)
			}
		}
		if _, err := InspectGeneratedProducerCommand(append(bytes.Clone(b), 0)); err == nil {
			t.Fatal("command suffix accepted")
		}
		for _, deadline := range []uint64{0, 1 << 63} {
			command.DeadlineUnixMillis = deadline
			if _, err := EncodeGeneratedProducerCommand(command); err == nil {
				t.Fatal("invalid command deadline accepted", deadline)
			}
		}
	}
	for _, change := range []func(*GeneratedProducerPreparation){
		func(p *GeneratedProducerPreparation) { p.ResourceContractID = ID{} },
		func(p *GeneratedProducerPreparation) { p.Action = 3 },
		func(p *GeneratedProducerPreparation) { p.LifecycleMode = 0 },
		func(p *GeneratedProducerPreparation) { p.ResourceDigest = ID{} },
		func(p *GeneratedProducerPreparation) { p.Action = 1 },
	} {
		bad := preparation
		change(&bad)
		if _, err := EncodeGeneratedProducerPreparation(bad); err == nil {
			t.Fatal("invalid preparation accepted")
		}
		if _, err := EncodeGeneratedProducerCommand(GeneratedProducerCommand{GeneratedProducerPreparation: bad, DeadlineUnixMillis: 1000, Intent: intent, OriginalFacts: original}); err == nil {
			t.Fatal("invalid command identity accepted")
		}
	}
}

func generatedCryptoFrozenFixture(t testing.TB) CryptoGeneratedFreezeRequest {
	t.Helper()
	c := generatedCryptoCompareFixture(t, 1).Context
	support, err := RequiredSupportDescriptor(c.DomainID, nil)
	if err != nil {
		t.Fatal(err)
	}
	access, err := AccessRecordsDescriptor(c.DomainID, nil)
	if err != nil {
		t.Fatal(err)
	}
	candidatePublicStateDescriptor, err := PublicStateDescriptor(PublicState{Domain: c.DomainID, AccessRoot: c.CurrentAccessRoot, RequiredSupport: support})
	if err != nil {
		t.Fatal(err)
	}
	results, err := GeneratorResultReferencesDescriptor(nil)
	if err != nil {
		t.Fatal(err)
	}
	uses, err := CryptoGeneratedKeyUseDescriptor(nil)
	if err != nil {
		t.Fatal(err)
	}
	return CryptoGeneratedFreezeRequest{OperationRef: generatedRecordID(27), Context: c, PhaseID: generatedRecordID(28), RequestIdentityDigest: generatedRecordID(29), CandidatePublicStateDescriptor: candidatePublicStateDescriptor, CandidateAccess: access, CandidateSupport: support, HeadCoreDigest: generatedRecordID(30), ConditionDigest: c.OriginalConditionDigest, ActualResults: results, KeyUses: uses}
}

// full_only: false
func TestCryptoGeneratedFrozenTraversalAndDescriptors(t *testing.T) {
	v := generatedCryptoFrozenFixture(t)
	b, err := EncodeCryptoGeneratedFreezeRequest(v)
	// Independent Python field concatenation: the three existing empty descriptors
	// have preimage lengths143/66/71; validated-results hashes label+u32(4,0);
	// key uses is SHA256(0000). IDs27/28/29/30 and the context above are literal.
	if err != nil || len(b) != 766 || Hash(b) != generatedCryptoHexID(t, "d8e21411e6f7fa00f412f094693b0e741b329a0f612d100d7e0e17de41540dc7") {
		t.Fatal("freeze body", len(b), err)
	}
	claim, err := EncodeCryptoGeneratedClaimRequest(CryptoGeneratedClaimRequest(v))
	if err != nil || !bytes.Equal(b, claim) {
		t.Fatal("claim changed fixed traversal", err)
	}
	got, err := InspectCryptoGeneratedFreezeRequest(b)
	if err != nil || got != v {
		t.Fatal("freeze round trip", err)
	}
	for n := 0; n < len(b); n++ {
		if _, err := InspectCryptoGeneratedFreezeRequest(b[:n]); err == nil {
			t.Fatal("freeze truncation accepted", n)
		}
	}
	for name, change := range map[string]func(*CryptoGeneratedFreezeRequest){
		"class3":              func(v *CryptoGeneratedFreezeRequest) { v.Context.OperationClass = 3 },
		"phase":               func(v *CryptoGeneratedFreezeRequest) { v.PhaseID = ID{} },
		"request":             func(v *CryptoGeneratedFreezeRequest) { v.RequestIdentityDigest = ID{} },
		"condition":           func(v *CryptoGeneratedFreezeRequest) { v.ConditionDigest = generatedRecordID(99) },
		"public state length": func(v *CryptoGeneratedFreezeRequest) { v.CandidatePublicStateDescriptor.Length++ },
		"access count":        func(v *CryptoGeneratedFreezeRequest) { v.CandidateAccess.Count++ },
		"support count":       func(v *CryptoGeneratedFreezeRequest) { v.CandidateSupport.Count++ },
		"result length":       func(v *CryptoGeneratedFreezeRequest) { v.ActualResults.Length++ },
		"key uses":            func(v *CryptoGeneratedFreezeRequest) { v.KeyUses.Length++ },
	} {
		t.Run(name, func(t *testing.T) {
			bad := v
			change(&bad)
			if _, err := EncodeCryptoGeneratedFreezeRequest(bad); err == nil {
				t.Fatal("invalid frozen facts accepted")
			}
		})
	}
	ref := GeneratorResultReference{Schema: 1, ResultID: generatedRecordID(1), ResultBodyDigest: generatedRecordID(2), ResultLength: 1326}
	row, err := EncodeGeneratorResultReference(ref)
	if err != nil || len(row) != 70 || Hash(row) != generatedCryptoHexID(t, "0a5f95d894addae65fa732eed6b8c34b033fa686b155c06ce9ff6106b3802cc2") {
		t.Fatal("reference body", err)
	}
	d, err := GeneratorResultReferencesDescriptor([]GeneratorResultReference{ref})
	if err != nil || d.Count != 1 || d.Length != 78 || d.Digest != generatedCryptoHexID(t, "4e4310b1c63f924a5429d15d5aada692a6a19f95badeb15afad4cb92b88e1187") {
		t.Fatal("reference descriptor", err)
	}
	if _, err := GeneratorResultReferencesDescriptor([]GeneratorResultReference{ref, ref}); err == nil {
		t.Fatal("duplicate result reference accepted")
	}
	ref.ResultLength = 92638
	if _, err := EncodeGeneratorResultReference(ref); err == nil {
		t.Fatal("excess result length accepted")
	}
}

// full_only: false
func TestCryptoGeneratedFactBindsCompleteFrozenCandidate(t *testing.T) {
	v := generatedCryptoFrozenFixture(t)
	instance := generatedRecordID(31)
	want := generatedCryptoHexID(t, "62d0906f88ec8eb36c4ae354942060f344d68f5cbb0596a9b15b2bdac81a0d75")
	// Independent Python field concatenation rederived the 766-byte freeze
	// vector above, then hashed the literal generated-facts-v1 purpose,
	// repeated-byte ID31 and B(freeze). The full preimage is 836 bytes.
	got, err := CryptoGeneratedFactDigest(instance, v)
	if err != nil || got != want {
		t.Fatal("independent generated fact", got, err)
	}
	for name, change := range map[string]func(*CryptoGeneratedFreezeRequest){
		"operation": func(v *CryptoGeneratedFreezeRequest) { v.OperationRef[0] ^= 1 },
		"context":   func(v *CryptoGeneratedFreezeRequest) { v.Context.SessionID[0] ^= 1 },
		"phase":     func(v *CryptoGeneratedFreezeRequest) { v.PhaseID[0] ^= 1 },
		"request":   func(v *CryptoGeneratedFreezeRequest) { v.RequestIdentityDigest[0] ^= 1 },
		"members":   func(v *CryptoGeneratedFreezeRequest) { v.CandidatePublicStateDescriptor.Digest[0] ^= 1 },
		"access":    func(v *CryptoGeneratedFreezeRequest) { v.CandidateAccess.Digest[0] ^= 1 },
		"support":   func(v *CryptoGeneratedFreezeRequest) { v.CandidateSupport.Digest[0] ^= 1 },
		"head":      func(v *CryptoGeneratedFreezeRequest) { v.HeadCoreDigest[0] ^= 1 },
		"condition": func(v *CryptoGeneratedFreezeRequest) {
			v.ConditionDigest[0] ^= 1
			v.Context.OriginalConditionDigest = v.ConditionDigest
		},
		"results":  func(v *CryptoGeneratedFreezeRequest) { v.ActualResults.Digest[0] ^= 1 },
		"key uses": func(v *CryptoGeneratedFreezeRequest) { v.KeyUses.Digest[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := v
			change(&changed)
			got, err := CryptoGeneratedFactDigest(instance, changed)
			if err == nil && got == want {
				t.Fatal("changed frozen field kept its fact")
			}
		})
	}
	if got, err := CryptoGeneratedFactDigest(generatedRecordID(32), v); err != nil || got == want {
		t.Fatal("custody instance not bound", err)
	}
	if _, err := CryptoGeneratedFactDigest(ID{}, v); err == nil {
		t.Fatal("missing custody instance accepted")
	}
	v.Context.OperationClass = CryptoAccessReplacementClass
	if _, err := CryptoGeneratedFactDigest(instance, v); err == nil {
		t.Fatal("different operation class accepted")
	}
}

func generatedCryptoProducerFixture(t testing.TB) (CryptoGeneratedProducerRequest, GeneratedResultRecord) {
	t.Helper()
	expected, material, result := generatedResultFixture(t, 1)
	c := generatedCryptoCompareFixture(t, 4).Context
	c.DomainID, c.CompatibilityID = material.Core.DomainID, material.Core.CompatibilityID
	ref, err := AppendRef(nil, Ref{Kind: RootKind, Format: CanonicalSchema, Domain: c.DomainID, Object: generatedRecordID(24), Digest: generatedRecordID(25), Length: 200}, CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	copy(c.PredecessorRootRef[:], ref)
	seedContext, err := OperationMaterialContextDigest(material.Core)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := EncodeAccessRecord(AccessRecord{Schema: CanonicalSchema, MaterialKind: 3, MaterialID: material.Core.OperationMaterialID, MaterialContextDigest: seedContext, PackageCheck: material.SeedCheck, Wraps: []WrapRow{{SubjectKind: 1, SubjectID: generatedRecordID(40), BindingID: generatedRecordID(41), BindingSerial: 1, RSACiphertext: bytes.Repeat([]byte{42}, 384)}}})
	if err != nil {
		t.Fatal(err)
	}
	x := expected.Template
	preparation := GeneratedProducerPreparation{Schema: GeneratedProducerPreparationSchema, LifecycleMode: GeneratorLifecycleManaged, DomainID: c.DomainID, OperationID: material.Core.OperationID, RequestIdentityDigest: generatedRecordID(3), PlanGraphID: expected.Plan.PlanGraphID, LineageID: x.LineageID, AttemptID: x.AttemptID, TransmissionID: x.TransmissionID, ResultID: x.ResultID, ResultContractID: x.ResultContractID, DescriptorID: x.DescriptorID, ExecutorID: x.ExecutorID, CredentialRouteID: x.CredentialRouteID, Action: x.Action, RequestDigest: expected.RequestDigest, IntentDigest: x.IntentDigest, ResourceContractID: x.ResourceContractID, ResourceDigest: x.ResourceDigest}
	v := CryptoGeneratedProducerRequest{OperationRef: generatedRecordID(27), Context: c, Template: x, Material: material, SeedAccess: seed, Preparation: preparation, Intent: GeneratorDescriptor{Digest: x.IntentDigest, Length: 100, Count: 1}}
	return v, result
}

// full_only: false
func TestCryptoGeneratedProducerAndAdoptBindings(t *testing.T) {
	v, result := generatedCryptoProducerFixture(t)
	b, err := EncodeCryptoGeneratedProducerRequest(v)
	if err != nil {
		t.Fatal("create-duty producer refused", err)
	}
	// Fixed layout: context418, tag1, template682, material236,
	// seed access591 and four u32 blob lengths precede preparation516.
	if len(b) != 2504 || b[418] != 8 || binary.BigEndian.Uint32(b[1940:1944]) != 516 {
		t.Fatal("producer preparation wire differs", len(b))
	}
	old := bytes.Clone(b)
	old[418] = 3
	if _, err := InspectCryptoGeneratedProducerRequest(old); err == nil {
		t.Fatal("retired producer prepare tag accepted")
	}
	commandIntent := generatorIntentFixture(t, generatedRecordID(6), v.Preparation.ResourceContractID, v.Preparation.LifecycleMode, []byte("{}"))
	commandPreparation := v.Preparation
	commandPreparation.IntentDigest, err = GeneratorIntentDigest(commandIntent)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := EncodeGeneratedProducerCommand(GeneratedProducerCommand{GeneratedProducerPreparation: commandPreparation, DeadlineUnixMillis: 1000, Intent: commandIntent})
	if err != nil {
		t.Fatal(err)
	}
	deadlineBody := bytes.Clone(b[:1940])
	deadlineBody = binary.BigEndian.AppendUint32(deadlineBody, uint32(len(issued)))
	deadlineBody = append(deadlineBody, issued...)
	deadlineBody = append(deadlineBody, b[2460:]...)
	if _, err := InspectCryptoGeneratedProducerRequest(deadlineBody); err == nil {
		t.Fatal("deadline-bearing producer preparation accepted")
	}
	view, err := InspectCryptoGeneratedProducerRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := view.Own()
	if err != nil {
		t.Fatal(err)
	}
	clear(b)
	if owned.Preparation != v.Preparation || !bytes.Equal(owned.SeedAccess, v.SeedAccess) {
		t.Fatal("producer preparation differs or borrows seed access")
	}
	for _, change := range []func(*CryptoGeneratedProducerRequest){func(v *CryptoGeneratedProducerRequest) { v.Preparation.AttemptID = generatedRecordID(99) }, func(v *CryptoGeneratedProducerRequest) { v.Preparation.ResourceContractID = generatedRecordID(99) }, func(v *CryptoGeneratedProducerRequest) { v.Context.OperationClass = 3 }, func(v *CryptoGeneratedProducerRequest) { v.Intent.Digest = generatedRecordID(99) }} {
		bad := v
		change(&bad)
		if _, err := EncodeCryptoGeneratedProducerRequest(bad); err == nil {
			t.Fatal("producer binding mutation accepted")
		}
	}
	resultBytes, err := EncodeGeneratedResultRecord(result)
	if err != nil {
		t.Fatal(err)
	}
	adopt := CryptoGeneratedAdoptRequest{OperationRef: v.OperationRef, Context: v.Context, Result: resultBytes, ExpectedResult: GeneratorDescriptor{Digest: Hash(resultBytes), Length: uint64(len(resultBytes)), Count: 1}}
	b, err = EncodeCryptoGeneratedAdoptRequest(adopt)
	if err != nil {
		t.Fatal(err)
	}
	adopted, err := InspectCryptoGeneratedAdoptRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	copyResult, err := adopted.Own()
	if err != nil {
		t.Fatal(err)
	}
	clear(b)
	if !bytes.Equal(copyResult.Result, resultBytes) {
		t.Fatal("adoption borrows result")
	}
	adopt.ExpectedResult.Length++
	if _, err := EncodeCryptoGeneratedAdoptRequest(adopt); err == nil {
		t.Fatal("unequal expected result accepted")
	}
}

// full_only: false
func TestCryptoGeneratedProducerIntentUsesRawByteLength(t *testing.T) {
	v, _ := generatedCryptoProducerFixture(t)
	for _, size := range []uint64{1, 2, 3, 4, 5, 6, 7, 8, GeneratorIntentMaxLength} {
		v.Intent.Length = size
		body, err := EncodeCryptoGeneratedProducerRequest(v)
		if err != nil {
			t.Fatalf("raw intent length %d: %v", size, err)
		}
		decoded, err := InspectCryptoGeneratedProducerRequest(body)
		if err != nil || decoded.Intent != v.Intent {
			t.Fatalf("raw intent length %d round trip: %v", size, err)
		}
		if size < 8 && v.Intent.Valid() {
			t.Fatal("raw intent exception weakened framed vectors")
		}
	}
	for _, change := range []func(*GeneratorDescriptor){
		func(d *GeneratorDescriptor) { d.Length = 0 },
		func(d *GeneratorDescriptor) { d.Length = GeneratorIntentMaxLength + 1 },
		func(d *GeneratorDescriptor) { d.Count = 0 },
		func(d *GeneratorDescriptor) { d.Count = 2 },
		func(d *GeneratorDescriptor) { d.Digest = ID{} },
	} {
		bad := v
		change(&bad.Intent)
		if _, err := EncodeCryptoGeneratedProducerRequest(bad); err == nil {
			t.Fatal("invalid raw intent descriptor accepted")
		}
		body, err := EncodeCryptoGeneratedProducerRequest(v)
		if err != nil {
			t.Fatal(err)
		}
		w := cryptoWriter{b: body[:len(body)-GeneratorDescriptorLength]}
		writeGeneratorDescriptor(&w, bad.Intent)
		if _, err := InspectCryptoGeneratedProducerRequest(w.b); err == nil {
			t.Fatal("invalid raw intent descriptor decoded")
		}
	}
}

func generatedCryptoValueEntryFixture(t testing.TB) (ApplyContext, CryptoGeneratedValueEntryPlan, CryptoGeneratedValueEntryResult) {
	t.Helper()
	_, material, result := generatedResultFixture(t, 1)
	c := generatedCryptoCompareFixture(t, 3).Context
	c.DomainID, c.CompatibilityID = material.Core.DomainID, material.Core.CompatibilityID
	ref, err := AppendRef(nil, Ref{Kind: RootKind, Format: CanonicalSchema, Domain: c.DomainID, Object: generatedRecordID(24), Digest: generatedRecordID(25), Length: 200}, CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	copy(c.PredecessorRootRef[:], ref)
	meta := generatedRecordEntryMetadata()
	meta.ConfigContractID = result.Core.ConfigContractID
	meta.IntentDigest = result.SafeFacts.IntentDigest
	meta.ResourceIncarnationID, err = GeneratorResourceID(result.Core.DomainID, result.Core.OperationID, result.Core.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	meta.OriginOperationID, meta.OriginAttemptID, meta.CreateResultID = result.Core.OperationID, result.Core.AttemptID, result.Core.ResultID
	meta.ResourceContractID, meta.ResourceDigest = result.SafeFacts.ResourceContractID, generatorResourceFixtureDigest(t, result.SafeFacts)
	core := ValueCore{Schema: CanonicalSchema, Profile: 2, CompatibilityID: c.CompatibilityID, CryptoSupportID: material.Core.CryptoSupportID, DomainID: c.DomainID, Name: "n", EntryIncarnationID: generatedRecordID(14), ValueStateID: meta.GenerationID, OriginSnapshotID: generatedRecordID(15), OriginTransitionID: generatedRecordID(16), DataKeyID: generatedRecordID(17), DataKeyEpoch: 1, CommitmentKeyID: generatedRecordID(18), CommitmentKeyEpoch: 1, ContentLength: result.Payload.ContentLength, ValueSource: Generated, InputEncoding: InputEncodingRaw, RetainedLength: result.Payload.ContentLength}
	core.GeneratedBindingDigest, err = GeneratedBindingDigest(meta)
	if err != nil {
		t.Fatal(err)
	}
	resultBytes, err := EncodeGeneratedResultRecord(result)
	if err != nil {
		t.Fatal(err)
	}
	input := CryptoGeneratedValueEntryPlan{OutputEncoding: OutputEncodingRaw, Slot: 1, Result: resultBytes, ValueCore: core, Generated: meta, Recipients: []ID{generatedRecordID(40)}}
	payload, err := EncodeCanonicalPayload(CanonicalPayload{Profile: 2, CryptoSupportID: core.CryptoSupportID, DataKeyID: core.DataKeyID, DataKeyEpoch: 1, CommitmentKeyID: core.CommitmentKeyID, CommitmentKeyEpoch: 1, ContentLength: core.ContentLength, Ciphertext: bytes.Repeat([]byte{90}, int(core.ContentLength)+16), InputEncoding: InputEncodingRaw, RetainedLength: core.ContentLength})
	if err != nil {
		t.Fatal(err)
	}
	entry := ValueEntry{Name: core.Name, Incarnation: core.EntryIncarnationID, ValueState: core.ValueStateID, OriginSnapshot: core.OriginSnapshotID, OriginTransition: core.OriginTransitionID, ValueSource: Generated, ConfidentialityClass: Secret, Recipients: input.Recipients, ValueBytes: payload, Generated: meta, InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, ContentLength: uint32(len(payload) - CanonicalPayloadOverhead), RetainedLength: uint32(len(payload) - CanonicalPayloadOverhead)}
	accessContext, err := ValueMaterialContextDigest(core)
	if err != nil {
		t.Fatal(err)
	}
	access := AccessRecord{Schema: CanonicalSchema, MaterialKind: 1, MaterialID: core.ValueStateID, MaterialContextDigest: accessContext, Wraps: []WrapRow{{SubjectKind: 1, SubjectID: input.Recipients[0], BindingID: generatedRecordID(41), BindingSerial: 1, RSACiphertext: bytes.Repeat([]byte{42}, 384)}}}
	output := CryptoGeneratedValueEntryResult{Slot: input.Slot, ResultID: result.Core.ResultID, ResultDigest: Hash(resultBytes), ValueCore: core, Entry: entry, Access: access}
	return c, input, output
}

// full_only: false
func TestCryptoGeneratedMemberBatchesAreTypedAndOwned(t *testing.T) {
	c, input, output := generatedCryptoValueEntryFixture(t)
	request := CryptoGeneratedValueEntriesRequest{OperationRef: generatedRecordID(27), Context: c, PhaseID: generatedRecordID(28), Final: 1, Rows: []CryptoGeneratedValueEntryPlan{input}}
	b, err := EncodeCryptoGeneratedValueEntriesRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	view, err := InspectCryptoGeneratedValueEntriesRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := view.Own()
	if err != nil {
		t.Fatal(err)
	}
	clear(b)
	if len(owned.Rows) != 1 || !bytes.Equal(owned.Rows[0].Result, input.Result) || owned.Rows[0].ValueCore != input.ValueCore {
		t.Fatal("member input retains borrowed bytes")
	}
	response := CryptoGeneratedValueEntriesResult{Final: 1, Rows: []CryptoGeneratedValueEntryResult{output}}
	b, err = EncodeCryptoGeneratedValueEntriesResult(response)
	if err != nil {
		t.Fatal(err)
	}
	resultView, err := InspectCryptoGeneratedValueEntriesResult(b)
	if err != nil {
		t.Fatal(err)
	}
	copyResult, err := resultView.Own()
	if err != nil {
		t.Fatal(err)
	}
	clear(b)
	if len(copyResult.Rows) != 1 || !bytes.Equal(copyResult.Rows[0].Entry.ValueBytes, output.Entry.ValueBytes) || !bytes.Equal(copyResult.Rows[0].Access.Wraps[0].RSACiphertext, output.Access.Wraps[0].RSACiphertext) {
		t.Fatal("member result retains borrowed bytes")
	}
	for name, change := range map[string]func(*CryptoGeneratedValueEntriesRequest){
		"class3":         func(v *CryptoGeneratedValueEntriesRequest) { v.Context.OperationClass = 3 },
		"no phase":       func(v *CryptoGeneratedValueEntriesRequest) { v.PhaseID = ID{} },
		"final tag":      func(v *CryptoGeneratedValueEntriesRequest) { v.Final = 2 },
		"duplicate slot": func(v *CryptoGeneratedValueEntriesRequest) { v.Rows = append(v.Rows, v.Rows[0]) },
		"raw length":     func(v *CryptoGeneratedValueEntriesRequest) { v.Rows[0].ValueCore.ContentLength-- },
		"source": func(v *CryptoGeneratedValueEntriesRequest) {
			v.Rows[0].ValueCore.ValueSource = Supplied
			v.Rows[0].ValueCore.GeneratedBindingDigest = ID{}
		},
		"metadata": func(v *CryptoGeneratedValueEntriesRequest) {
			v.Rows[0].Generated.ResourceDigest = generatedRecordID(99)
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := request
			bad.Rows = append([]CryptoGeneratedValueEntryPlan(nil), request.Rows...)
			change(&bad)
			if _, err := EncodeCryptoGeneratedValueEntriesRequest(bad); err == nil {
				t.Fatal("invalid member preparation accepted")
			}
		})
	}
	response.Rows[0].ResultID = ID{}
	if _, err := EncodeCryptoGeneratedValueEntriesResult(response); err == nil {
		t.Fatal("missing result identity accepted")
	}
}

// full_only: false
func TestCryptoGeneratedMemberResponseTraversalChecksWholeOrderedBatch(t *testing.T) {
	context, plans, results := generatedCryptoValueEntryBatchFixture(t, 3)
	requestBody, err := EncodeCryptoGeneratedValueEntriesRequest(CryptoGeneratedValueEntriesRequest{OperationRef: generatedRecordID(27),
		Context: context, PhaseID: generatedRecordID(28), Final: 1, Rows: plans})
	if err != nil {
		t.Fatal(err)
	}
	q := CryptoRequest{Schema: CryptoSchema, Kind: CryptoPrepare, RequestID: generatedRecordID(93),
		CustodyInstanceID: generatedRecordID(94), Body: requestBody}
	validate := func(t *testing.T, result CryptoGeneratedValueEntriesResult, want error) {
		t.Helper()
		body, err := EncodeCryptoGeneratedValueEntriesResult(result)
		if err != nil {
			t.Fatal("encode member result", err)
		}
		p := CryptoResponse{Schema: q.Schema, Kind: q.Kind, RequestID: q.RequestID, CustodyInstanceID: q.CustodyInstanceID,
			ResultCode: CryptoSuccess, Body: body}
		if err := ValidateCryptoExchange(q, p); err != want {
			t.Fatalf("member result relation: got %v want %v", err, want)
		}
	}
	validate(t, CryptoGeneratedValueEntriesResult{Final: 1, Rows: results}, nil)
	validate(t, CryptoGeneratedValueEntriesResult{Final: 1, Rows: results[:2]}, ErrCryptoMessage)
	validate(t, CryptoGeneratedValueEntriesResult{BatchIndex: 1, Final: 1, Rows: results}, ErrCryptoMessage)
	validate(t, CryptoGeneratedValueEntriesResult{Rows: results}, ErrCryptoMessage)
	mismatched := append([]CryptoGeneratedValueEntryResult(nil), results...)
	mismatched[1].ResultDigest = generatedRecordID(99)
	validate(t, CryptoGeneratedValueEntriesResult{Final: 1, Rows: mismatched}, ErrCryptoMessage)
}

// full_only: false
func TestCryptoGeneratedTypedResponsesAndClassRefusal(t *testing.T) {
	compare := generatedCryptoCompareFixture(t, 4)
	body, err := EncodeCryptoGeneratedCompareRequest(compare)
	if err != nil {
		t.Fatal(err)
	}
	request := CryptoRequest{Schema: 4, Kind: CryptoCompare, RequestID: generatedRecordID(50), CustodyInstanceID: generatedRecordID(51), Body: body}
	resultBody, err := EncodeCryptoGeneratedCompareResult(CryptoGeneratedCompareResult{OperationRef: generatedRecordID(52)})
	if err != nil {
		t.Fatal(err)
	}
	response := CryptoResponse{Schema: 4, Kind: CryptoCompare, RequestID: request.RequestID, CustodyInstanceID: request.CustodyInstanceID, ResultCode: CryptoSuccess, Body: resultBody}
	wire, err := EncodeCryptoGeneratedResponse(request, response)
	if err != nil {
		t.Fatal(err)
	}
	// Independent outer frame: u16(3),kind1,IDs50/51,u16(success1),
	// u16(key-use-count0),B(repeated-byte52 OperationRef).
	if len(wire) != 107 || Hash(wire) != generatedCryptoHexID(t, "77514fe68bfb23e494760f8fc413c283b6af62e001469f1de0eb3d04763ddaae") {
		t.Fatal("response independent frame differs")
	}
	view, err := InspectCryptoGeneratedResponse(request, wire)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := view.Own(request)
	if err != nil {
		t.Fatal(err)
	}
	clear(wire)
	if !bytes.Equal(owned.Body, resultBody) {
		t.Fatal("response body borrows wire")
	}
	request.Body = bytes.Clone(request.Body)
	request.Body[4] = 3
	if _, err := EncodeCryptoGeneratedResponse(request, response); err == nil {
		t.Fatal("class3 request accepted at generated response boundary")
	}
	request.Body = body
	response.ResultCode = CryptoPrivateRouteUnavailable
	response.Body = nil
	response.KeyUseRows = []KeyUseRow{{BindingID: generatedRecordID(1), PublicBindingDigest: generatedRecordID(2), SubjectKind: 1, SubjectID: generatedRecordID(3), Provider: AWS, Purpose: KeyUseMaterialOpen, Outcome: KeyUseDenied, Count: 1}}
	wire, err = EncodeCryptoGeneratedResponse(request, response)
	if err != nil {
		t.Fatal(err)
	}
	view, err = InspectCryptoGeneratedResponse(request, wire)
	if err != nil || view.KeyUseRows.RowCount() != 1 {
		t.Fatal("failure dropped attempted key use", err)
	}
	response.Body = []byte{0}
	if _, err := EncodeCryptoGeneratedResponse(request, response); err == nil {
		t.Fatal("failure carried material")
	}
}

func generatedCryptoFinishResultFixture(t testing.TB) CryptoGeneratedFinishPlanResult {
	t.Helper()
	id := generatedRecordID
	material := OperationMaterialRecord{Core: OperationMaterialCore{Schema: CanonicalSchema, Profile: 2, CompatibilityID: id(23), CryptoSupportID: id(31), DomainID: id(1), OperationID: id(2), OperationMaterialID: id(7), UsePlanDigest: id(6), SeedEpoch: 1}, SeedCheck: id(32)}
	// Independent SHA256("ENKV/CRYPTO/v2/material\0" || B(core204)).
	context := generatedCryptoHexID(t, "b76542839ab81ad8b44983a49bce519169a22a97a0c66155cc1e2cc8611b6405")
	seed, err := EncodeAccessRecord(AccessRecord{Schema: CanonicalSchema, MaterialKind: 3, MaterialID: id(7), MaterialContextDigest: context, PackageCheck: material.SeedCheck, Wraps: []WrapRow{{SubjectKind: 1, SubjectID: id(40), BindingID: id(41), BindingSerial: 1, RSACiphertext: bytes.Repeat([]byte{42}, 384)}}})
	if err != nil {
		t.Fatal(err)
	}
	transfer := TransferEnvelope{Core: TransferCore{Schema: 2, Profile: 2, CompatibilityID: id(23), CryptoSupportID: id(31), DomainID: id(1), OperationID: id(2), OperationMaterialID: id(7), UsePlanDigest: id(6), EnvelopeID: id(43), UseKind: 1, PacketKind: 5, PacketLength: 68, SourceID: id(44), SealedInputCoreDigest: id(45)}, Ciphertext: bytes.Repeat([]byte{46}, 84)}
	return CryptoGeneratedFinishPlanResult{Material: material, SeedAccess: seed, SourceProtections: []CryptoGeneratedSourceProtection{{SourceID: id(44), OriginalSourceCoreDigest: id(45), OriginalEnvelopeDigest: id(47), Transfer: transfer}}}
}

// full_only: false
func TestCryptoGeneratedFinishResultRetainsExactSources(t *testing.T) {
	v := generatedCryptoFinishResultFixture(t)
	b, err := EncodeCryptoGeneratedFinishPlanResult(v)
	// Independent Python concatenation from the fixture's explicit fields: material236,
	// seed access591, transfer410, source row510, framed source vector518.
	if err != nil || len(b) != 1358 || Hash(b) != generatedCryptoHexID(t, "c61fd4de4a7bf37aa2dee41dd22944c112cb6e8c699e85a23a717cc0605368ff") {
		t.Fatal("finish result independent wire differs", len(b), err)
	}
	view, err := InspectCryptoGeneratedFinishPlanResult(b)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := view.Own()
	if err != nil {
		t.Fatal(err)
	}
	for n := range b {
		if _, err := InspectCryptoGeneratedFinishPlanResult(b[:n]); err == nil {
			t.Fatal("truncated finish result accepted", n)
		}
	}
	clear(b)
	if !bytes.Equal(owned.SourceProtections[0].Transfer.Ciphertext, v.SourceProtections[0].Transfer.Ciphertext) || !bytes.Equal(owned.SeedAccess, v.SeedAccess) {
		t.Fatal("finish result borrows protected keys")
	}
	for name, mutate := range map[string]func(*CryptoGeneratedFinishPlanResult){
		"seed check":      func(v *CryptoGeneratedFinishPlanResult) { v.Material.SeedCheck = generatedRecordID(99) },
		"source identity": func(v *CryptoGeneratedFinishPlanResult) { v.SourceProtections[0].SourceID = generatedRecordID(99) },
		"original core": func(v *CryptoGeneratedFinishPlanResult) {
			v.SourceProtections[0].OriginalSourceCoreDigest = generatedRecordID(99)
		},
		"missing original envelope": func(v *CryptoGeneratedFinishPlanResult) { v.SourceProtections[0].OriginalEnvelopeDigest = ID{} },
		"use plan": func(v *CryptoGeneratedFinishPlanResult) {
			v.SourceProtections[0].Transfer.Core.UsePlanDigest = generatedRecordID(99)
		},
		"duplicate source": func(v *CryptoGeneratedFinishPlanResult) {
			v.SourceProtections = append(v.SourceProtections, v.SourceProtections[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := v
			bad.SourceProtections = append([]CryptoGeneratedSourceProtection(nil), v.SourceProtections...)
			mutate(&bad)
			if _, err := EncodeCryptoGeneratedFinishPlanResult(bad); err == nil {
				t.Fatal("mismatched protection accepted")
			}
		})
	}
}

// full_only: false
func TestCryptoGeneratedMemberOutputAccessMatchesRecipients(t *testing.T) {
	_, _, output := generatedCryptoValueEntryFixture(t)
	output.Access.Wraps[0].SubjectID = generatedRecordID(99)
	if _, err := EncodeCryptoGeneratedValueEntriesResult(CryptoGeneratedValueEntriesResult{Final: 1, Rows: []CryptoGeneratedValueEntryResult{output}}); err == nil {
		t.Fatal("foreign recipient wrap accepted")
	}
}

// full_only: false
func TestCryptoGeneratedEmptyMemberBatchIndependentHashes(t *testing.T) {
	v := CryptoGeneratedValueEntriesRequest{OperationRef: generatedRecordID(27), Context: generatedCryptoCompareFixture(t, 1).Context, PhaseID: generatedRecordID(28), Final: 1}
	b, err := EncodeCryptoGeneratedValueEntriesRequest(v)
	// Independent concatenation after OpRef+B(Context): 05,ID28,u32(0),01,
	// B(u32(0)); the result starts with05,u32(0),01,B(u32(0)).
	if err != nil || len(b) != 464 || Hash(b) != generatedCryptoHexID(t, "edcf4fe086d81c9e3abdd28e1fa4106c532065566ce2ace15144209f04b26f5f") {
		t.Fatal("empty member request differs", len(b), err)
	}
	r, err := EncodeCryptoGeneratedValueEntriesResult(CryptoGeneratedValueEntriesResult{Final: 1})
	if err != nil || len(r) != 14 || Hash(r) != generatedCryptoHexID(t, "3c719938717f62f7a87bc9730c0b852b28485805fd63bad125bc98f052c3dde3") {
		t.Fatal("empty member result differs", len(r), err)
	}
	for n := range b {
		if _, err := InspectCryptoGeneratedValueEntriesRequest(b[:n]); err == nil {
			t.Fatal("truncated empty request accepted", n)
		}
	}
	for n := range r {
		if _, err := InspectCryptoGeneratedValueEntriesResult(r[:n]); err == nil {
			t.Fatal("truncated empty result accepted", n)
		}
	}
	v.Final = 0
	if _, err := EncodeCryptoGeneratedValueEntriesRequest(v); err == nil {
		t.Fatal("empty nonfinal batch accepted")
	}
	v.Final, v.BatchIndex = 1, 1
	if _, err := EncodeCryptoGeneratedValueEntriesRequest(v); err == nil {
		t.Fatal("later empty batch accepted")
	}
}

// full_only: false
func TestCryptoGeneratedAllClosedRequestResponseVariants(t *testing.T) {
	id := generatedRecordID
	compare := generatedCryptoCompareFixture(t, 1)
	c, input, output := generatedCryptoValueEntryFixture(t)
	producer, _ := generatedCryptoProducerFixture(t)
	verification := generatedCryptoVerificationFixture(t)
	_, verificationResult := generatedCryptoProducerFixture(t)
	verificationPacket, err := EncodeGeneratedResultRecord(verificationResult)
	if err != nil {
		t.Fatal(err)
	}
	verification.Original.ResultID = verificationResult.Core.ResultID
	verification.OriginalResult = GeneratorResultReference{Schema: 1, ResultID: verificationResult.Core.ResultID,
		ResultBodyDigest: Hash(verificationPacket), ResultLength: uint32(len(verificationPacket))}
	verification.Context.IntentDescriptor, err = CryptoGeneratedAdmissionDescriptor(verification)
	if err != nil {
		t.Fatal(err)
	}
	supplied := generatedSuppliedCryptoFixture(t)
	frozen := generatedCryptoFrozenFixture(t)
	finish := generatedCryptoFinishResultFixture(t)
	finish.SourceProtections = nil
	part := CryptoGeneratedPlanPartRequest{OperationRef: id(27), Context: compare.Context, BlobKind: 2, Count: 1, Total: 4, WholeDigest: Hash([]byte("abcd")), Payload: []byte("abcd")}
	for _, row := range []struct {
		name           string
		kind           CryptoKind
		prepareVariant CryptoGeneratedPrepareVariant
		request        func() ([]byte, error)
		response       func() ([]byte, error)
	}{
		{"compare", CryptoCompare, 0, func() ([]byte, error) { return EncodeCryptoGeneratedCompareRequest(compare) }, func() ([]byte, error) {
			return EncodeCryptoGeneratedCompareResult(CryptoGeneratedCompareResult{OperationRef: id(52)})
		}},
		{"compare original", CryptoCompare, 0, func() ([]byte, error) { return EncodeCryptoGeneratedCompareRequest(verification) }, func() ([]byte, error) {
			return EncodeCryptoGeneratedCompareResult(CryptoGeneratedCompareResult{OperationRef: id(52)})
		}},
		{"verify original", CryptoPrepare, CryptoGeneratedPrepareVerifyOriginal, func() ([]byte, error) {
			return EncodeCryptoGeneratedVerifyRequest(CryptoGeneratedVerifyRequest{OperationRef: id(27), Context: verification.Context,
				Result: verificationPacket, ExpectedResult: GeneratorDescriptor{Digest: Hash(verificationPacket), Length: uint64(len(verificationPacket)), Count: 1}})
		}, func() ([]byte, error) { return EncodeGeneratorResultReference(verification.OriginalResult) }},
		{"part", CryptoPrepare, CryptoGeneratedPreparePlanPart, func() ([]byte, error) { return EncodeCryptoGeneratedPlanPartRequest(part) }, func() ([]byte, error) { return EncodeCryptoGeneratedPartResult(CryptoGeneratedPartResult{}) }},
		{"finish", CryptoPrepare, CryptoGeneratedPrepareFinishPlan, func() ([]byte, error) {
			return EncodeCryptoGeneratedFinishPlanRequest(CryptoGeneratedFinishPlanRequest{OperationRef: id(27), Context: compare.Context, Declaration: compare.ParentPlan.Declaration, Graph: compare.PlanGraph, SourceUses: compare.AcceptedSources})
		}, func() ([]byte, error) { return EncodeCryptoGeneratedFinishPlanResult(finish) }},
		{"producer", CryptoPrepare, CryptoGeneratedPrepareProducer, func() ([]byte, error) { return EncodeCryptoGeneratedProducerRequest(producer) }, func() ([]byte, error) {
			return EncodeCryptoGeneratedProducerResult(CryptoGeneratedProducerResult{ProducerLocatorID: id(53)})
		}},
		{"adopt", CryptoPrepare, CryptoGeneratedPrepareAdopt, func() ([]byte, error) {
			return EncodeCryptoGeneratedAdoptRequest(CryptoGeneratedAdoptRequest{OperationRef: id(27), Context: c, Result: input.Result, ExpectedResult: GeneratorDescriptor{Digest: Hash(input.Result), Length: uint64(len(input.Result)), Count: 1}})
		}, func() ([]byte, error) {
			return EncodeCryptoGeneratedAdoptResult(CryptoGeneratedAdoptResult{Result: input.Result})
		}},
		{"members", CryptoPrepare, CryptoGeneratedPrepareValueEntries, func() ([]byte, error) {
			return EncodeCryptoGeneratedValueEntriesRequest(CryptoGeneratedValueEntriesRequest{OperationRef: id(27), Context: c, PhaseID: id(28), Final: 1, Rows: []CryptoGeneratedValueEntryPlan{input}})
		}, func() ([]byte, error) {
			return EncodeCryptoGeneratedValueEntriesResult(CryptoGeneratedValueEntriesResult{Final: 1, Rows: []CryptoGeneratedValueEntryResult{output}})
		}},
		{"supplied", CryptoPrepare, CryptoGeneratedPrepareSupplied, func() ([]byte, error) { return EncodeCryptoGeneratedSuppliedRequest(supplied) }, func() ([]byte, error) {
			return EncodeCryptoGeneratedSuppliedResult(CryptoGeneratedSuppliedResult{Final: supplied.Final})
		}},
		{"freeze", CryptoFreeze, 0, func() ([]byte, error) { return EncodeCryptoGeneratedFreezeRequest(frozen) }, func() ([]byte, error) { return EncodeCryptoFreezeResult(CryptoFreezeResult{FactDigest: id(54)}) }},
		{"claim", CryptoClaim, 0, func() ([]byte, error) { return EncodeCryptoGeneratedClaimRequest(CryptoGeneratedClaimRequest(frozen)) }, func() ([]byte, error) { return nil, nil }},
		{"discard", CryptoDiscard, 0, func() ([]byte, error) {
			return EncodeCryptoGeneratedDiscardRequest(CryptoGeneratedDiscardRequest{OperationRef: id(27), Context: compare.Context})
		}, func() ([]byte, error) { return nil, nil }},
	} {
		t.Run(row.name, func(t *testing.T) {
			body, err := row.request()
			if err != nil {
				t.Fatal(err)
			}
			q := CryptoRequest{Schema: 4, Kind: row.kind, RequestID: id(50), CustodyInstanceID: id(51), Body: body}
			if err := ValidateCryptoGeneratedRequest(q); err != nil {
				t.Fatal("valid typed request refused", err)
			}
			if row.kind == CryptoPrepare {
				classified, err := InspectCryptoGeneratedPrepareRequest(q)
				if err != nil || classified.Variant != row.prepareVariant {
					t.Fatal("prepare classification differs", classified.Variant, err)
				}
			}
			requestWire, err := EncodeCryptoRequest(q)
			if err != nil {
				t.Fatal("common request envelope refused generated request", err)
			}
			decodedRequest, err := DecodeCryptoRequest(requestWire)
			if err != nil || decodedRequest.Schema != q.Schema || decodedRequest.Kind != q.Kind ||
				decodedRequest.RequestID != q.RequestID || decodedRequest.CustodyInstanceID != q.CustodyInstanceID || !bytes.Equal(decodedRequest.Body, q.Body) {
				t.Fatal("common request envelope changed generated request", err)
			}
			for _, cut := range []int{0, 1, 31, 32, 35, 36, 50, 418, 419, len(body) - 1} {
				if cut >= len(body) {
					continue
				}
				bad := q
				bad.Body = body[:cut]
				if err := ValidateCryptoGeneratedRequest(bad); err == nil {
					t.Fatal("request truncation accepted", cut)
				}
			}
			bad := q
			bad.Body = append(bytes.Clone(body), 0)
			if err := ValidateCryptoGeneratedRequest(bad); err == nil {
				t.Fatal("request suffix accepted")
			}
			for _, schema := range []uint16{0, 2, 3, 5} {
				bad = q
				bad.Schema = schema
				if err := ValidateCryptoGeneratedRequest(bad); err == nil {
					t.Fatal("outer version accepted", schema)
				}
			}
			bad = q
			bad.Body = bytes.Clone(body)
			offset := 36
			if q.Kind == CryptoCompare {
				offset = 4
			}
			bad.Body[offset] = 3
			if err := ValidateCryptoGeneratedRequest(bad); err == nil {
				t.Fatal("class3 admitted")
			}
			if q.Kind == CryptoPrepare {
				bad = q
				bad.Body = bytes.Clone(body)
				binary.BigEndian.PutUint32(bad.Body[32:36], CryptoApplyContextLength-1)
				if _, err := InspectCryptoGeneratedPrepareRequest(bad); err == nil {
					t.Fatal("malformed context length accepted")
				}
				bad.Body = bytes.Clone(body)
				if row.prepareVariant == CryptoGeneratedPrepareProducer {
					bad.Body[418] = 3
					if err := ValidateCryptoGeneratedRequest(bad); err == nil {
						t.Fatal("retired producer request tag accepted")
					}
					if _, err := InspectCryptoGeneratedPrepareRequest(bad); err == nil {
						t.Fatal("retired producer request classified")
					}
				}
				bad.Body[418] = 9
				if _, err := InspectCryptoGeneratedPrepareRequest(bad); err == nil {
					t.Fatal("unknown prepare variant accepted")
				}
			}
			out, err := row.response()
			if err != nil {
				t.Fatal(err)
			}
			p := CryptoResponse{Schema: 4, Kind: q.Kind, RequestID: q.RequestID, CustodyInstanceID: q.CustodyInstanceID, ResultCode: CryptoSuccess, Body: out}
			if row.prepareVariant == CryptoGeneratedPrepareProducer {
				want := append([]byte{8}, bytes.Repeat([]byte{53}, 32)...)
				if !bytes.Equal(out, want) {
					t.Fatal("producer locator response wire differs")
				}
				old := p
				old.Body = bytes.Clone(out)
				old.Body[0] = 3
				if _, err := InspectCryptoGeneratedProducerResult(old.Body); err == nil {
					t.Fatal("retired producer response tag accepted")
				}
				if err := ValidateCryptoExchange(q, old); err == nil {
					t.Fatal("retired producer response accepted by exchange")
				}
			}
			if err := ValidateCryptoExchange(q, p); err != nil {
				t.Fatal("common exchange refused generated response", err)
			}
			refused := p
			refused.ResultCode, refused.Body = CryptoInvalidAdmission, nil
			if err := ValidateCryptoExchange(q, refused); err != nil {
				t.Fatal("common exchange refused generated failure", err)
			}
			refused.Body = []byte{1}
			if err := ValidateCryptoExchange(q, refused); err == nil {
				t.Fatal("failure with a body accepted")
			}
			wire, err := EncodeCryptoGeneratedResponse(q, p)
			if err != nil {
				t.Fatal("typed response refused", err)
			}
			if _, err := InspectCryptoGeneratedResponse(q, wire); err != nil {
				t.Fatal(err)
			}
			for _, cut := range []int{0, 1, 3, 67, 69, 71, 74, len(wire) - 1} {
				if _, err := InspectCryptoGeneratedResponse(q, wire[:cut]); err == nil {
					t.Fatal("response truncation accepted", cut)
				}
			}
			if _, err := InspectCryptoGeneratedResponse(q, append(bytes.Clone(wire), 0)); err == nil {
				t.Fatal("response suffix accepted")
			}
			p.RequestID = id(99)
			if err := ValidateCryptoExchange(q, p); err == nil {
				t.Fatal("common exchange accepted cross-request response")
			}
			if _, err := EncodeCryptoGeneratedResponse(q, p); err == nil {
				t.Fatal("cross-request response accepted")
			}
		})
	}
}

// full_only: false
func TestCryptoGeneratedCapacityAndCanonicalChunkBoundaries(t *testing.T) {
	c := generatedCryptoCompareFixture(t, 1).Context
	p := CryptoGeneratedPlanPartRequest{OperationRef: generatedRecordID(27), Context: c, BlobKind: 2, Count: 2, Total: GeneratedFragmentMaxPayload + 1, WholeDigest: generatedRecordID(30), Payload: make([]byte, GeneratedFragmentMaxPayload)}
	b, err := EncodeCryptoGeneratedPlanPartRequest(p)
	if err != nil || len(b) > CryptoGeneratedPartLimit {
		t.Fatal("maximum part refused", err)
	}
	if _, err := InspectCryptoGeneratedPlanPartRequest(b); err != nil {
		t.Fatal(err)
	}
	p.Index, p.Offset, p.Payload = 1, GeneratedFragmentMaxPayload, []byte{1}
	if _, err := EncodeCryptoGeneratedPlanPartRequest(p); err != nil {
		t.Fatal("canonical tail refused", err)
	}
	for name, change := range map[string]func(*CryptoGeneratedPlanPartRequest){
		"unknown source part": func(v *CryptoGeneratedPlanPartRequest) { v.BlobKind = 4 },
		"wrong offset":        func(v *CryptoGeneratedPlanPartRequest) { v.Offset-- },
		"wrong count":         func(v *CryptoGeneratedPlanPartRequest) { v.Count++ },
		"empty tail":          func(v *CryptoGeneratedPlanPartRequest) { v.Payload = nil },
		"excess total":        func(v *CryptoGeneratedPlanPartRequest) { v.Total = 32<<20 + 1 },
		"excess graph":        func(v *CryptoGeneratedPlanPartRequest) { v.BlobKind = 3; v.Total = 8<<20 + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := p
			change(&bad)
			if _, err := EncodeCryptoGeneratedPlanPartRequest(bad); err == nil {
				t.Fatal("noncanonical part accepted")
			}
		})
	}
	if _, err := InspectCryptoGeneratedPlanPartRequest(make([]byte, CryptoGeneratedPartLimit+1)); err != ErrCryptoCapacity {
		t.Fatal("part allocation bound", err)
	}
	if _, err := InspectCryptoGeneratedCompareRequest(make([]byte, CryptoGeneratedCompareLimit+1)); err != ErrCryptoCapacity {
		t.Fatal("compare allocation bound", err)
	}
	if _, err := InspectCryptoGeneratedAdoptRequest(make([]byte, CryptoGeneratedAdoptLimit+1)); err != ErrCryptoCapacity {
		t.Fatal("adopt allocation bound", err)
	}
	if _, err := InspectCryptoGeneratedPrepareRequest(CryptoRequest{Schema: CryptoSchema, Kind: CryptoPrepare,
		RequestID: generatedRecordID(1), CustodyInstanceID: generatedRecordID(2), Body: make([]byte, CryptoRequestLimit-cryptoRequestHeader+1)}); err != ErrCryptoCapacity {
		t.Fatal("prepare union allocation bound", err)
	}
	if _, err := InspectCryptoGeneratedValueEntriesResult(make([]byte, CryptoGeneratedMaterialLimit+MaxSelectedGrantRows*GeneratedGrantSealLength+11)); err != ErrCryptoCapacity {
		t.Fatal("member result allocation bound", err)
	}
	if _, err := InspectCryptoGeneratedResponse(CryptoRequest{}, make([]byte, CryptoGeneratedResponseLimit+1)); err != ErrCryptoCapacity {
		t.Fatal("response allocation bound", err)
	}
	if _, err := GeneratorResultReferencesDescriptor(make([]GeneratorResultReference, 1409)); err != ErrCryptoCapacity {
		t.Fatal("reference count bound", err)
	}
}

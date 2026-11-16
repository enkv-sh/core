package contract

import (
	"bytes"
	"testing"
)

func fuzzRecord[T any](name string, decode func([]byte) (T, error), encode func(T) ([]byte, error)) func(*testing.T, []byte) {
	return func(t *testing.T, b []byte) {
		t.Helper()
		v, err := decode(b)
		if err != nil {
			return
		}
		canonical, err := encode(v)
		if err != nil || !bytes.Equal(b, canonical) {
			t.Fatalf("%s accepted noncanonical bytes", name)
		}
		if len(b) > 0 {
			for i := range b {
				b[i] ^= 255
			}
			owned, err := encode(v)
			for i := range b {
				b[i] ^= 255
			}
			if err != nil || !bytes.Equal(canonical, owned) {
				t.Fatalf("%s decode retained caller bytes", name)
			}
		}
	}
}

func fuzzOwnedRecord[T any, V any](name string, inspect func([]byte) (V, error), own func(V) (T, error), encode func(T) ([]byte, error)) func(*testing.T, []byte) {
	return func(t *testing.T, b []byte) {
		t.Helper()
		fuzzRecord(name, func(b []byte) (T, error) {
			view, err := inspect(b)
			if err != nil {
				var zero T
				return zero, err
			}
			v, err := own(view)
			if err != nil {
				t.Fatalf("%s inspected view cannot be owned: %v", name, err)
			}
			return v, err
		}, encode)(t, b)
	}
}

func fuzzInspected[T any, V any](name string, inspect func([]byte) (V, error), own func(V) (T, error), decode func([]byte) (T, error), encode func(T) ([]byte, error)) func(*testing.T, []byte) {
	base := fuzzRecord(name, decode, encode)
	return func(t *testing.T, b []byte) {
		t.Helper()
		view, inspection := inspect(b)
		_, decoding := decode(b)
		if (inspection == nil) != (decoding == nil) {
			t.Fatalf("%s inspector and decoder disagree", name)
		}
		if inspection == nil {
			owned, err := own(view)
			if err != nil {
				t.Fatalf("%s inspected view cannot be owned", name)
			}
			encoded, err := encode(owned)
			if err != nil || !bytes.Equal(encoded, b) {
				t.Fatalf("%s view changed exact bytes", name)
			}
		}
		base(t, b)
	}
}

// The corpus contains only public fields and opaque encrypted bytes. Inspectors
// must bound complete input before retained variable-length ownership.
// full_only: false
func FuzzFirstFlowRecords(f *testing.F) {
	q := initKeysFixture(f)
	add := func(b []byte, err error) {
		f.Helper()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	add(EncodeKMSBinding(q.Bindings[0].Binding))
	add(EncodeBindingTable(q.Bindings))
	add(EncodeInitKeyContext(q.Context))
	add(EncodeCryptoQualifyInitKeysRequest(q))
	add(EncodeGenesisRequestCore(GenesisRequestCore{InitID: q.Context.InitID, DomainID: q.Context.DomainID, DescriptorDigest: q.Context.DescriptorDigest, GenesisIdentityPlanDigest: q.Context.GenesisPlanDigest, SetupDigest: q.Context.DescriptorDigest, Expiry: 1, RecoveryMode: 0, InitOwnerDecision: 1, RecoveryLossAcknowledgement: 1}))
	body, err := EncodeCryptoQualifyInitKeysRequest(q)
	if err != nil {
		f.Fatal(err)
	}
	add(EncodeCryptoRequest(CryptoRequest{Schema: CryptoSchema, Kind: CryptoQualifyInitKeys, RequestID: Hash([]byte("request")), CustodyInstanceID: Hash([]byte("custody")), Body: body}))
	id := Hash([]byte("public corpus identity"))
	wrap := WrapRow{SubjectKind: 1, SubjectID: q.Bindings[0].SubjectID, BindingID: q.Bindings[0].Binding.BindingID, BindingSerial: 1, PublicBindingDigest: q.Probes[0].PublicBindingDigest, RSACiphertext: make([]byte, 384)}
	source := SealedInputCore{SealedInputCoreFields: SealedInputCoreFields{Schema: SealedInputSchema, Profile: 2, CompatibilityID: id, DomainID: id, FileIdentity: id, SourceID: id, CryptoSupportID: id, DataKeyID: id, DataKeyEpoch: 1, IntendedRecipientBindingSetDigest: id, InputEncoding: InputEncodingRaw, RetainedLength: 0}, Name: "public name"}
	add(EncodeSealedInputCore(source))
	add(EncodeSealedInputEnvelope(SealedInputEnvelope{Core: source, Ciphertext: make([]byte, 16), AuthorityWrap: wrap}))
	core := ValueCore{ValueSource: 1, Schema: CanonicalSchema, Profile: 2, CompatibilityID: id, CryptoSupportID: id, DomainID: id, Name: "public name", EntryIncarnationID: id, ValueStateID: id, OriginSnapshotID: id, OriginTransitionID: id, DataKeyID: id, DataKeyEpoch: 1, CommitmentKeyID: id, CommitmentKeyEpoch: 1, InputEncoding: InputEncodingRaw, RetainedLength: 0}
	add(EncodeValueCore(core))
	payload := CanonicalPayload{Profile: 2, CryptoSupportID: id, DataKeyID: id, DataKeyEpoch: 1, CommitmentKeyID: id, CommitmentKeyEpoch: 1, Ciphertext: make([]byte, 16), InputEncoding: InputEncodingRaw, RetainedLength: 0}
	add(EncodeCanonicalPayload(payload))
	add(EncodeAccessRecord(AccessRecord{Schema: CanonicalSchema, MaterialKind: 1, MaterialID: id, MaterialContextDigest: id, Wraps: []WrapRow{wrap}}))
	addCurrentKeyFuzzSeeds(f, q.Bindings)
	addGeneratedFuzzSeeds(f)
	checks := []func(*testing.T, []byte){
		fuzzInspected("binding", InspectKMSBinding, KMSBindingView.Own, DecodeKMSBinding, EncodeKMSBinding),
		fuzzInspected("signing binding", InspectPublicSigningBinding, PublicSigningBindingView.Own, DecodePublicSigningBinding, EncodePublicSigningBinding),
		fuzzInspected("binding table", InspectBindingTable, BindingTableView.Own, DecodeBindingTable, EncodeBindingTable),
		fuzzInspected("recipient", InspectRecipientRecord, RecipientRecordView.Own, DecodeRecipientRecord, EncodeRecipientRecord),
		fuzzInspected("source core", InspectSealedInputCore, SealedInputCoreView.Own, DecodeSealedInputCore, EncodeSealedInputCore),
		fuzzInspected("source", InspectSealedInputEnvelope, SealedInputEnvelopeView.Own, DecodeSealedInputEnvelope, EncodeSealedInputEnvelope),
		fuzzInspected("value core", InspectValueCore, ValueCoreView.Own, DecodeValueCore, EncodeValueCore),
		fuzzInspected("value payload", InspectCanonicalPayload, CanonicalPayloadView.Own, DecodeCanonicalPayload, EncodeCanonicalPayload),
		fuzzInspected("access", InspectAccessRecord, AccessRecordView.Own, DecodeAccessRecord, EncodeAccessRecord),
		fuzzInspected("member", InspectValueEntry, ValueEntryView.Own, DecodeValueEntry, EncodeValueEntry),
		fuzzInspected("current access", InspectCurrentAccessSection, CurrentAccessSectionView.Own, DecodeCurrentAccessSection, EncodeCurrentAccessSection),
		fuzzInspected("Crypto request", InspectCryptoRequest, CryptoRequestView.Own, DecodeCryptoRequest, EncodeCryptoRequest),
		fuzzInspected("Crypto response", InspectCryptoResponse, CryptoResponseView.Own, DecodeCryptoResponse, EncodeCryptoResponse),
		fuzzRecord("init context", DecodeInitKeyContext, EncodeInitKeyContext),
		fuzzRecord("init qualification", DecodeCryptoQualifyInitKeysRequest, EncodeCryptoQualifyInitKeysRequest),
		fuzzRecord("genesis descriptor", DecodeGenesisDescriptorCore, EncodeGenesisDescriptorCore),
		fuzzRecord("genesis request", DecodeGenesisRequestCore, EncodeGenesisRequestCore),
		fuzzRecord("genesis manifest", DecodeGenesisBootstrapManifestCore, EncodeGenesisBootstrapManifestCore),
		fuzzRecord("genesis closure", DecodeGenesisBootstrapClosureCore, EncodeGenesisBootstrapClosureCore),
		fuzzRecord("genesis subject", DecodeGenesisSubject, EncodeGenesisSubject),
		fuzzRecord("genesis challenge", DecodeGenesisK3ChallengeCore, EncodeGenesisK3ChallengeCore),
		fuzzRecord("Crypto compare", DecodeCryptoCompareRequest, EncodeCryptoCompareRequest),
		fuzzRecord("Crypto prepare", DecodeCryptoPrepareRequest, EncodeCryptoPrepareRequest),
		fuzzRecord("Crypto freeze", DecodeCryptoFreezeRequest, EncodeCryptoFreezeRequest),
		fuzzRecord("Crypto claim", DecodeCryptoClaimRequest, EncodeCryptoClaimRequest),
		fuzzRecord("Crypto discard", DecodeCryptoDiscardRequest, EncodeCryptoDiscardRequest),
		fuzzRecord("succession subject", DecodeSuccessionSubject, EncodeSuccessionSubject),
		fuzzRecord("successor evidence", DecodeSuccessorEvidenceVector, EncodeSuccessorEvidenceVector),
		fuzzRecord("compact mutation receipt", InspectCompactMutationReceipt, EncodeCompactMutationReceipt),
		fuzzRecord("mutation receipt indexes", InspectMutationReceiptIndexes, EncodeMutationReceiptIndexes),
		fuzzRecord("apply context", DecodeApplyContext, EncodeApplyContext),
		fuzzRecord("Crypto access replacement", DecodeCryptoAccessReplaceRequest, EncodeCryptoAccessReplaceRequest),
		fuzzRecord("Crypto successor qualification", DecodeCryptoAccessReplaceResult, EncodeCryptoAccessReplaceResult),
		fuzzRecord("Crypto access prepare", DecodeCryptoAccessPrepareRequest, EncodeCryptoAccessPrepareRequest),
		fuzzRecord("Crypto access prepare result", DecodeCryptoAccessPrepareResult, EncodeCryptoAccessPrepareResult),
		fuzzRecord("Crypto access freeze", DecodeCryptoAccessFreezeRequest, EncodeCryptoAccessFreezeRequest),
		fuzzRecord("Crypto access claim", DecodeCryptoAccessClaimRequest, EncodeCryptoAccessClaimRequest),
		fuzzRecord("operation seed core", DecodeOperationMaterialCore, EncodeOperationMaterialCore),
		fuzzRecord("operation seed record", DecodeOperationMaterialRecord, EncodeOperationMaterialRecord),
		fuzzRecord("transfer core", DecodeTransferCore, EncodeTransferCore),
		fuzzInspected("transfer envelope", InspectTransferEnvelope, TransferEnvelopeView.Own, DecodeTransferEnvelope, EncodeTransferEnvelope),
		fuzzInspected("retained canonical source", InspectRetainedCanonicalRecord, RetainedCanonicalRecordView.Own, DecodeRetainedCanonicalRecord, EncodeRetainedCanonicalRecord),
		fuzzSupportRecord,
		fuzzSuccessorKEKProbe,
	}
	checks = append(checks, generatedFuzzChecks()...)
	f.Add([]byte{})
	f.Add([]byte{255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > CryptoFrameLimit {
			return
		}
		for _, check := range checks {
			check(t, b)
		}
	})
}
